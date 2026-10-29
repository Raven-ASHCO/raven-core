//! The addresses this host offers a contact for a hole punch (any-network
//! plan §3 Phase 1 item 3), chosen by Raven instead of libp2p.
//!
//! Stock libp2p-dcutr 0.15 offers the swarm's `NewExternalAddrCandidate`s:
//! its last 20, oldest first (behaviour.rs:335-344, 362-385). That list has
//! three gaps:
//! - **Identify rewrites the port.** libp2p-identify 0.48 turns an observed
//!   address whose port is none of our listen ports into `observed IP +
//!   listen port` (behaviour.rs:350-397; the swarm's translation keeps only
//!   the IP, libp2p-swarm 0.48 translation.rs:39-55). Behind a NAT that
//!   changes the port (most CGNATs, a router whose 7423 is taken) DCUtR is
//!   offered `public:7423`, which nothing forwards. The raw observation is
//!   what can work, and the host feeds it here ([`CandidateBook::observed`]).
//! - **A router mapping is never a candidate.** libp2p-upnp reports its
//!   mapping only as a confirmed external address (behaviour.rs:418-442),
//!   and the swarm drops a later candidate equal to a confirmed address
//!   (lib.rs:1132-1141).
//! - **No own IPv6.** A host with global IPv6 behind a stateful firewall can
//!   hole-punch on it, but nothing reports its own address as a candidate.
//!
//! [`CandidateBook::candidates`] lists five tiers, highest first: confirmed
//! external addresses (UPnP, AutoNAT); own global IPv6 listen addresses (only
//! the OS-preferred source address once the host knows it, else at most two
//! IPs); raw observations that one of our relays, or two or more peers,
//! reported within [`OBSERVED_TTL`]; own global IPv4 listen addresses; then
//! the swarm's candidates (Identify's possibly rewritten guess, at most
//! four). Duplicates keep their highest tier, every QUIC address goes before
//! every TCP one, and at most [`MAX_CANDIDATES`] are offered.
//!
//! **Privacy.** Only `/ip4|ip6/<ip>/tcp/<port>` and
//! `/ip4|ip6/<ip>/udp/<port>/quic-v1` (port not 0) whose IP the
//! [`AddrRule`] allows: globally routable unicast outside the debug lab,
//! never a LAN, loopback, link-local, ULA, CGNAT or documentation address,
//! a DNS name, a circuit, a WSS form (`/tls`, `/sni`, `/ws`, `/wss`) or a
//! `/certhash` address. [`crate::gate::HolePunch`] offers them to verified
//! contacts only, and nothing here is fed to AutoNAT or Identify. The book
//! belongs to one endpoint: a network change rebuilds the endpoint
//! (Phase 0b), so the old network's evidence goes with it.
//!
//! **Restricted network** (RWS1 §9; [`CandidateBook::with_restricted`]):
//! while a relay reservation rides a proxied WSS connection, the book offers
//! nothing and records no swarm candidate. Through a proxy the relay sees
//! the proxy's egress IP, and Identify's rewrite turns that into
//! `egress IP + listen port` (the rewrite above), which nothing forwards.
//! Everything else the book holds is offered again once the flag clears.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use libp2p::multiaddr::Protocol;
use libp2p::swarm::FromSwarm;
use libp2p::{Multiaddr, PeerId};

use crate::gate::AddrRule;
use crate::host::{addr_ip, is_circuit, is_wss_form};

/// At most this many candidates are offered.
pub const MAX_CANDIDATES: usize = 8;
/// How long a raw observation counts after it was last reported.
pub const OBSERVED_TTL: Duration = Duration::from_secs(600);
/// Observed addresses kept at once (the least recently reported goes).
const MAX_OBSERVED: usize = 32;
/// Swarm candidates kept (the newest).
const MAX_OTHER: usize = 4;
/// Distinct observers remembered per observed address.
const MAX_OBSERVERS: usize = 4;
/// Peers that must agree on an observation no relay of ours made.
const AGREEING_PEERS: usize = 2;
/// Own IPv6 addresses offered while the preferred source is unknown.
const MAX_V6_IPS: usize = 2;

/// Who reported one observed address, and when last.
#[derive(Debug)]
struct Seen {
    by_relay: bool,
    observers: Vec<PeerId>,
    last: Instant,
}

impl Seen {
    fn trusted(&self) -> bool {
        self.by_relay || self.observers.len() >= AGREEING_PEERS
    }
}

/// How many addresses each tier holds (counts only, for logs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CandidateCounts {
    pub mapped: usize,
    pub ipv6: usize,
    pub observed: usize,
    pub listen: usize,
    pub other: usize,
}

impl fmt::Display for CandidateCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} mapped, {} ipv6, {} observed, {} listen, {} other",
            self.mapped, self.ipv6, self.observed, self.listen, self.other
        )
    }
}

/// The hole-punch candidates of one endpoint (see the module doc). Pure: the
/// caller feeds it swarm events, observations and the preferred IPv6 source.
#[derive(Debug)]
pub struct CandidateBook {
    rule: AddrRule,
    /// Own listen addresses ([`FromSwarm::NewListenAddr`] / `Expired`).
    listen: BTreeSet<Multiaddr>,
    /// Confirmed external addresses (UPnP, AutoNAT), oldest first.
    confirmed: Vec<Multiaddr>,
    /// Raw observed addresses, from the host.
    observed: HashMap<Multiaddr, Seen>,
    /// The swarm's candidates, newest first.
    other: VecDeque<Multiaddr>,
    preferred_v6: Option<Ipv6Addr>,
    /// The restricted-network flag ([`Self::with_restricted`]); `None`:
    /// never restricted.
    restricted: Option<Arc<AtomicBool>>,
}

impl CandidateBook {
    pub fn new(rule: AddrRule) -> Self {
        Self {
            rule,
            listen: BTreeSet::new(),
            confirmed: Vec::new(),
            observed: HashMap::new(),
            other: VecDeque::new(),
            preferred_v6: None,
            restricted: None,
        }
    }

    /// Follow `flag`, the host's restricted-network flag
    /// ([`crate::host::EndpointConfig::restricted`]; see the module doc).
    pub fn with_restricted(mut self, flag: Arc<AtomicBool>) -> Self {
        self.restricted = Some(flag);
        self
    }

    /// Is the restricted-network flag set (nothing is offered)?
    pub fn restricted(&self) -> bool {
        self.restricted
            .as_ref()
            .is_some_and(|r| r.load(Ordering::SeqCst))
    }

    /// `address` as a candidate (`/p2p/..` dropped: DCUtR appends this
    /// host's own), or `None` when it may not be offered.
    fn usable(&self, address: &Multiaddr) -> Option<Multiaddr> {
        // Never a WSS form, a `/certhash` (WebTransport, WebRTC) or a
        // circuit, wherever the component stands (the shape below refuses
        // them too; this keeps it so if the shape ever widens).
        if is_wss_form(address)
            || is_circuit(address)
            || address.iter().any(|p| matches!(p, Protocol::Certhash(_)))
        {
            return None;
        }
        let mut parts = address.iter();
        let mut out = match parts.next()? {
            p @ (Protocol::Ip4(_) | Protocol::Ip6(_)) => Multiaddr::empty().with(p),
            _ => return None,
        };
        match parts.next()? {
            Protocol::Tcp(port) if port != 0 => out.push(Protocol::Tcp(port)),
            Protocol::Udp(port) if port != 0 => {
                if !matches!(parts.next()?, Protocol::QuicV1) {
                    return None;
                }
                out.push(Protocol::Udp(port));
                out.push(Protocol::QuicV1);
            }
            _ => return None,
        }
        // Only a trailing `/p2p/<id>` may follow (never `/p2p-circuit`).
        match (parts.next(), parts.next()) {
            (None, _) | (Some(Protocol::P2p(_)), None) => {}
            _ => return None,
        }
        self.rule.allows(&out).then_some(out)
    }

    /// `observer` saw this host at `address` on a direct connection (its
    /// Identify `observed_addr`, raw). `by_relay`: `observer` is one of our
    /// relays.
    pub fn observed(
        &mut self,
        observer: PeerId,
        address: &Multiaddr,
        by_relay: bool,
        now: Instant,
    ) {
        let Some(address) = self.usable(address) else {
            return;
        };
        if !self.observed.contains_key(&address) && self.observed.len() >= MAX_OBSERVED {
            self.observed
                .retain(|_, s| now.saturating_duration_since(s.last) < OBSERVED_TTL);
            if self.observed.len() >= MAX_OBSERVED {
                let oldest = self
                    .observed
                    .iter()
                    .min_by_key(|(a, s)| (s.last, (*a).clone()))
                    .map(|(a, _)| a.clone());
                if let Some(oldest) = oldest {
                    self.observed.remove(&oldest);
                }
            }
        }
        let seen = self.observed.entry(address).or_insert(Seen {
            by_relay: false,
            observers: Vec::new(),
            last: now,
        });
        seen.by_relay |= by_relay;
        seen.last = now;
        if !seen.observers.contains(&observer) && seen.observers.len() < MAX_OBSERVERS {
            seen.observers.push(observer);
        }
    }

    /// The address this host sends IPv6 from (RFC 6724 source selection,
    /// usually a temporary one): once known, the only own IPv6 address
    /// offered.
    pub fn set_preferred_v6(&mut self, ip: Option<Ipv6Addr>) {
        self.preferred_v6 = ip;
    }

    /// Listen and external address changes, and the swarm's candidates.
    pub fn on_swarm_event(&mut self, event: &FromSwarm<'_>) {
        match event {
            FromSwarm::NewListenAddr(e) => {
                if let Some(a) = self.usable(e.addr) {
                    self.listen.insert(a);
                }
            }
            FromSwarm::ExpiredListenAddr(e) => {
                if let Some(a) = self.usable(e.addr) {
                    self.listen.remove(&a);
                }
            }
            FromSwarm::ExternalAddrConfirmed(e) => {
                if let Some(a) = self.usable(e.addr) {
                    if !self.confirmed.contains(&a) {
                        self.confirmed.push(a);
                    }
                }
            }
            FromSwarm::ExternalAddrExpired(e) => {
                if let Some(a) = self.usable(e.addr) {
                    self.confirmed.retain(|c| *c != a);
                }
            }
            // While restricted, Identify's guess may name the proxy's egress
            // IP: not kept for later.
            FromSwarm::NewExternalAddrCandidate(_) if self.restricted() => {}
            FromSwarm::NewExternalAddrCandidate(e) => {
                if let Some(a) = self.usable(e.addr) {
                    self.other.retain(|o| *o != a);
                    self.other.push_front(a);
                    self.other.truncate(MAX_OTHER);
                }
            }
            _ => {}
        }
    }

    /// The five tiers, highest first (see the module doc); all empty while
    /// restricted.
    fn tiers(&self, now: Instant) -> [Vec<Multiaddr>; 5] {
        if self.restricted() {
            return Default::default();
        }
        let mut v6_ips: Vec<IpAddr> = Vec::new();
        let ipv6 = self
            .listen
            .iter()
            .filter(|a| match (addr_ip(a), self.preferred_v6) {
                (Some(IpAddr::V6(ip)), Some(preferred)) => ip == preferred,
                (Some(ip @ IpAddr::V6(_)), None) => {
                    if !v6_ips.contains(&ip) {
                        if v6_ips.len() >= MAX_V6_IPS {
                            return false;
                        }
                        v6_ips.push(ip);
                    }
                    true
                }
                _ => false,
            })
            .cloned()
            .collect();
        let mut observed: Vec<(&Multiaddr, &Seen)> = self
            .observed
            .iter()
            .filter(|(_, s)| s.trusted() && now.saturating_duration_since(s.last) < OBSERVED_TTL)
            .collect();
        // A relay's word first, then the most agreement, then the newest.
        observed.sort_by(|(a, x), (b, y)| {
            (y.by_relay, y.observers.len(), y.last, *b).cmp(&(
                x.by_relay,
                x.observers.len(),
                x.last,
                *a,
            ))
        });
        let listen_v4 = self
            .listen
            .iter()
            .filter(|a| matches!(addr_ip(a), Some(IpAddr::V4(_))))
            .cloned()
            .collect();
        [
            self.confirmed.clone(),
            ipv6,
            observed.into_iter().map(|(a, _)| a.clone()).collect(),
            listen_v4,
            self.other.iter().cloned().collect(),
        ]
    }

    /// What a hole punch offers now, best first: the tiers in order,
    /// deduplicated (the highest tier wins), every QUIC address before every
    /// TCP one, at most [`MAX_CANDIDATES`]. Nothing while restricted.
    pub fn candidates(&self, now: Instant) -> Vec<Multiaddr> {
        let mut out: Vec<Multiaddr> = Vec::new();
        for a in self.tiers(now).into_iter().flatten() {
            if !out.contains(&a) {
                out.push(a);
            }
        }
        // Stable: within each transport the tier order stays.
        out.sort_by_key(|a| !a.iter().any(|p| matches!(p, Protocol::QuicV1)));
        out.truncate(MAX_CANDIDATES);
        out
    }

    /// Counts per tier (no address), for a log line: what is offered, so
    /// all zero while restricted.
    pub fn counts(&self, now: Instant) -> CandidateCounts {
        let [mapped, ipv6, observed, listen, other] = self.tiers(now).map(|t| t.len());
        CandidateCounts {
            mapped,
            ipv6,
            observed,
            listen,
            other,
        }
    }
}

#[cfg(test)]
mod tests {
    use libp2p::core::transport::ListenerId;
    use libp2p::identity::Keypair;
    use libp2p::swarm::behaviour::{
        ExpiredListenAddr, ExternalAddrConfirmed, ExternalAddrExpired, NewExternalAddrCandidate,
        NewListenAddr,
    };

    use super::*;

    fn peer(seed: u8) -> PeerId {
        Keypair::ed25519_from_bytes([seed; 32])
            .unwrap()
            .public()
            .to_peer_id()
    }

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    fn addrs(list: &[&str]) -> Vec<Multiaddr> {
        list.iter().map(|a| addr(a)).collect()
    }

    fn listen(book: &mut CandidateBook, a: &str) {
        let a = addr(a);
        book.on_swarm_event(&FromSwarm::NewListenAddr(NewListenAddr {
            listener_id: ListenerId::next(),
            addr: &a,
        }));
    }

    fn unlisten(book: &mut CandidateBook, a: &str) {
        let a = addr(a);
        book.on_swarm_event(&FromSwarm::ExpiredListenAddr(ExpiredListenAddr {
            listener_id: ListenerId::next(),
            addr: &a,
        }));
    }

    fn confirmed(book: &mut CandidateBook, a: &str) {
        let a = addr(a);
        book.on_swarm_event(&FromSwarm::ExternalAddrConfirmed(ExternalAddrConfirmed {
            addr: &a,
        }));
    }

    fn swarm_candidate(book: &mut CandidateBook, a: &str) {
        let a = addr(a);
        book.on_swarm_event(&FromSwarm::NewExternalAddrCandidate(
            NewExternalAddrCandidate { addr: &a },
        ));
    }

    #[test]
    fn the_identify_rewrite_never_leads() {
        let now = Instant::now();
        let relay = peer(1);
        let mut book = CandidateBook::new(AddrRule::GlobalOnly);
        // Identify's guess (the observed IP with our listen port) arrives
        // first, as it does on a live swarm; the raw observation after it.
        swarm_candidate(&mut book, "/ip4/11.0.1.2/tcp/7423");
        book.observed(relay, &addr("/ip4/11.0.1.2/tcp/30000"), true, now);
        assert_eq!(
            book.candidates(now),
            addrs(&["/ip4/11.0.1.2/tcp/30000", "/ip4/11.0.1.2/tcp/7423"])
        );
        assert_eq!(
            book.counts(now),
            CandidateCounts {
                observed: 1,
                other: 1,
                ..CandidateCounts::default()
            }
        );
        assert_eq!(
            book.counts(now).to_string(),
            "0 mapped, 0 ipv6, 1 observed, 0 listen, 1 other"
        );
    }

    #[test]
    fn mapped_and_confirmed_come_first_and_quic_before_tcp() {
        let now = Instant::now();
        let mut book = CandidateBook::new(AddrRule::GlobalOnly);
        swarm_candidate(&mut book, "/ip4/8.8.4.4/udp/7423/quic-v1");
        swarm_candidate(&mut book, "/ip4/8.8.4.4/tcp/7423");
        listen(&mut book, "/ip4/9.9.9.9/tcp/7423");
        book.observed(peer(1), &addr("/ip4/8.8.8.8/tcp/40000"), true, now);
        confirmed(&mut book, "/ip4/1.1.1.1/tcp/7423");
        confirmed(&mut book, "/ip4/1.1.1.1/udp/7423/quic-v1");
        assert_eq!(
            book.candidates(now),
            addrs(&[
                "/ip4/1.1.1.1/udp/7423/quic-v1",
                "/ip4/8.8.4.4/udp/7423/quic-v1",
                "/ip4/1.1.1.1/tcp/7423",
                "/ip4/8.8.8.8/tcp/40000",
                "/ip4/9.9.9.9/tcp/7423",
                "/ip4/8.8.4.4/tcp/7423",
            ])
        );
        // An expired confirmation (a lost UPnP mapping) is withdrawn.
        let gone = addr("/ip4/1.1.1.1/tcp/7423");
        book.on_swarm_event(&FromSwarm::ExternalAddrExpired(ExternalAddrExpired {
            addr: &gone,
        }));
        assert!(!book.candidates(now).contains(&gone));
        assert_eq!(book.counts(now).mapped, 1);
    }

    #[test]
    fn lan_loopback_linklocal_ula_cgnat_dns_and_circuits_are_never_offered() {
        let now = Instant::now();
        let relay = peer(1);
        let circuit = format!("/ip4/8.8.8.8/tcp/7423/p2p/{relay}/p2p-circuit");
        let local = [
            "/ip4/192.168.1.2/tcp/7423",
            "/ip4/10.0.0.2/udp/7423/quic-v1",
            "/ip4/172.16.0.9/tcp/7423",
            "/ip4/127.0.0.1/tcp/7423",
            "/ip4/100.64.0.1/tcp/7423",
            "/ip6/::1/udp/7423/quic-v1",
            "/ip6/fe80::1/tcp/7423",
            "/ip6/fd00::1/tcp/7423",
        ];
        let never = [
            circuit.as_str(),
            "/dns4/example.com/tcp/7423",
            "/dns6/example.com/udp/7423/quic-v1",
            "/ip4/0.0.0.0/tcp/7423",
            "/ip6/::/udp/7423/quic-v1",
            "/ip4/224.0.0.1/udp/7423/quic-v1",
            "/ip4/8.8.8.8/tcp/7423/ws",
            "/ip4/8.8.8.8/udp/7423/quic",
            "/ip4/8.8.8.8/udp/7423",
        ];
        for rule in [AddrRule::GlobalOnly, AddrRule::LabAnyIp] {
            let mut book = CandidateBook::new(rule);
            for a in local.iter().chain(&never) {
                listen(&mut book, a);
                confirmed(&mut book, a);
                swarm_candidate(&mut book, a);
                book.observed(relay, &addr(a), true, now);
            }
            let offered = book.candidates(now);
            for a in never {
                assert!(!offered.contains(&addr(a)), "{rule:?} offered {a}");
            }
            assert!(offered.iter().all(|a| !crate::host::is_circuit(a)));
            match rule {
                AddrRule::GlobalOnly => assert!(offered.is_empty(), "{offered:?}"),
                // The debug lab admits loopback and private, never the rest.
                AddrRule::LabAnyIp => {
                    assert_eq!(offered.len(), MAX_CANDIDATES, "{offered:?}");
                    assert!(offered
                        .iter()
                        .all(|a| local.contains(&a.to_string().as_str())));
                }
            }
        }
    }

    /// WSS forms (RWS1 §2), WebTransport / WebRTC `/certhash` addresses and
    /// circuits are never offered, by either rule and from any tier; the
    /// plain address with the same IP and port is (the layers are refused,
    /// not the IP).
    #[test]
    fn candidate_book_refuses_wss_sni_certhash_and_circuit_addresses() {
        use libp2p::multiaddr::multihash::Multihash;

        let now = Instant::now();
        let (relay, me) = (peer(1), peer(9));
        let certhash = Protocol::Certhash(Multihash::wrap(0x12, &[7; 32]).unwrap());
        for (rule, ip4, ip6) in [
            (AddrRule::GlobalOnly, "8.8.8.8", "2001:4860::8888"),
            (AddrRule::LabAnyIp, "127.0.0.1", "::1"),
        ] {
            let never: Vec<Multiaddr> = vec![
                addr(&format!("/ip4/{ip4}/tcp/443/tls/ws")),
                addr(&format!("/ip4/{ip4}/tcp/443/tls/sni/relay.example.org/ws")),
                addr(&format!("/ip4/{ip4}/tcp/443/tls/ws/p2p/{relay}")),
                addr(&format!("/ip6/{ip6}/tcp/443/tls/ws")),
                addr(&format!("/ip4/{ip4}/tcp/443/wss")),
                addr(&format!("/ip4/{ip4}/tcp/443/tls")),
                addr(&format!("/ip4/{ip4}/tcp/443/sni/relay.example.org")),
                addr(&format!("/ip4/{ip4}/tcp/443/ws")),
                addr(&format!("/ip4/{ip4}/udp/443/quic-v1/webtransport")).with(certhash.clone()),
                addr(&format!("/ip4/{ip4}/udp/443/webrtc-direct")).with(certhash.clone()),
                addr(&format!("/ip4/{ip4}/udp/443/quic-v1")).with(certhash.clone()),
                addr(&format!("/ip4/{ip4}/tcp/443/p2p/{relay}/p2p-circuit")),
                addr(&format!(
                    "/ip4/{ip4}/tcp/443/p2p/{relay}/p2p-circuit/p2p/{me}"
                )),
                addr(&format!(
                    "/ip4/{ip4}/udp/443/quic-v1/p2p/{relay}/p2p-circuit"
                )),
                addr(&format!(
                    "/ip4/{ip4}/tcp/443/tls/ws/p2p/{relay}/p2p-circuit"
                )),
                addr(&format!("/p2p/{relay}/p2p-circuit")),
            ];
            let plain = addr(&format!("/ip4/{ip4}/tcp/443"));
            let mut book = CandidateBook::new(rule);
            for a in &never {
                assert!(book.usable(a).is_none(), "{rule:?} admits {a}");
                let s = a.to_string();
                listen(&mut book, &s);
                confirmed(&mut book, &s);
                swarm_candidate(&mut book, &s);
                book.observed(relay, a, true, now);
                book.observed(peer(2), a, false, now);
                book.observed(peer(3), a, false, now);
            }
            assert!(book.candidates(now).is_empty(), "{rule:?}");
            assert_eq!(book.counts(now), CandidateCounts::default());
            assert!(book.observed.is_empty() && book.other.is_empty());
            // The same IP and port, plain: offered.
            book.observed(relay, &plain, true, now);
            assert_eq!(book.candidates(now), vec![plain], "{rule:?}");
        }
    }

    /// While the restricted-network flag is set (RWS1 §9) nothing is offered
    /// and Identify's guesses are not recorded (through a proxy they carry
    /// the proxy's egress IP); once it clears, everything else the book
    /// holds, including what arrived meanwhile, is offered again.
    #[test]
    fn candidates_are_empty_while_restricted_and_return_after() {
        let now = Instant::now();
        let relay = peer(1);
        let flag = Arc::new(AtomicBool::new(false));
        let mut book = CandidateBook::new(AddrRule::GlobalOnly).with_restricted(flag.clone());
        assert!(!book.restricted());
        confirmed(&mut book, "/ip4/1.1.1.1/tcp/7423");
        listen(&mut book, "/ip6/2a02:db8:1::10/udp/7423/quic-v1");
        book.observed(relay, &addr("/ip4/8.8.8.8/tcp/30000"), true, now);
        listen(&mut book, "/ip4/9.9.9.9/tcp/7423");
        swarm_candidate(&mut book, "/ip4/8.8.4.4/tcp/7423");
        let before = book.candidates(now);
        assert_eq!(
            before,
            addrs(&[
                "/ip6/2a02:db8:1::10/udp/7423/quic-v1",
                "/ip4/1.1.1.1/tcp/7423",
                "/ip4/8.8.8.8/tcp/30000",
                "/ip4/9.9.9.9/tcp/7423",
                "/ip4/8.8.4.4/tcp/7423",
            ])
        );
        let counts = book.counts(now);

        flag.store(true, Ordering::SeqCst);
        assert!(book.restricted());
        assert!(book.candidates(now).is_empty());
        assert_eq!(book.counts(now), CandidateCounts::default());
        // Identify's rewrite of the proxy's egress IP: dropped, not kept for
        // later. A raw observation is still recorded (a WSS one is refused).
        swarm_candidate(&mut book, "/ip4/11.0.1.2/tcp/7423");
        book.observed(relay, &addr("/ip4/11.0.1.2/tcp/41000/tls/ws"), true, now);
        book.observed(relay, &addr("/ip4/8.8.8.8/tcp/31000"), true, now);
        assert!(book.candidates(now).is_empty());

        flag.store(false, Ordering::SeqCst);
        assert!(!book.restricted());
        let after = book.candidates(now);
        assert!(
            !after.contains(&addr("/ip4/11.0.1.2/tcp/7423")),
            "{after:?}"
        );
        assert!(after.contains(&addr("/ip4/8.8.8.8/tcp/31000")), "{after:?}");
        assert_eq!(
            after
                .into_iter()
                .filter(|a| *a != addr("/ip4/8.8.8.8/tcp/31000"))
                .collect::<Vec<_>>(),
            before
        );
        assert_eq!(
            book.counts(now),
            CandidateCounts {
                observed: 2,
                ..counts
            }
        );
        // A book without a flag is never restricted.
        assert!(!CandidateBook::new(AddrRule::GlobalOnly).restricted());
    }

    #[test]
    fn ipv6_offers_only_the_preferred_source_when_known() {
        let now = Instant::now();
        let mut book = CandidateBook::new(AddrRule::GlobalOnly);
        for a in [
            "/ip6/2a02:db8:1::10/tcp/7423",
            "/ip6/2a02:db8:1::10/udp/7423/quic-v1",
            "/ip6/2a02:db8:1::20/tcp/7423",
            "/ip6/2a02:db8:1::30/tcp/7423",
            "/ip6/fe80::1/tcp/7423",
        ] {
            listen(&mut book, a);
        }
        // Unknown preferred source: at most two IPs (both transports of one).
        assert_eq!(
            book.candidates(now),
            addrs(&[
                "/ip6/2a02:db8:1::10/udp/7423/quic-v1",
                "/ip6/2a02:db8:1::10/tcp/7423",
                "/ip6/2a02:db8:1::20/tcp/7423",
            ])
        );
        book.set_preferred_v6(Some("2a02:db8:1::30".parse().unwrap()));
        assert_eq!(
            book.candidates(now),
            addrs(&["/ip6/2a02:db8:1::30/tcp/7423"])
        );
        assert_eq!(book.counts(now).ipv6, 1);
        // Known, but not one this host listens on: no own IPv6 at all.
        book.set_preferred_v6(Some("2a02:db8:1::99".parse().unwrap()));
        assert!(book.candidates(now).is_empty());
        book.set_preferred_v6(None);
        unlisten(&mut book, "/ip6/2a02:db8:1::10/tcp/7423");
        unlisten(&mut book, "/ip6/2a02:db8:1::10/udp/7423/quic-v1");
        assert_eq!(
            book.candidates(now),
            addrs(&[
                "/ip6/2a02:db8:1::20/tcp/7423",
                "/ip6/2a02:db8:1::30/tcp/7423"
            ])
        );
    }

    #[test]
    fn one_contacts_observation_is_not_enough_but_a_relays_or_two_peers_are() {
        let now = Instant::now();
        let (relay, c1, c2) = (peer(1), peer(2), peer(3));
        let mut book = CandidateBook::new(AddrRule::GlobalOnly);
        let lone = addr("/ip4/8.8.8.8/tcp/31000");
        book.observed(c1, &lone, false, now);
        book.observed(c1, &lone, false, now);
        assert!(book.candidates(now).is_empty(), "one peer, twice");
        book.observed(c2, &lone, false, now);
        assert_eq!(book.candidates(now), vec![lone.clone()]);
        let by_relay = addr("/ip4/8.8.8.8/tcp/32000");
        book.observed(relay, &by_relay, true, now);
        assert_eq!(book.candidates(now), vec![by_relay, lone]);
        assert_eq!(book.counts(now).observed, 2);
    }

    #[test]
    fn observations_expire_after_ttl() {
        let t0 = Instant::now();
        let relay = peer(1);
        let mut book = CandidateBook::new(AddrRule::GlobalOnly);
        let seen = addr("/ip4/8.8.8.8/tcp/30000");
        book.observed(relay, &seen, true, t0);
        assert_eq!(book.candidates(t0 + OBSERVED_TTL / 2), vec![seen.clone()]);
        assert!(book.candidates(t0 + OBSERVED_TTL).is_empty());
        // Reported again: it counts again.
        book.observed(relay, &seen, true, t0 + OBSERVED_TTL);
        assert_eq!(book.candidates(t0 + OBSERVED_TTL), vec![seen]);
        // A full table makes room by dropping the expired, then the oldest.
        let mut full = CandidateBook::new(AddrRule::GlobalOnly);
        for port in 0..MAX_OBSERVED as u16 {
            let a = addr(&format!("/ip4/8.8.8.8/tcp/{}", 1000 + port));
            full.observed(relay, &a, true, t0 + Duration::from_secs(u64::from(port)));
        }
        let later = t0 + Duration::from_secs(MAX_OBSERVED as u64);
        full.observed(relay, &addr("/ip4/8.8.8.8/tcp/9999"), true, later);
        assert_eq!(full.observed.len(), MAX_OBSERVED);
        assert!(!full.observed.contains_key(&addr("/ip4/8.8.8.8/tcp/1000")));
        assert!(full.observed.contains_key(&addr("/ip4/8.8.8.8/tcp/9999")));
    }

    #[test]
    fn the_list_is_bounded_deduplicated_and_p2p_suffix_free() {
        let now = Instant::now();
        let me = peer(9);
        let mut book = CandidateBook::new(AddrRule::GlobalOnly);
        // The same address in three tiers, once with our own /p2p suffix.
        confirmed(&mut book, &format!("/ip4/1.1.1.1/tcp/7423/p2p/{me}"));
        swarm_candidate(&mut book, "/ip4/1.1.1.1/tcp/7423");
        book.observed(peer(1), &addr("/ip4/1.1.1.1/tcp/7423"), true, now);
        assert_eq!(book.candidates(now), addrs(&["/ip4/1.1.1.1/tcp/7423"]));
        // Port 0 is never a candidate.
        swarm_candidate(&mut book, "/ip4/1.1.1.2/tcp/0");
        swarm_candidate(&mut book, "/ip4/1.1.1.2/udp/0/quic-v1");
        assert_eq!(book.candidates(now).len(), 1);
        // Swarm candidates: the newest four.
        for port in 1..=6u16 {
            swarm_candidate(&mut book, &format!("/ip4/2.2.2.2/tcp/{port}"));
        }
        assert_eq!(book.counts(now).other, MAX_OTHER);
        for port in 1..=20u16 {
            confirmed(&mut book, &format!("/ip4/3.3.3.3/tcp/{port}"));
        }
        let offered = book.candidates(now);
        assert_eq!(offered.len(), MAX_CANDIDATES);
        assert_eq!(offered[0], addr("/ip4/1.1.1.1/tcp/7423"));
        let mut unique = offered.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), offered.len());
        assert!(offered
            .iter()
            .all(|a| !a.iter().any(|p| matches!(p, Protocol::P2p(_)))));
    }
}
