//! What this host's NAT does to its outbound mappings, and whether a hole
//! punch with a contact can work at all (Phase 4, PortMap design P4.10 /
//! P4.11; owner decisions O4-6 and O4-7). Pure: no sockets, no clock of its
//! own, no swarm; raven-node feeds it and `gate::HolePunch` asks it.
//!
//! **Classifier** ([`NatClassifier`]). An observation is the external
//! address a peer saw on one direct outbound connection (Identify's raw
//! `observed_addr`), kept only when the connection
//! - was dialled by us (`ConnectedPoint::Dialer`) with
//!   `PortUse::Reuse` while a listener of that family is open, so its
//!   source port is the listen port and the observed port says what the NAT
//!   did to it;
//! - is a raw `/ip4|ip6/…/tcp/<port>` or `/ip4|ip6/…/udp/<port>/quic-v1`
//!   connection: never a circuit (`/p2p-circuit`: the relay's address, not
//!   ours) and never a WSS form (`/tls`, `/sni`, `/ws`, `/wss`: a TLS or
//!   proxied path whose source port and egress belong to someone else);
//! - goes to a globally routable peer, whose network ([`NetGroup`]: its /24
//!   or /48) is the observer.
//!
//! Who may observe (own relays and contacts) is the caller's rule. At most
//! [`MAX_OBS`] observations per transport and family are kept, each for
//! [`OBS_TTL`]. Two observations are compared only when they come from
//! different networks and their connections were open at the same time (a
//! NAT may reuse or move a mapping once the first connection is gone):
//! - the same external address on both: stable (`stable_kept` on the
//!   listen port, `stable_shifted` on another one);
//! - different addresses: `varies` (the mapping depends on the
//!   destination, so a hole punch cannot guess it; D13: no port
//!   prediction);
//! - one network, or one observer: `unknown`. With a single relay (the
//!   common case) the class stays unknown and only the "two failures" rule
//!   below skips punches.
//!
//! An own address seen on the listen port is `no_nat`. A lying observer can
//! only force `varies`, which removes hole punching on this network until
//! the next re-home; relays still deliver.
//!
//! **Punch policy** ([`PunchPolicy`]). A hole punch with a contact is
//! hopeless when both sides' IPv4 mappings vary (the contact's from its
//! RRH1 route hint, while the hint is fresh) and the two do not both have a
//! global IPv6 address, or after two failed punches with that contact on
//! this network (held [`FAIL_HOLD`]). The endpoint builds a fresh policy
//! for every network (Phase 0b re-home), so a network change resets it.
//! Disabled (the NAT_CLASS gate shut: `NAT_CLASS_PRODUCTION_ENABLED=false`)
//! it never skips, which is Phase 1's behaviour.
//!
//! **Lab.** `RAVEN_LAB_NAT_CLASS_FORCE` ([`raven_core::portmap_gate::lab_nat_class_force`])
//! overrides the policy's own class in debug builds with the lab unlock
//! only: harnesses on one computer have no second network to observe from.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use libp2p::core::transport::PortUse;
use libp2p::core::ConnectedPoint;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::ConnectionId;
use libp2p::{Multiaddr, PeerId};
use raven_core::portmap_gate::LabNatClass;
use raven_core::route_hints::{NatClass, NAT_FLAG_V6_GLOBAL, NAT_FLAG_V6_OPEN};

use crate::host::{is_circuit, is_wss_form, net_group, NetGroup};

/// How long one observation counts.
pub const OBS_TTL: Duration = Duration::from_secs(600);
/// Observations kept per transport and address family (oldest dropped).
pub const MAX_OBS: usize = 8;
/// How long two failed punches with a contact skip further ones.
pub const FAIL_HOLD: Duration = Duration::from_secs(6 * 3600);
/// Contacts the policy remembers a class or failures for (the expired and
/// then the oldest entries go first).
pub const MAX_PEERS: usize = 1024;

/// What a NAT does to an outbound mapping, as far as this host knows.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Mapping {
    /// Not enough evidence (fewer than two networks observed together).
    #[default]
    Unknown,
    /// An own address seen on the listen port: no NAT in the way.
    NoNat,
    /// One external address for every destination, on the listen port.
    StableKept,
    /// One external address for every destination, on another port.
    StableShifted,
    /// The external address depends on the destination.
    Varies,
}

impl Mapping {
    /// The word logs, status and the lab switch use.
    pub fn word(self) -> &'static str {
        match self {
            Mapping::Unknown => "unknown",
            Mapping::NoNat => "no_nat",
            Mapping::StableKept => "stable_kept",
            Mapping::StableShifted => "stable_shifted",
            Mapping::Varies => "varies",
        }
    }

    /// The class code of RRH1 NAT_CLASS (spec §13.1).
    pub fn code(self) -> u8 {
        match self {
            Mapping::Unknown => 0,
            Mapping::NoNat => 1,
            Mapping::StableKept => 2,
            Mapping::StableShifted => 3,
            Mapping::Varies => 4,
        }
    }

    /// A NAT_CLASS class code; an unknown one is `Unknown`.
    pub fn from_code(code: u8) -> Self {
        match code {
            1 => Mapping::NoNat,
            2 => Mapping::StableKept,
            3 => Mapping::StableShifted,
            4 => Mapping::Varies,
            _ => Mapping::Unknown,
        }
    }

    /// How promising a mapping is for a direct connection; `Unknown` is no
    /// evidence at all and ranks below everything.
    fn rank(self) -> u8 {
        match self {
            Mapping::Unknown => 0,
            Mapping::Varies => 1,
            Mapping::StableShifted => 2,
            Mapping::StableKept => 3,
            Mapping::NoNat => 4,
        }
    }

    /// The best known of two transports' mappings: `Varies` only when every
    /// known one varies, `Unknown` only when neither is known.
    fn best(a: Mapping, b: Mapping) -> Mapping {
        if b.rank() > a.rank() {
            b
        } else {
            a
        }
    }
}

impl From<LabNatClass> for Mapping {
    fn from(c: LabNatClass) -> Self {
        match c {
            LabNatClass::Varies => Mapping::Varies,
            LabNatClass::StableKept => Mapping::StableKept,
            LabNatClass::StableShifted => Mapping::StableShifted,
            LabNatClass::NoNat => Mapping::NoNat,
        }
    }
}

/// The transport a mapping belongs to (a NAT may treat TCP and UDP apart).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Tr {
    Tcp,
    Quic,
}

/// One host's NAT knowledge: per transport and family, plus whether it has
/// a global IPv6 address of its own. Sent to contacts in RRH1 (NAT_CLASS
/// TLV, behind the NAT_CLASS gate) and read back from theirs.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct NatSummary {
    pub v4_tcp: Mapping,
    pub v4_quic: Mapping,
    pub v6_tcp: Mapping,
    pub v6_quic: Mapping,
    /// The host has a globally routable IPv6 address of its own.
    pub v6_global: bool,
}

impl NatSummary {
    /// The IPv4 mapping: the best known of TCP and QUIC, so `Varies` only
    /// when every known transport varies.
    pub fn v4(&self) -> Mapping {
        Mapping::best(self.v4_tcp, self.v4_quic)
    }

    /// The IPv6 mapping, by the same rule.
    pub fn v6(&self) -> Mapping {
        Mapping::best(self.v6_tcp, self.v6_quic)
    }

    /// The RRH1 NAT_CLASS value of this summary; `v6_open`: an IPv6 pinhole
    /// is confirmed (flags bit 1).
    pub fn to_wire(&self, v6_open: bool) -> NatClass {
        let mut flags = 0;
        if self.v6_global {
            flags |= NAT_FLAG_V6_GLOBAL;
        }
        if v6_open {
            flags |= NAT_FLAG_V6_OPEN;
        }
        NatClass {
            v4_tcp: self.v4_tcp.code(),
            v4_quic: self.v4_quic.code(),
            v6_tcp: self.v6_tcp.code(),
            v6_quic: self.v6_quic.code(),
            flags,
        }
    }

    /// A contact's summary from its RRH1 NAT_CLASS.
    pub fn from_wire(c: &NatClass) -> Self {
        NatSummary {
            v4_tcp: Mapping::from_code(c.v4_tcp),
            v4_quic: Mapping::from_code(c.v4_quic),
            v6_tcp: Mapping::from_code(c.v6_tcp),
            v6_quic: Mapping::from_code(c.v6_quic),
            v6_global: c.flags & NAT_FLAG_V6_GLOBAL != 0,
        }
    }

    /// Every class replaced by `m` (`v6_global` kept).
    fn forced(self, m: Mapping) -> Self {
        NatSummary {
            v4_tcp: m,
            v4_quic: m,
            v6_tcp: m,
            v6_quic: m,
            v6_global: self.v6_global,
        }
    }
}

/// One peer's view of our external address on one connection.
#[derive(Clone, Copy, Debug)]
struct Obs {
    conn: ConnectionId,
    group: NetGroup,
    ext: SocketAddr,
    opened: Instant,
    closed: Option<Instant>,
    seen: Instant,
}

impl Obs {
    fn fresh(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.seen) < OBS_TTL
    }

    /// Were both connections open at some moment?
    fn overlaps(&self, other: &Obs) -> bool {
        let before = |a: &Obs, b: &Obs| a.closed.is_some_and(|c| c < b.opened);
        !before(self, other) && !before(other, self)
    }
}

/// The NAT mapping classifier (module doc). One per endpoint: a network
/// change rebuilds the endpoint, and the old network's evidence goes with
/// it.
#[derive(Debug, Default)]
pub struct NatClassifier {
    obs: HashMap<(Tr, bool), VecDeque<Obs>>,
    own: Vec<IpAddr>,
    listen_port: HashMap<(Tr, bool), u16>,
}

impl NatClassifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// The port of the open listener of `tr` and family (`v6`), or `None`
    /// when it closed (its observations go: no connection can reuse it).
    pub fn set_listen_port(&mut self, tr: Tr, v6: bool, port: Option<u16>) {
        match port {
            Some(p) if p != 0 => {
                self.listen_port.insert((tr, v6), p);
            }
            _ => {
                self.listen_port.remove(&(tr, v6));
                self.obs.remove(&(tr, v6));
            }
        }
    }

    /// This host's own interface addresses (for `no_nat` and `v6_global`).
    pub fn set_own_addrs(&mut self, addrs: impl IntoIterator<Item = IpAddr>) {
        self.own = addrs.into_iter().map(|ip| ip.to_canonical()).collect();
        self.own.sort();
        self.own.dedup();
    }

    /// Record that the peer on connection `conn` (`endpoint`, opened at
    /// `opened`) saw us as `observed`. Anything but a direct outbound
    /// connection that reused the listen port, to a globally routable peer
    /// over raw TCP or QUIC, is ignored (module doc); so is an observation
    /// of another transport or family than the connection's. A later
    /// observation on the same connection replaces the earlier one. Returns
    /// whether it was recorded.
    pub fn observed(
        &mut self,
        conn: ConnectionId,
        endpoint: &ConnectedPoint,
        observed: &Multiaddr,
        opened: Instant,
        now: Instant,
    ) -> bool {
        let ConnectedPoint::Dialer {
            address,
            port_use: PortUse::Reuse,
            ..
        } = endpoint
        else {
            return false;
        };
        let Some((tr, remote)) = raw_endpoint(address) else {
            return false;
        };
        let Some((ext_tr, ext)) = raw_endpoint(observed) else {
            return false;
        };
        let v6 = remote.is_ipv6();
        if ext_tr != tr || ext.is_ipv6() != v6 || ext.port() == 0 {
            return false;
        }
        if !self.listen_port.contains_key(&(tr, v6)) {
            return false;
        }
        let Some(group) = net_group(remote.ip()) else {
            return false;
        };
        let list = self.obs.entry((tr, v6)).or_default();
        list.retain(|o| o.fresh(now) && o.conn != conn);
        while list.len() >= MAX_OBS {
            list.pop_front();
        }
        list.push_back(Obs {
            conn,
            group,
            ext,
            opened,
            closed: None,
            seen: now,
        });
        true
    }

    /// Connection `conn` closed at `now`. Its observation still counts
    /// (until [`OBS_TTL`]) against those whose connections overlapped it.
    pub fn closed(&mut self, conn: ConnectionId, now: Instant) {
        for o in self.obs.values_mut().flat_map(|l| l.iter_mut()) {
            if o.conn == conn && o.closed.is_none() {
                o.closed = Some(now);
            }
        }
    }

    /// The mapping class of `tr` over IPv4 (`v6` false) or IPv6.
    pub fn class(&self, tr: Tr, v6: bool, now: Instant) -> Mapping {
        let lp = self.listen_port.get(&(tr, v6)).copied();
        let fresh: Vec<&Obs> = self
            .obs
            .get(&(tr, v6))
            .map(|l| l.iter().filter(|o| o.fresh(now)).collect())
            .unwrap_or_default();
        if fresh
            .iter()
            .any(|o| self.own.contains(&o.ext.ip()) && Some(o.ext.port()) == lp)
        {
            return Mapping::NoNat;
        }
        let (mut agree, mut differ) = (false, false);
        for (i, a) in fresh.iter().enumerate() {
            for b in &fresh[i + 1..] {
                if a.group == b.group || !a.overlaps(b) {
                    continue;
                }
                if a.ext == b.ext {
                    agree = true;
                } else {
                    differ = true;
                }
            }
        }
        match (agree, differ) {
            (_, true) => Mapping::Varies,
            (true, false) if fresh.iter().all(|o| Some(o.ext.port()) == lp) => Mapping::StableKept,
            (true, false) => Mapping::StableShifted,
            (false, false) => Mapping::Unknown,
        }
    }

    /// All four classes and the global IPv6 flag.
    pub fn summary(&self, now: Instant) -> NatSummary {
        NatSummary {
            v4_tcp: self.class(Tr::Tcp, false, now),
            v4_quic: self.class(Tr::Quic, false, now),
            v6_tcp: self.class(Tr::Tcp, true, now),
            v6_quic: self.class(Tr::Quic, true, now),
            v6_global: self
                .own
                .iter()
                .any(|ip| matches!(net_group(*ip), Some(NetGroup::V6(_)))),
        }
    }

    /// How many networks the fresh observations come from (for the
    /// counts-only log line).
    pub fn networks(&self, now: Instant) -> usize {
        let mut groups: Vec<NetGroup> = self
            .obs
            .values()
            .flat_map(|l| l.iter())
            .filter(|o| o.fresh(now))
            .map(|o| o.group)
            .collect();
        groups.sort();
        groups.dedup();
        groups.len()
    }
}

/// `/ip4|ip6/<ip>/tcp/<port>` or `/ip4|ip6/<ip>/udp/<port>/quic-v1`, with
/// at most a trailing `/p2p/<id>`: its transport and socket address
/// (canonical IP). Anything else (a circuit, a WSS form, a DNS name, other
/// transports) is `None`. The host uses it for its listen addresses.
pub fn raw_endpoint(address: &Multiaddr) -> Option<(Tr, SocketAddr)> {
    if is_circuit(address) || is_wss_form(address) {
        return None;
    }
    let mut it = address.iter();
    let ip = match it.next()? {
        Protocol::Ip4(a) => IpAddr::V4(a),
        Protocol::Ip6(a) => IpAddr::V6(a),
        _ => return None,
    };
    let (tr, port) = match (it.next()?, it.next()) {
        (Protocol::Tcp(port), None | Some(Protocol::P2p(_))) => (Tr::Tcp, port),
        (Protocol::Udp(port), Some(Protocol::QuicV1)) => match it.next() {
            None | Some(Protocol::P2p(_)) => (Tr::Quic, port),
            _ => return None,
        },
        _ => return None,
    };
    if it.next().is_some() {
        return None;
    }
    Some((tr, SocketAddr::new(ip.to_canonical(), port)))
}

/// Why a hole punch was skipped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SkipWhy {
    /// Both sides' IPv4 mappings vary, and they share no global IPv6.
    BothVary,
    /// Two punches with this contact failed on this network.
    FailedTwice,
}

/// The hole-punch skip rule (module doc). Fresh for every network.
#[derive(Debug, Default)]
pub struct PunchPolicy {
    /// This host's summary (see [`PunchPolicy::set_own`]).
    pub own: NatSummary,
    remote: HashMap<PeerId, (NatSummary, Instant)>,
    fails: HashMap<PeerId, (u8, Instant)>,
    /// Punches skipped so far.
    pub skipped: u64,
    /// The NAT_CLASS gate: when false, [`PunchPolicy::hopeless`] is always
    /// `None`.
    pub enabled: bool,
}

impl PunchPolicy {
    pub fn new(enabled: bool) -> Self {
        let mut policy = PunchPolicy {
            enabled,
            ..Self::default()
        };
        policy.set_own(NatSummary::default());
        policy
    }

    /// Should the hole punch with `peer` be skipped, and why?
    pub fn hopeless(&self, peer: &PeerId, now: Instant) -> Option<SkipWhy> {
        if !self.enabled {
            return None;
        }
        if let Some((n, at)) = self.fails.get(peer) {
            if *n >= 2 && now.saturating_duration_since(*at) < FAIL_HOLD {
                return Some(SkipWhy::FailedTwice);
            }
        }
        let (r, expiry) = self.remote.get(peer)?;
        if *expiry <= now {
            return None;
        }
        if self.own.v6_global && r.v6_global {
            return None;
        }
        (self.own.v4() == Mapping::Varies && r.v4() == Mapping::Varies).then_some(SkipWhy::BothVary)
    }

    /// A punch with `peer` failed at `now`.
    pub fn note_failure(&mut self, peer: PeerId, now: Instant) {
        if !self.fails.contains_key(&peer) {
            make_room(&mut self.fails, |(_, at)| {
                now.saturating_duration_since(*at) >= FAIL_HOLD
            });
        }
        let e = self.fails.entry(peer).or_insert((0, now));
        e.0 = e.0.saturating_add(1);
        e.1 = now;
    }

    /// A punch with `peer` succeeded: its failures are forgotten.
    pub fn note_success(&mut self, peer: &PeerId) {
        self.fails.remove(peer);
    }

    /// Forget every contact's summary (the route hints were read again).
    pub fn clear_remote(&mut self) {
        self.remote.clear();
    }

    /// `peer`'s summary from its route hint, valid until `expiry`.
    pub fn set_remote(&mut self, peer: PeerId, s: NatSummary, expiry: Instant) {
        if !self.remote.contains_key(&peer) {
            // The hints expiring first go first.
            make_room(&mut self.remote, |_| false);
        }
        self.remote.insert(peer, (s, expiry));
    }

    /// This host's summary; `RAVEN_LAB_NAT_CLASS_FORCE` replaces its
    /// classes in a debug build with the lab unlock.
    pub fn set_own(&mut self, s: NatSummary) {
        let force = if cfg!(debug_assertions) {
            raven_core::portmap_gate::lab_nat_class_force()
        } else {
            None
        };
        self.own = with_lab_force(s, force);
    }
}

/// `s` with every class replaced by `force`'s, if any.
fn with_lab_force(s: NatSummary, force: Option<LabNatClass>) -> NatSummary {
    match force {
        Some(c) => s.forced(c.into()),
        None => s,
    }
}

/// Keep `map` below [`MAX_PEERS`] before a new key goes in: drop the
/// `stale` entries, then the ones with the earliest instant.
fn make_room<V>(map: &mut HashMap<PeerId, (V, Instant)>, stale: impl Fn(&(V, Instant)) -> bool) {
    if map.len() < MAX_PEERS {
        return;
    }
    map.retain(|_, v| !stale(v));
    while map.len() >= MAX_PEERS {
        let Some(oldest) = map.iter().min_by_key(|(_, (_, at))| *at).map(|(p, _)| *p) else {
            break;
        };
        map.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::core::Endpoint;

    const LP: u16 = 7423;

    fn cid(n: usize) -> ConnectionId {
        ConnectionId::new_unchecked(n)
    }

    fn ma(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    fn dial(address: &str, port_use: PortUse) -> ConnectedPoint {
        ConnectedPoint::Dialer {
            address: ma(address),
            role_override: Endpoint::Dialer,
            port_use,
        }
    }

    fn reuse(address: &str) -> ConnectedPoint {
        dial(address, PortUse::Reuse)
    }

    /// A classifier with TCP and QUIC listeners on both families.
    fn listening() -> NatClassifier {
        let mut c = NatClassifier::new();
        for tr in [Tr::Tcp, Tr::Quic] {
            for v6 in [false, true] {
                c.set_listen_port(tr, v6, Some(LP));
            }
        }
        c
    }

    /// Observers on three different /24s, all globally routable.
    const R1: &str = "/ip4/8.8.8.8/tcp/7423";
    const R2: &str = "/ip4/9.9.9.9/tcp/7423";
    const R3: &str = "/ip4/1.1.1.1/tcp/7423";

    fn ext(port: u16) -> Multiaddr {
        ma(&format!("/ip4/203.0.113.9/tcp/{port}"))
    }

    #[test]
    fn two_groups_same_endpoint_is_stable_kept() {
        let t0 = Instant::now();
        let mut c = listening();
        assert!(c.observed(cid(1), &reuse(R1), &ext(LP), t0, t0));
        assert!(c.observed(cid(2), &reuse(R2), &ext(LP), t0, t0));
        assert_eq!(c.class(Tr::Tcp, false, t0), Mapping::StableKept);
        assert_eq!(c.class(Tr::Quic, false, t0), Mapping::Unknown);
        assert_eq!(c.class(Tr::Tcp, true, t0), Mapping::Unknown);
        assert_eq!(c.networks(t0), 2);
    }

    #[test]
    fn same_port_not_listen_port_is_stable_shifted() {
        let t0 = Instant::now();
        let mut c = listening();
        c.observed(cid(1), &reuse(R1), &ext(40_001), t0, t0);
        c.observed(cid(2), &reuse(R2), &ext(40_001), t0, t0);
        assert_eq!(c.class(Tr::Tcp, false, t0), Mapping::StableShifted);
    }

    #[test]
    fn two_groups_different_ports_is_varies() {
        let t0 = Instant::now();
        let mut c = listening();
        c.observed(cid(1), &reuse(R1), &ext(40_001), t0, t0);
        c.observed(cid(2), &reuse(R2), &ext(40_002), t0, t0);
        assert_eq!(c.class(Tr::Tcp, false, t0), Mapping::Varies);
        // One differing pair outweighs agreeing ones.
        c.observed(cid(3), &reuse(R3), &ext(40_001), t0, t0);
        assert_eq!(c.class(Tr::Tcp, false, t0), Mapping::Varies);
    }

    #[test]
    fn different_external_ips_is_varies() {
        let t0 = Instant::now();
        let mut c = listening();
        c.observed(cid(1), &reuse(R1), &ma("/ip4/203.0.113.9/tcp/7423"), t0, t0);
        c.observed(
            cid(2),
            &reuse(R2),
            &ma("/ip4/203.0.113.10/tcp/7423"),
            t0,
            t0,
        );
        assert_eq!(c.class(Tr::Tcp, false, t0), Mapping::Varies);
    }

    #[test]
    fn one_group_or_one_observer_is_unknown() {
        let t0 = Instant::now();
        let mut c = listening();
        c.observed(cid(1), &reuse(R1), &ext(40_001), t0, t0);
        assert_eq!(c.class(Tr::Tcp, false, t0), Mapping::Unknown);
        // A second observer on the same /24 is the same network: one opinion.
        c.observed(
            cid(2),
            &reuse("/ip4/8.8.8.9/tcp/7423"),
            &ext(40_002),
            t0,
            t0,
        );
        assert_eq!(c.class(Tr::Tcp, false, t0), Mapping::Unknown);
        assert_eq!(c.networks(t0), 1);
        // The same /48 over IPv6 likewise.
        let mut c = listening();
        let a = "/ip6/2606:4700:10::1/tcp/7423";
        let b = "/ip6/2606:4700:10:ffff::2/tcp/7423";
        let e = |p: u16| ma(&format!("/ip6/2001:4860:4860::99/tcp/{p}"));
        c.observed(cid(1), &reuse(a), &e(40_001), t0, t0);
        c.observed(cid(2), &reuse(b), &e(40_002), t0, t0);
        assert_eq!(c.class(Tr::Tcp, true, t0), Mapping::Unknown);
    }

    #[test]
    fn non_overlapping_connections_are_never_compared() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut c = listening();
        c.observed(cid(1), &reuse(R1), &ext(40_001), t0, t0);
        c.closed(cid(1), t0 + s(10));
        c.observed(cid(2), &reuse(R2), &ext(40_002), t0 + s(20), t0 + s(20));
        assert_eq!(c.class(Tr::Tcp, false, t0 + s(20)), Mapping::Unknown);
        // A third connection open while the second is: compared with it only.
        c.observed(cid(3), &reuse(R3), &ext(40_002), t0 + s(30), t0 + s(30));
        assert_eq!(c.class(Tr::Tcp, false, t0 + s(30)), Mapping::StableShifted);
        // Closing after the overlap keeps the comparison.
        c.closed(cid(2), t0 + s(40));
        assert_eq!(c.class(Tr::Tcp, false, t0 + s(41)), Mapping::StableShifted);
    }

    #[test]
    fn inbound_relayed_and_non_reuse_connections_are_ignored() {
        let t0 = Instant::now();
        let mut c = listening();
        let inbound = ConnectedPoint::Listener {
            local_addr: ma("/ip4/0.0.0.0/tcp/7423"),
            send_back_addr: ma(R1),
        };
        assert!(!c.observed(cid(1), &inbound, &ext(40_001), t0, t0));
        assert!(!c.observed(cid(2), &dial(R1, PortUse::New), &ext(40_001), t0, t0));
        let (relay, target) = (PeerId::random(), PeerId::random());
        let relayed = format!("{R1}/p2p/{relay}/p2p-circuit/p2p/{target}");
        assert!(!c.observed(cid(3), &reuse(&relayed), &ext(40_001), t0, t0));
        // A peer that is not globally routable is no observer.
        assert!(!c.observed(
            cid(4),
            &reuse("/ip4/192.168.1.20/tcp/7423"),
            &ext(40_001),
            t0,
            t0
        ));
        assert!(!c.observed(
            cid(5),
            &reuse("/dns4/relay.example/tcp/7423"),
            &ext(40_001),
            t0,
            t0
        ));
        // No listener of that family: the dial could not reuse its port.
        let mut v4_only = NatClassifier::new();
        v4_only.set_listen_port(Tr::Tcp, false, Some(LP));
        let v6 = "/ip6/2606:4700:10::1/tcp/7423";
        assert!(!v4_only.observed(
            cid(6),
            &reuse(v6),
            &ma("/ip6/2001:4860:4860::99/tcp/7423"),
            t0,
            t0
        ));
        assert!(!v4_only.observed(
            cid(7),
            &reuse("/ip4/8.8.8.8/udp/7423/quic-v1"),
            &ma("/ip4/203.0.113.9/udp/7423/quic-v1"),
            t0,
            t0
        ));
        // An observation of another transport or family than the connection's.
        assert!(!c.observed(
            cid(8),
            &reuse(R1),
            &ma("/ip4/203.0.113.9/udp/7423/quic-v1"),
            t0,
            t0
        ));
        assert!(!c.observed(
            cid(9),
            &reuse(R1),
            &ma("/ip6/2001:4860:4860::99/tcp/7423"),
            t0,
            t0
        ));
        assert!(!c.observed(cid(10), &reuse(R1), &ext(0), t0, t0));
        assert_eq!(c.summary(t0), NatSummary::default());
        assert_eq!(c.networks(t0), 0);
        // A listener that closes takes its observations with it.
        c.observed(cid(11), &reuse(R1), &ext(LP), t0, t0);
        c.observed(cid(12), &reuse(R2), &ext(LP), t0, t0);
        assert_eq!(c.class(Tr::Tcp, false, t0), Mapping::StableKept);
        c.set_listen_port(Tr::Tcp, false, None);
        assert_eq!(c.class(Tr::Tcp, false, t0), Mapping::Unknown);
    }

    #[test]
    fn wss_and_circuit_connections_are_ignored() {
        let t0 = Instant::now();
        let mut c = listening();
        let wss = [
            "/ip4/8.8.8.8/tcp/443/tls/ws",
            "/ip4/8.8.8.8/tcp/443/tls/sni/relay.example/ws",
            "/ip4/8.8.8.8/tcp/443/wss",
            "/ip4/8.8.8.8/tcp/443/ws",
            "/ip4/8.8.8.8/tcp/7423/p2p-circuit",
        ];
        for (i, remote) in wss.iter().enumerate() {
            assert!(
                !c.observed(cid(i), &reuse(remote), &ext(40_001), t0, t0),
                "{remote}"
            );
        }
        // The observed address itself in a WSS or circuit form.
        for (i, seen) in [
            "/ip4/203.0.113.9/tcp/40001/tls/ws",
            "/ip4/203.0.113.9/tcp/40001/p2p-circuit",
        ]
        .iter()
        .enumerate()
        {
            assert!(
                !c.observed(cid(10 + i), &reuse(R1), &ma(seen), t0, t0),
                "{seen}"
            );
        }
        assert_eq!(c.summary(t0), NatSummary::default());
        // The raw forms with a trailing /p2p are accepted.
        let r = format!("/ip4/8.8.8.8/udp/7423/quic-v1/p2p/{}", PeerId::random());
        assert!(c.observed(
            cid(20),
            &reuse(&r),
            &ma("/ip4/203.0.113.9/udp/40001/quic-v1"),
            t0,
            t0
        ));
    }

    #[test]
    fn own_address_is_no_nat() {
        let t0 = Instant::now();
        let mut c = listening();
        c.set_own_addrs([
            "203.0.113.9".parse().unwrap(),
            "192.168.1.5".parse().unwrap(),
        ]);
        // A shifted port on an own address is not "no NAT".
        c.observed(cid(1), &reuse(R1), &ext(40_001), t0, t0);
        assert_eq!(c.class(Tr::Tcp, false, t0), Mapping::Unknown);
        // One observer seeing an own address on the listen port suffices.
        c.observed(cid(2), &reuse(R2), &ext(LP), t0, t0);
        assert_eq!(c.class(Tr::Tcp, false, t0), Mapping::NoNat);
        // IPv4-mapped forms are the same address.
        let mut c = listening();
        c.set_own_addrs(["::ffff:203.0.113.9".parse().unwrap()]);
        c.observed(cid(1), &reuse(R1), &ext(LP), t0, t0);
        assert_eq!(c.class(Tr::Tcp, false, t0), Mapping::NoNat);
    }

    #[test]
    fn observations_expire_after_600s() {
        let t0 = Instant::now();
        let mut c = listening();
        c.observed(cid(1), &reuse(R1), &ext(LP), t0, t0);
        c.observed(cid(2), &reuse(R2), &ext(LP), t0, t0);
        let almost = t0 + OBS_TTL - Duration::from_secs(1);
        assert_eq!(c.class(Tr::Tcp, false, almost), Mapping::StableKept);
        assert_eq!(c.class(Tr::Tcp, false, t0 + OBS_TTL), Mapping::Unknown);
        assert_eq!(c.networks(t0 + OBS_TTL), 0);
        // A new observation on the same connection refreshes it.
        c.observed(cid(1), &reuse(R1), &ext(LP), t0, almost);
        c.observed(cid(2), &reuse(R2), &ext(LP), t0, almost);
        assert_eq!(c.class(Tr::Tcp, false, t0 + OBS_TTL), Mapping::StableKept);
        assert_eq!(c.obs[&(Tr::Tcp, false)].len(), 2);
    }

    #[test]
    fn at_most_eight_observations_per_transport_and_family() {
        let t0 = Instant::now();
        let mut c = listening();
        // Two varying observations, then eight agreeing ones push them out.
        c.observed(cid(100), &reuse(R1), &ext(40_001), t0, t0);
        c.observed(cid(101), &reuse(R2), &ext(40_002), t0, t0);
        assert_eq!(c.class(Tr::Tcp, false, t0), Mapping::Varies);
        for i in 0..MAX_OBS {
            let r = format!("/ip4/8.8.{i}.8/tcp/7423");
            assert!(c.observed(cid(i), &reuse(&r), &ext(40_003), t0, t0));
        }
        assert_eq!(c.obs[&(Tr::Tcp, false)].len(), MAX_OBS);
        assert_eq!(c.class(Tr::Tcp, false, t0), Mapping::StableShifted);
    }

    #[test]
    fn summary_varies_only_when_every_known_transport_varies() {
        let t0 = Instant::now();
        let q = |ip: &str| format!("/ip4/{ip}/udp/7423/quic-v1");
        let qe = |p: u16| ma(&format!("/ip4/203.0.113.9/udp/{p}/quic-v1"));
        let mut c = listening();
        c.observed(cid(1), &reuse(R1), &ext(40_001), t0, t0);
        c.observed(cid(2), &reuse(R2), &ext(40_002), t0, t0);
        // TCP varies, QUIC unknown: every known transport varies.
        let s = c.summary(t0);
        assert_eq!(
            (s.v4_tcp, s.v4_quic, s.v4()),
            (Mapping::Varies, Mapping::Unknown, Mapping::Varies)
        );
        assert_eq!(s.v6(), Mapping::Unknown);
        // QUIC stable: the best known wins.
        c.observed(cid(3), &reuse(&q("8.8.8.8")), &qe(LP), t0, t0);
        c.observed(cid(4), &reuse(&q("9.9.9.9")), &qe(LP), t0, t0);
        let s = c.summary(t0);
        assert_eq!(
            (s.v4_quic, s.v4()),
            (Mapping::StableKept, Mapping::StableKept)
        );
        // Both vary.
        c.observed(cid(5), &reuse(&q("1.1.1.1")), &qe(40_009), t0, t0);
        assert_eq!(c.summary(t0).v4(), Mapping::Varies);
        // IPv6 is classified on its own, and an own global IPv6 sets the flag.
        assert!(!c.summary(t0).v6_global);
        c.set_own_addrs(["fe80::1".parse().unwrap(), "fd00::1".parse().unwrap()]);
        assert!(!c.summary(t0).v6_global);
        c.set_own_addrs(["2001:4860:4860::99".parse().unwrap()]);
        let e6 = ma("/ip6/2001:4860:4860::99/tcp/7423");
        c.observed(cid(6), &reuse("/ip6/2606:4700:10::1/tcp/7423"), &e6, t0, t0);
        let s = c.summary(t0);
        assert!(s.v6_global);
        assert_eq!(
            (s.v6_tcp, s.v6(), s.v4()),
            (Mapping::NoNat, Mapping::NoNat, Mapping::Varies)
        );
        // Ranking of the best-of rule.
        use Mapping::*;
        for (a, b, best) in [
            (Unknown, Unknown, Unknown),
            (Varies, Unknown, Varies),
            (Varies, StableShifted, StableShifted),
            (StableKept, StableShifted, StableKept),
            (NoNat, Varies, NoNat),
        ] {
            assert_eq!(Mapping::best(a, b), best);
            assert_eq!(Mapping::best(b, a), best);
        }
    }

    #[test]
    fn punch_policy_table() {
        let t0 = Instant::now();
        let h = Duration::from_secs(3600);
        let peer = PeerId::random();
        let varies = NatSummary {
            v4_tcp: Mapping::Varies,
            ..NatSummary::default()
        };
        let mut p = PunchPolicy::new(true);
        p.own = varies;
        // No hint from the contact: try.
        assert_eq!(p.hopeless(&peer, t0), None);
        // Both vary: skip.
        p.set_remote(peer, varies, t0 + h);
        assert_eq!(p.hopeless(&peer, t0), Some(SkipWhy::BothVary));
        // One unknown: try.
        p.set_remote(peer, NatSummary::default(), t0 + h);
        assert_eq!(p.hopeless(&peer, t0), None);
        // One side stable on another transport: try.
        let mixed = NatSummary {
            v4_quic: Mapping::StableShifted,
            ..varies
        };
        p.set_remote(peer, mixed, t0 + h);
        assert_eq!(p.hopeless(&peer, t0), None);
        // Shared global IPv6 never skips.
        let v6 = NatSummary {
            v6_global: true,
            ..varies
        };
        p.set_remote(peer, v6, t0 + h);
        assert_eq!(p.hopeless(&peer, t0), Some(SkipWhy::BothVary));
        p.own = v6;
        assert_eq!(p.hopeless(&peer, t0), None);
        p.own = varies;
        // A stale remote hint is ignored.
        p.set_remote(peer, varies, t0 + h);
        assert_eq!(p.hopeless(&peer, t0 + h), None);
        // Two failures skip for 6 h; one does not.
        let other = PeerId::random();
        p.note_failure(other, t0);
        assert_eq!(p.hopeless(&other, t0), None);
        p.note_failure(other, t0 + h);
        assert_eq!(p.hopeless(&other, t0 + h), Some(SkipWhy::FailedTwice));
        assert_eq!(
            p.hopeless(&other, t0 + h + FAIL_HOLD - Duration::from_secs(1)),
            Some(SkipWhy::FailedTwice)
        );
        assert_eq!(p.hopeless(&other, t0 + h + FAIL_HOLD), None);
        // Failures skip even with shared global IPv6 (the punch was tried).
        p.own = v6;
        p.set_remote(other, v6, t0 + 2 * h);
        assert_eq!(p.hopeless(&other, t0 + h), Some(SkipWhy::FailedTwice));
        // Success resets.
        p.note_success(&other);
        assert_eq!(p.hopeless(&other, t0 + h), None);
        p.note_failure(other, t0 + h);
        assert_eq!(p.hopeless(&other, t0 + h), None);
        // Disabled always tries.
        p.own = varies;
        p.set_remote(peer, varies, t0 + h);
        p.note_failure(peer, t0);
        p.note_failure(peer, t0);
        assert_eq!(p.hopeless(&peer, t0), Some(SkipWhy::FailedTwice));
        p.enabled = false;
        assert_eq!(p.hopeless(&peer, t0), None);
        let off = PunchPolicy::new(false);
        assert_eq!(off.hopeless(&peer, t0), None);
        assert_eq!(off.skipped, 0);
    }

    #[test]
    fn punch_policy_memory_is_bounded() {
        let t0 = Instant::now();
        let mut p = PunchPolicy::new(true);
        let first = PeerId::random();
        p.note_failure(first, t0);
        for i in 0..MAX_PEERS + 10 {
            p.note_failure(PeerId::random(), t0 + Duration::from_secs(1 + i as u64));
            p.set_remote(PeerId::random(), NatSummary::default(), t0 + FAIL_HOLD);
        }
        assert!(p.fails.len() <= MAX_PEERS);
        assert!(p.remote.len() <= MAX_PEERS);
        // The oldest entry went first.
        assert!(!p.fails.contains_key(&first));
    }

    #[test]
    fn lab_force_replaces_own_classes_only() {
        let s = NatSummary {
            v4_tcp: Mapping::StableKept,
            v6_global: true,
            ..NatSummary::default()
        };
        assert_eq!(with_lab_force(s, None), s);
        for (c, m) in [
            (LabNatClass::Varies, Mapping::Varies),
            (LabNatClass::StableKept, Mapping::StableKept),
            (LabNatClass::StableShifted, Mapping::StableShifted),
            (LabNatClass::NoNat, Mapping::NoNat),
        ] {
            let f = with_lab_force(s, Some(c));
            assert_eq!((f.v4_tcp, f.v4_quic, f.v6_tcp, f.v6_quic), (m, m, m, m));
            assert!(f.v6_global);
            assert_eq!(Mapping::from(c).word(), m.word());
        }
        // Without the lab force set_own keeps the observed summary.
        if raven_core::portmap_gate::lab_nat_class_force().is_none() {
            let mut p = PunchPolicy::new(true);
            p.set_own(s);
            assert_eq!(p.own, s);
        }
    }

    /// RRH1 NAT_CLASS (spec §13.1): codes 0-4 in the order of the words,
    /// flags bit 0 global IPv6 and bit 1 a confirmed pinhole; a contact's
    /// value reads back as the summary it was made from, and a code above 4
    /// is unknown. `clear_remote` forgets every contact's summary.
    #[test]
    fn nat_summary_wire_round_trip() {
        let all = [
            Mapping::Unknown,
            Mapping::NoNat,
            Mapping::StableKept,
            Mapping::StableShifted,
            Mapping::Varies,
        ];
        for (code, m) in all.into_iter().enumerate() {
            assert_eq!(m.code() as usize, code);
            assert_eq!(Mapping::from_code(m.code()), m);
            assert_eq!(NatClass::word(m.code()), m.word());
        }
        assert_eq!(Mapping::from_code(5), Mapping::Unknown);
        assert_eq!(Mapping::from_code(0xff), Mapping::Unknown);
        let s = NatSummary {
            v4_tcp: Mapping::Varies,
            v4_quic: Mapping::StableShifted,
            v6_tcp: Mapping::StableKept,
            v6_quic: Mapping::Unknown,
            v6_global: true,
        };
        let wire = s.to_wire(false);
        assert_eq!(wire.to_bytes(), [4, 3, 2, 0, NAT_FLAG_V6_GLOBAL]);
        assert_eq!(s.to_wire(true).flags, NAT_FLAG_V6_GLOBAL | NAT_FLAG_V6_OPEN);
        assert_eq!(NatSummary::from_wire(&wire), s);
        assert_eq!(
            NatSummary::from_wire(&NatSummary::default().to_wire(false)),
            NatSummary::default()
        );
        let mut p = PunchPolicy::new(true);
        let peer = PeerId::random();
        let now = Instant::now();
        p.set_own(NatSummary {
            v4_tcp: Mapping::Varies,
            ..NatSummary::default()
        });
        p.set_remote(
            peer,
            NatSummary::from_wire(&NatClass {
                v4_tcp: 4,
                ..NatClass::default()
            }),
            now + Duration::from_secs(60),
        );
        if raven_core::portmap_gate::lab_nat_class_force().is_none() {
            assert_eq!(p.hopeless(&peer, now), Some(SkipWhy::BothVary));
        }
        p.clear_remote();
        assert_eq!(p.hopeless(&peer, now), None);
    }
}
