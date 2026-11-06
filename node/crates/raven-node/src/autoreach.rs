//! Auto-reach, part 1: STUN self-discovery (`docs/design/2026-10-auto-reach.md`
//! §3). raven-node asks public STUN servers which public address and port
//! they see for this computer, so a friend outside this network can be told
//! where to reach it, with no setup and no server of Raven's.
//!
//! - **Gate and consent.** [`raven_core::stun_discovery_live_enabled`]
//!   (debug `RAVEN_LAB_STUN_DISCOVERY=1` with the p2p lab unlock), and the
//!   profile's [`raven_core::node_policy::NodePolicy::stun_allowed`] (`raven
//!   node stun off`, or hide my IP for everyone, stops every query). While
//!   either is off nothing is sent and nothing found is used.
//! - **The anchor** ([`anchor`]): at every p2p endpoint generation (start,
//!   re-home), before libp2p binds its listeners, a plain UDP socket bound to
//!   each IPv4 QUIC listen address asks the servers and closes. The listener
//!   then binds the same address and port, so its traffic leaves through the
//!   same NAT mapping: the anchor's answer is the exact public endpoint of the
//!   p2p QUIC port.
//! - **The refresh** ([`run`]): every [`REFRESH_EVERY`] from a fresh port,
//!   for the public IP and the class; a public IP that moved away from the
//!   anchor's re-homes the p2p host ([`crate::p2p::Rehome::PublicAddress`]),
//!   at most once per [`REHOME_EVERY`]. Failures back off from [`RETRY_MIN`].
//! - **Seen from outside** ([`observed`], design §3.2): a STUN answer is not
//!   authenticated. Whoever answers this computer's DNS for the servers'
//!   names, or forges both servers' replies on its network, can make them
//!   agree on an address of their own, and contacts would dial it. So the
//!   public IP is told to contacts (route hints, the friend relay's
//!   addresses) only once a contact or one of this node's relays saw this
//!   computer at that very IP, on a connection this computer dialled
//!   directly at an IP no DNS answer gave (Identify's observed address,
//!   which the p2p host feeds in), within [`SEEN_FOR`] and since the last
//!   network change ([`shared_ip`]). An address a router mapped
//!   (NAT-PMP, PCP, UPnP) waits for the same sighting ([`seen_ip`]). The
//!   class, and this node's own punch decisions, still follow every answer.
//! - **What it gives** ([`discovered_p2p`], [`public_ip`], [`own_class`],
//!   [`inet_direct`], [`forward_ip`]): addresses fresh for [`FRESH_FOR`] and
//!   seen from outside, nothing after a network change until the next probe
//!   and the next sighting ([`network_changed`]).
//! - **Confirmation** ([`confirm`]): a contact that came in from outside on
//!   a port (not right after this node dialled it: that may be a punch)
//!   confirms that transport for [`CONFIRM_FOR`], for the public IP of that
//!   moment only.
//!
//! Kept in memory only (no address is ever written to disk). Lines say the
//! class and whether the address changed or was seen, never an address or
//! a port.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use raven_core::ipc::AutoReachStatus;
use raven_core::stun::{self, Answer, Discovery, StunClass, TxId};
use raven_swarm::libp2p::multiaddr::Protocol;
use raven_swarm::libp2p::Multiaddr;
use tokio::net::UdpSocket;
use tokio::sync::Notify;

/// How long the anchor probe may hold up an endpoint generation.
pub(crate) const ANCHOR_BUDGET: Duration = Duration::from_millis(1600);
/// How long a refresh probe waits for answers.
const REFRESH_BUDGET: Duration = Duration::from_secs(3);
/// When the requests of one probe go out (RFC 8489 §6.2.1, RTO 500 ms).
const SENDS_AT: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_millis(500),
    Duration::from_millis(1500),
];
/// How often the public address is asked again.
pub(crate) const REFRESH_EVERY: Duration = Duration::from_secs(20 * 60);
/// The first wait after a failed refresh (doubling up to the interval).
const RETRY_MIN: Duration = Duration::from_secs(30);
/// How long an answer stands without a newer one.
pub(crate) const FRESH_FOR: Duration = Duration::from_secs(45 * 60);
/// How long a contact's inbound connection confirms a port.
pub(crate) const CONFIRM_FOR: Duration = Duration::from_secs(24 * 3600);
/// How long a contact's or relay's sighting of this computer's public IP
/// stands without a newer one ([`observed`]): a day, as a confirmation does.
/// A network change drops it at once, and it vouches for its own IP only, so
/// an answer that later names another IP is not covered by it. Identify asks
/// again every minute on every open connection, so a relay or a contact that
/// stays connected keeps it fresh.
pub(crate) const SEEN_FOR: Duration = CONFIRM_FOR;
/// The most IPs kept as seen; a new one replaces the oldest sighting.
const MAX_SEEN: usize = 8;
/// The fewest minutes between two re-homes for a moved public IP.
const REHOME_EVERY: Duration = Duration::from_secs(10 * 60);
/// How long a server name may take to resolve.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);
/// How often [`run`] looks at the setting and the schedule.
const CHECK_EVERY: Duration = Duration::from_secs(2);
/// An inbound connection from a peer this node dialled within this long
/// may be a punch's (or DCUtR's) and confirms nothing.
pub(crate) const DIALLED_RECENTLY: Duration = Duration::from_secs(90);
/// Tries to bind an anchor socket while the last generation still holds
/// the port.
const BIND_TRIES: u32 = 5;
const BIND_WAIT: Duration = Duration::from_millis(100);
/// The prefix of every line.
const LABEL: &str = "raven-node autoreach";

/// What [`confirm`] counts: which of this node's ports a contact reached
/// from outside.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Reached {
    /// The p2p TCP listener.
    Tcp,
    /// The p2p QUIC listener.
    Quic,
    /// The Internet direct listener.
    Inet,
}

impl Reached {
    fn word(self) -> &'static str {
        match self {
            Reached::Tcp => "tcp",
            Reached::Quic => "quic",
            Reached::Inet => "inet",
        }
    }
}

/// One anchor probe's result for one QUIC listen address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Anchor {
    local: SocketAddrV4,
    disc: Discovery,
    at: Instant,
}

/// One refresh probe's result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Seen {
    disc: Discovery,
    asked: u32,
    at: Instant,
}

#[derive(Debug, Default)]
struct State {
    /// The gate is live and the profile allows queries ([`run`] and
    /// [`anchor`] keep it): nothing found is used otherwise.
    enabled: bool,
    /// `on`, `off` or `hidden` (status).
    setting: &'static str,
    anchors: Vec<Anchor>,
    /// Servers asked by the last anchor probe.
    anchor_asked: u32,
    refresh: Option<Seen>,
    /// Which of this node's ports a contact reached from outside, when, and
    /// the public IP STUN named then: a confirmation counts for that IP only
    /// ([`confirmed_for`]).
    confirmed: HashMap<Reached, (Instant, Option<Ipv4Addr>)>,
    /// Public IPv4 addresses a contact or one of this node's relays saw this
    /// computer at, on a connection it dialled directly ([`observed`]), and
    /// when last; at most [`MAX_SEEN`].
    seen: HashMap<Ipv4Addr, Instant>,
    /// The public QUIC endpoints (IP and port) such a peer saw this
    /// computer's QUIC listen socket at, and when last; at most
    /// [`MAX_SEEN`] ([`Sighting::quic`]).
    seen_quic: HashMap<SocketAddrV4, Instant>,
    /// The IP the last "seen" line was about ([`say_seen`]).
    seen_said: Option<Ipv4Addr>,
    /// The Internet direct listener's address, while it listens.
    inet_listen: Option<SocketAddr>,
    last_rehome: Option<Instant>,
    /// What the last line said: the address (compared, never printed) and
    /// the class.
    logged: Option<(Option<Ipv4Addr>, StunClass)>,
    /// "No server answered" was said since the last answer.
    silent_said: bool,
    /// Tests: a loopback lab without its stand-in for a sighting
    /// ([`lab_seen`]), so 127.0.0.1 needs a view there as anywhere.
    strict_lab: bool,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);
/// [`State::enabled`] without the lock (the p2p host reads it every tick).
static ENABLED: AtomicBool = AtomicBool::new(false);

fn with_state<T>(f: impl FnOnce(&mut State) -> T) -> T {
    let mut guard: MutexGuard<'_, Option<State>> = STATE.lock().unwrap_or_else(|p| p.into_inner());
    f(guard.get_or_insert_with(State::default))
}

fn wake() -> &'static Notify {
    static NOTIFY: OnceLock<Notify> = OnceLock::new();
    NOTIFY.get_or_init(Notify::new)
}

/// Is STUN discovery live for the profile in `data_dir` (the gate, and the
/// profile's setting)? Blocking: reads node_policy.json. The word is what
/// status says.
fn allowed(data_dir: &Path) -> (bool, &'static str) {
    if !raven_core::stun_discovery_live_enabled() {
        return (false, "");
    }
    let policy = raven_core::node_policy::load_policy(data_dir);
    if policy.hide_ip {
        (false, "hidden")
    } else if policy.stun == Some(false) {
        (false, "off")
    } else {
        (true, "on")
    }
}

/// Keep whether discovery is live; turned off, everything found is
/// forgotten at once.
fn set_enabled(on: bool, word: &'static str) {
    ENABLED.store(on, Ordering::SeqCst);
    with_state(|s| {
        s.enabled = on;
        s.setting = word;
        if !on {
            forget_network(s);
            s.logged = None;
        }
    });
}

/// Forget what belongs to the network this computer was on: the probes'
/// answers, the confirmations and who saw it where.
fn forget_network(s: &mut State) {
    s.anchors.clear();
    s.refresh = None;
    s.confirmed.clear();
    s.seen.clear();
    s.seen_quic.clear();
    s.seen_said = None;
}

/// Is STUN discovery live now (as [`run`] or [`anchor`] last read it)?
pub(crate) fn enabled() -> bool {
    ENABLED.load(Ordering::SeqCst)
}

/// This machine's network changed (netwatch): what was found belongs to the
/// old one. The re-homed endpoint's anchor finds the new one, and the
/// refresh runs soon after.
pub(crate) fn network_changed() {
    with_state(forget_network);
    wake().notify_one();
}

/// The servers a probe asks, resolved, and whether distinct ports count as
/// distinct servers (a harness's own list, `RAVEN_LAB_STUN_SERVERS`). IPv4
/// only: the probes are IPv4. Every public server is asked each time
/// ([`stun::servers_to_ask`]); one whose name does not resolve is left out
/// and the other is asked alone.
async fn servers() -> (Vec<SocketAddr>, bool) {
    if let Some(lab) = raven_core::portmap_gate::lab_stun_servers() {
        return (lab.into_iter().filter(SocketAddr::is_ipv4).collect(), true);
    }
    let lookups = stun::servers_to_ask()
        .into_iter()
        .map(|(host, port)| async move {
            let found =
                tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((host, port)))
                    .await
                    .ok()?
                    .ok()?;
            found.into_iter().find(SocketAddr::is_ipv4)
        });
    let mut out: Vec<SocketAddr> = Vec::new();
    for addr in futures::future::join_all(lookups)
        .await
        .into_iter()
        .flatten()
    {
        if !out.iter().any(|a| a.ip() == addr.ip()) {
            out.push(addr);
        }
    }
    (out, false)
}

/// Ask every server in `servers` from `sock`, with retransmissions at
/// [`SENDS_AT`], for at most `budget`. Only a Binding success response from
/// the server a request went to, to that request's transaction, with an
/// IPv4 mapped address counts ([`stun::parse_binding_success`]).
pub(crate) async fn probe(
    sock: &UdpSocket,
    servers: &[SocketAddr],
    budget: Duration,
) -> Vec<Answer> {
    use rand::RngCore;
    let mut pending: Vec<(SocketAddr, TxId)> = servers
        .iter()
        .map(|s| {
            let mut txid = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut txid);
            (*s, txid)
        })
        .collect();
    let mut answers: Vec<Answer> = Vec::new();
    let start = tokio::time::Instant::now();
    let mut sends = 0;
    let mut buf = [0u8; stun::MAX_MESSAGE_LEN + 1];
    while !pending.is_empty() {
        let elapsed = start.elapsed();
        if elapsed >= budget {
            break;
        }
        while sends < SENDS_AT.len() && elapsed >= SENDS_AT[sends] {
            for (server, txid) in &pending {
                let _ = sock.send_to(&stun::binding_request(txid), server).await;
            }
            sends += 1;
        }
        let next = SENDS_AT.get(sends).copied().unwrap_or(budget).min(budget);
        let wait = next
            .saturating_sub(start.elapsed())
            .max(Duration::from_millis(1));
        match tokio::time::timeout(wait, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                let Some(i) = pending.iter().position(|(s, _)| *s == from) else {
                    continue;
                };
                if let Ok(SocketAddr::V4(mapped)) =
                    stun::parse_binding_success(&buf[..n], &pending[i].1)
                {
                    answers.push(Answer {
                        server: from,
                        mapped,
                    });
                    pending.remove(i);
                }
            }
            // An ICMP error reported on the socket (Windows reports port
            // unreachable on the next receive): the other servers may still
            // answer.
            Ok(Err(_)) => tokio::time::sleep(Duration::from_millis(5)).await,
            Err(_) => {}
        }
    }
    answers
}

/// This computer's interface addresses (for `no_nat` behind a wildcard
/// bind).
fn own_ips() -> Vec<IpAddr> {
    raven_core::netifs::read()
        .map(|all| all.into_iter().map(|a| a.ip).collect())
        .unwrap_or_default()
}

/// The IPv4 QUIC listen addresses (`/ip4/<ip>/udp/<port>/quic-v1`) among
/// `listen` with a fixed port: what the anchor binds.
fn quic_v4(listen: &[String]) -> Vec<SocketAddrV4> {
    let mut out = Vec::new();
    for text in listen {
        let Ok(addr) = text.parse::<Multiaddr>() else {
            continue;
        };
        let mut it = addr.iter();
        if let (Some(Protocol::Ip4(ip)), Some(Protocol::Udp(port)), Some(Protocol::QuicV1)) =
            (it.next(), it.next(), it.next())
        {
            let a = SocketAddrV4::new(ip, port);
            if port != 0 && !out.contains(&a) {
                out.push(a);
            }
        }
    }
    out
}

/// Bind `local` for the anchor, waiting a little while the last endpoint
/// generation still holds it.
async fn bind_anchor(local: SocketAddrV4) -> Option<UdpSocket> {
    for i in 0..BIND_TRIES {
        match UdpSocket::bind(local).await {
            Ok(sock) => return Some(sock),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && i + 1 < BIND_TRIES => {
                tokio::time::sleep(BIND_WAIT).await;
            }
            Err(_) => return None,
        }
    }
    None
}

/// The anchor probe (module doc): before the p2p endpoint generation binds
/// `listen` (`P2pListen::multiaddrs`), ask the servers from each IPv4 QUIC
/// listen address, and keep what they said. Does nothing while discovery is
/// not live for `data_dir`. At most [`ANCHOR_BUDGET`] (plus name lookups).
pub(crate) async fn anchor(data_dir: &Path, listen: &[String]) {
    let dd = data_dir.to_path_buf();
    let (on, word) = tokio::task::spawn_blocking(move || allowed(&dd))
        .await
        .unwrap_or((false, ""));
    set_enabled(on, word);
    if !on {
        return;
    }
    let locals = quic_v4(listen);
    if locals.is_empty() {
        return;
    }
    let (servers, by_port) = servers().await;
    if servers.is_empty() {
        say_silent();
        return;
    }
    let own = own_ips();
    let mut anchors = Vec::new();
    for local in locals {
        let Some(sock) = bind_anchor(local).await else {
            continue;
        };
        let answers = probe(&sock, &servers, ANCHOR_BUDGET).await;
        drop(sock);
        if answers.is_empty() {
            continue;
        }
        anchors.push(Anchor {
            local,
            disc: stun::classify(local, &own, &answers, by_port),
            at: Instant::now(),
        });
    }
    let asked = u32::try_from(servers.len()).unwrap_or(u32::MAX);
    let found = !anchors.is_empty();
    with_state(|s| {
        s.anchors = anchors;
        s.anchor_asked = asked;
    });
    if found {
        say_found();
    } else {
        say_silent();
    }
}

/// One refresh probe from a fresh port; `true` when a server answered.
async fn refresh() -> bool {
    let (servers, by_port) = servers().await;
    let asked = u32::try_from(servers.len()).unwrap_or(u32::MAX);
    let wildcard = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    let (bound, answers) = match UdpSocket::bind(wildcard).await {
        Ok(sock) if !servers.is_empty() => {
            let bound = match sock.local_addr() {
                Ok(SocketAddr::V4(a)) => a,
                _ => wildcard,
            };
            (bound, probe(&sock, &servers, REFRESH_BUDGET).await)
        }
        _ => (wildcard, Vec::new()),
    };
    if answers.is_empty() {
        say_silent();
        return false;
    }
    let disc = stun::classify(bound, &own_ips(), &answers, by_port);
    with_state(|s| {
        s.refresh = Some(Seen {
            disc,
            asked,
            at: Instant::now(),
        });
    });
    say_found();
    true
}

/// The newest fresh public IPv4 address both probes agree on (the anchor's
/// first, then the refresh's), `None` while discovery is off. What STUN
/// says, for status: contacts are told it only once seen ([`shared_ip`]).
pub(crate) fn public_ip() -> Option<Ipv4Addr> {
    if !enabled() {
        return None;
    }
    with_state(|s| best_ip(s, Instant::now()))
}

fn best_ip(s: &State, now: Instant) -> Option<Ipv4Addr> {
    let fresh = |at: Instant| now.saturating_duration_since(at) < FRESH_FOR;
    let refresh = s.refresh.filter(|r| fresh(r.at));
    let anchor = s
        .anchors
        .iter()
        .filter(|a| fresh(a.at))
        .max_by_key(|a| a.at);
    match (anchor, refresh) {
        // The newer one wins (a refresh after a quiet change of the IP).
        (Some(a), Some(r)) if r.at > a.at => r.disc.public_ip.or(a.disc.public_ip),
        (Some(a), _) => a.disc.public_ip.or(refresh.and_then(|r| r.disc.public_ip)),
        (None, Some(r)) => r.disc.public_ip,
        (None, None) => None,
    }
}

/// The NAT class STUN saw: the anchor's (the p2p port's own), else the
/// refresh's; `Unknown` while discovery is off or nothing is fresh.
pub(crate) fn own_class() -> StunClass {
    if !enabled() {
        return StunClass::Unknown;
    }
    with_state(|s| class_of(s, Instant::now()))
}

fn class_of(s: &State, now: Instant) -> StunClass {
    let fresh = |at: Instant| now.saturating_duration_since(at) < FRESH_FOR;
    s.anchors
        .iter()
        .filter(|a| fresh(a.at) && a.disc.class != StunClass::Unknown)
        .max_by_key(|a| a.at)
        .map(|a| a.disc.class)
        .or_else(|| {
            s.refresh
                .filter(|r| fresh(r.at) && r.disc.class != StunClass::Unknown)
                .map(|r| r.disc.class)
        })
        .unwrap_or_default()
}

/// Does this computer's NAT keep ports (no NAT, or one address and the local
/// port for every server), as the fresh probes say? A single server's
/// answer on the local port counts too. Only then is a listener's own port
/// guessed for a forward (design §3.3): a NAT that shifts its outbound ports
/// is rarely set up with a same-port forward, and the guess would cost every
/// friend a dial that never answers.
fn keeps_ports(s: &State, now: Instant) -> bool {
    let fresh = |at: Instant| now.saturating_duration_since(at) < FRESH_FOR;
    let kept = |d: &Discovery, local_port: u16| match d.class {
        StunClass::NoNat | StunClass::StableKept => true,
        StunClass::Unknown => d.mapped.is_some_and(|m| m.port() == local_port),
        StunClass::StableShifted | StunClass::Varies => false,
    };
    let newest_anchor = s
        .anchors
        .iter()
        .filter(|a| fresh(a.at))
        .max_by_key(|a| a.at);
    match (newest_anchor, s.refresh.filter(|r| fresh(r.at))) {
        (Some(a), Some(r)) if r.at > a.at => {
            // The refresh's own socket: its local port is not kept here,
            // only its class.
            matches!(r.disc.class, StunClass::NoNat | StunClass::StableKept)
        }
        (Some(a), _) => kept(&a.disc, a.local.port()),
        (None, Some(r)) => matches!(r.disc.class, StunClass::NoNat | StunClass::StableKept),
        (None, None) => false,
    }
}

/// The public IPv4 address a forward of a listener's own port would be
/// reached at: the public IP once seen from outside ([`shared_ip`]) where
/// the NAT keeps ports ([`keeps_ports`]), else `None`. The friend relay
/// names it with its ports, and offers it only then.
pub(crate) fn forward_ip() -> Option<Ipv4Addr> {
    if !enabled() {
        return None;
    }
    let lab_local = raven_core::p2p_local_candidates_enabled();
    with_state(|s| forward_in(s, lab_local, Instant::now()))
}

fn forward_in(s: &State, lab_local: bool, now: Instant) -> Option<Ipv4Addr> {
    shared_ip(s, lab_local, now).filter(|_| keeps_ports(s, now))
}

/// Did a contact or one of this node's relays see this computer at `ip`
/// within [`SEEN_FOR`], since the last network change? In a loopback lab
/// that IP may stand in for a sighting ([`lab_seen`]).
fn seen_at(s: &State, ip: Ipv4Addr, lab_local: bool, now: Instant) -> bool {
    s.seen
        .get(&ip)
        .is_some_and(|at| now.saturating_duration_since(*at) < SEEN_FOR)
        || lab_seen(s, ip, lab_local)
}

/// The loopback lab's stand-in for a sighting: under `lab_local` (the
/// local-candidates switch of debug builds) every node is at 127.0.0.1 and
/// every contact sees it there, so that one address and its endpoints
/// count as seen; any other, 127.0.0.2 say, does not. The harness's
/// scenarios rest on it; tests can turn it off ([`State::strict_lab`]).
fn lab_seen(s: &State, ip: Ipv4Addr, lab_local: bool) -> bool {
    lab_local && !s.strict_lab && ip == Ipv4Addr::LOCALHOST
}

/// The public IP contacts may be told: STUN's ([`best_ip`]) once a contact
/// or one of this node's relays saw this computer there ([`seen_at`]).
fn shared_ip(s: &State, lab_local: bool, now: Instant) -> Option<Ipv4Addr> {
    best_ip(s, now).filter(|ip| seen_at(s, *ip, lab_local, now))
}

/// Did a contact or one of this node's relays see this computer at `ip`
/// lately ([`observed`])? Whether STUN discovery is on or not: an address a
/// router mapped (NAT-PMP, PCP or UPnP, answers anyone on this network can
/// forge) is told to contacts only then (the p2p host's route hints).
pub(crate) fn seen_ip(ip: Ipv4Addr, lab_local: bool) -> bool {
    with_state(|s| seen_at(s, ip, lab_local, Instant::now()))
}

/// Where a contact or one of this node's relays saw this computer
/// ([`observed`]): Identify's observed address (canonical), and whether the
/// connection is a QUIC dial that reused the listen port (libp2p's
/// default). Such a dial leaves from the QUIC listen socket, which has the
/// address and port the anchor asked STUN from, so the observed port is
/// that socket's public mapping. Where libp2p found no listen socket to
/// reuse, it is a dialer socket's mapping instead: still this computer's,
/// never a port of the answers' choosing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sighting {
    pub(crate) at: SocketAddr,
    pub(crate) quic: bool,
}

/// A contact or one of this node's relays saw this computer at `seen`:
/// Identify's observed address on a connection this computer dialled
/// directly (no relay circuit, no hole punch, no WebSocket) at an IP no DNS
/// answer gave, which the p2p host passes on only from a contact the peer
/// gate admits or from a relay it holds a slot on. That peer reports where
/// this computer's packets came from, and from the other side of every NAT
/// that is the public IP; nobody between can change what the authenticated
/// link says. (On a connection the peer dialled, Identify reports the
/// address the peer dialled, which proves nothing; at an IP a DNS answer
/// gave, whoever answered may pass the connection on from a host of its
/// own, which the peer then sees: the host passes on neither.) IPv4 only
/// (STUN's address is IPv4), and only an address that may be told
/// ([`usable`]). Kept whether or not STUN discovery is on ([`seen_ip`]); in
/// memory only, never logged.
pub(crate) fn observed(seen: Sighting, lab_local: bool) {
    if let Some(line) = with_state(|s| observe_in(s, seen, lab_local, Instant::now())) {
        eprintln!("{line}");
    }
}

/// [`observed`] on `s` at `now`: the line to say, if any ([`say_seen`]).
fn observe_in(s: &mut State, seen: Sighting, lab_local: bool, now: Instant) -> Option<String> {
    let SocketAddr::V4(at) = seen.at else {
        return None;
    };
    let ip = *at.ip();
    if !usable(ip, lab_local) {
        return None;
    }
    note_seen(s, ip, now);
    if seen.quic {
        note_seen_quic(s, at, now);
    }
    say_seen(s, lab_local, now)
}

/// A contact or one of this node's relays saw this computer at `ip` at
/// `now`; with [`MAX_SEEN`] IPs kept, the oldest sighting gives way.
fn note_seen(s: &mut State, ip: Ipv4Addr, now: Instant) {
    if !s.seen.contains_key(&ip) && s.seen.len() >= MAX_SEEN {
        if let Some(oldest) = s.seen.iter().min_by_key(|(_, at)| **at).map(|(ip, _)| *ip) {
            s.seen.remove(&oldest);
        }
    }
    s.seen.insert(ip, now);
}

/// Such a peer saw this computer's QUIC listen socket at `at` at `now`;
/// with [`MAX_SEEN`] endpoints kept, the oldest gives way.
fn note_seen_quic(s: &mut State, at: SocketAddrV4, now: Instant) {
    if !s.seen_quic.contains_key(&at) && s.seen_quic.len() >= MAX_SEEN {
        let oldest = s.seen_quic.iter().min_by_key(|(_, t)| **t).map(|(a, _)| *a);
        if let Some(oldest) = oldest {
            s.seen_quic.remove(&oldest);
        }
    }
    s.seen_quic.insert(at, now);
}

/// Did a contact or one of this node's relays see this computer's QUIC
/// listen socket at exactly `at` within [`SEEN_FOR`], since the last
/// network change? In a loopback lab its IP may stand in ([`lab_seen`]).
fn quic_seen_at(s: &State, at: SocketAddrV4, lab_local: bool, now: Instant) -> bool {
    s.seen_quic
        .get(&at)
        .is_some_and(|t| now.saturating_duration_since(*t) < SEEN_FOR)
        || lab_seen(s, *at.ip(), lab_local)
}

/// The line to say when the address STUN found is now seen from outside
/// (once per address; never the address): from then on contacts are told
/// it.
fn say_seen(s: &mut State, lab_local: bool, now: Instant) -> Option<String> {
    let shared = shared_ip(s, lab_local, now);
    if shared == s.seen_said {
        return None;
    }
    s.seen_said = shared;
    shared.map(|_| format!("{LABEL}: public address seen from outside; contacts are told it"))
}

/// A p2p address found for this node: host and transport, no `/p2p`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Found {
    pub(crate) text: String,
    /// A contact reached that transport from outside ([`confirm`]).
    pub(crate) confirmed: bool,
}

/// The p2p addresses STUN discovery found (design §4.1), for the host's
/// listen addresses `listen`: the QUIC endpoint of each IPv4 QUIC listen
/// port (the anchor's, or the public IP with the listen port when the NAT
/// keeps ports), then the public IP with each IPv4 TCP listen port. Only a
/// public IP a contact or one of this node's relays saw this computer at
/// ([`shared_ip`]) and that is globally routable (any unicast one under
/// `lab_local`, the local-candidates switch), and nothing while discovery
/// is off.
pub(crate) fn discovered_p2p(listen: &[Multiaddr], lab_local: bool) -> Vec<Found> {
    if !enabled() {
        return Vec::new();
    }
    with_state(|s| found_in(s, listen, lab_local, Instant::now()))
}

fn usable(ip: Ipv4Addr, lab_local: bool) -> bool {
    raven_core::p2p_route::is_global_ip(IpAddr::V4(ip))
        || (lab_local && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast())
}

/// Whether a contact's connection from `remote` can confirm the address
/// STUN found: an outside IPv4 source only. The address is IPv4; an IPv6
/// connection says nothing about whether the IPv4 port is reachable.
fn confirms_from(remote: IpAddr, lab_local: bool) -> bool {
    match remote {
        IpAddr::V4(v4) => usable(v4, lab_local),
        IpAddr::V6(_) => false,
    }
}

/// A contact reached `r` from outside within [`CONFIRM_FOR`] (whatever the
/// public IP was then): the reach class and status.
fn confirmed_now(s: &State, r: Reached, now: Instant) -> bool {
    s.confirmed
        .get(&r)
        .is_some_and(|(at, _)| now.saturating_duration_since(*at) < CONFIRM_FOR)
}

/// [`confirmed_now`] while STUN named `ip`: what the CONFIRMED marks of the
/// addresses at `ip` say. A confirmation made under another public IP says
/// nothing about this one.
fn confirmed_for(s: &State, r: Reached, ip: Ipv4Addr, now: Instant) -> bool {
    confirmed_now(s, r, now)
        && s.confirmed
            .get(&r)
            .is_some_and(|(_, at_ip)| *at_ip == Some(ip))
}

fn found_in(s: &State, listen: &[Multiaddr], lab_local: bool, now: Instant) -> Vec<Found> {
    let fresh = |at: Instant| now.saturating_duration_since(at) < FRESH_FOR;
    let Some(ip) = shared_ip(s, lab_local, now).filter(|ip| usable(*ip, lab_local)) else {
        return Vec::new();
    };
    let kept = keeps_ports(s, now);
    let mut quic: Vec<String> = Vec::new();
    let mut tcp: Vec<String> = Vec::new();
    for addr in listen {
        let mut it = addr.iter();
        match (it.next(), it.next(), it.next()) {
            (Some(Protocol::Ip4(_)), Some(Protocol::Udp(port)), Some(Protocol::QuicV1)) => {
                // The anchor of that port (bound to the wildcard or to this
                // address), else the listen port where the NAT keeps ports;
                // either only once seen at that very endpoint
                // ([`quic_seen_at`]): STUN's port is no proof either.
                let mapped = s
                    .anchors
                    .iter()
                    .filter(|a| fresh(a.at) && a.local.port() == port)
                    .find_map(|a| a.disc.mapped)
                    .filter(|m| *m.ip() == ip)
                    .map(|m| m.port())
                    .or(kept.then_some(port))
                    .filter(|p| quic_seen_at(s, SocketAddrV4::new(ip, *p), lab_local, now));
                if let Some(p) = mapped {
                    let text = format!("/ip4/{ip}/udp/{p}/quic-v1");
                    if !quic.contains(&text) {
                        quic.push(text);
                    }
                }
            }
            // A TCP port is reachable from outside only through a forward:
            // guessed on the same port, where the NAT keeps ports.
            (Some(Protocol::Ip4(_)), Some(Protocol::Tcp(port)), None) if kept => {
                let text = format!("/ip4/{ip}/tcp/{port}");
                if !tcp.contains(&text) {
                    tcp.push(text);
                }
            }
            _ => {}
        }
    }
    let (q, t) = (
        confirmed_for(s, Reached::Quic, ip, now),
        confirmed_for(s, Reached::Tcp, ip, now),
    );
    quic.into_iter()
        .map(|text| Found { text, confirmed: q })
        .chain(tcp.into_iter().map(|text| Found { text, confirmed: t }))
        .collect()
}

/// A contact connected in from `remote` on this node's `what` listener:
/// that port is reachable from outside, unless the contact is on this
/// node's own public address (a hairpin through the home router proves
/// nothing; under `lab_local` loopback counts) or the address is not
/// globally routable. `true` when it confirmed (the first time, a line).
/// The caller leaves out connections this node may have punched
/// ([`DIALLED_RECENTLY`]).
pub(crate) fn confirm(what: Reached, remote: IpAddr, lab_local: bool) -> bool {
    if !enabled() {
        return false;
    }
    let first = with_state(|s| confirm_in(s, what, remote, lab_local, Instant::now()));
    match first {
        Some(true) => {
            eprintln!(
                "{LABEL}: a contact reached this computer's {} port from outside: confirmed",
                match what {
                    Reached::Tcp => "p2p TCP",
                    Reached::Quic => "p2p QUIC",
                    Reached::Inet => "Internet direct",
                }
            );
            true
        }
        Some(false) => true,
        None => false,
    }
}

/// [`confirm`] on `s` at `now`: `Some(first)` when it confirmed, `None`
/// when the connection proves nothing. The confirmation keeps the public IP
/// STUN names now, and marks addresses at that IP only ([`confirmed_for`]).
fn confirm_in(
    s: &mut State,
    what: Reached,
    remote: IpAddr,
    lab_local: bool,
    now: Instant,
) -> Option<bool> {
    if !confirms_from(remote, lab_local) {
        return None;
    }
    let ip = best_ip(s, now);
    if !lab_local && ip.is_some_and(|ip| IpAddr::V4(ip) == remote) {
        return None;
    }
    let first = !confirmed_now(s, what, now);
    s.confirmed.insert(what, (now, ip));
    Some(first)
}

/// Did a contact reach one of the p2p listeners from outside within
/// [`CONFIRM_FOR`] ([`confirm`])? `false` while discovery is off.
pub(crate) fn reached_outside() -> bool {
    enabled()
        && with_state(|s| {
            let now = Instant::now();
            confirmed_now(s, Reached::Tcp, now) || confirmed_now(s, Reached::Quic, now)
        })
}

/// The Internet direct listener now listens at `addr` (`None`: it stopped).
pub(crate) fn set_inet_listen(addr: Option<SocketAddr>) {
    with_state(|s| s.inet_listen = addr);
}

/// The Internet direct listener's public address (`ip:port`) and whether a
/// contact reached it from outside under that IP: the public IP, once seen
/// from outside ([`shared_ip`]), with the listen port of an IPv4 (or
/// wildcard) listener. `None` while discovery is off or nothing is known.
pub(crate) fn inet_direct(lab_local: bool) -> Option<(SocketAddrV4, bool)> {
    if !enabled() {
        return None;
    }
    with_state(|s| inet_in(s, lab_local, Instant::now()))
}

fn inet_in(s: &State, lab_local: bool, now: Instant) -> Option<(SocketAddrV4, bool)> {
    let listen = s.inet_listen?;
    let v4_ok = match listen.ip() {
        IpAddr::V4(_) => true,
        IpAddr::V6(v6) => v6.is_unspecified() && !cfg!(windows),
    };
    if !v4_ok || listen.port() == 0 {
        return None;
    }
    let ip = shared_ip(s, lab_local, now)
        .filter(|ip| usable(*ip, lab_local))
        .filter(|_| keeps_ports(s, now))?;
    Some((
        SocketAddrV4::new(ip, listen.port()),
        confirmed_for(s, Reached::Inet, ip, now),
    ))
}

/// Did the public IP move away from the newest anchor's (a later refresh
/// saw another one)? Then every NAT mapping of this computer is gone.
fn moved(s: &State) -> bool {
    let (Some(r), Some(a)) = (s.refresh, s.anchors.iter().max_by_key(|a| a.at)) else {
        return false;
    };
    match (a.disc.public_ip, r.disc.public_ip) {
        (Some(before), Some(now)) => r.at > a.at && before != now,
        _ => false,
    }
}

/// One line when what was found changed: the class, and whether the
/// address is new or moved (never the address).
fn say_found() {
    let line = with_state(|s| {
        s.silent_said = false;
        let now = Instant::now();
        let ip = best_ip(s, now);
        let class = class_of(s, now);
        let answered = s
            .anchors
            .iter()
            .map(|a| a.disc.answered)
            .chain(s.refresh.map(|r| r.disc.answered))
            .max()
            .unwrap_or(0);
        let asked = s
            .anchor_asked
            .max(s.refresh.map_or(0, |r| r.asked))
            .max(answered);
        let what = match (s.logged, ip) {
            (Some((before, c)), _) if before == ip && c == class => return None,
            (Some((Some(before), _)), Some(now_ip)) if before != now_ip => "public address changed",
            (Some((Some(_), _)), Some(_)) => "public address unchanged",
            (_, Some(_)) => "public address found",
            (_, None) => "no public address agreed",
        };
        s.logged = Some((ip, class));
        Some(format!(
            "{LABEL}: {what} ({}; {answered} of {asked} servers)",
            class.phrase()
        ))
    });
    if let Some(line) = line {
        eprintln!("{line}");
    }
    // A sighting may have come before the answer that names its IP.
    let lab_local = raven_core::p2p_local_candidates_enabled();
    if let Some(line) = with_state(|s| say_seen(s, lab_local, Instant::now())) {
        eprintln!("{line}");
    }
}

/// One line the first time no server answers (until one answers again).
fn say_silent() {
    let first = with_state(|s| !std::mem::replace(&mut s.silent_said, true));
    if first {
        eprintln!("{LABEL}: no STUN server answered (UDP blocked or offline); retrying");
    }
}

/// The refresh wait after `failures` failed probes in a row: the interval
/// after a success, else [`RETRY_MIN`] doubling up to it.
fn next_wait(every: Duration, failures: u32) -> Duration {
    if failures == 0 {
        return every;
    }
    let min = RETRY_MIN.min(every);
    min.saturating_mul(1u32 << failures.saturating_sub(1).min(16))
        .min(every)
}

/// The refresh task of `raven-node service` (module doc). It never ends; it
/// sends nothing while discovery is not live or no p2p host runs.
pub(crate) async fn run(data_dir: PathBuf) -> Result<(), String> {
    let every = raven_core::portmap_gate::lab_stun_refresh_s()
        .map(Duration::from_secs)
        .unwrap_or(REFRESH_EVERY);
    let policy_file = raven_core::policy_path(&data_dir);
    // `None` until the first read: a missing node_policy.json has no stamp
    // either, and must still be read once (it means the defaults).
    let mut stamp: Option<Option<crate::p2p::FileStamp>> = None;
    let mut setting = (false, "");
    let mut failures = 0u32;
    // The first refresh after the anchor has had its turn.
    let mut due = tokio::time::Instant::now() + every.min(Duration::from_secs(10));
    loop {
        tokio::select! {
            () = tokio::time::sleep(CHECK_EVERY) => {}
            () = wake().notified() => {
                // A network change: refresh soon (the re-home's anchor first).
                due = due.min(tokio::time::Instant::now() + Duration::from_secs(5));
                failures = 0;
            }
        }
        let now_stamp = Some(crate::p2p::file_stamp(&policy_file));
        if now_stamp != stamp || !raven_core::stun_discovery_live_enabled() {
            stamp = now_stamp;
            let dd = data_dir.clone();
            setting = tokio::task::spawn_blocking(move || allowed(&dd))
                .await
                .unwrap_or((false, ""));
        }
        if setting.0 != enabled() || with_state(|s| s.setting) != setting.1 {
            set_enabled(setting.0, setting.1);
        }
        if !setting.0 || !crate::p2p::host_running() || tokio::time::Instant::now() < due {
            continue;
        }
        if refresh().await {
            failures = 0;
        } else {
            failures = failures.saturating_add(1);
        }
        due = tokio::time::Instant::now() + next_wait(every, failures);
        let rehome = with_state(|s| {
            let ok = moved(s) && s.last_rehome.is_none_or(|t| t.elapsed() >= REHOME_EVERY);
            if ok {
                s.last_rehome = Some(Instant::now());
                s.confirmed.clear();
            }
            ok
        });
        if rehome && crate::p2p::network_changed(crate::p2p::Rehome::PublicAddress) {
            eprintln!("{LABEL}: the public address moved; p2p re-homing for the new one");
        }
    }
}

/// Status (IPC `Status.p2p.auto_reach`) while the gate is live: words and
/// counts, never an address.
pub(crate) fn status() -> Option<AutoReachStatus> {
    if !raven_core::stun_discovery_live_enabled() {
        return None;
    }
    let ip = public_ip();
    with_state(|s| {
        let now = Instant::now();
        let last = s
            .anchors
            .iter()
            .map(|a| a.at)
            .chain(s.refresh.map(|r| r.at))
            .max();
        let (asked, answered) = match (s.anchors.iter().max_by_key(|a| a.at), s.refresh) {
            (Some(a), Some(r)) if r.at > a.at => (r.asked, r.disc.answered),
            (Some(a), _) => (s.anchor_asked, a.disc.answered),
            (None, Some(r)) => (r.asked, r.disc.answered),
            (None, None) => (0, 0),
        };
        Some(AutoReachStatus {
            state: if s.setting.is_empty() {
                "on"
            } else {
                s.setting
            }
            .into(),
            public: if !s.enabled {
                "none"
            } else if ip.is_some() {
                "found"
            } else if last.is_none() {
                "waiting"
            } else {
                "none"
            }
            .into(),
            class: class_of(s, now).word().into(),
            anchored: s.anchors.iter().any(|a| {
                now.saturating_duration_since(a.at) < FRESH_FOR && a.disc.mapped.is_some()
            }),
            asked,
            answered,
            age_s: last.map(|t| now.saturating_duration_since(t).as_secs()),
            reached: [Reached::Tcp, Reached::Quic, Reached::Inet]
                .into_iter()
                .filter(|r| confirmed_now(s, *r, now))
                .map(|r| r.word().to_string())
                .collect(),
            punch: None,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::stun::{BINDING_SUCCESS, MAGIC_COOKIE};

    /// A fake STUN server on loopback: answers every Binding request with the
    /// address `map` gives for the request's source (`None`: silent).
    async fn fake_server(map: fn(SocketAddr) -> Option<SocketAddr>) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                if n < 20 {
                    continue;
                }
                let Some(mapped) = map(from) else {
                    continue;
                };
                let SocketAddr::V4(m) = mapped else {
                    continue;
                };
                let mut msg = Vec::new();
                msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
                msg.extend_from_slice(&12u16.to_be_bytes());
                msg.extend_from_slice(&buf[4..20]);
                msg.extend_from_slice(&0x0020u16.to_be_bytes());
                msg.extend_from_slice(&8u16.to_be_bytes());
                msg.extend_from_slice(&[0, 1]);
                msg.extend_from_slice(&(m.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
                msg.extend_from_slice(&(u32::from(*m.ip()) ^ MAGIC_COOKIE).to_be_bytes());
                let _ = sock.send_to(&msg, from).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn a_probe_reads_every_answer_and_ignores_strangers() {
        let a =
            fake_server(|from| Some(SocketAddr::new("203.0.113.7".parse().unwrap(), from.port())))
                .await;
        let b =
            fake_server(|from| Some(SocketAddr::new("203.0.113.7".parse().unwrap(), from.port())))
                .await;
        let silent = fake_server(|_| None).await;
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = match sock.local_addr().unwrap() {
            SocketAddr::V4(l) => l,
            _ => unreachable!(),
        };
        let t0 = std::time::Instant::now();
        let answers = probe(&sock, &[a, b, silent], Duration::from_millis(800)).await;
        assert!(t0.elapsed() < Duration::from_secs(2));
        assert_eq!(answers.len(), 2, "{answers:?}");
        let disc = stun::classify(local, &[], &answers, true);
        assert_eq!(disc.class, StunClass::StableKept);
        assert_eq!(
            disc.mapped,
            Some(SocketAddrV4::new(
                "203.0.113.7".parse().unwrap(),
                local.port()
            ))
        );
    }

    #[tokio::test]
    async fn a_probe_ends_early_when_everyone_answered() {
        let a = fake_server(Some).await;
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let t0 = std::time::Instant::now();
        let answers = probe(&sock, &[a], Duration::from_secs(3)).await;
        assert_eq!(answers.len(), 1);
        assert!(
            t0.elapsed() < Duration::from_millis(400),
            "{:?}",
            t0.elapsed()
        );
    }

    /// Only an outside IPv4 source confirms the IPv4 address STUN found; an
    /// IPv6 connection does not.
    #[test]
    fn only_an_outside_ipv4_source_confirms_the_stun_address() {
        assert!(confirms_from("1.1.1.1".parse().unwrap(), false));
        assert!(!confirms_from("192.168.1.9".parse().unwrap(), false));
        assert!(!confirms_from("2001:db8::9".parse().unwrap(), false));
        assert!(!confirms_from("2606:4700::1111".parse().unwrap(), false));
        assert!(!confirms_from("::1".parse().unwrap(), true));
        assert!(confirms_from("127.0.0.1".parse().unwrap(), true));
    }

    #[test]
    fn quic_v4_takes_fixed_ipv4_quic_ports_only() {
        let listen: Vec<String> = [
            "/ip4/0.0.0.0/tcp/17423",
            "/ip4/0.0.0.0/udp/17423/quic-v1",
            "/ip6/::/udp/17423/quic-v1",
            "/ip4/127.0.0.1/udp/0/quic-v1",
            "/ip4/127.0.0.1/udp/4000/quic-v1",
            "/ip4/0.0.0.0/udp/17423/quic-v1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            quic_v4(&listen),
            vec![
                "0.0.0.0:17423".parse().unwrap(),
                "127.0.0.1:4000".parse().unwrap()
            ]
        );
    }

    fn disc(ip: &str, mapped: Option<&str>, class: StunClass) -> Discovery {
        Discovery {
            public_ip: Some(ip.parse().unwrap()),
            mapped: mapped.map(|m| m.parse().unwrap()),
            class,
            answered: 2,
            independent: 2,
        }
    }

    fn ma(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    /// A contact saw this computer at the public IP STUN names now, and its
    /// QUIC listen socket there at each of `quic` ports.
    fn seen_from_outside(s: &mut State, now: Instant, quic: &[u16]) {
        let ip = best_ip(s, now).expect("a public IP");
        note_seen(s, ip, now);
        for port in quic {
            note_seen_quic(s, SocketAddrV4::new(ip, *port), now);
        }
    }

    #[test]
    fn found_addresses_follow_the_anchor_or_port_preservation() {
        let now = Instant::now();
        let listen = [
            ma("/ip4/192.168.1.5/tcp/17423"),
            ma("/ip4/192.168.1.5/udp/17423/quic-v1"),
        ];
        // An anchor on another public port (not port-preserving).
        let mut s = State {
            enabled: true,
            anchors: vec![Anchor {
                local: "0.0.0.0:17423".parse().unwrap(),
                disc: disc("11.0.3.7", Some("11.0.3.7:40001"), StunClass::StableShifted),
                at: now,
            }],
            ..State::default()
        };
        let texts = |s: &State| -> Vec<String> {
            found_in(s, &listen, false, now)
                .into_iter()
                .map(|f| f.text)
                .collect()
        };
        // Nothing until a contact or relay saw this computer at that IP.
        assert!(texts(&s).is_empty());
        seen_from_outside(&mut s, now, &[40001, 17423]);
        // The anchor's exact QUIC endpoint; no TCP guess where the NAT
        // shifts ports.
        assert_eq!(texts(&s), vec!["/ip4/11.0.3.7/udp/40001/quic-v1"]);
        // No anchor, a port-keeping NAT: the listen port.
        s.anchors.clear();
        s.refresh = Some(Seen {
            disc: disc("11.0.3.7", Some("11.0.3.7:51000"), StunClass::StableKept),
            asked: 3,
            at: now,
        });
        assert_eq!(
            texts(&s),
            vec!["/ip4/11.0.3.7/udp/17423/quic-v1", "/ip4/11.0.3.7/tcp/17423"]
        );
        // A NAT that varies and no anchor: nothing (no QUIC endpoint is
        // known, and no forward is guessed where ports are not kept).
        s.refresh = Some(Seen {
            disc: disc("11.0.3.7", None, StunClass::Varies),
            asked: 3,
            at: now,
        });
        assert!(texts(&s).is_empty());
        // Documentation and private "public" addresses (a carrier NAT's
        // inside, say) are no address, except in a loopback lab.
        s.refresh = Some(Seen {
            disc: disc("203.0.113.7", None, StunClass::StableKept),
            asked: 3,
            at: now,
        });
        assert!(texts(&s).is_empty());
        // A private "public" address (a carrier NAT's inside, say) is no
        // address, except in a loopback lab.
        s.refresh = Some(Seen {
            disc: disc("10.0.0.7", None, StunClass::StableKept),
            asked: 3,
            at: now,
        });
        assert!(texts(&s).is_empty());
        seen_from_outside(&mut s, now, &[17423]);
        assert!(texts(&s).is_empty());
        assert_eq!(found_in(&s, &listen, true, now).len(), 2);
        // Stale after FRESH_FOR.
        let later = now + FRESH_FOR + Duration::from_secs(1);
        assert!(found_in(&s, &listen, true, later).is_empty());
    }

    #[test]
    fn a_confirmation_marks_its_transport_for_a_day() {
        let now = Instant::now();
        let listen = [
            ma("/ip4/0.0.0.0/tcp/17423"),
            ma("/ip4/0.0.0.0/udp/17423/quic-v1"),
        ];
        let mut s = State {
            enabled: true,
            refresh: Some(Seen {
                disc: disc("11.0.3.7", Some("11.0.3.7:17423"), StunClass::StableKept),
                asked: 3,
                at: now,
            }),
            ..State::default()
        };
        seen_from_outside(&mut s, now, &[17423]);
        s.confirmed.insert(Reached::Tcp, (now, best_ip(&s, now)));
        let f = found_in(&s, &listen, false, now);
        assert_eq!(
            f.iter().map(|f| f.confirmed).collect::<Vec<_>>(),
            vec![false, true],
            "QUIC unconfirmed, TCP confirmed"
        );
        let later = now + CONFIRM_FOR + Duration::from_secs(1);
        assert!(!confirmed_now(&s, Reached::Tcp, later));
    }

    /// INET-STUN-1: a STUN answer is not authenticated. Whoever answers this
    /// computer's DNS for the servers' names, or forges both servers'
    /// replies on its network, chooses the address, and contacts would dial
    /// it (showing that host their IPs, the times and their PeerIds). So
    /// what STUN names is told (route hints DIRECT and INET_DIRECT, the
    /// friend relay's addresses) only once a contact or one of this node's
    /// relays saw this computer at that very IP, on a connection this
    /// computer dialled directly; a network change forgets every sighting,
    /// and a confirmation counts for the IP it was made under only.
    #[test]
    fn a_stun_address_is_advertised_only_once_a_contact_saw_it() {
        let t0 = Instant::now();
        // Documentation addresses stand in for public ones (`lab` lets them
        // count as addresses; none of them is the loopback lab's own).
        let lab = true;
        let listen = [
            ma("/ip4/0.0.0.0/tcp/17423"),
            ma("/ip4/0.0.0.0/udp/17423/quic-v1"),
        ];
        let stun = |s: &mut State, ip: &str, at: Instant| {
            s.refresh = Some(Seen {
                disc: disc(ip, Some(&format!("{ip}:17423")), StunClass::StableKept),
                asked: 2,
                at,
            });
        };
        let told = |s: &State, now: Instant| {
            (
                found_in(s, &listen, lab, now)
                    .into_iter()
                    .map(|f| f.text)
                    .collect::<Vec<_>>(),
                inet_in(s, lab, now).map(|(a, _)| a.to_string()),
                forward_in(s, lab, now).map(|ip| ip.to_string()),
            )
        };
        let nothing = (Vec::<String>::new(), None, None);
        // A view of the QUIC listen socket at the listen port (the NAT
        // keeps ports): the IP and that endpoint.
        let quic_view = |s: &mut State, ip: &str, at: Instant| {
            let seen = Sighting {
                at: format!("{ip}:17423").parse().unwrap(),
                quic: true,
            };
            observe_in(s, seen, lab, at);
        };
        let at_7 = (
            vec![
                "/ip4/203.0.113.7/udp/17423/quic-v1".to_string(),
                "/ip4/203.0.113.7/tcp/17423".to_string(),
            ],
            Some("203.0.113.7:7422".to_string()),
            Some("203.0.113.7".to_string()),
        );
        let mut s = State {
            enabled: true,
            inet_listen: Some("0.0.0.0:7422".parse().unwrap()),
            ..State::default()
        };
        // Both servers agree, nobody saw this computer there: nothing told.
        stun(&mut s, "203.0.113.7", t0);
        assert_eq!(told(&s, t0), nothing, "told before anyone saw it");
        // A contact saw it at another IP: still nothing.
        note_seen(&mut s, "203.0.113.8".parse().unwrap(), t0);
        assert_eq!(told(&s, t0), nothing, "another IP was seen");
        // A contact saw it at the IP STUN named: the QUIC endpoint, the TCP
        // forward guess, Internet direct and the relay's IP, at that IP.
        quic_view(&mut s, "203.0.113.7", t0);
        assert_eq!(told(&s, t0), at_7);
        // The sighting stands while STUN keeps naming that IP, for a day.
        let t1 = t0 + Duration::from_secs(3600);
        stun(&mut s, "203.0.113.7", t1);
        assert_eq!(told(&s, t1), at_7);
        let t2 = t0 + SEEN_FOR + Duration::from_secs(1);
        stun(&mut s, "203.0.113.7", t2);
        assert_eq!(told(&s, t2), nothing, "a sighting older than a day");
        quic_view(&mut s, "203.0.113.7", t2);
        assert_eq!(told(&s, t2), at_7);
        // A contact reached the QUIC port from outside under that IP: it is
        // confirmed there...
        assert_eq!(
            confirm_in(
                &mut s,
                Reached::Quic,
                "192.0.2.50".parse().unwrap(),
                lab,
                t2
            ),
            Some(true)
        );
        assert!(found_in(&s, &listen, lab, t2)[0].confirmed);
        // ...and STUN then names another IP (someone took over the answers,
        // or the line moved): not told until seen there, and the old
        // confirmation does not carry over once it is.
        stun(&mut s, "198.51.100.9", t2);
        assert_eq!(told(&s, t2), nothing, "an IP nobody saw");
        quic_view(&mut s, "198.51.100.9", t2);
        let f = found_in(&s, &listen, lab, t2);
        assert_eq!(f[0].text, "/ip4/198.51.100.9/udp/17423/quic-v1");
        assert!(!f[0].confirmed, "confirmed under another IP");
        assert_eq!(inet_in(&s, lab, t2).map(|(_, c)| c), Some(false));
        // A network change forgets every sighting: the same answer on the
        // new network is told only once someone sees it there.
        forget_network(&mut s);
        stun(&mut s, "198.51.100.9", t2);
        assert_eq!(told(&s, t2), nothing, "a sighting from the old network");
        note_seen(&mut s, "198.51.100.9".parse().unwrap(), t2);
        assert_eq!(
            told(&s, t2).2,
            Some("198.51.100.9".to_string()),
            "seen on the new network"
        );
        // Turned off, nothing is kept.
        s.enabled = false;
        forget_network(&mut s);
        assert!(s.seen.is_empty() && s.seen_quic.is_empty() && s.confirmed.is_empty());
    }

    /// What counts as a sighting: an IPv4 address that may be told (never a
    /// private or documentation one outside the loopback lab, never IPv6),
    /// kept for at most MAX_SEEN IPs (the oldest gives way). It is said once
    /// when it covers the address STUN names, never naming the address. In
    /// the loopback lab 127.0.0.1 counts as seen and 127.0.0.2 does not.
    #[test]
    fn sightings_are_bounded_and_only_what_may_be_told() {
        let t0 = Instant::now();
        let mut s = State {
            enabled: true,
            ..State::default()
        };
        let v4 = |text: &str| -> Ipv4Addr { text.parse().unwrap() };
        let tcp = |text: &str| Sighting {
            at: SocketAddr::new(text.parse().unwrap(), 40123),
            quic: false,
        };
        for ip in [
            "192.168.1.9",
            "10.0.0.7",
            "203.0.113.7",
            "2001:db8::7",
            "::1",
        ] {
            assert_eq!(observe_in(&mut s, tcp(ip), false, t0), None);
        }
        assert!(s.seen.is_empty(), "{:?}", s.seen);
        // In the lab any unicast IPv4 counts; IPv6 never.
        assert_eq!(observe_in(&mut s, tcp("2001:db8::7"), true, t0), None);
        assert!(s.seen.is_empty());
        // STUN names 203.0.113.7: a sighting there is said once, with no
        // address in the line.
        s.refresh = Some(Seen {
            disc: disc("203.0.113.7", None, StunClass::StableKept),
            asked: 2,
            at: t0,
        });
        let line = observe_in(&mut s, tcp("203.0.113.7"), true, t0).unwrap();
        assert_eq!(
            line,
            "raven-node autoreach: public address seen from outside; contacts are told it"
        );
        assert!(!line.contains("203.0"), "{line}");
        assert_eq!(observe_in(&mut s, tcp("203.0.113.7"), true, t0), None);
        // At most MAX_SEEN IPs: newer sightings push out the oldest.
        for i in 1..=MAX_SEEN {
            let at = t0 + Duration::from_secs(i as u64);
            let ip = format!("198.51.100.{i}");
            assert_eq!(observe_in(&mut s, tcp(&ip), true, at), None);
        }
        assert_eq!(s.seen.len(), MAX_SEEN);
        assert!(!seen_at(&s, v4("203.0.113.7"), true, t0), "the oldest went");
        assert!(seen_at(&s, v4("198.51.100.1"), true, t0));
        // The loopback lab's own address counts as seen, only in the lab.
        assert!(seen_at(&s, Ipv4Addr::LOCALHOST, true, t0));
        assert!(!seen_at(&s, Ipv4Addr::LOCALHOST, false, t0));
        assert!(!seen_at(&s, v4("127.0.0.2"), true, t0));
    }

    /// INET-STUN-1 (design §3.2): STUN's port is no more authenticated than
    /// its IP, and behind a NAT shared with others whoever controls the
    /// answers could name a port of its own at the seen IP. So the QUIC
    /// endpoint (the anchor's mapped port, or the listen port where the NAT
    /// keeps ports) is told only once a contact or relay saw this
    /// computer's QUIC listen socket at that very IP and port. A view over
    /// TCP or from another socket, or at another port, vouches for the IP
    /// alone; a network change forgets them. The loopback lab's stand-in
    /// covers 127.0.0.1's endpoints too; a strict lab waits for the view.
    #[test]
    fn the_quic_endpoint_waits_for_a_quic_view_of_that_very_port() {
        let t0 = Instant::now();
        let lab = true;
        let listen = [ma("/ip4/0.0.0.0/udp/17423/quic-v1")];
        let told = |s: &State| -> Vec<String> {
            found_in(s, &listen, lab, t0)
                .into_iter()
                .map(|f| f.text)
                .collect()
        };
        let view = |at: &str, quic: bool| Sighting {
            at: at.parse().unwrap(),
            quic,
        };
        let anchored = |ip: &str, mapped: &str, class| Anchor {
            local: "0.0.0.0:17423".parse().unwrap(),
            disc: disc(ip, Some(mapped), class),
            at: t0,
        };
        // STUN named 203.0.113.7:40001 for the QUIC listen socket.
        let mut s = State {
            enabled: true,
            anchors: vec![anchored(
                "203.0.113.7",
                "203.0.113.7:40001",
                StunClass::StableShifted,
            )],
            ..State::default()
        };
        // Seen at that IP over TCP, and over QUIC from another socket: the
        // IP is seen, the endpoint is not told.
        observe_in(&mut s, view("203.0.113.7:51000", false), lab, t0);
        observe_in(&mut s, view("203.0.113.7:40001", false), lab, t0);
        assert!(seen_at(&s, "203.0.113.7".parse().unwrap(), lab, t0));
        assert_eq!(told(&s), Vec::<String>::new(), "a port nobody saw");
        // The listen socket seen at another port: still not.
        observe_in(&mut s, view("203.0.113.7:40002", true), lab, t0);
        assert_eq!(told(&s), Vec::<String>::new(), "another port was seen");
        // At that very endpoint: told.
        observe_in(&mut s, view("203.0.113.7:40001", true), lab, t0);
        assert_eq!(told(&s), vec!["/ip4/203.0.113.7/udp/40001/quic-v1"]);
        // A NAT that keeps ports: the listen port, once seen there.
        s.anchors = vec![anchored(
            "203.0.113.7",
            "203.0.113.7:17423",
            StunClass::StableKept,
        )];
        assert_eq!(told(&s), Vec::<String>::new());
        observe_in(&mut s, view("203.0.113.7:17423", true), lab, t0);
        assert_eq!(told(&s), vec!["/ip4/203.0.113.7/udp/17423/quic-v1"]);
        // A network change forgets the endpoints with the IPs.
        forget_network(&mut s);
        s.anchors = vec![anchored(
            "203.0.113.7",
            "203.0.113.7:17423",
            StunClass::StableKept,
        )];
        note_seen(&mut s, "203.0.113.7".parse().unwrap(), t0);
        assert_eq!(told(&s), Vec::<String>::new(), "an old network's view");
        // The loopback lab's stand-in: 127.0.0.1 and its endpoints count as
        // seen. A strict lab waits for a view of that very endpoint.
        s.anchors = vec![anchored("127.0.0.1", "127.0.0.1:17423", StunClass::NoNat)];
        let lab_endpoint = vec!["/ip4/127.0.0.1/udp/17423/quic-v1".to_string()];
        assert_eq!(told(&s), lab_endpoint);
        s.strict_lab = true;
        assert_eq!(told(&s), Vec::<String>::new(), "a strict lab's endpoint");
        observe_in(&mut s, view("127.0.0.1:17424", true), lab, t0);
        assert_eq!(told(&s), Vec::<String>::new());
        observe_in(&mut s, view("127.0.0.1:17423", true), lab, t0);
        assert_eq!(told(&s), lab_endpoint);
    }

    #[test]
    fn the_newest_probe_names_the_ip_and_a_moved_ip_re_homes() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(60);
        let mut s = State {
            anchors: vec![Anchor {
                local: "0.0.0.0:17423".parse().unwrap(),
                disc: disc(
                    "203.0.113.7",
                    Some("203.0.113.7:17423"),
                    StunClass::StableKept,
                ),
                at: t0,
            }],
            ..State::default()
        };
        assert_eq!(best_ip(&s, t1), Some("203.0.113.7".parse().unwrap()));
        assert!(!moved(&s));
        s.refresh = Some(Seen {
            disc: disc(
                "203.0.113.7",
                Some("203.0.113.7:50000"),
                StunClass::StableKept,
            ),
            asked: 3,
            at: t1,
        });
        assert!(!moved(&s), "the same IP");
        s.refresh = Some(Seen {
            disc: disc(
                "198.51.100.9",
                Some("198.51.100.9:50000"),
                StunClass::StableKept,
            ),
            asked: 3,
            at: t1,
        });
        assert!(moved(&s));
        assert_eq!(best_ip(&s, t1), Some("198.51.100.9".parse().unwrap()));
    }

    #[test]
    fn refresh_waits_back_off_to_the_interval() {
        let every = REFRESH_EVERY;
        assert_eq!(next_wait(every, 0), every);
        assert_eq!(next_wait(every, 1), RETRY_MIN);
        assert_eq!(next_wait(every, 2), RETRY_MIN * 2);
        assert_eq!(next_wait(every, 40), every);
        // A harness's short interval caps the backoff too.
        assert_eq!(next_wait(Duration::from_secs(5), 3), Duration::from_secs(5));
    }
}
