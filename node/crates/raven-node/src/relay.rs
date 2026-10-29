//! `raven-node relay` (transports design 2026-10 §3.5): a dedicated Circuit
//! Relay v2 relay for friends, e.g. on an always-on box at home, a Pi or a
//! small VPS. The relay kit installs it with one command per OS
//! (docs/RELAY_KIT.md).
//!
//! It holds **no Raven identity** and touches no keystore: its only key is
//! the libp2p key `relay_key.ed25519` (32-byte Ed25519 seed, owner-only), and
//! it refuses a folder that holds a Raven profile. It runs the relay server,
//! an optional AutoNAT v2 server, Identify and Ping with the limits of
//! [`RelayLimits`]; no Raven link protocol, no Kademlia, no mailbox.
//!
//! Only the PeerIds in `relay_allow.json` may connect, reserve and open
//! circuits, and circuits only to each other, the circle (on by default;
//! `raven relay allow|deny`), re-read every few seconds; a peer taken off the
//! list loses its reservation and its connection. Anyone else is refused by
//! the peer gate right after the Noise handshake, before any relay protocol
//! runs. No list admits nobody, an unreadable one admits nobody (fail
//! closed). `--open` serves anyone with the stricter limits, and stays a
//! presence oracle for strangers: a circuit to a peer that is reserved fails
//! differently from one to a peer that is not.
//! Logs and `relay_status.json` carry counts and ports only (NAT spec §5)
//! besides the relay's own PeerId, listen addresses and named addresses in
//! the status file, which `raven relay card` turns into `via=` lines for
//! friends. No relay address is compiled in anywhere.
//!
//! Listeners: TCP and QUIC on `--listen`, then TCP only on each `--also-tcp
//! LOCAL[:PUBLIC]` port (at most 2), e.g. 443 for networks that let only
//! HTTPS out. `--public-host` names the relay's public IP or DNS name with
//! every listening port, like `--external`. `--check` ([`check`]) looks at
//! the gate, the folder and every port, creates nothing and exits. Exit
//! codes ([`RelayExit`]): 0 a clean stop, 1 anything else, 2 bad flags
//! (main.rs), 3 held (the P2P gate is closed), 4 a listen port is busy or
//! needs a privilege, 5 the folder holds a profile or another relay runs in
//! it. Asked to stop (SIGTERM / SIGINT, Ctrl-C on Windows), it closes its
//! listeners and every connection, waits at most [`STOP_DRAIN`] and exits 0,
//! so clients see the reservation end at once instead of at a ping timeout.
//!
//! WSS on 443 (Phase 4, RWS1 §6; lab-only while `WSS_PRODUCTION_ENABLED` is
//! false: main.rs refuses `--wss` with WSS_HOLD, exit 2): `--wss
//! <PORT|IP:PORT>` adds a two-protocol TCP listener, `…/tcp/P/tls/ws`, for
//! networks that let only web traffic out. It takes WebSocket over TLS and
//! raw libp2p alike (the first byte decides), so it is the raw listener of
//! its port: a raw TCP listener on the same port (`--listen`'s, or Phase 2's
//! `--also-tcp 443`) is dropped, never opened beside it ([`listen_plan`]).
//! Its certificate ([`WssCert`]) is made at each start (self-signed, with
//! the `--wss-name` names) or is the operator's (`--wss-cert` with
//! `--wss-key`). The status file lists both forms of each address;
//! reservations, Identify and `advertised` name only the plain one (RWS1
//! §2.2), and lines name ports only, as for the other listeners. The relay
//! has no WSS client, so its AutoNAT dial-backs never go out over WSS.
//!
//! The same loop runs the friend relay of `raven-node service` (its own key
//! and folder): [`RelayCmd::label`] starts every line, its members come from
//! a shared watch instead of `relay_allow.json` ([`PolicySource`]), the
//! addresses it names from a feed, and it may ask the router for its port
//! (UPnP).
//!
//! What a relay learns: both PeerIds and IPs of every circuit, its timing,
//! duration and bytes, who reserves (and, with `--autonat-server`, the
//! addresses it is asked to probe). It never learns Raven IDs (unless it holds
//! cards that map PeerIds to them), plaintext, PairInit, RLB1, route tags or
//! message ids: they are inside libp2p Noise and, inside that, the Raven link.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use raven_core::clock::now_ms;
use raven_core::ipc::RelayCounts;
use raven_core::p2p_route::{relay_listen_multiaddrs, ExtraTcp, P2pListen};
use raven_core::relay_allow::{
    load_relay_allow, relay_is_running, write_relay_status, RelayStatusFile, RELAY_ALLOW_FILE,
    RELAY_KEY_FILE, RELAY_LOCK_FILE, RELAY_STATUS_HEARTBEAT,
};
use raven_swarm::host::{
    addr_ip, build_relay_swarm, is_circuit, is_global_ip, listen_port_label, probe_listen_addr,
    AllowPolicy, HostGate, ListenProbe, RelayAdvertiser, RelayBehaviourEvent, RelayGuard,
    RelayLimits, WssServerSide,
};
use raven_swarm::libp2p::core::ConnectedPoint;
use raven_swarm::libp2p::identity::Keypair;
use raven_swarm::libp2p::multiaddr::Protocol;
use raven_swarm::libp2p::swarm::{ConnectionId, SwarmEvent};
use raven_swarm::libp2p::{relay, upnp, Multiaddr, PeerId};
use raven_swarm::liveness::close_if_dead;
use tokio::sync::watch;

/// How often the allow-list is re-read and the status file refreshed (it is
/// rewritten when something changed, and at least every
/// [`RELAY_STATUS_HEARTBEAT`] as a heartbeat for `raven relay status`).
const RELOAD: Duration = Duration::from_secs(2);
/// How long a stop waits for the connections to close
/// ([`crate::p2p::SHUTDOWN_DRAIN`], as the endpoint's).
pub(crate) const STOP_DRAIN: Duration = crate::p2p::SHUTDOWN_DRAIN;

/// Who may reserve, from `relay_allow.json` in `dir`: `--open` admits anyone;
/// no file admits nobody; an unusable file admits nobody (fail closed). An
/// entry whose `expires_ms` has passed (a rotating friend's old PeerId, peer
/// rotation spec §7) is skipped: the next reload ([`RELOAD`]) drops it from
/// the policy, and the guard's recheck ends its reservation and circuits,
/// as for a removed entry.
pub(crate) fn allow_policy(dir: &Path, open: bool) -> AllowPolicy {
    if open {
        return AllowPolicy::Open;
    }
    match load_relay_allow(dir) {
        Ok(None) => AllowPolicy::Peers(HashSet::new()),
        Ok(Some(list)) => {
            let now = now_ms();
            let mut peers = HashSet::new();
            for entry in &list.peers {
                match entry.peer_id.parse::<PeerId>() {
                    // Still checked when expired: a bad entry fails closed.
                    Ok(_) if entry.expired(now) => {}
                    Ok(p) => {
                        peers.insert(p);
                    }
                    Err(_) => return AllowPolicy::Unreadable,
                }
            }
            AllowPolicy::Peers(peers)
        }
        Err(_) => AllowPolicy::Unreadable,
    }
}

/// Files whose presence means `dir` is a Raven profile, not a relay folder.
/// Only names are checked: nothing is opened, no keystore is asked.
const PROFILE_MARKERS: [&str; 4] = [
    raven_core::BACKEND_MARKER_NAME,
    raven_core::SEED_FILE_NAME,
    "contacts.json",
    raven_core::INDEXED_SESSION_METADATA_FILE,
];

fn refuse_profile_dir(dir: &Path) -> Result<(), String> {
    if PROFILE_MARKERS.iter().any(|m| dir.join(m).exists()) {
        return Err(format!(
            "{} holds a Raven profile: a relay needs a folder of its own (it holds no Raven \
             identity). Use `raven relay offer on` to relay from this profile with its own \
             relay key.",
            dir.display()
        ));
    }
    Ok(())
}

/// The relay's libp2p key: read `relay_key.ed25519`, or create it (32 random
/// bytes, owner-only, never overwritten). A profile's friend relay keeps it
/// under the profile's at-rest rules (privacy pack PP.6: RMS1 kind 31 in a
/// sealed profile; [`friend_relay_key`]).
pub(crate) fn load_or_create_relay_key(dir: &Path) -> Result<Keypair, String> {
    use rand::RngCore;
    if let Some(profile) = raven_core::relay_allow::friend_relay_profile(dir) {
        return friend_relay_key(profile, dir);
    }
    let path = dir.join(RELAY_KEY_FILE);
    if !path.exists() {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        match raven_core::paths::create_new_private(&path, &seed) {
            Ok(()) => {}
            // Another start won the race: use its key.
            Err(_) if path.exists() => {}
            Err(e) => return Err(format!("{RELAY_KEY_FILE}: {e}")),
        }
        seed.fill(0);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta =
            std::fs::symlink_metadata(&path).map_err(|e| format!("{RELAY_KEY_FILE}: {e}"))?;
        if !meta.is_file() {
            return Err(format!("{RELAY_KEY_FILE} is not a regular file"));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("{RELAY_KEY_FILE}: cannot restrict to owner-only: {e}"))?;
        }
    }
    let mut bytes = std::fs::read(&path).map_err(|e| format!("{RELAY_KEY_FILE}: {e}"))?;
    if bytes.len() != 32 {
        bytes.fill(0);
        return Err(format!(
            "{RELAY_KEY_FILE} must hold exactly 32 bytes; move it aside to make a new relay \
             identity (friends must then update their via= addresses)"
        ));
    }
    // `ed25519_from_bytes` zeroizes its input.
    Keypair::ed25519_from_bytes(&mut bytes).map_err(|e| format!("{RELAY_KEY_FILE}: {e}"))
}

/// [`load_or_create_relay_key`] of the friend relay of `profile` (its folder
/// `dir`): under the writer lock `at_rest::FILES` names, read sealed or
/// plain, or made (32 random bytes, sealed in a sealed profile). A key that
/// cannot be opened (the at-rest key not loaded yet, a changed byte) is an
/// error and is never replaced: the friend relay tries again later.
fn friend_relay_key(profile: &Path, dir: &Path) -> Result<Keypair, String> {
    use rand::RngCore;
    use raven_core::at_rest::{self, Kind};
    let path = dir.join(RELAY_KEY_FILE);
    raven_core::paths::ensure_private_dir(dir)?;
    let lock = at_rest::lock_file(profile, &path, Kind::FriendRelayKey)
        .map_err(|e| format!("{RELAY_KEY_FILE}: {e}"))?;
    let read = || {
        lock.load_bytes()
            .map_err(|e| format!("{RELAY_KEY_FILE}: {e}"))
    };
    let mut bytes = match read()? {
        Some(bytes) => bytes,
        None => {
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            let stored = lock.store_bytes(&seed);
            seed.fill(0);
            stored.map_err(|e| format!("{RELAY_KEY_FILE}: {e}"))?;
            read()?.ok_or_else(|| format!("{RELAY_KEY_FILE} vanished after it was written"))?
        }
    };
    if bytes.len() != 32 {
        return Err(format!(
            "{RELAY_KEY_FILE} must hold exactly 32 bytes; move it aside to make a new relay \
             identity (friends must then update their via= addresses)"
        ));
    }
    // `ed25519_from_bytes` zeroizes its input.
    Keypair::ed25519_from_bytes(&mut bytes[..]).map_err(|e| format!("{RELAY_KEY_FILE}: {e}"))
}

/// Why a relay would not start, or stopped other than when asked. Its
/// [`Self::code`] is the process exit code a supervisor and the relay kit
/// act on (0 is a clean stop, 2 bad flags).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RelayExit {
    /// The P2P gate is closed ([`raven_core::P2P_HOLD`]): no restart helps.
    Held,
    /// A listen port is busy or needs a privilege, or none could be opened.
    Port(String),
    /// The folder holds a Raven profile, another relay runs in it, or it
    /// cannot be made owner-only; or the `--wss` operator certificate or
    /// key cannot be used (a file the relay is pointed at: no restart
    /// helps until it is fixed).
    Folder(String),
    /// Anything else.
    Other(String),
}

impl RelayExit {
    /// Held 3, Port 4, Folder 5, Other 1 (stable: the relay kit and its
    /// docs name them).
    pub(crate) fn code(&self) -> i32 {
        match self {
            Self::Held => 3,
            Self::Port(_) => 4,
            Self::Folder(_) => 5,
            Self::Other(_) => 1,
        }
    }
}

impl fmt::Display for RelayExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Held => f.write_str(raven_core::P2P_HOLD),
            Self::Port(m) | Self::Folder(m) | Self::Other(m) => f.write_str(m),
        }
    }
}

/// Where a relay's members come from.
#[derive(Clone, Debug)]
pub(crate) enum PolicySource {
    /// `relay_allow.json` in its folder (or anyone, with `open`), re-read
    /// every [`RELOAD`]: `raven-node relay`.
    File,
    /// A watch its owner keeps up to date, read every [`RELOAD`]; the
    /// folder's allow-list is never read (the friend relay, whose members
    /// are the profile's verified contacts: [`crate::friend_relay`]).
    Shared(watch::Receiver<AllowPolicy>),
}

impl PolicySource {
    fn current(&self, dir: &Path, open: bool) -> AllowPolicy {
        match self {
            Self::File => allow_policy(dir, open),
            Self::Shared(rx) => rx.borrow().clone(),
        }
    }
}

/// `raven-node relay --wss`: the two-protocol TCP listener (RWS1 §6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WssListen {
    /// `…/tcp/P/tls/ws` on each of its addresses
    /// ([`P2pListen::wss_multiaddrs`]): TCP only.
    pub listen: P2pListen,
    pub cert: WssCert,
}

/// The certificate the WSS listener shows (RWS1 §4). Clients take any
/// certificate (libp2p Noise authenticates the relay inside the TLS), so it
/// only has to look like a web server's to the network in between.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WssCert {
    /// Self-signed, made at each start and kept in memory only, with these
    /// names (`--wss-name`) as its subjectAltNames (`localhost` without
    /// any).
    Ephemeral(Vec<String>),
    /// The operator's certificate chain (leaf first) and its private key,
    /// PEM files (`--wss-cert`, `--wss-key`), read at each start.
    Files(PathBuf, PathBuf),
}

impl WssCert {
    /// What the up line calls it.
    fn kind(&self) -> &'static str {
        match self {
            Self::Ephemeral(_) => "self-signed certificate",
            Self::Files(..) => "operator certificate",
        }
    }

    /// The listener's TLS side. An operator certificate that cannot be read
    /// or whose key is not the leaf's is an error (a later start may find
    /// it renewed).
    fn server_side(&self) -> Result<WssServerSide, String> {
        use raven_swarm::wss::tls::{ephemeral_server_tls, operator_server_tls};
        let tls = match self {
            Self::Ephemeral(names) => ephemeral_server_tls(names),
            Self::Files(chain, key) => operator_server_tls(chain, key),
        }
        .map_err(|e| format!("--wss: {e}"))?;
        Ok(WssServerSide { tls })
    }
}

/// What one relay runs with: `raven-node relay`'s flags (main.rs
/// `relay_command`), or the friend relay's settings.
#[derive(Clone, Debug)]
pub(crate) struct RelayCmd {
    pub data_dir: PathBuf,
    pub listen: P2pListen,
    pub open: bool,
    pub autonat_server: bool,
    pub limits: RelayLimits,
    /// Public addresses to name in reservations besides the listeners
    /// (`--external`, and the `--public-host` ones).
    pub external: Vec<Multiaddr>,
    /// TCP-only listeners besides `listen` (`--also-tcp`).
    pub also_tcp: Vec<ExtraTcp>,
    /// An `also_tcp` port that is busy, needs a privilege or cannot be
    /// opened is one line and skipped (the friend relay's 443), instead of
    /// [`RelayExit::Port`] (`raven-node relay`).
    pub extra_best_effort: bool,
    /// The WSS listener (`raven-node relay --wss`; never the friend relay's,
    /// RWS1 §2.3).
    pub wss: Option<WssListen>,
    /// A counts line at most this often (and only when the counts changed).
    pub counts_every: Duration,
    /// Ask the router to map the listen ports (UPnP-IGD, IPv4 only).
    pub upnp: bool,
    pub policy: PolicySource,
    /// Each new value replaces the named addresses
    /// ([`RelayAdvertiser::set_external`]; an empty one falls back to the
    /// listen addresses).
    pub external_feed: Option<watch::Receiver<Vec<Multiaddr>>>,
    /// Also holds the latest status (and `None` again after a stop).
    pub status_sink: Option<Arc<Mutex<Option<RelayStatusFile>>>>,
    /// Starts every line: "raven-node relay" or "raven-node friend relay".
    pub label: &'static str,
}

/// `refused`: reservations, circuits and connections (the peer gate).
fn counts(guard: &RelayGuard, open: bool, circuits: u32, refused: (u64, u64, u64)) -> RelayCounts {
    let c = guard.counts();
    RelayCounts {
        open,
        allowed_peers: c.allowed_peers,
        allow_list_unreadable: c.unreadable,
        reservations: c.active_reservations,
        circuits,
        reservations_refused: refused.0,
        circuits_refused: refused.1,
        connections_refused: refused.2,
    }
}

/// `file`: the members come from `relay_allow.json` ([`PolicySource::File`]),
/// so an empty list says how to add some. Otherwise (the friend relay) they
/// are the verified contacts plus the list kept by hand, minus the denied:
/// "members", never "allow-list", which names only the list kept by hand
/// (field test E2 r7).
fn policy_line(policy: &AllowPolicy, file: bool) -> String {
    match policy {
        AllowPolicy::Open => "open: anyone may reserve (stricter limits)".into(),
        AllowPolicy::Peers(p) if p.is_empty() && file => format!(
            "allow-list empty: nobody may reserve yet (add friends with `raven --data-dir <this \
             folder> relay allow`; {RELAY_ALLOW_FILE})"
        ),
        AllowPolicy::Peers(p) if p.is_empty() => {
            "no members (no verified contact, none added by hand): nobody may reserve yet".into()
        }
        AllowPolicy::Peers(p) if file => format!("allow-list: {} peer(s)", p.len()),
        AllowPolicy::Peers(p) => format!("members: {} peer(s)", p.len()),
        AllowPolicy::Unreadable if file => {
            format!("{RELAY_ALLOW_FILE} is unreadable: nobody may reserve until it is fixed")
        }
        AllowPolicy::Unreadable => "members unreadable: nobody may reserve".into(),
    }
}

/// `wss`: the WSS listener's certificate kind ([`WssCert::kind`]), when
/// there is one. Counts and ports only.
fn up_line(
    label: &str,
    listeners: usize,
    tcp_ports: &[u16],
    wss: Option<&str>,
    policy: &str,
) -> String {
    let ports: Vec<String> = tcp_ports.iter().map(u16::to_string).collect();
    let wss = wss
        .map(|kind| format!("wss=on ({kind}); "))
        .unwrap_or_default();
    format!(
        "{label}: up (listeners={listeners}; tcp ports {}; {wss}{policy})",
        ports.join(",")
    )
}

fn counts_line(label: &str, c: &RelayCounts) -> String {
    format!(
        "{label}: reservations={} circuits={} refused_reservations={} refused_circuits={} \
         refused_connections={}",
        c.reservations,
        c.circuits,
        c.reservations_refused,
        c.circuits_refused,
        c.connections_refused
    )
}

/// A port whose raw TCP listener the WSS listener replaces
/// ([`listen_plan`]).
fn shared_line(label: &str, port: u16) -> String {
    format!("{label}: port {port} serves raw libp2p and WSS")
}

fn stopped_line(label: &str, closed: usize) -> String {
    format!("{label}: stopped ({closed} connection(s) closed)")
}

/// Would the raw TCP listen address `raw` and the WSS one `wss` take the
/// same connections (review A-6)? The same fixed port and address family,
/// and the same IP or either one unspecified. An IPv6 listener is IPv6-only,
/// so it never overlaps an IPv4 one.
fn overlaps(raw: &Multiaddr, wss: &Multiaddr) -> bool {
    let port = tcp_port(raw).filter(|p| *p != 0);
    let (Some(a), Some(b)) = (addr_ip(raw), addr_ip(wss)) else {
        return false;
    };
    port.is_some()
        && port == tcp_port(wss)
        && a.is_ipv4() == b.is_ipv4()
        && (a == b || a.is_unspecified() || b.is_unspecified())
}

/// The TCP port of a listen address, if it is a TCP one.
fn tcp_port(addr: &Multiaddr) -> Option<u16> {
    addr.iter().find_map(|p| match p {
        Protocol::Tcp(n) => Some(n),
        _ => None,
    })
}

/// The `--also-tcp` ports friends reach on another port (`LOCAL:PUBLIC`):
/// `relay_status.json` keeps them, so `raven relay card --host` names the
/// public port, as `--public-host` does.
fn mapped_ports(also_tcp: &[ExtraTcp]) -> Vec<ExtraTcp> {
    also_tcp
        .iter()
        .filter(|e| e.local != e.public)
        .copied()
        .collect()
}

/// Is `addr` a WSS listen address (`…/tls/ws`)?
fn is_wss(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::Ws(_)))
}

/// What a relay listens on ([`listen_plan`]).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ListenPlan {
    pub addrs: Vec<Multiaddr>,
    /// How many of `addrs` (the first ones) are `--listen`'s.
    pub base: usize,
    /// The ports whose raw TCP listener the WSS listener replaces.
    pub shared: Vec<u16>,
}

/// Every address `cmd` listens on: TCP and QUIC on `listen`, then TCP on
/// each `also_tcp` port ([`relay_listen_multiaddrs`]), then `…/tcp/P/tls/ws`
/// on each of the WSS listener's addresses. The WSS listener is the raw
/// listener of its port (RWS1 §6): a raw TCP address on that port (Phase 2's
/// `--also-tcp 443`, or `--listen`'s) that it overlaps ([`overlaps`]: same
/// family, the same IP or a wildcard) is dropped instead of refused, and the
/// port is in `shared`. Two of our own sockets never share a port: probing
/// before binding cannot see our own, and SO_REUSEPORT would split the
/// connections between them. Port 0 (tests) is never shared.
pub(crate) fn listen_plan(cmd: &RelayCmd) -> Result<ListenPlan, RelayExit> {
    let parse = |t: &String| {
        t.parse::<Multiaddr>()
            .map_err(|e| RelayExit::Other(format!("relay listen: {e}")))
    };
    let raw = relay_listen_multiaddrs(&cmd.listen, &cmd.also_tcp)
        .map_err(|e| RelayExit::Other(format!("relay listen: {e}")))?;
    let wss = match &cmd.wss {
        Some(w) => w
            .listen
            .wss_multiaddrs()
            .iter()
            .map(parse)
            .collect::<Result<Vec<_>, _>>()?,
        None => Vec::new(),
    };
    let from_listen = cmd.listen.multiaddrs().len();
    let mut plan = ListenPlan {
        addrs: Vec::new(),
        base: 0,
        shared: Vec::new(),
    };
    for (i, text) in raw.iter().enumerate() {
        let addr = parse(text)?;
        if let Some(port) = tcp_port(&addr).filter(|_| wss.iter().any(|w| overlaps(&addr, w))) {
            if !plan.shared.contains(&port) {
                plan.shared.push(port);
            }
            continue;
        }
        if i < from_listen {
            plan.base += 1;
        }
        plan.addrs.push(addr);
    }
    plan.addrs.extend(wss);
    Ok(plan)
}

/// Which of `addrs` to open, from a probe of each before any is opened:
/// libp2p-tcp would share a port another program holds (SO_REUSEADDR /
/// SO_REUSEPORT) and silently lose connections to it. The first `base` are
/// `--listen`'s, then come `--also-tcp`'s, and the WSS listener's
/// (`…/tls/ws`) are `--wss`'s. A busy port, or one that needs a privilege,
/// is [`RelayExit::Port`], except an `--also-tcp` one when
/// `extra_best_effort`; a port that cannot be opened on this host is
/// skipped. Returns the addresses to open and one line per skipped port.
fn plan_listeners(
    addrs: Vec<Multiaddr>,
    base: usize,
    extra_best_effort: bool,
    label: &str,
    probe: impl Fn(&Multiaddr) -> Result<(), ListenProbe>,
) -> Result<(Vec<Multiaddr>, Vec<String>), RelayExit> {
    let mut usable = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    for (i, addr) in addrs.into_iter().enumerate() {
        let port = listen_port_label(&addr);
        let wss = is_wss(&addr);
        let extra = i >= base && !wss;
        let flag = if wss {
            "--wss"
        } else if extra {
            "--also-tcp"
        } else {
            "--listen"
        };
        let line = match probe(&addr) {
            Ok(()) => {
                usable.push(addr);
                continue;
            }
            Err(ListenProbe::Busy) if !(extra && extra_best_effort) => {
                return Err(RelayExit::Port(format!(
                    "relay listen: port {port} is already in use by another program (another \
                     relay or raven-node?); stop it or pick another {flag} port"
                )))
            }
            Err(ListenProbe::Privileged) if wss => {
                return Err(RelayExit::Port(format!(
                    "relay listen: port {port} (--wss) needs CAP_NET_BIND_SERVICE (the relay \
                     kit's systemd unit grants it) or root on this host (ports below 1024); \
                     otherwise use --wss on a high port and map 443 to it (see \
                     docs/RELAY_KIT.md)"
                )))
            }
            Err(ListenProbe::Privileged) if !(extra && extra_best_effort) => {
                return Err(RelayExit::Port(format!(
                    "relay listen: port {port} needs a privilege on this host (ports below \
                     1024): the relay kit's systemd unit grants CAP_NET_BIND_SERVICE; otherwise \
                     listen on a high port and map 443 to it (--also-tcp 7443:443, see \
                     docs/RELAY_KIT.md)"
                )))
            }
            Err(ListenProbe::Busy) => {
                format!("{label}: port {port} is already in use by another program; skipped")
            }
            Err(ListenProbe::Privileged) => format!(
                "{label}: port {port} cannot be opened by this user (Linux: \
                 CAP_NET_BIND_SERVICE or net.ipv4.ip_unprivileged_port_start); skipped"
            ),
            Err(ListenProbe::Absent | ListenProbe::Unavailable) => format!(
                "{label}: listen port {port} cannot be opened on this host (no such address \
                 family or interface); skipped"
            ),
        };
        if !lines.contains(&line) {
            lines.push(line);
        }
    }
    Ok((usable, lines))
}

/// A stamp further in the future than this is from a clock that went back:
/// [`earlier_confirmed_at`] does not keep it.
const CONFIRMED_CLOCK_SLACK_MS: u64 = 5 * 60 * 1000;

/// When this relay was last confirmed reachable (`confirmed_at_ms`: a member
/// reserved from a globally routable IP, or UPnP mapped its port), as the
/// status file of its last run in `dir` says, when that run had this key
/// (`peer`). A new run (a wake or a network change restarts the friend
/// relay, so does a new port) keeps it, so the confirmation, and the friend
/// relay's offer that rests on it, outlives the restart; its age still
/// counts from then. 0 when there is none, or it is from the future.
fn earlier_confirmed_at(dir: &Path, peer: &PeerId, now_ms: u64) -> u64 {
    raven_core::relay_allow::load_relay_status(dir)
        .ok()
        .flatten()
        .filter(|st| st.peer_id == peer.to_string())
        .map(|st| st.confirmed_at_ms)
        .filter(|at| *at <= now_ms.saturating_add(CONFIRMED_CLOCK_SLACK_MS))
        .unwrap_or(0)
}

/// Where each inbound connection comes from, while it is open: a
/// reservation accepted from a peer connected from a globally routable IP
/// proves that the relay is reachable from the Internet
/// (`relay_status.json` `confirmed_at_ms`). The addresses stay in memory:
/// never in a line or a file.
#[derive(Debug, Default)]
struct InboundFrom(HashMap<ConnectionId, (PeerId, Multiaddr)>);

impl InboundFrom {
    fn established(&mut self, peer: PeerId, id: ConnectionId, endpoint: &ConnectedPoint) {
        if let ConnectedPoint::Listener { send_back_addr, .. } = endpoint {
            self.0.insert(id, (peer, send_back_addr.clone()));
        }
    }

    fn closed(&mut self, id: &ConnectionId) {
        self.0.remove(id);
    }

    /// Is `peer` connected to us from a globally routable IP?
    fn global(&self, peer: &PeerId) -> bool {
        self.0
            .values()
            .any(|(p, from)| p == peer && addr_ip(from).is_some_and(is_global_ip))
    }
}

/// `relay_status.json` `advertised`: the addresses the advertiser names, in
/// its order (the operator's), then the swarm's other external addresses
/// (UPnP-confirmed), sorted. Never the loopback placeholder: it is the only
/// loopback external address the advertiser does not name (a router never
/// maps a loopback address).
fn advertised<'a>(
    named: Vec<Multiaddr>,
    external: impl Iterator<Item = &'a Multiaddr>,
) -> Vec<String> {
    let mut rest: Vec<&Multiaddr> = external
        .filter(|a| !named.contains(a) && !addr_ip(a).is_some_and(|ip| ip.is_loopback()))
        .collect();
    rest.sort();
    rest.dedup();
    named.iter().chain(rest).map(|a| a.to_string()).collect()
}

/// Keep `mapped`, the external addresses UPnP mapped for this relay's
/// ports (`relay_status.json` `upnp_addrs`), in step with `event`. `true`
/// when a mapping was confirmed.
fn note_upnp(mapped: &mut Vec<Multiaddr>, event: &upnp::Event) -> bool {
    match event {
        upnp::Event::NewExternalAddr { external_addr, .. } => {
            if !mapped.contains(external_addr) {
                mapped.push(external_addr.clone());
            }
            true
        }
        upnp::Event::ExpiredExternalAddr { external_addr, .. } => {
            mapped.retain(|a| a != external_addr);
            false
        }
        upnp::Event::GatewayNotFound | upnp::Event::NonRoutableGateway => false,
    }
}

/// The next value of the external-address feed. Pending forever without a
/// feed, or once its sender is gone (the named addresses then stay).
async fn next_external(feed: &mut Option<watch::Receiver<Vec<Multiaddr>>>) -> Vec<Multiaddr> {
    if let Some(rx) = feed {
        if rx.changed().await.is_ok() {
            return rx.borrow_and_update().clone();
        }
        *feed = None;
    }
    std::future::pending().await
}

fn store(sink: &Option<Arc<Mutex<Option<RelayStatusFile>>>>, status: Option<RelayStatusFile>) {
    if let Some(sink) = sink {
        *sink.lock().unwrap_or_else(|p| p.into_inner()) = status;
    }
}

/// `raven-node relay --check`: would this relay start? The gate, the folder
/// and every listen port (probed as a start probes them), then the relay
/// key and the allow-list, looked at only: nothing is created or changed,
/// not even the folder. One line per port, never an address. Returns the
/// lines and the exit code: 0, 3 held ([`RelayExit::Held`], ports not
/// probed), 4 a port problem, 5 the folder or the `--wss` certificate.
pub(crate) fn check(cmd: &RelayCmd) -> (Vec<String>, i32) {
    if !raven_core::p2p_live_enabled() {
        return (
            vec![raven_core::P2P_HOLD.to_string(), "ports not probed".into()],
            RelayExit::Held.code(),
        );
    }
    let folder = |line: String| (vec![line], RelayExit::Folder(String::new()).code());
    if let Err(e) = refuse_profile_dir(&cmd.data_dir) {
        return folder(e);
    }
    if relay_is_running(&cmd.data_dir) {
        return folder(format!(
            "a raven-node relay already runs in {} (one relay per folder): stop it first",
            cmd.data_dir.display()
        ));
    }
    let addrs = match listen_plan(cmd) {
        Ok(plan) => plan.addrs,
        Err(e) => return (vec![e.to_string()], e.code()),
    };
    // One verdict per port: both address families of `--listen PORT` are
    // one line.
    let mut ports: Vec<(String, Vec<Result<(), ListenProbe>>)> = Vec::new();
    for addr in &addrs {
        let port = listen_port_label(addr);
        let result = probe_listen_addr(addr);
        match ports.iter_mut().find(|(p, _)| *p == port) {
            Some((_, results)) => results.push(result),
            None => ports.push((port, vec![result])),
        }
    }
    let mut lines = Vec::new();
    let mut port_problem = false;
    for (port, results) in &ports {
        let verdict = if results.contains(&Err(ListenProbe::Busy)) {
            "busy (another program holds it)"
        } else if results.contains(&Err(ListenProbe::Privileged)) {
            "needs a privilege (ports below 1024)"
        } else if results.iter().any(Result::is_ok) {
            "ok"
        } else {
            "cannot be opened on this host"
        };
        port_problem |= verdict != "ok";
        lines.push(format!("listen {port} {verdict}"));
    }
    lines.push(format!(
        "relay key: {}",
        if cmd.data_dir.join(RELAY_KEY_FILE).is_file() {
            "present (PeerId kept)"
        } else {
            "created on first start"
        }
    ));
    lines.push(format!(
        "allow-list: {}",
        match cmd.policy.current(&cmd.data_dir, cmd.open) {
            AllowPolicy::Open => "not used (--open: anyone may reserve)".to_string(),
            AllowPolicy::Peers(p) if p.is_empty() => "none yet".to_string(),
            AllowPolicy::Peers(p) => format!("{} peer(s)", p.len()),
            AllowPolicy::Unreadable => "unreadable (nobody may reserve until it is fixed)".into(),
        }
    ));
    // The WSS listener's certificate, as a start builds it (review A-4):
    // an operator certificate or key that cannot be used fails here, not
    // at the start.
    let mut cert_problem = false;
    if let Some(w) = &cmd.wss {
        match w.cert.server_side() {
            Ok(_) => lines.push(format!("wss certificate: ok ({})", w.cert.kind())),
            Err(e) => {
                cert_problem = true;
                lines.push(format!("wss certificate: {e}"));
            }
        }
    }
    let code = if port_problem {
        RelayExit::Port(String::new()).code()
    } else if cert_problem {
        RelayExit::Folder(String::new()).code()
    } else {
        0
    };
    (lines, code)
}

/// Run the relay until `stop` resolves (then close everything and return
/// `Ok`), or until it cannot go on.
pub(crate) async fn run_relay(
    cmd: RelayCmd,
    stop: impl Future<Output = ()>,
) -> Result<(), RelayExit> {
    let label = cmd.label;
    let gate = HostGate::open(raven_core::p2p_live_enabled()).map_err(|_| RelayExit::Held)?;
    if cmd.wss.is_some() && !raven_core::wss_live_enabled() {
        // main.rs refuses `--wss` first (exit 2); never listen on WSS here.
        return Err(RelayExit::Other(raven_core::WSS_HOLD.into()));
    }
    cmd.limits
        .validate()
        .map_err(|e| RelayExit::Other(e.to_string()))?;
    let plan = listen_plan(&cmd)?;
    // Before anything is created: a certificate that cannot be used stops
    // the start, with the code `--check` gives it (5: the kit's unit does
    // not restart it; review A-4).
    let wss = match &cmd.wss {
        Some(w) => Some(w.cert.server_side().map_err(RelayExit::Folder)?),
        None => None,
    };
    raven_core::paths::ensure_private_dir(&cmd.data_dir).map_err(RelayExit::Folder)?;
    refuse_profile_dir(&cmd.data_dir).map_err(RelayExit::Folder)?;
    // One relay per folder, for its whole life (`raven relay status` probes
    // this lock to tell a stopped relay from a running one).
    let _instance = raven_core::paths::DataDirLock::acquire_within(
        &cmd.data_dir,
        RELAY_LOCK_FILE,
        Duration::from_secs(2),
    )
    .map_err(|_| {
        RelayExit::Folder(format!(
            "another raven-node relay already runs in {} (one relay per folder)",
            cmd.data_dir.display()
        ))
    })?;
    let key = load_or_create_relay_key(&cmd.data_dir).map_err(RelayExit::Other)?;
    let file = matches!(cmd.policy, PolicySource::File);
    let mut policy = cmd.policy.current(&cmd.data_dir, cmd.open);
    let guard = RelayGuard::new(policy.clone(), &cmd.limits);
    let mut swarm = build_relay_swarm(
        &gate,
        key,
        cmd.limits,
        &guard,
        cmd.autonat_server,
        cmd.upnp,
        wss,
    )
    .map_err(|e| RelayExit::Other(format!("relay: {e}")))?;
    let peer_id = *swarm.local_peer_id();
    for port in &plan.shared {
        eprintln!("{}", shared_line(label, *port));
    }
    // Probe every address before opening any.
    let (usable, skipped) = plan_listeners(
        plan.addrs,
        plan.base,
        cmd.extra_best_effort,
        label,
        probe_listen_addr,
    )?;
    for line in skipped {
        eprintln!("{line}");
    }
    let mut listeners = Vec::new();
    let mut tcp_ports: Vec<u16> = Vec::new();
    for addr in usable {
        let port = listen_port_label(&addr);
        let tcp = tcp_port(&addr);
        match swarm.listen_on(addr) {
            Ok(id) => {
                listeners.push(id);
                if let Some(p) = tcp.filter(|p| !tcp_ports.contains(p)) {
                    tcp_ports.push(p);
                }
            }
            Err(_) => eprintln!("{label}: listen port {port} could not be opened"),
        }
    }
    if listeners.is_empty() {
        return Err(RelayExit::Port(
            "relay listen: no listener could be opened".into(),
        ));
    }
    let listen_is_specific = matches!(cmd.listen, P2pListen::One(a) if !a.ip().is_unspecified());
    let mut advertiser = RelayAdvertiser::new(&mut swarm, listen_is_specific, &cmd.external);
    eprintln!(
        "{}",
        up_line(
            label,
            listeners.len(),
            &tcp_ports,
            cmd.wss.as_ref().map(|w| w.cert.kind()),
            &policy_line(&policy, file)
        )
    );
    if cmd.open {
        eprintln!(
            "{label}: OPEN relay: anyone may reserve and relay through this host; they all \
             learn its PeerId and address (stricter limits apply)"
        );
    }
    let mut feed = cmd.external_feed.clone();
    let mut inbound = InboundFrom::default();
    let mut upnp_state = if cmd.upnp {
        "on".to_string()
    } else {
        String::new()
    };
    let mut confirmed_at_ms = earlier_confirmed_at(&cmd.data_dir, &peer_id, now_ms());
    let mut upnp_addrs: Vec<Multiaddr> = Vec::new();
    let mut listen_addrs: Vec<Multiaddr> = Vec::new();
    let (mut circuits, mut res_refused, mut circ_refused) = (0u32, 0u64, 0u64);
    let mut published: Option<RelayStatusFile> = None;
    let mut last_write = tokio::time::Instant::now();
    let mut ticks = 0u32;
    let mut logged: Option<RelayCounts> = None;
    let mut last_log: Option<tokio::time::Instant> = None;
    let mut tick = tokio::time::interval(RELOAD);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(stop);
    loop {
        tokio::select! {
            biased;
            () = &mut stop => {
                // Clients see their reservation end now, not at a ping
                // timeout, and a restart finds the ports free.
                for id in listeners.drain(..) {
                    swarm.remove_listener(id);
                }
                let peers: Vec<PeerId> = swarm.connected_peers().copied().collect();
                for p in &peers {
                    let _ = swarm.disconnect_peer_id(*p);
                }
                let deadline = tokio::time::Instant::now() + STOP_DRAIN;
                while swarm.connected_peers().next().is_some() {
                    if tokio::time::timeout_at(deadline, swarm.select_next_some())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                store(&cmd.status_sink, None);
                eprintln!("{}", stopped_line(label, peers.len()));
                return Ok(());
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    if !is_circuit(&address) {
                        // A reservation must name at least one address, but
                        // never a LAN / loopback one nobody chose.
                        advertiser.on_new_listen_addr(&mut swarm, &address);
                        listen_addrs.push(address);
                    }
                }
                SwarmEvent::ExpiredListenAddr { address, .. } => {
                    advertiser.on_expired_listen_addr(&mut swarm, &address);
                    listen_addrs.retain(|a| *a != address);
                }
                SwarmEvent::ListenerError { .. } => {
                    eprintln!("{label}: a listener reported an error");
                }
                SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => {
                    inbound.established(peer_id, connection_id, &endpoint);
                }
                SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(event)) => {
                    guard.on_relay_event(&event);
                    match event {
                        relay::Event::ReservationReqAccepted { src_peer_id, .. } => {
                            if inbound.global(&src_peer_id) {
                                confirmed_at_ms = now_ms();
                            }
                        }
                        relay::Event::CircuitReqAccepted { .. } => circuits += 1,
                        relay::Event::CircuitClosed { .. } => circuits = circuits.saturating_sub(1),
                        relay::Event::CircuitReqDenied { .. } => circ_refused += 1,
                        relay::Event::ReservationReqDenied { .. } => res_refused += 1,
                        _ => {}
                    }
                }
                SwarmEvent::Behaviour(RelayBehaviourEvent::Upnp(event)) => {
                    if note_upnp(&mut upnp_addrs, &event) {
                        confirmed_at_ms = now_ms();
                    }
                    let (state, line) = crate::p2p::upnp_report(label, &event);
                    if state != upnp_state {
                        eprintln!("{line}");
                        upnp_state = state;
                    }
                }
                SwarmEvent::Behaviour(RelayBehaviourEvent::Ping(event)) => {
                    close_if_dead(&mut swarm, &event);
                }
                SwarmEvent::ConnectionClosed { peer_id, connection_id, num_established, .. } => {
                    inbound.closed(&connection_id);
                    guard.on_connection_closed(&peer_id, num_established);
                }
                _ => {}
            },
            addrs = next_external(&mut feed) => {
                advertiser.set_external(&mut swarm, &addrs);
            }
            _ = tick.tick() => {
                ticks = ticks.saturating_add(1);
                if ticks == 2 && cmd.external_feed.is_none() && advertiser.placeholder_only() {
                    eprintln!(
                        "{label}: no public address known (only private / loopback listen \
                         addresses): reservations name a loopback placeholder. Pass \
                         --public-host <your public IP or DNS name>, or --external \
                         /ip4/<public IP>/tcp/<port> (the address in `raven relay card --host`)"
                    );
                }
                guard.prune();
                let next = cmd.policy.current(&cmd.data_dir, cmd.open);
                if next != policy {
                    eprintln!("{label}: {}", policy_line(&next, file));
                    policy = next.clone();
                }
                for peer in guard.set_policy(next) {
                    let _ = swarm.disconnect_peer_id(peer);
                }
                // A member taken off the list loses its connection too, with
                // or without a reservation.
                for peer in swarm.behaviour().peer_gate.recheck() {
                    let _ = swarm.disconnect_peer_id(peer);
                }
                let conn_refused = swarm.behaviour().peer_gate.counts().total();
                let now = counts(
                    &guard,
                    cmd.open,
                    circuits,
                    (res_refused, circ_refused, conn_refused),
                );
                if logged.as_ref() != Some(&now)
                    && last_log.is_none_or(|t| t.elapsed() >= cmd.counts_every)
                {
                    eprintln!("{}", counts_line(label, &now));
                    logged = Some(now.clone());
                    last_log = Some(tokio::time::Instant::now());
                }
                let status = RelayStatusFile {
                    version: 1,
                    peer_id: peer_id.to_string(),
                    listen_addrs: listen_addrs.iter().map(|a| a.to_string()).collect(),
                    counts: now,
                    updated_at_ms: 0,
                    pid: std::process::id(),
                    advertised: advertised(advertiser.named(), swarm.external_addresses()),
                    upnp: upnp_state.clone(),
                    upnp_addrs: {
                        let mut texts: Vec<String> =
                            upnp_addrs.iter().map(|a| a.to_string()).collect();
                        texts.sort();
                        texts
                    },
                    confirmed_at_ms,
                    extra_tcp: mapped_ports(&cmd.also_tcp),
                };
                let stamped = RelayStatusFile {
                    updated_at_ms: now_ms(),
                    ..status.clone()
                };
                store(&cmd.status_sink, Some(stamped.clone()));
                // Rewritten on a change, and as a heartbeat.
                if published.as_ref() != Some(&status)
                    || last_write.elapsed() >= RELAY_STATUS_HEARTBEAT
                {
                    match write_relay_status(&cmd.data_dir, &stamped) {
                        Ok(()) => {
                            published = Some(status);
                            last_write = tokio::time::Instant::now();
                        }
                        Err(e) => eprintln!("{label}: status file: {e}"),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn peer(seed: u8) -> String {
        raven_core::p2p_route::local_peer_id(&raven_core::Identity::from_seed(&[seed; 32]))
    }

    /// `raven-node relay --data-dir <dir> --listen <listen>`, as main.rs
    /// fills it.
    pub(crate) fn dedicated(dir: &Path, listen: &str) -> RelayCmd {
        let listen = raven_core::p2p_route::normalize_p2p_listen(listen)
            .unwrap()
            .unwrap();
        RelayCmd {
            data_dir: dir.to_path_buf(),
            listen,
            open: false,
            autonat_server: false,
            limits: RelayLimits::friends(),
            external: Vec::new(),
            also_tcp: Vec::new(),
            extra_best_effort: false,
            wss: None,
            counts_every: Duration::from_secs(30),
            upnp: false,
            policy: PolicySource::File,
            external_feed: None,
            status_sink: None,
            label: "raven-node relay",
        }
    }

    /// Start `cmd` in a task; once its status file names a TCP and a QUIC
    /// listen address, return them with the relay's PeerId, the stop
    /// trigger and the task. Lab only (the gate must be open).
    pub(crate) async fn start(
        cmd: RelayCmd,
    ) -> (
        String,
        String,
        String,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<(), RelayExit>>,
    ) {
        let dir = cmd.data_dir.clone();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run_relay(cmd, async move {
            let _ = rx.await;
        }));
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(Some(st)) = raven_core::relay_allow::load_relay_status(&dir) {
                let find = |kind: &str| st.listen_addrs.iter().find(|a| a.contains(kind)).cloned();
                if let (Some(tcp), Some(quic)) = (find("/tcp/"), find("/quic-v1")) {
                    return (st.peer_id, tcp, quic, tx, task);
                }
            }
            assert!(!task.is_finished(), "the relay ended before it was up");
            assert!(
                std::time::Instant::now() < deadline,
                "the relay never came up"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// A new run of a relay keeps the confirmation its last run recorded
    /// with the same key (a wake or a network change restarts the friend
    /// relay); another key's, or one from the future, is not kept.
    #[test]
    fn a_restart_keeps_the_earlier_confirmation_of_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let me = load_or_create_relay_key(dir.path())
            .unwrap()
            .public()
            .to_peer_id();
        let now = 20_000 * 86_400_000u64;
        assert_eq!(earlier_confirmed_at(dir.path(), &me, now), 0, "no status");
        let status = |peer: &PeerId, at: u64| RelayStatusFile {
            version: 1,
            peer_id: peer.to_string(),
            confirmed_at_ms: at,
            ..RelayStatusFile::default()
        };
        write_relay_status(dir.path(), &status(&me, now - 3_600_000)).unwrap();
        assert_eq!(earlier_confirmed_at(dir.path(), &me, now), now - 3_600_000);
        let other = Keypair::generate_ed25519().public().to_peer_id();
        assert_eq!(earlier_confirmed_at(dir.path(), &other, now), 0);
        write_relay_status(dir.path(), &status(&me, now + 3_600_000)).unwrap();
        assert_eq!(earlier_confirmed_at(dir.path(), &me, now), 0, "future");
    }

    /// The same through a real restart: the new run reports the earlier
    /// `confirmed_at_ms` in its own status. Lab only.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restarted_relay_reports_its_earlier_confirmation() {
        if !raven_core::p2p_live_enabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let (peer_before, _, _, stop, task) = start(dedicated(dir.path(), "127.0.0.1:0")).await;
        let _ = stop.send(());
        assert!(task.await.unwrap().is_ok());
        let mut st = raven_core::relay_allow::load_relay_status(dir.path())
            .unwrap()
            .unwrap();
        let at = now_ms() - 3_600_000;
        st.confirmed_at_ms = at;
        st.updated_at_ms = 1;
        write_relay_status(dir.path(), &st).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run_relay(
            dedicated(dir.path(), "127.0.0.1:0"),
            async move {
                let _ = rx.await;
            },
        ));
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let st = loop {
            if let Ok(Some(st)) = raven_core::relay_allow::load_relay_status(dir.path()) {
                if st.updated_at_ms > 1 {
                    break st;
                }
            }
            assert!(!task.is_finished(), "the relay ended before it was up");
            assert!(std::time::Instant::now() < deadline, "no new status");
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(st.peer_id, peer_before);
        assert_eq!(st.confirmed_at_ms, at);
        let _ = tx.send(());
        assert!(task.await.unwrap().is_ok());
    }

    #[test]
    fn allow_policy_is_on_by_default_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            allow_policy(dir.path(), false),
            AllowPolicy::Peers(HashSet::new()),
            "no list: nobody"
        );
        assert_eq!(allow_policy(dir.path(), true), AllowPolicy::Open);
        raven_core::relay_allow::relay_allow(dir.path(), &peer(1), "bob").unwrap();
        match allow_policy(dir.path(), false) {
            AllowPolicy::Peers(p) => {
                assert_eq!(p.len(), 1);
                assert!(p.contains(&peer(1).parse().unwrap()));
            }
            other => panic!("{other:?}"),
        }
        std::fs::write(dir.path().join(RELAY_ALLOW_FILE), b"{broken").unwrap();
        assert_eq!(allow_policy(dir.path(), false), AllowPolicy::Unreadable);
        // `--open` does not depend on the file at all.
        assert_eq!(allow_policy(dir.path(), true), AllowPolicy::Open);
    }

    /// An entry whose `expires_ms` has passed admits nobody; one still
    /// running, or without the field, does. An invalid expired entry still
    /// fails the list closed.
    #[test]
    fn allow_policy_skips_expired_entries() {
        let dir = tempfile::tempdir().unwrap();
        let now = now_ms();
        let write = |entries: &[(String, Option<u64>)]| {
            let peers: Vec<_> = entries
                .iter()
                .map(|(p, at)| match at {
                    Some(at) => format!(r#"{{"peer_id":"{p}","expires_ms":{at}}}"#),
                    None => format!(r#"{{"peer_id":"{p}"}}"#),
                })
                .collect();
            let raw = format!(r#"{{"version":1,"peers":[{}]}}"#, peers.join(","));
            std::fs::write(dir.path().join(RELAY_ALLOW_FILE), raw).unwrap();
        };
        write(&[
            (peer(1), None),
            (peer(2), Some(now - 1)),
            (peer(3), Some(now + 3_600_000)),
        ]);
        match allow_policy(dir.path(), false) {
            AllowPolicy::Peers(p) => {
                let want: HashSet<PeerId> = [peer(1), peer(3)]
                    .iter()
                    .map(|p| p.parse().unwrap())
                    .collect();
                assert_eq!(p, want);
            }
            other => panic!("{other:?}"),
        }
        // The relay's own path: a schedule written by `raven relay allow
        // --schedule` is honoured the same way.
        let sched = [(1u64, peer(4)), (2, peer(5))];
        raven_core::relay_allow::relay_allow_schedule(dir.path(), "", &sched, |e| {
            if e == 1 {
                now - raven_core::relay_allow::SCHEDULE_GRACE_MS + 1_000
            } else {
                now + 3_600_000
            }
        })
        .unwrap();
        match allow_policy(dir.path(), false) {
            AllowPolicy::Peers(p) => {
                assert!(p.contains(&peer(4).parse().unwrap()), "not expired yet");
                assert!(p.contains(&peer(5).parse().unwrap()));
                assert!(!p.contains(&peer(2).parse().unwrap()));
            }
            other => panic!("{other:?}"),
        }
        write(&[(peer(1), None), ("12D3KooWnope".into(), Some(now - 1))]);
        assert_eq!(allow_policy(dir.path(), false), AllowPolicy::Unreadable);
        assert_eq!(allow_policy(dir.path(), true), AllowPolicy::Open);
    }

    #[test]
    fn the_relay_key_is_created_once_owner_only_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create_relay_key(dir.path()).unwrap();
        let again = load_or_create_relay_key(dir.path()).unwrap();
        assert_eq!(first.public().to_peer_id(), again.public().to_peer_id());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = dir.path().join(RELAY_KEY_FILE);
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            load_or_create_relay_key(dir.path()).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "tightened again");
        }
        std::fs::write(dir.path().join(RELAY_KEY_FILE), [1u8; 31]).unwrap();
        assert!(load_or_create_relay_key(dir.path()).is_err());
    }

    /// Privacy pack PP.6: a profile's friend relay keeps its key under the
    /// profile's at-rest rules: the raw 32 bytes in a plain profile, RMS1
    /// kind 31 once it is sealed (the same key: migrated in place; a new
    /// one is made sealed); a key this process cannot open (the at-rest key
    /// not loaded) is an error and never replaced. A dedicated relay folder
    /// keeps its plain key.
    #[test]
    fn a_profiles_friend_relay_key_follows_the_profile() {
        let lab = ["RAVEN_CHAT_HISTORY_BACKEND", "RAVEN_IDENTITY_BACKEND"]
            .iter()
            .any(|k| std::env::var(k).is_ok_and(|v| v == "locked-file"));
        if !(cfg!(windows) || (cfg!(debug_assertions) && lab)) {
            eprintln!("skipped: needs a debug build and RAVEN_CHAT_HISTORY_BACKEND=locked-file");
            return;
        }
        use raven_core::at_rest::{self, MigratePolicy};
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        std::fs::write(dd.join(raven_core::BACKEND_MARKER_NAME), b"locked-file\n").unwrap();
        let relay_dir = raven_core::relay_allow::friend_relay_dir(dd);
        let path = relay_dir.join(RELAY_KEY_FILE);
        let first = load_or_create_relay_key(&relay_dir).unwrap();
        assert_eq!(std::fs::read(&path).unwrap().len(), 32, "plain profile");
        let sealed =
            raven_core::privacy::migrate_all(dd, crate::now_ms(), MigratePolicy::Allow).unwrap();
        assert_eq!(sealed.outcome, raven_core::privacy::MigrateOutcome::Sealed);
        let raw = std::fs::read(&path).unwrap();
        assert!(at_rest::is_sealed(&raw) && raw[5] == 31, "migrated");
        let again = load_or_create_relay_key(&relay_dir).unwrap();
        assert_eq!(again.public().to_peer_id(), first.public().to_peer_id());
        std::fs::remove_file(&path).unwrap();
        let second = load_or_create_relay_key(&relay_dir).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(at_rest::is_sealed(&raw) && raw[5] == 31, "made sealed");
        assert_eq!(
            load_or_create_relay_key(&relay_dir)
                .unwrap()
                .public()
                .to_peer_id(),
            second.public().to_peer_id()
        );
        at_rest::forget_cached_keys(dd);
        assert!(load_or_create_relay_key(&relay_dir).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), raw, "never replaced");
        // A dedicated relay folder named like one, outside a profile: plain.
        let other = tempfile::tempdir().unwrap();
        let dedicated = other.path().join(raven_core::relay_allow::FRIEND_RELAY_DIR);
        std::fs::create_dir(&dedicated).unwrap();
        load_or_create_relay_key(&dedicated).unwrap();
        assert_eq!(
            std::fs::read(dedicated.join(RELAY_KEY_FILE)).unwrap().len(),
            32
        );
        assert_eq!(
            std::fs::read_dir(other.path()).unwrap().count(),
            1,
            "no lock file"
        );
    }

    #[test]
    fn a_profile_folder_is_never_used_as_a_relay_folder() {
        let dir = tempfile::tempdir().unwrap();
        refuse_profile_dir(dir.path()).unwrap();
        std::fs::write(dir.path().join("contacts.json"), b"[]").unwrap();
        let err = refuse_profile_dir(dir.path()).unwrap_err();
        assert!(err.contains("needs a folder of its own"), "{err}");
    }

    #[tokio::test]
    async fn the_relay_is_held_while_the_gate_is_closed() {
        if raven_core::p2p_live_enabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let err = run_relay(dedicated(dir.path(), "127.0.0.1:0"), std::future::pending())
            .await
            .unwrap_err();
        assert_eq!(err, RelayExit::Held);
        assert_eq!(err.to_string(), raven_core::P2P_HOLD);
        // Held before anything is created: no key, no status file.
        assert!(!dir.path().join(RELAY_KEY_FILE).exists());
    }

    #[test]
    fn relay_exit_codes_are_stable() {
        // The relay kit's installers and docs/RELAY_KIT.md name these.
        assert_eq!(RelayExit::Held.code(), 3);
        assert_eq!(RelayExit::Port("p".into()).code(), 4);
        assert_eq!(RelayExit::Folder("f".into()).code(), 5);
        assert_eq!(RelayExit::Other("o".into()).code(), 1);
        assert_eq!(RelayExit::Port("busy".into()).to_string(), "busy");
        assert!(RelayExit::Held.to_string().starts_with("P2P_HOLD:"));
    }

    #[test]
    fn check_creates_nothing_and_is_held_without_the_gate() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("relay");
        let (lines, code) = check(&dedicated(&dir, "127.0.0.1:0"));
        if raven_core::p2p_live_enabled() {
            assert_eq!(code, 0, "{lines:?}");
            assert!(lines.contains(&"listen 0/tcp ok".to_string()), "{lines:?}");
            assert!(lines.contains(&"listen 0/udp ok".to_string()), "{lines:?}");
            assert!(lines.contains(&"relay key: created on first start".to_string()));
            assert!(lines.contains(&"allow-list: none yet".to_string()));
        } else {
            assert_eq!(code, 3);
            assert_eq!(lines, [raven_core::P2P_HOLD, "ports not probed"]);
        }
        assert!(lines.iter().all(|l| !l.contains("127.0.0.1")), "{lines:?}");
        // Not even the folder.
        assert!(!dir.exists());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        // A profile folder or a running relay is the folder's exit code.
        if raven_core::p2p_live_enabled() {
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(dir.join("contacts.json"), b"[]").unwrap();
            let (lines, code) = check(&dedicated(&dir, "127.0.0.1:0"));
            assert_eq!(code, 5, "{lines:?}");
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "nothing added");
        }
    }

    #[test]
    fn check_names_a_busy_port() {
        if !raven_core::p2p_live_enabled() {
            return;
        }
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();
        let dir = tempfile::tempdir().unwrap();
        let (lines, code) = check(&dedicated(dir.path(), &format!("127.0.0.1:{port}")));
        assert_eq!(code, 4, "{lines:?}");
        assert!(
            lines.contains(&format!(
                "listen {port}/tcp busy (another program holds it)"
            )),
            "{lines:?}"
        );
        assert!(lines.iter().all(|l| !l.contains("127.0.0.1")), "{lines:?}");
        // An extra port that is busy is named too.
        let mut cmd = dedicated(dir.path(), "127.0.0.1:0");
        cmd.also_tcp = vec![ExtraTcp {
            local: port,
            public: port,
        }];
        let (lines, code) = check(&cmd);
        assert_eq!(code, 4, "{lines:?}");
        assert!(lines.contains(&format!(
            "listen {port}/tcp busy (another program holds it)"
        )));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// Review A-4: `--check` builds the WSS listener's certificate as a
    /// start does: an operator certificate or key that cannot be used is a
    /// `wss certificate:` line and exit 5, and the start itself exits 5 too
    /// (the kit's unit does not restart it), before anything is created.
    #[tokio::test]
    async fn check_and_start_refuse_a_wss_certificate_they_cannot_use() {
        if !raven_core::p2p_live_enabled() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("relay");
        let mut cmd = dedicated(&dir, "127.0.0.1:0");
        cmd.wss = Some(WssListen {
            cert: WssCert::Files(root.path().join("chain.pem"), root.path().join("key.pem")),
            ..wss_at("127.0.0.1:0")
        });
        let (lines, code) = check(&cmd);
        assert_eq!(code, 5, "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("wss certificate: --wss: certificate chain")),
            "{lines:?}"
        );
        if raven_core::wss_live_enabled() {
            let err = run_relay(cmd.clone(), std::future::pending())
                .await
                .unwrap_err();
            assert_eq!(err.code(), 5, "{err}");
            assert!(!dir.exists(), "nothing created");
        }
        // A self-signed certificate is always usable.
        cmd.wss = Some(wss_at("127.0.0.1:0"));
        let (lines, code) = check(&cmd);
        assert_eq!(code, 0, "{lines:?}");
        assert!(lines.contains(&"wss certificate: ok (self-signed certificate)".to_string()));
        assert!(!dir.exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relay_stops_cleanly_when_asked() {
        if !raven_core::p2p_live_enabled() {
            return;
        }
        use raven_swarm::gate::{GateHandle, PeerClass};
        use raven_swarm::host::{build_endpoint_swarm, EndpointConfig};
        use raven_swarm::libp2p::swarm::dial_opts::DialOpts;
        let dir = tempfile::tempdir().unwrap();
        // A member, connected when the stop comes.
        let member_key = Keypair::ed25519_from_bytes([5u8; 32]).unwrap();
        let member = member_key.public().to_peer_id();
        raven_core::relay_allow::relay_allow(dir.path(), &member.to_string(), "m").unwrap();
        let sink = Arc::new(Mutex::new(None));
        let mut cmd = dedicated(dir.path(), "127.0.0.1:0");
        cmd.status_sink = Some(sink.clone());
        let (relay_peer, tcp, _, stop, task) = start(cmd).await;
        assert!(relay_is_running(dir.path()));
        assert!(sink.lock().unwrap().is_some(), "the sink holds the status");
        let relay_peer: PeerId = relay_peer.parse().unwrap();
        let gate = GateHandle::default();
        gate.replace(
            HashMap::from([(relay_peer, PeerClass::OWN_RELAY)]),
            false,
            std::time::Instant::now(),
        );
        let mut client = build_endpoint_swarm(
            &HostGate::open(true).unwrap(),
            member_key,
            EndpointConfig {
                gate,
                ..EndpointConfig::default()
            },
        )
        .unwrap();
        client
            .dial(
                DialOpts::peer_id(relay_peer)
                    .addresses(vec![tcp.parse().unwrap()])
                    .build(),
            )
            .unwrap();
        // Until `want` is the member's connection state, within `secs`.
        async fn wait_until(
            client: &mut raven_swarm::libp2p::Swarm<raven_swarm::host::EndpointBehaviour>,
            relay: PeerId,
            want: bool,
            secs: u64,
        ) {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
            while client.is_connected(&relay) != want {
                tokio::time::timeout_at(deadline, client.select_next_some())
                    .await
                    .unwrap_or_else(|_| panic!("connected={want} within {secs} s"));
            }
        }
        wait_until(&mut client, relay_peer, true, 10).await;
        // Kept: the gate admits a member.
        tokio::time::sleep(Duration::from_millis(500)).await;
        wait_until(&mut client, relay_peer, true, 1).await;
        let asked = std::time::Instant::now();
        stop.send(()).unwrap();
        // The member sees the connection close at once, not at a ping
        // timeout.
        wait_until(&mut client, relay_peer, false, 3).await;
        let ended = tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .expect("stopped within 3 s")
            .unwrap();
        assert_eq!(ended, Ok(()));
        assert!(asked.elapsed() < Duration::from_secs(3));
        assert!(!relay_is_running(dir.path()), "the folder lock is released");
        assert!(
            sink.lock().unwrap().is_none(),
            "a stopped relay holds no status"
        );
    }

    /// `relay_status.json` keeps the ports a router or firewall maps
    /// (the kit's 7443:443), and only those.
    #[test]
    fn the_status_file_keeps_the_mapped_ports() {
        let tcp = |local, public| ExtraTcp { local, public };
        assert_eq!(
            mapped_ports(&[tcp(443, 443), tcp(7443, 443)]),
            [tcp(7443, 443)]
        );
        assert!(mapped_ports(&[tcp(443, 443), tcp(0, 0)]).is_empty());
    }

    #[test]
    fn an_extra_port_is_best_effort_only_when_asked() {
        let listen = raven_core::p2p_route::P2pListen::All(7423);
        let extra = [ExtraTcp {
            local: 443,
            public: 443,
        }];
        let addrs: Vec<Multiaddr> = relay_listen_multiaddrs(&listen, &extra)
            .unwrap()
            .iter()
            .map(|t| t.parse().unwrap())
            .collect();
        let base = listen.multiaddrs().len();
        for refusal in [
            ListenProbe::Busy,
            ListenProbe::Privileged,
            ListenProbe::Unavailable,
        ] {
            let probe = |a: &Multiaddr| {
                if tcp_port(a) == Some(443) {
                    Err(refusal)
                } else {
                    Ok(())
                }
            };
            // The friend relay: one line, never fatal.
            let (usable, lines) =
                plan_listeners(addrs.clone(), base, true, "raven-node friend relay", probe)
                    .unwrap();
            assert_eq!(usable.len(), base, "{refusal:?}");
            assert_eq!(lines.len(), 1, "{refusal:?}: {lines:?}");
            assert!(lines[0].starts_with("raven-node friend relay: "));
            assert!(lines[0].contains("443/tcp") && lines[0].ends_with("skipped"));
            // `raven-node relay`: a busy or privileged port is fatal.
            let dedicated = plan_listeners(addrs.clone(), base, false, "raven-node relay", probe);
            match refusal {
                ListenProbe::Busy | ListenProbe::Privileged => {
                    let err = dedicated.unwrap_err();
                    assert_eq!(err.code(), 4, "{err}");
                    assert!(err.to_string().contains("443/tcp"), "{err}");
                }
                _ => assert_eq!(dedicated.unwrap().0.len(), base),
            }
        }
        // `--listen`'s own port is never best effort.
        let busy_base = |a: &Multiaddr| {
            if tcp_port(a) == Some(7423) {
                Err(ListenProbe::Busy)
            } else {
                Ok(())
            }
        };
        let err =
            plan_listeners(addrs, base, true, "raven-node friend relay", busy_base).unwrap_err();
        assert!(matches!(err, RelayExit::Port(_)), "{err:?}");
        assert!(err.to_string().contains("--listen"), "{err}");
    }

    /// `raven-node relay --wss <listen>` with a self-signed certificate.
    fn wss_at(listen: &str) -> WssListen {
        WssListen {
            listen: raven_core::p2p_route::normalize_p2p_listen(listen)
                .unwrap()
                .unwrap(),
            cert: WssCert::Ephemeral(Vec::new()),
        }
    }

    /// RWS1 §6: the WSS listener is the raw listener of its port. A raw TCP
    /// address on the WSS port (Phase 2's `--also-tcp 443`, or `--listen`'s)
    /// is dropped, not refused, so no fixed port is ever bound by two of our
    /// own sockets; QUIC on the same port number stays, and the mapping of a
    /// replaced `--also-tcp LOCAL:PUBLIC` stays in the status file. Port 0
    /// (tests) is never shared.
    #[test]
    fn a_wss_port_replaces_the_raw_listener_of_its_port() {
        let tcp = |local, public| ExtraTcp { local, public };
        let plan = |listen: &str, also: &[ExtraTcp], wss: Option<&str>| {
            let mut cmd = dedicated(Path::new("relay"), listen);
            cmd.also_tcp = also.to_vec();
            cmd.wss = wss.map(wss_at);
            (listen_plan(&cmd).unwrap(), cmd)
        };
        let texts =
            |p: &ListenPlan| -> Vec<String> { p.addrs.iter().map(|a| a.to_string()).collect() };
        let raw_7423 = [
            "/ip4/0.0.0.0/tcp/7423",
            "/ip4/0.0.0.0/udp/7423/quic-v1",
            "/ip6/::/tcp/7423",
            "/ip6/::/udp/7423/quic-v1",
        ];
        let wss_443 = ["/ip4/0.0.0.0/tcp/443/tls/ws", "/ip6/::/tcp/443/tls/ws"];
        // Phase 2's raw 443 becomes the WSS listener.
        let (kit, _) = plan("7423", &[tcp(443, 443)], Some("443"));
        assert_eq!(texts(&kit), [&raw_7423[..], &wss_443[..]].concat());
        assert_eq!((kit.base, kit.shared.clone()), (4, vec![443]));
        // `--listen`'s own port: its QUIC stays.
        let (same, _) = plan("443", &[], Some("443"));
        assert_eq!(
            texts(&same),
            [
                "/ip4/0.0.0.0/udp/443/quic-v1",
                "/ip6/::/udp/443/quic-v1",
                wss_443[0],
                wss_443[1]
            ]
        );
        assert_eq!((same.base, same.shared.clone()), (2, vec![443]));
        // The kit's mapped 7443:443: no raw 7443 listener, the mapping kept.
        let (mapped, cmd) = plan("7423", &[tcp(7443, 443)], Some("7443"));
        assert_eq!(
            texts(&mapped),
            [
                &raw_7423[..],
                &["/ip4/0.0.0.0/tcp/7443/tls/ws", "/ip6/::/tcp/7443/tls/ws"][..]
            ]
            .concat()
        );
        assert_eq!(mapped.shared, [7443]);
        assert_eq!(mapped_ports(&cmd.also_tcp), [tcp(7443, 443)]);
        // Another port: nothing replaced.
        let (apart, _) = plan("7423", &[tcp(443, 443)], Some("8443"));
        assert!(apart.shared.is_empty());
        assert_eq!(apart.addrs.len(), 4 + 2 + 2);
        // One address: the same rule.
        let (one, _) = plan("127.0.0.1:7423", &[], Some("127.0.0.1:7423"));
        assert_eq!(
            texts(&one),
            [
                "/ip4/127.0.0.1/udp/7423/quic-v1",
                "/ip4/127.0.0.1/tcp/7423/tls/ws"
            ]
        );
        // Review A-6: a WSS listener on one IP replaces only the raw
        // listeners it overlaps (same family, the same IP or a wildcard):
        // the IPv4 wildcard goes, the IPv6 one stays.
        let (v4_only, _) = plan("443", &[], Some("203.0.113.5:443"));
        assert_eq!(
            texts(&v4_only),
            [
                "/ip4/0.0.0.0/udp/443/quic-v1",
                "/ip6/::/tcp/443",
                "/ip6/::/udp/443/quic-v1",
                "/ip4/203.0.113.5/tcp/443/tls/ws"
            ]
        );
        assert_eq!((v4_only.base, v4_only.shared.clone()), (3, vec![443]));
        let (kit_v4, _) = plan("7423", &[tcp(443, 443)], Some("203.0.113.5:443"));
        assert_eq!(
            texts(&kit_v4),
            [
                &raw_7423[..],
                &["/ip6/::/tcp/443", "/ip4/203.0.113.5/tcp/443/tls/ws"][..]
            ]
            .concat()
        );
        assert_eq!(kit_v4.shared, [443]);
        let (v6_only, _) = plan("443", &[], Some("[2001:db8::5]:443"));
        assert_eq!(
            texts(&v6_only),
            [
                "/ip4/0.0.0.0/tcp/443",
                "/ip4/0.0.0.0/udp/443/quic-v1",
                "/ip6/::/udp/443/quic-v1",
                "/ip6/2001:db8::5/tcp/443/tls/ws"
            ]
        );
        // A raw listener on one IP under a wildcard WSS listener goes; one
        // on another IP of the same family than a one-IP WSS listener stays.
        let (under, _) = plan("203.0.113.5:443", &[], Some("443"));
        assert_eq!(
            texts(&under),
            ["/ip4/203.0.113.5/udp/443/quic-v1", wss_443[0], wss_443[1]]
        );
        let (beside, _) = plan("203.0.113.6:443", &[], Some("203.0.113.5:443"));
        assert_eq!(
            texts(&beside),
            [
                "/ip4/203.0.113.6/tcp/443",
                "/ip4/203.0.113.6/udp/443/quic-v1",
                "/ip4/203.0.113.5/tcp/443/tls/ws"
            ]
        );
        assert!(beside.shared.is_empty());
        // Port 0: every listener gets a port of its own.
        let (any, _) = plan("127.0.0.1:0", &[tcp(0, 0)], Some("127.0.0.1:0"));
        assert_eq!(any.addrs.len(), 4);
        assert!(any.shared.is_empty());
        // Without --wss: as before.
        let (before, _) = plan("7423", &[tcp(443, 443)], None);
        assert_eq!(
            texts(&before),
            relay_listen_multiaddrs(&P2pListen::All(7423), &[tcp(443, 443)]).unwrap()
        );
        assert_eq!((before.base, before.shared.is_empty()), (4, true));
        // Never two of our own sockets on one fixed TCP port and family.
        for p in [
            &kit, &same, &mapped, &apart, &one, &before, &v4_only, &kit_v4, &v6_only, &under,
        ] {
            let mut bound: Vec<(bool, u16)> = Vec::new();
            for a in &p.addrs {
                if let Some(port) = tcp_port(a) {
                    let v4 = addr_ip(a).is_some_and(|ip| ip.is_ipv4());
                    assert!(!bound.contains(&(v4, port)), "twice: {a}");
                    bound.push((v4, port));
                }
            }
        }
    }

    /// The WSS listener's probe results name `--wss`: a port that needs a
    /// privilege says CAP_NET_BIND_SERVICE or root (never best effort), a
    /// busy one the usual text; lines name ports only.
    #[test]
    fn a_wss_port_that_needs_a_privilege_says_so() {
        let mut cmd = dedicated(Path::new("relay"), "7423");
        cmd.wss = Some(wss_at("443"));
        let plan = listen_plan(&cmd).unwrap();
        let at_443 = |refusal: ListenProbe| {
            move |a: &Multiaddr| {
                if tcp_port(a) == Some(443) {
                    Err(refusal)
                } else {
                    Ok(())
                }
            }
        };
        for best_effort in [false, true] {
            let run = |refusal| {
                plan_listeners(
                    plan.addrs.clone(),
                    plan.base,
                    best_effort,
                    "raven-node relay",
                    at_443(refusal),
                )
            };
            let err = run(ListenProbe::Privileged).unwrap_err();
            assert_eq!(err.code(), 4);
            assert_eq!(
                err.to_string(),
                "relay listen: port 443/tcp (--wss) needs CAP_NET_BIND_SERVICE (the relay kit's \
                 systemd unit grants it) or root on this host (ports below 1024); otherwise use \
                 --wss on a high port and map 443 to it (see docs/RELAY_KIT.md)"
            );
            let err = run(ListenProbe::Busy).unwrap_err();
            assert_eq!(err.code(), 4);
            assert!(
                err.to_string().contains("443/tcp is already in use")
                    && err.to_string().ends_with("pick another --wss port"),
                "{err}"
            );
            let (usable, lines) = run(ListenProbe::Absent).unwrap();
            assert_eq!(usable.len(), 4, "the WSS addresses are skipped");
            assert_eq!(
                lines,
                [
                    "raven-node relay: listen port 443/tcp cannot be opened on this host (no such \
                  address family or interface); skipped"
                ]
            );
        }
        let (usable, lines) =
            plan_listeners(plan.addrs.clone(), plan.base, false, "x", |_| Ok(())).unwrap();
        assert_eq!(usable, plan.addrs);
        assert!(lines.is_empty());
    }

    /// The up line names the certificate kind, the shared-port line the
    /// port: never a name, a path or an address.
    #[test]
    fn the_wss_lines_name_ports_and_the_certificate_kind_only() {
        let policy = policy_line(&AllowPolicy::Open, true);
        for (cert, kind) in [
            (
                WssCert::Ephemeral(vec!["relay.example.org".into(), "203.0.113.7".into()]),
                "self-signed certificate",
            ),
            (
                WssCert::Files("certs/fullchain.pem".into(), "certs/privkey.pem".into()),
                "operator certificate",
            ),
        ] {
            let line = up_line(
                "raven-node relay",
                4,
                &[7423, 443],
                Some(cert.kind()),
                &policy,
            );
            assert_eq!(
                line,
                format!(
                    "raven-node relay: up (listeners=4; tcp ports 7423,443; wss=on ({kind}); \
                     open: anyone may reserve (stricter limits))"
                )
            );
            for leak in ["relay.example.org", "203.0.113.7", "certs", ".pem"] {
                assert!(!line.contains(leak), "{line}");
            }
        }
        assert_eq!(
            shared_line("raven-node relay", 443),
            "raven-node relay: port 443 serves raw libp2p and WSS"
        );
    }

    /// The listener's TLS side: a self-signed certificate is made with any
    /// names; an operator certificate that cannot be read is an error that
    /// names no path.
    #[test]
    fn a_wss_certificate_is_made_or_read() {
        let made = WssCert::Ephemeral(vec!["relay.example.org".into(), "2001:db8::7".into()]);
        assert!(made.server_side().is_ok());
        assert!(WssCert::Ephemeral(Vec::new()).server_side().is_ok());
        let dir = tempfile::tempdir().unwrap();
        let missing = WssCert::Files(dir.path().join("fullchain.pem"), dir.path().join("key.pem"));
        let err = missing.server_side().unwrap_err();
        assert!(err.starts_with("--wss: certificate chain: "), "{err}");
        assert!(!err.contains("fullchain"), "{err}");
    }

    /// A relay never listens on WSS while the WSS gate is closed, even if a
    /// caller other than main.rs (which refuses `--wss` first) asks.
    #[tokio::test]
    async fn the_wss_listener_is_held_with_its_gate() {
        if raven_core::wss_live_enabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut cmd = dedicated(dir.path(), "127.0.0.1:0");
        cmd.wss = Some(wss_at("127.0.0.1:0"));
        let err = run_relay(cmd, std::future::pending()).await.unwrap_err();
        if raven_core::p2p_live_enabled() {
            assert_eq!(err, RelayExit::Other(raven_core::WSS_HOLD.into()));
        } else {
            assert_eq!(err, RelayExit::Held);
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// `relay_status.json` lists both forms of the WSS listener's address
    /// (`…/tcp/P/tls/ws` and `…/tcp/P`), and the raw `--also-tcp P` beside
    /// it was never opened: one raw `/tcp/P`, from the WSS listener. The
    /// relay names only the plain form, and a member reaches it on that one
    /// port over WSS and over raw libp2p. Lab only (both gates open).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relay_status_lists_both_forms() {
        if !(raven_core::p2p_live_enabled() && raven_core::wss_live_enabled()) {
            return;
        }
        use raven_swarm::gate::{GateHandle, PeerClass};
        use raven_swarm::host::{build_endpoint_swarm, EndpointConfig};
        use raven_swarm::libp2p::swarm::dial_opts::DialOpts;
        use raven_swarm::wss::{tls::client_tls, ClientSide};
        let dir = tempfile::tempdir().unwrap();
        let member_key = Keypair::ed25519_from_bytes([6u8; 32]).unwrap();
        let member = member_key.public().to_peer_id();
        raven_core::relay_allow::relay_allow(dir.path(), &member.to_string(), "m").unwrap();
        // One free port for Phase 2's raw extra listener and the WSS one.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut cmd = dedicated(dir.path(), "127.0.0.1:0");
        cmd.also_tcp = vec![ExtraTcp {
            local: port,
            public: port,
        }];
        cmd.wss = Some(wss_at(&format!("127.0.0.1:{port}")));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run_relay(cmd, async move {
            let _ = rx.await;
        }));
        let wss_form = format!("/ip4/127.0.0.1/tcp/{port}/tls/ws");
        let raw_form = format!("/ip4/127.0.0.1/tcp/{port}");
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let st = loop {
            if let Ok(Some(st)) = raven_core::relay_allow::load_relay_status(dir.path()) {
                let has = |a: &String| st.listen_addrs.contains(a);
                if has(&wss_form) && has(&raw_form) && st.listen_addrs.len() >= 4 {
                    break st;
                }
            }
            assert!(!task.is_finished(), "the relay ended before it was up");
            assert!(std::time::Instant::now() < deadline, "no WSS listener");
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        // `--listen`'s TCP and QUIC, then the WSS listener's two forms.
        assert_eq!(st.listen_addrs.len(), 4, "{:?}", st.listen_addrs);
        assert_eq!(
            st.listen_addrs.iter().filter(|a| **a == raw_form).count(),
            1,
            "one raw listener on the port: {:?}",
            st.listen_addrs
        );
        assert!(st.advertised.contains(&raw_form), "{:?}", st.advertised);
        assert!(
            st.advertised.iter().all(|a| !a.contains("/tls")),
            "{:?}",
            st.advertised
        );
        let relay: PeerId = st.peer_id.parse().unwrap();
        for form in [&wss_form, &raw_form] {
            let gate = GateHandle::default();
            gate.replace(
                HashMap::from([(relay, PeerClass::OWN_RELAY)]),
                false,
                std::time::Instant::now(),
            );
            let mut client = build_endpoint_swarm(
                &HostGate::open(true).unwrap(),
                member_key.clone(),
                EndpointConfig {
                    gate,
                    wss: Some(ClientSide {
                        tls: client_tls(),
                        proxy: None,
                    }),
                    ..EndpointConfig::default()
                },
            )
            .unwrap();
            client
                .dial(
                    DialOpts::peer_id(relay)
                        .addresses(vec![form.parse().unwrap()])
                        .build(),
                )
                .unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            while !client.is_connected(&relay) {
                tokio::time::timeout_at(deadline, client.select_next_some())
                    .await
                    .unwrap_or_else(|_| panic!("no connection over {form}"));
            }
        }
        let _ = tx.send(());
        assert_eq!(task.await.unwrap(), Ok(()));
    }

    #[test]
    fn a_global_reservation_confirms_the_relay_and_loopback_does_not() {
        let (a, b): (PeerId, PeerId) = (peer(1).parse().unwrap(), peer(2).parse().unwrap());
        let inbound_from = |from: &str| ConnectedPoint::Listener {
            local_addr: "/ip4/0.0.0.0/tcp/7423".parse().unwrap(),
            send_back_addr: from.parse().unwrap(),
        };
        let mut seen = InboundFrom::default();
        seen.established(
            a,
            ConnectionId::new_unchecked(1),
            &inbound_from("/ip4/127.0.0.1/tcp/50000"),
        );
        seen.established(
            b,
            ConnectionId::new_unchecked(2),
            &inbound_from("/ip4/192.168.1.5/tcp/50000"),
        );
        assert!(!seen.global(&a), "loopback");
        assert!(!seen.global(&b), "LAN");
        seen.established(
            b,
            ConnectionId::new_unchecked(3),
            &inbound_from("/ip4/8.8.8.8/tcp/50000"),
        );
        assert!(seen.global(&b));
        assert!(!seen.global(&a), "per peer");
        seen.closed(&ConnectionId::new_unchecked(3));
        assert!(!seen.global(&b), "only while that connection is open");
        // Our own dials (AutoNAT dial-backs) prove nothing about inbound.
        seen.established(
            a,
            ConnectionId::new_unchecked(4),
            &ConnectedPoint::Dialer {
                address: "/ip4/8.8.8.8/tcp/50000".parse().unwrap(),
                role_override: raven_swarm::libp2p::core::Endpoint::Dialer,
                port_use: raven_swarm::libp2p::core::transport::PortUse::New,
            },
        );
        assert!(!seen.global(&a));
    }

    /// `upnp_addrs` holds what UPnP mapped until the mapping expires; only a
    /// mapping confirms the relay.
    #[test]
    fn upnp_mappings_are_kept_until_they_expire() {
        let a = |t: &str| -> Multiaddr { t.parse().unwrap() };
        let mapped = |external: &str| upnp::Event::NewExternalAddr {
            local_addr: a("/ip4/192.168.1.5/tcp/7427"),
            external_addr: a(external),
        };
        let mut held = Vec::new();
        assert!(note_upnp(&mut held, &mapped("/ip4/8.8.8.8/tcp/7427")));
        assert!(note_upnp(
            &mut held,
            &mapped("/ip4/8.8.8.8/udp/7427/quic-v1")
        ));
        assert!(
            note_upnp(&mut held, &mapped("/ip4/8.8.8.8/tcp/7427")),
            "a renewal"
        );
        assert_eq!(held.len(), 2);
        for event in [
            upnp::Event::GatewayNotFound,
            upnp::Event::NonRoutableGateway,
        ] {
            assert!(!note_upnp(&mut held, &event));
        }
        assert_eq!(held.len(), 2);
        let expired = upnp::Event::ExpiredExternalAddr {
            local_addr: a("/ip4/192.168.1.5/tcp/7427"),
            external_addr: a("/ip4/8.8.8.8/tcp/7427"),
        };
        assert!(!note_upnp(&mut held, &expired));
        assert_eq!(held, [a("/ip4/8.8.8.8/udp/7427/quic-v1")]);
    }

    #[test]
    fn shared_policy_source_replaces_the_allow_file() {
        let dir = tempfile::tempdir().unwrap();
        raven_core::relay_allow::relay_allow(dir.path(), &peer(1), "bob").unwrap();
        let member: PeerId = peer(2).parse().unwrap();
        let (tx, rx) = watch::channel(AllowPolicy::Peers(HashSet::from([member])));
        let shared = PolicySource::Shared(rx);
        // The folder's allow-list is never read.
        assert_eq!(
            shared.current(dir.path(), false),
            AllowPolicy::Peers(HashSet::from([member]))
        );
        std::fs::write(dir.path().join(RELAY_ALLOW_FILE), b"{broken").unwrap();
        assert_eq!(
            shared.current(dir.path(), false),
            AllowPolicy::Peers(HashSet::from([member]))
        );
        tx.send_replace(AllowPolicy::Unreadable);
        assert_eq!(shared.current(dir.path(), false), AllowPolicy::Unreadable);
        // `File` reads it (and fails closed on it).
        assert_eq!(
            PolicySource::File.current(dir.path(), false),
            AllowPolicy::Unreadable
        );
    }

    #[test]
    fn lines_use_their_label_and_counts_only() {
        let c = RelayCounts {
            open: false,
            allowed_peers: 2,
            allow_list_unreadable: false,
            reservations: 1,
            circuits: 3,
            reservations_refused: 4,
            circuits_refused: 5,
            connections_refused: 6,
        };
        let members = AllowPolicy::Peers(HashSet::from([peer(1).parse().unwrap()]));
        for label in ["raven-node relay", "raven-node friend relay"] {
            let mut lines = vec![
                up_line(label, 3, &[7423, 443], None, &policy_line(&members, true)),
                counts_line(label, &c),
                stopped_line(label, 2),
            ];
            for policy in [
                AllowPolicy::Open,
                AllowPolicy::Unreadable,
                AllowPolicy::Peers(HashSet::new()),
                members.clone(),
            ] {
                lines.push(format!("{label}: {}", policy_line(&policy, false)));
            }
            let mapped = upnp::Event::NewExternalAddr {
                local_addr: "/ip4/192.168.1.5/tcp/7427".parse().unwrap(),
                external_addr: "/ip4/8.8.8.8/tcp/7427".parse().unwrap(),
            };
            for event in [mapped, upnp::Event::GatewayNotFound] {
                lines.push(crate::p2p::upnp_report(label, &event).1);
            }
            let addrs: Vec<Multiaddr> = ["/ip4/8.8.8.8/tcp/7423", "/ip4/8.8.8.8/tcp/443"]
                .iter()
                .map(|t| t.parse().unwrap())
                .collect();
            let privileged = |a: &Multiaddr| {
                if tcp_port(a) == Some(443) {
                    Err(ListenProbe::Privileged)
                } else {
                    Ok(())
                }
            };
            lines.extend(plan_listeners(addrs, 1, true, label, privileged).unwrap().1);
            for line in &lines {
                assert!(line.starts_with(&format!("{label}: ")), "{line}");
                for leak in ["/ip4", "/ip6", "/p2p", "8.8.8.8", "192.168", "12D3"] {
                    assert!(!line.contains(leak), "{line}");
                }
            }
            assert_eq!(
                lines[0],
                format!("{label}: up (listeners=3; tcp ports 7423,443; allow-list: 1 peer(s))")
            );
            assert_eq!(
                lines[1],
                format!(
                    "{label}: reservations=1 circuits=3 refused_reservations=4 \
                     refused_circuits=5 refused_connections=6"
                )
            );
            assert_eq!(
                lines[2],
                format!("{label}: stopped (2 connection(s) closed)")
            );
        }
        // Only `relay_allow.json` gets the hint about `raven relay allow`.
        let empty = AllowPolicy::Peers(HashSet::new());
        assert!(policy_line(&empty, true).contains("relay allow"));
        assert!(!policy_line(&empty, false).contains("relay allow"));
        // The friend relay's members are its verified contacts plus the
        // list kept by hand: never called the allow-list (field test E2 r7).
        assert_eq!(policy_line(&members, true), "allow-list: 1 peer(s)");
        assert_eq!(policy_line(&members, false), "members: 1 peer(s)");
        assert!(policy_line(&empty, false).contains("no verified contact, none added by hand"));
        assert!(!policy_line(&empty, false).contains("allow-list"));
    }

    #[test]
    fn advertised_names_the_operators_order_and_never_the_placeholder() {
        let a = |t: &str| -> Multiaddr { t.parse().unwrap() };
        let named = vec![
            a("/dns/relay.example.org/tcp/7423"),
            a("/dns/relay.example.org/udp/7423/quic-v1"),
            a("/dns/relay.example.org/tcp/443"),
        ];
        let external = [
            a("/dns/relay.example.org/tcp/443"),
            a("/ip4/8.8.8.8/tcp/7427"),
            a("/ip4/127.0.0.1/tcp/7423"),
            a("/dns/relay.example.org/tcp/7423"),
            a("/ip4/8.8.4.4/tcp/7427"),
        ];
        assert_eq!(
            advertised(named, external.iter()),
            [
                "/dns/relay.example.org/tcp/7423",
                "/dns/relay.example.org/udp/7423/quic-v1",
                "/dns/relay.example.org/tcp/443",
                "/ip4/8.8.4.4/tcp/7427",
                "/ip4/8.8.8.8/tcp/7427",
            ]
        );
        // Only the placeholder: nothing is named.
        assert!(advertised(Vec::new(), [a("/ip4/127.0.0.1/tcp/7423")].iter()).is_empty());
        // A loopback address the operator named stays (a lab's --listen
        // 127.0.0.1:P).
        assert_eq!(
            advertised(vec![a("/ip4/127.0.0.1/tcp/7423")], std::iter::empty()),
            ["/ip4/127.0.0.1/tcp/7423"]
        );
    }
}
