//! The p2p carrier (transports design 2026-10 §3, phase P3): libp2p as a
//! connectivity substrate for the Raven link.
//!
//! - **Host:** a supervised task in `service` (opt-in like Internet direct:
//!   `--p2p-listen` / `RAVEN_P2P_LISTEN` / `raven node p2p on`). It always
//!   listens: TCP + QUIC, IPv4 + IPv6 on 7423 by default, or the IP:PORT
//!   given, because DCUtR needs a listener socket (libp2p-quic dials as a
//!   listener only from one, transport.rs:311-320; libp2p-tcp reuses only a
//!   listening port, lib.rs:111-128). The retired `relay` setting (no
//!   listener) listens on 7423 anyway and logs one line saying so; only the
//!   debug `RAVEN_LAB_P2P_RELAY_ONLY=1` keeps it, for tests that show a node
//!   reachable only through relays (C6). Every listen address is
//!   probe-bound first, so a port another program holds is reported (and
//!   retried) instead of shared (libp2p-tcp sets SO_REUSEADDR /
//!   SO_REUSEPORT). The local preflight runs once; only the listen step is
//!   retried. It keeps reservations on at most two relays (`--p2p-relay` /
//!   `RAVEN_P2P_RELAYS` / node policy: at most two addresses; none is
//!   compiled in), one slot per relay PeerId, so two addresses of one relay
//!   (TCP 7423 and TCP 443) are one relay with a fallback. libp2p renews a
//!   reservation before it expires; a lost or refused one is re-requested
//!   with backoff on the relay's next address, and a relay named by DNS is
//!   re-resolved before every attempt, its addresses tried in turn. The
//!   service asks it to shut down cleanly (listeners, then connections
//!   closed) before it exits, so a restart is not refused by a relay still
//!   holding the old reservation.
//! - **Network changes:** netwatch tells the host when this machine's
//!   network changed (a network gone, unless the default route was read and
//!   stayed; back from no network; the default route moved; woke from
//!   sleep), and the host re-homes. It stops listening first (the
//!   swarm tells libp2p-upnp, which asks the router to drop the mappings it
//!   made: best effort, the old router may be out of reach by now), answers
//!   every waiting dial, closes every connection (at most 1 s), drops the
//!   whole endpoint and builds a fresh one on the SAME relays: new
//!   listeners, a new UPnP gateway search, new AutoNAT clients, empty DCUtR
//!   / Identify state, the AutoNAT verdict `unknown` again. A dial queued
//!   meanwhile is served by the new endpoint. The new endpoint dials each
//!   relay from a new local port before it reserves (the old connection may
//!   still hold the listen port's TCP 4-tuple, which macOS and Windows would
//!   refuse for 30 s or more), so the reservation comes at once. A relay
//!   briefly holds two reservations for this node (within its per-peer cap
//!   of two) until it reaps the silent old one. A contact's direct TCP
//!   address refused for that reason ("address in use", after a re-home or
//!   any other close of ours) is dialled once more from a new local port.
//!   Networks only added, or only gone beside a default route that stayed
//!   (a container or VM bridge), keep the endpoint: idle relay slots just
//!   retry at once.
//! - **Every relay silent:** a connection whose pings fail is closed (ping
//!   liveness). When every relay that held a reservation fails them within
//!   a minute and no other connection answered a ping since (a direct
//!   connection to anyone else, a contact's say, gets one ping round to
//!   answer first: with one relay, the usual case, nothing else tells our
//!   path from the relay), our own path died rather than the relays: the
//!   host tells netwatch, which reads the default route again and re-homes
//!   the host (`every relay stopped answering`, at most once per change gap)
//!   or reports a route change. After that re-home the outbox is kicked, its
//!   backoff kept. Debug builds:
//!   `RAVEN_LAB_P2P_PING=<interval s>,<timeout s>` pings faster (C13).
//! - **Reachability** (any-network plan §3 Phase 1 item 5): each relay slot's
//!   relay tests our addresses with an AutoNAT v2 client of its own. A result
//!   counts only from a relay we dialled directly at a global address, on a
//!   network (/24, /48) other than the tested IP's own ([`NatTally`]):
//!   `public` needs two such networks that reached one IP of ours, one gives
//!   `unconfirmed`. Status reports that verdict, the reachability class
//!   (`raven_core::reach`: public, mapped, relayed, unreachable, unknown) and
//!   a health row per relay (reserved or lost for how long, its last ping,
//!   the next try, its own check of us); a change of class is logged with
//!   counts only.
//! - **Link:** every `/raven/link/1.0.0` stream runs the *same* Raven Noise link
//!   as Internet direct (`internet_direct::P2P_LINK`: prologue
//!   `raven/p2p-link/v1`, the RIH1 identity bind, the contact gate, RLB1, then
//!   `dispatch_frame`). The responder answers verified (pinned) contacts only
//!   and treats everyone else like a stranger, with the same timing. A relay
//!   and any other libp2p peer see only libp2p-Noise(Raven-Noise(...)); the
//!   PeerId is never trusted, the pinned Raven key inside the link is.
//! - **Dial:** the contact's card and, while route hints are live, what its
//!   RRH1 said (its PeerId when the card has none, the relays it holds now,
//!   its confirmed addresses: `raven_core::p2p_route::P2pDialSet`), the first
//!   direct address, then the first circuit, then the rest (at most two
//!   connection attempts at once: the design's hedge). A contact this node
//!   hides its IP from (D4) is dialled only through the relays it names that
//!   this node holds a slot for itself (never one only the contact names: it
//!   may run it), and an explicit direct address of it, or a circuit through
//!   a relay this node does not hold, is refused; a circuit through a relay
//!   named by a DNS name is dialled only at the global addresses it resolves
//!   to;
//!   libp2p's DCUtR upgrades a circuit to a direct connection where the NATs
//!   allow it. It offers Raven's candidates (`raven_swarm::candidates`):
//!   router mappings, this host's preferred global IPv6 source (route
//!   memory's egress probe), the raw address our relays (or two peers) saw on
//!   a direct connection (Identify's own guess may carry a rewritten port),
//!   then the rest; global only, except under the debug
//!   `RAVEN_LAB_P2P_LOCAL_CANDIDATES=1`. A failed hole punch logs how many
//!   of each it had. A Raven link never moves: once the upgrade is in, the relayed
//!   connection is closed as soon as no link uses it, so the next attempt opens
//!   a *new* Raven link on the direct connection. Each dial logs (counts only)
//!   when the kind of connection its link uses changes: `link via a direct
//!   connection (<path>)` / `link via the relay (relayed)`.
//! - **Path labels and reversal** (any-network plan §3 Phase 1 item 4): the
//!   host records who opened each connection (us, the peer, a relay circuit,
//!   DCUtR), and every link is labelled from the side that started it:
//!   `direct` (its own connection), `reversed` (one the other side opened),
//!   `relayed` or `hole_punched` ([`link_path`]). libp2p-stream opens a
//!   stream on any of the peer's connections, so a mixed set is labelled
//!   conservatively. A dial to a contact that is already connected rides
//!   that connection: when the contact opened it (a node behind a NAT that
//!   reached us), that is the dial plan's deliberate connection reversal
//!   (§2.3 step 1), and the outbox worker tries such a contact's p2p route
//!   first ([`route_connected`]). Counts per path, since raven-node started,
//!   are in IPC `Status` (`p2p_paths`).
//! - **Relay role**: the friend relay (`service --relay`, `raven relay offer
//!   on`) is a separate swarm with a relay key of its own
//!   ([`crate::friend_relay`]), never this host. This host relays under the
//!   profile PeerId only behind the debug lab switch
//!   `RAVEN_LAB_P2P_PROFILE_RELAY=1` (the relay PeerId is then the user's
//!   own PeerId, which everyone who uses the relay learns): between the
//!   PeerIds in this profile's `relay_allow.json`, with a guard (the
//!   allow-list and the rate tables) made once per host start like the peer
//!   gate; a re-home frees what the old endpoint's peers had reserved.
//! - **Relays contacts offer** (any-network plan C7; only while the friend
//!   relay gate and route hints are live, [`P2pConfig::auto`]): the relays
//!   set by hand keep their slots, and the slots left are filled from the
//!   relays verified contacts offer in their route hints
//!   ([`raven_core::relay_select`]), read again whenever a file the peer
//!   gate reads changes. Every 10 s the host asks
//!   [`raven_core::relay_select::select`] and applies the answer in place:
//!   the peer gate admits a picked relay before its reservation is asked, a
//!   dropped one loses its slot and its connection, and the other slot keeps
//!   its reservation. Loss clocks start over with every endpoint generation,
//!   so our own sleep or a network change never counts against a relay, and
//!   a restart takes the relays it held again while they are offered
//!   (`relay_memory.json`). The AutoNAT clients are made per endpoint: after
//!   the relays changed, the endpoint is re-homed (`relays changed`) once no
//!   Raven link was open for a minute, or after 30 minutes. A relay that
//!   closes a connection we just dialled at once, with no reservation, does
//!   not count this node a member: circuits through it are left out of every
//!   dial for a while; one whose relay said the contact holds no
//!   reservation there is dialled last to that contact for 10 minutes. Logs
//!   say how many relays, never which.
//! - **Learned relay terms** (Phase 6a, only while learning connectivity is
//!   on, [`crate::learning::relay_terms`]): each relay's term (at most ±150)
//!   is added to automatic choice's score of an offered relay, which only
//!   picks among relays that may take a slot, and a contact dial's circuits
//!   go in term order, a demoted one still last ([`order_dial`]). Inbound
//!   links over our reservation on a relay count for it
//!   ([`inbound_relay`]).
//! - **Peer gate** (`raven_swarm::gate`): only the `p2p=` PeerIds of
//!   verified (pinned), unblocked contacts, the configured relays, the
//!   relays a contact's `via=` names (outbound only) and, with the relay
//!   role, the allow-listed members get a libp2p connection at all; everyone
//!   else is refused before any protocol runs. A contact this node hides its
//!   IP from, or whose PeerId only its route hints named and no p2p link has
//!   proved yet, is admitted hidden: links, but no hole punching and no
//!   Identify. A stranger learns this node's
//!   PeerId (already on its card) and gets a closed connection; its circuit
//!   is refused before this node accepts it. A relay serves circuits only
//!   between the peers on its allow-list, the circle (`--relay-open`: any
//!   verified contact). The set is read from contacts.json and
//!   blocked_pubs.json (and learned_routes.json and node_policy.json) off
//!   the swarm loop, once per host start and again whenever one of them
//!   changes (checked every tick); re-homes keep it. A
//!   dial admits the contact it just checked and its relays for 10 min, or
//!   until the files are next read, so a contact verified a moment ago is
//!   never refused by our own gate. Every tick disconnects the peers whose
//!   admission no longer holds (a contact blocked, unpinned or removed, an
//!   admission past its deadline). A corrupt file admits no contact (the
//!   relays still are). Refusals are logged with counts only; a dial that
//!   the contact's node or its relay turned away at once says what to do
//!   about it.
//! - **Restrictive networks** (Phase 4, `protocol/RAVEN_WSS_TRANSPORT_V1.md`;
//!   lab-only while `WSS_PRODUCTION_ENABLED=false`): every relay address is
//!   dialled at its RWS1 §2.3 forms ([`DialForms`], reservations and
//!   circuits alike): a WSS address at its raw sibling while the WSS gate is
//!   closed (`WSS_HOLD` said once), and while it is live raw first, or the
//!   WebSocket/TLS form first when the HTTPS proxy carries it. The proxy is
//!   `--p2p-proxy`, else `RAVEN_P2P_PROXY`, else node policy `p2p_proxy`
//!   (`auto`: the environment, then the system settings; [`ProxySource`],
//!   read again every endpoint generation, its own gate
//!   `WSS_PROXY_PRODUCTION_ENABLED`). A WSS name the proxy carries is never
//!   resolved here (the proxy resolves it); one resolved here keeps the name
//!   as its SNI (`/tls/sni/<name>/ws`). Each slot reports how its
//!   reservation travels (`tcp`, `quic`, `wss`, `wss-proxy`). While a slot
//!   asks for or holds one through the proxy, the network is restricted
//!   (owner decision O4-6): no hole-punch or AutoNAT candidates, no direct
//!   contact address dialled; set and cleared with a counts-only line.
//!   Status also names where the proxy setting came from (`proxy_source`)
//!   and the proxy's last 407 as a fixed word (`proxy_auth`:
//!   [`proxy_auth_word`]), for `raven status` and `raven node proxy`.
//! - **NAT mapping classes** (Phase 4 P4.24; lab-only while
//!   `NAT_CLASS_PRODUCTION_ENABLED=false`): each endpoint generation builds a
//!   classifier (`raven_swarm::natclass`) fed by what our relays and
//!   contacts see of us on connections we dialled from the listen port
//!   ([`nat_feed`]: the listener was reported when the dial began; the
//!   first reservations wait [`NAT_LISTEN_WAIT`] for it). A new summary goes
//!   to DCUtR's hole-punch policy, to route hints (RRH1 NAT_CLASS) and to
//!   status (`nat_mapping`), with one counts-only line. Contacts' classes
//!   come from their route hints with each peer gate read; a punch both
//!   sides' varying mappings make hopeless, or the third after two failures
//!   on this network, is skipped (one line per window, the reason only).
//!   Gate closed: none of it runs, as in Phase 1.
//! - **PeerId rotation** (Phase 4 P4.28, `protocol/RAVEN_P2P_PEER_ROTATION_V1.md`;
//!   lab-only while `PEER_ROTATION_PRODUCTION_ENABLED=false`): with the
//!   profile's setting on (`raven node p2p rotate on`), each endpoint
//!   generation is built with the key of the current epoch once every
//!   verified contact with a p2p route said it can follow
//!   ([`RotationState`]; else it waits on the fixed key). The host re-homes
//!   at each epoch boundary ([`Rehome::Rotate`]); when every relay it held
//!   before turns the new ID away within [`ROTATE_CHECK`], it goes back to
//!   the previous key until the next boundary or [`ROTATE_RETRY_S`]
//!   ([`Rehome::RotateBack`]). A rotating contact is dialled under the
//!   PeerIds its schedule names for now, the second only after the first
//!   was unreachable ([`DialCheck::second`]). Status names the key in use
//!   and the state; logs say only that the ID changed. Gate closed: the
//!   fixed key, as in Phase 1.
//!
//! Held by `raven_core::p2p_live_enabled` (P2P_PRODUCTION_ENABLED=false or the
//! debug lab unlock): with it closed nothing is built, so nothing listens,
//! dials, reserves or advertises. Logs carry categories and counts only (NAT
//! spec §5): no PeerId, address or key; this node's own PeerId and listen
//! addresses are shown by IPC `Status` (`raven status`).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime};

use futures::StreamExt;
use raven_core::identity::Identity;
use raven_core::ipc::{
    NatChecks, NatMappingStatus, P2pGateStatus, P2pPathCounts, P2pStatusInfo, PortMapStatus,
    RelayCounts, RelayHealth,
};
use raven_core::learned_routes::LearnedP2p;
use raven_core::net_proxy::ProxySetting;
use raven_core::outbox::{carrier_allowed_for_contact, DeliveryPath, OutboxCarrier, OutboxRoute};
use raven_core::p2p_route::{self, P2pDialSet, P2pDialTarget, P2pListen, ViaAddr};
use raven_core::portmap::Via;
use raven_core::reach::{reach_class, NatVerdict, ReachClass, ReachFacts};
use raven_core::reach_diag::{
    diagnose, AddrOutcome, CircuitOutcome, Diag, DialSummary, MyFacts, TheirFacts, Why,
};
use raven_core::relay_select::{
    self, Candidate, Change, Decision, LossWhy, Operator, SlotNow, Source,
};
use raven_swarm::diag::{dial_failures, Failed};
use raven_swarm::gate::{
    AddrRule, Admission as _, GateHandle, PeerClass, PeerNotAdmitted, SourceRefused,
};
use raven_swarm::host::{
    addr_ip, build_endpoint_swarm, is_circuit, is_global_ipv6, listen_port_label, net_group,
    probe_listen_addr, EndpointBehaviour, EndpointBehaviourEvent, EndpointConfig, HostGate,
    ListenProbe, NetGroup, RelayAdvertiser, RelayGuard, RelayLimits, RAVEN_LINK_PROTOCOL,
};
use raven_swarm::libp2p::core::transport::{ListenerId, PortUse, TransportError};
use raven_swarm::libp2p::core::ConnectedPoint;
use raven_swarm::libp2p::identity::Keypair;
use raven_swarm::libp2p::multiaddr::Protocol;
use raven_swarm::libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use raven_swarm::libp2p::swarm::{
    ConnectionError, ConnectionId, DialError, ListenError, SwarmEvent,
};
use raven_swarm::libp2p::{autonat, dcutr, identify, quic, relay, upnp, Multiaddr, PeerId, Swarm};
use raven_swarm::libp2p_stream::{Control, IncomingStreams, OpenStreamError};
use raven_swarm::liveness::{close_if_dead, reconnect_delay, retry_jitter};
use raven_swarm::natclass::{raw_endpoint, NatClassifier, NatSummary, SkipWhy, Tr};
use raven_swarm::portmap::{LostWhy, PortMapConfig, PortMapEvent};
use raven_swarm::wss::{self, ProxyLookup};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::compat::FuturesAsyncReadCompatExt;

use crate::internet_direct::{self, blocking, P2P_LINK};
use crate::learning::DialMeta;
use crate::netutil::{self, Admission, ConnectWait, DialProgress};
use crate::proxy::ProxySource;

/// The whole dial, below the 45 s IPC cap (as Internet direct).
const DIAL_DEADLINE: Duration = Duration::from_secs(40);
/// Connecting to the contact (direct, then circuits), within the dial.
const CONNECT_DEADLINE: Duration = Duration::from_secs(20);
/// How often the host re-reads the relay allow-list and re-publishes status.
const TICK: Duration = Duration::from_secs(1);
const ALLOW_RELOAD: Duration = Duration::from_secs(5);
/// A busy listen port is tried again after this, doubling up to the cap.
const LISTEN_RETRY_MIN: Duration = Duration::from_secs(2);
const LISTEN_RETRY_MAX: Duration = Duration::from_secs(60);
/// A specific listen address never opened that is on no interface: tried
/// this many times more (after 2, 4, 8, 16 and 32 s: a lease or an IPv6
/// duplicate-address check may take that long), then only again when
/// networks are added or the endpoint is re-homed ([`ListenSlot::failed`]).
const ABSENT_TRIES: u32 = 5;
/// How long a clean shutdown waits for the connections to close.
pub(crate) const SHUTDOWN_DRAIN: Duration = Duration::from_millis(1500);
/// How long a re-home waits for the old endpoint's connections to close.
const REHOME_DRAIN: Duration = Duration::from_secs(1);
/// For this long after a re-home, or an unlock (Lock v2 stopped the host), a
/// busy listen port is most likely our own old endpoint's (QUIC drains its
/// socket for a moment): it is retried every [`REBIND_RETRY`], quietly.
const REBIND_GRACE: Duration = Duration::from_secs(10);
const REBIND_RETRY: Duration = Duration::from_millis(500);
/// How long a dial waits for the relayed connections it closes (to put its
/// link on the direct connection) to be gone.
const PREFER_DIRECT_WAIT: Duration = Duration::from_secs(2);
/// AutoNAT results remembered: tested addresses, and servers per address
/// (each relay slot's client asks one).
const MAX_NAT_RESULTS: usize = 16;
const MAX_NAT_SERVERS: usize = 4;
/// Every reserved relay failing its pings within this window is our own path
/// dying ([`RelayLoss`]); it is reported at most once per window.
const RELAY_LOSS_WINDOW: Duration = Duration::from_secs(60);
/// A relay connection's close may be reported a moment after the loss of
/// the reservation it carried (the connection's handler goes first): a slot
/// that lost its reservation this recently held it on that connection.
const CLOSE_AFTER_LOSS: Duration = Duration::from_secs(1);
/// Peer-caused events are logged at most once per window.
static P2P_LOG: netutil::LogLimiter = netutil::LogLimiter::new(Duration::from_secs(30));
/// "a contact is unreachable (<reason>)": its own limiter, so it neither
/// hides nor is hidden by the other p2p failure lines.
static REACH_LOG: netutil::LogLimiter = netutil::LogLimiter::new(Duration::from_secs(30));
static CAP_LOG: netutil::LogLimiter = netutil::LogLimiter::new(Duration::from_secs(10));
/// Peer gate refusals (anyone can cause them): one counts-only line per
/// window.
static GATE_LOG: netutil::LogLimiter = netutil::LogLimiter::new(Duration::from_secs(30));
/// Skipped hole punches (Phase 4): one line per window, its reason only.
static SKIP_LOG: netutil::LogLimiter = netutil::LogLimiter::new(Duration::from_secs(30));
/// Auto-reach: serverless punch lines at most this often.
static PUNCH_LOG: netutil::LogLimiter = netutil::LogLimiter::new(Duration::from_secs(30));
/// How long a dial admits the contact it checked and its relays at most
/// ([`GateHandle::admit_dial`]): files read after the dial's check end it
/// sooner.
const DIAL_ADMIT_TTL: Duration = Duration::from_secs(600);
/// How often a dial checks its contact again because the peer gate read
/// newer files that do not name it ([`connect_checked`]) before it gives up.
const MAX_DIAL_RECHECKS: u32 = 3;
/// [`Host::connect`]'s answer when the gate holds files read after the
/// dial's check that do not name the peer a contact: check again. What the
/// dial reports only if that keeps happening.
const CHECK_AGAIN: &str = "P2P_UNREACHABLE: the contact book or block list kept changing while \
    the contact was dialled; nothing was dialled (try again)";
/// A connection we dialled that the other side closes this soon, before any
/// link used it, turned us away ([`refusal_hint`]).
const QUICK_CLOSE: Duration = Duration::from_secs(2);
/// How often automatic relay choice looks at the slots ([`Host::select_relays`];
/// also whenever the offers were read again).
const SELECT_EVERY: Duration = Duration::from_secs(10);
/// A connection that came up, or a ping answered, this recently proves this
/// node online: a relay that does not answer meanwhile is the relay's fault.
const ONLINE_PROOF: Duration = Duration::from_secs(120);
/// The relay memory is written at most this often, unless the picked relays
/// changed or a relay turned this node away (then at once).
const MEMORY_SAVE_EVERY: Duration = Duration::from_secs(300);
/// "relay kept" is logged at most this often (it holds every round).
const KEPT_LOG_EVERY: Duration = Duration::from_secs(1800);
/// After the relays changed, the AutoNAT clients still ask the old ones: the
/// endpoint is re-homed once no Raven link was open for this long ...
const AUTONAT_IDLE: Duration = Duration::from_secs(60);
/// ... or this long after the change, links or not.
const AUTONAT_STALE_MAX: Duration = Duration::from_secs(1800);
/// A circuit whose relay said the contact holds no reservation there is
/// dialled last to that contact for this long ([`note_demoted`]).
const DEMOTE_FOR: Duration = Duration::from_secs(600);
const MAX_DEMOTED: usize = 256;

/// Refusal while no host runs (p2p off, held, or still starting).
pub(crate) const P2P_NOT_RUNNING: &str = "P2P_NOT_RUNNING: the libp2p host of this raven-node is \
    not running (turn it on with `raven node p2p on` and restart raven-node)";
/// No p2p address of the contact answered.
pub(crate) const P2P_UNREACHABLE: &str =
    "P2P_UNREACHABLE: the contact is unreachable on every p2p address it has (direct and relay)";
/// A direct p2p dial to a contact this node hides its IP from (D4).
pub(crate) const P2P_HIDDEN_DIRECT: &str = "P2P_UNREACHABLE: you hide your IP from this contact: \
    direct p2p dials are off (raven contact hide-ip NAME off)";
/// A circuit to a contact this node hides its IP from (D4) through a relay
/// this node does not hold itself (the contact's own relay would see our
/// IP).
pub(crate) const P2P_HIDDEN_RELAY: &str = "P2P_UNREACHABLE: you hide your IP from this contact: \
    Raven reaches it only through your own relays, and this is not one of them \
    (raven contact hide-ip NAME off)";
/// A direct p2p dial while a relay reservation rides a proxied WSS
/// connection (restricted network, RWS1 §9).
pub(crate) const P2P_RESTRICTED_DIRECT: &str = "P2P_UNREACHABLE: this network lets Raven out \
    only through the HTTPS proxy (restricted network): direct p2p dials are off; contacts are \
    reached through your relays";

/// What the service runs (`main::service_p2p_config`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct P2pConfig {
    pub listen: P2pListen,
    /// The setting was the retired `relay`; `listen` is what replaced it.
    pub retired_relay: bool,
    /// The addresses of the relays to keep a reservation on (at most
    /// [`p2p_route::MAX_VIA`]); two of one relay are one relay with a
    /// fallback ([`relay_slots`]).
    pub relays: Vec<ViaAddr>,
    /// Also relay for others under this node's own PeerId (`Some(open)`):
    /// the retired `--relay` role, kept only behind the debug switch
    /// `RAVEN_LAB_P2P_PROFILE_RELAY=1` (`main::profile_relay_role`); the
    /// friend relay has its own key ([`crate::friend_relay`]).
    pub relay_server: Option<bool>,
    /// node_policy.json `upnp` (unset behaves as off): UPnP-IGD, and
    /// NAT-PMP/PCP for IPv4 where the PORT_MAP gate is open.
    pub upnp: Option<bool>,
    /// node_policy.json `v6_pinhole` (unset behaves as off): an IPv6 pinhole
    /// on the router, only with `upnp` on and the V6_PINHOLE gate open.
    pub v6_pinhole: Option<bool>,
    /// Automatic relay choice from the relays contacts offer (any-network
    /// plan C7): `None` while the friend relay gate or route hints are
    /// closed (no offers, no relay memory, no relay notes: the Phase 1
    /// host); else node_policy.json `relay_auto` at start-up, which the host
    /// then follows live.
    pub auto: Option<bool>,
    /// `relays` came from node_policy.json while its sealed sidecar, which
    /// holds them in a sealed profile (privacy pack PP.6), could not be read
    /// yet (raven-node's key thread had not loaded the at-rest key): the host
    /// starts without them and takes them once the key is there (the peer
    /// gate's next load, [`load_gate_for`]), re-homed once.
    pub policy_relays_pending: bool,
    /// The explicit proxy setting of WSS relay dials (RWS1 §8.2 source 1).
    pub proxy: P2pProxy,
}

/// `--p2p-proxy`, else `RAVEN_P2P_PROXY`, else node_policy.json `p2p_proxy`
/// (`main::service_p2p_proxy`): `auto` (the environment, then the system
/// settings), `off`, or one `http://` proxy ([`ProxySource`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct P2pProxy {
    pub setting: ProxySetting,
    /// Where it came from (empty: nowhere, `auto`).
    pub source: &'static str,
    /// It is node_policy.json's while its sealed sidecar could not be read
    /// yet (as [`P2pConfig::policy_relays_pending`]): the host starts with
    /// what node_policy.json alone holds, `off` (direct) when it holds
    /// nothing, and takes the saved setting (`auto` included) once the key
    /// is there (the peer gate's next load, [`load_gate_for`]).
    pub pending: bool,
}

/// What the service decided about p2p at start-up, reported by IPC
/// `Status` whether or not a host runs (`raven status`, `raven whoami
/// --card`): the effective setting and where it came from.
pub(crate) enum ServiceP2p<'a> {
    Off {
        source: &'a str,
    },
    Held {
        config: &'a P2pConfig,
        source: &'a str,
    },
    Configured {
        config: &'a P2pConfig,
        source: &'a str,
    },
    Error,
}

/// Publish the start-up decision (before any host runs).
pub(crate) fn publish_service_config(decision: ServiceP2p<'_>) {
    *lock(&CONFIG) = Some(service_info(decision));
}

/// What IPC `Status` reports for the start-up decision while no host runs.
/// `relays_configured` counts relays, not addresses: two of one relay (TCP
/// 7423 and TCP 443) are one relay with a fallback.
fn service_info(decision: ServiceP2p<'_>) -> P2pStatusInfo {
    let base = |config: Option<&P2pConfig>, source: &str| P2pStatusInfo {
        listen_setting: config.map(|c| c.listen.policy_text()).unwrap_or_default(),
        retired_listen: retired_listen(config),
        source: source.to_string(),
        relays: config
            .map(|c| c.relays.iter().map(|v| v.text.clone()).collect())
            .unwrap_or_default(),
        relays_configured: config.map_or(0, |c| p2p_route::distinct_relays(&c.relays) as u32),
        relay_role: config.is_some_and(|c| c.relay_server.is_some()),
        upnp: config.map_or_else(|| "off".into(), |c| upnp_initial(c.upnp)),
        nat: "unknown".into(),
        relay_auto: config.is_some_and(|c| c.auto == Some(true)),
        proxy_source: config.map_or("", |c| c.proxy.source).into(),
        ..P2pStatusInfo::default()
    };
    match decision {
        ServiceP2p::Off { source } => base(None, source),
        ServiceP2p::Held { config, source } => P2pStatusInfo {
            held: true,
            ..base(Some(config), source)
        },
        ServiceP2p::Configured { config, source } => base(Some(config), source),
        ServiceP2p::Error => P2pStatusInfo {
            config_error: "the p2p settings could not be used (see raven-node-service.log)".into(),
            ..base(None, "")
        },
    }
}

/// `P2pStatusInfo.retired_listen`: `relay` when the service was given the
/// retired setting, else empty.
fn retired_listen(config: Option<&P2pConfig>) -> String {
    if config.is_some_and(|c| c.retired_relay) {
        "relay".into()
    } else {
        String::new()
    }
}

// ── The running host, for dials and IPC Status ──────────────────────────────

enum Command {
    /// Connect to a contact `dial` just checked is verified, admitted as
    /// `class` (CONTACT, or CONTACT_HIDDEN: no hole punching, no Identify,
    /// and no address of it but the dial's); `relays`: the relays its
    /// addresses go through (admitted with it); `checked_at`: when that
    /// check began reading the files ([`GateHandle::admit_dial`]).
    Connect {
        peer: PeerId,
        class: PeerClass,
        relays: Vec<PeerId>,
        addrs: Vec<Multiaddr>,
        checked_at: std::time::Instant,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// The peer gate's set was read again ([`Host::poll_gate`]).
    GateLoaded(Box<GateLoad>),
    /// Before a link: if a direct connection exists, close the relayed ones
    /// (when no link uses them) so the link rides the direct one. Answers
    /// whether the link will use a direct connection.
    PreferDirect {
        peer: PeerId,
        reply: oneshot::Sender<bool>,
    },
    /// A relay's names were resolved for endpoint generation `gen`. Keyed by
    /// the relay's PeerId, not the slot's index: a slot may be removed in
    /// place meanwhile. An older generation's answer is ignored: the current
    /// one asked again itself, and acting on both would leave a reservation
    /// listener no slot tracks.
    Resolved {
        gen: u64,
        relay: PeerId,
        addrs: Vec<Multiaddr>,
    },
    /// Networks were only added ([`nudge`]): idle relay slots are due now,
    /// their backoff started over ([`RelaySlot::nudge`]).
    Nudge,
    /// The relays contacts offer were read again ([`Host::poll_offers`]);
    /// `None`: the read failed (tried again at the next tick).
    OffersLoaded(Option<OffersLoad>),
    /// Close every listener and connection, wait at most [`SHUTDOWN_DRAIN`],
    /// then stop.
    Shutdown { done: oneshot::Sender<()> },
}

/// Handle of the running host (one per endpoint generation).
struct HostHandle {
    commands: mpsc::Sender<Command>,
    control: Control,
    /// Raven links in flight per peer (both directions).
    links: Mutex<HashMap<PeerId, usize>>,
    /// This endpoint's connections and who opened each: the swarm loop
    /// writes it, the dials, the responder and the outbox worker read it.
    conns: Mutex<ConnTable>,
    /// How its dials go ([`Self::forms`]): it dials WSS, the host's proxy
    /// and restricted flag (both kept by the seed).
    wss: bool,
    proxy: Arc<ProxySource>,
    restricted: Arc<AtomicBool>,
}

/// Who opened a libp2p connection, for the path label of the links that
/// ride it ([`link_path`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnOrigin {
    /// A `/p2p-circuit` connection through a relay.
    Relayed,
    /// This node dialled it.
    Dialled,
    /// The peer dialled it.
    Accepted,
    /// DCUtR made it from a relayed one. Both sides dial and, on QUIC, both
    /// dials can succeed: ours is the one DCUtR reports, the peer's arrives
    /// inbound while its relayed connection is still open.
    Punched,
}

/// DCUtR upgrades remembered until their connection is reported, at most.
const MAX_PUNCHED_PENDING: usize = 64;

/// How long after DCUtR dialled a peer ([`HolePunch::last_attempt`]: both
/// sides dial at the same moment, for every attempt) an inbound direct
/// connection from that peer is the peer's half of the hole punch: its dial
/// is bounded by the 10 s connection timeout, plus the round trip.
///
/// [`HolePunch::last_attempt`]: raven_swarm::gate::HolePunch::last_attempt
const DCUTR_ATTEMPT_WINDOW: Duration = Duration::from_secs(20);

/// The fallback when no DCUtR dial was seen since the peer's relayed
/// connection opened (the peer's dial arrived before ours was made): how
/// long after a relayed connection opens an inbound direct one from the same
/// peer counts as the peer's half of a hole punch. DCUtR starts when the
/// relayed connection is established; it tries at most 3 times
/// (MAX_NUMBER_OF_UPGRADE_ATTEMPTS), each bounded by its 10 s stream timeout
/// (dcutr 0.15 handler/relayed.rs:91-95) and the 10 s connection timeout. An
/// older relayed connection may be one the peer no longer has (its network
/// changed and the relay has not noticed yet): its direct dial then is an
/// ordinary one.
const DCUTR_INBOUND_WINDOW: Duration = Duration::from_secs(60);

/// An endpoint's connections and their [`ConnOrigin`]. Pure: the swarm loop
/// feeds it the events.
#[derive(Debug, Default)]
struct ConnTable {
    conns: HashMap<ConnectionId, (PeerId, ConnOrigin)>,
    /// Connections DCUtR reported as its upgrade before their
    /// `ConnectionEstablished` came (the two arrive in either order).
    punched_pending: HashSet<ConnectionId>,
    /// When each relayed connection was established.
    relayed_at: HashMap<ConnectionId, Instant>,
    /// The relay each relayed connection goes through, when its circuit
    /// address (`/p2p/<relay>/p2p-circuit`) names it
    /// ([`Self::relayed_through`]): for a stale link's reason
    /// ([`Self::relays_to`], review 5a-3) and for learning connectivity's
    /// relay rows ([`Self::relay_of`]), and for Phase 6b R8 (which relay a
    /// relayed link's receipt, or its loss, is about).
    via: HashMap<ConnectionId, PeerId>,
    /// The relayed connections the peer opened: they came over our
    /// reservation on their relay ([`Self::reservation_relay_of`]).
    inbound_relayed: HashSet<ConnectionId>,
    /// When each `Accepted` connection was established ([`Self::upgraded`]).
    accepted_at: HashMap<ConnectionId, Instant>,
}

impl ConnTable {
    #[cfg(test)]
    fn established(&mut self, id: ConnectionId, peer: PeerId, relayed: bool, dialer: bool) {
        self.established_at(id, peer, relayed, dialer, Instant::now(), None);
    }

    /// `attempt`: when DCUtR last dialled `peer` ([`DCUTR_ATTEMPT_WINDOW`]).
    fn established_at(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        relayed: bool,
        dialer: bool,
        now: Instant,
        attempt: Option<Instant>,
    ) {
        let origin = if relayed {
            self.relayed_at.insert(id, now);
            if !dialer {
                self.inbound_relayed.insert(id);
            }
            ConnOrigin::Relayed
        } else if self.punched_pending.remove(&id) {
            ConnOrigin::Punched
        } else if dialer {
            ConnOrigin::Dialled
        } else if attempt
            .is_some_and(|at| now.saturating_duration_since(at) <= DCUTR_ATTEMPT_WINDOW)
        {
            // DCUtR dialled this peer a moment ago, and the peer dialled us
            // at the same moment: its half of the hole punch.
            ConnOrigin::Punched
        } else if self.conns.iter().any(|(cid, (p, origin))| {
            *p == peer
                && *origin == ConnOrigin::Relayed
                && self.relayed_at.get(cid).is_some_and(|opened| {
                    now.saturating_duration_since(*opened) <= DCUTR_INBOUND_WINDOW
                        && attempt.is_none_or(|at| at < *opened)
                })
        }) {
            // No DCUtR dial seen since the relayed connection opened (the
            // peer's may come first): a peer that reaches us only through a
            // relay dials us directly only to hole-punch (a dial to a
            // connected contact rides the connection it has), and DCUtR does
            // so only right after the relayed connection opens.
            ConnOrigin::Punched
        } else {
            self.accepted_at.insert(id, now);
            ConnOrigin::Accepted
        };
        self.conns.insert(id, (peer, origin));
    }

    /// DCUtR's `Ok(id)` for `peer`: `id` is the direct connection it made,
    /// and a connection `peer` opened to us shortly before is the peer's half
    /// of the same hole punch (its dial got here before ours was made).
    fn upgraded(&mut self, id: ConnectionId, peer: PeerId, now: Instant) {
        self.punched(id);
        let recent: Vec<ConnectionId> = self
            .accepted_at
            .iter()
            .filter(|(cid, at)| {
                now.saturating_duration_since(**at) <= DCUTR_ATTEMPT_WINDOW
                    && self.conns.get(cid).is_some_and(|(p, _)| *p == peer)
            })
            .map(|(cid, _)| *cid)
            .collect();
        for cid in recent {
            self.punched(cid);
        }
    }

    /// `id` is a hole-punched connection (DCUtR's `Ok(id)`).
    fn punched(&mut self, id: ConnectionId) {
        match self.conns.get_mut(&id) {
            Some((_, origin)) => {
                if *origin != ConnOrigin::Relayed {
                    *origin = ConnOrigin::Punched;
                    self.accepted_at.remove(&id);
                }
            }
            None => {
                if self.punched_pending.len() >= MAX_PUNCHED_PENDING {
                    self.punched_pending.clear();
                }
                self.punched_pending.insert(id);
            }
        }
    }

    /// Relayed connection `id` goes through `relay` (an unknown or a direct
    /// connection is not noted).
    fn relayed_through(&mut self, id: ConnectionId, relay: PeerId) {
        if self.relayed_at.contains_key(&id) {
            self.via.insert(id, relay);
        }
    }

    /// The relay of a relayed connection to `peer` (of several, the one
    /// with the smallest PeerId bytes); `None` when none is relayed.
    fn relay_of(&self, peer: &PeerId) -> Option<PeerId> {
        self.via
            .iter()
            .filter(|(id, _)| self.conns.get(id).is_some_and(|(p, _)| p == peer))
            .map(|(_, relay)| *relay)
            .min_by_key(|r| r.to_bytes())
    }

    /// The relay of a relayed connection `peer` opened to us, so over our
    /// reservation on that relay (of several, the one with the smallest
    /// PeerId bytes); `None` when none is open. A relayed connection this
    /// node dialled goes through the peer's relay and does not count.
    fn reservation_relay_of(&self, peer: &PeerId) -> Option<PeerId> {
        self.via
            .iter()
            .filter(|(id, _)| self.inbound_relayed.contains(id))
            .filter(|(id, _)| self.conns.get(id).is_some_and(|(p, _)| p == peer))
            .map(|(_, relay)| *relay)
            .min_by_key(|r| r.to_bytes())
    }

    fn closed(&mut self, id: ConnectionId) {
        self.punched_pending.remove(&id);
        self.relayed_at.remove(&id);
        self.via.remove(&id);
        self.inbound_relayed.remove(&id);
        self.accepted_at.remove(&id);
        self.conns.remove(&id);
    }

    /// The relays `peer`'s open relayed connections go through, each once.
    fn relays_to(&self, peer: &PeerId) -> Vec<PeerId> {
        let mut relays: Vec<PeerId> = Vec::new();
        for (id, (p, origin)) in &self.conns {
            if p != peer || *origin != ConnOrigin::Relayed {
                continue;
            }
            if let Some(relay) = self.via.get(id) {
                if !relays.contains(relay) {
                    relays.push(*relay);
                }
            }
        }
        relays.sort_by_key(|r| r.to_bytes());
        relays
    }

    fn origin(&self, id: ConnectionId) -> Option<ConnOrigin> {
        self.conns.get(&id).map(|(_, origin)| *origin)
    }

    fn origins(&self, peer: &PeerId) -> Vec<ConnOrigin> {
        self.conns
            .values()
            .filter(|(p, _)| p == peer)
            .map(|(_, o)| *o)
            .collect()
    }

    fn connected(&self, peer: &PeerId) -> bool {
        self.conns.values().any(|(p, _)| p == peer)
    }

    /// Whether a direct (not relayed) connection to a peer `which` picks is
    /// open.
    fn any_direct(&self, which: impl Fn(&PeerId) -> bool) -> bool {
        self.conns
            .values()
            .any(|(p, origin)| *origin != ConnOrigin::Relayed && which(p))
    }

    /// `peer`'s (direct, relayed) connections.
    fn split(&self, peer: &PeerId) -> (Vec<ConnectionId>, Vec<ConnectionId>) {
        let (mut direct, mut relayed) = (Vec::new(), Vec::new());
        for (id, (p, origin)) in &self.conns {
            if p == peer {
                if *origin == ConnOrigin::Relayed {
                    relayed.push(*id);
                } else {
                    direct.push(*id);
                }
            }
        }
        (direct, relayed)
    }

    fn peers(&self) -> HashSet<PeerId> {
        self.conns.values().map(|(p, _)| *p).collect()
    }

    fn is_empty(&self) -> bool {
        self.conns.is_empty()
    }
}

/// How a link to a peer travels, from the connections open to it when it
/// starts. `we_started`: this node opens the link (a dial), else the peer
/// does (the responder). libp2p-stream opens the stream on any one of them
/// (libp2p-stream shared.rs:124-131), so a mixed set is labelled
/// conservatively: `relayed` if any is, else `direct`. `None`: none open.
fn link_path(origins: &[ConnOrigin], we_started: bool) -> Option<DeliveryPath> {
    let first = origins.first()?;
    if origins.contains(&ConnOrigin::Relayed) {
        return Some(DeliveryPath::Relayed);
    }
    let one = |o: ConnOrigin| match (o, we_started) {
        (ConnOrigin::Punched, _) => DeliveryPath::HolePunched,
        (ConnOrigin::Dialled, true) | (ConnOrigin::Accepted, false) => DeliveryPath::Direct,
        _ => DeliveryPath::Reversed,
    };
    let path = one(*first);
    Some(if origins.iter().all(|o| one(*o) == path) {
        path
    } else {
        DeliveryPath::Direct
    })
}

static HOST: Mutex<Option<Arc<HostHandle>>> = Mutex::new(None);
/// The running host's status (overrides [`CONFIG`] while it runs).
static STATUS: Mutex<Option<P2pStatusInfo>> = Mutex::new(None);
/// The service's start-up decision ([`publish_service_config`]).
static CONFIG: Mutex<Option<P2pStatusInfo>> = Mutex::new(None);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn current_host() -> Option<Arc<HostHandle>> {
    lock(&HOST).clone()
}

/// The relay (PeerId bytes) an inbound Raven link from `peer` (a PeerId
/// text) came over: our reservation's, the relay of a relayed connection
/// the peer opened to us ([`ConnTable::reservation_relay_of`]). `None` when
/// no such connection is open (a direct link, or one over a circuit this
/// node dialled through the peer's relay), no host runs or the text is no
/// PeerId (learning connectivity, Phase 6a).
pub(crate) fn inbound_relay(peer: &str) -> Option<Vec<u8>> {
    let peer: PeerId = peer.parse().ok()?;
    current_host()?
        .reservation_relay_of(&peer)
        .map(|r| r.to_bytes())
}

/// Learning connectivity's terms of `relays` (Phase 6a, design §6,
/// [`crate::learning::relay_terms`]), the ones that are not 0: what
/// automatic relay choice adds to an offered relay's score and what orders
/// a contact dial's circuits. Empty while learning is off.
fn learned_terms(relays: &[PeerId]) -> Vec<(PeerId, i64)> {
    if relays.is_empty() || !crate::learning::live_on() {
        return Vec::new();
    }
    let keys: Vec<Vec<u8>> = relays.iter().map(|r| r.to_bytes()).collect();
    relays
        .iter()
        .zip(crate::learning::relay_terms(&keys))
        .filter(|(_, term)| *term != 0)
        .map(|(relay, term)| (*relay, term))
        .collect()
}

/// [`learned_terms`] of relays named by PeerId text (relay choice's
/// candidates), as [`relay_select::Input::learned`] takes them; a text that
/// is no PeerId has none.
fn learned_terms_of<'a>(relays: impl IntoIterator<Item = &'a str>) -> Vec<(String, i64)> {
    if !crate::learning::live_on() {
        return Vec::new();
    }
    let peers: Vec<PeerId> = relays.into_iter().filter_map(|t| t.parse().ok()).collect();
    learned_terms(&peers)
        .into_iter()
        .map(|(relay, term)| (relay.to_string(), term))
        .collect()
}

/// `relay`'s term among `terms` ([`learned_terms`]), 0 when it has none.
fn term_of(terms: &[(PeerId, i64)], relay: &PeerId) -> i64 {
    terms
        .iter()
        .find(|(r, _)| r == relay)
        .map_or(0, |(_, term)| *term)
}

/// The IPv6 address this host sends from (RFC 6724 source selection,
/// usually a temporary one): route memory's egress probe, a UDP connect that
/// sends nothing. Global only, except under the debug lab switch.
fn preferred_v6() -> Option<Ipv6Addr> {
    preferred_v6_of(
        raven_core::route_memory::egress_addrs().1,
        raven_core::p2p_local_candidates_enabled(),
    )
}

fn preferred_v6_of(egress: Option<Ipv6Addr>, lab_local: bool) -> Option<Ipv6Addr> {
    egress.filter(|ip| lab_local || is_global_ipv6(*ip))
}

fn is_ip6(address: &Multiaddr) -> bool {
    matches!(address.iter().next(), Some(Protocol::Ip6(_)))
}

/// Why the host starts its endpoint over ([`network_changed`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rehome {
    /// This machine's networks changed (netwatch).
    Network,
    /// This computer woke from sleep: whatever the NATs and the relays kept
    /// for us may be gone.
    Wake,
    /// The default route moved to another interface, the networks stayed.
    Route,
    /// Every relay holding a reservation stopped answering pings and nothing
    /// else answered one ([`RelayLoss`]), with no change netwatch could see:
    /// our own path died.
    PathLoss,
    /// Automatic relay choice changed the relays: the endpoint's AutoNAT
    /// clients, made per endpoint, still ask the old ones
    /// ([`autonat_rebind_due`]).
    Relays,
    /// PeerId rotation (Phase 4): the key changes (an epoch boundary, or the
    /// rotation state changed), so the endpoint is built with the new one.
    Rotate,
    /// PeerId rotation (Phase 4): every relay held before a rotation turned
    /// the new ID away, so the endpoint goes back to the previous key
    /// ([`Postponement`]).
    RotateBack,
    /// Auto-reach: STUN discovery saw this computer's public IP move with
    /// no network change netwatch could see (the ISP gave it another one):
    /// every NAT mapping is gone, and the new endpoint's anchor finds the
    /// new address ([`crate::autoreach`]).
    PublicAddress,
}

impl Rehome {
    fn text(self) -> &'static str {
        match self {
            Self::Network => "network changed",
            Self::Wake => "woke from sleep",
            Self::Route => "default route moved",
            Self::PathLoss => "every relay stopped answering",
            Self::Relays => "relays changed",
            Self::Rotate => "network ID rotated",
            Self::RotateBack => "network ID rotation postponed",
            Self::PublicAddress => "public address moved",
        }
    }
}

/// Bumped by every re-home request. An endpoint generation remembers the
/// value it was built under, so a request made while it was being built
/// re-homes it again.
static REHOME_SEQ: AtomicU64 = AtomicU64::new(0);
/// Why, for the next re-home (the latest request wins).
static REHOME_WHY: Mutex<Option<Rehome>> = Mutex::new(None);

fn rehome_notify() -> &'static Notify {
    static NOTIFY: OnceLock<Notify> = OnceLock::new();
    NOTIFY.get_or_init(Notify::new)
}

/// netwatch: start the endpoint over (module doc, "Network changes").
/// `false` when no host runs.
pub(crate) fn network_changed(why: Rehome) -> bool {
    if current_host().is_none() {
        return false;
    }
    *lock(&REHOME_WHY) = Some(why);
    REHOME_SEQ.fetch_add(1, Ordering::SeqCst);
    rehome_notify().notify_one();
    true
}

/// netwatch: networks were only added, so the endpoint and its paths stay;
/// idle relay slots retry at once on a fresh backoff. `false` when no host
/// runs (or its command queue is full).
pub(crate) fn nudge() -> bool {
    current_host().is_some_and(|h| h.commands.try_send(Command::Nudge).is_ok())
}

/// netwatch reads the default routes' fingerprint only while a host runs (or
/// route memory is live).
pub(crate) fn host_running() -> bool {
    current_host().is_some()
}

/// Tells netwatch that every relay went silent ([`RelayLoss`]); it decides
/// between a moved default route and a path loss. netwatch exists on Unix
/// and Windows only; elsewhere the slots' own backoff retries the relays.
fn report_relay_loss() {
    #[cfg(any(unix, windows))]
    crate::netwatch::hint(crate::netwatch::Hint::RelayLoss);
}

/// What IPC `Status` reports: the running host's state, else the service's
/// start-up decision (with `up: false`), else `None` (no service decision:
/// not `raven-node service`). The path counts are the process's and read
/// now, not at the host's last publish (up to a tick old): a delivery a dial
/// just counted shows at once. The friend relay's row is its own task's
/// ([`crate::friend_relay::status`]), there whether or not a host runs.
pub(crate) fn status_snapshot() -> Option<P2pStatusInfo> {
    let published = lock(&STATUS).clone();
    let mut info = match published {
        Some(mut info) => {
            info.paths = Some(path_counts());
            info
        }
        None => lock(&CONFIG).clone()?,
    };
    info.friend_relay = crate::friend_relay::status();
    Some(info)
}

/// The running host's endpoint is confirmed reachable: its reach class
/// ([`ReachClass`]) is public or mapped. The RRH1 custody offer's REACHABLE
/// bit (Phase 3, RAVEN_ROUTE_HINTS_V1 §12). `false` while no host runs.
pub(crate) fn reach_confirmed() -> bool {
    lock(&STATUS).as_ref().is_some_and(|s| {
        matches!(
            ReachClass::parse(&s.reach),
            ReachClass::Public | ReachClass::Mapped
        )
    })
}

/// This node's own p2p routes, as its route hints tell verified contacts
/// (`crate::hints`, RAVEN_ROUTE_HINTS_V1 §6): the host's PeerId, the relays
/// it holds an active reservation on (each active relay slot's `via=`
/// text), its confirmed (UPnP mapped or AutoNAT confirmed) addresses and its
/// listen addresses, both without `/p2p`, no circuit, sorted; and (Phase 4)
/// its NAT mapping classes while the NAT_CLASS gate is live; and (auto-reach)
/// the public addresses STUN discovery found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OwnP2p {
    pub peer_id: String,
    pub relays: Vec<String>,
    pub confirmed: Vec<String>,
    pub listen: Vec<String>,
    pub nat: Option<raven_core::route_hints::NatClass>,
    /// Auto-reach (gated): the public addresses STUN discovery found for the
    /// listeners that no contact has reached from outside yet (a reached one
    /// is among `confirmed`), QUIC first; without `/p2p`.
    pub discovered: Vec<String>,
    /// Auto-reach (gated): the Internet direct listener's public address
    /// (`ip:port`) and whether a contact reached it from outside (RRH1
    /// INET_DIRECT).
    pub inet: Vec<(String, bool)>,
}

/// [`OwnP2p`] as the running host last published it ([`note_own`]).
static OWN: Mutex<Option<OwnP2p>> = Mutex::new(None);

/// [`OwnP2p`] of the running host; `None` while no host runs.
pub(crate) fn own_routes() -> Option<OwnP2p> {
    lock(&OWN).clone()
}

/// Keep `own` as what route hints tell (`None`: no host runs), and wake the
/// announcer ([`crate::hints::own_changed`]) when it differs from what was
/// kept. `true` then. The host publishes every tick: an unchanged value
/// (a re-home that ends on the same reservations, say) wakes nobody.
fn note_own(own: Option<OwnP2p>) -> bool {
    let changed = replace_own(&mut lock(&OWN), own);
    if changed {
        crate::hints::own_changed();
    }
    changed
}

/// `held` becomes `own`; `true` when that changed it.
fn replace_own(held: &mut Option<OwnP2p>, own: Option<OwnP2p>) -> bool {
    let changed = *held != own;
    *held = own;
    changed
}

/// Ask a running host to shut down cleanly (close its connections, so a
/// relay frees the reservation at once) and wait at most `wait`.
pub(crate) async fn shutdown(wait: Duration) {
    let Some(host) = current_host() else {
        return;
    };
    let (done, finished) = oneshot::channel();
    if host.commands.send(Command::Shutdown { done }).await.is_ok() {
        let _ = tokio::time::timeout(wait, finished).await;
    }
}

/// Clears the published handle, status and own routes when the host task
/// ends.
struct RunningGuard;

impl Drop for RunningGuard {
    fn drop(&mut self) {
        *lock(&HOST) = None;
        // Back to the service's start-up decision (`up: false`).
        *lock(&STATUS) = None;
        *lock(&ANNOUNCED) = None;
        note_own(None);
    }
}

/// One Raven link in flight to or from `peer` (the upgrade waits for it).
struct LinkGuard {
    host: Arc<HostHandle>,
    peer: PeerId,
}

impl HostHandle {
    fn link(self: &Arc<Self>, peer: PeerId) -> LinkGuard {
        *lock(&self.links).entry(peer).or_insert(0) += 1;
        LinkGuard {
            host: Arc::clone(self),
            peer,
        }
    }

    fn links_to(&self, peer: &PeerId) -> usize {
        lock(&self.links).get(peer).copied().unwrap_or(0)
    }

    /// How a link to `peer` would travel now ([`link_path`]).
    fn path_to(&self, peer: &PeerId, we_started: bool) -> Option<DeliveryPath> {
        link_path(&lock(&self.conns).origins(peer), we_started)
    }

    /// Any connection to `peer` is open, whoever opened it.
    fn connected(&self, peer: &PeerId) -> bool {
        lock(&self.conns).connected(peer)
    }

    /// The relays `peer`'s open relayed connections go through.
    fn relays_to(&self, peer: &PeerId) -> Vec<PeerId> {
        lock(&self.conns).relays_to(peer)
    }

    /// The relay a relayed connection to `peer` goes through
    /// ([`ConnTable::relay_of`]).
    fn relay_of(&self, peer: &PeerId) -> Option<PeerId> {
        lock(&self.conns).relay_of(peer)
    }

    /// The relay of a relayed connection `peer` opened to us, over our
    /// reservation ([`ConnTable::reservation_relay_of`]).
    fn reservation_relay_of(&self, peer: &PeerId) -> Option<PeerId> {
        lock(&self.conns).reservation_relay_of(peer)
    }

    /// How a dial on this endpoint expands its addresses now.
    fn forms(&self) -> DialForms {
        DialForms {
            wss: self.wss,
            proxy: Some(Arc::clone(&self.proxy)),
            restricted: self.restricted.load(Ordering::SeqCst),
        }
    }

    async fn prefer_direct(&self, peer: PeerId) -> bool {
        let (reply, answer) = oneshot::channel();
        if self
            .commands
            .send(Command::PreferDirect { peer, reply })
            .await
            .is_err()
        {
            return false;
        }
        tokio::time::timeout(PREFER_DIRECT_WAIT + Duration::from_secs(1), answer)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false)
    }

    /// Connects to `peer` within `wait`'s value (today's
    /// [`CONNECT_DEADLINE`], or learning connectivity's shorter wait),
    /// marking it expired when that ran out.
    async fn connect(
        &self,
        peer: PeerId,
        class: PeerClass,
        relays: Vec<PeerId>,
        addrs: Vec<Multiaddr>,
        checked_at: std::time::Instant,
        wait: &ConnectWait,
    ) -> Result<(), String> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Connect {
                peer,
                class,
                relays,
                addrs,
                checked_at,
                reply,
            })
            .await
            .map_err(|_| P2P_NOT_RUNNING.to_string())?;
        // Never longer than today's.
        let within = wait.within.min(CONNECT_DEADLINE);
        match tokio::time::timeout(within, answer).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(P2P_NOT_RUNNING.to_string()),
            Err(_) => {
                wait.expire();
                Err(connect_timed_out(within))
            }
        }
    }
}

impl Drop for LinkGuard {
    fn drop(&mut self) {
        let mut links = lock(&self.host.links);
        if let Some(n) = links.get_mut(&self.peer) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                links.remove(&self.peer);
            }
        }
    }
}

// ── Dial ─────────────────────────────────────────────────────────────────────

/// A connect that got no answer within `wait`: today's words, naming the
/// wait used (whole seconds as today, tenths for a learned wait).
fn connect_timed_out(wait: Duration) -> String {
    let after = if wait.subsec_millis() == 0 {
        format!("{}s", wait.as_secs())
    } else {
        format!("{:.1}s", wait.as_secs_f32())
    };
    format!("{P2P_UNREACHABLE} (connect timed out after {after})")
}

fn open_stream_error(e: OpenStreamError) -> String {
    match e {
        OpenStreamError::UnsupportedProtocol(_) => {
            "p2p stream: the peer does not speak the Raven link (not a RAVEN node, or p2p is off \
             there)"
                .into()
        }
        OpenStreamError::Io(e) => netutil::io_error_text(&e),
        other => format!("p2p stream: {other}"),
    }
}

/// How long one `/dns*/` name may take to resolve.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Addresses one name resolves to that are dialled at most.
const MAX_RESOLVED: usize = 4;

/// The host and TCP port of an address that starts
/// `/<ip4|ip6|dns|dns4|dns6>/<host>/tcp/<port>` (a relay's raw or WSS form,
/// or a circuit through one): what the proxy decision reads (RWS1 §8.3).
/// `None` for anything else (QUIC).
fn tcp_host(addr: &Multiaddr) -> Option<(wss::Host, u16)> {
    let mut parts = addr.iter();
    let host = match parts.next()? {
        Protocol::Ip4(ip) => wss::Host::Ip(ip.into()),
        Protocol::Ip6(ip) => wss::Host::Ip(ip.into()),
        Protocol::Dns(n) | Protocol::Dns4(n) | Protocol::Dns6(n) => wss::Host::Name(n.to_string()),
        _ => return None,
    };
    match parts.next()? {
        Protocol::Tcp(port) => Some((host, port)),
        _ => None,
    }
}

/// WebSocket over TLS (RWS1 §2.1): `/tls` right after the host's
/// `/tcp/<port>` (a relay's WSS form, or a circuit through one).
fn is_wss(addr: &Multiaddr) -> bool {
    tcp_host(addr).is_some() && addr.iter().nth(2) == Some(Protocol::Tls)
}

/// The `/sni/<name>` right after the `/tls` of a WSS form whose host is an
/// IP ([`resolve_addr`] puts the name it resolved there).
fn wss_sni(addr: &Multiaddr) -> Option<String> {
    let mut parts = addr.iter();
    if !matches!(parts.next()?, Protocol::Ip4(_) | Protocol::Ip6(_)) {
        return None;
    }
    match (parts.next()?, parts.next()?, parts.next()?) {
        (Protocol::Tcp(_), Protocol::Tls, Protocol::Sni(name)) => Some(name.to_string()),
        _ => None,
    }
}

/// Whether a dial of `addr` goes through the HTTPS proxy
/// ([`ProxySource::applies`]): only a WSS form ever does (RWS1 §7: raw TCP
/// and QUIC never). A resolved form (`/ip4/A/…/tls/sni/<name>/ws`) goes
/// direct when its IP or its name bypasses the proxy, as the WSS transport
/// decides at the dial: [`resolve_addr`] resolves a WSS name only when it
/// bypasses, so the path label and restricted mode follow the real dial.
fn proxied(proxy: &ProxySource, addr: &Multiaddr) -> bool {
    is_wss(addr)
        && tcp_host(addr).is_some_and(|(host, port)| {
            proxy.applies(&host, port)
                && wss_sni(addr).is_none_or(|name| proxy.applies(&wss::Host::Name(name), port))
        })
}

/// The host has no libp2p DNS transport (it would make hickory buildable, see
/// raven-swarm's Cargo.toml): a `/dns|dns4|dns6/<name>/…` address is resolved
/// here with the system resolver into `/ip4|ip6/…` ones (the family the
/// protocol asks for). Anything else is returned unchanged; a name that does
/// not resolve gives nothing (it is then simply not dialled). A WSS form
/// (RWS1 §2.1) keeps its name: unresolved when the HTTPS proxy carries it
/// (`proxied`: only the proxy resolves it, §7), else as its SNI name, so
/// `/dns4/N/tcp/443/tls/ws/…` becomes `/ip4/A/tcp/443/tls/sni/N/ws/…`.
async fn resolve_addr(addr: Multiaddr, proxied: bool) -> Vec<Multiaddr> {
    let wss = is_wss(&addr);
    if proxied && wss {
        return vec![addr];
    }
    let mut parts = addr.iter();
    let (name, family) = match parts.next() {
        Some(Protocol::Dns(n)) => (n.to_string(), None),
        Some(Protocol::Dns4(n)) => (n.to_string(), Some(4)),
        Some(Protocol::Dns6(n)) => (n.to_string(), Some(6)),
        _ => return vec![addr],
    };
    let mut rest: Vec<Protocol<'static>> = parts.map(Protocol::acquire).collect();
    if wss {
        if let Some(tls) = rest.iter().position(|p| *p == Protocol::Tls) {
            rest.insert(tls + 1, Protocol::Sni(name.clone().into()));
        }
    }
    let port = rest
        .iter()
        .find_map(|p| match p {
            Protocol::Tcp(port) | Protocol::Udp(port) => Some(*port),
            _ => None,
        })
        .unwrap_or(0);
    raven_core::lab_audit::dns();
    let Ok(Ok(found)) = tokio::time::timeout(
        RESOLVE_TIMEOUT,
        tokio::net::lookup_host((name.as_str(), port)),
    )
    .await
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for sock in found {
        let host = match (sock.ip(), family) {
            (IpAddr::V4(v4), None | Some(4)) => Protocol::Ip4(v4),
            (IpAddr::V6(v6), None | Some(6)) => Protocol::Ip6(v6),
            _ => continue,
        };
        let mut resolved = Multiaddr::empty().with(host);
        for p in &rest {
            resolved.push(p.clone());
        }
        if !out.contains(&resolved) {
            out.push(resolved);
        }
        if out.len() >= MAX_RESOLVED {
            break;
        }
    }
    out
}

/// [`resolve_addr`] of each (nothing proxied), without duplicates (also
/// `raven-node relay-probe`'s).
pub(crate) async fn resolve_all(addrs: Vec<Multiaddr>) -> Vec<Multiaddr> {
    let mut out = Vec::new();
    for a in addrs {
        for r in resolve_addr(a, false).await {
            if !out.contains(&r) {
                out.push(r);
            }
        }
    }
    out
}

/// May this answer of a relay name someone else gave us be dialled? A
/// globally routable IP only, the rule an IP literal RELAY is held to
/// (`RAVEN_ROUTE_HINTS_V1` §5.2, and an offer's addresses), so a name a
/// contact controls never makes this node dial loopback or its local
/// networks. In debug builds `lab_local` keeps any answer and
/// `lab_loopback` a loopback one, as for route hints.
fn relay_answer_usable(addr: &Multiaddr, lab_local: bool, lab_loopback: bool) -> bool {
    addr_ip(addr).is_some_and(|ip| {
        p2p_route::is_global_ip(ip)
            || lab_local
            || (lab_loopback && ip.to_canonical().is_loopback())
    })
}

/// [`resolve_all`], where the answers of each address `held` names must be
/// [`relay_answer_usable`], and a WSS form `proxied` names keeps its name
/// for the proxy ([`resolve_addr`]). A held name the proxy would carry is
/// still resolved here first (review B-4): it is kept, unresolved, only
/// when this node's own answers are all usable, so a name a contact
/// controls never steers the user's proxy at their internal hosts or its
/// own loopback. A name that does not resolve here is not dialled.
async fn resolve_held(
    addrs: Vec<Multiaddr>,
    held: impl Fn(&Multiaddr) -> bool,
    proxied: impl Fn(&Multiaddr) -> bool,
    lab_local: bool,
    lab_loopback: bool,
) -> Vec<Multiaddr> {
    let mut out = Vec::new();
    for a in addrs {
        let held = held(&a);
        let proxied = proxied(&a);
        if held && proxied && is_dns(&a) {
            let answers = resolve_addr(a.clone(), false).await;
            let usable = !answers.is_empty()
                && answers
                    .iter()
                    .all(|r| relay_answer_usable(r, lab_local, lab_loopback));
            if usable && !out.contains(&a) {
                out.push(a);
            }
            continue;
        }
        for r in resolve_addr(a, proxied).await {
            let usable = !held || relay_answer_usable(&r, lab_local, lab_loopback);
            if usable && !out.contains(&r) {
                out.push(r);
            }
        }
    }
    out
}

/// [`resolve_all`] for a dial to a contact: a circuit whose relay is named
/// by a DNS name keeps only the answers that are globally routable
/// ([`relay_answer_usable`]). An IP literal, and a name for the contact
/// itself, are left as they are; a WSS form `proxied` names is left to the
/// proxy.
async fn resolve_dial(
    addrs: Vec<Multiaddr>,
    proxied: impl Fn(&Multiaddr) -> bool,
    lab_local: bool,
    lab_loopback: bool,
) -> Vec<Multiaddr> {
    resolve_held(
        addrs,
        |a| is_dns(a) && is_circuit(a),
        proxied,
        lab_local,
        lab_loopback,
    )
    .await
}

/// [`resolve_all`] for a relay slot's names. A slot picked from a contact's
/// offer (`offered`) keeps only the globally routable answers of a DNS name
/// ([`relay_answer_usable`]): the offer's IP literals are held to that
/// already, and a name it gives must not reach this node's loopback or
/// local networks either. A relay set by hand is resolved as it is. A WSS
/// form `proxied` names is left to the proxy (an offered one only when its
/// answers here are usable, [`resolve_held`]).
async fn resolve_slot(
    named: Vec<Multiaddr>,
    offered: bool,
    proxied: impl Fn(&Multiaddr) -> bool,
    lab_local: bool,
    lab_loopback: bool,
) -> Vec<Multiaddr> {
    resolve_held(
        named,
        |a| offered && is_dns(a),
        proxied,
        lab_local,
        lab_loopback,
    )
    .await
}

/// How the running host dials a relay or contact address: at its RWS1 §2.3
/// forms ([`p2p_route::relay_dial_forms`]). The default is a host that dials
/// no WSS (the gate closed, or no host running): a WSS address is dialled at
/// its raw sibling, and nothing is restricted.
#[derive(Clone, Default)]
struct DialForms {
    /// This host dials WSS (the WSS gate was live when it was built).
    wss: bool,
    /// The proxy of WSS dials: a relay it carries is dialled at its WSS
    /// form first, and a name it resolves is left to it.
    proxy: Option<Arc<ProxySource>>,
    /// Restricted network (RWS1 §9): WSS forms first, no direct address.
    restricted: bool,
}

impl DialForms {
    /// The running host's ([`HostHandle::forms`]), or the default while none
    /// runs (the dial is then refused with [`P2P_NOT_RUNNING`]).
    fn of_host() -> Self {
        current_host().map(|h| h.forms()).unwrap_or_default()
    }

    /// The WSS form of `v` first: the proxy carries it, or the network is
    /// restricted (its raw form would not get out).
    fn prefer_wss(&self, v: &ViaAddr) -> bool {
        self.restricted
            || self.proxy.as_ref().is_some_and(|proxy| {
                v.text
                    .parse::<Multiaddr>()
                    .ok()
                    .and_then(|a| tcp_host(&a))
                    .is_some_and(|(host, port)| proxy.applies(&host, port))
            })
    }

    /// Whether `addr` goes through the proxy ([`proxied`]).
    fn proxied(&self, addr: &Multiaddr) -> bool {
        self.proxy
            .as_ref()
            .is_some_and(|proxy| proxied(proxy, addr))
    }

    /// The forms of one relay address, best first.
    fn relay(&self, v: &ViaAddr) -> Vec<String> {
        p2p_route::relay_dial_forms(v, self.wss, self.prefer_wss(v))
    }

    /// While this host dials no WSS, a WSS address is dialled at its raw
    /// sibling: say so once per process (counts only).
    fn note_held<'a>(&self, addrs: impl IntoIterator<Item = &'a ViaAddr>) {
        if self.wss {
            return;
        }
        let wss = addrs.into_iter().filter(|v| v.is_wss()).count();
        if wss > 0 && !WSS_HOLD_SAID.swap(true, Ordering::SeqCst) {
            eprintln!(
                "raven-node p2p: {} ({wss} WSS relay address(es) dialled at their raw TCP form)",
                raven_core::WSS_HOLD
            );
        }
    }
}

/// [`DialForms::note_held`] said it.
static WSS_HOLD_SAID: AtomicBool = AtomicBool::new(false);

/// The libp2p addresses to try for `target`, in plan order
/// ([`P2pDialSet::dial_addrs_with`]: the first direct address, the first
/// circuit, then the rest), each relay address at its `forms`
/// ([`DialForms`]). `/p2p/<PeerId>` takes the dial set's addresses for that
/// PeerId: the contact book's and what its route hints said (none is fine:
/// a connection may already exist, or libp2p may know the contact's
/// addresses from an earlier connection). An explicit direct address is
/// refused on a restricted network ([`P2P_RESTRICTED_DIRECT`]).
fn dial_addrs(
    target: &P2pDialTarget,
    set: Option<&P2pDialSet>,
    forms: &DialForms,
) -> Result<Vec<Multiaddr>, String> {
    let set = set.filter(|s| s.peer_id == target.peer_id());
    let text: Vec<String> = match target {
        P2pDialTarget::Peer { .. } => set
            .map(|s| {
                forms.note_held(s.direct.iter().chain(&s.relays));
                s.dial_addrs_with(forms.wss, |v| forms.prefer_wss(v), forms.restricted)
            })
            .unwrap_or_default(),
        P2pDialTarget::Direct { .. } if forms.restricted => {
            return Err(P2P_RESTRICTED_DIRECT.to_string())
        }
        P2pDialTarget::Direct { addr, .. } => {
            forms.note_held([addr]);
            if addr.is_wss() {
                forms.relay(addr)
            } else {
                vec![addr.text.clone()]
            }
        }
        P2pDialTarget::Circuit { peer_id, relay } => {
            forms.note_held([relay]);
            forms
                .relay(relay)
                .into_iter()
                .map(|text| {
                    let form = ViaAddr {
                        text,
                        peer_id: relay.peer_id.clone(),
                    };
                    p2p_route::circuit_addr(&form, peer_id)
                })
                .collect()
        }
    };
    text.iter()
        .map(|t| {
            t.parse::<Multiaddr>()
                .map_err(|e| format!("p2p address: {e}"))
        })
        .collect()
}

/// The relays a dial of `target` may go through ([`dial_addrs`]): the dial
/// set's relays ([`P2pDialSet::relay_peer_ids`]: the ones its route hints
/// named, then its `via=` relays), or the one relay of an explicit circuit.
/// The dial admits them with the contact (CONTACT_RELAY). While learning
/// connectivity is on they go in the order its circuits do: by learned
/// term, highest first, stable ([`order_dial`]).
fn dial_relays(target: &P2pDialTarget, set: Option<&P2pDialSet>) -> Vec<PeerId> {
    let text: Vec<String> = match target {
        P2pDialTarget::Peer { peer_id } => set
            .filter(|s| s.peer_id == *peer_id)
            .map(P2pDialSet::relay_peer_ids)
            .unwrap_or_default(),
        P2pDialTarget::Direct { .. } => Vec::new(),
        P2pDialTarget::Circuit { relay, .. } => vec![relay.peer_id.clone()],
    };
    let mut relays: Vec<PeerId> = text.iter().filter_map(|t| t.parse().ok()).collect();
    let terms = learned_terms(&relays);
    if !terms.is_empty() {
        relays.sort_by_key(|r| std::cmp::Reverse(term_of(&terms, r)));
    }
    relays
}

/// Peers that turned one of our dials away at once ([`note_closed_at_once`]),
/// with when. A static: a re-home replaces the host and its handle, the
/// dial that asks may have started on the old one.
static CLOSED_AT_ONCE: Mutex<Option<HashMap<PeerId, Instant>>> = Mutex::new(None);
const MAX_CLOSED_AT_ONCE: usize = 256;

/// `peer` turned a dial of ours away at once: it closed a connection we had
/// just dialled before any link used it (its peer gate). Only that close
/// counts: what a relay answers a circuit request is the dial's facts
/// ([`note_dial_failure`]), never a refusal. A destination whose gate
/// refuses our circuit before accepting it makes the relay answer
/// CONNECTION_FAILED, which cannot be told from a contact that is gone
/// (`CircuitOutcome::NotOnRelay`).
fn note_closed_at_once(peer: PeerId) {
    let mut closed = lock(&CLOSED_AT_ONCE);
    let map = closed.get_or_insert_with(HashMap::new);
    if map.len() >= MAX_CLOSED_AT_ONCE && !map.contains_key(&peer) {
        map.clear();
    }
    map.insert(peer, Instant::now());
}

/// Did `peer` turn a dial of ours away at once since `since`?
fn closed_at_once_since(peer: &PeerId, since: Instant) -> bool {
    lock(&CLOSED_AT_ONCE)
        .as_ref()
        .and_then(|m| m.get(peer))
        .is_some_and(|at| *at >= since)
}

/// What a failed dial adds to its error when the contact's node, or its
/// relay, turned this node away at once (no new error code: the error keeps
/// its own, P2P_UNREACHABLE for a failed connect).
fn refusal_hint(target_closed: bool, relay_closed: bool) -> Option<&'static str> {
    if target_closed {
        Some(
            "the contact's node refused the p2p connection at once: it may not know this \
             node's PeerId yet (it learns it once the two of you are connected over Tor or the \
             local network, and only after it verified you)",
        )
    } else if relay_closed {
        Some(
            "the contact's relay refused this node: ask its operator to allow your PeerId \
             (`raven whoami --peer-id` prints it; they run `raven relay allow <PeerId>`) (this \
             node tries that relay again within 10 minutes, or as soon as the contact names it \
             again)",
        )
    } else {
        None
    }
}

/// `error` with [`refusal_hint`] appended when one applies to this dial.
fn with_refusal_hint(error: String, peer: &PeerId, relays: &[PeerId], since: Instant) -> String {
    let hint = refusal_hint(
        closed_at_once_since(peer, since),
        relays.iter().any(|r| closed_at_once_since(r, since)),
    );
    match hint {
        Some(hint) => format!("{error}; {hint}"),
        None => error,
    }
}

/// What the failed addresses of the dial in flight to each peer said (the
/// "nobody reachable" diagnosis, any-network plan C10). The host loop writes
/// it ([`Host::connect`], its `OutgoingConnectionError`); the dial reads it
/// once its connect fails, after its own [`CONNECT_DEADLINE`] too
/// ([`explain_unreachable`]). A static, as [`CLOSED_AT_ONCE`]: a re-home
/// replaces the host and its handle.
static DIAL_FACTS: Mutex<Option<DialFacts>> = Mutex::new(None);
/// Dials remembered at most: past that, the map starts over.
const MAX_DIAL_FACTS: usize = 64;

/// One dial in flight: the relays it planned and what its addresses said.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct InFlight {
    /// The dial's relays, in plan order.
    relays: Vec<PeerId>,
    /// What each relay answered our circuit request.
    circuits: HashMap<PeerId, CircuitOutcome>,
    /// What each direct address did.
    direct: Vec<AddrOutcome>,
    /// A network change or a host stop ended it, or it failed in a way that
    /// says nothing about the network (no transport ran): no reason.
    interrupted: bool,
    /// Connects waiting on this dial (a joined one included) that have not
    /// read it yet.
    waiters: u32,
}

impl InFlight {
    /// A dial planned through `relays`. `turned_away`: relays whose circuits
    /// were left out because they turned this node away as a non-member
    /// ([`order_dial`]): that refusal is their answer.
    fn new(relays: Vec<PeerId>, turned_away: &[PeerId]) -> Self {
        Self {
            relays,
            circuits: turned_away
                .iter()
                .map(|r| (*r, CircuitOutcome::Refused))
                .collect(),
            waiters: 1,
            ..Self::default()
        }
    }

    /// What the addresses of a failed dial to the target said. A relay's
    /// specific answer replaces an earlier "no answer"; nothing else is
    /// replaced.
    fn absorb(&mut self, failed: Vec<Failed>) {
        for f in failed {
            match f {
                Failed::Direct(o) => self.direct.push(o),
                Failed::Circuit { relay, outcome } => {
                    self.circuits
                        .entry(relay)
                        .and_modify(|o| {
                            if *o == CircuitOutcome::NoAnswer {
                                *o = outcome;
                            }
                        })
                        .or_insert(outcome);
                }
            }
        }
    }

    /// The relay's own dial failed: it said nothing.
    fn relay_silent(&mut self, relay: PeerId) {
        self.circuits
            .entry(relay)
            .or_insert(CircuitOutcome::NoAnswer);
    }

    /// One outcome per planned relay, in plan order (a relay never heard
    /// from, its connect timed out, is NoAnswer), then any other relay a
    /// circuit went through.
    fn per_relay(&self) -> Vec<(PeerId, CircuitOutcome)> {
        let mut others: Vec<(PeerId, CircuitOutcome)> = self
            .circuits
            .iter()
            .filter(|(r, _)| !self.relays.contains(r))
            .map(|(r, o)| (*r, *o))
            .collect();
        others.sort_by_key(|(r, _)| r.to_bytes());
        self.relays
            .iter()
            .map(|r| {
                let o = self.circuits.get(r).copied();
                (*r, o.unwrap_or(CircuitOutcome::NoAnswer))
            })
            .chain(others)
            .collect()
    }
}

/// [`InFlight`] per target.
#[derive(Default)]
struct DialFacts {
    by_peer: HashMap<PeerId, InFlight>,
}

impl DialFacts {
    /// At most [`MAX_DIAL_FACTS`] (one more is let in; past it, all go).
    fn bound(&mut self) {
        if self.by_peer.len() > MAX_DIAL_FACTS {
            self.by_peer.clear();
        }
    }

    /// A new dial to `peer`: it replaces what an earlier one left (a dial
    /// that connected, or one nobody read).
    fn begin(&mut self, peer: PeerId, f: InFlight) {
        self.by_peer.insert(peer, f);
    }

    /// A connect that joined the dial in flight to `peer`
    /// (DialPeerConditionFalse) reads that dial's facts too; `f` only when
    /// none are kept.
    fn join(&mut self, peer: PeerId, f: InFlight) {
        self.by_peer
            .entry(peer)
            .and_modify(|d| d.waiters += 1)
            .or_insert(f);
    }

    /// The dial to `peer` connected: nothing to explain.
    fn forget(&mut self, peer: &PeerId) {
        self.by_peer.remove(peer);
    }

    /// A dial to `peer` failed: `failures` ([`dial_failures`]) are what its
    /// addresses said; `says_nothing` when no transport ran (a gate denied
    /// it, it was aborted, reached the wrong peer). Every dial planned
    /// through `peer` as a relay heard nothing from it.
    fn failed(&mut self, peer: PeerId, failures: Vec<Failed>, says_nothing: bool) {
        if let Some(f) = self.by_peer.get_mut(&peer) {
            f.absorb(failures);
            f.interrupted |= says_nothing;
        }
        for f in self
            .by_peer
            .values_mut()
            .filter(|f| f.relays.contains(&peer))
        {
            f.relay_silent(peer);
        }
    }

    /// A re-home or a host stop ends every dial: their answers ("the network
    /// changed during the dial") get no reason.
    fn interrupt_all(&mut self) {
        for f in self.by_peer.values_mut() {
            f.interrupted = true;
        }
    }

    /// One waiting connect reads `peer`'s facts; the last one takes them.
    fn take(&mut self, peer: &PeerId) -> Option<InFlight> {
        let f = self.by_peer.get_mut(peer)?;
        f.waiters = f.waiters.saturating_sub(1);
        if f.waiters == 0 {
            self.by_peer.remove(peer)
        } else {
            Some(f.clone())
        }
    }
}

fn with_facts<T>(f: impl FnOnce(&mut DialFacts) -> T) -> T {
    let mut held = lock(&DIAL_FACTS);
    let facts = held.get_or_insert_with(DialFacts::default);
    facts.bound();
    f(facts)
}

/// This computer's default route, as netwatch last read it.
fn last_egress() -> Option<bool> {
    #[cfg(any(unix, windows))]
    {
        crate::netwatch::last_egress()
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// The PeerId a relay text (`/…/p2p/<relay>`) names: its last `/p2p`.
fn named_peer(text: &str) -> Option<PeerId> {
    let addr: Multiaddr = text.parse().ok()?;
    addr.iter()
        .filter_map(|p| match p {
            Protocol::P2p(peer) => Some(peer),
            _ => None,
        })
        .last()
}

/// Our relay slots in `Status` order (`relay_health`: the ones set by hand,
/// then the ones picked from offers): the relay of each. Slot `n` of the
/// reason block (`relay=mine<n>`) is the `n`th.
fn slot_relays(st: &P2pStatusInfo) -> Vec<Option<PeerId>> {
    st.relay_health
        .iter()
        .map(|h| named_peer(&h.relay))
        .collect()
}

/// [`slot_relays`] of the running host's `Status` as PeerId texts (empty
/// while none runs): what `relay=mine<n>` names now
/// ([`crate::delivery_paths`]).
pub(crate) fn slot_relay_ids() -> Vec<Option<String>> {
    status_snapshot()
        .map(|st| {
            slot_relays(&st)
                .into_iter()
                .map(|r| r.map(|r| r.to_base58()))
                .collect()
        })
        .unwrap_or_default()
}

/// What a failed dial learned, route by route: `closed` tells whether a peer
/// closed our connection at once during this dial.
fn dial_summary(
    f: InFlight,
    slots: &[Option<PeerId>],
    closed: impl Fn(&PeerId) -> bool,
    target_closed: bool,
) -> DialSummary {
    let circuits = f
        .per_relay()
        .into_iter()
        .map(|(r, o)| {
            let slot = slots
                .iter()
                .position(|s| *s == Some(r))
                .and_then(|i| u8::try_from(i + 1).ok());
            (slot, o, closed(&r))
        })
        .collect();
    DialSummary {
        interrupted: f.interrupted,
        target_closed_at_once: target_closed,
        circuits,
        direct: f.direct,
        slots_answering: Vec::new(),
    }
}

/// When each relay of ours last answered a ping (the host's ping events), so
/// a failed dial can tell a relay that answered while it ran from one that
/// went silent ([`slots_answering`]). A static, as [`CLOSED_AT_ONCE`]: a
/// re-home keeps it.
static RELAY_PINGED: Mutex<Option<HashMap<PeerId, Instant>>> = Mutex::new(None);

/// `relay`, a relay of ours, answered a ping at `at`.
fn note_relay_pinged(relay: PeerId, at: Instant) {
    let mut pinged = lock(&RELAY_PINGED);
    let map = pinged.get_or_insert_with(HashMap::new);
    if map.len() >= MAX_CLOSED_AT_ONCE && !map.contains_key(&relay) {
        map.clear();
    }
    map.insert(relay, at);
}

/// Did `relay` answer a ping at or after `since`?
fn relay_pinged_since(relay: &PeerId, since: Instant) -> bool {
    lock(&RELAY_PINGED)
        .as_ref()
        .and_then(|m| m.get(relay))
        .is_some_and(|at| *at >= since)
}

/// How long the diagnosis of a failed dial waits at most to learn whether a
/// relay of ours that gave no answer is up ([`await_slots`]): a default ping
/// round (15 s + 5 s) and a second. A relay that is up answers its next ping
/// within it. One that does not (frozen: our reservation on it can stay up
/// for 40 s more) is taken as not answering, as before.
const RELAY_VERDICT_WAIT: Duration = Duration::from_secs(21);

/// What is known of our relay slots that a failed dial got no answer
/// through ([`slot_verdict`]).
#[derive(Clone, Debug, PartialEq, Eq)]
enum SlotVerdict {
    /// These slots answered us after the dial began: they are up.
    Answering(Vec<u8>),
    /// None answered yet, and one still holds our reservation: wait.
    Open,
    /// None answered, and none holds our reservation now: no answer is the
    /// relays' (or there was no slot to ask about).
    Silent,
}

/// The slots in question: a circuit through it got no answer and its relay
/// held our reservation when the dial failed (`Status` order, slot `n` is
/// the `n`th row), each with its relay.
fn silent_slots(summary: &DialSummary, st: &P2pStatusInfo) -> Vec<(u8, PeerId)> {
    let mut out: Vec<(u8, PeerId)> = Vec::new();
    for slot in summary
        .circuits
        .iter()
        .filter(|c| c.1 == CircuitOutcome::NoAnswer)
        .filter_map(|c| c.0)
    {
        let Some(h) = st.relay_health.get(usize::from(slot).wrapping_sub(1)) else {
            continue;
        };
        if let (true, Some(relay)) = (h.state == "reserved", named_peer(&h.relay)) {
            if !out.iter().any(|(s, _)| *s == slot) {
                out.push((slot, relay));
            }
        }
    }
    out
}

/// The slots of `asked` ([`silent_slots`]) that answered (`pinged`), else
/// whether one still holds our reservation (`held`).
fn slot_verdict(
    asked: &[(u8, PeerId)],
    pinged: impl Fn(&PeerId) -> bool,
    held: impl Fn(u8, &PeerId) -> bool,
) -> SlotVerdict {
    let answering: Vec<u8> = asked
        .iter()
        .filter(|(_, r)| pinged(r))
        .map(|(s, _)| *s)
        .collect();
    if !answering.is_empty() {
        SlotVerdict::Answering(answering)
    } else if asked.iter().any(|(s, r)| held(*s, r)) {
        SlotVerdict::Open
    } else {
        SlotVerdict::Silent
    }
}

/// Does slot `slot` of `st` hold our reservation on `relay`?
fn holds_reservation(st: &P2pStatusInfo, slot: u8, relay: &PeerId) -> bool {
    st.relay_health
        .get(usize::from(slot).wrapping_sub(1))
        .is_some_and(|h| h.state == "reserved" && named_peer(&h.relay) == Some(*relay))
}

/// Our slots of `asked` ([`silent_slots`]) that answered a ping after the
/// dial began (`since`), once that is known: a relay that froze looks the
/// same as a contact that froze behind a relay that is up (both: no answer
/// in time), so while none has answered and one still holds our
/// reservation, this waits for its next ping or the loss of the
/// reservation, at most [`RELAY_VERDICT_WAIT`] (then none).
async fn await_slots(asked: &[(u8, PeerId)], since: Instant) -> Vec<u8> {
    let deadline = Instant::now() + RELAY_VERDICT_WAIT;
    loop {
        let now_st = status_snapshot().unwrap_or_default();
        let held = |slot: u8, relay: &PeerId| holds_reservation(&now_st, slot, relay);
        match slot_verdict(asked, |r| relay_pinged_since(r, since), held) {
            SlotVerdict::Answering(slots) => return slots,
            SlotVerdict::Silent => return Vec::new(),
            SlotVerdict::Open if Instant::now() >= deadline => return Vec::new(),
            SlotVerdict::Open => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
}

/// No global listen address (a circuit address does not count) and no UPnP
/// mapping.
fn behind_nat(listen_addrs: &[String], upnp: &str) -> bool {
    let global = listen_addrs
        .iter()
        .filter_map(|a| a.parse::<Multiaddr>().ok())
        .filter(|a| !a.iter().any(|p| p == Protocol::P2pCircuit))
        .any(|a| addr_ip(&a).is_some_and(p2p_route::is_global_ip));
    !global && !upnp.starts_with("mapped")
}

/// What this node knows of itself from its `Status`.
fn my_facts(st: &P2pStatusInfo, hides_ip_from_them: bool, no_default_route: bool) -> MyFacts {
    MyFacts {
        class: ReachClass::parse(&st.reach),
        behind_nat: behind_nat(&st.listen_addrs, &st.upnp),
        hides_ip_from_them,
        no_default_route,
    }
}

/// What this node knows of the contact's routes. Blocking (reads its route
/// hints):
/// - from_card_only: no route hints from it, not even an expired one;
/// - hint_expired: its last route hints have expired (a tombstone);
/// - heard_s: the smaller of [`crate::delivery_paths::heard_age`] and the
///   age of its last route hints.
fn their_facts(data_dir: &Path, key: &[u8; 32], now_ms: u64) -> TheirFacts {
    let hints = raven_core::learned_routes::last_heard(data_dir, key, now_ms);
    let hint_age = hints.map(|(at, _)| now_ms.saturating_sub(at) / 1000);
    let heard = crate::delivery_paths::heard_age(key).map(|d| d.as_secs());
    TheirFacts {
        from_card_only: hints.is_none(),
        hint_expired: hints.is_some_and(|(_, expired)| expired),
        heard_s: match (heard, hint_age) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        },
    }
}

/// Blocking: does this node hide its IP from the contact (D4,
/// [`raven_core::outbox::may_share_ip`]), has it no default route (netwatch's
/// last reading `egress`; before any, one look at the source addresses the
/// default routes would use: a UDP connect, nothing sent), and what it knows
/// of the contact.
fn local_facts(
    data_dir: &Path,
    key: &[u8; 32],
    egress: Option<bool>,
    now_ms: u64,
) -> (bool, bool, TheirFacts) {
    let hides_ip = !raven_core::outbox::may_share_ip(data_dir, key);
    let no_default_route = egress.map_or_else(
        || raven_core::route_memory::egress_addrs() == (None, None),
        |e| !e,
    );
    (
        hides_ip,
        no_default_route,
        their_facts(data_dir, key, now_ms),
    )
}

/// `e` and the reason block, joined as every route text is ("; ").
fn with_reason(e: String, d: &Diag) -> String {
    format!("{e}; {}", d.render())
}

/// The log line of a diagnosis: the reason's token, never a peer.
fn unreachable_line(why: Why) -> String {
    format!("a contact is unreachable ({})", why.token())
}

/// The error `e` of a connect to `peer` (the contact `contact`) that failed,
/// plus the reason block ([`raven_core::reach_diag`]) after whatever it
/// already says (Phase 1's refusal hint stays in front, for older clients).
/// Nothing is added when no dial ran, when it was interrupted, or when the
/// connect failed for another reason than [`P2P_UNREACHABLE`] (the host is
/// not up, the contact book kept changing). A relay of ours that gave no
/// answer is asked about ([`DialSummary::slots_answering`]: a contact
/// asleep behind a relay that is up is `contact_offline`, never "your relay
/// is not answering"); when that relay has not answered since the dial
/// began but still holds our reservation, the error goes back now without
/// a reason, and the reason is decided and kept once the relay answers or
/// loses the reservation ([`await_slots`]), so no caller waits for it. The
/// reason is kept for `raven status` ([`note_reason`]); the log line names
/// the reason only.
async fn explain_unreachable(
    data_dir: &Path,
    contact: &[u8; 32],
    peer: PeerId,
    e: String,
    since: Instant,
) -> String {
    let Some(mut facts) = with_facts(|f| f.take(&peer)) else {
        return e;
    };
    facts.interrupted |= !e.starts_with(P2P_UNREACHABLE);
    // What each relay answered, for learning connectivity's relay rows.
    let per_relay = facts.per_relay();
    explain_with(data_dir, contact, peer, facts, per_relay, e, since).await
}

/// Did a failed link ride a stale relayed connection (review 5a-3)? The
/// connect found a connection to the contact open already (`reused`: it
/// answered at once, no dial ran, so no facts explain the failure); the
/// link went over it relayed (`path`); no re-home ended it meanwhile
/// (`same_host`: that explains itself); and it got no answer at all before
/// the Noise handshake verified the contact (`stage`, also when
/// [`DIAL_DEADLINE`] cut it there; `error`: a time-out or no route, never a
/// close or a refusal). A circuit through a relay that froze stays open
/// until the relay is given up: with route hints on, the announcers' links
/// keep one open, every dial rode it, and `raven status` said nothing about
/// the relay for 40 s more.
fn stale_relayed_link(
    reused: bool,
    path: Option<DeliveryPath>,
    same_host: bool,
    stage: &str,
    error: &str,
) -> bool {
    reused
        && path == Some(DeliveryPath::Relayed)
        && same_host
        && stage == internet_direct::STAGE_NOISE
        && crate::outbox::dial_error_code(error) == crate::outbox::code::NOT_REACHABLE
}

/// Phase 6b S21: the relays a relayed link that broke inside
/// (`security::link_broke`) is noted against, as PeerId bytes (the
/// `SEC_RELAY_LINK_BROKEN` events and, while learning is on, R8's signal
/// to each one's learned term): the ones that link went through
/// (`through`, as the connection table named them when it opened), never
/// the rest of the contact's dial set (`dial_set`). Blaming every relay of
/// the set lowered the good relay with the bad one, so the circuit through
/// the bad one kept its place first and the good one was never tried
/// (review learning-7). Only when the table named none, the set's relay if
/// it has just one; otherwise none.
fn broken_link_relays(through: &[PeerId], dial_set: &[PeerId]) -> Vec<Vec<u8>> {
    let blamed = match (through, dial_set) {
        ([], [only]) => std::slice::from_ref(only),
        _ => through,
    };
    blamed.iter().map(|r| r.to_bytes()).collect()
}

/// [`explain_unreachable`] for a link that rode a stale relayed connection
/// ([`stale_relayed_link`]) through the relays `via`: no dial ran, so its
/// facts are those of a dial that got no answer through them, and the
/// reason is decided the same way (a relay of ours that answered a ping
/// since the dial began means the contact is silent behind it; one that has
/// not but still holds our reservation is decided once it answers or loses
/// it; otherwise it is not answering). No circuit dial ran, so learning
/// connectivity gets no relay answers from it (the link's own outcome
/// already names the relay it rode: `learning::observe_dial`).
async fn explain_stale_link(
    data_dir: &Path,
    contact: &[u8; 32],
    peer: PeerId,
    via: Vec<PeerId>,
    e: String,
    since: Instant,
) -> String {
    let facts = InFlight::new(via, &[]);
    explain_with(data_dir, contact, peer, facts, Vec::new(), e, since).await
}

/// [`explain_unreachable`] once the dial's facts are in hand; `per_relay`:
/// what each relay answered, for learning connectivity's relay rows.
async fn explain_with(
    data_dir: &Path,
    contact: &[u8; 32],
    peer: PeerId,
    facts: InFlight,
    per_relay: Vec<(PeerId, CircuitOutcome)>,
    e: String,
    since: Instant,
) -> String {
    let st = status_snapshot().unwrap_or_default();
    let slots = slot_relays(&st);
    let mut summary = dial_summary(
        facts,
        &slots,
        |p| closed_at_once_since(p, since),
        closed_at_once_since(&peer, since),
    );
    if summary.interrupted {
        return e;
    }
    let (dd, key, egress) = (data_dir.to_path_buf(), *contact, last_egress());
    let Ok((hides_ip, no_default_route, them)) =
        blocking(move || Ok(local_facts(&dd, &key, egress, crate::now_ms()))).await
    else {
        return e;
    };
    let me = my_facts(&st, hides_ip, no_default_route);
    // With no default route no relay answer decides anything (`no_route`).
    if !no_default_route {
        crate::learning::circuits(
            per_relay
                .into_iter()
                .map(|(r, outcome)| (r.to_bytes(), outcome))
                .collect(),
        );
        let asked = silent_slots(&summary, &st);
        let held = |slot: u8, relay: &PeerId| holds_reservation(&st, slot, relay);
        match slot_verdict(&asked, |r| relay_pinged_since(r, since), held) {
            SlotVerdict::Answering(slots) => summary.slots_answering = slots,
            SlotVerdict::Silent => {}
            SlotVerdict::Open => {
                let contact = *contact;
                tokio::spawn(async move {
                    summary.slots_answering = await_slots(&asked, since).await;
                    note_reason(&contact, &summary, &me, &them, &slots, Some(since));
                });
                return e;
            }
        }
    }
    match note_reason(contact, &summary, &me, &them, &slots, None) {
        Some(d) => with_reason(e, &d),
        None => e,
    }
}

/// The reason for a failed dial ([`diagnose`]), kept for `raven status`
/// with the relay its slot names (`slots`: our slots when the dial failed,
/// so a later replacement of that slot is never named as this reason's
/// relay) and logged (the reason only). `decided_late`: the dial's start,
/// when the reason is decided after the dial returned; it is then kept only
/// if nothing newer is known of the contact
/// ([`crate::delivery_paths::note_unreachable_after`]).
fn note_reason(
    contact: &[u8; 32],
    summary: &DialSummary,
    me: &MyFacts,
    them: &TheirFacts,
    slots: &[Option<PeerId>],
    decided_late: Option<Instant>,
) -> Option<Diag> {
    let d = diagnose(summary, me, them)?;
    let relay = d
        .relay
        .and_then(|slot| {
            slots
                .get(usize::from(slot).wrapping_sub(1))
                .copied()
                .flatten()
        })
        .map(|r| r.to_base58());
    let kept = match decided_late {
        Some(since) => {
            crate::delivery_paths::note_unreachable_after(contact, &d, relay, since.into_std())
        }
        None => {
            crate::delivery_paths::note_unreachable(contact, &d, relay);
            true
        }
    };
    // Another carrier delivered to it since p2p last could not (Tor, the
    // LAN): p2p not reaching it is no news worth a line (E2 r9 #3: this
    // line came every 30-40 s while Tor delivered). The reason is still kept
    // for status.
    if kept && crate::delivery_paths::failure_is_news(contact, OutboxCarrier::P2p) {
        netutil::log_limited(
            &REACH_LOG,
            "raven-node p2p",
            format_args!(
                "{} (contact {})",
                unreachable_line(d.why),
                netutil::link_tag(contact)
            ),
        );
    }
    Some(d)
}

/// What a failed outgoing dial to `peer` tells the diagnosis: what each of
/// its addresses said ([`dial_failures`]). A relay's answer to a circuit is
/// read there and only there (`Busy`, `NotOnRelay`, `Refused`): it is never
/// a quick close ([`note_closed_at_once`]). A relay whose peer gate refuses
/// a non-member does not answer at all, it closes the connection, and the
/// swarm loop notes that close itself.
fn note_dial_failure(facts: &mut DialFacts, peer: Option<PeerId>, error: &DialError) {
    if let Some(peer) = peer {
        let says_nothing = !matches!(error, DialError::Transport(_));
        facts.failed(peer, dial_failures(error), says_nothing);
    }
}

/// The relay of a circuit address (`…/p2p/<relay>/p2p-circuit/…`).
fn circuit_relay(addr: &Multiaddr) -> Option<PeerId> {
    let mut relay = None;
    for p in addr.iter() {
        match p {
            Protocol::P2p(peer) => relay = Some(peer),
            Protocol::P2pCircuit => return relay,
            _ => {}
        }
    }
    None
}

/// (target, relay): the relay said the target holds no reservation there
/// (NO_RESERVATION, [`CircuitOutcome::NotOnRelay`]), and when. In memory
/// only, and a static like [`CLOSED_AT_ONCE`]: a re-home keeps it.
static DEMOTED: Mutex<Option<HashMap<(PeerId, PeerId), Instant>>> = Mutex::new(None);

/// Circuits to `target` through `relay` go last for [`DEMOTE_FOR`]
/// ([`order_dial`]): an old route, but never skipped (the contact may be
/// back on that relay).
fn note_demoted(target: PeerId, relay: PeerId, now: Instant) {
    let mut demoted = lock(&DEMOTED);
    let map = demoted.get_or_insert_with(HashMap::new);
    if map.len() >= MAX_DEMOTED && !map.contains_key(&(target, relay)) {
        map.retain(|_, at| now.saturating_duration_since(*at) < DEMOTE_FOR);
        if map.len() >= MAX_DEMOTED {
            map.clear();
        }
    }
    map.insert((target, relay), now);
}

/// Are circuits to `target` through `relay` demoted at `now`?
fn is_demoted(target: &PeerId, relay: &PeerId, now: Instant) -> bool {
    lock(&DEMOTED)
        .as_ref()
        .and_then(|m| m.get(&(*target, *relay)))
        .is_some_and(|at| now.saturating_duration_since(*at) < DEMOTE_FOR)
}

/// A dial's addresses in plan order ([`P2pDialSet::dial_addrs`]), after what
/// this node learned of the relays: a circuit through a relay that turned
/// this node away as a non-member (`not_member`, for every target) is left
/// out; one through a relay the target held no reservation on lately
/// (`demoted`) goes last; the others go by their relay's learned `term`
/// ([`rank_circuits`]; all 0 while learning is off). The order is kept
/// otherwise, and a direct address is never touched.
fn order_dial(
    addrs: Vec<Multiaddr>,
    not_member: impl Fn(&PeerId) -> bool,
    demoted: impl Fn(&PeerId) -> bool,
    term: impl Fn(&PeerId) -> i64,
) -> Vec<Multiaddr> {
    let (mut first, mut last) = (Vec::new(), Vec::new());
    for addr in addrs {
        match raven_swarm::diag::circuit_relay(&addr) {
            Some(relay) if not_member(&relay) => {}
            Some(relay) if demoted(&relay) => last.push(addr),
            _ => first.push(addr),
        }
    }
    rank_circuits(&mut first, term);
    first.extend(last);
    first
}

/// Learning connectivity (Phase 6a, design §6): the circuits of `addrs` by
/// their relay's `term`, highest first, in the places circuits hold (a
/// direct address keeps its place), each relay's first circuit still before
/// any relay's fallback ([`P2pDialSet::dial_addrs`]). Order only, and
/// stable: with no term other than 0 nothing moves.
fn rank_circuits(addrs: &mut [Multiaddr], term: impl Fn(&PeerId) -> i64) {
    let mut firsts: Vec<PeerId> = Vec::new();
    let mut places: Vec<usize> = Vec::new();
    let mut circuits: Vec<(bool, i64, Multiaddr)> = Vec::new();
    for (place, addr) in addrs.iter().enumerate() {
        let Some(relay) = raven_swarm::diag::circuit_relay(addr) else {
            continue;
        };
        let fallback = firsts.contains(&relay);
        if !fallback {
            firsts.push(relay);
        }
        places.push(place);
        circuits.push((fallback, term(&relay), addr.clone()));
    }
    if circuits.iter().all(|(_, t, _)| *t == 0) {
        return;
    }
    circuits.sort_by_key(|(fallback, t, _)| (*fallback, std::cmp::Reverse(*t)));
    for (place, (_, _, addr)) in places.into_iter().zip(circuits) {
        addrs[place] = addr;
    }
}

/// Dial `multiaddr` (a p2p dial string ending in the target's PeerId, see
/// `raven_core::p2p_route::parse_p2p_dial`), run the Raven link expecting
/// `expected_pub_hex`, send `frames`, collect the replies. Verified contacts
/// only; nothing is dialled otherwise.
pub(crate) async fn dial(
    data_dir: &Path,
    multiaddr: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    dial_with_path(data_dir, multiaddr, expected_pub_hex, frames)
        .await
        .map(|(replies, _)| replies)
}

/// What the book says about `expected`, when a p2p dial may go to it: a
/// current, unblocked ([`raven_core::outbox::contact_admission`], as the
/// outbox checks before it plans a route) and verified contact. The dial
/// admits whom it connects to into our own peer gate, so a blocked contact
/// is refused here, before anything is dialled.
fn dial_contact(
    data_dir: &Path,
    expected: &[u8; 32],
) -> Result<Option<raven_core::outbox::ContactRoutes>, String> {
    use raven_core::outbox::ContactAdmission;
    let contact = match raven_core::outbox::contact_admission(data_dir, expected) {
        ContactAdmission::Allowed(contact) => Some(contact),
        ContactAdmission::NotContact => None,
        ContactAdmission::Blocked => {
            // "blocked peer": what the outbox files it as (the link's own
            // refusal reads the same).
            return Err(format!(
                "{}: blocked peer, or the block list cannot be read; nothing was dialled",
                crate::outbox::code::CONTACT_BLOCKED
            ));
        }
        ContactAdmission::Unreadable => {
            return Err(format!(
                "{}: the contact book or the block list cannot be read; nothing was dialled",
                crate::outbox::code::CONTACTS_UNREADABLE
            ))
        }
    };
    let pinned = contact.as_ref().is_some_and(|c| c.pinned);
    if !carrier_allowed_for_contact(OutboxCarrier::P2p, pinned) {
        return Err(format!(
            "{}: p2p delivery needs a verified contact (fingerprint pinned); nothing was dialled",
            raven_core::CONTACT_NOT_VERIFIED
        ));
    }
    Ok(contact)
}

/// Where a dial of a checked contact ([`dial_contact`]) may go.
struct DialPlan {
    /// Its book's PeerId and `via=` merged with what its route hints said
    /// ([`raven_core::outbox::with_learned_routes`], [`P2pDialSet::merge`]).
    set: Option<P2pDialSet>,
    /// This node hides its IP from it (D4,
    /// [`raven_core::outbox::may_share_ip`]): circuits only, through the
    /// relays this node holds itself (`held`).
    hide_ip: bool,
    /// The set's PeerId is a learned one no p2p link has proved yet.
    unproven: bool,
    /// Phase 4 PeerId rotation: the set under each PeerId the contact is
    /// dialled under now, in order, at most 2
    /// ([`raven_core::outbox::rotated_dial_peer_ids`], [`rotated_set`]);
    /// empty while its gate is closed or the contact is dialled as in
    /// Phase 1.
    rotated: Vec<P2pDialSet>,
}

/// The relays the running host holds a slot for (set by hand or picked
/// from an offer, reserved or not), at the addresses its slots name them
/// by: this node dials them there anyway, so their operators already see
/// its IP, and nobody else does. Empty while no host runs.
fn held_relays() -> Vec<ViaAddr> {
    let mut out: Vec<ViaAddr> = Vec::new();
    let status = lock(&STATUS);
    for text in status.iter().flat_map(|s| s.relays.iter()) {
        if let Ok(via) = p2p_route::parse_via(text) {
            if !out.contains(&via) {
                out.push(via);
            }
        }
    }
    out
}

/// Blocking: [`dial_contact`], then everything known about reaching it.
/// `held`: [`held_relays`], the only relays (and the only addresses of
/// them) a dial to a contact this node hides its IP from may go through.
fn dial_plan(data_dir: &Path, expected: &[u8; 32], held: &[ViaAddr]) -> Result<DialPlan, String> {
    dial_plan_with(
        data_dir,
        expected,
        held,
        raven_core::peer_rotation_live_enabled(),
    )
}

/// [`dial_plan`] with the PeerId rotation gate as an argument.
fn dial_plan_with(
    data_dir: &Path,
    expected: &[u8; 32],
    held: &[ViaAddr],
    rotation_live: bool,
) -> Result<DialPlan, String> {
    let contact = dial_contact(data_dir, expected)?
        .map(|c| raven_core::outbox::with_learned_routes(data_dir, expected, c));
    let hide_ip = !raven_core::outbox::may_share_ip(data_dir, expected);
    let Some(contact) = contact else {
        return Ok(DialPlan {
            set: None,
            hide_ip,
            unproven: false,
            rotated: Vec::new(),
        });
    };
    let learned = contact.p2p_learned.as_deref();
    // The network a same-LAN address was learned on, checked only when the
    // hints named one (it probes the default routes).
    let here = learned
        .filter(|l| !l.local_direct.is_empty())
        .and_then(|_| raven_core::route_memory::egress_tag());
    let set = P2pDialSet::merge(
        contact.p2p.as_ref(),
        learned,
        |v| local_direct_ok(learned, here.as_deref(), v),
        hide_ip.then_some(held),
    );
    let ids = contact
        .p2p
        .as_ref()
        .and_then(|_| {
            raven_core::outbox::rotated_dial_ids(data_dir, expected, rotation_live, crate::now_ms())
        })
        .unwrap_or_default();
    let rotated = contact.p2p.as_ref().map_or(Vec::new(), |book| {
        ids.iter()
            .filter_map(|id| {
                rotated_set(book, learned, id, &ids, hide_ip.then_some(held), |v| {
                    local_direct_ok(learned, here.as_deref(), v)
                })
            })
            .collect()
    });
    Ok(DialPlan {
        set,
        hide_ip,
        unproven: contact.p2p.is_none() && learned.is_some_and(|l| !l.proven),
        rotated,
    })
}

/// Phase 4 PeerId rotation: the dial set of a rotating contact under
/// `peer_id`, one of `ids` (the PeerIds it is dialled under now). Its
/// relays (the book's `via=` and the ones its route hints named) serve
/// whichever PeerId it uses; its direct addresses end in a PeerId, so only
/// the ones named under `peer_id` itself are kept (route hints that named
/// `peer_id`). An address naming any PeerId of the contact (its book's, its
/// learned one, `ids`) is never taken for a relay.
fn rotated_set(
    book: &p2p_route::ContactP2p,
    learned: Option<&LearnedP2p>,
    peer_id: &str,
    ids: &[String],
    hide_ip: Option<&[ViaAddr]>,
    local_direct_ok: impl Fn(&ViaAddr) -> bool,
) -> Option<P2pDialSet> {
    let theirs = |p: &str| {
        p == book.peer_id || ids.iter().any(|i| i == p) || learned.is_some_and(|l| l.peer_id == p)
    };
    let book = p2p_route::ContactP2p {
        peer_id: peer_id.to_string(),
        via: book
            .via
            .iter()
            .filter(|v| !theirs(&v.peer_id))
            .cloned()
            .collect(),
    };
    let learned = learned.map(|l| {
        if l.peer_id == peer_id {
            l.clone()
        } else {
            LearnedP2p {
                peer_id: peer_id.to_string(),
                relays: l
                    .relays
                    .iter()
                    .filter(|v| !theirs(&v.peer_id))
                    .cloned()
                    .collect(),
                direct: Vec::new(),
                local_direct: Vec::new(),
                ..l.clone()
            }
        }
    });
    P2pDialSet::merge(Some(&book), learned.as_ref(), local_direct_ok, hide_ip)
}

/// A same-LAN address a contact's route hints named is dialled only on the
/// network it was learned on (`here`: this computer's
/// [`raven_core::route_memory::egress_tag`] now) and only while netwatch
/// does not place it off this computer's networks.
fn local_direct_ok(learned: Option<&LearnedP2p>, here: Option<&str>, via: &ViaAddr) -> bool {
    let learned_on = learned.and_then(|l| l.local_tag.as_deref());
    if learned_on.is_none() || learned_on != here {
        return false;
    }
    via.text
        .parse::<Multiaddr>()
        .ok()
        .and_then(|a| addr_ip(&a))
        .is_some_and(|ip| on_link(ip) != Some(false))
}

/// netwatch's view of this computer's networks ([`crate::netwatch::on_link`]).
fn on_link(ip: IpAddr) -> Option<bool> {
    #[cfg(any(unix, windows))]
    {
        crate::netwatch::on_link(ip)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = ip;
        None
    }
}

/// What a dial checked ([`dial_contact`]) and where it goes.
struct DialCheck {
    /// When the check began reading the files: a peer gate set read from
    /// then on is at least as new ([`GateHandle::admit_dial`]).
    checked_at: std::time::Instant,
    addrs: Vec<Multiaddr>,
    relays: Vec<PeerId>,
    /// How our own peer gate admits the target: CONTACT_HIDDEN for a
    /// contact this node hides its IP from or whose learned PeerId is not
    /// proven (no hole punching, no Identify), else CONTACT.
    class: PeerClass,
    /// Phase 4 PeerId rotation: the PeerId dialled instead of the target's
    /// (the first a rotating contact is dialled under, [`DialPlan::rotated`]);
    /// `None` dials the target's.
    peer: Option<PeerId>,
    /// Its second PeerId, tried only after the first was unreachable
    /// ([`P2P_UNREACHABLE`]) within the same [`DIAL_DEADLINE`].
    second: Option<DialAlt>,
}

/// Phase 4: after a connect that ended `connected`, is a rotating
/// contact's second PeerId tried? Only when the first was unreachable
/// ([`P2P_UNREACHABLE`]): a refusal (blocked, not verified, a hidden IP),
/// the deadline or success never moves on.
fn try_second_peer_id(connected: &Result<(), String>) -> bool {
    connected
        .as_ref()
        .is_err_and(|e| e.starts_with(P2P_UNREACHABLE))
}

/// A rotating contact's second PeerId and where it is dialled
/// ([`DialCheck::second`]).
struct DialAlt {
    peer: PeerId,
    addrs: Vec<Multiaddr>,
    relays: Vec<PeerId>,
}

impl DialCheck {
    /// Dial the second PeerId from now on ([`DialCheck::second`]): `None`
    /// when there is none, or none that is `want` (when given).
    fn take_second(&mut self, want: Option<PeerId>) -> Option<PeerId> {
        if want.is_some_and(|w| self.second.as_ref().is_none_or(|a| a.peer != w)) {
            return None;
        }
        let alt = self.second.take()?;
        self.addrs = alt.addrs;
        self.relays = alt.relays;
        self.peer = Some(alt.peer);
        Some(alt.peer)
    }
}

/// Check that `expected` may be dialled over p2p ([`dial_contact`]) and
/// resolve where `target` goes, by that check's card and route hints. A
/// direct address of a contact this node hides its IP from is refused
/// before anything is dialled, and so is a circuit to it through a relay
/// this node does not hold, or through one of its relays at an address its
/// slot does not name ([`held_relays`]: the contact may have named its own
/// host for our relay's PeerId).
async fn check_dial(
    data_dir: &Path,
    expected: [u8; 32],
    target: &P2pDialTarget,
) -> Result<DialCheck, String> {
    check_dial_held(data_dir, expected, target, held_relays()).await
}

/// [`check_dial`] with the relays this node holds as an argument.
async fn check_dial_held(
    data_dir: &Path,
    expected: [u8; 32],
    target: &P2pDialTarget,
    held: Vec<ViaAddr>,
) -> Result<DialCheck, String> {
    let dd = data_dir.to_path_buf();
    let checked_at = std::time::Instant::now();
    let hold = held.clone();
    let plan = blocking(move || dial_plan(&dd, &expected, &hold)).await?;
    check_from_plan(plan, target, &held, checked_at).await
}

/// [`check_dial_held`] once the plan is read.
async fn check_from_plan(
    plan: DialPlan,
    target: &P2pDialTarget,
    held: &[ViaAddr],
    checked_at: std::time::Instant,
) -> Result<DialCheck, String> {
    if plan.hide_ip {
        match target {
            P2pDialTarget::Direct { .. } => return Err(P2P_HIDDEN_DIRECT.to_string()),
            P2pDialTarget::Circuit { relay, .. } if !held.contains(relay) => {
                return Err(P2P_HIDDEN_RELAY.to_string())
            }
            _ => {}
        }
    }
    let set = plan.set.as_ref();
    let learned_target = plan.unproven && set.is_some_and(|s| s.peer_id == target.peer_id());
    let class = if plan.hide_ip || learned_target {
        PeerClass::CONTACT_HIDDEN
    } else {
        PeerClass::CONTACT
    };
    // The running host's forms: its WSS client, its proxy, restricted or not.
    let forms = DialForms::of_host();
    let resolve = |text: Vec<Multiaddr>| {
        resolve_dial(
            text,
            |a| forms.proxied(a),
            raven_core::p2p_local_candidates_enabled(),
            raven_core::route_hints::lab_loopback_relays(),
        )
    };
    // Phase 4: a rotating contact named by its book's PeerId is dialled
    // under the PeerIds its schedule names for now.
    let rotating = matches!(target, P2pDialTarget::Peer { .. })
        && set.is_some_and(|s| s.peer_id == target.peer_id())
        && !plan.rotated.is_empty();
    if rotating {
        let mut alts = Vec::new();
        for s in plan.rotated.iter().take(2) {
            let Ok(peer) = s.peer_id.parse::<PeerId>() else {
                continue;
            };
            let t = P2pDialTarget::Peer {
                peer_id: s.peer_id.clone(),
            };
            alts.push(DialAlt {
                peer,
                addrs: resolve(dial_addrs(&t, Some(s), &forms)?).await,
                relays: dial_relays(&t, Some(s)),
            });
        }
        let mut alts = alts.into_iter();
        if let Some(first) = alts.next() {
            return Ok(DialCheck {
                checked_at,
                addrs: first.addrs,
                relays: first.relays,
                class,
                peer: Some(first.peer),
                second: alts.next(),
            });
        }
    }
    let addrs = resolve(dial_addrs(target, set, &forms)?).await;
    Ok(DialCheck {
        checked_at,
        addrs,
        relays: dial_relays(target, set),
        class,
        peer: None,
        second: None,
    })
}

/// Connect to `peer` under `check`'s admission. When the peer gate already
/// holds files read after that check that do not name the peer a contact (a
/// block, an unpin or a removal raced the dial, or only another contact
/// changed and the dial names a PeerId the card does not), the contact is
/// checked again ([`check_dial`], which refuses a blocked one) and the
/// connect repeated, at most [`MAX_DIAL_RECHECKS`] times. `check` ends as
/// the check the connect went with.
async fn connect_checked(
    host: &HostHandle,
    data_dir: &Path,
    expected: [u8; 32],
    target: &P2pDialTarget,
    peer: PeerId,
    check: &mut DialCheck,
    wait: &ConnectWait,
) -> Result<(), String> {
    let mut rechecks = 0;
    loop {
        let result = host
            .connect(
                peer,
                check.class,
                check.relays.clone(),
                check.addrs.clone(),
                check.checked_at,
                wait,
            )
            .await;
        match result {
            Err(e) if e == CHECK_AGAIN && rechecks < MAX_DIAL_RECHECKS => {
                rechecks += 1;
                *check = check_dial(data_dir, expected, target).await?;
                // A rotating contact's second PeerId stays the one dialled.
                if check.peer.is_some_and(|p| p != peer) {
                    check.take_second(Some(peer));
                }
            }
            other => return other,
        }
    }
}

/// [`dial`], plus how its link travelled ([`link_path`]; this node started
/// it). `None`: no connection was left to label when the link opened.
pub(crate) async fn dial_with_path(
    data_dir: &Path,
    multiaddr: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String> {
    dial_with_path_meta(
        data_dir,
        multiaddr,
        expected_pub_hex,
        frames,
        DialMeta::default(),
    )
    .await
}

/// [`dial_with_path`] with the worker's facts about it ([`DialMeta`]: a
/// resend of an object that went silent gives learning no reply-time
/// sample). Its waits are `crate::learning::waits`' (today's while learning
/// is off): the connect wait bounds each connect (direct, then circuits).
pub(crate) async fn dial_with_path_meta(
    data_dir: &Path,
    multiaddr: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
    meta: DialMeta,
) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String> {
    P2P_LINK.require_live()?;
    let expected = internet_direct::parse_pub_hex(expected_pub_hex)?;
    let target = p2p_route::parse_p2p_dial(multiaddr).map_err(|e| format!("p2p dial: {e}"))?;
    let mut check = check_dial(data_dir, expected, &target).await?;
    let mut peer: PeerId = match check.peer {
        Some(peer) => peer,
        None => target
            .peer_id()
            .parse()
            .map_err(|_| "p2p dial: invalid PeerId".to_string())?,
    };
    // Under a PeerId its schedule names, not the card's: say so (counts
    // only).
    if check
        .peer
        .is_some_and(|p| p.to_string() != target.peer_id())
    {
        note_epoch_dial(&expected, "current");
    }
    let host = current_host().ok_or_else(|| P2P_NOT_RUNNING.to_string())?;
    let started = Instant::now();
    let net = crate::learning::net();
    let waits = crate::learning::waits(&expected, OutboxCarrier::P2p);
    let mut progress = DialProgress::waiting(P2P_LINK.wire, &waits);
    progress.collector.set_race(meta.race);
    let connect_wait = progress.connect.clone();
    let mut path = None;
    let mut relay = None;
    // The relays a relayed link went through (Phase 6b R8).
    let mut through: Vec<PeerId> = Vec::new();
    let mut connect_failed = false;
    // The connect found a connection open already (an announcer's link, the
    // contact's, an earlier dial's): it answers at once and no dial runs. One
    // that is relayed: the generation the link rode it on, and the relays it
    // goes through (review 5a-3, [`stale_relayed_link`]).
    let mut reused = false;
    let mut riding: Option<(Arc<HostHandle>, Vec<PeerId>)> = None;
    // A probe's own bound (learning's exploration): it ends here, observed.
    let deadline = meta.deadline(DIAL_DEADLINE);
    let outcome = tokio::time::timeout(deadline, async {
        progress.stage = "connecting (direct, then through a relay)";
        let dialled_on = Arc::clone(&host);
        reused = host.connected(&peer);
        let mut connected = connect_checked(
            &host,
            data_dir,
            expected,
            &target,
            peer,
            &mut check,
            &connect_wait,
        )
        .await;
        // Phase 4: a rotating contact's second PeerId, only once the first
        // was unreachable.
        if try_second_peer_id(&connected) {
            if let Some(second) = check.take_second(None) {
                peer = second;
                note_epoch_dial(&expected, "other");
                reused = host.connected(&peer);
                connected = connect_checked(
                    &host,
                    data_dir,
                    expected,
                    &target,
                    peer,
                    &mut check,
                    &connect_wait,
                )
                .await;
            }
        }
        if let Err(e) = connected {
            connect_failed = true;
            return Err(e);
        }
        // A re-home may have replaced the endpoint while the connect waited
        // in the queue: the link opens on the generation that holds the
        // connection (an old generation's Control would wait for a swarm
        // that no longer runs). The connect itself went through the channel
        // every generation shares.
        let host = current_host().ok_or_else(|| P2P_NOT_RUNNING.to_string())?;
        // On another generation the connection is not the one seen open.
        reused &= Arc::ptr_eq(&host, &dialled_on);
        host.prefer_direct(peer).await;
        // Labelled once the relayed connections it closed are gone.
        path = host.path_to(&peer, true);
        if reused && path == Some(DeliveryPath::Relayed) {
            riding = Some((Arc::clone(&host), host.relays_to(&peer)));
        }
        // Learning connectivity (Phase 6a): the relay a relayed link rides.
        if path == Some(DeliveryPath::Relayed) && crate::learning::live_on() {
            relay = host.relay_of(&peer).map(|r| r.to_bytes());
        }
        // Phase 6b R8: every relay a relayed link went through.
        if path == Some(DeliveryPath::Relayed) {
            through = host.relays_to(&peer);
        }
        note_link_path(peer, path);
        let _link = host.link(peer);
        let control = host.control.clone();
        internet_direct::dial_session_on(
            P2P_LINK,
            data_dir,
            move || {
                let mut control = control.clone();
                async move {
                    control
                        .open_stream(peer, RAVEN_LINK_PROTOCOL)
                        .await
                        .map(|s| s.compat())
                        .map_err(open_stream_error)
                }
            },
            &expected,
            frames,
            Some(peer.to_base58()),
            &mut progress,
        )
        .await
    })
    .await;
    let relays = check.relays;
    // A link that rode a relayed connection open before it and got no
    // answer: the relays that connection goes through (review 5a-3).
    let stage = progress.stage;
    let stale = |e: &str| {
        riding.as_ref().and_then(|(link_host, via)| {
            let same_host = current_host().is_some_and(|h| Arc::ptr_eq(&h, link_host));
            (!via.is_empty() && stale_relayed_link(reused, path, same_host, stage, e))
                .then(|| via.clone())
        })
    };
    let timing = progress.timing();
    let expired = progress.expired();
    let dialled = progress.connecting_began();
    let replies = match outcome {
        Ok(Ok(())) => Ok(progress.collector.into_replies()),
        Ok(Err(e)) => {
            // Phase 6b: a link through a relay that broke inside, noted
            // against the relays it went through.
            if !connect_failed
                && path == Some(DeliveryPath::Relayed)
                && crate::security::link_broke(&e)
            {
                crate::security::relay_link_broken(broken_link_relays(&through, &relays));
            }
            let e = with_refusal_hint(e, &peer, &relays, started);
            // Why nobody answered, after the hint.
            Err(if connect_failed {
                explain_unreachable(data_dir, &expected, peer, e, started).await
            } else if let Some(via) = stale(&e) {
                explain_stale_link(data_dir, &expected, peer, via, e, started).await
            } else {
                e
            })
        }
        Err(_) => match progress
            .on_deadline("p2p", "the contact", deadline)
            .map_err(|e| with_refusal_hint(e, &peer, &relays, started))
        {
            Err(e) => Err(match stale(&e) {
                Some(via) => explain_stale_link(data_dir, &expected, peer, via, e, started).await,
                None => e,
            }),
            replies => replies,
        },
    };
    crate::clock_notes::dialled(&expected, frames, &replies);
    // Learning connectivity (Phase 6a, gated): Ok and Err alike.
    if dialled {
        crate::learning::observe_dial(
            &expected,
            OutboxCarrier::P2p,
            path,
            relay,
            frames,
            &replies,
            &timing,
            expired,
            meta,
            net,
        );
    }
    // Phase 6b S21: what a relayed link brought back, about its relay.
    if path == Some(DeliveryPath::Relayed) {
        let via: Vec<Vec<u8>> = through.iter().map(|r| r.to_bytes()).collect();
        crate::delivery_paths::relayed_dial(
            &expected,
            &via,
            frames,
            replies.as_ref().ok().map(Vec::as_slice),
        );
    }
    let replies = replies?;
    if let Some(path) = path {
        count_paths(|c| c.sent.add(path));
    }
    crate::delivery_paths::note(&expected, OutboxCarrier::P2p, path, frames, &replies);
    Ok((replies, path))
}

/// Phase 4: the PeerId kind each rotating contact was last dialled under
/// (`current`: the first its schedule names for now; `other`: the second):
/// a counts-only line whenever it changes, never the PeerId.
static EPOCH_DIALS: Mutex<Option<HashMap<[u8; 32], &'static str>>> = Mutex::new(None);

fn note_epoch_dial(contact: &[u8; 32], kind: &'static str) {
    let mut seen = lock(&EPOCH_DIALS);
    let map = seen.get_or_insert_with(HashMap::new);
    if map.len() >= MAX_LINK_KINDS && !map.contains_key(contact) {
        map.clear();
    }
    if map.insert(*contact, kind) != Some(kind) {
        eprintln!(
            "raven-node p2p: dialling a rotating contact under its scheduled network ID \
             (peer_epoch={kind})"
        );
    }
}

/// The path the last link to each peer used: a line is logged (counts only)
/// whenever it changes, e.g. after a DCUtR upgrade.
static LINK_KINDS: Mutex<Option<HashMap<PeerId, Option<DeliveryPath>>>> = Mutex::new(None);
const MAX_LINK_KINDS: usize = 256;

fn note_link_path(peer: PeerId, path: Option<DeliveryPath>) {
    let mut kinds = lock(&LINK_KINDS);
    let map = kinds.get_or_insert_with(HashMap::new);
    if map.len() >= MAX_LINK_KINDS && !map.contains_key(&peer) {
        map.clear();
    }
    if map.insert(peer, path) != Some(path) {
        eprintln!("{}", link_line(path));
    }
}

/// `raven-node p2p: link via a direct connection (<path>)` / `… via the
/// relay (relayed)`. The prefixes are what the harnesses grep (netns).
fn link_line(path: Option<DeliveryPath>) -> String {
    let via = match path {
        Some(DeliveryPath::Relayed) | None => "the relay",
        Some(_) => "a direct connection",
    };
    match path {
        Some(path) => format!("raven-node p2p: link via {via} ({})", path.label()),
        None => format!("raven-node p2p: link via {via}"),
    }
}

/// Raven links per path and DCUtR's verdicts since raven-node started
/// (IPC `Status` `paths`): a static, so a re-home keeps them.
static PATHS: Mutex<Option<P2pPathCounts>> = Mutex::new(None);

fn count_paths(f: impl FnOnce(&mut P2pPathCounts)) {
    f(lock(&PATHS).get_or_insert_with(P2pPathCounts::default));
}

fn path_counts() -> P2pPathCounts {
    lock(&PATHS).unwrap_or_default()
}

/// The outbox worker's `AttemptCtx::connected`: is this p2p route's contact
/// connected to this node right now (whoever opened the connection)? A dial
/// then rides that connection, so it goes first (deliberate reversal, dial
/// plan §2.3 step 1). `false` without a host and for other carriers; only a
/// short lock on the connection table, no call into the swarm loop.
pub(crate) fn route_connected(route: &OutboxRoute) -> bool {
    route_target(route).is_some_and(|peer| current_host().is_some_and(|h| h.connected(&peer)))
}

/// Did this p2p route's own PeerId turn a dial of ours away at once since
/// `since` ([`closed_at_once_since`]: its peer gate closed the connection)?
/// A relay's answer does not count, and neither does the hint text a dial
/// error carries. `false` for other carriers; only this process's p2p dials note
/// refusals.
pub(crate) fn target_refused_since(route: &OutboxRoute, since: std::time::Instant) -> bool {
    route_target(route).is_some_and(|peer| closed_at_once_since(&peer, Instant::from_std(since)))
}

/// The contact a p2p route dials: every form ends in its PeerId. `None` for
/// other carriers and unparsable routes.
fn route_target(route: &OutboxRoute) -> Option<PeerId> {
    if route.carrier != OutboxCarrier::P2p {
        return None;
    }
    let target = p2p_route::parse_p2p_dial(&route.dial).ok()?;
    target.peer_id().parse::<PeerId>().ok()
}

// ── Responder ───────────────────────────────────────────────────────────────

/// Admission key of a libp2p peer: a stable per-PeerId address in fd00::/8
/// (one /64 per PeerId), so the shared caps apply per peer. PeerIds are free,
/// so the global cap and pre-auth displacement still bound a flood; contacts
/// leave the pre-auth caps once their link authenticates.
fn admission_ip(peer: &PeerId) -> IpAddr {
    let bytes = peer.to_bytes();
    let mut o = [0u8; 16];
    o[0] = 0xfd;
    let tail = &bytes[bytes.len().saturating_sub(7)..];
    o[1..1 + tail.len()].copy_from_slice(tail);
    IpAddr::V6(Ipv6Addr::from(o))
}

/// Serve every inbound `/raven/link/1.0.0` stream: the Internet direct
/// responder (contact gate first) under the shared inbound limits.
async fn serve_streams(
    mut incoming: IncomingStreams,
    data_dir: PathBuf,
    identity: Arc<Identity>,
    host: Arc<HostHandle>,
) {
    let limits = netutil::PRODUCTION_INBOUND;
    let admission = Admission::new(limits);
    while let Some((peer, stream)) = incoming.next().await {
        let Some(mut slot) = admission.try_admit(admission_ip(&peer)) else {
            netutil::log_limited(
                &CAP_LOG,
                "p2p",
                format_args!("link cap reached; refused a link"),
            );
            continue;
        };
        let displaced = slot.displaced();
        let auth = slot.auth_flag();
        let (dd, id, host) = (data_dir.clone(), Arc::clone(&identity), Arc::clone(&host));
        tokio::spawn(async move {
            let _link = host.link(peer);
            // The peer started this link.
            let path = host.path_to(&peer, false);
            let work = async {
                P2P_LINK.require_live()?;
                internet_direct::serve_inbound_on(
                    P2P_LINK,
                    dd,
                    id,
                    stream.compat(),
                    limits,
                    &mut slot,
                    Some(peer.to_base58()),
                    None,
                    None,
                )
                .await
            };
            tokio::select! {
                done = tokio::time::timeout(limits.lifetime, work) => match done {
                    Ok(Ok(())) => {
                        if let Some(path) = path {
                            count_paths(|c| c.received.add(path));
                        }
                    }
                    Ok(Err(e)) => {
                        // Before the link knew whom it served: about the
                        // source the admission keys it by (Phase 6b S3).
                        if !auth.load(Ordering::Relaxed) {
                            crate::security::inbound_refused(
                                admission_ip(&peer),
                                OutboxCarrier::P2p,
                                &e,
                            );
                        }
                        netutil::log_inbound_failure(
                            "p2p inbound",
                            format_args!("from {}: {e}", netutil::link_tag(&peer.to_bytes())),
                        )
                    }
                    Err(_) => netutil::log_inbound_failure(
                        "p2p inbound",
                        format_args!(
                            "from {}: connection lifetime exceeded",
                            netutil::link_tag(&peer.to_bytes())
                        ),
                    ),
                },
                () = displaced.notified() => netutil::log_inbound_failure(
                    "p2p inbound",
                    format_args!(
                        "from {}: unauthenticated link displaced by a newcomer",
                        netutil::link_tag(&peer.to_bytes())
                    ),
                ),
            }
        });
    }
}

// ── The host task ────────────────────────────────────────────────────────────

/// One configured relay ([`relay_slots`]): its addresses as named (one, or
/// two of one relay, TCP 7423 and its TCP 443 fallback, in card order; any
/// may be `/dns*`), the forms they are dialled at, the addresses those
/// resolved to last, the one tried next, and the reservation's state.
struct RelaySlot {
    /// The relay: what the slot is found by ([`Command::Resolved`]).
    peer: PeerId,
    /// Each address as configured (canonical `via=` text), and parsed.
    texts: Vec<String>,
    named: Vec<Multiaddr>,
    /// The forms each address is dialled at (RWS1 §2.3,
    /// [`DialForms::relay`]), in the order of `texts`: planned again before
    /// every attempt ([`Self::plan_forms`]), as the WSS gate and the proxy
    /// decide them. Before the first plan, `named`.
    forms: Vec<Multiaddr>,
    /// What `forms` resolved to, in order ([`resolve_slot`]);
    /// [`Self::rotate`] walks it, so a refused or lost reservation is asked
    /// again on the next form or address, the fallback after the first.
    resolved: Vec<Multiaddr>,
    next: usize,
    listener: Option<ListenerId>,
    /// A re-homed endpoint's own connection to the relay, dialled from a
    /// new local port: the reservation is asked for on it once it is up
    /// ([`Host::request_reservation`]).
    connecting: Option<ConnectionId>,
    active: bool,
    resolving: bool,
    attempt: u32,
    retry_at: Option<Instant>,
    /// When the reservation was accepted (while `active`), or lost (after
    /// one was held in this endpoint).
    since: Option<Instant>,
    /// The last successful ping on a connection to the relay: when, and its
    /// round trip.
    ping: Option<(Instant, Duration)>,
    /// Set by hand, or picked from a contact's offer ([`Host::apply_selection`]).
    source: Source,
    /// When it was picked, or this endpoint generation started: a new
    /// generation starts every loss clock over, so our own sleep or a
    /// network change never counts against a relay.
    selected_at: Instant,
    /// How the reservation asked or held travels (`resolved[next]`, set
    /// when it is asked and again when it is accepted); `None` while there
    /// is neither. [`RelayPath::WssProxy`] makes the network restricted
    /// ([`Host::note_restricted`]).
    path: Option<RelayPath>,
}

/// How a relay slot's reservation travels (IPC `relay_paths`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelayPath {
    Tcp,
    Quic,
    /// WebSocket over TLS (RWS1), straight to the relay.
    Wss,
    /// WebSocket over TLS through the HTTPS proxy.
    WssProxy,
}

impl RelayPath {
    /// The path of a dial of `addr`; `proxy`: the host's, which a WSS form
    /// may go through ([`proxied`]).
    fn of(addr: &Multiaddr, proxy: &ProxySource) -> Self {
        if addr.iter().any(|p| matches!(p, Protocol::QuicV1)) {
            Self::Quic
        } else if !is_wss(addr) {
            Self::Tcp
        } else if proxied(proxy, addr) {
            Self::WssProxy
        } else {
            Self::Wss
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Quic => "quic",
            Self::Wss => "wss",
            Self::WssProxy => "wss-proxy",
        }
    }
}

/// The forms a relay named by `texts` is dialled at, in their order, each
/// once: a `via=` text at [`DialForms::relay`]'s, anything else as it is.
fn relay_forms(texts: &[String], dial: &DialForms) -> Vec<Multiaddr> {
    let vias: Vec<ViaAddr> = texts
        .iter()
        .filter_map(|t| p2p_route::parse_via(t).ok())
        .collect();
    dial.note_held(&vias);
    let mut forms: Vec<Multiaddr> = Vec::new();
    for text in texts {
        let planned = match p2p_route::parse_via(text) {
            Ok(via) => dial.relay(&via),
            Err(_) => vec![text.clone()],
        };
        for form in planned.iter().filter_map(|f| f.parse::<Multiaddr>().ok()) {
            if !forms.contains(&form) {
                forms.push(form);
            }
        }
    }
    forms
}

fn is_dns(addr: &Multiaddr) -> bool {
    matches!(
        addr.iter().next(),
        Some(Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_))
    )
}

impl RelaySlot {
    /// The slot of `relay`, named by `texts` (canonical `via=` text, at most
    /// [`p2p_route::MAX_VIA`] for a relay set by hand, an offer's at most
    /// four), nothing asked yet.
    fn new(
        relay: PeerId,
        texts: Vec<String>,
        source: Source,
        now: Instant,
    ) -> Result<Self, String> {
        let named = texts
            .iter()
            .map(|t| t.parse().map_err(|e| format!("p2p relay: {e}")))
            .collect::<Result<Vec<Multiaddr>, _>>()?;
        Ok(Self {
            peer: relay,
            texts,
            forms: named.clone(),
            named,
            resolved: Vec::new(),
            next: 0,
            listener: None,
            connecting: None,
            active: false,
            resolving: false,
            attempt: 0,
            retry_at: None,
            since: None,
            ping: None,
            source,
            selected_at: now,
            path: None,
        })
    }

    /// Plan the forms of every address afresh ([`relay_forms`]).
    fn plan_forms(&mut self, dial: &DialForms) {
        self.forms = relay_forms(&self.texts, dial);
    }

    /// It accepted a reservation in this endpoint generation.
    fn ever_reserved(&self) -> bool {
        self.since.is_some()
    }

    /// Since when it has been without the reservation it held in this
    /// endpoint generation (`None` while it holds one, or held none yet).
    fn lost_since(&self) -> Option<Instant> {
        self.since.filter(|_| !self.active)
    }

    /// An offer named it at other addresses (the relay moved): the slot
    /// takes them in place, its next try on the first. A reservation held
    /// stays; an idle slot is tried at once ([`Self::nudge`]).
    fn renamed(&mut self, texts: &[String], now: Instant) -> Result<(), String> {
        let named = texts
            .iter()
            .map(|t| t.parse().map_err(|e| format!("p2p relay: {e}")))
            .collect::<Result<Vec<Multiaddr>, _>>()?;
        self.texts = texts.to_vec();
        self.resolved = if named.iter().any(is_dns) {
            Vec::new()
        } else {
            named.clone()
        };
        self.forms = named.clone();
        self.named = named;
        self.next = 0;
        if !self.active {
            self.nudge(now);
        }
        Ok(())
    }

    fn arm_retry(&mut self, now: Instant) {
        let delay = reconnect_delay(self.attempt, retry_jitter());
        self.attempt = self.attempt.saturating_add(1);
        self.retry_at = Some(now + delay);
    }

    /// The next resolved address, in turn (of every address the relay is
    /// named by).
    fn rotate(&mut self) {
        if !self.resolved.is_empty() {
            self.next = (self.next + 1) % self.resolved.len();
        }
    }

    /// Some address is a `/dns*` name, resolved before every attempt.
    fn named_by_dns(&self) -> bool {
        self.named.iter().any(is_dns)
    }

    /// The address in use: the one the reservation is asked or held on
    /// (`resolved[next]`, a name's resolved address); before anything was
    /// resolved the first as configured, and while a name is looked up that
    /// name.
    fn in_use(&self) -> String {
        if !self.resolving {
            if let Some(addr) = self.resolved.get(self.next) {
                return addr.to_string();
            }
        }
        let named = if self.resolving {
            self.named.iter().position(is_dns).unwrap_or(0)
        } else {
            0
        };
        self.texts.get(named).cloned().unwrap_or_default()
    }

    /// Held a reservation at `now`, or lost it no more than
    /// [`CLOSE_AFTER_LOSS`] before.
    fn reserved_until(&self, now: Instant) -> bool {
        self.active
            || self
                .since
                .is_some_and(|t| now.saturating_duration_since(t) <= CLOSE_AFTER_LOSS)
    }

    /// Networks were added: an idle slot (no reservation and nothing in
    /// flight, so waiting out its backoff) is due now, its backoff started
    /// over. The tick starts it.
    fn nudge(&mut self, now: Instant) {
        if !self.active && !self.resolving && self.listener.is_none() && self.connecting.is_none() {
            self.attempt = 0;
            self.retry_at = Some(now);
        }
    }

    /// The relay's `Status` row at `now`; `check`: its AutoNAT check of us
    /// ([`NatTally::server_check`]).
    fn health(&self, now: Instant, check: &str) -> RelayHealth {
        let ago = |t: Instant| now.saturating_duration_since(t).as_secs();
        let state = if self.active {
            "reserved"
        } else if self.resolving {
            "resolving"
        } else if self.listener.is_some() || self.connecting.is_some() {
            "asking"
        } else if self.retry_at.is_some() {
            "retrying"
        } else {
            "waiting"
        };
        let held_or_lost = matches!(state, "reserved" | "retrying");
        RelayHealth {
            relay: self.in_use(),
            state: state.into(),
            for_s: self.since.filter(|_| held_or_lost).map(ago),
            ping_ms: self
                .ping
                .map(|(_, rtt)| u32::try_from(rtt.as_millis()).unwrap_or(u32::MAX)),
            ping_age_s: self.ping.map(|(at, _)| ago(at)),
            retry_in_s: self
                .retry_at
                .filter(|_| state == "retrying")
                .map(|t| t.saturating_duration_since(now).as_secs()),
            tries: self.attempt,
            check: check.into(),
            source: match self.source {
                Source::Manual => "manual",
                Source::Offer { .. } => "offer",
            }
            .into(),
            operator_pub_hex: self.source.operator().unwrap_or_default().into(),
        }
    }
}

/// One slot per relay, not per address: `groups` is
/// [`p2p_route::group_relays`] of the configured relays, so two addresses of
/// one relay (TCP 7423 and TCP 443) are one slot whose second address is the
/// fallback. At most [`p2p_route::MAX_VIA`] relays; one that is this node
/// itself (`me`) is skipped.
fn relay_slots(groups: Vec<(String, Vec<ViaAddr>)>, me: PeerId) -> Result<Vec<RelaySlot>, String> {
    let now = Instant::now();
    let mut slots = Vec::new();
    for (peer, vias) in groups.into_iter().take(p2p_route::MAX_VIA) {
        let relay: PeerId = peer
            .parse()
            .map_err(|_| "p2p relay: invalid PeerId".to_string())?;
        if relay == me {
            continue;
        }
        let texts = vias
            .into_iter()
            .take(p2p_route::MAX_VIA)
            .map(|v| v.text)
            .collect();
        slots.push(RelaySlot::new(relay, texts, Source::Manual, now)?);
    }
    Ok(slots)
}

/// The endpoint's AutoNAT v2 servers: each relay slot's relay, once (a relay
/// named by two addresses is one server, never two clients), at most two.
fn autonat_servers(slots: &[RelaySlot]) -> [Option<PeerId>; 2] {
    let mut servers = [None; 2];
    let mut peers: Vec<PeerId> = Vec::new();
    for slot in slots {
        if !peers.contains(&slot.peer) {
            peers.push(slot.peer);
        }
    }
    for (server, peer) in servers.iter_mut().zip(peers) {
        *server = Some(peer);
    }
    servers
}

/// A listen address and, while it cannot be opened (a busy port, or a
/// specific address on no interface now), when it is tried again.
struct ListenSlot {
    addr: Multiaddr,
    /// The swarm's listener while open (removed first on a re-home or a
    /// shutdown).
    listener: Option<ListenerId>,
    open: bool,
    failures: u32,
    /// The next try (`None`: untried, open, or `waiting`).
    retry_at: Option<Instant>,
    /// In a re-homed generation: until then a busy port is retried quietly
    /// ([`busy_wait`]).
    grace_until: Option<Instant>,
    /// It was open in an earlier generation ([`HostSeed::listens_opened`]):
    /// on no interface now, its address went away with the network that
    /// re-homed the endpoint, and it is retried until it is back.
    opened_before: bool,
    /// Tries left for an address never opened that is on no interface
    /// ([`ABSENT_TRIES`]).
    absent_tries: u32,
    /// Such an address after its tries: tried again only when networks are
    /// added ([`Self::nudge`]) or the endpoint is re-homed.
    waiting: bool,
}

impl ListenSlot {
    fn new(addr: Multiaddr, grace_until: Option<Instant>, opened_before: bool) -> Self {
        Self {
            addr,
            listener: None,
            open: false,
            failures: 0,
            retry_at: None,
            grace_until,
            opened_before,
            absent_tries: ABSENT_TRIES,
            waiting: false,
        }
    }

    /// Whether the next round tries it.
    fn due(&self, now: Instant) -> bool {
        !self.open && !self.waiting && self.retry_at.is_none_or(|t| t <= now)
    }

    /// Networks were added: a listen address waiting for its next try (its
    /// address was on no interface, or its port was busy) is due now, at
    /// the next tick, and an absent one gets its [`ABSENT_TRIES`] again.
    /// Its failures stay: no second log line.
    fn nudge(&mut self, now: Instant) {
        if !self.open && (self.waiting || self.retry_at.is_some()) {
            self.waiting = false;
            self.absent_tries = ABSENT_TRIES;
            self.retry_at = Some(now);
        }
    }

    /// Opening it failed (`probe`): when it is tried again, logged once (its
    /// port only). `false`: never, it is dropped (one "skipped" line).
    /// - A busy port: retried with backoff.
    /// - An address on no interface: one that was open before (it went away
    ///   with a network) is retried like a busy port until it is back; one
    ///   never opened (not up yet at start, or a mistyped address) is tried
    ///   [`ABSENT_TRIES`] times, then waits for networks to be added. A
    ///   wildcard of an address family this host lacks never comes back.
    /// - An address that can never be bound as asked (no such address
    ///   family, a port this process may not bind, an invalid address):
    ///   dropped. A port below 1024 that needs a privilege is said so (the
    ///   endpoint never asks for one unless told to).
    fn failed(&mut self, probe: ListenProbe, now: Instant) -> bool {
        let label = listen_port_label(&self.addr);
        match probe {
            ListenProbe::Busy => {
                let (delay, failed) = busy_wait(self.failures, self.grace_until, now);
                if failed {
                    if self.failures == 0 {
                        eprintln!(
                            "p2p failed: listen port {label} is already in use by another \
                             program (another raven-node?); it is not opened and is retried"
                        );
                    }
                    self.failures = self.failures.saturating_add(1);
                }
                self.retry_at = Some(now + delay);
                true
            }
            ListenProbe::Absent if listen_slot_can_return(&self.addr) => {
                if self.failures == 0 {
                    eprintln!(
                        "p2p failed: listen port {label} cannot be opened now (its address is \
                         on no interface of this host); it is opened once this host has it"
                    );
                }
                if self.opened_before {
                    let (delay, _) = busy_wait(self.failures, None, now);
                    self.retry_at = Some(now + delay);
                } else if self.absent_tries > 0 {
                    let tried = ABSENT_TRIES - self.absent_tries;
                    self.absent_tries -= 1;
                    self.retry_at = Some(now + LISTEN_RETRY_MIN.saturating_mul(1u32 << tried));
                } else {
                    self.retry_at = None;
                    self.waiting = true;
                }
                self.failures = self.failures.saturating_add(1);
                true
            }
            ListenProbe::Absent | ListenProbe::Unavailable => {
                eprintln!(
                    "p2p failed: listen port {label} cannot be opened on this host (no such \
                     address family or interface, a port this process may not use, or an \
                     invalid address); skipped"
                );
                false
            }
            ListenProbe::Privileged => {
                eprintln!(
                    "p2p failed: listen port {label} cannot be opened on this host (a port this \
                     process may not use: ports below 1024 need a privilege); skipped"
                );
                false
            }
        }
    }
}

/// Whether a listen address that cannot be bound here may become bindable
/// later: a specific address may (its interface, a VPN's or a second NIC's,
/// comes back); a wildcard of an address family this host lacks does not.
fn listen_slot_can_return(addr: &Multiaddr) -> bool {
    addr_ip(addr).is_some_and(|ip| !ip.is_unspecified())
}

/// Until when a generation's busy listen port is retried quietly
/// ([`busy_wait`]): one built for a re-home, or the first after an unlock.
fn listen_grace(rehomed: bool, unlocked_lately: bool, now: Instant) -> Option<Instant> {
    (rehomed || unlocked_lately).then(|| now + REBIND_GRACE)
}

/// How long a busy listen port waits before the next try, and whether that
/// counts as a failure (logged, backoff doubled). Right after a re-home our
/// own old endpoint may still hold the port (quinn drains its socket for a
/// moment): it is retried quickly, with no failure and no "another program"
/// line.
fn busy_wait(failures: u32, grace_until: Option<Instant>, now: Instant) -> (Duration, bool) {
    if grace_until.is_some_and(|t| now < t) {
        return (REBIND_RETRY, false);
    }
    let delay = LISTEN_RETRY_MIN
        .saturating_mul(1u32 << failures.min(5))
        .min(LISTEN_RETRY_MAX);
    (delay, true)
}

/// A connection that died because nothing came back for too long: a QUIC
/// idle timeout, or a socket timeout. Not a close by either side (a relay
/// that restarts or turns us away closes, it does not go silent).
/// libp2p-quic wraps quinn's error in an opaque type whose text is all
/// there is ("timed out"); `a_silent_quic_relay_path_is_reported_before_any_ping_fails`
/// pins it against the real transport.
fn closed_by_silence(cause: &ConnectionError) -> bool {
    let ConnectionError::IO(error) = cause else {
        return false;
    };
    if error.kind() == std::io::ErrorKind::TimedOut {
        return true;
    }
    let mut next: Option<&(dyn std::error::Error + 'static)> = error
        .get_ref()
        .map(|e| e as &(dyn std::error::Error + 'static));
    while let Some(e) = next {
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::TimedOut {
                return true;
            }
        }
        if let Some(quic::Error::Connection(c)) = e.downcast_ref() {
            return c.to_string() == "timed out";
        }
        next = e.source();
    }
    false
}

/// A dial refused because the local address and port it was bound to are
/// still in use with that remote ([`Host::redial_from_new_port`]), however
/// deep libp2p's transport layers wrapped it. An `io::Error`'s own `source`
/// skips the error it wraps (followed by `get_ref` instead), and libp2p's
/// `Either` layers are as transparent: their `source` is their content's,
/// so the walk stops short of the socket's error. Its debug text still
/// names the kind; `a_contact_dial_whose_4_tuple_is_still_held_goes_from_a_new_port`
/// pins that against the real transport.
fn addr_in_use(error: &std::io::Error) -> bool {
    use std::io::ErrorKind::AddrInUse;
    let mut next: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(e) = next {
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            if io.kind() == AddrInUse {
                return true;
            }
            if let Some(inner) = io.get_ref() {
                next = Some(inner);
                continue;
            }
        }
        next = e.source();
    }
    format!("{error:?}").contains(&format!("kind: {AddrInUse:?}"))
}

/// Tells our own path dying from one relay dying: every relay that held a
/// reservation when the first of them failed its pings has failed them
/// within [`RELAY_LOSS_WINDOW`], and no connection answered a ping since. A
/// relay connection that died by silence ([`closed_by_silence`], a QUIC idle
/// timeout) counts as failed pings. While a direct connection to anyone else
/// is open (a contact, a relay that held no reservation), it gets one ping
/// round to answer first: one that does says our path works and only the
/// relays died (with a single relay, the usual case, nothing else tells the
/// two apart). At most one report per window. Pure: the caller passes the
/// time.
#[derive(Debug, Default)]
struct RelayLoss {
    /// The first failure of the current window…
    first: Option<Instant>,
    /// …the relays that held a reservation then, and those of them that
    /// failed since.
    expected: HashSet<PeerId>,
    lost: HashSet<PeerId>,
    /// A ping succeeded on some connection after the first failure.
    answered: bool,
    /// Every expected relay failed while another connection was open: report
    /// at this time unless a ping is answered first ([`Self::due`]).
    pending: Option<Instant>,
    last_report: Option<Instant>,
}

impl RelayLoss {
    /// A ping succeeded (any connection).
    fn answered(&mut self) {
        if self.first.is_some() {
            self.answered = true;
        }
    }

    /// The connection to `peer` died by ping (or by silence); `reserved`:
    /// the relays holding a reservation now; `answer_within`: one ping round
    /// while a direct connection to anyone else is open, `None` when none
    /// is. `true`: report it now (every relay went silent).
    fn lost(
        &mut self,
        peer: PeerId,
        reserved: &HashSet<PeerId>,
        answer_within: Option<Duration>,
        now: Instant,
    ) -> bool {
        let fresh = self
            .first
            .is_none_or(|t| now.saturating_duration_since(t) > RELAY_LOSS_WINDOW);
        if fresh {
            if !reserved.contains(&peer) {
                return false;
            }
            *self = RelayLoss {
                first: Some(now),
                expected: reserved.clone(),
                last_report: self.last_report,
                ..RelayLoss::default()
            };
        }
        if !self.expected.contains(&peer) {
            return false;
        }
        self.lost.insert(peer);
        if self.answered || !self.expected.is_subset(&self.lost) {
            return false;
        }
        if let Some(wait) = answer_within {
            self.pending.get_or_insert(now + wait);
            return false;
        }
        self.report(now)
    }

    /// Every tick: `true` when a loss that waited for the other connections
    /// ([`Self::lost`]) is to be reported now (none of them answered).
    fn due(&mut self, now: Instant) -> bool {
        match self.pending {
            Some(_) if self.answered => {
                self.pending = None;
                false
            }
            Some(at) if now >= at => {
                self.pending = None;
                self.report(now)
            }
            _ => false,
        }
    }

    /// At most one report per window.
    fn report(&mut self, now: Instant) -> bool {
        let quiet = self
            .last_report
            .is_none_or(|t| now.saturating_duration_since(t) >= RELAY_LOSS_WINDOW);
        if quiet {
            self.last_report = Some(now);
        }
        quiet
    }
}

/// `RAVEN_LAB_P2P_PING=<interval s>,<timeout s>`: a faster ping, so a
/// harness sees every relay go silent in seconds (C13). Debug builds only
/// (independent of `RAVEN_LAB_TEST_A`); release builds never read it.
fn lab_ping() -> Option<(Duration, Duration)> {
    if !cfg!(debug_assertions) {
        return None;
    }
    parse_lab_ping(&std::env::var("RAVEN_LAB_P2P_PING").ok()?)
}

/// `<interval>,<timeout>` in whole seconds, 1 <= interval <= 60 and
/// 1 <= timeout <= interval; anything else is `None`.
fn parse_lab_ping(v: &str) -> Option<(Duration, Duration)> {
    let (interval, timeout) = v.split_once(',')?;
    let interval: u64 = interval.trim().parse().ok()?;
    let timeout: u64 = timeout.trim().parse().ok()?;
    ((1..=60).contains(&interval) && (1..=interval).contains(&timeout))
        .then(|| (Duration::from_secs(interval), Duration::from_secs(timeout)))
}

struct RelayRole {
    guard: RelayGuard,
    open: bool,
    data_dir: PathBuf,
    circuits: u32,
    circuits_refused: u64,
    reservations_refused: u64,
    last_reload: Instant,
    advertiser: RelayAdvertiser,
}

/// The relays contacts offer, as read off the swarm loop
/// ([`load_offers`], [`Command::OffersLoaded`]).
#[derive(Clone, Debug)]
struct OffersLoad {
    /// The files, stamped before they were read (a change while they are
    /// read is read again).
    stamp: GateStamp,
    candidates: Vec<Candidate>,
    /// node_policy.json `relay_auto` (an unreadable policy: off).
    policy_on: bool,
}

/// Blocking: the relays verified contacts offer this node
/// ([`raven_core::learned_routes::offers`]) as candidates
/// ([`relay_select::candidates`]), never this node's own PeerId (`me`), its
/// own friend relay or a contact's own p2p PeerId; and whether node policy
/// lets automatic choice use them.
fn load_offers(data_dir: &Path, me: &PeerId) -> OffersLoad {
    let stamp = gate_stamp(data_dir);
    let now_ms = crate::now_ms();
    let policy_on =
        raven_core::node_policy::try_load_policy(data_dir).is_ok_and(|p| p.relay_auto_on());
    let offers = raven_core::learned_routes::offers(data_dir, now_ms);
    let mut standing: HashMap<&str, Operator> = HashMap::new();
    for (operator, ..) in &offers {
        standing
            .entry(operator.as_str())
            .or_insert_with(|| operator_standing(data_dir, operator));
    }
    let me = me.to_string();
    let own_relay = crate::friend_relay::own_relay_key(data_dir)
        .map(|key| p2p_route::peer_id_from_ed25519_public(&key));
    // A contact's own PeerId (the book's, or one a link proved) is no relay
    // key another contact may name.
    let contacts: Vec<String> = raven_core::outbox::p2p_gate_peers(data_dir)
        .unwrap_or_default()
        .into_iter()
        .filter(|p| !p.learned || p.proven)
        .flat_map(|p| p.peer_ids().cloned().collect::<Vec<_>>())
        .collect();
    let mut own = vec![me.as_str()];
    own.extend(own_relay.as_deref());
    own.extend(contacts.iter().map(String::as_str));
    let candidates = relay_select::candidates(
        &offers,
        |operator| {
            standing
                .get(operator)
                .copied()
                .unwrap_or(Operator::Unverified)
        },
        &own,
    );
    OffersLoad {
        stamp,
        candidates,
        policy_on,
    }
}

/// What this node says now of the contact (device key `pub_hex`) that
/// offered a relay: verified (pinned, unblocked) and shown our IP, verified
/// but hidden from (D4: its relay would see our IP), or neither.
fn operator_standing(data_dir: &Path, pub_hex: &str) -> Operator {
    use raven_core::outbox::{contact_admission, may_share_ip, ContactAdmission};
    let Some(key) = hex::decode(pub_hex)
        .ok()
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
    else {
        return Operator::Unverified;
    };
    match contact_admission(data_dir, &key) {
        ContactAdmission::Allowed(contact) if contact.pinned => {
            if may_share_ip(data_dir, &key) {
                Operator::Verified
            } else {
                Operator::IpHidden
            }
        }
        _ => Operator::Unverified,
    }
}

/// Automatic relay choice as the host keeps it across endpoint generations
/// ([`HostSeed::keep_auto`]): the offers, the memory and the relays picked.
#[derive(Clone, Debug)]
struct AutoRelays {
    /// [`P2pConfig::auto`] is set: the friend relay gate and route hints are
    /// live. Nothing here runs otherwise.
    live: bool,
    /// node_policy.json `relay_auto`, as last read with the offers.
    policy_on: bool,
    candidates: Vec<Candidate>,
    /// The files the candidates were read from (`None`: not read yet).
    stamp: Option<GateStamp>,
    /// A read is running ([`Host::poll_offers`]).
    loading: bool,
    mem: relay_select::RelayMemory,
    /// The relays automatic choice holds, in slot order: the slots after the
    /// manual ones in the next endpoint generation.
    picked: Vec<(ViaAddr, Source)>,
    /// The memory changed since it was written, and must be written at once
    /// (a change of the picked relays, a relay that turned us away).
    dirty: bool,
    urgent: bool,
    saved_at: Option<Instant>,
    /// A write is running (one at a time).
    saving: Arc<AtomicBool>,
    /// When "relay kept" was last logged.
    kept_logged: Option<Instant>,
    /// The standby relay last dialled as the proof that this node is online
    /// ([`relay_select::probe`]), and when: at most one per replace-after
    /// window.
    probe: Option<(PeerId, Instant)>,
}

impl AutoRelays {
    /// Nothing automatic: the Phase 1 host.
    fn off() -> Self {
        Self {
            live: false,
            policy_on: false,
            candidates: Vec::new(),
            stamp: None,
            loading: false,
            mem: relay_select::RelayMemory::default(),
            picked: Vec::new(),
            dirty: false,
            urgent: false,
            saved_at: None,
            saving: Arc::new(AtomicBool::new(false)),
            kept_logged: None,
            probe: None,
        }
    }

    /// Blocking: the memory and the offers in `data_dir` when `live`.
    fn load(data_dir: &Path, me: &PeerId, live: bool) -> Self {
        if !live {
            return Self::off();
        }
        let offers = load_offers(data_dir, me);
        Self {
            live,
            policy_on: offers.policy_on,
            candidates: offers.candidates,
            stamp: Some(offers.stamp),
            mem: relay_select::load_memory(data_dir),
            ..Self::off()
        }
    }

    /// Automatic choice is on: live, and node policy lets it.
    fn on(&self) -> bool {
        self.live && self.policy_on
    }

    /// The offer of `peer`, while one is held.
    fn offer_of(&self, peer: &str) -> Option<&Candidate> {
        self.candidates.iter().find(|c| c.via.peer_id == peer)
    }

    /// Every address `via`'s relay is offered at (`via` alone when its
    /// offer is gone).
    fn addrs_of(&self, via: &ViaAddr) -> Vec<String> {
        self.offer_of(&via.peer_id)
            .map_or_else(|| vec![via.text.clone()], |c| c.addrs.clone())
    }

    /// The memory changed; `urgent`: write it at once.
    fn mark(&mut self, urgent: bool) {
        self.dirty = true;
        self.urgent |= urgent;
    }

    /// A restart takes the relays it held again ([`relay_select::RelayMemory::selected`])
    /// while they are offered and usable, and fills the slots left:
    /// [`relay_select::select`] with those as fresh slots, offline (nothing
    /// is replaced). The picked relays are the first generation's.
    fn start(&mut self, me: &PeerId, manual: &[ViaAddr], now_ms: u64) {
        if !self.live {
            return;
        }
        let slots: Vec<SlotNow> = self
            .mem
            .selected
            .iter()
            .filter(|p| self.offer_of(p).is_some())
            .map(|p| SlotNow {
                peer_id: p.clone(),
                manual: false,
                active: false,
                lost_since_ms: None,
                selected_at_ms: now_ms,
                ever_reserved: false,
            })
            .collect();
        let me = me.to_string();
        let learned = learned_terms_of(self.candidates.iter().map(|c| c.via.peer_id.as_str()));
        let d = relay_select::select(&relay_select::Input {
            me: &me,
            manual,
            offers: &self.candidates,
            slots: &slots,
            mem: &self.mem,
            online: false,
            auto: self.on(),
            now_ms,
            max: p2p_route::MAX_VIA,
            t: relay_select::Timing::current(),
            learned: &learned,
        });
        if relay_select::commit(&mut self.mem, &d, now_ms) {
            self.mark(true);
        }
        self.picked = auto_relays(&d);
    }
}

/// The relays a decision picked from offers, in order.
fn auto_relays(d: &Decision) -> Vec<(ViaAddr, Source)> {
    d.relays
        .iter()
        .filter(|(_, source)| *source != Source::Manual)
        .cloned()
        .collect()
}

/// After the relays changed at `stale_since`, the endpoint's AutoNAT
/// clients (made per endpoint) still ask the old relays: re-home once no
/// Raven link was open for [`AUTONAT_IDLE`] since the change (`idle_since`:
/// since when none is), or [`AUTONAT_STALE_MAX`] after it anyway. A re-home
/// closes every connection, so it waits for a quiet minute.
fn autonat_rebind_due(
    stale_since: Option<Instant>,
    idle_since: Option<Instant>,
    now: Instant,
) -> bool {
    let Some(stale) = stale_since else {
        return false;
    };
    now.saturating_duration_since(stale) >= AUTONAT_STALE_MAX
        || idle_since
            .is_some_and(|idle| now.saturating_duration_since(idle.max(stale)) >= AUTONAT_IDLE)
}

struct Host {
    swarm: Swarm<EndpointBehaviour>,
    /// Endpoint generation: 0 at start, one more per re-home.
    gen: u64,
    commands: mpsc::Sender<Command>,
    data_dir: PathBuf,
    /// The peers this host admits ([`gate_files`]): made once per host start
    /// and shared by every endpoint generation.
    gate: GateHandle,
    /// The files as [`gate`](Self::gate) was last loaded from them.
    gate_stamp: GateStamp,
    /// A load is running ([`Host::poll_gate`]).
    gate_loading: bool,
    config: P2pConfig,
    source: String,
    slots: Vec<RelaySlot>,
    listens: Vec<ListenSlot>,
    role: Option<RelayRole>,
    pending: HashMap<PeerId, Vec<oneshot::Sender<Result<(), String>>>>,
    /// This generation's handle: its connection table ([`ConnTable`]).
    handle: Arc<HostHandle>,
    /// When each connection we dialled was established (a quick close is a
    /// refusal, [`note_closed_at_once`]).
    opened: HashMap<ConnectionId, Instant>,
    /// Peers DCUtR upgraded whose relayed connections still have to go.
    upgraded: HashSet<PeerId>,
    /// Dials waiting for relayed connections to close (`PreferDirect`).
    preferring: Vec<(PeerId, Instant, oneshot::Sender<bool>)>,
    listen_addrs: Vec<Multiaddr>,
    /// AutoNAT v2 results per tested address and server.
    nat: NatTally,
    /// The network of each relay we dialled directly at a global address:
    /// its AutoNAT results count ([`NatTally`]).
    server_groups: HashMap<PeerId, NetGroup>,
    /// The reachability last logged ([`Host::publish`]).
    last_reach: Option<(ReachClass, NatVerdict)>,
    /// The router mapping in Phase 1's words (IPC `upnp`): `mapped <port>`
    /// for PCP and NAT-PMP too ([`port_map_step`]).
    upnp: String,
    /// Router port mapping while the PORT_MAP gate is open (IPC
    /// `port_map`); `None` while it is closed.
    port_map: Option<PortMapState>,
    peer_id: PeerId,
    /// Whether every relay went silent at once ([`report_relay_loss`]).
    relay_loss: RelayLoss,
    /// One ping round (interval + timeout): how long another connection
    /// gets to answer before silent relays are our path dying.
    ping_round: Duration,
    /// Contact dials made again from a new local port
    /// ([`Host::redial_from_new_port`]): their failure is final.
    fresh_port: HashSet<ConnectionId>,
    /// Automatic relay choice ([`AutoRelays`]): carried from generation to
    /// generation by the seed.
    auto: AutoRelays,
    /// The next round of automatic choice ([`SELECT_EVERY`]).
    next_select: Instant,
    /// The last connection that came up or ping that was answered: this
    /// node is online ([`ONLINE_PROOF`]).
    last_ok: Option<Instant>,
    /// The AutoNAT servers this endpoint was built with
    /// ([`autonat_servers`]); since when the slots name others, and since
    /// when no Raven link is open ([`autonat_rebind_due`]).
    autonat_built: [Option<PeerId>; 2],
    autonat_stale_since: Option<Instant>,
    idle_since: Option<Instant>,
    /// The HTTPS proxy's answer to this endpoint's last failed dial through
    /// it, when it was a 407 ([`proxy_auth_word`]; IPC `proxy_auth`), until
    /// a reservation is accepted (through the proxy or not).
    proxy_auth: &'static str,
    /// Phase 4: this network's NAT mapping classifier while the NAT_CLASS
    /// gate is live (`None` otherwise: Phase 1's behaviour). Fed by
    /// [`Self::conn_meta`]'s connections ([`Host::nat_observed`]).
    nat_class: Option<NatClassifier>,
    /// The connections the classifier may learn from ([`nat_feed`]): how
    /// each was dialled and when it came up.
    conn_meta: HashMap<ConnectionId, (ConnectedPoint, std::time::Instant)>,
    /// The listeners (transport, IPv6) this host had reported when each
    /// pending dial began ([`SwarmEvent::Dialing`]): libp2p-tcp binds a
    /// [`PortUse::Reuse`] dial to the listen port only once the listener
    /// is registered (for a wildcard listener, when its interface addresses
    /// are reported), so a dial that began before that left from another
    /// port although its endpoint still says `Reuse`. At most
    /// [`MAX_DIAL_FAMILIES`].
    dial_families: HashMap<ConnectionId, Vec<(Tr, bool)>>,
    /// The classifier's summary as last given to the hole-punch policy.
    nat_seen: NatSummary,
    /// The policy's skip count as last logged.
    punch_skips_seen: u64,
    /// Hole punches that failed on this endpoint (IPC `nat_mapping`).
    punch_failed: u64,
    /// Contacts' NAT classes from their route hints (the peer gate's last
    /// load, [`GateLoad::nat_remote`]); every generation's policy gets them.
    nat_remote: Vec<(PeerId, raven_core::route_hints::NatClass, u64)>,
    /// Phase 4 PeerId rotation as this generation applies it: its key is
    /// [`RotationState::key_epoch`]'s.
    rotation: RotationState,
    /// What it rests on (the peer gate's last load).
    rotation_facts: RotationFacts,
    /// A rollback in force, carried from generation to generation.
    postponed: Option<Postponement>,
    /// When the key changes next (Unix s): a re-home then
    /// ([`Rehome::Rotate`]).
    rotate_at: Option<u64>,
    /// After a rotation: the relays held before it ([`RotationWatch`]).
    rotation_watch: Option<RotationWatch>,
    /// The identity the epoch keys come from (`None`: never rotates).
    identity: Option<Arc<Identity>>,
    /// The peer gate's clock window when it was last loaded
    /// ([`rotation_window`]).
    gate_window: u64,
    /// Auto-reach: when this host last dialled each peer (at most
    /// [`MAX_DIALLED`]): an inbound connection from a peer dialled within
    /// [`crate::autoreach::DIALLED_RECENTLY`] may be a punch's and confirms
    /// no port ([`crate::autoreach::confirm`]).
    dialled: HashMap<PeerId, Instant>,
    /// Auto-reach: [`raven_core::serverless_punch_live_enabled`], read once
    /// per generation.
    punch_live: bool,
    /// The contacts serverless punching may dial (the peer gate's last load).
    punch_targets: Vec<PunchTarget>,
    /// Punch dials in flight: the contact each one is for.
    punch_inflight: HashMap<ConnectionId, [u8; 32]>,
}

/// Peers [`Host::dialled`] remembers (the oldest go first).
const MAX_DIALLED: usize = 512;

/// Pending dials whose listeners [`Host::dial_families`] remembers, at most.
const MAX_DIAL_FAMILIES: usize = 256;

/// Phase 4, with the NAT_CLASS gate live: the first reservations of a host
/// start this long after its listeners open, so their dials leave from the
/// listen port (the classifier learns from what the relays see).
const NAT_LISTEN_WAIT: Duration = Duration::from_secs(1);

/// The listeners (transport, IPv6) among `listen_addrs`.
fn listen_families(listen_addrs: &[Multiaddr]) -> Vec<(Tr, bool)> {
    let mut out: Vec<(Tr, bool)> = listen_addrs
        .iter()
        .filter_map(raw_endpoint)
        .filter(|(_, a)| a.port() != 0)
        .map(|(tr, a)| (tr, a.is_ipv6()))
        .collect();
    out.dedup();
    out
}

/// Phase 4: a connection the NAT classifier may learn from: one we dialled
/// directly ([`ConnectedPoint::Dialer`], not relayed) with
/// [`PortUse::Reuse`], over raw TCP or QUIC, while a listener of that
/// transport and family was open when the dial began (`families`, as
/// [`Host::dial_families`] recorded them: [`listen_families`]), so it left
/// from the listen port.
fn nat_feed(endpoint: &ConnectedPoint, families: &[(Tr, bool)]) -> bool {
    let ConnectedPoint::Dialer {
        address,
        port_use: PortUse::Reuse,
        ..
    } = endpoint
    else {
        return false;
    };
    raw_endpoint(address).is_some_and(|(tr, remote)| families.contains(&(tr, remote.is_ipv6())))
}

/// The port of the open listener of a transport and family, if any.
type ListenPort = ((Tr, bool), Option<u16>);

/// Phase 4: the classifier's view of the listen addresses: the port of the
/// open listener of each transport and family, and this host's own IPs.
fn nat_listen(listen_addrs: &[Multiaddr]) -> (Vec<ListenPort>, Vec<IpAddr>) {
    let raw: Vec<(Tr, std::net::SocketAddr)> =
        listen_addrs.iter().filter_map(raw_endpoint).collect();
    let ports = [
        (Tr::Tcp, false),
        (Tr::Quic, false),
        (Tr::Tcp, true),
        (Tr::Quic, true),
    ]
    .into_iter()
    .map(|(tr, v6)| {
        let port = raw
            .iter()
            .find(|(t, a)| *t == tr && a.is_ipv6() == v6 && a.port() != 0)
            .map(|(_, a)| a.port());
        ((tr, v6), port)
    })
    .collect();
    (ports, raw.iter().map(|(_, a)| a.ip()).collect())
}

/// The log line of a skipped hole punch.
fn skip_line(why: Option<SkipWhy>) -> &'static str {
    match why {
        Some(SkipWhy::FailedTwice) => {
            "hole punch skipped (two attempts failed on this network); staying on the relay"
        }
        _ => "hole punch skipped (both NAT mappings vary); staying on the relay",
    }
}

/// RWS1 §7: the IPC `proxy_auth` word of a failed dial that the HTTPS proxy
/// answered with a 407: `unsupported` (no Basic offered, NTLM or Negotiate:
/// Windows sign-in), `other` (no Basic offered and neither of those: Digest,
/// Bearer, another scheme or none named), `basic` (it wants a user name and
/// password; none was given) or `refused` (it refused the ones given).
/// `None` for any other failure.
fn proxy_auth_word(error: &DialError) -> Option<&'static str> {
    let DialError::Transport(failures) = error else {
        return None;
    };
    let found = failures.iter().find_map(|(_, e)| match e {
        TransportError::Other(e) => wss::proxy_error_in(e),
        TransportError::MultiaddrNotSupported(_) => None,
    })?;
    match found {
        wss::ProxyError::Auth {
            sent_basic: true, ..
        } => Some("refused"),
        wss::ProxyError::Auth { schemes, .. } if found.unsupported_auth() => {
            if schemes.iter().any(|s| matches!(*s, "NTLM" | "Negotiate")) {
                Some("unsupported")
            } else {
                Some("other")
            }
        }
        wss::ProxyError::Auth { .. } => Some("basic"),
        _ => None,
    }
}

fn upnp_initial(policy: Option<bool>) -> String {
    match policy {
        None => "unset".into(),
        Some(false) => "off".into(),
        Some(true) => "on".into(),
    }
}

fn mapped_port(addr: &Multiaddr) -> Option<u16> {
    addr.iter().find_map(|p| match p {
        Protocol::Tcp(port) | Protocol::Udp(port) => Some(port),
        _ => None,
    })
}

/// A UPnP-IGD event as the state status shows (`mapped <port>`, `failed`)
/// and the line logged when that state changes, which `label` starts
/// ("raven-node p2p", or a relay's [`crate::relay::RelayCmd::label`]). Ports
/// only, never an address.
pub(crate) fn upnp_report(label: &str, event: &upnp::Event) -> (String, String) {
    match event {
        upnp::Event::NewExternalAddr { external_addr, .. } => match mapped_port(external_addr) {
            Some(port) => (
                format!("mapped {port}"),
                format!("{label}: upnp mapped port {port}"),
            ),
            None => ("mapped".into(), format!("{label}: upnp mapped a port")),
        },
        upnp::Event::ExpiredExternalAddr { .. } => (
            "failed".into(),
            format!("{label}: upnp mapping failed (renewal refused)"),
        ),
        upnp::Event::GatewayNotFound => (
            "failed".into(),
            format!(
                "{label}: upnp mapping failed (no UPnP router found; NAT-PMP and PCP are not \
                 supported)"
            ),
        ),
        upnp::Event::NonRoutableGateway => (
            "failed".into(),
            format!("{label}: upnp mapping failed (the router is behind another NAT)"),
        ),
    }
}

/// Router port mapping as this endpoint saw it while the PORT_MAP gate is
/// open (Phase 4, RAVEN Port Mapping V1): IPC `port_map`
/// ([`PortMapStatus`]). Words, the mapped port and counts; never an
/// address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PortMapState {
    /// [`PortMapStatus::v4`].
    v4: &'static str,
    /// The port the router forwards while a mapping is up (0: none).
    v4_port: u16,
    /// IPv4 mappings up now, per protocol.
    v4_tcp: bool,
    v4_udp: bool,
    /// [`PortMapStatus::v6`].
    v6: &'static str,
    /// IPv6 pinholes open now, per protocol.
    v6_tcp: bool,
    v6_udp: bool,
    /// Mappings granted again after the first (a moved port or address, or
    /// after a lease ran out).
    renewals: u32,
    /// Router restarts seen ([`PortMapEvent::ServerRestarted`]).
    restarts: u32,
}

impl PortMapState {
    /// A generation's start: `upnp` is the consent; `v6` how the pinhole
    /// was set up ([`PortMapConfig::v6`] asks one, `v6_wanted` the gate and
    /// consent without a global IPv6 address).
    fn new(upnp: bool, v6: bool, v6_wanted: bool) -> Self {
        Self {
            v4: if upnp { "asking" } else { "off" },
            v6: match (v6, v6_wanted) {
                (true, _) => "asking",
                (false, true) => "none",
                (false, false) => "not_asked",
            },
            ..Self::default()
        }
    }

    fn status(&self) -> PortMapStatus {
        PortMapStatus {
            v4: self.v4.into(),
            v4_port: self.v4_port,
            v6: self.v6.into(),
            renewals: self.renewals,
            server_restarts: self.restarts,
        }
    }

    fn v4_up(&self) -> bool {
        self.v4_tcp || self.v4_udp
    }

    /// One mapping up (`tcp`: TCP, else UDP) through `via` at `port`.
    /// Whether anything changed.
    fn mapped_v4(&mut self, via: &'static str, port: u16, tcp: bool) -> bool {
        let before = *self;
        let slot = if tcp {
            &mut self.v4_tcp
        } else {
            &mut self.v4_udp
        };
        if *slot {
            self.renewals = self.renewals.saturating_add(1);
        }
        *slot = true;
        self.v4 = via;
        self.v4_port = port;
        (before.v4, before.v4_port, before.v4_tcp, before.v4_udp)
            != (self.v4, self.v4_port, self.v4_tcp, self.v4_udp)
    }

    /// One IPv4 mapping gone (`tcp`, or UDP): with none left, the router is
    /// asked again.
    fn lost_v4(&mut self, tcp: bool) {
        if tcp {
            self.v4_tcp = false;
        } else {
            self.v4_udp = false;
        }
        if !self.v4_up() {
            self.v4 = "asking";
            self.v4_port = 0;
        }
    }

    /// The protocols mapped now, as the log line names them.
    fn v4_protocols(&self) -> &'static str {
        match (self.v4_tcp, self.v4_udp) {
            (true, true) => "tcp+udp",
            (true, false) => "tcp",
            _ => "udp",
        }
    }
}

/// The log word of the protocol a router answered in.
fn via_name(via: Via) -> &'static str {
    match via {
        Via::Pcp => "PCP",
        Via::NatPmp => "NAT-PMP",
    }
}

/// [`PortMapStatus::v4`]'s word of the protocol a router answered in.
fn via_word(via: Via) -> &'static str {
    match via {
        Via::Pcp => "pcp",
        Via::NatPmp => "nat-pmp",
    }
}

/// A router's refusal in a few words: result code 2 is NOT_AUTHORIZED in
/// PCP and "not authorized or refused" in NAT-PMP.
fn refusal_text(via: Via, code: u16) -> String {
    match code {
        2 => format!("{}: not authorized", via_name(via)),
        code => format!("{}: result code {code}", via_name(via)),
    }
}

/// One port-mapping event while the PORT_MAP gate is open: `state` and the
/// legacy `upnp` string follow it (`mapped <port>` for PCP and NAT-PMP too,
/// so an older ash still shows the mapping, and [`Host::close_everything`]
/// lingers for the deletes), and the line to log, if any, which `label`
/// starts. Counts and ports only, never an address. While the gate is
/// closed only [`PortMapEvent::Upnp`] comes, and [`upnp_report`] alone
/// answers it.
fn port_map_step(
    state: &mut PortMapState,
    upnp: &mut String,
    label: &str,
    event: &PortMapEvent,
) -> Option<String> {
    let line = |text: String| Some(format!("{label}: {text}"));
    match event {
        PortMapEvent::Upnp(event) => {
            let (legacy, text) = match event {
                upnp::Event::GatewayNotFound => (
                    "failed".to_string(),
                    format!("{label}: no router port mapping found (UPnP, NAT-PMP, PCP)"),
                ),
                event => upnp_report(label, event),
            };
            match event {
                upnp::Event::NewExternalAddr { external_addr, .. } => {
                    let tcp = !is_udp(external_addr);
                    let port = mapped_port(external_addr).unwrap_or(0);
                    state.mapped_v4("upnp", port, tcp);
                }
                upnp::Event::ExpiredExternalAddr { external_addr, .. } => {
                    state.lost_v4(!is_udp(external_addr));
                }
                upnp::Event::GatewayNotFound if !state.v4_up() => state.v4 = "none",
                upnp::Event::NonRoutableGateway if !state.v4_up() => {
                    state.v4 = "behind_another_nat";
                }
                _ => {}
            }
            if legacy == *upnp {
                return None;
            }
            *upnp = legacy;
            Some(text)
        }
        PortMapEvent::Mapped {
            via,
            v6: false,
            port,
            tcp,
            ..
        } => {
            if !state.mapped_v4(via_word(*via), *port, *tcp) {
                return None;
            }
            *upnp = format!("mapped {port}");
            line(format!(
                "router port mapped ({}, port {port} {})",
                via_name(*via),
                state.v4_protocols()
            ))
        }
        PortMapEvent::Mapped { v6: true, tcp, .. } => {
            let first = !(state.v6_tcp || state.v6_udp);
            if *tcp {
                state.v6_tcp = true;
            } else {
                state.v6_udp = true;
            }
            state.v6 = "open";
            first.then(|| format!("{label}: IPv6 pinhole open on the router (PCP)"))
        }
        PortMapEvent::Lost {
            v6: false,
            why,
            tcp,
            ..
        } => {
            state.lost_v4(*tcp);
            if state.v4_up() {
                return None;
            }
            match why {
                LostWhy::Released => {
                    "on".clone_into(upnp);
                    None
                }
                LostWhy::Ended => {
                    "failed".clone_into(upnp);
                    line("router port mapping ended; asking the router again".into())
                }
            }
        }
        PortMapEvent::Lost { v6: true, tcp, .. } => {
            if *tcp {
                state.v6_tcp = false;
            } else {
                state.v6_udp = false;
            }
            if !(state.v6_tcp || state.v6_udp) {
                state.v6 = "asking";
            }
            None
        }
        PortMapEvent::NoServer {
            v6: false,
            upnp: true,
        } => line("no PCP or NAT-PMP answer; trying UPnP".into()),
        // Review E-2: a harness named the router, and UPnP would search the
        // real one: nothing else is tried.
        PortMapEvent::NoServer {
            v6: false,
            upnp: false,
        } => {
            state.v4 = "none";
            "failed".clone_into(upnp);
            line("no PCP or NAT-PMP answer; UPnP not tried (lab router)".into())
        }
        PortMapEvent::NoServer { v6: true, .. } | PortMapEvent::NoGateway { v6: true } => {
            state.v6 = "none";
            None
        }
        PortMapEvent::Refused { via, v6, code } => {
            if *v6 {
                state.v6 = "refused";
                return line(format!(
                    "router refuses the IPv6 pinhole ({})",
                    refusal_text(*via, *code)
                ));
            }
            if !state.v4_up() {
                state.v4 = "refused";
                "failed".clone_into(upnp);
            }
            line(format!(
                "router refuses port mapping ({})",
                refusal_text(*via, *code)
            ))
        }
        PortMapEvent::NonRoutable { carrier } => {
            // Only 100.64.0.0/10 is the provider's carrier NAT; a private
            // external address is another router of the site (double NAT),
            // which bridge mode or a forward on that router fixes.
            let (word, text) = if *carrier {
                (
                    "behind_another_nat",
                    "router is behind another NAT (carrier NAT): no mapping",
                )
            } else {
                (
                    "double_nat",
                    "router is behind another router (double NAT): no mapping",
                )
            };
            *state = PortMapState {
                v4: word,
                v4_port: 0,
                v4_tcp: false,
                v4_udp: false,
                ..*state
            };
            "failed".clone_into(upnp);
            line(text.into())
        }
        PortMapEvent::OffEgress => {
            state.v4 = "off_path";
            "failed".clone_into(upnp);
            line("router is not on the internet path (a VPN?): no mapping".into())
        }
        PortMapEvent::NoGateway { v6: false } => {
            state.v4 = "none";
            "failed".clone_into(upnp);
            line("no router port mapping found (UPnP, NAT-PMP, PCP)".into())
        }
        PortMapEvent::ServerRestarted { .. } => {
            state.restarts = state.restarts.saturating_add(1);
            line("router restarted; port mapped again".into())
        }
    }
}

/// A UDP (QUIC) address.
fn is_udp(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::Udp(_)))
}

/// AutoNAT v2 results per tested address and server (each relay slot has
/// its own client). A result counts only when the server's [`NetGroup`] is
/// known (we dialled it directly at a global address) and differs from the
/// tested IP's own group; `public` needs 2 different servers in 2 different
/// groups that reached the same IP (a TCP and a QUIC check of one IP agree).
/// PeerIds are free: one network is one opinion; and a server's group is
/// read from its connection of the moment, so a dual-stack relay can show
/// up in two: one server is one opinion too ([`independent`]). A fresh
/// endpoint generation (a re-home) starts over: no staleness bookkeeping.
/// Each result is the server's latest answer, so the verdict follows new
/// results both ways.
#[derive(Debug, Default)]
struct NatTally {
    /// Tested address -> server -> (the server's group when it answered,
    /// reached).
    results: HashMap<Multiaddr, HashMap<PeerId, (Option<NetGroup>, bool)>>,
}

/// One counted result's server and the group it answered from.
type Opinion = (PeerId, NetGroup);

/// The results that count, per tested IP: the servers (with their groups)
/// that reached it and those that failed; and how many did not count.
#[derive(Default)]
struct Counted {
    by_ip: BTreeMap<IpAddr, (BTreeSet<Opinion>, BTreeSet<Opinion>)>,
    not_counted: u32,
}

/// How many of `opinions` can be taken with no server and no group twice:
/// the independent ones (a maximum matching of servers to groups; the sets
/// hold at most [`MAX_NAT_RESULTS`] x [`MAX_NAT_SERVERS`]).
fn independent(opinions: &BTreeSet<Opinion>) -> usize {
    /// Kuhn's augmenting path from `server`; `taken`: group -> its server.
    fn augment(
        server: PeerId,
        opinions: &BTreeSet<Opinion>,
        seen: &mut BTreeSet<NetGroup>,
        taken: &mut BTreeMap<NetGroup, PeerId>,
    ) -> bool {
        for &(_, group) in opinions.iter().filter(|(s, _)| *s == server) {
            if !seen.insert(group) {
                continue;
            }
            let free = match taken.get(&group) {
                None => true,
                Some(&other) => augment(other, opinions, seen, taken),
            };
            if free {
                taken.insert(group, server);
                return true;
            }
        }
        false
    }
    let servers: BTreeSet<PeerId> = opinions.iter().map(|(s, _)| *s).collect();
    let mut taken = BTreeMap::new();
    let mut n = 0;
    for server in servers {
        if augment(server, opinions, &mut BTreeSet::new(), &mut taken) {
            n += 1;
        }
    }
    n
}

/// The tested IP and the server's group when a result counts: the group is
/// known and is not the tested IP's own (a server on our own network says
/// nothing about the Internet).
fn counted_result(tested: &Multiaddr, group: Option<NetGroup>) -> Option<(IpAddr, NetGroup)> {
    let ip = addr_ip(tested)?;
    let group = group?;
    (net_group(ip) != Some(group)).then_some((ip, group))
}

impl NatTally {
    fn record(
        &mut self,
        tested: Multiaddr,
        server: PeerId,
        group: Option<NetGroup>,
        reached: bool,
    ) {
        if self.results.len() >= MAX_NAT_RESULTS && !self.results.contains_key(&tested) {
            self.results.clear();
        }
        let servers = self.results.entry(tested).or_default();
        if servers.len() >= MAX_NAT_SERVERS && !servers.contains_key(&server) {
            servers.clear();
        }
        servers.insert(server, (group, reached));
    }

    /// The address is no longer ours (`ExternalAddrExpired`).
    fn forget(&mut self, addr: &Multiaddr) {
        self.results.remove(addr);
    }

    fn counted(&self) -> Counted {
        let mut c = Counted::default();
        for (tested, servers) in &self.results {
            for (server, (group, reached)) in servers {
                match counted_result(tested, *group) {
                    Some((ip, group)) => {
                        let (ok, failed) = c.by_ip.entry(ip).or_default();
                        if *reached {
                            ok.insert((*server, group));
                        } else {
                            failed.insert((*server, group));
                        }
                    }
                    None => c.not_counted = c.not_counted.saturating_add(1),
                }
            }
        }
        c
    }

    /// `public`: 2 or more independent servers reached one IP;
    /// `unconfirmed`: 1 did; `private`: only failures counted; `unknown`:
    /// nothing counted.
    fn verdict(&self) -> NatVerdict {
        let c = self.counted();
        match c.by_ip.values().map(|(ok, _)| independent(ok)).max() {
            Some(2..) => NatVerdict::Public,
            Some(1) => NatVerdict::Unconfirmed,
            Some(_) => NatVerdict::Private,
            None => NatVerdict::Unknown,
        }
    }

    /// `reached`: the most independent servers that reached one IP;
    /// `failed`: independent servers whose counted checks all failed (no
    /// server or group of theirs reached any IP).
    fn checks(&self) -> NatChecks {
        let c = self.counted();
        let reached = c
            .by_ip
            .values()
            .map(|(ok, _)| independent(ok))
            .max()
            .unwrap_or(0);
        let ok: BTreeSet<Opinion> = c.by_ip.values().flat_map(|(ok, _)| ok).copied().collect();
        let failed: BTreeSet<Opinion> = c
            .by_ip
            .values()
            .flat_map(|(_, failed)| failed)
            .filter(|(s, g)| !ok.iter().any(|(os, og)| os == s || og == g))
            .copied()
            .collect();
        let failed = independent(&failed);
        NatChecks {
            reached: u32::try_from(reached).unwrap_or(u32::MAX),
            failed: u32::try_from(failed).unwrap_or(u32::MAX),
            not_counted: c.not_counted,
        }
    }

    /// One server's own checks of us: `reached` (any that counts), `failed`
    /// (only counted failures), `not_counted`, or empty (none).
    fn server_check(&self, server: &PeerId) -> &'static str {
        let (mut reached, mut failed, mut not_counted) = (false, false, false);
        for (tested, servers) in &self.results {
            if let Some((group, ok)) = servers.get(server) {
                match counted_result(tested, *group) {
                    Some(_) if *ok => reached = true,
                    Some(_) => failed = true,
                    None => not_counted = true,
                }
            }
        }
        if reached {
            "reached"
        } else if failed {
            "failed"
        } else if not_counted {
            "not_counted"
        } else {
            ""
        }
    }
}

/// Length and modification time of a file: a cheap "did it change?".
pub(crate) type FileStamp = (u64, SystemTime);

pub(crate) fn file_stamp(path: &Path) -> Option<FileStamp> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.len(), meta.modified().ok()?))
}

/// The files the peer gate's set is read from: contacts.json, the block
/// list, what contacts' route hints said (a PeerId learned or proven, a
/// relay named) and the node policy (hide my IP); with the contact book's
/// reload generation, which moves when the at-rest key arrives (a book held
/// at start is read again then; privacy pack PP.4).
type GateStamp = ([Option<FileStamp>; 5], u64);

fn gate_stamp(data_dir: &Path) -> GateStamp {
    (
        [
            file_stamp(&data_dir.join(raven_core::contact_book::CONTACTS_FILE)),
            file_stamp(&raven_core::chat_history::blocked_path(data_dir)),
            file_stamp(&data_dir.join(raven_core::learned_routes::LEARNED_ROUTES_FILE)),
            file_stamp(&raven_core::node_policy::policy_path(data_dir)),
            file_stamp(&data_dir.join(raven_core::peer_rotation::PEER_SCHEDULES_FILE)),
        ],
        raven_core::contact_book::reload_generation(data_dir),
    )
}

fn admit(set: &mut HashMap<PeerId, PeerClass>, peer_id: &str, class: PeerClass) {
    if let Ok(peer) = peer_id.parse::<PeerId>() {
        *set.entry(peer).or_default() |= class;
    }
}

/// The peers an endpoint admits: the configured relays (OWN_RELAY), and for
/// every verified (pinned), unblocked contact with a `p2p=` PeerId (or,
/// while route hints are live, one its route hints named) that PeerId
/// (CONTACT, or CONTACT_HIDDEN when this node hides its IP from it or the
/// learned PeerId is not proven yet) and the relays its `via=` and its route
/// hints name (CONTACT_RELAY), as `raven_core::outbox::p2p_gate_peers` reads
/// them; while PeerId rotation is live (Phase 4), the contact's other
/// PeerIds too (its card's `p2pn=` and its schedule's epochs around its
/// clock), in the contact's class. `true`: the contact book or the block
/// list cannot be read, so only the relays are admitted (fail closed).
fn gate_files(data_dir: &Path, relays: &[ViaAddr]) -> (HashMap<PeerId, PeerClass>, bool) {
    let mut set = HashMap::new();
    for via in relays.iter().take(p2p_route::MAX_VIA) {
        admit(&mut set, &via.peer_id, PeerClass::OWN_RELAY);
    }
    match raven_core::outbox::p2p_gate_peers(data_dir) {
        Ok(peers) => {
            for peer in &peers {
                let class = if peer.hidden {
                    PeerClass::CONTACT_HIDDEN
                } else {
                    PeerClass::CONTACT
                };
                for peer_id in peer.peer_ids() {
                    admit(&mut set, peer_id, class);
                }
                for relay in &peer.relays {
                    admit(&mut set, relay, PeerClass::CONTACT_RELAY);
                }
            }
            (set, false)
        }
        Err(_) => (set, true),
    }
}

/// The peer gate's set as read from the files, and their stamp taken just
/// before (a change while they are read is loaded again).
struct GateLoad {
    stamp: GateStamp,
    /// When the reading began: the set ends the dial admissions whose check
    /// began by then ([`GateHandle::replace`]).
    read_at: std::time::Instant,
    files: HashMap<PeerId, PeerClass>,
    unreadable: bool,
    /// When a contact last named each contact relay (wall-clock ms): its
    /// route hints' snapshot, or a card (the contact book's last change).
    /// A relay that turned this node away before then is tried again
    /// ([`Host::relays_named_again`]).
    named_at: HashMap<PeerId, u64>,
    /// The relays node_policy.json names, read now that its sealed sidecar
    /// opens ([`P2pConfig::policy_relays_pending`]); the set above admits
    /// them already.
    policy_relays: Option<Vec<ViaAddr>>,
    /// Its proxy setting, likewise ([`P2pProxy::pending`]).
    policy_proxy: Option<String>,
    /// Phase 4: the NAT classes admitted contacts' route hints name (each
    /// with when its hint expires, wall-clock ms), while the NAT_CLASS gate
    /// is live; empty otherwise ([`nat_remote`]).
    nat_remote: Vec<(PeerId, raven_core::route_hints::NatClass, u64)>,
    /// Phase 4: what PeerId rotation rests on ([`rotation_facts`]); the
    /// default (gate closed) reads nothing. `None`: the load itself failed
    /// (a panic), so the facts held before stay ([`Host::gate_loaded`]).
    rotation: Option<RotationFacts>,
    /// Auto-reach: the contacts serverless punching may dial
    /// ([`punch_targets`]), while its gate is live; empty otherwise.
    punch_targets: Vec<PunchTarget>,
}

/// A contact serverless punching may dial (auto-reach design §5.1): a
/// verified contact the peer gate admits, this node may show its IP, whose
/// live route hints name its PeerId, at least one global QUIC endpoint and
/// a NAT class that keeps one mapping for every destination.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PunchTarget {
    key: [u8; 32],
    peer: PeerId,
    /// Its QUIC endpoints, each ending in `/p2p/<peer>`, at most 2.
    addrs: Vec<Multiaddr>,
    /// When its route hints came (wall ms).
    heard_ms: u64,
}

/// The QUIC endpoints serverless punching dials, per contact.
const PUNCH_ADDRS: usize = 2;

/// Blocking: the contacts serverless punching may dial ([`PunchTarget`]),
/// from their live route hints and the gate's files. Contacts whose NAT
/// class says a punch cannot work are counted (`skipped`).
fn punch_targets(data_dir: &Path, files: &HashMap<PeerId, PeerClass>) -> (Vec<PunchTarget>, u32) {
    let now = crate::now_ms();
    let mut out = Vec::new();
    let mut skipped = 0u32;
    for key in raven_core::learned_routes::live_contacts(data_dir, now) {
        let Some(view) = raven_core::learned_routes::learned(data_dir, &key, now) else {
            continue;
        };
        let Some(peer) = view
            .peer_id
            .as_deref()
            .and_then(|p| p.parse::<PeerId>().ok())
        else {
            continue;
        };
        if !files
            .get(&peer)
            .is_some_and(|c| c.intersects(PeerClass::CONTACT))
            || !raven_core::outbox::may_share_ip(data_dir, &key)
        {
            continue;
        }
        let addrs: Vec<Multiaddr> = view
            .direct
            .iter()
            .filter(|v| v.text.contains("/quic-v1/") && v.text.starts_with("/ip4/"))
            .filter_map(|v| v.text.parse().ok())
            .take(PUNCH_ADDRS)
            .collect();
        if addrs.is_empty() {
            continue;
        }
        let class = view.nat_class.map_or(0, |c| c.v4_quic);
        if !raven_core::stun::class_punchable(class) {
            skipped += 1;
            continue;
        }
        out.push(PunchTarget {
            key,
            peer,
            addrs,
            heard_ms: view.received_at_ms,
        });
    }
    (out, skipped)
}

/// Serverless punching's state across endpoint generations (its schedule
/// book, [`raven_core::punch::Book`], and its counts): the book starts over
/// on every re-home (a new network), the counts stay.
#[derive(Debug, Default)]
struct PunchState {
    book: raven_core::punch::Book,
    status: raven_core::ipc::PunchStatus,
}

static PUNCH: Mutex<Option<PunchState>> = Mutex::new(None);

fn with_punch<T>(f: impl FnOnce(&mut PunchState) -> T) -> T {
    f(lock(&PUNCH).get_or_insert_with(PunchState::default))
}

/// What a gate load that panicked leaves ([`Host::poll_gate`]): no contact
/// admitted (unreadable), nothing else read, and no rotation facts, so the
/// ones held stay; the next tick tries again.
fn failed_gate_load(read_at: std::time::Instant) -> GateLoad {
    GateLoad {
        stamp: ([None; 5], 0),
        read_at,
        files: HashMap::new(),
        unreadable: true,
        named_at: HashMap::new(),
        policy_relays: None,
        policy_proxy: None,
        nat_remote: Vec::new(),
        rotation: None,
        punch_targets: Vec::new(),
    }
}

/// Phase 4: the NAT classes of the contacts `files` admits as CONTACT, from
/// their live route hints ([`raven_core::learned_routes::nat_classes`]).
fn nat_remote(
    data_dir: &Path,
    files: &HashMap<PeerId, PeerClass>,
) -> Vec<(PeerId, raven_core::route_hints::NatClass, u64)> {
    raven_core::learned_routes::nat_classes(data_dir, crate::now_ms())
        .into_iter()
        .filter_map(|(_, peer_id, class, expires_ms)| {
            let peer = peer_id.parse::<PeerId>().ok()?;
            files
                .get(&peer)
                .is_some_and(|c| c.intersects(PeerClass::CONTACT))
                .then_some((peer, class, expires_ms))
        })
        .collect()
}

/// Blocking: reads the files.
#[cfg(test)]
fn load_gate(data_dir: &Path, relays: &[ViaAddr]) -> GateLoad {
    load_gate_for(data_dir, relays, false, false, None)
}

/// [`load_gate`]; `policy_pending`: the configured relays come from
/// node_policy.json and its sealed sidecar could not be read when the host
/// started, so they are read again first ([`policy_relays`]);
/// `proxy_pending`: the proxy setting likewise ([`policy_proxy`]); `id`:
/// the profile's identity, whose epochs tell whether PeerId rotation has
/// made its first switch ([`rotation_facts`]).
fn load_gate_for(
    data_dir: &Path,
    relays: &[ViaAddr],
    policy_pending: bool,
    proxy_pending: bool,
    id: Option<&Identity>,
) -> GateLoad {
    let read_at = std::time::Instant::now();
    let stamp = gate_stamp(data_dir);
    let policy_relays = policy_pending.then(|| policy_relays(data_dir)).flatten();
    let policy_proxy = proxy_pending.then(|| policy_proxy(data_dir)).flatten();
    let (files, unreadable) = gate_files(data_dir, policy_relays.as_deref().unwrap_or(relays));
    let named_at = relays_named_at(data_dir, &files);
    let nat_remote = if raven_core::nat_class_live_enabled() {
        nat_remote(data_dir, &files)
    } else {
        Vec::new()
    };
    let punch_targets = if raven_core::serverless_punch_live_enabled() {
        let (targets, skipped) = punch_targets(data_dir, &files);
        with_punch(|p| p.status.skipped_class = skipped);
        targets
    } else {
        Vec::new()
    };
    GateLoad {
        stamp,
        read_at,
        files,
        unreadable,
        named_at,
        policy_relays,
        policy_proxy,
        nat_remote,
        rotation: Some(rotation_facts(data_dir, id)),
        punch_targets,
    }
}

/// node_policy.json's proxy setting (its sealed sidecar merged), once that
/// can be read: `None` while the sidecar waits for the at-rest key.
fn policy_proxy(data_dir: &Path) -> Option<String> {
    if !raven_core::node_policy::peers_readable(data_dir) {
        return None;
    }
    Some(
        raven_core::node_policy::try_load_policy(data_dir)
            .ok()?
            .p2p_proxy,
    )
}

/// node_policy.json's proxy setting `text`, read once its sealed sidecar
/// opened ([`policy_proxy`]): `proxy` takes it, no longer pending. An
/// unusable one is logged (fixed text) and leaves `proxy` as it is (`auto`).
/// Whether the setting changed.
fn take_policy_proxy(proxy: &mut P2pProxy, text: &str) -> bool {
    proxy.pending = false;
    match crate::proxy::parse_explicit(text, crate::proxy::POLICY_SOURCE) {
        Ok(setting) if setting != proxy.setting => {
            proxy.setting = setting;
            proxy.source = crate::proxy::POLICY_SOURCE;
            eprintln!(
                "raven-node p2p: the proxy setting saved in node_policy_peers.rms could be read"
            );
            true
        }
        Ok(_) => false,
        Err(e) => {
            eprintln!("p2p failed: {e}; WSS dials keep the proxy setting they started with");
            false
        }
    }
}

/// The relays node_policy.json names (its sealed sidecar merged), once that
/// can be read: `None` while the sidecar waits for the at-rest key. At most
/// [`p2p_route::MAX_VIA`]; an entry that does not parse is left out (the
/// service checked them at start, when it could read them).
fn policy_relays(data_dir: &Path) -> Option<Vec<ViaAddr>> {
    if !raven_core::node_policy::peers_readable(data_dir) {
        return None;
    }
    let policy = raven_core::node_policy::try_load_policy(data_dir).ok()?;
    Some(
        policy
            .p2p_relays
            .iter()
            .filter_map(|text| p2p_route::parse_via(text).ok())
            .take(p2p_route::MAX_VIA)
            .collect(),
    )
}

/// [`GateLoad::named_at`]: the relays contacts' route hints name, when the
/// newest snapshot naming each came; a relay a contact's card names (a
/// CONTACT_RELAY of `files`) at least as of the contact book's last change.
fn relays_named_at(data_dir: &Path, files: &HashMap<PeerId, PeerClass>) -> HashMap<PeerId, u64> {
    let mut named: HashMap<PeerId, u64> = HashMap::new();
    let now_ms = crate::now_ms();
    for (relay, at) in raven_core::learned_routes::relays_named_at(data_dir, now_ms) {
        if let Ok(relay) = relay.parse::<PeerId>() {
            let e = named.entry(relay).or_default();
            *e = (*e).max(at);
        }
    }
    // The OS stamped the book's change time; route hints carry Raven's.
    let book_ms = std::fs::metadata(data_dir.join("contacts.json"))
        .and_then(|m| m.modified())
        .ok()
        .map(raven_core::clock::from_system)
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    if let Some(book_ms) = book_ms {
        for (relay, class) in files {
            if class.intersects(PeerClass::CONTACT_RELAY) {
                let e = named.entry(*relay).or_default();
                *e = (*e).max(book_ms);
            }
        }
    }
    named
}

const GATE_UNREADABLE: &str = "raven-node p2p: the contact book or block list cannot be read: \
    no contact is admitted over p2p until it is fixed (relays still are)";

/// Probe, then open, every listen address not open yet whose retry is due.
/// A busy port is retried with backoff (logged with its port only), an
/// address on no interface as [`ListenSlot::failed`] says, and an address
/// this host can never bind (no IPv6, say) is dropped after one line.
fn open_listeners(
    swarm: &mut Swarm<EndpointBehaviour>,
    listens: &mut Vec<ListenSlot>,
    now: Instant,
) {
    // Every due slot is probed, then the free ones are opened. (An IPv6
    // probe is IPv6-only, as libp2p binds, so our own `0.0.0.0` listener on
    // the port never makes the `[::]` one busy, in this round or a later.)
    let due: Vec<usize> = (0..listens.len())
        .filter(|i| listens[*i].due(now))
        .collect();
    let probes: Vec<(usize, Result<(), ListenProbe>)> = due
        .iter()
        .map(|i| (*i, probe_listen_addr(&listens[*i].addr)))
        .collect();
    let mut dropped = Vec::new();
    for (i, probe) in probes {
        let slot = &mut listens[i];
        let label = listen_port_label(&slot.addr);
        let outcome = match probe {
            Ok(()) => swarm
                .listen_on(slot.addr.clone())
                .map_err(|_| ListenProbe::Busy),
            Err(e) => Err(e),
        };
        match outcome {
            Ok(id) => {
                slot.listener = Some(id);
                slot.open = true;
                slot.retry_at = None;
                if slot.failures > 0 {
                    eprintln!("raven-node p2p: listen port {label} is open now");
                }
            }
            Err(probe) => {
                if !slot.failed(probe, now) {
                    dropped.push(i);
                }
            }
        }
    }
    for i in dropped.into_iter().rev() {
        listens.remove(i);
    }
}

impl Host {
    /// Status for IPC, one counts-only line whenever the reachability
    /// changes, and this endpoint's routes for route hints ([`note_own`]).
    fn publish(&mut self) {
        let (class, verdict) = self.reach();
        if self.last_reach != Some((class, verdict)) {
            self.last_reach = Some((class, verdict));
            eprintln!(
                "raven-node p2p: reachability {} ({} of 2 independent checks)",
                class.as_str(),
                self.nat.checks().reached.min(2)
            );
        }
        *lock(&STATUS) = Some(self.status_info());
        note_own(Some(self.own_p2p()));
    }

    /// What route hints tell verified contacts about this endpoint
    /// ([`OwnP2p`]): its PeerId, every address each active relay slot's
    /// relay is named by (its fallback too, at most
    /// [`raven_core::route_hints::MAX_ADDRS_PER_RELAY`] per relay), the
    /// external addresses the swarm holds as confirmed (UPnP mapped,
    /// AutoNAT confirmed; never a circuit) and its listen addresses. Sorted
    /// and without `/p2p`, so it changes only when its content does.
    fn own_p2p(&self) -> OwnP2p {
        let texts = |addrs: &mut dyn Iterator<Item = &Multiaddr>| {
            let mut out: Vec<String> = addrs
                .filter(|a| !is_circuit(a))
                .map(|a| {
                    a.iter()
                        .filter(|p| !matches!(p, Protocol::P2p(_)))
                        .collect::<Multiaddr>()
                        .to_string()
                })
                .collect();
            out.sort();
            out.dedup();
            out
        };
        // Auto-reach (gated): what STUN discovery found; a port a contact
        // reached from outside counts as confirmed.
        let found = crate::autoreach::discovered_p2p(
            &self.listen_addrs,
            raven_core::p2p_local_candidates_enabled(),
        );
        let mut confirmed = texts(&mut self.swarm.external_addresses());
        for f in found.iter().filter(|f| f.confirmed) {
            if !confirmed.contains(&f.text) {
                confirmed.push(f.text.clone());
            }
        }
        confirmed.sort();
        let discovered: Vec<String> = found
            .into_iter()
            .filter(|f| !f.confirmed && !confirmed.contains(&f.text))
            .map(|f| f.text)
            .collect();
        OwnP2p {
            peer_id: self.peer_id.to_string(),
            relays: self
                .slots
                .iter()
                .filter(|s| s.active)
                .flat_map(|s| {
                    s.texts
                        .iter()
                        .take(raven_core::route_hints::MAX_ADDRS_PER_RELAY)
                        .cloned()
                })
                .collect(),
            confirmed,
            listen: texts(&mut self.listen_addrs.iter()),
            // Phase 4: what the hole-punch policy acts on, while its gate
            // is live; a confirmed IPv6 pinhole sets flags bit 1.
            nat: self.nat_class.as_ref().map(|_| {
                let v6_open = self.port_map.is_some_and(|m| m.v6_tcp || m.v6_udp);
                self.swarm.behaviour().dcutr.policy.own.to_wire(v6_open)
            }),
            discovered,
            inet: crate::autoreach::inet_direct(raven_core::p2p_local_candidates_enabled())
                .map(|(addr, confirmed)| (addr.to_string(), confirmed))
                .into_iter()
                .collect(),
        }
    }

    /// The reachability class ([`reach_class`]) and the AutoNAT verdict it
    /// rests on.
    fn reach(&self) -> (ReachClass, NatVerdict) {
        let verdict = self.nat.verdict();
        let class = reach_class(ReachFacts {
            verdict,
            upnp_mapped: self.upnp.starts_with("mapped"),
            reservations: self.slots.iter().filter(|s| s.active).count(),
            listening: self.listens.iter().any(|l| l.open),
            // Auto-reach (gated): a contact came in from outside.
            reached_outside: crate::autoreach::reached_outside(),
        });
        (class, verdict)
    }

    /// What IPC `Status` reports while this endpoint runs.
    fn status_info(&self) -> P2pStatusInfo {
        let relay = self.role.as_ref().map(|r| {
            let c = r.guard.counts();
            RelayCounts {
                open: r.open,
                allowed_peers: c.allowed_peers,
                allow_list_unreadable: c.unreadable,
                reservations: c.active_reservations,
                circuits: r.circuits,
                reservations_refused: r.reservations_refused,
                circuits_refused: r.circuits_refused,
                connections_refused: self.swarm.behaviour().peer_gate.counts().total(),
            }
        });
        let (class, verdict) = self.reach();
        let now = Instant::now();
        P2pStatusInfo {
            up: true,
            peer_id: self.peer_id.to_string(),
            listen_addrs: self.listen_addrs.iter().map(|a| a.to_string()).collect(),
            nat: verdict.as_str().to_string(),
            reach: class.as_str().to_string(),
            nat_checks: self.nat.checks(),
            relay_health: self
                .slots
                .iter()
                .map(|s| s.health(now, self.nat.server_check(&s.peer)))
                .collect(),
            reservations: self
                .slots
                .iter()
                .filter(|s| s.active)
                .map(RelaySlot::in_use)
                .collect(),
            relays_configured: p2p_route::distinct_relays(&self.config.relays) as u32,
            upnp: self.upnp.clone(),
            port_map: self.port_map.map(|s| s.status()),
            relay,
            listen_setting: self.config.listen.policy_text(),
            retired_listen: retired_listen(Some(&self.config)),
            source: self.source.clone(),
            relays: self
                .slots
                .iter()
                .flat_map(|s| s.texts.iter().cloned())
                .collect(),
            relay_role: self.config.relay_server.is_some(),
            listen_retrying: self.listens.iter().filter(|l| !l.open).count() as u32,
            gate: Some(Box::new(self.gate_status())),
            paths: Some(path_counts()),
            relay_auto: self.auto.on(),
            relay_standby: self.standby(now) as u32,
            relay_paths: self
                .slots
                .iter()
                .map(|s| match s.path {
                    Some(path) if s.active => path.as_str().into(),
                    _ => String::new(),
                })
                .collect(),
            proxy: self.handle.proxy.status_word(),
            restricted: self.handle.restricted.load(Ordering::SeqCst),
            proxy_source: self.config.proxy.source.into(),
            proxy_auth: self.proxy_auth.into(),
            nat_mapping: self.nat_mapping(),
            rotation: self.rotation_status(),
            auto_reach: crate::autoreach::status().map(|mut ar| {
                ar.punch = self.punch_status();
                ar
            }),
            ..P2pStatusInfo::default()
        }
    }

    /// IPC `nat_mapping` while the NAT_CLASS gate is live: the classes the
    /// hole-punch policy acts on (and route hints tell), and its counts.
    fn nat_mapping(&self) -> Option<NatMappingStatus> {
        let nc = self.nat_class.as_ref()?;
        let hp = &self.swarm.behaviour().dcutr;
        let own = hp.policy.own;
        Some(NatMappingStatus {
            tcp: own.v4_tcp.word().into(),
            quic: own.v4_quic.word().into(),
            observers: u32::try_from(nc.networks(std::time::Instant::now())).unwrap_or(u32::MAX),
            punch_skipped: hp.skipped(),
            punch_failed: self.punch_failed,
        })
    }

    /// Auto-reach: the peer gate's new list of punch targets. A contact
    /// whose endpoints changed starts its failures over (its route hints
    /// told something new).
    fn punch_targets_loaded(&mut self, targets: Vec<PunchTarget>) {
        with_punch(|p| {
            for t in &targets {
                if !self.punch_targets.contains(t) {
                    p.book.fresh(&t.key);
                }
            }
            let keys: Vec<[u8; 32]> = targets.iter().map(|t| t.key).collect();
            p.book.retain(&keys);
            p.status.targets = u32::try_from(targets.len()).unwrap_or(u32::MAX);
        });
        self.punch_targets = targets;
    }

    /// Auto-reach (design §5): dial the contacts whose punch moment is now
    /// ([`raven_core::punch::Book::due`]), from the p2p QUIC listener (port
    /// reuse), while this node's own NAT class keeps one mapping for every
    /// destination and no connection to the contact is open.
    fn tick_punch(&mut self) {
        if !self.punch_live || self.punch_targets.is_empty() {
            return;
        }
        let Some(own) = self.identity.as_ref().map(|id| id.public_key_bytes()) else {
            return;
        };
        if !crate::autoreach::own_class().punchable() {
            return;
        }
        let quic_v4 = self.listen_addrs.iter().any(|a| {
            matches!(a.iter().next(), Some(Protocol::Ip4(_)))
                && a.iter().any(|p| matches!(p, Protocol::QuicV1))
        });
        if !quic_v4 {
            return;
        }
        let wanted: HashSet<[u8; 32]> = crate::outbox::waiting_peers(256).into_iter().collect();
        let Some(identity) = self.identity.as_ref() else {
            return;
        };
        // The pair's phase is made from the secret both friends share (their
        // R2 pair root): nobody who only knows the two keys can tell when
        // they punch. A key without a root is not punched.
        let open: Vec<raven_core::punch::Target> = self
            .punch_targets
            .iter()
            .filter(|t| !self.swarm.is_connected(&t.peer))
            .filter_map(|t| {
                let root = raven_core::lan_beacon::pair_root(identity, &t.key).ok()?;
                Some(raven_core::punch::Target {
                    key: t.key,
                    secret: *root,
                    wanted: wanted.contains(&t.key),
                    heard_ms: t.heard_ms,
                })
            })
            .collect();
        let slot_ms = raven_core::portmap_gate::lab_punch_slot_s()
            .map_or(raven_core::punch::SLOT_MS, |s| s * 1000);
        let due = with_punch(|p| {
            let due = p.book.due(&own, &open, crate::now_ms(), slot_ms);
            p.status.deferred += due.deferred;
            due
        });
        for key in due.dial {
            let Some(t) = self.punch_targets.iter().find(|t| t.key == key).cloned() else {
                continue;
            };
            let opts = DialOpts::peer_id(t.peer)
                .addresses(t.addrs.clone())
                .condition(PeerCondition::DisconnectedAndNotDialing)
                .build();
            let id = opts.connection_id();
            match self.swarm.dial(opts) {
                Ok(()) => {
                    self.punch_inflight.insert(id, key);
                    with_punch(|p| p.status.tried += 1);
                }
                Err(_) => with_punch(|p| p.book.result(&key, false, crate::now_ms())),
            }
        }
    }

    /// Auto-reach: a connection to a punch target came up (ours, or the
    /// contact's own punch arriving first): the punch worked. What waits
    /// for the contact goes at once ([`crate::outbox::peer_back`]).
    fn punch_connected(&mut self, id: ConnectionId, peer: &PeerId, endpoint: &ConnectedPoint) {
        let ours = self.punch_inflight.remove(&id);
        if endpoint.is_relayed() {
            return;
        }
        let key = ours.or_else(|| {
            let target = self.punch_targets.iter().find(|t| t.peer == *peer)?;
            self.punch_inflight
                .values()
                .any(|k| *k == target.key)
                .then_some(target.key)
        });
        let Some(key) = key else {
            return;
        };
        self.punch_inflight.retain(|_, k| *k != key);
        with_punch(|p| {
            p.book.result(&key, true, crate::now_ms());
            p.status.connected += 1;
        });
        netutil::log_limited(
            &PUNCH_LOG,
            "raven-node p2p",
            "serverless punch: a contact connected directly, no relay",
        );
        crate::outbox::peer_back(&key);
    }

    /// Auto-reach: a punch dial failed; it counts unless the contact's own
    /// punch came in meanwhile.
    fn punch_failed_dial(&mut self, id: ConnectionId, peer: Option<&PeerId>) {
        let Some(key) = self.punch_inflight.remove(&id) else {
            return;
        };
        let connected = peer.is_some_and(|p| self.swarm.is_connected(p));
        if !connected {
            with_punch(|p| p.book.result(&key, false, crate::now_ms()));
        }
    }

    /// Auto-reach: serverless punching's counts (IPC), while its gate is
    /// live.
    fn punch_status(&self) -> Option<raven_core::ipc::PunchStatus> {
        self.punch_live.then(|| with_punch(|p| p.status.clone()))
    }

    /// Auto-reach: this host dialled `peer` now ([`Self::dialled`]).
    fn note_dialled(&mut self, peer: PeerId, now: Instant) {
        if self.dialled.len() >= MAX_DIALLED && !self.dialled.contains_key(&peer) {
            if let Some(oldest) = self
                .dialled
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(p, _)| *p)
            {
                self.dialled.remove(&oldest);
            }
        }
        self.dialled.insert(peer, now);
    }

    /// Auto-reach (design §4.4): a contact the peer gate admits came in on a
    /// listener, not through a relay and not right after this host dialled
    /// it (a punch or DCUtR also brings an inbound connection): the port it
    /// came in on is reachable from outside ([`crate::autoreach::confirm`]).
    fn confirm_reach(&mut self, peer: &PeerId, endpoint: &ConnectedPoint) {
        if !crate::autoreach::enabled() {
            return;
        }
        let ConnectedPoint::Listener {
            local_addr,
            send_back_addr,
        } = endpoint
        else {
            return;
        };
        if is_circuit(local_addr) || is_circuit(send_back_addr) {
            return;
        }
        if !self.gate.class_of(peer).intersects(PeerClass::CONTACT) {
            return;
        }
        if self
            .dialled
            .get(peer)
            .is_some_and(|at| at.elapsed() < crate::autoreach::DIALLED_RECENTLY)
        {
            return;
        }
        let what = if local_addr.iter().any(|p| matches!(p, Protocol::QuicV1)) {
            crate::autoreach::Reached::Quic
        } else if local_addr.iter().any(|p| matches!(p, Protocol::Tcp(_))) {
            crate::autoreach::Reached::Tcp
        } else {
            return;
        };
        if let Some(ip) = addr_ip(send_back_addr) {
            crate::autoreach::confirm(what, ip, raven_core::p2p_local_candidates_enabled());
        }
    }

    /// Phase 4: the classifier's listen ports and own addresses follow the
    /// listen addresses.
    fn nat_listen_changed(&mut self) {
        let Some(nc) = self.nat_class.as_mut() else {
            return;
        };
        let (ports, own) = nat_listen(&self.listen_addrs);
        for ((tr, v6), port) in ports {
            nc.set_listen_port(tr, v6, port);
        }
        nc.set_own_addrs(own);
        self.refresh_nat();
    }

    /// Phase 4: Identify's raw observed address of us on `conn`, from
    /// `peer`. It counts when the connection may teach the classifier
    /// ([`Self::conn_meta`]) and the peer is one of our relays or a
    /// contact. The line [`Self::refresh_nat`] logged, if the classes
    /// changed.
    fn nat_observed(
        &mut self,
        conn: ConnectionId,
        peer: &PeerId,
        observed: &Multiaddr,
    ) -> Option<String> {
        let nc = self.nat_class.as_mut()?;
        let (endpoint, opened) = self.conn_meta.get(&conn)?;
        let observer = self.slots.iter().any(|s| s.peer == *peer)
            || self.gate.class_of(peer).intersects(PeerClass::CONTACT);
        if observer && nc.observed(conn, endpoint, observed, *opened, std::time::Instant::now()) {
            self.refresh_nat()
        } else {
            None
        }
    }

    /// Phase 4: when the classifier's summary changed, the hole-punch
    /// policy takes it, and one counts-only line says so (also returned).
    fn refresh_nat(&mut self) -> Option<String> {
        let nc = self.nat_class.as_ref()?;
        let now = std::time::Instant::now();
        let mut summary = nc.summary(now);
        // Auto-reach: STUN's class of the p2p QUIC port, while the
        // classifier (relays and contacts on two networks at once) has none.
        if summary.v4_quic == raven_swarm::natclass::Mapping::Unknown {
            summary.v4_quic =
                raven_swarm::natclass::Mapping::from_code(crate::autoreach::own_class().code());
        }
        if summary == self.nat_seen {
            return None;
        }
        self.nat_seen = summary;
        let line = format!(
            "raven-node p2p: NAT mapping {} (tcp), {} (quic) from {} networks",
            summary.v4_tcp.word(),
            summary.v4_quic.word(),
            nc.networks(now)
        );
        self.swarm
            .behaviour_mut()
            .dcutr
            .policy_mut()
            .set_own(summary);
        eprintln!("{line}");
        Some(line)
    }

    /// Phase 4: a hole punch skipped since the last look is logged (its
    /// reason only, rate-limited).
    fn note_punch_skips(&mut self) {
        let hp = &self.swarm.behaviour().dcutr;
        let skipped = hp.skipped();
        if skipped > self.punch_skips_seen {
            self.punch_skips_seen = skipped;
            netutil::log_limited(&SKIP_LOG, "raven-node p2p", skip_line(hp.last_skip()));
        }
    }

    /// Phase 4: contacts' NAT classes ([`Self::nat_remote`]) to the
    /// hole-punch policy, each until its route hint expires. Nothing while
    /// the NAT_CLASS gate is closed.
    fn apply_nat_remote(&mut self) {
        if self.nat_class.is_none() {
            return;
        }
        let (now, now_ms) = (std::time::Instant::now(), crate::now_ms());
        let policy = self.swarm.behaviour_mut().dcutr.policy_mut();
        policy.clear_remote();
        for (peer, class, expires_ms) in &self.nat_remote {
            if *expires_ms > now_ms {
                policy.set_remote(
                    *peer,
                    NatSummary::from_wire(class),
                    now + Duration::from_millis(expires_ms - now_ms),
                );
            }
        }
    }

    /// The slots as [`relay_select::select`] sees them, its clocks in
    /// wall-clock ms: a slot's are this generation's ([`RelaySlot::selected_at`]).
    fn slot_now(&self, now: Instant, now_ms: u64) -> Vec<SlotNow> {
        let ms = |t: Instant| {
            now_ms.saturating_sub(
                u64::try_from(now.saturating_duration_since(t).as_millis()).unwrap_or(u64::MAX),
            )
        };
        self.slots
            .iter()
            .map(|s| SlotNow {
                peer_id: s.peer.to_string(),
                manual: s.source == Source::Manual,
                active: s.active,
                lost_since_ms: s.lost_since().map(ms),
                selected_at_ms: ms(s.selected_at),
                ever_reserved: s.ever_reserved(),
            })
            .collect()
    }

    /// Offered relays automatic choice could take beside the slots
    /// ([`relay_select::standby`]).
    fn standby(&self, now: Instant) -> usize {
        if !self.auto.on() {
            return 0;
        }
        let now_ms = crate::now_ms();
        let me = self.peer_id.to_string();
        relay_select::standby(&relay_select::Input {
            me: &me,
            manual: &self.config.relays,
            offers: &self.auto.candidates,
            slots: &self.slot_now(now, now_ms),
            mem: &self.auto.mem,
            online: false,
            auto: true,
            now_ms,
            max: p2p_route::MAX_VIA,
            // Not read by the count.
            t: relay_select::Timing::default(),
            learned: &[],
        })
    }

    /// The peer gate's row (counts only; this generation's refusals).
    fn gate_status(&self) -> P2pGateStatus {
        let (contacts, relays, unreadable) = self.gate.summary();
        P2pGateStatus {
            contacts,
            relays,
            unreadable,
            refused: self.swarm.behaviour().peer_gate.counts().total(),
            refused_hole_punch: self.swarm.behaviour().dcutr.refused_targets(),
        }
    }

    /// Read the peer gate's set again, off the swarm loop, when contacts.json
    /// or the block list changed since the last load
    /// ([`Command::GateLoaded`]).
    fn poll_gate(&mut self) {
        if self.gate_loading {
            return;
        }
        // Phase 4: a rotating contact's admitted PeerIds move with the
        // clock, so the files are read again in each new window.
        let window = rotation_window();
        if gate_stamp(&self.data_dir) == self.gate_stamp && window == self.gate_window {
            return;
        }
        self.gate_window = window;
        self.gate_loading = true;
        let (data_dir, relays) = (self.data_dir.clone(), self.config.relays.clone());
        let pending = self.config.policy_relays_pending;
        let proxy_pending = self.config.proxy.pending;
        let commands = self.commands.clone();
        let read_at = std::time::Instant::now();
        let id = self.identity.clone();
        tokio::spawn(async move {
            let loaded = blocking(move || {
                Ok(load_gate_for(
                    &data_dir,
                    &relays,
                    pending,
                    proxy_pending,
                    id.as_deref(),
                ))
            })
            .await
            // The load itself cannot fail; a panic in it admits no
            // contact, and the next tick tries again.
            .unwrap_or_else(|_| failed_gate_load(read_at));
            let _ = commands.send(Command::GateLoaded(Box::new(loaded))).await;
        });
    }

    /// Take a newly read set, and disconnect the peers that lost the class a
    /// connection of theirs was admitted with. Logs counts only, when they
    /// change.
    fn gate_loaded(&mut self, mut loaded: GateLoad) {
        self.gate_loading = false;
        self.gate_stamp = loaded.stamp;
        // The at-rest key arrived (privacy pack PP.6): the relays
        // node_policy.json names could be read at last. A change re-homes the
        // endpoint, whose next generation reserves on them.
        if let Some(relays) = loaded.policy_relays.take() {
            self.config.policy_relays_pending = false;
            if relays != self.config.relays {
                eprintln!(
                    "raven-node p2p: the relays saved in node_policy_peers.rms could be read \
                     (relays={})",
                    p2p_route::distinct_relays(&relays)
                );
                self.config.relays = relays;
                network_changed(Rehome::Relays);
            }
        }
        // Its proxy setting likewise: the seed's proxy takes it at once (a
        // reservation held stays; the next dials follow it).
        if let Some(text) = loaded.policy_proxy.take() {
            if take_policy_proxy(&mut self.config.proxy, &text) {
                self.handle
                    .proxy
                    .set_explicit(self.config.proxy.setting.clone());
            }
        }
        let before = self.gate.summary();
        self.gate
            .replace(loaded.files, loaded.unreadable, loaded.read_at);
        let now = self.gate.summary();
        if now != before {
            let (contacts, relays, unreadable) = now;
            eprintln!(
                "raven-node p2p: peer gate reloaded (verified contacts {contacts}, relays \
                 {relays})"
            );
            if unreadable && !before.2 {
                eprintln!("{GATE_UNREADABLE}");
            }
        }
        self.recheck_gate();
        self.relays_named_again(&loaded.named_at);
        self.nat_remote = loaded.nat_remote;
        self.apply_nat_remote();
        self.punch_targets_loaded(loaded.punch_targets);
        // Phase 4: the setting or the contacts that can follow may have
        // changed what key this host should use. A load that failed says
        // nothing about them: the facts held stay (a panic must not send a
        // rotating host back to the fixed key).
        if let Some(rotation) = loaded.rotation {
            self.rotation_facts = rotation;
        }
        self.rotation_follow(false);
    }

    /// A contact's card or route hints named a relay again after it turned
    /// this node away (`named_at`, [`GateLoad::named_at`]): its operator may
    /// admit this node now, so dials try it again at once. A relay this node
    /// reserves on keeps its mark until it accepts a reservation.
    fn relays_named_again(&mut self, named_at: &HashMap<PeerId, u64>) {
        if !self.auto.live {
            return;
        }
        let mut ended = false;
        for (relay, at) in named_at {
            if self.slots.iter().any(|s| s.peer == *relay) {
                continue;
            }
            ended |= relay_select::named_again(&mut self.auto.mem, &relay.to_string(), *at);
        }
        if ended {
            self.auto.mark(true);
        }
    }

    /// Disconnect every peer whose admission no longer holds.
    fn recheck_gate(&mut self) {
        for peer in self.swarm.behaviour().peer_gate.recheck() {
            let _ = self.swarm.disconnect_peer_id(peer);
        }
    }

    fn connect(
        &mut self,
        peer: PeerId,
        class: PeerClass,
        relays: Vec<PeerId>,
        addrs: Vec<Multiaddr>,
        checked_at: std::time::Instant,
        reply: oneshot::Sender<Result<(), String>>,
    ) {
        // Already connected, whoever opened it: the link rides that
        // connection. When the contact opened it (a node behind a NAT that
        // reached us), this is the deliberate connection reversal of the
        // dial plan (§2.3 step 1), labelled `reversed`.
        if self.swarm.is_connected(&peer) {
            let _ = reply.send(Ok(()));
            return;
        }
        // The dial checked a moment ago that the contact is verified: our
        // own gate admits it (hidden, when the dial said so) and its relays,
        // unless the set it holds was read after that check and leaves the
        // peer out (then the dial checks again: `connect_checked`).
        let until = std::time::Instant::now() + DIAL_ADMIT_TTL;
        if self
            .gate
            .admit_dial(peer, class, &relays, checked_at, until)
            .is_err()
        {
            let _ = reply.send(Err(CHECK_AGAIN.to_string()));
            return;
        }
        let planned: Vec<PeerId> = addrs.iter().filter_map(circuit_relay).collect();
        let addrs = self.order_dial(peer, addrs);
        // Relays whose circuits were left out turned this node away.
        let mut turned_away: Vec<PeerId> = Vec::new();
        for r in planned {
            if !turned_away.contains(&r) && !addrs.iter().any(|a| circuit_relay(a) == Some(r)) {
                turned_away.push(r);
            }
        }
        let facts = InFlight::new(relays, &turned_away);
        let opts = DialOpts::peer_id(peer).addresses(addrs);
        // A hidden contact is dialled at the dial's addresses only (its
        // circuits, when this node hides its IP from it): no address another
        // protocol remembers for it. Nor is any contact on a restricted
        // network (RWS1 §9: no direct address).
        let restricted = self.handle.restricted.load(Ordering::SeqCst);
        let opts = if class == PeerClass::CONTACT && !restricted {
            opts.extend_addresses_through_behaviour()
        } else {
            opts
        };
        let opts = opts
            .condition(PeerCondition::DisconnectedAndNotDialing)
            .build();
        let dialled = self.swarm.dial(opts);
        // What this dial's addresses say is gathered for the diagnosis: a
        // dial with no address at all is one too (nothing to dial); a dial
        // refused here says nothing about the network.
        with_facts(|f| match &dialled {
            Ok(()) | Err(DialError::NoAddresses) => f.begin(peer, facts),
            Err(DialError::DialPeerConditionFalse(_)) => f.join(peer, facts),
            Err(_) => f.begin(
                peer,
                InFlight {
                    interrupted: true,
                    ..facts
                },
            ),
        });
        match dialled {
            Ok(()) | Err(DialError::DialPeerConditionFalse(_)) => {
                self.pending.entry(peer).or_default().push(reply);
            }
            Err(DialError::NoAddresses) => {
                let _ = reply.send(Err(format!("{P2P_UNREACHABLE} (no address known)")));
            }
            Err(_) => {
                let _ = reply.send(Err(P2P_UNREACHABLE.to_string()));
            }
        }
    }

    /// [`order_dial`] of a dial to `target` by what this node noted of the
    /// relays: their memory's not-member windows (every target), this
    /// target's demoted circuits (both only while automatic relay choice is
    /// live: the Phase 1 host notes nothing) and learning connectivity's
    /// relay terms ([`learned_terms`], none while learning is off), and the
    /// relays Phase 6b's responses put last (R8, every host). Unchanged with
    /// none of them.
    fn order_dial(&self, target: PeerId, addrs: Vec<Multiaddr>) -> Vec<Multiaddr> {
        let mut relays: Vec<PeerId> = Vec::new();
        for relay in addrs.iter().filter_map(circuit_relay) {
            if !relays.contains(&relay) {
                relays.push(relay);
            }
        }
        let terms = learned_terms(&relays);
        let live = self.auto.live;
        // Phase 6b R8 (the responses gate): a relay that lost receipts or
        // broke links goes last for an hour, whatever relay choice does.
        let any_last = crate::security::any_relay_demoted();
        let security_last =
            |relay: &PeerId| any_last && crate::security::relay_demoted(&relay.to_bytes());
        if !live && terms.is_empty() && !any_last {
            return addrs;
        }
        let (now, now_ms) = (Instant::now(), crate::now_ms());
        order_dial(
            addrs,
            |relay| live && self.auto.mem.is_not_member(&relay.to_string(), now_ms),
            |relay| (live && is_demoted(&target, relay, now)) || security_last(relay),
            |relay| term_of(&terms, relay),
        )
    }

    /// What a failed dial to `target` says about the relays of its circuits
    /// ([`dial_failures`]): a relay that answered NO_RESERVATION (or could
    /// not hand the circuit over) demotes that circuit for that target
    /// ([`note_demoted`]); a busy relay, or one that did not answer, is
    /// noted nowhere. A relay that closed our connection at once is
    /// [`Self::relay_turned_us_away`]'s.
    fn classify_dial_failure(&self, target: Option<PeerId>, error: &DialError) {
        let (Some(target), true) = (target, self.auto.live) else {
            return;
        };
        let now = Instant::now();
        for failed in dial_failures(error) {
            if let Failed::Circuit {
                relay,
                outcome: CircuitOutcome::NotOnRelay,
            } = failed
            {
                note_demoted(target, relay, now);
            }
        }
    }

    /// `peer` closed a connection we had just dialled at once, before any
    /// link used it ([`QUICK_CLOSE`]). When `peer` is a relay that held no
    /// reservation of ours on it (a relay slot's, or one a dial admitted
    /// with its contact), its peer gate does not count this node a member:
    /// noted in the memory ([`relay_select::note_not_member`]), written at
    /// once. Its slot is then dropped by automatic choice, and dials leave
    /// its circuits out. The long window is only for a relay this node
    /// reserves on that no contact offers (one set by hand); a contact's
    /// relay is skipped for the short one, and less when a contact names it
    /// again ([`Self::relays_named_again`]) or a circuit through it comes
    /// up: its operator may add this node any moment, and a quick close may
    /// also be a connection limit or a restart.
    fn relay_turned_us_away(&mut self, peer: PeerId, now: Instant) {
        if !self.auto.live {
            return;
        }
        let (relay, slot) = match self.slots.iter().find(|s| s.peer == peer) {
            Some(slot) => (!slot.reserved_until(now), true),
            None => {
                let class = self.gate.class_of(&peer);
                let relay = class.intersects(PeerClass::OWN_RELAY | PeerClass::CONTACT_RELAY)
                    && !class.intersects(PeerClass::CONTACT | PeerClass::CONTACT_HIDDEN);
                (relay, false)
            }
        };
        if !relay {
            return;
        }
        let key = peer.to_string();
        let short = !slot || self.auto.offer_of(&key).is_some();
        relay_select::note_not_member(&mut self.auto.mem, &key, short, crate::now_ms());
        self.auto.mark(true);
    }

    /// A relayed connection came up through `relay`: it admits this node,
    /// whatever it refused before ([`relay_select::clear_not_member`]).
    fn circuit_through(&mut self, relay: PeerId) {
        if self.auto.live && relay_select::clear_not_member(&mut self.auto.mem, &relay.to_string())
        {
            self.auto.mark(true);
        }
    }

    /// A dial [`Host::connect`] made to `peer` failed. Its direct TCP
    /// addresses that were refused because our listen port's connection to
    /// them is still held (TIME_WAIT after our own close, a re-home's
    /// included, or a FIN the old network never answered: macOS and Windows
    /// say "address in use", and libp2p-tcp falls back to a new port only on
    /// Linux's error) are dialled once more, from a new local port, instead
    /// of failing for 30-240 s. `true`: that dial is under way and answers
    /// the waiting replies.
    fn redial_from_new_port(&mut self, peer: PeerId, error: &DialError) -> bool {
        let DialError::Transport(failures) = error else {
            return false;
        };
        if !self.pending.contains_key(&peer) {
            return false;
        }
        let held: Vec<Multiaddr> = failures
            .iter()
            .filter(|(addr, failure)| {
                let tcp = addr.iter().any(|p| matches!(p, Protocol::Tcp(_)));
                let circuit = addr.iter().any(|p| p == Protocol::P2pCircuit);
                tcp && !circuit && matches!(failure, TransportError::Other(e) if addr_in_use(e))
            })
            .map(|(addr, _)| addr.clone())
            .collect();
        if held.is_empty() {
            return false;
        }
        let opts = DialOpts::peer_id(peer)
            .addresses(held)
            .allocate_new_port()
            .build();
        let id = opts.connection_id();
        if self.swarm.dial(opts).is_err() {
            return false;
        }
        self.fresh_port.insert(id);
        true
    }

    fn connections_to(&self, peer: &PeerId) -> (Vec<ConnectionId>, Vec<ConnectionId>) {
        lock(&self.handle.conns).split(peer)
    }

    fn prefer_direct(&mut self, peer: PeerId, reply: oneshot::Sender<bool>) {
        let (direct, relayed) = self.connections_to(&peer);
        if direct.is_empty() {
            let _ = reply.send(false);
            return;
        }
        let idle = current_host().is_none_or(|h| h.links_to(&peer) == 0);
        if relayed.is_empty() || !idle {
            // Nothing to close, or a link still rides the relay: the new one
            // may land on either connection.
            let _ = reply.send(relayed.is_empty());
            return;
        }
        for id in relayed {
            self.swarm.close_connection(id);
        }
        self.preferring.push((peer, Instant::now(), reply));
    }

    fn answer_preferring(&mut self, now: Instant) {
        let waiting = std::mem::take(&mut self.preferring);
        for (peer, since, reply) in waiting {
            let (direct, relayed) = self.connections_to(&peer);
            if relayed.is_empty() || now.saturating_duration_since(since) >= PREFER_DIRECT_WAIT {
                let _ = reply.send(!direct.is_empty() && relayed.is_empty());
            } else {
                self.preferring.push((peer, since, reply));
            }
        }
    }

    fn answer_pending(&mut self, peer: &PeerId, result: Result<(), String>) {
        if result.is_ok() {
            with_facts(|f| f.forget(peer));
        }
        for reply in self.pending.remove(peer).unwrap_or_default() {
            let _ = reply.send(result.clone());
        }
    }

    /// Resolve (when an address is named by DNS) and then request the
    /// reservation of `slot`. Resolution runs off the swarm loop; its answer
    /// comes back as `Command::Resolved`, keyed by the relay.
    fn start_reservation(&mut self, index: usize) {
        let dial = self.handle.forms();
        let slot = &mut self.slots[index];
        slot.retry_at = None;
        if !slot.active {
            slot.path = None;
        }
        slot.plan_forms(&dial);
        if !slot.named_by_dns() {
            slot.resolved = slot.forms.clone();
            self.request_reservation(index);
            return;
        }
        if slot.resolving {
            return;
        }
        slot.resolving = true;
        let (forms, relay) = (slot.forms.clone(), slot.peer);
        let offered = matches!(slot.source, Source::Offer { .. });
        let (commands, gen) = (self.commands.clone(), self.gen);
        let lab_local = raven_core::p2p_local_candidates_enabled();
        let lab_loopback = raven_core::route_hints::lab_loopback_relays();
        // Off the swarm loop: the proxy decision may read the system
        // settings.
        tokio::spawn(async move {
            let proxied = |a: &Multiaddr| dial.proxied(a);
            let addrs = resolve_slot(forms, offered, proxied, lab_local, lab_loopback).await;
            let _ = commands.send(Command::Resolved { gen, relay, addrs }).await;
        });
    }

    fn on_resolved(&mut self, relay: PeerId, addrs: Vec<Multiaddr>) {
        let Some(index) = self.slots.iter().position(|s| s.peer == relay) else {
            // A relay dialled as the online proof ([`Self::probe_relay`]).
            if self.auto.probe.is_some_and(|(p, _)| p == relay) {
                self.dial_probe(relay, addrs);
            }
            return;
        };
        let slot = &mut self.slots[index];
        slot.resolving = false;
        if addrs.is_empty() {
            netutil::log_limited(
                &P2P_LOG,
                "p2p failed",
                "a relay name does not resolve (yet) to an address this node may dial; \
                 retrying",
            );
            slot.arm_retry(Instant::now());
            return;
        }
        if addrs != slot.resolved {
            slot.next = 0;
            slot.resolved = addrs;
        }
        self.request_reservation(index);
    }

    fn request_reservation(&mut self, index: usize) {
        let slot = &mut self.slots[index];
        if slot.resolved.is_empty() {
            slot.arm_retry(Instant::now());
            return;
        }
        slot.next %= slot.resolved.len();
        let addr = slot.resolved[slot.next].clone();
        // Restricted from the moment a proxied WSS form is dialled: the
        // relay's Identify runs as soon as the connection is up, before the
        // reservation is accepted, and its view of us is then the proxy's
        // egress.
        slot.path = Some(RelayPath::of(&addr, &self.handle.proxy));
        self.note_restricted();
        let slot = &mut self.slots[index];
        // The relay client dials the relay from our listen port (libp2p's
        // port reuse). After a re-home on the same address the old
        // endpoint's connection may still hold exactly that TCP 4-tuple
        // (TIME_WAIT for 30-240 s, or a FIN the vanished network never
        // answers): macOS and Windows refuse the dial (address in use),
        // which libp2p-tcp does not fall back from, so the reservation would
        // wait that long. A re-homed endpoint dials the relay from a new
        // local port first; the relay client then reserves on that
        // connection.
        let tcp = addr.iter().any(|p| matches!(p, Protocol::Tcp(_)));
        if self.gen > 0 && tcp && !self.swarm.is_connected(&slot.peer) {
            let opts = DialOpts::peer_id(slot.peer)
                .addresses(vec![addr])
                .allocate_new_port()
                .build();
            let id = opts.connection_id();
            match self.swarm.dial(opts) {
                Ok(()) => slot.connecting = Some(id),
                Err(_) => {
                    slot.path = None;
                    slot.rotate();
                    slot.arm_retry(Instant::now());
                    self.note_restricted();
                }
            }
            return;
        }
        self.listen_via(index);
    }

    /// `peer`'s connection died by silence ([`closed_by_silence`]): for
    /// [`RelayLoss`] that is a relay failing its pings, if it held a
    /// reservation on it (the slot may have reported its loss a moment
    /// earlier, [`CLOSE_AFTER_LOSS`]).
    fn relay_went_silent(&mut self, peer: PeerId, now: Instant) {
        let reserved: HashSet<PeerId> = self
            .slots
            .iter()
            .filter(|s| s.active || (s.peer == peer && s.reserved_until(now)))
            .map(|s| s.peer)
            .collect();
        let wait = self.answer_within(peer, &reserved);
        if self.relay_loss.lost(peer, &reserved, wait, now) {
            report_relay_loss();
        }
    }

    /// [`RelayLoss::lost`]'s `answer_within`: one ping round while a direct
    /// connection to a peer other than `lost` and the `reserved` relays is
    /// open (a connection relayed through them would only fail with them).
    fn answer_within(&self, lost: PeerId, reserved: &HashSet<PeerId>) -> Option<Duration> {
        lock(&self.handle.conns)
            .any_direct(|p| *p != lost && !reserved.contains(p))
            .then_some(self.ping_round)
    }

    /// Restricted network (RWS1 §9, owner decision O4-6): set while a
    /// relay slot asks for or holds its reservation through the HTTPS proxy
    /// ([`RelayPath::WssProxy`]), cleared once none does. The flag is the
    /// seed's, shared with the candidate book, both AutoNAT clients and
    /// every dial ([`HostHandle::forms`]). A change is logged with counts
    /// only.
    fn note_restricted(&mut self) {
        let proxied = self
            .slots
            .iter()
            .filter(|s| s.path == Some(RelayPath::WssProxy))
            .count();
        let on = proxied > 0;
        if self.handle.restricted.swap(on, Ordering::SeqCst) != on {
            if on {
                eprintln!(
                    "raven-node p2p: restricted network: {proxied} relay(s) only through the \
                     HTTPS proxy; no hole punching and no direct dials"
                );
            } else {
                eprintln!("raven-node p2p: restricted network: off");
            }
        }
    }

    /// Ask for the reservation: the relay client reserves on a connection
    /// to the relay if there is one, else it dials one.
    fn listen_via(&mut self, index: usize) {
        let slot = &mut self.slots[index];
        let addr = slot.resolved[slot.next].clone().with(Protocol::P2pCircuit);
        match self.swarm.listen_on(addr) {
            Ok(id) => slot.listener = Some(id),
            Err(_) => {
                slot.listener = None;
                slot.path = None;
                slot.rotate();
                slot.arm_retry(Instant::now());
                self.note_restricted();
            }
        }
    }

    fn on_event(&mut self, event: SwarmEvent<EndpointBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                if let Some(role) = self.role.as_mut() {
                    // A relay must name at least one address in its
                    // reservations: never a LAN / loopback one it was not
                    // told to (`RelayAdvertiser`).
                    role.advertiser
                        .on_new_listen_addr(&mut self.swarm, &address);
                }
                // Own IPv6 is offered for hole punching only from the
                // address this host sends from (the candidate book).
                if is_ip6(&address) {
                    let preferred = preferred_v6();
                    self.swarm
                        .behaviour_mut()
                        .dcutr
                        .book_mut()
                        .set_preferred_v6(preferred);
                }
                if !self.listen_addrs.contains(&address) {
                    self.listen_addrs.push(address);
                }
                self.nat_listen_changed();
            }
            SwarmEvent::ExpiredListenAddr { address, .. } => {
                if let Some(role) = self.role.as_mut() {
                    role.advertiser
                        .on_expired_listen_addr(&mut self.swarm, &address);
                }
                if is_ip6(&address) {
                    let preferred = preferred_v6();
                    self.swarm
                        .behaviour_mut()
                        .dcutr
                        .book_mut()
                        .set_preferred_v6(preferred);
                }
                self.listen_addrs.retain(|a| *a != address);
                self.nat_listen_changed();
            }
            SwarmEvent::ExternalAddrExpired { address } => {
                self.nat.forget(&address);
            }
            SwarmEvent::ListenerClosed { listener_id, .. } => {
                let now = Instant::now();
                let mut lost = false;
                for slot in &mut self.slots {
                    if slot.listener == Some(listener_id) {
                        slot.listener = None;
                        slot.path = None;
                        if std::mem::take(&mut slot.active) {
                            lost = true;
                            slot.since = Some(now);
                            slot.ping = None;
                        }
                        // Lost or refused: the next address, after a pause.
                        slot.rotate();
                        slot.arm_retry(now);
                    }
                }
                if lost {
                    eprintln!(
                        "raven-node p2p: reservation lost (active={})",
                        self.slots.iter().filter(|s| s.active).count()
                    );
                }
                self.note_restricted();
            }
            SwarmEvent::Dialing {
                peer_id,
                connection_id,
            } => {
                if let Some(peer) = peer_id {
                    self.note_dialled(peer, Instant::now());
                }
                if self.nat_class.is_some() {
                    if self.dial_families.len() >= MAX_DIAL_FAMILIES {
                        self.dial_families.clear();
                    }
                    self.dial_families
                        .insert(connection_id, listen_families(&self.listen_addrs));
                }
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => {
                let attempt = self
                    .swarm
                    .behaviour()
                    .dcutr
                    .last_attempt(&peer_id)
                    .map(Instant::from_std);
                lock(&self.handle.conns).established_at(
                    connection_id,
                    peer_id,
                    endpoint.is_relayed(),
                    endpoint.is_dialer(),
                    Instant::now(),
                    attempt,
                );
                self.fresh_port.remove(&connection_id);
                self.last_ok = Some(Instant::now());
                self.confirm_reach(&peer_id, &endpoint);
                self.punch_connected(connection_id, &peer_id, &endpoint);
                // The online proof came up: choose again at once.
                if self.auto.probe.is_some_and(|(p, _)| p == peer_id) {
                    self.next_select = Instant::now();
                }
                if endpoint.is_relayed() {
                    let through = match &endpoint {
                        ConnectedPoint::Dialer { address, .. } => circuit_relay(address),
                        ConnectedPoint::Listener { local_addr, .. } => circuit_relay(local_addr),
                    };
                    if let Some(relay) = through {
                        lock(&self.handle.conns).relayed_through(connection_id, relay);
                        self.circuit_through(relay);
                    }
                    self.note_punch_skips();
                }
                if let Some(families) = self.dial_families.remove(&connection_id) {
                    if nat_feed(&endpoint, &families) {
                        self.conn_meta
                            .insert(connection_id, (endpoint.clone(), std::time::Instant::now()));
                    }
                }
                if endpoint.is_dialer() {
                    self.opened.insert(connection_id, Instant::now());
                }
                // A relay we dialled directly: its network decides whether
                // its AutoNAT checks of us are independent ones.
                if endpoint.is_dialer()
                    && !endpoint.is_relayed()
                    && self.slots.iter().any(|s| s.peer == peer_id)
                {
                    match addr_ip(endpoint.get_remote_address()).and_then(net_group) {
                        Some(group) => self.server_groups.insert(peer_id, group),
                        None => self.server_groups.remove(&peer_id),
                    };
                }
                self.answer_pending(&peer_id, Ok(()));
                if let Some(i) = self
                    .slots
                    .iter()
                    .position(|s| s.connecting == Some(connection_id))
                {
                    self.slots[i].connecting = None;
                    self.listen_via(i);
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                endpoint,
                num_established,
                cause,
            } => {
                lock(&self.handle.conns).closed(connection_id);
                if self.conn_meta.remove(&connection_id).is_some() {
                    if let Some(nc) = self.nat_class.as_mut() {
                        nc.closed(connection_id, std::time::Instant::now());
                    }
                }
                // A relay's last connection died by silence: with the default
                // timings QUIC's idle timeout comes before any ping can fail.
                if num_established == 0
                    && !endpoint.is_relayed()
                    && cause.as_ref().is_some_and(closed_by_silence)
                {
                    self.relay_went_silent(peer_id, Instant::now());
                }
                // A connection we dialled that the other side closed at
                // once, before any link used it: its peer gate refused us.
                // (`cause` is `None` when we closed it ourselves.)
                if let Some(at) = self.opened.remove(&connection_id) {
                    let quick = at.elapsed() < QUICK_CLOSE;
                    let idle = current_host().is_none_or(|h| h.links_to(&peer_id) == 0);
                    if quick && idle && cause.is_some() && num_established == 0 {
                        note_closed_at_once(peer_id);
                        self.relay_turned_us_away(peer_id, Instant::now());
                        self.rotation_refused(peer_id);
                    }
                }
                if let Some(role) = self.role.as_ref() {
                    role.guard.on_connection_closed(&peer_id, num_established);
                }
            }
            SwarmEvent::IncomingConnectionError {
                error: ListenError::Denied { cause },
                send_back_addr,
                ..
            } if cause.downcast_ref::<PeerNotAdmitted>().is_some() => netutil::log_limited(
                &GATE_LOG,
                "raven-node p2p",
                format_args!(
                    "refused a connection from a peer that is not a verified contact or a relay \
                     of this node (from {})",
                    netutil::link_tag(&send_back_addr.to_vec())
                ),
            ),
            // Phase 6b R1: the penalty box refused its source before Noise.
            SwarmEvent::IncomingConnectionError {
                error: ListenError::Denied { cause },
                send_back_addr,
                ..
            } if cause.downcast_ref::<SourceRefused>().is_some() => netutil::log_limited(
                &GATE_LOG,
                "raven-node p2p",
                format_args!(
                    "a source that failed too often was refused (from {})",
                    netutil::link_tag(&send_back_addr.to_vec())
                ),
            ),
            SwarmEvent::OutgoingConnectionError {
                connection_id,
                peer_id,
                error,
            } => {
                self.dial_families.remove(&connection_id);
                self.punch_failed_dial(connection_id, peer_id.as_ref());
                let from_new_port = self.fresh_port.remove(&connection_id);
                for slot in &mut self.slots {
                    if slot.connecting == Some(connection_id) {
                        slot.connecting = None;
                        slot.path = None;
                        slot.rotate();
                        slot.arm_retry(Instant::now());
                    }
                }
                self.note_restricted();
                if let Some(word) = proxy_auth_word(&error) {
                    self.proxy_auth = word;
                }
                let denied = matches!(
                    &error,
                    DialError::Denied { cause } if cause.downcast_ref::<PeerNotAdmitted>().is_some()
                );
                with_facts(|f| note_dial_failure(f, peer_id, &error));
                self.classify_dial_failure(peer_id, &error);
                if let Some(peer) = peer_id {
                    if !self.swarm.is_connected(&peer)
                        && (from_new_port || !self.redial_from_new_port(peer, &error))
                    {
                        let why = if denied {
                            format!("{P2P_UNREACHABLE} (this node does not admit that peer)")
                        } else {
                            P2P_UNREACHABLE.to_string()
                        };
                        self.answer_pending(&peer, Err(why));
                    }
                }
            }
            SwarmEvent::Behaviour(event) => self.on_behaviour(event),
            _ => {}
        }
    }

    fn on_behaviour(&mut self, event: EndpointBehaviourEvent) {
        match event {
            EndpointBehaviourEvent::RelayClient(relay::client::Event::ReservationReqAccepted {
                relay_peer_id,
                renewal,
                ..
            }) => {
                let mut fresh = !renewal;
                let mut held = false;
                let proxy = Arc::clone(&self.handle.proxy);
                for slot in &mut self.slots {
                    if slot.peer == relay_peer_id && slot.listener.is_some() {
                        if !slot.active {
                            fresh = true;
                            slot.since = Some(Instant::now());
                        }
                        slot.active = true;
                        slot.attempt = 0;
                        // The address it was asked on (RWS1: how it
                        // travels; through the proxy, the network is
                        // restricted).
                        if let Some(addr) = slot.resolved.get(slot.next) {
                            slot.path = Some(RelayPath::of(addr, &proxy));
                        }
                        held = true;
                    }
                }
                self.note_restricted();
                // A reservation held, through the proxy or not: whatever
                // its 407 said before no longer keeps this node away
                // (review B-2: a slot that rotated to its raw form after
                // the 407 must not keep the credentials hint).
                if held {
                    self.proxy_auth = "";
                }
                // A success: whatever the relay refused before is over.
                if held && self.auto.live {
                    let relay = relay_peer_id.to_string();
                    relay_select::note_ok(&mut self.auto.mem, &relay, crate::now_ms());
                    self.auto.mark(false);
                    self.note_new_server(relay_peer_id, Instant::now());
                }
                self.rotation_accepted(relay_peer_id);
                if fresh {
                    eprintln!(
                        "raven-node p2p: reservation accepted (active={})",
                        self.slots.iter().filter(|s| s.active).count()
                    );
                }
            }
            EndpointBehaviourEvent::Dcutr(dcutr::Event {
                remote_peer_id,
                result,
            }) => match result {
                Ok(id) => {
                    eprintln!("raven-node p2p: direct connection upgraded (dcutr)");
                    self.swarm
                        .behaviour_mut()
                        .dcutr
                        .policy_mut()
                        .note_success(&remote_peer_id);
                    lock(&self.handle.conns).upgraded(id, remote_peer_id, Instant::now());
                    count_paths(|c| c.upgrades = c.upgrades.saturating_add(1));
                    self.upgraded.insert(remote_peer_id);
                }
                Err(_) => {
                    count_paths(|c| c.upgrade_failures = c.upgrade_failures.saturating_add(1));
                    self.punch_failed = self.punch_failed.saturating_add(1);
                    self.swarm
                        .behaviour_mut()
                        .dcutr
                        .policy_mut()
                        .note_failure(remote_peer_id, std::time::Instant::now());
                    let offered = self
                        .swarm
                        .behaviour()
                        .dcutr
                        .book()
                        .counts(std::time::Instant::now());
                    netutil::log_limited(
                        &P2P_LOG,
                        "raven-node p2p",
                        format_args!(
                            "hole punch failed; staying on the relay (candidates: {offered})"
                        ),
                    )
                }
            },
            // What a peer saw as our address, raw (Identify's own candidate
            // may have the port rewritten): a hole-punch candidate once one
            // of our relays, or two peers, report it. Only a direct
            // connection's view is our mapping; on a circuit it is the
            // relay's.
            EndpointBehaviourEvent::Identify(identify::Event::Received {
                connection_id,
                peer_id,
                info,
                ..
            }) => {
                let direct = lock(&self.handle.conns)
                    .origin(connection_id)
                    .is_some_and(|o| o != ConnOrigin::Relayed);
                if direct {
                    let by_relay = self.slots.iter().any(|s| s.peer == peer_id);
                    self.swarm.behaviour_mut().dcutr.book_mut().observed(
                        peer_id,
                        &info.observed_addr,
                        by_relay,
                        std::time::Instant::now(),
                    );
                }
                // Phase 4: the same raw view classifies our NAT's mapping.
                self.nat_observed(connection_id, &peer_id, &info.observed_addr);
            }
            // One client per relay slot; a result counts only from a relay
            // on another network than ours ([`NatTally`]).
            EndpointBehaviourEvent::Autonat(autonat::v2::client::Event {
                tested_addr,
                server,
                result,
                ..
            })
            | EndpointBehaviourEvent::Autonat2(autonat::v2::client::Event {
                tested_addr,
                server,
                result,
                ..
            }) => {
                let group = self.server_groups.get(&server).copied();
                self.nat.record(tested_addr, server, group, result.is_ok());
            }
            // While the PORT_MAP gate is closed only libp2p-upnp's events
            // come, with Phase 1's lines; with it open, NAT-PMP and PCP's
            // too ([`port_map_step`]).
            EndpointBehaviourEvent::PortMap(event) => match (&mut self.port_map, event) {
                (Some(state), event) => {
                    let label = "raven-node p2p";
                    if let Some(line) = port_map_step(state, &mut self.upnp, label, &event) {
                        eprintln!("{line}");
                    }
                }
                (None, PortMapEvent::Upnp(event)) => {
                    let (state, line) = upnp_report("raven-node p2p", &event);
                    if state != self.upnp {
                        eprintln!("{line}");
                        self.upnp = state;
                    }
                }
                (None, _) => {}
            },
            EndpointBehaviourEvent::Ping(event) => {
                if let Ok(rtt) = &event.result {
                    self.relay_loss.answered();
                    let now = Instant::now();
                    self.last_ok = Some(now);
                    for slot in self.slots.iter_mut().filter(|s| s.peer == event.peer) {
                        slot.ping = Some((now, *rtt));
                    }
                    if self.slots.iter().any(|s| s.peer == event.peer) {
                        note_relay_pinged(event.peer, now);
                    }
                }
                if close_if_dead(&mut self.swarm, &event) {
                    // Still active: the reservation is lost only once the
                    // connection is closed.
                    let reserved: HashSet<PeerId> = self
                        .slots
                        .iter()
                        .filter(|s| s.active)
                        .map(|s| s.peer)
                        .collect();
                    let wait = self.answer_within(event.peer, &reserved);
                    if self
                        .relay_loss
                        .lost(event.peer, &reserved, wait, Instant::now())
                    {
                        report_relay_loss();
                    }
                }
            }
            EndpointBehaviourEvent::RelayServer(event) => {
                if let Some(role) = self.role.as_mut() {
                    role.guard.on_relay_event(&event);
                    match event {
                        relay::Event::CircuitReqAccepted { .. } => role.circuits += 1,
                        relay::Event::CircuitClosed { .. } => {
                            role.circuits = role.circuits.saturating_sub(1)
                        }
                        relay::Event::CircuitReqDenied { .. } => role.circuits_refused += 1,
                        relay::Event::ReservationReqDenied { .. } => role.reservations_refused += 1,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    fn tick(&mut self) {
        let now = Instant::now();
        open_listeners(&mut self.swarm, &mut self.listens, now);
        for i in 0..self.slots.len() {
            if self.slots[i].retry_at.is_some_and(|t| t <= now) {
                // A DNS name is resolved again before every attempt.
                self.start_reservation(i);
            }
        }
        // After an upgrade: close the relayed connections once no Raven link
        // rides them, so the next link opens on the direct connection.
        let host = current_host();
        let idle: Vec<PeerId> = self
            .upgraded
            .iter()
            .filter(|p| host.as_ref().is_none_or(|h| h.links_to(p) == 0))
            .copied()
            .collect();
        for peer in idle {
            self.upgraded.remove(&peer);
            let (direct, relayed) = self.connections_to(&peer);
            if direct.is_empty() {
                continue;
            }
            for id in relayed {
                self.swarm.close_connection(id);
            }
        }
        self.answer_preferring(now);
        if self.relay_loss.due(now) {
            report_relay_loss();
        }
        self.tick_gate(now);
        self.tick_auto(now);
        self.tick_rotation(now);
        self.note_restricted();
        // Observations expire: the classes may change with no event.
        self.refresh_nat();
        self.tick_punch();
        self.publish();
    }

    /// The peer gate's part of a tick: read the files again if they changed,
    /// the relay role's allow-list every [`ALLOW_RELOAD`], and disconnect
    /// every peer whose admission no longer holds: a member taken off the
    /// list, and a dial admission past its deadline, which no file change
    /// reports.
    fn tick_gate(&mut self, now: Instant) {
        self.poll_gate();
        if let Some(role) = self.role.as_mut() {
            role.guard.prune();
            if role.last_reload.elapsed() >= ALLOW_RELOAD {
                role.last_reload = now;
                let policy = crate::relay::allow_policy(&role.data_dir, role.open);
                for peer in role.guard.set_policy(policy) {
                    let _ = self.swarm.disconnect_peer_id(peer);
                }
            }
        }
        self.recheck_gate();
    }

    /// Automatic relay choice's part of a tick: read the offers again if a
    /// file changed, every [`SELECT_EVERY`] sample the picked relays and
    /// ask [`Self::select_relays`], write the memory when due, and re-home
    /// for new AutoNAT clients once that is due ([`autonat_rebind_due`]).
    fn tick_auto(&mut self, now: Instant) {
        if !self.auto.live {
            return;
        }
        self.poll_offers();
        if now >= self.next_select {
            self.next_select = now + SELECT_EVERY;
            self.observe_picked();
            self.select_relays(now);
        }
        self.save_memory(now);
        if lock(&self.handle.links).is_empty() {
            self.idle_since.get_or_insert(now);
        } else {
            self.idle_since = None;
        }
        if autonat_rebind_due(self.autonat_stale_since, self.idle_since, now) {
            self.autonat_stale_since = None;
            network_changed(Rehome::Relays);
        }
    }

    /// Read the relays contacts offer again, off the swarm loop, when a file
    /// the peer gate reads changed since the last read (learned_routes.json
    /// holds the offers; the contact book, the block list and the node
    /// policy decide who may be used) ([`Command::OffersLoaded`]).
    fn poll_offers(&mut self) {
        if !self.auto.live || self.auto.loading {
            return;
        }
        if self.auto.stamp == Some(gate_stamp(&self.data_dir)) {
            return;
        }
        self.auto.loading = true;
        let (data_dir, me) = (self.data_dir.clone(), self.peer_id);
        let commands = self.commands.clone();
        tokio::spawn(async move {
            let loaded = blocking(move || Ok(load_offers(&data_dir, &me))).await.ok();
            let _ = commands.send(Command::OffersLoaded(loaded)).await;
        });
    }

    /// Take the offers read again: a picked relay offered at other
    /// addresses moves in place ([`RelaySlot::renamed`], no new choice), and
    /// automatic choice looks at once (an offer withdrawn drops its relay, a
    /// new one fills an empty slot).
    fn offers_loaded(&mut self, loaded: Option<OffersLoad>) {
        self.auto.loading = false;
        let Some(loaded) = loaded else {
            return;
        };
        self.auto.stamp = Some(loaded.stamp);
        self.auto.policy_on = loaded.policy_on;
        self.auto.candidates = loaded.candidates;
        let now = Instant::now();
        for slot in self.slots.iter_mut().filter(|s| s.source != Source::Manual) {
            let Some(offer) = self.auto.offer_of(&slot.peer.to_string()) else {
                continue;
            };
            if offer.addrs == slot.texts {
                continue;
            }
            let (moved, addrs) = (offer.via.clone(), offer.addrs.clone());
            if slot.renamed(&addrs, now).is_ok() {
                for (via, _) in self.auto.picked.iter_mut() {
                    if via.peer_id == moved.peer_id {
                        *via = moved.clone();
                    }
                }
            }
        }
        if self.auto.live {
            self.select_relays(now);
        }
    }

    /// One availability sample of every picked relay
    /// ([`relay_select::observe`]): does it hold our reservation now?
    fn observe_picked(&mut self) {
        let now_ms = crate::now_ms();
        let mut sampled = false;
        for slot in self.slots.iter().filter(|s| s.source != Source::Manual) {
            let peer = slot.peer.to_string();
            let confirmed = self.auto.offer_of(&peer).is_some_and(|c| c.confirmed);
            relay_select::observe(&mut self.auto.mem, &peer, slot.active, confirmed, now_ms);
            sampled = true;
        }
        if sampled {
            self.auto.mark(false);
        }
    }

    /// Ask [`relay_select::select`] which relays to hold and apply the
    /// answer in place ([`Self::apply_selection`]); log what changed
    /// (counts only).
    fn select_relays(&mut self, now: Instant) {
        if !self.auto.live {
            return;
        }
        let now_ms = crate::now_ms();
        let slots = self.slot_now(now, now_ms);
        let online = self.slots.iter().any(|s| s.active)
            || self
                .last_ok
                .is_some_and(|t| now.saturating_duration_since(t) < ONLINE_PROOF);
        let me = self.peer_id.to_string();
        // Learning connectivity's terms (Phase 6a): only ever reorder the
        // relays that may take a slot; none while learning is off.
        let learned = learned_terms_of(self.auto.candidates.iter().map(|c| c.via.peer_id.as_str()));
        let input = relay_select::Input {
            me: &me,
            manual: &self.config.relays,
            offers: &self.auto.candidates,
            slots: &slots,
            mem: &self.auto.mem,
            online,
            auto: self.auto.on(),
            now_ms,
            max: p2p_route::MAX_VIA,
            t: relay_select::Timing::current(),
            learned: &learned,
        };
        let d = relay_select::select(&input);
        // Every slot down and nothing proves this node online: dial the
        // relay that would take a slot, as that proof.
        let probe = relay_select::probe(&input).map(|c| (c.via.peer_id.clone(), c.addrs.clone()));
        let picked = auto_relays(&d);
        let held: HashSet<String> = slots
            .iter()
            .filter(|s| !s.manual)
            .map(|s| s.peer_id.clone())
            .collect();
        let wanted: HashSet<String> = picked.iter().map(|(v, _)| v.peer_id.clone()).collect();
        if relay_select::commit(&mut self.auto.mem, &d, now_ms) {
            self.auto.mark(true);
        }
        if wanted != held {
            self.apply_selection(&picked, now);
        }
        self.log_changes(&d, &slots, now, now_ms);
        if let Some((relay, texts)) = probe {
            self.probe_relay(&relay, &texts, now);
        }
    }

    /// Dial `relay` (an offered relay in no slot, at its offer's `texts`)
    /// without asking it for a reservation: the proof that this node is
    /// online that automatic choice waits for while every slot is down
    /// ([`relay_select::probe`]). Once it connects ([`Self::last_ok`]) the
    /// next round replaces a slot with it, on that connection. At most one
    /// per replace-after window; the peer gate admits it as our own relay
    /// until the next choice. A DNS name is resolved first, to global
    /// answers only ([`resolve_slot`]).
    fn probe_relay(&mut self, relay: &str, texts: &[String], now: Instant) {
        let window = Duration::from_millis(relay_select::Timing::current().replace_after_ms);
        if self
            .auto
            .probe
            .is_some_and(|(_, at)| now.saturating_duration_since(at) < window)
        {
            return;
        }
        let Ok(peer) = relay.parse::<PeerId>() else {
            return;
        };
        if peer == self.peer_id || self.swarm.is_connected(&peer) {
            return;
        }
        self.auto.probe = Some((peer, now));
        let mut admit: Vec<PeerId> = self
            .auto
            .picked
            .iter()
            .filter_map(|(via, _)| via.peer_id.parse().ok())
            .collect();
        admit.push(peer);
        self.gate.set_auto_relays(&admit);
        let dial = self.handle.forms();
        let named = relay_forms(texts, &dial);
        if !named.iter().any(is_dns) {
            self.dial_probe(peer, named);
            return;
        }
        let (commands, gen) = (self.commands.clone(), self.gen);
        let lab_local = raven_core::p2p_local_candidates_enabled();
        let lab_loopback = raven_core::route_hints::lab_loopback_relays();
        tokio::spawn(async move {
            let proxied = |a: &Multiaddr| dial.proxied(a);
            let addrs = resolve_slot(named, true, proxied, lab_local, lab_loopback).await;
            let _ = commands
                .send(Command::Resolved {
                    gen,
                    relay: peer,
                    addrs,
                })
                .await;
        });
    }

    /// The dial of [`Self::probe_relay`], from a new local port (it needs no
    /// port reuse, and an old endpoint's connection may hold ours).
    fn dial_probe(&mut self, peer: PeerId, addrs: Vec<Multiaddr>) {
        if addrs.is_empty() {
            return;
        }
        let opts = DialOpts::peer_id(peer)
            .addresses(addrs)
            .allocate_new_port()
            .condition(PeerCondition::DisconnectedAndNotDialing)
            .build();
        if self.swarm.dial(opts).is_ok() {
            eprintln!(
                "raven-node p2p: every relay is down; trying another offered relay to tell \
                 whether this node is online"
            );
        }
    }

    /// Hold the relays `picked` (beside the manual ones) in place: the peer
    /// gate admits them before any dial, a slot no longer picked goes (its
    /// reservation listener removed, its connection closed by the gate's
    /// recheck), a new one is added at the end and asks for its reservation
    /// at once. The other slots keep theirs. The next endpoint generation
    /// starts from `picked`; its AutoNAT clients may now be stale.
    fn apply_selection(&mut self, picked: &[(ViaAddr, Source)], now: Instant) {
        let want: Vec<PeerId> = picked
            .iter()
            .filter_map(|(via, _)| via.peer_id.parse().ok())
            .collect();
        self.gate.set_auto_relays(&want);
        let mut gone = Vec::new();
        // A slot that goes after it held a reservation in this endpoint
        // generation was an AutoNAT server that answered.
        let mut server_lost = false;
        self.slots.retain_mut(|s| {
            let keep = s.source == Source::Manual || want.contains(&s.peer);
            if !keep {
                gone.extend(s.listener.take());
                server_lost |= s.ever_reserved();
            }
            keep
        });
        for listener in gone {
            self.swarm.remove_listener(listener);
        }
        self.note_restricted();
        for ((via, source), peer) in picked.iter().zip(&want) {
            if *peer == self.peer_id
                || self.slots.len() >= p2p_route::MAX_VIA
                || self.slots.iter().any(|s| s.peer == *peer)
            {
                continue;
            }
            let texts = self.auto.addrs_of(via);
            if let Ok(slot) = RelaySlot::new(*peer, texts, source.clone(), now) {
                self.slots.push(slot);
                self.start_reservation(self.slots.len() - 1);
            }
        }
        // A relay dropped lost its admission: close its connection.
        self.recheck_gate();
        self.auto.picked = picked.to_vec();
        self.note_autonat_servers(now, server_lost);
    }

    /// The AutoNAT servers the slots name now against the ones this
    /// endpoint was built with: current again, or stale since now when a
    /// server that answered went (`server_lost`). A relay that never held a
    /// reservation in this generation served nothing: swapping it for
    /// another changes nothing yet, and the new one marks the clients stale
    /// once it accepts a reservation ([`Self::note_new_server`]), so a pick
    /// that never reserves never re-homes the endpoint.
    fn note_autonat_servers(&mut self, now: Instant, server_lost: bool) {
        if autonat_servers(&self.slots) == self.autonat_built {
            self.autonat_stale_since = None;
        } else if server_lost {
            self.autonat_stale_since.get_or_insert(now);
        }
    }

    /// `relay` accepted a reservation: a relay this endpoint has no AutoNAT
    /// client for (picked since it was built) makes its clients stale.
    fn note_new_server(&mut self, relay: PeerId, now: Instant) {
        if !self.autonat_built.contains(&Some(relay))
            && autonat_servers(&self.slots).contains(&Some(relay))
        {
            self.autonat_stale_since.get_or_insert(now);
        }
    }

    /// One counts-only line per change of decision `d` (`slots`: the slots
    /// it was asked about); "relay kept" at most every [`KEPT_LOG_EVERY`].
    fn log_changes(&mut self, d: &Decision, slots: &[SlotNow], now: Instant, now_ms: u64) {
        let relays = self.slots.len();
        let mut standby = None;
        for change in &d.changes {
            match change {
                Change::Filled(_) => eprintln!(
                    "raven-node p2p: relay chosen (offered by a contact; relays={relays})"
                ),
                Change::Replaced {
                    old,
                    why: LossWhy::NotAnswering,
                    ..
                } => {
                    let lost_min = slots
                        .iter()
                        .find(|s| s.peer_id == *old)
                        .and_then(|s| s.lost_since_ms)
                        .map_or(0, |since| now_ms.saturating_sub(since) / 60_000);
                    let spare = *standby.get_or_insert_with(|| self.standby(now));
                    eprintln!(
                        "raven-node p2p: relay replaced (one stopped answering {lost_min} min \
                         ago; standby={spare})"
                    );
                }
                Change::Replaced {
                    why: LossWhy::NeverReserved,
                    ..
                } => eprintln!("raven-node p2p: relay replaced (it never accepted a reservation)"),
                Change::Dropped { why, .. } => {
                    eprintln!("raven-node p2p: relay dropped ({})", why.as_str())
                }
                Change::Kept(_) => {
                    let quiet = self
                        .auto
                        .kept_logged
                        .is_none_or(|t| now.saturating_duration_since(t) >= KEPT_LOG_EVERY);
                    if quiet {
                        self.auto.kept_logged = Some(now);
                        eprintln!(
                            "raven-node p2p: relay kept (not answering; no other offered relay \
                             may take its place now)"
                        );
                    }
                }
            }
        }
    }

    /// Write the relay memory off the swarm loop when it changed: at once
    /// for a change of the picked relays or a relay that turned us away,
    /// else at most every [`MEMORY_SAVE_EVERY`]. One write at a time.
    fn save_memory(&mut self, now: Instant) {
        let auto = &mut self.auto;
        if !auto.live || !auto.dirty {
            return;
        }
        let due = auto.urgent
            || auto
                .saved_at
                .is_none_or(|t| now.saturating_duration_since(t) >= MEMORY_SAVE_EVERY);
        if !due || auto.saving.swap(true, Ordering::SeqCst) {
            return;
        }
        auto.dirty = false;
        auto.urgent = false;
        auto.saved_at = Some(now);
        let (data_dir, mem, saving) = (
            self.data_dir.clone(),
            auto.mem.clone(),
            Arc::clone(&auto.saving),
        );
        tokio::task::spawn_blocking(move || {
            if relay_select::save_memory(&data_dir, &mem).is_err() {
                netutil::log_limited(
                    &P2P_LOG,
                    "raven-node p2p",
                    "the relay memory (relay_memory.json) could not be written; kept in memory",
                );
            }
            saving.store(false, Ordering::SeqCst);
        });
    }

    /// Shutdown: write the relay memory now if it changed since it was last
    /// written (after a write still running, so the newer one lands last).
    /// At most a second.
    async fn flush_memory(&mut self) {
        if !self.auto.live || !self.auto.dirty {
            return;
        }
        self.auto.dirty = false;
        let (data_dir, mem, saving) = (
            self.data_dir.clone(),
            self.auto.mem.clone(),
            Arc::clone(&self.auto.saving),
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), async move {
            while saving.swap(true, Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let _ = blocking(move || relay_select::save_memory(&data_dir, &mem)).await;
            saving.store(false, Ordering::SeqCst);
        })
        .await;
    }

    /// One command from the shared channel; `Some` ends this generation.
    fn on_command(&mut self, command: Command) -> Option<Ended> {
        match command {
            Command::Connect {
                peer,
                class,
                relays,
                addrs,
                checked_at,
                reply,
            } => self.connect(peer, class, relays, addrs, checked_at, reply),
            // The gate is shared by every generation: an older one's load is
            // as good.
            Command::GateLoaded(loaded) => self.gate_loaded(*loaded),
            Command::PreferDirect { peer, reply } => self.prefer_direct(peer, reply),
            Command::Resolved { gen, relay, addrs } => {
                if gen == self.gen {
                    self.on_resolved(relay, addrs);
                }
            }
            Command::Nudge => {
                let now = Instant::now();
                for slot in &mut self.slots {
                    slot.nudge(now);
                }
                for slot in &mut self.listens {
                    slot.nudge(now);
                }
            }
            // An older generation's read is as good (the files are shared).
            Command::OffersLoaded(loaded) => self.offers_loaded(loaded),
            Command::Shutdown { done } => return Some(Ended::Shutdown(done)),
        }
        None
    }

    /// Serve this endpoint until it is re-homed ([`network_changed`]), shut
    /// down, or fails. `seen`: [`REHOME_SEQ`] when it was built.
    async fn run(
        &mut self,
        commands: &mut mpsc::Receiver<Command>,
        responder: &JoinHandle<()>,
        seen: u64,
    ) -> Ended {
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            if REHOME_SEQ.load(Ordering::SeqCst) != seen {
                return Ended::Rehome(lock(&REHOME_WHY).take().unwrap_or(Rehome::Network));
            }
            tokio::select! {
                // Only wakes the loop: the check above decides.
                () = rehome_notify().notified() => continue,
                event = self.swarm.select_next_some() => {
                    // Status follows every event (a reservation, a listener),
                    // not just the tick, so `raven status` is never a second
                    // behind.
                    self.on_event(event);
                    self.answer_preferring(Instant::now());
                    self.publish();
                }
                command = commands.recv() => match command {
                    Some(command) => {
                        if let Some(ended) = self.on_command(command) {
                            return ended;
                        }
                    }
                    None => return Ended::Failed("p2p host: command channel closed".into()),
                },
                _ = tick.tick() => self.tick(),
            }
            if responder.is_finished() {
                return Ended::Failed("p2p host: the link responder stopped".into());
            }
        }
    }

    /// Listeners first (the swarm tells libp2p-upnp, which asks the router to
    /// drop the mappings it made), then every waiting dial is answered, then
    /// every connection is closed (QUIC sends its close frame, a relay frees
    /// our reservation at once). Drives the swarm until all of them are gone
    /// or `wait` passed. `upnp_grace` (shutdown): with a port mapped, it keeps
    /// driving until `wait` passed, because libp2p-upnp's gateway task
    /// completes a mapping removal only while the behaviour is there to take
    /// the answer.
    async fn close_everything(&mut self, wait: Duration, upnp_grace: bool) {
        let mut closing: HashSet<ListenerId> = self
            .listens
            .iter_mut()
            .filter_map(|l| l.listener.take())
            .collect();
        for id in &closing {
            self.swarm.remove_listener(*id);
        }
        // Their answers below say nothing about reaching the contacts.
        with_facts(DialFacts::interrupt_all);
        for reply in self.pending.drain().flat_map(|(_, replies)| replies) {
            let _ = reply.send(Err(format!(
                "{P2P_UNREACHABLE} (the network changed during the dial)"
            )));
        }
        for (_, _, reply) in self.preferring.drain(..) {
            let _ = reply.send(false);
        }
        let mut peers: HashSet<PeerId> = lock(&self.handle.conns).peers();
        for peer in &peers {
            let _ = self.swarm.disconnect_peer_id(*peer);
        }
        let linger = upnp_grace && self.upnp.starts_with("mapped");
        let deadline = Instant::now() + wait;
        while linger || !(lock(&self.handle.conns).is_empty() && closing.is_empty()) {
            match tokio::time::timeout_at(deadline, self.swarm.select_next_some()).await {
                Ok(SwarmEvent::ConnectionClosed { connection_id, .. }) => {
                    lock(&self.handle.conns).closed(connection_id);
                }
                Ok(SwarmEvent::ListenerClosed { listener_id, .. }) => {
                    closing.remove(&listener_id);
                }
                Ok(SwarmEvent::ConnectionEstablished { peer_id, .. }) => {
                    peers.insert(peer_id);
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        // The relay role's guard outlives this endpoint: whatever a peer
        // reserved here goes with it, closed in time or not.
        if let Some(role) = self.role.as_ref() {
            for peer in &peers {
                role.guard.on_peer_disconnected(peer);
            }
        }
    }
}

/// How one endpoint generation ended ([`Host::run`]).
enum Ended {
    Rehome(Rehome),
    Shutdown(oneshot::Sender<()>),
    Failed(String),
}

// ── PeerId rotation (Phase 4 P4.28) ─────────────────────────────────────

/// After a rotation, how long the relays held before it are watched for a
/// refusal of the new ID ([`RotationWatch`]).
const ROTATE_CHECK: Duration = Duration::from_secs(60);
/// A postponed rotation is tried again after this long (Unix seconds),
/// unless an epoch boundary comes first ([`Postponement`]).
const ROTATE_RETRY_S: u64 = 6 * 3600;

/// What the rotation state rests on besides the clock, read with the peer
/// gate ([`GateLoad::rotation`]): the gate, the profile's setting
/// (node_policy.json `peer_rotation`) and how many contacts cannot follow.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RotationFacts {
    /// `raven_core::peer_rotation_live_enabled`.
    live: bool,
    /// node_policy.json `peer_rotation` is on.
    setting: bool,
    /// [`raven_core::outbox::rotation_waiting_on`] (`u32::MAX` while the
    /// contact book or the block list cannot be read).
    waiting_on: u32,
    /// Since when this profile announces its coming PeerIds
    /// ([`raven_core::peer_rotation::OwnRotation`]): the first boundary after
    /// it switches the key. `None`: not ready yet.
    ready_ms: Option<u64>,
}

/// Blocking: [`RotationFacts`] now, keeping `peer_rotation_state.json` in
/// step: ready from now when the setting is on and every contact can
/// follow (and it was not already), cleared when the setting is off or,
/// before the first switch, a contact cannot follow. Once the first switch
/// of `id`'s key is made, a contact that cannot follow (a new one, or one
/// whose schedule a new card forgot) keeps `ready`: the host stays on its
/// epoch keys, since contacts that hold its epoch card admit no other
/// PeerId ([`RotationState::of`]). A book that cannot be read, or a state
/// file that cannot (a sealed one before the key is loaded), changes
/// nothing on disk. With the gate closed nothing is read or written.
fn rotation_facts(data_dir: &Path, id: Option<&Identity>) -> RotationFacts {
    rotation_facts_with(
        data_dir,
        id,
        raven_core::peer_rotation_live_enabled(),
        crate::now_ms(),
    )
}

/// [`rotation_facts`] with the rotation gate and the clock (Unix ms) as
/// arguments.
fn rotation_facts_with(
    data_dir: &Path,
    id: Option<&Identity>,
    live: bool,
    now_ms: u64,
) -> RotationFacts {
    use raven_core::peer_rotation::{load_own_rotation, save_own_rotation, OwnRotation};
    if !live {
        return RotationFacts::default();
    }
    let setting = raven_core::node_policy::load_policy(data_dir).peer_rotation == Some(true);
    let waiting_on = if setting {
        raven_core::outbox::rotation_waiting_on(data_dir).unwrap_or(u32::MAX)
    } else {
        0
    };
    let ready_ms = match load_own_rotation(data_dir) {
        Ok(own) => {
            let has_switched = id.is_some_and(|id| {
                let len = raven_core::peer_rotation::epoch_len_s();
                switched(
                    id,
                    own.ready_ms,
                    raven_core::peer_rotation::epoch_at(id, now_ms / 1000, len),
                    len,
                )
            });
            let want = match (setting, waiting_on) {
                (true, 0) => Some(own.ready_ms.unwrap_or(now_ms)),
                (true, u32::MAX) => own.ready_ms,
                (true, missing) if has_switched => {
                    netutil::log_limited(
                        &P2P_LOG,
                        "raven-node p2p",
                        format_args!(
                            "network ID rotation stays on: {missing} verified contact{} cannot \
                             follow it yet (they reach this node once they hear its route \
                             hints or get its card)",
                            if missing == 1 { "" } else { "s" }
                        ),
                    );
                    own.ready_ms
                }
                _ => None,
            };
            if want != own.ready_ms
                && save_own_rotation(data_dir, OwnRotation { ready_ms: want }).is_err()
            {
                netutil::log_limited(
                    &P2P_LOG,
                    "raven-node p2p",
                    "the PeerId rotation state (peer_rotation_state.json) could not be written; \
                     kept in memory",
                );
            }
            want
        }
        Err(_) => None,
    };
    RotationFacts {
        live: true,
        setting,
        waiting_on,
        ready_ms,
    }
}

/// A rotation rolled back (spec §8): every relay refused the ID of epoch
/// `refused`, so the host keeps the key of `epoch` (`None`: the fixed key)
/// while the clock is still in `refused` and until `retry_at` (Unix s).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Postponement {
    epoch: Option<u64>,
    refused: u64,
    retry_at: u64,
}

/// PeerId rotation as one endpoint generation applies it (evaluated at
/// every build, and again whenever the peer gate's files or the clock
/// change it: [`Host::rotation_follow`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RotationState {
    /// The gate is closed or the profile's setting is off: the fixed key.
    Off,
    /// The setting is on, but `missing` verified contacts with a p2p route
    /// have not said they can follow (no schedule with the capable bit):
    /// the fixed key.
    Waiting { missing: u32 },
    /// Every contact can follow: route hints announce the coming epoch keys
    /// (without `rotating`) while the fixed key stays until the first
    /// boundary after rotation became ready, so contacts admit the new
    /// PeerId before it is used (spec §9.1).
    Starting { epoch: u64, len_s: u64 },
    /// The key of the clock's epoch `epoch` (`len_s` seconds long).
    On { epoch: u64, len_s: u64 },
    /// Rolled back: the key of `epoch` (`None`: the fixed key) until the
    /// next boundary or `retry_at` (Unix s); `refused`: the clock's epoch,
    /// whose key the relays turned away.
    Postponed {
        epoch: Option<u64>,
        refused: u64,
        retry_at: u64,
        len_s: u64,
    },
}

impl RotationState {
    /// The state for `facts` at `now_unix`, in an epoch of `len_s` seconds
    /// whose clock epoch is `clock_epoch`; `ready_epoch`: the epoch of
    /// [`RotationFacts::ready_ms`] (rotation starts in the one after); a
    /// `postponed` rollback holds while the clock is still in the epoch it
    /// refused and before its retry.
    fn of(
        facts: RotationFacts,
        ready_epoch: Option<u64>,
        postponed: Option<Postponement>,
        clock_epoch: u64,
        len_s: u64,
        now_unix: u64,
    ) -> Self {
        if !facts.live || !facts.setting {
            return Self::Off;
        }
        // A contact that cannot follow holds rotation back only before the
        // first switch: after it, contacts that hold an epoch card admit
        // no other PeerId, so going back to the fixed key would cut them
        // off (and nothing could bring them the fixed PeerId).
        let switched = ready_epoch.is_some_and(|ready| ready < clock_epoch);
        if facts.waiting_on > 0 && !switched {
            return Self::Waiting {
                missing: facts.waiting_on,
            };
        }
        if !switched {
            return Self::Starting {
                epoch: clock_epoch,
                len_s,
            };
        }
        match postponed {
            Some(p) if p.refused == clock_epoch && now_unix < p.retry_at => Self::Postponed {
                epoch: p.epoch,
                refused: p.refused,
                retry_at: p.retry_at,
                len_s,
            },
            _ => Self::On {
                epoch: clock_epoch,
                len_s,
            },
        }
    }

    /// The epoch whose key the endpoint uses; `None`: the fixed key.
    fn key_epoch(self) -> Option<u64> {
        match self {
            Self::Off | Self::Waiting { .. } | Self::Starting { .. } => None,
            Self::On { epoch, .. } => Some(epoch),
            Self::Postponed { epoch, .. } => epoch,
        }
    }

    /// What route hints announce while an epoch key is in use: the epoch and
    /// whether it rolled back
    /// ([`raven_core::peer_rotation::announced_schedule`]); `None` with the
    /// fixed key ([`Host::announced`] adds the entries of `Starting`, and of
    /// a rollback to the fixed key).
    fn announced(self) -> Option<(u64, bool)> {
        match self {
            Self::On { epoch, .. } => Some((epoch, false)),
            Self::Postponed {
                epoch: Some(epoch), ..
            } => Some((epoch, true)),
            _ => None,
        }
    }

    /// IPC `rotation.state`.
    fn word(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Waiting { .. } => "waiting",
            Self::Starting { .. } => "starting",
            Self::On { .. } => "on",
            Self::Postponed { .. } => "postponed",
        }
    }

    /// When the key changes next (Unix s): the next boundary of `id`'s
    /// epochs, or a postponement's retry when that comes first; `None` while
    /// the key is fixed for want of a setting or of contacts.
    fn change_at(self, id: &Identity, now_unix: u64) -> Option<u64> {
        let boundary = |len: u64| raven_core::peer_rotation::next_boundary_unix(id, now_unix, len);
        match self {
            Self::Off | Self::Waiting { .. } => None,
            Self::On { len_s, .. } | Self::Starting { len_s, .. } => Some(boundary(len_s)),
            Self::Postponed {
                retry_at, len_s, ..
            } => Some(boundary(len_s).min(retry_at)),
        }
    }
}

/// The last epoch of `facts`' announcing ([`RotationFacts::ready_ms`]) for
/// `id`: the one half an epoch after it became ready, so contacts get at
/// least half an epoch to learn the coming PeerIds before the first switch.
fn ready_epoch(id: &Identity, facts: RotationFacts, len: u64) -> Option<u64> {
    ready_epoch_of(id, facts.ready_ms, len)
}

/// [`ready_epoch`] of a `ready_ms`.
fn ready_epoch_of(id: &Identity, ready_ms: Option<u64>, len: u64) -> Option<u64> {
    ready_ms
        .map(|ms| raven_core::peer_rotation::epoch_at(id, (ms / 1000).saturating_add(len / 2), len))
}

/// Has `id`'s key made its first switch by the clock's epoch `clock`
/// (rotation ready since `ready_ms`): the clock is past its last epoch of
/// announcing ([`ready_epoch`]).
fn switched(id: &Identity, ready_ms: Option<u64>, clock: u64, len: u64) -> bool {
    ready_epoch_of(id, ready_ms, len).is_some_and(|ready| ready < clock)
}

/// After a rotation: the relays held before it, each until it accepts a
/// reservation under the new ID or turns it away
/// ([`Host::rotation_refused`]), until `until`.
#[derive(Clone, Debug)]
struct RotationWatch {
    /// The key before the rotation (`None`: the fixed one).
    prev: Option<u64>,
    /// The epoch rotated to.
    epoch: u64,
    /// Relays that have neither accepted nor refused yet.
    waiting: HashSet<PeerId>,
    /// Relays that turned the new ID away.
    refused: usize,
    until: Instant,
}

/// What a generation leaves the next about rotation ([`HostSeed::rotation`]).
#[derive(Clone, Debug, Default)]
struct RotationMemory {
    facts: RotationFacts,
    postponed: Option<Postponement>,
    /// The key the last generation used and the relays it held a
    /// reservation on when it ended.
    last: Option<(Option<u64>, Vec<PeerId>)>,
}

/// The PEER_SCHEDULE route hints announce for the running host
/// ([`announced_schedule`]); `None` while no host runs.
static ANNOUNCED: Mutex<Option<raven_core::route_hints::PeerSchedule>> = Mutex::new(None);

/// What this node's route hints announce in PEER_SCHEDULE (spec §4) while
/// the rotation gate is live: the running host's schedule (its entries
/// while it uses epoch keys), else the capability alone.
pub(crate) fn announced_schedule() -> Option<raven_core::route_hints::PeerSchedule> {
    lock(&ANNOUNCED).clone()
}

/// The peer gate's clock window: while PeerId rotation is live, the
/// PeerIds a contact's schedule admits move with the clock, so the gate is
/// read again every quarter of an epoch ([`Host::poll_gate`]) even when no
/// file changed. 0 while the gate is closed.
pub(crate) fn rotation_window() -> u64 {
    if !raven_core::peer_rotation_live_enabled() {
        return 0;
    }
    let step = (raven_core::peer_rotation::epoch_len_s() / 4).max(1);
    crate::now_ms() / 1000 / step
}

impl Host {
    /// Publish what route hints announce for this generation, and (`log`)
    /// say in one counts-only line which state rotation is in.
    fn note_rotation(&self, log: bool) {
        let announced = self.announced();
        let changed = {
            let mut held = lock(&ANNOUNCED);
            let changed = *held != announced;
            *held = announced;
            changed
        };
        // Route hints carry it: contacts are told at once (the generation
        // moves).
        if changed {
            crate::hints::own_changed();
        }
        if !log {
            return;
        }
        match self.rotation {
            RotationState::Off => {}
            RotationState::Waiting { missing } => eprintln!(
                "raven-node p2p: network ID rotation waits: {} verified contact{} cannot follow it \
                 yet; keeping the fixed network ID",
                if missing == u32::MAX {
                    "the contact book cannot be read: every".to_string()
                } else {
                    missing.to_string()
                },
                if missing == 1 { "" } else { "s" }
            ),
            RotationState::Starting { .. } => eprintln!(
                "raven-node p2p: network ID rotation starts at the next epoch; telling contacts \
                 the coming network IDs first"
            ),
            RotationState::On { .. } => {
                eprintln!("raven-node p2p: network ID rotation on (a new network ID every epoch)")
            }
            RotationState::Postponed { .. } => eprintln!(
                "raven-node p2p: network ID rotation postponed; the previous network ID stays \
                 until the next epoch"
            ),
        }
    }

    /// What route hints announce for this generation while the rotation
    /// gate is live: its schedule while it uses an epoch key, else the
    /// capability alone.
    fn announced(&self) -> Option<raven_core::route_hints::PeerSchedule> {
        let len = raven_core::peer_rotation::epoch_len_s();
        self.rotation_facts
            .live
            .then(|| match (self.identity.as_deref(), self.rotation) {
                (
                    Some(id),
                    RotationState::Starting { epoch, .. }
                    | RotationState::Postponed {
                        epoch: None,
                        refused: epoch,
                        ..
                    },
                ) => {
                    // The coming keys, without `rotating`: the fixed key
                    // is still in use. A rollback to the fixed key says the
                    // same (never `postponed`, which would have contacts
                    // dial an epoch key first): contacts keep admitting
                    // the refused epoch's PeerId, which the retry uses.
                    let mut s = raven_core::peer_rotation::announced_schedule(
                        id,
                        Some((epoch, false)),
                        len,
                    );
                    s.flags &= !raven_core::route_hints::SCHEDULE_FLAG_ROTATING;
                    s
                }
                (Some(id), state) => {
                    raven_core::peer_rotation::announced_schedule(id, state.announced(), len)
                }
                (None, _) => raven_core::route_hints::PeerSchedule::capability_only(
                    u32::try_from(len).unwrap_or(u32::MAX),
                ),
            })
    }

    /// The rotation state now, from the peer gate's last facts and the
    /// clock (`boundary`: the change time [`Self::rotate_at`] came). A new
    /// key re-homes the endpoint ([`Rehome::Rotate`]); another state with
    /// the same key (a different count of contacts that cannot follow, say)
    /// only changes what status and route hints say.
    fn rotation_follow(&mut self, boundary: bool) {
        let Some(id) = self.identity.clone() else {
            return;
        };
        let now_unix = crate::now_ms() / 1000;
        let len = raven_core::peer_rotation::epoch_len_s();
        let clock = raven_core::peer_rotation::epoch_at(&id, now_unix, len);
        let ready = ready_epoch(&id, self.rotation_facts, len);
        let next = RotationState::of(
            self.rotation_facts,
            ready,
            self.postponed,
            clock,
            len,
            now_unix,
        );
        if next.key_epoch() != self.rotation.key_epoch() {
            let why = match (next, boundary) {
                (RotationState::On { .. }, true) => "network ID rotated (epoch boundary)",
                (RotationState::On { .. }, false) => "network ID rotation starts",
                (RotationState::Postponed { .. }, _) => "network ID rotation postponed",
                _ => "network ID rotation stopped; back to the fixed network ID",
            };
            eprintln!("raven-node p2p: {why}; re-homing");
            self.rotate_at = None;
            network_changed(Rehome::Rotate);
            return;
        }
        if next != self.rotation {
            self.rotation = next;
            self.note_rotation(true);
        }
        self.rotate_at = next.change_at(&id, now_unix);
    }

    /// The rotation part of a tick: the next change of key when it is due,
    /// and the end of a watch past [`ROTATE_CHECK`].
    fn tick_rotation(&mut self, now: Instant) {
        if self
            .rotate_at
            .is_some_and(|at| crate::now_ms() / 1000 >= at)
        {
            self.rotation_follow(true);
        }
        if self.rotation_watch.as_ref().is_some_and(|w| now >= w.until) {
            self.rotation_watch = None;
        }
    }

    /// `relay` turned us away at once (its peer gate: [`note_closed_at_once`]).
    /// When it is the last relay held before a rotation that had not yet
    /// accepted the new ID, and every one of them turned it away, the
    /// rotation is postponed and the endpoint goes back to the previous key
    /// ([`Rehome::RotateBack`]).
    fn rotation_refused(&mut self, relay: PeerId) {
        let Some(watch) = self.rotation_watch.as_mut() else {
            return;
        };
        if !watch.waiting.remove(&relay) {
            return;
        }
        watch.refused += 1;
        if !watch.waiting.is_empty() {
            return;
        }
        let (prev, epoch) = (watch.prev, watch.epoch);
        self.rotation_watch = None;
        self.postponed = Some(Postponement {
            epoch: prev,
            refused: epoch,
            retry_at: (crate::now_ms() / 1000).saturating_add(ROTATE_RETRY_S),
        });
        eprintln!(
            "raven-node p2p: network ID rotation postponed (every relay turned the new network \
             ID away); going back to the previous one"
        );
        network_changed(Rehome::RotateBack);
    }

    /// `relay` accepted a reservation: a rotation it was watched for stands.
    fn rotation_accepted(&mut self, relay: PeerId) {
        if self
            .rotation_watch
            .as_ref()
            .is_some_and(|w| w.waiting.contains(&relay))
        {
            self.rotation_watch = None;
        }
    }

    /// IPC `rotation` while the rotation gate is live.
    fn rotation_status(&self) -> Option<raven_core::ipc::RotationStatus> {
        if !self.rotation_facts.live {
            return None;
        }
        let now_unix = crate::now_ms() / 1000;
        Some(raven_core::ipc::RotationStatus {
            state: self.rotation.word().into(),
            waiting_on: match self.rotation {
                RotationState::Waiting { missing } => missing,
                _ => 0,
            },
            epoch: self.rotation.key_epoch(),
            epoch_len_s: raven_core::peer_rotation::epoch_len_s(),
            next_change_s: self.rotate_at.map(|at| at.saturating_sub(now_unix)),
        })
    }
}

/// The local state the responder needs, loaded once per host start: the
/// identity (also the libp2p key's seed), a current prekey (its RLB1 offer)
/// and the session store opened (so the host is not reported up while every
/// inbound frame would fail). The durable-state upkeep is the LAN listener's
/// (it always runs in the service); the files it reads are not read while
/// another pass rewrites them ([`netutil::durable_pass`]).
fn preflight(data_dir: &Path) -> Result<Identity, String> {
    P2P_LINK.require_live()?;
    let _pass = netutil::durable_pass();
    let identity = raven_core::load_identity_required(data_dir).map_err(|e| e.to_string())?;
    raven_core::ensure_local_prekey(data_dir, &identity)?;
    let _ = raven_core::IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    Ok(identity)
}

/// What every endpoint generation is built from: the parts made once per
/// host start ([`run_host`]). The command channel outlives the generations,
/// so a dial queued during a re-home is served by the next one; so do the
/// peer gate's set (with its dial admissions) and the relay role's guard
/// (with its allow-list and rate tables): a re-home never touches them.
struct HostSeed<'a> {
    gate: &'a HostGate,
    keypair: Keypair,
    data_dir: PathBuf,
    config: P2pConfig,
    source: String,
    commands: mpsc::Sender<Command>,
    /// `service --relay`: its limits, guard and `--relay-open`.
    role: Option<(RelayLimits, RelayGuard, bool)>,
    /// Who may connect ([`gate_files`]); with the relay role its listed
    /// members too.
    peers: GateHandle,
    /// The files as `peers` was first read from them.
    peers_stamp: GateStamp,
    /// The ping interval and timeout instead of the defaults
    /// (`RAVEN_LAB_P2P_PING`, [`lab_ping`]).
    ping: Option<(Duration, Duration)>,
    /// The listen addresses open in an earlier generation
    /// ([`Self::remember_open_listens`]): one on no interface after a
    /// re-home went away and is retried until it is back
    /// ([`ListenSlot::opened_before`]).
    listens_opened: Mutex<HashSet<Multiaddr>>,
    /// Automatic relay choice as the last generation left it
    /// ([`Self::keep_auto`]): the next one starts from its relays.
    auto: Mutex<AutoRelays>,
    /// The configured relays a generation took from node_policy.json's
    /// sealed sidecar once it could be read ([`Self::keep_relays`]): the
    /// next ones use them instead of `config.relays`.
    policy_relays: Mutex<Option<Vec<ViaAddr>>>,
    /// Its proxy setting, likewise ([`P2pProxy::pending`]).
    policy_proxy: Mutex<Option<P2pProxy>>,
    /// Restricted network (RWS1 §9), one flag per host start: every
    /// generation's [`EndpointConfig::restricted`] and [`HostHandle`] hold
    /// this one, so a re-home keeps it until the new generation's slots
    /// decide again ([`Host::note_restricted`]).
    restricted: Arc<AtomicBool>,
    /// The proxy of WSS relay dials (RWS1 §8), one per host start, from
    /// [`P2pConfig::proxy`]; every generation reads its sources again
    /// ([`ProxySource::invalidate`]).
    proxy: Arc<ProxySource>,
    /// Router port mapping's parts made once: the profile's nonce key
    /// (`raven_core::portmap::nonce_key`), else [`PortMapConfig::upnp_only`].
    port_map_base: PortMapConfig,
    /// What every generation reads again to set up router port mapping
    /// ([`RouterLookup`]).
    router: RouterLookup,
    /// Contacts' NAT classes as the peer gate last read them
    /// ([`GateLoad::nat_remote`], [`Self::keep_nat_remote`]): each
    /// generation's fresh hole-punch policy starts from them.
    nat_remote: Mutex<Vec<(PeerId, raven_core::route_hints::NatClass, u64)>>,
    /// Phase 4 PeerId rotation: the identity the epoch keys come from;
    /// `None` (tests) keeps [`Self::keypair`], the fixed key, always.
    identity: Option<Arc<Identity>>,
    /// Rotation as the last generation left it ([`Self::keep_rotation`]).
    rotation: Mutex<RotationMemory>,
}

/// What every endpoint generation reads again to set up router port mapping
/// with the PORT_MAP gate open (a network change may bring another router):
/// the PORT_MAP and V6_PINHOLE gates, the default routers and the egress
/// IPv6 address. Tests replace them.
#[derive(Clone, Copy)]
struct RouterLookup {
    /// `(port_map_live_enabled, v6_pinhole_live_enabled)`.
    gates: fn() -> (bool, bool),
    gateways: fn() -> raven_core::gateway::Gateways,
    /// The egress IPv4 address ([`PortMapConfig::egress_v4`]).
    egress_v4: fn() -> Option<Ipv4Addr>,
    egress_v6: fn() -> Option<Ipv6Addr>,
    /// A harness names the router (`RAVEN_LAB_PORTMAP_GATEWAY`, debug
    /// builds only): no UPnP, whose search would reach the real router
    /// ([`PortMapConfig::upnp_fallback`]; review E-2).
    lab_gateway: fn() -> bool,
}

impl Default for RouterLookup {
    fn default() -> Self {
        Self {
            gates: || {
                (
                    raven_core::port_map_live_enabled(),
                    raven_core::v6_pinhole_live_enabled(),
                )
            },
            gateways: raven_core::gateway::default_gateways,
            egress_v4: || lab_egress_v4().or_else(|| raven_core::route_memory::egress_addrs().0),
            egress_v6: || lab_egress_v6().or_else(|| raven_core::route_memory::egress_addrs().1),
            lab_gateway: || raven_core::portmap_gate::lab_portmap_gateway().is_some(),
        }
    }
}

/// The source address toward the IPv4 router a harness names
/// (`RAVEN_LAB_PORTMAP_GATEWAY`, debug builds only, else `None`): the
/// egress IPv4 address of the lab, so a fake gateway on 127.0.0.1 counts as
/// on the Internet path. Nothing is sent.
fn lab_egress_v4() -> Option<Ipv4Addr> {
    let gw = raven_core::portmap_gate::lab_portmap_gateway()?.v4?;
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect(std::net::SocketAddr::V4(gw)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if !ip.is_unspecified() => Some(ip),
        _ => None,
    }
}

/// The source address toward the IPv6 router a harness names
/// (`RAVEN_LAB_PORTMAP_GATEWAY`, debug builds only, else `None`): a fake
/// gateway on `[::1]` gets a pinhole asked for `::1`, which the default
/// route (toward 2001:db8::1) would never give. Nothing is sent.
fn lab_egress_v6() -> Option<Ipv6Addr> {
    let gw = raven_core::portmap_gate::lab_portmap_gateway()?.v6?;
    let socket = std::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect(std::net::SocketAddr::V6(gw)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V6(ip) if !ip.is_unspecified() => Some(ip),
        _ => None,
    }
}

impl<'a> HostSeed<'a> {
    /// `loaded`: the peer gate's first set ([`load_gate`], read off the
    /// async loop by the caller); `auto`: the offers and the relay memory
    /// ([`AutoRelays::load`], likewise). The relays automatic choice held
    /// before a restart are taken again while they are offered
    /// ([`AutoRelays::start`]), admitted by the peer gate from the start.
    #[allow(clippy::too_many_arguments)]
    fn new(
        gate: &'a HostGate,
        keypair: Keypair,
        data_dir: PathBuf,
        config: P2pConfig,
        source: String,
        commands: mpsc::Sender<Command>,
        loaded: GateLoad,
        mut auto: AutoRelays,
        port_map_base: PortMapConfig,
    ) -> Self {
        let role = config.relay_server.map(|open| {
            let limits = if open {
                RelayLimits::open()
            } else {
                RelayLimits::friends()
            };
            let guard = RelayGuard::new(crate::relay::allow_policy(&data_dir, open), &limits);
            (limits, guard, open)
        });
        // With the relay role its listed members are admitted too.
        let peers = GateHandle::new(role.as_ref().map(|(_, guard, _)| guard.clone()));
        peers.replace(loaded.files, loaded.unreadable, loaded.read_at);
        auto.start(
            &keypair.public().to_peer_id(),
            &config.relays,
            crate::now_ms(),
        );
        let picked: Vec<PeerId> = auto
            .picked
            .iter()
            .filter_map(|(via, _)| via.peer_id.parse().ok())
            .collect();
        peers.set_auto_relays(&picked);
        Self {
            gate,
            keypair,
            data_dir,
            source,
            commands,
            role,
            peers,
            peers_stamp: loaded.stamp,
            ping: lab_ping(),
            listens_opened: Mutex::new(HashSet::new()),
            auto: Mutex::new(auto),
            policy_relays: Mutex::new(None),
            policy_proxy: Mutex::new(None),
            restricted: Arc::new(AtomicBool::new(false)),
            proxy: Arc::new(ProxySource::new(config.proxy.setting.clone())),
            port_map_base,
            router: RouterLookup::default(),
            nat_remote: Mutex::new(loaded.nat_remote),
            identity: None,
            rotation: Mutex::new(RotationMemory {
                facts: loaded.rotation.unwrap_or_default(),
                ..RotationMemory::default()
            }),
            config,
        }
    }

    /// A generation ends: the next one starts from its rotation facts and
    /// rollback, and knows the key and the relays it ended with (a
    /// rotation then watches those relays, [`RotationWatch`]).
    fn keep_rotation(&self, host: &Host) {
        let relays = host
            .slots
            .iter()
            .filter(|s| s.active)
            .map(|s| s.peer)
            .collect();
        *lock(&self.rotation) = RotationMemory {
            facts: host.rotation_facts,
            postponed: host.postponed,
            last: Some((host.rotation.key_epoch(), relays)),
        };
    }

    /// The rotation state and the key of a generation built now, with the
    /// relays a rotation to a new epoch watches ([`RotationWatch`]).
    fn rotation_now(
        &self,
        now: Instant,
    ) -> (RotationState, Keypair, Option<RotationWatch>, Option<u64>) {
        let Some(id) = self.identity.as_deref() else {
            return (RotationState::Off, self.keypair.clone(), None, None);
        };
        let mem = lock(&self.rotation).clone();
        let now_unix = crate::now_ms() / 1000;
        let len = raven_core::peer_rotation::epoch_len_s();
        let clock = raven_core::peer_rotation::epoch_at(id, now_unix, len);
        let ready = ready_epoch(id, mem.facts, len);
        let state = RotationState::of(mem.facts, ready, mem.postponed, clock, len, now_unix);
        let keypair = match state.key_epoch() {
            Some(e) => raven_swarm::kad_node::libp2p_keypair_for_epoch(id, Some(e)),
            None => self.keypair.clone(),
        };
        let watch = match (state, mem.last) {
            (RotationState::On { epoch, .. }, Some((prev, relays)))
                if prev != Some(epoch) && !relays.is_empty() =>
            {
                Some(RotationWatch {
                    prev,
                    epoch,
                    waiting: relays.into_iter().collect(),
                    refused: 0,
                    until: now + ROTATE_CHECK,
                })
            }
            _ => None,
        };
        (state, keypair, watch, state.change_at(id, now_unix))
    }

    /// The contacts' NAT classes the last generation held: the next one's
    /// policy starts from them (a re-home reads no gate files).
    fn keep_nat_remote(&self, nat_remote: &[(PeerId, raven_core::route_hints::NatClass, u64)]) {
        *lock(&self.nat_remote) = nat_remote.to_vec();
    }

    /// Router port mapping for one generation, with the consent `upnp` and
    /// `v6_pinhole` of `config`: `None` while the PORT_MAP gate is closed
    /// (UPnP-IGD exactly as in Phase 1, [`PortMapConfig::upnp_only`]) or no
    /// consent was given. Otherwise the routers, the egress IPv6 address and
    /// the gates are read again here, so every network change searches
    /// anew. The second value is IPC `port_map`'s starting state while the
    /// gate is open. While a harness names the router (review E-2) UPnP
    /// never runs: with the gate closed the config then says only that.
    fn port_map_config(
        &self,
        config: &P2pConfig,
        any_ip: bool,
    ) -> (Option<PortMapConfig>, Option<PortMapState>) {
        let (pcp, v6_gate) = (self.router.gates)();
        let upnp_fallback = !(self.router.lab_gateway)();
        if !pcp {
            let confined = PortMapConfig {
                upnp_fallback,
                ..PortMapConfig::upnp_only()
            };
            return ((!upnp_fallback).then_some(confined), None);
        }
        let upnp = config.upnp == Some(true);
        let v6_wanted = upnp && v6_gate && config.v6_pinhole == Some(true);
        if !upnp {
            return (None, Some(PortMapState::new(false, false, false)));
        }
        let gw = (self.router.gateways)();
        let egress_v6 = if v6_wanted {
            (self.router.egress_v6)()
        } else {
            None
        };
        let lab = raven_core::portmap_gate::lab_portmap_gateway();
        let gw_port = lab
            .and_then(|g| g.v4.map(|a| a.port()).or(g.v6.map(|a| a.port())))
            .unwrap_or(raven_core::portmap::PCP_PORT);
        let cfg = PortMapConfig {
            gw_v4: gw.v4,
            gw_v6: gw.v6,
            egress_v4: gw.v4.and_then(|_| (self.router.egress_v4)()),
            egress_v6,
            pcp,
            v6: v6_wanted && egress_v6.is_some(),
            lifetime: raven_core::portmap_gate::lab_portmap_lifetime()
                .unwrap_or(raven_core::portmap::REQUESTED_LIFETIME_S),
            any_ip,
            gw_port,
            upnp_fallback,
            ..self.port_map_base.clone()
        };
        let state = PortMapState::new(true, cfg.v6, v6_wanted);
        (Some(cfg), Some(state))
    }

    /// A generation ends: when it took the relays node_policy.json's sealed
    /// sidecar names ([`P2pConfig::policy_relays_pending`]), the next ones
    /// start with them; its proxy setting likewise ([`P2pProxy::pending`]).
    fn keep_relays(&self, config: &P2pConfig) {
        if self.config.policy_relays_pending && !config.policy_relays_pending {
            *lock(&self.policy_relays) = Some(config.relays.clone());
        }
        if self.config.proxy.pending && !config.proxy.pending {
            *lock(&self.policy_proxy) = Some(config.proxy.clone());
        }
    }

    /// A generation ends: the next one starts from its automatic relay
    /// choice (the offers, the memory, the relays picked).
    fn keep_auto(&self, auto: &AutoRelays) {
        *lock(&self.auto) = auto.clone();
    }

    /// A generation ends: remember which listen addresses it had open.
    fn remember_open_listens(&self, listens: &[ListenSlot]) {
        let mut opened = lock(&self.listens_opened);
        for slot in listens.iter().filter(|l| l.open) {
            opened.insert(slot.addr.clone());
        }
    }

    /// A fresh endpoint, generation `gen`: its own swarm (and with it UPnP,
    /// AutoNAT, DCUtR and Identify state) and advertiser on the seed's peer
    /// gate and relay guard, the listeners opened and a reservation
    /// requested on every configured relay. `rehomed`: an earlier generation
    /// may still hold the listen ports for a moment, so a busy one is retried
    /// quietly at first.
    fn build(
        &self,
        gen: u64,
        rehomed: bool,
    ) -> Result<(Host, IncomingStreams, Arc<HostHandle>), String> {
        let mut config = self.config.clone();
        if let Some(relays) = lock(&self.policy_relays).clone() {
            config.relays = relays;
            config.policy_relays_pending = false;
        }
        if let Some(proxy) = lock(&self.policy_proxy).clone() {
            config.proxy = proxy;
        }
        let config = &config;
        // A re-home follows a network change, which may bring its own proxy.
        self.proxy.invalidate();
        let wss_live = raven_core::wss_live_enabled();
        let role = self.role.clone();
        let now = Instant::now();
        // Phase 4 PeerId rotation: the key of the epoch in use, or the fixed
        // one.
        let (rotation, keypair, rotation_watch, rotate_at) = self.rotation_now(now);
        let peer_id = keypair.public().to_peer_id();
        let groups = p2p_route::group_relays(&config.relays);
        let is_me =
            |(peer, _): &(String, Vec<ViaAddr>)| peer.parse::<PeerId>().ok() == Some(peer_id);
        if gen == 0 && groups.iter().take(p2p_route::MAX_VIA).any(is_me) {
            eprintln!("p2p failed: a configured relay is this node itself; skipped");
        }
        let mut slots = relay_slots(groups, peer_id)?;
        // Then the relays automatic choice holds, each at every address it
        // is offered at; their loss clocks start with this generation.
        let auto = lock(&self.auto).clone();
        for (via, source) in &auto.picked {
            let Ok(relay) = via.peer_id.parse::<PeerId>() else {
                continue;
            };
            if relay == peer_id
                || slots.len() >= p2p_route::MAX_VIA
                || slots.iter().any(|s| s.peer == relay)
            {
                continue;
            }
            if let Ok(slot) = RelaySlot::new(relay, auto.addrs_of(via), source.clone(), now) {
                slots.push(slot);
            }
        }
        // Each relay slot's relay tests our addresses with a client of its
        // own (AutoNAT v2).
        let autonat_servers = autonat_servers(&slots);
        // Hole punching offers and dials global addresses only, except in
        // the debug lab.
        let lab_local = raven_core::p2p_local_candidates_enabled();
        if lab_local && gen == 0 {
            eprintln!(
                "raven-node p2p: lab hole punching also offers and dials loopback and private \
                 addresses (debug build)"
            );
        }
        let (port_map, port_map_state) = self.port_map_config(config, lab_local);
        // Phase 4: NAT mapping classes and the hole-punch skip, while the
        // NAT_CLASS gate is live (debug lab only).
        let nat_live = raven_core::nat_class_live_enabled();
        if nat_live && gen == 0 {
            eprintln!("raven-node p2p: lab NAT mapping classes and hole-punch skips (debug build)");
        }
        let mut endpoint = EndpointConfig {
            upnp: config.upnp == Some(true),
            port_map,
            relay_server: role.as_ref().map(|(l, g, _)| (*l, g.clone())),
            gate: self.peers.clone(),
            hole_punch_addrs: if lab_local {
                AddrRule::LabAnyIp
            } else {
                AddrRule::GlobalOnly
            },
            autonat_servers,
            punch_policy: nat_live,
            restricted: self.restricted.clone(),
            // Relays over WebSocket/TLS (RWS1), through the seed's proxy
            // where one applies: only while the WSS gate is live.
            wss: wss_live.then(|| wss::ClientSide {
                tls: wss::tls::client_tls(),
                proxy: Some(Arc::clone(&self.proxy) as Arc<dyn ProxyLookup>),
            }),
            ..EndpointConfig::default()
        };
        if gen == 0 && wss_live {
            eprintln!(
                "raven-node p2p: lab relays over WebSocket/TLS (debug build){}",
                if raven_core::wss_proxy_live_enabled() {
                    ", through an HTTPS proxy where one applies"
                } else {
                    ""
                }
            );
        }
        if gen == 0
            && matches!(config.proxy.setting, ProxySetting::Url(_))
            && !raven_core::wss_proxy_live_enabled()
        {
            eprintln!(
                "raven-node p2p: {} (the proxy from {} is not used)",
                raven_core::WSS_PROXY_HOLD,
                config.proxy.source
            );
        }
        if let Some((interval, timeout)) = self.ping {
            if gen == 0 {
                eprintln!(
                    "raven-node p2p: lab ping every {}s, timeout {}s (debug build)",
                    interval.as_secs(),
                    timeout.as_secs()
                );
            }
            endpoint.ping_interval = interval;
            endpoint.ping_timeout = timeout;
        }
        let ping_round = endpoint.ping_interval + endpoint.ping_timeout;
        if gen == 0 && rotation != RotationState::Off {
            eprintln!("raven-node p2p: lab PeerId rotation (debug build)");
        }
        let mut swarm = build_endpoint_swarm(self.gate, keypair, endpoint)
            .map_err(|e| format!("p2p host: {e}"))?;
        // Phase 6b S5: its refusals are noted against the remote IP (gated:
        // nothing is installed while the security events gate is shut),
        // except while its set cannot be read (E1: the book held while the
        // at-rest key loads judges nobody).
        swarm
            .behaviour_mut()
            .peer_gate
            .set_refusal_hook(crate::security::p2p_gate_hook_of(self.peers.clone()));
        // Phase 6b R1: a direct inbound source the penalty box banned is
        // refused before Noise (nothing is installed while the responses
        // gate is shut).
        swarm
            .behaviour_mut()
            .peer_gate
            .set_admit_hook(crate::security::p2p_admit_hook());
        // ... and a contact's own direct inbound connection clears its source,
        // as on the TCP listeners (Phase 6 review sensing-7).
        swarm
            .behaviour_mut()
            .peer_gate
            .set_authenticated_hook(crate::security::p2p_authenticated_hook());
        let grace_until = listen_grace(rehomed, crate::lock::unlocked_within(REBIND_GRACE), now);
        let mut listens = Vec::new();
        for text in config.listen.multiaddrs() {
            let addr: Multiaddr = text.parse().map_err(|e| format!("p2p listen: {e}"))?;
            let opened_before = lock(&self.listens_opened).contains(&addr);
            listens.push(ListenSlot::new(addr, grace_until, opened_before));
        }
        let listen_is_specific =
            matches!(config.listen, P2pListen::One(a) if !a.ip().is_unspecified());
        let mut control = swarm.behaviour().stream.new_control();
        let incoming = control
            .accept(RAVEN_LINK_PROTOCOL)
            .map_err(|_| "p2p: the Raven link protocol is already registered".to_string())?;
        let handle = Arc::new(HostHandle {
            commands: self.commands.clone(),
            control,
            links: Mutex::new(HashMap::new()),
            conns: Mutex::new(ConnTable::default()),
            wss: wss_live,
            proxy: Arc::clone(&self.proxy),
            restricted: self.restricted.clone(),
        });
        let role = role.map(|(_, guard, open)| RelayRole {
            guard,
            open,
            data_dir: self.data_dir.clone(),
            circuits: 0,
            circuits_refused: 0,
            reservations_refused: 0,
            last_reload: now,
            advertiser: RelayAdvertiser::new(&mut swarm, listen_is_specific, &[]),
        });
        // Only the relays this generation reserves on again are watched.
        // One lock: a struct literal keeps each guard to its end.
        let (rotation_facts, postponed) = {
            let mem = lock(&self.rotation);
            (mem.facts, mem.postponed)
        };
        let rotation_watch = rotation_watch
            .map(|mut w| {
                w.waiting.retain(|r| slots.iter().any(|s| s.peer == *r));
                w
            })
            .filter(|w| !w.waiting.is_empty());
        let mut host = Host {
            swarm,
            gen,
            commands: self.commands.clone(),
            data_dir: self.data_dir.clone(),
            gate: self.peers.clone(),
            gate_stamp: self.peers_stamp,
            gate_loading: false,
            config: config.clone(),
            source: self.source.clone(),
            slots,
            listens,
            role,
            pending: HashMap::new(),
            handle: Arc::clone(&handle),
            opened: HashMap::new(),
            upgraded: HashSet::new(),
            preferring: Vec::new(),
            listen_addrs: Vec::new(),
            nat: NatTally::default(),
            server_groups: HashMap::new(),
            last_reach: None,
            upnp: upnp_initial(config.upnp),
            port_map: port_map_state,
            peer_id,
            relay_loss: RelayLoss::default(),
            ping_round,
            fresh_port: HashSet::new(),
            auto,
            next_select: now + SELECT_EVERY,
            last_ok: None,
            autonat_built: autonat_servers,
            autonat_stale_since: None,
            idle_since: None,
            proxy_auth: "",
            nat_class: nat_live.then(NatClassifier::new),
            conn_meta: HashMap::new(),
            dial_families: HashMap::new(),
            nat_seen: NatSummary::default(),
            punch_skips_seen: 0,
            punch_failed: 0,
            nat_remote: lock(&self.nat_remote).clone(),
            rotation,
            rotation_facts,
            postponed,
            rotate_at,
            rotation_watch,
            identity: self.identity.clone(),
            gate_window: rotation_window(),
            dialled: HashMap::new(),
            punch_live: raven_core::serverless_punch_live_enabled(),
            punch_targets: Vec::new(),
            punch_inflight: HashMap::new(),
        };
        // A new endpoint: a new network for the punch schedule.
        with_punch(|p| p.book.reset());
        host.note_rotation(gen == 0);
        host.apply_nat_remote();
        open_listeners(&mut host.swarm, &mut host.listens, now);
        for i in 0..host.slots.len() {
            if nat_live && gen == 0 && !host.listens.is_empty() {
                // Once the listeners are registered for port reuse.
                host.slots[i].retry_at = Some(now + NAT_LISTEN_WAIT);
            } else {
                host.start_reservation(i);
            }
        }
        Ok((host, incoming, handle))
    }
}

/// The service's libp2p host (supervised in `main`). Never returns `Ok`;
/// after a clean shutdown it parks. The gate, the preflight and the key are
/// done once; the endpoint is rebuilt whenever it is re-homed.
pub(crate) async fn run_host(
    data_dir: PathBuf,
    mut config: P2pConfig,
    source: String,
) -> Result<(), String> {
    let gate = HostGate::open(raven_core::p2p_live_enabled())
        .map_err(|_| raven_core::P2P_HOLD.to_string())?;
    let identity = Arc::new(
        netutil::retry_until_ok("p2p", || {
            let dd = data_dir.clone();
            async move {
                netutil::with_slow_notice(
                    "p2p",
                    "local state preflight (identity, prekey, session store)",
                    blocking(move || preflight(&dd)),
                )
                .await
            }
        })
        .await,
    );
    let keypair = raven_swarm::kad_node::libp2p_keypair_from_raven(&identity);
    let (commands, mut command_rx) = mpsc::channel(64);
    // The peer gate's first set, read off the async loop (with the relays
    // node_policy.json's sealed sidecar names, if it opens by now).
    let mut loaded = {
        let (dd, relays) = (data_dir.clone(), config.relays.clone());
        let (pending, proxy_pending) = (config.policy_relays_pending, config.proxy.pending);
        let id = Arc::clone(&identity);
        blocking(move || {
            Ok(load_gate_for(
                &dd,
                &relays,
                pending,
                proxy_pending,
                Some(&id),
            ))
        })
        .await?
    };
    if let Some(relays) = loaded.policy_relays.take() {
        config.relays = relays;
        config.policy_relays_pending = false;
    }
    if let Some(text) = loaded.policy_proxy.take() {
        take_policy_proxy(&mut config.proxy, &text);
    }
    if loaded.unreadable {
        eprintln!("{GATE_UNREADABLE}");
    }
    // The relays contacts offer and the relay memory, likewise (only while
    // automatic relay choice is live).
    let auto = {
        let (dd, me, live) = (
            data_dir.clone(),
            keypair.public().to_peer_id(),
            config.auto.is_some(),
        );
        blocking(move || Ok(AutoRelays::load(&dd, &me, live))).await?
    };
    let port_map_base = PortMapConfig {
        nonce_key: raven_core::portmap::nonce_key(&identity),
        ..PortMapConfig::upnp_only()
    };
    let mut seed = HostSeed::new(
        &gate,
        keypair,
        data_dir.clone(),
        config,
        source,
        commands,
        loaded,
        auto,
        port_map_base,
    );
    // Phase 4: the epoch keys come from the profile's identity.
    seed.identity = Some(Arc::clone(&identity));
    let mut gate_stamp = seed.peers_stamp;
    let _running = RunningGuard;
    let (mut gen, mut rehomed): (u64, Option<Rehome>) = (0, None);
    loop {
        // Read before the build: a request made while it runs re-homes again.
        let seen = REHOME_SEQ.load(Ordering::SeqCst);
        // Auto-reach (gated): ask STUN servers from the p2p QUIC port before
        // libp2p binds it, so the answer is that port's own public endpoint.
        crate::autoreach::anchor(&data_dir, &seed.config.listen.multiaddrs()).await;
        let (mut host, incoming, handle) = seed.build(gen, rehomed.is_some())?;
        // The peer gate outlives the generations, and so does what it was
        // last read from.
        host.gate_stamp = gate_stamp;
        *lock(&HOST) = Some(Arc::clone(&handle));
        host.publish();
        let responder = tokio::spawn(serve_streams(
            incoming,
            data_dir.clone(),
            Arc::clone(&identity),
            Arc::clone(&handle),
        ));
        match rehomed {
            None => {
                if host.config.retired_relay {
                    eprintln!(
                        "raven-node p2p: {}; listening on {} (TCP and QUIC, IPv4 and IPv6)",
                        p2p_route::RELAY_LISTEN_RETIRED,
                        p2p_route::DEFAULT_P2P_PORT
                    );
                }
                eprintln!(
                    "raven-node p2p: host up (listeners={}, relays={}{})",
                    host.listens.iter().filter(|l| l.open).count(),
                    host.slots.len(),
                    match &host.role {
                        Some(r) if r.open => {
                            ", relaying for any verified contact (the peer gate keeps strangers out)"
                        }
                        Some(_) => ", relaying between the peers on its allow-list",
                        None => "",
                    }
                );
                if host.role.as_ref().is_some_and(|r| r.open) {
                    eprintln!(
                        "raven-node p2p: OPEN relay role: any verified contact may reserve and \
                         relay through this host, and they all learn its PeerId (stricter limits \
                         apply)"
                    );
                }
                crate::outbox::listener_up();
                crate::custody::kick();
            }
            Some(why) => {
                eprintln!(
                    "raven-node p2p: re-homed ({}): listeners={}, relays={}",
                    why.text(),
                    host.listens.iter().filter(|l| l.open).count(),
                    host.slots.len()
                );
                // netwatch restarted the outbox's backoff for a network
                // change; a path loss, new relays or a new network ID is
                // none, so what waits is only kicked.
                if matches!(
                    why,
                    Rehome::PathLoss
                        | Rehome::Relays
                        | Rehome::Rotate
                        | Rehome::RotateBack
                        | Rehome::PublicAddress
                ) {
                    crate::outbox::listener_up();
                }
            }
        }
        let ended = host.run(&mut command_rx, &responder, seen).await;
        responder.abort();
        gate_stamp = host.gate_stamp;
        seed.remember_open_listens(&host.listens);
        seed.keep_auto(&host.auto);
        seed.keep_relays(&host.config);
        seed.keep_nat_remote(&host.nat_remote);
        seed.keep_rotation(&host);
        match ended {
            Ended::Rehome(why) => {
                host.close_everything(REHOME_DRAIN, false).await;
                drop(host);
                // The next link to each peer logs its kind again.
                *lock(&LINK_KINDS) = None;
                gen += 1;
                rehomed = Some(why);
            }
            Ended::Shutdown(done) => {
                host.close_everything(SHUTDOWN_DRAIN, true).await;
                host.flush_memory().await;
                drop(host);
                let _ = done.send(());
                // The process is about to exit: never restart.
                return std::future::pending().await;
            }
            Ended::Failed(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> String {
        p2p_route::local_peer_id(&Identity::from_seed(&[seed; 32]))
    }

    #[test]
    fn admission_key_is_stable_and_distinct_per_peer() {
        let a: PeerId = peer(1).parse().unwrap();
        let b: PeerId = peer(2).parse().unwrap();
        assert_eq!(admission_ip(&a), admission_ip(&a));
        assert_ne!(
            netutil::admission_key(admission_ip(&a)),
            netutil::admission_key(admission_ip(&b))
        );
        match admission_ip(&a) {
            IpAddr::V6(v6) => assert_eq!(v6.octets()[0], 0xfd),
            IpAddr::V4(_) => panic!("must be a ULA"),
        }
    }

    /// Learning's static waits (Phase 6a, `learning::wait`) are today's
    /// waits: a learned wait is clamped to them, so they must not drift.
    #[test]
    fn learning_static_waits_equal_the_node_constants() {
        use raven_core::learning::wait;
        use raven_core::outbox::OutboxCarrier;
        assert_eq!(wait::STATIC_CONNECT_PER_ADDR, netutil::CONNECT_TIMEOUT);
        assert_eq!(wait::STATIC_P2P_CONNECT, CONNECT_DEADLINE);
        assert_eq!(wait::STATIC_NEARBY_CONNECT, crate::nearby::CONNECT_BUDGET);
        assert_eq!(
            wait::STATIC_REPLY_FIRST,
            netutil::PRODUCTION_REPLY_WAITS.first
        );
        for (carrier, connect) in [
            (OutboxCarrier::Lan, netutil::CONNECT_TIMEOUT),
            (OutboxCarrier::Internet, netutil::CONNECT_TIMEOUT),
            (OutboxCarrier::P2p, CONNECT_DEADLINE),
            (OutboxCarrier::Nearby, crate::nearby::CONNECT_BUDGET),
        ] {
            let s = wait::statics(carrier);
            assert_eq!(
                (s.connect, s.reply_first, s.learned),
                (connect, netutil::PRODUCTION_REPLY_WAITS.first, false),
                "{carrier:?}"
            );
        }
    }

    /// P6.13: with learning off (gate shut, or the switch off) every
    /// carrier's waits are today's, byte for byte: the same values, the
    /// same dial progress, and the same error texts (a refused connect, a
    /// connect wait that ran out, the p2p connect deadline).
    #[tokio::test]
    async fn waits_are_static_when_off_byte_for_byte() {
        use crate::learning::{waits, Expired, TestService};
        use crate::netutil::{ConnectWait, CONNECT_BUDGET, CONNECT_TIMEOUT};
        use raven_core::learning::wait;
        let contact = [0x6b; 32];
        for off in ["gate shut", "switch off"] {
            let _t = TestService::install(off == "switch off");
            for (carrier, label, today) in [
                (
                    OutboxCarrier::Lan,
                    "LAN",
                    DialProgress::new("LAN", netutil::PRODUCTION_REPLY_WAITS),
                ),
                (
                    OutboxCarrier::Internet,
                    "INTERNET",
                    DialProgress::new("INTERNET", netutil::PRODUCTION_REPLY_WAITS),
                ),
            ] {
                let w = waits(&contact, carrier);
                assert_eq!(w, wait::statics(carrier), "{off}");
                let p = DialProgress::waiting(label, &w);
                assert_eq!(p.collector.waits(), today.collector.waits(), "{off}");
                assert_eq!(p.connect.within, today.connect.within, "{off}");
                assert_eq!(p.connect.within, CONNECT_TIMEOUT);
            }
            let w = waits(&contact, OutboxCarrier::P2p);
            assert_eq!(w, wait::statics(OutboxCarrier::P2p), "{off}");
            let p = DialProgress::waiting(P2P_LINK.wire, &w);
            assert_eq!(p.connect.within, CONNECT_DEADLINE, "{off}");
            assert_eq!(
                p.collector.waits(),
                netutil::PRODUCTION_REPLY_WAITS,
                "{off}"
            );
            assert_eq!(p.expired(), Expired::default());
        }
        // The p2p connect deadline's words, as today.
        assert_eq!(
            connect_timed_out(CONNECT_DEADLINE),
            format!(
                "{P2P_UNREACHABLE} (connect timed out after {}s)",
                CONNECT_DEADLINE.as_secs()
            )
        );
        // A learned wait names itself.
        assert!(connect_timed_out(Duration::from_millis(8_400)).ends_with("after 8.4s)"));
        // A refused connect: the same text through either function.
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let refused = free.local_addr().unwrap().to_string();
        drop(free);
        let wait = ConnectWait::new(CONNECT_TIMEOUT);
        assert_eq!(
            netutil::connect_dial_within(&refused, &wait, CONNECT_BUDGET)
                .await
                .unwrap_err(),
            netutil::connect_dial(&refused, CONNECT_TIMEOUT, CONNECT_BUDGET)
                .await
                .unwrap_err()
        );
        assert!(!wait.expired(), "refused is no expiry");
        // A connect wait that ran out: the same text, and only the waiting
        // one remembers it.
        let Some((hole, _listener, _queued)) = netutil::black_hole() else {
            return;
        };
        let hole = hole.to_string();
        let short = Duration::from_millis(300);
        let wait = ConnectWait::new(short);
        let err = netutil::connect_dial_within(&hole, &wait, CONNECT_BUDGET)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            netutil::connect_dial(&hole, short, CONNECT_BUDGET)
                .await
                .unwrap_err()
        );
        assert!(err.ends_with(": no answer within 0.3s)"), "{err}");
        assert!(wait.expired());
    }

    #[test]
    fn dial_addresses_follow_the_plan_order_and_the_contact_book() {
        let (bob, relay) = (peer(3), peer(4));
        let relay_via = format!("/ip4/198.51.100.1/tcp/7423/p2p/{relay}");
        let direct = format!("/ip4/203.0.113.9/tcp/7423/p2p/{bob}");
        let book =
            p2p_route::ContactP2p::from_fields(&bob, &[relay_via.clone(), direct.clone()]).unwrap();
        let contact = P2pDialSet::merge(Some(&book), None, |_| true, None).unwrap();
        let target = p2p_route::parse_p2p_dial(&p2p_route::peer_route(&bob)).unwrap();
        let got: Vec<String> = dial_addrs(&target, Some(&contact), &DialForms::default())
            .unwrap()
            .iter()
            .map(|a| a.to_string())
            .collect();
        assert_eq!(
            got,
            vec![direct.clone(), format!("{relay_via}/p2p-circuit/p2p/{bob}")]
        );
        // The book entry of another PeerId is never used.
        let other = p2p_route::parse_p2p_dial(&p2p_route::peer_route(&peer(5))).unwrap();
        assert!(dial_addrs(&other, Some(&contact), &DialForms::default())
            .unwrap()
            .is_empty());
        // An explicit address is dialled as given, nothing else.
        let explicit = p2p_route::parse_p2p_dial(&direct).unwrap();
        assert_eq!(
            dial_addrs(&explicit, Some(&contact), &DialForms::default())
                .unwrap()
                .len(),
            1
        );

        // The relays the dial admits with the contact: its via= relays (not
        // its own direct address), or the one of an explicit circuit.
        let relay_peer: PeerId = relay.parse().unwrap();
        assert_eq!(dial_relays(&target, Some(&contact)), vec![relay_peer]);
        assert!(dial_relays(&other, Some(&contact)).is_empty());
        assert!(dial_relays(&explicit, Some(&contact)).is_empty());
        let circuit =
            p2p_route::parse_p2p_dial(&format!("{relay_via}/p2p-circuit/p2p/{bob}")).unwrap();
        assert_eq!(dial_relays(&circuit, None), vec![relay_peer]);
    }

    #[tokio::test]
    async fn dial_is_held_or_refused_before_anything_is_dialled() {
        let dir = tempfile::tempdir().unwrap();
        let expected = hex::encode(Identity::from_seed(&[6; 32]).public_key_bytes());
        let target = p2p_route::peer_route(&peer(6));
        let err = dial(dir.path(), &target, &expected, &[]).await.unwrap_err();
        if !raven_core::p2p_live_enabled() {
            assert_eq!(err, raven_core::P2P_HOLD);
            return;
        }
        // Not a contact (or not verified): refused, nothing dialled.
        assert!(err.starts_with(raven_core::CONTACT_NOT_VERIFIED), "{err}");
        assert!(err.contains("nothing was dialled"), "{err}");
    }

    /// A p2p dial goes to a current, unblocked, verified contact only: the
    /// dial admits whom it connects to into our own peer gate, so a blocked
    /// contact is refused before anything is dialled.
    #[test]
    fn a_dial_goes_to_unblocked_verified_contacts_only() {
        use crate::outbox::code::{CONTACTS_UNREADABLE, CONTACT_BLOCKED};
        use raven_core::CONTACT_NOT_VERIFIED;
        let dir = tempfile::tempdir().unwrap();
        let (bob, carol, stranger) = ([0xaa; 32], [0xbb; 32], [0xcc; 32]);
        std::fs::write(
            dir.path().join("contacts.json"),
            serde_json::to_string(&vec![
                gate_row(&hex::encode(bob), true, peer(1), Vec::new()),
                gate_row(&hex::encode(carol), false, peer(2), Vec::new()),
            ])
            .unwrap(),
        )
        .unwrap();
        let contact = dial_contact(dir.path(), &bob).unwrap().unwrap();
        assert!(contact.pinned);
        assert_eq!(contact.p2p.unwrap().peer_id, peer(1));
        let refused = |key: &[u8; 32], code: &str| {
            let err = dial_contact(dir.path(), key).unwrap_err();
            assert!(
                err.starts_with(code) && err.contains("nothing was dialled"),
                "{err}"
            );
            err
        };
        refused(&carol, CONTACT_NOT_VERIFIED);
        refused(&stranger, CONTACT_NOT_VERIFIED);
        let mut blocks = raven_core::chat_history::BlockList::default();
        blocks.block(&hex::encode(bob));
        blocks.save(dir.path()).unwrap();
        let blocked = refused(&bob, CONTACT_BLOCKED);
        assert_eq!(crate::outbox::dial_error_code(&blocked), CONTACT_BLOCKED);
        std::fs::write(dir.path().join("contacts.json"), b"[{").unwrap();
        refused(&bob, CONTACTS_UNREADABLE);
    }

    #[tokio::test]
    async fn dns_route_names_are_resolved_before_libp2p_sees_them() {
        let peer = peer(9);
        let ip: Multiaddr = format!("/ip4/203.0.113.7/tcp/7423/p2p/{peer}")
            .parse()
            .unwrap();
        assert_eq!(resolve_addr(ip.clone(), false).await, vec![ip]);
        let named: Multiaddr = format!("/dns4/localhost/tcp/7423/p2p/{peer}")
            .parse()
            .unwrap();
        let got = resolve_addr(named, false).await;
        assert!(!got.is_empty(), "localhost resolves");
        for a in &got {
            let text = a.to_string();
            assert!(text.starts_with("/ip4/127."), "{text}");
            assert!(text.ends_with(&format!("/tcp/7423/p2p/{peer}")), "{text}");
        }
        let v6: Multiaddr = format!("/dns6/localhost/udp/7423/quic-v1/p2p/{peer}")
            .parse()
            .unwrap();
        for a in resolve_addr(v6, false).await {
            assert!(a.to_string().starts_with("/ip6/"), "{a}");
        }
        let nowhere: Multiaddr = format!("/dns4/no-such-host.invalid/tcp/7423/p2p/{peer}")
            .parse()
            .unwrap();
        assert!(resolve_addr(nowhere, false).await.is_empty());
    }

    /// A dial's circuit through a relay named by a DNS name keeps only the
    /// global answers (spec §5.2's RELAY rule), so a name the contact
    /// controls never makes this node dial loopback; the debug lab flags
    /// keep it. An IP literal, and a name for the contact itself, are left
    /// as they are.
    #[tokio::test]
    async fn a_relay_name_that_resolves_to_loopback_is_not_dialled() {
        let (bob, relay) = (peer(9), peer(10));
        let addr = |t: String| t.parse::<Multiaddr>().unwrap();
        let named = addr(format!(
            "/dns4/localhost/tcp/7423/p2p/{relay}/p2p-circuit/p2p/{bob}"
        ));
        let literal = addr(format!(
            "/ip4/127.0.0.1/tcp/7424/p2p/{relay}/p2p-circuit/p2p/{bob}"
        ));
        let direct = addr(format!("/dns4/localhost/tcp/7425/p2p/{bob}"));
        let all = vec![named, literal.clone(), direct];
        let got = resolve_dial(all.clone(), |_| false, false, false).await;
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!(got[0], literal);
        assert!(got[1].to_string().starts_with("/ip4/127."), "{got:?}");
        assert!(!got.iter().any(|a| a.to_string().contains("/tcp/7423/")));
        for (lab_local, lab_loopback) in [(true, false), (false, true)] {
            let got = resolve_dial(all.clone(), |_| false, lab_local, lab_loopback).await;
            assert_eq!(got.len(), 3, "{lab_local} {lab_loopback}: {got:?}");
        }
    }

    /// A relay slot picked from a contact's offer whose name resolves to
    /// loopback or a local network has nothing to dial (the offer rule for
    /// IP literals, held to the name's answers); the debug lab flags keep
    /// it. A relay set by hand, and an IP literal, are left as they are.
    #[tokio::test]
    async fn an_offered_relay_name_that_resolves_to_loopback_is_not_reserved_on() {
        let relay = peer(10);
        let addr = |t: String| t.parse::<Multiaddr>().unwrap();
        let named = addr(format!("/dns4/localhost/tcp/7427/p2p/{relay}"));
        let literal = addr(format!("/ip4/127.0.0.1/tcp/7428/p2p/{relay}"));
        let both = vec![named.clone(), literal.clone()];
        assert_eq!(
            resolve_slot(both.clone(), true, |_| false, false, false).await,
            vec![literal.clone()]
        );
        assert!(
            resolve_slot(vec![named.clone()], true, |_| false, false, false)
                .await
                .is_empty()
        );
        let by_hand = resolve_slot(both.clone(), false, |_| false, false, false).await;
        assert_eq!(by_hand.len(), 2, "{by_hand:?}");
        assert!(
            by_hand[0].to_string().starts_with("/ip4/127."),
            "{by_hand:?}"
        );
        for (lab_local, lab_loopback) in [(true, false), (false, true)] {
            let got = resolve_slot(both.clone(), true, |_| false, lab_local, lab_loopback).await;
            assert_eq!(got, by_hand, "{lab_local} {lab_loopback}");
        }
    }

    /// RWS1 §7 and §2.1: a WSS form the HTTPS proxy carries keeps its name
    /// (only the proxy resolves it); one resolved here keeps the name as its
    /// SNI name, a circuit through it too. Raw TCP never goes through a
    /// proxy, so it is resolved either way, and an IP literal stays as it
    /// is. An offered relay's name the proxy resolves is still held to the
    /// global rule by this node's own answers (review B-4).
    #[tokio::test]
    async fn resolve_addr_keeps_the_name_when_proxied_and_inserts_sni_when_resolving() {
        let (relay, bob) = (peer(9), peer(10));
        let addr = |t: String| t.parse::<Multiaddr>().unwrap();
        let named = addr(format!("/dns4/localhost/tcp/443/tls/ws/p2p/{relay}"));
        assert!(is_wss(&named));
        assert_eq!(
            tcp_host(&named),
            Some((wss::Host::Name("localhost".into()), 443))
        );
        assert_eq!(resolve_addr(named.clone(), true).await, vec![named.clone()]);
        let got = resolve_addr(named, false).await;
        assert!(!got.is_empty(), "localhost resolves");
        for a in &got {
            let text = a.to_string();
            assert!(text.starts_with("/ip4/127."), "{text}");
            assert!(
                text.ends_with(&format!("/tcp/443/tls/sni/localhost/ws/p2p/{relay}")),
                "{text}"
            );
        }
        assert!(got.contains(&addr(format!(
            "/ip4/127.0.0.1/tcp/443/tls/sni/localhost/ws/p2p/{relay}"
        ))));
        let circuit = addr(format!(
            "/dns4/localhost/tcp/443/tls/ws/p2p/{relay}/p2p-circuit/p2p/{bob}"
        ));
        assert!(is_wss(&circuit));
        assert_eq!(
            resolve_addr(circuit.clone(), true).await,
            vec![circuit.clone()]
        );
        let resolved = resolve_addr(circuit, false).await;
        assert!(!resolved.is_empty());
        for a in resolved {
            let text = a.to_string();
            assert!(
                text.starts_with("/ip4/127.")
                    && text.ends_with(&format!(
                        "/tcp/443/tls/sni/localhost/ws/p2p/{relay}/p2p-circuit/p2p/{bob}"
                    )),
                "{text}"
            );
        }
        let raw = addr(format!("/dns4/localhost/tcp/443/p2p/{relay}"));
        assert!(!is_wss(&raw));
        let resolved = resolve_addr(raw, true).await;
        assert!(!resolved.is_empty());
        for a in resolved {
            let text = a.to_string();
            assert!(
                text.starts_with("/ip4/127.") && !text.contains("/sni/"),
                "{text}"
            );
        }
        let literal = addr(format!(
            "/ip4/203.0.113.7/tcp/443/tls/sni/relay.example/ws/p2p/{relay}"
        ));
        assert!(is_wss(&literal));
        for proxied in [false, true] {
            assert_eq!(
                resolve_addr(literal.clone(), proxied).await,
                vec![literal.clone()]
            );
        }
        let quic = addr(format!("/ip4/203.0.113.7/udp/443/quic-v1/p2p/{relay}"));
        assert!(!is_wss(&quic) && tcp_host(&quic).is_none());
        // Review B-4: an offered name the proxy would carry is resolved
        // here first and kept, unresolved, only when every answer is
        // usable: `localhost` is loopback, so it is not dialled through the
        // proxy either (the debug lab flags keep it, still unresolved); a
        // name that does not resolve here is not dialled. A relay set by
        // hand is left to the proxy as it is.
        let offered = vec![addr(format!("/dns4/localhost/tcp/443/tls/ws/p2p/{relay}"))];
        assert!(resolve_slot(offered.clone(), true, |_| true, false, false)
            .await
            .is_empty());
        for (lab_local, lab_loopback) in [(true, false), (false, true)] {
            assert_eq!(
                resolve_slot(offered.clone(), true, |_| true, lab_local, lab_loopback).await,
                offered
            );
        }
        assert_eq!(
            resolve_slot(offered.clone(), false, |_| true, false, false).await,
            offered
        );
        let nowhere = vec![addr(format!(
            "/dns4/intranet-wiki.invalid/tcp/443/tls/ws/p2p/{relay}"
        ))];
        assert!(resolve_slot(nowhere.clone(), true, |_| true, true, true)
            .await
            .is_empty());
        assert_eq!(
            resolve_slot(nowhere.clone(), false, |_| true, false, false).await,
            nowhere
        );
        // A contact's circuit through such a relay, likewise.
        let circuit = vec![addr(format!(
            "/dns4/localhost/tcp/443/tls/ws/p2p/{relay}/p2p-circuit/p2p/{bob}"
        ))];
        assert!(resolve_dial(circuit.clone(), |_| true, false, false)
            .await
            .is_empty());
        assert_eq!(
            resolve_dial(circuit.clone(), |_| true, false, true).await,
            circuit
        );
        assert!(resolve_slot(offered, true, |_| false, false, false)
            .await
            .is_empty());
    }

    #[test]
    fn upnp_state_starts_from_the_policy() {
        assert_eq!(upnp_initial(None), "unset");
        assert_eq!(upnp_initial(Some(false)), "off");
        assert_eq!(upnp_initial(Some(true)), "on");
        let addr: Multiaddr = "/ip4/203.0.113.7/tcp/7423".parse().unwrap();
        assert_eq!(mapped_port(&addr), Some(7423));
    }

    /// Phase 4 (P4.20): with the PORT_MAP gate open, every port-mapping
    /// event moves IPC `port_map` and the legacy `upnp` string, which says
    /// `mapped <port>` for PCP and NAT-PMP too (an older ash still shows
    /// the mapping), and logs the design's lines: counts and ports only.
    #[test]
    fn port_map_state_and_legacy_upnp_string_table() {
        let mapped = |via, v6, port, tcp| PortMapEvent::Mapped {
            via,
            v6,
            port,
            tcp,
            udp: !tcp,
        };
        let lost = |v6, why, tcp| PortMapEvent::Lost {
            via: Via::Pcp,
            v6,
            why,
            tcp,
            udp: !tcp,
        };
        let upnp_new = |at: &str| {
            PortMapEvent::Upnp(upnp::Event::NewExternalAddr {
                local_addr: "/ip4/192.168.1.5/tcp/7423".parse().unwrap(),
                external_addr: at.parse().unwrap(),
            })
        };
        let line = |text: &str| Some(format!("raven-node p2p: {text}"));
        // (event, v4, v4_port, v6, legacy upnp, line)
        let table = [
            (
                mapped(Via::Pcp, false, 41000, true),
                "pcp",
                41000,
                "asking",
                "mapped 41000",
                line("router port mapped (PCP, port 41000 tcp)"),
            ),
            (
                mapped(Via::Pcp, false, 41000, false),
                "pcp",
                41000,
                "asking",
                "mapped 41000",
                line("router port mapped (PCP, port 41000 tcp+udp)"),
            ),
            // Granted again at the same port: counted, nothing logged.
            (
                mapped(Via::Pcp, false, 41000, true),
                "pcp",
                41000,
                "asking",
                "mapped 41000",
                None,
            ),
            (
                PortMapEvent::ServerRestarted { via: Via::Pcp },
                "pcp",
                41000,
                "asking",
                "mapped 41000",
                line("router restarted; port mapped again"),
            ),
            (
                mapped(Via::Pcp, true, 41000, true),
                "pcp",
                41000,
                "open",
                "mapped 41000",
                line("IPv6 pinhole open on the router (PCP)"),
            ),
            (
                mapped(Via::Pcp, true, 41000, false),
                "pcp",
                41000,
                "open",
                "mapped 41000",
                None,
            ),
            // One protocol released: the other still forwards.
            (
                lost(false, LostWhy::Released, true),
                "pcp",
                41000,
                "open",
                "mapped 41000",
                None,
            ),
            (
                lost(false, LostWhy::Ended, false),
                "asking",
                0,
                "open",
                "failed",
                line("router port mapping ended; asking the router again"),
            ),
            (
                PortMapEvent::NoServer {
                    v6: false,
                    upnp: true,
                },
                "asking",
                0,
                "open",
                "failed",
                line("no PCP or NAT-PMP answer; trying UPnP"),
            ),
            (
                upnp_new("/ip4/203.0.113.7/tcp/7423"),
                "upnp",
                7423,
                "open",
                "mapped 7423",
                line("upnp mapped port 7423"),
            ),
            (
                lost(true, LostWhy::Released, true),
                "upnp",
                7423,
                "open",
                "mapped 7423",
                None,
            ),
            (
                lost(true, LostWhy::Ended, false),
                "upnp",
                7423,
                "asking",
                "mapped 7423",
                None,
            ),
            (
                PortMapEvent::NonRoutable { carrier: true },
                "behind_another_nat",
                0,
                "asking",
                "failed",
                line("router is behind another NAT (carrier NAT): no mapping"),
            ),
            (
                mapped(Via::NatPmp, false, 7423, true),
                "nat-pmp",
                7423,
                "asking",
                "mapped 7423",
                line("router port mapped (NAT-PMP, port 7423 tcp)"),
            ),
        ];
        let mut state = PortMapState::new(true, true, true);
        let mut legacy = upnp_initial(Some(true));
        for (event, v4, port, v6, upnp_text, want) in table {
            let what = format!("{event:?}");
            let got = port_map_step(&mut state, &mut legacy, "raven-node p2p", &event);
            assert_eq!(got, want, "{what}");
            assert_eq!(
                (state.v4, state.v4_port, state.v6),
                (v4, port, v6),
                "{what}"
            );
            assert_eq!(legacy, upnp_text, "{what}");
            // What an older ash reads: mapped while a port is forwarded.
            assert_eq!(legacy.starts_with("mapped"), port != 0, "{what}");
            if let Some(got) = got {
                assert!(
                    !got.contains("203.0.113") && !got.contains("192.168"),
                    "{got}"
                );
            }
        }
        assert_eq!((state.renewals, state.restarts), (1, 1));
        let status = state.status();
        assert_eq!(
            status,
            PortMapStatus {
                v4: "nat-pmp".into(),
                v4_port: 7423,
                v6: "asking".into(),
                renewals: 1,
                server_restarts: 1,
            }
        );
        // Nothing found, a refusal, and UPnP's own "not found" with the gate
        // open (which names all three protocols).
        for (event, v4, v6, want) in [
            (
                PortMapEvent::NoGateway { v6: false },
                "none",
                "not_asked",
                line("no router port mapping found (UPnP, NAT-PMP, PCP)"),
            ),
            (
                PortMapEvent::Upnp(upnp::Event::GatewayNotFound),
                "none",
                "not_asked",
                line("no router port mapping found (UPnP, NAT-PMP, PCP)"),
            ),
            (
                PortMapEvent::Refused {
                    via: Via::Pcp,
                    v6: false,
                    code: 2,
                },
                "refused",
                "not_asked",
                line("router refuses port mapping (PCP: not authorized)"),
            ),
            (
                PortMapEvent::Refused {
                    via: Via::Pcp,
                    v6: true,
                    code: 8,
                },
                "asking",
                "refused",
                line("router refuses the IPv6 pinhole (PCP: result code 8)"),
            ),
            (PortMapEvent::NoGateway { v6: true }, "asking", "none", None),
            // Review E-2: a lab router's silence, and no UPnP after it.
            (
                PortMapEvent::NoServer {
                    v6: false,
                    upnp: false,
                },
                "none",
                "not_asked",
                line("no PCP or NAT-PMP answer; UPnP not tried (lab router)"),
            ),
            // Review C-2: only carrier NAT is the provider's; a private
            // external address is a double NAT at the site.
            (
                PortMapEvent::NonRoutable { carrier: true },
                "behind_another_nat",
                "not_asked",
                line("router is behind another NAT (carrier NAT): no mapping"),
            ),
            (
                PortMapEvent::NonRoutable { carrier: false },
                "double_nat",
                "not_asked",
                line("router is behind another router (double NAT): no mapping"),
            ),
            // Review C-1: the router is not on the Internet path.
            (
                PortMapEvent::OffEgress,
                "off_path",
                "not_asked",
                line("router is not on the internet path (a VPN?): no mapping"),
            ),
        ] {
            let what = format!("{event:?}");
            let mut state = PortMapState::new(true, false, false);
            let mut legacy = upnp_initial(Some(true));
            let got = port_map_step(&mut state, &mut legacy, "raven-node p2p", &event);
            assert_eq!(got, want, "{what}");
            assert_eq!((state.v4, state.v6), (v4, v6), "{what}");
            let failed = v4 != "asking";
            assert_eq!(legacy == "failed", failed, "{what}: {legacy}");
        }
        // No consent: off, and a pinhole without a global IPv6 address.
        assert_eq!(PortMapState::new(false, false, false).status().v4, "off");
        assert_eq!(PortMapState::new(true, false, true).status().v6, "none");
    }

    /// The gateway lookups P4.20's builds count ([`RouterLookup::gateways`]).
    static GATEWAY_LOOKUPS: AtomicU64 = AtomicU64::new(0);

    fn counted_gateways() -> raven_core::gateway::Gateways {
        GATEWAY_LOOKUPS.fetch_add(1, Ordering::SeqCst);
        raven_core::gateway::Gateways::default()
    }

    /// The egress IPv6 address toward a harness's IPv6 router is looked up
    /// only while the harness names one (carrier_matrix C44's `[::1]`).
    #[test]
    fn lab_egress_v6_needs_a_lab_ipv6_router() {
        if raven_core::portmap_gate::lab_portmap_gateway().is_some_and(|g| g.v6.is_some()) {
            return; // the caller names one: then the answer is the OS's
        }
        assert_eq!(lab_egress_v6(), None);
    }

    /// Phase 4 (P4.20): every generation (a network change re-homes) reads
    /// the routers again, with the PORT_MAP gate open and the consent given;
    /// with the gate closed or no consent nothing is looked up. No router
    /// is found here, so nothing is sent anywhere (no UPnP either).
    #[tokio::test]
    async fn host_seed_build_reads_the_gateway_each_generation() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let config = P2pConfig {
            upnp: Some(true),
            v6_pinhole: Some(true),
            ..loopback_config(Vec::new())
        };
        let (seed, _commands) = test_seed(&gate, dir.path(), config.clone());
        let seed = HostSeed {
            router: RouterLookup {
                gates: || (true, false),
                gateways: counted_gateways,
                egress_v4: || panic!("no IPv4 router: no egress lookup"),
                egress_v6: || panic!("the V6_PINHOLE gate is closed"),
                lab_gateway: || false,
            },
            ..seed
        };
        for gen in 0..2u64 {
            let (host, _incoming, _handle) = seed.build(gen, gen > 0).unwrap();
            assert_eq!(GATEWAY_LOOKUPS.load(Ordering::SeqCst), gen + 1);
            let status = host.status_info();
            assert_eq!(
                status.port_map,
                Some(PortMapStatus {
                    v4: "asking".into(),
                    v6: "not_asked".into(),
                    ..PortMapStatus::default()
                })
            );
            assert_eq!(status.upnp, "on");
            drop(host);
        }
        let (cfg, _) = seed.port_map_config(&config, true);
        let cfg = cfg.unwrap();
        assert!(cfg.pcp && cfg.any_ip && !cfg.v6);
        assert_eq!(
            *cfg.nonce_key,
            *raven_core::portmap::nonce_key(&Identity::from_seed(&[13; 32]))
        );
        assert_eq!(GATEWAY_LOOKUPS.load(Ordering::SeqCst), 3);
        // No consent: the gate open says `off`, and nothing is looked up.
        let off = P2pConfig {
            upnp: Some(false),
            ..config.clone()
        };
        let (host, _incoming, _handle) = seed.build(2, true).unwrap();
        drop(host);
        assert_eq!(GATEWAY_LOOKUPS.load(Ordering::SeqCst), 4);
        let (none, state) = seed.port_map_config(&off, false);
        assert!(none.is_none());
        assert_eq!(state.map(|s| s.v4), Some("off"));
        // The gate closed: Phase 1's UPnP-IGD exactly, no lookup.
        let closed = HostSeed {
            router: RouterLookup {
                gates: || (false, true),
                ..seed.router
            },
            ..seed
        };
        let (none, state) = closed.port_map_config(&config, false);
        assert!(none.is_none() && state.is_none());
        assert_eq!(GATEWAY_LOOKUPS.load(Ordering::SeqCst), 4);
        // The pinhole: its gate and consent, and the egress address read
        // only then.
        let v6 = HostSeed {
            router: RouterLookup {
                gates: || (true, true),
                gateways: raven_core::gateway::Gateways::default,
                egress_v4: || panic!("no IPv4 router: no egress lookup"),
                egress_v6: || Some(Ipv6Addr::LOCALHOST),
                lab_gateway: || false,
            },
            ..closed
        };
        let (cfg, state) = v6.port_map_config(&config, false);
        let cfg = cfg.unwrap();
        assert!(cfg.v6 && cfg.egress_v6 == Some(Ipv6Addr::LOCALHOST));
        assert_eq!(state.map(|s| s.v6), Some("asking"));
        let no_v6 = P2pConfig {
            v6_pinhole: None,
            ..config
        };
        let (cfg, state) = v6.port_map_config(&no_v6, false);
        assert!(!cfg.unwrap().v6);
        assert_eq!(state.map(|s| s.v6), Some("not_asked"));
        // Review C-1: with an IPv4 router, the egress IPv4 address is read
        // too and handed to the mapper, which asks the router only when
        // its source address toward it is that one.
        let v4 = HostSeed {
            router: RouterLookup {
                gates: || (true, false),
                gateways: || raven_core::gateway::Gateways {
                    v4: Some(Ipv4Addr::new(192, 168, 1, 1)),
                    v6: None,
                },
                egress_v4: || Some(Ipv4Addr::new(10, 8, 0, 2)),
                egress_v6: || None,
                lab_gateway: || false,
            },
            ..v6
        };
        let (cfg, _) = v4.port_map_config(&no_v6, false);
        let cfg = cfg.unwrap();
        assert_eq!(cfg.gw_v4, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(cfg.egress_v4, Some(Ipv4Addr::new(10, 8, 0, 2)));
        assert!(cfg.upnp_fallback);
        // Review E-2: a harness names the router. With the gate open the
        // mapper never falls back to UPnP; with it closed the config says
        // only that (no libp2p-upnp at once), and still no IPC port_map.
        let lab = HostSeed {
            router: RouterLookup {
                lab_gateway: || true,
                ..v4.router
            },
            ..v4
        };
        let (cfg, _) = lab.port_map_config(&no_v6, false);
        let cfg = cfg.unwrap();
        assert!(cfg.pcp && !cfg.upnp_fallback);
        let lab_closed = HostSeed {
            router: RouterLookup {
                gates: || (false, false),
                ..lab.router
            },
            ..lab
        };
        let (cfg, state) = lab_closed.port_map_config(&no_v6, false);
        let cfg = cfg.expect("a config that keeps UPnP off");
        assert!(!cfg.pcp && !cfg.v6 && !cfg.upnp_fallback);
        assert!(state.is_none());
    }

    /// Review item 8: the service's decision is reported whether or not a
    /// host runs (an installer flag included), and a running host's own
    /// status wins over it.
    #[test]
    fn status_reports_the_service_decision_with_or_without_a_host() {
        if current_host().is_some() {
            return;
        }
        assert_eq!(status_snapshot(), None, "not `raven-node service`: nothing");
        let relay = peer(7);
        let config = P2pConfig {
            listen: P2pListen::All(7423),
            retired_relay: false,
            relays: vec![p2p_route::parse_via(&format!(
                "/dns4/relay.example.org/tcp/7423/p2p/{relay}"
            ))
            .unwrap()],
            relay_server: Some(false),
            upnp: None,
            v6_pinhole: None,
            auto: None,
            policy_relays_pending: false,
            proxy: P2pProxy::default(),
        };
        publish_service_config(ServiceP2p::Held {
            config: &config,
            source: "--p2p-listen",
        });
        let held = status_snapshot().unwrap();
        assert!(!held.up && held.held);
        assert_eq!(held.listen_setting, "7423");
        assert_eq!(held.source, "--p2p-listen");
        assert_eq!(held.relays.len(), 1);
        assert!(
            held.relays[0].starts_with("/dns4/relay.example.org/"),
            "{:?}",
            held.relays
        );
        assert_eq!(held.relays_configured, 1);
        assert!(held.relay_role);
        assert_eq!(held.upnp, "unset");
        assert!(held.retired_listen.is_empty());
        // The retired `relay`: the setting that runs (7423), and what it
        // replaced.
        let retired = P2pConfig {
            retired_relay: true,
            ..config.clone()
        };
        publish_service_config(ServiceP2p::Configured {
            config: &retired,
            source: "node_policy.json",
        });
        let configured = status_snapshot().unwrap();
        assert_eq!(
            (
                configured.listen_setting.as_str(),
                configured.retired_listen.as_str()
            ),
            ("7423", "relay")
        );
        publish_service_config(ServiceP2p::Off {
            source: "RAVEN_P2P_LISTEN",
        });
        let off = status_snapshot().unwrap();
        assert!(off.listen_setting.is_empty() && !off.held && off.relays.is_empty());
        assert_eq!(off.source, "RAVEN_P2P_LISTEN");
        publish_service_config(ServiceP2p::Error);
        assert!(!status_snapshot().unwrap().config_error.is_empty());
        // The friend relay's row is its own task's, with or without a host
        // (`held`: no capability changes for the other tests meanwhile).
        let friend = raven_core::ipc::FriendRelayInfo {
            state: "held".into(),
            consent: "yes".into(),
            ..Default::default()
        };
        crate::friend_relay::set_status_for_test(Some(friend.clone()));
        assert_eq!(
            status_snapshot().unwrap().friend_relay,
            Some(friend.clone())
        );
        // A running host's status overrides the decision while it runs.
        *lock(&STATUS) = Some(P2pStatusInfo {
            up: true,
            ..P2pStatusInfo::default()
        });
        assert!(status_snapshot().unwrap().up);
        assert_eq!(status_snapshot().unwrap().friend_relay, Some(friend));
        crate::friend_relay::set_status_for_test(None);
        assert_eq!(status_snapshot().unwrap().friend_relay, None);
        // Its path counts are read now, not at its last publish.
        let before = status_snapshot().unwrap().paths.unwrap().sent.relayed;
        count_paths(|c| c.sent.add(DeliveryPath::Relayed));
        assert!(status_snapshot().unwrap().paths.unwrap().sent.relayed > before);
        *lock(&STATUS) = None;
        *lock(&CONFIG) = None;
        assert_eq!(status_snapshot(), None);
    }

    /// Phase 1 item 5: `public` needs two independent servers (two networks,
    /// neither ours) that reached the same IP; one network is one opinion
    /// whatever its PeerIds, and a result from a server we did not dial at a
    /// global address does not count. Each server's latest answer stands, so
    /// the verdict follows new results both ways.
    #[test]
    fn public_needs_two_independent_servers() {
        let ma = |s: &str| -> Multiaddr { s.parse().unwrap() };
        let group = |ip: &str| net_group(ip.parse().unwrap());
        let (s1, s2, s3): (PeerId, PeerId, PeerId) = (
            peer(31).parse().unwrap(),
            peer(32).parse().unwrap(),
            peer(33).parse().unwrap(),
        );
        // Our address, and relays on two other /24s and one in ours.
        let tcp = ma("/ip4/8.8.8.8/tcp/7423");
        let quic = ma("/ip4/8.8.8.8/udp/7423/quic-v1");
        let other_ip = ma("/ip4/9.9.9.9/tcp/7423");
        let (g1, g1b, g2, own) = (
            group("11.1.0.1"),
            group("11.1.0.2"),
            group("11.2.0.1"),
            group("8.8.8.77"),
        );
        let verdict = |rows: &[(&Multiaddr, PeerId, Option<NetGroup>, bool)]| {
            let mut t = NatTally::default();
            for (addr, server, g, ok) in rows {
                t.record((*addr).clone(), *server, *g, *ok);
            }
            (t.verdict(), t.checks())
        };
        let checks = |reached, failed, not_counted| NatChecks {
            reached,
            failed,
            not_counted,
        };
        assert_eq!(verdict(&[]), (NatVerdict::Unknown, checks(0, 0, 0)));
        // 1 server: unconfirmed.
        assert_eq!(
            verdict(&[(&tcp, s1, g1, true)]),
            (NatVerdict::Unconfirmed, checks(1, 0, 0))
        );
        // 2 servers in one /24: one opinion.
        assert_eq!(
            verdict(&[(&tcp, s1, g1, true), (&tcp, s2, g1b, true)]),
            (NatVerdict::Unconfirmed, checks(1, 0, 0))
        );
        // 2 /24s: public.
        assert_eq!(
            verdict(&[(&tcp, s1, g1, true), (&tcp, s2, g2, true)]),
            (NatVerdict::Public, checks(2, 0, 0))
        );
        // A server reached through a relay, on loopback or a LAN (no group)
        // does not count.
        assert_eq!(
            verdict(&[(&tcp, s1, g1, true), (&tcp, s2, None, true)]),
            (NatVerdict::Unconfirmed, checks(1, 0, 1))
        );
        // Nor does one in the tested IP's own /24.
        assert_eq!(
            verdict(&[(&tcp, s1, g1, true), (&tcp, s2, own, true)]),
            (NatVerdict::Unconfirmed, checks(1, 0, 1))
        );
        assert_eq!(
            verdict(&[(&tcp, s1, own, true)]),
            (NatVerdict::Unknown, checks(0, 0, 1))
        );
        // TCP reached by S1 and QUIC by S2, on one IP: they agree.
        assert_eq!(
            verdict(&[(&tcp, s1, g1, true), (&quic, s2, g2, true)]),
            (NatVerdict::Public, checks(2, 0, 0))
        );
        // Two different IPs, one server each: nobody confirmed either.
        assert_eq!(
            verdict(&[(&tcp, s1, g1, true), (&other_ip, s2, g2, true)]),
            (NatVerdict::Unconfirmed, checks(1, 0, 0))
        );
        // Failures only: private; reached and failed: unconfirmed.
        assert_eq!(
            verdict(&[(&tcp, s1, g1, false), (&quic, s2, g2, false)]),
            (NatVerdict::Private, checks(0, 2, 0))
        );
        assert_eq!(
            verdict(&[(&tcp, s1, g1, true), (&tcp, s2, g2, false)]),
            (NatVerdict::Unconfirmed, checks(1, 1, 0))
        );
        // A server that reached one address and failed another still counts
        // as having reached us.
        assert_eq!(
            verdict(&[(&tcp, s1, g1, true), (&quic, s1, g1, false)]),
            (NatVerdict::Unconfirmed, checks(1, 0, 0))
        );
        // One dual-stack relay, its group read from the connection of the
        // moment (IPv4, then IPv6): still one server, one opinion.
        let v6 = group("2a01:4f8:7::1");
        assert_eq!(
            verdict(&[(&tcp, s1, g1, true), (&quic, s1, v6, true)]),
            (NatVerdict::Unconfirmed, checks(1, 0, 0))
        );
        assert_eq!(
            verdict(&[(&tcp, s1, g1, false), (&quic, s1, v6, false)]),
            (NatVerdict::Private, checks(0, 1, 0))
        );
        // Two servers, one of them seen in two groups: two opinions as long
        // as each has a group of its own.
        assert_eq!(
            verdict(&[
                (&tcp, s1, g1, true),
                (&quic, s1, v6, true),
                (&tcp, s2, g1b, true)
            ]),
            (NatVerdict::Public, checks(2, 0, 0))
        );
        assert_eq!(
            verdict(&[
                (&tcp, s1, g1, true),
                (&quic, s2, g1b, true),
                (&tcp, s3, g1, true)
            ]),
            (NatVerdict::Unconfirmed, checks(1, 0, 0))
        );

        // The latest answer stands, both ways; an expired address is
        // forgotten.
        let mut t = NatTally::default();
        t.record(tcp.clone(), s1, g1, true);
        t.record(tcp.clone(), s2, g2, true);
        assert_eq!(t.verdict(), NatVerdict::Public);
        t.record(tcp.clone(), s2, g2, false);
        assert_eq!(
            t.verdict(),
            NatVerdict::Unconfirmed,
            "a later failure counts"
        );
        t.record(quic.clone(), s3, g2, true);
        assert_eq!(t.verdict(), NatVerdict::Public);
        assert_eq!(
            (
                t.server_check(&s1),
                t.server_check(&s2),
                t.server_check(&s3)
            ),
            ("reached", "failed", "reached")
        );
        t.forget(&quic);
        assert_eq!(t.verdict(), NatVerdict::Unconfirmed);
        t.forget(&tcp);
        assert_eq!(t.verdict(), NatVerdict::Unknown);
        assert_eq!(t.server_check(&s1), "");
        t.record(tcp.clone(), s1, None, true);
        assert_eq!(t.server_check(&s1), "not_counted");

        // Bounded: addresses, then servers per address, start over when
        // full.
        let mut t = NatTally::default();
        for port in 0..MAX_NAT_RESULTS as u16 {
            t.record(ma(&format!("/ip4/8.8.8.8/tcp/{port}")), s1, g1, false);
        }
        assert_eq!(t.results.len(), MAX_NAT_RESULTS);
        t.record(tcp.clone(), s1, g1, true);
        assert_eq!(t.results.len(), 1);
        for seed in 1..MAX_NAT_SERVERS as u8 {
            let server: PeerId = peer(40 + seed).parse().unwrap();
            t.record(tcp.clone(), server, g2, false);
        }
        assert_eq!(t.results[&tcp].len(), MAX_NAT_SERVERS);
        t.record(tcp.clone(), s3, g2, true);
        assert_eq!(t.results[&tcp].len(), 1);
    }

    /// Phase 1 item 7: each relay's `Status` row follows its reservation,
    /// its pings and its loss, at a fixed `now`.
    #[test]
    fn relay_health_follows_reservation_ping_and_loss() {
        let relay = peer(15);
        let addr: Multiaddr = format!("/ip4/198.51.100.7/tcp/7423/p2p/{relay}")
            .parse()
            .unwrap();
        // A fixed `now` far enough from the clock's start for `at`.
        let now = Instant::now() + Duration::from_secs(600);
        let at = |s: u64| now - Duration::from_secs(s);
        let slot = || RelaySlot {
            texts: vec![addr.to_string()],
            named: vec![addr.clone()],
            forms: vec![addr.clone()],
            peer: relay.parse().unwrap(),
            resolved: vec![addr.clone()],
            next: 0,
            listener: None,
            connecting: None,
            active: false,
            resolving: false,
            attempt: 0,
            retry_at: None,
            since: None,
            ping: None,
            source: Source::Manual,
            selected_at: Instant::now(),
            path: None,
        };
        let row = |state: &str| RelayHealth {
            relay: addr.to_string(),
            state: state.into(),
            source: "manual".into(),
            ..RelayHealth::default()
        };
        // Not tried yet.
        assert_eq!(slot().health(now, ""), row("waiting"));
        // Resolving its name, or asking for the reservation.
        let resolving = RelaySlot {
            resolving: true,
            ..slot()
        };
        assert_eq!(resolving.health(now, ""), row("resolving"));
        let asking = RelaySlot {
            listener: Some(ListenerId::next()),
            attempt: 1,
            ..slot()
        };
        assert_eq!(
            asking.health(now, ""),
            RelayHealth {
                tries: 1,
                ..row("asking")
            }
        );
        let dialling = RelaySlot {
            connecting: Some(ConnectionId::new_unchecked(3)),
            ..slot()
        };
        assert_eq!(dialling.health(now, "").state, "asking");
        // Reserved for 2 min, pinged 4 s ago in 31 ms, checked us.
        let reserved = RelaySlot {
            listener: Some(ListenerId::next()),
            active: true,
            since: Some(at(120)),
            ping: Some((at(4), Duration::from_micros(31_400))),
            ..slot()
        };
        assert_eq!(
            reserved.health(now, "reached"),
            RelayHealth {
                for_s: Some(120),
                ping_ms: Some(31),
                ping_age_s: Some(4),
                check: "reached".into(),
                ..row("reserved")
            }
        );
        // Lost 30 s ago, 3 failed attempts since, the next in 9 s.
        let lost = RelaySlot {
            since: Some(at(30)),
            attempt: 3,
            retry_at: Some(now + Duration::from_secs(9)),
            ..slot()
        };
        assert_eq!(
            lost.health(now, "not_counted"),
            RelayHealth {
                for_s: Some(30),
                retry_in_s: Some(9),
                tries: 3,
                check: "not_counted".into(),
                ..row("retrying")
            }
        );
        // Refused before it ever held one: no "lost ... ago"; a due retry
        // is due in 0 s.
        let refused = RelaySlot {
            attempt: 1,
            retry_at: Some(at(1)),
            ..slot()
        };
        assert_eq!(
            refused.health(now, ""),
            RelayHealth {
                retry_in_s: Some(0),
                tries: 1,
                ..row("retrying")
            }
        );
        // While asking again after a loss, the loss time is not shown.
        let again = RelaySlot {
            listener: Some(ListenerId::next()),
            since: Some(at(30)),
            ..slot()
        };
        assert_eq!(again.health(now, "").for_s, None);
        // A huge round trip saturates.
        let slow = RelaySlot {
            ping: Some((now, Duration::from_secs(u64::MAX / 1000))),
            ..slot()
        };
        assert_eq!(slow.health(now, "").ping_ms, Some(u32::MAX));
    }

    /// Review item 5: a named relay keeps its name, rotates through every
    /// address it resolved to, and backs off between attempts.
    #[test]
    fn relay_slots_keep_the_name_rotate_and_back_off() {
        let relay = peer(8);
        let named: Multiaddr = format!("/dns/relay.example.org/tcp/7423/p2p/{relay}")
            .parse()
            .unwrap();
        assert!(is_dns(&named));
        let ip: Multiaddr = format!("/ip4/198.51.100.7/tcp/7423/p2p/{relay}")
            .parse()
            .unwrap();
        assert!(!is_dns(&ip));
        let mut slot = RelaySlot {
            texts: vec![named.to_string()],
            named: vec![named.clone()],
            forms: vec![named.clone()],
            peer: relay.parse().unwrap(),
            resolved: Vec::new(),
            next: 0,
            listener: None,
            connecting: None,
            active: false,
            resolving: false,
            attempt: 0,
            retry_at: None,
            since: None,
            ping: None,
            source: Source::Manual,
            selected_at: Instant::now(),
            path: None,
        };
        slot.rotate();
        assert_eq!(slot.next, 0, "nothing resolved: nothing to rotate");
        slot.resolved = vec![ip.clone(), ip.clone(), ip];
        let seen: Vec<usize> = (0..4)
            .map(|_| {
                slot.rotate();
                slot.next
            })
            .collect();
        assert_eq!(seen, vec![1, 2, 0, 1]);
        let now = Instant::now();
        slot.arm_retry(now);
        let first = slot.retry_at.unwrap() - now;
        for _ in 0..6 {
            slot.arm_retry(now);
        }
        let later = slot.retry_at.unwrap() - now;
        assert_eq!(slot.attempt, 7);
        assert!(later > first, "{first:?} then {later:?}");
        assert_eq!(
            slot.named,
            vec![named],
            "the name is kept for the next resolve"
        );
    }

    /// Phase 0b: networks only added (no re-home) make every idle relay slot
    /// due at once on a fresh backoff; a slot holding a reservation,
    /// resolving its name or with a request in flight is left alone.
    #[test]
    fn a_nudge_makes_idle_relay_slots_due_and_restarts_their_backoff() {
        let relay = peer(14);
        let addr: Multiaddr = format!("/ip4/198.51.100.7/tcp/7423/p2p/{relay}")
            .parse()
            .unwrap();
        let slot = || RelaySlot {
            texts: vec![addr.to_string()],
            named: vec![addr.clone()],
            forms: vec![addr.clone()],
            peer: relay.parse().unwrap(),
            resolved: vec![addr.clone()],
            next: 0,
            listener: None,
            connecting: None,
            active: false,
            resolving: false,
            attempt: 0,
            retry_at: None,
            since: None,
            ping: None,
            source: Source::Manual,
            selected_at: Instant::now(),
            path: None,
        };
        let now = Instant::now();
        let mut idle = slot();
        for _ in 0..4 {
            idle.arm_retry(now);
        }
        assert!(idle.retry_at.is_some_and(|t| t > now));
        idle.nudge(now);
        assert_eq!((idle.attempt, idle.retry_at), (0, Some(now)));

        let untouched = [
            RelaySlot {
                listener: Some(ListenerId::next()),
                active: true,
                attempt: 2,
                ..slot()
            },
            RelaySlot {
                resolving: true,
                attempt: 3,
                ..slot()
            },
            RelaySlot {
                listener: Some(ListenerId::next()),
                attempt: 5,
                ..slot()
            },
            RelaySlot {
                connecting: Some(ConnectionId::new_unchecked(7)),
                attempt: 4,
                ..slot()
            },
        ];
        for mut s in untouched {
            let before = (
                s.attempt,
                s.retry_at,
                s.listener,
                s.connecting,
                s.active,
                s.resolving,
            );
            s.nudge(now);
            assert_eq!(
                (
                    s.attempt,
                    s.retry_at,
                    s.listener,
                    s.connecting,
                    s.active,
                    s.resolving
                ),
                before
            );
        }

        // Without a host there is nothing to nudge or re-home.
        if current_host().is_none() {
            assert!(!host_running());
            assert!(!nudge());
            assert!(!network_changed(Rehome::Wake));
        }
    }

    /// Phase 0b: right after a re-home (or an unlock) a busy listen port is
    /// most likely our own old endpoint's: it is retried every 500 ms and
    /// counts as no failure (no "another program" line). After the grace,
    /// and without one, today's doubling backoff applies.
    #[test]
    fn a_busy_port_right_after_a_rehome_is_retried_quietly() {
        let now = Instant::now();
        let grace = Some(now + REBIND_GRACE);
        assert_eq!(busy_wait(0, grace, now), (REBIND_RETRY, false));
        let last = now + REBIND_GRACE - Duration::from_millis(1);
        assert_eq!(busy_wait(3, grace, last), (REBIND_RETRY, false));
        assert_eq!(
            busy_wait(0, grace, now + REBIND_GRACE),
            (LISTEN_RETRY_MIN, true),
            "the grace is over"
        );
        // E1: the host the lock stopped is the old endpoint after an unlock.
        assert_eq!(listen_grace(false, true, now), grace);
        assert_eq!(listen_grace(true, false, now), grace);
        assert_eq!(listen_grace(false, false, now), None, "a service start");
        let backoff: Vec<(Duration, bool)> = (0..8).map(|f| busy_wait(f, None, now)).collect();
        let want: Vec<(Duration, bool)> = [2, 4, 8, 16, 32, 60, 60, 60]
            .iter()
            .map(|s| (Duration::from_secs(*s), true))
            .collect();
        assert_eq!(backoff, want);
    }

    /// A configured specific listen address that was open and is on no
    /// interface after a re-home (a VPN's or a second NIC's, gone with the
    /// network that changed) stays configured: it is retried with the busy
    /// port's backoff, and networks added (a nudge, with no re-home) make it
    /// due at once, so it opens again when its interface is back.
    #[tokio::test]
    async fn a_listen_address_that_went_away_is_retried_until_it_is_back() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        // TEST-NET-1: on no interface of any test host.
        let config = P2pConfig {
            listen: P2pListen::One("192.0.2.1:47423".parse().unwrap()),
            ..loopback_config(Vec::new())
        };
        let (seed, _commands) = test_seed(&gate, dir.path(), config);
        // Generation 0 had them open.
        for text in seed.config.listen.multiaddrs() {
            lock(&seed.listens_opened).insert(text.parse().unwrap());
        }
        let (mut host, _incoming, _handle) = seed.build(1, true).unwrap();
        assert_eq!(host.listens.len(), 2, "TCP and QUIC stay configured");
        let start = Instant::now();
        for slot in &host.listens {
            assert!(!slot.open && slot.listener.is_none() && slot.opened_before);
            assert_eq!(slot.failures, 1);
            let due = slot.retry_at.expect("retried");
            assert!(due > start && due <= start + LISTEN_RETRY_MIN, "{due:?}");
        }
        assert_eq!(host.status_info().listen_retrying, 2);
        // Retried when due, for as long as it takes: the backoff doubles up
        // to its cap and never stops.
        let mut at = start + LISTEN_RETRY_MIN;
        for failures in 2..=8u32 {
            open_listeners(&mut host.swarm, &mut host.listens, at);
            assert_eq!(host.listens.len(), 2);
            let delay = busy_wait(failures - 1, None, at).0;
            for slot in &host.listens {
                assert_eq!((slot.failures, slot.retry_at), (failures, Some(at + delay)));
                assert!(!slot.waiting);
            }
            at += delay;
        }
        // Networks were added: due now (the tick probes it).
        let before = Instant::now();
        assert!(host.on_command(Command::Nudge).is_none());
        for slot in &host.listens {
            assert!(slot
                .retry_at
                .is_some_and(|t| t >= before && t <= Instant::now()));
            assert_eq!(slot.failures, 8, "no second log line");
        }
        // A slot never tried waits for open_listeners.
        let mut untried = ListenSlot::new("/ip4/192.0.2.1/tcp/47423".parse().unwrap(), None, false);
        untried.nudge(Instant::now());
        assert_eq!(untried.retry_at, None);
        assert!(untried.due(Instant::now()));
    }

    /// A specific listen address never opened that is on no interface (not
    /// up yet at start, or mistyped) is tried a few times, then only when
    /// networks are added: never on a timer for ever. It stays configured
    /// (it opens once the address appears), at start and after a re-home.
    #[tokio::test]
    async fn an_absent_listen_address_never_opened_waits_for_networks_to_be_added() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let config = P2pConfig {
            listen: P2pListen::One("192.0.2.1:47423".parse().unwrap()),
            ..loopback_config(Vec::new())
        };
        let (seed, _commands) = test_seed(&gate, dir.path(), config);
        for (gen, rehomed) in [(0, false), (1, true)] {
            let (mut host, _incoming, _handle) = seed.build(gen, rehomed).unwrap();
            assert_eq!(host.listens.len(), 2, "TCP and QUIC stay configured");
            let start = Instant::now();
            for slot in &host.listens {
                assert!(!slot.open && !slot.opened_before && !slot.waiting);
                assert_eq!((slot.failures, slot.absent_tries), (1, ABSENT_TRIES - 1));
                let due = slot.retry_at.expect("tried again soon");
                assert!(due > start && due <= start + LISTEN_RETRY_MIN, "{due:?}");
            }
            // The tries: after 2, 4, 8, 16 and 32 s, then it waits.
            let mut at = start + LISTEN_RETRY_MIN;
            for tried in 1..ABSENT_TRIES {
                open_listeners(&mut host.swarm, &mut host.listens, at);
                let delay = LISTEN_RETRY_MIN * (1 << tried);
                for slot in &host.listens {
                    assert_eq!(slot.retry_at, Some(at + delay), "try {tried}");
                }
                at += delay;
            }
            open_listeners(&mut host.swarm, &mut host.listens, at);
            let far = at + Duration::from_secs(24 * 3600);
            for slot in &host.listens {
                assert!(slot.waiting && slot.retry_at.is_none());
                assert!(!slot.due(far), "never due on a timer");
                assert_eq!(slot.failures, ABSENT_TRIES + 1);
            }
            open_listeners(&mut host.swarm, &mut host.listens, far);
            assert!(host.listens.iter().all(|s| s.failures == ABSENT_TRIES + 1));
            // Still configured, not open.
            assert_eq!(host.listens.len(), 2);
            assert_eq!(host.status_info().listen_retrying, 2);
            // Networks were added: due now, with its tries again.
            let before = Instant::now();
            assert!(host.on_command(Command::Nudge).is_none());
            for slot in &host.listens {
                assert!(!slot.waiting && slot.absent_tries == ABSENT_TRIES);
                assert!(slot
                    .retry_at
                    .is_some_and(|t| t >= before && t <= Instant::now()));
            }
            let now = Instant::now();
            open_listeners(&mut host.swarm, &mut host.listens, now);
            for slot in &host.listens {
                assert_eq!(slot.retry_at, Some(now + LISTEN_RETRY_MIN));
                assert_eq!(slot.failures, ABSENT_TRIES + 2, "no second log line");
            }
        }
    }

    /// An address that can never be bound as asked (a port this process may
    /// not bind, one below 1024 that needs a privilege, an invalid address,
    /// no such address family), or a wildcard
    /// of a family this host lacks, is skipped once and dropped, whichever
    /// the generation; a busy port and an absent specific address are kept.
    #[test]
    fn a_listen_address_that_can_never_be_bound_is_skipped() {
        let now = Instant::now();
        let slot = |addr: &str, opened_before: bool| {
            ListenSlot::new(addr.parse().unwrap(), None, opened_before)
        };
        for opened_before in [false, true] {
            for addr in ["/ip4/192.0.2.1/tcp/80", "/ip6/2001:db8::1/udp/7423/quic-v1"] {
                let mut s = slot(addr, opened_before);
                assert!(!s.failed(ListenProbe::Unavailable, now), "{addr}");
                let mut s = slot(addr, opened_before);
                assert!(!s.failed(ListenProbe::Privileged, now), "{addr}");
                let mut s = slot(addr, opened_before);
                assert!(s.failed(ListenProbe::Absent, now), "{addr}");
                assert!(s.retry_at.is_some());
                let mut s = slot(addr, opened_before);
                assert!(s.failed(ListenProbe::Busy, now), "{addr}");
            }
            for wildcard in ["/ip6/::/tcp/7423", "/ip4/0.0.0.0/udp/7423/quic-v1"] {
                let mut s = slot(wildcard, opened_before);
                assert!(!s.failed(ListenProbe::Absent, now), "{wildcard}");
                assert!(!slot(wildcard, opened_before).failed(ListenProbe::Unavailable, now));
            }
        }
        assert!(!listen_slot_can_return(&"/ip6/::/tcp/1".parse().unwrap()));
        assert!(listen_slot_can_return(
            &"/ip4/192.0.2.1/tcp/1".parse().unwrap()
        ));
    }

    /// Phase 0b re-home on one port: the old endpoint still holds its IPv6
    /// sockets for a moment (QUIC drains) when the new one opens the IPv4
    /// ones; the IPv6 slots open quietly in a later round, next to our own
    /// IPv4 listeners (a dual-stack probe collided with those on Linux and
    /// kept them closed for the whole generation).
    #[tokio::test]
    async fn an_ipv6_slot_busy_for_a_round_opens_next_to_our_ipv4_listeners() {
        if std::net::UdpSocket::bind("[::]:0").is_err() {
            eprintln!("no IPv6 sockets on this host: skipped");
            return;
        }
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut tries = 0;
        let port = loop {
            tries += 1;
            assert!(tries < 100, "no port free on both wildcard addresses");
            let port = std::net::UdpSocket::bind("0.0.0.0:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let free = !matches!(port, 7420 | 7422 | 7423)
                && ["0.0.0.0", "[::]"].iter().all(|ip| {
                    let at = format!("{ip}:{port}");
                    std::net::UdpSocket::bind(&at).is_ok()
                        && std::net::TcpListener::bind(&at).is_ok()
                });
            if free {
                break port;
            }
        };
        // The old endpoint's IPv6 sockets (libp2p binds them IPv6-only).
        let mut old = build_endpoint_swarm(
            &gate,
            raven_swarm::kad_node::libp2p_keypair_from_raven(&Identity::from_seed(&[13; 32])),
            EndpointConfig::default(),
        )
        .unwrap();
        for at in [
            format!("/ip6/::/tcp/{port}"),
            format!("/ip6/::/udp/{port}/quic-v1"),
        ] {
            old.listen_on(at.parse().unwrap()).unwrap();
        }
        let config = P2pConfig {
            listen: P2pListen::All(port),
            ..loopback_config(Vec::new())
        };
        let (seed, _commands) = test_seed(&gate, dir.path(), config);
        let (mut host, _incoming, _handle) = seed.build(1, true).unwrap();
        assert_eq!(host.listens.len(), 4);
        for slot in &host.listens {
            assert_eq!(slot.open, !is_ip6(&slot.addr), "{}", slot.addr);
        }
        drop(old);
        let deadline = Instant::now() + REBIND_GRACE;
        while host.listens.iter().any(|l| !l.open) && Instant::now() < deadline {
            tokio::time::sleep(REBIND_RETRY).await;
            open_listeners(&mut host.swarm, &mut host.listens, Instant::now());
        }
        for slot in &host.listens {
            assert!(slot.open, "{} still closed", slot.addr);
            assert_eq!(slot.failures, 0, "retried quietly");
        }
    }

    /// Phase 0b: our own path died when every relay that held a reservation
    /// failed its pings within the window and no connection answered one
    /// since, another direct connection given one ping round to answer. One
    /// relay of two, or a contact's connection, is not that. At most one
    /// report per window.
    #[test]
    fn relay_loss_needs_every_reserved_relay_and_silence_elsewhere() {
        let (r1, r2): (PeerId, PeerId) = (peer(15).parse().unwrap(), peer(16).parse().unwrap());
        let bob: PeerId = peer(17).parse().unwrap();
        let set = |peers: &[PeerId]| peers.iter().copied().collect::<HashSet<PeerId>>();
        let s = Duration::from_secs;
        let t0 = Instant::now();

        // One of two relays lost: not our path.
        let mut loss = RelayLoss::default();
        assert!(!loss.lost(r1, &set(&[r1, r2]), None, t0));
        // Both lost (the first one's reservation is gone by then): once.
        assert!(loss.lost(r2, &set(&[r2]), None, t0 + s(10)));
        assert!(
            !loss.lost(r2, &set(&[r2]), None, t0 + s(11)),
            "reported once"
        );
        // A second report inside the window: no, even with both lost again.
        assert!(!loss.lost(r1, &set(&[r1, r2]), None, t0 + s(40)));
        assert!(!loss.lost(r2, &set(&[r2]), None, t0 + s(41)));
        // A window later, both lost again: reported again.
        assert!(!loss.lost(r1, &set(&[r1, r2]), None, t0 + s(75)));
        assert!(loss.lost(r2, &set(&[r2]), None, t0 + s(76)));

        // A ping answered after the first loss: something still reaches us.
        let mut loss = RelayLoss::default();
        loss.answered();
        assert!(!loss.answered, "nothing lost yet: no window to mark");
        assert!(!loss.lost(r1, &set(&[r1, r2]), None, t0));
        loss.answered();
        assert!(!loss.lost(r2, &set(&[r2]), None, t0 + s(5)));

        // A peer that holds no reservation (a contact): no window, no report.
        let mut loss = RelayLoss::default();
        assert!(!loss.lost(bob, &set(&[r1]), None, t0));
        assert!(loss.first.is_none());
        // With a single relay and no other connection, losing it is
        // enough; a contact lost inside the window changes nothing.
        assert!(loss.lost(r1, &set(&[r1]), None, t0 + s(1)));
        assert!(!loss.lost(bob, &set(&[]), None, t0 + s(2)));

        // A1: another connection open (a contact's direct one) gets one ping
        // round to answer first: it does, so only the relay died.
        let round = s(20);
        let mut loss = RelayLoss::default();
        assert!(!loss.lost(r1, &set(&[r1]), Some(round), t0));
        assert!(!loss.due(t0 + s(5)), "not yet");
        loss.answered();
        assert!(!loss.due(t0 + round), "answered: not our path");
        assert!(loss.pending.is_none() && loss.last_report.is_none());
        // It does not: our path died too, reported once the round is up.
        let mut loss = RelayLoss::default();
        assert!(!loss.lost(r1, &set(&[r1]), Some(round), t0));
        assert!(!loss.due(t0 + round - s(1)));
        assert!(loss.due(t0 + round));
        assert!(!loss.due(t0 + round + s(1)), "once");
        // Two relays: the second one lost while a contact is connected waits
        // too; the window's report limit still holds.
        let mut loss = RelayLoss::default();
        assert!(!loss.lost(r1, &set(&[r1, r2]), Some(round), t0));
        assert!(loss.pending.is_none(), "one of two");
        assert!(!loss.lost(r2, &set(&[r2]), Some(round), t0 + s(10)));
        assert!(loss.due(t0 + s(10) + round));
        assert!(!loss.lost(r1, &set(&[r1, r2]), None, t0 + s(40)));
        assert!(
            !loss.lost(r2, &set(&[r2]), None, t0 + s(41)),
            "reported once"
        );
    }

    #[test]
    fn lab_ping_parses_bounded_values_and_is_inert_in_release() {
        let s = Duration::from_secs;
        for (text, want) in [
            ("2,1", Some((s(2), s(1)))),
            (" 15 , 5 ", Some((s(15), s(5)))),
            ("1,1", Some((s(1), s(1)))),
            ("60,60", Some((s(60), s(60)))),
            ("0,0", None),
            ("2,0", None),
            ("2,3", None),
            ("61,1", None),
            ("2", None),
            ("2,1,1", None),
            ("-1,1", None),
            ("2,x", None),
            ("", None),
        ] {
            assert_eq!(parse_lab_ping(text), want, "{text:?}");
        }
        // Release builds never read it (runs in a release test job; a debug
        // build skips it). Edition 2021: a plain call.
        if !cfg!(debug_assertions) {
            std::env::set_var("RAVEN_LAB_P2P_PING", "2,1");
            assert_eq!(lab_ping(), None);
        }
    }

    /// A seed for a real endpoint (the test opens the gate itself; nothing
    /// is published and no process state is touched). The receiver keeps
    /// the command channel open. Its proxy source reads neither this
    /// process's environment nor this computer's settings (a lab run with
    /// the proxy gate open would otherwise follow them).
    fn test_seed<'a>(
        gate: &'a HostGate,
        data_dir: &Path,
        config: P2pConfig,
    ) -> (HostSeed<'a>, mpsc::Receiver<Command>) {
        let (commands, command_rx) = mpsc::channel(64);
        let loaded = load_gate(data_dir, &config.relays);
        let keypair = test_key(13);
        let auto = AutoRelays::load(
            data_dir,
            &keypair.public().to_peer_id(),
            config.auto.is_some(),
        );
        let setting = config.proxy.setting.clone();
        let port_map_base = PortMapConfig {
            nonce_key: raven_core::portmap::nonce_key(&Identity::from_seed(&[13; 32])),
            ..PortMapConfig::upnp_only()
        };
        let seed = HostSeed::new(
            gate,
            keypair,
            data_dir.to_path_buf(),
            config,
            "test".into(),
            commands,
            loaded,
            auto,
            port_map_base,
        );
        let system = raven_core::net_proxy::SystemProxy::default;
        let proxy = ProxySource::with_readers(setting, |_| None, system);
        let seed = HostSeed {
            proxy: Arc::new(proxy),
            ..seed
        };
        (seed, command_rx)
    }

    fn loopback_config(relays: Vec<ViaAddr>) -> P2pConfig {
        P2pConfig {
            listen: P2pListen::One("127.0.0.1:0".parse().unwrap()),
            retired_relay: false,
            relays,
            relay_server: None,
            upnp: None,
            v6_pinhole: None,
            auto: None,
            policy_relays_pending: false,
            proxy: P2pProxy::default(),
        }
    }

    fn gate_row(key: &str, pinned: bool, p2p: String, via: Vec<String>) -> serde_json::Value {
        serde_json::json!({ "pub_hex": key, "pinned": pinned, "p2p": p2p, "p2p_via": via })
    }

    fn gate_via(n: u8, ip: &str) -> String {
        format!("/ip4/{ip}/tcp/7423/p2p/{}", peer(n))
    }

    fn peer_id(n: u8) -> PeerId {
        peer(n).parse().unwrap()
    }

    /// Privacy pack PP.6: a sealed profile keeps the relays set by hand in
    /// node_policy.json's sealed sidecar. A host started before the at-rest
    /// key was loaded has none; the peer gate's next load after the key
    /// arrived reads them (and admits them as its own relays), once. Phase
    /// 4: the proxy setting the sidecar holds too, likewise.
    #[test]
    fn policy_relays_follow_the_at_rest_key() {
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
        let sealed =
            raven_core::privacy::migrate_all(dd, crate::now_ms(), MigratePolicy::Allow).unwrap();
        assert_eq!(sealed.outcome, raven_core::privacy::MigrateOutcome::Sealed);
        let relay = gate_via(5, "192.0.2.1");
        raven_core::node_policy::save_policy(
            dd,
            &raven_core::NodePolicy {
                p2p_listen: "7423".into(),
                p2p_relays: vec![relay.clone()],
                p2p_proxy: "http://proxy.example:3128".into(),
                ..raven_core::NodePolicy::default()
            },
        )
        .unwrap();
        at_rest::forget_cached_keys(dd);
        assert!(!raven_core::node_policy::peers_readable(dd));
        let early = load_gate_for(dd, &[], true, true, None);
        assert_eq!(early.policy_relays, None, "the key is not loaded yet");
        assert_eq!(early.policy_proxy, None, "the key is not loaded yet");
        assert!(early.files.is_empty());
        at_rest::keys_load_with(dd, MigratePolicy::Allow).unwrap();
        let ready = load_gate_for(dd, &[], true, true, None);
        assert_eq!(
            ready.policy_relays,
            Some(vec![p2p_route::parse_via(&relay).unwrap()])
        );
        assert_eq!(
            ready.policy_proxy.as_deref(),
            Some("http://proxy.example:3128")
        );
        assert_eq!(
            ready.files.get(&peer_id(5)).copied(),
            Some(PeerClass::OWN_RELAY)
        );
        // Not pending (flags, env, or read at start): nothing is read again.
        let again = load_gate_for(dd, &[], false, false, None);
        assert_eq!((again.policy_relays, again.policy_proxy), (None, None));
    }

    /// The peer gate's set: verified, unblocked contacts' `p2p=` PeerIds
    /// and the relays their `via=` names, plus the configured relays (two
    /// at most). A running endpoint takes a newly read set and drops a
    /// contact that is no longer verified; a re-home keeps the set.
    #[tokio::test]
    async fn gate_files_admit_verified_unblocked_contacts_and_their_relays() {
        use raven_swarm::gate::Admission as _;
        let dir = tempfile::tempdir().unwrap();
        let book = dir.path().join("contacts.json");
        let rows = |rows: Vec<serde_json::Value>| serde_json::to_string(&rows).unwrap();
        std::fs::write(
            &book,
            rows(vec![
                // Verified, through its relay (2) and directly (itself).
                gate_row(
                    &"aa".repeat(32),
                    true,
                    peer(1),
                    vec![gate_via(2, "203.0.113.9"), gate_via(1, "198.51.100.1")],
                ),
                // Not verified.
                gate_row(
                    &"bb".repeat(32),
                    false,
                    peer(3),
                    vec![gate_via(6, "203.0.113.9")],
                ),
                // One key, one row verified and one not: not verified.
                gate_row(&"cc".repeat(32), true, peer(4), Vec::new()),
                gate_row(&"CC".repeat(32), false, String::new(), Vec::new()),
                // Verified, but no usable PeerId.
                gate_row(&"dd".repeat(32), true, "junk".into(), Vec::new()),
                // Verified, but blocked (below), and its relay with it.
                gate_row(
                    &"ee".repeat(32),
                    true,
                    peer(18),
                    vec![gate_via(19, "203.0.113.9")],
                ),
            ]),
        )
        .unwrap();
        let mut blocks = raven_core::chat_history::BlockList::default();
        blocks.block(&"EE".repeat(32));
        blocks.save(dir.path()).unwrap();
        let relays = vec![
            p2p_route::parse_via(&gate_via(5, "192.0.2.1")).unwrap(),
            p2p_route::parse_via(&gate_via(2, "192.0.2.2")).unwrap(),
        ];
        let (set, unreadable) = gate_files(dir.path(), &relays);
        assert!(!unreadable);
        let expected: HashMap<PeerId, PeerClass> = [
            (peer_id(1), PeerClass::CONTACT),
            // Our own relay and a contact's.
            (peer_id(2), PeerClass::CONTACT_RELAY | PeerClass::OWN_RELAY),
            (peer_id(5), PeerClass::OWN_RELAY),
        ]
        .into();
        assert_eq!(set, expected);
        let none = tempfile::tempdir().unwrap();
        assert_eq!(
            gate_files(none.path(), &relays[..1]),
            ([(peer_id(5), PeerClass::OWN_RELAY)].into(), false)
        );

        // A running endpoint: built with the set, and it takes a new one.
        let gate = HostGate::open(true).unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(relays.clone()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        assert_eq!(host.gate.class_of(&peer_id(1)), PeerClass::CONTACT);
        assert_eq!(host.gate.class_of(&peer_id(3)), PeerClass::NONE);
        assert_eq!(host.gate.class_of(&peer_id(18)), PeerClass::NONE);
        assert_eq!(host.gate_stamp, gate_stamp(dir.path()));
        assert_eq!(
            host.status_info().gate.as_deref(),
            Some(&P2pGateStatus {
                contacts: 1,
                relays: 2,
                ..P2pGateStatus::default()
            })
        );
        std::fs::write(
            &book,
            rows(vec![
                gate_row(&"aa".repeat(32), false, peer(1), Vec::new()),
                gate_row(&"bb".repeat(32), true, peer(3), Vec::new()),
            ]),
        )
        .unwrap();
        assert_ne!(
            gate_stamp(dir.path()),
            host.gate_stamp,
            "the change is seen"
        );
        let fresh = load_gate(dir.path(), &relays);
        assert!(host
            .on_command(Command::GateLoaded(Box::new(fresh)))
            .is_none());
        assert_eq!(host.gate.class_of(&peer_id(1)), PeerClass::NONE);
        assert_eq!(host.gate.class_of(&peer_id(3)), PeerClass::CONTACT);
        assert_eq!(host.gate.summary(), (1, 2, false));
        assert_eq!(host.gate_stamp, gate_stamp(dir.path()));
        // A dial admits the contact it checked and its relays at once,
        // whatever the set read last.
        let (reply, _answer) = oneshot::channel();
        host.connect(
            peer_id(7),
            PeerClass::CONTACT,
            vec![peer_id(8)],
            Vec::new(),
            std::time::Instant::now(),
            reply,
        );
        assert_eq!(host.gate.class_of(&peer_id(7)), PeerClass::CONTACT);
        assert_eq!(host.gate.class_of(&peer_id(8)), PeerClass::CONTACT_RELAY);
        // The next endpoint generation shares the set (a re-home never
        // touches it).
        drop(host);
        let (fresh, _incoming, _handle) = seed.build(1, true).unwrap();
        assert_eq!(fresh.gate.class_of(&peer_id(3)), PeerClass::CONTACT);
        assert_eq!(fresh.gate.class_of(&peer_id(7)), PeerClass::CONTACT);
    }

    /// Every endpoint generation drops the seed's kept proxy decision, so
    /// the settings are read again after a re-home; between generations the
    /// decision is kept.
    #[tokio::test]
    async fn every_generation_reads_the_proxy_settings_again() {
        use std::sync::atomic::AtomicUsize;
        let dir = tempfile::tempdir().unwrap();
        let gate = HostGate::open(true).unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(Vec::new()));
        let reads = Arc::new(AtomicUsize::new(0));
        let counted = reads.clone();
        let seed = HostSeed {
            proxy: Arc::new(ProxySource::with_readers(
                ProxySetting::Auto,
                |_| None,
                move || {
                    counted.fetch_add(1, Ordering::SeqCst);
                    raven_core::net_proxy::SystemProxy::default()
                },
            )),
            ..seed
        };
        let (host, _incoming, _handle) = seed.build(0, false).unwrap();
        seed.proxy.effective();
        seed.proxy.effective();
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        drop(host);
        let (_fresh, _incoming, _handle) = seed.build(1, true).unwrap();
        seed.proxy.effective();
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }

    /// A proxy source behind an open (or shut) test gate, with the
    /// explicit proxy `http://proxy.example:3128`: nothing is read.
    fn test_proxy(gate: fn() -> bool) -> Arc<ProxySource> {
        Arc::new(
            ProxySource::with_readers(
                raven_core::net_proxy::parse_setting("http://proxy.example:3128").unwrap(),
                |_| None,
                raven_core::net_proxy::SystemProxy::default,
            )
            .with_gate(gate),
        )
    }

    /// Review B-1 (RWS1 §8.3): a WSS name the bypass list sends direct
    /// (`NO_PROXY=.corp.example`) is resolved here into
    /// `/ip4/A/…/tls/sni/<name>/ws`; that form is still direct, so the slot
    /// is labelled `wss` and the network is not restricted. Only the name
    /// decides for it: the same IP without the name goes through the proxy.
    #[test]
    fn a_resolved_wss_form_whose_name_bypasses_the_proxy_is_direct() {
        let proxy = ProxySource::with_readers(
            raven_core::net_proxy::ProxySetting::Auto,
            |name| match name {
                "HTTPS_PROXY" => Some("http://127.0.0.1:1".into()),
                "NO_PROXY" => Some(".corp.example".into()),
                _ => None,
            },
            raven_core::net_proxy::SystemProxy::default,
        )
        .with_gate(|| true);
        let relay = peer(13);
        let path = |text: String| RelayPath::of(&text.parse().unwrap(), &proxy);
        let host = |name: &str| wss::Host::Name(name.into());
        assert!(!proxy.applies(&host("relay.corp.example"), 443));
        assert!(proxy.applies(&host("relay.example.org"), 443));
        assert_eq!(
            path(format!(
                "/ip4/10.1.2.3/tcp/443/tls/sni/relay.corp.example/ws/p2p/{relay}"
            )),
            RelayPath::Wss
        );
        assert_eq!(
            path(format!(
                "/ip4/10.1.2.3/tcp/443/tls/sni/relay.example.org/ws/p2p/{relay}"
            )),
            RelayPath::WssProxy
        );
        assert_eq!(
            path(format!("/ip4/10.1.2.3/tcp/443/tls/ws/p2p/{relay}")),
            RelayPath::WssProxy
        );
        assert_eq!(
            path(format!(
                "/dns4/relay.corp.example/tcp/443/tls/ws/p2p/{relay}"
            )),
            RelayPath::Wss
        );
        let forms = DialForms {
            wss: true,
            proxy: Some(Arc::new(proxy)),
            restricted: false,
        };
        let resolved: Multiaddr =
            format!("/ip4/10.1.2.3/tcp/443/tls/sni/relay.corp.example/ws/p2p/{relay}")
                .parse()
                .unwrap();
        assert!(!forms.proxied(&resolved));
    }

    /// RWS1 §2.3 for a relay slot, planned before every attempt: with the
    /// WSS gate closed a WSS address is dialled at its raw sibling alone
    /// (whatever the proxy says); live, raw first, or the WSS form first
    /// when the proxy carries it or the network is restricted; a raw TCP
    /// 443 address gains its WSS sibling; QUIC and other ports stay as they
    /// are. How a form travels follows the proxy (never for loopback), and a
    /// contact's dial plan takes the same forms.
    #[test]
    fn relay_slot_forms_follow_proxy_and_gate() {
        let relay = peer(11);
        let wss = format!("/dns4/relay.example/tcp/443/tls/ws/p2p/{relay}");
        let raw_of_wss = format!("/dns4/relay.example/tcp/443/p2p/{relay}");
        let raw443 = format!("/ip4/203.0.113.7/tcp/443/p2p/{relay}");
        let wss_of_raw = format!("/ip4/203.0.113.7/tcp/443/tls/ws/p2p/{relay}");
        let quic = format!("/ip4/203.0.113.7/udp/7423/quic-v1/p2p/{relay}");
        let tcp = format!("/ip4/203.0.113.7/tcp/7423/p2p/{relay}");
        let now = Instant::now();
        let new_slot = |texts: Vec<String>| {
            RelaySlot::new(relay.parse().unwrap(), texts, Source::Manual, now).unwrap()
        };
        let forms = |slot: &RelaySlot| -> Vec<String> {
            slot.forms.iter().map(|a| a.to_string()).collect()
        };
        let mut slot = new_slot(vec![wss.clone(), raw443.clone()]);
        assert_eq!(forms(&slot), vec![wss.clone(), raw443.clone()], "as named");
        let closed_cases = [
            DialForms::default(),
            DialForms {
                wss: false,
                proxy: Some(test_proxy(|| true)),
                restricted: true,
            },
        ];
        for dial in &closed_cases {
            slot.plan_forms(dial);
            assert_eq!(forms(&slot), vec![raw_of_wss.clone(), raw443.clone()]);
        }
        slot.plan_forms(&DialForms {
            wss: true,
            proxy: Some(test_proxy(|| false)),
            restricted: false,
        });
        assert_eq!(
            forms(&slot),
            vec![
                raw_of_wss.clone(),
                wss.clone(),
                raw443.clone(),
                wss_of_raw.clone()
            ]
        );
        let carried = DialForms {
            wss: true,
            proxy: Some(test_proxy(|| true)),
            restricted: false,
        };
        let wss_first = vec![
            wss.clone(),
            raw_of_wss.clone(),
            wss_of_raw.clone(),
            raw443.clone(),
        ];
        slot.plan_forms(&carried);
        assert_eq!(forms(&slot), wss_first);
        slot.plan_forms(&DialForms {
            wss: true,
            proxy: None,
            restricted: true,
        });
        assert_eq!(forms(&slot), wss_first, "restricted");
        let mut other = new_slot(vec![quic.clone(), tcp.clone()]);
        other.plan_forms(&carried);
        assert_eq!(forms(&other), vec![quic.clone(), tcp.clone()]);

        let proxy = test_proxy(|| true);
        let path = |text: &str, proxy: &ProxySource| RelayPath::of(&text.parse().unwrap(), proxy);
        assert_eq!(path(&wss, &proxy), RelayPath::WssProxy);
        assert_eq!(path(&wss_of_raw, &proxy), RelayPath::WssProxy);
        assert_eq!(path(&raw443, &proxy), RelayPath::Tcp);
        assert_eq!(path(&quic, &proxy), RelayPath::Quic);
        let loopback = format!("/ip4/127.0.0.1/tcp/443/tls/ws/p2p/{relay}");
        assert_eq!(path(&loopback, &proxy), RelayPath::Wss);
        assert_eq!(path(&wss_of_raw, &test_proxy(|| false)), RelayPath::Wss);
        assert_eq!(
            [
                RelayPath::Tcp,
                RelayPath::Quic,
                RelayPath::Wss,
                RelayPath::WssProxy
            ]
            .map(RelayPath::as_str),
            ["tcp", "quic", "wss", "wss-proxy"]
        );

        // A contact's circuits through that relay, and an explicit circuit,
        // at the same forms.
        let bob = peer(12);
        let through = |form: &str| format!("{form}/p2p-circuit/p2p/{bob}");
        let book = p2p_route::ContactP2p::from_fields(&bob, std::slice::from_ref(&wss)).unwrap();
        let set = P2pDialSet::merge(Some(&book), None, |_| true, None).unwrap();
        let by_peer = p2p_route::parse_p2p_dial(&p2p_route::peer_route(&bob)).unwrap();
        let explicit = p2p_route::parse_p2p_dial(&through(&wss)).unwrap();
        let plan = |target: &P2pDialTarget, dial: &DialForms| -> Vec<String> {
            dial_addrs(target, Some(&set), dial)
                .unwrap()
                .iter()
                .map(|a| a.to_string())
                .collect()
        };
        for target in [&by_peer, &explicit] {
            assert_eq!(
                plan(target, &DialForms::default()),
                vec![through(&raw_of_wss)]
            );
            assert_eq!(
                plan(target, &carried),
                vec![through(&wss), through(&raw_of_wss)]
            );
        }
    }

    /// RWS1 §9 (owner decision O4-6): the restricted flag is set as soon as
    /// a slot asks for its reservation on a WSS form the proxy carries (the
    /// relay's Identify runs before the reservation is accepted), stays
    /// while the reservation is held that way, and clears when it is lost
    /// or asked on another path. Status shows the path, the proxy word and
    /// the flag; while it holds, a dial plans no direct address and an
    /// explicit one is refused. The flag is the seed's: every generation's
    /// endpoint and handle share it.
    #[tokio::test]
    async fn restricted_flag_follows_proxied_reservations() {
        let dir = tempfile::tempdir().unwrap();
        let gate = HostGate::open(true).unwrap();
        let relay = peer(41);
        let relay_id: PeerId = relay.parse().unwrap();
        let wss_text = format!("/ip4/203.0.113.7/tcp/443/tls/ws/p2p/{relay}");
        let raw_text = format!("/ip4/203.0.113.7/tcp/443/p2p/{relay}");
        let via = p2p_route::parse_via(&wss_text).unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(vec![via]));
        let seed = HostSeed {
            proxy: test_proxy(|| true),
            ..seed
        };
        let (mut host, _incoming, handle) = seed.build(0, false).unwrap();
        assert!(Arc::ptr_eq(&handle.restricted, &seed.restricted));
        assert!(Arc::ptr_eq(&handle.proxy, &seed.proxy));
        let restricted = || seed.restricted.load(Ordering::SeqCst);
        // Asked on a form the proxy carries: restricted at once.
        let ask = |host: &mut Host, text: &str| {
            host.slots[0].resolved = vec![text.parse().unwrap()];
            host.slots[0].next = 0;
            host.request_reservation(0);
        };
        ask(&mut host, &wss_text);
        assert_eq!(host.slots[0].path, Some(RelayPath::WssProxy));
        assert!(restricted() && handle.forms().restricted);
        let status = host.status_info();
        assert!(status.restricted);
        assert_eq!(status.relay_paths, vec![String::new()], "not held yet");
        assert_eq!(status.proxy, "setting");
        // Accepted on it: held through the proxy.
        host.on_event(SwarmEvent::Behaviour(EndpointBehaviourEvent::RelayClient(
            relay::client::Event::ReservationReqAccepted {
                relay_peer_id: relay_id,
                renewal: false,
                limit: None,
            },
        )));
        assert!(host.slots[0].active && restricted());
        assert_eq!(
            host.status_info().relay_paths,
            vec!["wss-proxy".to_string()]
        );
        // No direct address while restricted.
        let bob = peer(42);
        let direct = format!("/ip4/198.51.100.9/tcp/7423/p2p/{bob}");
        let book =
            p2p_route::ContactP2p::from_fields(&bob, &[direct.clone(), wss_text.clone()]).unwrap();
        let set = P2pDialSet::merge(Some(&book), None, |_| true, None).unwrap();
        let by_peer = p2p_route::parse_p2p_dial(&p2p_route::peer_route(&bob)).unwrap();
        let planned = dial_addrs(&by_peer, Some(&set), &handle.forms()).unwrap();
        assert!(
            !planned.is_empty() && planned.iter().all(is_circuit),
            "{planned:?}"
        );
        let explicit = p2p_route::parse_p2p_dial(&direct).unwrap();
        assert_eq!(
            dial_addrs(&explicit, Some(&set), &handle.forms()).unwrap_err(),
            P2P_RESTRICTED_DIRECT
        );
        // Lost: no longer restricted, and the direct address is back.
        let listener = host.slots[0].listener.unwrap();
        host.on_event(SwarmEvent::ListenerClosed {
            listener_id: listener,
            addresses: Vec::new(),
            reason: Err(std::io::Error::other("lost")),
        });
        assert!(!restricted() && !handle.forms().restricted);
        assert_eq!(host.slots[0].path, None);
        let status = host.status_info();
        assert!(!status.restricted);
        assert_eq!(status.relay_paths, vec![String::new()]);
        let planned = dial_addrs(&by_peer, Some(&set), &handle.forms()).unwrap();
        assert_eq!(planned[0].to_string(), direct);
        // Asked on the raw form: not restricted.
        ask(&mut host, &raw_text);
        assert_eq!(host.slots[0].path, Some(RelayPath::Tcp));
        assert!(!restricted());
        // The next generation shares the flag.
        ask(&mut host, &wss_text);
        assert!(restricted());
        drop(host);
        let (_next, _incoming, next_handle) = seed.build(1, true).unwrap();
        assert!(Arc::ptr_eq(&next_handle.restricted, &handle.restricted));
    }

    /// Review B-2: the proxy's 407 word is cleared by any reservation
    /// accepted, also one on the raw sibling a slot rotated to after the
    /// proxied form failed: a node that holds a relay is not kept away by
    /// the proxy, so the credentials hint must not stay.
    #[tokio::test]
    async fn a_reservation_on_the_raw_form_clears_the_proxys_407() {
        use raven_swarm::wss::ProxyError;
        let dir = tempfile::tempdir().unwrap();
        let gate = HostGate::open(true).unwrap();
        let relay = peer(43);
        let relay_id: PeerId = relay.parse().unwrap();
        let wss_text = format!("/ip4/203.0.113.7/tcp/443/tls/ws/p2p/{relay}");
        let raw_text = format!("/ip4/203.0.113.7/tcp/443/p2p/{relay}");
        let via = p2p_route::parse_via(&wss_text).unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(vec![via]));
        let seed = HostSeed {
            proxy: test_proxy(|| true),
            ..seed
        };
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        host.on_event(SwarmEvent::OutgoingConnectionError {
            connection_id: ConnectionId::new_unchecked(12),
            peer_id: Some(relay_id),
            error: DialError::Transport(vec![(
                wss_text.parse().unwrap(),
                TransportError::Other(std::io::Error::other(ProxyError::Auth {
                    schemes: vec!["Basic"],
                    sent_basic: false,
                })),
            )]),
        });
        assert_eq!(host.status_info().proxy_auth, "basic");
        host.slots[0].resolved = vec![raw_text.parse().unwrap()];
        host.slots[0].next = 0;
        host.request_reservation(0);
        assert_eq!(host.slots[0].path, Some(RelayPath::Tcp));
        host.on_event(SwarmEvent::Behaviour(EndpointBehaviourEvent::RelayClient(
            relay::client::Event::ReservationReqAccepted {
                relay_peer_id: relay_id,
                renewal: false,
                limit: None,
            },
        )));
        assert!(host.slots[0].active);
        let status = host.status_info();
        assert_eq!(status.relay_paths, vec!["tcp".to_string()]);
        assert!(status.proxy_auth.is_empty(), "{}", status.proxy_auth);
    }

    /// A dial admits the contact it checked and its relays, but the files
    /// read after it win: a contact blocked (or unpinned, or removed) once
    /// we dialled it is no longer admitted, and neither are the relays only
    /// its card named.
    #[tokio::test]
    async fn a_block_after_a_dial_ends_the_dial_admission() {
        use raven_swarm::gate::Admission as _;
        let dir = tempfile::tempdir().unwrap();
        let (bob, bob_relay) = (peer_id(1), peer_id(2));
        std::fs::write(
            dir.path().join("contacts.json"),
            serde_json::to_string(&vec![gate_row(
                &"aa".repeat(32),
                true,
                peer(1),
                vec![gate_via(2, "203.0.113.9")],
            )])
            .unwrap(),
        )
        .unwrap();
        let gate = HostGate::open(true).unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        let (reply, _answer) = oneshot::channel();
        host.connect(
            bob,
            PeerClass::CONTACT,
            vec![bob_relay],
            Vec::new(),
            std::time::Instant::now(),
            reply,
        );
        assert_eq!(host.gate.class_of(&bob), PeerClass::CONTACT);
        assert_eq!(host.gate.class_of(&bob_relay), PeerClass::CONTACT_RELAY);

        let mut blocks = raven_core::chat_history::BlockList::default();
        blocks.block(&"aa".repeat(32));
        blocks.save(dir.path()).unwrap();
        let fresh = load_gate(dir.path(), &[]);
        assert!(host
            .on_command(Command::GateLoaded(Box::new(fresh)))
            .is_none());
        assert_eq!(host.gate.class_of(&bob), PeerClass::NONE);
        assert_eq!(host.gate.class_of(&bob_relay), PeerClass::NONE);
        assert_eq!(host.gate.summary(), (0, 0, false));
    }

    /// A block written between a dial's check and its admission, with the
    /// reload it causes landing first, never leaves the dial admitted: the
    /// connect is refused, the dial checks the contact again, and that check
    /// refuses the blocked contact. A dial raced by a reload where only
    /// another contact changed is checked again and admitted, even to a
    /// PeerId the card does not list (an explicit dial).
    #[tokio::test]
    async fn a_dial_raced_by_a_reload_is_checked_again() {
        use raven_swarm::gate::Admission as _;
        let dir = tempfile::tempdir().unwrap();
        let bob_key = [0xaa; 32];
        let bob = gate_row(&hex::encode(bob_key), true, peer(1), Vec::new());
        let write_book = |rows: &[serde_json::Value]| {
            std::fs::write(
                dir.path().join("contacts.json"),
                serde_json::to_string(rows).unwrap(),
            )
            .unwrap();
        };
        write_book(std::slice::from_ref(&bob));
        let gate = HostGate::open(true).unwrap();
        let (seed, mut commands) = test_seed(&gate, dir.path(), loopback_config(Vec::new()));
        let (mut host, _incoming, handle) = seed.build(0, false).unwrap();
        let target_of = |n: u8| p2p_route::parse_p2p_dial(&gate_via(n, "203.0.113.9")).unwrap();

        // Only another contact changed, and the reload read it after the
        // check: the explicit dial is checked again, then admitted.
        let explicit = target_of(5);
        let mut check = check_dial(dir.path(), bob_key, &explicit).await.unwrap();
        let first = check.checked_at;
        write_book(&[bob, gate_row(&"cc".repeat(32), true, peer(3), Vec::new())]);
        assert!(host
            .on_command(Command::GateLoaded(Box::new(load_gate(dir.path(), &[]))))
            .is_none());
        assert_eq!(host.gate.class_of(&peer_id(5)), PeerClass::NONE);
        let mut connects = 0;
        {
            let wait = ConnectWait::new(CONNECT_DEADLINE);
            let dial = connect_checked(
                &handle,
                dir.path(),
                bob_key,
                &explicit,
                peer_id(5),
                &mut check,
                &wait,
            );
            let serve = async {
                while let Some(command) = commands.recv().await {
                    connects += u32::from(matches!(command, Command::Connect { .. }));
                    host.on_command(command);
                    if host.gate.class_of(&peer_id(5)) == PeerClass::CONTACT {
                        break;
                    }
                }
            };
            tokio::time::timeout(Duration::from_secs(10), async {
                tokio::select! {
                    _ = dial => panic!("answered before it was admitted"),
                    () = serve => {}
                }
            })
            .await
            .expect("admitted on the second connect");
        }
        assert_eq!(connects, 2, "refused once, then checked again");
        assert!(check.checked_at > first);

        // bob is blocked after the dial checked him, and the reload lands
        // before the dial's connect: refused, nothing admitted.
        let target = target_of(1);
        let mut check = check_dial(dir.path(), bob_key, &target).await.unwrap();
        let mut blocks = raven_core::chat_history::BlockList::default();
        blocks.block(&hex::encode(bob_key));
        blocks.save(dir.path()).unwrap();
        assert!(host
            .on_command(Command::GateLoaded(Box::new(load_gate(dir.path(), &[]))))
            .is_none());
        let err = {
            let wait = ConnectWait::new(CONNECT_DEADLINE);
            let dial = connect_checked(
                &handle,
                dir.path(),
                bob_key,
                &target,
                peer_id(1),
                &mut check,
                &wait,
            );
            let serve = async {
                while let Some(command) = commands.recv().await {
                    host.on_command(command);
                }
            };
            tokio::time::timeout(Duration::from_secs(10), async {
                tokio::select! {
                    result = dial => result,
                    () = serve => unreachable!("the command channel stays open"),
                }
            })
            .await
            .expect("answered at once")
            .unwrap_err()
        };
        assert!(
            err.starts_with(crate::outbox::code::CONTACT_BLOCKED),
            "{err}"
        );
        assert_eq!(host.gate.class_of(&peer_id(1)), PeerClass::NONE);
        assert!(!host.swarm.is_connected(&peer_id(1)));
    }

    /// A connection that only a dial admission let in is closed by the
    /// first tick after its deadline, though no file changed (nothing else
    /// would close it: Identify keeps it busy).
    #[tokio::test]
    async fn a_tick_closes_a_connection_whose_dial_admission_ended() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        // B admits the host as its verified contact; the host's own book
        // is empty, so only its dial admits B.
        let b_dir = dir.path().join("b");
        std::fs::create_dir_all(&b_dir).unwrap();
        let host_peer =
            raven_swarm::kad_node::libp2p_keypair_from_raven(&Identity::from_seed(&[13; 32]))
                .public()
                .to_peer_id();
        std::fs::write(
            b_dir.join("contacts.json"),
            serde_json::to_string(&vec![gate_row(
                &"aa".repeat(32),
                true,
                host_peer.to_string(),
                Vec::new(),
            )])
            .unwrap(),
        )
        .unwrap();
        let (b_seed, _b_commands) = test_seed(&gate, &b_dir, loopback_config(Vec::new()));
        let b_seed = HostSeed {
            keypair: raven_swarm::kad_node::libp2p_keypair_from_raven(&Identity::from_seed(
                &[22; 32],
            )),
            ..b_seed
        };
        let (mut b, _b_incoming, _b_handle) = b_seed.build(0, false).unwrap();
        let b_peer = *b.swarm.local_peer_id();
        let tcp = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let event = b.swarm.select_next_some().await;
                b.on_event(event);
                let tcp = b
                    .listen_addrs
                    .iter()
                    .find(|a| a.iter().any(|p| matches!(p, Protocol::Tcp(_))));
                if let Some(tcp) = tcp {
                    break tcp.clone();
                }
            }
        })
        .await
        .expect("B listens on TCP");

        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        host.gate
            .admit_dial(
                b_peer,
                PeerClass::CONTACT,
                &[],
                std::time::Instant::now(),
                deadline,
            )
            .unwrap();
        host.swarm
            .dial(DialOpts::peer_id(b_peer).addresses(vec![tcp]).build())
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while !host.swarm.is_connected(&b_peer) {
                tokio::select! {
                    event = b.swarm.select_next_some() => b.on_event(event),
                    event = host.swarm.select_next_some() => host.on_event(event),
                }
            }
        })
        .await
        .expect("the host connects to B");

        // Inside the admission a tick keeps the connection, and nothing
        // closes it past the deadline either.
        host.tick_gate(Instant::now());
        let past = Instant::from_std(deadline) + Duration::from_millis(200);
        assert!(!drive_until_closed(&mut host, &mut b, b_peer, past).await);
        assert!(host.swarm.is_connected(&b_peer));
        // The next tick does.
        host.tick_gate(Instant::now());
        let by = Instant::now() + Duration::from_secs(5);
        assert!(
            drive_until_closed(&mut host, &mut b, b_peer, by).await,
            "the tick after the deadline closes the connection"
        );
    }

    /// Run both hosts until `until`: `true` as soon as `host` has no
    /// connection to `peer` left.
    async fn drive_until_closed(
        host: &mut Host,
        b: &mut Host,
        peer: PeerId,
        until: Instant,
    ) -> bool {
        loop {
            tokio::select! {
                event = b.swarm.select_next_some() => b.on_event(event),
                event = host.swarm.select_next_some() => {
                    let gone = matches!(
                        &event,
                        SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. }
                            if *peer_id == peer
                    );
                    host.on_event(event);
                    if gone {
                        return true;
                    }
                }
                _ = tokio::time::sleep_until(until) => return false,
            }
        }
    }

    /// A contact book or block list that cannot be read admits no contact,
    /// but still the configured relays (fail closed; the relays keep the
    /// node reachable for when it is fixed).
    #[test]
    fn unreadable_contacts_admit_relays_only() {
        let dir = tempfile::tempdir().unwrap();
        let relays = vec![p2p_route::parse_via(&gate_via(5, "192.0.2.1")).unwrap()];
        let own: HashMap<PeerId, PeerClass> = [(peer_id(5), PeerClass::OWN_RELAY)].into();
        std::fs::write(
            dir.path().join("contacts.json"),
            serde_json::to_string(&vec![gate_row(&"aa".repeat(32), true, peer(1), Vec::new())])
                .unwrap(),
        )
        .unwrap();
        assert_eq!(gate_files(dir.path(), &relays).0.len(), 2);
        let blocked = raven_core::chat_history::blocked_path(dir.path());
        std::fs::write(&blocked, b"{broken").unwrap();
        assert_eq!(gate_files(dir.path(), &relays), (own.clone(), true));
        std::fs::remove_file(&blocked).unwrap();
        std::fs::write(dir.path().join("contacts.json"), b"[{").unwrap();
        let loaded = load_gate(dir.path(), &relays);
        assert!(loaded.unreadable);
        assert_eq!(loaded.files, own);
        assert_eq!(loaded.stamp, gate_stamp(dir.path()));
    }

    // ── Route hints: the dial set, hide my IP, own routes ────────────────

    /// A learned_routes.json row: what `key`'s route hints said.
    fn learned_row(key: &str, peer_id: &str, relays: &[String], proven: bool) -> serde_json::Value {
        let now = crate::now_ms();
        serde_json::json!({
            "pub_hex": key,
            "generation": 7,
            "received_at_ms": now,
            "expires_at_ms": now + 3_600_000,
            "via": "p2p",
            "peer_id": peer_id,
            "peer_id_proven": proven,
            "relays": relays,
        })
    }

    fn write_learned(dir: &Path, rows: &[serde_json::Value]) {
        std::fs::write(
            dir.join(raven_core::learned_routes::LEARNED_ROUTES_FILE),
            serde_json::to_vec(rows).unwrap(),
        )
        .unwrap();
    }

    /// Auto-reach (design §5.1): a punch target is a verified contact the
    /// gate admits whose live route hints name its PeerId, a global QUIC
    /// endpoint and a NAT class that keeps one mapping; a contact whose class
    /// varies (or is unknown) is counted as skipped, one with TCP only is no
    /// target, and hide my IP for everyone leaves none.
    #[test]
    fn punch_targets_need_a_quic_endpoint_and_a_stable_nat() {
        let dir = tempfile::tempdir().unwrap();
        let keys: Vec<String> = [0xb1u8, 0xc1, 0xd1, 0xe1]
            .iter()
            .map(|b| hex::encode([*b; 32]))
            .collect();
        std::fs::write(
            dir.path().join("contacts.json"),
            serde_json::to_string(
                &keys
                    .iter()
                    .enumerate()
                    .map(|(i, k)| gate_row(k, true, peer(i as u8 + 1), Vec::new()))
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        )
        .unwrap();
        let row = |i: usize, direct: &[&str], quic: u8| {
            let mut r = learned_row(&keys[i], &peer(i as u8 + 1), &[], true);
            r["direct"] = serde_json::json!(direct
                .iter()
                .map(|d| format!("{d}/p2p/{}", peer(i as u8 + 1)))
                .collect::<Vec<_>>());
            r["nat_class"] = serde_json::json!({"v4_tcp": 0, "v4_quic": quic, "v6_tcp": 0, "v6_quic": 0, "flags": 0});
            r
        };
        write_learned(
            dir.path(),
            &[
                row(
                    0,
                    &["/ip4/11.0.3.7/udp/40001/quic-v1", "/ip4/11.0.3.7/tcp/17423"],
                    3,
                ),
                row(1, &["/ip4/11.0.3.8/udp/17423/quic-v1"], 4),
                row(2, &["/ip4/11.0.3.9/tcp/17423"], 2),
                row(3, &["/ip4/11.0.3.10/udp/17423/quic-v1"], 0),
            ],
        );
        let (files, unreadable) = gate_files(dir.path(), &[]);
        assert!(!unreadable);
        let (targets, skipped) = punch_targets(dir.path(), &files);
        assert_eq!(targets.len(), 1, "{targets:?}");
        assert_eq!(targets[0].key, [0xb1; 32]);
        assert_eq!(targets[0].peer, peer_id(1));
        assert_eq!(
            texts(&targets[0].addrs),
            [format!("/ip4/11.0.3.7/udp/40001/quic-v1/p2p/{}", peer(1))]
        );
        assert_eq!(skipped, 2, "varies and unknown");
        hide_everyone(dir.path(), true);
        assert!(punch_targets(dir.path(), &files).0.is_empty());
    }

    fn hide_everyone(dir: &Path, hide_ip: bool) {
        raven_core::node_policy::save_policy(
            dir,
            &raven_core::node_policy::NodePolicy {
                hide_ip,
                ..raven_core::node_policy::NodePolicy::default()
            },
        )
        .unwrap();
    }

    fn texts(addrs: &[Multiaddr]) -> Vec<String> {
        addrs.iter().map(ToString::to_string).collect()
    }

    /// While route hints are live a dial adds the relays the contact's
    /// route hints named (its current reservations) ahead of its card's,
    /// and admits them as its relays, as the peer gate's files do. Hints
    /// that name another PeerId than the card's are ignored whole; with
    /// route hints off the dial is the card's.
    #[tokio::test]
    async fn dial_set_uses_learned_relays_and_admits_them() {
        use raven_swarm::gate::Admission as _;
        let dir = tempfile::tempdir().unwrap();
        let bob_key = [0xaa; 32];
        let bob = hex::encode(bob_key);
        std::fs::write(
            dir.path().join("contacts.json"),
            serde_json::to_string(&vec![gate_row(
                &bob,
                true,
                peer(1),
                vec![gate_via(2, "203.0.113.9")],
            )])
            .unwrap(),
        )
        .unwrap();
        write_learned(
            dir.path(),
            &[learned_row(
                &bob,
                &peer(1),
                &[gate_via(3, "11.0.2.3")],
                true,
            )],
        );
        let circuit = |n: u8, ip: &str| format!("{}/p2p-circuit/p2p/{}", gate_via(n, ip), peer(1));
        let target = p2p_route::parse_p2p_dial(&p2p_route::peer_route(&peer(1))).unwrap();
        let check = check_dial(dir.path(), bob_key, &target).await.unwrap();
        assert_eq!(check.class, PeerClass::CONTACT);
        if !raven_core::route_hints::route_hints_live() {
            assert_eq!(texts(&check.addrs), vec![circuit(2, "203.0.113.9")]);
            assert_eq!(check.relays, vec![peer_id(2)]);
            return;
        }
        assert_eq!(
            texts(&check.addrs),
            vec![circuit(3, "11.0.2.3"), circuit(2, "203.0.113.9")],
            "the relays it holds now first"
        );
        assert_eq!(check.relays, vec![peer_id(3), peer_id(2)]);

        let gate = HostGate::open(true).unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        assert_eq!(
            host.gate.class_of(&peer_id(3)),
            PeerClass::CONTACT_RELAY,
            "the files name it too"
        );
        let (reply, _answer) = oneshot::channel();
        host.connect(
            peer_id(1),
            check.class,
            check.relays.clone(),
            Vec::new(),
            check.checked_at,
            reply,
        );
        assert_eq!(host.gate.class_of(&peer_id(1)), PeerClass::CONTACT);
        assert_eq!(host.gate.class_of(&peer_id(3)), PeerClass::CONTACT_RELAY);

        // Hints naming another PeerId: the card's dial only.
        write_learned(
            dir.path(),
            &[learned_row(
                &bob,
                &peer(4),
                &[gate_via(3, "11.0.2.3")],
                true,
            )],
        );
        let check = check_dial(dir.path(), bob_key, &target).await.unwrap();
        assert_eq!(texts(&check.addrs), vec![circuit(2, "203.0.113.9")]);
        assert_eq!(check.relays, vec![peer_id(2)]);
    }

    /// Hide my IP (D4), for one contact or for everyone: a dial goes only
    /// through relays this node holds itself, is admitted hidden (no hole
    /// punching, no Identify), and an explicit direct address, or a circuit
    /// through a relay this node does not hold (the contact's own relay
    /// would see our IP), is refused before anything is dialled. Without
    /// it, today's plan.
    #[tokio::test]
    async fn hidden_contact_dials_circuits_only_and_a_direct_target_is_refused() {
        use raven_swarm::gate::Admission as _;
        let dir = tempfile::tempdir().unwrap();
        let bob_key = [0xaa; 32];
        let (direct, relay) = (gate_via(1, "203.0.113.7"), gate_via(2, "198.51.100.2"));
        let circuit = format!("{relay}/p2p-circuit/p2p/{}", peer(1));
        let book = |hide_ip: bool| {
            let mut row = gate_row(
                &hex::encode(bob_key),
                true,
                peer(1),
                vec![relay.clone(), direct.clone()],
            );
            row["hide_ip"] = hide_ip.into();
            std::fs::write(
                dir.path().join("contacts.json"),
                serde_json::to_string(&vec![row]).unwrap(),
            )
            .unwrap();
        };
        let target = |t: &str| p2p_route::parse_p2p_dial(t).unwrap();
        let by_peer = target(&p2p_route::peer_route(&peer(1)));

        book(false);
        let check = check_dial(dir.path(), bob_key, &by_peer).await.unwrap();
        assert_eq!(texts(&check.addrs), vec![direct.clone(), circuit.clone()]);
        assert_eq!(check.class, PeerClass::CONTACT);

        let vias = |texts: &[String]| -> Vec<ViaAddr> {
            texts
                .iter()
                .map(|t| p2p_route::parse_via(t).unwrap())
                .collect()
        };
        // This node's own slot for the contact's relay, at another address
        // than the one the contact gives for it.
        let mine = gate_via(2, "11.0.5.2");
        let my_circuit = format!("{mine}/p2p-circuit/p2p/{}", peer(1));
        for (row, everyone) in [(true, false), (false, true)] {
            book(row);
            hide_everyone(dir.path(), everyone);
            // This node holds the contact's relay too: its circuit, at the
            // address this node's slot names, never the contact's.
            let held = || vias(&[mine.clone(), gate_via(9, "11.0.5.9")]);
            let check = check_dial_held(dir.path(), bob_key, &by_peer, held())
                .await
                .unwrap();
            assert_eq!(
                texts(&check.addrs),
                vec![my_circuit.clone()],
                "{row} {everyone}"
            );
            assert_eq!(check.class, PeerClass::CONTACT_HIDDEN);
            assert_eq!(check.relays, vec![peer_id(2)]);
            let refused = check_dial_held(dir.path(), bob_key, &target(&direct), held())
                .await
                .err()
                .expect("a direct address is refused");
            assert_eq!(refused, P2P_HIDDEN_DIRECT);
            assert!(refused.starts_with("P2P_UNREACHABLE: you hide your IP"));
            let via = check_dial_held(dir.path(), bob_key, &target(&my_circuit), held())
                .await
                .unwrap();
            assert_eq!(via.class, PeerClass::CONTACT_HIDDEN);
            assert_eq!(texts(&via.addrs), vec![my_circuit.clone()]);
            // Our relay's PeerId at the contact's address (it may be the
            // contact's own host): refused, nothing dialled.
            let refused = check_dial_held(dir.path(), bob_key, &target(&circuit), held())
                .await
                .err()
                .expect("our relay at the contact's address is refused");
            assert_eq!(refused, P2P_HIDDEN_RELAY);

            // A relay only the contact names (it may run it): no circuit,
            // and an explicit one is refused; a connection the contact
            // opened through our relays is still used (no address needed).
            for held in [Vec::new(), vias(&[gate_via(9, "11.0.5.9")])] {
                let check = check_dial_held(dir.path(), bob_key, &by_peer, held.clone())
                    .await
                    .unwrap();
                assert!(check.addrs.is_empty(), "{:?}", texts(&check.addrs));
                assert!(check.relays.is_empty());
                assert_eq!(check.class, PeerClass::CONTACT_HIDDEN);
                let refused = check_dial_held(dir.path(), bob_key, &target(&circuit), held)
                    .await
                    .err()
                    .expect("a circuit through a relay we do not hold is refused");
                assert_eq!(refused, P2P_HIDDEN_RELAY);
            }
        }
        hide_everyone(dir.path(), false);

        // The peer gate admits it hidden, from the files and from the dial.
        book(true);
        let gate = HostGate::open(true).unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        assert_eq!(host.gate.class_of(&peer_id(1)), PeerClass::CONTACT_HIDDEN);
        let (reply, _answer) = oneshot::channel();
        host.connect(
            peer_id(1),
            PeerClass::CONTACT_HIDDEN,
            vec![peer_id(2)],
            Vec::new(),
            std::time::Instant::now(),
            reply,
        );
        assert_eq!(host.gate.class_of(&peer_id(1)), PeerClass::CONTACT_HIDDEN);
        assert_eq!(host.gate.class_of(&peer_id(2)), PeerClass::CONTACT_RELAY);
    }

    /// The peer gate's files: a contact this node hides its IP from, or
    /// (route hints live) one whose PeerId is learned and not proven, is
    /// CONTACT_HIDDEN; a proven one is a CONTACT, and the relays its hints
    /// name are its relays. Learning, proving or hiding changes a file the
    /// gate's stamp covers, so the gate reloads.
    #[test]
    fn gate_files_give_contact_hidden_for_hidden_and_unproven_contacts() {
        let dir = tempfile::tempdir().unwrap();
        let mut hidden = gate_row(&"aa".repeat(32), true, peer(1), Vec::new());
        hidden["hide_ip"] = true.into();
        std::fs::write(
            dir.path().join("contacts.json"),
            serde_json::to_string(&vec![
                hidden,
                gate_row(&"bb".repeat(32), true, peer(2), Vec::new()),
                gate_row(&"cc".repeat(32), true, String::new(), Vec::new()),
                gate_row(&"dd".repeat(32), true, String::new(), Vec::new()),
            ])
            .unwrap(),
        )
        .unwrap();
        let stamp = gate_stamp(dir.path());
        write_learned(
            dir.path(),
            &[
                learned_row(
                    &"cc".repeat(32),
                    &peer(3),
                    &[gate_via(5, "11.0.2.5")],
                    false,
                ),
                learned_row(&"dd".repeat(32), &peer(4), &[], true),
            ],
        );
        assert_ne!(gate_stamp(dir.path()), stamp, "learning reloads the gate");
        let (set, unreadable) = gate_files(dir.path(), &[]);
        assert!(!unreadable);
        assert_eq!(set.get(&peer_id(1)), Some(&PeerClass::CONTACT_HIDDEN));
        assert_eq!(set.get(&peer_id(2)), Some(&PeerClass::CONTACT));
        if raven_core::route_hints::route_hints_live() {
            assert_eq!(set.get(&peer_id(3)), Some(&PeerClass::CONTACT_HIDDEN));
            assert_eq!(set.get(&peer_id(4)), Some(&PeerClass::CONTACT));
            assert_eq!(set.get(&peer_id(5)), Some(&PeerClass::CONTACT_RELAY));
        } else {
            assert_eq!(set.len(), 2, "{set:?}");
        }

        // Hide my IP for everyone: every contact hidden; the policy file is
        // in the stamp too.
        let stamp = gate_stamp(dir.path());
        hide_everyone(dir.path(), true);
        assert_ne!(gate_stamp(dir.path()), stamp, "hiding reloads the gate");
        let (set, _) = gate_files(dir.path(), &[]);
        assert_eq!(set.get(&peer_id(2)), Some(&PeerClass::CONTACT_HIDDEN));
    }

    /// What route hints tell about this endpoint changes only when its
    /// content does: confirmed addresses in any order, with or without
    /// `/p2p`, are the same value, circuits are never in it, and the relay
    /// list follows the slots whose reservation is active.
    /// Phase 4 (P4.24): the NAT classifier learns only from connections we
    /// dialled directly, reusing the listen port, over raw TCP or QUIC,
    /// while a listener of that transport and family is open.
    #[test]
    fn conn_meta_marks_only_reuse_outbound_direct_connections() {
        use raven_swarm::libp2p::core::Endpoint;
        let listen: Vec<Multiaddr> = vec![
            "/ip4/0.0.0.0/tcp/7423".parse().unwrap(),
            "/ip4/192.168.7.5/udp/7423/quic-v1".parse().unwrap(),
        ];
        let dial = |address: &str, port_use: PortUse| ConnectedPoint::Dialer {
            address: address.parse().unwrap(),
            role_override: Endpoint::Dialer,
            port_use,
        };
        let r = peer(5);
        for (endpoint, want) in [
            (dial("/ip4/8.8.8.8/tcp/7423", PortUse::Reuse), true),
            (
                dial(&format!("/ip4/8.8.8.8/tcp/7423/p2p/{r}"), PortUse::Reuse),
                true,
            ),
            (dial("/ip4/8.8.8.8/udp/7423/quic-v1", PortUse::Reuse), true),
            // A new port says nothing about the listen port's mapping.
            (dial("/ip4/8.8.8.8/tcp/7423", PortUse::New), false),
            // No IPv6 listener.
            (dial("/ip6/2001:4860::8888/tcp/7423", PortUse::Reuse), false),
            // Relayed, WSS, by name: never.
            (
                dial(
                    &format!("/ip4/8.8.8.8/tcp/7423/p2p/{r}/p2p-circuit/p2p/{}", peer(6)),
                    PortUse::Reuse,
                ),
                false,
            ),
            (dial("/ip4/8.8.8.8/tcp/443/tls/ws", PortUse::Reuse), false),
            (
                dial("/dns4/relay.example.org/tcp/7423", PortUse::Reuse),
                false,
            ),
            // Inbound connections never.
            (
                ConnectedPoint::Listener {
                    local_addr: "/ip4/192.168.7.5/tcp/7423".parse().unwrap(),
                    send_back_addr: "/ip4/8.8.8.8/tcp/50000".parse().unwrap(),
                },
                false,
            ),
        ] {
            assert_eq!(
                nat_feed(&endpoint, &listen_families(&listen)),
                want,
                "{endpoint:?}"
            );
        }
        // No listener reported when the dial began (libp2p-tcp had not
        // registered one for reuse yet): nothing, whatever opened since.
        assert!(!nat_feed(
            &dial("/ip4/8.8.8.8/tcp/7423", PortUse::Reuse),
            &[]
        ));
        assert_eq!(
            listen_families(&listen),
            [(Tr::Tcp, false), (Tr::Quic, false)]
        );
        let (ports, own) = nat_listen(&listen);
        assert!(ports.contains(&((Tr::Tcp, false), Some(7423))));
        assert!(ports.contains(&((Tr::Quic, false), Some(7423))));
        assert!(ports.contains(&((Tr::Tcp, true), None)));
        assert!(own.contains(&"192.168.7.5".parse::<IpAddr>().unwrap()));
    }

    /// Phase 4 (P4.24): two of our contacts on two networks see us at one
    /// outside address on the listen port: `stable_kept`, given to the
    /// hole-punch policy, told in IPC status and route hints, and logged as
    /// one line of words and a count (no address, port or PeerId). A
    /// stranger's view does not count; a third view at another port makes
    /// it `varies`. With the gate closed (the default) none of it runs.
    #[tokio::test]
    async fn nat_class_change_updates_the_hole_punch_policy_and_logs_counts_only() {
        use raven_swarm::libp2p::core::Endpoint;
        use raven_swarm::natclass::Mapping;
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        if !raven_core::nat_class_live_enabled() {
            assert!(host.nat_class.is_none());
            assert!(!host.swarm.behaviour().dcutr.policy.enabled);
            assert_eq!(host.status_info().nat_mapping, None);
            assert_eq!(host.own_p2p().nat, None);
        }
        // As the NAT_CLASS gate would set it up.
        host.nat_class = Some(NatClassifier::new());
        host.swarm.behaviour_mut().dcutr.policy_mut().enabled = true;
        host.listen_addrs = vec!["/ip4/192.168.7.5/tcp/7423".parse().unwrap()];
        host.nat_listen_changed();
        let (c1, c2, stranger) = (peer_id(31), peer_id(32), peer_id(33));
        host.gate.replace(
            HashMap::from([(c1, PeerClass::CONTACT), (c2, PeerClass::CONTACT)]),
            false,
            std::time::Instant::now(),
        );
        let mut conns = 0;
        let mut connect = |host: &mut Host, ip: &str| {
            conns += 1;
            let id = ConnectionId::new_unchecked(conns);
            let endpoint = ConnectedPoint::Dialer {
                address: format!("/ip4/{ip}/tcp/7423").parse().unwrap(),
                role_override: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            };
            assert!(nat_feed(&endpoint, &listen_families(&host.listen_addrs)));
            host.conn_meta
                .insert(id, (endpoint, std::time::Instant::now()));
            id
        };
        let seen =
            |port: u16| -> Multiaddr { format!("/ip4/203.0.113.9/tcp/{port}").parse().unwrap() };
        let a = connect(&mut host, "8.8.8.8");
        assert_eq!(host.nat_observed(a, &c1, &seen(7423)), None, "one network");
        let b = connect(&mut host, "9.9.9.9");
        // A stranger's view is ignored, even on a qualifying connection.
        assert_eq!(host.nat_observed(b, &stranger, &seen(7423)), None);
        let line = host
            .nat_observed(b, &c2, &seen(7423))
            .expect("the class changed");
        assert_eq!(
            line,
            "raven-node p2p: NAT mapping stable_kept (tcp), unknown (quic) from 2 networks"
        );
        for leak in ["203.0", "8.8.8.8", "7423", "12D3"] {
            assert!(!line.contains(leak), "{leak}: {line}");
        }
        let forced = raven_core::portmap_gate::lab_nat_class_force().is_some();
        if !forced {
            let own = host.swarm.behaviour().dcutr.policy.own;
            assert_eq!(own.v4_tcp, Mapping::StableKept);
            let status = host.status_info().nat_mapping.unwrap();
            assert_eq!(
                (status.tcp.as_str(), status.quic.as_str(), status.observers),
                ("stable_kept", "unknown", 2)
            );
            assert_eq!(host.own_p2p().nat.map(|n| n.v4_tcp), Some(2));
        }
        // Nothing new: no line.
        assert_eq!(host.refresh_nat(), None);
        // A third network sees another port: the mapping varies.
        host.gate.replace(
            HashMap::from([
                (c1, PeerClass::CONTACT),
                (c2, PeerClass::CONTACT),
                (stranger, PeerClass::CONTACT),
            ]),
            false,
            std::time::Instant::now(),
        );
        let c = connect(&mut host, "1.1.1.1");
        let line = host.nat_observed(c, &stranger, &seen(40001)).unwrap();
        assert!(
            line.contains("varies (tcp)") && line.ends_with("from 3 networks"),
            "{line}"
        );
        assert!(!line.contains("40001"), "{line}");
        if !forced {
            assert_eq!(
                host.swarm.behaviour().dcutr.policy.own.v4_tcp,
                Mapping::Varies
            );
        }
    }

    #[tokio::test]
    async fn own_routes_export_changes_only_on_content_change() {
        let dir = tempfile::tempdir().unwrap();
        let relays = vec![
            p2p_route::parse_via(&gate_via(5, "192.0.2.1")).unwrap(),
            p2p_route::parse_via(&gate_via(6, "192.0.2.2")).unwrap(),
        ];
        let gate = HostGate::open(true).unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(relays.clone()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        let mut held = None;
        let first = host.own_p2p();
        assert_eq!(first.peer_id, host.peer_id.to_string());
        assert!(first.relays.is_empty(), "no reservation yet");
        assert!(replace_own(&mut held, Some(first)));
        assert!(!replace_own(&mut held, Some(host.own_p2p())), "nothing new");

        let v4: Multiaddr = "/ip4/198.51.100.7/tcp/7423".parse().unwrap();
        let v6: Multiaddr = "/ip6/2001:db8::7/udp/7423/quic-v1".parse().unwrap();
        let circuit: Multiaddr = format!("{}/p2p-circuit", gate_via(5, "192.0.2.1"))
            .parse()
            .unwrap();
        host.swarm
            .add_external_address(v6.clone().with(Protocol::P2p(host.peer_id)));
        host.swarm.add_external_address(circuit);
        host.swarm.add_external_address(v4.clone());
        host.listen_addrs = vec![
            "/ip4/192.168.7.5/tcp/7423".parse().unwrap(),
            "/ip4/10.0.0.5/tcp/7423".parse().unwrap(),
        ];
        let own = host.own_p2p();
        assert_eq!(own.confirmed, vec![v4.to_string(), v6.to_string()]);
        assert_eq!(
            own.listen,
            vec!["/ip4/10.0.0.5/tcp/7423", "/ip4/192.168.7.5/tcp/7423"]
        );
        assert!(replace_own(&mut held, Some(own)));
        host.swarm.remove_external_address(&v4);
        host.swarm.add_external_address(v4.clone());
        host.listen_addrs.reverse();
        assert!(
            !replace_own(&mut held, Some(host.own_p2p())),
            "the same addresses in another order"
        );

        // A reservation accepted on the second slot, then lost.
        host.slots[1].active = true;
        let own = host.own_p2p();
        assert_eq!(own.relays, vec![relays[1].text.clone()]);
        assert!(replace_own(&mut held, Some(own)));
        host.slots[1].active = false;
        assert!(replace_own(&mut held, Some(host.own_p2p())));
        // The host stopped.
        assert!(replace_own(&mut held, None));
        assert!(!replace_own(&mut held, None));
    }

    /// A relay's main address and its TCP 443 fallback (`raven relay card`).
    fn relay_pair(n: u8) -> (String, String) {
        let relay = peer(n);
        (
            format!("/ip4/192.0.2.7/tcp/7423/p2p/{relay}"),
            format!("/ip4/192.0.2.7/tcp/443/p2p/{relay}"),
        )
    }

    fn vias(texts: &[&String]) -> Vec<ViaAddr> {
        texts
            .iter()
            .map(|t| p2p_route::parse_via(t).unwrap())
            .collect()
    }

    /// `seed.build(gen, rehomed)` with the first reservations asked at once,
    /// as a build does while the NAT_CLASS gate is closed. Run with the
    /// caller's `RAVEN_LAB_TEST_A=1 RAVEN_LAB_NAT_CLASS=1`, a first
    /// generation waits [`NAT_LISTEN_WAIT`] for them (P4.24), and a test
    /// that never ticks the host would never see them (P4.30's run with
    /// every Phase 4 switch).
    fn build_reserving(
        seed: &HostSeed,
        gen: u64,
        rehomed: bool,
    ) -> (Host, IncomingStreams, Arc<HostHandle>) {
        let (mut host, incoming, handle) = seed.build(gen, rehomed).unwrap();
        if raven_core::nat_class_live_enabled() && gen == 0 && !host.listens.is_empty() {
            for i in 0..host.slots.len() {
                host.start_reservation(i);
            }
        }
        (host, incoming, handle)
    }

    /// Phase 2 (P2.11): one slot per relay, not per address. Two addresses
    /// of one relay are one slot holding both in card order (the second is
    /// the fallback); two relays are two slots; this node itself is skipped.
    #[test]
    fn relay_slots_group_two_addresses_of_one_relay() {
        let (a, b) = (peer(21), peer(22));
        let me = peer_id(23);
        let slots = |relays: &[ViaAddr]| relay_slots(p2p_route::group_relays(relays), me).unwrap();
        let a443 = format!("/ip4/198.51.100.7/tcp/443/p2p/{a}");
        let a7423 = format!("/dns/relay.example.org/tcp/7423/p2p/{a}");
        let b_quic = format!("/ip4/203.0.113.9/udp/7423/quic-v1/p2p/{b}");

        // Card order is kept: here the 443 address is asked first.
        let one = slots(&vias(&[&a443, &a7423]));
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].peer, peer_id(21));
        assert_eq!(one[0].texts, vec![a443.clone(), a7423.clone()]);
        let named: Vec<Multiaddr> = [&a443, &a7423].iter().map(|t| t.parse().unwrap()).collect();
        assert_eq!(one[0].named, named);
        assert!(one[0].named_by_dns() && one[0].resolved.is_empty());
        assert_eq!(one[0].in_use(), a443, "nothing resolved yet: as named");
        // A duplicate is one address.
        assert_eq!(slots(&vias(&[&a443, &a443]))[0].texts, vec![a443.clone()]);

        // Two relays: two slots, in order.
        let two = slots(&vias(&[&b_quic, &a443]));
        let peers: Vec<PeerId> = two.iter().map(|s| s.peer).collect();
        assert_eq!(peers, vec![peer_id(22), peer_id(21)]);
        assert_eq!(two[0].texts, vec![b_quic.clone()]);
        assert!(!two[0].named_by_dns());

        // This node named as a relay: skipped.
        let mine = format!("/ip4/192.0.2.1/tcp/7423/p2p/{me}");
        let kept = slots(&vias(&[&mine, &b_quic]));
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].peer, peer_id(22));
        assert!(slots(&[]).is_empty());
    }

    /// Phase 2 (P2.11): a refused (or lost) reservation is asked again,
    /// after the pause, on the relay's next address (its TCP 443 fallback),
    /// and after that on the first again.
    #[tokio::test]
    async fn a_refused_reservation_moves_to_the_fallback_address() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (main, fallback) = relay_pair(24);
        let config = loopback_config(vias(&[&main, &fallback]));
        let (seed, _commands) = test_seed(&gate, dir.path(), config);
        let (mut host, _incoming, _handle) = build_reserving(&seed, 0, false);
        assert_eq!(host.slots.len(), 1);
        let refused = |host: &mut Host| {
            let listener_id = host.slots[0].listener.expect("a reservation request");
            host.on_event(SwarmEvent::ListenerClosed {
                listener_id,
                addresses: Vec::new(),
                reason: Err(std::io::Error::other("reservation refused")),
            });
        };
        // The first endpoint asks on the first address at once.
        assert_eq!(host.slots[0].in_use(), main);
        refused(&mut host);
        let slot = &host.slots[0];
        assert!(slot.listener.is_none() && !slot.active);
        assert_eq!(slot.attempt, 1);
        assert!(slot.retry_at.is_some(), "a pause first");
        assert_eq!(slot.in_use(), fallback, "the fallback is next");
        // The pause is over (the tick): asked on the fallback.
        host.start_reservation(0);
        assert!(host.slots[0].listener.is_some());
        assert_eq!(host.slots[0].in_use(), fallback);
        // Refused there too: the first address again. With the WSS gate
        // live (RWS1 §2.3 (b)), the TCP 443 fallback's WSS sibling first.
        refused(&mut host);
        let mut refusals = 2;
        if raven_core::wss_live_enabled() {
            host.start_reservation(0);
            let sibling = fallback.replace("/tcp/443/", "/tcp/443/tls/ws/");
            assert_eq!(host.slots[0].in_use(), sibling);
            refused(&mut host);
            refusals += 1;
        }
        host.start_reservation(0);
        assert!(host.slots[0].listener.is_some());
        assert_eq!(host.slots[0].in_use(), main);
        assert_eq!(host.slots[0].attempt, refusals);
    }

    /// Phase 2 (P2.11): a resolution's answer finds its slot by the relay's
    /// PeerId, not by an index: it reaches the right slot, and a slot
    /// removed in place meanwhile neither takes nor shifts any answer.
    #[tokio::test]
    async fn resolved_answers_are_keyed_by_relay_not_index() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (a, b, c) = (peer(25), peer(26), peer(27));
        let named = |p: &str| format!("/dns4/localhost/tcp/7423/p2p/{p}");
        let (na, nb) = (named(&a), named(&b));
        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(vias(&[&na, &nb])));
        let (mut host, _incoming, _handle) = build_reserving(&seed, 0, false);
        assert!(host.slots.iter().all(|s| s.resolving));
        let at = |p: &str, port: u16| -> Multiaddr {
            format!("/ip4/127.0.0.1/tcp/{port}/p2p/{p}")
                .parse()
                .unwrap()
        };
        let answer = |relay: &str, addrs: Vec<Multiaddr>| Command::Resolved {
            gen: 0,
            relay: relay.parse().unwrap(),
            addrs,
        };
        // B's answer: B's slot, the second one.
        assert!(host.on_command(answer(&b, vec![at(&b, 7423)])).is_none());
        assert!(host.slots[0].resolving && host.slots[0].resolved.is_empty());
        let slot_b = &host.slots[1];
        assert!(!slot_b.resolving && slot_b.listener.is_some());
        assert_eq!(slot_b.resolved, vec![at(&b, 7423)]);

        // A's slot removed in place: B's slot is now the first, and A's
        // late answer (or a stranger's) goes nowhere.
        host.slots.remove(0);
        assert!(host.on_command(answer(&a, vec![at(&a, 9)])).is_none());
        assert!(host.on_command(answer(&c, vec![at(&c, 9)])).is_none());
        assert_eq!(host.slots.len(), 1);
        assert_eq!(host.slots[0].resolved, vec![at(&b, 7423)]);
        // B's next answer still finds it.
        assert!(host.on_command(answer(&b, vec![at(&b, 443)])).is_none());
        assert_eq!(host.slots[0].resolved, vec![at(&b, 443)]);
    }

    /// Phase 2 (P2.11): `reservations n/m` counts relays: one relay named
    /// by two addresses is one, with or without a running host; its row
    /// and its reservation show the address in use.
    #[tokio::test]
    async fn status_counts_relays_not_addresses() {
        let (main, fallback) = relay_pair(28);
        let (other, _) = relay_pair(29);
        let config = loopback_config(vias(&[&main, &fallback]));
        // No host runs: the start-up decision.
        let held = service_info(ServiceP2p::Held {
            config: &config,
            source: "--p2p-listen",
        });
        assert_eq!(held.relays_configured, 1);
        assert_eq!(held.relays, vec![main.clone(), fallback.clone()]);
        let two = loopback_config(vias(&[&main, &other]));
        let configured = service_info(ServiceP2p::Configured {
            config: &two,
            source: "node_policy.json",
        });
        assert_eq!(configured.relays_configured, 2);

        // The running host.
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), config);
        let (mut host, _incoming, _handle) = build_reserving(&seed, 0, false);
        let status = host.status_info();
        assert_eq!(status.relays_configured, 1);
        assert_eq!(status.relays, vec![main.clone(), fallback.clone()]);
        assert_eq!(status.relay_health.len(), 1, "one row per relay");
        assert_eq!(status.relay_health[0].relay, main);
        assert!(status.reservations.is_empty());
        // Held on the fallback: one reservation, at the address in use.
        host.slots[0].next = 1;
        host.slots[0].active = true;
        let status = host.status_info();
        assert_eq!(status.reservations, vec![fallback.clone()]);
        assert_eq!(status.relay_health[0].relay, fallback);
        assert_eq!(status.relay_health[0].state, "reserved");
        assert_eq!(status.relays_configured, 1);
    }

    /// Phase 4 (P4.16): status names where the proxy setting came from, with
    /// or without a running host, and the proxy's last 407 as a fixed word
    /// (`raven status` hints at Windows sign-in for NTLM or Negotiate); any
    /// other dial failure leaves it as it was.
    #[tokio::test]
    async fn status_names_the_proxy_source_and_the_proxys_407() {
        use raven_swarm::wss::ProxyError;
        let auth = |schemes: Vec<&'static str>, sent_basic: bool| {
            DialError::Transport(vec![(
                "/dns4/relay.invalid/tcp/443/tls/ws".parse().unwrap(),
                TransportError::Other(std::io::Error::other(ProxyError::Auth {
                    schemes,
                    sent_basic,
                })),
            )])
        };
        for (error, want) in [
            (auth(vec!["Negotiate", "NTLM"], false), Some("unsupported")),
            (auth(vec!["Digest", "NTLM"], false), Some("unsupported")),
            // Review B-6: not Windows sign-in.
            (auth(vec![], false), Some("other")),
            (auth(vec!["Digest"], false), Some("other")),
            (auth(vec!["Bearer", "other"], false), Some("other")),
            (auth(vec!["NTLM", "Basic"], false), Some("basic")),
            (auth(vec!["Basic"], true), Some("refused")),
        ] {
            assert_eq!(proxy_auth_word(&error), want, "{error:?}");
        }
        let other = DialError::Transport(vec![(
            "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
            TransportError::Other(std::io::Error::other(ProxyError::Refused(403))),
        )]);
        for error in [other, DialError::Aborted, DialError::NoAddresses] {
            assert_eq!(proxy_auth_word(&error), None, "{error:?}");
        }

        let (main, _) = relay_pair(27);
        let mut config = loopback_config(vias(&[&main]));
        config.proxy = P2pProxy {
            setting: ProxySetting::Off,
            source: "--p2p-proxy",
            pending: false,
        };
        let held = service_info(ServiceP2p::Held {
            config: &config,
            source: "node_policy.json",
        });
        assert_eq!(held.proxy_source, "--p2p-proxy");
        assert!(held.proxy_auth.is_empty());
        let off = service_info(ServiceP2p::Off {
            source: "node_policy.json",
        });
        assert!(off.proxy_source.is_empty());

        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), config);
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        let status = host.status_info();
        assert_eq!(status.proxy_source, "--p2p-proxy");
        assert!(status.proxy_auth.is_empty());
        let failed = |error| SwarmEvent::OutgoingConnectionError {
            connection_id: ConnectionId::new_unchecked(11),
            peer_id: None,
            error,
        };
        host.on_event(failed(auth(vec!["Negotiate"], false)));
        assert_eq!(host.status_info().proxy_auth, "unsupported");
        host.on_event(failed(DialError::Aborted));
        assert_eq!(host.status_info().proxy_auth, "unsupported", "kept");
        host.on_event(failed(auth(vec!["Basic"], true)));
        assert_eq!(host.status_info().proxy_auth, "refused");
    }

    /// Phase 2 (P2.11): each relay slot's relay is one AutoNAT server: a
    /// relay named by two addresses never gets two clients.
    #[test]
    fn autonat_servers_are_distinct_relays() {
        let me = peer_id(30);
        let (a_main, a_fallback) = relay_pair(31);
        let (b_main, _) = relay_pair(32);
        let slots =
            |relays: &[&String]| relay_slots(p2p_route::group_relays(&vias(relays)), me).unwrap();
        let (a, b) = (peer_id(31), peer_id(32));
        assert_eq!(
            autonat_servers(&slots(&[&a_main, &a_fallback])),
            [Some(a), None]
        );
        assert_eq!(
            autonat_servers(&slots(&[&a_fallback, &b_main])),
            [Some(a), Some(b)]
        );
        assert_eq!(autonat_servers(&slots(&[])), [None, None]);
        // Two slots of one relay (none is built so): still one server.
        let mut twice = slots(&[&a_main]);
        twice.extend(slots(&[&a_fallback]));
        assert_eq!(autonat_servers(&twice), [Some(a), None]);
    }

    /// Phase 2 (P2.11): route hints name every address of a relay holding
    /// our reservation, its fallback too, at most two per relay.
    #[tokio::test]
    async fn own_routes_export_names_both_addresses_of_one_relay() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (main, fallback) = relay_pair(33);
        let config = loopback_config(vias(&[&main, &fallback]));
        let (seed, _commands) = test_seed(&gate, dir.path(), config);
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        assert!(host.own_p2p().relays.is_empty(), "no reservation yet");
        // Held on the fallback: both addresses, in card order.
        host.slots[0].next = 1;
        host.slots[0].active = true;
        assert_eq!(host.own_p2p().relays, vec![main.clone(), fallback.clone()]);
        // Never more than two of one relay.
        host.slots[0]
            .texts
            .push(format!("/ip4/192.0.2.8/tcp/7423/p2p/{}", peer(33)));
        assert_eq!(host.own_p2p().relays, vec![main, fallback]);
    }

    /// A dial turned away at once says what to do: the contact's node
    /// (closed our connection at once) or its relay (closed our connection
    /// at once: we are not on its allow-list). Only refusals since the dial
    /// began count.
    #[test]
    fn refusal_hints_name_who_turned_the_dial_away() {
        let target = refusal_hint(true, false).unwrap();
        assert!(
            target.contains("refused the p2p connection at once")
                && target.contains("once the two of you are connected over Tor"),
            "{target}"
        );
        assert_eq!(refusal_hint(true, true), Some(target), "the contact first");
        let relay = refusal_hint(false, true).unwrap();
        assert!(
            relay.contains("`raven whoami --peer-id` prints it"),
            "{relay}"
        );
        assert!(
            relay.contains("tries that relay again within 10 minutes"),
            "{relay}"
        );
        assert_eq!(refusal_hint(false, false), None);
        for hint in [target, relay] {
            assert!(!hint.contains("12D3KooW"));
            // No hint changes how the outbox files the error.
            assert_eq!(
                crate::outbox::dial_error_code(&format!("{P2P_UNREACHABLE}; {hint}")),
                crate::outbox::dial_error_code(P2P_UNREACHABLE)
            );
        }

        let (bob, relay_peer, other) = (peer_id(20), peer_id(21), peer_id(22));
        let before = Instant::now();
        note_closed_at_once(bob);
        assert!(closed_at_once_since(&bob, before));
        assert!(!closed_at_once_since(&relay_peer, before));
        let later = Instant::now() + Duration::from_secs(5);
        assert!(!closed_at_once_since(&bob, later), "an older refusal");
        let err = with_refusal_hint(P2P_UNREACHABLE.into(), &bob, &[relay_peer], before);
        assert!(
            err.starts_with("P2P_UNREACHABLE") && err.ends_with(target),
            "{err}"
        );
        note_closed_at_once(relay_peer);
        let err = with_refusal_hint("x".into(), &other, &[relay_peer], before);
        assert_eq!(err, format!("x; {relay}"));
        assert_eq!(with_refusal_hint("x".into(), &other, &[], before), "x");
    }

    /// Phase 0b: a re-home answers every waiting dial and closes the
    /// listeners; the next generation starts reachability over (no AutoNAT
    /// verdict, UPnP back to its policy state, no reservation) and retries a
    /// busy listen port quietly at first.
    #[tokio::test]
    async fn a_rehome_answers_waiting_dials_and_starts_reachability_over() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        assert_eq!(host.listens.len(), 2, "TCP and QUIC");
        for slot in &host.listens {
            assert!(slot.open && slot.listener.is_some() && slot.grace_until.is_none());
        }
        let bob: PeerId = peer(12).parse().unwrap();
        let (reply, connect) = oneshot::channel();
        host.pending.entry(bob).or_default().push(reply);
        let (reply, prefer) = oneshot::channel();
        host.preferring.push((bob, Instant::now(), reply));
        let tested: Multiaddr = "/ip4/8.8.8.8/tcp/7423".parse().unwrap();
        for (seed, relay) in [(13, "11.1.0.1"), (14, "11.2.0.1")] {
            let server = peer(seed).parse().unwrap();
            let group = net_group(relay.parse().unwrap());
            host.nat.record(tested.clone(), server, group, true);
        }
        host.upnp = "mapped 7423".into();
        let status = host.status_info();
        assert_eq!(
            (status.nat.as_str(), status.reach.as_str()),
            ("public", "public")
        );
        assert_eq!(status.nat_checks.reached, 2);

        let started = Instant::now();
        host.close_everything(REHOME_DRAIN, false).await;
        assert!(
            started.elapsed() < REHOME_DRAIN,
            "both listeners reported closed before the deadline"
        );
        let err = connect.await.unwrap().unwrap_err();
        assert!(err.starts_with("P2P_UNREACHABLE"), "{err}");
        assert!(err.contains("network changed"), "{err}");
        assert!(!prefer.await.unwrap());
        assert!(host.listens.iter().all(|l| l.listener.is_none()));
        drop(host);

        let (fresh, _incoming, _handle) = seed.build(1, true).unwrap();
        assert_eq!(fresh.gen, 1);
        let status = fresh.status_info();
        assert!(status.up);
        assert!(status.retired_listen.is_empty());
        assert_eq!(status.nat, "unknown");
        assert_eq!(status.nat_checks, NatChecks::default());
        assert_eq!(
            status.reach, "unknown",
            "listening, nothing checked, no relay"
        );
        assert_eq!(status.upnp, upnp_initial(None));
        assert!(status.reservations.is_empty());
        assert_eq!(fresh.listens.len(), 2);
        assert!(fresh.listens.iter().all(|l| l.grace_until.is_some()));
    }

    /// Phase 0b: a relay name resolved for an older endpoint generation does
    /// not request a reservation on the current one (it asked again itself);
    /// its own answer does.
    #[tokio::test]
    async fn a_resolution_from_an_older_generation_is_ignored() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let relay = peer(11);
        let via = p2p_route::parse_via(&format!("/dns4/localhost/tcp/7423/p2p/{relay}")).unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(vec![via]));
        let (mut host, _incoming, _handle) = seed.build(1, true).unwrap();
        assert!(host.slots[0].resolving && host.slots[0].listener.is_none());
        let resolved: Multiaddr = format!("/ip4/127.0.0.1/tcp/7423/p2p/{relay}")
            .parse()
            .unwrap();
        let stale = Command::Resolved {
            gen: 0,
            relay: relay.parse().unwrap(),
            addrs: vec![resolved.clone()],
        };
        assert!(host.on_command(stale).is_none());
        let slot = &host.slots[0];
        assert!(slot.resolving, "still waiting for its own answer");
        assert!(slot.listener.is_none() && slot.resolved.is_empty());
        let own = Command::Resolved {
            gen: 1,
            relay: relay.parse().unwrap(),
            addrs: vec![resolved.clone()],
        };
        assert!(host.on_command(own).is_none());
        let slot = &host.slots[0];
        // A re-homed endpoint first dials the relay from a new local port.
        assert!(!slot.resolving && slot.connecting.is_some() && slot.listener.is_none());
        assert_eq!(slot.resolved, vec![resolved]);
    }

    /// Phase 0b: a re-homed endpoint reaches its relay from a new local port
    /// (the old endpoint's connection may still hold the listen port's TCP
    /// 4-tuple) and then reserves on that connection; the first endpoint
    /// asks the relay client directly, which reuses the listen port.
    #[tokio::test]
    async fn a_rehomed_endpoint_reserves_on_a_relay_connection_from_a_new_port() {
        use raven_swarm::libp2p::core::transport::PortUse;
        use raven_swarm::libp2p::core::ConnectedPoint;

        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        // The relay: a relay role on loopback, with its own key, whose
        // allow-list names the host (its peer gate admits members only: an
        // open role would admit verified contacts, never a stranger).
        let relay_dir = dir.path().join("relay");
        std::fs::create_dir_all(&relay_dir).unwrap();
        let host_peer =
            raven_swarm::kad_node::libp2p_keypair_from_raven(&Identity::from_seed(&[13; 32]))
                .public()
                .to_peer_id();
        raven_core::relay_allow::relay_allow(&relay_dir, &host_peer.to_string(), "host").unwrap();
        let (relay_seed, _relay_commands) = test_seed(
            &gate,
            &relay_dir,
            P2pConfig {
                relay_server: Some(false),
                ..loopback_config(Vec::new())
            },
        );
        let relay_seed = HostSeed {
            keypair: raven_swarm::kad_node::libp2p_keypair_from_raven(&Identity::from_seed(
                &[21; 32],
            )),
            ..relay_seed
        };
        let (mut relay, _incoming, _handle) = relay_seed.build(0, false).unwrap();
        let tcp = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let event = relay.swarm.select_next_some().await;
                relay.on_event(event);
                let tcp = relay
                    .listen_addrs
                    .iter()
                    .find(|a| a.iter().any(|p| matches!(p, Protocol::Tcp(_))));
                if let Some(tcp) = tcp {
                    break tcp.clone();
                }
            }
        })
        .await
        .expect("the relay listens on TCP");
        let via =
            p2p_route::parse_via(&format!("{tcp}/p2p/{}", relay.swarm.local_peer_id())).unwrap();
        let config = loopback_config(vec![via]);

        let (first_seed, _commands) = test_seed(&gate, dir.path(), config.clone());
        let (first, _incoming, _handle) = build_reserving(&first_seed, 0, false);
        assert!(first.slots[0].listener.is_some() && first.slots[0].connecting.is_none());
        drop(first);

        let (seed, _commands) = test_seed(&gate, dir.path(), config);
        let (mut host, _incoming, _handle) = seed.build(1, true).unwrap();
        assert!(host.slots[0].connecting.is_some() && host.slots[0].listener.is_none());
        let relay_peer = host.slots[0].peer;
        let mut port_use = None;
        tokio::time::timeout(Duration::from_secs(20), async {
            while !host.slots[0].active {
                tokio::select! {
                    event = relay.swarm.select_next_some() => relay.on_event(event),
                    event = host.swarm.select_next_some() => {
                        if let SwarmEvent::ConnectionEstablished {
                            peer_id,
                            endpoint: ConnectedPoint::Dialer { port_use: used, .. },
                            ..
                        } = &event
                        {
                            if *peer_id == relay_peer {
                                port_use.get_or_insert(*used);
                            }
                        }
                        host.on_event(event);
                    }
                }
            }
        })
        .await
        .expect("a reservation on the relay");
        assert_eq!(port_use, Some(PortUse::New));
        let slot = &host.slots[0];
        assert!(slot.listener.is_some() && slot.connecting.is_none());
        assert_eq!(host.status_info().reservations.len(), 1);
    }

    /// A UDP forwarder on loopback in front of `target` that drops every
    /// datagram both ways once `cut` is set: a path that dies silently.
    async fn cuttable_udp_path(
        target: std::net::SocketAddr,
        cut: Arc<std::sync::atomic::AtomicBool>,
    ) -> u16 {
        let front = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        back.connect(target).await.unwrap();
        let port = front.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut client = None;
            let (mut up, mut down) = (vec![0u8; 65536], vec![0u8; 65536]);
            loop {
                tokio::select! {
                    got = front.recv_from(&mut up) => {
                        let Ok((n, from)) = got else { return };
                        client = Some(from);
                        if !cut.load(Ordering::SeqCst) {
                            let _ = back.send(&up[..n]).await;
                        }
                    }
                    got = back.recv(&mut down) => {
                        let Ok(n) = got else { return };
                        if let (Some(to), false) = (client, cut.load(Ordering::SeqCst)) {
                            let _ = front.send_to(&down[..n], to).await;
                        }
                    }
                }
            }
        });
        port
    }

    /// Phase 0b with production timings (ping every 15 s, 5 s timeout): the
    /// only relay, reached over QUIC, goes silent right after a good ping.
    /// QUIC's idle timeout (10 s) closes the connection before any ping can
    /// fail, and that close reports the relay loss as a failed ping would.
    #[tokio::test]
    async fn a_silent_quic_relay_path_is_reported_before_any_ping_fails() {
        use raven_swarm::libp2p::ping;
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let relay_dir = dir.path().join("relay");
        std::fs::create_dir_all(&relay_dir).unwrap();
        let host_peer =
            raven_swarm::kad_node::libp2p_keypair_from_raven(&Identity::from_seed(&[13; 32]))
                .public()
                .to_peer_id();
        raven_core::relay_allow::relay_allow(&relay_dir, &host_peer.to_string(), "host").unwrap();
        let (relay_seed, _relay_commands) = test_seed(
            &gate,
            &relay_dir,
            P2pConfig {
                relay_server: Some(false),
                ..loopback_config(Vec::new())
            },
        );
        let relay_seed = HostSeed {
            keypair: raven_swarm::kad_node::libp2p_keypair_from_raven(&Identity::from_seed(
                &[22; 32],
            )),
            ..relay_seed
        };
        let (mut relay, _incoming, _handle) = relay_seed.build(0, false).unwrap();
        let quic = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let event = relay.swarm.select_next_some().await;
                relay.on_event(event);
                let quic = relay.listen_addrs.iter().find_map(|a| {
                    let mut it = a.iter();
                    match (it.next(), it.next(), it.next()) {
                        (
                            Some(Protocol::Ip4(ip)),
                            Some(Protocol::Udp(port)),
                            Some(Protocol::QuicV1),
                        ) => Some(std::net::SocketAddr::from((ip, port))),
                        _ => None,
                    }
                });
                if let Some(quic) = quic {
                    break quic;
                }
            }
        })
        .await
        .expect("the relay listens on QUIC");
        let cut = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let port = cuttable_udp_path(quic, Arc::clone(&cut)).await;
        let relay_peer = *relay.swarm.local_peer_id();
        let via = p2p_route::parse_via(&format!(
            "/ip4/127.0.0.1/udp/{port}/quic-v1/p2p/{relay_peer}"
        ))
        .unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(vec![via]));
        let (mut host, _incoming, _handle) = build_reserving(&seed, 0, false);
        let mut pings_failed = 0;
        let mut closed = false;
        tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                tokio::select! {
                    event = relay.swarm.select_next_some() => relay.on_event(event),
                    event = host.swarm.select_next_some() => {
                        match &event {
                            SwarmEvent::Behaviour(EndpointBehaviourEvent::Ping(ping::Event {
                                result: Err(_),
                                ..
                            })) => pings_failed += 1,
                            SwarmEvent::ConnectionClosed { peer_id, .. }
                                if *peer_id == relay_peer && cut.load(Ordering::SeqCst) =>
                            {
                                closed = true;
                            }
                            _ => {}
                        }
                        host.on_event(event);
                        // Cut the path as soon as the reservation is held.
                        if host.slots[0].active && !cut.load(Ordering::SeqCst) {
                            cut.store(true, Ordering::SeqCst);
                        }
                        if closed {
                            return;
                        }
                    }
                }
            }
        })
        .await
        .expect("the silent QUIC connection closes");
        assert_eq!(pings_failed, 0, "the idle timeout came first");
        assert!(
            host.relay_loss.last_report.is_some(),
            "every relay went silent: reported"
        );
    }

    fn test_key(seed: u8) -> Keypair {
        raven_swarm::kad_node::libp2p_keypair_from_raven(&Identity::from_seed(&[seed; 32]))
    }

    fn is_tcp(addr: &Multiaddr) -> bool {
        addr.iter().any(|p| matches!(p, Protocol::Tcp(_)))
    }

    /// A contact's endpoint on loopback (key `seed`) that admits the test
    /// host (key 13) as a contact, and its TCP listen address.
    async fn test_contact(gate: &HostGate, dir: &Path, seed: u8) -> (Host, Multiaddr) {
        let dir = dir.join(format!("contact{seed}"));
        std::fs::create_dir_all(&dir).unwrap();
        let (contact_seed, _commands) = test_seed(gate, &dir, loopback_config(Vec::new()));
        let contact_seed = HostSeed {
            keypair: test_key(seed),
            ..contact_seed
        };
        let (mut contact, _incoming, _handle) = contact_seed.build(0, false).unwrap();
        contact
            .gate
            .admit_dial(
                test_key(13).public().to_peer_id(),
                PeerClass::CONTACT,
                &[],
                std::time::Instant::now(),
                std::time::Instant::now() + Duration::from_secs(600),
            )
            .unwrap();
        let tcp = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let event = contact.swarm.select_next_some().await;
                contact.on_event(event);
                if let Some(tcp) = contact.listen_addrs.iter().find(|a| is_tcp(a)) {
                    break tcp.clone();
                }
            }
        })
        .await
        .expect("the contact listens on TCP");
        (contact, tcp)
    }

    /// A1: the only relay goes silent while a contact's direct connection
    /// keeps answering pings (every 2 s here). Our own path still works:
    /// that is one relay lost, no path loss (whose re-home would close the
    /// contact's connection for nothing), also once the ping round the
    /// contact had to answer in is over.
    #[tokio::test]
    async fn a_silent_relay_is_no_path_loss_while_a_contact_answers() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let relay_dir = dir.path().join("relay");
        std::fs::create_dir_all(&relay_dir).unwrap();
        let host_peer = test_key(13).public().to_peer_id();
        raven_core::relay_allow::relay_allow(&relay_dir, &host_peer.to_string(), "host").unwrap();
        let (relay_seed, _relay_commands) = test_seed(
            &gate,
            &relay_dir,
            P2pConfig {
                relay_server: Some(false),
                ..loopback_config(Vec::new())
            },
        );
        let relay_seed = HostSeed {
            keypair: test_key(23),
            ..relay_seed
        };
        let (mut relay, _incoming, _handle) = relay_seed.build(0, false).unwrap();
        let quic = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let event = relay.swarm.select_next_some().await;
                relay.on_event(event);
                let quic = relay.listen_addrs.iter().find_map(|a| {
                    let mut it = a.iter();
                    match (it.next(), it.next(), it.next()) {
                        (
                            Some(Protocol::Ip4(ip)),
                            Some(Protocol::Udp(port)),
                            Some(Protocol::QuicV1),
                        ) => Some(std::net::SocketAddr::from((ip, port))),
                        _ => None,
                    }
                });
                if let Some(quic) = quic {
                    break quic;
                }
            }
        })
        .await
        .expect("the relay listens on QUIC");
        let (mut contact, contact_tcp) = test_contact(&gate, dir.path(), 24).await;
        let contact_peer = *contact.swarm.local_peer_id();
        let cut = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let port = cuttable_udp_path(quic, Arc::clone(&cut)).await;
        let relay_peer = *relay.swarm.local_peer_id();
        let via = p2p_route::parse_via(&format!(
            "/ip4/127.0.0.1/udp/{port}/quic-v1/p2p/{relay_peer}"
        ))
        .unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(vec![via]));
        let seed = HostSeed {
            ping: Some((Duration::from_secs(2), Duration::from_secs(1))),
            ..seed
        };
        let (mut host, _incoming, _handle) = build_reserving(&seed, 0, false);
        assert_eq!(host.ping_round, Duration::from_secs(3));
        let mut ticks = tokio::time::interval(Duration::from_millis(250));
        let (mut asked, mut reply) = (false, None);
        let mut closed_at: Option<Instant> = None;
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    event = relay.swarm.select_next_some() => relay.on_event(event),
                    event = contact.swarm.select_next_some() => contact.on_event(event),
                    event = host.swarm.select_next_some() => {
                        let relay_closed = matches!(
                            &event,
                            SwarmEvent::ConnectionClosed { peer_id, .. } if *peer_id == relay_peer
                        );
                        host.on_event(event);
                        if relay_closed && cut.load(Ordering::SeqCst) {
                            closed_at.get_or_insert(Instant::now());
                        }
                    }
                    _ = ticks.tick() => {}
                }
                // Reserved: reach the contact directly, then cut the path
                // to the relay.
                if host.slots[0].active && !asked {
                    asked = true;
                    let (tx, rx) = oneshot::channel();
                    host.connect(
                        contact_peer,
                        PeerClass::CONTACT,
                        Vec::new(),
                        vec![contact_tcp.clone()],
                        std::time::Instant::now(),
                        tx,
                    );
                    reply = Some(rx);
                }
                if let Some(rx) = reply.as_mut() {
                    match rx.try_recv() {
                        Ok(result) => {
                            result.expect("the contact is reached directly");
                            reply = None;
                            cut.store(true, Ordering::SeqCst);
                        }
                        Err(oneshot::error::TryRecvError::Empty) => {}
                        Err(e) => panic!("{e}"),
                    }
                }
                // What the host's tick does.
                assert!(!host.relay_loss.due(Instant::now()), "reported");
                if let Some(at) = closed_at {
                    assert!(
                        host.relay_loss.last_report.is_none(),
                        "the contact answers: not our path"
                    );
                    if at.elapsed() >= host.ping_round + Duration::from_secs(2) {
                        return;
                    }
                }
            }
        })
        .await
        .expect("the silent relay connection closes");
        assert!(host.relay_loss.first.is_some(), "the relay was lost");
        assert!(host.relay_loss.answered && host.relay_loss.pending.is_none());
        assert!(host.swarm.is_connected(&contact_peer));
    }

    /// A socket's "address in use" is found under every wrapper, a
    /// transparent one (libp2p's `Either`) included; other failures are not.
    #[test]
    fn addr_in_use_is_found_under_transparent_wrappers() {
        use std::io::{Error, ErrorKind};
        /// As `either::Either`: its `source` is its content's.
        #[derive(Debug)]
        struct Transparent(Error);
        impl std::fmt::Display for Transparent {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
        impl std::error::Error for Transparent {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.0.source()
            }
        }
        // The OS's own codes, from which std derives the kind: errno on Unix
        // (`libc` is a Unix-only dependency), Winsock's on Windows.
        #[cfg(unix)]
        let (in_use, refused, not_here) =
            (libc::EADDRINUSE, libc::ECONNREFUSED, libc::EADDRNOTAVAIL);
        // WSAEADDRINUSE, WSAECONNREFUSED, WSAEADDRNOTAVAIL.
        #[cfg(windows)]
        let (in_use, refused, not_here) = (10048, 10061, 10049);
        let os = || Error::from_raw_os_error(in_use);
        assert_eq!(os().kind(), ErrorKind::AddrInUse);
        assert!(addr_in_use(&os()));
        assert!(addr_in_use(&Error::from(ErrorKind::AddrInUse)));
        assert!(addr_in_use(&Error::other(os())));
        assert!(addr_in_use(&Error::other(Transparent(os()))));
        assert!(addr_in_use(&Error::other(Transparent(Error::other(
            Transparent(os())
        )))));
        for other in [
            Error::from_raw_os_error(refused),
            Error::from(ErrorKind::TimedOut),
            Error::other(Transparent(Error::from_raw_os_error(not_here))),
        ] {
            assert!(!addr_in_use(&other), "{other:?}");
        }
    }

    /// A4: after a re-home on the same address, a contact's TCP address is
    /// dialled from the listen port again, whose 4-tuple the old endpoint's
    /// connection to it still holds (TIME_WAIT: macOS and Windows refuse
    /// it, Linux falls back to a new port by itself). The dial goes again
    /// from a new port at once instead of failing until the TIME_WAIT ends.
    #[tokio::test]
    async fn a_contact_dial_whose_4_tuple_is_still_held_goes_from_a_new_port() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (mut contact, contact_tcp) = test_contact(&gate, dir.path(), 25).await;
        let contact_peer = *contact.swarm.local_peer_id();
        let drive_contact = tokio::spawn(async move {
            loop {
                let event = contact.swarm.select_next_some().await;
                contact.on_event(event);
            }
        });
        // One listen port across the re-home (this computer's address stayed).
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let config = P2pConfig {
            listen: P2pListen::One(format!("127.0.0.1:{port}").parse().unwrap()),
            ..loopback_config(Vec::new())
        };
        let (seed, _commands) = test_seed(&gate, dir.path(), config);
        async fn listen_then_connect(
            host: &mut Host,
            peer: PeerId,
            addr: Multiaddr,
        ) -> Result<(), String> {
            tokio::time::timeout(Duration::from_secs(10), async {
                while !host.listen_addrs.iter().any(is_tcp) {
                    let event = host.swarm.select_next_some().await;
                    host.on_event(event);
                }
                let (tx, mut rx) = oneshot::channel();
                host.connect(
                    peer,
                    PeerClass::CONTACT,
                    Vec::new(),
                    vec![addr],
                    std::time::Instant::now(),
                    tx,
                );
                loop {
                    tokio::select! {
                        event = host.swarm.select_next_some() => host.on_event(event),
                        result = &mut rx => return result.expect("answered"),
                    }
                }
            })
            .await
            .expect("answered within 10 s")
        }
        let (mut first, _incoming, _handle) = seed.build(0, false).unwrap();
        listen_then_connect(&mut first, contact_peer, contact_tcp.clone())
            .await
            .expect("the first dial");
        // Settled (Identify and the first pings done): closed with a FIN,
        // not a reset, so our end of it waits out TIME_WAIT.
        let settle = Instant::now() + Duration::from_secs(1);
        while let Ok(event) = tokio::time::timeout_at(settle, first.swarm.select_next_some()).await
        {
            first.on_event(event);
        }
        // The re-home closes the connection from our end: its 4-tuple stays
        // held for a while.
        first.close_everything(REHOME_DRAIN, false).await;
        drop(first);
        let (mut host, _incoming, _handle) = seed.build(1, true).unwrap();
        let started = Instant::now();
        listen_then_connect(&mut host, contact_peer, contact_tcp)
            .await
            .expect("the dial after the re-home");
        assert!(started.elapsed() < Duration::from_secs(5));
        drive_contact.abort();
    }

    /// Besides failed pings, a relay connection that died by silence is its
    /// relay failing, also when its slot reported the reservation's loss a
    /// moment before the close; a close by either side, or a silence long
    /// after the reservation was lost, is not. A TCP relay failing its pings
    /// first and a QUIC relay closing by its idle timeout later: reported.
    #[tokio::test]
    async fn a_relay_connection_closed_by_silence_is_a_lost_relay() {
        use std::io::{Error, ErrorKind};
        let io = |e: Error| ConnectionError::IO(e);
        assert!(closed_by_silence(&io(Error::from(ErrorKind::TimedOut))));
        assert!(closed_by_silence(&io(Error::other(Error::from(
            ErrorKind::TimedOut
        )))));
        assert!(!closed_by_silence(&io(Error::from(
            ErrorKind::ConnectionReset
        ))));
        assert!(!closed_by_silence(&io(Error::other("closed by peer: 0"))));
        assert!(!closed_by_silence(&ConnectionError::KeepAliveTimeout));

        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        let slot = |peer: PeerId, active: bool, since: Option<Instant>| {
            let addr: Multiaddr = format!("/ip4/198.51.100.7/udp/7423/quic-v1/p2p/{peer}")
                .parse()
                .unwrap();
            RelaySlot {
                texts: vec![addr.to_string()],
                named: vec![addr.clone()],
                forms: vec![addr.clone()],
                peer,
                resolved: vec![addr],
                next: 0,
                listener: None,
                connecting: None,
                active,
                resolving: false,
                attempt: 0,
                retry_at: None,
                since,
                ping: None,
                source: Source::Manual,
                selected_at: Instant::now(),
                path: None,
            }
        };
        let (tcp, quic) = (peer_id(15), peer_id(16));
        let s = Duration::from_secs;
        let t0 = Instant::now();
        host.slots = vec![slot(tcp, true, Some(t0)), slot(quic, true, Some(t0))];
        // The TCP relay failed its pings (the Ping arm): a window for both.
        let both: HashSet<PeerId> = [tcp, quic].into_iter().collect();
        assert!(!host.relay_loss.lost(tcp, &both, None, t0 + s(20)));
        // The QUIC one's reservation listener closed a moment before its
        // connection's close (idle timeout) was seen.
        host.slots[1].active = false;
        host.slots[1].since = Some(t0 + s(25));
        host.relay_went_silent(quic, t0 + s(25) + Duration::from_millis(200));
        assert!(host.relay_loss.last_report.is_some(), "both relays lost");

        // A relay whose reservation was lost long before: not reserved now.
        host.relay_loss = RelayLoss::default();
        host.slots = vec![slot(quic, false, Some(t0))];
        host.relay_went_silent(quic, t0 + s(30));
        assert!(host.relay_loss.first.is_none(), "no window");
        // A connection to a relay that never held a reservation: neither.
        host.slots = vec![slot(quic, false, None)];
        host.relay_went_silent(quic, t0);
        assert!(host.relay_loss.first.is_none());
        // The only relay, reserved: lost and reported.
        host.slots = vec![slot(quic, true, Some(t0))];
        host.relay_went_silent(quic, t0 + s(30));
        assert!(host.relay_loss.last_report.is_some());
    }

    /// Path labels from the side that started the link: who opened each
    /// open connection, conservative for a mixed set.
    #[test]
    fn link_path_table() {
        use ConnOrigin::{Accepted, Dialled, Punched, Relayed};
        use DeliveryPath::{Direct, HolePunched, Relayed as ViaRelay, Reversed};
        let cases: [(&[ConnOrigin], bool, Option<DeliveryPath>); 14] = [
            (&[], true, None),
            (&[], false, None),
            (&[Dialled], true, Some(Direct)),
            (&[Dialled], false, Some(Reversed)),
            (&[Accepted], true, Some(Reversed)),
            (&[Accepted], false, Some(Direct)),
            (&[Relayed], true, Some(ViaRelay)),
            (&[Relayed], false, Some(ViaRelay)),
            (&[Punched], true, Some(HolePunched)),
            (&[Punched], false, Some(HolePunched)),
            // Any relayed connection: the stream may land on it.
            (&[Dialled, Relayed], true, Some(ViaRelay)),
            (&[Punched, Relayed], false, Some(ViaRelay)),
            // Mixed direct origins: `direct`, never a guess at the rarer one.
            (&[Accepted, Dialled], true, Some(Direct)),
            (&[Punched, Accepted], false, Some(Direct)),
        ];
        for (origins, we_started, want) in cases {
            assert_eq!(
                link_path(origins, we_started),
                want,
                "{origins:?} {we_started}"
            );
        }
        assert_eq!(link_path(&[Accepted, Accepted], true), Some(Reversed));
        // The log keeps the prefixes the harnesses grep.
        assert_eq!(
            link_line(Some(Reversed)),
            "raven-node p2p: link via a direct connection (reversed)"
        );
        assert_eq!(
            link_line(Some(HolePunched)),
            "raven-node p2p: link via a direct connection (hole_punched)"
        );
        assert_eq!(
            link_line(Some(ViaRelay)),
            "raven-node p2p: link via the relay (relayed)"
        );
        assert_eq!(link_line(None), "raven-node p2p: link via the relay");
    }

    /// Review 5a-3: a relayed connection keeps the relay it goes through
    /// while it is open (a stale link's reason asks about that relay); a
    /// direct or unknown connection notes none, and a close forgets it.
    #[test]
    fn a_relayed_connection_keeps_its_relay_until_it_closes() {
        let (bob, carol, r1, r2) = (peer_id(12), peer_id(14), peer_id(16), peer_id(18));
        let id = ConnectionId::new_unchecked;
        let mut table = ConnTable::default();
        table.established(id(1), bob, true, true);
        table.relayed_through(id(1), r1);
        table.established(id(2), bob, true, false);
        table.relayed_through(id(2), r2);
        table.established(id(3), bob, false, true);
        table.relayed_through(id(3), r2);
        table.established(id(4), carol, true, true);
        table.relayed_through(id(4), r1);
        table.relayed_through(id(9), r2);
        let mut both = vec![r1, r2];
        both.sort_by_key(|r| r.to_bytes());
        assert_eq!(table.relays_to(&bob), both);
        assert_eq!(table.relays_to(&carol), vec![r1]);
        table.closed(id(1));
        assert_eq!(table.relays_to(&bob), vec![r2]);
        table.closed(id(2));
        assert!(table.relays_to(&bob).is_empty(), "the direct one has none");
        assert_eq!(table.via.len(), 1, "carol's only");
        table.closed(id(4));
        assert!(table.via.is_empty());
    }

    /// Review 5a-3: only a link that rode a relayed connection open before
    /// its dial, on the generation that still runs, and that got no answer
    /// before the Noise handshake verified the contact is taken for a stale
    /// circuit.
    #[test]
    fn a_stale_relayed_link_is_reused_relayed_and_unanswered_before_the_handshake() {
        use DeliveryPath::{Direct, HolePunched, Relayed, Reversed};
        let noise = internet_direct::STAGE_NOISE;
        let timed_out =
            "p2p dial to the contact timed out after 40s while connecting and in the Noise \
             handshake";
        assert!(stale_relayed_link(
            true,
            Some(Relayed),
            true,
            noise,
            timed_out
        ));
        assert!(stale_relayed_link(
            true,
            Some(Relayed),
            true,
            noise,
            "internet handshake deadline exceeded"
        ));
        // The dial opened the connection: its own facts explain it.
        assert!(!stale_relayed_link(
            false,
            Some(Relayed),
            true,
            noise,
            timed_out
        ));
        // Not relayed, or no connection left to label.
        for path in [None, Some(Direct), Some(Reversed), Some(HolePunched)] {
            assert!(
                !stale_relayed_link(true, path, true, noise, timed_out),
                "{path:?}"
            );
        }
        // A re-home ended it: the network changed, nothing to explain.
        assert!(!stale_relayed_link(
            true,
            Some(Relayed),
            false,
            noise,
            timed_out
        ));
        // Past the handshake the contact answered.
        for stage in [
            "exchanging RLB1 offers",
            "sending frames",
            "waiting for a reply",
        ] {
            assert!(
                !stale_relayed_link(true, Some(Relayed), true, stage, timed_out),
                "{stage}"
            );
        }
        // An answer: the link was closed or turned away.
        for answer in [
            "peer closed the connection during the handshake (3 attempts)",
            "p2p stream: the peer does not speak the Raven link (not a RAVEN node, or p2p is off \
             there)",
            "identity mismatch",
        ] {
            assert!(
                !stale_relayed_link(true, Some(Relayed), true, noise, answer),
                "{answer}"
            );
        }
    }

    /// Review 5a-3: a link that rode a stale relayed connection gets the
    /// reason a dial that got no answer through its relay gets (here no slot
    /// of ours is that relay: `relay_asleep`), kept for `raven status`. A
    /// connect that answered at once leaves no facts, so before this such a
    /// link got no reason at all ([`explain_unreachable`] returns the error
    /// as it was).
    #[tokio::test]
    async fn a_stale_relayed_link_is_explained_as_a_relay_that_did_not_answer() {
        let _lock = crate::netwatch::egress_test_lock().await;
        crate::netwatch::set_last_egress(Some(true));
        let dir = tempfile::tempdir().unwrap();
        let (target, relay) = (PeerId::random(), PeerId::random());
        let contact = [0x5A; 32];
        let e = "p2p dial to the contact timed out after 40s while connecting and in the Noise \
                 handshake";
        let since = Instant::now();
        assert_eq!(
            explain_unreachable(dir.path(), &contact, target, e.into(), since).await,
            e,
            "no facts: no reason"
        );
        assert!(crate::delivery_paths::why_for(&contact).is_none());
        let text =
            explain_stale_link(dir.path(), &contact, target, vec![relay], e.into(), since).await;
        let d = Diag::find(&text).expect("a reason");
        assert_eq!(d.why, Why::RelayAsleep, "{text}");
        assert!(text.starts_with(e), "{text}");
        assert_eq!(
            crate::delivery_paths::why_for(&contact).map(|(d, _)| d.why),
            Some(Why::RelayAsleep)
        );
        crate::netwatch::set_last_egress(None);
    }

    /// DCUtR's `Ok(id)` and the connection's `ConnectionEstablished` come in
    /// either order; both orders label it `hole_punched`, a close forgets it,
    /// and the waiting set stays bounded.
    #[test]
    fn a_dcutr_connection_is_labelled_punched_whichever_event_comes_first() {
        let (bob, carol) = (peer_id(12), peer_id(14));
        let id = ConnectionId::new_unchecked;
        let mut table = ConnTable::default();
        // The result first: remembered until the connection is reported.
        table.punched(id(1));
        table.established(id(1), bob, false, true);
        assert_eq!(table.origins(&bob), vec![ConnOrigin::Punched]);
        assert!(table.punched_pending.is_empty());
        // The connection first (the dialling side reports `is_dialer`).
        table.established(id(2), carol, false, true);
        assert_eq!(table.origins(&carol), vec![ConnOrigin::Dialled]);
        table.punched(id(2));
        assert_eq!(table.origins(&carol), vec![ConnOrigin::Punched]);
        assert_eq!(
            link_path(&table.origins(&carol), true),
            Some(DeliveryPath::HolePunched)
        );
        // A relayed connection is never relabelled.
        table.established(id(3), carol, true, true);
        table.punched(id(3));
        assert_eq!(table.split(&carol), (vec![id(2)], vec![id(3)]));
        // The peer's half of the hole punch: inbound, direct, while its
        // relayed connection is open (DCUtR reports only our own dial).
        table.established(id(5), carol, false, false);
        assert_eq!(table.origin(id(5)), Some(ConnOrigin::Punched));
        table.closed(id(5));
        // Accepted and dialled, and the close of each.
        table.established(id(4), bob, false, false);
        let mut bobs = table.origins(&bob);
        bobs.sort_by_key(|o| *o as u8);
        assert_eq!(bobs, vec![ConnOrigin::Accepted, ConnOrigin::Punched]);
        assert!(table.connected(&bob) && table.connected(&carol));
        for n in 1..=4 {
            table.closed(id(n));
        }
        assert!(table.is_empty() && !table.connected(&bob));
        assert_eq!(link_path(&table.origins(&bob), true), None);
        // A result whose connection never comes is dropped by its close, and
        // at most MAX_PUNCHED_PENDING wait.
        table.punched(id(9));
        table.closed(id(9));
        assert!(table.punched_pending.is_empty());
        for n in 0..=MAX_PUNCHED_PENDING {
            table.punched(id(100 + n));
        }
        assert!(table.punched_pending.len() <= MAX_PUNCHED_PENDING);
        table.established(id(100 + MAX_PUNCHED_PENDING), bob, false, false);
        assert_eq!(table.origins(&bob), vec![ConnOrigin::Punched]);
        // Identify observations count only from direct connections.
        table.established(id(200), carol, true, true);
        assert_eq!(table.origin(id(200)), Some(ConnOrigin::Relayed));
        assert_eq!(table.origin(id(201)), None);
    }

    /// Learning connectivity (Phase 6a): a relayed connection remembers its
    /// relay until it closes; a direct one never has one, and of two relays
    /// the one with the smaller PeerId bytes is named.
    #[test]
    fn a_relayed_connection_names_its_relay_until_it_closes() {
        let (bob, carol, r1, r2) = (peer_id(12), peer_id(14), peer_id(21), peer_id(22));
        let id = ConnectionId::new_unchecked;
        let mut table = ConnTable::default();
        table.established(id(1), bob, false, true);
        table.relayed_through(id(1), r1);
        assert_eq!(table.relay_of(&bob), None, "a direct connection");
        table.established(id(2), bob, true, true);
        table.relayed_through(id(2), r1);
        assert_eq!(table.relay_of(&bob), Some(r1));
        assert_eq!(table.relay_of(&carol), None);
        table.established(id(3), bob, true, false);
        table.relayed_through(id(3), r2);
        let first = if r1.to_bytes() < r2.to_bytes() {
            r1
        } else {
            r2
        };
        assert_eq!(table.relay_of(&bob), Some(first));
        table.closed(id(2));
        table.closed(id(3));
        assert_eq!(table.relay_of(&bob), None);
        assert!(table.via.is_empty());
    }

    /// Learning connectivity (P6.15): an inbound link counts for the relay
    /// of a relayed connection the contact opened to us (over our
    /// reservation), never for the contact's relay that a circuit this node
    /// dialled goes through; six such links are three receipts' evidence.
    #[test]
    fn inbound_over_our_reservation_counts_for_that_relay() {
        use crate::learning::{inbound, TestService};
        let (bob, ours, theirs, carol) = (peer_id(160), peer_id(161), peer_id(162), peer_id(163));
        let id = ConnectionId::new_unchecked;
        let mut table = ConnTable::default();
        // Our circuit to Bob through his relay.
        table.established(id(1), bob, true, true);
        table.relayed_through(id(1), theirs);
        assert_eq!(table.relay_of(&bob), Some(theirs));
        assert_eq!(table.reservation_relay_of(&bob), None, "his relay");
        // Bob's circuit to us through our reservation.
        table.established(id(2), bob, true, false);
        table.relayed_through(id(2), ours);
        assert_eq!(table.reservation_relay_of(&bob), Some(ours));
        // A direct inbound connection names none.
        table.established(id(3), carol, false, false);
        assert_eq!(table.reservation_relay_of(&carol), None);

        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("home"));
        t.set_now(1_800_000_000_000);
        let contact = [0xB0; 32];
        for _ in 0..6 {
            let via = table.reservation_relay_of(&bob).map(|r| r.to_bytes());
            inbound(&contact, OutboxCarrier::P2p, via, false);
        }
        t.drain();
        let m = t.model().unwrap();
        assert_eq!(m.relay(&ours.to_bytes()).unwrap().beta.a_m, 3_000);
        assert!(m.relay(&theirs.to_bytes()).is_none());
        assert_eq!(learned_terms(&[theirs, ours]), vec![(ours, 90)]);

        table.closed(id(2));
        assert_eq!(table.reservation_relay_of(&bob), None);
        assert!(table.inbound_relayed.is_empty());
    }

    /// An inbound direct connection is the peer's half of a hole punch only
    /// while DCUtR can be running: right after a relayed connection to that
    /// peer opened. Later, the relayed one may be stale (the peer's network
    /// changed and the relay has not noticed) and the peer's direct dial is
    /// an ordinary one: `accepted`, so a link we start on it is `reversed`.
    #[test]
    fn only_an_inbound_connection_inside_the_dcutr_window_is_punched() {
        let (bob, carol) = (peer_id(12), peer_id(14));
        let id = ConnectionId::new_unchecked;
        let t0 = Instant::now();
        let mut table = ConnTable::default();
        table.established_at(id(1), bob, true, true, t0, None);
        // Inside the window: the hole punch's inbound half.
        table.established_at(id(2), bob, false, false, t0 + DCUTR_INBOUND_WINDOW, None);
        assert_eq!(table.origin(id(2)), Some(ConnOrigin::Punched));
        // After it: an ordinary inbound connection, not an upgrade.
        let late = t0 + DCUTR_INBOUND_WINDOW + Duration::from_secs(1);
        table.established_at(id(3), bob, false, false, late, None);
        assert_eq!(table.origin(id(3)), Some(ConnOrigin::Accepted));
        table.closed(id(2));
        table.closed(id(1));
        assert_eq!(table.origins(&bob), vec![ConnOrigin::Accepted]);
        assert_eq!(
            link_path(&table.origins(&bob), true),
            Some(DeliveryPath::Reversed)
        );
        // A fresh relayed connection opens a fresh window.
        table.established_at(id(4), carol, true, true, late, None);
        table.established_at(
            id(5),
            carol,
            false,
            false,
            late + Duration::from_secs(5),
            None,
        );
        assert_eq!(table.origin(id(5)), Some(ConnOrigin::Punched));
        // DCUtR's own report still wins whenever it comes.
        table.established_at(id(6), bob, true, true, t0, None);
        table.punched(id(7));
        table.established_at(id(7), bob, false, false, late, None);
        assert_eq!(table.origin(id(7)), Some(ConnOrigin::Punched));
        // A close forgets when the relayed connection opened.
        for n in 3..=7 {
            table.closed(id(n));
        }
        assert!(table.is_empty() && table.relayed_at.is_empty());
        assert!(table.accepted_at.is_empty());
    }

    /// DCUtR's own signals decide first, on both sides. Both sides dial at
    /// once on every attempt, so an inbound direct connection from a peer
    /// DCUtR dialled a moment ago is the peer's half of the punch, however
    /// long after the relayed connection opened (a third attempt after slow
    /// timeouts); DCUtR's success also relabels one the peer opened just
    /// before our own dial was made. The 60 s window is only the fallback
    /// for when no attempt was seen since the relayed connection opened: one
    /// long after the last attempt is an ordinary connection.
    #[test]
    fn dcutr_attempts_label_the_peers_half_of_a_hole_punch() {
        let (bob, carol, dave) = (peer_id(12), peer_id(14), peer_id(16));
        let id = ConnectionId::new_unchecked;
        let secs = Duration::from_secs;
        let t0 = Instant::now();
        let mut table = ConnTable::default();
        // A third attempt, 90 s after the relayed connection opened.
        table.established_at(id(1), bob, true, true, t0, None);
        let third = t0 + secs(90);
        table.established_at(id(2), bob, false, false, third + secs(3), Some(third));
        assert_eq!(table.origin(id(2)), Some(ConnOrigin::Punched));
        assert_eq!(
            link_path(&[ConnOrigin::Punched], true),
            Some(DeliveryPath::HolePunched)
        );
        // Inside the 60 s window, but 40 s after DCUtR's last dial: no hole
        // punch was under way.
        table.established_at(id(3), carol, true, true, t0, None);
        let tried = t0 + secs(5);
        table.established_at(id(4), carol, false, false, tried + secs(40), Some(tried));
        assert_eq!(table.origin(id(4)), Some(ConnOrigin::Accepted));
        // An attempt seen only before the relayed connection opened leaves
        // the fallback on.
        table.established_at(id(5), dave, true, true, t0 + secs(10), None);
        table.established_at(id(6), dave, false, false, t0 + secs(20), Some(t0));
        assert_eq!(table.origin(id(6)), Some(ConnOrigin::Punched));

        // The peer's dial got here before ours was made, long after the
        // relayed connection opened: accepted, until DCUtR reports our own
        // connection of that punch.
        let late = t0 + secs(200);
        table.established_at(id(7), dave, false, false, late, Some(t0 + secs(100)));
        assert_eq!(table.origin(id(7)), Some(ConnOrigin::Accepted));
        let old = late - secs(30);
        table.established_at(id(8), dave, false, false, old, None);
        table.established_at(id(9), carol, false, false, late, None);
        table.established_at(id(10), dave, false, true, late + secs(1), None);
        table.upgraded(id(10), dave, late + secs(1));
        assert_eq!(table.origin(id(10)), Some(ConnOrigin::Punched));
        assert_eq!(table.origin(id(7)), Some(ConnOrigin::Punched));
        // Not one from before that punch, nor another peer's.
        assert_eq!(table.origin(id(8)), Some(ConnOrigin::Accepted));
        assert_eq!(table.origin(id(9)), Some(ConnOrigin::Accepted));
        for n in 1..=10 {
            table.closed(id(n));
        }
        assert!(table.is_empty() && table.accepted_at.is_empty());
    }

    /// The candidate book's own IPv6 is the preferred source address, and
    /// only a global one outside the debug lab.
    #[test]
    fn the_preferred_v6_source_is_global_unless_the_lab_switch() {
        let global: Ipv6Addr = "2a02:db8:1::7".parse().unwrap();
        for local in ["::1", "fe80::1", "fd00::1", "2001:db8::1"] {
            let local: Ipv6Addr = local.parse().unwrap();
            assert_eq!(preferred_v6_of(Some(local), false), None, "{local}");
            assert_eq!(preferred_v6_of(Some(local), true), Some(local), "{local}");
        }
        assert_eq!(preferred_v6_of(Some(global), false), Some(global));
        assert_eq!(preferred_v6_of(None, true), None);
        assert!(is_ip6(&"/ip6/::1/tcp/7423".parse().unwrap()));
        assert!(!is_ip6(&"/ip4/127.0.0.1/tcp/7423".parse().unwrap()));
    }

    /// AppSubmit's probe reads a p2p refusal as the contact's only when the
    /// route's own PeerId turned the dial away, after the dial started.
    #[test]
    fn target_refused_since_reads_only_the_target_s_refusals() {
        let (bob, relay_peer) = (peer_id(41), peer_id(42));
        let route = OutboxRoute {
            carrier: OutboxCarrier::P2p,
            dial: p2p_route::peer_route(&bob.to_string()),
        };
        let circuit = OutboxRoute {
            carrier: OutboxCarrier::P2p,
            dial: format!("/ip4/127.0.0.1/tcp/7423/p2p/{relay_peer}/p2p-circuit/p2p/{bob}"),
        };
        let before = std::time::Instant::now();
        note_closed_at_once(bob);
        assert!(target_refused_since(&route, before));
        assert!(target_refused_since(&circuit, before), "Bob behind a relay");
        let later = std::time::Instant::now() + Duration::from_secs(5);
        assert!(!target_refused_since(&route, later), "an older refusal");

        // The relay turned a later dial away: not Bob's refusal.
        let mid = std::time::Instant::now();
        note_closed_at_once(relay_peer);
        assert!(!target_refused_since(&route, mid));
        assert!(!target_refused_since(&circuit, mid));
        let relay_route = OutboxRoute {
            carrier: OutboxCarrier::P2p,
            dial: p2p_route::peer_route(&relay_peer.to_string()),
        };
        assert!(target_refused_since(&relay_route, mid));

        for (carrier, dial) in [
            (OutboxCarrier::Lan, route.dial.clone()),
            (OutboxCarrier::Internet, route.dial.clone()),
            (OutboxCarrier::P2p, "not a p2p dial".to_string()),
        ] {
            assert!(!target_refused_since(
                &OutboxRoute { carrier, dial },
                before
            ));
        }
    }

    /// The worker's connected test is p2p-only and needs a running host.
    #[test]
    fn route_connected_is_false_without_a_host_and_for_non_p2p_routes() {
        let p2p = OutboxRoute {
            carrier: OutboxCarrier::P2p,
            dial: p2p_route::peer_route(&peer(12)),
        };
        assert!(current_host().is_none());
        assert!(!route_connected(&p2p));
        for (carrier, dial) in [
            (OutboxCarrier::Lan, "127.0.0.1:7420".to_string()),
            (OutboxCarrier::Internet, "203.0.113.7:7422".to_string()),
            (OutboxCarrier::P2p, "not a p2p dial".to_string()),
            (OutboxCarrier::Lan, p2p.dial.clone()),
        ] {
            assert!(!route_connected(&OutboxRoute { carrier, dial }));
        }
    }

    /// The path counts are the process's, not an endpoint's: a re-homed
    /// generation reports what the earlier one counted.
    #[tokio::test]
    async fn path_counts_survive_a_rehome() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(Vec::new()));
        let (mut host, _incoming, handle) = seed.build(0, false).unwrap();
        let before = host.status_info().paths.expect("a running host counts");
        count_paths(|c| c.sent.add(DeliveryPath::Reversed));
        count_paths(|c| c.received.add(DeliveryPath::HolePunched));
        count_paths(|c| c.upgrades += 1);
        // The connection table is the generation's.
        lock(&handle.conns).established(ConnectionId::new_unchecked(7), peer_id(12), false, false);
        assert!(handle.connected(&peer_id(12)));
        assert_eq!(
            handle.path_to(&peer_id(12), true),
            Some(DeliveryPath::Reversed)
        );
        lock(&handle.conns).closed(ConnectionId::new_unchecked(7));
        host.close_everything(REHOME_DRAIN, false).await;
        drop(host);
        let (fresh, _incoming, fresh_handle) = seed.build(1, true).unwrap();
        let after = fresh.status_info().paths.unwrap();
        assert!(after.sent.reversed > before.sent.reversed);
        assert!(after.received.hole_punched > before.received.hole_punched);
        assert!(after.upgrades > before.upgrades);
        assert!(!fresh_handle.connected(&peer_id(12)));
    }

    // ── Phase 2 (P2.21): automatic relay choice in the host ─────────────────

    /// A loopback config whose host runs automatic relay choice.
    fn auto_config(relays: Vec<ViaAddr>) -> P2pConfig {
        P2pConfig {
            auto: Some(true),
            ..loopback_config(relays)
        }
    }

    /// The offer of one relay at `addrs` (`via=` texts of one relay), by
    /// the verified contact `operator`, live for an hour.
    fn offered_at(addrs: &[&str], operator: u8) -> Candidate {
        let via = p2p_route::parse_via(addrs[0]).unwrap();
        Candidate {
            addrs: addrs.iter().map(|a| a.to_string()).collect(),
            group: None,
            via,
            source: Source::Offer {
                operator_pub_hex: hex::encode([operator; 32]),
            },
            confirmed: false,
            expires_at_ms: crate::now_ms() + 3_600_000,
            operator: Operator::Verified,
        }
    }

    fn offered(via: &str, operator: u8) -> Candidate {
        offered_at(&[via], operator)
    }

    /// The host reads `offers` from its files ([`Host::offers_loaded`]).
    fn offer(host: &mut Host, offers: Vec<Candidate>) {
        let stamp = gate_stamp(&host.data_dir);
        host.offers_loaded(Some(OffersLoad {
            stamp,
            candidates: offers,
            policy_on: true,
        }));
    }

    /// Where relay `seed` would be if anything listened there (nothing
    /// does: port 9 on loopback).
    fn nowhere(seed: u8) -> String {
        format!("/ip4/127.0.0.1/tcp/9/p2p/{}", peer(seed))
    }

    /// A relay on loopback with its own key (`seed`): the profile-key relay
    /// role with an allow-list, which names the test host (key 13) when it is
    /// a `member`. Its `via=` text at its TCP address.
    async fn lab_relay(gate: &HostGate, dir: &Path, seed: u8, member: bool) -> (Host, String) {
        let dir = dir.join(format!("relay{seed}"));
        std::fs::create_dir_all(&dir).unwrap();
        if member {
            let host_peer = test_key(13).public().to_peer_id().to_string();
            raven_core::relay_allow::relay_allow(&dir, &host_peer, "host").unwrap();
        }
        let (relay_seed, _commands) = test_seed(
            gate,
            &dir,
            P2pConfig {
                relay_server: Some(false),
                ..loopback_config(Vec::new())
            },
        );
        let relay_seed = HostSeed {
            keypair: test_key(seed),
            ..relay_seed
        };
        let (mut relay, _incoming, _handle) = relay_seed.build(0, false).unwrap();
        let tcp = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let event = relay.swarm.select_next_some().await;
                relay.on_event(event);
                if let Some(tcp) = relay.listen_addrs.iter().find(|a| is_tcp(a)) {
                    break tcp.clone();
                }
            }
        })
        .await
        .expect("the relay listens on TCP");
        let via = format!("{tcp}/p2p/{}", relay.swarm.local_peer_id());
        (relay, via)
    }

    /// Runs a relay in the background for the rest of the test.
    fn run_relay(mut relay: Host) -> (PeerId, JoinHandle<()>) {
        let peer = *relay.swarm.local_peer_id();
        let task = tokio::spawn(async move {
            loop {
                let event = relay.swarm.select_next_some().await;
                relay.on_event(event);
            }
        });
        (peer, task)
    }

    /// Drive `host` until `done`, at most `secs`: `false` on time-out.
    async fn drive(host: &mut Host, secs: u64, done: impl Fn(&Host) -> bool) -> bool {
        tokio::time::timeout(Duration::from_secs(secs), async {
            while !done(host) {
                let event = host.swarm.select_next_some().await;
                host.on_event(event);
            }
        })
        .await
        .is_ok()
    }

    /// The host resolves an offered relay's name with the offer rule: a
    /// name that answers only loopback gives the slot nothing to dial (no
    /// reservation is asked), unless a debug lab flag keeps local answers.
    #[tokio::test]
    async fn an_offered_slot_named_by_dns_resolves_to_global_answers_only() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (seed, mut commands) = test_seed(&gate, dir.path(), auto_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        let via = format!("/dns4/localhost/tcp/9/p2p/{}", peer(43));
        offer(&mut host, vec![offered(&via, 3)]);
        assert_eq!(host.slots.len(), 1);
        assert!(host.slots[0].resolving && host.slots[0].listener.is_none());
        let resolved = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(Command::Resolved { addrs, .. }) = commands.recv().await {
                    break addrs;
                }
            }
        })
        .await
        .expect("the name is looked up");
        let lab = raven_core::p2p_local_candidates_enabled()
            || raven_core::route_hints::lab_loopback_relays();
        assert_eq!(resolved.is_empty(), !lab, "{resolved:?}");
        if !lab {
            host.on_resolved(peer_id(43), resolved);
            let slot = &host.slots[0];
            assert!(
                slot.listener.is_none() && slot.connecting.is_none() && slot.retry_at.is_some(),
                "nothing dialled; retried later"
            );
        }
    }

    /// Both picked relays are down (asleep, or unreachable from here) and no
    /// connection proves this node online: automatic choice dials the
    /// offered relay that would take a slot (no reservation asked), and once
    /// it connects, replaces a slot with it. Without that it would wait for
    /// unrelated traffic.
    #[tokio::test]
    async fn with_every_slot_down_a_standby_is_dialled_as_the_online_proof() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (live, via) = lab_relay(&gate, dir.path(), 50, true).await;
        let (live, _task) = run_relay(live);
        let (seed, _commands) = test_seed(&gate, dir.path(), auto_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        // Two relays nothing answers at hold both slots, picked past their
        // probation (as after a restart while they sleep).
        let asleep = vec![offered(&nowhere(51), 1), offered(&nowhere(52), 2)];
        offer(&mut host, asleep.clone());
        assert_eq!(host.slots.len(), 2);
        let picked_at = Instant::now()
            .checked_sub(Duration::from_secs(180))
            .expect("an instant three minutes ago");
        for slot in &mut host.slots {
            slot.selected_at = picked_at;
        }
        host.last_ok = None;
        // A third relay is offered: the one to dial as the proof.
        let mut offers = asleep;
        offers.push(offered(&via, 3));
        offer(&mut host, offers);
        assert!(
            !host.slots.iter().any(|s| s.peer == live),
            "offline: no change"
        );
        assert_eq!(host.auto.probe.map(|(p, _)| p), Some(live));
        assert!(
            drive(&mut host, 10, |h| h.swarm.is_connected(&live)).await,
            "the standby is dialled"
        );
        assert!(host.last_ok.is_some());
        host.select_relays(Instant::now());
        assert!(
            host.slots.iter().any(|s| s.peer == live),
            "a slot replaced by the relay that answered"
        );
        assert!(
            drive(&mut host, 10, |h| h
                .slots
                .iter()
                .any(|s| s.peer == live && s.active))
            .await,
            "reserved on it"
        );
        // One dial per window: a second round does not dial again.
        let first = host.auto.probe.map(|(_, at)| at);
        host.last_ok = None;
        host.select_relays(Instant::now());
        assert_eq!(host.auto.probe.map(|(_, at)| at), first);
    }

    /// Two offered relays fill both slots and hold reservations. When one
    /// offer is withdrawn its slot goes (its listener, then its connection),
    /// and the other slot keeps the reservation it holds: the same
    /// listener, never asked again.
    #[tokio::test]
    async fn selection_is_applied_in_place_and_keeps_the_other_reservation() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (r1, via1) = lab_relay(&gate, dir.path(), 41, true).await;
        let (r2, via2) = lab_relay(&gate, dir.path(), 42, true).await;
        let ((p1, _t1), (p2, _t2)) = (run_relay(r1), run_relay(r2));
        let (seed, _commands) = test_seed(&gate, dir.path(), auto_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        assert!(host.slots.is_empty(), "nothing offered yet");
        offer(&mut host, vec![offered(&via1, 1), offered(&via2, 2)]);
        let mut peers: Vec<PeerId> = host.slots.iter().map(|s| s.peer).collect();
        peers.sort();
        let mut both = vec![p1, p2];
        both.sort();
        assert_eq!(peers, both, "both slots filled at once");
        assert!(host
            .slots
            .iter()
            .all(|s| s.listener.is_some() && matches!(s.source, Source::Offer { .. })));
        assert!(
            drive(&mut host, 20, |h| h.slots.iter().all(|s| s.active)).await,
            "both relays accept a reservation"
        );
        let kept = host.slots.iter().find(|s| s.peer == p2).unwrap();
        let (listener, since) = (kept.listener, kept.since);

        // The first relay's offer is withdrawn.
        offer(&mut host, vec![offered(&via2, 2)]);
        assert_eq!(host.slots.len(), 1);
        let slot = &host.slots[0];
        assert_eq!(
            (slot.peer, slot.listener, slot.since, slot.active),
            (p2, listener, since, true),
            "the other slot is untouched"
        );
        assert!(
            drive(&mut host, 10, |h| !h.swarm.is_connected(&p1)).await,
            "the dropped relay's connection is closed"
        );
        let slot = &host.slots[0];
        assert!(slot.active && slot.listener == listener && slot.attempt == 0);
        assert!(host.swarm.is_connected(&p2));
        assert_eq!(host.status_info().reservations.len(), 1);
        assert_eq!(host.auto.picked.len(), 1);
        assert_eq!(host.auto.mem.selected, vec![p2.to_string()]);
    }

    /// A picked relay is admitted by the peer gate before anything is
    /// dialled (its reservation is only asked); when another relay takes
    /// its place, the gate's recheck closes the old one's connection.
    #[tokio::test]
    async fn the_gate_admits_a_new_relay_before_the_dial_and_rechecks_the_old_one_out() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (r1, via1) = lab_relay(&gate, dir.path(), 43, true).await;
        let (p1, _task) = run_relay(r1);
        let (seed, _commands) = test_seed(&gate, dir.path(), auto_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        assert!(!host.gate.class_of(&p1).intersects(PeerClass::OWN_RELAY));
        offer(&mut host, vec![offered(&via1, 1)]);
        assert!(host.gate.class_of(&p1).intersects(PeerClass::OWN_RELAY));
        assert!(!host.swarm.is_connected(&p1), "nothing dialled yet");
        assert!(host.slots[0].listener.is_some(), "the reservation is asked");
        assert_eq!(host.gate_status().relays, 1);
        assert!(
            drive(&mut host, 20, |h| h.slots.iter().any(|s| s.active)).await,
            "reserved"
        );

        // Its offer withdrawn, another relay offered.
        let p2 = peer_id(44);
        offer(&mut host, vec![offered(&nowhere(44), 2)]);
        assert!(host.gate.class_of(&p2).intersects(PeerClass::OWN_RELAY));
        assert!(!host.gate.class_of(&p1).intersects(PeerClass::OWN_RELAY));
        let peers: Vec<PeerId> = host.slots.iter().map(|s| s.peer).collect();
        assert_eq!(peers, vec![p2]);
        assert!(
            drive(&mut host, 10, |h| !h.swarm.is_connected(&p1)).await,
            "the recheck closed the old relay's connection"
        );
        assert_eq!(host.gate_status().relays, 1);
    }

    /// A relay that does not count this node a member closes its
    /// connection right after Noise, before any reservation: noted as not a
    /// member (10 min while a contact offers it), written at once, and the
    /// next round drops its slot.
    #[tokio::test]
    async fn a_quick_close_on_a_reservation_marks_not_member() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (relay, via) = lab_relay(&gate, dir.path(), 45, false).await;
        let (p, _task) = run_relay(relay);
        let key = p.to_string();
        let (seed, _commands) = test_seed(&gate, dir.path(), auto_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        offer(&mut host, vec![offered(&via, 1)]);
        assert_eq!(host.slots.len(), 1);
        assert!(
            drive(&mut host, 20, |h| h
                .auto
                .mem
                .is_not_member(&key, crate::now_ms()))
            .await,
            "the quick close is noted"
        );
        let now_ms = crate::now_ms();
        let until = host.auto.mem.memo(&key).not_member_until_ms;
        assert!(
            until <= now_ms + relay_select::NOT_MEMBER_OFFERED_MS
                && until + 60_000 > now_ms + relay_select::NOT_MEMBER_OFFERED_MS,
            "offered: skipped for 10 min"
        );
        assert!(host.auto.dirty && host.auto.urgent, "to be written at once");
        assert!(closed_at_once_since(
            &p,
            Instant::now() - Duration::from_secs(30)
        ));
        host.select_relays(Instant::now());
        assert!(
            host.slots.is_empty(),
            "dropped: it does not admit this node"
        );
        assert!(!host.gate.class_of(&p).intersects(PeerClass::OWN_RELAY));
        host.save_memory(Instant::now());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !relay_select::load_memory(dir.path()).is_not_member(&key, crate::now_ms()) {
            assert!(std::time::Instant::now() < deadline, "not written");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// The loss clocks are the endpoint generation's: a relay lost in one
    /// generation (before a sleep or a network change) starts the next one
    /// picked a moment ago, never reserved there and not lost.
    #[tokio::test]
    async fn loss_clocks_restart_with_each_generation() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let relay = peer_id(46);
        let via = nowhere(46);
        let (seed, _commands) = test_seed(&gate, dir.path(), auto_config(Vec::new()));
        {
            let mut auto = lock(&seed.auto);
            let offer = offered(&via, 1);
            auto.picked = vec![(offer.via.clone(), offer.source.clone())];
            auto.candidates = vec![offer];
        }
        let start0 = Instant::now();
        let (mut host, _incoming, _handle) = build_reserving(&seed, 0, false);
        assert_eq!(host.slots.len(), 1);
        let slot = &host.slots[0];
        assert_eq!(slot.peer, relay);
        assert!(slot.selected_at >= start0 && slot.lost_since().is_none() && !slot.ever_reserved());
        // It held a reservation, then lost it.
        host.slots[0].active = true;
        host.slots[0].since = Some(start0);
        let listener_id = host.slots[0].listener.expect("asked");
        host.on_event(SwarmEvent::ListenerClosed {
            listener_id,
            addresses: Vec::new(),
            reason: Err(std::io::Error::other("lost")),
        });
        let lost = host.slots[0].lost_since().expect("lost in this generation");
        let row = host.slot_now(Instant::now(), crate::now_ms()).remove(0);
        assert!(row.lost_since_ms.is_some() && row.ever_reserved && !row.active);

        // The endpoint is re-homed: the next generation starts every clock.
        seed.keep_auto(&host.auto);
        drop(host);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let start1 = Instant::now();
        let (fresh, _incoming, _handle) = seed.build(1, true).unwrap();
        let slot = &fresh.slots[0];
        assert_eq!(slot.peer, relay, "the same relay, from the seed");
        assert!(slot.selected_at >= start1 && slot.selected_at > lost);
        assert!(slot.lost_since().is_none() && !slot.ever_reserved());
        let now_ms = crate::now_ms();
        let row = fresh.slot_now(Instant::now(), now_ms).remove(0);
        assert_eq!(row.lost_since_ms, None);
        assert!(!row.ever_reserved && !row.manual);
        assert!(
            now_ms - row.selected_at_ms < 5_000,
            "picked as this generation began"
        );
    }

    /// AutoNAT clients are made per endpoint: after the relays changed, the
    /// endpoint is re-homed once no Raven link was open for a minute since
    /// the change, or 30 minutes after it whatever happens. A new pick marks
    /// them stale once it accepts a reservation, a server that answered
    /// marks them stale when it goes, a pick that never reserved changes
    /// nothing; going back clears it.
    #[tokio::test]
    async fn autonat_rebind_waits_for_an_idle_minute_or_thirty_minutes() {
        let s = Duration::from_secs;
        let t0 = Instant::now() + s(3600);
        assert!(!autonat_rebind_due(None, Some(t0 - s(600)), t0 + s(3600)));
        // Links stay open: only after 30 min.
        assert!(!autonat_rebind_due(Some(t0), None, t0 + s(1799)));
        assert!(autonat_rebind_due(Some(t0), None, t0 + s(1800)));
        // Idle since before the change: a minute after the change.
        assert!(!autonat_rebind_due(Some(t0), Some(t0 - s(600)), t0 + s(59)));
        assert!(autonat_rebind_due(Some(t0), Some(t0 - s(600)), t0 + s(60)));
        // Idle from later on: a minute of it.
        assert!(!autonat_rebind_due(
            Some(t0),
            Some(t0 + s(100)),
            t0 + s(159)
        ));
        assert!(autonat_rebind_due(Some(t0), Some(t0 + s(100)), t0 + s(160)));

        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), auto_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        assert_eq!(host.autonat_built, [None, None]);
        offer(&mut host, vec![offered(&nowhere(47), 1)]);
        // A pick that never held a reservation serves nothing: its clients
        // are not stale yet, and replacing it re-homes nothing.
        assert_eq!(host.autonat_stale_since, None, "nothing reserved yet");
        offer(&mut host, vec![offered(&nowhere(46), 2)]);
        assert_eq!(host.slots[0].peer, peer_id(46));
        assert_eq!(host.autonat_stale_since, None, "a never-reserved pick went");
        // Once it accepts a reservation, the endpoint has no client for it.
        let accepted = SwarmEvent::Behaviour(EndpointBehaviourEvent::RelayClient(
            relay::client::Event::ReservationReqAccepted {
                relay_peer_id: peer_id(46),
                renewal: false,
                limit: None,
            },
        ));
        host.on_event(accepted);
        assert!(host.autonat_stale_since.is_some(), "a new server");
        offer(&mut host, Vec::new());
        assert!(host.slots.is_empty());
        assert_eq!(host.autonat_stale_since, None, "back to the built servers");
        // A server that answered and goes makes the clients stale at once.
        offer(&mut host, vec![offered(&nowhere(46), 2)]);
        host.slots[0].since = Some(Instant::now());
        offer(&mut host, vec![offered(&nowhere(47), 1)]);
        assert!(host.autonat_stale_since.is_some(), "a server went");
        offer(&mut host, Vec::new());
        // Due: the tick asks for the re-home once (no host is published
        // here, so nothing else happens) and clears the mark.
        let now = Instant::now();
        host.autonat_stale_since = Some(now - s(61));
        host.idle_since = Some(now - s(61));
        host.tick_auto(now);
        assert_eq!(host.autonat_stale_since, None);
        assert_eq!(Rehome::Relays.text(), "relays changed");
    }

    /// A reservation accepted on a picked relay changes the routes route
    /// hints tell (the relays held): the generation moves once; a renewal
    /// changes nothing. The relay's success is noted in the memory.
    #[tokio::test]
    async fn an_accepted_reservation_bumps_the_route_hint_generation_once() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let (relay, via) = (peer_id(48), nowhere(48));
        let (seed, _commands) = test_seed(&gate, dd, auto_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        offer(&mut host, vec![offered(&via, 1)]);
        assert!(host.slots[0].listener.is_some() && !host.slots[0].active);
        let before = host.own_p2p();
        assert!(before.relays.is_empty());
        let now_ms = crate::now_ms();
        let g0 = crate::hints::own_generation(dd, &before, now_ms).unwrap();
        assert_eq!(
            crate::hints::own_generation(dd, &host.own_p2p(), now_ms),
            Some(g0)
        );
        let accepted = |renewal: bool| {
            SwarmEvent::Behaviour(EndpointBehaviourEvent::RelayClient(
                relay::client::Event::ReservationReqAccepted {
                    relay_peer_id: relay,
                    renewal,
                    limit: None,
                },
            ))
        };
        host.on_event(accepted(false));
        assert!(host.slots[0].active);
        let after = host.own_p2p();
        assert_eq!(after.relays, vec![via.clone()]);
        let mut held = Some(before);
        assert!(
            replace_own(&mut held, Some(after.clone())),
            "the announcer wakes"
        );
        let g1 = crate::hints::own_generation(dd, &after, now_ms).unwrap();
        assert!(g1 > g0);
        // The renewal: same routes, no second bump.
        host.on_event(accepted(true));
        assert!(!replace_own(&mut held, Some(host.own_p2p())));
        assert_eq!(
            crate::hints::own_generation(dd, &host.own_p2p(), now_ms),
            Some(g1)
        );
        assert!(host.auto.mem.memo(&relay.to_string()).last_ok_ms >= now_ms);
    }

    /// The relay of a picked slot moved: its offer names other addresses.
    /// The slot takes them in place (no new choice: the same pick, the same
    /// time, the memory's generation unchanged); an idle slot is tried at
    /// once on the first, a reservation held stays.
    #[tokio::test]
    async fn an_offer_with_new_addresses_updates_the_slot_in_place() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let relay = peer(49);
        let old = nowhere(49);
        let (seed, _commands) = test_seed(&gate, dir.path(), auto_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        offer(&mut host, vec![offered(&old, 1)]);
        // Refused there: it waits out its backoff.
        let listener_id = host.slots[0].listener.expect("asked");
        host.on_event(SwarmEvent::ListenerClosed {
            listener_id,
            addresses: Vec::new(),
            reason: Err(std::io::Error::other("refused")),
        });
        assert_eq!(host.slots[0].attempt, 1);
        let (selected_at, generation) = (host.slots[0].selected_at, host.auto.mem.generation);

        let main = format!("/ip4/127.0.0.1/tcp/7427/p2p/{relay}");
        let fallback = format!("/ip4/127.0.0.1/tcp/443/p2p/{relay}");
        let now = Instant::now();
        offer(&mut host, vec![offered_at(&[&main, &fallback], 1)]);
        assert_eq!(host.slots.len(), 1);
        let slot = &host.slots[0];
        assert_eq!(slot.texts, vec![main.clone(), fallback.clone()]);
        let named: Vec<Multiaddr> = [&main, &fallback]
            .iter()
            .map(|t| t.parse().unwrap())
            .collect();
        assert_eq!(
            (&slot.named, &slot.resolved, slot.next),
            (&named, &named, 0)
        );
        assert_eq!(slot.selected_at, selected_at, "no new choice");
        assert_eq!(slot.attempt, 0, "its backoff starts over");
        assert!(slot
            .retry_at
            .is_some_and(|t| t <= now + Duration::from_secs(1)));
        assert_eq!(host.auto.mem.generation, generation);
        assert_eq!(host.auto.picked[0].0.text, main);

        // Held: the reservation stays where it is, the names change.
        host.slots[0].active = true;
        host.slots[0].listener = Some(ListenerId::next());
        let held = host.slots[0].listener;
        offer(&mut host, vec![offered(&fallback, 1)]);
        let slot = &host.slots[0];
        assert_eq!(slot.texts, vec![fallback.clone()]);
        assert!(slot.active && slot.listener == held);
        assert_eq!(host.auto.mem.generation, generation);
    }

    /// The circuit plan's addresses: a direct one to `target`, then
    /// circuits through `relays`.
    fn circuit(relay: PeerId, target: PeerId) -> Multiaddr {
        format!("/ip4/127.0.0.1/tcp/7427/p2p/{relay}/p2p-circuit/p2p/{target}")
            .parse()
            .unwrap()
    }

    /// A relay client's error as the transport stacks it, with the relay's
    /// answer `e` ([`dial_failures`]).
    fn relay_answered(
        e: raven_swarm::libp2p::relay::outbound::hop::ConnectError,
    ) -> TransportError<std::io::Error> {
        use raven_swarm::libp2p::core::transport::timeout::TransportTimeoutError;
        use raven_swarm::libp2p::swarm::derive_prelude::Either;
        TransportError::Other(std::io::Error::other(TransportTimeoutError::Other(
            Either::<_, std::io::Error>::Left(relay::client::transport::Error::Connect(e)),
        )))
    }

    /// A relay's answer to a circuit is read by `raven_swarm::diag` alone,
    /// never as a quick close: a member over the relay's circuit cap or rate
    /// (RESOURCE_LIMIT_EXCEEDED) hears that the relay is busy, with no
    /// "`raven relay allow` your card" hint, and a STOP the relay could not
    /// complete (CONNECTION_FAILED) says the contact is not on that relay,
    /// never that its node refused us: not for the diagnosis, and not for
    /// AppSubmit's probe ([`target_refused_since`]), although the
    /// contact's gate turning a circuit away gives that same answer.
    #[test]
    fn a_relay_s_circuit_answer_is_never_a_quick_close() {
        use raven_swarm::libp2p::relay::outbound::hop::ConnectError;
        let (bob, relay) = (peer_id(140), peer_id(141));
        assert_eq!(circuit_relay(&circuit(relay, bob)), Some(relay));
        let direct: Multiaddr = format!("/ip4/127.0.0.1/tcp/7423/p2p/{bob}")
            .parse()
            .unwrap();
        assert_eq!(circuit_relay(&direct), None);
        for (answer, want, slot) in [
            (ConnectError::ResourceLimitExceeded, Why::RelayBusy, Some(1)),
            (ConnectError::ConnectionFailed, Why::ContactOffline, None),
        ] {
            let since = Instant::now();
            let mut facts = DialFacts::default();
            facts.begin(bob, InFlight::new(vec![relay], &[]));
            let error = DialError::Transport(vec![(circuit(relay, bob), relay_answered(answer))]);
            note_dial_failure(&mut facts, Some(bob), &error);
            let summary = dial_summary(
                facts.take(&bob).unwrap(),
                &[Some(relay)],
                |p| closed_at_once_since(p, since),
                closed_at_once_since(&bob, since),
            );
            let d = diagnose(&summary, &MyFacts::default(), &TheirFacts::default()).unwrap();
            assert_eq!((d.why, d.relay), (want, slot), "{summary:?}");
            assert!(
                !closed_at_once_since(&relay, since) && !closed_at_once_since(&bob, since),
                "{want:?}: a relay's answer is no quick close"
            );
            // Nor, for AppSubmit's probe, Bob's refusal: a p2p-only contact
            // behind a relay whose gate turns the circuit away reads
            // retryable (APP_PEER_UNREACHABLE), never LINK_NOT_ACCEPTED.
            for dial in [
                p2p_route::peer_route(&bob.to_string()),
                circuit(relay, bob).to_string(),
            ] {
                let route = OutboxRoute {
                    carrier: OutboxCarrier::P2p,
                    dial,
                };
                assert!(!target_refused_since(&route, since.into_std()), "{want:?}");
            }
            assert_eq!(
                with_refusal_hint(P2P_UNREACHABLE.into(), &bob, &[relay], since),
                P2P_UNREACHABLE,
                "{want:?}: no refusal hint"
            );
        }
    }

    /// A contact asleep behind one of our relays that is up: the circuit gets
    /// no answer (the relay waits on the contact), but the relay holds our
    /// reservation and answers our pings. Only our slots that gave no answer
    /// and hold our reservation are asked about; one that answered a ping
    /// after the dial began is up, so the reason is `contact_offline` with no
    /// slot named (never "your relay is not answering"); one that lost our
    /// reservation, or answered only before the dial, leaves `relay_asleep`;
    /// one that holds it without an answer yet is waited for.
    #[tokio::test]
    async fn a_relay_that_answered_during_the_dial_makes_it_the_contact_s_silence() {
        use CircuitOutcome::{Busy, NoAnswer};
        let (r1, r2) = (peer_id(150), peer_id(151));
        let st = P2pStatusInfo {
            relay_health: vec![
                RelayHealth {
                    relay: format!("/ip4/11.0.0.1/tcp/7423/p2p/{r1}"),
                    state: "reserved".into(),
                    ..RelayHealth::default()
                },
                RelayHealth {
                    relay: format!("/ip4/11.0.0.2/tcp/7423/p2p/{r2}"),
                    state: "retrying".into(),
                    ..RelayHealth::default()
                },
            ],
            ..P2pStatusInfo::default()
        };
        let summary = DialSummary {
            circuits: vec![
                (Some(1), NoAnswer, false),
                (Some(2), NoAnswer, false),
                (None, NoAnswer, false),
                (Some(1), NoAnswer, false),
            ],
            ..DialSummary::default()
        };
        assert_eq!(silent_slots(&summary, &st), vec![(1, r1)]);
        let busy = DialSummary {
            circuits: vec![(Some(1), Busy, false)],
            ..DialSummary::default()
        };
        assert!(silent_slots(&busy, &st).is_empty());
        let asked = [(1u8, r1)];
        assert_eq!(
            slot_verdict(&asked, |_| true, |_, _| true),
            SlotVerdict::Answering(vec![1])
        );
        assert_eq!(
            slot_verdict(&asked, |_| false, |_, _| true),
            SlotVerdict::Open
        );
        assert_eq!(
            slot_verdict(&asked, |_| false, |_, _| false),
            SlotVerdict::Silent
        );
        assert_eq!(
            slot_verdict(&[], |_| true, |_, _| true),
            SlotVerdict::Silent
        );

        // A ping before the dial began proves nothing; one after it does.
        let since = Instant::now();
        note_relay_pinged(r1, since - Duration::from_millis(5));
        assert!(!relay_pinged_since(&r1, since));
        // Held when the dial failed, and no answer since it began: not
        // decided yet (the dial returns now, the reason comes later).
        let held = |slot: u8, relay: &PeerId| holds_reservation(&st, slot, relay);
        assert_eq!(
            slot_verdict(&asked, |r| relay_pinged_since(r, since), held),
            SlotVerdict::Open
        );
        // Not pinged, and no host holds our reservation on it now: decided
        // at once, no slot answered.
        let t = Instant::now();
        assert!(await_slots(&asked, since).await.is_empty());
        assert!(t.elapsed() < Duration::from_secs(2));
        let asleep = diagnose(&summary, &MyFacts::default(), &TheirFacts::default()).unwrap();
        assert_eq!((asleep.why, asleep.relay), (Why::RelayAsleep, Some(1)));

        note_relay_pinged(r1, Instant::now());
        assert!(relay_pinged_since(&r1, since));
        let answering = await_slots(&asked, since).await;
        assert_eq!(answering, vec![1]);
        let d = diagnose(
            &DialSummary {
                slots_answering: answering,
                ..summary.clone()
            },
            &MyFacts::default(),
            &TheirFacts::default(),
        )
        .unwrap();
        assert_eq!((d.why, d.relay), (Why::ContactOffline, None));
    }

    /// NO_RESERVATION from a relay demotes its circuits to that contact for
    /// 10 min: they go last, never out. A busy relay is noted nowhere,
    /// another contact's dials keep their order, and the Phase 1 host notes
    /// nothing.
    #[tokio::test]
    async fn no_reservation_demotes_but_never_skips_the_relay() {
        use raven_swarm::libp2p::relay::outbound::hop::ConnectError;
        let (target, other, r1, r2) = (peer_id(50), peer_id(51), peer_id(52), peer_id(53));
        let direct: Multiaddr = format!("/ip4/127.0.0.1/tcp/7423/p2p/{target}")
            .parse()
            .unwrap();
        let plan = vec![direct.clone(), circuit(r1, target), circuit(r2, target)];
        let failed = |t: PeerId| {
            DialError::Transport(vec![
                (circuit(r1, t), relay_answered(ConnectError::NoReservation)),
                (
                    circuit(r2, t),
                    relay_answered(ConnectError::ResourceLimitExceeded),
                ),
            ])
        };
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), auto_config(Vec::new()));
        let (host, _incoming, _handle) = seed.build(0, false).unwrap();
        host.classify_dial_failure(Some(target), &failed(target));
        let t = Instant::now();
        assert!(is_demoted(&target, &r1, t) && !is_demoted(&target, &r2, t));
        assert_eq!(
            host.order_dial(target, plan.clone()),
            vec![direct.clone(), circuit(r2, target), circuit(r1, target)],
            "last, never left out"
        );
        let elsewhere = vec![circuit(r1, other), circuit(r2, other)];
        assert_eq!(host.order_dial(other, elsewhere.clone()), elsewhere);
        // Ten minutes later it is in its place again.
        let s = Duration::from_secs(1);
        assert!(is_demoted(&target, &r1, t + DEMOTE_FOR - s));
        assert!(!is_demoted(&target, &r1, t + DEMOTE_FOR));
        assert_eq!(
            order_dial(
                plan.clone(),
                |_| false,
                |r| is_demoted(&target, r, t + DEMOTE_FOR),
                |_| 0
            ),
            plan
        );

        // The Phase 1 host (no automatic relay choice): nothing noted, the
        // plan's order kept.
        let phase1_dir = tempfile::tempdir().unwrap();
        let (seed, _commands) = test_seed(&gate, phase1_dir.path(), loopback_config(Vec::new()));
        let (phase1, _incoming, _handle) = seed.build(0, false).unwrap();
        phase1.classify_dial_failure(Some(other), &failed(other));
        assert!(!is_demoted(&other, &r1, Instant::now()));
        assert_eq!(phase1.order_dial(target, plan.clone()), plan);
    }

    /// Learning connectivity (P6.15): a contact dial's circuits go by their
    /// relay's learned term, highest first, in the places circuits hold;
    /// each relay's first address before any fallback; a demoted circuit
    /// stays last whatever its term. The Phase 1 host ranks too, and with
    /// learning off every order is today's.
    #[tokio::test]
    async fn circuits_through_a_well_scored_relay_go_first_demoted_stay_last() {
        use crate::learning::{circuits, inbound, TestService};
        use raven_swarm::libp2p::relay::outbound::hop::ConnectError;
        let target = peer(170);
        let target_id: PeerId = target.parse().unwrap();
        let [r1, r2, r3, r4] = [171u8, 172, 173, 174].map(peer_id);
        let via = |text: String| p2p_route::parse_via(&text).unwrap();
        let tcp = |r: PeerId, n: u8| via(format!("/ip4/198.51.100.{n}/tcp/4001/p2p/{r}"));
        let quic = |r: PeerId, n: u8| via(format!("/ip4/198.51.100.{n}/udp/4001/quic-v1/p2p/{r}"));
        let set = P2pDialSet {
            peer_id: target.clone(),
            direct: vec![
                via(format!("/ip4/203.0.113.9/tcp/4001/p2p/{target}")),
                via(format!("/ip4/203.0.113.10/tcp/4001/p2p/{target}")),
            ],
            relays: vec![
                tcp(r1, 1),
                tcp(r2, 2),
                tcp(r3, 3),
                tcp(r4, 4),
                quic(r1, 1),
                quic(r3, 3),
            ],
        };
        let by_peer = P2pDialTarget::Peer {
            peer_id: target.clone(),
        };
        let plan = dial_addrs(&by_peer, Some(&set), &DialForms::default()).unwrap();
        let circuit_of =
            |v: ViaAddr| -> Multiaddr { p2p_route::circuit_addr(&v, &target).parse().unwrap() };
        let (d1, d2) = (plan[0].clone(), plan[2].clone());
        let (r1a, r2a, r3a, r4a) = (
            circuit_of(tcp(r1, 1)),
            circuit_of(tcp(r2, 2)),
            circuit_of(tcp(r3, 3)),
            circuit_of(tcp(r4, 4)),
        );
        let (r1b, r3b) = (circuit_of(quic(r1, 1)), circuit_of(quic(r3, 3)));
        assert_eq!(
            plan,
            [
                d1.clone(),
                r1a.clone(),
                d2.clone(),
                r2a.clone(),
                r3a.clone(),
                r4a.clone(),
                r1b.clone(),
                r3b.clone()
            ],
            "the plan order (at most 8)"
        );

        // R2 said the target holds no reservation there: demoted.
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), auto_config(Vec::new()));
        let (host, _incoming, _handle) = seed.build(0, false).unwrap();
        host.classify_dial_failure(
            Some(target_id),
            &DialError::Transport(vec![(
                r2a.clone(),
                relay_answered(ConnectError::NoReservation),
            )]),
        );
        let phase1_dir = tempfile::tempdir().unwrap();
        let (seed, _commands) = test_seed(&gate, phase1_dir.path(), loopback_config(Vec::new()));
        let (phase1, _incoming, _handle) = seed.build(0, false).unwrap();

        // Learning on: R2 best (but demoted), R3 good, R1 unknown, R4 bad.
        let learn_dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(learn_dir.path(), Some("home"));
        t.set_now(1_800_000_000_000);
        let contact = [0xB0; 32];
        for (relay, links) in [(r2, 20), (r3, 6)] {
            for _ in 0..links {
                inbound(&contact, OutboxCarrier::P2p, Some(relay.to_bytes()), false);
            }
        }
        for _ in 0..3 {
            circuits(vec![(r4.to_bytes(), CircuitOutcome::NoAnswer)]);
        }
        t.drain();
        let terms = learned_terms(&[r1, r2, r3, r4]);
        let term = |r| term_of(&terms, &r);
        assert!(term(r2) > term(r3) && term(r3) > 0 && term(r1) == 0 && term(r4) < 0);
        assert_eq!(
            host.order_dial(target_id, plan.clone()),
            [
                d1.clone(),
                r3a.clone(),
                d2.clone(),
                r1a.clone(),
                r4a.clone(),
                r3b.clone(),
                r1b.clone(),
                r2a.clone()
            ],
            "by term, first addresses before fallbacks, the demoted one last"
        );
        assert_eq!(
            phase1.order_dial(target_id, plan.clone()),
            [
                d1.clone(),
                r2a.clone(),
                d2.clone(),
                r3a.clone(),
                r1a.clone(),
                r4a.clone(),
                r3b.clone(),
                r1b.clone()
            ],
            "nothing demoted on the Phase 1 host"
        );
        assert_eq!(dial_relays(&by_peer, Some(&set)), [r2, r3, r1, r4]);

        // Learning off: today's orders.
        drop(t);
        assert!(learned_terms(&[r1, r2, r3, r4]).is_empty());
        assert_eq!(
            host.order_dial(target_id, plan.clone()),
            [d1, r1a, d2, r3a, r4a, r1b, r3b, r2a]
        );
        assert_eq!(phase1.order_dial(target_id, plan.clone()), plan);
        assert_eq!(dial_relays(&by_peer, Some(&set)), [r1, r2, r3, r4]);
    }

    /// Review learning-7: a relayed link that broke inside is noted against
    /// the relay it went through, not every relay of the contact's dial set.
    /// With R1 breaking links and R2 good, three breaks put R2's circuit
    /// first (blaming both would lower them alike and keep R1 first, so R2
    /// would never be tried). The set's relay stands in only when the
    /// connection table named none and the set has just one.
    #[test]
    fn a_broken_relayed_link_is_noted_against_the_relay_it_went_through() {
        use crate::learning::{relay_security_signal, TestService};
        let target = peer(175);
        let [r1, r2] = [176u8, 177].map(peer_id);
        assert_eq!(broken_link_relays(&[r1], &[r1, r2]), [r1.to_bytes()]);
        assert_eq!(broken_link_relays(&[r2], &[r1]), [r2.to_bytes()]);
        assert_eq!(broken_link_relays(&[], &[r2]), [r2.to_bytes()]);
        assert!(broken_link_relays(&[], &[r1, r2]).is_empty());
        let learn_dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(learn_dir.path(), Some("home"));
        for _ in 0..3 {
            for relay in broken_link_relays(&[r1], &[r1, r2]) {
                relay_security_signal(&relay);
            }
        }
        t.drain();
        let terms = learned_terms(&[r1, r2]);
        assert!(term_of(&terms, &r1) < term_of(&terms, &r2), "{terms:?}");
        let circuit = |r: PeerId, n: u8| -> Multiaddr {
            format!("/ip4/198.51.100.{n}/tcp/4001/p2p/{r}/p2p-circuit/p2p/{target}")
                .parse()
                .unwrap()
        };
        let mut addrs = vec![circuit(r1, 1), circuit(r2, 2)];
        rank_circuits(&mut addrs, |r| term_of(&terms, r));
        assert_eq!(addrs, [circuit(r2, 2), circuit(r1, 1)], "R2 first");
    }

    /// Learning connectivity (P6.15): with learning off (the gate shut, or
    /// the user's switch off: nothing loaded) no relay has a term, whatever
    /// was posted; on, the same evidence gives one.
    #[test]
    fn terms_are_empty_when_off() {
        use crate::learning::{inbound, relay_terms, TestService};
        let relay = peer_id(165);
        let (key, text) = (relay.to_bytes(), relay.to_string());
        let contact = [0xB0; 32];
        for gate in [false, true] {
            let _off = TestService::install(gate);
            for _ in 0..6 {
                inbound(&contact, OutboxCarrier::P2p, Some(key.clone()), false);
            }
            assert!(relay_terms(std::slice::from_ref(&key)).is_empty());
            assert!(learned_terms(&[relay]).is_empty());
            assert!(learned_terms_of([text.as_str()]).is_empty());
        }
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("home"));
        t.set_now(1_800_000_000_000);
        // On, but no evidence yet: a term of 0, which is none.
        assert_eq!(relay_terms(std::slice::from_ref(&key)), [0]);
        assert!(learned_terms(&[relay]).is_empty());
        for _ in 0..6 {
            inbound(&contact, OutboxCarrier::P2p, Some(key.clone()), false);
        }
        t.drain();
        assert_eq!(relay_terms(std::slice::from_ref(&key)), [90]);
        assert_eq!(learned_terms(&[relay]), [(relay, 90)]);
        assert_eq!(
            learned_terms_of([text.as_str(), "not a PeerId"]),
            [(text.clone(), 90)]
        );
    }

    /// Learning connectivity (P6.15): automatic relay choice adds the
    /// learned term to an offered relay's score. Of three offered relays
    /// alike but for their keys, the two slots take the two the tie-break
    /// puts first; with learning on, a good term brings in the third.
    #[tokio::test]
    async fn relay_choice_adds_the_learned_term_to_its_score() {
        use crate::learning::{inbound, TestService};
        let gate = HostGate::open(true).unwrap();
        let offers = vec![
            offered(&nowhere(175), 1),
            offered(&nowhere(176), 2),
            offered(&nowhere(177), 3),
        ];
        let picked =
            |host: &Host| -> HashSet<PeerId> { host.slots.iter().map(|s| s.peer).collect() };
        let dir = tempfile::tempdir().unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), auto_config(Vec::new()));
        let (mut today, _incoming, _handle) = seed.build(0, false).unwrap();
        offer(&mut today, offers.clone());
        let held = picked(&today);
        assert_eq!(held.len(), 2);
        let left: PeerId = [175u8, 176, 177]
            .map(peer_id)
            .into_iter()
            .find(|p| !held.contains(p))
            .unwrap();

        let learn_dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(learn_dir.path(), Some("home"));
        t.set_now(1_800_000_000_000);
        for _ in 0..6 {
            inbound(
                &[0xB0; 32],
                OutboxCarrier::P2p,
                Some(left.to_bytes()),
                false,
            );
        }
        t.drain();
        let dir = tempfile::tempdir().unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), auto_config(Vec::new()));
        let (mut learned, _incoming, _handle) = seed.build(0, false).unwrap();
        offer(&mut learned, offers);
        assert!(
            picked(&learned).contains(&left),
            "the learned relay fills a slot"
        );
        assert_eq!(picked(&learned).len(), 2);
    }

    /// Phase 6b R8 (design A, step P6.28; the responses gate): a relay put
    /// last for its lost receipts or broken links goes last in every dial,
    /// on a host with automatic relay choice and on the Phase 1 host, for
    /// its hour only; with no other relay it is still dialled (never left
    /// out); with the gate shut nothing moves.
    #[tokio::test]
    async fn a_relay_put_last_for_security_goes_last_but_is_never_left_out() {
        let (target, bad, good) = (peer_id(231), peer_id(232), peer_id(233));
        let plan = vec![circuit(bad, target), circuit(good, target)];
        let gate = HostGate::open(true).unwrap();
        let dirs = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (seed, _commands) = test_seed(&gate, dirs.0.path(), auto_config(Vec::new()));
        let (auto, _incoming, _handle) = seed.build(0, false).unwrap();
        let (seed, _commands2) = test_seed(&gate, dirs.1.path(), loopback_config(Vec::new()));
        let (phase1, _incoming2, _handle2) = seed.build(0, false).unwrap();
        let now = crate::now_ms();
        crate::security::relay_last_for_test(&bad.to_bytes(), now + 60 * 60 * 1000);
        {
            use raven_core::security_gate::{set_lab_for_this_thread, SecGate};
            set_lab_for_this_thread(SecGate::Responses, Some(false));
            assert_eq!(auto.order_dial(target, plan.clone()), plan, "gate shut");
            set_lab_for_this_thread(SecGate::Responses, None);
        }
        let Some(_capture) = crate::security::tests::Capture::start() else {
            return;
        };
        let Some(_responding) = crate::security::tests::Responding::start() else {
            return;
        };
        let last = vec![circuit(good, target), circuit(bad, target)];
        assert_eq!(auto.order_dial(target, plan.clone()), last);
        assert_eq!(phase1.order_dial(target, plan.clone()), last);
        let alone = vec![circuit(bad, target)];
        assert_eq!(phase1.order_dial(target, alone.clone()), alone);
        assert!(!crate::security::relay_demoted(&good.to_bytes()));
    }

    /// A relayed connection remembers the relay it goes through (Phase 6b
    /// R8: whose receipts a relayed link's are), each relay once, until it
    /// closes; a direct connection names none.
    #[test]
    fn a_peers_relayed_connections_list_each_relay_once_until_they_close() {
        let (bob, r1, r2) = (peer_id(234), peer_id(235), peer_id(236));
        let id = ConnectionId::new_unchecked;
        let mut table = ConnTable::default();
        table.relayed_through(id(1), r1);
        assert!(table.relays_to(&bob).is_empty(), "not established yet");
        table.established(id(1), bob, true, true);
        table.relayed_through(id(1), r1);
        table.established(id(2), bob, true, true);
        table.relayed_through(id(2), r1);
        table.established(id(3), bob, false, true);
        assert_eq!(table.relays_to(&bob), vec![r1]);
        table.established(id(4), bob, true, true);
        table.relayed_through(id(4), r2);
        let mut both = table.relays_to(&bob);
        both.sort();
        let mut want = vec![r1, r2];
        want.sort();
        assert_eq!(both, want);
        for n in [1, 2, 4] {
            table.closed(id(n));
        }
        assert!(table.relays_to(&bob).is_empty());
        assert!(table.via.is_empty());
    }

    /// A relay a dial admitted with its contact closes our connection at
    /// once: it does not count this node a member. Its circuits are left out
    /// of every dial, to any contact, until `not_member_until`: 10 min for a
    /// contact's relay or an offered one (its operator may admit this node
    /// any moment), 6 h only for a relay set by hand that nobody offers; the
    /// contact's own quick close is no relay's.
    #[tokio::test]
    async fn a_non_member_quick_close_skips_the_relay_for_every_target_until_not_member_until() {
        let (t1, t2, relay, other) = (peer_id(54), peer_id(55), peer_id(56), peer_id(57));
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), auto_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        let now = std::time::Instant::now();
        host.gate
            .admit_dial(
                t1,
                PeerClass::CONTACT,
                &[relay],
                now,
                now + Duration::from_secs(600),
            )
            .unwrap();
        host.relay_turned_us_away(t1, Instant::now());
        assert!(!host
            .auto
            .mem
            .is_not_member(&t1.to_string(), crate::now_ms()));
        host.relay_turned_us_away(relay, Instant::now());
        let now_ms = crate::now_ms();
        let until = host.auto.mem.memo(&relay.to_string()).not_member_until_ms;
        assert!(
            until <= now_ms + relay_select::NOT_MEMBER_OFFERED_MS
                && until + 60_000 > now_ms + relay_select::NOT_MEMBER_OFFERED_MS,
            "a contact's relay: 10 min, never 6 h"
        );
        assert!(host.auto.urgent);
        for target in [t1, t2] {
            assert_eq!(
                host.order_dial(target, vec![circuit(relay, target), circuit(other, target)]),
                vec![circuit(other, target)],
                "skipped for every target"
            );
        }
        let plan = vec![circuit(relay, t2), circuit(other, t2)];
        let mem = &host.auto.mem;
        let at = |ms: u64| {
            order_dial(
                plan.clone(),
                |r| mem.is_not_member(&r.to_string(), ms),
                |_| false,
                |_| 0,
            )
        };
        assert_eq!(at(until - 1), vec![circuit(other, t2)]);
        assert_eq!(at(until), plan, "until not_member_until");

        // An offered relay in a slot, turned us away before any reservation:
        // 10 min.
        let offered_relay = peer_id(58);
        offer(&mut host, vec![offered(&nowhere(58), 1)]);
        assert_eq!(host.slots[0].peer, offered_relay);
        host.relay_turned_us_away(offered_relay, Instant::now());
        let until = host
            .auto
            .mem
            .memo(&offered_relay.to_string())
            .not_member_until_ms;
        assert!(until <= crate::now_ms() + relay_select::NOT_MEMBER_OFFERED_MS);
        assert!(until > now_ms);

        // A relay set by hand that nobody offers: 6 h.
        let (manual, _) = relay_pair(53);
        let (seed, _commands) = test_seed(&gate, dir.path(), auto_config(vias(&[&manual])));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        let manual_relay = peer_id(53);
        assert_eq!(host.slots[0].peer, manual_relay);
        host.relay_turned_us_away(manual_relay, Instant::now());
        let now_ms = crate::now_ms();
        let until = host
            .auto
            .mem
            .memo(&manual_relay.to_string())
            .not_member_until_ms;
        assert!(
            until <= now_ms + relay_select::NOT_MEMBER_OTHER_MS
                && until + 60_000 > now_ms + relay_select::NOT_MEMBER_OTHER_MS,
            "set by hand, not offered: 6 h"
        );
    }

    /// The gate's load says when a contact last named each contact relay: a
    /// card's relay as of the contact book's last change.
    #[test]
    fn a_gate_load_says_when_a_card_last_named_each_relay() {
        let dir = tempfile::tempdir().unwrap();
        let before = crate::now_ms().saturating_sub(2_000);
        let rows = vec![gate_row(
            &hex::encode([7u8; 32]),
            true,
            peer(60),
            vec![gate_via(61, "11.0.2.7")],
        )];
        std::fs::write(
            dir.path().join("contacts.json"),
            serde_json::to_string(&rows).unwrap(),
        )
        .unwrap();
        let loaded = load_gate(dir.path(), &[]);
        let at = loaded.named_at.get(&peer_id(61)).copied();
        assert!(
            at.is_some_and(|at| at >= before && at <= crate::now_ms()),
            "{at:?}"
        );
        assert_eq!(loaded.named_at.get(&peer_id(60)), None, "the contact");
    }

    /// A contact's relay that turned this node away is tried again as soon
    /// as a contact names it again (a new card or route hints snapshot, its
    /// operator may have admitted this node since) or a circuit through it
    /// comes up; a name from before the refusal changes nothing, and a
    /// relay this node reserves on keeps its mark.
    #[tokio::test]
    async fn a_relay_named_again_or_carrying_a_circuit_is_tried_again() {
        let (target, relay, slot_relay) = (peer_id(54), peer_id(56), peer_id(58));
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (seed, _commands) = test_seed(&gate, dir.path(), auto_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        let now = std::time::Instant::now();
        host.gate
            .admit_dial(
                target,
                PeerClass::CONTACT,
                &[relay],
                now,
                now + Duration::from_secs(600),
            )
            .unwrap();
        host.relay_turned_us_away(relay, Instant::now());
        let key = relay.to_string();
        let noted = host.auto.mem.memo(&key).not_member_at_ms;
        assert!(host.auto.mem.is_not_member(&key, crate::now_ms()));
        let skipped = vec![circuit(slot_relay, target)];
        let plan = vec![circuit(relay, target), circuit(slot_relay, target)];
        assert_eq!(host.order_dial(target, plan.clone()), skipped);
        let load = |named: &[(PeerId, u64)]| GateLoad {
            stamp: ([None; 5], 0),
            read_at: std::time::Instant::now(),
            files: HashMap::from([
                (target, PeerClass::CONTACT),
                (relay, PeerClass::CONTACT_RELAY),
            ]),
            unreadable: false,
            named_at: named.iter().copied().collect(),
            policy_relays: None,
            policy_proxy: None,
            nat_remote: Vec::new(),
            rotation: Some(RotationFacts::default()),
            punch_targets: Vec::new(),
        };
        // Named before the refusal: still skipped.
        host.gate_loaded(load(&[(relay, noted)]));
        assert!(host.auto.mem.is_not_member(&key, crate::now_ms()));
        // A fresh snapshot (or card) names it: tried again.
        host.auto.urgent = false;
        host.gate_loaded(load(&[(relay, noted + 1)]));
        assert!(!host.auto.mem.is_not_member(&key, crate::now_ms()));
        assert!(host.auto.urgent, "written at once");
        assert_eq!(host.order_dial(target, plan.clone()), plan);
        // A circuit through it ends a refusal too.
        host.relay_turned_us_away(relay, Instant::now());
        assert!(host.auto.mem.is_not_member(&key, crate::now_ms()));
        use raven_swarm::libp2p::core::transport::PortUse;
        use raven_swarm::libp2p::core::Endpoint;
        host.on_event(SwarmEvent::ConnectionEstablished {
            peer_id: target,
            connection_id: ConnectionId::new_unchecked(9),
            endpoint: ConnectedPoint::Dialer {
                address: circuit(relay, target),
                role_override: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            },
            num_established: std::num::NonZeroU32::new(1).unwrap(),
            concurrent_dial_errors: None,
            established_in: Duration::from_millis(5),
        });
        assert!(!host.auto.mem.is_not_member(&key, crate::now_ms()));
        // A relay this node reserves on keeps its mark.
        offer(&mut host, vec![offered(&nowhere(58), 1)]);
        assert_eq!(host.slots[0].peer, slot_relay);
        host.relay_turned_us_away(slot_relay, Instant::now());
        let slot_key = slot_relay.to_string();
        let at = host.auto.mem.memo(&slot_key).not_member_at_ms;
        host.offers_loaded(None);
        host.gate_loaded(load(&[(slot_relay, at + 1)]));
        assert!(host.auto.mem.is_not_member(&slot_key, crate::now_ms()));
    }

    /// Status lists the current slots: the relays set by hand first (every
    /// address of each), then the ones picked from offers, in slot order,
    /// with each row's source and operator; `relays_configured` counts the
    /// relays set by hand. Automatic choice turned off by node policy drops
    /// the picked ones.
    #[tokio::test]
    async fn status_relays_lists_current_slots_in_order() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (main, fallback) = relay_pair(59);
        let config = auto_config(vias(&[&main, &fallback]));
        let decided = service_info(ServiceP2p::Configured {
            config: &config,
            source: "node_policy.json",
        });
        assert!(decided.relay_auto);
        assert_eq!(decided.relays, vec![main.clone(), fallback.clone()]);
        let (seed, _commands) = test_seed(&gate, dir.path(), config);
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        let (a, b) = (nowhere(60), nowhere(61));
        offer(&mut host, vec![offered(&a, 1), offered(&b, 2)]);
        assert_eq!(host.slots.len(), 2, "one relay set by hand, one picked");
        let picked = host.slots[1].texts[0].clone();
        let status = host.status_info();
        assert_eq!(
            status.relays,
            vec![main.clone(), fallback.clone(), picked.clone()]
        );
        assert_eq!(status.relays_configured, 1);
        let sources: Vec<&str> = status
            .relay_health
            .iter()
            .map(|h| h.source.as_str())
            .collect();
        assert_eq!(sources, ["manual", "offer"]);
        assert!(status.relay_health[0].operator_pub_hex.is_empty());
        let operator = if picked == a { 1 } else { 2 };
        assert_eq!(
            status.relay_health[1].operator_pub_hex,
            hex::encode([operator; 32])
        );
        assert!(status.relay_auto);
        assert_eq!(status.relay_standby, 1, "the other offer");

        // The picked relay's offer is withdrawn: the other one takes the
        // slot, after the relay set by hand.
        let other = if picked == a { b.clone() } else { a.clone() };
        offer(&mut host, vec![offered(&other, 3 - operator)]);
        let status = host.status_info();
        assert_eq!(
            status.relays,
            vec![main.clone(), fallback.clone(), other.clone()]
        );
        assert_eq!(status.relay_standby, 0);

        // Node policy turns automatic choice off: only the relays set by hand.
        let stamp = gate_stamp(dir.path());
        host.offers_loaded(Some(OffersLoad {
            stamp,
            candidates: vec![offered(&other, 3 - operator)],
            policy_on: false,
        }));
        let status = host.status_info();
        assert_eq!(status.relays, vec![main, fallback]);
        assert!(!status.relay_auto);
        assert_eq!(status.relay_health.len(), 1);
    }

    /// What one failed dial learned, per relay: a relay's own dial failure
    /// marks every dial planned through it (NoAnswer); a later specific
    /// answer replaces NoAnswer and nothing else; a relay never heard from
    /// is NoAnswer; a relay left out as a non-member answered Refused; a
    /// failure where no transport ran says nothing (interrupted).
    #[test]
    fn in_flight_absorbs_target_and_relay_failures() {
        use raven_core::reach_diag::{AddrOutcome as A, CircuitOutcome as C};
        let (bob, carol, dave) = (peer_id(60), peer_id(61), peer_id(62));
        let (r1, r2, r3, r4, r5) = (
            peer_id(63),
            peer_id(64),
            peer_id(65),
            peer_id(66),
            peer_id(67),
        );
        let circuit = |relay, outcome| Failed::Circuit { relay, outcome };
        let mut facts = DialFacts::default();
        facts.begin(bob, InFlight::new(vec![r1, r2], &[]));
        facts.begin(carol, InFlight::new(vec![r1], &[]));
        facts.begin(dave, InFlight::new(vec![r3, r4], &[r4]));
        // r1's own dial failed: both dials through it heard nothing.
        facts.failed(r1, Vec::new(), false);
        assert_eq!(facts.by_peer[&carol].per_relay(), vec![(r1, C::NoAnswer)]);
        facts.failed(
            bob,
            vec![
                circuit(r1, C::NotOnRelay),
                Failed::Direct(A::Refused),
                circuit(r2, C::NoAnswer),
            ],
            false,
        );
        // A second answer does not replace a specific one; a circuit through
        // a relay the dial did not plan comes last.
        facts.failed(bob, vec![circuit(r1, C::Busy), circuit(r5, C::Busy)], false);
        let b = &facts.by_peer[&bob];
        assert_eq!(
            b.per_relay(),
            vec![(r1, C::NotOnRelay), (r2, C::NoAnswer), (r5, C::Busy)]
        );
        assert_eq!(b.direct, vec![A::Refused]);
        assert!(!b.interrupted);
        assert_eq!(
            facts.by_peer[&dave].per_relay(),
            vec![(r3, C::NoAnswer), (r4, C::Refused)]
        );
        // No transport ran (a gate denied it): no reason.
        facts.failed(dave, dial_failures(&DialError::Aborted), true);
        assert!(facts.by_peer[&dave].interrupted);

        // Into the summary: slot numbers for our own relays only, the
        // closed-at-once answers as `closed` says.
        let f = facts.take(&bob).unwrap();
        let summary = dial_summary(f, &[None, Some(r2)], |p| *p == r1, true);
        assert_eq!(
            summary,
            DialSummary {
                interrupted: false,
                target_closed_at_once: true,
                circuits: vec![
                    (None, C::NotOnRelay, true),
                    (Some(2), C::NoAnswer, false),
                    (None, C::Busy, false),
                ],
                direct: vec![A::Refused],
                slots_answering: Vec::new(),
            }
        );
        // Slot numbers follow `Status.relay_health` (current slots).
        let st = P2pStatusInfo {
            relay_health: vec![
                RelayHealth {
                    relay: format!("/ip4/11.0.0.1/tcp/7423/p2p/{r2}"),
                    ..RelayHealth::default()
                },
                RelayHealth {
                    relay: "/dns4/relay.example/tcp/443".into(),
                    ..RelayHealth::default()
                },
                RelayHealth {
                    relay: format!("/ip4/11.0.0.2/udp/7423/quic-v1/p2p/{r1}"),
                    ..RelayHealth::default()
                },
            ],
            ..P2pStatusInfo::default()
        };
        assert_eq!(slot_relays(&st), vec![Some(r2), None, Some(r1)]);
    }

    /// The facts are bounded (past MAX_DIAL_FACTS they start over), a
    /// re-home or a host stop interrupts every dial (their answers get no
    /// reason), and a dial that connected leaves nothing.
    #[test]
    fn facts_are_bounded_and_interrupted_by_a_rehome() {
        let mut facts = DialFacts::default();
        for _ in 0..MAX_DIAL_FACTS {
            facts.begin(PeerId::random(), InFlight::new(Vec::new(), &[]));
        }
        facts.bound();
        assert_eq!(facts.by_peer.len(), MAX_DIAL_FACTS);
        facts.begin(PeerId::random(), InFlight::new(Vec::new(), &[]));
        facts.bound();
        assert!(facts.by_peer.is_empty(), "past the bound: all go");
        let (bob, carol) = (peer_id(70), peer_id(71));
        facts.begin(bob, InFlight::new(vec![peer_id(72)], &[]));
        facts.begin(carol, InFlight::new(Vec::new(), &[]));
        facts.bound();
        assert_eq!(facts.by_peer.len(), 2, "within the bound: kept");
        facts.interrupt_all();
        let f = facts.take(&bob).unwrap();
        assert!(f.interrupted);
        assert_eq!(
            diagnose(
                &dial_summary(f, &[], |_| false, false),
                &MyFacts::default(),
                &TheirFacts::default()
            ),
            None
        );
        assert_eq!(facts.take(&bob), None, "read once");
        facts.forget(&carol);
        assert_eq!(facts.take(&carol), None);
    }

    /// A connect that joins the dial in flight to the same peer
    /// (DialPeerConditionFalse) keeps that dial's facts, and both waiting
    /// connects read them; a new dial replaces what an earlier one left.
    #[test]
    fn a_joined_dial_keeps_the_first_dials_facts() {
        use raven_core::reach_diag::CircuitOutcome as C;
        let (bob, r1, r2) = (peer_id(73), peer_id(74), peer_id(75));
        let mut facts = DialFacts::default();
        facts.begin(bob, InFlight::new(vec![r1], &[]));
        facts.failed(
            bob,
            vec![Failed::Circuit {
                relay: r1,
                outcome: C::NotOnRelay,
            }],
            false,
        );
        facts.join(bob, InFlight::new(vec![r2], &[]));
        let first = facts.take(&bob).expect("the first waiter");
        assert_eq!(first.relays, vec![r1]);
        assert_eq!(first.per_relay(), vec![(r1, C::NotOnRelay)]);
        let joined = facts.take(&bob).expect("the joined one");
        assert_eq!(
            (joined.relays, joined.circuits),
            (first.relays, first.circuits)
        );
        assert_eq!(facts.take(&bob), None, "both read");
        // Nothing in flight: a join starts the facts.
        facts.join(bob, InFlight::new(vec![r2], &[]));
        assert_eq!(facts.by_peer[&bob].relays, vec![r2]);
        // A new dial replaces left-over facts (a dial nobody read).
        facts.failed(
            bob,
            vec![Failed::Circuit {
                relay: r2,
                outcome: C::Busy,
            }],
            false,
        );
        facts.begin(bob, InFlight::new(vec![r2], &[]));
        assert_eq!(
            facts.take(&bob).unwrap().per_relay(),
            vec![(r2, C::NoAnswer)]
        );
    }

    /// Behind NAT: no global listen address and no UPnP mapping. A circuit
    /// address does not count; a global IPv6 one does; so does `mapped`.
    #[test]
    fn me_facts_behind_nat_from_listen_addrs_and_upnp() {
        let relay = peer(76);
        let lan = vec![
            "/ip4/192.168.1.5/tcp/7423".to_string(),
            "/ip4/127.0.0.1/udp/7423/quic-v1".to_string(),
            "/ip6/fe80::1/tcp/7423".to_string(),
            format!("/ip4/11.0.0.9/tcp/7423/p2p/{relay}/p2p-circuit"),
            "not an address".to_string(),
        ];
        assert!(behind_nat(&lan, "off"));
        assert!(behind_nat(&lan, "failed"));
        assert!(behind_nat(&[], "unset"));
        assert!(!behind_nat(&lan, "mapped 7423"));
        let mut v6 = lan.clone();
        v6.push("/ip6/2a00:11::7/udp/7423/quic-v1".into());
        assert!(!behind_nat(&v6, "off"));
        let mut v4 = lan.clone();
        v4.push("/ip4/11.0.0.7/tcp/7423".into());
        assert!(!behind_nat(&v4, "off"));

        let st = P2pStatusInfo {
            reach: "relayed".into(),
            listen_addrs: lan,
            upnp: "off".into(),
            ..P2pStatusInfo::default()
        };
        assert_eq!(
            my_facts(&st, true, false),
            MyFacts {
                class: ReachClass::Relayed,
                behind_nat: true,
                hides_ip_from_them: true,
                no_default_route: false,
            }
        );
        // No host (an empty Status): unknown, behind NAT.
        let none = my_facts(&P2pStatusInfo::default(), false, true);
        assert_eq!(none.class, ReachClass::Unknown);
        assert!(none.behind_nat && none.no_default_route);
    }

    /// What this node knows of the contact: card only without route hints;
    /// an expired hint (a tombstone) is stale but not card-only; last heard
    /// is the newer of a link or receipt and the last route hints.
    #[test]
    fn their_facts_card_only_and_expired_hint() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x7A; 32];
        let now = crate::now_ms();
        assert_eq!(
            their_facts(dir.path(), &key, now),
            TheirFacts {
                from_card_only: true,
                hint_expired: false,
                heard_s: None,
            }
        );
        let row = |received: u64, expires: u64| {
            serde_json::json!({
                "pub_hex": hex::encode(key),
                "generation": 3,
                "received_at_ms": received,
                "expires_at_ms": expires,
                "via": "p2p",
                "peer_id": peer(77),
            })
        };
        const H: u64 = 3_600_000;
        write_learned(dir.path(), &[row(now - 2 * H, now + H)]);
        let live = their_facts(dir.path(), &key, now);
        assert!(!live.from_card_only && !live.hint_expired);
        assert_eq!(live.heard_s, Some(2 * 3600));
        // Expired an hour ago: a tombstone.
        write_learned(dir.path(), &[row(now - 3 * H, now - H)]);
        let stale = their_facts(dir.path(), &key, now);
        assert!(!stale.from_card_only && stale.hint_expired);
        assert_eq!(stale.heard_s, Some(3 * 3600));
        // The contact reached us since: the newer one counts.
        crate::delivery_paths::heard(&key);
        let heard = their_facts(dir.path(), &key, now);
        assert!(heard.heard_s.is_some_and(|s| s < 60), "{heard:?}");
        assert!(heard.hint_expired, "the hints stay expired");
        // Heard, no hints at all.
        let other = [0x7B; 32];
        crate::delivery_paths::heard(&other);
        let only = their_facts(dir.path(), &other, now);
        assert!(only.from_card_only && only.heard_s.is_some_and(|s| s < 60));
    }

    /// The reason block goes after the error and Phase 1's refusal hint, and
    /// never changes how the outbox files the error: NOT_REACHABLE, for
    /// every reason and flag. ash finds the same reason back.
    #[test]
    fn the_reason_block_keeps_dial_error_code_not_reachable() {
        let errors = [
            P2P_UNREACHABLE.to_string(),
            format!("{P2P_UNREACHABLE} (connect timed out after 20s)"),
            format!("{P2P_UNREACHABLE} (no address known)"),
            format!("{P2P_UNREACHABLE}; {}", refusal_hint(true, false).unwrap()),
            format!("{P2P_UNREACHABLE}; {}", refusal_hint(false, true).unwrap()),
        ];
        for why in Why::ALL {
            for (relay, heard_s, stale, from_card) in [
                (None, None, false, false),
                (Some(1), Some(3 * 3600), true, true),
                (Some(2), Some(45), false, true),
            ] {
                let d = Diag {
                    why,
                    me: Some(ReachClass::Unreachable),
                    relay,
                    heard_s,
                    stale,
                    from_card,
                    asof_s: None,
                };
                for e in &errors {
                    let text = with_reason(e.clone(), &d);
                    assert!(text.starts_with(&format!("{e}; reach: why=")), "{text}");
                    assert_eq!(
                        crate::outbox::dial_error_code(&text),
                        crate::outbox::code::NOT_REACHABLE,
                        "{text}"
                    );
                    assert_eq!(Diag::find(&text).map(|f| f.why), Some(why), "{text}");
                }
            }
        }
    }

    /// The log line names the reason only: no PeerId, address or key.
    #[test]
    fn the_unreachable_log_line_names_no_peer() {
        for why in Why::ALL {
            let line = unreachable_line(why);
            assert_eq!(line, format!("a contact is unreachable ({})", why.token()));
            assert!(!line.contains("12D3KooW") && !line.contains('/'), "{line}");
            assert!(
                !line
                    .split(|c: char| !c.is_ascii_hexdigit())
                    .any(|w| w.len() >= 16),
                "{line}"
            );
        }
    }

    /// F9: with no default route the reason is `no_route`, before any relay
    /// reason the dial's answers would give; with one, the relays' answers
    /// decide. A connect that failed for another reason, or was interrupted,
    /// gets nothing; a dial nobody gathered facts for neither.
    #[tokio::test]
    async fn no_default_route_gives_no_route_before_any_relay_reason() {
        let _lock = crate::netwatch::egress_test_lock().await;
        let dir = tempfile::tempdir().unwrap();
        let (target, r1, r2) = (PeerId::random(), PeerId::random(), PeerId::random());
        let contact = [0x7C; 32];
        let dial = || {
            with_facts(|f| {
                f.begin(target, InFlight::new(vec![r1, r2], &[]));
                f.failed(r1, Vec::new(), false);
            });
        };
        let explain =
            |e: String| explain_unreachable(dir.path(), &contact, target, e, Instant::now());

        crate::netwatch::set_last_egress(Some(false));
        dial();
        let text = explain(P2P_UNREACHABLE.into()).await;
        let d = Diag::find(&text).expect("a reason");
        assert_eq!(d.why, Why::NoRoute, "{text}");
        assert_eq!(d.relay, None);
        assert!(text.starts_with(&format!("{P2P_UNREACHABLE}; reach: why=no_route")));
        assert_eq!(
            crate::delivery_paths::why_for(&contact).map(|(d, _)| d.why),
            Some(Why::NoRoute)
        );

        crate::netwatch::set_last_egress(Some(true));
        dial();
        let text = explain(P2P_UNREACHABLE.into()).await;
        assert_eq!(
            Diag::find(&text).map(|d| d.why),
            Some(Why::RelayAsleep),
            "{text}"
        );

        // Not a network fact: nothing added (and the facts are read).
        for e in [CHECK_AGAIN.to_string(), P2P_NOT_RUNNING.to_string()] {
            dial();
            assert_eq!(explain(e.clone()).await, e);
        }
        assert_eq!(explain(P2P_UNREACHABLE.into()).await, P2P_UNREACHABLE);
        dial();
        with_facts(DialFacts::interrupt_all);
        let changed = format!("{P2P_UNREACHABLE} (the network changed during the dial)");
        assert_eq!(explain(changed.clone()).await, changed);
        crate::netwatch::set_last_egress(None);
    }

    /// End to end in the host: a circuit dial to a contact that holds no
    /// reservation on the relay fails, its facts say what the relay answered
    /// (NO_RESERVATION), and both waiting connects (one joined the dial in
    /// flight) get `contact_offline`.
    #[tokio::test]
    async fn a_failed_circuit_dial_is_explained_by_the_relays_answer() {
        let _lock = crate::netwatch::egress_test_lock().await;
        crate::netwatch::set_last_egress(Some(true));
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (relay, via) = lab_relay(&gate, dir.path(), 44, true).await;
        let (relay_peer, _task) = run_relay(relay);
        let (seed, _commands) = test_seed(&gate, dir.path(), loopback_config(Vec::new()));
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        let target = PeerId::random();
        let circuit: Multiaddr = format!("{via}/p2p-circuit/p2p/{target}").parse().unwrap();
        let since = Instant::now();
        let mut answers = Vec::new();
        for _ in 0..2 {
            let (reply, answer) = oneshot::channel();
            host.connect(
                target,
                PeerClass::CONTACT,
                vec![relay_peer],
                vec![circuit.clone()],
                std::time::Instant::now(),
                reply,
            );
            answers.push(answer);
        }
        assert_eq!(with_facts(|f| f.by_peer[&target].waiters), 2, "one joined");
        assert!(
            drive(&mut host, 20, |h| !h.pending.contains_key(&target)).await,
            "the dial is answered"
        );
        for (i, answer) in answers.into_iter().enumerate() {
            let e = answer.await.unwrap().unwrap_err();
            assert!(e.starts_with(P2P_UNREACHABLE), "{e}");
            let contact = [0x7D + i as u8; 32];
            let text = explain_unreachable(dir.path(), &contact, target, e, since).await;
            assert_eq!(
                Diag::find(&text).map(|d| d.why),
                Some(Why::ContactOffline),
                "{text}"
            );
        }
        crate::netwatch::set_last_egress(None);
    }

    // ── Phase 4 PeerId rotation (P4.28) ───────────────────────────────────

    /// The rotation state table: the gate closed or the setting off is
    /// `off` (the fixed key); before the first switch a contact that cannot
    /// follow is `waiting`; all capable is `on` in the clock's epoch, and
    /// stays on once switched even when a contact cannot follow (review
    /// D-1); a rollback holds the previous key while the clock is in the
    /// refused epoch and before its retry, then rotation is `on` again.
    /// What status says and route hints announce follows.
    #[test]
    fn rotation_state_table() {
        let facts = |live: bool, setting: bool, waiting_on: u32| RotationFacts {
            live,
            setting,
            waiting_on,
            ready_ms: Some(0),
        };
        let (len, now) = (30u64, 1_000_000u64);
        // Ready long ago (epoch 0).
        let of = |f: RotationFacts, p: Option<Postponement>, clock: u64| {
            RotationState::of(f, Some(0), p, clock, len, now)
        };
        // Ready only now: the fixed key until the next boundary, the
        // coming keys announced; ready in an earlier epoch: on.
        assert_eq!(
            RotationState::of(facts(true, true, 0), None, None, 9, len, now),
            RotationState::Starting {
                epoch: 9,
                len_s: len
            }
        );
        let starting = RotationState::of(facts(true, true, 0), Some(9), None, 9, len, now);
        assert_eq!(
            (starting.word(), starting.key_epoch(), starting.announced()),
            ("starting", None, None)
        );
        assert_eq!(
            RotationState::of(facts(true, true, 0), Some(8), None, 9, len, now).key_epoch(),
            Some(9)
        );
        assert_eq!(of(facts(false, true, 0), None, 9), RotationState::Off);
        assert_eq!(of(facts(true, false, 0), None, 9), RotationState::Off);
        // Before the first switch a contact that cannot follow holds it
        // back; after it, rotation stays on (contacts that hold an epoch
        // card admit no other PeerId).
        for ready in [None, Some(9)] {
            assert_eq!(
                RotationState::of(facts(true, true, 1), ready, None, 9, len, now),
                RotationState::Waiting { missing: 1 }
            );
        }
        for waiting_on in [1, 3, u32::MAX] {
            assert_eq!(
                of(facts(true, true, waiting_on), None, 9),
                RotationState::On {
                    epoch: 9,
                    len_s: len
                },
                "{waiting_on}"
            );
        }
        assert_eq!(
            of(facts(true, true, 0), None, 9),
            RotationState::On {
                epoch: 9,
                len_s: len
            }
        );
        let back = Postponement {
            epoch: Some(8),
            refused: 9,
            retry_at: now + 60,
        };
        let postponed = of(facts(true, true, 0), Some(back), 9);
        assert_eq!(
            postponed,
            RotationState::Postponed {
                epoch: Some(8),
                refused: 9,
                retry_at: now + 60,
                len_s: len
            }
        );
        // The next epoch, or the retry: on again. The setting off wins over
        // a rollback; a contact that cannot follow does not (switched).
        assert_eq!(
            of(facts(true, true, 0), Some(back), 10).key_epoch(),
            Some(10)
        );
        let late = Postponement {
            retry_at: now,
            ..back
        };
        assert_eq!(of(facts(true, true, 0), Some(late), 9).key_epoch(), Some(9));
        assert_eq!(of(facts(true, true, 2), Some(back), 9), postponed);
        assert_eq!(of(facts(true, false, 0), Some(back), 9), RotationState::Off);
        // Keys, announcements and words.
        assert_eq!(RotationState::Off.key_epoch(), None);
        assert_eq!(RotationState::Waiting { missing: 1 }.key_epoch(), None);
        assert_eq!(postponed.key_epoch(), Some(8));
        assert_eq!(postponed.announced(), Some((8, true)));
        assert_eq!(
            of(facts(true, true, 0), None, 9).announced(),
            Some((9, false))
        );
        assert_eq!(RotationState::Waiting { missing: 1 }.announced(), None);
        let to_fixed = RotationState::Postponed {
            epoch: None,
            refused: 9,
            retry_at: now,
            len_s: len,
        };
        assert_eq!((to_fixed.key_epoch(), to_fixed.announced()), (None, None));
        assert_eq!(
            [
                RotationState::Off,
                RotationState::Waiting { missing: 1 },
                RotationState::On { epoch: 1, len_s: 1 },
                to_fixed
            ]
            .map(RotationState::word),
            ["off", "waiting", "on", "postponed"]
        );
        // The next change: the epoch boundary, or a retry that comes first.
        let id = Identity::from_seed(&[0x61; 32]);
        let boundary = raven_core::peer_rotation::next_boundary_unix(&id, now, len);
        assert_eq!(
            of(facts(true, true, 0), None, 9).change_at(&id, now),
            Some(boundary)
        );
        assert_eq!(postponed.change_at(&id, now), Some(boundary.min(now + 60)));
        assert_eq!(
            RotationState::Waiting { missing: 1 }.change_at(&id, now),
            None
        );
        // With the gate closed nothing is read and nothing rotates.
        if !raven_core::peer_rotation_live_enabled() {
            let dir = tempfile::tempdir().unwrap();
            assert_eq!(rotation_facts(dir.path(), None), RotationFacts::default());
        }
    }

    /// Review D-1: once the key made its first switch, a pinned contact
    /// that cannot follow (added after it, or whose schedule a new card
    /// forgot) keeps rotation on: `ready` stays on disk and the host keeps
    /// the clock epoch's key, since contacts holding its epoch card admit
    /// no other PeerId. Before the first switch it still waits (and `ready`
    /// is cleared), as the spec's `waiting` row says.
    #[test]
    fn a_contact_that_cannot_follow_keeps_a_switched_rotation_on() {
        use raven_core::peer_rotation::{load_own_rotation, save_own_rotation, OwnRotation};
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let id = Identity::from_seed(&[0x63; 32]);
        let len = raven_core::peer_rotation::epoch_len_s();
        let now_ms = crate::now_ms();
        let now_unix = now_ms / 1000;
        let clock = raven_core::peer_rotation::epoch_at(&id, now_unix, len);
        raven_core::node_policy::save_policy(
            dd,
            &raven_core::NodePolicy {
                peer_rotation: Some(true),
                ..raven_core::NodePolicy::default()
            },
        )
        .unwrap();
        // A pinned contact with a p2p route and no schedule.
        std::fs::write(
            dd.join("contacts.json"),
            serde_json::to_string(&vec![gate_row(
                &hex::encode([0x64; 32]),
                true,
                peer(3),
                vec![gate_via(2, "203.0.113.9")],
            )])
            .unwrap(),
        )
        .unwrap();
        let state = |facts: RotationFacts| {
            RotationState::of(
                facts,
                ready_epoch(&id, facts, len),
                None,
                clock,
                len,
                now_unix,
            )
        };

        // Ready three epochs ago: switched.
        let long_ago = now_ms.saturating_sub(3 * len * 1000);
        save_own_rotation(
            dd,
            OwnRotation {
                ready_ms: Some(long_ago),
            },
        )
        .unwrap();
        let facts = rotation_facts_with(dd, Some(&id), true, now_ms);
        assert_eq!((facts.waiting_on, facts.ready_ms), (1, Some(long_ago)));
        assert_eq!(load_own_rotation(dd).unwrap().ready_ms, Some(long_ago));
        assert_eq!(
            state(facts),
            RotationState::On {
                epoch: clock,
                len_s: len
            }
        );

        // Ready only now: not switched, so the contact holds it back.
        save_own_rotation(
            dd,
            OwnRotation {
                ready_ms: Some(now_ms),
            },
        )
        .unwrap();
        let facts = rotation_facts_with(dd, Some(&id), true, now_ms);
        assert_eq!((facts.waiting_on, facts.ready_ms), (1, None));
        assert_eq!(load_own_rotation(dd).unwrap().ready_ms, None);
        assert_eq!(state(facts), RotationState::Waiting { missing: 1 });
    }

    /// Review D-1: a gate load that panicked leaves the rotation facts held
    /// before (it read nothing about them), so a rotating host keeps its
    /// epoch key instead of going back to the fixed one.
    #[tokio::test]
    async fn a_failed_gate_load_keeps_the_rotation_facts() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let id = Arc::new(Identity::from_seed(&[14; 32]));
        let facts = RotationFacts {
            live: true,
            setting: true,
            waiting_on: 0,
            ready_ms: Some(0),
        };
        let (seed, commands) = test_seed(&gate, dir.path(), loopback_config(Vec::new()));
        let mut seed = HostSeed {
            identity: Some(Arc::clone(&id)),
            ..seed
        };
        seed.rotation = Mutex::new(RotationMemory {
            facts,
            ..RotationMemory::default()
        });
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        drop(commands);
        let key = host.rotation.key_epoch();
        assert!(key.is_some());
        host.gate_loaded(failed_gate_load(std::time::Instant::now()));
        assert_eq!(host.rotation_facts, facts);
        assert_eq!(host.rotation.key_epoch(), key);
    }

    /// Review D-3: a rollback to the fixed key announces like `starting`:
    /// the refused epoch's schedule without `rotating` (and never
    /// `postponed`), so contacts keep admitting the PeerId the retry uses
    /// while they still dial the fixed one first.
    #[tokio::test]
    async fn a_rollback_to_the_fixed_key_keeps_announcing_the_entries() {
        use raven_core::peer_rotation as pr;
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let id = Arc::new(Identity::from_seed(&[15; 32]));
        let fixed = p2p_route::local_peer_id(&id);
        let len = pr::epoch_len_s();
        let (seed, commands) = test_seed(&gate, dir.path(), loopback_config(Vec::new()));
        let mut seed = HostSeed {
            identity: Some(Arc::clone(&id)),
            ..seed
        };
        seed.rotation = Mutex::new(RotationMemory {
            facts: RotationFacts {
                live: true,
                setting: true,
                waiting_on: 0,
                ready_ms: Some(0),
            },
            ..RotationMemory::default()
        });
        let (mut host, _incoming, _handle) = seed.build(0, false).unwrap();
        drop(commands);
        let now_ms = crate::now_ms();
        let refused = pr::epoch_at(&id, now_ms / 1000, len);
        host.rotation = RotationState::Postponed {
            epoch: None,
            refused,
            retry_at: now_ms / 1000 + ROTATE_RETRY_S,
            len_s: len,
        };
        let announced = host.announced().unwrap();
        assert!(announced.capable() && !announced.rotating() && !announced.postponed());
        assert_eq!(announced.active_epoch, refused);
        assert_eq!(announced.entries.len(), pr::MAX_SCHEDULE);
        // A contact holding the fixed card admits the refused epoch's
        // PeerId and still dials the fixed one first.
        let held = pr::ContactSchedule::from_announced(&announced, now_ms);
        let refused_peer = pr::epoch_peer_id(&id, refused);
        let admitted = pr::admitted_peer_ids(Some(&fixed), None, Some(&held), now_ms / 1000);
        assert!(admitted.contains(&refused_peer), "{admitted:?}");
        let dialled = pr::dial_peer_ids(&fixed, None, Some(&held), now_ms / 1000);
        assert_eq!(dialled.first(), Some(&fixed));
        // A rollback to an epoch key still says `postponed`.
        host.rotation = RotationState::Postponed {
            epoch: Some(refused.saturating_sub(1)),
            refused,
            retry_at: now_ms / 1000 + ROTATE_RETRY_S,
            len_s: len,
        };
        let back = host.announced().unwrap();
        assert!(back.rotating() && back.postponed());
    }

    /// Phase 4: the second PeerId of a rotating contact is tried only after
    /// the first was unreachable. Its dial check names the clock's epoch
    /// PeerId first and the other side of the boundary second, each with
    /// its own circuits through the contact's relay; a refusal, success or
    /// any other error never moves on. With rotation not live the card's
    /// PeerId is dialled, as in Phase 1.
    #[tokio::test]
    async fn dial_tries_second_peer_id_only_after_unreachable() {
        use raven_core::peer_rotation as pr;
        let dir = tempfile::tempdir().unwrap();
        let bob = Identity::from_seed(&[0x62; 32]);
        let bob_key = bob.public_key_bytes();
        let (len, active) = (600u64, 50u64);
        let epoch = |e: u64| pr::epoch_peer_id(&bob, e);
        std::fs::write(
            dir.path().join("contacts.json"),
            serde_json::to_string(&vec![gate_row(
                &hex::encode(bob_key),
                true,
                epoch(active),
                vec![gate_via(2, "203.0.113.9")],
            )])
            .unwrap(),
        )
        .unwrap();
        let announced = pr::announced_schedule(&bob, Some((active, false)), len);
        let schedule = pr::ContactSchedule::from_announced(&announced, crate::now_ms());
        pr::save_schedule(dir.path(), &hex::encode(bob_key), &schedule).unwrap();
        let target = p2p_route::parse_p2p_dial(&p2p_route::peer_route(&epoch(active))).unwrap();
        let circuit = |p: &str| format!("{}/p2p-circuit/p2p/{p}", gate_via(2, "203.0.113.9"));

        let plan = dial_plan_with(dir.path(), &bob_key, &[], true).unwrap();
        assert_eq!(plan.rotated.len(), 2);
        let mut check = check_from_plan(plan, &target, &[], std::time::Instant::now())
            .await
            .unwrap();
        let first: PeerId = epoch(active).parse().unwrap();
        let second: PeerId = epoch(active + 1).parse().unwrap();
        assert_eq!(check.peer, Some(first));
        assert_eq!(texts(&check.addrs), vec![circuit(&epoch(active))]);
        assert_eq!(check.relays, vec![peer_id(2)]);
        // Only after "unreachable".
        assert!(try_second_peer_id(&Err(format!("{P2P_UNREACHABLE} (x)"))));
        for other in [
            Ok(()),
            Err(CHECK_AGAIN.to_string()),
            Err(P2P_HIDDEN_DIRECT.to_string()),
            Err("p2p dial: invalid PeerId".to_string()),
        ] {
            assert!(!try_second_peer_id(&other), "{other:?}");
        }
        // A recheck that wants another PeerId than the second keeps it.
        assert_eq!(check.take_second(Some(first)), None);
        assert!(check.second.is_some());
        assert_eq!(check.take_second(None), Some(second));
        assert_eq!(check.peer, Some(second));
        assert_eq!(texts(&check.addrs), vec![circuit(&epoch(active + 1))]);
        assert_eq!(check.relays, vec![peer_id(2)]);
        assert_eq!(check.take_second(None), None, "at most two");

        // Rotation not live, or an explicit circuit: the target's PeerId.
        let plan = dial_plan_with(dir.path(), &bob_key, &[], false).unwrap();
        assert!(plan.rotated.is_empty());
        let check = check_from_plan(plan, &target, &[], std::time::Instant::now())
            .await
            .unwrap();
        assert_eq!((check.peer, check.second.is_none()), (None, true));
        assert_eq!(texts(&check.addrs), vec![circuit(&epoch(active))]);
        let explicit = p2p_route::parse_p2p_dial(&circuit(&epoch(active))).unwrap();
        let plan = dial_plan_with(dir.path(), &bob_key, &[], true).unwrap();
        let check = check_from_plan(plan, &explicit, &[], std::time::Instant::now())
            .await
            .unwrap();
        assert_eq!(check.peer, None);
    }

    /// Phase 4: status names the PeerId of the key in use: the clock
    /// epoch's while rotation is on, the fixed one while it waits on a
    /// contact (or without an identity); IPC `rotation` says which, and the
    /// announced schedule carries the epoch's entries only while on.
    #[tokio::test]
    async fn status_peer_id_is_the_active_key() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let id = Arc::new(Identity::from_seed(&[13; 32]));
        let fixed = p2p_route::local_peer_id(&id);
        let len = raven_core::peer_rotation::epoch_len_s();
        let build = |facts: RotationFacts| {
            let (seed, commands) = test_seed(&gate, dir.path(), loopback_config(Vec::new()));
            let mut seed = HostSeed {
                identity: Some(Arc::clone(&id)),
                ..seed
            };
            seed.rotation = Mutex::new(RotationMemory {
                facts,
                ..RotationMemory::default()
            });
            let (host, _incoming, _handle) = seed.build(0, false).unwrap();
            drop(commands);
            host
        };
        let on = build(RotationFacts {
            live: true,
            setting: true,
            waiting_on: 0,
            ready_ms: Some(0),
        });
        let now_unix = crate::now_ms() / 1000;
        let clock = raven_core::peer_rotation::epoch_at(&id, now_unix, len);
        let info = on.status_info();
        let at_build = on.rotation.key_epoch().unwrap();
        assert!(
            at_build == clock || at_build + 1 == clock,
            "{at_build} {clock}"
        );
        assert_eq!(
            info.peer_id,
            raven_core::peer_rotation::epoch_peer_id(&id, at_build)
        );
        assert_ne!(info.peer_id, fixed);
        let r = info.rotation.unwrap();
        assert_eq!((r.state.as_str(), r.epoch), ("on", Some(at_build)));
        assert!(r.next_change_s.is_some_and(|s| s <= len));
        let announced = on.announced().unwrap();
        assert!(announced.rotating() && announced.active_epoch == at_build);
        assert_eq!(
            announced.entries.len(),
            raven_core::peer_rotation::MAX_SCHEDULE
        );
        assert_eq!(on.own_p2p().peer_id, info.peer_id);

        let waiting = build(RotationFacts {
            live: true,
            setting: true,
            waiting_on: 1,
            ready_ms: None,
        });
        let info = waiting.status_info();
        assert_eq!(info.peer_id, fixed);
        let r = info.rotation.unwrap();
        assert_eq!(
            (r.state.as_str(), r.waiting_on, r.epoch),
            ("waiting", 1, None)
        );
        let announced = waiting.announced().unwrap();
        assert!(announced.capable() && !announced.rotating() && announced.entries.is_empty());

        // Ready only now: the fixed key, the coming keys announced without
        // `rotating`.
        let starting = build(RotationFacts {
            live: true,
            setting: true,
            waiting_on: 0,
            ready_ms: Some(crate::now_ms()),
        });
        let info = starting.status_info();
        assert_eq!(info.peer_id, fixed);
        let r = info.rotation.unwrap();
        assert_eq!((r.state.as_str(), r.epoch), ("starting", None));
        assert!(r.next_change_s.is_some());
        let announced = starting.announced().unwrap();
        assert!(announced.capable() && !announced.rotating());
        assert_eq!(
            announced.entries.len(),
            raven_core::peer_rotation::MAX_SCHEDULE
        );

        // The gate closed (facts read nothing): the fixed key, no row.
        let off = build(RotationFacts::default());
        let info = off.status_info();
        assert_eq!(
            (info.peer_id.as_str(), info.rotation),
            (fixed.as_str(), None)
        );
        assert_eq!(off.announced(), None);
    }

    /// Phase 4: when every relay held before a rotation turns the new ID
    /// away (its peer gate closes the connection at once), the rotation is
    /// postponed: the previous key until the next epoch or a retry. A relay
    /// that accepts a reservation ends the watch.
    #[tokio::test]
    async fn every_relay_refusing_the_new_id_postpones_the_rotation() {
        let gate = HostGate::open(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let watch = |relay: PeerId| RotationWatch {
            prev: Some(4),
            epoch: 5,
            waiting: HashSet::from([relay]),
            refused: 0,
            until: Instant::now() + ROTATE_CHECK,
        };
        // Not a member: refused.
        let (relay, via) = lab_relay(&gate, dir.path(), 46, false).await;
        let (p, _task) = run_relay(relay);
        let config = loopback_config(vec![p2p_route::parse_via(&via).unwrap()]);
        let (seed, _commands) = test_seed(&gate, dir.path(), config);
        let (mut host, _incoming, _handle) = build_reserving(&seed, 0, false);
        host.rotation_watch = Some(watch(p));
        assert!(
            drive(&mut host, 20, |h| h.postponed.is_some()).await,
            "the refusal postpones"
        );
        let back = host.postponed.unwrap();
        assert_eq!((back.epoch, back.refused), (Some(4), 5));
        assert!(host.rotation_watch.is_none());
        let facts = RotationFacts {
            live: true,
            setting: true,
            waiting_on: 0,
            ready_ms: Some(0),
        };
        let now = crate::now_ms() / 1000;
        assert!(back.retry_at >= now + ROTATE_RETRY_S - 5);
        assert_eq!(
            RotationState::of(facts, Some(0), host.postponed, 5, 30, now).key_epoch(),
            Some(4)
        );

        // A member: the reservation is accepted, the rotation stands.
        let dir = tempfile::tempdir().unwrap();
        let (relay, via) = lab_relay(&gate, dir.path(), 47, true).await;
        let (p, _task) = run_relay(relay);
        let config = loopback_config(vec![p2p_route::parse_via(&via).unwrap()]);
        let (seed, _commands) = test_seed(&gate, dir.path(), config);
        let (mut host, _incoming, _handle) = build_reserving(&seed, 0, false);
        host.rotation_watch = Some(watch(p));
        assert!(
            drive(&mut host, 20, |h| h.rotation_watch.is_none()).await,
            "the acceptance ends the watch"
        );
        assert_eq!(host.postponed, None);
    }
}
