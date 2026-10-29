//! The P3 libp2p host (transports design 2026-10 §3.2-§3.6): the substrate a
//! Raven endpoint uses to reach NAT'd contacts, and the relay role.
//!
//! - **Endpoint** ([`build_endpoint_swarm`]): TCP + QUIC (IPv4 and IPv6),
//!   Circuit Relay v2 client, DCUtR, AutoNAT v2 client (one per relay
//!   slot), Identify ([`IDENTIFY_PROTOCOL`]), Ping, `connection_limits`,
//!   per-IP limits, optional router port mapping ([`crate::portmap`]:
//!   UPnP-IGD; NAT-PMP, PCP and IPv6 pinholes only behind
//!   PORT_MAP/V6_PINHOLE), and `libp2p-stream` for [`RAVEN_LINK_PROTOCOL`]. With
//!   `service --relay` it also carries the relay server ([`RelayLimits`],
//!   [`RelayGuard`]); its relay PeerId is then the user's own PeerId. The
//!   peer gate ([`crate::gate`]) is its third behaviour: everyone who is not
//!   a verified contact, a relay of this host or an allow-listed relay
//!   member is refused before any protocol handler exists. DCUtR offers
//!   Raven's candidates ([`crate::candidates`]: router mappings, own global
//!   IPv6, raw relay-observed addresses; global only, at most 8, QUIC
//!   first), not libp2p's own list.
//! - **Relay** ([`build_relay_swarm`], `raven-node relay`): relay server,
//!   optional AutoNAT v2 server, Identify, Ping, the limits and optional
//!   UPnP-IGD (off for the dedicated relay); no Raven link protocol, no
//!   Kademlia, no mailbox. Its peer gate admits the peers on its allow-list
//!   (anyone with `--open`) and nobody else.
//! - **WSS** (feature `wss`; RWS1, `protocol/RAVEN_WSS_TRANSPORT_V1.md`):
//!   libp2p's "other" transport, never `SwarmBuilder::with_websocket` (it
//!   would bring libp2p-dns). The endpoint dials relays at
//!   `…/tcp/<p>/tls[/sni/<n>]/ws` with [`EndpointConfig`]'s client side
//!   (straight or through an HTTPS proxy), as the dialer only, and never
//!   listens on WSS. A relay built with a server side serves a two-protocol
//!   port (`…/tls/ws` and raw libp2p on one TCP port) and has no WSS client,
//!   so its AutoNAT dial-backs never go out over WSS. A relay names only the
//!   raw address of such a listener ([`RelayAdvertiser`], RWS1 §2.2).
//!   [`EndpointConfig::restricted`] is the process's restricted-network flag
//!   (RWS1 §9): while it is set, DCUtR offers no candidates and neither
//!   AutoNAT client hears of one.
//!
//! libp2p is a substrate only: a PeerId authenticates a libp2p key, never a
//! Raven identity. raven-node runs the Raven Noise link (prologue
//! `raven/p2p-link/v1` + the RIH1 identity bind) inside every
//! `/raven/link/1.0.0` stream, so a relay sees only
//! libp2p-Noise(Raven-Noise(...)).
//!
//! Nothing here is policy-free on its own: every builder takes a [`HostGate`],
//! which the caller can only obtain with its runtime gate open
//! (`raven_core::p2p_live_enabled()` in raven-node). No relay, bootstrap or
//! AutoNAT server address is compiled in.

use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU8, NonZeroUsize};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use libp2p::connection_limits::{self, ConnectionLimits};
#[cfg(feature = "wss")]
use libp2p::core::transport::OptionalTransport;
use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{
    dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{
    autonat, identify, noise, ping, relay, tcp, upnp, yamux, Multiaddr, PeerId, StreamProtocol,
    Swarm, SwarmBuilder,
};

use crate::gate::{
    AddrRule, GateHandle, HolePunch, OnlyPeer, PeerClass, PeerGate, Scoped, IDENTIFY_SCOPE,
};
use crate::ip_limits::{IpLimitConfig, IpLimits};

/// The Raven link protocol: one Raven Noise link per stream.
pub const RAVEN_LINK_PROTOCOL: StreamProtocol = StreamProtocol::new("/raven/link/1.0.0");
/// Identify protocol name of every Raven libp2p host.
pub const IDENTIFY_PROTOCOL: &str = "/raven/identify/1.0.0";
/// Generic agent string: no version or OS detail for a scanner.
pub const AGENT_VERSION: &str = "raven";

/// Proof that the caller's runtime gate is open. The builders take one, so a
/// host cannot be built (and therefore cannot listen, dial, reserve or
/// advertise) while the gate is closed.
#[derive(Debug)]
pub struct HostGate(());

impl HostGate {
    /// `live`: the caller's runtime gate (raven-node:
    /// `raven_core::p2p_live_enabled()`).
    pub fn open(live: bool) -> Result<Self, HostError> {
        if live {
            Ok(Self(()))
        } else {
            Err(HostError::new(
                "the libp2p host is held: its runtime gate is closed",
            ))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostError {
    message: &'static str,
}

impl HostError {
    const fn new(message: &'static str) -> Self {
        Self { message }
    }

    pub const fn message(self) -> &'static str {
        self.message
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl Error for HostError {}

// ── Relay limits (transports design §3.5) ───────────────────────────────────

/// Relay server limits. Every value is finite and checked against a hard
/// maximum ([`RelayLimits::validate`]); zero is refused.
///
/// libp2p 0.57 knob names (the design's "(verify)" guesses, checked against
/// libp2p-relay 0.22): `max_reservations`, `max_reservations_per_peer`,
/// `reservation_duration`, `max_circuits`, `max_circuits_per_peer`,
/// `max_circuit_duration`, `max_circuit_bytes`, and the rate-limiter lists
/// `reservation_rate_limiters` / `circuit_src_rate_limiters`. libp2p has
/// **no** per-IP reservation cap and **no** allow-list: both are
/// [`RelayGuard`], which also does both per-source rates itself, keyed like
/// every other per-source limit (an IPv4 address or an IPv6 /64; libp2p's own
/// `*_per_ip` limiters key on the exact address, a /128 for IPv6, would spend
/// a source's tokens on requests the allow-list then refuses, and cannot
/// exempt loopback). Circuits are served only between peers on the
/// allow-list (anyone with `--open`): the circuit limiter is asked with the
/// source only (behaviour.rs:682-747), so a destination consents by
/// reserving on its circle's relay. The per-peer checks deny only when a
/// peer already holds *more* than `max_reservations_per_peer` or
/// `max_circuits_per_peer`, so [`Self::relay_config`] passes `per_peer - 1`
/// to get exactly `per_peer` (behaviour.rs:559-568, 694-695). A peer's
/// circuits count both ways: the ones it opens and the ones to it
/// (behaviour.rs:946-950).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    pub max_reservations: usize,
    pub max_reservations_per_peer: usize,
    pub max_reservations_per_ip: usize,
    pub reservation_duration: Duration,
    pub max_circuits: usize,
    pub max_circuits_per_peer: usize,
    pub max_circuit_duration: Duration,
    pub max_circuit_bytes: u64,
    /// Reservation requests per source IP per minute.
    pub reservation_rate_per_ip_per_min: u32,
    /// Circuit requests per source (IPv4 address or IPv6 /64) per minute.
    pub circuit_rate_per_ip_per_min: u32,
    pub max_established: u32,
    pub max_established_per_ip: u32,
    /// Exempt loopback from the per-IP caps (same-host tools and harnesses
    /// share one address by construction), as [`IpLimitConfig`] does.
    pub exempt_loopback: bool,
}

/// Hard maxima of [`RelayLimits`].
pub const RELAY_HARD_MAX: RelayLimits = RelayLimits {
    max_reservations: 1024,
    max_reservations_per_peer: 2,
    max_reservations_per_ip: 16,
    reservation_duration: Duration::from_secs(2 * 60 * 60),
    max_circuits: 256,
    max_circuits_per_peer: 8,
    max_circuit_duration: Duration::from_secs(30 * 60),
    max_circuit_bytes: 16 << 20,
    reservation_rate_per_ip_per_min: 60,
    circuit_rate_per_ip_per_min: 600,
    max_established: 1024,
    max_established_per_ip: 32,
    exempt_loopback: true,
};

impl RelayLimits {
    /// Friends-only (allow-list) defaults. Two reservations per peer: after a
    /// restart (or a network change) a friend's new connection reserves at
    /// once while the relay still holds the old, silent one until it times
    /// out.
    pub const fn friends() -> Self {
        Self {
            max_reservations: 128,
            max_reservations_per_peer: 2,
            max_reservations_per_ip: 4,
            reservation_duration: Duration::from_secs(30 * 60),
            max_circuits: 64,
            max_circuits_per_peer: 4,
            max_circuit_duration: Duration::from_secs(5 * 60),
            max_circuit_bytes: 2 << 20,
            reservation_rate_per_ip_per_min: 4,
            circuit_rate_per_ip_per_min: 30,
            max_established: 256,
            max_established_per_ip: 8,
            exempt_loopback: true,
        }
    }

    /// `--open` (anyone may reserve): the stricter defaults.
    pub const fn open() -> Self {
        Self {
            max_reservations: 32,
            max_circuit_bytes: 512 << 10,
            ..Self::friends()
        }
    }

    pub fn validate(&self) -> Result<(), HostError> {
        let h = RELAY_HARD_MAX;
        let counts = [
            (self.max_reservations as u64, h.max_reservations as u64),
            (
                self.max_reservations_per_peer as u64,
                h.max_reservations_per_peer as u64,
            ),
            (
                self.max_reservations_per_ip as u64,
                h.max_reservations_per_ip as u64,
            ),
            (self.max_circuits as u64, h.max_circuits as u64),
            (
                self.max_circuits_per_peer as u64,
                h.max_circuits_per_peer as u64,
            ),
            (self.max_circuit_bytes, h.max_circuit_bytes),
            (
                self.reservation_rate_per_ip_per_min as u64,
                h.reservation_rate_per_ip_per_min as u64,
            ),
            (
                self.circuit_rate_per_ip_per_min as u64,
                h.circuit_rate_per_ip_per_min as u64,
            ),
            (self.max_established as u64, h.max_established as u64),
            (
                self.max_established_per_ip as u64,
                h.max_established_per_ip as u64,
            ),
        ];
        if counts.iter().any(|(v, _)| *v == 0) {
            return Err(HostError::new("relay limits must be nonzero"));
        }
        if counts.iter().any(|(v, max)| v > max) {
            return Err(HostError::new("relay limit exceeds its hard maximum"));
        }
        let durations = [
            (self.reservation_duration, h.reservation_duration),
            (self.max_circuit_duration, h.max_circuit_duration),
        ];
        if durations.iter().any(|(d, _)| d.is_zero()) {
            return Err(HostError::new("relay durations must be nonzero"));
        }
        if durations.iter().any(|(d, max)| d > max) {
            return Err(HostError::new("relay duration exceeds its hard maximum"));
        }
        if self.max_reservations_per_peer > self.max_reservations
            || self.max_reservations_per_ip > self.max_reservations
            || self.max_circuits_per_peer > self.max_circuits
            || self.max_established_per_ip > self.max_established
            || self.max_established <= OUTBOUND_RESERVE
        {
            return Err(HostError::new(
                "per-peer or per-IP relay limit exceeds its total",
            ));
        }
        Ok(())
    }

    /// The libp2p relay configuration, with [`RelayGuard`] as the only
    /// reservation and circuit limiter. libp2p asks it last (after its own
    /// total and per-peer caps), so its "yes" means the request is accepted.
    pub fn relay_config(&self, guard: &RelayGuard) -> relay::Config {
        relay::Config {
            max_reservations: self.max_reservations,
            // libp2p denies only above this count (see the type docs).
            max_reservations_per_peer: self.max_reservations_per_peer.saturating_sub(1),
            reservation_duration: self.reservation_duration,
            reservation_rate_limiters: vec![guard.limiter()],
            max_circuits: self.max_circuits,
            // The same "more than" (behaviour.rs:694-695).
            max_circuits_per_peer: self.max_circuits_per_peer.saturating_sub(1),
            max_circuit_duration: self.max_circuit_duration,
            max_circuit_bytes: self.max_circuit_bytes,
            circuit_src_rate_limiters: vec![guard.circuit_limiter()],
        }
    }

    fn connection_limits(&self) -> connection_limits::Behaviour {
        connection_limits::Behaviour::new(
            ConnectionLimits::default()
                .with_max_pending_incoming(Some(64))
                .with_max_pending_outgoing(Some(64))
                .with_max_established(Some(self.max_established))
                // Strangers cannot take the slots our own dials need.
                .with_max_established_incoming(Some(
                    self.max_established.saturating_sub(OUTBOUND_RESERVE).max(1),
                ))
                .with_max_established_per_peer(Some(4)),
        )
    }

    fn ip_limits(&self) -> IpLimits {
        IpLimits::new(IpLimitConfig {
            max_pending_per_ip: 4,
            max_established_per_ip: self.max_established_per_ip,
            exempt_loopback: self.exempt_loopback,
        })
    }
}

/// Established connections every host keeps for its own dials (its relays,
/// contacts, AutoNAT dial-backs): inbound connections can never take them,
/// so a flood of strangers cannot lock a node out of its own relay.
pub const OUTBOUND_RESERVE: u32 = 16;

// ── Relay admission: allow-list and per-IP reservations ─────────────────────

/// Who may reserve on this relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowPolicy {
    /// `--open`: anyone (stricter limits).
    Open,
    /// The allow-list (`relay_allow.json`), the default. Empty = nobody.
    Peers(HashSet<PeerId>),
    /// The allow-list could not be read: nobody (fail closed).
    Unreadable,
}

impl AllowPolicy {
    /// May `peer` use the relay (connect, reserve, open circuits)?
    pub fn admits(&self, peer: &PeerId) -> bool {
        match self {
            Self::Open => true,
            Self::Peers(peers) => peers.contains(peer),
            Self::Unreadable => false,
        }
    }
}

/// Source bucket of a reservation: the exact IPv4 address or the IPv6 /64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IpBucket {
    V4([u8; 4]),
    V6([u8; 8]),
}

fn ip_bucket(addr: &Multiaddr, exempt_loopback: bool) -> Option<IpBucket> {
    let ip = addr.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })?;
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        ip => ip,
    };
    if exempt_loopback && ip.is_loopback() {
        return None;
    }
    Some(match ip {
        IpAddr::V4(v4) => IpBucket::V4(v4.octets()),
        IpAddr::V6(v6) => {
            let o = v6.octets();
            IpBucket::V6([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]])
        }
    })
}

/// Why a reservation was refused (counts only, never the peer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationRefusal {
    NotAllowed,
    AllowListUnreadable,
    PerIpCap,
    /// More new reservations from this source than its per-minute rate.
    PerIpRate,
}

/// Sources one rate table remembers at most. Beyond it the oldest source is
/// forgotten first, which only hands that source a fresh, full bucket.
pub const MAX_RATE_SOURCES: usize = 4096;

/// Token buckets per source (an IPv4 address or an IPv6 /64), bounded by
/// [`MAX_RATE_SOURCES`]. Admission is O(1); [`Self::prune`] (on the host's
/// timer, not on every request) drops the buckets that are full again.
#[derive(Debug)]
struct SourceRate {
    per_min: u32,
    buckets: HashMap<IpBucket, (f64, Instant)>,
    /// Insertion order of `buckets` (exactly its keys).
    order: VecDeque<IpBucket>,
}

impl SourceRate {
    fn new(per_min: u32) -> Self {
        Self {
            per_min,
            buckets: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn cap(&self) -> f64 {
        f64::from(self.per_min.max(1))
    }

    fn level(&self, tokens: f64, last: Instant, now: Instant) -> f64 {
        let cap = self.cap();
        (tokens + now.saturating_duration_since(last).as_secs_f64() * cap / 60.0).min(cap)
    }

    /// Take one token for `source`; `false` when its bucket is empty.
    fn try_take(&mut self, source: IpBucket, now: Instant) -> bool {
        let current = match self.buckets.get(&source) {
            Some(&(tokens, last)) => self.level(tokens, last, now),
            None => self.cap(),
        };
        if current < 1.0 {
            self.buckets.insert(source, (current, now));
            return false;
        }
        if !self.buckets.contains_key(&source) {
            while self.buckets.len() >= MAX_RATE_SOURCES {
                match self.order.pop_front() {
                    Some(oldest) => {
                        self.buckets.remove(&oldest);
                    }
                    None => break,
                }
            }
            self.order.push_back(source);
        }
        self.buckets.insert(source, (current - 1.0, now));
        true
    }

    /// Forget every source whose bucket is full again.
    fn prune(&mut self, now: Instant) {
        let cap = self.cap();
        let per_sec = cap / 60.0;
        self.buckets.retain(|_, (tokens, last)| {
            *tokens + now.saturating_duration_since(*last).as_secs_f64() * per_sec < cap
        });
        let kept = &self.buckets;
        self.order.retain(|source| kept.contains_key(source));
    }

    fn len(&self) -> usize {
        self.buckets.len()
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GuardCounts {
    pub allowed_peers: u32,
    pub open: bool,
    pub unreadable: bool,
    pub active_reservations: u32,
    pub refused_not_allowed: u64,
    pub refused_unreadable: u64,
    pub refused_per_ip: u64,
    pub refused_rate: u64,
    pub refused_circuit_rate: u64,
    /// Circuit requests from a source that may not use the relay.
    pub refused_circuit_not_allowed: u64,
}

#[derive(Debug)]
struct GuardState {
    policy: AllowPolicy,
    max_per_ip: usize,
    exempt_loopback: bool,
    /// Peers holding (or just granted) a reservation: their bucket and how
    /// many reservations libp2p accepted for them (a re-homed peer briefly
    /// holds two, one per connection; 0 until the first acceptance is seen).
    /// The count never exceeds the peer's open connections
    /// ([`RelayGuard::on_connection_closed`]).
    active: HashMap<PeerId, (Option<IpBucket>, u32)>,
    per_ip: HashMap<IpBucket, usize>,
    /// New reservations per source and minute.
    rate: SourceRate,
    /// Circuit requests per source and minute.
    circuit_rate: SourceRate,
    refused_not_allowed: u64,
    refused_unreadable: u64,
    refused_per_ip: u64,
    refused_rate: u64,
    refused_circuit_rate: u64,
    refused_circuit_not_allowed: u64,
}

/// The relay's own admission on top of libp2p: the allow-list (on by
/// default, fail closed), the per-IP reservation cap and the per-IP rate of
/// new reservations, in that order, so a refused peer spends nobody's rate,
/// plus, for circuits, the allow-list again and then the per-source rate.
/// Circuits are therefore served only between peers on the allow-list
/// (anyone with `--open`): the circle. libp2p-relay has none of them (its own
/// per-IP limiters key on the exact IPv6 address). Plugged in as the only
/// reservation and circuit limiter ([`RelayLimits::relay_config`]); the swarm
/// loop feeds it the relay events ([`Self::on_relay_event`]) and closed
/// connections ([`Self::on_connection_closed`]) and prunes it on its timer
/// ([`Self::prune`]). A dedicated relay's peer gate asks it too
/// ([`Self::may_use`]), so a peer that may not use the relay never gets a
/// connection. Clones share one state.
#[derive(Debug, Clone)]
pub struct RelayGuard {
    state: Arc<Mutex<GuardState>>,
}

impl RelayGuard {
    pub fn new(policy: AllowPolicy, limits: &RelayLimits) -> Self {
        Self {
            state: Arc::new(Mutex::new(GuardState {
                policy,
                max_per_ip: limits.max_reservations_per_ip,
                exempt_loopback: limits.exempt_loopback,
                active: HashMap::new(),
                per_ip: HashMap::new(),
                rate: SourceRate::new(limits.reservation_rate_per_ip_per_min),
                circuit_rate: SourceRate::new(limits.circuit_rate_per_ip_per_min),
                refused_not_allowed: 0,
                refused_unreadable: 0,
                refused_per_ip: 0,
                refused_rate: 0,
                refused_circuit_rate: 0,
                refused_circuit_not_allowed: 0,
            })),
        }
    }

    fn lock(&self) -> MutexGuard<'_, GuardState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Decide one reservation request (new or renewal) from `peer` at `addr`.
    pub fn admit(&self, peer: PeerId, addr: &Multiaddr) -> Result<(), ReservationRefusal> {
        self.admit_at(peer, addr, Instant::now())
    }

    /// [`Self::admit`] at a given time (tests).
    pub fn admit_at(
        &self,
        peer: PeerId,
        addr: &Multiaddr,
        now: Instant,
    ) -> Result<(), ReservationRefusal> {
        let mut st = self.lock();
        if !st.policy.admits(&peer) {
            return Err(if st.policy == AllowPolicy::Unreadable {
                st.refused_unreadable += 1;
                ReservationRefusal::AllowListUnreadable
            } else {
                st.refused_not_allowed += 1;
                ReservationRefusal::NotAllowed
            });
        }
        if st.active.contains_key(&peer) {
            // A renewal (or a second connection: libp2p's per-peer cap).
            return Ok(());
        }
        let bucket = ip_bucket(addr, st.exempt_loopback);
        if let Some(b) = bucket {
            if st.per_ip.get(&b).copied().unwrap_or(0) >= st.max_per_ip {
                st.refused_per_ip += 1;
                return Err(ReservationRefusal::PerIpCap);
            }
            if !st.rate.try_take(b, now) {
                st.refused_rate += 1;
                return Err(ReservationRefusal::PerIpRate);
            }
            *st.per_ip.entry(b).or_insert(0) += 1;
        }
        st.active.insert(peer, (bucket, 0));
        Ok(())
    }

    /// Decide one circuit request from `peer` at `addr`: it must be allowed
    /// to use the relay, checked first so a refused source spends nobody's
    /// tokens, then its per-minute rate (loopback exempt like everything
    /// else). libp2p asks this before it looks the destination up
    /// (libp2p-relay 0.22 behaviour.rs:682-747), so a refused source gets
    /// RESOURCE_LIMIT_EXCEEDED whether or not the destination is reserved.
    pub fn admit_circuit_at(&self, peer: &PeerId, addr: &Multiaddr, now: Instant) -> bool {
        let mut st = self.lock();
        if !st.policy.admits(peer) {
            st.refused_circuit_not_allowed += 1;
            return false;
        }
        let Some(b) = ip_bucket(addr, st.exempt_loopback) else {
            return true;
        };
        if st.circuit_rate.try_take(b, now) {
            true
        } else {
            st.refused_circuit_rate += 1;
            false
        }
    }

    /// Drop the rate buckets that are full again (call it on a timer).
    pub fn prune(&self) {
        self.prune_at(Instant::now());
    }

    pub fn prune_at(&self, now: Instant) {
        let mut st = self.lock();
        st.rate.prune(now);
        st.circuit_rate.prune(now);
    }

    /// Sources the two rate tables remember (tests, diagnostics).
    pub fn rate_sources(&self) -> (usize, usize) {
        let st = self.lock();
        (st.rate.len(), st.circuit_rate.len())
    }

    fn release(st: &mut GuardState, peer: &PeerId) {
        if let Some((Some(b), _)) = st.active.remove(peer) {
            if let Some(n) = st.per_ip.get_mut(&b) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    st.per_ip.remove(&b);
                }
            }
        }
    }

    /// Feed every relay server event: a reservation accepted on one more
    /// connection is counted; a timed-out one frees the peer's slot when it
    /// was its last. `ReservationClosed` counts nothing: libp2p-relay 0.22
    /// reports it for every connection of the peer that closes, reserved or
    /// not (behaviour.rs:407-437), and names no connection, so closes are
    /// counted from the swarm's [`Self::on_connection_closed`] instead.
    /// (A denial never took one: this guard says yes last.)
    pub fn on_relay_event(&self, event: &relay::Event) {
        let mut st = self.lock();
        match event {
            relay::Event::ReservationReqAccepted {
                src_peer_id,
                renewed: false,
            } => {
                if let Some((_, held)) = st.active.get_mut(src_peer_id) {
                    *held = held.saturating_add(1);
                }
            }
            relay::Event::ReservationTimedOut { src_peer_id } => {
                match st.active.get_mut(src_peer_id) {
                    Some((_, held)) if *held > 1 => *held -= 1,
                    _ => Self::release(&mut st, src_peer_id),
                }
            }
            _ => {}
        }
    }

    /// A connection of `peer` closed and `remaining` are still open
    /// (`SwarmEvent::ConnectionClosed`'s `num_established`). Each reservation
    /// lives on a connection of its own, so the peer holds at most
    /// `remaining`: a re-homed peer's silent old reservation is reaped while
    /// its new one stays, and with no connection left whatever it reserved
    /// is gone. (A plain extra connection that closes changes nothing.)
    pub fn on_connection_closed(&self, peer: &PeerId, remaining: u32) {
        let mut st = self.lock();
        if remaining == 0 {
            Self::release(&mut st, peer);
        } else if let Some((_, held)) = st.active.get_mut(peer) {
            *held = (*held).min(remaining);
        }
    }

    /// The peer has no connection left: whatever it reserved is gone
    /// ([`Self::on_connection_closed`] with none remaining).
    pub fn on_peer_disconnected(&self, peer: &PeerId) {
        self.on_connection_closed(peer, 0);
    }

    /// May `peer` use this relay (connect, reserve, open circuits)? The
    /// allow-list, or anyone with `--open`; nobody when it is unreadable.
    /// The dedicated relay's peer gate asks this.
    pub fn may_use(&self, peer: &PeerId) -> bool {
        self.lock().policy.admits(peer)
    }

    /// Is `peer` on the allow-list itself? `Open` and `Unreadable` list
    /// nobody, so an open relay role never makes a stranger a member of the
    /// endpoint's peer gate ([`crate::gate::GateHandle`]): `service
    /// --relay-open` serves any verified contact, never a stranger.
    pub fn is_listed(&self, peer: &PeerId) -> bool {
        matches!(&self.lock().policy, AllowPolicy::Peers(peers) if peers.contains(peer))
    }

    /// Replace the policy (an allow-list reload). Returns the peers that hold a
    /// reservation but are no longer allowed: the caller disconnects them.
    pub fn set_policy(&self, policy: AllowPolicy) -> Vec<PeerId> {
        let mut st = self.lock();
        st.policy = policy;
        let st = &*st;
        st.active
            .keys()
            .filter(|p| !st.policy.admits(p))
            .copied()
            .collect()
    }

    pub fn counts(&self) -> GuardCounts {
        let st = self.lock();
        GuardCounts {
            allowed_peers: match &st.policy {
                AllowPolicy::Peers(p) => p.len() as u32,
                _ => 0,
            },
            open: st.policy == AllowPolicy::Open,
            unreadable: st.policy == AllowPolicy::Unreadable,
            active_reservations: st.active.len() as u32,
            refused_not_allowed: st.refused_not_allowed,
            refused_unreadable: st.refused_unreadable,
            refused_per_ip: st.refused_per_ip,
            refused_rate: st.refused_rate,
            refused_circuit_rate: st.refused_circuit_rate,
            refused_circuit_not_allowed: st.refused_circuit_not_allowed,
        }
    }

    /// This guard as a libp2p reservation rate limiter.
    pub fn limiter(&self) -> Box<dyn relay::RateLimiter> {
        let guard = self.clone();
        Box::new(move |peer: PeerId, addr: &Multiaddr, _now| guard.admit(peer, addr).is_ok())
    }

    /// This guard as a libp2p circuit limiter (allow-list, then the rate per
    /// source).
    pub fn circuit_limiter(&self) -> Box<dyn relay::RateLimiter> {
        let guard = self.clone();
        Box::new(move |peer: PeerId, addr: &Multiaddr, _now| {
            guard.admit_circuit_at(&peer, addr, Instant::now())
        })
    }
}

// ── Which addresses a host may name ─────────────────────────────────────────

/// Globally routable unicast IPv4: [`raven_core::p2p_route::is_global_ipv4`],
/// the one rule for this host, its gate and RRH1 route hints.
pub fn is_global_ipv4(ip: Ipv4Addr) -> bool {
    raven_core::p2p_route::is_global_ipv4(ip)
}

/// Globally routable unicast IPv6, NAT64 and 6to4 as the IPv4 address they
/// carry: [`raven_core::p2p_route::is_global_ipv6`].
pub fn is_global_ipv6(ip: Ipv6Addr) -> bool {
    raven_core::p2p_route::is_global_ipv6(ip)
}

/// The IPv4 address an IPv6 address carries (IPv4-mapped, NAT64, 6to4):
/// [`raven_core::p2p_route::embedded_ipv4`].
fn embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    raven_core::p2p_route::embedded_ipv4(ip)
}

/// [`raven_core::p2p_route::is_global_ip`].
pub fn is_global_ip(ip: IpAddr) -> bool {
    raven_core::p2p_route::is_global_ip(ip)
}

/// The IP of the first `/ip4` / `/ip6` component, if any.
pub fn addr_ip(address: &Multiaddr) -> Option<IpAddr> {
    address.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

/// The network an address belongs to, for telling *independent*
/// reachability checks apart: PeerIds are free, networks are not, so one
/// network gives one opinion. The /24 of a global IPv4 address, the /48 of a
/// global IPv6 one; an IPv6 address that carries an IPv4 one (IPv4-mapped,
/// NAT64, 6to4: [`is_global_ipv6`]) is grouped as that IPv4 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NetGroup {
    V4([u8; 3]),
    V6([u16; 3]),
}

/// [`NetGroup`] of `ip`; `None` for anything not globally routable
/// (loopback, LAN, CGNAT, link-local, documentation, ...).
pub fn net_group(ip: IpAddr) -> Option<NetGroup> {
    if !is_global_ip(ip) {
        return None;
    }
    let v4 = |o: [u8; 4]| NetGroup::V4([o[0], o[1], o[2]]);
    Some(match ip {
        IpAddr::V4(a) => v4(a.octets()),
        IpAddr::V6(a) => match embedded_ipv4(a) {
            Some(m) => v4(m.octets()),
            None => {
                let s = a.segments();
                NetGroup::V6([s[0], s[1], s[2]])
            }
        },
    })
}

/// May a relay name this listen address of its own (in reservations and to
/// Identify)? Circuits never; the `…/tls/ws` form of a two-protocol WSS
/// listener never (RWS1 §2.2: its plain sibling, reported next, is named);
/// a globally routable one always; any other only when the operator listens
/// on that specific address (`--listen 10.0.0.1:7423`, a lab's
/// `127.0.0.1:0`): an unspecified listen address (`0.0.0.0`, `::`) must not
/// disclose the host's LAN, link-local or loopback addresses. `/dns*`
/// addresses come only from `--external`.
pub fn relay_may_advertise(address: &Multiaddr, listen_is_specific: bool) -> bool {
    if is_circuit(address) || is_wss_form(address) {
        return false;
    }
    match addr_ip(address) {
        Some(ip) => is_global_ip(ip) || listen_is_specific,
        None => false,
    }
}

/// Which own listen addresses a relaying host names as external (in its
/// reservations and to Identify), given how it listens:
/// - explicit addresses, when there are any: exactly those. They are the
///   operator's (`--external`, `--public-host`) at [`Self::new`], or the
///   latest [`Self::set_external`] (the friend relay's confirmed ones);
/// - else every listen address [`relay_may_advertise`] admits;
/// - else (an unspecified listen address with no global one) one loopback
///   listen address as a placeholder, which discloses nothing but the port:
///   libp2p clients refuse a reservation that names no address at all, and
///   friends dial the address in their `via=` anyway. A real address replaces
///   it as soon as one appears.
///
/// Expired listen addresses are withdrawn again, so a network change never
/// leaves a stale address advertised. Listen addresses are tracked while
/// explicit ones are named, so an empty [`Self::set_external`] falls back to
/// them.
#[derive(Debug, Default)]
pub struct RelayAdvertiser {
    listen_is_specific: bool,
    explicit: Vec<Multiaddr>,
    /// Listen addresses [`relay_may_advertise`] admits (named only while
    /// there is no explicit one).
    advertised: HashSet<Multiaddr>,
    /// The first loopback listen address: the placeholder's candidate.
    loopback: Option<Multiaddr>,
    placeholder: Option<Multiaddr>,
}

impl RelayAdvertiser {
    pub fn new<B: NetworkBehaviour>(
        swarm: &mut Swarm<B>,
        listen_is_specific: bool,
        external: &[Multiaddr],
    ) -> Self {
        let mut explicit: Vec<Multiaddr> = Vec::new();
        for addr in external {
            if !explicit.contains(addr) {
                swarm.add_external_address(addr.clone());
                explicit.push(addr.clone());
            }
        }
        Self {
            listen_is_specific,
            explicit,
            ..Self::default()
        }
    }

    /// What this advertiser has named to `swarm` now.
    fn in_swarm(&self) -> Vec<Multiaddr> {
        if !self.explicit.is_empty() {
            return self.explicit.clone();
        }
        self.advertised
            .iter()
            .chain(self.placeholder.as_ref())
            .cloned()
            .collect()
    }

    /// The loopback placeholder, when nothing else may be named.
    fn hold_place<B: NetworkBehaviour>(&mut self, swarm: &mut Swarm<B>) {
        if self.explicit.is_empty() && self.advertised.is_empty() && self.placeholder.is_none() {
            if let Some(addr) = self.loopback.clone() {
                swarm.add_external_address(addr.clone());
                self.placeholder = Some(addr);
            }
        }
    }

    /// Feed `SwarmEvent::NewListenAddr`.
    pub fn on_new_listen_addr<B: NetworkBehaviour>(
        &mut self,
        swarm: &mut Swarm<B>,
        addr: &Multiaddr,
    ) {
        // A WSS listener's `…/tls/ws` form is never named, not even as the
        // placeholder: its plain sibling comes next.
        if is_circuit(addr) || is_wss_form(addr) {
            return;
        }
        if relay_may_advertise(addr, self.listen_is_specific) {
            let new = self.advertised.insert(addr.clone());
            if self.explicit.is_empty() {
                if let Some(old) = self.placeholder.take() {
                    swarm.remove_external_address(&old);
                }
                if new {
                    swarm.add_external_address(addr.clone());
                }
            }
        } else if addr_ip(addr).is_some_and(|ip| ip.is_loopback()) {
            if self.loopback.is_none() {
                self.loopback = Some(addr.clone());
            }
            self.hold_place(swarm);
        }
    }

    /// Feed `SwarmEvent::ExpiredListenAddr`.
    pub fn on_expired_listen_addr<B: NetworkBehaviour>(
        &mut self,
        swarm: &mut Swarm<B>,
        addr: &Multiaddr,
    ) {
        if self.loopback.as_ref() == Some(addr) {
            self.loopback = None;
        }
        let named = self.advertised.remove(addr) && self.explicit.is_empty();
        if named || self.placeholder.as_ref() == Some(addr) {
            swarm.remove_external_address(addr);
            if self.placeholder.as_ref() == Some(addr) {
                self.placeholder = None;
            }
        }
    }

    /// Name exactly `addrs` from now on, in place of any explicit addresses
    /// before them: new ones are added, dropped ones withdrawn, and the
    /// loopback placeholder goes once any address is named. An empty list
    /// falls back to the listen-address rule (admitted listen addresses, or
    /// the placeholder).
    pub fn set_external<B: NetworkBehaviour>(&mut self, swarm: &mut Swarm<B>, addrs: &[Multiaddr]) {
        let before = self.in_swarm();
        self.explicit.clear();
        for addr in addrs {
            if !self.explicit.contains(addr) {
                self.explicit.push(addr.clone());
            }
        }
        self.placeholder = None;
        if self.explicit.is_empty() && self.advertised.is_empty() {
            self.placeholder = self.loopback.clone();
        }
        let after = self.in_swarm();
        for addr in &before {
            if !after.contains(addr) {
                swarm.remove_external_address(addr);
            }
        }
        for addr in &after {
            if !before.contains(addr) {
                swarm.add_external_address(addr.clone());
            }
        }
    }

    /// The addresses this relay names for itself: the explicit ones if any,
    /// else the admitted listen addresses, sorted. Never the loopback
    /// placeholder (`relay_status.json` `advertised`, `raven relay card`).
    pub fn named(&self) -> Vec<Multiaddr> {
        if !self.explicit.is_empty() {
            return self.explicit.clone();
        }
        let mut out: Vec<Multiaddr> = self.advertised.iter().cloned().collect();
        out.sort();
        out
    }

    /// Only the loopback placeholder is advertised (no public address known).
    pub fn placeholder_only(&self) -> bool {
        self.explicit.is_empty() && self.advertised.is_empty() && self.placeholder.is_some()
    }
}

/// Why a listen address cannot be opened, found before libp2p binds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenProbe {
    /// Another program holds the port: libp2p-tcp would still bind it
    /// (`SO_REUSEADDR`, and `SO_REUSEPORT` on Unix) and silently share or
    /// lose the connections, so it must not be opened.
    Busy,
    /// The address is on no interface of this host now (`EADDRNOTAVAIL`):
    /// it may appear later (a VPN's, a second NIC's, a lease, an IPv6
    /// address still being checked for duplicates).
    Absent,
    /// The address can never be bound here as asked: no such address family
    /// (no IPv6 stack), a port this process may not bind, an invalid
    /// address.
    Unavailable,
    /// A port below 1024 needs a privilege on this host (Unix: root,
    /// `CAP_NET_BIND_SERVICE`, Linux `net.ipv4.ip_unprivileged_port_start`).
    Privileged,
}

impl ListenProbe {
    /// What a failed probe bind of `port` says about the address.
    pub fn of_error(error: &std::io::Error, port: u16) -> Self {
        use std::io::ErrorKind;
        match error.kind() {
            ErrorKind::AddrInUse => Self::Busy,
            // Windows reports a port held exclusively as access denied.
            ErrorKind::PermissionDenied if cfg!(windows) => Self::Busy,
            ErrorKind::PermissionDenied if port < 1024 => Self::Privileged,
            ErrorKind::AddrNotAvailable => Self::Absent,
            _ => Self::Unavailable,
        }
    }
}

/// Probe-bind the exact TCP (or, for `/quic-v1`, UDP) address of `addr` with
/// a plain socket ([`probe_socket`]), which sets no `SO_REUSEPORT` (and on
/// Windows no `SO_REUSEADDR`), so a port another socket holds is reported
/// instead of shared. Port 0 and non-IP addresses are not probed. The probe
/// socket is closed before this returns. An IPv6 probe is IPv6-only, as
/// libp2p binds: our own `0.0.0.0` listener on the port never makes the
/// `[::]` probe busy.
pub fn probe_listen_addr(addr: &Multiaddr) -> Result<(), ListenProbe> {
    let Some(ip) = addr_ip(addr) else {
        return Ok(());
    };
    let mut port = None;
    let mut udp = false;
    for p in addr.iter() {
        match p {
            Protocol::Tcp(n) => port = Some(n),
            Protocol::Udp(n) => {
                port = Some(n);
                udp = true;
            }
            _ => {}
        }
    }
    let Some(port) = port.filter(|p| *p != 0) else {
        return Ok(());
    };
    let sock = std::net::SocketAddr::new(ip, port);
    probe_socket(sock, udp)
        .map(drop)
        .map_err(|e| ListenProbe::of_error(&e, port))
}

/// The probe socket for `sock`, bound (and for TCP listening) as std's
/// `UdpSocket::bind` / `TcpListener::bind` would, except that an IPv6 one is
/// IPv6-only, as libp2p-tcp and libp2p-quic bind theirs: a dual-stack `[::]`
/// socket (the Linux default) overlaps `0.0.0.0` on the same port, so it
/// would find our own IPv4 listener there and call the port busy.
fn probe_socket(sock: std::net::SocketAddr, udp: bool) -> std::io::Result<socket2::Socket> {
    use socket2::{Domain, Protocol as IpProtocol, Socket, Type};
    let (kind, protocol) = if udp {
        (Type::DGRAM, IpProtocol::UDP)
    } else {
        (Type::STREAM, IpProtocol::TCP)
    };
    let socket = Socket::new(Domain::for_address(sock), kind, Some(protocol))?;
    if sock.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    // As std's TcpListener: a port held only by TIME_WAIT is not busy.
    if !udp && cfg!(not(windows)) {
        socket.set_reuse_address(true)?;
    }
    socket.bind(&sock.into())?;
    if !udp {
        socket.listen(128)?;
    }
    Ok(socket)
}

/// "tcp" / "udp" and the port of a listen address, for logs that must not
/// name an address (NAT spec §5).
pub fn listen_port_label(addr: &Multiaddr) -> String {
    let mut out = String::from("?");
    for p in addr.iter() {
        match p {
            Protocol::Tcp(n) => out = format!("{n}/tcp"),
            Protocol::Udp(n) => out = format!("{n}/udp"),
            _ => {}
        }
    }
    out
}

/// Refuses every outbound dial to an address that is not globally routable.
/// On the relay-only host the only outbound dials are the AutoNAT v2 server's
/// dial-backs (the relay server dials nobody), whose target a client chooses:
/// without this a client could make the relay connect to its own loopback or
/// LAN services. libp2p-autonat 0.16 has no such filter of its own.
#[derive(Debug, Default)]
pub struct DialBackGuard {
    refused: u64,
}

/// Why [`DialBackGuard`] refused a dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotGloballyRoutable;

impl fmt::Display for NotGloballyRoutable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("dial-back target is not a globally routable address")
    }
}

impl Error for NotGloballyRoutable {}

impl DialBackGuard {
    pub fn refused(&self) -> u64 {
        self.refused
    }

    fn allowed(addresses: &[Multiaddr]) -> bool {
        !addresses.is_empty()
            && addresses
                .iter()
                .all(|a| addr_ip(a).is_some_and(is_global_ip) && !is_circuit(a))
    }
}

impl NetworkBehaviour for DialBackGuard {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        _effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if Self::allowed(addresses) {
            Ok(Vec::new())
        } else {
            self.refused += 1;
            Err(ConnectionDenied::new(NotGloballyRoutable))
        }
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if Self::allowed(std::slice::from_ref(addr)) {
            Ok(dummy::ConnectionHandler)
        } else {
            self.refused += 1;
            Err(ConnectionDenied::new(NotGloballyRoutable))
        }
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _peer: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        libp2p::core::util::unreachable(event)
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

// ── Endpoint host ────────────────────────────────────────────────────────────

/// What the endpoint host runs besides the always-on parts.
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    /// Router port mapping, the consent (node policy; owner decision Q8):
    /// UPnP-IGD; NAT-PMP, PCP and IPv6 pinholes only behind
    /// PORT_MAP/V6_PINHOLE ([`EndpointConfig::port_map`]).
    pub upnp: bool,
    /// How the router is asked once [`EndpointConfig::upnp`] allows it
    /// ([`crate::portmap::PortMapConfig`], built per generation). `None` is
    /// today's UPnP-IGD only.
    pub port_map: Option<crate::portmap::PortMapConfig>,
    /// `service --relay`: also relay for others (the user's own PeerId).
    pub relay_server: Option<(RelayLimits, RelayGuard)>,
    /// Who may connect (the peer gate, [`crate::gate`]). The default admits
    /// nobody (fail closed). With `relay_server`, build it with
    /// `GateHandle::new(Some(guard))`, so the relay's listed members are
    /// admitted too.
    pub gate: GateHandle,
    /// Addresses hole punching may offer and dial, and AutoNAT may test:
    /// [`AddrRule::GlobalOnly`] outside the debug lab.
    pub hole_punch_addrs: AddrRule,
    /// Skip hopeless hole punches (Phase 4, [`crate::natclass::PunchPolicy`]
    /// in [`HolePunch`]): `raven_core::nat_class_live_enabled()` by default.
    /// False: every contact's relayed connection gets DCUtR, as in Phase 1.
    pub punch_policy: bool,
    /// The relay of each relay slot (at most two): each gets an AutoNAT v2
    /// client of its own, which asks that relay only.
    pub autonat_servers: [Option<PeerId>; 2],
    /// How often each AutoNAT client tests the candidates it has not tested
    /// yet (it asks nothing while there are none).
    pub autonat_interval: Duration,
    pub connection_timeout: Duration,
    pub idle_connection_timeout: Duration,
    pub ping_interval: Duration,
    pub ping_timeout: Duration,
    pub identify_interval: Duration,
    /// WSS dials to relays (RWS1): the TLS client config and the proxy
    /// lookup. `None` (the default) builds no WSS transport, so a WSS
    /// address is not dialled at all.
    #[cfg(feature = "wss")]
    pub wss: Option<crate::wss::ClientSide>,
    /// Restricted network (RWS1 §9): set while a relay reservation rides a
    /// proxied WSS connection. The caller owns it, one per process, so it
    /// outlives re-homes; every endpoint generation gets a clone. False by
    /// default. While it is set, the candidate book offers nothing and
    /// records no swarm candidate ([`HolePunch::with_restricted`]), and both
    /// AutoNAT clients drop every candidate ([`Scoped::with_restricted`]).
    pub restricted: Arc<AtomicBool>,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            upnp: false,
            port_map: None,
            relay_server: None,
            gate: GateHandle::default(),
            hole_punch_addrs: AddrRule::GlobalOnly,
            punch_policy: raven_core::nat_class_live_enabled(),
            autonat_servers: [None, None],
            // A fresh endpoint (start, re-home) shows reachability soon.
            autonat_interval: Duration::from_secs(15),
            connection_timeout: Duration::from_secs(10),
            idle_connection_timeout: Duration::from_secs(60),
            ping_interval: Duration::from_secs(15),
            ping_timeout: Duration::from_secs(5),
            identify_interval: Duration::from_secs(60),
            #[cfg(feature = "wss")]
            wss: None,
            restricted: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Connection budget of an endpoint that does not relay: a few contacts,
/// their circuits and our relays. Inbound connections may hold at most
/// `ENDPOINT_MAX_ESTABLISHED - OUTBOUND_RESERVE` of them.
const ENDPOINT_MAX_ESTABLISHED: u32 = 64;
const ENDPOINT_MAX_PENDING: u32 = 16;
/// A direct and a relayed connection to one contact, plus one spare.
const ENDPOINT_MAX_PER_PEER: u32 = 3;

/// Field order is admission order (checked against libp2p 0.57):
/// swarm-derive 0.36 builds `handle_established_*` as nested
/// `select(select(f0?, f1?), f2?)` in declaration order (lib.rs:289-310,
/// 339-360), and the pending hooks are `?` statements in the same order
/// (272-287, 312-337), so the first field that denies stops the rest from
/// being asked; on any denial the swarm spawns no handler at all
/// (libp2p-swarm 0.48 lib.rs:700-763). So:
/// - `limits` and `ip_limits` come FIRST: a behaviour listed before them
///   (DCUtR keeps a record of every direct connection it is shown) would
///   otherwise record connections the limits then deny, and those records
///   never see a `ConnectionClosed`;
/// - `peer_gate` is third, before every protocol: a refused peer never
///   reaches a handler of the relay, DCUtR, AutoNAT, Identify or the Raven
///   link.
///
/// The protocols past the gate are scoped by class ([`crate::gate`]): DCUtR
/// to verified contacts, each AutoNAT client to the relay of its slot,
/// Identify to contacts, own relays and relay members. `stream` is not
/// scoped: the Raven link responder answers verified contacts only, with
/// the same timing for everyone else.
#[derive(NetworkBehaviour)]
pub struct EndpointBehaviour {
    limits: connection_limits::Behaviour,
    ip_limits: IpLimits,
    pub peer_gate: PeerGate<GateHandle>,
    pub relay_client: relay::client::Behaviour,
    pub relay_server: Toggle<relay::Behaviour>,
    /// Verified contacts only; it offers its [`crate::candidates::CandidateBook`]
    /// (fed raw observations by the host), global addresses only outside the
    /// debug lab (the field name keeps `EndpointBehaviourEvent::Dcutr`).
    pub dcutr: HolePunch,
    /// One AutoNAT v2 client per relay slot: libp2p-autonat 0.16 tests each
    /// candidate once per client against one random server
    /// (client/behaviour.rs:287-347) and tests it again only after
    /// UnsupportedProtocol / Io (204-231); the server dials back from its own
    /// key (server/behaviour.rs:116-123), so scoping a client to its relay's
    /// PeerId keeps the request and the dial-back with that client.
    pub autonat: Scoped<autonat::v2::client::Behaviour, OnlyPeer>,
    pub autonat_2: Scoped<autonat::v2::client::Behaviour, OnlyPeer>,
    /// Contacts, own relays and relay members only: no Identify with
    /// strangers or a contact's relay.
    pub identify: Scoped<identify::Behaviour>,
    pub ping: ping::Behaviour,
    /// Router port mapping ([`crate::portmap::PortMap`]; libp2p-upnp in it
    /// while the PORT_MAP gate is closed).
    pub port_map: Toggle<crate::portmap::PortMap>,
    pub stream: libp2p_stream::Behaviour,
}

/// Identify names only this host's *external* addresses: those a relay
/// reservation, UPnP or AutoNAT confirmed (plus, on a relay, the ones
/// [`relay_may_advertise`] admits). Listen addresses (LAN, link-local,
/// loopback) are never sent, and nothing is pushed unasked. DCUtR and AutoNAT
/// do not need them. AutoNAT works from the addresses peers *observe*
/// (`NewExternalAddrCandidate`, which Identify still reports); DCUtR from the
/// candidate book ([`crate::candidates`]), which also keeps the raw observed
/// address Identify's port rewrite would lose.
pub fn identify_config(key: &Keypair, interval: Duration) -> identify::Config {
    identify::Config::new(IDENTIFY_PROTOCOL.to_owned(), key.public())
        .with_agent_version(AGENT_VERSION.to_owned())
        .with_interval(interval)
        .with_hide_listen_addrs(true)
        .with_push_listen_addr_updates(false)
        .with_cache_size(64)
}

/// The endpoint's behaviours, composed in admission order (see
/// [`EndpointBehaviour`]); on its own so tests can build the real
/// composition.
pub(crate) fn endpoint_behaviour(
    key: &Keypair,
    relay_client: relay::client::Behaviour,
    cfg: &EndpointConfig,
) -> EndpointBehaviour {
    let local = key.public().to_peer_id();
    let (limits, ip_limits, relay_server) = match &cfg.relay_server {
        Some((relay_limits, guard)) => (
            relay_limits.connection_limits(),
            relay_limits.ip_limits(),
            Some(relay::Behaviour::new(
                local,
                relay_limits.relay_config(guard),
            )),
        ),
        None => (
            connection_limits::Behaviour::new(
                ConnectionLimits::default()
                    .with_max_pending_incoming(Some(ENDPOINT_MAX_PENDING))
                    .with_max_pending_outgoing(Some(ENDPOINT_MAX_PENDING))
                    .with_max_established(Some(ENDPOINT_MAX_ESTABLISHED))
                    .with_max_established_incoming(Some(
                        ENDPOINT_MAX_ESTABLISHED - OUTBOUND_RESERVE,
                    ))
                    .with_max_established_per_peer(Some(ENDPOINT_MAX_PER_PEER)),
            ),
            IpLimits::new(IpLimitConfig::default()),
            None,
        ),
    };
    // The relay of one slot as the only server of its client; candidates
    // follow the hole-punch rule, and none passes while restricted.
    let autonat = |server: Option<PeerId>| {
        Scoped::new(
            autonat::v2::client::Behaviour::new(
                crate::autonat_rng(),
                autonat::v2::client::Config::default()
                    .with_max_candidates(8)
                    .with_probe_interval(cfg.autonat_interval),
            ),
            OnlyPeer(server),
            PeerClass::OWN_RELAY,
            Some(cfg.hole_punch_addrs),
        )
        .with_restricted(cfg.restricted.clone())
    };
    EndpointBehaviour {
        limits,
        ip_limits,
        peer_gate: PeerGate::new(cfg.gate.clone()),
        relay_client,
        relay_server: Toggle::from(relay_server),
        dcutr: HolePunch::new(local, cfg.gate.clone(), cfg.hole_punch_addrs)
            .with_restricted(cfg.restricted.clone())
            .with_punch_policy(cfg.punch_policy),
        autonat: autonat(cfg.autonat_servers[0]),
        autonat_2: autonat(cfg.autonat_servers[1]),
        identify: Scoped::new(
            identify::Behaviour::new(identify_config(key, cfg.identify_interval)),
            cfg.gate.clone(),
            IDENTIFY_SCOPE,
            None,
        ),
        // Ping only reports a dead connection; the host loop closes it
        // (`crate::liveness::close_if_dead`).
        ping: ping::Behaviour::new(
            ping::Config::new()
                .with_interval(cfg.ping_interval)
                .with_timeout(cfg.ping_timeout),
        ),
        port_map: Toggle::from(cfg.upnp.then(|| {
            crate::portmap::PortMap::new(
                cfg.port_map
                    .clone()
                    .unwrap_or_else(crate::portmap::PortMapConfig::upnp_only),
            )
        })),
        stream: libp2p_stream::Behaviour::new(),
    }
}

/// The endpoint host: direct TCP / QUIC, the WSS client when
/// [`EndpointConfig`] has one (feature `wss`), the relay client transport,
/// and the behaviours above. No DNS transport: callers resolve `/dns*/` names
/// first (a proxied WSS dial leaves the name to the proxy). At most two
/// concurrent connection attempts per dial (the design's hedge of 2).
pub fn build_endpoint_swarm(
    _gate: &HostGate,
    identity: Keypair,
    config: EndpointConfig,
) -> Result<Swarm<EndpointBehaviour>, Box<dyn Error + Send + Sync>> {
    if let Some((limits, _)) = &config.relay_server {
        limits.validate()?;
    }
    let cfg = config.clone();
    let builder = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic();
    #[cfg(feature = "wss")]
    let builder =
        builder.with_other_transport(|key| -> Result<_, Box<dyn Error + Send + Sync>> {
            Ok(match config.wss.clone() {
                Some(c) => OptionalTransport::some(crate::wss::client_transport(key, c)?),
                None => OptionalTransport::none(),
            })
        })?;
    let swarm = builder
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(move |key, relay_client| endpoint_behaviour(key, relay_client, &cfg))?
        .with_swarm_config(move |c| {
            c.with_idle_connection_timeout(config.idle_connection_timeout)
                .with_notify_handler_buffer_size(NonZeroUsize::new(32).expect("nonzero"))
                .with_per_connection_event_buffer_size(32)
                .with_dial_concurrency_factor(NonZeroU8::new(2).expect("nonzero"))
                .with_max_negotiating_inbound_streams(64)
        })
        .with_connection_timeout(config.connection_timeout)
        .build();
    Ok(swarm)
}

// ── Relay-only host ──────────────────────────────────────────────────────────

/// `limits` and `ip_limits` first and `peer_gate` third, for the reasons
/// given at [`EndpointBehaviour`]: a peer that may not use the relay
/// ([`RelayGuard::may_use`]) gets one Noise handshake and a closed
/// connection, and never a relay, AutoNAT or Identify handler, so it learns
/// nothing about who is reserved. `dial_back_guard` before the AutoNAT
/// server. `upnp` is last: its handler is a dummy one.
#[derive(NetworkBehaviour)]
pub struct RelayBehaviour {
    limits: connection_limits::Behaviour,
    ip_limits: IpLimits,
    pub peer_gate: PeerGate<RelayGuard>,
    pub dial_back_guard: DialBackGuard,
    pub relay: relay::Behaviour,
    pub autonat_server: Toggle<autonat::v2::server::Behaviour>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    /// UPnP-IGD for the relay's own port (IPv4 only); a mapping is
    /// reported as a confirmed external address, which reservations name.
    pub upnp: Toggle<upnp::tokio::Behaviour>,
}

/// What a relay's two-protocol WSS listener needs (`wss::ServerSide`,
/// feature `wss`). Without the feature the type has no value, so a relay is
/// built with `None`.
#[cfg(feature = "wss")]
pub use crate::wss::ServerSide as WssServerSide;
/// What a relay's two-protocol WSS listener needs (`wss::ServerSide`,
/// feature `wss`). Without the feature the type has no value, so a relay is
/// built with `None`.
#[cfg(not(feature = "wss"))]
#[derive(Debug, Clone)]
pub enum WssServerSide {}

/// `raven-node relay`: the relay server with `limits` and `guard`, an
/// optional AutoNAT v2 server, Identify, Ping and optional UPnP-IGD (the
/// dedicated relay never asks a router). No Raven link protocol. With `wss`
/// it can also listen on `…/tcp/<p>/tls/ws`, a two-protocol port (RWS1 §6);
/// it never dials over WSS, so [`DialBackGuard`]'s dial-backs never do.
pub fn build_relay_swarm(
    _gate: &HostGate,
    identity: Keypair,
    limits: RelayLimits,
    guard: &RelayGuard,
    autonat_server: bool,
    upnp: bool,
    wss: Option<WssServerSide>,
) -> Result<Swarm<RelayBehaviour>, Box<dyn Error + Send + Sync>> {
    limits.validate()?;
    let guard = guard.clone();
    let builder = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic();
    #[cfg(feature = "wss")]
    let builder =
        builder.with_other_transport(|key| -> Result<_, Box<dyn Error + Send + Sync>> {
            Ok(match wss {
                Some(s) => OptionalTransport::some(crate::wss::server_transport(key, s)?),
                None => OptionalTransport::none(),
            })
        })?;
    #[cfg(not(feature = "wss"))]
    if let Some(never) = wss {
        match never {}
    }
    let swarm = builder
        .with_behaviour(move |key| RelayBehaviour {
            limits: limits.connection_limits(),
            ip_limits: limits.ip_limits(),
            peer_gate: PeerGate::new(guard.clone()),
            dial_back_guard: DialBackGuard::default(),
            relay: relay::Behaviour::new(key.public().to_peer_id(), limits.relay_config(&guard)),
            autonat_server: Toggle::from(
                autonat_server.then(|| autonat::v2::server::Behaviour::new(crate::autonat_rng())),
            ),
            identify: identify::Behaviour::new(identify_config(key, Duration::from_secs(60))),
            ping: ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(Duration::from_secs(15))
                    .with_timeout(Duration::from_secs(5)),
            ),
            upnp: Toggle::from(upnp.then(upnp::tokio::Behaviour::default)),
        })?
        .with_swarm_config(|c| {
            c.with_idle_connection_timeout(Duration::from_secs(60))
                .with_max_negotiating_inbound_streams(128)
        })
        .with_connection_timeout(Duration::from_secs(10))
        .build();
    Ok(swarm)
}

/// Is `address` a relayed (`/p2p-circuit`) address?
pub fn is_circuit(address: &Multiaddr) -> bool {
    address.iter().any(|p| matches!(p, Protocol::P2pCircuit))
}

/// Does `address` carry TLS or WebSocket layers (`/tls`, `/sni`, `/ws`,
/// `/wss`), as a WSS address does (RWS1 §2)?
pub(crate) fn is_wss_form(address: &Multiaddr) -> bool {
    address.iter().any(|p| {
        matches!(
            p,
            Protocol::Tls | Protocol::Sni(_) | Protocol::Ws(_) | Protocol::Wss(_)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diag::{circuit_relay, dial_failures, Failed};
    use crate::gate::{GateCounts, PeerNotAdmitted};
    use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
    use libp2p::swarm::{DialError, ListenError, NewExternalAddrCandidate, SwarmEvent};
    use raven_core::reach_diag::{AddrOutcome, CircuitOutcome};

    fn key(seed: u8) -> Keypair {
        Keypair::ed25519_from_bytes([seed; 32]).unwrap()
    }

    fn gate() -> HostGate {
        HostGate::open(true).unwrap()
    }

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn the_gate_is_required_to_build_anything() {
        assert_eq!(
            HostGate::open(false).unwrap_err().message(),
            "the libp2p host is held: its runtime gate is closed"
        );
        HostGate::open(true).unwrap();
    }

    #[test]
    fn relay_defaults_match_the_design_and_stay_under_the_hard_max() {
        let f = RelayLimits::friends();
        f.validate().unwrap();
        assert_eq!(
            (
                f.max_reservations,
                f.max_reservations_per_peer,
                f.max_reservations_per_ip
            ),
            (128, 2, 4)
        );
        assert_eq!(f.reservation_duration, Duration::from_secs(1800));
        assert_eq!((f.max_circuits, f.max_circuits_per_peer), (64, 4));
        assert_eq!(f.max_circuit_duration, Duration::from_secs(300));
        assert_eq!(f.max_circuit_bytes, 2 << 20);
        assert_eq!(
            (
                f.reservation_rate_per_ip_per_min,
                f.circuit_rate_per_ip_per_min
            ),
            (4, 30)
        );
        assert_eq!((f.max_established, f.max_established_per_ip), (256, 8));
        let o = RelayLimits::open();
        o.validate().unwrap();
        assert_eq!(o.max_reservations, 32);
        assert_eq!(o.max_circuit_bytes, 512 << 10);
        RELAY_HARD_MAX.validate().unwrap();

        // The libp2p per-peer check is "more than": compensated by one.
        let guard = RelayGuard::new(AllowPolicy::Open, &f);
        let config = f.relay_config(&guard);
        assert_eq!(
            config.max_reservations_per_peer, 1,
            "2 per peer: n - 1 for libp2p"
        );
        assert_eq!(
            config.max_circuits_per_peer, 3,
            "4 circuits per peer: n - 1 for libp2p"
        );
        let hard = RelayGuard::new(AllowPolicy::Open, &RELAY_HARD_MAX);
        assert_eq!(RELAY_HARD_MAX.relay_config(&hard).max_circuits_per_peer, 7);
        assert_eq!(config.max_circuit_bytes, 2 << 20);
        assert_eq!(config.reservation_rate_limiters.len(), 1, "the guard alone");
        assert_eq!(config.circuit_src_rate_limiters.len(), 1, "the guard alone");
    }

    #[test]
    fn relay_limits_refuse_zero_and_anything_above_the_hard_max() {
        let cases: [fn(&mut RelayLimits); 8] = [
            |l| l.max_reservations = RELAY_HARD_MAX.max_reservations + 1,
            |l| l.max_reservations_per_peer = 3,
            |l| l.max_circuit_bytes = (16 << 20) + 1,
            |l| l.max_circuit_duration = Duration::from_secs(30 * 60 + 1),
            |l| l.reservation_duration = Duration::from_secs(2 * 3600 + 1),
            |l| l.max_circuits = 0,
            |l| l.max_circuit_duration = Duration::ZERO,
            |l| l.max_reservations_per_ip = 200,
        ];
        for (i, edit) in cases.iter().enumerate() {
            let mut l = RelayLimits::friends();
            edit(&mut l);
            assert!(l.validate().is_err(), "case {i}");
        }
    }

    /// Per-IP cap tests: the rate is at its maximum so only the cap decides.
    fn strict(per_ip: usize) -> RelayLimits {
        RelayLimits {
            max_reservations_per_ip: per_ip,
            reservation_rate_per_ip_per_min: RELAY_HARD_MAX.reservation_rate_per_ip_per_min,
            exempt_loopback: false,
            ..RelayLimits::friends()
        }
    }

    /// C10: a peer that is not on the allow-list cannot reserve; an
    /// unreadable allow-list admits nobody; `--open` admits anyone.
    #[test]
    fn allow_list_is_on_by_default_and_fails_closed() {
        let (friend, stranger) = (PeerId::random(), PeerId::random());
        let from = addr("/ip4/198.51.100.7/tcp/4001");
        let guard = RelayGuard::new(
            AllowPolicy::Peers([friend].into_iter().collect()),
            &RelayLimits::friends(),
        );
        assert_eq!(guard.admit(friend, &from), Ok(()));
        assert_eq!(
            guard.admit(stranger, &from),
            Err(ReservationRefusal::NotAllowed)
        );
        let empty = RelayGuard::new(AllowPolicy::Peers(HashSet::new()), &RelayLimits::friends());
        assert_eq!(
            empty.admit(friend, &from),
            Err(ReservationRefusal::NotAllowed)
        );
        let broken = RelayGuard::new(AllowPolicy::Unreadable, &RelayLimits::friends());
        assert_eq!(
            broken.admit(friend, &from),
            Err(ReservationRefusal::AllowListUnreadable)
        );
        let open = RelayGuard::new(AllowPolicy::Open, &RelayLimits::open());
        assert_eq!(open.admit(stranger, &from), Ok(()));
        let c = guard.counts();
        assert_eq!(
            (
                c.allowed_peers,
                c.active_reservations,
                c.refused_not_allowed
            ),
            (1, 1, 1)
        );
        assert!(broken.counts().unreadable && broken.counts().refused_unreadable == 1);
        assert!(open.counts().open);
    }

    /// C10: per-IP reservation cap (IPv6 by /64), renewals do not count
    /// twice, and a closed or timed-out reservation frees its slot.
    #[test]
    fn per_ip_reservation_cap_holds_and_frees_on_close() {
        let guard = RelayGuard::new(AllowPolicy::Open, &strict(2));
        let host = addr("/ip4/198.51.100.7/tcp/4001");
        let other_port = addr("/ip4/198.51.100.7/udp/9/quic-v1");
        let (p1, p2, p3) = (PeerId::random(), PeerId::random(), PeerId::random());
        assert_eq!(guard.admit(p1, &host), Ok(()));
        assert_eq!(guard.admit(p2, &other_port), Ok(()));
        assert_eq!(guard.admit(p3, &host), Err(ReservationRefusal::PerIpCap));
        // Renewal of a peer that already holds one is not a new slot.
        assert_eq!(guard.admit(p1, &host), Ok(()));
        // Another address is its own bucket; one /64 is one bucket.
        assert_eq!(guard.admit(p3, &addr("/ip4/203.0.113.9/tcp/1")), Ok(()));
        let v6 = RelayGuard::new(AllowPolicy::Open, &strict(1));
        assert_eq!(
            v6.admit(PeerId::random(), &addr("/ip6/2001:db8:1:2::1/tcp/1")),
            Ok(())
        );
        assert_eq!(
            v6.admit(PeerId::random(), &addr("/ip6/2001:db8:1:2:ffff::9/tcp/1")),
            Err(ReservationRefusal::PerIpCap)
        );
        // The peer's last connection closing frees the slot (also a
        // timeout); libp2p's ReservationClosed alone does not.
        guard.on_relay_event(&relay::Event::ReservationClosed { src_peer_id: p1 });
        assert_eq!(
            guard.admit(PeerId::random(), &host),
            Err(ReservationRefusal::PerIpCap)
        );
        guard.on_connection_closed(&p1, 0);
        let p4 = PeerId::random();
        assert_eq!(guard.admit(p4, &host), Ok(()));
        guard.on_relay_event(&relay::Event::ReservationTimedOut { src_peer_id: p4 });
        guard.on_relay_event(&relay::Event::ReservationTimedOut { src_peer_id: p4 });
        let p5 = PeerId::random();
        assert_eq!(guard.admit(p5, &host), Ok(()));
        guard.on_peer_disconnected(&p5);
        // A denial libp2p made itself never frees a slot it did not take.
        guard.on_relay_event(&relay::Event::ReservationReqDenied {
            src_peer_id: p2,
            status: relay::StatusCode::ResourceLimitExceeded,
        });
        assert_eq!(guard.admit(PeerId::random(), &host), Ok(()));
        assert_eq!(
            guard.admit(PeerId::random(), &host),
            Err(ReservationRefusal::PerIpCap)
        );
        assert_eq!(guard.counts().refused_per_ip, 3);
        // Loopback is exempt unless configured otherwise.
        let lab = RelayGuard::new(AllowPolicy::Open, &RelayLimits::friends());
        for _ in 0..10 {
            assert_eq!(
                lab.admit(PeerId::random(), &addr("/ip4/127.0.0.1/tcp/1")),
                Ok(())
            );
        }
    }

    /// Phase 0b re-home: a peer whose fresh endpoint reserved again while
    /// the relay still held its old (silent) reservation keeps its slot when
    /// the old one is reaped, and frees it with its last one; a renewal on the
    /// same connection is not one more. libp2p's `ReservationClosed` comes
    /// for every connection that closes, reserved or not: the peer's open
    /// connections bound its count instead.
    #[test]
    fn a_peer_keeps_its_slot_until_its_last_reservation_closes() {
        let guard = RelayGuard::new(AllowPolicy::Open, &strict(1));
        let host = addr("/ip4/198.51.100.7/tcp/4001");
        let peer = PeerId::random();
        let accepted = |renewed| relay::Event::ReservationReqAccepted {
            src_peer_id: peer,
            renewed,
        };
        let closed = relay::Event::ReservationClosed { src_peer_id: peer };
        let taken = |guard: &RelayGuard| {
            guard.counts().active_reservations == 1
                && guard.admit(PeerId::random(), &host) == Err(ReservationRefusal::PerIpCap)
        };
        assert_eq!(guard.admit(peer, &host), Ok(()));
        guard.on_relay_event(&accepted(false));
        // The re-homed endpoint, on a second connection.
        assert_eq!(guard.admit(peer, &host), Ok(()));
        guard.on_relay_event(&accepted(false));
        guard.on_relay_event(&accepted(true));
        // A plain third connection (an AutoNAT dial-back) opens and closes.
        guard.on_relay_event(&closed);
        guard.on_connection_closed(&peer, 2);
        assert!(taken(&guard));
        // The relay reaps the silent old reservation: the slot stays taken.
        guard.on_relay_event(&closed);
        guard.on_connection_closed(&peer, 1);
        assert!(taken(&guard));
        // Another plain connection closes: still one reservation held.
        guard.on_relay_event(&closed);
        guard.on_connection_closed(&peer, 1);
        assert!(taken(&guard));
        // The last one ends: freed.
        guard.on_relay_event(&relay::Event::ReservationTimedOut { src_peer_id: peer });
        assert_eq!(guard.counts().active_reservations, 0);
        assert_eq!(guard.admit(PeerId::random(), &host), Ok(()));
        // Disconnecting frees a slot whatever it held.
        let other = PeerId::random();
        let elsewhere = addr("/ip4/203.0.113.9/tcp/1");
        assert_eq!(guard.admit(other, &elsewhere), Ok(()));
        for _ in 0..2 {
            guard.on_relay_event(&relay::Event::ReservationReqAccepted {
                src_peer_id: other,
                renewed: false,
            });
        }
        guard.on_connection_closed(&other, 0);
        assert_eq!(guard.admit(PeerId::random(), &elsewhere), Ok(()));
        // A peer admitted but not yet accepted keeps its slot while another
        // of its connections closes.
        let pending = PeerId::random();
        let third = addr("/ip4/192.0.2.44/tcp/1");
        assert_eq!(guard.admit(pending, &third), Ok(()));
        guard.on_connection_closed(&pending, 1);
        assert_eq!(
            guard.admit(PeerId::random(), &third),
            Err(ReservationRefusal::PerIpCap)
        );
        guard.on_peer_disconnected(&pending);
        assert_eq!(guard.admit(PeerId::random(), &third), Ok(()));
    }

    /// C10: new reservations per source and minute are capped; renewals and
    /// refused (not allow-listed) requests spend nothing; the bucket refills.
    #[test]
    fn reservation_rate_is_per_source_and_spent_only_on_admissions() {
        let limits = RelayLimits {
            reservation_rate_per_ip_per_min: 2,
            max_reservations_per_ip: 16,
            exempt_loopback: false,
            ..RelayLimits::friends()
        };
        let friends: Vec<PeerId> = (0..4).map(|_| PeerId::random()).collect();
        let guard = RelayGuard::new(
            AllowPolicy::Peers(friends.iter().copied().collect()),
            &limits,
        );
        let from = addr("/ip4/198.51.100.7/tcp/4001");
        let t0 = std::time::Instant::now();
        // Strangers spend nothing.
        for _ in 0..10 {
            assert_eq!(
                guard.admit_at(PeerId::random(), &from, t0),
                Err(ReservationRefusal::NotAllowed)
            );
        }
        assert_eq!(guard.admit_at(friends[0], &from, t0), Ok(()));
        assert_eq!(guard.admit_at(friends[1], &from, t0), Ok(()));
        // Renewal of an active one is free.
        assert_eq!(guard.admit_at(friends[0], &from, t0), Ok(()));
        assert_eq!(
            guard.admit_at(friends[2], &from, t0),
            Err(ReservationRefusal::PerIpRate)
        );
        // Another source has its own bucket; 30 s later one token is back.
        assert_eq!(
            guard.admit_at(friends[3], &addr("/ip4/203.0.113.1/tcp/1"), t0),
            Ok(())
        );
        let later = t0 + Duration::from_secs(31);
        assert_eq!(guard.admit_at(friends[2], &from, later), Ok(()));
        assert_eq!(guard.counts().refused_rate, 1);
        // Loopback is exempt by default (same-host tools and harnesses).
        let lab = RelayGuard::new(AllowPolicy::Open, &RelayLimits::friends());
        for _ in 0..20 {
            assert_eq!(
                lab.admit_at(PeerId::random(), &addr("/ip4/127.0.0.1/tcp/1"), t0),
                Ok(())
            );
        }
    }

    #[test]
    fn reloading_the_allow_list_names_the_peers_to_drop() {
        let (a, b) = (PeerId::random(), PeerId::random());
        let from = addr("/ip4/198.51.100.7/tcp/4001");
        let guard = RelayGuard::new(
            AllowPolicy::Peers([a, b].into_iter().collect()),
            &RelayLimits::friends(),
        );
        guard.admit(a, &from).unwrap();
        guard.admit(b, &addr("/ip4/198.51.100.8/tcp/1")).unwrap();
        let drop = guard.set_policy(AllowPolicy::Peers([a].into_iter().collect()));
        assert_eq!(drop, vec![b]);
        assert_eq!(
            guard.admit(b, &from),
            Err(ReservationRefusal::NotAllowed),
            "a denied peer cannot renew"
        );
        let mut drop = guard.set_policy(AllowPolicy::Unreadable);
        drop.sort();
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(drop, want);
    }

    // ── In-process relay + two endpoints over loopback ───────────────────

    struct Lab {
        relay: Swarm<RelayBehaviour>,
        relay_addr: Multiaddr,
        guard: RelayGuard,
        /// Every relay protocol event (its Debug text).
        relay_events: Vec<String>,
        /// The peers the relay's Identify heard from.
        identified: Vec<PeerId>,
        /// What the relay saw of its connections.
        conns: ConnLog,
    }

    /// One thing the relay saw of a connection.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Seen {
        /// `SwarmEvent::ConnectionEstablished` on the relay.
        Opened(PeerId, ConnectionId),
        /// `SwarmEvent::ConnectionClosed` on the relay (the guard was fed).
        Closed(PeerId, ConnectionId),
        /// libp2p-relay's `ReservationClosed` (the guard was fed): one per
        /// closed connection of the peer, reserved or not, queued at its
        /// close and so reported after its `Closed`.
        ReservationClosed(PeerId),
        /// `SwarmEvent::IncomingConnectionError`: a connection that closed
        /// before the relay had established it (libp2p-relay never saw it).
        Failed(ConnectionId),
    }

    /// The relay's connection history, oldest first. Shared, so a [`drive`]
    /// condition reads it while the lab is borrowed.
    #[derive(Debug, Clone, Default)]
    struct ConnLog(Arc<Mutex<Vec<Seen>>>);

    impl ConnLog {
        fn push(&self, seen: Seen) {
            self.0.lock().unwrap().push(seen);
        }

        /// The relay's connections from `peer` (open or closed), oldest first.
        fn opened(&self, peer: &PeerId) -> Vec<ConnectionId> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter_map(|s| match s {
                    Seen::Opened(p, c) if p == peer => Some(*c),
                    _ => None,
                })
                .collect()
        }

        /// Has the relay closed its connection `conn` from `peer` and fed
        /// the guard everything that close produces: the `ConnectionClosed`
        /// and libp2p-relay's `ReservationClosed` after it?
        fn settled(&self, peer: &PeerId, conn: ConnectionId) -> bool {
            let log = self.0.lock().unwrap();
            let Some(at) = log.iter().position(|s| *s == Seen::Closed(*peer, conn)) else {
                return false;
            };
            let closes = log[..=at]
                .iter()
                .filter(|s| matches!(s, Seen::Closed(p, _) if p == peer))
                .count();
            let reports = log
                .iter()
                .filter(|s| **s == Seen::ReservationClosed(*peer))
                .count();
            reports >= closes
        }
    }

    /// The relay's key seed ([`relay_peer`]).
    const RELAY_SEED: u8 = 0xA1;

    fn peer_of(seed: u8) -> PeerId {
        key(seed).public().to_peer_id()
    }

    /// The PeerId of every [`relay_lab`] relay.
    fn relay_peer() -> PeerId {
        peer_of(RELAY_SEED)
    }

    /// Listen on a loopback TCP port and return the address.
    async fn listen_loopback<B: NetworkBehaviour>(swarm: &mut Swarm<B>) -> Multiaddr {
        listen_at(swarm, "/ip4/127.0.0.1/tcp/0").await
    }

    /// Listen on a loopback QUIC port and return the address.
    async fn listen_quic_loopback<B: NetworkBehaviour>(swarm: &mut Swarm<B>) -> Multiaddr {
        listen_at(swarm, "/ip4/127.0.0.1/udp/0/quic-v1").await
    }

    async fn listen_at<B: NetworkBehaviour>(swarm: &mut Swarm<B>, at: &str) -> Multiaddr {
        swarm.listen_on(addr(at)).expect("listen");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                    return address;
                }
            }
        })
        .await
        .expect("listen timeout")
    }

    async fn relay_lab(limits: RelayLimits, policy: AllowPolicy) -> Lab {
        let guard = RelayGuard::new(policy, &limits);
        let mut relay =
            build_relay_swarm(&gate(), key(RELAY_SEED), limits, &guard, false, false, None)
                .unwrap();
        let relay_addr = listen_loopback(&mut relay).await;
        relay.add_external_address(relay_addr.clone());
        let relay_addr = relay_addr.with(Protocol::P2p(*relay.local_peer_id()));
        Lab {
            relay,
            relay_addr,
            guard,
            relay_events: Vec::new(),
            identified: Vec::new(),
            conns: ConnLog::default(),
        }
    }

    impl Lab {
        /// `peer` through this relay.
        fn circuit_to(&self, peer: PeerId) -> Multiaddr {
            self.relay_addr
                .clone()
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(peer))
        }

        /// One relay event: the guard is fed, the rest recorded.
        fn on_event(&mut self, event: SwarmEvent<RelayBehaviourEvent>) {
            match event {
                SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(e)) => {
                    self.guard.on_relay_event(&e);
                    if let relay::Event::ReservationClosed { src_peer_id } = &e {
                        self.conns.push(Seen::ReservationClosed(*src_peer_id));
                    }
                    self.relay_events.push(format!("{e:?}"));
                }
                SwarmEvent::Behaviour(RelayBehaviourEvent::Identify(
                    identify::Event::Received { peer_id, .. },
                )) => self.identified.push(peer_id),
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    connection_id,
                    ..
                } => self.conns.push(Seen::Opened(peer_id, connection_id)),
                SwarmEvent::ConnectionClosed {
                    peer_id,
                    connection_id,
                    num_established,
                    ..
                } => {
                    self.guard.on_connection_closed(&peer_id, num_established);
                    self.conns.push(Seen::Closed(peer_id, connection_id));
                }
                SwarmEvent::IncomingConnectionError { connection_id, .. } => {
                    self.conns.push(Seen::Failed(connection_id));
                }
                _ => {}
            }
        }
    }

    /// No AutoNAT server: neither AutoNAT client ever asks anyone.
    const NO_SERVERS: [Option<PeerId>; 2] = [None, None];

    /// A peer-gate set; a peer named twice gets both classes.
    fn admitted(admit: &[(PeerId, PeerClass)]) -> GateHandle {
        let mut files: HashMap<PeerId, PeerClass> = HashMap::new();
        for (peer, class) in admit {
            *files.entry(*peer).or_default() |= *class;
        }
        let handle = GateHandle::default();
        handle.replace(files, false, Instant::now());
        handle
    }

    /// An endpoint whose peer gate admits `admit` and nobody else.
    fn endpoint_with(
        seed: u8,
        admit: &[(PeerId, PeerClass)],
        rule: AddrRule,
        autonat_servers: [Option<PeerId>; 2],
    ) -> Swarm<EndpointBehaviour> {
        let config = EndpointConfig {
            gate: admitted(admit),
            hole_punch_addrs: rule,
            autonat_servers,
            ..EndpointConfig::default()
        };
        build_endpoint_swarm(&gate(), key(seed), config).unwrap()
    }

    /// An endpoint that admits nobody (for tests of other parts).
    fn lone_endpoint(seed: u8) -> Swarm<EndpointBehaviour> {
        endpoint_with(seed, &[], AddrRule::GlobalOnly, NO_SERVERS)
    }

    /// A circuit pair through the [`relay_lab`] relay: `a` reserves on it
    /// (its own relay) and admits `b` as a contact; `b` admits `a` as a
    /// contact and the relay as `a`'s relay.
    fn circuit_pair(
        a_seed: u8,
        b_seed: u8,
        rule: AddrRule,
    ) -> (Swarm<EndpointBehaviour>, Swarm<EndpointBehaviour>) {
        let (a, b, r) = (peer_of(a_seed), peer_of(b_seed), relay_peer());
        (
            endpoint_with(
                a_seed,
                &[(r, PeerClass::OWN_RELAY), (b, PeerClass::CONTACT)],
                rule,
                NO_SERVERS,
            ),
            endpoint_with(
                b_seed,
                &[(a, PeerClass::CONTACT), (r, PeerClass::CONTACT_RELAY)],
                rule,
                NO_SERVERS,
            ),
        )
    }

    /// Show `behaviour` a candidate, as Identify would.
    fn candidate(behaviour: &mut impl NetworkBehaviour, address: &Multiaddr) {
        behaviour.on_swarm_event(FromSwarm::NewExternalAddrCandidate(
            NewExternalAddrCandidate { addr: address },
        ));
    }

    /// The gate refusal an endpoint event reports, if it is one.
    fn gate_refusal(event: &SwarmEvent<EndpointBehaviourEvent>) -> Option<PeerNotAdmitted> {
        match event {
            SwarmEvent::IncomingConnectionError {
                error: ListenError::Denied { cause },
                ..
            }
            | SwarmEvent::OutgoingConnectionError {
                error: DialError::Denied { cause },
                ..
            } => cause.downcast_ref::<PeerNotAdmitted>().copied(),
            _ => None,
        }
    }

    /// Drive the relay (feeding the guard) and the endpoints until `done`
    /// picks a value: from an endpoint event (`Some((index, event))`), or on a
    /// 50 ms tick (`None`). At most 15 s; a timeout panics with what the
    /// relay saw of its connections and what everyone reported.
    async fn drive<T>(
        lab: &mut Lab,
        eps: &mut [&mut Swarm<EndpointBehaviour>],
        mut done: impl FnMut(Option<(usize, SwarmEvent<EndpointBehaviourEvent>)>) -> Option<T>,
    ) -> T {
        let mut seen: Vec<String> = Vec::new();
        let outcome = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let mut next = futures::future::select_all(
                    eps.iter_mut()
                        .map(|s| Box::pin(s.select_next_some()))
                        .collect::<Vec<_>>(),
                );
                tokio::select! {
                    event = lab.relay.select_next_some() => lab.on_event(event),
                    (event, i, _) = &mut next => {
                        seen.push(format!("{i}: {event:?}"));
                        if let Some(v) = done(Some((i, event))) {
                            return v;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {
                        if let Some(v) = done(None) {
                            return v;
                        }
                    }
                }
            }
        })
        .await;
        match outcome {
            Ok(v) => v,
            Err(_) => panic!(
                "relay lab timed out\nconnections: {:?}\nrelay events: {:#?}\nendpoint events: {:#?}",
                lab.conns.0.lock().unwrap(),
                lab.relay_events,
                seen
            ),
        }
    }

    fn reserve(ep: &mut Swarm<EndpointBehaviour>, relay: &Multiaddr) {
        ep.listen_on(relay.clone().with(Protocol::P2pCircuit))
            .expect("reservation listen");
    }

    fn accepted(event: &SwarmEvent<EndpointBehaviourEvent>) -> bool {
        matches!(
            event,
            SwarmEvent::Behaviour(EndpointBehaviourEvent::RelayClient(
                relay::client::Event::ReservationReqAccepted { .. }
            ))
        )
    }

    /// C10 end to end: an allow-listed peer gets a reservation; a peer that
    /// is not on the list is refused at the relay's peer gate (its
    /// reservation listener closes), so its request never reaches the relay
    /// protocol or the guard.
    #[tokio::test]
    async fn a_peer_off_the_allow_list_cannot_reserve() {
        let own_relay = [(relay_peer(), PeerClass::OWN_RELAY)];
        let mut ok = endpoint_with(0xB1, &own_relay, AddrRule::GlobalOnly, NO_SERVERS);
        let mut stranger = endpoint_with(0xB2, &own_relay, AddrRule::GlobalOnly, NO_SERVERS);
        let policy = AllowPolicy::Peers([*ok.local_peer_id()].into_iter().collect());
        let mut lab = relay_lab(RelayLimits::friends(), policy).await;
        let relay_addr = lab.relay_addr.clone();
        reserve(&mut ok, &relay_addr);
        drive(&mut lab, &mut [&mut ok], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        reserve(&mut stranger, &relay_addr);
        drive(&mut lab, &mut [&mut ok, &mut stranger], |e| {
            let (i, e) = e?;
            assert!(!(i == 1 && accepted(&e)), "stranger got a reservation");
            (i == 1 && matches!(e, SwarmEvent::ListenerClosed { .. })).then_some(())
        })
        .await;
        assert!(lab.relay.behaviour().peer_gate.counts().refused_inbound >= 1);
        let c = lab.guard.counts();
        assert_eq!(
            c.refused_not_allowed, 0,
            "refused before the relay protocol"
        );
        assert_eq!(c.active_reservations, 1);
    }

    /// What a failed dial to `peer` said ([`dial_failures`]), when `event`
    /// is that failure.
    fn failures_to(
        event: &SwarmEvent<EndpointBehaviourEvent>,
        peer: PeerId,
    ) -> Option<Vec<Failed>> {
        match event {
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(p),
                error,
                ..
            } if *p == peer => Some(dial_failures(error)),
            _ => None,
        }
    }

    /// [`crate::diag`] against a real relay, through the locked libp2p's
    /// error chain. A circuit to B through R: (a) B never reserved:
    /// NotOnRelay; (b) B reserved, then its swarm went away: NotOnRelay, at
    /// once; (c) through a relay that is gone (port closed): NoAnswer, and
    /// the relay client's own dial to it fails as well. (d) A direct address
    /// nobody listens on: Refused. (e) The relay an address names. A source
    /// R does not serve: (f) refused by R's circuit limiter for membership:
    /// Busy, as for its caps and rates (RESOURCE_LIMIT_EXCEEDED); (g)
    /// refused by R's peer gate: its connection is closed right after Noise
    /// and no answer comes back (raven-node notes that quick close itself).
    #[tokio::test]
    async fn circuit_failures_say_what_the_relay_answered() {
        const GONE_RELAY_SEED: u8 = 0xA2;
        let r = relay_peer();
        let (a_peer, b_peer, gone) = (peer_of(0x94), peer_of(0x95), peer_of(GONE_RELAY_SEED));
        let mut lab = relay_lab(
            RelayLimits::friends(),
            AllowPolicy::Peers([a_peer, b_peer].into_iter().collect()),
        )
        .await;
        let relay_addr = lab.relay_addr.clone();
        // A and the stranger hold B's card: B is their contact, R and the
        // relay that will be gone are B's relays.
        let holds_b = [
            (b_peer, PeerClass::CONTACT),
            (r, PeerClass::CONTACT_RELAY),
            (gone, PeerClass::CONTACT_RELAY),
        ];
        let mut a = endpoint_with(0x94, &holds_b, AddrRule::GlobalOnly, NO_SERVERS);
        let to_b = move |e: Option<(usize, SwarmEvent<EndpointBehaviourEvent>)>| {
            e.and_then(|(_, e)| failures_to(&e, b_peer))
        };
        let on_r = |outcome| [Failed::Circuit { relay: r, outcome }];

        // (a) B never reserved on R.
        a.dial(lab.circuit_to(b_peer)).unwrap();
        assert_eq!(
            drive(&mut lab, &mut [&mut a], to_b).await,
            on_r(CircuitOutcome::NotOnRelay)
        );

        // (b) B reserves, then its swarm goes away: R drops the reservation
        // with its connection, or its STOP to B fails (CONNECTION_FAILED).
        let mut b = endpoint_with(
            0x95,
            &[(a_peer, PeerClass::CONTACT), (r, PeerClass::OWN_RELAY)],
            AddrRule::GlobalOnly,
            NO_SERVERS,
        );
        assert!(reserves(&mut lab, &mut b).await);
        drop(b);
        let asked = Instant::now();
        a.dial(lab.circuit_to(b_peer)).unwrap();
        assert_eq!(
            drive(&mut lab, &mut [&mut a], to_b).await,
            on_r(CircuitOutcome::NotOnRelay)
        );
        assert!(
            asked.elapsed() < Duration::from_secs(5),
            "{:?}",
            asked.elapsed()
        );

        // (c) A relay that is gone: its swarm dropped, its port closed.
        let gone_addr = {
            let guard = RelayGuard::new(AllowPolicy::Open, &RelayLimits::friends());
            let mut relay = build_relay_swarm(
                &gate(),
                key(GONE_RELAY_SEED),
                RelayLimits::friends(),
                &guard,
                false,
                false,
                None,
            )
            .unwrap();
            listen_loopback(&mut relay).await.with(Protocol::P2p(gone))
        };
        a.dial(
            gone_addr
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(b_peer)),
        )
        .unwrap();
        let (mut relay_dial, mut circuit) = (None, None);
        drive(&mut lab, &mut [&mut a], |e| {
            if let Some((_, e)) = &e {
                if relay_dial.is_none() {
                    relay_dial = failures_to(e, gone);
                }
                if circuit.is_none() {
                    circuit = failures_to(e, b_peer);
                }
            }
            (relay_dial.is_some() && circuit.is_some()).then_some(())
        })
        .await;
        assert_eq!(
            circuit.unwrap(),
            [Failed::Circuit {
                relay: gone,
                outcome: CircuitOutcome::NoAnswer
            }]
        );
        assert_eq!(relay_dial.unwrap(), [Failed::Direct(AddrOutcome::Refused)]);

        // (d) A direct address nobody listens on.
        let closed = free_loopback_port();
        a.dial(addr(&format!("/ip4/127.0.0.1/tcp/{closed}/p2p/{b_peer}")))
            .unwrap();
        assert_eq!(
            drive(&mut lab, &mut [&mut a], to_b).await,
            [Failed::Direct(AddrOutcome::Refused)]
        );

        // (e) The last peer before the first `/p2p-circuit`; none for a
        // direct address or a circuit that names no relay.
        assert_eq!(circuit_relay(&lab.circuit_to(b_peer)), Some(r));
        assert_eq!(
            circuit_relay(&relay_addr.clone().with(Protocol::P2pCircuit)),
            Some(r)
        );
        assert_eq!(circuit_relay(&relay_addr), None);
        assert_eq!(
            circuit_relay(&addr(&format!("/ip4/127.0.0.1/tcp/4001/p2p/{b_peer}"))),
            None
        );
        assert_eq!(
            circuit_relay(&addr(&format!(
                "/ip4/127.0.0.1/tcp/4001/p2p-circuit/p2p/{b_peer}"
            ))),
            None
        );
        assert_eq!(circuit_relay(&addr("/p2p-circuit")), None);

        // (f) A holds a connection R admitted; then R's allow-list is
        // reloaded without A, and nothing here rechecks that connection:
        // R's circuit limiter refuses A's circuit for membership.
        connect_from_a_new_port(&mut lab, &mut a).await;
        let members = AllowPolicy::Peers([b_peer].into_iter().collect());
        assert!(lab.guard.set_policy(members).is_empty());
        a.dial(lab.circuit_to(b_peer)).unwrap();
        assert_eq!(
            drive(&mut lab, &mut [&mut a], to_b).await,
            on_r(CircuitOutcome::Busy)
        );
        assert_eq!(lab.guard.counts().refused_circuit_not_allowed, 1);

        // (g) A stranger to R: its peer gate closes the connection before
        // the relay protocol sees it.
        let mut s = endpoint_with(0x96, &holds_b, AddrRule::GlobalOnly, NO_SERVERS);
        let refused = lab.relay.behaviour().peer_gate.counts().refused_inbound;
        s.dial(lab.circuit_to(b_peer)).unwrap();
        let (mut closed_at_once, mut circuit) = (false, None);
        drive(&mut lab, &mut [&mut s], |e| {
            match &e {
                Some((
                    _,
                    SwarmEvent::ConnectionClosed {
                        peer_id,
                        cause: Some(_),
                        ..
                    },
                )) if *peer_id == r => closed_at_once = true,
                Some((_, e)) if circuit.is_none() => circuit = failures_to(e, b_peer),
                _ => {}
            }
            (closed_at_once && circuit.is_some()).then_some(())
        })
        .await;
        assert_eq!(circuit.unwrap(), on_r(CircuitOutcome::NoAnswer));
        assert_eq!(
            lab.relay.behaviour().peer_gate.counts().refused_inbound,
            refused + 1
        );
        assert_eq!(
            lab.guard.counts().refused_circuit_not_allowed,
            1,
            "the stranger never reached R's circuit limiter"
        );
        let s_text = s.local_peer_id().to_string();
        assert!(
            !lab.relay_events.iter().any(|e| e.contains(&s_text)),
            "{:?}",
            lab.relay_events
        );
    }

    /// Phase 0b re-home: a fresh endpoint with the same key reserves on the
    /// same relay at once while the old one (never polled again: its network
    /// is gone) still holds its reservation; a third is refused (two per
    /// peer, [`RelayLimits::friends`]).
    #[tokio::test]
    async fn a_fresh_endpoint_reserves_again_while_the_old_one_still_holds_its_reservation() {
        let own_relay = [(relay_peer(), PeerClass::OWN_RELAY)];
        let mut old = endpoint_with(0xC1, &own_relay, AddrRule::GlobalOnly, NO_SERVERS);
        let policy = AllowPolicy::Peers([*old.local_peer_id()].into_iter().collect());
        let mut lab = relay_lab(RelayLimits::friends(), policy).await;
        let relay_addr = lab.relay_addr.clone();
        reserve(&mut old, &relay_addr);
        drive(&mut lab, &mut [&mut old], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        let mut fresh = endpoint_with(0xC1, &own_relay, AddrRule::GlobalOnly, NO_SERVERS);
        reserve(&mut fresh, &relay_addr);
        drive(&mut lab, &mut [&mut fresh], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        // The guard counts peers: both reservations are this one PeerId's.
        assert_eq!(lab.guard.counts().active_reservations, 1);
        let mut third = endpoint_with(0xC1, &own_relay, AddrRule::GlobalOnly, NO_SERVERS);
        reserve(&mut third, &relay_addr);
        drive(&mut lab, &mut [&mut third], |e| {
            let (_, e) = e?;
            assert!(!accepted(&e), "a third reservation for one peer");
            matches!(e, SwarmEvent::ListenerClosed { .. }).then_some(())
        })
        .await;
    }

    /// Open a plain connection from `ep` to the relay, from a new local
    /// port, and drive both until each end has it. Returns the endpoint's
    /// id for it and the relay's.
    ///
    /// Both ends: the endpoint reports the connection established as soon
    /// as its own side of the upgrade is done, while the relay may still be
    /// finishing its side. Closed then, the relay reports an
    /// `IncomingConnectionError` instead of a `ConnectionClosed`, and
    /// libp2p-relay, which never knew the connection, no `ReservationClosed`.
    async fn open_a_plain_connection(
        lab: &mut Lab,
        ep: &mut Swarm<EndpointBehaviour>,
    ) -> (ConnectionId, ConnectionId) {
        use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
        let peer = *ep.local_peer_id();
        let known = lab.conns.opened(&peer).len();
        let opts = DialOpts::peer_id(relay_peer())
            .addresses(vec![lab.relay_addr.clone()])
            .condition(PeerCondition::Always)
            .allocate_new_port()
            .build();
        let id = opts.connection_id();
        ep.dial(opts).unwrap();
        let conns = lab.conns.clone();
        let mut ours = false;
        let theirs = drive(lab, &mut [&mut *ep], |e| {
            match e {
                Some((_, SwarmEvent::ConnectionEstablished { connection_id, .. }))
                    if connection_id == id =>
                {
                    ours = true;
                }
                Some((
                    _,
                    SwarmEvent::OutgoingConnectionError {
                        connection_id,
                        error,
                        ..
                    },
                )) if connection_id == id => {
                    panic!("the plain dial failed: {error}");
                }
                Some((
                    _,
                    SwarmEvent::ConnectionClosed {
                        connection_id,
                        cause,
                        ..
                    },
                )) if connection_id == id => {
                    panic!("the plain connection closed on its own: {cause:?}");
                }
                _ => {}
            }
            // The relay's side of it: the peer's first connection after the
            // ones the relay already had.
            let theirs = conns.opened(&peer).get(known).copied();
            theirs.filter(|_| ours)
        })
        .await;
        (id, theirs)
    }

    /// Open a plain extra connection from `ep` to the relay (as an AutoNAT
    /// v2 dial-back, a simultaneous dial or any other second connection
    /// is), close it once both ends have it ([`open_a_plain_connection`]:
    /// closed earlier, the close the tests are about never happens), and
    /// drive the relay until the guard has seen everything that close
    /// produces.
    async fn open_and_close_a_plain_connection(lab: &mut Lab, ep: &mut Swarm<EndpointBehaviour>) {
        let peer = *ep.local_peer_id();
        let (id, theirs) = open_a_plain_connection(lab, ep).await;
        assert!(ep.close_connection(id));
        let conns = lab.conns.clone();
        drive(lab, &mut [&mut *ep], |_| {
            conns.settled(&peer, theirs).then_some(())
        })
        .await;
    }

    /// For an endpoint that listens: its connection to the relay, from a
    /// new local port, before it reserves or dials a circuit (the relay
    /// client then uses this one). The relay client's own dial goes from
    /// the listen port (libp2p's port reuse), and on a machine busy with
    /// loopback tests some other socket may still hold exactly that 4-tuple:
    /// macOS refuses the dial ("address in use") and libp2p-tcp falls back
    /// to a new port only on Linux's error. raven-node dials from a new port
    /// itself where that matters; these tests are about what comes after.
    async fn connect_from_a_new_port(lab: &mut Lab, ep: &mut Swarm<EndpointBehaviour>) {
        open_a_plain_connection(lab, ep).await;
    }

    /// Whether `peer` gets a reservation on the lab relay (or is refused).
    async fn reserves(lab: &mut Lab, ep: &mut Swarm<EndpointBehaviour>) -> bool {
        let relay_addr = lab.relay_addr.clone();
        reserve(ep, &relay_addr);
        drive(lab, &mut [ep], |e| {
            let (_, e) = e?;
            if accepted(&e) {
                return Some(true);
            }
            matches!(e, SwarmEvent::ListenerClosed { .. }).then_some(false)
        })
        .await
    }

    /// libp2p-relay reports `ReservationClosed` for every connection of a
    /// peer that closes, reserved or not: a plain extra connection that
    /// closes must not free the slot of the reservation the peer still
    /// holds on its first one (the per-IP cap holds).
    #[tokio::test]
    async fn a_plain_extra_connection_closing_keeps_the_reservation_counted() {
        let own_relay = [(relay_peer(), PeerClass::OWN_RELAY)];
        let mut a = endpoint_with(0xC6, &own_relay, AddrRule::GlobalOnly, NO_SERVERS);
        let mut b = endpoint_with(0xC7, &own_relay, AddrRule::GlobalOnly, NO_SERVERS);
        let mut lab = relay_lab(strict(1), AllowPolicy::Open).await;
        assert!(reserves(&mut lab, &mut a).await);
        assert_eq!(lab.guard.counts().active_reservations, 1);
        open_and_close_a_plain_connection(&mut lab, &mut a).await;
        assert!(
            a.is_connected(&relay_peer()),
            "the reserved connection stays"
        );
        assert_eq!(lab.guard.counts().active_reservations, 1);
        assert!(!reserves(&mut lab, &mut b).await, "B past the per-IP cap");
        assert_eq!(lab.guard.counts().refused_per_ip, 1);
    }

    /// Phase 0b re-home with an extra connection: the peer holds its old
    /// and its new reservation, a plain extra connection closes, then the
    /// old endpoint's connection goes: the new reservation still holds the
    /// slot.
    #[tokio::test]
    async fn a_rehomed_peer_keeps_its_slot_through_an_extra_close_and_the_reap() {
        let own_relay = [(relay_peer(), PeerClass::OWN_RELAY)];
        let mut old = endpoint_with(0xC8, &own_relay, AddrRule::GlobalOnly, NO_SERVERS);
        let mut fresh = endpoint_with(0xC8, &own_relay, AddrRule::GlobalOnly, NO_SERVERS);
        let mut other = endpoint_with(0xC9, &own_relay, AddrRule::GlobalOnly, NO_SERVERS);
        let mut lab = relay_lab(strict(1), AllowPolicy::Open).await;
        let peer = *old.local_peer_id();
        assert!(reserves(&mut lab, &mut old).await);
        assert!(reserves(&mut lab, &mut fresh).await);
        assert_eq!(lab.guard.counts().active_reservations, 1);
        // The relay's side of each reservation's connection, in order.
        let [old_conn, _fresh_conn] = lab.conns.opened(&peer)[..] else {
            panic!("one connection per endpoint: {:?}", lab.conns);
        };
        open_and_close_a_plain_connection(&mut lab, &mut fresh).await;
        assert_eq!(lab.guard.counts().active_reservations, 1);
        // The old endpoint is gone; the relay reaps its connection.
        drop(old);
        let conns = lab.conns.clone();
        drive(&mut lab, &mut [&mut fresh], |_| {
            conns.settled(&peer, old_conn).then_some(())
        })
        .await;
        assert!(fresh.is_connected(&relay_peer()));
        assert_eq!(lab.guard.counts().active_reservations, 1);
        assert!(!reserves(&mut lab, &mut other).await, "past the per-IP cap");
    }

    /// Open a `/raven/link/1.0.0` stream from `b` to `a` (reserved on the
    /// relay) over the circuit, and return both ends.
    async fn circuit_stream(
        lab: &mut Lab,
        a: &mut Swarm<EndpointBehaviour>,
        b: &mut Swarm<EndpointBehaviour>,
    ) -> (libp2p::Stream, libp2p::Stream) {
        let a_peer = *a.local_peer_id();
        let mut incoming = a
            .behaviour()
            .stream
            .new_control()
            .accept(RAVEN_LINK_PROTOCOL)
            .unwrap();
        let mut control = b.behaviour().stream.new_control();
        b.dial(lab.circuit_to(a_peer)).unwrap();
        let opened = tokio::spawn(async move {
            control
                .open_stream(a_peer, RAVEN_LINK_PROTOCOL)
                .await
                .map_err(|e| e.to_string())
        });
        let accepted_stream = tokio::spawn(async move { incoming.next().await.map(|(_, s)| s) });
        drive(lab, &mut [a, b], |_| {
            (opened.is_finished() && accepted_stream.is_finished()).then_some(())
        })
        .await;
        let out = opened.await.unwrap().expect("open stream over the circuit");
        let inn = accepted_stream.await.unwrap().expect("inbound stream");
        (out, inn)
    }

    /// C10: a circuit that carries more than `max_circuit_bytes` is cut by
    /// the relay; well below the cap the bytes flow.
    #[tokio::test]
    async fn circuit_byte_cap_cuts_the_circuit() {
        let limits = RelayLimits {
            max_circuit_bytes: 64 << 10,
            ..RelayLimits::friends()
        };
        let (mut a, mut b) = circuit_pair(0xC1, 0xC2, AddrRule::GlobalOnly);
        let mut lab = relay_lab(limits, AllowPolicy::Open).await;
        let relay_addr = lab.relay_addr.clone();
        reserve(&mut a, &relay_addr);
        drive(&mut lab, &mut [&mut a], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        let (mut out, mut inn) = circuit_stream(&mut lab, &mut a, &mut b).await;
        // Small exchange first: within the cap.
        let pump = tokio::spawn(async move {
            out.write_all(b"ping").await.unwrap();
            out.flush().await.unwrap();
            let mut buf = [0u8; 4];
            inn.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            // Now far beyond the cap: the relay closes the circuit.
            let chunk = vec![0x5a; 16 << 10];
            let writer = async {
                for _ in 0..64 {
                    if out.write_all(&chunk).await.is_err() || out.flush().await.is_err() {
                        return true;
                    }
                }
                false
            };
            let reader = async {
                let mut total = 0usize;
                let mut buf = vec![0u8; 16 << 10];
                loop {
                    match inn.read(&mut buf).await {
                        Ok(0) | Err(_) => return total,
                        Ok(n) => total += n,
                    }
                }
            };
            let (write_failed, received) = futures::join!(writer, reader);
            (write_failed, received)
        });
        drive(&mut lab, &mut [&mut a, &mut b], |_| {
            pump.is_finished().then_some(())
        })
        .await;
        let (write_failed, received) = pump.await.unwrap();
        assert!(received < 64 * (16 << 10), "the whole megabyte got through");
        assert!(received <= (64 << 10) + (16 << 10), "received {received}");
        let _ = write_failed;
    }

    /// C10: a circuit that lives longer than `max_circuit_duration` is closed
    /// by the relay.
    #[tokio::test]
    async fn circuit_duration_cap_closes_the_circuit() {
        let limits = RelayLimits {
            max_circuit_duration: Duration::from_secs(2),
            ..RelayLimits::friends()
        };
        let (mut a, mut b) = circuit_pair(0xD1, 0xD2, AddrRule::GlobalOnly);
        let mut lab = relay_lab(limits, AllowPolicy::Open).await;
        let relay_addr = lab.relay_addr.clone();
        reserve(&mut a, &relay_addr);
        drive(&mut lab, &mut [&mut a], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        let started = std::time::Instant::now();
        let (_out, mut inn) = circuit_stream(&mut lab, &mut a, &mut b).await;
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                match inn.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        });
        drive(&mut lab, &mut [&mut a, &mut b], |_| {
            reader.is_finished().then_some(())
        })
        .await;
        let lived = started.elapsed();
        assert!(
            lived >= Duration::from_secs(1),
            "closed too early: {lived:?}"
        );
        assert!(lived < Duration::from_secs(12), "not closed: {lived:?}");
    }

    /// Review item 3: the rate table of an `--open` relay is bounded (the
    /// oldest source goes first) and pruned on the timer, not on every
    /// request.
    #[test]
    fn rate_tables_are_bounded_and_pruned_on_the_timer() {
        let limits = RelayLimits {
            reservation_rate_per_ip_per_min: 60,
            circuit_rate_per_ip_per_min: 60,
            max_reservations: 1024,
            max_reservations_per_ip: 16,
            exempt_loopback: false,
            ..RelayLimits::open()
        };
        let guard = RelayGuard::new(AllowPolicy::Open, &limits);
        // `--open`: every source may use the relay; only the rate decides.
        let anyone = PeerId::random();
        let t0 = Instant::now();
        let src = |i: usize| {
            addr(&format!(
                "/ip4/10.{}.{}.{}/tcp/1",
                i >> 16,
                (i >> 8) & 0xff,
                i & 0xff
            ))
        };
        for i in 0..(MAX_RATE_SOURCES + 100) {
            let _ = guard.admit_circuit_at(&anyone, &src(i), t0);
        }
        assert_eq!(guard.rate_sources().1, MAX_RATE_SOURCES, "bounded");
        // The oldest were forgotten: they get a fresh, full bucket again.
        for _ in 0..60 {
            assert!(guard.admit_circuit_at(&anyone, &src(0), t0));
        }
        assert!(
            !guard.admit_circuit_at(&anyone, &src(0), t0),
            "now that one is spent"
        );
        // Pruning keeps the buckets that are still refilling, drops full ones.
        guard.prune_at(t0 + Duration::from_secs(1));
        assert!(guard.rate_sources().1 >= 1);
        guard.prune_at(t0 + Duration::from_secs(120));
        assert_eq!(guard.rate_sources(), (0, 0));
        // IPv6: one /64 is one source (libp2p's own limiter keys on /128).
        let small = RelayLimits {
            circuit_rate_per_ip_per_min: 2,
            exempt_loopback: false,
            ..RelayLimits::friends()
        };
        let g = RelayGuard::new(AllowPolicy::Open, &small);
        assert!(g.admit_circuit_at(&anyone, &addr("/ip6/2001:db8:1:2::1/tcp/1"), t0));
        assert!(g.admit_circuit_at(&anyone, &addr("/ip6/2001:db8:1:2::2/tcp/1"), t0));
        assert!(!g.admit_circuit_at(&anyone, &addr("/ip6/2001:db8:1:2:ffff::3/tcp/1"), t0));
        assert!(g.admit_circuit_at(&anyone, &addr("/ip6/2001:db8:1:3::1/tcp/1"), t0));
        assert_eq!(g.counts().refused_circuit_rate, 1);
    }

    /// The per-family wrappers give raven-core's one rule
    /// (`raven_core::p2p_route::is_global_ip`, which RRH1 route hints use).
    fn same_rule_as_raven_core(ip: &str) -> bool {
        let ip: IpAddr = ip.parse().unwrap();
        let family = match ip {
            IpAddr::V4(v4) => is_global_ipv4(v4),
            IpAddr::V6(v6) => is_global_ipv6(v6),
        };
        family == raven_core::p2p_route::is_global_ip(ip) && family == is_global_ip(ip)
    }

    #[test]
    fn global_addresses_and_what_a_relay_may_name() {
        for ip in [
            "8.8.8.8",
            "203.0.114.1",
            "2606:4700::1111",
            "::ffff:8.8.4.4",
            // NAT64 (64:ff9b::/96) and 6to4 (2002::/16) of a global IPv4.
            "64:ff9b::808:808",
            "2002:808:808::1",
        ] {
            assert!(is_global_ip(ip.parse().unwrap()), "{ip}");
            assert!(same_rule_as_raven_core(ip), "{ip}");
        }
        for ip in [
            "10.0.0.1",
            "192.168.1.2",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "203.0.113.7",
            "198.18.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
            "ff02::1",
            "::ffff:192.168.1.1",
            // NAT64 and 6to4 of a private, loopback, CGNAT or unspecified
            // IPv4: as that IPv4 address (a translator would forward there).
            "64:ff9b::a00:1",
            "64:ff9b::7f00:1",
            "64:ff9b::c0a8:101",
            "64:ff9b::6440:1",
            "2002:c0a8:101::1",
            "2002:a00:1::1",
            "2002:7f00:1::1",
            "2002::1",
            // The local-use NAT64 prefix (RFC 8215) is never global.
            "64:ff9b:1::808:808",
        ] {
            assert!(!is_global_ip(ip.parse().unwrap()), "{ip}");
            assert!(same_rule_as_raven_core(ip), "{ip}");
        }
        let lan = addr("/ip4/192.168.1.5/tcp/7423");
        let public = addr("/ip4/8.8.8.8/tcp/7423");
        assert!(
            !relay_may_advertise(&lan, false),
            "wildcard listen: no LAN address"
        );
        assert!(relay_may_advertise(&lan, true), "the operator chose it");
        assert!(relay_may_advertise(&public, false));
        assert!(!relay_may_advertise(&addr("/ip4/127.0.0.1/tcp/1"), false));
        let circuit = addr(
            "/ip4/8.8.8.8/tcp/1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit",
        );
        assert!(!relay_may_advertise(&circuit, true));
    }

    /// Phase 1 item 5: a network is a /24 or a /48 of a globally routable
    /// address; nothing else has one (an AutoNAT result from such a server
    /// never counts).
    #[test]
    fn net_group_is_global_only() {
        let g = |ip: &str| net_group(ip.parse().unwrap());
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.2",
            "172.16.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "203.0.113.7",
            "198.51.100.7",
            "0.0.0.0",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
            "::ffff:192.168.1.1",
        ] {
            assert_eq!(g(ip), None, "{ip}");
        }
        assert_eq!(g("8.8.8.8"), Some(NetGroup::V4([8, 8, 8])));
        assert_eq!(g("8.8.8.8"), g("8.8.8.200"), "one /24");
        assert_ne!(g("8.8.8.8"), g("8.8.9.8"), "another /24");
        assert_eq!(
            g("11.1.0.1"),
            g("11.1.0.2"),
            "the netns reach run's R1 and R3"
        );
        assert_ne!(g("11.1.0.1"), g("11.2.0.1"));
        assert_eq!(
            g("2606:4700:10::1"),
            Some(NetGroup::V6([0x2606, 0x4700, 0x10]))
        );
        assert_eq!(g("2606:4700:10::1"), g("2606:4700:10:ffff::2"), "one /48");
        assert_ne!(g("2606:4700:10::1"), g("2606:4700:11::1"), "another /48");
        // An IPv6 address carrying an IPv4 one is that IPv4 network.
        assert_eq!(g("::ffff:8.8.4.4"), g("8.8.4.1"));
        assert_eq!(g("64:ff9b::808:808"), g("8.8.8.1"));
        assert_eq!(g("2002:808:808::1"), g("8.8.8.9"));
        assert_ne!(g("::ffff:8.8.4.4"), g("8.8.8.8"));
    }

    /// Review item 4: the AutoNAT v2 server's dial-back can only reach
    /// globally routable addresses.
    #[test]
    fn dial_backs_reach_only_global_addresses() {
        let mut guard = DialBackGuard::default();
        let deny = |g: &mut DialBackGuard, a: &str| {
            g.handle_pending_outbound_connection(
                ConnectionId::new_unchecked(1),
                None,
                &[addr(a)],
                Endpoint::Dialer,
            )
            .is_err()
        };
        assert!(deny(&mut guard, "/ip4/127.0.0.1/tcp/22"));
        assert!(deny(&mut guard, "/ip4/192.168.1.1/tcp/80"));
        assert!(deny(&mut guard, "/ip6/::1/udp/53/quic-v1"));
        assert!(deny(&mut guard, "/dns4/localhost/tcp/80"));
        assert!(!deny(&mut guard, "/ip4/8.8.8.8/tcp/7423"));
        assert!(guard
            .handle_pending_outbound_connection(
                ConnectionId::new_unchecked(2),
                None,
                &[],
                Endpoint::Dialer,
            )
            .is_err());
        assert_eq!(guard.refused(), 5);
    }

    /// Review item 1: Identify never sends a host's listen addresses (here a
    /// loopback one); only confirmed external addresses go out.
    #[tokio::test]
    async fn identify_does_not_publish_listen_addresses() {
        let mut a = endpoint_with(
            0xE1,
            &[(peer_of(0xE2), PeerClass::CONTACT)],
            AddrRule::GlobalOnly,
            NO_SERVERS,
        );
        let mut b = endpoint_with(
            0xE2,
            &[(peer_of(0xE1), PeerClass::CONTACT)],
            AddrRule::GlobalOnly,
            NO_SERVERS,
        );
        a.listen_on(addr("/ip4/127.0.0.1/tcp/0")).unwrap();
        let a_addr = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = a.select_next_some().await {
                    return address;
                }
            }
        })
        .await
        .unwrap();
        let confirmed = addr("/ip4/8.8.8.8/tcp/7423");
        a.add_external_address(confirmed.clone());
        b.dial(a_addr.clone().with(Protocol::P2p(*a.local_peer_id())))
            .unwrap();
        let info = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    _ = a.select_next_some() => {}
                    event = b.select_next_some() => {
                        if let SwarmEvent::Behaviour(EndpointBehaviourEvent::Identify(
                            identify::Event::Received { info, .. },
                        )) = event
                        {
                            return info;
                        }
                    }
                }
            }
        })
        .await
        .expect("identify info");
        assert!(
            !info.listen_addrs.contains(&a_addr),
            "listen address leaked: {:?}",
            info.listen_addrs
        );
        assert!(info
            .listen_addrs
            .iter()
            .all(|x| addr_ip(x).is_none_or(|ip| !ip.is_loopback())));
        assert!(
            info.listen_addrs.contains(&confirmed),
            "{:?}",
            info.listen_addrs
        );
        assert_eq!(info.agent_version, AGENT_VERSION);
    }

    /// Review items 10/11: the limits are asked first, and inbound
    /// connections can never take the slots our own dials need.
    #[test]
    fn limits_come_first_and_outbound_keeps_a_reserve() {
        const {
            assert!(ENDPOINT_MAX_ESTABLISHED > OUTBOUND_RESERVE);
        }
        RelayLimits::friends().validate().unwrap();
        let tiny = RelayLimits {
            max_established: OUTBOUND_RESERVE,
            max_established_per_ip: 1,
            ..RelayLimits::friends()
        };
        assert!(tiny.validate().is_err(), "no room left for our own dials");
        // Field order is the admission order of the derive (see the type
        // docs): the limits first, then the peer gate, then every protocol.
        for name in [
            "pub struct EndpointBehaviour {",
            "pub struct RelayBehaviour {",
        ] {
            assert_eq!(
                behaviour_fields(name)[..3],
                ["limits", "ip_limits", "peer_gate"],
                "{name}"
            );
        }
        let endpoint = behaviour_fields("pub struct EndpointBehaviour {");
        assert_eq!(
            endpoint,
            [
                "limits",
                "ip_limits",
                "peer_gate",
                "relay_client",
                "relay_server",
                "dcutr",
                "autonat",
                "autonat_2",
                "identify",
                "ping",
                "port_map",
                "stream"
            ]
        );
        let relay = behaviour_fields("pub struct RelayBehaviour {");
        let at = |field: &str| relay.iter().position(|f| f == field).expect(field);
        assert!(at("dial_back_guard") < at("autonat_server"), "{relay:?}");
    }

    /// The fields of the behaviour struct `name` in this file, in order.
    fn behaviour_fields(name: &str) -> Vec<String> {
        let src = include_str!("host.rs");
        let at = src.find(name).expect("struct");
        let body = &src[at..];
        let end = body.find("\n}").expect("end of struct");
        body[..end]
            .lines()
            .skip(1)
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("//"))
            .filter_map(|l| l.trim_start_matches("pub ").split_once(':'))
            .map(|(field, _)| field.to_string())
            .collect()
    }

    /// The relay's UPnP behaviour (a dummy handler) comes after every other
    /// one, so the gate still comes first and the dial-back guard still
    /// before the AutoNAT server; the dedicated relay builds it off.
    #[tokio::test]
    async fn relay_behaviour_field_order_keeps_gate_first_with_upnp_last() {
        let relay = behaviour_fields("pub struct RelayBehaviour {");
        assert_eq!(
            relay,
            [
                "limits",
                "ip_limits",
                "peer_gate",
                "dial_back_guard",
                "relay",
                "autonat_server",
                "identify",
                "ping",
                "upnp"
            ]
        );
        let guard = RelayGuard::new(AllowPolicy::Open, &RelayLimits::friends());
        for upnp in [false, true] {
            let swarm = build_relay_swarm(
                &gate(),
                key(0xE1),
                RelayLimits::friends(),
                &guard,
                false,
                upnp,
                None,
            )
            .unwrap();
            assert_eq!(swarm.behaviour().upnp.is_enabled(), upnp);
        }
    }

    /// Listen on `at` and return the first `count` addresses reported.
    #[cfg(feature = "wss")]
    async fn listen_reports<B: NetworkBehaviour>(
        swarm: &mut Swarm<B>,
        at: &str,
        count: usize,
    ) -> Vec<Multiaddr> {
        swarm.listen_on(addr(at)).expect("listen");
        let mut reported = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), async {
            while reported.len() < count {
                if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                    reported.push(address);
                }
            }
        })
        .await
        .expect("listen timeout");
        reported
    }

    /// A relay's WSS server side with an ephemeral certificate (RWS1 §4:
    /// libp2p Noise, not TLS, authenticates the relay).
    #[cfg(feature = "wss")]
    fn wss_server() -> crate::wss::ServerSide {
        crate::wss::ServerSide {
            tls: crate::wss::tls::ephemeral_server_tls(&[]).unwrap(),
        }
    }

    /// The [`relay_lab`] relay on a loopback WSS listener (a two-protocol
    /// port, RWS1 §6). `relay_addr` is the plain address, which the relay
    /// names; the `/tls/ws` form is returned beside the lab.
    #[cfg(feature = "wss")]
    async fn wss_relay_lab(policy: AllowPolicy) -> (Lab, Multiaddr) {
        let limits = RelayLimits::friends();
        let guard = RelayGuard::new(policy, &limits);
        let mut relay = build_relay_swarm(
            &gate(),
            key(RELAY_SEED),
            limits,
            &guard,
            false,
            false,
            Some(wss_server()),
        )
        .unwrap();
        let reported = listen_reports(&mut relay, "/ip4/127.0.0.1/tcp/0/tls/ws", 2).await;
        let raw = reported[1].clone();
        relay.add_external_address(raw.clone());
        let id = Protocol::P2p(*relay.local_peer_id());
        let wss_addr = reported[0].clone().with(id.clone());
        let lab = Lab {
            relay,
            relay_addr: raw.with(id),
            guard,
            relay_events: Vec::new(),
            identified: Vec::new(),
            conns: ConnLog::default(),
        };
        (lab, wss_addr)
    }

    /// A relay built with a WSS server side listens on `…/tcp/0/tls/ws` and
    /// reports the `/tls/ws` form, then the plain one, on one port; both
    /// probe as busy. A relay advertiser names only the plain one (RWS1
    /// §2.2), also as the loopback placeholder. A relay built without one
    /// does not listen on the WSS form.
    #[cfg(feature = "wss")]
    #[tokio::test]
    async fn relay_swarm_wss_listener_reports_tls_ws_and_raw_addresses() {
        use libp2p::core::transport::TransportError;
        let guard = RelayGuard::new(AllowPolicy::Open, &RelayLimits::friends());
        let relay = |wss: Option<WssServerSide>| {
            build_relay_swarm(
                &gate(),
                key(0xE2),
                RelayLimits::friends(),
                &guard,
                false,
                false,
                wss,
            )
            .unwrap()
        };
        let mut with = relay(Some(wss_server()));
        let reported = listen_reports(&mut with, "/ip4/127.0.0.1/tcp/0/tls/ws", 2).await;
        let Some(Protocol::Tcp(port)) = reported[1].iter().nth(1) else {
            panic!("not a TCP address: {}", reported[1]);
        };
        assert_ne!(port, 0);
        let raw = addr(&format!("/ip4/127.0.0.1/tcp/{port}"));
        assert_eq!(
            reported,
            [
                addr(&format!("/ip4/127.0.0.1/tcp/{port}/tls/ws")),
                raw.clone()
            ],
            "the /tls/ws form first, then the plain one"
        );
        for a in &reported {
            assert_eq!(probe_listen_addr(a), Err(ListenProbe::Busy), "{a}");
        }
        let ext = |s: &Swarm<RelayBehaviour>| -> Vec<Multiaddr> {
            s.external_addresses().cloned().collect()
        };

        // A specific listen address: the plain form is named, not the WSS one.
        let mut adv = RelayAdvertiser::new(&mut with, true, &[]);
        for a in &reported {
            adv.on_new_listen_addr(&mut with, a);
        }
        assert_eq!(adv.named(), vec![raw.clone()]);
        assert_eq!(ext(&with), vec![raw.clone()]);
        adv.on_expired_listen_addr(&mut with, &reported[0]);
        assert_eq!(adv.named(), vec![raw.clone()]);

        // A wildcard listen: the loopback placeholder is the plain form too.
        let mut without = relay(None);
        let mut adv = RelayAdvertiser::new(&mut without, false, &[]);
        for a in &reported {
            adv.on_new_listen_addr(&mut without, a);
        }
        assert!(adv.placeholder_only());
        assert_eq!(ext(&without), vec![raw.clone()]);
        assert!(!relay_may_advertise(&reported[0], true));
        assert!(!relay_may_advertise(
            &addr("/ip4/8.8.8.8/tcp/443/tls/ws"),
            false
        ));
        assert!(!relay_may_advertise(
            &addr("/ip4/8.8.8.8/tcp/443/tls/sni/relay.example.com/ws"),
            false
        ));
        assert!(relay_may_advertise(&addr("/ip4/8.8.8.8/tcp/443"), false));

        // Without a server side the WSS form is no listen address.
        assert!(matches!(
            without.listen_on(reported[0].clone()),
            Err(TransportError::MultiaddrNotSupported(_))
        ));
    }

    /// `build_endpoint_swarm` with and without a WSS client side. A has one:
    /// it reserves on the relay over the relay's `/tls/ws` form, and never
    /// listens on WSS itself (RWS1 §2.3). B is built as before: no transport
    /// takes the WSS form (nothing is sent), and B still reaches A through
    /// the relay's plain address. Every clone of a config shares one
    /// restricted flag.
    #[cfg(feature = "wss")]
    #[tokio::test]
    async fn endpoint_swarm_builds_with_and_without_wss() {
        use libp2p::core::transport::TransportError;
        use libp2p::core::ConnectedPoint;
        use std::sync::atomic::Ordering;
        let (a_peer, b_peer, r) = (peer_of(0x91), peer_of(0x92), relay_peer());
        let (mut lab, wss_addr) = wss_relay_lab(AllowPolicy::Open).await;
        let a_config = EndpointConfig {
            gate: admitted(&[(r, PeerClass::OWN_RELAY), (b_peer, PeerClass::CONTACT)]),
            wss: Some(crate::wss::ClientSide {
                tls: crate::wss::tls::client_tls(),
                proxy: None,
            }),
            ..EndpointConfig::default()
        };
        let restricted = a_config.restricted.clone();
        let mut a = build_endpoint_swarm(&gate(), key(0x91), a_config).unwrap();
        let mut b = endpoint_with(
            0x92,
            &[(a_peer, PeerClass::CONTACT), (r, PeerClass::CONTACT_RELAY)],
            AddrRule::GlobalOnly,
            NO_SERVERS,
        );

        let listen = addr("/ip4/127.0.0.1/tcp/0/tls/ws");
        for ep in [&mut a, &mut b] {
            assert!(matches!(
                ep.listen_on(listen.clone()),
                Err(TransportError::MultiaddrNotSupported(_))
            ));
        }

        b.dial(wss_addr.clone()).unwrap();
        let error = drive(&mut lab, &mut [&mut b], |e| match e?.1 {
            SwarmEvent::OutgoingConnectionError { error, .. } => Some(error),
            _ => None,
        })
        .await;
        match error {
            DialError::Transport(errors) => {
                assert!(!errors.is_empty());
                for (_, e) in &errors {
                    assert!(
                        matches!(e, TransportError::MultiaddrNotSupported(_)),
                        "{e:?}"
                    );
                }
            }
            other => panic!("{other:?}"),
        }
        assert!(lab.conns.opened(&b_peer).is_empty());

        reserve(&mut a, &wss_addr);
        let mut via = None;
        drive(&mut lab, &mut [&mut a], |e| {
            let (_, e) = e?;
            if let SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint: ConnectedPoint::Dialer { address, .. },
                ..
            } = &e
            {
                if *peer_id == r {
                    via = Some(address.clone());
                }
            }
            accepted(&e).then_some(())
        })
        .await;
        assert_eq!(via, Some(wss_addr.clone()), "reserved over the WSS form");

        let (mut out, mut inn) = circuit_stream(&mut lab, &mut a, &mut b).await;
        let echo = tokio::spawn(async move {
            out.write_all(b"wss").await.unwrap();
            out.flush().await.unwrap();
            let mut buf = [0u8; 3];
            inn.read_exact(&mut buf).await.unwrap();
            buf
        });
        drive(&mut lab, &mut [&mut a, &mut b], |_| {
            echo.is_finished().then_some(())
        })
        .await;
        assert_eq!(&echo.await.unwrap(), b"wss");

        // One flag for the process: a later generation's config is a clone.
        assert!(!restricted.load(Ordering::SeqCst));
        let next = EndpointConfig {
            restricted: restricted.clone(),
            ..EndpointConfig::default()
        };
        restricted.store(true, Ordering::SeqCst);
        assert!(next.clone().restricted.load(Ordering::SeqCst));
        assert!(!EndpointConfig::default().restricted.load(Ordering::SeqCst));
    }

    /// Review item 6: a port another program holds is found before libp2p
    /// (which sets SO_REUSEADDR / SO_REUSEPORT) would share it; a free one is
    /// not.
    #[tokio::test]
    async fn a_busy_port_is_found_before_libp2p_binds_it() {
        // Another libp2p host on a fixed port, TCP and QUIC. The port must
        // be free for both: a port free for TCP may be some other test's
        // QUIC socket, and anything may take it before `other` binds, so a
        // refused bind picks another port.
        let (port, mut other) = (0..20)
            .find_map(|_| {
                let port = free_loopback_port();
                let tcp = addr(&format!("/ip4/127.0.0.1/tcp/{port}"));
                let quic = addr(&format!("/ip4/127.0.0.1/udp/{port}/quic-v1"));
                // The probe finds it free (a broken probe fails every try).
                if probe_listen_addr(&tcp) != Ok(()) {
                    return None;
                }
                let mut other = lone_endpoint(0xF1);
                let bound = other.listen_on(tcp).is_ok() && other.listen_on(quic).is_ok();
                bound.then_some((port, other))
            })
            .expect("a loopback port free for TCP and UDP");
        let tcp = addr(&format!("/ip4/127.0.0.1/tcp/{port}"));
        let quic = addr(&format!("/ip4/127.0.0.1/udp/{port}/quic-v1"));
        let mut seen = 0;
        tokio::time::timeout(Duration::from_secs(5), async {
            while seen < 2 {
                if let SwarmEvent::NewListenAddr { .. } = other.select_next_some().await {
                    seen += 1;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(probe_listen_addr(&tcp), Err(ListenProbe::Busy));
        assert_eq!(probe_listen_addr(&quic), Err(ListenProbe::Busy));
        assert_eq!(listen_port_label(&tcp), format!("{port}/tcp"));
        assert_eq!(listen_port_label(&quic), format!("{port}/udp"));
        // Port 0 and addresses without a port are never probed.
        assert_eq!(probe_listen_addr(&addr("/ip4/127.0.0.1/tcp/0")), Ok(()));
        // An address this host does not have (now).
        assert_eq!(
            probe_listen_addr(&addr("/ip4/203.0.113.7/tcp/7423")),
            Err(ListenProbe::Absent)
        );
    }

    /// Relay kit: TCP 443 without the privilege is named as such, not
    /// skipped as an address family this host lacks. Only where the host
    /// reserves 443: Linux, not root, `ip_unprivileged_port_start` above 443.
    #[test]
    fn a_privileged_port_is_named_not_skipped() {
        let start = std::fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());
        // The effective uid: the second field of /proc/self/status `Uid:`.
        let euid = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("Uid:"))
                    .and_then(|ids| ids.split_whitespace().nth(1)?.parse::<u32>().ok())
            });
        match (start, euid) {
            (Some(start), Some(euid)) if start > 443 && euid != 0 => {}
            _ => {
                eprintln!(
                    "port 443 needs no privilege here (not Linux, root, or \
                     ip_unprivileged_port_start <= 443): skipped"
                );
                return;
            }
        }
        for a in [
            "/ip4/127.0.0.1/tcp/443",
            "/ip4/127.0.0.1/udp/443/quic-v1",
            // A relay's WSS listener (RWS1 §6) is probed as its TCP port.
            "/ip4/127.0.0.1/tcp/443/tls/ws",
        ] {
            assert_eq!(
                probe_listen_addr(&addr(a)),
                Err(ListenProbe::Privileged),
                "{a}"
            );
        }
    }

    /// Only an address on no interface now may come back; an address that
    /// can never be bound as asked is told apart from it.
    #[test]
    fn listen_probe_errors_tell_an_absent_address_from_one_that_never_binds() {
        use std::io::{Error, ErrorKind};
        let of = |kind: ErrorKind| ListenProbe::of_error(&Error::from(kind), 7423);
        assert_eq!(of(ErrorKind::AddrInUse), ListenProbe::Busy);
        assert_eq!(of(ErrorKind::AddrNotAvailable), ListenProbe::Absent);
        assert_eq!(
            of(ErrorKind::PermissionDenied),
            if cfg!(windows) {
                ListenProbe::Busy
            } else {
                ListenProbe::Unavailable
            }
        );
        // A port below 1024 this process may not bind is named as such
        // (Windows reports an exclusively held port the same way: busy).
        for port in [1, 80, 443, 1023] {
            assert_eq!(
                ListenProbe::of_error(&Error::from(ErrorKind::PermissionDenied), port),
                if cfg!(windows) {
                    ListenProbe::Busy
                } else {
                    ListenProbe::Privileged
                },
                "{port}"
            );
            let in_use = ListenProbe::of_error(&Error::from(ErrorKind::AddrInUse), port);
            assert_eq!(in_use, ListenProbe::Busy);
        }
        assert_ne!(
            ListenProbe::of_error(&Error::from(ErrorKind::PermissionDenied), 1024),
            ListenProbe::Privileged
        );
        // An invalid address, no such address family (std has no kind of
        // its own for EAFNOSUPPORT), anything else.
        for kind in [
            ErrorKind::InvalidInput,
            ErrorKind::Unsupported,
            ErrorKind::Other,
        ] {
            assert_eq!(of(kind), ListenProbe::Unavailable, "{kind:?}");
        }
    }

    /// Can this host open IPv6 sockets at all?
    fn has_ipv6() -> bool {
        let ok = std::net::UdpSocket::bind("[::]:0").is_ok();
        if !ok {
            eprintln!("no IPv6 sockets on this host: skipped");
        }
        ok
    }

    /// A loopback port free for TCP and UDP now (never one of Raven's own
    /// default ports).
    fn free_loopback_port() -> u16 {
        for _ in 0..100 {
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            if [7420, 7422, 7423].contains(&port) {
                continue;
            }
            if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
                return port;
            }
        }
        panic!("no loopback port free for TCP and UDP");
    }

    /// A port free for TCP and UDP on both wildcard addresses (never one of
    /// Raven's own default ports).
    fn free_wildcard_port() -> u16 {
        for _ in 0..100 {
            let port = std::net::UdpSocket::bind("0.0.0.0:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            if [7420, 7422, 7423].contains(&port) {
                continue;
            }
            let free = ["0.0.0.0", "[::]"].iter().all(|ip| {
                let at = format!("{ip}:{port}");
                std::net::UdpSocket::bind(&at).is_ok() && std::net::TcpListener::bind(&at).is_ok()
            });
            if free {
                return port;
            }
        }
        panic!("no port free on both wildcard addresses");
    }

    /// The probe binds an IPv6 address IPv6-only, as libp2p-tcp and
    /// libp2p-quic bind it: a dual-stack `[::]` probe (the Linux default)
    /// would overlap `0.0.0.0` on that port.
    #[test]
    fn an_ipv6_probe_is_ipv6_only_like_libp2p() {
        if !has_ipv6() {
            return;
        }
        for udp in [false, true] {
            let v6 = probe_socket("[::1]:0".parse().unwrap(), udp).unwrap();
            assert!(v6.only_v6().unwrap(), "udp={udp}");
            let wild = probe_socket("[::]:0".parse().unwrap(), udp).unwrap();
            assert!(wild.only_v6().unwrap(), "udp={udp}");
            probe_socket("127.0.0.1:0".parse().unwrap(), udp).unwrap();
        }
    }

    /// Phase 0b re-home: this endpoint's own `0.0.0.0` listeners (TCP and
    /// QUIC) never make the `[::]` probe of the same port busy, so an IPv6
    /// slot that was busy for one round (our old endpoint still draining)
    /// opens in a later one. On Linux a dual-stack probe collided with them.
    #[tokio::test]
    async fn our_own_ipv4_wildcard_listeners_do_not_make_the_ipv6_probe_busy() {
        if !has_ipv6() {
            return;
        }
        let port = free_wildcard_port();
        let mut ours = lone_endpoint(0xF3);
        ours.listen_on(addr(&format!("/ip4/0.0.0.0/tcp/{port}")))
            .unwrap();
        ours.listen_on(addr(&format!("/ip4/0.0.0.0/udp/{port}/quic-v1")))
            .unwrap();
        let mut seen = 0;
        tokio::time::timeout(Duration::from_secs(5), async {
            while seen < 2 {
                if let SwarmEvent::NewListenAddr { .. } = ours.select_next_some().await {
                    seen += 1;
                }
            }
        })
        .await
        .unwrap();
        let tcp6 = addr(&format!("/ip6/::/tcp/{port}"));
        let quic6 = addr(&format!("/ip6/::/udp/{port}/quic-v1"));
        assert_eq!(probe_listen_addr(&tcp6), Ok(()));
        assert_eq!(probe_listen_addr(&quic6), Ok(()));
        // The IPv4 ones are ours: busy.
        assert_eq!(
            probe_listen_addr(&addr(&format!("/ip4/0.0.0.0/tcp/{port}"))),
            Err(ListenProbe::Busy)
        );
        assert_eq!(
            probe_listen_addr(&addr(&format!("/ip4/0.0.0.0/udp/{port}/quic-v1"))),
            Err(ListenProbe::Busy)
        );
        // And libp2p opens the IPv6 ones next to them.
        ours.listen_on(tcp6).unwrap();
        ours.listen_on(quic6).unwrap();
        let mut seen = 0;
        tokio::time::timeout(Duration::from_secs(5), async {
            while seen < 2 {
                match ours.select_next_some().await {
                    SwarmEvent::NewListenAddr { .. } => seen += 1,
                    SwarmEvent::ListenerClosed { .. } | SwarmEvent::ListenerError { .. } => {
                        panic!("an IPv6 listener failed")
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
        // A port another socket holds on IPv6 only is still busy.
        let other = probe_socket(
            format!("[::]:{}", free_wildcard_port()).parse().unwrap(),
            true,
        )
        .unwrap();
        let held = other.local_addr().unwrap().as_socket().unwrap().port();
        assert_eq!(
            probe_listen_addr(&addr(&format!("/ip6/::/udp/{held}/quic-v1"))),
            Err(ListenProbe::Busy)
        );
    }

    /// Review items 1/14: a relaying host names only global (or explicitly
    /// chosen) addresses, a loopback placeholder otherwise, and withdraws
    /// expired ones.
    #[tokio::test]
    async fn a_relay_advertises_only_what_it_may_and_withdraws_expired() {
        let mut swarm = lone_endpoint(0xF2);
        let ext = |s: &Swarm<EndpointBehaviour>| -> Vec<Multiaddr> {
            s.external_addresses().cloned().collect()
        };
        let mut adv = RelayAdvertiser::new(&mut swarm, false, &[]);
        let lan = addr("/ip4/192.168.1.5/tcp/7423");
        let lo = addr("/ip4/127.0.0.1/tcp/7423");
        let public = addr("/ip4/8.8.8.8/tcp/7423");
        adv.on_new_listen_addr(&mut swarm, &lan);
        assert!(
            ext(&swarm).is_empty(),
            "no LAN address under a wildcard listen"
        );
        adv.on_new_listen_addr(&mut swarm, &lo);
        assert_eq!(ext(&swarm), vec![lo.clone()]);
        assert!(adv.placeholder_only());
        assert!(adv.named().is_empty(), "the placeholder is never named");
        adv.on_new_listen_addr(&mut swarm, &public);
        assert_eq!(
            ext(&swarm),
            vec![public.clone()],
            "the placeholder is replaced"
        );
        assert_eq!(adv.named(), vec![public.clone()]);
        adv.on_expired_listen_addr(&mut swarm, &public);
        assert!(ext(&swarm).is_empty(), "expired addresses are withdrawn");
        assert!(adv.named().is_empty());
        // A specific listen address (the operator chose it) is advertised.
        let mut specific = lone_endpoint(0xF3);
        let mut adv = RelayAdvertiser::new(&mut specific, true, &[]);
        adv.on_new_listen_addr(&mut specific, &lan);
        assert_eq!(ext(&specific), vec![lan.clone()]);
        assert_eq!(adv.named(), vec![lan.clone()]);
        // --external wins over everything else.
        let mut explicit = lone_endpoint(0xF4);
        let named = addr("/dns4/relay.example.com/tcp/7423");
        let mut adv = RelayAdvertiser::new(&mut explicit, false, std::slice::from_ref(&named));
        adv.on_new_listen_addr(&mut explicit, &public);
        assert_eq!(ext(&explicit), vec![named.clone()]);
        assert!(!adv.placeholder_only());
        assert_eq!(adv.named(), vec![named]);
    }

    /// The friend relay's feed: `set_external` names exactly its addresses
    /// (the placeholder goes, dropped ones are withdrawn); an empty list
    /// falls back to the listen addresses, or to the placeholder.
    #[tokio::test]
    async fn relay_advertiser_named_and_set_external() {
        let ext = |s: &Swarm<EndpointBehaviour>| -> Vec<Multiaddr> {
            let mut out: Vec<Multiaddr> = s.external_addresses().cloned().collect();
            out.sort();
            out
        };
        let lo = addr("/ip4/127.0.0.1/tcp/7427");
        let public = addr("/ip4/8.8.8.8/tcp/7427");
        let mapped = addr("/ip4/8.8.4.4/tcp/7427");
        let named = addr("/dns/relay.example.org/tcp/443");
        // Placeholder only, then the feed: the placeholder goes.
        let mut swarm = lone_endpoint(0xF5);
        let mut adv = RelayAdvertiser::new(&mut swarm, false, &[]);
        adv.on_new_listen_addr(&mut swarm, &lo);
        assert!(adv.placeholder_only() && adv.named().is_empty());
        adv.set_external(&mut swarm, &[mapped.clone(), mapped.clone()]);
        assert_eq!(ext(&swarm), vec![mapped.clone()]);
        assert_eq!(adv.named(), vec![mapped.clone()]);
        assert!(!adv.placeholder_only());
        // Replaced whole: a dropped address is withdrawn.
        adv.set_external(&mut swarm, std::slice::from_ref(&named));
        assert_eq!(ext(&swarm), vec![named.clone()]);
        assert_eq!(adv.named(), vec![named.clone()]);
        // A listen address seen meanwhile is not named while the feed is.
        adv.on_new_listen_addr(&mut swarm, &public);
        assert_eq!(ext(&swarm), vec![named.clone()]);
        // Empty: back to the listen-address rule (the public one).
        adv.set_external(&mut swarm, &[]);
        assert_eq!(ext(&swarm), vec![public.clone()]);
        assert_eq!(adv.named(), vec![public.clone()]);
        // And with no admitted listen address left: the placeholder again.
        adv.on_expired_listen_addr(&mut swarm, &public);
        assert!(ext(&swarm).is_empty());
        adv.set_external(&mut swarm, &[]);
        assert_eq!(ext(&swarm), vec![lo.clone()]);
        assert!(adv.placeholder_only() && adv.named().is_empty());
        // --external at the start is replaced by the feed the same way.
        let mut swarm = lone_endpoint(0xF6);
        let mut adv = RelayAdvertiser::new(&mut swarm, false, std::slice::from_ref(&named));
        adv.on_new_listen_addr(&mut swarm, &public);
        assert_eq!(ext(&swarm), vec![named.clone()]);
        adv.set_external(&mut swarm, std::slice::from_ref(&mapped));
        assert_eq!(ext(&swarm), vec![mapped.clone()]);
        adv.set_external(&mut swarm, &[]);
        assert_eq!(ext(&swarm), vec![public.clone()]);
        // Expired listen addresses never withdraw an explicit one.
        adv.set_external(&mut swarm, std::slice::from_ref(&public));
        adv.on_expired_listen_addr(&mut swarm, &public);
        assert_eq!(ext(&swarm), vec![public.clone()]);
        assert_eq!(adv.named(), vec![public]);
    }

    // ── The peer gate in the composed swarms ─────────────────────────────

    fn id(n: usize) -> ConnectionId {
        ConnectionId::new_unchecked(n)
    }

    /// The denial of a hook that must refuse (handlers are not `Debug`).
    fn refused<T>(result: Result<T, ConnectionDenied>) -> ConnectionDenied {
        match result {
            Ok(_) => panic!("admitted"),
            Err(denied) => denied,
        }
    }

    /// Handlers built by (DCUtR, Identify, both AutoNAT clients).
    fn built(b: &EndpointBehaviour) -> (u64, u64, u64) {
        (
            b.dcutr.handlers_built(),
            b.identify.handlers_built(),
            b.autonat.handlers_built() + b.autonat_2.handlers_built(),
        )
    }

    /// The derive-order proof on the real composition: the gate (third)
    /// refuses before DCUtR, Identify or AutoNAT build a handler, and each
    /// protocol builds one only for its own classes.
    #[test]
    fn the_gate_refuses_before_dcutr_identify_or_autonat_build_a_handler() {
        let (c, r, s) = (peer_of(0x11), peer_of(0x12), peer_of(0x13));
        let k = key(0x10);
        let local = k.public().to_peer_id();
        let cfg = EndpointConfig {
            gate: admitted(&[(c, PeerClass::CONTACT), (r, PeerClass::OWN_RELAY)]),
            autonat_servers: [Some(r), None],
            ..EndpointConfig::default()
        };
        let mut b = endpoint_behaviour(&k, relay::client::new(local).1, &cfg);
        let via_r = addr("/ip4/127.0.0.1/tcp/7424")
            .with(Protocol::P2p(r))
            .with(Protocol::P2pCircuit);
        let direct = addr("/ip4/127.0.0.1/tcp/7423");
        let remote = addr("/ip4/127.0.0.1/tcp/50000");
        let from = |p: PeerId| Multiaddr::empty().with(Protocol::P2p(p));
        let not_admitted = |denied: ConnectionDenied| {
            denied
                .downcast_ref::<PeerNotAdmitted>()
                .copied()
                .expect("refused by the peer gate")
        };

        // A stranger over a circuit: refused already when it is pending
        // (before this host accepts it or runs Noise), and established.
        let denied = refused(b.handle_pending_inbound_connection(id(1), &via_r, &from(s)));
        assert!(not_admitted(denied).relayed);
        let denied = refused(b.handle_established_inbound_connection(id(1), s, &via_r, &from(s)));
        assert!(not_admitted(denied).relayed);
        assert_eq!(built(&b), (0, 0, 0));
        // A stranger directly, both ways.
        b.handle_pending_inbound_connection(id(2), &direct, &remote)
            .unwrap();
        let denied = refused(b.handle_established_inbound_connection(id(2), s, &direct, &remote));
        assert_eq!(
            not_admitted(denied),
            PeerNotAdmitted {
                inbound: true,
                relayed: false
            }
        );
        let denied = refused(b.handle_pending_outbound_connection(
            id(3),
            Some(s),
            std::slice::from_ref(&remote),
            Endpoint::Dialer,
        ));
        assert!(!not_admitted(denied).inbound);
        let denied = refused(b.handle_established_outbound_connection(
            id(3),
            s,
            &remote,
            Endpoint::Dialer,
            PortUse::New,
        ));
        assert!(!not_admitted(denied).inbound);
        assert_eq!(built(&b), (0, 0, 0));
        assert_eq!(b.dcutr.relayed_handlers_built(), 0);
        assert_eq!(
            b.peer_gate.counts(),
            GateCounts {
                refused_inbound: 1,
                refused_relayed: 2,
                refused_outbound: 2
            }
        );

        // A contact over a circuit: DCUtR and Identify, no AutoNAT.
        b.handle_pending_inbound_connection(id(4), &via_r, &from(c))
            .unwrap();
        b.handle_established_inbound_connection(id(4), c, &via_r, &from(c))
            .unwrap();
        assert_eq!(built(&b), (1, 1, 0));
        assert_eq!(b.dcutr.relayed_handlers_built(), 1, "built from the book");
        // The own relay directly: Identify and its AutoNAT client, no DCUtR.
        b.handle_established_inbound_connection(id(5), r, &direct, &remote)
            .unwrap();
        assert_eq!(built(&b), (1, 2, 1));
        assert_eq!(b.autonat.handlers_built(), 1, "the client of r's slot");
        // The own relay over a circuit: circuits carry Raven links only.
        let denied = refused(b.handle_established_inbound_connection(id(6), r, &via_r, &from(r)));
        assert!(not_admitted(denied).relayed);
        assert_eq!(built(&b), (1, 2, 1));
    }

    /// A hidden contact (this node hides its IP from it, or its PeerId is
    /// not proven) is admitted on every kind of connection, and no DCUtR,
    /// Identify or AutoNAT handler is built for any of them: nothing it is
    /// sent names an address of ours.
    #[test]
    fn a_hidden_contact_gets_no_dcutr_or_identify_handler() {
        let (h, r) = (peer_of(0x14), peer_of(0x15));
        let k = key(0x16);
        let local = k.public().to_peer_id();
        let cfg = EndpointConfig {
            gate: admitted(&[(h, PeerClass::CONTACT_HIDDEN), (r, PeerClass::OWN_RELAY)]),
            autonat_servers: [Some(r), None],
            ..EndpointConfig::default()
        };
        let mut b = endpoint_behaviour(&k, relay::client::new(local).1, &cfg);
        let via_r = addr("/ip4/127.0.0.1/tcp/7424")
            .with(Protocol::P2p(r))
            .with(Protocol::P2pCircuit);
        let direct = addr("/ip4/127.0.0.1/tcp/7423");
        let remote = addr("/ip4/127.0.0.1/tcp/50000");
        let from = |p: PeerId| Multiaddr::empty().with(Protocol::P2p(p));

        // Over a circuit, inbound.
        b.handle_pending_inbound_connection(id(1), &via_r, &from(h))
            .unwrap();
        b.handle_established_inbound_connection(id(1), h, &via_r, &from(h))
            .unwrap();
        // Directly, inbound and outbound.
        b.handle_pending_inbound_connection(id(2), &direct, &remote)
            .unwrap();
        b.handle_established_inbound_connection(id(2), h, &direct, &remote)
            .unwrap();
        b.handle_pending_outbound_connection(
            id(3),
            Some(h),
            std::slice::from_ref(&remote),
            Endpoint::Dialer,
        )
        .unwrap();
        b.handle_established_outbound_connection(id(3), h, &remote, Endpoint::Dialer, PortUse::New)
            .unwrap();
        assert_eq!(built(&b), (0, 0, 0));
        assert_eq!(b.dcutr.relayed_handlers_built(), 0);
        assert_eq!(b.peer_gate.counts().total(), 0, "admitted every time");
    }

    #[derive(NetworkBehaviour)]
    struct Stranger {
        relay_client: relay::client::Behaviour,
        dcutr: libp2p::dcutr::Behaviour,
        identify: identify::Behaviour,
        ping: ping::Behaviour,
    }

    /// Stock rust-libp2p with no gate (the attacker model): it speaks
    /// Raven's Identify protocol, keeps what it learns, and hole-punches.
    fn stranger(seed: u8) -> Swarm<Stranger> {
        SwarmBuilder::with_existing_identity(key(seed))
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .unwrap()
            .with_behaviour(|key, relay_client| Stranger {
                relay_client,
                dcutr: libp2p::dcutr::Behaviour::new(key.public().to_peer_id()),
                identify: identify::Behaviour::new(
                    identify::Config::new(IDENTIFY_PROTOCOL.to_owned(), key.public())
                        .with_cache_size(64),
                ),
                ping: ping::Behaviour::default(),
            })
            .unwrap()
            .build()
    }

    /// What a peer learned about `target`.
    #[derive(Debug, Default)]
    struct Learned {
        addresses: usize,
        identify: usize,
        dcutr: usize,
        /// Hole-punch dials (`Dialing` is reported for a behaviour's dials
        /// only, never for an explicit `Swarm::dial`).
        dials: usize,
        /// Connections to `target` it saw closed.
        closed: usize,
        /// Every failed dial (Debug text).
        failed: Vec<String>,
    }

    impl Learned {
        fn see(&mut self, target: PeerId, event: SwarmEvent<StrangerEvent>) {
            match event {
                SwarmEvent::NewExternalAddrOfPeer { peer_id, .. } if peer_id == target => {
                    self.addresses += 1
                }
                SwarmEvent::Behaviour(StrangerEvent::Identify(identify::Event::Received {
                    peer_id,
                    ..
                })) if peer_id == target => self.identify += 1,
                SwarmEvent::Behaviour(StrangerEvent::Dcutr(e)) if e.remote_peer_id == target => {
                    self.dcutr += 1
                }
                SwarmEvent::Dialing {
                    peer_id: Some(p), ..
                } if p == target => self.dials += 1,
                SwarmEvent::ConnectionClosed { peer_id, .. } if peer_id == target => {
                    self.closed += 1
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    self.failed.push(format!("{error:?}"))
                }
                _ => {}
            }
        }
    }

    /// Drive the relay, the endpoint `b` and the stranger `s` (what it
    /// learns of `b` goes to `learned`) until `done` says so, after one of
    /// `b`'s events or on a 50 ms tick. At most 15 s; a timeout panics with
    /// what the relay saw and what `b` and `s` reported.
    async fn drive_stranger(
        lab: &mut Lab,
        b: &mut Swarm<EndpointBehaviour>,
        s: &mut Swarm<Stranger>,
        learned: &mut Learned,
        mut done: impl FnMut(Option<&SwarmEvent<EndpointBehaviourEvent>>, &Learned) -> bool,
    ) {
        let target = *b.local_peer_id();
        let mut seen: Vec<String> = Vec::new();
        let outcome = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                tokio::select! {
                    event = lab.relay.select_next_some() => lab.on_event(event),
                    event = s.select_next_some() => {
                        seen.push(format!("s: {event:?}"));
                        learned.see(target, event);
                    }
                    event = b.select_next_some() => {
                        seen.push(format!("b: {event:?}"));
                        if done(Some(&event), learned) {
                            return;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {
                        if done(None, learned) {
                            return;
                        }
                    }
                }
            }
        })
        .await;
        if outcome.is_err() {
            panic!(
                "stranger lab timed out\n{learned:?}\nconnections: {:?}\nrelay events: {:#?}\nevents: {:#?}",
                lab.conns.0.lock().unwrap(),
                lab.relay_events,
                seen
            );
        }
    }

    /// The plan's Phase 1 proof. A stranger (stock rust-libp2p, no gate)
    /// reaches B through an open relay and then directly: B refuses both, and
    /// the stranger learns no address of B, no Identify and no hole punch.
    /// A contact on the same relay gets all three, so the instruments would
    /// catch them if any flowed.
    #[tokio::test]
    async fn a_stranger_circuit_is_refused_and_learns_no_address() {
        let r = relay_peer();
        let (a_peer, b_peer) = (peer_of(0x61), peer_of(0x62));
        let mut lab = relay_lab(RelayLimits::friends(), AllowPolicy::Open).await;
        let relay_addr = lab.relay_addr.clone();
        // B has something to give away: a confirmed external address and a
        // hole-punch candidate (its loopback listen address, debug lab rule).
        // The external one is a `/ws` address: Identify sends it, but it is
        // never a hole-punch candidate, so the contact below dials nothing
        // off this machine.
        let mut b = endpoint_with(
            0x62,
            &[(a_peer, PeerClass::CONTACT), (r, PeerClass::OWN_RELAY)],
            AddrRule::LabAnyIp,
            NO_SERVERS,
        );
        let b_listen = listen_loopback(&mut b).await;
        let public = addr("/ip4/8.8.8.8/tcp/7423/ws");
        b.add_external_address(public.clone());
        candidate(&mut b.behaviour_mut().dcutr, &b_listen);
        connect_from_a_new_port(&mut lab, &mut b).await;
        reserve(&mut b, &relay_addr);
        drive(&mut lab, &mut [&mut b], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        let before = (
            b.behaviour().dcutr.handlers_built(),
            b.behaviour().identify.handlers_built(),
            b.behaviour().dcutr.relayed_handlers_built(),
        );

        let mut s = stranger(0x5E);
        let mut learned = Learned::default();
        s.dial(lab.circuit_to(b_peer)).unwrap();
        drive_stranger(&mut lab, &mut b, &mut s, &mut learned, |e, _| {
            e.and_then(gate_refusal).is_some_and(|n| n.relayed)
        })
        .await;
        s.dial(b_listen.clone().with(Protocol::P2p(b_peer)))
            .unwrap();
        drive_stranger(&mut lab, &mut b, &mut s, &mut learned, |e, _| {
            e.and_then(gate_refusal)
                .is_some_and(|n| n.inbound && !n.relayed)
        })
        .await;
        let quiet = Instant::now() + Duration::from_secs(3);
        drive_stranger(&mut lab, &mut b, &mut s, &mut learned, |_, _| {
            Instant::now() >= quiet
        })
        .await;
        let counts = b.behaviour().peer_gate.counts();
        assert_eq!((counts.refused_relayed, counts.refused_inbound), (1, 1));
        assert_eq!(
            (
                b.behaviour().dcutr.handlers_built(),
                b.behaviour().identify.handlers_built(),
                b.behaviour().dcutr.relayed_handlers_built()
            ),
            before,
            "no handler for the stranger"
        );
        assert_eq!(
            (
                learned.addresses,
                learned.identify,
                learned.dcutr,
                learned.dials
            ),
            (0, 0, 0, 0),
            "{learned:?}"
        );
        // The circuit failed at the relay; the direct connection was closed
        // right after Noise (the stranger's side had completed it).
        assert_eq!(learned.failed.len(), 1, "{learned:?}");
        assert!(
            learned.failed[0].contains("ConnectionFailed"),
            "{learned:?}"
        );
        assert_eq!(learned.closed, 1, "{learned:?}");

        // The positive control: a contact on the same relay.
        let mut a = endpoint_with(
            0x61,
            &[(b_peer, PeerClass::CONTACT), (r, PeerClass::CONTACT_RELAY)],
            AddrRule::LabAnyIp,
            NO_SERVERS,
        );
        let a_listen = listen_loopback(&mut a).await;
        candidate(&mut a.behaviour_mut().dcutr, &a_listen);
        connect_from_a_new_port(&mut lab, &mut a).await;
        a.dial(lab.circuit_to(b_peer)).unwrap();
        let (mut identified, mut address, mut punched) = (false, false, false);
        drive(&mut lab, &mut [&mut a, &mut b], |e| {
            match e {
                Some((
                    0,
                    SwarmEvent::Behaviour(EndpointBehaviourEvent::Identify(
                        identify::Event::Received { peer_id, info, .. },
                    )),
                )) if peer_id == b_peer => identified |= info.listen_addrs.contains(&public),
                Some((0, SwarmEvent::NewExternalAddrOfPeer { peer_id, .. })) => {
                    address |= peer_id == b_peer
                }
                Some((0, SwarmEvent::Behaviour(EndpointBehaviourEvent::Dcutr(e)))) => {
                    punched |= e.remote_peer_id == b_peer
                }
                _ => {}
            }
            (identified && address && punched).then_some(())
        })
        .await;
        assert!(b.behaviour().dcutr.handlers_built() > before.0);
        assert!(b.behaviour().dcutr.relayed_handlers_built() > before.2);
    }

    /// Identify runs with contacts, own relays and relay members only: B
    /// reserves on R (its own relay) and identifies with it; A reaches B
    /// through R (a contact's relay to A) and identifies only with B.
    #[tokio::test]
    async fn identify_runs_only_with_contacts_and_own_relays() {
        let (a_peer, b_peer) = (peer_of(0x31), peer_of(0x32));
        let mut lab = relay_lab(RelayLimits::friends(), AllowPolicy::Open).await;
        let relay_addr = lab.relay_addr.clone();
        let (mut b, mut a) = circuit_pair(0x32, 0x31, AddrRule::GlobalOnly);
        reserve(&mut b, &relay_addr);
        drive(&mut lab, &mut [&mut b], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        a.dial(lab.circuit_to(b_peer)).unwrap();
        let mut a_got_b = false;
        drive(&mut lab, &mut [&mut a, &mut b], |e| {
            if let Some((
                0,
                SwarmEvent::Behaviour(EndpointBehaviourEvent::Identify(
                    identify::Event::Received { peer_id, .. },
                )),
            )) = &e
            {
                a_got_b |= *peer_id == b_peer;
            }
            a_got_b.then_some(())
        })
        .await;
        let quiet = Instant::now() + Duration::from_secs(2);
        drive(&mut lab, &mut [&mut a, &mut b], |_| {
            (Instant::now() >= quiet).then_some(())
        })
        .await;
        assert!(lab.identified.contains(&b_peer), "{:?}", lab.identified);
        assert!(!lab.identified.contains(&a_peer), "{:?}", lab.identified);
        assert_eq!(
            a.behaviour().identify.handlers_built(),
            1,
            "B's circuit only"
        );
    }

    /// Consent by circle: a relay serves circuits only between its members.
    /// A stranger never gets past the relay's peer gate; a member that is not
    /// B's contact reaches B's gate and is refused there, learning nothing; a
    /// contact gets a working Raven link stream.
    #[tokio::test]
    async fn the_relay_serves_circuits_only_between_its_members() {
        let r = relay_peer();
        let (a_peer, b_peer, m_peer, s_peer) =
            (peer_of(0x71), peer_of(0x72), peer_of(0x73), peer_of(0x74));
        let members = AllowPolicy::Peers([a_peer, b_peer, m_peer].into_iter().collect());
        let mut lab = relay_lab(RelayLimits::friends(), members).await;
        let relay_addr = lab.relay_addr.clone();
        let (mut b, mut a) = circuit_pair(0x72, 0x71, AddrRule::GlobalOnly);
        reserve(&mut b, &relay_addr);
        drive(&mut lab, &mut [&mut b], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        // Both hold B's card: B is their contact, R its relay.
        let holds_b = [(b_peer, PeerClass::CONTACT), (r, PeerClass::CONTACT_RELAY)];

        // A stranger: refused at the relay's peer gate.
        let mut s = endpoint_with(0x74, &holds_b, AddrRule::GlobalOnly, NO_SERVERS);
        s.dial(lab.circuit_to(b_peer)).unwrap();
        drive(&mut lab, &mut [&mut b, &mut s], |e| {
            if let Some((0, e)) = &e {
                assert!(
                    !matches!(
                        e,
                        SwarmEvent::IncomingConnection { .. }
                            | SwarmEvent::IncomingConnectionError { .. }
                    ),
                    "the stranger reached B"
                );
            }
            matches!(e, Some((1, SwarmEvent::OutgoingConnectionError { .. }))).then_some(())
        })
        .await;
        assert!(lab.relay.behaviour().peer_gate.counts().refused_inbound >= 1);
        let s_text = s_peer.to_string();
        assert!(
            !lab.relay_events.iter().any(|e| e.contains(&s_text)),
            "{:?}",
            lab.relay_events
        );
        assert_eq!(b.behaviour().peer_gate.counts(), GateCounts::default());

        // A member that is not B's contact: the relay serves it, B refuses
        // the circuit before accepting it, and M learns nothing of B.
        let mut m = endpoint_with(0x73, &holds_b, AddrRule::GlobalOnly, NO_SERVERS);
        m.dial(lab.circuit_to(b_peer)).unwrap();
        let mut learned = 0;
        let (mut m_failed, mut b_refused) = (false, false);
        drive(&mut lab, &mut [&mut b, &mut m], |e| {
            match &e {
                Some((0, e)) => b_refused |= gate_refusal(e).is_some_and(|n| n.relayed),
                Some((
                    1,
                    SwarmEvent::NewExternalAddrOfPeer { .. }
                    | SwarmEvent::Behaviour(EndpointBehaviourEvent::Identify(
                        identify::Event::Received { .. },
                    )),
                )) => learned += 1,
                Some((1, SwarmEvent::OutgoingConnectionError { .. })) => m_failed = true,
                _ => {}
            }
            (m_failed && b_refused).then_some(())
        })
        .await;
        assert_eq!(learned, 0);
        assert_eq!(b.behaviour().peer_gate.counts().refused_relayed, 1);
        let m_text = m_peer.to_string();
        assert!(
            lab.relay_events.iter().any(|e| e.contains(&m_text)),
            "the relay served the member: {:?}",
            lab.relay_events
        );
        assert_eq!(lab.guard.counts().refused_circuit_not_allowed, 0);

        // A contact: a Raven link stream through the relay.
        let (mut out, mut inn) = circuit_stream(&mut lab, &mut b, &mut a).await;
        let echo = tokio::spawn(async move {
            out.write_all(b"circle").await.unwrap();
            out.flush().await.unwrap();
            let mut buf = [0u8; 6];
            inn.read_exact(&mut buf).await.unwrap();
            buf
        });
        drive(&mut lab, &mut [&mut b, &mut a], |_| {
            echo.is_finished().then_some(())
        })
        .await;
        assert_eq!(&echo.await.unwrap(), b"circle");
    }

    /// The relay's circuit limiter asks for membership before the rate: a
    /// refused source spends no token of its source address.
    #[test]
    fn a_circuit_source_must_be_a_member_before_it_spends_a_token() {
        let limits = RelayLimits {
            circuit_rate_per_ip_per_min: 1,
            exempt_loopback: false,
            ..RelayLimits::friends()
        };
        let (member, stranger) = (PeerId::random(), PeerId::random());
        let from = addr("/ip4/198.51.100.7/tcp/4001");
        let t0 = Instant::now();
        let guard = RelayGuard::new(AllowPolicy::Peers([member].into_iter().collect()), &limits);
        for _ in 0..5 {
            assert!(!guard.admit_circuit_at(&stranger, &from, t0));
        }
        let c = guard.counts();
        assert_eq!(
            (c.refused_circuit_not_allowed, c.refused_circuit_rate),
            (5, 0)
        );
        assert_eq!(guard.rate_sources().1, 0, "no token spent");
        assert!(guard.admit_circuit_at(&member, &from, t0));
        assert!(!guard.admit_circuit_at(&member, &from, t0), "then the rate");
        assert_eq!(guard.counts().refused_circuit_rate, 1);
        assert!(guard.may_use(&member) && guard.is_listed(&member));
        assert!(!guard.may_use(&stranger) && !guard.is_listed(&stranger));

        let broken = RelayGuard::new(AllowPolicy::Unreadable, &limits);
        assert!(!broken.admit_circuit_at(&member, &from, t0));
        assert!(!broken.may_use(&member));
        let open = RelayGuard::new(AllowPolicy::Open, &limits);
        assert!(open.admit_circuit_at(&stranger, &from, t0));
        assert!(open.may_use(&stranger));
        assert!(!open.is_listed(&stranger), "an open relay lists nobody");
    }

    /// The dial-time address rule: a contact that offers a private address
    /// (an old or malicious node: stock libp2p, no rule) gets no hole-punch
    /// dial from a node under the production rule. A reserves and offers a
    /// global candidate, which the contact only records ([`DialRecord`]); A
    /// is the circuit's listener, so it drives the attempts: each of its
    /// dials to the private address is refused before it starts, and DCUtR
    /// gives up after its retries. Nothing leaves this machine. With both on
    /// the production rule on loopback, nobody has a candidate and nothing
    /// is dialled.
    #[tokio::test]
    async fn a_private_hole_punch_target_is_refused() {
        let r = relay_peer();
        let mut lab = relay_lab(RelayLimits::friends(), AllowPolicy::Open).await;
        let relay_addr = lab.relay_addr.clone();
        let (a_peer, w_peer) = (peer_of(0x41), peer_of(0x42));
        let mut a = endpoint_with(
            0x41,
            &[(r, PeerClass::OWN_RELAY), (w_peer, PeerClass::CONTACT)],
            AddrRule::GlobalOnly,
            NO_SERVERS,
        );
        a.behaviour_mut().dcutr.book_mut().observed(
            r,
            &addr("/ip4/8.8.8.8/tcp/7423"),
            true,
            Instant::now(),
        );
        reserve(&mut a, &relay_addr);
        drive(&mut lab, &mut [&mut a], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        let mut w = witness(0x42, a_peer);
        candidate(
            &mut w.behaviour_mut().dcutr,
            &addr("/ip4/192.168.1.2/tcp/7423"),
        );
        w.dial(lab.circuit_to(a_peer)).unwrap();
        let (mut dials, mut failed) = (0, None);
        tokio::time::timeout(Duration::from_secs(15), async {
            while failed.is_none() {
                tokio::select! {
                    event = lab.relay.select_next_some() => lab.on_event(event),
                    _ = w.select_next_some() => {}
                    event = a.select_next_some() => match event {
                        SwarmEvent::Dialing { peer_id, .. } => {
                            dials += usize::from(peer_id == Some(w_peer))
                        }
                        SwarmEvent::Behaviour(EndpointBehaviourEvent::Dcutr(e)) => {
                            failed = Some(e.result.is_err())
                        }
                        _ => {}
                    },
                }
            }
        })
        .await
        .expect("no hole-punch result");
        assert_eq!(failed, Some(true), "A gave up on the hole punch");
        assert!(a.behaviour().dcutr.refused_targets() >= 1);
        assert_eq!(dials, 0, "no hole-punch dial started");
        assert!(
            !w.behaviour().dials.seen.is_empty(),
            "the exchange ran (A's candidate reached the contact)"
        );

        // Both on the production rule: no candidate, no dial.
        let (c_peer, d_peer) = (peer_of(0x43), peer_of(0x44));
        let mut c = endpoint_with(
            0x43,
            &[(r, PeerClass::OWN_RELAY), (d_peer, PeerClass::CONTACT)],
            AddrRule::GlobalOnly,
            NO_SERVERS,
        );
        let mut d = endpoint_with(
            0x44,
            &[(c_peer, PeerClass::CONTACT), (r, PeerClass::CONTACT_RELAY)],
            AddrRule::GlobalOnly,
            NO_SERVERS,
        );
        let d_listen = listen_loopback(&mut d).await;
        candidate(&mut d.behaviour_mut().dcutr, &d_listen);
        reserve(&mut c, &relay_addr);
        drive(&mut lab, &mut [&mut c], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        connect_from_a_new_port(&mut lab, &mut d).await;
        d.dial(lab.circuit_to(c_peer)).unwrap();
        let mut dials = 0;
        drive(&mut lab, &mut [&mut c, &mut d], |e| match e {
            Some((_, SwarmEvent::Dialing { peer_id, .. }))
                if peer_id == Some(c_peer) || peer_id == Some(d_peer) =>
            {
                dials += 1;
                None
            }
            Some((0, SwarmEvent::Behaviour(EndpointBehaviourEvent::Dcutr(e)))) => {
                assert!(e.result.is_err());
                Some(())
            }
            _ => None,
        })
        .await;
        assert_eq!(dials, 0);
        assert_eq!(
            (
                c.behaviour().dcutr.refused_targets(),
                d.behaviour().dcutr.refused_targets()
            ),
            (0, 0)
        );
    }

    /// Phase 1 item 3: a relayed connection's DCUtR handler offers the
    /// candidate book, and the hole punch upgrades it. Debug lab rule on
    /// loopback: each endpoint's own TCP and QUIC listen addresses are its
    /// candidates.
    #[tokio::test]
    async fn relayed_connections_carry_the_books_candidates_and_upgrade() {
        let mut lab = relay_lab(RelayLimits::friends(), AllowPolicy::Open).await;
        let relay_addr = lab.relay_addr.clone();
        let (mut b, mut a) = circuit_pair(0x52, 0x51, AddrRule::LabAnyIp);
        let (a_peer, b_peer) = (*a.local_peer_id(), *b.local_peer_id());
        for ep in [&mut a, &mut b] {
            listen_loopback(ep).await;
            listen_quic_loopback(ep).await;
            let offered = ep.behaviour().dcutr.book().candidates(Instant::now());
            assert_eq!(offered.len(), 2, "{offered:?}");
        }
        connect_from_a_new_port(&mut lab, &mut b).await;
        reserve(&mut b, &relay_addr);
        drive(&mut lab, &mut [&mut b], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        connect_from_a_new_port(&mut lab, &mut a).await;
        a.dial(lab.circuit_to(b_peer)).unwrap();
        let (mut upgraded, mut direct) = (false, false);
        drive(&mut lab, &mut [&mut a, &mut b], |e| {
            match e {
                Some((_, SwarmEvent::Behaviour(EndpointBehaviourEvent::Dcutr(e)))) => {
                    upgraded |= e.result.is_ok()
                }
                Some((
                    i,
                    SwarmEvent::ConnectionEstablished {
                        peer_id, endpoint, ..
                    },
                )) => {
                    let other = if i == 0 { b_peer } else { a_peer };
                    direct |= peer_id == other && !endpoint.is_relayed();
                }
                _ => {}
            }
            (upgraded && direct).then_some(())
        })
        .await;
        for ep in [&a, &b] {
            assert!(ep.behaviour().dcutr.relayed_handlers_built() >= 1);
            assert_eq!(ep.behaviour().dcutr.refused_targets(), 0);
        }
    }

    /// Phase 4 (P4.24): a hopeless hole punch is skipped before any DCUtR
    /// handler is built. A, the circuit's dialler, knows both NAT mappings
    /// vary: its relayed connection to B gets a dummy handler (no relayed
    /// handler built, one skip counted). B, the circuit's listener, opens
    /// its CONNECT as always and finds no DCUtR protocol: one Err, and no
    /// retry (dcutr 0.15 behaviour.rs:283-293); nobody dials anybody, and
    /// the relayed connection stays.
    #[tokio::test]
    async fn hole_punch_skips_before_building_a_dcutr_handler() {
        use crate::natclass::{Mapping, NatSummary, SkipWhy};
        let mut lab = relay_lab(RelayLimits::friends(), AllowPolicy::Open).await;
        let relay_addr = lab.relay_addr.clone();
        let (mut b, mut a) = circuit_pair(0x58, 0x57, AddrRule::LabAnyIp);
        let (a_peer, b_peer) = (*a.local_peer_id(), *b.local_peer_id());
        for ep in [&mut a, &mut b] {
            listen_loopback(ep).await;
        }
        let varies = NatSummary {
            v4_tcp: Mapping::Varies,
            v4_quic: Mapping::Varies,
            ..NatSummary::default()
        };
        {
            let hp = &mut a.behaviour_mut().dcutr;
            let policy = hp.policy_mut();
            policy.enabled = true;
            // Directly, not through set_own: no lab force applies.
            policy.own = varies;
            policy.set_remote(b_peer, varies, Instant::now() + Duration::from_secs(600));
        }
        connect_from_a_new_port(&mut lab, &mut b).await;
        reserve(&mut b, &relay_addr);
        drive(&mut lab, &mut [&mut b], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        connect_from_a_new_port(&mut lab, &mut a).await;
        a.dial(lab.circuit_to(b_peer)).unwrap();
        let (mut b_errors, mut a_events, mut dials) = (0, 0, 0);
        let mut quiet_until: Option<Instant> = None;
        drive(&mut lab, &mut [&mut a, &mut b], |e| {
            match e {
                Some((0, SwarmEvent::Behaviour(EndpointBehaviourEvent::Dcutr(_)))) => a_events += 1,
                Some((1, SwarmEvent::Behaviour(EndpointBehaviourEvent::Dcutr(e)))) => {
                    assert!(e.result.is_err(), "B upgraded without A's DCUtR");
                    b_errors += 1;
                    // Long enough for a retry (DCUtR's own come at once).
                    quiet_until.get_or_insert(Instant::now() + Duration::from_secs(4));
                }
                Some((
                    i,
                    SwarmEvent::ConnectionEstablished {
                        peer_id, endpoint, ..
                    },
                )) => {
                    let other = if i == 0 { b_peer } else { a_peer };
                    assert!(
                        peer_id != other || endpoint.is_relayed(),
                        "a direct connection appeared"
                    );
                }
                Some((
                    i,
                    SwarmEvent::ConnectionClosed {
                        peer_id, endpoint, ..
                    },
                )) => {
                    let other = if i == 0 { b_peer } else { a_peer };
                    assert!(
                        peer_id != other || !endpoint.is_relayed(),
                        "the relayed connection closed"
                    );
                }
                Some((_, SwarmEvent::Dialing { peer_id, .. })) => {
                    dials += usize::from(peer_id == Some(a_peer) || peer_id == Some(b_peer))
                }
                _ => {}
            }
            quiet_until
                .is_some_and(|t| Instant::now() >= t)
                .then_some(())
        })
        .await;
        assert_eq!(b_errors, 1, "one CONNECT failure on B, no retry");
        assert_eq!(a_events, 0, "A ran no hole punch");
        assert_eq!(dials, 0, "nobody dialled a candidate");
        let hp = &a.behaviour().dcutr;
        assert_eq!(hp.relayed_handlers_built(), 0);
        assert_eq!(hp.skipped(), 1);
        assert_eq!(hp.last_skip(), Some(SkipWhy::BothVary));
        assert_eq!(b.behaviour().dcutr.skipped(), 0);
        assert!(a.is_connected(&b_peer), "the relayed connection stays");
    }

    /// Without a usable candidate (production rule on loopback) nothing is
    /// offered or dialled, no direct connection appears, and the relayed
    /// connection stays up (Carrier Conformance §11.5.5: on failure keep the
    /// circuit).
    #[tokio::test]
    async fn without_usable_candidates_nothing_upgrades_and_the_relay_path_stays() {
        let mut lab = relay_lab(RelayLimits::friends(), AllowPolicy::Open).await;
        let relay_addr = lab.relay_addr.clone();
        let (mut b, mut a) = circuit_pair(0x54, 0x53, AddrRule::GlobalOnly);
        let (a_peer, b_peer) = (*a.local_peer_id(), *b.local_peer_id());
        for ep in [&mut a, &mut b] {
            listen_loopback(ep).await;
            listen_quic_loopback(ep).await;
            assert!(ep
                .behaviour()
                .dcutr
                .book()
                .candidates(Instant::now())
                .is_empty());
        }
        connect_from_a_new_port(&mut lab, &mut b).await;
        reserve(&mut b, &relay_addr);
        drive(&mut lab, &mut [&mut b], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        connect_from_a_new_port(&mut lab, &mut a).await;
        a.dial(lab.circuit_to(b_peer)).unwrap();
        let mut quiet_until: Option<Instant> = None;
        let mut dials = 0;
        drive(&mut lab, &mut [&mut a, &mut b], |e| {
            match e {
                Some((_, SwarmEvent::Behaviour(EndpointBehaviourEvent::Dcutr(e)))) => {
                    assert!(e.result.is_err(), "upgraded without a candidate");
                    quiet_until.get_or_insert(Instant::now() + Duration::from_secs(3));
                }
                Some((
                    i,
                    SwarmEvent::ConnectionEstablished {
                        peer_id, endpoint, ..
                    },
                )) => {
                    let other = if i == 0 { b_peer } else { a_peer };
                    assert!(
                        peer_id != other || endpoint.is_relayed(),
                        "a direct connection appeared"
                    );
                }
                Some((
                    i,
                    SwarmEvent::ConnectionClosed {
                        peer_id, endpoint, ..
                    },
                )) => {
                    let other = if i == 0 { b_peer } else { a_peer };
                    assert!(
                        peer_id != other || !endpoint.is_relayed(),
                        "the relayed connection closed"
                    );
                }
                Some((_, SwarmEvent::Dialing { peer_id, .. })) => {
                    dials += usize::from(peer_id == Some(a_peer) || peer_id == Some(b_peer))
                }
                _ => {}
            }
            quiet_until
                .is_some_and(|t| Instant::now() >= t)
                .then_some(())
        })
        .await;
        assert!(a.is_connected(&b_peer) && b.is_connected(&a_peer));
        assert_eq!(dials, 0, "no hole-punch dial");
        for ep in [&a, &b] {
            assert!(ep.behaviour().dcutr.relayed_handlers_built() >= 1);
            assert_eq!(ep.behaviour().dcutr.refused_targets(), 0);
        }
    }

    /// Records every dial to `target` that names no circuit (a hole punch's
    /// dial: its addresses are exactly the candidates the target sent), then
    /// refuses it, so nothing leaves this machine.
    struct DialRecord {
        target: PeerId,
        seen: Vec<Vec<Multiaddr>>,
    }

    impl NetworkBehaviour for DialRecord {
        type ConnectionHandler = dummy::ConnectionHandler;
        type ToSwarm = Infallible;

        fn handle_pending_outbound_connection(
            &mut self,
            _connection_id: ConnectionId,
            peer: Option<PeerId>,
            addresses: &[Multiaddr],
            _effective_role: Endpoint,
        ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
            if peer == Some(self.target)
                && !addresses.is_empty()
                && !addresses.iter().any(is_circuit)
            {
                self.seen.push(addresses.to_vec());
                return Err(ConnectionDenied::new(std::io::Error::other("recorded")));
            }
            Ok(Vec::new())
        }

        fn handle_established_inbound_connection(
            &mut self,
            _connection_id: ConnectionId,
            _peer: PeerId,
            _local_addr: &Multiaddr,
            _remote_addr: &Multiaddr,
        ) -> Result<THandler<Self>, ConnectionDenied> {
            Ok(dummy::ConnectionHandler)
        }

        fn handle_established_outbound_connection(
            &mut self,
            _connection_id: ConnectionId,
            _peer: PeerId,
            _addr: &Multiaddr,
            _role_override: Endpoint,
            _port_use: PortUse,
        ) -> Result<THandler<Self>, ConnectionDenied> {
            Ok(dummy::ConnectionHandler)
        }

        fn on_swarm_event(&mut self, _event: FromSwarm) {}

        fn on_connection_handler_event(
            &mut self,
            _peer: PeerId,
            _connection_id: ConnectionId,
            event: THandlerOutEvent<Self>,
        ) {
            libp2p::core::util::unreachable(event)
        }

        fn poll(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
            Poll::Pending
        }
    }

    /// Stock rust-libp2p DCUtR that records what a hole punch offers it.
    #[derive(NetworkBehaviour)]
    struct Witness {
        dials: DialRecord,
        relay_client: relay::client::Behaviour,
        dcutr: libp2p::dcutr::Behaviour,
    }

    /// A [`Witness`] that records the hole-punch dials to `target`.
    fn witness(seed: u8, target: PeerId) -> Swarm<Witness> {
        SwarmBuilder::with_existing_identity(key(seed))
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .unwrap()
            .with_behaviour(|key, relay_client| Witness {
                dials: DialRecord {
                    target,
                    seen: Vec::new(),
                },
                relay_client,
                dcutr: libp2p::dcutr::Behaviour::new(key.public().to_peer_id()),
            })
            .unwrap()
            .build()
    }

    /// Identify's rewritten guess (the observed IP with our listen port) and
    /// a private swarm candidate go to the book, never to libp2p's own list:
    /// the CONNECT a contact receives is the book's, the raw relay-observed
    /// port first and the guess last, though the guess arrived first (the
    /// inner DCUtR would have offered it alone).
    #[tokio::test]
    async fn swarm_candidates_never_reach_the_inner_behaviour() {
        let r = relay_peer();
        let mut lab = relay_lab(RelayLimits::friends(), AllowPolicy::Open).await;
        let relay_addr = lab.relay_addr.clone();
        let w_peer = peer_of(0x5C);
        let mut b = endpoint_with(
            0x5B,
            &[(r, PeerClass::OWN_RELAY), (w_peer, PeerClass::CONTACT)],
            AddrRule::GlobalOnly,
            NO_SERVERS,
        );
        let b_peer = *b.local_peer_id();
        candidate(
            &mut b.behaviour_mut().dcutr,
            &addr("/ip4/11.0.1.2/tcp/7423"),
        );
        candidate(
            &mut b.behaviour_mut().dcutr,
            &addr("/ip4/192.168.1.2/tcp/7423"),
        );
        b.behaviour_mut().dcutr.book_mut().observed(
            r,
            &addr("/ip4/11.0.1.2/tcp/30000"),
            true,
            Instant::now(),
        );
        reserve(&mut b, &relay_addr);
        drive(&mut lab, &mut [&mut b], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        let mut w = witness(0x5C, b_peer);
        // The witness needs a candidate of its own for the exchange to run:
        // a documentation address, which B's production rule never dials.
        candidate(
            &mut w.behaviour_mut().dcutr,
            &addr("/ip4/192.0.2.1/tcp/7423"),
        );
        w.dial(lab.circuit_to(b_peer)).unwrap();
        tokio::time::timeout(Duration::from_secs(15), async {
            while w.behaviour().dials.seen.is_empty() {
                tokio::select! {
                    event = lab.relay.select_next_some() => lab.on_event(event),
                    _ = b.select_next_some() => {}
                    _ = w.select_next_some() => {}
                }
            }
        })
        .await
        .expect("no hole-punch dial recorded");
        let named = |a: &str| addr(a).with(Protocol::P2p(b_peer));
        assert_eq!(
            w.behaviour().dials.seen[0],
            vec![
                named("/ip4/11.0.1.2/tcp/30000"),
                named("/ip4/11.0.1.2/tcp/7423")
            ]
        );
        assert_eq!(b.behaviour().dcutr.relayed_handlers_built(), 1);
    }

    #[derive(NetworkBehaviour)]
    struct NatServer {
        autonat: autonat::v2::server::Behaviour,
        identify: identify::Behaviour,
    }

    /// An AutoNAT v2 server without the relay's DialBackGuard (it may dial
    /// back to loopback), with Identify so clients see that it serves.
    async fn nat_server(seed: u8) -> (Swarm<NatServer>, Multiaddr) {
        let mut swarm = SwarmBuilder::with_existing_identity(key(seed))
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|key| NatServer {
                autonat: autonat::v2::server::Behaviour::new(crate::autonat_rng()),
                identify: identify::Behaviour::new(identify_config(key, Duration::from_secs(60))),
            })
            .unwrap()
            .build();
        let at = listen_loopback(&mut swarm).await;
        let at = at.with(Protocol::P2p(*swarm.local_peer_id()));
        (swarm, at)
    }

    /// One AutoNAT client per relay slot: the same candidate is tested once
    /// by each client, each against its own slot's relay only, and neither
    /// client hears of the other's connections (they `expect` that).
    #[tokio::test]
    async fn each_relay_slot_gets_its_own_autonat_test() {
        let (s1, s2) = (peer_of(0x81), peer_of(0x82));
        let (mut server_1, at_1) = nat_server(0x81).await;
        let (mut server_2, at_2) = nat_server(0x82).await;
        let config = EndpointConfig {
            gate: admitted(&[(s1, PeerClass::OWN_RELAY), (s2, PeerClass::OWN_RELAY)]),
            hole_punch_addrs: AddrRule::LabAnyIp,
            autonat_servers: [Some(s1), Some(s2)],
            autonat_interval: Duration::from_millis(500),
            ..EndpointConfig::default()
        };
        let mut c = build_endpoint_swarm(&gate(), key(0x80), config).unwrap();
        let c_listen = listen_loopback(&mut c).await;
        // The candidate both clients test, as Identify would report it.
        candidate(&mut c.behaviour_mut().autonat, &c_listen);
        candidate(&mut c.behaviour_mut().autonat_2, &c_listen);
        // From a new local port each: `c` listens, and a dial from its
        // listen port may meet a 4-tuple some other socket on a busy machine
        // still holds ([`connect_from_a_new_port`]).
        for (server, at) in [(s1, at_1), (s2, at_2)] {
            c.dial(
                libp2p::swarm::dial_opts::DialOpts::peer_id(server)
                    .addresses(vec![at])
                    .allocate_new_port()
                    .build(),
            )
            .unwrap();
        }
        let (mut first, mut second) = (Vec::new(), Vec::new());
        let mut seen = Vec::new();
        let tested = |results: &Vec<(Multiaddr, PeerId, bool)>| {
            results.iter().any(|(a, _, ok)| *a == c_listen && *ok)
        };
        tokio::time::timeout(Duration::from_secs(20), async {
            while !(tested(&first) && tested(&second)) {
                tokio::select! {
                    _ = server_1.select_next_some() => {}
                    _ = server_2.select_next_some() => {}
                    event = c.select_next_some() => match event {
                        SwarmEvent::Behaviour(EndpointBehaviourEvent::Autonat(e)) => {
                            first.push((e.tested_addr, e.server, e.result.is_ok()))
                        }
                        SwarmEvent::Behaviour(EndpointBehaviourEvent::Autonat2(e)) => {
                            second.push((e.tested_addr, e.server, e.result.is_ok()))
                        }
                        other => seen.push(format!("{other:?}")),
                    },
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!("autonat results: {first:?} / {second:?}\nother events: {seen:#?}")
        });
        assert!(first.iter().all(|(_, s, _)| *s == s1), "{first:?}");
        assert!(second.iter().all(|(_, s, _)| *s == s2), "{second:?}");
        // The request connection and the dial-back, each client its own.
        assert!(c.behaviour().autonat.handlers_built() >= 2);
        assert!(c.behaviour().autonat_2.handlers_built() >= 2);
        // Every connection closes; each client hears only of its own.
        for p in [s1, s2] {
            let _ = c.disconnect_peer_id(p);
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            while c.connected_peers().next().is_some() {
                tokio::select! {
                    _ = server_1.select_next_some() => {}
                    _ = server_2.select_next_some() => {}
                    _ = c.select_next_some() => {}
                }
            }
        })
        .await
        .expect("every connection closed");
    }

    /// RWS1 §9 on the real composition: while the restricted-network flag is
    /// set, no candidate (Identify's own, from the relay's observation, or
    /// one shown to the whole behaviour) reaches either AutoNAT client, so
    /// the relay is asked to test nothing, and the candidate book offers
    /// nothing; once it clears, the next candidate is tested and the book
    /// offers again. Only AutoNAT and DCUtR follow the flag.
    #[tokio::test]
    async fn a_restricted_endpoint_asks_its_relay_no_autonat_test() {
        use libp2p::swarm::dial_opts::DialOpts;
        use std::sync::atomic::Ordering;

        let s1 = peer_of(0x85);
        let (mut server, at) = nat_server(0x85).await;
        let restricted = Arc::new(AtomicBool::new(true));
        let config = EndpointConfig {
            gate: admitted(&[(s1, PeerClass::OWN_RELAY)]),
            hole_punch_addrs: AddrRule::LabAnyIp,
            autonat_servers: [Some(s1), None],
            autonat_interval: Duration::from_millis(500),
            restricted: restricted.clone(),
            ..EndpointConfig::default()
        };
        let mut c = build_endpoint_swarm(&gate(), key(0x86), config).unwrap();
        let c_listen = listen_loopback(&mut c).await;
        let b = c.behaviour();
        assert!(b.autonat.restricted() && b.autonat_2.restricted());
        assert!(b.dcutr.book().restricted());
        assert!(!b.identify.restricted());
        assert!(b.dcutr.book().candidates(Instant::now()).is_empty());
        assert_eq!(
            b.dcutr.book().counts(Instant::now()),
            crate::candidates::CandidateCounts::default()
        );

        candidate(c.behaviour_mut(), &c_listen);
        c.dial(
            DialOpts::peer_id(s1)
                .addresses(vec![at])
                .allocate_new_port()
                .build(),
        )
        .unwrap();
        // Until the server's Identify arrived (its own candidate with it,
        // and the client then knows the server serves), then twelve probe
        // intervals more: nothing is tested.
        let mut tested = Vec::new();
        let mut seen = Vec::new();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                tokio::select! {
                    _ = server.select_next_some() => {}
                    event = c.select_next_some() => match event {
                        SwarmEvent::Behaviour(EndpointBehaviourEvent::Identify(
                            identify::Event::Received { peer_id, .. },
                        )) if peer_id == s1 => break,
                        SwarmEvent::Behaviour(EndpointBehaviourEvent::Autonat(e)) => {
                            tested.push(e.tested_addr)
                        }
                        other => seen.push(format!("{other:?}")),
                    },
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no Identify from the server; events: {seen:#?}"));
        let quiet = tokio::time::sleep(Duration::from_secs(6));
        tokio::pin!(quiet);
        loop {
            tokio::select! {
                _ = &mut quiet => break,
                _ = server.select_next_some() => {}
                event = c.select_next_some() => {
                    if let SwarmEvent::Behaviour(EndpointBehaviourEvent::Autonat(e)) = event {
                        tested.push(e.tested_addr);
                    }
                }
            }
        }
        assert!(tested.is_empty(), "tested while restricted: {tested:?}");
        assert!(c.is_connected(&s1));
        assert!(c
            .behaviour()
            .dcutr
            .book()
            .candidates(Instant::now())
            .is_empty());

        // The flag clears: the next candidate is tested, and the book offers
        // the listen address again (the debug lab's rule admits loopback).
        restricted.store(false, Ordering::SeqCst);
        assert!(c
            .behaviour()
            .dcutr
            .book()
            .candidates(Instant::now())
            .contains(&c_listen));
        candidate(c.behaviour_mut(), &c_listen);
        tokio::time::timeout(Duration::from_secs(20), async {
            while !tested.contains(&c_listen) {
                tokio::select! {
                    _ = server.select_next_some() => {}
                    event = c.select_next_some() => {
                        if let SwarmEvent::Behaviour(EndpointBehaviourEvent::Autonat(e)) = event {
                            assert_eq!(e.server, s1);
                            tested.push(e.tested_addr);
                        }
                    }
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("not tested after the flag cleared: {tested:?}"));
    }

    /// A residual the waiver discloses (§4; owner decision on open relays),
    /// pinned so a future fix shows up here: on an `--open` relay a
    /// stranger still tells "reserved, but the peer refused"
    /// (CONNECTION_FAILED) from "not reserved" (NO_RESERVATION). It learns
    /// nothing else: no address, no Identify, no hole punch.
    #[tokio::test]
    async fn open_relay_presence_residual() {
        let r = relay_peer();
        let mut lab = relay_lab(RelayLimits::open(), AllowPolicy::Open).await;
        let relay_addr = lab.relay_addr.clone();
        let mut b = endpoint_with(
            0x92,
            &[(r, PeerClass::OWN_RELAY)],
            AddrRule::GlobalOnly,
            NO_SERVERS,
        );
        reserve(&mut b, &relay_addr);
        drive(&mut lab, &mut [&mut b], |e| {
            e.filter(|(_, e)| accepted(e)).map(|_| ())
        })
        .await;
        let mut s = stranger(0x9E);
        let mut learned = Learned::default();
        s.dial(lab.circuit_to(peer_of(0x93))).unwrap();
        drive_stranger(&mut lab, &mut b, &mut s, &mut learned, |_, l| {
            l.failed.len() == 1
        })
        .await;
        s.dial(lab.circuit_to(peer_of(0x92))).unwrap();
        drive_stranger(&mut lab, &mut b, &mut s, &mut learned, |_, l| {
            l.failed.len() == 2
        })
        .await;
        assert!(learned.failed[0].contains("NoReservation"), "{learned:?}");
        assert!(
            learned.failed[1].contains("ConnectionFailed"),
            "{learned:?}"
        );
        assert_eq!(
            (
                learned.addresses,
                learned.identify,
                learned.dcutr,
                learned.dials
            ),
            (0, 0, 0, 0),
            "{learned:?}"
        );
        assert_eq!(b.behaviour().peer_gate.counts().refused_relayed, 1);
    }

    #[test]
    fn circuit_addresses_are_recognised() {
        assert!(is_circuit(&addr(
            "/ip4/127.0.0.1/tcp/1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit"
        )));
        assert!(!is_circuit(&addr("/ip4/127.0.0.1/tcp/1")));
    }
}
