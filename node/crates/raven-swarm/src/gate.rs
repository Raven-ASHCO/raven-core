//! The peer gate (any-network plan §2.4, decision D3): who may hold a libp2p
//! connection to this host at all, decided before any protocol handler
//! exists.
//!
//! **Who is admitted.** Every remote PeerId has a [`PeerClass`], a set of
//! bits (one peer can be a contact and a relay at once), and [`admits`] is the
//! whole policy:
//!
//! | connection | admitted classes |
//! |---|---|
//! | a circuit (`/p2p-circuit`), either direction | CONTACT, CONTACT_HIDDEN |
//! | direct, inbound | CONTACT, CONTACT_HIDDEN, OWN_RELAY, RELAY_MEMBER |
//! | direct, outbound | any class but NONE |
//!
//! A circuit carries Raven links only, so only contacts get one. A hidden
//! contact (CONTACT_HIDDEN: this node hides its IP from it, or its PeerId is
//! learned from route hints and not proven yet) gets links like any contact,
//! but no hole punching and no Identify (their scopes are CONTACT and
//! [`IDENTIFY_SCOPE`]), so nothing it is told names an address of ours. A relay a
//! contact's `via=` names (CONTACT_RELAY) is dialled to reach that contact
//! and is never admitted inbound. An own relay is admitted inbound for its
//! AutoNAT v2 dial-back: the v2 client asks only peers it dialled itself
//! (libp2p-autonat 0.16 client/behaviour.rs:85-104), and the server dials
//! back from its own key (server/behaviour.rs:112-123).
//!
//! **Why [`PeerGate`] is composed third**, right after `limits` and
//! `ip_limits` and before the relay, DCUtR, AutoNAT, Identify and the Raven
//! link (checked against libp2p 0.57):
//! - swarm-derive 0.36 builds `handle_established_*` as nested
//!   `select(select(f0?, f1?), f2?)` (lib.rs:289-310, 339-360): the fields
//!   are asked in declaration order and the first `Err` returns before any
//!   later field is asked. The pending hooks (272-287, 312-337) are `?`
//!   statements in the same order.
//! - On a denial the swarm reports `ListenFailure` / `DialFailure` and
//!   returns before it spawns the connection (libp2p-swarm 0.48
//!   lib.rs:700-763, and 950-975 for a pending inbound denial, which reports
//!   `peer_id: None`): no handler of any field is ever polled.
//!
//! So a refused peer never reaches a protocol handler, and DCUtR never
//! records a direct connection (dcutr 0.15 behaviour.rs:173-200) that a
//! later field then denies.
//!
//! **Circuits are refused before Noise.** The relay client hands an incoming
//! circuit to the swarm with `send_back_addr = /p2p/<src>` taken from the
//! STOP message (libp2p-relay 0.22 priv_client/transport.rs:401-405) and
//! accepts the STOP only when the relayed connection is first polled
//! (priv_client.rs:469-479), which happens only after
//! `handle_pending_inbound_connection` admitted it. A stranger's circuit is
//! therefore refused before this host accepts it or runs Noise. That check
//! only denies: a relay could lie about the source, so admission waits for
//! the Noise-proven PeerId at the established stage.
//!
//! **Per-protocol scope.** [`Scoped`] runs a behaviour only on connections
//! of the peers in its scope. A behaviour cannot simply be told about fewer
//! peers: DCUtR (behaviour.rs:157, 161) and the AutoNAT client
//! (client/behaviour.rs:135, 175, 208) `expect` a `ConnectionClosed` only for
//! connections they saw, Identify notifies every connection it heard of
//! (identify 0.48 behaviour.rs:551-570), and the `Either` handler panics when
//! a notification reaches the wrong side (swarm handler/either.rs:106-111).
//!
//! **Hole punching.** [`HolePunch`] runs DCUtR for verified contacts only
//! and holds it to an [`AddrRule`] both ways: the candidates it offers, and
//! every address it dials. What it offers is Raven's [`CandidateBook`]
//! (raw relay-observed addresses, router mappings, own IPv6; never what the
//! rule refuses), not libp2p's own list. DCUtR dials whatever the remote
//! sent, with `PeerCondition::Always` (dcutr 0.15 behaviour.rs:274-283,
//! 306-320), and a behaviour cannot narrow a dial's addresses (its
//! pending-outbound hook can only add some, libp2p-swarm 0.48
//! lib.rs:459-480), so such a dial is refused whole.
//!
//! **Counts only.** [`PeerNotAdmitted`] names no peer and [`GateCounts`]
//! counts refusals, so a log line carries counts only (NAT spec §5).
//! libp2p-allow-block-list 0.7 is not used: its `NotAllowed` prints the
//! PeerId (lib.rs:172-178), and it knows no classes, direction or circuits.
//!
//! **What it does not do.** A relay's circuit limiter sees only the source,
//! never the destination (libp2p-relay 0.22 behaviour.rs:682-747), so a
//! relay cannot ask a destination for consent per source: a relay serves its
//! allow-list as one circle ([`RelayGuard::admit_circuit_at`]).
//! Per-destination consent is a Phase 2 decision.

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::ops::{BitOr, BitOrAssign};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{ready, Context, Poll};
use std::time::Instant;

use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::behaviour::ConnectionEstablished;
// `either::Either`, as the derive itself uses it (libp2p-swarm 0.48
// lib.rs:72-74): no `either` dependency of our own.
use libp2p::swarm::derive_prelude::Either;
use libp2p::swarm::{
    dummy, ConnectionClosed, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour,
    NewExternalAddrCandidate, NotifyHandler, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::{dcutr, Multiaddr, PeerId};

use crate::candidates::CandidateBook;
use crate::host::{addr_ip, is_circuit, is_global_ip, RelayGuard};
use crate::natclass::{PunchPolicy, SkipWhy};

// ── Classes and the policy ───────────────────────────────────────────────────

/// Why a remote PeerId may connect (a set of bits).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PeerClass(u8);

impl PeerClass {
    /// Not admitted at all.
    pub const NONE: Self = Self(0);
    /// A verified (pinned), unblocked contact: its card's `p2p=` PeerId.
    pub const CONTACT: Self = Self(1);
    /// A relay this host reserves on (`--p2p-relay`, RAVEN_P2P_RELAYS, policy),
    /// or one automatic relay choice picked ([`GateHandle::set_auto_relays`]).
    pub const OWN_RELAY: Self = Self(2);
    /// A relay a verified contact's `via=` names: dialled to reach the
    /// contact, never admitted inbound, never given Identify, AutoNAT or
    /// DCUtR.
    pub const CONTACT_RELAY: Self = Self(4);
    /// On this host's relay allow-list: may reserve and open circuits here.
    pub const RELAY_MEMBER: Self = Self(8);
    /// A verified contact this node hides its IP from (D4), or whose PeerId
    /// is learned (RRH1 route hints) and not yet proven by a p2p link: links
    /// yes (direct or relayed, both ways), DCUtR, candidates and Identify no.
    /// The bits from 32 up are free.
    pub const CONTACT_HIDDEN: Self = Self(16);

    /// Both sets of bits (`|` in a `const`).
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Do `self` and `other` share a bit?
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Did `self` have a bit that `now` lacks?
    pub const fn lost(self, now: Self) -> bool {
        self.0 & !now.0 != 0
    }
}

impl BitOr for PeerClass {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        self.union(other)
    }
}

impl BitOrAssign for PeerClass {
    fn bitor_assign(&mut self, other: Self) {
        *self = self.union(other);
    }
}

/// A contact, hidden or not: what a circuit (a Raven link) admits.
const ANY_CONTACT: PeerClass = PeerClass::CONTACT.union(PeerClass::CONTACT_HIDDEN);

/// Classes admitted on a direct inbound connection.
const INBOUND_DIRECT: PeerClass = ANY_CONTACT
    .union(PeerClass::OWN_RELAY)
    .union(PeerClass::RELAY_MEMBER);

/// Identify's scope on an endpoint: contacts, own relays and relay members
/// (never a stranger or a contact's relay).
pub const IDENTIFY_SCOPE: PeerClass = PeerClass::CONTACT
    .union(PeerClass::OWN_RELAY)
    .union(PeerClass::RELAY_MEMBER);

/// The scopes a protocol is given a connection for when it is established,
/// and keeps it for: [`HolePunch`] (CONTACT) and Identify
/// ([`IDENTIFY_SCOPE`]). [`PeerGate::recheck`] names a connection that
/// leaves one of them even while it is still admitted.
const SCOPES: [PeerClass; 2] = [PeerClass::CONTACT, IDENTIFY_SCOPE];

/// The classes [`GateHandle::admit_dial`] admits.
const DIAL_CLASSES: [PeerClass; 3] = [
    PeerClass::CONTACT,
    PeerClass::CONTACT_HIDDEN,
    PeerClass::CONTACT_RELAY,
];

/// The whole policy in one place (see the module table).
pub fn admits(class: PeerClass, inbound: bool, relayed: bool) -> bool {
    if relayed {
        // Circuits carry Raven links only.
        return class.intersects(ANY_CONTACT);
    }
    if inbound {
        return class.intersects(INBOUND_DIRECT);
    }
    class != PeerClass::NONE
}

/// Where a gate or a scope looks a peer's class up.
pub trait Admission: Send + 'static {
    fn class_of(&self, peer: &PeerId) -> PeerClass;
}

/// Admits one PeerId as OWN_RELAY and nobody else: the scope of the AutoNAT
/// client of one relay slot (its requests and that relay's dial-backs).
#[derive(Clone, Copy, Debug, Default)]
pub struct OnlyPeer(pub Option<PeerId>);

impl Admission for OnlyPeer {
    fn class_of(&self, peer: &PeerId) -> PeerClass {
        if self.0.as_ref() == Some(peer) {
            PeerClass::OWN_RELAY
        } else {
            PeerClass::NONE
        }
    }
}

/// A dedicated relay (`raven-node relay`) admits the peers that may use it
/// (its allow-list, or anyone with `--open`) and nobody else.
impl Admission for RelayGuard {
    fn class_of(&self, peer: &PeerId) -> PeerClass {
        if self.may_use(peer) {
            PeerClass::RELAY_MEMBER
        } else {
            PeerClass::NONE
        }
    }
}

// ── The admitted set of an endpoint ─────────────────────────────────────────

/// The peers an endpoint admits. Clones share one state (like
/// [`RelayGuard`]), so the host loop reloads the set the swarm's gate reads.
/// The default admits nobody (fail closed).
#[derive(Clone, Debug, Default)]
pub struct GateHandle {
    state: Arc<Mutex<GateState>>,
}

#[derive(Debug, Default)]
struct GateState {
    /// From contacts.json, the block list and the configured relays.
    files: HashMap<PeerId, PeerClass>,
    /// [`GateHandle::admit_dial`], per peer and class (one of
    /// [`DIAL_CLASSES`]).
    dialled: HashMap<(PeerId, PeerClass), DialAdmission>,
    /// [`GateHandle::set_auto_relays`]: OWN_RELAY on top of the files.
    auto: HashSet<PeerId>,
    /// `service --relay`: the PeerIds its allow-list names.
    relay: Option<RelayGuard>,
    /// The contact book or the block list could not be read.
    unreadable: bool,
    /// When the reading of `files` began ([`GateHandle::replace`]).
    files_read_at: Option<Instant>,
}

/// One class [`GateHandle::admit_dial`] admitted a peer with.
#[derive(Clone, Copy, Debug)]
struct DialAdmission {
    /// When the latest dial that admitted it checked the contact (began
    /// reading the files).
    at: Instant,
    /// Its deadline.
    until: Instant,
}

/// [`GateHandle::admit_dial`] refused: the files the gate holds were read
/// after the dial checked its contact, and they do not name the peer a
/// contact (it was blocked, unpinned or removed since, its book cannot be
/// read, or the dial names a PeerId its card does not). The caller checks
/// the contact again and dials with that check, or gives up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialCheckStale;

impl fmt::Display for DialCheckStale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the contact book or block list changed after the dial checked the contact")
    }
}

impl Error for DialCheckStale {}

impl GateHandle {
    /// `relay`: the guard of this endpoint's relay role, whose listed members
    /// are RELAY_MEMBER. An open relay role lists nobody
    /// ([`RelayGuard::is_listed`]): `--relay-open` on an endpoint never
    /// admits strangers.
    pub fn new(relay: Option<RelayGuard>) -> Self {
        Self {
            state: Arc::new(Mutex::new(GateState {
                relay,
                ..GateState::default()
            })),
        }
    }

    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Replace the set loaded from files, which were read from `read_at` on.
    /// `unreadable`: the contact book or the block list could not be read,
    /// so `files` holds the configured relays only (fail closed).
    ///
    /// A dial admission whose contact was checked by `read_at` ends here:
    /// these files are at least as new as that check, so a contact blocked,
    /// unpinned or removed since is no longer admitted, and neither are
    /// relays only its card named. One checked later stays until its
    /// deadline: the files may predate a contact verified a moment ago.
    pub fn replace(&self, files: HashMap<PeerId, PeerClass>, unreadable: bool, read_at: Instant) {
        let mut st = self.lock();
        st.files = files;
        st.unreadable = unreadable;
        st.files_read_at = Some(read_at);
        let now = Instant::now();
        st.dialled.retain(|_, d| d.until > now && d.at > read_at);
    }

    /// The caller began checking that `peer` is a verified contact at
    /// `checked_at`, right before dialling it: admit it as `class` (CONTACT,
    /// or CONTACT_HIDDEN for a contact this node hides its IP from or whose
    /// PeerId is not proven) and the relays the dial may use
    /// (CONTACT_RELAY) until `until`, or until files read from `checked_at`
    /// on replace the set ([`Self::replace`]), so a contact verified a moment
    /// ago is never refused on our own dial while the file set reloads.
    ///
    /// The set held now may itself have been read from `checked_at` on (a
    /// reload that ran while the dial waited, after a block): it is the newer
    /// word, so the dial is admitted only if it names `peer` a contact
    /// (then with its relays, until the next reload; hidden if that is all
    /// it names), else it is refused ([`DialCheckStale`]) and the caller
    /// checks again. Either way a block written after the check never leaves
    /// the dial admitted, and a dial never makes a hidden contact a CONTACT
    /// that newer files hide.
    pub fn admit_dial(
        &self,
        peer: PeerId,
        class: PeerClass,
        relays: &[PeerId],
        checked_at: Instant,
        until: Instant,
    ) -> Result<(), DialCheckStale> {
        let mut st = self.lock();
        let now = Instant::now();
        st.dialled.retain(|_, d| d.until > now);
        let files_newer = st
            .files_read_at
            .is_some_and(|read_at| read_at >= checked_at);
        let in_files = st.files.get(&peer).copied().unwrap_or_default();
        if files_newer && !in_files.intersects(ANY_CONTACT) {
            return Err(DialCheckStale);
        }
        // Newer files that name the contact hidden win over the dial's word.
        let hidden_by_files = files_newer && !in_files.intersects(PeerClass::CONTACT);
        let class = if class == PeerClass::CONTACT && !hidden_by_files {
            PeerClass::CONTACT
        } else {
            PeerClass::CONTACT_HIDDEN
        };
        let entries = std::iter::once((peer, class))
            .chain(relays.iter().map(|r| (*r, PeerClass::CONTACT_RELAY)));
        for key in entries {
            let entry = st.dialled.entry(key).or_insert(DialAdmission {
                at: checked_at,
                until,
            });
            entry.at = entry.at.max(checked_at);
            entry.until = entry.until.max(until);
        }
        Ok(())
    }

    /// The relays automatic relay choice (any-network plan C7) holds now,
    /// replacing the ones it held before. Each is an own relay (OWN_RELAY)
    /// on top of what the files say, from before its first dial: its
    /// reservation outbound and its AutoNAT dial-backs inbound are admitted.
    /// A relay dropped here keeps only what the files give it: the caller
    /// then runs [`PeerGate::recheck`] and disconnects the peers it names.
    /// File reloads ([`Self::replace`]) keep this set.
    pub fn set_auto_relays(&self, peers: &[PeerId]) {
        self.lock().auto = peers.iter().copied().collect();
    }

    /// Counts for status (never a PeerId): contacts (hidden ones included)
    /// and relays in the file set, the automatic relays among the relays
    /// (each relay once), and whether the contact book or block list was
    /// unreadable.
    pub fn summary(&self) -> (u32, u32, bool) {
        let st = self.lock();
        let count =
            |class: PeerClass| st.files.values().filter(|c| c.intersects(class)).count() as u32;
        let relay = PeerClass::OWN_RELAY | PeerClass::CONTACT_RELAY;
        let auto_only = st
            .auto
            .iter()
            .filter(|p| !st.files.get(p).is_some_and(|c| c.intersects(relay)))
            .count() as u32;
        (count(ANY_CONTACT), count(relay) + auto_only, st.unreadable)
    }
}

impl Admission for GateHandle {
    fn class_of(&self, peer: &PeerId) -> PeerClass {
        let st = self.lock();
        let mut class = st.files.get(peer).copied().unwrap_or_default();
        let now = Instant::now();
        for dialled in DIAL_CLASSES {
            if st
                .dialled
                .get(&(*peer, dialled))
                .is_some_and(|d| d.until > now)
            {
                class |= dialled;
            }
        }
        if st.relay.as_ref().is_some_and(|g| g.is_listed(peer)) {
            class |= PeerClass::RELAY_MEMBER;
        }
        if st.auto.contains(peer) {
            class |= PeerClass::OWN_RELAY;
        }
        class
    }
}

// ── The gate ─────────────────────────────────────────────────────────────────

/// Why [`PeerGate`] refused a connection. Names no peer (NAT spec §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerNotAdmitted {
    pub inbound: bool,
    pub relayed: bool,
}

impl fmt::Display for PeerNotAdmitted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the peer is not a verified contact or a relay of this node")
    }
}

impl Error for PeerNotAdmitted {}

/// Refusals of a [`PeerGate`]. `refused_relayed` counts circuits in either
/// direction; the other two count direct connections.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GateCounts {
    pub refused_inbound: u64,
    pub refused_relayed: u64,
    pub refused_outbound: u64,
}

impl GateCounts {
    /// Every refused connection.
    pub fn total(&self) -> u64 {
        self.refused_inbound + self.refused_relayed + self.refused_outbound
    }
}

/// Which [`GateCounts`] row a [`PeerGate`] refusal counts in, as its
/// [`RefusalHook`] is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    /// A direct connection a remote peer opened.
    Inbound,
    /// A circuit, in either direction.
    Relayed,
    /// A direct connection this node dialled.
    Outbound,
}

/// Told of a [`PeerGate`] refusal whose remote address names the remote's
/// own IP: that IP and the kind, never a PeerId (Phase 6b design A S5:
/// raven-node notes `SEC_P2P_GATE_REFUSED` against the network source). A
/// circuit's address names its relay, not the refused peer, so a circuit
/// refusal is never passed on.
pub type RefusalHook = Arc<dyn Fn(IpAddr, RefusalKind) + Send + Sync>;

/// Asked, before Noise, whether a direct inbound connection from this IP may
/// go on; `false` refuses it ([`SourceRefused`]). Phase 6b design A R1:
/// raven-node's penalty box for strangers. Never asked about a circuit (its
/// address names the relay) or about a dial of ours.
pub type AdmitHook = Arc<dyn Fn(IpAddr) -> bool + Send + Sync>;

/// Told the source IP of each direct inbound connection [`PeerGate`]
/// admitted as a contact's (CONTACT or CONTACT_HIDDEN), once its PeerId is
/// Noise-proven. Phase 6 review sensing-7: raven-node forgets that source
/// in its penalty box, as its TCP listeners do when a contact
/// authenticates, so a friend behind a stranger's banned address gets
/// through at once. Never told of a circuit (its address names the relay),
/// a dial of ours or a relay's connection.
pub type AuthenticatedHook = Arc<dyn Fn(IpAddr) + Send + Sync>;

/// [`PeerGate`] refused a direct inbound connection because its source
/// failed too often ([`AdmitHook`]). Names no address and no peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceRefused;

impl fmt::Display for SourceRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a source that failed too often was refused")
    }
}

impl Error for SourceRefused {}

/// Refuses, in all four connection hooks, every connection [`admits`] does
/// not allow for the peer's class, and circuits already at the pending stage
/// (see the module doc). Speaks no protocol and never dials.
pub struct PeerGate<A: Admission> {
    admission: A,
    /// Every connection admitted.
    connected: HashMap<ConnectionId, Admitted>,
    counts: GateCounts,
    /// Told of each refusal with an IP ([`Self::set_refusal_hook`]).
    refused: Option<RefusalHook>,
    /// Asked about each direct inbound source ([`Self::set_admit_hook`]).
    admit: Option<AdmitHook>,
    /// Told of each direct inbound contact's source
    /// ([`Self::set_authenticated_hook`]).
    authenticated: Option<AuthenticatedHook>,
}

/// A connection [`PeerGate`] admitted: its peer, the class it was admitted
/// with, and its kind.
#[derive(Clone, Copy, Debug)]
struct Admitted {
    peer: PeerId,
    class: PeerClass,
    inbound: bool,
    relayed: bool,
}

impl Admitted {
    /// Does the class `now` still give this connection what its class gave
    /// it: admission ([`admits`]), and every protocol scope it was in
    /// ([`SCOPES`])? Losing any other bit changes nothing on it: our own
    /// relay that a contact's `via=` stops naming keeps its reservation and
    /// every circuit through it.
    fn holds(&self, now: PeerClass) -> bool {
        admits(now, self.inbound, self.relayed)
            && SCOPES
                .iter()
                .all(|scope| !self.class.intersects(*scope) || now.intersects(*scope))
    }
}

impl<A: Admission> PeerGate<A> {
    pub fn new(admission: A) -> Self {
        Self {
            admission,
            connected: HashMap::new(),
            counts: GateCounts::default(),
            refused: None,
            admit: None,
            authenticated: None,
        }
    }

    pub fn counts(&self) -> GateCounts {
        self.counts
    }

    /// Tell `hook` of every later refusal with an IP ([`RefusalHook`]);
    /// `None` stops it. The counts and the refusals themselves stay as they
    /// are.
    pub fn set_refusal_hook(&mut self, hook: Option<RefusalHook>) {
        self.refused = hook;
    }

    /// Ask `hook` about the source IP of every later direct inbound
    /// connection, before Noise ([`AdmitHook`]); `None` stops asking. Its
    /// refusals are not [`GateCounts`] (no class was looked at) and are not
    /// passed to the [`RefusalHook`].
    pub fn set_admit_hook(&mut self, hook: Option<AdmitHook>) {
        self.admit = hook;
    }

    /// Tell `hook` the source IP of every later direct inbound connection
    /// admitted as a contact's ([`AuthenticatedHook`]); `None` stops it.
    pub fn set_authenticated_hook(&mut self, hook: Option<AuthenticatedHook>) {
        self.authenticated = hook;
    }

    /// After a reload, and now and then (a dial admission ends at its
    /// deadline with no reload): the peers with a connection whose admission
    /// no longer holds ([`Admitted::holds`]). The caller disconnects them (as
    /// it does with [`RelayGuard::set_policy`]); a peer that only gained a
    /// class, or lost one that changes nothing on its connections, stays.
    pub fn recheck(&self) -> Vec<PeerId> {
        let mut peers: Vec<PeerId> = self
            .connected
            .values()
            .filter(|c| !c.holds(self.admission.class_of(&c.peer)))
            .map(|c| c.peer)
            .collect();
        peers.sort();
        peers.dedup();
        peers
    }

    /// Admit `peer` on `connection` ([`Self::check`]) and remember it.
    fn establish(
        &mut self,
        connection: ConnectionId,
        peer: PeerId,
        inbound: bool,
        relayed: bool,
        remote: &Multiaddr,
    ) -> Result<dummy::ConnectionHandler, ConnectionDenied> {
        let class = self.check(&peer, inbound, relayed, Some(remote))?;
        // A contact's own direct connection: its source is no stranger's.
        if let (Some(hook), true) = (
            &self.authenticated,
            inbound && !relayed && class.intersects(ANY_CONTACT),
        ) {
            if let Some(ip) = addr_ip(remote) {
                hook(ip);
            }
        }
        self.connected.insert(
            connection,
            Admitted {
                peer,
                class,
                inbound,
                relayed,
            },
        );
        Ok(dummy::ConnectionHandler)
    }

    /// Admit `peer` or refuse it, counting the refusal and telling the
    /// hook (`remote`: the address the connection came from or went to).
    fn check(
        &mut self,
        peer: &PeerId,
        inbound: bool,
        relayed: bool,
        remote: Option<&Multiaddr>,
    ) -> Result<PeerClass, ConnectionDenied> {
        let class = self.admission.class_of(peer);
        if admits(class, inbound, relayed) {
            return Ok(class);
        }
        let kind = match (inbound, relayed) {
            (_, true) => {
                self.counts.refused_relayed += 1;
                RefusalKind::Relayed
            }
            (true, false) => {
                self.counts.refused_inbound += 1;
                RefusalKind::Inbound
            }
            (false, false) => {
                self.counts.refused_outbound += 1;
                RefusalKind::Outbound
            }
        };
        // A circuit's address names its relay, never the refused peer.
        if let (Some(hook), false) = (&self.refused, relayed) {
            if let Some(ip) = remote.and_then(addr_ip) {
                hook(ip, kind);
            }
        }
        Err(ConnectionDenied::new(PeerNotAdmitted { inbound, relayed }))
    }
}

impl<A: Admission> NetworkBehaviour for PeerGate<A> {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        // A circuit names its source before Noise; deny-only (module doc).
        if is_circuit(local_addr) {
            if let Some(Protocol::P2p(source)) = remote_addr.iter().last() {
                self.check(&source, true, true, Some(remote_addr))?;
            }
        } else if let (Some(admit), Some(ip)) = (&self.admit, addr_ip(remote_addr)) {
            // A direct connection names its source's own IP: a source that
            // failed too often is refused before Noise (Phase 6b R1).
            if !admit(ip) {
                return Err(ConnectionDenied::new(SourceRefused));
            }
        }
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.establish(
            connection_id,
            peer,
            true,
            is_circuit(local_addr),
            remote_addr,
        )
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        _effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if let Some(peer) = maybe_peer {
            let relayed = !addresses.is_empty() && addresses.iter().all(is_circuit);
            // Our own dial, refused before it leaves: no remote to name.
            self.check(&peer, false, relayed, None)?;
        }
        Ok(Vec::new())
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.establish(connection_id, peer, false, is_circuit(addr), addr)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionClosed(c) => {
                self.connected.remove(&c.connection_id);
            }
            // A later field denied a connection this gate admitted.
            FromSwarm::ListenFailure(f) => {
                self.connected.remove(&f.connection_id);
            }
            FromSwarm::DialFailure(f) => {
                self.connected.remove(&f.connection_id);
            }
            _ => {}
        }
    }

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

// ── Address scope ────────────────────────────────────────────────────────────

/// Which addresses hole punching may offer and dial, and AutoNAT may test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrRule {
    /// Globally routable unicast only ([`is_global_ip`]): the only rule
    /// outside the debug lab.
    GlobalOnly,
    /// Debug lab only (`raven_core::p2p_local_candidates_enabled`): any IP
    /// that is not unspecified or multicast, loopback and private included,
    /// for one-machine harnesses.
    LabAnyIp,
}

impl AddrRule {
    /// May `address` be offered or dialled? It must start with `/ip4` or
    /// `/ip6` (no `/dns*` name, no `/memory`), go on with the plain
    /// transport (`/tcp/P` or `/udp/P/quic-v1`) and end there or with one
    /// `/p2p`: never a circuit, and never a WSS form (`/tls`, `/sni`, `/ws`)
    /// or a `/certhash`, which a contact could otherwise have dialled
    /// through the HTTPS proxy with a name of its choosing (review A-2;
    /// endpoints never listen on WSS, RWS1 §2.3).
    pub fn allows(self, address: &Multiaddr) -> bool {
        let mut parts = address.iter();
        let ip = match parts.next() {
            Some(Protocol::Ip4(ip)) => IpAddr::V4(ip),
            Some(Protocol::Ip6(ip)) => IpAddr::V6(ip),
            _ => return false,
        };
        let plain = match parts.next() {
            Some(Protocol::Tcp(_)) => true,
            Some(Protocol::Udp(_)) => matches!(parts.next(), Some(Protocol::QuicV1)),
            _ => false,
        };
        if !plain
            || !matches!(
                (parts.next(), parts.next()),
                (None, _) | (Some(Protocol::P2p(_)), None)
            )
        {
            return false;
        }
        match self {
            Self::GlobalOnly => is_global_ip(ip),
            Self::LabAnyIp => {
                let ip = ip.to_canonical();
                !ip.is_unspecified() && !ip.is_multicast()
            }
        }
    }

    /// A dial target for `peer`: allowed, and a trailing `/p2p` names that
    /// peer itself.
    pub fn target_ok(self, address: &Multiaddr, peer: Option<&PeerId>) -> bool {
        self.allows(address)
            && match address.iter().last() {
                Some(Protocol::P2p(p)) => peer == Some(&p),
                _ => true,
            }
    }
}

// ── Per-protocol scope ───────────────────────────────────────────────────────

/// Runs `inner` only on connections of peers whose class is in `scope`; for
/// every other connection the handler is a dummy, and `inner` never hears of
/// it (no `ConnectionEstablished`, `ConnectionClosed` or `AddressChange`;
/// the established and remaining counts it is shown are of its own
/// connections). A `NotifyHandler::Any` from `inner` is pinned to one of its
/// connections, and a notification for a connection it has none on is
/// dropped (see the module doc). `candidates` filters
/// `NewExternalAddrCandidate`, and [`Self::with_restricted`] drops them all
/// while the restricted-network flag is set.
pub struct Scoped<B, A: Admission = GateHandle> {
    inner: B,
    admission: A,
    scope: PeerClass,
    candidates: Option<AddrRule>,
    /// The restricted-network flag; `None`: never restricted.
    restricted: Option<Arc<AtomicBool>>,
    /// Connections `inner` built a handler for, and their peer.
    connections: HashMap<ConnectionId, PeerId>,
    built: u64,
}

impl<B, A: Admission> Scoped<B, A> {
    pub fn new(inner: B, admission: A, scope: PeerClass, candidates: Option<AddrRule>) -> Self {
        Self {
            inner,
            admission,
            scope,
            candidates,
            restricted: None,
            connections: HashMap::new(),
            built: 0,
        }
    }

    /// Drop every `NewExternalAddrCandidate` while `flag` is set: the host's
    /// restricted-network flag ([`crate::host::EndpointConfig::restricted`],
    /// RWS1 §9). For an AutoNAT client: through a proxy, Identify's
    /// candidates carry the proxy's egress IP, so the relay is asked to test
    /// none of them.
    pub fn with_restricted(mut self, flag: Arc<AtomicBool>) -> Self {
        self.restricted = Some(flag);
        self
    }

    /// Is the restricted-network flag set (candidates are dropped)?
    pub fn restricted(&self) -> bool {
        self.restricted
            .as_ref()
            .is_some_and(|r| r.load(Ordering::SeqCst))
    }

    pub fn inner(&self) -> &B {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut B {
        &mut self.inner
    }

    /// Handlers `inner` has built (tests, diagnostics).
    pub fn handlers_built(&self) -> u64 {
        self.built
    }

    fn in_scope(&self, peer: &PeerId) -> bool {
        self.admission.class_of(peer).intersects(self.scope)
    }

    /// `peer`'s connections with a handler of `inner`, except `connection`.
    fn others(&self, peer: PeerId, connection: ConnectionId) -> usize {
        self.connections
            .iter()
            .filter(|(c, p)| **p == peer && **c != connection)
            .count()
    }

    fn record(&mut self, connection: ConnectionId, peer: PeerId) {
        self.connections.insert(connection, peer);
        self.built += 1;
    }
}

impl<B: NetworkBehaviour, A: Admission> NetworkBehaviour for Scoped<B, A> {
    type ConnectionHandler = Either<THandler<B>, dummy::ConnectionHandler>;
    type ToSwarm = B::ToSwarm;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if !self.in_scope(&peer) {
            return Ok(Either::Right(dummy::ConnectionHandler));
        }
        let handler = self.inner.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )?;
        self.record(connection_id, peer);
        Ok(Either::Left(handler))
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        self.inner.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if !self.in_scope(&peer) {
            return Ok(Either::Right(dummy::ConnectionHandler));
        }
        let handler = self.inner.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )?;
        self.record(connection_id, peer);
        Ok(Either::Left(handler))
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(c) => {
                if self.connections.contains_key(&c.connection_id) {
                    let other_established = self.others(c.peer_id, c.connection_id);
                    self.inner.on_swarm_event(FromSwarm::ConnectionEstablished(
                        ConnectionEstablished {
                            other_established,
                            ..c
                        },
                    ));
                }
            }
            FromSwarm::ConnectionClosed(c) => {
                if self.connections.remove(&c.connection_id).is_some() {
                    let remaining_established = self.others(c.peer_id, c.connection_id);
                    self.inner
                        .on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                            remaining_established,
                            ..c
                        }));
                }
            }
            FromSwarm::AddressChange(c) => {
                if self.connections.contains_key(&c.connection_id) {
                    self.inner.on_swarm_event(event);
                }
            }
            // A later field denied a connection `inner` may have built a
            // handler for; `inner`'s own dials fail here too.
            FromSwarm::ListenFailure(f) => {
                self.connections.remove(&f.connection_id);
                self.inner.on_swarm_event(event);
            }
            FromSwarm::DialFailure(f) => {
                self.connections.remove(&f.connection_id);
                self.inner.on_swarm_event(event);
            }
            FromSwarm::NewExternalAddrCandidate(c) => {
                if !self.restricted() && self.candidates.is_none_or(|rule| rule.allows(c.addr)) {
                    self.inner.on_swarm_event(event);
                }
            }
            _ => self.inner.on_swarm_event(event),
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            Either::Left(event) => {
                self.inner
                    .on_connection_handler_event(peer, connection_id, event)
            }
            Either::Right(never) => libp2p::core::util::unreachable(never),
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        loop {
            let event = match ready!(self.inner.poll(cx)) {
                ToSwarm::NotifyHandler {
                    peer_id,
                    handler,
                    event,
                } => {
                    let target = match handler {
                        NotifyHandler::One(c) => self.connections.contains_key(&c).then_some(c),
                        NotifyHandler::Any => self
                            .connections
                            .iter()
                            .filter(|(_, p)| **p == peer_id)
                            .map(|(c, _)| *c)
                            .min(),
                    };
                    // `inner` has no handler there: a dummy would panic on it.
                    let Some(connection) = target else {
                        continue;
                    };
                    ToSwarm::NotifyHandler {
                        peer_id,
                        handler: NotifyHandler::One(connection),
                        event: Either::Left(event),
                    }
                }
                other => other.map_in(Either::Left),
            };
            return Poll::Ready(event);
        }
    }
}

// ── Hole punching ────────────────────────────────────────────────────────────

/// Why [`HolePunch`] refused one of DCUtR's own dials. Names no address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HolePunchTargetRefused;

impl fmt::Display for HolePunchTargetRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a hole-punch target is not an address this node dials")
    }
}

impl Error for HolePunchTargetRefused {}

/// DCUtR for verified contacts (CONTACT) under Raven's address rule (see
/// the module doc):
/// - only a contact's connections get a DCUtR handler (a hidden contact,
///   CONTACT_HIDDEN, gets none); DCUtR never hears of the others, as with
///   [`Scoped`] (dcutr 0.15 `expect`s a
///   `ConnectionClosed` only for direct connections it recorded,
///   behaviour.rs:153-161);
/// - the candidates it offers are the [`CandidateBook`]'s, which keeps only
///   what `rule` allows. A relayed connection's handler is built by a
///   throwaway DCUtR fed exactly the book's list ([`Self::scratch`]); the
///   swarm's `NewExternalAddrCandidate`s go to the book only, never to
///   `inner`, so libp2p's own list is never offered;
/// - while the restricted-network flag is set ([`Self::with_restricted`]),
///   the book offers nothing, so a relayed handler built then has no
///   candidates and its hole punch fails before any dial (dcutr 0.15
///   refuses an empty CONNECT both ways, protocol/inbound.rs:45-47,
///   outbound.rs:62-64);
/// - a dial DCUtR asks for is refused whole unless every address passes
///   `rule` and a trailing `/p2p` names the peer dialled
///   ([`AddrRule::target_ok`]). DCUtR then tries again at most 3 times
///   (MAX_NUMBER_OF_UPGRADE_ATTEMPTS) and reports a failure;
/// - a hopeless hole punch is never started (Phase 4, [`PunchPolicy`]: both
///   NAT mappings vary, or two attempts failed on this network): the
///   contact's relayed connection gets a dummy handler, so this side sends
///   no CONNECT, and a CONNECT the contact opens finds no DCUtR protocol
///   here and fails there once (dcutr 0.15 behaviour.rs:283-293: no retry).
///   The connection stays tracked like any contact's, and is counted
///   ([`PunchPolicy::skipped`]). A fresh policy comes with every endpoint
///   generation (a network change forgets failures); disabled (the
///   NAT_CLASS gate closed: [`Self::with_punch_policy`] `false`, the
///   default) it never skips, which is Phase 1's behaviour.
///
/// DCUtR notifies only the relayed connection a hole punch belongs to, by
/// id (`NotifyHandler::One`, behaviour.rs:129-133), and only a connection it
/// built a handler for has one, so its notifications pass unchanged.
pub struct HolePunch<A: Admission = GateHandle> {
    inner: dcutr::Behaviour,
    local: PeerId,
    book: CandidateBook,
    admission: A,
    rule: AddrRule,
    /// Connections DCUtR built a handler for, and their peer.
    contacts: HashMap<ConnectionId, PeerId>,
    /// DCUtR's own dials in flight.
    dials: HashSet<ConnectionId>,
    /// When DCUtR last dialled each peer ([`Self::last_attempt`]), while
    /// that peer has a connection.
    attempts: HashMap<PeerId, Instant>,
    built: u64,
    relayed_built: u64,
    refused_targets: u64,
    /// The hole-punch skip rule (Phase 4); disabled unless
    /// [`Self::with_punch_policy`] enables it.
    pub policy: PunchPolicy,
    /// Why the last hole punch was skipped.
    last_skip: Option<SkipWhy>,
}

/// Peers whose last DCUtR dial [`HolePunch`] remembers, at most.
const MAX_ATTEMPTS_REMEMBERED: usize = 256;

impl<A: Admission> HolePunch<A> {
    pub fn new(local: PeerId, admission: A, rule: AddrRule) -> Self {
        Self {
            inner: dcutr::Behaviour::new(local),
            local,
            book: CandidateBook::new(rule),
            admission,
            rule,
            contacts: HashMap::new(),
            dials: HashSet::new(),
            attempts: HashMap::new(),
            built: 0,
            relayed_built: 0,
            refused_targets: 0,
            policy: PunchPolicy::new(false),
            last_skip: None,
        }
    }

    /// A fresh hole-punch policy, `enabled` while the NAT_CLASS gate is live
    /// (`raven_core::nat_class_live_enabled`): only then may it skip.
    pub fn with_punch_policy(self, enabled: bool) -> Self {
        Self {
            policy: PunchPolicy::new(enabled),
            ..self
        }
    }

    /// For the host: this host's NAT summary, contacts' summaries, punch
    /// outcomes.
    pub fn policy_mut(&mut self) -> &mut PunchPolicy {
        &mut self.policy
    }

    /// Why the last hole punch was skipped (`None`: none was).
    pub fn last_skip(&self) -> Option<SkipWhy> {
        self.last_skip
    }

    /// Hole punches skipped so far ([`PunchPolicy::skipped`]).
    pub fn skipped(&self) -> u64 {
        self.policy.skipped
    }

    /// The hole punch with `peer` on a new relayed connection is hopeless:
    /// counted, and the caller builds a dummy handler instead of DCUtR's
    /// (the connection is still tracked in `contacts`).
    fn skip_punch(&mut self, peer: &PeerId) -> bool {
        match self.policy.hopeless(peer, Instant::now()) {
            Some(why) => {
                self.policy.skipped += 1;
                self.last_skip = Some(why);
                true
            }
            None => false,
        }
    }

    /// The book follows `flag`, the host's restricted-network flag
    /// ([`CandidateBook::with_restricted`]).
    pub fn with_restricted(self, flag: Arc<AtomicBool>) -> Self {
        Self {
            book: self.book.with_restricted(flag),
            ..self
        }
    }

    /// The candidates this host offers.
    pub fn book(&self) -> &CandidateBook {
        &self.book
    }

    /// For the host: raw observations and the preferred IPv6 source.
    pub fn book_mut(&mut self) -> &mut CandidateBook {
        &mut self.book
    }

    /// Handlers DCUtR has built (tests, diagnostics).
    pub fn handlers_built(&self) -> u64 {
        self.built
    }

    /// Relayed-connection handlers built from the book so far (a stranger's
    /// circuit, refused by the peer gate, never adds one).
    pub fn relayed_handlers_built(&self) -> u64 {
        self.relayed_built
    }

    /// DCUtR dials refused for an address `rule` does not allow (counts
    /// only).
    pub fn refused_targets(&self) -> u64 {
        self.refused_targets
    }

    /// When DCUtR last dialled `peer` for a hole punch (allowed or refused),
    /// while `peer` has a connection. Both sides of a hole punch dial at the
    /// same moment, each when its side of the SYNC exchange completes (dcutr
    /// 0.15 behaviour.rs:303-320 on the side that received the relayed
    /// connection, :271-283 on the side that dialled it), for every attempt:
    /// a direct connection from `peer` that arrives right after it is the
    /// peer's half of the punch. DCUtR's own `Event` reports only this
    /// side's dial when it connects (:233-248), and no success on a side
    /// whose own dial failed while the peer's got through.
    pub fn last_attempt(&self, peer: &PeerId) -> Option<Instant> {
        self.attempts.get(peer).copied()
    }

    fn note_attempt(&mut self, peer: PeerId) {
        if self.attempts.len() >= MAX_ATTEMPTS_REMEMBERED && !self.attempts.contains_key(&peer) {
            self.attempts.clear();
        }
        self.attempts.insert(peer, Instant::now());
    }

    fn is_contact(&self, peer: &PeerId) -> bool {
        self.admission.class_of(peer).intersects(PeerClass::CONTACT)
    }

    /// A throwaway DCUtR that knows exactly the book's candidates, to build
    /// one relayed connection's handler. A relayed handler holds no
    /// behaviour state: its events are keyed by the relayed ConnectionId
    /// (dcutr 0.15 behaviour.rs:258-268) and handled by `inner`, and the
    /// handler snapshots the candidates when it is built (:185-186,
    /// :216-222), in LRU insertion order (:381-383), so the book's order is
    /// the order the CONNECT lists them.
    fn scratch(&mut self) -> dcutr::Behaviour {
        self.relayed_built += 1;
        let mut scratch = dcutr::Behaviour::new(self.local);
        for addr in self.book.candidates(Instant::now()) {
            scratch.on_swarm_event(FromSwarm::NewExternalAddrCandidate(
                NewExternalAddrCandidate { addr: &addr },
            ));
        }
        scratch
    }
}

impl<A: Admission> NetworkBehaviour for HolePunch<A> {
    type ConnectionHandler = Either<THandler<dcutr::Behaviour>, dummy::ConnectionHandler>;
    type ToSwarm = dcutr::Event;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if !self.is_contact(&peer) {
            return Ok(Either::Right(dummy::ConnectionHandler));
        }
        if is_circuit(local_addr) && self.skip_punch(&peer) {
            self.contacts.insert(connection_id, peer);
            return Ok(Either::Right(dummy::ConnectionHandler));
        }
        let handler = if is_circuit(local_addr) {
            self.scratch().handle_established_inbound_connection(
                connection_id,
                peer,
                local_addr,
                remote_addr,
            )?
        } else {
            self.inner.handle_established_inbound_connection(
                connection_id,
                peer,
                local_addr,
                remote_addr,
            )?
        };
        self.contacts.insert(connection_id, peer);
        self.built += 1;
        Ok(Either::Left(handler))
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        // Only DCUtR's own dials are checked; the swarm asks this hook
        // synchronously for the dial `poll` just recorded (libp2p-swarm 0.48
        // lib.rs:1096-1100 -> 428-470).
        if self.dials.remove(&connection_id) {
            if let Some(peer) = maybe_peer {
                self.note_attempt(peer);
            }
            if addresses.is_empty()
                || !addresses
                    .iter()
                    .all(|a| self.rule.target_ok(a, maybe_peer.as_ref()))
            {
                self.refused_targets += 1;
                return Err(ConnectionDenied::new(HolePunchTargetRefused));
            }
        }
        self.inner.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if !self.is_contact(&peer) {
            return Ok(Either::Right(dummy::ConnectionHandler));
        }
        if is_circuit(addr) && self.skip_punch(&peer) {
            self.contacts.insert(connection_id, peer);
            return Ok(Either::Right(dummy::ConnectionHandler));
        }
        let handler = if is_circuit(addr) {
            self.scratch().handle_established_outbound_connection(
                connection_id,
                peer,
                addr,
                role_override,
                port_use,
            )?
        } else {
            self.inner.handle_established_outbound_connection(
                connection_id,
                peer,
                addr,
                role_override,
                port_use,
            )?
        };
        self.contacts.insert(connection_id, peer);
        self.built += 1;
        Ok(Either::Left(handler))
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        self.book.on_swarm_event(&event);
        match event {
            // The book's, never `inner`'s: scratch handlers offer the book.
            FromSwarm::NewExternalAddrCandidate(_) => {}
            FromSwarm::ConnectionEstablished(c) => {
                if self.contacts.contains_key(&c.connection_id) {
                    self.inner.on_swarm_event(event);
                }
            }
            FromSwarm::ConnectionClosed(c) => {
                if c.remaining_established == 0 {
                    self.attempts.remove(&c.peer_id);
                }
                if self.contacts.remove(&c.connection_id).is_some() {
                    self.inner.on_swarm_event(event);
                }
            }
            FromSwarm::AddressChange(c) => {
                if self.contacts.contains_key(&c.connection_id) {
                    self.inner.on_swarm_event(event);
                }
            }
            // A later field denied a connection DCUtR may have built a
            // handler for (as in `Scoped`); DCUtR's own dials fail here too,
            // which is how it counts its attempts.
            FromSwarm::ListenFailure(f) => {
                self.contacts.remove(&f.connection_id);
                self.inner.on_swarm_event(event);
            }
            FromSwarm::DialFailure(f) => {
                self.dials.remove(&f.connection_id);
                self.contacts.remove(&f.connection_id);
                self.inner.on_swarm_event(event);
            }
            _ => self.inner.on_swarm_event(event),
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            Either::Left(event) => {
                self.inner
                    .on_connection_handler_event(peer, connection_id, event)
            }
            Either::Right(never) => libp2p::core::util::unreachable(never),
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        let event = ready!(self.inner.poll(cx));
        if let ToSwarm::Dial { opts } = &event {
            self.dials.insert(opts.connection_id());
        }
        Poll::Ready(event.map_in(Either::Left))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashSet, VecDeque};
    use std::time::Duration;

    use libp2p::core::upgrade::DeniedUpgrade;
    use libp2p::core::ConnectedPoint;
    use libp2p::identity::Keypair;
    use libp2p::swarm::behaviour::{AddressChange, NewExternalAddrCandidate};
    use libp2p::swarm::handler::{ConnectionEvent, ConnectionHandlerEvent, SubstreamProtocol};
    use libp2p::swarm::{ConnectionHandler, DialError, DialFailure, ListenError, ListenFailure};

    use super::*;
    use crate::host::{AllowPolicy, RelayLimits};

    fn peer(seed: u8) -> PeerId {
        Keypair::ed25519_from_bytes([seed; 32])
            .unwrap()
            .public()
            .to_peer_id()
    }

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    fn id(n: usize) -> ConnectionId {
        ConnectionId::new_unchecked(n)
    }

    fn direct() -> Multiaddr {
        addr("/ip4/127.0.0.1/tcp/7423")
    }

    /// This host's address on a circuit through `relay`.
    fn circuit(relay: PeerId) -> Multiaddr {
        addr("/ip4/127.0.0.1/tcp/7424")
            .with(Protocol::P2p(relay))
            .with(Protocol::P2pCircuit)
    }

    /// A gate whose files were read a moment ago, before anything the test
    /// does next (a dial's check included).
    fn gate_with(admit: &[(PeerId, PeerClass)]) -> GateHandle {
        let gate = GateHandle::default();
        gate.replace(admit.iter().copied().collect(), false, read_earlier());
        gate
    }

    /// When a load still in flight began reading the files: before anything
    /// the test does next.
    fn read_earlier() -> Instant {
        Instant::now() - Duration::from_secs(1)
    }

    fn listener(local: &Multiaddr, remote: &Multiaddr) -> ConnectedPoint {
        ConnectedPoint::Listener {
            local_addr: local.clone(),
            send_back_addr: remote.clone(),
        }
    }

    fn closed<B: NetworkBehaviour>(b: &mut B, connection: ConnectionId, peer: PeerId) {
        let endpoint = listener(&direct(), &direct());
        b.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: peer,
            connection_id: connection,
            endpoint: &endpoint,
            cause: None,
            remaining_established: 0,
        }));
    }

    /// The denial of a hook that must refuse (handlers are not `Debug`).
    fn refused<T>(result: Result<T, ConnectionDenied>) -> ConnectionDenied {
        match result {
            Ok(_) => panic!("admitted"),
            Err(denied) => denied,
        }
    }

    /// The error text of a denial, its cause included.
    fn texts(denied: &ConnectionDenied) -> String {
        format!("{denied} {denied:?} {}", denied.source().unwrap())
    }

    #[test]
    fn admits_follows_the_class_table() {
        let bits = [
            PeerClass::CONTACT,
            PeerClass::OWN_RELAY,
            PeerClass::CONTACT_RELAY,
            PeerClass::RELAY_MEMBER,
            PeerClass::CONTACT_HIDDEN,
        ];
        let mut seen = 0;
        for mask in 0u8..32 {
            let class = bits
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .fold(PeerClass::NONE, |c, (_, b)| c | *b);
            let has = |b: PeerClass| class.intersects(b);
            let contact = has(PeerClass::CONTACT) || has(PeerClass::CONTACT_HIDDEN);
            for inbound in [false, true] {
                for relayed in [false, true] {
                    let expected = if relayed {
                        contact
                    } else if inbound {
                        contact || has(PeerClass::OWN_RELAY) || has(PeerClass::RELAY_MEMBER)
                    } else {
                        mask != 0
                    };
                    assert_eq!(
                        admits(class, inbound, relayed),
                        expected,
                        "{class:?} inbound={inbound} relayed={relayed}"
                    );
                    seen += 1;
                }
            }
        }
        assert_eq!(seen, 128);
        // A hidden contact: links both ways, direct or relayed.
        for (inbound, relayed) in [(false, false), (false, true), (true, false), (true, true)] {
            assert!(
                admits(PeerClass::CONTACT_HIDDEN, inbound, relayed),
                "inbound={inbound} relayed={relayed}"
            );
        }
        // ...but neither hole punching (CONTACT) nor Identify.
        assert!(!PeerClass::CONTACT_HIDDEN.intersects(PeerClass::CONTACT));
        assert!(!PeerClass::CONTACT_HIDDEN.intersects(IDENTIFY_SCOPE));
        // The rows the design names.
        assert!(
            !admits(PeerClass::CONTACT_RELAY, true, false),
            "outbound only"
        );
        assert!(admits(PeerClass::CONTACT_RELAY, false, false));
        assert!(!admits(PeerClass::CONTACT_RELAY, false, true));
        assert!(
            admits(PeerClass::OWN_RELAY, true, false),
            "AutoNAT dial-back"
        );
        assert!(!admits(PeerClass::OWN_RELAY, true, true));
        assert!(!admits(PeerClass::RELAY_MEMBER, false, true));
        assert!(admits(PeerClass::CONTACT, true, true));
        assert!(!admits(PeerClass::NONE, false, false));

        assert!(PeerClass::CONTACT.lost(PeerClass::OWN_RELAY));
        assert!(!PeerClass::CONTACT.lost(PeerClass::CONTACT | PeerClass::OWN_RELAY));
        assert!(!PeerClass::NONE.lost(PeerClass::NONE));
    }

    #[test]
    fn the_gate_refuses_strangers_in_every_hook_and_names_no_peer() {
        let (c, r, x, s) = (peer(1), peer(2), peer(3), peer(4));
        let mut gate = PeerGate::new(gate_with(&[
            (c, PeerClass::CONTACT),
            (r, PeerClass::OWN_RELAY),
            (x, PeerClass::CONTACT_RELAY),
        ]));
        let via_r = circuit(r);
        let from = |p: PeerId| Multiaddr::empty().with(Protocol::P2p(p));

        // Pending inbound: a circuit names its source; a direct connection
        // has no PeerId yet.
        let denied = refused(gate.handle_pending_inbound_connection(id(1), &via_r, &from(s)));
        assert_eq!(
            denied.downcast_ref::<PeerNotAdmitted>(),
            Some(&PeerNotAdmitted {
                inbound: true,
                relayed: true
            })
        );
        let text = texts(&denied);
        assert!(!text.contains("12D3KooW"), "{text}");
        assert!(text.contains("not a verified contact"), "{text}");
        gate.handle_pending_inbound_connection(id(2), &via_r, &from(c))
            .unwrap();
        gate.handle_pending_inbound_connection(id(3), &direct(), &addr("/ip4/8.8.8.8/tcp/1"))
            .unwrap();
        assert_eq!(gate.counts().refused_relayed, 1);

        // Established inbound: a stranger, a contact's relay and an own relay
        // over a circuit are refused; an own relay direct and a contact over
        // a circuit are admitted.
        let remote = direct();
        for (n, p, local) in [(4, s, direct()), (5, x, direct()), (6, r, via_r.clone())] {
            let denied =
                refused(gate.handle_established_inbound_connection(id(n), p, &local, &remote));
            assert!(denied.downcast_ref::<PeerNotAdmitted>().is_some());
            assert!(!texts(&denied).contains("12D3KooW"));
        }
        gate.handle_established_inbound_connection(id(7), r, &direct(), &remote)
            .unwrap();
        gate.handle_established_inbound_connection(id(8), c, &via_r, &from(c))
            .unwrap();
        assert_eq!(
            gate.counts(),
            GateCounts {
                refused_inbound: 2,
                refused_relayed: 2,
                refused_outbound: 0
            }
        );

        // Pending outbound: a stranger is refused; a contact's relay is
        // dialled directly but never over a circuit; an unknown peer waits
        // for the established check.
        let target = |p: PeerId| vec![circuit(r).with(Protocol::P2p(p))];
        assert!(gate
            .handle_pending_outbound_connection(id(9), Some(s), &[direct()], Endpoint::Dialer)
            .is_err());
        gate.handle_pending_outbound_connection(id(10), Some(x), &[direct()], Endpoint::Dialer)
            .unwrap();
        assert!(gate
            .handle_pending_outbound_connection(id(11), Some(x), &target(x), Endpoint::Dialer)
            .is_err());
        gate.handle_pending_outbound_connection(id(12), Some(c), &target(c), Endpoint::Dialer)
            .unwrap();
        gate.handle_pending_outbound_connection(id(13), None, &[direct()], Endpoint::Dialer)
            .unwrap();

        // Established outbound: the same rules.
        let established = |gate: &mut PeerGate<GateHandle>, n, p, a: &Multiaddr| {
            gate.handle_established_outbound_connection(id(n), p, a, Endpoint::Dialer, PortUse::New)
        };
        let denied = refused(established(&mut gate, 14, s, &direct()));
        assert!(!texts(&denied).contains("12D3KooW"));
        established(&mut gate, 15, x, &direct()).unwrap();
        assert!(established(&mut gate, 16, x, &target(x)[0]).is_err());
        established(&mut gate, 17, c, &target(c)[0]).unwrap();
        established(&mut gate, 18, r, &direct()).unwrap();

        assert_eq!(
            gate.counts(),
            GateCounts {
                refused_inbound: 2,
                refused_relayed: 4,
                refused_outbound: 2
            }
        );
        assert_eq!(
            PeerNotAdmitted {
                inbound: false,
                relayed: false
            }
            .to_string(),
            "the peer is not a verified contact or a relay of this node"
        );
    }

    /// Phase 6b (P6.24): the refusal hook hears of each refusal once, with
    /// the remote's IP and the kind, never a PeerId; a circuit (whose
    /// address names the relay) and our own refused dial are not passed on,
    /// an admitted peer never is, and the counts are as without a hook.
    #[test]
    fn the_refusal_hook_hears_each_refusal_once_by_ip_never_a_peer() {
        let (c, r, x, s) = (peer(1), peer(2), peer(3), peer(4));
        let mut gate = PeerGate::new(gate_with(&[
            (c, PeerClass::CONTACT),
            (r, PeerClass::OWN_RELAY),
            (x, PeerClass::CONTACT_RELAY),
        ]));
        let heard: Arc<Mutex<Vec<(IpAddr, RefusalKind)>>> = Arc::default();
        let sink = Arc::clone(&heard);
        gate.set_refusal_hook(Some(Arc::new(move |ip, kind| {
            sink.lock().unwrap().push((ip, kind));
        })));
        let from = |p: PeerId| Multiaddr::empty().with(Protocol::P2p(p));
        let v4 = addr("/ip4/192.0.2.7/tcp/4001");
        let v6 = addr("/ip6/2001:db8::5/udp/4001/quic-v1");

        // A stranger inbound, twice from one address: two refusals, two calls.
        for n in [1, 2] {
            assert!(gate
                .handle_established_inbound_connection(id(n), s, &direct(), &v4)
                .is_err());
        }
        // An admitted contact: nothing.
        gate.handle_established_inbound_connection(id(3), c, &direct(), &v6)
            .unwrap();
        // A circuit names the relay (and a pending one only the source's
        // PeerId): counted, not passed on.
        assert!(gate
            .handle_pending_inbound_connection(id(4), &circuit(r), &from(s))
            .is_err());
        assert!(gate
            .handle_established_inbound_connection(id(5), s, &circuit(r), &from(s))
            .is_err());
        let to_x = circuit(r).with(Protocol::P2p(x));
        assert!(gate
            .handle_established_outbound_connection(id(6), x, &to_x, Endpoint::Dialer, PortUse::New)
            .is_err());
        // Our own dial refused before it leaves: no remote to name.
        assert!(gate
            .handle_pending_outbound_connection(
                id(7),
                Some(s),
                std::slice::from_ref(&v6),
                Endpoint::Dialer
            )
            .is_err());
        // A dial that reached a stranger at a direct address.
        assert!(gate
            .handle_established_outbound_connection(id(8), s, &v6, Endpoint::Dialer, PortUse::New)
            .is_err());

        let v4_ip: IpAddr = "192.0.2.7".parse().unwrap();
        let v6_ip: IpAddr = "2001:db8::5".parse().unwrap();
        assert_eq!(
            *heard.lock().unwrap(),
            [
                (v4_ip, RefusalKind::Inbound),
                (v4_ip, RefusalKind::Inbound),
                (v6_ip, RefusalKind::Outbound),
            ]
        );
        assert_eq!(
            gate.counts(),
            GateCounts {
                refused_inbound: 2,
                refused_relayed: 3,
                refused_outbound: 2
            }
        );
        // Off again: refusals go on, the hook hears nothing more.
        gate.set_refusal_hook(None);
        assert!(gate
            .handle_established_inbound_connection(id(9), s, &direct(), &v4)
            .is_err());
        assert_eq!(heard.lock().unwrap().len(), 3);
        assert_eq!(gate.counts().refused_inbound, 3);
    }

    /// Phase 6b R1 (P6.26): the admit hook is asked about each direct
    /// inbound source before Noise and refuses the ones it names; circuits,
    /// dials and established connections are never asked, and its refusals
    /// are no gate counts.
    #[test]
    fn the_admit_hook_refuses_a_banned_source_before_noise() {
        let (c, r, s) = (peer(1), peer(2), peer(3));
        let mut gate = PeerGate::new(gate_with(&[
            (c, PeerClass::CONTACT),
            (r, PeerClass::OWN_RELAY),
        ]));
        let banned: IpAddr = "192.0.2.9".parse().unwrap();
        let asked: Arc<Mutex<Vec<IpAddr>>> = Arc::default();
        let log = Arc::clone(&asked);
        let from = |p: PeerId| Multiaddr::empty().with(Protocol::P2p(p));
        let v4 = addr("/ip4/192.0.2.9/tcp/4001");
        let other = addr("/ip6/2001:db8::5/udp/4001/quic-v1");
        // No hook: everything goes on to Noise, as before.
        gate.handle_pending_inbound_connection(id(1), &direct(), &v4)
            .unwrap();
        gate.set_admit_hook(Some(Arc::new(move |ip| {
            log.lock().unwrap().push(ip);
            ip != banned
        })));
        let refused = gate
            .handle_pending_inbound_connection(id(2), &direct(), &v4)
            .unwrap_err();
        assert_eq!(
            refused.downcast_ref::<SourceRefused>(),
            Some(&SourceRefused)
        );
        assert_eq!(
            SourceRefused.to_string(),
            "a source that failed too often was refused"
        );
        gate.handle_pending_inbound_connection(id(3), &direct(), &other)
            .unwrap();
        // A circuit names the relay: the class decides, the hook is not asked.
        gate.handle_pending_inbound_connection(id(4), &circuit(r), &from(c))
            .unwrap();
        // Dials and established connections are not asked.
        gate.handle_pending_outbound_connection(
            id(5),
            Some(c),
            std::slice::from_ref(&v4),
            Endpoint::Dialer,
        )
        .unwrap();
        gate.handle_established_inbound_connection(id(6), c, &direct(), &v4)
            .unwrap();
        assert!(gate
            .handle_established_inbound_connection(id(7), s, &direct(), &other)
            .is_err());
        assert_eq!(
            *asked.lock().unwrap(),
            [banned, "2001:db8::5".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            gate.counts(),
            GateCounts {
                refused_inbound: 1,
                refused_relayed: 0,
                refused_outbound: 0
            },
            "only the stranger's class refusal counts"
        );
        // Off again: nothing is asked.
        gate.set_admit_hook(None);
        gate.handle_pending_inbound_connection(id(8), &direct(), &v4)
            .unwrap();
        assert_eq!(asked.lock().unwrap().len(), 2);
    }

    /// Phase 6 review (sensing-7): the authenticated hook hears the source
    /// IP of each direct inbound connection admitted as a contact's (a
    /// hidden one too), once the PeerId is proven; never a relay's or a
    /// stranger's, a circuit's or a dial of ours.
    #[test]
    fn the_authenticated_hook_hears_a_contacts_direct_inbound_source() {
        let (c, h, r, s) = (peer(1), peer(2), peer(3), peer(4));
        let mut gate = PeerGate::new(gate_with(&[
            (c, PeerClass::CONTACT),
            (h, PeerClass::CONTACT_HIDDEN),
            (r, PeerClass::OWN_RELAY),
        ]));
        let heard: Arc<Mutex<Vec<IpAddr>>> = Arc::default();
        let sink = Arc::clone(&heard);
        let from = |p: PeerId| Multiaddr::empty().with(Protocol::P2p(p));
        let v4 = addr("/ip4/192.0.2.9/tcp/4001");
        let v6 = addr("/ip6/2001:db8::5/udp/4001/quic-v1");
        // No hook: nothing to tell, as before.
        gate.handle_established_inbound_connection(id(1), c, &direct(), &v4)
            .unwrap();
        gate.set_authenticated_hook(Some(Arc::new(move |ip| {
            sink.lock().unwrap().push(ip);
        })));
        gate.handle_established_inbound_connection(id(2), c, &direct(), &v4)
            .unwrap();
        gate.handle_established_inbound_connection(id(3), h, &direct(), &v6)
            .unwrap();
        // A relay's own connection, a stranger, a contact's circuit and our
        // own dial to a contact: nothing.
        gate.handle_established_inbound_connection(id(4), r, &direct(), &v4)
            .unwrap();
        assert!(gate
            .handle_established_inbound_connection(id(5), s, &direct(), &v4)
            .is_err());
        gate.handle_established_inbound_connection(id(6), c, &circuit(r), &from(c))
            .unwrap();
        gate.handle_established_outbound_connection(id(7), c, &v4, Endpoint::Dialer, PortUse::New)
            .unwrap();
        let (v4_ip, v6_ip): (IpAddr, IpAddr) =
            ("192.0.2.9".parse().unwrap(), "2001:db8::5".parse().unwrap());
        assert_eq!(*heard.lock().unwrap(), [v4_ip, v6_ip]);
        // Off again: nothing more is told.
        gate.set_authenticated_hook(None);
        gate.handle_established_inbound_connection(id(8), c, &direct(), &v4)
            .unwrap();
        assert_eq!(heard.lock().unwrap().len(), 2);
    }

    #[test]
    fn recheck_names_peers_that_lost_a_class() {
        let (c, c2, r, d, dr, late) = (peer(1), peer(2), peer(3), peer(4), peer(5), peer(6));
        let handle = gate_with(&[
            (c, PeerClass::CONTACT),
            (c2, PeerClass::CONTACT),
            (r, PeerClass::OWN_RELAY),
        ]);
        let mut gate = PeerGate::new(handle.clone());
        // Our own dial to `d` (just verified) through its relay `dr`.
        handle
            .admit_dial(
                d,
                PeerClass::CONTACT,
                &[dr],
                Instant::now(),
                Instant::now() + Duration::from_secs(600),
            )
            .unwrap();
        let remote = direct();
        gate.handle_established_inbound_connection(id(1), c, &direct(), &remote)
            .unwrap();
        gate.handle_established_inbound_connection(id(2), c2, &direct(), &remote)
            .unwrap();
        for (n, p) in [(3, r), (4, d), (5, dr)] {
            gate.handle_established_outbound_connection(
                id(n),
                p,
                &direct(),
                Endpoint::Dialer,
                PortUse::New,
            )
            .unwrap();
        }
        assert_eq!(gate.recheck(), Vec::<PeerId>::new());
        assert_eq!(handle.summary(), (2, 1, false));

        // A reload drops c2 and gives r a second class: only c2 is named.
        // Its files were read before the dial (a load in flight): the dial
        // admissions survive it.
        handle.replace(
            [
                (c, PeerClass::CONTACT),
                (r, PeerClass::OWN_RELAY | PeerClass::CONTACT),
            ]
            .into(),
            false,
            read_earlier(),
        );
        assert_eq!(gate.recheck(), vec![c2]);
        assert_eq!(handle.class_of(&d), PeerClass::CONTACT);
        assert_eq!(handle.class_of(&dr), PeerClass::CONTACT_RELAY);

        // An unreadable contact book: the caller passes the relays only
        // (fail closed), so every contact is named, the dialled one and its
        // relay too (these files are newer than the dial), and the relay is
        // kept.
        handle.replace([(r, PeerClass::OWN_RELAY)].into(), true, Instant::now());
        // r's connection was admitted as OWN_RELAY, which it still is.
        let mut expected = vec![c, c2, d, dr];
        expected.sort();
        assert_eq!(gate.recheck(), expected);
        assert_eq!(handle.class_of(&r), PeerClass::OWN_RELAY);
        assert_eq!(handle.class_of(&d), PeerClass::NONE);
        assert_eq!(handle.summary(), (0, 1, true));

        // The swarm closed them: nothing is named any more.
        for (n, p) in [(1, c), (2, c2), (3, r), (4, d), (5, dr)] {
            closed(&mut gate, id(n), p);
        }
        assert_eq!(gate.recheck(), Vec::<PeerId>::new());

        // A dial admission ends at its deadline.
        handle
            .admit_dial(
                late,
                PeerClass::CONTACT,
                &[],
                Instant::now(),
                Instant::now(),
            )
            .unwrap();
        assert_eq!(handle.class_of(&late), PeerClass::NONE);
        assert!(gate
            .handle_established_outbound_connection(
                id(6),
                late,
                &direct(),
                Endpoint::Dialer,
                PortUse::New
            )
            .is_err());
    }

    /// A dial admission bridges the moment until the files are read again.
    /// A set read before it (a load still in flight) keeps it; a set read
    /// after it ends it: a contact blocked, unpinned or removed after we
    /// dialled it is named and refused, and so is the relay only its dial
    /// admitted.
    #[test]
    fn files_read_after_a_dial_end_its_admission() {
        let (c, bob, relay) = (peer(1), peer(2), peer(3));
        let handle = gate_with(&[(c, PeerClass::CONTACT)]);
        let mut gate = PeerGate::new(handle.clone());
        let stale = read_earlier();
        handle
            .admit_dial(
                bob,
                PeerClass::CONTACT,
                &[relay],
                Instant::now(),
                Instant::now() + Duration::from_secs(600),
            )
            .unwrap();
        let via_relay = circuit(relay).with(Protocol::P2p(bob));
        for (n, p, a) in [(1, relay, direct()), (2, bob, via_relay)] {
            gate.handle_established_outbound_connection(
                id(n),
                p,
                &a,
                Endpoint::Dialer,
                PortUse::New,
            )
            .unwrap();
        }
        assert_eq!(gate.recheck(), Vec::<PeerId>::new());

        // The load in flight lands, read before bob was verified: our own
        // dial is still admitted.
        handle.replace([(c, PeerClass::CONTACT)].into(), false, stale);
        assert_eq!(handle.class_of(&bob), PeerClass::CONTACT);
        assert_eq!(handle.class_of(&relay), PeerClass::CONTACT_RELAY);
        assert_eq!(gate.recheck(), Vec::<PeerId>::new());

        // bob is blocked: the files read next leave him out, and they are
        // newer than the dial.
        handle.replace([(c, PeerClass::CONTACT)].into(), false, Instant::now());
        assert_eq!(handle.class_of(&bob), PeerClass::NONE);
        assert_eq!(handle.class_of(&relay), PeerClass::NONE);
        let mut expected = vec![bob, relay];
        expected.sort();
        assert_eq!(gate.recheck(), expected);
        // He cannot come back, directly or over a circuit.
        let from = Multiaddr::empty().with(Protocol::P2p(bob));
        assert!(gate
            .handle_pending_inbound_connection(id(3), &circuit(relay), &from)
            .is_err());
        assert!(gate
            .handle_established_inbound_connection(id(4), bob, &direct(), &direct())
            .is_err());
        // The contact the files still name is never named.
        gate.handle_established_inbound_connection(id(5), c, &direct(), &direct())
            .unwrap();
        assert_eq!(gate.recheck(), expected);
    }

    /// A dial admits a hidden contact as hidden, and never as a CONTACT
    /// that files read after its check hide; a hidden connection keeps its
    /// admission and leaves no scope when the contact is hidden, while a
    /// CONTACT connection whose contact is hidden since is named (it leaves
    /// DCUtR's scope and Identify's).
    #[test]
    fn a_dial_never_makes_a_hidden_contact_a_contact() {
        let (h, c) = (peer(1), peer(2));
        let far = Instant::now() + Duration::from_secs(600);
        let ms = Duration::from_millis;
        let handle = gate_with(&[]);
        handle
            .admit_dial(h, PeerClass::CONTACT_HIDDEN, &[], Instant::now(), far)
            .unwrap();
        assert_eq!(handle.class_of(&h), PeerClass::CONTACT_HIDDEN);

        // Newer files that name it hidden win over a dial's CONTACT; older
        // ones do not.
        let checked = Instant::now() - ms(20);
        handle.replace(
            [(h, PeerClass::CONTACT_HIDDEN), (c, PeerClass::CONTACT)].into(),
            false,
            checked + ms(10),
        );
        handle
            .admit_dial(h, PeerClass::CONTACT, &[], checked, far)
            .unwrap();
        assert_eq!(handle.class_of(&h), PeerClass::CONTACT_HIDDEN);
        assert_eq!(handle.summary(), (2, 0, false), "hidden contacts count");
        handle
            .admit_dial(h, PeerClass::CONTACT, &[], Instant::now(), far)
            .unwrap();
        assert_eq!(
            handle.class_of(&h),
            PeerClass::CONTACT | PeerClass::CONTACT_HIDDEN
        );

        // Hidden since its connection was admitted: c is named, h is not.
        let handle = gate_with(&[(h, PeerClass::CONTACT_HIDDEN), (c, PeerClass::CONTACT)]);
        let mut gate = PeerGate::new(handle.clone());
        let from = |p: PeerId| Multiaddr::empty().with(Protocol::P2p(p));
        gate.handle_pending_inbound_connection(id(1), &circuit(peer(3)), &from(h))
            .unwrap();
        gate.handle_established_inbound_connection(id(1), h, &circuit(peer(3)), &from(h))
            .unwrap();
        gate.handle_established_inbound_connection(id(2), c, &direct(), &direct())
            .unwrap();
        handle.replace(
            [
                (h, PeerClass::CONTACT_HIDDEN),
                (c, PeerClass::CONTACT_HIDDEN),
            ]
            .into(),
            false,
            Instant::now(),
        );
        assert_eq!(gate.recheck(), vec![c]);
    }

    /// A contact blocked between a dial's check and its admission, with the
    /// reload the block causes reading the files in between, is never left
    /// admitted, whichever lands first: a dial admission counts from its
    /// check, not from when the swarm loop got to it. Files read after the
    /// check that still name the peer a contact admit it all the same.
    #[test]
    fn a_block_between_a_dials_check_and_its_admission_never_admits_it() {
        let (c, bob, relay, x) = (peer(1), peer(2), peer(3), peer(4));
        let far = Instant::now() + Duration::from_secs(600);
        let ms = Duration::from_millis;
        // The reload lands after the dial was admitted: it read the files
        // after the check, though before the admission.
        let handle = gate_with(&[(c, PeerClass::CONTACT)]);
        let checked = Instant::now() - ms(20);
        handle
            .admit_dial(bob, PeerClass::CONTACT, &[relay], checked, far)
            .unwrap();
        assert_eq!(handle.class_of(&bob), PeerClass::CONTACT);
        handle.replace([(c, PeerClass::CONTACT)].into(), false, checked + ms(10));
        assert_eq!(handle.class_of(&bob), PeerClass::NONE);
        assert_eq!(handle.class_of(&relay), PeerClass::NONE);

        // The reload lands first: the dial is refused, so its caller checks
        // the contact again.
        let handle = gate_with(&[(c, PeerClass::CONTACT)]);
        let checked = Instant::now() - ms(20);
        handle.replace([(c, PeerClass::CONTACT)].into(), false, checked + ms(10));
        assert_eq!(
            handle.admit_dial(bob, PeerClass::CONTACT, &[relay], checked, far),
            Err(DialCheckStale)
        );
        assert_eq!(handle.class_of(&bob), PeerClass::NONE);
        assert_eq!(handle.class_of(&relay), PeerClass::NONE);
        // A check made after that reload (still a contact, a PeerId the
        // files do not list: an explicit dial) is admitted.
        handle
            .admit_dial(x, PeerClass::CONTACT, &[relay], Instant::now(), far)
            .unwrap();
        assert_eq!(handle.class_of(&x), PeerClass::CONTACT);
        assert_eq!(handle.class_of(&relay), PeerClass::CONTACT_RELAY);
        // An equal instant counts as files at least as new as the check.
        let at = Instant::now();
        handle.replace([(c, PeerClass::CONTACT)].into(), false, at);
        assert_eq!(
            handle.admit_dial(x, PeerClass::CONTACT, &[], at, far),
            Err(DialCheckStale)
        );

        // Newer files that name the peer a contact: admitted, with the
        // relays the dial uses.
        let checked = Instant::now() - ms(20);
        handle.replace(
            [(c, PeerClass::CONTACT), (bob, PeerClass::CONTACT)].into(),
            false,
            checked + ms(10),
        );
        handle
            .admit_dial(bob, PeerClass::CONTACT, &[relay], checked, far)
            .unwrap();
        assert_eq!(handle.class_of(&relay), PeerClass::CONTACT_RELAY);
        // Newer files that could not be read admit nobody.
        handle.replace(HashMap::new(), true, Instant::now());
        assert_eq!(
            handle.admit_dial(c, PeerClass::CONTACT, &[], checked, far),
            Err(DialCheckStale)
        );
        assert_eq!(
            DialCheckStale.to_string(),
            "the contact book or block list changed after the dial checked the contact"
        );
    }

    /// A connection is named only when the class its peer holds now no
    /// longer admits it, or no longer puts it in a protocol scope it was in
    /// (CONTACT for circuits and DCUtR, the Identify scope). Losing any other
    /// bit changes nothing on it: our own relay that the last contact's
    /// `via=` stopped naming keeps its reservation and every circuit through
    /// it.
    #[test]
    fn recheck_names_only_connections_that_lost_admission_or_a_scope() {
        let (r, x, y, z, d) = (peer(1), peer(2), peer(3), peer(4), peer(5));
        let both = PeerClass::OWN_RELAY | PeerClass::CONTACT_RELAY;
        let handle = gate_with(&[
            (r, both),
            (x, PeerClass::CONTACT | PeerClass::CONTACT_RELAY),
            (y, PeerClass::CONTACT | PeerClass::CONTACT_RELAY),
            (z, both),
            (d, both),
        ]);
        let mut gate = PeerGate::new(handle.clone());
        for (n, p) in [(1, r), (2, x), (3, y), (4, z)] {
            gate.handle_established_outbound_connection(
                id(n),
                p,
                &direct(),
                Endpoint::Dialer,
                PortUse::New,
            )
            .unwrap();
        }
        // An own relay's AutoNAT dial-back (inbound).
        gate.handle_established_inbound_connection(id(5), d, &direct(), &direct())
            .unwrap();
        assert_eq!(gate.recheck(), Vec::<PeerId>::new());

        // r, x and d lose only CONTACT_RELAY: none is named. y loses CONTACT
        // (circuits, DCUtR, its Identify scope) and z the Identify scope
        // while both stay admitted outbound: both are named.
        handle.replace(
            [
                (r, PeerClass::OWN_RELAY),
                (x, PeerClass::CONTACT),
                (y, PeerClass::CONTACT_RELAY),
                (z, PeerClass::CONTACT_RELAY),
                (d, PeerClass::OWN_RELAY),
            ]
            .into(),
            false,
            Instant::now(),
        );
        let mut expected = vec![y, z];
        expected.sort();
        assert_eq!(gate.recheck(), expected);

        // An unreadable contact book keeps the configured relays ("relays
        // still are"): only the contacts are named.
        handle.replace(
            [r, z, d].map(|p| (p, PeerClass::OWN_RELAY)).into(),
            true,
            Instant::now(),
        );
        let mut expected = vec![x, y];
        expected.sort();
        assert_eq!(gate.recheck(), expected);
    }

    /// Automatic relay choice (any-network plan C7): a picked relay is an
    /// own relay before its first dial, both ways (its reservation, its
    /// AutoNAT dial-back) but never on a circuit, and through file reloads,
    /// until a newer pick drops it: the recheck then names it. A relay the
    /// files name stays theirs.
    #[test]
    fn auto_relays_are_own_relays_until_replaced() {
        let (c, r1, r2, m) = (peer(1), peer(2), peer(3), peer(4));
        let handle = gate_with(&[(c, PeerClass::CONTACT), (m, PeerClass::OWN_RELAY)]);
        let mut gate = PeerGate::new(handle.clone());
        assert_eq!(handle.class_of(&r1), PeerClass::NONE);
        assert_eq!(handle.summary(), (1, 1, false));

        handle.set_auto_relays(&[r1]);
        assert_eq!(handle.class_of(&r1), PeerClass::OWN_RELAY);
        assert_eq!(handle.summary(), (1, 2, false));
        gate.handle_established_outbound_connection(
            id(1),
            r1,
            &direct(),
            Endpoint::Dialer,
            PortUse::New,
        )
        .unwrap();
        gate.handle_established_inbound_connection(id(2), r1, &direct(), &direct())
            .unwrap();
        gate.handle_established_outbound_connection(
            id(3),
            m,
            &direct(),
            Endpoint::Dialer,
            PortUse::New,
        )
        .unwrap();
        assert!(gate
            .handle_established_inbound_connection(id(4), r1, &circuit(m), &direct())
            .is_err());
        assert_eq!(gate.recheck(), Vec::<PeerId>::new());
        // A reload of the files keeps the pick.
        handle.replace(
            [(c, PeerClass::CONTACT), (m, PeerClass::OWN_RELAY)].into(),
            false,
            Instant::now(),
        );
        assert_eq!(handle.class_of(&r1), PeerClass::OWN_RELAY);
        assert_eq!(gate.recheck(), Vec::<PeerId>::new());

        // R2 replaces R1: R1 is named (both its connections), R2 admitted.
        handle.set_auto_relays(&[r2]);
        assert_eq!(handle.class_of(&r1), PeerClass::NONE);
        assert_eq!(handle.class_of(&r2), PeerClass::OWN_RELAY);
        assert_eq!(gate.recheck(), vec![r1]);
        assert_eq!(handle.summary(), (1, 2, false));
        for n in [1, 2] {
            closed(&mut gate, id(n), r1);
        }
        assert_eq!(gate.recheck(), Vec::<PeerId>::new());

        // A pick the files name already counts once, and dropping it from
        // the picks leaves it what the files say.
        handle.set_auto_relays(&[m]);
        assert_eq!(handle.summary(), (1, 1, false));
        handle.set_auto_relays(&[]);
        assert_eq!(handle.class_of(&m), PeerClass::OWN_RELAY);
        assert_eq!(handle.class_of(&r2), PeerClass::NONE);
        assert_eq!(gate.recheck(), Vec::<PeerId>::new());
    }

    #[test]
    fn a_relay_role_admits_its_listed_members_only() {
        let (m, s) = (peer(1), peer(2));
        let limits = RelayLimits::friends();
        let listed = RelayGuard::new(AllowPolicy::Peers([m].into()), &limits);
        let handle = GateHandle::new(Some(listed));
        assert_eq!(handle.class_of(&m), PeerClass::RELAY_MEMBER);
        assert_eq!(handle.class_of(&s), PeerClass::NONE);
        // `--relay-open` on an endpoint makes nobody a member.
        let open = GateHandle::new(Some(RelayGuard::new(AllowPolicy::Open, &limits)));
        assert_eq!(open.class_of(&s), PeerClass::NONE);
        let unreadable = GateHandle::new(Some(RelayGuard::new(AllowPolicy::Unreadable, &limits)));
        assert_eq!(unreadable.class_of(&m), PeerClass::NONE);

        // A dedicated relay's gate: its allow-list, or anyone with --open.
        let relay = RelayGuard::new(AllowPolicy::Peers([m].into()), &limits);
        assert_eq!(relay.class_of(&m), PeerClass::RELAY_MEMBER);
        assert_eq!(relay.class_of(&s), PeerClass::NONE);
        let open = RelayGuard::new(AllowPolicy::Open, &limits);
        assert_eq!(open.class_of(&s), PeerClass::RELAY_MEMBER);
        let unreadable = RelayGuard::new(AllowPolicy::Unreadable, &limits);
        assert_eq!(unreadable.class_of(&m), PeerClass::NONE);

        let only = OnlyPeer(Some(m));
        assert_eq!(only.class_of(&m), PeerClass::OWN_RELAY);
        assert_eq!(only.class_of(&s), PeerClass::NONE);
        assert_eq!(OnlyPeer::default().class_of(&m), PeerClass::NONE);
    }

    /// A handler `Probe` can be notified through (a `u32`).
    struct ProbeHandler;

    impl ConnectionHandler for ProbeHandler {
        type FromBehaviour = u32;
        type ToBehaviour = Infallible;
        type InboundProtocol = DeniedUpgrade;
        type OutboundProtocol = DeniedUpgrade;
        type InboundOpenInfo = ();
        type OutboundOpenInfo = ();

        fn listen_protocol(&self) -> SubstreamProtocol<DeniedUpgrade> {
            SubstreamProtocol::new(DeniedUpgrade, ())
        }

        fn on_behaviour_event(&mut self, _event: u32) {}

        fn poll(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<ConnectionHandlerEvent<DeniedUpgrade, (), Infallible>> {
            Poll::Pending
        }

        fn on_connection_event(&mut self, _event: ConnectionEvent<DeniedUpgrade, DeniedUpgrade>) {}
    }

    /// Panics, as dcutr and the AutoNAT client do, on an event for a
    /// connection it never built a handler for, and records what it saw.
    #[derive(Default)]
    struct Probe {
        built: HashSet<ConnectionId>,
        /// (connection, other_established) / (connection, remaining_established).
        established: Vec<(ConnectionId, usize)>,
        closed: Vec<(ConnectionId, usize)>,
        address_changes: Vec<ConnectionId>,
        candidates: Vec<Multiaddr>,
        failures: Vec<ConnectionId>,
        queue: VecDeque<ToSwarm<(), u32>>,
    }

    impl Probe {
        fn known(&self, connection: ConnectionId, what: &str) {
            assert!(
                self.built.contains(&connection),
                "{what} for connection {connection} the probe never built a handler for"
            );
        }
    }

    impl NetworkBehaviour for Probe {
        type ConnectionHandler = ProbeHandler;
        type ToSwarm = ();

        fn handle_established_inbound_connection(
            &mut self,
            connection_id: ConnectionId,
            _peer: PeerId,
            _local_addr: &Multiaddr,
            _remote_addr: &Multiaddr,
        ) -> Result<THandler<Self>, ConnectionDenied> {
            self.built.insert(connection_id);
            Ok(ProbeHandler)
        }

        fn handle_established_outbound_connection(
            &mut self,
            connection_id: ConnectionId,
            _peer: PeerId,
            _addr: &Multiaddr,
            _role_override: Endpoint,
            _port_use: PortUse,
        ) -> Result<THandler<Self>, ConnectionDenied> {
            self.built.insert(connection_id);
            Ok(ProbeHandler)
        }

        fn on_swarm_event(&mut self, event: FromSwarm) {
            match event {
                FromSwarm::ConnectionEstablished(c) => {
                    self.known(c.connection_id, "ConnectionEstablished");
                    self.established
                        .push((c.connection_id, c.other_established));
                }
                FromSwarm::ConnectionClosed(c) => {
                    self.known(c.connection_id, "ConnectionClosed");
                    self.closed.push((c.connection_id, c.remaining_established));
                }
                FromSwarm::AddressChange(c) => {
                    self.known(c.connection_id, "AddressChange");
                    self.address_changes.push(c.connection_id);
                }
                FromSwarm::NewExternalAddrCandidate(c) => self.candidates.push(c.addr.clone()),
                FromSwarm::ListenFailure(f) => self.failures.push(f.connection_id),
                FromSwarm::DialFailure(f) => self.failures.push(f.connection_id),
                _ => {}
            }
        }

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
            match self.queue.pop_front() {
                Some(event) => Poll::Ready(event),
                None => Poll::Pending,
            }
        }
    }

    type ProbeEvent = ToSwarm<(), Either<u32, Infallible>>;

    fn poll(scoped: &mut Scoped<Probe>) -> Option<ProbeEvent> {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        match scoped.poll(&mut cx) {
            Poll::Ready(event) => Some(event),
            Poll::Pending => None,
        }
    }

    fn notified(event: Option<ProbeEvent>) -> Option<(PeerId, ConnectionId, u32)> {
        match event {
            Some(ToSwarm::NotifyHandler {
                peer_id,
                handler: NotifyHandler::One(connection),
                event: Either::Left(n),
            }) => Some((peer_id, connection, n)),
            _ => None,
        }
    }

    fn notify(scoped: &mut Scoped<Probe>, peer: PeerId, handler: NotifyHandler, n: u32) {
        scoped.inner_mut().queue.push_back(ToSwarm::NotifyHandler {
            peer_id: peer,
            handler,
            event: n,
        });
    }

    #[test]
    fn scoped_hides_out_of_scope_connections_from_the_inner_behaviour() {
        let (c, s) = (peer(1), peer(2));
        let gate = gate_with(&[(c, PeerClass::CONTACT)]);
        let mut scoped = Scoped::new(
            Probe::default(),
            gate.clone(),
            PeerClass::CONTACT,
            Some(AddrRule::GlobalOnly),
        );
        let remote = direct();
        let (ci, si) = (id(1), id(2));
        let h = scoped
            .handle_established_inbound_connection(ci, c, &direct(), &remote)
            .unwrap();
        assert!(matches!(h, Either::Left(_)));
        let h = scoped
            .handle_established_outbound_connection(
                si,
                s,
                &direct(),
                Endpoint::Dialer,
                PortUse::New,
            )
            .unwrap();
        assert!(matches!(h, Either::Right(_)));
        assert_eq!(scoped.handlers_built(), 1);

        // The swarm reports both connections (and an address change on
        // each): the probe hears only of its own, and would panic otherwise.
        let endpoint = listener(&direct(), &remote);
        let moved = listener(&direct(), &addr("/ip4/127.0.0.2/tcp/7423"));
        for (connection, p) in [(ci, c), (si, s)] {
            scoped.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id: p,
                connection_id: connection,
                endpoint: &endpoint,
                failed_addresses: &[],
                other_established: 0,
            }));
            scoped.on_swarm_event(FromSwarm::AddressChange(AddressChange {
                peer_id: p,
                connection_id: connection,
                old: &endpoint,
                new: &moved,
            }));
        }
        assert_eq!(scoped.inner().established, vec![(ci, 0)]);
        assert_eq!(scoped.inner().address_changes, vec![ci]);

        // `Any` is pinned to the contact's connection; a notification for a
        // peer or connection the probe has no handler on is dropped (the
        // dummy on the other side would panic on it).
        notify(&mut scoped, c, NotifyHandler::Any, 7);
        assert_eq!(notified(poll(&mut scoped)), Some((c, ci, 7)));
        notify(&mut scoped, s, NotifyHandler::Any, 8);
        notify(&mut scoped, s, NotifyHandler::One(si), 9);
        notify(&mut scoped, c, NotifyHandler::One(ci), 10);
        assert_eq!(notified(poll(&mut scoped)), Some((c, ci, 10)));
        scoped
            .inner_mut()
            .queue
            .push_back(ToSwarm::GenerateEvent(()));
        assert!(matches!(
            poll(&mut scoped),
            Some(ToSwarm::GenerateEvent(()))
        ));
        assert!(poll(&mut scoped).is_none());

        // The stranger becomes a contact: its next connection is in scope,
        // and the counts the probe sees are of its own connections only.
        gate.replace(
            [(c, PeerClass::CONTACT), (s, PeerClass::CONTACT)].into(),
            false,
            Instant::now(),
        );
        let sj = id(3);
        let h = scoped
            .handle_established_inbound_connection(sj, s, &direct(), &remote)
            .unwrap();
        assert!(matches!(h, Either::Left(_)));
        scoped.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id: s,
            connection_id: sj,
            endpoint: &endpoint,
            failed_addresses: &[],
            other_established: 1,
        }));
        assert_eq!(scoped.inner().established, vec![(ci, 0), (sj, 0)]);
        notify(&mut scoped, s, NotifyHandler::Any, 11);
        assert_eq!(notified(poll(&mut scoped)), Some((s, sj, 11)));

        // Candidates follow the rule.
        for candidate in ["/ip4/192.168.1.2/tcp/7423", "/ip4/8.8.8.8/tcp/7423"] {
            scoped.on_swarm_event(FromSwarm::NewExternalAddrCandidate(
                NewExternalAddrCandidate {
                    addr: &addr(candidate),
                },
            ));
        }
        assert_eq!(
            scoped.inner().candidates,
            vec![addr("/ip4/8.8.8.8/tcp/7423")]
        );
        let mut open = Scoped::new(Probe::default(), gate.clone(), PeerClass::CONTACT, None);
        open.on_swarm_event(FromSwarm::NewExternalAddrCandidate(
            NewExternalAddrCandidate {
                addr: &addr("/ip4/192.168.1.2/tcp/7423"),
            },
        ));
        assert_eq!(open.inner().candidates.len(), 1, "no rule: all pass");

        // Closing: the out-of-scope connection is never reported; the
        // remaining count is of the probe's connections.
        let close = |scoped: &mut Scoped<Probe>, connection, p, remaining| {
            scoped.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id: p,
                connection_id: connection,
                endpoint: &endpoint,
                cause: None,
                remaining_established: remaining,
            }));
        };
        close(&mut scoped, si, s, 1);
        close(&mut scoped, sj, s, 0);
        close(&mut scoped, ci, c, 0);
        close(&mut scoped, ci, c, 0);
        assert_eq!(scoped.inner().closed, vec![(sj, 0), (ci, 0)]);
        notify(&mut scoped, c, NotifyHandler::Any, 12);
        assert!(poll(&mut scoped).is_none(), "no connection left: dropped");

        // A later field denied a connection the probe had built a handler
        // for: the probe hears the failure, and the scope forgets it.
        let ck = id(4);
        scoped
            .handle_established_outbound_connection(
                ck,
                c,
                &direct(),
                Endpoint::Dialer,
                PortUse::New,
            )
            .unwrap();
        scoped.on_swarm_event(FromSwarm::DialFailure(DialFailure {
            peer_id: Some(c),
            error: &DialError::Aborted,
            connection_id: ck,
        }));
        scoped.on_swarm_event(FromSwarm::ListenFailure(ListenFailure {
            local_addr: &direct(),
            send_back_addr: &remote,
            error: &ListenError::Aborted,
            connection_id: id(5),
            peer_id: None,
        }));
        assert_eq!(scoped.inner().failures, vec![ck, id(5)]);
        notify(&mut scoped, c, NotifyHandler::One(ck), 13);
        assert!(poll(&mut scoped).is_none());
        assert_eq!(scoped.handlers_built(), 3);
    }

    /// The AutoNAT clients' wrapper (RWS1 §9): while the restricted-network
    /// flag is set, no candidate reaches the client, whatever the rule says
    /// (through a proxy, Identify's guess carries the proxy's egress IP), and
    /// nothing held back is replayed later; once the flag clears, candidates
    /// pass under the rule again. Connections are scoped as before.
    #[test]
    fn scoped_autonat_drops_candidates_while_restricted() {
        let r = peer(2);
        let flag = Arc::new(AtomicBool::new(false));
        let mut scoped = Scoped::new(
            Probe::default(),
            OnlyPeer(Some(r)),
            PeerClass::OWN_RELAY,
            Some(AddrRule::GlobalOnly),
        )
        .with_restricted(flag.clone());
        let show = |scoped: &mut Scoped<Probe, OnlyPeer>, a: &str| {
            scoped.on_swarm_event(FromSwarm::NewExternalAddrCandidate(
                NewExternalAddrCandidate { addr: &addr(a) },
            ));
        };
        assert!(!scoped.restricted());
        show(&mut scoped, "/ip4/8.8.8.8/tcp/7423");

        flag.store(true, Ordering::SeqCst);
        assert!(scoped.restricted());
        for a in [
            "/ip4/11.0.1.2/tcp/7423",
            "/ip4/11.0.1.2/udp/7423/quic-v1",
            "/ip4/11.0.1.2/tcp/41000/tls/ws",
        ] {
            show(&mut scoped, a);
        }
        // The relay's connection (here a WSS one) still gets the client.
        let h = scoped
            .handle_established_outbound_connection(
                id(1),
                r,
                &addr(&format!("/ip4/8.8.8.8/tcp/443/tls/ws/p2p/{r}")),
                Endpoint::Dialer,
                PortUse::New,
            )
            .unwrap();
        assert!(matches!(h, Either::Left(_)));
        assert_eq!(scoped.handlers_built(), 1);
        assert_eq!(
            scoped.inner().candidates,
            vec![addr("/ip4/8.8.8.8/tcp/7423")]
        );

        flag.store(false, Ordering::SeqCst);
        assert!(!scoped.restricted());
        show(&mut scoped, "/ip4/192.168.1.2/tcp/7423");
        show(&mut scoped, "/ip4/8.8.4.4/tcp/7423");
        assert_eq!(
            scoped.inner().candidates,
            vec![addr("/ip4/8.8.8.8/tcp/7423"), addr("/ip4/8.8.4.4/tcp/7423")]
        );
        // Without a flag (Identify's wrapper): never restricted.
        let open = Scoped::new(
            Probe::default(),
            OnlyPeer(Some(r)),
            PeerClass::OWN_RELAY,
            None,
        );
        assert!(!open.restricted());
    }

    #[test]
    fn hole_punch_scopes_contacts_and_refuses_private_targets() {
        let (c, r) = (peer(1), peer(2));
        let mut hp = HolePunch::new(
            peer(9),
            gate_with(&[(c, PeerClass::CONTACT), (r, PeerClass::OWN_RELAY)]),
            AddrRule::GlobalOnly,
        );
        let remote = direct();
        // Only a contact's connections get a DCUtR handler.
        let h = hp
            .handle_established_inbound_connection(id(1), r, &direct(), &remote)
            .unwrap();
        assert!(matches!(h, Either::Right(_)));
        let h = hp
            .handle_established_inbound_connection(id(2), c, &circuit(r), &remote)
            .unwrap();
        assert!(matches!(h, Either::Left(_)));
        let h = hp
            .handle_established_outbound_connection(
                id(3),
                c,
                &addr("/ip4/8.8.8.8/tcp/7423"),
                Endpoint::Dialer,
                PortUse::New,
            )
            .unwrap();
        assert!(matches!(h, Either::Left(_)));
        assert_eq!(hp.handlers_built(), 2);
        // The circuit's handler came from the candidate book, the direct one
        // from DCUtR itself.
        assert_eq!(hp.relayed_handlers_built(), 1);
        // The swarm's candidates go to the book only, under the same rule.
        for a in ["/ip4/192.168.1.2/tcp/7423", "/ip4/8.8.8.8/tcp/7423"] {
            let a = addr(a);
            hp.on_swarm_event(FromSwarm::NewExternalAddrCandidate(
                NewExternalAddrCandidate { addr: &a },
            ));
        }
        assert_eq!(
            hp.book().candidates(std::time::Instant::now()),
            vec![addr("/ip4/8.8.8.8/tcp/7423")]
        );
        // DCUtR `expect`s a ConnectionClosed only for direct connections it
        // recorded: the relay's must never reach it (this would panic).
        closed(&mut hp, id(1), r);
        closed(&mut hp, id(3), c);
        let relayed = listener(&circuit(r), &remote);
        hp.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: c,
            connection_id: id(2),
            endpoint: &relayed,
            cause: None,
            remaining_established: 0,
        }));
        assert!(hp.contacts.is_empty());

        // DCUtR's own dials (recorded by `poll`): refused whole unless every
        // address is allowed and names the peer.
        let pending = |hp: &mut HolePunch, n: usize, peer: PeerId, addrs: &[&str]| {
            let addrs: Vec<Multiaddr> = addrs.iter().map(|a| addr(a)).collect();
            hp.handle_pending_outbound_connection(id(n), Some(peer), &addrs, Endpoint::Listener)
        };
        let named = |p: PeerId| format!("/ip4/8.8.8.8/tcp/7423/p2p/{p}");
        // Review A-2: a WSS form a contact offers as a CONNECT candidate
        // is never dialled (it would go through the HTTPS proxy with an
        // SNI name of the contact's choosing).
        let wss = format!("/ip4/8.8.8.8/tcp/443/tls/sni/x.example/ws/p2p/{c}");
        for (n, addrs) in [
            (10, vec!["/ip4/192.168.1.2/tcp/7423".to_string()]),
            (11, vec![named(r)]),
            (12, vec![named(c), "/ip4/127.0.0.1/tcp/7423".to_string()]),
            (13, Vec::new()),
            (17, vec![wss.clone()]),
            (
                18,
                vec![named(c), format!("/ip4/8.8.8.8/tcp/443/tls/ws/p2p/{c}")],
            ),
        ] {
            hp.dials.insert(id(n));
            let addrs: Vec<&str> = addrs.iter().map(String::as_str).collect();
            let denied = refused(pending(&mut hp, n, c, &addrs));
            assert!(denied.downcast_ref::<HolePunchTargetRefused>().is_some());
            assert!(!format!("{denied} {denied:?}").contains("192.168"));
        }
        assert_eq!(hp.refused_targets(), 6);
        // Each DCUtR dial, refused or not, is an attempt with that peer.
        let tried = hp.last_attempt(&c).expect("an attempt with c");
        assert!(hp.last_attempt(&r).is_none());
        hp.dials.insert(id(14));
        pending(
            &mut hp,
            14,
            c,
            &[&named(c), "/ip4/8.8.4.4/udp/7423/quic-v1"],
        )
        .unwrap();
        assert!(hp.last_attempt(&c).is_some_and(|t| t >= tried));
        // A dial DCUtR did not issue is not its to judge, nor an attempt.
        let d = peer(3);
        pending(&mut hp, 15, d, &["/ip4/192.168.1.2/tcp/7423"]).unwrap();
        assert!(hp.last_attempt(&d).is_none());
        // A failed dial is forgotten.
        hp.dials.insert(id(16));
        hp.on_swarm_event(FromSwarm::DialFailure(DialFailure {
            peer_id: Some(c),
            error: &DialError::Aborted,
            connection_id: id(16),
        }));
        assert!(hp.dials.is_empty());
        assert_eq!(hp.refused_targets(), 6);
        // The attempt is forgotten once the peer has no connection left.
        let relayed = listener(&circuit(r), &remote);
        hp.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: c,
            connection_id: id(20),
            endpoint: &relayed,
            cause: None,
            remaining_established: 1,
        }));
        assert!(hp.last_attempt(&c).is_some());
        hp.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: c,
            connection_id: id(21),
            endpoint: &relayed,
            cause: None,
            remaining_established: 0,
        }));
        assert!(hp.last_attempt(&c).is_none());
        assert_eq!(
            HolePunchTargetRefused.to_string(),
            "a hole-punch target is not an address this node dials"
        );
    }

    /// Phase 4 (P4.24): with the policy enabled, a contact whose hole punch
    /// is hopeless gets a dummy handler on its relayed connections (both
    /// directions): no relayed handler is built, each skip is counted, the
    /// connection is still tracked and closes cleanly. Its direct
    /// connections and every other contact's circuits are untouched; with
    /// the policy disabled (the gate closed, the default) nothing is skipped.
    #[test]
    fn hole_punch_policy_skips_hopeless_circuits_only() {
        use crate::natclass::{Mapping, NatSummary};
        let (c, d, r) = (peer(1), peer(4), peer(2));
        let gate = gate_with(&[
            (c, PeerClass::CONTACT),
            (d, PeerClass::CONTACT),
            (r, PeerClass::OWN_RELAY),
        ]);
        let varies = NatSummary {
            v4_tcp: Mapping::Varies,
            ..NatSummary::default()
        };
        let later = std::time::Instant::now() + std::time::Duration::from_secs(600);
        let remote = direct();
        // Disabled (the default): Phase 1's behaviour, whatever is known.
        let mut off = HolePunch::new(peer(9), gate.clone(), AddrRule::GlobalOnly);
        assert!(!off.policy.enabled);
        off.policy.own = varies;
        off.policy.set_remote(c, varies, later);
        let h = off
            .handle_established_inbound_connection(id(1), c, &circuit(r), &remote)
            .unwrap();
        assert!(matches!(h, Either::Left(_)));
        assert_eq!((off.relayed_handlers_built(), off.skipped()), (1, 0));

        let mut hp = HolePunch::new(peer(9), gate, AddrRule::GlobalOnly).with_punch_policy(true);
        hp.policy.own = varies;
        hp.policy.set_remote(c, varies, later);
        let h = hp
            .handle_established_inbound_connection(id(1), c, &circuit(r), &remote)
            .unwrap();
        assert!(matches!(h, Either::Right(_)));
        let h = hp
            .handle_established_outbound_connection(
                id(2),
                c,
                &format!("{}/p2p/{c}", circuit(r)).parse().unwrap(),
                Endpoint::Dialer,
                PortUse::Reuse,
            )
            .unwrap();
        assert!(matches!(h, Either::Right(_)));
        assert_eq!((hp.relayed_handlers_built(), hp.skipped()), (0, 2));
        assert_eq!(hp.last_skip(), Some(SkipWhy::BothVary));
        assert_eq!(hp.contacts.len(), 2, "still tracked");
        // A direct connection to the same contact keeps DCUtR's own handler,
        // and another contact's circuit (no class known) gets one too.
        let h = hp
            .handle_established_outbound_connection(
                id(3),
                c,
                &addr("/ip4/8.8.8.8/tcp/7423"),
                Endpoint::Dialer,
                PortUse::New,
            )
            .unwrap();
        assert!(matches!(h, Either::Left(_)));
        let h = hp
            .handle_established_inbound_connection(id(4), d, &circuit(r), &remote)
            .unwrap();
        assert!(matches!(h, Either::Left(_)));
        assert_eq!((hp.relayed_handlers_built(), hp.skipped()), (1, 2));
        // The skipped circuits close without reaching DCUtR's direct-
        // connection bookkeeping (it would panic).
        let relayed = listener(&circuit(r), &remote);
        for n in [1, 2, 4] {
            hp.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id: if n == 4 { d } else { c },
                connection_id: id(n),
                endpoint: &relayed,
                cause: None,
                remaining_established: 1,
            }));
        }
        closed(&mut hp, id(3), c);
        assert!(hp.contacts.is_empty());
        // Two failures with a contact skip it too, until a success.
        let e = peer(5);
        hp.policy.note_failure(e, std::time::Instant::now());
        hp.policy.note_failure(e, std::time::Instant::now());
        let gate_e = gate_with(&[(e, PeerClass::CONTACT)]);
        hp.admission = gate_e;
        let h = hp
            .handle_established_inbound_connection(id(5), e, &circuit(r), &remote)
            .unwrap();
        assert!(matches!(h, Either::Right(_)));
        assert_eq!(hp.last_skip(), Some(SkipWhy::FailedTwice));
    }

    #[test]
    fn addr_rule_table() {
        use AddrRule::{GlobalOnly, LabAnyIp};
        let relay = peer(9);
        let c = peer(1);
        let refused_by_global = [
            "/ip4/10.1.2.3/tcp/7423",
            "/ip4/172.16.0.1/tcp/7423",
            "/ip4/172.31.255.1/udp/7423/quic-v1",
            "/ip4/192.168.1.2/tcp/7423",
            "/ip4/100.64.0.1/tcp/7423",
            "/ip4/127.0.0.1/tcp/7423",
            "/ip6/::1/tcp/7423",
            "/ip6/fe80::1/tcp/7423",
            "/ip6/fc00::1/tcp/7423",
            "/ip6/fd12:3456::1/udp/7423/quic-v1",
            "/ip6/2001:db8::1/tcp/7423",
            "/ip4/192.0.2.7/tcp/7423",
            "/ip6/::ffff:192.168.1.2/tcp/7423",
            "/ip6/64:ff9b::a00:1/tcp/7423",
            "/ip6/2002:c0a8:102::1/tcp/7423",
        ];
        for a in refused_by_global {
            assert!(!GlobalOnly.allows(&addr(a)), "{a}");
            assert!(LabAnyIp.allows(&addr(a)), "lab: {a}");
        }
        for a in [
            "/ip4/8.8.8.8/tcp/7423",
            "/ip4/8.8.8.8/udp/7423/quic-v1",
            "/ip6/2606:4700::1111/tcp/7423",
        ] {
            assert!(GlobalOnly.allows(&addr(a)), "{a}");
            assert!(LabAnyIp.allows(&addr(a)), "{a}");
        }
        // Never a circuit, a name, an IP-less address, unspecified or
        // multicast, whatever the rule.
        let via = addr("/ip4/8.8.8.8/tcp/7423")
            .with(Protocol::P2p(relay))
            .with(Protocol::P2pCircuit);
        let never = [
            via.clone(),
            via.with(Protocol::P2p(c)),
            addr("/dns4/example.com/tcp/7423"),
            addr("/dns6/example.com/tcp/7423"),
            addr("/dns/example.com/tcp/7423"),
            addr("/memory/1"),
            Multiaddr::empty(),
            Multiaddr::empty().with(Protocol::P2p(c)),
            addr("/ip4/0.0.0.0/tcp/7423"),
            addr("/ip6/::/tcp/7423"),
            addr("/ip6/::ffff:0.0.0.0/tcp/7423"),
            addr("/ip4/224.0.0.1/udp/7423/quic-v1"),
            addr("/ip6/ff02::1/udp/7423/quic-v1"),
            // Review A-2: only the plain transport, then at most one /p2p.
            addr("/ip4/8.8.8.8/tcp/443/tls/ws"),
            addr("/ip4/8.8.8.8/tcp/443/tls/sni/x.example/ws"),
            addr("/ip4/8.8.8.8/tcp/443/tls/sni/x.example/ws").with(Protocol::P2p(c)),
            addr("/ip4/8.8.8.8/tcp/443/wss"),
            addr("/ip4/8.8.8.8/tcp/443/ws"),
            addr("/ip4/8.8.8.8/tcp/443/tls"),
            addr("/ip6/2606:4700::1111/tcp/443/tls/ws"),
            addr("/ip4/8.8.8.8/udp/443/quic-v1/webtransport"),
            addr("/ip4/8.8.8.8/udp/443"),
            addr("/ip4/8.8.8.8"),
            addr("/ip4/8.8.8.8/tcp/7423")
                .with(Protocol::P2p(c))
                .with(Protocol::P2p(c)),
        ];
        for a in &never {
            for rule in [GlobalOnly, LabAnyIp] {
                assert!(!rule.allows(a), "{rule:?} {a}");
            }
        }

        // A trailing /p2p must name the peer being dialled.
        let public = addr("/ip4/8.8.8.8/tcp/7423");
        let named = public.clone().with(Protocol::P2p(c));
        assert!(GlobalOnly.target_ok(&public, Some(&c)));
        assert!(GlobalOnly.target_ok(&public, None));
        assert!(GlobalOnly.target_ok(&named, Some(&c)));
        assert!(GlobalOnly.target_ok(
            &addr("/ip4/8.8.8.8/udp/7423/quic-v1").with(Protocol::P2p(c)),
            Some(&c)
        ));
        assert!(!GlobalOnly.target_ok(&named, Some(&relay)));
        assert!(!GlobalOnly.target_ok(&named, None));
        let lan = addr("/ip4/192.168.1.2/tcp/7423").with(Protocol::P2p(c));
        assert!(!GlobalOnly.target_ok(&lan, Some(&c)));
        assert!(LabAnyIp.target_ok(&lan, Some(&c)));
        assert!(!LabAnyIp.target_ok(&lan, Some(&relay)));
    }
}
