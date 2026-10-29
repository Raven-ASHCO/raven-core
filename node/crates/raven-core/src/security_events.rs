//! Security events: the local `SEC_*` kinds, their thresholds, the
//! in-memory aggregator, the stranger penalty box and the classifiers that
//! turn a typed refusal into a kind (`docs/roadmap/plans/phase6-design.json`,
//! step P6.22; design A §1-§2 and R1).
//!
//! The codes are local, not wire: `docs/SECURITY_EVENTS.md` is the registry,
//! [`SecKind`] carries the same numbers, and a test reads that table. Nothing
//! here does I/O or reads a clock: callers pass the event time (`at_ms`) and
//! the penalty box's `Instant`.
//!
//! [`note`] is the one entry point the sensing points call. While
//! [`SecGate::Events`] is shut it returns at once: nothing is counted, no sink
//! is called, and builds behave byte for byte as before. Live, it counts the
//! event in the process-wide [`Aggregator`] (memory only, bounded) and hands
//! it with its severity to the registered [`SecSink`] (raven-node: the ledger
//! writer; ash: a direct best-effort write; steps P6.23-P6.25).
//!
//! The classifiers ([`classify_store_error`], [`classify_relayed`],
//! [`classify_custody_code`], [`classify_prekey_error`],
//! [`classify_at_rest_error`], [`classify_link_error`]) match every variant
//! of the error they read without a `_` arm, so a new variant does not build
//! until someone decides whether it is a security event. They name the kind
//! only; the caller knows whom to attribute it to.
//!
//! Privacy: a network source is a [`SourceKey`] (v4 /32, v6 /64), kept in
//! memory only and never printed (its `Debug` hides the address). Subjects
//! that may reach the ledger are contact, custodian or relay keys.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::time::{Duration, Instant};

use crate::at_rest::AtRestError;
use crate::clock_skew::PeerClock;
use crate::friend_custody::CustodyCode;
use crate::indexed_session_store::IndexedSessionStoreError;
use crate::lan_dispatch::{
    LINK_REFUSED_BLOCKED, LINK_REFUSED_NOT_CONTACT, LINK_REFUSED_NOT_VERIFIED,
    LINK_REFUSED_VERIFIED_ONLY,
};
use crate::outbox::OutboxCarrier;
use crate::prekey_lifecycle::PrekeyLifecycleError;
use crate::relayed_ingest::RelayedOutcome;
use crate::security_gate::{self, SecGate};

/// How many kinds there are ([`SecKind::ALL`]).
pub const KINDS: usize = 48;

/// One security event kind. The numbers are `docs/SECURITY_EVENTS.md`'s
/// codes: fixed forever once a build that raises them is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum SecKind {
    LinkTagFail = 1,
    HandshakeFail = 2,
    PreauthMalformed = 3,
    StrangerRefused = 4,
    BlockedRefused = 5,
    UnverifiedRemote = 6,
    PreauthFlood = 7,
    P2pGateRefused = 8,
    BeaconReplay = 9,
    BeaconFlood = 10,
    KnockReplay = 11,
    ObjectAuthFail = 20,
    ObjectSigFail = 21,
    ObjectReplay = 22,
    IndexJump = 23,
    SessionUnknown = 24,
    BindingMismatch = 25,
    RevokedDeviceUsed = 26,
    KeyChangeAttempt = 27,
    PrekeyRollback = 28,
    AddressImpostor = 29,
    CapabilityDowngrade = 30,
    ContactMalformed = 31,
    PairinitFlood = 32,
    ResetLoop = 33,
    ClockSkew = 34,
    PairSeedRoot = 35,
    CustodianBadObject = 40,
    CustodianUnrequested = 41,
    CustodianReplay = 42,
    DepositorFlood = 43,
    DepositorBadObject = 44,
    RelayNoReceipt = 45,
    RelayLinkBroken = 46,
    LetterBad = 47,
    HandoffRefused = 48,
    KnockFail = 49,
    LocalRollback = 60,
    UnlockFailed = 61,
    AdvisoryForged = 70,
    AdvisoryRollback = 71,
    AdvisoryEquivocation = 72,
    BundleForged = 73,
    UpdateUnlogged = 74,
    BundleDowngrade = 75,
    LogSplitView = 76,
    AdvisoryApplied = 77,
    UpdateFlood = 78,
}

impl SecKind {
    /// Every kind, each once, in code order.
    pub const ALL: [SecKind; KINDS] = [
        SecKind::LinkTagFail,
        SecKind::HandshakeFail,
        SecKind::PreauthMalformed,
        SecKind::StrangerRefused,
        SecKind::BlockedRefused,
        SecKind::UnverifiedRemote,
        SecKind::PreauthFlood,
        SecKind::P2pGateRefused,
        SecKind::BeaconReplay,
        SecKind::BeaconFlood,
        SecKind::KnockReplay,
        SecKind::ObjectAuthFail,
        SecKind::ObjectSigFail,
        SecKind::ObjectReplay,
        SecKind::IndexJump,
        SecKind::SessionUnknown,
        SecKind::BindingMismatch,
        SecKind::RevokedDeviceUsed,
        SecKind::KeyChangeAttempt,
        SecKind::PrekeyRollback,
        SecKind::AddressImpostor,
        SecKind::CapabilityDowngrade,
        SecKind::ContactMalformed,
        SecKind::PairinitFlood,
        SecKind::ResetLoop,
        SecKind::ClockSkew,
        SecKind::PairSeedRoot,
        SecKind::CustodianBadObject,
        SecKind::CustodianUnrequested,
        SecKind::CustodianReplay,
        SecKind::DepositorFlood,
        SecKind::DepositorBadObject,
        SecKind::RelayNoReceipt,
        SecKind::RelayLinkBroken,
        SecKind::LetterBad,
        SecKind::HandoffRefused,
        SecKind::KnockFail,
        SecKind::LocalRollback,
        SecKind::UnlockFailed,
        SecKind::AdvisoryForged,
        SecKind::AdvisoryRollback,
        SecKind::AdvisoryEquivocation,
        SecKind::BundleForged,
        SecKind::UpdateUnlogged,
        SecKind::BundleDowngrade,
        SecKind::LogSplitView,
        SecKind::AdvisoryApplied,
        SecKind::UpdateFlood,
    ];

    /// The registry code (what the ledger stores).
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// The kind with this registry code; None for an unassigned code.
    pub fn from_code(code: u16) -> Option<Self> {
        Self::ALL
            .binary_search_by_key(&code, |k| k.code())
            .ok()
            .map(|i| Self::ALL[i])
    }

    /// The registry name (`SEC_...`).
    pub const fn name(self) -> &'static str {
        match self {
            SecKind::LinkTagFail => "SEC_LINK_TAG_FAIL",
            SecKind::HandshakeFail => "SEC_HANDSHAKE_FAIL",
            SecKind::PreauthMalformed => "SEC_PREAUTH_MALFORMED",
            SecKind::StrangerRefused => "SEC_STRANGER_REFUSED",
            SecKind::BlockedRefused => "SEC_BLOCKED_REFUSED",
            SecKind::UnverifiedRemote => "SEC_UNVERIFIED_REMOTE",
            SecKind::PreauthFlood => "SEC_PREAUTH_FLOOD",
            SecKind::P2pGateRefused => "SEC_P2P_GATE_REFUSED",
            SecKind::BeaconReplay => "SEC_BEACON_REPLAY",
            SecKind::BeaconFlood => "SEC_BEACON_FLOOD",
            SecKind::KnockReplay => "SEC_KNOCK_REPLAY",
            SecKind::ObjectAuthFail => "SEC_OBJECT_AUTH_FAIL",
            SecKind::ObjectSigFail => "SEC_OBJECT_SIG_FAIL",
            SecKind::ObjectReplay => "SEC_OBJECT_REPLAY",
            SecKind::IndexJump => "SEC_INDEX_JUMP",
            SecKind::SessionUnknown => "SEC_SESSION_UNKNOWN",
            SecKind::BindingMismatch => "SEC_BINDING_MISMATCH",
            SecKind::RevokedDeviceUsed => "SEC_REVOKED_DEVICE_USED",
            SecKind::KeyChangeAttempt => "SEC_KEY_CHANGE_ATTEMPT",
            SecKind::PrekeyRollback => "SEC_PREKEY_ROLLBACK",
            SecKind::AddressImpostor => "SEC_ADDRESS_IMPOSTOR",
            SecKind::CapabilityDowngrade => "SEC_CAPABILITY_DOWNGRADE",
            SecKind::ContactMalformed => "SEC_CONTACT_MALFORMED",
            SecKind::PairinitFlood => "SEC_PAIRINIT_FLOOD",
            SecKind::ResetLoop => "SEC_RESET_LOOP",
            SecKind::ClockSkew => "SEC_CLOCK_SKEW",
            SecKind::PairSeedRoot => "SEC_PAIR_SEED_ROOT",
            SecKind::CustodianBadObject => "SEC_CUSTODIAN_BAD_OBJECT",
            SecKind::CustodianUnrequested => "SEC_CUSTODIAN_UNREQUESTED",
            SecKind::CustodianReplay => "SEC_CUSTODIAN_REPLAY",
            SecKind::DepositorFlood => "SEC_DEPOSITOR_FLOOD",
            SecKind::DepositorBadObject => "SEC_DEPOSITOR_BAD_OBJECT",
            SecKind::RelayNoReceipt => "SEC_RELAY_NO_RECEIPT",
            SecKind::RelayLinkBroken => "SEC_RELAY_LINK_BROKEN",
            SecKind::LetterBad => "SEC_LETTER_BAD",
            SecKind::HandoffRefused => "SEC_HANDOFF_REFUSED",
            SecKind::KnockFail => "SEC_KNOCK_FAIL",
            SecKind::LocalRollback => "SEC_LOCAL_ROLLBACK",
            SecKind::UnlockFailed => "SEC_UNLOCK_FAILED",
            SecKind::AdvisoryForged => "SEC_ADVISORY_FORGED",
            SecKind::AdvisoryRollback => "SEC_ADVISORY_ROLLBACK",
            SecKind::AdvisoryEquivocation => "SEC_ADVISORY_EQUIVOCATION",
            SecKind::BundleForged => "SEC_BUNDLE_FORGED",
            SecKind::UpdateUnlogged => "SEC_UPDATE_UNLOGGED",
            SecKind::BundleDowngrade => "SEC_BUNDLE_DOWNGRADE",
            SecKind::LogSplitView => "SEC_LOG_SPLIT_VIEW",
            SecKind::AdvisoryApplied => "SEC_ADVISORY_APPLIED",
            SecKind::UpdateFlood => "SEC_UPDATE_FLOOD",
        }
    }
}

/// How serious one occurrence is (the registry's "Default severity" and its
/// escalation rules, [`THRESHOLDS`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Severity {
    Notice,
    Suspicious,
    Alert,
}

/// A network source: `admission_key(ip)` (an IPv4-mapped IPv6 address folds
/// to IPv4, a native IPv6 address to its /64; loopback stays loopback).
/// Memory only, never stored, and never printed: `Debug` hides it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceKey(IpAddr);

impl SourceKey {
    pub fn of(ip: IpAddr) -> Self {
        Self(match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None if v6.is_loopback() => IpAddr::V6(v6),
                None => {
                    let mut octets = v6.octets();
                    octets[8..].fill(0);
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
            },
            v4 => v4,
        })
    }

    /// A source on the local network (at the LAN listener and the LAN
    /// beacon, when the caller found it local: raven-node keys a global
    /// IPv6 source from outside this computer's networks by its /64 with
    /// [`SourceKey::of`]): its whole address. Every link-local host shares fe80::/64
    /// and every SLAAC host on a LAN shares that LAN's /64, so the /64 of
    /// [`SourceKey::of`] would let one stranger on the Wi-Fi get every IPv6
    /// neighbour banned with it (Phase 6 review sensing-2). An IPv4-mapped
    /// address still folds to IPv4. A host may dodge its ban by changing its
    /// interface ID; the listeners' per-source and global caps still bound
    /// it.
    pub fn of_local(ip: IpAddr) -> Self {
        Self(match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            },
            v4 => v4,
        })
    }

    /// Another profile on this computer, or a harness ([`PenaltyBox`] never
    /// bans it unless told to).
    pub fn is_loopback(self) -> bool {
        self.0.is_loopback()
    }
}

impl fmt::Debug for SourceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SourceKey(..)")
    }
}

/// What kind of carrier a [`Attribution::Carrier`] names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CarrierRole {
    Custodian,
    Depositor,
    /// Keyed as `SHA-256("rvn1/sec/relay" || PeerId bytes)`
    /// ([`relay_subject`]).
    Relay,
}

/// The key a p2p relay is noted under (`peer_id`: its PeerId's bytes):
/// `SHA-256("rvn1/sec/relay" || peer_id)`, never the PeerId itself.
pub fn relay_subject(peer_id: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"rvn1/sec/relay");
    h.update(peer_id);
    h.finalize().into()
}

/// Who an event is about (design A §1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Attribution {
    /// A network source (memory only, never stored).
    Network { source: SourceKey },
    /// A verified signer: the contact's device key.
    Contact { peer: [u8; 32] },
    /// A custodian, depositor or relay key.
    Carrier {
        carrier: [u8; 32],
        role: CarrierRole,
    },
    /// This computer's own state.
    Local,
    /// A security update (design D): "passed on by", never "blamed".
    Update { passed_by: Option<[u8; 32]> },
}

/// How the object or link that raised the event reached this node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Via {
    /// A link the contact opened to this node.
    DirectLink(OutboxCarrier),
    /// A link this node dialled.
    Dial(OutboxCarrier),
    /// Fetched from this custodian.
    Custodian([u8; 32]),
    /// Through a p2p relay circuit (the Raven link inside still ends at the
    /// contact).
    Relay,
    /// From this computer's own state.
    Local,
}

/// One security event, as a sensing point hands it to [`note`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecEvent {
    pub kind: SecKind,
    pub who: Attribution,
    pub via: Via,
    /// Wall-clock time of the event (the caller's `clock::now_ms`).
    pub at_ms: u64,
    /// The network the link ran on (an egress tag digest), when known.
    pub network: Option<[u8; 8]>,
}

impl SecEvent {
    pub fn new(kind: SecKind, who: Attribution, via: Via, at_ms: u64) -> Self {
        Self {
            kind,
            who,
            via,
            at_ms,
            network: None,
        }
    }

    /// The same event, seen on network `tag`.
    pub fn on_network(self, tag: [u8; 8]) -> Self {
        Self {
            network: Some(tag),
            ..self
        }
    }
}

// ---- Thresholds ----

const MINUTE_MS: u64 = 60_000;
const HOUR_MS: u64 = 60 * MINUTE_MS;
const DAY_MS: u64 = 24 * HOUR_MS;

/// What an escalation rule counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Per {
    /// Events of the kind about the same subject.
    Subject,
    /// Events of the kind on the same network (egress tag), whoever they
    /// are about.
    Network,
}

/// "`at` or more within `within_ms`, counted per `per`".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub at: u32,
    pub within_ms: u64,
    pub per: Per,
}

/// One kind's row: its default severity, when it rises, and its weight as a
/// penalty-box strike (design A R1; 0: not a strike).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Threshold {
    pub base: Severity,
    pub suspicious: Option<Rule>,
    pub alert: Option<Rule>,
    pub strike: u8,
}

const fn row(base: Severity, strike: u8) -> Threshold {
    Threshold {
        base,
        suspicious: None,
        alert: None,
        strike,
    }
}

const fn per_subject(at: u32, within_ms: u64) -> Option<Rule> {
    Some(Rule {
        at,
        within_ms,
        per: Per::Subject,
    })
}

const NOTICE: Threshold = row(Severity::Notice, 0);
const SUSPICIOUS: Threshold = row(Severity::Suspicious, 0);
const ALERT: Threshold = row(Severity::Alert, 0);
/// Suspicious; Alert at 3 per 24 h.
const SUSPICIOUS_ALERT_AT_3: Threshold = Threshold {
    alert: per_subject(3, DAY_MS),
    ..SUSPICIOUS
};

/// The one table (`docs/SECURITY_EVENTS.md`, "Default severity" and the
/// R1 strikes), in code order: a const check below fails the build unless it
/// has exactly one row per kind. Two levels are decided elsewhere:
/// SEC_CAPABILITY_DOWNGRADE's level depends on the feature that went missing
/// (step P6.29), and SEC_RELAY_NO_RECEIPT's "more than half of 10 dials" is a
/// share of dials, not of events (step P6.28).
pub const THRESHOLDS: &[(SecKind, Threshold)] = &[
    (
        SecKind::LinkTagFail,
        Threshold {
            suspicious: per_subject(2, 10 * MINUTE_MS),
            alert: Some(Rule {
                at: 6,
                within_ms: DAY_MS,
                per: Per::Network,
            }),
            ..NOTICE
        },
    ),
    (SecKind::HandshakeFail, row(Severity::Notice, 1)),
    (SecKind::PreauthMalformed, row(Severity::Notice, 2)),
    (SecKind::StrangerRefused, row(Severity::Notice, 1)),
    (SecKind::BlockedRefused, row(Severity::Notice, 1)),
    (SecKind::UnverifiedRemote, NOTICE),
    (SecKind::PreauthFlood, SUSPICIOUS),
    (SecKind::P2pGateRefused, row(Severity::Notice, 1)),
    (SecKind::BeaconReplay, row(Severity::Suspicious, 4)),
    (SecKind::BeaconFlood, NOTICE),
    (SecKind::KnockReplay, row(Severity::Suspicious, 4)),
    (SecKind::ObjectAuthFail, SUSPICIOUS_ALERT_AT_3),
    (SecKind::ObjectSigFail, SUSPICIOUS_ALERT_AT_3),
    (SecKind::ObjectReplay, SUSPICIOUS_ALERT_AT_3),
    (SecKind::IndexJump, NOTICE),
    (SecKind::SessionUnknown, NOTICE),
    (SecKind::BindingMismatch, ALERT),
    (SecKind::RevokedDeviceUsed, ALERT),
    (SecKind::KeyChangeAttempt, ALERT),
    (SecKind::PrekeyRollback, SUSPICIOUS),
    (
        SecKind::AddressImpostor,
        Threshold {
            suspicious: per_subject(3, DAY_MS),
            ..NOTICE
        },
    ),
    (SecKind::CapabilityDowngrade, NOTICE),
    (SecKind::ContactMalformed, NOTICE),
    (SecKind::PairinitFlood, SUSPICIOUS),
    (SecKind::ResetLoop, SUSPICIOUS),
    (SecKind::ClockSkew, NOTICE),
    (SecKind::PairSeedRoot, NOTICE),
    (SecKind::CustodianBadObject, SUSPICIOUS_ALERT_AT_3),
    (SecKind::CustodianUnrequested, SUSPICIOUS),
    (SecKind::CustodianReplay, NOTICE),
    (SecKind::DepositorFlood, NOTICE),
    (SecKind::DepositorBadObject, SUSPICIOUS),
    (SecKind::RelayNoReceipt, NOTICE),
    (SecKind::RelayLinkBroken, SUSPICIOUS),
    (SecKind::LetterBad, SUSPICIOUS),
    (SecKind::HandoffRefused, NOTICE),
    (SecKind::KnockFail, row(Severity::Notice, 1)),
    (SecKind::LocalRollback, ALERT),
    (
        SecKind::UnlockFailed,
        Threshold {
            suspicious: per_subject(5, 10 * MINUTE_MS),
            ..NOTICE
        },
    ),
    (SecKind::AdvisoryForged, SUSPICIOUS),
    (SecKind::AdvisoryRollback, NOTICE),
    (SecKind::AdvisoryEquivocation, ALERT),
    (SecKind::BundleForged, SUSPICIOUS),
    (SecKind::UpdateUnlogged, SUSPICIOUS),
    (SecKind::BundleDowngrade, NOTICE),
    (SecKind::LogSplitView, ALERT),
    // The registry's "informational alert": shown as an alert, about an
    // update this node applied.
    (SecKind::AdvisoryApplied, ALERT),
    (SecKind::UpdateFlood, NOTICE),
];

// One row per kind, in `SecKind::ALL` order; codes strictly rising; every
// rule within what a tally remembers ([`RECENT`]) and above its base.
const _: () = {
    assert!(THRESHOLDS.len() == KINDS);
    assert!(KINDS <= Aggregator::MAX_KINDS);
    let mut i = 0;
    while i < KINDS {
        assert!(THRESHOLDS[i].0 as u16 == SecKind::ALL[i] as u16);
        if i > 0 {
            assert!((SecKind::ALL[i - 1] as u16) < (SecKind::ALL[i] as u16));
        }
        let t = THRESHOLDS[i].1;
        if let Some(r) = t.suspicious {
            assert!(r.at >= 1 && r.at as usize <= RECENT && r.within_ms > 0);
            assert!(matches!(t.base, Severity::Notice));
        }
        if let Some(r) = t.alert {
            assert!(r.at >= 1 && r.at as usize <= RECENT && r.within_ms > 0);
            assert!(!matches!(t.base, Severity::Alert));
        }
        i += 1;
    }
};

/// `kind`'s row in [`THRESHOLDS`].
pub fn threshold(kind: SecKind) -> Threshold {
    match THRESHOLDS.binary_search_by_key(&kind.code(), |(k, _)| k.code()) {
        Ok(i) => THRESHOLDS[i].1,
        // The const check above puts every kind in the table.
        Err(_) => unreachable!("THRESHOLDS has a row for every kind"),
    }
}

/// `kind`'s weight as a penalty-box strike (design A R1).
pub fn strike_weight(kind: SecKind) -> u32 {
    u32::from(threshold(kind).strike)
}

/// A pre-auth connection refused at the listener's own cap is one strike
/// too (design A R1); it has no event kind of its own.
pub const CAP_REFUSAL_STRIKE: u32 = 1;

// ---- Aggregator ----

/// How many recent event times one tally keeps (the largest rule count in
/// [`THRESHOLDS`] fits).
pub const RECENT: usize = 8;

/// What a [`Tally`] is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Subject {
    /// A network source.
    Source(SourceKey),
    /// A contact, carrier, or update passer key.
    Key([u8; 32]),
    /// A network (egress tag digest), for the per-network rules.
    Network([u8; 8]),
    Local,
    /// An update nobody passed on (fetched directly).
    Update,
}

impl Subject {
    pub fn of(who: &Attribution) -> Self {
        match *who {
            Attribution::Network { source } => Subject::Source(source),
            Attribution::Contact { peer } => Subject::Key(peer),
            Attribution::Carrier { carrier, .. } => Subject::Key(carrier),
            Attribution::Local => Subject::Local,
            Attribution::Update {
                passed_by: Some(key),
            } => Subject::Key(key),
            Attribution::Update { passed_by: None } => Subject::Update,
        }
    }
}

/// The events of one kind about one subject: how many, the first and last
/// times, and the last [`RECENT`] times for the windowed rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tally {
    pub count: u64,
    pub first_ms: u64,
    pub last_ms: u64,
    recent: [u64; RECENT],
}

impl Tally {
    fn new(at_ms: u64) -> Self {
        Self {
            count: 0,
            first_ms: at_ms,
            last_ms: at_ms,
            recent: [0; RECENT],
        }
    }

    fn push(&mut self, at_ms: u64) {
        self.recent[(self.count % RECENT as u64) as usize] = at_ms;
        self.count = self.count.saturating_add(1);
        self.first_ms = self.first_ms.min(at_ms);
        self.last_ms = self.last_ms.max(at_ms);
    }

    /// How many of the remembered events fall within the `window_ms` before
    /// `now_ms` (an event dated after `now_ms` counts as within).
    pub fn within(&self, window_ms: u64, now_ms: u64) -> u32 {
        let kept = self.count.min(RECENT as u64) as usize;
        self.recent[..kept]
            .iter()
            .filter(|&&t| now_ms.saturating_sub(t) < window_ms)
            .count() as u32
    }
}

/// A small least-recently-used map: at most `cap` entries; making room drops
/// the entry touched longest ago. O(log n) per touch.
#[derive(Debug)]
struct Lru<K, V> {
    cap: usize,
    tick: u64,
    map: HashMap<K, (u64, V)>,
    order: BTreeMap<u64, K>,
}

impl<K: Copy + Eq + Hash, V> Lru<K, V> {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            tick: 0,
            map: HashMap::new(),
            order: BTreeMap::new(),
        }
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn peek(&self, key: &K) -> Option<&V> {
        self.map.get(key).map(|(_, v)| v)
    }

    /// The entry for `key`, created with `fresh` (dropping the least
    /// recently touched one when full), now the most recently touched.
    fn touch(&mut self, key: K, fresh: impl FnOnce() -> V) -> &mut V {
        self.tick += 1;
        let tick = self.tick;
        match self.map.get(&key) {
            Some(&(old, _)) => {
                self.order.remove(&old);
            }
            None => {
                if self.map.len() >= self.cap {
                    if let Some((_, oldest)) = self.order.pop_first() {
                        self.map.remove(&oldest);
                    }
                }
            }
        }
        self.order.insert(tick, key);
        let slot = self.map.entry(key).or_insert_with(|| (tick, fresh()));
        slot.0 = tick;
        &mut slot.1
    }

    /// [`Self::touch`] without creating: None when `key` is not held.
    fn touch_existing(&mut self, key: &K) -> Option<&mut V> {
        if self.map.contains_key(key) {
            Some(self.touch(*key, || unreachable!("held")))
        } else {
            None
        }
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        let (tick, value) = self.map.remove(key)?;
        self.order.remove(&tick);
        Some(value)
    }

    fn values(&self) -> impl Iterator<Item = &V> {
        self.map.values().map(|(_, v)| v)
    }

    fn retain(&mut self, mut keep: impl FnMut(&V) -> bool) {
        let order = &mut self.order;
        self.map.retain(|_, (tick, v)| {
            let kept = keep(v);
            if !kept {
                order.remove(tick);
            }
            kept
        });
    }
}

/// Counts events per kind and subject, in memory only (design A §1, §6):
/// at most [`Self::MAX_KINDS`] kinds x [`Self::MAX_SUBJECTS`] subjects; a
/// new subject in a full kind drops the one noted longest ago. The per-kind
/// totals never drop.
#[derive(Debug)]
pub struct Aggregator {
    kinds: HashMap<SecKind, Lru<Subject, Tally>>,
    totals: HashMap<SecKind, u64>,
}

impl Default for Aggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl Aggregator {
    pub const MAX_KINDS: usize = 64;
    pub const MAX_SUBJECTS: usize = 1_024;

    pub fn new() -> Self {
        Self {
            kinds: HashMap::new(),
            totals: HashMap::new(),
        }
    }

    fn bump(&mut self, kind: SecKind, subject: Subject, at_ms: u64) -> Tally {
        let tally = self
            .kinds
            .entry(kind)
            .or_insert_with(|| Lru::new(Self::MAX_SUBJECTS))
            .touch(subject, || Tally::new(at_ms));
        tally.push(at_ms);
        *tally
    }

    /// Count `ev` and return the severity of this occurrence: the kind's
    /// base, raised by its rules ([`THRESHOLDS`]).
    pub fn record(&mut self, ev: &SecEvent) -> Severity {
        let row = threshold(ev.kind);
        let by_subject = self.bump(ev.kind, Subject::of(&ev.who), ev.at_ms);
        let network_rule = [row.suspicious, row.alert]
            .iter()
            .flatten()
            .any(|r| r.per == Per::Network);
        let by_network = match ev.network {
            Some(tag) if network_rule => Some(self.bump(ev.kind, Subject::Network(tag), ev.at_ms)),
            _ => None,
        };
        let total = self.totals.entry(ev.kind).or_default();
        *total = total.saturating_add(1);
        let mut severity = row.base;
        for (rule, level) in [
            (row.suspicious, Severity::Suspicious),
            (row.alert, Severity::Alert),
        ] {
            let Some(rule) = rule else { continue };
            let tally = match rule.per {
                Per::Subject => Some(&by_subject),
                Per::Network => by_network.as_ref(),
            };
            if tally.is_some_and(|t| t.within(rule.within_ms, ev.at_ms) >= rule.at) {
                severity = severity.max(level);
            }
        }
        severity
    }

    /// The tally of `kind` about `subject`, if still held.
    pub fn tally(&self, kind: SecKind, subject: &Subject) -> Option<Tally> {
        self.kinds.get(&kind)?.peek(subject).copied()
    }

    /// How many of `kind` about `subject` in the `window_ms` before `now_ms`
    /// (up to [`RECENT`]).
    pub fn count_within(
        &self,
        kind: SecKind,
        subject: &Subject,
        window_ms: u64,
        now_ms: u64,
    ) -> u32 {
        self.tally(kind, subject)
            .map_or(0, |t| t.within(window_ms, now_ms))
    }

    /// How many subjects of `kind` are held.
    pub fn subjects(&self, kind: SecKind) -> usize {
        self.kinds.get(&kind).map_or(0, Lru::len)
    }

    /// Every event of `kind` noted since start (evictions included).
    pub fn total(&self, kind: SecKind) -> u64 {
        self.totals.get(&kind).copied().unwrap_or(0)
    }

    /// The non-zero totals, in code order (the node's memory-only counts for
    /// `Status`).
    pub fn totals(&self) -> Vec<(SecKind, u64)> {
        SecKind::ALL
            .iter()
            .map(|&k| (k, self.total(k)))
            .filter(|&(_, n)| n > 0)
            .collect()
    }
}

// ---- The process-wide entry point ----

/// Where live events go after the aggregator (raven-node: a bounded queue to
/// the ledger writer; ash: a direct best-effort ledger write).
pub trait SecSink: Send + Sync {
    /// One live event and the severity [`Aggregator::record`] gave it.
    /// Called on the thread that noted it: return quickly, never block.
    fn accept(&self, ev: &SecEvent, severity: Severity);
}

static AGGREGATOR: OnceLock<Mutex<Aggregator>> = OnceLock::new();
static SINK: RwLock<Option<Arc<dyn SecSink>>> = RwLock::new(None);

fn aggregator() -> &'static Mutex<Aggregator> {
    AGGREGATOR.get_or_init(|| Mutex::new(Aggregator::new()))
}

/// Note one event: count it and pass it to the sink. Returns at once, with
/// nothing counted or passed on, while [`SecGate::Events`] is shut.
pub fn note(ev: SecEvent) {
    note_at_least(ev, Severity::Notice);
}

/// [`note`], with this occurrence's severity raised to at least `floor`:
/// for a level a share of dials decides, not a count of events
/// (SEC_RELAY_NO_RECEIPT's "more than half of 10 dials", step P6.28).
pub fn note_at_least(ev: SecEvent, floor: Severity) {
    if !security_gate::live(SecGate::Events) {
        return;
    }
    let severity = aggregator()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .record(&ev)
        .max(floor);
    let sink = SINK.read().unwrap_or_else(PoisonError::into_inner).clone();
    if let Some(sink) = sink {
        sink.accept(&ev, severity);
    }
}

/// Register the process's sink (replacing any earlier one).
pub fn set_sink(sink: Box<dyn SecSink>) {
    *SINK.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::from(sink));
}

/// Drop the registered sink: later events are only counted.
pub fn clear_sink() {
    *SINK.write().unwrap_or_else(PoisonError::into_inner) = None;
}

/// Read the process-wide aggregator (responses, `Status`).
pub fn with_aggregator<R>(f: impl FnOnce(&Aggregator) -> R) -> R {
    f(&aggregator().lock().unwrap_or_else(PoisonError::into_inner))
}

// ---- Penalty box (design A R1, OD6b-4) ----

/// Strikes count within this window from the first one.
pub const PENALTY_WINDOW: Duration = Duration::from_secs(60);
/// This many strikes in one window ban the source.
pub const PENALTY_BAN_AT: u32 = 16;
/// The first ban; each further one doubles, up to [`PENALTY_MAX_BAN`].
pub const PENALTY_FIRST_BAN: Duration = Duration::from_secs(60);
pub const PENALTY_MAX_BAN: Duration = Duration::from_secs(60 * 60);
/// A source with no strike for this long after its last strike and its last
/// ban is forgotten (its next ban is a first one again).
pub const PENALTY_FORGET: Duration = Duration::from_secs(10 * 60);
/// A banned source still gets one probation connection this often.
pub const PENALTY_PROBATION: Duration = Duration::from_secs(10);
/// Sources held at most; the least recently seen one is dropped.
pub const PENALTY_MAX_KEYS: usize = 4_096;

/// The `nth` ban's length (1-based): 60 s doubling, at most 1 h.
pub fn ban_length(nth: u32) -> Duration {
    let doublings = nth.saturating_sub(1).min(16);
    PENALTY_FIRST_BAN
        .saturating_mul(1 << doublings)
        .min(PENALTY_MAX_BAN)
}

/// What one strike did ([`PenaltyBox::strike`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Not counted: an exempt (loopback) source, or a weight of zero.
    Exempt,
    /// Counted: the strikes in the current window, below the ban.
    Counted(u32),
    /// This strike banned the source for this long (note
    /// SEC_PREAUTH_FLOOD once per ban).
    Banned(Duration),
    /// The source is banned already: the strike only keeps it remembered.
    StillBanned,
}

/// What a listener does with a new connection from a source
/// ([`PenaltyBox::admit`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    Allow,
    /// Banned, but this is the one probation connection of its 10 s: a
    /// contact that authenticates on it clears the source.
    Probation,
    Deny,
}

#[derive(Clone, Copy, Debug)]
struct Penalty {
    window_start: Instant,
    strikes: u32,
    last_strike: Instant,
    bans: u32,
    banned_until: Option<Instant>,
    last_probation: Option<Instant>,
}

impl Penalty {
    fn fresh(now: Instant) -> Self {
        Self {
            window_start: now,
            strikes: 0,
            last_strike: now,
            bans: 0,
            banned_until: None,
            last_probation: None,
        }
    }

    fn banned(&self, now: Instant) -> bool {
        self.banned_until.is_some_and(|until| now < until)
    }

    fn forgotten(&self, now: Instant) -> bool {
        let quiet_since = self
            .banned_until
            .map_or(self.last_strike, |until| until.max(self.last_strike));
        now.saturating_duration_since(quiet_since) >= PENALTY_FORGET
    }
}

/// Strangers' strikes and bans, per network source (design A R1): memory
/// only, at most [`PENALTY_MAX_KEYS`] sources. The caller passes `now` (a
/// monotonic `Instant`), so tests run on a fake clock.
#[derive(Debug)]
pub struct PenaltyBox {
    keys: Lru<SourceKey, Penalty>,
    exempt_loopback: bool,
}

impl Default for PenaltyBox {
    fn default() -> Self {
        Self::new()
    }
}

impl PenaltyBox {
    /// A box that never bans loopback (other local profiles, every harness).
    pub fn new() -> Self {
        Self::with_loopback_exempt(true)
    }

    /// `exempt == false` bans loopback like any source (the debug lab switch
    /// of step P6.26).
    pub fn with_loopback_exempt(exempt: bool) -> Self {
        Self {
            keys: Lru::new(PENALTY_MAX_KEYS),
            exempt_loopback: exempt,
        }
    }

    fn exempt(&self, key: SourceKey) -> bool {
        self.exempt_loopback && key.is_loopback()
    }

    /// Count a strike of `weight` against `key`.
    pub fn strike(&mut self, key: SourceKey, weight: u32, now: Instant) -> Verdict {
        if weight == 0 || self.exempt(key) {
            return Verdict::Exempt;
        }
        let p = self.keys.touch(key, || Penalty::fresh(now));
        if p.forgotten(now) {
            *p = Penalty::fresh(now);
        }
        if p.banned(now) {
            p.last_strike = now;
            return Verdict::StillBanned;
        }
        if now.saturating_duration_since(p.window_start) >= PENALTY_WINDOW {
            p.window_start = now;
            p.strikes = 0;
        }
        p.strikes = p.strikes.saturating_add(weight);
        p.last_strike = now;
        if p.strikes < PENALTY_BAN_AT {
            return Verdict::Counted(p.strikes);
        }
        p.bans = p.bans.saturating_add(1);
        let ban = ban_length(p.bans);
        p.banned_until = Some(now.checked_add(ban).unwrap_or(now));
        p.window_start = now;
        p.strikes = 0;
        p.last_probation = None;
        Verdict::Banned(ban)
    }

    /// May a new connection from `key` go on?
    pub fn admit(&mut self, key: SourceKey, now: Instant) -> Admit {
        if self.exempt(key) {
            return Admit::Allow;
        }
        let forgotten = match self.keys.touch_existing(&key) {
            None => return Admit::Allow,
            Some(p) => p.forgotten(now),
        };
        if forgotten {
            self.keys.remove(&key);
            return Admit::Allow;
        }
        let Some(p) = self.keys.touch_existing(&key) else {
            return Admit::Allow;
        };
        if !p.banned(now) {
            return Admit::Allow;
        }
        if p.last_probation
            .is_some_and(|t| now.saturating_duration_since(t) < PENALTY_PROBATION)
        {
            return Admit::Deny;
        }
        p.last_probation = Some(now);
        Admit::Probation
    }

    /// Is `key` banned at `now`? Only looks: no probation is used, nothing
    /// is touched (the LAN beacon's answerer, which answers no banned source
    /// at all, asks this).
    pub fn is_banned(&self, key: SourceKey, now: Instant) -> bool {
        !self.exempt(key) && self.keys.peek(&key).is_some_and(|p| p.banned(now))
    }

    /// A connection from `key` authenticated as a contact: forget the source
    /// (a friend behind the same address gets through; so does the attacker,
    /// who needs another [`PENALTY_BAN_AT`] strikes).
    pub fn authenticated(&mut self, key: SourceKey) {
        self.keys.remove(&key);
    }

    /// Sources banned at `now`.
    pub fn bans_active(&self, now: Instant) -> usize {
        self.keys.values().filter(|p| p.banned(now)).count()
    }

    /// Sources held.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.len() == 0
    }

    /// Drop every source that is forgotten at `now`.
    pub fn prune(&mut self, now: Instant) {
        self.keys.retain(|p| !p.forgotten(now));
    }
}

// ---- Classifiers ----

/// A Noise transport tag failure on an established link (S1). The text of
/// [`crate::lan_noise::LanNoiseError::Transport`], so a decrypt site that
/// returns this constant logs what it logged before (step P6.24 points
/// raven-node's decrypt sites at it).
pub const LINK_TAG_FAILED: &str = "noise transport failed";
/// [`crate::lan_noise::LanNoiseError::Handshake`]: a Noise handshake message
/// that does not parse (S2).
pub const NOISE_HANDSHAKE_FAILED: &str = "noise handshake failed";
/// [`crate::lan_noise::LanNoiseError::BindTruncated`].
pub const BIND_TRUNCATED: &str = "identity bind missing or truncated";
/// [`crate::lan_noise::LanNoiseError::BindBadSignature`].
pub const BIND_BAD_SIGNATURE: &str = "identity bind signature invalid";
/// raven-node `lan_direct`'s handshake deadline.
pub const LAN_HANDSHAKE_TIMEOUT: &str = "lan handshake deadline exceeded";
/// raven-node `internet_direct`'s handshake deadline.
pub const INTERNET_HANDSHAKE_TIMEOUT: &str = "internet handshake deadline exceeded";
/// raven-node `lan_direct`: a frame length of zero or over one Noise message.
pub const LAN_FRAME_LENGTH: &str = "lan frame length";
/// raven-node `internet_direct`: the same for Internet direct.
pub const INTERNET_FRAME_LENGTH: &str = "internet frame length";

/// The kind of a link error text: exact matches on the exported texts only
/// (the listener refusals of `lan_dispatch`, the handshake deadlines and
/// Noise handshake failures, the tag failure, the frame-length refusals);
/// any other text is None, among them `LINK_REFUSED_NOT_READY` (a book held
/// while its key loads judged nobody, E1). The caller adds what the text
/// cannot say: before authentication every kind here is about a network
/// source (a tag failure while the handshake is still running is pre-auth
/// garbage).
pub fn classify_link_error(text: &str) -> Option<SecKind> {
    match text {
        LINK_REFUSED_NOT_CONTACT => Some(SecKind::StrangerRefused),
        LINK_REFUSED_BLOCKED => Some(SecKind::BlockedRefused),
        LINK_REFUSED_NOT_VERIFIED | LINK_REFUSED_VERIFIED_ONLY => Some(SecKind::UnverifiedRemote),
        LAN_HANDSHAKE_TIMEOUT | INTERNET_HANDSHAKE_TIMEOUT | NOISE_HANDSHAKE_FAILED => {
            Some(SecKind::HandshakeFail)
        }
        LAN_FRAME_LENGTH | INTERNET_FRAME_LENGTH | BIND_TRUNCATED | BIND_BAD_SIGNATURE => {
            Some(SecKind::PreauthMalformed)
        }
        LINK_TAG_FAILED => Some(SecKind::LinkTagFail),
        _ => None,
    }
}

/// [`classify_store_error_at`] when the caller cannot tell what the refused
/// envelope said about the sender's clock (`EndpointNotCurrentlyValid` is
/// then not an event).
pub fn classify_store_error(e: &IndexedSessionStoreError, via: Via) -> Option<SecKind> {
    classify_store_error_at(e, via, None)
}

/// The kind of a session-store refusal (S6-S11, S23, S24). `via` decides two
/// rows: an outer signature that fails on an object a custodian served is
/// the custodian's (SEC_CUSTODIAN_BAD_OBJECT), and a receive-index replay a
/// custodian served is a re-served object (SEC_CUSTODIAN_REPLAY); on a link
/// both are the contact's. `clock` is what the refused envelope said about
/// the sender's clock ([`crate::clock_skew`]): `EndpointNotCurrentlyValid` is
/// SEC_CLOCK_SKEW only for an envelope dated in our future.
pub fn classify_store_error_at(
    e: &IndexedSessionStoreError,
    via: Via,
    clock: Option<PeerClock>,
) -> Option<SecKind> {
    use IndexedSessionStoreError as E;
    match e {
        E::AuthenticationFailed => Some(SecKind::ObjectAuthFail),
        E::OuterSignatureInvalid => match via {
            Via::Custodian(_) => Some(SecKind::CustodianBadObject),
            Via::DirectLink(_) | Via::Dial(_) | Via::Relay => Some(SecKind::ObjectSigFail),
            Via::Local => None,
        },
        E::Replay => match via {
            Via::Custodian(_) => Some(SecKind::CustodianReplay),
            Via::DirectLink(_) | Via::Dial(_) | Via::Relay | Via::Local => {
                Some(SecKind::ObjectReplay)
            }
        },
        E::LogicalMessageConflict | E::AckNonceConflict => Some(SecKind::ObjectReplay),
        E::ForwardJumpTooLarge => Some(SecKind::IndexJump),
        E::RouteTagMismatch => Some(SecKind::SessionUnknown),
        E::DeviceBindingMismatch | E::InvalidDeviceCertificate => Some(SecKind::BindingMismatch),
        E::RevokedDevice => Some(SecKind::RevokedDeviceUsed),
        E::RollbackDetected | E::LocalInboxAuthenticationFailed => Some(SecKind::LocalRollback),
        E::EndpointNotCurrentlyValid => match clock {
            Some(PeerClock::Ahead(_)) => Some(SecKind::ClockSkew),
            Some(PeerClock::Agrees) | None => None,
        },
        // Storage, locks and keys; this node's own outbound side; objects
        // no verified signature vouches for, or that only disagree with
        // local bookkeeping; a deferral; a retired session; a session a
        // security notice holds (P6.45: this node's own refusal).
        E::Sqlite(_)
        | E::ProtectedStore(_)
        | E::ProtectedStateMissing
        | E::CorruptProtectedState
        | E::NotFound
        | E::UnsupportedProfile
        | E::InvalidBinding
        | E::InitIdConflict
        | E::BindingConflict
        | E::ConfirmationConflict
        | E::SessionNotConfirmed
        | E::IndexExhausted
        | E::InvalidEndpointEnvelope
        | E::EndpointTypeMismatch
        | E::InvalidIndexedMessage
        | E::DeviceHintMismatch
        | E::InvalidEndpointPayload
        | E::LocalDeviceUnauthorized
        | E::LocalDeviceBindingMismatch
        | E::LocalSignerFailure
        | E::EndpointRandomnessUnavailable
        | E::OutboundPending
        | E::OutboundCollision
        | E::OutboundQueueHandoff
        | E::OutboundBindingMismatch
        | E::CorruptEndpointState
        | E::AckBytesConflict
        | E::AckEnqueue
        | E::AckOutstandingMismatch
        | E::AckTimestampMismatch
        | E::AckInnerSignatureInvalid
        | E::PairInit(_)
        | E::UnsupportedMetadataSchema(_)
        | E::MetaKeyUnavailable(_)
        | E::MetadataMigration(_)
        | E::SessionRetired
        | E::ApplicationDeferred
        | E::SuiteHeld => None,
        #[cfg(test)]
        E::InjectedCrashAfterProtectedWrite | E::InjectedEndpointFailure(_) => None,
    }
}

/// The kind of a relayed-ingest outcome (S7, S18, S24) as far as the outcome
/// alone tells it: junk a custodian served that fails before the contact's
/// signature is the custodian's, and an object dated in our future is clock
/// skew. `CUSTODY_REFUSED` is None here: it covers both pre-signature shape
/// refusals and store refusals after a valid signature (the contact's), so
/// the store error's own [`classify_store_error`] with [`Via::Custodian`]
/// names those (step P6.25).
pub fn classify_relayed(o: &RelayedOutcome) -> Option<SecKind> {
    match o {
        RelayedOutcome::MessageAccepted { .. } | RelayedOutcome::AckAccepted { .. } => None,
        RelayedOutcome::Refused(code) => match *code {
            "CUSTODY_MALFORMED" | "OUTER_SIGNATURE_INVALID" => Some(SecKind::CustodianBadObject),
            _ => None,
        },
        RelayedOutcome::Retry(_, code) => (*code == "CLOCK").then_some(SecKind::ClockSkew),
    }
}

/// Which end of a custody exchange this node is ([`classify_custody_code`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// This node is the custodian: it answered the code to a depositor
    /// (or a forwarder).
    Custodian,
    /// This node deposited or asked for a forward, and the custodian
    /// answered the code.
    Depositor,
}

/// The kind of a custody reply code (S19, S20). As the custodian: a
/// depositor over its rate or quota, or sending refused or malformed
/// objects, and a forward it had no right to ask. As the depositor: a
/// forward of this node's own signed object refused.
pub fn classify_custody_code(code: CustodyCode, side: Side) -> Option<SecKind> {
    use CustodyCode as C;
    match side {
        Side::Custodian => match code {
            C::RateLimited | C::Quota => Some(SecKind::DepositorFlood),
            C::RefusedObject | C::Malformed => Some(SecKind::DepositorBadObject),
            C::HopRefused => Some(SecKind::HandoffRefused),
            C::Ok
            | C::Duplicate
            | C::PolicyDenied
            | C::Hold
            | C::NotVerified
            | C::Expired
            | C::StoreFull
            | C::Persistence
            | C::RecipientNotAccepted
            | C::Conflict
            | C::NextHopUnknown
            | C::TagUnknown => None,
        },
        Side::Depositor => match code {
            C::HopRefused => Some(SecKind::HandoffRefused),
            C::Ok
            | C::Duplicate
            | C::PolicyDenied
            | C::Hold
            | C::NotVerified
            | C::RefusedObject
            | C::Expired
            | C::StoreFull
            | C::Quota
            | C::RateLimited
            | C::Persistence
            | C::Malformed
            | C::RecipientNotAccepted
            | C::Conflict
            | C::NextHopUnknown
            | C::TagUnknown => None,
        },
    }
}

/// The kind of a prekey-lifecycle refusal of a contact's PairInit (S16,
/// S24): the per-initiator claim quota is a PairInit flood, a PairInit dated
/// past the skew window is clock skew.
pub fn classify_prekey_error(e: &PrekeyLifecycleError) -> Option<SecKind> {
    use PrekeyLifecycleError as E;
    match e {
        E::ResourceLimit => Some(SecKind::PairinitFlood),
        E::PairInitClockSkew => Some(SecKind::ClockSkew),
        E::ProtectedStoreUnavailable
        | E::ProtectedStore
        | E::CorruptProtectedState
        | E::LockFailed
        | E::Database
        | E::InvalidGeneration
        | E::NonMonotonicSignedPrekeyId
        | E::ActorLineageMismatch
        | E::PairInit(_)
        | E::PairInitLifetime
        | E::PairInitOutsideGrace
        | E::UnknownPrekey
        | E::InitIdConflict
        | E::ClaimNotFound
        | E::ClaimBindingMismatch
        | E::ClaimHandoffExpired
        | E::NonContributoryWrapKey => None,
        #[cfg(test)]
        E::InjectedCrash(_) => None,
    }
}

/// The kind of an at-rest refusal (design C sensing point C1): sealed bytes
/// that fail authentication, name the wrong kind or are cut short were
/// changed outside Raven (SEC_LOCAL_ROLLBACK). A missing or not yet loaded
/// key, a newer format, a stale epoch (retried by the caller) and plain I/O
/// are not events.
pub fn classify_at_rest_error(e: &AtRestError) -> Option<SecKind> {
    match e {
        AtRestError::Tampered { .. } | AtRestError::WrongKind { .. } | AtRestError::Truncated => {
            Some(SecKind::LocalRollback)
        }
        AtRestError::KeyUnavailable(_)
        | AtRestError::KeyLost(_)
        | AtRestError::NoIdentity
        | AtRestError::NewerFormat(_)
        | AtRestError::StaleKeys { .. }
        | AtRestError::NotSealedMode
        | AtRestError::Io(_)
        | AtRestError::Json(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan_noise::LanNoiseError;
    use crate::pair_init::PairInitError;
    use crate::relayed_ingest::RetryScope;
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ip(s: &str) -> SourceKey {
        SourceKey::of(s.parse().unwrap())
    }

    fn contact(peer: [u8; 32]) -> Attribution {
        Attribution::Contact { peer }
    }

    fn ev(kind: SecKind, who: Attribution, at_ms: u64) -> SecEvent {
        SecEvent::new(kind, who, Via::DirectLink(OutboxCarrier::Lan), at_ms)
    }

    fn crate_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    // ---- kinds and the registry ----

    #[test]
    fn codes_round_trip_and_names_are_unique() {
        let mut names = HashSet::new();
        for k in SecKind::ALL {
            assert_eq!(SecKind::from_code(k.code()), Some(k));
            assert!(k.name().starts_with("SEC_"), "{k:?}");
            assert!(names.insert(k.name()), "{k:?}");
        }
        let assigned: Vec<u16> = (0..=u16::MAX)
            .filter(|&c| SecKind::from_code(c).is_some())
            .collect();
        assert_eq!(assigned.len(), KINDS);
        for unassigned in [0, 12, 19, 36, 39, 50, 59, 62, 69, 79, 80, 92, u16::MAX] {
            assert_eq!(SecKind::from_code(unassigned), None, "{unassigned}");
        }
    }

    /// The registry table in docs/SECURITY_EVENTS.md and [`SecKind`] list the
    /// same codes and names, and each row's default severity is the base in
    /// [`THRESHOLDS`].
    #[test]
    fn kinds_match_the_registry_document() {
        let path = crate_dir().join("../../../docs/SECURITY_EVENTS.md");
        let text =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let mut seen = Vec::new();
        for line in text.lines() {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            // "| code | SEC_NAME (note) | attribution | severity | ..."
            if cells.len() < 5 || !cells[2].starts_with("SEC_") {
                continue;
            }
            let Ok(code) = cells[1].parse::<u16>() else {
                continue;
            };
            let name = cells[2].split_whitespace().next().unwrap();
            let kind = SecKind::from_code(code)
                .unwrap_or_else(|| panic!("registry code {code} has no SecKind"));
            assert_eq!(kind.name(), name, "code {code}");
            let first = cells[4]
                .split(|c: char| !c.is_ascii_alphabetic())
                .next()
                .unwrap();
            let base = match first {
                "Notice" => Severity::Notice,
                "Suspicious" => Severity::Suspicious,
                "Alert" | "informational" => Severity::Alert,
                other => panic!("code {code}: severity {other:?}"),
            };
            assert_eq!(threshold(kind).base, base, "{name}");
            seen.push(kind);
        }
        assert_eq!(seen, SecKind::ALL.to_vec(), "registry rows, in code order");
    }

    #[test]
    fn thresholds_cover_every_kind_once() {
        assert_eq!(THRESHOLDS.len(), KINDS);
        for (i, k) in SecKind::ALL.iter().enumerate() {
            assert_eq!(THRESHOLDS[i].0, *k);
            assert_eq!(threshold(*k), THRESHOLDS[i].1);
        }
        // The named rows.
        let t = threshold(SecKind::LinkTagFail);
        assert_eq!(t.base, Severity::Notice);
        assert_eq!(t.suspicious, per_subject(2, 10 * MINUTE_MS));
        assert_eq!(
            t.alert.map(|r| (r.at, r.within_ms, r.per)),
            Some((6, DAY_MS, Per::Network))
        );
        for k in [
            SecKind::ObjectAuthFail,
            SecKind::ObjectSigFail,
            SecKind::ObjectReplay,
            SecKind::CustodianBadObject,
        ] {
            assert_eq!(threshold(k), SUSPICIOUS_ALERT_AT_3, "{k:?}");
        }
        for k in [
            SecKind::BindingMismatch,
            SecKind::RevokedDeviceUsed,
            SecKind::KeyChangeAttempt,
            SecKind::LocalRollback,
        ] {
            assert_eq!(threshold(k).base, Severity::Alert, "{k:?}");
        }
        // R1 strikes: handshake 1, malformed 2, refusals 1, p2p gate 1,
        // beacon or knock replay 4, radio knock failure 1; nothing else.
        let strikes: Vec<(SecKind, u32)> = SecKind::ALL
            .iter()
            .map(|&k| (k, strike_weight(k)))
            .filter(|&(_, w)| w > 0)
            .collect();
        assert_eq!(
            strikes,
            vec![
                (SecKind::HandshakeFail, 1),
                (SecKind::PreauthMalformed, 2),
                (SecKind::StrangerRefused, 1),
                (SecKind::BlockedRefused, 1),
                (SecKind::P2pGateRefused, 1),
                (SecKind::BeaconReplay, 4),
                (SecKind::KnockReplay, 4),
                (SecKind::KnockFail, 1),
            ]
        );
        assert_eq!(CAP_REFUSAL_STRIKE, 1);
    }

    // ---- aggregator ----

    #[test]
    fn severity_rises_with_the_rules() {
        let mut agg = Aggregator::new();
        let a = contact([1; 32]);
        let t0 = 1_800_000_000_000;
        // Suspicious; Alert at 3 per 24 h, per contact.
        assert_eq!(
            agg.record(&ev(SecKind::ObjectAuthFail, a, t0)),
            Severity::Suspicious
        );
        assert_eq!(
            agg.record(&ev(SecKind::ObjectAuthFail, a, t0 + 1)),
            Severity::Suspicious
        );
        assert_eq!(
            agg.record(&ev(SecKind::ObjectAuthFail, contact([2; 32]), t0 + 2)),
            Severity::Suspicious,
            "another contact's count is its own"
        );
        assert_eq!(
            agg.record(&ev(SecKind::ObjectAuthFail, a, t0 + 3)),
            Severity::Alert
        );
        // Out of the window: the first two no longer count.
        let later = t0 + DAY_MS + 2;
        assert_eq!(
            agg.record(&ev(SecKind::ObjectAuthFail, a, later)),
            Severity::Suspicious
        );
        assert_eq!(
            agg.tally(SecKind::ObjectAuthFail, &Subject::Key([1; 32]))
                .unwrap()
                .count,
            4
        );

        // Link tag: Suspicious at 2 per contact per 10 min; Alert at 6 per
        // 24 h on one network, across contacts.
        let net = [7; 8];
        let tag =
            |peer: u8, at: u64| ev(SecKind::LinkTagFail, contact([peer; 32]), at).on_network(net);
        assert_eq!(agg.record(&tag(1, t0)), Severity::Notice);
        assert_eq!(
            agg.record(&tag(1, t0 + 10 * MINUTE_MS)),
            Severity::Notice,
            "10 min apart"
        );
        assert_eq!(
            agg.record(&tag(1, t0 + 11 * MINUTE_MS)),
            Severity::Suspicious
        );
        assert_eq!(agg.record(&tag(2, t0 + HOUR_MS)), Severity::Notice);
        assert_eq!(agg.record(&tag(3, t0 + 2 * HOUR_MS)), Severity::Notice);
        assert_eq!(
            agg.record(&tag(4, t0 + 3 * HOUR_MS)),
            Severity::Alert,
            "sixth on one network"
        );
        // Without a network the network rule cannot fire.
        let mut quiet = Aggregator::new();
        for i in 0..8u8 {
            let s = quiet.record(&ev(SecKind::LinkTagFail, contact([i; 32]), t0));
            assert_eq!(s, Severity::Notice);
        }
        assert_eq!(quiet.subjects(SecKind::LinkTagFail), 8);

        // Alert at 1 stays Alert; a plain Notice stays Notice.
        assert_eq!(
            agg.record(&ev(SecKind::BindingMismatch, a, t0)),
            Severity::Alert
        );
        for i in 0..20 {
            assert_eq!(
                agg.record(&ev(SecKind::IndexJump, a, t0 + i)),
                Severity::Notice
            );
        }
        assert_eq!(
            agg.count_within(SecKind::IndexJump, &Subject::Key([1; 32]), HOUR_MS, t0 + 20),
            RECENT as u32
        );
        assert_eq!(agg.total(SecKind::IndexJump), 20);
    }

    #[test]
    fn aggregator_is_bounded_and_drops_the_oldest_subject() {
        let mut agg = Aggregator::new();
        let t0 = 1_000_000;
        let key = |i: u32| {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_be_bytes());
            k
        };
        for i in 0..Aggregator::MAX_SUBJECTS as u32 {
            agg.record(&ev(SecKind::ClockSkew, contact(key(i)), t0 + u64::from(i)));
        }
        assert_eq!(agg.subjects(SecKind::ClockSkew), Aggregator::MAX_SUBJECTS);
        // Note subject 0 again: subject 1 is now the oldest.
        agg.record(&ev(SecKind::ClockSkew, contact(key(0)), t0 + 5_000));
        agg.record(&ev(SecKind::ClockSkew, contact(key(5_000)), t0 + 5_001));
        assert_eq!(agg.subjects(SecKind::ClockSkew), Aggregator::MAX_SUBJECTS);
        assert!(agg
            .tally(SecKind::ClockSkew, &Subject::Key(key(0)))
            .is_some());
        assert!(agg
            .tally(SecKind::ClockSkew, &Subject::Key(key(1)))
            .is_none());
        assert!(agg
            .tally(SecKind::ClockSkew, &Subject::Key(key(5_000)))
            .is_some());
        assert_eq!(
            agg.total(SecKind::ClockSkew),
            Aggregator::MAX_SUBJECTS as u64 + 2
        );
        // A flood of network sources stays within the bound.
        for i in 0..3_000u32 {
            let source = SourceKey::of(IpAddr::from(0x0A00_0000u32.wrapping_add(i).to_be_bytes()));
            agg.record(&ev(
                SecKind::HandshakeFail,
                Attribution::Network { source },
                t0,
            ));
        }
        assert_eq!(
            agg.subjects(SecKind::HandshakeFail),
            Aggregator::MAX_SUBJECTS
        );
        // Every kind at once stays within kinds x subjects.
        for k in SecKind::ALL {
            agg.record(&ev(k, Attribution::Local, t0));
        }
        assert!(agg.kinds.len() <= Aggregator::MAX_KINDS);
        assert!(agg
            .kinds
            .values()
            .all(|l| l.len() <= Aggregator::MAX_SUBJECTS));
        assert_eq!(agg.totals().len(), KINDS);
        assert_eq!(agg.totals()[0].0, SecKind::LinkTagFail);
    }

    #[test]
    fn subjects_follow_the_attribution() {
        let s = ip("10.0.0.9");
        assert_eq!(
            Subject::of(&Attribution::Network { source: s }),
            Subject::Source(s)
        );
        assert_eq!(Subject::of(&contact([3; 32])), Subject::Key([3; 32]));
        let custodian = Attribution::Carrier {
            carrier: [4; 32],
            role: CarrierRole::Custodian,
        };
        assert_eq!(Subject::of(&custodian), Subject::Key([4; 32]));
        assert_eq!(Subject::of(&Attribution::Local), Subject::Local);
        assert_eq!(
            Subject::of(&Attribution::Update {
                passed_by: Some([5; 32])
            }),
            Subject::Key([5; 32])
        );
        assert_eq!(
            Subject::of(&Attribution::Update { passed_by: None }),
            Subject::Update
        );
    }

    #[test]
    fn source_keys_fold_like_admission_and_hide_the_address() {
        assert_eq!(ip("::ffff:192.0.2.1"), ip("192.0.2.1"));
        assert_eq!(ip("2001:db8:1:2:aaaa::1"), ip("2001:db8:1:2:bbbb::2"));
        assert_ne!(ip("2001:db8:1:2::1"), ip("2001:db8:1:3::1"));
        assert_ne!(ip("10.0.0.9"), ip("10.0.0.10"));
        for lo in ["127.0.0.1", "127.9.9.9", "::1", "::ffff:127.0.0.1"] {
            assert!(ip(lo).is_loopback(), "{lo}");
        }
        for not in ["10.0.0.1", "::2", "2001:db8::1", "0.0.0.0"] {
            assert!(!ip(not).is_loopback(), "{not}");
        }
        let shown = format!(
            "{:?}",
            Attribution::Network {
                source: ip("192.0.2.77")
            }
        );
        assert!(!shown.contains("192") && !shown.contains("77"), "{shown}");
    }

    /// Phase 6 review (sensing-2): a local-network source is its whole
    /// address (every link-local host shares fe80::/64, every SLAAC host
    /// one LAN's /64), so a ban on one neighbour leaves another allowed;
    /// IPv4 and IPv4-mapped sources key as [`SourceKey::of`] does.
    #[test]
    fn a_local_source_is_its_whole_address() {
        let local = |s: &str| SourceKey::of_local(s.parse().unwrap());
        assert_ne!(local("fe80::1"), local("fe80::abcd:1234"));
        assert_ne!(local("2001:db8:1:2::a"), local("2001:db8:1:2::b"));
        assert_eq!(local("fe80::1"), local("fe80::1"));
        assert_eq!(local("::ffff:192.168.1.5"), local("192.168.1.5"));
        assert_eq!(local("192.168.1.5"), ip("192.168.1.5"));
        assert!(local("::1").is_loopback());
        // The /64 fold stays for everything else (Internet, p2p).
        assert_eq!(ip("fe80::1"), ip("fe80::abcd:1234"));
        let mut pb = PenaltyBox::new();
        let t0 = Instant::now();
        let (bad, friend) = (local("fe80::bad:1"), local("fe80::f00d:2"));
        assert_eq!(
            flood(&mut pb, bad, 16, t0),
            Verdict::Banned(PENALTY_FIRST_BAN)
        );
        assert_eq!(pb.admit(friend, t0), Admit::Allow);
        assert_eq!(pb.admit(friend, t0 + Duration::from_secs(1)), Admit::Allow);
        assert!(!pb.is_banned(friend, t0));
        assert!(pb.is_banned(bad, t0));
    }

    // ---- note() and the gate ----

    #[test]
    fn note_is_inert_while_the_gate_is_shut() {
        const MARK: [u8; 32] = [0xA7; 32];
        // P6.28: `note_at_least` raises one occurrence's level (a relay's
        // share of lost receipts), never lowers it.
        const RAISED: [u8; 32] = [0xA8; 32];
        struct Counting(Arc<AtomicUsize>);
        impl SecSink for Counting {
            fn accept(&self, ev: &SecEvent, severity: Severity) {
                if ev.who == contact(MARK) {
                    assert_eq!(severity, Severity::Suspicious);
                    self.0.fetch_add(1, Ordering::SeqCst);
                }
                if ev.who == contact(RAISED) {
                    let want = if ev.at_ms == 1 {
                        Severity::Alert
                    } else {
                        Severity::Notice
                    };
                    assert_eq!(severity, want);
                    self.0.fetch_add(10, Ordering::SeqCst);
                }
            }
        }
        let seen = Arc::new(AtomicUsize::new(0));
        set_sink(Box::new(Counting(Arc::clone(&seen))));
        let marked = ev(SecKind::ObjectReplay, contact(MARK), 1_000);
        let held = || with_aggregator(|a| a.tally(SecKind::ObjectReplay, &Subject::Key(MARK)));

        security_gate::set_lab_for_this_thread(SecGate::Events, Some(false));
        for _ in 0..3 {
            note(marked);
        }
        assert_eq!(
            seen.load(Ordering::SeqCst),
            0,
            "a shut gate passes nothing on"
        );
        assert_eq!(held(), None, "and counts nothing");

        // Open (a debug build only: release ignores the lab unlock).
        security_gate::set_lab_for_this_thread(SecGate::Events, Some(true));
        note(marked);
        let live = usize::from(cfg!(debug_assertions));
        assert_eq!(seen.load(Ordering::SeqCst), live);
        assert_eq!(held().map_or(0, |t| t.count), live as u64);
        note_at_least(ev(SecKind::IndexJump, contact(RAISED), 1), Severity::Alert);
        note_at_least(ev(SecKind::IndexJump, contact(RAISED), 2), Severity::Notice);
        assert_eq!(seen.load(Ordering::SeqCst), live * 21);

        security_gate::set_lab_for_this_thread(SecGate::Events, None);
        clear_sink();
    }

    // ---- penalty box ----

    fn flood(pb: &mut PenaltyBox, key: SourceKey, n: u32, now: Instant) -> Verdict {
        let mut last = Verdict::Exempt;
        for _ in 0..n {
            last = pb.strike(key, 1, now);
        }
        last
    }

    #[test]
    fn sixteen_strikes_ban_with_probation_every_ten_seconds() {
        let mut pb = PenaltyBox::new();
        let t0 = Instant::now();
        let bad = ip("10.0.0.9");
        let friend = ip("10.0.0.10");
        assert_eq!(flood(&mut pb, bad, 15, t0), Verdict::Counted(15));
        assert_eq!(pb.admit(bad, t0), Admit::Allow);
        assert_eq!(pb.strike(bad, 1, t0), Verdict::Banned(PENALTY_FIRST_BAN));
        assert_eq!(pb.bans_active(t0), 1);
        // Banned: one probation connection per 10 s.
        assert_eq!(pb.admit(bad, t0), Admit::Probation);
        assert_eq!(pb.admit(bad, t0 + Duration::from_secs(9)), Admit::Deny);
        assert_eq!(
            pb.admit(bad, t0 + Duration::from_secs(10)),
            Admit::Probation
        );
        assert_eq!(pb.admit(bad, t0 + Duration::from_secs(11)), Admit::Deny);
        assert_eq!(
            pb.strike(bad, 1, t0 + Duration::from_secs(12)),
            Verdict::StillBanned
        );
        // Another source is untouched.
        assert_eq!(pb.admit(friend, t0), Admit::Allow);
        // The ban ends after 60 s.
        assert_eq!(pb.admit(bad, t0 + Duration::from_secs(60)), Admit::Allow);
        assert_eq!(pb.bans_active(t0 + Duration::from_secs(60)), 0);
        // Weights add up: eight malformed frames (weight 2) ban too.
        let other = ip("10.0.0.11");
        for _ in 0..7 {
            assert!(matches!(
                pb.strike(other, strike_weight(SecKind::PreauthMalformed), t0),
                Verdict::Counted(_)
            ));
        }
        assert_eq!(pb.strike(other, 2, t0), Verdict::Banned(PENALTY_FIRST_BAN));
        // A weight of zero is no strike.
        assert_eq!(pb.strike(friend, 0, t0), Verdict::Exempt);
        assert_eq!(pb.len(), 2);
    }

    /// `is_banned` only looks: the probation is still there afterwards,
    /// and an exempt source is never banned.
    #[test]
    fn is_banned_only_looks() {
        let mut pb = PenaltyBox::new();
        let t0 = Instant::now();
        let bad = ip("10.0.0.12");
        assert!(!pb.is_banned(bad, t0), "unknown");
        flood(&mut pb, bad, 15, t0);
        assert!(!pb.is_banned(bad, t0), "struck, not banned");
        assert_eq!(pb.strike(bad, 1, t0), Verdict::Banned(PENALTY_FIRST_BAN));
        for _ in 0..3 {
            assert!(pb.is_banned(bad, t0));
        }
        assert_eq!(pb.admit(bad, t0), Admit::Probation, "not used up");
        assert!(!pb.is_banned(bad, t0 + PENALTY_FIRST_BAN), "over");
        let lo = ip("127.0.0.1");
        flood(&mut pb, lo, 32, t0);
        assert!(!pb.is_banned(lo, t0), "loopback is exempt");
        let mut strict = PenaltyBox::with_loopback_exempt(false);
        flood(&mut strict, lo, 16, t0);
        assert!(strict.is_banned(lo, t0));
    }

    #[test]
    fn strikes_count_within_one_minute() {
        let mut pb = PenaltyBox::new();
        let t0 = Instant::now();
        let k = ip("192.0.2.5");
        assert_eq!(flood(&mut pb, k, 15, t0), Verdict::Counted(15));
        assert_eq!(
            pb.strike(k, 1, t0 + PENALTY_WINDOW),
            Verdict::Counted(1),
            "a new window"
        );
        assert_eq!(
            flood(&mut pb, k, 14, t0 + PENALTY_WINDOW),
            Verdict::Counted(15)
        );
        assert_eq!(
            pb.strike(k, 1, t0 + PENALTY_WINDOW + Duration::from_secs(59)),
            Verdict::Banned(PENALTY_FIRST_BAN)
        );
    }

    #[test]
    fn bans_double_up_to_an_hour_and_ten_clean_minutes_forget() {
        assert_eq!(ban_length(0), PENALTY_FIRST_BAN);
        let secs: Vec<u64> = (1..=9).map(|n| ban_length(n).as_secs()).collect();
        assert_eq!(secs, [60, 120, 240, 480, 960, 1_920, 3_600, 3_600, 3_600]);
        assert_eq!(ban_length(u32::MAX), PENALTY_MAX_BAN);

        let mut pb = PenaltyBox::new();
        let k = ip("2001:db8:5::1");
        let mut now = Instant::now();
        for want in [60, 120, 240, 480, 960, 1_920, 3_600, 3_600] {
            assert_eq!(
                flood(&mut pb, k, 16, now),
                Verdict::Banned(Duration::from_secs(want))
            );
            assert_eq!(
                pb.admit(k, now + Duration::from_secs(want - 1)),
                Admit::Probation
            );
            // Struck again 5 minutes after the ban ends: still remembered.
            now += Duration::from_secs(want) + Duration::from_secs(5 * 60);
        }
        // Ten clean minutes after the last ban ends: forgotten, so the next
        // ban is a first one again.
        let mut pb = PenaltyBox::new();
        let t0 = Instant::now();
        assert_eq!(
            flood(&mut pb, k, 16, t0),
            Verdict::Banned(Duration::from_secs(60))
        );
        let quiet = t0 + Duration::from_secs(60) + PENALTY_FORGET;
        assert_eq!(pb.admit(k, quiet), Admit::Allow);
        assert!(pb.is_empty(), "admit drops a forgotten source");
        assert_eq!(
            flood(&mut pb, k, 16, quiet),
            Verdict::Banned(Duration::from_secs(60))
        );
        // Strikes alone are forgotten after ten clean minutes too.
        let other = ip("198.51.100.1");
        assert_eq!(flood(&mut pb, other, 10, t0), Verdict::Counted(10));
        pb.prune(t0 + PENALTY_FORGET);
        assert_eq!(pb.len(), 1, "only the banned source is left");
        // The same /64 is one source.
        assert_eq!(pb.admit(ip("2001:db8:5::ffff"), quiet), Admit::Probation);
    }

    #[test]
    fn an_authenticated_contact_clears_the_source() {
        let mut pb = PenaltyBox::new();
        let t0 = Instant::now();
        let shared = ip("203.0.113.8");
        assert_eq!(
            flood(&mut pb, shared, 16, t0),
            Verdict::Banned(PENALTY_FIRST_BAN)
        );
        // A friend behind the same address gets the probation connection
        // within 10 s and authenticates on it.
        let t1 = t0 + Duration::from_secs(3);
        assert_eq!(pb.admit(shared, t0), Admit::Probation);
        assert_eq!(pb.admit(shared, t1), Admit::Deny);
        assert_eq!(pb.admit(shared, t0 + PENALTY_PROBATION), Admit::Probation);
        pb.authenticated(shared);
        assert_eq!(pb.admit(shared, t0 + PENALTY_PROBATION), Admit::Allow);
        assert_eq!(pb.bans_active(t1), 0);
        // The attacker needs another 16 strikes, and gets a first ban again.
        assert_eq!(flood(&mut pb, shared, 15, t1), Verdict::Counted(15));
        assert_eq!(pb.strike(shared, 1, t1), Verdict::Banned(PENALTY_FIRST_BAN));
    }

    #[test]
    fn the_box_holds_at_most_4096_sources() {
        let mut pb = PenaltyBox::new();
        let t0 = Instant::now();
        let key =
            |i: u32| SourceKey::of(IpAddr::from(0x0A00_0000u32.wrapping_add(i).to_be_bytes()));
        for i in 0..PENALTY_MAX_KEYS as u32 {
            assert_eq!(pb.strike(key(i), 15, t0), Verdict::Counted(15));
        }
        assert_eq!(pb.len(), PENALTY_MAX_KEYS);
        // Source 0 seen again; a new source then drops source 1 (least
        // recently seen).
        assert_eq!(pb.admit(key(0), t0), Admit::Allow);
        assert_eq!(
            pb.strike(key(PENALTY_MAX_KEYS as u32), 1, t0),
            Verdict::Counted(1)
        );
        assert_eq!(pb.len(), PENALTY_MAX_KEYS);
        assert_eq!(pb.strike(key(0), 1, t0), Verdict::Banned(PENALTY_FIRST_BAN));
        assert_eq!(
            pb.strike(key(1), 1, t0),
            Verdict::Counted(1),
            "dropped, so counted afresh"
        );
        assert_eq!(pb.len(), PENALTY_MAX_KEYS);
    }

    #[test]
    fn loopback_is_never_banned_unless_told() {
        let t0 = Instant::now();
        let mut pb = PenaltyBox::new();
        for lo in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            assert_eq!(flood(&mut pb, ip(lo), 100, t0), Verdict::Exempt, "{lo}");
            assert_eq!(pb.admit(ip(lo), t0), Admit::Allow);
        }
        assert!(pb.is_empty());
        let mut strict = PenaltyBox::with_loopback_exempt(false);
        assert_eq!(
            flood(&mut strict, ip("127.0.0.1"), 16, t0),
            Verdict::Banned(PENALTY_FIRST_BAN)
        );
        assert_eq!(strict.admit(ip("127.0.0.1"), t0), Admit::Probation);
        assert_eq!(strict.admit(ip("127.0.0.1"), t0), Admit::Deny);
    }

    // ---- classifiers ----

    /// Every variant once, with its decided kind. `ordinal` is an exhaustive
    /// match of its own: a new variant breaks the build here as in the
    /// classifier, and the table below must then grow a row.
    fn store_ordinal(e: &IndexedSessionStoreError) -> usize {
        use IndexedSessionStoreError as E;
        match e {
            E::Sqlite(_) => 0,
            E::ProtectedStore(_) => 1,
            E::ProtectedStateMissing => 2,
            E::CorruptProtectedState => 3,
            E::RollbackDetected => 4,
            E::NotFound => 5,
            E::UnsupportedProfile => 6,
            E::InvalidBinding => 7,
            E::InitIdConflict => 8,
            E::BindingConflict => 9,
            E::ConfirmationConflict => 10,
            E::SessionNotConfirmed => 11,
            E::IndexExhausted => 12,
            E::Replay => 13,
            E::ForwardJumpTooLarge => 14,
            E::AuthenticationFailed => 15,
            E::InvalidEndpointEnvelope => 16,
            E::EndpointTypeMismatch => 17,
            E::EndpointNotCurrentlyValid => 18,
            E::InvalidIndexedMessage => 19,
            E::DeviceHintMismatch => 20,
            E::RouteTagMismatch => 21,
            E::InvalidDeviceCertificate => 22,
            E::RevokedDevice => 23,
            E::DeviceBindingMismatch => 24,
            E::OuterSignatureInvalid => 25,
            E::InvalidEndpointPayload => 26,
            E::LocalDeviceUnauthorized => 27,
            E::LocalDeviceBindingMismatch => 28,
            E::LocalSignerFailure => 29,
            E::EndpointRandomnessUnavailable => 30,
            E::OutboundPending => 31,
            E::OutboundCollision => 32,
            E::OutboundQueueHandoff => 33,
            E::OutboundBindingMismatch => 34,
            E::LogicalMessageConflict => 35,
            E::CorruptEndpointState => 36,
            E::LocalInboxAuthenticationFailed => 37,
            E::AckBytesConflict => 38,
            E::AckEnqueue => 39,
            E::AckOutstandingMismatch => 40,
            E::AckTimestampMismatch => 41,
            E::AckInnerSignatureInvalid => 42,
            E::AckNonceConflict => 43,
            E::PairInit(_) => 44,
            E::UnsupportedMetadataSchema(_) => 45,
            E::MetaKeyUnavailable(_) => 46,
            E::MetadataMigration(_) => 47,
            E::SessionRetired => 48,
            E::ApplicationDeferred => 49,
            E::InjectedCrashAfterProtectedWrite => 50,
            E::InjectedEndpointFailure(_) => 51,
            E::SuiteHeld => 52,
        }
    }
    const STORE_VARIANTS: usize = 53;

    #[test]
    fn every_store_error_is_decided() {
        use IndexedSessionStoreError as E;
        use SecKind as K;
        let link = Via::DirectLink(OutboxCarrier::Lan);
        let rows: Vec<(E, Option<K>)> = vec![
            (E::Sqlite(rusqlite::Error::QueryReturnedNoRows), None),
            (E::ProtectedStore("x".into()), None),
            (E::ProtectedStateMissing, None),
            (E::CorruptProtectedState, None),
            (E::RollbackDetected, Some(K::LocalRollback)),
            (E::NotFound, None),
            (E::UnsupportedProfile, None),
            (E::InvalidBinding, None),
            (E::InitIdConflict, None),
            (E::BindingConflict, None),
            (E::ConfirmationConflict, None),
            (E::SessionNotConfirmed, None),
            (E::IndexExhausted, None),
            (E::Replay, Some(K::ObjectReplay)),
            (E::ForwardJumpTooLarge, Some(K::IndexJump)),
            (E::AuthenticationFailed, Some(K::ObjectAuthFail)),
            (E::InvalidEndpointEnvelope, None),
            (E::EndpointTypeMismatch, None),
            (E::EndpointNotCurrentlyValid, None),
            (E::InvalidIndexedMessage, None),
            (E::DeviceHintMismatch, None),
            (E::RouteTagMismatch, Some(K::SessionUnknown)),
            (E::InvalidDeviceCertificate, Some(K::BindingMismatch)),
            (E::RevokedDevice, Some(K::RevokedDeviceUsed)),
            (E::DeviceBindingMismatch, Some(K::BindingMismatch)),
            (E::OuterSignatureInvalid, Some(K::ObjectSigFail)),
            (E::InvalidEndpointPayload, None),
            (E::LocalDeviceUnauthorized, None),
            (E::LocalDeviceBindingMismatch, None),
            (E::LocalSignerFailure, None),
            (E::EndpointRandomnessUnavailable, None),
            (E::OutboundPending, None),
            (E::OutboundCollision, None),
            (E::OutboundQueueHandoff, None),
            (E::OutboundBindingMismatch, None),
            (E::LogicalMessageConflict, Some(K::ObjectReplay)),
            (E::CorruptEndpointState, None),
            (E::LocalInboxAuthenticationFailed, Some(K::LocalRollback)),
            (E::AckBytesConflict, None),
            (E::AckEnqueue, None),
            (E::AckOutstandingMismatch, None),
            (E::AckTimestampMismatch, None),
            (E::AckInnerSignatureInvalid, None),
            (E::AckNonceConflict, Some(K::ObjectReplay)),
            (E::PairInit(PairInitError::InvalidLength), None),
            (E::UnsupportedMetadataSchema(9), None),
            (E::MetaKeyUnavailable("x".into()), None),
            (E::MetadataMigration("x".into()), None),
            (E::SessionRetired, None),
            (E::ApplicationDeferred, None),
            (E::InjectedCrashAfterProtectedWrite, None),
            (E::InjectedEndpointFailure("x"), None),
            (E::SuiteHeld, None),
        ];
        let mut ordinals: Vec<usize> = rows.iter().map(|(e, _)| store_ordinal(e)).collect();
        ordinals.sort_unstable();
        assert_eq!(
            ordinals,
            (0..STORE_VARIANTS).collect::<Vec<_>>(),
            "one row per variant"
        );
        for (e, want) in &rows {
            assert_eq!(classify_store_error(e, link), *want, "{e:?}");
            assert_eq!(
                classify_store_error(e, Via::Dial(OutboxCarrier::P2p)),
                *want,
                "{e:?}"
            );
            assert_eq!(classify_store_error(e, Via::Relay), *want, "{e:?}");
        }
        // Via a custodian: an outer signature that fails is the custodian's,
        // a replayed index a re-served object; the rest as on a link.
        let custodian = Via::Custodian([9; 32]);
        for (e, want) in &rows {
            let want = match e {
                E::OuterSignatureInvalid => Some(K::CustodianBadObject),
                E::Replay => Some(K::CustodianReplay),
                _ => *want,
            };
            assert_eq!(classify_store_error(e, custodian), want, "{e:?}");
        }
        // From local state no signature failed on anything a peer sent.
        assert_eq!(
            classify_store_error(&E::OuterSignatureInvalid, Via::Local),
            None
        );
        assert_eq!(
            classify_store_error(&E::Replay, Via::Local),
            Some(K::ObjectReplay)
        );
        // Clock: only an envelope from our future is skew.
        let late = E::EndpointNotCurrentlyValid;
        assert_eq!(
            classify_store_error_at(&late, link, Some(PeerClock::Ahead(6 * MINUTE_MS))),
            Some(K::ClockSkew)
        );
        assert_eq!(
            classify_store_error_at(&late, link, Some(PeerClock::Agrees)),
            None
        );
        assert_eq!(classify_store_error_at(&late, link, None), None);
        assert_eq!(
            classify_store_error_at(&E::AuthenticationFailed, link, Some(PeerClock::Ahead(1))),
            Some(K::ObjectAuthFail),
            "the clock decides only the validity row"
        );
    }

    fn prekey_ordinal(e: &PrekeyLifecycleError) -> usize {
        use PrekeyLifecycleError as E;
        match e {
            E::ProtectedStoreUnavailable => 0,
            E::ProtectedStore => 1,
            E::CorruptProtectedState => 2,
            E::LockFailed => 3,
            E::Database => 4,
            E::InvalidGeneration => 5,
            E::NonMonotonicSignedPrekeyId => 6,
            E::ActorLineageMismatch => 7,
            E::ResourceLimit => 8,
            E::PairInit(_) => 9,
            E::PairInitLifetime => 10,
            E::PairInitOutsideGrace => 11,
            E::PairInitClockSkew => 12,
            E::UnknownPrekey => 13,
            E::InitIdConflict => 14,
            E::ClaimNotFound => 15,
            E::ClaimBindingMismatch => 16,
            E::ClaimHandoffExpired => 17,
            E::NonContributoryWrapKey => 18,
            E::InjectedCrash(_) => 19,
        }
    }

    #[test]
    fn every_prekey_error_is_decided() {
        use PrekeyLifecycleError as E;
        let rows: Vec<(E, Option<SecKind>)> = vec![
            (E::ProtectedStoreUnavailable, None),
            (E::ProtectedStore, None),
            (E::CorruptProtectedState, None),
            (E::LockFailed, None),
            (E::Database, None),
            (E::InvalidGeneration, None),
            (E::NonMonotonicSignedPrekeyId, None),
            (E::ActorLineageMismatch, None),
            (E::ResourceLimit, Some(SecKind::PairinitFlood)),
            (E::PairInit(PairInitError::InvalidMagic), None),
            (E::PairInitLifetime, None),
            (E::PairInitOutsideGrace, None),
            (E::PairInitClockSkew, Some(SecKind::ClockSkew)),
            (E::UnknownPrekey, None),
            (E::InitIdConflict, None),
            (E::ClaimNotFound, None),
            (E::ClaimBindingMismatch, None),
            (E::ClaimHandoffExpired, None),
            (E::NonContributoryWrapKey, None),
            (E::InjectedCrash("x"), None),
        ];
        let mut ordinals: Vec<usize> = rows.iter().map(|(e, _)| prekey_ordinal(e)).collect();
        ordinals.sort_unstable();
        assert_eq!(ordinals, (0..20).collect::<Vec<_>>(), "one row per variant");
        for (e, want) in &rows {
            assert_eq!(classify_prekey_error(e), *want, "{e:?}");
        }
    }

    #[test]
    fn every_at_rest_error_is_decided() {
        let ordinal = |e: &AtRestError| match e {
            AtRestError::KeyUnavailable(_) => 0,
            AtRestError::KeyLost(_) => 1,
            AtRestError::NoIdentity => 2,
            AtRestError::Tampered { .. } => 3,
            AtRestError::WrongKind { .. } => 4,
            AtRestError::Truncated => 5,
            AtRestError::NewerFormat(_) => 6,
            AtRestError::StaleKeys { .. } => 7,
            AtRestError::NotSealedMode => 8,
            AtRestError::Io(_) => 9,
            AtRestError::Json(_) => 10,
        };
        let rows: Vec<(AtRestError, Option<SecKind>)> = vec![
            (AtRestError::KeyUnavailable("x".into()), None),
            (AtRestError::KeyLost("x".into()), None),
            (AtRestError::NoIdentity, None),
            (
                AtRestError::Tampered { kind: 3 },
                Some(SecKind::LocalRollback),
            ),
            (
                AtRestError::WrongKind { want: 1, got: 2 },
                Some(SecKind::LocalRollback),
            ),
            (AtRestError::Truncated, Some(SecKind::LocalRollback)),
            (AtRestError::NewerFormat(9), None),
            (AtRestError::StaleKeys { epoch: 4 }, None),
            (AtRestError::NotSealedMode, None),
            (AtRestError::Io("x".into()), None),
            (AtRestError::Json("x".into()), None),
        ];
        let mut ordinals: Vec<usize> = rows.iter().map(|(e, _)| ordinal(e)).collect();
        ordinals.sort_unstable();
        assert_eq!(ordinals, (0..11).collect::<Vec<_>>(), "one row per variant");
        for (e, want) in &rows {
            assert_eq!(classify_at_rest_error(e), *want, "{e:?}");
        }
    }

    #[test]
    fn every_custody_code_is_decided_on_both_sides() {
        use CustodyCode as C;
        let all = [
            C::Ok,
            C::Duplicate,
            C::PolicyDenied,
            C::Hold,
            C::NotVerified,
            C::RefusedObject,
            C::Expired,
            C::StoreFull,
            C::Quota,
            C::RateLimited,
            C::Persistence,
            C::Malformed,
            C::RecipientNotAccepted,
            C::Conflict,
            C::NextHopUnknown,
            C::TagUnknown,
            C::HopRefused,
        ];
        // Every wire code 0..=16 once (10 is Persistence; unknown codes read
        // as Persistence too).
        let wire: Vec<C> = (0..=16u8).map(C::from_u8).collect();
        assert_eq!(wire, all.to_vec());
        for c in all {
            let as_custodian = match c {
                C::RateLimited | C::Quota => Some(SecKind::DepositorFlood),
                C::RefusedObject | C::Malformed => Some(SecKind::DepositorBadObject),
                C::HopRefused => Some(SecKind::HandoffRefused),
                _ => None,
            };
            assert_eq!(
                classify_custody_code(c, Side::Custodian),
                as_custodian,
                "{c:?}"
            );
            let as_depositor = (c == C::HopRefused).then_some(SecKind::HandoffRefused);
            assert_eq!(
                classify_custody_code(c, Side::Depositor),
                as_depositor,
                "{c:?}"
            );
        }
    }

    /// Every outcome code `relayed_ingest` returns (read from its source, so
    /// a new code fails here until it is decided).
    #[test]
    fn every_relayed_outcome_is_decided() {
        let decided: &[(&str, Option<SecKind>)] = &[
            (
                "Refused:CUSTODY_MALFORMED",
                Some(SecKind::CustodianBadObject),
            ),
            (
                "Refused:OUTER_SIGNATURE_INVALID",
                Some(SecKind::CustodianBadObject),
            ),
            ("Refused:CUSTODY_REFUSED", None),
            ("Refused:ENVELOPE_EXPIRED", None),
            // Phase 6 review sensing-1: a session an early re-key closed.
            ("Refused:SESSION_RETIRED", None),
            ("Refused:CONTACT_NOT_VERIFIED", None),
            ("Refused:SENDER_NOT_CONTACT", None),
            ("Refused:SENDER_BLOCKED", None),
            ("Retry:CLOCK", Some(SecKind::ClockSkew)),
            ("Retry:STORE", None),
            ("Retry:RETRY", None),
            ("Retry:CONTACTS_UNREADABLE", None),
            ("Retry:OWED_ACK_FULL", None),
            ("Retry:OWED_ACKS_UNAVAILABLE", None),
            ("Retry:NO_PEER_CERT", None),
            ("Retry:APP_DEFERRED", None),
            ("Retry:APP_INBOX", None),
            ("Retry:HISTORY", None),
            ("Retry:LOCAL_DEVICE", None),
            ("Retry:SESSION_ENDING", None),
            ("Retry:OWED_ACK_WRITE", None),
        ];
        let path = crate_dir().join("src/relayed_ingest.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        let code = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        let literal_after = |rest: &str| -> Option<String> {
            let rest = rest.trim_start().strip_prefix('"')?;
            Some(rest[..rest.find('"')?].to_owned())
        };
        let mut found = HashSet::new();
        for (i, _) in code.match_indices("Refused(") {
            if let Some(c) = literal_after(&code[i + "Refused(".len()..]) {
                found.insert(format!("Refused:{c}"));
            }
        }
        for (i, _) in code.match_indices("Retry(RetryScope::") {
            let rest = &code[i..];
            let comma = rest.find(',').unwrap();
            if let Some(c) = literal_after(&rest[comma + 1..]) {
                found.insert(format!("Retry:{c}"));
            }
        }
        let table: HashSet<String> = decided.iter().map(|(c, _)| (*c).to_owned()).collect();
        assert_eq!(
            found, table,
            "relayed_ingest's outcome codes and this table"
        );
        for (code, want) in decided {
            let (variant, text) = code.split_once(':').unwrap();
            let text: &'static str = Box::leak(text.to_owned().into_boxed_str());
            let outcome = match variant {
                "Refused" => RelayedOutcome::Refused(text),
                _ => RelayedOutcome::Retry(RetryScope::Item, text),
            };
            assert_eq!(classify_relayed(&outcome), *want, "{code}");
            assert_eq!(outcome.releases(), variant == "Refused");
        }
        for accepted in [
            RelayedOutcome::MessageAccepted {
                peer: [1; 32],
                message_id: [2; 16],
                duplicate: true,
                group: false,
            },
            RelayedOutcome::AckAccepted {
                peer: [1; 32],
                acked_message_id: [2; 16],
            },
        ] {
            assert_eq!(classify_relayed(&accepted), None);
        }
        for scope in [RetryScope::Item, RetryScope::Peer, RetryScope::Store] {
            assert_eq!(
                classify_relayed(&RelayedOutcome::Retry(scope, "CLOCK")),
                Some(SecKind::ClockSkew)
            );
        }
    }

    #[test]
    fn link_errors_match_exact_texts_only() {
        let rows: &[(&str, SecKind)] = &[
            (LINK_REFUSED_NOT_CONTACT, SecKind::StrangerRefused),
            (LINK_REFUSED_BLOCKED, SecKind::BlockedRefused),
            (LINK_REFUSED_NOT_VERIFIED, SecKind::UnverifiedRemote),
            (LINK_REFUSED_VERIFIED_ONLY, SecKind::UnverifiedRemote),
            (LAN_HANDSHAKE_TIMEOUT, SecKind::HandshakeFail),
            (INTERNET_HANDSHAKE_TIMEOUT, SecKind::HandshakeFail),
            (NOISE_HANDSHAKE_FAILED, SecKind::HandshakeFail),
            (LAN_FRAME_LENGTH, SecKind::PreauthMalformed),
            (INTERNET_FRAME_LENGTH, SecKind::PreauthMalformed),
            (BIND_TRUNCATED, SecKind::PreauthMalformed),
            (BIND_BAD_SIGNATURE, SecKind::PreauthMalformed),
            (LINK_TAG_FAILED, SecKind::LinkTagFail),
        ];
        for (text, kind) in rows {
            assert_eq!(classify_link_error(text), Some(*kind), "{text}");
            // Exact only: a prefix, a suffix or another case is not it.
            assert_eq!(classify_link_error(&format!("{text}: x")), None);
            assert_eq!(classify_link_error(&format!(" {text}")), None);
            assert_eq!(classify_link_error(&text.to_uppercase()), None);
        }
        for other in [
            "",
            "lan read timeout",
            "peer closed",
            "lan frame too large",
            "identity bind does not match expected pub",
            // E1: a held book judged nobody, so no stranger was refused.
            crate::lan_dispatch::LINK_REFUSED_NOT_READY,
        ] {
            assert_eq!(classify_link_error(other), None, "{other}");
        }
        // The Noise texts are LanNoiseError's own.
        assert_eq!(LanNoiseError::Transport.to_string(), LINK_TAG_FAILED);
        assert_eq!(LanNoiseError::Handshake.to_string(), NOISE_HANDSHAKE_FAILED);
        assert_eq!(LanNoiseError::BindTruncated.to_string(), BIND_TRUNCATED);
        assert_eq!(
            LanNoiseError::BindBadSignature.to_string(),
            BIND_BAD_SIGNATURE
        );
    }

    /// raven-node returns these texts through the constants (step P6.24):
    /// no link module's code spells one of them out any more (its tests
    /// still do, to keep the texts byte for byte), so the classifier and the
    /// link cannot drift apart.
    #[test]
    fn link_texts_are_the_node_texts() {
        let node = crate_dir().join("../raven-node/src");
        let read = |f: &str| {
            let source = std::fs::read_to_string(node.join(f)).unwrap();
            source
                .split("#[cfg(test)]\nmod tests")
                .next()
                .unwrap()
                .to_string()
        };
        let lan = read("lan_direct.rs");
        let inet = read("internet_direct.rs");
        let main = read("main.rs");
        for (source, name, text) in [
            (&lan, "LAN_HANDSHAKE_TIMEOUT", LAN_HANDSHAKE_TIMEOUT),
            (&lan, "LAN_FRAME_LENGTH", LAN_FRAME_LENGTH),
            (
                &inet,
                "INTERNET_HANDSHAKE_TIMEOUT",
                INTERNET_HANDSHAKE_TIMEOUT,
            ),
            (&inet, "INTERNET_FRAME_LENGTH", INTERNET_FRAME_LENGTH),
            (&main, "LINK_TAG_FAILED", LINK_TAG_FAILED),
        ] {
            assert!(
                source.contains(&format!("security_events::{name}")),
                "{name}"
            );
            assert!(!source.contains(&format!("\"{text}\"")), "{text}");
        }
    }

    /// A relay is noted under a domain-separated digest of its PeerId bytes,
    /// never the bytes themselves.
    #[test]
    fn relay_subjects_are_digests() {
        let a = relay_subject(b"peer-a");
        assert_eq!(a, relay_subject(b"peer-a"));
        assert_ne!(a, relay_subject(b"peer-b"));
        let mut plain = [0u8; 32];
        plain[..6].copy_from_slice(b"peer-a");
        assert_ne!(a, plain);
        use sha2::{Digest, Sha256};
        assert_ne!(a, <[u8; 32]>::from(Sha256::digest(b"peer-a")));
    }
}
