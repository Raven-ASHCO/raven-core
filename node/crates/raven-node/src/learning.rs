//! Learning connectivity in raven-node (Phase 6a, `docs/roadmap/plans/
//! phase6-design.json` design "Phase 6a"; P6.11 observes and persists,
//! P6.12 applies the learned carrier order, P6.13 the adaptive waits, P6.14
//! explores, P6.15 scores relays, P6.16 chooses custody's carriers). The
//! model (`raven_core::learning`) learns from this node's own dial
//! outcomes, ranks the carriers the static plan already holds and may
//! shorten a dial's waits, never lengthen them.
//!
//! - **Observations.** The carrier dials (`lan_direct::dial`,
//!   `dial_announce`, `internet_direct::dial`, `p2p::dial_with_path`) call
//!   [`observe_dial`] for Ok and Err alike, next to `delivery_paths::note`.
//!   It does no I/O (it reads this computer's egress tag once, a UDP
//!   connect with nothing sent: a network that moved during the dial,
//!   whether or not netwatch acted on it yet, is no evidence): it
//!   classifies the result (the stable dial code, or the Phase 2 reason
//!   token of a p2p reason block) and posts one
//!   [`Observation`] into a bounded channel ([`INTAKE`]); a full channel
//!   counts as dropped. A wait that ran out ([`Expired`]) backs that wait
//!   off; a dial the worker marks as a resend of an object that went
//!   silent ([`DialMeta::karn_exclude`]) gives no reply-time sample (Karn).
//!   The worker posts a [`retract`] when every ACK of a
//!   dial was refused; the inbound links post [`inbound`] (a contact back on
//!   the local network from a new address halves the LAN doubt; a link over
//!   our reservation on a relay counts for that relay); a failed p2p dial
//!   posts its circuits' outcomes ([`circuits`]).
//! - **Relays.** [`relay_terms`] gives each relay's learned term (design
//!   §6): the p2p host adds it to relay selection's score of an offered
//!   relay (it never starts a change) and orders a contact dial's circuits
//!   by it (a demoted circuit stays last).
//! - **The service** ([`run`], supervised in `main`): it re-reads the
//!   user's switch (`node_policy.learning`) every [`POLICY_POLL`]; while on,
//!   it loads the model once (`learning::store`, on the blocking pool),
//!   applies what the channel brings and saves every [`SAVE_EVERY`] when
//!   something changed ([`final_save`] at shutdown, at most
//!   [`FINAL_SAVE_WAIT`]). A model loaded while the profile's at-rest key
//!   was not here yet (still loading at the start, or after an unlock) is
//!   memory only until it is: each poll asks the sealer again, and then the
//!   file is read and replaces it (with no file, what was learned meanwhile
//!   is kept and saved). A save the key refuses is tried again at the next
//!   one. While the file is not read, one contact cannot be forgotten in it:
//!   `LearningReset` for a contact is an error, not "cleared 0".
//! - **Order.** [`plan`] gives the learned order for a contact on this
//!   network (`learning::rank`; the static order while cold or pinned). The
//!   shared resolver (`outbox::peer_plan`: the worker, `AppSubmit`, the
//!   announcer and session renewal) ranks every plan of that contact by it
//!   instead of the route memory's route, which is neither read nor taught
//!   while learning is on (OD6a-10); G3's silent-route rotation and a
//!   connected route still go first. An order that is no pure reorder of a
//!   plan is a [`contradiction`]: the static plan, pinned for an hour. The
//!   worker remembers the order after an attempt that reached the contact
//!   ([`remember_order`], the hysteresis start) and counts plans that left
//!   the static order ([`planned`], `Status.learning.would_reorder_24h`).
//!   IPC `LearningPlan` answers the same order (`state=on`; `raven send`'s
//!   probe order), `LearningReset` forgets in memory and on disk.
//! - **Waits.** Each LAN, Internet and p2p dial asks [`waits`] (design §4,
//!   `learning::wait`): the connect wait (per address for LAN and Internet,
//!   the p2p connect) and the first-reply wait of a warm, fresh arm, never
//!   above today's values; today's while learning is off or the arm is
//!   cold. The connect budget, the dial deadlines, the worker's 45 s, the
//!   idle reply wait and the inbound limits stay as they are.
//! - **Exploration** (design §5, OD6a-5). A carrier that lost its place is
//!   tried again only by dials that carry no user message, so a route that
//!   healed comes back without a message waiting on it:
//!   - Every [`EXPLORE_TICK`] the service may send one *probe*: a frame-less
//!     dial ([`crate::outbox::Dialer::probe_within`]; it takes no frames)
//!     over the first planned route of one carrier, within that carrier's
//!     connect wait plus [`PROBE_SLACK`]. Its link (or failure) reaches the
//!     model through the carriers' hook like any dial's.
//!   - A worker batch of owed ACKs with no message may put that carrier
//!     first ([`explore_ack_order`]) when its failures are cheap
//!     ([`ACK_EXPLORE_FAIL_MS`]). A batch with any message keeps the
//!     exploit order.
//!   - Only verified, unblocked contacts whose sending the user did not
//!     pause (Phase 6b P6.31's hold) written to (a message dial, or a
//!     receipt on this network) within [`ACTIVE_MS`]; only carriers the
//!     contact's current plan holds (the gates, hide-IP), never its top
//!     one and never nearby; a LAN or Internet carrier only after a receipt
//!     on this network within [`RECEIPT_WITHIN_MS`] (a LAN dialer binds its
//!     identity before the responder proves its own), p2p while it is live.
//!   - An arm is due after [`RECOVER_GAP_MS`] when it sits below its static
//!     place with a success streak, else after [`PROBE_ARM_GAP_MS`]
//!     (`RAVEN_LAB_LEARNING_TUNE` replaces both in a debug lab run), and
//!     only when nothing else observed it within the shorter of its gap and
//!     30 min. The stalest due arm goes first.
//!   - The budget is global: [`PROBES_PER_HOUR`] with a burst of
//!     [`PROBE_BURST`], one probe in flight, nothing within [`SETTLE_MS`] of
//!     a network change or while the file is kept in memory because a newer
//!     Raven wrote it. Probes and ACK explorations both spend it and both
//!     count in `Status.learning.probes_24h`.
//!   - Side effects: a probe is an authenticated link the contact sees (and,
//!     over p2p, the relay); it makes the contact's node run `peer_seen`
//!     (at most one dial-back per 60 s), which is useful. Logs carry counts
//!     only.
//! - **Carry choice** (design §7, P6.16), live only while learning is on,
//!   friend custody is live and in use ([`carry_live`]: `raven custody use
//!   on`, or a custodian listed for a verified contact; OD6a-14):
//!   - Encounters ([`encounter`]): an authenticated link with a verified,
//!     unblocked contact in either direction (`custody::peer_seen`, from
//!     the trusted inbound links, a beacon answer and new route hints; an
//!     outbound dial that linked, in [`observe_dial`]) and a nearby pipe up
//!     (`custody::encounter`). Without carry choice none is kept.
//!   - Pick ([`carry_pick`]): the worker leaves a contact's mail with at
//!     most [`CARRY_CAP`] of every custodian candidate
//!     (`custody_client::custodian_candidates`), ranked by this node's own
//!     encounters × its own receipts, in that order for the deposits, the
//!     letters and the handoff plan (`outbox::custodians_for`); cold, or
//!     with carry choice off, today's `deposit_custodians`. An object is
//!     never left with more than [`CARRY_CAP`] candidates. The 60 s wait,
//!     the failed direct try, parks, strikes and chunks are unchanged.
//!   - Outcomes ([`carry_outcome`]): a message friends held that the worker
//!     finds delivered credits them, one whose time ran out (expired, or
//!     parked by the horizon) debits them; a message never left with a
//!     friend is no evidence.
//!   - A forwarder visits its next hops in its own order of meeting them
//!     ([`forward_order`], order only). `LearningPlan` names the pick with
//!     why (`carry=ranked`), the custody log line its token
//!     (`carry=cold|ranked`), and `Status.learning.carriers` counts the
//!     carry rows.
//!   - Not here (6a non-goals): finding a carrier that moved (code report
//!     w1/w2, F8 and the beacon join round are Phase 3's); the 24 h custody
//!     and envelope ceilings and the 7 d letter and horizon limits are never
//!     extended; a custodian never sprays again.
//! - **Off.** With the gate shut (`LEARNING_PRODUCTION_ENABLED`, debug
//!   `RAVEN_LAB_LEARNING=1`) or the user's switch off, nothing is observed,
//!   loaded or written, `learning.bin` is never made, and `Status` carries
//!   no `learning` (gate shut) or an `off` row.
//!
//! Privacy: the model keeps contacts, networks and relays only as HMAC keys
//! (`learning::model`), the file is sealed (RMS1 kind 22), and logs carry
//! counts and fixed words only: never an address, key, PeerId, network tag
//! or name. `Status.learning` rows name contacts by key for local ash. The
//! explorer's own notes (whom this node wrote to, which arm it explored
//! when) live in memory only, bounded, and are never written or logged.
//!
//! [`Service`] holds the state (the design's MODEL and NET: the loaded model
//! and the network tag cache); its std mutexes are never held across an
//! await or any I/O.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use raven_core::clock::now_ms;
use raven_core::custody_gate::CustodyGates;
use raven_core::ipc::{IpcResponse, LearningCarry, LearningRow, LearningStatus, MAX_LEARNING_ROWS};
use raven_core::learning::carry::{self, Candidate, CARRY_CAP};
use raven_core::learning::estimate::DAY_MS;
use raven_core::learning::explain::{State, Why};
use raven_core::learning::model::{fail_prior_ms, ArmKey, Model, MAX_CONTACTS};
use raven_core::learning::observe::{evidence, DialTiming, FrameKind, Observation};
use raven_core::learning::rank::{self, Order};
use raven_core::learning::store::{self, PlatformSealer, SealError, Sealer, StoreState};
use raven_core::learning::wait::{self, WaitKind, Waits};
use raven_core::outbox::{DeliveryPath, OutboxCarrier, OutboxRoute};
use raven_core::reach_diag::{CircuitOutcome, Diag};
use tokio::sync::mpsc;

use crate::netutil::LogLimiter;
use crate::outbox::AttemptCtx;

/// Observations waiting for the service; past it they are dropped.
pub(crate) const INTAKE: usize = 256;
/// The user's switch is read again this often.
pub(crate) const POLICY_POLL: Duration = Duration::from_secs(2);
/// A changed model is saved this often.
pub(crate) const SAVE_EVERY: Duration = Duration::from_secs(60);
/// The save at shutdown waits at most this long.
pub(crate) const FINAL_SAVE_WAIT: Duration = Duration::from_secs(2);

/// The carriers learning ranks, in the static plan's order (nearby keeps its
/// static place and is never ranked).
const RANKED: [OutboxCarrier; 3] = [
    OutboxCarrier::Lan,
    OutboxCarrier::Internet,
    OutboxCarrier::P2p,
];

const HOUR_MS: u64 = 3_600_000;

/// The explorer looks for one probe this often (design §5).
pub(crate) const EXPLORE_TICK: Duration = Duration::from_secs(60);
/// A contact is explored only after a message dial to it (or, after a
/// restart, a receipt from it on this network) within this long.
pub(crate) const ACTIVE_MS: u64 = 7 * DAY_MS;
/// A LAN or Internet arm is explored only after a receipt over it on this
/// network within this long.
pub(crate) const RECEIPT_WITHIN_MS: u64 = 7 * DAY_MS;
/// An arm below its static place with a success streak is due again after
/// this long.
pub(crate) const RECOVER_GAP_MS: u64 = 15 * 60_000;
/// Any other arm is due again after this long.
pub(crate) const PROBE_ARM_GAP_MS: u64 = 60 * 60_000;
/// An arm observed this recently (or within its gap, if shorter) needs no
/// exploring.
const SEEN_GAP_CAP_MS: u64 = 30 * 60_000;
/// The global exploration budget: this many per hour...
pub(crate) const PROBES_PER_HOUR: u64 = 6;
/// ...and at most this many at once.
pub(crate) const PROBE_BURST: u64 = 2;
/// Nothing is explored this soon after a network change.
pub(crate) const SETTLE_MS: u64 = 2 * 60_000;
/// A probe waits this much longer than its carrier's connect wait.
pub(crate) const PROBE_SLACK: Duration = Duration::from_secs(5);
/// An owed-ACK batch explores an arm only when its failures cost at most
/// this (ms).
pub(crate) const ACK_EXPLORE_FAIL_MS: u32 = 10_000;
/// The budget counts in thousandths of a probe.
const MILLI: u64 = 1_000;

static SAVE_LOG: LogLimiter = LogLimiter::new(Duration::from_secs(600));
static CONTRADICTION_LOG: LogLimiter = LogLimiter::new(Duration::from_secs(600));

/// What the worker knows about a dial that the carrier does not (P6.13):
/// the carriers' `*_with_meta` dials take it; every other caller passes the
/// default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DialMeta {
    /// The dial resends an object that went silent before
    /// (`outbox::Entry::unacked_route`): its ACK may answer the earlier
    /// copy, so its reply time is no sample (Karn).
    pub karn_exclude: bool,
    /// An exploration probe's bound ([`crate::outbox::Dialer::probe_within`]):
    /// the carrier gives up after it (or its own deadline, if shorter), so
    /// the probe's failure still reaches learning through the carrier's
    /// hook instead of being dropped with the dial (review learning-8).
    pub within: Option<Duration>,
    /// The outbox race this dial is in ([`crate::onion::race`], the Tor
    /// carrier's "happy eyeballs"): it claims the attempt when its link
    /// authenticated, or writes nothing.
    pub race: Option<crate::onion::race::RaceTicket>,
}

impl DialMeta {
    /// The deadline of a carrier dial whose own is `own`: [`Self::within`]
    /// when it is shorter.
    pub(crate) fn deadline(self, own: Duration) -> Duration {
        self.within.map_or(own, |d| d.min(own))
    }
}

/// Which of a dial's waits ran out
/// ([`crate::netutil::DialProgress::expired`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Expired {
    /// A connect wait: one address's (LAN, Internet) or the p2p connect.
    pub connect: bool,
    /// The first-reply wait, after frames that get a reply were written.
    pub reply: bool,
}

/// What the channel carries to the service.
enum Msg {
    /// A dial's observation and the waits that ran out in it.
    Observe(Observation, Expired),
    Retract {
        contact: [u8; 32],
        carrier: OutboxCarrier,
        net: Option<String>,
        at_ms: u64,
    },
    Inbound {
        contact: [u8; 32],
        carrier: OutboxCarrier,
        net: Option<String>,
        via_relay: Option<Vec<u8>>,
        moved_local: bool,
        at_ms: u64,
    },
    Circuits {
        outcomes: Vec<(Vec<u8>, CircuitOutcome)>,
        at_ms: u64,
    },
    /// A Phase 6b security event about a relay (R8, P6.28's merge
    /// amendment): its PeerId bytes.
    RelaySecurity { relay: Vec<u8>, at_ms: u64 },
    /// An authenticated link with a verified contact (carry choice, P6.16).
    Encounter { peer: [u8; 32], at_ms: u64 },
    /// What became of an object for `recipient` that `holders` held.
    Carry {
        recipient: [u8; 32],
        holders: Vec<[u8; 32]>,
        delivered: bool,
        at_ms: u64,
    },
}

/// What carry choice knows about this profile (P6.16), refreshed by each
/// poll while learning is on and friend custody is live (empty otherwise):
/// whether custody is in use (OD6a-14: `raven custody use on`, or a
/// custodian listed for a verified contact) and the verified, unblocked
/// contacts (the only ones an encounter is kept for). Memory only.
#[derive(Debug, Default, PartialEq, Eq)]
struct CarryFacts {
    in_use: bool,
    pinned: BTreeSet<[u8; 32]>,
}

/// Counts over the last 24 hours, in hourly buckets (memory only).
#[derive(Clone, Copy, Debug, Default)]
struct Window([(u64, u32); 24]);

impl Window {
    fn add(&mut self, now_ms: u64) {
        let hour = now_ms / HOUR_MS;
        let slot = &mut self.0[(hour % 24) as usize];
        if slot.0 != hour {
            *slot = (hour, 0);
        }
        slot.1 = slot.1.saturating_add(1);
    }

    fn total(&self, now_ms: u64) -> u32 {
        let hour = now_ms / HOUR_MS;
        self.0
            .iter()
            .filter(|(at, _)| *at <= hour && hour - *at < 24)
            .fold(0u32, |n, (_, c)| n.saturating_add(*c))
    }
}

/// The loaded model and what the service knows about it.
struct Learner {
    dir: PathBuf,
    sealer: Arc<dyn Sealer + Send + Sync>,
    model: Model,
    /// What the load found, and so what may be written.
    store: StoreState,
    /// Changed since the last save.
    dirty: bool,
    saved_at_ms: Option<u64>,
    /// Evidence applied, observations not kept (not evidence, a network
    /// change mid-dial, a full channel) and worker plans whose learned
    /// order left the static one ([`planned`]).
    observed: Window,
    dropped: Window,
    would_reorder: Window,
    /// Exploration dials: probes and ACK explorations.
    probes: Window,
    /// When this node last dialled a message to a contact (memory only, at
    /// most [`MAX_CONTACTS`]): who is active.
    wrote: BTreeMap<[u8; 32], u64>,
    /// When the explorer last tried an arm (contact, network, carrier),
    /// whatever the dial said (memory only, bounded).
    explored: BTreeMap<([u8; 32], Option<String>, OutboxCarrier), u64>,
}

/// The arms [`Learner::explored`] remembers.
const MAX_EXPLORED: usize = 2 * MAX_CONTACTS * RANKED.len();

/// The exploration gaps (design §5), or the lab's ([`gaps`]).
#[derive(Clone, Copy, Debug)]
struct Gaps {
    probe_ms: u64,
    recover_ms: u64,
}

/// [`PROBE_ARM_GAP_MS`] and [`RECOVER_GAP_MS`], or what
/// `RAVEN_LAB_LEARNING_TUNE` gives (debug only; a release build never reads
/// it).
fn gaps() -> Gaps {
    match raven_core::learning::lab_tune() {
        Some(t) => Gaps {
            probe_ms: t.probe_gap_ms,
            recover_ms: t.recover_gap_ms,
        },
        None => Gaps {
            probe_ms: PROBE_ARM_GAP_MS,
            recover_ms: RECOVER_GAP_MS,
        },
    }
}

/// Keeps the `max` newest entries of `map`.
fn keep_newest<K: Ord + Clone>(map: &mut BTreeMap<K, u64>, max: usize) {
    while map.len() > max {
        let Some(oldest) = map
            .iter()
            .min_by_key(|(_, at)| **at)
            .map(|(k, _)| k.clone())
        else {
            return;
        };
        map.remove(&oldest);
    }
}

impl Learner {
    /// The state `Status` and the reason blocks show: on, unless nothing
    /// may be written or the file was started over.
    fn shown(&self) -> State {
        match self.store {
            StoreState::MemoryOnly(_) => State::MemoryOnly,
            StoreState::ResetAfterUnreadable => State::ResetAfterUnreadable,
            StoreState::On | StoreState::Shadow => State::On,
        }
    }

    /// May the explorer act at all? Not while the file is kept in memory
    /// because a newer Raven wrote it.
    fn may_explore(&self) -> bool {
        self.store != StoreState::MemoryOnly("newer")
    }

    /// Was `peer` written to lately: a message dial within [`ACTIVE_MS`], or
    /// (the dial notes are memory only) a receipt over any of its arms on
    /// network `net` within it?
    fn active(&self, peer: &[u8; 32], net: Option<&str>, now: u64) -> bool {
        let within = |at: u64| at != 0 && now.saturating_sub(at) <= ACTIVE_MS;
        self.wrote.get(peer).is_some_and(|at| within(*at))
            || RANKED.iter().any(|carrier| {
                let key = ArmKey {
                    contact: *peer,
                    net: net.map(str::to_owned),
                    carrier: *carrier,
                };
                self.model
                    .arm(&key)
                    .is_some_and(|a| within(a.last_receipt_ms))
            })
    }

    /// Is the arm `key` due for exploring at `now` (design §5), sitting at
    /// `pos` of the contact's current carrier order whose static order is
    /// `statics`? Its staleness (when anything last observed or explored
    /// it) if so. Never the top carrier or nearby; LAN and Internet only
    /// after a receipt on this network within [`RECEIPT_WITHIN_MS`].
    fn due(
        &self,
        key: &ArmKey,
        pos: usize,
        statics: &[OutboxCarrier],
        now: u64,
        gaps: Gaps,
    ) -> Option<u64> {
        if pos == 0 || !RANKED.contains(&key.carrier) {
            return None;
        }
        let static_pos = statics.iter().position(|c| *c == key.carrier)?;
        let arm = self.model.arm(key);
        if key.carrier != OutboxCarrier::P2p {
            let receipt = arm.map_or(0, |a| a.last_receipt_ms);
            if receipt == 0 || now.saturating_sub(receipt) > RECEIPT_WITHIN_MS {
                return None;
            }
        }
        let streak = arm.map_or(0, |a| a.beta.streak);
        let gap = if pos > static_pos && streak >= 1 {
            gaps.recover_ms
        } else {
            gaps.probe_ms
        };
        let tried = self
            .explored
            .get(&(key.contact, key.net.clone(), key.carrier))
            .copied()
            .unwrap_or(0)
            .max(arm.map_or(0, |a| a.last_probe_ms));
        let seen = arm.map_or(0, |a| a.last_obs_ms).max(tried);
        let elapsed = |at: u64| now.checked_sub(at);
        let rested = elapsed(seen).is_some_and(|d| d >= gap.min(SEEN_GAP_CAP_MS))
            && elapsed(tried).is_some_and(|d| d >= gap);
        rested.then_some(seen)
    }

    /// The explorer tried `contact`'s arm on `carrier` on `net` at `now`:
    /// one exploration dial counted.
    fn explored_at(
        &mut self,
        contact: &[u8; 32],
        net: Option<String>,
        carrier: OutboxCarrier,
        now: u64,
    ) {
        self.explored.insert((*contact, net, carrier), now);
        keep_newest(&mut self.explored, MAX_EXPLORED);
        self.probes.add(now);
    }
}

/// The exploration budget and its rails (design §5); memory only.
struct Explore {
    /// Thousandths of a probe left ([`PROBE_BURST`] at most)...
    tokens_m: u64,
    /// ...as of this time (`None`: never spent, so full).
    filled_ms: Option<u64>,
    /// A probe is being dialled.
    in_flight: bool,
    /// netwatch's last network change.
    changed_ms: Option<u64>,
}

impl Explore {
    const fn new() -> Self {
        Self {
            tokens_m: 0,
            filled_ms: None,
            in_flight: false,
            changed_ms: None,
        }
    }

    /// Tops the budget up for the time since the last top-up
    /// ([`PROBES_PER_HOUR`]), to [`PROBE_BURST`] at most; a clock that
    /// stepped back adds nothing.
    fn refill(&mut self, now: u64) {
        let cap = PROBE_BURST * MILLI;
        let per_hour = PROBES_PER_HOUR * MILLI;
        let Some(at) = self.filled_ms else {
            self.tokens_m = cap;
            self.filled_ms = Some(now);
            return;
        };
        let Some(elapsed) = now.checked_sub(at) else {
            self.filled_ms = Some(now);
            return;
        };
        let add = elapsed.saturating_mul(per_hour) / HOUR_MS;
        if self.tokens_m + add >= cap {
            self.tokens_m = cap;
            self.filled_ms = Some(now);
        } else {
            self.tokens_m += add;
            // What `add` paid for; the rest of `elapsed` counts next time.
            self.filled_ms = Some(at + add * HOUR_MS / per_hour);
        }
    }

    /// Nothing within [`SETTLE_MS`] of a network change.
    fn settling(&self, now: u64) -> bool {
        self.changed_ms
            .is_some_and(|at| now < at.saturating_add(SETTLE_MS))
    }

    /// May one exploration dial go now: settled, and a whole probe left?
    fn may_spend(&mut self, now: u64) -> bool {
        self.refill(now);
        !self.settling(now) && self.tokens_m >= MILLI
    }

    /// Spends one probe of the budget, if one is left (and settled).
    fn spend(&mut self, now: u64) -> bool {
        let ok = self.may_spend(now);
        if ok {
            self.tokens_m -= MILLI;
        }
        ok
    }
}

/// The one probe in flight ([`Service::begin_flight`]); ends when dropped.
struct Flight<'a>(&'a Service);

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        lock(&self.0.explore).in_flight = false;
    }
}

/// What one exploration tick did ([`Service::explore_once`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Explored {
    pub(crate) contact: [u8; 32],
    pub(crate) carrier: OutboxCarrier,
    /// The route probed, as planned.
    pub(crate) route: OutboxRoute,
    /// The probe authenticated a link.
    pub(crate) linked: bool,
}

/// The learning service's state: one per process ([`SERVICE`]); a test
/// installs its own for its thread ([`TestService`]).
pub(crate) struct Service {
    /// The learning gate (`learning_live`).
    gate: fn() -> bool,
    /// Reads this computer's network tag (`network_tag_for_learning`).
    tag: fn() -> Option<String>,
    /// MODEL: `None` until the service loads it (gate live and the user's
    /// switch on) and again once the switch goes off.
    model: Mutex<Option<Learner>>,
    /// NET: the network tag, refreshed at load and by netwatch.
    net: Mutex<Option<String>>,
    /// The user's switch as last read (and a model loaded).
    on: AtomicBool,
    intake: Mutex<Option<mpsc::Sender<Msg>>>,
    /// Held while the file is written or removed (saves and resets never
    /// interleave).
    file: Mutex<()>,
    /// The exploration budget, the probe in flight and the last network
    /// change; never held with the model's lock.
    explore: Mutex<Explore>,
    /// Carry choice's facts ([`CarryFacts`]); never held with the model's
    /// lock.
    carry: Mutex<CarryFacts>,
    /// A test's own wall clock for this service (0: Raven's clock).
    #[cfg(test)]
    clock: std::sync::atomic::AtomicU64,
    /// A test's network moved without netwatch acting on it yet: what
    /// [`test_tag`] reads (`None`: the cached tag, nothing moved).
    #[cfg(test)]
    egress: Mutex<Option<Option<String>>>,
}

static SERVICE: Service = Service::new(
    raven_core::learning::learning_live,
    raven_core::route_memory::network_tag_for_learning,
);

#[cfg(test)]
thread_local! {
    static TEST_SERVICE: std::cell::Cell<Option<&'static Service>> =
        const { std::cell::Cell::new(None) };
}

/// The process's service, or the current test thread's.
fn service() -> &'static Service {
    #[cfg(test)]
    if let Some(svc) = TEST_SERVICE.with(std::cell::Cell::get) {
        return svc;
    }
    &SERVICE
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Service {
    const fn new(gate: fn() -> bool, tag: fn() -> Option<String>) -> Self {
        Self {
            gate,
            tag,
            model: Mutex::new(None),
            net: Mutex::new(None),
            on: AtomicBool::new(false),
            intake: Mutex::new(None),
            file: Mutex::new(()),
            explore: Mutex::new(Explore::new()),
            carry: Mutex::new(CarryFacts {
                in_use: false,
                pinned: BTreeSet::new(),
            }),
            #[cfg(test)]
            clock: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            egress: Mutex::new(None),
        }
    }

    fn live_on(&self) -> bool {
        (self.gate)() && self.on.load(Ordering::Acquire)
    }

    /// Raven's wall clock ([`now_ms`]); a test may set its own service's
    /// ([`TestService::set_now`]).
    fn now(&self) -> u64 {
        #[cfg(test)]
        {
            let at = self.clock.load(Ordering::Acquire);
            if at != 0 {
                return at;
            }
        }
        now_ms()
    }

    fn net(&self) -> Option<String> {
        lock(&self.net).clone()
    }

    /// Into the channel; a full (or absent) channel counts as dropped.
    fn post(&self, msg: Msg) {
        let sent = lock(&self.intake)
            .as_ref()
            .is_some_and(|tx| tx.try_send(msg).is_ok());
        if !sent {
            self.dropped_one();
        }
    }

    /// The model goes (Lock v2: [`let_go`]); `on` with it, and carry
    /// choice's copy of the verified contacts' keys (read from the book the
    /// lock drops; a poll while locked reads none).
    fn let_go(&self) {
        *lock(&self.carry) = CarryFacts::default();
        if lock(&self.model).take().is_some() {
            self.on.store(false, Ordering::Release);
            eprintln!("raven-node learning: let go while Raven is locked");
        }
    }

    /// One observation that never reached the model, counted (`Status`).
    fn dropped_one(&self) {
        if let Some(l) = lock(&self.model).as_mut() {
            l.dropped.add(self.now());
        }
    }

    /// Applies one message to the model (nothing without one).
    fn apply(&self, msg: Msg) {
        let now = self.now();
        let mut held = lock(&self.model);
        let Some(l) = held.as_mut() else {
            return;
        };
        match msg {
            Msg::Observe(o, expired) => {
                // A message dial, whatever it gave: this contact is active
                // (exploration).
                if o.kind == FrameKind::Message {
                    let at = l.wrote.entry(o.contact).or_insert(0);
                    *at = (*at).max(o.at_ms);
                    keep_newest(&mut l.wrote, MAX_CONTACTS);
                }
                if o.net_changed
                    || o.carrier == OutboxCarrier::Nearby
                    || o.evidence.weight().is_none()
                {
                    l.dropped.add(now);
                    return;
                }
                l.model.observe(&o, o.at_ms);
                // A wait that ran out with no sample of it later in the same
                // dial (another address that linked is one) backs off.
                let net = o.net.as_deref();
                if expired.connect && o.timing.connect_ms.is_none() {
                    l.model
                        .rtt_expired(&o.contact, net, o.carrier, WaitKind::Connect);
                }
                if expired.reply && o.timing.reply_ms.is_none() {
                    l.model
                        .rtt_expired(&o.contact, net, o.carrier, WaitKind::Reply);
                }
                l.observed.add(now);
            }
            Msg::Retract {
                contact,
                carrier,
                net,
                at_ms,
            } => l.model.retract(&contact, net.as_deref(), carrier, at_ms),
            Msg::Inbound {
                contact,
                carrier,
                net,
                via_relay,
                moved_local,
                at_ms,
            } => {
                if let Some(relay) = via_relay {
                    l.model.relay_inbound(&relay, at_ms);
                }
                if moved_local {
                    l.model
                        .halve_doubt(&contact, net.as_deref(), carrier, at_ms);
                }
            }
            Msg::Circuits { outcomes, at_ms } => {
                for (relay, outcome) in outcomes {
                    l.model.relay_circuit(&relay, outcome, at_ms);
                }
            }
            Msg::RelaySecurity { relay, at_ms } => l.model.relay_security(&relay, at_ms),
            Msg::Encounter { peer, at_ms } => {
                l.model.encounter(&peer, at_ms);
            }
            Msg::Carry {
                recipient,
                holders,
                delivered,
                at_ms,
            } => l
                .model
                .carry_outcome(&recipient, &holders, delivered, at_ms),
        }
        l.dirty = true;
    }

    /// Reads the user's switch (only while the gate is live): on loads the
    /// model once, off saves what changed and lets it go. Nothing loads
    /// while Raven is locked (Lock v2), and a model still here then goes
    /// unsaved: the lock saved it while the key was there ([`save_for_lock`]).
    async fn poll(&'static self, dd: &Path, sealer: &Arc<dyn Sealer + Send + Sync>) {
        if crate::lock::is_locked() {
            self.let_go();
            return;
        }
        // The user's switch and, while friend custody is live, carry
        // choice's facts ([`CarryFacts`]): one blocking read of each file.
        let custody = CustodyGates::current().live;
        let (on, facts) = if (self.gate)() {
            let dd = dd.to_path_buf();
            tokio::task::spawn_blocking(move || {
                let policy = raven_core::node_policy::load_policy(&dd);
                let on = policy.learning != Some(false);
                let facts = if on && custody {
                    carry_facts(&dd, policy.custody_use == Some(true))
                } else {
                    CarryFacts::default()
                };
                (on, facts)
            })
            .await
            .unwrap_or_default()
        } else {
            (false, CarryFacts::default())
        };
        *lock(&self.carry) = facts;
        let loaded = lock(&self.model).is_some();
        if on && !loaded {
            let (dir, s, tag) = (dd.to_path_buf(), Arc::clone(sealer), self.tag);
            let now = self.now();
            let Ok((model, state, net)) = tokio::task::spawn_blocking(move || {
                let (model, state) = store::load(&dir, &*s, now);
                (model, state, tag())
            })
            .await
            else {
                return;
            };
            *lock(&self.net) = net;
            let learner = Learner {
                dir: dd.to_path_buf(),
                sealer: Arc::clone(sealer),
                model,
                store: state,
                dirty: false,
                saved_at_ms: None,
                observed: Window::default(),
                dropped: Window::default(),
                would_reorder: Window::default(),
                probes: Window::default(),
                wrote: BTreeMap::new(),
                explored: BTreeMap::new(),
            };
            let shown = learner.shown();
            *lock(&self.model) = Some(learner);
            self.on.store(true, Ordering::Release);
            eprintln!(
                "raven-node learning: {} (the learned carrier order is used)",
                shown.token()
            );
        } else if on {
            // A restarted service task finds the model still loaded.
            self.on.store(true, Ordering::Release);
            if self.key_awaited() {
                let svc: &'static Service = self;
                let _ = tokio::task::spawn_blocking(move || svc.load_when_key_is_back()).await;
            }
        } else if loaded {
            self.on.store(false, Ordering::Release);
            let svc: &'static Service = self;
            let _ = tokio::task::spawn_blocking(move || svc.save_now()).await;
            *lock(&self.model) = None;
            eprintln!("raven-node learning: off");
        }
    }

    /// The model was loaded memory only because the at-rest key was not
    /// here (`keystore`): the sealer is asked again at each poll
    /// ([`Self::load_when_key_is_back`]).
    fn key_awaited(&self) -> bool {
        lock(&self.model)
            .as_ref()
            .is_some_and(|l| l.store == StoreState::MemoryOnly("keystore"))
    }

    /// [`Self::key_awaited`], once the sealer can seal (the key loaded late:
    /// a keychain prompt at the start, its retries, an unlock whose key
    /// loader had not finished): the file is read again and its model
    /// replaces the one kept in memory, whose counts and explorer notes stay
    /// (its rows are under another secret and cannot be merged). With no
    /// file, the model learned in memory is kept and saved from now on. A
    /// profile that is not sealed stays memory only. Under the file lock
    /// (no save or reset in between). Blocking.
    fn load_when_key_is_back(&self) {
        let _file = lock(&self.file);
        let (dir, sealer) = {
            let held = lock(&self.model);
            let Some(l) = held
                .as_ref()
                .filter(|l| l.store == StoreState::MemoryOnly("keystore"))
            else {
                return;
            };
            (l.dir.clone(), Arc::clone(&l.sealer))
        };
        if sealer.protect(&dir, store::MAGIC).is_err() {
            return;
        }
        let on_disk = std::fs::symlink_metadata(dir.join(store::LEARNING_FILE)).is_ok();
        let loaded = on_disk.then(|| store::load(&dir, &*sealer, self.now()));
        if matches!(loaded, Some((_, StoreState::MemoryOnly("keystore")))) {
            return;
        }
        let mut held = lock(&self.model);
        let Some(l) = held
            .as_mut()
            .filter(|l| l.store == StoreState::MemoryOnly("keystore"))
        else {
            return;
        };
        match loaded {
            Some((model, state)) if state != StoreState::ResetAfterUnreadable => {
                l.model = model;
                l.store = state;
                l.dirty = false;
            }
            // No file, or one that does not open (the next save replaces
            // it): nothing to read, so what was learned meanwhile stays.
            other => {
                let state = other.map_or(StoreState::On, |(_, state)| state);
                l.store = state;
                l.model.state = state.state();
                l.dirty = true;
            }
        }
        eprintln!(
            "raven-node learning: {} (the at-rest key is here now)",
            l.shown().token()
        );
    }

    /// Saves the model when it changed and may be written: copied under its
    /// lock, sealed and written outside it, under the file lock. A key that
    /// is not here (Lock, a keystore slow to answer) is tried again at the
    /// next save; the first save of a model started over makes it `on`
    /// again. Blocking.
    fn save_now(&self) {
        let _file = lock(&self.file);
        let job = {
            let mut held = lock(&self.model);
            let Some(l) = held.as_mut() else {
                return;
            };
            if !l.dirty || l.model.state == State::MemoryOnly {
                return;
            }
            l.dirty = false;
            (l.dir.clone(), Arc::clone(&l.sealer), l.model.clone())
        };
        let (dir, sealer, model) = job;
        let at = self.now();
        let saved = store::save(&dir, &*sealer, &model, at);
        drop(model);
        let mut held = lock(&self.model);
        let Some(l) = held.as_mut() else {
            return;
        };
        match saved {
            Ok(()) => {
                l.saved_at_ms = Some(at);
                if l.store == StoreState::ResetAfterUnreadable {
                    l.store = StoreState::On;
                    l.model.state = State::On;
                }
            }
            // The key is not here for now (it is loading, or Raven is being
            // locked): kept, and tried again at the next save. Turning the
            // model memory only would stop it being saved for the whole run.
            Err(e) if e.contains(&SealError::Unavailable.to_string()) => {
                l.dirty = true;
                if let Some(n) = SAVE_LOG.hit_at(std::time::Instant::now()) {
                    eprintln!(
                        "raven-node learning: the at-rest key is unavailable; not saved ({n}x), \
                         tried again later"
                    );
                }
            }
            Err(_) => {
                l.dirty = true;
                if let Some(n) = SAVE_LOG.hit_at(std::time::Instant::now()) {
                    eprintln!("raven-node learning: not saved ({n}x); tried again later");
                }
            }
        }
    }

    /// The waits of a dial to `contact` over `carrier` on this network
    /// (`wait::waits`); today's while learning is off. Reads only.
    fn waits(&self, contact: &[u8; 32], carrier: OutboxCarrier) -> Waits {
        if !self.live_on() {
            return wait::statics(carrier);
        }
        let key = ArmKey {
            contact: *contact,
            net: self.net(),
            carrier,
        };
        let now = self.now();
        let held = lock(&self.model);
        match held.as_ref() {
            Some(l) => wait::waits(l.model.arm(&key), carrier, now),
            None => wait::statics(carrier),
        }
    }

    /// The relay term of each of `relays` (PeerId bytes), in that order;
    /// empty while learning is off. Reads only.
    fn relay_terms(&self, relays: &[Vec<u8>]) -> Vec<i64> {
        if !self.live_on() {
            return Vec::new();
        }
        let now = self.now();
        lock(&self.model)
            .as_ref()
            .map_or_else(Vec::new, |l| l.model.relay_terms(relays, now))
    }

    /// Carry choice is live (P6.16): learning on, friend custody live and
    /// in use ([`CarryFacts::in_use`], OD6a-14).
    fn carry_live(&self) -> bool {
        self.live_on() && CustodyGates::current().live && lock(&self.carry).in_use
    }

    /// Carry choice's pick for `recipient` from `cands` (their static
    /// order; `learning::carry`); `None` while carry choice is not live.
    /// Reads only.
    fn carry_pick(
        &self,
        recipient: &[u8; 32],
        cands: &[Candidate],
    ) -> Option<(Vec<[u8; 32]>, Why)> {
        if !self.carry_live() {
            return None;
        }
        let now = self.now();
        lock(&self.model)
            .as_ref()
            .map(|l| l.model.carry_pick(recipient, cands, CARRY_CAP, now))
    }

    /// `LearningPlan`'s carry rows for `recipient` from `cands`: the pick in
    /// its order with each custodian's words while it is learned
    /// (`carry=ranked`); none while cold or carry choice is not live. Reads
    /// only.
    fn carry_rows(&self, recipient: &[u8; 32], cands: &[Candidate]) -> Vec<LearningCarry> {
        if !self.carry_live() {
            return Vec::new();
        }
        let now = self.now();
        let held = lock(&self.model);
        let Some(l) = held.as_ref() else {
            return Vec::new();
        };
        let (pick, why) = l.model.carry_pick(recipient, cands, CARRY_CAP, now);
        if why == Why::Cold {
            return Vec::new();
        }
        pick.iter()
            .map(|c| {
                let (delivered, outcomes) = l.model.carry_record(c, recipient, now);
                LearningCarry {
                    peer_pub_hex: hex::encode(c),
                    met: carry::met_word(l.model.predict_q16(c, now)).into(),
                    delivered,
                    outcomes,
                }
            })
            .collect()
    }

    /// `hops` in this node's own order of meeting them
    /// (`Model::forward_order`); `None` while carry choice is not live.
    fn forward_order(&self, hops: &[[u8; 32]]) -> Option<Vec<[u8; 32]>> {
        if !self.carry_live() {
            return None;
        }
        let now = self.now();
        lock(&self.model)
            .as_ref()
            .map(|l| l.model.forward_order(hops, now))
    }

    /// The learned order for `peer` from `static_carriers` on this network,
    /// and that network's tag. Reads only.
    fn plan(
        &self,
        peer: &[u8; 32],
        static_carriers: &[OutboxCarrier],
    ) -> Option<(Order, Option<String>)> {
        if !self.live_on() {
            return None;
        }
        let net = self.net();
        let now = self.now();
        let held = lock(&self.model);
        let l = held.as_ref()?;
        let order = rank::order(&l.model, peer, net.as_deref(), static_carriers, None, now);
        Some((order, net))
    }

    /// `order` was applied to `peer`'s plans on `net` and an attempt reached
    /// the contact: the next ranking starts from it (memory only).
    fn remember_order(&self, peer: &[u8; 32], net: Option<&str>, order: &Order) {
        if !self.live_on() {
            return;
        }
        if let Some(l) = lock(&self.model).as_mut() {
            l.model.remember_order(peer, net, order);
        }
    }

    /// A learned order did not give a pure reorder of a plan of `peer` on
    /// `net`: counted, and that contact-network is pinned to the static
    /// order for an hour. The contradictions so far.
    fn contradiction(&self, peer: &[u8; 32], net: Option<&str>) -> Option<u32> {
        if !self.live_on() {
            return None;
        }
        let mut held = lock(&self.model);
        let l = held.as_mut()?;
        l.model.note_contradiction(peer, net, self.now());
        l.dirty = true;
        Some(l.model.counters().contradictions)
    }

    /// A worker plan used `order` where `static_carriers` was the static
    /// order: counted when they differ.
    fn planned(&self, order: &Order, static_carriers: &[OutboxCarrier]) {
        if !self.live_on() {
            return;
        }
        let fixed = Order::fixed(static_carriers, Why::Kept, State::On);
        if order.carriers != fixed.carriers {
            if let Some(l) = lock(&self.model).as_mut() {
                l.would_reorder.add(self.now());
            }
        }
    }

    /// `Status.learning` at `now`, rows for `contacts` (the contact book's
    /// keys) on the current network.
    fn status_of(&self, contacts: &[[u8; 32]], now: u64) -> LearningStatus {
        let net = self.net();
        let held = lock(&self.model);
        let Some(l) = held.as_ref() else {
            return LearningStatus {
                state: State::Off.token().into(),
                ..LearningStatus::default()
            };
        };
        let shown = l.shown();
        let mut rows: Vec<(u64, LearningRow)> = Vec::new();
        for contact in contacts {
            let mut newest = None;
            let mut carriers = Vec::with_capacity(RANKED.len());
            for carrier in RANKED {
                let key = ArmKey {
                    contact: *contact,
                    net: net.clone(),
                    carrier,
                };
                if let Some(arm) = l.model.arm(&key) {
                    carriers.push(carrier);
                    newest = newest.max(Some(arm.last_obs_ms));
                }
            }
            let Some(newest) = newest else {
                continue;
            };
            let order = rank::order(&l.model, contact, net.as_deref(), &carriers, None, now);
            rows.push((
                newest,
                LearningRow {
                    peer_pub_hex: hex::encode(contact),
                    order: order.carriers.iter().map(|c| c.label().into()).collect(),
                    why: order.render(),
                },
            ));
        }
        rows.sort_by_key(|row| std::cmp::Reverse(row.0));
        rows.truncate(MAX_LEARNING_ROWS);
        let sizes = l.model.sizes();
        LearningStatus {
            state: shown.token().into(),
            contacts: sizes.contacts,
            networks: sizes.networks,
            relays: sizes.relays,
            carriers: sizes.carry,
            observations_24h: l.observed.total(now),
            probes_24h: l.probes.total(now),
            dropped_24h: l.dropped.total(now),
            contradictions: l.model.counters().contradictions,
            would_reorder_24h: l.would_reorder.total(now),
            saved_age_s: l
                .saved_at_ms
                .filter(|_| shown != State::MemoryOnly)
                .map(|at| now.saturating_sub(at) / 1000),
            rows: rows.into_iter().map(|(_, row)| row).collect(),
        }
    }

    /// Forgets `peer` (or everyone): in memory when loaded, and on disk (a
    /// contact's rows saved without them, everyone's file removed). The
    /// contacts whose rows went. A file that is not read (the model is
    /// memory only: the key not here yet, a newer Raven's file) cannot lose
    /// one contact's rows: an error, never "cleared 0" while the rows stay
    /// (ash's own reset says the same). Blocking.
    fn reset(&self, dd: &Path, peer: Option<[u8; 32]>) -> Result<u32, String> {
        const UNREAD: &str = "the learning file cannot be opened now; nothing was forgotten";
        let _file = lock(&self.file);
        let now = self.now();
        // No file: nothing to remove or rewrite (and no lock file made).
        let on_disk = std::fs::symlink_metadata(dd.join(store::LEARNING_FILE)).is_ok();
        let unread = lock(&self.model)
            .as_ref()
            .is_some_and(|l| matches!(l.store, StoreState::MemoryOnly(_)));
        if peer.is_some() && on_disk && unread {
            return Err(UNREAD.into());
        }
        let loaded = {
            let mut held = lock(&self.model);
            held.as_mut().map(|l| {
                let cleared = forget(&mut l.model, peer);
                l.dirty = false;
                if peer.is_none() {
                    l.saved_at_ms = None;
                }
                let save = (peer.is_some() && l.model.state != State::MemoryOnly)
                    .then(|| (Arc::clone(&l.sealer), l.model.clone()));
                (cleared, save)
            })
        };
        match (loaded, peer) {
            (Some((cleared, _)), None) => {
                if on_disk {
                    store::delete(dd)?;
                }
                Ok(cleared)
            }
            (Some((cleared, save)), Some(_)) => {
                if let Some((sealer, model)) = save {
                    store::save(dd, &*sealer, &model, now)?;
                    if let Some(l) = lock(&self.model).as_mut() {
                        l.saved_at_ms = Some(now);
                    }
                }
                Ok(cleared)
            }
            (None, _) if !on_disk => Ok(0),
            (None, None) => {
                let (mut model, _) = store::load(dd, &PlatformSealer, now);
                let cleared = forget(&mut model, None);
                store::delete(dd)?;
                Ok(cleared)
            }
            (None, Some(_)) => {
                let (mut model, state) = store::load(dd, &PlatformSealer, now);
                if matches!(state, StoreState::MemoryOnly(_)) {
                    return Err(UNREAD.into());
                }
                let cleared = forget(&mut model, peer);
                if cleared > 0 {
                    store::save(dd, &PlatformSealer, &model, now)?;
                }
                Ok(cleared)
            }
        }
    }
}

/// Forgets `peer`'s rows (1 when it had any) or every row (the contacts
/// that had arms).
fn forget(model: &mut Model, peer: Option<[u8; 32]>) -> u32 {
    match peer {
        Some(p) => u32::from(model.forget_contact(&p) > 0),
        None => {
            let contacts = model.sizes().contacts;
            model.forget_all();
            contacts
        }
    }
}

// ── The hooks (no I/O) ──────────────────────────────────────────────────────

/// Learning is on in this process: the gate is live, the user's switch on
/// (read every [`POLICY_POLL`]) and the model loaded.
pub(crate) fn live_on() -> bool {
    service().live_on()
}

/// The network tag a dial starts on (pass it to [`observe_dial`]); `None`
/// while learning is off.
pub(crate) fn net() -> Option<String> {
    let svc = service();
    if !svc.live_on() {
        return None;
    }
    svc.net()
}

/// The code the learning table knows a failed dial by: the Phase 2 reason
/// token when the error carries the p2p reason block, else the stable dial
/// code.
fn fail_code(e: &str) -> &'static str {
    match Diag::find(e) {
        Some(d) => d.why.token(),
        None => crate::outbox::dial_error_code(e),
    }
}

/// One carrier dial ended (`result`, Ok or Err) to `contact` over
/// `carrier`: its path, the relay of a relayed path (PeerId bytes), what it
/// carried, its times ([`crate::netutil::DialProgress::timing`]), the waits
/// that ran out in it ([`crate::netutil::DialProgress::expired`]), the
/// worker's facts about it ([`DialMeta`]) and the network tag it started on
/// ([`net`]). No I/O but one look at this computer's egress tag (a UDP
/// connect, nothing sent): classified and posted to the service; nothing
/// while learning is off. A network change during the dial is not
/// evidence, whether or not netwatch acted on it yet.
// The design's hook signature: each argument is one fact of the dial.
#[allow(clippy::too_many_arguments)]
pub(crate) fn observe_dial(
    contact: &[u8; 32],
    carrier: OutboxCarrier,
    path: Option<DeliveryPath>,
    relay: Option<Vec<u8>>,
    frames: &[Vec<u8>],
    result: &Result<Vec<Vec<u8>>, String>,
    t: &DialTiming,
    expired: Expired,
    meta: DialMeta,
    net_at_start: Option<String>,
) {
    // A dial that lost the outbox race wrote nothing and says nothing about
    // its route (it authenticated; the other path was only quicker).
    if result
        .as_ref()
        .err()
        .is_some_and(|e| crate::onion::race::is_race_lost(e))
    {
        return;
    }
    let svc = service();
    if !svc.live_on() {
        return;
    }
    // A dial whose link was tampered with (`SEC_LINK_TAG_FAIL`, Phase 6b
    // P6.24's merge amendment, 6b risk 7) teaches nothing, so whoever breaks
    // some links cannot steer the learned order: dropped, and counted so.
    if crate::security::take_excluded_dial(contact, carrier) {
        svc.dropped_one();
        return;
    }
    // The network moved during the dial: netwatch refreshed the cached tag,
    // or it has not yet (its debounce, a change its gap holds, a default
    // route its next poll finds moved), so the tag read now (the egress
    // addresses: a UDP connect, nothing sent) is another (review
    // learning-5).
    let cached = svc.net();
    let net_changed = cached != net_at_start || (svc.tag)() != cached;
    let kind = FrameKind::of(frames);
    let code = result.as_ref().err().map(|e| fail_code(e));
    let ok = result.as_ref().ok().map(Vec::as_slice);
    let evidence = evidence(kind, ok, !frames.is_empty(), code, net_changed);
    svc.post(Msg::Observe(
        Observation {
            contact: *contact,
            net: net_at_start,
            net_changed,
            carrier,
            path,
            relay: relay.filter(|_| path == Some(DeliveryPath::Relayed)),
            kind,
            evidence,
            timing: *t,
            karn_exclude: meta.karn_exclude,
            at_ms: svc.now(),
        },
        expired,
    ));
    // An authenticated link with a verified contact (carry choice).
    if result.is_ok() {
        encounter(contact);
    }
}

/// The waits of a dial to `contact` over `carrier` (design §4,
/// `learning::wait`): a warm, fresh arm's on this network, never above
/// today's; today's ([`wait::statics`]) while learning is off or the arm is
/// cold. The carriers' dials ask it once, at their start.
pub(crate) fn waits(contact: &[u8; 32], carrier: OutboxCarrier) -> Waits {
    service().waits(contact, carrier)
}

/// The worker refused every ACK a dial to `contact` over `carrier` at
/// `at_ms` brought back: the receipt it was credited with is taken back.
pub(crate) fn retract(contact: &[u8; 32], carrier: OutboxCarrier, at_ms: u64) {
    let svc = service();
    if !svc.live_on() {
        return;
    }
    svc.post(Msg::Retract {
        contact: *contact,
        carrier,
        net: svc.net(),
        at_ms,
    });
}

/// A contact's authenticated inbound link over `carrier`: over our
/// reservation on relay `via_relay` (PeerId bytes) it counts for that
/// relay; `moved_local` (it reached us from a new address on the local
/// network) halves the doubt of its arm on this network.
pub(crate) fn inbound(
    contact: &[u8; 32],
    carrier: OutboxCarrier,
    via_relay: Option<Vec<u8>>,
    moved_local: bool,
) {
    let svc = service();
    if !svc.live_on() || (via_relay.is_none() && !moved_local) {
        return;
    }
    svc.post(Msg::Inbound {
        contact: *contact,
        carrier,
        net: svc.net(),
        via_relay,
        moved_local,
        at_ms: svc.now(),
    });
}

/// What each relay of a failed p2p dial answered our circuit request
/// (relay PeerId bytes): the relay rows.
pub(crate) fn circuits(outcomes: Vec<(Vec<u8>, CircuitOutcome)>) {
    let svc = service();
    if !svc.live_on() || outcomes.is_empty() {
        return;
    }
    svc.post(Msg::Circuits {
        outcomes,
        at_ms: svc.now(),
    });
}

/// A Phase 6b security event about the relay with PeerId bytes `relay`
/// (`SEC_RELAY_LINK_BROKEN`, or a Suspicious `SEC_RELAY_NO_RECEIPT`; R8 for
/// a profile that learns, P6.28's merge amendment): a negative-only signal
/// to its relay term (`Model::relay_security`, bounded like the term).
/// Nothing while learning is off: R8 then puts the relay last for an hour
/// (`crate::security`).
pub(crate) fn relay_security_signal(relay: &[u8]) {
    let svc = service();
    if !svc.live_on() {
        return;
    }
    svc.post(Msg::RelaySecurity {
        relay: relay.to_vec(),
        at_ms: svc.now(),
    });
}

/// Learning's term of each of `relays` (PeerId bytes, design §6,
/// `learning::relay::term`: at most ±150, 0 below its evidence threshold),
/// in the same order: what relay selection adds to an offered relay's score
/// and what orders a contact dial's circuits (`p2p`). Empty while learning
/// is off. Reads only.
pub(crate) fn relay_terms(relays: &[Vec<u8>]) -> Vec<i64> {
    service().relay_terms(relays)
}

/// netwatch saw the network change (or go): the tag is read again, and
/// nothing is explored for [`SETTLE_MS`]. Nothing while the gate is shut.
pub(crate) fn network_changed() {
    let svc = service();
    if !(svc.gate)() {
        return;
    }
    let tag = (svc.tag)();
    *lock(&svc.net) = tag;
    lock(&svc.explore).changed_ms = Some(svc.now());
}

/// The learned order for `peer` given the static plan's carriers
/// (`rank::carriers_of` of its plain plan), and the network tag it was
/// ranked on (pass it to [`remember_order`] and [`contradiction`]); `None`
/// while learning is off. Reads only.
pub(crate) fn plan(
    peer: &[u8; 32],
    static_carriers: &[OutboxCarrier],
) -> Option<(Order, Option<String>)> {
    service().plan(peer, static_carriers)
}

/// The worker applied `order` to `peer`'s plans on `net` and the attempt
/// reached the contact: the hysteresis of the next ranking starts from it.
/// Nothing while learning is off.
pub(crate) fn remember_order(peer: &[u8; 32], net: Option<&str>, order: &Order) {
    service().remember_order(peer, net, order);
}

/// A plan of `peer` on `net` got a learned order that is no pure reorder of
/// it (`RoutePlan::learning_contradiction`; the caller used the static
/// plan): counted, the contact-network pinned to the static order for an
/// hour (`Model::note_contradiction`), and one count-only line logged.
/// Nothing while learning is off.
pub(crate) fn contradiction(peer: &[u8; 32], net: Option<&str>) {
    if let Some(n) = service().contradiction(peer, net) {
        if CONTRADICTION_LOG
            .hit_at(std::time::Instant::now())
            .is_some()
        {
            eprintln!(
                "raven-node learning: a learned order did not fit a plan; the static order is \
                 used for an hour ({n} so far)"
            );
        }
    }
}

/// A worker attempt planned with `order` where the static order was
/// `static_carriers`: counted (`would_reorder_24h`) when they differ.
pub(crate) fn planned(order: &Order, static_carriers: &[OutboxCarrier]) {
    service().planned(order, static_carriers);
}

// ── Carry choice (design §7, P6.16) ─────────────────────────────────────────

/// Carry choice is live: learning on, friend custody live
/// (`CustodyGates::current`) and in use (`raven custody use on`, or a
/// custodian listed for a verified contact: OD6a-14). Without it no
/// encounter or carry outcome is kept and every pick is today's.
pub(crate) fn carry_live() -> bool {
    service().carry_live()
}

/// An authenticated link with `peer` (either direction, a beacon answer, a
/// nearby pipe up): one encounter, merged with the last one within 30 min
/// (`Model::encounter`). Kept only while carry choice is live and `peer` is
/// a verified, unblocked contact. No I/O.
pub(crate) fn encounter(peer: &[u8; 32]) {
    let svc = service();
    if !svc.live_on() || !CustodyGates::current().live {
        return;
    }
    let keep = {
        let facts = lock(&svc.carry);
        facts.in_use && facts.pinned.contains(peer)
    };
    if keep {
        svc.post(Msg::Encounter {
            peer: *peer,
            at_ms: svc.now(),
        });
    }
}

/// The custodians to leave `recipient`'s mail with, from `cands`
/// (`custody_client::custodian_candidates`, their order and offers): carry
/// choice's pick of at most [`CARRY_CAP`] in its order, with why (cold:
/// today's choice); `None` while carry choice is not live (the caller keeps
/// `deposit_custodians`). Always a subset of `cands`. No I/O.
pub(crate) fn carry_pick(
    recipient: &[u8; 32],
    cands: &[([u8; 32], Option<u8>)],
) -> Option<(crate::outbox::CustodySet, Why)> {
    let cs: Vec<Candidate> = cands.iter().map(|(k, o)| Candidate::of(*k, *o)).collect();
    let (keys, why) = service().carry_pick(recipient, &cs)?;
    let picked = keys
        .iter()
        .filter_map(|k| cands.iter().find(|(c, _)| c == k).copied())
        .collect();
    Some((picked, why))
}

/// What became of an object for `recipient` that `holders` (custodians)
/// held: a verified receipt (`delivered`) or its expiry or park without
/// one. Each holder's carry row gets its share. Nothing while carry choice
/// is not live or without a holder. No I/O.
pub(crate) fn carry_outcome(recipient: &[u8; 32], holders: &[[u8; 32]], delivered: bool) {
    let svc = service();
    if holders.is_empty() || !svc.carry_live() {
        return;
    }
    svc.post(Msg::Carry {
        recipient: *recipient,
        holders: holders.to_vec(),
        delivered,
        at_ms: svc.now(),
    });
}

/// A forwarder's next hops in the order it visits them: by this node's own
/// predictability of meeting each (order only) while carry choice is live,
/// else as given. Always the same hops. Reads only.
pub(crate) fn forward_order(hops: &[[u8; 32]]) -> Vec<[u8; 32]> {
    service()
        .forward_order(hops)
        .unwrap_or_else(|| hops.to_vec())
}

/// [`CarryFacts`] of the profile at `dd` (blocking: the book and the block
/// list): the verified, unblocked contacts, and custody in use with the
/// user's consent (`consent`) or a custodian listed for one of them that is
/// one too. An unreadable book: no contact.
fn carry_facts(dd: &Path, consent: bool) -> CarryFacts {
    #[derive(serde::Deserialize)]
    struct Row {
        #[serde(default)]
        pub_hex: String,
        #[serde(default)]
        custodians: Vec<String>,
    }
    let pinned: BTreeSet<[u8; 32]> = raven_core::outbox::pinned_unblocked_contacts(dd)
        .unwrap_or_default()
        .into_iter()
        .collect();
    let listed = || {
        let rows: Vec<Row> = raven_core::contact_book::read_rows(dd)
            .ok()
            .flatten()
            .unwrap_or_default();
        rows.iter().any(|row| {
            parse_key(&row.pub_hex).is_some_and(|k| {
                pinned.contains(&k)
                    && row
                        .custodians
                        .iter()
                        .filter_map(|c| parse_key(c))
                        .any(|c| c != k && pinned.contains(&c))
            })
        })
    };
    let in_use = consent || listed();
    CarryFacts { in_use, pinned }
}

// ── Exploration (design §5) ─────────────────────────────────────────────────

impl Service {
    /// The one probe in flight, unless one already is.
    fn begin_flight(&self) -> Option<Flight<'_>> {
        let mut e = lock(&self.explore);
        if e.in_flight {
            return None;
        }
        e.in_flight = true;
        Some(Flight(self))
    }

    /// The stalest due arm ([`Learner::due`]) among `plans` (a contact, its
    /// current carrier order and its static one) on network `net` at `now`
    /// that `accept` also takes, as (contact, carrier).
    fn stalest(
        &self,
        plans: &[([u8; 32], Vec<OutboxCarrier>, Vec<OutboxCarrier>)],
        net: Option<&str>,
        now: u64,
        accept: impl Fn(&Learner, &ArmKey) -> bool,
    ) -> Option<([u8; 32], OutboxCarrier)> {
        let gaps = gaps();
        let held = lock(&self.model);
        let l = held.as_ref()?;
        let mut best: Option<(u64, [u8; 32], usize, OutboxCarrier)> = None;
        for (peer, current, statics) in plans {
            for (pos, carrier) in current.iter().enumerate() {
                let key = ArmKey {
                    contact: *peer,
                    net: net.map(str::to_owned),
                    carrier: *carrier,
                };
                let Some(seen) = l.due(&key, pos, statics, now, gaps) else {
                    continue;
                };
                if !accept(l, &key) {
                    continue;
                }
                let case = (seen, *peer, pos, *carrier);
                if best.as_ref().is_none_or(|b| case < *b) {
                    best = Some(case);
                }
            }
        }
        best.map(|(_, peer, _, carrier)| (peer, carrier))
    }

    /// One exploration tick over the worker's context (design §5): at most
    /// one frame-less probe of the stalest due arm of an active, verified
    /// contact, within the budget. What it probed, if anything. Blocking
    /// (the book, the plans, the dial).
    fn explore_once(&self, ctx: &AttemptCtx) -> Option<Explored> {
        if !self.live_on() {
            return None;
        }
        let _flight = self.begin_flight()?;
        let now = self.now();
        if !lock(&self.explore).may_spend(now) {
            return None;
        }
        let net = self.net();
        // Verified, unblocked contacts (one read of the book and the block
        // list) whose sending the user did not pause (Phase 6b P6.31: nothing
        // is dialled to one, not even a probe), then the active ones.
        let mut book = raven_core::outbox::pinned_unblocked_contacts(&ctx.data_dir).ok()?;
        let policy = raven_core::node_policy::load_policy(&ctx.data_dir);
        book.retain(|p| !policy.send_held(p));
        let active: Vec<[u8; 32]> = {
            let held = lock(&self.model);
            let l = held.as_ref().filter(|l| l.may_explore())?;
            book.into_iter()
                .filter(|p| l.active(p, net.as_deref(), now))
                .collect()
        };
        // Each one's plan as a dial makes it now (admission again, the
        // gates, hide-IP, the learned order); no lock held.
        let mut routes: BTreeMap<[u8; 32], Vec<OutboxRoute>> = BTreeMap::new();
        let mut plans = Vec::with_capacity(active.len());
        for peer in active {
            if let Some((planned, statics)) = crate::outbox::explore_plan(ctx, &peer) {
                plans.push((peer, rank::carriers_of(&planned), statics));
                routes.insert(peer, planned);
            }
        }
        let (peer, carrier) = self.stalest(&plans, net.as_deref(), now, |_, _| true)?;
        let (route, dial) = crate::outbox::probe_route(routes.get(&peer)?, carrier, true)?;
        if !lock(&self.explore).spend(now) {
            return None;
        }
        if let Some(l) = lock(&self.model).as_mut() {
            l.explored_at(&peer, net, carrier, now);
        }
        let deadline = self.waits(&peer, carrier).connect + PROBE_SLACK;
        let linked = ctx
            .dialer
            .probe_within(&ctx.data_dir, &dial, &hex::encode(peer), deadline)
            .is_ok();
        Some(Explored {
            contact: peer,
            carrier,
            route,
            linked,
        })
    }

    /// One exploration tick on the blocking pool, with the worker's context
    /// (`ctx_of`: none, no tick). Nothing while learning is off.
    fn explore_in_background(&'static self, ctx_of: fn() -> Option<Arc<AttemptCtx>>) {
        if !self.live_on() {
            return;
        }
        let Some(ctx) = ctx_of() else {
            return;
        };
        tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            let _here = OnThread::enter(self);
            let _ = self.explore_once(&ctx);
        });
    }

    /// [`explore_ack_order`] on this service.
    fn explore_ack(
        &self,
        peer: &[u8; 32],
        pinned: bool,
        statics: &[OutboxCarrier],
        routes: &mut Vec<(OutboxRoute, OutboxRoute)>,
    ) -> Option<OutboxCarrier> {
        if !pinned || !self.live_on() {
            return None;
        }
        let now = self.now();
        {
            let mut e = lock(&self.explore);
            if e.in_flight || !e.may_spend(now) {
                return None;
            }
        }
        let net = self.net();
        let planned: Vec<OutboxRoute> = routes.iter().map(|(p, _)| p.clone()).collect();
        let plans = [(*peer, rank::carriers_of(&planned), statics.to_vec())];
        let (_, carrier) = self.stalest(&plans, net.as_deref(), now, |l, key| {
            let fail_ms = l
                .model
                .arm(key)
                .map_or_else(|| fail_prior_ms(key.carrier), |a| a.fail_ms);
            l.may_explore()
                && l.active(peer, key.net.as_deref(), now)
                && fail_ms <= ACK_EXPLORE_FAIL_MS
        })?;
        if !lock(&self.explore).spend(now) {
            return None;
        }
        if let Some(l) = lock(&self.model).as_mut() {
            l.explored_at(peer, net, carrier, now);
        }
        // A stable move: that carrier's routes first, the rest in order.
        let (mut first, rest): (Vec<_>, Vec<_>) = std::mem::take(routes)
            .into_iter()
            .partition(|(p, _)| p.carrier == carrier);
        first.extend(rest);
        *routes = first;
        Some(carrier)
    }
}

/// ACK-only exploration (design §5), from the worker's attempt on `peer`
/// when its batch holds owed ACKs and ACK rows and no message: the
/// stalest due arm of `routes` (the owed ACKs' routes, as (planned,
/// dialled); `statics` the contact's static carrier order) whose failures
/// cost at most [`ACK_EXPLORE_FAIL_MS`] goes first, within the exploration
/// budget. Never for an unverified contact, never the top carrier; nothing
/// while learning is off. The carrier moved, if any.
pub(crate) fn explore_ack_order(
    peer: &[u8; 32],
    pinned: bool,
    statics: &[OutboxCarrier],
    routes: &mut Vec<(OutboxRoute, OutboxRoute)>,
) -> Option<OutboxCarrier> {
    service().explore_ack(peer, pinned, statics, routes)
}

// ── Status and IPC (blocking) ───────────────────────────────────────────────

/// IPC `Status` `learning`: `None` while the gate is shut, `off` while the
/// user's switch is off, else the state, counts and rows (current network,
/// newest first, at most [`MAX_LEARNING_ROWS`]). Blocking (reads the
/// contact book first, never under the model's lock).
pub(crate) fn status(data_dir: &Path) -> Option<LearningStatus> {
    let svc = service();
    if !(svc.gate)() {
        return None;
    }
    let contacts = contact_keys(data_dir);
    Some(svc.status_of(&contacts, svc.now()))
}

/// The contact book's keys (an unreadable book: none).
fn contact_keys(data_dir: &Path) -> Vec<[u8; 32]> {
    #[derive(serde::Deserialize)]
    struct Row {
        #[serde(default)]
        pub_hex: String,
    }
    let rows: Vec<Row> = raven_core::contact_book::read_rows(data_dir)
        .ok()
        .flatten()
        .unwrap_or_default();
    let mut keys: BTreeMap<[u8; 32], ()> = BTreeMap::new();
    for row in rows {
        if let Some(key) = parse_key(&row.pub_hex) {
            keys.insert(key, ());
        }
    }
    keys.into_keys().collect()
}

fn parse_key(hex_key: &str) -> Option<[u8; 32]> {
    hex::decode(hex_key.trim()).ok()?.try_into().ok()
}

fn error(v: u16, code: &str, message: impl Into<String>) -> IpcResponse {
    IpcResponse::Error {
        v,
        code: code.into(),
        message: message.into(),
    }
}

fn hold(v: u16) -> IpcResponse {
    error(
        v,
        "LEARNING_HOLD",
        raven_core::learning::LEARNING_HOLD.to_string(),
    )
}

/// IPC `LearningPlan` (blocking): the hold while the gate is shut; else,
/// while learning is on, the learned order of the contact's plan ([`plan`],
/// the order the worker uses) with `state=on` (memory only and a started
/// over file included: the order is used; the reason block names them),
/// and the static order with `state=off why=off` while the user's switch is
/// off. `static_carriers` is the worker's resolver
/// (`outbox::static_carriers`). While carry choice is live and has learned
/// about the contact's custodians (`custodians`: the worker's candidates,
/// `outbox::custodian_candidates`, read only then), `carry` names the ones
/// its mail is left with, in that order (P6.16).
pub(crate) fn ipc_plan(
    v: u16,
    peer_pub_hex: &str,
    static_carriers: impl FnOnce(&[u8; 32]) -> Result<Vec<OutboxCarrier>, &'static str>,
    custodians: impl FnOnce(&[u8; 32]) -> Vec<([u8; 32], Option<u8>)>,
) -> IpcResponse {
    let svc = service();
    if !(svc.gate)() {
        return hold(v);
    }
    let Some(peer) = parse_key(peer_pub_hex) else {
        return error(v, "IPC_BAD_PEER", "peer_pub_hex must be 64 hex chars");
    };
    let carriers = match static_carriers(&peer) {
        Ok(c) => c,
        Err(code) => return error(v, code, format!("{code}: no plan for this contact")),
    };
    let (order, state) = match svc.plan(&peer, &carriers) {
        Some((order, _)) => (order, State::On),
        None => (Order::fixed(&carriers, Why::Off, State::Off), State::Off),
    };
    let carry = if svc.carry_live() {
        let cands: Vec<Candidate> = custodians(&peer)
            .iter()
            .map(|(k, o)| Candidate::of(*k, *o))
            .collect();
        svc.carry_rows(&peer, &cands)
    } else {
        Vec::new()
    };
    IpcResponse::LearningPlan {
        v,
        order: order.carriers.iter().map(|c| c.label().into()).collect(),
        why: order.render(),
        state: state.token().into(),
        carry,
    }
}

/// IPC `LearningReset` (blocking): the hold while the gate is shut; else
/// `peer_pub_hex`'s rows (or everyone's) forgotten in memory and on disk.
pub(crate) fn ipc_reset(v: u16, data_dir: &Path, peer_pub_hex: Option<&str>) -> IpcResponse {
    let svc = service();
    if !(svc.gate)() {
        return hold(v);
    }
    let peer = match peer_pub_hex.map(parse_key) {
        None => None,
        Some(Some(p)) => Some(p),
        Some(None) => return error(v, "IPC_BAD_PEER", "peer_pub_hex must be 64 hex chars"),
    };
    match svc.reset(data_dir, peer) {
        Ok(cleared) => IpcResponse::LearningReset { v, cleared },
        Err(_) => error(
            v,
            "LEARNING_RESET",
            "the learning file could not be changed; try again",
        ),
    }
}

// ── The service ─────────────────────────────────────────────────────────────

/// The learning service (supervised in `main`): reads the user's switch
/// every [`POLICY_POLL`] (only while the gate is live), loads the model when
/// on, applies the observations, saves every [`SAVE_EVERY`] when changed and
/// explores every [`EXPLORE_TICK`] over the outbox worker's context (none
/// while no worker runs). Runs until aborted.
pub async fn run(data_dir: PathBuf) -> Result<(), String> {
    run_on(
        &SERVICE,
        data_dir,
        Arc::new(PlatformSealer),
        crate::outbox::attempt_ctx,
    )
    .await
}

/// Clears the channel (and with it `on`) when the service task ends; the
/// model stays for [`final_save`].
struct Stopped(&'static Service);

impl Drop for Stopped {
    fn drop(&mut self) {
        self.0.on.store(false, Ordering::Release);
        *lock(&self.0.intake) = None;
    }
}

async fn run_on(
    svc: &'static Service,
    dd: PathBuf,
    sealer: Arc<dyn Sealer + Send + Sync>,
    ctx_of: fn() -> Option<Arc<AttemptCtx>>,
) -> Result<(), String> {
    let (tx, mut rx) = mpsc::channel(INTAKE);
    *lock(&svc.intake) = Some(tx);
    let _stopped = Stopped(svc);
    let mut poll = tokio::time::interval(POLICY_POLL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut save = tokio::time::interval_at(tokio::time::Instant::now() + SAVE_EVERY, SAVE_EVERY);
    save.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut explore =
        tokio::time::interval_at(tokio::time::Instant::now() + EXPLORE_TICK, EXPLORE_TICK);
    explore.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = poll.tick() => svc.poll(&dd, &sealer).await,
            Some(msg) = rx.recv() => svc.apply(msg),
            _ = save.tick() => {
                let _ = tokio::task::spawn_blocking(move || svc.save_now()).await;
            }
            _ = explore.tick() => svc.explore_in_background(ctx_of),
        }
    }
}

/// Lock v2 (Phase 6b P6.40, `crate::lock`), before the keys go: what
/// changed is saved while the profile's key is still there, waiting at most
/// [`FINAL_SAVE_WAIT`]. Then [`let_go`].
pub(crate) async fn save_for_lock() {
    let svc = service();
    let _ = tokio::time::timeout(
        FINAL_SAVE_WAIT,
        tokio::task::spawn_blocking(move || svc.save_now()),
    )
    .await;
}

/// Lock v2, once the keys went: the model goes too. Its secret (the HMAC
/// key every contact, network and relay is named by) is a key of this
/// profile, and a locked raven-node holds none; nothing loads it again
/// until Raven is unlocked (the next poll after the unlock reads the file).
pub(crate) fn let_go() {
    service().let_go();
}

/// The save at shutdown: what changed since the last one, best effort,
/// waiting at most [`FINAL_SAVE_WAIT`].
pub(crate) async fn final_save() {
    let svc = service();
    let _ = tokio::time::timeout(
        FINAL_SAVE_WAIT,
        tokio::task::spawn_blocking(move || svc.save_now()),
    )
    .await;
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// `svc` as the service of the current thread (a blocking-pool thread the
/// explorer runs on) until dropped: a test's own service reaches the hooks
/// its probe dial calls. Test builds only.
#[cfg(test)]
struct OnThread(Option<&'static Service>);

#[cfg(test)]
impl OnThread {
    fn enter(svc: &'static Service) -> Self {
        Self(TEST_SERVICE.with(|c| c.replace(Some(svc))))
    }
}

#[cfg(test)]
impl Drop for OnThread {
    fn drop(&mut self) {
        TEST_SERVICE.with(|c| c.set(self.0));
    }
}

/// A learning service for the current test thread (and the tasks of a
/// `#[tokio::test]` on it), in place of the process's until dropped.
#[cfg(test)]
pub(crate) struct TestService {
    pub(crate) svc: &'static Service,
    rx: Option<mpsc::Receiver<Msg>>,
}

#[cfg(test)]
fn gate_open() -> bool {
    true
}

#[cfg(test)]
fn gate_shut() -> bool {
    false
}

/// A test service's tag: its cached one (netwatch acted on every change),
/// or the network a test moved to without netwatch acting
/// ([`TestService::set_egress`]).
#[cfg(test)]
fn test_tag() -> Option<String> {
    let svc = service();
    let moved = lock(&svc.egress).clone();
    moved.unwrap_or_else(|| svc.net())
}

#[cfg(test)]
impl TestService {
    /// Installed with the gate open (`live`) or shut; nothing loaded.
    pub(crate) fn install(live: bool) -> Self {
        let svc: &'static Service = Box::leak(Box::new(Service::new(
            if live { gate_open } else { gate_shut },
            test_tag,
        )));
        TEST_SERVICE.with(|c| c.set(Some(svc)));
        Self { svc, rx: None }
    }

    /// Installed live and on, with an empty model on `dir` (the identity
    /// sealer) on network `net`; [`Self::drain`] applies what was posted.
    pub(crate) fn loaded(dir: &Path, net: Option<&str>) -> Self {
        let mut t = Self::install(true);
        let (tx, rx) = mpsc::channel(INTAKE);
        *lock(&t.svc.intake) = Some(tx);
        *lock(&t.svc.net) = net.map(str::to_owned);
        *lock(&t.svc.model) = Some(Learner {
            dir: dir.to_path_buf(),
            sealer: Arc::new(tests::Plain::default()),
            model: Model::new_empty([7; 32]),
            store: StoreState::On,
            dirty: false,
            saved_at_ms: None,
            observed: Window::default(),
            dropped: Window::default(),
            would_reorder: Window::default(),
            probes: Window::default(),
            wrote: BTreeMap::new(),
            explored: BTreeMap::new(),
        });
        t.svc.on.store(true, Ordering::Release);
        t.rx = Some(rx);
        t
    }

    /// Applies every message posted so far.
    pub(crate) fn drain(&mut self) -> usize {
        let mut n = 0;
        if let Some(rx) = self.rx.as_mut() {
            while let Ok(msg) = rx.try_recv() {
                self.svc.apply(msg);
                n += 1;
            }
        }
        n
    }

    /// `n` message dials to `contact` on the current network, each pair
    /// `failing` black-holed (no answer: NOT_REACHABLE) then `delivering`
    /// with an ACK (a receipt), as the carrier hooks post them; applied.
    pub(crate) fn teach(
        &mut self,
        contact: &[u8; 32],
        failing: OutboxCarrier,
        delivering: OutboxCarrier,
        n: usize,
    ) {
        use raven_core::envelope::EnvType;
        let frames = vec![tests::env(EnvType::Message)];
        for _ in 0..n {
            for (carrier, result) in [
                (
                    failing,
                    Err(
                        "lan connect: cannot connect to 192.0.2.1:9: no answer within 5.0s"
                            .to_string(),
                    ),
                ),
                (delivering, Ok(vec![tests::env(EnvType::Ack)])),
            ] {
                observe_dial(
                    contact,
                    carrier,
                    None,
                    None,
                    &frames,
                    &result,
                    &DialTiming::default(),
                    Expired::default(),
                    DialMeta::default(),
                    net(),
                );
            }
        }
        self.drain();
    }

    /// One message dial to `contact` over `carrier` on the current network
    /// at this service's clock, as the carrier hooks post it: `delivered`
    /// (an ACK came back: a receipt, in that carrier's usual time) or not
    /// (no answer within the 5 s connect wait: NOT_REACHABLE); applied.
    pub(crate) fn wrote(&mut self, contact: &[u8; 32], carrier: OutboxCarrier, delivered: bool) {
        use raven_core::envelope::EnvType;
        let frames = vec![tests::env(EnvType::Message)];
        let (result, timing) = if delivered {
            (Ok(vec![tests::env(EnvType::Ack)]), tests::usual(carrier))
        } else {
            (
                Err(
                    "lan connect: cannot connect to 192.0.2.1:9: no answer within 5.0s".to_string(),
                ),
                DialTiming {
                    total_ms: 5_000,
                    ..DialTiming::default()
                },
            )
        };
        observe_dial(
            contact,
            carrier,
            None,
            None,
            &frames,
            &result,
            &timing,
            Expired::default(),
            DialMeta::default(),
            net(),
        );
        self.drain();
    }

    /// netwatch's refresh, to `net`.
    pub(crate) fn set_net(&self, net: Option<&str>) {
        *lock(&self.svc.net) = net.map(str::to_owned);
    }

    /// This computer is on network `net` now, and netwatch has not acted
    /// on it yet (the cached tag stays); `None`: no move.
    pub(crate) fn set_egress(&self, net: Option<Option<&str>>) {
        *lock(&self.svc.egress) = net.map(|n| n.map(str::to_owned));
    }

    /// This service's wall clock reads `at_ms` from now on.
    pub(crate) fn set_now(&self, at_ms: u64) {
        self.svc.clock.store(at_ms, Ordering::Release);
    }

    /// Carry choice's facts as a poll reads them: custody `in_use` and the
    /// verified, unblocked contacts `pinned`.
    pub(crate) fn set_carry(&self, in_use: bool, pinned: &[[u8; 32]]) {
        *lock(&self.svc.carry) = CarryFacts {
            in_use,
            pinned: pinned.iter().copied().collect(),
        };
    }

    /// The loaded model (a copy).
    pub(crate) fn model(&self) -> Option<Model> {
        lock(&self.svc.model).as_ref().map(|l| l.model.clone())
    }

    pub(crate) fn status(&self, contacts: &[[u8; 32]]) -> LearningStatus {
        self.svc.status_of(contacts, self.svc.now())
    }
}

#[cfg(test)]
impl Drop for TestService {
    fn drop(&mut self) {
        TEST_SERVICE.with(|c| c.set(None));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use raven_core::envelope::{EnvType, Envelope};
    use raven_core::learning::model::Arm;
    use raven_core::learning::store::Zeroizing;
    use raven_core::learning::store::LEARNING_FILE;
    use std::sync::atomic::AtomicUsize;

    const BOB: [u8; 32] = [0xB0; 32];

    /// The identity sealer (the store's tests' own), counting its seals, or
    /// failing as an unavailable key does (until the key is back:
    /// `unavailable` cleared).
    #[derive(Default)]
    pub(crate) struct Plain {
        pub(crate) unavailable: AtomicBool,
        pub(crate) seals: AtomicUsize,
    }

    impl Plain {
        /// The key not here (yet).
        pub(crate) fn unavailable() -> Self {
            Self {
                unavailable: AtomicBool::new(true),
                ..Self::default()
            }
        }

        fn refuses(&self) -> bool {
            self.unavailable.load(Ordering::SeqCst)
        }
    }

    impl Sealer for Plain {
        fn protect(&self, _dd: &Path, pt: &[u8]) -> Result<Vec<u8>, SealError> {
            if self.refuses() {
                return Err(SealError::Unavailable);
            }
            self.seals.fetch_add(1, Ordering::SeqCst);
            Ok(pt.to_vec())
        }

        fn unprotect(&self, _dd: &Path, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
            if self.refuses() {
                return Err(SealError::Unavailable);
            }
            Ok(Zeroizing::new(ct.to_vec()))
        }
    }

    pub(crate) fn env(kind: EnvType) -> Vec<u8> {
        Envelope {
            env_type: kind as u8,
            flags: 0,
            message_id: [0x11; 16],
            routing_tag: [0x22; 16],
            dest_device_hint: 0,
            created_at: 1,
            expires_at: 2,
            hop_limit: 4,
            replication_budget: 1,
            anti_replay_nonce: [0x33; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: vec![0x44; 32],
            sender_authentication: vec![0u8; 64],
        }
        .pack()
    }

    fn timing() -> DialTiming {
        DialTiming {
            connect_ms: Some(40),
            reply_ms: Some(90),
            total_ms: 150,
        }
    }

    /// A carrier's usual times for a dial that linked (and was answered):
    /// LAN 50 ms, Internet 300 ms, p2p 1 s.
    pub(crate) fn usual(carrier: OutboxCarrier) -> DialTiming {
        let (connect_ms, reply_ms) = match carrier {
            OutboxCarrier::Lan => (20, 30),
            OutboxCarrier::Internet => (100, 200),
            OutboxCarrier::P2p | OutboxCarrier::Nearby => (500, 500),
            OutboxCarrier::Onion => (15_000, 1_000),
        };
        DialTiming {
            connect_ms: Some(connect_ms),
            reply_ms: Some(reply_ms),
            total_ms: connect_ms + reply_ms,
        }
    }

    fn arm(t: &TestService, net: Option<&str>, carrier: OutboxCarrier) -> Option<Arm> {
        t.model()?
            .arm(&ArmKey {
                contact: BOB,
                net: net.map(str::to_owned),
                carrier,
            })
            .copied()
    }

    fn observe(carrier: OutboxCarrier, result: Result<Vec<Vec<u8>>, String>) {
        let frames = vec![env(EnvType::Message)];
        observe_dial(
            &BOB,
            carrier,
            None,
            None,
            &frames,
            &result,
            &timing(),
            Expired::default(),
            DialMeta::default(),
            net(),
        );
    }

    /// Lock v2 (Phase 6b P6.40) with learning on: a lock saves what was
    /// learned while the profile's key is there and lets the model go; no
    /// poll loads it while Raven is locked (a passphrase profile also starts
    /// locked); the first poll after the unlock loads it again from the
    /// file.
    #[tokio::test]
    async fn a_lock_saves_the_model_and_lets_it_go_until_the_unlock() {
        use raven_core::security_gate::{set_lab_for_this_thread, SecGate};
        struct Shut;
        impl Drop for Shut {
            fn drop(&mut self) {
                set_lab_for_this_thread(SecGate::LocalProtection, None);
            }
        }
        set_lab_for_this_thread(SecGate::LocalProtection, Some(true));
        let _shut = Shut;
        if !crate::lock::live() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("home"));
        observe(OutboxCarrier::Lan, Ok(vec![env(EnvType::Ack)]));
        assert_eq!(t.drain(), 1);
        let sealer: Arc<dyn Sealer + Send + Sync> = Arc::new(Plain::default());
        crate::lock::lock(dir.path()).await.unwrap();
        assert!(t.model().is_none(), "let go at the lock");
        assert!(!live_on());
        assert!(dir.path().join(LEARNING_FILE).exists(), "saved first");
        t.svc.poll(dir.path(), &sealer).await;
        assert!(t.model().is_none(), "nothing loads while locked");
        crate::lock::unlock(dir.path(), None).await.unwrap();
        t.svc.poll(dir.path(), &sealer).await;
        assert!(live_on());
        assert!(
            arm(&t, Some("home"), OutboxCarrier::Lan).is_some(),
            "loaded again from the file"
        );
    }

    /// Phase 6b P6.24's merge amendment (6b risk 7): a dial whose link was
    /// tampered with (`security::exclude_dial`, as `SEC_LINK_TAG_FAIL` marks
    /// it) teaches learning nothing and counts as dropped; only that
    /// contact's dial over that carrier, and once.
    #[test]
    fn a_tampered_dial_teaches_learning_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("home"));
        // A contact of its own: the marks are process-wide.
        let carol = [0xC7; 32];
        let dial = |carrier, result: Result<Vec<Vec<u8>>, String>| {
            observe_dial(
                &carol,
                carrier,
                None,
                None,
                &[env(EnvType::Message)],
                &result,
                &timing(),
                Expired::default(),
                DialMeta::default(),
                net(),
            );
        };
        let arm_of = |t: &TestService, carrier| {
            t.model()?
                .arm(&ArmKey {
                    contact: carol,
                    net: Some("home".to_owned()),
                    carrier,
                })
                .copied()
        };
        let tag_failed = || {
            Err(
                "LAN_DIAL_BAD_REPLY: the peer's reply could not be read (noise transport failed); \
                 the frames were sent, delivery is unconfirmed and a retry is safe"
                    .to_owned(),
            )
        };
        crate::security::exclude_dial(&carol, OutboxCarrier::Lan);
        dial(OutboxCarrier::Internet, Ok(vec![env(EnvType::Ack)]));
        dial(OutboxCarrier::Lan, tag_failed());
        t.drain();
        assert!(arm_of(&t, OutboxCarrier::Lan).is_none(), "not learned");
        assert!(
            arm_of(&t, OutboxCarrier::Internet).is_some(),
            "another carrier is"
        );
        assert_eq!(t.status(&[carol]).dropped_24h, 1);
        // Once: the next LAN dial is learned again.
        dial(OutboxCarrier::Lan, tag_failed());
        t.drain();
        assert!(arm_of(&t, OutboxCarrier::Lan).is_some());
        assert_eq!(t.status(&[carol]).dropped_24h, 1);
    }

    /// Every ranked carrier: an ACK reply is a receipt (success, timing
    /// samples), an error a failure of its code's weight; each is one
    /// observation of the last 24 hours, on the dial's network.
    #[test]
    fn observe_dial_records_ok_and_err_for_every_carrier() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("home"));
        for carrier in RANKED {
            observe(carrier, Ok(vec![env(EnvType::Ack)]));
            observe(
                carrier,
                Err("lan connect: cannot connect to 127.0.0.1:9 (Connection refused)".into()),
            );
            assert_eq!(t.drain(), 2);
            let row = arm(&t, Some("home"), carrier).expect("an arm");
            // Receipt +1000, NOT_LISTENING 250 after it.
            assert_eq!((row.beta.a_m, row.beta.b_m), (1_000, 250), "{carrier:?}");
            assert_eq!(row.connect.n, 2, "{carrier:?}");
            assert_eq!(row.reply.n, 2, "{carrier:?}");
            assert_eq!(row.tries(), (1, 2), "{carrier:?}");
            assert!(arm(&t, None, carrier).is_none());
        }
        let st = t.status(&[BOB]);
        assert_eq!(st.observations_24h, 6);
        // `carriers` counts carry rows (P6.16): dials make none.
        assert_eq!((st.contacts, st.networks, st.carriers), (1, 1, 0));
        // A failure that is not evidence (a hold) is dropped, not learned.
        observe(OutboxCarrier::P2p, Err("P2P_HOLD: p2p is lab-only".into()));
        t.drain();
        assert_eq!(t.status(&[BOB]).dropped_24h, 1);
        assert_eq!(
            arm(&t, Some("home"), OutboxCarrier::P2p).unwrap().tries(),
            (1, 2)
        );
    }

    /// The p2p reason block names the failure (Phase 2 token), before the
    /// dial code.
    #[test]
    fn a_p2p_reason_block_gives_the_failure_its_weight() {
        assert_eq!(
            fail_code("P2P_UNREACHABLE: nobody answered (reach: why=contact_offline asof=3)"),
            "contact_offline"
        );
        assert_eq!(
            fail_code("lan connect: cannot connect (Connection refused)"),
            "NOT_LISTENING"
        );
    }

    /// Off (gate shut, or the user's switch off): nothing is observed or
    /// posted, the service loads nothing, no `learning.bin` is made, and
    /// Status has no row (shut) or an `off` one.
    #[tokio::test(start_paused = true)]
    async fn nothing_is_observed_or_written_when_off() {
        let dir = tempfile::tempdir().unwrap();
        for live in [false, true] {
            let t = TestService::install(live);
            if live {
                raven_core::node_policy::update_policy(dir.path(), |p| p.learning = Some(false))
                    .unwrap();
            }
            let svc = t.svc;
            let task = tokio::spawn(run_on(
                svc,
                dir.path().to_path_buf(),
                Arc::new(Plain::default()),
                no_worker,
            ));
            tokio::time::sleep(POLICY_POLL * 3).await;
            assert!(!live_on() && net().is_none());
            observe(OutboxCarrier::Lan, Ok(vec![env(EnvType::Ack)]));
            inbound(&BOB, OutboxCarrier::Lan, Some(b"relay".to_vec()), true);
            retract(&BOB, OutboxCarrier::Lan, now_ms());
            assert!(plan(&BOB, &RANKED).is_none());
            assert!(lock(&svc.model).is_none());
            tokio::time::sleep(SAVE_EVERY * 2).await;
            final_save().await;
            task.abort();
            assert!(!dir.path().join(LEARNING_FILE).exists());
            let st = status(dir.path());
            if live {
                assert_eq!(st.unwrap().state, "off");
            } else {
                assert!(st.is_none());
            }
        }
    }

    /// The network moved between the dial's start and its end: dropped,
    /// never an arm on either network.
    #[test]
    fn a_network_change_mid_dial_is_not_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("home"));
        let at_start = net();
        t.set_net(Some("cafe"));
        let frames = vec![env(EnvType::Message)];
        observe_dial(
            &BOB,
            OutboxCarrier::Lan,
            Some(DeliveryPath::Direct),
            None,
            &frames,
            &Err("lan connect: cannot connect (Connection refused)".into()),
            &timing(),
            Expired::default(),
            DialMeta::default(),
            at_start,
        );
        t.drain();
        assert!(arm(&t, Some("home"), OutboxCarrier::Lan).is_none());
        assert!(arm(&t, Some("cafe"), OutboxCarrier::Lan).is_none());
        let st = t.status(&[BOB]);
        assert_eq!((st.observations_24h, st.dropped_24h), (0, 1));
    }

    /// The worker refused every ACK of a dial: its receipt is taken back.
    #[test]
    fn a_retract_takes_the_receipt_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("home"));
        observe(OutboxCarrier::Lan, Ok(vec![env(EnvType::Ack)]));
        t.drain();
        assert_eq!(
            arm(&t, Some("home"), OutboxCarrier::Lan).unwrap().beta.a_m,
            1_000
        );
        retract(&BOB, OutboxCarrier::Lan, now_ms());
        t.drain();
        let arm = arm(&t, Some("home"), OutboxCarrier::Lan).unwrap();
        assert_eq!((arm.beta.a_m, arm.tries()), (0, (0, 1)));
    }

    /// A contact back on the local network from a new address halves its
    /// LAN doubt here (not elsewhere); a plain inbound link changes nothing.
    #[test]
    fn inbound_from_a_new_local_address_halves_lan_doubt() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("home"));
        for _ in 0..2 {
            observe(
                OutboxCarrier::Lan,
                Err("lan connect: cannot connect to 127.0.0.1:9: no answer within 5.0s".into()),
            );
        }
        t.drain();
        let before = arm(&t, Some("home"), OutboxCarrier::Lan).unwrap().beta.b_m;
        assert!(before > 0);
        inbound(&BOB, OutboxCarrier::Lan, None, false);
        assert_eq!(t.drain(), 0, "nothing to say");
        inbound(&BOB, OutboxCarrier::Lan, None, true);
        t.drain();
        assert_eq!(
            arm(&t, Some("home"), OutboxCarrier::Lan).unwrap().beta.b_m,
            before / 2
        );
        // On another network: no arm there, none made.
        t.set_net(Some("office"));
        inbound(&BOB, OutboxCarrier::Lan, None, true);
        t.drain();
        assert!(arm(&t, Some("office"), OutboxCarrier::Lan).is_none());
    }

    /// A receipt over a relayed p2p path counts for its relay; an inbound
    /// link over our reservation counts half; a failed dial's circuits
    /// count by their outcome. A direct path names no relay.
    #[test]
    fn relayed_receipts_feed_the_relay_row() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("home"));
        let frames = vec![env(EnvType::Message)];
        let acked: Result<Vec<Vec<u8>>, String> = Ok(vec![env(EnvType::Ack)]);
        observe_dial(
            &BOB,
            OutboxCarrier::P2p,
            Some(DeliveryPath::Relayed),
            Some(b"relay-1".to_vec()),
            &frames,
            &acked,
            &timing(),
            Expired::default(),
            DialMeta::default(),
            net(),
        );
        observe_dial(
            &BOB,
            OutboxCarrier::P2p,
            Some(DeliveryPath::Direct),
            Some(b"relay-2".to_vec()),
            &frames,
            &acked,
            &timing(),
            Expired::default(),
            DialMeta::default(),
            net(),
        );
        inbound(&BOB, OutboxCarrier::P2p, Some(b"relay-3".to_vec()), false);
        circuits(vec![
            (b"relay-4".to_vec(), CircuitOutcome::Busy),
            (b"relay-5".to_vec(), CircuitOutcome::NotOnRelay),
        ]);
        t.drain();
        let m = t.model().unwrap();
        assert_eq!(m.relay(b"relay-1").unwrap().beta.a_m, 1_000);
        assert!(m.relay(b"relay-2").is_none());
        assert_eq!(m.relay(b"relay-3").unwrap().beta.a_m, 500);
        assert_eq!(m.relay(b"relay-4").unwrap().beta.b_m, 500);
        // A contact not on its relay says nothing about the relay.
        assert!(m.relay(b"relay-5").is_none());
        assert_eq!(t.status(&[BOB]).relays, 3);
    }

    /// The learned order (P6.12): static while cold, the faster carrier
    /// first once the evidence says so, on the network it was ranked on.
    /// Planning reads only; a worker plan counts a reorder ([`planned`]),
    /// and an attempt that reached the contact remembers the order (the
    /// hysteresis start, [`remember_order`]).
    #[test]
    fn plan_ranks_and_the_worker_counts_and_remembers() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("home"));
        // Cold: the static order, nothing counted.
        let (cold, net) = plan(&BOB, &RANKED).unwrap();
        assert_eq!(
            (cold.carriers.as_slice(), cold.why),
            (&RANKED[..], Why::Cold)
        );
        assert_eq!(net.as_deref(), Some("home"));
        planned(&cold, &RANKED);
        assert_eq!(t.status(&[BOB]).would_reorder_24h, 0);
        t.teach(&BOB, OutboxCarrier::Lan, OutboxCarrier::Internet, 4);
        let (order, net) = plan(&BOB, &RANKED).unwrap();
        assert_eq!(order.carriers[0], OutboxCarrier::Internet);
        assert_eq!(order.detail.state, State::On);
        assert_eq!(t.status(&[BOB]).would_reorder_24h, 0, "planning reads only");
        planned(&order, &RANKED);
        let st = t.status(&[BOB]);
        assert_eq!(st.state, "on");
        assert_eq!(st.would_reorder_24h, 1);
        assert_eq!(st.rows.len(), 1);
        assert_eq!(st.rows[0].order[0], "internet_dial");
        assert!(
            st.rows[0].why.starts_with("learn: state=on "),
            "{}",
            st.rows[0].why
        );
        // The orders remembered (memory only), as the model's Debug counts.
        let remembered = |t: &TestService| format!("{:?}", t.model().unwrap());
        assert!(remembered(&t).contains("current: 0"), "{}", remembered(&t));
        remember_order(&BOB, net.as_deref(), &order);
        assert!(remembered(&t).contains("current: 1"), "{}", remembered(&t));
        // Off: nothing is planned, counted or remembered.
        drop(t);
        let _off = TestService::install(true);
        assert!(plan(&BOB, &RANKED).is_none());
        planned(&order, &RANKED);
        remember_order(&BOB, net.as_deref(), &order);
        contradiction(&BOB, net.as_deref());
    }

    /// Status names contacts by key and carriers by label only: no network
    /// tag, address or relay, rows of the current network only.
    #[test]
    fn status_counts_and_rows_have_no_address() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("net-tag-secret"));
        let frames = vec![env(EnvType::Message)];
        observe_dial(
            &BOB,
            OutboxCarrier::P2p,
            Some(DeliveryPath::Relayed),
            Some(b"relay-peer-id".to_vec()),
            &frames,
            &Ok(vec![env(EnvType::Ack)]),
            &timing(),
            Expired::default(),
            DialMeta::default(),
            net(),
        );
        observe(
            OutboxCarrier::Lan,
            Err("lan connect: cannot connect to 192.168.1.20:7420 (Connection refused)".into()),
        );
        t.drain();
        let carol = [0xC0; 32];
        let st = t.status(&[BOB, carol]);
        assert_eq!(st.state, "on");
        assert_eq!(
            (st.contacts, st.networks, st.relays, st.carriers),
            (1, 1, 1, 0)
        );
        assert_eq!(st.rows.len(), 1, "Carol has no rows");
        assert_eq!(st.rows[0].peer_pub_hex, hex::encode(BOB));
        let json = serde_json::to_string(&st).unwrap();
        for secret in [
            "net-tag-secret",
            "192.168",
            "7420",
            "relay-peer-id",
            "127.0.0.1",
        ] {
            assert!(!json.contains(secret), "{secret}: {json}");
        }
        // Another network: counts stay, no rows.
        t.set_net(Some("elsewhere"));
        let st = t.status(&[BOB]);
        assert!(st.rows.is_empty());
        assert_eq!(st.contacts, 1);
        // At most MAX_LEARNING_ROWS, newest first.
        t.set_net(Some("net-tag-secret"));
        let many: Vec<[u8; 32]> = (0..20u8).map(|i| [i; 32]).collect();
        for key in &many {
            observe_dial(
                key,
                OutboxCarrier::Lan,
                None,
                None,
                &frames,
                &Ok(vec![env(EnvType::Ack)]),
                &timing(),
                Expired::default(),
                DialMeta::default(),
                net(),
            );
        }
        t.drain();
        assert_eq!(t.status(&many).rows.len(), MAX_LEARNING_ROWS);
    }

    /// The service saves a changed model once per SAVE_EVERY (not at each
    /// observation), and the final save writes what changed since.
    #[tokio::test(start_paused = true)]
    async fn save_is_debounced_and_final_save_runs() {
        let dir = tempfile::tempdir().unwrap();
        let t = TestService::install(true);
        let sealer = Arc::new(Plain::default());
        let task = tokio::spawn(run_on(
            t.svc,
            dir.path().to_path_buf(),
            sealer.clone(),
            no_worker,
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(live_on());
        let file = dir.path().join(LEARNING_FILE);
        observe(OutboxCarrier::Lan, Ok(vec![env(EnvType::Ack)]));
        tokio::time::sleep(SAVE_EVERY - Duration::from_secs(1)).await;
        assert!(!file.exists(), "not before the save interval");
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(file.exists());
        let saves = sealer.seals.load(Ordering::SeqCst);
        // Nothing changed: no save at the next interval.
        tokio::time::sleep(SAVE_EVERY).await;
        assert_eq!(sealer.seals.load(Ordering::SeqCst), saves);
        let before = std::fs::read(&file).unwrap();
        observe(OutboxCarrier::Internet, Ok(vec![env(EnvType::Ack)]));
        tokio::time::sleep(Duration::from_millis(100)).await;
        final_save().await;
        assert_ne!(std::fs::read(&file).unwrap(), before);
        assert!(t.status(&[BOB]).saved_age_s.is_some());
        task.abort();
        // A reload has both arms.
        let (m, state) = store::load(dir.path(), &*sealer, now_ms());
        assert_eq!(state, StoreState::On);
        assert_eq!(m.sizes().arms, 2);
    }

    /// No key: the model learns in memory, nothing is ever written, and
    /// Status says so (no save age).
    #[tokio::test(start_paused = true)]
    async fn memory_only_when_the_sealer_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let t = TestService::install(true);
        let sealer = Arc::new(Plain::unavailable());
        let task = tokio::spawn(run_on(t.svc, dir.path().to_path_buf(), sealer, no_worker));
        tokio::time::sleep(Duration::from_millis(100)).await;
        observe(OutboxCarrier::Lan, Ok(vec![env(EnvType::Ack)]));
        tokio::time::sleep(SAVE_EVERY * 2).await;
        final_save().await;
        task.abort();
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("learning")));
        let st = t.status(&[BOB]);
        assert_eq!(st.state, "memory_only");
        assert_eq!((st.observations_24h, st.saved_age_s), (1, None));
        // A key that is away for a while later (Raven being locked, a slow
        // keychain; review learning-1): not saved then, never memory only,
        // and saved at the next save once it is back.
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), None);
        observe(OutboxCarrier::Lan, Ok(vec![env(EnvType::Ack)]));
        t.drain();
        let away = Arc::new(Plain::unavailable());
        let sealer: Arc<dyn Sealer + Send + Sync> = away.clone();
        lock(&t.svc.model).as_mut().unwrap().sealer = sealer;
        t.svc.save_now();
        assert_eq!(t.status(&[BOB]).state, "on");
        assert!(!dir.path().join(LEARNING_FILE).exists());
        away.unavailable.store(false, Ordering::SeqCst);
        t.svc.save_now();
        assert!(dir.path().join(LEARNING_FILE).exists(), "saved once back");
        assert!(t.status(&[BOB]).saved_age_s.is_some());
    }

    /// Review learning-1: the at-rest key loads after the service's first
    /// poll (a keychain prompt at the start, its retries, an unlock whose
    /// key loader had not finished). That poll keeps learning in memory
    /// only; while the file is not read, one contact cannot be forgotten in
    /// it (an error, the file untouched, never "cleared 0"); the first poll
    /// once the key is here reads the file, and its rows can be forgotten.
    #[tokio::test]
    async fn a_key_that_loads_late_is_waited_for_and_the_file_read_then() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        // What an earlier run learned about Bob, saved.
        {
            let mut t = TestService::loaded(dd, Some("home"));
            observe(OutboxCarrier::Lan, Ok(vec![env(EnvType::Ack)]));
            t.drain();
            t.svc.save_now();
        }
        let file = dd.join(LEARNING_FILE);
        let saved = std::fs::read(&file).unwrap();
        let t = TestService::install(true);
        let late = Arc::new(Plain::unavailable());
        let sealer: Arc<dyn Sealer + Send + Sync> = late.clone();
        for _ in 0..2 {
            t.svc.poll(dd, &sealer).await;
            assert!(live_on());
            let st = t.status(&[BOB]);
            assert_eq!((st.state.as_str(), st.contacts), ("memory_only", 0));
        }
        match ipc_reset(1, dd, Some(&hex::encode(BOB))) {
            IpcResponse::Error { code, .. } => assert_eq!(code, "LEARNING_RESET"),
            other => panic!("{other:?}"),
        }
        assert_eq!(std::fs::read(&file).unwrap(), saved, "nothing forgotten");
        // The key is here: the next poll reads the file.
        late.unavailable.store(false, Ordering::SeqCst);
        t.svc.poll(dd, &sealer).await;
        let st = t.status(&[BOB]);
        assert_eq!((st.state.as_str(), st.contacts), ("on", 1));
        match ipc_reset(1, dd, Some(&hex::encode(BOB))) {
            IpcResponse::LearningReset { cleared, .. } => assert_eq!(cleared, 1),
            other => panic!("{other:?}"),
        }
        let (on_disk, _) = store::load(dd, &*late, now_ms());
        assert_eq!(on_disk.sizes().contacts, 0, "saved without Bob");
    }

    /// Review learning-1 with no file yet: what was learned while the key
    /// was not here is kept once it is, and saved from then on.
    #[tokio::test]
    async fn with_no_file_what_was_learned_before_the_key_came_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let mut t = TestService::install(true);
        let (tx, rx) = mpsc::channel(INTAKE);
        *lock(&t.svc.intake) = Some(tx);
        t.rx = Some(rx);
        let late = Arc::new(Plain::unavailable());
        let sealer: Arc<dyn Sealer + Send + Sync> = late.clone();
        t.svc.poll(dd, &sealer).await;
        observe(OutboxCarrier::Lan, Ok(vec![env(EnvType::Ack)]));
        assert_eq!(t.drain(), 1);
        t.svc.save_now();
        assert_eq!(t.status(&[BOB]).state, "memory_only");
        assert!(!dd.join(LEARNING_FILE).exists());
        late.unavailable.store(false, Ordering::SeqCst);
        t.svc.poll(dd, &sealer).await;
        let st = t.status(&[BOB]);
        assert_eq!((st.state.as_str(), st.contacts), ("on", 1));
        t.svc.save_now();
        let (on_disk, state) = store::load(dd, &*late, now_ms());
        assert_eq!((state, on_disk.sizes().contacts), (StoreState::On, 1));
    }

    /// Review learning-5: the network moved and netwatch has not acted on
    /// it yet (its debounce, a change its gap holds, a default route its
    /// next poll finds moved). The cached tag still says `home`, but a dial
    /// that ends then teaches `home` nothing (dropped, so counted); once
    /// netwatch acted, dials count again, on the new network.
    #[test]
    fn a_network_netwatch_has_not_acted_on_yet_is_not_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("home"));
        let no_answer =
            || Err("lan connect: cannot connect to 192.0.2.1:9: no answer within 5.0s".into());
        t.set_egress(Some(Some("office")));
        observe(OutboxCarrier::Lan, no_answer());
        t.drain();
        assert!(arm(&t, Some("home"), OutboxCarrier::Lan).is_none());
        assert!(arm(&t, Some("office"), OutboxCarrier::Lan).is_none());
        let st = t.status(&[BOB]);
        assert_eq!((st.observations_24h, st.dropped_24h), (0, 1));
        // No network at all yet (Wi-Fi gone, the next one not up): the same.
        t.set_egress(Some(None));
        observe(OutboxCarrier::Lan, no_answer());
        t.drain();
        assert!(arm(&t, Some("home"), OutboxCarrier::Lan).is_none());
        // netwatch acted: the cache says office, and the dial counts there.
        t.set_egress(None);
        t.set_net(Some("office"));
        observe(OutboxCarrier::Lan, no_answer());
        t.drain();
        assert!(arm(&t, Some("office"), OutboxCarrier::Lan).is_some());
        assert!(arm(&t, Some("home"), OutboxCarrier::Lan).is_none());
        let st = t.status(&[BOB]);
        assert_eq!((st.observations_24h, st.dropped_24h), (1, 2));
    }

    /// Review learning-6: Lock v2 lets carry choice's facts go with the
    /// model, so no copy of the verified contacts' keys stays while locked;
    /// a poll while locked (no model left) clears them again.
    #[test]
    fn letting_go_forgets_carry_choices_contacts() {
        let dir = tempfile::tempdir().unwrap();
        let t = TestService::loaded(dir.path(), Some("home"));
        t.set_carry(true, &[BOB, [0xC0; 32]]);
        let_go();
        assert!(t.model().is_none());
        assert_eq!(*lock(&t.svc.carry), CarryFacts::default());
        t.set_carry(true, &[BOB]);
        let_go();
        assert_eq!(*lock(&t.svc.carry), CarryFacts::default());
    }

    /// The user's switch goes off: within one poll nothing is observed and
    /// the model (saved first) is let go.
    #[tokio::test(start_paused = true)]
    async fn policy_off_stops_observing_within_2s() {
        let dir = tempfile::tempdir().unwrap();
        let t = TestService::install(true);
        let task = tokio::spawn(run_on(
            t.svc,
            dir.path().to_path_buf(),
            Arc::new(Plain::default()),
            no_worker,
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(live_on());
        observe(OutboxCarrier::Lan, Ok(vec![env(EnvType::Ack)]));
        raven_core::node_policy::update_policy(dir.path(), |p| p.learning = Some(false)).unwrap();
        let off_at = tokio::time::Instant::now();
        while live_on() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(off_at.elapsed() <= POLICY_POLL, "{:?}", off_at.elapsed());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(lock(&t.svc.model).is_none());
        assert!(
            dir.path().join(LEARNING_FILE).exists(),
            "saved on the way off"
        );
        // Back on: loaded again from the file.
        raven_core::node_policy::update_policy(dir.path(), |p| p.learning = None).unwrap();
        tokio::time::sleep(POLICY_POLL + Duration::from_millis(100)).await;
        assert!(live_on());
        assert_eq!(t.model().unwrap().sizes().arms, 1);
        task.abort();
    }

    /// IPC: a reset forgets one contact (saved without it) or everyone
    /// (the file removed), counting the contacts; while the gate is shut
    /// both ops answer the hold; a plan answers the learned order (`on`),
    /// or the static one while the user's switch is off.
    #[test]
    fn ipc_reset_clears_memory_and_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("home"));
        let carol = [0xC0; 32];
        for key in [BOB, carol] {
            let frames = vec![env(EnvType::Message)];
            observe_dial(
                &key,
                OutboxCarrier::Lan,
                None,
                None,
                &frames,
                &Ok(vec![env(EnvType::Ack)]),
                &timing(),
                Expired::default(),
                DialMeta::default(),
                net(),
            );
        }
        t.drain();
        t.svc.save_now();
        let file = dir.path().join(LEARNING_FILE);
        assert!(file.exists());
        match ipc_reset(1, dir.path(), Some(&hex::encode(BOB))) {
            IpcResponse::LearningReset { cleared, .. } => assert_eq!(cleared, 1),
            other => panic!("{other:?}"),
        }
        assert_eq!(t.model().unwrap().sizes().contacts, 1);
        let (on_disk, _) = store::load(dir.path(), &Plain::default(), now_ms());
        assert_eq!(on_disk.sizes().contacts, 1, "saved without Bob");
        match ipc_reset(1, dir.path(), None) {
            IpcResponse::LearningReset { cleared, .. } => assert_eq!(cleared, 1),
            other => panic!("{other:?}"),
        }
        assert_eq!(t.model().unwrap().sizes().arms, 0);
        assert!(!file.exists());
        assert!(matches!(
            ipc_reset(1, dir.path(), Some("zz")),
            IpcResponse::Error { ref code, .. } if code == "IPC_BAD_PEER"
        ));
        match ipc_plan(1, &hex::encode(BOB), |_| Ok(RANKED.to_vec()), no_custodians) {
            IpcResponse::LearningPlan {
                order, why, state, ..
            } => {
                assert_eq!(order, ["lan_dial", "internet_dial", "p2p_dial"]);
                assert_eq!(state, "on");
                assert_eq!(why, "learn: state=on order=lan,internet,p2p why=cold");
            }
            other => panic!("{other:?}"),
        }
        // The order the worker uses (P6.12): Internet first once LAN fails.
        t.teach(&BOB, OutboxCarrier::Lan, OutboxCarrier::Internet, 4);
        match ipc_plan(1, &hex::encode(BOB), |_| Ok(RANKED.to_vec()), no_custodians) {
            IpcResponse::LearningPlan {
                order, why, state, ..
            } => {
                assert_eq!(order[0], "internet_dial");
                assert_eq!(state, "on");
                assert!(why.starts_with("learn: state=on order=internet,"), "{why}");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            ipc_plan(1, &hex::encode(BOB), |_| Err("NOT_A_CONTACT"), no_custodians),
            IpcResponse::Error { ref code, .. } if code == "NOT_A_CONTACT"
        ));
        drop(t);
        // The gate open, the user's switch off: the static order, `off`.
        let off = TestService::install(true);
        match ipc_plan(1, &hex::encode(BOB), |_| Ok(RANKED.to_vec()), no_custodians) {
            IpcResponse::LearningPlan {
                order, why, state, ..
            } => {
                assert_eq!(order, ["lan_dial", "internet_dial", "p2p_dial"]);
                assert_eq!(state, "off");
                assert_eq!(why, "learn: state=off order=lan,internet,p2p why=off");
            }
            other => panic!("{other:?}"),
        }
        drop(off);
        let _shut = TestService::install(false);
        for resp in [
            ipc_reset(1, dir.path(), None),
            ipc_plan(
                1,
                &hex::encode(BOB),
                |_| panic!("no plan while shut"),
                |_| panic!("no custodians while shut"),
            ),
        ] {
            assert!(
                matches!(resp, IpcResponse::Error { ref code, .. } if code == "LEARNING_HOLD"),
                "{resp:?}"
            );
        }
    }

    /// `ipc_plan`'s custodians when no custodian is known.
    fn no_custodians(_: &[u8; 32]) -> Vec<([u8; 32], Option<u8>)> {
        Vec::new()
    }

    /// One dial to BOB over `carrier` (a message frame) with these times,
    /// expiries and worker facts, on the current network.
    fn dialled(
        carrier: OutboxCarrier,
        result: Result<Vec<Vec<u8>>, String>,
        timing: DialTiming,
        expired: Expired,
        meta: DialMeta,
    ) {
        let frames = vec![env(EnvType::Message)];
        observe_dial(
            &BOB,
            carrier,
            None,
            None,
            &frames,
            &result,
            &timing,
            expired,
            meta,
            net(),
        );
    }

    fn times(connect_ms: Option<u32>, reply_ms: Option<u32>) -> DialTiming {
        DialTiming {
            connect_ms,
            reply_ms,
            total_ms: connect_ms.unwrap_or(0) + reply_ms.unwrap_or(0),
        }
    }

    const ALL: [OutboxCarrier; 4] = [
        OutboxCarrier::Lan,
        OutboxCarrier::Internet,
        OutboxCarrier::P2p,
        OutboxCarrier::Nearby,
    ];

    /// P6.13: the gate shut, the switch off, no arm, an arm with three
    /// samples or one on another network: every carrier dials with today's
    /// waits, and its progress is today's (5 s per address, 20 s p2p, 30 s
    /// then 2 s for replies). The fourth sample makes the arm warm.
    #[test]
    fn cold_dials_use_todays_waits() {
        let today = |carrier| {
            for c in ALL {
                assert_eq!(waits(&BOB, c), wait::statics(c), "{carrier}: {c:?}");
            }
        };
        {
            let _shut = TestService::install(false);
            today("gate shut");
        }
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("home"));
        today("no arm");
        for _ in 0..3 {
            for carrier in RANKED {
                observe(carrier, Ok(vec![env(EnvType::Ack)]));
            }
        }
        t.drain();
        assert_eq!(
            arm(&t, Some("home"), OutboxCarrier::Lan).unwrap().connect.n,
            3
        );
        today("three samples");
        t.svc.on.store(false, Ordering::Release);
        today("switch off");
        t.svc.on.store(true, Ordering::Release);
        for carrier in RANKED {
            observe(carrier, Ok(vec![env(EnvType::Ack)]));
        }
        t.drain();
        for carrier in RANKED {
            assert!(waits(&BOB, carrier).learned, "{carrier:?}: four samples");
        }
        assert_eq!(
            waits(&BOB, OutboxCarrier::Nearby),
            wait::statics(OutboxCarrier::Nearby)
        );
        t.set_net(Some("office"));
        today("another network");
        // Today's waits make today's dial.
        use crate::netutil::{DialProgress, CONNECT_TIMEOUT, PRODUCTION_REPLY_WAITS};
        for (carrier, label, connect) in [
            (OutboxCarrier::Lan, "LAN", CONNECT_TIMEOUT),
            (OutboxCarrier::Internet, "INTERNET", CONNECT_TIMEOUT),
            (OutboxCarrier::P2p, "P2P", Duration::from_secs(20)),
        ] {
            let p = DialProgress::waiting(label, &waits(&BOB, carrier));
            assert_eq!(p.collector.waits(), PRODUCTION_REPLY_WAITS, "{label}");
            assert_eq!(p.connect.within, connect, "{label}");
            assert!(!p.connect.expired());
            assert_eq!(p.expired(), Expired::default());
        }
    }

    /// P6.13: a wait that ran out doubles (at most ×8, never above today's)
    /// until its next sample; a connect that ran out on one address and
    /// then linked on another gave a sample, so it does not back off.
    #[test]
    fn an_expired_wait_backs_off_and_a_sample_resets_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("home"));
        let ack = || Ok(vec![env(EnvType::Ack)]);
        let ms = Duration::from_millis;
        // Four 4 s connects and replies: rttvar 2000 → 1500 → 1125 → 843,
        // RTO = 4000 + 3372 ms, the wait 2·RTO = 14 744 ms.
        for carrier in [OutboxCarrier::Lan, OutboxCarrier::P2p] {
            for _ in 0..4 {
                let timing = times(Some(4_000), Some(4_000));
                dialled(
                    carrier,
                    ack(),
                    timing,
                    Expired::default(),
                    DialMeta::default(),
                );
            }
        }
        t.drain();
        let lan = || waits(&BOB, OutboxCarrier::Lan);
        let p2p = || waits(&BOB, OutboxCarrier::P2p);
        assert_eq!((lan().connect, lan().reply_first), (ms(5_000), ms(14_744)));
        assert_eq!((p2p().connect, p2p().reply_first), (ms(14_744), ms(14_744)));
        // The p2p connect ran out (no link): ×2 is 29.5 s, held at 20 s.
        dialled(
            OutboxCarrier::P2p,
            Err(format!(
                "{} (connect timed out after 14.7s)",
                crate::p2p::P2P_UNREACHABLE
            )),
            times(None, None),
            Expired {
                connect: true,
                reply: false,
            },
            DialMeta::default(),
        );
        t.drain();
        assert_eq!((p2p().connect, p2p().reply_first), (ms(20_000), ms(14_744)));
        // The LAN reply wait ran out after the frames (only the offer came
        // back): ×2, then held at today's 30 s.
        let offer_only = || Ok(vec![b"offer".to_vec()]);
        let no_reply = Expired {
            connect: false,
            reply: true,
        };
        dialled(
            OutboxCarrier::Lan,
            offer_only(),
            times(Some(4_000), None),
            no_reply,
            DialMeta::default(),
        );
        t.drain();
        assert_eq!(lan().reply_first, ms(29_488));
        dialled(
            OutboxCarrier::Lan,
            offer_only(),
            times(Some(4_000), None),
            no_reply,
            DialMeta::default(),
        );
        t.drain();
        let a = arm(&t, Some("home"), OutboxCarrier::Lan).unwrap();
        assert_eq!(
            (lan().reply_first, a.reply.backoff, a.connect.backoff),
            (ms(30_000), 2, 0)
        );
        // One address ran out, the next linked: a connect sample, no backoff.
        dialled(
            OutboxCarrier::Lan,
            ack(),
            times(Some(4_000), Some(4_000)),
            Expired {
                connect: true,
                reply: false,
            },
            DialMeta::default(),
        );
        t.drain();
        let a = arm(&t, Some("home"), OutboxCarrier::Lan).unwrap();
        assert_eq!(
            (a.connect.backoff, a.reply.backoff),
            (0, 0),
            "samples reset both"
        );
        // rttvar (3·843)/4 = 632, RTO = 4000 + 2528 ms.
        assert_eq!(lan().reply_first, ms(13_056));
        // A sample resets the p2p connect too.
        dialled(
            OutboxCarrier::P2p,
            ack(),
            times(Some(4_000), Some(4_000)),
            Expired::default(),
            DialMeta::default(),
        );
        t.drain();
        assert_eq!(p2p().connect, ms(13_056));
        // A dial whose network changed mid-way is no evidence: no backoff.
        let at_start = net();
        t.set_net(Some("office"));
        let frames = vec![env(EnvType::Message)];
        observe_dial(
            &BOB,
            OutboxCarrier::Lan,
            None,
            None,
            &frames,
            &offer_only(),
            &times(None, None),
            Expired {
                connect: true,
                reply: true,
            },
            DialMeta::default(),
            at_start,
        );
        t.drain();
        t.set_net(Some("home"));
        assert_eq!(lan().reply_first, ms(13_056));
    }

    /// P6.13: a Karn-excluded dial (a resend of an object that went silent)
    /// gives a connect sample but no reply sample; the same dial without
    /// the exclusion does.
    #[test]
    fn karn_excluded_dials_take_no_reply_sample() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("home"));
        let karn = DialMeta {
            karn_exclude: true,
            ..DialMeta::default()
        };
        let ack = || Ok(vec![env(EnvType::Ack)]);
        dialled(
            OutboxCarrier::Internet,
            ack(),
            timing(),
            Expired::default(),
            karn,
        );
        t.drain();
        let a = arm(&t, Some("home"), OutboxCarrier::Internet).unwrap();
        assert_eq!((a.connect.n, a.reply.n), (1, 0));
        dialled(
            OutboxCarrier::Internet,
            ack(),
            timing(),
            Expired::default(),
            DialMeta::default(),
        );
        t.drain();
        let a = arm(&t, Some("home"), OutboxCarrier::Internet).unwrap();
        assert_eq!((a.connect.n, a.reply.n), (2, 1));
    }

    /// P6.13, a property over seeded dials: whatever the times, expiries,
    /// outcomes and Karn flags, no wait a dial is given is ever above
    /// today's (and no learned one below its floor); the idle reply wait
    /// is always today's.
    #[test]
    fn no_wait_ever_exceeds_the_static_value() {
        use crate::netutil::{DialProgress, CONNECT_TIMEOUT, PRODUCTION_REPLY_WAITS};
        struct XorShift(u64);
        impl XorShift {
            fn next(&mut self) -> u64 {
                self.0 ^= self.0 >> 12;
                self.0 ^= self.0 << 25;
                self.0 ^= self.0 >> 27;
                self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
            }
            fn ms(&mut self) -> Option<u32> {
                match self.next() % 4 {
                    0 => None,
                    1 => Some((self.next() % 200) as u32),
                    2 => Some((self.next() % 40_000) as u32),
                    _ => Some(self.next() as u32 >> (self.next() % 32)),
                }
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("home"));
        let mut rng = XorShift(0x5EED_6A13);
        let mut learned = 0;
        for step in 0..3_000 {
            let carrier = ALL[(rng.next() % 4) as usize];
            let result = match rng.next() % 3 {
                0 => Ok(vec![env(EnvType::Ack)]),
                1 => Ok(vec![b"offer".to_vec()]),
                _ => Err("lan connect: cannot connect (no answer within 1.5s)".to_string()),
            };
            let timing = times(rng.ms(), rng.ms());
            let expired = Expired {
                connect: rng.next().is_multiple_of(3),
                reply: rng.next().is_multiple_of(3),
            };
            let meta = DialMeta {
                karn_exclude: rng.next().is_multiple_of(4),
                ..DialMeta::default()
            };
            dialled(carrier, result, timing, expired, meta);
            if step % 7 == 0 {
                t.drain();
            }
            for (c, label, connect) in [
                (OutboxCarrier::Lan, "LAN", CONNECT_TIMEOUT),
                (OutboxCarrier::Internet, "INTERNET", CONNECT_TIMEOUT),
                (OutboxCarrier::P2p, "P2P", Duration::from_secs(20)),
            ] {
                let w = waits(&BOB, c);
                let s = wait::statics(c);
                assert!(
                    w.connect <= s.connect && w.reply_first <= s.reply_first,
                    "{step}"
                );
                assert!(w.reply_first >= wait::MIN_REPLY_FIRST, "{step}");
                learned += usize::from(w.learned);
                let p = DialProgress::waiting(label, &w);
                assert!(p.connect.within <= connect, "{step}: {label}");
                let r = p.collector.waits();
                assert!(r.first <= PRODUCTION_REPLY_WAITS.first, "{step}: {label}");
                assert_eq!(r.idle, PRODUCTION_REPLY_WAITS.idle, "{step}: {label}");
            }
            assert_eq!(
                waits(&BOB, OutboxCarrier::Nearby),
                wait::statics(OutboxCarrier::Nearby)
            );
        }
        assert!(learned > 1_000, "the property saw learned waits: {learned}");
    }

    /// The 24-hour counts forget what is older.
    #[test]
    fn windows_count_the_last_24_hours() {
        let mut w = Window::default();
        let t0 = 1_800_000_000_000;
        w.add(t0);
        w.add(t0 + HOUR_MS);
        assert_eq!(w.total(t0 + HOUR_MS), 2);
        assert_eq!(w.total(t0 + 24 * HOUR_MS), 1);
        assert_eq!(w.total(t0 + 25 * HOUR_MS), 0);
        w.add(t0 + 30 * HOUR_MS);
        assert_eq!(w.total(t0 + 30 * HOUR_MS), 1);
    }
    // ── Exploration (P6.14) ─────────────────────────────────────────────────

    use raven_core::identity::Identity;
    use std::collections::BTreeSet;

    const MIN_MS: u64 = 60_000;
    const LAN: OutboxCarrier = OutboxCarrier::Lan;
    const INTERNET: OutboxCarrier = OutboxCarrier::Internet;
    const P2P: OutboxCarrier = OutboxCarrier::P2p;

    /// No outbox worker: the explorer has no context and does nothing.
    fn no_worker() -> Option<Arc<AttemptCtx>> {
        None
    }

    thread_local! {
        static TEST_WORKER: std::cell::RefCell<Option<Arc<AttemptCtx>>> =
            const { std::cell::RefCell::new(None) };
    }

    /// The worker context a test installed for its thread.
    fn test_worker() -> Option<Arc<AttemptCtx>> {
        TEST_WORKER.with(|w| w.borrow().clone())
    }

    /// The far side of every dial, in process: a carrier links (nothing but
    /// the peer's offer comes back) unless it is down (nobody answers), and
    /// the dial is observed as the carriers observe theirs. Every dial is
    /// logged: its route, its frame count and the contact.
    #[derive(Default)]
    struct ProbeNet {
        down: Mutex<Vec<OutboxCarrier>>,
        log: Mutex<Vec<(OutboxRoute, usize, [u8; 32])>>,
    }

    impl ProbeNet {
        fn set_down(&self, carrier: OutboxCarrier, down: bool) {
            let mut d = self.down.lock().unwrap();
            d.retain(|c| *c != carrier);
            if down {
                d.push(carrier);
            }
        }

        fn dials(&self) -> Vec<(OutboxRoute, usize, [u8; 32])> {
            self.log.lock().unwrap().clone()
        }
    }

    impl crate::outbox::Dialer for ProbeNet {
        fn dial(
            &self,
            _data_dir: &Path,
            route: &OutboxRoute,
            expected: &str,
            frames: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            let contact = parse_key(expected).expect("the contact's key");
            let at_start = net();
            self.log
                .lock()
                .unwrap()
                .push((route.clone(), frames.len(), contact));
            let (result, timing) = if self.down.lock().unwrap().contains(&route.carrier) {
                (
                    Err("cannot connect: no answer within 5.0s".to_string()),
                    DialTiming {
                        total_ms: 5_000,
                        ..DialTiming::default()
                    },
                )
            } else {
                let usual = usual(route.carrier);
                let link = DialTiming {
                    reply_ms: None,
                    total_ms: usual.connect_ms.unwrap_or_default(),
                    ..usual
                };
                (Ok(vec![b"offer".to_vec()]), link)
            };
            observe_dial(
                &contact,
                route.carrier,
                None,
                None,
                frames,
                &result,
                &timing,
                Expired::default(),
                DialMeta::default(),
                at_start,
            );
            result
        }
    }

    /// A contact book row for `key` with a LAN, an Internet and a p2p route.
    fn row(key: &[u8; 32], pinned: bool, hide_ip: bool) -> String {
        let peer_id = raven_core::p2p_route::local_peer_id(&Identity::from_seed(&[0x77; 32]));
        format!(
            r#"{{"petname":"P","pub_hex":"{}","pinned":{pinned},"hide_ip":{hide_ip},"lan_dial":"192.168.1.20:7420","internet_dial":"203.0.113.7:7422","p2p":"{peer_id}"}}"#,
            hex::encode(key)
        )
    }

    fn book(dir: &Path, rows: &[String]) {
        std::fs::write(dir.join("contacts.json"), format!("[{}]", rows.join(","))).unwrap();
    }

    /// The worker's context over `net`: LAN and Internet live, p2p when
    /// `p2p`.
    fn worker(dir: &Path, net: &Arc<ProbeNet>, p2p: bool) -> AttemptCtx {
        use crate::outbox::test_rig::{off, on, test_ctx};
        AttemptCtx {
            internet_live: on,
            p2p_live: if p2p { on } else { off },
            ..test_ctx(dir, Arc::new(Identity::from_seed(&[0xA1; 32])), net.clone())
        }
    }

    /// The explorer's rig: a learning service on network `home` with its
    /// own clock (from the wall clock's now), a contact book and a worker
    /// context over [`ProbeNet`].
    struct ExploreRig {
        dir: tempfile::TempDir,
        t: TestService,
        net: Arc<ProbeNet>,
        ctx: AttemptCtx,
        p2p: bool,
        at: u64,
    }

    impl ExploreRig {
        fn new(rows: &[String], p2p: bool) -> Self {
            let dir = tempfile::tempdir().unwrap();
            book(dir.path(), rows);
            let t = TestService::loaded(dir.path(), Some("home"));
            let net = Arc::new(ProbeNet::default());
            let ctx = worker(dir.path(), &net, p2p);
            let at = now_ms();
            t.set_now(at);
            Self {
                dir,
                t,
                net,
                ctx,
                p2p,
                at,
            }
        }

        fn at(&mut self, at: u64) {
            self.at = at;
            self.t.set_now(at);
        }

        fn advance(&mut self, ms: u64) {
            self.at(self.at + ms);
        }

        /// One exploration tick now; what its dial posted is applied.
        fn tick(&mut self) -> Option<Explored> {
            let explored = self.t.svc.explore_once(&self.ctx);
            self.t.drain();
            explored
        }

        /// A tick every minute for `minutes`: the probes, by minute.
        fn run(&mut self, minutes: u64) -> Vec<(u64, Explored)> {
            let mut probes = Vec::new();
            for minute in 0..minutes {
                if let Some(e) = self.tick() {
                    probes.push((minute, e));
                }
                self.advance(MIN_MS);
            }
            probes
        }

        fn wrote(&mut self, key: &[u8; 32], carrier: OutboxCarrier, delivered: bool) {
            self.t.wrote(key, carrier, delivered);
        }

        /// The static carrier order of a contact's plan here.
        fn statics(&self) -> Vec<OutboxCarrier> {
            let mut statics = vec![LAN, INTERNET];
            if self.p2p {
                statics.push(P2P);
            }
            statics
        }

        /// The learned first carrier of `key`.
        fn first(&self, key: &[u8; 32]) -> OutboxCarrier {
            plan(key, &self.statics()).unwrap().0.carriers[0]
        }

        /// `key`'s LAN delivered twice, then stopped answering while
        /// Internet delivered: Internet leads, LAN sits below its static
        /// place, and the worker remembered that order.
        fn lan_failed(&mut self, key: &[u8; 32]) {
            self.wrote(key, LAN, true);
            self.wrote(key, LAN, true);
            for _ in 0..4 {
                self.wrote(key, LAN, false);
                self.wrote(key, INTERNET, true);
            }
            let (order, net) = plan(key, &self.statics()).unwrap();
            assert_eq!(order.carriers[0], INTERNET);
            remember_order(key, net.as_deref(), &order);
        }

        fn arm(&self, key: &[u8; 32], carrier: OutboxCarrier) -> Option<Arm> {
            self.t
                .model()?
                .arm(&ArmKey {
                    contact: *key,
                    net: Some("home".into()),
                    carrier,
                })
                .copied()
        }
    }

    /// The gap tests assume the design's gaps, not the lab's.
    fn tuned() -> bool {
        let tuned = raven_core::learning::lab_tune().is_some();
        if tuned {
            eprintln!("skipped: RAVEN_LAB_LEARNING_TUNE replaces the exploration gaps");
        }
        tuned
    }

    /// A probe is a frame-less dial (`Dialer::probe_within` takes no
    /// frames): every dial the explorer made over six hours, on every
    /// carrier it chose, carried nothing, and the model took each as a
    /// probe (link evidence, `last_probe_ms`).
    #[test]
    fn probes_never_carry_frames() {
        let mut r = ExploreRig::new(&[row(&BOB, true, false)], true);
        r.lan_failed(&BOB);
        let probes = r.run(6 * 60);
        let dials = r.net.dials();
        assert!(probes.len() >= 6, "{probes:?}");
        assert_eq!(dials.len(), probes.len());
        assert!(dials.iter().all(|(_, frames, _)| *frames == 0), "{dials:?}");
        let carriers: BTreeSet<OutboxCarrier> = probes.iter().map(|(_, e)| e.carrier).collect();
        assert!(
            carriers.contains(&LAN) && carriers.contains(&P2P),
            "{carriers:?}"
        );
        for carrier in carriers {
            assert!(
                r.arm(&BOB, carrier).unwrap().last_probe_ms > 0,
                "{carrier:?}"
            );
        }
        assert!(probes.iter().all(|(_, e)| e.linked && e.contact == BOB));
        let st = r.t.status(&[BOB]);
        assert_eq!(st.probes_24h as usize, probes.len());
    }

    /// Only a contact written to within 7 days is explored: not a verified
    /// contact never written to, nor one last written to 8 days ago; and a
    /// week without a message ends the active one's probes too.
    #[test]
    fn only_active_pinned_contacts_are_probed() {
        let (carol, dave) = ([0xC0; 32], [0xD0; 32]);
        let rows = [
            row(&BOB, true, false),
            row(&carol, true, false),
            row(&dave, true, false),
        ];
        let mut r = ExploreRig::new(&rows, true);
        let t0 = r.at;
        r.at(t0 - 8 * DAY_MS);
        r.wrote(&dave, LAN, true);
        r.at(t0);
        r.wrote(&BOB, LAN, true);
        // Bob's LAN leads; his p2p arm (never dialled) is due hourly.
        let probes = r.run(3 * 60);
        assert_eq!(probes.len(), 3, "{probes:?}");
        assert!(
            probes
                .iter()
                .all(|(_, e)| e.contact == BOB && e.carrier == P2P),
            "{probes:?}"
        );
        r.at(t0 + ACTIVE_MS + MIN_MS);
        assert_eq!(r.run(3 * 60), []);
        assert!(r.net.dials().iter().all(|(_, _, key)| *key == BOB));
    }

    /// A stranger (not in the book), a blocked contact and an unverified
    /// one are never probed, however much this node wrote to them; the
    /// verified contact beside them is. An unverified contact's owed-ACK
    /// batch never explores either.
    #[test]
    fn a_stranger_blocked_or_unverified_contact_is_never_probed() {
        let (stranger, blocked, unverified) = ([0x5A; 32], [0xBB; 32], [0xE0; 32]);
        let rows = [
            row(&BOB, true, false),
            row(&blocked, true, false),
            row(&unverified, false, false),
        ];
        let mut r = ExploreRig::new(&rows, true);
        let mut blocks = raven_core::BlockList::default();
        blocks.block(&hex::encode(blocked));
        blocks.save(r.dir.path()).unwrap();
        for key in [BOB, stranger, blocked, unverified] {
            r.lan_failed(&key);
        }
        let probes = r.run(3 * 60);
        assert!(!probes.is_empty());
        let dials = r.net.dials();
        assert!(dials.iter().all(|(_, _, key)| *key == BOB), "{dials:?}");
        let (l, i) = (
            OutboxRoute {
                carrier: LAN,
                dial: "192.168.1.20:7420".into(),
            },
            OutboxRoute {
                carrier: INTERNET,
                dial: "203.0.113.7:7422".into(),
            },
        );
        let mut routes = vec![(i.clone(), i), (l.clone(), l)];
        let before = routes.clone();
        assert_eq!(
            explore_ack_order(&unverified, false, &r.statics(), &mut routes),
            None
        );
        assert_eq!(routes, before);
    }

    /// Review learning-2: "Pause sending to Bob until I check" (Phase 6b
    /// P6.31) stops probes too. Bob is active with a due p2p arm, yet while
    /// the hold lasts nothing is planned or dialled to him; resumed, he is
    /// probed again.
    #[test]
    fn a_contact_whose_sending_is_paused_is_never_probed() {
        let mut r = ExploreRig::new(&[row(&BOB, true, false)], true);
        r.wrote(&BOB, LAN, true);
        raven_core::node_policy::set_send_hold(r.dir.path(), &BOB, true).unwrap();
        assert_eq!(r.run(3 * 60), []);
        assert!(r.net.dials().is_empty(), "{:?}", r.net.dials());
        assert!(crate::outbox::explore_plan(&r.ctx, &BOB).is_none());
        raven_core::node_policy::set_send_hold(r.dir.path(), &BOB, false).unwrap();
        let probes = r.run(60);
        assert!(!probes.is_empty());
        assert!(probes
            .iter()
            .all(|(_, e)| (e.contact, e.carrier) == (BOB, P2P)));
    }

    /// A LAN or Internet arm is explored only after a receipt over it on
    /// this network within 7 days: not one that never delivered, delivered
    /// 8 days ago or only on another network. p2p needs no receipt (test
    /// above); here it is off.
    #[test]
    fn lan_and_internet_probes_need_a_past_receipt_on_this_network() {
        let keys: [[u8; 32]; 6] = [
            [0x10; 32], [0x20; 32], [0x30; 32], [0x40; 32], [0x50; 32], [0x60; 32],
        ];
        let [never, stale, elsewhere, fresh, inet_never, inet_fresh] = keys;
        let rows: Vec<String> = keys.iter().map(|k| row(k, true, false)).collect();
        let mut r = ExploreRig::new(&rows, false);
        let t0 = r.at;
        // LAN delivered 8 days ago, a day ago, only on another network, or
        // never; then it stopped answering while Internet delivered.
        r.at(t0 - 8 * DAY_MS);
        r.wrote(&stale, LAN, true);
        r.at(t0 - DAY_MS);
        r.wrote(&fresh, LAN, true);
        r.at(t0);
        r.t.set_net(Some("cafe"));
        r.wrote(&elsewhere, LAN, true);
        r.t.set_net(Some("home"));
        for key in [never, stale, elsewhere, fresh] {
            for _ in 0..4 {
                r.wrote(&key, LAN, false);
                r.wrote(&key, INTERNET, true);
            }
            assert_eq!(r.first(&key), INTERNET);
        }
        // LAN leads; Internet delivered a day ago, or never.
        r.at(t0 - DAY_MS);
        r.wrote(&inet_fresh, INTERNET, true);
        r.at(t0);
        r.wrote(&inet_never, INTERNET, false);
        for key in [inet_never, inet_fresh] {
            for _ in 0..2 {
                r.wrote(&key, LAN, true);
            }
            assert_eq!(r.first(&key), LAN);
        }
        // Only the fresh arms (and, once fresh's LAN is back on top, its
        // Internet arm, which delivered).
        let probed: BTreeSet<([u8; 32], OutboxCarrier)> = r
            .run(3 * 60)
            .into_iter()
            .map(|(_, e)| (e.contact, e.carrier))
            .collect();
        assert!(probed.contains(&(fresh, LAN)), "{probed:?}");
        assert!(probed.contains(&(inet_fresh, INTERNET)), "{probed:?}");
        assert!(
            probed
                .iter()
                .all(|(key, _)| [fresh, inet_fresh].contains(key)),
            "{probed:?}"
        );
    }

    /// The budget is global: a burst of two, then one probe per 10 minutes
    /// (6 per hour) however many arms are due, one in flight at a time; it
    /// is what `probes_24h` counts.
    #[test]
    fn the_budget_is_six_per_hour_burst_two() {
        let keys: Vec<[u8; 32]> = (1..=12u8).map(|i| [i; 32]).collect();
        let rows: Vec<String> = keys.iter().map(|k| row(k, true, false)).collect();
        let mut r = ExploreRig::new(&rows, true);
        for key in &keys {
            r.wrote(key, LAN, true);
        }
        {
            let _flight = r.t.svc.begin_flight().unwrap();
            assert!(r.t.svc.begin_flight().is_none());
            assert_eq!(r.tick(), None, "one probe in flight");
        }
        // Twelve p2p arms due every hour: twice what the budget allows.
        let probes = r.run(3 * 60);
        let minutes: Vec<u64> = probes.iter().map(|(m, _)| *m).collect();
        assert_eq!(minutes[..3], [0, 1, 10], "{minutes:?}");
        for start in 0..=120 {
            let n = minutes
                .iter()
                .filter(|m| (start..start + 60).contains(*m))
                .count();
            assert!(n <= 8, "{n} in the hour from minute {start}: {minutes:?}");
        }
        assert_eq!(
            minutes.iter().filter(|m| **m >= 60).count(),
            12,
            "6 per hour: {minutes:?}"
        );
        assert!(probes.iter().all(|(_, e)| e.carrier == P2P));
        assert_eq!(r.t.status(&keys).probes_24h as usize, probes.len());
    }

    /// Nothing is explored in the 2 minutes after netwatch saw the network
    /// change, probes and owed-ACK batches alike, nor while a newer Raven's
    /// file is kept in memory only. Settled, an owed-ACK batch puts the due
    /// arm first and spends the budget for it.
    #[test]
    fn no_probe_within_two_minutes_of_a_network_change() {
        if tuned() {
            return;
        }
        let mut r = ExploreRig::new(&[row(&BOB, true, false)], false);
        r.lan_failed(&BOB);
        r.advance(31 * MIN_MS);
        network_changed();
        // The test service reads no tag: back on `home`.
        r.t.set_net(Some("home"));
        assert_eq!(r.tick(), None);
        r.advance(MIN_MS + 59_000);
        assert_eq!(r.tick(), None);
        let (l, i) = (
            OutboxRoute {
                carrier: LAN,
                dial: "192.168.1.20:7420".into(),
            },
            OutboxRoute {
                carrier: INTERNET,
                dial: "203.0.113.7:7422".into(),
            },
        );
        let learned = vec![(i.clone(), i.clone()), (l.clone(), l.clone())];
        let mut routes = learned.clone();
        let statics = r.statics();
        assert_eq!(explore_ack_order(&BOB, true, &statics, &mut routes), None);
        assert_eq!(routes, learned);
        r.advance(1_000);
        // Settled: LAN (its failures cost 5 s) goes first, once.
        assert_eq!(
            explore_ack_order(&BOB, true, &statics, &mut routes),
            Some(LAN)
        );
        assert_eq!(routes, [(l.clone(), l), (i.clone(), i)]);
        assert_eq!(r.tick(), None, "LAN was explored just now");
        assert_eq!(r.t.status(&[BOB]).probes_24h, 1);
        // A newer Raven wrote the file: nothing is explored. Memory only for
        // another reason explores as usual.
        r.advance(2 * HOUR_MS);
        let store = |r: &ExploreRig, state: StoreState| {
            lock(&r.t.svc.model).as_mut().unwrap().store = state;
        };
        store(&r, StoreState::MemoryOnly("newer"));
        let mut routes = learned.clone();
        assert_eq!(explore_ack_order(&BOB, true, &statics, &mut routes), None);
        assert_eq!(r.tick(), None);
        store(&r, StoreState::MemoryOnly("keystore"));
        let probe = r.tick().expect("explored");
        assert_eq!((probe.contact, probe.carrier), (BOB, LAN));
    }

    /// An arm below its static place is re-tested every 15 minutes once it
    /// has a success streak (recovering), else hourly: LAN fails its probes
    /// at minutes 30 and 90, heals, and succeeds at 150 and 165.
    #[test]
    fn a_recovering_arm_is_retested_every_15_minutes_others_hourly() {
        if tuned() {
            return;
        }
        let mut r = ExploreRig::new(&[row(&BOB, true, false)], false);
        r.lan_failed(&BOB);
        r.net.set_down(LAN, true);
        let mut probes = r.run(91);
        r.net.set_down(LAN, false);
        probes.extend(r.run(170 - 91).into_iter().map(|(m, e)| (m + 91, e)));
        let seen: Vec<(u64, bool)> = probes.iter().map(|(m, e)| (*m, e.linked)).collect();
        assert_eq!(
            seen,
            [(30, false), (90, false), (150, true), (165, true)],
            "{probes:?}"
        );
        assert!(probes.iter().all(|(_, e)| e.carrier == LAN));
        assert_eq!(r.first(&BOB), INTERNET, "not recovered yet");
    }

    /// The user's switch goes off: the service's explorer stops within one
    /// poll however long it then runs, and starts again when it is back on
    /// (the contact's receipt, saved on the way off, keeps it active).
    #[tokio::test(start_paused = true)]
    async fn policy_off_stops_probes() {
        /// Waits (in real time: the probe dials on the blocking pool) for
        /// `n` dials, then lets the service apply what they posted.
        async fn dials(net: &ProbeNet, n: usize) -> usize {
            for _ in 0..1_000 {
                if net.dials().len() >= n {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
                tokio::task::yield_now().await;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            net.dials().len()
        }
        let dir = tempfile::tempdir().unwrap();
        book(dir.path(), &[row(&BOB, true, false)]);
        let mut t = TestService::install(true);
        let net = Arc::new(ProbeNet::default());
        let ctx = Arc::new(worker(dir.path(), &net, true));
        TEST_WORKER.with(|w| *w.borrow_mut() = Some(ctx));
        let mut at = now_ms();
        t.set_now(at);
        let task = tokio::spawn(run_on(
            t.svc,
            dir.path().to_path_buf(),
            Arc::new(Plain::default()),
            test_worker,
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(live_on());
        t.wrote(&BOB, LAN, true);
        // The first tick probes Bob's p2p arm (never dialled: due).
        tokio::time::sleep(EXPLORE_TICK).await;
        assert_eq!(dials(&net, 1).await, 1);
        // An hour later it is due again.
        at += HOUR_MS + MIN_MS;
        t.set_now(at);
        tokio::time::sleep(EXPLORE_TICK).await;
        assert_eq!(dials(&net, 2).await, 2);
        // Off: nothing more, however long.
        raven_core::node_policy::update_policy(dir.path(), |p| p.learning = Some(false)).unwrap();
        tokio::time::sleep(POLICY_POLL * 2).await;
        assert!(!live_on());
        at += 3 * HOUR_MS;
        t.set_now(at);
        tokio::time::sleep(EXPLORE_TICK * 3).await;
        assert_eq!(dials(&net, 3).await, 2);
        // On again.
        raven_core::node_policy::update_policy(dir.path(), |p| p.learning = None).unwrap();
        tokio::time::sleep(POLICY_POLL * 2).await;
        assert!(live_on());
        tokio::time::sleep(EXPLORE_TICK).await;
        assert_eq!(dials(&net, 3).await, 3);
        task.abort();
        TEST_WORKER.with(|w| *w.borrow_mut() = None);
        assert!(net.dials().iter().all(|(_, frames, _)| *frames == 0));
    }

    /// Hide-IP leaves Internet out of a contact's plan, so it is never
    /// probed there, though it delivered a day ago; the contact beside it
    /// gets its Internet probe. With the node's own hide-IP, nobody does.
    #[test]
    fn hide_ip_contacts_get_no_internet_probe() {
        let carol = [0xC0; 32];
        let mut r = ExploreRig::new(&[row(&BOB, true, true), row(&carol, true, false)], false);
        let t0 = r.at;
        for key in [BOB, carol] {
            r.at(t0 - DAY_MS);
            r.wrote(&key, INTERNET, true);
            r.at(t0);
            r.wrote(&key, LAN, true);
            r.wrote(&key, LAN, true);
        }
        let probes = r.run(2 * 60);
        assert!(!probes.is_empty());
        assert!(
            probes
                .iter()
                .all(|(_, e)| (e.contact, e.carrier) == (carol, INTERNET)),
            "{probes:?}"
        );
        raven_core::node_policy::update_policy(r.dir.path(), |p| p.hide_ip = true).unwrap();
        r.advance(2 * HOUR_MS);
        assert_eq!(r.run(2 * 60), []);
    }

    /// LAN went black and healed while no message was sent: the probes'
    /// links alone bring the static order back after at most 4 successes.
    /// The carrier on top is never the one probed.
    #[test]
    fn probe_outcomes_revive_a_recovered_lan() {
        let mut r = ExploreRig::new(&[row(&BOB, true, false)], false);
        r.lan_failed(&BOB);
        let mut successes = 0;
        let mut back = None;
        for minute in 0..4 * 60 {
            let top = r.first(&BOB);
            if back.is_none() && top == LAN {
                back = Some(successes);
            }
            if let Some(e) = r.tick() {
                assert_ne!(
                    e.carrier, top,
                    "minute {minute}: the top carrier was probed"
                );
                assert!(e.linked);
                if e.carrier == LAN {
                    successes += 1;
                }
            }
            r.advance(MIN_MS);
        }
        let back = back.expect("the static order came back");
        assert!(
            (1..=4).contains(&back),
            "LAN first again after {back} probe successes"
        );
    }

    // ── Carry choice (P6.16) ────────────────────────────────────────────────

    /// Friend custody live (or not) on this thread; back on drop.
    struct Custody;

    impl Custody {
        fn live(live: bool) -> Self {
            raven_core::custody_gate::set_custody_gates_for_this_thread(Some(CustodyGates {
                live,
                wan: false,
            }));
            Self
        }
    }

    impl Drop for Custody {
        fn drop(&mut self) {
            raven_core::custody_gate::set_custody_gates_for_this_thread(None);
        }
    }

    /// OD6a-14: an encounter (a link either way, a beacon answer through
    /// `custody::peer_seen`, a dial that linked) is kept only while carry
    /// choice is live (friend custody live and in use) and only for a
    /// verified, unblocked contact; carry outcomes likewise.
    #[test]
    fn no_encounter_is_recorded_without_custody() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), Some("home"));
        let carol = [0xCA; 32];
        let seen = |t: &mut TestService, how: u8| {
            match how {
                0 => encounter(&carol),
                1 => crate::custody::peer_seen(&carol),
                _ => observe_dial(
                    &carol,
                    OutboxCarrier::Lan,
                    None,
                    None,
                    &[],
                    &Ok(Vec::new()),
                    &DialTiming::default(),
                    Expired::default(),
                    DialMeta::default(),
                    net(),
                ),
            }
            t.drain();
            t.model().unwrap().encounter_of(&carol).is_some()
        };
        for how in 0..3 {
            // Friend custody not live: none, whatever the profile says.
            let custody = Custody::live(false);
            t.set_carry(true, &[carol]);
            assert!(!carry_live());
            assert!(!seen(&mut t, how), "{how}");
            drop(custody);
            let _custody = Custody::live(true);
            // Live but not in use (no consent, nothing listed): none.
            t.set_carry(false, &[carol]);
            assert!(!carry_live());
            assert!(!seen(&mut t, how), "{how}");
            // In use, but Carol is no verified, unblocked contact: none.
            t.set_carry(true, &[]);
            assert!(carry_live());
            assert!(!seen(&mut t, how), "{how}");
        }
        // Outcomes need carry choice too.
        let _custody = Custody::live(true);
        t.set_carry(false, &[carol, BOB]);
        carry_outcome(&BOB, &[carol], true);
        t.drain();
        assert!(t.model().unwrap().carry_of(&carol, &BOB).is_none());
        assert!(carry_pick(&BOB, &[(carol, None)]).is_none());
        // Live: each of the three is an encounter.
        for how in 0..3 {
            let mut fresh = TestService::loaded(dir.path(), Some("home"));
            fresh.set_carry(true, &[carol]);
            assert!(seen(&mut fresh, how), "{how}");
        }
        // Learning off: nothing, carry choice is not live.
        let off = TestService::install(true);
        off.set_carry(true, &[carol]);
        assert!(!carry_live());
        assert!(carry_pick(&BOB, &[(carol, None)]).is_none());
    }

    /// What a poll reads for carry choice: the verified, unblocked
    /// contacts, and custody in use with the user's consent or a custodian
    /// listed for a verified contact that is one too.
    #[test]
    fn carry_facts_read_consent_and_listed_custodians() {
        let dir = tempfile::tempdir().unwrap();
        let (carol, dave, erin) = ([0xCA; 32], [0xDA; 32], [0xE1; 32]);
        type Row<'a> = ([u8; 32], bool, &'a [[u8; 32]]);
        let book = |rows: &[Row<'_>]| {
            let rows: Vec<serde_json::Value> = rows
                .iter()
                .map(|(key, pinned, custodians)| {
                    serde_json::json!({
                        "pub_hex": hex::encode(key),
                        "pinned": pinned,
                        "custodians": custodians.iter().map(hex::encode).collect::<Vec<_>>(),
                    })
                })
                .collect();
            std::fs::write(
                dir.path().join("contacts.json"),
                serde_json::Value::Array(rows).to_string(),
            )
            .unwrap();
        };
        // Bob lists Dave, who is not verified: not in use without consent.
        book(&[(BOB, true, &[dave]), (carol, true, &[]), (dave, false, &[])]);
        let facts = carry_facts(dir.path(), false);
        assert!(!facts.in_use);
        assert_eq!(facts.pinned, [BOB, carol].into_iter().collect());
        assert!(carry_facts(dir.path(), true).in_use, "consent");
        // Bob lists Carol: in use.
        book(&[(BOB, true, &[carol]), (carol, true, &[]), (erin, true, &[])]);
        assert!(carry_facts(dir.path(), false).in_use);
        // Carol blocked: neither verified-and-unblocked nor in use.
        let mut blocks = raven_core::chat_history::BlockList::default();
        blocks.block(&hex::encode(carol));
        blocks.save(dir.path()).unwrap();
        let facts = carry_facts(dir.path(), false);
        assert!(!facts.in_use);
        assert_eq!(facts.pinned, [BOB, erin].into_iter().collect());
        // No book: nothing.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(carry_facts(empty.path(), false), CarryFacts::default());
    }

    /// A forwarder's next hops (`custody::forward_pass`): while carry
    /// choice is live, the same hops ordered by this node's own encounters
    /// (ties in the given order); otherwise exactly as given.
    #[test]
    fn forward_pass_order_is_a_permutation() {
        use rand::{Rng, SeedableRng};
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), None);
        let _custody = Custody::live(true);
        let hops: Vec<[u8; 32]> = (1..=6u8).map(|i| [i; 32]).collect();
        t.set_carry(false, &hops);
        encounter(&hops[5]);
        t.drain();
        assert_eq!(forward_order(&hops), hops, "not live: as given");
        t.set_carry(true, &hops);
        assert_eq!(forward_order(&hops), hops, "cold: as given");
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xf0_4d);
        let mut at = 1_800_000_000_000u64;
        for round in 0..200 {
            at += rng.gen_range(0..6 * HOUR_MS);
            t.set_now(at);
            encounter(&hops[rng.gen_range(0..hops.len())]);
            t.drain();
            let given: Vec<[u8; 32]> = (0..rng.gen_range(0..8))
                .map(|_| hops[rng.gen_range(0..hops.len())])
                .collect();
            let order = forward_order(&given);
            let (mut a, mut b) = (given.clone(), order.clone());
            a.sort_unstable();
            b.sort_unstable();
            assert_eq!(a, b, "{round}: the same hops");
            let model = t.model().unwrap();
            let p = |h: &[u8; 32]| model.predict_q16(h, at);
            assert!(order.windows(2).all(|w| p(&w[0]) >= p(&w[1])), "{round}");
        }
        // Only the fourth met: it goes first, the rest as given.
        drop(t);
        let mut t = TestService::loaded(dir.path(), None);
        t.set_carry(true, &hops);
        encounter(&hops[3]);
        t.drain();
        assert_eq!(
            forward_order(&hops),
            [hops[3], hops[0], hops[1], hops[2], hops[4], hops[5]]
        );
    }

    /// `LearningPlan` names carry choice's pick (P6.16) only while it is
    /// live and learned: each with how often this node meets it and its
    /// record; cold or not live: none.
    #[test]
    fn learning_plan_names_the_carry_pick() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), None);
        let _custody = Custody::live(true);
        let (carol, dave) = ([0xCA; 32], [0xDA; 32]);
        t.set_carry(true, &[BOB, carol, dave]);
        let custodians = |_: &[u8; 32]| vec![(carol, None), (dave, Some(1))];
        let carry = || match ipc_plan(1, &hex::encode(BOB), |_| Ok(RANKED.to_vec()), custodians) {
            IpcResponse::LearningPlan { carry, .. } => carry,
            other => panic!("{other:?}"),
        };
        assert!(carry().is_empty(), "cold");
        encounter(&dave);
        carry_outcome(&BOB, &[dave], true);
        t.drain();
        let rows = carry();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            (rows[0].peer_pub_hex.as_str(), rows[0].met.as_str()),
            (hex::encode(dave).as_str(), "often")
        );
        assert_eq!((rows[0].delivered, rows[0].outcomes), (1, 1));
        assert_eq!(
            (rows[1].peer_pub_hex.as_str(), rows[1].met.as_str()),
            (hex::encode(carol).as_str(), "never")
        );
        assert_eq!(t.status(&[BOB]).carriers, 1, "one carry row");
        t.set_carry(false, &[BOB, carol, dave]);
        assert!(carry().is_empty(), "not live");
    }
}
