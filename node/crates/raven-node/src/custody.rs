//! Friend custody fetcher (`docs/design/2026-10-friend-custody.md` §8.1): a
//! supervised task that collects this node's mail from its contacts'
//! custodians, ingests it under the hinted session and releases it there.
//! The park map is shared with the outbox worker's deposit phase (§7.3).
//!
//! Phase 3 (§19, learned custody): while custody rides route hints
//! ([`raven_core::custody_gate::custody_hints_live`]) each pass first
//! chooses this node's home custodians again
//! ([`raven_core::custody_home::refresh`]; a change is announced), fetches
//! from them for every verified contact, plans a custodian with the custody
//! offer it announced and the LAN beacon's finds, and keeps derived store
//! tags between passes ([`TagCache`]). A custodian whose last link was
//! relayed gets [`MAX_PAGES_PER_TRIGGER_RELAYED`] pages a trigger. `raven
//! outbox hand-off` arms a [`hand_off`] window for the outbox worker.
//!
//! All of it is behind the custody gate: with the gate closed for the life of
//! the process the task idles.
//!
//! **Custody handoff (Phase 5 P5.21, `RAVEN_CUSTODY_HANDOFF_V1.md` §3.2,
//! §3.6)**, behind [`raven_core::custody_gate::handoff_live`] as well, in the
//! same task: each fetch round also registers this node's inbound store tags
//! at the custodian (TAGS REGISTER, again every 6 h; a custodian that
//! answered OK within 24 h is announced with `HANDOFF_INBOX`,
//! [`handoff_inbox_ok`]), and after each
//! fetch pass the forwarder ([`forward_pass`]) hands the objects friends
//! left here for another friend on to that friend (HANDOFF/DELIVER). Handoff
//! parks and strikes ([`park_handoff`], [`strike_handoff`]) are kept apart
//! from plain custody's: a custodian without the handoff ops still takes
//! plain deposits.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use raven_core::custody_client::{
    custodian_routes, custody_after_ms, fetch_round, fetch_round_with, fetch_targets,
    forward_round, handoff_gate_closed, inbound_register_tags_cached, inbound_tags_cached,
    registration_wanted, FetchState, ItemAnswer, TagCache, TagRegistration, MAX_PAGES_PER_TRIGGER,
    MAX_PAGES_PER_TRIGGER_RELAYED,
};
use raven_core::custody_gate::{custody_hints_live, handoff_live, CustodyGates};
use raven_core::custody_handoff::{DueForward, HandoffStore};
use raven_core::friend_custody::CustodyCode;
use raven_core::identity::Identity;
use raven_core::outbox::{retry_delay, DeliveryPath, OutboxCarrier, OutboxRoute};
use tokio::sync::Notify;

use crate::onion::race::{RaceGuard, Side as RaceSide};
use tokio::time::Instant;

/// Base fetch interval per custodian.
const BASE_INTERVAL: Duration = Duration::from_secs(60);
/// The interval doubles after empty rounds up to this.
const MAX_INTERVAL: Duration = Duration::from_secs(600);
/// Empty rounds before the interval starts doubling.
const EMPTY_BEFORE_BACKOFF: u32 = 3;
pub(crate) const PARK_HOUR: Duration = Duration::from_secs(3_600);
/// The handoff park after UNSUPPORTED or NOT_VERIFIED, and the pair park
/// after NEXT_HOP_UNKNOWN (handoff spec §3.2, §3.5).
pub(crate) const PARK_DAY: Duration = Duration::from_secs(86_400);
/// Deposit strikes within [`PARK_HOUR`] that park a custodian (and handoff
/// strikes that park handoff there).
const STRIKES_TO_PARK: usize = 3;
/// Phase 6b R6 (design A, step P6.28): what a custodian served failed
/// Raven's checks this many times within [`PARK_DAY`] (a bad object, an
/// unrequested item, a bad letter in its name): it is parked for a day.
const MISBEHAVED_STRIKES_TO_PARK: usize = 3;
/// Why such a custodian is parked. Only an explicit retry (`raven outbox
/// retry`, IPC `OutboxKick { retry: true }`, [`retry`]) lifts it: a
/// listener coming back ([`kick`]) says nothing about the custodian.
pub(crate) const CUSTODY_MISBEHAVED: &str = "CUSTODY_MISBEHAVED";
/// The forwarder's interval while forward rows are pending (lab override
/// `RAVEN_LAB_CUSTODY_FORWARD_MS`) ...
const FORWARD_INTERVAL: Duration = Duration::from_secs(60);
/// ... and its look while none is (a row whose kick never came).
const FORWARD_IDLE: Duration = Duration::from_secs(600);
/// Due forward rows one pass reads at most.
const FORWARD_ROWS_PER_PASS: usize = 256;
/// Forwarder dials per next hop and pass (16 objects each).
const FORWARD_DIALS_PER_HOP: usize = 4;
/// A custodian is announced with `HANDOFF_INBOX` while its last TAGS OK is
/// younger than this (handoff spec §3.6).
const INBOX_FRESH: Duration = Duration::from_secs(86_400);
/// TAG_UNKNOWN (the recipient has not registered yet): the row waits this
/// long, doubling up to [`TAG_UNKNOWN_MAX`], with ±50 % jitter.
const TAG_UNKNOWN_FIRST: Duration = Duration::from_secs(60);
const TAG_UNKNOWN_MAX: Duration = Duration::from_secs(600);
const PER_DIAL_DEADLINE: Duration = Duration::from_secs(45);
/// How many mail friends a fetch pass asks at the same time, at most
/// ([`fetch_pass_with`]). A node collects its own mail from at most two
/// ([`raven_core::custody_home::MAX_HOME`]); more are due at once only
/// while dropped ones drain or contacts list custodians of their own. The
/// rest follow as turns end.
const ASKED_AT_ONCE: usize = 4;
/// While mail friends are being asked, the pass sleeps until the next one's
/// time, a turn's end or a wake ([`Shared::ring`]), never shorter than this
/// (the fetcher's own shortest wait, [`Shared::next_wait`]) ...
const LOOK_AGAIN: Duration = Duration::from_millis(200);
/// ... and never longer than this: a custodian made due some other way is
/// asked within it.
const LOOK_AT_LEAST: Duration = Duration::from_secs(5);
/// A custodian whose turn in a fetch pass dialled it is asked again in the
/// same pass when it is due again, but no sooner than this after that turn
/// ended (a tenth of the fetch interval, at most this: [`PassTimes`]): kicks
/// within it make one more turn, not one each, and a custodian whose next
/// time is already past when its turn ends (one that is away, after a dial
/// of 75 s) is not dialled back to back. The rest is the pass's own: a pass
/// that ends while one rests leaves its due to the next pass, which asks it
/// at once, as one after the other did.
const AGAIN_AFTER: Duration = Duration::from_secs(5);
/// In one fetch pass, a custodian's turns that dial it start at most this
/// many times in one fetch interval (the pass's base interval: a lab
/// interval scales it), its first turn counted. A burst of wakes (a node's
/// start: its listeners, Tor, Tor's relays, seconds apart; a network that
/// comes and goes) asks a friend this often at most, not once for each
/// wake. Its own next times come an interval or more after its last turn
/// began, so they pass; only the retries of a friend that was not reached
/// and is owed releases (5 s, doubling) come sooner, and those then wait
/// for its window. A turn that dialled nothing (no route yet, nothing to
/// ask) takes no place: wakes before Tor could dial filled a friend's
/// window that only Tor reaches, which then waited up to an interval after
/// Tor came up (review mail-friends-4, finding 2). Counted per pass before
/// (review mail-friends-3 R1), the wakes at a node's start used up a
/// friend that is there, and its own next times then waited for the pass
/// to end behind friends that are away. Each pass begins with an empty
/// window.
const TURNS_IN_AN_INTERVAL: usize = 3;
/// A fetch pass gives a custodian that has had its turn in it another one
/// while the pass is younger than this; after that only one whose last
/// turn reached it, and only while a turn that holds the pass is still
/// out: one that started before then, or a custodian's first turn in the
/// pass (review mail-friends-4, finding 3: a friend that is there waited
/// behind a first turn that started late, of one that is away). So a
/// friend that is there is asked at its times for as long as friends that
/// are away keep the pass going, and the pass still ends: neither kind of
/// turn can follow another without end, each ends by its deadlines, and
/// then nothing starts but a custodian's first turn. The next pass reads
/// the mail friends, the home custodians and the forward rows again.
/// Twice an Internet or LAN dial's deadline and a Tor dial's together:
/// time for a friend that is away to be asked again, at its own times and
/// after the wakes that came during its turns. A custodian's first turn in
/// a pass has no such bound.
const NEW_TURNS_FOR: Duration = PER_DIAL_DEADLINE
    .saturating_add(ONION_DIAL_DEADLINE)
    .saturating_mul(2);
/// A custody dial over Tor has Tor's waits (design 2026-10-tor-fallback
/// §3.5): the onion dial's own deadline, and a little more.
const ONION_DIAL_DEADLINE: Duration =
    raven_core::onion::ONION_DIAL_DEADLINE.saturating_add(Duration::from_secs(5));
/// Tor (lab): a fetch poll over the onion route at most this often per
/// custodian, unless the last round there brought mail or the custodian
/// just linked to this node (design 2026-10-tor-fallback §3.6: an idle poll
/// is no reason to build Tor circuits). Deposits and the forwarder carry
/// mail: they always may.
const ONION_FETCH_EVERY: Duration = Duration::from_secs(30 * 60);
/// `raven outbox hand-off`: deposits skip the 60 s wait this long.
const HAND_OFF_WINDOW: Duration = Duration::from_secs(600);
/// A nearby encounter with a custodian makes it due at most this often
/// ([`encounter`]).
const ENCOUNTER_GAP: Duration = Duration::from_secs(300);
/// A link with a contact, or a LAN beacon find, makes its fetch or the rows
/// for it due at once at most this often ([`peer_seen`]): the spacing of a
/// route-hint kick and of an announce link.
const LINK_SEEN_GAP: Duration = Duration::from_secs(60);
/// Waiting contacts an encounter looks through at most ([`kick_carried`]):
/// every one in practice. Their custodians come from one read of the book
/// for all of them ([`raven_core::custody_client::deposit_custodians_for`]),
/// so mail for a contact past the 64 waiting longest no longer waits out
/// its backoff while a friend who may carry it is in range (review
/// nearby-7).
const CARRIED_LOOKUPS: usize = 4096;
/// Hand-offs armed at once, at most (one per contact, one for all).
const MAX_HAND_OFFS: usize = 64;
/// Home custodians are chosen again at least this often (a drain that ran
/// out, a policy ash changed), and at once after [`offers_changed`].
const HOME_REFRESH: Duration = Duration::from_secs(60);

/// The longest wait before an idle poll of a custodian that could not be
/// reached at all ([`unreachable_wait`]).
const UNREACHABLE_IDLE_MAX: Duration = Duration::from_secs(30 * 60);

/// The times a fetch pass keeps ([`fetch_pass_with`]).
#[derive(Clone, Copy, Debug)]
struct PassTimes {
    /// The fetch interval (a lab interval, `RAVEN_LAB_CUSTODY_FETCH_MS`,
    /// scales every wait).
    base: Duration,
    /// The rest between two turns of a custodian in a pass: a tenth of the
    /// fetch interval, at most [`AGAIN_AFTER`].
    again_after: Duration,
    /// [`NEW_TURNS_FOR`].
    new_turns_for: Duration,
}

impl PassTimes {
    fn now() -> Self {
        #[cfg(test)]
        if let Some(times) = PASS_TIMES_FOR_TESTS.with(std::cell::Cell::get) {
            return times;
        }
        Self::for_base(lab_fetch_interval().unwrap_or(BASE_INTERVAL))
    }

    /// A lab interval below [`SHORTEST_INTERVAL`] counts as that, as for
    /// the fetcher's own wait (review mail-friends-4, finding 6: with 0 ms
    /// a friend that is there was asked as fast as its turns ended).
    fn for_base(base: Duration) -> Self {
        let base = base.max(SHORTEST_INTERVAL);
        Self {
            base,
            again_after: (base / 10).min(AGAIN_AFTER),
            new_turns_for: NEW_TURNS_FOR,
        }
    }
}

/// The shortest fetch interval a lab interval sets ([`run_fetcher`],
/// [`PassTimes`]).
const SHORTEST_INTERVAL: Duration = Duration::from_millis(200);

#[cfg(test)]
thread_local! {
    /// The [`PassTimes`] of this test thread's passes (a test of a second
    /// turn in a pass need not wait minutes for it).
    static PASS_TIMES_FOR_TESTS: std::cell::Cell<Option<PassTimes>> =
        const { std::cell::Cell::new(None) };
    /// The not-reached lines this test thread's passes printed.
    static NOT_REACHED_FOR_TESTS: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
    /// Called on a turn's thread once it knows where its custodian can be
    /// dialled, before it takes the work ([`ask`]); a test sets it through
    /// a [`TurnGate`].
    static ROUTES_FOUND_FOR_TESTS: std::cell::RefCell<Option<RoutesFound>> =
        const { std::cell::RefCell::new(None) };
    /// The looks of this test thread's passes that ask several custodians
    /// at the same time ([`Pass::ask_at_once`]).
    static LOOKS_FOR_TESTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// A mail check's deadline as this test thread sees it
    /// ([`pass_deadline`]), in place of the process's own (it belongs to
    /// the embedded node's checks). This thread's only: a pass that asks
    /// several custodians at the same time sees it as it begins and at its
    /// looks, but its turns' threads see what the pass kept by then, and
    /// the process's own.
    static CHECK_DEADLINE_FOR_TESTS: std::cell::Cell<Option<CheckDeadline>> =
        const { std::cell::Cell::new(None) };
}

/// [`ROUTES_FOUND_FOR_TESTS`]: called with the custodian.
#[cfg(test)]
type RoutesFound = Arc<dyn Fn(&[u8; 32]) + Send + Sync>;

/// The wait after a fetch round that reached the custodian on no route,
/// the `failures`-th such round in a row (0 first): with something owed
/// there (`owed`: releases to send) a delivery's retry (5 s doubling to 10
/// min); else `base` doubling to [`UNREACHABLE_IDLE_MAX`].
fn unreachable_wait(failures: u32, owed: bool, base: Duration) -> Duration {
    if owed {
        return retry_delay(failures, jitter());
    }
    base.saturating_mul(2u32.saturating_pow(failures.min(16)))
        .min(UNREACHABLE_IDLE_MAX.max(base))
}

/// The line of a custodian a fetch did not reach at all: "contact #ab12
/// not reached for mail (onion_dial); due again in 60 s". The keeper's
/// short tag, the carrier tried last and its schedule's wait from now,
/// nothing else. Due, not asked: while other turns keep the pass going it
/// rests first ([`AGAIN_AFTER`]), and a pass that is old asks it no more
/// (review mail-friends-3 n4: "asked again in 0 s" was about 5 s then).
fn not_reached_line(
    custodian: &[u8; 32],
    carrier: Option<OutboxCarrier>,
    next: Duration,
) -> String {
    format!(
        "contact {} not reached for mail ({}); due again in {} s",
        crate::netutil::link_tag(custodian),
        carrier.map_or("unknown", OutboxCarrier::label),
        next.as_secs()
    )
}

/// The fetch line (counts, the carrier and the keeper's short tag only):
/// group copies counted apart from chat messages (E2 r9: "fetched
/// messages=2" said nothing about groups), "fetched messages=1 acks=0
/// refused=0 kept=0 group_copies=1 from contact #ab12 (lan_dial)". The
/// first four keep their order (the fault matrix reads them).
fn fetched_line(
    r: &raven_core::custody_client::FetchReport,
    carrier: Option<OutboxCarrier>,
    custodian: &[u8; 32],
) -> String {
    format!(
        "fetched messages={} acks={} refused={} kept={} group_copies={} from contact {} ({})",
        r.accepted_messages.saturating_sub(r.accepted_group_copies),
        r.accepted_acks,
        r.refused,
        r.retried,
        r.accepted_group_copies,
        crate::netutil::link_tag(custodian),
        carrier.map_or("unknown", OutboxCarrier::label)
    )
}

/// The notice for objects a keeper served under this node's tags that the
/// contact a tag names did not sign: someone else left them there. They are
/// released; the keeper could not tell, so it is not blamed (no strike).
/// Counts and the keeper's short tag only.
fn foreign_line(foreign: usize, custodian: &[u8; 32]) -> String {
    format!(
        "released {foreign} object(s) at contact {} that the contact they were left for did \
         not sign (someone else left them there; the keeper is not blamed)",
        crate::netutil::link_tag(custodian)
    )
}

/// What a wake that came while a custodian's turn was out (a kick, a
/// network change, Tor coming up, a link from it, its new routes, an
/// encounter) makes of it once the turn ends ([`Shared::end_fetch`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Woken {
    /// The turn reached it: it keeps its own next time.
    Kept,
    /// The turn reached nothing (no route, every dial failed): due at once.
    AtOnce,
    /// A mail check's budget cut the turn: due this long on, or at its own
    /// next time if that is still ahead and comes sooner, its empty rounds
    /// forgotten whichever wake it was (for a custodian whose turn is not
    /// out, a link and new routes keep them). Not at once: a node that runs
    /// on after the check (the iPhone's background node) dialled it the
    /// moment the check ended, with no budget (review mail-friends-3 R3);
    /// nor only at its own next time, up to 10 minutes on after a wake that
    /// asked for it (review mail-friends-5, finding B).
    After(Duration),
}

/// What showed a contact to this node ([`Shared::wake`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wake {
    /// An authenticated link from it ([`peer_seen`]).
    Linked,
    /// What this node plans for it changed: route hints, a LAN beacon find
    /// at a new address ([`routes_changed`]).
    Moved,
    /// A nearby encounter ([`encounter`]).
    Met,
}

/// The longest fetch interval after empty rounds for the base interval
/// `base`: [`MAX_INTERVAL`], ten base intervals (a lab interval,
/// `RAVEN_LAB_CUSTODY_FETCH_MS`, scales it too).
fn max_interval(base: Duration) -> Duration {
    base.saturating_mul(10).min(MAX_INTERVAL)
}

/// The fetch interval at a custodian after `empty` empty rounds in a row,
/// for the base interval `base`: `base` up to [`EMPTY_BEFORE_BACKOFF`] of
/// them, then doubling up to [`max_interval`].
fn idle_interval(empty: u32, base: Duration) -> Duration {
    if empty > EMPTY_BEFORE_BACKOFF {
        (base * 2u32.saturating_pow(empty - EMPTY_BEFORE_BACKOFF)).min(max_interval(base))
    } else {
        base
    }
}

#[derive(Default)]
struct Shared {
    /// custodian -> parked until (with why).
    parked: HashMap<[u8; 32], (Instant, &'static str)>,
    /// (custodian, peer) -> parked until (RECIPIENT_NOT_ACCEPTED): this
    /// node's DEPOSITs for that recipient there. While custody handoff is
    /// live the fetcher still collects that peer's mail there (review
    /// handoff-4).
    parked_pair: HashMap<([u8; 32], [u8; 32]), Instant>,
    /// Per-peer fetch backoff (`Retry(Peer)`): until.
    peer_backoff: HashMap<[u8; 32], Instant>,
    /// Per custodian: fetch state, next due, empty rounds.
    states: HashMap<[u8; 32], (FetchState, Instant, u32)>,
    /// Deposit strikes (PEER_CLOSED after an accepted link) per custodian.
    strikes: HashMap<[u8; 32], Vec<Instant>>,
    /// Phase 6b R6: misbehaviour strikes per custodian (within a day).
    misbehaved: HashMap<[u8; 32], Vec<Instant>>,
    /// The custodians a fetch pass asks now, several at the same time
    /// (each one's entry is out of `states` meanwhile), each with whether
    /// [`peer_seen`] named it since, or a kick, a network change or Tor
    /// coming up came ([`Shared::all_due`]).
    in_pass: HashMap<[u8; 32], bool>,
    /// Inbound store tags derived so far (§8.1), in memory only. A pass
    /// takes it out while it runs.
    tags: TagCache,
    /// How the last dial that reached each custodian travelled (fetch or
    /// deposit): a relayed one gets fewer pages a trigger.
    last_path: HashMap<[u8; 32], DeliveryPath>,
    /// Fetch rounds in a row in which every dial failed, per custodian.
    failures: HashMap<[u8; 32], u32>,
    /// Armed hand-offs (`raven outbox hand-off`): per contact, or `None`
    /// for every contact, until.
    hand_off: HashMap<Option<[u8; 32]>, Instant>,
    /// Learned custody offers changed ([`offers_changed`]): the next pass
    /// chooses the home custodians again.
    home_dirty: bool,
    /// When the home custodians were last chosen again.
    home_at: Option<Instant>,
    // ── Custody handoff (P5.21) ──
    /// custodian -> handoff parked until (with why); plain custody there is
    /// unaffected.
    handoff_parked: HashMap<[u8; 32], (Instant, &'static str)>,
    /// (custodian, next hop) -> handoff parked until (NEXT_HOP_UNKNOWN).
    handoff_pair_parked: HashMap<([u8; 32], [u8; 32]), Instant>,
    /// Handoff strikes (a handoff dial the custodian closed) per custodian;
    /// the plain `strikes` are not touched.
    handoff_strikes: HashMap<[u8; 32], Vec<Instant>>,
    /// Per next hop: no forwarder dial before (no route, a failed dial),
    /// and the failures in a row.
    forward_wait: HashMap<[u8; 32], (Instant, u32)>,
    /// Next hops whose rows are due at once, whatever their next try (that
    /// friend linked in: hand over now).
    forward_early: HashSet<[u8; 32]>,
    /// Every next hop's rows are due at once (a kick, a network change, an
    /// inbound FORWARD).
    forward_all: bool,
    /// When the forwarder looks next (`None`: on the next pass).
    forward_next: Option<Instant>,
    /// Next hops this node held rows for at its last passes (a link from
    /// one of them wakes the forwarder); cleared once nothing is pending.
    forward_hops: HashSet<[u8; 32]>,
    /// Custodians that answered this node's TAGS REGISTER with OK, when.
    inbox_ok: HashMap<[u8; 32], Instant>,
    /// A contact linked (perhaps with a new session): the next pass
    /// registers new tags even at a custodian that is not due.
    register_due: bool,
    /// Inbound store tags derived for registration (other days than
    /// `tags`'s), in memory only.
    register_tags: TagCache,
    /// Nearby encounters that made a custodian due ([`encounter`]): when.
    encounters: HashMap<[u8; 32], Instant>,
    /// Links and beacon finds that made a contact's fetch or rows due
    /// ([`peer_seen`]): when.
    linked: HashMap<[u8; 32], Instant>,
    /// Per custodian: when a fetch last dialled it over Tor.
    onion_fetch_at: HashMap<[u8; 32], Instant>,
    /// While a fetch pass asks several custodians at the same time: where
    /// it hears that one may have come due ([`Self::ring`]), with the
    /// number of the [`Bell`] that hung it.
    bell: Option<(u64, std::sync::mpsc::Sender<Note>)>,
}

fn shared() -> &'static Mutex<Shared> {
    static SHARED: OnceLock<Mutex<Shared>> = OnceLock::new();
    SHARED.get_or_init(Mutex::default)
}

fn notify() -> &'static Notify {
    static NOTIFY: OnceLock<Notify> = OnceLock::new();
    NOTIFY.get_or_init(Notify::new)
}

fn lock_of(m: &Mutex<Shared>) -> std::sync::MutexGuard<'_, Shared> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn lock() -> std::sync::MutexGuard<'static, Shared> {
    lock_of(shared())
}

impl Shared {
    /// May a fetch at `custodian` (`empty` rounds without mail there in a
    /// row) use the onion route at `now` ([`ONION_FETCH_EVERY`]): the last
    /// round brought mail (or none ran yet), the custodian linked to this
    /// node within [`LINK_SEEN_GAP`], or no fetch went there over Tor for
    /// [`ONION_FETCH_EVERY`].
    fn onion_fetch_ok(&self, custodian: &[u8; 32], empty: u32, now: Instant) -> bool {
        let within = |at: Option<&Instant>, span: Duration| {
            at.is_some_and(|at| now.saturating_duration_since(*at) < span)
        };
        empty == 0
            || within(self.linked.get(custodian), LINK_SEEN_GAP)
            || !within(self.onion_fetch_at.get(custodian), ONION_FETCH_EVERY)
    }

    /// [`kick`]: every custodian due at `now` ([`Self::all_due`]), parks
    /// cleared (save a misbehaving custodian's, which only [`Self::retry`]
    /// lifts).
    fn kick(&mut self, now: Instant) {
        self.all_due(now);
        // An explicit kick (OutboxKick) also clears parks.
        self.parked.retain(|_, (_, why)| *why == CUSTODY_MISBEHAVED);
        self.parked_pair.clear();
    }

    /// Every custodian due at `now` with its empty rounds forgotten, and
    /// every forward row. Each one a pass is asking (out of `states`
    /// meanwhile) is due again when its turn ends, as [`Woken`] says: at
    /// once if the turn reached nothing, a base interval on if a mail
    /// check's budget cut it ([`Self::end_fetch`]). A kick, a network
    /// change or Tor coming up during its dial was lost for it before.
    fn all_due(&mut self, now: Instant) {
        for (_, due, empty) in self.states.values_mut() {
            *due = now;
            *empty = 0;
        }
        for again in self.in_pass.values_mut() {
            *again = true;
        }
        self.forward_everything(now);
        self.ring();
    }

    /// A custodian may have come due: a fetch pass that is asking several
    /// at the same time looks now ([`Pass::ask_at_once`]), not at its next
    /// look.
    fn ring(&self) {
        if let Some((_, bell)) = &self.bell {
            let _ = bell.send(Note::Due);
        }
    }

    /// [`retry`]: [`Self::kick`], and a misbehaving custodian's park lifted
    /// too (with its strikes).
    fn retry(&mut self, now: Instant) {
        self.parked.clear();
        self.misbehaved.clear();
        self.kick(now);
    }

    /// Every forward row due at `now`, whatever its next try or its next
    /// hop's wait (handoff parks stay: they are the custodians' answers).
    /// Nothing while the handoff gate is closed: no forward pass would run
    /// to take it, and a look due in the past would wake the fetcher every
    /// 200 ms (review D-2).
    fn forward_everything(&mut self, now: Instant) {
        if !handoff_live() {
            return;
        }
        self.forward_all = true;
        self.forward_wait.clear();
        self.forward_next = Some(now);
    }

    /// [`peer_seen`] for custody handoff at `now`: `peer` is a next hop
    /// this node holds rows for (its rows are due now), and every new
    /// session's tags are registered on the next pass. `true`: wake the
    /// fetcher (a forward is due).
    fn seen_for_handoff(&mut self, peer: &[u8; 32], now: Instant) -> bool {
        self.register_due = true;
        if !self.forward_hops.contains(peer) {
            return false;
        }
        self.forward_early.insert(*peer);
        self.forward_wait.remove(peer);
        self.forward_next = Some(now);
        true
    }

    /// Is handoff parked at `custodian` (`hop`: or for that pair) at `now`?
    /// A plain park of the whole custodian (it refused custody, its links
    /// closed) holds handoffs too; a plain pair park does not.
    fn handoff_parked(&self, custodian: &[u8; 32], hop: Option<&[u8; 32]>, now: Instant) -> bool {
        let live = |until: &Instant| *until > now;
        self.parked
            .get(custodian)
            .is_some_and(|(until, _)| live(until))
            || self
                .handoff_parked
                .get(custodian)
                .is_some_and(|(until, _)| live(until))
            || hop.is_some_and(|h| {
                self.handoff_pair_parked
                    .get(&(*custodian, *h))
                    .is_some_and(live)
            })
    }

    fn park_handoff(
        &mut self,
        custodian: &[u8; 32],
        for_: Duration,
        why: &'static str,
        now: Instant,
    ) {
        self.handoff_parked.insert(*custodian, (now + for_, why));
    }

    fn park_handoff_pair(
        &mut self,
        custodian: &[u8; 32],
        hop: &[u8; 32],
        for_: Duration,
        now: Instant,
    ) {
        self.handoff_pair_parked
            .insert((*custodian, *hop), now + for_);
    }

    /// [`strike_handoff`] at `now`: `true` when this strike parked handoff
    /// at `custodian` (for [`PARK_HOUR`]).
    fn strike_handoff(&mut self, custodian: &[u8; 32], now: Instant) -> bool {
        let list = self.handoff_strikes.entry(*custodian).or_default();
        list.retain(|t| now.saturating_duration_since(*t) < PARK_HOUR);
        list.push(now);
        if list.len() < STRIKES_TO_PARK {
            return false;
        }
        list.clear();
        self.park_handoff(custodian, PARK_HOUR, "CUSTODY_HANDOFF_UNSUPPORTED", now);
        true
    }

    /// A forwarder dial to `hop` failed (or found no route) at `now`: no
    /// dial there before the retry delay (5 s doubling to 10 min).
    fn forward_failed(&mut self, hop: &[u8; 32], now: Instant) {
        let failures = self.forward_wait.get(hop).map_or(0, |(_, n)| *n);
        let wait = retry_delay(failures, jitter());
        self.forward_wait
            .insert(*hop, (now + wait, failures.saturating_add(1)));
    }

    /// [`handoff_inbox_ok`] at `now`.
    fn inbox_ok(&self, custodian: &[u8; 32], now: Instant) -> bool {
        self.inbox_ok
            .get(custodian)
            .is_some_and(|at| now.saturating_duration_since(*at) < INBOX_FRESH)
    }

    /// `peer` showed itself (`why`): `true` when it is a custodian waiting
    /// for its next fetch and that fetch is due at `now` now (wake the
    /// fetcher). A link from a custodian ([`Wake::Linked`]) pulls the fetch
    /// forward only while its last round reached nothing (it is back); one
    /// that answered keeps its schedule and its empty-round backoff (E2
    /// night: a link either way made the other side's fetch due at once with
    /// its backoff cleared, so two friends that each fetch from the other
    /// linked about twice a minute all night). New routes
    /// ([`Wake::Moved`]) pull it forward with the backoff kept; a nearby
    /// encounter ([`Wake::Met`]) starts the backoff over. One that names a
    /// custodian whose turn is out makes it due again when that turn ends,
    /// as [`Woken`] says ([`Self::end_fetch`]).
    fn wake(&mut self, peer: &[u8; 32], why: Wake, now: Instant) -> bool {
        let back = self.failures.get(peer).is_some_and(|n| *n > 0);
        if let Some((_, due, empty)) = self.states.get_mut(peer) {
            if why == Wake::Linked && !back {
                return false;
            }
            *due = now;
            if why == Wake::Met {
                *empty = 0;
            }
            self.ring();
            return true;
        }
        if let Some(again) = self.in_pass.get_mut(peer) {
            *again = true;
        }
        false
    }

    /// [`peer_seen`] at `now`: [`Self::peer_seen`] and, with `handoff`
    /// (its gate live), [`Self::seen_for_handoff`] for `peer` at most once
    /// per [`LINK_SEEN_GAP`]. E1: each link from a friend made what waited
    /// for it due at once (its fetch, or the rows for it, clearing their
    /// retry wait), and the link that work opened did the same on the
    /// friend's side: a custodian and the friend it hands rows to dialled
    /// each other back to back, about two links a second, each telling
    /// route hints. Within the gap the link still asks for new tags to be
    /// registered (`None`: nothing woken); else whether it woke the fetcher.
    fn linked(&mut self, peer: &[u8; 32], handoff: bool, now: Instant) -> Option<bool> {
        if handoff {
            self.register_due = true;
        }
        self.linked
            .retain(|_, at| now.saturating_duration_since(*at) < LINK_SEEN_GAP);
        if self.linked.contains_key(peer) {
            return None;
        }
        self.linked.insert(*peer, now);
        Some(self.seen_as(peer, Wake::Linked, handoff, now))
    }

    /// [`routes_changed`] at `now`: [`Self::wake`] ([`Wake::Moved`]) and,
    /// with `handoff`, [`Self::seen_for_handoff`] for `peer`. `true`: wake
    /// the fetcher.
    fn seen(&mut self, peer: &[u8; 32], handoff: bool, now: Instant) -> bool {
        self.seen_as(peer, Wake::Moved, handoff, now)
    }

    /// [`Self::wake`] for `why` and, with `handoff`, the rows for `peer`.
    fn seen_as(&mut self, peer: &[u8; 32], why: Wake, handoff: bool, now: Instant) -> bool {
        let mut wake = self.wake(peer, why, now);
        if handoff {
            wake |= self.seen_for_handoff(peer, now);
        }
        wake
    }

    /// [`encounter`]: [`Self::peer_seen`] for `peer` at most once per
    /// [`ENCOUNTER_GAP`], and with `handoff` (its gate live)
    /// [`Self::seen_for_handoff`] too. `None` inside the gap (nothing done);
    /// else whether it woke a custodian or made forward rows due.
    fn encounter(&mut self, peer: &[u8; 32], handoff: bool, now: Instant) -> Option<bool> {
        self.encounters
            .retain(|_, at| now.saturating_duration_since(*at) < ENCOUNTER_GAP);
        if self.encounters.contains_key(peer) {
            return None;
        }
        self.encounters.insert(*peer, now);
        Some(self.seen_as(peer, Wake::Met, handoff, now))
    }

    /// [`forward_hops`]: the next hops of the last passes, in key order.
    fn hops(&self) -> Vec<[u8; 32]> {
        let mut hops: Vec<[u8; 32]> = self.forward_hops.iter().copied().collect();
        hops.sort_unstable();
        hops
    }

    /// A fetch pass starts on `custodian` (its entry taken out of `states`).
    fn begin_fetch(&mut self, custodian: &[u8; 32]) {
        self.in_pass.insert(*custodian, false);
    }

    /// A fetch pass is done with `custodian`: due at `due` after `empty`
    /// empty rounds, unless a wake came meanwhile (a link from it or its new
    /// routes: perhaps it moved while the pass dialled where it was, cutoff
    /// F8; a kick, a network change, Tor coming up, an encounter): then as
    /// `woken` says ([`Woken`]). When it is due.
    fn end_fetch(
        &mut self,
        custodian: [u8; 32],
        state: FetchState,
        (due, empty): (Instant, u32),
        woken: Woken,
        now: Instant,
    ) -> Instant {
        let again = self.in_pass.remove(&custodian).unwrap_or(false);
        let (due, empty) = match woken {
            Woken::AtOnce if again => (now, empty),
            // Its own next time if that comes sooner (review mail-friends-6,
            // nit 2: a wake made it due later than none would have).
            Woken::After(wait) if again => {
                let after = now + wait;
                (if due > now { due.min(after) } else { after }, 0)
            }
            _ => (due, empty),
        };
        self.states.insert(custodian, (state, due, empty));
        due
    }

    /// [`network_changed`]: every custodian due at `now`, and every forward
    /// row ([`Self::all_due`]); parks and strikes stay.
    fn network_changed(&mut self, now: Instant) {
        self.all_due(now);
    }

    /// [`tor_ready`]: as after a network change, every custodian due at
    /// `now` with its empty rounds forgotten (so the idle-Tor rule,
    /// [`Self::onion_fetch_ok`], lets its onion route through), and every
    /// forward row ([`Self::all_due`]); parks and strikes stay.
    fn tor_ready(&mut self, now: Instant) {
        self.all_due(now);
    }

    /// [`note_deposit`]: `custodian` due by `due` at the latest (a base
    /// interval on, beyond a pass's longest sleep: nothing to ring).
    fn note_deposit(&mut self, custodian: &[u8; 32], due: Instant) {
        let entry = self
            .states
            .entry(*custodian)
            .or_insert_with(|| (FetchState::default(), due, 0));
        entry.1 = entry.1.min(due);
        entry.2 = 0;
    }

    /// [`parked`] at `now`.
    fn parked(
        &self,
        custodian: &[u8; 32],
        peer: Option<&[u8; 32]>,
        now: Instant,
    ) -> Option<&'static str> {
        if let Some((until, why)) = self.parked.get(custodian) {
            if *until > now {
                return Some(why);
            }
        }
        peer.and_then(|p| self.parked_pair.get(&(*custodian, *p)))
            .filter(|until| **until > now)
            .map(|_| "CUSTODY_RECIPIENT_REFUSED")
    }

    /// [`strike`] at `now`: `true` when this strike parked the custodian.
    fn strike(&mut self, custodian: &[u8; 32], now: Instant) -> bool {
        let list = self.strikes.entry(*custodian).or_default();
        list.retain(|t| now.saturating_duration_since(*t) < PARK_HOUR);
        list.push(now);
        if list.len() < STRIKES_TO_PARK {
            return false;
        }
        list.clear();
        if !self.misbehaving(custodian, now) {
            self.parked
                .insert(*custodian, (now + PARK_HOUR, "CUSTODY_UNSUPPORTED"));
        }
        true
    }

    /// Is `custodian` parked for misbehaviour at `now`? An answer that came
    /// back on a dial already under way then never shortens that park.
    fn misbehaving(&self, custodian: &[u8; 32], now: Instant) -> bool {
        self.parked
            .get(custodian)
            .is_some_and(|(until, why)| *why == CUSTODY_MISBEHAVED && *until > now)
    }

    /// [`strike_misbehaved`] at `now`: `true` when this strike parked the
    /// custodian (for [`PARK_DAY`], [`CUSTODY_MISBEHAVED`]).
    fn strike_misbehaved(&mut self, custodian: &[u8; 32], now: Instant) -> bool {
        let list = self.misbehaved.entry(*custodian).or_default();
        list.retain(|t| now.saturating_duration_since(*t) < PARK_DAY);
        list.push(now);
        if list.len() < MISBEHAVED_STRIKES_TO_PARK {
            return false;
        }
        list.clear();
        self.parked
            .insert(*custodian, (now + PARK_DAY, CUSTODY_MISBEHAVED));
        true
    }

    /// [`park_for_code`] at `now`.
    fn park_for_code(
        &mut self,
        custodian: &[u8; 32],
        peer: &[u8; 32],
        code: CustodyCode,
        now: Instant,
    ) {
        let park = |s: &mut Self, for_: Duration| {
            if !s.misbehaving(custodian, now) {
                s.parked.insert(*custodian, (now + for_, code.registry()));
            }
        };
        match code {
            CustodyCode::PolicyDenied | CustodyCode::Hold => park(self, PARK_HOUR),
            CustodyCode::NotVerified => park(self, Duration::from_secs(86_400)),
            CustodyCode::RecipientNotAccepted => {
                self.parked_pair
                    .insert((*custodian, *peer), now + PARK_HOUR);
            }
            CustodyCode::StoreFull
            | CustodyCode::Quota
            | CustodyCode::RateLimited
            | CustodyCode::Persistence => park(self, Duration::from_secs(60)),
            _ => {}
        }
    }

    /// [`hand_off`] at `now`: armed for [`HAND_OFF_WINDOW`]. Lapsed ones
    /// are dropped, and at most [`MAX_HAND_OFFS`] are kept (the oldest go).
    fn hand_off(&mut self, peer: Option<[u8; 32]>, now: Instant) {
        self.hand_off.retain(|_, until| *until > now);
        self.hand_off.insert(peer, now + HAND_OFF_WINDOW);
        while self.hand_off.len() > MAX_HAND_OFFS {
            let Some(oldest) = self
                .hand_off
                .iter()
                .min_by_key(|(_, until)| **until)
                .map(|(k, _)| *k)
            else {
                break;
            };
            self.hand_off.remove(&oldest);
        }
    }

    /// Is a hand-off for `peer` (or for every contact) armed at `now`?
    fn handed_off(&self, peer: &[u8; 32], now: Instant) -> bool {
        [Some(*peer), None]
            .iter()
            .any(|k| self.hand_off.get(k).is_some_and(|until| *until > now))
    }

    /// How long the fetcher may sleep at `now` (at most `base`, at least
    /// 200 ms): until the next custodian is due, a parked one not before its
    /// park ends (review D-2: a past-due entry the pass does not take, which
    /// a parked custodian is, made the loop spin every 200 ms).
    fn next_wait(&self, now: Instant, base: Duration) -> Duration {
        self.states
            .iter()
            .map(|(custodian, (_, due, _))| {
                let due = match self.parked.get(custodian) {
                    Some((until, _)) => (*due).max(*until),
                    None => *due,
                };
                due.saturating_duration_since(now)
            })
            // The forwarder's next look (handoff: none while the gate is
            // closed, nothing is ever scheduled then).
            .chain(self.forward_next.map(|t| t.saturating_duration_since(now)))
            .min()
            .unwrap_or(base)
            .clamp(Duration::from_millis(200), base)
    }

    /// After a pass: only custodians this node fetches from (`targets`)
    /// keep a schedule (review D-2). A deposit at a contact's custodian, or
    /// a drain that ran out, leaves an entry no pass takes again; due in
    /// the past, it would make the fetcher spin.
    fn keep_targets(&mut self, targets: &std::collections::HashSet<[u8; 32]>) {
        self.states
            .retain(|custodian, _| targets.contains(custodian));
        self.failures
            .retain(|custodian, _| targets.contains(custodian));
        self.onion_fetch_at
            .retain(|custodian, _| targets.contains(custodian));
    }

    /// [`offers_changed`]: the next pass chooses the home custodians again.
    fn offers_changed(&mut self) {
        self.home_dirty = true;
    }

    /// Should a pass at `now` choose the home custodians again (and note
    /// that it does)? After [`Self::offers_changed`], on the first pass and
    /// at least every [`HOME_REFRESH`].
    fn take_home_refresh(&mut self, now: Instant) -> bool {
        let due = self.home_dirty
            || self
                .home_at
                .is_none_or(|at| now.saturating_duration_since(at) >= HOME_REFRESH);
        if due {
            self.home_dirty = false;
            self.home_at = Some(now);
        }
        due
    }
}

/// A custodian linked to us, or the listener came up: fetch now.
pub(crate) fn kick() {
    lock().kick(Instant::now());
    notify().notify_one();
}

/// `raven outbox retry` (IPC `OutboxKick { retry: true }`): [`kick`], and a
/// custodian parked for misbehaviour ([`strike_misbehaved`]) is used again.
pub(crate) fn retry() {
    lock().retry(Instant::now());
    notify().notify_one();
}

/// `peer` linked in (an authenticated inbound link), at most once per
/// [`LINK_SEEN_GAP`] per contact ([`Shared::linked`]): a custodian whose
/// last fetch round reached nothing is fetched from now (it is back; one
/// that answered keeps its schedule, E2), the rows for it as a next hop are
/// due now, and a link still asks for new tags to be registered.
pub(crate) fn peer_seen(peer: &[u8; 32]) {
    // Carry choice (Phase 6a P6.16): an encounter, kept only while carry
    // choice is live and `peer` is a verified, unblocked contact.
    crate::learning::encounter(peer);
    let handoff = handoff_live();
    if lock().linked(peer, handoff, Instant::now()) == Some(true) {
        notify().notify_one();
    }
}

/// `peer` told us new routes, or the LAN beacon found it at a new address:
/// if it is a custodian we fetch from, fetch soon (its empty-round backoff
/// stays). One a fetch pass is dialling right now (perhaps at the address
/// it just replaced: a custodian that moved announces itself, cutoff F8) is
/// due again when that turn ends, as [`Woken`] says ([`Shared::end_fetch`]).
/// Custody handoff: a friend this node holds rows for is here (the mule
/// trigger), and a new session's tags want registering. Its callers space
/// it themselves (a route-hint kick once a minute per contact, a beacon
/// find at a new address once per round).
pub(crate) fn routes_changed(peer: &[u8; 32]) {
    crate::learning::encounter(peer);
    let handoff = handoff_live();
    if lock().seen(peer, handoff, Instant::now()) {
        notify().notify_one();
    }
}

/// A nearby pipe to `peer` came up (Phase 5 P5.33; Nearby design step 5.12
/// and cutoff addendum F11d): if it is a custodian we fetch from, fetch from
/// it now ([`peer_seen`]), and (custody handoff) if it is a next hop this
/// node holds rows for, hand them over now; at most once per
/// [`ENCOUNTER_GAP`] per peer, instead of waiting for the timers. A no-op
/// while the custody gates are closed (nothing is tracked). `true`: a new
/// encounter with the gates live; the caller then lets the outbox leave
/// with `peer` what it may carry ([`kick_carried`]), since the pipe-up kick
/// reaches only `peer`'s own mail.
pub(crate) fn encounter(peer: &[u8; 32]) -> bool {
    if !CustodyGates::current().live {
        return false;
    }
    // Carry choice (Phase 6a P6.16): an encounter for learning too (its
    // model merges encounters within 30 min, so it sees every pipe-up, not
    // only the ones past ENCOUNTER_GAP).
    crate::learning::encounter(peer);
    let handoff = handoff_live();
    let Some(wake) = lock().encounter(peer, handoff, Instant::now()) else {
        return false;
    };
    if wake {
        notify().notify_one();
    }
    true
}

/// Blocking. Custody on a nearby encounter with `custodian` (P5.33, cutoff
/// addendum; [`encounter`] said it is new): the contacts something waits for
/// (objects or owed ACKs; up to [`CARRIED_LOOKUPS`], the longest waiting
/// first) whose custodians include it (the worker's own list:
/// [`raven_core::custody_client::deposit_custodians`], or, while carry
/// choice is live, every candidate it picks from,
/// [`raven_core::custody_client::custodian_candidates`]) are due now, so
/// what may be left with it goes over the pipe while it is up, not after
/// their backoff. A plain kick: their backoff stands (G5). How many
/// contacts (a counts-only line when any).
pub(crate) fn kick_carried(data_dir: &Path, local: &[u8; 32], custodian: &[u8; 32]) -> usize {
    let wall = raven_core::clock::now_ms();
    let carried = carried_from(
        data_dir,
        local,
        custodian,
        crate::outbox::waiting_peers,
        wall,
    );
    for peer in &carried {
        crate::outbox::kick(Some(peer), false, false);
    }
    if !carried.is_empty() {
        eprintln!(
            "raven-node custody: a mail friend is nearby; retrying {} contacts",
            carried.len()
        );
    }
    carried.len()
}

/// [`kick_carried`]'s choice among what `waiting_peers` (the outbox's,
/// asked for at most [`CARRIED_LOOKUPS`]) names, with every contact's
/// custodians (or, while carry choice is live, candidates) from one read of
/// the book.
pub(crate) fn carried_from(
    data_dir: &Path,
    local: &[u8; 32],
    custodian: &[u8; 32],
    waiting_peers: impl FnOnce(usize) -> Vec<[u8; 32]>,
    wall: u64,
) -> Vec<[u8; 32]> {
    let waiting = waiting_peers(CARRIED_LOOKUPS);
    // While carry choice is live (Phase 6a P6.16) the worker picks among
    // every candidate, and meeting `custodian` is what raises it there, so
    // any contact it is a candidate of may now leave mail with it.
    let lists = if crate::learning::carry_live() {
        raven_core::custody_client::custodian_candidates_for(data_dir, local, &waiting, wall)
    } else {
        raven_core::custody_client::deposit_custodians_for(data_dir, local, &waiting, wall)
    };
    let lists: HashMap<_, _> = waiting.iter().copied().zip(lists).collect();
    carried_by(custodian, waiting, |peer| {
        lists.get(peer).cloned().unwrap_or_default()
    })
}

/// [`kick_carried`]'s choice: the contacts of `waiting` (never `custodian`
/// itself: its own mail rode the pipe-up kick) whose custodians
/// (`custodians_of`) include `custodian`.
fn carried_by(
    custodian: &[u8; 32],
    waiting: Vec<[u8; 32]>,
    mut custodians_of: impl FnMut(&[u8; 32]) -> Vec<([u8; 32], Option<u8>)>,
) -> Vec<[u8; 32]> {
    waiting
        .into_iter()
        .filter(|peer| peer != custodian && custodians_of(peer).iter().any(|(c, _)| c == custodian))
        .collect()
}

/// The next hops this node holds custody handoff rows for, as its last
/// forward passes saw them, in key order: nearby's background advertising
/// looks for them (Phase 5 F11d), the LAN beacon's join round goes while
/// there is one (review cross-3), and an encounter with one wakes the
/// forwarder ([`encounter`]). Nobody while the handoff gate is closed.
pub(crate) fn forward_hops() -> Vec<[u8; 32]> {
    if !handoff_live() {
        return Vec::new();
    }
    lock().hops()
}

/// Tests: `hop` is (`true`) or is no longer (`false`) a next hop of this
/// process's forward rows, as a forward pass notes it ([`forward_hops`]).
#[cfg(test)]
pub(crate) fn note_forward_hop_for_tests(hop: &[u8; 32], on: bool) {
    let mut s = lock();
    if on {
        s.forward_hops.insert(*hop);
    } else {
        s.forward_hops.remove(hop);
    }
}

/// This machine's network changed (`netwatch`): every custodian is due now.
/// Parks and strikes stay (they are the custodians' answers, not our
/// network's). With the custody gate closed the fetcher idles and nothing is
/// tracked, so this does nothing.
pub(crate) fn network_changed() {
    lock().network_changed(Instant::now());
    notify().notify_one();
}

#[cfg(test)]
thread_local! {
    /// [`tor_ready`] calls on this thread (a `#[tokio::test]` runs its
    /// tasks on it).
    static TOR_READY_CALLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// This node's Tor became usable (`crate::onion`): a helper life's first
/// ready (a start, a network change, a wake, a restart), Tor relays reached
/// after a ready from Tor's cache, or our own Tor working again (T11). Every
/// custodian is due now with its empty rounds forgotten, so the idle-Tor
/// rule ([`ONION_FETCH_EVERY`]) lets its onion route through: a mail friend
/// only Tor reaches is asked for what it holds as soon as Tor is ready, not
/// at the next poll (up to a minute later) or 30 minutes after the last Tor
/// fetch there. A custodian whose turn is out is due again when that turn
/// ends, as [`Woken`] says. Parks and strikes stay; with the custody gate
/// closed nothing is tracked, so this does nothing.
pub(crate) fn tor_ready() {
    #[cfg(test)]
    TOR_READY_CALLS.with(|n| n.set(n.get() + 1));
    lock().tor_ready(Instant::now());
    notify().notify_one();
}

/// How often [`tor_ready`] ran on this thread.
#[cfg(test)]
pub(crate) fn tor_ready_calls() -> u32 {
    TOR_READY_CALLS.with(std::cell::Cell::get)
}

/// A contact's custody offer (or the custodians it announced) changed
/// (`crate::hints`, RRH1 §12): the fetcher chooses this node's home
/// custodians again now.
pub(crate) fn offers_changed() {
    lock().offers_changed();
    notify().notify_one();
}

/// `raven outbox hand-off` (IPC `OutboxKick.custody_now`): for the next
/// [`HAND_OFF_WINDOW`] the worker leaves what waits for `peer` (`None`: for
/// every contact) with friends without the 60 s wait. A failed direct try is
/// still needed first.
pub(crate) fn hand_off(peer: Option<[u8; 32]>) {
    lock().hand_off(peer, Instant::now());
}

/// How old a message to `peer` must be before the worker leaves it with a
/// friend: 0 while a [`hand_off`] for it (or for every contact) is armed,
/// else [`custody_after_ms`].
pub(crate) fn custody_after_for(peer: &[u8; 32]) -> u64 {
    if lock().handed_off(peer, Instant::now()) {
        0
    } else {
        custody_after_ms()
    }
}

/// The worker deposited at `custodian`: an ACK may come back there.
pub(crate) fn note_deposit(custodian: &[u8; 32]) {
    lock().note_deposit(custodian, Instant::now() + BASE_INTERVAL);
}

/// A dial reached `custodian` and travelled `path` (the worker's deposits;
/// the fetcher notes its own).
pub(crate) fn note_path(custodian: &[u8; 32], path: DeliveryPath) {
    lock().last_path.insert(*custodian, path);
}

/// Is `custodian` (or the pair with `peer`) parked? Why.
pub(crate) fn parked(custodian: &[u8; 32], peer: Option<&[u8; 32]>) -> Option<&'static str> {
    lock().parked(custodian, peer, Instant::now())
}

/// A PEER_CLOSED on a custody dial after an accepted link: 3 within an hour
/// park the custodian for an hour (it is likely an old build). The park is
/// logged, with counts only (carrier_matrix C33 waits for that line).
pub(crate) fn strike(custodian: &[u8; 32]) {
    if lock().strike(custodian, Instant::now()) {
        eprintln!(
            "raven-node custody: a friend closed {STRIKES_TO_PARK} deposit links within an \
             hour; no custody link to it for an hour (CUSTODY_UNSUPPORTED)"
        );
    }
}

/// Phase 6b R6 (design A, step P6.28; the responses gate, which the
/// caller checks): what `custodian` served failed Raven's checks. The
/// [`MISBEHAVED_STRIKES_TO_PARK`]-th strike within a day parks it for a
/// day (no deposit there, no fetch from it); it stays a contact and a
/// friend, and [`retry`] lifts the park. `true` when this strike parked it.
/// The park is logged with counts only.
pub(crate) fn strike_misbehaved(custodian: &[u8; 32]) -> bool {
    let parked = lock().strike_misbehaved(custodian, Instant::now());
    if parked {
        eprintln!(
            "raven-node custody: what a friend's mailbox served failed Raven's checks \
             {MISBEHAVED_STRIKES_TO_PARK} times within a day; not using it as a mailbox for a \
             day ({CUSTODY_MISBEHAVED})"
        );
    }
    parked
}

/// How the custodian's answer parks it (§7.3 step 3).
pub(crate) fn park_for_code(custodian: &[u8; 32], peer: &[u8; 32], code: CustodyCode) {
    lock().park_for_code(custodian, peer, code, Instant::now());
}

/// An inbound HANDOFF was dispatched (`lan_direct`, `internet_direct`): a
/// FORWARD left here is handed on within about 200 ms, not at the next
/// interval. Every forward row is due now.
pub(crate) fn kick_forward() {
    if !handoff_live() {
        return;
    }
    lock().forward_everything(Instant::now());
    notify().notify_one();
}

/// Is handoff parked at `custodian` (`hop`: or for the pair)? A plain park
/// of the whole custodian holds handoffs too.
pub(crate) fn handoff_parked(custodian: &[u8; 32], hop: Option<&[u8; 32]>) -> bool {
    lock().handoff_parked(custodian, hop, Instant::now())
}

/// Park handoff (only) at `custodian` for `for_` (handoff spec §3.2, §3.5).
pub(crate) fn park_handoff(custodian: &[u8; 32], for_: Duration, why: &'static str) {
    lock().park_handoff(custodian, for_, why, Instant::now());
}

/// Park handoff at `custodian` towards `hop` for `for_` (NEXT_HOP_UNKNOWN:
/// the next announced inbox is tried instead).
pub(crate) fn park_handoff_pair(custodian: &[u8; 32], hop: &[u8; 32], for_: Duration) {
    lock().park_handoff_pair(custodian, hop, for_, Instant::now());
}

/// A handoff dial `custodian` closed (PEER_CLOSED): 3 within an hour park
/// handoff there for an hour; plain custody's strikes are not touched.
pub(crate) fn strike_handoff(custodian: &[u8; 32]) {
    strike_handoff_on(shared(), custodian, Instant::now());
}

/// Mark (or forget) `custodian`'s TAGS OK in the process-wide state.
#[cfg(test)]
pub(crate) fn set_inbox_ok_for_test(custodian: &[u8; 32], ok: bool) {
    let mut s = lock();
    if ok {
        s.inbox_ok.insert(*custodian, Instant::now());
    } else {
        s.inbox_ok.remove(custodian);
    }
}

/// Did `custodian` answer this node's TAGS REGISTER with OK within 24 h
/// (handoff spec §3.6)? The route-hints snapshot sets `HANDOFF_INBOX` on its
/// CUSTODIAN_TAG exactly then.
pub(crate) fn handoff_inbox_ok(custodian: &[u8; 32]) -> bool {
    handoff_live() && lock().inbox_ok(custodian, Instant::now())
}

/// Pages one fetch trigger may take from a custodian whose last link
/// travelled `last`: all of them over a direct link (one we opened, one it
/// opened, or one DCUtR made), fewer over a relay or before any link (a
/// friend relay's circuit budget).
fn pages_for(last: Option<DeliveryPath>) -> usize {
    match last {
        Some(DeliveryPath::Direct | DeliveryPath::HolePunched | DeliveryPath::Reversed) => {
            MAX_PAGES_PER_TRIGGER
        }
        Some(DeliveryPath::Relayed) | None => MAX_PAGES_PER_TRIGGER_RELAYED,
    }
}

/// The pages the letter round may fetch at a custodian after the base
/// round made `base_dials` dials there in the same trigger: what is left of
/// the trigger's budget ([`pages_for`]), at least one (review letters-5).
fn letter_pages(last: Option<DeliveryPath>, base_dials: usize) -> usize {
    pages_for(last).saturating_sub(base_dials).max(1)
}

/// Dial `routes` until one answers, starting with the one at `*first` (the
/// route that answered last in this fetch pass) and then the others in plan
/// order; the one that answers is remembered in `*first`. A fetch round
/// dials once per page: after the first page its later dials go straight to
/// the route that linked, not through a stale saved address planned before
/// it (a custodian that moved, cutoff F8). `Err` of the last route tried.
fn dial_in_turn<R, T>(
    routes: &[R],
    first: &mut usize,
    mut dial: impl FnMut(&R) -> Result<T, String>,
) -> Result<T, String> {
    let lead = (*first < routes.len()).then_some(*first);
    let order = lead
        .into_iter()
        .chain((0..routes.len()).filter(|i| Some(*i) != lead));
    let mut last = Err("no custodian route".to_string());
    for at in order {
        last = dial(&routes[at]);
        if last.is_ok() {
            *first = at;
            break;
        }
    }
    last
}

fn lab_fetch_interval() -> Option<Duration> {
    if !raven_core::pair_init::lab_test_a_enabled() {
        return None;
    }
    std::env::var("RAVEN_LAB_CUSTODY_FETCH_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_millis)
}

/// Dial one custodian route (the carriers the worker uses), and how its link
/// travelled: LAN and Internet direct links are always `direct`, a p2p link
/// says ([`crate::p2p::dial_with_path`]; `None`: not known). Within what is
/// left of a bounded mail check's budget for the pass that dials (`left`,
/// [`CheckBudget`]; `None`: no check bounds it), when that is shorter than
/// the dial's own deadline.
pub(crate) fn dial_route_path(
    handle: &tokio::runtime::Handle,
    data_dir: &Path,
    route: &OutboxRoute,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
    left: Option<Duration>,
) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String> {
    let direct = |replies| (replies, Some(DeliveryPath::Direct));
    handle.block_on(async {
        let work = async {
            match route.carrier {
                OutboxCarrier::Lan => {
                    crate::lan_direct::dial(data_dir, &route.dial, expected_pub_hex, frames)
                        .await
                        .map(direct)
                }
                OutboxCarrier::Internet => {
                    crate::internet_direct::dial(data_dir, &route.dial, expected_pub_hex, frames)
                        .await
                        .map(direct)
                }
                OutboxCarrier::P2p => {
                    crate::p2p::dial_with_path(data_dir, &route.dial, expected_pub_hex, frames)
                        .await
                }
                OutboxCarrier::Nearby => {
                    crate::nearby::dial(data_dir, &route.dial, expected_pub_hex, frames)
                        .await
                        .map(direct)
                }
                // A custodian's Tor route (lab, `custodian_routes`): a
                // deposit, the forwarder, a fetch within ONION_FETCH_EVERY;
                // its path is Tor. Every pass plans the friend's nearby
                // route after it (`nearby::custodian_route`): a pipe to the
                // friend that is up meanwhile cuts it ([`onion_unless_pipe`]).
                OutboxCarrier::Onion => {
                    let pipe = crate::internet_direct::parse_pub_hex(expected_pub_hex)
                        .ok()
                        .and_then(|peer| crate::nearby::custodian_route(&peer))
                        .map(|(planned, _)| (planned, RaceGuard::new()));
                    let meta = crate::learning::DialMeta {
                        race: pipe.as_ref().map(|(_, race)| race.ticket(RaceSide::Onion)),
                        ..crate::learning::DialMeta::default()
                    };
                    let dial = crate::onion::dial_with_meta(
                        data_dir,
                        &route.dial,
                        expected_pub_hex,
                        frames,
                        meta,
                    );
                    match &pipe {
                        Some((planned, race)) => {
                            onion_unless_pipe(dial, race, || {
                                crate::nearby::route_connected(planned)
                            })
                            .await
                        }
                        None => dial.await,
                    }
                    .map(|replies| (replies, None))
                }
            }
        };
        let own = if route.carrier == OutboxCarrier::Onion {
            ONION_DIAL_DEADLINE
        } else {
            PER_DIAL_DEADLINE
        };
        // A bounded mail check (embedded node, iOS background refresh):
        // no dial outlives the budget of the pass that dials, not even once
        // the check has let go of its deadline (review mail-friends-4,
        // finding 5: each dial read the process's deadline as it was).
        within_deadline(work, own, left).await
    })
}

/// `work` (a custody dial) within its own deadline (`own`), or within what
/// is left of a bounded mail check's budget (`left`; `None`: no check runs)
/// when that is shorter. A dial the budget cuts before it is answered says
/// [`MAIL_CHECK_BUDGET`], not that the custodian did not answer in its time
/// (review mail-friends-2 N2: that counted as a failure, with its backoff,
/// for a friend that was given a second). Once the budget is spent the
/// dial does not go out.
async fn within_deadline<T>(
    work: impl std::future::Future<Output = Result<T, String>>,
    own: Duration,
    left: Option<Duration>,
) -> Result<T, String> {
    let (deadline, by_budget) = match left {
        Some(left) if left.is_zero() => return Err(MAIL_CHECK_BUDGET.into()),
        Some(left) if left < own => (left, true),
        _ => (own, false),
    };
    tokio::time::timeout(deadline, work)
        .await
        .unwrap_or_else(|_| {
            Err(if by_budget {
                MAIL_CHECK_BUDGET
            } else {
                "custody dial deadline"
            }
            .into())
        })
}

/// How often a custodian's Tor dial looks for a nearby pipe to the same
/// friend ([`onion_unless_pipe`]).
const PIPE_POLL: Duration = Duration::from_millis(200);

/// A custodian's Tor dial (`dial`, holding `race`'s onion ticket) while a
/// nearby pipe to the same friend may be up (`pipe_up`): once it is, the
/// pipe's side takes the race and Tor writes nothing
/// ([`crate::onion::race::RACE_LOST`]), so the nearby route, next in turn,
/// is dialled while the pipe is there. Waiting for Tor (up to 75 s) let the
/// pipe idle out unused (RNL1 §6: 30 s), as in the outbox (field test R1,
/// 2026-11-02). A Tor link that authenticated first goes on.
async fn onion_unless_pipe<T>(
    dial: impl std::future::Future<Output = Result<T, String>>,
    race: &RaceGuard,
    pipe_up: impl Fn() -> bool,
) -> Result<T, String> {
    let piped = async {
        loop {
            if pipe_up() {
                if crate::onion::race::claim(race.ticket(RaceSide::Direct)) {
                    return;
                }
                std::future::pending::<()>().await;
            }
            tokio::time::sleep(PIPE_POLL).await;
        }
    };
    tokio::select! {
        done = dial => done,
        () = piped => Err(crate::onion::race::RACE_LOST.into()),
    }
}

/// One custody dial as a fetch pass makes it: a route, the custodian's key
/// (hex), the frames; the replies and how the link travelled. A pass's
/// custodians are dialled at the same time, each from its own thread.
type PassDial<'a> = dyn Fn(&OutboxRoute, &str, &[Vec<u8>]) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String>
    + Sync
    + 'a;

/// What a fetch pass reaches beyond the data dir: the network, the LAN
/// beacon and the announcer (tests hand in their own).
struct PassIo<'a> {
    dial: &'a PassDial<'a>,
    /// Ask the LAN beacon to look for a due custodian, or for a next hop
    /// the forwarder is about to dial (`Want::Custody`).
    want: &'a dyn Fn(&[u8; 32]),
    /// Where the LAN beacon found a custodian just now.
    finds: &'a dyn Fn(&[u8; 32]) -> Vec<String>,
    /// A dial to one of those finds did not reach the custodian: the
    /// beacon forgets it (§7, review A-5). Called from the thread of the
    /// custodian's turn, one call at a time ([`AtWork`]).
    find_failed: &'a (dyn Fn(&[u8; 32], &str) + Sync),
    /// The home custodians changed (now this many): announce it.
    home_changed: &'a mut dyn FnMut(usize),
    /// The LAN carrier may carry custody now (its gate, `raven lan off`).
    lan: bool,
    /// Mail from `peer` was taken: kick its outbox (owed ACKs, a REPLY
    /// letter, a confirmed letter session).
    kick: &'a dyn Fn(&[u8; 32]),
    /// How many custodians the pass asks at the same time, at most
    /// ([`ASKED_AT_ONCE`]). 1: one after the other, each on the pass's own
    /// thread.
    at_once: usize,
    /// What is left of a bounded mail check's budget for this pass
    /// ([`CheckBudget`]; `None`: no check runs). Once it is spent no turn
    /// starts and no dial goes out.
    budget: &'a (dyn Fn() -> Option<Duration> + Sync),
}

impl PassIo<'_> {
    /// A bounded mail check's time is up: no new turn.
    fn budget_spent(&self) -> bool {
        (self.budget)().is_some_and(|left| left.is_zero())
    }
}

/// A custody dial with what is left of a bounded mail check's budget for
/// its pass (`None`: no check bounds it), as [`dial_route_path`] takes it.
type BudgetDial<'a> = dyn Fn(
        &OutboxRoute,
        &str,
        &[Vec<u8>],
        Option<Duration>,
    ) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String>
    + Sync
    + 'a;

/// A fetch pass that begins now, under a bounded mail check's budget as it
/// sees it ([`CheckBudget`]): `pass` makes the pass with a dial that hands
/// `net` what is left of the budget for each dial, and with the budget
/// itself ([`PassIo::budget`]). The node's passes are made through here
/// ([`node_pass`]), and so is one test's that asks one custodian at a
/// time.
fn within_check<R>(
    net: &BudgetDial<'_>,
    pass: impl FnOnce(&PassDial<'_>, &(dyn Fn() -> Option<Duration> + Sync)) -> R,
) -> R {
    let budget = CheckBudget::begin();
    let dial = |route: &OutboxRoute, expected: &str, frames: &[Vec<u8>]| {
        net(route, expected, frames, budget.left())
    };
    pass(&dial, &|| budget.left())
}

/// One fetch pass of the node (blocking pool): every due custodian, then
/// (custody handoff) one forward pass ([`node_pass`]), each dial over this
/// device's routes ([`node_dial`]).
fn fetch_pass(data_dir: &Path, identity: &Identity, handle: &tokio::runtime::Handle) {
    node_pass(shared(), data_dir, identity, &node_dial(handle, data_dir));
}

/// The node's custody dial ([`dial_route_path`]) with what is left of its
/// pass's budget: none left, it returns at once ([`MAIL_CHECK_BUDGET`]).
fn node_dial<'a>(handle: &'a tokio::runtime::Handle, data_dir: &'a Path) -> Box<BudgetDial<'a>> {
    Box::new(
        move |route: &OutboxRoute, expected: &str, frames: &[Vec<u8>], left: Option<Duration>| {
            dial_route_path(handle, data_dir, route, expected, frames, left)
        },
    )
}

/// [`fetch_pass`] on `shared`, every custody dial through `net` with what
/// is left of a check's budget ([`within_check`]): the node's own pass,
/// with the LAN beacon, the outbox and the announcer of this process. The
/// node gives it its own state and dial; a test, its own.
fn node_pass(shared: &Mutex<Shared>, data_dir: &Path, identity: &Identity, net: &BudgetDial<'_>) {
    within_check(net, |dial, budget| {
        let mut home_changed = |n: usize| {
            crate::hints::own_changed();
            eprintln!("raven-node custody: mail friends now {n}");
        };
        let mut io = PassIo {
            dial,
            want: &|c| crate::lan_beacon::want(c, crate::lan_beacon::Want::Custody),
            finds: &crate::lan_beacon::candidates,
            find_failed: &crate::lan_beacon::dial_failed,
            home_changed: &mut home_changed,
            lan: raven_core::custody_gate::carrier_gates_now().lan,
            // Mail that came through a friend does not show the contact is
            // directly reachable: a plain kick, the backoff stands (G5).
            kick: &|peer| {
                crate::outbox::kick(Some(peer), false, false);
            },
            at_once: ASKED_AT_ONCE,
            budget,
        };
        let inbox_changed = fetch_pass_with(
            shared,
            data_dir,
            identity,
            Instant::now(),
            raven_core::clock::now_ms(),
            &mut io,
        );
        if inbox_changed {
            // A custodian's HANDOFF_INBOX flag changed: every contact it is
            // announced to hears it (RRH1 §4, the per-contact snapshot).
            crate::hints::own_changed();
        }
        if handoff_live() {
            let pass = forward_pass_with(
                shared,
                data_dir,
                Instant::now(),
                raven_core::clock::now_ms(),
                &mut io,
            );
            if pass.dials > 0 || pass.dropped > 0 {
                // Counts only.
                eprintln!(
                    "raven-node custody: handed on {} kept {} refused {} dropped {}",
                    pass.handed, pass.kept, pass.refused, pass.dropped
                );
            }
        }
    });
}

/// [`fetch_pass`] on `shared` at `now` (monotonic) and `wall` (ms), through
/// `io`. `true`: a custodian's `HANDOFF_INBOX` (TAGS OK within 24 h) came
/// or went (announce it).
///
/// **Mail friends are asked at the same time.** Every custodian that is due
/// has a turn of its own ([`Pass::plan`], [`ask`], [`Pass::settle`]), and
/// with more than one custodian each turn runs on a thread of its own: a
/// friend's mail comes when that friend answers, whatever the others do.
/// A pass used to ask them one after the other, and the mail one friend
/// held waited behind a friend that was away for that one's whole dial,
/// over Tor 75 s and more. Three real machines, 2026-11-19 (W11-F1): with
/// two mail friends and the first by key off, the mail the other one held
/// came 62 s, 114 s and 88.6 s after the receiver's start. A wait chosen
/// in advance for the first one (tried for a day) only traded that case
/// for others: the dial times of one desktop node's log (877 answered Tor
/// dials) say a friend that is there needs up to 37 s on a fresh path, and
/// one that is off fails after 9 s to 113 s.
///
/// - **Only the waiting overlaps.** What a turn does on this device (taking
///   a page in, the stores, the letters), and working a turn out, is done
///   one at a time ([`AtWork`]): a turn lets go only while a dial of its
///   own is out. The stores see one fetch at a time, as before, page by
///   page. Only where a custodian can be dialled is looked up outside it
///   (a read: a saved name may take 5 s to resolve).
/// - **One that comes due meanwhile is asked meanwhile,** whether it has
///   had its turn in this pass or not: a wake (a link from it, new routes,
///   a kick, Tor coming up: [`Shared::ring`]) or its own next time starts
///   its turn at once, so it does not wait for the pass to end behind a
///   dial to a friend that is away. A custodian has one turn out at a
///   time and [`TURNS_IN_AN_INTERVAL`] in a fetch interval at most;
///   another one in the same pass comes no sooner than [`AGAIN_AFTER`]
///   after one that dialled it, and once the pass is [`NEW_TURNS_FOR`] old
///   only for one whose last turn reached it, while a turn that started
///   before then, or a custodian's first turn, is out. Mail a turn takes
///   in may bring a session, and with it tags the turns already asked did
///   not ask for: a custodian whose turn missed them is asked again
///   ([`Pass::retag`]).
/// - **At most `io.at_once` turns at the same time** ([`ASKED_AT_ONCE`]):
///   the rest follow as turns end, a custodian not asked yet in the pass
///   before one asked again, friends that answered their last round first
///   ([`in_asking_order`]), each worked out when its place frees. With one
///   custodian in all, or one at a time, each turn runs on the pass's own
///   thread, one after the other, once.
/// - **Nothing else changes:** who is asked, what each one is asked and
///   told, the dials' deadlines, each custodian's schedule, parks and
///   failures; a custodian that comes due during a long pass sees its
///   rounds then, not after the pass. In a bounded mail check every dial
///   that starts has what is left of the check's budget ([`CheckBudget`]),
///   and the turns share it by running at the same time; once it is spent
///   no turn starts and no dial goes out, and a turn the budget cut before
///   any of its dials was answered was no round there: it is due again on
///   its interval, or a base interval on if a wake came during it
///   ([`Woken`]).
fn fetch_pass_with(
    shared: &Mutex<Shared>,
    data_dir: &Path,
    identity: &Identity,
    now: Instant,
    wall: u64,
    io: &mut PassIo<'_>,
) -> bool {
    let local = identity.public_key_bytes();
    let hints_live = custody_hints_live();
    // Custody handoff (P5.21): each round registers this node's inbound
    // tags at the custodian (TAGS REGISTER ahead of RELEASE and FETCH).
    let handoff = handoff_live();
    let register_due = handoff && std::mem::take(&mut lock_of(shared).register_due);
    // Home custodians (Phase 3): chosen again after an offer changed and at
    // least every minute; a change is announced (counts only in the log).
    if hints_live && lock_of(shared).take_home_refresh(now) {
        if let Ok((home, true)) = raven_core::custody_home::refresh(data_dir, &local, wall) {
            (io.home_changed)(home.len());
        }
    }
    let Ok(targets) = fetch_targets(data_dir, &local, wall) else {
        // Not known now (an unreadable book, say): what was due waits a
        // round instead of being retried every 200 ms (review D-2).
        let base = lab_fetch_interval().unwrap_or(BASE_INTERVAL);
        for (_, due, _) in lock_of(shared).states.values_mut() {
            *due = (*due).max(now + base);
        }
        return false;
    };
    let target_keys: std::collections::HashSet<[u8; 32]> =
        targets.iter().map(|(custodian, _)| *custodian).collect();
    // The custody offers custodians announced (RRH1 §12), read once.
    let offers = if hints_live {
        raven_core::learned_routes::learned_custody_all(data_dir, wall)
    } else {
        HashMap::new()
    };
    let work = Mutex::new(());
    let asking = Asking {
        data_dir,
        identity,
        dial: io.dial,
        find_failed: io.find_failed,
        work: &work,
        budget: io.budget,
    };
    // Each cache is taken in a statement of its own: the schedule's lock is
    // let go before it is taken again.
    let cache = std::mem::take(&mut lock_of(shared).tags);
    let reg_cache = std::mem::take(&mut lock_of(shared).register_tags);
    let times = PassTimes::now();
    let mut pass = Pass {
        shared,
        asking: &asking,
        handoff,
        register_due,
        custody_live: CustodyGates::current().live,
        base: times.base,
        again_after: times.again_after,
        new_turns_for: times.new_turns_for,
        offers,
        cache,
        reg_cache,
        inbox_changed: false,
    };
    if io.at_once <= 1 || targets.len() <= 1 {
        // One after the other, each worked out when its turn comes.
        for (custodian, peers) in &targets {
            if io.budget_spent() {
                break;
            }
            if let Some(turn) = pass.plan(io, custodian, peers, (now, wall), true) {
                let asked = ask(turn, &asking);
                pass.settle(io, asked);
            }
        }
    } else {
        pass.ask_at_once(io, targets, (now, wall));
    }
    let mut s = lock_of(shared);
    s.tags = pass.cache;
    s.register_tags = pass.reg_cache;
    s.keep_targets(&target_keys);
    pass.inbox_changed
}

/// What every turn of one fetch pass works with, on whatever thread it
/// runs: the data dir, the identity, the network, and the pass's one
/// [`AtWork`] lock.
struct Asking<'a> {
    data_dir: &'a Path,
    identity: &'a Identity,
    dial: &'a PassDial<'a>,
    find_failed: &'a (dyn Fn(&[u8; 32], &str) + Sync),
    work: &'a Mutex<()>,
    /// What is left of a bounded mail check's budget for the pass
    /// ([`PassIo::budget`]).
    budget: &'a (dyn Fn() -> Option<Duration> + Sync),
}

impl Asking<'_> {
    /// A bounded mail check's time is up for the pass: no dial goes out.
    fn budget_spent(&self) -> bool {
        (self.budget)().is_some_and(|left| left.is_zero())
    }
}

/// One turn at a time: what the turns of a fetch pass do on this device
/// (taking a page in, the stores, the letters), while their dials overlap.
/// A turn holds this from the moment it knows where its custodian can be
/// dialled to its end, and lets go only while a dial of its own is out
/// ([`AtWork::away`]); the pass's thread holds it while it works a turn
/// out ([`Pass::plan`]), while it notes a turn's end ([`Pass::settle`])
/// and while it looks for tags a turn missed ([`Pass::retag`]). No dial
/// and no other turn is waited for while holding it (only what this
/// device's own work takes: the schedule's, the letters' and the beacon's
/// locks, the stores' file locks, which the app or the CLI may hold a
/// moment), and no lock a turn holds is held across its dial, so the turns
/// cannot hold each other up for longer than a page takes.
struct AtWork<'a> {
    lock: &'a Mutex<()>,
    held: Option<std::sync::MutexGuard<'a, ()>>,
}

impl<'a> AtWork<'a> {
    fn begin(lock: &'a Mutex<()>) -> Self {
        let held = Some(lock.lock().unwrap_or_else(|e| e.into_inner()));
        Self { lock, held }
    }

    /// `wait` (a dial) runs with the work let go, so the other turns go on
    /// meanwhile; the work is taken again before this turn goes on.
    fn away<T>(&mut self, wait: impl FnOnce() -> T) -> T {
        self.held = None;
        let out = wait();
        self.held = Some(self.lock.lock().unwrap_or_else(|e| e.into_inner()));
        out
    }
}

/// One custodian's turn in a fetch pass, as the pass's thread worked it
/// out ([`Pass::plan`]): everything its turn needs that is read under the
/// schedule's lock, from the tag caches or from the LAN beacon.
struct Turn {
    custodian: [u8; 32],
    /// When the pass found it due (monotonic, and wall ms): its turn's
    /// time, as a pass's time was every custodian's.
    now: Instant,
    wall: u64,
    state: FetchState,
    /// Empty rounds in a row before this turn.
    empty: u32,
    /// The peers whose mail it is asked for now.
    live_peers: Vec<[u8; 32]>,
    last_path: Option<DeliveryPath>,
    /// Handoff registration here (the gate open, handoff not parked at
    /// this custodian and not known to be missing there).
    registering: bool,
    /// The custody offer it announced.
    offer: Option<u8>,
    /// Where the LAN beacon found it just now.
    finds: Vec<String>,
    /// Its onion route may be used (the idle-Tor rule,
    /// [`Shared::onion_fetch_ok`]).
    onion: bool,
    tags: BTreeMap<[u8; 16], raven_core::relayed_ingest::RelayHint>,
    register: BTreeMap<[u8; 16], u64>,
    wants_tags: bool,
}

/// What a custodian's turn brought ([`ask`]), for the pass's thread to
/// note ([`Pass::settle`]).
struct Asked {
    /// The turn, with the custodian's fetch state as the rounds left it.
    turn: Turn,
    /// No route at all: nothing was asked.
    no_route: bool,
    report: Option<raven_core::custody_client::FetchReport>,
    letters: Option<raven_core::custody_client::LetterFetchReport>,
    /// Dials the custodian answered.
    answered: usize,
    /// How its last link travelled, when a dial said.
    path: Option<DeliveryPath>,
    /// The carrier of the last route that answered: the fetch line names
    /// it (counts and the carrier only), so a log shows that mail came
    /// over nearby alone (the field test's Bluetooth-only node).
    carrier: Option<OutboxCarrier>,
    /// The carrier of the last route dialled: the line of a custodian that
    /// was not reached names it.
    tried: Option<OutboxCarrier>,
    /// Whether this fetch dialled the custodian over Tor.
    over_tor: bool,
    /// Dials that went out and had their time (answered or not).
    dialled: usize,
    /// A dial the mail check's budget did not let out, or cut before it was
    /// answered ([`MAIL_CHECK_BUDGET`]): none of those says anything about
    /// the custodian or the route.
    cut: bool,
}

/// One custodian's turn ([`Turn`]): where it can be dialled now, the fetch
/// round, the letters, the withdraws; what that brought ([`Asked`]). It
/// runs at the same time as other custodians' turns, on a thread of its
/// own when the pass asks several, and touches nothing of the pass but
/// through `asking`: its dials go out with the work let go ([`AtWork`]),
/// everything else it does it does alone.
fn ask(mut turn: Turn, asking: &Asking<'_>) -> Asked {
    let custodian = turn.custodian;
    let (data_dir, identity, wall) = (asking.data_dir, asking.identity, turn.wall);
    // Where it can be dialled, before the work is taken: a saved name that
    // does not resolve is waited for here (up to 5 s,
    // `LOCALIZE_RESOLVE_TIMEOUT`), in this custodian's own turn.
    // The worker's on-link filter: right after a network change (which
    // makes every custodian due) an address learned on the network left
    // is not dialled.
    let mut routes = custodian_routes(data_dir, &custodian, turn.offer, &turn.finds, |ip| {
        crate::outbox::learned_lan_on_link(ip) != Some(false)
    });
    // Tor (lab): an idle poll builds no Tor circuits (ONION_FETCH_EVERY).
    if !turn.onion {
        routes.retain(|(planned, _)| planned.carrier != OutboxCarrier::Onion);
    }
    // Phase 5: over a nearby pipe too (last), under the custody gates.
    routes.extend(crate::nearby::custodian_route(&custodian));
    #[cfg(test)]
    if let Some(found) = ROUTES_FOUND_FOR_TESTS.with(|f| f.borrow().clone()) {
        found(&custodian);
    }
    let mut work = AtWork::begin(asking.work);
    let mut report = None;
    let mut letters = None;
    let (answered, mut path) = (std::cell::Cell::new(0usize), None);
    let carrier = std::cell::Cell::new(None::<OutboxCarrier>);
    let tried = std::cell::Cell::new(None::<OutboxCarrier>);
    let over_tor = std::cell::Cell::new(false);
    let (dialled, cut) = (std::cell::Cell::new(0usize), std::cell::Cell::new(false));
    let expected = hex::encode(custodian);
    let mut first = 0;
    let finds = &turn.finds;
    let mut dial = |frames: &[Vec<u8>]| {
        dial_in_turn(&routes, &mut first, |(planned, route)| {
            // Once the check's budget has cut a dial of this turn, or is
            // spent for the pass, nothing more goes out (review
            // mail-friends-3 R3: the next route went out with no budget
            // once the check had let go of its deadline).
            let got = if cut.get() || asking.budget_spent() {
                Err(MAIL_CHECK_BUDGET.to_string())
            } else {
                // The dial is out: the other turns go on meanwhile.
                work.away(|| (asking.dial)(route, &expected, frames))
            };
            if matches!(&got, Err(e) if e == MAIL_CHECK_BUDGET) {
                // The check's time was up before it went out or before it
                // was answered: nothing is learned about the custodian or
                // the route.
                cut.set(true);
                return got;
            }
            dialled.set(dialled.get() + 1);
            if route.carrier == OutboxCarrier::Onion {
                over_tor.set(true);
            }
            tried.set(Some(route.carrier));
            // A find that does not lead to the custodian is one no
            // longer (§7, review A-5).
            if let Err(e) = &got {
                if crate::outbox::custody_find_failed(finds, planned, e) {
                    (asking.find_failed)(&custodian, &planned.dial);
                }
            } else {
                carrier.set(Some(route.carrier));
            }
            got
        })
        .map(|(replies, how)| {
            answered.set(answered.get() + 1);
            path = how.or(path);
            replies
        })
    };
    if !routes.is_empty()
        && (!turn.tags.is_empty() || !turn.state.pending_release.is_empty() || turn.wants_tags)
    {
        let pages = pages_for(turn.last_path);
        report = Some(if turn.registering {
            crate::letters::with_handoff_caps(&custodian, |caps| {
                let register = TagRegistration {
                    custodian,
                    tags: &turn.register,
                    caps,
                };
                fetch_round_with(
                    data_dir,
                    identity,
                    &turn.tags,
                    Some(register),
                    &mut turn.state,
                    wall,
                    pages,
                    &mut dial,
                )
            })
        } else {
            fetch_round(
                data_dir,
                identity,
                &turn.tags,
                &mut turn.state,
                wall,
                pages,
                &mut dial,
            )
        });
    }
    // Sealed letters (Phase 5b): asked for with or without a live
    // session, since a letter brings its own; settled letters this
    // custodian holds for the senders whose mail came are withdrawn,
    // and (P5.16) this node's own LETTERs it holds whose messages went
    // directly since (a letter session completed directly). Not when
    // the base round just tried every route and none answered: the
    // letter round and the withdraws would only try the same dead
    // routes again in this pass. The two rounds share one page budget
    // (review letters-5).
    let base_dials = report.as_ref().map_or(0, |r| r.dials);
    let unreachable = base_dials > 0 && answered.get() == 0;
    if !routes.is_empty() && !unreachable {
        letters = crate::letters::fetch_at(
            data_dir,
            identity,
            &custodian,
            wall,
            letter_pages(turn.last_path, base_dials),
            &mut dial,
        );
        let mut peers: Vec<[u8; 32]> = letters
            .iter()
            .flat_map(|r| r.touched.iter().copied())
            .collect();
        for peer in crate::letters::letter_peers_at(data_dir, &custodian, wall) {
            if !peers.contains(&peer) {
                peers.push(peer);
            }
        }
        for peer in &peers {
            if let Ok(store) =
                raven_core::indexed_session_store::IndexedSessionStore::open(data_dir)
            {
                crate::letters::withdraw_settled(
                    data_dir,
                    &store,
                    peer,
                    Some(&custodian),
                    wall,
                    &mut |_: &[u8; 32], frames: &[Vec<u8>]| dial(frames),
                );
            }
        }
    }
    let (answered, carrier, tried, over_tor) =
        (answered.get(), carrier.get(), tried.get(), over_tor.get());
    Asked {
        no_route: routes.is_empty(),
        turn,
        report,
        letters,
        answered,
        path,
        carrier,
        tried,
        over_tor,
        dialled: dialled.get(),
        cut: cut.get(),
    }
}

/// What a turn's thread takes over from the pass's thread, where the pass
/// would have asked the custodian itself: the runtime the pass runs in
/// (the node's, on its blocking pool), and in tests the gates a test set
/// for its own thread only.
struct FromPassThread {
    runtime: Option<tokio::runtime::Handle>,
    #[cfg(test)]
    gates: Vec<TurnGate>,
}

/// A gate an in-process test set for its own thread only, as the call that
/// sets it again on a turn's thread ([`FromPassThread`]). Only what a test
/// pushes onto [`TURN_GATES`] reaches a turn's thread: the custody tests'
/// `Gates` push the custody gates, the hints, the carrier gates and the lab
/// letter switch. A test whose pass runs turns on their own threads
/// (`at_once` above 1, more than one custodian) and that sets any other
/// override of its thread (the handoff gate, base ops only, a policy, a
/// session lifetime...) pushes it there too, or its turns run without it;
/// the tests that set those run their passes one turn at a time, on their
/// own thread (`at_once: 1`).
#[cfg(test)]
type TurnGate = Arc<dyn Fn() + Send + Sync>;

/// Tests: no bounded mail check runs ([`PassIo::budget`]).
#[cfg(test)]
fn no_budget() -> Option<Duration> {
    None
}

#[cfg(test)]
thread_local! {
    /// This test thread's [`TurnGate`]s.
    static TURN_GATES: std::cell::RefCell<Vec<TurnGate>> =
        const { std::cell::RefCell::new(Vec::new()) };
    /// How many more turn threads this test thread's passes may start
    /// ([`on_its_own_thread`]; `None`: as many as they want). Past that,
    /// none is to be had.
    static TURN_THREADS_FOR_TESTS: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

impl FromPassThread {
    /// On the pass's thread.
    fn here() -> Self {
        Self {
            runtime: tokio::runtime::Handle::try_current().ok(),
            #[cfg(test)]
            gates: TURN_GATES.with(|gates| gates.borrow().clone()),
        }
    }

    /// On a turn's thread, for as long as the guard lives.
    fn enter(&self) -> Option<tokio::runtime::EnterGuard<'_>> {
        #[cfg(test)]
        for set in &self.gates {
            set();
        }
        self.runtime.as_ref().map(tokio::runtime::Handle::enter)
    }
}

/// What a turn's thread sends when it ends: what the turn brought, or the
/// panic that ended it.
type TurnEnd = std::thread::Result<Box<Asked>>;

/// What a fetch pass that asks several custodians at the same time hears
/// ([`Pass::ask_at_once`]).
enum Note {
    /// The turn of the pass's custodian with this number ended.
    Ended(usize, TurnEnd),
    /// A custodian may have come due ([`Shared::ring`]).
    Due,
}

/// Where a turn that was to start runs ([`on_its_own_thread`]).
enum Started {
    /// On a thread of its own: its end comes through the channel.
    OnItsThread,
    /// No thread could be started: the caller asks the custodian itself.
    Here(Box<Turn>),
}

/// Start `turn` (of the pass's custodian number `n`) on a thread of its own
/// in `scope`; once that thread runs, it sends its end through `ended`,
/// whatever that end is: everything it does, entering the pass's runtime
/// included, is inside the catch.
fn on_its_own_thread<'scope>(
    scope: &'scope std::thread::Scope<'scope, '_>,
    (n, turn): (usize, Turn),
    asking: &'scope Asking<'scope>,
    from: &'scope FromPassThread,
    ended: &std::sync::mpsc::Sender<Note>,
) -> Started {
    // The turn waits where both sides can reach it: a thread that could not
    // be started never ran, and the turn is still there for the caller.
    let slot = Arc::new(Mutex::new(Some(turn)));
    let theirs = Arc::clone(&slot);
    let ended = ended.clone();
    let body = move || {
        let end = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _here = from.enter();
            let turn = theirs.lock().unwrap_or_else(|e| e.into_inner()).take();
            Box::new(ask(turn.expect("a turn's thread has its turn"), asking))
        }));
        let _ = ended.send(Note::Ended(n, end));
    };
    #[cfg(test)]
    let none_left = TURN_THREADS_FOR_TESTS.with(|left| {
        let none = left.get() == Some(0);
        left.set(left.get().map(|n| n.saturating_sub(1)));
        none
    });
    #[cfg(test)]
    let thread = if none_left {
        // As when the system has no thread to give: the body never runs.
        drop(body);
        Err(std::io::Error::other("no thread (test)"))
    } else {
        std::thread::Builder::new()
            .name("raven-mail-friend".into())
            .spawn_scoped(scope, body)
            .map(drop)
    };
    #[cfg(not(test))]
    let thread = std::thread::Builder::new()
        .name("raven-mail-friend".into())
        .spawn_scoped(scope, body)
        .map(drop);
    match thread {
        Ok(()) => Started::OnItsThread,
        Err(_) => {
            let turn = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
            Started::Here(Box::new(
                turn.expect("a thread that did not start took no turn"),
            ))
        }
    }
}

/// The custodians of a pass in the order their turns start in: those that
/// answered their last round before those that were not reached in theirs
/// (`failures`), each group as it was (by key). It matters only with more
/// of them due than are asked at the same time ([`ASKED_AT_ONCE`]): a friend
/// that is away is away for a while, and the others should not wait for a
/// free place behind it in every pass.
fn in_asking_order(keepers: &mut [Keeper], failures: &HashMap<[u8; 32], u32>) {
    keepers.sort_by_key(|k| failures.get(&k.custodian).is_some_and(|n| *n > 0));
}

/// One custodian of a pass that asks several at the same time
/// ([`Pass::ask_at_once`]), and its turns in it so far.
struct Keeper {
    custodian: [u8; 32],
    /// The contacts whose mail it may hold (`fetch_targets`).
    peers: Vec<[u8; 32]>,
    /// Looked at in this pass: only its first look may take it before its
    /// time, for a new tag to register (rg3).
    looked: bool,
    /// Its turns in this pass.
    turns: u32,
    /// When its last turns that dialled it started (the pass's clock), the
    /// last [`TURNS_IN_AN_INTERVAL`] of them, and the one out.
    started: std::collections::VecDeque<Instant>,
    /// A turn of its is out ...
    out: bool,
    /// ... and it holds the pass ([`NEW_TURNS_FOR`]): it started while the
    /// pass was young, or it is its first in the pass.
    holds: bool,
    /// Its last turn that ended reached nothing there (no route, every
    /// dial failed, or the check's time was up): tags it missed are no
    /// reason to ask it again ([`Pass::retag`]).
    missed: bool,
    /// Its next turn in this pass starts no sooner (the pass's clock):
    /// [`AGAIN_AFTER`] after a turn of its that dialled it ended.
    rest_until: Option<Instant>,
    /// The peers its last turn asked for, and the tags it asked with.
    live_peers: Vec<[u8; 32]>,
    asked_for: HashSet<[u8; 16]>,
    /// While its turn is out, another turn's mail brought tags this one
    /// did not ask for: it is due again when it ends ([`Pass::retag`]).
    retag: bool,
}

impl Keeper {
    fn new((custodian, peers): ([u8; 32], Vec<[u8; 32]>)) -> Self {
        Self {
            custodian,
            peers,
            looked: false,
            turns: 0,
            started: std::collections::VecDeque::new(),
            out: false,
            holds: false,
            missed: false,
            rest_until: None,
            live_peers: Vec::new(),
            asked_for: HashSet::new(),
            retag: false,
        }
    }

    /// Its `turn` starts, in a pass that is `young` or not.
    fn starts(&mut self, turn: &Turn, young: bool) {
        // Neither a turn that starts while the pass is young nor a first
        // turn can follow another without end: either may hold the pass.
        self.holds = young || self.turns == 0;
        self.turns += 1;
        self.started.push_back(turn.now);
        self.live_peers.clone_from(&turn.live_peers);
        self.asked_for = turn.tags.keys().copied().collect();
        self.retag = false;
    }

    /// Its turn has ended; one that `dialled` nothing gives its place in
    /// the window back ([`TURNS_IN_AN_INTERVAL`]).
    fn ended(&mut self, dialled: bool) {
        if !dialled {
            self.started.pop_back();
        }
        while self.started.len() > TURNS_IN_AN_INTERVAL {
            self.started.pop_front();
        }
    }

    /// No turn of its starts before this (the pass's clock): `interval`
    /// after the first of its last [`TURNS_IN_AN_INTERVAL`] turns that
    /// dialled it began (`None`: it has had fewer).
    fn free_at(&self, interval: Duration) -> Option<Instant> {
        let n = self.started.len();
        (n >= TURNS_IN_AN_INTERVAL).then(|| self.started[n - TURNS_IN_AN_INTERVAL] + interval)
    }
}

/// While a pass asks several custodians at the same time, the schedule
/// rings it ([`Shared::ring`]); the bell comes down when the pass ends,
/// however it ends. Only its own: a pass of a node that stopped may end
/// after a new node's pass has hung its bell (review mail-friends-2 N3).
struct Bell<'a>(&'a Mutex<Shared>, u64);

impl<'a> Bell<'a> {
    fn hang(shared: &'a Mutex<Shared>, bell: &std::sync::mpsc::Sender<Note>) -> Self {
        static HUNG: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let number = HUNG.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        lock_of(shared).bell = Some((number, bell.clone()));
        Self(shared, number)
    }
}

impl Drop for Bell<'_> {
    fn drop(&mut self) {
        let mut s = lock_of(self.0);
        if s.bell.as_ref().is_some_and(|(number, _)| *number == self.1) {
            s.bell = None;
        }
    }
}

/// What a turn's end left for the pass ([`Pass::settle`]).
struct Settled {
    /// The peers whose mail it took in.
    touched: Vec<[u8; 32]>,
    /// A dial of it went out.
    dialled: bool,
    /// It reached nothing there ([`Keeper::missed`]).
    missed: bool,
}

/// One fetch pass's own things: what a custodian's turn is worked out from
/// ([`Pass::plan`]) and what is noted when it has ended
/// ([`Pass::settle`]), both on the pass's thread.
struct Pass<'a> {
    shared: &'a Mutex<Shared>,
    asking: &'a Asking<'a>,
    /// The handoff gate, and whether a contact linked since the last pass
    /// (a new tag may want registering even where no fetch is due).
    handoff: bool,
    register_due: bool,
    custody_live: bool,
    /// The fetch interval (a lab interval scales every wait).
    base: Duration,
    /// The rest between two turns of a custodian in this pass, and how long
    /// it gives those that had their turn another one ([`PassTimes`]).
    again_after: Duration,
    new_turns_for: Duration,
    /// The custody offers custodians announced (RRH1 §12), read once.
    offers: HashMap<[u8; 32], raven_core::learned_routes::LearnedCustody>,
    cache: TagCache,
    reg_cache: TagCache,
    inbox_changed: bool,
}

impl Pass<'_> {
    /// `custodian`'s turn, if it is due at `now` (monotonic, and wall ms):
    /// worked out here, on the pass's thread, with its entry taken out of
    /// `states` ([`Shared::begin_fetch`]). `None`: not now (parked, or not
    /// due yet: its entry stays). `first`: the pass's first look, which
    /// also takes a custodian that is not due but has a new tag to register
    /// (rg3); a later look takes only what came due. What it reads beyond
    /// the schedule (the stores' tags, the beacon) it reads with the turns'
    /// work held ([`AtWork`]), as a turn's own work: never while another
    /// turn is at its own.
    fn plan(
        &mut self,
        io: &PassIo<'_>,
        custodian: &[u8; 32],
        peers: &[[u8; 32]],
        (now, wall): (Instant, u64),
        first: bool,
    ) -> Option<Turn> {
        let (shared, handoff) = (self.shared, self.handoff);
        let (data_dir, identity) = (self.asking.data_dir, self.asking.identity);
        let custodian = *custodian;
        {
            let s = lock_of(shared);
            if s.parked(&custodian, None, now).is_some() {
                return None;
            }
            let later = |(_, due, _): &(FetchState, Instant, u32)| *due > now;
            if !first && s.states.get(&custodian).is_some_and(later) {
                return None;
            }
        }
        let _work = AtWork::begin(self.asking.work);
        let (state, due, empty) = {
            let mut s = lock_of(shared);
            let entry = s
                .states
                .remove(&custodian)
                .unwrap_or((FetchState::default(), now, 0));
            drop(s);
            entry
        };
        // A pair park (the custodian refused this node's DEPOSIT for that
        // peer as the recipient: it does not pin it) says the peer has no
        // mail of its own there for this node. With custody handoff live it
        // may well have: the peer's own friend DELIVERs it there for this
        // node to collect. So the pair park is the depositor's alone then,
        // and the peer's tags are still fetched and registered here (review
        // handoff-4).
        let (live_peers, last_path) = {
            let s = lock_of(shared);
            let live: Vec<[u8; 32]> = peers
                .iter()
                .copied()
                .filter(|p| s.peer_backoff.get(p).is_none_or(|until| *until <= now))
                .filter(|p| {
                    handoff
                        || s.parked_pair
                            .get(&(custodian, *p))
                            .is_none_or(|until| *until <= now)
                })
                .collect();
            (live, s.last_path.get(&custodian).copied())
        };
        // Handoff registration here: the gate open, handoff not parked at
        // this custodian and not known to be missing there.
        let registering = handoff
            && !lock_of(shared).handoff_parked(&custodian, None, now)
            && crate::letters::handoff_supported(&custodian, wall) != Some(false);
        let register_tags = |cache: &mut TagCache| {
            inbound_register_tags_cached(data_dir, identity, &live_peers, wall, cache)
                .unwrap_or_default()
        };
        // Not due yet: unless a contact just linked and a tag of its (a new
        // session's) waits to be registered here (rg3).
        let early = first
            && due > now
            && self.register_due
            && registering
            && registration_wanted(&state, &register_tags(&mut self.reg_cache), wall);
        if due > now && !early {
            lock_of(shared)
                .states
                .insert(custodian, (state, due, empty));
            return None;
        }
        lock_of(shared).begin_fetch(&custodian);
        // A due custodian may be on this network at another address: the
        // LAN beacon looks (RAVEN_LAN_BEACON_V1 §8), and what it found
        // leads the LAN routes.
        if self.custody_live && io.lan {
            (io.want)(&custodian);
        }
        let offer = self.offers.get(&custodian).and_then(|l| l.offer);
        let finds = (io.finds)(&custodian);
        let onion = lock_of(shared).onion_fetch_ok(&custodian, empty, now);
        let tags = inbound_tags_cached(data_dir, identity, &live_peers, wall, &mut self.cache)
            .unwrap_or_default();
        let register = if registering {
            register_tags(&mut self.reg_cache)
        } else {
            BTreeMap::new()
        };
        let wants_tags = registering && registration_wanted(&state, &register, wall);
        Some(Turn {
            custodian,
            now,
            wall,
            state,
            empty,
            live_peers,
            last_path,
            registering,
            offer,
            finds,
            onion,
            tags,
            register,
            wants_tags,
        })
    }

    /// The turns of a pass with several custodians, at the same time, each
    /// on a thread of its own, at most `io.at_once` at once: every one that
    /// is due at the pass's time, and while turns are still out every one
    /// that comes due (at the pass's time plus what has gone by, never
    /// behind this device's clock), again too, as [`fetch_pass_with`] says.
    /// A turn is worked out when its place frees ([`Self::plan`]), and its
    /// end is noted as it comes ([`Self::noted`]). The pass sleeps until a
    /// turn ends, the schedule rings ([`Shared::ring`]) or the next
    /// custodian's time comes ([`Self::next_look`]); it is over when no turn
    /// is out. A turn that panicked ends the pass as a panic in a pass
    /// always did: no turn starts after it, and it is resumed once the turns
    /// that are out have ended and been noted; so is a panic on the pass's
    /// own thread (a turn asked there, or noting one).
    fn ask_at_once(
        &mut self,
        io: &PassIo<'_>,
        targets: raven_core::custody_client::FetchTargets,
        (now, wall): (Instant, u64),
    ) {
        let asking = self.asking;
        let from = FromPassThread::here();
        let began = std::time::Instant::now();
        // The pass's clock: its time plus what has gone by, and never behind
        // this device's own, by which kicks, wakes and links make a
        // custodian due (review mail-friends-2 L3: it ran behind by the
        // pass's setup, so a ring found the custodian it rang for not due
        // yet, and its turn waited for a later look).
        let pass_time = || {
            let at = (now + began.elapsed()).max(Instant::now());
            let gone = at.saturating_duration_since(now);
            let gone_ms = u64::try_from(gone.as_millis()).unwrap_or(u64::MAX);
            (at, wall.saturating_add(gone_ms))
        };
        let mut keepers: Vec<Keeper> = targets.into_iter().map(Keeper::new).collect();
        in_asking_order(&mut keepers, &lock_of(self.shared).failures);
        let (bell, notes) = std::sync::mpsc::channel::<Note>();
        let rung = Bell::hang(self.shared, &bell);
        let mut out = 0usize;
        let mut died = None;
        std::thread::scope(|scope| {
            // The first look too is at the pass's clock (review
            // mail-friends-3 n1: at the pass's own time it found a custodian
            // that a kick during the pass's setup made due not due yet).
            let mut at = pass_time();
            let looked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| loop {
                #[cfg(test)]
                LOOKS_FOR_TESTS.with(|looks| looks.set(looks.get() + 1));
                let young = at.0.saturating_duration_since(now) < self.new_turns_for;
                // Once the pass is old, a turn that started while it was
                // young, or a custodian's first, still keeps it going for a
                // friend that is there: from the look it starts in, for the
                // custodians after it in this look and for the sleep after
                // it (a late first turn may start in the look where the last
                // young turn ended, and nothing else would wake the pass
                // until a turn ends).
                let mut held = keepers.iter().any(|k| k.out && k.holds);
                let may_start = died.is_none() && !io.budget_spent();
                // A free place goes to a custodian not asked yet in this
                // pass before one asked again (review mail-friends-2 N4),
                // each in asking order.
                let order: Vec<usize> = (0..keepers.len())
                    .filter(|n| keepers[*n].turns == 0)
                    .chain((0..keepers.len()).filter(|n| keepers[*n].turns > 0))
                    .collect();
                for n in order {
                    if !may_start || out >= io.at_once {
                        break;
                    }
                    let k = &mut keepers[n];
                    let resting = k.rest_until.is_some_and(|until| until > at.0);
                    let crowded = k.free_at(self.base).is_some_and(|free| free > at.0);
                    let more = k.turns == 0 || young || (held && !k.missed);
                    if k.out || resting || crowded || !more {
                        continue;
                    }
                    let first = !std::mem::replace(&mut k.looked, true);
                    let custodian = k.custodian;
                    let Some(turn) = self.plan(io, &custodian, &keepers[n].peers, at, first) else {
                        continue;
                    };
                    keepers[n].starts(&turn, young);
                    match on_its_own_thread(scope, (n, turn), asking, &from, &bell) {
                        Started::OnItsThread => {
                            keepers[n].out = true;
                            out += 1;
                            held |= keepers[n].holds;
                        }
                        Started::Here(turn) => {
                            let asked = ask(*turn, asking);
                            self.noted(io, &mut keepers, n, asked, pass_time());
                        }
                    }
                }
                if out == 0 {
                    break;
                }
                let wait = if may_start && out < io.at_once {
                    self.next_look(&keepers, pass_time().0, young, held)
                } else {
                    LOOK_AT_LEAST
                };
                // Everything heard by now, then the next look.
                let mut heard = notes.recv_timeout(wait).ok();
                while let Some(note) = heard {
                    if let Note::Ended(n, end) = note {
                        out -= 1;
                        keepers[n].out = false;
                        match end {
                            Ok(asked) => self.noted(io, &mut keepers, n, *asked, pass_time()),
                            Err(panic) => {
                                died.get_or_insert(panic);
                            }
                        }
                    }
                    heard = notes.try_recv().ok();
                }
                at = pass_time();
            }));
            if let Err(panic) = looked {
                // A panic on the pass's own thread: the turns that are out
                // end on their own, and each end is noted before the panic
                // goes on (review mail-friends-2 N1: their entries stayed
                // out of the schedule, and what they were owed was lost).
                died.get_or_insert(panic);
                while out > 0 {
                    let Ok(note) = notes.recv() else {
                        break;
                    };
                    if let Note::Ended(n, end) = note {
                        out -= 1;
                        keepers[n].out = false;
                        if let Ok(asked) = end {
                            // A fault in noting it: the first panic goes on.
                            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                self.noted(io, &mut keepers, n, *asked, pass_time());
                            }));
                        }
                    }
                }
            }
        });
        drop(rung);
        if let Some(panic) = died {
            std::panic::resume_unwind(panic);
        }
    }

    /// Keeper number `n`'s turn has ended with `asked`, at the pass's time
    /// `at`: it is noted ([`Self::settle`]), the keeper rests before another
    /// turn ([`AGAIN_AFTER`]; a turn that dialled nothing, [`LOOK_AGAIN`],
    /// and it gives its place in the window back), and the mail it took in
    /// may make a custodian of the pass due again ([`Self::retag`]). Tags
    /// it missed while it was out make it due again only if this turn
    /// reached its custodian: one that was not reached keeps the wait its
    /// failure gave it (review mail-friends-2 L2).
    fn noted(
        &mut self,
        io: &PassIo<'_>,
        keepers: &mut [Keeper],
        n: usize,
        asked: Asked,
        at: (Instant, u64),
    ) {
        let settled = self.settle(io, asked);
        let k = &mut keepers[n];
        let rest = if settled.dialled {
            self.again_after
        } else {
            LOOK_AGAIN
        };
        k.rest_until = Some(at.0 + rest);
        k.ended(settled.dialled);
        k.missed = settled.missed;
        if std::mem::take(&mut k.retag) && !settled.missed {
            if let Some((_, due, _)) = lock_of(self.shared).states.get_mut(&k.custodian) {
                *due = (*due).min(at.0);
            }
        }
        self.retag(keepers, &settled.touched, at);
    }

    /// A turn took in mail of `touched` at `at`, and that may have brought a
    /// session, whose tags no turn asked for before. In a pass that asked
    /// one custodian after the other, the next one was asked with them;
    /// here the turns started together. So each custodian of the pass whose
    /// last turn asked for one of those peers' mail without one of their
    /// tags now (the one that took the mail in too) is due again: at once,
    /// or as its turn that is out ends, if that reaches it. Not one whose
    /// last turn reached nothing there: that turn asked it nothing, and it
    /// waits out its failure's backoff (review mail-friends-2 L2). Worked
    /// out with the work held ([`AtWork`]): it reads the session store.
    fn retag(&mut self, keepers: &mut [Keeper], touched: &[[u8; 32]], (now, wall): (Instant, u64)) {
        if touched.is_empty() {
            return;
        }
        let _work = AtWork::begin(self.asking.work);
        let (data_dir, identity) = (self.asking.data_dir, self.asking.identity);
        for k in keepers
            .iter_mut()
            .filter(|k| k.turns > 0 && (k.out || !k.missed))
        {
            let peers: Vec<[u8; 32]> = k
                .live_peers
                .iter()
                .copied()
                .filter(|p| touched.contains(p))
                .collect();
            if peers.is_empty() {
                continue;
            }
            let tags = inbound_tags_cached(data_dir, identity, &peers, wall, &mut self.cache)
                .unwrap_or_default();
            if tags.keys().all(|tag| k.asked_for.contains(tag)) {
                continue;
            }
            if k.out {
                k.retag = true;
            } else if let Some((_, due, _)) = lock_of(self.shared).states.get_mut(&k.custodian) {
                *due = (*due).min(now);
            }
        }
    }

    /// How long a pass with turns out sleeps at `now` (its clock) when no
    /// turn ends and the schedule does not ring: until the first of its
    /// custodians that may start a turn is due (parks, rests and
    /// [`TURNS_IN_AN_INTERVAL`] included; those that had their turn may
    /// have another while the pass is `young`, or while a turn that holds
    /// it keeps it going, `held`, if their last turn reached them), between
    /// [`LOOK_AGAIN`] and [`LOOK_AT_LEAST`]. One that may not start another
    /// turn is left out: it is due, and the pass would look every 200 ms for
    /// nothing.
    fn next_look(&self, keepers: &[Keeper], now: Instant, young: bool, held: bool) -> Duration {
        let s = lock_of(self.shared);
        keepers
            .iter()
            .filter(|k| !k.out && (k.turns == 0 || young || (held && !k.missed)))
            .map(|k| {
                let mut due = s.states.get(&k.custodian).map_or(now, |(_, due, _)| *due);
                if let Some((until, _)) = s.parked.get(&k.custodian) {
                    due = due.max(*until);
                }
                if let Some(until) = k.rest_until {
                    due = due.max(until);
                }
                if let Some(free) = k.free_at(self.base) {
                    due = due.max(free);
                }
                due.saturating_duration_since(now)
            })
            .min()
            .unwrap_or(LOOK_AT_LEAST)
            .clamp(LOOK_AGAIN, LOOK_AT_LEAST)
    }

    /// A custodian's turn has ended: what it brought is noted (its next
    /// time, failures and parks, the peers to back off, the outboxes to
    /// kick, the log's lines) and its entry is back in `states`
    /// ([`Shared::end_fetch`]). On the pass's thread, as each turn ends,
    /// with the turns' work held ([`AtWork`]).
    fn settle(&mut self, io: &PassIo<'_>, asked: Asked) -> Settled {
        let _work = AtWork::begin(self.asking.work);
        let (shared, base) = (self.shared, self.base);
        let Asked {
            turn,
            no_route,
            report,
            letters,
            answered,
            path,
            carrier,
            tried,
            over_tor,
            dialled,
            cut,
        } = asked;
        let Turn {
            custodian,
            now,
            state,
            empty,
            live_peers,
            registering,
            ..
        } = turn;
        let letter_dials = letters.as_ref().map_or(0, |r| r.dials);
        let mut empty = empty;
        // A bounded mail check whose time was up before any dial of this
        // turn was answered (none went out, or the budget cut one on its
        // way): nothing is known about the custodian, as with no route
        // (review mail-friends-1, finding 3, and mail-friends-2 N2: both
        // were counted and logged as not reached, with a backoff).
        let unasked = cut && answered == 0;
        let all_failed = !unasked
            && (report.as_ref().is_some_and(|r| r.dials > 0) || letter_dials > 0)
            && answered == 0
            && dialled > 0;
        let next = {
            let mut s = lock_of(shared);
            if let Some(p) = path {
                s.last_path.insert(custodian, p);
            }
            if no_route || unasked {
                // No route at all (no address known, Tor not usable yet, or
                // the idle-Tor rule took its route), or the check's time
                // was up: nothing was asked there, so this was no round.
                // Its failures and empty rounds stay as they were, and it
                // is looked at again on its current interval; Tor coming up
                // makes it due at once ([`tor_ready`]), and so does the next
                // mail check. It used to count as an empty round, which
                // after an iPhone open or a network change kept the onion
                // route off until 30 minutes after the last Tor fetch there
                // (ONION_FETCH_EVERY). A wake during its turn makes one with
                // no route due at once, and one the check cut a base
                // interval on ([`Woken`]: the check's own kick reaches the
                // turns of a pass that began before it, review
                // mail-friends-4, finding 1); a wake after its turn makes
                // it due at once, as it does any.
                idle_interval(empty, base)
            } else if all_failed {
                // Not reached at all. With releases owed there it is retried
                // like a delivery (5 s doubling to 10 min); an idle poll,
                // with nothing known to wait there, backs off from the base
                // interval to UNREACHABLE_IDLE_MAX (E2 r9 #3: an unreachable
                // friend was dialled 9 times in 22 minutes for nothing). Its
                // return (a link, new routes, a beacon find) makes it due at
                // once either way.
                let failures = s.failures.entry(custodian).or_insert(0);
                let wait = unreachable_wait(*failures, !state.pending_release.is_empty(), base);
                *failures = failures.saturating_add(1);
                wait
            } else {
                s.failures.remove(&custodian);
                let letters_came = letters
                    .as_ref()
                    .is_some_and(|r| r.letters > 0 || r.released > 0);
                match &report {
                    _ if letters_came => {
                        empty = 0;
                        base
                    }
                    Some(r) if r.items > 0 || r.released > 0 => {
                        empty = 0;
                        base
                    }
                    _ => {
                        empty = empty.saturating_add(1);
                        idle_interval(empty, base)
                    }
                }
            }
        };
        if let (Some(r), true) = (&report, registering) {
            self.inbox_changed |= note_registration(&mut lock_of(shared), &custodian, r, now);
        }
        if let Some(r) = &report {
            crate::security::custody_fetched(&custodian, r);
            if let Some(code) = r.custodian_code {
                if let Some(peer) = live_peers.first() {
                    lock_of(shared).park_for_code(&custodian, peer, code, now);
                }
            }
            let mut s = lock_of(shared);
            for (peer, why) in &r.peer_backoff {
                let wait = if *why == "OWED_ACK_FULL" {
                    Duration::from_secs(60)
                } else {
                    Duration::from_secs(30)
                };
                s.peer_backoff.insert(*peer, now + wait);
            }
            drop(s);
            // Mail that came through a friend does not show the contact is
            // directly reachable: a plain kick, the backoff stands (G5).
            for peer in &r.touched {
                (io.kick)(peer);
            }
            if r.accepted_messages + r.accepted_acks > 0 {
                FETCHED_MESSAGES.fetch_add(
                    r.accepted_messages as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                eprintln!(
                    "raven-node custody: {}",
                    fetched_line(r, carrier, &custodian)
                );
            }
            if r.foreign > 0 {
                eprintln!(
                    "raven-node custody: {}",
                    foreign_line(r.foreign, &custodian)
                );
            }
        }
        if let Some(r) = &letters {
            let mut s = lock_of(shared);
            for (peer, why) in &r.peer_backoff {
                let wait = if *why == "OWED_ACK_FULL" {
                    Duration::from_secs(60)
                } else {
                    Duration::from_secs(30)
                };
                s.peer_backoff.insert(*peer, now + wait);
            }
            drop(s);
            for peer in &r.touched {
                (io.kick)(peer);
            }
        }
        if over_tor {
            lock_of(shared).onion_fetch_at.insert(custodian, now);
        }
        let missed = no_route || unasked || all_failed;
        let woken = if no_route || all_failed {
            Woken::AtOnce
        } else if unasked {
            Woken::After(base)
        } else {
            Woken::Kept
        };
        let ended = Instant::now();
        let due = lock_of(shared).end_fetch(custodian, state, (now + next, empty), woken, ended);
        if all_failed {
            // The node's log was silent about a mail friend it waited for
            // and did not reach (W11-F2): the keeper's short tag, the
            // carrier tried last and the wait from now, nothing else.
            let line = not_reached_line(&custodian, tried, due.saturating_duration_since(ended));
            #[cfg(test)]
            NOT_REACHED_FOR_TESTS.with(|lines| lines.borrow_mut().push(line.clone()));
            eprintln!("raven-node custody: {line}");
        }
        let mut touched: Vec<[u8; 32]> = report.iter().flat_map(|r| r.touched.clone()).collect();
        for peer in letters.iter().flat_map(|r| r.touched.iter()) {
            if !touched.contains(peer) {
                touched.push(*peer);
            }
        }
        Settled {
            touched,
            dialled: dialled > 0,
            missed,
        }
    }
}

/// What a fetch round `r` at `custodian` showed about this node's tag
/// registration there (handoff spec §3.6), at `now`. `true`: its
/// `HANDOFF_INBOX` came or went.
/// - TAGS UNSUPPORTED (no handoff ops there; the capability cache keeps it
///   for 24 h too), POLICY_DENIED or HOLD: handoff parked there (24 h, 1 h,
///   1 h) and no inbox;
/// - any other refusal of this node
///   ([`raven_core::custody_client::FetchReport::custodian_refused`]: the
///   FETCH answered POLICY_DENIED, HOLD or NOT_VERIFIED, TAGS
///   NOT_VERIFIED): no inbox (the plain park follows the FETCH's code);
/// - every TAGS frame answered OK: the inbox is fresh now. Only that keeps
///   it fresh: the custodian may have lost what this node registered there
///   without a word (review handoff-1), and a registered tag is sent again
///   once its OK is [`raven_core::custody_client::TAG_CONFIRM_MS`] old;
/// - conflicts (another recipient registered one of the tags; both lose
///   it): a counts-only line.
fn note_registration(
    s: &mut Shared,
    custodian: &[u8; 32],
    r: &raven_core::custody_client::FetchReport,
    now: Instant,
) -> bool {
    if r.tag_conflicts > 0 {
        eprintln!(
            "raven-node custody: CUSTODY_TAG_CONFLICT {}",
            r.tag_conflicts
        );
    }
    let refused = match r.tags_code {
        Some(c @ (CustodyCode::PolicyDenied | CustodyCode::Hold)) => {
            Some((PARK_HOUR, c.registry()))
        }
        _ if r.tags_unsupported => Some((PARK_DAY, "CUSTODY_HANDOFF_UNSUPPORTED")),
        _ => None,
    };
    let before = s.inbox_ok(custodian, now);
    if let Some((for_, why)) = refused {
        s.park_handoff(custodian, for_, why, now);
        s.inbox_ok.remove(custodian);
    } else if r.custodian_refused() {
        s.inbox_ok.remove(custodian);
    } else if r.tags_ok {
        s.inbox_ok.insert(*custodian, now);
    }
    before != s.inbox_ok(custodian, now)
}

fn lab_forward_interval() -> Option<Duration> {
    if !raven_core::pair_init::lab_test_a_enabled() {
        return None;
    }
    std::env::var("RAVEN_LAB_CUSTODY_FORWARD_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_millis)
}

/// How long a row answered TAG_UNKNOWN waits after `attempts` earlier tries
/// (the recipient has not registered yet): [`TAG_UNKNOWN_FIRST`] doubling to
/// [`TAG_UNKNOWN_MAX`], ±50 % jitter (`jitter` in `[0, 1]`, 0.5 = none),
/// never above the maximum.
fn tag_unknown_delay(attempts: u32, jitter: f64) -> Duration {
    let ceiling = TAG_UNKNOWN_FIRST
        .saturating_mul(1u32 << attempts.min(8))
        .min(TAG_UNKNOWN_MAX);
    let jitter = if jitter.is_finite() {
        jitter.clamp(0.0, 1.0)
    } else {
        0.5
    };
    ceiling.mul_f64(0.5 + jitter).min(TAG_UNKNOWN_MAX)
}

/// A wall-clock time `wait` after `wall` (ms).
fn wall_after(wall: u64, wait: Duration) -> u64 {
    wall.saturating_add(u64::try_from(wait.as_millis()).unwrap_or(u64::MAX))
}

/// What one forward pass did (counts only).
#[derive(Debug, Default, PartialEq, Eq)]
struct ForwardPass {
    /// Dials made to next hops.
    dials: usize,
    /// Rows the next hop now holds (STORED or DUPLICATE).
    handed: usize,
    /// Rows refused for good (a terminal code).
    refused: usize,
    /// Rows dropped unsent: their depositor or next hop is no contact any
    /// more.
    dropped: usize,
    /// Rows still pending after the pass.
    kept: i64,
}

/// The forwarder (handoff spec §3.2), on `shared` at `now` / `wall`: the
/// objects friends left here for another friend (FORWARD rows) go to that
/// friend, the next hop, as HANDOFF/DELIVER, at most 16 a dial and
/// [`FORWARD_DIALS_PER_HOP`] dials per next hop. Due are the rows whose
/// next try came, and every row of a next hop just seen (and all of them
/// after a kick, a network change or an inbound FORWARD). Before a row is
/// sent its depositor and next hop are checked again (handoff spec §3.2): a
/// row of a party that is no pinned, unblocked contact any more is dropped
/// unsent. Each next hop it dials is first wanted from the LAN beacon (with
/// the LAN carrier's gate open; review cross-3). While the contact book or
/// the block list cannot be read nobody is known to be one or not: the pass
/// drops nothing and sends nothing, and looks again after its interval
/// (review handoff-2). Answers:
/// STORED / DUPLICATE mark the row handed (never sent again); TAG_UNKNOWN
/// waits ([`tag_unknown_delay`]); a terminal code marks it refused; HOLD /
/// POLICY_DENIED park handoff at the next hop for an hour, NOT_VERIFIED and
/// UNSUPPORTED for a day; anything else waits the retry delay. A dial the
/// next hop closed is a handoff strike; another failure waits the retry
/// delay for that next hop. Once a bounded mail check's budget is spent no
/// next hop is dialled, and a dial it cut is no failure: nothing is learned
/// about the hop or its routes, and what was due stays due (all of it: a
/// hop the pass reached before the cut may be asked again at the next
/// pass, ahead of its retry wait; review mail-friends-7, N3). Nothing while
/// the handoff gate is closed (no dial, no file). The next hops are visited
/// in key order, or while carry choice is live (Phase 6a P6.16) in the
/// order of this node's own predictability of meeting them
/// ([`crate::learning::forward_order`]); that changes only which goes
/// first.
fn forward_pass_with(
    shared: &Mutex<Shared>,
    data_dir: &Path,
    now: Instant,
    wall: u64,
    io: &mut PassIo<'_>,
) -> ForwardPass {
    let mut out = ForwardPass::default();
    if !handoff_live() || lock_of(shared).forward_next.is_some_and(|t| t > now) {
        return out;
    }
    let base = lab_forward_interval()
        .unwrap_or(FORWARD_INTERVAL)
        .max(Duration::from_millis(200));
    let (all, early) = {
        let mut s = lock_of(shared);
        (
            std::mem::take(&mut s.forward_all),
            std::mem::take(&mut s.forward_early),
        )
    };
    let mut store = match HandoffStore::open_existing(data_dir) {
        Ok(Some(store)) => store,
        Ok(None) => {
            let mut s = lock_of(shared);
            s.forward_hops.clear();
            s.forward_next = Some(now + FORWARD_IDLE);
            return out;
        }
        Err(_) => {
            lock_of(shared).forward_next = Some(now + base);
            return out;
        }
    };
    // The parties still pinned, unblocked contacts, read once. Not known
    // (the book held while the profile's key loads, a corrupt book or
    // block list): every party would read as gone and every row go. What
    // was due stays due for the next look.
    let Some(parties) = raven_core::friend_custody::custody_parties(data_dir) else {
        let mut s = lock_of(shared);
        s.forward_all |= all;
        s.forward_early.extend(early);
        s.forward_next = Some(now + base);
        return out;
    };
    let due = store
        .forward_due_for(wall, FORWARD_ROWS_PER_PASS, &|hop| {
            all || early.contains(hop)
        })
        .unwrap_or_default();
    let ok = |key: &[u8; 32]| parties.contains(key);
    let (due, gone): (Vec<DueForward>, Vec<DueForward>) = due
        .into_iter()
        .partition(|r| ok(&r.depositor) && ok(&r.next_hop));
    if !gone.is_empty() {
        out.dropped = gone.len();
        let _ = store.maintain(wall, &ok);
    }
    let mut by_hop: BTreeMap<[u8; 32], Vec<DueForward>> = BTreeMap::new();
    for row in due {
        by_hop.entry(row.next_hop).or_default().push(row);
    }
    let offers = if custody_hints_live() {
        raven_core::learned_routes::learned_custody_all(data_dir, wall)
    } else {
        HashMap::new()
    };
    // Carry choice (Phase 6a P6.16): the next hops this node meets most
    // often go first (order only); key order otherwise.
    let hops: Vec<[u8; 32]> = by_hop.keys().copied().collect();
    // A dial a mail check's budget did not let out, or cut before it was
    // answered ([`MAIL_CHECK_BUDGET`]): nothing is learned about the hop or
    // the route, and no other hop is dialled (review mail-friends-6, nit 7:
    // every hop's beacon find was forgotten and its retry wait grew, though
    // nothing went out).
    let cut = std::cell::Cell::new(false);
    for hop in &crate::learning::forward_order(&hops) {
        if cut.get() || io.budget_spent() {
            cut.set(true);
            break;
        }
        let Some(rows) = by_hop.get(hop) else {
            continue;
        };
        {
            let s = lock_of(shared);
            if s.handoff_parked(hop, None, now)
                || s.forward_wait
                    .get(hop)
                    .is_some_and(|(until, _)| *until > now)
            {
                continue;
            }
        }
        // The next hop may be on this network at another address (a new
        // DHCP lease): the LAN beacon looks, as for a due custodian in the
        // fetch pass, and its answer makes the hop's rows due at once
        // (`peer_seen`; review cross-3). The handoff gate needs custody
        // live, so only the LAN carrier's gate is left to check.
        if io.lan {
            (io.want)(hop);
        }
        let offer = offers.get(hop).and_then(|l| l.offer);
        let finds = (io.finds)(hop);
        let mut routes = custodian_routes(data_dir, hop, offer, &finds, |ip| {
            crate::outbox::learned_lan_on_link(ip) != Some(false)
        });
        // Phase 5: over a nearby pipe too (last), under the custody gates.
        routes.extend(crate::nearby::custodian_route(hop));
        if routes.is_empty() {
            // CUSTODIAN_NOT_USABLE now: the rows wait for a route.
            lock_of(shared).forward_failed(hop, now);
            continue;
        }
        let expected = hex::encode(hop);
        let mut first = 0;
        let mut rest: &[DueForward] = rows;
        for _ in 0..FORWARD_DIALS_PER_HOP {
            if rest.is_empty() {
                break;
            }
            let dialled = std::cell::Cell::new(false);
            let mut dial = |frames: &[Vec<u8>]| {
                dial_in_turn(&routes, &mut first, |(planned, route)| {
                    let got = if cut.get() || io.budget_spent() {
                        Err(MAIL_CHECK_BUDGET.to_string())
                    } else {
                        (io.dial)(route, &expected, frames)
                    };
                    if matches!(&got, Err(e) if e == MAIL_CHECK_BUDGET) {
                        cut.set(true);
                        return got;
                    }
                    dialled.set(true);
                    if let Err(e) = &got {
                        if crate::outbox::custody_find_failed(&finds, planned, e) {
                            (io.find_failed)(hop, &planned.dial);
                        }
                    }
                    got
                })
                .map(|(replies, _)| replies)
            };
            let got = crate::letters::with_handoff_caps(hop, |caps| {
                forward_round(hop, rest, caps, wall, &mut dial)
            });
            out.dials += usize::from(dialled.get());
            let answers = match got {
                Ok(answers) => answers,
                Err(e) if e == handoff_gate_closed() => return out,
                Err(_) if cut.get() => break,
                Err(e) => {
                    if crate::outbox::dial_error_code(&e) == crate::outbox::code::PEER_REFUSED {
                        strike_handoff_on(shared, hop, now);
                    } else {
                        lock_of(shared).forward_failed(hop, now);
                    }
                    break;
                }
            };
            if answers.is_empty() {
                break;
            }
            lock_of(shared).forward_wait.remove(hop);
            let mut parked = false;
            for (digest, answer) in &answers {
                let attempts = rest
                    .iter()
                    .find(|r| r.digest == *digest)
                    .map_or(0, |r| r.attempts);
                let park = |for_: Duration, why: &'static str| {
                    lock_of(shared).park_handoff(hop, for_, why, now);
                };
                match *answer {
                    Some(ItemAnswer::Code(code)) if code.held() => {
                        out.handed += 1;
                        let _ = store.mark_handed(digest, hop, code);
                    }
                    Some(ItemAnswer::Code(CustodyCode::TagUnknown)) => {
                        let next = wall_after(wall, tag_unknown_delay(attempts, jitter()));
                        let _ = store.backoff(digest, hop, next, CustodyCode::TagUnknown);
                    }
                    Some(ItemAnswer::Code(
                        code @ (CustodyCode::RefusedObject
                        | CustodyCode::Expired
                        | CustodyCode::Malformed
                        | CustodyCode::Conflict
                        | CustodyCode::RecipientNotAccepted
                        | CustodyCode::HopRefused),
                    )) => {
                        out.refused += 1;
                        let _ = store.mark_refused(digest, hop, code);
                        // A DELIVER is never refused for its signer: the
                        // custodian's doing (Phase 6b S20).
                        if code == CustodyCode::HopRefused {
                            let carrier = routes
                                .get(first)
                                .map_or(raven_core::outbox::OutboxCarrier::Lan, |(planned, _)| {
                                    planned.carrier
                                });
                            crate::security::handoff_refused(hop, carrier);
                        }
                    }
                    Some(ItemAnswer::Code(
                        code @ (CustodyCode::PolicyDenied | CustodyCode::Hold),
                    )) => {
                        park(PARK_HOUR, code.registry());
                        parked = true;
                    }
                    Some(ItemAnswer::Code(code @ CustodyCode::NotVerified)) => {
                        park(PARK_DAY, code.registry());
                        parked = true;
                    }
                    Some(ItemAnswer::Unsupported) => {
                        park(PARK_DAY, "CUSTODY_HANDOFF_UNSUPPORTED");
                        parked = true;
                    }
                    Some(ItemAnswer::Code(code)) => {
                        let next = wall_after(wall, retry_delay(attempts, jitter()));
                        let _ = store.backoff(digest, hop, next, code);
                    }
                    // No answer: the row is due again next pass.
                    None => {}
                }
            }
            if parked {
                break;
            }
            rest = &rest[answers.len().min(rest.len())..];
        }
    }
    out.kept = store.usage().map_or(0, |u| u.pending);
    let mut s = lock_of(shared);
    if cut.get() {
        // What a wake made due stays due for the next pass, a base interval
        // on (as a fetch turn the budget cut): all of it, the hops this pass
        // reached too (a cut comes only with a mail check, and handoff only
        // in the lab).
        s.forward_all |= all;
        s.forward_early.extend(early);
    }
    if out.kept == 0 {
        s.forward_hops.clear();
        s.forward_next = Some(now + FORWARD_IDLE);
    } else {
        s.forward_hops.extend(by_hop.keys().copied());
        s.forward_next = Some(now + base);
    }
    out
}

/// [`strike_handoff`] on `shared` (the forwarder's own, tests' too).
fn strike_handoff_on(shared: &Mutex<Shared>, custodian: &[u8; 32], now: Instant) {
    if lock_of(shared).strike_handoff(custodian, now) {
        eprintln!(
            "raven-node custody: a friend closed {STRIKES_TO_PARK} handoff links within an \
             hour; no handoff to it for an hour (CUSTODY_HANDOFF_UNSUPPORTED)"
        );
    }
}

/// A uniform sample from `[0, 1]` for [`retry_delay`]'s jitter.
fn jitter() -> f64 {
    use rand::Rng;
    rand::thread_rng().gen_range(0.0..=1.0)
}

// ── Passes, for a bounded mail check (embedded node; docs/IOS.md) ──────────

/// Fetch passes begun in this process (each pass's number), the number of
/// the latest one that finished (a pass whose node stopped never does), and
/// the messages they took in: a mail check waits for a pass that began
/// after its kick.
static PASSES_BEGUN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static PASSES_DONE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static FETCHED_MESSAGES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static PASS_DONE: OnceLock<Notify> = OnceLock::new();
/// While a bounded mail check runs: when its custody dials must be done;
/// and the last such deadline, with the passes begun when it was set.
static PASS_DEADLINE: Mutex<CheckDeadline> = Mutex::new(CheckDeadline {
    set: None,
    last: None,
});
/// The error of a custody dial a mail check's budget no longer allows.
pub(crate) const MAIL_CHECK_BUDGET: &str = "MAIL_CHECK_BUDGET: the mail check's time is up";

fn pass_done() -> &'static Notify {
    PASS_DONE.get_or_init(Notify::new)
}

/// A fetch pass begins ([`run_fetcher`]): its number.
fn pass_begins() -> u64 {
    PASSES_BEGUN.fetch_add(1, std::sync::atomic::Ordering::AcqRel) + 1
}

/// Pass number `number` has ended: a mail check that waits for it goes on.
fn pass_ended(number: u64) {
    PASSES_DONE.fetch_max(number, std::sync::atomic::Ordering::AcqRel);
    pass_done().notify_waiters();
}

/// The fetch passes begun in this process by now.
fn passes_begun() -> u64 {
    PASSES_BEGUN.load(std::sync::atomic::Ordering::Acquire)
}

/// A bounded mail check's deadline in this process ([`set_pass_deadline`]).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct CheckDeadline {
    /// When the custody dials of the check that runs now must be done
    /// (`None`: no check runs).
    set: Option<std::time::Instant>,
    /// The last deadline a check set, and how many passes had begun when
    /// it did ([`PASSES_BEGUN`]): one of those may have been at work, and
    /// seen nothing of it before the check let go (review mail-friends-5,
    /// finding A).
    last: Option<(std::time::Instant, u64)>,
}

impl CheckDeadline {
    /// A check sets `until` (`None`: it lets go). A deadline set is the
    /// last one too, with the passes begun by now.
    #[cfg(any(test, feature = "embedded"))]
    fn record(&mut self, until: Option<std::time::Instant>) {
        self.set = until;
        if let Some(until) = until {
            self.last = Some((until, passes_begun()));
        }
    }
}

/// A bounded mail check's deadline as it is now.
fn pass_deadline() -> CheckDeadline {
    #[cfg(test)]
    if let Some(deadline) = CHECK_DEADLINE_FOR_TESTS.with(std::cell::Cell::get) {
        return deadline;
    }
    *PASS_DEADLINE.lock().unwrap_or_else(|e| e.into_inner())
}

/// A bounded mail check's budget as one fetch pass sees it: the pass keeps
/// the earliest check deadline it has seen (as it began, or at a look, a
/// turn's start or a dial since) to its end, and every dial it makes has
/// that much left at most ([`within_check`]). The check lets go of its
/// deadline when its wait for a pass ends, at the latest at that deadline,
/// and a pass may still be at work then: its turns dialled on with no
/// budget, after the check had told the app it was done (review
/// mail-friends-3 R3; review mail-friends-4, findings 1 and 5: so did a
/// pass that began before the check, and every dial with the deadline let
/// go). A pass that had begun when the check set it keeps it too, even one
/// that saw nothing of it before the check let go: a pass that asks one
/// custodian at a time looks at nothing while its dial is out, and a check
/// may begin and end meanwhile (review mail-friends-5, finding A). A check
/// with a later deadline does not lengthen it. A pass that begins after the
/// check let go keeps nothing: the node's own schedule goes on.
struct CheckBudget {
    /// The passes begun when this one began, itself among them
    /// ([`pass_begins`]): its number, as the fetcher counts. Exact with one
    /// fetcher in the process. A stopped node's fetcher that is still at
    /// work could begin a pass between this one's count and its budget:
    /// then it is one too large, and a check that set its deadline and let
    /// go in that gap is not kept, as before review mail-friends-5's
    /// finding A (review mail-friends-7, N2).
    number: u64,
    /// The earliest check deadline this pass has seen.
    kept: Mutex<Option<std::time::Instant>>,
}

impl CheckBudget {
    /// The budget of the pass that begins now.
    fn begin() -> Self {
        let budget = Self {
            number: passes_begun(),
            kept: Mutex::new(None),
        };
        budget.see();
        budget
    }

    /// The deadline set now, and the last one set if this pass had begun
    /// by then, are kept when earlier than the one kept; the one kept.
    fn see(&self) -> Option<std::time::Instant> {
        let deadline = pass_deadline();
        let last = deadline
            .last
            .filter(|&(_, begun)| self.number <= begun)
            .map(|(until, _)| until);
        let mut kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
        for until in [deadline.set, last].into_iter().flatten() {
            *kept = Some(kept.map_or(until, |kept| kept.min(until)));
        }
        *kept
    }

    /// What is left of it now (`None`: no check bounds this pass).
    fn left(&self) -> Option<Duration> {
        self.see()
            .map(|until| until.saturating_duration_since(std::time::Instant::now()))
    }
}

/// Bound every custody dial until `until` (`None`: the usual deadlines). A
/// deadline set is the last one too, with the passes begun by now
/// ([`CheckDeadline::record`]).
#[cfg(feature = "embedded")]
pub(crate) fn set_pass_deadline(until: Option<std::time::Instant>) {
    PASS_DEADLINE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .record(until);
}

/// The tests that move this process's pass counts or check deadline, one
/// at a time: a pass is told apart by the passes begun before it
/// ([`CheckBudget::number`]), and those are the whole process's. Every
/// test that begins a pass ([`pass_begun_for_tests`]) holds it.
#[cfg(test)]
pub(crate) fn passes_for_tests() -> std::sync::MutexGuard<'static, ()> {
    static PASSES: Mutex<()> = Mutex::new(());
    PASSES.lock().unwrap_or_else(|e| e.into_inner())
}

/// The deadline [`set_pass_deadline`] set, as it is now.
#[cfg(all(test, feature = "embedded"))]
pub(crate) fn pass_deadline_set() -> Option<std::time::Instant> {
    PASS_DEADLINE.lock().unwrap_or_else(|e| e.into_inner()).set
}

/// The last deadline a check set, and the passes begun then.
#[cfg(all(test, feature = "embedded"))]
pub(crate) fn pass_deadline_last() -> Option<(std::time::Instant, u64)> {
    PASS_DEADLINE.lock().unwrap_or_else(|e| e.into_inner()).last
}

/// A pass begins and ends at once, as far as the pass counts go (they move
/// as the fetcher's own do for it); its number. The caller holds
/// [`passes_for_tests`].
#[cfg(test)]
pub(crate) fn pass_begun_for_tests() -> u64 {
    let number = pass_begins();
    pass_ended(number);
    number
}

/// Passes begun, the latest pass finished, messages taken in, in this
/// process.
#[cfg(feature = "embedded")]
pub(crate) fn pass_counts() -> (u64, u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (
        PASSES_BEGUN.load(Relaxed),
        PASSES_DONE.load(Relaxed),
        FETCHED_MESSAGES.load(Relaxed),
    )
}

/// Waits (at most `limit`) until pass number `n` (counting from 1), or a
/// later one, has finished; whether it did.
#[cfg(feature = "embedded")]
pub(crate) async fn wait_pass_done(n: u64, limit: Duration) -> bool {
    let wait = async {
        loop {
            let notified = pass_done().notified();
            if PASSES_DONE.load(std::sync::atomic::Ordering::Acquire) >= n {
                return;
            }
            notified.await;
        }
    };
    tokio::time::timeout(limit, wait).await.is_ok()
}

/// Whether the fetcher works in this process (the custody gate).
#[cfg(feature = "embedded")]
pub(crate) fn fetcher_live() -> bool {
    CustodyGates::current().live
}

/// The supervised fetcher task.
pub async fn run_fetcher(data_dir: PathBuf) -> Result<(), String> {
    if !CustodyGates::current().live {
        // Closed for the life of the process (lab switches are read at
        // start): idle without touching the identity store.
        std::future::pending::<()>().await;
    }
    let dd = data_dir.clone();
    let identity = Arc::new(
        tokio::task::spawn_blocking(move || {
            raven_core::load_identity_required(&dd).map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| format!("custody blocking join: {e}"))??,
    );
    loop {
        let base = lab_fetch_interval()
            .unwrap_or(BASE_INTERVAL)
            .max(SHORTEST_INTERVAL);
        let (dd, id) = (data_dir.clone(), Arc::clone(&identity));
        let handle = tokio::runtime::Handle::current();
        let number = pass_begins();
        let pass = tokio::task::spawn_blocking(move || fetch_pass(&dd, &id, &handle)).await;
        pass_ended(number);
        pass.map_err(|e| format!("custody blocking join: {e}"))?;
        let wait = lock().next_wait(Instant::now(), base);
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = notify().notified() => {}
        }
    }
}

#[cfg(test)]
mod handoff_tests;

#[cfg(test)]
mod tests {
    use super::*;

    // Each test works on a `Shared` of its own: the process-wide one is
    // also moved by other modules' tests (a listener coming up kicks it),
    // and tests run in parallel (E-custody-harness-docs-10).

    /// Objects someone else left under this node's tags: one notice with the
    /// count and the keeper's short tag, which says the keeper is not
    /// blamed (it could not tell).
    #[test]
    fn the_foreign_object_notice_blames_no_keeper() {
        let keeper = [0x6C; 32];
        let line = foreign_line(3, &keeper);
        let tag = crate::netutil::link_tag(&keeper);
        assert!(
            line.starts_with("released 3 object(s) at contact "),
            "{line}"
        );
        assert!(line.contains(&tag) && line.contains("not blamed"), "{line}");
        assert!(!line.contains(&hex::encode(keeper)[..8]), "{line}");
    }

    /// E2 r9 #14: the fetch line counts group copies apart from chat
    /// messages and names the keeper by its short tag only.
    #[test]
    fn the_fetch_line_counts_group_copies_apart() {
        let r = raven_core::custody_client::FetchReport {
            accepted_messages: 3,
            accepted_group_copies: 2,
            accepted_acks: 1,
            ..Default::default()
        };
        let keeper = [0x6B; 32];
        let line = fetched_line(&r, Some(OutboxCarrier::Lan), &keeper);
        let tag = crate::netutil::link_tag(&keeper);
        assert_eq!(
            line,
            format!(
                "fetched messages=1 acks=1 refused=0 kept=0 group_copies=2 from contact {tag} \
                 (lan_dial)"
            )
        );
        assert!(!line.contains(&hex::encode(keeper)[..8]), "{line}");
    }

    #[test]
    fn parks_follow_the_custodian_codes() {
        let mut s = Shared::default();
        let now = Instant::now();
        let (c, p) = ([0xC1; 32], [0xB1; 32]);
        assert_eq!(s.parked(&c, Some(&p), now), None);
        s.park_for_code(&c, &p, CustodyCode::RecipientNotAccepted, now);
        assert_eq!(s.parked(&c, None, now), None);
        assert_eq!(
            s.parked(&c, Some(&p), now),
            Some("CUSTODY_RECIPIENT_REFUSED")
        );
        s.park_for_code(&c, &p, CustodyCode::Hold, now);
        assert_eq!(s.parked(&c, None, now), Some("CUSTODY_HOLD"));
        assert_eq!(
            s.parked(&c, None, now + PARK_HOUR),
            None,
            "an hour, no more"
        );
        // DUPLICATE / STORED never park.
        let d = [0xC2; 32];
        s.park_for_code(&d, &p, CustodyCode::Duplicate, now);
        assert_eq!(s.parked(&d, None, now), None);
        // An explicit kick clears every park.
        s.kick(now);
        assert_eq!(s.parked(&c, Some(&p), now), None);
    }

    /// Review D-2: the fetcher sleeps until a custodian is due, a parked
    /// one not before its park ends, never less than 200 ms nor more than
    /// the base interval.
    #[test]
    fn next_wait_waits_out_parks() {
        let mut s = Shared::default();
        let now = Instant::now();
        let base = BASE_INTERVAL;
        assert_eq!(s.next_wait(now, base), base, "nothing scheduled");
        let (c, p) = ([0xC6; 32], [0xB6; 32]);
        s.note_deposit(&c, now);
        assert_eq!(
            s.next_wait(now, base),
            Duration::from_millis(200),
            "due now"
        );
        // Parked for an hour (its entry is past due, the pass skips it).
        s.park_for_code(&c, &p, CustodyCode::Hold, now);
        let later = now + Duration::from_secs(5);
        assert_eq!(s.next_wait(later, base), base);
        // Parked for a minute: woken when the park ends.
        s.park_for_code(&c, &p, CustodyCode::Quota, now);
        assert_eq!(s.next_wait(later, base), Duration::from_secs(55));
        // A due custodian that is not parked still wins.
        let d = [0xC7; 32];
        s.note_deposit(&d, later + Duration::from_secs(10));
        assert_eq!(s.next_wait(later, base), Duration::from_secs(10));
        // Only targets keep a schedule.
        s.keep_targets(&[d].into_iter().collect());
        assert!(!s.states.contains_key(&c));
        assert!(s.states.contains_key(&d));
    }

    /// Tor (lab, design 2026-10-tor-fallback §3.6): an idle fetch poll goes
    /// over Tor at most every ONION_FETCH_EVERY; mail that just came, or a
    /// link from the custodian, lets the next one go at once.
    #[test]
    fn idle_fetch_polls_go_over_tor_only_now_and_then() {
        let mut s = Shared::default();
        let now = Instant::now();
        let c = [0xC9; 32];
        // The first fetch (or one after mail): Tor may carry it.
        assert!(s.onion_fetch_ok(&c, 0, now));
        assert!(s.onion_fetch_ok(&c, 3, now), "never over Tor yet");
        s.onion_fetch_at.insert(c, now);
        let soon = now + Duration::from_secs(60);
        assert!(
            !s.onion_fetch_ok(&c, 1, soon),
            "an idle poll a minute later"
        );
        assert!(s.onion_fetch_ok(&c, 0, soon), "the last round brought mail");
        assert!(s.onion_fetch_ok(&c, 4, now + ONION_FETCH_EVERY));
        // A link from the custodian (it dialled this node, over Tor too).
        s.linked.insert(c, soon);
        assert!(s.onion_fetch_ok(&c, 2, soon + Duration::from_secs(10)));
        assert!(!s.onion_fetch_ok(&c, 2, soon + LINK_SEEN_GAP));
        // Only targets keep it.
        s.keep_targets(&HashSet::new());
        assert!(s.onion_fetch_at.is_empty());
    }

    #[test]
    fn a_network_change_makes_custodians_due_but_keeps_parks() {
        let mut s = Shared::default();
        let now = Instant::now();
        let c = [0xC4; 32];
        s.note_deposit(&c, now + BASE_INTERVAL);
        s.park_for_code(&c, &[0xB4; 32], CustodyCode::Hold, now);
        assert_eq!(s.states[&c].1, now + BASE_INTERVAL, "due in a minute");
        let later = now + Duration::from_secs(1);
        s.network_changed(later);
        assert_eq!((s.states[&c].1, s.states[&c].2), (later, 0), "due now");
        assert_eq!(
            s.parked(&c, None, later),
            Some("CUSTODY_HOLD"),
            "the park stays"
        );
    }

    /// This node's Tor became usable (a helper life's first ready, relays
    /// after a ready from cache, our Tor working again): every custodian is
    /// due now with its empty rounds forgotten, so the idle-Tor rule lets
    /// the onion route through at once; every forward row is due; parks
    /// stay.
    #[test]
    fn tor_coming_up_makes_every_custodian_due_with_tor_allowed() {
        let _g = Gates::on(true, false);
        raven_core::custody_gate::set_handoff_gate_for_this_thread(Some(true));
        let mut s = Shared::default();
        let t0 = Instant::now();
        let (c, d) = ([0xCA; 32], [0xCB; 32]);
        // The last Tor fetch at `c`, 5 minutes ago, found nothing.
        s.onion_fetch_at.insert(c, t0);
        let now = t0 + Duration::from_secs(300);
        let later = now + Duration::from_secs(480);
        s.states.insert(c, (FetchState::default(), later, 5));
        s.states.insert(d, (FetchState::default(), later, 0));
        s.park_for_code(&d, &[0xBB; 32], CustodyCode::Hold, now);
        s.forward_next = Some(later);
        assert!(!s.onion_fetch_ok(&c, 4, now), "an idle poll: no Tor yet");
        s.tor_ready(now);
        raven_core::custody_gate::set_handoff_gate_for_this_thread(None);
        for x in [c, d] {
            assert_eq!((s.states[&x].1, s.states[&x].2), (now, 0), "due now");
        }
        assert!(s.onion_fetch_ok(&c, s.states[&c].2, now), "over Tor now");
        assert_eq!(s.parked(&d, None, now), Some("CUSTODY_HOLD"), "parks stay");
        assert!(s.forward_all);
        assert_eq!(s.forward_next, Some(now), "forward rows due");
    }

    /// A kick, a network change or Tor coming up while a pass dials a
    /// custodian (its entry is out of `states` then) was lost for it: the
    /// pass put back its own next time. Now that custodian is due again as
    /// soon as the pass ends if it reached nothing there, and a base
    /// interval on, its empty rounds forgotten, if a mail check's budget cut
    /// its turn (review mail-friends-5, finding B: it kept its own next
    /// time, up to 10 minutes), or at its own next time if that comes
    /// sooner (review mail-friends-6, nit 2); a pass that reached it keeps
    /// its own next time and empty rounds.
    #[test]
    fn a_wake_during_a_custodians_fetch_is_not_lost() {
        let mut s = Shared::default();
        let now = Instant::now();
        let c = [0xCC; 32];
        let later = now + BASE_INTERVAL;
        type Wake = fn(&mut Shared, Instant);
        let wakes: [(&str, Wake); 3] = [
            ("a kick", Shared::kick),
            ("a network change", Shared::network_changed),
            ("Tor ready", Shared::tor_ready),
        ];
        let a_while = Duration::from_secs(7);
        for (what, wake) in wakes {
            for (woken, due, empty) in [
                (Woken::AtOnce, now, 2),
                (Woken::Kept, later, 2),
                (Woken::After(a_while), now + a_while, 0),
            ] {
                s.states.remove(&c);
                s.begin_fetch(&c);
                wake(&mut s, now);
                s.end_fetch(c, FetchState::default(), (later, 2), woken, now);
                assert_eq!(
                    (s.states[&c].1, s.states[&c].2),
                    (due, empty),
                    "{what}, {woken:?}"
                );
                assert!(s.in_pass.is_empty());
            }
        }
        // With no wake, a cut turn too keeps its own next time.
        s.states.remove(&c);
        s.begin_fetch(&c);
        s.end_fetch(
            c,
            FetchState::default(),
            (later, 2),
            Woken::After(a_while),
            now,
        );
        assert_eq!((s.states[&c].1, s.states[&c].2), (later, 2));
        // Woken: its own next time if that comes sooner; not at once if it
        // has come.
        let secs = Duration::from_secs;
        let ended = now + secs(10);
        for (own, due) in [
            (now + secs(12), now + secs(12)),
            (ended, ended + a_while),
            (now + secs(3), ended + a_while),
        ] {
            s.states.remove(&c);
            s.begin_fetch(&c);
            s.kick(now);
            s.end_fetch(
                c,
                FetchState::default(),
                (own, 2),
                Woken::After(a_while),
                ended,
            );
            assert_eq!(
                (s.states[&c].1, s.states[&c].2),
                (due, 0),
                "{:?}",
                own - now
            );
        }
    }

    /// The idle interval is the empty-round rule as it was: the base
    /// interval for the first three empty rounds, then doubling up to ten
    /// base intervals.
    #[test]
    fn the_idle_interval_is_the_empty_round_rule() {
        let old = |empty: u32, base: Duration| {
            if empty > EMPTY_BEFORE_BACKOFF {
                (base * 2u32.saturating_pow(empty - EMPTY_BEFORE_BACKOFF)).min(max_interval(base))
            } else {
                base
            }
        };
        for base in [BASE_INTERVAL, Duration::from_secs(1)] {
            for empty in 0..=12 {
                assert_eq!(
                    idle_interval(empty, base),
                    old(empty, base),
                    "{empty} {base:?}"
                );
            }
        }
        let minutes = |m: u64| Duration::from_secs(60 * m);
        let idle: Vec<Duration> = (0..8).map(|n| idle_interval(n, BASE_INTERVAL)).collect();
        assert_eq!(idle, [1, 1, 1, 1, 2, 4, 8, 10].map(minutes));
    }

    /// The iPhone app back in front, or a desktop's Tor restarted after a
    /// network change, with a mail friend only Tor reaches: custody is
    /// kicked at once (the listeners came up, the network changed) and
    /// Tor is ready from its cache 2 s later. Before, the pass at the kick
    /// found no route (Tor not ready yet) and counted an empty round, and
    /// nothing told custody when Tor was ready: the friend was asked at
    /// the next poll a minute later, or, when the last Tor fetch there
    /// (which found nothing) was 5 minutes before, once the idle-Tor rule
    /// let Tor through again, 27 minutes later. Now it is asked as soon as
    /// Tor is ready.
    #[test]
    fn a_mail_friend_only_tor_reaches_is_asked_as_soon_as_tor_is_ready() {
        let c = [0xCE; 32];
        let ready_after = Duration::from_secs(2);
        // After the kick, when the first Tor fetch at `c` goes (`None`: not
        // within an hour). The last Tor fetch there was `tor_fetch_before`
        // before the kick, if any; it had brought nothing, as the rounds
        // since (`c` was last due 4 minutes on, after 6 empty rounds).
        let first_tor_fetch = |tor_fetch_before: Option<Duration>, old_rule: bool| {
            let t = Instant::now();
            let t0 = t + Duration::from_secs(3_600);
            let mut s = Shared::default();
            s.states
                .insert(c, (FetchState::default(), t0 + 4 * BASE_INTERVAL, 6));
            if let Some(before) = tor_fetch_before {
                s.onion_fetch_at.insert(c, t0 - before);
            }
            s.kick(t0);
            let mut now = t0;
            while now < t0 + Duration::from_secs(3_600) {
                let tor = now >= t0 + ready_after;
                if now == t0 + ready_after && !old_rule {
                    s.tor_ready(now);
                }
                let (due, empty) = (s.states[&c].1, s.states[&c].2);
                if due <= now {
                    if tor && s.onion_fetch_ok(&c, empty, now) {
                        return Some(now - t0);
                    }
                    // A pass with no route to `c` (Tor not ready yet, or
                    // the idle-Tor rule): before, an empty round.
                    let empty = if old_rule { empty + 1 } else { empty };
                    let next = now + idle_interval(empty, BASE_INTERVAL);
                    s.states.insert(c, (FetchState::default(), next, empty));
                }
                now += Duration::from_secs(1);
            }
            None
        };
        let recent = Some(Duration::from_secs(300));
        let before = [first_tor_fetch(None, true), first_tor_fetch(recent, true)];
        let after = [first_tor_fetch(None, false), first_tor_fetch(recent, false)];
        eprintln!(
            "a mail friend only Tor reaches is asked over Tor {before:?} after the kick before \
             (no Tor fetch there lately; one 5 min before), {after:?} now"
        );
        let secs = |s: u64| Some(Duration::from_secs(s));
        assert_eq!(before, [secs(60), secs(27 * 60)]);
        assert_eq!(after, [secs(2), secs(2)]);
    }

    /// Phase 5 nearby (design step 5.12, cutoff addendum F11d): a pipe to a
    /// custodian makes it due now, once per five minutes; a contact that is
    /// no custodian changes nothing.
    #[test]
    fn a_nearby_encounter_makes_a_custodian_due_once() {
        let mut s = Shared::default();
        let now = Instant::now();
        let c = [0xC8; 32];
        s.note_deposit(&c, now + BASE_INTERVAL);
        assert_eq!(
            s.encounter(&[0xB8; 32], false, now),
            Some(false),
            "not a custodian"
        );
        assert_eq!(s.encounter(&c, false, now), Some(true), "fetched now");
        assert_eq!(s.states[&c].1, now);
        // A pass ran: next due in a minute.
        let later = now + Duration::from_secs(60);
        s.states.get_mut(&c).unwrap().1 = later + BASE_INTERVAL;
        assert_eq!(s.encounter(&c, false, later), None, "once per gap");
        assert_eq!(s.states[&c].1, later + BASE_INTERVAL);
        let after = now + ENCOUNTER_GAP;
        assert_eq!(s.encounter(&c, false, after), Some(true));
        assert_eq!(s.states[&c].1, after);
    }

    /// Custody handoff over nearby (merge I.5): a pipe to a next hop this
    /// node holds rows for makes them due now, whatever its retry wait, once
    /// per five minutes, and only with the handoff gate live; a contact that
    /// is no next hop wakes nothing. The advertised hops are those rows'.
    #[test]
    fn a_nearby_encounter_hands_over_to_a_next_hop() {
        let mut s = Shared::default();
        let now = Instant::now();
        let (hop, other) = ([0xD8; 32], [0xD9; 32]);
        s.forward_hops.insert(hop);
        s.forward_failed(&hop, now);
        s.forward_next = Some(now + FORWARD_INTERVAL);
        assert_eq!(s.hops(), [hop]);
        assert_eq!(
            s.encounter(&other, true, now),
            Some(false),
            "no rows for it"
        );
        assert_eq!(
            s.encounter(&hop, false, now),
            Some(false),
            "the handoff gate closed"
        );
        assert!(!s.forward_early.contains(&hop));
        let later = now + Duration::from_secs(1);
        s.encounters.clear();
        assert_eq!(
            s.encounter(&hop, true, later),
            Some(true),
            "handed over now"
        );
        assert!(s.forward_early.contains(&hop));
        assert!(!s.forward_wait.contains_key(&hop), "no retry wait");
        assert_eq!(s.forward_next, Some(later));
        s.forward_early.clear();
        assert_eq!(
            s.encounter(&hop, true, later + Duration::from_secs(60)),
            None
        );
        assert!(s.forward_early.is_empty(), "once per gap");
    }

    /// E1 (three machines): mac-b, a custodian handing rows on, told its
    /// route hints about twice a second for a minute at a time ("and 62
    /// more like it in the last 30s"). Each link from a friend made what
    /// waited for it due at once, and the link that work opened did the
    /// same on the friend's side. Here F1 holds rows for A that do not go
    /// yet (each forward fails), and A collects its mail from F1: F1's
    /// forward link wakes A's fetch, A's fetch link wakes F1's forward and
    /// clears its retry wait. Over one simulated minute (a link takes 500
    /// ms) that was 120 links; once per contact per minute it is 3.
    #[test]
    fn a_custodian_and_its_next_hop_do_not_dial_each_other_back_to_back() {
        let (f1_key, a_key) = ([0xF1; 32], [0x0A; 32]);
        let link = Duration::from_millis(500);
        let links_in_a_minute = |gap: bool| -> usize {
            let t0 = Instant::now();
            let (mut f1, mut a) = (Shared::default(), Shared::default());
            f1.forward_hops.insert(a_key);
            f1.forward_failed(&a_key, t0);
            a.states
                .insert(f1_key, (FetchState::default(), t0 + BASE_INTERVAL, 0));
            // What a link from `peer` wakes on `s`: since E1, at most once a
            // minute; before, every time.
            let woken = |s: &mut Shared, peer: &[u8; 32], now: Instant| {
                if gap {
                    s.linked(peer, true, now) == Some(true)
                } else {
                    s.seen(peer, true, now)
                }
            };
            // A's own fetch from F1 starts it.
            let (mut links, mut next) = (0, Some((a_key, t0)));
            while let Some((from, at)) = next.take() {
                let now = at + link;
                if now > t0 + Duration::from_secs(60) {
                    break;
                }
                links += 1;
                if from == a_key {
                    // F1 heard A: the rows for A are due, and its forward
                    // link fails again.
                    if woken(&mut f1, &a_key, now) {
                        f1.forward_failed(&a_key, now);
                        next = Some((f1_key, now));
                    }
                } else if woken(&mut a, &f1_key, now) {
                    // A heard F1: its fetch from F1 is due.
                    next = Some((a_key, now));
                }
            }
            links
        };
        assert_eq!(links_in_a_minute(false), 120, "back to back before");
        // F1's forward link no longer pulls A's fetch forward either: A
        // reached F1 at its last fetch (E2).
        assert_eq!(links_in_a_minute(true), 2, "once per contact a minute");
        // A link in the gap still asks for new tags to be registered.
        let mut s = Shared::default();
        let now = Instant::now();
        assert_eq!(s.linked(&a_key, true, now), Some(false));
        s.register_due = false;
        assert_eq!(s.linked(&a_key, true, now + Duration::from_secs(1)), None);
        assert!(s.register_due);
        assert_eq!(s.linked(&a_key, true, now + LINK_SEEN_GAP), Some(false));
    }

    /// With the handoff gate closed nearby advertises for no next hop.
    #[test]
    fn forward_hops_are_nobody_with_the_handoff_gate_closed() {
        use raven_core::custody_gate::set_handoff_gate_for_this_thread;
        set_handoff_gate_for_this_thread(Some(false));
        let hops = forward_hops();
        set_handoff_gate_for_this_thread(None);
        assert!(hops.is_empty());
    }

    /// With the custody gate closed an encounter is a no-op: nothing is
    /// tracked or woken.
    #[test]
    fn an_encounter_with_the_custody_gate_off_is_a_no_op() {
        use raven_core::custody_gate::set_custody_gates_for_this_thread;
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: false,
            wan: false,
        }));
        let peer = [0xC9; 32];
        let new = encounter(&peer);
        set_custody_gates_for_this_thread(None);
        assert!(!new, "nothing for the caller to kick");
        assert!(!lock().encounters.contains_key(&peer));
    }

    /// Cutoff F8: a custodian that announces new routes (or links to us)
    /// while a fetch pass dials it, perhaps at the address it just left, is
    /// due again as soon as that pass ends if the pass reached nothing, and
    /// a base interval on, its empty rounds forgotten, if a mail check's
    /// budget cut its turn ([`Woken`]); a pass that reached it, or that
    /// nobody interrupted, keeps its own next time and its empty rounds, and
    /// another contact changes nothing.
    #[test]
    fn a_custodian_seen_during_its_fetch_is_due_again() {
        let mut s = Shared::default();
        let now = Instant::now();
        let c = [0xC5; 32];
        let later = now + BASE_INTERVAL;
        s.begin_fetch(&c);
        assert!(!s.wake(&[0xB5; 32], Wake::Moved, now), "not a custodian");
        s.end_fetch(c, FetchState::default(), (later, 2), Woken::AtOnce, now);
        assert_eq!(s.states[&c].1, later, "not seen: its own next time");
        assert_eq!(s.states[&c].2, 2);
        let a_while = Duration::from_secs(7);
        for (why, woken, due, empty) in [
            (Wake::Moved, Woken::AtOnce, now, 2),
            (Wake::Linked, Woken::AtOnce, now, 2),
            (Wake::Moved, Woken::Kept, later, 2),
            (Wake::Linked, Woken::Kept, later, 2),
            (Wake::Moved, Woken::After(a_while), now + a_while, 0),
            (Wake::Linked, Woken::After(a_while), now + a_while, 0),
        ] {
            s.states.remove(&c);
            s.begin_fetch(&c);
            assert!(!s.wake(&c, why, now), "in a pass: no wake yet");
            s.end_fetch(c, FetchState::default(), (later, 2), woken, now);
            assert_eq!(
                (s.states[&c].1, s.states[&c].2),
                (due, empty),
                "{why:?} {woken:?}"
            );
            assert!(s.in_pass.is_empty());
        }
        // Waiting for its next fetch: new routes make it due now, and the
        // fetcher wakes; its empty rounds stay.
        s.states.insert(c, (FetchState::default(), later, 2));
        let then = now + Duration::from_secs(1);
        assert!(s.wake(&c, Wake::Moved, then));
        assert_eq!((s.states[&c].1, s.states[&c].2), (then, 2));
        // A nearby encounter starts the backoff over.
        let met = then + Duration::from_secs(1);
        s.states.insert(c, (FetchState::default(), later, 5));
        assert!(s.wake(&c, Wake::Met, met));
        assert_eq!((s.states[&c].1, s.states[&c].2), (met, 0));
    }

    /// E2 night: a link from a custodian that answered its last fetch
    /// leaves the fetch where it was (its empty-round backoff too); one
    /// whose last round reached nothing is fetched from at once (it is
    /// back).
    #[test]
    fn a_link_pulls_a_fetch_forward_only_from_a_custodian_that_was_not_reached() {
        let mut s = Shared::default();
        let now = Instant::now();
        let c = [0xC7; 32];
        let later = now + Duration::from_secs(480);
        s.states.insert(c, (FetchState::default(), later, 6));
        assert!(!s.wake(&c, Wake::Linked, now));
        assert_eq!((s.states[&c].1, s.states[&c].2), (later, 6));
        s.failures.insert(c, 2);
        assert!(s.wake(&c, Wake::Linked, now));
        assert_eq!((s.states[&c].1, s.states[&c].2), (now, 6));
    }

    /// The longest interval after empty rounds is ten base intervals: 10
    /// minutes, and 10 s under a 1 s lab interval (the custody scenarios').
    #[test]
    fn the_longest_fetch_interval_is_ten_base_intervals() {
        assert_eq!(max_interval(BASE_INTERVAL), MAX_INTERVAL);
        assert_eq!(
            max_interval(Duration::from_secs(1)),
            Duration::from_secs(10)
        );
        assert_eq!(max_interval(Duration::from_secs(3600)), MAX_INTERVAL);
    }

    /// E2 night (win-c, nothing to send all night): two friends that each
    /// fetch from the other as a mail friend. Before, each fetch link made
    /// the other side's fetch due at once with its backoff cleared (at most
    /// once a minute per contact), so neither fetch ever left its 60 s base:
    /// about 2 links a minute per friend, 120 an hour. Now a link wakes only
    /// a fetch whose last round reached nothing, and the empty rounds
    /// stretch each fetch to 10 minutes: over a simulated hour 12 links.
    #[test]
    fn two_mail_friends_idle_for_an_hour() {
        let (a_key, b_key) = ([0xA1; 32], [0xB1; 32]);
        let hour = Duration::from_secs(3600);
        // The next interval after `empty` empty rounds (the pass's rule).
        let next = |empty: u32| {
            if empty > EMPTY_BEFORE_BACKOFF {
                (BASE_INTERVAL * 2u32.saturating_pow(empty - EMPTY_BEFORE_BACKOFF))
                    .min(max_interval(BASE_INTERVAL))
            } else {
                BASE_INTERVAL
            }
        };
        // `me` fetches from `them_key` when due at `now` (a fetch that finds
        // nothing: one link), and `them` hears that link from `my_key`.
        let step = |me: &mut Shared,
                    them: &mut Shared,
                    (my_key, them_key): ([u8; 32], [u8; 32]),
                    now: Instant,
                    old_rule: bool|
         -> usize {
            let (due, empty) = (me.states[&them_key].1, me.states[&them_key].2);
            if due > now {
                return 0;
            }
            let empty = empty + 1;
            me.states
                .insert(them_key, (FetchState::default(), now + next(empty), empty));
            if old_rule {
                // Before: once a minute per contact, due now, backoff gone.
                them.linked
                    .retain(|_, at| now.saturating_duration_since(*at) < LINK_SEEN_GAP);
                if them.linked.insert(my_key, now).is_none() {
                    if let Some((_, due, empty)) = them.states.get_mut(&my_key) {
                        *due = now;
                        *empty = 0;
                    }
                }
            } else {
                them.linked(&my_key, false, now);
            }
            1
        };
        // Links in the first and in the second idle hour.
        let links_per_hour = |old_rule: bool| -> [usize; 2] {
            let t0 = Instant::now();
            // Each side's view of the other as a custodian.
            let (mut a, mut b) = (Shared::default(), Shared::default());
            a.states.insert(b_key, (FetchState::default(), t0, 0));
            b.states.insert(
                a_key,
                (FetchState::default(), t0 + Duration::from_secs(7), 0),
            );
            let mut links = [0, 0];
            let mut now = t0;
            while now < t0 + 2 * hour {
                let h = usize::from(now >= t0 + hour);
                links[h] += step(&mut a, &mut b, (a_key, b_key), now, old_rule);
                links[h] += step(&mut b, &mut a, (b_key, a_key), now, old_rule);
                now += Duration::from_secs(1);
            }
            links
        };
        let (before, after) = (links_per_hour(true), links_per_hour(false));
        eprintln!(
            "two mail friends idle: {before:?} links in hours 1 and 2 before, {after:?} after"
        );
        assert!(before.iter().all(|n| *n >= 110), "before: {before:?}");
        // The first hour climbs the backoff (60 s three times, then 2, 4,
        // 8, 10 minutes); then one fetch each way per 10 minutes.
        assert!(after[0] <= 24, "after: {after:?}");
        assert_eq!(after[1], 12, "after: {after:?}");
    }

    #[test]
    fn three_strikes_park_an_old_custodian() {
        let mut s = Shared::default();
        let now = Instant::now();
        let c = [0xC3; 32];
        assert!(!s.strike(&c, now));
        assert!(!s.strike(&c, now));
        assert_eq!(s.parked(&c, None, now), None);
        // The third parks (and says so: the park's log line).
        assert!(s.strike(&c, now));
        assert_eq!(s.parked(&c, None, now), Some("CUSTODY_UNSUPPORTED"));
        // Strikes an hour apart never add up.
        let d = [0xC6; 32];
        for i in 0..3 {
            assert!(!s.strike(&d, now + PARK_HOUR * i));
        }
        assert_eq!(s.parked(&d, None, now + PARK_HOUR * 2), None);
    }

    /// Phase 6b R6 (design A, step P6.28): the third misbehaviour strike
    /// within a day parks the custodian for a day (no deposit there, no
    /// fetch, no handoff); a listener coming back keeps that park, only an
    /// explicit retry (`raven outbox retry`) lifts it. Strikes a day apart
    /// never add up, and the old-build strikes are their own.
    #[test]
    fn three_misbehaviour_strikes_park_a_custodian_for_a_day() {
        let mut s = Shared::default();
        let now = Instant::now();
        let (c, p) = ([0xC7; 32], [0xB7; 32]);
        assert!(!s.strike_misbehaved(&c, now));
        assert!(!s.strike(&c, now), "a deposit strike counts apart");
        assert!(!s.strike_misbehaved(&c, now + PARK_HOUR));
        assert_eq!(s.parked(&c, Some(&p), now + PARK_HOUR), None);
        let at = now + PARK_HOUR * 2;
        assert!(s.strike_misbehaved(&c, at));
        assert_eq!(s.parked(&c, Some(&p), at), Some(CUSTODY_MISBEHAVED));
        assert!(s.handoff_parked(&c, None, at));
        assert_eq!(
            s.parked(&c, None, at + PARK_DAY - Duration::from_secs(1)),
            Some(CUSTODY_MISBEHAVED)
        );
        assert_eq!(s.parked(&c, None, at + PARK_DAY), None, "a day, no more");
        // An answer from a dial already under way never shortens it.
        s.park_for_code(&c, &p, CustodyCode::RateLimited, at);
        for _ in 0..STRIKES_TO_PARK {
            s.strike(&c, at);
        }
        assert_eq!(s.parked(&c, None, at + PARK_HOUR), Some(CUSTODY_MISBEHAVED));
        // A listener coming back (or a custodian linking in) keeps it, and
        // clears the other parks as before.
        s.park_for_code(&[0xC8; 32], &p, CustodyCode::Hold, at);
        s.kick(at);
        assert_eq!(s.parked(&c, None, at), Some(CUSTODY_MISBEHAVED));
        assert_eq!(s.parked(&[0xC8; 32], None, at), None);
        // `raven outbox retry` lifts it.
        s.retry(at);
        assert_eq!(s.parked(&c, Some(&p), at), None);
        assert!(!s.handoff_parked(&c, None, at));
        // Strikes a day apart never add up.
        let d = [0xC9; 32];
        for i in 0..3 {
            assert!(!s.strike_misbehaved(&d, now + PARK_DAY * i));
        }
        assert_eq!(s.parked(&d, None, now + PARK_DAY * 2), None);
    }

    /// E-custody-harness-docs-9: once a route answered in a fetch pass, the
    /// pass's later dials (each page of a round) try it first, not the
    /// stale saved address planned before it; the others follow in plan
    /// order when it stops answering.
    #[test]
    fn a_fetch_pass_dials_the_route_that_answered_first() {
        let routes = ["saved 192.168.1.9:7420", "seen 10.42.0.5:7420", "p2p"];
        let mut calls: Vec<&str> = Vec::new();
        let mut first = 0;
        let mut up = vec!["seen 10.42.0.5:7420", "p2p"];
        let dial = |first: &mut usize, up: &[&str], calls: &mut Vec<&'static str>| {
            dial_in_turn(&routes, first, |r: &&'static str| {
                calls.push(*r);
                if up.contains(r) {
                    Ok(*r)
                } else {
                    Err(format!("{r}: no answer"))
                }
            })
        };
        assert_eq!(dial(&mut first, &up, &mut calls), Ok(routes[1]));
        assert_eq!(calls, [routes[0], routes[1]], "plan order at first");
        calls.clear();
        for _ in 0..3 {
            assert_eq!(dial(&mut first, &up, &mut calls), Ok(routes[1]));
        }
        assert_eq!(
            calls, [routes[1]; 3],
            "the stale address is not dialled again"
        );
        // It stops answering: the others in plan order, and the next one to
        // answer leads from then on.
        up.retain(|r| *r == "p2p");
        calls.clear();
        assert_eq!(dial(&mut first, &up, &mut calls), Ok(routes[2]));
        assert_eq!(calls, [routes[1], routes[0], routes[2]]);
        calls.clear();
        assert_eq!(dial(&mut first, &up, &mut calls), Ok(routes[2]));
        assert_eq!(calls, [routes[2]]);
        // Nothing answers: every route once, the last error.
        up.clear();
        calls.clear();
        assert_eq!(
            dial(&mut first, &up, &mut calls),
            Err("seen 10.42.0.5:7420: no answer".into())
        );
        assert_eq!(calls, [routes[2], routes[0], routes[1]]);
        assert_eq!(first, 2, "kept for the next dial");
        // No route at all.
        let none: [&str; 0] = [];
        let mut first = 0;
        assert_eq!(
            dial_in_turn(&none, &mut first, |_| Ok(())),
            Err("no custodian route".into())
        );
    }

    /// A custodian's Tor dial as [`dial_route_path`] makes it while a nearby
    /// pipe to the friend may come up: Tor takes `tor_for`, claiming the
    /// race right before it writes (`netutil::ReplyCollector::begin`), and
    /// says whether it wrote.
    fn custody_tor_dial(
        rt: &tokio::runtime::Runtime,
        tor_claims_after: Duration,
        tor_for: Duration,
        pipe_up: impl Fn() -> bool,
        wrote: &std::sync::atomic::AtomicBool,
    ) -> Result<&'static str, String> {
        let race = RaceGuard::new();
        let ticket = race.ticket(RaceSide::Onion);
        let tor = async move {
            tokio::time::sleep(tor_claims_after).await;
            if !crate::onion::race::claim(ticket) {
                return Err(crate::onion::race::RACE_LOST.to_string());
            }
            wrote.store(true, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(tor_for.saturating_sub(tor_claims_after)).await;
            Ok("tor")
        };
        rt.block_on(onion_unless_pipe(tor, &race, pipe_up))
    }

    /// Row R3 (a custodian hands held mail to a friend over Bluetooth) in
    /// small: the friend's nearby pipe comes up while the custodian's Tor
    /// dial still tries (up to 75 s; here 4 s). Tor yields and writes
    /// nothing, and the nearby route, planned after it, carries the frames
    /// while the pipe is up. Before, the pass waited for Tor and the pipe
    /// idled out unused (RNL1 §6: 30 s).
    #[test]
    fn a_custody_tor_dial_yields_to_a_nearby_pipe_that_comes_up() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let t = std::time::Instant::now();
        let pipe_up = || t.elapsed() >= Duration::from_millis(300);
        let wrote = std::sync::atomic::AtomicBool::new(false);
        let routes = [OutboxCarrier::Onion, OutboxCarrier::Nearby];
        let mut first = 0;
        let mut calls = Vec::new();
        let got = dial_in_turn(&routes, &mut first, |carrier| {
            calls.push(*carrier);
            match carrier {
                OutboxCarrier::Onion => custody_tor_dial(
                    &rt,
                    Duration::from_secs(4),
                    Duration::from_secs(4),
                    pipe_up,
                    &wrote,
                ),
                _ if pipe_up() => Ok("nearby"),
                _ => Err(crate::nearby::NEARBY_NOT_IN_RANGE.into()),
            }
        });
        assert_eq!(got, Ok("nearby"));
        assert_eq!(calls, routes);
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        assert!(
            !wrote.load(std::sync::atomic::Ordering::SeqCst),
            "Tor wrote nothing"
        );
    }

    /// A Tor link that authenticated before the pipe came up goes on: the
    /// pipe takes nothing from it, and nothing else is dialled.
    #[test]
    fn a_custody_tor_dial_that_got_through_first_is_not_cut() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let t = std::time::Instant::now();
        let wrote = std::sync::atomic::AtomicBool::new(false);
        let got = custody_tor_dial(
            &rt,
            Duration::from_millis(100),
            Duration::from_millis(800),
            || t.elapsed() >= Duration::from_millis(300),
            &wrote,
        );
        assert_eq!(got, Ok("tor"));
        assert!(wrote.load(std::sync::atomic::Ordering::SeqCst));
    }

    // ── Phase 3 P3.20: learned custody in the fetcher ──────────────────────

    use crate::outbox::test_rig as rig;
    use raven_core::custody_gate::{
        set_custody_gates_for_this_thread, set_custody_hints_for_this_thread,
    };
    use raven_core::device_cert::ensure_local_device_certificate;
    use raven_core::friend_custody::{
        decode_request, encode_reply, RequestDecode, Rfc1Reply, Rfc1Request,
    };
    use raven_core::lan_dispatch::{cache_peer_bundle, local_bundle};
    use raven_core::outbox::CarrierGates;
    use raven_core::paths::PRIMARY_DEVICE_ID;
    use std::cell::RefCell;

    /// Custody live (no WAN), custody riding route hints and the LAN
    /// carrier open on this test thread; the letters held, whatever
    /// `RAVEN_LAB_LETTER` the suite runs with (with them a fetch pass also
    /// asks for letters, one more dial: the letter tests use `LettersOn`);
    /// cleared on drop.
    struct Gates;

    impl Gates {
        /// On this thread, and on the thread of every turn a pass of this
        /// thread starts ([`TURN_GATES`]).
        fn on(live: bool, hints: bool) -> Self {
            Self::set(live, hints);
            TURN_GATES.with(|gates| {
                gates
                    .borrow_mut()
                    .push(Arc::new(move || Self::set(live, hints)));
            });
            Self
        }

        fn set(live: bool, hints: bool) {
            set_custody_gates_for_this_thread(Some(CustodyGates { live, wan: false }));
            set_custody_hints_for_this_thread(Some(hints));
            raven_core::custody_gate::set_carrier_gates_for_this_thread(Some(CarrierGates {
                lan: true,
                internet: false,
                p2p: false,
                nearby: false,
                onion: false,
            }));
            raven_core::horizon::set_lab_letter_for_this_thread(Some(false));
        }
    }

    impl Drop for Gates {
        fn drop(&mut self) {
            TURN_GATES.with(|gates| gates.borrow_mut().clear());
            set_custody_gates_for_this_thread(None);
            set_custody_hints_for_this_thread(None);
            raven_core::custody_gate::set_carrier_gates_for_this_thread(None);
            raven_core::horizon::set_lab_letter_for_this_thread(None);
        }
    }

    /// Alice (this node) with live sessions to Bob and Dave, and Carol, a
    /// verified contact on this network who may hold mail.
    struct Fix {
        a: tempfile::TempDir,
        alice: Identity,
        bob: [u8; 32],
        dave: [u8; 32],
        carol: [u8; 32],
        _peers: Vec<tempfile::TempDir>,
    }

    impl Fix {
        fn new(seed: u8) -> Self {
            let a = tempfile::tempdir().unwrap();
            let alice = Identity::from_seed(&[seed; 32]);
            ensure_local_device_certificate(a.path(), &alice, PRIMARY_DEVICE_ID).unwrap();
            raven_core::ensure_local_prekey(a.path(), &alice).unwrap();
            let a_bundle = local_bundle(a.path(), &alice).unwrap();
            let id = |n: u8| Identity::from_seed(&[seed.wrapping_add(n); 32]);
            let mut fix = Self {
                a,
                alice,
                bob: id(1).public_key_bytes(),
                dave: id(2).public_key_bytes(),
                carol: id(9).public_key_bytes(),
                _peers: Vec::new(),
            };
            // The book first: a pairing needs the peer as a contact.
            fix.book(&[]);
            for n in 1..=2u8 {
                let dir = tempfile::tempdir().unwrap();
                let peer = id(n);
                ensure_local_device_certificate(dir.path(), &peer, PRIMARY_DEVICE_ID).unwrap();
                raven_core::ensure_local_prekey(dir.path(), &peer).unwrap();
                rig::contacts(dir.path(), &fix.alice.public_key_bytes(), "", "", false);
                let bundle = local_bundle(dir.path(), &peer).unwrap();
                cache_peer_bundle(fix.dir(), &bundle).unwrap();
                rig::pair(fix.dir(), &fix.alice, dir.path(), &peer, &a_bundle, &bundle);
                fix._peers.push(dir);
            }
            fix
        }

        fn dir(&self) -> &Path {
            self.a.path()
        }

        /// Alice's book: Bob (listing `bob_lists`), Dave and Carol, all
        /// verified, each with a LAN route.
        fn book(&self, bob_lists: &[[u8; 32]]) {
            self.book_with(bob_lists, &[]);
        }

        /// [`Self::book`] in which Dave lists `dave_lists`.
        fn book_with(&self, bob_lists: &[[u8; 32]], dave_lists: &[[u8; 32]]) {
            let row = |key: &[u8; 32], dial: &str, custodians: &[[u8; 32]]| {
                serde_json::json!({
                    "pub_hex": hex::encode(key),
                    "pinned": true,
                    "lan_dial": dial,
                    "custodians": custodians.iter().map(hex::encode).collect::<Vec<_>>(),
                })
            };
            let rows = serde_json::json!([
                row(&self.bob, "192.168.1.11:7420", bob_lists),
                row(&self.dave, "192.168.1.12:7420", dave_lists),
                row(&self.carol, "192.168.1.50:7420", &[]),
            ]);
            std::fs::write(self.dir().join("contacts.json"), rows.to_string()).unwrap();
        }

        /// Carol's row in Alice's book loses its saved address: no route to
        /// her ([`Self::book`] gives it back).
        fn carol_has_no_address(&self) {
            let book = self.dir().join("contacts.json");
            let mut rows: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&book).unwrap()).unwrap();
            for row in rows.as_array_mut().unwrap() {
                if row["pub_hex"] == hex::encode(self.carol) {
                    row.as_object_mut().unwrap().remove("lan_dial");
                }
            }
            std::fs::write(&book, rows.to_string()).unwrap();
        }

        /// Alice's node policy: friend mailboxes `custody_use`.
        fn uses_friends(&self, custody_use: Option<bool>) {
            raven_core::save_policy(
                self.dir(),
                &raven_core::NodePolicy {
                    custody_use,
                    ..Default::default()
                },
            )
            .unwrap();
        }

        /// Carol's route hints (as learned_routes keeps them) offer custody
        /// with `flags`.
        fn carol_offers(&self, flags: u8, wall: u64) {
            let entry = serde_json::json!([{
                "pub_hex": hex::encode(self.carol),
                "generation": wall,
                "received_at_ms": wall,
                "expires_at_ms": wall + 600_000,
                "via": "lan",
                "custody_offer": flags,
            }]);
            std::fs::write(
                self.dir()
                    .join(raven_core::learned_routes::LEARNED_ROUTES_FILE),
                entry.to_string(),
            )
            .unwrap();
        }

        /// The inbound store tags of Alice's live sessions with `peers`.
        fn tags_of(&self, peers: &[[u8; 32]], wall: u64) -> Vec<[u8; 16]> {
            raven_core::custody_client::inbound_tags(self.dir(), &self.alice, peers, wall)
                .unwrap()
                .into_keys()
                .collect()
        }
    }

    /// What a test sets and its mock reads, on whatever thread the mock is
    /// dialled from (a pass asks several custodians from threads of their
    /// own).
    #[derive(Default)]
    struct Told<T>(Mutex<T>);

    impl<T: Copy> Told<T> {
        fn set(&self, value: T) {
            *self.0.lock().unwrap() = value;
        }

        fn get(&self) -> T {
            *self.0.lock().unwrap()
        }
    }

    /// Carol's side of a custody dial: an empty page (or one that always
    /// has more), releases taken; or down.
    #[derive(Default)]
    struct Carol {
        dials: Mutex<Vec<Vec<Vec<u8>>>>,
        down: Told<bool>,
        paging: Told<bool>,
        path: Told<Option<DeliveryPath>>,
    }

    impl Carol {
        fn dial(&self, frames: &[Vec<u8>]) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String> {
            self.dials.lock().unwrap().push(frames.to_vec());
            if self.down.get() {
                return Err("lan connect: cannot connect (Connection refused)".into());
            }
            let mut replies = vec![b"RLB1-offer".to_vec()];
            for f in frames {
                let Ok(RequestDecode::Request(id, request)) = decode_request(f) else {
                    continue;
                };
                let reply = match request {
                    Rfc1Request::Fetch { .. } => Rfc1Reply::FetchEnd {
                        code: CustodyCode::Ok,
                        returned: 0,
                        next: self.paging.get().then_some([7; 32]),
                    },
                    Rfc1Request::Release { digests } => Rfc1Reply::ReleaseResult {
                        code: CustodyCode::Ok,
                        released: digests.len() as u8,
                    },
                    // Deposits, and the letter ops (RFC1 §10) no test here sends.
                    _ => continue,
                };
                replies.push(encode_reply(&id, &reply));
            }
            Ok((replies, self.path.get().or(Some(DeliveryPath::Direct))))
        }

        fn count(&self) -> usize {
            self.dials.lock().unwrap().len()
        }

        /// The tags of every FETCH sent so far.
        fn fetched(&self) -> Vec<[u8; 16]> {
            let mut out = Vec::new();
            for frames in self.dials.lock().unwrap().iter() {
                for f in frames {
                    if let Ok(RequestDecode::Request(_, Rfc1Request::Fetch { tags, .. })) =
                        decode_request(f)
                    {
                        out.extend(tags);
                    }
                }
            }
            out.sort_unstable();
            out.dedup();
            out
        }
    }

    /// What a pass did beyond Carol: beacon wants and home changes.
    #[derive(Default)]
    struct Seen {
        wants: RefCell<Vec<[u8; 32]>>,
        homes: RefCell<Vec<usize>>,
    }

    /// One fetch pass of Alice at `now` / `wall`, Carol answering. As in
    /// every test that looks at one custodian's turn, the turns run on the
    /// test's own thread, one after the other (`at_once: 1`): the gates a
    /// test sets are its thread's own. The tests of asking at the same time
    /// (f18) take the node's `ASKED_AT_ONCE` and carry their gates
    /// (`Gates`).
    fn pass(
        fix: &Fix,
        shared: &Mutex<Shared>,
        carol: &Carol,
        seen: &Seen,
        lan: bool,
        now: Instant,
        wall: u64,
    ) {
        let dial = |_: &OutboxRoute, expected: &str, frames: &[Vec<u8>]| {
            assert_eq!(expected, hex::encode(fix.carol), "only Carol is dialled");
            carol.dial(frames)
        };
        let mut home_changed = |n: usize| seen.homes.borrow_mut().push(n);
        let want = |c: &[u8; 32]| seen.wants.borrow_mut().push(*c);
        let finds = |_: &[u8; 32]| Vec::new();
        let mut io = PassIo {
            dial: &dial,
            want: &want,
            finds: &finds,
            find_failed: &|_, _| {},
            home_changed: &mut home_changed,
            lan,
            kick: &|_| {},
            at_once: 1,
            budget: &no_budget,
        };
        fetch_pass_with(shared, fix.dir(), &fix.alice, now, wall, &mut io);
    }

    /// Far enough on that every custodian is due again.
    const LATER: Duration = Duration::from_secs(3_600);

    /// Review A-5: the LAN beacon found Carol at an address she has since
    /// left. A fetch pass dials that find first; nobody listens there, so
    /// the beacon is told to forget it (as a delivery dial tells it), once,
    /// and the pass goes on to her saved address. A refusal by Carol herself
    /// says nothing about the address and forgets nothing.
    #[test]
    fn f16_a_fetch_dial_that_misses_a_beacon_find_forgets_it() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let fix = Fix::new(0xa7);
        let wall = raven_core::clock::now_ms();
        fix.uses_friends(Some(true));
        fix.carol_offers(0, wall);
        let carol = Carol::default();
        let stale = "192.168.1.99:47532";
        for (why, forgets) in [
            ("lan connect: cannot connect (Connection refused)", true),
            ("lan_dial_peer_closed", false),
        ] {
            let shared = Mutex::default();
            let dialled = Mutex::new(Vec::new());
            let forgot = Mutex::new(Vec::new());
            let dial = |route: &OutboxRoute, _: &str, frames: &[Vec<u8>]| {
                dialled.lock().unwrap().push(route.dial.clone());
                if route.dial == stale {
                    return Err(why.to_string());
                }
                carol.dial(frames)
            };
            let mut home_changed = |_: usize| {};
            let finds = |c: &[u8; 32]| {
                if *c == fix.carol {
                    vec![stale.to_string()]
                } else {
                    Vec::new()
                }
            };
            let find_failed =
                |c: &[u8; 32], d: &str| forgot.lock().unwrap().push((*c, d.to_string()));
            let mut io = PassIo {
                dial: &dial,
                want: &|_| {},
                finds: &finds,
                find_failed: &find_failed,
                home_changed: &mut home_changed,
                lan: true,
                kick: &|_| {},
                at_once: 1,
                budget: &no_budget,
            };
            fetch_pass_with(
                &shared,
                fix.dir(),
                &fix.alice,
                Instant::now(),
                wall,
                &mut io,
            );
            let dialled = dialled.into_inner().unwrap();
            assert_eq!(dialled[..2], [stale, "192.168.1.50:7420"], "{why}");
            assert_eq!(
                dialled.iter().filter(|d| *d == stale).count(),
                1,
                "later pages go to the route that linked"
            );
            let want: Vec<([u8; 32], String)> = if forgets {
                vec![(fix.carol, stale.to_string())]
            } else {
                Vec::new()
            };
            assert_eq!(forgot.into_inner().unwrap(), want, "{why}");
        }
    }

    // ── W11-F1: mail friends are asked at the same time ────────────────────

    /// Both Carol and Dave offer to hold Alice's mail (her two mail
    /// friends, as `raven custody home auto` picks them).
    fn two_offer(fix: &Fix, wall: u64) {
        let entry = |key: &[u8; 32]| {
            serde_json::json!({
                "pub_hex": hex::encode(key),
                "generation": wall,
                "received_at_ms": wall,
                "expires_at_ms": wall + 600_000,
                "via": "lan",
                "custody_offer": 0,
            })
        };
        std::fs::write(
            fix.dir()
                .join(raven_core::learned_routes::LEARNED_ROUTES_FILE),
            serde_json::json!([entry(&fix.carol), entry(&fix.dave)]).to_string(),
        )
        .unwrap();
    }

    /// Alice with her two mail friends: the fixture whose keys put Dave
    /// before Carol, and the one that puts Carol first. A pass works its
    /// custodians out in the order of their keys, so which of the two a
    /// pass that asked one after the other would have asked first depends
    /// on the seed. Checked, not assumed: the first test of this finding
    /// was named for the mail friend that is away being asked first, and
    /// ran with the other order.
    fn two_friends(dave_leads: bool) -> (Fix, u64) {
        let fix = Fix::new(if dave_leads { 0xb5 } else { 0xb3 });
        assert_eq!(fix.dave < fix.carol, dave_leads, "the seed's key order");
        let wall = raven_core::clock::now_ms();
        fix.uses_friends(Some(true));
        two_offer(&fix, wall);
        (fix, wall)
    }

    /// A custody dial of the tests below: who it goes to, the route, the
    /// frames.
    type DialTo<'a> = dyn Fn(
            &'static str,
            &OutboxRoute,
            &[Vec<u8>],
        ) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String>
        + Sync
        + 'a;

    /// The beacon and its forgetting, for a pass that has no find.
    fn no_finds(_: &[u8; 32]) -> Vec<String> {
        Vec::new()
    }

    fn forget_nothing(_: &[u8; 32], _: &str) {}

    /// The LAN beacon of a test's pass: its finds and its forgetting.
    type Beacon<'a> = (
        &'a dyn Fn(&[u8; 32]) -> Vec<String>,
        &'a (dyn Fn(&[u8; 32], &str) + Sync),
    );

    /// One pass over Alice's mail friends as the node makes it, at most
    /// `at_once` asked at the same time: every dial goes through `dial`,
    /// on the thread of that custodian's turn.
    fn pass_at_once(
        fix: &Fix,
        shared: &Mutex<Shared>,
        at: (Instant, u64),
        at_once: usize,
        finds: &dyn Fn(&[u8; 32]) -> Vec<String>,
        find_failed: &(dyn Fn(&[u8; 32], &str) + Sync),
        dial: &DialTo<'_>,
    ) {
        pass_at_once_in(
            fix,
            shared,
            at,
            at_once,
            (finds, find_failed),
            dial,
            &no_budget,
        );
    }

    /// [`pass_at_once`] within a mail check's `budget`.
    fn pass_at_once_in(
        fix: &Fix,
        shared: &Mutex<Shared>,
        (now, wall): (Instant, u64),
        at_once: usize,
        (finds, find_failed): Beacon<'_>,
        dial: &DialTo<'_>,
        budget: &(dyn Fn() -> Option<Duration> + Sync),
    ) {
        let to = |route: &OutboxRoute, expected: &str, frames: &[Vec<u8>]| {
            let who = [(fix.carol, "carol"), (fix.dave, "dave"), (fix.bob, "bob")]
                .into_iter()
                .find(|(key, _)| expected == hex::encode(key))
                .map_or("nobody", |(_, who)| who);
            dial(who, route, frames)
        };
        let mut home_changed = |_: usize| {};
        let mut io = PassIo {
            dial: &to,
            want: &|_| {},
            finds,
            find_failed,
            home_changed: &mut home_changed,
            lan: true,
            kick: &|_| {},
            at_once,
            budget,
        };
        fetch_pass_with(shared, fix.dir(), &fix.alice, now, wall, &mut io);
    }

    /// A custody dial of the tests below, with what is left of the check's
    /// budget for it.
    type NetTo<'a> = dyn Fn(
            &'static str,
            &OutboxRoute,
            &[Vec<u8>],
            Option<Duration>,
        ) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String>
        + Sync
        + 'a;

    /// `net` as a pass dials, with who each dial goes to by name.
    fn named_net<'a>(fix: &'a Fix, net: &'a NetTo<'a>) -> Box<BudgetDial<'a>> {
        Box::new(
            move |route: &OutboxRoute,
                  expected: &str,
                  frames: &[Vec<u8>],
                  left: Option<Duration>| {
                let who = [(fix.carol, "carol"), (fix.dave, "dave"), (fix.bob, "bob")]
                    .into_iter()
                    .find(|(key, _)| expected == hex::encode(key))
                    .map_or("nobody", |(_, who)| who);
                net(who, route, frames, left)
            },
        )
    }

    /// A pass over Alice's mail friends that begins now, as the node makes
    /// one that a mail check may bound ([`within_check`], as [`node_pass`]
    /// does), with the beacon's `finds` and at most `at_once` asked at the
    /// same time: every dial goes through `net`, with what is left of the
    /// check's budget.
    fn pass_within_check(
        fix: &Fix,
        shared: &Mutex<Shared>,
        (now, wall): (Instant, u64),
        at_once: usize,
        finds: &dyn Fn(&[u8; 32]) -> Vec<String>,
        net: &NetTo<'_>,
    ) {
        let to = named_net(fix, net);
        within_check(&to, |dial, budget| {
            let mut home_changed = |_: usize| {};
            let mut io = PassIo {
                dial,
                want: &|_| {},
                finds,
                find_failed: &forget_nothing,
                home_changed: &mut home_changed,
                lan: true,
                kick: &|_| {},
                at_once,
                budget,
            };
            fetch_pass_with(shared, fix.dir(), &fix.alice, now, wall, &mut io);
        });
    }

    /// The custody dials that are out at the same moment, as a test's dial
    /// counts them.
    #[derive(Default)]
    struct DialsOut {
        /// Out now, and the most at once so far.
        out: Mutex<(usize, usize)>,
        moved: std::sync::Condvar,
    }

    impl DialsOut {
        /// A dial goes out, and waits (`limit` at most) until `together`
        /// dials have been out at once. Whether they were.
        fn begin(&self, together: usize, limit: Duration) -> bool {
            let mut out = self.out.lock().unwrap();
            out.0 += 1;
            out.1 = out.1.max(out.0);
            self.moved.notify_all();
            let (out, _) = self
                .moved
                .wait_timeout_while(out, limit, |out| out.1 < together)
                .unwrap();
            out.1 >= together
        }

        fn end(&self) {
            self.out.lock().unwrap().0 -= 1;
        }

        fn most(&self) -> usize {
            self.out.lock().unwrap().1
        }
    }

    /// Whether `custodian`'s turn has ended on `shared`: its next time is
    /// back in the schedule.
    fn turn_ended(shared: &Mutex<Shared>, custodian: &[u8; 32]) -> bool {
        let s = lock_of(shared);
        s.states.contains_key(custodian) && !s.in_pass.contains_key(custodian)
    }

    /// Waits (10 s at most) until `done`; whether it came.
    fn wait_until(done: impl Fn() -> bool) -> bool {
        let began = std::time::Instant::now();
        while !done() {
            if began.elapsed() > Duration::from_secs(10) {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        true
    }

    /// Two mail friends are dialled at the same time, each from a thread of
    /// its turn: the dial to each one waits here until the other's is out
    /// too, which never comes in a pass that asks one after the other.
    #[test]
    fn f18_two_mail_friends_are_dialled_at_the_same_time() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let (fix, wall) = two_friends(true);
        let shared = Mutex::default();
        let (carol, dave) = (Carol::default(), Carol::default());
        let out = DialsOut::default();
        let seen = Mutex::new(Vec::new());
        pass_at_once(
            &fix,
            &shared,
            (Instant::now(), wall),
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| {
                let both = out.begin(2, Duration::from_secs(5));
                let thread = std::thread::current().name().map(str::to_string);
                seen.lock().unwrap().push((who, both, thread));
                let got = if who == "carol" {
                    carol.dial(frames)
                } else {
                    dave.dial(frames)
                };
                out.end();
                got
            },
        );
        let mut seen = seen.into_inner().unwrap();
        seen.sort();
        let turn = Some("raven-mail-friend".to_string());
        assert_eq!(
            seen,
            [("carol", true, turn.clone()), ("dave", true, turn)],
            "each one's dial saw the other's out, from its turn's thread"
        );
        assert_eq!(out.most(), 2);
        let s = lock_of(&shared);
        assert!(s.states.contains_key(&fix.carol) && s.states.contains_key(&fix.dave));
        assert!(s.failures.is_empty() && s.in_pass.is_empty());
    }

    /// W11-F1 (three real machines, 2026-11-19): a receiver with two mail
    /// friends, one of them off, got the mail the other one held 62 s,
    /// 114 s and 88.6 s after its start: the pass asked the one that was
    /// off first and waited out its Tor dial. Here Dave is away, and his
    /// dial stays out until Carol's whole turn has ended (10 s at most):
    /// she is asked, answers and has her next time back in the schedule
    /// while his dial is still out, whichever of the two comes first by
    /// key. Dave's failure counts once.
    #[test]
    fn f18_a_mail_friend_that_is_away_does_not_keep_the_other_waiting() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        for dave_leads in [true, false] {
            let (fix, wall) = two_friends(dave_leads);
            let shared = Mutex::default();
            let carol = Carol::default();
            let carol_done = Told::<Option<bool>>::default();
            let began = std::time::Instant::now();
            pass_at_once(
                &fix,
                &shared,
                (Instant::now(), wall),
                ASKED_AT_ONCE,
                &no_finds,
                &forget_nothing,
                &|who, _, frames| {
                    if who == "carol" {
                        return carol.dial(frames);
                    }
                    carol_done.set(Some(wait_until(|| turn_ended(&shared, &fix.carol))));
                    Err("custody dial deadline".to_string())
                },
            );
            assert_eq!(
                carol_done.get(),
                Some(true),
                "Carol's turn ended while Dave's dial was out (Dave first by key: {dave_leads})"
            );
            assert!(began.elapsed() < Duration::from_secs(8), "nobody waited");
            assert!(carol.count() >= 1);
            let s = lock_of(&shared);
            assert_eq!(s.failures.get(&fix.dave), Some(&1));
            assert_eq!(s.failures.get(&fix.carol), None);
            assert!(s.states.contains_key(&fix.dave) && s.in_pass.is_empty());
        }
    }

    /// Only the waiting overlaps: what the turns do on this device is done
    /// by one turn at a time. The beacon's finds of both mail friends are
    /// stale and their dials fail at the same moment; each turn then tells
    /// the beacon to forget its find (which takes a while here), and the
    /// two never do that at the same time.
    #[test]
    fn f18_what_the_turns_do_on_this_device_is_done_one_at_a_time() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let (fix, wall) = two_friends(true);
        let shared = Mutex::default();
        let answers = Carol::default();
        let out = DialsOut::default();
        let stale = |c: &[u8; 32]| {
            if *c == fix.carol {
                "192.168.1.98:47532"
            } else {
                "192.168.1.99:47532"
            }
        };
        let finds = |c: &[u8; 32]| vec![stale(c).to_string()];
        // In the beacon's forgetting now, and the most at once.
        let forgetting = Mutex::new((0usize, 0usize));
        let forgot = Mutex::new(Vec::new());
        let find_failed = |c: &[u8; 32], d: &str| {
            {
                let mut f = forgetting.lock().unwrap();
                f.0 += 1;
                f.1 = f.1.max(f.0);
            }
            std::thread::sleep(Duration::from_millis(150));
            forgot.lock().unwrap().push((*c, d.to_string()));
            forgetting.lock().unwrap().0 -= 1;
        };
        pass_at_once(
            &fix,
            &shared,
            (Instant::now(), wall),
            ASKED_AT_ONCE,
            &finds,
            &find_failed,
            &|_, route, frames| {
                if route.dial.ends_with(":47532") {
                    out.begin(2, Duration::from_secs(5));
                    out.end();
                    return Err("lan connect: cannot connect (Connection refused)".to_string());
                }
                answers.dial(frames)
            },
        );
        assert_eq!(out.most(), 2, "the two stale dials were out together");
        let mut forgot = forgot.into_inner().unwrap();
        forgot.sort();
        let mut want = vec![
            (fix.carol, stale(&fix.carol).to_string()),
            (fix.dave, stale(&fix.dave).to_string()),
        ];
        want.sort();
        assert_eq!(forgot, want);
        assert_eq!(forgetting.lock().unwrap().1, 1, "one turn at a time");
        assert!(answers.count() >= 2, "both answered at their saved address");
    }

    /// Working a custodian's turn out (its tags, the beacon's finds) is
    /// this device's work too: it waits while another turn is at its own.
    /// Dave's find is stale and his turn tells the beacon to forget it,
    /// which takes a while here; Carol comes due right then (new routes:
    /// the schedule rings the pass at once), and her turn is worked out
    /// once Dave's has let go of the work, never while it holds it.
    #[test]
    fn f18_a_turn_is_worked_out_while_no_other_turn_is_at_work() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let (fix, wall) = two_friends(true);
        let shared: Mutex<Shared> = Mutex::default();
        let now = Instant::now();
        let later = now + Duration::from_secs(600);
        lock_of(&shared)
            .states
            .insert(fix.carol, (FetchState::default(), later, 0));
        let answers = Carol::default();
        let forgetting = Mutex::new(false);
        // Whose turn was worked out, and whether Dave's was at work then.
        let worked_out = Mutex::new(Vec::new());
        let finds = |c: &[u8; 32]| {
            let busy = *forgetting.lock().unwrap();
            let dave = *c == fix.dave;
            worked_out
                .lock()
                .unwrap()
                .push((if dave { "dave" } else { "carol" }, busy));
            if dave {
                vec!["192.168.1.99:47532".to_string()]
            } else {
                Vec::new()
            }
        };
        let woke_at = Mutex::new(None);
        let find_failed = |_: &[u8; 32], _: &str| {
            *forgetting.lock().unwrap() = true;
            *woke_at.lock().unwrap() = Some(std::time::Instant::now());
            let woke = lock_of(&shared).wake(&fix.carol, Wake::Moved, Instant::now());
            assert!(woke, "Carol is due now");
            std::thread::sleep(Duration::from_millis(800));
            *forgetting.lock().unwrap() = false;
        };
        // Dave's saved address answers once Carol has been asked and her
        // turn has ended (her entry is in the schedule from the start).
        let (carol_dials, carol_done) = (
            Told::<usize>::default(),
            Told::<Option<Duration>>::default(),
        );
        pass_at_once(
            &fix,
            &shared,
            (now, wall),
            ASKED_AT_ONCE,
            &finds,
            &find_failed,
            &|who, route, frames| {
                if route.dial.ends_with(":47532") {
                    return Err("lan connect: cannot connect (Connection refused)".to_string());
                }
                if who == "carol" {
                    carol_dials.set(carol_dials.get() + 1);
                }
                if who == "dave" {
                    let done =
                        wait_until(|| carol_dials.get() >= 1 && turn_ended(&shared, &fix.carol));
                    let woke = woke_at.lock().unwrap().expect("the wake came");
                    carol_done.set(done.then(|| woke.elapsed()));
                }
                answers.dial(frames)
            },
        );
        assert_eq!(
            *worked_out.lock().unwrap(),
            [("dave", false), ("carol", false)],
            "Carol's turn was worked out while Dave's was not at work"
        );
        let after = carol_done
            .get()
            .expect("Carol's turn ended while Dave's was out");
        // About 0.8 s (the forgetting's sleep); the cuts that do not ring
        // the pass make it about 5.05 s (review mail-friends-8, 8.4).
        assert!(
            after < Duration::from_secs(4),
            "the wake rang the pass (it sleeps 5 s otherwise): {after:?}"
        );
        assert!(turn_ended(&shared, &fix.carol) && turn_ended(&shared, &fix.dave));
    }

    /// The work a turn holds ([`AtWork`]): let go while its dial is out, so
    /// another turn can take it, and held again when the dial is back.
    #[test]
    fn f18_a_turn_lets_go_of_the_work_only_while_its_dial_is_out() {
        let lock = Mutex::new(());
        let mut work = AtWork::begin(&lock);
        let taken = || std::thread::scope(|s| s.spawn(|| lock.try_lock().is_ok()).join().unwrap());
        assert!(!taken(), "held from the turn's start");
        assert!(work.away(taken), "free while the dial is out");
        assert!(!taken(), "held again after the dial");
        drop(work);
        assert!(taken(), "free when the turn has ended");
    }

    /// A mail friend that comes due while turns are out is asked at once,
    /// in the same pass. Dave is away and due; Carol was asked a moment ago
    /// and is not. While Dave's dial is out a kick comes (the listeners
    /// came up, a link, Tor): Carol is due now, and she is asked and done
    /// while Dave's dial is still out. Before, she waited for the pass to
    /// end, behind the dial to a friend that is away. Dave, whose turn
    /// reached nothing, is due again after the pass and not asked twice in
    /// it.
    #[test]
    fn f18_one_that_comes_due_while_a_dial_is_out_is_asked_at_once() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let (fix, wall) = two_friends(true);
        let shared: Mutex<Shared> = Mutex::default();
        let now = Instant::now();
        let later = now + Duration::from_secs(600);
        lock_of(&shared)
            .states
            .insert(fix.carol, (FetchState::default(), later, 0));
        let carol = Carol::default();
        let dave_dials = Mutex::new(0usize);
        let carol_done = Told::<Option<bool>>::default();
        pass_at_once(
            &fix,
            &shared,
            (now, wall),
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| {
                if who == "carol" {
                    return carol.dial(frames);
                }
                *dave_dials.lock().unwrap() += 1;
                assert_eq!(carol.count(), 0, "Carol was not due when the pass began");
                let kicked = std::time::Instant::now();
                lock_of(&shared).kick(now);
                let done = wait_until(|| carol.count() >= 1 && turn_ended(&shared, &fix.carol));
                carol_done.set(Some(done && kicked.elapsed() < Duration::from_secs(3)));
                Err("custody dial deadline".to_string())
            },
        );
        assert_eq!(
            carol_done.get(),
            Some(true),
            "Carol was asked while Dave's dial was out, the kick ringing the pass \
             (it sleeps 5 s otherwise)"
        );
        assert_eq!(*dave_dials.lock().unwrap(), 1, "one turn in a pass");
        let s = lock_of(&shared);
        assert_eq!(s.failures.get(&fix.dave), Some(&1));
        assert!(
            s.states[&fix.dave].1 <= Instant::now(),
            "the kick came during his turn, which reached nothing: due again"
        );
        assert!(s.states[&fix.carol].1 > Instant::now(), "Carol answered");
        drop(s);
        // And one whose own time comes while a dial is out: the pass's time
        // goes on with the clock. Carol is due 300 ms after the pass began.
        let (fix, wall) = two_friends(true);
        let shared: Mutex<Shared> = Mutex::default();
        let now = Instant::now();
        let soon = now + Duration::from_millis(300);
        lock_of(&shared)
            .states
            .insert(fix.carol, (FetchState::default(), soon, 0));
        let carol = Carol::default();
        let carol_done = Told::<Option<bool>>::default();
        pass_at_once(
            &fix,
            &shared,
            (now, wall),
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| {
                if who == "carol" {
                    return carol.dial(frames);
                }
                let done = wait_until(|| carol.count() >= 1 && turn_ended(&shared, &fix.carol));
                carol_done.set(Some(done));
                Err("custody dial deadline".to_string())
            },
        );
        assert_eq!(carol_done.get(), Some(true), "Carol was asked when due");
    }

    /// A turn's thread is in the runtime the pass runs in (the node's, on
    /// its blocking pool), as the pass's own thread is: what a turn calls
    /// finds the runtime where it found it before, and a real dial from it
    /// blocks on that runtime, its timers and sockets driven (here a LAN
    /// dial to a closed port on this machine's loopback, refused at once:
    /// one the system just gave out and took back, not a fixed one that
    /// something may listen on).
    #[test]
    fn f18_a_turns_thread_is_in_the_runtime_of_the_pass() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let (fix, wall) = two_friends(true);
        let shared = Mutex::default();
        let answers = Carol::default();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let in_runtime = Mutex::new(Vec::new());
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .unwrap()
            .port();
        let closed = OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial: format!("127.0.0.1:{port}"),
        };
        let dial = |who: &'static str, _: &OutboxRoute, frames: &[Vec<u8>]| {
            let turn = std::thread::current().name() == Some("raven-mail-friend");
            let dialled = tokio::runtime::Handle::try_current().is_ok_and(|handle| {
                let slept = handle.block_on(async {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    true
                });
                let expected = hex::encode(fix.carol);
                let refused = dial_route_path(&handle, fix.dir(), &closed, &expected, frames, None);
                slept && refused.is_err()
            });
            in_runtime.lock().unwrap().push((who, turn, dialled));
            answers.dial(frames)
        };
        {
            let _in = runtime.enter();
            let at = (Instant::now(), wall);
            pass_at_once(
                &fix,
                &shared,
                at,
                ASKED_AT_ONCE,
                &no_finds,
                &forget_nothing,
                &dial,
            );
        }
        let mut seen = in_runtime.into_inner().unwrap();
        seen.sort();
        assert_eq!(seen, [("carol", true, true), ("dave", true, true)]);
        // And with no runtime about the pass, none about its turns.
        let in_runtime = Mutex::new(Vec::new());
        let dial = |who: &'static str, _: &OutboxRoute, frames: &[Vec<u8>]| {
            let found = tokio::runtime::Handle::try_current().is_ok();
            in_runtime.lock().unwrap().push((who, found));
            answers.dial(frames)
        };
        let (fix, wall) = two_friends(true);
        let shared = Mutex::default();
        let at = (Instant::now(), wall);
        pass_at_once(
            &fix,
            &shared,
            at,
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &dial,
        );
        let mut seen = in_runtime.into_inner().unwrap();
        seen.sort();
        assert_eq!(seen, [("carol", false), ("dave", false)]);
    }

    /// Review mail-friends-2 N2: a custody dial that the mail check's budget
    /// cuts before it is answered says so ([`MAIL_CHECK_BUDGET`]), not that
    /// the custodian did not answer in its time; one its own deadline cuts
    /// says that, as ever; with none of the budget left it does not go out.
    /// The dial here never answers (a friend whose dial hangs).
    #[test]
    fn f18_a_dial_the_checks_budget_cuts_says_so() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let went_out = Told::<usize>::default();
        let went = &went_out;
        let hangs = move || async move {
            went.set(went.get() + 1);
            std::future::pending::<Result<(), String>>().await
        };
        let ms = Duration::from_millis;
        let cut = |own, left| {
            let began = std::time::Instant::now();
            let got = runtime.block_on(within_deadline(hangs(), own, left));
            (got.err(), began.elapsed())
        };
        let (by_budget, took) = cut(PER_DIAL_DEADLINE, Some(ms(300)));
        assert_eq!(by_budget.as_deref(), Some(MAIL_CHECK_BUDGET), "{took:?}");
        assert!(
            took >= ms(300) && took < Duration::from_secs(10),
            "{took:?}"
        );
        let (own, took) = cut(ms(200), Some(Duration::from_secs(30)));
        assert_eq!(own.as_deref(), Some("custody dial deadline"));
        assert!(
            took >= ms(200) && took < Duration::from_secs(10),
            "{took:?}"
        );
        let (own, _) = cut(ms(100), None);
        assert_eq!(own.as_deref(), Some("custody dial deadline"));
        assert_eq!(went_out.get(), 3);
        let (spent, _) = cut(PER_DIAL_DEADLINE, Some(Duration::ZERO));
        assert_eq!(spent.as_deref(), Some(MAIL_CHECK_BUDGET));
        assert_eq!(went_out.get(), 3, "no dial once the budget is spent");
    }

    /// ... and the node's custody dial ([`node_dial`], as [`fetch_pass`]
    /// makes it) keeps what is left of its pass's budget
    /// ([`dial_route_path`]'s `left`, [`CheckBudget`]): with none left it
    /// does not go out (review mail-friends-6, finding 1). (Let out, it
    /// would fail at once on this test profile, with another error.)
    #[test]
    fn f18_a_custody_dial_keeps_the_checks_budget() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let (fix, _) = two_friends(true);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .unwrap()
            .port();
        let closed = OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial: format!("127.0.0.1:{port}"),
        };
        let (expected, frames) = (hex::encode(fix.carol), [b"fetch".to_vec()]);
        let node = node_dial(runtime.handle(), fix.dir());
        let dial = |left| node(&closed, &expected, &frames, left).err();
        assert_eq!(
            dial(Some(Duration::ZERO)).as_deref(),
            Some(MAIL_CHECK_BUDGET)
        );
        let out = dial(None).expect("a dial that went out fails here");
        assert_ne!(out, MAIL_CHECK_BUDGET, "with no check it goes out");
    }

    /// Review mail-friends-6, finding 1: the node's own pass ([`node_pass`],
    /// as [`fetch_pass`] makes it, here over this test's state and dial)
    /// keeps a mail check's budget: once it is spent no turn starts, nothing
    /// is dialled and no schedule changes; with 60 s left each dial has what
    /// is left of them, no less than when it begins (a loaded machine began
    /// the dials 7.8 s after the check set its deadline, in a stress run at
    /// a load average of 240 to 370, read live). Carol and Dave are asked at
    /// the same time: each dial is out until the other has begun too (5 s at
    /// most), so a node that asks one after the other (W11-F1) leaves the
    /// first out alone (review mail-friends-7, N1).
    #[test]
    fn f18_the_nodes_pass_keeps_the_checks_budget() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let _passes = passes_for_tests();
        let (fix, _) = two_friends(true);
        let shared: Mutex<Shared> = Mutex::default();
        let dials = Mutex::new(Vec::new());
        let out = AtomicUsize::new(0);
        let secs = Duration::from_secs;
        let until = std::time::Instant::now() + secs(60);
        let refused =
            |who: &'static str, _: &OutboxRoute, _: &[Vec<u8>], left: Option<Duration>| {
                let still = until.saturating_duration_since(std::time::Instant::now());
                out.fetch_add(1, Ordering::SeqCst);
                let since = std::time::Instant::now();
                while out.load(Ordering::SeqCst) < 2 && since.elapsed() < Duration::from_secs(5) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                let together = out.load(Ordering::SeqCst) >= 2;
                dials.lock().unwrap().push((who, left, together, still));
                Err("lan connect: cannot connect (Connection refused)".to_string())
            };
        let net = named_net(&fix, &refused);
        set_check_deadline(Some(std::time::Instant::now()));
        node_pass(&shared, fix.dir(), &fix.alice, &net);
        assert!(dials.lock().unwrap().is_empty(), "nothing dialled");
        {
            let s = lock_of(&shared);
            assert!(s.states.is_empty() && s.in_pass.is_empty(), "no turn");
        }
        set_check_deadline(Some(until));
        node_pass(&shared, fix.dir(), &fix.alice, &net);
        CHECK_DEADLINE_FOR_TESTS.with(|d| d.set(None));
        let mut dials = std::mem::take(&mut *dials.lock().unwrap());
        dials.sort();
        assert_eq!(
            dials.iter().map(|(who, ..)| *who).collect::<Vec<_>>(),
            ["carol", "dave"]
        );
        assert!(
            dials.iter().all(|(_, _, together, _)| *together),
            "asked at the same time: {dials:?}"
        );
        assert!(
            dials.iter().all(|(_, left, _, still)| {
                left.is_some_and(|left| left >= *still && left <= secs(60))
            }),
            "{dials:?}"
        );
    }

    /// No more than `at_once` are asked at the same time, and those that
    /// answered their last round start first. Three custodians (Bob holds
    /// mail too: Dave lists him), two at once; the first of them by key was
    /// not reached last time. Each dial waits (1.5 s at most) for the other
    /// two to be out with it: two are out together, never three, and the
    /// one that was not reached is dialled last.
    #[test]
    fn f18_no_more_than_at_once_and_those_that_answered_first() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let (fix, wall) = two_friends(true);
        fix.book_with(&[], &[fix.bob]);
        let names = [(fix.bob, "bob"), (fix.carol, "carol"), (fix.dave, "dave")];
        let (first, first_name) = *names.iter().min().unwrap();
        let shared: Mutex<Shared> = Mutex::default();
        lock_of(&shared).failures.insert(first, 1);
        let answers = Carol::default();
        let out = DialsOut::default();
        let order = Mutex::new(Vec::new());
        pass_at_once(
            &fix,
            &shared,
            (Instant::now(), wall),
            2,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| {
                order.lock().unwrap().push(who);
                out.begin(3, Duration::from_millis(1500));
                let got = answers.dial(frames);
                out.end();
                got
            },
        );
        let order = order.into_inner().unwrap();
        assert_eq!(out.most(), 2, "two at once, never three: {order:?}");
        assert_eq!(order.len(), 3, "each one asked once: {order:?}");
        assert_eq!(order.last(), Some(&first_name), "{order:?}");
        let s = lock_of(&shared);
        assert!(s.failures.is_empty() && s.in_pass.is_empty());
        assert_eq!(s.states.len(), 3);
        let local = fix.alice.public_key_bytes();
        let targets = fetch_targets(fix.dir(), &local, wall).unwrap();
        assert_eq!(targets.len(), 3, "Bob, Carol and Dave");
    }

    /// Review mail-friends-2 N4: a free place goes to a custodian not asked
    /// yet in the pass before one asked again. Two at once: Dave (out until
    /// the end) and Carol start; Bob (Dave lists him; not reached last
    /// time, so asked last) is parked. Carol answers and rests; a kick lifts
    /// Bob's park and makes both due at the same look: Bob takes the free
    /// place, and Carol follows when his turn ends.
    #[test]
    fn f18_a_free_place_goes_to_one_not_asked_yet_first() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let _t = Times::set(60_000, 50, 80_000);
        let (fix, wall) = two_friends(true);
        fix.book_with(&[], &[fix.bob]);
        let shared: Mutex<Shared> = Mutex::default();
        {
            let mut s = lock_of(&shared);
            s.failures.insert(fix.bob, 1);
            s.parked
                .insert(fix.bob, (Instant::now() + LATER, "TEST_PARK"));
        }
        let answers = Carol::default();
        let order = Mutex::new(Vec::new());
        let dave_dials = Told::<usize>::default();
        pass_at_once(
            &fix,
            &shared,
            (Instant::now(), wall),
            2,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| {
                if who != "dave" {
                    order.lock().unwrap().push(who);
                    return answers.dial(frames);
                }
                dave_dials.set(dave_dials.get() + 1);
                if dave_dials.get() > 1 {
                    return Err("custody dial deadline".to_string());
                }
                wait_until(|| turn_ended(&shared, &fix.carol));
                std::thread::sleep(Duration::from_millis(200));
                lock_of(&shared).kick(Instant::now());
                wait_until(|| {
                    order.lock().unwrap().len() >= 3
                        && turn_ended(&shared, &fix.carol)
                        && turn_ended(&shared, &fix.bob)
                });
                Err("custody dial deadline".to_string())
            },
        );
        let order = order.into_inner().unwrap();
        assert_eq!(order, ["carol", "bob", "carol"]);
    }

    /// Review mail-friends-2 N3: a pass's bell comes down with that pass
    /// only. A pass of a node that stopped (its runtime has a moment's
    /// grace) may end after a new node's pass has hung its bell: the new
    /// one is still rung, and comes down with its own pass.
    #[test]
    fn f18_an_old_passs_bell_leaves_a_new_one_hung() {
        let shared: Mutex<Shared> = Mutex::default();
        let (old, _old_notes) = std::sync::mpsc::channel::<Note>();
        let (new, new_notes) = std::sync::mpsc::channel::<Note>();
        let old_bell = Bell::hang(&shared, &old);
        let new_bell = Bell::hang(&shared, &new);
        drop(old_bell);
        lock_of(&shared).ring();
        assert!(
            matches!(new_notes.try_recv(), Ok(Note::Due)),
            "the new pass is rung"
        );
        drop(new_bell);
        assert!(lock_of(&shared).bell.is_none(), "its own came down");
    }

    /// With no thread to be had for a turn the pass asks the custodian on
    /// its own thread, and goes on: both mail friends are asked and done.
    #[test]
    fn f18_with_no_thread_to_be_had_the_pass_asks_on_its_own_thread() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let (fix, wall) = two_friends(true);
        let shared = Mutex::default();
        let answers = Carol::default();
        let threads = Mutex::new(Vec::new());
        TURN_THREADS_FOR_TESTS.with(|left| left.set(Some(0)));
        pass_at_once(
            &fix,
            &shared,
            (Instant::now(), wall),
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| {
                threads
                    .lock()
                    .unwrap()
                    .push((who, std::thread::current().id()));
                answers.dial(frames)
            },
        );
        TURN_THREADS_FOR_TESTS.with(|left| left.set(None));
        let mut threads = threads.into_inner().unwrap();
        threads.sort_by_key(|(who, _)| *who);
        let here = std::thread::current().id();
        assert_eq!(threads, [("carol", here), ("dave", here)]);
        let s = lock_of(&shared);
        assert!(s.states.contains_key(&fix.carol) && s.states.contains_key(&fix.dave));
        assert!(s.in_pass.is_empty());
    }

    /// One mail friend in all is asked as ever, on the pass's own thread;
    /// so is each of several when the pass asks one at a time.
    #[test]
    fn f18_one_mail_friend_alone_is_asked_on_the_pass_thread() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let here = std::thread::current().id();
        // Carol alone offers.
        let fix = Fix::new(0xb4);
        let wall = raven_core::clock::now_ms();
        fix.uses_friends(Some(true));
        fix.carol_offers(0, wall);
        let (answers, threads) = (Carol::default(), Mutex::new(Vec::new()));
        let dial = |who: &'static str, _: &OutboxRoute, frames: &[Vec<u8>]| {
            threads
                .lock()
                .unwrap()
                .push((who, std::thread::current().id()));
            answers.dial(frames)
        };
        let at = (Instant::now(), wall);
        let shared = Mutex::default();
        pass_at_once(
            &fix,
            &shared,
            at,
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &dial,
        );
        assert_eq!(*threads.lock().unwrap(), [("carol", here)]);
        // Two, one at a time: in the order of their keys.
        let (fix, wall) = two_friends(true);
        threads.lock().unwrap().clear();
        let shared = Mutex::default();
        let at = (Instant::now(), wall);
        pass_at_once(&fix, &shared, at, 1, &no_finds, &forget_nothing, &dial);
        assert_eq!(*threads.lock().unwrap(), [("dave", here), ("carol", here)]);
    }

    /// A wake for each of the custodians a pass asks at the same time is
    /// kept for that one: with one place for "the custodian in the pass"
    /// the second one's start forgot the first.
    #[test]
    fn f18_a_wake_is_kept_for_each_custodian_in_a_pass() {
        let mut s = Shared::default();
        let now = Instant::now();
        let later = now + BASE_INTERVAL;
        let (a, b, c) = ([0xA1; 32], [0xA2; 32], [0xA3; 32]);
        for x in [a, b, c] {
            s.begin_fetch(&x);
        }
        // New routes of `a`, nothing about `b`.
        assert!(!s.wake(&a, Wake::Moved, now));
        let state = FetchState::default;
        assert_eq!(s.end_fetch(a, state(), (later, 1), Woken::AtOnce, now), now);
        assert_eq!(
            s.end_fetch(b, state(), (later, 1), Woken::AtOnce, now),
            later
        );
        assert_eq!((s.states[&a].1, s.states[&b].1), (now, later));
        // A kick is for every one still in the pass, once.
        s.kick(now);
        assert_eq!(s.end_fetch(c, state(), (later, 1), Woken::AtOnce, now), now);
        assert!(s.in_pass.is_empty());
        s.begin_fetch(&c);
        assert_eq!(
            s.end_fetch(c, state(), (later, 1), Woken::AtOnce, now),
            later
        );
    }

    /// A turn that panics ends the pass as a panic in a pass always did
    /// (the fetcher's supervisor sees it), but only once the other turns
    /// have ended and been noted: nothing waits for an end that will never
    /// come.
    #[test]
    fn f18_a_turn_that_panics_ends_the_pass_after_the_others() {
        if !rig::lab_backends() {
            return;
        }
        let (ended, end) = std::sync::mpsc::channel();
        // On a thread of its own: a pass that never ended must not hang
        // the test.
        std::thread::spawn(move || {
            let _g = Gates::on(true, true);
            let (fix, wall) = two_friends(true);
            let shared = Mutex::default();
            let carol = Carol::default();
            let pass = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pass_at_once(
                    &fix,
                    &shared,
                    (Instant::now(), wall),
                    ASKED_AT_ONCE,
                    &no_finds,
                    &forget_nothing,
                    &|who, _, frames| {
                        if who == "carol" {
                            return carol.dial(frames);
                        }
                        wait_until(|| turn_ended(&shared, &fix.carol));
                        panic!("a fault in Dave's turn");
                    },
                );
            }));
            let carol_noted = turn_ended(&shared, &fix.carol);
            let _ = ended.send((pass.is_err(), carol_noted, carol.count()));
        });
        let (panicked, carol_noted, carol_dials) = end
            .recv_timeout(Duration::from_secs(30))
            .expect("the pass ended");
        assert!(panicked, "the panic ends the pass");
        assert!(carol_noted && carol_dials >= 1, "Carol's turn was noted");
    }

    /// The line of a mail friend that was not reached names its short tag,
    /// the carrier tried last and the wait, and nothing else (W11-F2: the
    /// log was silent about it).
    #[test]
    fn f18_the_not_reached_line_names_no_key() {
        let keeper = [0x6D; 32];
        let line = not_reached_line(&keeper, Some(OutboxCarrier::Onion), Duration::from_secs(60));
        let tag = crate::netutil::link_tag(&keeper);
        assert_eq!(
            line,
            format!("contact {tag} not reached for mail (onion_dial); due again in 60 s")
        );
        assert!(!line.contains(&hex::encode(keeper)[..8]), "{line}");
        let line = not_reached_line(&keeper, None, Duration::ZERO);
        assert_eq!(
            line,
            format!("contact {tag} not reached for mail (unknown); due again in 0 s")
        );
    }

    /// A pass's times ([`PassTimes`]): a custodian rests 5 s between two
    /// turns in a pass ([`AGAIN_AFTER`]), a tenth of the fetch interval
    /// when a lab interval is shorter (the fault matrix's 2 s: 200 ms); new
    /// turns for [`NEW_TURNS_FOR`] either way. A lab interval under 200 ms
    /// is taken as 200 ms, as the fetcher takes it ([`SHORTEST_INTERVAL`],
    /// review mail-friends-4, finding 6).
    #[test]
    fn f18_a_pass_rests_a_tenth_of_its_interval_at_most_5_s() {
        let times = PassTimes::for_base(BASE_INTERVAL);
        assert_eq!(times.again_after, Duration::from_secs(5));
        // New turns for twice an Internet dial's deadline and a Tor dial's
        // together: 250 s, not an onion dial's 80 s (review mail-friends-2,
        // finding 1); three turns in an interval at most.
        assert_eq!(times.new_turns_for, Duration::from_secs(250));
        assert_eq!(TURNS_IN_AN_INTERVAL, 3);
        let lab = PassTimes::for_base(Duration::from_secs(2));
        assert_eq!(
            (lab.base, lab.again_after, lab.new_turns_for),
            (
                Duration::from_secs(2),
                Duration::from_millis(200),
                Duration::from_secs(250)
            )
        );
        let none = PassTimes::for_base(Duration::ZERO);
        assert_eq!(
            (none.base, none.again_after),
            (Duration::from_millis(200), Duration::from_millis(20))
        );
    }

    /// The times of this thread's passes ([`PassTimes`]), in ms, until
    /// dropped.
    struct Times;

    impl Times {
        fn set(base: u64, again_after: u64, new_turns_for: u64) -> Self {
            let ms = Duration::from_millis;
            PASS_TIMES_FOR_TESTS.with(|t| {
                t.set(Some(PassTimes {
                    base: ms(base),
                    again_after: ms(again_after),
                    new_turns_for: ms(new_turns_for),
                }));
            });
            Self
        }
    }

    impl Drop for Times {
        fn drop(&mut self) {
            PASS_TIMES_FOR_TESTS.with(|t| t.set(None));
        }
    }

    /// The not-reached lines this thread's passes printed since the last
    /// call.
    fn not_reached_lines() -> Vec<String> {
        NOT_REACHED_FOR_TESTS.with(|lines| std::mem::take(&mut *lines.borrow_mut()))
    }

    /// Review mail-friends-1, finding 1: a mail friend that already had its
    /// turn in a pass and comes due again is asked again in it, not after
    /// the pass behind the friend that is away. Both are due; Carol answers
    /// at once, Dave is away. While his dial is out a kick comes (the
    /// listeners, Tor, a link): Carol is asked again, no sooner than her
    /// rest after her first turn (here 1.5 s, well above what a turn takes
    /// in a debug build), and done while his dial is still out. Dave, whose
    /// turn ends last, is not asked again in the pass.
    #[test]
    fn f18_one_that_had_its_turn_is_asked_again_when_it_comes_due_again() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let _t = Times::set(60_000, 1500, 80_000);
        let (fix, wall) = two_friends(true);
        let shared: Mutex<Shared> = Mutex::default();
        let carol = Carol::default();
        let carol_at = Mutex::new(Vec::new());
        let dave_dials = Mutex::new(0usize);
        let twice = Told::<Option<bool>>::default();
        pass_at_once(
            &fix,
            &shared,
            (Instant::now(), wall),
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| {
                if who == "carol" {
                    carol_at.lock().unwrap().push(std::time::Instant::now());
                    return carol.dial(frames);
                }
                *dave_dials.lock().unwrap() += 1;
                let first = wait_until(|| turn_ended(&shared, &fix.carol));
                lock_of(&shared).kick(Instant::now());
                let again = wait_until(|| {
                    carol_at.lock().unwrap().len() >= 2 && turn_ended(&shared, &fix.carol)
                });
                twice.set(Some(first && again));
                Err("custody dial deadline".to_string())
            },
        );
        assert_eq!(
            twice.get(),
            Some(true),
            "asked again while Dave's dial was out"
        );
        let at = carol_at.into_inner().unwrap();
        assert_eq!(at.len(), 2, "once, and once after the kick: {at:?}");
        assert!(
            at[1] - at[0] >= Duration::from_millis(1500),
            "not before her rest: {:?}",
            at[1] - at[0]
        );
        assert_eq!(*dave_dials.lock().unwrap(), 1, "Dave once");
        let s = lock_of(&shared);
        assert_eq!(s.failures.get(&fix.dave), Some(&1));
        assert!(!s.failures.contains_key(&fix.carol) && s.in_pass.is_empty());
    }

    /// Review mail-friends-1, finding 5: while a dial is out the pass
    /// sleeps until a turn ends, the schedule rings, or one of its
    /// custodians may start a turn; it does not look every 200 ms. Carol
    /// answers and rests 2 s (new routes make her due meanwhile: a wake,
    /// which leaves parks as they are), Bob is parked for an hour, Dave's
    /// dial is out until Carol has been asked again: six looks or so in
    /// all, where looking every 200 ms through her rest made ten more.
    #[test]
    fn f18_the_pass_sleeps_while_no_turn_can_start() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let _t = Times::set(60_000, 2000, 80_000);
        let (fix, wall) = two_friends(true);
        fix.book_with(&[], &[fix.bob]);
        let shared: Mutex<Shared> = Mutex::default();
        lock_of(&shared)
            .parked
            .insert(fix.bob, (Instant::now() + LATER, "TEST_PARK"));
        let carol = Carol::default();
        let (again, bob_dials) = (Told::<Option<bool>>::default(), Told::<usize>::default());
        LOOKS_FOR_TESTS.with(|looks| looks.set(0));
        pass_at_once(
            &fix,
            &shared,
            (Instant::now(), wall),
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| match who {
                "carol" => carol.dial(frames),
                "dave" => {
                    let ended = wait_until(|| turn_ended(&shared, &fix.carol));
                    let woke = lock_of(&shared).wake(&fix.carol, Wake::Moved, Instant::now());
                    let asked =
                        wait_until(|| carol.count() >= 2 && turn_ended(&shared, &fix.carol));
                    again.set(Some(ended && woke && asked));
                    Err("custody dial deadline".to_string())
                }
                _ => {
                    bob_dials.set(bob_dials.get() + 1);
                    Err("custody dial deadline".to_string())
                }
            },
        );
        let looks = LOOKS_FOR_TESTS.with(std::cell::Cell::get);
        assert_eq!(
            again.get(),
            Some(true),
            "Carol was asked again after her rest"
        );
        assert_eq!((carol.count(), bob_dials.get()), (2, 0), "Bob stays parked");
        assert!(looks <= 10, "looks: {looks}");
    }

    /// ... and one whose own next time comes while a dial is out is asked
    /// again then, by the pass's own clock, with nothing ringing: Carol's
    /// fetch interval is 400 ms here (her next time is 400 ms after the
    /// pass's), and the pass looks at least every 5 s otherwise. Not before
    /// her time, measured from the pass's start, which the pass's clock
    /// never runs behind (review mail-friends-2 L4: from her first dial it
    /// hung on how long that turn took); and within 4 s of her first dial,
    /// not of the pass's start, as a loaded machine can hold a pass's setup
    /// up by seconds (review mail-friends-8, 8.1: a stress run at a load
    /// average of 240 to 370, read live, made her first dial 2.1 s late
    /// once, and her second came at 2.5 s). A pass that misses her time
    /// asks her at its next look, 5 s after her first turn.
    #[test]
    fn f18_one_that_had_its_turn_is_asked_again_at_its_own_time() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let _t = Times::set(400, 50, 80_000);
        let (fix, wall) = two_friends(true);
        let shared: Mutex<Shared> = Mutex::default();
        let carol = Carol::default();
        let carol_at = Mutex::new(Vec::new());
        let start = std::time::Instant::now();
        pass_at_once(
            &fix,
            &shared,
            (Instant::now(), wall),
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| {
                if who == "carol" {
                    carol_at.lock().unwrap().push(start.elapsed());
                    return carol.dial(frames);
                }
                wait_until(|| carol_at.lock().unwrap().len() >= 2);
                Err("custody dial deadline".to_string())
            },
        );
        let at = carol_at.into_inner().unwrap();
        assert!(at.len() >= 2, "{at:?}");
        assert!(
            at[1] >= Duration::from_millis(400)
                && at[1].saturating_sub(at[0]) < Duration::from_secs(4),
            "at her time, not at a later look: {at:?}"
        );
    }

    /// Review mail-friends-3 R1: once a pass is old (here 5 s, the
    /// backstop of [`NEW_TURNS_FOR`]), a friend that is there is still
    /// asked at its times while a turn that holds the pass keeps it going,
    /// and one whose last turn reached nothing is not. Carol's and Bob's
    /// fetch interval is 1 s. Bob answers at first; his second turn, about
    /// 1 s after his first, starts while the pass is young and is out until
    /// 9.8 s: it holds the pass, though it is not his first (first turns
    /// hold it too: review mail-friends-4, finding 3). Dave's dial fails at
    /// 5.4 s, and a kick during it made him due at once. After Dave's turn
    /// Carol is asked at her times, Dave is not asked again, and the pass
    /// ends with Bob's turn (the next one reads the mail friends again).
    /// Meanwhile it sleeps until Carol is due: Dave is due, but may not
    /// start a turn, and looking every 200 ms for him fails the bound on
    /// its looks. Before, nothing was asked once the pass was old.
    /// Dave's turn is out for the pass until it notes his end, as his entry
    /// leaves `in_pass`, and until then his first turn holds the pass; so
    /// her asks count from then, not from his dial's end (review
    /// mail-friends-10, 10.1: where only first turns held it, round 8's
    /// run, at a load average of about 340, asked her about 0.95 s after
    /// his dial ended, and one more such ask would have let that cut
    /// through). Her dial looks at his entry, under the pass's lock, as she
    /// is asked: a watch on another thread sees the noting late, and an ask
    /// planned after it could count before it (review mail-friends-11,
    /// 11.1). Once it is noted, at most one ask that the pass planned before
    /// can come, so two are wanted: one turn of hers is out at a time, and
    /// each dials once here (one page, no letters: review mail-friends-11,
    /// 11.5). A kick makes Carol due at once too, her empty rounds
    /// forgotten, but only while her entry is in the schedule (not out for a
    /// turn, nor taken out for one being planned: review mail-friends-10,
    /// 10.2). Her answers are empty, so from her fourth turn her interval
    /// doubles: with them kept, she is asked once after Dave's turn, not
    /// three times. So the kick waits, from 4.3 s to 5.2 s, until her entry
    /// is in the schedule, looked at under the pass's lock (review
    /// mail-friends-9, N2: a kick at a set time can come while her turn is
    /// out; with one at 4.8 s, two stress runs asked her once after Dave's
    /// turn in 14 of 28 runs, at a load average of 4 to 9, and a turn held
    /// up long enough takes in two kicks 0.5 s apart).
    /// The times of Dave's and Bob's dials run from the pass's first dial,
    /// and the pass is young for five of Bob's intervals: its age runs from
    /// the call, his turns from its first look, which a loaded machine made
    /// up to 0.6 s later (review mail-friends-5, nit F), and a loaded
    /// machine can hold a pass's setup up by seconds (review mail-friends-8,
    /// 8.1: with three intervals, a setup held up by 2 s would start his
    /// second turn once the pass was old). A run proves nothing, and runs
    /// again (twice at most), if Bob had no second dial while the pass was
    /// young (a setup held up by more than about 3.8 s makes it come once
    /// the pass is old: review mail-friends-9, on 8.1; the pass held up by
    /// about 4 s from just before it falls due gives him none: review
    /// mail-friends-10, 10.3), if Carol's entry was out of the schedule from
    /// 4.3 s to 5.2 s, if Bob's second dial did not see the pass note Dave's
    /// end (review mail-friends-11, 11.3), or if fewer than two of her asks
    /// came once it had noted it and one or more came between his dial's end
    /// and that (the run then shows nothing of what holds the pass once his
    /// turn has ended). If Dave's end reaches the pass late, her asks at her
    /// times leave two after the noting while it comes up to about 1.95 s
    /// after his dial's end (0.94 s if her last ask, 0.43 s before Bob's
    /// turn ends, is held up past that), and a later noting runs again. If
    /// the pass itself is held up from his dial's end, two come after it
    /// while that lasts under about 3.4 s and one (a failure) while it lasts
    /// up to about 4.4 s; past that Bob's dial sees no noting, and the run
    /// runs again (review mail-friends-11, 11.4). Dave's and Bob's dials are
    /// checked on every run (Bob's twice at most). Bob's turn is out long
    /// enough for Carol to be asked twice after Dave's although a loaded
    /// machine held her turn up to 1.8 s past her time (with Bob out 2.4 s
    /// past Dave's turn, a stress run at a load average of about 285, read
    /// live, asked her once); the pass may end up to 2 s after his turn, for
    /// the same reason.
    #[test]
    fn f18_an_old_pass_still_asks_a_friend_that_is_there() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let _t = Times::set(1000, 10, 5000);
        let mut proved_nothing = Vec::new();
        let (run, after) = loop {
            let run = old_pass_run();
            assert_eq!(
                run.dials.0, 1,
                "Dave is not asked again once the pass is old"
            );
            assert!(
                run.dials.1 <= 2,
                "Bob is asked twice at most: {:?}",
                run.dials
            );
            let young = run
                .again
                .is_some_and(|again| again < Duration::from_millis(5000));
            let (in_lag, after) = run.asked_around_daves_end();
            if young && run.kicked && run.noted.is_some() && (after >= 2 || in_lag == 0) {
                break (run, after);
            }
            proved_nothing.push((run.setup, run.again, run.kicked, run.noted, in_lag, after));
            assert!(
                proved_nothing.len() < 3,
                "no run proved anything (setup, Bob's second dial, kicked, Dave noted, Carol's \
                 asks in the lag and after): {proved_nothing:?}"
            );
        };
        if !proved_nothing.is_empty() {
            eprintln!(
                "runs that proved nothing (setup, Bob's second dial, kicked, Dave noted, \
                 Carol's asks in the lag and after): {proved_nothing:?}"
            );
        }
        let OldPassRun {
            carol_at: at,
            again,
            ended,
            noted,
            took,
            looks,
            ..
        } = run;
        assert!(
            after >= 2,
            "Carol was asked at her times once Dave's end was noted ({noted:?}; his dial \
             ended {ended:?}), Bob's second turn out (from {again:?}): {at:?}"
        );
        assert!(
            took < Duration::from_millis(11_800),
            "the pass ended with Bob's turn: {took:?}"
        );
        assert!(looks <= 28, "looks: {looks}");
    }

    /// What one run of [`f18_an_old_pass_still_asks_a_friend_that_is_there`]
    /// measured: the dials to Dave and to Bob; when Bob's second dial came,
    /// when the pass's first dial came, when Carol was asked (and where
    /// Dave's turn then was), when Dave's dial ended and when Bob's second
    /// dial saw that the pass had noted his end (if it did while that turn
    /// was out), from before the call; whether Carol was kicked while her
    /// entry was in the schedule; how long the pass took from its first
    /// dial; and its looks.
    struct OldPassRun {
        dials: (usize, usize),
        again: Option<Duration>,
        setup: Duration,
        kicked: bool,
        carol_at: Vec<(Duration, Option<bool>)>,
        ended: Duration,
        noted: Option<Duration>,
        took: Duration,
        looks: usize,
    }

    impl OldPassRun {
        /// Carol's asks once Dave's dial had ended: those while the pass
        /// had not noted his end yet (the lag), and those once it had, each
        /// as her dial found his entry.
        fn asked_around_daves_end(&self) -> (usize, usize) {
            let asked = |noted: bool| {
                self.carol_at
                    .iter()
                    .filter(|(_, dave)| *dave == Some(noted))
                    .count()
            };
            (asked(false), asked(true))
        }
    }

    /// One run of [`f18_an_old_pass_still_asks_a_friend_that_is_there`].
    fn old_pass_run() -> OldPassRun {
        let (fix, wall) = two_friends(true);
        fix.book_with(&[], &[fix.bob]);
        let shared: Mutex<Shared> = Mutex::default();
        let (carol, bob) = (Carol::default(), Carol::default());
        let began = std::time::Instant::now();
        let first = std::sync::OnceLock::new();
        let until = |ms: u64| {
            let first: std::time::Instant = *first.get().expect("a dial");
            (first + Duration::from_millis(ms)).saturating_duration_since(std::time::Instant::now())
        };
        let carol_at = Mutex::new(Vec::new());
        let (dave_dials, bob_dials) = (Told::<usize>::default(), Told::<usize>::default());
        let (dave_ended, dave_noted) = (
            Told::<Option<Duration>>::default(),
            Told::<Option<Duration>>::default(),
        );
        let bob_again = Told::<Option<Duration>>::default();
        let kicked = Told::<bool>::default();
        LOOKS_FOR_TESTS.with(|looks| looks.set(0));
        pass_at_once(
            &fix,
            &shared,
            (Instant::now(), wall),
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| {
                first.get_or_init(std::time::Instant::now);
                match who {
                    "carol" => {
                        // Where Dave's turn was as she is asked: his dial
                        // not ended (None), ended but his entry still in
                        // `in_pass` (Some(false): the pass had not noted
                        // his end), or ended and his entry out of it
                        // (Some(true): it had, `Shared::end_fetch`).
                        let at = began.elapsed();
                        let dave = dave_ended
                            .get()
                            .map(|_| !lock_of(&shared).in_pass.contains_key(&fix.dave));
                        carol_at.lock().unwrap().push((at, dave));
                        carol.dial(frames)
                    }
                    "dave" => {
                        dave_dials.set(dave_dials.get() + 1);
                        std::thread::sleep(until(4300));
                        while !until(5200).is_zero() {
                            let mut s = lock_of(&shared);
                            if s.states.contains_key(&fix.carol)
                                && !s.in_pass.contains_key(&fix.carol)
                            {
                                s.kick(Instant::now());
                                kicked.set(true);
                                break;
                            }
                            drop(s);
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        std::thread::sleep(until(5400));
                        dave_ended.set(Some(began.elapsed()));
                        Err("custody dial deadline".to_string())
                    }
                    _ => {
                        bob_dials.set(bob_dials.get() + 1);
                        if bob_dials.get() == 1 {
                            return bob.dial(frames);
                        }
                        bob_again.set(Some(began.elapsed()));
                        // Whether, and when, this dial sees that the pass
                        // has noted Dave's end: his entry leaves `in_pass`
                        // as it does (`Shared::end_fetch`).
                        while !until(9800).is_zero() {
                            if dave_ended.get().is_some()
                                && !lock_of(&shared).in_pass.contains_key(&fix.dave)
                            {
                                dave_noted.set(Some(began.elapsed()));
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        std::thread::sleep(until(9800));
                        Err("custody dial deadline".to_string())
                    }
                }
            },
        );
        let first = *first.get().expect("a dial");
        OldPassRun {
            took: first.elapsed(),
            looks: LOOKS_FOR_TESTS.with(std::cell::Cell::get),
            dials: (dave_dials.get(), bob_dials.get()),
            again: bob_again.get(),
            setup: first.saturating_duration_since(began),
            kicked: kicked.get(),
            carol_at: carol_at.into_inner().unwrap(),
            ended: dave_ended.get().expect("Dave's dial ended"),
            noted: dave_noted.get(),
        }
    }

    /// ... and an old pass ends once its young turns have: friends that are
    /// there, whose turns overlap, do not keep it going between them. Carol
    /// and Bob each answer after 450 ms (Bob from 200 ms on: he is parked
    /// until then) and are due again by then (a fetch interval of 40 ms),
    /// so one of them is always out; Dave's dial is out for 1 s, past the
    /// backstop of 600 ms. Once his has ended no turn starts, and the pass
    /// ends when theirs do, about 1.3 s after its first dial. Were any turn
    /// out to keep it going, it would go on until they stop answering. The
    /// times run from the pass's first dial (their stop is 6 s after it),
    /// as a loaded machine can hold a pass's setup up by seconds (review
    /// mail-friends-8, 8.1). The bound (4 s) leaves room for a loaded
    /// machine: timed from the test's start, the pass took 1.3 to 1.9 s in
    /// 60 timed runs, and once 2.6 s (a stress run of three copies, a load
    /// average of about 50, read live), past the 2.5 s it had.
    #[test]
    fn f18_an_old_pass_ends_when_its_young_turns_have() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let _t = Times::set(40, 10, 600);
        let (fix, wall) = two_friends(true);
        fix.book_with(&[], &[fix.bob]);
        let shared: Mutex<Shared> = Mutex::default();
        let parked = (Instant::now() + Duration::from_millis(200), "TEST_PARK");
        lock_of(&shared).parked.insert(fix.bob, parked);
        let (carol, bob) = (Carol::default(), Carol::default());
        let first = std::sync::OnceLock::new();
        let first_dial = || *first.get_or_init(std::time::Instant::now);
        let slow = |side: &Carol, frames: &[Vec<u8>]| {
            let since = first_dial();
            std::thread::sleep(Duration::from_millis(450));
            if since.elapsed() > Duration::from_secs(6) {
                return Err("custody dial deadline".to_string());
            }
            side.dial(frames)
        };
        pass_at_once(
            &fix,
            &shared,
            (Instant::now(), wall),
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| match who {
                "carol" => slow(&carol, frames),
                "bob" => slow(&bob, frames),
                _ => {
                    first_dial();
                    std::thread::sleep(Duration::from_millis(1000));
                    Err("custody dial deadline".to_string())
                }
            },
        );
        let took = first.get().expect("a dial").elapsed();
        assert!(
            carol.count() >= 2 && bob.count() >= 1,
            "both were asked: {} {}",
            carol.count(),
            bob.count()
        );
        assert!(
            took < Duration::from_secs(4),
            "the pass ended with its young turns: {took:?}"
        );
    }

    /// Review mail-friends-4, finding 3: a custodian's first turn in a pass
    /// holds it too, when it starts once the pass is old. The pass is old
    /// after 1.2 s; Carol's fetch interval is 1 s. Bob is parked until
    /// 1.4 s, so his first turn starts once the pass is old. Dave's first
    /// turn is out until 1.5 s after the pass's first dial, and Bob's until
    /// 5.5 s after it. After Dave's turn, Carol is asked at her times while
    /// Bob's is out, and the pass ends with Bob's turn. Before, nothing
    /// held the pass once Dave's turn had ended: she waited for Bob's. The
    /// times run from the pass's first dial, as a loaded machine can hold a
    /// pass's setup up by seconds (review mail-friends-8, 8.1). Bob's turn
    /// is out long enough for Carol to be asked twice after Dave's although
    /// a loaded machine held her turn up to 1.8 s past her time (review
    /// mail-friends-8, 8.2: with Bob out 2.5 s past Dave's turn, a hold of
    /// about 1 s would leave her one); the pass may end up to 2 s after his
    /// turn, for the same reason.
    #[test]
    fn f18_a_late_first_turn_holds_an_old_pass() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let _t = Times::set(1000, 10, 1200);
        let (fix, wall) = two_friends(true);
        fix.book_with(&[], &[fix.bob]);
        let shared: Mutex<Shared> = Mutex::default();
        let parked = (Instant::now() + Duration::from_millis(1400), "TEST_PARK");
        lock_of(&shared).parked.insert(fix.bob, parked);
        let carol = Carol::default();
        let began = std::time::Instant::now();
        let first = std::sync::OnceLock::new();
        let until = |ms: u64| {
            let first: std::time::Instant = *first.get().expect("a dial");
            (first + Duration::from_millis(ms)).saturating_duration_since(std::time::Instant::now())
        };
        let carol_at = Mutex::new(Vec::new());
        let dave_ended = Told::<Option<Duration>>::default();
        let bob_out = Told::<Option<(Duration, Duration)>>::default();
        pass_at_once(
            &fix,
            &shared,
            (Instant::now(), wall),
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| {
                first.get_or_init(std::time::Instant::now);
                match who {
                    "carol" => {
                        carol_at.lock().unwrap().push(began.elapsed());
                        carol.dial(frames)
                    }
                    "dave" => {
                        std::thread::sleep(until(1500));
                        dave_ended.set(Some(began.elapsed()));
                        Err("custody dial deadline".to_string())
                    }
                    _ => {
                        let from = began.elapsed();
                        std::thread::sleep(until(5500));
                        bob_out.set(bob_out.get().or(Some((from, began.elapsed()))));
                        Err("custody dial deadline".to_string())
                    }
                }
            },
        );
        let took = began.elapsed();
        let at = carol_at.into_inner().unwrap();
        let ended = dave_ended.get().expect("Dave's dial ended");
        let (bob, bob_ended) = bob_out.get().expect("Bob was dialled");
        assert!(
            bob > Duration::from_millis(1200),
            "Bob's first turn started once the pass was old: {bob:?}"
        );
        assert!(
            at.iter().filter(|t| **t > ended && **t < bob_ended).count() >= 2,
            "Carol was asked at her times while Bob's turn was out (to {bob_ended:?}): {at:?}"
        );
        assert!(
            took < bob_ended + Duration::from_secs(2),
            "the pass ended with Bob's turn ({bob_ended:?}): {took:?}"
        );
    }

    /// ... and it holds the pass from the look it starts in. The pass is
    /// old after 0.9 s; Carol's fetch interval is 1 s. Once Carol's second
    /// turn has ended, Bob's park ends 20 ms later and Dave's first turn
    /// 60 ms later; the pass looks no sooner than 200 ms after the look at
    /// her turn's end, so it looks again when Dave's turn ends, and Bob's
    /// first turn starts in that look, with no turn out that holds the pass
    /// as the look begins. Carol is asked at her times while Bob's turn is
    /// out (4.5 s: long enough for two of her turns although a loaded
    /// machine held her turn up to 1.8 s past her time, and shorter than
    /// the 5 s a pass that looked only at turns' ends would sleep; review
    /// mail-friends-8, 8.2). Before (the stress run of this change found
    /// it, the pass having begun late), that look and its sleep went by the
    /// turns out as the look began: the pass slept until Bob's turn ended,
    /// and ended with it.
    #[test]
    fn f18_a_turn_holds_the_pass_from_the_look_it_starts_in() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let _t = Times::set(1000, 10, 900);
        let (fix, wall) = two_friends(true);
        fix.book_with(&[], &[fix.bob]);
        let shared: Mutex<Shared> = Mutex::default();
        let an_hour = (Instant::now() + Duration::from_secs(3_600), "TEST_PARK");
        lock_of(&shared).parked.insert(fix.bob, an_hour);
        let carol = Carol::default();
        let began = std::time::Instant::now();
        let carol_at = Mutex::new(Vec::new());
        let bob_out = Told::<Option<(Duration, Duration)>>::default();
        pass_at_once(
            &fix,
            &shared,
            (Instant::now(), wall),
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| match who {
                "carol" => {
                    carol_at.lock().unwrap().push(began.elapsed());
                    carol.dial(frames)
                }
                "dave" => {
                    wait_until(|| carol.count() >= 2 && turn_ended(&shared, &fix.carol));
                    let soon = (Instant::now() + Duration::from_millis(20), "TEST_PARK");
                    lock_of(&shared).parked.insert(fix.bob, soon);
                    std::thread::sleep(Duration::from_millis(60));
                    Err("custody dial deadline".to_string())
                }
                _ => {
                    let from = began.elapsed();
                    std::thread::sleep(Duration::from_millis(4500));
                    bob_out.set(Some((from, began.elapsed())));
                    Err("custody dial deadline".to_string())
                }
            },
        );
        let at = carol_at.into_inner().unwrap();
        let (from, to) = bob_out.get().expect("Bob was dialled");
        assert!(
            at.iter().filter(|t| **t > from && **t < to).count() >= 2,
            "Carol was asked at her times while Bob's turn was out ({from:?} to {to:?}): {at:?}"
        );
    }

    /// Review mail-friends-3 R1: a custodian has [`TURNS_IN_AN_INTERVAL`]
    /// turns in a fetch interval at most (here 5 s), not three in a pass.
    /// Carol answers at once; while Dave's dial is out (until 6 s after her
    /// first turn: a loaded machine may start the pass late) a kick comes
    /// 600 ms after each of her first three turns. The first two ask her
    /// again at once; the third finds her three turns in the interval, and
    /// she is asked when the first of them is an interval old, 5 s after
    /// the pass began at the soonest (not when the last is: that comes after
    /// Dave's turn, and the pass has ended), in the same pass. Until then
    /// the pass sleeps: she is due, but no reason to look every 200 ms
    /// (about 3 s of that would be some 15 looks more; with a 3 s interval
    /// the bound could not tell the two apart). Before, the kicks used up
    /// her three turns, and she was asked again only by the next pass.
    #[test]
    fn f18_a_custodian_has_three_turns_in_an_interval_at_most() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let _t = Times::set(5000, 10, 80_000);
        let (fix, wall) = two_friends(true);
        let shared: Mutex<Shared> = Mutex::default();
        let carol = Carol::default();
        let began = std::time::Instant::now();
        let carol_at = Mutex::new(Vec::new());
        let dave_dials = Told::<usize>::default();
        LOOKS_FOR_TESTS.with(|looks| looks.set(0));
        pass_at_once(
            &fix,
            &shared,
            (Instant::now(), wall),
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| {
                if who == "carol" {
                    carol_at.lock().unwrap().push(began.elapsed());
                    return carol.dial(frames);
                }
                dave_dials.set(dave_dials.get() + 1);
                if dave_dials.get() > 1 {
                    return Err("custody dial deadline".to_string());
                }
                for turns in 1..=3 {
                    wait_until(|| carol.count() >= turns && turn_ended(&shared, &fix.carol));
                    std::thread::sleep(Duration::from_millis(600));
                    lock_of(&shared).kick(Instant::now());
                }
                // Out until 6 s after her first turn began.
                let first = carol_at.lock().unwrap()[0];
                let out = (first + Duration::from_millis(6000)).saturating_sub(began.elapsed());
                std::thread::sleep(out);
                Err("custody dial deadline".to_string())
            },
        );
        let at = carol_at.into_inner().unwrap();
        let looks = LOOKS_FOR_TESTS.with(std::cell::Cell::get);
        assert_eq!(at.len(), 4, "three, and one an interval on: {at:?}");
        let ms = Duration::from_millis;
        // This takes about 1.4 s; the cuts that do not ask her at once make
        // it about 5 s (review mail-friends-8, 8.3).
        assert!(
            at[2] < at[0] + ms(4000),
            "the first two kicks asked her at once: {at:?}"
        );
        // Her first turn was planned after `began`, so the window opens 5 s
        // after `began` at the soonest, however late her first dial was
        // (review mail-friends-4, finding 8).
        assert!(
            at[3] >= ms(5000),
            "the fourth once the first was an interval old: {at:?}"
        );
        assert!(looks <= 14, "looks: {looks}");
    }

    /// A custodian's window ([`Keeper::free_at`]): free until it has had
    /// [`TURNS_IN_AN_INTERVAL`] turns that dialled it, then an interval
    /// after the first of its last three began, not after its first ever or
    /// its last. A turn that dialled nothing takes no place (review
    /// mail-friends-4, finding 2).
    #[test]
    fn f18_a_custodians_window_is_its_last_three_turns_that_dialled() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let interval = s(60);
        let mut k = Keeper::new(([0x6E; 32], Vec::new()));
        let mut free = Vec::new();
        for (at, dialled) in [
            (0, true),
            (1, false),
            (2, true),
            (3, true),
            (61, true),
            (62, false),
            (63, true),
        ] {
            let turn = turn_of([0x6E; 32], (t0 + s(at), 0), Vec::new(), BTreeMap::new());
            k.starts(&turn, true);
            k.ended(dialled);
            free.push(k.free_at(interval));
        }
        let at = |secs| Some(t0 + s(secs));
        assert_eq!(free, [None, None, None, at(60), at(62), at(62), at(63)]);
    }

    /// Review mail-friends-4, finding 2: a turn that dialled nothing takes
    /// no place in a custodian's window. Carol has no saved address at
    /// first, as a friend only Tor reaches has none before Tor can dial;
    /// while Dave's dial is out, a kick after each of her first three turns
    /// makes her due, and her address comes just before the third kick. Her
    /// fourth turn dials her at once: within 4 s of her first turn, not of
    /// the test's start, as a loaded machine can hold a pass's setup up by
    /// seconds (review mail-friends-8, 8.1). Before, her three turns with
    /// no route filled her window, and she was dialled only once the first
    /// of them was an interval old (here 10 s: that wait runs from when her
    /// first turn was planned, the bound from inside it, so with 6 s a
    /// first turn held up by 2 s would let a pass that wrongly waits for it
    /// through: review mail-friends-9, N3). The bound leaves room for a
    /// loaded machine: with an interval of 3 s and a bound of 2.5 s from
    /// the test's start, she was once dialled 2.62 s on (a stress run, at a
    /// load average of 220 to 350, read live).
    #[test]
    fn f18_a_turn_that_dialled_nothing_takes_no_place_in_the_window() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let _t = Times::set(10_000, 10, 80_000);
        let (fix, wall) = two_friends(true);
        fix.carol_has_no_address();
        let shared: Mutex<Shared> = Mutex::default();
        let carol = Carol::default();
        let carol_turns = Arc::new(Told::<usize>::default());
        let first_turn = Arc::new(Told::<Option<std::time::Instant>>::default());
        let found: RoutesFound = {
            let (turns, first, carol) =
                (Arc::clone(&carol_turns), Arc::clone(&first_turn), fix.carol);
            Arc::new(move |c: &[u8; 32]| {
                if *c == carol {
                    turns.set(turns.get() + 1);
                    first.set(first.get().or(Some(std::time::Instant::now())));
                }
            })
        };
        TURN_GATES.with(|gates| {
            gates.borrow_mut().push(Arc::new(move || {
                ROUTES_FOUND_FOR_TESTS.with(|f| *f.borrow_mut() = Some(Arc::clone(&found)));
            }));
        });
        let dialled_at = Told::<Option<std::time::Instant>>::default();
        let dave_dials = Told::<usize>::default();
        pass_at_once(
            &fix,
            &shared,
            (Instant::now(), wall),
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| {
                if who == "carol" {
                    dialled_at.set(dialled_at.get().or(Some(std::time::Instant::now())));
                    return carol.dial(frames);
                }
                dave_dials.set(dave_dials.get() + 1);
                if dave_dials.get() > 1 {
                    return Err("custody dial deadline".to_string());
                }
                for turns in 1..=3 {
                    wait_until(|| carol_turns.get() >= turns && turn_ended(&shared, &fix.carol));
                    if turns == 3 {
                        fix.book(&[]);
                    }
                    lock_of(&shared).kick(Instant::now());
                }
                wait_until(|| dialled_at.get().is_some());
                Err("custody dial deadline".to_string())
            },
        );
        let dialled = dialled_at.get().expect("Carol was dialled");
        let first = first_turn.get().expect("Carol had a turn");
        let at = dialled.saturating_duration_since(first);
        assert!(carol_turns.get() >= 4, "{}", carol_turns.get());
        assert!(
            at < Duration::from_secs(4),
            "dialled at once, not when her window opened: {at:?} after her first turn"
        );
    }

    /// Review mail-friends-2 L3: a ring starts the turn of the custodian it
    /// rang for at once, not at a later look: the pass's clock is never
    /// behind the one the kick made it due by. Here the pass's setup took
    /// three seconds (its time is three seconds old when it starts), as it
    /// may on a phone with a cold store: a clock behind by that found Carol
    /// not due yet at the ring, and asked her three seconds later. Carol
    /// answers and rests 50 ms; Dave's dial is out; a kick past her rest
    /// makes her due, and she is dialled again within two seconds. Her
    /// dials are timed where they happen: her whole turn can be shorter
    /// than a look at the schedule from another thread. The bound leaves
    /// room for a loaded machine: with a second's setup and a bound of
    /// 500 ms, she was once dialled 553 ms after the ring (a stress run, at
    /// a load average of 220 to 350, read live).
    #[test]
    fn f18_a_ring_starts_the_turn_it_rang_for_at_once() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let _t = Times::set(60_000, 50, 80_000);
        let (fix, wall) = two_friends(true);
        let shared: Mutex<Shared> = Mutex::default();
        let carol = Carol::default();
        let carol_at = Mutex::new(Vec::new());
        let rang = Told::<Option<std::time::Instant>>::default();
        let dave_dials = Told::<usize>::default();
        let setup = Duration::from_secs(3);
        pass_at_once(
            &fix,
            &shared,
            (Instant::now() - setup, wall - 3000),
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| {
                if who == "carol" {
                    carol_at.lock().unwrap().push(std::time::Instant::now());
                    return carol.dial(frames);
                }
                dave_dials.set(dave_dials.get() + 1);
                if dave_dials.get() > 1 {
                    return Err("custody dial deadline".to_string());
                }
                wait_until(|| turn_ended(&shared, &fix.carol));
                std::thread::sleep(Duration::from_millis(150));
                rang.set(Some(std::time::Instant::now()));
                lock_of(&shared).kick(Instant::now());
                wait_until(|| carol.count() >= 2 && turn_ended(&shared, &fix.carol));
                Err("custody dial deadline".to_string())
            },
        );
        let at = carol_at.into_inner().unwrap();
        assert_eq!(at.len(), 2, "once, and once after the ring: {at:?}");
        let rang = rang.get().expect("the kick came");
        let took = at[1].saturating_duration_since(rang);
        assert!(
            took < Duration::from_secs(2),
            "dialled {took:?} after the ring"
        );
    }

    /// Review mail-friends-1, finding 3: in a mail check whose time is up,
    /// a turn none of whose dials went out was no round. Dave counts no
    /// failure, has no not-reached line and is due again on his interval,
    /// as one with no route (review mail-friends-3 R3: he was due at once,
    /// and a node that runs on after the check dialled him the moment it
    /// ended, with no budget); Carol, whose dial went out, answered. So is
    /// one whose dials the budget cut before any answered (review
    /// mail-friends-2 N2): a beacon find of his that refused, then his
    /// saved route cut on its way. Once the budget has cut a dial of his
    /// turn nothing more of it goes out: his find cut, his saved route is
    /// not dialled. A kick during a turn the budget cut makes him due a
    /// base interval on, not at once (review mail-friends-4, finding 1: the
    /// check's own kick reaches the turns of a pass that began before it,
    /// and made him due at once; [`Woken::After`]). A dial that did go
    /// out, had its time and failed is a failure, with its line: the
    /// keeper's tag, the carrier and the wait from now.
    #[test]
    fn f18_a_turn_the_check_never_let_out_is_no_round() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let refused = "lan connect: cannot connect (Connection refused)";
        let stale = "192.168.1.98:47533";
        for (find, find_says, dave_says, kick, waits, dials) in [
            (None, refused, MAIL_CHECK_BUDGET, false, None, 1),
            (Some(stale), refused, MAIL_CHECK_BUDGET, false, None, 2),
            // His find cut: his saved route is not dialled.
            (Some(stale), MAIL_CHECK_BUDGET, refused, false, None, 1),
            // A kick came during his turn, which the check cut: due a base
            // interval on (with no empty rounds, as on his interval), not at
            // once.
            (None, refused, MAIL_CHECK_BUDGET, true, None, 1),
            // The idle wait from now: his interval, less what the pass took
            // after his turn ended (in a stress run at a load average of 240
            // to 370, read live, more than 2 s once: 57 s).
            (None, refused, refused, false, Some(50..=60), 1),
            // A kick came during his turn, which reached nothing: he is due
            // again at once, and the line says so.
            (None, refused, refused, true, Some(0..=0), 1),
        ] {
            let (fix, wall) = two_friends(true);
            let shared: Mutex<Shared> = Mutex::default();
            let carol = Carol::default();
            let finds = |c: &[u8; 32]| {
                find.filter(|_| *c == fix.dave)
                    .map(|find| vec![find.to_string()])
                    .unwrap_or_default()
            };
            let dave_dials = Told::<usize>::default();
            not_reached_lines();
            pass_at_once(
                &fix,
                &shared,
                (Instant::now(), wall),
                ASKED_AT_ONCE,
                &finds,
                &forget_nothing,
                &|who, route, frames| {
                    if who == "carol" {
                        return carol.dial(frames);
                    }
                    dave_dials.set(dave_dials.get() + 1);
                    if Some(route.dial.as_str()) == find {
                        return Err(find_says.to_string());
                    }
                    if kick {
                        lock_of(&shared).kick(Instant::now());
                    }
                    Err(dave_says.to_string())
                },
            );
            let lines = not_reached_lines();
            let s = lock_of(&shared);
            assert!(!s.failures.contains_key(&fix.carol) && carol.count() == 1);
            assert!(
                kick || s.states[&fix.carol].1 > Instant::now(),
                "Carol answered"
            );
            assert_eq!(dave_dials.get(), dials, "{find:?} {find_says}");
            let Some(waits) = waits else {
                assert_eq!(s.failures.get(&fix.dave), None, "no failure");
                assert!(lines.is_empty(), "no line: {lines:?}");
                assert!(
                    s.states[&fix.dave].1 > Instant::now() + Duration::from_secs(50),
                    "due again on his interval"
                );
                continue;
            };
            assert_eq!(s.failures.get(&fix.dave), Some(&1));
            let tag = crate::netutil::link_tag(&fix.dave);
            let lan = OutboxCarrier::Lan.label();
            let line = format!("contact {tag} not reached for mail ({lan}); due again in ");
            assert_eq!(lines.len(), 1, "{lines:?}");
            let wait = lines[0]
                .strip_prefix(&line)
                .and_then(|wait| wait.strip_suffix(" s"))
                .and_then(|wait| wait.parse::<u64>().ok());
            assert!(wait.is_some_and(|wait| waits.contains(&wait)), "{lines:?}");
            assert_eq!(s.states[&fix.dave].1 <= Instant::now(), kick, "due at once");
        }
    }

    /// ... and once the check's time is up no turn starts at all: nothing
    /// is dialled and no schedule changes, whether the pass asks its mail
    /// friends at the same time or one after the other. A budget spent
    /// while a dial is out lets no turn start after it: the kick that comes
    /// then asks nobody.
    #[test]
    fn f18_no_turn_starts_once_the_checks_time_is_up() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let _t = Times::set(60_000, 50, 80_000);
        for at_once in [ASKED_AT_ONCE, 1] {
            let (fix, wall) = two_friends(true);
            let shared: Mutex<Shared> = Mutex::default();
            let dials = Mutex::new(0usize);
            let spent = || Some(Duration::ZERO);
            pass_at_once_in(
                &fix,
                &shared,
                (Instant::now(), wall),
                at_once,
                (&no_finds, &forget_nothing),
                &|_, _, _| {
                    *dials.lock().unwrap() += 1;
                    Err(MAIL_CHECK_BUDGET.to_string())
                },
                &spent,
            );
            assert_eq!(*dials.lock().unwrap(), 0, "at_once {at_once}");
            let s = lock_of(&shared);
            assert!(
                s.states.is_empty() && s.in_pass.is_empty(),
                "at_once {at_once}"
            );
        }
        // Spent while Dave's dial is out.
        let (fix, wall) = two_friends(true);
        let shared: Mutex<Shared> = Mutex::default();
        let carol = Carol::default();
        let up = Told::<bool>::default();
        let budget = || Some(if up.get() { Duration::ZERO } else { LATER });
        pass_at_once_in(
            &fix,
            &shared,
            (Instant::now(), wall),
            ASKED_AT_ONCE,
            (&no_finds, &forget_nothing),
            &|who, _, frames| {
                if who == "carol" {
                    return carol.dial(frames);
                }
                wait_until(|| turn_ended(&shared, &fix.carol));
                up.set(true);
                lock_of(&shared).kick(Instant::now());
                std::thread::sleep(Duration::from_millis(400));
                Err("custody dial deadline".to_string())
            },
            &budget,
        );
        assert_eq!(carol.count(), 1, "not asked again once the time was up");
    }

    /// Review mail-friends-3 R3: once the check's time is up no dial of a
    /// turn goes out either, not only no turn. Dave's beacon find refuses,
    /// and meanwhile (Carol's turn over) the time is up: his saved route is
    /// not dialled. Nothing was asked there: no failure, no line, due again
    /// on his interval.
    #[test]
    fn f18_no_dial_goes_out_once_the_checks_time_is_up() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let (fix, wall) = two_friends(true);
        let shared: Mutex<Shared> = Mutex::default();
        let carol = Carol::default();
        let stale = "192.168.1.98:47533";
        let finds = |c: &[u8; 32]| {
            if *c == fix.dave {
                vec![stale.to_string()]
            } else {
                Vec::new()
            }
        };
        let up = Told::<bool>::default();
        let budget = || Some(if up.get() { Duration::ZERO } else { LATER });
        let dave_dials = Told::<usize>::default();
        not_reached_lines();
        pass_at_once_in(
            &fix,
            &shared,
            (Instant::now(), wall),
            ASKED_AT_ONCE,
            (&finds, &forget_nothing),
            &|who, _, frames| {
                if who == "carol" {
                    return carol.dial(frames);
                }
                dave_dials.set(dave_dials.get() + 1);
                wait_until(|| turn_ended(&shared, &fix.carol));
                up.set(true);
                Err("lan connect: cannot connect (Connection refused)".to_string())
            },
            &budget,
        );
        let lines = not_reached_lines();
        let s = lock_of(&shared);
        assert_eq!(dave_dials.get(), 1, "his saved route was not dialled");
        assert_eq!(carol.count(), 1);
        assert_eq!(s.failures.get(&fix.dave), None, "no failure");
        assert!(lines.is_empty(), "no line: {lines:?}");
        assert!(
            s.states[&fix.dave].1 > Instant::now() + Duration::from_secs(50),
            "due again on his interval"
        );
    }

    /// A check sets `until` (`None`: it lets go) on this test thread, as
    /// [`set_pass_deadline`] does in the process ([`CheckDeadline::record`]).
    fn set_check_deadline(until: Option<std::time::Instant>) {
        CHECK_DEADLINE_FOR_TESTS.with(|d| {
            let mut deadline = d.get().unwrap_or_default();
            deadline.record(until);
            d.set(Some(deadline));
        });
    }

    /// Review mail-friends-3 R3, mail-friends-4, finding 1, and
    /// mail-friends-5, finding A: a pass keeps the earliest check deadline
    /// it has seen ([`CheckBudget`]), to its end. The check lets go of it
    /// when its wait for the pass ends, and the pass may still be at work
    /// then: it has no more time than the check gave it. A later deadline
    /// does not lengthen it, an earlier one shortens it for good, and a pass
    /// that began before the check keeps its deadline once it has seen it,
    /// or once the check let go if it had begun when the check set it. The
    /// passes begin as the fetcher's do, and are told apart by the passes
    /// begun before them (review mail-friends-6, finding 1: one too few or
    /// too many, as a pass counts itself or as a check counts, and the pass
    /// at work keeps nothing, or the next one a spent deadline).
    #[test]
    fn f18_a_pass_keeps_the_earliest_check_deadline_it_sees() {
        let _passes = passes_for_tests();
        let set = set_check_deadline;
        let secs = Duration::from_secs;
        let now = std::time::Instant::now();
        // No more than `most` from the start, and no less than is left of it
        // when it is looked at, however late that is on a loaded machine.
        let within = |left: Option<Duration>, most: u64| {
            let still = secs(most).saturating_sub(now.elapsed());
            left.is_some_and(|left| left >= still && left <= secs(most))
        };
        set(Some(now + secs(30)));
        // The pass the check waits for.
        pass_begun_for_tests();
        let pass = CheckBudget::begin();
        set(None);
        assert!(within(pass.left(), 30), "kept: {:?}", pass.left());
        set(Some(now + secs(90)));
        assert!(within(pass.left(), 30), "not lengthened: {:?}", pass.left());
        set(Some(now + secs(10)));
        assert!(within(pass.left(), 10), "the earlier: {:?}", pass.left());
        set(None);
        assert!(
            within(pass.left(), 10),
            "kept, the earliest: {:?}",
            pass.left()
        );
        // One that began with no check runs has no bound until one begins,
        // and keeps that one's once it has seen it, after the check let go.
        pass_begun_for_tests();
        let before = CheckBudget::begin();
        assert_eq!(before.left(), None);
        set(Some(now + secs(20)));
        assert!(within(before.left(), 20), "{:?}", before.left());
        set(None);
        assert!(
            within(before.left(), 20),
            "kept once seen: {:?}",
            before.left()
        );
        // One at work while a check set its deadline and let go of it,
        // which saw nothing of it meanwhile (its dial was out), keeps it
        // all the same; the next one, which began after the check let go,
        // keeps nothing.
        pass_begun_for_tests();
        let unseen = CheckBudget::begin();
        assert_eq!(unseen.left(), None);
        set(Some(now + secs(15)));
        set(None);
        assert!(
            within(unseen.left(), 15),
            "kept, unseen: {:?}",
            unseen.left()
        );
        pass_begun_for_tests();
        assert_eq!(CheckBudget::begin().left(), None, "began after");
        // The deadline it kept has passed: spent.
        let spent = CheckBudget {
            number: 0,
            kept: Mutex::new(Some(now)),
        };
        assert_eq!(spent.left(), Some(Duration::ZERO));
        CHECK_DEADLINE_FOR_TESTS.with(|d| d.set(None));
    }

    /// Review mail-friends-5, finding A and nit G: a pass that asks one
    /// custodian at a time (as with one mail friend) keeps a check's
    /// deadline that was set and let go while its dial was out, though it
    /// looked at nothing meanwhile; and each of its dials has what is left
    /// of its budget, as the node's passes hand it on ([`within_check`]).
    /// Before, such a pass saw nothing of that check, and the custodian's
    /// next route went out with its usual deadline. A first check runs as
    /// the pass begins (60 s left): Dave's find is dialled with that much
    /// left; during that dial a second check begins and ends, and its
    /// deadline (50 ms on) passes. His saved route does not go out, and
    /// Carol's turn does not start: her schedule is as it was.
    #[test]
    fn f18_a_pass_keeps_a_check_deadline_set_and_let_go_during_its_dial() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let _passes = passes_for_tests();
        let stale = "192.168.1.98:47533";
        let (fix, wall) = two_friends(true);
        let shared: Mutex<Shared> = Mutex::default();
        let finds = |c: &[u8; 32]| {
            if *c == fix.dave {
                vec![stale.to_string()]
            } else {
                Vec::new()
            }
        };
        let first = std::time::Instant::now() + Duration::from_secs(60);
        set_check_deadline(Some(first));
        // The pass the first check waits for.
        pass_begun_for_tests();
        let dials = Mutex::new(Vec::new());
        pass_within_check(
            &fix,
            &shared,
            (Instant::now(), wall),
            1,
            &finds,
            &|who, route, _, left| {
                // What is left of the first check's time as the dial begins,
                // however late that is on a loaded machine.
                let still = first.saturating_duration_since(std::time::Instant::now());
                dials
                    .lock()
                    .unwrap()
                    .push((who, route.dial.clone(), left, still));
                let soon = std::time::Instant::now() + Duration::from_millis(50);
                set_check_deadline(Some(soon));
                std::thread::sleep(Duration::from_millis(100));
                set_check_deadline(None);
                Err("lan connect: cannot connect (Connection refused)".to_string())
            },
        );
        CHECK_DEADLINE_FOR_TESTS.with(|d| d.set(None));
        let dials = dials.into_inner().unwrap();
        assert_eq!(dials.len(), 1, "Dave's find only: {dials:?}");
        let (who, route, left, still) = &dials[0];
        assert_eq!((*who, route.as_str()), ("dave", stale));
        assert!(
            left.is_some_and(|left| left >= *still && left <= Duration::from_secs(60)),
            "the first check's budget: {left:?}"
        );
        let s = lock_of(&shared);
        assert!(s.states.contains_key(&fix.dave), "his turn ended");
        assert!(
            !s.states.contains_key(&fix.carol) && !s.in_pass.contains_key(&fix.carol),
            "no turn of Carol's"
        );
    }

    /// Review mail-friends-8, 8.6: each dial has what is left of the pass's
    /// budget as the dial begins ([`within_check`]), not what was left as
    /// the pass began. A first check runs as the pass begins (60 s left):
    /// Dave's find is dialled with that much left; during that dial a
    /// second check sets a deadline 10 s on, and keeps it. His saved route
    /// and Carol's turn then go out with no more than 10 s. A pass that
    /// read its budget once, as it began, would give them about 60 s, more
    /// than the second check left them. The pass asks one custodian at a
    /// time, so the later dials begin after the second check set its
    /// deadline.
    #[test]
    fn f18_each_dial_has_what_is_left_of_its_budget_as_it_begins() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let _passes = passes_for_tests();
        let stale = "192.168.1.98:47533";
        let (fix, wall) = two_friends(true);
        let shared: Mutex<Shared> = Mutex::default();
        let finds = |c: &[u8; 32]| {
            if *c == fix.dave {
                vec![stale.to_string()]
            } else {
                Vec::new()
            }
        };
        let secs = Duration::from_secs;
        let first = std::time::Instant::now() + secs(60);
        set_check_deadline(Some(first));
        // The pass the first check waits for.
        pass_begun_for_tests();
        let second = Told::<Option<std::time::Instant>>::default();
        let dials = Mutex::new(Vec::new());
        pass_within_check(
            &fix,
            &shared,
            (Instant::now(), wall),
            1,
            &finds,
            &|who, route, _, left| {
                // What is left of each check's time as the dial begins,
                // however late that is on a loaded machine.
                let now = std::time::Instant::now();
                let still = |until: std::time::Instant| until.saturating_duration_since(now);
                let dial = (who, route.dial.clone(), left);
                dials
                    .lock()
                    .unwrap()
                    .push((dial, still(first), second.get().map(still)));
                if second.get().is_none() {
                    let until = std::time::Instant::now() + secs(10);
                    second.set(Some(until));
                    set_check_deadline(Some(until));
                }
                Err("lan connect: cannot connect (Connection refused)".to_string())
            },
        );
        CHECK_DEADLINE_FOR_TESTS.with(|d| d.set(None));
        let dials = dials.into_inner().unwrap();
        let ((who, route, left), still, _) = &dials[0];
        assert_eq!((*who, route.as_str()), ("dave", stale), "{dials:?}");
        assert!(
            left.is_some_and(|left| left >= *still && left <= secs(60)),
            "the first check's budget: {dials:?}"
        );
        assert!(dials.len() >= 3, "his saved route and Carol's: {dials:?}");
        assert!(
            dials[1..].iter().all(|((_, _, left), _, still)| {
                still.is_some_and(|still| left.is_some_and(|l| l >= still && l <= secs(10)))
            }),
            "what was left of the second check's time as each began: {dials:?}"
        );
    }

    /// Review mail-friends-5, finding B: a wake during a turn a mail
    /// check's budget cut (here a kick) makes the custodian due a base
    /// interval on, its empty rounds forgotten (a wake forgets those of one
    /// whose turn is not out, and makes it due at once); with no wake it
    /// keeps its own next time. Dave has had seven empty rounds, so his own
    /// next time is 10 minutes on. Before, a cut turn kept it whatever came
    /// during it.
    #[test]
    fn f18_a_wake_during_a_cut_turn_makes_it_due_a_base_interval_on() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        for kick in [true, false] {
            let (fix, wall) = two_friends(true);
            let shared: Mutex<Shared> = Mutex::default();
            let now = Instant::now();
            lock_of(&shared)
                .states
                .insert(fix.dave, (FetchState::default(), now, 7));
            let carol = Carol::default();
            pass_at_once(
                &fix,
                &shared,
                (now, wall),
                ASKED_AT_ONCE,
                &no_finds,
                &forget_nothing,
                &|who, _, frames| {
                    if who == "carol" {
                        return carol.dial(frames);
                    }
                    if kick {
                        lock_of(&shared).kick(Instant::now());
                    }
                    Err(MAIL_CHECK_BUDGET.to_string())
                },
            );
            let s = lock_of(&shared);
            let (_, due, empty) = s.states[&fix.dave];
            let after = due.saturating_duration_since(Instant::now());
            if kick {
                assert_eq!(empty, 0, "his empty rounds forgotten");
                assert!(
                    after > Duration::from_secs(50) && after <= BASE_INTERVAL,
                    "a base interval on: {after:?}"
                );
            } else {
                assert_eq!(empty, 7, "his empty rounds stay");
                assert!(
                    after > Duration::from_secs(500),
                    "his own next time: {after:?}"
                );
            }
        }
    }

    /// Review mail-friends-3 n1: the pass's first look too is at its clock,
    /// never behind this device's. Here its setup took a second, and Carol
    /// came due meanwhile (half a second ago: a kick during the setup);
    /// Dave is due in an hour. She is asked in this pass. Before, the first
    /// look, at the pass's own time, found her not due yet; no turn was
    /// out, so nobody was asked and the pass ended.
    #[test]
    fn f18_the_first_look_is_at_the_passs_clock() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let (fix, wall) = two_friends(true);
        let shared: Mutex<Shared> = Mutex::default();
        let carol = Carol::default();
        let real = Instant::now();
        {
            let mut s = lock_of(&shared);
            let carol_due = real - Duration::from_millis(500);
            s.states
                .insert(fix.carol, (FetchState::default(), carol_due, 0));
            s.states
                .insert(fix.dave, (FetchState::default(), real + LATER, 0));
        }
        let dave_dials = Told::<usize>::default();
        pass_at_once(
            &fix,
            &shared,
            (real - Duration::from_secs(1), wall - 1000),
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| {
                if who == "carol" {
                    return carol.dial(frames);
                }
                dave_dials.set(dave_dials.get() + 1);
                Err("custody dial deadline".to_string())
            },
        );
        assert_eq!((carol.count(), dave_dials.get()), (1, 0), "Carol only");
    }

    /// Review mail-friends-1, finding 8: no turn starts after one panicked.
    /// Bob (Dave lists him), Carol and Dave are due; Carol answers; Dave's
    /// turn panics while Bob's dial is out, and a kick makes Carol due
    /// again (after her rest, 3 s: a panic hook that writes a backtrace may
    /// take a while): she is not asked again, and the panic ends the pass
    /// once Bob's turn has ended and been noted.
    #[test]
    fn f18_no_turn_starts_after_one_panicked() {
        if !rig::lab_backends() {
            return;
        }
        let (ended, end) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _g = Gates::on(true, true);
            let _t = Times::set(60_000, 3000, 80_000);
            let (fix, wall) = two_friends(true);
            fix.book_with(&[], &[fix.bob]);
            let shared = Mutex::default();
            let (carol, bob) = (Carol::default(), Carol::default());
            let pass = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pass_at_once(
                    &fix,
                    &shared,
                    (Instant::now(), wall),
                    ASKED_AT_ONCE,
                    &no_finds,
                    &forget_nothing,
                    &|who, _, frames| match who {
                        "carol" => carol.dial(frames),
                        "bob" => {
                            wait_until(|| turn_ended(&shared, &fix.carol));
                            lock_of(&shared).kick(Instant::now());
                            std::thread::sleep(Duration::from_millis(3500));
                            bob.dial(frames)
                        }
                        _ => {
                            wait_until(|| turn_ended(&shared, &fix.carol));
                            panic!("a fault in Dave's turn");
                        }
                    },
                );
            }));
            let bob_noted = turn_ended(&shared, &fix.bob);
            let _ = ended.send((pass.is_err(), carol.count(), bob_noted));
        });
        let (panicked, carol_dials, bob_noted) = end
            .recv_timeout(Duration::from_secs(30))
            .expect("the pass ended");
        assert!(panicked, "the panic ends the pass");
        assert_eq!(carol_dials, 1, "nobody asked after the panic");
        assert!(bob_noted, "Bob's turn was noted first");
    }

    /// Review mail-friends-2 N1: so does a panic on the pass's own thread.
    /// One thread is to be had: Dave's turn (he leads) gets it; Carol's
    /// runs on the pass's thread and panics while Dave's dial is out. The
    /// panic ends the pass once Dave's turn has ended and been noted: his
    /// next time is back in the schedule.
    #[test]
    fn f18_a_fault_on_the_pass_thread_still_notes_the_turns_that_are_out() {
        if !rig::lab_backends() {
            return;
        }
        let (ended, end) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _g = Gates::on(true, true);
            let (fix, wall) = two_friends(true);
            let shared = Mutex::default();
            let dave = Carol::default();
            let faulted = Told::<bool>::default();
            TURN_THREADS_FOR_TESTS.with(|left| left.set(Some(1)));
            let pass = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pass_at_once(
                    &fix,
                    &shared,
                    (Instant::now(), wall),
                    ASKED_AT_ONCE,
                    &no_finds,
                    &forget_nothing,
                    &|who, _, frames| {
                        if who == "carol" {
                            faulted.set(true);
                            panic!("a fault in Carol's turn, on the pass's thread");
                        }
                        wait_until(|| faulted.get());
                        std::thread::sleep(Duration::from_millis(300));
                        dave.dial(frames)
                    },
                );
            }));
            TURN_THREADS_FOR_TESTS.with(|left| left.set(None));
            let dave_noted = turn_ended(&shared, &fix.dave);
            let _ = ended.send((pass.is_err(), faulted.get(), dave.count(), dave_noted));
        });
        let (panicked, faulted, dave_dials, dave_noted) = end
            .recv_timeout(Duration::from_secs(30))
            .expect("the pass ended");
        assert!(panicked && faulted, "Carol's panic ends the pass");
        assert_eq!(dave_dials, 1);
        assert!(dave_noted, "Dave's turn was noted first");
    }

    /// ... and a second fault, in noting one of those turns, leaves the
    /// others noted: the first fault goes on once they all are. Two threads
    /// are to be had: Dave's and Bob's turns get them; Carol's (last: she
    /// was not reached last time) runs on the pass's thread, where on her
    /// way out she leaves the not-reached lines held, so noting Dave's
    /// failed turn panics too. Bob's turn ends after Dave's, and is noted.
    #[test]
    fn f18_a_second_fault_in_noting_leaves_the_other_turns_noted() {
        if !rig::lab_backends() {
            return;
        }
        let (ended, end) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _g = Gates::on(true, true);
            let (fix, wall) = two_friends(true);
            fix.book_with(&[], &[fix.bob]);
            let shared: Mutex<Shared> = Mutex::default();
            lock_of(&shared).failures.insert(fix.carol, 1);
            let bob = Carol::default();
            let (faulted, dave_dials) = (Told::<bool>::default(), Told::<usize>::default());
            TURN_THREADS_FOR_TESTS.with(|left| left.set(Some(2)));
            let pass = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pass_at_once(
                    &fix,
                    &shared,
                    (Instant::now(), wall),
                    ASKED_AT_ONCE,
                    &no_finds,
                    &forget_nothing,
                    &|who, _, frames| match who {
                        "carol" => {
                            NOT_REACHED_FOR_TESTS.with(|lines| std::mem::forget(lines.borrow()));
                            faulted.set(true);
                            panic!("a fault in Carol's turn, on the pass's thread");
                        }
                        "dave" => {
                            dave_dials.set(dave_dials.get() + 1);
                            wait_until(|| faulted.get());
                            Err("custody dial deadline".to_string())
                        }
                        _ => {
                            wait_until(|| faulted.get());
                            std::thread::sleep(Duration::from_millis(300));
                            bob.dial(frames)
                        }
                    },
                );
            }));
            TURN_THREADS_FOR_TESTS.with(|left| left.set(None));
            let noted = (
                turn_ended(&shared, &fix.dave),
                turn_ended(&shared, &fix.bob),
            );
            let dials = (dave_dials.get(), bob.count());
            let _ = ended.send((pass.is_err(), faulted.get(), dials, noted));
        });
        let (panicked, faulted, dials, (dave_noted, bob_noted)) = end
            .recv_timeout(Duration::from_secs(30))
            .expect("the pass ended");
        assert!(panicked && faulted, "Carol's panic ends the pass");
        assert_eq!(dials, (1, 1), "Dave and Bob once each");
        assert!(
            dave_noted,
            "Dave's end was back in the schedule before it panicked"
        );
        assert!(bob_noted, "Bob's turn was noted after the second fault");
    }

    /// Where a custodian can be dialled is looked up before its turn takes
    /// the work: a lookup that takes a while (a saved name that does not
    /// resolve: up to 5 s) holds no other turn up. Dave's lookup waits here
    /// until Carol's whole turn has ended.
    #[test]
    fn f18_a_turns_route_lookup_holds_no_other_turn_up() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let (fix, wall) = two_friends(true);
        let shared: Arc<Mutex<Shared>> = Arc::default();
        let carol_done = Arc::new(Told::<Option<bool>>::default());
        let found: RoutesFound = {
            let (shared, carol_done, carol, dave) = (
                Arc::clone(&shared),
                Arc::clone(&carol_done),
                fix.carol,
                fix.dave,
            );
            Arc::new(move |c: &[u8; 32]| {
                if *c == dave {
                    carol_done.set(Some(wait_until(|| turn_ended(&shared, &carol))));
                }
            })
        };
        TURN_GATES.with(|gates| {
            gates.borrow_mut().push(Arc::new(move || {
                ROUTES_FOUND_FOR_TESTS.with(|f| *f.borrow_mut() = Some(Arc::clone(&found)));
            }));
        });
        let answers = Carol::default();
        pass_at_once(
            &fix,
            &shared,
            (Instant::now(), wall),
            ASKED_AT_ONCE,
            &no_finds,
            &forget_nothing,
            &|_, _, frames| answers.dial(frames),
        );
        assert_eq!(carol_done.get(), Some(true), "Carol's turn ended meanwhile");
        assert!(turn_ended(&shared, &fix.dave));
    }

    /// Review mail-friends-1, finding 4: a turn is worked out when its
    /// place frees, not when it is found due, so what the schedule says
    /// then is what counts. Bob (Dave lists him), Carol and Dave are due,
    /// two asked at the same time; while the first two dials are out the
    /// third one is parked (as the deposits' strikes park a custodian): it
    /// is not asked in this pass.
    #[test]
    fn f18_a_turn_is_worked_out_when_its_place_frees() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let (fix, wall) = two_friends(true);
        fix.book_with(&[], &[fix.bob]);
        let shared: Mutex<Shared> = Mutex::default();
        let answers = Carol::default();
        let out = DialsOut::default();
        let dialled = Mutex::new(Vec::new());
        let together = Told::<bool>::default();
        let keys = [("bob", fix.bob), ("carol", fix.carol), ("dave", fix.dave)];
        pass_at_once(
            &fix,
            &shared,
            (Instant::now(), wall),
            2,
            &no_finds,
            &forget_nothing,
            &|who, _, frames| {
                dialled.lock().unwrap().push(who);
                if out.begin(2, Duration::from_secs(5)) {
                    together.set(true);
                }
                {
                    let seen = dialled.lock().unwrap();
                    let mut s = lock_of(&shared);
                    for (name, key) in keys {
                        if !seen.contains(&name) {
                            s.parked.insert(key, (Instant::now() + LATER, "TEST_PARK"));
                        }
                    }
                }
                let got = answers.dial(frames);
                out.end();
                got
            },
        );
        assert!(together.get(), "the first two were asked at the same time");
        let dialled = dialled.into_inner().unwrap();
        assert_eq!(
            dialled.len(),
            2,
            "the third was parked when its place freed: {dialled:?}"
        );
        let s = lock_of(&shared);
        assert!(s.in_pass.is_empty() && s.failures.is_empty());
    }

    /// Review mail-friends-1, finding 7: whatever a turn's thread runs
    /// into, its end reaches the pass: entering the pass's runtime (and in
    /// tests the gates) is inside the catch too. Every turn's thread panics
    /// there (a gate of this test): the pass ends with that panic, instead
    /// of waiting for ends that never come.
    #[test]
    fn f18_a_turns_thread_that_fails_before_its_turn_still_ends_the_pass() {
        if !rig::lab_backends() {
            return;
        }
        let (ended, end) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _g = Gates::on(true, true);
            TURN_GATES.with(|gates| {
                gates
                    .borrow_mut()
                    .push(Arc::new(|| panic!("a fault entering a turn's thread")));
            });
            let (fix, wall) = two_friends(true);
            let shared = Mutex::default();
            let answers = Carol::default();
            let pass = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pass_at_once(
                    &fix,
                    &shared,
                    (Instant::now(), wall),
                    ASKED_AT_ONCE,
                    &no_finds,
                    &forget_nothing,
                    &|_, _, frames| answers.dial(frames),
                );
            }));
            let _ = ended.send((pass.is_err(), answers.count()));
        });
        let (panicked, dials) = end
            .recv_timeout(Duration::from_secs(30))
            .expect("the pass ended");
        assert!(panicked, "with the panic");
        assert_eq!(dials, 0, "no turn ran");
    }

    /// The tags a turn missed are looked at with the work held
    /// ([`Pass::retag`]): they come from the session store, which a turn's
    /// page writes. A turn holds the work here for 400 ms.
    #[test]
    fn f18_tags_are_looked_at_with_the_work_held() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let (fix, wall) = two_friends(true);
        let shared: Mutex<Shared> = Mutex::default();
        let now = Instant::now();
        let mut keepers = vec![Keeper::new((fix.carol, vec![fix.bob]))];
        keepers[0].turns = 1;
        keepers[0].live_peers = vec![fix.bob];
        with_pass(&fix, &shared, |pass, _| {
            let work = pass.asking.work;
            let held = std::sync::Barrier::new(2);
            let waited = std::thread::scope(|s| {
                s.spawn(|| {
                    let _turn = AtWork::begin(work);
                    held.wait();
                    std::thread::sleep(Duration::from_millis(400));
                });
                held.wait();
                let began = std::time::Instant::now();
                pass.retag(&mut keepers, &[fix.bob], (now, wall));
                began.elapsed()
            });
            assert!(waited >= Duration::from_millis(300), "{waited:?}");
        });
    }

    /// A [`Pass`] over Alice's folder in `fix` on `shared`, with no network,
    /// handed to `f` with its `PassIo`.
    fn with_pass<T>(
        fix: &Fix,
        shared: &Mutex<Shared>,
        f: impl FnOnce(&mut Pass<'_>, &PassIo<'_>) -> T,
    ) -> T {
        let work = Mutex::new(());
        let dial = |_: &OutboxRoute, _: &str, _: &[Vec<u8>]| Err("no dial here".to_string());
        let asking = Asking {
            data_dir: fix.dir(),
            identity: &fix.alice,
            dial: &dial,
            find_failed: &forget_nothing,
            work: &work,
            budget: &no_budget,
        };
        let mut pass = Pass {
            shared,
            asking: &asking,
            handoff: false,
            register_due: false,
            custody_live: true,
            base: BASE_INTERVAL,
            again_after: Duration::from_millis(700),
            new_turns_for: NEW_TURNS_FOR,
            offers: HashMap::new(),
            cache: TagCache::default(),
            reg_cache: TagCache::default(),
            inbox_changed: false,
        };
        let mut home_changed = |_: usize| {};
        let io = PassIo {
            dial: &dial,
            want: &|_| {},
            finds: &no_finds,
            find_failed: &forget_nothing,
            home_changed: &mut home_changed,
            lan: true,
            kick: &|_| {},
            at_once: ASKED_AT_ONCE,
            budget: &no_budget,
        };
        f(&mut pass, &io)
    }

    /// A turn of `custodian` at `now` that asks for the mail of
    /// `live_peers` with `tags`.
    fn turn_of(
        custodian: [u8; 32],
        (now, wall): (Instant, u64),
        live_peers: Vec<[u8; 32]>,
        tags: BTreeMap<[u8; 16], raven_core::relayed_ingest::RelayHint>,
    ) -> Turn {
        Turn {
            custodian,
            now,
            wall,
            state: FetchState::default(),
            empty: 0,
            live_peers,
            last_path: None,
            registering: false,
            offer: None,
            finds: Vec::new(),
            onion: false,
            tags,
            register: BTreeMap::new(),
            wants_tags: false,
        }
    }

    /// The tags of Alice's live session with Bob, as a turn asks with them.
    fn bob_tags(fix: &Fix, wall: u64) -> BTreeMap<[u8; 16], raven_core::relayed_ingest::RelayHint> {
        let tags =
            raven_core::custody_client::inbound_tags(fix.dir(), &fix.alice, &[fix.bob], wall)
                .unwrap();
        assert!(!tags.is_empty(), "Alice's session with Bob");
        tags
    }

    /// What a turn of `custodian` at `now` brought that asked nothing
    /// there (`dialled` dials went out, each answered).
    fn asked_nothing(custodian: [u8; 32], at: (Instant, u64), dialled: usize) -> Asked {
        Asked {
            turn: turn_of(custodian, at, Vec::new(), BTreeMap::new()),
            no_route: false,
            report: None,
            letters: None,
            answered: dialled,
            path: None,
            carrier: None,
            tried: None,
            over_tor: false,
            dialled,
            cut: false,
        }
    }

    /// A turn's end as the pass notes it ([`Pass::noted`]): the custodian
    /// rests [`AGAIN_AFTER`] (here 700 ms) after a turn that dialled it,
    /// [`LOOK_AGAIN`] after one that dialled nothing; one whose turn missed
    /// tags another turn's mail brought while it was out is due at once as
    /// it ends; and the mail a turn took in makes due again each custodian
    /// whose last turn asked for that peer's mail without one of its tags
    /// now, the one that took it in too ([`Pass::retag`]).
    #[test]
    fn f18_a_turns_end_sets_its_rest_and_missed_tags_make_it_due() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let (fix, wall) = two_friends(true);
        let shared: Mutex<Shared> = Mutex::default();
        let now = Instant::now();
        let mut keepers = vec![
            Keeper::new((fix.carol, vec![fix.bob])),
            Keeper::new((fix.dave, vec![fix.bob])),
        ];
        with_pass(&fix, &shared, |pass, io| {
            lock_of(&shared).begin_fetch(&fix.carol);
            pass.noted(
                io,
                &mut keepers,
                0,
                asked_nothing(fix.carol, (now, wall), 1),
                (now, wall),
            );
            assert_eq!(
                keepers[0].rest_until,
                Some(now + Duration::from_millis(700))
            );
            assert!(
                lock_of(&shared).states[&fix.carol].1 > now,
                "its own next time"
            );
            keepers[1].retag = true;
            lock_of(&shared).begin_fetch(&fix.dave);
            pass.noted(
                io,
                &mut keepers,
                1,
                asked_nothing(fix.dave, (now, wall), 0),
                (now, wall),
            );
            assert_eq!(
                keepers[1].rest_until,
                Some(now + LOOK_AGAIN),
                "it dialled nothing"
            );
            assert!(lock_of(&shared).states[&fix.dave].1 <= now, "due at once");
            assert!(!keepers[1].retag);
            // Carol's turn took in Bob's mail, which may have brought a
            // session: her turn asked without its tags, Dave's with them.
            let later = now + BASE_INTERVAL;
            lock_of(&shared).states.get_mut(&fix.dave).unwrap().1 = later;
            let bob_tags = bob_tags(&fix, wall);
            keepers[0].starts(
                &turn_of(fix.carol, (now, wall), vec![fix.bob], BTreeMap::new()),
                true,
            );
            keepers[1].starts(
                &turn_of(fix.dave, (now, wall), vec![fix.bob], bob_tags),
                true,
            );
            lock_of(&shared).begin_fetch(&fix.carol);
            let mut asked = asked_nothing(fix.carol, (now, wall), 1);
            asked.report = Some(raven_core::custody_client::FetchReport {
                touched: vec![fix.bob],
                ..Default::default()
            });
            pass.noted(io, &mut keepers, 0, asked, (now, wall));
            {
                let s = lock_of(&shared);
                assert!(
                    s.states[&fix.carol].1 <= now,
                    "due again for the tags she missed"
                );
                assert_eq!(s.states[&fix.dave].1, later, "Dave asked with them");
            }
            // Flagged while out, but that turn reached nothing there: the
            // wait its failure gave it stands (review mail-friends-2 L2).
            keepers[1].retag = true;
            lock_of(&shared).begin_fetch(&fix.dave);
            let mut failed = asked_nothing(fix.dave, (now, wall), 1);
            failed.answered = 0;
            failed.report = Some(raven_core::custody_client::FetchReport {
                dials: 1,
                ..Default::default()
            });
            pass.noted(io, &mut keepers, 1, failed, (now, wall));
            assert!(keepers[1].missed && !keepers[1].retag);
            let s = lock_of(&shared);
            assert_eq!(s.failures.get(&fix.dave), Some(&1));
            assert!(s.states[&fix.dave].1 > now, "its backoff stands");
        });
    }

    /// Mail a turn took in for a peer may bring a session whose tags the
    /// turns asked at the same time did not ask for (in a pass that asked
    /// one after the other, the next one was asked with them): a custodian
    /// whose last turn asked for that peer's mail without one of its tags
    /// now is due again (at once; flagged while its turn is out), one whose
    /// turn asked with all of them is not, nor one that asks for other
    /// peers' mail.
    #[test]
    fn f18_tags_a_turn_did_not_ask_with_make_its_custodian_due_again() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let (fix, wall) = two_friends(true);
        let shared: Mutex<Shared> = Mutex::default();
        let now = Instant::now();
        let later = now + BASE_INTERVAL;
        let schedule = |c: [u8; 32]| {
            lock_of(&shared)
                .states
                .insert(c, (FetchState::default(), later, 0));
        };
        let due_at = |c: &[u8; 32]| lock_of(&shared).states[c].1;
        let mut keepers = vec![
            Keeper::new((fix.carol, vec![fix.bob])),
            Keeper::new((fix.dave, vec![fix.bob])),
        ];
        // The turns they had: Carol's asked for Bob's mail with none of
        // his tags, Dave's with all of them.
        let bob_tags = bob_tags(&fix, wall);
        keepers[0].starts(
            &turn_of(fix.carol, (now, wall), vec![fix.bob], BTreeMap::new()),
            true,
        );
        keepers[1].starts(
            &turn_of(fix.dave, (now, wall), vec![fix.bob], bob_tags),
            true,
        );
        schedule(fix.carol);
        schedule(fix.dave);
        with_pass(&fix, &shared, |pass, _| {
            pass.retag(&mut keepers, &[fix.bob], (now, wall));
            assert!(due_at(&fix.carol) <= now, "Carol's turn missed Bob's tags");
            assert_eq!(due_at(&fix.dave), later, "Dave's asked with them");
            // Out: due again when it ends.
            schedule(fix.carol);
            keepers[0].out = true;
            pass.retag(&mut keepers, &[fix.bob], (now, wall));
            assert!(keepers[0].retag);
            assert_eq!(due_at(&fix.carol), later);
            // Mail of another peer: nothing.
            keepers[0].out = false;
            keepers[0].retag = false;
            pass.retag(&mut keepers, &[fix.dave], (now, wall));
            assert!(!keepers[0].retag);
            assert_eq!(due_at(&fix.carol), later);
            // One whose last turn reached nothing there: its turn asked it
            // nothing, and its backoff stands (review mail-friends-2 L2).
            keepers[0].missed = true;
            pass.retag(&mut keepers, &[fix.bob], (now, wall));
            assert_eq!(due_at(&fix.carol), later, "not reached last time");
            // ... unless a turn of its is out again: that one may reach it.
            keepers[0].out = true;
            pass.retag(&mut keepers, &[fix.bob], (now, wall));
            assert!(keepers[0].retag, "out again: flagged");
        });
    }

    /// Bob's fetch pass in the letters world `w` on `shared`, his mail
    /// friends Carol and Dave asked at the same time: every dial through
    /// `dial`, the beacon's finds and forgetting, every outbox kick
    /// through `kick`.
    fn bob_pass(
        w: &crate::letters::tests::World,
        shared: &Mutex<Shared>,
        dial: &PassDial<'_>,
        (finds, find_failed): Beacon<'_>,
        kick: &dyn Fn(&[u8; 32]),
    ) {
        let mut home_changed = |_: usize| {};
        let mut io = PassIo {
            dial,
            want: &|_| {},
            finds,
            find_failed,
            home_changed: &mut home_changed,
            lan: true,
            kick,
            at_once: ASKED_AT_ONCE,
            budget: &no_budget,
        };
        let (now, wall) = (Instant::now(), raven_core::clock::now_ms());
        fetch_pass_with(shared, w.b.path(), &w.bob, now, wall, &mut io);
    }

    /// Alice's messages `texts`, left by her worker with both of Bob's mail
    /// friends, in a letters world of seed `seed`.
    fn left_with_both(seed: u8, texts: &[&str]) -> crate::letters::tests::World {
        let w = crate::letters::tests::World::new(seed, true, true);
        for text in texts {
            w.stage(text);
        }
        let report = w.attempt();
        assert_eq!(report.outcomes.len(), texts.len(), "{report:?}");
        let both = crate::outbox::Outcome::Deposited { held: 2 };
        assert!(report.outcomes.values().all(|o| *o == both), "{report:?}");
        let n = i64::try_from(texts.len()).unwrap();
        assert_eq!(
            (w.objects_at(w.carol_pub), w.objects_at(w.dave_pub)),
            (n, n)
        );
        w
    }

    /// Review mail-friends-1, finding 2: real mail on the turns' threads.
    /// Alice's two messages wait at both of Bob's mail friends (sealed
    /// objects, as her worker leaves them with Carol and Dave), and Bob's
    /// pass asks the two at the same time: each message reaches his inbox
    /// exactly once, both keepers let go of what they held (RELEASE), the
    /// two dials were out together, and the outbox kicked is Alice's. Then
    /// with a third one: noting a turn's end is this device's work too.
    /// Carol's mail kicks Alice's outbox while her end is noted; Dave's
    /// dial to a stale find fails right then, and his turn tells the beacon
    /// to forget the find only once Carol's end has been noted.
    #[test]
    fn f18_mail_both_friends_hold_comes_once_when_both_are_asked_at_once() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, false);
        let _lan = crate::lan_direct::lan_switch_untouched();
        let w = left_with_both(0x1b, &["first", "second"]);
        let (carol, dave) = (w.carol_pub, w.dave_pub);
        let shared = Mutex::default();
        let out = DialsOut::default();
        let net = |route: &OutboxRoute, expected: &str, frames: &[Vec<u8>]| {
            crate::outbox::Dialer::dial(&*w.net, w.b.path(), route, expected, frames)
                .map(|replies| (replies, Some(DeliveryPath::Direct)))
        };
        let dial = |route: &OutboxRoute, expected: &str, frames: &[Vec<u8>]| {
            out.begin(2, Duration::from_secs(5));
            let got = net(route, expected, frames);
            out.end();
            got
        };
        let kicked = Mutex::new(Vec::new());
        let kick = |peer: &[u8; 32]| kicked.lock().unwrap().push(*peer);
        bob_pass(&w, &shared, &dial, (&no_finds, &forget_nothing), &kick);
        let mut inbox = w.bob_inbox();
        inbox.sort();
        assert_eq!(inbox, ["first", "second"], "each message once");
        assert_eq!(out.most(), 2, "the two were asked at the same time");
        assert_eq!(
            (w.objects_at(carol), w.objects_at(dave)),
            (0, 0),
            "both let go"
        );
        let kicked = kicked.into_inner().unwrap();
        assert!(!kicked.is_empty() && kicked.iter().all(|p| *p == w.alice_pub));
        {
            let s = lock_of(&shared);
            assert!(s.failures.is_empty() && s.in_pass.is_empty());
            assert!(s.states.contains_key(&carol) && s.states.contains_key(&dave));
        }
        drop(w);
        // Noting an end holds the work.
        let w = left_with_both(0x1b, &["third"]);
        let stale = "192.168.1.99:47532";
        let finds = |c: &[u8; 32]| {
            if *c == w.dave_pub {
                vec![stale.to_string()]
            } else {
                Vec::new()
            }
        };
        let kicking = std::sync::atomic::AtomicBool::new(false);
        let (forgot, overlap) = (
            Mutex::new(0usize),
            std::sync::atomic::AtomicBool::new(false),
        );
        let find_failed = |_: &[u8; 32], _: &str| {
            *forgot.lock().unwrap() += 1;
            if kicking.load(std::sync::atomic::Ordering::SeqCst) {
                overlap.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        };
        let kicks = Mutex::new(0usize);
        let kick = |_: &[u8; 32]| {
            *kicks.lock().unwrap() += 1;
            kicking.store(true, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(300));
            kicking.store(false, std::sync::atomic::Ordering::SeqCst);
        };
        let waited = Told::<Option<bool>>::default();
        let net = |route: &OutboxRoute, expected: &str, frames: &[Vec<u8>]| {
            crate::outbox::Dialer::dial(&*w.net, w.b.path(), route, expected, frames)
                .map(|replies| (replies, Some(DeliveryPath::Direct)))
        };
        let dial = |route: &OutboxRoute, expected: &str, frames: &[Vec<u8>]| {
            if route.dial == stale {
                waited.set(Some(wait_until(|| {
                    kicking.load(std::sync::atomic::Ordering::SeqCst)
                })));
                return Err("lan connect: cannot connect (Connection refused)".to_string());
            }
            net(route, expected, frames)
        };
        let shared = Mutex::default();
        bob_pass(&w, &shared, &dial, (&finds, &find_failed), &kick);
        assert_eq!(
            waited.get(),
            Some(true),
            "Dave's stale dial failed while Carol's end was noted"
        );
        assert!(*kicks.lock().unwrap() >= 1 && *forgot.lock().unwrap() == 1);
        assert!(
            !overlap.load(std::sync::atomic::Ordering::SeqCst),
            "Dave's turn worked while Carol's end was being noted"
        );
        assert_eq!(w.bob_inbox(), ["third"]);
        assert_eq!(
            (w.objects_at(w.carol_pub), w.objects_at(w.dave_pub)),
            (0, 0)
        );
    }

    #[test]
    fn f8_home_custodian_fetched_with_tags_of_every_live_pinned_session() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let fix = Fix::new(0xa1);
        let wall = raven_core::clock::now_ms();
        fix.uses_friends(Some(true));
        fix.carol_offers(0, wall);
        let (shared, carol, seen) = (Mutex::default(), Carol::default(), Seen::default());
        pass(&fix, &shared, &carol, &seen, true, Instant::now(), wall);
        // Carol became the home custodian (announced once), and one dial
        // asked her for the mail of both live sessions, with no static
        // list anywhere.
        assert_eq!(*seen.homes.borrow(), [1]);
        assert_eq!(
            raven_core::custody_home::home(fix.dir(), &fix.alice.public_key_bytes(), wall),
            [fix.carol]
        );
        let (bob, dave) = (
            fix.tags_of(&[fix.bob], wall),
            fix.tags_of(&[fix.dave], wall),
        );
        assert!(!bob.is_empty() && !dave.is_empty());
        let mut both: Vec<[u8; 16]> = bob.iter().chain(&dave).copied().collect();
        both.sort_unstable();
        assert_eq!(carol.count(), 1);
        assert_eq!(carol.fetched(), both);
        // Derived once: the next pass takes the tags from the cache.
        let loads = lock_of(&shared).tags.protected_loads();
        assert_eq!(loads, 2, "one load per session");
        pass(
            &fix,
            &shared,
            &carol,
            &seen,
            true,
            Instant::now() + LATER,
            wall,
        );
        assert_eq!(carol.count(), 2);
        assert_eq!(lock_of(&shared).tags.protected_loads(), loads);
        assert_eq!(*seen.homes.borrow(), [1], "no change, no announce");
        // Without consent nothing is announced or fetched from her (she is
        // still drained: next test).
        fix.uses_friends(None);
        assert!(
            raven_core::custody_home::home(fix.dir(), &fix.alice.public_key_bytes(), wall)
                .is_empty()
        );
    }

    #[test]
    fn f9_retired_custodian_drained_then_dropped() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let fix = Fix::new(0xa4);
        let wall = raven_core::clock::now_ms();
        fix.uses_friends(Some(true));
        fix.carol_offers(0, wall);
        let (shared, carol, seen) = (Mutex::default(), Carol::default(), Seen::default());
        let t0 = Instant::now();
        pass(&fix, &shared, &carol, &seen, true, t0, wall);
        assert_eq!(carol.count(), 1);
        // Mailboxes off: Carol is retired, and still fetched from while
        // what was left with her may be there.
        fix.uses_friends(Some(false));
        lock_of(&shared).offers_changed();
        pass(&fix, &shared, &carol, &seen, true, t0 + LATER, wall + 1_000);
        assert_eq!(*seen.homes.borrow(), [1, 0], "home emptied, announced");
        assert_eq!(carol.count(), 2, "draining");
        // Past the drain: she is no longer a target. Nothing dials her and
        // her schedule goes (review D-2: kept, it was due in the past for
        // ever and the fetcher woke every 200 ms).
        let late = wall + raven_core::custody_home::DRAIN_MS + 2_000;
        lock_of(&shared).offers_changed();
        let at = t0 + LATER * 120;
        pass(&fix, &shared, &carol, &seen, true, at, late);
        assert_eq!(carol.count(), 2);
        assert!(!lock_of(&shared).states.contains_key(&fix.carol));
        assert_eq!(lock_of(&shared).next_wait(at, BASE_INTERVAL), BASE_INTERVAL);
        assert!(raven_core::custody_home::fetch_from(
            fix.dir(),
            &fix.alice.public_key_bytes(),
            late
        )
        .is_empty());
    }

    /// Review D-2: the worker deposited at a contact's mail friend this
    /// node does not fetch from (the usual Phase 3 case). After the next
    /// pass that custodian has no schedule, so the fetcher sleeps the base
    /// interval instead of waking every 200 ms for ever.
    #[test]
    fn f15_a_deposit_at_a_custodian_this_node_does_not_fetch_from_does_not_spin() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let fix = Fix::new(0xa9);
        let wall = raven_core::clock::now_ms();
        fix.uses_friends(Some(true));
        fix.carol_offers(0, wall);
        let (shared, carol, seen) = (Mutex::default(), Carol::default(), Seen::default());
        let t0 = Instant::now();
        let elsewhere = [0xEE; 32];
        lock_of(&shared).note_deposit(&elsewhere, t0 + BASE_INTERVAL);
        let at = t0 + BASE_INTERVAL + Duration::from_secs(1);
        pass(&fix, &shared, &carol, &seen, true, at, wall);
        assert_eq!(
            carol.count(),
            1,
            "Carol, the home custodian, is fetched from"
        );
        assert!(!lock_of(&shared).states.contains_key(&elsewhere));
        assert_eq!(lock_of(&shared).next_wait(at, BASE_INTERVAL), BASE_INTERVAL);
        // A network change does not bring it back.
        lock_of(&shared).network_changed(at);
        assert!(!lock_of(&shared).states.contains_key(&elsewhere));
    }

    /// Phase 5 P5.33 (custody on a nearby encounter): with the lab gates on,
    /// a pipe to a custodian runs one fetch from it now instead of at its
    /// next time, another inside five minutes runs none, and a contact that
    /// is no custodian makes nobody due. Through the process-wide state a
    /// new encounter is reported once (the caller then kicks what the
    /// custodian may carry).
    #[test]
    fn an_encounter_with_the_lab_gates_on_fetches_once() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let fix = Fix::new(0xb4);
        let wall = raven_core::clock::now_ms();
        fix.uses_friends(Some(true));
        fix.carol_offers(0, wall);
        let (shared, carol, seen) = (Mutex::default(), Carol::default(), Seen::default());
        let t0 = Instant::now();
        pass(&fix, &shared, &carol, &seen, true, t0, wall);
        assert_eq!(carol.count(), 1, "the first round");
        let t1 = t0 + Duration::from_secs(1);
        pass(&fix, &shared, &carol, &seen, true, t1, wall);
        assert_eq!(carol.count(), 1, "not due before its next time");
        assert_eq!(
            lock_of(&shared).encounter(&fix.dave, false, t1),
            Some(false),
            "Dave keeps no mail for Alice"
        );
        pass(&fix, &shared, &carol, &seen, true, t1, wall);
        assert_eq!(carol.count(), 1);
        assert_eq!(
            lock_of(&shared).encounter(&fix.carol, false, t1),
            Some(true)
        );
        pass(&fix, &shared, &carol, &seen, true, t1, wall);
        assert_eq!(carol.count(), 2, "fetched once on the encounter");
        let t2 = t1 + Duration::from_secs(30);
        assert_eq!(lock_of(&shared).encounter(&fix.carol, false, t2), None);
        pass(&fix, &shared, &carol, &seen, true, t2, wall);
        assert_eq!(carol.count(), 2, "once per gap");
        let peer = [0xE5; 32];
        assert!(encounter(&peer), "new, the gates live");
        assert!(!encounter(&peer), "inside the gap");
    }

    /// Phase 5 P5.33: an encounter with a custodian makes due the waiting
    /// contacts whose custodians (the worker's own list) include it, so a
    /// deposit goes while the pipe is up; never the custodian itself (its
    /// own mail rode the pipe-up kick), and nobody for a contact that
    /// carries for nobody.
    #[test]
    fn an_encounter_kicks_what_the_custodian_may_carry() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, false);
        let fix = Fix::new(0xb7);
        fix.book(&[fix.carol]);
        let local = fix.alice.public_key_bytes();
        let wall = raven_core::clock::now_ms();
        let of = |peer: &[u8; 32]| {
            raven_core::custody_client::deposit_custodians(fix.dir(), &local, peer, wall)
        };
        let waiting = vec![fix.dave, fix.carol, fix.bob];
        assert_eq!(carried_by(&fix.carol, waiting.clone(), of), [fix.bob]);
        assert!(carried_by(&fix.dave, waiting.clone(), of).is_empty());
        fix.book(&[]);
        assert!(
            carried_by(&fix.carol, waiting, of).is_empty(),
            "listed no more"
        );
    }

    /// Review nearby-7: an encounter looks through every waiting contact,
    /// not only the 64 waiting longest: of 100 waiting contacts only the
    /// 90th lists the custodian, and it is the one kicked; the outbox is
    /// asked for more than 100.
    #[test]
    fn an_encounter_looks_through_every_waiting_contact() {
        let dir = tempfile::tempdir().unwrap();
        let (local, carol) = ([0xEE; 32], [0xC0; 32]);
        let waiting: Vec<[u8; 32]> = (1..=100u8).map(|i| [i; 32]).collect();
        let row = |key: &[u8; 32], custodians: &[[u8; 32]]| {
            serde_json::json!({
                "pub_hex": hex::encode(key),
                "pinned": true,
                "custodians": custodians.iter().map(hex::encode).collect::<Vec<_>>(),
            })
        };
        let lists_carol = [carol];
        let mut rows = vec![row(&carol, &[])];
        rows.extend(
            waiting
                .iter()
                .enumerate()
                .map(|(i, p)| row(p, if i == 89 { &lists_carol[..] } else { &[] })),
        );
        std::fs::write(
            dir.path().join("contacts.json"),
            serde_json::Value::Array(rows).to_string(),
        )
        .unwrap();
        let asked = std::cell::Cell::new(0);
        let outbox = |limit: usize| {
            asked.set(limit);
            waiting.iter().take(limit).copied().collect()
        };
        let wall = raven_core::clock::now_ms();
        assert_eq!(
            carried_from(dir.path(), &local, &carol, outbox, wall),
            [waiting[89]]
        );
        assert!(asked.get() > waiting.len(), "asked for {}", asked.get());
        // The batch answers as the one-contact lookup does.
        let each: Vec<_> = waiting
            .iter()
            .map(|p| raven_core::custody_client::deposit_custodians(dir.path(), &local, p, wall))
            .collect();
        assert_eq!(
            raven_core::custody_client::deposit_custodians_for(dir.path(), &local, &waiting, wall),
            each
        );
        assert_eq!(each[89], [(carol, None)]);
    }

    #[test]
    fn f10_relayed_last_path_uses_four_pages() {
        if !rig::lab_backends() {
            return;
        }
        assert_eq!(pages_for(None), MAX_PAGES_PER_TRIGGER_RELAYED);
        assert_eq!(pages_for(Some(DeliveryPath::Relayed)), 4);
        for direct in [
            DeliveryPath::Direct,
            DeliveryPath::HolePunched,
            DeliveryPath::Reversed,
        ] {
            assert_eq!(pages_for(Some(direct)), MAX_PAGES_PER_TRIGGER);
        }
        let _g = Gates::on(true, true);
        let fix = Fix::new(0xa7);
        let wall = raven_core::clock::now_ms();
        fix.uses_friends(Some(true));
        fix.carol_offers(0, wall);
        let (shared, carol, seen) = (Mutex::default(), Carol::default(), Seen::default());
        carol.paging.set(true);
        // Never linked: the relayed budget.
        carol.path.set(Some(DeliveryPath::Relayed));
        let t0 = Instant::now();
        pass(&fix, &shared, &carol, &seen, true, t0, wall);
        assert_eq!(carol.count(), 4);
        assert_eq!(
            lock_of(&shared).last_path.get(&fix.carol),
            Some(&DeliveryPath::Relayed)
        );
        pass(&fix, &shared, &carol, &seen, true, t0 + LATER, wall);
        assert_eq!(carol.count(), 8, "relayed again: four more");
        // A direct link (it hole-punched): the full budget next time.
        carol.path.set(Some(DeliveryPath::HolePunched));
        pass(&fix, &shared, &carol, &seen, true, t0 + LATER * 2, wall);
        assert_eq!(carol.count(), 12, "still relayed when the pass began");
        pass(&fix, &shared, &carol, &seen, true, t0 + LATER * 3, wall);
        assert_eq!(carol.count(), 12 + MAX_PAGES_PER_TRIGGER);
    }

    /// E2 r9 #3: a custodian reached on no route is retried like a delivery
    /// only while something is owed there; an idle poll doubles from the
    /// base interval to 30 minutes.
    #[test]
    fn an_unreachable_custodian_with_nothing_owed_backs_off() {
        let base = BASE_INTERVAL;
        let idle: Vec<Duration> = (0..8).map(|n| unreachable_wait(n, false, base)).collect();
        assert_eq!(
            idle,
            [1, 2, 4, 8, 16, 30, 30, 30].map(|m| Duration::from_secs(60 * m))
        );
        // Dials in the first 22 minutes: 0, 1, 3, 7 and 15 min (9 before).
        let mut at = Duration::ZERO;
        let mut dials = 0;
        for w in &idle {
            if at > Duration::from_secs(22 * 60) {
                break;
            }
            dials += 1;
            at += *w;
        }
        assert_eq!(dials, 5);
        let owed = unreachable_wait(0, true, base);
        assert!(owed <= Duration::from_millis(7_500), "{owed:?}");
        // A lab base interval longer than the cap keeps its own.
        let long = Duration::from_secs(3_600);
        assert_eq!(unreachable_wait(3, false, long), long);
    }

    #[test]
    fn f11_dial_failure_backs_off_from_the_base_interval_when_nothing_is_owed() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let fix = Fix::new(0xaa);
        let wall = raven_core::clock::now_ms();
        fix.uses_friends(Some(true));
        fix.carol_offers(0, wall);
        let (shared, carol, seen) = (Mutex::default(), Carol::default(), Seen::default());
        carol.down.set(true);
        let t0 = Instant::now();
        let wait_after = |at: Instant| lock_of(&shared).states[&fix.carol].1 - at;
        pass(&fix, &shared, &carol, &seen, true, t0, wall);
        assert_eq!(carol.count(), 1);
        // E2 r9 #3: nothing owed there, so an idle poll backs off from the
        // base interval (it is fetched at once when it shows up again).
        let w = wait_after(t0);
        assert_eq!(w, BASE_INTERVAL, "an idle poll: the base interval");
        let t1 = t0 + LATER;
        pass(&fix, &shared, &carol, &seen, true, t1, wall);
        let w = wait_after(t1);
        assert_eq!(w, BASE_INTERVAL * 2, "doubled");
        assert_eq!(lock_of(&shared).failures[&fix.carol], 2);
        // She answers (nothing for us): the empty-round interval again.
        carol.down.set(false);
        let t2 = t1 + LATER;
        pass(&fix, &shared, &carol, &seen, true, t2, wall);
        assert_eq!(wait_after(t2), BASE_INTERVAL);
        assert!(!lock_of(&shared).failures.contains_key(&fix.carol));
    }

    /// A pass that finds no route to a custodian at all (here no saved
    /// address; Tor not usable yet, or the idle-Tor rule taking its onion
    /// route, leaves none the same way) asks nothing there: nothing is
    /// dialled, and it is no round. Before, it counted an empty round and
    /// cleared the custodian's failures: after an iPhone open or a network
    /// change the idle-Tor rule then kept Tor off there until 30 minutes
    /// after the last Tor fetch, and a link from a friend that had been
    /// unreachable no longer pulled its fetch forward. Now its empty rounds
    /// and failures stay, and it is looked at again on its current
    /// interval (Tor coming up makes it due at once).
    #[test]
    fn a_pass_with_no_route_to_a_custodian_is_no_round() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, false);
        let fix = Fix::new(0xB9);
        // Bob lists Carol as his mail friend (a fetch target with or
        // without hints); Carol has no saved address.
        fix.book(&[fix.carol]);
        let book = fix.dir().join("contacts.json");
        let mut rows: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&book).unwrap()).unwrap();
        for row in rows.as_array_mut().unwrap() {
            if row["pub_hex"] == hex::encode(fix.carol) {
                row.as_object_mut().unwrap().remove("lan_dial");
            }
        }
        std::fs::write(&book, rows.to_string()).unwrap();
        let wall = raven_core::clock::now_ms();
        let base = lab_fetch_interval().unwrap_or(BASE_INTERVAL);
        for empty in [0, 5] {
            let (shared, carol, seen) = (Mutex::default(), Carol::default(), Seen::default());
            let t0 = Instant::now();
            {
                let mut s = lock_of(&shared);
                s.states
                    .insert(fix.carol, (FetchState::default(), t0, empty));
                s.failures.insert(fix.carol, 2);
            }
            pass(&fix, &shared, &carol, &seen, true, t0, wall);
            assert_eq!(*seen.wants.borrow(), [fix.carol], "the pass took her");
            assert_eq!(carol.count(), 0, "nothing dialled");
            let s = lock_of(&shared);
            assert_eq!(
                (s.states[&fix.carol].1, s.states[&fix.carol].2),
                (t0 + idle_interval(empty, base), empty),
                "no round: her interval, her empty rounds"
            );
            assert_eq!(s.failures.get(&fix.carol), Some(&2), "her failures stay");
        }
    }

    #[test]
    fn f12_offers_changed_refreshes_home_and_calls_own_changed() {
        if !rig::lab_backends() {
            return;
        }
        let _g = Gates::on(true, true);
        let fix = Fix::new(0xad);
        let wall = raven_core::clock::now_ms();
        fix.uses_friends(Some(true));
        let (shared, carol, seen) = (Mutex::default(), Carol::default(), Seen::default());
        let t0 = Instant::now();
        // Nobody offers yet: no home, nothing announced.
        pass(&fix, &shared, &carol, &seen, true, t0, wall);
        assert!(seen.homes.borrow().is_empty());
        // Carol's offer arrives; until it is noted (or a minute passed)
        // the home is not chosen again.
        fix.carol_offers(0, wall);
        pass(
            &fix,
            &shared,
            &carol,
            &seen,
            true,
            t0 + Duration::from_secs(1),
            wall,
        );
        assert!(seen.homes.borrow().is_empty());
        lock_of(&shared).offers_changed();
        pass(
            &fix,
            &shared,
            &carol,
            &seen,
            true,
            t0 + Duration::from_secs(2),
            wall,
        );
        assert_eq!(*seen.homes.borrow(), [1], "chosen and announced");
        assert!(!lock_of(&shared).home_dirty);
        // A minute on, chosen again without a note (nothing changed).
        pass(
            &fix,
            &shared,
            &carol,
            &seen,
            true,
            t0 + HOME_REFRESH * 2,
            wall,
        );
        assert_eq!(*seen.homes.borrow(), [1]);
        // Not while custody does not ride route hints.
        let _off = Gates::on(true, false);
        fix.uses_friends(Some(false));
        lock_of(&shared).offers_changed();
        pass(
            &fix,
            &shared,
            &carol,
            &seen,
            true,
            t0 + HOME_REFRESH * 4,
            wall,
        );
        assert_eq!(*seen.homes.borrow(), [1]);
        assert!(lock_of(&shared).home_dirty, "kept for when it does");
    }

    #[test]
    fn f13_hand_off_window_expires_after_ten_minutes() {
        let mut s = Shared::default();
        let now = Instant::now();
        let (bob, dave) = ([0xB7; 32], [0xD7; 32]);
        assert!(!s.handed_off(&bob, now));
        s.hand_off(Some(bob), now);
        assert!(s.handed_off(&bob, now + Duration::from_secs(599)));
        assert!(!s.handed_off(&bob, now + HAND_OFF_WINDOW), "ten minutes");
        assert!(!s.handed_off(&dave, now), "for Bob only");
        // For every contact.
        s.hand_off(None, now);
        assert!(s.handed_off(&dave, now + Duration::from_secs(1)));
        assert!(!s.handed_off(&dave, now + HAND_OFF_WINDOW));
        // Bounded: lapsed ones go, then the oldest.
        for i in 0..(MAX_HAND_OFFS as u32 + 8) {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_be_bytes());
            s.hand_off(Some(k), now + Duration::from_millis(u64::from(i)));
        }
        assert_eq!(s.hand_off.len(), MAX_HAND_OFFS);
        // The process-wide one the worker reads.
        let peer = [0xE7; 32];
        assert_eq!(custody_after_for(&peer), custody_after_ms());
        hand_off(Some(peer));
        assert_eq!(custody_after_for(&peer), 0);
    }

    #[test]
    fn f14_a_due_custodian_raises_a_beacon_want_only_while_custody_and_lan_are_live() {
        if !rig::lab_backends() {
            return;
        }
        let fix = Fix::new(0xb1);
        // Bob lists Carol himself: a fetch target with or without hints.
        fix.book(&[Identity::from_seed(&[0xb1u8.wrapping_add(9); 32]).public_key_bytes()]);
        let wall = raven_core::clock::now_ms();
        let wants = |live: bool, lan: bool| {
            let _g = Gates::on(live, false);
            let (shared, carol, seen) = (Mutex::default(), Carol::default(), Seen::default());
            pass(&fix, &shared, &carol, &seen, lan, Instant::now(), wall);
            let wants = seen.wants.borrow().clone();
            wants
        };
        assert_eq!(wants(true, true), [fix.carol]);
        assert!(wants(true, false).is_empty(), "LAN off");
        assert!(wants(false, true).is_empty(), "custody gate closed");
        // Not due: no want.
        let _g = Gates::on(true, false);
        let (shared, carol, seen) = (Mutex::default(), Carol::default(), Seen::default());
        let t0 = Instant::now();
        pass(&fix, &shared, &carol, &seen, true, t0, wall);
        pass(
            &fix,
            &shared,
            &carol,
            &seen,
            true,
            t0 + Duration::from_secs(1),
            wall,
        );
        assert_eq!(seen.wants.borrow().len(), 1);
    }

    // ── Phase 5b P5.15: sealed letters in the fetcher ──────────────────────

    /// One fetch pass of Alice's (the letters world) through its net; the
    /// contacts whose outbox it kicked.
    fn letter_pass(w: &crate::letters::tests::World, shared: &Mutex<Shared>) -> Vec<[u8; 32]> {
        use crate::outbox::Dialer;
        let kicked = RefCell::new(Vec::new());
        let dial = |route: &OutboxRoute, expected: &str, frames: &[Vec<u8>]| {
            w.net
                .dial(w.a.path(), route, expected, frames)
                .map(|replies| (replies, Some(DeliveryPath::Direct)))
        };
        let mut home_changed = |_: usize| {};
        let kick = |peer: &[u8; 32]| kicked.borrow_mut().push(*peer);
        let mut io = PassIo {
            dial: &dial,
            want: &|_| {},
            finds: &|_| Vec::new(),
            find_failed: &|_, _| {},
            home_changed: &mut home_changed,
            lan: true,
            kick: &kick,
            at_once: 1,
            budget: &no_budget,
        };
        fetch_pass_with(
            shared,
            w.a.path(),
            &w.alice,
            Instant::now(),
            raven_core::clock::now_ms(),
            &mut io,
        );
        kicked.into_inner()
    }

    /// Alice and Bob never paired: no live session, so no store tag to ask
    /// for, yet the pass asks Carol for letters and takes Bob's, which
    /// brings its own session.
    #[test]
    fn fetch_pass_fetches_letters_with_no_live_session() {
        if !rig::lab_backends() {
            return;
        }
        let _on = crate::letters::tests::LettersOn::new();
        let w = crate::letters::tests::World::new(0xc1, false, false);
        w.bob_letter_for_alice("no session needed", w.carol_pub);
        assert_eq!(w.held_at(w.carol_pub), 1);
        let shared = Mutex::default();
        letter_pass(&w, &shared);
        assert_eq!(w.alice_inbox(), vec!["no session needed".to_string()]);
        // Released on the round's next dial, after the intake committed.
        assert_eq!(w.held_at(w.carol_pub), 0);
    }

    /// P5.16 (s61b): a letter session completed directly leaves its letter
    /// with Carol, and nothing is due for Bob any more (the worker's custody
    /// phase does not run for him again); Alice's next fetch pass at Carol
    /// withdraws it.
    #[test]
    fn fetch_pass_withdraws_a_letter_completed_directly() {
        if !rig::lab_backends() {
            return;
        }
        let _on = crate::letters::tests::LettersOn::new();
        let w = crate::letters::tests::World::new(0xc9, false, true);
        w.letters_known();
        let mid = w.stage("gone directly");
        w.attempt();
        assert_eq!(w.held_at(w.carol_pub), 1);
        w.net
            .bob_down
            .store(false, std::sync::atomic::Ordering::SeqCst);
        w.attempt();
        assert_eq!(w.history(&mid).as_deref(), Some("delivered"));
        assert_eq!(w.held_at(w.carol_pub), 1, "still there after delivery");
        assert_eq!(
            crate::letters::letter_peers_at(w.a.path(), &w.carol_pub, raven_core::clock::now_ms()),
            vec![w.bob_pub]
        );
        let shared = Mutex::default();
        letter_pass(&w, &shared);
        assert_eq!(w.held_at(w.carol_pub), 0);
        assert!(w.book(false).letters.is_empty());
    }

    /// Review letters-5: the base round tried every route of a custodian
    /// and none answered: the letter round and the withdraws do not try the
    /// same dead routes again in that pass (one dial, not two).
    #[test]
    fn an_unreachable_custodian_is_dialled_once_per_pass() {
        if !rig::lab_backends() {
            return;
        }
        let _on = crate::letters::tests::LettersOn::new();
        // The handoff gate held: with RAVEN_LAB_CUSTODY_HANDOFF set the base
        // round would also carry this node's TAGS REGISTER ahead of FETCH.
        use raven_core::custody_gate::set_handoff_gate_for_this_thread;
        set_handoff_gate_for_this_thread(Some(false));
        let w = crate::letters::tests::World::new(0xE5, false, true);
        let calls = Mutex::new(Vec::<Vec<u8>>::new());
        let dial = |_: &OutboxRoute,
                    _: &str,
                    frames: &[Vec<u8>]|
         -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String> {
            calls.lock().unwrap().push(
                frames
                    .iter()
                    .filter(|f| raven_core::friend_custody::is_rfc1(f))
                    .map(|f| f[5])
                    .collect(),
            );
            Err("custody dial deadline".into())
        };
        let mut home_changed = |_: usize| {};
        let kick = |_: &[u8; 32]| {};
        let mut io = PassIo {
            dial: &dial,
            want: &|_| {},
            finds: &|_| Vec::new(),
            find_failed: &|_, _| {},
            home_changed: &mut home_changed,
            lan: true,
            kick: &kick,
            at_once: 1,
            budget: &no_budget,
        };
        fetch_pass_with(
            &Mutex::default(),
            w.a.path(),
            &w.alice,
            Instant::now(),
            raven_core::clock::now_ms(),
            &mut io,
        );
        set_handoff_gate_for_this_thread(None);
        assert_eq!(
            calls.into_inner().unwrap(),
            vec![vec![raven_core::friend_custody::OP_FETCH]],
            "the base round only"
        );
    }

    /// Review letters-5: the letter round gets what the base round left of
    /// the trigger's page budget, at least one page.
    #[test]
    fn the_letter_round_shares_the_trigger_page_budget() {
        assert_eq!(letter_pages(None, 0), MAX_PAGES_PER_TRIGGER_RELAYED);
        assert_eq!(letter_pages(None, 1), MAX_PAGES_PER_TRIGGER_RELAYED - 1);
        assert_eq!(
            letter_pages(Some(DeliveryPath::Relayed), 3),
            MAX_PAGES_PER_TRIGGER_RELAYED - 3
        );
        assert_eq!(
            letter_pages(Some(DeliveryPath::Direct), 3),
            MAX_PAGES_PER_TRIGGER - 3
        );
        assert_eq!(letter_pages(None, MAX_PAGES_PER_TRIGGER_RELAYED), 1);
        assert_eq!(letter_pages(Some(DeliveryPath::Direct), 99), 1);
    }

    /// The contact whose letter was taken has its outbox kicked (a REPLY
    /// and ACKs are owed now); a pass that takes nothing kicks nobody.
    #[test]
    fn touched_peers_kick_outbox() {
        if !rig::lab_backends() {
            return;
        }
        let _on = crate::letters::tests::LettersOn::new();
        let w = crate::letters::tests::World::new(0xc5, false, false);
        w.bob_letter_for_alice("kick me", w.carol_pub);
        let shared = Mutex::default();
        assert_eq!(letter_pass(&w, &shared), vec![w.bob_pub]);
        lock_of(&shared).kick(Instant::now());
        assert!(letter_pass(&w, &shared).is_empty());
    }
}
