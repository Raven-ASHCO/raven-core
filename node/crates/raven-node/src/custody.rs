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
    /// The custodian a fetch pass works on now (its entry is out of
    /// `states` meanwhile), and whether [`peer_seen`] named it since.
    in_pass: Option<([u8; 32], bool)>,
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

    /// [`kick`]: every custodian due at `now`, parks cleared (save a
    /// misbehaving custodian's, which only [`Self::retry`] lifts).
    fn kick(&mut self, now: Instant) {
        for (_, due, empty) in self.states.values_mut() {
            *due = now;
            *empty = 0;
        }
        // An explicit kick (OutboxKick) also clears parks.
        self.parked.retain(|_, (_, why)| *why == CUSTODY_MISBEHAVED);
        self.parked_pair.clear();
        self.forward_everything(now);
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
    /// encounter ([`Wake::Met`]) starts the backoff over. One that names the
    /// custodian a pass is dialling makes it due again when that pass ends,
    /// if the pass reached nothing ([`Self::end_fetch`]).
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
            return true;
        }
        if let Some((custodian, again)) = self.in_pass.as_mut() {
            if *custodian == *peer {
                *again = true;
            }
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
        self.in_pass = Some((*custodian, false));
    }

    /// A fetch pass is done with `custodian`: due at `due` after `empty`
    /// empty rounds, or at `now` when the pass reached nothing (`missed`: no
    /// route, or every dial failed) and a link from it or its new routes
    /// came meanwhile (perhaps it moved while the pass dialled where it
    /// was, cutoff F8). A pass that reached it keeps its own next time.
    fn end_fetch(
        &mut self,
        custodian: [u8; 32],
        state: FetchState,
        (due, empty): (Instant, u32),
        missed: bool,
        now: Instant,
    ) {
        let again = matches!(self.in_pass.take(), Some((c, true)) if c == custodian);
        let due = if again && missed { now } else { due };
        self.states.insert(custodian, (state, due, empty));
    }

    /// [`network_changed`]: every custodian due at `now`, and every forward
    /// row; parks and strikes stay.
    fn network_changed(&mut self, now: Instant) {
        for (_, due, empty) in self.states.values_mut() {
            *due = now;
            *empty = 0;
        }
        self.forward_everything(now);
    }

    /// [`note_deposit`]: `custodian` due by `due` at the latest.
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
/// fetched from once more when that pass ends, if the pass reached nothing
/// ([`Shared::end_fetch`]). Custody handoff: a friend this node holds rows
/// for is here (the mule trigger), and a new session's tags want
/// registering. Its callers space it themselves (a route-hint kick once a
/// minute per contact, a beacon find at a new address once per round).
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
/// says ([`crate::p2p::dial_with_path`]; `None`: not known).
pub(crate) fn dial_route_path(
    handle: &tokio::runtime::Handle,
    data_dir: &Path,
    route: &OutboxRoute,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
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
                // its path is Tor.
                OutboxCarrier::Onion => crate::onion::dial_with_meta(
                    data_dir,
                    &route.dial,
                    expected_pub_hex,
                    frames,
                    crate::learning::DialMeta::default(),
                )
                .await
                .map(|replies| (replies, None)),
            }
        };
        let deadline = if route.carrier == OutboxCarrier::Onion {
            ONION_DIAL_DEADLINE
        } else {
            PER_DIAL_DEADLINE
        };
        tokio::time::timeout(deadline, work)
            .await
            .unwrap_or_else(|_| Err("custody dial deadline".into()))
    })
}

/// One custody dial as a fetch pass makes it: a route, the custodian's key
/// (hex), the frames; the replies and how the link travelled.
type PassDial<'a> = dyn FnMut(&OutboxRoute, &str, &[Vec<u8>]) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String>
    + 'a;

/// What a fetch pass reaches beyond the data dir: the network, the LAN
/// beacon and the announcer (tests hand in their own).
struct PassIo<'a> {
    dial: &'a mut PassDial<'a>,
    /// Ask the LAN beacon to look for a due custodian, or for a next hop
    /// the forwarder is about to dial (`Want::Custody`).
    want: &'a dyn Fn(&[u8; 32]),
    /// Where the LAN beacon found a custodian just now.
    finds: &'a dyn Fn(&[u8; 32]) -> Vec<String>,
    /// A dial to one of those finds did not reach the custodian: the
    /// beacon forgets it (§7, review A-5).
    find_failed: &'a dyn Fn(&[u8; 32], &str),
    /// The home custodians changed (now this many): announce it.
    home_changed: &'a mut dyn FnMut(usize),
    /// The LAN carrier may carry custody now (its gate, `raven lan off`).
    lan: bool,
    /// Mail from `peer` was taken: kick its outbox (owed ACKs, a REPLY
    /// letter, a confirmed letter session).
    kick: &'a dyn Fn(&[u8; 32]),
}

/// One fetch pass over every due custodian (blocking pool), then (custody
/// handoff) one forward pass.
fn fetch_pass(data_dir: &Path, identity: &Identity, handle: &tokio::runtime::Handle) {
    let mut dial = |route: &OutboxRoute, expected: &str, frames: &[Vec<u8>]| {
        dial_route_path(handle, data_dir, route, expected, frames)
    };
    let mut home_changed = |n: usize| {
        crate::hints::own_changed();
        eprintln!("raven-node custody: mail friends now {n}");
    };
    let mut io = PassIo {
        dial: &mut dial,
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
    };
    let inbox_changed = fetch_pass_with(
        shared(),
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
            shared(),
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
}

/// [`fetch_pass`] on `shared` at `now` (monotonic) and `wall` (ms), through
/// `io`. `true`: a custodian's `HANDOFF_INBOX` (TAGS OK within 24 h) came
/// or went (announce it).
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
    let mut inbox_changed = false;
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
    let custody_live = CustodyGates::current().live;
    let base = lab_fetch_interval().unwrap_or(BASE_INTERVAL);
    let mut cache = std::mem::take(&mut lock_of(shared).tags);
    let mut reg_cache = std::mem::take(&mut lock_of(shared).register_tags);
    for (custodian, peers) in targets {
        if lock_of(shared).parked(&custodian, None, now).is_some() {
            continue;
        }
        let (mut state, due, empty) = {
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
                .into_iter()
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
        let early = due > now
            && register_due
            && registering
            && registration_wanted(&state, &register_tags(&mut reg_cache), wall);
        if due > now && !early {
            lock_of(shared)
                .states
                .insert(custodian, (state, due, empty));
            continue;
        }
        lock_of(shared).begin_fetch(&custodian);
        // A due custodian may be on this network at another address: the
        // LAN beacon looks (RAVEN_LAN_BEACON_V1 §8), and what it found
        // leads the LAN routes.
        if custody_live && io.lan {
            (io.want)(&custodian);
        }
        let offer = offers.get(&custodian).and_then(|l| l.offer);
        // The worker's on-link filter: right after a network change (which
        // makes every custodian due) an address learned on the network left
        // is not dialled.
        let finds = (io.finds)(&custodian);
        let mut routes = custodian_routes(data_dir, &custodian, offer, &finds, |ip| {
            crate::outbox::learned_lan_on_link(ip) != Some(false)
        });
        // Tor (lab): an idle poll builds no Tor circuits (ONION_FETCH_EVERY).
        if !lock_of(shared).onion_fetch_ok(&custodian, empty, now) {
            routes.retain(|(planned, _)| planned.carrier != OutboxCarrier::Onion);
        }
        // Phase 5: over a nearby pipe too (last), under the custody gates.
        routes.extend(crate::nearby::custodian_route(&custodian));
        let tags = inbound_tags_cached(data_dir, identity, &live_peers, wall, &mut cache)
            .unwrap_or_default();
        let register = if registering {
            register_tags(&mut reg_cache)
        } else {
            BTreeMap::new()
        };
        let wants_tags = registering && registration_wanted(&state, &register, wall);
        let mut report = None;
        let mut letters = None;
        let (answered, mut path) = (std::cell::Cell::new(0usize), None);
        // The carrier of the last route that answered: the fetch line names
        // it (counts and the carrier only), so a log shows that mail came
        // over nearby alone (the field test's Bluetooth-only node).
        let carrier = std::cell::Cell::new(None::<OutboxCarrier>);
        // Whether this fetch dialled the custodian over Tor.
        let over_tor = std::cell::Cell::new(false);
        let expected = hex::encode(custodian);
        let mut first = 0;
        let mut dial = |frames: &[Vec<u8>]| {
            dial_in_turn(&routes, &mut first, |(planned, route)| {
                if route.carrier == OutboxCarrier::Onion {
                    over_tor.set(true);
                }
                let got = (io.dial)(route, &expected, frames);
                // A find that does not lead to the custodian is one no
                // longer (§7, review A-5).
                if let Err(e) = &got {
                    if crate::outbox::custody_find_failed(&finds, planned, e) {
                        (io.find_failed)(&custodian, &planned.dial);
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
            && (!tags.is_empty() || !state.pending_release.is_empty() || wants_tags)
        {
            let pages = pages_for(last_path);
            report = Some(if registering {
                crate::letters::with_handoff_caps(&custodian, |caps| {
                    let register = TagRegistration {
                        custodian,
                        tags: &register,
                        caps,
                    };
                    fetch_round_with(
                        data_dir,
                        identity,
                        &tags,
                        Some(register),
                        &mut state,
                        wall,
                        pages,
                        &mut dial,
                    )
                })
            } else {
                fetch_round(
                    data_dir, identity, &tags, &mut state, wall, pages, &mut dial,
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
                letter_pages(last_path, base_dials),
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
        let letter_dials = letters.as_ref().map_or(0, |r| r.dials);
        let mut empty = empty;
        let all_failed = (report.as_ref().is_some_and(|r| r.dials > 0) || letter_dials > 0)
            && answered.get() == 0;
        let next = {
            let mut s = lock_of(shared);
            if let Some(p) = path {
                s.last_path.insert(custodian, p);
            }
            if all_failed {
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
                        if empty > EMPTY_BEFORE_BACKOFF {
                            (base * 2u32.saturating_pow(empty - EMPTY_BEFORE_BACKOFF))
                                .min(max_interval(base))
                        } else {
                            base
                        }
                    }
                }
            }
        };
        if let (Some(r), true) = (&report, registering) {
            inbox_changed |= note_registration(&mut lock_of(shared), &custodian, r, now);
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
                eprintln!(
                    "raven-node custody: {}",
                    fetched_line(r, carrier.get(), &custodian)
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
        if over_tor.get() {
            lock_of(shared).onion_fetch_at.insert(custodian, now);
        }
        let missed = routes.is_empty() || all_failed;
        lock_of(shared).end_fetch(
            custodian,
            state,
            (now + next, empty),
            missed,
            Instant::now(),
        );
    }
    let mut s = lock_of(shared);
    s.tags = cache;
    s.register_tags = reg_cache;
    s.keep_targets(&target_keys);
    inbox_changed
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
/// delay for that next hop. Nothing while the handoff gate is closed (no
/// dial, no file). The next hops are visited in key order, or while carry
/// choice is live (Phase 6a P6.16) in the order of this node's own
/// predictability of meeting them ([`crate::learning::forward_order`]);
/// that changes only which goes first.
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
    for hop in &crate::learning::forward_order(&hops) {
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
            let mut dialled = false;
            let mut dial = |frames: &[Vec<u8>]| {
                dialled = true;
                dial_in_turn(&routes, &mut first, |(planned, route)| {
                    let got = (io.dial)(route, &expected, frames);
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
            out.dials += usize::from(dialled);
            let answers = match got {
                Ok(answers) => answers,
                Err(e) if e == handoff_gate_closed() => return out,
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
            .max(Duration::from_millis(200));
        let (dd, id) = (data_dir.clone(), Arc::clone(&identity));
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || fetch_pass(&dd, &id, &handle))
            .await
            .map_err(|e| format!("custody blocking join: {e}"))?;
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
    /// due again as soon as that pass ends if the pass reached nothing; a
    /// pass that reached it, or that nobody interrupted, keeps its own next
    /// time and its empty rounds, and another contact changes nothing.
    #[test]
    fn a_custodian_seen_during_its_fetch_is_due_again() {
        let mut s = Shared::default();
        let now = Instant::now();
        let c = [0xC5; 32];
        let later = now + BASE_INTERVAL;
        s.begin_fetch(&c);
        assert!(!s.wake(&[0xB5; 32], Wake::Moved, now), "not a custodian");
        s.end_fetch(c, FetchState::default(), (later, 2), true, now);
        assert_eq!(s.states[&c].1, later, "not seen: its own next time");
        assert_eq!(s.states[&c].2, 2);
        for (why, missed, due) in [
            (Wake::Moved, true, now),
            (Wake::Linked, true, now),
            (Wake::Moved, false, later),
            (Wake::Linked, false, later),
        ] {
            s.states.remove(&c);
            s.begin_fetch(&c);
            assert!(!s.wake(&c, why, now), "in a pass: no wake yet");
            s.end_fetch(c, FetchState::default(), (later, 2), missed, now);
            assert_eq!(
                (s.states[&c].1, s.states[&c].2),
                (due, 2),
                "{why:?} {missed}"
            );
            assert!(s.in_pass.is_none());
        }
        // Waiting for its next fetch: new routes make it due now, and the
        // fetcher wakes; its empty rounds stay.
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
    use std::cell::{Cell, RefCell};

    /// Custody live (no WAN), custody riding route hints and the LAN
    /// carrier open on this test thread; the letters held, whatever
    /// `RAVEN_LAB_LETTER` the suite runs with (with them a fetch pass also
    /// asks for letters, one more dial: the letter tests use `LettersOn`);
    /// cleared on drop.
    struct Gates;

    impl Gates {
        fn on(live: bool, hints: bool) -> Self {
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
            Self
        }
    }

    impl Drop for Gates {
        fn drop(&mut self) {
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
                row(&self.dave, "192.168.1.12:7420", &[]),
                row(&self.carol, "192.168.1.50:7420", &[]),
            ]);
            std::fs::write(self.dir().join("contacts.json"), rows.to_string()).unwrap();
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

    /// Carol's side of a custody dial: an empty page (or one that always
    /// has more), releases taken; or down.
    #[derive(Default)]
    struct Carol {
        dials: RefCell<Vec<Vec<Vec<u8>>>>,
        down: Cell<bool>,
        paging: Cell<bool>,
        path: Cell<Option<DeliveryPath>>,
    }

    impl Carol {
        fn dial(&self, frames: &[Vec<u8>]) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String> {
            self.dials.borrow_mut().push(frames.to_vec());
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
            self.dials.borrow().len()
        }

        /// The tags of every FETCH sent so far.
        fn fetched(&self) -> Vec<[u8; 16]> {
            let mut out = Vec::new();
            for frames in self.dials.borrow().iter() {
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

    /// One fetch pass of Alice at `now` / `wall`, Carol answering.
    fn pass(
        fix: &Fix,
        shared: &Mutex<Shared>,
        carol: &Carol,
        seen: &Seen,
        lan: bool,
        now: Instant,
        wall: u64,
    ) {
        let mut dial = |_: &OutboxRoute, expected: &str, frames: &[Vec<u8>]| {
            assert_eq!(expected, hex::encode(fix.carol), "only Carol is dialled");
            carol.dial(frames)
        };
        let mut home_changed = |n: usize| seen.homes.borrow_mut().push(n);
        let want = |c: &[u8; 32]| seen.wants.borrow_mut().push(*c);
        let finds = |_: &[u8; 32]| Vec::new();
        let mut io = PassIo {
            dial: &mut dial,
            want: &want,
            finds: &finds,
            find_failed: &|_, _| {},
            home_changed: &mut home_changed,
            lan,
            kick: &|_| {},
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
            let dialled = RefCell::new(Vec::new());
            let forgot = RefCell::new(Vec::new());
            let mut dial = |route: &OutboxRoute, _: &str, frames: &[Vec<u8>]| {
                dialled.borrow_mut().push(route.dial.clone());
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
            let find_failed = |c: &[u8; 32], d: &str| forgot.borrow_mut().push((*c, d.to_string()));
            let mut io = PassIo {
                dial: &mut dial,
                want: &|_| {},
                finds: &finds,
                find_failed: &find_failed,
                home_changed: &mut home_changed,
                lan: true,
                kick: &|_| {},
            };
            fetch_pass_with(
                &shared,
                fix.dir(),
                &fix.alice,
                Instant::now(),
                wall,
                &mut io,
            );
            let dialled = dialled.into_inner();
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
            assert_eq!(forgot.into_inner(), want, "{why}");
        }
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
        let mut dial = |route: &OutboxRoute, expected: &str, frames: &[Vec<u8>]| {
            w.net
                .dial(w.a.path(), route, expected, frames)
                .map(|replies| (replies, Some(DeliveryPath::Direct)))
        };
        let mut home_changed = |_: usize| {};
        let kick = |peer: &[u8; 32]| kicked.borrow_mut().push(*peer);
        let mut io = PassIo {
            dial: &mut dial,
            want: &|_| {},
            finds: &|_| Vec::new(),
            find_failed: &|_, _| {},
            home_changed: &mut home_changed,
            lan: true,
            kick: &kick,
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
        let calls = RefCell::new(Vec::<Vec<u8>>::new());
        let mut dial = |_: &OutboxRoute,
                        _: &str,
                        frames: &[Vec<u8>]|
         -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String> {
            calls.borrow_mut().push(
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
            dial: &mut dial,
            want: &|_| {},
            finds: &|_| Vec::new(),
            find_failed: &|_, _| {},
            home_changed: &mut home_changed,
            lan: true,
            kick: &kick,
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
            calls.into_inner(),
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
