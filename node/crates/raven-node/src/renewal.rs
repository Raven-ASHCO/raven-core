//! Proactive session renewal ([`raven_core::session_renewal`], Phase 3 item
//! 4): on every authenticated link with a contact, after a short settle,
//! renew the session when less than 12 h remain. A supervised task; with the
//! gate closed for the life of the process it idles and every hook is a
//! no-op.
//!
//! - **Links.** lan_direct and internet_direct (Internet direct and the p2p
//!   Raven link) call [`note_live_link`] once a contact's link authenticated:
//!   inbound in the trusted branch, outbound after the contact's verified
//!   RLB1 offer. The renewer's own probe and PairInit dials are not noted
//!   again (`in_flight`).
//! - **Settle.** A contact is stepped [`SETTLE`] after its first link (the
//!   earliest due wins), well inside libp2p's 60 s idle timeout, so the
//!   renewal can ride the connection the contact opened.
//! - **Recheck memo.** A step that found nothing due remembers when it will
//!   be (at most [`RECHECK_MAX`] ahead): links before then open no store.
//!   [`network_changed`] forgets the memo and the lapse marks.
//! - **Bounded.** At most [`GLOBAL_MAX`] renewals per [`GLOBAL_SPAN`] over all
//!   contacts; the per-contact budget is the store's
//!   ([`raven_core::session_renewal`]). A contact waiting for the other side
//!   after a lapse is stepped again only while its link is recent
//!   ([`LIVE_WINDOW`]). A busy send lock retries after [`LOCK_BUSY_RETRY`]
//!   (the round is counted inside the lock, so nothing was spent).
//! - **Early re-key** (Phase 6b R2, step P6.27). [`request_early`] (the
//!   security responder, after the store noted the request) forgets the
//!   contact's recheck memo and steps it now when its link is recent;
//!   otherwise on its next live link. A renewal it makes kicks the outbox,
//!   which runs the reset step that re-seals what the retired session held.
//! - **Logs.** Counts and fixed codes only, at most one line an hour per code.

#[cfg(test)]
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use raven_core::clock::now_ms;
use raven_core::indexed_session_store::IndexedSessionStore;
use raven_core::outbox::{send_lock_busy, OutboxCarrier};
use raven_core::session_renewal::{
    code, run_renewal_step, session_renewal_live_enabled, RenewEnv, RenewStep, Role,
    RENEW_LAPSED_FALLBACK_MS,
};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::netutil::LogLimiter;
use crate::outbox::{AttemptCtx, WorkerIo};

/// From a contact's first link to its step: below libp2p's 60 s idle timeout
/// (raven-swarm host.rs), so the contact's own connection can carry it.
const SETTLE: Duration = Duration::from_secs(15);
/// A link this recent still counts as live.
const LIVE_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Renewals over all contacts ...
const GLOBAL_MAX: usize = 6;
/// ... per this span.
const GLOBAL_SPAN: Duration = Duration::from_secs(600);
/// The peer's send lock was busy (or no outbox worker yet): try again after.
const LOCK_BUSY_RETRY: Duration = Duration::from_secs(5);
/// A recheck memo never reaches further than this.
const RECHECK_MAX: Duration = Duration::from_secs(3_600);
/// Contacts queued, and recheck memos, at most.
const MAX_TRACKED: usize = 1024;
/// Nothing queued: sleep this long unless a link wakes the task.
const IDLE: Duration = Duration::from_secs(3_600);
/// One log line per code per this window (not [`RENEWED`]).
const LOG_WINDOW: Duration = Duration::from_secs(3_600);
/// The code of a renewal's line: each renewal has a line of its own.
const RENEWED: &str = "RENEWED";
/// The log prefix.
const LOG_WHAT: &str = "raven-node renewal";

/// How the link came up (both are endpoint-authenticated contact links).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LiveLink {
    Inbound,
    Outbound,
}

/// A contact waiting for its step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pending {
    due: Instant,
    last_live: Instant,
    /// When this node first saw the pair lapsed on a live link (wall ms).
    lapsed_noticed_at_ms: Option<u64>,
}

#[derive(Debug, Default)]
struct Queue {
    running: bool,
    peers: HashMap<[u8; 32], Pending>,
    /// The contact a step works on now: its links are the renewer's own.
    in_flight: Option<[u8; 32]>,
    /// When the renewals of the last [`GLOBAL_SPAN`] were made.
    started: VecDeque<Instant>,
    /// Per contact: no step before this (nothing was due).
    recheck: HashMap<[u8; 32], Instant>,
    /// An early re-key was asked for the contact in flight: its step may
    /// have read the store before, so it is not memoized.
    early_in_flight: Option<[u8; 32]>,
}

/// A contact to step now, with its lapse mark.
type Pick = ([u8; 32], Option<u64>);

/// What the task does after a step besides the queue.
#[derive(Debug, Default, PartialEq, Eq)]
struct Effect {
    /// Kick the outbox for the contact (the session-reset step owns it).
    kick: bool,
    /// (code, line): one log line, limited per code.
    log: Option<(&'static str, String)>,
}

fn carrier_name(carrier: OutboxCarrier) -> &'static str {
    match carrier {
        OutboxCarrier::Lan => "lan",
        OutboxCarrier::Internet => "internet",
        OutboxCarrier::P2p => "p2p",
        OutboxCarrier::Nearby => "nearby",
        OutboxCarrier::Onion => "onion",
    }
}

/// Waits of the budget alone: until then a step can only answer the same
/// wait (or not due), so they are memoized like "not due".
fn budget_wait(code: &str) -> bool {
    [
        code::RENEW_BACKOFF,
        code::RENEW_DAILY_CAP,
        code::REPAIR_COOLDOWN,
    ]
    .contains(&code)
}

impl Queue {
    /// A live link with `peer` at `now`: `true` when it was queued (wake the
    /// task).
    fn note(&mut self, peer: &[u8; 32], now: Instant) -> bool {
        if !self.running || self.in_flight == Some(*peer) {
            return false;
        }
        match self.recheck.get(peer) {
            Some(until) if *until > now => return false,
            Some(_) => {
                self.recheck.remove(peer);
            }
            None => {}
        }
        if !self.peers.contains_key(peer) && self.peers.len() >= MAX_TRACKED {
            return false;
        }
        let p = self.peers.entry(*peer).or_insert(Pending {
            due: now + SETTLE,
            last_live: now,
            lapsed_noticed_at_ms: None,
        });
        p.last_live = now;
        // The earliest wins; the step re-checks under the peer's lock.
        p.due = p.due.min(now + SETTLE);
        true
    }

    /// An early re-key was noted for `peer` at `now`: `true` when it is
    /// queued to step now (wake the task). Otherwise its next live link
    /// queues it (the recheck memo is gone).
    fn request_early(&mut self, peer: &[u8; 32], now: Instant) -> bool {
        self.recheck.remove(peer);
        if self.in_flight == Some(*peer) {
            self.early_in_flight = Some(*peer);
            return false;
        }
        match self.peers.get_mut(peer) {
            Some(p) if self.running => {
                p.due = p.due.min(now);
                true
            }
            _ => false,
        }
    }

    fn network_changed(&mut self) {
        self.recheck.clear();
        for p in self.peers.values_mut() {
            p.lapsed_noticed_at_ms = None;
        }
    }

    /// The contact to step now (with its lapse mark), or how long to wait.
    /// Contacts whose link went quiet are dropped first.
    fn next_due(&mut self, now: Instant) -> (Option<Pick>, Duration) {
        self.peers
            .retain(|_, p| now.saturating_duration_since(p.last_live) <= LIVE_WINDOW);
        while self
            .started
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= GLOBAL_SPAN)
        {
            self.started.pop_front();
        }
        let Some((peer, p)) = self.peers.iter().min_by_key(|(k, p)| (p.due, **k)) else {
            return (None, IDLE);
        };
        if p.due > now {
            return (None, p.due - now);
        }
        if let Some(first) = self
            .started
            .front()
            .filter(|_| self.started.len() >= GLOBAL_MAX)
        {
            return (None, (*first + GLOBAL_SPAN).saturating_duration_since(now));
        }
        (Some((*peer, p.lapsed_noticed_at_ms)), Duration::ZERO)
    }

    /// No step for `peer` before `at_ms` (wall), and never past
    /// [`RECHECK_MAX`] from `now`; `None`: [`RECHECK_MAX`].
    fn memo(&mut self, peer: &[u8; 32], at_ms: Option<u64>, now: Instant, wall: u64) {
        if self.early_in_flight == Some(*peer) {
            return;
        }
        let wait = at_ms.map_or(RECHECK_MAX, |at| {
            Duration::from_millis(at.saturating_sub(wall)).min(RECHECK_MAX)
        });
        self.recheck.retain(|_, until| *until > now);
        if self.recheck.len() < MAX_TRACKED || self.recheck.contains_key(peer) {
            self.recheck.insert(*peer, now + wait);
        }
    }

    /// The step for `peer` ended at `now` (`wall`) with `result` (`None`: no
    /// outbox worker to step with yet).
    fn apply(
        &mut self,
        peer: &[u8; 32],
        result: Option<Result<RenewStep, String>>,
        now: Instant,
        wall: u64,
    ) -> Effect {
        self.in_flight = None;
        let early_in_flight = self.early_in_flight == Some(*peer);
        let effect = self.apply_step(peer, result, now, wall);
        if early_in_flight {
            self.early_in_flight = None;
        }
        effect
    }

    fn apply_step(
        &mut self,
        peer: &[u8; 32],
        result: Option<Result<RenewStep, String>>,
        now: Instant,
        wall: u64,
    ) -> Effect {
        let mut effect = Effect::default();
        let step = match result {
            None => {
                self.retry(peer, now + LOCK_BUSY_RETRY);
                return effect;
            }
            // A local lock, not the contact: no failure was counted, and a
            // round counted in the step's first lock whose PairInit was never
            // created was given back (run_renewal_step). Only a busy lock in
            // the step's own failure bookkeeping leaves its round counted:
            // the retry then waits out the cooldown.
            Some(Err(e)) if send_lock_busy(&e) => {
                self.retry(peer, now + LOCK_BUSY_RETRY);
                return effect;
            }
            Some(Err(_)) => {
                effect.log = Some(("STORE", "store error (STORE)".into()));
                self.peers.remove(peer);
                return effect;
            }
            Some(Ok(step)) => step,
        };
        match step {
            RenewStep::Renewed { role, carrier, .. } => {
                self.started.push_back(now);
                // An early re-key retired the older sessions: the outbox
                // runs the reset step that re-seals what they held.
                effect.kick = role == Role::Early;
                effect.log = Some((
                    RENEWED,
                    format!(
                        "renewed a session ({}) over {}",
                        role.label(),
                        carrier_name(carrier)
                    ),
                ));
            }
            RenewStep::NotDue { recheck_at_ms } => self.memo(peer, recheck_at_ms, now, wall),
            // The session-reset step owns the contact: the outbox runs it.
            RenewStep::Held(code::RENEW_RESET_PENDING) => effect.kick = true,
            RenewStep::Held(held) => effect.log = Some((held, format!("held ({held})"))),
            RenewStep::Unreachable(e) => {
                let why = crate::outbox::dial_error_code(&e);
                effect.log = Some((why, format!("contact not reachable ({why})")));
            }
            RenewStep::Wait {
                until_ms,
                code: code::RENEW_WAIT_PEER,
            } => {
                let due = now + Duration::from_millis(until_ms.saturating_sub(wall));
                if let Some(p) = self.peers.get_mut(peer) {
                    if due <= p.last_live + LIVE_WINDOW {
                        // The step took "noticed" as its own now.
                        p.lapsed_noticed_at_ms
                            .get_or_insert(until_ms.saturating_sub(RENEW_LAPSED_FALLBACK_MS));
                        p.due = due;
                        return effect;
                    }
                }
            }
            RenewStep::Wait {
                until_ms,
                code: why,
            } => {
                if budget_wait(why) {
                    self.memo(peer, Some(until_ms), now, wall);
                }
            }
        }
        self.peers.remove(peer);
        effect
    }

    fn retry(&mut self, peer: &[u8; 32], at: Instant) {
        if let Some(p) = self.peers.get_mut(peer) {
            p.due = at;
        }
    }
}

/// The renewer's shared state: its queue, and the wake-up for its task.
struct Renewer {
    queue: Mutex<Queue>,
    wake: Notify,
}

impl Renewer {
    fn new() -> Self {
        Self {
            queue: Mutex::new(Queue::default()),
            wake: Notify::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn note(&self, peer: &[u8; 32]) {
        let wake = self.lock().note(peer, Instant::now());
        if wake {
            self.wake.notify_one();
        }
    }
}

fn global() -> &'static Renewer {
    static RENEWER: OnceLock<Renewer> = OnceLock::new();
    RENEWER.get_or_init(Renewer::new)
}

#[cfg(test)]
thread_local! {
    /// [`RunningForTest`]: this thread's own queue (a `#[tokio::test]` runs
    /// both ends of a loopback link on its thread).
    static FOR_TEST: RefCell<Option<Queue>> = const { RefCell::new(None) };
}

/// A live, authenticated link with the contact `peer`: renew soon if due. A
/// no-op while the renewer does not run (the gate closed) and for the
/// renewer's own dials.
pub(crate) fn note_live_link(peer: &[u8; 32], _how: LiveLink) {
    #[cfg(test)]
    if FOR_TEST
        .with(|q| {
            q.borrow_mut()
                .as_mut()
                .map(|q| q.note(peer, Instant::now()))
        })
        .is_some()
    {
        return;
    }
    global().note(peer);
}

/// Phase 6b R2 (step P6.27): an early re-key with `peer` was noted in the
/// store ([`raven_core::session_renewal::request_early`]): step it now when
/// its link is recent, else on its next live link (or the dial an outbox
/// kick makes). A no-op while the renewer does not run.
pub(crate) fn request_early(peer: &[u8; 32]) {
    #[cfg(test)]
    if FOR_TEST
        .with(|q| {
            q.borrow_mut()
                .as_mut()
                .map(|q| q.request_early(peer, Instant::now()))
        })
        .is_some()
    {
        return;
    }
    let r = global();
    let wake = r.lock().request_early(peer, Instant::now());
    if wake {
        r.wake.notify_one();
    }
}

/// This machine's network changed (`netwatch`): the recheck memos and lapse
/// marks were made on the old network.
pub(crate) fn network_changed() {
    global().lock().network_changed();
}

/// Is the renewer running in this process (`raven-node service`, gate open)?
pub(crate) fn is_running() -> bool {
    #[cfg(test)]
    if let Some(running) = FOR_TEST.with(|q| q.borrow().as_ref().map(|q| q.running)) {
        return running;
    }
    global().lock().running
}

/// The supervised renewer task.
pub async fn run_renewer() -> Result<(), String> {
    run_gated(
        global(),
        session_renewal_live_enabled(),
        |peer, lapsed| async move {
            let ctx = crate::outbox::attempt_ctx()?;
            Some(
                tokio::task::spawn_blocking(move || renew_peer(&ctx, &peer, lapsed))
                    .await
                    .unwrap_or_else(|_| Err("renewal step panicked".into())),
            )
        },
        kick_outbox,
    )
    .await
}

fn kick_outbox(peer: &[u8; 32]) {
    let _ = crate::outbox::kick(Some(peer), false, false);
}

/// One renewal step for `peer` with the outbox worker's context: its plan
/// (contact, gates, learned and beacon routes, route memory) and its store
/// and dialer under the peer's send lock.
fn renew_peer(ctx: &AttemptCtx, peer: &[u8; 32], lapsed: Option<u64>) -> Result<RenewStep, String> {
    let wall = now_ms();
    let plan = match crate::outbox::plan_inputs(ctx, peer, wall, true) {
        Ok(plan) => plan,
        Err(held) => return Ok(RenewStep::Held(held)),
    };
    let routes = plan.renewal_routes(peer);
    let mut store = IndexedSessionStore::open(&ctx.data_dir).map_err(|e| e.redacted_display())?;
    let env = RenewEnv {
        data_dir: &ctx.data_dir,
        identity: &ctx.identity,
        peer: *peer,
        routes: &routes,
        pinned: plan.contact.pinned,
        lapsed_noticed_at_ms: lapsed,
        now_ms: wall,
    };
    run_renewal_step(&env, &mut WorkerIo::new(ctx, peer, &mut store))
}

/// `running` while the task runs.
struct Running<'a>(&'a Renewer);

impl<'a> Running<'a> {
    fn set(r: &'a Renewer) -> Self {
        r.lock().running = true;
        Self(r)
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        let mut q = self.0.lock();
        q.running = false;
        q.in_flight = None;
    }
}

/// The task: idles while `live` is false; otherwise steps each due contact
/// with `step` (`None`: no outbox worker yet) and applies the result.
async fn run_gated<S, Fut>(
    r: &Renewer,
    live: bool,
    mut step: S,
    kick: fn(&[u8; 32]),
) -> Result<(), String>
where
    S: FnMut([u8; 32], Option<u64>) -> Fut,
    Fut: Future<Output = Option<Result<RenewStep, String>>>,
{
    if !live {
        // Closed for the life of the process (lab switches are read at
        // start): nothing is queued, nothing opened.
        std::future::pending::<()>().await;
    }
    let _running = Running::set(r);
    loop {
        let (pick, wait) = r.lock().next_due(Instant::now());
        if let Some((peer, lapsed)) = pick {
            r.lock().in_flight = Some(peer);
            let result = step(peer, lapsed).await;
            let effect = r.lock().apply(&peer, result, Instant::now(), now_ms());
            if effect.kick {
                kick(&peer);
            }
            if let Some((code, line)) = effect.log {
                log_code(code, &line);
            }
            continue;
        }
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = r.wake.notified() => {}
        }
    }
}

type Limiters = Mutex<HashMap<&'static str, LogLimiter>>;

/// One line per code per [`LOG_WINDOW`], except a renewal: every one has its
/// line (review C-3: the fault matrix and C31 count them to see that no
/// second renewal follows; [`GLOBAL_MAX`] per [`GLOBAL_SPAN`] and each
/// contact's budget already bound them).
fn log_code(code: &'static str, line: &str) {
    static LOGS: OnceLock<Limiters> = OnceLock::new();
    match log_hits(
        LOGS.get_or_init(Mutex::default),
        code,
        std::time::Instant::now(),
    ) {
        None => {}
        Some(1) => eprintln!("{LOG_WHAT}: {line}"),
        Some(n) => eprintln!(
            "{LOG_WHAT}: {line} (and {} more like it in the last {}s)",
            n - 1,
            LOG_WINDOW.as_secs()
        ),
    }
}

/// [`log_code`]'s count: `Some(n)` writes a line now for `n` events (this
/// one included), `None` writes nothing.
fn log_hits(logs: &Limiters, code: &'static str, now: std::time::Instant) -> Option<u64> {
    if code == RENEWED {
        return Some(1);
    }
    logs.lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(code)
        .or_insert_with(|| LogLimiter::new(LOG_WINDOW))
        .hit_at(now)
}

/// Marks the renewer running for the current thread until dropped, with a
/// queue of its own ([`note_live_link`], [`is_running`]); see
/// [`queued_for_test`].
#[cfg(test)]
pub(crate) struct RunningForTest;

#[cfg(test)]
impl RunningForTest {
    pub(crate) fn set() -> Self {
        FOR_TEST.with(|q| {
            *q.borrow_mut() = Some(Queue {
                running: true,
                ..Queue::default()
            })
        });
        Self
    }
}

#[cfg(test)]
impl Drop for RunningForTest {
    fn drop(&mut self) {
        FOR_TEST.with(|q| *q.borrow_mut() = None);
    }
}

/// Under [`RunningForTest`]: is `peer` queued for a step?
#[cfg(test)]
pub(crate) fn queued_for_test(peer: &[u8; 32]) -> bool {
    FOR_TEST.with(|q| {
        q.borrow()
            .as_ref()
            .is_some_and(|q| q.peers.contains_key(peer))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use raven_core::session_renewal::Role;

    // Each test works on a `Renewer` of its own: the process-wide one is
    // never running in tests.

    type Calls = Arc<Mutex<Vec<([u8; 32], Instant, Option<u64>)>>>;

    fn renewed() -> RenewStep {
        RenewStep::Renewed {
            role: Role::Primary,
            carrier: OutboxCarrier::Lan,
            retried_pending: false,
        }
    }

    fn no_kick(_: &[u8; 32]) {}

    /// The renewer task on `r` with `answer` for each step (recorded in the
    /// returned calls); started and running when this returns.
    async fn spawn_renewer(
        r: &Arc<Renewer>,
        kick: fn(&[u8; 32]),
        answer: impl Fn(&[u8; 32], usize, Option<u64>) -> Option<Result<RenewStep, String>>
            + Send
            + Sync
            + 'static,
    ) -> (Calls, tokio::task::JoinHandle<Result<(), String>>) {
        let calls: Calls = Arc::default();
        let (r2, log) = (Arc::clone(r), Arc::clone(&calls));
        let task = tokio::spawn(async move {
            run_gated(
                &r2,
                true,
                |peer, lapsed| {
                    let n = {
                        let mut log = log.lock().unwrap();
                        log.push((peer, Instant::now(), lapsed));
                        log.iter().filter(|(p, _, _)| *p == peer).count()
                    };
                    std::future::ready(answer(&peer, n, lapsed))
                },
                kick,
            )
            .await
        });
        tokio::task::yield_now().await;
        assert!(r.lock().running);
        (calls, task)
    }

    fn count(calls: &Calls, peer: &[u8; 32]) -> usize {
        calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _, _)| p == peer)
            .count()
    }

    fn times(calls: &Calls, peer: &[u8; 32]) -> Vec<Instant> {
        calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _, _)| p == peer)
            .map(|(_, t, _)| *t)
            .collect()
    }

    /// Phase 6b R2 (P6.27): an early re-key forgets the contact's recheck
    /// memo and steps a contact whose link is recent now (no settle); one
    /// with no recent link waits for its next link; the step in flight when
    /// it came is not memoized; an early renewal kicks the outbox (the reset
    /// step re-seals what the retired session held), another does not.
    #[tokio::test(start_paused = true)]
    async fn an_early_rekey_steps_a_live_contact_now() {
        let (a, b, t0) = ([0xE1; 32], [0xE2; 32], Instant::now());
        let s = Duration::from_secs;
        assert!(!Queue::default().request_early(&a, t0), "not running");
        let mut q = Queue {
            running: true,
            ..Queue::default()
        };
        // Nothing was due: memoized, a link queues nothing.
        q.memo(&a, None, t0, 0);
        assert!(!q.note(&a, t0));
        // No recent link: the memo goes, the next link queues it.
        assert!(!q.request_early(&a, t0 + s(1)));
        assert!(q.peers.is_empty());
        assert!(q.note(&a, t0 + s(2)));
        assert_eq!(
            q.next_due(t0 + s(3)),
            (None, SETTLE - s(1)),
            "a link settles first"
        );
        // Queued: due now.
        assert!(q.request_early(&a, t0 + s(3)));
        assert_eq!(q.next_due(t0 + s(3)), (Some((a, None)), Duration::ZERO));
        // In flight: its "not due" is not memoized.
        q.in_flight = Some(a);
        assert!(!q.request_early(&a, t0 + s(4)));
        let effect = q.apply(
            &a,
            Some(Ok(RenewStep::NotDue {
                recheck_at_ms: Some(u64::MAX),
            })),
            t0 + s(5),
            0,
        );
        assert_eq!(effect, Effect::default());
        assert!(!q.recheck.contains_key(&a));
        assert!(q.note(&a, t0 + s(6)), "the next link steps it");
        // An early renewal kicks the outbox; another renewal does not.
        assert!(q.note(&b, t0 + s(6)));
        q.in_flight = Some(b);
        let early = RenewStep::Renewed {
            role: Role::Early,
            carrier: OutboxCarrier::Lan,
            retried_pending: false,
        };
        assert!(q.apply(&b, Some(Ok(early)), t0 + s(7), 0).kick);
        assert!(q.note(&b, t0 + s(8)));
        assert!(!q.apply(&b, Some(Ok(renewed())), t0 + s(9), 0).kick);
    }

    #[tokio::test(start_paused = true)]
    async fn note_live_link_settles_and_keeps_the_earliest_due() {
        let (a, t0) = ([0xA1; 32], Instant::now());
        // Not running (the gate closed): nothing is queued.
        let mut q = Queue::default();
        assert!(!q.note(&a, t0));
        assert!(q.peers.is_empty());
        let mut q = Queue {
            running: true,
            ..Queue::default()
        };
        assert!(q.note(&a, t0));
        assert_eq!(
            q.next_due(t0 + Duration::from_secs(10)),
            (None, Duration::from_secs(5))
        );
        // A second link keeps the first due and refreshes the link.
        assert!(q.note(&a, t0 + Duration::from_secs(10)));
        assert_eq!(q.peers[&a].due, t0 + SETTLE);
        assert_eq!(q.peers[&a].last_live, t0 + Duration::from_secs(10));
        // A later due (a lapsed wait, a busy lock) is pulled in to the settle.
        q.peers.get_mut(&a).unwrap().due = t0 + Duration::from_secs(300);
        q.note(&a, t0 + Duration::from_secs(20));
        assert_eq!(q.peers[&a].due, t0 + Duration::from_secs(20) + SETTLE);
        assert_eq!(
            q.next_due(t0 + Duration::from_secs(40)),
            (Some((a, None)), Duration::ZERO)
        );

        // The task steps the contact once, SETTLE after its first link.
        let r = Arc::new(Renewer::new());
        let (calls, task) = spawn_renewer(&r, no_kick, |_, _, _| Some(Ok(renewed()))).await;
        let t0 = Instant::now();
        r.note(&a);
        tokio::time::sleep(Duration::from_secs(5)).await;
        r.note(&a);
        tokio::time::sleep(Duration::from_secs(9)).await;
        assert_eq!(count(&calls, &a), 0);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(times(&calls, &a), [t0 + SETTLE]);
        tokio::time::sleep(Duration::from_secs(3_600)).await;
        assert_eq!(count(&calls, &a), 1);
        assert!(r.lock().peers.is_empty());
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn own_dials_do_not_requeue() {
        let (a, b) = ([0xA2; 32], [0xB2; 32]);
        let r = Arc::new(Renewer::new());
        let r2 = Arc::clone(&r);
        // The step's own dials link with the contact (and another contact
        // links meanwhile).
        let (calls, task) = spawn_renewer(&r, no_kick, move |peer, _, _| {
            r2.note(peer);
            if *peer == a {
                r2.note(&b);
            }
            Some(Ok(renewed()))
        })
        .await;
        r.note(&a);
        tokio::time::sleep(Duration::from_secs(3_600)).await;
        assert_eq!(count(&calls, &a), 1, "our own dial did not queue it again");
        assert_eq!(count(&calls, &b), 1, "another contact's link did");
        assert!(r.lock().peers.is_empty());
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn the_global_bucket_spreads_a_burst() {
        let peers: Vec<[u8; 32]> = (0..10u8).map(|i| [0xC0 + i; 32]).collect();
        let r = Arc::new(Renewer::new());
        let (calls, task) = spawn_renewer(&r, no_kick, |_, _, _| Some(Ok(renewed()))).await;
        let t0 = Instant::now();
        for p in &peers {
            r.note(p);
        }
        tokio::time::sleep(Duration::from_secs(9 * 60)).await;
        assert_eq!(calls.lock().unwrap().len(), GLOBAL_MAX);
        tokio::time::sleep(Duration::from_secs(2 * 60)).await;
        let all = calls.lock().unwrap().clone();
        assert_eq!(all.len(), 10);
        assert!(all[GLOBAL_MAX..]
            .iter()
            .all(|(_, t, _)| *t >= t0 + SETTLE + GLOBAL_SPAN));
        let mut stepped: Vec<[u8; 32]> = all.iter().map(|(p, _, _)| *p).collect();
        stepped.sort();
        assert_eq!(stepped, peers, "each contact once");
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn wait_peer_is_retried_only_while_the_link_is_recent() {
        let (near, far) = ([0xD1; 32], [0xD2; 32]);
        let until = Arc::new(Mutex::new(HashMap::new()));
        let u2 = Arc::clone(&until);
        let r = Arc::new(Renewer::new());
        let (calls, task) = spawn_renewer(&r, no_kick, move |peer, n, _| {
            if n > 1 {
                return Some(Ok(renewed()));
            }
            // The contact's smaller key goes first: 10 min, and 20 min (past
            // the live window) for the other.
            let wait = if *peer == near { 10 } else { 20 };
            let until_ms = now_ms() + wait * 60_000;
            u2.lock().unwrap().insert(*peer, until_ms);
            Some(Ok(RenewStep::Wait {
                until_ms,
                code: code::RENEW_WAIT_PEER,
            }))
        })
        .await;
        let t0 = Instant::now();
        r.note(&near);
        r.note(&far);
        tokio::time::sleep(Duration::from_secs(30 * 60)).await;
        let near_times = times(&calls, &near);
        assert_eq!(near_times.len(), 2, "retried once its wait ended");
        let first_wait = near_times[1] - near_times[0];
        assert!(
            first_wait <= Duration::from_secs(600) && first_wait > Duration::from_secs(590),
            "{first_wait:?}"
        );
        let noticed = until.lock().unwrap()[&near] - RENEW_LAPSED_FALLBACK_MS;
        assert_eq!(calls.lock().unwrap().last().unwrap().2, Some(noticed));
        assert_eq!(times(&calls, &far), [t0 + SETTLE], "the link went quiet");
        assert!(r.lock().peers.is_empty());
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn lock_busy_retries_in_5s_without_counting() {
        let (busy, early) = ([0xE1; 32], [0xE2; 32]);
        let r = Arc::new(Renewer::new());
        let (calls, task) =
            spawn_renewer(&r, no_kick, move |peer, n, _| match (n, *peer == busy) {
                (1, true) => Some(Err("lan lock: database is locked".into())),
                // No outbox worker yet: the same retry.
                (1, false) => None,
                _ => Some(Ok(RenewStep::NotDue {
                    recheck_at_ms: None,
                })),
            })
            .await;
        let t0 = Instant::now();
        r.note(&busy);
        r.note(&early);
        tokio::time::sleep(Duration::from_secs(60)).await;
        for p in [busy, early] {
            assert_eq!(
                times(&calls, &p),
                [t0 + SETTLE, t0 + SETTLE + LOCK_BUSY_RETRY]
            );
        }
        assert!(
            r.lock().started.is_empty(),
            "nothing was renewed or counted"
        );
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn gate_off_note_is_a_noop_and_the_task_idles() {
        raven_core::session_renewal::set_lab_session_renewal_for_this_thread(Some(false));
        let live = session_renewal_live_enabled();
        raven_core::session_renewal::set_lab_session_renewal_for_this_thread(None);
        assert!(!live);
        let a = [0xF1; 32];
        let r = Arc::new(Renewer::new());
        let stepped = Arc::new(AtomicUsize::new(0));
        let (r2, s2) = (Arc::clone(&r), Arc::clone(&stepped));
        let task = tokio::spawn(async move {
            run_gated(
                &r2,
                live,
                |_, _| {
                    s2.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Some(Ok(renewed())))
                },
                no_kick,
            )
            .await
        });
        tokio::task::yield_now().await;
        r.note(&a);
        tokio::time::sleep(Duration::from_secs(3_600)).await;
        assert!(!r.lock().running);
        assert!(r.lock().peers.is_empty());
        assert_eq!(stepped.load(Ordering::SeqCst), 0);
        assert!(!task.is_finished(), "it idles, it does not end");
        task.abort();
        // The process-wide hooks are no-ops too: no renewer runs here.
        note_live_link(&a, LiveLink::Inbound);
        assert!(!is_running());
        assert!(!global().lock().peers.contains_key(&a));
    }

    static KICKED: Mutex<Vec<[u8; 32]>> = Mutex::new(Vec::new());

    fn record_kick(peer: &[u8; 32]) {
        KICKED.lock().unwrap().push(*peer);
    }

    #[tokio::test(start_paused = true)]
    async fn reset_pending_kicks_the_outbox() {
        let (reset, fork) = ([0x91; 32], [0x92; 32]);
        let r = Arc::new(Renewer::new());
        let (calls, task) = spawn_renewer(&r, record_kick, move |peer, _, _| {
            Some(Ok(RenewStep::Held(if *peer == reset {
                code::RENEW_RESET_PENDING
            } else {
                raven_core::session_reset::code::PEER_IDENTITY_FORK
            })))
        })
        .await;
        r.note(&reset);
        r.note(&fork);
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(count(&calls, &reset), 1);
        assert_eq!(count(&calls, &fork), 1);
        let kicked = KICKED.lock().unwrap().clone();
        assert!(kicked.contains(&reset), "the reset step runs in the outbox");
        assert!(!kicked.contains(&fork), "other holds only log");
        assert!(r.lock().peers.is_empty());
        task.abort();
    }

    /// The memo: a contact whose session is not due opens no store again
    /// until it is (at most an hour), however often it links; a network
    /// change forgets it. Budget waits are memoized the same way.
    #[tokio::test(start_paused = true)]
    async fn recheck_memo_skips_store_opens_until_due_and_network_change_clears_it() {
        let (a, capped) = ([0x81; 32], [0x82; 32]);
        let r = Arc::new(Renewer::new());
        let (calls, task) = spawn_renewer(&r, no_kick, move |peer, _, _| {
            Some(Ok(if *peer == a {
                RenewStep::NotDue {
                    recheck_at_ms: Some(now_ms() + 2 * 3_600_000),
                }
            } else {
                RenewStep::Wait {
                    until_ms: now_ms() + 20 * 60_000,
                    code: code::RENEW_DAILY_CAP,
                }
            }))
        })
        .await;
        for _ in 0..60 {
            r.note(&a);
            r.note(&capped);
            tokio::time::sleep(Duration::from_secs(55)).await;
        }
        assert_eq!(count(&calls, &a), 1, "one store open over 60 links");
        // The cap's memo ended after 20 min: one more step then.
        assert_eq!(count(&calls, &capped), 3);
        // A network change forgets the memo.
        r.lock().network_changed();
        r.note(&a);
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert_eq!(count(&calls, &a), 2);
        // An hour at most: then the next link steps again.
        tokio::time::sleep(RECHECK_MAX).await;
        r.note(&a);
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert_eq!(count(&calls, &a), 3);
        task.abort();
    }

    /// Review C-3: a second renewal within the hour has its own line (the
    /// harnesses count them); other codes stay one line per hour.
    #[test]
    fn every_renewal_is_logged_other_codes_once_an_hour() {
        let logs = Limiters::default();
        let now = std::time::Instant::now();
        assert_eq!(log_hits(&logs, RENEWED, now), Some(1));
        assert_eq!(
            log_hits(&logs, RENEWED, now + Duration::from_secs(1)),
            Some(1)
        );
        let held = code::RENEW_RESET_PENDING;
        assert_eq!(log_hits(&logs, held, now), Some(1));
        assert_eq!(log_hits(&logs, held, now + Duration::from_secs(1)), None);
        assert_eq!(log_hits(&logs, held, now + LOG_WINDOW), Some(2));
    }

    #[test]
    fn network_change_clears_the_lapse_marks() {
        let now = Instant::now();
        let mut q = Queue {
            running: true,
            ..Queue::default()
        };
        let a = [0x71; 32];
        q.note(&a, now);
        q.peers.get_mut(&a).unwrap().lapsed_noticed_at_ms = Some(5);
        q.recheck.insert([0x72; 32], now + RECHECK_MAX);
        q.network_changed();
        assert_eq!(q.peers[&a].lapsed_noticed_at_ms, None);
        assert!(q.recheck.is_empty());
    }

    #[test]
    fn the_thread_mark_queues_contacts_on_this_thread_only() {
        let a = [0x61; 32];
        assert!(!is_running());
        {
            let _running = RunningForTest::set();
            assert!(is_running());
            note_live_link(&a, LiveLink::Outbound);
            assert!(queued_for_test(&a));
            assert!(!global().lock().peers.contains_key(&a));
            let other = std::thread::spawn(is_running).join().unwrap();
            assert!(!other);
        }
        assert!(!is_running());
        assert!(!queued_for_test(&a));
    }
}
