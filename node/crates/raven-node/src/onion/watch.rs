//! The Tor helper's watchdogs and restart policy (design
//! `docs/design/2026-10-tor-fallback.md` §3.7), as pure state: the
//! supervisor (`super::supervise`) feeds it the helper's events and the
//! clock, and kills or restarts the helper when it says so.
//!
//! - **Progress watchdog:** during bootstrap, no new progress for
//!   [`STALL_EARLY`] while no directory is in (Arti reports nothing while
//!   it downloads the consensus, so a slow link sits at 15 % for a while)
//!   or [`PROGRESS_STALL`] later kills the helper.
//! - **Bootstrap cap:** a helper not ready within [`BOOTSTRAP_MAX`] is
//!   killed, even while it still makes progress.
//! - **Liveness:** a helper that answers no ping for [`PING_DEAD`] is
//!   killed, during bootstrap too (a hung helper is this computer's
//!   problem, not the network's).
//! - **Blame ([`Life::blame`]):** a bootstrap that ended says where the
//!   trouble is: the network (no Tor relay answered, or Tor says offline,
//!   filtered, can't reach Tor) or this computer (the helper crashed, hung
//!   or said a local error; Tor's clock check failed; or it got stuck after
//!   Tor relays answered, Arti issue #2726).
//! - **Backoff:** a helper that failed is started again after
//!   [`RESTART_MIN`] doubling to [`RESTART_MAX`]; a blocked network after
//!   [`BLOCKED_RETRY_MIN`] doubling to the same cap. A helper that ran
//!   [`STABLE_AFTER`] starts the count over. A restart for a network change
//!   or a wake waits for nothing.
//! - **Fresh guard state:** after [`FRESH_STATE_AFTER`] stuck bootstraps
//!   in a row the next start sets the old guard state aside (Arti issue
//!   #2534).

use std::time::{Duration, Instant};

use super::proto;

/// No new bootstrap progress this long while no directory is in (up to
/// 15 %: connecting, then the consensus download, which reports nothing
/// until it is complete).
pub(crate) const STALL_EARLY: Duration = Duration::from_secs(120);
/// No new bootstrap progress this long once the directory is loading.
pub(crate) const PROGRESS_STALL: Duration = Duration::from_secs(60);
/// No bootstrap takes longer, progress or not.
pub(crate) const BOOTSTRAP_MAX: Duration = Duration::from_secs(5 * 60);
/// How often the helper is pinged (from its start).
pub(crate) const PING_EVERY: Duration = Duration::from_secs(20);
/// A helper silent this long is hung.
pub(crate) const PING_DEAD: Duration = Duration::from_secs(60);
/// The first restart wait after a failure.
pub(crate) const RESTART_MIN: Duration = Duration::from_secs(5);
/// The first retry wait after a blocked bootstrap.
pub(crate) const BLOCKED_RETRY_MIN: Duration = Duration::from_secs(30);
/// No wait is longer.
pub(crate) const RESTART_MAX: Duration = Duration::from_secs(10 * 60);
/// A helper that ran this long counts its failures from zero again.
pub(crate) const STABLE_AFTER: Duration = Duration::from_secs(10 * 60);
/// Stuck bootstraps in a row before a fresh guard state.
pub(crate) const FRESH_STATE_AFTER: u32 = 3;
/// Up to this percent no directory is in yet.
const EARLY_PCT: u8 = 15;
/// The longest helper error text kept.
const MAX_ERROR: usize = 80;

/// Why the supervisor ends a helper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum End {
    /// Not ready within [`BOOTSTRAP_MAX`].
    BootstrapBudget,
    /// No bootstrap progress for [`STALL_EARLY`] or [`PROGRESS_STALL`].
    ProgressStall,
    /// No pong for [`PING_DEAD`].
    Unresponsive,
    /// The helper exited (or could not be started).
    Exited,
    /// The helper said Tor is too old for the network (Arti's exit on an
    /// unsupported protocol version, issue #1932).
    Obsolete,
    /// This computer's network changed (netwatch).
    NetworkChanged,
    /// This computer woke from sleep (netwatch).
    Woke,
}

impl End {
    /// A restart for this end waits no backoff and is no failure.
    pub(crate) fn immediate(self) -> bool {
        matches!(self, Self::NetworkChanged | Self::Woke)
    }

    /// The bootstrap got stuck (counts toward a fresh guard state).
    pub(crate) fn stuck(self) -> bool {
        matches!(self, Self::BootstrapBudget | Self::ProgressStall)
    }

    /// The status line's reason.
    pub(crate) fn words(self) -> &'static str {
        match self {
            Self::BootstrapBudget => "not ready within 5 minutes",
            Self::ProgressStall => "the Tor start stopped making progress",
            Self::Unresponsive => "the Tor helper stopped answering",
            Self::Exited => "the Tor helper stopped",
            Self::Obsolete => "this Tor version is too old for the network",
            Self::NetworkChanged => "network changed",
            Self::Woke => "woke from sleep",
        }
    }
}

/// Where the trouble is when a helper ended ([`Life::blame`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Blame {
    /// Nobody's: a restart (network change, wake, a ready helper that
    /// stopped, an old Tor).
    Restart,
    /// The network kept Tor out; the short reason.
    Network(String),
    /// Tor could not start on this computer; the short reason.
    ThisComputer(String),
}

/// One helper's life, as the watchdogs see it, with its last words (states
/// and fixed tags only).
#[derive(Clone, Debug)]
pub(crate) struct Life {
    started: Instant,
    last_progress: Instant,
    pct: u8,
    ready_at: Option<Instant>,
    last_pong: Instant,
    pongs: u32,
    /// The last bootstrap stage ([`proto::STAGES`]).
    stage: Option<&'static str>,
    /// Tor's last word for a blockage ([`proto::blockage_word`]).
    tor_says: Option<&'static str>,
    /// The helper's last error (its fixed text) and whether it is local.
    error: Option<(String, bool)>,
    /// A panic on its stderr.
    crashed: bool,
}

impl Life {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            started: now,
            last_progress: now,
            pct: 0,
            ready_at: None,
            last_pong: now,
            pongs: 0,
            stage: None,
            tor_says: None,
            error: None,
            crashed: false,
        }
    }

    /// A progress event: new progress (a higher percent, or a later stage)
    /// resets the stall clock; the same again does not. Returns whether
    /// the stage changed (worth a log line).
    pub(crate) fn progress(
        &mut self,
        pct: u8,
        stage: Option<&'static str>,
        tor_says: Option<&'static str>,
        now: Instant,
    ) -> bool {
        let rank = |s: Option<&str>| s.and_then(|s| proto::STAGES.iter().position(|x| *x == s));
        // Into a later directory stage is progress; a stage of trouble
        // (no handshake, stuck) is not.
        let later_stage =
            stage.is_some_and(proto::relays_reached) && rank(stage) > rank(self.stage);
        if pct > self.pct || later_stage {
            self.last_progress = now;
        }
        self.pct = self.pct.max(pct);
        self.tor_says = tor_says;
        let changed = stage.is_some() && stage != self.stage;
        if stage.is_some() {
            self.stage = stage;
        }
        changed
    }

    pub(crate) fn ready(&mut self, now: Instant) {
        if self.ready_at.is_none() {
            self.ready_at = Some(now);
            self.last_pong = now;
        }
    }

    pub(crate) fn pong(&mut self, now: Instant) {
        self.last_pong = now;
        self.pongs = self.pongs.saturating_add(1);
    }

    /// The helper said this went wrong (its fixed text, cut short).
    pub(crate) fn error(&mut self, what: &str, local: bool) {
        let what: String = what
            .chars()
            .filter(|c| c.is_ascii_graphic() || *c == ' ')
            .take(MAX_ERROR)
            .collect();
        self.error = Some((what, local));
    }

    /// Its stderr showed a panic.
    pub(crate) fn crashed(&mut self) {
        self.crashed = true;
    }

    pub(crate) fn pct(&self) -> u8 {
        self.pct
    }

    /// The helper's last error and whether its cause is local.
    pub(crate) fn last_error(&self) -> Option<(&str, bool)> {
        self.error
            .as_ref()
            .map(|(what, local)| (what.as_str(), *local))
    }

    pub(crate) fn tor_says(&self) -> Option<&'static str> {
        self.tor_says
    }

    pub(crate) fn stage(&self) -> Option<&'static str> {
        self.stage
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.ready_at.is_some()
    }

    /// From start to ready.
    pub(crate) fn bootstrap_time(&self) -> Option<Duration> {
        self.ready_at.map(|r| r.duration_since(self.started))
    }

    /// How long it has run.
    pub(crate) fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.started)
    }

    /// Tor relays answered handshakes (the stage says so; an older helper
    /// without stages: 15 % or more).
    fn relays_reached(&self) -> bool {
        self.stage
            .map_or(self.pct >= EARLY_PCT, proto::relays_reached)
    }

    /// Whether a watchdog ends it now.
    pub(crate) fn check(&self, now: Instant) -> Option<End> {
        if now.saturating_duration_since(self.last_pong) >= PING_DEAD {
            return Some(End::Unresponsive);
        }
        if self.ready_at.is_some() {
            return None;
        }
        if now.saturating_duration_since(self.started) >= BOOTSTRAP_MAX {
            return Some(End::BootstrapBudget);
        }
        let window = if self.pct <= EARLY_PCT {
            STALL_EARLY
        } else {
            PROGRESS_STALL
        };
        (now.saturating_duration_since(self.last_progress) >= window).then_some(End::ProgressStall)
    }

    /// Where the trouble is, now that it ended for `end`.
    pub(crate) fn blame(&self, end: End) -> Blame {
        if end.immediate() || end == End::Obsolete || self.is_ready() {
            return Blame::Restart;
        }
        let local_error = self
            .error
            .as_ref()
            .filter(|(_, local)| *local)
            .map(|(what, _)| what.clone());
        let pct = self.pct;
        match end {
            End::Exited | End::Unresponsive => Blame::ThisComputer(if self.crashed {
                format!("the Tor helper crashed at {pct} %")
            } else if let Some(what) = local_error {
                what
            } else if end == End::Unresponsive {
                format!("the Tor helper hung at {pct} %")
            } else {
                format!("the Tor helper stopped at {pct} %")
            }),
            _ => {
                if let Some(what) = local_error {
                    return Blame::ThisComputer(what);
                }
                match self.tor_says {
                    Some("clock_skewed") => {
                        return Blame::ThisComputer("this computer's clock looks wrong".into());
                    }
                    Some(word @ ("offline" | "filtered" | "cant_reach_tor" | "directory")) => {
                        return Blame::Network(format!("Tor says: {word}"));
                    }
                    _ => {}
                }
                if self.relays_reached() {
                    Blame::ThisComputer(format!("stuck at {pct} % after Tor relays answered"))
                } else {
                    Blame::Network("no Tor relay answered".into())
                }
            }
        }
    }

    /// One log line of its last words for `end` (fixed words, numbers).
    pub(crate) fn summary(&self, end: End, now: Instant) -> String {
        let mut parts = vec![
            format!("{} %", self.pct),
            format!("stage {}", self.stage.unwrap_or("-")),
        ];
        if let Some(word) = self.tor_says {
            parts.push(format!("Tor says {word}"));
        }
        if let Some((what, local)) = &self.error {
            let place = if *local { "this computer" } else { "Tor" };
            parts.push(format!("helper error ({place}): {what}"));
        }
        if self.crashed {
            parts.push("helper crashed".into());
        }
        parts.push(format!(
            "no progress for {} s",
            now.saturating_duration_since(self.last_progress).as_secs()
        ));
        parts.push(format!(
            "answered {} pings, last {} s ago",
            self.pongs,
            now.saturating_duration_since(self.last_pong).as_secs()
        ));
        format!(
            "Tor helper ended after {} s ({}): {}",
            self.age(now).as_secs(),
            end.words(),
            parts.join(", ")
        )
    }
}

/// How long a change of the onion service's reachability must hold before
/// the log and `raven status` take it (field test r34: Arti's publisher
/// says "bootstrapping" for every descriptor republish and intro point
/// change, 20 times an hour on one Wi-Fi, while the descriptor already
/// published still works).
pub(crate) const SERVICE_SETTLE: Duration = Duration::from_secs(60);

/// How long evidence of whether friends can reach the onion service (a
/// friend's authenticated incoming Tor link, a self-check) counts over
/// what Arti says ([`ServiceWatch`]).
pub(crate) const EVIDENCE_HOLD: Duration = Duration::from_secs(10 * 60);

/// What made the service count as reachable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Via {
    /// Arti's own state.
    Arti,
    /// A friend's authenticated incoming Tor link.
    Friend,
    /// A self-check: our own Tor client reached it as a friend would.
    SelfCheck,
}

/// What the log says about the onion service ([`ServiceWatch`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServiceNews {
    /// Reachable for the first time in this helper's life (said at once).
    Reachable { via: Via },
    /// Not reachable for [`SERVICE_SETTLE`], since `since`
    /// ([`ServiceWatch::why`]).
    Unreachable { since: Instant },
    /// Reachable again after [`Self::Unreachable`]: once it held
    /// [`SERVICE_SETTLE`], or at once on evidence.
    ReachableAgain { via: Via },
}

/// One piece of evidence: when, whether the service was reached, by what,
/// and a failed self-check's fixed reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Evidence {
    at: Instant,
    reached: bool,
    via: Via,
    reason: Option<&'static str>,
}

/// The onion service's reachability as the log and `raven status` tell it.
///
/// Evidence first: the latest friend's authenticated incoming Tor link or
/// self-check younger than [`EVIDENCE_HOLD`] says whether friends can reach
/// it, whatever Arti says (field test round 9: Arti said
/// "degraded_unreachable" for whole upload rounds in which every HSDir that
/// needed a new copy timed out, while the copies from earlier rounds, valid
/// three hours, still served friends). Arti saying reachable ends the
/// evidence (newer news). Without evidence, Arti's states, settled: running
/// and degraded-reachable are reachable; while it is reachable,
/// bootstrapping is too (a republish); any other state, or bootstrapping
/// before the first publish or after a loss, is not. The first "reachable"
/// counts at once, and so does evidence that it is reachable; any other
/// change only once it held [`SERVICE_SETTLE`].
#[derive(Clone, Debug, Default)]
pub(crate) struct ServiceWatch {
    state: Option<proto::ServiceState>,
    reason: Option<&'static str>,
    /// What the log and status say: `None` until first reachable.
    settled: Option<bool>,
    /// Since when the reading differs from `settled`.
    differs_since: Option<Instant>,
    evidence: Option<Evidence>,
}

impl ServiceWatch {
    fn evidence(&self, now: Instant) -> Option<Evidence> {
        self.evidence
            .filter(|e| now.saturating_duration_since(e.at) < EVIDENCE_HOLD)
    }

    fn reads_reachable(&self, now: Instant) -> bool {
        if let Some(e) = self.evidence(now) {
            return e.reached;
        }
        self.state.is_some_and(proto::ServiceState::reachable)
            || (self.settled == Some(true)
                && self.state == Some(proto::ServiceState::Bootstrapping))
    }

    /// Arti said `state` (with `reason`) at `now`.
    pub(crate) fn observe(
        &mut self,
        state: proto::ServiceState,
        reason: Option<&'static str>,
        now: Instant,
    ) -> Option<ServiceNews> {
        self.state = Some(state);
        self.reason = reason;
        if state.reachable() {
            // Newer news than the evidence: Arti's state rules again.
            self.evidence = None;
        }
        self.settle(now)
    }

    /// A friend's authenticated incoming Tor link at `now`.
    pub(crate) fn reached_by_friend(&mut self, now: Instant) -> Option<ServiceNews> {
        self.evidence = Some(Evidence {
            at: now,
            reached: true,
            via: Via::Friend,
            reason: None,
        });
        self.settle(now)
    }

    /// A self-check at `now`: `reached`, or not for `reason`.
    pub(crate) fn self_checked(
        &mut self,
        reached: bool,
        reason: Option<&'static str>,
        now: Instant,
    ) -> Option<ServiceNews> {
        self.evidence = Some(Evidence {
            at: now,
            reached,
            via: Via::SelfCheck,
            reason,
        });
        self.settle(now)
    }

    /// Arti reports trouble (a state other than reachable or a republish):
    /// worth a self-check ([`SelfChecks::trouble`]).
    pub(crate) fn arti_trouble(&self) -> bool {
        matches!(
            self.state,
            Some(
                proto::ServiceState::DegradedUnreachable
                    | proto::ServiceState::Recovering
                    | proto::ServiceState::Broken
            )
        )
    }

    /// The news by `now` (called every tick too).
    pub(crate) fn settle(&mut self, now: Instant) -> Option<ServiceNews> {
        let reachable = self.reads_reachable(now);
        let proven = self.evidence(now).filter(|e| e.reached && reachable);
        let via = proven.map_or(Via::Arti, |e| e.via);
        let Some(settled) = self.settled else {
            if !reachable {
                return None;
            }
            self.settled = Some(true);
            self.differs_since = None;
            return Some(ServiceNews::Reachable { via });
        };
        if settled == reachable {
            self.differs_since = None;
            return None;
        }
        let since = *self.differs_since.get_or_insert(now);
        if proven.is_none() && now.saturating_duration_since(since) < SERVICE_SETTLE {
            return None;
        }
        self.differs_since = None;
        self.settled = Some(reachable);
        Some(if reachable {
            ServiceNews::ReachableAgain { via }
        } else {
            ServiceNews::Unreachable { since }
        })
    }

    /// The settled reachability: `None` before it was first reachable.
    pub(crate) fn settled(&self) -> Option<bool> {
        self.settled
    }

    /// Arti's last state and reason, after a failed self-check's reason
    /// while that counts (what an unreachable service shows).
    pub(crate) fn why(&self, now: Instant) -> String {
        let word = self.state.map_or("unknown", proto::ServiceState::word);
        let arti = match self.reason {
            Some(reason) => format!("Arti: {word}, {reason}"),
            None => format!("Arti: {word}"),
        };
        match self.evidence(now) {
            Some(e) if !e.reached => {
                format!("self-check failed: {}; {arti}", e.reason.unwrap_or("other"))
            }
            _ => arti,
        }
    }
}

/// The first self-check, after the onion service was launched.
pub(crate) const SELF_CHECK_FIRST: Duration = Duration::from_secs(3 * 60);
/// Self-checks while they reach the service: two an hour.
pub(crate) const SELF_CHECK_EVERY: Duration = Duration::from_secs(30 * 60);
/// After a failed self-check, and the least gap between two when Arti
/// reports trouble: at most six an hour.
pub(crate) const SELF_CHECK_AGAIN: Duration = Duration::from_secs(10 * 60);
/// When Arti reports trouble, a self-check this soon (within the gap).
pub(crate) const SELF_CHECK_ON_TROUBLE: Duration = Duration::from_secs(30);
/// A self-check the helper did not answer within this is given up.
pub(crate) const SELF_CHECK_WAIT: Duration = Duration::from_secs(90);
/// The first self-check of a run this soon after a descriptor upload round
/// that HSDirs took (E2 r40: after a network change Tor was ready in 3 s
/// and 8 of 8 HSDirs took the descriptor 20 s later, but `raven status`
/// knew the service reachable only at the first self-check, 3 min after).
pub(crate) const SELF_CHECK_AFTER_UPLOAD: Duration = Duration::from_secs(45);

/// When to ask the helper for a self-check (one at a time).
#[derive(Clone, Debug, Default)]
pub(crate) struct SelfChecks {
    n: u64,
    next: Option<Instant>,
    asked: Option<(u64, Instant)>,
    last: Option<Instant>,
}

impl SelfChecks {
    /// The onion service was launched at `now`.
    pub(crate) fn published(&mut self, now: Instant) {
        if self.next.is_none() && self.asked.is_none() && self.last.is_none() {
            self.next = Some(now + SELF_CHECK_FIRST);
        }
    }

    /// HSDirs took our descriptor at `now`: the run's first self-check
    /// within [`SELF_CHECK_AFTER_UPLOAD`] (never sooner than planned, and
    /// nothing once this run has asked one).
    pub(crate) fn uploaded(&mut self, now: Instant) {
        if self.asked.is_some() || self.last.is_some() {
            return;
        }
        let soon = now + SELF_CHECK_AFTER_UPLOAD;
        self.next = Some(self.next.map_or(soon, |next| next.min(soon)));
    }

    /// Arti reports trouble at `now`: a self-check soon, not sooner than
    /// [`SELF_CHECK_AGAIN`] after the last one.
    pub(crate) fn trouble(&mut self, now: Instant) {
        if self.asked.is_some() {
            return;
        }
        let soonest = (now + SELF_CHECK_ON_TROUBLE)
            .max(self.last.map_or(now, |last| last + SELF_CHECK_AGAIN));
        self.next = Some(self.next.map_or(soonest, |next| next.min(soonest)));
    }

    /// The self-check to ask for at `now`, if one is due.
    pub(crate) fn due(&mut self, now: Instant) -> Option<u64> {
        if let Some((_, at)) = self.asked {
            if now.saturating_duration_since(at) < SELF_CHECK_WAIT {
                return None;
            }
            // Not answered: given up, tried again later.
            self.asked = None;
            self.last = Some(now);
            self.next = Some(now + SELF_CHECK_AGAIN);
        }
        if self.next.is_none_or(|next| now < next) {
            return None;
        }
        self.n += 1;
        self.asked = Some((self.n, now));
        self.next = None;
        Some(self.n)
    }

    /// The helper answered self-check `n` at `now`; `false` for an answer
    /// to none asked (late or unknown: ignored).
    pub(crate) fn answered(&mut self, n: u64, reached: bool, now: Instant) -> bool {
        if self.asked.map(|(asked, _)| asked) != Some(n) {
            return false;
        }
        self.asked = None;
        self.last = Some(now);
        self.next = Some(
            now + if reached {
                SELF_CHECK_EVERY
            } else {
                SELF_CHECK_AGAIN
            },
        );
        true
    }
}

/// The onion service's outages since raven-node started (settled losses,
/// [`ServiceNews::Unreachable`] to reachable again), for `raven status`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Outages {
    pub(crate) count: u32,
    /// The one going on: since when.
    pub(crate) open_since: Option<Instant>,
    /// The last one that ended: when it ended and how long it lasted.
    pub(crate) last: Option<(Instant, Duration)>,
}

impl Outages {
    /// An outage that began at `since`.
    pub(crate) fn began(&mut self, since: Instant) {
        if self.open_since.is_none() {
            self.count = self.count.saturating_add(1);
            self.open_since = Some(since);
        }
    }

    /// The service is reachable again at `now`.
    pub(crate) fn ended(&mut self, now: Instant) {
        if let Some(since) = self.open_since.take() {
            self.last = Some((now, now.saturating_duration_since(since)));
        }
    }
}

/// The restart policy across helper lives.
#[derive(Clone, Debug, Default)]
pub(crate) struct Restarts {
    /// Failures in a row (the backoff's exponent).
    failures: u32,
    /// Stuck bootstraps in a row.
    blocked: u32,
    /// Helpers started.
    pub(crate) started: u32,
}

/// What to do after a helper ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Next {
    /// Wait this long first (interrupted by a network change).
    pub(crate) wait: Duration,
    /// Start with a fresh guard state.
    pub(crate) fresh_state: bool,
    /// The network kept Tor out ([`BLOCKED_RETRY_MIN`] backoff).
    pub(crate) blocked: bool,
}

impl Restarts {
    pub(crate) fn started(&mut self) {
        self.started = self.started.saturating_add(1);
    }

    /// A helper of age `ran` ended for `end`, with `blame`
    /// ([`Life::blame`]): what comes next.
    pub(crate) fn ended(&mut self, end: End, ran: Duration, blame: &Blame) -> Next {
        if ran >= STABLE_AFTER {
            self.failures = 0;
        }
        if end.immediate() {
            return Next {
                wait: Duration::ZERO,
                fresh_state: false,
                blocked: false,
            };
        }
        if end.stuck() {
            self.blocked = self.blocked.saturating_add(1);
        } else {
            self.blocked = 0;
        }
        let network = matches!(blame, Blame::Network(_));
        let base = if network {
            BLOCKED_RETRY_MIN
        } else {
            RESTART_MIN
        };
        let wait = base
            .saturating_mul(1u32 << self.failures.min(10))
            .min(RESTART_MAX);
        self.failures = self.failures.saturating_add(1);
        let fresh_state = self.blocked >= FRESH_STATE_AFTER;
        if fresh_state {
            self.blocked = 0;
        }
        Next {
            wait,
            fresh_state,
            blocked: network,
        }
    }

    /// A helper got ready: blocked bootstraps no longer count in a row.
    pub(crate) fn ready(&mut self) {
        self.blocked = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    /// A life that answers every ping up to `until` (as a live helper does).
    fn ponged(life: &mut Life, t: Instant, until: u64) {
        for s in (0..=until).step_by(20) {
            life.pong(t + secs(s));
        }
    }

    #[test]
    fn a_bootstrap_that_keeps_progressing_ends_only_at_its_cap() {
        let t = Instant::now();
        let mut life = Life::new(t);
        // Slow but steady progress (a slow link), never ready.
        for i in 1..=29u64 {
            life.progress(
                (15 + i * 2) as u8,
                Some("microdescriptors"),
                None,
                t + secs(i * 10),
            );
        }
        ponged(&mut life, t, 300);
        assert_eq!(life.check(t + secs(299)), None);
        assert_eq!(life.check(t + BOOTSTRAP_MAX), Some(End::BootstrapBudget));
    }

    #[test]
    fn a_slow_consensus_download_is_not_a_stall() {
        let t = Instant::now();
        let mut life = Life::new(t);
        life.progress(15, Some("consensus"), None, t + secs(3));
        ponged(&mut life, t, 200);
        // Field test S15 (win-c): 45 s at 15 % used to end it. Arti says
        // nothing while it downloads the consensus.
        assert_eq!(life.check(t + secs(46)), None);
        assert_eq!(life.check(t + secs(122)), None);
        assert_eq!(life.check(t + secs(123)), Some(End::ProgressStall));
    }

    #[test]
    fn a_stuck_bootstrap_ends_at_the_progress_watchdog() {
        let t = Instant::now();
        let mut life = Life::new(t);
        life.progress(15, Some("consensus"), None, t + secs(5));
        life.progress(40, Some("microdescriptors"), None, t + secs(20));
        // The same again is no progress.
        life.progress(40, Some("microdescriptors"), None, t + secs(50));
        ponged(&mut life, t, 200);
        assert_eq!(life.check(t + secs(79)), None);
        assert_eq!(life.check(t + secs(80)), Some(End::ProgressStall));
    }

    #[test]
    fn a_later_directory_stage_is_progress_but_trouble_is_not() {
        let t = Instant::now();
        let mut life = Life::new(t);
        assert!(life.progress(15, Some("waiting"), None, t + secs(1)));
        assert!(life.progress(15, Some("consensus"), None, t + secs(100)));
        ponged(&mut life, t, 300);
        assert_eq!(life.check(t + secs(219)), None);
        // Stuck is no progress.
        assert!(life.progress(15, Some("stuck"), Some("directory"), t + secs(200)));
        assert_eq!(life.check(t + secs(220)), Some(End::ProgressStall));
        assert!(!life.progress(15, Some("stuck"), Some("directory"), t + secs(221)));
    }

    #[test]
    fn a_helper_must_answer_pings_while_it_starts_and_once_ready() {
        let t = Instant::now();
        let mut life = Life::new(t);
        life.progress(15, Some("consensus"), None, t + secs(5));
        // No pong at all: hung, before any bootstrap watchdog.
        assert_eq!(life.check(t + secs(59)), None);
        assert_eq!(life.check(t + secs(60)), Some(End::Unresponsive));

        let mut life = Life::new(t);
        life.progress(100, Some("usable"), None, t + secs(8));
        life.ready(t + secs(9));
        assert_eq!(life.bootstrap_time(), Some(secs(9)));
        // No bootstrap watchdog once ready.
        life.pong(t + secs(400));
        assert_eq!(life.check(t + secs(450)), None);
        assert_eq!(life.check(t + secs(460)), Some(End::Unresponsive));
    }

    #[test]
    fn blame_tells_this_computer_from_the_network() {
        let t = Instant::now();
        let computer = |s: &str| Blame::ThisComputer(s.into());
        let network = |s: &str| Blame::Network(s.into());

        // Win-c (S15): relays answered, then stuck at 15 % (Arti #2726).
        let mut life = Life::new(t);
        life.progress(15, Some("consensus"), None, t);
        assert_eq!(
            life.blame(End::ProgressStall),
            computer("stuck at 15 % after Tor relays answered")
        );
        // ... and the helper stopped answering, or crashed, or said why.
        assert_eq!(
            life.blame(End::Unresponsive),
            computer("the Tor helper hung at 15 %")
        );
        assert_eq!(
            life.blame(End::Exited),
            computer("the Tor helper stopped at 15 %")
        );
        life.error("Tor client not created: folder permissions", true);
        assert_eq!(
            life.blame(End::Exited),
            computer("Tor client not created: folder permissions")
        );
        assert_eq!(
            life.blame(End::ProgressStall),
            computer("Tor client not created: folder permissions")
        );
        life.crashed();
        assert_eq!(
            life.blame(End::Exited),
            computer("the Tor helper crashed at 15 %")
        );

        // No relay answered, or Tor says the network is the trouble.
        let mut life = Life::new(t);
        life.progress(0, Some("connecting"), None, t);
        assert_eq!(
            life.blame(End::ProgressStall),
            network("no Tor relay answered")
        );
        life.progress(7, Some("stuck"), Some("cant_reach_tor"), t);
        assert_eq!(
            life.blame(End::BootstrapBudget),
            network("Tor says: cant_reach_tor")
        );
        // A network error from the helper is no reason to blame this computer.
        life.error("bootstrap failed: no answer from the Tor network", false);
        assert_eq!(
            life.blame(End::ProgressStall),
            network("Tor says: cant_reach_tor")
        );
        life.progress(7, Some("no_handshake"), Some("clock_skewed"), t);
        assert_eq!(
            life.blame(End::ProgressStall),
            computer("this computer's clock looks wrong")
        );

        // An older helper without stages: 15 % means relays answered.
        let mut life = Life::new(t);
        life.progress(10, None, None, t);
        assert_eq!(
            life.blame(End::ProgressStall),
            network("no Tor relay answered")
        );
        life.progress(15, None, None, t);
        assert_eq!(
            life.blame(End::ProgressStall),
            computer("stuck at 15 % after Tor relays answered")
        );

        // Restarts blame nobody.
        for end in [End::NetworkChanged, End::Woke, End::Obsolete] {
            assert_eq!(life.blame(end), Blame::Restart);
        }
        life.ready(t);
        assert_eq!(life.blame(End::Unresponsive), Blame::Restart);
        assert_eq!(life.blame(End::Exited), Blame::Restart);
    }

    #[test]
    fn last_words_are_states_and_numbers_only() {
        let t = Instant::now();
        let mut life = Life::new(t);
        life.progress(15, Some("consensus"), None, t + secs(2));
        life.pong(t + secs(20));
        // Control characters are dropped and the text is cut short.
        life.error(
            &format!("bootstrap failed: Tor directory\n\u{1b}{}", "x".repeat(99)),
            false,
        );
        let line = life.summary(End::ProgressStall, t + secs(122));
        assert_eq!(
            line,
            format!(
                "Tor helper ended after 122 s (the Tor start stopped making progress): 15 %, \
                 stage consensus, helper error (Tor): bootstrap failed: Tor directory{}, \
                 no progress for 120 s, answered 1 pings, last 102 s ago",
                "x".repeat(MAX_ERROR - 31)
            )
        );
    }

    /// Field test r34 (win-c): Arti says "bootstrapping" for every republish
    /// while the published descriptor still works. Once reachable, those
    /// blips are no news; a real loss is said once it held a minute, and so
    /// is the way back.
    #[test]
    fn onion_service_blips_are_no_news_and_a_loss_that_lasts_is() {
        use proto::ServiceState as S;
        let t = Instant::now();
        let mut w = ServiceWatch::default();
        // Before the first publish: bootstrapping is not reachable.
        assert_eq!(w.observe(S::Bootstrapping, None, t), None);
        assert_eq!(w.settled(), None);
        assert_eq!(w.settle(t + secs(300)), None);
        // The first "reachable" is said at once.
        assert_eq!(
            w.observe(S::DegradedReachable, None, t + secs(74)),
            Some(ServiceNews::Reachable { via: Via::Arti })
        );
        // Republish blips (win-c: 2-10 s apart, in bursts): nothing.
        for i in 0..20u64 {
            let at = t + secs(100 + i * 7);
            let state = if i % 2 == 0 {
                S::Bootstrapping
            } else {
                S::Running
            };
            assert_eq!(w.observe(state, None, at), None);
            assert_eq!(w.settle(at + secs(3)), None);
        }
        // An unreachable state shorter than a minute: nothing.
        assert_eq!(
            w.observe(
                S::DegradedUnreachable,
                Some("descriptor upload failed"),
                t + secs(400)
            ),
            None
        );
        assert_eq!(w.settle(t + secs(459)), None);
        assert_eq!(w.observe(S::Running, None, t + secs(459)), None);
        // One that lasts (two unreachable states in a row): said once, from
        // when it began.
        let lost = t + secs(700);
        assert_eq!(
            w.observe(S::Recovering, Some("intro point stopped answering"), lost),
            None
        );
        assert_eq!(
            w.observe(
                S::DegradedUnreachable,
                Some("descriptor upload failed"),
                lost + secs(30)
            ),
            None
        );
        assert!(w.arti_trouble());
        assert_eq!(
            w.settle(lost + secs(60)),
            Some(ServiceNews::Unreachable { since: lost })
        );
        assert_eq!(
            w.why(lost + secs(60)),
            "Arti: degraded_unreachable, descriptor upload failed"
        );
        assert_eq!(w.settle(lost + secs(120)), None, "said once");
        // After a loss, bootstrapping is no way back; running is, after a minute.
        assert_eq!(w.observe(S::Bootstrapping, None, lost + secs(130)), None);
        assert_eq!(w.settle(lost + secs(195)), None);
        let back = lost + secs(200);
        assert_eq!(w.observe(S::Running, None, back), None);
        assert_eq!(w.settle(back + secs(59)), None);
        assert_eq!(
            w.settle(back + secs(60)),
            Some(ServiceNews::ReachableAgain { via: Via::Arti })
        );
    }

    /// Evidence over Arti's word (field tests rounds 8 and 9): a friend's
    /// link or a self-check that reached the service makes it reachable at
    /// once whatever Arti says; a failed self-check makes it unreachable
    /// after a minute whatever Arti says; Arti saying reachable is newer
    /// news; evidence counts for EVIDENCE_HOLD.
    #[test]
    fn evidence_tells_whether_friends_can_reach_the_service() {
        use proto::ServiceState as S;
        let t = Instant::now();
        let mut w = ServiceWatch::default();
        assert_eq!(w.observe(S::Bootstrapping, None, t), None);
        assert_eq!(
            w.reached_by_friend(t + secs(40)),
            Some(ServiceNews::Reachable { via: Via::Friend })
        );
        // Round 9: Arti says an upload round timed out; a self-check
        // reaches the service: no news, still reachable.
        assert_eq!(
            w.observe(
                S::DegradedUnreachable,
                Some("descriptor upload timed out"),
                t + secs(100)
            ),
            None
        );
        assert_eq!(w.self_checked(true, None, t + secs(130)), None);
        assert_eq!(w.settle(t + secs(130) + EVIDENCE_HOLD - secs(1)), None);
        // Evidence runs out with Arti still unreachable: a loss after a minute.
        let out = t + secs(130) + EVIDENCE_HOLD;
        assert_eq!(w.settle(out), None);
        assert_eq!(
            w.settle(out + SERVICE_SETTLE),
            Some(ServiceNews::Unreachable { since: out })
        );
        // A self-check that reaches it brings it back at once.
        assert_eq!(
            w.self_checked(true, None, out + secs(90)),
            Some(ServiceNews::ReachableAgain {
                via: Via::SelfCheck
            })
        );
        // Arti says running (newer news); then a failed self-check: a loss
        // after a minute, whatever Arti said, with the reason.
        assert_eq!(w.observe(S::Running, None, out + secs(100)), None);
        let failed = out + secs(200);
        assert_eq!(w.self_checked(false, Some("no descriptor"), failed), None);
        assert_eq!(
            w.settle(failed + SERVICE_SETTLE),
            Some(ServiceNews::Unreachable { since: failed })
        );
        assert_eq!(
            w.why(failed + SERVICE_SETTLE),
            "self-check failed: no descriptor; Arti: running"
        );
        // A friend's link brings it back at once.
        assert_eq!(
            w.reached_by_friend(failed + secs(120)),
            Some(ServiceNews::ReachableAgain { via: Via::Friend })
        );
        // With no Arti state at all yet, a friend's link still counts.
        let mut fresh = ServiceWatch::default();
        assert_eq!(
            fresh.reached_by_friend(t),
            Some(ServiceNews::Reachable { via: Via::Friend })
        );
    }

    /// Self-checks: the first after the service was launched, then two an
    /// hour while they reach it, six an hour at most while they fail or
    /// Arti reports trouble; one at a time; an unanswered one is given up.
    #[test]
    fn self_checks_are_few_and_follow_trouble() {
        let t = Instant::now();
        let mut c = SelfChecks::default();
        assert_eq!(c.due(t), None, "nothing launched");
        c.published(t);
        assert_eq!(c.due(t + SELF_CHECK_FIRST - secs(1)), None);
        let first = t + SELF_CHECK_FIRST;
        assert_eq!(c.due(first), Some(1));
        assert_eq!(c.due(first + secs(5)), None, "one at a time");
        assert!(!c.answered(9, true, first + secs(20)), "not asked");
        assert!(c.answered(1, true, first + secs(20)));
        let ok = first + secs(20);
        assert_eq!(c.due(ok + SELF_CHECK_EVERY - secs(1)), None);
        // Arti reports trouble 5 min after a check: the next one waits out
        // the gap, then goes.
        c.trouble(ok + secs(300));
        assert_eq!(c.due(ok + SELF_CHECK_AGAIN - secs(1)), None);
        assert_eq!(c.due(ok + SELF_CHECK_AGAIN), Some(2));
        let failed = ok + SELF_CHECK_AGAIN + secs(40);
        assert!(c.answered(2, false, failed));
        // While failing: again after SELF_CHECK_AGAIN; trouble meanwhile
        // pulls nothing closer.
        c.trouble(failed + secs(10));
        assert_eq!(c.due(failed + SELF_CHECK_AGAIN - secs(1)), None);
        assert_eq!(c.due(failed + SELF_CHECK_AGAIN), Some(3));
        // Not answered within SELF_CHECK_WAIT: given up, again later.
        let asked = failed + SELF_CHECK_AGAIN;
        assert_eq!(c.due(asked + SELF_CHECK_WAIT), None);
        assert!(!c.answered(3, true, asked + SELF_CHECK_WAIT + secs(1)));
        assert_eq!(c.due(asked + SELF_CHECK_WAIT + SELF_CHECK_AGAIN), Some(4));
        // Trouble long after the last check: within SELF_CHECK_ON_TROUBLE.
        let mut c = SelfChecks::default();
        c.published(t);
        assert_eq!(c.due(t + SELF_CHECK_FIRST), Some(1));
        assert!(c.answered(1, true, t + SELF_CHECK_FIRST));
        let later = t + SELF_CHECK_FIRST + secs(20 * 60);
        c.trouble(later);
        assert_eq!(c.due(later + SELF_CHECK_ON_TROUBLE - secs(1)), None);
        assert_eq!(c.due(later + SELF_CHECK_ON_TROUBLE), Some(2));
    }

    /// E2 r40 #F: the first upload round HSDirs took brings the run's
    /// first self-check close (45 s, not 3 min); later rounds change
    /// nothing.
    #[test]
    fn the_first_upload_round_brings_the_first_self_check_close() {
        let t = Instant::now();
        let mut c = SelfChecks::default();
        c.published(t);
        c.uploaded(t + secs(20));
        let soon = t + secs(20) + SELF_CHECK_AFTER_UPLOAD;
        assert_eq!(c.due(soon - secs(1)), None);
        assert_eq!(c.due(soon), Some(1));
        assert!(c.answered(1, true, soon + secs(10)));
        // Later rounds: the schedule stays.
        c.uploaded(soon + secs(60));
        assert_eq!(c.due(soon + secs(60) + SELF_CHECK_AFTER_UPLOAD), None);
        assert_eq!(c.due(soon + secs(10) + SELF_CHECK_EVERY), Some(2));
        // A round before the launch is known: the check still comes soon.
        let mut c = SelfChecks::default();
        c.uploaded(t);
        assert_eq!(c.due(t + SELF_CHECK_AFTER_UPLOAD), Some(1));
    }

    #[test]
    fn outages_are_counted_and_the_last_one_kept() {
        let t = Instant::now();
        let mut o = Outages::default();
        o.ended(t);
        assert_eq!(o, Outages::default(), "nothing to end");
        o.began(t);
        o.began(t + secs(30));
        assert_eq!((o.count, o.open_since), (1, Some(t)));
        o.ended(t + secs(960));
        assert_eq!(o.open_since, None);
        assert_eq!(o.last, Some((t + secs(960), secs(960))));
        o.began(t + secs(2000));
        assert_eq!(o.count, 2);
    }

    #[test]
    fn failures_back_off_and_a_stable_run_starts_over() {
        let mut r = Restarts::default();
        let local = Blame::ThisComputer("x".into());
        let waits: Vec<u64> = (0..9)
            .map(|_| r.ended(End::Exited, secs(1), &local).wait.as_secs())
            .collect();
        assert_eq!(waits, [5, 10, 20, 40, 80, 160, 320, 600, 600]);
        assert_eq!(r.ended(End::Exited, STABLE_AFTER, &local).wait, RESTART_MIN);
    }

    #[test]
    fn a_network_change_or_wake_restarts_at_once_and_is_no_failure() {
        let mut r = Restarts::default();
        r.ended(End::Exited, secs(1), &Blame::Restart);
        for end in [End::NetworkChanged, End::Woke] {
            let next = r.ended(end, secs(1), &Blame::Restart);
            assert_eq!(next.wait, Duration::ZERO);
            assert!(!next.blocked && !next.fresh_state);
        }
        // The failure count was not moved by them.
        assert_eq!(
            r.ended(End::Exited, secs(1), &Blame::Restart).wait,
            secs(10)
        );
    }

    #[test]
    fn blocked_bootstraps_retry_slower_and_then_start_with_fresh_guards() {
        let mut r = Restarts::default();
        let net = Blame::Network("no Tor relay answered".into());
        let a = r.ended(End::ProgressStall, STALL_EARLY, &net);
        assert_eq!((a.wait, a.blocked, a.fresh_state), (secs(30), true, false));
        let b = r.ended(End::ProgressStall, STALL_EARLY, &net);
        assert_eq!((b.wait, b.blocked, b.fresh_state), (secs(60), true, false));
        // Stuck on this computer: the short backoff, still a stuck start.
        let local = Blame::ThisComputer("stuck".into());
        let c = r.ended(End::ProgressStall, STALL_EARLY, &local);
        assert_eq!((c.wait, c.blocked, c.fresh_state), (secs(20), false, true));
        // The streak starts over after the fresh start.
        assert!(
            !r.ended(End::BootstrapBudget, BOOTSTRAP_MAX, &net)
                .fresh_state
        );
    }

    #[test]
    fn a_ready_helper_clears_the_stuck_streak() {
        let mut r = Restarts::default();
        let net = Blame::Network("x".into());
        r.ended(End::BootstrapBudget, BOOTSTRAP_MAX, &net);
        r.ended(End::BootstrapBudget, BOOTSTRAP_MAX, &net);
        r.ready();
        assert!(
            !r.ended(End::BootstrapBudget, BOOTSTRAP_MAX, &net)
                .fresh_state
        );
    }

    #[test]
    fn end_words_never_name_an_address() {
        for end in [
            End::BootstrapBudget,
            End::ProgressStall,
            End::Unresponsive,
            End::Exited,
            End::Obsolete,
            End::NetworkChanged,
            End::Woke,
        ] {
            assert!(!end.words().contains(".onion"));
            assert!(!end.words().chars().any(|c| c.is_ascii_digit() && c != '5'));
        }
    }
}
