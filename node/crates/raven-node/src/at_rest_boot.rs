//! The at-rest key at service start (privacy pack PP.4; design
//! docs/design/2026-10-at-rest-metadata.md section 4.2, review R14).
//!
//! In a sealed profile, or one this build seals (a release build, or a
//! debug build with `RAVEN_LAB_AT_REST=1`), raven-node loads the at-rest key
//! on a thread of its own: a keychain call has no timeout and may wait on a
//! macOS dialog. The listeners start at once and admit nobody meanwhile: the
//! contact book is held ([`contact_book::hold`]), so every admission refuses
//! exactly as for an unreadable book. `Status.at_rest` says
//! `waiting_for_keychain`, then `key_unavailable` while it retries: after
//! 30 s, 1, 2, 4 and 8 minutes, then every 15 minutes (a user who pressed
//! Deny is not shown a dialog every 30 s), and at once when the user asks
//! (`raven status`: an IPC Status with `retry_key`) and the last try ended
//! 30 s ago or more. The terminal app's periodic Status never asks (review
//! B-sealed-stores-6: with the app open, every Status 30 s after a try
//! started one, a dialog every 30 s). A key that is gone from the keystore
//! while the key file is there (`AtRestError::KeyLost`: a new login
//! keychain, a profile copied elsewhere) is `key_lost`, tried again every
//! 15 minutes only and when the user asks (review A-keys-format-4): no
//! dialog is waiting. At most one keystore call is outstanding. With the key
//! loaded, [`privacy::migrate_all`] seals what is still plain; then the book
//! is released and cached ([`contact_book::enable_process_cache`]). A plain
//! profile this build does not seal never calls the keystore here. Never a
//! plaintext fallback.
//!
//! Log lines are fixed words and counts only.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use raven_core::at_rest::{self, AtRestError, MigratePolicy, Mode};
use raven_core::contact_book;
use raven_core::ipc::AtRestStatus;
use raven_core::privacy::{self, MigrateOutcome, MigrateReport};

/// Why every read of the book refuses while the key loads.
const HOLD_WHY: &str = "raven-node is waiting for the at-rest key";
/// Why every read of the book refuses while Lock v2 holds the profile.
const LOCKED_WHY: &str = "Raven is locked";
/// The line each failed try may log (rate limited).
const LOCKED_LINE: &str =
    "the friends list is locked: Raven needs the keychain or passphrase; nobody can connect \
     until then";
/// The same line when the key is gone from the keystore.
const LOST_LINE: &str =
    "the friends list is locked: its key is gone from the keychain or passphrase vault; nobody \
     can connect until it is back";

/// How long the loader waits between tries.
#[derive(Debug, Clone, Copy)]
struct Timing {
    /// After the n-th failed try in a row (the last one repeats).
    retry: [Duration; 6],
    /// The user's Status asks for a try at once when the last one ended at
    /// least this long ago.
    status_retry: Duration,
    /// A migration deferred for free space is tried again after this.
    space_retry: Duration,
}

impl Timing {
    const REAL: Timing = Timing {
        retry: [
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(2 * 60),
            Duration::from_secs(4 * 60),
            Duration::from_secs(8 * 60),
            Duration::from_secs(15 * 60),
        ],
        status_retry: Duration::from_secs(30),
        space_retry: Duration::from_secs(60 * 60),
    };

    /// The wait after `failures` failed tries in a row (1 or more).
    fn backoff(&self, failures: usize) -> Duration {
        self.retry[failures.clamp(1, self.retry.len()) - 1]
    }

    /// The last (longest) step: the wait while the key is gone.
    fn slowest(&self) -> Duration {
        self.retry[self.retry.len() - 1]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Plain,
    UnsealedByUser,
    WaitingForKeychain,
    KeyUnavailable,
    /// The key file is there, its key is gone from the keystore.
    KeyLost,
    Migrating,
    Sealed,
    NeedsDiskSpace,
}

impl Phase {
    fn word(self) -> &'static str {
        match self {
            Phase::Plain => privacy::STATE_PLAIN,
            Phase::UnsealedByUser => privacy::STATE_UNSEALED_BY_USER,
            Phase::WaitingForKeychain => privacy::STATE_WAITING_FOR_KEYCHAIN,
            Phase::KeyUnavailable => privacy::STATE_KEY_UNAVAILABLE,
            Phase::KeyLost => privacy::STATE_KEY_LOST,
            Phase::Migrating => privacy::STATE_MIGRATING,
            Phase::Sealed => privacy::STATE_SEALED,
            Phase::NeedsDiskSpace => privacy::STATE_NEEDS_DISK_SPACE,
        }
    }
}

/// One profile's loader as `Status` sees it.
struct Boot {
    phase: Phase,
    /// When the last try ended (a slow keychain answer counts from its end).
    last_end: Option<Instant>,
    /// A try is running now.
    trying: bool,
    /// The user's Status asked for a try now.
    poked: bool,
    status_retry: Duration,
    /// The loader thread runs (it ends once the profile is sealed or plain
    /// for good).
    running: bool,
}

/// Per data dir (one in raven-node; tests run several).
static BOOTS: Mutex<BTreeMap<PathBuf, Boot>> = Mutex::new(BTreeMap::new());
static WAKE: Condvar = Condvar::new();

fn boots() -> MutexGuard<'static, BTreeMap<PathBuf, Boot>> {
    BOOTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

static LOCKED_LOG: crate::netutil::LogLimiter =
    crate::netutil::LogLimiter::new(Duration::from_secs(15 * 60));

/// Service start (and `raven-node ipc`), before any listener: decide whether
/// this profile needs its at-rest key, hold the contact book and start the
/// loader if it does. Returns at once; never calls the keystore on this
/// thread.
pub(crate) fn start(data_dir: &Path) {
    start_with(data_dir, MigratePolicy::Auto, Timing::REAL, |dd| {
        privacy::migrate_all(dd, crate::now_ms(), MigratePolicy::Auto)
    });
}

fn start_with<F>(data_dir: &Path, policy: MigratePolicy, timing: Timing, attempt: F)
where
    F: Fn(&Path) -> Result<MigrateReport, AtRestError> + Send + 'static,
{
    let settled = match privacy::mode(data_dir) {
        Mode::UnsealedByUser => Some(Phase::UnsealedByUser),
        Mode::Plain if !policy.allows_sealing() => Some(Phase::Plain),
        Mode::Plain | Mode::Sealed => None,
    };
    let first = settled.unwrap_or(Phase::WaitingForKeychain);
    boots().insert(
        data_dir.to_path_buf(),
        Boot {
            phase: first,
            last_end: None,
            trying: settled.is_none(),
            poked: false,
            status_retry: timing.status_retry,
            running: settled.is_none(),
        },
    );
    if let Some(phase) = settled {
        open_book(data_dir);
        eprintln!("raven-node at_rest: {}", phase.word());
        return;
    }
    contact_book::hold(data_dir, HOLD_WHY);
    let dd = data_dir.to_path_buf();
    let spawned = std::thread::Builder::new()
        .name("raven-at-rest".into())
        .spawn(move || run(&dd, timing, attempt));
    if spawned.is_err() {
        // No thread: nothing loads the key, so the book stays held (fail
        // closed) and Status says so.
        settle(data_dir, Phase::KeyUnavailable);
        loader_ended(data_dir);
        eprintln!("raven-node at_rest: could not start the key loader; nobody is admitted");
    }
}

/// The loader: try, then wait (backoff, or a Status asking), until the
/// profile is sealed or plain for good.
fn run<F>(data_dir: &Path, timing: Timing, attempt: F)
where
    F: Fn(&Path) -> Result<MigrateReport, AtRestError>,
{
    let mut failures = 0usize;
    let mut told: Option<Phase> = None;
    loop {
        begin_try(data_dir);
        let result = attempt(data_dir);
        let (phase, wait) = match result {
            Ok(report) => {
                failures = 0;
                open_book(data_dir);
                if report.sealed > 0 {
                    eprintln!(
                        "raven-node at_rest: sealed {} file(s){}",
                        report.sealed,
                        if report.leftovers > 0 {
                            " (an older build had written plain copies)"
                        } else {
                            ""
                        }
                    );
                }
                match report.outcome {
                    MigrateOutcome::Sealed | MigrateOutcome::OlderNodeRunning => {
                        (Phase::Sealed, None)
                    }
                    MigrateOutcome::NotAllowed | MigrateOutcome::NoIdentity => (Phase::Plain, None),
                    MigrateOutcome::UnsealedByUser => (Phase::UnsealedByUser, None),
                    MigrateOutcome::NeedsDiskSpace { .. } => {
                        (Phase::NeedsDiskSpace, Some(timing.space_retry))
                    }
                }
            }
            Err(error) => {
                failures += 1;
                if at_rest::keys_cached(data_dir).is_ok() {
                    // The key is here, so the book opens: admit again, and
                    // finish sealing later.
                    open_book(data_dir);
                    eprintln!(
                        "raven-node at_rest: sealing did not finish ({error}); trying again later"
                    );
                    (by_mode(data_dir), Some(timing.backoff(failures)))
                } else if matches!(error, AtRestError::KeyLost(_)) {
                    // Gone, not waiting for a dialog: the slowest step only
                    // (and when the user asks), in case it is put back.
                    crate::netutil::log_limited(&LOCKED_LOG, "raven-node", LOST_LINE);
                    (Phase::KeyLost, Some(timing.slowest()))
                } else {
                    crate::netutil::log_limited(&LOCKED_LOG, "raven-node", LOCKED_LINE);
                    (Phase::KeyUnavailable, Some(timing.backoff(failures)))
                }
            }
        };
        settle(data_dir, phase);
        if told != Some(phase) {
            told = Some(phase);
            // The harnesses wait for the first such line: the book is open
            // (or will not be) from here on. Later ones say a change (the
            // key arrived after all).
            eprintln!("raven-node at_rest: {}", phase.word());
        }
        let Some(wait) = wait else {
            loader_ended(data_dir);
            return;
        };
        wait_or_poke(data_dir, wait);
    }
}

fn loader_ended(data_dir: &Path) {
    if let Some(boot) = boots().get_mut(data_dir) {
        boot.running = false;
    }
}

/// The book opens: released and cached, unless Lock v2 locked the profile
/// meanwhile (its hold stays until the unlock).
fn open_book(data_dir: &Path) {
    if !raven_core::local_lock::engaged(data_dir) {
        contact_book::enable_process_cache(data_dir);
    }
}

/// Lock v2 (P6.40): the book is held again (its plaintext goes) and the
/// at-rest keys are forgotten.
pub(crate) fn lock(data_dir: &Path) {
    contact_book::hold(data_dir, LOCKED_WHY);
    at_rest::forget_cached_keys(data_dir);
}

/// Lock v2: the profile is unlocked. The key loads again as at service
/// start: a loader still waiting between tries tries at once, else a new
/// one starts (a plain profile's book opens at once).
pub(crate) fn unlock(data_dir: &Path) {
    {
        let mut boots = boots();
        if let Some(boot) = boots.get_mut(data_dir).filter(|boot| boot.running) {
            boot.poked = true;
            WAKE.notify_all();
            return;
        }
    }
    start(data_dir);
}

/// Whether this profile's at-rest key is being loaded now (a try runs: at
/// service start, after an Unlock, or a retry), so its held book opens in a
/// moment unless the try fails. Not between failed tries, and not while Lock
/// v2 holds the profile: no wait opens the book then. An inbound link waits
/// for the book only while this holds (`netutil::book_open_within`, E1).
pub(crate) fn key_loading(data_dir: &Path) -> bool {
    boots().get(data_dir).is_some_and(|boot| boot.trying)
        && !raven_core::local_lock::engaged(data_dir)
}

/// The state while the book opens but sealing did not finish.
fn by_mode(data_dir: &Path) -> Phase {
    match privacy::mode(data_dir) {
        Mode::Sealed => Phase::Sealed,
        Mode::Plain => Phase::Plain,
        Mode::UnsealedByUser => Phase::UnsealedByUser,
    }
}

fn begin_try(data_dir: &Path) {
    let mut boots = boots();
    if let Some(boot) = boots.get_mut(data_dir) {
        boot.trying = true;
        boot.poked = false;
        boot.phase = if at_rest::keys_cached(data_dir).is_ok() {
            Phase::Migrating
        } else {
            Phase::WaitingForKeychain
        };
    }
}

fn settle(data_dir: &Path, phase: Phase) {
    if let Some(boot) = boots().get_mut(data_dir) {
        boot.trying = false;
        boot.last_end = Some(Instant::now());
        boot.phase = phase;
    }
}

/// Sleep `wait`, or less when the user's Status asks for a try.
fn wait_or_poke(data_dir: &Path, wait: Duration) {
    let deadline = Instant::now() + wait;
    let mut boots = boots();
    loop {
        if let Some(boot) = boots.get_mut(data_dir) {
            if std::mem::take(&mut boot.poked) {
                return;
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        boots = WAKE
            .wait_timeout(boots, deadline - now)
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .0;
    }
}

/// `Status.at_rest`: this process's loader state when it runs one, else
/// what the profile's files say. With `retry_key` (`raven status`), while
/// the key is unavailable or lost and the last try ended 30 s ago or more,
/// it asks for a try now; the terminal app's poll (without it) never does,
/// so the retries keep their backoff while the app is open (review
/// B-sealed-stores-6).
pub(crate) fn status(data_dir: &Path, retry_key: bool) -> AtRestStatus {
    let word = {
        let mut boots = boots();
        match boots.get_mut(data_dir) {
            Some(boot) => {
                let due = retry_key
                    && matches!(boot.phase, Phase::KeyUnavailable | Phase::KeyLost)
                    && !boot.trying
                    && boot
                        .last_end
                        .is_none_or(|at| at.elapsed() >= boot.status_retry);
                if due && !boot.poked {
                    boot.poked = true;
                    WAKE.notify_all();
                }
                Some(boot.phase.word())
            }
            None => None,
        }
    };
    let local = privacy::status(data_dir);
    local.to_ipc(word.unwrap_or_else(|| local.state()))
}

#[cfg(test)]
pub(crate) mod tests;
