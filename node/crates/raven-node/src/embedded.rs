//! raven-node inside the caller's own process (feature `embedded`;
//! docs/IOS.md). iOS lets an app start no helper process and suspends it in
//! the background, so the app runs the node itself:
//!
//! - **The same service.** [`start`] runs `raven-node service`'s own code
//!   ([`crate::run_service`]) on a runtime of its own (a few worker threads
//!   named `raven-node-*`), with the profile layout, stores, listeners and
//!   workers of the program. Nothing in it calls `exit`: a failure ends the
//!   node, never the app.
//! - **The same IPC.** Its IPC server is the program's, on connections made
//!   in process ([`raven_core::ipc::inproc`]: a socket pair each) instead of
//!   a socket file, so every client (the desktop engine, the CLI's code in
//!   it) talks to it exactly as to the program. Its instance lock is the
//!   program's too: one node per profile, embedded or not.
//! - **One node per process.** The service keeps process-wide state (the
//!   p2p host, the custody park map, the Tor helper's life), as the program
//!   does: a second profile in the same process is refused.
//! - **Lifecycle.** [`pause`] stops it cleanly (listeners closed, Tor's
//!   helper and its circuits gone, the p2p host's goodbyes sent) and holds
//!   it stopped until [`resume`]; the app calls them when it goes to the
//!   background and comes back. [`pause_keeping_nearby`] (an app with
//!   background Bluetooth, Task 2 Phase B) stops it the same way and starts
//!   a small node that keeps Bluetooth nearby: IPC, the outbox worker, the
//!   custody fetcher and forwarder and the nearby carrier as a background
//!   life; no listener, no p2p host, no Tor. [`resume`] replaces it with the
//!   full node. [`check_mail`] does one bounded custody fetch from friends
//!   (iOS background refresh), starting a small node for it when none runs
//!   (no radio: a running background node is asked instead).
//! - **Its log** goes to `<profile>/raven-node-service.log` (0600), where
//!   the CLI keeps the program's.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::{run_service, ServiceEnd, ServiceHost, ServiceOptions};

/// The node's log, in the profile (the CLI's `raven-node-service.log`).
pub const LOG_FILE_NAME: &str = "raven-node-service.log";
/// A log grown past this is started afresh when the node starts.
const LOG_MAX_BYTES: u64 = 1024 * 1024;
/// How long [`start`] waits for the node's IPC (the identity and the
/// at-rest key load first; a keychain answer is quick on iOS).
const READY_WAIT: Duration = Duration::from_secs(30);
/// How long a stop waits for the service's goodbyes (p2p, friend relay,
/// learning, the security ledger: about 3 s at most) and its runtime.
const STOP_WAIT: Duration = Duration::from_secs(8);
/// The runtime's grace for tasks still running once the service ended.
const RUNTIME_GRACE: Duration = Duration::from_secs(2);
/// Worker threads of the node's runtime unless the caller says.
pub const DEFAULT_WORKERS: usize = 2;
/// What a mail check leaves for stopping the node it started, out of its
/// budget.
const MAIL_CHECK_STOP_RESERVE: Duration = Duration::from_secs(3);
/// The longest budget a mail check accepts (iOS gives a background refresh
/// about 30 s in all).
pub const MAIL_CHECK_MAX_BUDGET: Duration = Duration::from_secs(28);
/// This computer only, any free port.
const ANY_LOOPBACK_PORT: &str = "127.0.0.1:0";

/// What [`start`] runs.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// The service's settings (`raven-node service`'s flags).
    pub service: ServiceOptions,
    /// Worker threads of the node's runtime.
    pub workers: usize,
}

impl NodeConfig {
    /// The profile in `data_dir`, its LAN listener on `lan_listen`. The
    /// mock BLE bridge, which no friend reaches, takes any free loopback
    /// port, as the CLI's start gives the program (ash ext.rs
    /// `node_service_command`): never 7421, which Raven reserves.
    pub fn new(data_dir: impl Into<PathBuf>, lan_listen: impl Into<String>) -> Self {
        let mut service = ServiceOptions::new(data_dir.into(), lan_listen);
        service.ble_listen = ANY_LOOPBACK_PORT.into();
        Self {
            service,
            workers: DEFAULT_WORKERS,
        }
    }

    fn data_dir(&self) -> &Path {
        &self.service.data_dir
    }
}

/// Where the embedded node stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// No node runs in this process.
    Stopped,
    /// It runs: listeners, workers, Tor (where built and allowed).
    Running,
    /// [`pause`] stopped it; only [`resume`] starts it again.
    Paused,
    /// A small node runs for a mail check ([`check_mail`]).
    MailCheck,
    /// Paused with Bluetooth nearby kept: the small background node runs
    /// ([`pause_keeping_nearby`]).
    Background,
}

impl State {
    pub fn word(self) -> &'static str {
        match self {
            State::Stopped => "stopped",
            State::Running => "running",
            State::Paused => "paused",
            State::MailCheck => "mail_check",
            State::Background => "background",
        }
    }
}

/// What kind of node runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// The whole service.
    Full,
    /// A mail check's small node: no radio.
    MailCheck,
    /// The background node: a mail check's, with the nearby carrier.
    Background,
}

/// [`status`]'s answer.
#[derive(Clone, Debug)]
pub struct Status {
    pub state: State,
    /// The profile it runs (or is paused) for.
    pub data_dir: Option<PathBuf>,
    /// Why the last node ended, when it ended by itself or could not start.
    pub last_end: Option<String>,
}

/// What [`check_mail`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MailCheck {
    /// The custody gate lets this build fetch from friends.
    pub custody_live: bool,
    /// A small node was started for the check (none ran).
    pub started_node: bool,
    /// A whole fetch pass over the friends who hold mail finished in time.
    pub completed: bool,
    /// Messages taken in from friends during the check.
    pub messages: u64,
    pub elapsed: Duration,
}

/// A refusal [`start`] gives while [`pause`] holds the node.
pub const PAUSED_TEXT: &str =
    "PAUSED: Raven is paused while the app is in the background; it starts again when the app \
     is opened";

struct Running {
    data_dir: PathBuf,
    kind: Kind,
    stop: tokio::sync::watch::Sender<bool>,
    /// The service's end, once its thread is done.
    done: mpsc::Receiver<String>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[derive(Default)]
struct Controller {
    running: Option<Running>,
    /// The profile [`pause`] holds stopped.
    paused: Option<PathBuf>,
    last_end: Option<String>,
}

static CONTROLLER: Mutex<Controller> = Mutex::new(Controller {
    running: None,
    paused: None,
    last_end: None,
});
/// Start, stop, pause, resume and mail checks, one at a time.
static TURN: Mutex<()> = Mutex::new(());

fn controller() -> MutexGuard<'static, Controller> {
    CONTROLLER.lock().unwrap_or_else(PoisonError::into_inner)
}

fn turn() -> MutexGuard<'static, ()> {
    TURN.lock().unwrap_or_else(PoisonError::into_inner)
}

fn same_profile(a: &Path, b: &Path) -> bool {
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    a == b || canon(a) == canon(b)
}

/// Where the embedded node stands now.
pub fn status() -> Status {
    let mut c = controller();
    reap(&mut c);
    let (state, data_dir) = match (&c.running, &c.paused) {
        (Some(r), _) if r.kind == Kind::MailCheck => (State::MailCheck, Some(r.data_dir.clone())),
        (Some(r), _) if r.kind == Kind::Background => (State::Background, Some(r.data_dir.clone())),
        (Some(r), _) => (State::Running, Some(r.data_dir.clone())),
        (None, Some(p)) => (State::Paused, Some(p.clone())),
        (None, None) => (State::Stopped, None),
    };
    Status {
        state,
        data_dir,
        last_end: c.last_end.clone(),
    }
}

/// Whether a node (a full one, a mail check's or the background one) runs
/// for `data_dir` in this process.
pub fn running_for(data_dir: &Path) -> bool {
    let mut c = controller();
    reap(&mut c);
    c.running
        .as_ref()
        .is_some_and(|r| same_profile(&r.data_dir, data_dir))
}

/// Whether [`pause`] holds `data_dir`.
pub fn paused_for(data_dir: &Path) -> bool {
    controller()
        .paused
        .as_ref()
        .is_some_and(|p| same_profile(p, data_dir))
}

/// A node whose service ended by itself (its IPC could not start, a
/// supervisor died): forgotten, its end kept for [`status`].
fn reap(c: &mut Controller) {
    let ended = match c.running.as_ref().map(|r| r.done.try_recv()) {
        Some(Ok(end)) => Some(end),
        Some(Err(mpsc::TryRecvError::Disconnected)) => Some("the node's thread ended".into()),
        _ => None,
    };
    if let Some(end) = ended {
        if let Some(mut r) = c.running.take() {
            if let Some(t) = r.thread.take() {
                let _ = t.join();
            }
        }
        c.last_end = Some(end);
    }
}

/// Starts the node for `config`'s profile and waits until its IPC answers.
/// `Ok` at once when it already runs. Refused while [`pause`] holds the
/// profile ([`PAUSED_TEXT`]) and while a node for another profile runs in
/// this process. A mail check's node is replaced by a full one.
pub fn start(config: &NodeConfig) -> Result<(), String> {
    let _turn = turn();
    if paused_for(config.data_dir()) {
        return Err(PAUSED_TEXT.into());
    }
    start_locked(config, Kind::Full)
}

fn start_locked(config: &NodeConfig, kind: Kind) -> Result<(), String> {
    let dir = config.data_dir().to_path_buf();
    {
        let mut c = controller();
        reap(&mut c);
        if let Some(r) = &c.running {
            if !same_profile(&r.data_dir, &dir) {
                return Err(format!(
                    "an embedded raven-node already runs for another profile ({}) in this \
                     process",
                    r.data_dir.display()
                ));
            }
            // The full node does all a small one does; a small node gives
            // way to any other kind.
            if r.kind == kind || r.kind == Kind::Full {
                return Ok(());
            }
        }
    }
    // A small node gives way to the one asked for.
    stop_locked(STOP_WAIT);
    open_profile(&dir)?;
    open_log(&dir);
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let (done_tx, done_rx) = mpsc::channel::<String>();
    let workers = config.workers.max(1);
    let opts = config.service.clone();
    let thread = std::thread::Builder::new()
        .name("raven-node".into())
        .spawn(move || {
            let end = run_on_own_runtime(opts, workers, stop_rx, kind);
            let _ = done_tx.send(end);
        })
        .map_err(|e| format!("the node's thread did not start: {e}"))?;
    controller().running = Some(Running {
        data_dir: dir.clone(),
        kind,
        stop: stop_tx,
        done: done_rx,
        thread: Some(thread),
    });
    wait_ready(&dir)
}

/// The service on a runtime of its own; what ended it, in words.
fn run_on_own_runtime(
    opts: ServiceOptions,
    workers: usize,
    stop: tokio::sync::watch::Receiver<bool>,
    kind: Kind,
) -> String {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_name("raven-node-worker")
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return format!("no runtime for the node: {e}"),
    };
    let host = ServiceHost::Embedded {
        stop,
        mail_check_only: kind != Kind::Full,
        nearby_background: kind == Kind::Background,
    };
    let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(run_service(opts, host))
    }));
    // What is still running (a dial, a helper's last words) gets a moment;
    // then the runtime and every socket it holds are gone.
    runtime.shutdown_timeout(RUNTIME_GRACE);
    let end = match ended {
        Ok(Ok(end)) => end_words(&end),
        Ok(Err(e)) => e,
        Err(_) => "the node stopped after an internal error".into(),
    };
    eprintln!("raven-node: embedded node ended ({end})");
    end
}

fn end_words(end: &ServiceEnd) -> String {
    match end {
        ServiceEnd::Stopped => "stopped".into(),
        ServiceEnd::TimedOut => "its time ran out".into(),
        ServiceEnd::IpcStopped => "its IPC ended: another raven-node may serve this profile \
                                   (see raven-node-service.log)"
            .into(),
        ServiceEnd::SupervisorDied(what) => format!("its {what} supervisor ended"),
    }
}

/// Until the node's IPC endpoint is registered, or its service ended.
fn wait_ready(dir: &Path) -> Result<(), String> {
    let deadline = Instant::now() + READY_WAIT;
    loop {
        if raven_core::ipc::inproc::is_registered(dir) {
            return Ok(());
        }
        {
            let mut c = controller();
            reap(&mut c);
            if c.running.is_none() {
                return Err(c
                    .last_end
                    .clone()
                    .unwrap_or_else(|| "the node ended while starting".into()));
            }
        }
        if Instant::now() >= deadline {
            stop_locked(STOP_WAIT);
            return Err(format!(
                "the node did not come up within {} s (see raven-node-service.log)",
                READY_WAIT.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// What the program checks before it touches a profile (lib.rs
/// `cli_main`): a resolved folder, no unfinished erase or key change; then
/// the profile's applied security notice.
fn open_profile(dir: &Path) -> Result<(), String> {
    raven_core::paths::require_resolved_data_dir(dir)?;
    raven_core::erase::refuse_if_unfinished(dir)?;
    raven_core::privacy::refuse_if_meta_rotation_unfinished(dir)?;
    raven_core::suite_policy::attach(dir);
    Ok(())
}

/// The node's lines go to the profile's service log (0600, appended; a log
/// past [`LOG_MAX_BYTES`] starts afresh). Without it they go to stderr.
fn open_log(dir: &Path) {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let path = dir.join(LOG_FILE_NAME);
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > LOG_MAX_BYTES) {
        let _ = std::fs::remove_file(&path);
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .and_then(|f| {
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            Ok(f)
        });
    crate::netutil::set_log_file(file.ok());
}

/// Stops the node (if one runs) and waits for it, at most `wait`. The
/// pause stays as it is. `true`: one was running.
pub fn stop(wait: Duration) -> bool {
    let _turn = turn();
    stop_locked(wait)
}

fn stop_locked(wait: Duration) -> bool {
    let Some(mut r) = controller().running.take() else {
        return false;
    };
    let _ = r.stop.send(true);
    let end = match r.done.recv_timeout(wait) {
        Ok(end) => {
            if let Some(t) = r.thread.take() {
                let _ = t.join();
            }
            end
        }
        // Still finishing (a blocking store call): its thread ends by
        // itself; the instance lock refuses a new node until it has.
        Err(_) => "still stopping".into(),
    };
    controller().last_end = Some(end);
    true
}

/// The app goes to the background: stop the node cleanly and hold it
/// stopped for `data_dir` until [`resume`]. `true`: one was running.
pub fn pause(data_dir: &Path) -> bool {
    let _turn = turn();
    controller().paused = Some(data_dir.to_path_buf());
    stop_locked(STOP_WAIT)
}

/// The app goes to the background and keeps Bluetooth nearby (an app with
/// the `bluetooth-central` and `bluetooth-peripheral` background modes,
/// Task 2 Phase B): the full node stops cleanly as [`pause`] stops it, the
/// pause holds `config`'s profile, and the small background node starts
/// (see the module doc). `true`: a full node was running. The nearby
/// carrier in it still needs its gate and the user's `nearby` setting, as
/// everywhere.
pub fn pause_keeping_nearby(config: &NodeConfig) -> Result<bool, String> {
    let _turn = turn();
    controller().paused = Some(config.data_dir().to_path_buf());
    let was = stop_locked(STOP_WAIT);
    start_locked(config, Kind::Background)?;
    Ok(was)
}

/// The app is back: the pause ends and the node starts again (the
/// background node, if one runs, gives way to it).
pub fn resume(config: &NodeConfig) -> Result<(), String> {
    let _turn = turn();
    controller().paused = None;
    start_locked(config, Kind::Full)
}

/// The app's Bluetooth permission (iOS with feature `nearby-radio`), read
/// without a manager and so without a prompt: `not_determined`,
/// `restricted`, `denied` or `allowed`. `None` elsewhere (on macOS the
/// permission belongs to RavenNearby.app, which this process never asks),
/// and in an app whose Info.plist lacks `NSBluetoothAlwaysUsageDescription`
/// (iOS may end an app at its first Bluetooth call then: nothing is read).
#[cfg(all(target_os = "ios", feature = "nearby-radio"))]
pub fn nearby_permission() -> Option<&'static str> {
    use crate::nearby::apple::cb;
    cb::has_usage_description().then(|| cb::permission_word(cb::authorization_raw()))
}

/// The app's Bluetooth permission: none outside iOS.
#[cfg(not(all(target_os = "ios", feature = "nearby-radio")))]
pub fn nearby_permission() -> Option<&'static str> {
    None
}

/// Lock v2 while no node runs for `data_dir` in this process (the app's
/// launch while it says asleep, or a lock while paused): the lock is held
/// by the process, so the next start of a node for the profile (a full one,
/// the background one or a mail check's) starts locked, whatever its
/// keystore. `Ok(false)` while the gate is shut: nothing is held. Refused
/// while a node runs: its IPC `Lock` locks it.
pub fn lock_while_stopped(data_dir: &Path) -> Result<bool, String> {
    let _turn = turn();
    if running_for(data_dir) {
        return Err("a node runs for this profile: its IPC Lock locks it".into());
    }
    Ok(crate::lock::hold_before_start(data_dir))
}

/// Lock v2 as this process holds it for `data_dir`, a node running or not.
/// `None` while the gate is shut.
pub fn held_locked(data_dir: &Path) -> Option<bool> {
    crate::lock::held(data_dir)
}

/// The pause ends; nothing is started (the caller starts the node its own
/// way, e.g. through the CLI's start with its refusals).
pub fn end_pause() {
    let _turn = turn();
    controller().paused = None;
}

/// One bounded custody fetch from the friends who hold this profile's mail
/// (iOS background refresh: everything within `budget`, at most
/// [`MAIL_CHECK_MAX_BUDGET`]). A running node is asked for a fetch pass now;
/// otherwise (paused, stopped) a small node runs for the check: IPC, the
/// outbox worker (owed receipts, waiting messages) and the custody fetcher,
/// no listener, no Tor, no radio; it is stopped again before the budget
/// ends. Every custody dial is cut at the budget. Mail that arrives this way
/// is in the profile when it returns (`messages` counts it). While a
/// running node's pass is waited for, nothing else waits for the check: a
/// start, a stop, a pause or a resume goes at once (audit T9).
pub fn check_mail(config: &NodeConfig, budget: Duration) -> Result<MailCheck, String> {
    check(config, budget, true).map(|done| done.unwrap_or_default())
}

/// [`check_mail`] only when a node already runs for the profile: `None`,
/// with nothing done, when none runs (the caller starts nothing then, and
/// may call [`check_mail`] its own way).
pub fn check_mail_if_running(
    config: &NodeConfig,
    budget: Duration,
) -> Result<Option<MailCheck>, String> {
    check(config, budget, false)
}

/// Mail checks, one at a time (each sets the custody passes' deadline).
static CHECKS: Mutex<()> = Mutex::new(());

fn check(
    config: &NodeConfig,
    budget: Duration,
    may_start: bool,
) -> Result<Option<MailCheck>, String> {
    let began = Instant::now();
    let budget = budget.min(MAIL_CHECK_MAX_BUDGET);
    let _one_check = CHECKS.lock().unwrap_or_else(PoisonError::into_inner);
    let mut held_turn = Some(turn());
    let mut out = MailCheck {
        custody_live: crate::custody::fetcher_live(),
        ..MailCheck::default()
    };
    if !out.custody_live {
        out.elapsed = began.elapsed();
        return Ok(Some(out));
    }
    let dir = config.data_dir().to_path_buf();
    let already = running_for(&dir);
    if !already && !may_start {
        return Ok(None);
    }
    let fetch_budget = if already {
        budget
    } else {
        budget.saturating_sub(MAIL_CHECK_STOP_RESERVE)
    };
    let deadline = began + fetch_budget;
    crate::custody::set_pass_deadline(Some(deadline));
    let (begun, _, fetched_before) = crate::custody::pass_counts();
    let result = (|| {
        if !already {
            start_locked(config, Kind::MailCheck)?;
            out.started_node = true;
        } else {
            crate::custody::kick();
            // The running node fetches by itself: its turn is free while
            // the pass is waited for. A node this check started keeps it,
            // so that nothing else starts or stops a node meanwhile.
            held_turn = None;
        }
        // A pass that begins after now: a running node's next one (after
        // the kick), a new node's first.
        let left = deadline.saturating_duration_since(Instant::now());
        out.completed =
            block_on_small(crate::custody::wait_pass_done(begun + 1, left)).unwrap_or(false);
        Ok::<(), String>(())
    })();
    crate::custody::set_pass_deadline(None);
    if out.started_node {
        let left = (began + budget).saturating_duration_since(Instant::now());
        stop_locked(left.max(Duration::from_millis(500)));
    }
    drop(held_turn);
    result?;
    out.messages = crate::custody::pass_counts().2 - fetched_before;
    out.elapsed = began.elapsed();
    Ok(Some(out))
}

/// Runs a small future (a wait on the node's state) on a throwaway
/// current-thread runtime: the caller is an app thread, not the node's.
fn block_on_small<F: std::future::Future>(f: F) -> Result<F::Output, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map(|rt| rt.block_on(f))
        .map_err(|e| format!("no runtime for the wait: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The node inside an app binds no port Raven reserves (7420-7427): its
    /// mock BLE bridge, which no friend reaches, takes any free loopback
    /// port, as the CLI's start gives the program (ash ext.rs
    /// `node_service_command`).
    #[test]
    fn the_embedded_node_takes_no_reserved_port() {
        let config = NodeConfig::new("/nonexistent/profile", "127.0.0.1:0");
        let ble: std::net::SocketAddr = config.service.ble_listen.parse().unwrap();
        assert!(ble.ip().is_loopback(), "{ble}");
        assert_eq!(ble.port(), 0, "{ble}");
    }
}
