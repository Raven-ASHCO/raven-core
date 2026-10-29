//! The Tor onion carrier (lab; `protocol/RAVEN_ONION_CARRIER_V1.md`, design
//! `docs/design/2026-10-tor-fallback.md`).
//!
//! **Tor is only a pipe.** Every onion stream carries the same Raven Noise
//! link as Internet direct ([`ONION_LINK`]: RIH1 identity bind, contact gate,
//! RLB1, ATSAM sessions, sealed ACKs), with its own prologue. Tor
//! authenticates nothing for Raven.
//!
//! **Arti runs in a helper process** (`raven-tor-helper`, cargo feature
//! `tor`), never in raven-node: a panic, Arti's `exit(1)` on an obsolete
//! protocol version (Arti #1932) or a bootstrap that spins at 100 % CPU (Arti
//! #2726) ends or hangs the helper, which this module kills and restarts.
//! raven-node itself never links Arti. The local protocol is [`proto`].
//!
//! **This module:**
//! - [`run`]: the supervised service task (only while the gate is open and a
//!   helper exists): the identity preflight, the forward listener for
//!   inbound onion streams, and the helper's life (start, config, events,
//!   watchdogs, restarts: [`watch`]);
//! - [`dial_with_meta`]: an outbound Raven link to a contact's onion service
//!   through the helper;
//! - [`network_changed`]: netwatch's hook (a network change or a wake from
//!   sleep restarts the helper; Arti handles neither, #2705, #594);
//! - [`status`] and [`status_line`]: "Tor: starting / ready / blocked on
//!   this network";
//! - the own binding ([`own_binding`]): the onion key the helper reported,
//!   signed by the Raven identity (`raven_core::onion::OnionBinding`) and
//!   kept in `onion_self.json` for cards and route hints;
//! - [`race`]: the outbox's race between the direct paths and Tor.
//!
//! **Logs** carry states and counts only: never a friend's onion address,
//! never this node's own, never Arti's own text.
//!
//! **Lab only:** `raven_core::onion_live_enabled()` (debug builds with
//! `RAVEN_LAB_TEST_A=1` and `RAVEN_LAB_TOR=1`). Debug builds may name the
//! helper (`RAVEN_TOR_HELPER=<absolute path>`) or run the loopback helper
//! instead (`RAVEN_LAB_TOR_LOOPBACK=<directory>`, [`loopback`]: the same
//! protocol with no Tor network, for tests).

pub(crate) mod proto;
pub(crate) mod race;
pub(crate) mod watch;

#[cfg(debug_assertions)]
pub(crate) mod loopback;

use std::convert::Infallible;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use raven_core::identity::Identity;
use raven_core::onion::{OnionBinding, ONION_CONNECT_BUDGET, ONION_DIAL_DEADLINE};
use raven_core::OutboxCarrier;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::internet_direct::{self, ONION_LINK};
use crate::learning::DialMeta;
use crate::netutil::{self, Admission, DialProgress, LogLimiter, ReplyWaits};
use proto::{ConnectReply, Event, ServiceState};
use watch::{Blame, End, Life, Outages, Restarts, SelfChecks, ServiceNews, ServiceWatch, Via};

/// The helper's executable name, next to raven-node.
pub(crate) const HELPER_EXECUTABLE: &str = "raven-tor-helper";
/// Debug builds: the helper to start instead (an absolute path).
pub(crate) const HELPER_ENV: &str = "RAVEN_TOR_HELPER";
/// Debug builds: run the loopback helper ([`loopback`]) with this registry
/// directory instead of Tor.
pub(crate) const LOOPBACK_ENV: &str = "RAVEN_LAB_TOR_LOOPBACK";
/// Debug builds: the race's head start in ms instead of
/// [`raven_core::onion::ONION_HEAD_START`] (tests).
pub(crate) const HEAD_START_ENV: &str = "RAVEN_LAB_TOR_HEAD_START_MS";
/// Tor's state, cache and keys under the profile.
pub(crate) const TOR_DIR: &str = "tor";
/// The admission key of an inbound onion link: its rendezvous circuit's
/// number from the helper ([`proto::decode_forward`]), as a unique-local
/// IPv6 /64 (the admission folds a source to its /64). Tor hides who
/// dialled; a circuit is the finest thing the helper can tell apart, and
/// one client's circuit cannot take every slot (security review
/// 2026-10-29 #1).
fn circuit_source(circuit: u64) -> IpAddr {
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1..8].copy_from_slice(&circuit.to_be_bytes()[1..]);
    IpAddr::V6(Ipv6Addr::from(octets))
}
/// How long the forward listener waits for the helper's header (the helper
/// writes it at once).
const TOKEN_WAIT: Duration = Duration::from_secs(10);
/// Local connections still owing the helper's header, at most: one more
/// closes the oldest of them. The helper writes its header at once, so
/// only a program without the token ever waits here, and it holds no
/// admission slot while it does.
const PRE_TOKEN_MAX: usize = 32;
/// How long an admitted onion link waits for the dialer's first byte
/// (Noise message 1, sent right after its CONNECTED): well below the whole
/// handshake's deadline, so a silent stream gives its slot back soon.
pub(crate) const FIRST_MESSAGE_WAIT: Duration = Duration::from_secs(10);

static LOG: LogLimiter = LogLimiter::new(Duration::from_secs(600));
static FORWARD_LOG: LogLimiter = LogLimiter::new(Duration::from_secs(600));

// ── Status ──────────────────────────────────────────────────────────────────

/// Where the onion carrier is, for the status line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Phase {
    /// The gate is closed (no `RAVEN_LAB_TOR`), or no service task runs.
    #[default]
    Off,
    /// No helper next to raven-node (built without the `tor` feature).
    NotBuilt,
    /// The helper bootstraps.
    Starting,
    /// The helper's client is bootstrapped: onion dials can start.
    Ready,
    /// The last bootstraps did not get through on this network; retrying.
    Blocked,
    /// Tor could not start on this computer (the helper crashed, hung, said
    /// a local error, or got stuck after Tor relays answered); retrying.
    CantStart,
    /// The helper is being started again (a failure, a network change).
    Restarting,
}

/// The onion carrier's state ([`status`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Status {
    pub(crate) phase: Phase,
    /// Bootstrap percent while starting.
    pub(crate) pct: u8,
    /// Tor's own word for why it is stuck ([`proto::blockage_word`]).
    pub(crate) tor_says: Option<&'static str>,
    /// The onion service's settled reachability ([`ServiceWatch`]): `None`
    /// until it was first reachable in this helper's life.
    pub(crate) service_reachable: Option<bool>,
    /// Why it is not reachable (a failed self-check, Arti's state and
    /// reason), while settled so.
    pub(crate) service_why: Option<String>,
    /// Its outages since raven-node started (kept across helper lives).
    pub(crate) outages: Outages,
    /// Why it is blocked, cannot start or is restarting (fixed words and
    /// numbers).
    pub(crate) why: Option<String>,
    /// When the next start is due (blocked or restarting).
    pub(crate) retry_at: Option<Instant>,
    /// The last helper's time from start to ready.
    pub(crate) bootstrap: Option<Duration>,
    /// Helpers started since raven-node started.
    pub(crate) starts: u32,
    /// The own binding exists (the onion key is known and signed).
    pub(crate) published: bool,
}

static STATUS: Mutex<Option<Status>> = Mutex::new(None);

fn status_lock() -> std::sync::MutexGuard<'static, Option<Status>> {
    STATUS.lock().unwrap_or_else(PoisonError::into_inner)
}

fn update_status(f: impl FnOnce(&mut Status)) {
    f(status_lock().get_or_insert_with(Status::default));
}

/// The onion carrier's state now.
pub(crate) fn status() -> Status {
    let mut s = status_lock().clone().unwrap_or_default();
    s.published = own_binding().is_some();
    s
}

/// The status line for IPC `Status` (`raven status`): `None` while the
/// gate is closed.
pub(crate) fn status_text() -> Option<String> {
    raven_core::onion_live_enabled().then(|| {
        let mut s = status();
        if s.phase == Phase::Off {
            // The task has not set a phase yet: it is about to start.
            s.phase = Phase::Starting;
        }
        status_line(&s, Instant::now())
    })
}

/// One line for `raven status` and the node log, states only.
pub(crate) fn status_line(s: &Status, now: Instant) -> String {
    let retry = s
        .retry_at
        .map(|at| at.saturating_duration_since(now))
        .filter(|d| !d.is_zero())
        .map(|d| format!("retrying in {}", wait_words(d)));
    match s.phase {
        Phase::Off => "Tor: off".into(),
        Phase::NotBuilt => "Tor: not built in this raven".into(),
        Phase::Starting => match s.tor_says {
            Some(word) => format!("Tor: starting ({} %, Tor says: {word})", s.pct),
            None => format!("Tor: starting ({} %)", s.pct),
        },
        Phase::Ready => {
            let history = outage_words(&s.outages, now);
            match s.service_reachable {
                Some(true) => with_parts("Tor: ready", history, None),
                Some(false) => {
                    let head = match s.outages.open_since {
                        Some(since) => format!(
                            "Tor: ready, onion service unreachable for {}",
                            wait_words(now.saturating_duration_since(since))
                        ),
                        None => "Tor: ready, onion service unreachable".into(),
                    };
                    with_parts(&head, s.service_why.clone(), history)
                }
                None => match history {
                    Some(history) => format!("Tor: ready (onion service publishing; {history})"),
                    None => "Tor: ready (onion service publishing)".into(),
                },
            }
        }
        Phase::Blocked => with_parts("Tor: blocked on this network", s.why.clone(), retry),
        Phase::CantStart => with_parts(
            "Tor: could not start on this computer",
            s.why.clone(),
            retry,
        ),
        Phase::Restarting => with_parts("Tor: restarting", s.why.clone(), retry),
    }
}

/// The onion service's outages since start, for the status line: none
/// said while there were none.
fn outage_words(o: &Outages, now: Instant) -> Option<String> {
    if o.count == 0 {
        return None;
    }
    let mut words = format!("onion service outages since start: {}", o.count);
    if let Some((ended, lasted)) = o.last {
        words.push_str(&format!(
            ", the last lasted {} and ended {} ago",
            wait_words(lasted),
            wait_words(now.saturating_duration_since(ended))
        ));
    }
    Some(words)
}

/// `head (why; retry)`, or just `head`.
fn with_parts(head: &str, why: Option<String>, retry: Option<String>) -> String {
    let parts: Vec<String> = why.into_iter().chain(retry).collect();
    if parts.is_empty() {
        head.into()
    } else {
        format!("{head} ({})", parts.join("; "))
    }
}

fn wait_words(d: Duration) -> String {
    let s = d.as_secs().max(1);
    if s < 120 {
        format!("{s} s")
    } else {
        format!("{} min", s.div_ceil(60))
    }
}

// ── The running helper ──────────────────────────────────────────────────────

/// What dials need from the running helper.
#[derive(Clone)]
struct Live {
    token: [u8; proto::TOKEN_LEN],
    connect: Option<SocketAddr>,
    binding: Option<OnionBinding>,
}

static LIVE: Mutex<Option<Live>> = Mutex::new(None);

fn live_lock() -> std::sync::MutexGuard<'static, Option<Live>> {
    LIVE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The helper's connect address and its token, while it is ready.
fn ready_connect() -> Option<(SocketAddr, [u8; proto::TOKEN_LEN])> {
    let live = live_lock();
    let live = live.as_ref()?;
    Some((live.connect?, live.token))
}

/// This node's own onion binding while the onion service task runs and the
/// helper reported its key (route hints and the status read it; a card
/// reads `onion_self.json`).
pub(crate) fn own_binding() -> Option<OnionBinding> {
    live_lock().as_ref()?.binding
}

/// Ends with the task: no dial may use a helper that is gone.
struct LiveGuard;

impl Drop for LiveGuard {
    fn drop(&mut self) {
        *live_lock() = None;
        raven_core::onion_gate::set_onion_ready(false);
        update_status(|s| *s = Status::default());
    }
}

/// The onion route may be planned for `peer` now: the gate is open and the
/// helper is ready ([`raven_core::onion_gate::onion_usable_now`]).
pub(crate) fn available() -> bool {
    raven_core::onion_gate::onion_usable_now() && ready_connect().is_some()
}

/// Blocking: keep `binding`, learned from the verified contact `peer`'s
/// route hints (RRH1 ONION, already verified), in its contact book row
/// (`onion`) when it is newer than the one there (or there is none). The
/// book is sealed at rest, and the binding goes with the contact. It is
/// verified again here: never an unsigned or foreign onion address. Best
/// effort: an unreadable or locked book keeps what it had.
pub(crate) fn learn_binding(data_dir: &Path, peer: &[u8; 32], binding: OnionBinding) {
    if let Err(e) = raven_core::onion::store_contact_binding(data_dir, peer, &binding) {
        netutil::log_limited(&LOG, "raven-node onion", format_args!("contact book: {e}"));
    }
}

/// The race's head start ([`raven_core::onion::ONION_HEAD_START`]; debug
/// builds may set [`HEAD_START_ENV`] for tests).
pub(crate) fn head_start() -> Duration {
    if cfg!(debug_assertions) {
        if let Some(ms) = std::env::var(HEAD_START_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
        {
            return Duration::from_millis(ms.min(60_000));
        }
    }
    raven_core::onion::ONION_HEAD_START
}

// ── Restarts on network change and wake ─────────────────────────────────────

static RESTART: tokio::sync::Notify = tokio::sync::Notify::const_new();
static RESTART_WHY: Mutex<Option<End>> = Mutex::new(None);

/// netwatch's hook: this computer's paths are stale (a network gone or
/// back, the default route moved) or it woke from sleep. A running helper is
/// restarted at once (Arti handles neither, #2705, #594); a helper waiting
/// for its next start starts now. Nothing while no onion task runs.
pub(crate) fn network_changed(woke: bool) {
    if live_lock().is_none() {
        return;
    }
    *RESTART_WHY.lock().unwrap_or_else(PoisonError::into_inner) =
        Some(if woke { End::Woke } else { End::NetworkChanged });
    RESTART.notify_one();
}

async fn restart_requested() -> End {
    RESTART.notified().await;
    RESTART_WHY
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .unwrap_or(End::NetworkChanged)
}

// ── Finding and starting the helper ─────────────────────────────────────────

/// How the helper is started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Launcher {
    /// `raven-tor-helper` (Arti).
    Exe(PathBuf),
    /// Debug builds: `raven-node tor-loopback-helper` with this registry
    /// directory (no Tor network).
    Loopback { exe: PathBuf, dir: PathBuf },
}

impl Launcher {
    /// The helper this process would start; `None`: none is built.
    pub(crate) fn find() -> Option<Self> {
        let exe = std::env::current_exe().ok();
        Self::find_with(
            cfg!(debug_assertions),
            std::env::var_os(LOOPBACK_ENV).map(PathBuf::from),
            std::env::var_os(HELPER_ENV).map(PathBuf::from),
            exe,
            |p| p.is_file(),
        )
    }

    /// [`Self::find`] from its inputs: in a debug build the loopback
    /// directory first, then an absolute helper path; else the helper next
    /// to raven-node.
    pub(crate) fn find_with(
        debug: bool,
        loopback: Option<PathBuf>,
        env: Option<PathBuf>,
        exe: Option<PathBuf>,
        exists: impl Fn(&Path) -> bool,
    ) -> Option<Self> {
        if debug {
            if let (Some(dir), Some(exe)) = (
                loopback.filter(|d| d.is_absolute()),
                exe.as_ref().filter(|e| exists(e)),
            ) {
                return Some(Self::Loopback {
                    exe: exe.clone(),
                    dir,
                });
            }
            if let Some(p) = env.filter(|p| !p.as_os_str().is_empty()) {
                return (p.is_absolute() && exists(&p)).then_some(Self::Exe(p));
            }
        }
        let name = format!("{HELPER_EXECUTABLE}{}", std::env::consts::EXE_SUFFIX);
        let helper = exe?.parent()?.join(name);
        exists(&helper).then_some(Self::Exe(helper))
    }

    fn command(&self) -> tokio::process::Command {
        let mut cmd = match self {
            Self::Exe(p) => tokio::process::Command::new(p),
            Self::Loopback { exe, dir } => {
                let mut c = tokio::process::Command::new(exe);
                c.arg("tor-loopback-helper").arg("--registry").arg(dir);
                c
            }
        };
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        cmd
    }
}

/// One started helper, as the supervisor drives it.
pub(crate) struct Proc {
    pub(crate) stdin: Pin<Box<dyn AsyncWrite + Send>>,
    pub(crate) stdout: Pin<Box<dyn AsyncRead + Send>>,
    pub(crate) stderr: Option<Pin<Box<dyn AsyncRead + Send>>>,
    /// Resolves when the helper ended (after a kill too).
    pub(crate) done: Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    /// Ends it now.
    pub(crate) kill: Option<tokio::sync::oneshot::Sender<()>>,
}

/// Starts helpers ([`Launcher`] in the service; a fake in tests).
pub(crate) trait Spawn: Send + Sync {
    fn spawn(&self) -> Result<Proc, String>;
}

impl Spawn for Launcher {
    fn spawn(&self) -> Result<Proc, String> {
        let mut child = self
            .command()
            .spawn()
            .map_err(|e| format!("the Tor helper could not be started ({})", e.kind()))?;
        let stdin = child.stdin.take().ok_or("the Tor helper has no stdin")?;
        let stdout = child.stdout.take().ok_or("the Tor helper has no stdout")?;
        let stderr = child.stderr.take();
        let (kill, killed) = tokio::sync::oneshot::channel::<()>();
        let done = async move {
            tokio::select! {
                _ = child.wait() => {}
                _ = killed => {
                    let _ = child.kill().await;
                }
            }
        };
        Ok(Proc {
            stdin: Box::pin(stdin),
            stdout: Box::pin(stdout),
            stderr: stderr.map(|e| Box::pin(e) as Pin<Box<dyn AsyncRead + Send>>),
            done: Box::pin(done),
            kill: Some(kill),
        })
    }
}

// ── The service task ────────────────────────────────────────────────────────

/// The onion carrier's service task (supervised by raven-node like every
/// carrier): nothing while the gate is closed or no helper is built (it
/// says so once), else the identity preflight, the forward listener and the
/// helper's life, for as long as the task lives.
pub(crate) async fn run(data_dir: PathBuf) -> Result<(), String> {
    if !raven_core::onion_live_enabled() {
        return std::future::pending().await;
    }
    let Some(launcher) = Launcher::find() else {
        update_status(|s| s.phase = Phase::NotBuilt);
        eprintln!(
            "raven-node onion: Tor: not built in this raven (no {HELPER_EXECUTABLE} next to \
             raven-node; build with `--features tor`)"
        );
        return std::future::pending().await;
    };
    run_with(data_dir, Arc::new(launcher)).await
}

/// [`run`] with the helper starter given.
pub(crate) async fn run_with(data_dir: PathBuf, spawner: Arc<dyn Spawn>) -> Result<(), String> {
    let identity = Arc::new(
        netutil::retry_until_ok("onion", || {
            let dd = data_dir.clone();
            async move {
                internet_direct::blocking(move || {
                    internet_direct::preflight_link_ready(ONION_LINK, &dd)
                        .map_err(|e| raven_core::disk_space::with_disk_full_note(&dd, e))
                })
                .await
            }
        })
        .await,
    );
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|e| format!("onion forward listener: {}", netutil::io_error_text(&e)))?;
    let forward = listener
        .local_addr()
        .map_err(|e| format!("onion forward listener: {e}"))?;
    let token: [u8; proto::TOKEN_LEN] = rand::random();
    *live_lock() = Some(Live {
        token,
        connect: None,
        binding: None,
    });
    let _live = LiveGuard;
    let state_dir = data_dir.join(TOR_DIR);
    std::fs::create_dir_all(&state_dir)
        .map_err(|e| format!("onion state directory: {}", netutil::io_error_text(&e)))?;
    restrict_dir(&state_dir);
    let serving = tokio::spawn(serve_forward(
        listener,
        token,
        data_dir.clone(),
        identity.clone(),
    ));
    let _serving = AbortOnDrop(serving.abort_handle());
    let config = proto::Config {
        v: proto::PROTO_VERSION,
        state_dir: state_dir.to_string_lossy().into_owned(),
        token: hex::encode(token),
        forward: forward.to_string(),
        port: raven_core::onion::ONION_VIRTUAL_PORT,
        fresh_state: false,
    };
    match supervise(spawner, config, data_dir, identity).await {}
}

struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Owner-only, best effort (Arti checks permissions itself and refuses a
/// directory others can write).
fn restrict_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// The helper's lives, one after the other, for as long as the task lives.
async fn supervise(
    spawner: Arc<dyn Spawn>,
    mut config: proto::Config,
    data_dir: PathBuf,
    identity: Arc<Identity>,
) -> Infallible {
    let mut restarts = Restarts::default();
    loop {
        restarts.started();
        update_status(|s| {
            *s = Status {
                phase: Phase::Starting,
                starts: restarts.started,
                published: s.published,
                outages: s.outages,
                ..Status::default()
            }
        });
        eprintln!("raven-node onion: Tor: starting");
        let started = Instant::now();
        let (end, blame) = match spawner.spawn() {
            Ok(proc) => {
                let (end, life) =
                    run_once(proc, &config, &mut restarts, &data_dir, &identity).await;
                // The helper's last words: states, fixed tags and numbers.
                eprintln!(
                    "raven-node onion: {}",
                    life.summary(end, now_for_watchdogs())
                );
                (end, life.blame(end))
            }
            Err(e) => {
                eprintln!("raven-node onion: {e}");
                (End::Exited, Blame::ThisComputer(e))
            }
        };
        if let Some(live) = live_lock().as_mut() {
            live.connect = None;
        }
        raven_core::onion_gate::set_onion_ready(false);
        let next = restarts.ended(end, started.elapsed(), &blame);
        config.fresh_state = next.fresh_state;
        let retry_at = (!next.wait.is_zero()).then(|| Instant::now() + next.wait);
        update_status(|s| {
            (s.phase, s.why) = match blame {
                Blame::Network(why) => (Phase::Blocked, Some(why)),
                Blame::ThisComputer(why) => (Phase::CantStart, Some(why)),
                Blame::Restart => (Phase::Restarting, Some(end.words().into())),
            };
            s.retry_at = retry_at;
            s.service_reachable = None;
            s.service_why = None;
        });
        eprintln!(
            "raven-node onion: {}",
            status_line(&status(), Instant::now())
        );
        if !next.wait.is_zero() {
            // A network change or a wake ends the wait: the new network may
            // let Tor through.
            tokio::select! {
                () = tokio::time::sleep(next.wait) => {}
                _ = restart_requested() => {}
            }
        }
    }
}

/// The watchdogs' clock: tokio's (a paused test clock moves it), as a std
/// instant.
fn now_for_watchdogs() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// One helper's life: the config, then its events under the watchdogs,
/// until it ends or is ended. Returns why, and what it saw of the helper.
async fn run_once(
    mut proc: Proc,
    config: &proto::Config,
    restarts: &mut Restarts,
    data_dir: &Path,
    identity: &Arc<Identity>,
) -> (End, Life) {
    let kill = |proc: &mut Proc| {
        if let Some(k) = proc.kill.take() {
            let _ = k.send(());
        }
    };
    if proc
        .stdin
        .write_all(proto::line(config).as_bytes())
        .await
        .is_err()
    {
        kill(&mut proc);
        return (End::Exited, Life::new(now_for_watchdogs()));
    }
    let mut life = Life::new(now_for_watchdogs());
    let mut stdout = LineReader::new(proc.stdout);
    let mut stderr = proc.stderr.map(LineReader::new);
    let mut obsolete = false;
    let mut errors_logged = 0u8;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut ping = tokio::time::interval(watch::PING_EVERY);
    let mut ping_n: u64 = 0;
    let mut service = ServiceWatch::default();
    let mut checks = SelfChecks::default();
    let mut friend_links_seen = FRIEND_LINKS.load(std::sync::atomic::Ordering::Relaxed);
    let mut done = proc.done;
    loop {
        tokio::select! {
            line = stdout.next_line() => match line {
                Some(line) => {
                    let now = now_for_watchdogs();
                    handle_event(
                        &line,
                        &mut life,
                        restarts,
                        (&mut service, &mut checks),
                        data_dir,
                        identity,
                        &mut errors_logged,
                        now,
                    )
                    .await;
                }
                None => {
                    // Its stdout closed: it is ending. Give it a moment to
                    // finish (and to say why on stderr), then make sure.
                    let _ = tokio::time::timeout(Duration::from_secs(5), &mut done).await;
                    if let Some(err) = stderr.as_mut() {
                        let said = drain_stderr(err).await;
                        obsolete |= said.obsolete;
                        if said.panicked {
                            life.crashed();
                        }
                    }
                    if let Some(k) = proc.kill.take() {
                        let _ = k.send(());
                    }
                    return (if obsolete { End::Obsolete } else { End::Exited }, life);
                }
            },
            line = next_stderr(&mut stderr) => {
                if let Some(line) = line {
                    obsolete |= says_obsolete(&line);
                    if says_panicked(&line) {
                        life.crashed();
                    }
                }
            }
            () = &mut done => {
                // Its last events (an error it said just before it exited)
                // may still be in the pipe: read them first.
                let drain = async {
                    while let Some(line) = stdout.next_line().await {
                        handle_event(
                            &line,
                            &mut life,
                            restarts,
                            (&mut service, &mut checks),
                            data_dir,
                            identity,
                            &mut errors_logged,
                            now_for_watchdogs(),
                        )
                        .await;
                    }
                };
                let _ = tokio::time::timeout(Duration::from_secs(2), drain).await;
                if let Some(err) = stderr.as_mut() {
                    let said = drain_stderr(err).await;
                    obsolete |= said.obsolete;
                    if said.panicked {
                        life.crashed();
                    }
                }
                return (if obsolete { End::Obsolete } else { End::Exited }, life);
            }
            _ = tick.tick() => {
                // A friend's authenticated incoming Tor link since the last
                // tick proves the service reachable ([`friend_reached_us`]).
                let proofs = FRIEND_LINKS.load(std::sync::atomic::Ordering::Relaxed);
                if proofs != friend_links_seen {
                    friend_links_seen = proofs;
                    if let Some(news) = service.reached_by_friend(now_for_watchdogs()) {
                        say_service(news, &service, &life, now_for_watchdogs());
                    }
                }
                if let Some(news) = service.settle(now_for_watchdogs()) {
                    say_service(news, &service, &life, now_for_watchdogs());
                }
                // Measure, instead of trusting Arti's state: our own Tor
                // client reaches our service as a friend would.
                if let Some(n) = checks.due(now_for_watchdogs()) {
                    let cmd = proto::line(&proto::Command::SelfCheck { n });
                    if proc.stdin.write_all(cmd.as_bytes()).await.is_err() {
                        // Its stdin closed: it is ending; `done` says when.
                    }
                }
                if let Some(end) = life.check(now_for_watchdogs()) {
                    if let Some(k) = proc.kill.take() {
                        let _ = k.send(());
                    }
                    let _ = tokio::time::timeout(Duration::from_secs(5), &mut done).await;
                    return (end, life);
                }
            }
            // From the start: a helper that hangs while it bootstraps is
            // this computer's problem, not the network's.
            _ = ping.tick() => {
                ping_n += 1;
                let cmd = proto::line(&proto::Command::Ping { n: ping_n });
                if proc.stdin.write_all(cmd.as_bytes()).await.is_err() {
                    // Its stdin closed: it is ending; `done` says when.
                }
            }
            end = restart_requested() => {
                let _ = proc
                    .stdin
                    .write_all(proto::line(&proto::Command::Stop).as_bytes())
                    .await;
                if let Some(k) = proc.kill.take() {
                    let _ = k.send(());
                }
                let _ = tokio::time::timeout(Duration::from_secs(5), &mut done).await;
                return (end, life);
            }
        }
    }
}

async fn next_stderr(stderr: &mut Option<LineReader>) -> Option<String> {
    match stderr {
        Some(r) => match r.next_line().await {
            Some(line) => Some(line),
            None => {
                *stderr = None;
                std::future::pending().await
            }
        },
        None => std::future::pending().await,
    }
}

/// Arti's own words when a consensus marks its version unsupported (it then
/// calls `exit(1)`, Arti #1932). The stderr texts raven-node looks for;
/// none of it is logged.
fn says_obsolete(line: &str) -> bool {
    line.contains("unsupported software version")
}

/// A Rust panic's first line (`thread '…' panicked at …`).
fn says_panicked(line: &str) -> bool {
    line.contains("panicked at")
}

/// What the helper's last stderr lines said.
#[derive(Default)]
struct Said {
    obsolete: bool,
    panicked: bool,
}

async fn drain_stderr(stderr: &mut LineReader) -> Said {
    let mut said = Said::default();
    let read_all = async {
        while let Some(line) = stderr.next_line().await {
            said.obsolete |= says_obsolete(&line);
            said.panicked |= says_panicked(&line);
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(2), read_all).await;
    said
}

/// The helper error lines logged per helper life (the rest are in its
/// last words).
const ERRORS_LOGGED: u8 = 4;

/// One event from the helper.
#[allow(clippy::too_many_arguments)]
async fn handle_event(
    line: &str,
    life: &mut Life,
    restarts: &mut Restarts,
    (service, checks): (&mut ServiceWatch, &mut SelfChecks),
    data_dir: &Path,
    identity: &Arc<Identity>,
    errors_logged: &mut u8,
    now: Instant,
) {
    let Ok(event) = serde_json::from_str::<Event>(line) else {
        netutil::log_limited(
            &LOG,
            "raven-node onion",
            "the Tor helper wrote a line it should not",
        );
        return;
    };
    match event {
        Event::Progress {
            pct,
            blocked,
            stage,
        } => {
            let pct = pct.min(100);
            // Fixed words only, whatever the helper wrote.
            let tor_says = blocked.as_deref().map(proto::blockage_word);
            let stage = stage.as_deref().map(proto::known_stage);
            let new_stage = life.progress(pct, stage, tor_says, now);
            if new_stage && !life.is_ready() {
                // A few lines per start: where a slow or stuck start is.
                eprintln!(
                    "raven-node onion: Tor: starting ({} %, {}{}, {} s)",
                    life.pct(),
                    life.stage().unwrap_or("-"),
                    life.tor_says()
                        .map(|w| format!(", Tor says: {w}"))
                        .unwrap_or_default(),
                    life.age(now).as_secs()
                );
            }
            update_status(|s| {
                if s.phase == Phase::Starting {
                    s.pct = life.pct();
                    s.tor_says = tor_says;
                }
            });
        }
        Event::Ready { connect } => {
            let Some(addr) = connect
                .parse::<SocketAddr>()
                .ok()
                .filter(|a| a.ip().is_loopback())
            else {
                netutil::log_limited(
                    &LOG,
                    "raven-node onion",
                    "the Tor helper named no loopback port",
                );
                return;
            };
            let first = !life.is_ready();
            life.ready(now);
            restarts.ready();
            if let Some(live) = live_lock().as_mut() {
                live.connect = Some(addr);
            }
            raven_core::onion_gate::set_onion_ready(true);
            let bootstrap = life.bootstrap_time();
            update_status(|s| {
                s.phase = Phase::Ready;
                s.pct = 100;
                s.tor_says = None;
                s.why = None;
                s.retry_at = None;
                s.bootstrap = bootstrap;
            });
            if first {
                eprintln!(
                    "raven-node onion: Tor: ready (bootstrap {})",
                    bootstrap.map_or_else(|| "?".into(), wait_words)
                );
                // A path just opened: what waits goes now.
                let _ = crate::outbox::network_changed();
            }
        }
        Event::Onion { hs_id } => {
            let Some(hs_id) = proto::parse_hs_id(&hs_id) else {
                netutil::log_limited(
                    &LOG,
                    "raven-node onion",
                    "the Tor helper named no onion key",
                );
                return;
            };
            let dd = data_dir.to_path_buf();
            let id = identity.clone();
            let bound = internet_direct::blocking(move || own_binding_for(&dd, &id, hs_id)).await;
            match bound {
                Ok(binding) => {
                    if let Some(live) = live_lock().as_mut() {
                        live.binding = Some(binding);
                    }
                    update_status(|s| s.published = true);
                    // Route hints tell friends the (new) address.
                    crate::hints::own_changed();
                    // The service is launched: self-checks from now on.
                    checks.published(now);
                }
                Err(e) => netutil::log_limited(&LOG, "raven-node onion", e),
            }
        }
        Event::Service { state, reason } => {
            let Some(state) = ServiceState::parse(&state) else {
                return;
            };
            // Fixed phrases only, whatever the helper wrote.
            let reason = reason.as_deref().map(proto::known_reason);
            // Arti's raw states are not news (it says "bootstrapping" for
            // every republish): only what settled ([`ServiceWatch`]).
            if let Some(news) = service.observe(state, reason, now) {
                say_service(news, service, life, now);
            }
            if service.arti_trouble() {
                checks.trouble(now);
            }
        }
        Event::Uploads { ok, of } => {
            // Counts only (round 9: rounds whose HSDirs all timed out made
            // Arti say "degraded_unreachable").
            eprintln!(
                "raven-node onion: Tor: descriptor upload round: {ok} of {of} HSDirs took it"
            );
            // Published: a self-check soon says whether friends reach us
            // (E2 r40: 3 min after a network change before).
            if ok > 0 {
                checks.uploaded(now);
            }
        }
        Event::SelfCheck { n, reached, reason } => {
            if !checks.answered(n, reached, now) {
                return;
            }
            let reason = reason.as_deref().map(proto::known_connect_reason);
            let arti = service.arti_trouble().then(|| service.why(now));
            match (reached, arti) {
                (true, None) => eprintln!("raven-node onion: Tor: self-check reached our onion service"),
                (true, Some(arti)) => eprintln!(
                    "raven-node onion: Tor: self-check reached our onion service, whatever {arti} says"
                ),
                (false, _) => eprintln!(
                    "raven-node onion: Tor: self-check did not reach our onion service ({})",
                    reason.unwrap_or("other")
                ),
            }
            if reached {
                // Tor works here: no friend's Tor route stays marked failed
                // for the next send (E2 r40).
                crate::delivery_paths::tor_works_here();
            }
            if let Some(news) = service.self_checked(reached, reason, now) {
                say_service(news, service, life, now);
            }
        }
        Event::Pong { .. } => life.pong(now),
        Event::Error { what, local } => {
            // The helper's texts are fixed and name no address; cut anyway
            // (Life::error).
            life.error(&what, local);
            if *errors_logged < ERRORS_LOGGED {
                *errors_logged += 1;
                if let Some((what, local)) = life.last_error() {
                    let place = if local { "this computer" } else { "Tor" };
                    eprintln!("raven-node onion: Tor helper error ({place}): {what}");
                }
            }
        }
    }
}

/// Friends' authenticated incoming Tor links so far ([`friend_reached_us`]).
static FRIEND_LINKS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A friend (a verified contact) reached this node over Tor and its link
/// authenticated: our onion service is reachable, whatever Arti says yet
/// ([`ServiceWatch::reached_by_friend`]). Counts only; who it was is not
/// kept.
pub(crate) fn friend_reached_us() {
    FRIEND_LINKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// The onion service's settled news: one log line and the status. Our own
/// service's state gates nothing else: sends to friends (Tor client
/// circuits) and friends' links to us (the published descriptor) go on
/// whatever Arti says meanwhile.
fn say_service(news: ServiceNews, watch: &ServiceWatch, life: &Life, now: Instant) {
    let how = |via: Via| match via {
        Via::Arti => "",
        Via::Friend => "a friend reached it over Tor",
        Via::SelfCheck => "a self-check reached it",
    };
    match news {
        ServiceNews::Reachable { via } => eprintln!(
            "raven-node onion: Tor: onion service reachable ({} after start{})",
            wait_words(life.age(now)),
            match via {
                Via::Arti => String::new(),
                via => format!("; {} before Tor said so", how(via)),
            }
        ),
        ServiceNews::Unreachable { since } => eprintln!(
            "raven-node onion: Tor: onion service unreachable for {} ({})",
            wait_words(now.saturating_duration_since(since)),
            watch.why(now)
        ),
        ServiceNews::ReachableAgain { via } => eprintln!(
            "raven-node onion: Tor: onion service reachable again{}",
            match via {
                Via::Arti => String::new(),
                via => format!(" ({})", how(via)),
            }
        ),
    }
    let reachable = watch.settled();
    let why = (reachable == Some(false)).then(|| watch.why(now));
    update_status(|s| {
        s.service_reachable = reachable;
        s.service_why = why;
        match news {
            ServiceNews::Unreachable { since } => s.outages.began(since),
            ServiceNews::Reachable { .. } | ServiceNews::ReachableAgain { .. } => {
                s.outages.ended(now);
            }
        }
    });
}

/// Blocking: this node's binding for the onion key `hs_id`: the saved one
/// when it names that key and verifies, else a new one (dated after the
/// saved one, so friends take it), saved.
fn own_binding_for(
    data_dir: &Path,
    identity: &Identity,
    hs_id: [u8; 32],
) -> Result<OnionBinding, String> {
    let own = identity.public_key_bytes();
    let now = raven_core::onion::now_s();
    let saved = raven_core::onion::load_own(data_dir);
    if let Some(b) = saved.filter(|b| b.hs_id == hs_id && b.verify(&own, now)) {
        return Ok(b);
    }
    let issued = saved.map_or(now, |b| now.max(b.issued_s.saturating_add(1)));
    let binding = OnionBinding::sign(identity, hs_id, issued);
    raven_core::onion::save_own(data_dir, &binding)?;
    Ok(binding)
}

/// Lines of at most [`proto::MAX_LINE`] bytes; a longer one is skipped.
pub(crate) struct LineReader {
    inner: Pin<Box<dyn AsyncRead + Send>>,
    buf: Vec<u8>,
    eof: bool,
}

impl LineReader {
    pub(crate) fn new(inner: Pin<Box<dyn AsyncRead + Send>>) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            eof: false,
        }
    }

    /// The next line without its newline; `None` at the end.
    pub(crate) async fn next_line(&mut self) -> Option<String> {
        let mut skipping = false;
        loop {
            if let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=i).collect();
                if skipping || line.len() > proto::MAX_LINE + 1 {
                    skipping = false;
                    continue;
                }
                let text = String::from_utf8_lossy(&line[..line.len() - 1]);
                return Some(text.trim_end_matches('\r').to_string());
            }
            if self.buf.len() > proto::MAX_LINE {
                self.buf.clear();
                skipping = true;
            }
            if self.eof {
                return None;
            }
            let mut chunk = [0u8; 1024];
            match self.inner.read(&mut chunk).await {
                Ok(0) | Err(_) => self.eof = true,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
            }
        }
    }
}

// ── Inbound: the forward listener ───────────────────────────────────────────

/// Serve the helper's forwarded onion streams: the helper's header first
/// (token and circuit number) before any admission slot is taken, then the
/// Raven link listener of the onion carrier, under the onion limits, counted
/// per circuit.
async fn serve_forward(
    listener: TcpListener,
    token: [u8; proto::TOKEN_LEN],
    data_dir: PathBuf,
    identity: Arc<Identity>,
) -> Infallible {
    let limits = netutil::ONION_INBOUND;
    // No penalty box: every source is the helper (Tor hides who dialled).
    let admission = Admission::new(limits);
    let pre_token = Arc::new(PreToken::default());
    loop {
        let (stream, peer) = crate::accept_retrying("onion", &mut || listener.accept()).await;
        if !peer.ip().is_loopback() {
            continue;
        }
        let _ = stream.set_nodelay(true);
        let (waiting, kicked) = pre_token.enter();
        let (dd, id) = (data_dir.clone(), identity.clone());
        let (admission, pre_token) = (Arc::clone(&admission), Arc::clone(&pre_token));
        tokio::spawn(async move {
            // The header before any slot: a local program without the token
            // holds none (security review 2026-10-29 #1).
            let header = tokio::select! {
                got = check_token(stream, &token) => got,
                () = kicked.notified() => Err("a local connection waited too long for its token".into()),
            };
            pre_token.leave(waiting);
            let (stream, circuit) = match header {
                Ok(got) => got,
                Err(e) => {
                    netutil::log_inbound_failure("onion inbound", format_args!("{e}"));
                    return;
                }
            };
            let Some(mut slot) = admission.try_admit(circuit_source(circuit)) else {
                netutil::log_limited(
                    &FORWARD_LOG,
                    "onion",
                    "inbound onion link cap reached; refused a link",
                );
                return;
            };
            let displaced = slot.displaced();
            let work = async move {
                first_message_within(&stream, FIRST_MESSAGE_WAIT).await?;
                ONION_LINK.require_live()?;
                internet_direct::serve_inbound_on(
                    ONION_LINK, dd, id, stream, limits, &mut slot, None, None, None,
                )
                .await
            };
            tokio::select! {
                done = tokio::time::timeout(limits.lifetime, work) => match done {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => netutil::log_inbound_failure(
                        "onion inbound",
                        format_args!("from a Tor stream: {e}"),
                    ),
                    Err(_) => netutil::log_inbound_failure(
                        "onion inbound",
                        "from a Tor stream: connection lifetime exceeded",
                    ),
                },
                () = displaced.notified() => netutil::log_inbound_failure(
                    "onion inbound",
                    "from a Tor stream: unauthenticated link displaced by a newcomer",
                ),
                () = crate::lock::until_locked() => {}
            }
        });
    }
}

/// The forward listener's connections still owing the helper's header
/// ([`PRE_TOKEN_MAX`]): a newcomer past the cap closes the oldest.
#[derive(Default)]
struct PreToken(Mutex<PreTokenState>);

#[derive(Default)]
struct PreTokenState {
    next: u64,
    waiting: std::collections::VecDeque<(u64, Arc<tokio::sync::Notify>)>,
}

impl PreToken {
    /// A new connection's place, and its "closed for a newcomer" signal.
    fn enter(&self) -> (u64, Arc<tokio::sync::Notify>) {
        let mut st = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if st.waiting.len() >= PRE_TOKEN_MAX {
            if let Some((_, oldest)) = st.waiting.pop_front() {
                // Stores a permit: the wake-up is not lost if that task has
                // not polled yet.
                oldest.notify_one();
            }
        }
        let id = st.next;
        st.next += 1;
        let kicked = Arc::new(tokio::sync::Notify::new());
        st.waiting.push_back((id, Arc::clone(&kicked)));
        (id, kicked)
    }

    fn leave(&self, id: u64) {
        let mut st = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        st.waiting.retain(|(w, _)| *w != id);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .waiting
            .len()
    }
}

/// The helper's header within [`TOKEN_WAIT`]: the token, then the stream's
/// circuit number. Anyone else on this computer is closed before any Raven
/// byte.
async fn check_token(
    mut stream: TcpStream,
    token: &[u8; proto::TOKEN_LEN],
) -> Result<(TcpStream, u64), String> {
    let mut got = [0u8; proto::FORWARD_HEADER_LEN];
    tokio::time::timeout(TOKEN_WAIT, stream.read_exact(&mut got))
        .await
        .map_err(|_| "no helper token".to_string())?
        .map_err(|e| netutil::io_error_text(&e))?;
    match proto::decode_forward(&got, token) {
        Some(circuit) => Ok((stream, circuit)),
        None => Err("a local connection without the Tor helper's token".into()),
    }
}

/// Wait up to `wait` for the dialer's first byte (Noise message 1), without
/// reading it.
async fn first_message_within(stream: &TcpStream, wait: Duration) -> Result<(), String> {
    let mut one = [0u8; 1];
    match tokio::time::timeout(wait, stream.peek(&mut one)).await {
        Ok(Ok(n)) if n > 0 => Ok(()),
        Ok(Ok(_)) => Err("the Tor stream closed before Noise message 1".into()),
        Ok(Err(e)) => Err(netutil::io_error_text(&e)),
        Err(_) => Err(format!("no Noise message 1 within {}s", wait.as_secs())),
    }
}

// ── Outbound: an onion dial ─────────────────────────────────────────────────

/// Not ready to dial over Tor.
pub(crate) const ONION_NOT_READY: &str = "ONION_NOT_READY: Tor is not ready on this computer yet \
    (starting, or blocked on this network)";
/// The contact's onion service did not answer over Tor.
pub(crate) const ONION_UNREACHABLE: &str = "ONION_UNREACHABLE: the contact's onion service did \
    not answer over Tor";
/// The route is no onion route.
const ONION_BAD_ROUTE: &str = "onion route must be onion:<64 hex>";

/// An onion dial to the verified contact `expected_pub_hex` at the onion
/// route `dial` ([`raven_core::onion::dial_for`]): the helper's Tor stream,
/// then the Raven link ([`ONION_LINK`]), `frames` and their replies. Waits
/// sized for Tor (design §3.5). In the outbox race, `meta.race` claims the
/// attempt when the link authenticated.
pub(crate) async fn dial_with_meta(
    data_dir: &Path,
    dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
    meta: DialMeta,
) -> Result<Vec<Vec<u8>>, String> {
    ONION_LINK.require_live()?;
    let expected = internet_direct::parse_pub_hex(expected_pub_hex)?;
    {
        let dd = data_dir.to_path_buf();
        let pinned =
            internet_direct::blocking(move || raven_core::contact_is_pinned(&dd, &expected))
                .await?;
        if !raven_core::carrier_allowed_for_contact(OutboxCarrier::Onion, pinned) {
            return Err(format!(
                "{}: Tor delivery needs a verified contact (fingerprint pinned); nothing was \
                 dialled",
                raven_core::CONTACT_NOT_VERIFIED
            ));
        }
    }
    let hs_id = raven_core::onion::dial_hs_id(dial).ok_or(ONION_BAD_ROUTE)?;
    let (helper, token) = ready_connect().ok_or(ONION_NOT_READY)?;
    // Counted as running until it ends, however it ends (E2 r40: a send
    // whose friend Tor is still dialling need not wait for Tor again).
    let _running = crate::delivery_paths::onion_dial_started(&expected);
    let mut progress = DialProgress::with_connect(
        "ONION",
        ReplyWaits {
            first: netutil::PRODUCTION_REPLY_WAITS.first,
            idle: raven_core::onion::ONION_REPLY_IDLE,
        },
        ONION_CONNECT_BUDGET,
    );
    progress.collector.set_race(meta.race);
    let deadline = meta.deadline(ONION_DIAL_DEADLINE);
    let outcome = tokio::time::timeout(
        deadline,
        internet_direct::dial_session_on(
            ONION_LINK,
            data_dir,
            || connect_via_helper(helper, token, hs_id),
            &expected,
            frames,
            None,
            &mut progress,
        ),
    )
    .await;
    let replies = match outcome {
        Ok(Ok(())) => Ok(progress.collector.into_replies()),
        Ok(Err(e)) => Err(e),
        // Never the onion address in the text: "a contact's onion service".
        Err(_) => progress.on_deadline("onion", "a contact's onion service", deadline),
    };
    crate::clock_notes::dialled(&expected, frames, &replies);
    let replies = replies?;
    crate::delivery_paths::note(&expected, OutboxCarrier::Onion, None, frames, &replies);
    Ok(replies)
}

/// A Tor stream to `hs_id`'s onion service through the helper at `helper`.
async fn connect_via_helper(
    helper: SocketAddr,
    token: [u8; proto::TOKEN_LEN],
    hs_id: [u8; 32],
) -> Result<TcpStream, String> {
    let work = async {
        let mut stream = TcpStream::connect(helper)
            .await
            .map_err(|_| ONION_NOT_READY.to_string())?;
        let _ = stream.set_nodelay(true);
        stream
            .write_all(&proto::encode_connect(
                &token,
                &hs_id,
                raven_core::onion::ONION_VIRTUAL_PORT,
            ))
            .await
            .map_err(|_| ONION_NOT_READY.to_string())?;
        let mut head = [0u8; 2];
        stream
            .read_exact(&mut head)
            .await
            .map_err(|_| ONION_NOT_READY.to_string())?;
        let mut reason = vec![0u8; usize::from(head[1])];
        stream
            .read_exact(&mut reason)
            .await
            .map_err(|_| ONION_NOT_READY.to_string())?;
        match ConnectReply::decode(head[0], &reason) {
            ConnectReply::Ok => Ok(stream),
            ConnectReply::NotReady(_) => Err(ONION_NOT_READY.to_string()),
            ConnectReply::Unreachable(why)
            | ConnectReply::Timeout(why)
            | ConnectReply::Failed(why) => Err(format!("{ONION_UNREACHABLE} ({why})")),
        }
    };
    tokio::time::timeout(ONION_CONNECT_BUDGET, work)
        .await
        .map_err(|_| {
            format!(
                "{ONION_UNREACHABLE} (no circuit within {}s)",
                ONION_CONNECT_BUDGET.as_secs()
            )
        })?
}

#[cfg(test)]
mod tests;
