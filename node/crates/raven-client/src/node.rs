//! The background program, raven-node: `node.*`, the watcher behind
//! `events.poll`, and the start a send makes.
//!
//! Adapted from the terminal app's `tui/node.rs` (branch
//! feature/terminal-app): its Status read as the CLI reads it, a start that
//! runs the CLI's own (ext.rs, through the engine bridge) and remembers
//! whether this app started the node, and the stop rules (OD-16): never a
//! login service; on Unix the process this profile's Status names; on
//! Windows only a process this app started that Status still names.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Weak;
use std::time::{Duration, Instant};

use ash_engine::engine::{self as bridge, NodeReach, NotReceiving};
use raven_core::ipc::{ContactPath, IpcRequest, IpcResponse};
use serde_json::{json, Value};

use crate::engine::{build_kind, lock, now_ms, Inner};
use crate::envelope::{code, ApiError, Args, OpResult};
use crate::explain;
use crate::profile::KeyLoad;

/// How long one Status may take: a healthy node answers at once.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
/// The watcher's beat.
const TICK: Duration = Duration::from_secs(1);
/// The watcher stops when nobody polled for this long.
pub(crate) const WATCH_IDLE_STOP: Duration = Duration::from_secs(30);
const STOP_WAIT: Duration = Duration::from_secs(3);
const STOP_POLL: Duration = Duration::from_millis(100);
const STOP_PING: Duration = Duration::from_millis(500);
/// Overrides where the app finds raven-node (an addition of the engine; the
/// CLI has no such variable).
pub const NODE_PROGRAM_ENV: &str = "RAVEN_NODE_BIN";
/// The listen address of a node the app starts while receiving is off: this
/// computer only, any free port.
const LOOPBACK_LISTEN: &str = "127.0.0.1:0";
/// The login services Raven's installers set up.
const LAUNCH_AGENT: &str = "Library/LaunchAgents/com.raven.raven-node.plist";
const SYSTEMD_UNIT: &str = "systemd/user/raven-node.service";
const SCHEDULED_TASK: &str = "RavenNodeBridge";

/// Where raven-node stands, from its own Status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reach {
    /// Listening on the network.
    Listening,
    /// Listening on a loopback address: friends can't reach it.
    LocalOnly,
    /// Running, with its listener down (a busy port, an address no longer
    /// on this computer, `raven lan off`, or outbound only).
    SendOnly,
    NotRunning,
    /// Something owns the profile's endpoint but does not answer sensibly.
    NotAnswering,
}

impl Reach {
    fn word(self) -> &'static str {
        match self {
            Reach::Listening => "listening",
            Reach::LocalOnly => "local_only",
            Reach::SendOnly => "send_only",
            Reach::NotRunning => "not_running",
            Reach::NotAnswering => "not_answering",
        }
    }
}

/// One Status answer.
#[derive(Debug, Clone)]
pub(crate) struct Probe {
    pub reach: Reach,
    /// Why it does not receive ([`Reach::SendOnly`]), when the CLI can tell:
    /// `addr_not_here`, `port_in_use` or `lan_off`.
    pub not_receiving: Option<&'static str>,
    pub pid: Option<u32>,
    /// Where its listener is bound, while it receives.
    pub listen: Option<String>,
    pub last_paths: Vec<ContactPath>,
    /// The transports of the relays its p2p host uses (`tcp`, `quic`,
    /// `wss`, `wss-proxy`).
    pub relay_paths: Vec<String>,
}

impl Probe {
    /// A node holds the profile's endpoint (answering or not).
    pub(crate) fn running(&self) -> bool {
        self.reach != Reach::NotRunning
    }

    fn answered(&self) -> bool {
        !matches!(self.reach, Reach::NotRunning | Reach::NotAnswering)
    }
}

/// The CLI's reading of a Status answer (cli.rs `classify_node_reach`,
/// through the engine bridge), with a node that receives split by where it
/// listens: a listener bound to an address that has left this computer
/// receives nothing, however up it says it is (`raven status` says
/// `addr_not_here`, as the terminal app does).
pub(crate) fn probe_of(status: &Result<IpcResponse, String>) -> Probe {
    probe_of_here(status, raven_core::netifs::is_on_this_computer)
}

/// [`probe_of`] where `here` says whether an address is one of this
/// computer's own (None: can't be told).
pub(crate) fn probe_of_here(
    status: &Result<IpcResponse, String>,
    here: impl Fn(std::net::IpAddr) -> Option<bool>,
) -> Probe {
    let (reach, not_receiving) = match bridge::node_reach_here(status, here) {
        NodeReach::Receiving => (Reach::Listening, None),
        NodeReach::LocalOnly => (Reach::LocalOnly, None),
        NodeReach::SendOnly(why) => (
            Reach::SendOnly,
            why.map(|why| match why {
                NotReceiving::AddrNotHere => "addr_not_here",
                NotReceiving::PortInUse => "port_in_use",
                NotReceiving::LanOff => "lan_off",
            }),
        ),
        NodeReach::NotRunning => (Reach::NotRunning, None),
        NodeReach::NotAnswering => (Reach::NotAnswering, None),
    };
    let (pid, listen, last_paths, relay_paths) = match status {
        Ok(IpcResponse::Status {
            pid,
            lan_listen,
            last_paths,
            p2p,
            ..
        }) => (
            *pid,
            lan_listen
                .clone()
                .filter(|_| matches!(reach, Reach::Listening | Reach::LocalOnly)),
            last_paths.clone(),
            p2p.as_ref()
                .map_or_else(Vec::new, |i| i.relay_paths.clone()),
        ),
        _ => (None, None, Vec::new(), Vec::new()),
    };
    Probe {
        reach,
        not_receiving,
        pid,
        listen,
        last_paths,
        relay_paths,
    }
}

/// The profile's raven-node now: one Status, [`PROBE_TIMEOUT`] at most.
pub(crate) fn probe(data_dir: &Path) -> Probe {
    probe_of(&bridge::ipc_request_timeout(
        data_dir,
        &IpcRequest::status(),
        PROBE_TIMEOUT,
    ))
}

/// What the engine remembers about the node.
#[derive(Debug, Default)]
pub(crate) struct NodeMemory {
    /// The pid of a node this app started, while that one still runs.
    pub started_by_app: Option<u32>,
    /// The last successful Status (wall ms).
    pub last_ok_ms: u64,
    /// What the last `node` event said, to send the next only on a change.
    last_said: Option<String>,
}

/// The watcher thread, as `events.poll` keeps it alive.
#[derive(Debug, Default)]
pub(crate) struct WatcherState {
    pub running: bool,
    pub last_poll: Option<Instant>,
}

/// The raven-node program a start runs: `RAVEN_NODE_BIN` when set, else
/// next to this program, else the CLI's lookup (next to this program, or
/// `raven-node` on PATH when this program's path is unknown).
pub(crate) fn node_program() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os(NODE_PROGRAM_ENV).filter(|p| !p.is_empty()) {
        let p = PathBuf::from(p);
        return if p.is_file() {
            Ok(p)
        } else {
            Err(format!(
                "{NODE_PROGRAM_ENV} names {}, which is missing: build or install raven-node there",
                p.display()
            ))
        };
    }
    let name = if cfg!(windows) {
        "raven-node.exe"
    } else {
        "raven-node"
    };
    if let Some(next_to_us) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(name)))
        .filter(|p| p.is_file())
    {
        return Ok(next_to_us);
    }
    let cli = bridge::cli_node_program();
    if cli.components().count() > 1 && !cli.is_file() && !cli.with_extension("exe").is_file() {
        return Err(format!(
            "raven-node is missing next to this program ({}): build or install raven-node next \
             to the app",
            cli.display()
        ));
    }
    Ok(cli)
}

impl Inner {
    /// The listen address for a node this app starts for the profile in
    /// `dir`: on the network while receiving is on (`RAVEN_SERVICE_LAN_LISTEN`
    /// when set, as for the CLI, else the profile's own port, as the CLI
    /// starts it), else this computer only.
    fn listen_for_start(&self, dir: &Path) -> String {
        if self.settings().receive {
            bridge::service_lan_listen_env()
                .unwrap_or_else(|| bridge::default_service_lan_listen_for(dir))
        } else {
            LOOPBACK_LISTEN.to_owned()
        }
    }

    /// API.md's `NodeStatus` for `p`; `starting` while this app starts one.
    pub(crate) fn status_value(&self, p: &Probe, starting: bool) -> Value {
        let (started_by_app, last_ok_ms) = {
            let mem = lock(&self.node);
            (
                p.pid.is_some() && mem.started_by_app == p.pid,
                mem.last_ok_ms,
            )
        };
        let listening = p.listen.clone();
        let receive = match &listening {
            Some(listen) => !bridge::listen_is_loopback(listen),
            None => (p.answered() || starting) && self.settings().receive,
        };
        let gate = |production: bool| if production { "on" } else { "preview" };
        // Every way a developer build's lab switch turned on in this
        // process (network.rs; never in a release build).
        let lab = crate::network::lab_ways();
        let mut v = json!({
            "running": p.running(),
            "started_by_app": started_by_app,
            "receive": receive,
            "last_ok_ms": last_ok_ms,
            "build": build_kind(),
            "carriers": {
                "lan": gate(raven_core::LAN_DIRECT_PRODUCTION_ENABLED),
                "internet": gate(raven_core::INTERNET_DIRECT_PRODUCTION_ENABLED),
                "p2p": gate(raven_core::P2P_PRODUCTION_ENABLED),
                "custody": gate(raven_core::custody_gate::FRIEND_CUSTODY_PRODUCTION_ENABLED),
                "nearby": gate(raven_core::NEARBY_PRODUCTION_ENABLED),
            },
            // Extra fields: the node's state in one word ("starting" while
            // this app starts it), and the carriers a developer build's lab
            // switch turned on in this process (never in a release).
            "state": if starting { "starting" } else { p.reach.word() },
            "lab": lab,
            // The `RAVEN_LAB_*` variables this engine sees (names only),
            // which a raven-node it starts inherits (none in a release).
            "lab_switches": crate::network::lab_switches_seen(),
        });
        if let Some(pid) = p.pid {
            v["pid"] = pid.into();
        }
        if let Some(listen) = listening {
            v["listening"] = listen.into();
        }
        if let Some(why) = p.not_receiving {
            // An extra field: why a running node does not receive.
            v["not_receiving"] = why.into();
        }
        if let Some(ip) = raven_core::route_memory::egress_addrs().0 {
            v["address"] = ip.to_string().into();
        }
        v
    }

    /// Notes a Status: the heartbeat (`status_ok`) when it answered, a node
    /// this app started that is gone, and a `node` event when what the app
    /// shows changed.
    pub(crate) fn note_probe(&self, p: &Probe, starting: bool) -> Value {
        {
            let mut mem = lock(&self.node);
            if p.answered() {
                mem.last_ok_ms = now_ms();
            }
            if mem.started_by_app.is_some() && mem.started_by_app != p.pid && p.answered() {
                mem.started_by_app = None;
            }
            if !p.running() {
                mem.started_by_app = None;
            }
        }
        if p.answered() {
            self.emit("status_ok", json!({}));
        }
        let status = self.status_value(p, starting);
        let said = format!(
            "{}|{}|{:?}|{:?}|{}|{}",
            status["running"],
            status["state"],
            p.pid,
            p.listen,
            status["receive"],
            status["started_by_app"]
        );
        let changed = {
            let mut mem = lock(&self.node);
            let changed = mem.last_said.as_deref() != Some(said.as_str());
            mem.last_said = Some(said);
            changed
        };
        if changed {
            self.emit("node", json!({"status": status.clone()}));
        }
        status
    }

    pub(crate) fn node_status_op(&self) -> OpResult {
        let dir = self.data_dir()?;
        Ok(self.note_probe(&probe(dir), false))
    }

    /// Starts the profile's node unless one answers; the caller holds the
    /// node gate. Refused before the identity exists (`raven-node service`
    /// would make one itself). Err is the start's own text.
    fn ensure_node_locked(&self) -> Result<Probe, String> {
        self.identity().map_err(|e| e.detail)?;
        let dir = self.data_dir().map_err(|e| e.detail)?.to_path_buf();
        let before = probe(&dir);
        if before.running() {
            return Ok(before);
        }
        if vault_needs_passphrase_file(&dir) {
            return Err(format!(
                "raven-node {}: it runs without a terminal",
                explain::PASSPHRASE_MARK
            ));
        }
        let program = node_program()?;
        let listen = self.listen_for_start(&dir);
        self.note_probe(&before, true);
        let started = bridge::ensure_node(&dir, &program, &listen, &self.node_slot);
        let after = probe(&dir);
        if let Ok(Some(pid)) = started {
            if after.pid == Some(pid) {
                lock(&self.node).started_by_app = Some(pid);
            }
        }
        self.note_probe(&after, false);
        started.map(|_| after)
    }

    /// The start a send makes before it dials (under the node gate, so it
    /// never races `node.start`).
    pub(crate) fn ensure_node_for_send(&self) -> Result<(), String> {
        let started = {
            let _gate = lock(&self.node_gate);
            self.ensure_node_locked().map(|_| ())
        };
        self.after_node_start();
        started
    }

    /// A raven-node that just started seals a release build's profile at
    /// its own start: the at-rest key is loaded now if this process lacks
    /// it (outside the node gate; profile.rs).
    fn after_node_start(&self) {
        if let Ok(dir) = self.data_dir() {
            if bridge::at_rest_key_missing(dir) {
                let _ = self.open_as(KeyLoad::Now);
            }
        }
    }

    pub(crate) fn node_start(&self) -> OpResult {
        self.identity()?;
        let started = {
            let _gate = lock(&self.node_gate);
            self.ensure_node_locked()
        };
        self.after_node_start();
        match started {
            Ok(after) => Ok(self.status_value(&after, false)),
            Err(why) => {
                let plain = explain::explain_node_start(&why);
                // `raven lock` stopped it: the app's Locked screen unlocks.
                let code = if why.trim() == bridge::LOCKED_TEXT {
                    code::PROFILE_LOCKED
                } else {
                    code::NODE_NOT_RUNNING
                };
                Err(ApiError::new(
                    code,
                    format!("{} {}", plain.headline, plain.next)
                        .trim()
                        .to_owned(),
                    why,
                ))
            }
        }
    }

    /// Stops this profile's node as the stop rules allow. What happened is
    /// in the extra field `stop`: `stopped`, `still_running`, `advice` (with
    /// how to stop it by hand in `note`), `managed` (a login service runs
    /// it), `not_running` or `failed`.
    pub(crate) fn node_stop(&self) -> OpResult {
        let dir = self.data_dir()?.to_path_buf();
        let _gate = lock(&self.node_gate);
        let now = probe(&dir);
        let started_by_app = lock(&self.node).started_by_app;
        let managed = detect_managed().is_some();
        let plan = stop_plan(
            cfg!(windows),
            managed,
            now.running(),
            now.pid,
            started_by_app,
        );
        let (word, note) = match plan {
            StopPlan::Terminate(pid) => match terminate(pid) {
                Ok(()) => wait_stopped(&dir),
                Err(e) => ("failed", e.to_string()),
            },
            StopPlan::TaskKill(pid) => match task_kill(pid) {
                Ok(()) => wait_stopped(&dir),
                Err(e) => ("failed", e.to_string()),
            },
            StopPlan::Advise(pid) => ("advice", bridge::profile_stop_advice(&dir, pid)),
            StopPlan::Managed => (
                "managed",
                "Raven's background program runs as a login service, which would start it \
                 again; it was left running."
                    .to_owned(),
            ),
            StopPlan::NotRunning => ("not_running", String::new()),
        };
        let after = probe(&dir);
        let mut status = self.note_probe(&after, false);
        status["stop"] = word.into();
        if !note.is_empty() {
            status["note"] = note.into();
        }
        Ok(status)
    }

    /// `events.poll`: never blocks. Keeps the watcher running (it stops
    /// after half a minute without a poll).
    pub(crate) fn events_poll(&self, args: &Args) -> OpResult {
        let after = args.opt_u64("after_seq")?.unwrap_or(0);
        self.ensure_watcher();
        let batch = self.events.poll(after);
        Ok(json!({"seq": batch.seq, "events": batch.events, "reset": batch.reset}))
    }

    fn ensure_watcher(&self) {
        let mut w = lock(&self.watcher);
        w.last_poll = Some(Instant::now());
        if w.running {
            return;
        }
        let me = self.me.clone();
        if std::thread::Builder::new()
            .name("raven-client-watcher".into())
            .spawn(move || watch(me))
            .is_ok()
        {
            w.running = true;
        }
    }

    /// One beat of the watcher: the node's Status, then (once the identity
    /// is known) what changed in the profile.
    fn tick(&self) {
        let Ok(dir) = self.data_dir() else {
            return;
        };
        let p = probe(dir);
        self.note_probe(&p, false);
        // The profile as an operation opens it (profile.rs): nothing is read
        // while it is closed, and a key raven-node's start made necessary is
        // loaded.
        if self.cached_identity().is_some() && self.open().is_ok() {
            let _ = self.refresh(Duration::from_millis(900));
            self.refresh_groups();
        }
    }
}

/// The watcher: about once a second while someone polls.
fn watch(me: Weak<Inner>) {
    loop {
        {
            let Some(inner) = me.upgrade() else {
                return;
            };
            {
                let mut w = lock(&inner.watcher);
                if w.last_poll.is_none_or(|at| at.elapsed() > WATCH_IDLE_STOP) {
                    w.running = false;
                    return;
                }
            }
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.tick()));
        }
        std::thread::sleep(TICK);
    }
}

/// How a stop is carried out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopPlan {
    /// SIGTERM to the pid this profile's own Status reports (Unix).
    Terminate(u32),
    /// `taskkill /F` (Windows): only a pid this app started that Status
    /// still reports.
    TaskKill(u32),
    /// Say how instead.
    Advise(Option<u32>),
    /// A login service runs it.
    Managed,
    NotRunning,
}

/// The stop rules (the terminal app's node.rs `stop_plan`).
pub(crate) fn stop_plan(
    windows: bool,
    managed: bool,
    running: bool,
    status_pid: Option<u32>,
    started_by_app: Option<u32>,
) -> StopPlan {
    if managed {
        return StopPlan::Managed;
    }
    if !running {
        return StopPlan::NotRunning;
    }
    match (windows, status_pid) {
        (false, Some(pid)) => StopPlan::Terminate(pid),
        (true, Some(pid)) if started_by_app == Some(pid) => StopPlan::TaskKill(pid),
        (_, pid) => StopPlan::Advise(pid),
    }
}

/// Pings until the node stops answering, [`STOP_WAIT`] at most.
fn wait_stopped(dir: &Path) -> (&'static str, String) {
    let deadline = Instant::now() + STOP_WAIT;
    loop {
        if !bridge::ipc_daemon_up_within(dir, STOP_PING) {
            return ("stopped", String::new());
        }
        if Instant::now() >= deadline {
            return (
                "still_running",
                "It was asked to stop and is still answering; it may need a few more seconds."
                    .into(),
            );
        }
        std::thread::sleep(STOP_POLL);
    }
}

#[cfg(unix)]
fn terminate(pid: u32) -> std::io::Result<()> {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    const SIGTERM: i32 = 15;
    let pid = match i32::try_from(pid) {
        Ok(pid) if pid > 0 => pid,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{pid} is not the id of a single process"),
            ))
        }
    };
    // SAFETY: kill(2) takes plain integers and touches no memory; `pid` is
    // positive, so it names one process, never a group.
    if unsafe { kill(pid, SIGTERM) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn terminate(pid: u32) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!("no graceful stop for process {pid} here"),
    ))
}

/// A Windows tool by absolute path (`%SystemRoot%\System32\<tool>`), never
/// a PATH lookup.
fn system_tool(tool: &str) -> Option<PathBuf> {
    let root = PathBuf::from(std::env::var_os("SystemRoot")?);
    root.is_absolute().then(|| root.join("System32").join(tool))
}

fn task_kill(pid: u32) -> std::io::Result<()> {
    let taskkill = system_tool("taskkill.exe").ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "SystemRoot is not set")
    })?;
    let status = Command::new(taskkill)
        .args(["/F", "/PID", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "taskkill ended with {status}"
        )))
    }
}

/// A login service that runs raven-node: launchd, systemd or the task
/// scheduler would start it again after a stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Managed {
    LaunchAgent,
    SystemdUser,
    ScheduledTask,
}

/// Whether Raven's installer set raven-node up to start at login. Read-only.
pub(crate) fn detect_managed() -> Option<Managed> {
    if cfg!(windows) {
        let schtasks = system_tool("schtasks.exe")?;
        let found = Command::new(schtasks)
            .args(["/Query", "/TN", SCHEDULED_TASK])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        return found.then_some(Managed::ScheduledTask);
    }
    let absolute = |var: &str| {
        std::env::var_os(var)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    let home = absolute("HOME");
    let (file, kind) = if cfg!(target_os = "macos") {
        (home?.join(LAUNCH_AGENT), Managed::LaunchAgent)
    } else {
        let config = absolute("XDG_CONFIG_HOME").or_else(|| home.map(|h| h.join(".config")))?;
        (config.join(SYSTEMD_UNIT), Managed::SystemdUser)
    };
    file.is_file().then_some(kind)
}

/// A passphrase-vault profile (Unix without a system keychain) with no
/// passphrase file: raven-node, which has no terminal, can't unlock it.
/// What the profile's files record decides (`has_passphrase`: its keystore
/// marker or vault file), never the choice a new profile would get: a
/// profile whose keys are elsewhere (the debug build's lab `locked-file`
/// stores record no keystore) is never held back, and nothing is probed.
#[cfg(all(unix, not(target_os = "macos")))]
fn vault_needs_passphrase_file(dir: &Path) -> bool {
    use raven_core::keystore_vault::{PASSPHRASE_FILE_ENV, SYSTEMD_CREDENTIAL_NAME};
    if !matches!(raven_core::keystore_select::has_passphrase(dir), Ok(true)) {
        return false;
    }
    if std::env::var_os(PASSPHRASE_FILE_ENV).is_some_and(|f| !f.is_empty()) {
        return false;
    }
    match std::env::var_os("CREDENTIALS_DIRECTORY").filter(|d| !d.is_empty()) {
        Some(creds) => !Path::new(&creds).join(SYSTEMD_CREDENTIAL_NAME).exists(),
        None => true,
    }
}

#[cfg(not(all(unix, not(target_os = "macos"))))]
fn vault_needs_passphrase_file(_dir: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::ipc::IPC_VERSION;

    fn status(
        pid: Option<u32>,
        caps: &[&str],
        listen: Option<&str>,
    ) -> Result<IpcResponse, String> {
        Ok(IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: caps.iter().map(|c| (*c).to_owned()).collect(),
            p2p: None,
            pid,
            lan_listen: listen.map(str::to_owned),
            last_paths: Vec::new(),
            route_hints: None,
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: None,
            lan: None,
            security: None,
            nearby: None,
            learning: None,
            locked: None,
            updates: None,
            tor: None,
        })
    }

    fn read(status: &Result<IpcResponse, String>) -> Probe {
        probe_of_here(status, |_| None)
    }

    #[test]
    fn reach_follows_the_status_and_where_it_listens() {
        let p = read(&status(Some(42), &["lan_direct"], Some("0.0.0.0:7420")));
        assert_eq!((p.reach, p.pid), (Reach::Listening, Some(42)));
        assert_eq!(
            read(&status(None, &["lan_direct"], Some("127.0.0.1:5000"))).reach,
            Reach::LocalOnly
        );
        let send_only = read(&status(None, &["ipc"], Some("127.0.0.1:5000")));
        assert_eq!((send_only.reach, send_only.listen), (Reach::SendOnly, None));
        assert_eq!(send_only.not_receiving, None);
        assert_eq!(
            read(&Err("raven-node is not running; start it".into())).reach,
            Reach::NotRunning
        );
        assert_eq!(
            read(&Ok(IpcResponse::Pong { v: IPC_VERSION })).reach,
            Reach::NotAnswering
        );
    }

    /// cli.rs's `classify_node_reach` (CP.5, Phase 3): a listener bound to
    /// an address that has left this computer, a port another program has
    /// and `raven lan off` are not receiving, and say why; the first never
    /// offers its address (a card's `lan=` reads `listen`).
    #[test]
    fn a_listener_that_cannot_be_reached_is_not_receiving() {
        let bound = status(Some(7), &["lan_direct"], Some("192.0.2.10:7420"));
        let gone = probe_of_here(&bound, |_| Some(false));
        assert_eq!(
            (gone.reach, gone.not_receiving, gone.listen.as_deref()),
            (Reach::SendOnly, Some("addr_not_here"), None)
        );
        let here = probe_of_here(&bound, |_| Some(true));
        assert_eq!(
            (here.reach, here.listen.as_deref()),
            (Reach::Listening, Some("192.0.2.10:7420"))
        );
        // Every address bound, or one that can't be told: as before.
        let any = status(Some(7), &["lan_direct"], Some("0.0.0.0:7420"));
        assert_eq!(probe_of_here(&any, |_| Some(false)).reach, Reach::Listening);
        assert_eq!(probe_of_here(&bound, |_| None).reach, Reach::Listening);

        let mut busy = status(Some(7), &["ipc"], None);
        if let Ok(IpcResponse::Status {
            lan_listen_wanted,
            lan_bind_error,
            ..
        }) = &mut busy
        {
            *lan_listen_wanted = Some("0.0.0.0:7420".into());
            *lan_bind_error = Some(raven_core::ipc::LAN_BIND_IN_USE.into());
        }
        assert_eq!(read(&busy).not_receiving, Some("port_in_use"));

        let mut off = status(Some(7), &["ipc"], None);
        if let Ok(IpcResponse::Status { lan, .. }) = &mut off {
            *lan = Some(raven_core::ipc::LanStatus {
                mode: raven_core::ipc::LAN_MODE_OFF.into(),
                ..Default::default()
            });
        }
        let off = read(&off);
        assert_eq!(
            (off.reach, off.not_receiving),
            (Reach::SendOnly, Some("lan_off"))
        );
    }

    #[test]
    fn stop_rules_never_touch_a_login_service_or_a_stranger_on_windows() {
        assert_eq!(
            stop_plan(false, true, true, Some(5), Some(5)),
            StopPlan::Managed
        );
        assert_eq!(
            stop_plan(false, false, false, None, None),
            StopPlan::NotRunning
        );
        assert_eq!(
            stop_plan(false, false, true, Some(5), None),
            StopPlan::Terminate(5)
        );
        assert_eq!(
            stop_plan(true, false, true, Some(5), Some(5)),
            StopPlan::TaskKill(5)
        );
        assert_eq!(
            stop_plan(true, false, true, Some(5), Some(6)),
            StopPlan::Advise(Some(5))
        );
        assert_eq!(
            stop_plan(false, false, true, None, None),
            StopPlan::Advise(None)
        );
    }

    #[cfg(unix)]
    #[test]
    fn terminate_signals_one_process_only() {
        for pid in [0, u32::MAX, 1 << 31] {
            assert_eq!(
                terminate(pid).map_err(|e| e.kind()),
                Err(std::io::ErrorKind::InvalidInput),
                "{pid}"
            );
        }
    }
}
