//! The background program, raven-node, as the app sees it and runs it.
//!
//! - [`probe`]: its Status, read as `ash status` reads it (cli.rs's
//!   `classify_node_reach`: a loopback listener receives on this computer
//!   only), with the port it listens on and why its listener isn't bound
//!   (the Status's `lan_bind_error` and `lan_listen_wanted`).
//! - Starting it is `Controller::ensure_node` (controller.rs), which runs
//!   ext.rs's own start, as a send does, and tells a node this app started
//!   from one that ran already ([`started_by_app`]): the
//!   `started raven-node (process N)` line ext.rs prints, read from the stderr
//!   ring up to a sync sentinel.
//! - The vault check ([`vault_check`]: a vault profile, whether raven-node
//!   lacks its passphrase file, and whether PASSFILE's file is there), the
//!   login-service check (Raven's own login item for this profile, through
//!   bridge.rs: [`LoginItemKnown`], PP.23; [`login_service_for`] where this
//!   build reads no login items) and stopping it ([`stop`], OD-16; Lock now
//!   builds on it, UXF.7). The stop step itself is node_control.rs's
//!   (through bridge.rs), which `raven lock` runs too (privacy pack PP.15).
//! - For NET: its service log's last lines ([`service_log_tail`]), why a
//!   node that runs isn't receiving ([`BindFailure`], from the log as it is
//!   written: [`listener_in_log`]), and what this build lets on
//!   ([`GatesView`]: On, Preview or Lab, never a switch).
//!
//! No node is started before the profile has an identity (`raven-node
//! service` would create one itself), and none is stopped that the app may
//! not stop: a login service, or on Windows a process this app did not start.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::net::SocketAddr;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use raven_core::arrivals::ArrivedVia;
use raven_core::ipc::{IpcRequest, IpcResponse, OutboxItem, IPC_VERSION, MAX_OUTBOX_LIST};

use super::bridge::{
    self, AtRestStateView, ListenerDown, LoginItemView, NodeReach, SecurityCounts,
};
use super::display;
use super::errors::Plain;
#[cfg(test)]
use super::testkit;

// The stop step (node_control.rs, through bridge.rs; the CLI's `raven lock`
// runs it too).
pub(super) use super::bridge::{stop_plan, StopOutcome, StopPlan};

/// How long one Status (or Ping) may take: a healthy node answers at once.
pub(super) const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
/// What ext.rs prints when it has spawned raven-node (`started_notice`;
/// testkit checks ext.rs still says it).
pub(super) const STARTED_MARK: &str = "started raven-node (process ";
/// Most of the service log one read takes: its end, where a start writes.
const LOG_TAIL_BYTES: u64 = 64 * 1024;
/// The service log's lines NET's log view shows: its newest.
pub(super) const LOG_VIEW_LINES: usize = 40;
/// The login services Raven's installers set up (cli.rs's
/// `service_restart_hint` names the same ones).
const LAUNCH_AGENT: &str = "Library/LaunchAgents/com.raven.raven-node.plist";
const SYSTEMD_UNIT: &str = "systemd/user/raven-node.service";
/// The passphrase file PASSFILE's steps make, under the home folder.
#[cfg(any(test, all(unix, not(target_os = "macos"))))]
const PASSPHRASE_FILE: &str = ".config/raven/keystore-passphrase";

/// Where raven-node stands, from its own Status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reach {
    /// Listening on the network, on `port` (None: an older node that does
    /// not say where).
    Listening {
        port: Option<u16>,
    },
    /// Listening on a loopback address: friends can't reach it.
    LocalOnly,
    /// Running, with its listener down (a busy port, or outbound only).
    SendOnly,
    NotRunning,
    /// Something owns the profile's endpoint but does not answer sensibly.
    NotAnswering,
}

/// One Status answer, as the app keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Probe {
    pub(super) reach: Reach,
    pub(super) pid: Option<u32>,
    /// Where its listener is bound, as it says (`0.0.0.0:7420`).
    pub(super) listen: Option<String>,
    pub(super) capabilities: Vec<String>,
    /// p2p is set up for it, but its build keeps the carrier off (Status's
    /// `p2p.held`).
    pub(super) p2p_held: bool,
    /// The request was taken and never answered: a timeout, not a refusal.
    pub(super) timed_out: bool,
    /// Why its listener isn't bound, as its Status says.
    pub(super) bind: Option<BindFailure>,
    /// The profile's at-rest state, as its Status says it (privacy pack
    /// PP.4); None from a node of an older build, or with no answer.
    pub(super) at_rest: Option<AtRestStateView>,
    /// Its security counts (Status.security, Phase 6b P6.31): None while its
    /// security events gate is shut, from an older build, or with no answer.
    pub(super) security: Option<SecurityCounts>,
    /// Lock v2 (Status.locked, P6.40): whether it runs locked. None while
    /// its local-protection gate is shut, from an older build, or with no
    /// answer.
    pub(super) locked: Option<bool>,
    /// Bluetooth nearby (Status.nearby, Phase 5): whether it runs it, as
    /// `raven status` reads it. None: it reports no nearby engine (held in
    /// its build, older), or no answer.
    pub(super) nearby: Option<bool>,
    /// The Tor onion carrier's status line (Status.tor, lab): 'Tor: ready',
    /// 'Tor: starting (45 %)'. None while its gate is closed, from an older
    /// build, or with no answer.
    pub(super) tor: Option<String>,
}

impl Probe {
    /// `status` (an answer or its error) as the app reads it, its listen
    /// address checked against this computer's own addresses: a listener
    /// bound to one that has left this computer is not receiving.
    pub(super) fn read(status: &Result<IpcResponse, String>) -> Probe {
        Probe::of_here(status, bridge::is_on_this_computer)
    }

    /// `status` as the app reads it, where whether an address is this
    /// computer's can't be told (tests; [`Probe::read`] checks).
    #[cfg(test)]
    pub(super) fn of(status: &Result<IpcResponse, String>) -> Probe {
        Probe::of_here(status, |_| None)
    }

    /// `status` as the app reads it; `here` says whether an address is one
    /// of this computer's own (None: can't be told).
    pub(super) fn of_here(
        status: &Result<IpcResponse, String>,
        here: impl Fn(std::net::IpAddr) -> Option<bool>,
    ) -> Probe {
        let reach = bridge::classify_node_reach(status, here);
        let (pid, listen, capabilities, bind) = match status {
            Ok(IpcResponse::Status {
                pid,
                lan_listen,
                capabilities,
                lan_listen_wanted,
                lan_bind_error,
                ..
            }) => (
                *pid,
                lan_listen.clone(),
                capabilities.clone(),
                // Why its listener isn't bound, as the cutoff pack's Status
                // says it (CP.5). An older node says nothing, so its
                // service log tells ([`listener_in_log`]).
                lan_bind_error.as_deref().and_then(|kind| {
                    bind_failure(kind, lan_listen_wanted.as_deref().unwrap_or(""))
                }),
            ),
            _ => (None, None, Vec::new(), None),
        };
        // Bound, but to an address that has left this computer: the same
        // as a bind to it that failed (CP.5's words).
        let bind = match &reach {
            NodeReach::SendOnly {
                down: ListenerDown::AddrNotHere { wanted },
            } if bind.is_none() => Some(BindFailure::AddrNotHere {
                wanted: wanted.clone(),
            }),
            _ => bind,
        };
        Probe {
            reach: reach_of(status, &reach),
            pid,
            listen,
            capabilities,
            p2p_held: bridge::service_p2p(status).is_some_and(|p2p| p2p.held),
            timed_out: matches!(status, Err(e) if bridge::error_means_no_answer(e)),
            bind,
            at_rest: bridge::at_rest_state(status),
            security: bridge::security_counts(status),
            locked: match status {
                Ok(IpcResponse::Status { locked, .. }) => *locked,
                _ => None,
            },
            nearby: match status {
                Ok(IpcResponse::Status {
                    nearby: Some(info), ..
                }) => Some(info.enabled),
                _ => None,
            },
            tor: match status {
                Ok(IpcResponse::Status { tor, .. }) => tor.clone(),
                _ => None,
            },
        }
    }

    /// A Status that was asked and not answered in time (or is still out:
    /// Windows asks one at a time).
    pub(super) fn timed_out() -> Probe {
        Probe {
            reach: Reach::NotAnswering,
            pid: None,
            listen: None,
            capabilities: Vec::new(),
            p2p_held: false,
            timed_out: true,
            bind: None,
            at_rest: None,
            security: None,
            locked: None,
            nearby: None,
            tor: None,
        }
    }

    /// A node runs and answers.
    pub(super) fn running(&self) -> bool {
        matches!(
            self.reach,
            Reach::Listening { .. } | Reach::LocalOnly | Reach::SendOnly
        )
    }
}

/// cli.rs's reading of `status` (`reach`: a loopback listener receives on
/// this computer only), with the port a node listens on the network on.
fn reach_of(status: &Result<IpcResponse, String>, reach: &NodeReach) -> Reach {
    match reach {
        NodeReach::SendAndReceive => {
            let listen = match status {
                Ok(IpcResponse::Status { lan_listen, .. }) => lan_listen.as_deref(),
                _ => None,
            };
            Reach::Listening {
                port: listen.and_then(|l| l.parse::<SocketAddr>().ok().map(|a| a.port())),
            }
        }
        NodeReach::ReceiveLocalOnly { .. } => Reach::LocalOnly,
        NodeReach::SendOnly { .. } => Reach::SendOnly,
        NodeReach::NotRunning => Reach::NotRunning,
        NodeReach::NotAnswering => Reach::NotAnswering,
    }
}

/// The host of a listen address on this computer only, as the screens name
/// it: its IP (`127.0.0.1`, `::1`) or `localhost`, the forms cli.rs's
/// `classify_node_reach` counts; 127.0.0.1 when it can't be told.
/// Never the raw text, which the node wrote.
pub(super) fn local_host(listen: Option<&str>) -> String {
    let listen = listen.map_or("", str::trim);
    match listen.parse::<SocketAddr>() {
        Ok(at) => at.ip().to_string(),
        Err(_) if listen.starts_with(LOCALHOST) => LOCALHOST.to_owned(),
        Err(_) => "127.0.0.1".to_owned(),
    }
}

/// The name a listen address on this computer only may have (ext.rs).
const LOCALHOST: &str = "localhost";

/// The profile's raven-node now: one Status, [`PROBE_TIMEOUT`] at most.
pub(super) fn probe(data_dir: &Path) -> Probe {
    Probe::read(&bridge::ipc_request_timeout(
        data_dir,
        &status_request(),
        PROBE_TIMEOUT,
    ))
}

/// The app's periodic Status: it never asks raven-node to try its at-rest
/// key again (review B-sealed-stores-6: only `raven status` does, so the
/// retries keep their backoff while the app is open).
pub(super) fn status_request() -> IpcRequest {
    IpcRequest::status()
}

/// The outbox's messages, every friend's or one friend's (`peer`, hex):
/// never OutboxKick, which only a send, Retry or Cancel sends.
pub(super) fn outbox_request(peer: Option<String>) -> IpcRequest {
    IpcRequest::OutboxList {
        v: IPC_VERSION,
        peer_pub_hex: peer,
        limit: Some(MAX_OUTBOX_LIST),
    }
}

/// The items of an OutboxList answer; None for any other answer or error.
/// How messages came and went, as the running raven-node remembers since
/// it started (IPC `Arrivals`): by message id (hex, lower case). The chat
/// shows it beside each message (field test E3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Paths {
    /// Messages received.
    pub(super) received: HashMap<String, ArrivedVia>,
    /// Messages of yours a receipt confirmed.
    pub(super) delivered: HashMap<String, ArrivedVia>,
}

/// The poller's `Arrivals` request.
pub(super) fn arrivals_request() -> IpcRequest {
    IpcRequest::Arrivals { v: IPC_VERSION }
}

/// [`Paths`] from an `Arrivals` answer; None from an older raven-node or
/// none. A way this app doesn't know is left out.
pub(super) fn paths_of(answer: Result<IpcResponse, String>) -> Option<Paths> {
    let Ok(IpcResponse::Arrivals {
        rows, delivered, ..
    }) = answer
    else {
        return None;
    };
    let by_id = |rows: Vec<raven_core::ipc::ArrivalRow>| {
        rows.into_iter()
            .filter_map(|r| {
                Some((
                    r.message_id_hex.to_ascii_lowercase(),
                    ArrivedVia::parse(&r.via)?,
                ))
            })
            .collect()
    };
    Some(Paths {
        received: by_id(rows),
        delivered: by_id(delivered),
    })
}

pub(super) fn outbox_items(answer: Result<IpcResponse, String>) -> Option<Vec<OutboxItem>> {
    match answer {
        Ok(IpcResponse::OutboxListResult { items, .. }) => Some(items),
        _ => None,
    }
}

/// What the screens say about the background program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NodeState {
    /// Not asked yet.
    Unknown,
    /// A vault profile with no passphrase file: raven-node can't unlock it
    /// (PASSFILE), so the app never starts one.
    NeedsPassphraseFile,
    /// This app is starting it, since `since` (the chip's spinner).
    Starting {
        since: Instant,
    },
    Listening {
        port: Option<u16>,
    },
    ReceivingLocalOnly,
    SendOnly,
    NotRunning,
    NotAnswering,
    /// The last start failed, and none runs.
    StartFailed(Plain),
}

impl NodeState {
    fn of(reach: Reach) -> NodeState {
        match reach {
            Reach::Listening { port } => NodeState::Listening { port },
            Reach::LocalOnly => NodeState::ReceivingLocalOnly,
            Reach::SendOnly => NodeState::SendOnly,
            Reach::NotRunning => NodeState::NotRunning,
            Reach::NotAnswering => NodeState::NotAnswering,
        }
    }
}

/// The raven-node program a start runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Program {
    /// Next to this program (NET shows it).
    pub(super) binary: PathBuf,
    /// This program's own path is known. Without it ext.rs would look
    /// raven-node up on PATH, so the app starts none.
    pub(super) exe_known: bool,
}

impl Program {
    pub(super) fn of_this_process() -> Program {
        Program {
            binary: bridge::raven_node_bin_public(),
            exe_known: std::env::current_exe().is_ok(),
        }
    }
}

/// The background program as the app knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NodeView {
    pub(super) state: NodeState,
    /// Its process id, from its last Status.
    pub(super) pid: Option<u32>,
    pub(super) listen: Option<String>,
    /// The pid of a node this app started, while that one still runs.
    pub(super) started_by_app: Option<u32>,
    /// It runs as a login service, which would start it again.
    pub(super) managed: Option<Managed>,
    /// Raven's own login item for this profile, as bridge.rs read it
    /// (PP.23): LOCK unloads it for this login session.
    pub(super) login_item: LoginItemKnown,
    pub(super) program: Program,
    /// What its Status lists it doing now (`lan_direct`, `p2p`, …).
    pub(super) capabilities: Vec<String>,
    /// p2p is set up for it, but its build keeps the carrier off.
    pub(super) p2p_held: bool,
    /// Windows: three Status requests in a row went unanswered, so the
    /// poller asks no more until the user checks again.
    pub(super) polling_stopped: bool,
    /// Why its listener isn't bound, as its last Status said.
    bind: Option<BindFailure>,
    /// The same, as its service log said while the app read it; forgotten
    /// once a Status finds it bound, stopped or not answering.
    bind_logged: Option<BindFailure>,
    /// The profile's at-rest state, as its last Status said it (privacy
    /// pack PP.4): NET's chip and rows when Raven can't open the friends
    /// list, or the profile is not encrypted.
    pub(super) at_rest: Option<AtRestStateView>,
    /// Its security counts, as its last Status said them (P6.31): NET's
    /// Security rows.
    pub(super) security: Option<SecurityCounts>,
    /// Lock v2 (P6.40): it runs locked, as its last Status said (None: it
    /// does not say).
    pub(super) locked: Option<bool>,
    /// Bluetooth nearby, as its last Status said ([`Probe::nearby`]).
    pub(super) nearby: Option<bool>,
    /// The Tor onion carrier, as its last Status said ([`Probe::tor`]).
    pub(super) tor: Option<String>,
    /// Windows: whose folder process `.0` serves, once read
    /// ([`folder_of`]).
    pub(super) folder: Option<(u32, NodeFolder)>,
}

impl NodeView {
    pub(super) fn new(program: Program) -> NodeView {
        NodeView {
            state: NodeState::Unknown,
            pid: None,
            listen: None,
            started_by_app: None,
            managed: None,
            login_item: LoginItemKnown::Unknown,
            program,
            capabilities: Vec::new(),
            p2p_held: false,
            polling_stopped: false,
            bind: None,
            bind_logged: None,
            at_rest: None,
            security: None,
            locked: None,
            nearby: None,
            tor: None,
            folder: None,
        }
    }

    /// A node runs and answers.
    pub(super) fn running(&self) -> bool {
        matches!(
            self.state,
            NodeState::Listening { .. } | NodeState::ReceivingLocalOnly | NodeState::SendOnly
        )
    }

    /// Its listener receives from the network: what `raven status` calls
    /// receiving.
    pub(super) fn receiving(&self) -> bool {
        matches!(self.state, NodeState::Listening { .. })
    }

    /// Whose folder the running one serves, once read (Windows).
    pub(super) fn folder(&self) -> Option<&NodeFolder> {
        match (&self.folder, self.running_pid()) {
            (Some((pid, folder)), Some(running)) if *pid == running => Some(folder),
            _ => None,
        }
    }

    /// The pid of the running one this app may end on Windows: the one it
    /// started, or one whose command line names this folder.
    pub(super) fn ours(&self) -> Option<u32> {
        self.started_by_app.or_else(|| {
            (self.folder() == Some(&NodeFolder::This))
                .then_some(self.running_pid())
                .flatten()
        })
    }

    /// The process that keeps running when the app quits.
    pub(super) fn running_pid(&self) -> Option<u32> {
        self.pid.filter(|_| self.running())
    }

    /// The node's own word (a probe, or the poller's Status). While this app
    /// starts one the start decides the state; a problem the app found stays
    /// until a node actually runs.
    pub(super) fn apply(&mut self, probe: &Probe) {
        self.pid = probe.pid;
        self.listen = probe.listen.clone();
        self.capabilities = probe.capabilities.clone();
        self.p2p_held = probe.p2p_held;
        self.bind = probe.bind.clone();
        self.at_rest = probe.at_rest;
        self.security = probe.security;
        self.locked = probe.locked;
        self.nearby = probe.nearby;
        self.tor = probe.tor.clone();
        if probe.reach != Reach::SendOnly {
            self.bind_logged = None;
        }
        if !probe.timed_out {
            self.polling_stopped = false;
        }
        if self.started_by_app.is_some() && self.started_by_app != probe.pid {
            // Gone, or replaced by another one.
            self.started_by_app = None;
        }
        match self.state {
            NodeState::Starting { .. } => {}
            NodeState::NeedsPassphraseFile | NodeState::StartFailed(_) if !probe.running() => {}
            _ => self.state = NodeState::of(probe.reach),
        }
    }

    /// Why a node that runs isn't receiving, when it says a reason the app
    /// words: its Status, else its service log (an older node). None in any
    /// other state.
    pub(super) fn bind_failure(&self) -> Option<&BindFailure> {
        if self.state != NodeState::SendOnly {
            return None;
        }
        self.bind.as_ref().or(self.bind_logged.as_ref())
    }

    /// What the service log written since the poller began reading it
    /// (`log`) says of the listener, if anything.
    pub(super) fn read_log(&mut self, log: &str) {
        if let Some(said) = listener_in_log(log.lines()) {
            self.bind_logged = said;
        }
    }
}

/// What a start found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Ensured {
    /// ext.rs's error when no node could be started or reached.
    pub(super) result: Result<(), String>,
    /// Status right after.
    pub(super) after: Probe,
    pub(super) started_by_app: Option<u32>,
    /// What the start printed on stdout; its stderr is in the ring, `ring`.
    pub(super) captured: String,
    pub(super) ring: Range<u64>,
}

/// The pid in ext.rs's `started raven-node (process N)` line among `lines`
/// (stderr, as the ring keeps it), each shaped as the screen would show it
/// first, so no escape sequence or invisible character can fake or hide it.
pub(super) fn notice_pid<'a>(lines: impl IntoIterator<Item = &'a str>) -> Option<u32> {
    lines.into_iter().find_map(|line| {
        let line = display::one_line(line, u16::MAX, "");
        let rest = &line[line.find(STARTED_MARK)? + STARTED_MARK.len()..];
        let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        if !rest[digits..].starts_with(')') {
            return None;
        }
        rest[..digits].parse().ok()
    })
}

/// Whether this app started the node that runs after a start: only when none
/// ran before, and the one running is the one ext.rs said it spawned. When
/// the stderr reader never reached the sentinel (`synced` false), that line
/// may not be in the ring yet: then the pid the node reports.
pub(super) fn started_by_app(
    before: Reach,
    after_pid: Option<u32>,
    notice_pid: Option<u32>,
    synced: bool,
) -> Option<u32> {
    if before != Reach::NotRunning {
        return None;
    }
    if synced {
        notice_pid.filter(|pid| after_pid == Some(*pid))
    } else {
        after_pid
    }
}

/// The vault decision: raven-node can unlock a vault profile only from a
/// passphrase file (`RAVEN_KEYSTORE_PASSPHRASE_FILE`, set and not empty) or a
/// systemd credential (`$CREDENTIALS_DIRECTORY/raven-keystore-passphrase`).
/// A profile whose keystore can't be told (`uses_vault` failed) is not held
/// back here: the start's own error says so.
#[cfg(any(test, all(unix, not(target_os = "macos"))))]
pub(super) fn needs_passphrase_file(
    uses_vault: Result<bool, String>,
    passphrase_file: Option<&OsStr>,
    credentials_dir: Option<&OsStr>,
    exists: impl Fn(&Path) -> bool,
) -> bool {
    if !matches!(uses_vault, Ok(true)) {
        return false;
    }
    if passphrase_file.is_some_and(|file| !file.is_empty()) {
        return false;
    }
    match credentials_dir.filter(|dir| !dir.is_empty()) {
        Some(dir) => !exists(&Path::new(dir).join(bridge::SYSTEMD_CREDENTIAL_NAME)),
        None => true,
    }
}

/// What the vault check found for this profile and process.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Vault {
    /// The profile keeps its keys in the passphrase vault (`uses_vault`
    /// said so): Lock locks it (UXF.7). Any other keeps them in the
    /// system's keychain, which stays open while the user is logged in.
    pub(super) profile: bool,
    /// raven-node can't unlock it ([`needs_passphrase_file`]).
    pub(super) needs_passphrase_file: bool,
    /// The file PASSFILE says to save the passphrase in is there
    /// ([`passphrase_file`]).
    pub(super) passphrase_saved: bool,
    /// A vault profile's passphrase is saved in this file, which unlocks it
    /// for anyone who can read it (review D-lock-tui-2: LOCK says so, as
    /// `raven lock` does): `RAVEN_KEYSTORE_PASSPHRASE_FILE`'s, the systemd
    /// credential, the one Raven's own login item hands raven-node, or
    /// PASSFILE's default, the first that is there (bridge.rs's
    /// `saved_passphrase_file`).
    pub(super) passphrase_file: Option<PathBuf>,
}

/// The vault check for this profile and process. Only Unix other than macOS
/// has the vault; it may ask Secret Service (with a timeout), so it runs on
/// the node worker.
pub(super) fn vault_check(data_dir: &Path) -> Vault {
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let uses_vault = bridge::uses_vault(data_dir);
        let profile = matches!(uses_vault, Ok(true));
        Vault {
            profile,
            // Lock now v2 (P6.40): raven-node starts such a profile locked,
            // and LOCKED takes the passphrase.
            needs_passphrase_file: !bridge::lock_v2_live()
                && needs_passphrase_file(
                    uses_vault,
                    std::env::var_os(bridge::PASSPHRASE_FILE_ENV).as_deref(),
                    std::env::var_os("CREDENTIALS_DIRECTORY").as_deref(),
                    Path::exists,
                ),
            passphrase_saved: passphrase_file(std::env::var_os("HOME").as_deref())
                .is_some_and(|file| file.exists()),
            passphrase_file: profile
                .then(|| bridge::saved_passphrase_file(data_dir))
                .flatten(),
        }
    }
    #[cfg(not(all(unix, not(target_os = "macos"))))]
    {
        let _ = data_dir;
        Vault::default()
    }
}

/// Where PASSFILE says to save the passphrase (INSTALL_Linux.md):
/// `~/.config/raven/keystore-passphrase`. Only an absolute HOME counts.
#[cfg(any(test, all(unix, not(target_os = "macos"))))]
pub(super) fn passphrase_file(home: Option<&OsStr>) -> Option<PathBuf> {
    let home = Path::new(home?);
    home.is_absolute().then(|| home.join(PASSPHRASE_FILE))
}

/// A login service that runs raven-node: launchd, systemd or the scheduler
/// would start it again after a stop, so the app never stops it (and
/// `ash status` never tells to kill it: cli.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Managed {
    LaunchAgent,
    SystemdUser,
    ScheduledTask,
}

/// What the app knows of Raven's own login item for this profile (PP.23).
/// The node worker asks bridge.rs (node_control.rs's `own_login_item`: the
/// installer's item, and only when its `--data-dir` is this profile's), so
/// another profile's item is not this one's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LoginItemKnown {
    /// Not read yet: LOCK waits for the read (review D-lock-tui-6).
    Unknown,
    /// This build reads no login items (or the read failed): `managed` is
    /// [`login_service_for`]'s, and LOCK stops as UXF.7 did, with the lock
    /// recorded around the stop.
    NotAvailable,
    /// Read: Raven's own login item doesn't run this profile.
    None,
    /// Raven's own login item runs this profile: LOCK unloads it for this
    /// login session, and Raven starts again at the next login (unless a
    /// `raven lock` turned it off: [`LoginItemView::stays_off`]).
    Own(LoginItemView),
}

impl LoginItemKnown {
    /// bridge.rs's answer.
    pub(super) fn of(item: Option<LoginItemView>) -> LoginItemKnown {
        item.map_or(LoginItemKnown::None, LoginItemKnown::Own)
    }
}

/// The login service Raven's installer set up for the profile at
/// `data_dir`, if any, for a build that reads no login items through
/// bridge.rs (UXF.7's check; cli.rs's hints use it too). On macOS and Linux
/// the agent's or unit's file must run raven-node for that profile
/// ([`runs_profile`]; a file that is there but can't be read still counts).
/// Windows' task is not read: an installed one counts (the scheduler is
/// asked, by absolute path with no input or output). Read-only.
pub(crate) fn login_service_for(data_dir: &Path) -> Option<Managed> {
    if cfg!(windows) {
        return scheduled_task_installed().then_some(Managed::ScheduledTask);
    }
    let macos = cfg!(target_os = "macos");
    let file = login_service_file(macos, std::env::var_os("HOME").as_deref())?;
    let managed = if macos {
        Managed::LaunchAgent
    } else {
        Managed::SystemdUser
    };
    if !file.is_file() {
        return None;
    }
    let Ok(text) = std::fs::read_to_string(file) else {
        return Some(managed);
    };
    let mut dirs = vec![data_dir.to_string_lossy().into_owned()];
    if let Ok(real) = std::fs::canonicalize(data_dir) {
        dirs.push(real.to_string_lossy().into_owned());
    }
    runs_profile(&text, &dirs).then_some(managed)
}

/// Whether a login service's file (`text`: the launch agent's plist or the
/// systemd unit Raven's installers write) runs raven-node with `--data-dir`
/// at one of `dirs`, written as each installer writes it: a plist string
/// (XML-escaped) or a quoted systemd word.
pub(super) fn runs_profile(text: &str, dirs: &[String]) -> bool {
    dirs.iter().any(|dir| {
        let xml = dir
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        let unit = dir
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$");
        text.contains(&format!("<string>{xml}</string>"))
            || text.contains(&format!("--data-dir \"{unit}\""))
    })
}

/// Where the installer puts the login service on macOS (a launch agent) or
/// another Unix (a systemd user unit, always under `~/.config`: the
/// installer ignores `XDG_CONFIG_HOME`, PP.23). Only an absolute home
/// counts: a relative HOME is no home.
pub(super) fn login_service_file(macos: bool, home: Option<&OsStr>) -> Option<PathBuf> {
    let home = home.map(Path::new).filter(|home| home.is_absolute())?;
    Some(if macos {
        home.join(LAUNCH_AGENT)
    } else {
        home.join(".config").join(SYSTEMD_UNIT)
    })
}

fn scheduled_task_installed() -> bool {
    let Some(schtasks) =
        bridge::system_tool(std::env::var_os("SystemRoot").as_deref(), "schtasks.exe")
    else {
        return false;
    };
    Command::new(schtasks)
        .args(["/Query", "/TN", bridge::SCHEDULED_TASK])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// A stop and the Status after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Stopped {
    pub(super) outcome: StopOutcome,
    pub(super) after: Probe,
}

impl Stopped {
    /// The stop went, and this profile's Status says nothing runs any more:
    /// LOCK's end (UXF.7), and what keeps the app's lock (PP.23).
    pub(super) fn gone(&self) -> bool {
        matches!(self.outcome, StopOutcome::Stopped | StopOutcome::NotRunning)
            && self.after.reach == Reach::NotRunning
    }
}

/// Whose Raven folder a running background program serves. On Windows the
/// IPC pipe is per user, so another folder's raven-node answers this
/// folder's Status too: its command line's `--data-dir` tells (E1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NodeFolder {
    This,
    /// Another folder's, as its command line names it.
    Other(String),
    /// Its command line couldn't be read.
    Unknown,
}

/// Whose folder process `pid` serves (Windows: [`process_command_line`]).
pub(super) fn folder_of(pid: u32, data_dir: &Path) -> NodeFolder {
    match process_command_line(pid)
        .as_deref()
        .map(data_dir_in_command_line)
    {
        Some(Some(dir)) if same_folder(Path::new(&dir), data_dir) => NodeFolder::This,
        Some(Some(dir)) => NodeFolder::Other(dir),
        _ => NodeFolder::Unknown,
    }
}

/// The `--data-dir` a raven-node command line names, quoted or not.
pub(super) fn data_dir_in_command_line(line: &str) -> Option<String> {
    let (_, rest) = line.split_once(" --data-dir")?;
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
    let dir = match rest.strip_prefix('"') {
        Some(quoted) => quoted.split_once('"')?.0,
        None => rest.split_whitespace().next()?,
    };
    Some(dir.to_owned()).filter(|dir| !dir.is_empty())
}

/// `a` and `b` name the same folder: canonical where they exist, with
/// Windows' spelling rules (either slash, any case, no `\\?\` prefix, no
/// separator at the end).
pub(super) fn same_folder(a: &Path, b: &Path) -> bool {
    let spelled = |path: &Path| {
        let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let text = path.to_string_lossy().replace('/', "\\");
        let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
        text.trim_end_matches('\\').to_lowercase()
    };
    spelled(a) == spelled(b)
}

/// The command line of process `pid`, as Windows' process list has it
/// (PowerShell by its absolute path, 10 s at most). None elsewhere.
fn process_command_line(pid: u32) -> Option<String> {
    if !cfg!(windows) {
        return None;
    }
    let shell = bridge::system_tool(
        std::env::var_os("SystemRoot").as_deref(),
        r"WindowsPowerShell\v1.0\powershell.exe",
    )?;
    let query = format!("(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine");
    let mut child = Command::new(shell)
        .args(["-NoProfile", "-NonInteractive", "-Command", &query])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut line = String::new();
    child.stdout.take()?.read_to_string(&mut line).ok()?;
    Some(line.trim().to_owned()).filter(|line| !line.is_empty())
}

/// Stops this profile's node as the stop rules allow (node_control.rs's
/// `stop_plan`: never a login service; on Unix the pid Status reports; on
/// Windows only a pid this app started, still reported), with a Status
/// taken just before, then waits a few seconds for it to stop answering.
pub(super) fn stop(data_dir: &Path, started_by_app: Option<u32>, managed: bool) -> Stopped {
    let now = probe(data_dir);
    let plan = bridge::stop_plan(
        cfg!(windows),
        managed,
        now.reach != Reach::NotRunning,
        now.pid,
        started_by_app,
    );
    Stopped {
        outcome: bridge::carry_out_stop(data_dir, plan),
        after: probe(data_dir),
    }
}

/// UPDATES' install (Phase 6 P6.47): this profile's node is stopped around
/// the swap of Raven's programs as the stop rules allow (this app's own
/// node on Windows too), started again from the new programs and checked
/// (`Ping` within 20 s), else the old programs go back and start again;
/// then a Status, so the app shows the node as it is now; and the node it
/// started from this app (review lock-updates-local-7).
pub(super) fn install_update(
    data_dir: &Path,
    serial: u64,
    started_by_app: Option<u32>,
) -> (Result<Vec<String>, String>, Probe, Option<u32>) {
    let (result, started) = bridge::install_update(data_dir, serial, started_by_app);
    (result, probe(data_dir), started)
}

/// The service log from byte `from` to its end (the last 64 KiB at most),
/// and where it ends now. A log shorter than `from` was started afresh: then
/// from its start.
pub(super) fn service_log_from(data_dir: &Path, from: u64) -> io::Result<(String, u64)> {
    let mut file = File::open(bridge::service_log_path(data_dir))?;
    let len = file.metadata()?.len();
    let from = if from > len { 0 } else { from };
    let start = from.max(len.saturating_sub(LOG_TAIL_BYTES));
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(len - start).read_to_end(&mut bytes)?;
    Ok((String::from_utf8_lossy(&bytes).into_owned(), len))
}

/// The service log's length now; 0 when there is none.
pub(super) fn service_log_len(data_dir: &Path) -> u64 {
    std::fs::metadata(bridge::service_log_path(data_dir)).map_or(0, |m| m.len())
}

/// The service log's last `count` lines (of its last 64 KiB), oldest first,
/// raw: NET's log view shapes each one. None yet is no lines.
pub(super) fn service_log_tail(data_dir: &Path, count: usize) -> io::Result<Vec<String>> {
    let (text, len) = match service_log_from(data_dir, 0) {
        Ok(read) => read,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(last_lines(&text, len > LOG_TAIL_BYTES, count))
}

/// The last `count` lines of `text`. `cut`: it begins inside a line (the log
/// is longer than one read), so its first line is a part and is dropped.
fn last_lines(text: &str, cut: bool, count: usize) -> Vec<String> {
    let lines: Vec<&str> = text.lines().skip(usize::from(cut)).collect();
    lines[lines.len().saturating_sub(count)..]
        .iter()
        .map(|line| (*line).to_owned())
        .collect()
}

// ── Why it isn't receiving ──────────────────────────────────────────────────

/// Why a node that runs has no listener, in the cases the app words (NET's
/// row; the header chip for the first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum BindFailure {
    /// The address it is set to listen on, `wanted` (raw: drawn through
    /// display.rs), isn't on this computer now. It listens by itself once
    /// the address is back.
    AddrNotHere { wanted: String },
    /// Another program on this computer uses its port.
    InUse { port: u16 },
}

/// The cutoff pack's names for why a bind failed (its Status's
/// `lan_bind_error`, CP.5), of those the app words.
const ADDR_NOT_HERE: &str = raven_core::ipc::LAN_BIND_ADDR_NOT_HERE;
const IN_USE: &str = raven_core::ipc::LAN_BIND_IN_USE;

/// How each OS says a bind's address isn't on this computer
/// (EADDRNOTAVAIL: macOS 49, Linux 99, Windows 10049), and that its port is
/// taken (EADDRINUSE: 48, 98, 10048).
const ADDR_NOT_HERE_WORDS: [&str; 5] = [
    "can't assign requested address",
    "cannot assign requested address",
    "os error 49",
    "os error 99",
    "os error 10049",
];
const IN_USE_WORDS: [&str; 4] = [
    "address already in use",
    "os error 48",
    "os error 98",
    "os error 10048",
];

/// What raven-node logs once its LAN listener is bound (lan_direct.rs;
/// testkit checks it still does).
pub(super) const LISTENING_MARK: &str = "raven-node lan_direct: listen ";
/// What it logs at each bind that failed: `retry_until_ok`'s
/// `<name> failed: ` before lan_direct.rs's `lan_direct bind <wanted>: <error>`.
pub(super) const BIND_FAILED_MARK: &str = "lan_direct failed: lan_direct bind ";
/// The line ext.rs writes before each run it starts.
pub(super) const RUN_MARK: &str = "--- ash: starting raven-node service ---";

/// A bind failure of the kind `kind` (CP.5's word) for the address
/// `wanted`: None for a kind the app doesn't word, or a port it can't read.
fn bind_failure(kind: &str, wanted: &str) -> Option<BindFailure> {
    let wanted = wanted.trim();
    match kind {
        ADDR_NOT_HERE if !wanted.is_empty() => Some(BindFailure::AddrNotHere {
            wanted: wanted.to_owned(),
        }),
        IN_USE => wanted
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse().ok())
            .map(|port| BindFailure::InUse { port }),
        _ => None,
    }
}

/// A bind error in the OS's words, as the kind CP.5 names it; None for one
/// the app doesn't word.
fn bind_error_kind(error: &str) -> Option<&'static str> {
    let l = error.to_ascii_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| l.contains(w));
    if has(&ADDR_NOT_HERE_WORDS) {
        Some(ADDR_NOT_HERE)
    } else if has(&IN_USE_WORDS) {
        Some(IN_USE)
    } else {
        None
    }
}

/// What the service log's `lines` (oldest first) say the LAN listener did
/// last, from the newest line about it: `Some(Some(..))` its bind failed
/// for a reason the app words; `Some(None)` it is bound, failed for another
/// reason, or a new run began; None when no line says. Lines of other
/// transports never count.
pub(super) fn listener_in_log<'a>(
    lines: impl DoubleEndedIterator<Item = &'a str>,
) -> Option<Option<BindFailure>> {
    lines.rev().find_map(|line| {
        if line.contains(LISTENING_MARK) || line.contains(RUN_MARK) {
            return Some(None);
        }
        let at = line.find(BIND_FAILED_MARK)? + BIND_FAILED_MARK.len();
        Some(line[at..].split_once(": ").and_then(|(wanted, error)| {
            bind_error_kind(error).and_then(|kind| bind_failure(kind, wanted))
        }))
    })
}

// ── What this build lets on ─────────────────────────────────────────────────

/// How far one way of reaching friends is on in this build (NET's labels).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GateState {
    /// Its production gate is on: 'On', or what the way does.
    On,
    /// Off in this release and in this process: 'Not in this version'.
    Preview,
    /// Off in this release, but on in this process: a developer build with
    /// the lab switch ('Lab only').
    Lab,
}

impl GateState {
    /// From a gate's `*_PRODUCTION_ENABLED` constant and its live function.
    pub(super) fn of(gate: bridge::Gate) -> GateState {
        match (gate.production, gate.live) {
            (true, _) => GateState::On,
            (false, false) => GateState::Preview,
            (false, true) => GateState::Lab,
        }
    }
}

/// The ways of reaching friends as this process's gates have them, read once
/// before the app's threads start. NET only says what they are: nothing in
/// the app turns a gate on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct GatesView {
    pub(super) lan: GateState,
    pub(super) internet: GateState,
    pub(super) p2p: GateState,
    /// Friends holding mail for you (friend custody).
    pub(super) custody: GateState,
    /// Bluetooth nearby: the same gate `raven status` goes by.
    pub(super) nearby: GateState,
    /// A developer build (debug assertions on), where lab switches work.
    pub(super) developer: bool,
}

impl GatesView {
    /// This build's gates, read now (constants, and the lab switch from the
    /// environment).
    pub(super) fn of_this_build() -> GatesView {
        GatesView::of(bridge::gates_now(), cfg!(debug_assertions))
    }

    /// `gates` as NET labels them, in a `developer` build or a release.
    pub(super) fn of(gates: bridge::Gates, developer: bool) -> GatesView {
        GatesView {
            lan: GateState::of(gates.lan),
            internet: GateState::of(gates.internet),
            p2p: GateState::of(gates.p2p),
            custody: GateState::of(gates.custody),
            nearby: GateState::of(gates.nearby),
            developer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// E1: the folder a Windows raven-node serves, from its command line.
    #[test]
    fn the_folder_of_a_command_line() {
        let dir = |line: &str| data_dir_in_command_line(line);
        assert_eq!(
            dir(
                r#""C:\Raven\raven-node.exe" service --data-dir "C:\Homes\sam\raven 3m" --lan-listen 0.0.0.0:17420"#
            ),
            Some(r"C:\Homes\sam\raven 3m".into())
        );
        assert_eq!(
            dir(
                r"C:\Raven\raven-node.exe service --data-dir C:\Homes\sam\.raven --ble-listen 127.0.0.1:0"
            ),
            Some(r"C:\Homes\sam\.raven".into())
        );
        assert_eq!(
            dir("raven-node service --data-dir=/p/q"),
            Some("/p/q".into())
        );
        assert_eq!(dir("raven-node service --lan-listen 0.0.0.0:7420"), None);
        assert_eq!(dir("raven-node service --data-dir "), None);
        // Windows spells one folder many ways.
        for (a, b, same) in [
            (r"C:\Homes\Sam\.raven", r"c:\homes\sam\.raven\", true),
            (r"\\?\C:\Homes\sam\.raven", "C:/Homes/sam/.raven", true),
            (r"C:\Homes\sam\.raven", r"C:\Homes\sam\.raven2", false),
        ] {
            assert_eq!(same_folder(Path::new(a), Path::new(b)), same, "{a} {b}");
        }
        // Not on Windows: nothing to read, so nobody's folder is known.
        if !cfg!(windows) {
            assert_eq!(folder_of(1, Path::new("/p")), NodeFolder::Unknown);
        }
    }

    use std::ffi::OsString;

    fn ok(answer: IpcResponse) -> Result<IpcResponse, String> {
        Ok(answer)
    }

    fn status(pid: Option<u32>, capabilities: &[&str], lan_listen: Option<&str>) -> IpcResponse {
        IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: capabilities.iter().map(|c| (*c).to_owned()).collect(),
            p2p: None,
            pid,
            lan_listen: lan_listen.map(str::to_owned),
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
            tor: None,
            learning: None,
            locked: None,
            updates: None,
        }
    }

    #[test]
    fn reach_follows_the_status_and_where_it_listens() {
        let cases = [
            (
                ok(status(Some(4242), &["lan_direct"], Some("0.0.0.0:7420"))),
                Reach::Listening { port: Some(7420) },
            ),
            (
                ok(status(None, &["lan_direct"], Some("192.168.1.20:7424"))),
                Reach::Listening { port: Some(7424) },
            ),
            (
                ok(status(None, &["lan_direct"], Some("127.0.0.1:7420"))),
                Reach::LocalOnly,
            ),
            (
                ok(status(None, &["lan_direct"], Some("[::1]:55001"))),
                Reach::LocalOnly,
            ),
            // An older node says nothing about where.
            (
                ok(status(None, &["lan_direct"], None)),
                Reach::Listening { port: None },
            ),
            (ok(status(None, &["ipc"], None)), Reach::SendOnly),
            (
                ok(status(None, &["ipc"], Some("127.0.0.1:7420"))),
                Reach::SendOnly,
            ),
            (
                ok(IpcResponse::Pong { v: IPC_VERSION }),
                Reach::NotAnswering,
            ),
        ];
        for (answer, want) in cases {
            let probe = Probe::of(&answer);
            assert_eq!(probe.reach, want, "{answer:?}");
            assert!(!probe.timed_out);
        }
        let probe = Probe::of(&ok(status(
            Some(4242),
            &["lan_direct"],
            Some("0.0.0.0:7420"),
        )));
        assert_eq!(
            (probe.pid, probe.listen.as_deref()),
            (Some(4242), Some("0.0.0.0:7420"))
        );
        assert!(probe.running());
    }

    /// A node whose listener is down, with the cutoff pack's word for why
    /// (CP.5): `kind` for the address `wanted`.
    fn told(pid: Option<u32>, wanted: &str, kind: &str) -> IpcResponse {
        let mut answer = status(pid, &["ipc"], None);
        if let IpcResponse::Status {
            lan_listen_wanted,
            lan_bind_error,
            ..
        } = &mut answer
        {
            *lan_listen_wanted = Some(wanted.to_owned());
            *lan_bind_error = Some(kind.to_owned());
        }
        answer
    }

    #[test]
    fn the_status_says_why_its_listener_is_down() {
        let cases = [
            (
                told(None, "192.0.2.10:7499", "addr_not_here"),
                Some(BindFailure::AddrNotHere {
                    wanted: "192.0.2.10:7499".into(),
                }),
            ),
            (
                told(None, "0.0.0.0:7420", "in_use"),
                Some(BindFailure::InUse { port: 7420 }),
            ),
            // Words the app has none for, or an address it can't read.
            (told(None, "0.0.0.0:7420", "denied"), None),
            (told(None, "0.0.0.0:7420", "other"), None),
            (told(None, "", "addr_not_here"), None),
            (told(None, "0.0.0.0", "in_use"), None),
            // An older node says nothing: its service log tells.
            (status(None, &["ipc"], None), None),
        ];
        for (answer, want) in cases {
            let probe = Probe::of(&ok(answer.clone()));
            assert_eq!(probe.reach, Reach::SendOnly, "{answer:?}");
            assert_eq!(probe.bind, want, "{answer:?}");
        }
        // Not a node that runs with its listener down: nothing to say.
        assert_eq!(
            Probe::of(&Err("raven-node is not running; x".into())).bind,
            None
        );
    }

    /// A listener still bound to an address that has left this computer
    /// (a new network): not receiving, for the reason a failed bind to it
    /// gives (D-interfaces-texts-2). MEET then offers no address.
    #[test]
    fn a_listener_whose_address_left_is_not_receiving() {
        let bound = ok(status(
            Some(42),
            &["ipc", "lan_direct"],
            Some("192.0.2.10:7499"),
        ));
        let gone = Probe::of_here(&bound, |_| Some(false));
        assert_eq!(gone.reach, Reach::SendOnly);
        assert_eq!(
            gone.bind,
            Some(BindFailure::AddrNotHere {
                wanted: "192.0.2.10:7499".into()
            })
        );
        assert!(gone.running());
        let mut view = NodeView::new(Program {
            binary: PathBuf::from("/opt/raven/raven-node"),
            exe_known: true,
        });
        view.apply(&gone);
        assert_eq!(view.state, NodeState::SendOnly);
        assert_eq!(
            view.bind_failure(),
            Some(&BindFailure::AddrNotHere {
                wanted: "192.0.2.10:7499".into()
            })
        );
        // Here, or can't be told: listening, as before.
        for here in [Some(true), None] {
            let probe = Probe::of_here(&bound, |_| here);
            assert_eq!(probe.reach, Reach::Listening { port: Some(7499) });
            assert_eq!(probe.bind, None);
        }
        // Every address is never asked about.
        let any = ok(status(
            Some(42),
            &["ipc", "lan_direct"],
            Some("0.0.0.0:7420"),
        ));
        let probe = Probe::of_here(&any, |ip| panic!("asked about {ip}"));
        assert_eq!(probe.reach, Reach::Listening { port: Some(7420) });
        // The probe the app runs reads this computer's addresses: TEST-NET-1
        // is on none of them.
        assert_eq!(Probe::read(&bound).reach, Reach::SendOnly);
    }

    #[test]
    fn a_listener_on_this_computer_only_is_named_by_its_host() {
        for (listen, want) in [
            (Some("127.0.0.1:55001"), "127.0.0.1"),
            (Some(" 127.0.0.2:7420 "), "127.0.0.2"),
            (Some("[::1]:55001"), "::1"),
            (Some("localhost:7420"), "localhost"),
            (None, "127.0.0.1"),
            // Never the node's own text.
            (Some("\u{1b}[2Jlocalhost:7420"), "127.0.0.1"),
        ] {
            assert_eq!(local_host(listen), want, "{listen:?}");
        }
        // Those forms are the ones that count as this computer only.
        for listen in ["[::1]:55001", "localhost:7420"] {
            let probe = Probe::of(&ok(status(None, &["lan_direct"], Some(listen))));
            assert_eq!(probe.reach, Reach::LocalOnly, "{listen}");
        }
    }

    /// A bind that failed, as raven-node logs it, with the OS's `error`.
    fn bind_failed(wanted: &str, error: &str) -> String {
        format!("lan_direct failed: lan_direct bind {wanted}: {error}")
    }

    const RETRYING: &str =
        "lan_direct: unavailable; IPC and the other transports keep running; retrying in 30s";

    #[test]
    fn the_service_log_says_why_the_listener_is_down() {
        let not_here = |wanted: &str| {
            Some(Some(BindFailure::AddrNotHere {
                wanted: wanted.into(),
            }))
        };
        let in_use = |port| Some(Some(BindFailure::InUse { port }));
        let gone = "192.0.2.10:7499";
        let mac = "Can't assign requested address (os error 49)";
        let cases: Vec<(Vec<String>, Option<Option<BindFailure>>)> = vec![
            // An address that isn't here, as macOS, Linux and Windows say it.
            (
                vec![bind_failed(gone, mac), RETRYING.into()],
                not_here(gone),
            ),
            (
                vec![bind_failed(
                    gone,
                    "Cannot assign requested address (os error 99)",
                )],
                not_here(gone),
            ),
            (
                vec![bind_failed(
                    gone,
                    "The requested address is not valid in its context. (os error 10049)",
                )],
                not_here(gone),
            ),
            (
                vec![bind_failed("[fe80::1%en0]:7420", mac)],
                not_here("[fe80::1%en0]:7420"),
            ),
            // A port another program has.
            (
                vec![bind_failed(
                    "0.0.0.0:7420",
                    "Address already in use (os error 48)",
                )],
                in_use(7420),
            ),
            (
                vec![bind_failed(
                    "0.0.0.0:7420",
                    "Address already in use (os error 98)",
                )],
                in_use(7420),
            ),
            (
                vec![bind_failed(
                    "[::]:7424",
                    "Only one usage of each socket address (protocol/network address/port) \
                     is normally permitted. (os error 10048)",
                )],
                in_use(7424),
            ),
            // A reason the app doesn't word, a port it can't read, a line
            // cut short: the listener is down, why isn't said.
            (
                vec![bind_failed("0.0.0.0:80", "Permission denied (os error 13)")],
                Some(None),
            ),
            (
                vec![bind_failed(
                    "localhost:http",
                    "Address already in use (os error 48)",
                )],
                Some(None),
            ),
            (
                vec![format!("lan_direct failed: lan_direct bind {gone}")],
                Some(None),
            ),
            // The newest line says: bound since, failed since, or a new run.
            (
                vec![
                    bind_failed(gone, mac),
                    format!("raven-node lan_direct: listen {gone}"),
                ],
                Some(None),
            ),
            (
                vec![
                    format!("raven-node lan_direct: listen {gone}"),
                    bind_failed(gone, mac),
                ],
                not_here(gone),
            ),
            (
                vec![
                    bind_failed(gone, mac),
                    "--- ash: starting raven-node service ---".into(),
                ],
                Some(None),
            ),
            // Other lines say nothing: another transport's bind, the
            // listener's preflight, or no line at all.
            (
                vec![
                    format!("internet_direct failed: internet_direct bind {gone}: {mac}"),
                    "lan_direct failed: local state preflight: disk is full".into(),
                    RETRYING.into(),
                ],
                None,
            ),
            (Vec::new(), None),
        ];
        for (lines, want) in cases {
            assert_eq!(
                listener_in_log(lines.iter().map(String::as_str)),
                want,
                "{lines:?}"
            );
        }
    }

    #[test]
    fn a_node_view_says_why_it_isnt_receiving_until_it_is() {
        let mut view = NodeView::new(Program {
            binary: PathBuf::from("/opt/raven/raven-node"),
            exe_known: true,
        });
        let send_only = Probe::of(&ok(status(Some(42), &["ipc"], None)));
        let listening = Probe::of(&ok(status(Some(42), &["lan_direct"], Some("0.0.0.0:7420"))));
        let gone = BindFailure::AddrNotHere {
            wanted: "192.0.2.10:7499".into(),
        };
        let failed = format!(
            "{}\r\n{RETRYING}\r\n",
            bind_failed(
                "192.0.2.10:7499",
                "Can't assign requested address (os error 49)"
            )
        );
        view.apply(&send_only);
        assert_eq!(view.state, NodeState::SendOnly);
        assert_eq!(view.bind_failure(), None, "no word yet");
        view.read_log("raven-node: something else\n");
        assert_eq!(view.bind_failure(), None);
        view.read_log(&failed);
        assert_eq!(view.bind_failure(), Some(&gone));
        // A poll of the Status keeps it while it still isn't receiving.
        view.apply(&send_only);
        assert_eq!(view.bind_failure(), Some(&gone));
        // Bound since, then the port is taken.
        view.read_log("raven-node lan_direct: listen 192.0.2.10:7499\n");
        assert_eq!(view.bind_failure(), None);
        view.read_log(&bind_failed(
            "0.0.0.0:7420",
            "Address already in use (os error 48)",
        ));
        assert_eq!(
            view.bind_failure(),
            Some(&BindFailure::InUse { port: 7420 })
        );
        // The Status's own word wins over the log's (the cutoff pack's
        // fields), and the log's is there again without it.
        view.apply(&Probe::of(&ok(told(
            Some(42),
            "192.0.2.10:7499",
            "addr_not_here",
        ))));
        assert_eq!(view.bind_failure(), Some(&gone));
        view.apply(&send_only);
        assert_eq!(
            view.bind_failure(),
            Some(&BindFailure::InUse { port: 7420 })
        );
        // Receiving again: the word is forgotten, so a later stop of the
        // listener has none until the log says.
        view.apply(&listening);
        assert_eq!(view.bind_failure(), None);
        view.apply(&send_only);
        assert_eq!(view.bind_failure(), None);
        // What the log said during a start counts once it ends.
        view.state = NodeState::Starting {
            since: Instant::now(),
        };
        view.read_log(&failed);
        assert_eq!(view.bind_failure(), None, "still starting");
        view.state = NodeState::Unknown;
        view.apply(&send_only);
        assert_eq!(view.bind_failure(), Some(&gone));
        // Stopped: nothing to say, and nothing kept.
        view.apply(&Probe::of(&Err("raven-node is not running; x".into())));
        assert_eq!(view.bind_failure(), None);
        view.apply(&send_only);
        assert_eq!(view.bind_failure(), None);
    }

    #[test]
    fn ipc_errors_read_as_not_running_or_not_answering() {
        // Nothing listens in an empty profile. (Unix only: on Windows the
        // pipe is per user, and a real node would answer.)
        #[cfg(unix)]
        {
            let dir = testkit::short_dir();
            let none = probe(dir.path());
            assert_eq!(none.reach, Reach::NotRunning);
            assert!(!none.running() && !none.timed_out);
        }
        let none = Probe::of(&Err("raven-node is not running; start it (x)".into()));
        assert_eq!(none.reach, Reach::NotRunning);
        assert_eq!(
            Probe::of(&Err("ipc_transport_missing".into())).reach,
            Reach::NotAnswering
        );
        let timed_out = Probe::timed_out();
        assert_eq!(timed_out.reach, Reach::NotAnswering);
        assert!(timed_out.timed_out);
    }

    #[test]
    fn the_started_notice_names_the_pid() {
        // As ext.rs prints it on a terminal: colours around 'notice'.
        let lines = [
            "raven: something else (process 7)",
            "\x1b[1;35mnotice\x1b[0m: started raven-node (process 4242), RAVEN's background \
             service for this profile. It keeps running after ash exits.",
            "\x1b[2mstop only this one with: kill 4242 · log: /tmp/x\x1b[0m",
        ];
        assert_eq!(notice_pid(lines), Some(4242));
        assert_eq!(notice_pid(["started raven-node (process 12)"]), Some(12));
        // Hidden characters can't fake a pid; nor can a cut line.
        for fake in [
            "started raven-node (process 4242",
            "started raven-node (process )",
            "started raven-node (process 42x)",
            "started raven-node (process 99999999999)",
        ] {
            assert_eq!(notice_pid([fake]), None, "{fake:?}");
        }
        // What the screen would show is read: an escape sequence or an
        // invisible character is dropped first.
        assert_eq!(
            notice_pid(["started raven-node (process\u{200b} 42)"]),
            Some(42)
        );
        assert_eq!(
            notice_pid(["started raven-node (process 42\x1b[0m43)"]),
            Some(4243)
        );
        assert_eq!(notice_pid(Vec::<&str>::new()), None);
    }

    #[test]
    fn only_a_node_this_app_spawned_counts_as_started_by_it() {
        use Reach::{Listening, LocalOnly, NotAnswering, NotRunning};
        let up = Listening { port: Some(7420) };
        let table = [
            // before, pid after, pid in the notice, synced -> started_by_app
            (NotRunning, Some(42), Some(42), true, Some(42)),
            (NotRunning, Some(43), Some(42), true, None),
            (NotRunning, Some(42), None, true, None),
            (NotRunning, None, Some(42), true, None),
            (up, Some(42), Some(42), true, None),
            (LocalOnly, Some(42), None, false, None),
            (NotAnswering, Some(42), Some(42), true, None),
            // The reader never got to the sentinel: the pid after.
            (NotRunning, Some(42), None, false, Some(42)),
            (NotRunning, None, None, false, None),
        ];
        for (before, after, notice, synced, want) in table {
            assert_eq!(
                started_by_app(before, after, notice, synced),
                want,
                "{before:?} {after:?} {notice:?} {synced}"
            );
        }
    }

    /// uses_vault, passphrase file, credentials dir, credential exists ->
    /// needs a passphrase file.
    type Case<'a> = (
        Result<bool, String>,
        Option<&'a OsString>,
        Option<&'a OsString>,
        bool,
        bool,
    );

    #[test]
    fn the_vault_decision_table() {
        let file = OsString::from("/home/sam/.config/raven/keystore-passphrase");
        let creds = OsString::from("/run/credentials/raven-node.service");
        let empty = OsString::new();
        let table: [Case; 9] = [
            (Ok(false), None, None, false, false),
            (Err("no keystore".into()), None, None, false, false),
            (Ok(true), None, None, false, true),
            (Ok(true), Some(&file), None, false, false),
            (Ok(true), Some(&empty), None, false, true),
            (Ok(true), None, Some(&creds), true, false),
            (Ok(true), None, Some(&creds), false, true),
            (Ok(true), None, Some(&empty), true, true),
            (Ok(true), Some(&file), Some(&creds), false, false),
        ];
        for (vault, passfile, dir, exists, want) in table {
            let got = needs_passphrase_file(
                vault.clone(),
                passfile.map(OsString::as_os_str),
                dir.map(OsString::as_os_str),
                |_: &Path| exists,
            );
            assert_eq!(got, want, "{vault:?} {passfile:?} {dir:?} {exists}");
        }
        // The credential is looked for under its systemd name.
        let looked = std::cell::RefCell::new(Vec::new());
        needs_passphrase_file(Ok(true), None, Some(creds.as_os_str()), |path: &Path| {
            looked.borrow_mut().push(path.to_path_buf());
            false
        });
        assert_eq!(
            looked.into_inner(),
            [Path::new(&creds).join("raven-keystore-passphrase")]
        );
    }

    #[cfg(not(all(unix, not(target_os = "macos"))))]
    #[test]
    fn no_vault_here() {
        assert_eq!(vault_check(Path::new("unused")), Vault::default());
    }

    /// PASSFILE's file is under the home folder, which must be absolute.
    #[test]
    fn the_passphrase_file_is_where_passfile_says() {
        let home = std::env::temp_dir();
        assert_eq!(
            passphrase_file(Some(home.as_os_str())),
            Some(home.join(".config/raven/keystore-passphrase"))
        );
        assert_eq!(passphrase_file(Some(OsStr::new("home/sam"))), None);
        assert_eq!(passphrase_file(Some(OsStr::new(""))), None);
        assert_eq!(passphrase_file(None), None);
    }

    #[test]
    fn login_services_are_where_the_installers_put_them() {
        let home = std::env::temp_dir();
        let os = |p: &Path| p.as_os_str().to_owned();
        assert_eq!(
            login_service_file(true, Some(&os(&home))),
            Some(home.join("Library/LaunchAgents/com.raven.raven-node.plist"))
        );
        // Always ~/.config: the installer ignores XDG_CONFIG_HOME (PP.23).
        assert_eq!(
            login_service_file(false, Some(&os(&home))),
            Some(home.join(".config/systemd/user/raven-node.service"))
        );
        // A relative or missing folder is no answer, never the current folder.
        let relative = OsString::from("relative/home");
        assert_eq!(login_service_file(true, Some(&relative)), None);
        assert_eq!(login_service_file(false, Some(&relative)), None);
        assert_eq!(login_service_file(true, None), None);
        assert_eq!(login_service_file(false, None), None);
    }

    /// A login service counts for a profile only when its file runs
    /// raven-node for that profile, as each installer writes the path
    /// (D-interfaces-texts-3: `ash status` must not tell another profile to
    /// stop it).
    #[test]
    fn a_login_service_runs_the_profile_its_file_names() {
        let plist = "<array>\n    <string>/opt/bin/raven-node</string>\n    \
                     <string>service</string>\n    <string>--data-dir</string>\n    \
                     <string>/homes/sam/R&amp;D/.raven</string>\n    <string>--lan-listen</string>\n    \
                     <string>127.0.0.1:7420</string>\n  </array>\n  <key>StandardOutPath</key>\
                     <string>/homes/sam/R&amp;D/.raven/raven-node.log</string>";
        let dirs = |d: &[&str]| d.iter().map(|d| (*d).to_owned()).collect::<Vec<_>>();
        assert!(runs_profile(plist, &dirs(&["/homes/sam/R&D/.raven"])));
        assert!(runs_profile(
            plist,
            &dirs(&["relative/.raven", "/homes/sam/R&D/.raven"])
        ));
        // Another profile, one inside it, or one whose name starts the same.
        for other in [
            "/homes/sam/R&D/.raven2",
            "/homes/sam/R&D",
            "/homes/sam/.raven",
        ] {
            assert!(!runs_profile(plist, &dirs(&[other])), "{other}");
        }
        let unit = "[Service]\nExecStart=\"/home/sam/.local/bin/raven-node\" service --data-dir \
                    \"/home/sam/my \\\"raven\\\" 100%%\" --lan-listen \"127.0.0.1:7420\"\n";
        assert!(runs_profile(unit, &dirs(&["/home/sam/my \"raven\" 100%"])));
        assert!(!runs_profile(unit, &dirs(&["/home/sam/my"])));
        assert!(!runs_profile(unit, &dirs(&[])));
    }

    #[test]
    fn a_node_view_takes_the_nodes_word_unless_the_app_knows_better() {
        let program = Program {
            binary: PathBuf::from("/opt/raven/raven-node"),
            exe_known: true,
        };
        let mut view = NodeView::new(program);
        assert_eq!(view.state, NodeState::Unknown);
        let listening = Probe::of(&Ok(status(Some(42), &["lan_direct"], Some("0.0.0.0:7420"))));
        view.apply(&listening);
        assert_eq!(view.state, NodeState::Listening { port: Some(7420) });
        assert_eq!(view.running_pid(), Some(42));

        // A start in progress keeps its spinner until the start answers.
        let since = Instant::now();
        view.state = NodeState::Starting { since };
        view.apply(&listening);
        assert_eq!(view.state, NodeState::Starting { since });

        // A passphrase-file profile stays so while nothing runs.
        view.state = NodeState::NeedsPassphraseFile;
        let none = Probe::of(&Err("raven-node is not running; x".into()));
        view.apply(&none);
        assert_eq!(view.state, NodeState::NeedsPassphraseFile);
        assert_eq!(view.running_pid(), None);
        view.apply(&listening);
        assert!(view.running());

        // Started by this app until another pid answers, or none.
        view.started_by_app = Some(42);
        view.apply(&listening);
        assert_eq!(view.started_by_app, Some(42));
        view.apply(&none);
        assert_eq!(
            (view.started_by_app, &view.state),
            (None, &NodeState::NotRunning)
        );

        // Windows' stopped polling ends with the next real answer.
        view.polling_stopped = true;
        view.apply(&Probe::timed_out());
        assert!(view.polling_stopped);
        view.apply(&none);
        assert!(!view.polling_stopped);
    }

    #[test]
    fn the_service_log_is_read_from_where_a_start_began() {
        let dir = testkit::short_dir();
        assert_eq!(service_log_len(dir.path()), 0);
        assert!(service_log_from(dir.path(), 0).is_err());
        let log = bridge::service_log_path(dir.path());
        std::fs::write(&log, "old marker\n").unwrap();
        let from = service_log_len(dir.path());
        std::fs::write(&log, "old marker\nnew line\n").unwrap();
        let (text, end) = service_log_from(dir.path(), from).unwrap();
        assert_eq!((text.as_str(), end), ("new line\n", 20));
        // Started afresh (shorter than before): from its start.
        std::fs::write(&log, "fresh\n").unwrap();
        assert_eq!(service_log_from(dir.path(), end).unwrap().0, "fresh\n");
        // Only the last 64 KiB.
        std::fs::write(&log, "x".repeat(70 * 1024)).unwrap();
        let (text, _) = service_log_from(dir.path(), 0).unwrap();
        assert_eq!(text.len() as u64, LOG_TAIL_BYTES);
    }

    #[test]
    fn the_log_view_gets_the_last_lines_whole() {
        let dir = testkit::short_dir();
        // No log yet: nothing to show, not an error.
        assert!(service_log_tail(dir.path(), 40).unwrap().is_empty());
        let log = bridge::service_log_path(dir.path());
        let text: String = (1..=50).map(|n| format!("line {n}\r\n")).collect();
        std::fs::write(&log, text).unwrap();
        let tail = service_log_tail(dir.path(), 40).unwrap();
        assert_eq!(tail.len(), 40);
        assert_eq!(
            (tail[0].as_str(), tail[39].as_str()),
            ("line 11", "line 50")
        );
        assert_eq!(
            service_log_tail(dir.path(), 3).unwrap(),
            ["line 48", "line 49", "line 50"]
        );
        // Longer than one read: the line the read began inside is dropped.
        let long = format!("{}\nwhole one\nwhole two\n", "x".repeat(70 * 1024));
        std::fs::write(&log, long).unwrap();
        assert_eq!(
            service_log_tail(dir.path(), 40).unwrap(),
            ["whole one", "whole two"]
        );
        assert!(last_lines("", false, 40).is_empty());
        assert_eq!(last_lines("a\nb", false, 40), ["a", "b"]);
    }

    #[test]
    fn a_held_p2p_carrier_is_read_from_the_status() {
        let held = |held: bool| {
            let mut answer = status(Some(42), &["ipc", "lan_direct"], Some("0.0.0.0:7420"));
            if let IpcResponse::Status { p2p, .. } = &mut answer {
                *p2p = Some(Box::new(raven_core::ipc::P2pStatusInfo {
                    held,
                    listen_setting: "7423".into(),
                    ..Default::default()
                }));
            }
            Probe::of(&Ok(answer))
        };
        assert!(held(true).p2p_held);
        assert!(!held(false).p2p_held);
        assert!(!Probe::of(&Ok(status(Some(42), &["ipc"], None))).p2p_held);
        let mut view = NodeView::new(Program {
            binary: PathBuf::from("/opt/raven/raven-node"),
            exe_known: true,
        });
        view.apply(&held(true));
        assert!(view.p2p_held);
        view.apply(&Probe::of(&Err("raven-node is not running; x".into())));
        assert!(!view.p2p_held);
    }

    #[test]
    fn gate_labels_follow_the_constant_and_the_live_function() {
        let gate = |production, live| bridge::Gate { production, live };
        assert_eq!(GateState::of(gate(true, true)), GateState::On);
        assert_eq!(GateState::of(gate(true, false)), GateState::On);
        assert_eq!(GateState::of(gate(false, false)), GateState::Preview);
        assert_eq!(GateState::of(gate(false, true)), GateState::Lab);
        let lab = bridge::Gates {
            lan: gate(true, true),
            internet: gate(false, true),
            p2p: gate(false, true),
            custody: gate(false, false),
            nearby: gate(false, true),
        };
        assert_eq!(
            GatesView::of(lab, true),
            GatesView {
                lan: GateState::On,
                internet: GateState::Lab,
                p2p: GateState::Lab,
                custody: GateState::Preview,
                nearby: GateState::Lab,
                developer: true,
            }
        );
        // This build: a gate reads On only when its production constant is
        // on, whatever the lab switch says.
        let now = bridge::gates_now();
        let view = GatesView::of_this_build();
        for (gate, state) in [
            (now.lan, view.lan),
            (now.internet, view.internet),
            (now.p2p, view.p2p),
            (now.custody, view.custody),
            (now.nearby, view.nearby),
        ] {
            assert_eq!(state == GateState::On, gate.production, "{gate:?}");
        }
        assert_eq!(
            now.internet.production,
            raven_core::INTERNET_DIRECT_PRODUCTION_ENABLED
        );
        assert_eq!(now.p2p.production, raven_core::P2P_PRODUCTION_ENABLED);
        assert_eq!(view.developer, cfg!(debug_assertions));
    }

    #[test]
    fn requests_are_status_and_outbox_list_only() {
        assert_eq!(
            status_request(),
            IpcRequest::Status {
                v: IPC_VERSION,
                retry_key: false
            }
        );
        assert_eq!(
            outbox_request(Some("ab".repeat(32))),
            IpcRequest::OutboxList {
                v: IPC_VERSION,
                peer_pub_hex: Some("ab".repeat(32)),
                limit: Some(200),
            }
        );
        let item = OutboxItem {
            state: "queued".into(),
            ..OutboxItem::default()
        };
        let list = IpcResponse::OutboxListResult {
            v: IPC_VERSION,
            worker_running: true,
            items: vec![item.clone()],
        };
        assert_eq!(outbox_items(Ok(list)), Some(vec![item]));
        assert_eq!(outbox_items(Ok(IpcResponse::Pong { v: 1 })), None);
        assert_eq!(outbox_items(Err("down".into())), None);
    }
}
