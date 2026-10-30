//! Extended ash commands: bootstrap, device sync, chat, secure send, mailbox.
//! Kept separate from main.rs to keep the interactive shell readable.

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use rand::RngCore;
use raven_core::address::encode_address;
use raven_core::atsam_mlkem::HybridKeypair;
use raven_core::bootstrap::{load_bootstrap, save_bootstrap, try_load_bootstrap, BootstrapConfig};
use raven_core::chat_history::{BlockList, ChatHistory};
use raven_core::device_cert::{
    ensure_local_device_certificate, load_device_registry_checked, save_device_registry,
    with_device_registry_lock,
};
use raven_core::device_sync::{
    import_contact_sync_checked, seal_contact_sync, ContactSyncPlaintext, RevocationRecord,
    RevocationStore, SyncContact,
};
use raven_core::envelope::Envelope;
use raven_core::fingerprint::device_fingerprint_v1;
use raven_core::identity::Identity;
#[cfg(unix)]
use raven_core::ipc::default_socket_path;
use raven_core::ipc::{IpcRequest, IpcResponse, IPC_VERSION};
use raven_core::messaging_path::{assert_no_silent_fastapi, resolve_terminal_messaging_path};
use raven_core::outbox::{DeliveryPath, OutboxCarrier};
use raven_core::paths::{LanListen, PRIMARY_DEVICE_ID};
use raven_core::prekey_bundle::{PrekeyBundle, PrekeyBundleJson, PrekeyStore};
use raven_core::prekey_lifecycle::{PrekeyGenerationPrivate, PrekeyLifecycleActor};
use raven_core::reach_diag::{
    self, CircleFacts, Diag, Fix, MailPath, Why, HOLD_MAIL_CMD, KIT_REF, LAN_ON_CMD, MAILBOX_CMD,
    OFFER_CMD,
};
use raven_core::sanitize::{sanitize_terminal_line, sanitize_terminal_text};
use raven_core::security_words;
use raven_core::store_object::{
    mailbox_tag, mailbox_tags_with_overlap, store_tag_from_mailbox, StoreMailbox, StoreObject,
};
use std::process::Command;
use std::time::Duration;
use zeroize::Zeroize;

// Shared with cli.rs: one palette (honours NO_COLOR / non-TTY), one strict
// pub_hex parser, one clock, one host:port validator.
use super::{
    looks_like_lan_dial as looks_like_host_port, now_ms, parse_pub_hex_strict as parse_pub_hex,
    C_BOLD, C_CYAN, C_DIM, C_GREEN, C_PURPLE, C_RESET, DEFAULT_LAN_PORT, RECEIVED_AGAIN_NOTE,
};

#[derive(Debug, PartialEq, Eq)]
pub enum LineResult {
    Line(String),
    Eof,
    /// The line was not valid UTF-8 (a terminal or paste in a legacy encoding).
    /// It was read and dropped; the input is still open, so the caller says so
    /// and carries on instead of ending the session as if the user had quit.
    BadInput,
    Err,
}

pub fn read_line_result() -> LineResult {
    read_line_from(&mut io::stdin().lock())
}

fn read_line_from(input: &mut impl io::BufRead) -> LineResult {
    let mut s = String::new();
    match input.read_line(&mut s) {
        Ok(0) => LineResult::Eof,
        Ok(_) => LineResult::Line(s.trim().to_string()),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => LineResult::BadInput,
        Err(_) => LineResult::Err,
    }
}

pub fn raven_node_bin_public() -> PathBuf {
    raven_node_bin()
}

fn raven_node_bin() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("raven-node")))
        .unwrap_or_else(|| PathBuf::from("raven-node"))
}

/// Per-profile log the auto-started service writes stdout/stderr to (0600, in
/// the private data dir). It is the only place a failed start can explain itself.
const DAEMON_LOG_NAME: &str = raven_core::paths::SERVICE_LOG_NAME;
/// A fresh service must answer IPC within this window. It runs identity init
/// (Keychain / SQLCipher) before it binds the socket, which can take many
/// seconds on a cold profile.
const DAEMON_READY_DEADLINE: Duration = Duration::from_secs(20);
/// IPC timeout of one readiness probe, so a wedged daemon cannot eat the whole
/// window in a single probe.
const DAEMON_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a service that holds the instance lock but does not answer is given
/// before it is reported as unresponsive (the lock is taken right before the
/// socket is bound, so a healthy service answers within moments).
const DAEMON_LOCK_HOLDER_GRACE: Duration = Duration::from_secs(5);
const DAEMON_LOG_TAIL_BYTES: u64 = 2048;
/// Cap on the service log. `open_daemon_log` enforces it when ash starts a
/// service; the running service enforces it itself (it truncates its own log in
/// place) when ash passes the cap in [`DAEMON_LOG_MAX_ENV`], which it does only
/// for a log it opened, so a service started any other way is never touched.
const DAEMON_LOG_MAX_BYTES: u64 = 1 << 20;
const DAEMON_LOG_MAX_ENV: &str = "RAVEN_SERVICE_LOG_MAX_BYTES";
const DAEMON_LOG_MARKER: &str = "--- ash: starting raven-node service ---";
/// A service whose log says it is blocked on a macOS Keychain dialog is waiting
/// for a person, not slow: it gets this many times the usual readiness window
/// (160 s for the default 20 s), long enough to find the dialog and answer it
/// and still bounded, so a dialog nobody answers cannot hang ash for good.
const DAEMON_KEYCHAIN_WAIT_FACTOR: u32 = 8;
/// A service that has not answered after this long gets a "still starting" note
/// (terminals only: pipes keep their output).
const DAEMON_SLOW_START_NOTICE_AFTER: Duration = Duration::from_secs(3);
/// How often the service log is re-read while waiting, for the Keychain marker.
const DAEMON_LOG_POLL: Duration = Duration::from_millis(500);
/// After the service answers IPC, how long ash waits for it to report its LAN
/// listener (`lan_direct` in Status capabilities) before it says the computer is
/// not receiving. The listener starts right after IPC, so this is only slack.
const DAEMON_LISTENER_WAIT: Duration = Duration::from_secs(3);
/// What to do when the service waited on macOS for Keychain access. Appended to
/// the "did not answer" error: on a Mac that is by far the most likely cause.
const KEYCHAIN_APPROVE_HINT: &str =
    "If macOS asked for Keychain access for raven-node, approve it (Always Allow) and retry";

/// The service this process last auto-started, with the log offset where its
/// output begins. A slow start is awaited rather than duplicated (a second
/// spawn would only fail to bind the LAN port), and an exited child is reaped.
pub(super) type StartedDaemon = std::sync::Mutex<Option<(std::process::Child, u64)>>;
static STARTED_DAEMON: StartedDaemon = std::sync::Mutex::new(None);

/// Ends the service this process started, if it still runs, and reaps it:
/// `raven update install` (Phase 6 P6.47) after the new programs' node did
/// not answer, so the old programs' node can start. Its pid, if it ran.
/// Only this process's own child is ever ended.
pub(super) fn end_started_daemon() -> Option<u32> {
    let mut slot = STARTED_DAEMON.lock().unwrap_or_else(|e| e.into_inner());
    let (mut child, _) = slot.take()?;
    let pid = child.id();
    if matches!(child.try_wait(), Ok(None)) {
        let _ = child.kill();
        let _ = child.wait();
        return Some(pid);
    }
    None
}

/// The pid of the service this process started last, while it still runs
/// (review lock-updates-local-7): the node `raven update install` started
/// from the terminal app is the app's own, as one its start spawned is.
pub(super) fn started_daemon_pid() -> Option<u32> {
    let mut slot = STARTED_DAEMON.lock().unwrap_or_else(|e| e.into_inner());
    let (child, _) = slot.as_mut()?;
    matches!(child.try_wait(), Ok(None)).then(|| child.id())
}

fn daemon_log_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DAEMON_LOG_NAME)
}

/// Open (append, 0600) the service log; returns the file and the offset where
/// this attempt's output starts. A log grown past the cap is dropped first.
fn open_daemon_log(path: &Path) -> io::Result<(std::fs::File, u64)> {
    if std::fs::metadata(path).is_ok_and(|m| m.len() > DAEMON_LOG_MAX_BYTES) {
        let _ = std::fs::remove_file(path);
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `mode` only applies on creation; tighten a pre-existing file too.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let start = file.metadata()?.len();
    writeln!(file, "{DAEMON_LOG_MARKER}")?;
    Ok((file, start))
}

/// Last bytes of this attempt's output (sanitized for the terminal).
fn daemon_log_tail(path: &Path, from: u64) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return String::new();
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let begin = from.max(len.saturating_sub(DAEMON_LOG_TAIL_BYTES));
    if file.seek(SeekFrom::Start(begin)).is_err() {
        return String::new();
    }
    let mut raw = Vec::new();
    let _ = file.take(DAEMON_LOG_TAIL_BYTES).read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw);
    let kept: Vec<&str> = text
        .lines()
        .filter(|l| *l != DAEMON_LOG_MARKER && !l.trim().is_empty())
        .collect();
    sanitize_terminal_text(&kept.join("\n"))
}

/// Failure text: what happened, the service's own last words, the full log.
/// A full disk is named even when the service died before it could say so (its
/// stores then fail with "unable to open database file" or "database failed").
/// `then`: what freeing space does (nothing restarts a service that exited).
fn daemon_failure(
    what: &str,
    log: &Path,
    tail: &str,
    then: raven_core::disk_space::OnceFreed,
) -> String {
    let mut msg = what.to_string();
    if !tail.is_empty() {
        msg.push_str("\n  service output:");
        let lines: Vec<&str> = tail.lines().collect();
        for line in &lines[lines.len().saturating_sub(8)..] {
            msg.push_str("\n    ");
            msg.push_str(line);
        }
        let lower = tail.to_lowercase();
        if lower.contains("failed to bind") || lower.contains("in use") {
            msg.push_str(
                "\n  hint: another process holds the LAN port; set \
                 RAVEN_SERVICE_LAN_LISTEN=127.0.0.1:0 for an outbound-only service",
            );
        }
    }
    // The log sits in the profile, so its folder is the disk the stores need.
    if let Some(note) = log
        .parent()
        .and_then(|dir| raven_core::disk_space::disk_full_note(dir, tail, then))
    {
        msg.push_str(&format!("\n  hint: {note}"));
    }
    msg.push_str(&format!("\n  full log: {}", log.display()));
    msg
}

/// Keep the service alive after ash exits or its terminal closes: own process
/// group on Unix (a tty Ctrl-C / hangup targets the foreground group only),
/// detached console and new group on Windows.
fn detach_from_terminal(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = cmd;
    }
}

fn node_service_command(node: &Path, data_dir: &Path, listen: &str) -> Command {
    let mut cmd = Command::new(node);
    cmd.arg("service").arg("--data-dir").arg(data_dir).args([
        "--lan-listen",
        listen,
        "--ble-listen",
        "127.0.0.1:0",
    ]);
    cmd
}

/// How to stop the one service this ash started, by its process id: never a
/// pattern that would also match the service of another profile.
pub(super) fn stop_advice(pid: u32) -> String {
    if cfg!(windows) {
        // The service runs detached (no window), so plain `taskkill` only asks it
        // to close and Windows refuses; it has to be forced.
        format!("taskkill /F /PID {pid}")
    } else {
        format!("kill {pid}")
    }
}

/// What the service log says the service is blocked on: the Keychain marker line
/// the daemon writes while a macOS dialog holds its Keychain call
/// (`raven_core::macos_keychain`), in the plain words of the hint ash itself shows.
fn keychain_block_in(log_tail: &str) -> Option<&'static str> {
    use raven_core::macos_keychain::{last_daemon_marker, KeychainWhat};
    const ALL: [KeychainWhat; 4] = [
        KeychainWhat::IdentitySeed,
        KeychainWhat::ChatHistoryKey,
        KeychainWhat::SessionSecret,
        KeychainWhat::PrekeyState,
    ];
    let marker = last_daemon_marker(log_tail)?;
    Some(
        ALL.iter()
            .find(|what| what.token() == marker.what)
            .map_or("a saved secret", |what| what.label()),
    )
}

/// Said once, when the service log first shows it is waiting for a Keychain answer.
fn keychain_wait_notice(what: &str, wait_more: Duration) -> String {
    format!(
        "{C_PURPLE}note{C_RESET}: raven-node (the background service) is waiting for macOS \
         Keychain access to {what}.\n  \
         If a macOS window asks whether raven-node may use it, approve it (choose \"Always \
         Allow\"); the window can be hidden behind other windows.\n  \
         ash keeps waiting for up to {} more seconds, then gives up. Ctrl-C stops waiting now.",
        wait_more.as_secs()
    )
}

/// The service did not answer IPC in time, though it is still running.
fn slow_start_error(pid: u32, waited: Duration, keychain: Option<&str>) -> String {
    let mut msg = format!(
        "raven-node service did not answer IPC within {}s (it is still running as process \
         {pid}; retry shortly, or stop only this one with: {})",
        waited.as_secs(),
        stop_advice(pid)
    );
    if let Some(what) = keychain {
        msg.push_str(&format!(
            "\n  its log says it is waiting for macOS Keychain access to {what}"
        ));
    }
    if keychain.is_some() || cfg!(target_os = "macos") {
        msg.push_str(&format!("\n  {KEYCHAIN_APPROVE_HINT}"));
    }
    msg
}

/// Poll until the service answers IPC, exits (reported at once with its log
/// tail), or `deadline` passes. The IPC probe comes first, so another daemon
/// that came up meanwhile (a concurrent start) also counts as success.
///
/// A service can also be *waiting for a person*: on macOS it blocks inside a
/// Keychain call until a dialog is answered and says so in its log. ash notices,
/// tells the user once what to do, and gives it [`DAEMON_KEYCHAIN_WAIT_FACTOR`]
/// times the window instead of giving up on it after 20 s.
fn wait_for_daemon(
    data_dir: &Path,
    child: &mut std::process::Child,
    log_start: u64,
    deadline: Duration,
) -> Result<(), String> {
    let log = daemon_log_path(data_dir);
    let started = std::time::Instant::now();
    let mut deadline = deadline;
    let log_poll = DAEMON_LOG_POLL.min(deadline / 5);
    let mut keychain: Option<&'static str> = None;
    let mut next_log_look = Duration::ZERO;
    let mut said_still_starting = false;
    let mut delay = Duration::from_millis(40);
    loop {
        if super::ipc_client::ipc_daemon_up_within(data_dir, DAEMON_PROBE_TIMEOUT) {
            return Ok(());
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if super::ipc_client::ipc_daemon_up_within(data_dir, DAEMON_PROBE_TIMEOUT) {
                    return Ok(());
                }
                return Err(daemon_failure(
                    &format!("raven-node service exited during startup ({status})"),
                    &log,
                    &daemon_log_tail(&log, log_start),
                    raven_core::disk_space::OnceFreed::NotRunning,
                ));
            }
            Ok(None) => {}
            Err(e) => return Err(format!("could not poll the raven-node service: {e}")),
        }
        let elapsed = started.elapsed();
        // Always look once more at the deadline: a marker written a moment ago
        // must not be missed by the poll interval.
        if keychain.is_none() && (elapsed >= next_log_look || elapsed >= deadline) {
            next_log_look = elapsed + log_poll;
            if let Some(what) = keychain_block_in(&daemon_log_tail(&log, log_start)) {
                deadline = deadline.saturating_mul(DAEMON_KEYCHAIN_WAIT_FACTOR);
                eprintln!(
                    "{}",
                    keychain_wait_notice(what, deadline.saturating_sub(elapsed))
                );
                keychain = Some(what);
            }
        }
        if keychain.is_none()
            && !said_still_starting
            && elapsed >= DAEMON_SLOW_START_NOTICE_AFTER
            && io::stderr().is_terminal()
        {
            said_still_starting = true;
            eprintln!("{C_DIM}waiting for the raven-node service to start ...{C_RESET}");
        }
        if elapsed >= deadline {
            // Still running but not answering: the user retries.
            return Err(daemon_failure(
                &slow_start_error(child.id(), deadline, keychain),
                &log,
                &daemon_log_tail(&log, log_start),
                raven_core::disk_space::OnceFreed::RunAgain,
            ));
        }
        std::thread::sleep(delay.min(deadline - elapsed));
        delay = (delay * 3 / 2).min(Duration::from_millis(250));
    }
}

/// Printed right after the service is spawned: what it is, that it outlives ash,
/// and how to stop only this one (its process id, never a name pattern that would
/// also stop another profile's service).
fn started_notice(pid: u32, log: &Path) -> String {
    format!(
        "{C_PURPLE}notice{C_RESET}: started raven-node (process {pid}), RAVEN's background service \
         for this profile. It keeps running after ash exits.\n\
         {C_DIM}stop only this one with: {} · log: {}{C_RESET}",
        stop_advice(pid),
        log.display()
    )
}

/// Spawn `cmd` detached with stdout/stderr in the 0600 service log, say what was
/// started ([`started_notice`]), then wait for it to serve IPC. Reuses a
/// still-running service this process started earlier instead of spawning a
/// competing one.
fn start_daemon(
    data_dir: &Path,
    mut cmd: Command,
    deadline: Duration,
    slot: &StartedDaemon,
) -> Result<(), String> {
    let mut slot = slot.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((child, _)) = slot.as_mut() {
        if !matches!(child.try_wait(), Ok(None)) {
            *slot = None; // exited (now reaped) or unpollable: start afresh
        }
    }
    if slot.is_none() {
        let log = daemon_log_path(data_dir);
        let (stdout, stderr, log_start, log_captured) = match open_daemon_log(&log) {
            Ok((file, start)) => match file.try_clone() {
                Ok(dup) => (
                    std::process::Stdio::from(dup),
                    std::process::Stdio::from(file),
                    start,
                    true,
                ),
                Err(_) => (
                    std::process::Stdio::null(),
                    std::process::Stdio::null(),
                    0,
                    false,
                ),
            },
            Err(e) => {
                eprintln!(
                    "{C_DIM}note: cannot write {} ({e}); service output will not be captured{C_RESET}",
                    log.display()
                );
                (
                    std::process::Stdio::null(),
                    std::process::Stdio::null(),
                    0,
                    false,
                )
            }
        };
        if log_captured {
            // The daemon outlives this process and appends for weeks: let it
            // bound the log it was handed (see DAEMON_LOG_MAX_BYTES).
            cmd.env(DAEMON_LOG_MAX_ENV, DAEMON_LOG_MAX_BYTES.to_string());
        }
        cmd.stdin(std::process::Stdio::null())
            .stdout(stdout)
            .stderr(stderr);
        detach_from_terminal(&mut cmd);
        let child = cmd.spawn().map_err(|e| {
            format!(
                "could not start {} ({e}); build or install raven-node next to ash",
                cmd.get_program().to_string_lossy()
            )
        })?;
        // Said before the wait, so a process that was left running (Ctrl-C while
        // waiting) is never a surprise.
        eprintln!("{}", started_notice(child.id(), &log));
        *slot = Some((child, log_start));
    }
    let (child, log_start) = slot.as_mut().expect("daemon slot filled above");
    wait_for_daemon(data_dir, child, *log_start, deadline)
}

/// What the IPC endpoint of a profile says about the service that owns it.
#[derive(Debug, PartialEq, Eq)]
enum ExistingService {
    /// It answered a Ping.
    Up,
    /// A live service holds the instance lock (the contained path) but does not
    /// answer: wedged (stopped, deadlocked) or blocked on an OS keystore prompt.
    /// (Detected through the Unix instance lock only; Windows has no such lock.)
    #[cfg_attr(not(unix), allow(dead_code))]
    Unresponsive(PathBuf),
    /// No service for this profile (no one answers, no one holds the lock).
    Absent,
}

/// Probe the service for `data_dir`: up to three short pings (a busy daemon can
/// miss one), then, on Unix, whether a live service still *owns* the profile.
///
/// A pinged-out service that holds the instance lock is `Unresponsive`: its
/// socket must never be unlinked and no competing service started, which would
/// only die on that lock with a misleading "exited during startup". The lock is
/// taken only after the service's identity preflight, right before it binds, so a
/// holder that stays silent past a short `grace` (the gap between taking the lock
/// and listening) is not "still starting". Worst case is a few probes plus
/// `grace` instead of three full 10 s IPC timeouts. `still_starting`: the lock
/// belongs to a service this process started itself, which `start_daemon` waits for.
fn probe_existing_service(
    data_dir: &Path,
    probe: Duration,
    grace: Duration,
    still_starting: bool,
) -> ExistingService {
    for attempt in 0..3 {
        if super::ipc_client::ipc_daemon_up_within(data_dir, probe) {
            return ExistingService::Up;
        }
        if attempt < 2 {
            std::thread::sleep(Duration::from_millis(150));
        }
    }
    #[cfg(unix)]
    if !still_starting {
        let lock = raven_core::ipc::instance_lock_path(&default_socket_path(data_dir));
        if instance_lock_is_held(&lock) {
            let deadline = std::time::Instant::now() + grace;
            loop {
                if super::ipc_client::ipc_daemon_up_within(data_dir, probe) {
                    return ExistingService::Up;
                }
                if std::time::Instant::now() >= deadline {
                    return ExistingService::Unresponsive(lock);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (grace, still_starting);
    ExistingService::Absent
}

/// True when another process holds the (exclusive `flock`) instance lock at
/// `lock`. Probing takes the lock for an instant when it is free and releases it
/// at once. A missing or unopenable lock file has no holder.
#[cfg(unix)]
fn instance_lock_is_held(lock: &Path) -> bool {
    let Ok(file) = std::fs::OpenOptions::new().read(true).open(lock) else {
        return false;
    };
    matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock))
}

/// Whether a process holds this profile's IPC instance lock (Unix; Windows
/// has no lock file: always false). `raven lock` (PP.15) waits for it to be
/// free before it says Raven stopped.
pub(super) fn instance_lock_held(data_dir: &Path) -> bool {
    #[cfg(unix)]
    {
        instance_lock_is_held(&raven_core::ipc::instance_lock_path(&default_socket_path(
            data_dir,
        )))
    }
    #[cfg(not(unix))]
    {
        let _ = data_dir;
        false
    }
}

/// Start of [`unresponsive_service_error`]; the send path reports this error as
/// is instead of wrapping it in "not running and could not be started", which
/// would be the opposite of the truth.
const SERVICE_UNRESPONSIVE_PREFIX: &str =
    "local raven-node service is running but is not answering IPC";

/// Single-quote `s` for a POSIX shell (the stop advice below is pasted into one).
pub(super) fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Escape `s` for a POSIX extended regular expression (`pkill -f` takes one).
fn ere_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(
            c,
            '.' | '[' | ']' | '{' | '}' | '(' | ')' | '*' | '+' | '?' | '^' | '$' | '|' | '\\'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A Keychain marker in the service log describes what the service is doing now
/// only while the log is still being written: the guard repeats the marker every
/// 30 s while a dialog is open and writes nothing when it is answered, so an old
/// marker is just history.
const KEYCHAIN_MARKER_FRESH: Duration = Duration::from_secs(90);

fn log_written_within(path: &Path, window: Duration) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|written| written.elapsed().ok())
        .is_some_and(|age| age <= window)
}

fn unresponsive_service_error(data_dir: &Path, lock: &Path) -> String {
    // A service blocked on a Keychain dialog says so in its log: name it, so the
    // user answers the dialog instead of killing a healthy service. Only a log
    // that is still being written can say what the service waits for now.
    let log = daemon_log_path(data_dir);
    let waiting = if log_written_within(&log, KEYCHAIN_MARKER_FRESH) {
        keychain_block_in(&daemon_log_tail(&log, 0))
    } else {
        None
    }
    .map(|what| format!(" Its log says it is waiting for macOS Keychain access to {what}."))
    .unwrap_or_default();
    format!(
        "{SERVICE_UNRESPONSIVE_PREFIX} (profile {}; it holds {}): it may be wedged or waiting \
         on an OS keystore prompt.{waiting} Not starting a second one. Answer any prompt and \
         retry, or stop only this profile's service with: {}",
        data_dir.display(),
        lock.display(),
        profile_stop_advice(data_dir, None)
    )
}

/// How to stop this profile's service and no other: by the process id its IPC
/// `Status` reported, else (an older raven-node, or one that does not answer)
/// by a pattern anchored to this profile's `--data-dir`, which is how ash
/// starts every service.
pub(super) fn profile_stop_advice(data_dir: &Path, pid: Option<u32>) -> String {
    match pid {
        Some(pid) => stop_advice(pid),
        None if cfg!(windows) => format!(
            "end the raven-node.exe of this profile in Task Manager (Details: its command line \
             has --data-dir {})",
            data_dir.display()
        ),
        // `pkill -f` matches an unanchored regex against the whole command line: end
        // the pattern at the argument so `--data-dir /a/b` cannot also stop `/a/b2`.
        None => format!(
            "pkill -f {}",
            shell_quote(&format!(
                "raven-node service --data-dir {}( |$)",
                ere_escape(&data_dir.display().to_string())
            ))
        ),
    }
}

/// What the service reports about its LAN listener: `Some(true)` it is up,
/// `Some(false)` Status came back without `lan_direct` (port busy or unusable),
/// `None` Status could not be asked.
fn listener_reported(status: &Result<IpcResponse, String>) -> Option<bool> {
    match status {
        Ok(IpcResponse::Status { capabilities, .. }) => {
            Some(capabilities.iter().any(|c| c == "lan_direct"))
        }
        _ => None,
    }
}

/// Poll the service's Status for up to `wait` until it lists `lan_direct`. The
/// capability is listed only while the listener is really bound, and the service
/// answers IPC before its listener is up, so the first answers can still say no.
fn wait_for_lan_listener(data_dir: &Path, wait: Duration) -> Option<bool> {
    let deadline = std::time::Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let probe = DAEMON_PROBE_TIMEOUT.min(left.max(Duration::from_millis(200)));
        let state = listener_reported(&super::ipc_client::ipc_request_timeout(
            data_dir,
            &IpcRequest::status(),
            probe,
        ));
        if state != Some(false) || std::time::Instant::now() >= deadline {
            return state;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn listen_port_is_ephemeral(listen: &str) -> bool {
    listen
        .parse::<std::net::SocketAddr>()
        .is_ok_and(|a| a.port() == 0)
}

pub(super) fn listen_is_loopback(listen: &str) -> bool {
    listen
        .parse::<std::net::SocketAddr>()
        .map(|a| a.ip().is_loopback())
        .unwrap_or_else(|_| listen.starts_with("localhost"))
}

/// The next port after `port` that is not one RAVEN itself uses (mock BLE
/// 7421, Internet direct 7422, libp2p 7423, friend relay 7427): suggesting
/// 7421 for a second profile's LAN listener collided with the service's own
/// mock BLE listener.
fn next_free_lan_port(port: u16) -> Option<u16> {
    let mut next = port.checked_add(1)?;
    while raven_core::paths::RESERVED_RAVEN_PORTS.contains(&next) {
        next = next.checked_add(1)?;
    }
    Some(next)
}

/// A listen address for a second profile on this computer: the same host, the
/// next port RAVEN does not use itself (`auto` stays `auto`, on that port).
pub(super) fn alternative_listen(listen: &str) -> String {
    let next_default = next_free_lan_port(DEFAULT_LAN_PORT).unwrap_or(DEFAULT_LAN_PORT);
    if let Ok(LanListen::Auto { port }) = raven_core::paths::parse_lan_listen(listen) {
        let port = next_free_lan_port(port).unwrap_or(next_default);
        return format!("{}:{port}", raven_core::LAN_LISTEN_AUTO);
    }
    let fallback = || format!("0.0.0.0:{next_default}");
    match listen.parse::<std::net::SocketAddr>() {
        Ok(mut addr) if addr.port() != 0 => match next_free_lan_port(addr.port()) {
            Some(port) => {
                addr.set_port(port);
                addr.to_string()
            }
            None => fallback(),
        },
        _ => fallback(),
    }
}

/// What to tell the user about the LAN listener of a service ash just started.
/// "It receives on ..." only once the service says its listener is up; when it is
/// not, the computer would otherwise be silently deaf (a second profile on the
/// same machine always loses the default port), so say so once per process.
fn listener_message(
    listen: &str,
    state: Option<bool>,
    log: &Path,
    warned: &AtomicBool,
    pid: Option<u32>,
) -> Option<String> {
    let listen = sanitize_terminal_line(listen);
    // `auto` is a setting, not an address: every network of this computer.
    let auto_port = match raven_core::paths::parse_lan_listen(&listen) {
        Ok(LanListen::Auto { port }) => Some(port),
        _ => None,
    };
    match state {
        Some(true) => Some(format!(
            "{C_DIM}it is receiving messages{}{}{C_RESET}",
            match auto_port {
                Some(port) => format!(" on every network of this computer, port {port}"),
                // Port 0 asks the OS for a free one: the configured text says nothing.
                None if listen_port_is_ephemeral(&listen) => String::new(),
                None => format!(" on {listen}"),
            },
            if listen_is_loopback(&listen) {
                " (this computer only)"
            } else {
                " (other computers on your network can reach it)"
            }
        )),
        Some(false) if !warned.swap(true, Ordering::SeqCst) => Some(format!(
            "{C_PURPLE}warning{C_RESET}: this computer is NOT receiving messages: LAN port \
             {} is busy or unavailable (log: {}). Sending still works.\n  To receive: \
             free that port (the service keeps retrying by itself), or stop this service ({}) \
             and run ash again with RAVEN_SERVICE_LAN_LISTEN={} (and tell your contacts the \
             new port). Setting the variable while this service keeps running changes nothing.",
            auto_port.map_or_else(|| listen.clone(), |port| port.to_string()),
            log.display(),
            match pid {
                Some(pid) => stop_advice(pid),
                None => "stop this profile's service".to_string(),
            },
            alternative_listen(&listen)
        )),
        _ => None,
    }
}

/// Set once the "not receiving" warning was printed (once per ash process).
static LISTENER_WARNED: AtomicBool = AtomicBool::new(false);

/// What a service ash starts while `raven lan off` holds says about its
/// listener: there is none to wait for.
const LAN_OFF_START_NOTE: &str = "it does not listen on your network: LAN is off on this \
     computer (`raven lan on` turns it back on)";

/// Start the service with `cmd`, wait until it answers IPC, then say whether it
/// is receiving. The part of [`ensure_mac_lan_daemon`] that follows the probes.
/// `lan_off` (`raven lan off`, Phase 3): the service binds no LAN listener, so
/// nothing is waited for and that is what is said.
#[allow(clippy::too_many_arguments)]
fn start_and_report(
    data_dir: &Path,
    cmd: Command,
    listen: &str,
    deadline: Duration,
    listener_wait: Duration,
    slot: &StartedDaemon,
    warned: &AtomicBool,
    lan_off: bool,
) -> Result<(), String> {
    start_daemon(data_dir, cmd, deadline, slot)?;
    if lan_off {
        eprintln!("{C_DIM}{LAN_OFF_START_NOTE}{C_RESET}");
        return Ok(());
    }
    let pid = slot
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|(child, _)| child.id());
    if let Some(message) = listener_message(
        listen,
        wait_for_lan_listener(data_dir, listener_wait),
        &daemon_log_path(data_dir),
        warned,
        pid,
    ) {
        eprintln!("{message}");
    }
    Ok(())
}

/// Every interface, the Mac-listens port: where a service ash starts receives
/// when `RAVEN_SERVICE_LAN_LISTEN` is unset and `auto`'s gate is closed
/// ([`default_service_lan_listen`]), and the address `ash listen` falls back
/// to. Kept a socket address for the port arithmetic.
pub(super) const DEFAULT_SERVICE_LAN_LISTEN: std::net::SocketAddr = std::net::SocketAddr::V4(
    std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, DEFAULT_LAN_PORT),
);

/// The `--lan-listen` of a service ash starts for the profile in `data_dir`
/// when `RAVEN_SERVICE_LAN_LISTEN` is unset (Phase 3, D7): `auto` (every
/// network of this computer, both families, local sources only) while its
/// gate is live ([`raven_core::lan_auto_live`]), else
/// [`DEFAULT_SERVICE_LAN_LISTEN`], which is what `auto` means while the gate
/// is closed. Phase 6b P6.36: on the port the profile picked, where it
/// picked one ([`raven_core::node_policy::profile_lan_port`]), read at each
/// start, so `raven lan port random` moves the next one.
pub(super) fn default_service_lan_listen_for(data_dir: &Path) -> String {
    default_service_lan_listen_with(
        raven_core::lan_auto_live(),
        raven_core::node_policy::profile_lan_port(data_dir),
    )
}

/// [`default_service_lan_listen_for`] this process's profile
/// ([`note_own_profile`]; none noted: the default port), for the texts that
/// say where such a service would listen.
pub(super) fn default_service_lan_listen() -> String {
    default_service_lan_listen_with(raven_core::lan_auto_live(), own_profile_lan_port())
}

/// [`default_service_lan_listen_for`] with the gate and the profile's port
/// passed in.
fn default_service_lan_listen_with(auto_live: bool, port: Option<u16>) -> String {
    match (auto_live, port) {
        (true, None) => raven_core::LAN_LISTEN_AUTO.to_string(),
        (true, Some(port)) => format!("{}:{port}", raven_core::LAN_LISTEN_AUTO),
        (false, None) => DEFAULT_SERVICE_LAN_LISTEN.to_string(),
        (false, Some(port)) => {
            std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port)).to_string()
        }
    }
}

/// The profile this process works on (ash's main notes it once its data dir
/// is known): what [`own_lan_port`] reads.
static OWN_PROFILE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Note `data_dir` as this process's profile ([`own_lan_port`]).
pub(crate) fn note_own_profile(data_dir: &Path) {
    let _ = OWN_PROFILE.set(data_dir.to_path_buf());
}

/// The LAN port this process's profile picked (Phase 6b P6.36; read again
/// at each call, so a `raven lan port random` in another terminal shows),
/// `None` with none (or no profile noted).
fn own_profile_lan_port() -> Option<u16> {
    OWN_PROFILE
        .get()
        .and_then(|dir| raven_core::node_policy::profile_lan_port(dir))
}

/// The LAN port of this process's profile: the one it picked (Phase 6b
/// P6.36), else [`DEFAULT_LAN_PORT`]. What the hints that name "your" port
/// say (how to set the login service up again, where friends reach you).
pub(crate) fn own_lan_port() -> u16 {
    own_profile_lan_port().unwrap_or(DEFAULT_LAN_PORT)
}

/// `RAVEN_SERVICE_LAN_LISTEN`, trimmed, when it is set to anything: the LAN
/// address of a service ash starts by itself, which `ash listen` also honours.
pub(super) fn service_lan_listen_env() -> Option<String> {
    std::env::var("RAVEN_SERVICE_LAN_LISTEN")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Start / revive the LAN + IPC daemon the secure send path dials through.
///
/// The service it starts is persistent (it outlives ash: own process group, its
/// output kept in `raven-node-service.log`) and receives on
/// `RAVEN_SERVICE_LAN_LISTEN` (default [`default_service_lan_listen_for`]:
/// `0.0.0.0:7420`, the Mac-listens port, or `auto` while its gate is live;
/// on the profile's own port where it picked one),
/// so the user is told what was started, how to stop that one process, and
/// whether it is really receiving (the listener can be down while IPC works,
/// and there is none while `raven lan off` holds).
///
/// `Err` carries why it is not up (exit status, the service's own last output,
/// the log path) so callers refuse the send with a real reason instead of a
/// bare "No such file or directory" from the next IPC connect.
pub fn ensure_mac_lan_daemon(data_dir: &Path) -> Result<(), String> {
    ensure_lan_daemon_as_before(data_dir, None)
}

/// [`ensure_mac_lan_daemon`] for a node that ran before on `was` (its
/// `Status.lan_listen`; `None`: unknown), as `raven update install` and
/// `rollback` start one again where no login item does (review
/// lock-updates-local-6): `RAVEN_SERVICE_LAN_LISTEN` when set, else
/// [`restart_lan_listen`], so a node kept on this computer only is not
/// started again on every network.
pub(super) fn ensure_lan_daemon_as_before(
    data_dir: &Path,
    was: Option<&str>,
) -> Result<(), String> {
    // Outbound-IPC-only deployments (or same-host tests) may need a different
    // or ephemeral LAN bind than the default receive port.
    let listen = service_lan_listen_env()
        .unwrap_or_else(|| restart_lan_listen(was, default_service_lan_listen_for(data_dir)));
    ensure_daemon_in(data_dir, &raven_node_bin(), &listen, &STARTED_DAEMON).map(|_| ())
}

/// [`ensure_mac_lan_daemon`] with the program, the listen address and the
/// record of the service this process started (`slot`) given by the caller:
/// the desktop engine (engine_bridge.rs) names its own program and listens
/// as its settings say, and keeps one record per profile. `Ok(Some(pid))`:
/// the service running now is the one in `slot` (started by this caller).
pub(super) fn ensure_daemon_in(
    data_dir: &Path,
    node: &Path,
    listen: &str,
    slot: &StartedDaemon,
) -> Result<Option<u32>, String> {
    // A service this process started earlier may still be coming up: its socket
    // is not stale, and it must not be replaced.
    let still_starting = slot
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
        .is_some_and(|(child, _)| matches!(child.try_wait(), Ok(None)));
    match probe_existing_service(
        data_dir,
        DAEMON_PROBE_TIMEOUT,
        DAEMON_LOCK_HOLDER_GRACE,
        still_starting,
    ) {
        ExistingService::Up => return Ok(started_pid(slot)),
        ExistingService::Unresponsive(lock) => {
            return Err(unresponsive_service_error(data_dir, &lock));
        }
        ExistingService::Absent => {}
    }
    // Lock now (privacy pack PP.15, review R16): a profile `raven lock`
    // stopped stays stopped until `raven unlock`, so a send or `raven
    // listen` never undoes it. A node that runs anyway (started at login by
    // a login item Lock left on) is used as it is, above.
    if let Some(why) = auto_start_refusal(data_dir) {
        return Err(why.to_owned());
    }
    #[cfg(unix)]
    {
        let sock = default_socket_path(data_dir);
        if !still_starting && sock.exists() {
            // Stale UDS after crash → remove so a fresh service can bind.
            let _ = std::fs::remove_file(&sock);
        }
    }
    start_and_report(
        data_dir,
        node_service_command(node, data_dir, listen),
        listen,
        DAEMON_READY_DEADLINE,
        DAEMON_LISTENER_WAIT,
        slot,
        &LISTENER_WARNED,
        raven_core::lan_user_off(),
    )?;
    Ok(started_pid(slot))
}

/// The process id of the service in `slot` while it still runs.
fn started_pid(slot: &StartedDaemon) -> Option<u32> {
    let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
    let (child, _) = guard.as_mut()?;
    matches!(child.try_wait(), Ok(None)).then(|| child.id())
}

/// The `--lan-listen` of a node started again in place of one that listened
/// on `was` (`Status.lan_listen`), `default` being what a new one gets
/// (review lock-updates-local-6): `was` as it was (this computer only, one
/// network's address, a port of its own), except that every interface on
/// `default`'s `auto` port stays `auto` (whose IPv4 socket `was` is);
/// `default` when `was` is unknown (LAN off, an older node; a node Lock v2
/// holds is never stopped for an update, `update_install::NodeHost::locked`).
pub(super) fn restart_lan_listen(was: Option<&str>, default: String) -> String {
    let Some(was) = was.and_then(|was| was.trim().parse::<std::net::SocketAddr>().ok()) else {
        return default;
    };
    let auto_on_its_port = matches!(
        raven_core::paths::parse_lan_listen(&default),
        Ok(raven_core::paths::LanListen::Auto { port }) if port == was.port()
    );
    if was.ip().is_unspecified() && auto_on_its_port {
        default
    } else {
        was.to_string()
    }
}

/// Why ash must not start this profile's raven-node by itself now: an erase
/// of the profile did not finish (privacy pack PP.16: only `raven erase`
/// may touch it), or `raven lock` stopped it (PP.15), and only `raven
/// unlock` (or opening the terminal app, PP.23) starts it again.
pub(super) fn auto_start_refusal(data_dir: &Path) -> Option<&'static str> {
    if raven_core::erase::in_progress(data_dir) {
        return Some(raven_core::erase::UNFINISHED_TEXT);
    }
    raven_core::privacy::lock_state(data_dir)
        .locked_by_user
        .then_some(raven_core::privacy::LOCKED_TEXT)
}

// ── Bootstrap UX ──────────────────────────────────────────────────────────

pub fn cmd_bootstrap_show(data_dir: &Path) {
    let cfg = load_bootstrap(data_dir);
    println!("{C_BOLD}bootstrap{C_RESET}");
    println!(
        "{C_DIM}use_raven_defaults{C_RESET} {}",
        cfg.use_raven_defaults
    );
    println!(
        "{C_DIM}raven_defaults{C_RESET}     {}",
        cfg.raven_defaults.len()
    );
    for p in &cfg.raven_defaults {
        println!("  {C_DIM}raven{C_RESET} {}", sanitize_terminal_line(p));
    }
    println!("{C_DIM}custom{C_RESET}            {}", cfg.custom.len());
    for p in &cfg.custom {
        println!("  {C_CYAN}+{C_RESET} {}", sanitize_terminal_line(p));
    }
    println!(
        "{C_DIM}manual_peers{C_RESET}      {}",
        cfg.manual_peers.len()
    );
    for p in &cfg.manual_peers {
        println!("  {C_GREEN}*{C_RESET} {}", sanitize_terminal_line(p));
    }
    println!(
        "{C_DIM}effective{C_RESET}         {} peers",
        cfg.effective_peers().len()
    );
    println!(
        "{C_DIM}manual_only_ok{C_RESET}    {}",
        cfg.manual_peer_only_ok()
    );
}

/// Load `bootstrap.json` for a read-modify-write. A file that exists but cannot
/// be read or parsed is an error, never the fail-closed empty default (which
/// would then be saved over the user's real peer lists). A missing file is the
/// default config, so a first `add` still works.
fn load_bootstrap_for_edit(data_dir: &Path) -> Result<BootstrapConfig, String> {
    try_load_bootstrap(data_dir).map_err(|e| {
        format!(
            "bootstrap.json is unreadable ({e}); refusing to overwrite it. Fix or move it \
             aside, or reset it explicitly with `ash node init-bootstrap`"
        )
    })
}

fn bootstrap_add_apply(data_dir: &Path, multiaddr: &str, manual: bool) -> Result<String, String> {
    let s = sanitize_terminal_text(multiaddr.trim());
    if s.is_empty() {
        return Err("empty multiaddr".into());
    }
    let mut cfg = load_bootstrap_for_edit(data_dir)?;
    if manual {
        if !cfg.manual_peers.iter().any(|x| x == &s) {
            cfg.manual_peers.push(s.clone());
        }
    } else {
        cfg.add_custom(s.clone());
    }
    save_bootstrap(data_dir, &cfg).map_err(|e| format!("save failed: {e}"))?;
    Ok(s)
}

pub fn cmd_bootstrap_add(data_dir: &Path, multiaddr: &str, manual: bool) {
    match bootstrap_add_apply(data_dir, multiaddr, manual) {
        Ok(s) => println!("{C_GREEN}ok{C_RESET} added {}", s),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
    cmd_bootstrap_show(data_dir);
}

fn bootstrap_disable_raven_apply(data_dir: &Path) -> Result<(), String> {
    let mut cfg = load_bootstrap_for_edit(data_dir)?;
    cfg.remove_raven_defaults();
    save_bootstrap(data_dir, &cfg).map_err(|e| format!("save failed: {e}"))
}

pub fn cmd_bootstrap_disable_raven(data_dir: &Path) {
    if let Err(e) = bootstrap_disable_raven_apply(data_dir) {
        eprintln!("{e}");
        std::process::exit(1);
    }
    println!("{C_GREEN}ok{C_RESET} raven defaults disabled/cleared");
    cmd_bootstrap_show(data_dir);
}

pub fn cmd_bootstrap_init(data_dir: &Path, no_raven_defaults: bool) {
    let mut cfg = BootstrapConfig::default();
    if no_raven_defaults {
        cfg.remove_raven_defaults();
    }
    if let Err(e) = save_bootstrap(data_dir, &cfg) {
        eprintln!("save failed: {e}");
        std::process::exit(1);
    }
    println!("{C_GREEN}ok{C_RESET} wrote bootstrap.json");
    cmd_bootstrap_show(data_dir);
}

// ── Device sync ───────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct LocalContactRow {
    #[serde(default)]
    petname: String,
    #[serde(default)]
    public_tag: String,
    #[serde(default)]
    alias: String,
    address: String,
    pub_hex: String,
    #[serde(default)]
    pinned: bool,
    #[serde(default)]
    lan_dial: String,
    /// Kept through the load → merge → save of a sync import (the CLI's
    /// `Contact` writes it only when set; so does this row).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    internet_dial: String,
    /// The p2p route (P3), kept the same way.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    p2p: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    p2p_via: Vec<String>,
    /// The next epoch's PeerId (a card's `p2pn=`, Phase 4), kept the same way.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    p2p_next: String,
    /// Friend custody custodians: a local choice, kept through sync imports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    custodians: Vec<String>,
    /// Hide my IP from this contact: a local choice, kept the same way.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    hide_ip: bool,
}

/// The contact book's rows for device sync (sealed or plain); no book is an
/// empty one, an unreadable one an error.
fn load_local_contacts(data_dir: &Path) -> Result<Vec<LocalContactRow>, String> {
    Ok(raven_core::contact_book::read_rows(data_dir)
        .map_err(|e| super::book_error_text(data_dir, e))?
        .unwrap_or_default())
}

pub fn cmd_device_sync_export(data_dir: &Path, id: &Identity, device_id: &str, out: &Path) {
    let contacts = match load_local_contacts(data_dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let sync: Vec<SyncContact> = contacts
        .into_iter()
        .map(|c| {
            SyncContact {
                petname: c.petname,
                public_tag: if c.public_tag.is_empty() {
                    c.alias.clone()
                } else {
                    c.public_tag
                },
                alias: c.alias,
                address: c.address,
                pub_hex: c.pub_hex,
                pinned: c.pinned,
            }
            .migrate()
        })
        .collect();
    let plain = ContactSyncPlaintext {
        schema: 1,
        from_device_id: sanitize_terminal_text(device_id),
        contacts: sync,
        issued_at_ms: now_ms(),
    };
    match seal_contact_sync(id, &plain) {
        Ok(wire) => {
            if let Err(e) = std::fs::write(out, hex::encode(&wire)) {
                eprintln!("write failed: {e}");
                std::process::exit(1);
            }
            println!(
                "{C_GREEN}ok{C_RESET} sealed {} contacts → {}",
                plain.contacts.len(),
                out.display()
            );
            println!("{C_DIM}note{C_RESET} hex blob — exchange OOB / opaque store only");
        }
        Err(e) => {
            eprintln!("seal failed: {e}");
            std::process::exit(1);
        }
    }
}

pub fn cmd_device_sync_import(data_dir: &Path, id: &Identity, file: &Path) {
    let raw = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("read: {e}");
            std::process::exit(1);
        }
    };
    let wire = match hex::decode(raw.trim()) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("hex: {e}");
            std::process::exit(1);
        }
    };
    match device_sync_import_apply(data_dir, id, &wire) {
        Ok(added) => println!("{C_GREEN}ok{C_RESET} imported {added} new contact(s)"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

fn device_sync_import_apply(data_dir: &Path, id: &Identity, wire: &[u8]) -> Result<usize, String> {
    // The book's writer lock (`.contacts.lock.sqlite`) serialises the
    // contacts.json load → merge → save of a sync import; the save below
    // writes through it.
    let book =
        raven_core::contact_book::lock(data_dir).map_err(|e| format!("contacts lock: {e}"))?;
    // Load the local book BEFORE importing: the import records the per-sender
    // replay watermark, so a corrupt or unreadable contacts.json must fail
    // first, while the same sync file can still be imported once it is fixed.
    let mut local: Vec<LocalContactRow> = book
        .read_rows()
        .map_err(|e| super::book_error_text(data_dir, e))?
        .unwrap_or_default();
    // Fail-closed: checked registry (corrupt ≠ empty), sender auth unless no
    // registry exists yet, and replayed/stale blobs refused per sender.
    let imported = import_contact_sync_checked(data_dir, id, wire, now_ms())
        .map_err(|e| format!("import failed: {e}"))?;
    let mut added = 0usize;
    for sc in imported {
        // Same validation as `contact add`: strict key, canonical address that
        // the key actually encodes to. Rows here become trusted peers.
        let (pub_hex, address) = match validate_sync_row(&sc.address, &sc.pub_hex) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "{C_PURPLE}skip{C_RESET} invalid synced contact ({})",
                    sanitize_terminal_line(&e)
                );
                continue;
            }
        };
        if local
            .iter()
            .any(|c| c.pub_hex.eq_ignore_ascii_case(&pub_hex) || c.address == address)
        {
            continue;
        }
        // Pin conflict: refuse overwrite of pinned different key for same tag.
        let tag = if sc.public_tag.is_empty() {
            sc.alias.clone()
        } else {
            sc.public_tag.clone()
        };
        if !tag.is_empty()
            && local.iter().any(|c| {
                c.pinned
                    && c.public_tag.eq_ignore_ascii_case(&tag)
                    && !c.pub_hex.eq_ignore_ascii_case(&pub_hex)
            })
        {
            eprintln!(
                "{C_PURPLE}skip{C_RESET} @{} — pinned local key differs",
                sanitize_terminal_line(&tag)
            );
            continue;
        }
        local.push(LocalContactRow {
            petname: sanitize_terminal_line(sc.petname.trim()),
            public_tag: sanitize_terminal_line(&tag),
            alias: sanitize_terminal_line(&sc.alias),
            address,
            pub_hex,
            pinned: sc.pinned,
            lan_dial: String::new(),
            internet_dial: String::new(),
            p2p: String::new(),
            p2p_via: Vec::new(),
            p2p_next: String::new(),
            custodians: Vec::new(),
            hide_ip: false,
        });
        added += 1;
    }
    book.write_rows(&local)
        .map_err(|e| format!("save contacts: {}", super::book_error_text(data_dir, e)))?;
    Ok(added)
}

/// Strict key + canonical address bound to that key → `(pub_hex, address)`.
fn validate_sync_row(address: &str, pub_hex: &str) -> Result<(String, String), String> {
    let ed = parse_pub_hex(pub_hex)?;
    let address = raven_core::address::from_display(address);
    if raven_core::address::decode_address(&address).is_none() {
        return Err("address is not valid rvn1 bech32m".into());
    }
    if encode_address(&ed) != address {
        return Err("address/pub mismatch".into());
    }
    Ok((hex::encode(ed), address))
}

#[derive(Debug, PartialEq, Eq)]
enum RevokeOutcome {
    /// A new record was issued and saved.
    Revoked,
    /// The store already revoked this device at this or a newer epoch.
    AlreadyRevoked,
}

/// Revoke `device_id` in the revocation store and keep the device registry in
/// step. The registry push is idempotent and runs on every outcome, so a rerun
/// repairs a data dir where an earlier run saved `revocations.json` but failed
/// before the registry (that rerun must not be turned away as "already
/// applied" or as a same-epoch conflict with its own earlier record).
fn device_revoke_apply(
    data_dir: &Path,
    id: &Identity,
    device_id: &str,
    epoch: u64,
) -> Result<RevokeOutcome, String> {
    let user_hex = hex::encode(id.public_key_bytes());
    let mut store =
        RevocationStore::load_checked(data_dir).map_err(|e| format!("revocation store: {e}"))?;
    let outcome = if store
        .epoch_of(&user_hex, device_id)
        .is_some_and(|existing| existing >= epoch)
    {
        RevokeOutcome::AlreadyRevoked
    } else {
        let rec = RevocationRecord::issue(id, device_id, epoch, now_ms(), "operator-revoke")?;
        if store.apply(rec)? {
            store
                .save(data_dir)
                .map_err(|e| format!("revocation save failed: {e}"))?;
            RevokeOutcome::Revoked
        } else {
            RevokeOutcome::AlreadyRevoked
        }
    };
    with_device_registry_lock(data_dir, || {
        let mut reg = load_device_registry_checked(data_dir)?;
        store.push_into_registry(&user_hex, &mut reg);
        save_device_registry(data_dir, &reg)
    })
    .map_err(|e| format!("device registry: {e}"))?;
    Ok(outcome)
}

pub fn cmd_device_revoke(data_dir: &Path, id: &Identity, device_id: &str, epoch: u64) {
    match device_revoke_apply(data_dir, id, device_id, epoch) {
        Ok(RevokeOutcome::Revoked) => println!(
            "{C_GREEN}ok{C_RESET} revoked {}",
            sanitize_terminal_line(device_id)
        ),
        Ok(RevokeOutcome::AlreadyRevoked) => println!(
            "{C_DIM}already revoked at epoch >= {epoch}; device registry reconciled{C_RESET}"
        ),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

// ── Send outcomes in plain words ──────────────────────────────────────────
//
// Every way a send can end is said in the user's terms: what happened to their
// text (delivered / queued locally / NOT SENT, nothing queued), who it concerns
// (the contact's name, never a key) and the next step. The raw daemon or OS text
// stays at the end as "(technical: ...)" so logs and bug reports still carry it.
// The text goes to stderr (see `send_failure_line`); only success is on stdout.

/// Who a send goes to, where, and how its outcome is shown.
#[derive(Clone, Debug, Default)]
pub(crate) struct SendCtx {
    /// Petname, else `@tag`; empty when the peer is not a saved contact.
    pub(crate) name: String,
    /// Flags that select this contact in `ash contact ...` hints.
    pub(crate) selector: String,
    /// The peer's key (64 hex): `ash contact unblock` takes nothing else.
    pub(crate) pub_hex: String,
    /// The `host:port` being dialled (may be empty).
    pub(crate) dial: String,
    /// The profile, to name files in recovery steps.
    pub(crate) data_dir: Option<PathBuf>,
    /// Chat transcript lines instead of `status ...` lines.
    pub(crate) chat: bool,
    /// The user named the carrier (`--carrier internet`): the lab Internet
    /// carrier then prints its evidence line (`carrier=internet_dial`) without
    /// verbose mode. A carrier picked by `--carrier auto` is named only in
    /// verbose mode.
    pub(crate) show_carrier: bool,
    /// What the send asked for, recorded with a queued message so
    /// raven-node's outbox never retries it on more: `auto` unless the user
    /// forced a carrier (`--carrier`) or typed the exact LAN address
    /// (`--peer`, menu direct host:port), however many routes this attempt
    /// had. `None` (tests; `run_send_secure_on`, whose one route is the
    /// carrier the user named): the narrowest the routes allow.
    pub(crate) choice: Option<raven_core::outbox::CarrierChoice>,
    /// Friend custody may carry this send's own message: no carrier was
    /// forced (`--carrier` absent or `auto`).
    pub(crate) custody_ok: bool,
    /// LAN dials this send planned from what was learned about the contact
    /// (where it last reached us, its route hints): tried now, never recorded
    /// with a queued message (raven-node's worker plans them again through
    /// its own on-link filter).
    pub(crate) unrecorded: Vec<String>,
}

/// `s` as one POSIX shell word in a hint: bare when plain, else quoted.
/// (Windows shells: [`selector_for_shell`].)
fn shell_word(s: &str) -> String {
    let plain = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-' | ':'));
    if plain {
        s.to_string()
    } else if s.chars().any(|c| matches!(c, '"' | '$' | '`' | '\\' | '!')) {
        shell_quote(s)
    } else {
        format!("\"{s}\"")
    }
}

/// The `ash contact ...` selector flags for a contact known by `name`
/// (petname, or `@tag`) or else by `address`, as words the user can paste
/// into this platform's shell.
fn selector_for(name: &str, address: &str) -> String {
    selector_for_shell(name, address, cfg!(windows))
}

/// [`selector_for`] for a POSIX shell, or (`windows`) for PowerShell, the
/// default there, and cmd.exe. A name either of those would change is not
/// put in the command: a bare `@` is a PowerShell splat, `$` and a backtick
/// expand inside its double quotes, `,` makes an array, and cmd.exe expands
/// `%VAR%` (inside double quotes too) and takes no single quotes. The
/// contact's rvn1 address, which is plain, selects it instead (as
/// `relay_arg_for` gives `--relay` the friend's own address); with no
/// address, the name goes in PowerShell's verbatim single quotes.
fn selector_for_shell(name: &str, address: &str, windows: bool) -> String {
    let (flag, word) = if let Some(tag) = name.strip_prefix('@') {
        ("--tag", tag)
    } else if !name.is_empty() {
        ("--petname", name)
    } else if !address.is_empty() {
        return format!("--address {address}");
    } else {
        return String::new();
    };
    if !windows {
        format!("{flag} {}", shell_word(word))
    } else if super::p2p_cli::plain_word(word, true) {
        format!("{flag} {word}")
    } else if super::p2p_cli::plain_word(address, true) {
        format!("--address {address}")
    } else {
        format!("{flag} {}", super::p2p_cli::powershell_quote(word))
    }
}

impl SendCtx {
    /// Only a display name is known (see [`friendly_send_error`]).
    pub(crate) fn named(who: &str) -> Self {
        let name = sanitize_terminal_line(who.trim());
        Self {
            selector: selector_for(&name, ""),
            name,
            ..Self::default()
        }
    }

    /// When the last secure connection with this contact ended, from the
    /// session store's metadata (only when the profile has a store): None
    /// while one can take messages, for a contact never paired, and without
    /// a profile (tests).
    /// With the long message horizon live a message waits for a new one
    /// (P5.8): None.
    fn session_ended_at(&self) -> Option<u64> {
        if raven_core::horizon::horizon_live_enabled() {
            return None;
        }
        let dir = self.data_dir.as_deref()?;
        let key = parse_pub_hex(&self.pub_hex).ok()?;
        match raven_core::outbox::queue_reach(dir, &key, now_ms()).ok()? {
            raven_core::outbox::QueueReach::Ended { at_ms } => Some(at_ms),
            _ => None,
        }
    }

    fn who(&self) -> String {
        if self.name.is_empty() {
            "the other person".into()
        } else {
            self.name.clone()
        }
    }

    /// The name the outcome lines use for the recipient.
    pub(crate) fn display_name(&self) -> String {
        self.who()
    }

    fn whose(&self) -> String {
        format!("{}'s", self.who())
    }

    fn sel(&self) -> String {
        if self.selector.is_empty() {
            "--petname NAME".into()
        } else {
            self.selector.clone()
        }
    }
}

/// `raven outbox show`'s line for a message held as `CONTACT_NOT_VERIFIED`.
/// A contact with a LAN address saved was held there because that address
/// is not on the local network (an unverified contact is dialled only at an
/// address there, as raven-node's outbox localizes it); without one, its
/// only route is the Internet, which needs the contact verified.
fn not_verified_line(data_dir: &Path, ctx: &SendCtx) -> String {
    let who = ctx.who();
    // `raven lan verified-only on` (Phase 3 P3.C2): no LAN route at all.
    if raven_core::node_policy::lan_verified_only(data_dir) {
        if let Ok(peer) = parse_pub_hex(&ctx.pub_hex) {
            return verified_only_words(&who, &peer);
        }
    }
    let lan = match contact_for_key(data_dir, &ctx.pub_hex) {
        Ok(contact) => contact
            .map(|c| c.lan_dial.trim().to_string())
            .filter(|dial| !dial.is_empty()),
        // Never a guess about its routes from a book that cannot be read.
        Err(e) => return e,
    };
    match lan {
        Some(dial) => format!(
            "{who} is not verified, so RAVEN reaches {who} only at an address on your local \
             network, and the saved LAN address {} is not one there. Save the IP address {who} \
             has on your network: {}. Or compare security words with them by phone or in \
             person: raven contact verify {}.",
            sanitize_terminal_line(&dial),
            fix_address_cmd(FailedCarrier::Lan, &ctx.sel()),
            ctx.sel()
        ),
        None => format!(
            "Its only route is the Internet, which needs {who} verified: compare security words \
             with them by phone or in person: raven contact verify {}.",
            ctx.sel()
        ),
    }
}

/// The saved contact whose key is `pub_hex` (read-only). A book that cannot
/// be read (sealed without its key, corrupt) is an error for the caller to
/// say, never "no contact" (privacy pack PP.4).
fn contact_for_key(data_dir: &Path, pub_hex: &str) -> Result<Option<LocalContactRow>, String> {
    Ok(load_local_contacts(data_dir)?
        .into_iter()
        .find(|c| c.pub_hex.trim().eq_ignore_ascii_case(pub_hex.trim())))
}

/// Who `peer_pub_hex` is to the user: the contact's petname, else its `@tag`.
/// `petname` / `tag` are what the caller already knows (the chat does); the CLI
/// send paths pass "" and the saved contact is looked up here.
pub(crate) fn send_ctx(data_dir: &Path, petname: &str, tag: &str, peer_pub_hex: &str) -> SendCtx {
    let clean_tag = |t: &str| sanitize_terminal_line(t.trim().trim_start_matches('@'));
    let mut petname = sanitize_terminal_line(petname.trim());
    let mut tag = clean_tag(tag);
    // A label only: a book that cannot be read leaves the name unknown
    // (never "not a contact"; what needs the book reports it).
    if petname.is_empty() && tag.is_empty() {
        if let Ok(Some(c)) = contact_for_key(data_dir, peer_pub_hex) {
            petname = sanitize_terminal_line(c.petname.trim());
            tag = clean_tag(&c.public_tag);
        }
    }
    let name = if !petname.is_empty() {
        petname
    } else if !tag.is_empty() {
        format!("@{tag}")
    } else {
        String::new()
    };
    let key = parse_pub_hex(peer_pub_hex).ok();
    SendCtx {
        selector: selector_for(&name, &key.map(|k| encode_address(&k)).unwrap_or_default()),
        name,
        pub_hex: key.map(hex::encode).unwrap_or_default(),
        dial: String::new(),
        data_dir: Some(data_dir.to_path_buf()),
        chat: false,
        show_carrier: false,
        choice: None,
        custody_ok: false,
        unrecorded: Vec::new(),
    }
}

/// How a failed send is explained. The raw text decides ([`classify_cause`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cause {
    /// The computer answered but nothing listens on that port.
    NotListening,
    /// No answer at all (off, asleep, other network, new IP).
    NotReachable,
    /// The saved computer name (`name.local`) is not found on this network:
    /// nothing was dialled.
    NameNotFound,
    /// Something answered, then hung up or went silent.
    ClosedEarly,
    /// The peer took the connection and closed it without a word.
    PeerRefused,
    /// The address belongs to another key than the saved contact's.
    WrongIdentity,
    BadAddress,
    NoAddress,
    /// RAVEN's own background service on this computer.
    ServiceDown,
    ServiceStart,
    /// The service was started and is still running but has not answered yet: a
    /// slow start, often a macOS Keychain window nobody has answered.
    ServiceSlow,
    HistoryUnreadable,
    KeychainDenied,
    HistoryLocked,
    TooLarge,
    BadCharacters,
    Blocked,
    SendInProgress,
    /// Nothing but whitespace was typed.
    EmptyMessage,
    /// This computer's noise pin store (M0, `lan_noise_pins.json`) exists
    /// but cannot be read: raven-node dials no one until it is fixed.
    PinStoreUnreadable,
    /// `raven lan off` is in effect (Phase 3, `LAN_OFF`): nothing was dialled
    /// on the local network.
    LanOff,
    /// macOS refused raven-node's own connection to a local-network address
    /// ("No route to host", [`raven_core::outbox::local_network_refused`]):
    /// the app that started raven-node has no Local Network permission, or got
    /// it after raven-node started. Nothing reached the contact.
    LocalNetworkRefused,
    /// Not one of the above: the raw text is all there is.
    Other,
}

pub(super) fn classify_cause(raw: &str) -> Cause {
    let l = raw.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| l.contains(n));
    // Most specific first: several texts embed the words of another. A service
    // that is still running but slow to answer is wrapped in the same "not
    // running and could not be started" prefix as one that failed to start.
    if has(&["did not answer ipc within", "is still running as process"]) {
        Cause::ServiceSlow
    } else if has(&["service is not running and could not be started"]) {
        Cause::ServiceStart
    } else if has(&[PIN_STORE_NEEDLE]) {
        Cause::PinStoreUnreadable
    } else if has(&[LAN_OFF_NEEDLE]) {
        Cause::LanOff
    } else if has(&[
        "identity bind does not match",
        "rlb1 identity does not match",
        "rlb1 offer identity mismatch",
        NOISE_PIN_NEEDLE,
    ]) {
        Cause::WrongIdentity
    } else if has(&[
        "_dial_peer_closed",
        "link_not_accepted",
        "closed the connection without",
        "waiting_for_pair_response",
        "not a local contact",
    ]) {
        Cause::PeerRefused
    } else if raven_core::outbox::local_network_refused(raw) {
        // This computer's, not the contact's: it wins over what the other
        // routes found (a reach reason, a refused or a silent address).
        Cause::LocalNetworkRefused
    } else if has(NAME_NOT_FOUND_NEEDLES) {
        Cause::NameNotFound
    } else if has(&["on the local block list", "blocked peer"]) {
        Cause::Blocked
    } else if has(&["still held by another raven process"]) {
        Cause::HistoryLocked
    } else if has(&[
        "chat history is corrupt",
        "chat history authentication failed",
        "protected chat-history key is corrupt",
        "chat history file has unsafe metadata",
        "plaintext chat history",
    ]) {
        Cause::HistoryUnreadable
    } else if has(&[
        "protected chat-history key is missing",
        "keychain read failed",
        "keychain default failed",
        "keychain add failed",
        "chat-history backend unavailable",
    ]) {
        Cause::KeychainDenied
    } else if has(&["message too large for"]) {
        Cause::TooLarge
    } else if has(&["violates the bounded application policy"]) {
        Cause::BadCharacters
    } else if has(&["earlier outbound object must be retried"]) {
        Cause::SendInProgress
    } else if has(&["message is empty"]) {
        Cause::EmptyMessage
    } else if has(&["host:port required", "localistenqueue"]) {
        Cause::NoAddress
    } else if has(&[
        "invalid socket address",
        "must be host:port",
        "lan_dial parse",
        "internet_dial parse",
    ]) {
        Cause::BadAddress
    } else if has(&[
        "raven-node is not running",
        "service stopped during the request",
        "raven-node did not answer in time",
        "ipc_transport_missing",
        "is running but is not answering ipc",
        "ipc worker exited",
        "ipc_frame",
        "unexpected ipc",
    ]) {
        Cause::ServiceDown
    } else if has(&["connection refused", "actively refused"]) {
        Cause::NotListening
    } else if has(&[
        "closed the connection during the handshake",
        "early eof",
        "failed to fill whole buffer",
        "connection reset",
        "broken pipe",
        "read timeout",
        "handshake deadline exceeded",
        "did not return an rlb1 bundle",
    ]) {
        Cause::ClosedEarly
    } else if has(&[
        "no answer within",
        "timed out",
        "timeout",
        "cannot connect",
        "connect budget exhausted",
        "no route to host",
        "network is unreachable",
        "host is down",
        "unknown network interface",
        "dial exceeded",
        "p2p_unreachable",
    ]) {
        Cause::NotReachable
    } else {
        Cause::Other
    }
}

/// How the resolvers say a computer name was not found: raven-node's own
/// prefix, the Rust resolver's, getaddrinfo's on macOS and Linux (EAI_NONAME,
/// EAI_AGAIN) and Windows' (WSAHOST_NOT_FOUND, os error 11001).
const NAME_NOT_FOUND_NEEDLES: &[&str] = &[
    "cannot resolve",
    "failed to lookup address",
    "could not be resolved",
    "nodename nor servname",
    "name or service not known",
    "no such host is known",
    "temporary failure in name resolution",
];

/// raven-node's text when another key answered at the contact's address and
/// the dial stopped before identifying this computer (M0, a noise pin
/// mismatch): a [`Cause::WrongIdentity`] with its own words, since nothing
/// was told to whatever answered and the contact is often back there later.
const NOISE_PIN_NEEDLE: &str = "lan noise pin mismatch";

pub(super) fn is_noise_pin_mismatch(raw: &str) -> bool {
    raw.to_ascii_lowercase().contains(NOISE_PIN_NEEDLE)
}

/// The other cause of a noise pin mismatch: `who` reinstalled RAVEN without
/// its seed, so its key changed and no wait can reach it (the dial cannot
/// tell that from another computer at the address).
fn pin_reinstall_step(who: &str, sel: &str) -> String {
    format!(
        "If {who} reinstalled RAVEN, get their new invite, compare the fingerprint with them by \
         phone or in person, then `ash contact remove {sel}` and add them again."
    )
}

/// raven-node's text when this computer's noise pin store exists but cannot
/// be read (`lan noise pin unavailable: lan_noise_pins.json: <io kind>`): no
/// dial goes out ([`Cause::PinStoreUnreadable`]).
const PIN_STORE_NEEDLE: &str = "lan noise pin unavailable";

/// `raven lan off`'s code, as raven-node's LAN dial refusal and a send's own
/// LAN probe error carry it (`LAN_OFF: …`, [`Cause::LanOff`]; lowercase, as
/// matched). With its colon: a reason block's `why=lan_off` (Phase 3
/// diagnosis) never changes how a text is read.
const LAN_OFF_NEEDLE: &str = "lan_off:";
/// The pin store's file name in the data folder (raven-core's
/// `lan_noise_pin::NOISE_PIN_FILE`; a sealed profile's is
/// `NOISE_PIN_SEALED_FILE`, named when raven-node's text names it).
const PIN_STORE_FILE: &str = raven_core::lan_noise_pin::NOISE_PIN_FILE;

/// The pin store as the reader can find it: its path when the data folder is
/// known, then why it cannot be read when raven-node says (` (permission
/// denied)`), made safe for the terminal.
fn pin_store_file(ctx: &SendCtx, raw: &str) -> String {
    let sealed = raven_core::lan_noise_pin::NOISE_PIN_SEALED_FILE;
    let name = if raw.contains(sealed) {
        sealed
    } else {
        PIN_STORE_FILE
    };
    let file = match &ctx.data_dir {
        Some(dir) => sanitize_terminal_line(&dir.join(name).display().to_string()),
        None => format!("{name} (in your RAVEN data folder)"),
    };
    let kind = raw
        .split(&format!("{name}: "))
        .nth(1)
        .and_then(|rest| rest.split([';', ')', '(']).next())
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(|k| format!(" ({})", sanitize_terminal_line(k)))
        .unwrap_or_default();
    format!("{file}{kind}")
}

/// The address being dialled: the caller's, else the one the daemon names
/// ("cannot connect to 10.0.0.5:7420 (...)"), as ` at <address>` (or nothing).
fn at_dial(ctx: &SendCtx, raw: &str) -> String {
    let named = raw
        .split("cannot connect to ")
        .nth(1)
        .and_then(|rest| rest.split([' ', '(']).next())
        .unwrap_or_default();
    let dial = if ctx.dial.trim().is_empty() {
        named
    } else {
        ctx.dial.trim()
    };
    if dial.is_empty() {
        String::new()
    } else {
        format!(" at {}", sanitize_terminal_line(dial))
    }
}

/// The computer name a dial could not find, as the reader saw it saved: the
/// one raven-node names ("cannot resolve x.local: ..."), else the host of
/// the address being dialled; made safe for the terminal, empty when
/// neither says.
fn unresolved_name(ctx: &SendCtx, raw: &str) -> String {
    let named = raw
        .split("cannot resolve ")
        .nth(1)
        .and_then(|rest| rest.split([':', ' ', ';', ')']).next())
        .unwrap_or_default();
    let dial = ctx.dial.trim();
    let host = if !named.is_empty() {
        named
    } else {
        dial.rsplit_once(':').map_or(dial, |(host, _)| host)
    };
    sanitize_terminal_line(host.trim_start_matches('[').trim_end_matches(']'))
}

/// The text a [`Cause::NameNotFound`] is read from when that is what the
/// failure says: `raw` itself, or a failed LAN route's part of it when this
/// computer has no route to the internet ([`p2p_reason`]). None for any
/// other cause, and when a p2p reason explains it.
fn name_not_found_part(cause: Cause, ctx: &SendCtx, raw: &str) -> Option<String> {
    match p2p_reason(cause, ctx, raw) {
        None => (cause == Cause::NameNotFound).then(|| raw.to_owned()),
        Some(Reach::Lan(Cause::NameNotFound, part, _)) => Some(part),
        Some(_) => None,
    }
}

/// What to do when the contact's computer name was not found ([`Cause::NameNotFound`]):
/// `waits`, the message is queued and goes out once the two are on the same
/// network; otherwise when to send it again. `fix` saves a new address.
fn name_not_found_step(ctx: &SendCtx, fix: &str, waits: bool) -> String {
    let new_address = new_address_step(ctx, fix);
    if waits {
        format!("When you are both on the same network it goes out by itself. {new_address}")
    } else {
        format!("Send it again when you are both on the same network. {new_address}")
    }
}

/// Save the contact's new address with `fix`, if its computer has one.
fn new_address_step(ctx: &SendCtx, fix: &str) -> String {
    format!(
        "If {} computer has a new address, save it: {fix}.",
        ctx.whose()
    )
}

/// The `(max N bytes)` of the size refusal, in words a reader can use.
fn too_large_sentence(raw: &str) -> String {
    let limit = raw
        .split("(max ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse::<usize>().ok());
    match limit {
        Some(n) => format!(
            "this message is too big to send in one piece (the limit is {n} bytes: about {} \
             Persian or {n} English letters)",
            n / 2
        ),
        None => "this message is too big to send in one piece".into(),
    }
}

fn history_file(ctx: &SendCtx) -> String {
    match &ctx.data_dir {
        Some(dir) => dir.join("chat_history.json").display().to_string(),
        None => "chat_history.json (in your RAVEN data folder)".into(),
    }
}

/// What happened, without a closing period: the caller adds the sentence end.
fn cause_sentence(cause: Cause, ctx: &SendCtx, raw: &str, first_contact: bool) -> String {
    // E2 r40: Tor answered the send's check, the message's own Tor dial
    // connection then did not get through: say exactly that.
    if raw.contains(super::pair_init_lab::ONION_CHECKED_THEN_LOST) {
        return format!(
            "{} answered over Tor, but the message itself did not get through this time",
            ctx.who()
        );
    }
    // Tor not dialled by this send: raven-node's outbox is already trying
    // it for an earlier message and has not reached the friend yet (field
    // test E3: "couldn't be reached" while nothing had been tried).
    if raw.contains(super::pair_init_lab::TOR_BUSY) {
        return format!(
            "Raven is already trying to reach {} over Tor with an earlier message, and Tor \
             hasn't reached {} yet",
            ctx.who(),
            ctx.who()
        );
    }
    // E2 r40 (A): Tor was the only way and it did not answer within the
    // send's wait.
    if tor_only_no_answer(raw) {
        return format!("{} couldn't be reached over Tor right now", ctx.who());
    }
    if let Some(sentence) = every_way_failed(ctx, raw) {
        return sentence;
    }
    match p2p_reason(cause, ctx, raw) {
        Some(Reach::P2p(d, names)) => return p2p_cause_sentence(&d, ctx, &names),
        Some(Reach::Lan(lan, part, no_route)) => {
            // The LAN addresses tried, as the send listed them.
            let tried = SendCtx {
                dial: lan_dials_tried(&part),
                ..ctx.clone()
            };
            let sentence = cause_sentence(lan, &tried, &part, first_contact);
            return if no_route {
                format!("{sentence} (this computer has no route to the internet)")
            } else {
                sentence
            };
        }
        None => {}
    }
    let (who, whose, at) = (ctx.who(), ctx.whose(), at_dial(ctx, raw));
    match cause {
        // A sender cannot tell a locked Raven from a closed one (E1).
        Cause::NotListening => format!(
            "{whose} computer is there, but Raven isn't receiving right now (it may be locked or \
             closed)"
        ),
        Cause::NotReachable => format!(
            "{who} did not answer{at}: their computer may be off or asleep, on another \
             network, or have a new IP address"
        ),
        Cause::NameNotFound => format!(
            "{whose} computer name{} could not be found on this network ({who} may be away, or \
             on another network)",
            spaced(&unresolved_name(ctx, raw))
        ),
        Cause::ClosedEarly => format!(
            "something answered{at} but stopped talking or hung up: it may not be RAVEN, or \
             {whose} RAVEN is busy or stuck"
        ),
        Cause::PeerRefused if first_contact => format!(
            "{who} did not accept your first message: most often {who} has not added you as a \
             contact yet (both of you must add each other)"
        ),
        Cause::PeerRefused => format!(
            "{who} accepted the connection but refused it without saying why: {who} may not \
             have you in their contacts, may have lost their connection with you (for \
             example after a reinstall), or {whose} RAVEN could not save the message (their \
             chat history or Keychain), in which case it may already be in their inbox"
        ),
        Cause::WrongIdentity if is_noise_pin_mismatch(raw) => format!(
            "something else answered at {whose} address{at}: it is not {whose} RAVEN, so RAVEN \
             stopped before telling it who you are"
        ),
        Cause::WrongIdentity => format!(
            "the computer{at} answered, but it is not {who}: its key is not the one you saved \
             for {who}"
        ),
        Cause::BadAddress if ctx.dial.trim().is_empty() => {
            "the saved address is not a valid IP:PORT".into()
        }
        Cause::BadAddress => format!(
            "the saved address \"{}\" is not a valid IP:PORT",
            sanitize_terminal_line(ctx.dial.trim())
        ),
        Cause::NoAddress => format!("{who} has no network address saved yet"),
        Cause::ServiceDown => {
            "RAVEN's background service (raven-node) on this computer is not answering".into()
        }
        Cause::ServiceStart => {
            "RAVEN's background service (raven-node) could not be started on this computer".into()
        }
        Cause::ServiceSlow if waits_on_keychain(raw) => {
            "RAVEN's background service (raven-node) was started but is still waiting for macOS \
             Keychain access"
                .into()
        }
        Cause::ServiceSlow => {
            "RAVEN's background service (raven-node) was started but has not answered yet".into()
        }
        Cause::HistoryUnreadable => {
            "your local chat history cannot be opened (the file is damaged or its key changed)"
                .into()
        }
        Cause::KeychainDenied => "RAVEN could not open its saved chat key (the system keychain \
             refused access, or the key is missing)"
            .into(),
        Cause::HistoryLocked => "another RAVEN program on this computer is holding your chat \
             history (usually raven-node, waiting for a Keychain answer)"
            .into(),
        Cause::TooLarge => too_large_sentence(raw),
        Cause::BadCharacters => "your message contains characters that cannot be sent (control \
             characters, for example from arrow, Home or End keys)"
            .into(),
        Cause::Blocked => format!("{who} is blocked on this computer"),
        Cause::SendInProgress => {
            format!("another send to {who} is still running (another terminal?)")
        }
        Cause::EmptyMessage => "the message is empty (it has no visible text)".into(),
        Cause::PinStoreUnreadable => format!(
            "RAVEN cannot read {}, the file it checks your friends' computers against, so it \
             connects to no one",
            pin_store_file(ctx, raw)
        ),
        Cause::LanOff => format!(
            "LAN is off on this computer (`raven lan off`), so RAVEN does not connect to {who} \
             on your network"
        ),
        Cause::LocalNetworkRefused => format!(
            "this Mac did not let RAVEN connect to {who}{at}: macOS itself answered \"No route \
             to host\", as it does while the app that started raven-node has no Local Network \
             permission (or got it only after raven-node started), so {who} was never asked"
        ),
        Cause::Other => "the send could not be completed".into(),
    }
}

/// True when the service's own words say it waits for a macOS Keychain answer.
fn waits_on_keychain(raw: &str) -> bool {
    raw.to_ascii_lowercase()
        .contains("waiting for macos keychain access")
}

/// The number after `marker` in `raw` (the process id in "... still running as
/// process 123; ...").
fn number_after(raw: &str, marker: &str) -> Option<u32> {
    let rest = raw.split(marker).nth(1)?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// What to do about it; empty when there is nothing to add. `raw` is the text the
/// cause was read from (a few causes carry facts in it, such as a process id).
/// Which carrier a failed dial used, from its technical text: the advice to give
/// differs (a LAN address cannot fix an Internet route).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailedCarrier {
    Lan,
    Internet,
    P2p,
}

fn failed_carrier(raw: &str) -> FailedCarrier {
    let l = raw.to_ascii_lowercase();
    if l.contains("internet_dial") || l.contains("internet connect") {
        FailedCarrier::Internet
    } else if l.contains("p2p_dial") || l.contains("p2p_unreachable") {
        FailedCarrier::P2p
    } else {
        FailedCarrier::Lan
    }
}

/// The command that saves a corrected address for the carrier that failed.
fn fix_address_cmd(carrier: FailedCarrier, sel: &str) -> String {
    match carrier {
        FailedCarrier::Lan => format!("ash contact set-dial {sel} --lan-dial IP:PORT"),
        FailedCarrier::Internet => format!("ash contact set-addr {sel} --internet HOST:PORT"),
        FailedCarrier::P2p => format!("ash contact set-addr {sel} --p2p PEER_ID --via MULTIADDR"),
    }
}

/// What a send whose p2p probe ash cut short says (no reason yet). The
/// dial raven-node runs gives its reason within 20 s when it connects
/// nothing, but a dial that rides a link gone stale ends later (its stream
/// times out, at most at its 40 s deadline) and gives none: the reason
/// comes with the next try, within about a minute (lan_fault_matrix s48:
/// 43-45 s after the relay froze).
const STILL_FINDING_OUT: &str = "RAVEN is still finding out why: `raven status` says it once \
                                 raven-node has tried again (within about a minute).";

/// The next step after an Internet direct dial reached nobody. With no
/// route to the internet (`no_route`, raven-node's `Status.egress`, asked
/// only here) nothing on the contact's side (Internet direct, a port
/// forward) could help: only the same network can.
fn internet_unreachable_step(who: &str, fix: &str, no_route: impl FnOnce() -> bool) -> String {
    if no_route() {
        format!(
            "This computer has no route to the internet right now: send it again when you and \
             {who} are on the same network (the same Wi-Fi, a hotspot or a cable)."
        )
    } else {
        format!(
            "{who} must be reachable from the Internet: Internet direct on in their raven-node \
             (`raven node internet on`) and their router forwarding that port to their \
             computer. If their address changed: {fix}."
        )
    }
}

fn next_step(cause: Cause, ctx: &SendCtx, first_contact: bool, raw: &str) -> String {
    match p2p_reason(cause, ctx, raw) {
        Some(Reach::P2p(d, names)) => {
            let mode = if first_contact {
                StepMode::FirstContact
            } else {
                StepMode::Later
            };
            if let Some(step) = p2p_next_step(&d, ctx, &names, mode) {
                return step;
            }
        }
        Some(Reach::Lan(lan, part, _)) => return next_step(lan, ctx, first_contact, &part),
        None => {}
    }
    let (who, sel) = (ctx.who(), ctx.sel());
    let carrier = failed_carrier(raw);
    let fix = fix_address_cmd(carrier, &sel);
    match cause {
        // The computer answered at that address: nothing says it is wrong.
        Cause::NotListening => format!("Ask {who} to open Raven, then send again."),
        Cause::NotReachable => match carrier {
            FailedCarrier::Lan => format!(
                "Check that you are on the same network as {who}. If their IP changed: {fix}."
            ),
            FailedCarrier::Internet => internet_unreachable_step(&who, &fix, || {
                ctx.data_dir
                    .as_deref()
                    .is_some_and(super::p2p_cli::daemon_has_no_route)
            }),
            FailedCarrier::P2p => {
                let step = format!(
                    "{who} must be reachable directly or through a relay you both use (`raven \
                     node p2p on --relay ...`). If their address changed: {fix}."
                );
                // ash gave up before raven-node's own dial ended: it knows why
                // once that dial, or the next try, ends.
                if raw.contains("the probe was cut short") && !raw.contains(reach_diag::REACH_TAG) {
                    format!("{step} {STILL_FINDING_OUT}")
                } else {
                    step
                }
            }
        },
        Cause::NameNotFound => name_not_found_step(ctx, &fix, !first_contact),
        Cause::ClosedEarly => {
            format!("Try again in a moment. If it keeps happening, check the address: {fix}.")
        }
        Cause::PeerRefused if first_contact => format!(
            "Send {who} your invite line (`ash whoami`) and ask them to add you and to keep \
             `ash listen` running, then send again."
        ),
        Cause::PeerRefused => format!(
            "Send {who} your invite line (`ash whoami`) and ask them to check that you are in \
             their contacts, that `ash listen` is running and that no macOS Keychain window \
             is waiting for them (`ash doctor` shows more). If they already see your message, \
             do not send it again."
        ),
        // Both causes: another computer took the address (it goes out
        // later), or the contact reinstalled RAVEN, which changes this key
        // too and no wait can reach (a first message gives the reinstall
        // step alone, below).
        Cause::WrongIdentity if !first_contact && is_noise_pin_mismatch(raw) => format!(
            "It goes out when {who} connects to you, when you join another network, or when \
             you save {who}'s new address. {}",
            pin_reinstall_step(&who, &sel)
        ),
        Cause::WrongIdentity => format!(
            "If {who} reinstalled RAVEN, get their new invite, compare the fingerprint with \
             them by phone or in person, then `ash contact remove {sel}` and add them again. \
             If only their address changed: {fix}."
        ),
        Cause::BadAddress => {
            format!("Save a valid one: ash contact set-dial {sel} --lan-dial 192.168.1.20:7420.")
        }
        Cause::NoAddress => format!(
            "Ask {who} to run `ash listen` and tell you the IP:PORT it shows, then save it: ash \
             contact set-dial {sel} --lan-dial IP:PORT."
        ),
        Cause::ServiceDown => {
            "Try again in a moment; if it keeps happening, run `ash doctor`.".into()
        }
        Cause::ServiceStart => {
            "The technical details below say why; fix that and send again.".into()
        }
        Cause::ServiceSlow => {
            let stop = number_after(raw, "is still running as process ")
                .map(|pid| format!(" Or stop it with: {}.", stop_advice(pid)))
                .unwrap_or_default();
            if waits_on_keychain(raw) {
                format!(
                    "If a macOS window asks whether raven-node may use a saved secret, approve \
                     it (choose \"Always Allow\"; the window can be hidden behind other \
                     windows), then send again.{stop}"
                )
            } else {
                format!(
                    "Wait a moment and send again; if it keeps happening, run `ash \
                     doctor`.{stop}"
                )
            }
        }
        Cause::HistoryUnreadable => format!(
            "Your keys and contacts are not affected. Quit ash, move {} aside (keep it if you \
             may want to recover it), then try again: the history starts empty.",
            history_file(ctx)
        ),
        Cause::KeychainDenied => {
            "On a Mac, approve the Keychain window when it asks (Always Allow), then send again."
                .into()
        }
        Cause::HistoryLocked => "Answer any macOS Keychain window (Always Allow), then send \
             again. The service log (raven-node-service.log in your RAVEN data folder) says \
             what it is waiting for."
            .into(),
        Cause::TooLarge => "Shorten it or split it into several messages.".into(),
        Cause::BadCharacters => "Retype it with plain text only; arrow keys do not edit inside \
             this prompt, use Backspace."
            .into(),
        Cause::Blocked => unblock_hint(ctx),
        Cause::SendInProgress => "Wait a moment, then send again.".into(),
        Cause::EmptyMessage => "Type some text and send again.".into(),
        Cause::PinStoreUnreadable => "Fix that file's owner or permissions (for example after \
             RAVEN ran with sudo), or move it aside (RAVEN learns your friends' keys again as \
             you connect), then send again."
            .into(),
        Cause::LanOff => "Turn LAN back on with `raven lan on`, then send again.".into(),
        Cause::LocalNetworkRefused => format!(
            "In System Settings > Privacy & Security > Local Network, turn on the app that \
             started raven-node (your terminal app, or Raven), then restart raven-node so it \
             gets the permission: {}.",
            super::service_restart_hint()
        ),
        Cause::Other => String::new(),
    }
}

/// The undo for a block. `ash contact unblock` takes the key itself.
fn unblock_hint(ctx: &SendCtx) -> String {
    if ctx.pub_hex.is_empty() {
        "To undo: ash contact unblock --pub-hex <their key>".into()
    } else {
        format!("To undo: ash contact unblock --pub-hex {}", ctx.pub_hex)
    }
}

// ── why a p2p contact cannot be reached (diagnosis) ─────────────────────────
//
// raven-node decides WHY a p2p dial reached nobody and appends its reason
// block (`reach: why=…`, raven_core::reach_diag) to the P2P_UNREACHABLE text;
// ash says WHAT TO DO. Every text below needs that block, so an older
// raven-node (or a release build, where p2p never runs) keeps today's text.

/// How a p2p reason's next step is worded: a first message (it cannot
/// wait in the queue), a later one that was not queued, or a queued one
/// (never "send again": the queued copy would go out twice).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StepMode {
    FirstContact,
    Later,
    Queued,
}

/// What the p2p reason sentences name besides the contact: our own relay
/// slot the reason names (`relay`: "Carol's relay" when a contact offered
/// it, else "your relay at host:port", else "your relay"), that relay's
/// owner (`relay_owner`, empty when it is not a contact's), the fix, the
/// friend the fix names (`friend`, for [`Fix::AskFriend`]) and the port a
/// port forward names (`port`: the running raven-node's p2p port,
/// [`super::p2p_cli::p2p_port`], else the release default).
#[derive(Clone, Debug, PartialEq, Eq)]
struct ReachNames {
    relay: String,
    relay_owner: String,
    fix: Fix,
    friend: String,
    port: u16,
}

impl ReachNames {
    /// The names for `d`, from the profile's files: the circle
    /// ([`reach_diag::circle_facts`]; unreadable: not known, so
    /// [`Fix::Generic`] where the circle decides) and, only when the reason
    /// names our relay, the fix may be offering relaying or it names the
    /// port to forward (both behind NAT), the running raven-node's `Status`
    /// (2 s at most).
    fn load(ctx: &SendCtx, d: &Diag) -> Self {
        let Some(dir) = ctx.data_dir.as_deref() else {
            return Self::from_facts(d, None, &CircleFacts::default(), &|_| String::new(), &[]);
        };
        let mut circle = reach_diag::circle_facts(dir, now_ms()).unwrap_or_default();
        if offline_reason(d.why) {
            circle.mail = contact_mail_path(dir, &ctx.pub_hex);
        }
        let status =
            (d.relay.is_some() || matches!(d.why, Why::NoRelay | Why::BothNat)).then(|| {
                super::ipc_client::ipc_request_timeout(
                    dir,
                    &IpcRequest::status(),
                    Duration::from_secs(2),
                )
            });
        let info = status.as_ref().and_then(super::p2p_cli::p2p_info);
        let policy_relays = if d.relay.is_some() {
            raven_core::node_policy::try_load_policy(dir)
                .map(|p| p.p2p_relays)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Self::from_facts(
            d,
            info,
            &circle,
            &|hex| contact_label(dir, hex),
            &policy_relays,
        )
    }

    /// [`Self::load`] once the facts are read: `label` names a contact by
    /// its key (hex; empty when it is no contact), `policy_relays` are the
    /// relays node_policy.json sets by hand (a slot's last fallback).
    fn from_facts(
        d: &Diag,
        info: Option<&raven_core::ipc::P2pStatusInfo>,
        circle: &CircleFacts,
        label: &dyn Fn(&str) -> String,
        policy_relays: &[String],
    ) -> Self {
        let me_public = info
            .is_some_and(|i| super::p2p_cli::class_of(i) == raven_core::reach::ReachClass::Public);
        let relaying = info.is_some_and(super::p2p_cli::relaying_for_contacts);
        let fix = reach_diag::pick_fix(d, me_public, relaying, circle);
        let friend = match fix {
            Fix::AskFriend(key) => non_empty_or(label(&hex::encode(key)), "a contact"),
            _ => String::new(),
        };
        let (mut relay, mut relay_owner) = (String::new(), String::new());
        if let Some(slot) = d.relay {
            let i = usize::from(slot.saturating_sub(1));
            let health = info.and_then(|info| info.relay_health.get(i));
            if let Some(h) = health.filter(|h| h.source == "offer") {
                relay_owner = label(&h.operator_pub_hex);
            }
            let at = health
                .map(|h| h.relay.as_str())
                .or(policy_relays.get(i).map(String::as_str))
                .map(super::p2p_cli::relay_label)
                .filter(|at| at != "(no address)");
            relay = if !relay_owner.is_empty() {
                format!("{relay_owner}'s relay")
            } else if let Some(at) = at {
                format!("your relay at {at}")
            } else {
                "your relay".into()
            };
        }
        Self {
            relay,
            relay_owner,
            fix,
            friend,
            port: info.map_or(
                raven_core::p2p_route::DEFAULT_P2P_PORT,
                super::p2p_cli::p2p_port,
            ),
        }
    }
}

/// A reason that says the contact is offline: the ones a friend's mailbox
/// can help with ([`reach_diag::pick_fix`]).
pub(super) fn offline_reason(why: Why) -> bool {
    matches!(
        why,
        Why::ContactOffline | Why::DirectFailed | Why::LanNoAnswer
    )
}

/// Whether a friend could hold mail for the contact `pub_hex` names
/// ([`reach_diag::mail_path`]): read only while learned custody is live
/// (a release build reads nothing), with this profile's key.
pub(super) fn contact_mail_path(data_dir: &Path, pub_hex: &str) -> MailPath {
    contact_mail_paths(data_dir, &[pub_hex])
        .pop()
        .map_or(MailPath::NoFix, |(_, m)| m)
}

/// [`contact_mail_path`] for several contacts (key hex), with one read of
/// this profile's key: (lowercase key hex, path) for each one that has a
/// mailbox fix; nothing while learned custody is not live.
pub(super) fn contact_mail_paths(data_dir: &Path, pub_hexes: &[&str]) -> Vec<(String, MailPath)> {
    if pub_hexes.is_empty() || !raven_core::custody_gate::custody_hints_live() {
        return Vec::new();
    }
    let Ok(Some(identity)) = raven_core::load_identity(data_dir) else {
        return Vec::new();
    };
    let (local, now) = (identity.public_key_bytes(), now_ms());
    pub_hexes
        .iter()
        .filter_map(|hex| {
            let peer = parse_pub_hex(hex).ok()?;
            let path = reach_diag::mail_path(data_dir, &local, &peer, now);
            (path != MailPath::NoFix).then(|| (hex::encode(peer), path))
        })
        .collect()
}

fn non_empty_or(text: String, fallback: &str) -> String {
    if text.is_empty() {
        fallback.to_string()
    } else {
        text
    }
}

/// A contact's name (petname, else `@tag`) by its key; empty when the key
/// is no contact of this profile. Never the key itself.
pub(crate) fn contact_label(data_dir: &Path, pub_hex: &str) -> String {
    if pub_hex.trim().is_empty() {
        return String::new();
    }
    send_ctx(data_dir, "", "", pub_hex).name
}

/// The sealed letters this computer left with friends (Phase 5 P5.16, for
/// `raven node custody status`): one row per letter and friend that holds
/// it, `With Carol for Bob · until Tue 14:05 (in about 46 h)`, on this
/// computer's clock. A letter being withdrawn, a REPLY, and a book that
/// cannot be read show nothing.
pub(crate) fn letters_left_rows(data_dir: &Path, now_ms: u64) -> Vec<String> {
    use raven_core::letter_deposits::{load, DepositKind};
    let Ok(book) = load(data_dir, now_ms) else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    for letter in &book.letters {
        if letter.withdraw || letter.kind != DepositKind::Letter {
            continue;
        }
        let who = non_empty_or(
            contact_label(data_dir, &hex::encode(letter.peer)),
            "a contact",
        );
        for custodian in &letter.held_by {
            let custodian =
                non_empty_or(contact_label(data_dir, &hex::encode(custodian)), "a friend");
            rows.push(letter_with_text(
                &custodian,
                &who,
                &until_text(letter.expires_at_ms, now_ms),
            ));
        }
    }
    rows
}

/// "With {custodian} for {who} · until {until}" (the cutoff addendum's
/// letter state).
pub(crate) fn letter_with_text(custodian: &str, who: &str, until: &str) -> String {
    format!("With {custodian} for {who} · until {until}")
}

/// What the friends holding a letter learn (the cutoff addendum's consent
/// and details text, "{custodian} can't read it, but knows you wrote to
/// {who}, and when; the letter is signed by you.").
pub(crate) fn letter_knows_text(custodians: &[String], who: &str) -> String {
    let (names, knows) = match custodians {
        [one] => (one.clone(), "knows"),
        many => (many.join(" and "), "each knows"),
    };
    format!(
        "{names} can't read it, but {knows} you wrote to {who}, and when; the letter is signed by \
         you."
    )
}

/// `raven outbox status` for a message in a sealed letter (P5.16): who
/// holds the letter and until when, then what they learn. Empty when no
/// friend holds a letter with it (or the book cannot be read).
fn letter_detail_rows(data_dir: &Path, peer_hex: &str, mid: &[u8; 16], now_ms: u64) -> Vec<String> {
    use raven_core::letter_deposits::{load, DepositKind};
    let (Ok(book), Ok(peer)) = (load(data_dir, now_ms), parse_pub_hex(peer_hex)) else {
        return Vec::new();
    };
    let who = non_empty_or(contact_label(data_dir, peer_hex), "your contact");
    let mut rows = Vec::new();
    let mut names = Vec::new();
    for letter in book.carrying(&peer, mid) {
        if letter.withdraw || letter.kind != DepositKind::Letter {
            continue;
        }
        for custodian in &letter.held_by {
            let name = non_empty_or(contact_label(data_dir, &hex::encode(custodian)), "a friend");
            rows.push(format!(
                "  letter      {}",
                letter_with_text(&name, &who, &until_text(letter.expires_at_ms, now_ms))
            ));
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    if !names.is_empty() {
        rows.push(format!("  letter      {}", letter_knows_text(&names, &who)));
    }
    rows
}

/// How a failed p2p dial is explained ([`p2p_reason`]).
enum Reach {
    /// raven-node's reason, and the names its sentences use.
    P2p(Diag, ReachNames),
    /// The LAN route failed too and its own result says more than the p2p
    /// reason (its cause and its part of the joined multi-route text, the
    /// LAN addresses tried named in it); `no_route`: this computer has no
    /// route to the internet.
    Lan(Cause, String, bool),
}

/// The reason raven-node gave for a failed p2p dial, when `raw` carries
/// one and the dial reached nobody. A refusal, a wrong key or any other
/// cause never gets one. A failed LAN route wins with no route to the
/// internet (it is the only route that could have worked), and over a p2p
/// dial whose own direct addresses only did not answer (E1: after two LAN
/// lines a send said the friend "did not answer at the internet address"
/// it gave you; the LAN addresses are what it showed it tried, and their
/// result says as much).
fn p2p_reason(cause: Cause, ctx: &SendCtx, raw: &str) -> Option<Reach> {
    if !matches!(
        cause,
        Cause::NotReachable | Cause::NotListening | Cause::ClosedEarly | Cause::NameNotFound
    ) {
        return None;
    }
    let d = Diag::find(raw)?;
    if let Some((lan, part)) = lan_route_failure(raw) {
        // E2 r9 #4: never NAT or relay advice when the friend's saved
        // address is on this computer's own network: the LAN's answer there
        // (its computer is there but Raven isn't answering, or nobody
        // answered on this network) says more.
        if matches!(d.why, Why::NoRoute | Why::DirectFailed) || lan_part_on_our_network(&part) {
            return Some(Reach::Lan(lan, part, d.why == Why::NoRoute));
        }
    }
    let names = ReachNames::load(ctx, &d);
    Some(Reach::P2p(d, names))
}

/// Whether a LAN part of a failed send (`lan_dial <ip:port>: ...`) dialled
/// an address on one of this computer's networks now.
fn lan_part_on_our_network(part: &str) -> bool {
    lan_part_ips(part).into_iter().any(on_our_network)
}

#[cfg(test)]
thread_local! {
    /// Tests: what [`on_our_network`] answers (None: ask the OS).
    static ON_OUR_NETWORK: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// `ip` is on one of this computer's networks now.
pub(crate) fn on_our_network(ip: std::net::IpAddr) -> bool {
    #[cfg(test)]
    if let Some(on) = ON_OUR_NETWORK.with(std::cell::Cell::get) {
        return on;
    }
    raven_core::netifs::on_our_networks(ip) == Some(true)
}

/// The IP addresses a LAN part dialled (`ip:port`, `[v6]:port`); a name is
/// none.
fn lan_part_ips(part: &str) -> Vec<std::net::IpAddr> {
    route_parts(part, "lan_dial ")
        .into_iter()
        .filter_map(|p| {
            let dial = p["lan_dial ".len()..].split(": ").next()?.trim();
            dial.parse::<std::net::SocketAddr>().ok().map(|a| a.ip())
        })
        .collect()
}

/// The ways a failed send tried, in plain words and a fixed order, from its
/// joined route failures (`<route> <address>: ...; ...`): "on the local
/// network", "directly", "over p2p", "over Bluetooth", "over Tor". Empty for
/// a one-route failure (its error names no route).
fn ways_tried(raw: &str) -> Vec<&'static str> {
    [
        ("lan_dial ", "on the local network"),
        ("internet_dial ", "directly"),
        ("p2p_dial ", "over p2p"),
        ("nearby_dial ", "over Bluetooth"),
        ("onion_dial ", "over Tor"),
    ]
    .into_iter()
    .filter(|(route, _)| !route_parts(raw, route).is_empty())
    .map(|(_, words)| words)
    .collect()
}

/// A send whose one way was Tor, which did not answer: within the send's
/// Tor wait, or with raven-node's outbox still trying it
/// ([`super::pair_init_lab::TOR_BUSY`]). Never LAN advice for it.
fn tor_only_no_answer(raw: &str) -> bool {
    let ways = ways_tried(raw);
    let tor_alone = ways == ["over Tor"] || (ways.is_empty() && raw.contains("ONION_UNREACHABLE"));
    tor_alone && (raw.contains("ONION_UNREACHABLE") || raw.contains("the probe was cut short"))
}

/// "a", "a and b", "a, b and c".
fn and_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// "a", "a or b", "a, b or c".
fn or_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} or {last}", rest.join(", ")),
    }
}

/// E2 r9 #5: the cause of a send that tried several ways, one of them Tor,
/// and reached the friend on none: every way tried, no address ("Bob
/// couldn't be reached right now: no answer on the local network, over p2p
/// or over Tor"), and that Tor is not ready here when it was not. `None`
/// for a send with one way, or without Tor (its LAN and p2p reasons say
/// more), and when the friend's Raven refused on this computer's network
/// (#4: its computer is there, Raven is not receiving). A LAN address here
/// that only did not answer is one of the ways tried (E2 r40: the friend
/// had moved, and the words named that LAN address as the reason).
fn every_way_failed(ctx: &SendCtx, raw: &str) -> Option<String> {
    let ways = ways_tried(raw);
    if ways.len() < 2 || !ways.contains(&"over Tor") {
        return None;
    }
    if lan_route_failure(raw)
        .is_some_and(|(lan, part)| lan == Cause::NotListening && lan_part_on_our_network(&part))
    {
        return None;
    }
    let tor_here = if raw.contains("ONION_NOT_READY") {
        "; Tor isn't ready on this computer yet"
    } else {
        ""
    };
    Some(format!(
        "{} couldn't be reached right now: no answer {}{tor_here}",
        ctx.who(),
        or_list(&ways)
    ))
}

/// The LAN route's part of a joined multi-route failure
/// (`lan_dial <address>: …; p2p_dial …`) and its cause, when it failed as
/// a dial does (nobody answered, nobody listened, it hung up). Several LAN
/// routes (a beacon's find and the saved address) are one part that names
/// each address tried ([`lan_dials_tried`]).
fn lan_route_failure(raw: &str) -> Option<(Cause, String)> {
    let parts = route_parts(raw, "lan_dial ");
    let first = *parts.first()?;
    if first.contains(reach_diag::REACH_TAG) {
        return None;
    }
    let cause = classify_cause(first);
    if !matches!(
        cause,
        Cause::NotReachable | Cause::NotListening | Cause::ClosedEarly | Cause::NameNotFound
    ) {
        return None;
    }
    let others: Vec<&str> = parts[1..]
        .iter()
        .copied()
        .filter(|p| classify_cause(p) == cause && !p.contains(reach_diag::REACH_TAG))
        .collect();
    Some((
        cause,
        [first]
            .into_iter()
            .chain(others)
            .collect::<Vec<_>>()
            .join("; "),
    ))
}

/// The parts of a joined multi-route failure (`<route> <address>: …`, `; `
/// between them) whose route is `route` (`"lan_dial "`), in order.
fn route_parts<'a>(raw: &'a str, route: &str) -> Vec<&'a str> {
    const ROUTES: [&str; 5] = [
        "lan_dial ",
        "internet_dial ",
        "p2p_dial ",
        "nearby_dial ",
        "onion_dial ",
    ];
    let mut starts: Vec<usize> = Vec::new();
    for r in ROUTES {
        if raw.starts_with(r) {
            starts.push(0);
        }
        starts.extend(raw.match_indices(&format!("; {r}")).map(|(at, _)| at + 2));
    }
    starts.sort_unstable();
    starts
        .iter()
        .enumerate()
        .filter(|(_, &at)| raw[at..].starts_with(route))
        .map(|(i, &at)| {
            let end = starts.get(i + 1).map_or(raw.len(), |next| next - 2);
            &raw[at..end]
        })
        .collect()
}

/// The addresses the LAN parts in `part` ([`lan_route_failure`]) dialled,
/// each once, in order: "A" or "A or B".
fn lan_dials_tried(part: &str) -> String {
    let mut dials: Vec<&str> = Vec::new();
    for p in route_parts(part, "lan_dial ") {
        let dial = p["lan_dial ".len()..]
            .split(": ")
            .next()
            .unwrap_or_default();
        if !dial.is_empty() && !dials.contains(&dial) {
            dials.push(dial);
        }
    }
    dials.join(" or ")
}

/// This computer can be reached, as the reason block says (so the contact
/// could open a connection to it).
fn me_reachable(d: &Diag) -> bool {
    use raven_core::reach::ReachClass;
    matches!(
        d.me,
        Some(ReachClass::Public | ReachClass::Mapped | ReachClass::Relayed)
    )
}

/// What happened, for a p2p reason, without a closing period (as
/// [`cause_sentence`]).
fn p2p_cause_sentence(d: &Diag, ctx: &SendCtx, n: &ReachNames) -> String {
    let (who, whose) = (ctx.who(), ctx.whose());
    let age = super::p2p_cli::age_text;
    let heard = d
        .heard_s
        .map(|s| format!("; RAVEN last heard from {who} {} ago", age(s)))
        .unwrap_or_default();
    let stale = if d.stale {
        format!(
            "; the routes {who} last sent you are out of date, so {who} may also have moved to \
             another relay"
        )
    } else {
        String::new()
    };
    let card = if d.from_card {
        format!("; this comes from {whose} card, so if {who} has a relay now, ask for a new card")
    } else {
        String::new()
    };
    let sentence = match d.why {
        Why::ContactOffline => format!(
            "{who} is offline: {whose} relay answered, but {whose} computer is not connected to \
             it (switched off, asleep, without internet, or RAVEN is not running there)\
             {heard}{stale}"
        ),
        Why::RelayAsleep if d.relay.is_some() => format!(
            "{}, which you and {who} both use, is not answering (asleep, switched off or \
             offline), so there is no path to {who} right now",
            n.relay
        ),
        Why::RelayAsleep => format!(
            "{whose} relay is not answering (asleep, switched off or offline), so there is no \
             path to {who} right now{stale}"
        ),
        Why::RelayRefused => format!(
            "{whose} relay turned you away: a friend's relay carries messages only between \
             people its owner has verified, and you are not one of them"
        ),
        Why::RelayOff => format!(
            "{whose} relay no longer relays (its owner turned relaying off), and {who} has not \
             told you about a new one yet"
        ),
        Why::RelayBusy => format!(
            "{whose} relay turned the connection away (it is full right now, or it does not \
             relay for you)"
        ),
        Why::NotAdmitted => format!(
            "{whose} RAVEN closed the internet connection at once: {who} may not have your \
             current card (your p2p address) yet"
        ),
        Why::BothNat => format!(
            "you and {who} are both behind NAT (as on most home routers, hotspots and mobile \
             data): neither computer can be reached directly from the internet, and {who} uses \
             no relay{card}"
        ),
        Why::NoRelay if me_reachable(d) => format!(
            "{who} cannot be reached directly from the internet and uses no relay, so only a \
             connection {who} opens can carry it (you can be reached, so {who} can open \
             one){card}"
        ),
        Why::NoRelay => {
            format!("{who} cannot be reached directly from the internet and uses no relay{card}")
        }
        Why::DirectFailed => format!(
            "{who} did not answer at the internet address {who} gave you: {whose} computer may \
             be off or asleep, or on another network{stale}"
        ),
        Why::NoRoute => format!(
            "this computer has no route to the internet right now, so RAVEN can reach {who} \
             only on the same network as you (the same Wi-Fi, a hotspot or a cable){heard}"
        ),
        Why::LanOff => format!(
            "you turned the local network off (`{LAN_ON_CMD}` turns it on), so RAVEN does not \
             look for {who} here, and it knows no other way to reach {who}{heard}"
        ),
        Why::LanNoAnswer => format!(
            "{LAN_NO_ANSWER_SHORT}: RAVEN looked for {who} here and got no answer, and it knows \
             no other way to reach {who}{heard}"
        ),
    };
    match d.asof_s {
        Some(s) => format!(
            "{who} did not answer in time; RAVEN's check {} ago found that {sentence}",
            age(s)
        ),
        None => sentence,
    }
}

/// What `lan_no_answer` says (Phase 3 diagnosis, P3.C6 words): the beacon
/// asked, and nobody it looked for answered on this network. Only what this
/// computer saw, never a claim about the internet.
pub(super) const LAN_NO_ANSWER_SHORT: &str = "none of your friends answered on this network";

/// What to try about `lan_no_answer` (P3.C6): a Wi-Fi that keeps devices
/// apart is the usual cause on a shared network.
pub(super) const LAN_NO_ANSWER_ADVICE: &str = "If you are on the same Wi-Fi, it may keep devices \
     apart (common in hotels and guest Wi-Fi): make a hotspot instead (docs/OFFLINE_GUIDE.md §3).";

/// `lan_no_answer` in full, as a status row says it (P3.C6):
/// [`LAN_NO_ANSWER_SHORT`] as a sentence, then [`LAN_NO_ANSWER_ADVICE`].
pub(super) const LAN_NO_ANSWER_TEXT: &str = "None of your friends answered on this network. If \
     you are on the same Wi-Fi, it may keep devices apart (common in hotels and guest Wi-Fi): make \
     a hotspot instead (docs/OFFLINE_GUIDE.md §3).";

/// `lan_off` in full, as a status row says it (P3.C6): the user's own
/// choice, how to undo it, and that nothing is lost.
pub(super) const LAN_OFF_TEXT: &str =
    "You turned the local network off (`raven lan on` turns it on). Your messages wait here.";

/// `raven status`'s first line on no network at all (P3.C6: `netifs` has
/// nothing a friend could share). The terminal app's network screen says
/// the same.
pub(crate) const NOT_ON_ANY_NETWORK_TEXT: &str = "This computer isn't on any network. To reach a \
     friend nearby, join the same Wi-Fi, make a hotspot, or connect a cable. Your messages wait \
     here.";

/// `raven status`'s first line while the local network is the only carrier
/// raven-node runs (P3.C6): the contacts it saw here in the last ten
/// minutes (a count) and what waits ([`waiting_messages_line`], or none).
/// Local facts only, never a claim about the internet.
pub(crate) fn lan_only_line(friends_here: u32, waiting: Option<&str>) -> String {
    format!(
        "Raven works on this network without the internet. Friends seen here in the last 10 \
         min: {friends_here}. {}",
        waiting.unwrap_or("Waiting messages: 0.")
    )
}

/// The running raven-node's Tor carrier, for `raven status`'s first line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TorNow {
    /// Off, not built, or no word of it (an older raven-node).
    Off,
    Starting,
    Ready,
    /// On, but it cannot connect on this network.
    NotWorking,
}

/// `raven status`'s first line while raven-node runs the local network and
/// Tor and no other carrier (field test E3): how friends are reached now,
/// the contacts it saw here in the last ten minutes (a count) and what
/// waits ([`waiting_messages_line`], or none). With Tor off it is
/// [`lan_only_line`].
pub(crate) fn lan_and_tor_line(friends_here: u32, tor: TorNow, waiting: Option<&str>) -> String {
    let how = match tor {
        TorNow::Off => return lan_only_line(friends_here, waiting),
        TorNow::Ready => {
            "Raven reaches friends on this network directly, and friends elsewhere over Tor."
        }
        TorNow::Starting => {
            "Raven reaches friends on this network directly; Tor is starting, for friends \
             elsewhere."
        }
        TorNow::NotWorking => {
            "Raven reaches friends on this network directly; Tor can't connect on this network \
             now, so friends elsewhere can't be reached."
        }
    };
    format!(
        "{how} Friends seen here in the last 10 min: {friends_here}. {}",
        waiting.unwrap_or("Waiting messages: 0.")
    )
}

/// `raven status`'s row for a contact whose saved address answered with
/// another key in the last ten minutes (M0, P3.C6).
pub(crate) fn pin_blocked_text(who: &str) -> String {
    format!("Something else answered at {who}'s old address; RAVEN didn't introduce you.")
}

/// What to do about a p2p reason, in `mode`; `None` for [`Fix::Generic`]
/// (the circle is not known: today's advice stays).
fn p2p_next_step(d: &Diag, ctx: &SendCtx, n: &ReachNames, mode: StepMode) -> Option<String> {
    let (who, whose) = (ctx.who(), ctx.whose());
    let queued = mode == StepMode::Queued;
    // The ending most fixes take: send again, or RAVEN keeps trying.
    let then = if queued {
        " RAVEN keeps trying meanwhile."
    } else {
        " Then send again."
    };
    let offer = OFFER_CMD;
    let port = n.port;
    let step = match n.fix {
        Fix::Generic => return None,
        Fix::LocalOnly => match mode {
            StepMode::FirstContact | StepMode::Later => {
                format!("Send it again when you and {who} are on the same network.")
            }
            StepMode::Queued => format!(
                "Nothing to do: it goes out when you and {who} are on the same network, or when \
                 this computer can reach the internet again."
            ),
        },
        Fix::WaitUntilOnline => match mode {
            StepMode::FirstContact => send_again_when_online(&who),
            StepMode::Later => format!("Wait until {who} is back online, then send again."),
            StepMode::Queued => {
                format!("Nothing to do on your side: it goes out when {who} is back online.")
            }
        },
        Fix::LanOn => match mode {
            StepMode::FirstContact | StepMode::Later => {
                format!("Turn the local network back on (`{LAN_ON_CMD}`), then send again.")
            }
            // The why row says how to turn it on (LAN_OFF_TEXT).
            StepMode::Queued => "Your messages wait here.".into(),
        },
        // A first message has no session a friend could hold it in.
        Fix::UseMailbox | Fix::AskFriendToHoldMail if mode == StepMode::FirstContact => {
            send_again_when_online(&who)
        }
        Fix::UseMailbox => format!(
            "Turn on friend mailboxes (`{MAILBOX_CMD}`): a friend you both verified can then \
             hold your messages while {who} is offline (that friend learns that you wrote to \
             {who}, not what).{}",
            if queued {
                format!(" Otherwise it goes out when {who} is back online.")
            } else {
                format!(" Or wait until {who} is back online, then send again.")
            }
        ),
        Fix::AskFriendToHoldMail => format!(
            "No friend holds mail for {who} yet: ask a friend you both verified, whose computer \
             is always on, to run `{HOLD_MAIL_CMD}`.{}",
            if queued {
                format!(" Otherwise it goes out when {who} is back online.")
            } else {
                format!(" Or wait until {who} is back online, then send again.")
            }
        ),
        Fix::RetryLater if queued => format!(
            "RAVEN tries again by itself. If it keeps happening, {whose} relay may not relay for \
             you: ask {who} whose relay it is."
        ),
        Fix::RetryLater => format!(
            "Try again in a few minutes. If it keeps happening, {whose} relay may not relay for \
             you: ask {who} whose relay it is."
        ),
        Fix::TheyNeedNewRelay => format!(
            "{who} gets a new relay by itself once a friend of {whose} offers relaying; ask {who} \
             to look at `raven status`{}",
            if queued {
                ". RAVEN keeps trying meanwhile."
            } else {
                ", then send again."
            }
        ),
        Fix::ResendCard => format!(
            "Make sure {who} verified you (`raven contact verify` on both computers). {who}'s \
             node learns this computer's network ID once you are connected over Tor or the local \
             network{}",
            if queued {
                "; RAVEN keeps trying meanwhile."
            } else {
                ", then send again."
            }
        ),
        Fix::WakeRelay if d.relay.is_none() => format!(
            "Ask {who} to check {whose} relay: the computer it runs on must be on and awake \
             (`raven relay status` there shows whether it runs).{then}"
        ),
        Fix::WakeRelay if !n.relay_owner.is_empty() => format!(
            "Ask {} to wake that computer (`raven relay status` on it shows whether the relay \
             runs); until it answers, contacts outside this network cannot reach you \
             either.{then}",
            n.relay_owner
        ),
        Fix::WakeRelay => format!(
            "Check that computer: it must be on, awake and running the relay (`raven relay \
             status` on it); until it answers, contacts outside this network cannot reach you \
             either.{then}"
        ),
        Fix::AskRelayOwner => format!(
            "Ask {who} whose relay it is and become that person's verified contact (`raven \
             whoami --card` on both computers), or ask a friend you share with {who} to offer \
             relaying (`{offer}` on their computer).{then}"
        ),
        Fix::TheyWriteFirst => match mode {
            StepMode::FirstContact if me_reachable(d) => {
                format!("Ask {who} to send you the first message instead: {who} can reach you.")
            }
            StepMode::FirstContact => format!(
                "Ask {who} to get a relay (a friend of {whose} who offers relaying), then send \
                 again."
            ),
            StepMode::Later => format!("Wait until {who} sends you a message, then send again."),
            StepMode::Queued => format!(
                "It goes out when {who} next sends you a message: RAVEN answers over the \
                 connection {who} opens. {who} can also get a relay: a friend of {whose} who \
                 offers relaying."
            ),
        },
        Fix::OfferRelaying => format!(
            "This computer can be reached from the internet: offer relaying to your verified \
             contacts (`{offer}`). {who} then keeps a connection to it, and RAVEN delivers over \
             that.{}",
            if queued {
                format!(" Otherwise it goes out when {who} next sends you a message.")
            } else {
                " Then send again.".into()
            }
        ),
        Fix::AskFriend(_) => format!(
            "{name} can be reached from the internet: ask {name} to offer relaying (`{offer}` on \
             {name}'s computer); RAVEN then uses it for you and {who} by itself, as long as you \
             are both {name}'s verified contacts. Or run {KIT_REF} on a Raspberry Pi or a small \
             VPS, or forward port {port} (TCP and UDP) on your router to this computer.{}",
            if queued { "" } else { " Then send again." },
            name = n.friend
        ),
        Fix::NobodyReachable => format!(
            "Nobody in your circle can be reached from the internet, so nothing can carry \
             messages between two computers behind NAT. Any one of these fixes it: ask a friend \
             whose computer has a public IP or a forwarded port to offer relaying (`{offer}` on \
             their computer); run {KIT_REF} on a Raspberry Pi with a forwarded port, or on a \
             small VPS; or forward port {port} (TCP and UDP) on your router to this computer \
             (`raven node upnp on` does it if your router supports UPnP), after which RAVEN asks \
             once whether this computer may relay for your contacts.{}",
            if queued { "" } else { " Then send again." }
        ),
    };
    // Nobody answered here: what to try on this network first (P3.C6).
    Some(if d.why == Why::LanNoAnswer {
        format!("{LAN_NO_ANSWER_ADVICE} {step}")
    } else {
        step
    })
}

/// `raven outbox list`'s legend for a p2p reason (`last: NOT_REACHABLE
/// (…)`).
fn reach_legend(d: &Diag) -> &'static str {
    match d.why {
        Why::ContactOffline => "offline: not connected to their relay",
        Why::RelayAsleep if d.relay.is_some() => "your shared relay is not answering",
        Why::RelayAsleep => "their relay is not answering",
        Why::RelayRefused => "their relay turned you away",
        Why::RelayOff => "their relay stopped relaying",
        Why::RelayBusy => "their relay is full",
        Why::NotAdmitted => "they need your current card",
        Why::BothNat => "both behind NAT, no relay",
        Why::NoRelay => "they use no relay",
        Why::DirectFailed => "no answer at their internet address",
        Why::NoRoute => "no route to the internet from this computer",
        Why::LanOff => "you turned the local network off: raven lan on",
        Why::LanNoAnswer => LAN_NO_ANSWER_SHORT,
    }
}

/// `raven outbox status`'s `why` and `what to do` rows for an item whose
/// last p2p try left a reason (`why`, the reason block); none without one.
fn outbox_why_rows(ctx: &SendCtx, why: &str) -> Vec<String> {
    let Some(d) = Diag::find(why) else {
        return Vec::new();
    };
    let names = ReachNames::load(ctx, &d);
    outbox_why_rows_with(ctx, &d, &names)
}

fn outbox_why_rows_with(ctx: &SendCtx, d: &Diag, names: &ReachNames) -> Vec<String> {
    let mut rows = vec![format!(
        "  why         {}.",
        p2p_cause_sentence(d, ctx, names)
    )];
    if let Some(step) = p2p_next_step(d, ctx, names, StepMode::Queued) {
        rows.push(format!("  what to do  {step}"));
    }
    rows
}

/// `"the first 30 characters…"` of a message for outcome lines, or nothing.
/// A group copy waiting for the same friend reads as the group message's
/// text with a `group:` mark, and a group update as `(group update)`, never
/// as its frame.
pub(crate) fn quoted_preview(text: &str) -> String {
    if raven_core::group::is_group_text(text.as_bytes()) {
        return match raven_core::group::parse_frame(text.as_bytes()) {
            Some(raven_core::group::GroupFrame::Msg(m)) => {
                format!("group: {}", quoted_preview(&m.body))
            }
            _ => "(group update)".into(),
        };
    }
    let line = sanitize_terminal_line(text.trim());
    if line.is_empty() {
        return String::new();
    }
    let mut shown: String = line.chars().take(30).collect();
    if line.chars().count() > 30 {
        shown.push('…');
    }
    format!("\"{shown}\"")
}

/// ` "preview"` (with a leading space), or nothing.
fn spaced(preview: &str) -> String {
    if preview.is_empty() {
        String::new()
    } else {
        format!(" {preview}")
    }
}

fn join_sentences(parts: &[String]) -> String {
    parts
        .iter()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Start of the "queued locally" outcome (see [`queued_text`]).
pub(crate) const QUEUED_PREFIX: &str = "not delivered yet";
/// Start of the "sent but unconfirmed" outcome (see [`unconfirmed_text`]).
pub(crate) const UNCONFIRMED_PREFIX: &str = "sent, delivery unconfirmed";

/// True for text that already is a finished outcome line.
fn is_outcome_text(text: &str) -> bool {
    text.starts_with("NOT SENT")
        || text.starts_with(QUEUED_PREFIX)
        || text.starts_with(UNCONFIRMED_PREFIX)
        || text.starts_with("send refused: ")
}

/// NOT SENT: the message was refused before anything of it was queued.
/// `first_contact`: no session with the peer exists yet, so it could not wait
/// for the peer to come online either.
fn not_sent_for(cause: Cause, ctx: &SendCtx, raw: &str, first_contact: bool) -> String {
    let who = ctx.who();
    // A first message to a contact that is not merely offline needs a path
    // first, not only the contact online.
    let no_path = first_contact
        && matches!(
            p2p_reason(cause, ctx, raw),
            Some(Reach::P2p(d, _)) if d.why != Why::ContactOffline
        );
    let reach_failed = first_contact
        && matches!(
            cause,
            Cause::NotListening | Cause::NotReachable | Cause::ClosedEarly | Cause::NameNotFound
        );
    // E1: a first message says the same rule wherever it comes up
    // ([`first_message_rule`]); when the contact's computer was not there,
    // when to send it again.
    let mut again = None;
    let nothing_queued = if no_path {
        first_message_not_kept(
            &who,
            Some(&format!("there is no working path to {who} now")),
        )
    } else if reach_failed {
        match ctx.session_ended_at() {
            // Not a first message: the secure connection ran out (cutoff
            // pack CP.6), and only a meeting sets up a new one.
            Some(at) => session_ended_sentence(ctx, at, now_ms()),
            None => {
                if matches!(cause, Cause::NotReachable | Cause::NameNotFound) {
                    again = Some(send_again_when_online(&who));
                }
                first_message_not_kept(&who, None)
            }
        }
    } else {
        "Nothing was queued.".into()
    };
    // Nothing waits here, so the noise pin step (M0, "it goes out when ...")
    // would not hold: the same moments, as when to send it again.
    let step = if cause == Cause::WrongIdentity && !first_contact && is_noise_pin_mismatch(raw) {
        format!(
            "Send it again once {who} has connected to you, after you join another network, or \
             after you save {who}'s new address. {}",
            pin_reinstall_step(&who, &ctx.sel())
        )
    } else if let Some(part) = name_not_found_part(cause, ctx, raw) {
        // Nothing waits here either: when to send it again (said already
        // for a first message).
        let fix = fix_address_cmd(failed_carrier(&part), &ctx.sel());
        if again.is_some() {
            new_address_step(ctx, &fix)
        } else {
            name_not_found_step(ctx, &fix, false)
        }
    } else {
        next_step(cause, ctx, first_contact, raw)
    };
    // The step's own closing words, when they are the ones just said.
    let step = match &again {
        Some(again) => step
            .strip_suffix(again.as_str())
            .map_or(step.clone(), |rest| rest.trim_end().to_owned()),
        None => step,
    };
    join_sentences(&[
        format!(
            "NOT SENT: {}.",
            cause_sentence(cause, ctx, raw, first_contact)
        ),
        nothing_queued,
        again.unwrap_or_default(),
        step,
        technical_note(raw),
    ])
}

/// What RAVEN says wherever a first message comes up (E1: the send result,
/// `raven contact list` and the terminal app said "must be online", "needs a
/// working path" and "given up" for the same thing): RAVEN has never
/// connected with `who`, so nothing can keep a message for them, and one goes
/// only while both computers are online. Its words keep "a first message
/// needs", which the apps' engines read in a NOT SENT.
pub(crate) fn first_message_rule(who: &str) -> String {
    format!("A {}.", first_message_words(who))
}

fn first_message_words(who: &str) -> String {
    format!(
        "first message needs you and {who} both online (RAVEN hasn't connected with {who} \
         yet)"
    )
}

/// NOT SENT's middle sentence for a first message: it was not kept, by
/// [`first_message_rule`]; `and` adds what else stood in the way.
fn first_message_not_kept(who: &str, and: Option<&str>) -> String {
    let words = first_message_words(who);
    match and {
        Some(and) => format!("It was not kept: a {words}, and {and}."),
        None => format!("It was not kept: a {words}."),
    }
}

/// When to send a first message again that found the contact's computer
/// away.
pub(crate) fn send_again_when_online(who: &str) -> String {
    format!("Send it again when {who} is online.")
}

/// NOT SENT's middle sentence once the secure connection with the contact
/// ended at `at_ms` (a session this node starts lasts a day from its
/// PairInit, `LAN_SESSION_LIFETIME_MS`, not from the last contact).
fn session_ended_sentence(ctx: &SendCtx, at_ms: u64, now_ms: u64) -> String {
    format!(
        "Nothing was queued: RAVEN's secure connection with {who} ended {when} (each one lasts a \
         day from when it is set up), and a new one needs you both on the same network at the \
         same time. Send it when you meet.",
        who = ctx.who(),
        when = ended_text(at_ms, now_ms)
    )
}

/// [`not_sent_for`] with the cause read from the raw text.
pub(crate) fn not_sent_text(ctx: &SendCtx, raw: &str, first_contact: bool) -> String {
    not_sent_for(classify_cause(raw), ctx, raw, first_contact)
}

/// How long a staged message can still go out, and who retries it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RetryNote {
    /// Unix ms until when it can still go out: when its sealed envelope
    /// expires (min(session end, now + 24 h)), or, with the long message
    /// horizon live (Phase 5a), its message's deadline (written + 7 d), as
    /// raven-node parks it past its envelope and seals it again.
    pub(crate) expires_at_ms: u64,
    /// When its sealed envelope expires (min(session end, now + 24 h), a
    /// letter's later): what a friend holding a sealed copy keeps it until
    /// (E2 r9 #7); 0 when not known.
    pub(crate) copy_expires_at_ms: u64,
    /// raven-node's background outbox took it (its `OutboxKick` was accepted):
    /// it keeps retrying without another send. False with a service that has
    /// no outbox (an older raven-node): only the next send retries it.
    pub(crate) background: bool,
    /// The friends (labels) raven-node may leave a sealed copy with while
    /// the contact stays unreachable (friend custody,
    /// `raven_core::custody_client::deposit_custodians`, or carry choice's
    /// pick in its order); empty: none.
    pub(crate) custodians: Vec<String>,
    /// Carry choice (Phase 6a P6.16): why the first of them goes first,
    /// when raven-node learned it ([`carry_first_words`]); `None`: today's
    /// choice.
    pub(crate) carry_first: Option<String>,
}

/// The phrase the chat looks for to show "raven-node keeps trying".
pub(crate) const BACKGROUND_RETRY: &str = "raven-node keeps trying";

impl RetryNote {
    /// `tomorrow 09:10 (in about 19 h)` on this computer's clock, or `in
    /// about 19 h` when its offset cannot be read ([`until_text`]).
    fn until(&self) -> String {
        until_text(self.expires_at_ms, now_ms())
    }

    /// When a friend's sealed copy expires ([`Self::copy_expires_at_ms`]),
    /// in the same words as [`Self::until`]; `None` when not known.
    fn copy_until(&self) -> Option<String> {
        (self.copy_expires_at_ms > 0).then(|| until_text(self.copy_expires_at_ms, now_ms()))
    }

    /// Who sends it again: the service, or the user's next send.
    fn retried_by(&self, who: &str) -> String {
        if self.background {
            "raven-node, in the background,".into()
        } else {
            format!("your next send to {who}")
        }
    }
}

/// When `expires_at_ms` runs out, seen at `now_ms`, on this computer's clock
/// (cutoff pack CP.6): `today 14:05 (in about 3 h)`, `tomorrow 09:10 (in
/// about 19 h)`, `Tue 14:05 (in about 46 h)`, from 6 days on `Thu 23 Oct
/// 14:05`. Without the local offset only `in about 22 h`: never a time on
/// another clock ("UTC" invited a wrong meeting time). Plain ASCII. The OS is
/// asked on the caller's thread; tests use [`until_text_with_offset`].
pub(crate) fn until_text(expires_at_ms: u64, now_ms: u64) -> String {
    deadline_words(&raven_core::local_time::deadline(expires_at_ms, now_ms))
}

/// [`until_text`] with the offset given (seconds east of UTC; None: unknown).
#[cfg(test)]
pub(crate) fn until_text_with_offset(expires_at_ms: u64, now_ms: u64, off: Option<i32>) -> String {
    deadline_words(&raven_core::local_time::deadline_with_offset(
        expires_at_ms,
        now_ms,
        off,
    ))
}

/// A deadline on this computer's clock, with its zone (E2 r38: "expires Thu
/// 5 Nov 11:03" named no zone while the arrival times did): `today 14:05
/// (UTC+1, in about 3 h)`, `Thu 5 Nov 11:03 (UTC+1)`.
fn deadline_words(d: &raven_core::local_time::Deadline) -> String {
    if !d.local {
        return d.rel.clone();
    }
    let zone = zone_label(d.utc_offset_s).unwrap_or_else(|| "local time".into());
    match d.days_ahead {
        0 => format!("today {} ({zone}, {})", d.hh_mm, d.rel),
        1 => format!("tomorrow {} ({zone}, {})", d.hh_mm, d.rel),
        2..=5 => format!("{} {} ({zone}, {})", d.weekday, d.hh_mm, d.rel),
        _ => format!("{} {} {} {} ({zone})", d.weekday, d.day, d.month, d.hh_mm),
    }
}

/// When something ended, seen at `now_ms`, on this computer's clock: `today
/// at 09:10`, `yesterday at 14:05`, `on Tue at 14:05`, `on Thu 23 Oct at
/// 14:05`; without the local offset `about 25 h ago`. Plain ASCII.
pub(crate) fn ended_text(at_ms: u64, now_ms: u64) -> String {
    ended_words(
        &raven_core::local_time::deadline(at_ms, now_ms),
        at_ms,
        now_ms,
    )
}

/// The zone of this computer's clock at `at_ms`, as a label: `UTC`,
/// `UTC+1`, `UTC-5`, `UTC+5:30`; `None` when the OS does not say (a time is
/// then shown as "about 3 h ago", which needs none).
pub(crate) fn zone_label(off_s: Option<i32>) -> Option<String> {
    let off = off_s?;
    if off == 0 {
        return Some("UTC".into());
    }
    let sign = if off < 0 { '-' } else { '+' };
    let (h, m) = (off.unsigned_abs() / 3600, off.unsigned_abs() % 3600 / 60);
    Some(if m == 0 {
        format!("UTC{sign}{h}")
    } else {
        format!("UTC{sign}{h}:{m:02}")
    })
}

/// [`ended_text`]: every time names its zone now (E2 r9 #11, r38).
pub(crate) fn ended_text_zoned(at_ms: u64, now_ms: u64) -> String {
    ended_text(at_ms, now_ms)
}

/// [`ended_text`] with the offset given (seconds east of UTC).
pub(crate) fn ended_zoned_with_offset(at_ms: u64, now_ms: u64, off: Option<i32>) -> String {
    ended_words(
        &raven_core::local_time::deadline_with_offset(at_ms, now_ms, off),
        at_ms,
        now_ms,
    )
}

#[cfg(test)]
fn ended_text_with_offset(at_ms: u64, now_ms: u64, off: Option<i32>) -> String {
    ended_words(
        &raven_core::local_time::deadline_with_offset(at_ms, now_ms, off),
        at_ms,
        now_ms,
    )
}

/// The day something is planned for, seen at `now_ms`, on this computer's
/// clock: `on Sat 25 Oct`; without the local offset `in about 7 days`
/// (privacy pack PP.9: the first retention deletion). Plain ASCII.
pub(crate) fn on_day_text(at_ms: u64, now_ms: u64) -> String {
    on_day_words(&raven_core::local_time::deadline(at_ms, now_ms))
}

#[cfg(test)]
pub(crate) fn on_day_text_with_offset(at_ms: u64, now_ms: u64, off: Option<i32>) -> String {
    on_day_words(&raven_core::local_time::deadline_with_offset(
        at_ms, now_ms, off,
    ))
}

fn on_day_words(d: &raven_core::local_time::Deadline) -> String {
    if !d.local {
        return d.rel.clone();
    }
    format!("on {} {} {}", d.weekday, d.day, d.month)
}

/// When something happened, on this computer's clock with its zone (E2 r9
/// #11): `today at 01:42 (UTC+1)`; `about 3 h ago` without the offset.
pub(crate) fn ended_words(d: &raven_core::local_time::Deadline, at_ms: u64, now_ms: u64) -> String {
    if !d.local {
        return raven_core::local_time::ago_text(at_ms, now_ms);
    }
    let zone = zone_label(d.utc_offset_s).unwrap_or_else(|| "local time".into());
    let words = match d.days_ahead {
        0 => format!("today at {}", d.hh_mm),
        -1 => format!("yesterday at {}", d.hh_mm),
        -5..=-2 => format!("on {} at {}", d.weekday, d.hh_mm),
        _ => format!("on {} {} {} at {}", d.weekday, d.day, d.month, d.hh_mm),
    };
    format!("{words} ({zone})")
}

/// [`next_step`] for a message that is already queued: advice that ends in "then
/// send again" must not invite retyping it (the retry would deliver both copies).
fn next_step_queued(cause: Cause, ctx: &SendCtx, raw: &str, retry: &RetryNote) -> String {
    let who = ctx.who();
    // Said once (E2 r38: "you do not need to send it again", "The message
    // waits and goes by itself" and "Do not retype this message: it goes
    // out as soon as ..." said it three ways): the queued sentence says it
    // goes by itself, this only that it must not be typed again.
    let do_not_retype = if retry.background {
        "Do not retype this message.".to_string()
    } else {
        format!("Do not retype this message: it goes out with your next send to {who}.")
    };
    // E2 r9 #5, #6: every way failed with Tor among them, or a mail friend
    // will carry it, or (r40) Tor answered and only the message did not get
    // through: no address to fix and no network to share, so no LAN advice.
    if retry.background
        && (every_way_failed(ctx, raw).is_some()
            || carried(retry)
            || tor_only_no_answer(raw)
            || raw.contains(super::pair_init_lab::ONION_CHECKED_THEN_LOST))
    {
        return do_not_retype;
    }
    match p2p_reason(cause, ctx, raw) {
        Some(Reach::P2p(d, names)) => {
            if let Some(step) = p2p_next_step(&d, ctx, &names, StepMode::Queued) {
                return join_sentences(&[step, do_not_retype]);
            }
        }
        Some(Reach::Lan(lan, part, _)) => return next_step_queued(lan, ctx, &part, retry),
        None => {}
    }
    if cause == Cause::NameNotFound && !retry.background {
        // Without a background outbox only the next send takes it.
        let fix = fix_address_cmd(failed_carrier(raw), &ctx.sel());
        let step = format!(
            "If {} computer has a new address, save it: {fix}.",
            ctx.whose()
        );
        return join_sentences(&[step, do_not_retype]);
    }
    if cause == Cause::NotListening && retry.background {
        // Locked or closed there: nothing to do here but wait (E1).
        return do_not_retype;
    }
    if cause == Cause::WrongIdentity && is_noise_pin_mismatch(raw) {
        // A reinstall changed the key: no wait reaches it.
        let step = if retry.background {
            format!(
                "It waits until {who} connects to you or you change networks; if {who} \
                 reinstalled RAVEN, get their new invite and add them again."
            )
        } else {
            // Without a background outbox only the next send takes it.
            format!("If {who} reinstalled RAVEN, get their new invite and add them again.")
        };
        return join_sentences(&[step, do_not_retype]);
    }
    let step = next_step(cause, ctx, false, raw)
        .replace(", then send again.", ".")
        .replace("Try again in a moment. ", "");
    join_sentences(&[step, do_not_retype])
}

/// The message is durably queued here but its dial failed. Say until when it
/// can still go out, and whether raven-node keeps trying it in the background
/// (only the next send does with a service that has no outbox).
pub(crate) fn queued_text(ctx: &SendCtx, raw: &str, preview: &str, retry: &RetryNote) -> String {
    let cause = classify_cause(raw);
    let who = ctx.who();
    let until = retry.until();
    join_sentences(&[
        format!(
            "{QUEUED_PREFIX}: your message{} to {who} is queued locally because {}.",
            spaced(preview),
            cause_sentence(cause, ctx, raw, false)
        ),
        if retry.background {
            format!(
                "Queued: {BACKGROUND_RETRY} in the background until {until} and sends it by \
                 itself {} (`raven outbox list` shows it); after that it is not sent, and \
                 `raven outbox list` says so.",
                when_it_goes(raw, retry, &who)
            )
        } else {
            format!(
                "It is NOT retried automatically (this raven-node has no background outbox): \
                 it is sent when you next send {who} a message, until {until}; after that it \
                 expires."
            )
        },
        next_step_queued(cause, ctx, raw, retry),
        custody_sentence(&who, retry, &until),
        technical_note(raw),
    ])
}

/// A mail friend will carry it (friend custody), with raven-node retrying.
fn carried(retry: &RetryNote) -> bool {
    retry.background && !retry.custodians.is_empty()
}

/// When a queued message goes by itself: "when you are both on the same
/// network" only for a send that had nothing but the local network; with
/// another way (p2p, Tor, ...) or a mail friend, "as soon as Bob can be
/// reached" (E2 r9 #6: a friend on another network was told to share one;
/// r40: a send over Tor alone is not a local one either).
fn when_it_goes(raw: &str, retry: &RetryNote, who: &str) -> String {
    let ways = ways_tried(raw);
    let lan_only = (ways.is_empty() && !raw.contains("ONION_")) || ways == ["on the local network"];
    if lan_only && !carried(retry) {
        "when you are both on the same network".into()
    } else {
        format!("as soon as {who} can be reached")
    }
}

/// The message waits for a new secure connection with the contact (the long
/// message horizon, Phase 5a, P5.8): no session could take it, so it is
/// parked until its deadline (`retry.expires_at_ms`), and raven-node (or the
/// next send that reaches the contact) sets up a new session, then sends
/// it. Starts with [`QUEUED_PREFIX`] and names [`BACKGROUND_RETRY`] when the
/// background outbox took it, as every queued line: the chat and the
/// terminal app read them.
pub(crate) fn parked_text(ctx: &SendCtx, raw: &str, preview: &str, retry: &RetryNote) -> String {
    let who = ctx.who();
    join_sentences(&[
        format!(
            "{QUEUED_PREFIX}: your message{} to {who} is queued: {who} isn't reachable now. When \
             you are both on the same network, RAVEN first sets up a new secure connection, then \
             sends it. It can wait until {}.",
            spaced(preview),
            retry.until()
        ),
        if retry.background {
            format!(
                "{BACKGROUND_RETRY} in the background (`raven outbox list` shows it as waiting)."
            )
        } else {
            format!(
                "It is NOT retried automatically (this raven-node has no background outbox): it \
                 goes out with your next send to {who} that reaches {who}."
            )
        },
        "Do not retype this message.".into(),
        technical_note(raw),
    ])
}

/// "Carol", "Carol and Dan".
fn friends_words(friends: &[String]) -> String {
    match friends {
        [] => String::new(),
        [one] => sanitize_terminal_line(one),
        [rest @ .., last] => format!(
            "{} and {}",
            rest.iter()
                .map(|f| sanitize_terminal_line(f))
                .collect::<Vec<_>>()
                .join(", "),
            sanitize_terminal_line(last)
        ),
    }
}

/// When raven-node first leaves a copy with a friend: "in about a minute".
fn custody_after_words() -> String {
    let secs = raven_core::custody_client::custody_after_ms().div_ceil(1000);
    if secs <= 90 {
        "in about a minute".into()
    } else {
        format!("in about {} minutes", secs.div_ceil(60))
    }
}

/// Carry choice's words for the friend a message is left with first
/// (Phase 6a P6.16), from raven-node's `LearningPlan` carry row: `Carol first
/// (you meet often; delivered 3 of 4 before)`; without an outcome yet only
/// how often you meet. Plain ASCII; the name is made terminal-safe.
pub(crate) fn carry_first_words(name: &str, met: &str, delivered: u32, outcomes: u32) -> String {
    let met = match met {
        "often" => "you meet often",
        "sometimes" => "you meet sometimes",
        "rarely" => "you rarely meet",
        _ => "you have not met lately",
    };
    let name = sanitize_terminal_line(name);
    if outcomes == 0 {
        format!("{name} first ({met})")
    } else {
        format!("{name} first ({met}; delivered {delivered} of {outcomes} before)")
    }
}

/// The queued text's friend custody sentence (Phase 3 item 3): who gets a
/// sealed copy, how long their Raven holds it (until the contact collects
/// it, or until `until`, the envelope's expiry; P3.C4), what they learn,
/// and how to hand it over now; with carry choice's reason when raven-node
/// learned who goes first (P6.16). Empty without a friend, or when nothing
/// retries it in the background.
fn custody_sentence(who: &str, retry: &RetryNote, until: &str) -> String {
    if retry.custodians.is_empty() || !retry.background {
        return String::new();
    }
    let first = retry
        .carry_first
        .as_ref()
        .map_or(String::new(), |w| format!(" Left with {w}."));
    let friend = friends_words(&retry.custodians);
    let (holds, knows) = if let [one] = retry.custodians.as_slice() {
        let ravens = format!("{}'s Raven", sanitize_terminal_line(one));
        (format!("{ravens} holds"), format!("{ravens} knows"))
    } else {
        (
            format!("The Ravens of {friend} hold"),
            "their Ravens know".to_string(),
        )
    };
    // E2 r9 #7: one hold time everywhere: the sealed copy's own expiry, as
    // `raven outbox list` says it ("held by 1 friend until ..."), not the
    // message's 7-day deadline, which is this computer's and comes after.
    let copy_until = retry.copy_until().unwrap_or_else(|| until.to_string());
    let (shared, passes) = if retry.custodians.len() == 1 {
        ("a mail friend you share", "passes")
    } else {
        ("mail friends you share", "pass")
    };
    format!(
        "{who} can't be reached now: raven-node keeps trying and leaves a sealed copy with \
         {friend} ({shared}) {}, who {passes} it on when {who} is back.{first} {holds} it \
         until {copy_until}, when that copy expires. {friend} can't read it, but {knows} that \
         you wrote to {who}, and when. Keep this computer online until `raven outbox list` \
         says it is held by a friend, or run `raven outbox hand-off`.",
        custody_after_words()
    )
}

/// The peer's acknowledgement came back (it holds the message) but this computer
/// could not finish recording that, so the text must not be retyped.
pub(crate) fn recorded_locally_failed_text(
    ctx: &SendCtx,
    raw: &str,
    preview: &str,
    retry: &RetryNote,
) -> String {
    let (who, whose) = (ctx.who(), ctx.whose());
    let cause = classify_cause(raw);
    let local = matches!(
        cause,
        Cause::HistoryUnreadable | Cause::KeychainDenied | Cause::HistoryLocked
    );
    join_sentences(&[
        format!(
            "{UNCONFIRMED_PREFIX}: your message{} reached {whose} computer and an \
             acknowledgement came back, but {}.",
            spaced(preview),
            if local {
                cause_sentence(cause, ctx, raw, false)
            } else {
                "this computer could not finish recording it".to_string()
            }
        ),
        format!(
            "Do not retype it: fix the problem below, and {} finishes the record (until {}).",
            retry.retried_by(&who),
            retry.until()
        ),
        if local {
            next_step(cause, ctx, false, raw)
        } else {
            String::new()
        },
        technical_note(raw),
    ])
}

/// The new message's frames were written and only its ACK is missing: the peer
/// may already hold it, so it must not be retyped.
pub(crate) fn unconfirmed_text(
    ctx: &SendCtx,
    raw: &str,
    preview: &str,
    retry: &RetryNote,
) -> String {
    let (who, whose) = (ctx.who(), ctx.whose());
    join_sentences(&[
        format!(
            "{UNCONFIRMED_PREFIX}: your message{} was sent to {whose} computer, but {who} has \
             not confirmed it yet ({who}'s RAVEN may be unable to save it, or {who} may have \
             removed or blocked you).",
            spaced(preview)
        ),
        if retry.background {
            format!(
                "Do not retype it: {BACKGROUND_RETRY} in the background until {who} confirms \
                 it, until {}.",
                retry.until()
            )
        } else {
            format!(
                "Do not retype it: it stays queued, and your next send to {who} tries again, \
                 until {}.",
                retry.until()
            )
        },
        technical_note(raw),
    ])
}

/// The peer is unreachable and `queued` earlier messages already wait for it:
/// this one was not queued (see `MAX_QUEUED_PER_PEER`).
pub(crate) fn queue_full_text(ctx: &SendCtx, queued: usize) -> String {
    let who = ctx.who();
    format!(
        "NOT SENT: {queued} earlier messages to {who} are already waiting until {who} can be \
         reached, so this one was not queued. They go out first (`raven outbox list`); send \
         this message again once they have arrived."
    )
}

/// The shared outbound stage is nearly full of messages waiting for contacts
/// that cannot be reached: this one was not queued, so sends to reachable
/// contacts keep working.
pub(crate) fn offline_stage_full_text(ctx: &SendCtx) -> String {
    let who = ctx.who();
    format!(
        "NOT SENT: {who} cannot be reached and too many messages are already waiting for \
         contacts who are offline, so this one was not queued (room is kept for contacts \
         who can be reached). See `raven outbox list`; send it again once some have arrived \
         or were cancelled."
    )
}

/// An earlier message failed again on a route that answered (a refusal, not an
/// unreachable peer), so this one was not queued behind it. While the peer is
/// unreachable later messages do queue behind earlier ones instead.
pub(crate) fn earlier_undelivered_text(
    ctx: &SendCtx,
    raw: &str,
    preview: &str,
    retry: &RetryNote,
) -> String {
    let cause = classify_cause(raw);
    let who = ctx.who();
    join_sentences(&[
        format!(
            "NOT SENT: an earlier message{} to {who} is still undelivered ({}), so this message \
             was not queued behind it.",
            spaced(preview),
            cause_sentence(cause, ctx, raw, false)
        ),
        next_step(cause, ctx, false, raw),
        if retry.background {
            format!(
                "{BACKGROUND_RETRY} the earlier one in the background (until {}); send this \
                 message again once it has arrived (`raven outbox list`).",
                retry.until()
            )
        } else {
            format!(
                "Then send this message again: the earlier one goes first (until {}).",
                retry.until()
            )
        },
        technical_note(raw),
    ])
}

/// An earlier message was sent again but its ACK has not come, so this one was
/// not queued. Unlike a refusal its frames *were* written.
pub(crate) fn earlier_unconfirmed_text(ctx: &SendCtx, preview: &str) -> String {
    let who = ctx.who();
    format!(
        "NOT SENT: an earlier message{} to {who} was sent again, but {who} has not confirmed \
         it yet (it may already have arrived), so this message was not queued. Wait a moment, \
         then send again.",
        spaced(preview)
    )
}

// ── Clocks (cutoff pack CP.7, F10 / M11) ──────────────────────────────────
//
// Raven refuses what is dated more than five minutes in its future, and in a
// long cutoff nothing sets the clocks. Each side sees only the half where the
// other side is ahead: raven-node notes it (`Status.clock_skew`), and these
// say so. The LAN beacon sees both halves, to within its 10-minute epochs
// (Phase 3 P3.C3: "or more", behind as well). Raven never sets the clock
// itself.

/// How far apart two clocks are, from whole minutes: `10 min` (under 90),
/// `3 h` (under two days), `2 days`.
pub(crate) fn skew_span(minutes: i32) -> String {
    let m = minutes.unsigned_abs();
    let hours = (m + 30) / 60;
    match m {
        0..=89 => format!("{m} min"),
        _ if hours < 48 => format!("{hours} h"),
        _ => format!("{} days", (hours + 12) / 24),
    }
}

/// `raven status`'s `clocks` row: `who`'s clock runs `minutes` ahead of ours
/// (behind when negative, which only the LAN beacon tells); `at_least`: the
/// LAN beacon's estimate, that much or more (Phase 3 P3.C3, F11b).
pub(crate) fn clock_row_text(who: &str, minutes: i32, at_least: bool) -> String {
    let span = skew_span(minutes);
    let span = if at_least {
        format!("{span} or more")
    } else {
        span
    };
    if minutes < 0 {
        format!(
            "{who}'s clock is about {span} behind yours: {who} refuses your messages until the \
             clocks agree. Check the time and time zone on both laptops."
        )
    } else {
        format!(
            "{who}'s clock is about {span} ahead of yours: messages from {who} are refused \
             until the clocks agree. Check the time and time zone on both laptops."
        )
    }
}

/// A send's sentence when `who`'s clock and ours differ by `minutes`.
pub(crate) fn clocks_differ_text(who: &str, minutes: i32) -> String {
    format!(
        "{who}'s clock and yours differ by about {}, so RAVEN can't set up a secure \
         connection. Check the time and time zone on both laptops.",
        skew_span(minutes)
    )
}

/// [`clocks_differ_text`] for a message that went out but whose confirmation
/// was refused here: `who`'s clock runs `minutes` ahead, so its ACK is dated
/// in our future, while our message (in its past) may well have reached it
/// (review C-time-deadlines-6; s99's "Bob +10").
pub(crate) fn acks_refused_text(who: &str, minutes: i32) -> String {
    format!(
        "{who}'s clock and yours differ by about {}, so {who}'s confirmations are refused here; \
         {who} may have the message. Check the time and time zone on both laptops.",
        skew_span(minutes)
    )
}

/// A send's last sentence when a contact that answers the link twice took
/// our PairInit or message without an answer, and nothing measured a skew.
pub(crate) const SAME_TIME_HINT: &str =
    "If this keeps happening while you are together, check that both laptops show the same time.";

/// An outcome's `(technical: ...)` note: the raw text with every address
/// left out (a queued send's note never names the friend's address). The
/// cause was read from the raw text before.
fn technical_note(raw: &str) -> String {
    format!("(technical: {})", raven_core::ipc::without_addresses(raw))
}

/// The raw text of an outcome line: what its `(technical: ...)` holds, or
/// the whole text.
fn technical_part(text: &str) -> &str {
    text.rfind("(technical: ")
        .map(|i| &text[i + "(technical: ".len()..])
        .map_or(text, |rest| rest.strip_suffix(')').unwrap_or(rest))
}

/// `sentence` put before the outcome's `(technical: ...)`, or at the end.
fn before_technical(text: &str, sentence: &str) -> String {
    match text.rfind("(technical: ") {
        Some(i) => join_sentences(&[text[..i].to_string(), sentence.into(), text[i..].into()]),
        None => join_sentences(&[text.to_string(), sentence.into()]),
    }
}

/// What the running raven-node says about `pub_hex`'s clock (one `Status`,
/// 2 s at most): the minutes it runs ahead of ours, and how many of our
/// PairInits and messages it took in a row without an answer.
fn clock_facts(data_dir: &Path, pub_hex: &str) -> Option<(Option<i32>, u32)> {
    let Ok(IpcResponse::Status {
        clock_skew,
        unanswered,
        ..
    }) = super::ipc_client::ipc_request_timeout(
        data_dir,
        &IpcRequest::status(),
        Duration::from_secs(2),
    )
    else {
        return None;
    };
    let theirs = |key: &str| key.trim().eq_ignore_ascii_case(pub_hex.trim());
    Some((
        clock_skew
            .iter()
            .find(|r| theirs(&r.peer_pub_hex) && r.minutes > 0)
            .map(|r| r.minutes),
        unanswered
            .iter()
            .find(|r| theirs(&r.peer_pub_hex))
            .map_or(0, |r| r.times),
    ))
}

/// The clock sentence for a failed send's outcome `text`, if any:
/// - raven-node saw this contact's clock ahead of ours (something it sent,
///   or its RLB1 offer, dated in our future, within the last hour):
///   [`acks_refused_text`] when the message went out and only its
///   confirmation failed (a `sent, delivery unconfirmed` outcome: no ACK
///   came back, or the one that came back could not be recorded), else
///   [`clocks_differ_text`];
/// - else, when the contact took the PairInit or message and gave no answer
///   (a refusal) for at least the second time in a row: [`SAME_TIME_HINT`].
///
/// Only for an outcome where the contact answered the link or nothing names
/// the cause (`facts` is asked only then); never for a local problem, an
/// unreachable contact or a gate text.
fn clock_sentence(
    text: &str,
    who: &str,
    facts: impl FnOnce() -> Option<(Option<i32>, u32)>,
) -> Option<String> {
    if !is_outcome_text(text) {
        return None;
    }
    let raw = technical_part(text);
    let cause = classify_cause(raw);
    let no_ack = raw.contains("WAITING_FOR_ENDPOINT_ACK");
    let silent = cause == Cause::PeerRefused || no_ack;
    if !silent && cause != Cause::Other {
        return None;
    }
    // The message reached the contact; only its confirmation did not count.
    let went_out = no_ack || text.starts_with(UNCONFIRMED_PREFIX);
    match facts()? {
        (Some(minutes), _) if went_out => Some(acks_refused_text(who, minutes)),
        (Some(minutes), _) => Some(clocks_differ_text(who, minutes)),
        (None, times) if silent && times >= 2 => Some(SAME_TIME_HINT.to_string()),
        _ => None,
    }
}

/// A failed send's outcome with its [`clock_sentence`] (cutoff pack CP.7),
/// before `(technical: ...)`; anything else unchanged.
fn with_clock_words(text: String, ctx: &SendCtx) -> String {
    let (Some(dir), false) = (ctx.data_dir.as_deref(), ctx.pub_hex.is_empty()) else {
        return text;
    };
    match clock_sentence(&text, &ctx.who(), || clock_facts(dir, &ctx.pub_hex)) {
        Some(sentence) if !text.contains(&sentence) => before_technical(&text, &sentence),
        _ => text,
    }
}

/// Plain-words text for a failed send. `raw` is whatever the send path
/// returned (a daemon or OS error, or one of the outcome texts below, which pass
/// through unchanged); `who` is the contact's name, empty when unknown.
///
/// The result starts with the outcome (`NOT SENT: ...`, `not delivered yet: ...
/// queued locally ...`, `sent, delivery unconfirmed: ...`; anything it does not
/// understand keeps the old `send refused: ...` form), names the person, gives the
/// next step, and keeps the raw text at the end as `(technical: ...)`. One line,
/// no newline of its own: callers that sanitize to a single line stay readable.
pub(crate) fn friendly_send_error(raw: &str, who: &str) -> String {
    let raw = raw.trim();
    translate_known(raw, &SendCtx::named(who)).unwrap_or_else(|| {
        if is_outcome_text(raw) {
            raw.to_string()
        } else {
            format!("send refused: {raw}")
        }
    })
}

/// [`friendly_send_error`] for text the send path itself returns: `None` for text
/// that is already an outcome line, or that no sentence covers (a gate text such
/// as `INTERNET_DIRECT_HOLD` or an `ATSAM_*` code must reach callers untouched).
fn translate_known(raw: &str, ctx: &SendCtx) -> Option<String> {
    let raw = raw.trim();
    if is_outcome_text(raw) {
        return None;
    }
    match classify_cause(raw) {
        Cause::Other => None,
        cause => Some(not_sent_for(cause, ctx, raw, false)),
    }
}

/// Technical delivery lines (message id, carrier) in the default output:
/// `RAVEN_VERBOSE=1` (or `ASH_VERBOSE=1`).
pub(crate) fn verbose() -> bool {
    verbose_with(|name| std::env::var_os(name))
}

fn verbose_with(get: impl Fn(&str) -> Option<std::ffi::OsString>) -> bool {
    ["RAVEN_VERBOSE", "ASH_VERBOSE"]
        .iter()
        .any(|name| get(name).is_some_and(|v| !v.is_empty() && v != "0"))
}

/// Whether the session store remembers a secure connection with the
/// contact whose device key is `peer`: one that can still take messages,
/// or the end of its last one, kept 30 days
/// ([`raven_core::indexed_session_store::SESSION_END_KEEP_MS`]). A read of
/// the store's metadata only (no keychain); a send asks it before it sets
/// up a new one.
pub(crate) fn session_remembered(data_dir: &Path, peer: &[u8; 32]) -> bool {
    use raven_core::outbox::{queue_reach, QueueReach};
    matches!(
        queue_reach(data_dir, peer, now_ms()),
        Ok(QueueReach::CanWait { .. } | QueueReach::Ended { .. })
    )
}

/// Whether this computer and the contact `peer_pub_hex` had a secure
/// connection before the one a send just set up (field test E2 r7: one set
/// up again after the last ran out said "First time talking"): `remembered`
/// ([`session_remembered`], read before it was set up), else `history`,
/// whether the chat history holds a message with the contact (one goes
/// only over a secure connection, and a first message that could not go is
/// never kept), for a session that ended longer ago than the store
/// remembers. `history` is asked only then.
pub(crate) fn talked_before(remembered: bool, history: impl FnOnce() -> bool) -> bool {
    remembered || history()
}

/// The chat history of `data_dir` holds a message with `peer_pub_hex` (an
/// unreadable one: no).
pub(crate) fn history_with(data_dir: &Path, peer_pub_hex: &str) -> bool {
    ChatHistory::load(data_dir)
        .is_ok_and(|h| h.for_peer(peer_pub_hex).iter().any(|e| !e.is_group_copy()))
}

impl SendCtx {
    /// What a send says once it set up a secure connection: "First time"
    /// only when there never was one with the contact (`before`:
    /// [`talked_before`]).
    fn connection_set_up_line(&self, before: bool) -> String {
        let who = self.who();
        match (self.chat, before) {
            (true, false) => format!("  {C_DIM}(secure connection with {who} set up){C_RESET}"),
            (true, true) => format!(
                "  {C_DIM}(new secure connection with {who} set up: the last one had run \
                 out){C_RESET}"
            ),
            (false, false) => {
                format!("{C_DIM}First time talking to {who}: secure connection set up.{C_RESET}")
            }
            (false, true) => format!(
                "{C_DIM}New secure connection with {who} set up (the last one had run \
                 out).{C_RESET}"
            ),
        }
    }

    /// `status delivered` stays the first words of the line: scripts and the iOS
    /// gate look for exactly that, and only a verified ACK may print it. The chat
    /// shows its own transcript line instead.
    fn delivered_line(&self) -> Option<String> {
        (!self.chat).then(|| {
            format!(
                "{C_GREEN}status{C_RESET} delivered — {} confirmed receipt",
                self.who()
            )
        })
    }

    /// The lab Internet carrier is evidence-driven when the user named it
    /// (`--carrier internet`: `carrier=internet_dial` is asserted by its smoke
    /// script); everyone else, `--carrier auto` included, sees this on request.
    /// `path=` (how the link travelled, when known) comes last, after `peer=`.
    /// A Tor delivery names no address (never an onion address): no `peer=`
    /// then (field test E3: an empty `peer=` read like missing data), and its
    /// path is Tor.
    fn delivery_detail_line(
        &self,
        carrier: &str,
        path: Option<DeliveryPath>,
        mid: &[u8; 16],
        verbose: bool,
    ) -> Option<String> {
        (verbose || (self.show_carrier && carrier == "internet_dial")).then(|| {
            let peer = sanitize_terminal_line(&self.dial);
            let peer = if peer.trim().is_empty() {
                String::new()
            } else {
                format!(" peer={peer}")
            };
            let path = match path {
                Some(p) => format!(" path={}", p.label()),
                None if carrier == OutboxCarrier::Onion.label() => " path=tor".to_string(),
                None => String::new(),
            };
            format!(
                "{C_DIM}message {}… via carrier={carrier}{peer}{path}{C_RESET}",
                hex::encode(&mid[..4]),
            )
        })
    }

    /// How a p2p delivery travelled, in words: one dim line under `status
    /// delivered`, which stays as it is. p2p only (LAN and Internet direct
    /// are always direct), not in verbose mode (its detail line says
    /// `path=`) and not in the chat.
    fn path_line(
        &self,
        carrier: &str,
        path: Option<DeliveryPath>,
        verbose: bool,
    ) -> Option<String> {
        if self.chat || verbose {
            return None;
        }
        // The Tor onion carrier (lab): its path is Tor whatever the link.
        if carrier == OutboxCarrier::Onion.label() {
            return Some(format!(
                "{C_DIM}  path: via Tor (neither of you saw the other's IP address){C_RESET}"
            ));
        }
        // E2 r9 #1: the send races every way at once; one line says which
        // carried it, whatever the carrier.
        if carrier == OutboxCarrier::Lan.label() {
            return Some(format!("{C_DIM}  path: same network (LAN){C_RESET}"));
        }
        if carrier == OutboxCarrier::Internet.label() {
            return Some(format!("{C_DIM}  path: direct over the internet{C_RESET}"));
        }
        if carrier == OutboxCarrier::Nearby.label() {
            return Some(format!("{C_DIM}  path: Bluetooth nearby{C_RESET}"));
        }
        if carrier != OutboxCarrier::P2p.label() {
            return None;
        }
        let words = match path? {
            DeliveryPath::Relayed => "through a relay (it passes only encrypted bytes)".to_string(),
            DeliveryPath::Direct => "direct connection".to_string(),
            DeliveryPath::Reversed => format!("over {}'s own connection to you", self.who()),
            DeliveryPath::HolePunched => "direct (hole-punched through both routers)".to_string(),
        };
        Some(format!("{C_DIM}  path: {words}{C_RESET}"))
    }

    fn earlier_delivered_line(&self, preview: &str) -> String {
        if self.chat {
            format!(
                "  {C_GREEN}✓{C_RESET} your earlier message{} to {} has now arrived",
                spaced(preview),
                self.who()
            )
        } else {
            format!(
                "{C_GREEN}status{C_RESET} delivered — your earlier message{} to {} has now \
                 arrived and {} confirmed it",
                spaced(preview),
                self.who(),
                self.who()
            )
        }
    }

    fn earlier_failed_line(&self, preview: &str, why: &str) -> String {
        format!(
            "{C_BOLD}status{C_RESET} failed: your earlier message{} to {}: {why}",
            spaced(preview),
            self.who()
        )
    }

    /// A session had to be set up first: the first one with this peer, or
    /// a new one after the last ran out (`before`, [`talked_before`]).
    pub(crate) fn say_connection_set_up(&self, before: bool) {
        println!("{}", self.connection_set_up_line(before));
    }

    /// The new message was acknowledged by the receiver (its sealed ACK
    /// verified). `path`: how its link travelled, when known.
    pub(crate) fn say_delivered(&self, carrier: &str, path: Option<DeliveryPath>, mid: &[u8; 16]) {
        let verbose = verbose();
        if let Some(line) = self.delivered_line() {
            println!("{line}");
        }
        if let Some(line) = self.path_line(carrier, path, verbose) {
            println!("{line}");
        }
        if let Some(line) = self.delivery_detail_line(carrier, path, mid, verbose) {
            println!("{line}");
        }
    }

    /// An earlier, queued message was delivered by this send's retry.
    pub(crate) fn say_earlier_delivered(&self, preview: &str) {
        println!("{}", self.earlier_delivered_line(preview));
    }

    /// An earlier, queued message was given up on. A failure: stderr.
    pub(crate) fn say_earlier_failed(&self, preview: &str, why: &str) {
        eprintln!("{}", self.earlier_failed_line(preview, why));
    }

    /// An earlier message expired before it ever left this computer.
    pub(crate) fn say_earlier_ran_out(&self, preview: &str) {
        self.say_earlier_failed(preview, &time_ran_out_text(&self.who()));
    }

    /// Session reset: the contact no longer took the secure connection and
    /// `n` waiting messages were sealed again under a new one (design §16),
    /// worded by `why` (Phase 6 review re-verify, sensing-1).
    pub(crate) fn peer_reset_line(&self, n: usize, why: ResetWhy) -> String {
        let who = self.who();
        match (self.chat, why) {
            (true, ResetWhy::Lost) => format!(
                "  (new secure connection with {who}: {who}'s RAVEN was reset; {n} waiting \
                 message(s) re-sent)"
            ),
            (true, ResetWhy::Replaced) => format!(
                "  (new secure connection with {who}: {who}'s RAVEN replaced the old one; {n} \
                 waiting message(s) re-sent)"
            ),
            (false, ResetWhy::Lost) => format!(
                "{who}'s RAVEN no longer had your secure connection (it was reinstalled or \
                 restored from a backup). A new secure connection was set up and {n} waiting \
                 message(s) were sent again."
            ),
            (false, ResetWhy::Replaced) => format!(
                "{who}'s RAVEN set up a new secure connection with you and no longer took the \
                 older one (as it does after a security re-key or a restore). {n} waiting \
                 message(s) were sent again under a new one; nothing needs doing."
            ),
        }
    }

    /// The contact presented a new device certificate (it was reinstalled):
    /// the session this send set up replaces the old one.
    pub(crate) fn say_new_connection_after_reset(&self) {
        let who = self.who();
        println!(
            "{who}'s RAVEN was reinstalled (it has a new device certificate): a new secure \
             connection was set up."
        );
    }

    pub(crate) fn say_peer_reset(&self, n: usize, why: ResetWhy) {
        if n > 0 {
            println!("{}", self.peer_reset_line(n, why));
        }
    }

    /// Earlier messages held after a contact reset, with what to do
    /// (stderr), worded by `why` (Phase 6 review re-verify, sensing-1).
    pub(crate) fn reset_held_line(
        &self,
        code: &str,
        rows: usize,
        today: usize,
        why: ResetWhy,
    ) -> String {
        let who = self.who();
        match code {
            // The contact set up the newer connection itself (most often a
            // security re-key there): nothing was lost on its side, but it
            // is not proof enough to re-seal over the Internet (design
            // §9.2, P2), so the person still decides.
            "PEER_RESET_CONFIRM" if why == ResetWhy::Replaced => format!(
                "{rows} earlier message(s) to {who} are on hold: {who}'s RAVEN set up a new \
                 secure connection with you and no longer takes the older one they were sealed \
                 in, as it does after a security re-key or a restore. The new one was not made on \
                 your local \
                 network, so RAVEN does not send them again by itself until you are both on the \
                 same local network. To send them now, run `raven outbox resend --contact \
                 {who}` (after a re-key, {who}'s `raven security` says Raven set up a new secure \
                 connection with you); `raven outbox cancel` drops one. (technical: \
                 PEER_RESET_CONFIRM)"
            ),
            "PEER_RESET_CONFIRM" => format!(
                "{rows} earlier message(s) to {who} are on hold: {who}'s RAVEN lost your secure \
                 connection, and the new one could not be made on your local network, so RAVEN \
                 will not send them again by itself. If {who} confirms they reinstalled or \
                 restored RAVEN, run `raven outbox resend --contact {who}`; `raven outbox \
                 cancel` drops one. (technical: PEER_RESET_CONFIRM)"
            ),
            "PEER_RESET_LOOP" => format!(
                "{rows} earlier message(s) to {who} are on hold: {who}'s RAVEN lost your secure \
                 connection {today} times today, so RAVEN stopped re-sending by itself. Ask {who} \
                 to run `raven doctor`, then run `raven outbox resend --contact {who}`. \
                 (technical: PEER_RESET_LOOP)"
            ),
            "PEER_IDENTITY_FORK" => format!(
                "Warning: {who}'s Raven identity seems to be in use on two computers at once \
                 (one said it no longer has your connection while another kept using it). \
                 {rows} earlier message(s) are on hold and will not be re-sent by themselves. \
                 Check with {who} in person or by phone; run `raven outbox resend --contact \
                 {who}` only if they confirm. (technical: PEER_IDENTITY_FORK)"
            ),
            other => format!(
                "{rows} earlier message(s) to {who} are waiting: {who}'s RAVEN lost your secure \
                 connection and raven-node sets up a new one. (technical: {other})"
            ),
        }
    }

    pub(crate) fn say_reset_held(&self, code: &str, rows: usize, today: usize, why: ResetWhy) {
        if rows > 0 {
            eprintln!("{}", self.reset_held_line(code, rows, today, why));
        }
    }

    /// Re-seals raven-node did in the background, reported once.
    pub(crate) fn say_unnotified_reseals(&self, n: usize, at_ms: u64, why: ResetWhy) {
        if n == 0 {
            return;
        }
        println!(
            "{}",
            reseal_note_line(&self.who(), n, &ended_text(at_ms, now_ms()), why)
        );
    }
}

/// Why a contact no longer takes the secure connection a message was
/// sealed in, as far as this computer can tell (Phase 6 review re-verify,
/// sensing-1): it set up a newer one itself (`Replaced`: a security re-key
/// on its side, or a restore after which it set up one;
/// `IndexedSessionStore::contact_replaced_retired_session`), or it lost
/// it (`Lost`: reinstalled or restored, with nothing set up since).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResetWhy {
    Lost,
    Replaced,
}

impl ResetWhy {
    /// For the contact `peer` in this profile now (`Lost` when the store
    /// cannot be read).
    pub(crate) fn of(data_dir: &Path, peer: &[u8; 32]) -> Self {
        let replaced = raven_core::indexed_session_store::IndexedSessionStore::open(data_dir)
            .ok()
            .and_then(|mut store| store.contact_replaced_retired_session(peer, now_ms()).ok())
            .unwrap_or(false);
        if replaced {
            ResetWhy::Replaced
        } else {
            ResetWhy::Lost
        }
    }
}

/// [`SendCtx::say_unnotified_reseals`]'s line. `when` is [`ended_text`]:
/// `today at 14:05` on this computer's clock, or `about 3 h ago` without its
/// offset; never a time on another clock (review C-time-deadlines-7, CP.6).
fn reseal_note_line(who: &str, n: usize, when: &str, why: ResetWhy) -> String {
    match why {
        ResetWhy::Lost => format!(
            "Note: {n} message(s) to {who} were sent again under a new secure connection \
             {when}, after {who}'s RAVEN was reinstalled or restored."
        ),
        ResetWhy::Replaced => format!(
            "Note: {n} message(s) to {who} were sent again under a new secure connection \
             {when}, after {who}'s RAVEN replaced the old one (as it does after a security \
             re-key or a restore)."
        ),
    }
}

/// NOT SENT: every session with the contact was retired (it lost RAVEN) and it
/// cannot be reached, so there is nothing to queue the message under.
pub(crate) fn peer_reset_unreachable_text(ctx: &SendCtx) -> String {
    let who = ctx.who();
    format!(
        "NOT SENT: {who}'s RAVEN lost your secure connection and {who} cannot be reached right \
         now, so there is no connection to queue this message under. Nothing was queued; send \
         it again when {who} is online. (technical: PEER_RESET_UNREACHABLE)"
    )
}

/// Prints one stderr line when the work it guards runs longer than `after`, and
/// only when stderr is a terminal: a pipe or a log keeps exactly the output it
/// had. Dropping it ends the wait (and joins the helper thread).
pub(crate) struct SlowNote {
    stop: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// How long a send runs before it says it is working.
const SLOW_NOTE_AFTER: Duration = Duration::from_secs(1);

impl SlowNote {
    pub(crate) fn start(message: String) -> Self {
        Self::start_with(
            message,
            SLOW_NOTE_AFTER,
            io::stderr().is_terminal(),
            Box::new(|m| eprintln!("{C_DIM}{m}{C_RESET}")),
        )
    }

    fn start_with(
        message: String,
        after: Duration,
        enabled: bool,
        emit: Box<dyn Fn(&str) + Send>,
    ) -> Self {
        if !enabled {
            return Self {
                stop: None,
                thread: None,
            };
        }
        let (stop, rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("ash-slow-note".into())
            .spawn(move || {
                // A sender that is dropped wakes this at once (`Disconnected`):
                // only a full timeout means the work is still running.
                if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = rx.recv_timeout(after) {
                    emit(&message);
                }
            })
            .ok();
        Self {
            stop: Some(stop),
            thread,
        }
    }
}

impl Drop for SlowNote {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// ── Secure send (seal in ash → IPC enqueue; never argv plaintext) ─────────

pub fn refuse_argv_plaintext() {
    eprintln!("{C_PURPLE}REFUSE{C_RESET}: plaintext on argv is forbidden (visible via ps).");
    eprintln!(
        "{C_DIM}use:{C_RESET} ash send --contact @alice   (type the message, then {})",
        super::END_OF_INPUT
    );
    eprintln!(
        "     {C_DIM}Typing the message after the command keeps it out of your shell history.{C_RESET}"
    );
    eprintln!(
        "{C_DIM} or:{C_RESET} {}",
        super::file_send_example("@alice")
    );
    eprintln!(
        "{C_DIM} or:{C_RESET} ash send --peer … --peer-pub-hex …   # then type message on stdin"
    );
    std::process::exit(2);
}

/// Lab Test A send: PairInit LAN OOB → PairResponse → IndexedSessionStore envelope.
/// Never uses public-key-derived seal_message / unsafe-demo-crypto.
///
/// The `Err` text is already the user's sentence (see [`friendly_send_error`]): the
/// contact is named by `petname` / `tag`, or looked up from `peer_pub_hex`.
/// `choice`: what the user asked for (see `SendCtx::choice`). `unrecorded`:
/// [`SendCtx::unrecorded`] (a learned address, such as cutoff F7's guess for
/// a contact with no address saved, is dialled now and never recorded).
#[allow(clippy::too_many_arguments)]
pub fn run_send_secure(
    data_dir: &Path,
    id: &Identity,
    peer: &str,
    peer_pub_hex: &str,
    listen: &str,
    text: &str,
    petname: &str,
    tag: &str,
    choice: raven_core::outbox::CarrierChoice,
    custody_ok: bool,
    unrecorded: &[String],
) -> Result<(), String> {
    let ctx = SendCtx {
        choice: Some(choice),
        custody_ok,
        unrecorded: unrecorded.to_vec(),
        ..send_ctx(data_dir, petname, tag, peer_pub_hex)
    };
    send_with(
        data_dir,
        id,
        peer,
        peer_pub_hex,
        listen,
        text,
        &ctx,
        super::pair_init_lab::DialCarrier::Lan,
    )
}

/// Same as [`run_send_secure`] on a named carrier (`lan` or lab `internet`).
#[allow(clippy::too_many_arguments)]
pub fn run_send_secure_on(
    data_dir: &Path,
    id: &Identity,
    peer: &str,
    peer_pub_hex: &str,
    listen: &str,
    text: &str,
    petname: &str,
    tag: &str,
    carrier: super::pair_init_lab::DialCarrier,
) -> Result<(), String> {
    let ctx = SendCtx {
        // The caller named this carrier: the lab Internet carrier keeps its
        // evidence line (see `SendCtx::show_carrier`).
        show_carrier: carrier == super::pair_init_lab::DialCarrier::Internet,
        ..send_ctx(data_dir, petname, tag, peer_pub_hex)
    };
    send_with(
        data_dir,
        id,
        peer,
        peer_pub_hex,
        listen,
        text,
        &ctx,
        carrier,
    )
}

/// `raven send` over a contact's routes, in order (LAN first, then Internet;
/// see `pair_init_lab::run_pair_init_and_send_routes`), and the route that was
/// used. `show_carrier`: the user named the carrier (`--carrier internet`).
/// `unrecorded`: [`SendCtx::unrecorded`].
#[allow(clippy::too_many_arguments)]
pub fn run_send_secure_routes(
    data_dir: &Path,
    id: &Identity,
    routes: &[super::pair_init_lab::DialRoute],
    peer_pub_hex: &str,
    text: &str,
    show_carrier: bool,
    choice: raven_core::outbox::CarrierChoice,
    unrecorded: &[String],
) -> Result<super::pair_init_lab::DialRoute, String> {
    let first = routes.first().ok_or_else(|| {
        "valid lan_dial host:port required — refusing LocalListenQueue / 127.0.0.1:0 fallback"
            .to_string()
    })?;
    let ctx = SendCtx {
        dial: super::pair_init_lab::ctx_dial(first),
        show_carrier,
        choice: Some(choice),
        custody_ok: choice == raven_core::outbox::CarrierChoice::Auto,
        unrecorded: unrecorded.to_vec(),
        ..send_ctx(data_dir, "", "", peer_pub_hex)
    };
    deliver_routes(data_dir, id, routes, peer_pub_hex, text, &ctx)
        .map_err(|e| with_clock_words(translate_known(&e, &ctx).unwrap_or(e), &ctx))
}

/// One send, whatever the carrier: every error that leaves it is the user's
/// sentence where one exists. Text no sentence covers (the `INTERNET_DIRECT_HOLD`
/// gate, `ATSAM_*` codes, the FastAPI refusal) is returned untouched.
#[allow(clippy::too_many_arguments)]
fn send_with(
    data_dir: &Path,
    id: &Identity,
    peer: &str,
    peer_pub_hex: &str,
    listen: &str,
    text: &str,
    ctx: &SendCtx,
    carrier: super::pair_init_lab::DialCarrier,
) -> Result<(), String> {
    use super::pair_init_lab::DialCarrier;
    // LAN may fall back to the listen address; the lab Internet carrier dials
    // `peer` only.
    let dial = match carrier {
        DialCarrier::Lan if !looks_like_host_port(peer) && looks_like_host_port(listen) => listen,
        _ => peer,
    };
    let ctx = SendCtx {
        dial: dial.trim().to_string(),
        ..ctx.clone()
    };
    deliver(data_dir, id, dial, peer_pub_hex, text, &ctx, carrier)
        .map_err(|e| with_clock_words(translate_known(&e, &ctx).unwrap_or(e), &ctx))
}

fn deliver(
    data_dir: &Path,
    id: &Identity,
    dial: &str,
    peer_pub_hex: &str,
    text: &str,
    ctx: &SendCtx,
    carrier: super::pair_init_lab::DialCarrier,
) -> Result<(), String> {
    let route = super::pair_init_lab::DialRoute {
        carrier,
        dial: dial.to_string(),
    };
    deliver_routes(data_dir, id, &[route], peer_pub_hex, text, ctx).map(|_| ())
}

/// [`deliver`] over several routes (tried in order, see
/// `pair_init_lab::run_pair_init_and_send_routes`). Every check runs before the
/// local service is started or anything is dialled.
fn deliver_routes(
    data_dir: &Path,
    id: &Identity,
    routes: &[super::pair_init_lab::DialRoute],
    peer_pub_hex: &str,
    text: &str,
    ctx: &SendCtx,
) -> Result<super::pair_init_lab::DialRoute, String> {
    use super::pair_init_lab::DialCarrier;
    let path = resolve_terminal_messaging_path();
    assert_no_silent_fastapi(path)?;
    let blocks = BlockList::load_checked(data_dir)?;
    if blocks.is_blocked(peer_pub_hex) {
        return Err("peer is on the local block list".into());
    }
    let peer_pub = parse_pub_hex(peer_pub_hex)?;
    if text.trim().is_empty() {
        return Err("message is empty".into());
    }
    if !raven_core::app_channel::chat_text_allowed(text) {
        return Err(super::pair_init_lab::RESERVED_PREFIX_REFUSAL.into());
    }
    let Some(first) = routes.first() else {
        return Err(
            "valid lan_dial host:port required — refusing LocalListenQueue / 127.0.0.1:0 fallback"
                .into(),
        );
    };
    for route in routes {
        let plausible = if matches!(
            route.carrier,
            DialCarrier::P2p | DialCarrier::Nearby | DialCarrier::Onion
        ) {
            route.carrier.plausible(&route.dial)
        } else {
            looks_like_host_port(&route.dial)
        };
        if !plausible {
            return Err(format!(
                "valid {} {} required — refusing LocalListenQueue / 127.0.0.1:0 fallback",
                route.carrier.label(),
                match route.carrier {
                    DialCarrier::P2p => "/p2p/<PeerId> address",
                    DialCarrier::Nearby => "nearby:<contact key> route",
                    DialCarrier::Onion => "onion:<onion key> route",
                    _ => "host:port",
                }
            ));
        }
        // The Internet and p2p carriers have their own (stricter) gates than
        // LAN: refuse here, before ensure_mac_lan_daemon changes this
        // machine's listening state.
        if let Some(hold) = route.carrier.hold() {
            return Err(hold.into());
        }
        // And only for a verified (pinned) contact: refused before anything
        // starts or is dialled.
        if route.carrier != DialCarrier::Lan
            && !raven_core::carrier_allowed_for_contact(
                route.carrier.outbox(),
                raven_core::contact_is_pinned(data_dir, &peer_pub)?,
            )
        {
            return Err(super::pair_init_lab::unverified_carrier_text(
                &ctx.who(),
                super::pair_init_lab::carrier_word(route.carrier),
                &format!(
                    "raven contact verify --address {}",
                    encode_address(&peer_pub)
                ),
                &super::pair_init_lab::pin_command_hint(&peer_pub),
            ));
        }
    }
    // Unverified contacts are LAN only, at local-network addresses only: a
    // name is resolved first and dialled as the resolved address (one that
    // does not resolve now, under F1, is probed as a name not found). While
    // `raven lan off` holds no LAN route is resolved or dialled.
    let lan_off = lan_off_now(data_dir);
    // `raven lan verified-only on` (Phase 3 P3.C2): no LAN link at all with
    // an unverified contact, so nothing is started or dialled for it.
    if !lan_off
        && routes.iter().any(|r| r.carrier == DialCarrier::Lan)
        && raven_core::node_policy::lan_verified_only(data_dir)
        && !raven_core::contact_is_pinned(data_dir, &peer_pub)?
    {
        return Err(verified_only_text(&ctx.who(), &peer_pub));
    }
    let (dial_routes, unresolved) = send_dial_routes(data_dir, routes, &peer_pub, ctx, lan_off)?;
    let (dial, carrier) = (first.dial.as_str(), first.carrier);

    let mut message_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut message_id);
    let mid_prefix = hex::encode(&message_id[..4]);

    if !super::trace_delivery::live_pair_init_outbound_ready() {
        let status = super::trace_delivery::production_gate_status();
        if carrier == DialCarrier::Lan {
            super::trace_delivery::trace_event(
                "ash/ext.rs:run_send_secure",
                "TRACE_SEND_BLOCKED",
                status,
                Some(&mid_prefix),
                Some("no_live_pair_init_or_indexed_session_callsite"),
            );
            eprintln!("{C_PURPLE}status{C_RESET} {status}");
            eprintln!(
                "Message not sent — set RAVEN_LAB_TEST_A=1 (debug) after wiring, or wait for production gates."
            );
        }
        return Err(status.into());
    }

    require_local_daemon(data_dir)?;
    if carrier == DialCarrier::Lan {
        super::trace_delivery::trace_event(
            "ash/ext.rs:run_send_secure",
            "TRACE_SEND_LAB_PAIR_INIT",
            super::trace_delivery::production_gate_status(),
            Some(&mid_prefix),
            Some("pair_init_lab"),
        );
    }
    // The probe order: raven-node's learned carrier order while learning
    // connectivity is on (Phase 6a), else the contact's remembered route
    // first (lab only; keyed by the routes as planned, never a resolved LAN
    // literal). After every refusal above, so a refused send reads nothing.
    let planned: Vec<raven_core::OutboxRoute> = routes
        .iter()
        .map(|r| raven_core::OutboxRoute {
            carrier: r.carrier.outbox(),
            dial: r.dial.trim().to_string(),
        })
        .collect();
    let lan_skipped = lan_off && routes.iter().any(|r| r.carrier == DialCarrier::Lan);
    // While LAN is off, plan order and nothing remembered or taught: a LAN
    // route that was never tried did not fail.
    let probe = if lan_skipped {
        let others = routes.iter().any(|r| r.carrier != DialCarrier::Lan);
        eprintln!("{C_DIM}{}{C_RESET}", lan_off_send_note(&ctx.who(), others));
        super::pair_init_lab::ProbePlan::in_order(routes.len())
    } else {
        super::pair_init_lab::ProbePlan::remembered(data_dir, &peer_pub, planned)
    }
    .with_unresolved(unresolved);
    // The network part: on a terminal, say so when it takes more than a second.
    // It names the address tried first (the planned form, as before; while LAN
    // is off, the first one that is dialled).
    let first_dialled = if lan_skipped {
        routes.iter().find(|r| r.carrier != DialCarrier::Lan)
    } else {
        routes.get(probe.first())
    };
    // Every way races (E2 r9 #1): with more than one, the note names none.
    let shown = first_dialled.map_or_else(
        || sanitize_terminal_line(dial),
        super::pair_init_lab::dial_shown,
    );
    let _working = SlowNote::start(if dial_routes.len() > 1 {
        format!("sending to {} ...", ctx.who())
    } else {
        format!("sending to {} at {shown} ...", ctx.who())
    });
    let used = super::pair_init_lab::run_pair_init_and_send_routes(
        data_dir,
        id,
        &dial_routes,
        &probe,
        peer_pub_hex,
        text,
        ctx,
    )?;
    // The caller knows the routes as planned (the saved / env addresses).
    Ok(dial_routes
        .iter()
        .position(|r| *r == used)
        .map(|i| routes[i].clone())
        .unwrap_or(used))
}

/// The routes to dial for `peer`: as planned for a verified contact; for an
/// unverified one every LAN address must be on the local network
/// (`raven_core::outbox::localize_lan_route`, the rule raven-node's outbox
/// applies too), else nothing is dialled.
///
/// Cutoff F1 (gate `OFFLINE_LAN`): a saved computer name that does not
/// resolve now is the contact being away, not a refusal. Its route is kept
/// as planned (the name: raven-node's outbox localizes it again at every
/// dial) and its index comes back with the probe error it stands for
/// (`lan connect: cannot resolve <name>: ...`, a name not found), so the
/// send probes nothing there and queues the message when a session exists.
fn local_dial_routes(
    data_dir: &Path,
    routes: &[super::pair_init_lab::DialRoute],
    peer: &[u8; 32],
    ctx: &SendCtx,
) -> Result<LocalDialRoutes, String> {
    local_dial_routes_with(data_dir, routes, peer, ctx, raven_core::offline_lan_live())
}

/// The routes to dial, and (route index, probe error) for each kept route
/// whose name did not resolve ([`local_dial_routes`]).
type LocalDialRoutes = (Vec<super::pair_init_lab::DialRoute>, Vec<(usize, String)>);

/// [`local_dial_routes`] with the `OFFLINE_LAN` gate passed in: closed, an
/// unresolved name refuses the send as before.
fn local_dial_routes_with(
    data_dir: &Path,
    routes: &[super::pair_init_lab::DialRoute],
    peer: &[u8; 32],
    ctx: &SendCtx,
    offline_lan: bool,
) -> Result<LocalDialRoutes, String> {
    use raven_core::outbox::{localize_lan_route, RouteRefusal, LOCALIZE_RESOLVE_TIMEOUT};
    let pinned = raven_core::contact_is_pinned(data_dir, peer)?;
    // A card's LAN route keeps the local-network rule for a verified contact
    // too (`raven_core::outbox::ContactRoutes::lan_local_only`).
    let book = raven_core::outbox::contact_routes(data_dir, peer)?;
    let mut out = Vec::with_capacity(routes.len());
    let mut unresolved = Vec::new();
    for (i, route) in routes.iter().enumerate() {
        let planned = raven_core::OutboxRoute {
            carrier: route.carrier.outbox(),
            dial: route.dial.trim().to_string(),
        };
        let pinned_contact = pinned;
        let pinned = pinned && !book.as_ref().is_some_and(|c| c.lan_local_only(&planned));
        let why = match localize_lan_route(&planned, pinned, LOCALIZE_RESOLVE_TIMEOUT) {
            Ok(local) => {
                out.push(super::pair_init_lab::DialRoute {
                    carrier: route.carrier,
                    dial: local.dial,
                });
                continue;
            }
            Err(why) => why,
        };
        let shown = sanitize_terminal_line(route.dial.trim());
        let away = offline_lan && why.is_unresolved_name();
        let reason = match why {
            RouteRefusal::NotLocal => format!("{shown} is not on your local network"),
            // F1: kept as planned, in raven-node's words for a name it
            // cannot resolve. Nothing is dialled here either.
            RouteRefusal::Unresolved(e) if away => {
                let host = planned.dial.rsplit_once(':').map_or("", |(host, _)| host);
                let host = host.trim_start_matches('[').trim_end_matches(']');
                unresolved.push((
                    i,
                    format!(
                        "lan connect: cannot resolve {}: {}",
                        sanitize_terminal_line(host),
                        sanitize_terminal_line(&e)
                    ),
                ));
                out.push(super::pair_init_lab::DialRoute {
                    carrier: route.carrier,
                    dial: planned.dial,
                });
                continue;
            }
            RouteRefusal::Unresolved(e) => format!(
                "{shown} could not be resolved ({}), so RAVEN cannot tell it is on your \
                 local network",
                sanitize_terminal_line(&e)
            ),
        };
        if pinned_contact {
            // Verified, but the address came from a card.
            return Err(card_lan_text(&ctx.who(), &reason, peer));
        }
        return Err(super::pair_init_lab::unverified_remote_lan_text(
            &ctx.who(),
            &reason,
            &format!("raven contact verify --address {}", encode_address(peer)),
            &super::pair_init_lab::pin_command_hint(peer),
        ));
    }
    Ok((out, unresolved))
}

/// A send to a verified contact whose LAN address came from a card and is
/// not on the local network (`reason`): a card's routes are not signed, so
/// such an address is dialled only on the local network. NOT SENT, nothing
/// dialled; the user can set an address they trust.
fn card_lan_text(who: &str, reason: &str, peer: &[u8; 32]) -> String {
    format!(
        "NOT SENT: {reason}, and that LAN address came from {who}'s card: a LAN address from a \
         card is used only on your local network, because nobody signs a card's addresses. If \
         {who} gave you this address themselves, save it: raven contact set-dial --address {} \
         HOST:PORT. Nothing was dialled.",
        encode_address(peer),
    )
}

/// A send to a contact that is not verified while `raven lan verified-only
/// on` holds (Phase 3 P3.C2; the cutoff people report's words): NOT SENT,
/// nothing dialled, with the local code `LAN_VERIFIED_ONLY`.
pub(crate) fn verified_only_text(who: &str, peer: &[u8; 32]) -> String {
    format!(
        "NOT SENT: {} ({})",
        verified_only_words(who, peer),
        raven_core::LAN_VERIFIED_ONLY
    )
}

/// The sentences of [`verified_only_text`]: why, and how to verify.
fn verified_only_words(who: &str, peer: &[u8; 32]) -> String {
    format!(
        "Only verified friends can connect on this network: {who} isn't verified yet. Compare \
         security codes with {who} in person (`raven contact verify --address {}`).",
        encode_address(peer)
    )
}

/// `raven lan off` (Phase 3, D7) for a send: what node_policy.json says now
/// (an unreadable file keeps off the local network, owner decision), and the
/// switch of this process set to it ([`raven_core::set_lan_user_off`]). Read
/// again at each send, so the terminal app, which stays open, follows a
/// `raven lan on|off` typed in another terminal. Once the meeting time of
/// `raven lan on --for` is over (P3.C2) LAN is off as raven-node has it; a
/// meeting time ash cannot read now (the at-rest key) is left to raven-node,
/// and one that will never open (damaged, another profile's) is off, as
/// raven-node holds it until `raven lan on` replaces it.
pub(crate) fn lan_off_now(data_dir: &Path) -> bool {
    let off = lan_off_at(
        raven_core::node_policy::try_load_policy(data_dir)
            .map(|p| p.lan_off)
            .ok(),
        &raven_core::lan_meeting::load_until(data_dir),
        raven_core::clock::now_ms(),
    );
    raven_core::set_lan_user_off(off);
    off
}

/// ash's security sink (Phase 6b, step P6.25), kept so the process can
/// write what is pending before it exits ([`flush_security_sink`]).
static SECURITY_SINK: std::sync::OnceLock<raven_core::security_ledger::DirectSink> =
    std::sync::OnceLock::new();

/// Register ash's sink for `data_dir` while the security events gate is
/// live (design A §3): each event this process notes (a refused key change,
/// what raven-core's paths sense) goes straight into the profile's security
/// ledger, best effort; a profile that is not sealed keeps none. Nothing
/// while the gate is shut: no sink, no file.
pub(crate) fn start_security_sink(data_dir: &Path) {
    if !raven_core::security_sense::live() {
        return;
    }
    let sink = SECURITY_SINK
        .get_or_init(|| raven_core::security_ledger::DirectSink::new(data_dir))
        .clone();
    raven_core::security_events::set_sink(Box::new(sink));
}

/// Write what ash's sink holds now (the ledger writes one event per kind
/// and subject at once, later ones a minute apart): at the end of a
/// command, and before an exit on an error.
pub(crate) fn flush_security_sink() {
    if let Some(sink) = SECURITY_SINK.get() {
        sink.flush();
    }
}

/// [`lan_off_now`] from what was read: `lan_off` (`None`: node_policy.json
/// cannot be read, so off) and the meeting time at `now_ms` (an error that
/// `AtRestError::is_unavailable` says may pass: raven-node decides; any
/// other: off, as raven-node has it).
fn lan_off_at(
    lan_off: Option<bool>,
    meeting: &Result<Option<u64>, raven_core::at_rest::AtRestError>,
    now_ms: u64,
) -> bool {
    lan_off.unwrap_or(true)
        || match meeting {
            Ok(until) => !raven_core::lan_meeting::lan_on_at(false, *until, now_ms),
            Err(e) => !e.is_unavailable(),
        }
}

/// The probe error of a LAN route while `raven lan off` holds: raven-node's
/// own refusal of a LAN dial, in its words.
fn lan_off_probe_error() -> String {
    format!(
        "{}: raven lan off is in effect (raven lan on)",
        raven_core::LAN_OFF
    )
}

/// What a send says while `raven lan off` holds and it has LAN routes: none
/// is dialled. `others`: it has routes on other carriers, which it tries.
fn lan_off_send_note(who: &str, others: bool) -> String {
    format!(
        "{}: LAN is off on this computer, so RAVEN does not connect to {who} on your \
         network{} (`raven lan on` turns LAN back on).",
        raven_core::LAN_OFF,
        if others {
            format!(" and tries {who}'s other addresses")
        } else {
            String::new()
        }
    )
}

/// The routes to dial for this send ([`local_dial_routes`]). While `raven lan
/// off` holds (`lan_off`) every LAN route is kept as planned and comes back
/// with the LAN_OFF probe error, so it is never dialled: the send goes over
/// another carrier, or the message waits for `raven lan on` where it can be
/// queued (raven-node's worker skips LAN while it is off). A saved name is
/// not even resolved (a `.local` name asks the network); a literal address
/// still gets the unverified-contact check, which asks nothing.
fn send_dial_routes(
    data_dir: &Path,
    routes: &[super::pair_init_lab::DialRoute],
    peer: &[u8; 32],
    ctx: &SendCtx,
    lan_off: bool,
) -> Result<LocalDialRoutes, String> {
    use super::pair_init_lab::DialCarrier;
    if !lan_off {
        return local_dial_routes(data_dir, routes, peer, ctx);
    }
    let lan = |r: &super::pair_init_lab::DialRoute| r.carrier == DialCarrier::Lan;
    // The routes that are checked: every other carrier's, and the literal
    // LAN addresses (their check reads nothing from the network).
    let checked: Vec<usize> = (0..routes.len())
        .filter(|&i| {
            !lan(&routes[i])
                || routes[i]
                    .dial
                    .trim()
                    .parse::<std::net::SocketAddr>()
                    .is_ok()
        })
        .collect();
    let picked: Vec<_> = checked.iter().map(|&i| routes[i].clone()).collect();
    let (dialled, unresolved) = local_dial_routes(data_dir, &picked, peer, ctx)?;
    let mut out: Vec<_> = routes
        .iter()
        .map(|r| super::pair_init_lab::DialRoute {
            carrier: r.carrier,
            dial: r.dial.trim().to_string(),
        })
        .collect();
    for (&i, route) in checked.iter().zip(dialled) {
        if !lan(&routes[i]) {
            out[i] = route;
        }
    }
    let mut known: Vec<(usize, String)> = (0..routes.len())
        .filter(|&i| lan(&routes[i]))
        .map(|i| (i, lan_off_probe_error()))
        .collect();
    known.extend(
        unresolved
            .into_iter()
            .map(|(j, e)| (checked[j], e))
            .filter(|(i, _)| !lan(&routes[*i])),
    );
    Ok((out, known))
}

/// The send path dials through the local raven-node service: refuse with the
/// reason when it is not running and cannot be started. A service that runs but
/// does not answer is reported as that, in its own words (they already say what to
/// do), not wrapped in "could not be started": that would be the opposite of the
/// truth. So is a profile `raven lock` stopped (PP.15): nothing was tried.
fn require_local_daemon(data_dir: &Path) -> Result<(), String> {
    ensure_mac_lan_daemon(data_dir).map_err(|e| {
        if e.starts_with(SERVICE_UNRESPONSIVE_PREFIX)
            || e == raven_core::privacy::LOCKED_TEXT
            || e == raven_core::erase::UNFINISHED_TEXT
        {
            format!("NOT SENT, nothing queued: {e}")
        } else {
            format!("local raven-node service is not running and could not be started: {e}")
        }
    })?;
    // Lock now v2 (Phase 6 P6.40): a raven-node that runs locked sends
    // nothing, so nothing is staged for it either (as with Lock now v1).
    if node_runs_locked(data_dir) {
        return Err(format!(
            "NOT SENT, nothing queued: {}",
            raven_core::privacy::LOCKED_V2_TEXT
        ));
    }
    Ok(())
}

/// Lock v2 (P6.40): this profile's raven-node answers that it is locked.
/// Asked only while the local-protection gate is live in this build (a
/// release build asks nothing more).
pub(super) fn node_runs_locked(data_dir: &Path) -> bool {
    raven_core::security_gate::live(raven_core::security_gate::SecGate::LocalProtection)
        && matches!(
            super::ipc_client::ipc_request_timeout(
                data_dir,
                &raven_core::ipc::IpcRequest::status(),
                std::time::Duration::from_secs(3),
            ),
            Ok(raven_core::ipc::IpcResponse::Status {
                locked: Some(true),
                ..
            })
        )
}

// ── Outbox: what raven-node is still trying to deliver ────────────────────

/// What `raven outbox` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboxCmd {
    List {
        contact_pub_hex: Option<String>,
    },
    Status {
        mid: String,
    },
    Retry {
        mid: String,
    },
    Cancel {
        mid: String,
        yes: bool,
    },
    /// `raven outbox hand-off`: leave undelivered messages with a friend now.
    HandOff {
        contact_pub_hex: Option<String>,
    },
}

/// Rows `raven outbox list` asks for (the IPC cap).
const OUTBOX_LIST_LIMIT: u16 = raven_core::ipc::MAX_OUTBOX_LIST;

/// Messages each contact still has waiting in raven-node's outbox (queued,
/// sent or held; receipts not counted), by key (lowercase hex): one
/// `OutboxList`. Empty when no (new enough) raven-node answers.
pub(crate) fn live_outbox_counts(data_dir: &Path) -> LiveOutbox {
    let req = IpcRequest::OutboxList {
        v: IPC_VERSION,
        peer_pub_hex: None,
        limit: Some(OUTBOX_LIST_LIMIT),
    };
    let mut live = LiveOutbox::default();
    if let Ok(IpcResponse::OutboxListResult { items, .. }) =
        super::ipc_client::ipc_request_timeout(data_dir, &req, Duration::from_secs(2))
    {
        for item in items.iter().filter(|i| {
            i.kind != "ack" && matches!(i.state.as_str(), "queued" | "sent" | "held" | "waiting")
        }) {
            let peer = item.peer_pub_hex.trim().to_ascii_lowercase();
            if let Some(code) = lan_failure_code(item) {
                live.lan_failed.insert(peer.clone(), code);
            }
            *live.counts.entry(peer).or_default() += 1;
        }
    }
    live
}

/// What raven-node's outbox holds now, per contact (lowercase key hex).
#[derive(Debug, Default)]
pub(crate) struct LiveOutbox {
    /// Messages waiting.
    pub(crate) counts: std::collections::HashMap<String, usize>,
    /// The code of a waiting message whose last try failed on the LAN as a
    /// dial does ([`lan_failure_code`]).
    pub(crate) lan_failed: std::collections::HashMap<String, &'static str>,
}

/// A waiting message's last try failed on the LAN as a dial does (nobody
/// answered, nobody was receiving, it hung up): its code. raven-node keeps
/// that one over a p2p dial whose reason only says the contact's direct
/// addresses did not answer, as `raven send` says it (E1).
fn lan_failure_code(item: &raven_core::ipc::OutboxItem) -> Option<&'static str> {
    if item.carrier != "lan_dial" {
        return None;
    }
    ["NOT_LISTENING", "NOT_REACHABLE", "CLOSED_EARLY"]
        .into_iter()
        .find(|code| item.last_error_code == *code)
}

/// The outbox as raven-node sees it, or as the store holds it at `now` when no
/// service answers (then nothing is retrying it: `worker_running` is false).
fn outbox_items(
    data_dir: &Path,
    peer: Option<&str>,
    now: u64,
) -> Result<(bool, Vec<raven_core::ipc::OutboxItem>), String> {
    let req = IpcRequest::OutboxList {
        v: IPC_VERSION,
        peer_pub_hex: peer.map(str::to_string),
        limit: Some(OUTBOX_LIST_LIMIT),
    };
    if let Ok(IpcResponse::OutboxListResult {
        worker_running,
        items,
        ..
    }) = super::ipc_client::ipc_request(data_dir, &req)
    {
        let mut items = items;
        with_message_deadlines(data_dir, &mut items);
        return Ok((worker_running, items));
    }
    // No (new enough) service: read the store directly. Read only.
    let store = raven_core::IndexedSessionStore::open(data_dir)
        .map_err(|e| format!("outbox: {}", e.redacted_display()))?;
    let want = peer.and_then(|p| parse_pub_hex(p).ok());
    // Queued while the peer was unreachable and never written: still "queued".
    // Read as evidence, past its deadline too, as raven-node's `scan_store`
    // does: the live records alone would call it written once it ran out.
    let records = raven_core::outbox::object_route_evidence(data_dir, now).unwrap_or_default();
    let mut items = Vec::new();
    for (rows, state) in [
        (
            store.pending_endpoint_outbound_for_recipient(want.as_ref()),
            "queued",
        ),
        (
            store.awaiting_ack_endpoint_outbound_for_recipient(want.as_ref()),
            "sent",
        ),
    ] {
        for row in rows.map_err(|e| format!("outbox: {}", e.redacted_display()))? {
            items.push(raven_core::ipc::OutboxItem {
                message_id_hex: hex::encode(row.message_id),
                peer_pub_hex: hex::encode(row.recipient_device),
                kind: match row.kind {
                    raven_core::EndpointOutboundKind::Message => "message".into(),
                    raven_core::EndpointOutboundKind::Ack => "ack".into(),
                },
                state: if records.get(&row.message_id).is_some_and(|r| r.unsent) {
                    "queued".into()
                } else {
                    state.into()
                },
                expires_at_ms: Envelope::unpack(&row.immutable_envelope_bytes)
                    .map(|e| e.expires_at)
                    .unwrap_or(0),
                ..Default::default()
            });
        }
    }
    // Parked messages (the long message horizon, lab only), as raven-node
    // lists them: `waiting` until their own deadline.
    if raven_core::horizon::horizon_live_enabled() {
        let peers = match want {
            Some(p) => vec![p],
            None => store
                .parked_peers()
                .map_err(|e| format!("outbox: {}", e.redacted_display()))?
                .into_iter()
                .map(|p| p.peer)
                .collect(),
        };
        for p in peers {
            for row in store
                .parked_for_recipient(&p)
                .map_err(|e| format!("outbox: {}", e.redacted_display()))?
            {
                items.push(raven_core::ipc::OutboxItem {
                    message_id_hex: hex::encode(row.message_id),
                    peer_pub_hex: hex::encode(p),
                    kind: "message".into(),
                    state: "waiting".into(),
                    expires_at_ms: row.deadline_ms,
                    ..Default::default()
                });
            }
        }
    }
    with_message_deadlines(data_dir, &mut items);
    Ok((false, items))
}

/// The full message id for a prefix the user typed (8+ hex, as `mid=` and the
/// history show it): among the outbox and the outbound history. Unique or an
/// error.
fn resolve_outbox_mid(
    data_dir: &Path,
    typed: &str,
    items: &[raven_core::ipc::OutboxItem],
) -> Result<[u8; 16], String> {
    let want = typed
        .trim()
        .trim_end_matches('…')
        .trim_end_matches("...")
        .to_ascii_lowercase();
    if want.len() < 8 || want.len() > 32 || !want.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "message id {} must be 8 to 32 hex characters (the id `raven outbox list` shows)",
            sanitize_terminal_line(typed)
        ));
    }
    let mut hits: Vec<String> = items
        .iter()
        .filter(|i| matches!(i.kind.as_str(), "message" | "app"))
        .map(|i| i.message_id_hex.to_ascii_lowercase())
        .collect();
    if let Ok(history) = ChatHistory::load(data_dir) {
        hits.extend(
            history
                .entries
                .iter()
                .filter(|e| e.direction == "out")
                .map(|e| e.message_id_hex.to_ascii_lowercase()),
        );
    }
    hits.retain(|m| m.starts_with(&want));
    hits.sort_unstable();
    hits.dedup();
    match hits.as_slice() {
        [one] => hex::decode(one)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| "message id is not valid hex".to_string()),
        [] => Err(format!(
            "no message {} you sent on this profile (see `raven outbox list`)",
            sanitize_terminal_line(&want)
        )),
        many => Err(format!(
            "{} messages start with {}: type more of the id",
            many.len(),
            sanitize_terminal_line(&want)
        )),
    }
}

/// `"first words…"` of one of our staged messages (local only; never sent
/// over IPC), or nothing.
fn outbox_preview(data_dir: &Path, message_id: &[u8; 16]) -> String {
    raven_core::load_staged_outbound_body(data_dir, message_id)
        .ok()
        .flatten()
        .map(|s| quoted_preview(&s.body))
        .unwrap_or_default()
}

/// The line under a contact in `raven contact list` (cutoff pack CP.6): how
/// long a message written now could wait for `who`, or why none can.
pub(crate) fn queue_reach_line(
    who: &str,
    reach: raven_core::outbox::QueueReach,
    now_ms: u64,
) -> String {
    queue_reach_words(
        who,
        reach,
        |at| until_text(at, now_ms),
        |at| ended_text(at, now_ms),
    )
}

/// How long a message written to `peer` now could wait for them: the one
/// rule `raven contact list`, the terminal app and the desktop apps share
/// (E1: the terminal app said "until tomorrow" where the app's Routes said
/// "up to 7 days"). With the long message horizon live (Phase 5a, P5.8) its
/// own deadline, [`raven_core::horizon::MESSAGE_HORIZON_MS`] from now, a
/// secure connection or not: RAVEN parks a message whose envelope runs out
/// and seals it again, and sets up a new connection first when none is left.
/// Otherwise the session store's answer (cutoff pack CP.6), from `reader`
/// (the profile's session metadata), which is never read while the horizon
/// is live.
pub(crate) fn away_reach_with(
    reader: Option<&raven_core::indexed_session_store::SessionMetadataReader>,
    peer: &[u8; 32],
    now_ms: u64,
) -> Result<raven_core::outbox::QueueReach, String> {
    if raven_core::horizon::horizon_live_enabled() {
        return Ok(raven_core::outbox::QueueReach::CanWait {
            until_ms: raven_core::horizon::message_deadline(now_ms),
        });
    }
    raven_core::outbox::queue_reach_with(reader, peer, now_ms)
}

/// [`away_reach_with`], opening the profile's session metadata only when it
/// is needed (and only when it exists: a fresh profile's store is never
/// created here).
pub(crate) fn away_reach(
    data_dir: &Path,
    peer: &[u8; 32],
    now_ms: u64,
) -> Result<raven_core::outbox::QueueReach, String> {
    if raven_core::horizon::horizon_live_enabled() {
        return away_reach_with(None, peer, now_ms);
    }
    raven_core::outbox::queue_reach(data_dir, peer, now_ms)
}

/// The line under a contact in `raven contact list` for [`away_reach`]'s
/// answer: with the long message horizon live it says how many days that
/// is, since every message gets them (P5.8).
pub(crate) fn away_line(who: &str, reach: raven_core::outbox::QueueReach, now_ms: u64) -> String {
    match reach {
        raven_core::outbox::QueueReach::CanWait { until_ms }
            if raven_core::horizon::horizon_live_enabled() =>
        {
            horizon_reach_words(who, &until_text(until_ms, now_ms))
        }
        reach => queue_reach_line(who, reach, now_ms),
    }
}

/// When a waiting message of yours runs out for good, by the rule raven-node's
/// outbox applies: with the long message horizon live (Phase 5a) its own
/// deadline, [`raven_core::horizon::MESSAGE_HORIZON_MS`] after it was written
/// (`written_ms`), since an envelope that runs out first only parks it
/// ([`raven_core::outbox::park_or_give_up_expired`]) and raven-node seals it
/// again; otherwise its envelope's expiry. raven-node lists a queued, sent or
/// held message with its envelope's expiry (E1: `raven outbox` said "expires
/// tomorrow" where the horizon keeps it 7 days). A copy friends hold keeps
/// the copy's own expiry, a parked (`waiting`) row its deadline, and a row
/// whose written time isn't known what raven-node said.
pub fn waits_until(item: &raven_core::ipc::OutboxItem, written_ms: Option<u64>) -> u64 {
    match written_ms.filter(|ms| *ms > 0) {
        Some(written) if horizon_keeps(item) => raven_core::horizon::message_deadline(written),
        _ => item.expires_at_ms,
    }
}

/// A row the long message horizon keeps past its envelope: a message of
/// yours still queued, sent or held, that no friend holds, while the horizon
/// is live.
fn horizon_keeps(item: &raven_core::ipc::OutboxItem) -> bool {
    item.kind == "message"
        && matches!(item.state.as_str(), "queued" | "sent" | "held")
        && item.in_custody == 0
        && raven_core::horizon::horizon_live_enabled()
}

/// [`waits_until`] over a list of raven-node's (or the store's) rows, each
/// message's written time read as the outbox reads it
/// ([`raven_core::horizon::deadline_for`]: its stage, else its history row),
/// so `raven outbox`, `raven status` and the terminal app name the time the
/// outbox applies. Nothing is read while the horizon is off.
pub(crate) fn with_message_deadlines(data_dir: &Path, items: &mut [raven_core::ipc::OutboxItem]) {
    for item in items.iter_mut().filter(|item| horizon_keeps(item)) {
        let ids = (
            parse_pub_hex(&item.peer_pub_hex).ok(),
            hex::decode(&item.message_id_hex)
                .ok()
                .and_then(|b| <[u8; 16]>::try_from(b).ok()),
        );
        let (Some(peer), Some(mid)) = ids else {
            continue;
        };
        if let Some((written, _)) = raven_core::horizon::deadline_for(data_dir, &peer, &mid) {
            item.expires_at_ms = waits_until(item, Some(written));
        }
    }
}

fn horizon_reach_words(who: &str, until: &str) -> String {
    format!(
        "If {who} is away, Raven keeps trying for up to {} days (until {until}).",
        raven_core::horizon::MESSAGE_HORIZON_MS / raven_core::horizon::DAY_MS
    )
}

fn queue_reach_words(
    who: &str,
    reach: raven_core::outbox::QueueReach,
    until: impl Fn(u64) -> String,
    ended: impl Fn(u64) -> String,
) -> String {
    use raven_core::outbox::QueueReach;
    match reach {
        QueueReach::CanWait { until_ms } => {
            format!(
                "If {who} is away, Raven keeps trying until {}.",
                until(until_ms)
            )
        }
        QueueReach::Ended { at_ms } => format!(
            "To write to {who}, meet first: RAVEN can't hold new messages for {who} now (the \
             secure connection ended {}).",
            ended(at_ms)
        ),
        QueueReach::NeverPaired => first_message_rule(who),
    }
}

/// `raven status`'s first line while messages wait (cutoff pack CP.6):
/// `Waiting messages: 2 (the oldest can wait until today 14:05 (in about 3
/// h)).` None when none wait, or when that is not known. Reads raven-node's
/// outbox, else the session store, and only when the profile has one (a
/// fresh profile's store is never created here).
pub(crate) fn waiting_messages_line(data_dir: &Path, now_ms: u64) -> Option<String> {
    let store = data_dir.join(raven_core::indexed_session_store::INDEXED_SESSION_METADATA_FILE);
    if !store.is_file() {
        return None;
    }
    let (_, items) = outbox_items(data_dir, None, now_ms).ok()?;
    waiting_words(&items, now_ms, |at| until_text(at, now_ms))
}

/// A row still listed as waiting whose deadline passed at `now` (raven-node
/// is down, or has not settled it yet) waits no longer: it is counted apart
/// and never named as the next to run out (review C-time-deadlines-4). One a
/// carrier already wrote (`sent`: only the confirmation is missing) may have
/// arrived, so it is never said to be "not sent" (review FU-4).
fn waiting_words(
    items: &[raven_core::ipc::OutboxItem],
    now: u64,
    until: impl Fn(u64) -> String,
) -> Option<String> {
    let (ran_out, waiting): (Vec<_>, Vec<_>) = items
        .iter()
        .filter(|i| {
            i.kind == "message"
                && matches!(i.state.as_str(), "queued" | "sent" | "held" | "waiting")
        })
        .partition(|i| i.expires_at_ms > 0 && i.expires_at_ms <= now);
    let n = waiting.len();
    let unconfirmed = ran_out.iter().filter(|i| i.state == "sent").count();
    let unsent = ran_out.len() - unconfirmed;
    let line = match waiting
        .iter()
        .map(|i| i.expires_at_ms)
        .filter(|at| *at > 0)
        .min()
    {
        _ if n == 0 && ran_out.is_empty() => return None,
        _ if n == 0 => {
            return Some(format!(
                "Waiting messages: none ({}).",
                ran_out_words(unsent, unconfirmed, "")
            ))
        }
        Some(at) => format!(
            "Waiting messages: {n} (the oldest can wait until {}).",
            until(at)
        ),
        None => format!("Waiting messages: {n}."),
    };
    Some(if ran_out.is_empty() {
        line
    } else {
        format!("{line} {}.", ran_out_words(unsent, unconfirmed, " more"))
    })
}

/// [`waiting_words`]' rows past their deadline: `unsent` never written
/// (they will not be sent), `unconfirmed` written but not confirmed in time
/// (they may have arrived). `more`: " more" after the waiting count.
fn ran_out_words(unsent: usize, unconfirmed: usize, more: &str) -> String {
    let unsent =
        (unsent > 0).then(|| format!("{unsent}{more} ran out of time and will not be sent"));
    let unconfirmed = (unconfirmed > 0).then(|| {
        let were = if unconfirmed == 1 { "was" } else { "were" };
        format!("{unconfirmed}{more} {were} sent but not confirmed in time and may have arrived")
    });
    [unsent, unconfirmed]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("; ")
}

/// How long after it was written `raven outbox list` still shows a message
/// the history says ran out of time (its deadline is at most a day later).
const RAN_OUT_LISTED_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// `raven outbox list`'s rows for messages the history says ran out of time
/// (`expired`) that `items` does not list: raven-node keeps its finished
/// rows in memory only, and after a restart past the deadline the prune may
/// settle a message before its worker ever sees it (review FU-1,
/// C-time-deadlines-2), although the queued text promises `raven outbox
/// list` says so. Written in the last [`RAN_OUT_LISTED_MS`], to `peer` when
/// given; newest first. The history keeps no deadline, so none is shown.
fn ran_out_from_history(
    history: &[raven_core::chat_history::ChatHistoryEntry],
    items: &[raven_core::ipc::OutboxItem],
    peer: Option<&str>,
    now: u64,
) -> Vec<raven_core::ipc::OutboxItem> {
    let listed: std::collections::HashSet<String> = items
        .iter()
        .map(|i| i.message_id_hex.to_ascii_lowercase())
        .collect();
    let mut rows: Vec<_> = history
        .iter()
        .filter(|e| e.direction == "out" && e.delivery == "expired")
        .filter(|e| e.created_at_ms.saturating_add(RAN_OUT_LISTED_MS) > now)
        .filter(|e| peer.is_none_or(|p| e.peer_pub_hex.trim().eq_ignore_ascii_case(p.trim())))
        .filter(|e| !listed.contains(&e.message_id_hex.to_ascii_lowercase()))
        .collect();
    rows.sort_by_key(|e| std::cmp::Reverse(e.created_at_ms));
    rows.into_iter()
        .map(|e| raven_core::ipc::OutboxItem {
            message_id_hex: e.message_id_hex.to_ascii_lowercase(),
            peer_pub_hex: e.peer_pub_hex.trim().to_ascii_lowercase(),
            kind: "message".into(),
            state: "expired".into(),
            ..raven_core::ipc::OutboxItem::default()
        })
        .collect()
}

/// Why an expired message was given up when it never left this computer:
/// no carrier wrote it and no friend held a copy (cutoff pack CP.6). Reads
/// after "status failed: your earlier message ... to {who}:" too.
pub(crate) fn time_ran_out_text(who: &str) -> String {
    format!(
        "time ran out before {who} could be reached: it never left this computer (send it again \
         when you are together)"
    )
}

/// "held by 2 friends until today 14:05 (in about 3 h), not delivered yet":
/// friends that hold a sealed copy of a waiting message (friend custody,
/// `OutboxItem::in_custody`) and until when they keep it at the latest (the
/// envelope's expiry, local time; P3.C4). No time without one, or once it
/// passed.
pub(crate) fn held_by_friends_text(n: u8, expires_at_ms: u64, now: u64) -> String {
    let until = if expires_at_ms > now {
        format!(" until {}", until_text(expires_at_ms, now))
    } else {
        String::new()
    };
    format!(
        "held by {n} friend{}{until}, not delivered yet",
        if n == 1 { "" } else { "s" }
    )
}

/// Why an expired message that friends held was not delivered: time ran
/// out before the recipient collected it (P3.C4). Which friends held it is
/// not kept once it expired (review FU-3), so they are counted, not named.
pub(crate) fn custody_ran_out_text(who: &str, friends: u8, expired_at_ms: u64, now: u64) -> String {
    let friend = if friends <= 1 {
        "the friend who held it".to_string()
    } else {
        format!("the {friends} friends who held it")
    };
    let when = if expired_at_ms == 0 {
        String::new()
    } else {
        format!(" {}", ended_text(expired_at_ms, now))
    };
    format!("time ran out: {who} didn't collect it from {friend} before it expired{when}")
}

/// Why an expired message was not delivered when a friend that held it
/// passed it on to `who`'s own friend (custody handoff,
/// `OutboxItem::custody_forwarded`): no receipt came back, which does not
/// say that `who` did not collect it, since the receipt comes back through
/// friends only if `who` verified your friend too (review handoff-3: "didn't
/// collect it" could be false, and invite a second copy). Counted, not
/// named, as [`custody_ran_out_text`].
pub(crate) fn custody_unconfirmed_text(
    who: &str,
    friends: u8,
    expired_at_ms: u64,
    now: u64,
) -> String {
    let friend = if friends <= 1 {
        "the friend who held it".to_string()
    } else {
        format!("the {friends} friends who held it")
    };
    let when = if expired_at_ms == 0 {
        String::new()
    } else {
        format!(" {}", ended_text(expired_at_ms, now))
    };
    format!(
        "time ran out before delivery was confirmed: {friend} passed it on to {who}'s friend, \
         and no receipt came back before it expired{when} ({who} may have it)"
    )
}

/// The text for an expired message friends held (`item.in_custody > 0`):
/// [`custody_unconfirmed_text`] when one of them passed it on, else
/// [`custody_ran_out_text`].
fn custody_expired_text(who: &str, item: &raven_core::ipc::OutboxItem, now: u64) -> String {
    if item.custody_forwarded {
        custody_unconfirmed_text(who, item.in_custody, item.expires_at_ms, now)
    } else {
        custody_ran_out_text(who, item.in_custody, item.expires_at_ms, now)
    }
}

/// "in 40 s" / "now" / "-" for the next scheduled attempt.
fn next_try_text(next_attempt_ms: u64, now: u64) -> String {
    if next_attempt_ms == 0 {
        "-".into()
    } else if next_attempt_ms <= now {
        "now".into()
    } else {
        let secs = (next_attempt_ms - now).div_ceil(1000);
        if secs < 120 {
            format!("in {secs} s")
        } else {
            format!("in {} min", secs.div_ceil(60))
        }
    }
}

/// The state column of an outbox row: raven-node's word, but `held` for a
/// waiting message a friend holds a sealed copy of (E2 r9: the column said
/// "sent" while the same row said "held by 1 friend ..., not delivered
/// yet").
fn state_word(item: &raven_core::ipc::OutboxItem) -> String {
    let waiting = matches!(item.state.as_str(), "queued" | "sent" | "held");
    if waiting && item.in_custody > 0 {
        "held".into()
    } else {
        sanitize_terminal_line(&item.state)
    }
}

/// One `raven outbox list` row, without the history's previews.
#[cfg(test)]
fn outbox_row_line(data_dir: &Path, item: &raven_core::ipc::OutboxItem, now: u64) -> String {
    outbox_row_line_with(data_dir, item, now, &HistoryPreviews::new())
}

/// The sent messages' previews in the chat history, by message id (lower
/// hex): what a row whose staged body is gone (delivered, given up) shows
/// (E2 r40: `raven outbox`'s "recently finished" rows had no label). Group
/// copies included: each member's row has its own message id.
type HistoryPreviews = std::collections::HashMap<String, String>;

fn history_previews(history: &ChatHistory) -> HistoryPreviews {
    history
        .entries
        .iter()
        .filter(|e| e.direction == "out")
        .map(|e| {
            let text = if e.body.is_empty() {
                &e.preview
            } else {
                &e.body
            };
            (e.message_id_hex.to_ascii_lowercase(), quoted_preview(text))
        })
        .filter(|(_, preview)| !preview.is_empty())
        .collect()
}

/// [`outbox_row_line`], with the history's previews for rows whose staged
/// body is gone.
fn outbox_row_line_with(
    data_dir: &Path,
    item: &raven_core::ipc::OutboxItem,
    now: u64,
    previews: &HistoryPreviews,
) -> String {
    let mid: [u8; 16] = hex::decode(&item.message_id_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .unwrap_or([0; 16]);
    let who = send_ctx(data_dir, "", "", &item.peer_pub_hex).who();
    let what = if item.kind == "ack" {
        "receipt for a message from".to_string()
    } else if item.kind == "app" {
        // RDAP's agent payload: no chat preview exists, and none is shown.
        "agent payload (RDAP) to".to_string()
    } else {
        let mut preview = outbox_preview(data_dir, &mid);
        if preview.is_empty() {
            preview = previews
                .get(&item.message_id_hex.to_ascii_lowercase())
                .cloned()
                .unwrap_or_default();
        }
        format!("message{} to", spaced(&preview))
    };
    let mut line = format!(
        "  {}  {:<9} {what} {who}",
        &item.message_id_hex[..8.min(item.message_id_hex.len())],
        state_word(item)
    );
    if item.attempts > 0 {
        line.push_str(&format!("  attempts {}", item.attempts));
    }
    if !item.last_error_code.is_empty() {
        line.push_str(&format!("  last: {}", last_error_words(item, &who)));
    }
    if item.next_attempt_ms > 0 {
        line.push_str(&format!(
            "  next try {}",
            next_try_text(item.next_attempt_ms, now)
        ));
    }
    let waiting = matches!(item.state.as_str(), "queued" | "sent" | "held");
    let held = waiting && item.in_custody > 0;
    if held {
        line.push_str(&format!(
            "  {}",
            held_words(
                item.in_custody,
                item.expires_at_ms,
                keeps_trying_until(data_dir, item),
                now
            )
        ));
    }
    if item.state == "expired" && item.never_sent {
        line.push_str(&format!("  {}", time_ran_out_text(&who)));
    } else if item.state == "expired" && item.in_custody > 0 {
        line.push_str(&format!("  {}", custody_expired_text(&who, item, now)));
    } else if let Some((word, when)) = deadline_part(item, now) {
        // "held by N friends until …" names that time already.
        if !(held && word == "expires") {
            line.push_str(&format!("  {word} {when}"));
        }
    }
    if !item.path.is_empty() && matches!(item.state.as_str(), "sent" | "delivered") {
        line.push_str(&format!("  via {}", sanitize_terminal_line(&item.path)));
    }
    line
}

/// A delivery at least this long after the message was written is a late
/// one: the apps and `raven outbox` say when it came (E1: a message that
/// waited an hour said only "Delivered").
pub const LATE_DELIVERY_MS: u64 = 60_000;

/// A time for every row of `finished` (raven-node's recently finished rows,
/// newest first, as it lists them), by message id (E2 r9: only the last row
/// had one): a delivered message's arrival (raven-node keeps each one's own,
/// `delivered_at_ms`; from an older raven-node the newest delivered message
/// to each friend is its last delivery to them, whose age its Status keeps
/// in `last_paths`), else when it was written (`written`, from the history).
/// An expired row with a deadline says when it ran out already
/// ([`deadline_part`]), and gets nothing here.
fn finished_times(
    finished: &[&raven_core::ipc::OutboxItem],
    last_paths: &[raven_core::ipc::ContactPath],
    written: &std::collections::HashMap<String, u64>,
    now: u64,
) -> std::collections::HashMap<String, (&'static str, u64)> {
    let mut seen = std::collections::HashSet::new();
    let mut times = std::collections::HashMap::new();
    for item in finished {
        let mid = item.message_id_hex.to_ascii_lowercase();
        if item.state == "expired" && item.expires_at_ms > 0 {
            continue;
        }
        let mut arrived = None;
        if item.kind == "message" && item.state == "delivered" {
            let peer = item.peer_pub_hex.trim().to_ascii_lowercase();
            if item.delivered_at_ms > 0 {
                arrived = Some(item.delivered_at_ms);
            } else if seen.insert(peer.clone()) {
                arrived = last_paths
                    .iter()
                    .find(|p| p.peer_pub_hex.trim().eq_ignore_ascii_case(&peer))
                    .map(|p| now.saturating_sub(p.age_s.saturating_mul(1000)));
            }
        }
        match (arrived, written.get(&mid)) {
            (Some(at), _) => {
                times.insert(mid, ("arrived", at));
            }
            (None, Some(&w)) if w > 0 => {
                times.insert(mid, ("written", w));
            }
            _ => {}
        }
    }
    times
}

/// An outbox row's deadline, never a past one as if still to come (review
/// C-time-deadlines-4): `expires today 14:05 (in about 3 h)` while it waits,
/// `ran out today at 09:00` once that time passed (an expired row, or a
/// waiting one raven-node has not settled yet). Nothing for a row that
/// finished another way (delivered, failed, cancelled, gone) or has no
/// deadline. A parked message (`waiting`, the long message horizon) shows
/// its own deadline: `waiting · until Mon 14:05 (in 6 days)`.
fn deadline_part(item: &raven_core::ipc::OutboxItem, now: u64) -> Option<(&'static str, String)> {
    let at = item.expires_at_ms;
    let parked = item.state == "waiting";
    let waiting = parked || matches!(item.state.as_str(), "queued" | "sent" | "held");
    if at == 0 || !(waiting || item.state == "expired") {
        return None;
    }
    Some(if parked && at > now {
        ("waiting ·", format!("until {}", until_text(at, now)))
    } else if waiting && at > now {
        ("expires", until_text(at, now))
    } else {
        ("ran out", ended_text_zoned(at, now))
    })
}

/// An outbox row's last error in words (E1: `last: MAILBOX_OFF` meant
/// nothing to a reader; `raven outbox status` keeps the code as `last
/// error`): a reset code's legend, the contact's reason for a contact that
/// could not be reached when raven-node gave one, else the terminal app's
/// words for the code, else the code as it came.
fn last_error_words(item: &raven_core::ipc::OutboxItem, who: &str) -> String {
    let code = item.last_error_code.trim();
    if let Some(meaning) = reset_code_legend(code) {
        return meaning.into();
    }
    // E2 r40 #E: several ways tried and none answered: every way of the
    // last attempt, the same words whichever dial ended last.
    if let Some(words) = no_answer_on_ways(code, &item.tried, who) {
        return words;
    }
    if code == "NOT_REACHABLE" {
        if let Some(d) = Diag::find(&item.why) {
            return reach_legend(&d).into();
        }
    }
    super::tui::outbox_code_headline(code, who).unwrap_or_else(|| sanitize_terminal_line(code))
}

/// A waiting message's reason when its last attempt dialled several ways
/// (`tried`, carrier labels) and none answered (`code`): "Bob couldn't be
/// reached right now: no answer on the local network, over p2p or over
/// Tor" (as `raven send` says it). `None` for one way, or another reason.
fn no_answer_on_ways(code: &str, tried: &[String], who: &str) -> Option<String> {
    if !matches!(code, "NOT_REACHABLE" | "ONION_UNREACHABLE") {
        return None;
    }
    let ways = carrier_ways(tried);
    (ways.len() > 1).then(|| {
        format!(
            "{who} couldn't be reached right now: no answer {}",
            or_list(&ways)
        )
    })
}

/// Carrier labels (`lan_dial`, ...) as the ways a send names them, in the
/// fixed order [`ways_tried`] uses; unknown labels are left out.
fn carrier_ways(labels: &[String]) -> Vec<&'static str> {
    [
        ("lan_dial", "on the local network"),
        ("internet_dial", "directly"),
        ("p2p_dial", "over p2p"),
        ("nearby_dial", "over Bluetooth"),
        ("onion_dial", "over Tor"),
    ]
    .into_iter()
    .filter(|(label, _)| labels.iter().any(|l| l == label))
    .map(|(_, words)| words)
    .collect()
}

/// How the attempts of an outbox object ended, in a few words each
/// (`raven outbox status`'s attempts row, E2 r40 #D): "9 no answer, 1
/// delivered". Codes without words of their own show as they are.
fn attempt_outcome_words(outcomes: &[raven_core::ipc::AttemptCount]) -> String {
    outcomes
        .iter()
        .map(|o| {
            let what = match o.code.as_str() {
                "DELIVERED" => "delivered".to_string(),
                "NO_ACK_YET" => "written, no receipt".to_string(),
                "NOT_REACHABLE" | "ONION_UNREACHABLE" => "no answer".to_string(),
                "NOT_LISTENING" => "Raven not receiving".to_string(),
                "PEER_REFUSED" | "LINK_NOT_ACCEPTED" => "refused".to_string(),
                "CLOSED_EARLY" => "hung up".to_string(),
                "ONION_NOT_READY" => "Tor not ready here".to_string(),
                "NO_ROUTE" => "no route".to_string(),
                other => sanitize_terminal_line(other),
            };
            format!("{} {what}", o.count)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The way a delivered object went, in words (E2 r40 #D: `raven outbox
/// status` said "delivered" with no way): "over Tor", "over p2p
/// (hole_punched)". Empty when not known.
fn delivered_way(i: &raven_core::ipc::OutboxItem) -> String {
    let way = carrier_ways(std::slice::from_ref(&i.carrier))
        .first()
        .copied()
        .unwrap_or_default()
        .to_string();
    match (way.is_empty(), i.path.is_empty()) {
        (true, _) => String::new(),
        (false, true) => way,
        (false, false) => format!("{way} ({})", sanitize_terminal_line(&i.path)),
    }
}

/// `raven outbox status`: the worker's rows for one object.
fn outbox_status_rows(i: &raven_core::ipc::OutboxItem, now: u64) -> Vec<String> {
    let mut rows = Vec::new();
    if !i.carrier.is_empty() {
        rows.push(format!(
            "  carrier     {}",
            sanitize_terminal_line(&i.carrier)
        ));
    }
    // How the last p2p write travelled (empty for LAN and Internet direct).
    if !i.path.is_empty() {
        rows.push(format!("  path        {}", sanitize_terminal_line(&i.path)));
    }
    // The count alone (scripts and the harnesses read it); then, E2 r40
    // #D, the attempts by how they ended, and the ways the last one tried.
    rows.push(format!("  attempts    {}", i.attempts));
    if !i.outcomes.is_empty() {
        rows.push(format!(
            "  results     {}",
            attempt_outcome_words(&i.outcomes)
        ));
    }
    let ways = carrier_ways(&i.tried);
    if i.state == "delivered" {
        let way = delivered_way(i);
        if !way.is_empty() {
            rows.push(format!("  delivered   {way}"));
        }
    } else if !ways.is_empty() {
        rows.push(format!("  last tried  {}", and_list(&ways)));
    }
    rows.push(format!(
        "  next try    {}",
        next_try_text(i.next_attempt_ms, now)
    ));
    if !i.last_error_code.is_empty() {
        rows.push(format!(
            "  last error  {}",
            sanitize_terminal_line(&i.last_error_code)
        ));
    }
    if i.in_custody > 0 && matches!(i.state.as_str(), "queued" | "sent" | "held") {
        rows.push(format!(
            "  friends     {}",
            held_by_friends_text(i.in_custody, i.expires_at_ms, now)
        ));
    }
    if let Some((word, when)) = deadline_part(i, now) {
        rows.push(format!("  {word:<11} {when}"));
    }
    rows
}

/// A held message's words in `raven outbox list` (E2 r38): the friends'
/// copy and until when they keep it, then the message's own deadline when
/// it comes later ("held by 1 friend until Fri 30 Oct 10:05 (UTC), not
/// delivered yet; Raven keeps trying until Thu 5 Nov 10:03 (UTC)").
fn held_words(n: u8, copy_expires_at_ms: u64, keeps_until: Option<u64>, now: u64) -> String {
    let held = held_by_friends_text(n, copy_expires_at_ms, now);
    match keeps_until.filter(|&at| at > now) {
        Some(at) => format!("{held}; Raven keeps trying until {}", until_text(at, now)),
        None => held,
    }
}

/// `raven outbox status`'s `last error` row in words, the code after them
/// (E2 r38: "last error IN_CUSTODY" showed the raw code): "last error  a
/// friend's computer is holding a sealed copy for Bob (IN_CUSTODY)". A code
/// with no words stays as it is.
fn worded_last_error(rows: &mut [String], item: &raven_core::ipc::OutboxItem, who: &str) {
    let code = item.last_error_code.trim();
    if code.is_empty() {
        return;
    }
    let words = last_error_words(item, who);
    if words == sanitize_terminal_line(code) {
        return;
    }
    if let Some(row) = rows.iter_mut().find(|r| r.starts_with("  last error")) {
        *row = format!(
            "  last error  {} ({})",
            lower_first(&words),
            sanitize_terminal_line(code)
        );
    }
}

/// `s` with its first letter in lower case (a headline inside a row).
fn lower_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_lowercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// The message's own deadline (the long message horizon) for a waiting
/// message a friend holds a sealed copy of, when it comes after that
/// copy's expiry: Raven keeps trying until then itself (E2 r38: `raven send`
/// said "until Thu 5 Nov" and `raven outbox status` only "expires
/// tomorrow", the copy's). `None` otherwise.
fn keeps_trying_until(data_dir: &Path, item: &raven_core::ipc::OutboxItem) -> Option<u64> {
    let held = item.kind == "message"
        && matches!(item.state.as_str(), "queued" | "sent" | "held")
        && item.in_custody > 0;
    if !held || !raven_core::horizon::horizon_live_enabled() {
        return None;
    }
    let peer = parse_pub_hex(&item.peer_pub_hex).ok()?;
    let mid: [u8; 16] = hex::decode(&item.message_id_hex).ok()?.try_into().ok()?;
    let (written, _) = raven_core::horizon::deadline_for(data_dir, &peer, &mid)?;
    let deadline = raven_core::horizon::message_deadline(written);
    (deadline > item.expires_at_ms).then_some(deadline)
}

/// `extra` rows go right after `rows`' `last error` (at the end without
/// one).
fn after_last_error(rows: &mut Vec<String>, extra: Vec<String>) {
    let at = rows
        .iter()
        .position(|r| r.starts_with("  last error"))
        .map_or(rows.len(), |i| i + 1);
    rows.splice(at..at, extra);
}

/// What a session-reset outbox code means (design §16 legend), and the
/// pin store's code (M0), whose fix is on this computer.
fn reset_code_legend(code: &str) -> Option<&'static str> {
    Some(match code {
        "PIN_STORE_UNREADABLE" => {
            "RAVEN cannot read its noise pin file in its data folder (lan_noise_pins.json, or \
             lan_noise_pins.rms once the profile is encrypted) and connects to no one; \
             `ash doctor` says more"
        }
        "PEER_RESET" => {
            "the contact's RAVEN lost the secure connection; being sent again under a new one"
        }
        "PEER_RESET_CONFIRM" => "on hold: waiting for you to confirm (`raven outbox resend`)",
        "PEER_RESET_LOOP" => "on hold: too many connection resets today",
        "PEER_IDENTITY_FORK" => "on hold: the contact's identity may be in use twice",
        "PEER_RESET_NO_BODY" => "sealed by another app; it has to send it again",
        "RESEAL_CAP" => "given up after repeated connection resets",
        "PEER_RESET_WAIT_PREKEY" => "waiting for the contact to renew its keys",
        "PEER_RESET_CLOCK" => "the contact's clock is behind; it cannot renew its keys",
        _ => return None,
    })
}

/// `raven outbox list` with nothing waiting and nothing it still lists. It
/// never says why a message is not there (a first message that could not go
/// was never kept: its send said so, E1).
pub(crate) const NOTHING_WAITING: &str = "Nothing waiting to be sent.";

/// `raven outbox list` with nothing waiting: how many of the messages it
/// still lists were delivered and how many were given up (E1: "delivered or
/// given up" left a user unsure which), or [`NOTHING_WAITING`] when it lists
/// none (a first message that could not go was never kept, so it is neither).
fn nothing_waiting_line(delivered: usize, given_up: usize) -> String {
    let n = |count: usize| {
        if count == 1 {
            "1 message".to_owned()
        } else {
            format!("{count} messages")
        }
    };
    match (delivered, given_up) {
        (0, 0) => NOTHING_WAITING.to_owned(),
        (_, 0) => "Nothing waiting: every message you sent was delivered.".to_owned(),
        (0, g) => format!("Nothing waiting: {} given up (listed below).", n(g)),
        (d, g) => format!(
            "Nothing waiting: {} delivered, {} given up (listed below).",
            n(d),
            n(g)
        ),
    }
}

/// `raven outbox [list|status|retry|cancel]`.
pub fn cmd_outbox(data_dir: &Path, cmd: OutboxCmd) -> Result<(), String> {
    let now = now_ms();
    match cmd {
        OutboxCmd::List { contact_pub_hex } => {
            let (running, mut items) = outbox_items(data_dir, contact_pub_hex.as_deref(), now)?;
            // What ran out of time while nothing kept its row (review FU-1).
            let full_history = ChatHistory::load(data_dir).ok();
            let previews = full_history
                .as_ref()
                .map(history_previews)
                .unwrap_or_default();
            let history = full_history.map(ChatHistory::without_group_copies);
            if let Some(history) = &history {
                let ran_out =
                    ran_out_from_history(&history.entries, &items, contact_pub_hex.as_deref(), now);
                items.extend(ran_out);
            }
            let live: Vec<_> = items
                .iter()
                .filter(|i| matches!(i.state.as_str(), "queued" | "sent" | "held" | "waiting"))
                .collect();
            if live.is_empty() {
                let delivered = items.iter().filter(|i| i.state == "delivered").count();
                println!(
                    "{}",
                    nothing_waiting_line(delivered, items.len() - delivered)
                );
            } else {
                println!("{C_BOLD}outbox{C_RESET} ({} waiting)", live.len());
                for item in &live {
                    println!("{}", outbox_row_line_with(data_dir, item, now, &previews));
                }
            }
            let finished: Vec<_> = items
                .iter()
                .filter(|i| !matches!(i.state.as_str(), "queued" | "sent" | "held" | "waiting"))
                .take(10)
                .collect();
            if !finished.is_empty() {
                // A time on every row, with its zone (E1: a message that
                // waited an hour said only "delivered"; E2 r9: only the last
                // row had a time, and no zone).
                let written: std::collections::HashMap<String, u64> = history
                    .iter()
                    .flat_map(|h| &h.entries)
                    .filter(|e| e.direction == "out")
                    .map(|e| (e.message_id_hex.to_ascii_lowercase(), e.created_at_ms))
                    .collect();
                let old_node = finished
                    .iter()
                    .any(|i| i.state == "delivered" && i.delivered_at_ms == 0);
                let last_paths = if old_node {
                    match super::ipc_client::ipc_request_timeout(
                        data_dir,
                        &IpcRequest::status(),
                        Duration::from_secs(2),
                    ) {
                        Ok(IpcResponse::Status { last_paths, .. }) => last_paths,
                        _ => Vec::new(),
                    }
                } else {
                    Vec::new()
                };
                let times = finished_times(&finished, &last_paths, &written, now);
                println!("{C_DIM}recently finished:{C_RESET}");
                for item in finished {
                    let mut line = outbox_row_line_with(data_dir, item, now, &previews);
                    if let Some((word, at)) = times.get(&item.message_id_hex.to_ascii_lowercase()) {
                        line.push_str(&format!("  {word} {}", ended_text_zoned(*at, now)));
                    }
                    println!("{line}");
                }
            }
            if !running && !live.is_empty() {
                println!(
                    "{C_DIM}raven-node's outbox is not running, so nothing is retried right \
                     now: start it with `ash listen` (or send a message, which starts it).{C_RESET}"
                );
            }
            Ok(())
        }
        OutboxCmd::Status { mid } => {
            let (running, items) = outbox_items(data_dir, None, now)?;
            let message_id = resolve_outbox_mid(data_dir, &mid, &items)?;
            let mid_hex = hex::encode(message_id);
            let req = IpcRequest::OutboxStatus {
                v: IPC_VERSION,
                message_id_hex: mid_hex.clone(),
            };
            let item = match super::ipc_client::ipc_request(data_dir, &req) {
                Ok(IpcResponse::OutboxStatusResult { mut item, .. }) => {
                    with_message_deadlines(data_dir, std::slice::from_mut(&mut item));
                    Some(item)
                }
                _ => items.into_iter().find(|i| i.message_id_hex == mid_hex),
            };
            let history = ChatHistory::load(data_dir).ok().and_then(|h| {
                h.entries.into_iter().find(|e| {
                    e.direction == "out" && e.message_id_hex.eq_ignore_ascii_case(&mid_hex)
                })
            });
            let (peer_hex, state) = match (&item, &history) {
                (Some(i), _) => (i.peer_pub_hex.clone(), i.state.clone()),
                (None, Some(h)) => (h.peer_pub_hex.clone(), h.delivery.clone()),
                (None, None) => return Err("no such message on this profile".into()),
            };
            let who = send_ctx(data_dir, "", "", &peer_hex).who();
            if item.as_ref().is_some_and(|i| i.kind == "app") {
                println!(
                    "{C_BOLD}agent payload (RDAP){C_RESET} {}… to {who}",
                    &mid_hex[..8]
                );
            } else {
                let preview = outbox_preview(data_dir, &message_id);
                println!(
                    "{C_BOLD}message{C_RESET} {}…{} to {who}",
                    &mid_hex[..8],
                    spaced(&preview)
                );
            }
            let state = match &item {
                Some(i) => state_word(i),
                None => sanitize_terminal_line(&state),
            };
            println!("  state       {state}");
            if let Some(i) = &item {
                let mut rows = outbox_status_rows(i, now);
                worded_last_error(&mut rows, i, &who);
                // A friend holds a copy that expires before the message's own
                // deadline: both, each named (E2 r38).
                if let Some(until) = keeps_trying_until(data_dir, i) {
                    rows.push(format!("  keeps trying until {}", until_text(until, now)));
                }
                let ctx = send_ctx(data_dir, "", "", &i.peer_pub_hex);
                after_last_error(&mut rows, outbox_why_rows(&ctx, &i.why));
                if i.state == "expired" && i.never_sent {
                    rows.push(format!("  why         {}", time_ran_out_text(&who)));
                } else if i.state == "expired" && i.in_custody > 0 {
                    rows.push(format!(
                        "  why         {}",
                        custody_expired_text(&who, i, now)
                    ));
                }
                for row in rows {
                    println!("{row}");
                }
            }
            if matches!(state.as_str(), "queued" | "sent" | "held") {
                for row in letter_detail_rows(data_dir, &peer_hex, &message_id, now) {
                    println!("{row}");
                }
            }
            if let Some(h) = &history {
                println!(
                    "  history     {}",
                    if h.delivery.is_empty() {
                        "delivered".to_string()
                    } else {
                        sanitize_terminal_line(&h.delivery)
                    }
                );
            }
            if item
                .as_ref()
                .is_some_and(|i| i.last_error_code == raven_core::CONTACT_NOT_VERIFIED)
            {
                let ctx = send_ctx(data_dir, "", "", &peer_hex);
                println!("{C_DIM}{}{C_RESET}", not_verified_line(data_dir, &ctx));
            }
            if !running && item.as_ref().is_some_and(outbox_retries_it) {
                println!(
                    "{C_DIM}raven-node's outbox is not running: start it with `ash listen`.{C_RESET}"
                );
            }
            Ok(())
        }
        OutboxCmd::Retry { mid } => {
            let (_, items) = outbox_items(data_dir, None, now)?;
            let message_id = resolve_outbox_mid(data_dir, &mid, &items)?;
            let mid_hex = hex::encode(message_id);
            let Some(item) = items.iter().find(|i| i.message_id_hex == mid_hex) else {
                return Err(format!(
                    "message {}… is not waiting to be delivered (`raven outbox status {}` says \
                     what happened to it)",
                    &mid_hex[..8],
                    &mid_hex[..8]
                ));
            };
            let peer = parse_pub_hex(&item.peer_pub_hex)?;
            let who = send_ctx(data_dir, "", "", &item.peer_pub_hex).who();
            if super::pair_init_lab::outbox_retry_kick(data_dir, Some(&peer)) {
                println!(
                    "raven-node is trying again now: `raven outbox status {}` shows the result.",
                    &mid_hex[..8]
                );
                Ok(())
            } else {
                Err(format!(
                    "raven-node's outbox is not running here, so nothing retries it in the \
                     background: start it with `ash listen`, or it goes out with your next send \
                     to {who}."
                ))
            }
        }
        OutboxCmd::Cancel { mid, yes } => {
            let (_, items) = outbox_items(data_dir, None, now)?;
            let message_id = resolve_outbox_mid(data_dir, &mid, &items)?;
            cancel_outbound(data_dir, &message_id, yes)
        }
        OutboxCmd::HandOff { contact_pub_hex } => {
            println!("{}", hand_off(data_dir, contact_pub_hex.as_deref())?);
            Ok(())
        }
    }
}

/// `raven outbox status`'s note when raven-node does not run: what only its
/// outbox moves on. Queued, sent (an ACK may still come) and held messages,
/// and (review cross-5) one parked until its deadline (`waiting`, Phase
/// 5a), which only raven-node pairs and seals again.
fn outbox_retries_it(item: &raven_core::ipc::OutboxItem) -> bool {
    matches!(item.state.as_str(), "queued" | "sent" | "held" | "waiting")
}

/// `raven outbox hand-off [--contact X]`: raven-node leaves sealed copies of
/// the messages it could not deliver (to `peer_hex`, or to anyone) with a
/// friend now instead of after a minute (`OutboxKick { retry, custody_now }`).
/// Refused while friend custody is held in this build.
fn hand_off(data_dir: &Path, peer_hex: Option<&str>) -> Result<String, String> {
    if !raven_core::custody_gate::CustodyGates::current().live {
        return Err(raven_core::custody_gate::CUSTODY_HOLD.into());
    }
    let peer = peer_hex.map(parse_pub_hex).transpose()?;
    let to = peer_hex
        .map(|p| format!(" to {}", send_ctx(data_dir, "", "", p).who()))
        .unwrap_or_default();
    if super::pair_init_lab::outbox_hand_off_kick(data_dir, peer.as_ref()) {
        Ok(format!(
            "raven-node now leaves sealed copies of the messages{to} it could not deliver with a \
             friend (your mail friends, or the custodians you set): `raven outbox list` says \
             \"held by\" once a friend holds one."
        ))
    } else {
        Err(format!(
            "raven-node's outbox is not running here, so nothing can hand the messages{to} to a \
             friend: start it with `ash listen`."
        ))
    }
}

/// What `raven outbox cancel` stops: a copy in the outbox, or a message
/// parked until its deadline (Phase 5a), which has no outbox row (parking
/// moved it out, or it was parked before any session existed).
enum Waiting {
    Outbox(raven_core::EndpointOutbound),
    Parked(raven_core::indexed_session_store::ParkedOutbound),
}

impl Waiting {
    fn peer(&self) -> [u8; 32] {
        match self {
            Self::Outbox(row) => row.recipient_device,
            Self::Parked(row) => row.recipient_device,
        }
    }
}

/// The message `message_id` waiting to be delivered: its copy in the
/// outbox, else its parked row (to any contact).
fn find_waiting(
    store: &raven_core::IndexedSessionStore,
    message_id: &[u8; 16],
) -> Result<Option<Waiting>, String> {
    let mut rows = store
        .pending_endpoint_outbound()
        .map_err(|e| e.redacted_display())?;
    rows.extend(
        store
            .awaiting_ack_endpoint_outbound()
            .map_err(|e| e.redacted_display())?,
    );
    if let Some(row) = rows.into_iter().find(|r| {
        r.kind == raven_core::EndpointOutboundKind::Message && r.message_id == *message_id
    }) {
        return Ok(Some(Waiting::Outbox(row)));
    }
    for parked in store.parked_peers().map_err(|e| e.redacted_display())? {
        if let Some(row) = store
            .parked_for_recipient(&parked.peer)
            .map_err(|e| e.redacted_display())?
            .into_iter()
            .find(|r| r.message_id == *message_id)
        {
            return Ok(Some(Waiting::Parked(row)));
        }
    }
    Ok(None)
}

/// Stop retrying one of our messages: abandoned in the store, `cancelled` in
/// the history, under the same per-peer lock as every send. A message that
/// was already written may still have arrived. A message parked until its
/// deadline (Phase 5a), which `raven outbox list` shows as waiting, is given
/// up the way the horizon step gives one up, so it is never sealed again
/// (review 5a-1, [`raven_core::horizon::cancel_parked`]). A message the
/// worker already moved into a sealed letter leaves that letter too
/// ([`raven_core::letter_deposits::cancel_message`]).
pub(crate) fn cancel_outbound(
    data_dir: &Path,
    message_id: &[u8; 16],
    yes: bool,
) -> Result<(), String> {
    let mid_hex = hex::encode(message_id);
    let not_waiting = || {
        format!(
            "message {}… is not waiting to be delivered (`raven outbox status {}` says what \
             happened to it)",
            &mid_hex[..8],
            &mid_hex[..8]
        )
    };
    let store = raven_core::IndexedSessionStore::open(data_dir)
        .map_err(|e| format!("outbox: {}", e.redacted_display()))?;
    let found = find_waiting(&store, message_id)?;
    drop(store);
    let Some(found) = found else {
        return Err(not_waiting());
    };
    let peer = found.peer();
    let who = send_ctx(data_dir, "", "", &hex::encode(peer)).who();
    let agent = raven_core::app_channel::is_app_outbound(data_dir, message_id).unwrap_or(false);
    let preview = outbox_preview(data_dir, message_id);
    let what = if agent {
        "agent payload (RDAP)".to_string()
    } else {
        format!("message{}", spaced(&preview))
    };
    if !yes {
        if !io::stdin().is_terminal() {
            return Err("add --yes to cancel without the typed confirmation".into());
        }
        print!("Stop trying to deliver your {what} to {who}? Type yes to confirm: ");
        let _ = io::stdout().flush();
        match read_line_result() {
            LineResult::Line(l) if l.trim().eq_ignore_ascii_case("yes") => {}
            _ => {
                println!("{C_DIM}not cancelled: nothing changed.{C_RESET}");
                return Ok(());
            }
        }
    }
    let _lock = super::pair_init_lab::acquire_send_lock(data_dir, &peer)?;
    let mut store = raven_core::IndexedSessionStore::open(data_dir)
        .map_err(|e| format!("outbox: {}", e.redacted_display()))?;
    // Under the lock, again: raven-node's worker may have parked the copy
    // (its envelope ran out) or sealed the parked message again meanwhile.
    // Gone from both, what was read first decides (an ACK may have
    // delivered it).
    let found = match find_waiting(&store, message_id)? {
        Some(now) if now.peer() == peer => now,
        _ => found,
    };
    // Read while the store still holds it (a prune forgets the record of a
    // message the outbox no longer holds, privacy pack PP.7): was it ever
    // written by a carrier (a prepared one the contact read and refused,
    // too), or left with a friend (who still holds it)?
    let (unsent, written, with_friend) =
        raven_core::outbox::object_route_evidence(data_dir, now_ms())
            .ok()
            .and_then(|records| {
                records
                    .get(message_id)
                    .map(|r| (r.unsent, r.written, r.with_friend))
            })
            .unwrap_or((false, false, false));
    let (outcome, handed_to_queue) = match found {
        Waiting::Outbox(row) => {
            let key = store
                .record_key_for_session_id(&row.session_id)
                .map_err(|e| e.redacted_display())?
                .ok_or("the session of that message is gone; nothing to cancel")?;
            // A parked row of the same message next to its copy (a crash
            // leftover the next horizon step would seal again) goes first.
            store
                .give_up_parked(&peer, message_id)
                .map_err(|e| e.redacted_display())?;
            let outcome = raven_core::outbox::give_up_outbound(
                data_dir,
                &mut store,
                &key,
                &row.recipient_device,
                &row.session_id,
                &row.object_digest,
                &row.message_id,
                raven_core::outbox::HISTORY_CANCELLED,
            )?;
            (
                outcome,
                row.state == raven_core::EndpointOutboxState::Queued,
            )
        }
        Waiting::Parked(row) => {
            match raven_core::horizon::cancel_parked(data_dir, &mut store, &peer, message_id)? {
                // A copy parked from its session may have been sent.
                Some(outcome) => (outcome, row.from_session.is_some()),
                // Settled meanwhile: a late ACK delivered it, or it was
                // given up (its status says how).
                None if store
                    .message_copies_for_recipient(&peer, message_id)
                    .map_err(|e| e.redacted_display())?
                    .iter()
                    .any(|c| {
                        matches!(
                            c.delivery_state,
                            Some(
                                raven_core::EndpointDeliveryState::Delivered
                                    | raven_core::EndpointDeliveryState::Read
                            )
                        )
                    }) =>
                {
                    (raven_core::outbox::GiveUp::Delivered, false)
                }
                None => return Err(not_waiting()),
            }
        }
    };
    let _ = raven_core::outbox::clear_object_routes(data_dir, &[*message_id]);
    if outcome == raven_core::outbox::GiveUp::Delivered {
        println!(
            "{C_GREEN}status{C_RESET} delivered - {who} confirmed it before it could be cancelled"
        );
        return Ok(());
    }
    // A copy the worker already moved into a sealed letter (Phase 5b) is in
    // that letter too: the letter is withdrawn, still under the lock, and
    // the worker letters what else it carried without this one.
    let letters =
        raven_core::letter_deposits::cancel_message(data_dir, &peer, message_id, now_ms());
    // The worker notices at once (and drops it from its schedule).
    let _ = super::pair_init_lab::outbox_kick(data_dir, Some(&peer));
    let reached = with_friend || written || (handed_to_queue && !unsent);
    println!(
        "cancelled: raven-node stops trying to deliver your {what} to {who}.{}",
        cancelled_note(&who, reached, &letters)
    );
    Ok(())
}

/// The part of the cancel answer that says whether the contact may have the
/// message anyway: `reached` (a carrier wrote it, or a friend took it) and
/// what [`raven_core::letter_deposits::cancel_message`] found. A letter
/// already with a friend may still be collected before its withdraw
/// arrives; a book that could not be read cannot say.
pub(crate) fn cancelled_note(
    who: &str,
    reached: bool,
    letters: &Result<raven_core::letter_deposits::CancelledLetters, String>,
) -> String {
    match letters {
        Ok(found) if found.with_friend => format!(
            " Its sealed letter is already with a friend, so {who} may have it anyway: \
             raven-node asks the friend to drop it."
        ),
        Err(_) => format!(
            " The letters left with friends could not be checked, so {who} may have it anyway."
        ),
        Ok(_) if reached => format!(" It was already sent once, so {who} may have it anyway."),
        Ok(_) => String::new(),
    }
}

// ── Chat session with slash commands ──────────────────────────────────────

/// Position in a peer's endpoint inbox: the store's own place
/// ([`raven_core::InboxPosition`], privacy pack PP.14). In a sealed
/// profile's store it is the rows' insertion `seq`; in a clear one
/// `(received_at_ms, message_id)`, with "no message id" below every id. The
/// derived order is the listing order of
/// `list_endpoint_inbox_for_sender_after` within one order; a cursor saved
/// in the other order is placed by the store (a store only moves forward,
/// and a position of the newer order sorts after every older one).
type InboxCursor = raven_core::InboxPosition;

const CHAT_INBOX_POLL_LIMIT: usize = 8;
const CHAT_PENDING_MAX: usize = 64;

/// One inbox row ready to print, with its id so a row the chat already showed
/// (as part of the history dump) is not shown a second time.
#[derive(Clone)]
struct InboxLine {
    message_id: [u8; 16],
    text: String,
}

#[derive(Clone)]
struct PendingInboxBatch {
    lines: Vec<InboxLine>,
    cursor_after: InboxCursor,
}

#[derive(Default)]
struct ChatPendingQueue {
    batches: Vec<PendingInboxBatch>,
    /// Latest inbox error only — never competes with message slots.
    last_error: Option<String>,
    /// At most one batch waiting while the display queue is full.
    deferred: Option<PendingInboxBatch>,
    /// "New message" notice already shown for what is queued; cleared when the
    /// queue is drained, so one burst of messages gives one notice.
    notified: bool,
}

/// Print the rows of `batch` the chat has not shown yet and remember them. A
/// row is skipped only if it was *actually printed* (history dump or an earlier
/// batch): existence in the history is not enough, because the poller persists a
/// row to history before it is displayed.
fn print_unseen_lines(batch: &PendingInboxBatch, shown: &mut std::collections::HashSet<[u8; 16]>) {
    for line in unseen_lines(batch, shown) {
        println!("{}", line.text);
    }
}

/// The rows of `batch` not in `shown`, which are added to it.
fn unseen_lines<'a>(
    batch: &'a PendingInboxBatch,
    shown: &mut std::collections::HashSet<[u8; 16]>,
) -> Vec<&'a InboxLine> {
    batch
        .lines
        .iter()
        .filter(|line| shown.insert(line.message_id))
        .collect()
}

fn chat_inbox_cursors_path(data_dir: &Path) -> PathBuf {
    data_dir.join(raven_core::chat_history::CHAT_INBOX_CURSORS_FILE)
}

#[derive(Debug)]
enum CursorMapError {
    Missing,
    Io(String),
    Corrupt(String),
}

/// The cursor map, sealed (privacy pack PP.6: RMS1 kind 9 in a sealed
/// profile) or plain. A file that cannot be opened now (the at-rest key not
/// loaded, an I/O error) is `Io`; one that does not open under this
/// profile's key or does not parse is `Corrupt`: either way the chat does
/// not open ([`cursor_unavailable_text`]).
fn load_cursor_map(
    data_dir: &Path,
) -> Result<serde_json::Map<String, serde_json::Value>, CursorMapError> {
    let path = chat_inbox_cursors_path(data_dir);
    match raven_core::at_rest::load_bytes(
        data_dir,
        &path,
        raven_core::at_rest::Kind::ChatInboxCursors,
    ) {
        Ok(None) => Err(CursorMapError::Missing),
        Err(e) if e.is_unavailable() => Err(CursorMapError::Io(e.to_string())),
        Err(e) => Err(CursorMapError::Corrupt(e.to_string())),
        Ok(Some(raw)) => {
            let value: serde_json::Value =
                serde_json::from_slice(&raw).map_err(|e| CursorMapError::Corrupt(e.to_string()))?;
            let serde_json::Value::Object(map) = value else {
                return Err(CursorMapError::Corrupt(
                    "chat_inbox_cursors.json root must be an object".into(),
                ));
            };
            Ok(map)
        }
    }
}

/// One contact's saved cursor: `{"seq": n}` (format 2, PP.14: a sealed
/// profile's store) or `{"received_at_ms": t, "message_id_hex": ..}` (format
/// 1: a clear store, and every cursor saved before PP.14).
fn parse_cursor_entry(entry: &serde_json::Value) -> Result<InboxCursor, String> {
    let obj = entry
        .as_object()
        .ok_or_else(|| "cursor entry must be an object".to_string())?;
    if let Some(seq) = obj.get("seq") {
        let seq = seq
            .as_u64()
            .ok_or_else(|| "cursor seq must be a number".to_string())?;
        return Ok(InboxCursor::seq(seq));
    }
    let received_at_ms = obj
        .get("received_at_ms")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "cursor entry missing received_at_ms".to_string())?;
    let message_id = match obj.get("message_id_hex") {
        None => None,
        Some(serde_json::Value::Null) => None,
        Some(v) => {
            let hex_s = v
                .as_str()
                .ok_or_else(|| "cursor message_id_hex must be a string".to_string())?;
            let bytes = hex::decode(hex_s).map_err(|e| format!("cursor message_id_hex: {e}"))?;
            if bytes.len() != 16 {
                return Err("cursor message_id_hex must be 16 bytes".into());
            }
            let mut id = [0u8; 16];
            id.copy_from_slice(&bytes);
            Some(id)
        }
    };
    Ok(InboxCursor::received(received_at_ms, message_id))
}

fn load_durable_inbox_cursor(data_dir: &Path, contact_pub: &str) -> Result<InboxCursor, String> {
    match load_cursor_map(data_dir) {
        Err(CursorMapError::Missing) => Ok(InboxCursor::default()),
        Err(CursorMapError::Io(e)) => Err(format!("inbox cursor read failed: {e}")),
        Err(CursorMapError::Corrupt(e)) => Err(format!("inbox cursor corrupt: {e}")),
        Ok(map) => {
            let want = contact_pub.trim().to_lowercase();
            match map.get(&want) {
                None => Ok(InboxCursor::default()),
                Some(entry) => parse_cursor_entry(entry),
            }
        }
    }
}

fn save_durable_inbox_cursor(
    data_dir: &Path,
    contact_pub: &str,
    cursor: &InboxCursor,
) -> Result<(), String> {
    let path = chat_inbox_cursors_path(data_dir);
    // The file's writer lock (raven_core::chat_history::CHAT_INBOX_CURSORS_LOCK):
    // sealed in a sealed profile, today's JSON otherwise.
    let lock = raven_core::at_rest::lock_file(
        data_dir,
        &path,
        raven_core::at_rest::Kind::ChatInboxCursors,
    )
    .map_err(|e| e.to_string())?;
    let mut map = match load_cursor_map(data_dir) {
        Ok(map) => map,
        Err(CursorMapError::Missing) => serde_json::Map::new(),
        Err(CursorMapError::Io(e)) => return Err(format!("inbox cursor read failed: {e}")),
        Err(CursorMapError::Corrupt(e)) => {
            return Err(format!("inbox cursor corrupt (refusing overwrite): {e}"));
        }
    };
    let mut entry = serde_json::Map::new();
    match cursor.order {
        raven_core::InboxOrder::Seq => {
            entry.insert("seq".into(), serde_json::Value::from(cursor.seq));
        }
        raven_core::InboxOrder::Received => {
            entry.insert("received_at_ms".into(), serde_json::Value::from(cursor.seq));
            if let Some(id) = cursor.message_id {
                entry.insert(
                    "message_id_hex".into(),
                    serde_json::Value::String(hex::encode(id)),
                );
            }
        }
    }
    map.insert(
        contact_pub.trim().to_lowercase(),
        serde_json::Value::Object(entry),
    );
    let json =
        serde_json::to_vec_pretty(&serde_json::Value::Object(map)).map_err(|e| e.to_string())?;
    lock.store_bytes(&json).map_err(|e| e.to_string())
}

fn compute_inbox_tombstone(data_dir: &Path, contact_pub: &str) -> Result<InboxCursor, String> {
    let peer = parse_pub_hex(contact_pub)?;
    let mut store =
        raven_core::IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let mut cursor = InboxCursor::default();
    loop {
        let rows = store
            .list_endpoint_inbox_for_sender_after(&peer, &cursor, CHAT_INBOX_POLL_LIMIT)
            .map_err(|e| e.redacted_display())?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            cursor = row.position;
        }
    }
    Ok(cursor)
}

/// A cursor loaded from the file, in the order of the store it is read
/// with: one saved before the store moved to schema 3 (PP.14) is placed
/// once, and saved again in the new format. Without a store it stays as it
/// is (nothing was received).
fn place_inbox_cursor(
    data_dir: &Path,
    contact_pub: &str,
    cursor: InboxCursor,
) -> Result<InboxCursor, String> {
    let store = raven_core::indexed_session_store::INDEXED_SESSION_METADATA_FILE;
    if !data_dir.join(store).exists() {
        return Ok(cursor);
    }
    let peer = parse_pub_hex(contact_pub)?;
    let store =
        raven_core::IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let placed = store
        .resolve_inbox_position(&peer, &cursor)
        .map_err(|e| e.redacted_display())?;
    if placed != cursor {
        save_durable_inbox_cursor(data_dir, contact_pub, &placed)?;
    }
    Ok(placed)
}

fn advance_inbox_cursor_past_peer(
    data_dir: &Path,
    contact_pub: &str,
) -> Result<InboxCursor, String> {
    let cursor = compute_inbox_tombstone(data_dir, contact_pub)?;
    save_durable_inbox_cursor(data_dir, contact_pub, &cursor)?;
    Ok(cursor)
}

/// Tombstone inbox first, then delete the chat — crash between leaves history
/// intact under an advanced cursor (no inbox rebuild). Never clear-then-tombstone.
///
/// The chat goes for good (privacy pack PP.8, [`raven_core::privacy::delete_chat`]):
/// the session store's rows the cursor covers, each leaving a tombstone, then
/// every history row of the contact. A message that arrives meanwhile is past
/// the cursor: it stays, to be shown.
fn clear_peer_history_with_tombstone(
    data_dir: &Path,
    contact_pub: &str,
) -> Result<(InboxCursor, raven_core::privacy::ChatDeletion), String> {
    let peer = parse_pub_hex(contact_pub)?;
    // No session store: nothing was received (and none is created).
    let store = raven_core::indexed_session_store::INDEXED_SESSION_METADATA_FILE;
    let cursor = if data_dir.join(store).exists() {
        compute_inbox_tombstone(data_dir, contact_pub)?
    } else {
        InboxCursor::default()
    };
    save_durable_inbox_cursor(data_dir, contact_pub, &cursor)?;
    let deleted = raven_core::privacy::delete_chat(data_dir, &peer, Some(&cursor))?;
    Ok((cursor, deleted))
}

/// `raven chats delete`: [`clear_peer_history_with_tombstone`] outside a chat
/// window (an open one keeps its own cursor).
pub(crate) fn delete_chat_with(
    data_dir: &Path,
    contact_pub: &str,
) -> Result<raven_core::privacy::ChatDeletion, String> {
    clear_peer_history_with_tombstone(data_dir, contact_pub).map(|(_, deleted)| deleted)
}

/// Messages to `contact_pub` still waiting to be sent (queued, sent without
/// a confirmation yet, or held): raven-node's outbox, or the store when no
/// raven-node answers (none is created). Agent payloads and receipts are not
/// counted.
pub(crate) fn waiting_messages_to(data_dir: &Path, contact_pub: &str) -> usize {
    waiting_messages(data_dir, Some(contact_pub))
}

/// [`waiting_messages_to`] for one contact, or (None) for every contact
/// together: the terminal app's erase says how many go (PP.22).
pub(crate) fn waiting_messages(data_dir: &Path, contact_pub: Option<&str>) -> usize {
    let waiting = |items: &[raven_core::ipc::OutboxItem]| {
        items
            .iter()
            .filter(|i| {
                i.kind == "message"
                    && contact_pub.is_none_or(|contact_pub| {
                        i.peer_pub_hex
                            .trim()
                            .eq_ignore_ascii_case(contact_pub.trim())
                    })
                    && matches!(i.state.as_str(), "queued" | "sent" | "held")
            })
            .count()
    };
    let req = IpcRequest::OutboxList {
        v: IPC_VERSION,
        peer_pub_hex: contact_pub.map(str::to_string),
        limit: Some(OUTBOX_LIST_LIMIT),
    };
    if let Ok(IpcResponse::OutboxListResult { items, .. }) =
        super::ipc_client::ipc_request(data_dir, &req)
    {
        return waiting(&items);
    }
    let store = raven_core::indexed_session_store::INDEXED_SESSION_METADATA_FILE;
    if !data_dir.join(store).exists() {
        return 0;
    }
    outbox_items(data_dir, contact_pub, now_ms())
        .map(|(_, items)| waiting(&items))
        .unwrap_or(0)
}

fn peek_endpoint_inbox_for_contact(
    data_dir: &Path,
    contact_pub: &str,
    cursor: &InboxCursor,
) -> Result<Option<PendingInboxBatch>, String> {
    let peer = parse_pub_hex(contact_pub)?;
    let mut store =
        raven_core::IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let rows = store
        .list_endpoint_inbox_for_sender_after(&peer, cursor, CHAT_INBOX_POLL_LIMIT)
        .map_err(|e| e.redacted_display())?;
    if rows.is_empty() {
        return Ok(None);
    }
    let mut lines = Vec::new();
    let mut cursor_after = *cursor;
    for row in rows {
        cursor_after = row.position;
        // An agent payload (app channel) belongs to RDAP: step past it,
        // never print it, never put it in chat history.
        if !matches!(
            raven_core::app_channel::classify(&row.plaintext),
            raven_core::app_channel::PayloadClass::Chat
        ) {
            continue;
        }
        let preview = String::from_utf8_lossy(&row.plaintext);
        let again = record_received_chat(data_dir, &store, &peer, &row)?;
        lines.push(InboxLine {
            message_id: row.message_id,
            text: chat_inbox_line_text(&row.message_id, &preview, again),
        });
    }
    Ok(Some(PendingInboxBatch {
        lines,
        cursor_after,
    }))
}

/// One received chat row of `peer`'s, as the chat polls it: written to the
/// history, unless it is a copy of a message taken before (receiver dedup,
/// P5.5: the contact re-sent it under a new session). Such a copy shows the
/// note, not the body again (the store's inbound-seen row outlives the first
/// copy's inbox row and history entry), and stays out of the history, whose
/// readers would show it as a new message once the first copy's entry is
/// gone (review 5a-4). Whether it is one; a store that cannot answer says
/// no.
fn record_received_chat(
    data_dir: &Path,
    store: &raven_core::IndexedSessionStore,
    peer: &[u8; 32],
    row: &raven_core::EndpointInboxRow,
) -> Result<bool, String> {
    let again =
        raven_core::app_channel::received_again(store, peer, &row.message_id, row.received_at_ms);
    if !again {
        raven_core::persist_lan_chat_history(
            data_dir,
            "in",
            peer,
            &row.message_id,
            row.created_at_ms,
            "received",
            &row.plaintext,
        )?;
    } else {
        // Other text under the id marks the first copy's row, which keeps
        // its body (ATSAM_ENDPOINT_TRANSACTION_V1 §3).
        raven_core::ChatHistory::note_inbound_copy_persisted(
            data_dir,
            &hex::encode(peer),
            &hex::encode(row.message_id),
            Some(&String::from_utf8_lossy(&row.plaintext)),
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(again)
}

/// The chat's line for one received message: its short id and the body, or
/// [`RECEIVED_AGAIN_NOTE`] instead of the body for a copy of a message taken
/// before (`again`).
fn chat_inbox_line_text(message_id: &[u8; 16], body: &str, again: bool) -> String {
    let shown = if again {
        format!("{C_DIM}{RECEIVED_AGAIN_NOTE}{C_RESET}")
    } else {
        sanitize_terminal_line(body)
    };
    format!(
        "  ← {C_DIM}{}{C_RESET} {shown}",
        hex::encode(&message_id[..4])
    )
}

/// A batch of agent payloads only: move the newest queued batch's cursor past
/// them, so nothing is shown and no notice is due. `false` when nothing is
/// queued (the caller then advances the shared cursor itself).
fn absorb_silent_batch(pending: &std::sync::Mutex<ChatPendingQueue>, cursor: InboxCursor) -> bool {
    let Ok(mut q) = pending.lock() else {
        return true;
    };
    if let Some(deferred) = q.deferred.as_mut() {
        deferred.cursor_after = cursor;
        return true;
    }
    match q.batches.last_mut() {
        Some(last) => {
            last.cursor_after = cursor;
            true
        }
        None => false,
    }
}

fn chat_queue_blocks_poll(pending: &std::sync::Mutex<ChatPendingQueue>) -> bool {
    let Ok(q) = pending.lock() else {
        return true;
    };
    q.batches.len() >= CHAT_PENDING_MAX || q.deferred.is_some()
}

/// Queue a batch for the main thread. `true` when the caller should show the
/// "new message" notice: the first batch since the queue was last drained.
fn push_chat_batch(pending: &std::sync::Mutex<ChatPendingQueue>, batch: PendingInboxBatch) -> bool {
    let Ok(mut q) = pending.lock() else {
        return false;
    };
    if q.batches.len() >= CHAT_PENDING_MAX {
        // Keep exactly one deferred batch; do not re-peek/re-persist in a hot loop.
        if q.deferred.is_none() {
            q.deferred = Some(batch);
        }
    } else {
        q.batches.push(batch);
    }
    !std::mem::replace(&mut q.notified, true)
}

fn set_chat_pending_error(pending: &std::sync::Mutex<ChatPendingQueue>, err: String) {
    if let Ok(mut q) = pending.lock() {
        q.last_error = Some(err);
    }
}

fn poll_cursor_with_pending(
    pending: &std::sync::Mutex<ChatPendingQueue>,
    shared: InboxCursor,
) -> InboxCursor {
    let Ok(q) = pending.lock() else {
        return shared;
    };
    q.batches.last().map(|b| b.cursor_after).unwrap_or(shared)
}

/// Drop everything queued but not yet printed. After `/clear-local-history`
/// those rows are older than the tombstone and must never be shown.
fn discard_chat_pending(pending: &std::sync::Mutex<ChatPendingQueue>) {
    if let Ok(mut q) = pending.lock() {
        q.batches.clear();
        q.deferred = None;
        q.last_error = None;
        q.notified = false;
    }
}

/// Print queued batches in order and advance the durable cursor. Forward-only:
/// a batch at or behind the cursor was already shown (or cleared), so it is
/// skipped rather than printed twice or moving the cursor backwards.
fn drain_chat_pending(
    data_dir: &Path,
    contact_pub: &str,
    pending: &std::sync::Mutex<ChatPendingQueue>,
    cursor: &mut InboxCursor,
    shown: &mut std::collections::HashSet<[u8; 16]>,
) {
    let Ok(mut q) = pending.lock() else {
        return;
    };
    if let Some(err) = q.last_error.take() {
        eprintln!("{}", inbox_problem_text(&err, data_dir));
    }
    let mut batches = std::mem::take(&mut q.batches);
    if let Some(deferred) = q.deferred.take() {
        batches.push(deferred);
    }
    q.notified = false;
    drop(q);
    let before = *cursor;
    for batch in batches {
        if batch.cursor_after <= *cursor {
            continue;
        }
        print_unseen_lines(&batch, shown);
        *cursor = batch.cursor_after;
    }
    if *cursor != before {
        if let Err(e) = save_durable_inbox_cursor(data_dir, contact_pub, cursor) {
            eprintln!("inbox cursor save failed: {e}");
        }
    }
}

/// How long the chat's "is my receiver running?" check may take: it is read-only
/// (it never starts the service) and must not delay a chat that ends at once.
const CHAT_RECEIVER_PROBE: Duration = Duration::from_millis(500);

/// Whether this computer can receive messages right now, as the local service
/// itself reports it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReceiverState {
    /// The service runs and its LAN listener is up.
    Receiving,
    /// The service runs but its LAN listener is not up (busy port, or started
    /// outbound-only): sending works, nothing can arrive.
    NotReceiving,
    /// No service for this profile.
    NotRunning,
    /// Something owns the endpoint but does not answer in time (stuck or busy).
    NotAnswering,
}

fn classify_receiver(status: &Result<IpcResponse, String>) -> ReceiverState {
    match (listener_reported(status), status) {
        (Some(true), _) => ReceiverState::Receiving,
        (Some(false), _) => ReceiverState::NotReceiving,
        (None, Err(e)) if super::ipc_client::error_means_not_running(e) => {
            ReceiverState::NotRunning
        }
        (None, _) => ReceiverState::NotAnswering,
    }
}

/// Ask the local service (one Status, bounded by `wait`) whether this computer is
/// receiving. Read-only: it never starts the service, so it is safe for the inbox,
/// the status screen and the menu as well as the chat.
pub(crate) fn receiver_state(data_dir: &Path, wait: Duration) -> ReceiverState {
    classify_receiver(&super::ipc_client::ipc_request_timeout(
        data_dir,
        &IpcRequest::status(),
        wait,
    ))
}

/// The chat's one-time heads-up (stderr) when replies cannot arrive.
fn chat_receiver_note(state: ReceiverState, name: &str) -> Option<String> {
    match state {
        ReceiverState::Receiving => None,
        ReceiverState::NotRunning => Some(format!(
            "{C_PURPLE}note{C_RESET}: raven-node is not running, so replies from {name} cannot \
             arrive yet. It starts when you send a message here, or run `ash listen` in another \
             terminal."
        )),
        ReceiverState::NotReceiving => Some(format!(
            "{C_PURPLE}warning{C_RESET}: this computer is NOT receiving messages: raven-node runs, \
             but its LAN listener is down (a busy port, or started outbound-only), so replies \
             from {name} cannot arrive. See raven-node-service.log in your RAVEN data folder, or \
             run `ash doctor`."
        )),
        ReceiverState::NotAnswering => Some(format!(
            "{C_PURPLE}note{C_RESET}: raven-node is running but not answering, so replies from \
             {name} may not arrive. Run `ash doctor` for details."
        )),
    }
}

/// What `/clear-local-history` prints once the chat is deleted (privacy pack
/// PP.8).
fn chat_cleared_text(name: &str) -> String {
    format!("{C_GREEN}cleared{C_RESET}: your chat with {name} is deleted from this computer.")
}

/// What the chat calls the other person: petname, else `@tag`, else a short
/// fingerprint (never 64 hex digits).
fn chat_name(petname: &str, tag: &str, contact_pub: &str) -> String {
    let petname = sanitize_terminal_line(petname.trim());
    if !petname.is_empty() {
        return petname;
    }
    let tag = sanitize_terminal_line(tag.trim().trim_start_matches('@'));
    if !tag.is_empty() {
        return format!("@{tag}");
    }
    match parse_pub_hex(contact_pub) {
        Ok(key) => format!("device {}", device_fingerprint_v1(&key)),
        Err(_) => "this contact".into(),
    }
}

fn chat_header(name: &str, tag: &str) -> String {
    let tag = sanitize_terminal_line(tag.trim().trim_start_matches('@'));
    let tag = if tag.is_empty() || name == format!("@{tag}") {
        String::new()
    } else {
        format!(" @{tag}")
    };
    format!("{C_BOLD}chat with{C_RESET} {name}{tag}")
}

/// What one line typed in the chat means.
#[derive(Debug, PartialEq, Eq)]
enum ChatInput<'a> {
    Empty,
    /// Text for the other person.
    Send(&'a str),
    /// `/help`, or the bare word `help` / `?` (`bare`).
    Help {
        bare: bool,
    },
    /// `/back`, `/quit`, `/q`, `/exit`, or the bare words `exit` / `quit` (`bare`).
    Leave {
        bare: bool,
    },
    /// Any other `/command`.
    Command(&'a str),
}

/// `help`, `?`, `exit` and `quit` typed on their own are the chat's commands, not
/// a message: nobody opens a chat to send their friend the word "quit", and
/// sending it by mistake cannot be taken back. Add a character to send the word.
fn classify_chat_input(line: &str) -> ChatInput<'_> {
    let line = line.trim();
    if line.is_empty() {
        return ChatInput::Empty;
    }
    if line.starts_with('/') {
        return match line.split_whitespace().next().unwrap_or("") {
            "/help" | "/?" => ChatInput::Help { bare: false },
            "/back" | "/quit" | "/q" | "/exit" => ChatInput::Leave { bare: false },
            other => ChatInput::Command(other),
        };
    }
    match line.to_lowercase().as_str() {
        "help" | "?" => ChatInput::Help { bare: true },
        "exit" | "quit" => ChatInput::Leave { bare: true },
        _ => ChatInput::Send(line),
    }
}

pub(super) fn chat_help_lines(name: &str, tag: &str) -> Vec<String> {
    let tag = sanitize_terminal_line(tag.trim().trim_start_matches('@'));
    let file_send = if tag.is_empty() {
        super::file_send_example("@tag")
    } else {
        super::file_send_example(&format!("@{tag}"))
    };
    vec![
        format!("  Type a message and press Enter to send it to {name}."),
        "  /help      this list".into(),
        format!(
            "  /back      leave the chat (also /quit, exit, quit, or {})",
            super::END_OF_INPUT
        ),
        format!("  /info      who {name} is (name, tag, key, address)"),
        format!("  /verify    your security words to read to {name}, and how to check {name}'s"),
        format!("  /block     stop all messages to and from {name} (asks first)"),
        format!(
            "  /clear-local-history   delete your chat with {name} from this computer \
             ({name} keeps their copy)"
        ),
        format!(
            "  New messages from {name} show up after you press Enter. A line that starts with \
             / is read as a command."
        ),
        // A terminal in canonical mode drops what is typed past about 1000 bytes
        // (macOS: 1023), including the Enter: the message looks frozen or is cut.
        format!(
            "  A message is one line: keep it under about 1000 bytes (roughly 500 Persian or \
             1000 English letters), a terminal may cut a longer one. For longer or multi-line \
             text: {file_send}"
        ),
    ]
}

/// The transcript line for a message just sent (stdout) and, when it did not go
/// through, the sentence that says why (stderr). The failure marker never says
/// "delivered": only a verified ACK does, and that is the `Ok` case.
fn chat_echo(text: &str, result: &Result<(), String>, name: &str) -> (String, Option<String>) {
    let shown = sanitize_terminal_line(text);
    match result {
        Ok(()) => (
            format!(
                "  {C_DIM}→{C_RESET} {shown}  {C_GREEN}✓{C_RESET} {C_DIM}{name} confirmed receipt{C_RESET}"
            ),
            None,
        ),
        Err(error) => {
            let line = friendly_send_error(error, name);
            let marker = if line.starts_with(QUEUED_PREFIX) && line.contains(BACKGROUND_RETRY) {
                "[queued: raven-node keeps trying]"
            } else if line.starts_with(QUEUED_PREFIX) {
                "[queued: goes out with your next message]"
            } else if line.starts_with(UNCONFIRMED_PREFIX) {
                "[sent, not confirmed]"
            } else {
                "[NOT SENT]"
            };
            (format!("  {C_DIM}→{C_RESET} {shown}  {C_DIM}{marker}{C_RESET}"), Some(line))
        }
    }
}

/// `/verify`: MY security words to read out (and my old-style code, for a
/// friend with an older Raven), what this command does not do, and the one
/// command that checks the friend's words and marks them verified. Nothing
/// of the friend's words or code: that check is blind.
fn verify_lines(
    name: &str,
    my_words: &str,
    my_fp: &str,
    pinned: Option<bool>,
    verify_command: &str,
) -> Vec<String> {
    let mut lines = vec![
        format!("{C_BOLD}Your security words{C_RESET} (read all 10 to {name})"),
        format!("{C_BOLD}words{C_RESET}       {my_words}"),
        format!("{C_DIM}old-style code (for a friend with an older Raven): {my_fp}{C_RESET}"),
        format!(
            "{C_DIM}Call {name} or meet in person, not in this chat: each of you reads all 10 of \
             your own words to the other. This only shows yours; nothing is changed.{C_RESET}"
        ),
    ];
    match pinned {
        Some(true) => lines.push(format!(
            "{C_DIM}{name} is already marked verified (pinned) on this computer.{C_RESET}"
        )),
        Some(false) => lines.push(format!(
            "{C_DIM}{name} is not marked verified yet. To type the words {name} reads and mark \
             {name} verified, leave the chat and run: {verify_command}{C_RESET}"
        )),
        None => {}
    }
    lines
}

fn chat_verify_lines(data_dir: &Path, id: &Identity, contact_pub: &str, name: &str) -> Vec<String> {
    let Ok(key) = parse_pub_hex(contact_pub) else {
        return Vec::new();
    };
    let me = id.public_key_bytes();
    let my_words = security_words::words_v1(&me).join(" ");
    // The command asks for what the OTHER person reads out and shows nothing
    // of theirs before it matches.
    let verify_command = format!("ash contact verify --address {}", encode_address(&key));
    let pinned = match contact_for_key(data_dir, contact_pub) {
        Ok(contact) => contact.map(|c| c.pinned),
        // Never "not verified" from a book that cannot be read.
        Err(e) => return vec![e],
    };
    verify_lines(
        name,
        &my_words,
        &device_fingerprint_v1(&me),
        pinned,
        &verify_command,
    )
}

/// `/info`'s words line: the contact's security words once they are
/// verified (pinned); before that they stay hidden, so the blind check of
/// `contact verify` means something.
fn info_words(data_dir: &Path, contact_pub: &str, key: &[u8; 32], name: &str) -> String {
    match contact_for_key(data_dir, contact_pub) {
        Ok(Some(c)) if c.pinned => security_words::words_v1(key).join(" "),
        Ok(_) => format!("(shown once you verify {name}: /verify)"),
        // Never "not verified" from a book that cannot be read.
        Err(e) => e,
    }
}

/// `/block`: ask first (an empty answer, anything but yes, or end of input
/// cancels), then block and say how to undo it. `true` when the chat should end.
fn chat_block(data_dir: &Path, contact_pub: &str, name: &str) -> bool {
    println!(
        "{C_BOLD}Block {name}?{C_RESET} You will not receive messages from {name}, and you \
         cannot send to {name}, until you unblock."
    );
    print!("Type yes to block; anything else cancels: ");
    let _ = io::stdout().flush();
    let answer = read_line_result();
    let confirmed = matches!(
        &answer,
        LineResult::Line(l) if l.eq_ignore_ascii_case("yes") || l.eq_ignore_ascii_case("y")
    );
    if !confirmed {
        if !matches!(answer, LineResult::Line(_)) {
            println!();
        }
        println!("{C_DIM}not blocked{C_RESET}");
        return false;
    }
    let mut blocks = match BlockList::load_checked(data_dir) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("block list: {e}");
            return false;
        }
    };
    blocks.block(contact_pub);
    if let Err(e) = blocks.save(data_dir) {
        eprintln!("block save failed: {e}");
        return false;
    }
    super::forget_outbox_routes(data_dir, contact_pub);
    for note in super::forget_mail_friend(data_dir, contact_pub) {
        eprintln!("{}", sanitize_terminal_line(&note));
    }
    println!(
        "{C_GREEN}blocked{C_RESET} {name}. Messages from {name} are ignored from now on, and \
         you cannot send to {name}."
    );
    let hint = SendCtx {
        pub_hex: parse_pub_hex(contact_pub)
            .map(hex::encode)
            .unwrap_or_default(),
        ..SendCtx::default()
    };
    println!("{C_DIM}{}{C_RESET}", unblock_hint(&hint));
    true
}

/// The file that remembers which messages the chat has already shown cannot be
/// read, so the chat cannot open. It holds no messages, but it also remembers
/// which conversations were cleared (`/clear-local-history`): moving it aside
/// makes the old messages of those show up again, so say so.
fn cursor_unavailable_text(raw: &str, data_dir: &Path) -> String {
    format!(
        "chat not opened: the file that remembers which messages you have already seen ({}) \
         cannot be used. Your messages and contacts are not affected. If you move that file \
         aside (keep it if you want to look at it), the chat opens again, but conversations \
         you cleared with /clear-local-history show their old messages again. \
         (technical: {raw})",
        chat_inbox_cursors_path(data_dir).display()
    )
}

/// Why the chat history cannot be used, in the user's words, and what to do (the
/// raw reason stays at the end). `None` for a reason no sentence covers.
fn history_problem_text(raw: &str, data_dir: &Path) -> Option<String> {
    let ctx = SendCtx {
        data_dir: Some(data_dir.to_path_buf()),
        ..SendCtx::default()
    };
    match classify_cause(raw) {
        cause @ (Cause::HistoryUnreadable | Cause::KeychainDenied | Cause::HistoryLocked) => {
            Some(format!(
                "{}. {} (technical: {raw})",
                cause_sentence(cause, &ctx, raw, false),
                next_step(cause, &ctx, false, raw)
            ))
        }
        _ => None,
    }
}

/// The history could not be opened when the chat started.
fn history_unavailable_text(raw: &str, data_dir: &Path) -> String {
    format!(
        "local protected history unavailable: {}",
        history_problem_text(raw, data_dir).unwrap_or_else(|| raw.to_string())
    )
}

/// The background reader could not list or save new messages. The same history
/// problems end here, and a bare "chat history is corrupt" has no way out.
fn inbox_problem_text(raw: &str, data_dir: &Path) -> String {
    format!(
        "inbox: {}",
        history_problem_text(raw, data_dir).unwrap_or_else(|| raw.to_string())
    )
}

/// The `SendCtx` of one chat line: transcript lines, and the carrier choice
/// and friend custody of the `ash send --chat` that opened the chat (G4:
/// `auto` unless `--carrier lan` or `--peer`).
fn chat_send_ctx(
    data_dir: &Path,
    petname: &str,
    tag: &str,
    pub_hex: &str,
    choice: raven_core::outbox::CarrierChoice,
    custody_ok: bool,
) -> SendCtx {
    SendCtx {
        chat: true,
        choice: Some(choice),
        custody_ok,
        ..send_ctx(data_dir, petname, tag, pub_hex)
    }
}

/// `choice` / `custody_ok`: what every line of this chat records when it has
/// to wait for raven-node's outbox ([`chat_send_ctx`]).
#[allow(clippy::too_many_arguments)]
pub fn cmd_chat_session(
    data_dir: &Path,
    id: &Identity,
    contact_petname: &str,
    contact_tag: &str,
    contact_pub: &str,
    peer_listen: &str,
    choice: raven_core::outbox::CarrierChoice,
    custody_ok: bool,
) {
    let name = chat_name(contact_petname, contact_tag, contact_pub);
    println!("{}", chat_header(&name, contact_tag));
    println!(
        "{C_DIM}  type a message and press Enter · /help lists the commands · /back leaves{C_RESET}"
    );
    if let Some(note) = chat_receiver_note(receiver_state(data_dir, CHAT_RECEIVER_PROBE), &name) {
        eprintln!("{note}");
    }
    let mut starting_cursor = match load_durable_inbox_cursor(data_dir, contact_pub) {
        Ok(c) => c,
        Err(e) => {
            // Nothing else can open this chat, and ending quietly with exit 0 hid
            // that: say what file it is and that nothing was lost.
            eprintln!("{}", cursor_unavailable_text(&e, data_dir));
            std::process::exit(1);
        }
    };
    let mut peer_history_nonempty = false;
    // Ids of the inbound rows the history dump below actually prints. The daemon
    // persists every received message to the history when it arrives, so a
    // message that came in while the chat was closed is in the dump *and* still
    // after the saved inbox cursor: without this it was shown twice.
    let mut shown: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
    match ChatHistory::load(data_dir).map(ChatHistory::without_group_copies) {
        Ok(history) => {
            let rows = history.for_peer(contact_pub);
            peer_history_nonempty = !rows.is_empty();
            if rows.is_empty() {
                println!("{C_DIM}(no local history){C_RESET}");
            } else {
                for e in rows.iter().rev().take(20).rev() {
                    if e.direction == "in" {
                        if let Some(id) = hex::decode(&e.message_id_hex)
                            .ok()
                            .and_then(|b| <[u8; 16]>::try_from(b).ok())
                        {
                            shown.insert(id);
                        }
                    }
                    let dir = if e.direction == "out" { "→" } else { "←" };
                    let text = if e.body.is_empty() {
                        e.preview.as_str()
                    } else {
                        e.body.as_str()
                    };
                    let mid: String = e.message_id_hex.chars().take(8).collect();
                    println!(
                        "  {C_DIM}{}{C_RESET} {} {}{}",
                        sanitize_terminal_line(&mid),
                        dir,
                        sanitize_terminal_line(text),
                        super::delivery_suffix(e)
                    );
                }
            }
        }
        Err(error) => {
            eprintln!("{}", history_unavailable_text(&error.to_string(), data_dir));
        }
    }
    // History already covers prior inbox traffic; avoid replaying it under the
    // history dump when this peer has never had a durable cursor saved.
    if starting_cursor.is_start() && peer_history_nonempty {
        match advance_inbox_cursor_past_peer(data_dir, contact_pub) {
            Ok(c) => starting_cursor = c,
            Err(e) => eprintln!("inbox cursor catch-up failed: {e}"),
        }
    } else {
        match place_inbox_cursor(data_dir, contact_pub, starting_cursor) {
            Ok(c) => starting_cursor = c,
            Err(e) => eprintln!("{}", inbox_problem_text(&e, data_dir)),
        }
    }
    let inbox_cursor = std::sync::Arc::new(std::sync::Mutex::new(starting_cursor));
    let pending_lines = std::sync::Arc::new(std::sync::Mutex::new(ChatPendingQueue::default()));
    if let Ok(mut cursor) = inbox_cursor.lock() {
        loop {
            match peek_endpoint_inbox_for_contact(data_dir, contact_pub, &cursor) {
                Ok(None) => break,
                Ok(Some(batch)) => {
                    print_unseen_lines(&batch, &mut shown);
                    *cursor = batch.cursor_after;
                    if let Err(e) = save_durable_inbox_cursor(data_dir, contact_pub, &cursor) {
                        eprintln!("inbox cursor save failed: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("{}", inbox_problem_text(&e, data_dir));
                    break;
                }
            }
        }
    }

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_c = std::sync::Arc::clone(&stop);
    let cursor_c = std::sync::Arc::clone(&inbox_cursor);
    let pending_c = std::sync::Arc::clone(&pending_lines);
    let data_dir_c = data_dir.to_path_buf();
    let contact_c = contact_pub.to_string();
    // `peek_gate` serialises one whole peek with `/clear-local-history`; `epoch`
    // counts the clears. Neither is the cursor lock, which the prompt needs: a
    // peek persists to the protected history (keystore, SQLite) and can stall, and
    // while it held the cursor lock the chat could not even redraw its prompt.
    let peek_gate = std::sync::Arc::new(std::sync::Mutex::new(()));
    let epoch = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (gate_c, epoch_c) = (
        std::sync::Arc::clone(&peek_gate),
        std::sync::Arc::clone(&epoch),
    );
    let notice_prompt = format!("{C_PURPLE}{name}>{C_RESET} ");
    let poller = std::thread::spawn(move || {
        use std::sync::atomic::Ordering::SeqCst;
        while !stop_c.load(SeqCst) {
            std::thread::sleep(Duration::from_millis(500));
            if stop_c.load(SeqCst) {
                break;
            }
            if chat_queue_blocks_poll(&pending_c) {
                continue;
            }
            // Only `/clear-local-history` waits on this gate. Within it, the
            // cursor lock is held just to read the start position and again to
            // publish; the slow peek in between holds neither.
            let Ok(_gate) = gate_c.lock() else {
                break;
            };
            let (start, seen_epoch) = {
                let Ok(shared) = cursor_c.lock() else {
                    break;
                };
                (
                    poll_cursor_with_pending(&pending_c, *shared),
                    epoch_c.load(SeqCst),
                )
            };
            let peeked = peek_endpoint_inbox_for_contact(&data_dir_c, &contact_c, &start);
            let Ok(mut shared) = cursor_c.lock() else {
                break;
            };
            // A clear while this ran moved the tombstone past these rows (the
            // gate keeps that from happening mid-peek, this is the cheap recheck):
            // drop the batch, the next tick starts from the new cursor.
            if epoch_c.load(SeqCst) != seen_epoch
                || poll_cursor_with_pending(&pending_c, *shared) != start
            {
                continue;
            }
            match peeked {
                Ok(None) => {}
                Ok(Some(batch)) if batch.lines.is_empty() => {
                    if !absorb_silent_batch(&pending_c, batch.cursor_after) {
                        *shared = batch.cursor_after;
                    }
                }
                Ok(Some(batch)) => {
                    if push_chat_batch(&pending_c, batch) {
                        // The chat sits in a blocking read until Enter, so say a
                        // message is waiting; the lines themselves are only ever
                        // printed between prompts (never over a half-typed line).
                        println!(
                            "\n{C_DIM}  (new message — press Enter to show){C_RESET}\n{notice_prompt}"
                        );
                        let _ = io::stdout().flush();
                    }
                }
                Err(e) => set_chat_pending_error(&pending_c, e),
            }
            drop(shared);
        }
    });

    loop {
        // Never clear the half-typed line: print queued inbox only between prompts.
        if let Ok(mut cursor) = inbox_cursor.lock() {
            drain_chat_pending(
                data_dir,
                contact_pub,
                &pending_lines,
                &mut cursor,
                &mut shown,
            );
        }
        print!("{C_PURPLE}{name}>{C_RESET} ");
        let _ = io::stdout().flush();
        let line = match read_line_result() {
            LineResult::Eof | LineResult::Err => {
                println!("{C_DIM}left chat{C_RESET}");
                break;
            }
            LineResult::BadInput => {
                eprintln!(
                    "input was not valid UTF-8, line skipped (nothing was sent; is your \
                     terminal set to UTF-8?)"
                );
                continue;
            }
            LineResult::Line(line) => line,
        };
        match classify_chat_input(&line) {
            ChatInput::Empty => continue,
            ChatInput::Help { bare } => {
                if bare {
                    println!(
                        "{C_DIM}\"{}\" is not sent to {name}; here are the chat commands:{C_RESET}",
                        sanitize_terminal_line(&line)
                    );
                }
                for help_line in chat_help_lines(&name, contact_tag) {
                    println!("{C_DIM}{help_line}{C_RESET}");
                }
            }
            ChatInput::Leave { bare } => {
                if bare {
                    println!(
                        "{C_DIM}\"{}\" leaves the chat; it is not sent to {name}.{C_RESET}",
                        sanitize_terminal_line(&line)
                    );
                }
                println!("{C_DIM}left chat{C_RESET}");
                break;
            }
            ChatInput::Command("/info") => {
                println!(
                    "{C_DIM}petname{C_RESET} {}",
                    sanitize_terminal_line(contact_petname)
                );
                if !contact_tag.is_empty() {
                    println!(
                        "{C_DIM}tag{C_RESET}     @{}",
                        sanitize_terminal_line(contact_tag)
                    );
                }
                println!(
                    "{C_DIM}pub{C_RESET}     {}",
                    sanitize_terminal_line(contact_pub)
                );
                if let Ok(p) = parse_pub_hex(contact_pub) {
                    println!("{C_DIM}fp{C_RESET}      {}", device_fingerprint_v1(&p));
                    println!(
                        "{C_DIM}words{C_RESET}   {}",
                        info_words(data_dir, contact_pub, &p, &name)
                    );
                    println!("{C_DIM}address{C_RESET} {}", encode_address(&p));
                }
            }
            ChatInput::Command("/verify") => {
                for verify_line in chat_verify_lines(data_dir, id, contact_pub, &name) {
                    println!("{verify_line}");
                }
            }
            ChatInput::Command("/block") => {
                if chat_block(data_dir, contact_pub, &name) {
                    // Nothing can be sent to them now: the chat ends here.
                    println!("{C_DIM}left chat{C_RESET}");
                    break;
                }
            }
            ChatInput::Command("/clear-local-history") => {
                // Behind the peek gate (no peek is in flight) and under the
                // cursor lock, so the poller cannot re-persist or queue rows
                // from before the tombstone while it runs; the epoch bump
                // makes any peek that did start before it discard its batch.
                let _gate = peek_gate.lock().unwrap_or_else(|e| e.into_inner());
                if let Ok(mut cursor) = inbox_cursor.lock() {
                    match clear_peer_history_with_tombstone(data_dir, contact_pub) {
                        Ok((c, _)) => {
                            *cursor = c;
                            epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            discard_chat_pending(&pending_lines);
                            println!("{}", chat_cleared_text(&name));
                        }
                        Err(error) => {
                            eprintln!("local history clear failed: {error}");
                        }
                    }
                }
            }
            ChatInput::Command(other) => println!(
                "{C_DIM}unknown command:{C_RESET} {} {C_DIM}— type /help{C_RESET}",
                sanitize_terminal_line(other)
            ),
            ChatInput::Send(text) => {
                let ctx = chat_send_ctx(
                    data_dir,
                    contact_petname,
                    contact_tag,
                    contact_pub,
                    choice,
                    custody_ok,
                );
                let sent = send_with(
                    data_dir,
                    id,
                    peer_listen,
                    contact_pub,
                    "127.0.0.1:0",
                    text,
                    &ctx,
                    super::pair_init_lab::DialCarrier::Lan,
                );
                let (echo, failure) = chat_echo(text, &sent, &name);
                println!("{echo}");
                if let Some(failure) = failure {
                    eprintln!("{failure}");
                }
                // No second inbox reader here: the poller is the only producer and
                // the drain at the top of the loop the only consumer. A peek from
                // the shared cursor ignored queued batches, printed their rows
                // now and again at the next drain, and could save the cursor
                // behind what was already shown.
            }
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = poller.join();
    if let Ok(mut cursor) = inbox_cursor.lock() {
        drain_chat_pending(
            data_dir,
            contact_pub,
            &pending_lines,
            &mut cursor,
            &mut shown,
        );
    };
}

// ── Real prekey publish ───────────────────────────────────────────────────

pub fn cmd_prekey_publish_real(
    data_dir: &Path,
    id: &Identity,
    device_id: &str,
    out: Option<&Path>,
) -> Result<(), String> {
    let device_id = if device_id.trim().is_empty() {
        PRIMARY_DEVICE_ID
    } else {
        device_id
    };
    ensure_local_device_certificate(data_dir, id, device_id)
        .map_err(|e| format!("device cert: {e}"))?;

    let mut rng = rand::thread_rng();
    let mut kp = HybridKeypair::generate(&mut rng);

    let now = now_ms();
    let actor = match PrekeyLifecycleActor::open(data_dir) {
        Ok(a) => a,
        Err(e) => {
            kp.x25519_secret.zeroize();
            kp.mlkem_seed.zeroize();
            return Err(format!("prekey actor: {e}"));
        }
    };
    // Above every id this identity signed or still publishes, and never below
    // the wall-clock floor: after a reinstall contacts accept it as a rotation.
    // An unreadable store fails here, before a lifecycle generation is spent.
    let published = match raven_core::PrekeyStore::load_checked(data_dir) {
        Ok(store) => store
            .fetch_valid(&id.public_key_bytes(), now)
            .map_or(0, |b| b.signed_prekey_id),
        Err(e) => {
            kp.x25519_secret.zeroize();
            kp.mlkem_seed.zeroize();
            return Err(format!("prekey store: {e}"));
        }
    };
    let next_id = match actor
        .status()
        .map_err(|e| e.to_string())
        .and_then(|status| {
            raven_core::prekey_lifecycle::next_signed_prekey_id(
                status.highest_signed_prekey_id,
                published,
                0,
                now,
            )
            .map_err(|e| e.to_string())
        }) {
        Ok(id) => id,
        Err(e) => {
            kp.x25519_secret.zeroize();
            kp.mlkem_seed.zeroize();
            return Err(format!("prekey status: {e}"));
        }
    };
    let bundle = match PrekeyBundle::from_hybrid_public(
        sanitize_terminal_text(device_id),
        kp.x25519_public,
        kp.mlkem_ek_bytes.clone(),
        next_id,
        now,
        now.saturating_add(30 * 24 * 3600 * 1000),
    ) {
        Ok(b) => b,
        Err(e) => {
            kp.x25519_secret.zeroize();
            kp.mlkem_seed.zeroize();
            return Err(e);
        }
    };
    let bundle = match bundle.sign(id) {
        Ok(b) => b,
        Err(e) => {
            kp.x25519_secret.zeroize();
            kp.mlkem_seed.zeroize();
            return Err(format!("sign: {e}"));
        }
    };

    // Private material is durable only via PrekeyLifecycleActor's protected
    // backend. Do not also write a plaintext `prekey_hybrid.secret` duplicate.
    // Delete any legacy plaintext first so a failed remove cannot leave a
    // consumed generation while the command still fails (retry would burn gens).
    let legacy = data_dir.join("prekey_hybrid.secret");
    if legacy.exists() {
        std::fs::remove_file(&legacy).map_err(|e| {
            format!("legacy prekey_hybrid.secret still present and could not be removed: {e}")
        })?;
    }
    // Build the private half straight from `kp` (no named stack copies that
    // would outlive this call), then wipe `kp`; `private` wipes itself on drop,
    // including when install_generation fails.
    let private = PrekeyGenerationPrivate::new(kp.x25519_secret, kp.mlkem_seed, vec![]);
    kp.x25519_secret.zeroize();
    kp.mlkem_seed.zeroize();
    actor
        .install_generation(std::slice::from_ref(&bundle), private, now)
        .map_err(|e| format!("prekey install_generation: {e}"))?;

    raven_core::publish_local_prekey_bundle_checked(data_dir, &bundle, now)
        .map_err(|e| format!("publish: {e}"))?;
    println!("{C_GREEN}prekey published{C_RESET} (real X25519 + ML-KEM-768 EK)");
    println!(
        "{C_DIM}store_key{C_RESET} {}",
        hex::encode(PrekeyBundle::store_key(&id.public_key_bytes()))
    );
    println!("{C_DIM}note{C_RESET}      never FastAPI — OOB/file/DHT only");
    if let Some(path) = out {
        let j = bundle.to_json();
        let raw =
            serde_json::to_string_pretty(&j).map_err(|e| format!("prekey export encode: {e}"))?;
        raven_core::atomic_write_private(path, raw.as_bytes())
            .map_err(|e| format!("prekey export write: {e}"))?;
        println!("{C_DIM}oob_file{C_RESET} {}", path.display());
    }
    Ok(())
}

/// The text of a styled line: the palette is live whenever the test run has a
/// terminal, and assertions are about words.
#[cfg(test)]
fn plain(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod sync_row_tests {
    use super::*;

    #[test]
    fn sync_rows_must_bind_address_to_key() {
        let alice = Identity::from_seed(&[0x41; 32]);
        let mallory = Identity::from_seed(&[0x4d; 32]);
        let a_hex = hex::encode(alice.public_key_bytes());
        let (pub_hex, address) =
            validate_sync_row(&alice.address(), &a_hex.to_uppercase()).unwrap();
        assert_eq!(pub_hex, a_hex);
        assert_eq!(address, alice.address());
        // Alice's address with Mallory's key is refused (was imported verbatim).
        assert!(
            validate_sync_row(&alice.address(), &hex::encode(mallory.public_key_bytes())).is_err()
        );
        assert!(validate_sync_row(&alice.address(), "zz").is_err());
        assert!(validate_sync_row("not-an-address", &a_hex).is_err());
    }
}

#[cfg(test)]
mod chat_cursor_tests {
    use super::*;
    use std::sync::Mutex;

    const PEER: &str = "AB00000000000000000000000000000000000000000000000000000000000001";

    fn cur(ms: u64, id: u8) -> InboxCursor {
        InboxCursor::received(ms, Some([id; 16]))
    }

    fn batch(ms: u64, id: u8) -> PendingInboxBatch {
        PendingInboxBatch {
            lines: vec![InboxLine {
                message_id: [id; 16],
                text: format!("line {ms}"),
            }],
            cursor_after: cur(ms, id),
        }
    }

    #[test]
    fn durable_cursor_round_trips_per_peer_and_case_insensitively() {
        let dir = tempfile::tempdir().unwrap();
        let load = |peer: &str| load_durable_inbox_cursor(dir.path(), peer).unwrap();
        assert_eq!(load(PEER), InboxCursor::default());
        save_durable_inbox_cursor(dir.path(), PEER, &cur(42, 7)).unwrap();
        let other = "cd00000000000000000000000000000000000000000000000000000000000002";
        save_durable_inbox_cursor(dir.path(), other, &cur(9, 1)).unwrap();
        assert_eq!(load(&PEER.to_lowercase()), cur(42, 7));
        assert_eq!(load(PEER), cur(42, 7));
        assert_eq!(load(other), cur(9, 1));
        // A cursor without message id (legacy) still parses.
        let entry = serde_json::json!({ "received_at_ms": 5 });
        let c = parse_cursor_entry(&entry).unwrap();
        assert_eq!(c, InboxCursor::received(5, None));
        // Format 2 (PP.14): a sealed profile's store counts its rows.
        save_durable_inbox_cursor(dir.path(), PEER, &InboxCursor::seq(17)).unwrap();
        assert_eq!(load(PEER), InboxCursor::seq(17));
        let raw = std::fs::read_to_string(chat_inbox_cursors_path(dir.path())).unwrap();
        assert!(raw.contains("\"seq\": 17"), "{raw}");
        assert!(parse_cursor_entry(&serde_json::json!({ "seq": "x" })).is_err());
    }

    /// Privacy pack PP.6: in a sealed profile the cursors (which friends
    /// you chat with, and the conversations you cleared) are RMS1 kind 9;
    /// one this process cannot open keeps the chat closed with the same
    /// sentence and is never written over.
    #[test]
    fn sealed_cursors_round_trip_and_an_unopenable_file_keeps_the_chat_closed() {
        let lab = ["RAVEN_CHAT_HISTORY_BACKEND", "RAVEN_IDENTITY_BACKEND"]
            .iter()
            .any(|k| std::env::var(k).is_ok_and(|v| v == "locked-file"));
        if !(cfg!(windows) || (cfg!(debug_assertions) && lab)) {
            eprintln!("skipped: needs a debug build and RAVEN_CHAT_HISTORY_BACKEND=locked-file");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        std::fs::write(dd.join(raven_core::BACKEND_MARKER_NAME), b"locked-file\n").unwrap();
        save_durable_inbox_cursor(dd, PEER, &cur(42, 7)).unwrap();
        let report = raven_core::privacy::migrate_all(
            dd,
            now_ms(),
            raven_core::at_rest::MigratePolicy::Allow,
        )
        .unwrap();
        assert_eq!(report.outcome, raven_core::privacy::MigrateOutcome::Sealed);
        let path = chat_inbox_cursors_path(dd);
        let sealed = |raw: &[u8]| raven_core::at_rest::is_sealed(raw) && raw[5] == 9;
        assert!(sealed(&std::fs::read(&path).unwrap()), "migrated");
        assert_eq!(load_durable_inbox_cursor(dd, PEER).unwrap(), cur(42, 7));
        let other = "cd00000000000000000000000000000000000000000000000000000000000002";
        save_durable_inbox_cursor(dd, other, &cur(9, 1)).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(sealed(&raw), "written sealed");
        assert!(!String::from_utf8_lossy(&raw).contains(other));
        assert_eq!(load_durable_inbox_cursor(dd, other).unwrap(), cur(9, 1));
        // The key not loaded: the chat stays closed, nothing is written.
        raven_core::at_rest::forget_cached_keys(dd);
        let err = load_durable_inbox_cursor(dd, PEER).unwrap_err();
        assert!(err.starts_with("inbox cursor read failed"), "{err}");
        assert!(cursor_unavailable_text(&err, dd).starts_with("chat not opened"));
        assert!(save_durable_inbox_cursor(dd, PEER, &cur(50, 8)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), raw);
        // A changed byte: corrupt, never overwritten.
        raven_core::at_rest::keys_load_with(dd, raven_core::at_rest::MigratePolicy::Allow).unwrap();
        let mut bad = raw.clone();
        *bad.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &bad).unwrap();
        let err = load_durable_inbox_cursor(dd, PEER).unwrap_err();
        assert!(err.starts_with("inbox cursor corrupt"), "{err}");
        let err = save_durable_inbox_cursor(dd, PEER, &cur(50, 8)).unwrap_err();
        assert!(err.contains("refusing overwrite"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), bad);
    }

    #[test]
    fn corrupt_cursor_file_is_reported_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = chat_inbox_cursors_path(dir.path());
        for bad in [&b"{not json"[..], b"[1,2]"] {
            std::fs::write(&path, bad).unwrap();
            let err = load_durable_inbox_cursor(dir.path(), PEER).unwrap_err();
            assert!(err.contains("corrupt"), "{err}");
            let err = save_durable_inbox_cursor(dir.path(), PEER, &cur(1, 1)).unwrap_err();
            assert!(err.contains("refusing overwrite"), "{err}");
            assert_eq!(std::fs::read(&path).unwrap(), bad);
        }
        for entry in [
            serde_json::json!("x"),
            serde_json::json!({}),
            serde_json::json!({ "received_at_ms": 1, "message_id_hex": "00" }),
            serde_json::json!({ "received_at_ms": 1, "message_id_hex": 3 }),
        ] {
            assert!(parse_cursor_entry(&entry).is_err(), "{entry}");
        }
    }

    #[test]
    fn pending_queue_defers_one_batch_when_full_and_polls_from_newest() {
        let q = Mutex::new(ChatPendingQueue::default());
        let shared = cur(1, 1);
        assert_eq!(poll_cursor_with_pending(&q, shared), shared);
        assert!(!chat_queue_blocks_poll(&q));
        for i in 0..CHAT_PENDING_MAX as u64 {
            push_chat_batch(&q, batch(10 + i, 2));
        }
        // Next poll continues after the newest queued batch, not the shared one.
        let newest = cur(10 + CHAT_PENDING_MAX as u64 - 1, 2);
        assert_eq!(poll_cursor_with_pending(&q, shared), newest);
        assert!(chat_queue_blocks_poll(&q));
        // Full: exactly one deferred batch is kept; later pushes are dropped
        // (the poller is blocked, so they are re-peeked from the cursor).
        push_chat_batch(&q, batch(500, 3));
        push_chat_batch(&q, batch(600, 4));
        let g = q.lock().unwrap();
        assert_eq!(g.batches.len(), CHAT_PENDING_MAX);
        assert_eq!(g.deferred.as_ref().unwrap().cursor_after, cur(500, 3));
    }

    #[test]
    fn drain_advances_and_persists_cursor_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let q = Mutex::new(ChatPendingQueue::default());
        push_chat_batch(&q, batch(10, 1));
        push_chat_batch(&q, batch(20, 2));
        q.lock().unwrap().deferred = Some(batch(30, 3));
        set_chat_pending_error(&q, "boom".into());
        let mut cursor = cur(5, 0);
        drain_chat_pending(
            dir.path(),
            PEER,
            &q,
            &mut cursor,
            &mut std::collections::HashSet::new(),
        );
        assert_eq!(cursor, cur(30, 3), "deferred batch is drained last");
        assert_eq!(
            load_durable_inbox_cursor(dir.path(), PEER).unwrap(),
            cur(30, 3)
        );
        let g = q.lock().unwrap();
        assert!(g.batches.is_empty() && g.deferred.is_none() && g.last_error.is_none());
        drop(g);
        // Nothing queued → cursor unchanged, file untouched.
        let path = chat_inbox_cursors_path(dir.path());
        let before = std::fs::read(&path).unwrap();
        drain_chat_pending(
            dir.path(),
            PEER,
            &q,
            &mut cursor,
            &mut std::collections::HashSet::new(),
        );
        assert_eq!(cursor, cur(30, 3));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn cursor_order_matches_the_sql_order() {
        // (received_at_ms, message_id), "no id" below any id.
        let none = |ms| InboxCursor::received(ms, None);
        assert!(none(5) < cur(5, 0));
        assert!(cur(5, 0) < cur(5, 1));
        assert!(cur(5, 255) < cur(6, 0));
        assert!(none(6) > cur(5, 255));
        assert_eq!(cur(5, 1).max(cur(5, 2)), cur(5, 2));
        // A sealed profile's store (PP.14): by `seq`, after every position of
        // the clear order (a store only moves forward).
        assert!(InboxCursor::seq(1) < InboxCursor::seq(2));
        assert!(cur(u64::MAX, 255) < InboxCursor::seq(0));
    }

    /// A batch queued before the cursor moved on (the same rows shown by another
    /// path, or cleared by `/clear-local-history`) must neither print again nor
    /// drag the durable cursor backwards.
    #[test]
    fn drain_skips_stale_batches_and_never_moves_the_cursor_back() {
        let dir = tempfile::tempdir().unwrap();
        let q = Mutex::new(ChatPendingQueue::default());
        let mut cursor = cur(50, 5);
        save_durable_inbox_cursor(dir.path(), PEER, &cursor).unwrap();
        push_chat_batch(&q, batch(30, 3)); // behind the cursor
        push_chat_batch(&q, batch(50, 5)); // exactly at the cursor
        push_chat_batch(&q, batch(60, 6)); // genuinely new
        drain_chat_pending(
            dir.path(),
            PEER,
            &q,
            &mut cursor,
            &mut std::collections::HashSet::new(),
        );
        assert_eq!(cursor, cur(60, 6));
        assert_eq!(
            load_durable_inbox_cursor(dir.path(), PEER).unwrap(),
            cur(60, 6)
        );

        // Only stale batches queued: cursor and file stay exactly as they were.
        let path = chat_inbox_cursors_path(dir.path());
        let before = std::fs::read(&path).unwrap();
        push_chat_batch(&q, batch(10, 1));
        q.lock().unwrap().deferred = Some(batch(60, 6));
        drain_chat_pending(
            dir.path(),
            PEER,
            &q,
            &mut cursor,
            &mut std::collections::HashSet::new(),
        );
        assert_eq!(cursor, cur(60, 6));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn discard_drops_queued_batches_deferred_and_error() {
        let q = Mutex::new(ChatPendingQueue::default());
        push_chat_batch(&q, batch(10, 1));
        q.lock().unwrap().deferred = Some(batch(20, 2));
        set_chat_pending_error(&q, "boom".into());
        discard_chat_pending(&q);
        let g = q.lock().unwrap();
        assert!(g.batches.is_empty() && g.deferred.is_none() && g.last_error.is_none());
    }
}

#[cfg(all(test, unix))]
mod prekey_private_store_tests {
    use super::*;
    use tempfile::tempdir;

    /// The lab file-backed prekey store. These tests must never reach the OS
    /// keychain, whatever environment `cargo test` runs in (on a Mac the real
    /// backend is the login Keychain: a dialog, or an item left behind). Set once
    /// and left set, never restored: the other tests of this binary use the same
    /// backend and a restore would race with them.
    fn lab_prekey_backend() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| unsafe { std::env::set_var("RAVEN_PREKEY_BACKEND", "locked-file") });
    }

    #[test]
    fn persistence_failure_prevents_publication_and_export() {
        lab_prekey_backend();
        let dir = tempdir().expect("tempdir");
        let unusable_data_dir = dir.path().join("not-a-directory");
        std::fs::write(&unusable_data_dir, b"blocker").expect("blocker");
        let export = dir.path().join("public-prekey.json");
        let identity = Identity::from_seed(&[0x55; 32]);

        let err =
            cmd_prekey_publish_real(&unusable_data_dir, &identity, "test-device", Some(&export));
        assert!(err.is_err());

        assert!(!export.exists());
        assert!(!unusable_data_dir.join("prekey_store.json").exists());
        assert!(!unusable_data_dir.join("prekey_hybrid.secret").exists());
    }

    #[test]
    fn publish_does_not_write_plaintext_hybrid_secret() {
        let dir = tempdir().expect("tempdir");
        let identity = Identity::from_seed(&[0x77; 32]);
        // rust-linux has no Secret Service. The explicit lab locked-file
        // backend lets publish succeed so we can assert it still never writes
        // a plaintext hybrid secret.
        lab_prekey_backend();
        cmd_prekey_publish_real(dir.path(), &identity, PRIMARY_DEVICE_ID, None).expect("publish");
        assert!(!dir.path().join("prekey_hybrid.secret").exists());
        assert!(dir.path().join("prekey_store.json").exists());
    }

    /// Lost-state recovery §4: the lifecycle state is gone but the store still
    /// holds our earlier (legacy counter) bundle. The next publish takes an id
    /// above it and at least the wall-clock floor, so a contact that pinned the
    /// old bundle accepts the new one as a rotation.
    #[test]
    fn prekey_publish_after_state_loss_uses_time_floor() {
        lab_prekey_backend();
        let dir = tempdir().expect("tempdir");
        let identity = Identity::from_seed(&[0x78; 32]);
        let earlier = now_ms() - 60_000;
        let kp = HybridKeypair::generate(&mut rand::thread_rng());
        let old = PrekeyBundle::from_hybrid_public(
            PRIMARY_DEVICE_ID,
            kp.x25519_public,
            kp.mlkem_ek_bytes.clone(),
            7,
            earlier,
            earlier + 30 * 24 * 3600 * 1000,
        )
        .unwrap()
        .sign(&identity)
        .unwrap();
        let mut store = PrekeyStore::default();
        store.publish(&old, earlier).unwrap();
        store.save(dir.path()).unwrap();
        let mut contact_pin = store.clone();

        let floor = raven_core::prekey_lifecycle::time_floor_signed_prekey_id(now_ms());
        cmd_prekey_publish_real(dir.path(), &identity, PRIMARY_DEVICE_ID, None).expect("publish");
        let fresh = PrekeyStore::load_checked(dir.path())
            .unwrap()
            .fetch_valid(&identity.public_key_bytes(), now_ms())
            .unwrap();
        assert!(fresh.signed_prekey_id > 7 && fresh.signed_prekey_id >= floor);
        contact_pin
            .publish(&fresh, now_ms())
            .expect("the old pin accepts the new bundle");
    }
}

/// `contact add --prekey-file`: verify the OOB bundle against the contact key
/// and store it in the local prekey store (same path as `ash prekey fetch`).
pub fn contact_add_fetch_prekey(
    data_dir: &Path,
    pub_hex: &str,
    prekey_file: Option<&Path>,
) -> Result<(), String> {
    // Same (whoami-line tolerant) parser `contact add` just accepted.
    let ed = super::parse_pub_hex(pub_hex)?;
    let now = now_ms();
    let bundle = if let Some(path) = prekey_file {
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let j: PrekeyBundleJson = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        PrekeyBundle::from_json(&j)?
    } else {
        PrekeyStore::load_checked(data_dir)?
            .fetch(&ed, now)?
            .ok_or_else(|| "no prekey in local store (pass --prekey-file)".to_string())?
    };
    bundle.verify(now)?;
    if bundle.identity_ed25519_pub != ed {
        return Err("PREKEY_IDENTITY_MISMATCH".into());
    }
    raven_core::publish_prekey_bundle_checked(data_dir, &bundle, now)
        .map_err(|e| format!("store publish: {e}"))?;
    println!(
        "{C_GREEN}prekey ok{C_RESET} (verified, cached in prekey_store.json; fp={})",
        device_fingerprint_v1(&ed)
    );
    Ok(())
}

// ── Mailbox put/get (opaque tags) ─────────────────────────────────────────

pub fn mailbox_db_path(data_dir: &Path) -> PathBuf {
    data_dir.join("mailbox_store.json")
}

/// Serialises `mailbox put`'s load → put → save of `mailbox_store.json` (each
/// save atomically replaces the whole snapshot, so unlocked concurrent puts
/// would drop each other's objects while both reporting "stored").
const MAILBOX_LOCK: &str = ".mailbox_store.lock.sqlite";

fn mailbox_store_put(data_dir: &Path, obj: StoreObject) -> Result<(), String> {
    let _lock = raven_core::DataDirLock::acquire(data_dir, MAILBOX_LOCK)
        .map_err(|e| format!("mailbox lock: {e}"))?;
    let path = mailbox_db_path(data_dir);
    let mut mb =
        StoreMailbox::load_disk(&path, 64).map_err(|e| format!("mailbox database: {e}"))?;
    mb.put(obj).map_err(|e| format!("put: {e}"))?;
    mb.save_disk(&path)
        .map_err(|e| format!("mailbox persistence: {e}"))
}

pub fn cmd_mailbox_put(
    data_dir: &Path,
    k_route_hex: &str,
    epoch: u64,
    slot: u64,
    envelope_hex: &str,
) {
    let k = match hex::decode(k_route_hex.trim()) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("k_route_hex required");
            std::process::exit(1);
        }
    };
    let packed = match hex::decode(envelope_hex.trim()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("envelope hex: {e}");
            std::process::exit(1);
        }
    };
    let envelope = match Envelope::unpack(&packed) {
        Some(value) => value,
        None => {
            eprintln!("envelope must be a strict RavenEnvelopeV1 object");
            std::process::exit(1);
        }
    };
    let mtag = mailbox_tag(&k, epoch, slot);
    let store_tag = store_tag_from_mailbox(&mtag);
    let now = now_ms();
    if now < envelope.created_at || now >= envelope.expires_at {
        eprintln!("envelope is not within its validity window");
        std::process::exit(1);
    }
    let obj = StoreObject {
        store_tag,
        message_id: envelope.message_id,
        created_at_ms: now,
        expires_at_ms: envelope.expires_at,
        flags: 0,
        packed_envelope: packed,
        custody_sig: None,
    };
    if let Err(e) = mailbox_store_put(data_dir, obj) {
        eprintln!("{e}");
        std::process::exit(1);
    }
    println!("{C_GREEN}stored{C_RESET}");
    println!("{C_DIM}mailbox_tag{C_RESET} {}", hex::encode(mtag));
    println!(
        "{C_DIM}store_tag{C_RESET}   {} (opaque index — no username)",
        hex::encode(store_tag)
    );
}

pub fn cmd_mailbox_get(data_dir: &Path, k_route_hex: &str, epoch: u64, slot: u64) {
    let k = match hex::decode(k_route_hex.trim()) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("k_route_hex required");
            std::process::exit(1);
        }
    };
    let tags = mailbox_tags_with_overlap(&k, epoch, slot);
    let mb = match StoreMailbox::load_disk(&mailbox_db_path(data_dir), 64) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("mailbox database: {error}");
            std::process::exit(1);
        }
    };
    let now = now_ms();
    let mut found = 0usize;
    for mtag in &tags {
        let st = store_tag_from_mailbox(mtag);
        for obj in mb.get(&st, now) {
            found += 1;
            println!(
                "{C_GREEN}hit{C_RESET} store_tag={} msg={}… env_len={}",
                hex::encode(st),
                &hex::encode(obj.message_id)[..8],
                obj.packed_envelope.len()
            );
        }
    }
    if found == 0 {
        println!("{C_DIM}no objects for rotating mailbox tags{C_RESET}");
    } else {
        println!("{C_DIM}retrieved {found} (opaque tags only){C_RESET}");
    }
}

#[cfg(test)]
mod bootstrap_edit_tests {
    use super::*;

    fn seed_peers(dir: &Path) {
        bootstrap_add_apply(dir, "/ip4/10.0.0.1/tcp/4001", false).unwrap();
        bootstrap_add_apply(dir, "/ip4/10.0.0.2/tcp/4001", true).unwrap();
    }

    #[test]
    fn add_on_a_missing_file_starts_from_the_default_config() {
        let dir = tempfile::tempdir().unwrap();
        let added = bootstrap_add_apply(dir.path(), " /ip4/1.2.3.4/tcp/4001 ", false).unwrap();
        assert_eq!(added, "/ip4/1.2.3.4/tcp/4001");
        let cfg = try_load_bootstrap(dir.path()).unwrap();
        assert!(cfg.custom.iter().any(|p| p == "/ip4/1.2.3.4/tcp/4001"));
    }

    #[test]
    fn add_and_disable_never_overwrite_a_corrupt_bootstrap_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = raven_core::bootstrap::bootstrap_path(dir.path());
        for bad in [&b"{not json"[..], b"", b"[1,2,3]"] {
            std::fs::write(&path, bad).unwrap();
            let err = bootstrap_add_apply(dir.path(), "/ip4/1.2.3.4/tcp/4001", false).unwrap_err();
            assert!(err.contains("refusing to overwrite"), "{err}");
            assert!(err.contains("init-bootstrap"), "{err}");
            assert!(bootstrap_add_apply(dir.path(), "/ip4/1.2.3.4/tcp/1", true).is_err());
            assert!(bootstrap_disable_raven_apply(dir.path()).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bad, "file must be untouched");
        }
    }

    #[test]
    fn add_on_a_valid_file_keeps_existing_entries() {
        let dir = tempfile::tempdir().unwrap();
        seed_peers(dir.path());
        bootstrap_add_apply(dir.path(), "/ip4/10.0.0.3/tcp/4001", false).unwrap();
        let cfg = try_load_bootstrap(dir.path()).unwrap();
        assert!(cfg.custom.iter().any(|p| p == "/ip4/10.0.0.1/tcp/4001"));
        assert!(cfg.custom.iter().any(|p| p == "/ip4/10.0.0.3/tcp/4001"));
        assert!(cfg
            .manual_peers
            .iter()
            .any(|p| p == "/ip4/10.0.0.2/tcp/4001"));
        bootstrap_disable_raven_apply(dir.path()).unwrap();
        let cfg = try_load_bootstrap(dir.path()).unwrap();
        assert!(cfg.custom.iter().any(|p| p == "/ip4/10.0.0.1/tcp/4001"));
    }

    #[test]
    fn empty_multiaddr_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            bootstrap_add_apply(dir.path(), "   ", false).unwrap_err(),
            "empty multiaddr"
        );
    }
}

#[cfg(test)]
mod device_sync_import_tests {
    use super::*;

    fn sync_blob(owner: &Identity, contact: &Identity, issued_at_ms: u64) -> Vec<u8> {
        let plain = ContactSyncPlaintext {
            schema: 1,
            from_device_id: "ash-primary".into(),
            contacts: vec![SyncContact {
                petname: "bob".into(),
                public_tag: "bob".into(),
                alias: String::new(),
                address: contact.address(),
                pub_hex: hex::encode(contact.public_key_bytes()),
                pinned: false,
            }],
            issued_at_ms,
        };
        seal_contact_sync(owner, &plain).unwrap()
    }

    /// The import burns the per-sender replay watermark, so a contacts.json
    /// that cannot be loaded must fail BEFORE it: re-running the same sync file
    /// after fixing the file must work (it used to fail SYNC_REPLAY_OR_STALE).
    #[test]
    fn corrupt_contacts_fail_before_the_replay_watermark_is_consumed() {
        let owner = Identity::from_seed(&[0x71; 32]);
        let bob = Identity::from_seed(&[0x72; 32]);
        let dir = tempfile::tempdir().unwrap();
        let wire = sync_blob(&owner, &bob, now_ms());

        let contacts = dir.path().join("contacts.json");
        std::fs::write(&contacts, b"{not json").unwrap();
        let err = device_sync_import_apply(dir.path(), &owner, &wire).unwrap_err();
        assert!(err.contains("contacts.json corrupt"), "{err}");
        assert_eq!(std::fs::read(&contacts).unwrap(), b"{not json");

        std::fs::remove_file(&contacts).unwrap();
        assert_eq!(
            device_sync_import_apply(dir.path(), &owner, &wire).unwrap(),
            1,
            "same sync file imports once the book is readable"
        );
        let rows = load_local_contacts(dir.path()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pub_hex, hex::encode(bob.public_key_bytes()));

        // Replay protection is intact after a successful import.
        let err = device_sync_import_apply(dir.path(), &owner, &wire).unwrap_err();
        assert!(err.contains("SYNC_REPLAY_OR_STALE"), "{err}");
    }
}

#[cfg(test)]
mod device_revoke_tests {
    use super::*;

    fn device_revoked_in_registry(dir: &Path, device_id: &str) -> bool {
        load_device_registry_checked(dir)
            .unwrap()
            .is_revoked(device_id)
    }

    #[test]
    fn revoke_updates_store_and_registry_and_is_idempotent() {
        let owner = Identity::from_seed(&[0x73; 32]);
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            device_revoke_apply(dir.path(), &owner, "phone", 1).unwrap(),
            RevokeOutcome::Revoked
        );
        assert!(device_revoked_in_registry(dir.path(), "phone"));
        // Same epoch again: no new record, no REVOKE_EPOCH_CONFLICT.
        assert_eq!(
            device_revoke_apply(dir.path(), &owner, "phone", 1).unwrap(),
            RevokeOutcome::AlreadyRevoked
        );
        // Older epoch is also "already revoked"; a newer one is a new record.
        assert_eq!(
            device_revoke_apply(dir.path(), &owner, "phone", 0).unwrap(),
            RevokeOutcome::AlreadyRevoked
        );
        assert_eq!(
            device_revoke_apply(dir.path(), &owner, "phone", 2).unwrap(),
            RevokeOutcome::Revoked
        );
    }

    /// An earlier run saved revocations.json and then failed before the device
    /// registry. The rerun (same epoch, fresh signature) used to be refused as
    /// REVOKE_EPOCH_CONFLICT / "already applied" and never reached the registry.
    #[test]
    fn rerun_repairs_a_registry_left_behind_by_a_partial_revoke() {
        let owner = Identity::from_seed(&[0x74; 32]);
        let dir = tempfile::tempdir().unwrap();
        let mut store = RevocationStore::load_checked(dir.path()).unwrap();
        let rec = RevocationRecord::issue(&owner, "stolen", 1, 111, "operator-revoke").unwrap();
        assert!(store.apply(rec).unwrap());
        store.save(dir.path()).unwrap();
        assert!(
            !device_revoked_in_registry(dir.path(), "stolen"),
            "precondition: registry step never ran"
        );

        assert_eq!(
            device_revoke_apply(dir.path(), &owner, "stolen", 1).unwrap(),
            RevokeOutcome::AlreadyRevoked
        );
        assert!(device_revoked_in_registry(dir.path(), "stolen"));
    }

    #[test]
    fn corrupt_revocation_store_is_an_error_not_an_empty_store() {
        let owner = Identity::from_seed(&[0x75; 32]);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("revocations.json"), b"{not json").unwrap();
        let err = device_revoke_apply(dir.path(), &owner, "phone", 1).unwrap_err();
        assert!(err.contains("revocation store"), "{err}");
    }
}

#[cfg(test)]
mod mailbox_put_tests {
    use super::*;

    fn object(mid: u8) -> StoreObject {
        let expires = 9_000_000_000_000u64;
        let mut env = Envelope {
            env_type: raven_core::envelope::EnvType::Message as u8,
            flags: 0,
            message_id: [mid; 16],
            routing_tag: [3u8; 16],
            dest_device_hint: 0,
            created_at: 1,
            expires_at: expires,
            hop_limit: 4,
            replication_budget: 2,
            anti_replay_nonce: [4u8; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: vec![mid],
            sender_authentication: vec![],
        };
        env.sign_with(&Identity::from_seed(&[0x76; 32]));
        StoreObject {
            store_tag: [9u8; 16],
            message_id: [mid; 16],
            created_at_ms: 1,
            expires_at_ms: expires,
            flags: 0,
            packed_envelope: env.pack(),
            custody_sig: None,
        }
    }

    /// Each put atomically replaces the whole snapshot, so without the lock two
    /// racing puts start from the same snapshot and one object is lost.
    #[test]
    fn concurrent_puts_do_not_lose_objects() {
        const PUTS: u8 = 8;
        let dir = tempfile::tempdir().unwrap();
        std::thread::scope(|scope| {
            for mid in 1..=PUTS {
                let data_dir = dir.path();
                scope.spawn(move || mailbox_store_put(data_dir, object(mid)).unwrap());
            }
        });
        let mb = StoreMailbox::load_disk(&mailbox_db_path(dir.path()), 64).unwrap();
        assert_eq!(mb.get(&[9u8; 16], 2).len(), usize::from(PUTS));
    }

    #[test]
    fn put_into_a_corrupt_mailbox_is_refused_and_leaves_it_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = mailbox_db_path(dir.path());
        std::fs::write(&path, b"{not json").unwrap();
        let err = mailbox_store_put(dir.path(), object(1)).unwrap_err();
        assert!(err.contains("mailbox database"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"{not json");
    }
}

#[cfg(test)]
mod internet_gate_tests {
    use super::*;

    /// A refused lab-only Internet send must not change this machine's
    /// listening state: the gate fires before any daemon is started.
    #[test]
    fn internet_carrier_is_refused_before_a_daemon_is_started() {
        if raven_core::internet_direct_live_enabled() {
            return; // lab (debug + RAVEN_LAB_TEST_A=1): the gate is open by design
        }
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::from_seed(&[0x77; 32]);
        let peer_pub = hex::encode(Identity::from_seed(&[0x78; 32]).public_key_bytes());
        let err = run_send_secure_on(
            dir.path(),
            &id,
            "127.0.0.1:9",
            &peer_pub,
            "127.0.0.1:0",
            "hello",
            "",
            "",
            super::super::pair_init_lab::DialCarrier::Internet,
        )
        .unwrap_err();
        assert!(err.starts_with("INTERNET_DIRECT_HOLD"), "{err}");
        assert!(
            !daemon_log_path(dir.path()).exists(),
            "no daemon start was attempted"
        );
    }
}

#[cfg(all(test, unix))]
mod daemon_start_tests {
    use super::super::ipc_client::test_support::{
        short_tempdir, spawn_pong_server, spawn_status_server,
    };
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    fn shell(script: &str) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", script]);
        cmd
    }

    fn sleeper() -> Command {
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg("30");
        cmd
    }

    fn empty_slot() -> StartedDaemon {
        Mutex::new(None)
    }

    fn kill_started(slot: &StartedDaemon) {
        if let Some((mut child, _)) = slot.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    #[test]
    fn early_exit_is_reported_at_once_with_status_and_log_tail() {
        let dir = short_tempdir();
        let slot = empty_slot();
        let err = start_daemon(
            dir.path(),
            shell("echo 'service: boom' >&2; echo 'lan_direct failed to bind' >&2; exit 3"),
            Duration::from_secs(30),
            &slot,
        )
        .unwrap_err();
        assert!(err.contains("exited during startup"), "{err}");
        assert!(err.contains("exit status: 3"), "{err}");
        assert!(err.contains("service: boom"), "{err}");
        assert!(
            err.contains("RAVEN_SERVICE_LAN_LISTEN=127.0.0.1:0"),
            "{err}"
        );
        assert!(err.contains(DAEMON_LOG_NAME), "{err}");
        // The exited child was reaped (status cached), not left as a zombie.
        let mut held = slot.lock().unwrap();
        let (child, _) = held.as_mut().unwrap();
        assert!(child.try_wait().unwrap().is_some());
    }

    /// The detached daemon appends for weeks, so it is handed the cap for the log
    /// it was given (and only for a log ash opened): the running service
    /// truncates its own file in place, ash only enforces the cap at the next start.
    #[test]
    fn daemon_is_told_the_log_cap_for_the_log_it_was_given() {
        let dir = short_tempdir();
        let err = start_daemon(
            dir.path(),
            shell("echo \"cap=${RAVEN_SERVICE_LOG_MAX_BYTES:-unset}\" >&2; exit 1"),
            Duration::from_secs(30),
            &empty_slot(),
        )
        .unwrap_err();
        assert!(
            err.contains(&format!("cap={DAEMON_LOG_MAX_BYTES}")),
            "daemon must be told the cap: {err}"
        );
        // The variable name is the contract with raven-node.
        assert_eq!(DAEMON_LOG_MAX_ENV, "RAVEN_SERVICE_LOG_MAX_BYTES");
    }

    /// Holds the daemon's instance lock the way `raven-node` does (an exclusive
    /// `flock` on `<sock>.lock`) and, optionally, never answers on its socket.
    struct FakeService {
        _lock: std::fs::File,
        sock: PathBuf,
    }

    impl FakeService {
        fn wedged(data_dir: &Path) -> Self {
            let sock = raven_core::default_socket_path(data_dir);
            let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
            std::thread::spawn(move || {
                // Accept and sit on every connection: a stopped / deadlocked daemon.
                let mut held = Vec::new();
                for stream in listener.incoming() {
                    match stream {
                        Ok(s) => held.push(s),
                        Err(_) => return,
                    }
                }
            });
            Self::hold_lock(sock)
        }

        fn hold_lock(sock: PathBuf) -> Self {
            let lock_path = raven_core::ipc::instance_lock_path(&sock);
            let lock = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(lock_path)
                .unwrap();
            lock.lock().unwrap();
            Self { _lock: lock, sock }
        }
    }

    const FAST_PROBE: Duration = Duration::from_millis(150);
    const FAST_GRACE: Duration = Duration::from_millis(400);

    /// A SIGSTOPped / deadlocked service keeps its instance lock but never
    /// answers. It used to cost three full 10 s IPC timeouts, after which ash
    /// unlinked the live socket and started a second service that died on the
    /// lock ("exited during startup"). It is now reported as what it is, quickly,
    /// and left alone.
    #[test]
    fn wedged_service_holding_the_lock_is_reported_not_replaced() {
        let dir = short_tempdir();
        let svc = FakeService::wedged(dir.path());
        let started = std::time::Instant::now();
        let verdict = probe_existing_service(dir.path(), FAST_PROBE, FAST_GRACE, false);
        let lock = raven_core::ipc::instance_lock_path(&svc.sock);
        assert_eq!(verdict, ExistingService::Unresponsive(lock.clone()));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "bounded: {:?}",
            started.elapsed()
        );
        assert!(
            svc.sock.exists(),
            "a live service's socket must not be unlinked"
        );
        let msg = unresponsive_service_error(dir.path(), &lock);
        assert!(msg.starts_with(SERVICE_UNRESPONSIVE_PREFIX), "{msg}");
        assert!(msg.contains("is running"), "{msg}");
        assert!(msg.contains("not answering IPC"), "{msg}");
        assert!(msg.contains("Not starting a second one"), "{msg}");
        // Stops only this profile's service, never every raven-node on the machine:
        // the pattern ends at the argument, so a profile whose directory merely
        // starts with this one's (`/a/b` vs `/a/b2`) is not matched.
        assert!(
            msg.contains(&format!(
                "pkill -f 'raven-node service --data-dir {}( |$)'",
                ere_escape(&dir.path().display().to_string())
            )),
            "{msg}"
        );
        assert!(!msg.contains("pkill -f 'raven-node service'"), "{msg}");
        assert!(!msg.contains("exited during startup"), "{msg}");
    }

    #[test]
    fn answering_service_is_up_even_while_it_holds_the_lock() {
        let dir = short_tempdir();
        let sock = raven_core::default_socket_path(dir.path());
        spawn_pong_server(&sock);
        let _svc = FakeService::hold_lock(sock);
        assert_eq!(
            probe_existing_service(dir.path(), FAST_PROBE, FAST_GRACE, false),
            ExistingService::Up
        );
    }

    #[test]
    fn no_service_and_a_stale_lock_file_are_absent() {
        let dir = short_tempdir();
        assert_eq!(
            probe_existing_service(dir.path(), FAST_PROBE, FAST_GRACE, false),
            ExistingService::Absent
        );
        // A lock file nobody holds (the daemon exited; the kernel dropped its
        // flock) is not a service.
        let sock = raven_core::default_socket_path(dir.path());
        std::fs::write(raven_core::ipc::instance_lock_path(&sock), b"").unwrap();
        assert_eq!(
            probe_existing_service(dir.path(), FAST_PROBE, FAST_GRACE, false),
            ExistingService::Absent
        );
    }

    /// A lock held by the service this very process just spawned belongs to
    /// `start_daemon`, which waits for it: not "unresponsive".
    #[test]
    fn a_lock_held_by_our_own_starting_service_is_not_reported() {
        let dir = short_tempdir();
        let sock = raven_core::default_socket_path(dir.path());
        let _svc = FakeService::hold_lock(sock);
        assert_eq!(
            probe_existing_service(dir.path(), FAST_PROBE, FAST_GRACE, true),
            ExistingService::Absent
        );
    }

    #[test]
    fn unspawnable_binary_is_reported_by_name() {
        let dir = short_tempdir();
        let err = start_daemon(
            dir.path(),
            Command::new("/nonexistent/raven-node"),
            Duration::from_secs(5),
            &empty_slot(),
        )
        .unwrap_err();
        assert!(
            err.contains("could not start /nonexistent/raven-node"),
            "{err}"
        );
    }

    #[test]
    fn service_is_ready_as_soon_as_ipc_answers() {
        let dir = short_tempdir();
        spawn_pong_server(&raven_core::default_socket_path(dir.path()));
        let slot = empty_slot();
        start_daemon(dir.path(), sleeper(), Duration::from_secs(30), &slot).unwrap();
        kill_started(&slot);
    }

    #[test]
    fn slow_start_times_out_without_killing_and_is_reused_not_respawned() {
        let dir = short_tempdir();
        let slot = empty_slot();
        let err =
            start_daemon(dir.path(), sleeper(), Duration::from_millis(300), &slot).unwrap_err();
        assert!(err.contains("did not answer IPC"), "{err}");
        assert!(err.contains("still running"), "{err}");
        let first_pid = slot.lock().unwrap().as_ref().map(|(c, _)| c.id()).unwrap();

        // A second attempt waits for the same child; spawning the (broken)
        // command it is handed would give "could not start" instead.
        let err = start_daemon(
            dir.path(),
            Command::new("/nonexistent/raven-node"),
            Duration::from_millis(300),
            &slot,
        )
        .unwrap_err();
        assert!(err.contains("did not answer IPC"), "{err}");
        assert_eq!(
            slot.lock().unwrap().as_ref().map(|(c, _)| c.id()),
            Some(first_pid)
        );
        kill_started(&slot);
    }

    #[test]
    fn another_daemon_answering_counts_even_if_our_child_exited() {
        // e.g. a concurrent ash started the real service; ours lost the port race.
        let dir = short_tempdir();
        spawn_pong_server(&raven_core::default_socket_path(dir.path()));
        start_daemon(
            dir.path(),
            shell("echo 'lan_direct failed to bind' >&2; exit 1"),
            Duration::from_secs(30),
            &empty_slot(),
        )
        .unwrap();
    }

    #[test]
    fn child_is_detached_into_its_own_process_group() {
        let pgid = |pid: u32| -> Option<String> {
            let out = Command::new("ps")
                .args(["-o", "pgid=", "-p", &pid.to_string()])
                .output()
                .ok()?;
            out.status
                .success()
                .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
        };
        let dir = short_tempdir();
        spawn_pong_server(&raven_core::default_socket_path(dir.path()));
        let slot = empty_slot();
        start_daemon(dir.path(), sleeper(), Duration::from_secs(30), &slot).unwrap();
        let child_pid = slot.lock().unwrap().as_ref().map(|(c, _)| c.id()).unwrap();
        if let (Some(ours), Some(theirs)) = (pgid(std::process::id()), pgid(child_pid)) {
            // A tty Ctrl-C / hangup goes to the foreground process group only.
            assert_ne!(ours, theirs, "daemon must not share ash's process group");
            assert_eq!(theirs, child_pid.to_string(), "child leads its own group");
        }
        kill_started(&slot);
    }

    #[test]
    fn log_is_private_appended_and_capped() {
        let dir = tempfile::tempdir().unwrap();
        let log = daemon_log_path(dir.path());

        // A pre-existing world-readable log is tightened, and appended to.
        std::fs::write(&log, b"older run\n").unwrap();
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (_file, start) = open_daemon_log(&log).unwrap();
        assert_eq!(start, "older run\n".len() as u64);
        assert_eq!(
            std::fs::metadata(&log).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let raw = std::fs::read_to_string(&log).unwrap();
        assert!(raw.starts_with("older run\n") && raw.contains(DAEMON_LOG_MARKER));

        // Created fresh: 0600 from the start.
        let fresh = dir.path().join("fresh.log");
        open_daemon_log(&fresh).unwrap();
        assert_eq!(
            std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // Past the cap the old content is dropped instead of growing forever.
        std::fs::File::options()
            .write(true)
            .open(&log)
            .unwrap()
            .set_len(DAEMON_LOG_MAX_BYTES + 1)
            .unwrap();
        let (_file, start) = open_daemon_log(&log).unwrap();
        assert_eq!(start, 0);
    }

    #[test]
    fn log_tail_covers_only_this_attempt_and_is_sanitized() {
        let dir = tempfile::tempdir().unwrap();
        let log = daemon_log_path(dir.path());
        std::fs::write(&log, b"previous attempt: stale error\n").unwrap();
        let (mut file, start) = open_daemon_log(&log).unwrap();
        writeln!(file, "fresh line\r\n\x1b[31mred\x1b[0m").unwrap();
        let tail = daemon_log_tail(&log, start);
        assert!(tail.contains("fresh line"), "{tail:?}");
        assert!(tail.contains("red"), "{tail:?}");
        assert!(!tail.contains("stale error"), "{tail:?}");
        assert!(!tail.contains(DAEMON_LOG_MARKER), "{tail:?}");
        assert!(!tail.contains('\u{1b}'), "{tail:?}");
        // Bounded: a huge burst keeps only the last DAEMON_LOG_TAIL_BYTES.
        let big = "x".repeat(10_000);
        writeln!(file, "{big}\nlast words").unwrap();
        let tail = daemon_log_tail(&log, start);
        assert!(tail.len() as u64 <= DAEMON_LOG_TAIL_BYTES, "{}", tail.len());
        assert!(tail.ends_with("last words"), "{tail:?}");
    }

    #[test]
    fn failure_text_hints_only_for_a_port_conflict() {
        use raven_core::disk_space::OnceFreed;
        let log = Path::new("/p/raven-node-service.log");
        let daemon_failure =
            |what, log, tail| daemon_failure(what, log, tail, OnceFreed::NotRunning);
        let busy = daemon_failure("exited", log, "Error: Address already in use");
        assert!(
            busy.contains("RAVEN_SERVICE_LAN_LISTEN=127.0.0.1:0"),
            "{busy}"
        );
        let other = daemon_failure("exited", log, "identity locked");
        assert!(!other.contains("RAVEN_SERVICE_LAN_LISTEN"), "{other}");
        assert!(
            other.contains("identity locked") && other.contains("full log: /p/"),
            "{other}"
        );
        let silent = daemon_failure("exited", log, "");
        assert!(!silent.contains("service output"), "{silent}");
    }

    #[test]
    fn failure_text_names_a_full_disk() {
        use raven_core::disk_space::OnceFreed;
        let dir = tempfile::tempdir().unwrap();
        let log = daemon_log_path(dir.path());
        let tail = "lan_direct failed: outbox: database or disk is full";
        let full = daemon_failure("exited", &log, tail, OnceFreed::NotRunning);
        assert!(full.contains("\n  hint: disk is full"), "{full}");
        assert!(full.contains("512 MB"), "{full}");
        // The service exited: freeing space restarts nothing.
        assert!(
            full.contains(
                "free some space, then run the command again (raven-node is not running)"
            ),
            "{full}"
        );
        assert!(!full.contains("carries on by itself"), "{full}");
        // Still running but not answering: retry, nothing claims it carries on.
        let slow = daemon_failure("did not answer", &log, tail, OnceFreed::RunAgain);
        assert!(
            slow.contains("free some space, then run the command again\n"),
            "{slow}"
        );
        assert!(!slow.contains("carries on by itself"), "{slow}");
        // The disk under this test is not full: a Keychain-only failure gets no
        // disk hint.
        let keychain = daemon_failure("exited", &log, MARKER, OnceFreed::NotRunning);
        assert!(!keychain.contains("disk is full"), "{keychain}");
    }

    /// What the daemon writes while a macOS dialog holds its Keychain call.
    const MARKER: &str = "raven-node: BLOCKED_ON_KEYCHAIN what=identity waited=3s \
                          hint=\"approve the macOS dialog for this program (Always Allow)\"";

    fn blocked_on_keychain() -> Command {
        shell(&format!("echo '{MARKER}' >&2; sleep 30"))
    }

    fn started_pid(slot: &StartedDaemon) -> u32 {
        slot.lock().unwrap().as_ref().map(|(c, _)| c.id()).unwrap()
    }

    /// The service is not slow, it is waiting for a person to answer a dialog: it
    /// gets a longer (bounded) window instead of the 20 s timeout that made ash
    /// give up on a healthy service. Here it "answers" after about 0.9 s, far past
    /// the 250 ms window and inside the extended one.
    #[test]
    fn a_service_waiting_for_a_keychain_answer_gets_more_time_not_a_timeout() {
        let dir = short_tempdir();
        let sock = raven_core::default_socket_path(dir.path());
        let answer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(900));
            spawn_pong_server(&sock);
        });
        let slot = empty_slot();
        let started = std::time::Instant::now();
        start_daemon(
            dir.path(),
            blocked_on_keychain(),
            Duration::from_millis(250),
            &slot,
        )
        .expect("a service blocked on the Keychain is waited for");
        assert!(
            started.elapsed() >= Duration::from_millis(500),
            "{:?}",
            started.elapsed()
        );
        answer.join().unwrap();
        kill_started(&slot);
    }

    /// The extension is bounded, and the timeout then says what to do about it.
    #[test]
    fn the_keychain_wait_is_bounded_and_the_timeout_error_names_it() {
        let dir = short_tempdir();
        let slot = empty_slot();
        let started = std::time::Instant::now();
        let err = start_daemon(
            dir.path(),
            blocked_on_keychain(),
            Duration::from_millis(250),
            &slot,
        )
        .unwrap_err();
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(1500) && waited < Duration::from_secs(20),
            "250 ms x {DAEMON_KEYCHAIN_WAIT_FACTOR}, not forever: {waited:?}"
        );
        assert!(err.contains("did not answer IPC within 2s"), "{err}");
        assert!(
            err.contains("waiting for macOS Keychain access to your Raven identity"),
            "{err}"
        );
        assert!(err.contains(KEYCHAIN_APPROVE_HINT), "{err}");
        assert!(err.contains("still running"), "{err}");
        let pid = started_pid(&slot);
        assert!(err.contains(&format!("kill {pid}")), "{err}");
        assert!(!err.contains("pkill"), "{err}");
        kill_started(&slot);
    }

    /// A marker from an earlier attempt (before this start's log offset) is not
    /// this service's: no extension, no claim.
    #[test]
    fn a_stale_keychain_marker_from_an_earlier_attempt_is_not_counted() {
        let dir = short_tempdir();
        std::fs::write(
            daemon_log_path(dir.path()),
            format!("{DAEMON_LOG_MARKER}\n{MARKER}\n"),
        )
        .unwrap();
        let slot = empty_slot();
        let started = std::time::Instant::now();
        let err =
            start_daemon(dir.path(), sleeper(), Duration::from_millis(250), &slot).unwrap_err();
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "{:?}",
            started.elapsed()
        );
        assert!(!err.contains("Keychain access to"), "{err}");
        assert!(!err.contains("its log says"), "{err}");
        kill_started(&slot);
    }

    /// The ordinary timeout names the one process to stop (never `pkill -f
    /// 'raven-node service'`, which stops every profile's service); the Keychain
    /// advice is for the platform that has a Keychain.
    #[test]
    fn an_ordinary_timeout_names_the_process_to_stop() {
        let dir = short_tempdir();
        let slot = empty_slot();
        let err =
            start_daemon(dir.path(), sleeper(), Duration::from_millis(300), &slot).unwrap_err();
        let pid = started_pid(&slot);
        assert!(err.contains(&format!("process {pid}")), "{err}");
        assert!(err.contains(&format!("kill {pid}")), "{err}");
        assert!(!err.contains("pkill"), "{err}");
        assert_eq!(
            err.contains(KEYCHAIN_APPROVE_HINT),
            cfg!(target_os = "macos"),
            "{err}"
        );
        assert!(!err.contains("its log says"), "no marker, no claim: {err}");
        kill_started(&slot);
    }

    #[test]
    fn the_start_notice_names_the_process_to_stop_and_the_log() {
        let log = Path::new("/p/raven-node-service.log");
        let text = plain(&started_notice(4242, log));
        assert!(text.contains("raven-node (process 4242)"), "{text}");
        assert!(text.contains("keeps running after ash exits"), "{text}");
        assert!(
            text.contains("stop only this one with: kill 4242"),
            "{text}"
        );
        assert!(text.contains("log: /p/raven-node-service.log"), "{text}");
        assert!(!text.contains("pkill"), "{text}");
        assert_eq!(
            stop_advice(7),
            if cfg!(windows) {
                "taskkill /F /PID 7"
            } else {
                "kill 7"
            }
        );
    }

    /// An unresponsive service whose own log says it waits for the Keychain is
    /// named as such, so the user answers the dialog instead of killing it.
    #[test]
    fn an_unresponsive_service_blocked_on_the_keychain_is_named() {
        let dir = short_tempdir();
        std::fs::write(
            daemon_log_path(dir.path()),
            format!("{DAEMON_LOG_MARKER}\n{MARKER}\n"),
        )
        .unwrap();
        let msg = unresponsive_service_error(dir.path(), Path::new("/x.lock"));
        assert!(
            msg.contains("waiting for macOS Keychain access to your Raven identity"),
            "{msg}"
        );
        assert!(msg.starts_with(SERVICE_UNRESPONSIVE_PREFIX), "{msg}");
        let quiet = short_tempdir();
        let msg = unresponsive_service_error(quiet.path(), Path::new("/x.lock"));
        assert!(!msg.contains("Keychain access to"), "{msg}");
    }

    /// A marker in a log nobody has written for a long time is history (the dialog
    /// was answered long ago), not the reason the service is unresponsive now.
    #[test]
    fn a_stale_keychain_marker_is_not_blamed_for_a_wedged_service() {
        let dir = short_tempdir();
        let log = daemon_log_path(dir.path());
        std::fs::write(&log, format!("{DAEMON_LOG_MARKER}\n{MARKER}\n")).unwrap();
        let long_ago = std::time::SystemTime::now() - Duration::from_secs(24 * 3600);
        std::fs::File::options()
            .write(true)
            .open(&log)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
        let msg = unresponsive_service_error(dir.path(), Path::new("/x.lock"));
        assert!(!msg.contains("Keychain access to"), "{msg}");
        assert!(msg.starts_with(SERVICE_UNRESPONSIVE_PREFIX), "{msg}");
    }

    #[test]
    fn the_stop_pattern_escapes_regex_characters_in_the_path() {
        assert_eq!(ere_escape("/a/b.c+(d)"), "/a/b\\.c\\+\\(d\\)");
        assert_eq!(ere_escape("/plain/dir-1"), "/plain/dir-1");
    }

    #[test]
    fn keychain_marker_is_read_back_in_plain_words() {
        let line = |what: &str| {
            format!("raven-node: BLOCKED_ON_KEYCHAIN what={what} waited=3s hint=\"x\"")
        };
        assert_eq!(
            keychain_block_in(&line("identity")),
            Some("your Raven identity")
        );
        assert_eq!(
            keychain_block_in(&line("chat_history")),
            Some("your chat history")
        );
        assert_eq!(
            keychain_block_in(&line("session")),
            Some("a conversation key")
        );
        assert_eq!(
            keychain_block_in(&line("prekey")),
            Some("key-exchange data")
        );
        assert_eq!(
            keychain_block_in(&line("something_new")),
            Some("a saved secret")
        );
        // The newest complete marker wins; text that merely mentions the tag does not count.
        let log = format!(
            "{}\n{}\nunrelated line\n",
            line("identity"),
            line("session")
        );
        assert_eq!(keychain_block_in(&log), Some("a conversation key"));
        assert_eq!(
            keychain_block_in("note: BLOCKED_ON_KEYCHAIN is a marker"),
            None
        );
        assert_eq!(keychain_block_in(""), None);
    }

    /// After IPC answers, the LAN listener may still be coming up: wait for
    /// `lan_direct`, but only so long, and say "unknown" when nothing answers.
    #[test]
    fn the_listener_poll_waits_for_lan_direct_and_reports_each_outcome() {
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;
        let listing =
            |caps: &[&str]| -> Vec<String> { caps.iter().map(|c| c.to_string()).collect() };

        let dir = short_tempdir();
        spawn_status_server(&raven_core::default_socket_path(dir.path()), {
            let up = listing(&["ipc", "lan_direct"]);
            move || up.clone()
        });
        assert_eq!(
            wait_for_lan_listener(dir.path(), Duration::from_secs(5)),
            Some(true)
        );

        // The listener comes up shortly after IPC does.
        let dir = short_tempdir();
        let up = Arc::new(AtomicBool::new(false));
        spawn_status_server(&raven_core::default_socket_path(dir.path()), {
            let up = up.clone();
            move || {
                if up.load(Ordering::SeqCst) {
                    vec!["ipc".into(), "lan_direct".into()]
                } else {
                    vec!["ipc".into()]
                }
            }
        });
        let flip = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            up.store(true, Ordering::SeqCst);
        });
        assert_eq!(
            wait_for_lan_listener(dir.path(), Duration::from_secs(10)),
            Some(true)
        );
        flip.join().unwrap();

        // Never: IPC only. Reported after the wait, not before and not forever.
        let dir = short_tempdir();
        spawn_status_server(&raven_core::default_socket_path(dir.path()), || {
            vec!["ipc".into()]
        });
        let started = std::time::Instant::now();
        assert_eq!(
            wait_for_lan_listener(dir.path(), Duration::from_millis(400)),
            Some(false)
        );
        assert!(
            started.elapsed() >= Duration::from_millis(400),
            "{:?}",
            started.elapsed()
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );

        // Nothing answers: unknown, at once.
        let dir = short_tempdir();
        let started = std::time::Instant::now();
        assert_eq!(
            wait_for_lan_listener(dir.path(), Duration::from_secs(3)),
            None
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    /// A started service that never lists `lan_direct` is reported (the warning
    /// flag is the once-per-process guard); one that does is not.
    #[test]
    fn a_started_service_without_a_listener_is_reported_once() {
        use std::sync::atomic::AtomicBool;
        let run = |caps: &'static [&'static str]| -> bool {
            let dir = short_tempdir();
            spawn_status_server(&raven_core::default_socket_path(dir.path()), move || {
                caps.iter().map(|c| c.to_string()).collect()
            });
            let slot = empty_slot();
            let warned = AtomicBool::new(false);
            start_and_report(
                dir.path(),
                sleeper(),
                "0.0.0.0:7420",
                Duration::from_secs(30),
                Duration::from_millis(300),
                &slot,
                &warned,
                false,
            )
            .unwrap();
            kill_started(&slot);
            warned.load(Ordering::SeqCst)
        };
        assert!(run(&["ipc", "bridge"]), "no lan_direct: warned");
        assert!(
            !run(&["ipc", "lan_direct"]),
            "listener up: nothing to warn about"
        );
    }

    /// Phase 3 P3.6: a service started while `raven lan off` holds binds no
    /// LAN listener; nothing waits for one (or warns of a busy port).
    #[test]
    fn a_service_started_while_lan_is_off_is_not_waited_for() {
        use std::sync::atomic::AtomicBool;
        let dir = short_tempdir();
        spawn_status_server(&raven_core::default_socket_path(dir.path()), || {
            vec!["ipc".to_string()]
        });
        let slot = empty_slot();
        let warned = AtomicBool::new(false);
        let started = std::time::Instant::now();
        start_and_report(
            dir.path(),
            sleeper(),
            "0.0.0.0:7420",
            Duration::from_secs(30),
            Duration::from_secs(30),
            &slot,
            &warned,
            true,
        )
        .unwrap();
        kill_started(&slot);
        assert!(!warned.load(Ordering::SeqCst), "no busy-port warning");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{:?}",
            started.elapsed()
        );
        assert!(
            LAN_OFF_START_NOTE.contains("LAN is off")
                && LAN_OFF_START_NOTE.contains("raven lan on")
        );
    }
}

#[cfg(test)]
mod chat_queue_tests {
    use super::*;

    fn batch(ids: &[u8], cursor_ms: u64) -> PendingInboxBatch {
        PendingInboxBatch {
            lines: ids
                .iter()
                .map(|&b| InboxLine {
                    message_id: [b; 16],
                    text: format!("line {b}"),
                })
                .collect(),
            cursor_after: InboxCursor::received(cursor_ms, ids.last().map(|&b| [b; 16])),
        }
    }

    /// A message that arrived while the chat was closed is in the history dump
    /// *and* after the saved inbox cursor: it must be shown once, not twice, while
    /// a row the dump did not print is still shown.
    #[test]
    fn rows_the_history_dump_printed_are_not_shown_again() {
        let mut shown: std::collections::HashSet<[u8; 16]> = [[2u8; 16]].into_iter().collect();
        let b = batch(&[1, 2, 3], 10);
        let fresh: Vec<&str> = unseen_lines(&b, &mut shown)
            .into_iter()
            .map(|l| l.text.as_str())
            .collect();
        assert_eq!(fresh, vec!["line 1", "line 3"]);
        // The same batch again (a re-peek after a crash between peek and cursor
        // save) shows nothing new.
        assert!(unseen_lines(&b, &mut shown).is_empty());
        // A row that merely exists in the history but was never printed is new.
        let later = batch(&[4], 11);
        assert_eq!(unseen_lines(&later, &mut shown).len(), 1);
    }

    /// Receiver dedup (P5.5): a copy of a message taken before shows the
    /// note instead of its body; any other line is exactly today's.
    #[test]
    fn chat_line_of_a_copy_seen_before_says_received_again() {
        let mid = [0x5Au8; 16];
        let short = hex::encode(&mid[..4]);
        assert_eq!(
            chat_inbox_line_text(&mid, "hello\nthere", false),
            format!(
                "  ← {C_DIM}{short}{C_RESET} {}",
                sanitize_terminal_line("hello\nthere")
            )
        );
        let again = chat_inbox_line_text(&mid, "hello", true);
        assert!(again.contains(RECEIVED_AGAIN_NOTE), "{again}");
        assert!(again.contains(&short), "{again}");
        assert!(!again.contains("hello"), "{again}");
    }

    /// Review 5a-4: the chat writes a received message to the history once.
    /// A later copy (the contact re-sealed it under a new session, its ACK
    /// lost) is not written again, also once the first copy's history row is
    /// gone (the chat deleted, or the 2,000-entry cap): the terminal app and
    /// `raven messages` read the history only and would show it as new.
    #[test]
    fn the_chat_writes_a_later_copy_to_no_history() {
        raven_core::horizon::set_lab_horizon_for_this_thread(Some(true));
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let (peer, mid) = ([0x0b; 32], [0x5a; 16]);
        let mut store = raven_core::IndexedSessionStore::open(dd).unwrap();
        // The accept path noted copy 1 at its receive stamp.
        let (first_at, again_at) = (1_000_000, 1_000_000 + 25 * 3_600_000);
        store
            .note_inbound_seen(&peer, &mid, first_at, first_at + 8 * 86_400_000)
            .unwrap();
        let row = |received_at_ms: u64, session: u8| raven_core::EndpointInboxRow {
            session_id: [session; 32],
            object_digest: [session; 32],
            message_id: mid,
            sender_device: peer,
            created_at_ms: first_at,
            received_at_ms,
            position: raven_core::InboxPosition::received(received_at_ms, Some(mid)),
            plaintext: b"taken once".to_vec(),
        };
        let history = || -> Vec<String> {
            raven_core::ChatHistory::load(dd)
                .unwrap()
                .entries
                .into_iter()
                .filter(|e| e.direction == "in")
                .map(|e| e.body)
                .collect()
        };
        assert!(!record_received_chat(dd, &store, &peer, &row(first_at, 1)).unwrap());
        assert_eq!(history(), vec!["taken once"]);
        raven_core::ChatHistory::delete_for_contact(dd, &hex::encode(peer)).unwrap();
        assert!(record_received_chat(dd, &store, &peer, &row(again_at, 2)).unwrap());
        assert!(history().is_empty(), "the later copy is not written");
        // Without receiver dedup (nothing re-seals) every row is written.
        raven_core::horizon::set_lab_horizon_for_this_thread(Some(false));
        raven_core::session_reset::set_lab_session_reset_for_this_thread(Some(0));
        assert!(!record_received_chat(dd, &store, &peer, &row(again_at, 2)).unwrap());
        assert_eq!(history(), vec!["taken once"]);
        raven_core::session_reset::set_lab_session_reset_for_this_thread(None);
        raven_core::horizon::set_lab_horizon_for_this_thread(None);
    }

    /// One burst of messages gives one "new message" notice; draining the queue
    /// (or discarding it) re-arms it.
    #[test]
    fn a_burst_gives_one_notice_until_the_queue_is_drained() {
        let dir = tempfile::tempdir().unwrap();
        let pending = std::sync::Mutex::new(ChatPendingQueue::default());
        assert!(
            push_chat_batch(&pending, batch(&[1], 1)),
            "first batch notifies"
        );
        assert!(
            !push_chat_batch(&pending, batch(&[2], 2)),
            "same burst: silent"
        );
        assert!(!push_chat_batch(&pending, batch(&[3], 3)));

        let mut cursor = InboxCursor::default();
        let mut shown = std::collections::HashSet::new();
        drain_chat_pending(
            dir.path(),
            &"ab".repeat(32),
            &pending,
            &mut cursor,
            &mut shown,
        );
        assert_eq!(shown.len(), 3, "all rows were printed once");
        assert_eq!(cursor.seq, 3, "cursor advanced past the burst");
        assert!(
            push_chat_batch(&pending, batch(&[4], 4)),
            "drained: notifies again"
        );

        discard_chat_pending(&pending);
        assert!(
            push_chat_batch(&pending, batch(&[5], 5)),
            "discarded: notifies again"
        );
    }

    /// A full display queue defers one batch but still counts as one burst.
    #[test]
    fn a_full_queue_defers_a_batch_without_a_second_notice() {
        let pending = std::sync::Mutex::new(ChatPendingQueue::default());
        for i in 0..CHAT_PENDING_MAX {
            push_chat_batch(&pending, batch(&[1], i as u64 + 1));
        }
        assert!(chat_queue_blocks_poll(&pending));
        assert!(!push_chat_batch(&pending, batch(&[9], 999)));
        assert!(pending.lock().unwrap().deferred.is_some());
    }
}

#[cfg(test)]
mod send_outcome_tests {
    use super::*;

    fn bob() -> SendCtx {
        SendCtx {
            name: "Bob".into(),
            selector: "--petname Bob".into(),
            pub_hex: "ab".repeat(32),
            dial: "192.168.0.16:7420".into(),
            data_dir: Some(PathBuf::from("/data")),
            chat: false,
            show_carrier: false,
            choice: None,
            custody_ok: false,
            unrecorded: Vec::new(),
        }
    }

    const DAY_MS: u64 = 24 * 60 * 60 * 1000;

    /// Staged now, retried only by the next send (a service without outbox).
    fn next_send() -> RetryNote {
        RetryNote {
            expires_at_ms: now_ms() + DAY_MS,
            copy_expires_at_ms: 0,
            background: false,
            custodians: Vec::new(),
            carry_first: None,
        }
    }

    /// Staged now and taken by raven-node's background outbox.
    /// Until dropped, no address is on this computer's networks (a test's
    /// sample LAN addresses must not depend on the network it runs on).
    fn off_our_network() -> impl Drop {
        struct Away;
        impl Drop for Away {
            fn drop(&mut self) {
                ON_OUR_NETWORK.with(|c| c.set(None));
            }
        }
        ON_OUR_NETWORK.with(|c| c.set(Some(false)));
        Away
    }

    fn background() -> RetryNote {
        RetryNote {
            expires_at_ms: now_ms() + DAY_MS,
            copy_expires_at_ms: 0,
            background: true,
            custodians: Vec::new(),
            carry_first: None,
        }
    }

    /// (a text the send path can see, how it must be read, words its sentence
    /// must carry): the table behind every "NOT SENT: ..." line. `history`
    /// is bob()'s chat history file, as the OS writes the path.
    fn sentence_table(history: &str) -> Vec<(&'static str, Cause, Vec<&str>)> {
        vec![
            (
                "ipc LAN_DIAL: lan connect: cannot connect to 192.168.0.16:7420 (192.168.0.16:7420: Connection refused (os error 61))",
                Cause::NotListening,
                vec![
                    "Bob's computer is there, but Raven isn't receiving right now (it may be \
                     locked or closed)",
                    "Ask Bob to open Raven",
                ],
            ),
            (
                "ipc LAN_DIAL: lan connect: cannot connect to 192.168.0.16:7420 (192.168.0.16:7420: no answer within 5.0s)",
                Cause::NotReachable,
                vec!["Bob did not answer at 192.168.0.16:7420", "same network", "new IP address"],
            ),
            (
                "ipc LAN_DIAL: lan dial to 192.168.0.16:7420 timed out after 45s while connecting and in the Noise handshake",
                Cause::NotReachable,
                vec!["Bob did not answer"],
            ),
            (
                "ipc LAN_DIAL: lan read timeout",
                Cause::ClosedEarly,
                vec!["something answered at 192.168.0.16:7420 but stopped talking or hung up", "may not be RAVEN"],
            ),
            ("ipc LAN_DIAL: early eof", Cause::ClosedEarly, vec!["hung up"]),
            (
                "ipc LAN_DIAL: peer closed the connection during the handshake (3 attempts); the peer may be at its connection limit or may not be a RAVEN node",
                Cause::ClosedEarly,
                vec!["hung up"],
            ),
            (
                "peer did not return an RLB1 bundle",
                Cause::ClosedEarly,
                vec!["may not be RAVEN"],
            ),
            (
                "ipc LAN_DIAL: identity bind does not match expected pub",
                Cause::WrongIdentity,
                vec![
                    "it is not Bob",
                    "its key is not the one you saved",
                    "compare the fingerprint",
                    "ash contact remove --petname Bob",
                ],
            ),
            (
                "ipc LAN_DIAL: LAN_DIAL_PEER_CLOSED: the peer closed the connection without replying; the frames were sent, delivery is unconfirmed and a retry is safe",
                Cause::PeerRefused,
                vec!["accepted the connection but refused it without saying why", "ash whoami"],
            ),
            (
                "WAITING_FOR_PAIR_RESPONSE: no PairResponse on LanDial (1 frames: rlb1)",
                Cause::PeerRefused,
                vec!["ash whoami"],
            ),
            (
                "ipc LAN_DIAL: lan_dial parse: invalid socket address syntax",
                Cause::BadAddress,
                vec!["the saved address \"192.168.0.16:7420\" is not a valid IP:PORT", "192.168.1.20:7420"],
            ),
            (
                "valid lan_dial host:port required — refusing LocalListenQueue / 127.0.0.1:0 fallback",
                Cause::NoAddress,
                vec!["Bob has no network address saved yet", "ash contact set-dial --petname Bob"],
            ),
            (
                "the local raven-node service stopped during the request (the connection closed before it answered)",
                Cause::ServiceDown,
                vec!["RAVEN's background service (raven-node) on this computer is not answering", "ash doctor"],
            ),
            (
                "raven-node is not running; start it with `ash listen`, or send a message (that starts it too) (nothing is listening at /x/raven-node.sock: No such file or directory (os error 2))",
                Cause::ServiceDown,
                vec!["not answering"],
            ),
            (
                "local raven-node service is not running and could not be started: raven-node service exited during startup (exit status: 3)\n  full log: /data/raven-node-service.log",
                Cause::ServiceStart,
                vec!["could not be started on this computer", "technical details below say why"],
            ),
            (
                "chat history is corrupt",
                Cause::HistoryUnreadable,
                vec![history, "Your keys and contacts are not affected", "the history starts empty"],
            ),
            (
                "chat history authentication failed (wrong key or tampered file)",
                Cause::HistoryUnreadable,
                vec!["cannot be opened"],
            ),
            (
                "protected chat-history backend unavailable: keychain read failed: User interaction is not allowed.",
                Cause::KeychainDenied,
                vec!["could not open its saved chat key", "approve the Keychain window"],
            ),
            (
                "chat history I/O failed: history lock: still held by another raven process after 10s (database is locked); if the raven-node service is waiting on an OS keystore prompt, answer it, or see raven-node-service.log in the data dir",
                Cause::HistoryLocked,
                vec!["another RAVEN program on this computer is holding your chat history", "raven-node-service.log"],
            ),
            (
                "message too large for lan_dial (max 49152 bytes)",
                Cause::TooLarge,
                vec!["49152 bytes", "24576 Persian", "49152 English", "split"],
            ),
            (
                "endpoint text payload violates the bounded application policy",
                Cause::BadCharacters,
                vec!["control characters", "Backspace"],
            ),
            (
                "an earlier outbound object must be retried before reserving another key",
                Cause::SendInProgress,
                vec!["another send to Bob is still running"],
            ),
            (
                "peer is on the local block list",
                Cause::Blocked,
                vec!["Bob is blocked on this computer", "ash contact unblock --pub-hex abababab"],
            ),
            ("message is empty", Cause::EmptyMessage, vec!["empty", "Type some text"]),
        ]
    }

    /// (a text the send path can see, how it must be read, words its sentence
    /// must carry): the table behind every "NOT SENT: ..." line.
    #[test]
    fn raw_errors_become_sentences_with_a_next_step_and_keep_the_raw_text() {
        // bob()'s data dir, as the OS writes the path (`\` on Windows).
        let history = Path::new("/data")
            .join("chat_history.json")
            .display()
            .to_string();
        for (raw, cause, words) in &sentence_table(&history) {
            assert_eq!(classify_cause(raw), *cause, "{raw}");
            let text = not_sent_for(*cause, &bob(), raw, false);
            assert!(text.starts_with("NOT SENT: "), "{text}");
            assert!(text.contains("Nothing was queued"), "{text}");
            assert!(
                text.ends_with(&format!(
                    "(technical: {})",
                    raven_core::ipc::without_addresses(raw)
                )),
                "the raw text stays at the end, without addresses: {text}"
            );
            assert!(
                !text.to_lowercase().contains("delivered"),
                "a refusal never claims delivery: {text}"
            );
            assert_eq!(
                text.lines().count(),
                raw.lines().count(),
                "one line, no newline of its own: {text}"
            );
            for word in words {
                assert!(text.contains(word), "{word:?} missing from: {text}");
            }
        }
    }

    /// M0: another key answered at the contact's address and RAVEN stopped
    /// before identifying this computer (a noise pin mismatch). Read as
    /// WrongIdentity, ahead of the refusal needles, in its own words: each
    /// text one line, no LAN command (the address may well be right), a
    /// queued message never "send again". Every text names both causes
    /// (A-noise-pin-2): another computer took the address (it waits), or the
    /// contact reinstalled RAVEN without its seed (a new key that no wait
    /// can reach: get the new invite).
    #[test]
    fn a_noise_pin_mismatch_says_something_else_answered() {
        let raw = "ipc LAN_DIAL: lan noise pin mismatch: a different key answered at this \
                   address; RAVEN stopped before identifying this computer";
        assert_eq!(classify_cause(raw), Cause::WrongIdentity);
        let wrapped = format!("lan_dial 192.168.0.16:7420: {raw}; LINK_NOT_ACCEPTED");
        assert_eq!(classify_cause(&wrapped), Cause::WrongIdentity);
        let ctx = bob();
        let what = "something else answered at Bob's address at 192.168.0.16:7420: it is not \
                    Bob's RAVEN, so RAVEN stopped before telling it who you are";
        let later = "It goes out when Bob connects to you, when you join another network, or \
                     when you save Bob's new address. If Bob reinstalled RAVEN, get their new \
                     invite, compare the fingerprint with them by phone or in person, then `ash \
                     contact remove --petname Bob` and add them again.";
        let waits = "It waits until Bob connects to you or you change networks; if Bob \
                     reinstalled RAVEN, get their new invite and add them again.";
        let reinstall = "If Bob reinstalled RAVEN, get their new invite and add them again.";
        let note = RetryNote {
            expires_at_ms: now_ms() + DAY_MS,
            copy_expires_at_ms: 0,
            background: true,
            custodians: Vec::new(),
            carry_first: None,
        };
        let queued = queued_text(&ctx, raw, "\"hi\"", &note);
        assert!(queued.contains(&format!("because {what}.")), "{queued}");
        assert!(queued.contains(waits), "{queued}");
        assert!(!queued.contains(later), "{queued}");
        // A service without a background outbox: only the next send takes it.
        let next_send = queued_text(
            &ctx,
            raw,
            "\"hi\"",
            &RetryNote {
                background: false,
                ..note.clone()
            },
        );
        assert!(!next_send.contains(waits), "{next_send}");
        assert!(next_send.contains(reinstall), "{next_send}");
        assert!(
            next_send.contains("it goes out with your next send to Bob."),
            "{next_send}"
        );
        let earlier = earlier_undelivered_text(&ctx, raw, "\"hi\"", &note);
        assert!(earlier.contains(later), "{earlier}");
        let not_sent = not_sent_text(&ctx, raw, false);
        assert!(
            not_sent.contains(&format!("NOT SENT: {what}.")),
            "{not_sent}"
        );
        assert!(not_sent.contains("Nothing was queued."), "{not_sent}");
        assert!(
            not_sent.contains(
                "Send it again once Bob has connected to you, after you join another network, \
                 or after you save Bob's new address. If Bob reinstalled RAVEN, get their new \
                 invite, compare the fingerprint with them by phone or in person, then `ash \
                 contact remove --petname Bob` and add them again."
            ),
            "{not_sent}"
        );
        assert!(
            !not_sent.contains("it goes out"),
            "nothing waits: {not_sent}"
        );
        for text in [&queued, &next_send, &earlier, &not_sent] {
            assert_eq!(text.lines().count(), 1, "{text}");
            assert!(!text.contains("--lan-dial"), "{text}");
            assert!(text.contains("Bob reinstalled RAVEN"), "{text}");
            assert!(!text.contains("Nothing to do"), "{text}");
            // The words (the technical text at the end is raven-node's).
            let words = text.split("(technical:").next().unwrap().to_lowercase();
            assert!(!words.contains(" pin"), "{text}");
        }
        // ("you do not need to send it again" is the queue's own line.)
        for text in [&queued, &next_send] {
            assert!(!text.to_lowercase().contains("send again"), "{text}");
            assert!(!text.contains("Send it again"), "{text}");
        }
        // A first message: today's WrongIdentity step, the new sentence.
        let first = not_sent_text(&ctx, raw, true);
        assert!(first.contains(what), "{first}");
        assert!(first.contains("If Bob reinstalled RAVEN"), "{first}");
        // A bind mismatch keeps today's words.
        let bind = not_sent_text(&ctx, "ipc LAN_DIAL: identity bind does not match", false);
        assert!(
            bind.contains("it is not Bob: its key is not the one you saved"),
            "{bind}"
        );
        assert!(bind.contains("If Bob reinstalled RAVEN"), "{bind}");
    }

    /// A-noise-pin-4: this computer's noise pin store exists but cannot be
    /// read, so raven-node dials nobody. Its own cause, not "the send could
    /// not be completed": it names the file in the data folder and the fix
    /// (owner or permissions, or move it aside), queued or not, and `raven
    /// outbox list` explains its code.
    #[test]
    fn an_unreadable_pin_store_names_the_file_and_the_fix() {
        let raw = "ipc LAN_DIAL: lan noise pin unavailable: lan_noise_pins.json: permission denied";
        assert_eq!(classify_cause(raw), Cause::PinStoreUnreadable);
        let wrapped = format!("lan_dial 192.168.0.16:7420: {raw}; internet_dial x: timed out");
        assert_eq!(classify_cause(&wrapped), Cause::PinStoreUnreadable);
        // Not a mismatch, and the mismatch is not this.
        assert!(!is_noise_pin_mismatch(raw));
        assert_eq!(
            classify_cause("ipc LAN_DIAL: lan noise pin mismatch: a different key answered"),
            Cause::WrongIdentity
        );
        let ctx = bob();
        let file = Path::new("/data")
            .join("lan_noise_pins.json")
            .display()
            .to_string();
        let what = format!(
            "RAVEN cannot read {file} (permission denied), the file it checks your friends' \
             computers against, so it connects to no one"
        );
        let fix = "fix that file's owner or permissions (for example after raven ran with \
                   sudo), or move it aside (raven learns your friends' keys again as you \
                   connect)";
        let not_sent = not_sent_text(&ctx, raw, false);
        assert!(
            not_sent.contains(&format!("NOT SENT: {what}.")),
            "{not_sent}"
        );
        assert!(not_sent.to_lowercase().contains(fix), "{not_sent}");
        assert!(not_sent.contains("then send again."), "{not_sent}");
        let note = RetryNote {
            expires_at_ms: now_ms() + DAY_MS,
            copy_expires_at_ms: 0,
            background: true,
            custodians: Vec::new(),
            carry_first: None,
        };
        let queued = queued_text(&ctx, raw, "\"hi\"", &note);
        assert!(queued.contains(&format!("because {what}.")), "{queued}");
        assert!(queued.to_lowercase().contains(fix), "{queued}");
        assert!(!queued.to_lowercase().contains("send again"), "{queued}");
        // No data dir known: the file is still named.
        let unnamed = not_sent_text(&SendCtx::named("Bob"), raw, false);
        assert!(
            unnamed.contains("lan_noise_pins.json (in your RAVEN data folder)"),
            "{unnamed}"
        );
        for text in [&not_sent, &queued, &unnamed] {
            assert_eq!(text.lines().count(), 1, "{text}");
            assert!(!text.contains("the send could not be completed"), "{text}");
        }
        let legend = reset_code_legend("PIN_STORE_UNREADABLE").unwrap();
        assert!(legend.contains("lan_noise_pins.json"), "{legend}");
        assert!(legend.contains("lan_noise_pins.rms"), "{legend}");
        assert!(legend.contains("ash doctor"), "{legend}");
        // A sealed profile's pin file (privacy pack PP.5) is named as such.
        let sealed = "ipc LAN_DIAL: lan noise pin unavailable: lan_noise_pins.rms: sealed data \
                      failed authentication (kind 16)";
        let file = Path::new("/data")
            .join("lan_noise_pins.rms")
            .display()
            .to_string();
        let not_sent = not_sent_text(&ctx, sealed, false);
        assert!(
            not_sent.contains(&format!(
                "RAVEN cannot read {file} (sealed data failed authentication), the file"
            )),
            "{not_sent}"
        );
    }

    /// CP.5 (F2): a saved computer name that does not resolve is its own
    /// cause, from every resolver's words (raven-node's prefix, macOS's and
    /// Linux's getaddrinfo, Windows), after the identity and refusal
    /// needles and before every dial failure.
    #[test]
    fn a_name_that_does_not_resolve_is_name_not_found() {
        let c4b = "ipc LAN_DIAL: lan connect: cannot resolve raven-cutoff-nohost-zz.local: failed \
                   to lookup address information: nodename nor servname provided, or not known";
        for raw in [
            c4b,
            "failed to lookup address information: nodename nor servname provided, or not known",
            "failed to lookup address information: Name or service not known",
            "failed to lookup address information: Temporary failure in name resolution",
            "No such host is known. (os error 11001)",
            "cannot resolve bob-mac.local: timed out after 10s",
            "cannot resolve bob-mac.local: it has no address",
            "bob-mac.local could not be resolved (resolution timed out)",
            // A joined multi-route text: the name wins over the other routes'
            // dial failures.
            "lan_dial bob-mac.local:7420: cannot resolve bob-mac.local: Name or service not \
             known; internet_dial 203.0.113.7:7422: cannot connect to 203.0.113.7:7422 (no \
             answer within 5.0s)",
            "lan_dial bob-mac.local:7420: cannot resolve bob-mac.local: Name or service not \
             known; lan_dial 192.168.0.16:7420: Connection refused (os error 61)",
        ] {
            assert_eq!(classify_cause(raw), Cause::NameNotFound, "{raw}");
        }
        // The identity and refusal needles come first.
        for (raw, cause) in [
            (
                "lan_dial a.local:7420: cannot resolve a.local: x; lan_dial 192.168.0.16:7420: \
                 identity bind does not match",
                Cause::WrongIdentity,
            ),
            (
                "lan_dial a.local:7420: cannot resolve a.local: x; LINK_NOT_ACCEPTED",
                Cause::PeerRefused,
            ),
        ] {
            assert_eq!(classify_cause(raw), cause, "{raw}");
        }

        let ctx = SendCtx {
            dial: "raven-cutoff-nohost-zz.local:7420".into(),
            ..bob()
        };
        let what = "Bob's computer name raven-cutoff-nohost-zz.local could not be found on this \
                    network (Bob may be away, or on another network)";
        let fix = "ash contact set-dial --petname Bob --lan-dial IP:PORT.";
        let later = format!(
            "When you are both on the same network it goes out by itself. If Bob's computer has \
             a new address, save it: {fix}"
        );
        let again = format!(
            "Send it again when you are both on the same network. If Bob's computer has a new \
             address, save it: {fix}"
        );
        // Queued (c4b): the cause names the name, and it goes out by itself.
        let queued = queued_text(&ctx, c4b, "\"hi\"", &background());
        assert!(queued.contains(&format!("because {what}.")), "{queued}");
        assert!(queued.contains(&later), "{queued}");
        assert!(!queued.contains("could not be completed"), "{queued}");
        // Only the next send takes it without a background outbox.
        let next = queued_text(&ctx, c4b, "\"hi\"", &next_send());
        assert!(!next.contains("by itself"), "{next}");
        assert!(
            next.contains(&format!(
                "If Bob's computer has a new address, save it: {fix}"
            )),
            "{next}"
        );
        assert!(
            next.contains("it goes out with your next send to Bob."),
            "{next}"
        );
        for text in [&queued, &next] {
            assert!(!text.to_lowercase().contains("send again"), "{text}");
            assert!(!text.contains("Send it again"), "{text}");
        }
        // Nothing waits: when to send it again, a first message or a later one.
        let not_sent = not_sent_text(&ctx, c4b, false);
        assert!(
            not_sent.starts_with(&format!("NOT SENT: {what}.")),
            "{not_sent}"
        );
        assert!(not_sent.contains(&again), "{not_sent}");
        assert!(
            !not_sent.contains("it goes out"),
            "nothing waits: {not_sent}"
        );
        // A first message: the rule it goes by and when to send it again
        // (E1), then the new address.
        let first = not_sent_text(&ctx, c4b, true);
        assert!(
            first.contains(&format!(
                "It was not kept: a first message needs you and Bob both online (RAVEN hasn't \
                 connected with Bob yet). Send it again when Bob is online. If Bob's computer \
                 has a new address, save it: {fix}"
            )),
            "{first}"
        );
        assert!(!first.contains(&again), "said once: {first}");
        // Behind an earlier message that is still queued: that one goes out.
        let earlier = earlier_undelivered_text(&ctx, c4b, "\"hi\"", &background());
        assert!(earlier.contains(&later), "{earlier}");
        for text in [&queued, &next, &not_sent, &first, &earlier] {
            assert_eq!(text.lines().count(), 1, "{text}");
        }

        // The name is the one raven-node could not resolve, else the saved
        // address's host; never a raw control character.
        let named = not_sent_text(&bob(), c4b, false);
        assert!(
            named.contains("Bob's computer name raven-cutoff-nohost-zz.local could not"),
            "{named}"
        );
        let windows = "No such host is known. (os error 11001)";
        let saved = not_sent_text(&ctx, windows, false);
        assert!(saved.contains(what), "{saved}");
        let hostile = SendCtx {
            dial: "evil\u{1b}[2J.local:7420".into(),
            ..bob()
        };
        let safe = not_sent_text(&hostile, windows, false);
        assert!(
            !safe.split("(technical:").next().unwrap().contains('\u{1b}'),
            "{safe:?}"
        );
        let nameless = not_sent_text(&SendCtx::named("Bob"), windows, false);
        assert!(
            nameless
                .starts_with("NOT SENT: Bob's computer name could not be found on this network"),
            "{nameless}"
        );

        // No route to the internet: the LAN route's name failure wins over
        // the p2p reason, and nothing claims it goes out by itself.
        let no_route = format!(
            "lan_dial bob-mac.local:7420: ipc LAN_DIAL: lan connect: cannot resolve \
             bob-mac.local: Name or service not known; p2p_dial /p2p/12D3KooWx: {P2P_RAW}; \
             reach: why=no_route me=unknown"
        );
        let lan_first = not_sent_text(&nobody_known(), &no_route, false);
        assert!(
            lan_first.starts_with(
                "NOT SENT: Bob's computer name bob-mac.local could not be found on this network \
                 (Bob may be away, or on another network) (this computer has no route to the \
                 internet)."
            ),
            "{lan_first}"
        );
        assert!(
            lan_first.contains("Send it again when you are both"),
            "{lan_first}"
        );
        assert_no_internet_side_fix(lan_first.split("(technical:").next().unwrap());
    }

    /// An Internet or p2p dial that nobody answered gets advice for that
    /// carrier, never a LAN command or "check that you are on the same network".
    #[test]
    fn unreachable_advice_follows_the_carrier_that_failed() {
        let ctx = SendCtx::named("Bob");
        let internet = not_sent_text(
            &ctx,
            "ipc INTERNET_DIAL: internet connect: cannot connect to 203.0.113.18:7422 \
             (203.0.113.18:7422: no answer within 5.0s)",
            false,
        );
        assert!(
            internet.contains("reachable from the Internet"),
            "{internet}"
        );
        assert!(internet.contains("--internet HOST:PORT"), "{internet}");
        assert!(!internet.contains("same network"), "{internet}");
        assert!(!internet.contains("--lan-dial"), "{internet}");
        let p2p = not_sent_text(
            &ctx,
            "ipc P2P_DIAL: P2P_UNREACHABLE: the contact is unreachable on every p2p address it \
             has (direct and relay)",
            false,
        );
        assert!(p2p.contains("through a relay"), "{p2p}");
        assert!(p2p.contains("--p2p PEER_ID --via MULTIADDR"), "{p2p}");
        assert!(!p2p.contains("--lan-dial"), "{p2p}");
        let lan = not_sent_text(
            &ctx,
            "ipc LAN_DIAL: lan connect: cannot connect to 192.168.0.16:7420 (no answer within \
             5.0s)",
            false,
        );
        assert!(
            lan.contains("same network") && lan.contains("--lan-dial IP:PORT"),
            "{lan}"
        );
    }

    /// A service that is still running but slow to answer (often a macOS Keychain
    /// window nobody has answered) is not "could not be started": say what it is
    /// waiting for and what to do, and keep "could not be started" for real
    /// start failures.
    #[test]
    fn a_service_that_is_still_starting_is_not_reported_as_unable_to_start() {
        let slow = "local raven-node service is not running and could not be started: raven-node service did not answer IPC within 160s (it is still running as process 4321; retry shortly, or stop only this one with: kill 4321)\n  its log says it is waiting for macOS Keychain access to your Raven identity";
        assert_eq!(classify_cause(slow), Cause::ServiceSlow);
        let text = not_sent_for(Cause::ServiceSlow, &bob(), slow, false);
        assert!(
            text.contains("was started but is still waiting for macOS Keychain access"),
            "{text}"
        );
        assert!(text.contains("Always Allow"), "{text}");
        assert!(
            text.contains(&format!("Or stop it with: {}.", stop_advice(4321))),
            "{text}"
        );
        assert!(
            !text.contains("could not be started on this computer"),
            "{text}"
        );
        assert!(text.starts_with("NOT SENT: "), "{text}");

        let quiet = "local raven-node service is not running and could not be started: raven-node service did not answer IPC within 20s (it is still running as process 77; retry shortly, or stop only this one with: kill 77)";
        assert_eq!(classify_cause(quiet), Cause::ServiceSlow);
        let text = not_sent_for(Cause::ServiceSlow, &bob(), quiet, false);
        assert!(text.contains("has not answered yet"), "{text}");
        assert!(text.contains("ash doctor"), "{text}");
        assert!(
            !text.contains("Keychain"),
            "no Keychain claim without evidence: {text}"
        );

        let failed = "local raven-node service is not running and could not be started: raven-node service exited during startup (exit status: 3)";
        assert_eq!(classify_cause(failed), Cause::ServiceStart);
    }

    /// After the first contact a refusal without a reason can also mean the peer
    /// could not save the message (it may already be in their inbox): never tell the
    /// sender to just send it again.
    #[test]
    fn a_later_refusal_may_mean_the_peer_could_not_save_it_and_never_invites_a_duplicate() {
        let raw =
            "ipc LAN_DIAL: LAN_DIAL_PEER_CLOSED: the peer closed the connection without replying";
        let text = not_sent_for(Cause::PeerRefused, &bob(), raw, false);
        assert!(text.contains("could not save the message"), "{text}");
        assert!(text.contains("may already be in their inbox"), "{text}");
        assert!(text.contains("do not send it again"), "{text}");
        assert!(!text.contains("then send again"), "{text}");
    }

    /// A message that IS queued is delivered by the next send: the advice must say
    /// not to retype it (the retry would deliver both copies). The same for
    /// every p2p reason.
    #[test]
    fn queued_advice_never_invites_retyping_the_queued_message() {
        let raw = "ipc LAN_DIAL: lan connect: cannot connect to 192.168.0.16:7420 (192.168.0.16:7420: Connection refused (os error 61)); mid=abcdef01…";
        let text = queued_text(&bob(), raw, "\"hello\"", &next_send());
        assert!(text.starts_with(QUEUED_PREFIX), "{text}");
        assert!(text.contains("Do not retype this message"), "{text}");
        assert!(!text.contains(", then send again"), "{text}");
        assert!(
            text.contains("Ask Bob to open Raven."),
            "the next step stays: {text}"
        );
        let text = queued_text(&bob(), raw, "\"hello\"", &background());
        assert!(text.contains("Do not retype this message"), "{text}");
        assert!(text.contains("sends it by itself"), "{text}");
        assert!(!text.contains(", then send again"), "{text}");
        // Every p2p reason, with every fix it can get.
        for (d, n) in every_case() {
            let step = p2p_next_step(&d, &bob(), &n, StepMode::Queued).unwrap_or_default();
            assert!(!step.contains(", then send again"), "{step}");
            assert!(!step.contains("Then send again"), "{step}");
        }
        for why in Why::ALL {
            let raw = with_block(&format!("reach: why={} me=unreachable", why.token()));
            for retry in [background(), next_send()] {
                let text = queued_text(&nobody_known(), &raw, "\"hello\"", &retry);
                assert!(text.contains("Do not retype this message"), "{text}");
                assert!(!text.contains(", then send again"), "{text}");
                assert!(!text.contains("Then send again"), "{text}");
            }
        }
    }

    // ── p2p reasons (the diagnosis) ─────────────────────────────────────

    use raven_core::reach::ReachClass;

    /// raven-node's P2P_UNREACHABLE text as ash sees it.
    const P2P_RAW: &str = "ipc P2P_DIAL: P2P_UNREACHABLE: the contact is unreachable on every p2p \
                           address it has (direct and relay)";

    /// [`P2P_RAW`] with raven-node's reason block.
    fn with_block(block: &str) -> String {
        format!("{P2P_RAW}; {block}")
    }

    /// Bob with no profile: the circle is not known.
    fn nobody_known() -> SendCtx {
        SendCtx {
            data_dir: None,
            ..bob()
        }
    }

    /// The names a fix is worded with (Carol owns our relay slot, Dana is
    /// the friend to ask).
    fn names(fix: Fix) -> ReachNames {
        ReachNames {
            relay: "Carol's relay".into(),
            relay_owner: "Carol".into(),
            fix,
            friend: "Dana".into(),
            port: raven_core::p2p_route::DEFAULT_P2P_PORT,
        }
    }

    /// Every reason with each kind of flag it may carry.
    fn every_diag() -> Vec<Diag> {
        let mut out = Vec::new();
        for why in Why::ALL {
            for relay in [None, Some(1)] {
                for (heard_s, stale, from_card, asof_s) in [
                    (None, false, false, None),
                    (Some(10_800), true, true, None),
                    (Some(60), false, false, Some(30)),
                ] {
                    for me in [
                        None,
                        Some(ReachClass::Unreachable),
                        Some(ReachClass::Relayed),
                    ] {
                        out.push(Diag {
                            why,
                            me,
                            relay,
                            heard_s,
                            stale,
                            from_card,
                            asof_s,
                        });
                    }
                }
            }
        }
        out
    }

    /// Unknown, nobody, an offering friend, a reachable one.
    fn circles() -> Vec<CircleFacts> {
        let known = CircleFacts {
            known: true,
            ..CircleFacts::default()
        };
        vec![
            CircleFacts::default(),
            known.clone(),
            CircleFacts {
                offers: vec![[3; 32]],
                ..known.clone()
            },
            CircleFacts {
                reachable: vec![[4; 32]],
                ..known.clone()
            },
            // Phase 3 custody: no friend can hold mail for the contact.
            CircleFacts {
                mail: MailPath::MailboxOff,
                ..known.clone()
            },
            CircleFacts {
                mail: MailPath::NoFriend,
                ..known
            },
        ]
    }

    /// Every fix each reason can get, with the facts that pick it.
    fn every_case() -> Vec<(Diag, ReachNames)> {
        let mut out = Vec::new();
        for d in every_diag() {
            for circle in circles() {
                for (public, relaying) in [(false, false), (true, false), (true, true)] {
                    let fix = reach_diag::pick_fix(&d, public, relaying, &circle);
                    out.push((d.clone(), names(fix)));
                }
            }
        }
        out
    }

    /// A next step that ends a first or later send: it says when to send
    /// again, to wait, or who writes first.
    fn ends_with_a_send_again_or_a_wait(step: &str) -> bool {
        let lower = step.to_ascii_lowercase();
        [
            "send again",
            "send it again",
            "send it when",
            "wait until",
            "try again",
            "send you the first message",
        ]
        .iter()
        .any(|w| lower.contains(w))
    }

    #[test]
    fn p2p_reasons_have_a_sentence_and_a_step_for_every_reason_and_mode() {
        let ctx = bob();
        let mut seen = std::collections::HashSet::new();
        for (d, n) in every_case() {
            let sentence = p2p_cause_sentence(&d, &ctx, &n);
            assert!(
                !sentence.is_empty() && !sentence.contains('\n'),
                "{sentence}"
            );
            assert!(!sentence.ends_with('.'), "the caller ends it: {sentence}");
            assert!(!sentence.contains("--lan-dial"), "{sentence}");
            for mode in [StepMode::FirstContact, StepMode::Later, StepMode::Queued] {
                let Some(step) = p2p_next_step(&d, &ctx, &n, mode) else {
                    assert_eq!(n.fix, Fix::Generic, "{d:?}");
                    continue;
                };
                seen.insert(std::mem::discriminant(&n.fix));
                assert!(!step.contains('\n') && step.ends_with('.'), "{step}");
                assert!(!step.contains("--lan-dial"), "{step}");
                if mode == StepMode::Queued {
                    assert!(
                        !step.to_ascii_lowercase().contains("send again"),
                        "a queued message is never sent again by hand: {step}"
                    );
                } else {
                    assert!(ends_with_a_send_again_or_a_wait(&step), "{mode:?}: {step}");
                }
            }
        }
        // Every fix but Generic was worded.
        assert_eq!(seen.len(), 14, "{seen:?}");
    }

    /// Phase 3 diagnosis (P3.23) in P3.C6's plain words: the local network
    /// reasons and the mailbox fixes, word for word where the plan gives the
    /// words. The why and what-to-do rows together say P3.C6's LAN_OFF and
    /// LAN_NO_ANSWER texts.
    #[test]
    fn lan_off_and_lan_no_answer_texts_and_the_mailbox_fixes() {
        let ctx = bob();
        let lan_off = Diag::find("reach: why=lan_off").unwrap();
        let silent = Diag::find("reach: why=lan_no_answer heard=5m").unwrap();
        assert_eq!(
            p2p_cause_sentence(&lan_off, &ctx, &names(Fix::LanOn)),
            "you turned the local network off (`raven lan on` turns it on), so RAVEN does not \
             look for Bob here, and it knows no other way to reach Bob"
        );
        assert_eq!(
            p2p_cause_sentence(&silent, &ctx, &names(Fix::WaitUntilOnline)),
            "none of your friends answered on this network: RAVEN looked for Bob here and got \
             no answer, and it knows no other way to reach Bob; RAVEN last heard from Bob 5 min \
             ago"
        );
        assert_eq!(
            reach_legend(&silent),
            "none of your friends answered on this network"
        );
        assert_eq!(
            reach_legend(&lan_off),
            "you turned the local network off: raven lan on"
        );
        assert_eq!(
            LAN_NO_ANSWER_TEXT,
            "None of your friends answered on this network. If you are on the same Wi-Fi, it \
             may keep devices apart (common in hotels and guest Wi-Fi): make a hotspot instead \
             (docs/OFFLINE_GUIDE.md §3)."
        );
        assert_eq!(
            LAN_NO_ANSWER_TEXT,
            format!("None{}. {LAN_NO_ANSWER_ADVICE}", &LAN_NO_ANSWER_SHORT[4..])
        );
        assert_eq!(
            LAN_OFF_TEXT,
            "You turned the local network off (`raven lan on` turns it on). Your messages wait \
             here."
        );
        let step =
            |d: &Diag, fix: Fix, mode: StepMode| p2p_next_step(d, &ctx, &names(fix), mode).unwrap();
        assert_eq!(
            step(&lan_off, Fix::LanOn, StepMode::Queued),
            "Your messages wait here."
        );
        assert_eq!(
            step(&lan_off, Fix::LanOn, StepMode::Later),
            "Turn the local network back on (`raven lan on`), then send again."
        );
        assert_eq!(
            step(&silent, Fix::WaitUntilOnline, StepMode::Queued),
            format!(
                "{LAN_NO_ANSWER_ADVICE} Nothing to do on your side: it goes out when Bob is back \
                 online."
            )
        );
        assert_eq!(
            step(&silent, Fix::UseMailbox, StepMode::Queued),
            format!(
                "{LAN_NO_ANSWER_ADVICE} Turn on friend mailboxes (`raven custody use on`): a \
                 friend you both verified can then hold your messages while Bob is offline (that \
                 friend learns that you wrote to Bob, not what). Otherwise it goes out when Bob \
                 is back online."
            )
        );
        assert_eq!(
            step(&silent, Fix::AskFriendToHoldMail, StepMode::Queued),
            format!(
                "{LAN_NO_ANSWER_ADVICE} No friend holds mail for Bob yet: ask a friend you both \
                 verified, whose computer is always on, to run `raven node custody on`. \
                 Otherwise it goes out when Bob is back online."
            )
        );
        assert!(step(&silent, Fix::AskFriendToHoldMail, StepMode::Later)
            .ends_with("Or wait until Bob is back online, then send again."));
        // A first message cannot be held by a friend: it waits for Bob (the
        // NOT SENT before it says why, E1).
        for fix in [Fix::UseMailbox, Fix::AskFriendToHoldMail] {
            assert_eq!(
                step(&silent, fix, StepMode::FirstContact),
                format!("{LAN_NO_ANSWER_ADVICE} Send it again when Bob is online.")
            );
        }
        // The fixes come from pick_fix: an offline contact (p2p or LAN)
        // with no friend to hold mail.
        for d in [&silent, &Diag::find("reach: why=contact_offline").unwrap()] {
            for (mail, want) in [
                (MailPath::NoFix, Fix::WaitUntilOnline),
                (MailPath::MailboxOff, Fix::UseMailbox),
                (MailPath::NoFriend, Fix::AskFriendToHoldMail),
            ] {
                let circle = CircleFacts {
                    known: true,
                    mail,
                    ..CircleFacts::default()
                };
                let n = ReachNames::from_facts(d, None, &circle, &|_| String::new(), &[]);
                assert_eq!(n.fix, want);
            }
        }
        // `raven outbox status` rows for a LAN object raven-node gave the
        // reason to.
        let rows = outbox_why_rows(&nobody_known(), "reach: why=lan_off asof=30s");
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert!(
            rows[0].contains("you turned the local network off (`raven lan on` turns it on)"),
            "{rows:?}"
        );
        assert_eq!(
            rows[1], "  what to do  Your messages wait here.",
            "{rows:?}"
        );
        // Release builds: learned custody is not live, so no mailbox fix is
        // read (and no identity is loaded for it).
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            contact_mail_path(dir.path(), &"ab".repeat(32)),
            MailPath::NoFix
        );
    }

    /// A reason block's `why=lan_off` never reads as raven-node's LAN_OFF
    /// refusal; the refusal itself still does.
    #[test]
    fn a_lan_off_reason_block_is_not_the_lan_off_refusal() {
        let refusal = "LAN_OFF: raven lan off is in effect (raven lan on)";
        assert_eq!(classify_cause(refusal), Cause::LanOff);
        assert_eq!(
            classify_cause(&format!("ipc LAN_OFF: {refusal}")),
            Cause::LanOff
        );
        assert_eq!(
            classify_cause(&with_block("reach: why=lan_off")),
            Cause::NotReachable
        );
        assert_eq!(
            classify_cause("lan_dial 192.168.0.16:7420: no answer within 7s; reach: why=lan_off)"),
            Cause::NotReachable
        );
        // The fail-closed pin store comes first among local problems.
        assert_eq!(
            classify_cause(&format!(
                "lan noise pin unavailable: lan_noise_pins.json: denied; {refusal}"
            )),
            Cause::PinStoreUnreadable
        );
    }

    /// A reason block never changes how today's text is read: the cause
    /// class of every known raw text stays the same with any block after it.
    #[test]
    fn reach_tokens_never_change_the_cause_class() {
        let mut raws: Vec<(String, Cause)> = sentence_table("")
            .into_iter()
            .map(|(raw, cause, _)| (raw.to_string(), cause))
            .collect();
        raws.push((P2P_RAW.to_string(), Cause::NotReachable));
        let blocks: Vec<String> = every_diag().iter().map(Diag::render).collect();
        for (raw, cause) in &raws {
            assert_eq!(classify_cause(raw), *cause, "{raw}");
            for block in &blocks {
                let joined = format!("{raw}; {block}");
                assert_eq!(classify_cause(&joined), *cause, "{joined}");
                let wrapped = format!("p2p_dial /p2p/x: {raw}; {block}");
                assert_eq!(classify_cause(&wrapped), *cause, "{wrapped}");
            }
        }
    }

    /// An older raven-node (no reason block) gets exactly today's text.
    #[test]
    fn an_old_daemon_text_is_byte_identical() {
        let ctx = SendCtx::named("Bob");
        let step = "Bob must be reachable directly or through a relay you both use (`raven node \
                    p2p on --relay ...`). If their address changed: ash contact set-addr \
                    --petname Bob --p2p PEER_ID --via MULTIADDR.";
        let cause = "Bob did not answer: their computer may be off or asleep, on another network, \
                     or have a new IP address";
        assert_eq!(
            not_sent_text(&ctx, P2P_RAW, false),
            format!("NOT SENT: {cause}. Nothing was queued. {step} (technical: {P2P_RAW})")
        );
        assert_eq!(
            not_sent_text(&ctx, P2P_RAW, true),
            format!(
                "NOT SENT: {cause}. It was not kept: a first message needs you and Bob both \
                 online (RAVEN hasn't connected with Bob yet). Send it again when Bob is online. \
                 {step} (technical: {P2P_RAW})"
            )
        );
        let retry = background();
        assert_eq!(
            queued_text(&ctx, P2P_RAW, "\"hi\"", &retry),
            format!(
                "not delivered yet: your message \"hi\" to Bob is queued locally because {cause}. \
                 Queued: raven-node keeps trying in the background until {} and sends it by \
                 itself when you are both on the same network (`raven outbox list` shows it); \
                 after that it is not sent, and `raven outbox list` says so. {step} Do not \
                 retype this message. (technical: {P2P_RAW})",
                retry.until()
            )
        );
        // A block with a reason this ash does not know is no block.
        let newer = with_block("reach: why=moon_phase me=relayed");
        assert_eq!(
            not_sent_text(&ctx, &newer, false),
            format!("NOT SENT: {cause}. Nothing was queued. {step} (technical: {newer})")
        );
    }

    /// A multi-route failure joins the LAN route's old refusal and the p2p
    /// route's reason: the reason explains it, and no LAN advice is given.
    #[test]
    fn a_multi_route_failure_uses_the_p2p_reason_over_a_stale_lan_refusal() {
        // Their LAN address is on no network of this computer, whatever
        // network the test runs on.
        let _away = off_our_network();
        let raw = format!(
            "lan_dial 192.168.0.16:7420: ipc LAN_DIAL: lan connect: cannot connect to \
             192.168.0.16:7420 (192.168.0.16:7420: Connection refused (os error 61)); p2p_dial \
             /p2p/12D3KooWx: {P2P_RAW}; reach: why=contact_offline me=relayed heard=2h"
        );
        assert_eq!(classify_cause(&raw), Cause::NotListening);
        let text = not_sent_text(&nobody_known(), &raw, false);
        let sentence = text.split("(technical:").next().unwrap();
        assert!(
            sentence.starts_with(
                "NOT SENT: Bob is offline: Bob's relay answered, but Bob's computer is not \
                 connected to it"
            ),
            "{text}"
        );
        assert!(
            sentence.contains("RAVEN last heard from Bob 2 h ago"),
            "{text}"
        );
        assert!(
            sentence.contains("Wait until Bob is back online, then send again."),
            "{text}"
        );
        assert!(!sentence.contains("not listening"), "{text}");
        assert!(!sentence.contains("--lan-dial"), "{text}");
    }

    /// A refusal, a wrong key, a block or any cause other than "nobody
    /// answered" keeps today's sentence, whatever block follows.
    #[test]
    fn a_refusal_or_wrong_key_never_gets_a_reach_reason() {
        let ctx = nobody_known();
        for raw in [
            "ipc P2P_DIAL: P2P_DIAL_PEER_CLOSED: the peer closed the connection without replying",
            "ipc P2P_DIAL: identity bind does not match expected pub",
            "peer is on the local block list",
            "message too large for p2p_dial (max 49152 bytes)",
            "raven-node is not running; start it with `ash listen`",
        ] {
            for d in every_diag() {
                let joined = format!("{raw}; {}", d.render());
                let cause = classify_cause(&joined);
                let today = not_sent_for(cause, &ctx, raw, false);
                let with = not_sent_for(cause, &ctx, &joined, false);
                assert_eq!(
                    with.split("(technical:").next(),
                    today.split("(technical:").next(),
                    "{joined}"
                );
                assert!(p2p_reason(cause, &ctx, &joined).is_none(), "{joined}");
            }
        }
    }

    /// A first message needs a working path, not only the contact online:
    /// the rule it goes by (E1), and that there is no path; an offline
    /// contact gets the rule and "send it again when Bob is online", once.
    #[test]
    fn the_first_message_says_it_needs_a_path_not_just_online() {
        let ctx = nobody_known();
        let rule = "a first message needs you and Bob both online (RAVEN hasn't connected with \
                    Bob yet)";
        let text = not_sent_text(
            &ctx,
            &with_block("reach: why=both_nat me=unreachable"),
            true,
        );
        assert!(
            text.starts_with("NOT SENT: you and Bob are both behind NAT"),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "It was not kept: {rule}, and there is no working path to Bob now."
            )),
            "{text}"
        );
        assert!(!text.contains("Send it again when Bob is online"), "{text}");
        let text = not_sent_text(&ctx, &with_block("reach: why=contact_offline"), true);
        assert!(
            text.contains(&format!(
                "It was not kept: {rule}. Send it again when Bob is online."
            )),
            "{text}"
        );
        assert_eq!(
            text.matches("Send it again when Bob is online.").count(),
            1,
            "{text}"
        );
    }

    /// Both behind NAT: a friend who offers relaying is named first, then
    /// one who can be reached from the internet; with nobody, the three
    /// ways out (a friend's relay offer, the relay kit, a port forward).
    #[test]
    fn the_circle_fix_names_an_offering_friend_first_then_a_reachable_one_else_the_three_options() {
        let d = Diag::find("reach: why=both_nat me=unreachable").unwrap();
        let label = |hex: &str| match hex {
            h if h == hex::encode([3; 32]) => "Carol".to_string(),
            h if h == hex::encode([4; 32]) => "Dana".to_string(),
            _ => String::new(),
        };
        let step = |circle: CircleFacts| {
            let n = ReachNames::from_facts(&d, None, &circle, &label, &[]);
            p2p_next_step(&d, &bob(), &n, StepMode::Later).unwrap()
        };
        let known = CircleFacts {
            known: true,
            ..CircleFacts::default()
        };
        let both = step(CircleFacts {
            offers: vec![[3; 32]],
            reachable: vec![[4; 32]],
            ..known.clone()
        });
        assert!(
            both.starts_with(
                "Carol can be reached from the internet: ask Carol to offer relaying (`raven \
                 relay offer on` on Carol's computer); RAVEN then uses it for you and Bob by \
                 itself, as long as you are both Carol's verified contacts."
            ),
            "{both}"
        );
        let reachable = step(CircleFacts {
            reachable: vec![[4; 32]],
            ..known.clone()
        });
        assert!(reachable.starts_with("Dana can be reached"), "{reachable}");
        for text in [&both, &reachable] {
            assert!(text.contains("the relay kit (docs/RELAY_KIT.md)"), "{text}");
            assert!(text.ends_with(" Then send again."), "{text}");
        }
        let nobody = step(known.clone());
        for words in [
            "Nobody in your circle can be reached from the internet",
            "Any one of these fixes it",
            "(`raven relay offer on` on their computer)",
            "run the relay kit (docs/RELAY_KIT.md) on a Raspberry Pi",
            "forward port 7423 (TCP and UDP)",
            "`raven node upnp on`",
        ] {
            assert!(nobody.contains(words), "{words:?} missing: {nobody}");
        }
        // The port named is the one the running raven-node listens on (field
        // test E2 r7: a profile on 17423 was told to forward 7423).
        let profile = raven_core::ipc::P2pStatusInfo {
            up: true,
            listen_setting: "17423".into(),
            ..Default::default()
        };
        for circle in [
            CircleFacts {
                offers: vec![[3; 32]],
                ..known.clone()
            },
            known.clone(),
        ] {
            let n = ReachNames::from_facts(&d, Some(&profile), &circle, &label, &[]);
            assert_eq!(n.port, 17423);
            let text = p2p_next_step(&d, &bob(), &n, StepMode::Queued).unwrap();
            assert!(text.contains("forward port 17423 (TCP and UDP)"), "{text}");
            assert!(!text.contains("port 7423"), "{text}");
        }
        // Not known (no profile): today's advice.
        let n = ReachNames::from_facts(&d, None, &CircleFacts::default(), &label, &[]);
        assert_eq!(n.fix, Fix::Generic);
        assert_eq!(p2p_next_step(&d, &bob(), &n, StepMode::Later), None);

        // From the profile's own files: a verified contact whose card names
        // a direct address of its own (a global one: a documentation, LAN or
        // loopback address says nothing about the internet).
        let dir = tempfile::tempdir().unwrap();
        let carol = Identity::from_seed(&[61; 32]);
        let peer = raven_core::p2p_route::local_peer_id(&carol);
        let book = serde_json::json!([{
            "petname": "Carol", "public_tag": "", "alias": "", "address": carol.address(),
            "pub_hex": hex::encode(carol.public_key_bytes()), "pinned": true, "lan_dial": "",
            "p2p": peer, "p2p_via": [format!("/ip4/11.0.0.9/tcp/7423/p2p/{peer}")],
        }]);
        std::fs::write(dir.path().join("contacts.json"), book.to_string()).unwrap();
        let ctx = SendCtx {
            data_dir: Some(dir.path().to_path_buf()),
            ..bob()
        };
        let text = queued_text(
            &ctx,
            &with_block("reach: why=both_nat me=unreachable"),
            "",
            &background(),
        );
        assert!(
            text.contains("Carol can be reached from the internet: ask Carol to offer relaying"),
            "{text}"
        );
        assert!(!text.contains(&peer), "{text}");
    }

    /// ash's 7 s probe ended before raven-node's dial did: without a reason
    /// yet, the text says `raven status` will tell.
    #[test]
    fn cut_short_p2p_probe_says_raven_status_will_tell() {
        let raw = "p2p_dial /p2p/12D3KooWx: no answer within 7s (the probe was cut short; nothing \
                   was sent)";
        let tell = "RAVEN is still finding out why: `raven status` says it once raven-node has \
                    tried again (within about a minute).";
        assert_eq!(tell, STILL_FINDING_OUT);
        // No 20 s promise: a dial on a stale link gives its reason only
        // with the next try.
        assert!(!tell.contains("20 s"));
        let text = queued_text(&nobody_known(), raw, "", &background());
        assert!(text.contains(tell), "{text}");
        assert!(text.contains("Do not retype this message"), "{text}");
        // Not for a LAN probe, and not once the reason is known.
        let lan = "lan_dial 192.168.0.16:7420: no answer within 7s (the probe was cut short; \
                   nothing was sent)";
        assert!(!queued_text(&nobody_known(), lan, "", &background()).contains(tell));
        let known = format!("{raw}; reach: why=contact_offline asof=30s");
        assert!(!queued_text(&nobody_known(), &known, "", &background()).contains(tell));
    }

    /// raven-node's earlier check (`asof`) wraps the reason: the contact did
    /// not answer in time, and what that check found.
    #[test]
    fn asof_wraps_the_sentence() {
        let raw = "p2p_dial /p2p/12D3KooWx: no answer within 7s (the probe was cut short; nothing \
                   was sent); reach: why=contact_offline me=relayed asof=30s";
        let text = queued_text(&nobody_known(), raw, "\"hi\"", &background());
        assert!(
            text.starts_with(
                "not delivered yet: your message \"hi\" to Bob is queued locally because Bob did \
                 not answer in time; RAVEN's check 30 s ago found that Bob is offline: Bob's \
                 relay answered"
            ),
            "{text}"
        );
        assert!(
            text.contains("Nothing to do on your side: it goes out when Bob is back online."),
            "{text}"
        );
        for d in every_diag().into_iter().filter(|d| d.asof_s.is_some()) {
            let s = p2p_cause_sentence(&d, &bob(), &names(Fix::WaitUntilOnline));
            assert!(
                s.starts_with("Bob did not answer in time; RAVEN's check 30 s ago found that "),
                "{s}"
            );
        }
    }

    /// `raven outbox list`: `last: NOT_REACHABLE` says the reason's legend
    /// when raven-node gave one, else the code's words.
    #[test]
    fn outbox_row_has_a_reach_legend_only_with_a_reason() {
        let dir = tempfile::tempdir().unwrap();
        let item = |why: &str| raven_core::ipc::OutboxItem {
            message_id_hex: "cd".repeat(16),
            peer_pub_hex: "ef".repeat(32),
            kind: "message".into(),
            state: "queued".into(),
            carrier: "p2p_dial".into(),
            attempts: 3,
            last_error_code: "NOT_REACHABLE".into(),
            why: why.into(),
            ..Default::default()
        };
        let line = plain(&outbox_row_line(
            dir.path(),
            &item("reach: why=both_nat"),
            0,
        ));
        assert!(line.contains("last: both behind NAT, no relay"), "{line}");
        let mine = plain(&outbox_row_line(
            dir.path(),
            &item("reach: why=relay_asleep relay=mine2"),
            0,
        ));
        assert!(
            mine.contains("last: your shared relay is not answering"),
            "{mine}"
        );
        for why in ["", "reach: why=moon_phase", "garbage"] {
            let line = plain(&outbox_row_line(dir.path(), &item(why), 0));
            assert!(
                line.contains(
                    "last: ef…'s computer couldn't be reached (it may be off, asleep, or on \
                     another network)"
                ) || line.contains("computer couldn't be reached"),
                "{line}"
            );
            assert!(!line.contains("NOT_REACHABLE"), "{line}");
        }
        for why in Why::ALL {
            let d = Diag::find(&format!("reach: why={}", why.token())).unwrap();
            assert!(!reach_legend(&d).is_empty());
        }
        assert_eq!(
            reach_legend(&Diag::find("reach: why=no_route").unwrap()),
            "no route to the internet from this computer"
        );
    }

    /// E1: `raven outbox list` says every code raven-node gives in words
    /// (`last: MAILBOX_OFF` meant nothing), a reset code its legend, a code
    /// this ash does not know as it came; `raven outbox status` keeps the
    /// code (`last error`).
    #[test]
    fn outbox_row_says_its_last_error_in_words() {
        let dir = tempfile::tempdir().unwrap();
        let item = |code: &str, carrier: &str| raven_core::ipc::OutboxItem {
            message_id_hex: "cd".repeat(16),
            peer_pub_hex: "ef".repeat(32),
            kind: "message".into(),
            state: "queued".into(),
            carrier: carrier.into(),
            attempts: 2,
            last_error_code: code.into(),
            ..Default::default()
        };
        let last = |code: &str, carrier: &str| {
            let line = plain(&outbox_row_line(dir.path(), &item(code, carrier), 0));
            line.split("  last: ")
                .nth(1)
                .unwrap_or_else(|| panic!("{line}"))
                .split("  ")
                .next()
                .unwrap()
                .to_owned()
        };
        let mailbox = last("MAILBOX_OFF", "");
        assert!(mailbox.contains("friend mailboxes are off"), "{mailbox}");
        let refused = last("NOT_LISTENING", "lan_dial");
        assert!(
            refused.ends_with(
                "computer is there, but Raven isn't receiving right now (it may be locked or \
                 closed)"
            ),
            "{refused}"
        );
        assert_eq!(
            last("PEER_RESET_LOOP", ""),
            "on hold: too many connection resets today"
        );
        assert_eq!(last("SOMETHING_NEW", ""), "SOMETHING_NEW");
        // Every code raven-node gives has words: never the code itself.
        for code in [
            "NOT_A_CONTACT",
            "CONTACT_BLOCKED",
            "SENDING_PAUSED",
            "CONTACTS_UNREADABLE",
            "NO_ROUTE",
            "DEFERRED",
            "SEND_IN_PROGRESS",
            "LOCK",
            "NO_PEER_CERT",
            "STORE",
            "NO_ACK_YET",
            "EXPIRED",
            "P2P_HOLD",
            "P2P_NOT_RUNNING",
            "NEARBY_NOT_IN_RANGE",
            "LINK_NOT_ACCEPTED",
            "PEER_REFUSED",
            "WRONG_IDENTITY",
            "CLOSED_EARLY",
            "DIAL_FAILED",
            "IN_CUSTODY",
            "NO_SHARED_CUSTODIAN",
            "CUSTODIAN_NOT_OFFERING",
            "MAILBOX_OFF",
            "WAITING_FOR_CARRIER",
            "CONTACT_NOT_VERIFIED",
        ] {
            let words = last(code, "lan_dial");
            assert!(
                !words.contains(code) && !words.is_empty(),
                "{code}: {words}"
            );
        }
        let rows = outbox_status_rows(&item("MAILBOX_OFF", ""), 0);
        assert!(
            rows.iter().any(|r| r == "  last error  MAILBOX_OFF"),
            "{rows:?}"
        );
    }

    /// E1: a friend whose Raven refused the connection (locked or closed:
    /// a sender cannot tell) is said to be there but not receiving; a
    /// queued message waits and goes by itself, a message not sent asks to
    /// open Raven. Neither names `ash listen` or a new address: the
    /// computer answered at it.
    #[test]
    fn a_friend_not_receiving_may_be_locked_or_closed() {
        let raw = "ipc LAN_DIAL: lan connect: cannot connect to 192.168.0.16:7420 \
                   (192.168.0.16:7420: Connection refused (os error 61))";
        let ctx = bob();
        let queued = queued_text(&ctx, raw, "", &background());
        assert!(
            queued.contains(
                "queued locally because Bob's computer is there, but Raven isn't receiving \
                 right now (it may be locked or closed)."
            ),
            "{queued}"
        );
        // E2 r38: "it goes by itself" is said once (the queued sentence).
        assert_eq!(
            queued.matches("Do not retype this message").count(),
            1,
            "{queued}"
        );
        assert!(
            !queued.contains("The message waits and goes by itself."),
            "{queued}"
        );
        assert!(
            !queued.contains("you do not need to send it again"),
            "{queued}"
        );
        let not_sent = not_sent_text(&ctx, raw, false);
        assert!(
            not_sent.starts_with(
                "NOT SENT: Bob's computer is there, but Raven isn't receiving right now (it may \
                 be locked or closed)."
            ),
            "{not_sent}"
        );
        assert!(
            not_sent.contains("Ask Bob to open Raven, then send again."),
            "{not_sent}"
        );
        for text in [&queued, &not_sent] {
            let head = text.split("(technical:").next().unwrap();
            assert!(!head.contains("ash listen"), "{text}");
            assert!(!head.contains("set-dial"), "{text}");
        }
        // Without a background outbox it goes with the next send.
        let next = queued_text(&ctx, raw, "", &RetryNote::default());
        assert!(
            next.contains("Ask Bob to open Raven.")
                && next.contains("it goes out with your next send to Bob"),
            "{next}"
        );
    }

    /// P5.6 (the long message horizon): a parked message is `waiting` with
    /// its own deadline in local time, `waiting · until …`, never "expires".
    #[test]
    fn outbox_row_of_a_parked_message_says_waiting_until_its_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_700_000_000_000u64;
        let at = now + 6 * 24 * 3_600_000;
        let item = raven_core::ipc::OutboxItem {
            message_id_hex: "cd".repeat(16),
            peer_pub_hex: "ef".repeat(32),
            kind: "message".into(),
            state: "waiting".into(),
            next_attempt_ms: now + 5_000,
            expires_at_ms: at,
            ..Default::default()
        };
        let line = plain(&outbox_row_line(dir.path(), &item, now));
        assert!(
            line.contains(&format!("waiting · until {}", until_text(at, now))),
            "{line}"
        );
        assert!(!line.contains("expires"), "{line}");
        let rows = outbox_status_rows(&item, now);
        assert!(
            rows.iter()
                .any(|r| r.contains("waiting ·") && r.contains("until")),
            "{rows:?}"
        );
    }

    /// `raven outbox status`: `why` and `what to do` right after `last
    /// error`, in the send path's own words (queued: nothing to retype).
    #[test]
    fn outbox_status_prints_why_and_what_to_do() {
        let item = raven_core::ipc::OutboxItem {
            message_id_hex: "ab".repeat(16),
            state: "queued".into(),
            carrier: "p2p_dial".into(),
            attempts: 2,
            last_error_code: "NOT_REACHABLE".into(),
            expires_at_ms: 1,
            why: "reach: why=both_nat me=unreachable".into(),
            ..Default::default()
        };
        let d = Diag::find(&item.why).unwrap();
        let mut rows = outbox_status_rows(&item, 0);
        after_last_error(
            &mut rows,
            outbox_why_rows_with(&bob(), &d, &names(Fix::NobodyReachable)),
        );
        let at = rows
            .iter()
            .position(|r| r.starts_with("  last error"))
            .unwrap();
        assert!(
            rows[at + 1].starts_with("  why         you and Bob are both behind NAT"),
            "{rows:?}"
        );
        assert!(rows[at + 1].ends_with("uses no relay."), "{rows:?}");
        assert!(
            rows[at + 2].starts_with(
                "  what to do  Nobody in your circle can be reached from the internet"
            ),
            "{rows:?}"
        );
        assert!(!rows[at + 2].contains("send again"), "{rows:?}");
        assert!(rows[at + 3].starts_with("  expires"), "{rows:?}");
        // No reason: no rows.
        assert!(outbox_why_rows(&nobody_known(), "").is_empty());
        assert!(outbox_why_rows(&nobody_known(), "NOT_REACHABLE").is_empty());
        // Without a `last error` they go last.
        let mut bare = vec!["  attempts    1".to_string()];
        after_last_error(&mut bare, vec!["  why         x.".into()]);
        assert_eq!(bare[1], "  why         x.");
    }

    /// No text for a computer without a route names a fix on the internet
    /// side: none of them could help.
    fn assert_no_internet_side_fix(text: &str) {
        let lower = text.to_ascii_lowercase();
        for word in [
            "relay kit",
            "relay_kit",
            "vps",
            "raspberry pi",
            OFFER_CMD,
            "upnp",
            "forward",
            "--external",
            "public ip",
            "wake",
        ] {
            assert!(!lower.contains(word), "{word:?} in: {text}");
        }
    }

    /// F9: an Internet direct dial that reached nobody while this computer
    /// has no route to the internet advises nothing on the contact's side
    /// (Internet direct on, a port forward): only the same network helps.
    /// raven-node is asked (`Status.egress`) for that step only; with a
    /// route, or with no raven-node answering, today's text.
    #[test]
    fn internet_direct_step_without_a_route_advises_nothing_on_the_internet_side() {
        let fix = fix_address_cmd(FailedCarrier::Internet, "--petname Bob");
        let offline = internet_unreachable_step("Bob", &fix, || true);
        assert_no_internet_side_fix(&offline);
        assert_eq!(
            offline,
            "This computer has no route to the internet right now: send it again when you and \
             Bob are on the same network (the same Wi-Fi, a hotspot or a cable)."
        );
        let online = internet_unreachable_step("Bob", &fix, || false);
        assert!(
            online.contains("their router forwarding that port"),
            "{online}"
        );
        // Through the outcome line: no raven-node answers in this folder.
        let dir = tempfile::tempdir().unwrap();
        let ctx = SendCtx {
            data_dir: Some(dir.path().to_path_buf()),
            ..bob()
        };
        let raw = "internet_dial 203.0.113.7:7422: internet connect: no answer within 10s";
        let text = not_sent_text(&ctx, raw, false);
        assert!(text.contains("their router forwarding that port"), "{text}");
    }

    #[test]
    fn no_route_texts_never_suggest_internet_side_fixes() {
        let ctx = bob();
        let cases: Vec<(Diag, ReachNames)> = every_case()
            .into_iter()
            .filter(|(d, _)| d.why == Why::NoRoute)
            .collect();
        assert!(!cases.is_empty());
        for (d, n) in cases {
            assert_eq!(n.fix, Fix::LocalOnly, "{d:?}");
            assert_no_internet_side_fix(&p2p_cause_sentence(&d, &ctx, &n));
            for mode in [StepMode::FirstContact, StepMode::Later, StepMode::Queued] {
                assert_no_internet_side_fix(&p2p_next_step(&d, &ctx, &n, mode).unwrap());
            }
            assert!(p2p_cause_sentence(&d, &ctx, &n).contains("only on the same network"));
        }
        // The whole outcome lines, every flag, every way a send ends.
        let ctx = nobody_known();
        for d in every_diag().into_iter().filter(|d| d.why == Why::NoRoute) {
            let raw = with_block(&d.render());
            let sentences = |t: String| t.split("(technical:").next().unwrap().to_string();
            for first in [true, false] {
                assert_no_internet_side_fix(&sentences(not_sent_text(&ctx, &raw, first)));
            }
            for retry in [background(), next_send()] {
                assert_no_internet_side_fix(&sentences(queued_text(&ctx, &raw, "", &retry)));
            }
        }
        let queued = queued_text(&ctx, &with_block("reach: why=no_route"), "", &background());
        assert!(
            queued.contains(
                "Nothing to do: it goes out when you and Bob are on the same network, or when \
                 this computer can reach the internet again."
            ),
            "{queued}"
        );
        let first = not_sent_text(&ctx, &with_block("reach: why=no_route"), true);
        assert!(
            first.starts_with(
                "NOT SENT: this computer has no route to the internet right now, so RAVEN can \
                 reach Bob only on the same network as you (the same Wi-Fi, a hotspot or a \
                 cable)."
            ),
            "{first}"
        );
        assert!(
            first.contains(
                "It was not kept: a first message needs you and Bob both online (RAVEN hasn't \
                 connected with Bob yet), and there is no working path to Bob now. Send it \
                 again when you and Bob are on the same network."
            ),
            "{first}"
        );
    }

    /// E1 (three machines): a send listed two LAN dials to win-c (the
    /// address the beacon found and the saved one), queued, and said it was
    /// queued "because win-c did not answer at the internet address win-c
    /// gave you": the p2p route after them (not listed) failed at its direct
    /// addresses, and its reason won. A p2p dial whose direct addresses only
    /// did not answer says nothing the LAN routes do not: their result names
    /// the addresses tried. Any other p2p reason still explains the send,
    /// and a p2p dial alone keeps its own words.
    #[test]
    fn a_direct_failed_p2p_reason_does_not_hide_the_lan_routes_tried() {
        // Their LAN address is on no network of this computer, whatever
        // network the test runs on.
        let _away = off_our_network();
        let lan = |at: &str| {
            format!(
                "lan_dial {at}: ipc LAN_DIAL: lan connect: cannot connect to {at} ({at}: no \
                 answer within 5.0s)"
            )
        };
        let p2p = |why: &str| format!("p2p_dial /p2p/12D3KooWx: {P2P_RAW}; reach: why={why}");
        let raw = format!(
            "{}; {}; {}; mid=1fb52189…",
            lan("192.168.0.31:17420"),
            lan("192.168.0.30:17420"),
            p2p("direct_failed me=public")
        );
        let ctx = SendCtx {
            name: "win-c".into(),
            dial: "192.168.0.31:17420".into(),
            ..bob()
        };
        let said = "win-c did not answer at 192.168.0.31:17420 or 192.168.0.30:17420: their \
                    computer may be off or asleep, on another network, or have a new IP address";
        let queued = queued_text(&ctx, &raw, "\"hi\"", &background());
        assert!(
            queued.contains(&format!("is queued locally because {said}.")),
            "{queued}"
        );
        let not_sent = not_sent_text(&ctx, &raw, false);
        assert!(
            not_sent.starts_with(&format!("NOT SENT: {said}.")),
            "{not_sent}"
        );
        for text in [&queued, &not_sent] {
            let sentence = text.split("(technical:").next().unwrap();
            assert!(!sentence.contains("internet address"), "{text}");
            assert!(sentence.contains("Check that you are on the same network as win-c"));
        }
        // Another reason says more than the LAN routes: it still explains.
        let offline = format!(
            "{}; {}",
            lan("192.168.0.31:17420"),
            p2p("contact_offline me=relayed")
        );
        assert!(not_sent_text(&ctx, &offline, false).starts_with("NOT SENT: win-c is offline"));
        // The p2p dial alone: its own words.
        let alone = format!("{P2P_RAW}; reach: why=direct_failed me=public");
        assert!(
            not_sent_text(&ctx, &alone, false).contains("did not answer at the internet address")
        );
    }

    /// Three-machine test 2026-10-25: macOS refused one Mac's raven-node
    /// every LAN connection ("No route to host (os error 65)", its Local
    /// Network permission) while both contacts were up. The CLI said "did not
    /// answer at 192.168.0.25:17420: their computer may be off" and, with the
    /// internet route after it, "did not answer at the internet address":
    /// this computer's refusal is said as such, with the permission and the
    /// restart, whatever the other routes found.
    #[test]
    fn a_macos_local_network_refusal_is_this_computers_not_the_contacts() {
        let lan = "ipc LAN_DIAL: lan connect: cannot connect to 192.168.0.25:17420 \
                   (192.168.0.25:17420: No route to host (os error 65)); mid=1fb52189…";
        let joined = format!(
            "lan_dial 192.168.0.16:17420: {lan}; p2p_dial /p2p/12D3KooWx: {P2P_RAW}; reach: \
             why=direct_failed me=public"
        );
        let ctx = bob();
        for raw in [lan, joined.as_str()] {
            assert_eq!(classify_cause(raw), Cause::LocalNetworkRefused, "{raw}");
            for text in [
                not_sent_text(&ctx, raw, true),
                queued_text(&ctx, raw, "\"hi\"", &background()),
            ] {
                assert!(
                    text.contains(
                        "this Mac did not let RAVEN connect to Bob at 192.168.0.16:7420: macOS \
                         itself answered \"No route to host\""
                    ),
                    "{text}"
                );
                assert!(
                    text.contains("Privacy & Security > Local Network, turn on the app that"),
                    "{text}"
                );
                assert!(text.contains("then restart raven-node"), "{text}");
                for wrong in ["may be off", "internet address", "same network as Bob"] {
                    assert!(!text.contains(wrong), "{wrong:?} in: {text}");
                }
            }
        }
        // A public address's "no route", and Linux's number, stay what they were.
        let public = "internet connect: cannot connect to 203.0.113.7:7422 (203.0.113.7:7422: \
                      No route to host (os error 65))";
        assert_eq!(classify_cause(public), Cause::NotReachable);
        let linux = lan.replace("os error 65", "os error 113");
        assert_eq!(classify_cause(&linux), Cause::NotReachable);
    }

    /// With no route to the internet a failed LAN route says more than the
    /// p2p reason: its own sentence, marked; a computer with a route keeps
    /// the p2p reason (above), and a LAN refusal is no LAN result.
    #[test]
    fn with_no_route_a_lan_result_wins_over_any_p2p_reason() {
        // Their LAN address is on no network of this computer, whatever
        // network the test runs on.
        let _away = off_our_network();
        let lan = |e: &str| {
            format!(
                "lan_dial 192.168.0.16:7420: ipc LAN_DIAL: lan connect: cannot connect to \
                 192.168.0.16:7420 (192.168.0.16:7420: {e}); p2p_dial /p2p/12D3KooWx: {P2P_RAW}; \
                 reach: why=no_route me=unknown"
            )
        };
        let ctx = nobody_known();
        let text = not_sent_text(&ctx, &lan("no answer within 5.0s"), false);
        assert!(
            text.starts_with(
                "NOT SENT: Bob did not answer at 192.168.0.16:7420: their computer may be off or \
                 asleep, on another network, or have a new IP address (this computer has no \
                 route to the internet)."
            ),
            "{text}"
        );
        assert!(
            text.contains("Check that you are on the same network as Bob."),
            "{text}"
        );
        let text = not_sent_text(&ctx, &lan("Connection refused (os error 61)"), false);
        assert!(
            text.starts_with(
                "NOT SENT: Bob's computer is there, but Raven isn't receiving right now (it may \
                 be locked or closed) (this computer has no route to the internet)."
            ),
            "{text}"
        );
        let queued = queued_text(&ctx, &lan("early eof"), "", &background());
        assert!(
            queued.contains("but stopped talking or hung up")
                && queued.contains("(this computer has no route to the internet)."),
            "{queued}"
        );
        assert!(queued.contains("Do not retype this message"), "{queued}");
        for text in [&text, &queued] {
            assert_no_internet_side_fix(text.split("(technical:").next().unwrap());
        }
        // The LAN route last, or a refusal on it: the p2p reason stays.
        let p2p_first = format!(
            "p2p_dial /p2p/12D3KooWx: {P2P_RAW}; reach: why=no_route; lan_dial 192.168.0.16:7420: \
             ipc LAN_DIAL: lan connect: cannot connect to 192.168.0.16:7420 (no answer within \
             5.0s)"
        );
        // (the block is not the last text: no reason at all, today's words)
        assert!(Diag::find(&p2p_first).is_some());
        let refused = format!(
            "lan_dial 192.168.0.16:7420: ipc LAN_DIAL: LAN_DIAL_PEER_CLOSED: the peer closed the \
             connection without replying; p2p_dial /p2p/x: {P2P_RAW}; reach: why=no_route"
        );
        assert!(lan_route_failure(&refused).is_none());
        // Without "no route" the LAN part is not consulted.
        let with_route = lan("no answer within 5.0s").replace("why=no_route", "why=both_nat");
        let text = not_sent_text(&ctx, &with_route, false);
        assert!(
            text.starts_with("NOT SENT: you and Bob are both behind NAT"),
            "{text}"
        );
    }

    /// The peer's acknowledgement came back but this computer could not record it:
    /// the message was delivered, so it is neither "NOT SENT" nor "nothing queued".
    #[test]
    fn an_acknowledged_message_that_could_not_be_recorded_is_never_called_not_sent() {
        let raw = "chat history I/O failed: history lock: still held by another raven process after 10s (database is locked)";
        let text = recorded_locally_failed_text(&bob(), raw, "\"hello\"", &next_send());
        assert!(text.starts_with(UNCONFIRMED_PREFIX), "{text}");
        assert!(
            !text.contains("NOT SENT") && !text.contains("Nothing was queued"),
            "{text}"
        );
        assert!(text.contains("reached Bob's computer"), "{text}");
        assert!(text.contains("Do not retype it"), "{text}");
        assert!(
            text.contains("another RAVEN program on this computer is holding your chat history"),
            "{text}"
        );
        assert!(text.ends_with(&format!("(technical: {raw})")), "{text}");
        assert_eq!(
            translate_known(&text, &bob()),
            None,
            "an outcome line passes through unchanged"
        );
        let other = recorded_locally_failed_text(&bob(), "disk full", "", &background());
        assert!(
            other.contains("raven-node, in the background, finishes"),
            "{other}"
        );
        assert!(
            other.contains("this computer could not finish recording it"),
            "{other}"
        );
    }

    #[test]
    fn a_first_message_that_cannot_wait_says_so() {
        let refused =
            "ipc LAN_DIAL: LAN_DIAL_PEER_CLOSED: the peer closed the connection without replying";
        let text = not_sent_for(Cause::PeerRefused, &bob(), refused, true);
        assert!(
            text.contains("Bob did not accept your first message"),
            "{text}"
        );
        assert!(
            text.contains("has not added you as a contact yet"),
            "{text}"
        );
        assert!(text.contains("ask them to add you"), "{text}");
        let sentence = text.split("(technical:").next().unwrap();
        assert!(!sentence.contains("retry is safe"), "{text}");
        let down = "ipc LAN_DIAL: lan connect: cannot connect to 192.168.0.16:7420 (192.168.0.16:7420: Connection refused (os error 61))";
        let text = not_sent_text(&bob(), down, true);
        assert!(
            text.contains(
                "It was not kept: a first message needs you and Bob both online (RAVEN hasn't \
                 connected with Bob yet). Ask Bob to open Raven, then send again."
            ),
            "{text}"
        );
        let later = not_sent_text(&bob(), down, false);
        assert!(!later.contains("first message"), "{later}");
    }

    /// Cutoff pack CP.6: the deadline on this computer's clock, with how
    /// long is left; only how long is left when the offset is unknown.
    #[test]
    fn the_expiry_is_a_local_clock_time_and_how_long_is_left() {
        const MIN: u64 = 60_000;
        const HOUR: u64 = 60 * MIN;
        // 2026-10-20 (a Tuesday) 10:35:00 UTC.
        let at = 1_792_492_500_000;
        let tehran = |now: u64| until_text_with_offset(at, now, Some(12_600));
        // E2 r38: with this computer's zone.
        assert_eq!(
            tehran(at - 30_000),
            "today 14:05 (UTC+3:30, in less than a minute)"
        );
        assert_eq!(
            tehran(at - 45 * MIN),
            "today 14:05 (UTC+3:30, in about 45 min)"
        );
        assert_eq!(
            tehran(at - 3 * HOUR),
            "today 14:05 (UTC+3:30, in about 3 h)"
        );
        assert_eq!(
            tehran(at - 19 * HOUR),
            "tomorrow 14:05 (UTC+3:30, in about 19 h)"
        );
        assert_eq!(
            tehran(at - 50 * HOUR),
            "Tue 14:05 (UTC+3:30, in about 2 days)"
        );
        assert_eq!(tehran(at - 6 * 24 * HOUR), "Tue 20 Oct 14:05 (UTC+3:30)");
        assert_eq!(
            tehran(at + 5_000),
            "today 14:05 (UTC+3:30, in less than a minute)"
        );
        // New York (UTC-5): 05:35, seen the evening before.
        assert_eq!(
            until_text_with_offset(at, at - 9 * HOUR, Some(-18_000)),
            "tomorrow 05:35 (UTC-5, in about 9 h)"
        );
        assert_eq!(
            until_text_with_offset(at, at - (23 * 60 + 40) * MIN, Some(0)),
            "tomorrow 10:35 (UTC, in about 24 h)"
        );
        // No offset: how long is left, nothing else.
        assert_eq!(
            until_text_with_offset(at, at - 22 * HOUR, None),
            "in about 22 h"
        );
        assert!(until_text(at, 0).is_ascii());
    }

    /// A time is always this computer's own clock time, named by this
    /// computer's own zone (E2 r38: a zone with every time); never a time on
    /// another clock (CP.6: "UTC" alone invited a wrong meeting time), and
    /// without the offset only how long.
    #[test]
    fn until_text_names_this_computers_own_zone_only() {
        const HOUR: u64 = 3_600_000;
        let at = 1_792_492_500_000;
        for (off, zone) in [
            (Some(12_600), Some("(UTC+3:30")),
            (Some(-18_000), Some("(UTC-5")),
            (Some(0), Some("(UTC")),
            (None, None),
        ] {
            for left in [0, 30_000, HOUR, 22 * HOUR, 9 * 24 * HOUR] {
                let text = until_text_with_offset(at, at - left, off);
                match zone {
                    Some(zone) => assert!(text.contains(zone), "{off:?} {left}: {text}"),
                    None => assert!(!text.contains("UTC"), "{off:?} {left}: {text}"),
                }
                assert!(text.is_ascii(), "{text}");
            }
        }
        // And on this machine's own clock: its own zone.
        let here = zone_label(raven_core::local_time::utc_offset_s(at));
        if let Some(here) = here {
            assert!(until_text(at, at - HOUR).contains(&format!("({here}")));
            assert!(ended_text(at, at + HOUR).contains(&format!("({here})")));
        }
    }

    /// Phase 5 P5.16: a letter a friend holds reads "With {custodian} for
    /// {who} · until {until}" (one row per friend), and its details say what
    /// that friend learns; a REPLY, a letter being withdrawn and one nobody
    /// holds show nothing.
    #[test]
    fn letter_rows_name_the_friend_the_contact_and_until_when() {
        use raven_core::letter_deposits::{update, DepositKind, LetterDeposit};
        let dir = tempfile::tempdir().unwrap();
        let (bob, carol, dan) = (
            Identity::from_seed(&[71; 32]),
            Identity::from_seed(&[72; 32]),
            Identity::from_seed(&[73; 32]),
        );
        let entry = |name: &str, id: &Identity| {
            serde_json::json!({
                "petname": name, "public_tag": "", "alias": "", "address": id.address(),
                "pub_hex": hex::encode(id.public_key_bytes()), "pinned": true, "lan_dial": "",
            })
        };
        let book = serde_json::json!([
            entry("Bob", &bob),
            entry("Carol", &carol),
            entry("Dan", &dan)
        ]);
        std::fs::write(dir.path().join("contacts.json"), book.to_string()).unwrap();
        let now = now_ms();
        let until = now + 6 * 24 * 3_600_000;
        let row = |kind: DepositKind, n: u8| {
            LetterDeposit::new(
                kind,
                bob.public_key_bytes(),
                [n; 32],
                vec![n; 600],
                now,
                until,
                vec![[n; 16]],
                Vec::new(),
            )
        };
        let mid = [1u8; 16];
        update(dir.path(), now, |book| {
            let mut held = row(DepositKind::Letter, 1);
            held.held_by = vec![carol.public_key_bytes(), dan.public_key_bytes()];
            let mut reply = row(DepositKind::Reply, 2);
            reply.held_by = vec![carol.public_key_bytes()];
            let mut gone = row(DepositKind::Letter, 3);
            gone.held_by = vec![carol.public_key_bytes()];
            gone.withdraw = true;
            book.letters = vec![held, reply, gone, row(DepositKind::Letter, 4)];
        })
        .unwrap();
        let when = until_text(until, now);
        assert_eq!(
            letters_left_rows(dir.path(), now),
            vec![
                format!("With Carol for Bob · until {when}"),
                format!("With Dan for Bob · until {when}"),
            ]
        );
        let peer_hex = hex::encode(bob.public_key_bytes());
        assert_eq!(
            letter_detail_rows(dir.path(), &peer_hex, &mid, now),
            vec![
                format!("  letter      With Carol for Bob · until {when}"),
                format!("  letter      With Dan for Bob · until {when}"),
                "  letter      Carol and Dan can't read it, but each knows you wrote to Bob, \
                 and when; the letter is signed by you."
                    .to_string(),
            ]
        );
        assert!(letter_detail_rows(dir.path(), &peer_hex, &[3; 16], now).is_empty());
        assert!(letter_detail_rows(dir.path(), &peer_hex, &[4; 16], now).is_empty());
        assert_eq!(
            letter_knows_text(&["Carol".to_string()], "Bob"),
            "Carol can't read it, but knows you wrote to Bob, and when; the letter is signed by \
             you."
        );
        // A book that cannot be read, or none: nothing.
        let empty = tempfile::tempdir().unwrap();
        assert!(letters_left_rows(empty.path(), now).is_empty());
    }

    #[test]
    fn a_past_end_reads_on_the_local_clock_or_as_how_long_ago() {
        const HOUR: u64 = 3_600_000;
        let at = 1_792_492_500_000;
        let tehran = |now: u64| ended_text_with_offset(at, now, Some(12_600));
        assert_eq!(tehran(at + HOUR), "today at 14:05 (UTC+3:30)");
        assert_eq!(tehran(at + 20 * HOUR), "yesterday at 14:05 (UTC+3:30)");
        assert_eq!(tehran(at + 3 * 24 * HOUR), "on Tue at 14:05 (UTC+3:30)");
        assert_eq!(
            tehran(at + 9 * 24 * HOUR),
            "on Tue 20 Oct at 14:05 (UTC+3:30)"
        );
        assert_eq!(
            ended_text_with_offset(at, at + 25 * HOUR, None),
            "about 25 h ago"
        );
    }

    /// Privacy pack PP.9: the day of the first retention deletion, on the
    /// local clock (never UTC), or how long until it.
    #[test]
    fn a_planned_day_reads_on_the_local_clock_or_as_how_long_until() {
        const HOUR: u64 = 3_600_000;
        let at = 1_792_492_500_000;
        let week = 7 * 24 * HOUR;
        assert_eq!(
            on_day_text_with_offset(at, at - week, Some(12_600)),
            "on Tue 20 Oct"
        );
        assert_eq!(
            on_day_text_with_offset(at, at, Some(12_600)),
            "on Tue 20 Oct"
        );
        assert_eq!(
            on_day_text_with_offset(at, at - week, None),
            "in about 7 days"
        );
        assert!(!on_day_text(at, at - HOUR).contains("UTC"));
    }

    /// The queued text keeps what the chat, the terminal app and the
    /// carrier matrix (C4) parse: the prefix and the retry words, verbatim.
    #[test]
    fn queued_text_keeps_the_prefix_and_retry_words() {
        let ctx = bob();
        let raw = "ipc LAN_DIAL: lan read timeout; mid=01020304…";
        let kept = queued_text(&ctx, raw, "\"hi\"", &background());
        assert!(kept.starts_with(QUEUED_PREFIX), "{kept}");
        assert!(
            kept.contains("raven-node keeps trying in the background until"),
            "{kept}"
        );
        assert!(kept.contains(BACKGROUND_RETRY), "{kept}");
        let words = "and sends it by itself when you are both on the same network (`raven outbox \
                     list` shows it); after that it is not sent, and `raven outbox list` says so.";
        assert!(kept.contains(words), "{words:?} missing from: {kept}");
        assert!(!kept.contains("you do not need to stay online"), "{kept}");
    }

    /// P5.8, the long message horizon: a message parked for a contact
    /// without a session keeps the prefix and the retry words the chat and
    /// the terminal app parse, and says what happens next and until when.
    #[test]
    fn parked_text_keeps_the_prefix_and_names_the_deadline() {
        let ctx = bob();
        let raw = "ipc LAN_DIAL: lan connect: connection refused; HORIZON_PARKED; mid=01020304…";
        let kept = parked_text(&ctx, raw, "\"hi\"", &background());
        assert!(kept.starts_with(QUEUED_PREFIX), "{kept}");
        assert!(kept.contains(BACKGROUND_RETRY), "{kept}");
        let until = until_text(background().expires_at_ms, now_ms());
        let words = format!(
            "your message \"hi\" to Bob is queued: Bob isn't reachable now. When you are both on \
             the same network, RAVEN first sets up a new secure connection, then sends it. It can \
             wait until {until}."
        );
        assert!(kept.contains(&words), "{words:?} missing from: {kept}");
        assert!(kept.contains("Do not retype this message."), "{kept}");
        assert!(kept.ends_with(&format!("(technical: {raw})")), "{kept}");
        let alone = parked_text(
            &ctx,
            raw,
            "",
            &RetryNote {
                background: false,
                ..background()
            },
        );
        assert!(alone.starts_with(QUEUED_PREFIX), "{alone}");
        assert!(!alone.contains(BACKGROUND_RETRY), "{alone}");
        assert!(alone.contains("NOT retried automatically"), "{alone}");
        // The chat's marker for each.
        let marker = |line: &str| {
            let (_, err) = chat_echo("hi", &Err(line.to_string()), "Bob");
            assert_eq!(err.as_deref(), Some(line));
            chat_echo("hi", &Err(line.to_string()), "Bob").0
        };
        assert!(marker(&kept).contains("[queued: raven-node keeps trying]"));
        assert!(marker(&alone).contains("[queued: goes out with your next message]"));
    }

    /// P5.8: `raven contact list` while the horizon is live, by the rule the
    /// terminal app and the desktop apps share (E1: "until tomorrow" in one,
    /// "up to 7 days" in the other): a message written now waits 7 days,
    /// whatever the session store says; with the horizon off, the store's
    /// answer (here: no secure connection yet).
    #[test]
    fn contact_list_line_with_the_horizon() {
        use raven_core::outbox::QueueReach;
        assert_eq!(
            horizon_reach_words("Bob", "Thu 29 Oct 14:05"),
            "If Bob is away, Raven keeps trying for up to 7 days (until Thu 29 Oct 14:05)."
        );
        let dir = tempfile::tempdir().unwrap();
        let (peer, now) = ([0x42u8; 32], 1_792_492_500_000);
        let deadline = now + raven_core::horizon::MESSAGE_HORIZON_MS;
        raven_core::horizon::set_lab_horizon_for_this_thread(Some(true));
        let reach = away_reach(dir.path(), &peer, now);
        let line = reach.clone().map(|r| away_line("Bob", r, now));
        raven_core::horizon::set_lab_horizon_for_this_thread(Some(false));
        let off = away_reach(dir.path(), &peer, now);
        raven_core::horizon::set_lab_horizon_for_this_thread(None);
        assert_eq!(reach, Ok(QueueReach::CanWait { until_ms: deadline }));
        let line = line.unwrap();
        assert!(
            line.ends_with(&format!("(until {}).", until_text(deadline, now))),
            "{line}"
        );
        assert!(!dir
            .path()
            .join(raven_core::indexed_session_store::INDEXED_SESSION_METADATA_FILE)
            .exists());
        assert_eq!(off, Ok(QueueReach::NeverPaired));
    }

    /// E1 (one wait everywhere): with the horizon live, a queued, sent or held
    /// message of yours waits until 7 days after it was written, the
    /// deadline the outbox parks it for, not its envelope's day; a parked
    /// row, a copy friends hold, an ACK and a finished row keep what
    /// raven-node said, and so does everything while the horizon is off.
    #[test]
    fn a_waiting_message_waits_until_the_deadline_the_outbox_applies() {
        let written = 1_792_492_500_000;
        let envelope = written + 21 * 3_600_000;
        let deadline = raven_core::horizon::message_deadline(written);
        let item = |kind: &str, state: &str, in_custody: u8| raven_core::ipc::OutboxItem {
            kind: kind.into(),
            state: state.into(),
            in_custody,
            expires_at_ms: envelope,
            ..Default::default()
        };
        raven_core::horizon::set_lab_horizon_for_this_thread(Some(true));
        let live: Vec<u64> = ["queued", "sent", "held"]
            .iter()
            .map(|state| waits_until(&item("message", state, 0), Some(written)))
            .collect();
        let kept = [
            waits_until(&item("message", "waiting", 0), Some(written)),
            waits_until(&item("message", "queued", 1), Some(written)),
            waits_until(&item("ack", "queued", 0), Some(written)),
            waits_until(&item("message", "delivered", 0), Some(written)),
            waits_until(&item("message", "queued", 0), None),
        ];
        raven_core::horizon::set_lab_horizon_for_this_thread(Some(false));
        let off = waits_until(&item("message", "queued", 0), Some(written));
        raven_core::horizon::set_lab_horizon_for_this_thread(None);
        assert_eq!(live, [deadline; 3]);
        assert_eq!(kept, [envelope; 5]);
        assert_eq!(off, envelope);
    }

    /// P5.8: without raven-node, `raven outbox list` reads the store, and a
    /// parked message is listed `waiting` until its deadline (horizon on);
    /// the status line counts it.
    #[test]
    fn outbox_list_shows_waiting_from_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let peer = [0x42u8; 32];
        let (mid, now) = ([0x5au8; 16], now_ms());
        let deadline = raven_core::horizon::message_deadline(now);
        assert!(raven_core::IndexedSessionStore::open(dir.path())
            .unwrap()
            .park_outbound(&peer, &mid, None, now, deadline, now)
            .unwrap());
        raven_core::horizon::set_lab_horizon_for_this_thread(Some(false));
        let (running, items) = outbox_items(dir.path(), None, now).unwrap();
        assert!(!running);
        assert!(items.is_empty(), "{items:?}");
        raven_core::horizon::set_lab_horizon_for_this_thread(Some(true));
        let (_, items) = outbox_items(dir.path(), Some(&hex::encode(peer)), now).unwrap();
        raven_core::horizon::set_lab_horizon_for_this_thread(None);
        assert_eq!(items.len(), 1, "{items:?}");
        let item = &items[0];
        assert_eq!(item.state, "waiting");
        assert_eq!(item.kind, "message");
        assert_eq!(item.message_id_hex, hex::encode(mid));
        assert_eq!(item.expires_at_ms, deadline);
        let line = plain(&outbox_row_line(dir.path(), item, now));
        assert!(line.contains("waiting · until"), "{line}");
        assert_eq!(
            waiting_words(&items, now, |_| "<deadline>".into()).as_deref(),
            Some("Waiting messages: 1 (the oldest can wait until <deadline>).")
        );
    }

    /// Cutoff pack CP.7: the clock words, one line each.
    #[test]
    fn clock_words_one_line_each() {
        for (minutes, span) in [
            (5, "5 min"),
            (10, "10 min"),
            (89, "89 min"),
            (90, "2 h"),
            (180, "3 h"),
            (47 * 60, "47 h"),
            (3 * 24 * 60, "3 days"),
            (-10, "10 min"),
        ] {
            assert_eq!(skew_span(minutes), span, "{minutes}");
        }
        assert_eq!(
            clock_row_text("Bob", 10, false),
            "Bob's clock is about 10 min ahead of yours: messages from Bob are refused until \
             the clocks agree. Check the time and time zone on both laptops."
        );
        // Phase 3 P3.C3 (F11b): the LAN beacon's estimate, either side.
        assert_eq!(
            clock_row_text("Bob", 10, true),
            "Bob's clock is about 10 min or more ahead of yours: messages from Bob are \
             refused until the clocks agree. Check the time and time zone on both laptops."
        );
        assert_eq!(
            clock_row_text("Bob", -10, true),
            "Bob's clock is about 10 min or more behind yours: Bob refuses your messages \
             until the clocks agree. Check the time and time zone on both laptops."
        );
        assert_eq!(
            clocks_differ_text("Bob", 10),
            "Bob's clock and yours differ by about 10 min, so RAVEN can't set up a secure \
             connection. Check the time and time zone on both laptops."
        );
        assert_eq!(
            SAME_TIME_HINT,
            "If this keeps happening while you are together, check that both laptops show the \
             same time."
        );
        for line in [
            clock_row_text("Bob", 300, false),
            clock_row_text("Bob", -3000, true),
            clocks_differ_text("Bob", 3000),
            SAME_TIME_HINT.into(),
        ] {
            assert!(!line.contains('\n') && line.is_ascii(), "{line}");
        }
    }

    /// Which send outcomes get a clock sentence (a refusal, or what nothing
    /// names), which one, and where it goes; raven-node is not even asked for
    /// an unreachable contact, a local problem or a gate text.
    #[test]
    fn clock_sentence_only_where_the_clock_may_explain_it() {
        let ctx = bob();
        let refused = queued_text(
            &ctx,
            "ipc LAN_DIAL: LAN_DIAL_PEER_CLOSED: the peer closed the connection without \
             replying; mid=01020304…",
            "\"hi\"",
            &background(),
        );
        let differ = clocks_differ_text("Bob", 10);
        assert_eq!(
            clock_sentence(&refused, "Bob", || Some((Some(10), 0))).as_deref(),
            Some(differ.as_str())
        );
        assert_eq!(clock_sentence(&refused, "Bob", || Some((None, 1))), None);
        assert_eq!(
            clock_sentence(&refused, "Bob", || Some((None, 2))).as_deref(),
            Some(SAME_TIME_HINT)
        );
        assert_eq!(clock_sentence(&refused, "Bob", || None), None);
        // No ACK came back: the same hint.
        let unconfirmed = unconfirmed_text(
            &ctx,
            "WAITING_FOR_ENDPOINT_ACK: no sealed ACK came back; mid=01020304…",
            "\"hi\"",
            &background(),
        );
        assert_eq!(
            clock_sentence(&unconfirmed, "Bob", || Some((None, 3))).as_deref(),
            Some(SAME_TIME_HINT)
        );
        // Review C-time-deadlines-6: a measured skew with only the ACK
        // missing says the confirmations are refused and that Bob may have
        // it, never that no secure connection could be set up.
        let acks = clock_sentence(&unconfirmed, "Bob", || Some((Some(10), 0))).unwrap();
        assert_eq!(acks, acks_refused_text("Bob", 10));
        assert_eq!(
            acks,
            "Bob's clock and yours differ by about 10 min, so Bob's confirmations are refused \
             here; Bob may have the message. Check the time and time zone on both laptops."
        );
        assert!(!acks.contains("can't set up"), "{acks}");
        assert!(!acks.contains('\n') && acks.is_ascii(), "{acks}");
        // s99's "Bob +10": Bob's ACK came back but was refused here as from
        // the future.
        let unrecorded = recorded_locally_failed_text(
            &ctx,
            "endpoint envelope or bound session is not currently valid",
            "\"hi\"",
            &background(),
        );
        assert!(unrecorded.starts_with(UNCONFIRMED_PREFIX), "{unrecorded}");
        assert_eq!(
            clock_sentence(&unrecorded, "Bob", || Some((Some(10), 0))),
            Some(acks_refused_text("Bob", 10))
        );
        assert_eq!(clock_sentence(&unrecorded, "Bob", || Some((None, 3))), None);
        // A refusal no sentence covers (an offer from the future): the
        // measured skew, never the hint.
        let other = not_sent_text(&ctx, "ipc LAN_DIAL: PREKEY_NOT_YET_VALID", true);
        assert_eq!(
            clock_sentence(&other, "Bob", || Some((Some(12), 5))).as_deref(),
            Some(clocks_differ_text("Bob", 12).as_str())
        );
        assert_eq!(clock_sentence(&other, "Bob", || Some((None, 5))), None);
        let never = || -> Option<(Option<i32>, u32)> { panic!("raven-node asked") };
        let unreachable = queued_text(
            &ctx,
            "ipc LAN_DIAL: lan connect: timed out; mid=01020304…",
            "\"hi\"",
            &background(),
        );
        assert_eq!(clock_sentence(&unreachable, "Bob", never), None);
        let local = not_sent_text(&ctx, "raven-node is not running", false);
        assert_eq!(clock_sentence(&local, "Bob", never), None);
        assert_eq!(
            clock_sentence(
                "INTERNET_DIRECT_HOLD: Internet direct is held",
                "Bob",
                never
            ),
            None
        );
        // Before the technical part, which stays last and whole.
        assert_eq!(
            technical_part(&refused),
            "ipc LAN_DIAL: LAN_DIAL_PEER_CLOSED: the peer closed the connection without \
             replying; mid=01020304…"
        );
        let told = before_technical(&refused, &differ);
        assert!(told.starts_with(QUEUED_PREFIX), "{told}");
        assert!(
            told.ends_with(&format!(
                "{differ} (technical: {})",
                technical_part(&refused)
            )),
            "{told}"
        );
        assert_eq!(before_technical("plain", "Then this."), "plain Then this.");
        // Without a profile or a key nothing is asked or added.
        let quiet = SendCtx {
            data_dir: None,
            ..bob()
        };
        assert_eq!(with_clock_words(refused.clone(), &quiet), refused);
    }

    /// The line under each contact in `raven contact list`.
    #[test]
    fn contact_list_lines_for_live_ended_and_never_paired() {
        use raven_core::outbox::QueueReach;
        const HOUR: u64 = 3_600_000;
        let at = 1_792_492_500_000;
        let now = at - 19 * HOUR;
        let line = |reach| {
            queue_reach_words(
                "Bob",
                reach,
                |t| until_text_with_offset(t, now, Some(12_600)),
                |t| ended_text_with_offset(t, now, Some(12_600)),
            )
        };
        assert_eq!(
            line(QueueReach::CanWait { until_ms: at }),
            "If Bob is away, Raven keeps trying until tomorrow 14:05 (UTC+3:30, in about 19 h)."
        );
        assert_eq!(
            line(QueueReach::Ended {
                at_ms: now - 2 * HOUR
            }),
            "To write to Bob, meet first: RAVEN can't hold new messages for Bob now (the secure \
             connection ended today at 17:05 (UTC+3:30))."
        );
        // E1: the rule a send's NOT SENT and the app say too.
        assert_eq!(
            line(QueueReach::NeverPaired),
            "A first message needs you and Bob both online (RAVEN hasn't connected with Bob \
             yet)."
        );
        assert_eq!(line(QueueReach::NeverPaired), first_message_rule("Bob"));
        // Without the local offset: how long, never a clock time.
        assert_eq!(
            queue_reach_line("Bob", QueueReach::Ended { at_ms: 0 }, 25 * HOUR),
            queue_reach_words(
                "Bob",
                QueueReach::Ended { at_ms: 0 },
                |_| unreachable!(),
                |t| { ended_text(t, 25 * HOUR) }
            )
        );
    }

    #[test]
    fn the_status_line_counts_waiting_messages_and_names_the_first_to_run_out() {
        use raven_core::ipc::OutboxItem;
        let item = |kind: &str, state: &str, expires_at_ms: u64| OutboxItem {
            kind: kind.into(),
            state: state.into(),
            expires_at_ms,
            ..OutboxItem::default()
        };
        let until = |at: u64| format!("<{at}>");
        assert_eq!(waiting_words(&[], 10, until), None);
        let finished = [item("message", "delivered", 9), item("ack", "queued", 1)];
        assert_eq!(waiting_words(&finished, 10, until), None);
        let items = [
            item("message", "queued", 300),
            item("message", "sent", 200),
            item("message", "held", 0),
            item("message", "expired", 100),
            item("ack", "queued", 50),
        ];
        assert_eq!(
            waiting_words(&items, 10, until).as_deref(),
            Some("Waiting messages: 3 (the oldest can wait until <200>).")
        );
        assert_eq!(
            waiting_words(&[item("message", "queued", 0)], 10, until).as_deref(),
            Some("Waiting messages: 1.")
        );
    }

    /// E1: "every message you sent was delivered or given up" left a user
    /// unsure which; the line counts each, and says "delivered" alone when
    /// nothing was given up. With nothing listed it claims neither (a first
    /// message that could not go was never kept).
    #[test]
    fn nothing_waiting_says_how_many_were_delivered_and_given_up() {
        assert_eq!(nothing_waiting_line(0, 0), "Nothing waiting to be sent.");
        assert_eq!(nothing_waiting_line(0, 0), NOTHING_WAITING);
        assert_eq!(
            nothing_waiting_line(6, 0),
            "Nothing waiting: every message you sent was delivered."
        );
        assert_eq!(
            nothing_waiting_line(0, 1),
            "Nothing waiting: 1 message given up (listed below)."
        );
        assert_eq!(
            nothing_waiting_line(3, 2),
            "Nothing waiting: 3 messages delivered, 2 messages given up (listed below)."
        );
        for (d, g) in [(0, 0), (4, 0), (1, 1)] {
            assert!(!nothing_waiting_line(d, g).contains("delivered or given up"));
        }
    }

    /// Review FU-1: after a restart past the deadline, when the prune settled
    /// a message before raven-node's worker saw it, nothing in raven-node
    /// lists it; `raven outbox list` still shows it from the history (once,
    /// newest first, for a week), as the queued text promises.
    #[test]
    fn a_message_that_ran_out_is_listed_from_the_history() {
        use raven_core::chat_history::ChatHistoryEntry;
        use raven_core::ipc::OutboxItem;
        const DAY: u64 = 86_400_000;
        let now = 1_792_492_500_000;
        let (bob, carol) = (hex::encode([0xBB; 32]), hex::encode([0xCC; 32]));
        let mid = |i: u8| hex::encode([i; 16]);
        let row = |i: u8, direction: &str, peer: &str, at: u64, delivery: &str| ChatHistoryEntry {
            message_id_hex: mid(i),
            direction: direction.into(),
            peer_petname: String::new(),
            peer_tag: String::new(),
            peer_pub_hex: peer.into(),
            created_at_ms: at,
            delivery: delivery.into(),
            preview: String::new(),
            body: String::new(),
            stored_at_ms: None,
            id_conflict: false,
        };
        let history = [
            row(1, "out", &bob, now - 2 * DAY, "expired"),
            row(2, "out", &carol, now - DAY, "expired"),
            row(3, "out", &bob, now - 8 * DAY, "expired"),
            row(4, "out", &bob, now - DAY, "delivered"),
            row(5, "in", &bob, now - DAY, "expired"),
            row(6, "out", &bob, now - DAY / 2, "expired"),
        ];
        // raven-node still lists the newest one (its worker finished it).
        let listed = [OutboxItem {
            message_id_hex: mid(6),
            kind: "message".into(),
            state: "expired".into(),
            ..OutboxItem::default()
        }];
        let got = ran_out_from_history(&history, &listed, None, now);
        let ids: Vec<&str> = got.iter().map(|i| i.message_id_hex.as_str()).collect();
        assert_eq!(ids, [mid(2), mid(1)], "newest first, once, a week back");
        assert!(got
            .iter()
            .all(|i| i.kind == "message" && i.state == "expired" && i.expires_at_ms == 0));
        assert_eq!(got[1].peer_pub_hex, bob);
        let bobs = ran_out_from_history(&history, &listed, Some(&bob.to_uppercase()), now);
        assert_eq!(bobs.len(), 1);
        assert_eq!(bobs[0].message_id_hex, mid(1));
        // Its line: expired, and no deadline made up for it.
        let dir = tempfile::tempdir().unwrap();
        let line = plain(&outbox_row_line(dir.path(), &got[0], now));
        assert!(line.contains(" expired "), "{line}");
        assert!(
            !line.contains("expires") && !line.contains("ran out"),
            "{line}"
        );
    }

    /// Review C-time-deadlines-4: a row still listed as waiting after its
    /// deadline (raven-node down or not caught up) is never named as the
    /// next to run out, and an expired row never reads as still to come.
    #[test]
    fn a_past_deadline_is_never_shown_as_still_to_come() {
        use raven_core::ipc::OutboxItem;
        const HOUR: u64 = 3_600_000;
        let now = 1_792_492_500_000;
        let item = |state: &str, expires_at_ms: u64| OutboxItem {
            kind: "message".into(),
            state: state.into(),
            expires_at_ms,
            ..OutboxItem::default()
        };
        let until = |at: u64| format!("<{at}>");
        let items = [item("queued", now - HOUR), item("sent", now + 2 * HOUR)];
        assert_eq!(
            waiting_words(&items, now, until),
            Some(format!(
                "Waiting messages: 1 (the oldest can wait until <{}>). 1 more ran out of time \
                 and will not be sent.",
                now + 2 * HOUR
            ))
        );
        assert_eq!(
            waiting_words(&[item("queued", now - HOUR)], now, until).as_deref(),
            Some("Waiting messages: none (1 ran out of time and will not be sent).")
        );
        // Review FU-4: a row a carrier wrote (only the confirmation is
        // missing) may have arrived: never "will not be sent".
        let sent = waiting_words(&[item("sent", now - HOUR)], now, until).unwrap();
        assert_eq!(
            sent,
            "Waiting messages: none (1 was sent but not confirmed in time and may have arrived)."
        );
        let mixed = [
            item("queued", now - HOUR),
            item("held", now - HOUR),
            item("sent", now - HOUR),
            item("sent", now - 2 * HOUR),
            item("queued", now + 2 * HOUR),
        ];
        assert_eq!(
            waiting_words(&mixed, now, until),
            Some(format!(
                "Waiting messages: 1 (the oldest can wait until <{}>). 2 more ran out of time \
                 and will not be sent; 2 more were sent but not confirmed in time and may have \
                 arrived.",
                now + 2 * HOUR
            ))
        );
        // `raven outbox list` and `raven outbox status`.
        let dir = tempfile::tempdir().unwrap();
        let mut expired = item("expired", now - 6 * HOUR);
        expired.message_id_hex = "0102030405060708".into();
        let line = plain(&outbox_row_line(dir.path(), &expired, now));
        assert!(line.contains("  ran out "), "{line}");
        assert!(
            line.ends_with(&ended_text_zoned(now - 6 * HOUR, now)),
            "{line}"
        );
        assert!(
            !line.contains("expires") && !line.contains("in less than a minute"),
            "{line}"
        );
        let mut late = item("queued", now - HOUR);
        late.message_id_hex = "0102030405060708".into();
        let line = plain(&outbox_row_line(dir.path(), &late, now));
        assert!(
            line.contains("  ran out ") && !line.contains("expires"),
            "{line}"
        );
        let mut live = item("sent", now + 3 * HOUR);
        live.message_id_hex = "0102030405060708".into();
        let line = plain(&outbox_row_line(dir.path(), &live, now));
        assert!(
            line.ends_with(&format!("  expires {}", until_text(now + 3 * HOUR, now))),
            "{line}"
        );
        for state in ["failed", "cancelled", "delivered", "gone"] {
            let mut done = item(state, now - HOUR);
            done.message_id_hex = "0102030405060708".into();
            let line = plain(&outbox_row_line(dir.path(), &done, now));
            assert!(
                !line.contains("expires") && !line.contains("ran out"),
                "{state}: {line}"
            );
        }
        let rows = outbox_status_rows(&expired, now);
        assert!(
            rows.contains(&format!(
                "  ran out     {}",
                ended_text_zoned(now - 6 * HOUR, now)
            )),
            "{rows:?}"
        );
        assert!(!rows.iter().any(|r| r.contains("expires")), "{rows:?}");
        let rows = outbox_status_rows(&live, now);
        assert!(
            rows.contains(&format!(
                "  expires     {}",
                until_text(now + 3 * HOUR, now)
            )),
            "{rows:?}"
        );
    }

    #[test]
    fn not_sent_after_the_secure_connection_ended_says_so() {
        let ctx = bob();
        let at = 1_792_492_500_000;
        let text = session_ended_sentence(&ctx, at, at + 25 * 3_600_000);
        assert!(
            text.starts_with("Nothing was queued: RAVEN's secure connection with Bob ended "),
            "{text}"
        );
        assert!(
            text.ends_with(
                " (each one lasts a day from when it is set up), and a new one needs you both on \
                 the same network at the same time. Send it when you meet."
            ),
            "{text}"
        );
        // A contact never paired (no profile here) gets the first-message
        // rule (E1), never a meeting.
        let down = "ipc LAN_DIAL: lan connect: cannot connect to 192.168.0.16:7420 \
                    (192.168.0.16:7420: no answer within 5.0s)";
        let first = not_sent_text(&ctx, down, true);
        assert!(
            first.contains(
                "It was not kept: a first message needs you and Bob both online (RAVEN hasn't \
                 connected with Bob yet). Send it again when Bob is online."
            ),
            "{first}"
        );
        assert!(
            !first.contains("ended") && !first.contains("meet"),
            "{first}"
        );
    }

    /// Phase 6 review re-verify (sensing-1): after an early security re-key
    /// on the contact's side (it set up a newer connection itself), no line
    /// says its RAVEN lost the connection or asks whether it was
    /// reinstalled: held messages say it replaced the connection and how to
    /// send them now; re-sent ones say nothing needs doing. A contact that
    /// lost the connection keeps the reset words.
    #[test]
    fn a_replaced_connection_is_not_called_lost_or_a_reinstall() {
        let ctx = bob();
        let held = ctx.reset_held_line("PEER_RESET_CONFIRM", 2, 0, ResetWhy::Replaced);
        assert!(
            held.starts_with(
                "2 earlier message(s) to Bob are on hold: Bob's RAVEN set up a new secure \
                 connection with you and no longer takes the older one they were sealed in, as \
                 it does after a security re-key or a restore."
            ),
            "{held}"
        );
        assert!(held.contains("raven outbox resend --contact Bob"), "{held}");
        assert!(held.contains("(technical: PEER_RESET_CONFIRM)"), "{held}");
        for line in [
            held.clone(),
            ctx.peer_reset_line(2, ResetWhy::Replaced),
            reseal_note_line("Bob", 2, "about 3 h ago", ResetWhy::Replaced),
        ] {
            assert!(!line.contains("lost your secure connection"), "{line}");
            assert!(!line.contains("reinstalled"), "{line}");
            assert!(!line.contains("was reset"), "{line}");
        }
        assert!(ctx.peer_reset_line(2, ResetWhy::Replaced).ends_with(
            "2 waiting message(s) were sent again under a new one; nothing needs doing."
        ));
        let chat = SendCtx {
            chat: true,
            ..bob()
        };
        assert_eq!(
            chat.peer_reset_line(1, ResetWhy::Replaced),
            "  (new secure connection with Bob: Bob's RAVEN replaced the old one; 1 waiting \
             message(s) re-sent)"
        );
        // Lost: as before.
        let lost = ctx.reset_held_line("PEER_RESET_CONFIRM", 2, 0, ResetWhy::Lost);
        assert!(
            lost.contains("Bob's RAVEN lost your secure connection"),
            "{lost}"
        );
        assert!(lost.contains("reinstalled or restored RAVEN"), "{lost}");
        assert!(ctx
            .peer_reset_line(2, ResetWhy::Lost)
            .contains("it was reinstalled or restored from a backup"));
        // The other held codes do not depend on it.
        for code in ["PEER_RESET_LOOP", "PEER_IDENTITY_FORK"] {
            assert_eq!(
                ctx.reset_held_line(code, 2, 3, ResetWhy::Replaced),
                ctx.reset_held_line(code, 2, 3, ResetWhy::Lost)
            );
        }
    }

    /// Review C-time-deadlines-7: the background re-seal note names the time
    /// on this computer's clock, or how long ago without its offset; never
    /// UTC.
    #[test]
    fn the_reseal_note_uses_this_computers_clock() {
        const HOUR: u64 = 3_600_000;
        // 2026-10-20 10:35 UTC: 14:05 in Tehran (UTC+3:30).
        let at = 1_792_492_500_000;
        let now = at + 3 * HOUR;
        let line = reseal_note_line(
            "Bob",
            2,
            &ended_text_with_offset(at, now, Some(12_600)),
            ResetWhy::Lost,
        );
        assert_eq!(
            line,
            "Note: 2 message(s) to Bob were sent again under a new secure connection today at \
             14:05 (UTC+3:30), after Bob's RAVEN was reinstalled or restored."
        );
        let line = reseal_note_line(
            "Bob",
            2,
            &ended_text_with_offset(at, now, None),
            ResetWhy::Lost,
        );
        assert!(line.contains("connection about 3 h ago, after"), "{line}");
        assert!(!line.contains("10:35"), "no time on another clock: {line}");
        assert!(
            !line.contains("UTC"),
            "no zone without a clock time: {line}"
        );
    }

    /// An expired message that never left this computer says so.
    #[test]
    fn time_ran_out_names_the_contact_and_that_it_never_left() {
        assert_eq!(
            time_ran_out_text("Bob"),
            "time ran out before Bob could be reached: it never left this computer (send it \
             again when you are together)"
        );
        assert_eq!(
            bob().earlier_failed_line("\"hi\"", &time_ran_out_text("Bob")),
            format!(
                "{C_BOLD}status{C_RESET} failed: your earlier message \"hi\" to Bob: time ran out \
                 before Bob could be reached: it never left this computer (send it again when you \
                 are together)"
            )
        );
    }

    #[test]
    fn queued_unconfirmed_and_earlier_texts_say_what_happened_to_the_text() {
        let ctx = bob();
        let raw = "ipc LAN_DIAL: lan read timeout; mid=01020304…";
        let queued = queued_text(&ctx, raw, "\"see you at 5\"", &next_send());
        for word in [
            "not delivered yet: your message \"see you at 5\" to Bob is queued locally because",
            "NOT retried automatically",
            "in about 24 h)",
            "after that it expires",
            "(technical: ipc LAN_DIAL: lan read timeout; mid=01020304…)",
        ] {
            assert!(queued.contains(word), "{word:?} missing from: {queued}");
        }
        // With raven-node's outbox: the background promise, not "NOT retried".
        let kept = queued_text(&ctx, raw, "\"see you at 5\"", &background());
        for word in [
            "not delivered yet: your message \"see you at 5\" to Bob is queued locally because",
            "Queued: raven-node keeps trying in the background until ",
            "in about 24 h)",
            "Do not retype this message.",
            "raven outbox list",
        ] {
            assert!(kept.contains(word), "{word:?} missing from: {kept}");
        }
        assert!(!kept.contains("NOT retried"), "{kept}");
        let sentence = kept.split("(technical:").next().unwrap();
        assert!(
            sentence.is_ascii(),
            "plain ASCII for any console: {sentence}"
        );
        let unconfirmed = unconfirmed_text(
            &ctx,
            "WAITING_FOR_ENDPOINT_ACK: no sealed ACK came back; mid=01020304…",
            "\"hi\"",
            &next_send(),
        );
        for word in [
            "sent, delivery unconfirmed: your message \"hi\" was sent to Bob's computer",
            "Bob has not confirmed it yet",
            "Do not retype it",
            "your next send to Bob tries again, until ",
        ] {
            assert!(
                unconfirmed.contains(word),
                "{word:?} missing from: {unconfirmed}"
            );
        }
        let unconfirmed = unconfirmed_text(&ctx, "no sealed ACK", "\"hi\"", &background());
        assert!(
            unconfirmed.contains("raven-node keeps trying in the background until Bob confirms it"),
            "{unconfirmed}"
        );
        let earlier = earlier_undelivered_text(&ctx, raw, "\"see you at 5\"", &next_send());
        for word in [
            "NOT SENT: an earlier message \"see you at 5\" to Bob is still undelivered",
            "this message was not queued behind it",
            "send this message again",
            "the earlier one goes first (until ",
        ] {
            assert!(earlier.contains(word), "{word:?} missing from: {earlier}");
        }
        let earlier_kept = earlier_undelivered_text(&ctx, raw, "\"see you at 5\"", &background());
        assert!(
            earlier_kept.contains("raven-node keeps trying the earlier one in the background"),
            "{earlier_kept}"
        );
        let awaiting = earlier_unconfirmed_text(&ctx, "");
        assert!(
            awaiting.starts_with("NOT SENT: an earlier message to Bob was sent again"),
            "{awaiting}"
        );
        assert!(
            awaiting.contains("this message was not queued"),
            "{awaiting}"
        );
        // Only a verified ACK may say "delivered" (and it says it elsewhere).
        for text in [&queued, &unconfirmed, &earlier, &awaiting] {
            assert!(!text.contains("status delivered"), "{text}");
        }
    }

    #[test]
    fn outcome_texts_pass_through_and_unknown_text_keeps_the_old_refusal_form() {
        let ctx = bob();
        let outcomes = [
            queued_text(&ctx, "ipc LAN_DIAL: lan read timeout", "", &next_send()),
            queued_text(&ctx, "ipc LAN_DIAL: lan read timeout", "", &background()),
            unconfirmed_text(&ctx, "no sealed ACK", "", &next_send()),
            unconfirmed_text(&ctx, "no sealed ACK", "", &background()),
            earlier_undelivered_text(&ctx, "ipc LAN_DIAL: early eof", "", &next_send()),
            earlier_unconfirmed_text(&ctx, ""),
            not_sent_text(&ctx, "ipc LAN_DIAL: early eof", false),
            "NOT SENT, nothing queued: another `ash send` to this peer from this profile was still running after 120s; try again shortly".to_string(),
            "send refused: x".to_string(),
        ];
        for text in &outcomes {
            assert_eq!(&friendly_send_error(text, "Bob"), text, "idempotent");
            assert_eq!(translate_known(text, &ctx), None);
        }
        // Gate texts and codes no sentence covers reach callers untouched (a unit
        // test and scripts match their exact words), and print as before.
        for gate in [
            super::super::pair_init_lab::INTERNET_DIRECT_HOLD,
            "ATSAM_SESSION_REQUIRED: the peer's certificate is not the one bound into the confirmed session (renewed or re-certified); nothing was sent",
            "ATSAM_LINEAGE_REVOKED: peer device lineage is revoked; nothing was sent",
            "REFUSE: serverless path must never silently use FastAPI for message delivery",
            "pub_hex must be 64 hex characters",
            "block list corrupt: refusing to continue",
        ] {
            assert_eq!(classify_cause(gate), Cause::Other, "{gate}");
            assert_eq!(translate_known(gate, &ctx), None, "{gate}");
            assert_eq!(friendly_send_error(gate, "Bob"), format!("send refused: {gate}"));
        }
    }

    #[test]
    fn the_person_is_named_never_a_key_and_hostile_names_are_neutralised() {
        let raw = "ipc LAN_DIAL: lan connect: cannot connect to 10.0.0.5:7420 (10.0.0.5:7420: Connection refused (os error 61))";
        let named = friendly_send_error(raw, "Bob");
        assert!(named.contains("Bob's computer is there"), "{named}");
        // The daemon's text stays, without the address.
        assert!(
            !named.contains("10.0.0.5") && named.contains("cannot connect to <local address>"),
            "the daemon's own text, without the address: {named}"
        );
        assert!(named.contains("Ask Bob to open Raven"), "{named}");
        let anonymous = friendly_send_error(raw, "");
        assert!(
            anonymous.contains("the other person's computer is there"),
            "{anonymous}"
        );
        // The address fix names the person as the shell reads it (a dial
        // that got no answer: the address may be old).
        let raw = "ipc LAN_DIAL: lan connect: cannot connect to 10.0.0.5:7420 (10.0.0.5:7420: no answer within 5.0s)";
        let anonymous = friendly_send_error(raw, "");
        assert!(anonymous.contains("--petname NAME"), "{anonymous}");
        assert!(friendly_send_error(raw, "@bob").contains("--tag bob"));
        // Quoted for this platform's shell: PowerShell's single quotes on
        // Windows (no address is known here), double quotes elsewhere.
        let q = |name: &str| {
            if cfg!(windows) {
                format!("--petname '{name}'")
            } else {
                format!("--petname \"{name}\"")
            }
        };
        assert!(friendly_send_error(raw, "Offline Mobile").contains(&q("Offline Mobile")));
        assert!(friendly_send_error(raw, "علی رضا").contains(&q("علی رضا")));
        let hostile = friendly_send_error(raw, "Bob\u{1b}[2J\nsecond line");
        assert!(
            !hostile.contains('\u{1b}') && !hostile.contains('\n'),
            "{hostile:?}"
        );
        // No 64-hex key anywhere unless it is the block undo (which needs the key).
        assert!(!named
            .chars()
            .collect::<Vec<_>>()
            .windows(64)
            .any(|w| w.iter().all(char::is_ascii_hexdigit)));
    }

    #[test]
    fn shell_words_and_selectors_are_safe_to_paste() {
        assert_eq!(shell_word("Bob"), "Bob");
        assert_eq!(shell_word("Offline Mobile"), "\"Offline Mobile\"");
        assert_eq!(shell_word("a$b"), "'a$b'");
        assert_eq!(shell_word("it's"), "\"it's\"");
        assert_eq!(selector_for("Bob", ""), "--petname Bob");
        assert_eq!(selector_for("@bob", ""), "--tag bob");
        assert_eq!(selector_for("", "rvn1qabc"), "--address rvn1qabc");
        assert_eq!(selector_for("", ""), "");
    }

    /// On Windows (PowerShell by default, or cmd.exe) a hint never puts a
    /// name in the command that the shell would change: the contact's plain
    /// rvn1 address selects it instead, and with no address the name goes
    /// in PowerShell's verbatim single quotes, never in double quotes.
    #[test]
    fn windows_selectors_are_safe_in_powershell_and_cmd() {
        let address = "rvn1qexampleaddress0";
        let win = |name: &str, address: &str| selector_for_shell(name, address, true);
        assert_eq!(win("Bob", address), "--petname Bob");
        assert_eq!(win("@bob", address), "--tag bob");
        assert_eq!(win("", address), format!("--address {address}"));
        assert_eq!(win("", ""), "");
        for name in [
            "Offline Mobile",
            "it's",
            "a$b",
            "$HOME",
            "50%off",
            "%USERPROFILE%",
            "`whoami`",
            "a,b",
            "@@splat",
            "Robin (Office)",
            "\u{201c}quoted\u{201d}",
        ] {
            assert_eq!(win(name, address), format!("--address {address}"), "{name}");
            let quoted = win(name, "");
            assert!(
                !quoted.contains('"') && quoted.ends_with('\''),
                "{name}: {quoted}"
            );
        }
        assert_eq!(win("Offline Mobile", ""), "--petname 'Offline Mobile'");
        assert_eq!(win("it's", ""), "--petname 'it''s'");
        assert_eq!(win("@a,b", ""), "--tag 'a,b'");
        // The POSIX forms are unchanged.
        assert_eq!(
            selector_for_shell("Offline Mobile", address, false),
            "--petname \"Offline Mobile\""
        );
    }

    #[test]
    fn previews_show_the_users_own_words_cut_short_and_safe() {
        assert_eq!(quoted_preview("see you at 5"), "\"see you at 5\"");
        assert_eq!(quoted_preview("   \n "), "");
        let long = "x".repeat(45);
        assert_eq!(quoted_preview(&long), format!("\"{}…\"", "x".repeat(30)));
        // Persian text and its ZWNJ come through intact.
        let persian = "می\u{200c}خواهم کتاب\u{200c}ها رو ببینم";
        assert_eq!(quoted_preview(persian), format!("\"{persian}\""));
        let nasty = quoted_preview("a\u{1b}[31mb\nc");
        assert!(
            !nasty.contains('\u{1b}') && !nasty.contains('\n'),
            "{nasty:?}"
        );
    }

    #[test]
    fn the_contact_is_named_from_the_book_by_key() {
        let dir = tempfile::tempdir().unwrap();
        let (bob_id, carol_id, nobody) = (
            Identity::from_seed(&[0x41; 32]),
            Identity::from_seed(&[0x42; 32]),
            Identity::from_seed(&[0x43; 32]),
        );
        let hex_of = |id: &Identity| hex::encode(id.public_key_bytes());
        let row = |id: &Identity, petname: &str, tag: &str| {
            serde_json::json!({
                "petname": petname, "public_tag": tag, "alias": tag,
                "address": id.address(), "pub_hex": hex_of(id), "pinned": false, "lan_dial": ""
            })
        };
        std::fs::write(
            dir.path().join("contacts.json"),
            serde_json::to_vec(&vec![
                row(&bob_id, "Bob", "bob"),
                row(&carol_id, "", "carol"),
            ])
            .unwrap(),
        )
        .unwrap();

        let ctx = send_ctx(dir.path(), "", "", &hex_of(&bob_id).to_uppercase());
        assert_eq!(
            (ctx.name.as_str(), ctx.selector.as_str()),
            ("Bob", "--petname Bob")
        );
        assert_eq!(
            ctx.pub_hex,
            hex_of(&bob_id),
            "normalised for `contact unblock`"
        );
        let ctx = send_ctx(dir.path(), "", "", &hex_of(&carol_id));
        assert_eq!(
            (ctx.name.as_str(), ctx.selector.as_str()),
            ("@carol", "--tag carol")
        );
        // Not a contact: no name, and the hint selects by address.
        let ctx = send_ctx(dir.path(), "", "", &hex_of(&nobody));
        assert_eq!(ctx.name, "");
        assert_eq!(ctx.selector, format!("--address {}", nobody.address()));
        // What the caller already knows wins (the chat passes it).
        let ctx = send_ctx(dir.path(), "Zed", "", &hex_of(&bob_id));
        assert_eq!(ctx.name, "Zed");
        // An unreadable book or key is "unknown", never a panic.
        std::fs::write(dir.path().join("contacts.json"), b"{not json").unwrap();
        assert_eq!(send_ctx(dir.path(), "", "", &hex_of(&bob_id)).name, "");
        let ctx = send_ctx(dir.path(), "", "", "zz");
        assert_eq!(
            (
                ctx.name.as_str(),
                ctx.selector.as_str(),
                ctx.pub_hex.as_str()
            ),
            ("", "", "")
        );
    }

    /// Success is on stdout and says who confirmed it; `status delivered` stays
    /// the literal start (scripts and the iOS gate match it) and the technical
    /// line (message id, carrier) shows only on request or for the lab carrier.
    #[test]
    fn connection_set_up_says_first_time_only_without_an_earlier_one() {
        // The session store's memory decides first; the chat history is not
        // read then.
        assert!(talked_before(true, || panic!("history read")));
        assert!(talked_before(false, || true));
        assert!(!talked_before(false, || false));
        // A profile with no session store and no chat history: never talked.
        let dir = tempfile::tempdir().unwrap();
        let peer = [0x42; 32];
        let peer_hex = hex::encode(peer);
        assert!(!session_remembered(dir.path(), &peer));
        assert!(!dir
            .path()
            .join(raven_core::indexed_session_store::INDEXED_SESSION_METADATA_FILE)
            .exists());
        assert!(!history_with(dir.path(), &peer_hex));
        // A message with the contact in the chat history (the lab K_hist):
        // they talked before, whatever the store remembers.
        let lab = std::env::var("RAVEN_CHAT_HISTORY_BACKEND").is_ok_and(|v| v == "locked-file");
        if !(cfg!(debug_assertions) && lab) {
            eprintln!("skipped: needs a debug build and RAVEN_CHAT_HISTORY_BACKEND=locked-file");
            return;
        }
        raven_core::ChatHistory::append_persisted(
            dir.path(),
            raven_core::ChatHistoryEntry {
                message_id_hex: "11".repeat(16),
                direction: "in".into(),
                peer_petname: String::new(),
                peer_tag: String::new(),
                peer_pub_hex: peer_hex.to_uppercase(),
                created_at_ms: 1,
                delivery: "received".into(),
                preview: "hi".into(),
                body: "hi".into(),
                stored_at_ms: None,
                id_conflict: false,
            },
        )
        .unwrap();
        assert!(history_with(dir.path(), &peer_hex));
        assert!(!history_with(dir.path(), &hex::encode([0x43; 32])));
    }

    #[test]
    fn success_lines_name_the_person_and_keep_the_status_literal() {
        let ctx = bob();
        let line = plain(&ctx.delivered_line().unwrap());
        assert_eq!(line, "status delivered — Bob confirmed receipt");
        assert!(line.starts_with("status delivered"));
        assert!(
            !line.contains("mid=") && !line.contains("carrier") && !line.contains("PairResponse")
        );
        // Chat shows its own transcript line instead.
        assert_eq!(
            SendCtx {
                chat: true,
                ..bob()
            }
            .delivered_line(),
            None
        );

        let mid = [0xab; 16];
        assert_eq!(
            ctx.delivery_detail_line("lan_dial", None, &mid, false),
            None
        );
        let verbose = plain(
            &ctx.delivery_detail_line("lan_dial", None, &mid, true)
                .unwrap(),
        );
        assert!(
            verbose.contains("abababab") && verbose.contains("carrier=lan_dial"),
            "{verbose}"
        );
        // `--carrier auto` names the carrier only in verbose mode, Internet too.
        assert_eq!(
            ctx.delivery_detail_line("internet_dial", None, &mid, false),
            None
        );
        // A carrier the user named (`--carrier internet`) keeps its lab evidence.
        let named = SendCtx {
            show_carrier: true,
            ..bob()
        };
        assert_eq!(
            named.delivery_detail_line("lan_dial", None, &mid, false),
            None
        );
        let lab = plain(
            &named
                .delivery_detail_line("internet_dial", None, &mid, false)
                .unwrap(),
        );
        assert!(
            lab.contains("carrier=internet_dial") && lab.contains("peer=192.168.0.16:7420"),
            "{lab}"
        );

        let first = plain(&ctx.connection_set_up_line(false));
        assert_eq!(
            first,
            "First time talking to Bob: secure connection set up."
        );
        assert!(!first.contains("PairResponse"));
        // Field test E2 r7: a new one after the last ran out is no first.
        assert_eq!(
            plain(&ctx.connection_set_up_line(true)),
            "New secure connection with Bob set up (the last one had run out)."
        );
        let chat = SendCtx {
            chat: true,
            ..bob()
        };
        assert_eq!(
            plain(&chat.connection_set_up_line(false)),
            "  (secure connection with Bob set up)"
        );
        assert_eq!(
            plain(&chat.connection_set_up_line(true)),
            "  (new secure connection with Bob set up: the last one had run out)"
        );
        let earlier = plain(&ctx.earlier_delivered_line("\"see you at 5\""));
        assert!(
            earlier.starts_with("status delivered — your earlier message \"see you at 5\" to Bob"),
            "{earlier}"
        );
        let failed = plain(&ctx.earlier_failed_line("\"x\"", "it expired"));
        assert_eq!(
            failed,
            "status failed: your earlier message \"x\" to Bob: it expired"
        );
        // Nothing here ever prints for someone unnamed as an empty string.
        let anon = SendCtx::default();
        assert!(
            plain(&anon.delivered_line().unwrap()).contains("the other person confirmed receipt")
        );
    }

    /// The verbose detail line gains `path=` after `peer=`; the `carrier=`
    /// token and everything before it stay as they were.
    #[test]
    fn delivery_detail_line_appends_path_after_peer() {
        let ctx = SendCtx {
            dial: "/p2p/12D3KooWExample".into(),
            ..bob()
        };
        let mid = [0xab; 16];
        let line = plain(
            &ctx.delivery_detail_line("p2p_dial", Some(DeliveryPath::Relayed), &mid, true)
                .unwrap(),
        );
        assert_eq!(
            line,
            "message abababab… via carrier=p2p_dial peer=/p2p/12D3KooWExample path=relayed"
        );
        let unknown = plain(
            &ctx.delivery_detail_line("p2p_dial", None, &mid, true)
                .unwrap(),
        );
        assert!(unknown.ends_with("peer=/p2p/12D3KooWExample"), "{unknown}");
        let lan = plain(
            &bob()
                .delivery_detail_line("lan_dial", Some(DeliveryPath::Direct), &mid, true)
                .unwrap(),
        );
        assert_eq!(
            lan,
            "message abababab… via carrier=lan_dial peer=192.168.0.16:7420 path=direct"
        );
        // Not verbose: nothing, path or not.
        assert_eq!(
            ctx.delivery_detail_line("p2p_dial", Some(DeliveryPath::Direct), &mid, false),
            None
        );
        // Tor names no address (field test E3: "peer=" stood empty): no
        // peer field, and the path is Tor.
        let tor = SendCtx {
            dial: String::new(),
            ..bob()
        };
        let line = plain(
            &tor.delivery_detail_line("onion_dial", None, &mid, true)
                .unwrap(),
        );
        assert_eq!(line, "message abababab… via carrier=onion_dial path=tor");
    }

    /// The dim `path:` line: how a delivery travelled, in words, and neither
    /// in verbose mode (the detail line says `path=`) nor in the chat.
    #[test]
    fn path_line_is_not_verbose_not_chat() {
        let ctx = bob();
        let line = |path| {
            ctx.path_line("p2p_dial", Some(path), false)
                .map(|l| plain(&l))
        };
        assert_eq!(
            line(DeliveryPath::Relayed).unwrap(),
            "  path: through a relay (it passes only encrypted bytes)"
        );
        assert_eq!(
            line(DeliveryPath::Direct).unwrap(),
            "  path: direct connection"
        );
        assert_eq!(
            line(DeliveryPath::Reversed).unwrap(),
            "  path: over Bob's own connection to you"
        );
        assert_eq!(
            line(DeliveryPath::HolePunched).unwrap(),
            "  path: direct (hole-punched through both routers)"
        );
        assert_eq!(ctx.path_line("p2p_dial", None, false), None);
        assert_eq!(
            ctx.path_line("p2p_dial", Some(DeliveryPath::Relayed), true),
            None
        );
        // E2 r9 #1: every carrier says what carried it, in words.
        for (carrier, words) in [
            ("lan_dial", "  path: same network (LAN)"),
            ("internet_dial", "  path: direct over the internet"),
            ("nearby_dial", "  path: Bluetooth nearby"),
            (
                "onion_dial",
                "  path: via Tor (neither of you saw the other's IP address)",
            ),
        ] {
            assert_eq!(
                ctx.path_line(carrier, Some(DeliveryPath::Direct), false)
                    .map(|l| plain(&l))
                    .as_deref(),
                Some(words)
            );
            assert_eq!(
                ctx.path_line(carrier, None, true),
                None,
                "verbose: {carrier}"
            );
        }
        let chat = SendCtx {
            chat: true,
            ..bob()
        };
        assert_eq!(
            chat.path_line("p2p_dial", Some(DeliveryPath::Relayed), false),
            None
        );
        // `status delivered` itself is untouched.
        assert_eq!(
            plain(&ctx.delivered_line().unwrap()),
            "status delivered — Bob confirmed receipt"
        );
    }

    /// `raven outbox status` shows the path row after the carrier when the
    /// worker recorded one (p2p), and no such row otherwise.
    #[test]
    fn outbox_status_prints_the_path_row() {
        let item = raven_core::ipc::OutboxItem {
            message_id_hex: "ab".repeat(16),
            state: "delivered".into(),
            carrier: "p2p_dial".into(),
            attempts: 2,
            path: "reversed".into(),
            ..Default::default()
        };
        let rows = outbox_status_rows(&item, 0);
        assert_eq!(rows[0], "  carrier     p2p_dial");
        assert_eq!(rows[1], "  path        reversed");
        assert_eq!(rows[2], "  attempts    2");
        let lan = raven_core::ipc::OutboxItem {
            carrier: "lan_dial".into(),
            path: String::new(),
            ..item.clone()
        };
        let rows = outbox_status_rows(&lan, 0);
        assert!(rows.iter().all(|r| !r.contains("path")), "{rows:?}");
        assert_eq!(rows[0], "  carrier     lan_dial");
        assert_eq!(rows[1], "  attempts    2");
    }

    /// `raven outbox list` rows end in `via <path>` for written p2p objects.
    #[test]
    fn outbox_row_line_shows_via_path() {
        let dir = tempfile::tempdir().unwrap();
        let item = |state: &str, path: &str| raven_core::ipc::OutboxItem {
            message_id_hex: "cd".repeat(16),
            peer_pub_hex: "ef".repeat(32),
            kind: "message".into(),
            state: state.into(),
            carrier: "p2p_dial".into(),
            attempts: 1,
            path: path.into(),
            ..Default::default()
        };
        let line = plain(&outbox_row_line(
            dir.path(),
            &item("delivered", "hole_punched"),
            0,
        ));
        assert!(line.ends_with("  via hole_punched"), "{line}");
        let sent = plain(&outbox_row_line(dir.path(), &item("sent", "relayed"), 0));
        assert!(sent.ends_with("  via relayed"), "{sent}");
        let none = plain(&outbox_row_line(dir.path(), &item("delivered", ""), 0));
        assert!(!none.contains("via"), "{none}");
        let queued = plain(&outbox_row_line(dir.path(), &item("queued", "relayed"), 0));
        assert!(!queued.contains("via"), "{queued}");
    }

    /// E2 r40 #D, #E: `raven outbox status` counts the attempts by how they
    /// ended, names the ways the last one tried (or the way it was
    /// delivered), and the waiting reason names every way, whichever dial
    /// ended last.
    #[test]
    fn outbox_status_counts_attempts_and_names_the_ways() {
        let count = |code: &str, count: u32| raven_core::ipc::AttemptCount {
            code: code.into(),
            count,
        };
        let waiting = raven_core::ipc::OutboxItem {
            message_id_hex: "cd".repeat(16),
            peer_pub_hex: "ef".repeat(32),
            kind: "message".into(),
            state: "queued".into(),
            carrier: "onion_dial".into(),
            attempts: 10,
            last_error_code: "NOT_REACHABLE".into(),
            tried: vec!["lan_dial".into(), "p2p_dial".into(), "onion_dial".into()],
            outcomes: vec![count("NOT_REACHABLE", 9), count("ONION_NOT_READY", 1)],
            ..Default::default()
        };
        let rows = outbox_status_rows(&waiting, 0);
        assert!(
            rows.contains(&"  results     9 no answer, 1 Tor not ready here".to_string()),
            "{rows:?}"
        );
        assert!(
            rows.contains(&"  last tried  on the local network, over p2p and over Tor".to_string()),
            "{rows:?}"
        );
        let reason = "Bob couldn't be reached right now: no answer on the local network, over \
                      p2p or over Tor";
        assert_eq!(last_error_words(&waiting, "Bob"), reason);
        // The same whichever dial ended last.
        let tor_last = raven_core::ipc::OutboxItem {
            last_error_code: "ONION_UNREACHABLE".into(),
            ..waiting.clone()
        };
        assert_eq!(last_error_words(&tor_last, "Bob"), reason);
        // One way: that way's own words.
        let tor_only = raven_core::ipc::OutboxItem {
            tried: vec!["onion_dial".into()],
            ..tor_last.clone()
        };
        assert_eq!(
            last_error_words(&tor_only, "Bob"),
            "Bob couldn't be reached over Tor right now"
        );
        // Delivered: the way it went, not the ways tried before.
        let delivered = raven_core::ipc::OutboxItem {
            state: "delivered".into(),
            last_error_code: String::new(),
            outcomes: vec![count("NOT_REACHABLE", 9), count("DELIVERED", 1)],
            ..waiting.clone()
        };
        let rows = outbox_status_rows(&delivered, 0);
        assert!(
            rows.contains(&"  results     9 no answer, 1 delivered".to_string()),
            "{rows:?}"
        );
        assert!(
            rows.contains(&"  delivered   over Tor".to_string()),
            "{rows:?}"
        );
        assert!(!rows.iter().any(|r| r.contains("last tried")), "{rows:?}");
        let p2p = raven_core::ipc::OutboxItem {
            carrier: "p2p_dial".into(),
            path: "hole_punched".into(),
            ..delivered
        };
        assert!(outbox_status_rows(&p2p, 0)
            .contains(&"  delivered   over p2p (hole_punched)".to_string()));
        // An older raven-node: as before.
        let old = raven_core::ipc::OutboxItem {
            tried: Vec::new(),
            outcomes: Vec::new(),
            ..waiting
        };
        let rows = outbox_status_rows(&old, 0);
        assert!(rows.contains(&"  attempts    10".to_string()), "{rows:?}");
        assert!(!rows.iter().any(|r| r.contains("results")), "{rows:?}");
        assert_ne!(last_error_words(&old, "Bob"), reason);
    }

    /// E2 r40 #5: a finished row (its staged body gone) shows the message's
    /// words from the chat history, as a waiting row does.
    #[test]
    fn finished_outbox_rows_show_the_message_words() {
        let dir = tempfile::tempdir().unwrap();
        let entry = |mid: &str, direction: &str, body: &str, preview: &str| {
            raven_core::chat_history::ChatHistoryEntry {
                message_id_hex: mid.into(),
                direction: direction.into(),
                peer_petname: "Bob".into(),
                peer_tag: String::new(),
                peer_pub_hex: "ef".repeat(32),
                created_at_ms: 1,
                delivery: "delivered".into(),
                preview: preview.into(),
                body: body.into(),
                stored_at_ms: None,
                id_conflict: false,
            }
        };
        let history = ChatHistory {
            entries: vec![
                entry(&"CD".repeat(16), "out", "see you at noon", "see you…"),
                entry(&"ab".repeat(16), "out", "", "legacy row"),
                entry(&"12".repeat(16), "in", "not ours", "not ours"),
            ],
        };
        let previews = history_previews(&history);
        assert_eq!(previews.len(), 2, "{previews:?}");
        let item = |mid: &str| raven_core::ipc::OutboxItem {
            message_id_hex: mid.into(),
            peer_pub_hex: "ef".repeat(32),
            kind: "message".into(),
            state: "delivered".into(),
            ..Default::default()
        };
        let line = plain(&outbox_row_line_with(
            dir.path(),
            &item(&"cd".repeat(16)),
            0,
            &previews,
        ));
        assert!(line.contains("message \"see you at noon\" to"), "{line}");
        let legacy = plain(&outbox_row_line_with(
            dir.path(),
            &item(&"ab".repeat(16)),
            0,
            &previews,
        ));
        assert!(legacy.contains("message \"legacy row\" to"), "{legacy}");
        // Without the history: as before, no words.
        let bare = plain(&outbox_row_line(dir.path(), &item(&"cd".repeat(16)), 0));
        assert!(bare.contains("delivered message to"), "{bare}");
    }

    /// E1: `raven outbox list` says when a late delivery came; E2 r9: every
    /// finished row has a time. A delivered message its own arrival (from an
    /// older raven-node, the newest one to a friend that friend's last
    /// delivery, whose age its Status keeps), any other row when it was
    /// written; an expired row with a deadline says when it ran out instead.
    #[test]
    fn every_finished_row_says_when() {
        const HOUR: u64 = 3_600_000;
        let now = 40 * HOUR;
        let item = |mid: u8, peer: u8, state: &str| raven_core::ipc::OutboxItem {
            message_id_hex: format!("{mid:02x}").repeat(16),
            peer_pub_hex: format!("{peer:02x}").repeat(32),
            kind: "message".into(),
            state: state.into(),
            ..Default::default()
        };
        let path = |peer: u8, age_s: u64| raven_core::ipc::ContactPath {
            peer_pub_hex: format!("{peer:02x}").repeat(32),
            carrier: "lan_dial".into(),
            age_s,
            ..Default::default()
        };
        // Newest first, as raven-node lists its finished rows.
        let mut ran_out = item(1, 0xb0, "expired");
        ran_out.expires_at_ms = now - HOUR;
        let mut own_time = item(6, 0xe0, "delivered");
        own_time.delivered_at_ms = now - 5_000;
        let rows = [
            ran_out,
            item(2, 0xb0, "delivered"),
            item(3, 0xb0, "delivered"),
            item(4, 0xc0, "delivered"),
            item(5, 0xd0, "failed"),
            own_time,
        ];
        let finished: Vec<&raven_core::ipc::OutboxItem> = rows.iter().collect();
        let written: std::collections::HashMap<String, u64> = [
            ("01", now - 26 * HOUR),
            ("02", now - 3 * HOUR),
            ("03", now - 4 * HOUR),
            ("04", now - 100_000),
            ("05", now - 3 * HOUR),
            ("06", now - 9_000),
        ]
        .into_iter()
        .map(|(mid, at)| (mid.repeat(16), at))
        .collect();
        let last_paths = [path(0xb0, 600), path(0xc0, 60)];
        let times = finished_times(&finished, &last_paths, &written, now);
        let want = std::collections::HashMap::from([
            ("02".repeat(16), ("arrived", now - 600_000)),
            ("03".repeat(16), ("written", now - 4 * HOUR)),
            ("04".repeat(16), ("arrived", now - 60_000)),
            ("05".repeat(16), ("written", now - 3 * HOUR)),
            ("06".repeat(16), ("arrived", now - 5_000)),
        ]);
        assert_eq!(times, want);
        // Each time names its zone; without one it is an age.
        let at = 1_761_700_000_000;
        assert_eq!(zone_label(Some(0)).as_deref(), Some("UTC"));
        assert_eq!(zone_label(Some(3_600)).as_deref(), Some("UTC+1"));
        assert_eq!(zone_label(Some(-18_000)).as_deref(), Some("UTC-5"));
        assert_eq!(zone_label(Some(19_800)).as_deref(), Some("UTC+5:30"));
        let zoned = ended_zoned_with_offset(at - 60_000, at, Some(3_600));
        assert!(
            zoned.ends_with(" (UTC+1)") && zoned.contains(" at "),
            "{zoned}"
        );
        let plain_age = ended_zoned_with_offset(at - 3 * HOUR, at, None);
        assert_eq!(plain_age, "about 3 h ago");
    }

    /// E2 r38: a held message names both deadlines when the message's own
    /// comes after its copy's; `raven outbox status` says its last error in
    /// words, the code after them.
    #[test]
    fn a_held_message_names_both_deadlines_and_its_last_error_in_words() {
        const HOUR: u64 = 3_600_000;
        let now = 1_792_492_500_000;
        let copy = now + 24 * HOUR;
        let message = now + 7 * 24 * HOUR;
        let words = held_words(1, copy, Some(message), now);
        assert_eq!(
            words,
            format!(
                "held by 1 friend until {}, not delivered yet; Raven keeps trying until {}",
                until_text(copy, now),
                until_text(message, now)
            )
        );
        assert_eq!(
            held_words(1, copy, None, now),
            held_by_friends_text(1, copy, now)
        );
        let item = raven_core::ipc::OutboxItem {
            message_id_hex: "ab".repeat(16),
            peer_pub_hex: "ef".repeat(32),
            kind: "message".into(),
            state: "sent".into(),
            last_error_code: "IN_CUSTODY".into(),
            in_custody: 1,
            expires_at_ms: copy,
            ..Default::default()
        };
        let mut rows = outbox_status_rows(&item, now);
        worded_last_error(&mut rows, &item, "Bob");
        let want =
            "  last error  a friend's computer is holding a sealed copy for Bob (IN_CUSTODY)";
        assert!(rows.iter().any(|r| r == want), "{rows:?}");
        // A code with no words stays.
        let odd = raven_core::ipc::OutboxItem {
            last_error_code: "SOMETHING_NEW".into(),
            ..item
        };
        let mut rows = outbox_status_rows(&odd, now);
        worded_last_error(&mut rows, &odd, "Bob");
        assert!(
            rows.iter().any(|r| r == "  last error  SOMETHING_NEW"),
            "{rows:?}"
        );
    }

    /// E2 r9: a waiting message a friend holds is `held` in the state
    /// column, as its row says, not `sent`.
    #[test]
    fn a_held_message_says_held_in_the_state_column() {
        let dir = tempfile::tempdir().unwrap();
        let item = |state: &str, in_custody: u8| raven_core::ipc::OutboxItem {
            message_id_hex: "ab".repeat(16),
            peer_pub_hex: "ef".repeat(32),
            kind: "message".into(),
            state: state.into(),
            in_custody,
            ..Default::default()
        };
        let held = plain(&outbox_row_line(dir.path(), &item("sent", 1), 0));
        assert!(held.starts_with("  abababab  held "), "{held}");
        let sent = plain(&outbox_row_line(dir.path(), &item("sent", 0), 0));
        assert!(sent.starts_with("  abababab  sent "), "{sent}");
        let done = plain(&outbox_row_line(dir.path(), &item("delivered", 1), 0));
        assert!(done.starts_with("  abababab  delivered "), "{done}");
    }

    /// Friend custody (Phase 3 item 3): a waiting message friends hold says
    /// so in `raven outbox list` and `raven outbox status`; one that ran out
    /// after friends held it says time ran out before the contact collected
    /// it (P3.C4).
    #[test]
    fn outbox_list_shows_held_by_n_friends() {
        let dir = tempfile::tempdir().unwrap();
        let item = |state: &str, in_custody: u8| raven_core::ipc::OutboxItem {
            message_id_hex: "cd".repeat(16),
            peer_pub_hex: "ef".repeat(32),
            kind: "message".into(),
            state: state.into(),
            last_error_code: "IN_CUSTODY".into(),
            in_custody,
            expires_at_ms: 3_600_000,
            ..Default::default()
        };
        let one = plain(&outbox_row_line(dir.path(), &item("sent", 1), 0));
        // Until when the friend keeps it, in local time, and no second
        // "expires" naming the same time (P3.C4).
        let until = until_text(3_600_000, 0);
        assert!(
            one.contains(&format!(
                "  held by 1 friend until {until}, not delivered yet"
            )),
            "{one}"
        );
        assert!(!one.contains("expires"), "{one}");
        let two = plain(&outbox_row_line(dir.path(), &item("held", 2), 0));
        assert!(
            two.contains(&format!(
                "  held by 2 friends until {until}, not delivered yet"
            )),
            "{two}"
        );
        let none = plain(&outbox_row_line(dir.path(), &item("sent", 0), 0));
        assert!(!none.contains("held by"), "{none}");
        assert!(none.contains(&format!("  expires {until}")), "{none}");
        let rows = outbox_status_rows(&item("queued", 2), 0);
        assert!(
            rows.contains(&format!(
                "  friends     held by 2 friends until {until}, not delivered yet"
            )),
            "{rows:?}"
        );
        // Past its time (raven-node has not settled it yet): no time named.
        assert_eq!(
            held_by_friends_text(1, 3_600_000, 3_600_000),
            "held by 1 friend, not delivered yet"
        );
        assert_eq!(
            held_by_friends_text(2, 0, 0),
            "held by 2 friends, not delivered yet"
        );
        // Expired after friends held it: time ran out before the contact
        // collected it.
        let ran_out = plain(&outbox_row_line(dir.path(), &item("expired", 1), 7_200_000));
        assert!(
            ran_out.contains("  time ran out: ")
                && ran_out
                    .contains(" didn't collect it from the friend who held it before it expired "),
            "{ran_out}"
        );
        assert!(!ran_out.contains("held by 1 friend"), "{ran_out}");
        assert_eq!(
            custody_ran_out_text("Bob", 2, 0, 0),
            "time ran out: Bob didn't collect it from the 2 friends who held it before it expired"
        );
    }

    /// Review handoff-3: a message a friend passed on to the contact's own
    /// friend (custody handoff) that ran out says its delivery was not
    /// confirmed, never that the contact didn't collect it (the contact may
    /// have, its receipt having no way back through friends); a plain hold
    /// keeps the text above.
    #[test]
    fn an_expired_message_a_friend_passed_on_was_not_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let item = |in_custody: u8, custody_forwarded: bool| raven_core::ipc::OutboxItem {
            message_id_hex: "cd".repeat(16),
            peer_pub_hex: "ef".repeat(32),
            kind: "message".into(),
            state: "expired".into(),
            last_error_code: "EXPIRED".into(),
            in_custody,
            custody_forwarded,
            expires_at_ms: 3_600_000,
            ..Default::default()
        };
        let passed = plain(&outbox_row_line(dir.path(), &item(1, true), 7_200_000));
        assert!(
            passed.contains(
                "  time ran out before delivery was confirmed: the friend who held it passed it \
                 on to "
            ) && passed.contains(" and no receipt came back before it expired ")
                && passed.ends_with(" may have it)"),
            "{passed}"
        );
        assert!(!passed.contains("didn't collect"), "{passed}");
        let held = plain(&outbox_row_line(dir.path(), &item(1, false), 7_200_000));
        assert!(held.contains(" didn't collect it from "), "{held}");
        assert_eq!(
            custody_unconfirmed_text("Bob", 2, 0, 0),
            "time ran out before delivery was confirmed: the 2 friends who held it passed it on \
             to Bob's friend, and no receipt came back before it expired (Bob may have it)"
        );
    }

    /// Review cross-5: `raven outbox status` says raven-node's outbox is
    /// not running for a message parked until its deadline (`waiting`,
    /// Phase 5a) too: only raven-node pairs and seals it again. A message
    /// that ended needs nothing of it.
    #[test]
    fn a_parked_message_waits_for_the_outbox() {
        let item = |state: &str| raven_core::ipc::OutboxItem {
            state: state.into(),
            ..Default::default()
        };
        for state in ["queued", "sent", "held", "waiting"] {
            assert!(outbox_retries_it(&item(state)), "{state}");
        }
        for state in ["delivered", "expired", "failed", "cancelled", ""] {
            assert!(!outbox_retries_it(&item(state)), "{state}");
        }
    }

    /// The queued text names the friend raven-node leaves a copy with, how
    /// long its Raven holds it and what it knows (P3.C4); only while raven-node retries it in the
    /// background, and never without a friend.
    #[test]
    fn queued_text_names_the_friend_and_what_it_learns() {
        let raw = "lan connect: cannot connect to 192.168.0.16:7420 (Connection refused)";
        // E2 r9 #7: the copy expires before the message's own deadline.
        let copy = now_ms() + 6 * 3_600_000;
        let with = |names: &[&str], kicked: bool| RetryNote {
            custodians: names.iter().map(|n| n.to_string()).collect(),
            background: kicked,
            copy_expires_at_ms: copy,
            ..background()
        };
        let note = with(&["Carol"], true);
        let text = queued_text(&bob(), raw, "\"hi\"", &note);
        // How long Carol's Raven holds it and what it knows (P3.C4): until
        // the copy expires, as `raven outbox list` says it (E2 r9 #7).
        let held = until_text(copy, now_ms());
        assert!(
            text.contains(&format!(
                "Bob can't be reached now: raven-node keeps trying and leaves a sealed copy with \
                 Carol (a mail friend you share) in about a minute, who passes it on when Bob is \
                 back. Carol's Raven holds it until {held}, when that copy expires. Carol can't \
                 read it, but Carol's Raven knows that you wrote to Bob, and when. Keep this \
                 computer online until `raven outbox list` says it is held by a friend, or run \
                 `raven outbox hand-off`."
            )),
            "{text}"
        );
        // E2 r9 #6: with a mail friend, no "same network" and no address
        // to fix.
        assert!(text.contains("as soon as Bob can be reached"), "{text}");
        assert!(!text.contains("same network"), "{text}");
        assert!(!text.contains("set-dial"), "{text}");
        assert!(
            text.ends_with(&format!(
                "(technical: {})",
                raven_core::ipc::without_addresses(raw)
            )),
            "{text}"
        );
        // The friend's LAN address is not in a queued send's text.
        assert!(
            !text.contains("10.0.0.") && !text.contains("192.168."),
            "{text}"
        );
        let two = queued_text(&bob(), raw, "\"hi\"", &with(&["Carol", "Dan"], true));
        assert!(
            two.contains(&format!(
                "a sealed copy with Carol and Dan (mail friends you share) in about a minute, who \
                 pass it on when Bob is back. The Ravens of Carol and Dan hold it until {held}, \
                 when that copy expires. Carol and Dan can't read it, but their Ravens know that \
                 you wrote to Bob, and when."
            )),
            "{two}"
        );
        for note in [with(&[], true), with(&["Carol"], false)] {
            let text = queued_text(&bob(), raw, "\"hi\"", &note);
            assert!(!text.contains("sealed copy"), "{text}");
        }
    }

    /// E2 r9 #5: a send that tried the LAN, p2p and Tor and reached the
    /// friend on none names every way tried, with no address, and gives no
    /// LAN advice; Tor not ready here says so.
    #[test]
    fn a_send_that_tried_every_way_names_them_without_an_address() {
        let raw = "lan_dial 192.168.0.16:17420: lan connect: cannot connect to \
                   192.168.0.16:17420 (no answer within 5.0s (the probe was cut short; nothing \
                   was sent)); p2p_dial /p2p/12D3KooWExample: ipc P2P_DIAL: P2P_UNREACHABLE: \
                   no route; reach: why=direct_failed; onion_dial Tor: ipc ONION_UNREACHABLE: \
                   ONION_UNREACHABLE: the contact's onion service did not answer over Tor";
        ON_OUR_NETWORK.with(|c| c.set(Some(false)));
        let text = queued_text(&bob(), raw, "\"hi\"", &background());
        let words = text.split("(technical:").next().unwrap();
        assert!(
            words.contains(
                "is queued locally because Bob couldn't be reached right now: no answer on the \
                 local network, over p2p or over Tor."
            ),
            "{text}"
        );
        assert!(words.contains("as soon as Bob can be reached"), "{text}");
        // E2 r38: said once.
        assert_eq!(
            words.matches("Do not retype this message.").count(),
            1,
            "{text}"
        );
        for never in [
            "192.168",
            "same network",
            "set-dial",
            "/p2p/",
            "The message waits and goes by itself",
            "you do not need to send it again",
        ] {
            assert!(!words.contains(never), "{never}: {text}");
        }
        let not_ready = raw.replace(
            "ipc ONION_UNREACHABLE: ONION_UNREACHABLE: the contact's onion service did not \
             answer over Tor",
            "ipc ONION_NOT_READY: ONION_NOT_READY: Tor is not ready on this computer yet",
        );
        let text = queued_text(&bob(), &not_ready, "\"hi\"", &background());
        assert!(
            text.contains("over p2p or over Tor; Tor isn't ready on this computer yet."),
            "{text}"
        );
        // Without Tor among them, the LAN and p2p reasons stay as they were.
        let no_tor = raw.split("; onion_dial").next().unwrap();
        let text = queued_text(&bob(), no_tor, "\"hi\"", &background());
        assert!(!text.contains("couldn't be reached right now"), "{text}");
        ON_OUR_NETWORK.with(|c| c.set(None));
    }

    /// E2 r40 #3: a send whose LAN address is on this network but did not
    /// answer (the friend moved), or was not dialled again (it failed
    /// lately), with Tor tried last: the ways tried, never that address.
    #[test]
    fn a_tor_send_names_the_ways_tried_not_the_lan_address() {
        let timed_out = "lan_dial 192.168.0.16:17420: lan connect: cannot connect to \
                         192.168.0.16:17420 (no answer within 5.0s (the probe was cut short; \
                         nothing was sent)); onion_dial Tor: ipc ONION_UNREACHABLE: \
                         ONION_UNREACHABLE: the contact's onion service did not answer over Tor";
        let skipped = "lan_dial 192.168.0.16:17420: lan connect: cannot connect to \
                       192.168.0.16:17420 (no answer within 5.0s) (failed 20 s ago; not tried \
                       again now); p2p_dial /p2p/12D3KooWExample: ipc P2P_DIAL: P2P_UNREACHABLE: \
                       no route; reach: why=direct_failed; onion_dial Tor: ipc \
                       ONION_UNREACHABLE: ONION_UNREACHABLE: the contact's onion service did \
                       not answer over Tor";
        ON_OUR_NETWORK.with(|c| c.set(Some(true)));
        for (raw, ways) in [
            (timed_out, "no answer on the local network or over Tor."),
            (
                skipped,
                "no answer on the local network, over p2p or over Tor.",
            ),
        ] {
            let text = queued_text(&bob(), raw, "\"hi\"", &background());
            let words = text.split("(technical:").next().unwrap();
            assert!(
                words.contains(&format!("Bob couldn't be reached right now: {ways}")),
                "{text}"
            );
            for never in ["192.168", "onion:", "set-dial", "same network"] {
                assert!(!words.contains(never), "{never}: {text}");
            }
        }
        ON_OUR_NETWORK.with(|c| c.set(None));
    }

    /// E2 r40 (A): Tor the only way, not answering within the send's wait
    /// (or raven-node's outbox still trying it): said as Tor's, no address,
    /// no LAN advice.
    #[test]
    fn a_tor_only_send_that_did_not_answer_says_tor() {
        let ctx = SendCtx {
            dial: String::new(),
            ..bob()
        };
        for raw in [
            "onion_dial Tor: no answer within 25s (the probe was cut short; nothing was sent)",
            "ipc ONION_UNREACHABLE: ONION_UNREACHABLE: the contact's onion service did not \
             answer over Tor",
        ] {
            let text = queued_text(&ctx, raw, "\"hi\"", &background());
            let words = text.split("(technical:").next().unwrap();
            assert!(
                words.contains("because Bob couldn't be reached over Tor right now."),
                "{text}"
            );
            assert!(words.contains("as soon as Bob can be reached"), "{text}");
            for never in [
                "set-dial",
                "same network",
                "IP address",
                "192.168",
                "onion:",
            ] {
                assert!(!words.contains(never), "{never}: {text}");
            }
        }
    }

    /// Field test E3: a send that left Tor to raven-node's outbox (it is
    /// already trying Tor for an earlier message and has not reached the
    /// friend yet) dialled nothing over Tor: it says so, alone or after
    /// other ways that did not answer, never "couldn't be reached".
    #[test]
    fn a_send_that_left_tor_to_the_outbox_says_so() {
        let ctx = SendCtx {
            dial: String::new(),
            ..bob()
        };
        let busy = super::super::pair_init_lab::TOR_BUSY;
        for raw in [
            busy.to_string(),
            format!("onion_dial Tor: {busy}"),
            format!(
                "p2p_dial /p2p/12D3KooWExample: ipc P2P_DIAL: P2P_NOT_RUNNING: the libp2p \
                 host of this raven-node is not running; onion_dial Tor: {busy}"
            ),
        ] {
            let text = queued_text(&ctx, &raw, "\"hi\"", &background());
            let words = text.split("(technical:").next().unwrap();
            assert!(
                words.contains(
                    "because Raven is already trying to reach Bob over Tor with an earlier \
                     message, and Tor hasn't reached Bob yet."
                ),
                "{text}"
            );
            for never in ["couldn't be reached", "no answer", "onion:", "192.168"] {
                assert!(!words.contains(never), "{never}: {text}");
            }
        }
    }

    /// E2 r40 #2: Tor answered the send's check, then the message's own Tor
    /// connection failed: said as that, with no address and no LAN advice.
    #[test]
    fn a_message_lost_after_tor_answered_says_so() {
        let raw = format!(
            "{}: ipc ONION_UNREACHABLE: ONION_UNREACHABLE (rendezvous failed)",
            super::super::pair_init_lab::ONION_CHECKED_THEN_LOST
        );
        let text = queued_text(&bob(), &raw, "\"hi\"", &background());
        let words = text.split("(technical:").next().unwrap();
        assert!(
            words.contains(
                "Bob answered over Tor, but the message itself did not get through this time."
            ),
            "{text}"
        );
        assert_eq!(
            words.matches("Do not retype this message.").count(),
            1,
            "{text}"
        );
        for never in ["did not answer at", "onion:", "same network", "set-dial"] {
            assert!(!words.contains(never), "{never}: {text}");
        }
    }

    /// E2 r9 #4: a friend whose saved address is on this computer's network
    /// and whose Raven is closed: the LAN's answer, never NAT advice, even
    /// when p2p's reason is "both behind NAT" and Tor was tried too.
    #[test]
    fn a_friend_closed_on_our_network_gets_the_lan_reason_not_nat_advice() {
        let raw = "lan_dial 192.168.0.16:17420: lan connect: cannot connect to \
                   192.168.0.16:17420 (Connection refused); p2p_dial /p2p/12D3KooWExample: ipc \
                   P2P_DIAL: P2P_UNREACHABLE: no route; reach: why=both_nat me=unreachable; \
                   onion_dial Tor: ipc ONION_UNREACHABLE: ONION_UNREACHABLE: the contact's onion \
                   service did not answer over Tor";
        ON_OUR_NETWORK.with(|c| c.set(Some(true)));
        let text = queued_text(&bob(), raw, "\"hi\"", &background());
        let words = text
            .split("(technical:")
            .next()
            .unwrap()
            .to_ascii_lowercase();
        assert!(
            words.contains("bob's computer is there, but raven isn't receiving right now"),
            "{text}"
        );
        assert!(!words.contains("nat") && !words.contains("relay"), "{text}");
        // Not on this network: Tor's way of saying it.
        ON_OUR_NETWORK.with(|c| c.set(Some(false)));
        let text = queued_text(&bob(), raw, "\"hi\"", &background());
        assert!(text.contains("couldn't be reached right now"), "{text}");
        ON_OUR_NETWORK.with(|c| c.set(None));
    }

    /// Phase 6a P6.16: when raven-node's carry choice learned who goes
    /// first, the queued text says so after the friends it names (in its
    /// order); without it the text is today's.
    #[test]
    fn queued_text_says_who_goes_first_when_raven_node_learned_it() {
        assert_eq!(
            carry_first_words("Carol", "often", 3, 4),
            "Carol first (you meet often; delivered 3 of 4 before)"
        );
        assert_eq!(
            carry_first_words("Dave", "sometimes", 0, 0),
            "Dave first (you meet sometimes)"
        );
        assert_eq!(
            carry_first_words("Erin", "rarely", 0, 1),
            "Erin first (you rarely meet; delivered 0 of 1 before)"
        );
        assert_eq!(
            carry_first_words("Fay", "never", 1, 1),
            "Fay first (you have not met lately; delivered 1 of 1 before)"
        );
        assert_eq!(
            carry_first_words("Ca\x1b[2Jrol", "often", 0, 0),
            "Carol first (you meet often)"
        );
        let raw = "lan connect: cannot connect to 192.168.0.16:7420 (Connection refused)";
        let note = RetryNote {
            custodians: vec!["Carol".into(), "Dave".into()],
            carry_first: Some(carry_first_words("Carol", "often", 3, 4)),
            ..background()
        };
        let text = queued_text(&bob(), raw, "\"hi\"", &note);
        assert!(
            text.contains(
                "leaves a sealed copy with Carol and Dave (mail friends you share) in about a \
                 minute, who pass it on when Bob is back. Left with Carol first (you meet often; \
                 delivered 3 of 4 before). The Ravens of Carol and Dave hold it until "
            ),
            "{text}"
        );
        let today = queued_text(
            &bob(),
            raw,
            "\"hi\"",
            &RetryNote {
                carry_first: None,
                ..note
            },
        );
        assert!(!today.contains("Left with"), "{today}");
        assert!(
            today.contains("when Bob is back. The Ravens of Carol and Dave hold it"),
            "{today}"
        );
    }

    #[test]
    fn verbose_is_an_explicit_opt_in() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| std::ffi::OsString::from(*v))
            }
        };
        assert!(!verbose_with(env(&[])));
        assert!(!verbose_with(env(&[("RAVEN_VERBOSE", "")])));
        assert!(!verbose_with(env(&[("RAVEN_VERBOSE", "0")])));
        assert!(verbose_with(env(&[("RAVEN_VERBOSE", "1")])));
        assert!(verbose_with(env(&[("ASH_VERBOSE", "1")])));
    }

    #[test]
    fn the_listener_messages_say_receiving_only_when_it_is_and_warn_once_otherwise() {
        let log = Path::new("/p/raven-node-service.log");
        let warned = AtomicBool::new(false);
        let up =
            plain(&listener_message("0.0.0.0:7420", Some(true), log, &warned, Some(4242)).unwrap());
        assert!(up.contains("receiving messages on 0.0.0.0:7420"), "{up}");
        assert!(
            up.contains("other computers on your network can reach it"),
            "{up}"
        );
        assert!(!warned.load(Ordering::SeqCst));
        let local =
            plain(&listener_message("127.0.0.1:0", Some(true), log, &warned, Some(4242)).unwrap());
        assert!(
            local.contains("this computer only") && !local.contains(":0"),
            "{local}"
        );
        assert_eq!(
            listener_message("0.0.0.0:7420", None, log, &warned, Some(4242)),
            None,
            "unknown: say nothing"
        );

        let down = plain(
            &listener_message("0.0.0.0:7420", Some(false), log, &warned, Some(4242)).unwrap(),
        );
        for word in [
            "warning: this computer is NOT receiving messages",
            "LAN port 0.0.0.0:7420 is busy or unavailable",
            "(log: /p/raven-node-service.log)",
            "Sending still works",
            "free that port (the service keeps retrying by itself)",
            // `taskkill /F /PID 4242` on Windows.
            &format!("stop this service ({})", stop_advice(4242)),
            "run ash again with RAVEN_SERVICE_LAN_LISTEN=0.0.0.0:7424",
            "Setting the variable while this service keeps running changes nothing",
        ] {
            assert!(down.contains(word), "{word:?} missing from: {down}");
        }
        assert!(!down.contains("IPC + LAN receive on"), "{down}");
        assert_eq!(
            listener_message("0.0.0.0:7420", Some(false), log, &warned, Some(4242)),
            None,
            "once per process"
        );
    }

    /// Busy-port and wedged-service advice stops one process (by the id the
    /// service reported) or this profile's service, never every raven-node.
    #[test]
    fn profile_stop_advice_names_one_process_or_one_profile() {
        let dir = Path::new("/homes/a/raven.b");
        let by_pid = profile_stop_advice(dir, Some(4242));
        assert_eq!(by_pid, stop_advice(4242));
        if cfg!(windows) {
            assert_eq!(by_pid, "taskkill /F /PID 4242");
        } else {
            assert_eq!(by_pid, "kill 4242");
        }
        let by_profile = profile_stop_advice(dir, None);
        if cfg!(windows) {
            assert!(
                by_profile.contains("--data-dir /homes/a/raven.b"),
                "{by_profile}"
            );
            assert!(!by_profile.contains("pkill"), "{by_profile}");
        } else {
            assert_eq!(
                by_profile,
                "pkill -f 'raven-node service --data-dir /homes/a/raven\\.b( |$)'"
            );
        }
        for advice in [by_pid, by_profile] {
            assert!(!advice.contains("pkill -f raven-node"), "{advice}");
            assert!(
                !advice.contains("pkill -f 'raven-node service'"),
                "{advice}"
            );
        }
    }

    #[test]
    fn the_service_listen_default_is_the_mac_listens_port() {
        assert_eq!(
            DEFAULT_SERVICE_LAN_LISTEN.to_string(),
            format!("0.0.0.0:{DEFAULT_LAN_PORT}")
        );
    }

    /// Phase 3 P3.6: a service ash starts listens `auto` only while that
    /// gate is live (in a debug build its lab switch, RAVEN_LAB_LAN_AUTO=1);
    /// otherwise on 0.0.0.0:7420, as before.
    #[test]
    fn the_service_listen_default_is_auto_only_while_its_gate_is_live() {
        assert_eq!(default_service_lan_listen_with(false, None), "0.0.0.0:7420");
        assert_eq!(default_service_lan_listen_with(true, None), "auto");
        assert_eq!(
            default_service_lan_listen(),
            default_service_lan_listen_with(raven_core::lan_auto_live(), None)
        );
        let switch = std::env::var("RAVEN_LAB_LAN_AUTO").ok();
        if !raven_core::lan_gate::LAN_AUTO_LISTEN_PRODUCTION_ENABLED
            && (!cfg!(debug_assertions) || switch.as_deref() != Some("1"))
        {
            assert_eq!(default_service_lan_listen(), "0.0.0.0:7420");
        }
    }

    /// Phase 6b P6.36: a service ash starts for a profile that picked a LAN
    /// port listens there (`auto:PORT` while `auto` is live, else
    /// 0.0.0.0:PORT), read from the profile at each start; a profile without
    /// one, and every profile while the random-port gate is shut, as before.
    /// No process profile noted: the hints say the default port.
    #[test]
    fn the_service_listen_default_takes_the_profiles_port() {
        use raven_core::security_gate::{set_lab_for_this_thread, SecGate};
        assert_eq!(
            default_service_lan_listen_with(false, Some(43_210)),
            "0.0.0.0:43210"
        );
        assert_eq!(
            default_service_lan_listen_with(true, Some(43_210)),
            "auto:43210"
        );
        let picked = tempfile::tempdir().unwrap();
        raven_core::node_policy::update_policy(picked.path(), |p| p.lan_listen_port = Some(43_210))
            .unwrap();
        let fresh = tempfile::tempdir().unwrap();
        let auto = raven_core::lan_auto_live();
        set_lab_for_this_thread(SecGate::RandomPort, Some(false));
        for dir in [&picked, &fresh] {
            assert_eq!(
                default_service_lan_listen_for(dir.path()),
                default_service_lan_listen_with(auto, None)
            );
        }
        if cfg!(debug_assertions) {
            set_lab_for_this_thread(SecGate::RandomPort, Some(true));
            assert_eq!(
                default_service_lan_listen_for(picked.path()),
                default_service_lan_listen_with(auto, Some(43_210))
            );
            assert_eq!(
                default_service_lan_listen_for(fresh.path()),
                default_service_lan_listen_with(auto, None)
            );
        }
        assert_eq!(own_lan_port(), DEFAULT_LAN_PORT);
        set_lab_for_this_thread(SecGate::RandomPort, None);
    }

    /// Review lock-updates-local-6: an update that starts raven-node again
    /// (no login item) starts it where the one it stopped listened: a node
    /// the app kept on this computer only stays there, a network's address
    /// or a port of its own stays as it was; one on every interface on
    /// `auto`'s port stays `auto`; unknown (a locked node, LAN off, an older
    /// one): the default, as a send's start.
    #[test]
    fn an_update_restarts_raven_node_where_it_listened() {
        let default = || "0.0.0.0:7424".to_owned();
        for (was, want) in [
            (Some("127.0.0.1:7424"), "127.0.0.1:7424"),
            (Some("127.0.0.1:53817"), "127.0.0.1:53817"),
            (Some("[::1]:7424"), "[::1]:7424"),
            (Some("192.168.1.20:7424"), "192.168.1.20:7424"),
            (Some("0.0.0.0:7500"), "0.0.0.0:7500"),
            (Some("0.0.0.0:7424"), "0.0.0.0:7424"),
            (Some(" 127.0.0.1:7424 "), "127.0.0.1:7424"),
            (None, "0.0.0.0:7424"),
            (Some("auto"), "0.0.0.0:7424"),
            (Some("not an address"), "0.0.0.0:7424"),
        ] {
            assert_eq!(restart_lan_listen(was, default()), want, "{was:?}");
        }
        // `auto` binds 0.0.0.0 and [::] on its port: kept `auto` (local
        // sources only), never widened to a plain 0.0.0.0.
        assert_eq!(
            restart_lan_listen(Some("0.0.0.0:7425"), "auto:7425".into()),
            "auto:7425"
        );
        assert_eq!(
            restart_lan_listen(Some("0.0.0.0:7420"), "auto".into()),
            "auto"
        );
        assert_eq!(
            restart_lan_listen(Some("0.0.0.0:7500"), "auto:7425".into()),
            "0.0.0.0:7500"
        );
        assert_eq!(
            restart_lan_listen(Some("127.0.0.1:7425"), "auto:7425".into()),
            "127.0.0.1:7425"
        );
    }

    #[test]
    fn a_second_profile_is_offered_the_next_port() {
        // 7421-7423 are RAVEN's own ports (mock BLE, Internet, libp2p).
        assert_eq!(alternative_listen("0.0.0.0:7420"), "0.0.0.0:7424");
        assert_eq!(alternative_listen("[::]:7420"), "[::]:7424");
        assert_eq!(alternative_listen("0.0.0.0:7424"), "0.0.0.0:7425");
        assert_eq!(alternative_listen("192.168.1.9:9000"), "192.168.1.9:9001");
        for odd in ["127.0.0.1:0", "0.0.0.0:65535", "not-an-address", ""] {
            assert_eq!(alternative_listen(odd), "0.0.0.0:7424", "{odd}");
        }
        assert!(listen_is_loopback("127.0.0.1:7420") && listen_is_loopback("localhost:7420"));
        assert!(!listen_is_loopback("0.0.0.0:7420") && !listen_is_loopback("192.168.1.9:7420"));
        // Phase 3 P3.6: `auto` stays `auto`, on the next port RAVEN does not
        // use itself, and is never this computer only.
        assert_eq!(alternative_listen("auto"), "auto:7424");
        assert_eq!(alternative_listen("auto:7420"), "auto:7424");
        assert_eq!(alternative_listen("auto:7424"), "auto:7425");
        assert_eq!(alternative_listen("AUTO:7426"), "auto:7428");
        assert_eq!(alternative_listen("auto:65535"), "auto:7424");
        for auto in ["auto", "auto:7424", "AUTO"] {
            assert!(!listen_is_loopback(auto), "{auto}");
        }
    }

    /// `auto` is said as what it is (every network of this computer), and a
    /// busy one names its port and offers `auto` on the next one.
    #[test]
    fn the_listener_messages_say_auto_in_words() {
        let log = Path::new("/p/raven-node-service.log");
        let warned = AtomicBool::new(false);
        let up = plain(&listener_message("auto", Some(true), log, &warned, None).unwrap());
        assert!(
            up.contains("receiving messages on every network of this computer, port 7420"),
            "{up}"
        );
        assert!(
            up.contains("other computers on your network can reach it"),
            "{up}"
        );
        let down = plain(&listener_message("auto:7424", Some(false), log, &warned, None).unwrap());
        for word in [
            "LAN port 7424 is busy or unavailable",
            "RAVEN_SERVICE_LAN_LISTEN=auto:7425",
        ] {
            assert!(down.contains(word), "{word:?} missing from: {down}");
        }
    }
}

#[cfg(test)]
mod slow_note_tests {
    use super::*;
    use std::sync::mpsc;

    type Sink = Box<dyn Fn(&str) + Send>;

    fn channel_sink() -> (mpsc::Receiver<String>, Sink) {
        let (tx, rx) = mpsc::channel();
        (rx, Box::new(move |m: &str| tx.send(m.to_string()).unwrap()))
    }

    #[test]
    fn it_speaks_when_the_work_outlasts_the_delay() {
        let (rx, emit) = channel_sink();
        let note = SlowNote::start_with(
            "sending to Bob ...".into(),
            Duration::from_millis(20),
            true,
            emit,
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10)).unwrap(),
            "sending to Bob ..."
        );
        drop(note);
    }

    #[test]
    fn it_stays_quiet_when_the_work_finishes_first() {
        let (rx, emit) = channel_sink();
        let note = SlowNote::start_with("sending ...".into(), Duration::from_secs(600), true, emit);
        let started = std::time::Instant::now();
        drop(note); // joins the helper thread: nothing can be printed afterwards
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert!(rx.try_recv().is_err());
    }

    /// A pipe or a log keeps exactly the output it had.
    #[test]
    fn it_never_speaks_when_stderr_is_not_a_terminal() {
        let (rx, emit) = channel_sink();
        let note = SlowNote::start_with("sending ...".into(), Duration::ZERO, false, emit);
        drop(note);
        assert!(rx.try_recv().is_err());
    }
}

#[cfg(test)]
mod chat_ux_tests {
    use super::*;

    /// G4: every line of a chat records the carrier choice and friend custody
    /// of the `ash send --chat` that opened it (`auto` and custody unless
    /// `--carrier lan`), and is still a chat transcript line for that contact.
    #[test]
    fn a_chat_line_records_what_the_chat_was_opened_with() {
        use raven_core::outbox::CarrierChoice;
        let dir = tempfile::tempdir().unwrap();
        let bob = hex::encode(Identity::from_seed(&[0x44; 32]).public_key_bytes());
        let ctx = chat_send_ctx(dir.path(), "Bob", "", &bob, CarrierChoice::Auto, true);
        assert!(ctx.chat);
        assert_eq!(ctx.choice, Some(CarrierChoice::Auto));
        assert!(ctx.custody_ok);
        assert_eq!(
            (ctx.name.as_str(), ctx.pub_hex.as_str()),
            ("Bob", bob.as_str())
        );
        assert_eq!(
            ctx.data_dir.as_deref(),
            Some(dir.path()),
            "the rest comes from send_ctx"
        );
        let ctx = chat_send_ctx(dir.path(), "Bob", "", &bob, CarrierChoice::Lan, false);
        assert!(ctx.chat);
        assert_eq!(ctx.choice, Some(CarrierChoice::Lan));
        assert!(!ctx.custody_ok);
    }

    #[test]
    fn bare_help_exit_and_quit_are_commands_not_messages() {
        use ChatInput::*;
        for (line, want) in [
            ("help", Help { bare: true }),
            ("?", Help { bare: true }),
            ("  HELP  ", Help { bare: true }),
            ("Exit", Leave { bare: true }),
            ("quit", Leave { bare: true }),
            ("/help", Help { bare: false }),
            ("/?", Help { bare: false }),
            ("/back", Leave { bare: false }),
            ("/quit", Leave { bare: false }),
            ("/q", Leave { bare: false }),
            ("/exit", Leave { bare: false }),
            ("/info", Command("/info")),
            ("/block now", Command("/block")),
            ("/nope", Command("/nope")),
            ("", Empty),
            ("   ", Empty),
        ] {
            assert_eq!(classify_chat_input(line), want, "{line:?}");
        }
        // Anything else is a message, including lines that merely contain those words.
        for line in [
            "help me",
            "hello",
            "quit smoking?",
            "exit 3",
            "?? what",
            "helpful",
            "سلام",
            "کمک",
        ] {
            assert_eq!(classify_chat_input(line), Send(line), "{line:?}");
        }
        assert_eq!(classify_chat_input("  padded  "), Send("padded"));
    }

    #[test]
    fn help_lists_every_command_and_names_the_person() {
        let help = chat_help_lines("Bob", "bob").join("\n");
        for command in [
            "/help",
            "/back",
            "/info",
            "/verify",
            "/block",
            "/clear-local-history",
        ] {
            assert!(help.contains(command), "{command} missing: {help}");
        }
        for word in [
            "quit",
            super::super::END_OF_INPUT,
            "Bob",
            "press Enter",
            "starts with /",
            "under about 1000 bytes",
            "ash send --contact @bob < message.txt",
        ] {
            assert!(help.contains(word), "{word} missing: {help}");
        }
        assert!(!help.contains("pub_hex"));
        // A contact without a tag still gets the pattern.
        assert!(chat_help_lines("Bob", "")
            .join("\n")
            .contains("ash send --contact @tag < message.txt"));
    }

    /// Privacy pack PP.8: `/clear-local-history` deletes the chat for good
    /// and says so in the UX copy's words; its help line says the friend
    /// keeps their copy.
    #[test]
    fn clearing_the_chat_says_it_is_deleted_from_this_computer() {
        let plain = |text: String| {
            text.replace(&C_GREEN.to_string(), "")
                .replace(&C_RESET.to_string(), "")
        };
        assert_eq!(
            plain(chat_cleared_text("Bob")),
            "cleared: your chat with Bob is deleted from this computer."
        );
        let help = chat_help_lines("Bob", "bob").join("\n");
        assert!(
            help.contains(
                "/clear-local-history   delete your chat with Bob from this computer (Bob keeps \
                 their copy)"
            ),
            "{help}"
        );
    }

    #[test]
    fn the_chat_names_the_person_never_64_hex_digits() {
        let key = "ab".repeat(32);
        assert_eq!(chat_name("Bob", "bob", &key), "Bob");
        assert_eq!(chat_name("", "@bob", &key), "@bob");
        let by_fp = chat_name("", "", &key);
        assert!(
            by_fp.starts_with("device ") && !by_fp.contains(&key),
            "{by_fp}"
        );
        assert_eq!(chat_name("", "", "zz"), "this contact");
        let hostile = chat_name("Bob\u{1b}[2J\nx", "", &key);
        assert!(
            hostile.starts_with("Bob") && !hostile.contains('\u{1b}') && !hostile.contains('\n'),
            "{hostile:?}"
        );
        assert_eq!(plain(&chat_header("Bob", "bob")), "chat with Bob @bob");
        assert_eq!(plain(&chat_header("@bob", "bob")), "chat with @bob");
        assert_eq!(plain(&chat_header("Bob", "")), "chat with Bob");
    }

    #[test]
    fn a_sent_line_is_echoed_with_what_happened_to_it() {
        let (echo, failure) = chat_echo("hello bob", &Ok(()), "Bob");
        let echo = plain(&echo);
        assert_eq!(echo, "  → hello bob  ✓ Bob confirmed receipt");
        assert_eq!(failure, None);

        let ctx = SendCtx {
            name: "Bob".into(),
            ..SendCtx::default()
        };
        let day = RetryNote {
            expires_at_ms: now_ms() + 24 * 60 * 60 * 1000,
            copy_expires_at_ms: 0,
            background: false,
            custodians: Vec::new(),
            carry_first: None,
        };
        let queued = queued_text(&ctx, "ipc LAN_DIAL: lan read timeout", "\"hi\"", &day);
        let kept = queued_text(
            &ctx,
            "ipc LAN_DIAL: lan read timeout",
            "\"hi\"",
            &RetryNote {
                background: true,
                ..day.clone()
            },
        );
        let unconfirmed = unconfirmed_text(&ctx, "no sealed ACK", "\"hi\"", &day);
        let refused = not_sent_text(&ctx, "ipc LAN_DIAL: early eof", false);
        for (text, marker, sentence) in [
            (
                queued,
                "[queued: goes out with your next message]",
                "not delivered yet",
            ),
            (
                kept,
                "[queued: raven-node keeps trying]",
                "not delivered yet",
            ),
            (
                unconfirmed,
                "[sent, not confirmed]",
                "sent, delivery unconfirmed",
            ),
            (refused, "[NOT SENT]", "NOT SENT"),
        ] {
            let (echo, failure) = chat_echo("hi there", &Err(text.clone()), "Bob");
            let echo = plain(&echo);
            assert_eq!(echo, format!("  → hi there  {marker}"));
            assert!(
                !echo.to_lowercase().contains("delivered"),
                "stdout never claims delivery for a message that was not confirmed: {echo}"
            );
            let failure = failure.expect("the sentence goes to stderr");
            assert_eq!(failure, text);
            assert!(failure.starts_with(sentence), "{failure}");
        }
        // A raw error from outside the send path is made friendly, not echoed raw.
        let (echo, failure) = chat_echo("hi", &Err("ipc LAN_DIAL: early eof".into()), "Bob");
        assert!(plain(&echo).ends_with("[NOT SENT]"));
        assert!(failure.unwrap().starts_with("NOT SENT: "));
        // The echoed text is neutralised like every peer- or user-supplied line.
        let (echo, _) = chat_echo("a\u{1b}[31mb\nc", &Ok(()), "Bob");
        assert!(!echo.contains('\u{1b}') && !echo.contains('\n'), "{echo:?}");
    }

    #[test]
    fn verify_says_what_it_does_and_what_it_does_not() {
        let fp = "H3si-4Bmu-hqJl";
        let words = "turtle frog bread wolf paper laptop funnel mango honey wagon";
        let cmd = "ash contact verify --address rvn1x";
        let unpinned = verify_lines("Bob", words, fp, Some(false), cmd);
        let text = plain(&unpinned.join("\n"));
        assert_eq!(
            text.lines().next().unwrap(),
            "Your security words (read all 10 to Bob)"
        );
        for word in [
            &format!("words       {words}"),
            "old-style code (for a friend with an older Raven): H3si-4Bmu-hqJl",
            "not in this chat",
            "This only shows yours; nothing is changed",
            "Bob is not marked verified yet",
            cmd,
        ] {
            assert!(text.contains(word), "{word:?} missing from: {text}");
        }
        let pinned = plain(&verify_lines("Bob", words, fp, Some(true), cmd).join("\n"));
        assert!(
            pinned.contains("already marked verified (pinned)"),
            "{pinned}"
        );
        assert!(!pinned.contains(cmd));
        let unknown = plain(&verify_lines("Bob", words, fp, None, cmd).join("\n"));
        assert!(!unknown.contains("verified"), "{unknown}");
        assert!(!unknown.contains(cmd));
    }

    /// `/verify` shows MY words and code, never the friend's: their check is
    /// blind (`contact verify`).
    #[test]
    fn chat_verify_shows_my_words_and_nothing_of_theirs() {
        let dir = tempfile::tempdir().unwrap();
        let me = Identity::from_seed(&[0x5a; 32]);
        let bob = Identity::from_seed(&[0x42; 32]);
        let bob_hex = hex::encode(bob.public_key_bytes());
        let text = plain(&chat_verify_lines(dir.path(), &me, &bob_hex, "Bob").join("\n"));
        let mine = security_words::words_v1(&me.public_key_bytes()).join(" ");
        assert!(text.contains(&mine), "{text}");
        assert!(text.contains(&device_fingerprint_v1(&me.public_key_bytes())));
        let theirs = security_words::words_v1(&bob.public_key_bytes());
        assert!(!text.contains(&theirs.join(" ")), "{text}");
        assert!(!text.contains(&device_fingerprint_v1(&bob.public_key_bytes())));
        // Not in the book: no command to mark them verified.
        assert!(!text.contains("contact verify"), "{text}");
        // /info hides an unverified friend's words too.
        let info = info_words(dir.path(), &bob_hex, &bob.public_key_bytes(), "Bob");
        assert_eq!(info, "(shown once you verify Bob: /verify)");
    }

    #[test]
    fn the_receiver_note_explains_why_replies_cannot_arrive() {
        let status = |caps: &[&str]| -> Result<IpcResponse, String> {
            Ok(IpcResponse::Status {
                v: IPC_VERSION,
                bridge: false,
                store: false,
                relay: false,
                forward_pending: 0,
                capabilities: caps.iter().map(|c| c.to_string()).collect(),
                p2p: None,
                pid: None,
                lan_listen: None,
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
            })
        };
        assert_eq!(
            classify_receiver(&status(&["ipc", "lan_direct"])),
            ReceiverState::Receiving
        );
        assert_eq!(
            classify_receiver(&status(&["ipc"])),
            ReceiverState::NotReceiving
        );
        assert_eq!(
            classify_receiver(&Err("raven-node is not running; start it with `ash listen` (nothing is listening at /x)".into())),
            ReceiverState::NotRunning
        );
        assert_eq!(
            classify_receiver(&Err(
                "raven-node did not answer in time: it is busy or stuck".into()
            )),
            ReceiverState::NotAnswering
        );
        assert_eq!(
            classify_receiver(&Ok(IpcResponse::Pong { v: IPC_VERSION })),
            ReceiverState::NotAnswering
        );
        assert_eq!(chat_receiver_note(ReceiverState::Receiving, "Bob"), None);
        let off = plain(&chat_receiver_note(ReceiverState::NotRunning, "Bob").unwrap());
        assert!(off.contains("replies from Bob cannot arrive yet"), "{off}");
        assert!(off.contains("ash listen"), "{off}");
        assert!(
            off.contains("when you send a message here"),
            "starts by itself on the first send: {off}"
        );
        let deaf = plain(&chat_receiver_note(ReceiverState::NotReceiving, "Bob").unwrap());
        assert!(deaf.contains("NOT receiving messages"), "{deaf}");
        assert!(deaf.contains("raven-node-service.log"), "{deaf}");
        let stuck = plain(&chat_receiver_note(ReceiverState::NotAnswering, "Bob").unwrap());
        assert!(stuck.contains("not answering"), "{stuck}");
    }

    /// The probe is read-only and bounded: a profile with no service answers at
    /// once and nothing is started.
    #[cfg(unix)]
    #[test]
    fn the_receiver_probe_never_starts_anything() {
        let dir = super::super::ipc_client::test_support::short_tempdir();
        let started = std::time::Instant::now();
        assert_eq!(
            receiver_state(dir.path(), Duration::from_millis(500)),
            ReceiverState::NotRunning
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert!(
            !daemon_log_path(dir.path()).exists(),
            "no service log: nothing was started"
        );
    }

    /// A line in the wrong encoding is dropped with a message; it does not end the
    /// session as if the user had quit, and the next line still reads.
    #[test]
    fn a_line_that_is_not_utf8_is_skipped_not_taken_for_quitting() {
        let mut input =
            io::Cursor::new(b"hello  \n\xed\xa1\xe4\xe3 \n  second line \nlast".to_vec());
        assert_eq!(read_line_from(&mut input), LineResult::Line("hello".into()));
        assert_eq!(read_line_from(&mut input), LineResult::BadInput);
        assert_eq!(
            read_line_from(&mut input),
            LineResult::Line("second line".into())
        );
        assert_eq!(read_line_from(&mut input), LineResult::Line("last".into()));
        assert_eq!(read_line_from(&mut input), LineResult::Eof);
        let mut persian = io::Cursor::new("سلام دنیا\n".as_bytes().to_vec());
        assert_eq!(
            read_line_from(&mut persian),
            LineResult::Line("سلام دنیا".into())
        );
    }

    #[test]
    fn an_unreadable_history_comes_with_a_way_out() {
        let dir = Path::new("/data");
        // As the OS writes it: `/data\chat_history.json` on Windows.
        let history = dir.join("chat_history.json").display().to_string();
        let corrupt = history_unavailable_text("chat history is corrupt", dir);
        for word in [
            "local protected history unavailable:",
            history.as_str(),
            "Your keys and contacts are not affected",
            "(technical: chat history is corrupt)",
        ] {
            assert!(corrupt.contains(word), "{word:?} missing from: {corrupt}");
        }
        let key = history_unavailable_text("protected chat-history key is missing", dir);
        assert!(key.contains("approve the Keychain window"), "{key}");
        assert_eq!(
            history_unavailable_text("chat history I/O failed: disk full", dir),
            "local protected history unavailable: chat history I/O failed: disk full"
        );
    }

    #[test]
    fn an_unusable_cursor_file_is_named_and_the_cost_of_moving_it_is_stated() {
        let dir = Path::new("/data");
        let cursors = dir.join("chat_inbox_cursors.json").display().to_string();
        let text = cursor_unavailable_text("inbox cursor corrupt: expected value", dir);
        for word in [
            "chat not opened",
            cursors.as_str(),
            "Your messages and contacts are not affected",
            "If you move that file aside",
            // The file also remembers cleared conversations: moving it brings
            // their old messages back, so that must be said, not hidden.
            "you cleared with /clear-local-history show their old messages again",
            "(technical: inbox cursor corrupt: expected value)",
        ] {
            assert!(text.contains(word), "{word:?} missing from: {text}");
        }
        assert!(!text.contains("safe to move"), "{text}");
    }

    #[test]
    fn the_background_reader_explains_a_history_problem_too() {
        let dir = Path::new("/data");
        let corrupt = inbox_problem_text("chat history is corrupt", dir);
        assert!(
            corrupt.starts_with("inbox: your local chat history cannot be opened"),
            "{corrupt}"
        );
        let history = dir.join("chat_history.json").display().to_string();
        assert!(corrupt.contains(&history), "{corrupt}");
        assert!(
            corrupt.contains("(technical: chat history is corrupt)"),
            "{corrupt}"
        );
        // Anything else is shown as it was.
        assert_eq!(inbox_problem_text("boom", dir), "inbox: boom");
    }

    #[test]
    fn blocking_asks_first_and_names_the_undo() {
        // The confirm itself reads the process stdin; the pieces around it are pure.
        let ctx = SendCtx {
            pub_hex: "cd".repeat(32),
            ..SendCtx::default()
        };
        assert_eq!(
            unblock_hint(&ctx),
            format!("To undo: ash contact unblock --pub-hex {}", "cd".repeat(32))
        );
        assert!(unblock_hint(&SendCtx::default()).contains("--pub-hex <their key>"));
    }
}

#[cfg(test)]
mod local_route_tests {
    use super::super::pair_init_lab::{DialCarrier, DialRoute};
    use super::*;
    use raven_core::CONTACT_NOT_VERIFIED;

    fn book(dir: &Path, peer: &[u8; 32], pinned: bool) {
        std::fs::write(
            dir.join("contacts.json"),
            format!(
                r#"[{{"petname":"Bob","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":{pinned},"lan_dial":""}}]"#,
                hex::encode(peer)
            ),
        )
        .unwrap();
    }

    fn lan(dial: &str) -> DialRoute {
        DialRoute {
            carrier: DialCarrier::Lan,
            dial: dial.into(),
        }
    }

    fn dials(routes: &[DialRoute]) -> Vec<String> {
        routes.iter().map(|r| r.dial.clone()).collect()
    }

    /// `raven send` to a verified contact whose saved LAN address came from
    /// a card and is not local: refused before any dial, in words that do
    /// not call the contact unverified. Typed here, the same address goes.
    #[test]
    fn a_verified_contacts_card_lan_address_is_used_only_locally() {
        let dir = tempfile::tempdir().unwrap();
        let peer = [0x5du8; 32];
        let row = |trusted: bool| {
            std::fs::write(
                dir.path().join("contacts.json"),
                format!(
                    r#"[{{"petname":"Bob","address":"","pub_hex":"{}","pinned":true,"lan_dial":"203.0.113.7:7420","lan_dial_trusted":{trusted}}}]"#,
                    hex::encode(peer)
                ),
            )
            .unwrap();
        };
        let ctx = SendCtx {
            name: "Bob".into(),
            ..SendCtx::default()
        };
        let routes = [lan("203.0.113.7:7420")];
        row(false);
        let err = local_dial_routes_with(dir.path(), &routes, &peer, &ctx, true).unwrap_err();
        assert!(err.contains("came from Bob's card"), "{err}");
        assert!(!err.contains("not verified"), "{err}");
        assert!(err.contains("Nothing was dialled"), "{err}");
        row(true);
        let (kept, _) = local_dial_routes_with(dir.path(), &routes, &peer, &ctx, true).unwrap();
        assert_eq!(dials(&kept), ["203.0.113.7:7420"]);
    }

    /// `raven outbox show` on a message held as CONTACT_NOT_VERIFIED: a
    /// contact with a LAN address saved was held because that address is not
    /// on the local network (cutoff F1 queues one whose name does not
    /// resolve, and the worker may then find it outside it), so the line
    /// says that and how to save a local one; "its only route is the
    /// Internet" only for a contact without one.
    #[test]
    fn a_held_lan_route_is_explained_as_off_the_local_network() {
        let dir = tempfile::tempdir().unwrap();
        let bob = Identity::from_seed(&[0x4b; 32]);
        let write = |lan: &str| {
            std::fs::write(
                dir.path().join("contacts.json"),
                serde_json::to_vec(&serde_json::json!([{
                    "petname": "Bob", "public_tag": "", "alias": "", "address": bob.address(),
                    "pub_hex": hex::encode(bob.public_key_bytes()), "pinned": false,
                    "lan_dial": lan
                }]))
                .unwrap(),
            )
            .unwrap();
        };
        let line = || {
            let ctx = send_ctx(dir.path(), "", "", &hex::encode(bob.public_key_bytes()));
            not_verified_line(dir.path(), &ctx)
        };
        write("bob-mac.local:7420");
        let lan = line();
        assert!(!lan.contains("only route is the Internet"), "{lan}");
        for words in [
            "Bob is not verified",
            "only at an address on your local network",
            "bob-mac.local:7420 is not one there",
            "ash contact set-dial --petname Bob --lan-dial IP:PORT",
            "raven contact verify --petname Bob",
        ] {
            assert!(lan.contains(words), "{words}: {lan}");
        }
        write("");
        let inet = line();
        assert!(
            inet.starts_with("Its only route is the Internet, which needs Bob verified"),
            "{inet}"
        );
        // Phase 3 P3.C2: under `raven lan verified-only on` the hold is that
        // setting's, whatever routes the book has.
        write("192.168.1.20:7420");
        raven_core::node_policy::set_lan_verified_only(dir.path(), true).unwrap();
        assert_eq!(
            line(),
            verified_only_words("Bob", &bob.public_key_bytes()),
            "{}",
            line()
        );
    }

    /// Phase 3 P3.C2: once the meeting time of `raven lan on --for` is over,
    /// LAN is off for a send as after `raven lan off` (raven-node turned it
    /// off); before it, or without one, as the policy says; a meeting time
    /// ash cannot read now changes nothing here, and one that will never
    /// open (B-7: damaged, another profile's) is off, as raven-node has it.
    #[test]
    fn lan_is_off_for_a_send_once_the_meeting_time_is_over() {
        use raven_core::at_rest::AtRestError;
        const T: u64 = 1_800_000_000_000;
        let not_now = || Err(AtRestError::KeyUnavailable("not loaded".into()));
        for (lan_off, meeting, off) in [
            (Some(false), Ok(None), false),
            (Some(true), Ok(None), true),
            (None, Ok(None), true),
            (Some(false), Ok(Some(T + 1)), false),
            (Some(false), Ok(Some(T)), true),
            (Some(false), Ok(Some(T - 60_000)), true),
            (Some(false), not_now(), false),
            (Some(true), not_now(), true),
            (Some(false), Err(AtRestError::Io("busy".into())), false),
            (Some(false), Err(AtRestError::Tampered { kind: 32 }), true),
            (
                Some(false),
                Ok(Some(T + raven_core::lan_meeting::MAX_MEETING_MS + 1)),
                true,
            ),
        ] {
            assert_eq!(
                lan_off_at(lan_off, &meeting, T),
                off,
                "{lan_off:?} {meeting:?}"
            );
        }
    }

    /// Phase 3 P3.C2: with `raven lan verified-only on` a send to an
    /// unverified contact is refused before anything is started or dialled
    /// (no raven-node is asked: its socket never appears), in the step's
    /// words with the local code; the refusal is outside the LAN-off path.
    #[test]
    fn with_verified_only_an_unverified_contact_is_refused_before_anything_starts() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let peer = [0x5eu8; 32];
        let ctx = SendCtx {
            name: "Bob".into(),
            ..SendCtx::default()
        };
        book(dd, &peer, false);
        raven_core::node_policy::set_lan_verified_only(dd, true).unwrap();
        let id = Identity::from_seed(&[0x5f; 32]);
        let err = deliver_routes(
            dd,
            &id,
            &[lan("192.168.1.20:7420")],
            &hex::encode(peer),
            "hi",
            &ctx,
        )
        .unwrap_err();
        assert_eq!(err, verified_only_text("Bob", &peer));
        assert!(err.starts_with("NOT SENT: Only verified friends can connect on this network"));
        assert!(
            !raven_core::default_socket_path(dd).exists(),
            "nothing started"
        );
        assert!(!dd.join(raven_core::outbox::OUTBOX_ROUTES_FILE).exists());
        assert_eq!(
            classify_cause(&err),
            Cause::Other,
            "its own words, not a dial's"
        );
    }

    /// L (`raven send` side): an unverified contact is dialled only when every
    /// address resolves to the local network (names are resolved first and the
    /// resolved literal is what gets dialled); one address outside it refuses the
    /// whole send before anything is dialled. A verified contact is unchanged.
    #[test]
    fn an_unverified_contact_is_dialled_only_at_local_network_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let peer = [0x5bu8; 32];
        let ctx = SendCtx {
            name: "Bob".into(),
            ..SendCtx::default()
        };
        book(dir.path(), &peer, false);

        let (ok, unresolved) = local_dial_routes(
            dir.path(),
            &[
                lan("192.168.1.20:7300"),
                lan("10.0.0.7:7300"),
                lan("[fe80::1%en0]:7300"),
            ],
            &peer,
            &ctx,
        )
        .unwrap();
        assert_eq!(
            dials(&ok),
            ["192.168.1.20:7300", "10.0.0.7:7300", "[fe80::1%en0]:7300"]
        );
        assert!(unresolved.is_empty());

        let (named, _) =
            local_dial_routes(dir.path(), &[lan("localhost:7300")], &peer, &ctx).unwrap();
        let addr: std::net::SocketAddr = named[0].dial.parse().expect("a resolved literal");
        assert!(addr.ip().is_loopback() && addr.port() == 7300, "{addr}");

        for public in ["203.0.113.5:7300", "100.64.1.2:7300", "[2001:db8::1]:7300"] {
            let err = local_dial_routes(dir.path(), &[lan(public)], &peer, &ctx).unwrap_err();
            assert!(err.starts_with("NOT SENT: Bob is not verified"), "{err}");
            assert!(err.contains("is not on your local network"), "{err}");
            assert!(err.contains("Nothing was dialled"), "{err}");
            assert!(err.contains(CONTACT_NOT_VERIFIED), "{err}");
        }
        // Every address must be local, not just the first.
        assert!(local_dial_routes(
            dir.path(),
            &[lan("192.168.1.20:7300"), lan("203.0.113.5:7300")],
            &peer,
            &ctx
        )
        .is_err());

        book(dir.path(), &peer, true);
        let (pinned, _) =
            local_dial_routes(dir.path(), &[lan("203.0.113.5:7300")], &peer, &ctx).unwrap();
        assert_eq!(dials(&pinned), ["203.0.113.5:7300"]);
    }

    /// Phase 3 P3.6, `raven lan off`: every LAN route of a send is kept as
    /// planned and fails at once with LAN_OFF (never dialled; a name is not
    /// even resolved); the other carriers' routes are as before; a literal
    /// address still gets the unverified-contact check. With LAN on nothing
    /// changes.
    #[test]
    fn with_lan_off_no_lan_route_is_dialled_or_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let peer = [0x5du8; 32];
        let ctx = SendCtx {
            name: "Bob".into(),
            ..SendCtx::default()
        };
        let internet = DialRoute {
            carrier: DialCarrier::Internet,
            dial: "203.0.113.9:7422".into(),
        };
        let lan_off = lan_off_probe_error();
        assert_eq!(
            lan_off,
            "LAN_OFF: raven lan off is in effect (raven lan on)"
        );
        assert_eq!(classify_cause(&lan_off), Cause::LanOff);
        assert_eq!(
            classify_cause(&format!("ipc LAN_OFF: {lan_off}")),
            Cause::LanOff
        );

        book(dir.path(), &peer, true);
        let routes = [
            lan(" 192.168.1.20:7420 "),
            lan("no-such-host.invalid:7420"),
            internet.clone(),
        ];
        let (kept, known) = send_dial_routes(dir.path(), &routes, &peer, &ctx, true).unwrap();
        assert_eq!(
            dials(&kept),
            [
                "192.168.1.20:7420",
                "no-such-host.invalid:7420",
                "203.0.113.9:7422"
            ]
        );
        assert_eq!(
            known,
            vec![(0, lan_off.clone()), (1, lan_off.clone())],
            "the LAN routes fail at once; the Internet one is probed"
        );
        // LAN on: exactly today's routes.
        assert_eq!(
            send_dial_routes(dir.path(), &routes, &peer, &ctx, false).unwrap(),
            local_dial_routes(dir.path(), &routes, &peer, &ctx).unwrap()
        );

        // An unverified contact: a name is not resolved (nothing asked of the
        // network, no refusal), a local literal passes, a public one is
        // refused as before.
        book(dir.path(), &peer, false);
        let (kept, known) = send_dial_routes(
            dir.path(),
            &[lan("no-such-host.invalid:7420"), lan("10.0.0.7:7420")],
            &peer,
            &ctx,
            true,
        )
        .unwrap();
        assert_eq!(dials(&kept), ["no-such-host.invalid:7420", "10.0.0.7:7420"]);
        assert_eq!(known, vec![(0, lan_off.clone()), (1, lan_off)]);
        let err = send_dial_routes(dir.path(), &[lan("203.0.113.5:7300")], &peer, &ctx, true)
            .unwrap_err();
        assert!(err.starts_with("NOT SENT: Bob is not verified"), "{err}");

        // What the send says, and the outcome's words for LAN_OFF.
        assert_eq!(
            lan_off_send_note("Bob", false),
            "LAN_OFF: LAN is off on this computer, so RAVEN does not connect to Bob on your \
             network (`raven lan on` turns LAN back on)."
        );
        assert!(lan_off_send_note("Bob", true)
            .contains("on your network and tries Bob's other addresses (`raven lan on`"));
        let text = not_sent_text(
            &ctx,
            "LAN_OFF: raven lan off is in effect (raven lan on)",
            true,
        );
        assert!(
            text.starts_with(
                "NOT SENT: LAN is off on this computer (`raven lan off`), so RAVEN does not \
                 connect to Bob on your network. Nothing was queued. Turn LAN back on with \
                 `raven lan on`, then send again."
            ),
            "{text}"
        );
    }

    /// A saved name that resolves nowhere (`.invalid` never does).
    const AWAY: &str = "no-such-host.invalid:7300";

    fn bob_unverified(dir: &Path) -> ([u8; 32], SendCtx) {
        let peer = [0x5cu8; 32];
        book(dir, &peer, false);
        let ctx = SendCtx {
            name: "Bob".into(),
            ..SendCtx::default()
        };
        (peer, ctx)
    }

    /// Cutoff F1 (CP.9), gate open: an unverified contact's saved name that
    /// does not resolve now is kept as planned (raven-node localizes it again
    /// at every dial), with the probe error raven-node would give for it, a
    /// name not found; a local literal beside it is dialled as before.
    #[test]
    fn an_unresolved_name_is_kept_with_its_probe_error_under_the_switch() {
        let dir = tempfile::tempdir().unwrap();
        let (peer, ctx) = bob_unverified(dir.path());
        let (kept, unresolved) = local_dial_routes_with(
            dir.path(),
            &[lan(&format!(" {AWAY} ")), lan("192.168.1.20:7300")],
            &peer,
            &ctx,
            true,
        )
        .unwrap();
        assert_eq!(dials(&kept), [AWAY, "192.168.1.20:7300"]);
        assert_eq!(unresolved.len(), 1, "{unresolved:?}");
        let (i, probe) = &unresolved[0];
        assert_eq!(*i, 0);
        assert!(
            probe.starts_with("lan connect: cannot resolve no-such-host.invalid: "),
            "{probe}"
        );
        assert_eq!(classify_cause(probe), Cause::NameNotFound, "{probe}");
        assert!(!probe.contains(CONTACT_NOT_VERIFIED), "{probe}");
        let shown = SendCtx {
            dial: AWAY.into(),
            ..ctx.clone()
        };
        assert_eq!(unresolved_name(&shown, probe), "no-such-host.invalid");
    }

    /// Gate closed: exactly today's refusal, byte for byte, and nothing kept.
    #[test]
    fn unverified_unresolved_name_is_today_with_the_gate_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (peer, ctx) = bob_unverified(dir.path());
        let err = local_dial_routes_with(dir.path(), &[lan(AWAY)], &peer, &ctx, false).unwrap_err();
        let e = match raven_core::outbox::localize_lan_route(
            &raven_core::OutboxRoute {
                carrier: raven_core::OutboxCarrier::Lan,
                dial: AWAY.into(),
            },
            false,
            raven_core::outbox::LOCALIZE_RESOLVE_TIMEOUT,
        ) {
            Err(raven_core::outbox::RouteRefusal::Unresolved(e)) => e,
            other => panic!("{other:?}"),
        };
        let today = super::super::pair_init_lab::unverified_remote_lan_text(
            "Bob",
            &format!(
                "{AWAY} could not be resolved ({}), so RAVEN cannot tell it is on your local \
                 network",
                sanitize_terminal_line(&e)
            ),
            &format!("raven contact verify --address {}", encode_address(&peer)),
            &super::super::pair_init_lab::pin_command_hint(&peer),
        );
        assert_eq!(err, today);
        assert!(err.contains(CONTACT_NOT_VERIFIED), "{err}");
        assert!(err.contains("Nothing was dialled"), "{err}");
    }

    /// Gate open or closed: an address off the local network and a malformed
    /// one still refuse the whole send, before anything is dialled, even
    /// beside a name that is kept.
    #[test]
    fn a_not_local_literal_is_still_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (peer, ctx) = bob_unverified(dir.path());
        for live in [false, true] {
            for (dial, why) in [
                ("203.0.113.5:7300", "is not on your local network"),
                ("[2001:db8::1]:7300", "is not on your local network"),
                ("bob-mac.local:http", "could not be resolved (bad port)"),
                (
                    "[fe80::zz%en0]:7300",
                    "could not be resolved (bad scoped IPv6)",
                ),
            ] {
                // Open, a kept name before it changes nothing.
                let beside = [vec![lan(dial)], vec![lan(AWAY), lan(dial)]];
                for routes in &beside[..if live { 2 } else { 1 }] {
                    let err =
                        local_dial_routes_with(dir.path(), routes, &peer, &ctx, live).unwrap_err();
                    assert!(err.starts_with("NOT SENT: Bob is not verified"), "{err}");
                    assert!(err.contains(why), "{live} {dial}: {err}");
                    assert!(err.contains(CONTACT_NOT_VERIFIED), "{err}");
                }
            }
        }
        // A verified contact's name is not resolved here at all.
        book(dir.path(), &peer, true);
        for live in [false, true] {
            let (kept, unresolved) =
                local_dial_routes_with(dir.path(), &[lan(AWAY)], &peer, &ctx, live).unwrap();
            assert_eq!(
                (dials(&kept), unresolved.len()),
                (vec![AWAY.to_string()], 0)
            );
        }
    }

    /// Privacy pack PP.4 (review R23): a book this process cannot open (its
    /// key not loaded) is an error of the line that needed it, never "no
    /// contact", "not verified" or a guess about its routes; the send's name
    /// label alone stays unknown.
    #[test]
    fn quiet_readers_fail_their_operation_on_key_unavailable() {
        let lab = ["RAVEN_CHAT_HISTORY_BACKEND", "RAVEN_IDENTITY_BACKEND"]
            .iter()
            .any(|k| std::env::var(k).is_ok_and(|v| v == "locked-file"));
        // Windows: the key is DPAPI-wrapped for this user, never a prompt.
        if !(cfg!(windows) || (cfg!(debug_assertions) && lab)) {
            eprintln!("skipped: needs a debug build and RAVEN_CHAT_HISTORY_BACKEND=locked-file");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        std::fs::write(dd.join(raven_core::BACKEND_MARKER_NAME), b"locked-file\n").unwrap();
        let me = Identity::from_seed(&[0x5b; 32]);
        let bob = Identity::from_seed(&[0x4c; 32]);
        let bob_hex = hex::encode(bob.public_key_bytes());
        let row = serde_json::json!({
            "petname": "Bob", "address": bob.address(), "pub_hex": bob_hex,
            "pinned": true, "lan_dial": "192.168.1.20:7420"
        });
        raven_core::contact_book::write_rows(dd, &[row]).unwrap();
        let report = raven_core::privacy::migrate_all(
            dd,
            now_ms(),
            raven_core::at_rest::MigratePolicy::Allow,
        )
        .unwrap();
        assert_eq!(report.outcome, raven_core::privacy::MigrateOutcome::Sealed);
        // The control: with the key, every reader knows Bob.
        assert!(contact_for_key(dd, &bob_hex)
            .unwrap()
            .is_some_and(|c| c.pinned));
        let words = security_words::words_v1(&bob.public_key_bytes()).join(" ");
        assert_eq!(
            info_words(dd, &bob_hex, &bob.public_key_bytes(), "Bob"),
            words
        );
        assert_eq!(send_ctx(dd, "", "", &bob_hex).name, "Bob");
        // This process lost the key (another binary sealed it, say).
        raven_core::at_rest::forget_cached_keys(dd);
        let sentence = raven_core::privacy::KEY_UNAVAILABLE_TEXT;
        assert_eq!(
            contact_for_key(dd, &bob_hex).err().as_deref(),
            Some(sentence)
        );
        assert_eq!(
            info_words(dd, &bob_hex, &bob.public_key_bytes(), "Bob"),
            sentence
        );
        assert_eq!(chat_verify_lines(dd, &me, &bob_hex, "Bob"), [sentence]);
        let ctx = send_ctx(dd, "", "", &bob_hex);
        assert_eq!(
            ctx.name, "",
            "a label only: unknown, never \"not a contact\""
        );
        assert_eq!(not_verified_line(dd, &ctx), sentence);
        assert_eq!(load_local_contacts(dd).err().as_deref(), Some(sentence));
    }
}

#[cfg(test)]
mod lock_tests {
    use super::*;

    /// Privacy pack PP.15 (review R16): while `raven lock` holds, the send
    /// path refuses before anything is started (no service log, no spawn);
    /// once unlocked, nothing refuses.
    #[test]
    fn send_while_locked_does_not_start_the_node() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        std::fs::write(dd.join(raven_core::BACKEND_MARKER_NAME), b"locked-file\n").unwrap();
        assert_eq!(auto_start_refusal(dd), None);
        raven_core::privacy::set_locked(dd, None).unwrap();
        // Checked first: nothing below may get as far as a start.
        assert_eq!(
            auto_start_refusal(dd),
            Some("Raven is locked. Run `raven unlock` to start it again.")
        );
        assert_eq!(
            require_local_daemon(dd).unwrap_err(),
            "NOT SENT, nothing queued: Raven is locked. Run `raven unlock` to start it again."
        );
        assert_eq!(
            ensure_mac_lan_daemon(dd).unwrap_err(),
            raven_core::privacy::LOCKED_TEXT
        );
        assert!(
            !daemon_log_path(dd).exists(),
            "no start was tried (it opens the service log first)"
        );
        raven_core::privacy::set_unlocked(dd).unwrap();
        assert_eq!(auto_start_refusal(dd), None);
    }

    /// Privacy pack PP.16: while an erase is unfinished the send path (and
    /// the terminal app's start) refuses before anything is started; the
    /// marker wins over a lock.
    #[test]
    fn send_during_an_unfinished_erase_does_not_start_the_node() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        std::fs::write(dd.join(raven_core::BACKEND_MARKER_NAME), b"locked-file\n").unwrap();
        raven_core::privacy::set_locked(dd, None).unwrap();
        raven_core::erase::begin(dd).unwrap();
        assert_eq!(
            auto_start_refusal(dd),
            Some(raven_core::erase::UNFINISHED_TEXT)
        );
        assert_eq!(
            require_local_daemon(dd).unwrap_err(),
            format!(
                "NOT SENT, nothing queued: {}",
                raven_core::erase::UNFINISHED_TEXT
            )
        );
        assert!(!daemon_log_path(dd).exists(), "no start was tried");
        raven_core::erase::abandon(dd).unwrap();
        assert_eq!(
            auto_start_refusal(dd),
            Some(raven_core::privacy::LOCKED_TEXT)
        );
    }
}
