//! Stopping this profile's raven-node, and Raven's own login item (privacy
//! pack PP.15, Lock now v1).
//!
//! - The stop step ([`stop_plan`], [`carry_out_stop`], [`stop`]): the
//!   terminal app's (UXF.7, OD-16), moved here from tui/node.rs so that
//!   `raven lock` and the app's Lock stop a node the same way; the app runs
//!   it from here through tui/bridge.rs. A Status taken just before says
//!   which process runs; on Unix it gets SIGTERM (its graceful stop), on
//!   Windows `taskkill /F` only when this app started it (the pipe is per
//!   user there, so another profile's node answers it too), and otherwise
//!   the user is told how.
//! - Raven's own login item ([`own_login_item`]). The installers create ONE
//!   per OS user, not per profile: macOS
//!   `~/Library/LaunchAgents/com.raven.raven-node.plist` (label
//!   `com.raven.raven-node`, `RunAtLoad` and `KeepAlive`), Linux
//!   `~/.config/systemd/user/raven-node.service` (always `~/.config`: the
//!   installer ignores XDG_CONFIG_HOME; `Restart=on-failure`), Windows the
//!   per-user scheduled task `RavenNodeBridge` (at logon, restart count 999).
//!   It is this profile's only when it runs `raven-node service` with a
//!   `--data-dir` that canonicalizes to this data dir. Anything else
//!   (another profile's item, a service someone else wrote) is "a service
//!   Raven didn't install for this profile" and is never touched.
//! - What Lock, unlock and erase do to it ([`stop_for_session`],
//!   [`disable_login_item`], [`enable_login_item`], [`remove_login_item`];
//!   review R16, PP.16). launchd's
//!   KeepAlive starts a killed node again within about 10 s, so stopping a
//!   node Raven's own item runs always unloads the job for this login
//!   session (`launchctl bootout`); "keep stopped" also disables it, which
//!   lasts across logins. Linux: `systemctl --user stop` / `disable --now` /
//!   `enable --now`. Windows: `schtasks /End`, `/Change /DISABLE`,
//!   `/Change /ENABLE` and `/Run`. Every tool runs by absolute path, never a
//!   PATH lookup (Linux falls back to one only when systemctl is in neither
//!   standard place), with no input and no shell.
//!
//! A debug build reads and runs none of the real ones: only with
//! `RAVEN_LAB_LOGIN_ITEM_ROOT` (the folder that stands in for the item's)
//! and `RAVEN_LAB_LOGIN_ITEM_TOOLS` (where fake `launchctl` / `systemctl` /
//! `schtasks.exe` live) set, else it refuses ([`LoginEnv::current`]), so no
//! test touches a real login item. A release build never reads them.

use std::ffi::{OsStr, OsString};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use raven_core::ipc::{IpcRequest, IpcResponse};
use raven_core::lan_gate::{LAB_LOGIN_ITEM_ROOT, LAB_LOGIN_ITEM_TOOLS};
use raven_core::sanitize::sanitize_terminal_line;

use super::{ext, ipc_client};

/// How long one Status may take: a healthy node answers at once.
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
/// How long a stopped node may take to stop answering.
const STOP_WAIT: Duration = Duration::from_secs(3);
const STOP_POLL: Duration = Duration::from_millis(100);
const STOP_PING: Duration = Duration::from_millis(500);

// ── The stop step (OD-16; UXF.7) ────────────────────────────────────────────

/// How a stop the user asked for is carried out (OD-16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StopPlan {
    /// SIGTERM to the pid this profile's own Status reports (Unix): its
    /// graceful stop. The endpoint is per profile there, so it is this
    /// profile's node.
    Terminate(u32),
    /// `taskkill /F` (Windows, which has no graceful stop): only a pid this
    /// app started that a Status taken just now still reports. The pipe is
    /// per user there, so another profile's node answers it too.
    TaskKill(u32),
    /// Say how instead (ext.rs's `profile_stop_advice`, with this pid).
    Advise(Option<u32>),
    /// A login service runs it.
    Managed,
    NotRunning,
}

/// The stop rules: never a login service; on Unix the pid Status reports; on
/// Windows only a pid this app started, still reported.
pub(super) fn stop_plan(
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

/// How a stop went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum StopOutcome {
    Stopped,
    /// Told to stop, but it still answers after a few seconds.
    StillRunning,
    /// How to stop it by hand.
    Advice(String),
    /// A login service runs it.
    Managed,
    NotRunning,
    /// The signal or taskkill failed.
    Failed(String),
}

/// Carries out `plan` for this profile's node, then waits up to
/// [`STOP_WAIT`] for it to stop answering.
pub(super) fn carry_out_stop(data_dir: &Path, plan: StopPlan) -> StopOutcome {
    match plan {
        StopPlan::Terminate(pid) => match terminate(pid) {
            Ok(()) => wait_stopped(data_dir),
            Err(e) => StopOutcome::Failed(e.to_string()),
        },
        StopPlan::TaskKill(pid) => match task_kill(pid) {
            Ok(()) => wait_stopped(data_dir),
            Err(e) => StopOutcome::Failed(e.to_string()),
        },
        StopPlan::Advise(pid) => StopOutcome::Advice(ext::profile_stop_advice(data_dir, pid)),
        StopPlan::Managed => StopOutcome::Managed,
        StopPlan::NotRunning => StopOutcome::NotRunning,
    }
}

/// The profile's raven-node now: one Status, [`PROBE_TIMEOUT`] at most.
fn status(data_dir: &Path) -> Result<IpcResponse, String> {
    ipc_client::ipc_request_timeout(data_dir, &IpcRequest::status(), PROBE_TIMEOUT)
}

/// Whether a Status answer (or its error) says a node runs, and its pid. A
/// node that took the request and never answered runs too.
fn running_pid(status: &Result<IpcResponse, String>) -> (bool, Option<u32>) {
    match status {
        Ok(IpcResponse::Status { pid, .. }) => (true, *pid),
        Err(e) if ipc_client::error_means_not_running(e) => (false, None),
        _ => (true, None),
    }
}

/// The CLI's stop (`raven lock`): a Status taken just now, then
/// [`stop_plan`] for a node no login service runs (Raven's own login item
/// is unloaded before this) and that this process did not start. Also says
/// which pid the Status reported.
pub(super) fn stop(data_dir: &Path) -> (StopOutcome, Option<u32>) {
    stop_as(data_dir, None)
}

/// [`stop`] for a node this process may have started (`started_by_app`:
/// the terminal app's, which Windows may end; Phase 6 P6.47's install).
pub(super) fn stop_as(data_dir: &Path, started_by_app: Option<u32>) -> (StopOutcome, Option<u32>) {
    let (running, pid) = running_pid(&status(data_dir));
    let plan = stop_plan(cfg!(windows), false, running, pid, started_by_app);
    (carry_out_stop(data_dir, plan), pid)
}

/// Sends SIGTERM to one process: raven-node's graceful stop. Refuses 0 and
/// ids above `i32::MAX`, which kill(2) would take as a process group or as
/// every process the user owns. Unix only: Windows has no graceful stop, and
/// taskkill runs there instead.
#[cfg(unix)]
pub(super) fn kill_term(pid: u32) -> io::Result<()> {
    use std::ffi::c_int;
    extern "C" {
        // pid_t is a 32-bit int on every Unix Raven builds for.
        fn kill(pid: i32, sig: c_int) -> c_int;
    }
    // The same value on Linux, macOS and the BSDs.
    const SIGTERM: c_int = 15;
    let pid = match i32::try_from(pid) {
        Ok(pid) if pid > 0 => pid,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{pid} is not the id of a single process"),
            ))
        }
    };
    // SAFETY: kill(2) takes plain integers and touches no memory; `pid` is
    // positive, so it names one process, never a group.
    if unsafe { kill(pid, SIGTERM) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn terminate(pid: u32) -> io::Result<()> {
    kill_term(pid)
}

#[cfg(not(unix))]
fn terminate(pid: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("no graceful stop for process {pid} here"),
    ))
}

/// A Windows tool by absolute path, `%SystemRoot%\System32\<tool>`: never a
/// PATH lookup, so a program planted next to Raven is never run. None when
/// SystemRoot is unset or not absolute.
pub(super) fn system_tool(system_root: Option<&OsStr>, tool: &str) -> Option<PathBuf> {
    let root = Path::new(system_root?);
    root.is_absolute().then(|| root.join("System32").join(tool))
}

/// `%SystemRoot%\System32\taskkill.exe /F /PID <pid>`, with no input or
/// output.
fn task_kill(pid: u32) -> io::Result<()> {
    let taskkill = system_tool(std::env::var_os("SystemRoot").as_deref(), "taskkill.exe")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "SystemRoot is not set"))?;
    let status = Command::new(taskkill)
        .args(["/F", "/PID", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("taskkill ended with {status}")))
    }
}

/// Pings until the node stops answering, [`STOP_WAIT`] at most.
fn wait_stopped(data_dir: &Path) -> StopOutcome {
    let deadline = Instant::now() + STOP_WAIT;
    loop {
        if !ipc_client::ipc_daemon_up_within(data_dir, STOP_PING) {
            return StopOutcome::Stopped;
        }
        if Instant::now() >= deadline {
            return StopOutcome::StillRunning;
        }
        std::thread::sleep(STOP_POLL);
    }
}

/// Whether this profile's node is gone: it answers no Ping and (Unix) no
/// process holds its instance lock.
pub(super) fn node_gone(data_dir: &Path) -> bool {
    !ipc_client::ipc_daemon_up_within(data_dir, STOP_PING) && !ext::instance_lock_held(data_dir)
}

/// Whether the node is gone, after waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Gone {
    Yes,
    /// It still runs: the pid its Status reports now, if it says.
    No {
        pid: Option<u32>,
    },
}

/// Waits up to `wait` for [`node_gone`] (`raven lock` confirms its stop
/// with 5 s).
pub(super) fn wait_gone(data_dir: &Path, wait: Duration) -> Gone {
    let deadline = Instant::now() + wait;
    loop {
        if node_gone(data_dir) {
            return Gone::Yes;
        }
        if Instant::now() >= deadline {
            return Gone::No {
                pid: running_pid(&status(data_dir)).1,
            };
        }
        std::thread::sleep(STOP_POLL);
    }
}

/// Whether a node answers for this profile now.
pub(super) fn node_answers(data_dir: &Path) -> bool {
    ipc_client::ipc_daemon_up_within(data_dir, STOP_PING)
}

// ── Raven's own login item (review R16) ─────────────────────────────────────

/// launchd's label for the agent macos_launchd.sh installs.
const LAUNCHD_LABEL: &str = "com.raven.raven-node";
/// The agent's file, in `~/Library/LaunchAgents`.
const LAUNCH_AGENT_FILE: &str = "com.raven.raven-node.plist";
/// The systemd user unit linux_systemd_user.sh installs, in
/// `~/.config/systemd/user`.
const SYSTEMD_UNIT: &str = "raven-node.service";
/// The per-user scheduled task windows_service.ps1 registers.
pub(super) const SCHEDULED_TASK: &str = "RavenNodeBridge";
/// The task's definition in the lab folder (a real one is asked of the
/// scheduler: `schtasks /Query /XML`).
const SCHEDULED_TASK_LAB_FILE: &str = "RavenNodeBridge.xml";
/// Far larger than any item the installers write; a bigger one is not ours.
const MAX_ITEM_BYTES: u64 = 256 * 1024;
/// What a debug build says without both lab switches.
pub(super) const LAB_GUARD_TEXT: &str = "this debug build does not read or change login items \
     unless RAVEN_LAB_LOGIN_ITEM_ROOT and RAVEN_LAB_LOGIN_ITEM_TOOLS are set (lab switches): a \
     release build uses the real ones";

/// The system a login item belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Platform {
    /// launchd (a launch agent).
    MacOs,
    /// systemd (a user unit): every Unix other than macOS.
    Linux,
    /// The task scheduler.
    Windows,
}

impl Platform {
    /// This build's.
    pub(super) const THIS: Platform = if cfg!(windows) {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::MacOs
    } else {
        Platform::Linux
    };

    /// The tool that acts on the item.
    fn tool_name(self) -> &'static str {
        match self {
            Platform::MacOs => "launchctl",
            Platform::Linux => "systemctl",
            Platform::Windows => "schtasks.exe",
        }
    }

    /// The item's file in its folder (the lab's task definition on Windows).
    pub(super) fn item_file(self) -> &'static str {
        match self {
            Platform::MacOs => LAUNCH_AGENT_FILE,
            Platform::Linux => SYSTEMD_UNIT,
            Platform::Windows => SCHEDULED_TASK_LAB_FILE,
        }
    }
}

/// Where Raven's login item lives and which tool acts on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LoginEnv {
    platform: Platform,
    /// The folder that holds the item's file (`~/Library/LaunchAgents`,
    /// `~/.config/systemd/user`, or the lab's). None: a real Windows, where
    /// the scheduler is asked.
    folder: Option<PathBuf>,
    /// launchctl, systemctl or schtasks.exe.
    tool: PathBuf,
    /// launchd's domain is `gui/<uid>`.
    uid: u32,
}

impl LoginEnv {
    /// This process's: the real folder and tool in a release build; in a
    /// debug build the lab's, and only with both lab switches set (the
    /// guard), so no debug build or test reads or changes a real login item.
    pub(super) fn current() -> Result<LoginEnv, String> {
        LoginEnv::resolve(
            cfg!(debug_assertions),
            raven_core::p2p_gate::lab_switch(LAB_LOGIN_ITEM_ROOT),
            raven_core::p2p_gate::lab_switch(LAB_LOGIN_ITEM_TOOLS),
            Platform::THIS,
            std::env::var_os("HOME"),
            std::env::var_os("SystemRoot"),
            current_uid(),
        )
    }

    /// [`LoginEnv::current`]'s rule. `debug`: whether this is a debug build;
    /// `root`, `tools`: the lab switches (a release build passes None and
    /// never uses them).
    fn resolve(
        debug: bool,
        root: Option<String>,
        tools: Option<String>,
        platform: Platform,
        home: Option<OsString>,
        system_root: Option<OsString>,
        uid: u32,
    ) -> Result<LoginEnv, String> {
        if debug {
            let absolute = |dir: Option<String>| {
                dir.map(PathBuf::from)
                    .filter(|dir| dir.is_absolute())
                    .ok_or_else(|| LAB_GUARD_TEXT.to_owned())
            };
            let (root, tools) = (absolute(root)?, absolute(tools)?);
            return Ok(LoginEnv {
                platform,
                folder: Some(root),
                tool: tools.join(platform.tool_name()),
                uid,
            });
        }
        let home = home.map(PathBuf::from).filter(|home| home.is_absolute());
        let (folder, tool) = match platform {
            Platform::MacOs => (
                Some(
                    home.ok_or("no home folder: Raven's login item can't be found")?
                        .join("Library/LaunchAgents"),
                ),
                PathBuf::from("/bin/launchctl"),
            ),
            Platform::Linux => (
                Some(
                    home.ok_or("no home folder: Raven's login item can't be found")?
                        .join(".config/systemd/user"),
                ),
                ["/usr/bin/systemctl", "/bin/systemctl"]
                    .into_iter()
                    .map(PathBuf::from)
                    .find(|tool| tool.is_file())
                    .unwrap_or_else(|| PathBuf::from("systemctl")),
            ),
            Platform::Windows => (
                None,
                system_tool(system_root.as_deref(), "schtasks.exe")
                    .ok_or("SystemRoot is not set: the task scheduler can't be asked")?,
            ),
        };
        Ok(LoginEnv {
            platform,
            folder,
            tool,
            uid,
        })
    }

    /// A lab env (tests): the item's file in `root`, the fake tool in
    /// `tools`.
    #[cfg(test)]
    pub(super) fn lab(platform: Platform, root: &Path, tools: &Path, uid: u32) -> LoginEnv {
        LoginEnv {
            platform,
            folder: Some(root.to_path_buf()),
            tool: tools.join(platform.tool_name()),
            uid,
        }
    }

    /// launchd's name for the agent in this user's GUI domain.
    fn launchd_target(&self) -> String {
        format!("gui/{}/{LAUNCHD_LABEL}", self.uid)
    }
}

/// The real user id, for launchd's `gui/<uid>` domain (what `id -u` prints).
#[cfg(unix)]
fn current_uid() -> u32 {
    extern "C" {
        fn getuid() -> u32;
    }
    // SAFETY: getuid(2) takes no arguments, cannot fail and touches no memory.
    unsafe { getuid() }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

/// Raven's own login item for this profile ([`own_login_item`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LoginItem {
    platform: Platform,
    /// The agent's plist, the unit, or the lab's task definition; None for a
    /// real scheduled task.
    file: Option<PathBuf>,
}

impl LoginItem {
    /// The system it belongs to (the terminal app names it, PP.23).
    pub(super) fn platform(&self) -> Platform {
        self.platform
    }
}

/// Raven's OWN login item, when it runs THIS profile: the installer's item
/// is there, runs `raven-node service`, and its `--data-dir` canonicalizes
/// to `data_dir`. None for no item, an item for another profile, an item
/// someone else wrote, or one that can't be read. Read-only.
pub(super) fn own_login_item(env: &LoginEnv, data_dir: &Path) -> Option<LoginItem> {
    let (text, file) = match &env.folder {
        Some(folder) => {
            let file = folder.join(env.platform.item_file());
            (read_capped(&file)?, Some(file))
        }
        None => (scheduled_task_xml(&env.tool)?, None),
    };
    let dir = item_data_dir(env.platform, &text)?;
    same_dir(Path::new(&dir), data_dir).then_some(LoginItem {
        platform: env.platform,
        file,
    })
}

/// The `--data-dir` of the `raven-node service` an item's text runs, as the
/// installer wrote it: a launch agent's plist, a systemd unit, or a task's
/// XML definition. None when the text is not one of Raven's.
pub(super) fn item_data_dir(platform: Platform, text: &str) -> Option<String> {
    service_data_dir(&item_argv(platform, text)?)
}

/// The address Raven's OWN login item for this profile ([`own_login_item`])
/// gives raven-node's LAN listener (`--lan-listen`), as the installer wrote
/// it. A value that names a port (`auto:PORT`, `IP:PORT`) keeps that port
/// at every start, whatever port the profile picks later (`raven lan port
/// random`; Phase 6 review traffic-5); a plain `auto` follows the profile.
/// None for no own item, one that can't be read, or one without the flag.
/// Read-only.
pub(super) fn own_item_lan_listen(env: &LoginEnv, data_dir: &Path) -> Option<String> {
    let text = match &env.folder {
        Some(folder) => read_capped(&folder.join(env.platform.item_file()))?,
        None => scheduled_task_xml(&env.tool)?,
    };
    let argv = item_argv(env.platform, &text)?;
    let dir = service_data_dir(&argv)?;
    if !same_dir(Path::new(&dir), data_dir) {
        return None;
    }
    let at = argv.iter().position(|arg| arg == "--lan-listen")?;
    argv.get(at + 1).filter(|value| !value.is_empty()).cloned()
}

/// The command line an item's text runs (see [`item_data_dir`]). None when
/// the text is not one of Raven's.
fn item_argv(platform: Platform, text: &str) -> Option<Vec<String>> {
    let argv = match platform {
        Platform::MacOs => {
            if xml_string(after_key(text, "Label")?)? != LAUNCHD_LABEL {
                return None;
            }
            let array = after_key(text, "ProgramArguments")?.strip_prefix("<array>")?;
            let array = &array[..array.find("</array>")?];
            let mut argv = Vec::new();
            let mut rest = array.trim_start();
            while !rest.is_empty() {
                let end = rest.find("</string>")?;
                argv.push(xml_string(rest)?);
                rest = rest[end + "</string>".len()..].trim_start();
            }
            argv
        }
        Platform::Linux => {
            let line = text
                .lines()
                .map(str::trim)
                .find_map(|line| line.strip_prefix("ExecStart="))?;
            systemd_words(line)?
        }
        Platform::Windows => {
            let command = xml_element(text, "Command")?;
            let mut argv = vec![command.trim_matches('"').to_owned()];
            argv.extend(windows_words(&xml_element(text, "Arguments")?)?);
            argv
        }
    };
    Some(argv)
}

/// The passphrase file Raven's own systemd unit hands raven-node for a
/// passphrase-vault profile (review D-lock-tui-3): the path of its
/// `Environment="RAVEN_KEYSTORE_PASSPHRASE_FILE=<path>"` line, else of its
/// `LoadCredential=raven-keystore-passphrase:<path>` line (raven-node reads
/// the variable first), as linux_systemd_user.sh writes them. Only an
/// absolute path; whether the file is there is the caller's to check. None
/// for the other systems' items, whose installers take no passphrase file.
/// Read-only.
pub(super) fn item_passphrase_file(item: &LoginItem) -> Option<PathBuf> {
    if item.platform != Platform::Linux {
        return None;
    }
    unit_passphrase_file(&read_capped(item.file.as_deref()?)?)
}

/// [`item_passphrase_file`] of a unit's text. Absolute means a Unix path
/// here (a unit is a Linux file), whatever system reads it.
fn unit_passphrase_file(text: &str) -> Option<PathBuf> {
    use raven_core::keystore_vault::{PASSPHRASE_FILE_ENV, SYSTEMD_CREDENTIAL_NAME};
    let absolute = |path: &str| path.starts_with('/').then(|| PathBuf::from(path));
    let (mut named, mut credential) = (None, None);
    for line in text.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("Environment=") {
            let words = systemd_words(value).unwrap_or_default();
            let prefix = format!("{PASSPHRASE_FILE_ENV}=");
            named = words
                .iter()
                .rev()
                .find_map(|word| word.strip_prefix(&prefix))
                .map(absolute)
                .unwrap_or(named);
        } else if let Some(value) = line.strip_prefix("LoadCredential=") {
            if let Some((_, path)) = value
                .split_once(':')
                .filter(|(id, _)| *id == SYSTEMD_CREDENTIAL_NAME)
            {
                credential = absolute(path.trim());
            }
        }
    }
    named.or(credential)
}

/// The data dir of `raven-node service ... --data-dir DIR ...`.
fn service_data_dir(argv: &[String]) -> Option<String> {
    let program = argv.first()?;
    let name = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase();
    if !matches!(name.as_str(), "raven-node" | "raven-node.exe") || argv.get(1)? != "service" {
        return None;
    }
    let at = argv.iter().position(|arg| arg == "--data-dir")?;
    argv.get(at + 1).filter(|dir| !dir.is_empty()).cloned()
}

/// The text after a plist `<key>KEY</key>`, its leading space trimmed.
fn after_key<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let tag = format!("<key>{key}</key>");
    let at = text.find(&tag)? + tag.len();
    Some(text[at..].trim_start())
}

/// The value of the `<string>` element `text` starts with, unescaped.
fn xml_string(text: &str) -> Option<String> {
    let body = text.strip_prefix("<string>")?;
    Some(xml_unescape(&body[..body.find("</string>")?]))
}

/// The text of the first `<NAME>` element, unescaped.
fn xml_element(text: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let start = text.find(&open)? + open.len();
    let end = start + text[start..].find(&format!("</{name}>"))?;
    Some(xml_unescape(&text[start..end]))
}

/// The five XML entities (the installer escapes `&`, `<` and `>`; the
/// scheduler may write the quotes as entities too).
fn xml_unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// An `ExecStart=` value split into words as systemd does for the units the
/// installer writes (sd_quote: `"..."` with `\\` and `\"`, `%%` and `$$`).
/// None for an unterminated quote.
fn systemd_words(line: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        let Some(&first) = chars.peek() else {
            return Some(words);
        };
        let mut word = String::new();
        let quoted = first == '"';
        if quoted {
            chars.next();
        }
        loop {
            match chars.next() {
                None if quoted => return None,
                None => break,
                Some('"') if quoted => break,
                Some(c) if !quoted && c.is_whitespace() => break,
                Some('\\') => word.push(chars.next()?),
                Some('%') if chars.peek() == Some(&'%') => {
                    chars.next();
                    word.push('%');
                }
                Some('$') if chars.peek() == Some(&'$') => {
                    chars.next();
                    word.push('$');
                }
                Some(c) => word.push(c),
            }
        }
        words.push(word);
    }
}

/// A task's arguments split into words (windows_service.ps1 quotes the data
/// dir as `"..."`; backslashes are path separators there, not escapes).
/// None for an unterminated quote.
fn windows_words(line: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        if chars.peek().is_none() {
            return Some(words);
        }
        let mut word = String::new();
        let mut quoted = false;
        loop {
            match chars.next() {
                None if quoted => return None,
                None => break,
                Some('"') => quoted = !quoted,
                Some(c) if !quoted && c.is_whitespace() => break,
                Some(c) => word.push(c),
            }
        }
        words.push(word);
    }
}

/// Whether two paths name the same existing folder.
fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// A file's text, [`MAX_ITEM_BYTES`] at most; None when it can't be read.
fn read_capped(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut raw = Vec::new();
    file.take(MAX_ITEM_BYTES + 1).read_to_end(&mut raw).ok()?;
    if raw.len() as u64 > MAX_ITEM_BYTES {
        return None;
    }
    Some(decode_text(&raw))
}

/// The scheduler's definition of Raven's task (`schtasks /Query /TN
/// RavenNodeBridge /XML`), or None when there is none.
fn scheduled_task_xml(schtasks: &Path) -> Option<String> {
    let out = Command::new(schtasks)
        .args(["/Query", "/TN", SCHEDULED_TASK, "/XML"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() || out.stdout.len() as u64 > MAX_ITEM_BYTES {
        return None;
    }
    Some(decode_text(&out.stdout))
}

/// UTF-16LE (with its byte-order mark, as the scheduler may write a task's
/// XML) or UTF-8 text.
pub(super) fn decode_text(raw: &[u8]) -> String {
    match raw.strip_prefix(&[0xFF, 0xFE]) {
        Some(utf16) => {
            let units: Vec<u16> = utf16
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes(*pair))
                .collect();
            String::from_utf16_lossy(&units)
        }
        None => {
            String::from_utf8_lossy(raw.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(raw)).into_owned()
        }
    }
}

/// The tool runs for each action, in order (the arguments after the tool).
fn session_stop_args(env: &LoginEnv) -> Vec<Vec<String>> {
    match env.platform {
        Platform::MacOs => vec![args(&["bootout", &env.launchd_target()])],
        Platform::Linux => vec![args(&["--user", "stop", SYSTEMD_UNIT])],
        Platform::Windows => vec![args(&["/End", "/TN", SCHEDULED_TASK])],
    }
}

fn disable_args(env: &LoginEnv) -> Vec<Vec<String>> {
    match env.platform {
        Platform::MacOs => vec![args(&["disable", &env.launchd_target()])],
        Platform::Linux => vec![args(&["--user", "disable", "--now", SYSTEMD_UNIT])],
        Platform::Windows => vec![args(&["/Change", "/TN", SCHEDULED_TASK, "/DISABLE"])],
    }
}

fn enable_args(env: &LoginEnv, item: &LoginItem, start: bool) -> Option<Vec<Vec<String>>> {
    Some(match (env.platform, start) {
        (Platform::MacOs, false) => vec![args(&["enable", &env.launchd_target()])],
        (Platform::MacOs, true) => {
            let plist = item.file.as_deref()?.to_str()?;
            vec![
                args(&["enable", &env.launchd_target()]),
                args(&["bootstrap", &format!("gui/{}", env.uid), plist]),
            ]
        }
        (Platform::Linux, false) => vec![args(&["--user", "enable", SYSTEMD_UNIT])],
        (Platform::Linux, true) => vec![args(&["--user", "enable", "--now", SYSTEMD_UNIT])],
        (Platform::Windows, start) => {
            let mut runs = vec![args(&["/Change", "/TN", SCHEDULED_TASK, "/ENABLE"])];
            if start {
                runs.push(args(&["/Run", "/TN", SCHEDULED_TASK]));
            }
            runs
        }
    })
}

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

/// Stops the node Raven's own login item runs for this login session:
/// launchd unloads the job (`bootout`; without it KeepAlive starts the node
/// again within about 10 s), systemd stops the unit, the scheduler ends the
/// task. The item stays on for the next login. A job that was not loaded
/// fails here and is still stopped: the caller checks the node.
pub(super) fn stop_for_session(env: &LoginEnv, item: &LoginItem) -> Result<(), String> {
    run_all(env, item, session_stop_args(env))
}

/// Turns Raven's own login item off until [`enable_login_item`] (launchd's
/// `disable`, which lasts across logins; systemd's `disable --now`; the
/// scheduler's `/DISABLE`).
pub(super) fn disable_login_item(env: &LoginEnv, item: &LoginItem) -> Result<(), String> {
    run_all(env, item, disable_args(env))
}

/// Turns Raven's own login item back on, and with `start` starts it now
/// (`enable` + `bootstrap`, `enable --now`, `/ENABLE` + `/Run`). Without
/// `start` (a node runs already) only the setting changes.
pub(super) fn enable_login_item(
    env: &LoginEnv,
    item: &LoginItem,
    start: bool,
) -> Result<(), String> {
    let runs = enable_args(env, item, start)
        .ok_or_else(|| "the login item's file has no usable path".to_owned())?;
    run_all(env, item, runs)
}

/// Removes Raven's own login item for this profile (`raven erase`, privacy
/// pack PP.16): it names the data dir, the listen addresses and the relays
/// in plain. The plist or unit file is deleted (systemd then reloads its
/// units, best effort); the scheduler deletes the task (`schtasks /Delete
/// /TN RavenNodeBridge /F`; the lab's task file goes too). Run
/// [`stop_for_session`] first. Only the item [`own_login_item`] found for
/// this data dir is ever passed here.
pub(super) fn remove_login_item(env: &LoginEnv, item: &LoginItem) -> Result<(), String> {
    debug_assert_eq!(item.platform, env.platform);
    if env.platform == Platform::Windows {
        run_tool(&env.tool, &args(&["/Delete", "/TN", SCHEDULED_TASK, "/F"]))?;
    }
    if let Some(file) = &item.file {
        match std::fs::remove_file(file) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(sanitize_terminal_line(&format!("{}: {e}", file.display()))),
        }
    }
    if env.platform == Platform::Linux {
        let _ = run_tool(&env.tool, &args(&["--user", "daemon-reload"]));
    }
    Ok(())
}

fn run_all(env: &LoginEnv, item: &LoginItem, runs: Vec<Vec<String>>) -> Result<(), String> {
    debug_assert_eq!(item.platform, env.platform);
    for argv in runs {
        run_tool(&env.tool, &argv)?;
    }
    Ok(())
}

/// One run of the tool by its path, with no input; its error output names
/// why it failed.
fn run_tool(tool: &Path, argv: &[String]) -> Result<(), String> {
    let what = || {
        let name = tool.file_name().map_or_else(
            || tool.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        sanitize_terminal_line(&format!("{name} {}", argv.join(" ")))
    };
    let out = Command::new(tool)
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("{}: {}", what(), sanitize_terminal_line(&e.to_string())))?;
    if out.status.success() {
        return Ok(());
    }
    let said = String::from_utf8_lossy(&out.stderr);
    let said = sanitize_terminal_line(said.trim());
    Err(if said.is_empty() {
        format!("{} ended with {}", what(), out.status)
    } else {
        format!("{} ended with {}: {said}", what(), out.status)
    })
}

#[cfg(test)]
pub(super) mod tests;
