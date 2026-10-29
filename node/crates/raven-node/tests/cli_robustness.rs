//! Robustness of the real `raven-node` binary: CLI commands must not panic or
//! hang on network and input errors, `status` must not touch a fresh profile,
//! and `service` must keep IPC up when a transport cannot.
//!
//! Anything that needs an identity runs in a *child* process with the
//! documented lab backend (debug builds only), so no test touches the OS
//! keystore. Waiting is event driven (markers on the child's stderr, or the
//! child exiting), never a fixed sleep.

use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use raven_core::queue::{DeliveryState, OutgoingQueue, QueueItem};

const NODE: &str = env!("CARGO_BIN_EXE_raven-node");
const PEER_PUB_HEX: &str = "abababababababababababababababababababababababababababababababab";

/// Identity-dependent tests need the documented lab backend (debug builds
/// only), which the Linux CI job exports for the whole run
/// (`RAVEN_IDENTITY_BACKEND=locked-file`). Elsewhere they are skipped rather
/// than risk a keystore prompt: run them locally with
/// `RAVEN_IDENTITY_BACKEND=locked-file RAVEN_CHAT_HISTORY_BACKEND=locked-file
/// RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1 cargo test -p raven-node --test cli_robustness`.
fn lab_identity_available() -> bool {
    let requested = std::env::var("RAVEN_IDENTITY_BACKEND").is_ok_and(|v| v == "locked-file");
    if !(cfg!(debug_assertions) && requested) {
        eprintln!("skipped: needs a debug build and RAVEN_IDENTITY_BACKEND=locked-file");
        return false;
    }
    true
}

fn node() -> Command {
    let mut c = Command::new(NODE);
    c.env("RAVEN_IDENTITY_BACKEND", "locked-file")
        .env("RAVEN_CHAT_HISTORY_BACKEND", "locked-file")
        .env("RAVEN_ALLOW_EPHEMERAL_DATA_DIR", "1")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null());
    c
}

/// Short path: a Unix socket path must fit `sun_path`.
fn temp_dir() -> tempfile::TempDir {
    let mut b = tempfile::Builder::new();
    b.prefix("rn");
    #[cfg(unix)]
    return b.tempdir_in("/tmp").expect("tempdir");
    #[cfg(not(unix))]
    b.tempdir().expect("tempdir")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn refused_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn init_profile(dir: &Path) {
    let out = node()
        .args(["init", "--data-dir"])
        .arg(dir)
        .output()
        .expect("run init");
    assert!(out.status.success(), "init failed: {}", text(&out));
}

fn queue_two_items(dir: &Path) -> [[u8; 16]; 2] {
    let queue = OutgoingQueue::open(&dir.join("queue.sqlite")).unwrap();
    let ids = [[1u8; 16], [2u8; 16]];
    for (n, id) in ids.iter().enumerate() {
        queue
            .enqueue(&QueueItem {
                message_id: *id,
                packed_envelope: vec![n as u8 + 1; 3],
                peer_addr: "someone".into(),
                state: DeliveryState::Queued,
                created_at_ms: 1_000 + n as u64,
            })
            .unwrap();
    }
    ids
}

/// Regression: `status` opened (and so created) forward_queue.sqlite, which
/// made the next `init` / `service` fail the first-install proof.
#[test]
fn status_leaves_a_fresh_profile_untouched() {
    let dir = temp_dir();
    let data = dir.path().join("fresh");
    let out = node()
        .args(["status", "--data-dir"])
        .arg(&data)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let shown = text(&out);
    assert!(shown.contains("forward_queue_pending=0"), "{shown}");
    assert!(
        !data.join("forward_queue.sqlite").exists(),
        "status created the queue file"
    );
    if lab_identity_available() {
        // ... so a later init on the same path still works.
        init_profile(&data);
    }
}

/// Regression: an unreadable queue was printed as pending=0 / total=0.
/// Privacy pack PP.16: while an erase of the profile is unfinished, no
/// raven-node command runs on it (a login item that starts the service
/// anyway, `status`, `init`), and nothing is written into it.
#[test]
fn an_unfinished_erase_closes_the_profile() {
    let dir = temp_dir();
    std::fs::write(dir.path().join("erase_in_progress"), b"raven erase\n").unwrap();
    for args in [
        &[
            "service",
            "--lan-listen",
            "127.0.0.1:0",
            "--ble-listen",
            "127.0.0.1:0",
        ][..],
        &["ipc"],
        &["status"],
        &["init"],
    ] {
        let out = node()
            .args(&args[..1])
            .arg("--data-dir")
            .arg(dir.path())
            .args(&args[1..])
            .output()
            .expect("run raven-node");
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", text(&out));
        assert!(
            text(&out).contains(
                "An erase of this Raven profile did not finish. Run `raven erase` to finish it."
            ),
            "{args:?}: {}",
            text(&out)
        );
    }
    let names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["erase_in_progress"], "nothing was written");
}

#[test]
fn status_reports_an_unreadable_queue_instead_of_zero() {
    let dir = temp_dir();
    std::fs::write(
        dir.path().join("forward_queue.sqlite"),
        b"definitely not a sqlite database, but long enough to be read as a header ....",
    )
    .unwrap();
    let out = node()
        .args(["status", "--data-dir"])
        .arg(dir.path())
        .output()
        .unwrap();
    let shown = text(&out);
    assert!(!out.status.success(), "{shown}");
    assert!(shown.contains("forward_queue_error="), "{shown}");
    assert!(shown.contains("forward_queue_pending=unknown"), "{shown}");
    assert!(!shown.contains("forward_queue_pending=0"), "{shown}");
}

/// Without `--data-dir`, an override or a usable HOME there is no profile to
/// open. Every data-dir subcommand must say so up front and exit 1: not fall
/// back to a cwd-relative `./raven-data` (a different identity per working
/// directory) and not fail later with an opaque "Not a directory".
#[test]
fn no_resolvable_profile_fails_up_front_and_creates_nothing() {
    let cwd = temp_dir();
    for args in [
        &["init"][..],
        &["address"],
        &["status"],
        &["bridge"],
        &["run"],
        &[
            "flush",
            "--peer",
            "127.0.0.1:1",
            "--peer-pub-hex",
            PEER_PUB_HEX,
        ],
        #[cfg(any(unix, windows))]
        &["ipc"],
        #[cfg(any(unix, windows))]
        &["service"],
    ] {
        let out = node()
            .current_dir(cwd.path())
            .env_remove("HOME")
            .env_remove("USERPROFILE")
            .env_remove("HOMEDRIVE")
            .env_remove("HOMEPATH")
            .env_remove("RAVEN_DATA_DIR")
            .env_remove("ASH_DATA_DIR")
            .args(args)
            .output()
            .unwrap();
        let shown = text(&out);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {shown}");
        assert!(
            shown.contains("cannot determine the Raven data directory"),
            "{args:?}: {shown}"
        );
        assert!(shown.contains("RAVEN_DATA_DIR"), "{args:?}: {shown}");
        assert!(!shown.contains("Not a directory"), "{args:?}: {shown}");
        assert!(!shown.contains("panicked"), "{args:?}: {shown}");
    }
    assert_eq!(
        std::fs::read_dir(cwd.path()).unwrap().count(),
        0,
        "a failed start must not leave a profile in the working directory"
    );
}

/// `raven-node ble-status` (kept for old scripts, Phase 5 P5.27) needs no
/// profile and opens no radio (no Bluetooth prompt): it prints the mock BLE
/// adapter, the nearby gate and the backend this build would use, and exits
/// 0. The retired CoreBluetooth experiment's lines are gone.
#[test]
fn ble_status_exits_0_with_no_radio() {
    let cwd = temp_dir();
    let out = node()
        .current_dir(cwd.path())
        .env_remove("HOME")
        .env_remove("USERPROFILE")
        .env_remove("RAVEN_DATA_DIR")
        .env_remove("RAVEN_LAB_NEARBY_ETHER")
        .arg("ble-status")
        .output()
        .unwrap();
    let shown = text(&out);
    assert_eq!(out.status.code(), Some(0), "{shown}");
    for line in [
        "ble_adapter=",
        "nearby_gate=",
        "nearby_backend=none",
        "nearby_radio=not_opened",
    ] {
        assert!(shown.contains(line), "{line}: {shown}");
    }
    assert!(!shown.contains("corebluetooth"), "{shown}");
    assert!(!shown.contains("panicked"), "{shown}");
    assert_eq!(std::fs::read_dir(cwd.path()).unwrap().count(), 0);
}

/// The default profile is the shared one (`$HOME/.raven`, as for `ash`), never
/// `./raven-data` under whatever directory the command ran in.
#[test]
fn default_profile_is_the_shared_home_profile_not_the_working_directory() {
    if !lab_identity_available() {
        return;
    }
    let home = temp_dir();
    let cwd = temp_dir();
    let run = |args: &[&str]| {
        node()
            .current_dir(cwd.path())
            .env("HOME", home.path())
            .env_remove("RAVEN_DATA_DIR")
            .env_remove("ASH_DATA_DIR")
            .args(args)
            .output()
            .unwrap()
    };
    let init = run(&["init"]);
    assert!(init.status.success(), "{}", text(&init));
    let address = run(&["address"]);
    assert!(address.status.success(), "{}", text(&address));
    assert_eq!(text(&init), text(&address), "same profile on every command");
    assert!(
        home.path().join(".raven").is_dir(),
        "the profile lives under $HOME/.raven"
    );
    assert!(!cwd.path().join("raven-data").exists());
    assert_eq!(std::fs::read_dir(cwd.path()).unwrap().count(), 0);
}

/// Regression: `flush` unwrapped every connect: a refused peer panicked
/// (exit 101) and the items behind the first were never attempted.
#[test]
fn flush_attempts_every_item_and_fails_cleanly_when_the_peer_is_down() {
    if !lab_identity_available() {
        return;
    }
    let dir = temp_dir();
    init_profile(dir.path());
    queue_two_items(dir.path());
    let peer = format!("127.0.0.1:{}", refused_port());
    let out = node()
        .args(["flush", "--data-dir"])
        .arg(dir.path())
        .args(["--peer", &peer, "--peer-pub-hex", PEER_PUB_HEX])
        .args(["--timeout-secs", "2"])
        .output()
        .unwrap();
    let shown = text(&out);
    assert_eq!(out.status.code(), Some(1), "not a panic (101): {shown}");
    assert!(!shown.contains("panicked"), "{shown}");
    assert_eq!(
        shown.matches("connect: cannot connect").count(),
        2,
        "{shown}"
    );
    assert!(shown.contains("2 item(s) not sent"), "{shown}");
}

#[test]
fn flush_rejects_bad_peer_input_without_panicking() {
    if !lab_identity_available() {
        return;
    }
    let dir = temp_dir();
    init_profile(dir.path());
    for (args, code) in [
        (
            ["--peer", "no-port-here", "--peer-pub-hex", PEER_PUB_HEX],
            2,
        ),
        (["--peer", "127.0.0.1:1", "--peer-pub-hex", "not-hex"], 2),
    ] {
        let out = node()
            .args(["flush", "--data-dir"])
            .arg(dir.path())
            .args(args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(code), "{}", text(&out));
        assert!(!text(&out).contains("panicked"), "{}", text(&out));
    }
}

/// `--peer` is documented as host:port: names resolve (here `localhost`,
/// where the listener is v4-only) and delivered items are marked Sent.
#[test]
fn flush_dials_by_name_and_marks_items_sent() {
    if !lab_identity_available() {
        return;
    }
    let dir = temp_dir();
    init_profile(dir.path());
    let ids = queue_two_items(dir.path());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        use std::io::Read;
        let mut frames = Vec::new();
        for _ in 0..2 {
            let (mut s, _) = listener.accept().unwrap();
            let mut len = [0u8; 4];
            s.read_exact(&mut len).unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            s.read_exact(&mut body).unwrap();
            frames.push(body);
            // Keep the connection open until flush gives up on it.
            let mut rest = Vec::new();
            let _ = s.read_to_end(&mut rest);
        }
        frames
    });
    let out = node()
        .args(["flush", "--data-dir"])
        .arg(dir.path())
        .args(["--peer", &format!("localhost:{port}")])
        .args(["--peer-pub-hex", PEER_PUB_HEX, "--timeout-secs", "1"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(server.join().unwrap(), vec![vec![1u8; 3], vec![2u8; 3]]);
    let queue = OutgoingQueue::open(&dir.path().join("queue.sqlite")).unwrap();
    for id in ids {
        assert_eq!(queue.get(&id).unwrap().unwrap().state, DeliveryState::Sent);
    }
}

/// `run --peer` with a dead peer is an error exit, never a hang or a panic.
/// Regression (relay kit, macOS): launchd restarts a relay that fails at
/// start every 10 s, and the 1 MiB cap on its log (`RAVEN_SERVICE_LOG_MAX_BYTES`)
/// was checked only after 30 s, which such a run never lives: the log grew
/// by a line per start. It is checked before the first line now, and with
/// `RAVEN_RELAY_EXIT_PAUSE_SECS` (the kit's plist) a lasting failure waits
/// before it exits; `--check` never waits.
#[cfg(unix)]
#[test]
fn a_relay_that_fails_at_start_bounds_its_log_and_waits_when_asked() {
    use std::io::Write as _;
    use std::time::{Duration, Instant};
    let dir = temp_dir();
    let log = dir.path().join("relay.log");
    let cap: usize = 64 * 1024;
    let run = |pause: Option<&str>, check: bool| {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .unwrap();
        f.write_all(&vec![b'x'; 2 * cap]).unwrap();
        let mut cmd = node();
        cmd.args(["relay", "--data-dir"])
            .arg(dir.path().join("relay"))
            .args(["--also-tcp", "not-a-port"])
            .env("RAVEN_SERVICE_LOG_MAX_BYTES", cap.to_string())
            .env_remove("RAVEN_RELAY_EXIT_PAUSE_SECS")
            .stdout(Stdio::null())
            .stderr(Stdio::from(f));
        if check {
            cmd.arg("--check");
        }
        if let Some(p) = pause {
            cmd.env("RAVEN_RELAY_EXIT_PAUSE_SECS", p);
        }
        let started = Instant::now();
        let status = cmd.status().unwrap();
        (
            status.code(),
            started.elapsed(),
            std::fs::read_to_string(&log).unwrap(),
        )
    };
    let (code, _, text) = run(None, false);
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.len() < cap,
        "the log was not cut at start: {} bytes",
        text.len()
    );
    assert!(
        unstamped(&text).starts_with("relay: --also-tcp must be"),
        "{text}"
    );
    assert!(!text.contains("exiting (2) in"), "{text}");

    let (code, took, text) = run(Some("1"), false);
    assert_eq!(code, Some(2), "{text}");
    assert!(took >= Duration::from_secs(1), "{took:?}");
    assert!(text.contains("relay: exiting (2) in 1 s"), "{text}");
    assert!(text.len() < cap, "{} bytes", text.len());

    let (code, _, text) = run(Some("3600"), true);
    assert_eq!(code, Some(2), "{text}");
    assert!(
        !text.contains("exiting (2) in"),
        "--check never waits: {text}"
    );
}

/// `text` without the UTC time raven-node starts each log line with
/// (`2026-10-25T12:43:10Z `).
fn unstamped(text: &str) -> &str {
    match text.split_once(' ') {
        Some((stamp, rest)) if stamp.len() == 20 && stamp.ends_with('Z') => rest,
        _ => text,
    }
}

/// `raven-node relay --wss` while the WSS gate is closed (no lab switches):
/// exit 2 with WSS_HOLD, `--check` too, before any port is probed or the
/// folder is made (RWS1 §1).
#[test]
fn relay_wss_is_refused_with_wss_hold_while_held() {
    let dir = temp_dir();
    for check in [false, true] {
        let mut cmd = node();
        cmd.args(["relay", "--data-dir"])
            .arg(dir.path().join("relay"))
            .args(["--listen", "127.0.0.1:0", "--wss", "443"])
            .env_remove("RAVEN_LAB_TEST_A")
            .env_remove("RAVEN_LAB_WSS")
            .env_remove("RAVEN_RELAY_EXIT_PAUSE_SECS");
        if check {
            cmd.arg("--check");
        }
        let out = cmd.output().unwrap();
        let text = text(&out);
        assert_eq!(out.status.code(), Some(2), "{text}");
        assert!(unstamped(&text).starts_with("relay: WSS_HOLD: "), "{text}");
        assert!(!dir.path().join("relay").exists(), "nothing created");
    }
}

#[test]
fn run_reports_an_unreachable_peer_and_exits() {
    if !lab_identity_available() {
        return;
    }
    let dir = temp_dir();
    // Both ports are picked while both are held: with `--listen 127.0.0.1:0`
    // the kernel could hand the node the freed "dead" port, and the node
    // would then dial itself (a timeout, not a refusal).
    let (peer_port, listen_port) = {
        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let own = TcpListener::bind("127.0.0.1:0").unwrap();
        (
            dead.local_addr().unwrap().port(),
            own.local_addr().unwrap().port(),
        )
    };
    let peer = format!("127.0.0.1:{peer_port}");
    let listen = format!("127.0.0.1:{listen_port}");
    let out = node()
        .args(["run", "--data-dir"])
        .arg(dir.path())
        .args(["--listen", &listen, "--peer", &peer])
        .args(["--timeout-secs", "3"])
        .output()
        .unwrap();
    let shown = text(&out);
    assert_eq!(out.status.code(), Some(1), "{shown}");
    assert!(shown.contains("connect: cannot connect to"), "{shown}");
    assert!(!shown.contains("panicked"), "{shown}");
}

#[cfg(unix)]
mod service {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::process::{Child, ChildStderr};
    use std::sync::mpsc::{self, Receiver};
    use std::time::Duration;

    use raven_core::ipc::{IpcRequest, IpcResponse, IPC_VERSION};

    /// A running `raven-node service` with its stderr as a stream of lines.
    struct Service {
        child: Child,
        lines: Receiver<String>,
        seen: Vec<String>,
    }

    impl Drop for Service {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Service {
        fn start(data: &Path, lan_listen: &str) -> Self {
            Self::spawn(node().args(["service", "--data-dir"]).arg(data).args([
                "--lan-listen",
                lan_listen,
                "--ble-listen",
                "127.0.0.1:0",
            ]))
        }

        /// Dedicated IPC only (`raven-node ipc`), as documented for setups that
        /// run the bridge elsewhere.
        fn start_ipc_only(data: &Path) -> Self {
            Self::spawn(node().args(["ipc", "--data-dir"]).arg(data))
        }

        fn spawn(cmd: &mut Command) -> Self {
            let mut child = cmd
                .stderr(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()
                .expect("spawn service");
            let stderr: ChildStderr = child.stderr.take().unwrap();
            let (tx, lines) = mpsc::channel();
            std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
            Self {
                child,
                lines,
                seen: Vec::new(),
            }
        }

        /// Block until a stderr line contains `marker` (it may already have been read).
        fn wait_for(&mut self, marker: &str) {
            if self.seen.iter().any(|l| l.contains(marker)) {
                return;
            }
            loop {
                match self.lines.recv_timeout(Duration::from_secs(90)) {
                    Ok(line) => {
                        let hit = line.contains(marker);
                        self.seen.push(line);
                        if hit {
                            return;
                        }
                    }
                    Err(e) => panic!(
                        "no {marker:?} from service ({e}); stderr so far:\n{}",
                        self.seen.join("\n")
                    ),
                }
            }
        }

        fn still_running(&mut self) -> bool {
            self.child.try_wait().unwrap().is_none()
        }
    }

    fn ipc(data: &Path, req: &IpcRequest) -> IpcResponse {
        let mut s = UnixStream::connect(data.join("raven-node.sock")).expect("connect ipc");
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        s.write_all(&raven_core::encode_request(req).unwrap())
            .unwrap();
        let mut len = [0u8; 4];
        s.read_exact(&mut len).unwrap();
        let mut frame = vec![0u8; 4 + u32::from_be_bytes(len) as usize];
        frame[..4].copy_from_slice(&len);
        s.read_exact(&mut frame[4..]).unwrap();
        raven_core::decode_response(&frame).unwrap()
    }

    fn capabilities(data: &Path) -> Vec<String> {
        match ipc(data, &IpcRequest::status()) {
            IpcResponse::Status { capabilities, .. } => capabilities,
            other => panic!("{other:?}"),
        }
    }

    /// `Status`'s process id and LAN listener address.
    fn pid_and_lan_listen(data: &Path) -> (Option<u32>, Option<String>) {
        match ipc(data, &IpcRequest::status()) {
            IpcResponse::Status {
                pid, lan_listen, ..
            } => (pid, lan_listen),
            other => panic!("{other:?}"),
        }
    }

    /// Regression: a busy LAN port made `service` exit, taking the IPC server
    /// with it (ash's outbound sends only need IPC), and a slow preflight
    /// parked it before the bridge ever started. IPC now stays up, Status
    /// shows the listener as down, and the listener comes up once the port is free.
    #[test]
    fn a_busy_lan_port_does_not_take_ipc_down_and_heals_when_freed() {
        if !lab_identity_available() {
            return;
        }
        let dir = temp_dir();
        let data = dir.path().join("d");
        let holder = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = holder.local_addr().unwrap().port();
        let mut svc = Service::start(&data, &format!("127.0.0.1:{port}"));
        svc.wait_for("lan_direct failed");
        svc.wait_for("raven-node ipc: listening");

        assert_eq!(
            ipc(&data, &IpcRequest::Ping { v: IPC_VERSION }),
            IpcResponse::Pong { v: IPC_VERSION }
        );
        let caps = capabilities(&data);
        assert!(caps.contains(&"ipc".to_string()), "{caps:?}");
        assert!(
            !caps.contains(&"lan_direct".to_string()),
            "a listener that is not up must not be advertised: {caps:?}"
        );
        assert!(svc.still_running(), "service exited on a busy LAN port");
        // It names itself, and no listen address while the listener is down.
        assert_eq!(pid_and_lan_listen(&data), (Some(svc.child.id()), None));

        // Free the port: the supervised listener retries and comes up, and
        // IPC kept serving throughout.
        drop(holder);
        svc.wait_for("lan_direct: listen");
        assert!(capabilities(&data).contains(&"lan_direct".to_string()));
        assert_eq!(
            pid_and_lan_listen(&data),
            (Some(svc.child.id()), Some(format!("127.0.0.1:{port}")))
        );
        assert!(svc.still_running());
    }

    /// Regression: `raven-node ipc` on a fresh profile binds its socket and
    /// instance lock before any identity exists. They survive a stop (a kill
    /// leaves both behind) and used to make the first `init` fail with an
    /// identity continuity violation until they were removed by hand.
    #[test]
    fn ipc_only_start_before_init_does_not_wedge_first_install() {
        if !lab_identity_available() {
            return;
        }
        let dir = temp_dir();
        let data = dir.path().join("d");
        let mut ipc_only = Service::start_ipc_only(&data);
        ipc_only.wait_for("raven-node ipc: listening");
        // Killed, not stopped: nothing cleans the socket or the lock up.
        drop(ipc_only);
        assert!(data.join("raven-node.sock").exists(), "socket left behind");
        assert!(
            data.join("raven-node.sock.lock").exists(),
            "instance lock left behind"
        );
        init_profile(&data);
        let out = node()
            .args(["address", "--data-dir"])
            .arg(&data)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", text(&out));
    }

    #[test]
    fn status_advertises_lan_direct_once_the_listener_is_up() {
        if !lab_identity_available() {
            return;
        }
        let dir = temp_dir();
        let data = dir.path().join("d");
        let mut svc = Service::start(&data, "127.0.0.1:0");
        svc.wait_for("lan_direct: listen");
        let caps = capabilities(&data);
        assert!(caps.contains(&"lan_direct".to_string()), "{caps:?}");
        assert!(svc.still_running());
    }
}
