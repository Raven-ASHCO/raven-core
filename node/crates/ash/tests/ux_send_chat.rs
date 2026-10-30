//! Black-box checks of what `ash` tells the user: how a send ends (delivered /
//! queued / NOT SENT), what the chat does with `help` / `exit` / `/block` /
//! `/verify` and with a line in the wrong encoding, and how a dead or hung local
//! service is reported.
//!
//! Every run uses throwaway profiles and the file-backed (`locked-file`) secret
//! stores, so nothing here can reach the OS keychain or the network. The local
//! daemon is faked by a UDS server in the test process (it answers Ping, Status,
//! LanDial, InternetDial and P2pDial, the dials by driving a second profile's
//! real `dispatch_frame`), so the real `ash` binary sees an "already running"
//! service and starts none. Should a fake ever stall (ash then takes its
//! socket for a dead service's and starts a real one), that service listens
//! on 127.0.0.1 only (every run pins `RAVEN_SERVICE_LAN_LISTEN`, never the
//! default 0.0.0.0:7420) and is stopped when the fixture drops
//! ([`StopService`]).
//!
//! Unix only: the planted 0600 identity seed and the UDS are the unix layout.
#![cfg(unix)]

use std::collections::HashSet;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use raven_core::chat_history::BlockList;
use raven_core::device_cert::ensure_local_device_certificate;
use raven_core::fingerprint::device_fingerprint_v1;
use raven_core::identity::Identity;
use raven_core::ipc::{
    decode_request, encode_response, ContactWhy, IpcRequest, IpcResponse, P2pStatusInfo,
    RelayHealth, IPC_VERSION,
};
use raven_core::lan_dispatch::{dispatch_frame, encode_local_offer, local_bundle};
use raven_core::paths::PRIMARY_DEVICE_ID;

/// The identity `plant_identity` writes (a 0600 locked-file seed).
const SEED: u8 = 0x5a;

/// Every zone a text names is this computer's own (CP.6: never a time on
/// another clock; E2 r38: a clock time names its zone, "(UTC+1)").
fn only_local_zone(text: &str) -> bool {
    let off = raven_core::local_time::utc_offset_s(raven_core::clock::now_ms());
    let here = match off {
        Some(0) => "UTC".to_string(),
        Some(off) => {
            let sign = if off < 0 { '-' } else { '+' };
            let (h, m) = (off.unsigned_abs() / 3600, off.unsigned_abs() % 3600 / 60);
            if m == 0 {
                format!("UTC{sign}{h}")
            } else {
                format!("UTC{sign}{h}:{m:02}")
            }
        }
        None => return !text.contains("UTC"),
    };
    text.match_indices("(UTC").all(|(at, _)| {
        let label: String = text[at + 1..]
            .chars()
            .take_while(|c| *c != ',' && *c != ')')
            .collect();
        label == here
    })
}

fn ash(dir: &Path) -> Command {
    ash_at(Path::new(env!("CARGO_BIN_EXE_ash")), dir)
}

/// [`ash`] run from `bin`. A service ash starts by itself (when no local
/// service answers) receives on 127.0.0.1 only, never on the LAN port
/// another raven-node on this machine may hold; a test that wants another
/// address sets `RAVEN_SERVICE_LAN_LISTEN` after this.
fn ash_at(bin: &Path, dir: &Path) -> Command {
    let mut c = Command::new(bin);
    c.arg("--data-dir")
        .arg(dir)
        .env("RAVEN_IDENTITY_BACKEND", "locked-file")
        .env("RAVEN_CHAT_HISTORY_BACKEND", "locked-file")
        .env("RAVEN_PREKEY_BACKEND", "locked-file")
        .env("RAVEN_SESSION_BACKEND", "locked-file")
        .env("RAVEN_ALLOW_EPHEMERAL_DATA_DIR", "1")
        .env("NO_COLOR", "1")
        .env_remove("RAVEN_PEER")
        .env_remove("ASH_LAN_DIAL")
        .env_remove("RAVEN_VERBOSE")
        .env_remove("ASH_VERBOSE")
        .env("RAVEN_SERVICE_LAN_LISTEN", "127.0.0.1:0")
        .env_remove("RAVEN_LAB_NET_TAG");
    // Plain profiles, whatever privacy switches the suite runs with: the
    // tests read and write the profiles' files themselves, and the service
    // that answers here is a stand-in without an at-rest state (an older
    // node to the upgrade interlock). Sealing is tested where it is chosen
    // (raven-core, ux_screens, carrier_matrix C87, the fault matrix).
    for switch in raven_core::lan_gate::PRIVACY_LAB_SWITCHES {
        c.env_remove(switch);
    }
    // The long message horizon and the letters held, whatever switches the
    // suite runs with: with them a send nothing can take is parked instead of
    // refused or given up (Phase 5a, P5.8). The horizon is on in release
    // builds since 2026-10, so it is closed here (a debug build's "0"):
    // these tests pin the words of a send without it. `with_horizon` and the
    // tests that set RAVEN_LAB_HORIZON themselves turn it on for one command.
    c.env(raven_core::horizon::LAB_HORIZON, "0");
    c.env_remove(raven_core::horizon::LAB_LETTER);
    // Release builds have the Tor onion carrier and STUN discovery on since
    // 2026-10; no test here reaches the Tor network or asks a public STUN
    // server, so a raven-node these tests start has both closed (a debug
    // build's "0").
    c.env("RAVEN_LAB_TOR", "0")
        .env("RAVEN_LAB_STUN_DISCOVERY", "0");
    // Every process of a test runs on one clock: a lab clock file reaches ash
    // and its service only when this test process runs on it too (the lab
    // unlock set for the whole suite), never through a lab unlock that a test
    // gives one command.
    if !on_lab_clock() {
        c.env_remove("RAVEN_LAB_CLOCK_FILE");
    }
    c
}

/// This suite runs on a lab clock (raven_core::clock: the lab unlock and
/// `RAVEN_LAB_CLOCK_FILE` set for the whole run).
fn on_lab_clock() -> bool {
    raven_core::pair_init::lab_test_a_enabled()
        && std::env::var_os("RAVEN_LAB_CLOCK_FILE").is_some()
}

fn run(mut c: Command, stdin: &[u8]) -> Output {
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ash");
    // The child may exit without reading its stdin: a broken pipe is fine.
    let _ = child.stdin.take().unwrap().write_all(stdin);
    child.wait_with_output().expect("wait ash")
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

/// A private profile directory whose socket path fits `sun_path`.
fn short_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    if dir.path().as_os_str().len() <= 60 {
        return dir;
    }
    tempfile::Builder::new()
        .prefix("ux")
        .tempdir_in("/tmp")
        .unwrap()
}

fn plant_identity(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let seed = dir.join("identity.seed");
    std::fs::write(&seed, [SEED; 32]).unwrap();
    std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn pub_hex(id: &Identity) -> String {
    hex::encode(id.public_key_bytes())
}

/// If a bug ever made one of these runs start a real service, do not leave it
/// behind: stop the one for this profile (and only that one).
struct StopService(PathBuf);

impl Drop for StopService {
    fn drop(&mut self) {
        let _ = Command::new("pkill")
            .args([
                "-f",
                &format!("raven-node service --data-dir {}", self.0.display()),
            ])
            .status();
    }
}

fn add_bob(dir: &Path, bob: &Identity, dial: &str) {
    let mut c = ash(dir);
    c.args(["contact", "add", "--address", &bob.address()])
        .args(["--pub-hex", &pub_hex(bob)])
        .args(["--petname", "Bob", "--tag", "bob", "--lan-dial", dial]);
    let o = run(c, b"");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
}

// ── the chat ────────────────────────────────────────────────────────────────

fn chat_profile() -> (tempfile::TempDir, Identity, StopService) {
    let dir = short_dir();
    plant_identity(dir.path());
    let bob = Identity::from_seed(&[0x42; 32]);
    add_bob(dir.path(), &bob, "127.0.0.1:9");
    let guard = StopService(dir.path().to_path_buf());
    (dir, bob, guard)
}

fn chat(dir: &Path, stdin: &[u8]) -> Output {
    let mut c = ash(dir);
    c.args(["send", "--contact", "@bob", "--chat"]);
    run(c, stdin)
}

#[test]
fn chat_commands_typed_as_words_are_not_sent_to_the_friend() {
    let (dir, _bob, _guard) = chat_profile();
    let o = chat(dir.path(), b"help\n/help\nexit\n");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{err}");
    assert!(
        out.contains("\"help\" is not sent to Bob; here are the chat commands:"),
        "{out}"
    );
    for command in [
        "/help",
        "/back",
        "/info",
        "/verify",
        "/block",
        "/clear-local-history",
    ] {
        assert!(out.contains(command), "{command} missing: {out}");
    }
    assert!(
        out.contains("\"exit\" leaves the chat; it is not sent to Bob."),
        "{out}"
    );
    assert!(out.contains("left chat"), "{out}");
    // Nothing reached the send path: no refusal text, no service was started.
    assert!(
        !out.contains("NOT SENT") && !err.contains("NOT SENT"),
        "{out}\n{err}"
    );
    assert!(
        !dir.path().join("raven-node-service.log").exists(),
        "a send would have started the service"
    );
    // The receiver is not running here: the chat says so up front, once.
    assert!(
        err.contains("raven-node is not running, so replies from Bob cannot arrive yet"),
        "{err}"
    );
    assert_eq!(err.matches("replies from Bob").count(), 1, "{err}");
    assert!(err.contains("ash listen"), "{err}");
}

/// A damaged cursor file used to end the chat with a bare line and exit status 0.
#[test]
fn a_chat_that_cannot_open_says_why_and_fails() {
    let (dir, _bob, _guard) = chat_profile();
    let cursors = dir.path().join("chat_inbox_cursors.json");
    std::fs::write(&cursors, b"{not json").unwrap();
    let o = chat(dir.path(), b"hello\n");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{out}\n{err}");
    assert!(err.contains("chat not opened"), "{err}");
    assert!(err.contains(&cursors.display().to_string()), "{err}");
    assert!(
        err.contains("Your messages and contacts are not affected"),
        "{err}"
    );
    assert!(err.contains("(technical: inbox cursor corrupt"), "{err}");
    assert!(!out.contains("left chat"), "it never opened: {out}");
    assert_eq!(
        std::fs::read(&cursors).unwrap(),
        b"{not json",
        "the file is left alone"
    );
    assert!(
        !dir.path().join("raven-node-service.log").exists(),
        "nothing was sent or started"
    );
}

#[test]
fn chat_quit_leaves_and_the_header_points_to_help() {
    let (dir, _bob, _guard) = chat_profile();
    let o = chat(dir.path(), b"quit\n");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(out.contains("chat with Bob @bob"), "{out}");
    assert!(out.contains("/help lists the commands"), "{out}");
    assert_eq!(out.matches("left chat").count(), 1, "{out}");
}

/// A line in a legacy encoding is dropped with a message, and the chat goes on:
/// the `/help` after it still runs, and only the `/back` ends the session.
#[test]
fn chat_survives_a_line_that_is_not_utf8() {
    let (dir, _bob, _guard) = chat_profile();
    let o = chat(dir.path(), b"\xed\xa1\xe4\xe3\n/help\n/back\n");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{err}");
    assert!(
        err.contains("input was not valid UTF-8, line skipped"),
        "{err}"
    );
    assert!(
        out.contains("/clear-local-history"),
        "the chat went on: {out}"
    );
    assert_eq!(out.matches("left chat").count(), 1, "{out}");
    assert!(
        !dir.path().join("raven-node-service.log").exists(),
        "the dropped line was not sent"
    );
}

#[test]
fn chat_block_asks_first_and_names_the_undo() {
    // End of input, or anything but yes, cancels.
    for (input, left_by_command) in [
        (&b"/block\n"[..], false),
        (&b"/block\nno\n/back\n"[..], true),
    ] {
        let (dir, bob, _guard) = chat_profile();
        let o = chat(dir.path(), input);
        let out = text(&o.stdout);
        assert_eq!(code(&o), 0, "{}", text(&o.stderr));
        assert!(out.contains("Block Bob?"), "{out}");
        assert!(
            out.contains("Type yes to block; anything else cancels"),
            "{out}"
        );
        assert!(out.contains("not blocked"), "{out}");
        assert!(
            out.contains("left chat"),
            "the chat went on ({left_by_command}): {out}"
        );
        assert!(
            !BlockList::load_checked(dir.path())
                .unwrap()
                .is_blocked(&pub_hex(&bob)),
            "nobody is blocked without a yes"
        );
    }

    // A yes blocks, says who, names the undo, and ends the chat.
    let (dir, bob, _guard) = chat_profile();
    let o = chat(dir.path(), b"/block\nyes\n");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(out.contains("blocked Bob."), "{out}");
    assert!(
        out.contains(&format!(
            "To undo: ash contact unblock --pub-hex {}",
            pub_hex(&bob)
        )),
        "{out}"
    );
    assert_eq!(
        out.matches(&pub_hex(&bob)).count(),
        1,
        "the key appears once, inside the undo command, never as the confirmation: {out}"
    );
    assert!(out.contains("left chat"), "blocking ends the chat: {out}");
    assert!(BlockList::load_checked(dir.path())
        .unwrap()
        .is_blocked(&pub_hex(&bob)));

    // Afterwards a send says so, names the undo, and starts nothing.
    let mut c = ash(dir.path());
    c.args(["send", "--contact", "@bob"]);
    let o = run(c, b"hi\n");
    let err = text(&o.stderr);
    assert_eq!(code(&o), 1, "{err}");
    assert!(
        err.contains("NOT SENT: Bob is blocked on this computer."),
        "{err}"
    );
    assert!(err.contains("ash contact unblock --pub-hex"), "{err}");
    assert!(
        !dir.path().join("raven-node-service.log").exists(),
        "a blocked send must not start the service"
    );
}

#[test]
fn chat_verify_says_what_it_does_and_how_to_mark_the_contact_verified() {
    let (dir, bob, _guard) = chat_profile();
    let me = Identity::from_seed(&[SEED; 32]);
    let my_fp = device_fingerprint_v1(&me.public_key_bytes());
    let my_words = raven_core::security_words::words_v1(&me.public_key_bytes()).join(" ");
    let o = chat(dir.path(), b"/verify\n/info\n/back\n");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let words = [
        // MY words to read out, and my old-style code for an older Raven.
        "Your security words (read all 10 to Bob)".to_string(),
        format!("words       {my_words}"),
        format!("old-style code (for a friend with an older Raven): {my_fp}"),
        "not in this chat".to_string(),
        "This only shows yours; nothing is changed".to_string(),
        "Bob is not marked verified yet".to_string(),
        // The command asks for what Bob READS OUT and shows nothing of his
        // before it matches.
        format!("ash contact verify --address {}", bob.address()),
        // /info keeps Bob's words hidden until he is verified.
        "(shown once you verify Bob: /verify)".to_string(),
    ];
    for word in &words {
        assert!(out.contains(word.as_str()), "{word:?} missing from: {out}");
    }
    let bob_words = raven_core::security_words::words_v1(&bob.public_key_bytes()).join(" ");
    assert!(!out.contains(&bob_words), "the check is blind: {out}");
    assert!(!out.contains("--verify-fp"), "{out}");
}

#[test]
fn a_whitespace_only_message_is_refused_before_anything_starts() {
    let (dir, _bob, _guard) = chat_profile();
    let mut c = ash(dir.path());
    c.args(["send", "--contact", "@bob"]);
    let o = run(c, b"   \n\n");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{err}");
    assert!(err.contains("NOT SENT: the message is empty"), "{err}");
    assert!(err.contains("Nothing was queued"), "{err}");
    assert!(!out.to_lowercase().contains("delivered"), "{out}");
    assert!(!dir.path().join("raven-node-service.log").exists());
}

// ── the local service, dead or hung ─────────────────────────────────────────

#[test]
fn ipc_ping_without_a_service_says_so_and_how_to_start_it() {
    let dir = short_dir();
    let mut c = ash(dir.path());
    c.arg("ipc-ping");
    let o = run(c, b"");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{err}");
    assert!(!out.contains("ipc pong"), "{out}");
    assert!(
        err.contains("ipc ping failed: raven-node is not running"),
        "{err}"
    );
    assert!(err.contains("ash listen"), "{err}");
    assert!(
        err.contains("No such file"),
        "the OS text stays at the end for a log search: {err}"
    );
}

/// A service that accepts the connection and never answers (stopped, deadlocked,
/// or blocked on a Keychain dialog) is reported within seconds, not 10 s of
/// silence, and as "not answering", not as an OS error.
#[test]
fn a_hung_service_is_reported_in_seconds_as_not_answering() {
    let dir = short_dir();
    let listener = UnixListener::bind(raven_core::default_socket_path(dir.path())).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = stop.clone();
    let server = std::thread::spawn(move || {
        let mut held: Vec<UnixStream> = Vec::new();
        while !stop_c.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => held.push(stream),
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    });
    let mut c = ash(dir.path());
    c.arg("ipc-ping");
    let started = Instant::now();
    let o = run(c, b"");
    let waited = started.elapsed();
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    let err = text(&o.stderr);
    assert_eq!(code(&o), 1, "{err}");
    assert!(waited < Duration::from_secs(8), "bounded: {waited:?}");
    assert!(
        err.contains("ipc ping failed: raven-node did not answer in time"),
        "{err}"
    );
    assert!(err.contains("ash doctor"), "{err}");
    assert!(!err.contains("not running"), "stuck is not absent: {err}");
}

#[test]
fn status_names_a_service_that_is_not_running_in_plain_words() {
    let dir = short_dir();
    plant_identity(dir.path());
    let mut c = ash(dir.path());
    c.arg("status");
    let o = run(c, b"");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(out.contains("raven-node is not running"), "{out}");
    assert!(out.contains("ash listen"), "{out}");
}

// ── the service a send starts (the real raven-node, when it is built) ───────

/// The `raven-node` that sits next to `ash` (what `ash` itself would start), or
/// `None` when this test run did not build it (`cargo test -p ash` alone).
fn raven_node_next_to_ash() -> Option<PathBuf> {
    let node = Path::new(env!("CARGO_BIN_EXE_ash")).with_file_name("raven-node");
    node.exists().then_some(node)
}

/// The number after `marker` in `text` (a process id the notice printed).
fn number_after(text: &str, marker: &str) -> Option<u32> {
    let rest = text.split(marker).nth(1)?;
    rest.chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()
}

fn process_command(pid: u32) -> String {
    let out = Command::new("ps")
        .args(["-o", "command=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    text(&out.stdout).trim().to_string()
}

/// A send into a profile with no service starts one. The notice says what was
/// started, that it outlives ash, and how to stop only that one process: its id
/// (and the profile's own command line proves the id is the right one).
#[test]
fn starting_the_service_says_what_it_is_and_how_to_stop_only_it() {
    if raven_node_next_to_ash().is_none() {
        eprintln!("skipped: raven-node is not built next to ash");
        return;
    }
    let (dir, _bob, guard) = chat_profile();
    let mut c = ash(dir.path());
    c.args(["send", "--contact", "@bob"])
        .env("RAVEN_SERVICE_LAN_LISTEN", "127.0.0.1:0");
    let o = run(c, b"hello\n");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    let pid = number_after(&err, "started raven-node (process ").expect(&err);
    let alive = Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .unwrap()
        .success();
    let command = process_command(pid);
    let _ = Command::new("kill").arg(pid.to_string()).status();
    drop(guard);

    assert!(alive, "the service keeps running after ash exits: {err}");
    assert!(
        command.contains(&format!(
            "raven-node service --data-dir {}",
            dir.path().display()
        )),
        "the id belongs to THIS profile's service: {command}"
    );
    for word in [
        "notice: started raven-node (process",
        "RAVEN's background service for this profile. It keeps running after ash exits.",
        &format!("stop only this one with: kill {pid}"),
        &format!(
            "log: {}",
            dir.path().join("raven-node-service.log").display()
        ),
        "it is receiving messages (this computer only)",
    ] {
        assert!(err.contains(word), "{word:?} missing from: {err}");
    }
    assert!(!err.contains("pkill"), "no blanket stop advice: {err}");
    assert!(!err.contains("IPC + LAN receive on"), "{err}");
    assert!(!out.to_lowercase().contains("delivered"), "{out}");
    // The peer is unreachable (nothing listens on port 9): the send says so.
    assert_eq!(code(&o), 1, "{err}");
    assert!(err.contains("NOT SENT: Bob's computer is there"), "{err}");
}

/// A fake service that accepts and never answers (a stalled fake): ash
/// takes its socket for a dead service's and starts one by itself. That
/// service is told to receive on 127.0.0.1 (every helper here pins
/// `RAVEN_SERVICE_LAN_LISTEN`), never the default 0.0.0.0:7420 another
/// raven-node on this machine may hold, and the fixture's guard stops it.
/// Nothing binds a port: ash runs from a hard link next to a stand-in
/// `raven-node` that records how it was started and exits.
#[test]
fn a_stalled_fake_never_gets_a_service_on_the_lan_port() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, _bob, _guard) = chat_profile();
    let bin = tempfile::tempdir().unwrap();
    let ash_here = bin.path().join("ash");
    if std::fs::hard_link(env!("CARGO_BIN_EXE_ash"), &ash_here).is_err() {
        std::fs::copy(env!("CARGO_BIN_EXE_ash"), &ash_here).unwrap();
    }
    let started_with = bin.path().join("started-with.txt");
    let stand_in = bin.path().join("raven-node");
    std::fs::write(
        &stand_in,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nexit 3\n",
            started_with.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&stand_in, std::fs::Permissions::from_mode(0o755)).unwrap();
    // The stalled fake: it holds every connection and answers nothing.
    let listener = UnixListener::bind(raven_core::default_socket_path(dir.path())).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = stop.clone();
    let fake = std::thread::spawn(move || {
        let mut held = Vec::new();
        while !stop_c.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => held.push(stream),
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    });
    let mut c = ash_at(&ash_here, dir.path());
    c.args(["send", "--contact", "@bob"]);
    let o = run(c, b"hello\n");
    stop.store(true, Ordering::SeqCst);
    fake.join().unwrap();
    let err = text(&o.stderr);
    let args = std::fs::read_to_string(&started_with)
        .unwrap_or_else(|_| panic!("ash started no service: {err}"));
    let args: Vec<&str> = args.lines().collect();
    assert_eq!(args.first(), Some(&"service"), "{args:?}");
    let at = args
        .iter()
        .position(|a| *a == "--lan-listen")
        .unwrap_or_else(|| panic!("no --lan-listen: {args:?}"));
    assert_eq!(args.get(at + 1), Some(&"127.0.0.1:0"), "{args:?}");
    assert!(!args.iter().any(|a| a.contains("0.0.0.0")), "{args:?}");
    assert_ne!(code(&o), 0, "nothing was sent: {err}");
}

/// The port this profile would receive on is taken (a second profile on the same
/// computer always meets this): the service runs and sending works, but the
/// computer is deaf, and the user is told so, with the way out.
#[test]
fn a_busy_lan_port_is_reported_as_not_receiving_with_the_way_out() {
    if raven_node_next_to_ash().is_none() {
        eprintln!("skipped: raven-node is not built next to ash");
        return;
    }
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let (dir, _bob, guard) = chat_profile();
    let mut c = ash(dir.path());
    c.args(["send", "--contact", "@bob"])
        .env("RAVEN_SERVICE_LAN_LISTEN", format!("127.0.0.1:{port}"));
    let o = run(c, b"hello\n");
    let err = text(&o.stderr);
    let pid = number_after(&err, "started raven-node (process ");
    if let Some(pid) = pid {
        let _ = Command::new("kill").arg(pid.to_string()).status();
    }
    drop(guard);
    drop(taken);

    for word in [
        "warning: this computer is NOT receiving messages".to_string(),
        format!("LAN port 127.0.0.1:{port} is busy or unavailable"),
        format!(
            "(log: {})",
            dir.path().join("raven-node-service.log").display()
        ),
        "Sending still works.".to_string(),
        // The way out must work: the running service keeps its busy port, so the
        // variable only helps after it is stopped (and it names how, by pid).
        "free that port (the service keeps retrying by itself)".to_string(),
        format!(
            "run ash again with RAVEN_SERVICE_LAN_LISTEN=127.0.0.1:{}",
            port + 1
        ),
        "Setting the variable while this service keeps running changes nothing".to_string(),
    ] {
        assert!(err.contains(&word), "{word:?} missing from: {err}");
    }
    let pid = pid.expect("the started notice names the service process");
    let stop = if cfg!(windows) {
        format!("taskkill /F /PID {pid}")
    } else {
        format!("kill {pid}")
    };
    assert!(
        err.contains(&format!("stop this service ({stop})")),
        "{stop:?} missing from: {err}"
    );
    assert!(!err.contains("it is receiving messages"), "{err}");
    assert!(!err.contains("IPC + LAN receive on"), "{err}");
    assert_eq!(err.matches("is NOT receiving").count(), 1, "once: {err}");
    // Sending still got as far as the peer (nothing listens on port 9).
    assert!(err.contains("NOT SENT: Bob's computer is there"), "{err}");
}

/// `ash listen --listen` receives on the port it was given: the address to tell
/// a friend carries that port, the service really answers there, and the user
/// is told how to keep that port for a service a send starts by itself.
#[test]
fn listen_on_a_chosen_port_receives_there() {
    use std::io::BufRead;
    use std::os::unix::process::CommandExt;
    if raven_node_next_to_ash().is_none() {
        eprintln!("skipped: raven-node is not built next to ash");
        return;
    }
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let (dir, _bob, guard) = chat_profile();
    let logs = tempfile::tempdir().unwrap();
    let err_log = logs.path().join("stderr.txt");
    let mut c = ash(dir.path());
    c.args(["listen", "--listen", &format!("127.0.0.1:{port}")])
        // Its own process group: ash and the raven-node it runs stop together.
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&err_log).unwrap());
    let mut child = c.spawn().expect("spawn ash listen");
    let (tx, lines) = std::sync::mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut seen: Vec<String> = Vec::new();
    // The screen ends with a blank line after "Accepting your …" (and the hint).
    let complete = |seen: &[String]| {
        seen.iter()
            .position(|l| l.contains("Accepting your"))
            .is_some_and(|at| seen[at..].iter().any(|l| l.is_empty()))
    };
    while !complete(&seen) {
        let left = deadline.saturating_duration_since(Instant::now());
        match lines.recv_timeout(left) {
            Ok(line) => seen.push(line),
            Err(_) => break,
        }
    }
    // Before anything is stopped: something must answer on that port now.
    let answered = std::net::TcpStream::connect(("127.0.0.1", port)).is_ok();
    let _ = Command::new("kill")
        .args(["-TERM", &format!("-{}", child.id())])
        .status();
    let _ = child.wait();
    drop(guard);
    let out = seen.join("\n");
    let err = std::fs::read_to_string(&err_log).unwrap_or_default();

    assert!(out.contains("LISTENING"), "stdout: {out}\nstderr: {err}");
    assert!(
        out.contains(&format!("127.0.0.1:{port} (this computer only)")),
        "{out}"
    );
    assert!(
        out.contains(&format!("export RAVEN_SERVICE_LAN_LISTEN=127.0.0.1:{port}")),
        "{out}"
    );
    assert!(
        answered,
        "nothing answers on 127.0.0.1:{port}: {out}\n{err}"
    );
}

// ── how a send ends, against a faked local service and a real peer ──────────

const UP: u8 = 0;
const DOWN: u8 = 1;
const WRONG_KEY: u8 = 2;
/// Bob answers every message with the FIRST ACK he ever sent (a stale or
/// replayed receipt for an earlier message).
const STALE_ACK: u8 = 3;

const REFUSED: &str =
    "lan connect: cannot connect to 127.0.0.1:9 (127.0.0.1:9: Connection refused (os error 61))";
const PEER_CLOSED: &str = "LAN_DIAL_PEER_CLOSED: the peer closed the connection without replying; \
     the frames were sent, delivery is unconfirmed and a retry is safe";

/// raven-node's text for a p2p dial that reached nobody.
const P2P_UNREACHABLE_TEXT: &str =
    "P2P_UNREACHABLE: the contact is unreachable on every p2p address it has (direct and relay)";

fn lab_backends() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        for key in [
            "RAVEN_SESSION_BACKEND",
            "RAVEN_PREKEY_BACKEND",
            "RAVEN_CHAT_HISTORY_BACKEND",
            "RAVEN_IDENTITY_BACKEND",
        ] {
            unsafe { std::env::set_var(key, "locked-file") };
        }
    });
}

/// Alice (the profile under test, run by the real `ash`) and Bob (a second
/// profile the faked service drives), joined by a UDS server on Alice's socket.
struct Net {
    /// Stops a service ash started for Alice if the fake ever stalled
    /// (dropped first, before her folder goes).
    _stop: StopService,
    a: tempfile::TempDir,
    b: tempfile::TempDir,
    mode: Arc<AtomicU8>,
    /// The faked service runs raven-node's background outbox (it accepts
    /// `OutboxKick`); off, it answers like an older service.
    outbox: Arc<AtomicBool>,
    /// Session reset lab switch for `ash` and the faked service.
    reset: bool,
    /// (op, address) of every dial the faked service was asked for.
    dials: Arc<Mutex<Vec<(String, String)>>>,
    /// Addresses whose dials are refused (nobody listening), whatever `mode`.
    dead: Arc<Mutex<HashSet<String>>>,
    /// What the faked service's p2p side says (dial errors, its status).
    p2p: P2pFake,
}

/// The faked service's p2p side: while `error` is set every `P2pDial` is
/// answered `P2P_DIAL` with it (after `delay`, on a thread of its own, so
/// the service keeps answering); `status` is the `p2p` and `unreachable`
/// its `Status` reports.
#[derive(Clone, Default)]
struct P2pFake {
    error: Arc<Mutex<Option<String>>>,
    delay: Arc<Mutex<Option<Duration>>>,
    status: Arc<Mutex<(Option<P2pStatusInfo>, Vec<ContactWhy>)>>,
    /// The Tor side: what the next `OnionDial`s get, in order (`None`: Bob
    /// answers; `Some(text)`: raven-node's ONION_UNREACHABLE with that text).
    /// Empty: Bob answers every one.
    onion: Arc<Mutex<std::collections::VecDeque<Option<String>>>>,
}

impl Net {
    /// `bob_trusts_alice`: Bob has Alice in his contacts (otherwise he refuses
    /// her first message, as a stranger's).
    fn new(bob_trusts_alice: bool) -> Self {
        Self::build(bob_trusts_alice, false)
    }

    /// Both sides run with the session reset lab switch on.
    fn with_reset(bob_trusts_alice: bool) -> Self {
        Self::build(bob_trusts_alice, true)
    }

    fn build(bob_trusts_alice: bool, reset: bool) -> Self {
        lab_backends();
        let (a, b) = (short_dir(), short_dir());
        let alice = Identity::from_seed(&[SEED; 32]);
        let bob = Identity::from_seed(&[0x42; 32]);
        plant_identity(a.path());
        for (dir, id) in [(a.path(), &alice), (b.path(), &bob)] {
            ensure_local_device_certificate(dir, id, PRIMARY_DEVICE_ID).unwrap();
            raven_core::ensure_local_prekey(dir, id).unwrap();
        }
        add_bob(a.path(), &bob, "127.0.0.1:9");
        if bob_trusts_alice {
            let row = serde_json::json!([{
                "petname": "Alice", "public_tag": "", "alias": "",
                "address": alice.address(), "pub_hex": pub_hex(&alice),
                "pinned": false, "lan_dial": ""
            }]);
            std::fs::write(b.path().join("contacts.json"), row.to_string()).unwrap();
        }
        let a_bundle = local_bundle(a.path(), &alice).unwrap();
        let mode = Arc::new(AtomicU8::new(UP));
        let outbox = Arc::new(AtomicBool::new(false));
        let dials: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
        let dead: Arc<Mutex<HashSet<String>>> = Arc::default();
        let p2p = P2pFake::default();
        let listener = UnixListener::bind(raven_core::default_socket_path(a.path())).unwrap();
        let (b_dir, bob_c, mode_c, outbox_c, dials_c, dead_c, p2p_c) = (
            b.path().to_path_buf(),
            Identity::from_seed(&[0x42; 32]),
            mode.clone(),
            outbox.clone(),
            dials.clone(),
            dead.clone(),
            p2p.clone(),
        );
        let alice_pub = alice.public_key_bytes();
        std::thread::spawn(move || {
            // Bob's side follows the test, never the suite's
            // RAVEN_LAB_SESSION_RESET.
            raven_core::session_reset::set_lab_session_reset_for_this_thread(Some(u8::from(reset)));
            let first_ack = std::sync::Mutex::new(None::<Vec<u8>>);
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                serve_one(
                    &mut stream,
                    &b_dir,
                    &bob_c,
                    &a_bundle,
                    &alice_pub,
                    &mode_c,
                    &first_ack,
                    &outbox_c,
                    &dials_c,
                    &dead_c,
                    &p2p_c,
                );
            }
        });
        Self {
            _stop: StopService(a.path().to_path_buf()),
            a,
            b,
            mode,
            outbox,
            reset,
            dials,
            dead,
            p2p,
        }
    }

    /// Bob loses his Raven state (sessions, prekeys, history) and starts again
    /// from the same seed; his device certificate stays.
    fn wipe_bob(&self) {
        // Prekey ids are seconds since 2020 and an install may run one ahead
        // of the clock: a real reinstall is never this fast, so wait until a
        // fresh id is above Bob's old one.
        let bob_pub = Identity::from_seed(&[0x42; 32]).public_key_bytes();
        let now = raven_core::clock::now_ms;
        let old_id = raven_core::PrekeyStore::load_checked(self.b.path())
            .ok()
            .and_then(|s| s.fetch_valid(&bob_pub, now()))
            .map_or(0, |b| b.signed_prekey_id);
        while raven_core::prekey_lifecycle::time_floor_signed_prekey_id(now()) <= old_id {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        for entry in std::fs::read_dir(self.b.path()).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "contacts.json" || name.starts_with("device") {
                continue;
            }
            let path = entry.path();
            if path.is_dir() {
                std::fs::remove_dir_all(&path).unwrap();
            } else {
                std::fs::remove_file(&path).unwrap();
            }
        }
        let bob = Identity::from_seed(&[0x42; 32]);
        ensure_local_device_certificate(self.b.path(), &bob, PRIMARY_DEVICE_ID).unwrap();
        raven_core::ensure_local_prekey(self.b.path(), &bob).unwrap();
    }

    fn set_mode(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }

    fn set_outbox(&self, running: bool) {
        self.outbox.store(running, Ordering::SeqCst);
    }

    fn send(&self, message: &str) -> Output {
        self.send_env(message, &[])
    }

    /// [`Self::send`] with extra environment for `ash`.
    fn send_env(&self, message: &str, env: &[(&str, &str)]) -> Output {
        let mut c = ash(self.a.path());
        c.args(["send", "--contact", "@bob"]);
        if self.reset {
            c.env("RAVEN_LAB_SESSION_RESET", "1");
        } else {
            c.env_remove("RAVEN_LAB_SESSION_RESET");
        }
        for (k, v) in env {
            c.env(k, v);
        }
        run(c, format!("{message}\n").as_bytes())
    }

    /// `send --contact @bob --carrier p2p` with the p2p lab switch (this is
    /// a debug build of `ash`). Route hints stay off whatever the suite's
    /// switches: with them and the p2p lab switch, learned custody runs and an
    /// offline contact's next step offers friend mailboxes instead of
    /// "Nothing to do" (Phase 3 P3.23, tested in ash's unit tests).
    fn send_p2p(&self, message: &str) -> Output {
        let mut c = ash(self.a.path());
        c.args(["send", "--contact", "@bob", "--carrier", "p2p"])
            .env("RAVEN_LAB_TEST_A", "1")
            .env("RAVEN_LAB_ROUTE_HINTS", "0");
        run(c, format!("{message}\n").as_bytes())
    }

    /// Every p2p dial fails with raven-node's P2P_UNREACHABLE text and
    /// `block` (none: an older raven-node's text); `None` lets them through.
    fn set_p2p_error(&self, block: Option<Option<&str>>) {
        *self.p2p.error.lock().unwrap() = block.map(|b| match b {
            Some(b) => format!("{P2P_UNREACHABLE_TEXT}; {b}"),
            None => P2P_UNREACHABLE_TEXT.to_string(),
        });
    }

    /// The next `OnionDial`s, in order: `None` Bob answers, `Some(text)`
    /// raven-node's ONION_UNREACHABLE with that text.
    fn set_onion_plan(&self, plan: &[Option<&str>]) {
        *self.p2p.onion.lock().unwrap() = plan.iter().map(|p| p.map(str::to_string)).collect();
    }

    /// The dials asked for since the last call: (op, address).
    fn take_dials(&self) -> Vec<(String, String)> {
        std::mem::take(&mut *self.dials.lock().unwrap())
    }

    fn bob_inbox(&self) -> Vec<String> {
        let mut store = raven_core::IndexedSessionStore::open(self.b.path()).unwrap();
        let mut texts: Vec<String> = store
            .list_endpoint_inbox()
            .unwrap()
            .into_iter()
            .map(|row| String::from_utf8_lossy(&row.plaintext).into_owned())
            .collect();
        texts.sort();
        texts
    }
}

/// One framed `IpcRequest` in, one framed `IpcResponse` out.
#[allow(clippy::too_many_arguments)]
fn serve_one(
    stream: &mut UnixStream,
    b_dir: &Path,
    bob: &Identity,
    a_bundle: &raven_core::LanBundle,
    alice_pub: &[u8; 32],
    mode: &AtomicU8,
    first_ack: &std::sync::Mutex<Option<Vec<u8>>>,
    outbox: &AtomicBool,
    dials: &Mutex<Vec<(String, String)>>,
    dead: &Mutex<HashSet<String>>,
    p2p: &P2pFake,
) {
    let mut len = [0u8; 4];
    if stream.read_exact(&mut len).is_err() {
        return;
    }
    let mut frame = len.to_vec();
    frame.resize(4 + u32::from_be_bytes(len) as usize, 0);
    if stream.read_exact(&mut frame[4..]).is_err() {
        return;
    }
    let error = |message: &str| IpcResponse::Error {
        v: IPC_VERSION,
        code: "LAN_DIAL".into(),
        message: message.into(),
    };
    // A dial: logged, refused at a dead address, else Bob answers; the reply
    // kind follows the carrier (`lan`, `internet` or `p2p`, through a relay).
    let serve_dial = |op: &str, addr: String, frames_b64: Vec<String>| {
        dials.lock().unwrap().push((op.into(), addr.clone()));
        let answer = if dead.lock().unwrap().contains(&addr) {
            error(REFUSED)
        } else {
            dial_bob(
                b_dir,
                bob,
                a_bundle,
                alice_pub,
                mode,
                first_ack,
                &frames_b64,
            )
        };
        match (op, answer) {
            ("internet", IpcResponse::LanDialResult { v, frames_b64 }) => {
                IpcResponse::InternetDialResult { v, frames_b64 }
            }
            ("p2p", IpcResponse::LanDialResult { v, frames_b64 }) => IpcResponse::P2pDialResult {
                v,
                frames_b64,
                path: Some("relayed".into()),
            },
            ("onion", IpcResponse::LanDialResult { v, frames_b64 }) => {
                IpcResponse::OnionDialResult { v, frames_b64 }
            }
            (_, other) => other,
        }
    };
    let (p2p_status, unreachable) = p2p.status.lock().unwrap().clone();
    let response = match decode_request(&frame) {
        Ok(IpcRequest::Ping { .. }) => IpcResponse::Pong { v: IPC_VERSION },
        Ok(IpcRequest::Status { .. }) => IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into(), "lan_direct".into()],
            p2p: p2p_status.map(Box::new),
            pid: None,
            lan_listen: None,
            last_paths: Vec::new(),
            route_hints: None,
            unreachable,
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
        },
        Ok(IpcRequest::LanDial {
            lan_dial,
            frames_b64,
            ..
        }) => serve_dial("lan", lan_dial, frames_b64),
        Ok(IpcRequest::InternetDial {
            internet_dial,
            frames_b64,
            ..
        }) => serve_dial("internet", internet_dial, frames_b64),
        Ok(IpcRequest::P2pDial {
            multiaddr,
            frames_b64,
            ..
        }) => match p2p.error.lock().unwrap().clone() {
            None => serve_dial("p2p", multiaddr, frames_b64),
            Some(message) => {
                dials.lock().unwrap().push(("p2p".into(), multiaddr));
                let reply = IpcResponse::Error {
                    v: IPC_VERSION,
                    code: "P2P_DIAL".into(),
                    message,
                };
                if let Some(delay) = *p2p.delay.lock().unwrap() {
                    let mut late = stream.try_clone().unwrap();
                    std::thread::spawn(move || {
                        std::thread::sleep(delay);
                        let _ = late.write_all(&encode_response(&reply).unwrap());
                    });
                    return;
                }
                reply
            }
        },
        Ok(IpcRequest::OnionDial {
            onion_dial,
            frames_b64,
            ..
        }) => match p2p.onion.lock().unwrap().pop_front().flatten() {
            None => serve_dial("onion", onion_dial, frames_b64),
            Some(message) => {
                dials.lock().unwrap().push(("onion".into(), onion_dial));
                IpcResponse::Error {
                    v: IPC_VERSION,
                    code: "ONION_UNREACHABLE".into(),
                    message,
                }
            }
        },
        Ok(IpcRequest::OutboxKick { .. }) if outbox.load(Ordering::SeqCst) => {
            IpcResponse::Accepted { v: IPC_VERSION }
        }
        _ => error("unsupported request"),
    };
    let _ = stream.write_all(&encode_response(&response).unwrap());
}

/// One dial reaching Bob: his offer, then his real dispatcher's replies.
fn dial_bob(
    b_dir: &Path,
    bob: &Identity,
    a_bundle: &raven_core::LanBundle,
    alice_pub: &[u8; 32],
    mode: &AtomicU8,
    first_ack: &std::sync::Mutex<Option<Vec<u8>>>,
    frames_b64: &[String],
) -> IpcResponse {
    let error = |message: &str| IpcResponse::Error {
        v: IPC_VERSION,
        code: "LAN_DIAL".into(),
        message: message.into(),
    };
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    match mode.load(Ordering::SeqCst) {
        DOWN => error(REFUSED),
        WRONG_KEY => error("identity bind does not match expected pub"),
        _ => {
            let offer = encode_local_offer(b_dir, bob).unwrap();
            let mut replies = vec![b64(&offer)];
            let mut failure = None;
            for b64_frame in frames_b64 {
                let f = base64::engine::general_purpose::STANDARD
                    .decode(b64_frame)
                    .unwrap();
                match dispatch_frame(b_dir, bob, a_bundle, alice_pub, &f) {
                    Ok(more) => {
                        for reply in more {
                            let is_ack = raven_core::Envelope::unpack(&reply)
                                .is_some_and(|e| e.env_type == raven_core::EnvType::Ack as u8);
                            let mut kept = first_ack.lock().unwrap();
                            let reply = match (is_ack, kept.as_ref()) {
                                (true, None) => {
                                    *kept = Some(reply.clone());
                                    reply
                                }
                                (true, Some(old)) if mode.load(Ordering::SeqCst) == STALE_ACK => {
                                    old.clone()
                                }
                                _ => reply,
                            };
                            replies.push(b64(&reply));
                        }
                    }
                    // The daemon closes on a dispatch error: the dialer sees a
                    // silent peer (the stranger case).
                    Err(_) => {
                        failure = Some(PEER_CLOSED.to_string());
                        break;
                    }
                }
            }
            match failure {
                Some(text) => error(&text),
                None => IpcResponse::LanDialResult {
                    v: IPC_VERSION,
                    frames_b64: replies,
                },
            }
        }
    }
}

#[test]
fn a_delivered_send_names_the_person_keeps_the_status_line_and_drops_the_jargon() {
    let net = Net::new(true);
    let o = net.send("hello Bob");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        out.lines()
            .any(|l| l == "First time talking to Bob: secure connection set up."),
        "{out}"
    );
    // The literal scripts and the iOS gate match, on stdout, with the person.
    assert!(
        out.lines()
            .any(|l| l == "status delivered — Bob confirmed receipt"),
        "{out}"
    );
    for jargon in [
        "PairResponse",
        "mid=",
        "carrier=",
        "indexed message",
        "queued after dial",
    ] {
        assert!(!out.contains(jargon), "{jargon} in default output: {out}");
    }
    assert_eq!(
        err, "",
        "the service was already running: nothing to announce"
    );
    assert_eq!(net.bob_inbox(), vec!["hello Bob"]);

    // The second message needs no first-contact line.
    let o = net.send("second");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{out}");
    assert!(!out.contains("First time"), "{out}");
    assert!(
        out.contains("status delivered — Bob confirmed receipt"),
        "{out}"
    );
    assert_eq!(net.bob_inbox(), vec!["hello Bob", "second"]);
}

/// Removing a contact keeps its secure sessions until they expire, so a
/// contact added back is reached again at once (carrier matrix C90): the
/// contact still holds its side of them, and what it sealed under them.
#[test]
fn removing_a_contact_keeps_its_sessions_until_they_expire() {
    let net = Net::new(true);
    let o = net.send("hello Bob");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let bob = Identity::from_seed(&[0x42; 32]).public_key_bytes();
    let sessions = |dir: &Path| {
        raven_core::IndexedSessionStore::open(dir)
            .unwrap()
            .find_confirmed_sessions_for_peer_at(&bob, raven_core::clock::now_ms())
            .unwrap()
            .len()
    };
    assert_eq!(sessions(net.a.path()), 1);
    let mut c = ash(net.a.path());
    c.args(["contact", "remove", "--petname", "Bob", "--yes"]);
    let o = run(c, b"");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert_eq!(sessions(net.a.path()), 1);
}

/// Field test E2 r7: a secure connection set up again with a contact this
/// computer has talked with is no "First time talking". Here Alice's
/// session store has nothing of Bob any more (as after its prune, once the
/// end it remembers is older than 30 days): her chat history says they
/// talked.
#[test]
fn a_new_secure_connection_with_a_contact_talked_with_is_no_first_time() {
    let net = Net::new(true);
    let o = net.send("hello Bob");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{out}");
    assert!(
        out.lines()
            .any(|l| l == "First time talking to Bob: secure connection set up."),
        "{out}"
    );
    for suffix in ["", "-wal", "-shm"] {
        let path = net.a.path().join(format!(
            "{}{suffix}",
            raven_core::indexed_session_store::INDEXED_SESSION_METADATA_FILE
        ));
        let _ = std::fs::remove_file(path);
    }
    let o = net.send("hello again");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        out.lines()
            .any(|l| l == "New secure connection with Bob set up (the last one had run out)."),
        "{out}"
    );
    assert!(!out.contains("First time"), "{out}");
    assert!(
        out.contains("status delivered — Bob confirmed receipt"),
        "{out}"
    );
    assert_eq!(net.bob_inbox(), vec!["hello Bob", "hello again"]);
}

#[test]
fn a_stranger_is_told_to_ask_to_be_added_and_nothing_says_delivered() {
    let net = Net::new(false);
    let o = net.send("stranger probe");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{out}\n{err}");
    assert!(!out.to_lowercase().contains("delivered"), "stdout: {out}");
    assert!(
        err.starts_with("NOT SENT: Bob did not accept your first message"),
        "{err}"
    );
    assert!(err.contains("has not added you as a contact yet"), "{err}");
    assert!(err.contains("Nothing was queued"), "{err}");
    assert!(err.contains("ash whoami"), "{err}");
    let sentence = err.split("(technical:").next().unwrap();
    assert!(!sentence.contains("retry is safe"), "{err}");
    assert!(
        err.contains("(technical: ipc LAN_DIAL: LAN_DIAL_PEER_CLOSED"),
        "{err}"
    );
    assert!(net.bob_inbox().is_empty());
}

#[test]
fn an_unreachable_first_contact_says_nothing_was_queued_and_why() {
    let net = Net::new(true);
    net.set_mode(DOWN);
    let o = net.send("anyone there");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{err}");
    assert!(!out.to_lowercase().contains("delivered"), "{out}");
    assert!(
        err.starts_with(
            "NOT SENT: Bob's computer is there, but Raven isn't receiving right now (it may be \
             locked or closed)."
        ),
        "{err}"
    );
    assert!(
        err.contains(
            "It was not kept: a first message needs you and Bob both online (RAVEN hasn't \
             connected with Bob yet)."
        ),
        "{err}"
    );
    // E1: the computer answered at that address: no address fix, no `ash
    // listen`.
    assert!(
        err.contains("Ask Bob to open Raven, then send again."),
        "{err}"
    );
    let head = err.split("(technical:").next().unwrap();
    assert!(
        !head.contains("set-dial") && !head.contains("ash listen"),
        "{err}"
    );
    assert!(
        err.contains("Connection refused"),
        "the raw text stays at the end: {err}"
    );
}

#[test]
fn a_changed_address_is_flagged_as_a_different_computer() {
    let net = Net::new(true);
    net.set_mode(WRONG_KEY);
    let o = net.send("hi");
    let err = text(&o.stderr);
    assert_eq!(code(&o), 1, "{err}");
    assert!(err.contains("answered, but it is not Bob"), "{err}");
    assert!(err.contains("compare the fingerprint"), "{err}");
    assert!(err.contains("ash contact remove --petname Bob"), "{err}");
    assert!(err.starts_with("NOT SENT: "), "{err}");
}

/// The whole life of queued messages: sent while the peer is down (queued, with
/// the real retry rule), a second one queued behind it, then both delivered in
/// order by the next send, and every line says which text it is about.
#[test]
fn queued_messages_are_named_by_their_text_and_delivered_by_the_next_send() {
    let net = Net::new(true);
    assert_eq!(code(&net.send("first")), 0);
    net.set_mode(DOWN);

    let o = net.send("are you there");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{err}");
    assert!(!out.to_lowercase().contains("delivered"), "stdout: {out}");
    assert!(
        err.starts_with(
            "not delivered yet: your message \"are you there\" to Bob is queued locally because"
        ),
        "{err}"
    );
    // This faked service has no background outbox (an older raven-node): the
    // next send retries it, until the envelope's expiry a day from now.
    assert!(err.contains("It is NOT retried automatically"), "{err}");
    // On this computer's clock, never UTC (cutoff pack CP.6).
    assert!(err.contains("in about 24 h)"), "{err}");
    assert!(only_local_zone(&err), "{err}");

    // Bob is still unreachable: the second message queues behind the first
    // instead of being refused.
    let o = net.send("second one");
    let err = text(&o.stderr);
    assert_eq!(code(&o), 1, "{err}");
    assert!(
        err.starts_with(
            "not delivered yet: your message \"second one\" to Bob is queued locally because"
        ),
        "{err}"
    );

    net.set_mode(UP);
    let o = net.send("third");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}\n{err}");
    let earlier: Vec<&str> = out
        .lines()
        .filter(|l| l.starts_with("status delivered — your earlier message"))
        .collect();
    assert_eq!(
        earlier,
        vec![
            "status delivered — your earlier message \"are you there\" to Bob has now arrived and Bob confirmed it",
            "status delivered — your earlier message \"second one\" to Bob has now arrived and Bob confirmed it",
        ],
        "{out}"
    );
    assert!(
        out.lines()
            .any(|l| l == "status delivered — Bob confirmed receipt"),
        "{out}"
    );
    assert_eq!(
        net.bob_inbox(),
        vec!["are you there", "first", "second one", "third"]
    );
}

/// While the peer stays unreachable, messages queue behind each other only up
/// to the per-peer cap; the next one is refused and nothing of it is queued.
#[test]
fn the_offline_queue_per_peer_is_bounded() {
    let net = Net::new(true);
    assert_eq!(code(&net.send("first")), 0);
    net.set_mode(DOWN);
    for i in 0..32 {
        let o = net.send(&format!("waiting {i}"));
        let err = text(&o.stderr);
        assert!(err.starts_with("not delivered yet: "), "message {i}: {err}");
    }
    let o = net.send("one too many");
    let err = text(&o.stderr);
    assert_eq!(code(&o), 1, "{err}");
    assert!(
        err.starts_with("NOT SENT: 32 earlier messages to Bob are already waiting"),
        "{err}"
    );
    net.set_mode(UP);
    assert_eq!(code(&net.send("after")), 0);
    let inbox = net.bob_inbox();
    assert!(!inbox.iter().any(|m| m == "one too many"), "{inbox:?}");
    for i in 0..32 {
        let want = format!("waiting {i}");
        assert!(inbox.contains(&want), "{want} missing: {inbox:?}");
    }
}

/// With raven-node's background outbox the queued sentence says so: nothing to
/// do, no retyping, and until when it keeps trying (a day, the envelope's
/// validity). The send itself returns at once instead of waiting it out.
#[test]
fn a_queued_message_is_handed_to_the_background_outbox() {
    let net = Net::new(true);
    assert_eq!(code(&net.send("first")), 0);
    net.set_mode(DOWN);
    net.set_outbox(true);
    let started = std::time::Instant::now();
    let o = net.send("are you there");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "a queued send ends within 10 s"
    );
    assert_eq!(code(&o), 1, "not delivered yet: {err}");
    assert!(!out.to_lowercase().contains("delivered"), "stdout: {out}");
    assert!(
        err.starts_with(
            "not delivered yet: your message \"are you there\" to Bob is queued locally because"
        ),
        "{err}"
    );
    for words in [
        "Queued: raven-node keeps trying in the background until ",
        "in about 24 h)",
        "Do not retype this message.",
    ] {
        assert!(err.contains(words), "{words:?} missing: {err}");
    }
    assert!(!err.contains("NOT retried"), "{err}");
    assert!(only_local_zone(&err), "{err}");
    // The routes this send used are recorded for the worker (hints only).
    let routes = std::fs::read_to_string(net.a.path().join("outbox_routes.json")).unwrap();
    assert!(routes.contains("127.0.0.1:9"), "{routes}");
}

/// The long message horizon's lab switch (Phase 5a, P5.8) for one `ash`
/// command of this debug build; the letters and route hints stay off
/// whatever the suite's switches.
fn with_horizon(mut c: Command) -> Command {
    c.env("RAVEN_LAB_TEST_A", "1")
        .env("RAVEN_LAB_HORIZON", "1")
        .env_remove("RAVEN_LAB_LETTER")
        .env("RAVEN_LAB_ROUTE_HINTS", "0");
    c
}

/// P5.8: with the horizon on, a message to Bob, away and with no secure
/// connection yet, is parked instead of NOT SENT: the queued line says
/// what happens next and until when, `outbox list` shows it waiting until
/// its deadline, `contact list` says messages can wait 7 days, and the
/// next send that reaches Bob sets up the connection and delivers it first.
#[test]
fn an_unreachable_contact_without_a_session_parks_the_message_with_the_horizon() {
    let net = Net::new(true);
    net.set_mode(DOWN);
    let horizon = [
        ("RAVEN_LAB_TEST_A", "1"),
        ("RAVEN_LAB_HORIZON", "1"),
        ("RAVEN_LAB_LETTER", "0"),
        ("RAVEN_LAB_ROUTE_HINTS", "0"),
    ];
    let o = net.send_env("while you were away", &horizon);
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{err}");
    assert!(!out.to_lowercase().contains("delivered"), "stdout: {out}");
    assert!(
        err.starts_with(
            "not delivered yet: your message \"while you were away\" to Bob is queued: Bob \
             isn't reachable now. When you are both on the same network, RAVEN first sets up a \
             new secure connection, then sends it. It can wait until "
        ),
        "{err}"
    );
    assert!(err.contains("Do not retype this message."), "{err}");
    assert!(!err.contains("NOT SENT"), "{err}");
    assert!(only_local_zone(&err), "{err}");

    let mut c = with_horizon(ash(net.a.path()));
    c.args(["outbox", "list"]);
    let o = run(c, b"");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(out.contains("(1 waiting)"), "{out}");
    assert!(out.contains("waiting · until "), "{out}");

    let mut c = with_horizon(ash(net.a.path()));
    c.args(["contact", "list"]);
    let o = run(c, b"");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        out.contains("If Bob is away, Raven keeps trying for up to 7 days (until "),
        "{out}"
    );

    net.set_mode(UP);
    let o = net.send_env("back again", &horizon);
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        out.lines().any(|l| l
            == "status delivered — your earlier message \"while you were away\" to Bob has now \
                arrived and Bob confirmed it"),
        "{out}"
    );
    assert_eq!(net.bob_inbox(), vec!["back again", "while you were away"]);
}

/// raven-node's words for a Tor connect that did not get through.
const TOR_TIMEOUT: &str = "ONION_UNREACHABLE: the contact's onion service did not answer over \
     Tor (tor timeout)";

/// Bob verified and reached only over Tor (a signed onion address, no LAN
/// address).
fn make_bob_tor_only(net: &Net) {
    let bob = Identity::from_seed(&[0x42; 32]);
    let hs_id = Identity::from_seed(&[0x44; 32]).public_key_bytes();
    let binding =
        raven_core::onion::OnionBinding::sign(&bob, hs_id, raven_core::onion::now_s()).to_text();
    edit_bob_row(net, |row| {
        row["pinned"] = true.into();
        row["lan_dial"] = "".into();
        row["onion"] = binding.clone().into();
    });
}

/// Field test E3 round 2 (mac-b to win-c, a message LOST): the two had
/// talked for hours, their secure connection had ended (24 h), so the send
/// set up a new one. Tor answered its check ("answered first (10.4 s)"),
/// then the new connection's first step over Tor got no answer, and the
/// message was "NOT SENT ... It was not kept: a first message needs you
/// and win-c both online", with LAN advice ("same network", "set-dial")
/// and raven-node's code. A message to a verified friend is never dropped
/// for want of a connection: it waits (the long message horizon), the
/// words do not contradict Tor's answer and give no LAN or developer
/// advice, and it goes when the friend can be reached again.
#[test]
fn a_message_after_the_session_ended_is_kept_when_tor_drops_the_new_connection() {
    if !cfg!(debug_assertions) {
        return; // the lab clock and the lab switches are debug-only
    }
    let net = Net::new(true);
    make_bob_tor_only(&net);
    let clock_dir = tempfile::tempdir().unwrap();
    let clock = clock_dir.path().join("offset-ms");
    std::fs::write(&clock, "0").unwrap();
    let clock_text = clock.to_string_lossy().into_owned();
    let env = [
        ("RAVEN_LAB_TEST_A", "1"),
        ("RAVEN_LAB_HORIZON", "1"),
        ("RAVEN_LAB_LETTER", "0"),
        ("RAVEN_LAB_ROUTE_HINTS", "0"),
        ("RAVEN_LAB_TOR", "1"),
        ("RAVEN_LAB_CLOCK_FILE", clock_text.as_str()),
    ];
    // Over Tor, a new secure connection, delivered.
    let o = net.send_env("before the connection ended", &env);
    assert_eq!(code(&o), 0, "{}\n{}", text(&o.stdout), text(&o.stderr));
    assert_eq!(net.bob_inbox(), vec!["before the connection ended"]);
    // A day and an hour later on Alice's clock: the connection ended.
    std::fs::write(&clock, (25 * 3_600_000u64).to_string()).unwrap();
    // Tor answers the check; the new connection's first step gets no answer.
    net.set_onion_plan(&[None, Some(TOR_TIMEOUT)]);
    let o = net.send_env("after the connection ended", &env);
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{out}\n{err}");
    assert!(!err.contains("NOT SENT"), "{err}");
    assert!(!err.contains("not kept"), "{err}");
    assert!(err.contains("queued"), "{err}");
    // The person's words (a script, as here, also gets raven-node's codes
    // at the end; a terminal shows them with --verbose only).
    let words = err.split("(technical:").next().unwrap();
    for advice in [
        "same network",
        "set-dial",
        "IP:PORT",
        "ONION_UNREACHABLE",
        "ipc ",
    ] {
        assert!(!words.contains(advice), "{advice}: {err}");
    }
    // It never says Tor did not answer after Tor answered.
    assert!(!words.contains("couldn't be reached over Tor"), "{err}");
    let mut c = with_horizon(ash(net.a.path()));
    c.args(["outbox", "list"])
        .env("RAVEN_LAB_CLOCK_FILE", &clock);
    let o = run(c, b"");
    let listed = text(&o.stdout);
    assert!(listed.contains("(1 waiting)"), "{listed}");
    // Its words: Bob answered over Tor; it goes as soon as Bob can be
    // reached.
    assert!(
        err.starts_with(
            "not delivered yet: your message \"after the connection ended\" to Bob is queued: \
             Bob answered over Tor, but the new secure connection was not finished this time. \
             As soon as Bob can be reached, RAVEN first sets up a new secure connection, then \
             sends it."
        ),
        "{err}"
    );
    // Bob can be reached again: the next send that reaches him sends the
    // waiting message first. (Bob's side runs on this test's real clock:
    // Alice's goes back to it, so the two agree on what is valid.)
    std::fs::write(&clock, "0").unwrap();
    let o = net.send_env("back again", &env);
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert_eq!(
        net.bob_inbox(),
        vec![
            "after the connection ended",
            "back again",
            "before the connection ended"
        ]
    );
}

/// Field test E3 round 2 (mac-b #11, and R2-6): a send to a friend
/// reached over Tor, with no secure connection, got Tor's "unreachable"
/// after 5.3 s while Tor worked, and queued with words about "the same
/// network". Tor's quick miss is checked once more at once, within the
/// send's Tor wait: the second check answers, the new connection is set up
/// over Tor and the message is delivered, nothing queued.
#[test]
fn a_quick_tor_miss_on_a_new_connection_is_checked_again_and_delivered() {
    let net = Net::new(true);
    make_bob_tor_only(&net);
    let env = [
        ("RAVEN_LAB_HORIZON", "1"),
        ("RAVEN_LAB_LETTER", "0"),
        ("RAVEN_LAB_ROUTE_HINTS", "0"),
        ("RAVEN_LAB_TOR", "1"),
    ];
    let miss = "ONION_UNREACHABLE: the contact's onion service did not answer over Tor \
                (rendezvous failed)";
    net.set_onion_plan(&[Some(miss)]);
    let o = net.send_env("over Tor at last", &env);
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(!err.contains("same network"), "{err}");
    assert_eq!(net.bob_inbox(), vec!["over Tor at last"]);
    // The check twice, then the new connection and the message.
    let tor: Vec<String> = net
        .take_dials()
        .into_iter()
        .filter(|(op, _)| op == "onion")
        .map(|(op, _)| op)
        .collect();
    assert!(tor.len() >= 3, "{tor:?}");
}

/// A saved computer name that resolves nowhere: `.invalid` never does, and
/// the resolver says so at once.
const AWAY_NAME: &str = "no-such-host.invalid:7420";

/// What Bob being away reads as when his saved name does not resolve.
const NAME_NOT_FOUND: &str = "Bob's computer name no-such-host.invalid could not be found on \
     this network (Bob may be away, or on another network)";

/// `contact set-addr @bob --lan dial` in Alice's book.
fn set_bob_lan(dir: &Path, dial: &str) {
    let mut c = ash(dir);
    c.args(["contact", "set-addr", "@bob", "--lan", dial]);
    let o = run(c, b"");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
}

/// Cutoff F1 (CP.9), the OFFLINE_LAN gate open (its debug switch): Bob is
/// unverified, the two share a session, and his saved computer name does not
/// resolve now (he is away). The send asks the service for no dial at all and
/// queues the message, saying his computer name was not found; the outbox is
/// handed the name, which raven-node localizes again at every dial.
#[test]
fn unverified_unresolved_name_queues_with_a_session_under_the_switch() {
    let net = Net::new(true);
    assert_eq!(code(&net.send("first")), 0);
    set_bob_lan(net.a.path(), AWAY_NAME);
    net.set_outbox(true);
    net.take_dials();
    let started = Instant::now();
    let o = net.send_env("are you there", &[("RAVEN_LAB_OFFLINE", "1")]);
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert!(started.elapsed() < Duration::from_secs(10), "{err}");
    assert_eq!(code(&o), 1, "{out}\n{err}");
    assert!(
        err.starts_with(&format!(
            "not delivered yet: your message \"are you there\" to Bob is queued locally \
             because {NAME_NOT_FOUND}."
        )),
        "{err}"
    );
    assert!(
        err.contains("When you are both on the same network it goes out by itself."),
        "{err}"
    );
    assert!(!err.contains(raven_core::CONTACT_NOT_VERIFIED), "{err}");
    assert!(!err.contains("could not be completed"), "{err}");
    assert_eq!(net.take_dials(), Vec::new(), "nothing is dialled at a name");
    let routes = std::fs::read_to_string(net.a.path().join("outbox_routes.json")).unwrap();
    assert!(routes.contains(AWAY_NAME), "{routes}");
    assert_eq!(net.bob_inbox(), vec!["first"]);
}

/// The same name without a session: NOT SENT, a first message needs you
/// both online, never "not verified" while the gate is open. With the gate closed
/// (its debug switch at 0) it is today's refusal: not verified, the name
/// could not be resolved, nothing dialled.
#[test]
fn unverified_unresolved_name_is_not_sent_without_a_session() {
    let net = Net::new(true);
    set_bob_lan(net.a.path(), AWAY_NAME);
    let o = net.send_env("anyone there", &[("RAVEN_LAB_OFFLINE", "0")]);
    let err = text(&o.stderr);
    assert_eq!(code(&o), 1, "{err}");
    assert!(err.starts_with("NOT SENT: Bob is not verified"), "{err}");
    assert!(
        err.contains(&format!("{AWAY_NAME} could not be resolved")),
        "{err}"
    );
    assert!(err.contains(raven_core::CONTACT_NOT_VERIFIED), "{err}");

    let o = net.send_env("anyone there", &[("RAVEN_LAB_OFFLINE", "1")]);
    let err = text(&o.stderr);
    assert_eq!(code(&o), 1, "{err}");
    assert!(
        err.starts_with(&format!("NOT SENT: {NAME_NOT_FOUND}.")),
        "{err}"
    );
    assert!(
        err.contains(
            "It was not kept: a first message needs you and Bob both online (RAVEN hasn't \
             connected with Bob yet). Send it again when Bob is online."
        ),
        "{err}"
    );
    assert!(!err.contains(raven_core::CONTACT_NOT_VERIFIED), "{err}");
    assert_eq!(net.take_dials(), Vec::new(), "nothing is dialled");
    assert!(net.bob_inbox().is_empty());
    assert!(
        !net.a.path().join("outbox_routes.json").exists(),
        "nothing queued"
    );
}

/// A local chat-history failure while the message is being staged leaves nothing
/// pending: "nothing was queued" is true, and a later send does not silently
/// deliver the text the user was told was NOT sent (retyping it, as advised,
/// would then have sent it twice).
#[test]
fn a_history_failure_while_staging_leaves_nothing_behind_to_deliver_later() {
    let net = Net::new(true);
    assert_eq!(code(&net.send("first")), 0);
    let history = net.a.path().join("chat_history.json");
    let good = std::fs::read(&history).expect("a delivered send wrote the chat history");
    let mut bad = good.clone();
    for byte in bad.iter_mut().skip(8).take(80) {
        *byte ^= 0xA5;
    }
    std::fs::write(&history, &bad).unwrap();

    let o = net.send("lost text");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{out}\n{err}");
    assert!(err.starts_with("NOT SENT: "), "{err}");
    assert!(err.contains("Nothing was queued"), "{err}");
    assert!(!out.to_lowercase().contains("delivered"), "{out}");

    std::fs::write(&history, &good).unwrap();
    let o = net.send("next");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        !out.contains("earlier message"),
        "the text that was reported as not sent must not come back: {out}"
    );
    assert_eq!(net.bob_inbox(), vec!["first", "next"]);
}

/// An ACK that belongs to an EARLIER message (a stale or replayed receipt) must
/// never make the new message read "delivered": the new message stays
/// unconfirmed and is confirmed by a later send, once its own ACK comes back.
#[test]
fn an_ack_for_an_earlier_message_never_marks_the_new_one_delivered() {
    let net = Net::new(true);
    assert_eq!(code(&net.send("first")), 0);

    net.set_mode(STALE_ACK);
    let o = net.send("second");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_ne!(code(&o), 0, "{out}\n{err}");
    assert!(
        !out.contains("status delivered"),
        "a receipt for \"first\" must not confirm \"second\": {out}"
    );
    assert!(err.starts_with("sent, delivery unconfirmed"), "{err}");
    assert_eq!(net.bob_inbox(), vec!["first", "second"], "Bob did get it");

    net.set_mode(UP);
    let o = net.send("third");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        out.contains("your earlier message \"second\""),
        "its own ACK confirms it on the next send: {out}"
    );
    assert_eq!(net.bob_inbox(), vec!["first", "second", "third"]);
}

/// The chat shows what it sent and what happened to it, in plain words.
#[test]
fn the_chat_echoes_what_it_sent_with_the_outcome() {
    let net = Net::new(true);
    let mut c = ash(net.a.path());
    c.args(["send", "--contact", "@bob", "--chat"]);
    let o = run(c, b"hello bob\n/back\n");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{err}");
    assert!(out.contains("(secure connection with Bob set up)"), "{out}");
    assert!(
        out.contains("→ hello bob  ✓ Bob confirmed receipt"),
        "{out}"
    );
    assert!(
        !out.contains("status delivered"),
        "the chat has its own transcript line: {out}"
    );
    assert_eq!(err, "", "service up and receiving: no warning: {err}");
    assert_eq!(net.bob_inbox(), vec!["hello bob"]);

    net.set_mode(DOWN);
    let mut c = ash(net.a.path());
    c.args(["send", "--contact", "@bob", "--chat"]);
    let o = run(c, b"are you there\n/back\n");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{err}");
    assert!(
        out.contains("→ are you there  [queued: goes out with your next message]"),
        "{out}"
    );
    assert!(
        !out.to_lowercase().contains("delivered"),
        "stdout never claims delivery: {out}"
    );
    assert!(
        err.contains("not delivered yet: your message \"are you there\" to Bob is queued locally"),
        "{err}"
    );
}

#[test]
fn a_send_to_a_reinstalled_contact_is_delivered_with_the_reset_line() {
    let net = Net::with_reset(true);
    let o = net.send("before the reinstall");
    assert_eq!(code(&o), 0, "{}{}", text(&o.stdout), text(&o.stderr));
    net.wipe_bob();
    let o = net.send("after the reinstall");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}{err}");
    assert!(
        out.contains("RAVEN no longer had your secure connection"),
        "{out}{err}"
    );
    assert!(out.contains("status"), "{out}");
    assert!(out.contains("delivered"), "{out}");
    assert!(!err.contains("PEER_PREKEY_RESET"), "{err}");
    assert_eq!(net.bob_inbox(), vec!["after the reinstall".to_string()]);
    // The next send uses the new session directly: no reset line.
    let o = net.send("and again");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{out}{}", text(&o.stderr));
    assert!(!out.contains("RAVEN no longer had"), "{out}");
}

#[test]
fn without_the_switch_a_reinstalled_contact_keeps_todays_answer() {
    let net = Net::new(true);
    let o = net.send("before the reinstall");
    assert_eq!(code(&o), 0, "{}{}", text(&o.stdout), text(&o.stderr));
    net.wipe_bob();
    let o = net.send("after the reinstall");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_ne!(code(&o), 0, "{out}{err}");
    assert!(!out.contains("RAVEN no longer had"), "{out}");
    assert!(net.bob_inbox().is_empty());
}

/// Review regression: a message held in a session the contact lost (its
/// restart was held by the reset cooldown) never blocks later sends, and the
/// user is never told to type it again.
#[test]
fn a_held_row_in_a_retired_session_never_blocks_a_later_offline_send() {
    let net = Net::with_reset(true);
    assert_eq!(code(&net.send("m0")), 0);
    net.wipe_bob();
    let o = net.send("m1");
    assert_eq!(code(&o), 0, "{}{}", text(&o.stdout), text(&o.stderr));
    // Second reinstall within the cooldown: m2 is retired with its session and
    // waits; the user is told it is queued, never "NOT SENT ... send again".
    net.wipe_bob();
    let o = net.send("m2");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert!(
        !out.contains("NOT SENT") && !err.contains("NOT SENT"),
        "{out}{err}"
    );
    assert!(
        err.contains("not delivered yet") || out.contains("not delivered yet"),
        "{out}{err}"
    );
    // Bob reachable: an ordinary new session carries m3.
    let o = net.send("m3");
    assert_eq!(code(&o), 0, "{}{}", text(&o.stdout), text(&o.stderr));
    // Bob down: m4 is queued behind nothing that blocks it.
    net.set_mode(DOWN);
    let o = net.send("m4");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert!(
        !out.contains("NOT SENT") && !err.contains("NOT SENT"),
        "{out}{err}"
    );
    assert!(
        err.contains("not delivered yet") || out.contains("not delivered yet"),
        "{out}{err}"
    );
}

/// G2 (lab only): Bob's LAN address is dead and his Internet address
/// answers. The next send on the same network goes to the Internet address
/// first, without the dead LAN dial; on another network the plan is LAN
/// first again.
#[test]
fn a_contact_reached_over_the_internet_is_dialled_there_first_next_time() {
    let net = Net::new(true);
    let book = net.a.path().join("contacts.json");
    let mut rows: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&book).unwrap()).unwrap();
    for row in rows.as_array_mut().unwrap() {
        row["pinned"] = true.into();
        row["internet_dial"] = "127.0.0.1:7422".into();
    }
    std::fs::write(&book, rows.to_string()).unwrap();
    net.dead.lock().unwrap().insert("127.0.0.1:9".into());
    let lan = ("lan".to_string(), "127.0.0.1:9".to_string());
    let internet = ("internet".to_string(), "127.0.0.1:7422".to_string());
    let on = |tag: &'static str| [("RAVEN_LAB_TEST_A", "1"), ("RAVEN_LAB_NET_TAG", tag)];
    let delivered = |o: &Output| {
        let (out, err) = (text(&o.stdout), text(&o.stderr));
        assert_eq!(code(o), 0, "{out}\n{err}");
        assert!(
            out.contains("status delivered — Bob confirmed receipt"),
            "{out}\n{err}"
        );
    };

    delivered(&net.send_env("one", &on("t")));
    let dials = net.take_dials();
    assert_eq!(dials[..2], [lan.clone(), internet.clone()], "{dials:?}");
    assert!(dials[1..].iter().all(|d| *d == internet), "{dials:?}");
    let memory = std::fs::read_to_string(net.a.path().join("route_memory.json")).unwrap();
    assert!(memory.contains("127.0.0.1:7422"), "{memory}");

    delivered(&net.send_env("two", &on("t")));
    let dials = net.take_dials();
    assert!(
        !dials.is_empty() && dials.iter().all(|d| *d == internet),
        "the Internet address first, no dead LAN dial: {dials:?}"
    );

    delivered(&net.send_env("three", &on("u")));
    let dials = net.take_dials();
    assert_eq!(
        dials.first(),
        Some(&lan),
        "another network: LAN first again: {dials:?}"
    );
    assert_eq!(net.bob_inbox(), vec!["one", "three", "two"]);
}

/// Phase 3 P3.6: with `raven lan off` (node_policy.json `lan_off`) a send
/// dials nothing on the LAN and says LAN_OFF. With a session the message
/// waits, queued for raven-node's outbox with Bob's LAN route recorded for
/// when LAN is on again; Bob's Internet address is still used where that is
/// allowed (verified, the lab switch).
#[test]
fn a_send_with_lan_off_skips_lan_routes_and_says_lan_off() {
    let net = Net::new(true);
    assert_eq!(code(&net.send("first")), 0);
    std::fs::write(
        net.a.path().join("node_policy.json"),
        r#"{"lan_off": true}"#,
    )
    .unwrap();
    net.set_outbox(true);
    net.take_dials();
    let o = net.send("while LAN is off");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{out}\n{err}");
    assert!(
        err.contains(
            "LAN_OFF: LAN is off on this computer, so RAVEN does not connect to Bob on your \
             network (`raven lan on` turns LAN back on)."
        ),
        "{err}"
    );
    assert!(
        err.contains(
            "not delivered yet: your message \"while LAN is off\" to Bob is queued locally \
             because LAN is off on this computer (`raven lan off`), so RAVEN does not connect \
             to Bob on your network."
        ),
        "{err}"
    );
    assert!(
        err.contains("Turn LAN back on with `raven lan on`."),
        "{err}"
    );
    assert!(!out.to_lowercase().contains("delivered"), "{out}");
    assert_eq!(
        net.take_dials(),
        Vec::new(),
        "nothing is dialled on the LAN"
    );
    let routes = std::fs::read_to_string(net.a.path().join("outbox_routes.json")).unwrap();
    assert!(routes.contains("127.0.0.1:9"), "{routes}");
    assert_eq!(net.bob_inbox(), vec!["first"]);

    // Bob verified, with an Internet address: the send goes there, and the
    // LAN stays undialled.
    edit_bob_row(&net, |row| {
        row["pinned"] = true.into();
        row["internet_dial"] = "127.0.0.1:47422".into();
    });
    let o = net.send_env("over the internet", &[("RAVEN_LAB_TEST_A", "1")]);
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        out.contains("status delivered — Bob confirmed receipt"),
        "{out}\n{err}"
    );
    assert!(err.contains("and tries Bob's other addresses"), "{err}");
    let dials = net.take_dials();
    assert!(
        !dials.is_empty() && dials.iter().all(|(op, _)| op == "internet"),
        "{dials:?}"
    );
    assert!(net.bob_inbox().contains(&"over the internet".to_string()));
}

/// Phase 3 P3.C2 (cutoff M1): with `raven lan verified-only on` Alice's send
/// to Bob, who is not verified, is NOT SENT before anything is dialled, in
/// the step's words; once Bob is verified it is delivered; and with the
/// setting off an unverified Bob is reached on the LAN as before.
#[test]
fn a_send_under_verified_only_to_an_unverified_contact_dials_nothing() {
    let net = Net::new(true);
    assert_eq!(code(&net.send("first")), 0);
    let lan = |state: &str| {
        let mut c = ash(net.a.path());
        c.args(["lan", "verified-only", state]);
        run(c, b"")
    };
    let o = lan("on");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        text(&o.stdout).starts_with("Only verified friends can connect on the local network now"),
        "{}",
        text(&o.stdout)
    );
    net.take_dials();
    let o = net.send("only for the verified");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{out}\n{err}");
    let both = format!("{out}\n{err}");
    assert!(
        both.contains(
            "NOT SENT: Only verified friends can connect on this network: Bob isn't verified \
             yet. Compare security codes with Bob in person (`raven contact verify --address \
             rvn1"
        ),
        "{both}"
    );
    assert!(both.contains("(LAN_VERIFIED_ONLY)"), "{both}");
    assert_eq!(net.take_dials(), Vec::new(), "nothing is dialled");
    assert_eq!(net.bob_inbox(), vec!["first"]);

    edit_bob_row(&net, |row| row["pinned"] = true.into());
    let o = net.send("now verified");
    assert_eq!(code(&o), 0, "{}\n{}", text(&o.stdout), text(&o.stderr));
    assert!(net.bob_inbox().contains(&"now verified".to_string()));

    edit_bob_row(&net, |row| row["pinned"] = false.into());
    let o = lan("off");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let o = net.send("every contact again");
    assert_eq!(code(&o), 0, "{}\n{}", text(&o.stdout), text(&o.stderr));
    assert!(net.bob_inbox().contains(&"every contact again".to_string()));
}

/// Bob's route hints as raven-node keeps them (`learned_routes.json` in
/// Alice's folder): a LAN port on `lan_ip` and, optionally, a PeerId.
fn plant_learned_routes(dir: &Path, port: Option<u16>, peer_id: Option<(&str, bool)>) {
    let bob = Identity::from_seed(&[0x42; 32]);
    let now = raven_core::clock::now_ms();
    let mut row = serde_json::json!({
        "pub_hex": pub_hex(&bob), "generation": now, "received_at_ms": now,
        "expires_at_ms": now + 3_600_000, "via": "lan",
    });
    if let Some(port) = port {
        row["lan"] = serde_json::json!({
            "generation": now, "received_at_ms": now, "expires_at_ms": now + 3_600_000,
            "lan_port": port, "lan_ip": "127.0.0.1",
        });
    }
    if let Some((id, proven)) = peer_id {
        row["peer_id"] = id.into();
        row["peer_id_proven"] = proven.into();
    }
    std::fs::write(
        dir.join("learned_routes.json"),
        serde_json::json!([row]).to_string(),
    )
    .unwrap();
}

/// Bob's book rows in Alice's folder, edited by `edit`.
fn edit_bob_row(net: &Net, edit: impl Fn(&mut serde_json::Value)) {
    let book = net.a.path().join("contacts.json");
    let mut rows: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&book).unwrap()).unwrap();
    for row in rows.as_array_mut().unwrap() {
        edit(row);
    }
    std::fs::write(&book, rows.to_string()).unwrap();
}

fn bob_row(net: &Net) -> serde_json::Value {
    let rows: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(net.a.path().join("contacts.json")).unwrap())
            .unwrap();
    rows[0].clone()
}

/// s04 in ash (route hints, lab switch): Bob's saved LAN port is dead and his
/// route hints say he listens on another port. With the switch the announced
/// port is tried after the saved one, delivers, and is saved for the next
/// send; without it nothing but the saved route is dialled.
#[test]
fn learned_rrh1_port_is_tried_and_saved() {
    let net = Net::new(true);
    net.dead.lock().unwrap().insert("127.0.0.1:9".into());
    plant_learned_routes(net.a.path(), Some(7424), None);
    let lan = |dial: &str| ("lan".to_string(), dial.to_string());

    let mut off = ash(net.a.path());
    off.args(["send", "--contact", "@bob"])
        .env("RAVEN_LAB_ROUTE_HINTS", "0");
    let o = run(off, b"switch off\n");
    assert_eq!(code(&o), 1, "{}", text(&o.stderr));
    let dials = net.take_dials();
    assert!(
        !dials.is_empty() && dials.iter().all(|d| *d == lan("127.0.0.1:9")),
        "the switch off: the saved route only: {dials:?}"
    );

    let o = net.send_env("moved", &[("RAVEN_LAB_ROUTE_HINTS", "1")]);
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        out.contains("status delivered — Bob confirmed receipt"),
        "{out}\n{err}"
    );
    assert!(
        out.contains("Their LAN address changed: saved 127.0.0.1:7424 for next Send."),
        "{out}"
    );
    let dials = net.take_dials();
    assert_eq!(dials.first(), Some(&lan("127.0.0.1:9")), "{dials:?}");
    assert!(dials.contains(&lan("127.0.0.1:7424")), "{dials:?}");
    assert_eq!(bob_row(&net)["lan_dial"], "127.0.0.1:7424");
    assert_eq!(net.bob_inbox(), vec!["moved"]);
}

/// A PeerId Bob's route hints name is dialled as `/p2p/<PeerId>` (verified
/// contact, p2p and route hints on) but goes into the book only once a p2p
/// link has proved it: an unproven one must stay a hidden contact of the p2p
/// host.
#[test]
fn an_unproven_learned_peer_id_is_not_saved_into_the_book() {
    let net = Net::new(true);
    edit_bob_row(&net, |row| row["pinned"] = true.into());
    net.dead.lock().unwrap().insert("127.0.0.1:9".into());
    let peer_id = &raven_core::p2p_route::local_peer_id(&Identity::from_seed(&[0x42; 32]));
    let p2p = ("p2p".to_string(), format!("/p2p/{peer_id}"));
    let on = [("RAVEN_LAB_ROUTE_HINTS", "1"), ("RAVEN_LAB_TEST_A", "1")];
    // Alice's raven-node runs a libp2p host: a send plans p2p only then
    // (field test E3).
    *net.p2p.status.lock().unwrap() = (
        Some(P2pStatusInfo {
            up: true,
            ..P2pStatusInfo::default()
        }),
        Vec::new(),
    );

    plant_learned_routes(net.a.path(), None, Some((peer_id, false)));
    let o = net.send_env("unproven", &on);
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        out.contains("status delivered — Bob confirmed receipt"),
        "{out}\n{err}"
    );
    assert!(net.take_dials().contains(&p2p));
    assert!(!out.contains("Saved their p2p route"), "{out}");
    assert!(
        bob_row(&net).get("p2p").is_none(),
        "an unproven PeerId stays out of the book: {}",
        bob_row(&net)
    );

    // Proved by a p2p link (raven-node notes it): saved for the next send.
    plant_learned_routes(net.a.path(), None, Some((peer_id, true)));
    let o = net.send_env("proven", &on);
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        out.contains("Saved their p2p route for next Send."),
        "{out}"
    );
    assert_eq!(bob_row(&net)["p2p"], peer_id.as_str());
    assert_eq!(net.bob_inbox(), vec!["proven", "unproven"]);
}

/// Blocking a contact in the chat forgets what its route hints said.
#[test]
fn a_blocked_contacts_route_hints_are_forgotten() {
    let (dir, _bob, _guard) = chat_profile();
    plant_learned_routes(dir.path(), Some(7424), None);
    let o = chat(dir.path(), b"/block\nyes\n");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let left = std::fs::read_to_string(dir.path().join("learned_routes.json")).unwrap();
    assert!(
        !left.contains(&pub_hex(&Identity::from_seed(&[0x42; 32]))),
        "{left}"
    );
}

// ── why a p2p contact cannot be reached (the diagnosis) ─────────────────────

/// Bob's p2p route (his PeerId, through a relay) in Alice's book, Bob
/// verified: what a p2p send dials. Returns his PeerId.
fn add_bob_p2p(net: &Net) -> String {
    let peer = raven_core::p2p_route::local_peer_id(&Identity::from_seed(&[0x42; 32]));
    let relay = raven_core::p2p_route::local_peer_id(&Identity::from_seed(&[0x61; 32]));
    edit_bob_row(net, |row| {
        row["pinned"] = true.into();
        row["p2p"] = peer.clone().into();
        row["p2p_via"] = serde_json::json!([format!("/ip4/198.51.100.7/tcp/40999/p2p/{relay}")]);
    });
    peer
}

/// Carol, verified, in Alice's book; her card names a direct internet
/// address of her own, a global one (so she can be reached from the
/// internet; a documentation, LAN or loopback address would not count).
fn add_carol(net: &Net) -> Identity {
    let carol = Identity::from_seed(&[0x43; 32]);
    let peer = raven_core::p2p_route::local_peer_id(&carol);
    let book = net.a.path().join("contacts.json");
    let mut rows: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&book).unwrap()).unwrap();
    rows.as_array_mut().unwrap().push(serde_json::json!({
        "petname": "Carol", "public_tag": "", "alias": "", "address": carol.address(),
        "pub_hex": pub_hex(&carol), "pinned": true, "lan_dial": "",
        "p2p": peer, "p2p_via": [format!("/ip4/11.0.0.9/tcp/40999/p2p/{peer}")],
    }));
    std::fs::write(&book, rows.to_string()).unwrap();
    carol
}

/// A session with Bob (a first LAN send), then Bob's p2p route: later p2p
/// sends to him queue when they fail.
fn net_with_a_p2p_bob() -> Net {
    let net = Net::new(true);
    assert_eq!(code(&net.send("first")), 0);
    add_bob_p2p(&net);
    net.set_outbox(true);
    net
}

/// The outcome line of a send (`not delivered yet: …` / `NOT SENT: …`).
fn outcome_of(err: &str) -> String {
    err.lines()
        .find(|l| l.starts_with("not delivered yet") || l.starts_with("NOT SENT"))
        .unwrap_or_else(|| panic!("no outcome line: {err}"))
        .to_string()
}

/// [`outcome_of`], checked for what every diagnosis line keeps: one line,
/// no PeerId or `/p2p/` outside its technical part, no `--lan-dial`, and
/// when queued never "send again".
fn outcome_line(err: &str) -> String {
    let line = outcome_of(err);
    let sentences = line.split("(technical:").next().unwrap();
    assert!(
        !sentences.contains("12D3KooW") && !sentences.contains("/p2p/"),
        "{line}"
    );
    assert!(!line.contains("--lan-dial"), "{line}");
    if line.starts_with("not delivered yet") {
        assert!(!sentences.to_lowercase().contains("send again"), "{line}");
        assert!(sentences.contains("Do not retype this message"), "{line}");
    }
    line
}

#[test]
fn an_unreachable_p2p_contact_behind_nat_is_queued_with_the_three_fixes() {
    let net = net_with_a_p2p_bob();
    net.set_p2p_error(Some(Some("reach: why=both_nat me=unreachable")));
    let o = net.send_p2p("hi");
    let err = text(&o.stderr);
    assert_eq!(code(&o), 1, "{err}");
    let line = outcome_line(&err);
    assert!(
        line.starts_with(
            "not delivered yet: your message \"hi\" to Bob is queued locally because you and Bob \
             are both behind NAT"
        ),
        "{line}"
    );
    for words in [
        "Nobody in your circle can be reached",
        "`raven relay offer on`",
        "relay kit",
        "forward port 7423 (TCP and UDP)",
        "Do not retype this message",
        "(technical: ipc P2P_DIAL: P2P_UNREACHABLE",
    ] {
        assert!(line.contains(words), "{words:?} missing: {line}");
    }
    assert_eq!(net.bob_inbox(), vec!["first"]);
    net.set_p2p_error(None);
    let o = net.send_p2p("now");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert_eq!(net.bob_inbox(), vec!["first", "hi", "now"]);
}

#[test]
fn a_friend_who_can_be_reached_is_named_in_the_fix() {
    let net = net_with_a_p2p_bob();
    add_carol(&net);
    net.set_p2p_error(Some(Some("reach: why=both_nat me=unreachable")));
    let o = net.send_p2p("hi");
    let line = outcome_line(&text(&o.stderr));
    assert!(
        line.contains(
            "Carol can be reached from the internet: ask Carol to offer relaying (`raven relay \
             offer on` on Carol's computer); RAVEN then uses it for you and Bob by itself"
        ),
        "{line}"
    );
    assert!(!line.contains("Nobody in your circle"), "{line}");
    assert_eq!(net.bob_inbox(), vec!["first"]);
}

#[test]
fn an_offline_contact_says_nothing_to_do_and_when_last_heard() {
    let net = net_with_a_p2p_bob();
    net.set_p2p_error(Some(Some("reach: why=contact_offline me=relayed heard=3h")));
    let o = net.send_p2p("hi");
    let line = outcome_line(&text(&o.stderr));
    for words in [
        "queued locally because Bob is offline: Bob's relay answered",
        "RAVEN last heard from Bob 3 h ago",
        "Nothing to do on your side: it goes out when Bob is back online.",
    ] {
        assert!(line.contains(words), "{words:?} missing: {line}");
    }
    assert!(!line.contains("relay kit"), "{line}");
    assert_eq!(net.bob_inbox(), vec!["first"]);
}

#[test]
fn a_sleeping_shared_relay_is_named_from_status() {
    let net = net_with_a_p2p_bob();
    let carol = add_carol(&net);
    let relay = raven_core::p2p_route::local_peer_id(&Identity::from_seed(&[0x62; 32]));
    *net.p2p.status.lock().unwrap() = (
        Some(P2pStatusInfo {
            up: true,
            reach: "relayed".into(),
            relay_health: vec![RelayHealth {
                relay: format!("/ip4/198.51.100.8/tcp/40998/p2p/{relay}"),
                state: "retrying".into(),
                tries: 2,
                source: "offer".into(),
                operator_pub_hex: pub_hex(&carol),
                ..RelayHealth::default()
            }],
            ..P2pStatusInfo::default()
        }),
        Vec::new(),
    );
    net.set_p2p_error(Some(Some("reach: why=relay_asleep me=relayed relay=mine1")));
    let o = net.send_p2p("hi");
    let line = outcome_line(&text(&o.stderr));
    for words in [
        "Carol's relay, which you and Bob both use, is not answering",
        "Ask Carol to wake that computer",
        "RAVEN keeps trying meanwhile.",
    ] {
        assert!(line.contains(words), "{words:?} missing: {line}");
    }
    assert!(!line.contains("198.51.100.8"), "{line}");
}

#[test]
fn a_relay_that_turns_you_away_says_whose_contact_to_become() {
    let net = net_with_a_p2p_bob();
    net.set_p2p_error(Some(Some("reach: why=relay_refused me=relayed")));
    let o = net.send_p2p("hi");
    let line = outcome_line(&text(&o.stderr));
    for words in [
        "Bob's relay turned you away: a friend's relay carries messages only between people its \
         owner has verified, and you are not one of them",
        "Ask Bob whose relay it is and become that person's verified contact",
    ] {
        assert!(line.contains(words), "{words:?} missing: {line}");
    }
}

#[test]
fn a_first_p2p_message_says_it_needs_a_working_path() {
    let net = Net::new(true);
    add_bob_p2p(&net);
    net.set_p2p_error(Some(Some("reach: why=both_nat me=unreachable")));
    let o = net.send_p2p("hello");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{err}");
    assert!(!out.to_lowercase().contains("delivered"), "{out}");
    let line = outcome_line(&err);
    assert!(
        line.starts_with("NOT SENT: you and Bob are both behind NAT"),
        "{line}"
    );
    assert!(
        line.contains(
            "It was not kept: a first message needs you and Bob both online (RAVEN hasn't \
             connected with Bob yet), and there is no working path to Bob now."
        ),
        "{line}"
    );
    assert!(net.bob_inbox().is_empty());
}

/// An older raven-node gives no reason: today's words, which name the
/// address dialled (here `/p2p/<PeerId>`) as they always did.
#[test]
fn an_older_daemon_without_reasons_keeps_todays_text() {
    let net = net_with_a_p2p_bob();
    net.set_p2p_error(Some(None));
    let o = net.send_p2p("hi");
    let line = outcome_of(&text(&o.stderr));
    for words in [
        "queued locally because Bob did not answer at /p2p/",
        ": their computer may be off or asleep",
        "Bob must be reachable directly or through a relay you both use",
    ] {
        assert!(line.contains(words), "{words:?} missing: {line}");
    }
    for words in [
        "behind NAT",
        "relay kit",
        "raven relay offer",
        "still finding out",
    ] {
        assert!(!line.contains(words), "{words:?} in: {line}");
    }
}

#[test]
fn a_cut_short_probe_uses_the_daemons_last_check() {
    let net = net_with_a_p2p_bob();
    let bob = Identity::from_seed(&[0x42; 32]);
    *net.p2p.status.lock().unwrap() = (
        None,
        vec![ContactWhy {
            peer_pub_hex: pub_hex(&bob),
            reason: "reach: why=contact_offline me=relayed".into(),
            age_s: 30,
        }],
    );
    *net.p2p.delay.lock().unwrap() = Some(Duration::from_secs(8));
    net.set_p2p_error(Some(None));
    let o = net.send_p2p("hi");
    let line = outcome_line(&text(&o.stderr));
    assert!(
        line.contains(
            "queued locally because Bob did not answer in time; RAVEN's check 30 s ago found \
             that Bob is offline"
        ),
        "{line}"
    );
    assert!(
        line.contains("Nothing to do on your side: it goes out when Bob is back online."),
        "{line}"
    );
    assert!(line.contains("the probe was cut short"), "{line}");
}

/// The live chat dials the contact's LAN address only (`--chat --carrier
/// p2p` is refused in this slice), so it never meets a p2p reason: its
/// queued line is the sentence `ash send` prints for the same LAN failure,
/// and no p2p reason is made up for it. `ash send` over every route (the
/// p2p one too) gives the p2p reason instead.
#[test]
fn the_chat_echo_carries_the_same_reason() {
    let net = net_with_a_p2p_bob();
    net.dead.lock().unwrap().insert("127.0.0.1:9".into());
    net.set_p2p_error(Some(Some("reach: why=both_nat me=unreachable")));
    net.take_dials();
    let mut c = ash(net.a.path());
    c.args(["send", "--contact", "@bob", "--chat"])
        .env("RAVEN_LAB_TEST_A", "1");
    let o = run(c, b"are you there\n/back\n");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{err}");
    assert!(out.contains("\u{2192} are you there  [queued"), "{out}");
    assert!(
        net.take_dials().iter().all(|(op, _)| op == "lan"),
        "the chat dials no p2p route"
    );
    let chat = outcome_of(&err);
    let because = |l: &str| {
        l.split(" Queued:")
            .next()
            .unwrap()
            .split("queued locally because ")
            .nth(1)
            .unwrap()
            .to_string()
    };
    assert_eq!(
        because(&chat),
        "Bob's computer is there, but Raven isn't receiving right now (it may be locked or \
         closed).",
        "{chat}"
    );
    // Without the lab unlock a command runs on the system clock: on a lab
    // clock run it would be that far apart from the rest of the test.
    if !on_lab_clock() {
        let mut lan = ash(net.a.path());
        lan.args(["send", "--contact", "@bob", "--carrier", "lan"])
            .env_remove("RAVEN_LAB_TEST_A");
        let send = outcome_of(&text(&run(lan, b"are you there\n").stderr));
        assert_eq!(because(&chat), because(&send), "{chat}\n{send}");
    }
    // Every route, the p2p one included: Bob's saved address is on this
    // computer's own network (loopback) and refused, so the LAN's answer
    // explains it, never NAT advice (E2 r9 #4).
    let o = net.send_env("still there?", &[("RAVEN_LAB_TEST_A", "1")]);
    let every = outcome_line(&text(&o.stderr));
    assert_eq!(because(&every), because(&chat), "{every}");
    assert!(
        !every.split("(technical:").next().unwrap().contains("NAT"),
        "{every}"
    );
}

#[test]
fn back_online_delivers_and_the_reason_is_gone() {
    let net = net_with_a_p2p_bob();
    net.set_p2p_error(Some(Some("reach: why=contact_offline me=relayed")));
    assert_eq!(code(&net.send_p2p("while away")), 1);
    net.set_p2p_error(None);
    let o = net.send_p2p("back");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        out.contains(
            "status delivered \u{2014} your earlier message \"while away\" to Bob has now arrived"
        ),
        "{out}"
    );
    assert!(
        out.contains("status delivered \u{2014} Bob confirmed receipt"),
        "{out}"
    );
    assert!(
        !err.contains("offline") && !out.contains("offline"),
        "{out}\n{err}"
    );
    assert_eq!(net.bob_inbox(), vec!["back", "first", "while away"]);
}

// ── the inbox once the secure connection ended (E2 round 7) ─────────────────

/// The three-machine test's lab switch set S12 (the switches `raven inbox`
/// may meet; the radio and relay ones are left out: nothing here may reach
/// the network).
const S12: [(&str, &str); 6] = [
    ("RAVEN_LAB_TEST_A", "1"),
    ("RAVEN_LAB_AT_REST", "1"),
    ("RAVEN_LAB_HORIZON", "1"),
    ("RAVEN_LAB_ROUTE_HINTS", "1"),
    ("RAVEN_LAB_LOCAL_PROTECTION", "1"),
    ("RAVEN_LAB_SECURITY_EVENTS", "1"),
];

/// Set S5A's switches that change a profile on this computer: no long
/// message horizon and no local protection (its router and relay switches
/// are left out for the same reason).
const S5A: [(&str, &str); 3] = [
    ("RAVEN_LAB_TEST_A", "1"),
    ("RAVEN_LAB_AT_REST", "1"),
    ("RAVEN_LAB_ROUTE_HINTS", "1"),
];

/// A `raven-node service` started by a test, stopped when dropped.
struct NodeGuard(std::process::Child);

impl Drop for NodeGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// E2 round 7 (three-machine test, seen on two computers): a sealed profile
/// that had received messages showed them in `raven inbox` under lab switch
/// set S12. Its secure connections ended while no raven-node ran; the next
/// raven-node start (under set S5A) moved the received messages of the
/// ended sessions into the chat history, as it must, and pruned the
/// sessions. From then on `raven inbox` said "No messages yet" under every
/// switch set, though the chat history kept every message. Nothing was lost:
/// the inbox read only the live sessions' rows. It lists what the chat
/// history keeps too.
#[test]
fn the_inbox_still_lists_messages_after_their_secure_connection_ended() {
    if !cfg!(debug_assertions) {
        return; // lab switches and the lab clock are debug-only
    }
    let Some(node_bin) = raven_node_next_to_ash() else {
        eprintln!("skipped: raven-node is not built next to ash");
        return;
    };
    let net = Net::new(true);
    for message in ["first E1", "second E1"] {
        let o = net.send(message);
        assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    }
    assert_eq!(net.bob_inbox(), vec!["first E1", "second E1"]);
    let bob = net.b.path();
    {
        use std::os::unix::fs::PermissionsExt;
        let seed = bob.join("identity.seed");
        std::fs::write(&seed, [0x42; 32]).unwrap();
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    // Bob's identity recorded, as `raven init` leaves it.
    let mut c = ash(bob);
    c.arg("whoami");
    let o = run(c, b"");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let _stop = StopService(bob.to_path_buf());
    let clock_dir = tempfile::tempdir().unwrap();
    let clock = clock_dir.path().join("offset-ms");
    std::fs::write(&clock, "0").unwrap();
    let inbox = |set: &[(&str, &str)]| {
        let mut c = ash(bob);
        c.arg("inbox").env("RAVEN_LAB_CLOCK_FILE", &clock);
        for (k, v) in set {
            c.env(k, v);
        }
        run(c, b"")
    };

    // S12: the first command seals the profile; both messages are listed.
    let o = inbox(&S12);
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{out}\n{}", text(&o.stderr));
    assert!(out.contains("inbox (2)"), "{out}");
    let history = std::fs::read(raven_core::chat_history::history_path(bob)).unwrap();
    assert!(
        history.starts_with(b"RVNHIST2"),
        "the history is sealed: {}\n{:?}",
        text(&o.stderr),
        std::fs::read_to_string(bob.join("privacy.json"))
    );

    // Three days later (the 24-hour sessions ended while no raven-node
    // ran), raven-node starts under S5A: its start prune archives and
    // removes the ended sessions.
    std::fs::write(&clock, (3 * 24 * 3_600_000u64).to_string()).unwrap();
    let mut node = Command::new(&node_bin);
    node.args(["service", "--data-dir"])
        .arg(bob)
        .args(["--lan-listen", "127.0.0.1:0", "--ble-listen", "127.0.0.1:0"])
        .env("RAVEN_IDENTITY_BACKEND", "locked-file")
        .env("RAVEN_CHAT_HISTORY_BACKEND", "locked-file")
        .env("RAVEN_PREKEY_BACKEND", "locked-file")
        .env("RAVEN_SESSION_BACKEND", "locked-file")
        .env("RAVEN_ALLOW_EPHEMERAL_DATA_DIR", "1")
        .env("RAVEN_LAB_CLOCK_FILE", &clock)
        .env_remove("RAVEN_INTERNET_LISTEN")
        .env_remove("RAVEN_P2P_LISTEN")
        .env_remove("RAVEN_P2P_RELAY")
        .env_remove(raven_core::horizon::LAB_HORIZON)
        .env_remove(raven_core::security_gate::LAB_LOCAL_PROTECTION)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in S5A {
        node.env(k, v);
    }
    let mut child = node.spawn().expect("spawn raven-node");
    let stderr = child.stderr.take().unwrap();
    let guard = NodeGuard(child);
    let (tx, lines) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut seen = Vec::new();
    loop {
        match lines.recv_timeout(Duration::from_secs(90)) {
            Ok(line) => {
                let up = line.contains("lan_direct: listen");
                seen.push(line);
                if up {
                    break;
                }
            }
            Err(e) => panic!("raven-node did not start ({e}):\n{}", seen.join("\n")),
        }
    }
    drop(guard);
    raven_core::at_rest::keys_load(bob).unwrap();
    let sessions = raven_core::IndexedSessionStore::open(bob)
        .unwrap()
        .list_record_keys()
        .unwrap();
    assert!(sessions.is_empty(), "the ended sessions were pruned");
    let kept: Vec<String> = raven_core::ChatHistory::load(bob)
        .unwrap()
        .entries
        .into_iter()
        .filter(|e| e.direction == "in")
        .map(|e| e.body)
        .collect();
    assert_eq!(kept, vec!["first E1", "second E1"], "nothing was lost");

    // Under either switch set the inbox lists both, and never says it is
    // empty.
    for set in [&S5A[..], &S12[..]] {
        let o = inbox(set);
        let (out, err) = (text(&o.stdout), text(&o.stderr));
        assert_eq!(code(&o), 0, "{out}\n{err}");
        assert!(out.contains("inbox (2)"), "{out}\n{err}");
        for message in ["first E1", "second E1"] {
            assert_eq!(out.matches(message).count(), 1, "{message}: {out}");
        }
        assert!(out.contains("from Alice"), "{out}");
        assert!(!out.contains("No messages yet"), "{out}");
    }

    // What cannot be read is said, never shown as an empty inbox: the
    // at-rest key unavailable (the keystore said no) ...
    let mut keyless = S12.to_vec();
    keyless.push(("RAVEN_LAB_AT_REST_KEY_FAULT", "unavailable"));
    let o = inbox(&keyless);
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{out}\n{err}");
    assert!(err.contains("inbox:"), "{err}");
    assert!(!out.contains("No messages yet"), "{out}");
    // ... or a history that does not open.
    let path = raven_core::chat_history::history_path(bob);
    let good = std::fs::read(&path).unwrap();
    let mut bad = good.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    std::fs::write(&path, &bad).unwrap();
    let o = inbox(&S12);
    std::fs::write(&path, &good).unwrap();
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{out}\n{err}");
    assert!(
        err.contains(&format!(
            "inbox: Raven can't read the chat history in {} now, so the messages it keeps are \
             not shown. They are not deleted.",
            bob.display()
        )),
        "{err}"
    );
    assert!(!out.contains("No messages yet"), "{out}");
    assert!(text(&inbox(&S12).stdout).contains("inbox (2)"));
}
