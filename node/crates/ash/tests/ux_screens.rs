//! Black-box checks of the plain-language screens of `ash`: help and version,
//! the first-run offer, the menu text, `status` / `doctor` / `inbox` saying what
//! is going on, how a contact is named and saved, and `--contact <petname>`.
//!
//! Every run uses a throwaway profile and the file-backed (`locked-file`)
//! secret stores, so nothing here can reach the OS keychain or the network. The
//! local node is either absent or faked by a UDS server inside the test (it only
//! answers Ping and Status), so no run starts a real `raven-node`. Should a fake
//! ever stall (ash then starts a real service), that service listens on
//! 127.0.0.1 only (`RAVEN_SERVICE_LAN_LISTEN` is pinned) and is stopped when
//! the fake drops. `doctor --router` runs only against a fake router on
//! loopback (the lab gateway, `RAVEN_LAB_PORTMAP_GATEWAY`), so no test asks a
//! real router.
//!
//! Unix only: the planted 0600 identity seed and the UDS are the unix layout.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use raven_core::identity::Identity;
use raven_core::ipc::{
    decode_request, encode_response, BeaconCounts, ContactPath, ContactSkew, ContactWhy,
    IpcRequest, IpcResponse, LanStatus, NearbyStatusInfo, OutboxItem, P2pStatusInfo, RelayHealth,
    SecurityStatus, IPC_VERSION,
};
use raven_core::portmap_fake::{FakeGateway, Mode};

fn ash(dir: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ash"));
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
        .env("RAVEN_SERVICE_LAN_LISTEN", "127.0.0.1:0");
    // Release builds have the Tor onion carrier and STUN discovery on since
    // 2026-10; no test here reaches the Tor network or asks a public STUN
    // server, so a raven-node these tests start has both closed (a debug
    // build's "0").
    c.env("RAVEN_LAB_TOR", "0")
        .env("RAVEN_LAB_STUN_DISCOVERY", "0");
    c
}

fn run(mut c: Command, stdin: &str) -> Output {
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ash");
    // The child may exit without reading its stdin: a broken pipe is fine.
    let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
    child.wait_with_output().expect("wait ash")
}

/// `ash --data-dir <dir> <args>` run to completion with `stdin`.
fn ash_out(dir: &Path, args: &[&str], stdin: &str) -> Output {
    let mut c = ash(dir);
    c.args(args);
    run(c, stdin)
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// What `ash status` and `ash doctor` say about a profile whose keys are in
/// the lab file backend: every profile here is one (cutoff pack CP.8).
const LAB_WARNING: &str = "This profile keeps its keys unencrypted (lab file backend): use it \
     for tests only, never for real messages.";

/// `ash status` without the lab-profile warning it ends with here (its last
/// row, after the verdict).
fn status_body(out: &str) -> &str {
    out.trim_end()
        .strip_suffix(LAB_WARNING)
        .unwrap_or_else(|| panic!("the lab warning is not the last row of:\n{out}"))
        .trim_end()
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
    plant_identity_seed(dir, 0x5a);
}

/// A profile whose identity is `Identity::from_seed(&[byte; 32])`.
fn plant_identity_seed(dir: &Path, byte: u8) {
    use std::os::unix::fs::PermissionsExt;
    let seed = dir.join("identity.seed");
    std::fs::write(&seed, [byte; 32]).unwrap();
    std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn pub_hex(id: &Identity) -> String {
    hex::encode(id.public_key_bytes())
}

fn add_bob(dir: &Path, petname: &str) -> Identity {
    let bob = Identity::from_seed(&[0x42; 32]);
    let mut c = ash(dir);
    c.args(["contact", "add", "--address", &bob.address()])
        .args(["--pub-hex", &pub_hex(&bob), "--petname", petname]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    bob
}

/// What a [`FakeNode`] reports besides its capabilities: the p2p host,
/// the contacts it could not reach, the default route reading, where its
/// LAN listener is bound and why it could not bind (`Status`), its LAN row
/// (Phase 3 `Status.lan`), its last delivery paths, the contacts whose clock
/// runs ahead (CP.7), and its outbox (`OutboxList`, `OutboxStatus`).
#[derive(Clone, Default)]
struct Fake {
    p2p: Option<P2pStatusInfo>,
    lan_listen: Option<String>,
    lan: Option<LanStatus>,
    lan_listen_wanted: Option<String>,
    lan_bind_error: Option<String>,
    clock_skew: Vec<ContactSkew>,
    unreachable: Vec<ContactWhy>,
    egress: Option<bool>,
    last_paths: Vec<ContactPath>,
    outbox: Vec<OutboxItem>,
    /// Phase 5: Bluetooth nearby as Status reports it, and `NearbyControl`
    /// answered with it (`enable` / `disable` save the choice as raven-node
    /// does); `nearby_old`: an older raven-node, `IPC_FRAME` to every
    /// nearby request.
    nearby: Option<NearbyStatusInfo>,
    nearby_old: bool,
    /// Phase 6b: raven-node's security counts (`Status.security`).
    security: Option<SecurityStatus>,
}

/// A local node that answers Ping and Status (with `caps`), the outbox
/// requests and `SetLan` (`raven lan on|off`, applied at once), and nothing
/// else.
struct FakeNode {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// The profile it fakes the service of.
    dir: std::path::PathBuf,
}

impl FakeNode {
    fn start(dir: &Path, caps: &[&str]) -> Self {
        Self::start_with(dir, caps, Fake::default())
    }

    fn start_with(dir: &Path, caps: &[&str], fake: Fake) -> Self {
        let listener = UnixListener::bind(raven_core::default_socket_path(dir)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_c = stop.clone();
        let caps: Vec<String> = caps.iter().map(|c| c.to_string()).collect();
        let profile = dir.to_path_buf();
        let thread = std::thread::spawn(move || {
            // `SetLan` off closes the LAN listener, as raven-node does: its
            // `lan_direct` capability goes until `SetLan` on.
            let mut lan_on = true;
            let mut nearby = fake.nearby.clone();
            while !stop_c.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut len = [0u8; 4];
                if stream.read_exact(&mut len).is_err() {
                    continue;
                }
                let mut frame = len.to_vec();
                frame.resize(4 + u32::from_be_bytes(len) as usize, 0);
                if stream.read_exact(&mut frame[4..]).is_err() {
                    continue;
                }
                let response = match decode_request(&frame) {
                    Ok(IpcRequest::Ping { .. }) => IpcResponse::Pong { v: IPC_VERSION },
                    Ok(IpcRequest::Status { .. }) => IpcResponse::Status {
                        v: IPC_VERSION,
                        bridge: true,
                        store: true,
                        relay: false,
                        forward_pending: 0,
                        capabilities: caps
                            .iter()
                            .filter(|c| lan_on || c.as_str() != "lan_direct")
                            .cloned()
                            .collect(),
                        p2p: fake.p2p.clone().map(Box::new),
                        pid: None,
                        lan_listen: fake.lan_listen.clone(),
                        last_paths: fake.last_paths.clone(),
                        route_hints: None,
                        unreachable: fake.unreachable.clone(),
                        egress: fake.egress,
                        lan_listen_wanted: fake.lan_listen_wanted.clone(),
                        lan_bind_error: fake.lan_bind_error.clone(),
                        clock_skew: fake.clock_skew.clone(),
                        unanswered: Vec::new(),
                        at_rest: None,
                        lan: fake.lan.clone(),
                        security: fake.security.clone().map(Box::new),
                        nearby: nearby.clone().map(Box::new),
                        tor: None,
                        learning: None,
                        locked: None,
                        updates: None,
                    },
                    Ok(IpcRequest::NearbyControl { .. } | IpcRequest::NearbyDial { .. })
                        if fake.nearby_old =>
                    {
                        IpcResponse::Error {
                            v: IPC_VERSION,
                            code: "IPC_FRAME".into(),
                            message: "unknown variant".into(),
                        }
                    }
                    Ok(IpcRequest::NearbyControl { action, .. }) => {
                        let mut status = nearby.clone().unwrap_or_default();
                        if action == "enable" || action == "disable" {
                            let on = action == "enable";
                            raven_core::node_policy::update_settings(&profile, |p| {
                                p.nearby = Some(on)
                            })
                            .unwrap();
                            status.enabled = on;
                            nearby = Some(status.clone());
                        }
                        IpcResponse::NearbyControlResult {
                            v: IPC_VERSION,
                            status: Box::new(status),
                        }
                    }
                    Ok(IpcRequest::SetLan { on, until_ms, .. }) => {
                        lan_on = on;
                        IpcResponse::LanSet {
                            v: IPC_VERSION,
                            on,
                            applied: true,
                            until_ms: until_ms.filter(|_| on),
                        }
                    }
                    Ok(IpcRequest::OutboxList { .. }) => IpcResponse::OutboxListResult {
                        v: IPC_VERSION,
                        worker_running: true,
                        items: fake.outbox.clone(),
                    },
                    Ok(IpcRequest::OutboxStatus { message_id_hex, .. }) => {
                        match fake
                            .outbox
                            .iter()
                            .find(|i| i.message_id_hex == message_id_hex)
                        {
                            Some(item) => IpcResponse::OutboxStatusResult {
                                v: IPC_VERSION,
                                item: item.clone(),
                            },
                            None => IpcResponse::Error {
                                v: IPC_VERSION,
                                code: "OUTBOX_UNKNOWN".into(),
                                message: "no such object".into(),
                            },
                        }
                    }
                    // Learning connectivity (Phase 6a): as a raven-node
                    // from before it, which does not know the ops (its
                    // Status has no `learning` either).
                    Ok(IpcRequest::LearningPlan { .. } | IpcRequest::LearningReset { .. }) => {
                        IpcResponse::Error {
                            v: IPC_VERSION,
                            code: "IPC_FRAME".into(),
                            message: "unknown variant".into(),
                        }
                    }
                    _ => IpcResponse::Error {
                        v: IPC_VERSION,
                        code: "UNSUPPORTED".into(),
                        message: "not faked".into(),
                    },
                };
                let _ = stream.write_all(&encode_response(&response).unwrap());
            }
        });
        FakeNode {
            stop,
            thread: Some(thread),
            dir: dir.to_path_buf(),
        }
    }
}

impl Drop for FakeNode {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        // If a bug ever made ash start a real service for this profile, do
        // not leave it behind (that one only: matched by its folder).
        let _ = Command::new("pkill")
            .args([
                "-f",
                &format!("raven-node service --data-dir {}", self.dir.display()),
            ])
            .status();
    }
}

// ── help and version ────────────────────────────────────────────────────────

#[test]
fn version_and_help_are_plain_and_the_example_starts_with_adding_each_other() {
    let dir = tempfile::tempdir().unwrap();
    let o = ash_out(dir.path(), &["--version"], "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(text(&o.stdout).starts_with("ash "), "{}", text(&o.stdout));

    let o = ash_out(dir.path(), &["--help"], "");
    let help = text(&o.stdout);
    assert_eq!(code(&o), 0);
    assert!(help.to_lowercase().contains("raven"), "{help}");
    // The worked example: both add each other first, the receiver listens.
    assert!(help.contains("FIRST CHAT"), "{help}");
    assert!(
        help.contains("ash whoami") && help.contains("invite"),
        "{help}"
    );
    assert!(help.contains("ash listen"), "{help}");
    // A Windows console ends input at Ctrl-Z, then Enter.
    let end = if cfg!(windows) {
        "Ctrl-Z, then Enter"
    } else {
        "Ctrl-D"
    };
    assert!(
        help.contains(&format!(
            "ash send --contact Bob    type the message, then {end}"
        )),
        "{help}"
    );
    // CP.8: typed after the command, never piped through `echo`, the message
    // stays out of the shell history.
    assert!(help.contains("keeps it out of your shell"), "{help}");
    assert!(!help.contains("echo \""), "{help}");
    assert!(help.contains("added each other"), "{help}");
    // Nothing a repository checkout is needed for, no developer vocabulary.
    for dev in [
        "final_serverless_proof",
        "AUTOMATED_PROOF_GREEN",
        "PairInit",
        "--peer-pub-hex <receiver",
    ] {
        assert!(!help.contains(dev), "{dev:?} in {help}");
    }

    // `--data-dir` is explained for a person, with no `[default: ""]`.
    let o = ash_out(dir.path(), &["-h"], "");
    let short = text(&o.stdout);
    assert!(
        short.contains("Folder where Raven keeps your identity"),
        "{short}"
    );
    assert!(
        !short.contains("mktemp") && !short.contains("[default: \"\"]"),
        "{short}"
    );
}

#[test]
fn send_help_says_the_text_comes_from_stdin_and_shows_the_example() {
    let dir = tempfile::tempdir().unwrap();
    let o = ash_out(dir.path(), &["send", "--help"], "");
    let help = text(&o.stdout);
    assert_eq!(code(&o), 0);
    assert!(help.contains("stdin"), "{help}");
    let end = if cfg!(windows) {
        "Ctrl-Z, then Enter"
    } else {
        "Ctrl-D"
    };
    assert!(
        help.contains(&format!(
            "ash send --contact @alice   (type the message, then {end})"
        )),
        "{help}"
    );
    assert!(help.contains("keeps it out of your shell"), "{help}");
    assert!(!help.contains("echo \""), "{help}");
    assert!(help.contains("--contact <CONTACT>"), "{help}");
    // How to reach the contact is a user choice now (transports P1, P3;
    // Bluetooth nearby, P5.28): shown.
    assert!(
        help.contains("--carrier <auto|lan|internet|p2p|onion|nearby>"),
        "{help}"
    );
    // The old developer-only wording and the unusable options are gone from view.
    for old in ["Forward send to raven-node", "--listen", "--stdin-text"] {
        assert!(!help.contains(old), "{old:?} in {help}");
    }
    // ... but they are still accepted (scripts pass them).
    let o = ash_out(
        dir.path(),
        &[
            "send",
            "--stdin-text",
            "--carrier",
            "lan",
            "--contact",
            "@x",
        ],
        "hi\n",
    );
    assert!(
        !text(&o.stderr).contains("unexpected argument"),
        "{}",
        text(&o.stderr)
    );
}

// ── first run and the menu ──────────────────────────────────────────────────

#[test]
fn the_first_run_prompt_explains_what_an_identity_is_and_a_typo_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let o = ash_out(dir.path(), &[], "ok\nq\n");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        out.contains("Your identity is a private key that stays on this computer"),
        "{out}"
    );
    assert!(
        out.contains("no account, no phone number, no server"),
        "{out}"
    );
    assert!(
        out.contains("Create your Raven identity now? [Y/n]"),
        "{out}"
    );
    // An answer that is neither yes nor no is not a yes (and a pipe is never
    // asked twice: the next line belongs to the menu).
    assert!(
        out.contains("Not a yes or a no — identity not created"),
        "{out}"
    );
    assert!(!dir.path().join("identity.seed").exists());
    assert!(out.contains("fly safe"), "{out}");
}

#[test]
fn the_menu_is_one_copy_of_plain_words_with_one_quit_line() {
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    let o = ash_out(dir.path(), &[], "5\n\n6\n7\nh\nzzz\nQ\n");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    // Hints in plain words, Mailbox / Nearby honest about being local.
    assert!(out.contains("messages you received"), "{out}");
    assert!(out.contains("stay online to receive"), "{out}");
    assert!(out.contains("add a friend (paste their invite)"), "{out}");
    for jargon in [
        "committed endpoint inbox",
        "ephemeral BLE discovery",
        "opaque offline put/get",
    ] {
        assert!(!out.contains(jargon), "{jargon:?} in {out}");
    }
    assert!(
        out.contains("advanced tool, this computer only (not your inbox)"),
        "{out}"
    );
    assert!(
        out.contains("Bluetooth: verified contacts in radio range"),
        "{out}"
    );
    assert!(
        out.contains("Nearby (Bluetooth): your verified contacts in radio range"),
        "{out}"
    );
    assert!(!out.contains("demo"), "{out}");
    assert!(
        out.contains("Mailbox is an advanced tool for this computer only"),
        "{out}"
    );
    // `h` helps, a wrong key says what to pick, a capital Q quits.
    assert!(out.contains("Pick a number from 1 to 8"), "{out}");
    assert!(
        out.contains("unknown: zzz — pick 1-8 or q (h = help)"),
        "{out}"
    );
    assert!(out.contains("fly safe"), "{out}");
    // The quit key is listed once per screen, not twice.
    assert_eq!(out.matches("q  quit   q  quit").count(), 0, "{out}");
    let screens = out
        .matches("R A V E N")
        .count()
        .max(out.matches("◆ MESSAGES").count());
    assert_eq!(out.matches("    q  quit").count(), screens, "{out}");
    // The scripted keys still land on the same screens.
    assert!(out.contains("Send / Chat"), "{out}");
}

#[test]
fn the_tutorial_says_both_people_add_each_other_and_the_receiver_listens() {
    let dir = tempfile::tempdir().unwrap();
    let o = ash_out(dir.path(), &[], "y\n8\n\nq\n");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(out.contains("[1/4] Your identity"), "{out}");
    assert!(out.contains("the `invite` line"), "{out}");
    assert!(out.contains("They must add YOU the same way"), "{out}");
    assert!(out.contains("keep menu 4 (Listen) open"), "{out}");
    assert!(out.contains("run `ash doctor`"), "{out}");
    // The old advice (address + fingerprint is not enough to be added) and the
    // false green tick for the path rule are gone.
    assert!(!out.contains("address+fingerprint"), "{out}");
    assert!(!out.contains("messaging_path must read"), "{out}");
    assert!(!out.contains("bridge relays"), "{out}");
    // The status it runs ends with the verdict.
    assert!(
        out.contains("raven-node is not running: start it with `ash listen`"),
        "{out}"
    );
    assert!(
        out.contains("Full diagnostics anytime: ash doctor"),
        "{out}"
    );
}

// ── status, doctor, inbox ───────────────────────────────────────────────────

#[test]
fn status_gives_a_plain_receiving_row_and_a_verdict_for_every_node_state() {
    // No node at all.
    let dir = short_dir();
    plant_identity(dir.path());
    let o = ash_out(dir.path(), &["status"], "");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        out.contains("receiving     NO — raven-node is not running"),
        "{out}"
    );
    assert!(
        status_body(&out)
            .ends_with("raven-node is not running: start it with `ash listen` (it also starts by itself when you send a message)."),
        "{out}"
    );
    // The raw OS error is not there. Field test E3 round 2: "BRIDGE",
    // "daemon running (answers IPC)" and "forward_q" were developer words;
    // the queue row is a --verbose one now, the key in hex and the raw
    // invite too.
    assert!(
        out.contains("CONNECTIONS") && !out.contains("BRIDGE"),
        "{out}"
    );
    assert!(!out.contains("forward_q"), "{out}");
    assert!(!out.contains("os error"), "{out}");
    for developer in ["pub_hex", "invite", "public bits only", "answers IPC"] {
        assert!(!out.contains(developer), "{developer}: {out}");
    }
    // Field test E3: no developer rows unless asked for (`--verbose`, or
    // RAVEN_VERBOSE=1); the same command still ends the same way.
    for technical in [
        "serverless_rvn1",
        "never silently uses FastAPI",
        "path_rule",
        "configured",
        "policy        ",
        "endpoint      ",
    ] {
        assert!(!out.contains(technical), "{technical}: {out}");
    }
    let verbose = ash_out(dir.path(), &["status", "--verbose"], "");
    assert_eq!(code(&verbose), 0, "{}", text(&verbose.stderr));
    let verbose = text(&verbose.stdout);
    for technical in [
        "serverless_rvn1",
        "never silently uses FastAPI",
        "configured",
        "policy        ",
        "forward_q",
        "pub_hex",
    ] {
        assert!(verbose.contains(technical), "{technical}: {verbose}");
    }
    assert_eq!(
        status_body(&verbose).lines().last(),
        status_body(&out).lines().last()
    );
    assert!(
        !out.contains("mock_ble") && !out.contains("transports"),
        "{out}"
    );

    // A node whose LAN listener is up receives.
    let dir = short_dir();
    plant_identity(dir.path());
    let node = FakeNode::start(dir.path(), &["ipc", "lan_direct", "bridge", "store"]);
    let o = ash_out(dir.path(), &["status"], "");
    drop(node);
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(out.contains("receiving     YES"), "{out}");
    assert!(
        status_body(&out).ends_with("You can send and receive."),
        "{out}"
    );
    assert!(out.contains("raven-node    running\n"), "{out}");

    // A node without its LAN listener (busy port, outbound-only) cannot receive.
    let dir = short_dir();
    plant_identity(dir.path());
    let node = FakeNode::start(dir.path(), &["ipc", "bridge"]);
    let o = ash_out(dir.path(), &["status"], "");
    drop(node);
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        out.contains("receiving     NO — raven-node runs but its LAN listener is down"),
        "{out}"
    );
    assert!(out.contains("You can send but NOT receive"), "{out}");
    assert!(!out.contains("You can send and receive"), "{out}");
}

/// CP.5 (F2): a listener on loopback receives on this computer only, and a
/// listener whose address is not on this computer says so, never "busy
/// port"; `ash doctor` has a `receiving:` key for both.
#[test]
fn status_says_when_friends_cannot_reach_this_computer() {
    let dir = short_dir();
    plant_identity(dir.path());
    let fake = Fake {
        lan_listen: Some("127.0.0.1:47312".into()),
        ..Fake::default()
    };
    let node = FakeNode::start_with(dir.path(), &["ipc", "lan_direct", "bridge"], fake);
    let status = ash_out(dir.path(), &["status"], "");
    let doctor = ash_out(dir.path(), &["doctor"], "");
    drop(node);
    let out = text(&status.stdout);
    assert_eq!(code(&status), 0, "{}", text(&status.stderr));
    assert!(
        out.contains(
            "receiving     ONLY THIS COMPUTER — raven-node listens on 127.0.0.1:47312, so friends \
             on your network cannot reach you. Run `ash listen` to listen on your networks"
        ),
        "{out}"
    );
    assert!(!out.contains("receiving     YES"), "{out}");
    assert!(
        status_body(&out).ends_with(
            "You can send, but friends cannot reach you: raven-node listens on this computer \
             only (127.0.0.1:47312)."
        ),
        "{out}"
    );
    let report = text(&doctor.stdout);
    assert!(
        report.contains("  receiving: local_only (127.0.0.1:47312)"),
        "{report}"
    );

    let dir = short_dir();
    plant_identity(dir.path());
    let fake = Fake {
        lan_listen_wanted: Some("192.0.2.10:7499".into()),
        lan_bind_error: Some("addr_not_here".into()),
        ..Fake::default()
    };
    let node = FakeNode::start_with(dir.path(), &["ipc", "bridge"], fake);
    let status = ash_out(dir.path(), &["status"], "");
    let doctor = ash_out(dir.path(), &["doctor"], "");
    drop(node);
    let out = text(&status.stdout);
    assert_eq!(code(&status), 0, "{}", text(&status.stderr));
    assert!(
        out.contains(
            "receiving     NO — raven-node is set to listen on 192.0.2.10:7499, but that address \
             is not on this computer now (did you change networks?)."
        ),
        "{out}"
    );
    assert!(out.contains("is not on this computer now"), "{out}");
    assert!(!out.contains("busy port"), "{out}");
    let report = text(&doctor.stdout);
    assert!(
        report.contains("  receiving: no (addr_not_here 192.0.2.10:7499)"),
        "{report}"
    );
    assert!(!report.contains("busy port"), "{report}");
}

/// The `LAN` row of `ash status` and of the doctor's summary (Phase 3 P3.6).
fn lan_row(value: &str) -> String {
    format!("  {:<14}{value}", "LAN")
}

/// This profile's `node_policy.json`, as `raw` (a setting, or bytes that
/// cannot be read).
fn write_policy(dir: &Path, raw: &str) {
    std::fs::write(dir.join("node_policy.json"), raw).unwrap();
}

/// A running raven-node's `Status.lan`.
fn lan(mode: &str, listen: &[&str], local_only: bool) -> Option<LanStatus> {
    Some(LanStatus {
        mode: mode.into(),
        listen: listen.iter().map(|at| at.to_string()).collect(),
        local_only,
        ..LanStatus::default()
    })
}

/// Phase 3 P3.6: the LAN row of `ash status` and `ash doctor` for every mode
/// a running raven-node reports, `raven lan off` (and the receiving row that
/// goes with it), and the fail-closed row of a node_policy.json that cannot
/// be read: the doctor's first summary row then, and its next step is `raven
/// lan on`.
#[test]
fn status_and_doctor_show_the_lan_row_for_every_mode() {
    let listening = ["ipc", "lan_direct"];
    for (listen, lan, row) in [
        (
            "0.0.0.0:7420",
            lan("on", &["0.0.0.0:7420", "[::]:7420"], true),
            "on - all networks of this computer, contacts only",
        ),
        (
            "0.0.0.0:7420",
            lan("on", &["0.0.0.0:7420"], false),
            "on - 0.0.0.0:7420",
        ),
        (
            "127.0.0.1:7420",
            lan("this-computer", &["127.0.0.1:7420"], false),
            "this computer only (127.0.0.1:7420)",
        ),
    ] {
        let dir = short_dir();
        plant_identity(dir.path());
        let fake = Fake {
            lan_listen: Some(listen.into()),
            lan,
            ..Fake::default()
        };
        let node = FakeNode::start_with(dir.path(), &listening, fake);
        let status = ash_out(dir.path(), &["status"], "");
        let doctor = ash_out(dir.path(), &["doctor"], "");
        drop(node);
        let out = text(&status.stdout);
        assert_eq!(code(&status), 0, "{}", text(&status.stderr));
        assert!(out.contains(&format!("{}\n", lan_row(row))), "{out}");
        let report = text(&doctor.stdout);
        assert!(report.contains(&format!("{}\n", lan_row(row))), "{report}");
    }

    // `raven lan off`: the node listens nowhere, and the receiving row says
    // why (never a busy port).
    let dir = short_dir();
    plant_identity(dir.path());
    write_policy(dir.path(), r#"{"lan_off": true}"#);
    let fake = Fake {
        lan: lan("off", &[], false),
        ..Fake::default()
    };
    let node = FakeNode::start_with(dir.path(), &["ipc", "bridge"], fake);
    let status = ash_out(dir.path(), &["status"], "");
    let doctor = ash_out(dir.path(), &["doctor"], "");
    drop(node);
    let out = text(&status.stdout);
    assert!(out.contains(&lan_row("off - raven lan on")), "{out}");
    assert!(
        out.contains(
            "receiving     NO — LAN is off on this computer (`raven lan on` turns it back on)"
        ),
        "{out}"
    );
    assert!(!out.contains("busy port"), "{out}");
    let report = text(&doctor.stdout);
    assert!(report.contains(&lan_row("off - raven lan on")), "{report}");
    assert!(report.contains("  receiving: no (lan_off)"), "{report}");

    // node_policy.json cannot be read: LAN is off (fail closed), said first.
    let dir = short_dir();
    plant_identity(dir.path());
    write_policy(dir.path(), "{\"lan_off\": tru");
    let status = ash_out(dir.path(), &["status"], "");
    let doctor = ash_out(dir.path(), &["doctor"], "");
    let unreadable = lan_row("off because node_policy.json cannot be read - raven lan on");
    let out = text(&status.stdout);
    assert!(out.contains(&unreadable), "{out}");
    let report = text(&doctor.stdout);
    assert!(
        report.starts_with(&format!("raven doctor\nSUMMARY\n{unreadable}\n")),
        "{report}"
    );
    assert!(
        report.contains("next step     run `raven lan on`: node_policy.json cannot be read"),
        "{report}"
    );
    assert!(
        report
            .trim_end()
            .lines()
            .last()
            .is_some_and(|l| l.starts_with("Next step: run `raven lan on`")),
        "{report}"
    );
}

/// Phase 3 P3.11: the `nearby search` row of `ash status`, `ash doctor` and
/// `raven lan status`, right after the LAN row in the first two: the LAN
/// beacon's state and last ten minutes' counts as the running raven-node
/// reports them (never an address), "multicast blocked" once its queries
/// went out and none came back, and "held in this build" while its gate is
/// closed. An older raven-node (no beacon in its LAN row): no such row.
#[test]
fn status_and_doctor_show_the_nearby_search_row() {
    let counts = |state: &str, sent: u32, answered: u32, echo_ok: bool| BeaconCounts {
        state: state.into(),
        interfaces: 1,
        echo_ok,
        queries_10m: sent,
        answered_10m: answered,
        answers_sent_10m: 2,
        dropped_10m: 0,
        no_answer: Vec::new(),
    };
    let all = "on - all networks of this computer, contacts only";
    for (beacon, row) in [
        (
            Some(counts("on", 3, 1, true)),
            Some("on (answers only your contacts); last 10 min: 3 sent, 1 answered"),
        ),
        (
            Some(counts("on", 4, 0, false)),
            Some(
                "on (answers only your contacts); last 10 min: 4 sent, 0 answered; multicast \
                 blocked on this computer (the macOS Local Network permission, or a firewall)",
            ),
        ),
        (
            Some(counts("held", 0, 0, false)),
            Some("held in this build"),
        ),
        (None, None),
    ] {
        let dir = short_dir();
        plant_identity(dir.path());
        let mut lan = lan("on", &["0.0.0.0:7420", "[::]:7420"], true);
        lan.as_mut().unwrap().beacon = beacon.map(Box::new);
        let fake = Fake {
            lan_listen: Some("0.0.0.0:7420".into()),
            lan,
            ..Fake::default()
        };
        let node = FakeNode::start_with(dir.path(), &["ipc", "lan_direct"], fake);
        let status = ash_out(dir.path(), &["status"], "");
        let doctor = ash_out(dir.path(), &["doctor"], "");
        let lan_status = ash_out(dir.path(), &["lan", "status"], "");
        drop(node);
        assert_eq!(code(&status), 0, "{}", text(&status.stderr));
        let lan_status = text(&lan_status.stdout);
        // `raven status` leaves out what only says this build holds the
        // search back (field test E3); `raven doctor` keeps it.
        let held = row == Some("held in this build");
        for (out, shown) in [
            (text(&status.stdout), row.filter(|_| !held)),
            (text(&doctor.stdout), row),
        ] {
            match shown {
                Some(row) => assert!(
                    out.contains(&format!("{}\n  {:<14}{row}\n", lan_row(all), "LAN search")),
                    "{out}"
                ),
                None => assert!(!out.contains("LAN search"), "{out}"),
            }
        }
        match row {
            Some(row) => assert!(
                lan_status.contains(&format!("  {:<14}{row}\n", "LAN search")),
                "{lan_status}"
            ),
            None => assert!(!lan_status.contains("LAN search"), "{lan_status}"),
        }
        // Counts and words only.
        assert!(!lan_status.contains("192.168."), "{lan_status}");
    }
}

/// `ash` with the nearby lab switches (debug build): this build has
/// Bluetooth nearby.
/// P6.17: a raven-node that reports no learning (one from before Phase 6a,
/// or one that holds it) shows nothing new: no LEARNING section in `raven
/// status`, no `learning:` or `learning_row_` line in `raven doctor`. `raven
/// learning status` says learning is held, and `reset` falls back to the
/// file (none here: nothing to forget). Without a terminal `reset` needs
/// --yes and asks nothing.
#[test]
fn old_daemon_shows_nothing_new() {
    let dir = short_dir();
    plant_identity(dir.path());
    add_bob(dir.path(), "Bob");
    let status = with_node(dir.path(), Fake::default(), &["status"]);
    assert!(!status.contains("LEARNING"), "{status}");
    let doctor = with_node(dir.path(), Fake::default(), &["doctor"]);
    assert!(
        !doctor
            .lines()
            .any(|l| l.trim_start().starts_with("learning:") || l.contains("learning_row_")),
        "{doctor}"
    );
    let out = with_node(dir.path(), Fake::default(), &["learning", "status"]);
    assert_eq!(out.trim_end(), "learning: held in this build", "{out}");
    let out = with_node(
        dir.path(),
        Fake::default(),
        &["learning", "status", "--json"],
    );
    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("one JSON object");
    assert_eq!(json["state"], "held", "{out}");
    assert_eq!(json["rows"], serde_json::json!([]), "{out}");
    let out = with_node(dir.path(), Fake::default(), &["learning", "reset", "--yes"]);
    assert!(out.contains("nothing to forget (cleared 0)"), "{out}");
    assert!(!dir.path().join("learning.bin").exists());
    let node = FakeNode::start(dir.path(), &["ipc"]);
    let o = ash_out(dir.path(), &["learning", "reset"], "y\n");
    drop(node);
    let _ = std::fs::remove_file(raven_core::default_socket_path(dir.path()));
    assert_eq!(code(&o), 1, "{}", text(&o.stdout));
    assert!(
        text(&o.stderr).contains("pass --yes"),
        "{}",
        text(&o.stderr)
    );
    assert!(!text(&o.stdout).contains("[y/N]"), "{}", text(&o.stdout));
}

fn ash_nearby_lab(dir: &Path) -> Command {
    let mut c = ash(dir);
    c.env("RAVEN_LAB_TEST_A", "1").env("RAVEN_LAB_NEARBY", "1");
    c
}

/// `ash` as a build that holds nearby: since 2026-10 release builds have
/// it on macOS only, so here its debug switch closes it (`0`), on every
/// system.
fn ash_nearby_held(dir: &Path) -> Command {
    let mut c = ash(dir);
    c.env("RAVEN_LAB_NEARBY", "0");
    c
}

/// Why nearby is held (ash's `nearby_cli::HELD_WHY`): release builds have it
/// on macOS only; on macOS only the debug switch closes it.
const HELD_WHY: &str = if cfg!(target_os = "macos") {
    "Bluetooth nearby is closed in this process (RAVEN_LAB_NEARBY=0)"
} else {
    "Bluetooth nearby is in release builds on macOS only"
};
/// The same in `raven doctor`.
const HELD_DOCTOR: &str = if cfg!(target_os = "macos") {
    "RAVEN_LAB_NEARBY=0"
} else {
    "NEARBY_PRODUCTION_ENABLED=false: macOS only"
};

fn nearby_info(radio: &str, roles: &[&str], address: &str) -> NearbyStatusInfo {
    NearbyStatusInfo {
        enabled: true,
        gate_live: true,
        radio: radio.into(),
        roles: roles.iter().map(|r| r.to_string()).collect(),
        address_privacy: address.into(),
        ..NearbyStatusInfo::default()
    }
}

/// Phase 5 (P5.28): the NEARBY rows of `ash status` and the `nearby:` line
/// of `ash doctor`, as snapshots: held (a saved choice only; nothing at
/// all in a release status without one), off, Bluetooth not allowed, a
/// public address (nearby inactive), and a central-only radio; each
/// says what to do, and no row names a key or an address.
#[test]
fn status_and_doctor_show_the_nearby_rows() {
    // Held, nothing saved: no section; doctor names the flag.
    let dir = short_dir();
    plant_identity(dir.path());
    let status = with_node_cmd(
        dir.path(),
        Fake::default(),
        ash_nearby_held(dir.path()),
        &["status"],
    );
    assert!(!status.contains("BLUETOOTH NEARBY"), "{status}");
    let doctor = with_node_cmd(
        dir.path(),
        Fake::default(),
        ash_nearby_held(dir.path()),
        &["doctor"],
    );
    assert!(
        doctor.contains(&format!("\n  bluetooth_nearby: held ({HELD_DOCTOR})\n")),
        "{doctor}"
    );
    assert!(!doctor.contains("bluetooth: skipped"), "{doctor}");
    // Held with a saved choice (a lab profile under a release build).
    std::fs::write(dir.path().join("node_policy.json"), r#"{"nearby":true}"#).unwrap();
    let status = with_node_cmd(
        dir.path(),
        Fake::default(),
        ash_nearby_held(dir.path()),
        &["status"],
    );
    assert_eq!(
        section(&status, "BLUETOOTH NEARBY"),
        [format!(
            "  {:<14}held in this build: {HELD_WHY} (your choice is kept)",
            "state"
        )],
        "{status}"
    );

    let mut off = nearby_info("off", &[], "unknown");
    off.enabled = false;
    // A fixed public address: nearby inactive, no advert and no connect
    // (Phase 5 review nearby-1); Windows says why in its own words.
    const PUBLIC_ROW: &str = if cfg!(windows) {
        "address       nearby inactive: Windows may use this PC's fixed Bluetooth address, so it \
         neither advertises nor connects until that is ruled out (row N7w)"
    } else {
        "address       nearby inactive: the adapter would use its fixed public address, so this \
         computer neither advertises nor connects; set Privacy = device in \
         /etc/bluetooth/main.conf (admin)"
    };
    let cases: [(NearbyStatusInfo, &[&str], Option<&str>); 5] = [
        (
            off,
            &["state         off (turn on: raven nearby enable; verified contacts only)"],
            None,
        ),
        (
            nearby_info("unauthorized", &[], "unknown"),
            &[
                "state         on (verified contacts only)",
                "radio         not allowed: allow Bluetooth for Raven in this computer's privacy \
                 settings (on macOS: RavenNearby), then restart raven-node",
            ],
            Some("bluetooth_nearby_fix: not allowed"),
        ),
        (
            nearby_info("powered_on", &["central", "peripheral"], "public"),
            &[
                "state         on (verified contacts only)",
                "radio         on",
                PUBLIC_ROW,
                "in range      0 contacts in range now, 0 connected",
            ],
            Some("bluetooth_nearby_fix: nearby inactive: "),
        ),
        (
            nearby_info("powered_on", &["central"], "public"),
            &[
                "state         on (verified contacts only)",
                "radio         on, central only: this computer can only connect to contacts \
                 that advertise",
                PUBLIC_ROW,
                "in range      0 contacts in range now, 0 connected",
            ],
            Some("bluetooth_nearby_fix: nearby inactive: "),
        ),
        (
            nearby_info("powered_on", &["central"], "random"),
            &[
                "state         on (verified contacts only)",
                "radio         on, central only: this computer can only connect to contacts \
                 that advertise",
                "in range      0 contacts in range now, 0 connected",
            ],
            Some("bluetooth_nearby_fix: on, central only"),
        ),
    ];
    for (info, rows, fix) in cases {
        let dir = short_dir();
        plant_identity(dir.path());
        let fake = || Fake {
            nearby: Some(info.clone()),
            ..Fake::default()
        };
        let status = with_node_cmd(dir.path(), fake(), ash_nearby_lab(dir.path()), &["status"]);
        let got: Vec<String> = section(&status, "BLUETOOTH NEARBY")
            .iter()
            .map(|l| l.trim_start().to_string())
            .collect();
        assert_eq!(got, rows, "{status}");
        let doctor = with_node_cmd(dir.path(), fake(), ash_nearby_lab(dir.path()), &["doctor"]);
        assert!(
            doctor.contains(&format!(
                "\n  bluetooth_nearby: enabled={} radio={}",
                if info.enabled { "yes" } else { "no" },
                info.radio
            )),
            "{doctor}"
        );
        match fix {
            Some(fix) => assert!(doctor.contains(&format!("\n  {fix}")), "{doctor}"),
            None => assert!(!doctor.contains("nearby_fix"), "{doctor}"),
        }
        let nearby = with_node_cmd(dir.path(), fake(), ash_nearby_lab(dir.path()), &["nearby"]);
        assert!(nearby.starts_with("Nearby (Bluetooth): "), "{nearby}");
        for row in rows {
            assert!(nearby.contains(row), "{row:?} in {nearby}");
        }
        for out in [&status, &doctor, &nearby] {
            assert!(!out.contains("ether-"), "{out}");
        }
    }
}

/// Phase 5 (P5.28): `ash nearby enable` shows the consent (with this
/// computer's Bluetooth name) once, before the first choice is saved, and
/// the running raven-node applies it; `disable` and a later `enable` ask
/// nothing. An older raven-node (IPC_FRAME) is "too old for nearby", and a
/// build that holds nearby refuses with the hold and saves nothing.
#[test]
fn nearby_enable_shows_the_consent_once_and_an_old_node_is_too_old() {
    let dir = short_dir();
    plant_identity(dir.path());
    let fake = || Fake {
        nearby: Some(NearbyStatusInfo {
            gate_live: true,
            radio: "off".into(),
            ..NearbyStatusInfo::default()
        }),
        ..Fake::default()
    };
    let first = with_node_cmd(
        dir.path(),
        fake(),
        ash_nearby_lab(dir.path()),
        &["nearby", "enable"],
    );
    assert!(
        first.contains("Nearby (Bluetooth) lets your verified contacts"),
        "{first}"
    );
    assert!(first.contains("can read its Bluetooth name '"), "{first}");
    assert!(
        first.contains("only your verified contacts can use it"),
        "{first}"
    );
    assert!(
        first.contains("ok nearby=on: raven-node looks for your verified contacts"),
        "{first}"
    );
    let policy = std::fs::read_to_string(dir.path().join("node_policy.json")).unwrap();
    assert!(policy.contains("\"nearby\": true"), "{policy}");
    for args in [&["nearby", "disable"][..], &["nearby", "enable"]] {
        let again = with_node_cmd(dir.path(), fake(), ash_nearby_lab(dir.path()), args);
        assert!(!again.contains("Bluetooth name"), "{again}");
        assert!(again.starts_with("ok nearby="), "{again}");
    }

    let old = Fake {
        nearby_old: true,
        ..Fake::default()
    };
    let status = with_node_cmd(
        dir.path(),
        old.clone(),
        ash_nearby_lab(dir.path()),
        &["nearby", "status"],
    );
    assert!(
        status.contains("Nearby (Bluetooth): raven-node is too old for nearby: update it"),
        "{status}"
    );
    let node = FakeNode::start_with(dir.path(), &["ipc"], old);
    let mut c = ash_nearby_lab(dir.path());
    c.args(["nearby", "enable"]);
    let refused = run(c, "");
    drop(node);
    let _ = std::fs::remove_file(raven_core::default_socket_path(dir.path()));
    assert_eq!(code(&refused), 1, "{}", text(&refused.stdout));
    assert!(
        text(&refused.stderr).contains("raven-node is too old for nearby: update it"),
        "{}",
        text(&refused.stderr)
    );

    // A build that holds nearby refuses and saves nothing.
    let held = short_dir();
    plant_identity(held.path());
    let mut c = ash_nearby_held(held.path());
    c.args(["nearby", "enable"]);
    let o = run(c, "");
    assert_eq!(code(&o), 1, "{}", text(&o.stdout));
    assert!(
        text(&o.stderr).contains("NEARBY_HOLD"),
        "{}",
        text(&o.stderr)
    );
    assert!(!held.path().join("node_policy.json").exists());
    let mut c = ash_nearby_held(held.path());
    c.args(["send", "--contact", "@bob", "--carrier", "nearby"]);
    let o = run(c, "hi\n");
    assert_ne!(code(&o), 0);
    assert!(
        !text(&o.stderr).contains("unknown --carrier"),
        "{}",
        text(&o.stderr)
    );
}

/// Phase 3 P3.6: `raven lan off` saves the setting and turns the running
/// raven-node's LAN off at once; `raven node lan status` (the alias) shows
/// it; `raven lan on` turns it back on; with no raven-node the next one
/// reads the setting.
#[test]
fn lan_off_and_on_save_the_setting_and_tell_the_running_node() {
    let dir = short_dir();
    plant_identity(dir.path());
    let policy = || std::fs::read_to_string(dir.path().join("node_policy.json")).unwrap();
    let node = FakeNode::start(dir.path(), &["ipc", "lan_direct"]);
    let off = ash_out(dir.path(), &["lan", "off"], "");
    let saved_off = policy();
    let status = ash_out(dir.path(), &["node", "lan", "status"], "");
    let on = ash_out(dir.path(), &["lan", "on"], "");
    drop(node);
    let out = text(&off.stdout);
    assert_eq!(code(&off), 0, "{}", text(&off.stderr));
    assert!(
        out.starts_with("LAN off: this computer stops listening on the local network"),
        "{out}"
    );
    assert!(
        out.contains("(p2p on port 7423 is separate: raven node p2p off.)"),
        "{out}"
    );
    assert!(
        out.contains("The running raven-node turned LAN off now."),
        "{out}"
    );
    assert!(saved_off.contains(r#""lan_off": true"#), "{saved_off}");
    let out = text(&status.stdout);
    assert_eq!(code(&status), 0, "{}", text(&status.stderr));
    assert!(out.starts_with("LAN: off - raven lan on\n"), "{out}");
    let out = text(&on.stdout);
    assert_eq!(code(&on), 0, "{}", text(&on.stderr));
    assert!(out.starts_with("LAN on: "), "{out}");
    assert!(
        out.contains("The running raven-node turned LAN on now."),
        "{out}"
    );
    assert!(!policy().contains("lan_off"), "{}", policy());

    // No raven-node: saved, and read when one starts.
    let o = ash_out(dir.path(), &["lan", "off"], "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        text(&o.stdout).contains("raven-node is not running: it reads this when it starts."),
        "{}",
        text(&o.stdout)
    );
    assert!(policy().contains(r#""lan_off": true"#));
}

/// Phase 3 P3.C2 (cutoff M1): `raven lan on --for 30m` saves the meeting
/// time and tells the running raven-node, in the step's words; `raven lan
/// status` says until when, and once the meeting time is over (a lab clock
/// 31 minutes ahead) when listening stopped; `raven lan verified-only on`
/// saves that setting and the status says so; a bad time changes nothing.
#[test]
fn lan_on_for_and_verified_only_say_what_they_do() {
    let dir = short_dir();
    let dd = dir.path();
    plant_identity(dd);
    std::fs::write(dd.join(raven_core::BACKEND_MARKER_NAME), b"locked-file\n").unwrap();
    write_policy(dd, r#"{"lan_off": true}"#);
    let node = FakeNode::start(dd, &["ipc", "lan_direct"]);
    let open = ash_out(dd, &["lan", "on", "--for", "30m"], "");
    let status = ash_out(dd, &["lan", "status"], "");
    let clock = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(clock.path(), format!("{}\n", 31 * 60_000)).unwrap();
    let later = run(
        {
            let mut c = ash(dd);
            c.args(["lan", "status"])
                .env("RAVEN_LAB_TEST_A", "1")
                .env("RAVEN_LAB_CLOCK_FILE", clock.path());
            c
        },
        "",
    );
    let verified = ash_out(dd, &["lan", "verified-only", "on"], "");
    let status_verified = ash_out(dd, &["lan", "status"], "");
    let bad = ash_out(dd, &["lan", "on", "--for", "90s"], "");
    drop(node);

    let out = text(&open.stdout);
    assert_eq!(code(&open), 0, "{}", text(&open.stderr));
    assert!(out.starts_with("Open to friends "), "{out}");
    assert!(
        out.contains(
            "Only your friends can connect. Others on this network may still see that this \
             computer is waiting for connections."
        ),
        "{out}"
    );
    assert!(
        out.contains("The running raven-node turned LAN on now."),
        "{out}"
    );
    assert!(dd.join("lan_meeting.json").exists());
    assert!(
        !std::fs::read_to_string(dd.join("node_policy.json"))
            .unwrap()
            .contains("lan_off"),
        "LAN on"
    );
    let out = text(&status.stdout);
    assert_eq!(code(&status), 0, "{}", text(&status.stderr));
    assert!(
        out.starts_with("LAN: on until ") || out.starts_with("LAN: on for about "),
        "{out}"
    );
    assert!(
        out.contains("verified-only off: every contact can connect"),
        "{out}"
    );
    assert!(!out.contains("Stopped listening"), "{out}");
    let out = text(&later.stdout);
    assert_eq!(code(&later), 0, "{}", text(&later.stderr));
    assert!(
        out.starts_with("LAN: off - the meeting time is over (raven lan on --for 1h)\n"),
        "{out}"
    );
    assert!(out.contains("\nStopped listening "), "{out}");
    assert!(
        out.contains(
            "Your messages wait for the next meeting. `raven lan on --for 1h` opens it again."
        ),
        "{out}"
    );
    assert_eq!(code(&verified), 0, "{}", text(&verified.stderr));
    assert!(
        text(&verified.stdout)
            .starts_with("Only verified friends can connect on the local network now"),
        "{}",
        text(&verified.stdout)
    );
    assert!(std::fs::read_to_string(dd.join("node_policy.json"))
        .unwrap()
        .contains(r#""lan_verified_only": true"#));
    let out = text(&status_verified.stdout);
    assert!(
        out.contains("verified-only on: only verified friends can connect"),
        "{out}"
    );
    let err = text(&bad.stderr);
    assert_eq!(code(&bad), 1, "{err}");
    assert!(err.contains("--for takes minutes or hours"), "{err}");
}

/// Phase 3 P3.6: `raven listen` refuses while `raven lan off` holds, before
/// anything else (no service is started).
#[test]
fn listen_refuses_with_lan_off_and_says_how_to_turn_it_on() {
    let dir = short_dir();
    plant_identity(dir.path());
    write_policy(dir.path(), r#"{"lan_off": true}"#);
    let o = ash_out(dir.path(), &["listen", "--listen", "127.0.0.1:47391"], "");
    let err = text(&o.stderr);
    assert_eq!(code(&o), 1, "{err}");
    assert!(
        err.contains("LAN_OFF: LAN is off on this computer (`raven lan off`)"),
        "{err}"
    );
    assert!(err.contains("Turn it back on with: raven lan on"), "{err}");
    assert!(!err.contains("No pinned contacts"), "LAN_OFF first: {err}");
    assert!(
        !raven_core::default_socket_path(dir.path()).exists(),
        "nothing was started"
    );
}

/// CP.8: a profile whose keys are in the lab file backend says so: the last
/// row of `ash status` (after the verdict, so the rows scripts read are
/// unchanged) and a key line in `ash doctor`. Every test profile is one; a
/// release build refuses the backend (the unit tests cover the condition).
#[test]
fn a_lab_profile_says_its_keys_are_unencrypted() {
    let dir = short_dir();
    plant_identity(dir.path());
    let o = ash_out(dir.path(), &["status"], "");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert_eq!(out.trim_end().lines().last(), Some(LAB_WARNING), "{out}");
    assert_eq!(out.matches(LAB_WARNING).count(), 1, "{out}");
    assert!(status_body(&out).starts_with("\nSTATUS"), "{out}");
    let o = ash_out(dir.path(), &["doctor"], "");
    let report = text(&o.stdout);
    assert!(
        report.contains(&format!(
            "  lab_backend: locked-file (keys unencrypted)\n  {LAB_WARNING}\n"
        )),
        "{report}"
    );
    // The summary and the last line stay the doctor's own.
    assert!(report.starts_with("raven doctor\nSUMMARY"), "{report}");
    assert!(
        report
            .trim_end()
            .lines()
            .last()
            .is_some_and(|l| l.starts_with("Next step: ")),
        "{report}"
    );
}

#[test]
fn doctor_opens_with_a_summary_and_a_next_step_and_keeps_its_technical_lines() {
    let dir = short_dir();
    plant_identity(dir.path());
    add_bob(dir.path(), "Bob");
    let o = ash_out(dir.path(), &["doctor"], "");
    let out = text(&o.stdout);
    // Identity is fine and the node being down is not a failure of the report.
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    // The summary: every row up to the technical details (a lab run's gates
    // add rows, such as the security notices' `updates`).
    let top: Vec<&str> = out
        .lines()
        .take_while(|l| !l.contains("(technical details follow)"))
        .collect();
    let top = top.join("\n");
    assert!(top.starts_with("raven doctor\nSUMMARY"), "{top}");
    assert!(top.contains("identity      OK"), "{top}");
    assert!(top.contains("raven-node    NOT running"), "{top}");
    assert!(top.contains("contacts      1"), "{top}");
    assert!(
        top.contains("next step     to receive messages run `ash listen`"),
        "{top}"
    );
    // Also the last line, so `| tail` shows it.
    assert!(
        out.trim_end()
            .lines()
            .last()
            .unwrap()
            .starts_with("Next step: to receive messages run `ash listen`"),
        "{out}"
    );
    // Every token line the scripts and installers read is still there.
    for token in [
        "serverless_rvn1",
        "never silently uses FastAPI",
        "daemon_presence: down",
        "daemon_ready: not_ready",
        "send_path:",
        "identity: present",
        "ipc_endpoint=",
    ] {
        assert!(out.contains(token), "{token:?} missing from {out}");
    }
    // The node being down is a plain row, not a raw error code.
    assert!(!top.contains("os error"), "{top}");

    // With no identity the one step is `ash init`.
    let empty = short_dir();
    let o = ash_out(empty.path(), &["doctor"], "");
    let out = text(&o.stdout);
    assert!(
        out.contains("identity      MISSING (run: ash init)"),
        "{out}"
    );
    assert!(out.contains("next step     run `ash init`"), "{out}");
}

const IGD_1: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
const IGD_2: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:2";
const V6_FIREWALL: &str = "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1";

/// A router for `ash doctor --router` on 127.0.0.1:0, in a thread: a
/// [`FakeGateway`] (PCP and NAT-PMP) that also answers an SSDP search for a
/// target it serves, as a router does. A debug build with the lab unlock
/// sends every probe of the doctor to `RAVEN_LAB_PORTMAP_GATEWAY`: here.
struct FakeRouter {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    searches: Arc<AtomicUsize>,
    thread: Option<std::thread::JoinHandle<FakeGateway>>,
}

impl FakeRouter {
    fn start(mode: Mode, serves: &'static [&'static str]) -> Self {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let addr = sock.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let searches = Arc::new(AtomicUsize::new(0));
        let (stop_t, searches_t) = (stop.clone(), searches.clone());
        let thread = std::thread::spawn(move || {
            let mut gw = FakeGateway::new(mode, Instant::now());
            let mut buf = [0u8; 2048];
            while !stop_t.load(Ordering::SeqCst) {
                let Ok((n, src)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                let request = &buf[..n];
                let reply = if request.starts_with(b"M-SEARCH") {
                    searches_t.fetch_add(1, Ordering::SeqCst);
                    std::str::from_utf8(request)
                        .ok()
                        .and_then(|t| t.lines().find_map(|l| l.strip_prefix("ST: ")))
                        .filter(|st| serves.contains(st))
                        .map(|st| {
                            format!(
                                "HTTP/1.1 200 OK\r\nEXT:\r\nLOCATION: \
                                 http://192.0.2.1:5000/rootDesc.xml\r\nST: {st}\r\n\
                                 USN: uuid:1::{st}\r\n\r\n"
                            )
                            .into_bytes()
                        })
                } else {
                    gw.reply(request, src, Instant::now())
                };
                if let Some(reply) = reply {
                    let _ = sock.send_to(&reply, src);
                }
            }
            gw
        });
        FakeRouter {
            addr,
            stop,
            searches,
            thread: Some(thread),
        }
    }

    /// Stop it: the gateway (what it saw and holds) and how many SSDP
    /// searches came.
    fn stop(mut self) -> (FakeGateway, usize) {
        self.stop.store(true, Ordering::SeqCst);
        let gw = self.thread.take().unwrap().join().unwrap();
        (gw, self.searches.load(Ordering::SeqCst))
    }
}

impl Drop for FakeRouter {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Phase 4 P4.4: `ash doctor --router` asks the router what it speaks and
/// prints one block of `key=word` lines after the reachability lines, never
/// an address; it maps nothing. Plain `ash doctor` sends the router nothing.
#[test]
fn doctor_router_section_says_what_the_router_speaks_in_words() {
    // Only a debug build reads the lab gateway (a release one would ask the
    // real router).
    if !cfg!(debug_assertions) {
        return;
    }
    let dir = short_dir();
    plant_identity(dir.path());
    let doctor = |router: &FakeRouter, args: &[&str]| -> String {
        let mut c = ash(dir.path());
        c.args(args)
            .env("RAVEN_LAB_TEST_A", "1")
            .env("RAVEN_LAB_PORTMAP_GATEWAY", router.addr.to_string());
        let o = run(c, "");
        assert_eq!(code(&o), 0, "{}", text(&o.stderr));
        text(&o.stdout)
    };
    let section = |out: &str| -> Vec<String> {
        out.lines()
            .filter(|l| l.starts_with("  router_"))
            .map(str::to_string)
            .collect()
    };
    // The doctor only asked: ANNOUNCEs (lifetime 0) and NAT-PMP external
    // address requests, and the router holds no mapping.
    let read_only = |gw: &FakeGateway| {
        assert!(!gw.log.is_empty());
        for seen in &gw.log {
            assert!(
                seen.op == 0 && seen.lifetime == 0 && seen.proto.is_none(),
                "{seen:?}"
            );
        }
        assert!(gw.mappings.is_empty(), "{:?}", gw.mappings);
    };

    let quiet = FakeRouter::start(Mode::Pcp, &[IGD_1, IGD_2, V6_FIREWALL]);
    let out = doctor(&quiet, &["doctor"]);
    assert!(section(&out).is_empty(), "{out}");
    let (gw, searches) = quiet.stop();
    assert!(gw.log.is_empty(), "{:?}", gw.log);
    assert_eq!(searches, 0);

    // A PCP router that also speaks NAT-PMP (as miniupnpd does), with UPnP
    // IGDv2 and the IPv6 firewall service.
    let pcp = FakeRouter::start(Mode::Pcp, &[IGD_1, IGD_2, V6_FIREWALL]);
    let out = doctor(&pcp, &["doctor", "--router"]);
    assert!(
        out.contains(
            "  router_gateway_v4=found\n  router_gateway_v6=none\n  router_pcp=yes\n  \
             router_natpmp=yes\n  router_upnp_igd=v2\n  router_ipv6_firewall_control=yes\n  \
             router_external_v4=global\n"
        ),
        "{out}"
    );
    let at = |line: &str| {
        out.find(line)
            .unwrap_or_else(|| panic!("{line:?} in {out}"))
    };
    assert!(at("  reach_class: ") < at("  router_gateway_v4="), "{out}");
    let (gw, searches) = pcp.stop();
    read_only(&gw);
    assert!(searches >= 3, "{searches}");
    let pcp_out = out;

    // A NAT-PMP-only router with UPnP IGDv1 and no IPv6 firewall service.
    let natpmp = FakeRouter::start(Mode::NatPmpOnly, &[IGD_1]);
    let out = doctor(&natpmp, &["doctor", "--router"]);
    assert!(
        out.contains(
            "  router_gateway_v4=found\n  router_gateway_v6=none\n  router_pcp=no\n  \
             router_natpmp=yes\n  router_upnp_igd=v1\n  router_ipv6_firewall_control=no\n  \
             router_external_v4=global\n"
        ),
        "{out}"
    );
    read_only(&natpmp.stop().0);

    // Nothing the router said (its external address, its description's
    // address) is printed, nor the router's own address.
    for out in [&pcp_out, &out] {
        assert_eq!(section(out).len(), 7, "{out}");
        assert!(
            !out.contains("11.0.2.9") && !out.contains("192.0.2.1"),
            "{out}"
        );
        assert!(
            section(out).iter().all(|l| !l.contains("127.0.0.1")),
            "{out}"
        );
    }
}

#[test]
fn an_empty_inbox_says_why_and_names_the_profile_and_touches_nothing() {
    let dir = short_dir();
    plant_identity(dir.path());
    let o = ash_out(dir.path(), &["inbox"], "");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        out.contains(&format!("No messages yet in {}.", dir.path().display())),
        "{out}"
    );
    assert!(out.contains("nobody has written to you yet"), "{out}");
    assert!(
        out.contains("they have not added you as a contact"),
        "{out}"
    );
    assert!(
        out.contains("this computer is not receiving (check: `ash status`)"),
        "{out}"
    );
    assert!(out.contains("keep `ash listen` running"), "{out}");
    // A stopped node is named on stderr (stdout stays the message list).
    assert!(
        text(&o.stderr).contains("raven-node is not running, so nothing can arrive right now"),
        "{}",
        text(&o.stderr)
    );
    assert!(!out.contains("endpoint inbox empty"), "{out}");

    // With a node that receives there is no such warning.
    let dir = short_dir();
    plant_identity(dir.path());
    let node = FakeNode::start(dir.path(), &["ipc", "lan_direct"]);
    let o = ash_out(dir.path(), &["inbox"], "");
    drop(node);
    assert_eq!(code(&o), 0);
    assert!(
        !text(&o.stderr).contains("nothing can arrive"),
        "{}",
        text(&o.stderr)
    );
    // And one that runs without its listener says so.
    let dir = short_dir();
    plant_identity(dir.path());
    let node = FakeNode::start(dir.path(), &["ipc"]);
    let o = ash_out(dir.path(), &["inbox"], "");
    drop(node);
    assert!(
        text(&o.stderr).contains("this computer is NOT receiving"),
        "{}",
        text(&o.stderr)
    );

    // Before the identity the read-only command creates nothing.
    let bare = short_dir();
    let o = ash_out(bare.path(), &["inbox"], "");
    assert_eq!(code(&o), 0);
    assert!(
        text(&o.stdout).contains("no identity yet"),
        "{}",
        text(&o.stdout)
    );
    // (only the empty identity lock that every identity check leaves, which the
    // first-install check treats as inert: `ash init` still works afterwards)
    let left: Vec<String> = std::fs::read_dir(bare.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        left.iter().all(|n| n == ".identity_store.lock.sqlite"),
        "{left:?}"
    );
    let o = ash_out(bare.path(), &["init"], "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
}

// ── contacts ────────────────────────────────────────────────────────────────

/// Field test E3: after `raven node internet off` and `raven node p2p off`
/// the advice named the launchd agent though none was installed and no
/// raven-node ran. With none running there is nothing to do, and it says
/// so; no login item command.
#[test]
fn node_settings_say_nothing_to_do_while_no_node_runs() {
    let dir = short_dir();
    plant_identity(dir.path());
    for args in [
        &["node", "internet", "off"][..],
        &["node", "p2p", "off"][..],
        &["node", "upnp", "off"][..],
    ] {
        let o = ash_out(dir.path(), args, "");
        assert_eq!(code(&o), 0, "{args:?}: {}", text(&o.stderr));
        let out = text(&o.stdout);
        assert!(
            out.contains(
                "raven-node isn't running: it uses this when it starts (nothing to do now)."
            ),
            "{args:?}: {out}"
        );
        for never in ["launchctl", "systemctl", "ScheduledTask", "installed agent"] {
            assert!(!out.contains(never), "{never}: {out}");
        }
    }
}

/// Field test E3: `raven contact forget-address` without a terminal says in
/// plain words that nothing was forgotten and how a script does it, and
/// exits 2 (1 is a failure); with --yes it forgets every saved route.
#[test]
fn forget_address_without_a_terminal_says_so_and_exits_2() {
    let dir = short_dir();
    plant_identity(dir.path());
    add_bob(dir.path(), "Bob");
    let mut c = ash(dir.path());
    c.args(["contact", "forget-address", "Bob"]);
    let o = run(c, "");
    assert_eq!(code(&o), 2, "{}", text(&o.stderr));
    let err = text(&o.stderr);
    assert!(
        err.contains(
            "Nothing forgotten: forget-address asks first, and there is no terminal to ask on. \
             To forget Bob's addresses from a script, add --yes."
        ),
        "{err}"
    );
    assert!(!err.contains("stdin"), "{err}");
    let mut c = ash(dir.path());
    c.args(["contact", "forget-address", "Bob", "--yes"]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let out = text(&o.stdout);
    for row in [
        "address forgotten Bob",
        "lan_dial    (none)",
        "internet    (none)",
        "p2p         (none)",
    ] {
        assert!(out.contains(row), "{row}: {out}");
    }
}

#[test]
fn contact_saved_says_the_other_person_must_add_you_back() {
    let dir = short_dir();
    plant_identity(dir.path());
    let bob = Identity::from_seed(&[0x42; 32]);
    let mut c = ash(dir.path());
    c.args(["contact", "add", "--address", &bob.address()])
        .args(["--pub-hex", &pub_hex(&bob), "--petname", "Bob"]);
    let o = run(c, "");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    // The substrings scripts grep for ...
    assert!(out.contains("contact saved"), "{out}");
    assert!(out.contains("saved on this computer only"), "{out}");
    // Plain words: no server names or jargon a person has to look up.
    assert!(
        !out.contains("FastAPI") && !out.contains("registrar"),
        "{out}"
    );
    assert!(
        out.contains("fingerprint") && out.contains("pinned"),
        "{out}"
    );
    // ... the name, and the one thing to do next.
    assert!(out.contains("contact saved: Bob"), "{out}");
    assert!(out.contains("ask Bob to add YOU too"), "{out}");
    assert!(out.contains("`ash whoami`"), "{out}");
    assert!(out.contains("BOTH of you have added each other"), "{out}");
    assert!(out.contains("not verified yet"), "{out}");
    // The phone note belongs to the guided flow, not to the command line.
    assert!(!out.contains("iPhone") && !out.contains("آیفون"), "{out}");

    // A contact with no name does not show an address as its "petname".
    let carol = Identity::from_seed(&[0x43; 32]);
    let mut c = ash(dir.path());
    c.args(["contact", "add", "--address", &carol.address()])
        .args(["--pub-hex", &pub_hex(&carol)]);
    let o = run(c, "");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(out.contains("contact saved (no name given"), "{out}");
    assert!(out.contains("petname     (none yet)"), "{out}");
    assert!(out.contains("ask them to add YOU too"), "{out}");

    // E2 r9: adding Bob's card again (same key) is an update: nothing to
    // ask Bob, who has had this computer for days.
    let mut c = ash(dir.path());
    c.args(["contact", "add", "--address", &bob.address()])
        .args(["--pub-hex", &pub_hex(&bob), "--petname", "Bob"]);
    let o = run(c, "");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(out.contains("contact saved: Bob"), "{out}");
    assert!(out.contains("Bob was already your contact"), "{out}");
    assert!(!out.contains("add YOU too"), "{out}");
    assert!(!out.contains("BOTH of you"), "{out}");
}

#[test]
fn contact_add_card_accepts_the_invite_line_whoami_prints() {
    // Bob's profile prints his invite ...
    let bob_dir = short_dir();
    plant_identity_seed(bob_dir.path(), 0x42);
    let o = ash_out(bob_dir.path(), &["whoami"], "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let whoami = text(&o.stdout);
    let invite = whoami
        .lines()
        .find(|l| l.starts_with("invite"))
        .unwrap_or_else(|| panic!("no invite line in:\n{whoami}"))
        .to_string();

    // ... and the line, label and all, is what `--card` takes on Alice's.
    let dir = short_dir();
    plant_identity(dir.path());
    let mut c = ash(dir.path());
    c.args(["contact", "add", "--card", &invite, "--petname", "Bob"]);
    let o = run(c, "");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(out.contains("invite read"), "{out}");
    assert!(out.contains("contact saved: Bob"), "{out}");
    // Saved under Bob's key, not pinned: his code is not shown until a check
    // matched (blind entry), and the next step is comparing words.
    let bob = Identity::from_seed(&[0x42; 32]);
    let fp = raven_core::fingerprint::device_fingerprint_v1(&bob.public_key_bytes());
    assert!(!out.contains(&fp), "{out}");
    assert!(out.contains("not verified yet"), "{out}");
    assert!(out.contains("raven contact verify Bob"), "{out}");
    assert!(!text(&o.stderr).contains("YOUR OWN identity"));
}

/// `raven whoami --card` prints a raven-card/3 (PeerId and relays, no
/// address) only with the route hints lab switch; `--compat`, an address of
/// yours, or a build without the switch print exactly today's raven-card/2.
/// A friend's raven adds the /3 card and says it holds no address. Cards
/// with routes are lab cards (the lab unlock `RAVEN_LAB_TEST_A=1`): see
/// [`cards_carry_no_unsigned_routes_outside_the_lab`].
#[test]
fn whoami_card_is_v3_only_with_route_hints_and_compat_prints_todays_card() {
    let bob_dir = short_dir();
    plant_identity_seed(bob_dir.path(), 0x42);
    let relay = raven_core::p2p_route::local_peer_id(&Identity::from_seed(&[0x43; 32]));
    let via = format!("/ip4/198.51.100.7/tcp/7423/p2p/{relay}");
    let fallback = format!("/ip4/198.51.100.7/tcp/443/p2p/{relay}");
    let card = |extra: &[&str], hints: bool| {
        let mut c = ash(bob_dir.path());
        c.args(["whoami", "--card", "--via", &via, "--via", &fallback])
            .args(extra)
            .env("RAVEN_LAB_TEST_A", "1");
        if hints {
            c.env("RAVEN_LAB_ROUTE_HINTS", "1");
        } else {
            c.env("RAVEN_LAB_ROUTE_HINTS", "0");
        }
        let o = run(c, "");
        assert_eq!(code(&o), 0, "{}", text(&o.stderr));
        text(&o.stdout)
    };
    let today = card(&[], false);
    assert_eq!(today.lines().count(), 1, "{today}");
    assert!(today.starts_with("raven-card/2 "), "{today}");
    assert!(
        today
            .trim_end()
            .ends_with(&format!(" via={via} via={fallback}")),
        "{today}"
    );
    let v3 = card(&[], true);
    assert_eq!(v3.lines().count(), 1, "{v3}");
    assert!(v3.starts_with("raven-card/3 "), "{v3}");
    assert!(
        v3.trim_end()
            .ends_with(&format!(" relay={via} relay={fallback}")),
        "{v3}"
    );
    for absent in ["via=", "inet=", "lan="] {
        assert!(!v3.contains(absent), "{v3}");
    }
    assert_eq!(card(&["--compat"], true), today);
    assert_eq!(card(&["--compat"], false), today);
    assert!(card(&["--lan", "192.168.1.20:7420"], true).starts_with("raven-card/2 "));

    let dir = short_dir();
    plant_identity(dir.path());
    let mut c = ash(dir.path());
    c.args(["contact", "add", "--card", v3.trim(), "--petname", "Bob"])
        .env("RAVEN_LAB_TEST_A", "1");
    let o = run(c, "");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        out.contains(
            "This card carries no address of Bob: Raven learns how to reach them when you \
             first connect (through their relays)"
        ),
        "{out}"
    );
    let book = std::fs::read_to_string(dir.path().join("contacts.json")).unwrap();
    let rows: serde_json::Value = serde_json::from_str(&book).unwrap();
    let bob = Identity::from_seed(&[0x42; 32]);
    assert_eq!(rows[0]["p2p"], raven_core::p2p_route::local_peer_id(&bob));
    assert_eq!(rows[0]["p2p_via"], serde_json::json!([via, fallback]));
    assert!(rows[0].get("lan_dial").is_none_or(|v| v == ""), "{book}");
    assert!(rows[0].get("internet_dial").is_none(), "{book}");
}

/// Outside the lab (a release build, or a debug build without the lab
/// unlock) a card carries no unsigned route: `raven whoami --card` prints
/// the key (and `onion=` once Tor is up) and refuses `--inet` and `--via`;
/// `raven contact add --card` keeps a lab card's key and LAN address, takes
/// none of its Internet or p2p routes and says so in one line on stderr.
#[test]
fn cards_carry_no_unsigned_routes_outside_the_lab() {
    let bob_dir = short_dir();
    plant_identity_seed(bob_dir.path(), 0x44);
    let relay = raven_core::p2p_route::local_peer_id(&Identity::from_seed(&[0x45; 32]));
    let via = format!("/ip4/198.51.100.7/tcp/7423/p2p/{relay}");
    let whoami = |extra: &[&str], lab: bool| {
        let mut c = ash(bob_dir.path());
        c.args(["whoami", "--card"]).args(extra);
        if lab {
            c.env("RAVEN_LAB_TEST_A", "1");
        } else {
            c.env_remove("RAVEN_LAB_TEST_A");
        }
        run(c, "")
    };
    let plain = whoami(&[], false);
    assert_eq!(code(&plain), 0, "{}", text(&plain.stderr));
    let card = text(&plain.stdout);
    assert!(card.starts_with("raven-card/1 "), "{card}");
    for absent in ["inet=", "p2p=", "via=", "relay=", "lan="] {
        assert!(!card.contains(absent), "{card}");
    }
    for (flag, value) in [("--inet", "203.0.113.7:7422"), ("--via", via.as_str())] {
        let o = whoami(&[flag, value], false);
        assert_eq!(code(&o), 1, "{flag}: {}", text(&o.stdout));
        assert!(
            text(&o.stderr).contains(&format!(
                "{flag}: a card carries no Internet or p2p address in this raven"
            )),
            "{}",
            text(&o.stderr)
        );
        assert!(text(&o.stdout).is_empty());
    }
    // The LAN address the user puts in stays (kept to the local network).
    let lan = whoami(&["--lan", "192.168.1.20:7420"], false);
    assert!(text(&lan.stdout).contains(" lan=192.168.1.20:7420"));

    // A lab card with every route, read outside the lab.
    let lab_card = text(
        &whoami(
            &[
                "--inet",
                "203.0.113.7:7422",
                "--lan",
                "192.168.1.20:7420",
                "--via",
                &via,
            ],
            true,
        )
        .stdout,
    );
    assert!(
        lab_card.contains(" inet=") && lab_card.contains(" via="),
        "{lab_card}"
    );
    let dir = short_dir();
    plant_identity(dir.path());
    let mut c = ash(dir.path());
    c.args([
        "contact",
        "add",
        "--card",
        lab_card.trim(),
        "--petname",
        "Bob",
    ])
    .env_remove("RAVEN_LAB_TEST_A");
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let err = text(&o.stderr);
    assert_eq!(
        err.matches(
            "note: Raven ignored this card's inet=, p2p= and via=: no key signs a card's \
                     addresses, so Raven never dials one"
        )
        .count(),
        1,
        "{err}"
    );
    let book = std::fs::read_to_string(dir.path().join("contacts.json")).unwrap();
    let rows: serde_json::Value = serde_json::from_str(&book).unwrap();
    assert_eq!(rows[0]["lan_dial"], "192.168.1.20:7420", "{book}");
    assert!(
        rows[0].get("internet_dial").is_none_or(|v| v == ""),
        "{book}"
    );
    assert!(rows[0].get("p2p").is_none_or(|v| v == ""), "{book}");
    assert!(
        rows[0]
            .get("p2p_via")
            .is_none_or(|v| v == &serde_json::json!([])),
        "{book}"
    );
    // Its network ID for a relay operator, on request.
    let mut c = ash(bob_dir.path());
    c.args(["whoami", "--peer-id"]);
    let id = run(c, "");
    assert_eq!(
        text(&id.stdout).trim(),
        raven_core::p2p_route::local_peer_id(&Identity::from_seed(&[0x44; 32]))
    );
}

/// `raven contact hide-ip` and `raven node hide-ip` say what they change,
/// and `raven status` shows it (no row while nothing is hidden and the route
/// hints switch is off, so today's status is unchanged).
#[test]
fn hide_ip_commands_say_what_they_do_and_status_shows_the_row() {
    let dir = short_dir();
    plant_identity(dir.path());
    add_bob(dir.path(), "Bob");
    let status = || {
        let mut c = ash(dir.path());
        c.arg("status").env("RAVEN_LAB_ROUTE_HINTS", "0");
        text(&run(c, "").stdout)
    };
    assert!(!status().contains("hide my IP"));
    let o = ash_out(dir.path(), &["contact", "hide-ip", "Bob", "on"], "");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        out.contains(
            "Bob will reach you only through your relays: Raven stops telling Bob your IP \
             address and turns off direct connections with Bob."
        ),
        "{out}"
    );
    assert!(
        out.contains("Same-network (LAN) links are not affected."),
        "{out}"
    );
    assert!(status().contains("  hide my IP    off (1 contact hidden)"));
    let o = ash_out(dir.path(), &["node", "hide-ip", "on"], "");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        out.contains("Your contacts will reach you only through your relays"),
        "{out}"
    );
    assert!(status().contains("  hide my IP    on (every contact)"));
    let o = ash_out(dir.path(), &["contact", "hide-ip", "Nobody", "on"], "");
    assert_eq!(code(&o), 1, "{}", text(&o.stdout));
}

/// Field test E3 (major): `raven status` printed the profile's 10
/// security words, and status is what people paste into bug reports. The
/// words belong to the verify flow: `raven whoami --words` shows them on
/// request; `whoami`, `status`, `doctor` and `whoami --json` never do.
#[test]
fn whoami_shows_the_security_words_only_on_request_and_keeps_the_fingerprint_and_card() {
    let dir = short_dir();
    plant_identity_seed(dir.path(), 0x42);
    let bob = Identity::from_seed(&[0x42; 32]);
    let key = bob.public_key_bytes();
    let fp = raven_core::fingerprint::device_fingerprint_v1(&key);
    let words = raven_core::security_words::words_v1(&key);
    let o = ash_out(dir.path(), &["whoami"], "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let out = text(&o.stdout);
    // Field test E3 round 2: no key in hex by default (the invite holds it
    // for a friend; --verbose and --json show it).
    let want = format!(
        "  address       {}\n  fingerprint   {fp}\ninvite        raven:{}:{}\n",
        bob.address(),
        bob.address(),
        pub_hex(&bob)
    );
    assert!(out.starts_with(&want), "{out}");
    assert!(!out.contains("pub_hex"), "{out}");
    for args in [
        &["whoami"][..],
        &["status"],
        &["doctor"],
        &["whoami", "--json"],
    ] {
        let o = ash_out(dir.path(), args, "");
        let all = format!("{}{}", text(&o.stdout), text(&o.stderr));
        // One word may be an ordinary English word; the ten in a row are
        // the leak.
        assert!(!all.contains(&words.join(" ")), "{args:?}: {all}");
        assert!(!all.contains("security_words"), "{args:?}: {all}");
    }
    let o = ash_out(dir.path(), &["whoami", "--words"], "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(
        out.starts_with(&format!("  words         {}\n", words.join(" "))),
        "{out}"
    );
    assert!(out.contains("Don't send them with your invite"), "{out}");

    let o = ash_out(dir.path(), &["whoami", "--json", "--words"], "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let json: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(json["fingerprint"], fp.as_str());
    assert_eq!(json["security_words"]["version"], 1);
    assert_eq!(
        json["security_words"]["words"],
        serde_json::json!(words.to_vec())
    );

    // The card does not change: no words in it.
    let o = ash_out(dir.path(), &["whoami", "--card"], "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert_eq!(
        text(&o.stdout),
        format!(
            "raven-card/1 address={} pub_hex={} fingerprint={fp}\n",
            bob.address(),
            pub_hex(&bob)
        )
    );
}

#[test]
fn a_pasted_whoami_with_its_words_line_adds_the_friend_under_the_right_name() {
    // Bob's whole `ash whoami` output, pasted into Alice's guided add.
    let bob_dir = short_dir();
    plant_identity_seed(bob_dir.path(), 0x42);
    // An older Raven's whoami block had a words line: pasted whole, it is
    // still skipped as a leftover.
    let o = ash_out(bob_dir.path(), &["whoami"], "");
    let words_line = text(&ash_out(bob_dir.path(), &["whoami", "--words"], "").stdout)
        .lines()
        .next()
        .unwrap()
        .to_string();
    let mut whoami = text(&o.stdout);
    whoami.insert_str(
        whoami.find("invite").expect("the invite line"),
        &format!("{words_line}\n"),
    );
    assert!(whoami.contains("  words  "), "{whoami}");

    let dir = short_dir();
    plant_identity(dir.path());
    let o = ash_out(
        dir.path(),
        &[],
        &format!("5\na\n{whoami}\nFriend\n\nc\n\nq\n"),
    );
    let out = text(&o.stdout);
    assert!(out.contains("contact saved: Friend"), "{out}");
    // The check is blind: Bob's words and code are not shown before it.
    let bob = Identity::from_seed(&[0x42; 32]);
    let words = raven_core::security_words::words_v1(&bob.public_key_bytes()).join(" ");
    let asked = out.find("Check it's really Friend").expect("the blind ask");
    let fp = raven_core::fingerprint::device_fingerprint_v1(&bob.public_key_bytes());
    assert!(!out[asked..].contains(&words), "{out}");
    let saved_at = out.find("contact saved").unwrap();
    assert!(!out[asked..saved_at].contains(&fp), "{out}");
    let book = std::fs::read_to_string(dir.path().join("contacts.json")).unwrap();
    assert!(book.contains("\"petname\": \"Friend\""), "{book}");
    assert!(book.contains("\"pinned\": false"), "{book}");
}

#[test]
fn your_own_identity_is_refused_in_the_guided_add_and_flagged_on_the_command_line() {
    let dir = short_dir();
    plant_identity(dir.path());
    let me = Identity::from_seed(&[0x5a; 32]);

    // Command line: scripts add the profile's own key on purpose, so it is saved,
    // but the person is told.
    let mut c = ash(dir.path());
    c.args(["contact", "add", "--address", &me.address()])
        .args(["--pub-hex", &pub_hex(&me), "--petname", "Me"]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        text(&o.stdout).contains("contact saved"),
        "{}",
        text(&o.stdout)
    );
    assert!(
        text(&o.stderr).contains("YOUR OWN identity"),
        "{}",
        text(&o.stderr)
    );

    // Guided add (menu 5, a, paste): refused, nothing saved.
    let fresh = short_dir();
    plant_identity(fresh.path());
    let invite = format!("raven:{}:{}", me.address(), pub_hex(&me));
    let o = ash_out(
        fresh.path(),
        &[],
        &format!("5\na\n{invite}\nFriend\nc\n\nq\n"),
    );
    let both = format!("{}{}", text(&o.stdout), text(&o.stderr));
    assert!(both.contains("That is YOUR OWN invite"), "{both}");
    assert!(!both.contains("contact saved"), "{both}");
    assert!(!fresh.path().join("contacts.json").exists());

    // Another key through the same menu still saves.
    let bob = Identity::from_seed(&[0x42; 32]);
    let invite = format!("raven:{}:{}", bob.address(), pub_hex(&bob));
    let o = ash_out(
        fresh.path(),
        &[],
        &format!("5\na\n{invite}\nFriend\nc\n\nq\n"),
    );
    let both = format!("{}{}", text(&o.stdout), text(&o.stderr));
    assert!(both.contains("contact saved"), "{both}");
    assert!(fresh.path().join("contacts.json").exists());
}

#[test]
fn send_contact_finds_a_person_by_petname_like_the_picker_does() {
    let dir = short_dir();
    plant_identity(dir.path());
    add_bob(dir.path(), "Bob");

    // Petname in any case: the contact is FOUND (it has no address yet, which is
    // a different, later error) — before this, only an @tag worked.
    for name in ["Bob", "bob", "BOB"] {
        let o = ash_out(dir.path(), &["send", "--contact", name], "hello\n");
        let err = text(&o.stderr);
        assert_eq!(code(&o), 1, "{err}");
        assert!(!err.contains("no contact for"), "{name}: {err}");
        assert!(
            err.contains("contact Bob has no reachable lan_dial"),
            "{name}: {err}"
        );
        assert!(
            !text(&o.stdout).contains("delivered"),
            "{}",
            text(&o.stdout)
        );
    }
    // The chat finds the same person.
    let o = ash_out(dir.path(), &["send", "--chat", "--contact", "bob"], "");
    let err = text(&o.stderr);
    assert!(!err.contains("no contact for"), "{err}");
    assert!(
        err.contains("contact Bob has no reachable lan_dial"),
        "{err}"
    );

    // Nobody by that name: say who exists and how to name them.
    let o = ash_out(dir.path(), &["send", "--contact", "Zed"], "hello\n");
    let err = text(&o.stderr);
    assert_eq!(code(&o), 1);
    assert!(
        err.contains("no contact for Zed. Your contacts: Bob."),
        "{err}"
    );
    assert!(err.contains("--contact NAME or --contact @tag"), "{err}");
    // A lone @ still reaches nobody, not the untagged contact.
    let o = ash_out(dir.path(), &["send", "--contact", "@"], "hello\n");
    assert_eq!(code(&o), 1);
    assert!(
        text(&o.stderr).contains("no contact for @"),
        "{}",
        text(&o.stderr)
    );
}

#[test]
fn the_send_picker_says_it_sends_one_message_and_where_a_live_chat_is() {
    let dir = short_dir();
    plant_identity(dir.path());
    add_bob(dir.path(), "Bob");
    // Menu 1, a blank pick (back to the menu), quit.
    let o = ash_out(dir.path(), &[], "1\n\nq\n");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        out.contains("Pick a contact by number, @tag or petname"),
        "{out}"
    );
    assert!(
        out.contains("This sends one message. For a live chat: ash send --contact NAME --chat"),
        "{out}"
    );
    assert!(out.contains("fly safe"), "{out}");
}

// ── why contacts cannot be reached (the diagnosis) ──────────────────────────

/// `people` as this profile's contacts (`pinned`: verified), written
/// directly; their keys are `Identity::from_seed(&[seed; 32])`.
fn plant_book(dir: &Path, people: &[(&str, u8, bool)]) -> Vec<Identity> {
    let ids: Vec<Identity> = people
        .iter()
        .map(|(_, seed, _)| Identity::from_seed(&[*seed; 32]))
        .collect();
    let rows: Vec<serde_json::Value> = people
        .iter()
        .zip(&ids)
        .map(|((name, _, pinned), id)| {
            serde_json::json!({
                "petname": name, "public_tag": "", "alias": "", "address": id.address(),
                "pub_hex": pub_hex(id), "pinned": pinned, "lan_dial": "",
            })
        })
        .collect();
    std::fs::write(
        dir.join("contacts.json"),
        serde_json::Value::Array(rows).to_string(),
    )
    .unwrap();
    ids
}

/// A running p2p host of class `reach`, nothing else known.
fn host(reach: &str) -> P2pStatusInfo {
    P2pStatusInfo {
        up: true,
        peer_id: "12D3KooWFakeHostPeerIdForUxScreens".into(),
        nat: "unknown".into(),
        reach: reach.into(),
        upnp: "unset".into(),
        listen_setting: "7423".into(),
        ..P2pStatusInfo::default()
    }
}

fn why(id: &Identity, reason: &str, age_s: u64) -> ContactWhy {
    ContactWhy {
        peer_pub_hex: pub_hex(id),
        reason: reason.into(),
        age_s,
    }
}

/// One live message in raven-node's outbox for `id`.
fn waiting(id: &Identity, n: u8, why: &str) -> OutboxItem {
    OutboxItem {
        message_id_hex: format!("{n:02x}").repeat(16),
        peer_pub_hex: pub_hex(id),
        kind: "message".into(),
        state: "queued".into(),
        carrier: "p2p_dial".into(),
        attempts: 2,
        last_error_code: "NOT_REACHABLE".into(),
        why: why.into(),
        ..OutboxItem::default()
    }
}

/// `ash <args>` against a faked node reporting `fake`.
fn with_node(dir: &Path, fake: Fake, args: &[&str]) -> String {
    with_node_cmd(dir, fake, ash(dir), args)
}

/// [`with_node`] with learned custody off whatever the suite's switches:
/// without route hints `custody_hints_live` is false, so an unreachable
/// contact's next step never offers friend mailboxes (Phase 3 P3.23; the
/// mailbox fix itself is tested in ash's unit tests, which set the gate per
/// thread).
fn with_node_no_custody(dir: &Path, fake: Fake, args: &[&str]) -> String {
    let mut c = ash(dir);
    c.env("RAVEN_LAB_ROUTE_HINTS", "0");
    with_node_cmd(dir, fake, c, args)
}

fn with_node_cmd(dir: &Path, fake: Fake, mut c: Command, args: &[&str]) -> String {
    let node = FakeNode::start_with(dir, &["ipc", "lan_direct", "bridge", "store"], fake);
    c.args(args);
    let o = run(c, "");
    drop(node);
    let _ = std::fs::remove_file(raven_core::default_socket_path(dir));
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    text(&o.stdout)
}

/// No contact key (64 hex) anywhere, and no PeerId in the reachability
/// sections (`p2p_peer` is this node's own).
fn assert_no_keys(out: &str, ids: &[Identity]) {
    for id in ids {
        assert!(!out.contains(&pub_hex(id)), "{out}");
    }
    for title in ["REACHABILITY", "NOT REACHABLE NOW", "SUMMARY"] {
        for line in section(out, title) {
            assert!(!line.contains("12D3KooW"), "{line}");
        }
    }
    for line in out.lines().filter(|l| {
        [
            "  reach_",
            "  unreachable_",
            "  internet_route",
            "  why ",
            "  what to do",
        ]
        .iter()
        .any(|k| l.starts_with(k))
    }) {
        assert!(!line.contains("12D3KooW"), "{line}");
    }
}

/// The section after the line starting with `title`, up to the next blank
/// line.
fn section<'a>(out: &'a str, title: &str) -> Vec<&'a str> {
    out.lines()
        .skip_while(|l| !l.starts_with(title))
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .collect()
}

#[test]
fn status_names_who_cannot_be_reached_and_why() {
    let dir = short_dir();
    plant_identity(dir.path());
    let ids = plant_book(dir.path(), &[("Bob", 0x42, true), ("Carol", 0x43, true)]);
    let (bob, carol) = (&ids[0], &ids[1]);
    let both_nat = "reach: why=both_nat me=unreachable";
    let fake = Fake {
        p2p: Some(host("unreachable")),
        unreachable: vec![
            why(bob, both_nat, 180),
            why(
                carol,
                "reach: why=contact_offline me=unreachable heard=3h",
                30,
            ),
            why(&Identity::from_seed(&[0x44; 32]), both_nat, 5),
        ],
        outbox: vec![waiting(bob, 1, both_nat), waiting(bob, 2, both_nat)],
        ..Fake::default()
    };
    let out = with_node(dir.path(), fake, &["status"]);
    let rows = section(&out, "NOT REACHABLE NOW");
    assert_eq!(
        rows[..3],
        [
            "  (why the last try failed; since raven-node started)",
            "  Bob           no path \u{2014} you and Bob are both behind NAT, and Bob uses no \
             relay; 2 messages waiting, 3 min ago",
            "  Carol         offline \u{2014} Carol's computer is not connected to its relay; \
             last heard 3 h ago, 30 s ago",
        ],
        "{out}"
    );
    assert!(
        rows[3].starts_with(
            "  what to do    nobody in your circle can be reached from the internet, so nothing \
             can carry messages between two computers behind NAT. Any one of these fixes it:"
        ),
        "{out}"
    );
    assert_eq!(rows.len(), 4, "a stranger's row is skipped: {out}");
    assert_no_keys(&out, &ids);
}

#[test]
fn status_circle_row_says_nobody_is_reachable() {
    let dir = short_dir();
    plant_identity(dir.path());
    let ids = plant_book(dir.path(), &[("Bob", 0x42, true)]);
    let fake = Fake {
        p2p: Some(host("unreachable")),
        ..Fake::default()
    };
    let out = with_node(dir.path(), fake, &["status"]);
    let rows = section(&out, "REACHABILITY");
    assert!(
        rows.contains(
            &"  circle        nobody in your circle can be reached from the internet yet (no \
              relay offers, no contact with a public address)"
        ),
        "{out}"
    );
    assert!(
        rows.iter().any(|r| r
            .starts_with("  what to do    nobody in your circle can be reached from the internet, so nobody outside this network can reach you.")),
        "{out}"
    );
    assert!(!out.contains("NOT REACHABLE NOW"), "{out}");
    assert_no_keys(&out, &ids);
}

#[test]
fn status_w1_names_the_sleeping_relays_owner() {
    let dir = short_dir();
    plant_identity(dir.path());
    let ids = plant_book(dir.path(), &[("Bob", 0x42, true), ("Carol", 0x43, true)]);
    let mut info = host("unreachable");
    info.relay_health = vec![RelayHealth {
        relay: "/ip4/198.51.100.7/tcp/7427/p2p/12D3KooWFakeRelayPeerId".into(),
        state: "retrying".into(),
        tries: 3,
        retry_in_s: Some(20),
        source: "offer".into(),
        operator_pub_hex: pub_hex(&ids[1]),
        ..RelayHealth::default()
    }];
    info.relay_auto = true;
    let fake = Fake {
        p2p: Some(info),
        ..Fake::default()
    };
    let out = with_node(dir.path(), fake, &["status"]);
    let rows = section(&out, "REACHABILITY");
    assert!(
        rows.contains(
            &"  relay 1       NOT reserved yet \u{2014} Carol's relay (198.51.100.7:7427); next try \
              in 20 s (3 failed)"
        ),
        "{out}"
    );
    assert!(
        rows.contains(
            &"  what to do    Carol's relay is not answering (asleep or switched off?), so \
              contacts outside this network cannot reach you. Ask Carol to wake that computer \
              (`raven relay status` on it shows whether the relay runs); raven-node keeps trying."
        ),
        "{out}"
    );
    assert_no_keys(&out, &ids);
}

/// Phase 4 (P4.16): `status` says when the relay rides WebSocket/TLS
/// through the HTTPS proxy on a restricted network, and names what keeps
/// relays away (a proxy script, Windows sign-in) in the `p2p` row and as
/// the doctor's next step. `node proxy` shows the saved setting and what
/// the running raven-node uses, saves one, and refuses a password without
/// repeating it.
#[test]
fn status_doctor_and_node_proxy_name_the_wss_relay_and_the_proxy() {
    let dir = short_dir();
    plant_identity(dir.path());
    let ids = plant_book(dir.path(), &[("Bob", 0x42, true)]);
    let relay = "/ip4/198.51.100.7/tcp/443/p2p/12D3KooWFakeRelayPeerId";
    let mut wss = host("relayed");
    wss.reservations = vec![relay.into()];
    wss.relays_configured = 1;
    wss.relay_health = vec![RelayHealth {
        relay: relay.into(),
        state: "reserved".into(),
        ..RelayHealth::default()
    }];
    wss.relay_paths = vec!["wss-proxy".into()];
    wss.restricted = true;
    wss.proxy = "env".into();
    wss.proxy_source = "node_policy.json".into();
    let fake = |p2p: &P2pStatusInfo| Fake {
        p2p: Some(p2p.clone()),
        ..Fake::default()
    };
    let out = with_node(dir.path(), fake(&wss), &["status"]);
    assert!(
        out.contains(
            "reservations 1/1; relay over WSS through the HTTPS proxy; restricted network (relay \
             only))"
        ),
        "{out}"
    );
    let shown = with_node(dir.path(), fake(&wss), &["node", "proxy"]);
    assert_eq!(
        shown.lines().take(2).collect::<Vec<_>>(),
        [
            "saved       auto (HTTPS_PROXY, then the system settings)",
            "raven-node  uses the setting from node_policy.json; relay dials over WebSocket/TLS \
             go through the proxy in its environment (HTTPS_PROXY or ALL_PROXY)",
        ],
        "{shown}"
    );

    // A proxy script, then a proxy that wants Windows sign-in.
    let mut pac = host("unreachable");
    pac.relays_configured = 1;
    pac.relay_health = vec![RelayHealth {
        relay: relay.into(),
        state: "retrying".into(),
        tries: 3,
        retry_in_s: Some(20),
        ..RelayHealth::default()
    }];
    pac.proxy = "unsupported: pac".into();
    pac.proxy_source = "node_policy.json".into();
    let pac_text = "your system uses a proxy script (PAC), which Raven cannot read: `raven node \
                    proxy http://host:port`";
    let out = with_node(dir.path(), fake(&pac), &["status"]);
    assert!(out.contains(&format!("; {pac_text})")), "{out}");
    let doctor = with_node(dir.path(), fake(&pac), &["doctor"]);
    assert_eq!(
        doctor.trim_end().lines().last().unwrap(),
        format!("Next step: {pac_text}"),
        "{doctor}"
    );
    let mut ntlm = pac.clone();
    ntlm.proxy = "setting".into();
    ntlm.proxy_auth = "unsupported".into();
    let sign_in = "the HTTPS proxy needs Windows sign-in (NTLM/Kerberos), not supported";
    let doctor = with_node(dir.path(), fake(&ntlm), &["doctor"]);
    assert_eq!(
        doctor.trim_end().lines().last().unwrap(),
        format!("Next step: {sign_in}"),
        "{doctor}"
    );
    let shown = with_node(dir.path(), fake(&ntlm), &["node", "proxy"]);
    assert!(shown.contains(&format!("note: {sign_in}")), "{shown}");
    assert_no_keys(&doctor, &ids);

    // Saved; a password is refused and never repeated.
    let o = ash_out(
        dir.path(),
        &["node", "proxy", "http://alice:pw5ecret@proxy.example:3128"],
        "",
    );
    assert_eq!(code(&o), 1);
    let err = text(&o.stderr);
    assert!(
        err.contains(
            "set them in the service's RAVEN_P2P_PROXY; node_policy.json holds no secrets"
        ),
        "{err}"
    );
    assert!(
        !err.contains("pw5ecret") && !text(&o.stdout).contains("pw5ecret"),
        "{err}"
    );
    let o = ash_out(
        dir.path(),
        &["node", "proxy", "http://proxy.example:3128"],
        "",
    );
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        text(&o.stdout).starts_with("ok proxy=http://proxy.example:3128 saved in "),
        "{}",
        text(&o.stdout)
    );
    let o = ash_out(dir.path(), &["node", "proxy"], "");
    assert!(
        text(&o.stdout).starts_with("saved       http://proxy.example:3128\n"),
        "{}",
        text(&o.stdout)
    );
}

/// Cutoff pack CP.7: a contact whose clock raven-node saw ahead of ours gets
/// a `clocks` row (by name, never by key), and `ash doctor` counts them.
#[test]
fn status_says_whose_clock_runs_ahead() {
    let dir = short_dir();
    plant_identity(dir.path());
    let ids = plant_book(dir.path(), &[("Bob", 0x42, true)]);
    let fake = Fake {
        clock_skew: vec![
            ContactSkew {
                peer_pub_hex: pub_hex(&ids[0]),
                minutes: 10,
                at_least: false,
            },
            ContactSkew {
                peer_pub_hex: "ee".repeat(32),
                minutes: 30,
                at_least: false,
            },
        ],
        ..Fake::default()
    };
    let out = with_node(dir.path(), fake.clone(), &["status"]);
    assert!(
        out.contains(
            "  clocks        Bob's clock is about 10 min ahead of yours: messages from Bob are \
             refused until the clocks agree. Check the time and time zone on both laptops."
        ),
        "{out}"
    );
    assert_eq!(out.matches("clock is about").count(), 1, "{out}");
    assert_no_keys(&out, &ids);
    let doctor = with_node(dir.path(), fake, &["doctor"]);
    assert!(doctor.contains("  clock_skew_contacts: 2"), "{doctor}");
    let quiet = with_node(dir.path(), Fake::default(), &["status"]);
    assert!(!quiet.contains("clocks"), "{quiet}");
}

/// Phase 3 P3.C3 (F11b): the LAN beacon's clock estimate (a contact an
/// epoch or more behind) is a `clocks` row of `raven status`, and the
/// contacts its search asked for in vain are named in the nearby search row
/// of `raven status`, `raven doctor` and `raven lan status`, with the clock
/// hint; by name, never by key.
#[test]
fn status_names_the_contacts_the_nearby_search_got_no_answer_from() {
    let dir = short_dir();
    plant_identity(dir.path());
    let ids = plant_book(dir.path(), &[("Bob", 0x42, true), ("Carol", 0x43, true)]);
    let mut lan = lan("on", &["0.0.0.0:7420"], true);
    lan.as_mut().unwrap().beacon = Some(Box::new(BeaconCounts {
        state: "on".into(),
        interfaces: 1,
        echo_ok: true,
        queries_10m: 3,
        no_answer: vec![pub_hex(&ids[0]), "ee".repeat(32)],
        ..BeaconCounts::default()
    }));
    let fake = Fake {
        lan_listen: Some("0.0.0.0:7420".into()),
        lan,
        clock_skew: vec![ContactSkew {
            peer_pub_hex: pub_hex(&ids[1]),
            minutes: -10,
            at_least: true,
        }],
        ..Fake::default()
    };
    let node = FakeNode::start_with(dir.path(), &["ipc", "lan_direct"], fake);
    let status = ash_out(dir.path(), &["status"], "");
    let doctor = ash_out(dir.path(), &["doctor"], "");
    let lan_status = ash_out(dir.path(), &["lan", "status"], "");
    drop(node);
    // While pair seeds are live (the child inherits this run's switches),
    // the hint also names a lost pair seed (Phase 6 review traffic-7).
    let seeds = if raven_core::pair_seed::live() {
        ", or that Bob's Raven still has your pair's changing key (the next connection between \
         you agrees on a new one)"
    } else {
        ""
    };
    let row = format!(
        "  {:<14}on (answers only your contacts); last 10 min: 3 sent, 0 answered; no answer \
         from Bob; if Bob is here, check that both laptops show the same time{seeds}\n",
        "LAN search"
    );
    for out in [&status, &doctor, &lan_status] {
        let out = text(&out.stdout);
        assert!(out.contains(&row), "{out}");
        assert_no_keys(&out, &ids);
    }
    let status = text(&status.stdout);
    assert!(
        status.contains(
            "  clocks        Carol's clock is about 10 min or more behind yours: Carol refuses \
             your messages until the clocks agree. Check the time and time zone on both laptops."
        ),
        "{status}"
    );
    assert!(
        text(&doctor.stdout).contains("  clock_skew_contacts: 1"),
        "{}",
        text(&doctor.stdout)
    );
}

#[test]
fn doctor_counts_the_unreachable_and_ends_with_the_circle_fix() {
    let dir = short_dir();
    plant_identity(dir.path());
    let ids = plant_book(dir.path(), &[("Bob", 0x42, true), ("Carol", 0x43, true)]);
    let fake = Fake {
        p2p: Some(host("unknown")),
        unreachable: vec![
            why(&ids[0], "reach: why=both_nat me=unknown", 60),
            why(&ids[1], "reach: why=contact_offline me=unknown", 60),
        ],
        ..Fake::default()
    };
    let out = with_node(dir.path(), fake, &["doctor"]);
    assert!(
        out.contains("  cannot reach  2 contacts over the internet (raven status says why)"),
        "{out}"
    );
    assert!(
        out.contains(
            "  reach_circle: relay_offers=0 relays_in_use=0 reachable_contacts=0 p2p_contacts=0"
        ),
        "{out}"
    );
    assert!(
        out.contains(
            "  unreachable_contacts: 2 (raven status names them) contact_offline=1 both_nat=1"
        ),
        "{out}"
    );
    assert!(!out.contains("internet_route"), "{out}");
    let last = out.trim_end().lines().last().unwrap();
    assert!(
        last.starts_with(
            "Next step: nobody in your circle can be reached from the internet, so nothing can \
             carry messages between two computers behind NAT."
        ),
        "{out}"
    );
    assert_no_keys(&out, &ids);
}

#[test]
fn outbox_list_says_why_a_p2p_message_waits() {
    let dir = short_dir();
    plant_identity(dir.path());
    let ids = plant_book(dir.path(), &[("Bob", 0x42, true)]);
    let item = waiting(&ids[0], 7, "reach: why=both_nat me=unreachable");
    let fake = Fake {
        p2p: Some(host("unreachable")),
        outbox: vec![item.clone(), waiting(&ids[0], 8, "")],
        ..Fake::default()
    };
    let out = with_node(dir.path(), fake.clone(), &["outbox", "list"]);
    let lines: Vec<&str> = out.lines().filter(|l| l.contains("  last: ")).collect();
    assert_eq!(lines.len(), 2, "{out}");
    assert!(
        lines[0].contains("message to Bob  attempts 2  last: both behind NAT, no relay"),
        "{out}"
    );
    // No reason: the code's words (E1: never the code itself).
    assert!(
        lines[1].contains("last: Bob's computer couldn't be reached"),
        "no reason, the code's words: {out}"
    );
    assert!(!out.contains("NOT_REACHABLE"), "{out}");

    let out = with_node(
        dir.path(),
        fake,
        &["outbox", "status", &item.message_id_hex[..8]],
    );
    let rows: Vec<&str> = out.lines().collect();
    let at = rows
        .iter()
        .position(|r| r.starts_with("  last error  both behind NAT, no relay (NOT_REACHABLE)"))
        .unwrap_or_else(|| panic!("{out}"));
    assert!(
        rows[at + 1].starts_with("  why         you and Bob are both behind NAT"),
        "{out}"
    );
    assert!(
        rows[at + 2]
            .starts_with("  what to do  Nobody in your circle can be reached from the internet"),
        "{out}"
    );
    assert!(!out.contains("send again"), "{out}");
    assert_no_keys(&out, &ids);
}

/// A release build runs no p2p host (`p2p: None`): `raven status` has no
/// REACHABILITY or NOT REACHABLE NOW section, whatever else is reported.
#[test]
fn a_release_like_status_has_no_reach_sections() {
    let dir = short_dir();
    plant_identity(dir.path());
    let ids = plant_book(dir.path(), &[("Bob", 0x42, true)]);
    let fake = Fake {
        unreachable: vec![why(&ids[0], "reach: why=both_nat", 5)],
        ..Fake::default()
    };
    let out = with_node(dir.path(), fake, &["status"]);
    for word in [
        "REACHABILITY",
        "NOT REACHABLE NOW",
        "circle  ",
        "behind NAT",
    ] {
        assert!(!out.contains(word), "{word:?} in {out}");
    }
    assert!(out.contains("receiving     YES"), "{out}");
    assert!(
        status_body(&out).ends_with("You can send and receive."),
        "{out}"
    );
    let doctor = with_node(dir.path(), Fake::default(), &["doctor"]);
    assert!(!doctor.contains("cannot reach"), "{doctor}");
    assert!(!doctor.contains("unreachable_contacts"), "{doctor}");
    assert!(
        doctor.contains("reach_class: off (p2p host not running)"),
        "{doctor}"
    );
}

/// Without a route to the internet: W0 in REACHABILITY, one row for every
/// contact in NOT REACHABLE NOW, and no internet-side fix anywhere.
#[test]
fn status_without_a_route_says_so_once() {
    let dir = short_dir();
    plant_identity(dir.path());
    let ids = plant_book(dir.path(), &[("Bob", 0x42, true), ("Carol", 0x43, true)]);
    let fake = Fake {
        p2p: Some(host("unreachable")),
        egress: Some(false),
        unreachable: vec![
            why(&ids[0], "reach: why=no_route me=unreachable", 20),
            why(&ids[1], "reach: why=no_route me=unreachable heard=1h", 40),
        ],
        outbox: vec![
            waiting(&ids[0], 1, "reach: why=no_route"),
            waiting(&ids[1], 2, "reach: why=no_route"),
        ],
        ..Fake::default()
    };
    let out = with_node(dir.path(), fake, &["status"]);
    let reach = section(&out, "REACHABILITY");
    assert!(
        reach.contains(
            &"  what to do    this computer has no route to the internet right now: contacts \
              outside this network cannot reach you, and nothing on this computer can change \
              that. People on this network (Wi-Fi, hotspot or cable) still can."
        ),
        "{out}"
    );
    let rows = section(&out, "NOT REACHABLE NOW");
    assert_eq!(
        rows,
        [
            "  (why the last try failed; since raven-node started)",
            "  contacts      this computer has no route to the internet: only contacts on this \
             network can be reached (2 messages waiting)",
            "  what to do    nothing to fix from here: messages to people on this network still \
             go; the rest wait.",
        ],
        "{out}"
    );
    for line in reach.iter().chain(&rows) {
        let lower = line.to_ascii_lowercase();
        for word in [
            "relay kit",
            "vps",
            "raspberry pi",
            "raven relay offer",
            "upnp",
            "forward port",
            "public ip",
            "wake",
        ] {
            assert!(!lower.contains(word), "{word:?} in {line}");
        }
    }
    assert_no_keys(&out, &ids);
}

/// Phase 3 P3.C6: the plain offline words, one row per state. `raven
/// status`'s first line while the local network is the only carrier (the
/// friends seen here and what waits), or that this computer is on no network
/// when this host is on none; the `old address` row (M0); and nobody
/// answering here or the local network turned off, in the outbox rows and as
/// the doctor's next step. Never a key or an address.
#[test]
fn plain_offline_words_for_every_lan_state() {
    let dir = short_dir();
    plant_identity(dir.path());
    let ids = plant_book(dir.path(), &[("Bob", 0x42, true), ("Carol", 0x43, true)]);
    // The fake node says 2 friends were seen here (Phase 3 review E-1: a
    // link with only fe80:: then counts).
    let on_a_network = raven_core::netifs::read()
        .ok()
        .map(|all| raven_core::netifs::on_a_network_seen(all, Some(2)));
    let mut lan_row = lan("on", &["0.0.0.0:47311"], true);
    let row = lan_row.as_mut().unwrap();
    row.friends_here_10m = Some(2);
    row.pin_blocked = vec![pub_hex(&ids[1]), "ee".repeat(32)];
    let lan_only = Fake {
        lan_listen: Some("0.0.0.0:47311".into()),
        lan: lan_row,
        ..Fake::default()
    };
    let first = |out: &str| -> String {
        out.lines()
            .skip_while(|l| !l.starts_with("STATUS"))
            .nth(1)
            .unwrap_or_default()
            .to_string()
    };
    let not_here = "This computer isn't on any network. To reach a friend nearby, join the same \
                    Wi-Fi, make a hotspot, or connect a cable. Your messages wait here.";
    let out = with_node(dir.path(), lan_only.clone(), &["status"]);
    if on_a_network == Some(false) {
        assert_eq!(first(&out), not_here, "{out}");
    } else {
        assert_eq!(
            first(&out),
            "Raven works on this network without the internet. Friends seen here in the last 10 \
             min: 2. Waiting messages: 0.",
            "{out}"
        );
    }
    assert!(
        out.lines().any(|l| l
            == "  old address   Something else answered at Carol's old address; RAVEN didn't \
                introduce you."),
        "{out}"
    );
    assert_eq!(out.matches("old address;").count(), 1, "{out}");
    assert_no_keys(&out, &ids);
    // A message waits until a deadline (the session store exists): the
    // same line says so.
    let store = dir
        .path()
        .join(raven_core::indexed_session_store::INDEXED_SESSION_METADATA_FILE);
    std::fs::write(&store, b"").unwrap();
    let mut item = waiting(&ids[0], 1, "");
    item.expires_at_ms = raven_core::clock::now_ms() + 3 * 3_600_000;
    let out = with_node(
        dir.path(),
        Fake {
            outbox: vec![item],
            ..lan_only.clone()
        },
        &["status"],
    );
    if on_a_network != Some(false) {
        let line = first(&out);
        assert!(
            line.starts_with(
                "Raven works on this network without the internet. Friends seen here in the \
                 last 10 min: 2. Waiting messages: 1 (the oldest can wait until "
            ) && line.ends_with(")."),
            "{out}"
        );
    }
    std::fs::remove_file(&store).unwrap();
    // A p2p host runs too: not the local-network-only line.
    let out = with_node(
        dir.path(),
        Fake {
            p2p: Some(host("unknown")),
            ..lan_only
        },
        &["status"],
    );
    assert!(!out.contains("Raven works on this network"), "{out}");

    // Nobody answered here: the outbox rows and the doctor's next step.
    let mut silent = waiting(&ids[0], 3, "reach: why=lan_no_answer");
    silent.carrier = "lan_dial".into();
    let fake = Fake {
        unreachable: vec![why(&ids[0], "reach: why=lan_no_answer", 30)],
        outbox: vec![silent.clone()],
        ..Fake::default()
    };
    let list = with_node_no_custody(dir.path(), fake.clone(), &["outbox", "list"]);
    assert!(
        list.contains("last: none of your friends answered on this network"),
        "{list}"
    );
    let status = with_node_no_custody(
        dir.path(),
        fake.clone(),
        &["outbox", "status", &silent.message_id_hex[..8]],
    );
    let advice = "If you are on the same Wi-Fi, it may keep devices apart (common in hotels and \
                  guest Wi-Fi): make a hotspot instead (docs/OFFLINE_GUIDE.md §3).";
    assert!(
        status.contains(
            "  why         none of your friends answered on this network: RAVEN looked for Bob \
             here and got no answer"
        ),
        "{status}"
    );
    assert!(
        status.contains(&format!(
            "  what to do  {advice} Nothing to do on your side"
        )),
        "{status}"
    );
    let doctor = with_node_no_custody(dir.path(), fake, &["doctor"]);
    assert_eq!(
        doctor.trim_end().lines().last().unwrap(),
        format!("Next step: None of your friends answered on this network. {advice}"),
        "{doctor}"
    );
    assert_no_keys(&doctor, &ids);

    // The local network turned off: the same rows, in its words.
    let mut off = waiting(&ids[0], 4, "reach: why=lan_off");
    off.carrier = "lan_dial".into();
    let fake = Fake {
        unreachable: vec![why(&ids[0], "reach: why=lan_off", 30)],
        outbox: vec![off.clone()],
        ..Fake::default()
    };
    let status = with_node(
        dir.path(),
        fake.clone(),
        &["outbox", "status", &off.message_id_hex[..8]],
    );
    assert!(
        status.contains(
            "  why         you turned the local network off (`raven lan on` turns it on)"
        ),
        "{status}"
    );
    assert!(
        status.contains("  what to do  Your messages wait here."),
        "{status}"
    );
    let doctor = with_node(dir.path(), fake, &["doctor"]);
    assert_eq!(
        doctor.trim_end().lines().last().unwrap(),
        "Next step: You turned the local network off (`raven lan on` turns it on). Your messages \
         wait here.",
        "{doctor}"
    );
}

/// Phase 3 P3.C6: no text of ash says or tests that the internet is down;
/// they say what this computer sees (its networks, who answered, what
/// waits). The no-route sentence (Phase 2) says "no route to the internet",
/// a local fact, and none of these.
#[test]
fn no_text_says_the_internet_is_down() {
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert!(files.len() > 10, "{files:?}");
    let needles = [
        ["internet", "is down"].join(" "),
        ["no internet", "connection"].join(" "),
        ["offline", "network"].join(" "),
    ];
    for file in files {
        // Rust's line continuations join words across lines: read them as
        // one line.
        let text = std::fs::read_to_string(&file).unwrap().to_ascii_lowercase();
        let joined: String = text
            .split_whitespace()
            .map(|w| w.trim_matches('\\'))
            .filter(|w| !w.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        for needle in &needles {
            assert!(
                !joined.contains(needle.as_str()),
                "{needle:?} in {}",
                file.display()
            );
        }
    }
}

// ── what `ash listen` tells a friend ────────────────────────────────────────

/// This profile's service already receives on every IPv4 address: `ash
/// listen` lists every such address of this computer a friend could dial,
/// hotspot first, with the service's port, as raven-core reads them. On no
/// network it says how to get on one. Never a placeholder, on any system.
#[test]
fn listen_tells_the_friend_every_address_of_this_computer() {
    let dir = short_dir();
    plant_identity(dir.path());
    add_bob(dir.path(), "Bob");
    // A free loopback port for the one `ash listen` would use (it is only
    // tried, then left alone: the faked service already receives).
    let asked = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .unwrap()
        .port();
    let fake = Fake {
        lan_listen: Some("0.0.0.0:47311".into()),
        ..Fake::default()
    };
    let node = FakeNode::start_with(dir.path(), &["ipc", "lan_direct"], fake);
    let o = ash_out(
        dir.path(),
        &["listen", "--listen", &format!("127.0.0.1:{asked}")],
        "",
    );
    drop(node);
    let _ = std::fs::remove_file(raven_core::default_socket_path(dir.path()));
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{out}\n{}", text(&o.stderr));
    assert!(
        out.contains("already running and receiving on port 47311"),
        "{out}"
    );
    assert!(!out.contains('<'), "{out}");
    // A listener on 0.0.0.0 takes no IPv6 address.
    let lan: Vec<_> = raven_core::netifs::lan_addresses_for_friends()
        .into_iter()
        .filter(|a| a.ip.is_ipv4())
        .collect();
    let lines: Vec<&str> = out.lines().collect();
    if lan.iter().all(raven_core::netifs::is_virtual) {
        assert!(
            out.contains(
                "This computer isn't on any network right now. Join a Wi-Fi, make a hotspot, \
                 or connect a cable, then run `ash listen` again."
            ),
            "{out}"
        );
        return;
    }
    let at = lines
        .iter()
        .position(|l| *l == "Tell your friend one of these addresses (this computer, port 47311):")
        .unwrap_or_else(|| panic!("no address heading in:\n{out}"));
    let rows = &lines[at + 1..at + 1 + lan.len()];
    for (row, a) in rows.iter().zip(&lan) {
        let dial = std::net::SocketAddr::new(a.ip, 47311).to_string();
        assert!(row.starts_with(&format!("  {dial} ")), "{row:?} for {a:?}");
        assert!(row.trim_end().ends_with(')'), "{row:?}");
    }
    // Every address, and no more rows.
    assert!(
        lines
            .get(at + 1 + lan.len())
            .is_none_or(|l| !l.trim_end().ends_with(')')),
        "{out}"
    );
}

/// Privacy pack PP.8: `raven chats delete` says what it does in its help,
/// asks before deleting (a piped stdin cannot answer: `--yes` is needed, and
/// nothing is deleted), names the person and counts what went, and says that
/// messages still waiting to be sent stay.
#[test]
fn chats_delete_asks_first_and_says_what_stays() {
    let dir = short_dir();
    plant_identity(dir.path());
    let bob = add_bob(dir.path(), "Bob");

    let o = ash_out(dir.path(), &["--help"], "");
    assert!(
        text(&o.stdout).contains("Your chats on this computer"),
        "{}",
        text(&o.stdout)
    );
    let o = ash_out(dir.path(), &["chats", "delete", "--help"], "");
    let help = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    for words in [
        "Delete your chat with one contact on this computer",
        "Your contact keeps their copy",
        "Messages still waiting to be sent stay",
        "raven chats delete --petname Bob",
    ] {
        assert!(help.contains(words), "{words:?} missing: {help}");
    }

    // Not a terminal: the typed answer cannot come, so nothing is deleted.
    let o = ash_out(
        dir.path(),
        &["chats", "delete", "--petname", "Bob"],
        "delete\n",
    );
    assert_eq!(code(&o), 1);
    assert!(
        text(&o.stderr).contains("stdin is not a terminal: pass --yes"),
        "{}",
        text(&o.stderr)
    );
    assert!(!text(&o.stdout).contains("Deleted"), "{}", text(&o.stdout));

    let o = ash_out(
        dir.path(),
        &["chats", "delete", "--petname", "Nobody", "--yes"],
        "",
    );
    assert_eq!(code(&o), 1);
    assert!(
        text(&o.stderr).starts_with("no contact named Nobody"),
        "{}",
        text(&o.stderr)
    );

    let fake = Fake {
        outbox: vec![waiting(&bob, 1, ""), waiting(&bob, 2, "")],
        ..Fake::default()
    };
    let out = with_node(
        dir.path(),
        fake,
        &["chats", "delete", "--petname", "Bob", "--yes"],
    );
    assert!(
        out.contains("Deleted your chat with Bob on this computer (0 messages)."),
        "{out}"
    );
    assert!(
        out.contains(
            "2 messages to Bob are still waiting to be sent. They stay, and they show in your \
             chat again once they are sent."
        ),
        "{out}"
    );
    assert!(out.contains("raven outbox cancel"), "{out}");
}

/// Privacy pack PP.9: `raven chats keep` and `raven chats status` say what
/// they do; a setting it does not know is refused; the setting holds; the
/// next deletion is "not planned yet" until a build that may seal starts
/// the retention clock (a debug build only with `RAVEN_LAB_AT_REST=1`), and
/// then there is nothing old enough to go in a new profile.
#[test]
fn chats_keep_and_status_say_what_they_do() {
    let dir = short_dir();
    plant_identity(dir.path());
    add_bob(dir.path(), "Bob");
    let lab = |args: &[&str], at_rest: bool| {
        let mut c = ash(dir.path());
        c.args(args).env_remove("RAVEN_LAB_RETENTION_GRACE_MS");
        if at_rest {
            c.env("RAVEN_LAB_AT_REST", "1");
        } else {
            c.env_remove("RAVEN_LAB_AT_REST");
        }
        run(c, "")
    };

    let o = lab(&["chats", "--help"], false);
    let help = text(&o.stdout);
    for words in ["keep", "status", "raven chats keep 90d"] {
        assert!(help.contains(words), "{words:?} missing: {help}");
    }
    let o = lab(&["chats", "keep", "--help"], false);
    let help = text(&o.stdout);
    for words in [
        "7d, 30d (the default), 90d or always",
        "your friends' copies aren't",
        "Messages still waiting to be sent are never deleted",
    ] {
        assert!(help.contains(words), "{words:?} missing: {help}");
    }

    let o = lab(&["chats", "keep", "365d"], false);
    assert_eq!(code(&o), 2, "{}", text(&o.stderr));
    assert!(
        text(&o.stderr).contains("possible values"),
        "{}",
        text(&o.stderr)
    );

    let o = lab(&["chats", "keep", "7d"], false);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert_eq!(
        text(&o.stdout).trim(),
        "Keep chats on this computer for 7 days. Older chats are deleted from this computer. \
         Your friends' copies aren't."
    );
    let o = lab(&["chats", "status"], false);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(out.contains("Chats are kept for: 7 days"), "{out}");
    assert!(out.contains("Next deletion: not planned yet"), "{out}");

    let o = lab(&["chats", "status"], true);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(out.contains("Chats are kept for: 7 days"), "{out}");
    assert!(
        out.contains("Next deletion: none (no chats old enough to go)"),
        "{out}"
    );
    // A new profile: no retention notice, and no grace line in status.
    assert!(
        !text(&o.stderr).contains("New: Raven deletes"),
        "{}",
        text(&o.stderr)
    );
    let o = lab(&["chats", "keep", "always"], true);
    assert_eq!(
        text(&o.stdout).trim(),
        "Raven keeps your chats on this computer until you delete them."
    );
    let out = text(&lab(&["chats", "status"], true).stdout);
    assert!(
        out.contains("Chats are kept for: always (until you delete them)"),
        "{out}"
    );
    assert!(out.contains("Next deletion: none"), "{out}");
}

/// Whether `text` holds something shaped like an IPv4 address (four dotted
/// numbers).
fn has_ipv4(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .any(|token| {
            let parts: Vec<&str> = token.trim_matches('.').split('.').collect();
            parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3)
        })
}

/// Phase 6b P6.30: `raven security` and the security rows of the other
/// commands. With the security events gate shut (every release build) it
/// says so and exits 0, and makes no ledger. Live (a debug build's lab
/// switches; the profile sealed), a refused key change is one alert:
/// `raven security` lists and explains it, `--json` (v1) carries it,
/// `raven status` shows it in its SECURITY section with the strangers the
/// running raven-node refused, `raven doctor` counts it, a security words
/// match in `raven contact verify` resolves it, and so do `resolve N` and
/// `clear` (typed, or `--yes`). No output names an address, a whole key
/// or an rvn1 address.
#[test]
fn security_notices_in_the_cli() {
    let dir = short_dir();
    let dd = dir.path();
    plant_identity(dd);
    let ash_sec = |args: &[&str], live: bool| {
        let mut c = ash(dd);
        c.args(args).env("RAVEN_LAB_AT_REST", "1");
        if live {
            c.env("RAVEN_LAB_TEST_A", "1")
                .env("RAVEN_LAB_SECURITY_EVENTS", "1");
        } else {
            c.env_remove("RAVEN_LAB_SECURITY_EVENTS");
        }
        c
    };
    let sec = |args: &[&str], live: bool| run(ash_sec(args, live), "");
    for args in [
        &["security"][..],
        &["security", "explain", "1"],
        &["security", "resolve", "1"],
        &["security", "clear"],
    ] {
        let o = sec(args, false);
        assert_eq!(code(&o), 0, "{args:?}: {}", text(&o.stderr));
        assert_eq!(
            text(&o.stdout).trim(),
            "Security notices are not part of this version.",
            "{args:?}"
        );
    }
    let o = sec(&["security", "--json"], false);
    let json: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(json["v"], 1);
    assert_eq!(json["available"], false);
    assert_eq!(json["why"], "not_in_this_version");
    assert_eq!(json["alerts"], serde_json::json!([]));
    assert!(
        !dd.join("security_events.sqlite").exists(),
        "no ledger while shut"
    );
    if !cfg!(debug_assertions) {
        return;
    }

    // Alice, verified; then an invite with another key under her tag.
    let alice = Identity::from_seed(&[0x41; 32]);
    let mallory = Identity::from_seed(&[0x4d; 32]);
    let fp = raven_core::fingerprint::device_fingerprint_v1(&alice.public_key_bytes());
    let mut c = ash_sec(&["contact", "add", "--address", &alice.address()], false);
    c.args(["--pub-hex", &pub_hex(&alice), "--petname", "Alice"])
        .args(["--tag", "alice", "--verify-fp", &fp]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let refused_key_change = || {
        let mut c = ash_sec(&["contact", "add", "--address", &mallory.address()], true);
        c.args(["--pub-hex", &pub_hex(&mallory), "--petname", "Mallory"])
            .args(["--tag", "alice"]);
        let o = run(c, "");
        assert_ne!(code(&o), 0);
        assert!(
            text(&o.stderr).contains("KEY_CHANGE_REFUSED_WITHOUT_REPIN"),
            "{}",
            text(&o.stderr)
        );
    };
    refused_key_change();
    // What the security commands printed (`raven status` and `raven
    // doctor` print this profile's own key and address by design: only
    // their security part counts).
    let seen = std::cell::RefCell::new(String::new());
    let out = |o: Output| {
        assert_eq!(code(&o), 0, "{}", text(&o.stderr));
        let stdout = text(&o.stdout);
        seen.borrow_mut().push_str(&stdout);
        stdout
    };
    let headline = "An invite had a different key from the Alice you verified";
    let list = out(sec(&["security"], true));
    assert!(list.contains(&format!("1. ! {headline} (")), "{list}");
    for line in [
        "Raven kept the old key.",
        "If Alice really has a new key (a new computer or a reinstall), compare security words \
         with Alice before you add it. If not, ignore that invite.",
        "raven contact verify --petname Alice",
        "More about one: raven security explain N.",
    ] {
        assert!(list.contains(line), "{line:?} missing: {list}");
    }
    let raw = out(sec(&["security", "--json"], true));
    let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(json["v"], 1);
    assert_eq!(json["available"], true);
    let alerts = json["alerts"].as_array().unwrap();
    assert_eq!(alerts.len(), 1, "{json}");
    assert_eq!(alerts[0]["kind"], "SEC_KEY_CHANGE_ATTEMPT");
    assert_eq!(alerts[0]["code"], 27);
    assert_eq!(alerts[0]["severity"], "alert");
    assert_eq!(alerts[0]["state"], "seen", "the list was read");
    assert_eq!(alerts[0]["about"]["name"], "Alice");
    assert_eq!(alerts[0]["about"]["verified"], true);
    assert_eq!(alerts[0]["about"]["key_prefix"], &pub_hex(&alice)[..8]);
    assert_eq!(alerts[0]["headline"], headline);
    let explain = out(sec(&["security", "explain", "1"], true));
    for line in [
        "SEC_KEY_CHANGE_ATTEMPT (27)",
        &format!("Alice (verified friend, key {})", &pub_hex(&alice)[..8]),
        "Per day         today 1",
        "How serious     alert",
    ] {
        assert!(explain.contains(line), "{line:?} missing: {explain}");
    }
    let o = sec(&["security", "explain", "2"], true);
    assert_eq!(code(&o), 1);
    assert!(text(&o.stderr).contains("There is no security notice 2"));

    // `raven status` with a running raven-node that refused strangers.
    {
        let _node = FakeNode::start_with(
            dd,
            &["ipc", "lan_direct"],
            Fake {
                security: Some(SecurityStatus {
                    strangers_refused_1h: 37,
                    ..SecurityStatus::default()
                }),
                ..Fake::default()
            },
        );
        let o = sec(&["status"], true);
        assert_eq!(code(&o), 0, "{}", text(&o.stderr));
        let status = text(&o.stdout);
        let section = status
            .split("SECURITY ")
            .nth(1)
            .unwrap_or_else(|| panic!("no SECURITY section: {status}"));
        for line in [
            &format!("  ! {headline} ("),
            "    raven contact verify --petname Alice",
            "  Strangers refused in the last hour: 37 (they learned nothing about you)",
            "  Details: raven security",
        ] {
            assert!(section.contains(line), "{line:?} missing: {section}");
        }
        let section = section
            .split("\n\n")
            .next()
            .unwrap_or_else(|| panic!("{section}"));
        seen.borrow_mut().push_str(section);
        let list = out(sec(&["security"], true));
        assert!(
            list.contains("Strangers refused in the last hour: 37"),
            "{list}"
        );
    }
    let doctor = text(&sec(&["doctor"], true).stdout);
    let summary = doctor.split("(technical details follow)").next().unwrap();
    assert!(
        summary.contains("1 open alert (raven security)"),
        "{summary}"
    );
    assert!(
        summary.contains("raven contact verify --petname Alice"),
        "{summary}"
    );

    // A security words match resolves it.
    let words = raven_core::security_words::words_v1(&alice.public_key_bytes()).join(" ");
    let verify = out(sec(
        &["contact", "verify", "Alice", "--check", &words],
        true,
    ));
    assert!(
        verify.contains("Resolved 1 security notice about Alice."),
        "{verify}"
    );
    let list = out(sec(&["security"], true));
    assert!(list.contains("No open security notices."), "{list}");
    let doctor = text(&sec(&["doctor"], true).stdout);
    assert!(!doctor.contains("open alert"), "{doctor}");

    // `resolve N` and `clear`. N is the notice's own number (Phase 6
    // review sensing-6): the first one, resolved above, keeps its 1.
    refused_key_change();
    let again: serde_json::Value =
        serde_json::from_str(&out(sec(&["security", "--json"], true))).unwrap();
    assert_eq!(again["alerts"][0]["n"], 2, "{again}");
    let o = sec(&["security", "resolve", "1"], true);
    assert_eq!(code(&o), 1, "1 is resolved already");
    assert!(text(&o.stderr).contains("There is no security notice 1"));
    let resolved = out(sec(&["security", "resolve", "2"], true));
    assert_eq!(
        resolved.trim(),
        format!("Resolved: {headline}. What Raven did about it stays as it is.")
    );
    refused_key_change();
    let o = sec(&["security", "clear"], true);
    assert_eq!(code(&o), 1, "no terminal, no --yes");
    assert!(
        text(&o.stderr).contains("pass --yes"),
        "{}",
        text(&o.stderr)
    );
    let still: serde_json::Value =
        serde_json::from_str(&out(sec(&["security", "--json"], true))).unwrap();
    assert_eq!(still["alerts"].as_array().unwrap().len(), 1);
    let cleared = out(sec(&["security", "clear", "--yes"], true));
    assert_eq!(
        cleared.trim(),
        "Deleted every security notice and count Raven kept on this computer."
    );
    let none: serde_json::Value =
        serde_json::from_str(&out(sec(&["security", "--json"], true))).unwrap();
    assert_eq!(none["alerts"], serde_json::json!([]));

    // Nothing names an address, a whole key or an rvn1 address.
    let seen = seen.into_inner();
    let me = Identity::from_seed(&[0x5a; 32]);
    for id in [&alice, &mallory, &me] {
        assert!(!seen.contains(&pub_hex(id)), "a whole key in: {seen}");
        assert!(!seen.contains(&id.address()), "an address in: {seen}");
    }
    assert!(!seen.contains("rvn1"), "{seen}");
    assert!(!has_ipv4(&seen), "{seen}");
}
