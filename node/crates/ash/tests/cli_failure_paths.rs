//! Black-box checks of `ash` failure paths: commands must exit non-zero and
//! explain on stderr, trust prompts must not decide on EOF / blank answers, and
//! first-run identity creation needs a real "yes".
//!
//! Every run uses a throwaway data dir and the file-backed (`locked-file`)
//! secret stores, so nothing here can reach the OS keychain or the network.
//!
//! Unix only: the planted 0600 identity seed is the unix locked-file layout
//! (the Windows ACL-hardened store is not exercised here).
#![cfg(unix)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use raven_core::address::encode_address;
use raven_core::fingerprint::device_fingerprint_v1;
use raven_core::identity::Identity;

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
        // A service a run starts by itself receives on 127.0.0.1 only, never
        // on the LAN port another raven-node on this machine may hold.
        .env("RAVEN_SERVICE_LAN_LISTEN", "127.0.0.1:0");
    // Plain profiles, whatever privacy switches the suite runs with (the
    // tests read the profile's files themselves); a test that wants a lab
    // login item or an erase root sets it after this.
    for switch in raven_core::lan_gate::PRIVACY_LAB_SWITCHES {
        c.env_remove(switch);
    }
    c
}

/// Run to completion with `stdin_text` on a (non-terminal) stdin.
fn run(mut c: Command, stdin_text: &str) -> Output {
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ash");
    // The child may exit without reading its stdin: a broken pipe is fine.
    let _ = child.stdin.take().unwrap().write_all(stdin_text.as_bytes());
    child.wait_with_output().expect("wait ash")
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A usable locked-file identity without running `ash init` (32-byte 0600 seed).
fn plant_identity(dir: &Path) {
    let seed = dir.join("identity.seed");
    std::fs::write(&seed, [0x5au8; 32]).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn ident(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

fn pub_hex(id: &Identity) -> String {
    hex::encode(id.public_key_bytes())
}

fn add_contact_args(c: &mut Command, id: &Identity, petname: &str, tag: Option<&str>, dial: &str) {
    c.args(["contact", "add", "--address", &id.address()])
        .args(["--pub-hex", &pub_hex(id), "--petname", petname]);
    if let Some(t) = tag {
        c.args(["--tag", t]);
    }
    if !dial.is_empty() {
        c.args(["--lan-dial", dial]);
    }
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

#[test]
fn listen_exits_nonzero_when_it_cannot_start() {
    // No identity.
    let dir = tempfile::tempdir().unwrap();
    let mut c = ash(dir.path());
    c.arg("listen");
    let o = run(c, "");
    assert_eq!(code(&o), 1, "{}", text(&o.stderr));
    assert!(!text(&o.stderr).trim().is_empty());
    assert!(!text(&o.stdout).contains("LISTENING"));

    // Identity but no contacts to accept.
    plant_identity(dir.path());
    let mut c = ash(dir.path());
    c.arg("listen");
    let o = run(c, "");
    assert_eq!(code(&o), 1, "{}", text(&o.stderr));
    assert!(
        text(&o.stderr).contains("No pinned contacts"),
        "{}",
        text(&o.stderr)
    );
    assert!(!text(&o.stdout).contains("LISTENING"));

    // Corrupt contact book.
    std::fs::write(dir.path().join("contacts.json"), "{not-json").unwrap();
    let mut c = ash(dir.path());
    c.arg("listen");
    let o = run(c, "");
    assert_eq!(code(&o), 1);
    assert!(text(&o.stderr).contains("corrupt"), "{}", text(&o.stderr));
    assert!(!text(&o.stdout).contains("LISTENING"));
}

/// A taken port is named with the way out: find the one process that holds it,
/// or receive on another port. Never a pattern that stops every raven-node.
/// `RAVEN_SERVICE_LAN_LISTEN` chooses the port the way `--listen` does (a send
/// that starts the service uses it too).
#[test]
fn listen_on_a_taken_port_names_one_process() {
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    let mut c = ash(dir.path());
    add_contact_args(&mut c, &ident(0x21), "Poline", None, "192.168.1.20:7420");
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));

    let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = holder.local_addr().unwrap().to_string();
    let port = holder.local_addr().unwrap().port();
    let mut by_flag = ash(dir.path());
    by_flag.args(["listen", "--listen", &listen]);
    let mut by_env = ash(dir.path());
    by_env
        .arg("listen")
        .env("RAVEN_SERVICE_LAN_LISTEN", &listen);
    for c in [by_flag, by_env] {
        let o = run(c, "");
        let err = text(&o.stderr);
        assert_eq!(code(&o), 1, "{err}");
        for word in [
            format!("port {port} ({listen}) is already taken by another program"),
            "kill <PID>".to_string(),
            "if it is RAVEN for another profile, leave it running".to_string(),
            // The next port (RAVEN's own 7421-7423 never come up here).
            match port.checked_add(1) {
                Some(next) => format!("ash listen --listen 127.0.0.1:{next}"),
                None => "ash listen --listen 0.0.0.0:7424".to_string(),
            },
        ] {
            assert!(err.contains(&word), "{word:?} missing from: {err}");
        }
        assert!(!err.contains("pkill"), "{err}");
        assert!(!text(&o.stdout).contains("LISTENING"));
    }
    drop(holder);
}

#[test]
fn inbox_on_an_unopenable_store_is_a_failure_not_an_empty_inbox() {
    let dir = tempfile::tempdir().unwrap();
    // A regular file where the profile directory should be: the store cannot open.
    let not_a_dir = dir.path().join("profile-is-a-file");
    std::fs::write(&not_a_dir, b"x").unwrap();
    let mut c = ash(&not_a_dir);
    c.arg("inbox");
    let o = run(c, "");
    assert_eq!(
        code(&o),
        1,
        "stdout={} stderr={}",
        text(&o.stdout),
        text(&o.stderr)
    );
    assert!(text(&o.stderr).contains("inbox:"), "{}", text(&o.stderr));
    assert!(!text(&o.stdout).contains("endpoint inbox empty"));
}

#[test]
fn prekey_fetch_and_import_peer_prekey_fail_loudly() {
    let dir = tempfile::tempdir().unwrap();
    let peer = pub_hex(&ident(0x31));

    let mut c = ash(dir.path());
    c.args(["prekey", "fetch", "--pub-hex", "zz"]);
    let o = run(c, "");
    assert_eq!(code(&o), 1);
    assert!(text(&o.stderr).contains("pub_hex"), "{}", text(&o.stderr));
    assert!(!text(&o.stdout).contains("prekey ok"));

    // `import-peer-prekey … && ash send …` must stop at an unreadable bundle.
    let mut c = ash(dir.path());
    c.args([
        "lab",
        "import-peer-prekey",
        "--peer-pub-hex",
        &peer,
        "--file",
    ])
    .arg(dir.path().join("missing.json"));
    let o = run(c, "");
    assert_eq!(code(&o), 1);
    assert!(text(&o.stderr).contains("read:"), "{}", text(&o.stderr));

    let garbage = dir.path().join("bundle.json");
    std::fs::write(&garbage, "{not json").unwrap();
    let mut c = ash(dir.path());
    c.args(["prekey", "fetch", "--pub-hex", &peer, "--file"])
        .arg(&garbage);
    let o = run(c, "");
    assert_eq!(code(&o), 1);
    assert!(text(&o.stderr).contains("json:"), "{}", text(&o.stderr));
}

#[test]
fn contact_lookups_that_match_nothing_exit_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    for args in [
        &["contact", "verify", "--tag", "nobody"][..],
        &["contact", "verify"][..],
        &["contact", "verify", "--petname", "Zed"][..],
        &["contact", "resolve", "--tag", "nobody"][..],
        // A lone "@" names nobody (it used to match every untagged contact).
        &["contact", "resolve", "--tag", "@"][..],
    ] {
        let mut c = ash(dir.path());
        c.args(args);
        let o = run(c, "");
        assert_eq!(code(&o), 1, "{args:?}: {}", text(&o.stderr));
        assert!(!text(&o.stderr).trim().is_empty(), "{args:?}");
    }
}

#[test]
fn alias_publish_defaults_to_the_next_sequence_and_refuses_regressions() {
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    let publish = |extra: &[&str]| {
        let mut c = ash(dir.path());
        c.args(["alias", "publish", "--alias", "alice"]).args(extra);
        run(c, "")
    };
    let o = publish(&["--sequence", "5"]);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    // The old default (sequence 1) would silently overwrite seq 5 locally and
    // be rejected as stale by every peer that already holds it.
    let o = publish(&["--sequence", "1"]);
    assert_eq!(code(&o), 1);
    assert!(
        text(&o.stderr).contains("ALIAS_STALE_SEQUENCE"),
        "{}",
        text(&o.stderr)
    );
    // No --sequence: stored + 1.
    let o = publish(&[]);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        text(&o.stdout).contains("sequence    6"),
        "{}",
        text(&o.stdout)
    );
    // A first claim for another alias starts at 1.
    let mut c = ash(dir.path());
    c.args(["alias", "publish", "--alias", "bob"]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        text(&o.stdout).contains("sequence    1"),
        "{}",
        text(&o.stdout)
    );
}

#[test]
fn verify_fp_is_case_sensitive_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    let poline = ident(0x41);
    let fp = device_fingerprint_v1(&poline.public_key_bytes());
    assert_ne!(fp, fp.to_ascii_lowercase(), "vector must contain capitals");
    let mut c = ash(dir.path());
    add_contact_args(&mut c, &poline, "Poline", None, "192.168.1.20:7420");
    c.args(["--verify-fp", &fp.to_ascii_lowercase()]);
    let o = run(c, "");
    assert_ne!(code(&o), 0, "a case-folded fingerprint must not pin");
    let err = text(&o.stderr);
    assert!(
        err.contains("fingerprint mismatch") && err.contains("case-sensitive"),
        "{err}"
    );
    assert!(
        !dir.path().join("contacts.json").exists()
            || !std::fs::read_to_string(dir.path().join("contacts.json"))
                .unwrap()
                .contains("Poline"),
        "nothing saved on a mismatch"
    );
    // Dashes are display only: the bare characters pin.
    let mut c = ash(dir.path());
    add_contact_args(&mut c, &poline, "Poline", None, "192.168.1.20:7420");
    c.args(["--verify-fp", &fp.replace('-', "")]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
}

/// Phase 6b P6.25 (S12): another key offered under a verified friend's tag
/// is refused as before, and while the security events gate is live (a
/// debug build's lab switches, the profile sealed) it is one
/// `SEC_KEY_CHANGE_ATTEMPT` alert in the profile's security ledger; while
/// the gate is shut no ledger file is ever made.
#[test]
fn a_refused_key_change_is_one_ledger_alert_only_with_the_events_gate() {
    use raven_core::security_events::SecKind;
    use raven_core::security_ledger::{ledger_path, rows_on_disk};
    if !cfg!(debug_assertions) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    let alice = ident(0x41);
    let mallory = ident(0x4D);
    let lab = |c: &mut Command, events: bool| {
        c.env("RAVEN_LAB_AT_REST", "1");
        if events {
            c.env("RAVEN_LAB_TEST_A", "1")
                .env("RAVEN_LAB_SECURITY_EVENTS", "1");
        } else {
            c.env_remove("RAVEN_LAB_SECURITY_EVENTS");
        }
    };
    let mut c = ash(dir.path());
    add_contact_args(&mut c, &alice, "Alice", Some("alice"), "");
    c.args([
        "--verify-fp",
        &device_fingerprint_v1(&alice.public_key_bytes()),
    ]);
    lab(&mut c, false);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let attempt = |events: bool| {
        let mut c = ash(dir.path());
        add_contact_args(&mut c, &mallory, "Mallory", Some("alice"), "");
        lab(&mut c, events);
        let o = run(c, "");
        assert_ne!(code(&o), 0);
        assert!(
            text(&o.stderr).contains("KEY_CHANGE_REFUSED_WITHOUT_REPIN"),
            "{}",
            text(&o.stderr)
        );
    };
    attempt(false);
    assert!(!ledger_path(dir.path()).exists(), "no ledger while shut");
    attempt(true);
    let kind = SecKind::KeyChangeAttempt.code();
    assert_eq!(
        rows_on_disk(dir.path()).unwrap(),
        Some(vec![("sec_counts", kind), ("sec_alerts", kind)]),
        "one count and one alert"
    );
}

/// Security words (RAVEN_SECURITY_WORDS_V1) on the command line: `contact
/// add --verify-fp` / `--verify-words` and `contact verify`. A refusal never
/// prints the expected words.
#[test]
fn security_words_pin_and_a_mismatch_never_shows_the_expected_words() {
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    let poline = ident(0x41);
    let words = raven_core::security_words::words_v1(&poline.public_key_bytes());
    let other = raven_core::security_words::words_v1(&ident(0x42).public_key_bytes()).join(" ");
    let book = dir.path().join("contacts.json");
    let assert_no_expected_words = |o: &Output| {
        let both = format!("{}{}", text(&o.stdout), text(&o.stderr));
        for w in &words {
            assert!(!both.contains(w), "{w} shown in: {both}");
        }
    };

    // contact add --verify-words with someone else's words: refused, nothing saved.
    let mut c = ash(dir.path());
    add_contact_args(&mut c, &poline, "Poline", None, "192.168.1.20:7420");
    c.args(["--verify-words", &other]);
    let o = run(c, "");
    assert_eq!(code(&o), 1);
    assert!(
        text(&o.stderr).contains("security words do not match this key: refusing to pin"),
        "{}",
        text(&o.stderr)
    );
    assert_no_expected_words(&o);
    assert!(!book.exists(), "nothing saved on a mismatch");

    // Saved, not verified: `contact verify` without a terminal shows the
    // contact as before, and no words yet.
    let mut c = ash(dir.path());
    add_contact_args(
        &mut c,
        &poline,
        "Poline",
        Some("poline"),
        "192.168.1.20:7420",
    );
    assert_eq!(code(&run(c, "")), 0);
    let o = run_args(dir.path(), &["contact", "verify", "Poline"]);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(out.contains("pinned      no"), "{out}");
    assert!(
        out.contains(&device_fingerprint_v1(&poline.public_key_bytes())),
        "{out}"
    );
    assert_no_expected_words(&o);

    // --check with the wrong words, or not 10 words: exit 1, the reason,
    // nothing pinned.
    for (typed, why) in [
        (
            other.as_str(),
            "These are real Raven words, but not Poline's.",
        ),
        (
            &words[..9].join(" ") as &str,
            "You typed 9 words. A set has 10: ask Poline which one you missed.",
        ),
    ] {
        let o = run_args(
            dir.path(),
            &["contact", "verify", "@poline", "--check", typed],
        );
        assert_eq!(code(&o), 1, "{typed}");
        assert!(text(&o.stderr).contains(why), "{}", text(&o.stderr));
        assert_no_expected_words(&o);
        assert!(std::fs::read_to_string(&book)
            .unwrap()
            .contains("\"pinned\": false"));
    }

    // Her words: pinned, name, tag and address kept, and now they show.
    let o = run_args(
        dir.path(),
        &["contact", "verify", "Poline", "--check", &words.join(" ")],
    );
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(
        out.contains("Poline is verified \u{2713} (pinned on this computer)"),
        "{out}"
    );
    assert!(
        out.contains(&format!("words       {}", words.join(" "))),
        "{out}"
    );
    let saved = std::fs::read_to_string(&book).unwrap();
    assert!(saved.contains("\"pinned\": true"), "{saved}");
    assert!(saved.contains("\"petname\": \"Poline\""), "{saved}");
    assert!(saved.contains("192.168.1.20:7420"), "{saved}");
    let o = run_args(dir.path(), &["contact", "verify", "--tag", "poline"]);
    let out = text(&o.stdout);
    assert!(out.contains("pinned      yes"), "{out}");
    assert!(
        out.contains(&format!("words       {}", words.join(" "))),
        "{out}"
    );

    // The old code still pins through --verify-fp (a fresh profile).
    let fresh = tempfile::tempdir().unwrap();
    plant_identity(fresh.path());
    let mut c = ash(fresh.path());
    add_contact_args(&mut c, &poline, "Poline", None, "");
    c.args([
        "--verify-fp",
        &device_fingerprint_v1(&poline.public_key_bytes()),
    ]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(std::fs::read_to_string(fresh.path().join("contacts.json"))
        .unwrap()
        .contains("\"pinned\": true"));
}

fn run_args(dir: &Path, args: &[&str]) -> Output {
    let mut c = ash(dir);
    c.args(args);
    run(c, "")
}

#[test]
fn contact_set_dial_remove_and_unblock_are_explicit_and_local() {
    let dir = tempfile::tempdir().unwrap();
    // Contacts are profile state: they need the identity to exist first.
    plant_identity(dir.path());
    let poline = ident(0x41);
    let fp = device_fingerprint_v1(&poline.public_key_bytes());
    let mut c = ash(dir.path());
    add_contact_args(
        &mut c,
        &poline,
        "Poline",
        Some("poline"),
        "192.168.1.20:7420",
    );
    c.args(["--verify-fp", &fp]);
    assert_eq!(code(&run(c, "")), 0);

    // Refresh the dial without losing petname / tag / pin.
    let mut c = ash(dir.path());
    c.args([
        "contact",
        "set-dial",
        "--petname",
        "Poline",
        "--lan-dial",
        "192.168.1.31:7420",
    ]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let book = std::fs::read_to_string(dir.path().join("contacts.json")).unwrap();
    assert!(book.contains("192.168.1.31:7420") && !book.contains("192.168.1.20:7420"));
    assert!(
        book.contains("\"petname\": \"Poline\"") && book.contains("\"public_tag\": \"poline\"")
    );
    assert!(book.contains("\"pinned\": true"));

    let mut c = ash(dir.path());
    c.args([
        "contact",
        "set-dial",
        "--petname",
        "Nobody",
        "--lan-dial",
        "10.0.0.1:7420",
    ]);
    assert_eq!(code(&run(c, "")), 1);

    // Removing needs a real confirmation: piped stdin cannot give one.
    let mut c = ash(dir.path());
    c.args(["contact", "remove", "--petname", "Poline"]);
    let o = run(c, "remove\n");
    assert_eq!(code(&o), 1);
    assert!(std::fs::read_to_string(dir.path().join("contacts.json"))
        .unwrap()
        .contains("Poline"));
    let mut c = ash(dir.path());
    c.args(["contact", "remove", "--petname", "Poline", "--yes"]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(!std::fs::read_to_string(dir.path().join("contacts.json"))
        .unwrap()
        .contains("Poline"));

    // Unblock: not blocked → error, unknown key format → error.
    let mut c = ash(dir.path());
    c.args(["contact", "unblock", "--pub-hex", &pub_hex(&poline)]);
    let o = run(c, "");
    assert_eq!(code(&o), 1);
    assert!(
        text(&o.stderr).contains("not on the block list"),
        "{}",
        text(&o.stderr)
    );
    let mut c = ash(dir.path());
    c.args(["contact", "unblock", "--pub-hex", "zz"]);
    assert_eq!(code(&run(c, "")), 1);
}

#[test]
fn send_to_a_lone_at_sign_reaches_nobody() {
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    let bob = ident(0x42);
    let mut c = ash(dir.path());
    add_contact_args(&mut c, &bob, "Bob", None, "192.168.1.9:7420");
    assert_eq!(code(&run(c, "")), 0);
    // `--contact "@$TAG"` with $TAG unset must not fall onto the petname-only contact.
    let mut c = ash(dir.path());
    c.args(["send", "--contact", "@"]);
    let o = run(c, "secret\n");
    assert_eq!(code(&o), 1);
    assert!(
        text(&o.stderr).contains("no contact for"),
        "{}",
        text(&o.stderr)
    );
}

#[test]
fn status_reports_a_broken_book_and_does_not_present_policy_as_live_state() {
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    std::fs::write(dir.path().join("contacts.json"), "{not-json").unwrap();
    let mut c = ash(dir.path());
    c.arg("status");
    let o = run(c, "");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 1, "{out}");
    assert!(text(&o.stderr).contains("corrupt"), "{}", text(&o.stderr));
    // The rest of the screen still renders, with the failure shown in place.
    assert!(
        out.contains("CONTACTS") && out.contains("unavailable"),
        "{out}"
    );
    assert!(out.contains("BRIDGE") && out.contains("forward_q"), "{out}");
    // No daemon is running: say so instead of claiming transports / capabilities.
    assert!(out.contains("not running"), "{out}");
    assert!(
        !out.contains("mock_ble") && !out.contains("transports"),
        "{out}"
    );
}

#[test]
fn node_flag_on_an_unreadable_policy_warns_about_the_reset_flags() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("node_policy.json"), "{broken").unwrap();
    let mut c = ash(dir.path());
    c.args(["node", "bridge", "on"]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        text(&o.stderr).contains("unreadable"),
        "{}",
        text(&o.stderr)
    );
    let out = text(&o.stdout);
    assert!(
        out.contains("bridge=on") && out.contains("store=off"),
        "{out}"
    );
}

#[test]
fn first_run_identity_needs_a_real_yes() {
    // stdin closed (EOF): no human decided, nothing is created.
    let dir = tempfile::tempdir().unwrap();
    let o = run(ash(dir.path()), "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(!dir.path().join("identity.seed").exists());
    assert!(
        text(&o.stdout).contains("identity not created"),
        "{}",
        text(&o.stdout)
    );
    // A blank line on a pipe is not a decision either.
    let o = run(ash(dir.path()), "\n");
    assert_eq!(code(&o), 0);
    assert!(!dir.path().join("identity.seed").exists());
    // An explicit yes still works (the menu smoke script relies on it).
    let o = run(ash(dir.path()), "y\nq\n");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(dir.path().join("identity.seed").exists());
    assert!(
        text(&o.stdout).contains("identity created"),
        "{}",
        text(&o.stdout)
    );
}

/// Drive menu 5 → a (guided add) with `answers` and return the output.
fn guided_add(dir: &Path, answers: &str) -> Output {
    run(ash(dir), &format!("5\na\n{answers}"))
}

#[test]
fn guided_add_never_trusts_a_contact_on_eof_or_a_blank_answer() {
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    let friend = ident(0x51);
    let invite = format!("raven:{}:{}", friend.address(), pub_hex(&friend));
    let fp = device_fingerprint_v1(&friend.public_key_bytes());
    let book = dir.path().join("contacts.json");

    // EOF at the fingerprint prompt.
    let o = guided_add(dir.path(), &format!("{invite}\nFriend\n"));
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(!book.exists(), "EOF must not add a contact");
    assert!(
        text(&o.stdout).contains("nothing saved"),
        "{}",
        text(&o.stdout)
    );
    // A blank answer (stray Enter / pasted empty line) aborts too.
    let o = guided_add(dir.path(), &format!("{invite}\nFriend\n\nq\n"));
    assert!(!book.exists(), "{}", text(&o.stdout));
    // `v` alone never pins: it asks for the fingerprint, and EOF there aborts.
    let o = guided_add(dir.path(), &format!("{invite}\nFriend\nv\n"));
    assert!(!book.exists(), "{}", text(&o.stdout));
    // ... and a wrong fingerprint aborts.
    let o = guided_add(
        dir.path(),
        &format!("{invite}\nFriend\nv\nAAAA-BBBB-CCCC\n"),
    );
    assert!(!book.exists(), "{}", text(&o.stdout));
    assert!(
        text(&o.stdout).contains("did not match"),
        "{}",
        text(&o.stdout)
    );
    // `c` saves unpinned (what the menu smoke script drives).
    let o = guided_add(dir.path(), &format!("{invite}\nFriend\nc\n\nq\n"));
    assert!(
        text(&o.stdout).contains("contact saved"),
        "{}",
        text(&o.stdout)
    );
    let saved = std::fs::read_to_string(&book).unwrap();
    assert!(saved.contains("\"pinned\": false"), "{saved}");
    std::fs::remove_file(&book).unwrap();
    // v + the typed fingerprint pins.
    let o = guided_add(dir.path(), &format!("{invite}\nFriend\nv\n{fp}\nq\n"));
    assert!(
        text(&o.stdout).contains("contact saved"),
        "{}",
        text(&o.stdout)
    );
    let saved = std::fs::read_to_string(&book).unwrap();
    assert!(saved.contains("\"pinned\": true"), "{saved}");
}

#[test]
fn pasted_contact_card_cannot_answer_the_fingerprint_prompt_by_itself() {
    // The reported scenario: a "contact card" whose later lines line up with
    // the tag / petname / dial / choice prompts and end in `v`.
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    let attacker = ident(0x66);
    let card = format!(
        "address {}\npub_hex {}\n\nMom\n\nv\n",
        encode_address(&attacker.public_key_bytes()),
        pub_hex(&attacker)
    );
    let o = guided_add(dir.path(), &card);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        !dir.path().join("contacts.json").exists(),
        "pasted `v` must not pin: {}",
        text(&o.stdout)
    );
}

#[test]
fn menu_survives_a_corrupt_contact_book() {
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    std::fs::write(dir.path().join("contacts.json"), "{not-json").unwrap();
    // 3 Status, 5 Contacts (Enter = back), q: neither screen may end the session.
    let o = run(ash(dir.path()), "3\n5\n\nq\n");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(text(&o.stdout).contains("fly safe"), "{}", text(&o.stdout));
    assert!(text(&o.stderr).contains("corrupt"), "{}", text(&o.stderr));
}

/// First-install wedge: whatever a command creates in a profile with no identity
/// makes the first `ash init` fail the continuity check ("profile contains
/// state but has no identity continuity record") and point at identity theft.
/// Commands that create state must therefore refuse (or do nothing) until the
/// identity exists, and the profile must stay initialisable afterwards.
mod first_install {
    use super::*;

    /// Names inert for the first-install check (see raven-core identity_store).
    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn assert_still_initialisable(dir: &Path) {
        let mut c = ash(dir);
        c.arg("init");
        let o = run(c, "");
        assert_eq!(
            code(&o),
            0,
            "init refused after a pre-identity command: stdout={} stderr={}",
            text(&o.stdout),
            text(&o.stderr)
        );
        assert!(text(&o.stdout).contains("pub_hex="), "{}", text(&o.stdout));
    }

    #[test]
    fn inbox_before_the_identity_creates_nothing_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = ash(dir.path());
        c.arg("inbox");
        let o = run(c, "");
        assert_eq!(code(&o), 0, "{}", text(&o.stderr));
        let out = text(&o.stdout);
        assert!(out.contains("no identity yet"), "{out}");
        assert!(out.contains("ash init"), "{out}");
        assert!(!out.contains("endpoint inbox empty"), "{out}");
        for name in entries(dir.path()) {
            assert!(
                !name.starts_with("indexed_sessions") && name != "indexed-session-secrets",
                "inbox created the session store: {name}"
            );
        }
        assert_still_initialisable(dir.path());
    }

    /// `ash nearby` (its status) only reads; `ash nearby enable` before the
    /// identity is refused (the hold in a build without nearby, else "ash
    /// init"); neither creates anything (P5.28 retired the old mock and its
    /// nearby_registry.json).
    #[test]
    fn nearby_before_the_identity_is_refused_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = ash(dir.path());
        c.arg("nearby");
        let o = run(c, "");
        assert_eq!(code(&o), 0, "{}", text(&o.stderr));
        assert!(
            text(&o.stdout).contains("Nearby (Bluetooth)"),
            "{}",
            text(&o.stdout)
        );
        for lab in [false, true] {
            let mut c = ash(dir.path());
            if lab {
                c.env("RAVEN_LAB_TEST_A", "1").env("RAVEN_LAB_NEARBY", "1");
            } else {
                c.env_remove("RAVEN_LAB_NEARBY");
            }
            c.args(["nearby", "enable"]);
            let o = run(c, "");
            assert_eq!(code(&o), 1, "{}", text(&o.stdout));
            let want = if lab { "ash init" } else { "NEARBY_HOLD" };
            assert!(text(&o.stderr).contains(want), "{}", text(&o.stderr));
        }
        // The identity lock the check takes is allow-listed (as for the
        // other commands here); nothing else.
        let made: Vec<String> = entries(dir.path())
            .into_iter()
            .filter(|n| !n.starts_with(".identity_store.lock"))
            .collect();
        assert!(made.is_empty(), "{made:?}");
        assert_still_initialisable(dir.path());
    }

    #[test]
    fn contact_add_before_the_identity_is_refused_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let bob = ident(0x43);
        let mut c = ash(dir.path());
        add_contact_args(&mut c, &bob, "Bob", None, "");
        let o = run(c, "");
        assert_eq!(code(&o), 1, "{}", text(&o.stdout));
        assert!(text(&o.stderr).contains("ash init"), "{}", text(&o.stderr));
        assert!(!dir.path().join("contacts.json").exists());
        assert_still_initialisable(dir.path());
    }

    /// Menu 5 -> a(dd) on the first-run menu: piped input, no identity.
    #[test]
    fn menu_add_contact_before_the_identity_is_refused_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let bob = ident(0x44);
        let c = ash(dir.path());
        // n: decline identity creation; 5 a: add a contact; paste an invite.
        let script = format!(
            "n\n5\na\nraven:{}:{}\n\n\n\nq\n",
            bob.address(),
            pub_hex(&bob)
        );
        let o = run(c, &script);
        let all = format!("{}{}", text(&o.stdout), text(&o.stderr));
        assert!(all.contains("needs an identity first"), "{all}");
        assert!(!dir.path().join("contacts.json").exists(), "{all}");
        assert_still_initialisable(dir.path());
    }

    /// Menu 2 (Inbox) is the second entry of the first-run menu.
    #[test]
    fn menu_inbox_before_the_identity_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let o = run(ash(dir.path()), "n\n2\nq\n");
        let all = format!("{}{}", text(&o.stdout), text(&o.stderr));
        assert!(all.contains("no identity yet"), "{all}");
        for name in entries(dir.path()) {
            assert!(!name.starts_with("indexed_sessions"), "{name}");
        }
        assert_still_initialisable(dir.path());
    }

    /// An unreadable identity store must not be answered with "run `ash init`"
    /// (that is what is failing): the first-run tip says what to do instead.
    #[test]
    fn unreadable_identity_store_is_not_answered_with_ash_init_tip() {
        let dir = tempfile::tempdir().unwrap();
        // Leftover state without an identity record: a continuity violation.
        std::fs::write(dir.path().join("contacts.json"), "[]").unwrap();
        let c = ash(dir.path());
        let o = run(c, "q\n");
        let out = text(&o.stdout);
        assert!(out.contains("identity unavailable"), "{out}");
        assert!(!out.contains("run `ash init` anytime"), "{out}");
        assert!(out.contains("recovery steps"), "{out}");
    }
}

/// Rust ignores SIGPIPE, so a closed stdout pipe (`ash ... | head -1`,
/// `... | grep -q x`) made std's `println!` panic: exit 101 and "failed printing
/// to stdout: Broken pipe". The reader is gone from the start here (the read
/// end is closed before the process exists), so the very first write hits EPIPE.
#[test]
fn a_closed_stdout_pipe_is_not_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    for args in [&["banner"][..], &["whoami"], &["doctor"], &["inbox"]] {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let mut c = ash(dir.path());
        c.args(args)
            .stdin(Stdio::null())
            .stdout(writer)
            .stderr(Stdio::piped());
        let o = c.spawn().unwrap().wait_with_output().unwrap();
        let err = text(&o.stderr);
        assert!(!err.contains("panicked"), "{args:?}: {err}");
        assert!(!err.contains("Broken pipe"), "{args:?}: {err}");
        assert_ne!(code(&o), 101, "{args:?}: {err}");
    }
    // Output that is not broken still arrives (the shadowed macros print).
    let mut c = ash(dir.path());
    c.arg("banner");
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(text(&o.stdout).contains("R A V E N"), "{}", text(&o.stdout));
}

/// `ash contact remove` is the deliberate re-pin: it also forgets the prekey
/// pinned for that contact. A contact that reinstalled is refused
/// (PEER_PREKEY_RESET) for new sessions until its old pinned prekey expires;
/// removing and re-adding it is the way to accept it sooner.
#[test]
fn contact_remove_forgets_the_pinned_prekey() {
    use raven_core::atsam_mlkem::HybridKeypair;
    use raven_core::prekey_bundle::{PrekeyBundle, PrekeyStore};
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    let poline = ident(0x45);
    let mut c = ash(dir.path());
    add_contact_args(&mut c, &poline, "Poline", None, "");
    assert_eq!(code(&run(c, "")), 0);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let kp = HybridKeypair::generate(&mut rand::thread_rng());
    let bundle = PrekeyBundle::from_hybrid_public(
        "ash-primary",
        kp.x25519_public,
        kp.mlkem_ek_bytes.clone(),
        5,
        now,
        now + 3_600_000,
    )
    .unwrap()
    .sign(&poline)
    .unwrap();
    let mut store = PrekeyStore::load_checked(dir.path()).unwrap();
    store.publish(&bundle, now).unwrap();
    store.save(dir.path()).unwrap();
    let pinned = |dir: &Path| {
        PrekeyStore::load_checked(dir)
            .unwrap()
            .fetch(&poline.public_key_bytes(), now)
            .unwrap()
            .is_some()
    };
    assert!(pinned(dir.path()), "precondition: a prekey is pinned");

    let mut c = ash(dir.path());
    c.args(["contact", "remove", "--petname", "Poline", "--yes"]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(out.contains("removed"), "{out}");
    assert!(out.contains("forgot the prekey pinned"), "{out}");
    assert!(!pinned(dir.path()), "the pin must be gone with the contact");
    // Idempotent: nothing pinned, nothing said, still a clean removal of the next one.
    assert!(
        !dir.path().join("contacts.json").exists() || {
            let raw = std::fs::read_to_string(dir.path().join("contacts.json")).unwrap();
            !raw.contains("Poline")
        }
    );
}

/// The in-process half of the test below opens a profile's keys here: only
/// with the file-backed lab backends (never the OS keychain).
fn lab_backends_in_process() {
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

/// Privacy pack PP.10: a sealed profile's chat history is RVNHIST2 (under
/// the epoch data keys). The build before the pack (the PP.1 snapshot,
/// `RAVEN_FAULT_PRIVACY_OLD_BIN=<dir with its ash>`, the fault matrix's
/// variable for that build) reads it as corrupt: its
/// Messages screen says so, and the file is neither written over nor moved
/// aside (its legacy import needs a leading `{`). Temp profile only.
#[test]
#[ignore = "needs the pre-pack build: RAVEN_FAULT_PRIVACY_OLD_BIN=<dir with its ash>"]
fn rvnhist2_makes_the_snapshot_build_fail_closed_not_move_aside() {
    use raven_core::at_rest::MigratePolicy;
    let Some(old_bin) = std::env::var_os("RAVEN_FAULT_PRIVACY_OLD_BIN") else {
        eprintln!("skipped: RAVEN_FAULT_PRIVACY_OLD_BIN is not set");
        return;
    };
    lab_backends_in_process();
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    let o = run(
        {
            let mut c = ash(dd);
            c.arg("init");
            c
        },
        "",
    );
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    // This build seals the profile and keeps a chat in it.
    let report =
        raven_core::privacy::migrate_all(dd, 1_800_000_000_000, MigratePolicy::Allow).unwrap();
    assert_eq!(report.outcome, raven_core::privacy::MigrateOutcome::Sealed);
    raven_core::ChatHistory::append_persisted(
        dd,
        raven_core::ChatHistoryEntry {
            message_id_hex: "ab".repeat(16),
            direction: "in".into(),
            peer_petname: "Bob".into(),
            peer_tag: String::new(),
            peer_pub_hex: "cd".repeat(32),
            created_at_ms: 1_800_000_000_000,
            delivery: "received".into(),
            preview: String::new(),
            body: "rvnhist2".into(),
            stored_at_ms: None,
            id_conflict: false,
        },
    )
    .unwrap();
    let history = dd.join("chat_history.json");
    let before = std::fs::read(&history).unwrap();
    assert!(before.starts_with(b"RVNHIST2"));

    // The older build's Messages screen (Contacts, then Messages).
    let mut c = Command::new(Path::new(&old_bin).join("ash"));
    c.arg("--data-dir")
        .arg(dd)
        .env("RAVEN_IDENTITY_BACKEND", "locked-file")
        .env("RAVEN_CHAT_HISTORY_BACKEND", "locked-file")
        .env("RAVEN_PREKEY_BACKEND", "locked-file")
        .env("RAVEN_SESSION_BACKEND", "locked-file")
        .env("RAVEN_ALLOW_EPHEMERAL_DATA_DIR", "1")
        .env("NO_COLOR", "1")
        .env("RAVEN_SERVICE_LAN_LISTEN", "127.0.0.1:0");
    let o = run(c, "5\n1\n\nq\n");
    let all = format!("{}{}", text(&o.stdout), text(&o.stderr));
    assert!(
        all.contains("local protected history unavailable: chat history is corrupt"),
        "{all}"
    );
    assert!(!all.contains("rvnhist2"), "the old build showed no message");
    assert_eq!(
        std::fs::read(&history).unwrap(),
        before,
        "never written over"
    );
    let moved: Vec<String> = std::fs::read_dir(dd)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("chat_history.json."))
        .collect();
    assert!(moved.is_empty(), "never moved aside: {moved:?}");
    // This build still reads it.
    let entries = raven_core::ChatHistory::load(dd).unwrap().entries;
    assert_eq!(entries[0].body, "rvnhist2");
}

/// Privacy pack PP.15: a profile with an identity on record (the seed and
/// its keystore marker), for `raven lock`.
fn plant_recorded_identity(dir: &Path) {
    plant_identity(dir);
    std::fs::write(dir.join("identity.backend"), b"locked-file\n").unwrap();
}

/// Run to completion, at most `secs` (a command that would wait for good is
/// killed by its own handle and the test fails).
fn run_bounded(mut c: Command, secs: u64) -> Output {
    let mut child = c
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ash");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("ash did not end within {secs} s");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    child.wait_with_output().expect("wait ash")
}

/// `raven lock` without a terminal needs `--yes`, and a debug build needs
/// both login-item lab switches (it never reads or changes the real login
/// item). Nothing is locked either way.
#[test]
fn lock_needs_yes_off_a_terminal_and_the_lab_switches_in_debug() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = ash(dir.path());
    c.arg("lock").arg("--yes");
    let o = run(c, "");
    assert_eq!(code(&o), 1);
    assert!(
        text(&o.stderr).contains("this profile has no identity yet"),
        "{}",
        text(&o.stderr)
    );
    plant_recorded_identity(dir.path());
    let mut c = ash(dir.path());
    c.arg("lock");
    let o = run(c, "y\n");
    assert_eq!(code(&o), 1);
    assert!(
        text(&o.stderr)
            .contains("stdin is not a terminal: pass --yes to lock without the question"),
        "{}",
        text(&o.stderr)
    );
    // The guard (a release build of this test runs the release binary, which
    // has none: it never reads the lab switches).
    if cfg!(debug_assertions) {
        let mut c = ash(dir.path());
        c.args(["lock", "--yes"])
            .env_remove("RAVEN_LAB_LOGIN_ITEM_ROOT")
            .env_remove("RAVEN_LAB_LOGIN_ITEM_TOOLS");
        let o = run(c, "");
        assert_eq!(code(&o), 1);
        assert!(
            text(&o.stderr).contains(
                "this debug build does not read or change login items unless \
                 RAVEN_LAB_LOGIN_ITEM_ROOT and RAVEN_LAB_LOGIN_ITEM_TOOLS are set"
            ),
            "{}",
            text(&o.stderr)
        );
    }
    let mut c = ash(dir.path());
    c.arg("doctor");
    let o = run(c, "");
    assert!(
        text(&o.stdout).contains("lock: locked_by_user=0"),
        "{}",
        text(&o.stdout)
    );
}

/// `raven lock --yes` with no node running and no login item (empty lab
/// folders): Raven is stopped and locked; `raven status` says so first,
/// `raven doctor` keys it, and `raven listen` (which starts raven-node)
/// refuses instead of undoing the lock.
#[test]
fn lock_holds_until_unlock_and_listen_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let lab = tempfile::tempdir().unwrap();
    let (items, tools) = (lab.path().join("items"), lab.path().join("tools"));
    std::fs::create_dir_all(&items).unwrap();
    std::fs::create_dir_all(&tools).unwrap();
    plant_recorded_identity(dir.path());
    let mut c = ash(dir.path());
    add_contact_args(&mut c, &ident(0x22), "Poline", None, "127.0.0.1:9");
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));

    let mut c = ash(dir.path());
    c.args(["lock", "--yes"])
        .env("RAVEN_LAB_LOGIN_ITEM_ROOT", &items)
        .env("RAVEN_LAB_LOGIN_ITEM_TOOLS", &tools);
    let o = run_bounded(c, 60);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert_eq!(
        text(&o.stdout).lines().collect::<Vec<_>>(),
        [
            "Raven is stopped.",
            "Run `raven unlock` to start it again. If Raven is open in another window, close \
             it too. Clear your terminal too: its scrollback may show messages."
        ]
    );

    let mut c = ash(dir.path());
    c.arg("status");
    let o = run(c, "");
    let first = text(&o.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    assert_eq!(
        first,
        "Raven is locked (stopped). Run `raven unlock` to start it again."
    );
    let mut c = ash(dir.path());
    c.arg("doctor");
    let o = run(c, "");
    assert!(
        text(&o.stdout).contains("lock: locked_by_user=1"),
        "{}",
        text(&o.stdout)
    );

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut c = ash(dir.path());
    c.args(["listen", "--listen", &format!("127.0.0.1:{port}")]);
    let o = run_bounded(c, 60);
    assert_eq!(code(&o), 1, "{}", text(&o.stderr));
    assert!(
        text(&o.stderr).contains("Raven is locked. Run `raven unlock` to start it again."),
        "{}",
        text(&o.stderr)
    );
    assert!(!text(&o.stdout).contains("LISTENING"));
    assert!(
        !dir.path().join("raven-node.sock").exists(),
        "no raven-node was started"
    );
}

/// Privacy pack PP.16: a debug build's `raven erase` touches no folder
/// outside `RAVEN_LAB_ERASE_ROOT` (and none without it), a folder that is
/// not a Raven profile is refused in every build, and so is a run without a
/// terminal. Nothing is changed by any refusal.
#[test]
fn guard_refuses_live_profiles() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let profile = root.path().join("a");
    std::fs::create_dir_all(&profile).unwrap();
    plant_recorded_identity(&profile);
    let names = |dir: &Path| {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };
    let before = names(&profile);
    let erase = |root: Option<&Path>| {
        let mut c = ash(&profile);
        c.arg("erase").env_remove("RAVEN_LAB_ERASE_ROOT");
        if let Some(root) = root {
            c.env("RAVEN_LAB_ERASE_ROOT", root);
        }
        run(c, "erase\n")
    };
    if cfg!(debug_assertions) {
        for root in [None, Some(elsewhere.path())] {
            let o = erase(root);
            assert_eq!(code(&o), 1, "{}", text(&o.stderr));
            assert!(
                text(&o.stderr)
                    .contains("this debug build erases only a profile inside RAVEN_LAB_ERASE_ROOT"),
                "{}",
                text(&o.stderr)
            );
        }
    }
    // Inside the root: past the guard, refused without a terminal.
    let o = erase(Some(root.path()));
    assert_eq!(code(&o), 1, "{}", text(&o.stderr));
    assert!(
        text(&o.stderr).contains("raven erase needs a terminal: type erase to confirm."),
        "{}",
        text(&o.stderr)
    );
    // Not a Raven profile (a folder of someone's own files).
    let docs = root.path().join("docs");
    std::fs::create_dir_all(&docs).unwrap();
    std::fs::write(docs.join("contacts.json"), b"[]").unwrap();
    let mut c = ash(&docs);
    c.arg("erase").env("RAVEN_LAB_ERASE_ROOT", root.path());
    let o = run(c, "erase\n");
    assert_eq!(code(&o), 1);
    assert!(
        text(&o.stderr)
            .contains("This folder doesn't look like a Raven profile, so erase won't touch it: "),
        "{}",
        text(&o.stderr)
    );
    assert_eq!(names(&docs), ["contacts.json"]);
    assert_eq!(names(&profile), before, "nothing changed");
}

/// Privacy pack PP.16: while an erase is unfinished every command but
/// `raven erase` refuses the profile before it opens anything (the send
/// path, status, the menu), and nothing is written into it.
#[test]
fn marker_blocks_every_other_entry_point() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("erase_in_progress"), b"raven erase\n").unwrap();
    let unfinished =
        "An erase of this Raven profile did not finish. Run `raven erase` to finish it.";
    for args in [
        &["status"][..],
        &["doctor"],
        &["init"],
        &["inbox"],
        &["send", "--contact", "@bob"],
        &["listen", "--listen", "127.0.0.1:9"],
        &["lock", "--yes"],
        &[],
    ] {
        let mut c = ash(dir.path());
        c.args(args);
        let o = run_bounded(c, 60);
        assert_eq!(code(&o), 1, "{args:?}: {}", text(&o.stderr));
        assert!(
            text(&o.stderr).contains(unfinished),
            "{args:?}: {}",
            text(&o.stderr)
        );
    }
    let names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["erase_in_progress"], "nothing was written");
}
