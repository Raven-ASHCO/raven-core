//! The chat controls in the CLI (0.1.1): `raven contact block|unblock|unverify
//! NAME`, `raven chats clear|delete|pin|unpin NAME`. Everything stays on this
//! computer; nothing is sent. No raven-node runs.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use raven_core::chat_prefs::{self, CHAT_PREFS_FILE};
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
        .env("RAVEN_SERVICE_LAN_LISTEN", "127.0.0.1:0")
        .env("RAVEN_LAB_TOR", "0")
        .env("RAVEN_LAB_STUN_DISCOVERY", "0");
    for switch in raven_core::lan_gate::PRIVACY_LAB_SWITCHES {
        c.env_remove(switch);
    }
    c
}

/// Runs `args` on a (non-terminal) stdin with `stdin_text`.
fn run(dir: &Path, args: &[&str], stdin_text: &str) -> Output {
    let mut c = ash(dir);
    c.args(args);
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ash");
    let _ = child.stdin.take().unwrap().write_all(stdin_text.as_bytes());
    child.wait_with_output().expect("wait ash")
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn ok(dir: &Path, args: &[&str]) -> String {
    let o = run(dir, args, "");
    assert_eq!(o.status.code(), Some(0), "{args:?}: {}", text(&o));
    text(&o)
}

fn fails(dir: &Path, args: &[&str]) -> String {
    let o = run(dir, args, "");
    assert_eq!(o.status.code(), Some(1), "{args:?}: {}", text(&o));
    text(&o)
}

/// A profile with a planted locked-file identity and Bob, verified.
fn profile_with_bob() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let seed = dir.path().join("identity.seed");
    std::fs::write(&seed, [0x5au8; 32]).unwrap();
    // The seed file is owner-only where modes exist (Windows has none).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let bob = Identity::from_seed(&[0x42; 32]);
    let key = hex::encode(bob.public_key_bytes());
    let fp = device_fingerprint_v1(&bob.public_key_bytes());
    ok(
        dir.path(),
        &[
            "contact",
            "add",
            "--address",
            &bob.address(),
            "--pub-hex",
            &key,
            "--petname",
            "Bob",
            "--verify-fp",
            &fp,
        ],
    );
    (dir, key)
}

fn pinned_in_book(dir: &Path) -> bool {
    std::fs::read_to_string(dir.join("contacts.json"))
        .unwrap()
        .contains("\"pinned\": true")
}

#[test]
fn block_and_unblock_a_saved_contact_by_name() {
    let (dir, key) = profile_with_bob();
    let dd = dir.path();
    // Piped stdin cannot answer the question: nothing is blocked.
    let o = run(dd, &["contact", "block", "Bob"], "yes\n");
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("--yes"), "{}", text(&o));
    assert!(!raven_core::BlockList::load_checked(dd)
        .unwrap()
        .is_blocked(&key));

    let said = ok(dd, &["contact", "block", "Bob", "--yes"]);
    assert!(said.contains("blocked Bob on this computer"), "{said}");
    assert!(raven_core::BlockList::load_checked(dd)
        .unwrap()
        .is_blocked(&key));
    // The contact stays, still verified.
    assert!(pinned_in_book(dd));

    let said = ok(dd, &["contact", "unblock", "Bob"]);
    assert!(said.contains("unblocked Bob"), "{said}");
    assert!(!raven_core::BlockList::load_checked(dd)
        .unwrap()
        .is_blocked(&key));
    let said = fails(dd, &["contact", "unblock", "Bob"]);
    assert!(said.contains("Bob is not blocked"), "{said}");
    // Naming both ways is refused; an unknown name too.
    fails(dd, &["contact", "unblock", "Bob", "--pub-hex", &key]);
    fails(dd, &["contact", "block", "Nobody", "--yes"]);
}

#[test]
fn unverify_keeps_the_contact_and_asks_for_the_words_again() {
    let (dir, _) = profile_with_bob();
    let dd = dir.path();
    assert!(pinned_in_book(dd));
    let said = ok(dd, &["contact", "unverify", "Bob", "--yes"]);
    assert!(said.contains("not verified any more"), "{said}");
    assert!(!pinned_in_book(dd));
    assert!(std::fs::read_to_string(dd.join("contacts.json"))
        .unwrap()
        .contains("Bob"));
    let said = fails(dd, &["contact", "unverify", "Bob", "--yes"]);
    assert!(said.contains("Bob is not verified"), "{said}");
}

#[test]
fn pin_delete_and_remove_keep_the_chat_list_on_this_computer() {
    let (dir, key) = profile_with_bob();
    let dd = dir.path();
    let chat = chat_prefs::contact_chat(&key);

    ok(dd, &["chats", "pin", "Bob"]);
    assert!(chat_prefs::load(dd).unwrap().is_pinned(&chat));
    ok(dd, &["chats", "unpin", "--petname", "Bob"]);
    assert!(!dd.join(CHAT_PREFS_FILE).exists(), "nothing left: no file");

    // Clear keeps the chat in the list; delete takes it out until a new
    // message.
    let said = ok(dd, &["chats", "clear", "Bob", "--yes"]);
    assert!(said.contains("Deleted your chat with Bob"), "{said}");
    assert!(!said.contains("leaves your chat list"), "{said}");
    assert!(!dd.join(CHAT_PREFS_FILE).exists());
    let said = ok(dd, &["chats", "delete", "--petname", "Bob", "--yes"]);
    assert!(said.contains("leaves your chat list"), "{said}");
    assert!(chat_prefs::load(dd).unwrap().is_hidden(&chat, 0));
    // One chat at a time.
    fails(dd, &["chats", "delete", "Bob", "--petname", "Bob", "--yes"]);
    fails(dd, &["chats", "pin"]);

    // Removing the contact forgets its chat's pin and deletion.
    ok(dd, &["chats", "pin", "Bob"]);
    ok(dd, &["contact", "remove", "--petname", "Bob", "--yes"]);
    assert!(!dd.join(CHAT_PREFS_FILE).exists());
}
