//! PP.4 tests of the contact book: every reader on a sealed book and on the
//! same book in plain, writes, the fail-closed paths, the writer lock and
//! the long-lived process's cache and hold. Profiles are temp folders with an
//! identity marker; keys come from the test build's lab K_hist (never a
//! keychain item).

use super::*;
use crate::at_rest::MigratePolicy;
use crate::chat_history::{BlockList, ChatHistory};
use crate::identity_store::BACKEND_MARKER_NAME;
use crate::outbox::{ContactAdmission, OutboxCarrier};
use crate::privacy::{self, MigrateOutcome};
use std::time::Duration;

const NOW: u64 = 20_000 * 24 * 60 * 60 * 1000;

fn key(n: u8) -> [u8; 32] {
    [n; 32]
}

fn hex_of(n: u8) -> String {
    hex::encode(key(n))
}

fn pid(seed: u8) -> String {
    crate::p2p_route::local_peer_id(&crate::identity::Identity::from_seed(&[seed; 32]))
}

/// A temp profile with an identity on record (its backend marker only).
pub(crate) fn profile() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(BACKEND_MARKER_NAME), b"locked-file\n").unwrap();
    dir
}

/// Seal `dir` as raven-node's start would (the key file is expected here).
pub(crate) fn seal(dir: &Path) {
    crate::at_rest::tests::expect_key_file(dir);
    let report = privacy::migrate_all(dir, NOW, MigratePolicy::Allow).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::Sealed);
}

/// Bob (verified, every route, a custodian), Carol (verified, listed as
/// Bob's custodian and he as hers), Dave (not verified, hides my IP), Eve
/// (blocked): the fields the fourteen readers read.
pub(crate) fn fixture(dd: &Path) {
    let addr = |n: u8| crate::encode_address(&key(n));
    let rows = serde_json::json!([
        {
            "petname": "Bob", "public_tag": "bob", "address": addr(1), "pub_hex": hex_of(1),
            "pinned": true, "lan_dial": "192.168.1.20:7420",
            "internet_dial": "203.0.113.9:7422", "p2p": pid(1),
            "p2p_via": [format!("/ip4/11.0.0.1/tcp/7423/p2p/{}", pid(1))],
            "custodians": [hex_of(2)],
        },
        {
            "petname": "Carol", "alias": "carol", "address": addr(2), "pub_hex": hex_of(2),
            "pinned": true, "lan_dial": "10.0.0.5:7420", "custodians": [hex_of(1)],
        },
        {
            "petname": "Dave", "address": addr(3), "pub_hex": hex_of(3), "pinned": false,
            "lan_dial": "192.168.1.30:7420", "hide_ip": true,
        },
        { "petname": "Eve", "address": addr(4), "pub_hex": hex_of(4), "pinned": true },
    ]);
    std::fs::write(
        dd.join(CONTACTS_FILE),
        serde_json::to_vec_pretty(&rows).unwrap(),
    )
    .unwrap();
    BlockList {
        pub_hex: vec![hex_of(4)],
    }
    .save(dd)
    .unwrap();
}

/// What every reader of the book answers, as text.
fn readers(dd: &Path) -> Vec<String> {
    let me = key(9);
    let mut out = Vec::new();
    for n in [1u8, 2, 3, 4, 5] {
        let k = key(n);
        out.push(format!(
            "routes {n} {:?}",
            crate::outbox::contact_routes(dd, &k)
        ));
        out.push(format!(
            "pinned {n} {:?}",
            crate::outbox::contact_is_pinned(dd, &k)
        ));
        out.push(format!(
            "admission {n} {:?}",
            crate::outbox::contact_admission(dd, &k)
        ));
        for carrier in [
            OutboxCarrier::Lan,
            OutboxCarrier::Internet,
            OutboxCarrier::P2p,
        ] {
            for source in [None, Some("192.168.1.7"), Some("198.51.100.7")] {
                let source = source.map(|s| s.parse().unwrap());
                out.push(format!(
                    "link {n} {carrier:?} {source:?} {:?}",
                    crate::lan_dispatch::link_admission(dd, &k, carrier, source)
                ));
            }
        }
        out.push(format!(
            "custodians {n} {:?}",
            crate::custody_client::listed_custodians(dd, &k, &me)
        ));
        out.push(format!(
            "p2p ids {n} {:?}",
            crate::outbox::contact_p2p_peer_ids(dd, &hex_of(n))
        ));
    }
    let mut admitted: Vec<String> = crate::outbox::admitted_contact_keys(dd)
        .unwrap()
        .into_iter()
        .collect();
    admitted.sort();
    out.push(format!("admitted {admitted:?}"));
    out.push(format!("gate {:?}", crate::outbox::p2p_gate_peers(dd)));
    out.push(format!(
        "fetch {:?}",
        crate::custody_client::fetch_targets(dd, &me, crate::clock::now_ms())
    ));
    out.push(format!(
        "circle {:?}",
        crate::reach_diag::circle_facts(dd, NOW)
    ));
    out
}

/// The petname and tag history keeps for a message from `n`.
fn history_label(dd: &Path, n: u8, mid: u8) -> (String, String) {
    crate::lan_dispatch::persist_lan_chat_history(
        dd,
        "in",
        &key(n),
        &[mid; 16],
        NOW,
        "delivered",
        b"hi",
    )
    .unwrap();
    let entry = ChatHistory::load(dd)
        .unwrap()
        .entries
        .into_iter()
        .find(|e| e.message_id_hex == hex::encode([mid; 16]))
        .unwrap();
    (entry.peer_petname, entry.peer_tag)
}

#[test]
fn every_reader_sees_the_same_rows_sealed_or_plain() {
    let dir = profile();
    let dd = dir.path();
    fixture(dd);
    let plain = readers(dd);
    let plain_labels = [history_label(dd, 1, 1), history_label(dd, 2, 2)];
    assert_eq!(
        plain_labels,
        [
            ("Bob".to_string(), "bob".to_string()),
            ("Carol".to_string(), "carol".to_string())
        ]
    );
    // Not an empty fixture: the readers saw contacts.
    assert!(
        plain.iter().any(|l| l.starts_with("routes 1 Ok(Some(")),
        "{plain:#?}"
    );
    assert!(plain.iter().any(|l| l.contains("Blocked")), "{plain:#?}");

    seal(dd);
    let raw = std::fs::read(dd.join(CONTACTS_FILE)).unwrap();
    assert!(at_rest::is_sealed(&raw), "the book was not sealed");
    assert_eq!(readers(dd), plain);
    assert_eq!(
        [history_label(dd, 1, 3), history_label(dd, 2, 4)],
        plain_labels
    );
    // Through the process cache too (raven-node).
    enable_process_cache(dd);
    assert_eq!(readers(dd), plain);
}

#[test]
fn writes_are_sealed() {
    #[derive(Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Row {
        petname: String,
        pub_hex: String,
    }
    let rows = vec![
        Row {
            petname: "Bob".into(),
            pub_hex: hex_of(1),
        },
        Row {
            petname: "Zoë".into(),
            pub_hex: hex_of(2),
        },
    ];
    // A plain profile: exactly today's pretty JSON (ash's to_string_pretty).
    let dir = profile();
    let dd = dir.path();
    write_rows(dd, &rows).unwrap();
    assert_eq!(
        std::fs::read(dd.join(CONTACTS_FILE)).unwrap(),
        serde_json::to_string_pretty(&rows).unwrap().into_bytes()
    );
    // A sealed profile: RMS1, and it reads back as the rows.
    seal(dd);
    write_rows(dd, &rows[..1]).unwrap();
    let raw = std::fs::read(dd.join(CONTACTS_FILE)).unwrap();
    assert!(at_rest::is_sealed(&raw));
    assert!(!raw.windows(3).any(|w| w == b"Bob"));
    assert_eq!(read_rows::<Row>(dd).unwrap().unwrap(), rows[..1]);
    // Sealed, but this process lost the key: never a plaintext fallback.
    at_rest::forget_cached_keys(dd);
    assert!(write_rows(dd, &rows).unwrap_err().is_locked());
    assert_eq!(std::fs::read(dd.join(CONTACTS_FILE)).unwrap(), raw);
}

#[test]
fn a_corrupt_sealed_book_fails_closed_never_empty() {
    let dir = profile();
    let dd = dir.path();
    fixture(dd);
    seal(dd);
    let path = dd.join(CONTACTS_FILE);
    let sealed = std::fs::read(&path).unwrap();
    for (what, bytes) in [
        ("a flipped byte", {
            let mut b = sealed.clone();
            let at = b.len() - 20;
            b[at] ^= 0x40;
            b
        }),
        ("truncated", sealed[..30].to_vec()),
        ("another kind", {
            let mut b = sealed.clone();
            b[5] = Kind::LanSeen.code();
            b
        }),
    ] {
        std::fs::write(&path, &bytes).unwrap();
        let err = read_rows::<serde_json::Value>(dd).unwrap_err();
        assert!(matches!(err, BookError::Corrupt(_)), "{what}: {err:?}");
        assert!(
            err.to_string().starts_with("contacts.json corrupt: "),
            "{err}"
        );
        assert_eq!(
            crate::outbox::contact_admission(dd, &key(1)),
            ContactAdmission::Unreadable,
            "{what}"
        );
        assert!(
            crate::outbox::contact_routes(dd, &key(1)).is_err(),
            "{what}"
        );
        assert!(crate::outbox::admitted_contact_keys(dd).is_err(), "{what}");
        assert!(crate::outbox::p2p_gate_peers(dd).is_err(), "{what}");
        assert!(
            crate::custody_client::listed_custodians(dd, &key(1), &key(9)).is_err(),
            "{what}"
        );
        assert!(crate::custody_client::fetch_targets(dd, &key(9), crate::clock::now_ms()).is_err());
        assert!(crate::reach_diag::circle_facts(dd, NOW).is_err(), "{what}");
        assert_eq!(
            crate::lan_dispatch::link_admission(dd, &key(1), OutboxCarrier::Lan, None),
            Err(crate::lan_dispatch::LINK_REFUSED_NOT_CONTACT),
            "{what}"
        );
        assert!(crate::lan_dispatch::persist_lan_chat_history(
            dd,
            "in",
            &key(1),
            &[1; 16],
            NOW,
            "delivered",
            b"hi"
        )
        .is_err());
        // The bytes are left as they were.
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "{what}");
    }
}

/// The quiet reader in raven-core (`contact_label_for_pub`, which names the
/// sender of a received chat in history): a book this process cannot open
/// fails the write, never an empty label written into history. raven-node's
/// and ash's quiet readers have their own cases.
#[test]
fn quiet_readers_fail_their_operation_on_key_unavailable() {
    let dir = profile();
    let dd = dir.path();
    fixture(dd);
    seal(dd);
    assert_eq!(history_label(dd, 1, 1).0, "Bob");
    let sealed = std::fs::read(dd.join(CONTACTS_FILE)).unwrap();
    let persist = |mid: u8| {
        crate::lan_dispatch::persist_lan_chat_history(
            dd,
            "in",
            &key(1),
            &[mid; 16],
            NOW,
            "delivered",
            b"hi",
        )
    };
    let rows_in_history = || ChatHistory::load(dd).unwrap().entries.len();
    let before = rows_in_history();
    // KeyUnavailable: the key is not loaded in this process.
    at_rest::forget_cached_keys(dd);
    let err = persist(2).unwrap_err();
    assert!(err.starts_with("contacts.json: locked ("), "{err}");
    assert_eq!(rows_in_history(), before);
    // StaleKeys: sealed under an epoch this process has not loaded.
    at_rest::keys_load_with(dd, MigratePolicy::Never).unwrap();
    let mut stale = sealed.clone();
    stale[6..10].copy_from_slice(&2u32.to_be_bytes());
    std::fs::write(dd.join(CONTACTS_FILE), &stale).unwrap();
    assert!(read_rows::<serde_json::Value>(dd).unwrap_err().is_locked());
    assert!(persist(3).is_err());
    assert_eq!(rows_in_history(), before);
    // Tampered: a changed byte.
    let mut tampered = sealed.clone();
    let at = tampered.len() - 1;
    tampered[at] ^= 1;
    std::fs::write(dd.join(CONTACTS_FILE), &tampered).unwrap();
    assert!(persist(4).is_err());
    assert_eq!(rows_in_history(), before);
    // Restored: the label is back.
    std::fs::write(dd.join(CONTACTS_FILE), &sealed).unwrap();
    assert_eq!(history_label(dd, 1, 5).0, "Bob");
}

#[test]
fn save_contacts_takes_the_contacts_lock() {
    let dir = profile();
    let dd = dir.path().to_path_buf();
    fixture(&dd);
    let before = std::fs::read(dd.join(CONTACTS_FILE)).unwrap();
    let held = crate::paths::DataDirLock::acquire(&dd, CONTACTS_LOCK).unwrap();
    let writer = {
        let dd = dd.clone();
        std::thread::spawn(move || {
            write_rows(
                &dd,
                &[serde_json::json!({ "petname": "Zed", "pub_hex": hex_of(7) })],
            )
        })
    };
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        std::fs::read(dd.join(CONTACTS_FILE)).unwrap(),
        before,
        "the writer did not wait for the book's lock"
    );
    drop(held);
    writer.join().unwrap().unwrap();
    let rows: Vec<serde_json::Value> = read_rows(&dd).unwrap().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["petname"], "Zed");
    // A read-modify-write under the lock writes through it (no second
    // acquire of the same lock).
    let book = lock(&dd).unwrap();
    let mut rows: Vec<serde_json::Value> = book.read_rows().unwrap().unwrap();
    rows.push(serde_json::json!({ "petname": "Amy", "pub_hex": hex_of(8) }));
    book.write_rows(&rows).unwrap();
    drop(book);
    assert_eq!(
        read_rows::<serde_json::Value>(&dd).unwrap().unwrap().len(),
        2
    );
}

#[test]
fn missing_book_is_the_only_empty_one() {
    let dir = profile();
    let dd = dir.path();
    assert_eq!(read_rows::<serde_json::Value>(dd).unwrap(), None);
    assert_eq!(read_plain(dd).unwrap().as_deref(), None);
    std::fs::write(dd.join(CONTACTS_FILE), b"{not json").unwrap();
    let err = read_rows::<serde_json::Value>(dd).unwrap_err();
    assert!(
        err.to_string().starts_with("contacts.json corrupt: "),
        "today's prefix: {err}"
    );
    std::fs::write(dd.join(CONTACTS_FILE), b"[]").unwrap();
    assert_eq!(
        read_rows::<serde_json::Value>(dd).unwrap(),
        Some(Vec::new())
    );
}

/// raven-node's hold: every read of the book refuses until the key is
/// loaded and the cache enabled; the reload generation moves both times.
#[test]
fn a_held_book_refuses_every_reader_until_released() {
    let dir = profile();
    let dd = dir.path();
    fixture(dd);
    let generation = reload_generation(dd);
    hold(dd, "waiting for the test");
    assert!(reload_generation(dd) > generation);
    let err = read_rows::<serde_json::Value>(dd).unwrap_err();
    assert_eq!(err, BookError::Locked("waiting for the test".into()));
    assert_eq!(
        crate::outbox::contact_admission(dd, &key(1)),
        ContactAdmission::Unreadable
    );
    assert!(lock(dd).unwrap().read_rows::<serde_json::Value>().is_err());
    // Its canonical spelling is held too (a temp folder under a link).
    let canonical = std::fs::canonicalize(dd).unwrap();
    assert!(read_rows::<serde_json::Value>(&canonical)
        .unwrap_err()
        .is_locked());
    let held_at = reload_generation(dd);
    enable_process_cache(dd);
    assert!(reload_generation(dd) > held_at);
    // Another profile's book is not touched (its stamps stay as they are).
    let other = profile();
    assert_eq!(reload_generation(other.path()), 0);
    assert!(matches!(
        crate::outbox::contact_admission(dd, &key(1)),
        ContactAdmission::Allowed(_)
    ));
}

/// The cache re-reads on every stamp change before it answers: a contact
/// removed (or added) by another process is seen by the next admission.
#[test]
fn the_process_cache_rereads_on_a_changed_stamp() {
    let dir = profile();
    let dd = dir.path();
    fixture(dd);
    seal(dd);
    enable_process_cache(dd);
    let allowed = |n: u8| {
        matches!(
            crate::outbox::contact_admission(dd, &key(n)),
            ContactAdmission::Allowed(_)
        )
    };
    assert!(allowed(1) && allowed(2));
    // Remove Bob through the book's writer (another process: the stamp).
    let rows: Vec<serde_json::Value> = read_rows(dd).unwrap().unwrap();
    let kept: Vec<_> = rows
        .into_iter()
        .filter(|r| r["pub_hex"] != hex_of(1))
        .collect();
    write_rows(dd, &kept).unwrap();
    assert!(!allowed(1) && allowed(2));
    // A plain rewrite in place (same file, other bytes): seen as well.
    std::fs::write(
        dd.join(CONTACTS_FILE),
        serde_json::to_vec(&serde_json::json!([{ "pub_hex": hex_of(1), "pinned": true }])).unwrap(),
    )
    .unwrap();
    assert!(allowed(1) && !allowed(2));
    // The block list goes through the same cache, with its own texts.
    BlockList {
        pub_hex: vec![hex_of(1)],
    }
    .save(dd)
    .unwrap();
    assert_eq!(
        crate::outbox::contact_admission(dd, &key(1)),
        ContactAdmission::Blocked
    );
    std::fs::write(crate::chat_history::blocked_path(dd), b"{nope").unwrap();
    let err = BlockList::load_checked(dd).unwrap_err();
    assert!(err.starts_with("block list corrupt: "), "{err}");
    std::fs::remove_file(crate::chat_history::blocked_path(dd)).unwrap();
    assert!(BlockList::load_checked(dd).unwrap().pub_hex.is_empty());
    // A book that went away is no book.
    std::fs::remove_file(dd.join(CONTACTS_FILE)).unwrap();
    assert_eq!(read_rows::<serde_json::Value>(dd).unwrap(), None);
}
