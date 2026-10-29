//! The handoff store (P5.19): the file's protection and pragmas, the
//! version and damage rules, the forwarder's API, the prune, and the at-rest
//! shapes (keyed in a sealed profile; the moves of the privacy passes).
//! The store takes the RSO1 as opaque bytes: the handler tests in
//! `friend_custody/tests/handoff_custodian.rs` feed it real objects.

use super::*;
use crate::sqlite_rebuild::{self as rebuild, Shape};
use rusqlite::Connection;

const NOW: u64 = 1_800_000_000_000;
const HOUR: u64 = 3_600_000;

fn key(n: u8) -> [u8; 32] {
    [n; 32]
}

fn rso1(n: u8) -> Vec<u8> {
    let mut bytes = vec![n; 300];
    bytes[..4].copy_from_slice(b"RSO1");
    bytes
}

/// Object `n` (digest `[n; 32]`, tag `[n; 16]`) from `depositor` for
/// `next_hop`, admitted at `at`.
fn put(
    store: &mut HandoffStore,
    n: u8,
    next_hop: u8,
    depositor: u8,
    at: u64,
    expires: u64,
) -> CustodyCode {
    store
        .forward(
            &[n; 32],
            &key(next_hop),
            &key(depositor),
            &[n; 16],
            &rso1(n),
            expires,
            at,
        )
        .unwrap()
}

fn raw(dir: &Path) -> Connection {
    Connection::open(handoff_db_path(dir)).unwrap()
}

/// `(user_version, shape)` of the store as it is on disk.
fn shape(dir: &Path) -> (i64, Shape) {
    let conn = raw(dir);
    (
        rebuild::user_version(&conn).unwrap(),
        rebuild::shape(&conn, "custody_forward_v1", "kh_object_digest").unwrap(),
    )
}

fn digests(due: &[DueForward]) -> Vec<u8> {
    due.iter().map(|d| d.digest[0]).collect()
}

#[test]
fn store_is_private_lazy_and_reopens_identically() {
    let dir = tempfile::tempdir().unwrap();
    let path = handoff_db_path(dir.path());
    assert!(HandoffStore::open_existing(dir.path()).unwrap().is_none());
    assert!(!path.exists(), "open_existing creates nothing");
    let mut store = HandoffStore::open_or_create(dir.path()).unwrap();
    assert_eq!(
        put(&mut store, 1, 0xB1, 0xA1, NOW, NOW + HOUR),
        CustodyCode::Ok
    );
    {
        let conn = store.conn_for_tests();
        let pragma = |name: &str| -> String {
            conn.query_row(&format!("PRAGMA {name}"), [], |r| {
                r.get::<_, rusqlite::types::Value>(0)
            })
            .map(|v| match v {
                rusqlite::types::Value::Integer(n) => n.to_string(),
                rusqlite::types::Value::Text(t) => t,
                other => format!("{other:?}"),
            })
            .unwrap()
        };
        assert_eq!(pragma("synchronous"), "2", "FULL");
        assert_eq!(pragma("busy_timeout"), "10000");
        assert_eq!(pragma("journal_mode"), "wal");
        assert_eq!(pragma("auto_vacuum"), "2", "INCREMENTAL");
        assert_eq!(pragma("secure_delete"), "1");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for suffix in ["", "-wal"] {
            let file = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
            let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", file.display());
        }
    }
    #[cfg(windows)]
    {
        let sid = crate::win_acl::user_sid().unwrap();
        assert!(crate::win_acl::read_dacl(&path)
            .unwrap()
            .is_owner_only(crate::win_acl::Kind::File, sid));
    }
    drop(store);
    assert_eq!(shape(dir.path()), (1, Shape::Clear));
    let store = HandoffStore::open_existing(dir.path()).unwrap().unwrap();
    let due = store.forward_due(NOW, 10).unwrap();
    assert_eq!(
        due,
        [DueForward {
            digest: [1; 32],
            next_hop: key(0xB1),
            depositor: key(0xA1),
            store_tag: [1; 16],
            rso1: rso1(1),
            expires_at_ms: NOW + HOUR,
            attempts: 0,
            last_code: None,
        }]
    );
}

#[test]
fn a_newer_store_is_refused_and_a_damaged_one_quarantined() {
    let dir = tempfile::tempdir().unwrap();
    drop(HandoffStore::open_or_create(dir.path()).unwrap());
    raw(dir.path())
        .execute_batch("PRAGMA user_version = 3;")
        .unwrap();
    for opened in [
        HandoffStore::open_existing(dir.path()).map(|_| ()),
        HandoffStore::open_or_create(dir.path()).map(|_| ()),
    ] {
        let e = opened.unwrap_err();
        assert!(e.contains("newer"), "{e}");
    }
    assert_eq!(shape(dir.path()).0, 3, "a refused store is left as it is");

    let dir = tempfile::tempdir().unwrap();
    let path = handoff_db_path(dir.path());
    std::fs::write(&path, b"this is not a database ".repeat(200)).unwrap();
    let mut store = HandoffStore::open_existing(dir.path()).unwrap().unwrap();
    assert_eq!(
        put(&mut store, 2, 0xB1, 0xA1, NOW, NOW + HOUR),
        CustodyCode::Ok
    );
    drop(store);
    let aside: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.unwrap().file_name().into_string().ok())
        .filter(|name| name.starts_with("custody_handoff.sqlite.corrupt-"))
        .collect();
    assert_eq!(aside.len(), 1, "{aside:?}");
    assert_eq!(
        crate::at_rest::registry::rule_for(&aside[0]).map(|r| r.rule),
        Some(crate::at_rest::registry::Rule::KeyedSqlite)
    );
    // The prune drops the copy once its rows would all have expired.
    let later = crate::clock::now_ms() + 9 * 24 * HOUR;
    maintain(dir.path(), later).unwrap();
    assert!(std::fs::read_dir(dir.path()).unwrap().all(|e| !e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .contains(".corrupt-")));
}

/// forward_due (oldest first, limited), mark_handed (never due again; a
/// re-FORWARD is a duplicate), mark_refused, backoff, and the counts.
#[test]
fn the_forwarder_api() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = HandoffStore::open_or_create(dir.path()).unwrap();
    for n in [3u8, 1, 2] {
        assert_eq!(
            put(&mut store, n, 0xB1, 0xA1, NOW + u64::from(n), NOW + HOUR),
            CustodyCode::Ok
        );
    }
    let at = NOW + 10;
    assert_eq!(digests(&store.forward_due(at, 10).unwrap()), [1, 2, 3]);
    assert_eq!(digests(&store.forward_due(at, 2).unwrap()), [1, 2]);
    let hop = key(0xB1);
    assert!(store.mark_handed(&[1; 32], &hop, CustodyCode::Ok).unwrap());
    assert_eq!(digests(&store.forward_due(at, 10).unwrap()), [2, 3]);
    assert_eq!(
        put(&mut store, 1, 0xB1, 0xA1, at, NOW + HOUR),
        CustodyCode::Duplicate
    );
    assert!(store
        .mark_refused(&[2; 32], &hop, CustodyCode::RefusedObject)
        .unwrap());
    assert!(store
        .backoff(&[3; 32], &hop, NOW + 60_000, CustodyCode::TagUnknown)
        .unwrap());
    assert!(store.forward_due(at, 10).unwrap().is_empty());
    // A trigger for that next hop (it was seen, a kick) makes the
    // backed-off row due at once; another next hop's trigger does not, and
    // neither brings back a handed or refused row.
    let early = |h: &[u8; 32]| *h == hop;
    assert_eq!(
        digests(&store.forward_due_for(at, 10, &early).unwrap()),
        [3]
    );
    assert!(store
        .forward_due_for(at, 10, &|h| *h == key(0xB2))
        .unwrap()
        .is_empty());
    let due = store.forward_due(NOW + 60_000, 10).unwrap();
    assert_eq!(digests(&due), [3]);
    assert_eq!(
        (due[0].attempts, due[0].last_code),
        (1, Some(CustodyCode::TagUnknown as u8))
    );
    // Nothing is due once it expired.
    assert!(store.forward_due(NOW + HOUR, 10).unwrap().is_empty());
    assert!(!store.mark_handed(&[9; 32], &hop, CustodyCode::Ok).unwrap());
    let usage = store.usage().unwrap();
    assert_eq!(
        (usage.pending, usage.handed, usage.refused, usage.tags),
        (1, 1, 1, 0)
    );
    assert_eq!(usage.bytes, 3 * rso1(1).len() as i64);
}

#[test]
fn maintain_drops_expired_and_unpinned_rows_and_purge_empties() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = HandoffStore::open_or_create(dir.path()).unwrap();
    assert_eq!(
        put(&mut store, 1, 0xB1, 0xA1, NOW, NOW + HOUR),
        CustodyCode::Ok
    );
    assert_eq!(
        put(&mut store, 2, 0xB2, 0xA1, NOW, NOW + HOUR),
        CustodyCode::Ok
    );
    assert_eq!(
        put(&mut store, 3, 0xB1, 0xA2, NOW, NOW + 600_000),
        CustodyCode::Ok
    );
    assert_eq!(
        put(&mut store, 4, 0xB1, 0xA3, NOW, NOW + HOUR),
        CustodyCode::Ok
    );
    for (recipient, tag) in [(0xC1, 0x51), (0xC2, 0x52)] {
        let outcome = store
            .register(&key(recipient), &[([tag; 16], NOW + HOUR)], NOW)
            .unwrap();
        assert_eq!(outcome.accepted, 1);
    }
    // 0xB2 (a next hop), 0xA3 (a depositor) and 0xC2 (a recipient) are no
    // longer pinned.
    let gone = [key(0xB2), key(0xA3), key(0xC2)];
    let removed = store.maintain(NOW, &|k| !gone.contains(k)).unwrap();
    assert_eq!(removed, 3);
    assert_eq!(digests(&store.forward_due(NOW, 10).unwrap()), [1, 3]);
    assert_eq!(
        store.tag_recipient(&[0x52; 16], NOW).unwrap(),
        TagState::Unknown
    );
    // Expired rows go.
    let removed = store.maintain(NOW + 1_200_000, &|_| true).unwrap();
    assert_eq!(removed, 1);
    let usage = store.usage().unwrap();
    assert_eq!((usage.pending, usage.tags), (1, 1));
    assert_eq!(store.purge().unwrap(), 2);
    assert_eq!(store.usage().unwrap(), HandoffUsage::default());
}

/// Review handoff-2: the durable prune drops a party's rows only while the
/// contact book and the block list can be read. Held (raven-node's start
/// in a profile it seals, until the key is loaded) or corrupt, every party
/// would read as no contact and every forward row and tag registration go:
/// only expired rows go then. Readable again, a party that is no contact
/// any more still loses its rows.
#[test]
fn maintain_drops_no_party_while_the_book_cannot_be_read() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let book = |keys: &[u8]| {
        let rows: Vec<serde_json::Value> = keys
            .iter()
            .map(|n| {
                serde_json::json!({
                    "pub_hex": hex::encode(key(*n)),
                    "pinned": true,
                    "lan_dial": "192.168.1.9:7420",
                })
            })
            .collect();
        std::fs::write(
            d.join("contacts.json"),
            serde_json::Value::Array(rows).to_string(),
        )
        .unwrap();
    };
    book(&[0xA1, 0xB1, 0xC1]);
    let mut store = HandoffStore::open_or_create(d).unwrap();
    assert_eq!(
        put(&mut store, 1, 0xB1, 0xA1, NOW, NOW + HOUR),
        CustodyCode::Ok
    );
    assert_eq!(
        put(&mut store, 2, 0xB1, 0xA1, NOW, NOW + 600_000),
        CustodyCode::Ok
    );
    let outcome = store
        .register(&key(0xC1), &[([0x51; 16], NOW + HOUR)], NOW)
        .unwrap();
    assert_eq!(outcome.accepted, 1);
    drop(store);
    let held = |d: &Path| {
        let usage = HandoffStore::open_existing(d)
            .unwrap()
            .unwrap()
            .usage()
            .unwrap();
        (usage.pending, usage.tags)
    };
    // A corrupt block list: nobody is known to be gone.
    let blocked = crate::chat_history::blocked_path(d);
    std::fs::write(&blocked, b"{ not a block list").unwrap();
    assert_eq!(maintain(d, NOW).unwrap(), 0);
    assert_eq!(held(d), (2, 1));
    std::fs::remove_file(&blocked).unwrap();
    // The book held: the same, but an expired row still goes.
    crate::contact_book::hold(d, "the at-rest key is loading");
    assert_eq!(maintain(d, NOW + 700_000).unwrap(), 1);
    assert_eq!(held(d), (1, 1));
    // Readable again: the recipient no longer a contact loses its tag.
    crate::contact_book::enable_process_cache(d);
    book(&[0xA1, 0xB1]);
    assert_eq!(maintain(d, NOW + 700_000).unwrap(), 1);
    assert_eq!(held(d), (1, 0));
}

/// Every byte of the store files, for the scan.
fn file_bytes(dir: &Path) -> Vec<u8> {
    let path = handoff_db_path(dir);
    let mut bytes = std::fs::read(&path).unwrap();
    if let Ok(wal) = std::fs::read(format!("{}-wal", path.display())) {
        bytes.extend(wal);
    }
    bytes
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// In a sealed profile the store is keyed and sealed: neither the parties
/// nor the digest nor the object are in the file, raw or hex. The way back
/// (unseal), the migration forward and a re-key keep every row.
#[test]
fn a_sealed_store_is_keyed_and_moves_both_ways() {
    let dir = crate::contact_book::tests::profile();
    let dd = dir.path();
    crate::contact_book::tests::seal(dd);
    let digest = [0xD7; 32];
    let mut store = HandoffStore::open_or_create(dd).unwrap();
    assert_eq!(shape(dd), (2, Shape::Keyed));
    let code = store
        .forward(
            &digest,
            &key(0xB7),
            &key(0xA7),
            &[0x57; 16],
            &rso1(0x5C),
            NOW + HOUR,
            NOW,
        )
        .unwrap();
    assert_eq!(code, CustodyCode::Ok);
    let outcome = store
        .register(&key(0xC7), &[([0x58; 16], NOW + HOUR)], NOW)
        .unwrap();
    assert_eq!(outcome.accepted, 1);
    let bytes = file_bytes(dd);
    for secret in [key(0xA7), key(0xB7), key(0xC7), digest] {
        assert!(!contains(&bytes, &secret), "{}", hex::encode(secret));
        assert!(!contains(&bytes, hex::encode(secret).as_bytes()));
    }
    assert!(!contains(&bytes, &rso1(0x5C)[4..68]), "the RSO1 is sealed");
    drop(store);
    let check = |dd: &Path| {
        let store = HandoffStore::open_existing(dd).unwrap().unwrap();
        let due = store.forward_due(NOW, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(
            (
                due[0].digest,
                due[0].next_hop,
                due[0].depositor,
                &due[0].rso1
            ),
            (digest, key(0xB7), key(0xA7), &rso1(0x5C))
        );
        assert_eq!(
            store.tag_recipient(&[0x58; 16], NOW).unwrap(),
            TagState::Live(key(0xC7))
        );
    };
    // The way back: clear columns, every row kept.
    let back = unseal(dd).unwrap();
    assert_eq!((back.rows, back.dropped), (2, 0));
    assert_eq!(shape(dd), (1, Shape::Clear));
    let depositor: Vec<u8> = raw(dd)
        .query_row("SELECT depositor FROM custody_forward_v1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(depositor, key(0xA7));
    assert!(needs_migration(dd));
    // Forward again (the privacy passes), then keyed anew.
    assert!(migrate(dd).unwrap());
    assert_eq!(shape(dd), (2, Shape::Keyed));
    assert!(!needs_migration(dd));
    check(dd);
    let again = rekey(dd).unwrap();
    assert_eq!((again.rows, again.dropped), (2, 0));
    assert_eq!(shape(dd), (2, Shape::Keyed));
    check(dd);
    let current = crate::at_rest::keys_cached(dd).unwrap().current_epoch();
    assert_eq!(rows_off_epoch(dd, current).unwrap(), 0);
    assert_eq!(reseal_rows(dd).unwrap(), rebuild::RowReseal::default());
    assert!(!contains(&file_bytes(dd), &key(0xA7)));
}

/// A clear store made before the profile was sealed moves with the sealing
/// pass (`privacy::migrate_all`).
#[test]
fn a_clear_store_moves_when_the_profile_is_sealed() {
    let dir = crate::contact_book::tests::profile();
    let dd = dir.path();
    let mut store = HandoffStore::open_or_create(dd).unwrap();
    assert_eq!(
        put(&mut store, 6, 0xB6, 0xA6, NOW, NOW + HOUR),
        CustodyCode::Ok
    );
    drop(store);
    assert_eq!(shape(dd), (1, Shape::Clear));
    crate::contact_book::tests::seal(dd);
    assert_eq!(shape(dd), (2, Shape::Keyed));
    let store = HandoffStore::open_existing(dd).unwrap().unwrap();
    assert_eq!(digests(&store.forward_due(NOW, 10).unwrap()), [6]);
    drop(store);
    assert!(!contains(&file_bytes(dd), &key(0xA6)));
}
