//! PP.12 tests of the app store at rest: a sealed profile's store keys its
//! senders (schema 3); a schema-2 store moves there with the rebuild recipe
//! and back. Schema 2 is written and read with the PP.1 snapshot's exact SQL
//! (what every older build runs). Profiles are temp folders whose keys come
//! from the test build's lab K_hist (never a keychain item).

use super::tests::{item, profile, Setup, TestSealer};
use super::*;
use crate::sqlite_rebuild::{fault, Fault};

const NOW: u64 = 1_800_000_000_000;

// ── The PP.1 snapshot's exact SQL (what an older build does) ──

/// The batch an older build runs on a store below schema 2 (a racing older
/// process that read the version before a migration runs it as well).
const OLDER_BATCH: &str = "PRAGMA journal_mode=WAL;
     CREATE TABLE IF NOT EXISTS app_inbox(
       sender_device BLOB NOT NULL, message_id BLOB NOT NULL, app_id BLOB NOT NULL,
       sender_identity BLOB NOT NULL, content_type TEXT NOT NULL,
       created_at_ms INTEGER NOT NULL, received_at_ms INTEGER NOT NULL,
       expires_at_ms INTEGER NOT NULL, body_len INTEGER NOT NULL, cert_hash BLOB NOT NULL,
       sealed BLOB NOT NULL,
       PRIMARY KEY(sender_device, message_id), UNIQUE(sender_device, app_id));
     CREATE TABLE IF NOT EXISTS app_tombstones(
       sender_device BLOB NOT NULL, message_id BLOB NOT NULL, app_id BLOB NOT NULL,
       disposition TEXT NOT NULL CHECK(disposition IN
         ('done','rejected','expired','revoked','not_contact','blocked')),
       at_ms INTEGER NOT NULL, PRIMARY KEY(sender_device, message_id));
     CREATE INDEX IF NOT EXISTS app_tombstones_app ON app_tombstones(sender_device, app_id);
     CREATE TABLE IF NOT EXISTS app_outbox(
       peer_identity BLOB NOT NULL, client_ref TEXT NOT NULL, peer_device BLOB NOT NULL,
       content_type TEXT NOT NULL, app_id BLOB NOT NULL, body_sha256 BLOB NOT NULL,
       message_id BLOB NOT NULL UNIQUE, session_id BLOB NOT NULL,
       object_digest BLOB NOT NULL, created_at_ms INTEGER NOT NULL,
       expires_at_ms INTEGER NOT NULL,
       state TEXT NOT NULL CHECK(state IN
         ('queued','sent','delivered','expired','failed','cancelled')),
       last_error_code TEXT NOT NULL DEFAULT '', attempt_seq INTEGER NOT NULL,
       updated_at_ms INTEGER NOT NULL,
       PRIMARY KEY(peer_identity, client_ref));
     CREATE TABLE IF NOT EXISTS app_consumer(
       id INTEGER PRIMARY KEY CHECK(id = 1), consumer TEXT NOT NULL,
       bound_at_ms INTEGER NOT NULL);
     CREATE TABLE IF NOT EXISTS app_pair_attempts(
       peer_device BLOB NOT NULL, at_ms INTEGER NOT NULL);
     CREATE TABLE IF NOT EXISTS app_quarantine(
       sender_device BLOB NOT NULL, message_id BLOB NOT NULL, app_id BLOB NOT NULL,
       sender_identity BLOB NOT NULL, content_type TEXT NOT NULL,
       created_at_ms INTEGER NOT NULL, received_at_ms INTEGER NOT NULL,
       expires_at_ms INTEGER NOT NULL, body_len INTEGER NOT NULL, cert_hash BLOB NOT NULL,
       sealed BLOB NOT NULL, quarantined_at_ms INTEGER NOT NULL,
       PRIMARY KEY(sender_device, message_id));
     PRAGMA user_version = 2;";

/// An older build's `AppStore::open`: it refuses anything above schema 2,
/// and runs its batch below it.
fn older_open(dir: &Path) -> Result<Connection, String> {
    let conn = Connection::open(app_store_path(dir)).map_err(|e| e.to_string())?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if version > 2 {
        return Err("APP_STORE: app_channel.sqlite3 is newer than this build".into());
    }
    if version < 2 {
        conn.execute_batch(OLDER_BATCH).map_err(|e| e.to_string())?;
    }
    Ok(conn)
}

/// An older build's inbox insert.
fn older_ingest(conn: &Connection, it: &AppInboxItem) -> rusqlite::Result<usize> {
    let sealed = TestSealer.seal(&serde_json::to_vec(it).unwrap()).unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO app_inbox (sender_device, message_id, app_id,
           sender_identity, content_type, created_at_ms, received_at_ms, expires_at_ms,
           body_len, cert_hash, sealed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            it.sender_device.as_slice(),
            it.message_id.as_slice(),
            it.app_id.as_slice(),
            it.sender_identity.as_slice(),
            it.content_type,
            ms(it.created_at_ms),
            ms(it.received_at_ms),
            ms(it.expires_at_ms),
            it.body.len() as i64,
            it.cert_hash.as_slice(),
            sealed,
        ],
    )
}

/// Every row of the three sender tables, as an older build reads them.
type OlderRows = (Vec<Vec<rusqlite::types::Value>>, usize);

fn older_rows(conn: &Connection) -> OlderRows {
    let mut all = Vec::new();
    for (table, columns) in [
        (
            "app_inbox",
            "sender_device, message_id, app_id, sender_identity, content_type, created_at_ms, \
             received_at_ms, expires_at_ms, body_len, cert_hash, sealed",
        ),
        (
            "app_tombstones",
            "sender_device, message_id, app_id, disposition, at_ms",
        ),
        (
            "app_quarantine",
            "sender_device, message_id, app_id, sender_identity, content_type, created_at_ms, \
             received_at_ms, expires_at_ms, body_len, cert_hash, sealed, quarantined_at_ms",
        ),
    ] {
        let n = columns.split(',').count();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT rowid, {columns} FROM {table} ORDER BY rowid"
            ))
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                (0..=n)
                    .map(|i| r.get::<_, rusqlite::types::Value>(i))
                    .collect::<Result<Vec<_>, _>>()
            })
            .unwrap();
        all.extend(rows.map(Result::unwrap));
    }
    let outbox: i64 = conn
        .query_row("SELECT COUNT(*) FROM app_outbox", [], |r| r.get(0))
        .unwrap();
    (all, usize::try_from(outbox).unwrap())
}

/// The fixture's three inbox items (two senders), in page order.
fn items() -> Vec<AppInboxItem> {
    [(1u8, 1u8), (1, 2), (2, 3)]
        .into_iter()
        .map(|(sender, mid)| AppInboxItem {
            received_at_ms: NOW + u64::from(mid),
            ..item(sender, mid, "a2a-request/1")
        })
        .collect()
}

/// A sealed profile with a schema-2 store an older build wrote: three inbox
/// items, a tombstone (sender 3), a quarantined row (sender 4), an outbox
/// record and a pairing attempt.
fn sealed_with_clear_store() -> tempfile::TempDir {
    let dir = profile(Setup::SealedFresh);
    let conn = older_open(dir.path()).unwrap();
    for it in items() {
        older_ingest(&conn, &it).unwrap();
    }
    conn.execute(
        "INSERT OR REPLACE INTO app_tombstones
           (sender_device, message_id, app_id, disposition, at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            [3u8; 32].as_slice(),
            [4u8; 16].as_slice(),
            [5u8; 16].as_slice(),
            "done",
            ms(NOW)
        ],
    )
    .unwrap();
    let bad = item(4, 6, "a2a-request/1");
    older_ingest(&conn, &bad).unwrap();
    conn.execute_batch(
        "INSERT OR REPLACE INTO app_quarantine SELECT sender_device, message_id,
           app_id, sender_identity, content_type, created_at_ms, received_at_ms,
           expires_at_ms, body_len, cert_hash, sealed, 7
         FROM app_inbox WHERE message_id = x'06060606060606060606060606060606';
         DELETE FROM app_inbox WHERE message_id = x'06060606060606060606060606060606';
         INSERT INTO app_pair_attempts (peer_device, at_ms) VALUES (x'0909', 1);",
    )
    .unwrap();
    dir
}

fn schema(dir: &Path) -> (i64, Shape) {
    let conn = Connection::open(app_store_path(dir)).unwrap();
    (
        rebuild::user_version(&conn).unwrap(),
        rebuild::shape(&conn, "app_inbox", KEYED_COLUMN).unwrap(),
    )
}

/// What the store serves, and what it remembers: the page, whether the
/// tombstoned and the quarantined rows are still known.
fn served(dir: &Path) -> (Vec<AppInboxItem>, Admit, i64) {
    let mut store = AppStore::open(dir, &TestSealer).unwrap();
    let page = store.page("rdap", false, 10, NOW, &|_| Ok(None)).unwrap();
    let tombstoned = store
        .admit(&[3; 32], &[4; 16], &[0xEE; 16], "a2a-request/1", 1)
        .unwrap();
    let quarantined: i64 = store
        .conn
        .query_row("SELECT COUNT(*) FROM app_quarantine", [], |r| r.get(0))
        .unwrap();
    (page, tombstoned, quarantined)
}

fn want() -> (Vec<AppInboxItem>, Admit, i64) {
    (items(), Admit::AlreadyDone, 1)
}

fn rowids(dir: &Path, table: &str, column: &str) -> Vec<(i64, Vec<u8>)> {
    let conn = Connection::open(app_store_path(dir)).unwrap();
    let mut stmt = conn
        .prepare(&format!(
            "SELECT rowid, {column} FROM {table} ORDER BY rowid"
        ))
        .unwrap();
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

fn file_or_wal_holds(dir: &Path, marker: &[u8]) -> bool {
    let path = app_store_path(dir);
    let mut wal = path.clone().into_os_string();
    wal.push("-wal");
    let hex = hex::encode(marker);
    [path, PathBuf::from(wal)].iter().any(|p| {
        std::fs::read(p).is_ok_and(|bytes| {
            bytes.windows(marker.len()).any(|w| w == marker)
                || bytes
                    .windows(hex.len())
                    .any(|w| w.eq_ignore_ascii_case(hex.as_bytes()))
        })
    })
}

#[test]
fn byte_scan_finds_no_sender_device_or_identity() {
    for migrated in [false, true] {
        let dir = if migrated {
            profile(Setup::Plain)
        } else {
            profile(Setup::SealedFresh)
        };
        let markers: [[u8; 32]; 3] = rand::random();
        let [sender, identity, cert] = markers;
        let it = |mid: u8| AppInboxItem {
            sender_device: sender,
            sender_identity: identity,
            cert_hash: cert,
            received_at_ms: NOW + u64::from(mid),
            ..item(1, mid, "a2a-request/1")
        };
        {
            let mut store = AppStore::open(dir.path(), &TestSealer).unwrap();
            for mid in 1..=3 {
                assert!(store.ingest(&it(mid)).unwrap());
            }
            // One served and acknowledged (a tombstone), one set aside.
            store
                .conn
                .execute(
                    "UPDATE app_inbox SET sealed = x'00' WHERE message_id = ?1",
                    params![[3u8; 16].as_slice()],
                )
                .unwrap();
            let page = store.page("rdap", false, 10, NOW, &|_| Ok(None)).unwrap();
            assert_eq!(page.len(), 2);
            assert!(store
                .ack("rdap", &sender, &[1; 16], Disposition::Done, NOW)
                .unwrap());
        }
        if migrated {
            assert!(
                file_or_wal_holds(dir.path(), &sender),
                "the fixture is clear"
            );
            crate::contact_book::tests::seal(dir.path());
        }
        let store = AppStore::open(dir.path(), &TestSealer).unwrap();
        assert!(store.keyed);
        assert!(crate::paths::checkpoint_truncate(&store.conn)
            .unwrap()
            .completed());
        drop(store);
        for (what, marker) in [
            ("sender device", sender),
            ("sender identity", identity),
            ("certificate hash", cert),
        ] {
            assert!(
                !file_or_wal_holds(dir.path(), &marker),
                "the {what} is readable in the store (migrated: {migrated})"
            );
        }
        // Still served, tombstoned and set aside as before.
        let mut store = AppStore::open(dir.path(), &TestSealer).unwrap();
        let page = store.page("rdap", false, 10, NOW, &|_| Ok(None)).unwrap();
        assert_eq!(page, vec![it(2)]);
        assert_eq!(
            store
                .admit(&sender, &[1; 16], &[0xEE; 16], "a2a-request/1", 1)
                .unwrap(),
            Admit::AlreadyDone
        );
    }
}

#[test]
fn old_version_store_migrates_with_rows_intact() {
    let dir = sealed_with_clear_store();
    let before: Vec<_> = ["app_inbox", "app_tombstones", "app_quarantine"]
        .iter()
        .map(|table| rowids(dir.path(), table, "message_id"))
        .collect();
    assert_eq!(schema(dir.path()), (CLEAR_VERSION, Shape::Clear));
    assert!(needs_migration(dir.path()));
    assert!(migrate(dir.path()).unwrap());
    assert!(!migrate(dir.path()).unwrap(), "once");
    assert_eq!(schema(dir.path()), (SCHEMA_VERSION, Shape::Keyed));
    // Rowids kept in every table.
    let after: Vec<_> = ["app_inbox", "app_tombstones", "app_quarantine"]
        .iter()
        .map(|table| rowids(dir.path(), table, "message_id"))
        .collect();
    assert_eq!(after, before);
    assert_eq!(served(dir.path()), want());
    let conn = Connection::open(app_store_path(dir.path())).unwrap();
    assert_eq!(
        rebuild::recorded(&conn, STORE).unwrap(),
        Some((SCHEMA_VERSION, false))
    );
    // The other tables are as they were.
    let pairs: i64 = conn
        .query_row("SELECT COUNT(*) FROM app_pair_attempts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(pairs, 1);
}

#[test]
fn migration_crash_at_each_statement_recovers() {
    let mut stops = 0;
    for at in 0.. {
        let dir = sealed_with_clear_store();
        let older = older_rows(&older_open(dir.path()).unwrap());
        fault::arm(Fault::CrashAt(at));
        let opened = AppStore::open(dir.path(), &TestSealer);
        if fault::armed() {
            fault::disarm();
            assert!(opened.unwrap().keyed);
            break;
        }
        stops += 1;
        let err = opened.err().expect("an injected stop fails the open");
        assert!(err.contains("injected stop"), "{err}");
        match schema(dir.path()) {
            (CLEAR_VERSION, Shape::Clear) => {
                assert_eq!(
                    older_rows(&older_open(dir.path()).unwrap()),
                    older,
                    "stop at {at}"
                );
            }
            (SCHEMA_VERSION, Shape::Keyed) => assert!(scrub_pending(dir.path()), "stop at {at}"),
            other => panic!("stop at {at} left {other:?}"),
        }
        assert_eq!(served(dir.path()), want(), "stop at {at}");
        finish_scrub(dir.path());
        assert!(!scrub_pending(dir.path()), "stop at {at}");
    }
    assert!(stops >= 17, "only {stops} statements");
}

#[test]
fn migration_rolls_back_on_count_mismatch() {
    let dir = sealed_with_clear_store();
    let older = older_rows(&older_open(dir.path()).unwrap());
    fault::arm(Fault::DropOneRow);
    let err = AppStore::open(dir.path(), &TestSealer).err().unwrap();
    assert!(
        err.contains("app_inbox would hold 2 rows instead of 3"),
        "{err}"
    );
    assert_eq!(schema(dir.path()), (CLEAR_VERSION, Shape::Clear));
    assert_eq!(older_rows(&older_open(dir.path()).unwrap()), older);
    assert_eq!(served(dir.path()), want());
}

#[test]
fn vacuum_deferred_while_a_reader_is_open() {
    let dir = sealed_with_clear_store();
    let reader = Connection::open(app_store_path(dir.path())).unwrap();
    reader
        .execute_batch("BEGIN; SELECT COUNT(*) FROM app_inbox;")
        .unwrap();
    assert!(AppStore::open(dir.path(), &TestSealer).unwrap().keyed);
    assert!(scrub_pending(dir.path()));
    assert_eq!(finish_scrub(dir.path()), Some(false), "still in the way");
    reader.execute_batch("COMMIT;").unwrap();
    drop(reader);
    assert_eq!(finish_scrub(dir.path()), Some(true));
    assert!(!scrub_pending(dir.path()));
    assert_eq!(served(dir.path()), want());
}

#[test]
fn disk_full_during_migration_leaves_the_old_store() {
    let dir = sealed_with_clear_store();
    fault::arm(Fault::NoSpace);
    let store = AppStore::open(dir.path(), &TestSealer).unwrap();
    assert!(!store.keyed, "deferred: the store works as it is");
    drop(store);
    assert_eq!(schema(dir.path()), (CLEAR_VERSION, Shape::Clear));
    let dir = sealed_with_clear_store();
    let older = older_rows(&older_open(dir.path()).unwrap());
    fault::arm(Fault::DiskFull);
    let err = AppStore::open(dir.path(), &TestSealer).err().unwrap();
    assert!(err.contains("full"), "{err}");
    assert_eq!(schema(dir.path()), (CLEAR_VERSION, Shape::Clear));
    assert_eq!(older_rows(&older_open(dir.path()).unwrap()), older);
    assert_eq!(served(dir.path()), want());
}

#[test]
fn older_code_refuses_the_migrated_store() {
    let dir = sealed_with_clear_store();
    assert!(migrate(dir.path()).unwrap());
    assert_eq!(
        older_open(dir.path()).err().unwrap(),
        "APP_STORE: app_channel.sqlite3 is newer than this build"
    );
}

#[test]
fn older_open_restamps_v1_and_new_build_recovers() {
    let dir = sealed_with_clear_store();
    assert!(migrate(dir.path()).unwrap());
    let before = rowids(dir.path(), "app_inbox", "kh_sender");
    // An older process that read a version below 2 before the migration now
    // runs its batch: every CREATE is a no-op, the stamp is not.
    let older = Connection::open(app_store_path(dir.path())).unwrap();
    older.execute_batch(OLDER_BATCH).unwrap();
    assert_eq!(schema(dir.path()), (CLEAR_VERSION, Shape::Keyed));
    let err = older_ingest(&older, &item(9, 9, "a2a-request/1")).unwrap_err();
    assert!(err.to_string().contains("sender_device"), "{err}");
    drop(older);
    assert!(!migrate(dir.path()).unwrap(), "stamped again, not migrated");
    assert_eq!(schema(dir.path()), (SCHEMA_VERSION, Shape::Keyed));
    assert_eq!(rowids(dir.path(), "app_inbox", "kh_sender"), before);
    assert_eq!(served(dir.path()), want());
}

#[test]
fn reverse_migration_round_trip() {
    let dir = sealed_with_clear_store();
    let older = older_rows(&older_open(dir.path()).unwrap());
    assert!(migrate(dir.path()).unwrap());
    let back = unseal(dir.path()).unwrap();
    assert_eq!((back.rows, back.dropped, back.scrub_pending), (5, 0, false));
    assert_eq!(schema(dir.path()), (CLEAR_VERSION, Shape::Clear));
    assert_eq!(older_rows(&older_open(dir.path()).unwrap()), older);
    assert!(unseal(dir.path()).unwrap().already);
    assert_eq!(served(dir.path()), want(), "forward again");
    assert_eq!(schema(dir.path()), (SCHEMA_VERSION, Shape::Keyed));
}

#[test]
fn a_sealed_store_without_its_key_fails_closed() {
    let dir = profile(Setup::SealedFresh);
    crate::at_rest::forget_cached_keys(dir.path());
    let err = AppStore::open(dir.path(), &MetadataOnly).err().unwrap();
    assert!(err.starts_with(STORE_KEY_UNAVAILABLE), "{err}");
    assert!(!app_store_path(dir.path()).exists(), "nothing created");
    crate::at_rest::keys_load_with(dir.path(), crate::at_rest::MigratePolicy::Never).unwrap();
    AppStore::open(dir.path(), &TestSealer)
        .unwrap()
        .ingest(&item(1, 1, "a2a-request/1"))
        .unwrap();
    crate::at_rest::forget_cached_keys(dir.path());
    let err = AppStore::open(dir.path(), &MetadataOnly).err().unwrap();
    assert!(err.starts_with(STORE_KEY_UNAVAILABLE), "{err}");
    crate::at_rest::keys_load_with(dir.path(), crate::at_rest::MigratePolicy::Never).unwrap();
    let mut store = AppStore::open(dir.path(), &TestSealer).unwrap();
    assert_eq!(
        store
            .page("c", false, 10, NOW, &|_| Ok(None))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn rotation_reseals_every_meta_and_the_old_epoch_can_go() {
    let dir = sealed_with_clear_store();
    assert!(migrate(dir.path()).unwrap());
    // Three inbox rows, the tombstone and the quarantined row.
    assert_eq!(meta_rows_off_epoch(dir.path(), 1).unwrap(), 0);
    crate::at_rest::add_epoch(dir.path(), 1).unwrap();
    assert_eq!(meta_rows_off_epoch(dir.path(), 2).unwrap(), 5);
    let resealed = reseal_rows(dir.path()).unwrap();
    // Five metas; the three bodies are the test sealer's, which no epoch or
    // chat-history key opens.
    assert_eq!((resealed.resealed, resealed.unreadable), (5, 3));
    assert_eq!(meta_rows_off_epoch(dir.path(), 2).unwrap(), 0);
    crate::at_rest::drop_old_epochs(dir.path()).unwrap();
    assert_eq!(served(dir.path()), want());
}

/// A cursor names the sender in clear; in schema 3 the order is by the
/// keyed sender, and paging with the cursor still visits every item once.
#[test]
fn the_cursor_pages_every_item_once() {
    for setup in [Setup::Plain, Setup::SealedFresh] {
        let dir = profile(setup);
        let mut store = AppStore::open(dir.path(), &TestSealer).unwrap();
        for sender in 1..=6u8 {
            let it = AppInboxItem {
                received_at_ms: NOW,
                ..item(sender, sender, "a2a-request/1")
            };
            assert!(store.ingest(&it).unwrap());
        }
        let mut seen = Vec::new();
        let mut after = None;
        loop {
            let query = PageQuery {
                content_type: None,
                after,
                limit: 2,
                byte_budget: usize::MAX,
            };
            let page = store
                .page_query("c", false, &query, NOW, &|_| Ok(None))
                .unwrap();
            seen.extend(page.items.iter().map(|it| it.sender_device[0]));
            after = page.next;
            if !page.more {
                break;
            }
        }
        seen.sort_unstable();
        assert_eq!(seen, [1, 2, 3, 4, 5, 6], "{setup:?}");
    }
}

/// "Timing within 10%" (PP.12): admit, ingest, four pages, the
/// acknowledgements and the upkeep of 48 items on a sealed profile's store
/// against a plain one, best of five. As for owed ACKs
/// (`owed_acks::tests::timing_within_ten_percent`) the bound is the added
/// time per item (60 µs), and the ratio is printed. Run by hand
/// (`--release -- --ignored --nocapture`).
#[test]
#[ignore]
fn timing_within_ten_percent() {
    fn run(dir: &Path) -> std::time::Duration {
        let started = std::time::Instant::now();
        let mut store = AppStore::open(dir, &TestSealer).unwrap();
        for n in 0..48u8 {
            let it = item(n % 3, n, "a2a-request/1");
            store
                .admit(
                    &it.sender_device,
                    &it.message_id,
                    &it.app_id,
                    &it.content_type,
                    10,
                )
                .unwrap();
            store.ingest(&it).unwrap();
        }
        for _ in 0..4 {
            store.page("c", false, 64, NOW, &|_| Ok(None)).unwrap();
        }
        for n in 0..48u8 {
            store
                .ack("c", &[n % 3; 32], &[n; 16], Disposition::Done, NOW)
                .unwrap();
        }
        store.maintain(NOW + 9 * 86_400_000).unwrap();
        started.elapsed()
    }
    let (plain, sealed) = (profile(Setup::Plain), profile(Setup::SealedFresh));
    let (mut best_plain, mut best_sealed) = (std::time::Duration::MAX, std::time::Duration::MAX);
    for _ in 0..5 {
        best_plain = best_plain.min(run(plain.path()));
        best_sealed = best_sealed.min(run(sealed.path()));
    }
    let ratio = best_sealed.as_secs_f64() / best_plain.as_secs_f64();
    let per_item = best_sealed.saturating_sub(best_plain) / 48;
    println!(
        "app store: plain {best_plain:?}, sealed {best_sealed:?}, ratio {ratio:.3}, \
         added per item {per_item:?}"
    );
    assert!(
        per_item <= std::time::Duration::from_micros(60),
        "sealing adds {per_item:?} per item"
    );
}
