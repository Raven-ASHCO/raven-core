//! Tests of the owed-ACK store. The suite runs on a plain profile's clear
//! store, a sealed profile's new schema-2 store and one migrated from
//! schema 1 (PP.12). The migration tests write and read schema 1 with the
//! PP.1 snapshot's exact SQL (what every older build runs). Profiles are
//! temp folders whose keys come from the test build's lab K_hist (never a
//! keychain item).

use super::*;
use crate::paths::scrub_test;
use crate::sqlite_rebuild::{fault, Fault};

const NOW: u64 = 1_800_000_000_000;
const HOUR: u64 = 3_600_000;

fn record(store: &mut OwedAcks, peer: u8, d: u8, sid: Option<[u8; 32]>) -> Result<(), OwedError> {
    store.record(
        &[peer; 32],
        sid,
        &[d; 32],
        &[d; 300],
        NOW + 60_000,
        Origin::Relayed,
        NOW,
    )
}

/// Where the suite runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Setup {
    /// A profile that is not sealed: schema 1, as before the pack.
    Plain,
    /// A sealed profile's first store: created at schema 2.
    SealedFresh,
    /// A schema-1 store from before the profile was sealed, migrated by the
    /// sealing pass.
    Migrated,
}

const SETUPS: [Setup; 3] = [Setup::Plain, Setup::SealedFresh, Setup::Migrated];

fn profile(setup: Setup) -> tempfile::TempDir {
    let dir = crate::contact_book::tests::profile();
    match setup {
        Setup::Plain => {}
        Setup::SealedFresh => crate::contact_book::tests::seal(dir.path()),
        Setup::Migrated => {
            drop(older_open_at(&owed_acks_path(dir.path())).unwrap());
            crate::contact_book::tests::seal(dir.path());
            assert_eq!(schema(dir.path()), (SCHEMA_VERSION, Shape::Keyed));
        }
    }
    dir
}

// ── The PP.1 snapshot's exact SQL (what an older build does) ──

/// The batch every build before PP.12 runs at each open, after its version
/// check, outside a transaction.
const OLDER_BATCH: &str = "PRAGMA journal_mode=WAL;
     PRAGMA synchronous=FULL;
     CREATE TABLE IF NOT EXISTS owed_acks_v1 (
       ack_digest BLOB PRIMARY KEY NOT NULL CHECK(length(ack_digest)=32),
       peer BLOB NOT NULL CHECK(length(peer)=32),
       session_id BLOB CHECK(session_id IS NULL OR length(session_id)=32),
       bytes BLOB NOT NULL,
       expires_at_ms INTEGER NOT NULL,
       origin INTEGER NOT NULL,
       recorded_at_ms INTEGER NOT NULL);
     CREATE INDEX IF NOT EXISTS idx_owed_peer ON owed_acks_v1(peer);
     CREATE TABLE IF NOT EXISTS owed_ack_held_v1 (
       ack_digest BLOB NOT NULL, custodian BLOB NOT NULL,
       PRIMARY KEY (ack_digest, custodian));
     PRAGMA user_version = 1;";

/// An older build's `OwedAcks::open_at`: its user_version check (it refuses
/// anything above 1), its integrity check, then the batch.
fn older_open_at(path: &Path) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    conn.busy_timeout(std::time::Duration::from_secs(10))
        .map_err(|e| e.to_string())?;
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if version > 1 {
        return Err("owed_acks.sqlite is newer than this build".into());
    }
    let ok: String = conn
        .query_row("PRAGMA quick_check", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if ok != "ok" {
        return Err("owed_acks.sqlite failed its integrity check".into());
    }
    conn.execute_batch(OLDER_BATCH).map_err(|e| e.to_string())?;
    Ok(conn)
}

/// An older build's `OwedAcks::open`: a file it cannot use (a newer schema
/// among them) is renamed `owed_acks.sqlite.corrupt-<ms>`, its sidecars are
/// deleted, and a new empty clear store starts. `true` when it set one aside.
fn older_open(dir: &Path) -> (Connection, bool) {
    let path = owed_acks_path(dir);
    match older_open_at(&path) {
        Ok(conn) => (conn, false),
        Err(e) if unusable(&e) => {
            let aside = path.with_extension(format!("sqlite.corrupt-{}", crate::clock::now_ms()));
            std::fs::rename(&path, &aside).unwrap();
            for side in ["-wal", "-shm"] {
                let mut p = path.clone().into_os_string();
                p.push(side);
                let _ = std::fs::remove_file(PathBuf::from(p));
            }
            (older_open_at(&path).unwrap(), true)
        }
        Err(e) => panic!("{e}"),
    }
}

/// An older build's insert.
fn older_record(conn: &Connection, row: &Row) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO owed_acks_v1
           (ack_digest, peer, session_id, bytes, expires_at_ms, origin, recorded_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            row.digest.as_slice(),
            row.peer.as_slice(),
            row.session.map(|s| s.to_vec()),
            row.bytes,
            ms(row.expires),
            row.origin as u8,
            ms(row.recorded),
        ],
    )
}

/// An older build's listing, in its order.
fn older_rows(conn: &Connection) -> Vec<Row> {
    let mut stmt = conn
        .prepare(
            "SELECT ack_digest, peer, session_id, bytes, expires_at_ms, origin, recorded_at_ms
             FROM owed_acks_v1 ORDER BY recorded_at_ms, ack_digest",
        )
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok(Row {
                digest: r.get::<_, Vec<u8>>(0)?.try_into().unwrap(),
                peer: r.get::<_, Vec<u8>>(1)?.try_into().unwrap(),
                session: r
                    .get::<_, Option<Vec<u8>>>(2)?
                    .map(|s| s.try_into().unwrap()),
                bytes: r.get(3)?,
                expires: u64::try_from(r.get::<_, i64>(4)?).unwrap(),
                origin: Origin::from_i64(r.get(5)?),
                recorded: u64::try_from(r.get::<_, i64>(6)?).unwrap(),
            })
        })
        .unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

fn older_held(conn: &Connection) -> Vec<([u8; 32], [u8; 32])> {
    let mut stmt = conn
        .prepare(
            "SELECT ack_digest, custodian FROM owed_ack_held_v1 ORDER BY ack_digest, custodian",
        )
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?.try_into().unwrap(),
                r.get::<_, Vec<u8>>(1)?.try_into().unwrap(),
            ))
        })
        .unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

/// One owed ACK as the fixture writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    digest: [u8; 32],
    peer: [u8; 32],
    session: Option<[u8; 32]>,
    bytes: Vec<u8>,
    expires: u64,
    origin: Origin,
    recorded: u64,
}

fn fixture_rows() -> Vec<Row> {
    let row = |d: u8, peer: u8, session: Option<[u8; 32]>, origin, recorded| Row {
        digest: [d; 32],
        peer: [peer; 32],
        session,
        bytes: vec![d; 200 + usize::from(d)],
        expires: NOW + 5 * HOUR + u64::from(d),
        origin,
        recorded,
    };
    vec![
        row(0x11, 0xA1, Some([0x51; 32]), Origin::Link, NOW - 3_000),
        row(0x12, 0xA1, None, Origin::Relayed, NOW - 2_000),
        row(0x13, 0xA2, None, Origin::Prepared, NOW - 1_000),
    ]
}

/// The custodian marks of the fixture.
const FIXTURE_HELD: [([u8; 32], [u8; 32]); 2] =
    [([0x11; 32], [0xC1; 32]), ([0x11; 32], [0xC2; 32])];

fn expected(rows: &[Row]) -> Vec<OwedAck> {
    rows.iter()
        .map(|row| OwedAck {
            ack_digest: row.digest,
            peer: row.peer,
            session_id: row.session,
            bytes: row.bytes.clone(),
            expires_at_ms: row.expires,
            origin: row.origin,
            held_by: FIXTURE_HELD
                .iter()
                .filter(|(d, _)| *d == row.digest)
                .map(|(_, c)| *c)
                .collect(),
        })
        .collect()
}

/// A sealed profile with a schema-1 store an older build wrote (the
/// fixture's three ACKs and two custodian marks).
fn sealed_with_clear_store() -> tempfile::TempDir {
    let dir = profile(Setup::SealedFresh);
    let conn = older_open_at(&owed_acks_path(dir.path())).unwrap();
    for row in fixture_rows() {
        older_record(&conn, &row).unwrap();
    }
    for (d, c) in FIXTURE_HELD {
        conn.execute(
            "INSERT INTO owed_ack_held_v1 (ack_digest, custodian) VALUES (?1, ?2)",
            params![d.as_slice(), c.as_slice()],
        )
        .unwrap();
    }
    dir
}

fn raw(dir: &Path) -> Connection {
    Connection::open(owed_acks_path(dir)).unwrap()
}

/// `(user_version, shape)` of the store as it is on disk.
fn schema(dir: &Path) -> (i64, Shape) {
    let conn = raw(dir);
    (
        rebuild::user_version(&conn).unwrap(),
        rebuild::shape(&conn, ACKS, KEYED_COLUMN).unwrap(),
    )
}

fn rowids(dir: &Path, column: &str) -> Vec<(i64, Vec<u8>)> {
    let conn = raw(dir);
    let mut stmt = conn
        .prepare(&format!(
            "SELECT rowid, {column} FROM owed_acks_v1 ORDER BY rowid"
        ))
        .unwrap();
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

fn keys_of(dir: &Path) -> Arc<MetaKeys> {
    at_rest::keys_cached(dir).unwrap()
}

/// The store's main file or its WAL holds `marker` (as bytes or hex).
fn file_or_wal_holds(dir: &Path, marker: &[u8]) -> bool {
    let path = owed_acks_path(dir);
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

// ── The suite, on every setup ──

#[test]
fn record_is_idempotent_fills_session_and_lists_in_order() {
    for setup in SETUPS {
        let dir = profile(setup);
        let (mut store, rebuilt) = OwedAcks::open(dir.path()).unwrap();
        assert!(!rebuilt);
        assert_eq!(store.keyed(), setup != Setup::Plain, "{setup:?}");
        record(&mut store, 1, 10, None).unwrap();
        record(&mut store, 1, 10, Some([9; 32])).unwrap();
        record(&mut store, 1, 11, None).unwrap();
        store.add_held(&[10; 32], &[0xC0; 32]).unwrap();
        store.add_held(&[10; 32], &[0xC0; 32]).unwrap();
        // Only for an ACK the table owes.
        store.add_held(&[0x77; 32], &[0xC0; 32]).unwrap();
        let list = store.list(NOW).unwrap();
        assert_eq!(list.len(), 2, "{setup:?}");
        assert_eq!(list[0].session_id, Some([9; 32]));
        assert_eq!(list[0].held_by, vec![[0xC0; 32]]);
        assert_eq!(list[0].bytes, vec![10; 300]);
        assert_eq!(list[0].origin, Origin::Relayed);
        assert_eq!(list[0].expires_at_ms, NOW + 60_000);
        assert_eq!(list[1].ack_digest, [11; 32]);
        assert_eq!(store.clear(&[[10; 32]]).unwrap(), 1);
        assert_eq!(store.list(NOW).unwrap().len(), 1);
        // Expired entries are dropped by list (the exact expiry decides,
        // whatever the coarse hour says).
        assert!(store.list(NOW + 60_000).unwrap().is_empty(), "{setup:?}");
        assert_eq!(store.fill().unwrap().0, 0);
    }
}

#[test]
fn full_pushes_back_and_never_evicts() {
    for setup in SETUPS {
        let dir = profile(setup);
        let (mut store, _) = OwedAcks::open(dir.path()).unwrap();
        for i in 0..MAX_OWED_PER_PEER {
            let mut d = [0u8; 32];
            d[..8].copy_from_slice(&(i as u64).to_be_bytes());
            store
                .record(&[1; 32], None, &d, b"ack", NOW + 60_000, Origin::Link, NOW)
                .unwrap();
        }
        assert!(!store.has_room(&[1; 32]).unwrap());
        assert!(store.has_room(&[2; 32]).unwrap());
        assert!(matches!(
            record(&mut store, 1, 0xEE, None),
            Err(OwedError::Full)
        ));
        assert_eq!(store.list(NOW).unwrap().len(), MAX_OWED_PER_PEER as usize);
        record(&mut store, 2, 0xEE, None).unwrap();
        assert_eq!(
            store.drop_peer(&[1; 32]).unwrap(),
            MAX_OWED_PER_PEER as usize,
            "{setup:?}"
        );
        assert!(store.has_room(&[1; 32]).unwrap());
        assert_eq!(store.list(NOW).unwrap().len(), 1);
    }
}

#[test]
fn corrupt_file_is_set_aside_and_rebuild_is_signalled() {
    for setup in [Setup::Plain, Setup::SealedFresh] {
        let dir = profile(setup);
        std::fs::write(
            owed_acks_path(dir.path()),
            b"not a database at all, really not",
        )
        .unwrap();
        let (mut store, rebuilt) = OwedAcks::open(dir.path()).unwrap();
        assert!(rebuilt);
        assert_eq!(store.keyed(), setup != Setup::Plain);
        assert!(store.list(NOW).unwrap().is_empty());
        let aside = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().contains(".corrupt-"));
        assert!(aside);
    }
    assert!(!Origin::Rebuilt.may_deposit());
    assert!(Origin::Relayed.may_deposit());
}

/// CI.1: the set-aside copies the unusable bytes aside and keeps the store
/// file itself (its inode) for the fresh store. A connection another opener
/// made to the old file just before then shares the fresh store's -wal and
/// -shm with it under SQLite's locks; a renamed-aside file's connection
/// shared them by name only, and reset or deleted them under the fresh
/// store (under load, `concurrent_openers_set_a_corrupt_file_aside_once`
/// failed between one run in 60 and one in 8).
#[cfg(unix)]
#[test]
fn a_set_aside_keeps_the_store_file_and_copies_its_bytes_aside() {
    use std::os::unix::fs::MetadataExt;
    for setup in [Setup::Plain, Setup::SealedFresh] {
        let dir = profile(setup);
        let path = owed_acks_path(dir.path());
        std::fs::write(&path, b"not a database at all").unwrap();
        let inode = std::fs::metadata(&path).unwrap().ino();
        let (_, rebuilt) = OwedAcks::open(dir.path()).unwrap();
        assert!(rebuilt, "{setup:?}");
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode, "{setup:?}");
        let asides = set_asides(dir.path());
        assert_eq!(asides.len(), 1, "{setup:?}");
        assert_eq!(std::fs::read(&asides[0]).unwrap(), b"not a database at all");
    }
}

#[test]
fn concurrent_openers_set_a_corrupt_file_aside_once() {
    for setup in [Setup::Plain, Setup::SealedFresh] {
        let dir = profile(setup);
        std::fs::write(owed_acks_path(dir.path()), b"not a database at all").unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (path, barrier) = (dir.path().to_path_buf(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    OwedAcks::open(&path).map(|(_, rebuilt)| rebuilt)
                })
            })
            .collect();
        let rebuilt: Vec<bool> = threads
            .into_iter()
            .map(|t| t.join().unwrap().unwrap())
            .collect();
        // A later opener finds the fresh file under the lock and keeps it.
        assert_eq!(rebuilt.iter().filter(|r| **r).count(), 1, "{rebuilt:?}");
        let aside = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".corrupt-"))
            .count();
        assert_eq!(aside, 1, "{setup:?}");
    }
}

/// Part of the race above (P4.30's N1): two first opens of a fresh file
/// race on `PRAGMA journal_mode=WAL` and the schema, and SQLite answers the
/// one that comes second BUSY at once, without waiting its busy timeout.
/// The open tries again, briefly, and gets the store.
#[test]
fn an_open_answered_busy_at_once_tries_again() {
    for setup in [Setup::Plain, Setup::SealedFresh] {
        let dir = profile(setup);
        // The other first opener, in the middle of its schema: it holds the
        // write lock of the fresh file, still in rollback mode.
        let other = Connection::open(owed_acks_path(dir.path())).unwrap();
        other
            .execute_batch("BEGIN IMMEDIATE; CREATE TABLE racing (x INTEGER);")
            .unwrap();
        let done = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            other.execute_batch("ROLLBACK").unwrap();
        });
        let started = std::time::Instant::now();
        let (mut store, rebuilt) = OwedAcks::open(dir.path()).unwrap();
        assert!(started.elapsed() < BUSY_WAIT, "{setup:?}");
        assert!(!rebuilt, "{setup:?}");
        done.join().unwrap();
        assert_eq!(store.keyed(), setup != Setup::Plain);
        record(&mut store, 1, 1, None).unwrap();
        assert_eq!(store.list(NOW).unwrap().len(), 1, "{setup:?}");
    }
}

#[test]
fn open_existing_creates_nothing() {
    for setup in [Setup::Plain, Setup::SealedFresh] {
        let dir = profile(setup);
        assert!(OwedAcks::open_existing(dir.path()).unwrap().is_none());
        assert!(!owed_acks_path(dir.path()).exists());
    }
}

#[test]
fn secure_delete_is_on_after_open() {
    for setup in SETUPS {
        let dir = profile(setup);
        let (store, _) = OwedAcks::open(dir.path()).unwrap();
        assert_eq!(scrub_test::secure_delete(&store.conn), 1, "{setup:?}");
    }
}

/// PP.2: the owed-ACK prune overwrites an expired ACK, and its own
/// checkpoint takes that into the main file and empties the WAL. (In a
/// sealed profile the bytes never reach the file in clear at all:
/// `byte_scan_finds_no_peer_key_or_custodian`.)
#[test]
fn a_deleted_row_leaves_no_bytes_after_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let path = owed_acks_path(dir.path());
    let marker = scrub_test::marker();
    let (mut store, _) = OwedAcks::open(dir.path()).unwrap();
    store
        .record(
            &[1; 32],
            None,
            &[2; 32],
            &marker,
            NOW + 60_000,
            Origin::Link,
            NOW,
        )
        .unwrap();
    scrub_test::assert_written(&store.conn, &path, &marker);
    assert!(store.list(NOW + 60_000).unwrap().is_empty());
    scrub_test::assert_scrubbed(&path, &marker);
}

// ── PP.12: the sealed store and its migration ──

#[test]
fn byte_scan_finds_no_peer_key_or_custodian() {
    let markers = |n: u8| -> [[u8; 32]; 4] {
        let mut m: [[u8; 32]; 4] = rand::random();
        for (i, marker) in m.iter_mut().enumerate() {
            marker[0] = n.wrapping_add(i as u8);
        }
        m
    };
    // A store sealed from its first row, and one migrated from schema 1.
    for migrated in [false, true] {
        let dir = profile(Setup::SealedFresh);
        let [peer, digest, custodian, bytes] = markers(u8::from(migrated));
        if migrated {
            let conn = older_open_at(&owed_acks_path(dir.path())).unwrap();
            let row = Row {
                digest,
                peer,
                session: None,
                bytes: bytes.to_vec(),
                expires: NOW + HOUR,
                origin: Origin::Relayed,
                recorded: NOW,
            };
            older_record(&conn, &row).unwrap();
            conn.execute(
                "INSERT INTO owed_ack_held_v1 (ack_digest, custodian) VALUES (?1, ?2)",
                params![digest.as_slice(), custodian.as_slice()],
            )
            .unwrap();
            crate::paths::checkpoint_truncate(&conn).unwrap();
            drop(conn);
            assert!(file_or_wal_holds(dir.path(), &peer), "the fixture is clear");
        }
        let (mut store, _) = OwedAcks::open(dir.path()).unwrap();
        assert!(store.keyed());
        if !migrated {
            store
                .record(
                    &peer,
                    None,
                    &digest,
                    &bytes,
                    NOW + HOUR,
                    Origin::Relayed,
                    NOW,
                )
                .unwrap();
            store.add_held(&digest, &custodian).unwrap();
        }
        let list = store.list(NOW).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!((list[0].peer, list[0].ack_digest), (peer, digest));
        assert_eq!(list[0].held_by, vec![custodian]);
        assert_eq!(list[0].bytes, bytes);
        assert!(crate::paths::checkpoint_truncate(&store.conn)
            .unwrap()
            .completed());
        drop(store);
        for (what, marker) in [
            ("peer key", peer),
            ("ack digest", digest),
            ("custodian", custodian),
            ("ack bytes", bytes),
        ] {
            assert!(
                !file_or_wal_holds(dir.path(), &marker),
                "the {what} is readable in the store (migrated: {migrated})"
            );
        }
    }
}

#[test]
fn old_version_store_migrates_with_rows_intact() {
    let dir = sealed_with_clear_store();
    let before = rowids(dir.path(), "ack_digest");
    assert_eq!(schema(dir.path()), (CLEAR_VERSION, Shape::Clear));
    let (mut store, _) = OwedAcks::open(dir.path()).unwrap();
    assert!(store.keyed());
    assert_eq!(store.list(NOW).unwrap(), expected(&fixture_rows()));
    drop(store);
    assert_eq!(schema(dir.path()), (SCHEMA_VERSION, Shape::Keyed));
    // Rowids kept: each row has the rowid it had, under its keyed digest.
    let keys = keys_of(dir.path());
    let after = rowids(dir.path(), "kh_ack_digest");
    let mapped: Vec<(i64, Vec<u8>)> = before
        .iter()
        .map(|(rowid, digest)| (*rowid, kh_digest(&keys, digest).to_vec()))
        .collect();
    assert_eq!(after, mapped);
    assert_eq!(
        rebuild::recorded(&raw(dir.path()), STORE).unwrap(),
        Some((SCHEMA_VERSION, false)),
        "recorded, and scrubbed"
    );
    // The sealing pass of a sealed profile does it eagerly too.
    let dir = sealed_with_clear_store();
    assert!(needs_migration(dir.path()));
    assert!(migrate(dir.path()).unwrap());
    assert!(!needs_migration(dir.path()));
    assert!(!migrate(dir.path()).unwrap(), "once");
}

#[test]
fn migration_crash_at_each_statement_recovers() {
    let rows = fixture_rows();
    let mut stops = 0;
    for at in 0.. {
        let dir = sealed_with_clear_store();
        fault::arm(Fault::CrashAt(at));
        let opened = OwedAcks::open(dir.path());
        if fault::armed() {
            // Past the last statement: the migration went through.
            fault::disarm();
            assert!(opened.unwrap().0.keyed());
            break;
        }
        stops += 1;
        let err = opened.err().expect("an injected stop fails the open");
        assert!(err.to_string().contains("injected stop"), "{err}");
        assert!(!unusable(&err.to_string()), "never set aside: {err}");
        // Either the old store as it was, or the new one complete.
        match schema(dir.path()) {
            (CLEAR_VERSION, Shape::Clear) => {
                assert_eq!(older_rows(&raw(dir.path())), rows, "stop at {at}");
                assert_eq!(older_held(&raw(dir.path())).len(), FIXTURE_HELD.len());
            }
            (SCHEMA_VERSION, Shape::Keyed) => {
                assert!(scrub_pending(dir.path()), "stop at {at}: scrub left");
            }
            other => panic!("stop at {at} left {other:?}"),
        }
        let (mut store, _) = OwedAcks::open(dir.path()).unwrap();
        assert_eq!(store.list(NOW).unwrap(), expected(&rows), "stop at {at}");
        drop(store);
        finish_scrub(dir.path());
        assert!(!scrub_pending(dir.path()), "stop at {at}");
    }
    // The tables, every row, the checks and the commit: each was a stop.
    assert!(stops >= 15, "only {stops} statements");
}

#[test]
fn migration_rolls_back_on_count_mismatch() {
    let dir = sealed_with_clear_store();
    fault::arm(Fault::DropOneRow);
    let err = OwedAcks::open(dir.path())
        .err()
        .expect("the count check stops it");
    assert!(
        err.to_string().contains("would hold 2 rows instead of 3"),
        "{err}"
    );
    assert!(!unusable(&err.to_string()));
    assert_eq!(schema(dir.path()), (CLEAR_VERSION, Shape::Clear));
    assert_eq!(older_rows(&raw(dir.path())), fixture_rows());
    assert_eq!(rebuild::recorded(&raw(dir.path()), STORE).unwrap(), None);
    let (mut store, _) = OwedAcks::open(dir.path()).unwrap();
    assert_eq!(store.list(NOW).unwrap(), expected(&fixture_rows()));
}

#[test]
fn vacuum_deferred_while_a_reader_is_open() {
    let dir = sealed_with_clear_store();
    // A reader on the old snapshot (another process's open connection).
    let reader = raw(dir.path());
    reader
        .execute_batch("BEGIN; SELECT COUNT(*) FROM owed_acks_v1;")
        .unwrap();
    let (mut store, _) = OwedAcks::open(dir.path()).unwrap();
    assert!(store.keyed());
    assert!(scrub_pending(dir.path()), "the reader held the scrub up");
    assert_eq!(store.list(NOW).unwrap(), expected(&fixture_rows()));
    // Still in the way: the next pass leaves it pending.
    assert_eq!(finish_scrub(dir.path()), Some(false));
    reader.execute_batch("COMMIT;").unwrap();
    drop(reader);
    drop(store);
    assert_eq!(finish_scrub(dir.path()), Some(true));
    assert!(!scrub_pending(dir.path()));
    assert_eq!(finish_scrub(dir.path()), None, "nothing left");
    // A writer in the way of the VACUUM itself.
    let dir = sealed_with_clear_store();
    fault::arm(Fault::VacuumBusy);
    drop(OwedAcks::open(dir.path()).unwrap());
    assert!(scrub_pending(dir.path()));
    assert_eq!(finish_scrub(dir.path()), Some(true));
}

#[test]
fn disk_full_during_migration_leaves_the_old_store() {
    // Too little free space: not started; the store works as it is.
    let dir = sealed_with_clear_store();
    fault::arm(Fault::NoSpace);
    let (mut store, _) = OwedAcks::open(dir.path()).unwrap();
    assert!(!store.keyed());
    assert_eq!(store.list(NOW).unwrap(), expected(&fixture_rows()));
    drop(store);
    assert_eq!(schema(dir.path()), (CLEAR_VERSION, Shape::Clear));
    assert!(OwedAcks::open(dir.path()).unwrap().0.keyed(), "later");
    // The disk fills up during the rebuild: rolled back, nothing lost.
    let dir = sealed_with_clear_store();
    fault::arm(Fault::DiskFull);
    let err = OwedAcks::open(dir.path()).err().expect("SQLITE_FULL");
    assert!(err.to_string().contains("full"), "{err}");
    assert!(!unusable(&err.to_string()));
    assert_eq!(schema(dir.path()), (CLEAR_VERSION, Shape::Clear));
    assert_eq!(older_rows(&raw(dir.path())), fixture_rows());
    let (mut store, _) = OwedAcks::open(dir.path()).unwrap();
    assert_eq!(store.list(NOW).unwrap(), expected(&fixture_rows()));
}

#[test]
fn older_code_refuses_the_migrated_store() {
    let dir = sealed_with_clear_store();
    drop(OwedAcks::open(dir.path()).unwrap());
    // The PP.1 snapshot's user_version check: "newer", which its caller
    // answers by setting the file aside unread (owed_set_aside_v2_is_merged_back).
    let err = older_open_at(&owed_acks_path(dir.path())).err().unwrap();
    assert_eq!(err, "owed_acks.sqlite is newer than this build");
    assert!(unusable(&err));
}

#[test]
fn owed_set_aside_v2_is_merged_back() {
    let dir = sealed_with_clear_store();
    drop(OwedAcks::open(dir.path()).unwrap());
    let rows = fixture_rows();
    // An older build: it sets the schema-2 store aside and starts a clear
    // one, where it rebuilds one of the same ACKs (push-only) and owes a
    // new one.
    let (conn, set_aside) = older_open(dir.path());
    assert!(set_aside);
    assert!(
        older_rows(&conn).is_empty(),
        "it read nothing of the sealed rows"
    );
    let rebuilt = Row {
        bytes: b"rebuilt".to_vec(),
        origin: Origin::Rebuilt,
        recorded: NOW,
        ..rows[1].clone()
    };
    let fresh = Row {
        digest: [0x14; 32],
        peer: [0xA3; 32],
        session: None,
        bytes: b"new".to_vec(),
        expires: NOW + HOUR,
        origin: Origin::Link,
        recorded: NOW + 1,
    };
    older_record(&conn, &rebuilt).unwrap();
    older_record(&conn, &fresh).unwrap();
    drop(conn);
    // Something else under the set-aside name: kept, sealed in place.
    let junk = dir.path().join("owed_acks.sqlite.corrupt-1");
    std::fs::write(&junk, b"not a database at all").unwrap();
    // This build again: the clear store moves to schema 2, the set-aside's
    // rows that are not there come back, and the set-aside goes.
    let (mut store, _) = OwedAcks::open(dir.path()).unwrap();
    assert!(store.keyed());
    let mut want = vec![rows[0].clone(), rows[2].clone(), rebuilt, fresh];
    want.sort_by_key(|row| (row.recorded, row.digest));
    let mut want = expected(&want);
    // The marks the set-aside held come back for an ACK that is present.
    assert_eq!(want[0].held_by.len(), FIXTURE_HELD.len());
    want.iter_mut()
        .filter(|ack| ack.ack_digest != rows[0].digest)
        .for_each(|ack| ack.held_by.clear());
    assert_eq!(store.list(NOW).unwrap(), want);
    let left: Vec<String> = set_asides(dir.path())
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        left,
        ["owed_acks.sqlite.corrupt-1"],
        "the merged one is gone"
    );
    assert!(is_sealed_file(&junk));
    assert_eq!(
        &at_rest::load_bytes(dir.path(), &junk, Kind::OwedAcksAside)
            .unwrap()
            .unwrap()[..],
        b"not a database at all"
    );
    assert_eq!(sealed_set_asides(dir.path()), 1);
    assert_eq!(merge_set_asides(dir.path()).unwrap(), AsideMerge::default());
}

#[test]
fn older_open_restamps_v1_and_new_build_recovers() {
    let dir = sealed_with_clear_store();
    drop(OwedAcks::open(dir.path()).unwrap());
    let before = rowids(dir.path(), "kh_ack_digest");
    // An older process that read user_version 1 before the migration now
    // runs its batch: every CREATE is a no-op, the stamp is not.
    let older = raw(dir.path());
    older.execute_batch(OLDER_BATCH).unwrap();
    assert_eq!(schema(dir.path()), (CLEAR_VERSION, Shape::Keyed));
    // Its writes fail closed (no clear row is written).
    let err = older_record(&older, &fixture_rows()[0]).unwrap_err();
    assert!(
        err.to_string().contains("no column named ack_digest"),
        "{err}"
    );
    drop(older);
    // This build trusts the shape and its raven_schema row: stamped again,
    // not migrated twice.
    let (mut store, _) = OwedAcks::open(dir.path()).unwrap();
    assert!(store.keyed());
    assert_eq!(store.list(NOW).unwrap(), expected(&fixture_rows()));
    drop(store);
    assert_eq!(schema(dir.path()), (SCHEMA_VERSION, Shape::Keyed));
    assert_eq!(rowids(dir.path(), "kh_ack_digest"), before);
}

#[test]
fn reverse_migration_round_trip() {
    let dir = sealed_with_clear_store();
    let before = rowids(dir.path(), "ack_digest");
    drop(OwedAcks::open(dir.path()).unwrap());
    let back = unseal(dir.path()).unwrap();
    assert_eq!((back.rows, back.dropped), (5, 0));
    assert!(!back.scrub_pending);
    // Exactly what an older build reads, rowids kept.
    assert_eq!(schema(dir.path()), (CLEAR_VERSION, Shape::Clear));
    let older = older_open_at(&owed_acks_path(dir.path())).unwrap();
    assert_eq!(older_rows(&older), fixture_rows());
    let mut held = FIXTURE_HELD.to_vec();
    held.sort();
    assert_eq!(older_held(&older), held);
    drop(older);
    assert_eq!(rowids(dir.path(), "ack_digest"), before);
    assert!(unseal(dir.path()).unwrap().already);
    // And forward again.
    let (mut store, _) = OwedAcks::open(dir.path()).unwrap();
    assert!(store.keyed());
    assert_eq!(store.list(NOW).unwrap(), expected(&fixture_rows()));
}

#[test]
fn a_sealed_store_without_its_key_fails_closed() {
    let dir = profile(Setup::SealedFresh);
    at_rest::forget_cached_keys(dir.path());
    // No key: no store is created, clear or not.
    assert!(matches!(
        OwedAcks::open(dir.path()),
        Err(OwedError::KeyUnavailable(_))
    ));
    assert!(!owed_acks_path(dir.path()).exists());
    at_rest::keys_load_with(dir.path(), at_rest::MigratePolicy::Never).unwrap();
    let (mut store, _) = OwedAcks::open(dir.path()).unwrap();
    record(&mut store, 1, 1, None).unwrap();
    drop(store);
    at_rest::forget_cached_keys(dir.path());
    let before = std::fs::read(owed_acks_path(dir.path())).unwrap();
    let err = OwedAcks::open(dir.path()).err().unwrap();
    assert!(matches!(err, OwedError::KeyUnavailable(_)), "{err}");
    assert!(set_asides(dir.path()).is_empty(), "never set aside");
    assert_eq!(std::fs::read(owed_acks_path(dir.path())).unwrap(), before);
    at_rest::keys_load_with(dir.path(), at_rest::MigratePolicy::Never).unwrap();
    assert_eq!(
        OwedAcks::open(dir.path())
            .unwrap()
            .0
            .list(NOW)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn rotation_reseals_every_value_and_the_old_epoch_can_go() {
    let dir = profile(Setup::SealedFresh);
    let (mut store, _) = OwedAcks::open(dir.path()).unwrap();
    record(&mut store, 1, 1, None).unwrap();
    record(&mut store, 2, 2, None).unwrap();
    store.add_held(&[1; 32], &[0xC0; 32]).unwrap();
    let want = store.list(NOW).unwrap();
    assert_eq!(rows_off_epoch(dir.path(), 1).unwrap(), 0);
    at_rest::add_epoch(dir.path(), 1).unwrap();
    // Two ACK rows and one mark are on epoch 1 now.
    assert_eq!(rows_off_epoch(dir.path(), 2).unwrap(), 3);
    let resealed = reseal_rows(dir.path()).unwrap();
    assert_eq!((resealed.resealed, resealed.unreadable), (3, 0));
    assert_eq!(rows_off_epoch(dir.path(), 2).unwrap(), 0);
    assert_eq!(reseal_rows(dir.path()).unwrap(), RowReseal::default());
    at_rest::drop_old_epochs(dir.path()).unwrap();
    assert_eq!(store.list(NOW).unwrap(), want);
}

/// The coarse hour prunes only rows whose exact expiry has passed; the rest
/// of that hour is decided from `meta`.
#[test]
fn the_prune_hour_never_deletes_a_live_ack() {
    let dir = profile(Setup::SealedFresh);
    let (mut store, _) = OwedAcks::open(dir.path()).unwrap();
    let start = 500_000 * HOUR;
    for (d, expires) in [(1u8, start + 10), (2, start + HOUR - 1), (3, start + HOUR)] {
        store
            .record(
                &[1; 32],
                None,
                &[d; 32],
                b"ack",
                expires,
                Origin::Link,
                start,
            )
            .unwrap();
    }
    let digests =
        |list: Vec<OwedAck>| -> Vec<u8> { list.iter().map(|a| a.ack_digest[0]).collect() };
    assert_eq!(digests(store.list(start).unwrap()), [1, 2, 3]);
    assert_eq!(digests(store.list(start + 10).unwrap()), [2, 3]);
    assert_eq!(digests(store.list(start + HOUR - 1).unwrap()), [3]);
    assert!(store.list(start + HOUR).unwrap().is_empty());
}

/// "Timing within 10%" (PP.12): the hot path (room check, record, four
/// listings, clear) of 64 ACKs on a sealed profile's store against a plain
/// one, best of five. Sealing adds a fixed CPU cost per value (two AEAD
/// seals with random nonces per ACK, two opens per listed row), which stays
/// far within 10% of a commit that pays a real fsync; where fsync is nearly
/// free (macOS without F_FULLFSYNC) this list-heavy mix shows more, so the
/// bound is the added time per ACK (60 µs), and the ratio is printed. Timing
/// depends on the machine: run by hand (`--release -- --ignored
/// --nocapture`).
#[test]
#[ignore]
fn timing_within_ten_percent() {
    fn run(dir: &Path) -> std::time::Duration {
        let started = std::time::Instant::now();
        let (mut store, _) = OwedAcks::open(dir).unwrap();
        for i in 0..64u8 {
            assert!(store.has_room(&[i % 4; 32]).unwrap());
            store
                .record(
                    &[i % 4; 32],
                    None,
                    &[i; 32],
                    &[i; 400],
                    NOW + HOUR,
                    Origin::Link,
                    NOW,
                )
                .unwrap();
        }
        for _ in 0..4 {
            assert_eq!(store.list(NOW).unwrap().len(), 64);
        }
        let all: Vec<[u8; 32]> = (0..64u8).map(|i| [i; 32]).collect();
        assert_eq!(store.clear(&all).unwrap(), 64);
        started.elapsed()
    }
    let (plain, sealed) = (profile(Setup::Plain), profile(Setup::SealedFresh));
    let (mut best_plain, mut best_sealed) = (std::time::Duration::MAX, std::time::Duration::MAX);
    for _ in 0..5 {
        best_plain = best_plain.min(run(plain.path()));
        best_sealed = best_sealed.min(run(sealed.path()));
    }
    let ratio = best_sealed.as_secs_f64() / best_plain.as_secs_f64();
    let per_ack = best_sealed.saturating_sub(best_plain) / 64;
    println!(
        "owed acks: plain {best_plain:?}, sealed {best_sealed:?}, ratio {ratio:.3}, \
         added per ACK {per_ack:?}"
    );
    assert!(
        per_ack <= std::time::Duration::from_micros(60),
        "sealing adds {per_ack:?} per ACK"
    );
}
