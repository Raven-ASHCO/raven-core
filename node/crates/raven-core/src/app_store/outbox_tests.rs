//! Security review 2026-11, PRIV-1: the app store's outbox and pairing
//! budget at rest. In a sealed profile no outbox record and no pairing
//! attempt names the friend in clear: the friend's keys, the message ids,
//! the object digests and the client refs are keyed lookups, and every clear
//! value a record names is in its sealed `meta` (`session_id` stays clear,
//! R20). A schema-3 store (the pack's earlier builds: its outbox and budget
//! clear) moves at its open, in one transaction that a crash anywhere leaves
//! as it was; final records go after their retention at every upkeep.
//! Schema 3 is written with the exact SQL of those builds
//! ([`SCHEMA_3_BATCH`] and the inserts below). Profiles are temp folders
//! whose keys come from the test build's lab K_hist (never a keychain item).

use std::collections::BTreeSet;

use super::sealed_tests::file_or_wal_holds;
use super::tests::{item, profile, Setup, TestSealer, SETUPS};
use super::*;
use crate::sqlite_rebuild::{fault, Fault};

const NOW: u64 = 1_800_000_000_000;
const DAY: u64 = 86_400_000;
const HOUR: u64 = 3_600_000;

/// A record whose every value is random, to `peer` (identity key and
/// device) when given.
fn random_record(state: OutState, peer: Option<([u8; 32], [u8; 32])>) -> AppOutRecord {
    let (identity, device) = peer.unwrap_or_else(rand::random);
    let digests: [[u8; 32]; 3] = rand::random();
    let [body, object, session] = digests;
    let ids: [[u8; 16]; 2] = rand::random();
    AppOutRecord {
        peer_identity: identity,
        client_ref: format!("task-{}", hex::encode(rand::random::<[u8; 8]>())),
        peer_device: device,
        content_type: "a2a-request/1".into(),
        app_id: ids[0],
        body_sha256: body,
        message_id: ids[1],
        session_id: session,
        object_digest: object,
        created_at_ms: NOW,
        expires_at_ms: NOW + 4 * HOUR,
        state,
        last_error_code: String::new(),
        attempt_seq: 0,
    }
}

/// Every value of a record that names the friend or the object: not a
/// protocol word, a code, a time or a counter, and not the session id
/// (clear on purpose, R20).
fn named_values(rec: &AppOutRecord) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("identity key", rec.peer_identity.to_vec()),
        ("device key", rec.peer_device.to_vec()),
        ("client ref", rec.client_ref.as_bytes().to_vec()),
        ("app id", rec.app_id.to_vec()),
        ("body digest", rec.body_sha256.to_vec()),
        ("message id", rec.message_id.to_vec()),
        ("object digest", rec.object_digest.to_vec()),
    ]
}

/// What every outbox and budget query answers for the records of one
/// friend (the API raven-node's app channel and outbox worker use).
#[derive(Debug, PartialEq)]
struct OutboxReads {
    /// Per record: by its `(peer, client_ref)`, by its message id, whether
    /// it is an app object, and the dedup decision of the same body.
    records: Vec<(Option<AppOutRecord>, Option<AppOutRecord>, bool, Dedup)>,
    inflight: u32,
    ids: BTreeSet<[u8; 16]>,
    /// The live records last written at or before the reading time, by
    /// message id.
    live: Vec<AppOutRecord>,
    budget_today: i64,
    last_attempt: Option<u64>,
}

fn outbox_reads(store: &AppStore<'_>, recs: &[AppOutRecord], at: u64) -> OutboxReads {
    let device = &recs[0].peer_device;
    let mut live = store.live_records(at).unwrap();
    live.retain(|rec| rec.peer_device == *device);
    live.sort_by_key(|rec| rec.message_id);
    OutboxReads {
        records: recs
            .iter()
            .map(|rec| {
                (
                    store
                        .outbox_record(&rec.peer_identity, &rec.client_ref)
                        .unwrap(),
                    store.record_by_message(&rec.message_id).unwrap(),
                    store.is_app_message(&rec.message_id).unwrap(),
                    store
                        .dedup(
                            &rec.peer_identity,
                            &rec.client_ref,
                            &rec.content_type,
                            &rec.body_sha256,
                            false,
                        )
                        .unwrap(),
                )
            })
            .collect(),
        inflight: store.inflight_for_device(device).unwrap(),
        ids: store
            .message_ids_for_device(device)
            .unwrap()
            .into_iter()
            .collect(),
        live,
        budget_today: store.pair_attempts_today(device, at).unwrap(),
        last_attempt: store.last_pair_attempt_at(device).unwrap(),
    }
}

/// What [`outbox_reads`] gives for `recs` (one friend, every record last
/// written at or before the reading time) and its pairing attempts.
fn outbox_want(recs: &[AppOutRecord], attempts: i64, last: Option<u64>) -> OutboxReads {
    let live_state = |rec: &AppOutRecord| matches!(rec.state, OutState::Queued | OutState::Sent);
    let mut live: Vec<AppOutRecord> = recs.iter().filter(|r| live_state(r)).cloned().collect();
    live.sort_by_key(|rec| rec.message_id);
    OutboxReads {
        records: recs
            .iter()
            .map(|rec| {
                (
                    Some(rec.clone()),
                    Some(rec.clone()),
                    true,
                    Dedup::Return {
                        state: rec.state,
                        message_id: rec.message_id,
                    },
                )
            })
            .collect(),
        inflight: u32::try_from(live.len()).unwrap(),
        ids: recs.iter().map(|rec| rec.message_id).collect(),
        live,
        budget_today: attempts,
        last_attempt: last,
    }
}

/// The store's version and the shape of the inbox, the outbox and the
/// pairing budget.
fn shapes(dir: &Path) -> (i64, Shape, Shape, Shape) {
    let conn = Connection::open(app_store_path(dir)).unwrap();
    (
        rebuild::user_version(&conn).unwrap(),
        rebuild::shape(&conn, "app_inbox", KEYED_COLUMN).unwrap(),
        rebuild::shape(&conn, "app_outbox", "kh_peer_identity").unwrap(),
        rebuild::shape(&conn, "app_pair_attempts", "kh_peer_device").unwrap(),
    )
}

const SCHEMA_3: (i64, Shape, Shape, Shape) = (3, Shape::Keyed, Shape::Clear, Shape::Clear);
const SCHEMA_4: (i64, Shape, Shape, Shape) = (4, Shape::Keyed, Shape::Keyed, Shape::Keyed);

/// Every row of every table (the schema table aside) with its rowid, as
/// stored.
fn raw_rows(dir: &Path) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    let conn = Connection::open(app_store_path(dir)).unwrap();
    let tables: Vec<String> = {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table'
                 AND name NOT IN ('raven_schema') ORDER BY name",
            )
            .unwrap();
        let names = stmt.query_map([], |r| r.get(0)).unwrap();
        names.collect::<Result<_, _>>().unwrap()
    };
    tables
        .into_iter()
        .map(|table| {
            let mut stmt = conn
                .prepare(&format!("SELECT rowid, * FROM {table} ORDER BY rowid"))
                .unwrap();
            let n = stmt.column_count();
            let rows = stmt
                .query_map([], |r| {
                    (0..n)
                        .map(|i| r.get::<_, rusqlite::types::Value>(i))
                        .collect::<Result<Vec<_>, _>>()
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            (table, rows)
        })
        .collect()
}

/// The rowids of each table.
fn rowids(dir: &Path) -> Vec<(String, Vec<i64>)> {
    raw_rows(dir)
        .into_iter()
        .map(|(table, rows)| {
            let ids = rows
                .iter()
                .map(|row| match row[0] {
                    rusqlite::types::Value::Integer(id) => id,
                    ref other => panic!("rowid {other:?}"),
                })
                .collect();
            (table, ids)
        })
        .collect()
}

/// The fixture's inbox item and its tombstoned sender.
fn inbox_item() -> AppInboxItem {
    item(1, 1, "a2a-request/1")
}

/// A sealed profile with a schema-3 store an earlier build of the pack
/// wrote: an inbox item, a tombstone, two outbox records to one friend (one
/// sent, one delivered a day ago) and two pairing attempts to its device,
/// each with that build's exact SQL. The records, as they read back.
fn sealed_with_schema_3_store() -> (tempfile::TempDir, Vec<AppOutRecord>) {
    let dir = profile(Setup::SealedFresh);
    let dd = dir.path();
    assert!(!app_store_path(dd).exists());
    create_schema_3_store_for_tests(dd);
    let held = crate::at_rest::keys_cached(dd).unwrap();
    let keys: &MetaKeys = &held;
    let conn = Connection::open(app_store_path(dd)).unwrap();
    // The inbox and the tombstones as schema 3's ingest and ack write them.
    let it = inbox_item();
    let kh = sender_key(Some(keys), &it.sender_device);
    let meta = seal_inbox_meta(
        keys,
        &row_pk(&kh, &it.message_id),
        &InboxMeta {
            sender_device: hex::encode(it.sender_device),
            sender_identity: hex::encode(it.sender_identity),
            created_at_ms: it.created_at_ms,
            cert_hash: hex::encode(it.cert_hash),
        },
    );
    conn.execute(
        "INSERT OR IGNORE INTO app_inbox (kh_sender, message_id, app_id, content_type,
           received_at_ms, expires_at_ms, body_len, sealed, meta)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            kh,
            it.message_id.as_slice(),
            it.app_id.as_slice(),
            it.content_type,
            ms(it.received_at_ms),
            ms(it.expires_at_ms),
            it.body.len() as i64,
            TestSealer.seal(&serde_json::to_vec(&it).unwrap()).unwrap(),
            meta,
        ],
    )
    .unwrap();
    let (gone, gone_mid) = ([3u8; 32], [4u8; 16]);
    let kh_gone = sender_key(Some(keys), &gone);
    conn.execute(
        "INSERT OR REPLACE INTO app_tombstones
           (kh_sender, message_id, app_id, disposition, at_ms, meta)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            kh_gone,
            gone_mid.as_slice(),
            [5u8; 16].as_slice(),
            "done",
            ms(NOW),
            seal_tombstone_meta(keys, &row_pk(&kh_gone, &gone_mid), &gone),
        ],
    )
    .unwrap();
    // The outbox and the budget as schema 3's put_record and
    // spend_pair_attempt write them.
    let sent = random_record(OutState::Sent, None);
    let delivered = AppOutRecord {
        state: OutState::Delivered,
        attempt_seq: 1,
        ..random_record(
            OutState::Delivered,
            Some((sent.peer_identity, sent.peer_device)),
        )
    };
    for (rec, updated) in [(&sent, NOW), (&delivered, NOW - DAY)] {
        conn.execute(
            "INSERT OR REPLACE INTO app_outbox (peer_identity, client_ref, peer_device,
               content_type, app_id, body_sha256, message_id, session_id, object_digest,
               created_at_ms, expires_at_ms, state, last_error_code, attempt_seq, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                rec.peer_identity.as_slice(),
                rec.client_ref,
                rec.peer_device.as_slice(),
                rec.content_type,
                rec.app_id.as_slice(),
                rec.body_sha256.as_slice(),
                rec.message_id.as_slice(),
                rec.session_id.as_slice(),
                rec.object_digest.as_slice(),
                ms(rec.created_at_ms),
                ms(rec.expires_at_ms),
                rec.state.as_str(),
                rec.last_error_code,
                i64::from(rec.attempt_seq),
                ms(updated),
            ],
        )
        .unwrap();
    }
    for at in [NOW - 2 * HOUR, NOW - HOUR] {
        conn.execute(
            "INSERT INTO app_pair_attempts (peer_device, at_ms) VALUES (?1, ?2)",
            params![sent.peer_device.as_slice(), ms(at)],
        )
        .unwrap();
    }
    drop(conn);
    (dir, vec![sent, delivered])
}

/// The fixture's two pairing attempts, the last an hour ago.
const FIXTURE_ATTEMPTS: (i64, Option<u64>) = (2, Some(NOW - HOUR));

/// What a store with the fixture's data serves: its inbox page, whether the
/// tombstoned item is still known, and the outbox and budget reads.
fn served(dir: &Path, recs: &[AppOutRecord]) -> (Vec<AppInboxItem>, Admit, OutboxReads) {
    let mut store = AppStore::open(dir, &TestSealer).unwrap();
    let page = store.page("rdap", false, 10, NOW, &|_| Ok(None)).unwrap();
    let tombstoned = store
        .admit(&[3; 32], &[4; 16], &[0xEE; 16], "a2a-request/1", 1)
        .unwrap();
    (page, tombstoned, outbox_reads(&store, recs, NOW))
}

fn want(recs: &[AppOutRecord]) -> (Vec<AppInboxItem>, Admit, OutboxReads) {
    let (attempts, last) = FIXTURE_ATTEMPTS;
    (
        vec![inbox_item()],
        Admit::AlreadyDone,
        outbox_want(recs, attempts, last),
    )
}

/// No value a record names is in the store's file or its WAL, raw or as
/// hex.
fn assert_no_named_value(dir: &Path, recs: &[AppOutRecord], why: &str) {
    for rec in recs {
        for (what, value) in named_values(rec) {
            assert!(
                !file_or_wal_holds(dir, &value),
                "the {what} is readable in the store ({why})"
            );
        }
    }
}

/// PRIV-1: in a sealed profile (its first store, and a clear store the
/// sealing moved) a record and a pairing attempt leave none of their values
/// in the file or its WAL, no clear table holds rows, and every query still
/// answers as it did.
#[test]
fn a_sealed_store_keeps_no_outbox_or_budget_value_in_clear() {
    for setup in [Setup::SealedFresh, Setup::Migrated] {
        let dir = profile(setup);
        let dd = dir.path();
        let rec = random_record(OutState::Queued, None);
        let mut store = AppStore::open(dd, &TestSealer).unwrap();
        store.put_record(&rec, NOW).unwrap();
        assert_eq!(
            store.spend_pair_attempt(&rec.peer_device, NOW, 0).unwrap(),
            PairSpend::Spent
        );
        assert!(store
            .set_state(&rec.message_id, OutState::Sent, "", NOW)
            .unwrap());
        let sent = AppOutRecord {
            state: OutState::Sent,
            ..rec.clone()
        };
        assert_eq!(
            outbox_reads(&store, std::slice::from_ref(&sent), NOW),
            outbox_want(&[sent], 1, Some(NOW)),
            "{setup:?}"
        );
        assert!(crate::paths::checkpoint_truncate(&store.conn)
            .unwrap()
            .completed());
        drop(store);
        assert_no_named_value(dd, &[rec], &format!("{setup:?}"));
        assert_eq!(clear_tables_with_rows(dd).unwrap(), Vec::<&str>::new());
    }
}

/// PRIV-1: a final record (delivered, expired, failed, cancelled) goes once
/// its last change is older than the retention, at the next upkeep (not
/// only at the next submit); a live one stays for the reconcile to settle.
/// In every shape.
#[test]
fn maintain_drops_final_records_after_their_retention() {
    use OutState::*;
    for setup in SETUPS {
        let dir = profile(setup);
        let mut store = AppStore::open(dir.path(), &TestSealer).unwrap();
        let recs: Vec<AppOutRecord> = [Queued, Sent, Delivered, Expired, Failed, Cancelled]
            .into_iter()
            .map(|state| random_record(state, None))
            .collect();
        for rec in &recs {
            store.put_record(rec, NOW).unwrap();
        }
        let kept = |store: &AppStore<'_>| -> Vec<bool> {
            recs.iter()
                .map(|rec| store.record_by_message(&rec.message_id).unwrap().is_some())
                .collect()
        };
        store
            .maintain(NOW + APP_OUTBOX_FINAL_RETENTION_MS - 1)
            .unwrap();
        assert_eq!(kept(&store), [true; 6], "{setup:?}");
        store.maintain(NOW + 9 * DAY).unwrap();
        assert_eq!(
            kept(&store),
            [true, true, false, false, false, false],
            "{setup:?}"
        );
    }
}

/// PRIV-1: a schema-3 store moves to schema 4 (the eager pass, once): the
/// outbox and the budget keyed with their rowids, the inbox as it was;
/// every record, the budget, the inbox item and the tombstone read back as
/// before; the scrub leaves none of the clear values in the file or its
/// WAL; and the store keeps working.
#[test]
fn a_schema_3_store_moves_to_4_and_its_outbox_values_leave_the_file() {
    let (dir, recs) = sealed_with_schema_3_store();
    let dd = dir.path();
    assert_eq!(shapes(dd), SCHEMA_3);
    for (what, value) in named_values(&recs[0]) {
        assert!(
            file_or_wal_holds(dd, &value),
            "the fixture is clear: {what}"
        );
    }
    let before = rowids(dd);
    assert!(needs_migration(dd));
    assert!(migrate(dd).unwrap());
    assert!(!migrate(dd).unwrap(), "once");
    assert_eq!(shapes(dd), SCHEMA_4);
    assert_eq!(rowids(dd), before, "rowids kept in every table");
    let conn = Connection::open(app_store_path(dd)).unwrap();
    assert_eq!(rebuild::recorded(&conn, STORE).unwrap(), Some((4, false)));
    drop(conn);
    assert!(!scrub_pending(dd));
    assert_no_named_value(dd, &recs, "migrated");
    assert_eq!(clear_tables_with_rows(dd).unwrap(), Vec::<&str>::new());
    assert_eq!(served(dd, &recs), want(&recs));
    // It keeps working: the sent record is delivered, a resend of the
    // delivered one is answered from its record, a third record is sealed
    // and the budget counts on.
    let mut store = AppStore::open(dd, &TestSealer).unwrap();
    assert!(store
        .set_state(&recs[0].message_id, OutState::Delivered, "", NOW)
        .unwrap());
    let resend = store
        .dedup(
            &recs[1].peer_identity,
            &recs[1].client_ref,
            &recs[1].content_type,
            &recs[1].body_sha256,
            true,
        )
        .unwrap();
    assert_eq!(
        resend,
        Dedup::Return {
            state: OutState::Delivered,
            message_id: recs[1].message_id
        }
    );
    let third = random_record(
        OutState::Queued,
        Some((recs[0].peer_identity, recs[0].peer_device)),
    );
    store.put_record(&third, NOW).unwrap();
    assert_eq!(
        store
            .spend_pair_attempt(&recs[0].peer_device, NOW, HOUR)
            .unwrap(),
        PairSpend::Spent
    );
    let all = [
        AppOutRecord {
            state: OutState::Delivered,
            ..recs[0].clone()
        },
        recs[1].clone(),
        third,
    ];
    assert_eq!(
        outbox_reads(&store, &all, NOW),
        outbox_want(&all, 3, Some(NOW))
    );
    assert!(crate::paths::checkpoint_truncate(&store.conn)
        .unwrap()
        .completed());
    drop(store);
    assert_no_named_value(dd, &all, "after the move");
}

/// PRIV-1: the move from schema 3 stopped before any one of its statements
/// (as a crash would) leaves the store at schema 3, every row as it was, or
/// at schema 4 with the scrub pending; either way the next open serves the
/// same data, and the next prune pass finishes the scrub.
#[test]
fn migration_from_schema_3_crash_at_each_statement_recovers() {
    let mut stops = 0;
    for at in 0.. {
        let (dir, recs) = sealed_with_schema_3_store();
        let dd = dir.path();
        let older = raw_rows(dd);
        fault::arm(Fault::CrashAt(at));
        let opened = AppStore::open(dd, &TestSealer);
        if fault::armed() {
            fault::disarm();
            drop(opened.unwrap());
            assert_eq!(shapes(dd), SCHEMA_4, "the last run moved the store");
            break;
        }
        stops += 1;
        let err = opened.err().expect("an injected stop fails the open");
        assert!(err.contains("injected stop"), "{err}");
        match shapes(dd) {
            SCHEMA_3 => assert_eq!(raw_rows(dd), older, "stop at {at}"),
            SCHEMA_4 => assert!(scrub_pending(dd), "stop at {at}"),
            other => panic!("stop at {at} left {other:?}"),
        }
        assert_eq!(served(dd, &recs), want(&recs), "stop at {at}");
        finish_scrub(dd);
        assert!(!scrub_pending(dd), "stop at {at}");
        assert_no_named_value(dd, &recs, &format!("stop at {at}"));
    }
    assert!(stops >= 10, "only {stops} statements");
}

/// PRIV-1: a move from schema 3 that would lose an outbox row rolls back:
/// the store stays at schema 3 with every row, and serves as before.
#[test]
fn migration_from_schema_3_rolls_back_on_count_mismatch() {
    let (dir, recs) = sealed_with_schema_3_store();
    let dd = dir.path();
    let older = raw_rows(dd);
    fault::arm(Fault::DropOneRow);
    let err = AppStore::open(dd, &TestSealer).err();
    fault::disarm();
    let err = err.expect("the count check stops the move");
    assert!(
        err.contains("app_outbox would hold 1 rows instead of 2"),
        "{err}"
    );
    assert_eq!(shapes(dd), SCHEMA_3);
    assert_eq!(raw_rows(dd), older);
    assert_eq!(served(dd, &recs), want(&recs));
}

/// The outbox's and the pairing budget's rows as stored (rowid first).
fn outbox_rows(dir: &Path) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    raw_rows(dir)
        .into_iter()
        .filter(|(table, _)| table == "app_outbox" || table == "app_pair_attempts")
        .collect()
}

/// The distinct values of one column.
fn column_values(dir: &Path, table: &str, column: &str) -> BTreeSet<Vec<u8>> {
    let conn = Connection::open(app_store_path(dir)).unwrap();
    let mut stmt = conn
        .prepare(&format!("SELECT {column} FROM {table}"))
        .unwrap();
    let rows = stmt.query_map([], |r| r.get(0)).unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

/// PRIV-1 with `raven privacy rotate-meta`: under a new lookup key every
/// keyed column of the outbox and the budget is computed anew and every
/// `meta` sealed under the new epoch, in a schema-4 store and in a schema-3
/// one (whose outbox and budget it keys with the rest); the data reads back
/// as before, and a second pass changes nothing.
#[test]
fn rotate_meta_keys_the_outbox_and_the_budget_again() {
    for moved_first in [true, false] {
        let (dir, recs) = sealed_with_schema_3_store();
        let dd = dir.path();
        if moved_first {
            assert!(migrate(dd).unwrap());
        }
        let old = crate::at_rest::keys_cached(dd).unwrap();
        let to = old.current_epoch() + 1;
        crate::at_rest::begin_meta_rotation(dd, to).unwrap();
        let new = crate::at_rest::keys_cached(dd).unwrap();
        let moved = rekey(dd).unwrap();
        // The inbox item, the tombstone, two records and two attempts.
        assert_eq!((moved.rows, moved.dropped), (6, 0), "{moved_first}");
        assert_eq!(shapes(dd), SCHEMA_4, "{moved_first}");
        let (identity, device) = (recs[0].peer_identity, recs[0].peer_device);
        for (keys, now) in [(&new, true), (&old, false)] {
            let want_identity = BTreeSet::from([pair_lookup(keys, &identity)]);
            let want_device = BTreeSet::from([pair_lookup(keys, &device)]);
            assert_eq!(
                column_values(dd, "app_outbox", "kh_peer_identity") == want_identity,
                now,
                "{moved_first}"
            );
            assert_eq!(
                column_values(dd, "app_outbox", "kh_peer_device") == want_device,
                now,
                "{moved_first}"
            );
            assert_eq!(
                column_values(dd, "app_pair_attempts", "kh_peer_device") == want_device,
                now,
                "{moved_first}"
            );
        }
        assert_eq!(meta_rows_off_epoch(dd, to).unwrap(), 0, "{moved_first}");
        assert!(!scrub_pending(dd), "{moved_first}");
        assert_no_named_value(dd, &recs, "re-keyed");
        assert_eq!(served(dd, &recs), want(&recs), "{moved_first}");
        let after = outbox_rows(dd);
        rekey(dd).unwrap();
        let again = outbox_rows(dd);
        // The keyed columns stay; only the metas' random nonces change.
        let keyed_part = |rows: &[(String, Vec<Vec<rusqlite::types::Value>>)]| {
            rows.iter()
                .map(|(table, rows)| {
                    // `meta` is each table's last column (after the rowid).
                    let meta = if table == "app_outbox" { 14 } else { 3 };
                    let rows: Vec<Vec<rusqlite::types::Value>> = rows
                        .iter()
                        .map(|row| {
                            let mut row = row.clone();
                            row.remove(meta);
                            row
                        })
                        .collect();
                    (table.clone(), rows)
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(keyed_part(&again), keyed_part(&after), "{moved_first}");
        assert_eq!(served(dd, &recs), want(&recs), "{moved_first}");
    }
}

/// PRIV-1 with `raven privacy unseal`: the way back gives the outbox and the
/// budget exactly the rows (and rowids) the clear schema had, from schema 4
/// and from a schema-3 store whose move had not come yet; the next open in
/// a sealed profile moves them again.
#[test]
fn unseal_gives_the_outbox_and_the_budget_back_byte_for_byte() {
    for moved_first in [true, false] {
        let (dir, recs) = sealed_with_schema_3_store();
        let dd = dir.path();
        let older = outbox_rows(dd);
        if moved_first {
            assert!(migrate(dd).unwrap());
        }
        let back = unseal(dd).unwrap();
        // The inbox item and the tombstone; from schema 4 the two records
        // and the two attempts too.
        let rows = if moved_first { 6 } else { 2 };
        assert_eq!(
            (back.rows, back.dropped, back.scrub_pending),
            (rows, 0, false),
            "{moved_first}"
        );
        assert_eq!(
            shapes(dd),
            (CLEAR_VERSION, Shape::Clear, Shape::Clear, Shape::Clear),
            "{moved_first}"
        );
        assert_eq!(outbox_rows(dd), older, "{moved_first}");
        assert!(unseal(dd).unwrap().already, "{moved_first}");
        assert_eq!(served(dd, &recs), want(&recs), "forward again");
        assert_eq!(shapes(dd), SCHEMA_4, "{moved_first}");
    }
}

/// Review R06 at schema 4: an older process (from before the pack) that runs
/// its batch on a moved store creates nothing (every name exists) and its
/// outbox and budget writes fail closed; its stamp is put right by the next
/// open, never taken for a move. A schema-3 build refuses the store by its
/// recorded version.
#[test]
fn an_older_build_on_schema_4_fails_closed_and_is_stamped_again() {
    let (dir, recs) = sealed_with_schema_3_store();
    let dd = dir.path();
    assert!(migrate(dd).unwrap());
    let before = raw_rows(dd);
    let older = Connection::open(app_store_path(dd)).unwrap();
    older
        .execute_batch(super::sealed_tests::OLDER_BATCH)
        .unwrap();
    let err = older
        .execute(
            "INSERT INTO app_pair_attempts (peer_device, at_ms) VALUES (?1, ?2)",
            params![recs[0].peer_device.as_slice(), 1],
        )
        .unwrap_err();
    assert!(err.to_string().contains("peer_device"), "{err}");
    let err = older
        .execute(
            "UPDATE app_outbox SET state = 'cancelled' WHERE message_id = ?1",
            params![recs[0].message_id.as_slice()],
        )
        .unwrap_err();
    assert!(err.to_string().contains("message_id"), "{err}");
    // The version a schema-3 build compares before anything else.
    let recorded = rebuild::recorded(&older, STORE).unwrap();
    assert_eq!(recorded, Some((SCHEMA_VERSION, false)));
    assert!(recorded.unwrap().0 > SENDERS_KEYED_VERSION);
    drop(older);
    assert_eq!(
        shapes(dd),
        (CLEAR_VERSION, Shape::Keyed, Shape::Keyed, Shape::Keyed)
    );
    assert!(!migrate(dd).unwrap(), "stamped again, not migrated");
    assert_eq!(shapes(dd), SCHEMA_4);
    assert_eq!(raw_rows(dd), before);
    assert_eq!(served(dd, &recs), want(&recs));
}

/// Too little free space for the move: a schema-3 store keeps working as it
/// is (its outbox and budget still clear, as before this build), and a later
/// pass moves it.
#[test]
fn too_little_space_leaves_a_schema_3_store_working_until_a_later_pass() {
    let (dir, recs) = sealed_with_schema_3_store();
    let dd = dir.path();
    let older = raw_rows(dd);
    fault::arm(Fault::NoSpace);
    let store = AppStore::open(dd, &TestSealer).unwrap();
    assert!(!fault::armed(), "the preflight ran");
    assert!(store.keyed && !store.outbox_keyed, "deferred");
    let (attempts, last) = FIXTURE_ATTEMPTS;
    assert_eq!(
        outbox_reads(&store, &recs, NOW),
        outbox_want(&recs, attempts, last)
    );
    drop(store);
    assert_eq!(shapes(dd), SCHEMA_3);
    assert_eq!(raw_rows(dd), older);
    assert!(needs_migration(dd));
    assert!(migrate(dd).unwrap(), "the next pass moves it");
    assert_eq!(shapes(dd), SCHEMA_4);
    assert_eq!(served(dd, &recs), want(&recs));
}

/// A store whose tables mix the shapes in a way no build writes (every move
/// changes them in one transaction) does not open, and is left as it is.
#[test]
fn a_store_that_mixes_the_shapes_does_not_open() {
    let dir = profile(Setup::SealedFresh);
    let dd = dir.path();
    drop(AppStore::open(dd, &TestSealer).unwrap());
    Connection::open(app_store_path(dd))
        .unwrap()
        .execute_batch(&format!(
            "DROP TABLE app_pair_attempts; {}",
            pair_attempts_table("CREATE TABLE app_pair_attempts", false)
        ))
        .unwrap();
    let err = AppStore::open(dd, &MetadataOnly).err().unwrap();
    assert_eq!(err, MIXED_LAYOUT);
    assert_eq!(shapes(dd), (4, Shape::Keyed, Shape::Keyed, Shape::Clear));
}

/// A record whose keyed column was edited, or whose `meta` is another
/// record's, is a bad row: its reads fail (never another record's values),
/// and the worker's set of the friend's app objects still knows the others.
#[test]
fn a_record_whose_columns_do_not_match_its_meta_is_a_bad_row() {
    let dir = profile(Setup::SealedFresh);
    let dd = dir.path();
    let first = random_record(OutState::Queued, None);
    let peer = Some((first.peer_identity, first.peer_device));
    let recs = [
        first,
        random_record(OutState::Queued, peer),
        random_record(OutState::Queued, peer),
    ];
    let mut store = AppStore::open(dd, &TestSealer).unwrap();
    for rec in &recs {
        store.put_record(rec, NOW).unwrap();
    }
    store
        .conn
        .execute_batch(
            "UPDATE app_outbox SET kh_object_digest = zeroblob(32) WHERE rowid = 1;
             UPDATE app_outbox SET meta = (SELECT meta FROM app_outbox WHERE rowid = 3)
               WHERE rowid = 2;",
        )
        .unwrap();
    for rec in &recs[..2] {
        let err = store
            .outbox_record(&rec.peer_identity, &rec.client_ref)
            .unwrap_err();
        assert!(err.contains("APP_STORE"), "{err}");
        assert!(store.record_by_message(&rec.message_id).is_err());
    }
    assert_eq!(
        store
            .outbox_record(&recs[2].peer_identity, &recs[2].client_ref)
            .unwrap(),
        Some(recs[2].clone())
    );
    assert!(store.live_records(NOW).is_err(), "never a partial answer");
    assert_eq!(
        store.message_ids_for_device(&recs[0].peer_device).unwrap(),
        std::collections::HashSet::from([recs[2].message_id])
    );
    assert_eq!(store.inflight_for_device(&recs[0].peer_device).unwrap(), 3);
}
