//! PP.12 tests of the SQLite stores' part of the migration and the prune
//! passes ([`upkeep_stores`]): the sealing pass moves the owed-ACK store and
//! the app store to their keyed schemas, the upgrade interlock holds a move
//! back, the prune pass finishes a scrub a reader held up and settles an
//! older build's set-aside, `raven privacy status` lists both, and a
//! data-key rotation re-seals the stores' meta before the old epoch goes.
//! Profiles are temp folders whose keys come from the test build's lab K_hist.

use super::*;
use crate::app_store::{AppStore, MetadataOnly};
use crate::contact_book::tests::{profile, seal};
use crate::owed_acks::{Origin, OwedAcks};
use crate::sqlite_rebuild::{self as rebuild, Shape};

const T0: u64 = 20_100 * DAY_MS + HOUR_MS;
const LATER: u64 = 1_800_000_000_000;

fn shape_of(path: &Path, table: &str, column: &str) -> Shape {
    let conn = rusqlite::Connection::open(path).unwrap();
    rebuild::shape(&conn, table, column).unwrap()
}

fn owed_shape(dd: &Path) -> Shape {
    shape_of(
        &crate::owed_acks::owed_acks_path(dd),
        "owed_acks_v1",
        "kh_ack_digest",
    )
}

fn app_shape(dd: &Path) -> Shape {
    shape_of(
        &crate::app_store::app_store_path(dd),
        "app_inbox",
        "kh_sender",
    )
}

fn owe(dd: &Path, n: u8) {
    OwedAcks::open(dd)
        .unwrap()
        .0
        .record(&[n; 32], None, &[n; 32], b"ack", LATER, Origin::Link, T0)
        .unwrap();
}

#[test]
fn sealing_moves_both_stores_and_the_interlock_holds_a_move_back() {
    // A profile sealed for the first time: its stores move in the same pass.
    let dir = profile();
    let dd = dir.path();
    owe(dd, 1);
    drop(AppStore::open(dd, &MetadataOnly).unwrap());
    assert_eq!(
        (owed_shape(dd), app_shape(dd)),
        (Shape::Clear, Shape::Clear)
    );
    seal(dd);
    assert_eq!(
        (owed_shape(dd), app_shape(dd)),
        (Shape::Keyed, Shape::Keyed)
    );
    assert_eq!(OwedAcks::open(dd).unwrap().0.list(T0).unwrap().len(), 1);
    // A sealed profile in which an older build made clear stores: an older
    // raven-node still answers, so they stay as they are; asked only then.
    let dir = profile();
    let dd = dir.path();
    seal(dd);
    let asked = std::cell::Cell::new(0);
    let older = || {
        asked.set(asked.get() + 1);
        true
    };
    let report = migrate_all_with(dd, T0, MigratePolicy::Allow, Some(&older)).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::Sealed);
    assert_eq!(asked.get(), 0, "nothing to move: not asked");
    crate::owed_acks::create_clear_store_for_tests(dd);
    crate::app_store::create_clear_store_for_tests(dd);
    migrate_all_with(dd, T0, MigratePolicy::Allow, Some(&older)).unwrap();
    assert_eq!(asked.get(), 1);
    assert_eq!(
        (owed_shape(dd), app_shape(dd)),
        (Shape::Clear, Shape::Clear)
    );
    let gone = || false;
    migrate_all_with(dd, T0, MigratePolicy::Allow, Some(&gone)).unwrap();
    assert_eq!(
        (owed_shape(dd), app_shape(dd)),
        (Shape::Keyed, Shape::Keyed)
    );
    // A profile that is not sealed keeps its clear stores.
    let dir = profile();
    let dd = dir.path();
    owe(dd, 2);
    assert_eq!(upkeep_stores(dd), StoreUpkeep::default());
    assert_eq!(owed_shape(dd), Shape::Clear);
}

#[test]
fn the_prune_pass_finishes_a_scrub_and_settles_a_set_aside_and_status_lists_them() {
    let dir = profile();
    let dd = dir.path();
    seal(dd);
    crate::owed_acks::create_clear_store_for_tests(dd);
    let reader = rusqlite::Connection::open(crate::owed_acks::owed_acks_path(dd)).unwrap();
    reader
        .execute_batch("BEGIN; SELECT COUNT(*) FROM owed_acks_v1;")
        .unwrap();
    let report = upkeep_stores(dd);
    assert_eq!((report.migrated, report.scrub_pending), (1, true));
    assert!(store_status(dd).scrub_pending);
    reader.execute_batch("COMMIT;").unwrap();
    drop(reader);
    // The next prune pass (raven-node every 10 minutes, ash without a node).
    let _ = crate::lan_dispatch::prune_expired_lan_durable_state(dd);
    assert!(!store_status(dd).scrub_pending);
    // An older build's set-aside that is not this profile's store.
    std::fs::write(dd.join("owed_acks.sqlite.corrupt-5"), b"not a database").unwrap();
    assert_eq!(store_status(dd).set_aside_stores, 0, "not sealed yet");
    let report = upkeep_stores(dd);
    assert_eq!(report.sealed_set_asides, 1);
    assert!(report.did_anything());
    assert_eq!(store_status(dd).set_aside_stores, 1);
    assert_eq!(upkeep_stores(dd), StoreUpkeep::default(), "once");
    assert_eq!(
        report.to_string(),
        "migrated=0 merged_rows=0 sealed_set_asides=1 failed=0 scrub_pending=false"
    );
}

#[test]
fn rotation_reseals_the_stores_before_the_old_epoch_goes() {
    let dir = profile();
    let dd = dir.path();
    seal(dd);
    owe(dd, 1);
    owe(dd, 2);
    let sealer = crate::app_store::PlatformRowSealer::new(dd);
    let mut app = AppStore::open(dd, &sealer).unwrap();
    let item = crate::app_store::AppInboxItem {
        sender_device: [7; 32],
        message_id: [7; 16],
        app_id: [8; 16],
        sender_identity: [7; 32],
        content_type: "a2a-request/1".into(),
        created_at_ms: T0,
        received_at_ms: T0,
        expires_at_ms: LATER,
        cert_json: "{}".into(),
        cert_hash: [0; 32],
        body: "task".into(),
    };
    assert!(app.ingest(&item).unwrap());
    drop(app);
    assert_eq!(rotation_state(dd).old_objects, 0);
    // A rotation starts and re-seals everything (both stores included) in
    // the same pass; the old epoch goes once the grace is cut short.
    let started = rotate_data_key_now(dd, T0, false).unwrap();
    assert!(started.started);
    // Two ACK rows, the app row's body and its meta.
    assert!(started.resealed >= 4, "{started:?}");
    assert_eq!(rotation_state(dd).old_objects, 0);
    let dropped = rotate_data_key_now(dd, T0, true).unwrap();
    assert!(dropped.dropped, "{dropped:?}");
    assert_eq!(at_rest::keys_cached(dd).unwrap().epochs(), [2]);
    assert_eq!(OwedAcks::open(dd).unwrap().0.list(T0).unwrap().len(), 2);
    let page = AppStore::open(dd, &sealer)
        .unwrap()
        .page("c", false, 10, T0, &|_| Ok(None))
        .unwrap();
    assert_eq!(page, vec![item]);
}
