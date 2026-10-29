//! PP.10 tests: the data-key rotation ([`rotate_data_key`]). The chat
//! history, the outbound stage and the app rows move under the epoch keys
//! at the migration; a rotation adds an epoch, re-seals every object, keeps
//! the old epoch through the grace (a stale writer loses nothing), then
//! drops it once a re-scan finds nothing left, and a copy of an old file no
//! longer opens. Every step survives a crash; at most one start a day; a
//! plain profile never rotates. Profiles are temp folders whose keys come
//! from the test build's lab K_hist (never a keychain item); nothing here
//! calls the keystore after the first key load.

use super::tests::{arm, kh_row_like_an_epoch_row, Crash};
use super::*;
use crate::app_store::{AppInboxItem, AppStore, PlatformRowSealer, RowSealer};
use crate::chat_history::{
    history_form, list_staged_outbound_bodies, load_staged_outbound_body, stage_form,
    stage_outbound_body, ChatHistory, ChatHistoryEntry, ChatHistoryError, SealForm,
};
use crate::contact_book::tests::{fixture, profile};
use std::sync::Arc;

/// The start of a day, plus an hour.
const T0: u64 = 20_100 * DAY_MS + HOUR_MS;

fn row(n: u8, direction: &str) -> ChatHistoryEntry {
    ChatHistoryEntry {
        message_id_hex: hex::encode([n; 16]),
        direction: direction.into(),
        peer_petname: String::new(),
        peer_tag: String::new(),
        peer_pub_hex: hex::encode([0x40 + n % 4; 32]),
        created_at_ms: T0,
        delivery: if direction == "in" {
            "received"
        } else {
            "delivered"
        }
        .into(),
        preview: String::new(),
        body: format!("m{n}"),
        stored_at_ms: None,
        id_conflict: false,
    }
}

fn bodies(dd: &Path) -> Vec<String> {
    ChatHistory::load(dd)
        .unwrap()
        .entries
        .into_iter()
        .map(|e| e.body)
        .collect()
}

/// A message to friend `n` still waiting to be sent (its staged body).
fn stage(dd: &Path, n: u8) {
    stage_outbound_body(
        dd,
        &[n; 32],
        &[n; 32],
        &[n; 32],
        &[n; 16],
        T0,
        &format!("s{n}"),
    )
    .unwrap();
}

fn staged(dd: &Path, n: u8) -> String {
    load_staged_outbound_body(dd, &[n; 16])
        .unwrap()
        .expect("still staged")
        .body
}

fn app_item(n: u8) -> AppInboxItem {
    AppInboxItem {
        sender_device: [n; 32],
        message_id: [n; 16],
        app_id: [n ^ 0x80; 16],
        sender_identity: [n; 32],
        content_type: "application/x-test".into(),
        created_at_ms: T0,
        received_at_ms: T0 + u64::from(n),
        expires_at_ms: u64::MAX / 2,
        cert_json: "{}".into(),
        cert_hash: [0; 32],
        body: format!("app-{n}"),
    }
}

fn ingest(dd: &Path, n: u8) {
    ingest_with(dd, &PlatformRowSealer::new(dd), n);
}

fn ingest_with(dd: &Path, sealer: &dyn RowSealer, n: u8) {
    assert!(AppStore::open(dd, sealer)
        .unwrap()
        .ingest(&app_item(n))
        .unwrap());
}

/// The app inbox as the bound consumer pages it: bodies, and how many rows
/// were set aside.
fn app_page(dd: &Path) -> (Vec<String>, u64) {
    let sealer = PlatformRowSealer::new(dd);
    let mut store = AppStore::open(dd, &sealer).unwrap();
    let items = store
        .page("test", false, 50, T0, &|_| Ok(None))
        .unwrap()
        .into_iter()
        .map(|item| item.body)
        .collect();
    (items, store.quarantined)
}

/// Seal `dd` as raven-node's start would (the key file is expected here).
fn seal_at(dd: &Path, now: u64) {
    crate::at_rest::tests::expect_key_file(dd);
    let report = migrate_all(dd, now, MigratePolicy::Allow).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::Sealed);
}

/// A profile whose history, stage and app row K_hist sealed directly (an
/// older build's), with the contact book and block list, then sealed: the
/// history, stage and app row move under epoch 1 at the migration.
fn sealed_with_data() -> tempfile::TempDir {
    let dir = profile();
    let dd = dir.path();
    fixture(dd);
    ChatHistory::append_persisted(dd, row(1, "out")).unwrap();
    stage(dd, 1);
    ingest(dd, 1);
    assert_eq!(history_form(dd), SealForm::Other);
    seal_at(dd, T0);
    dir
}

fn contact_rows(dd: &Path) -> Vec<serde_json::Value> {
    crate::contact_book::read_rows(dd).unwrap().unwrap()
}

/// What every reader of the profile answers.
fn readers(
    dd: &Path,
) -> (
    Vec<String>,
    String,
    Vec<String>,
    Vec<serde_json::Value>,
    Vec<String>,
) {
    let (app, quarantined) = app_page(dd);
    assert_eq!(quarantined, 0, "no row is set aside");
    (
        bodies(dd),
        staged(dd, 1),
        app,
        contact_rows(dd),
        crate::chat_history::BlockList::load_checked(dd)
            .unwrap()
            .pub_hex,
    )
}

fn epochs(dd: &Path) -> Vec<u32> {
    crate::at_rest::keys_cached(dd).unwrap().epochs()
}

#[test]
fn migration_moves_history_stage_and_app_rows_under_the_epoch_keys() {
    let dir = sealed_with_data();
    let dd = dir.path();
    assert_eq!(history_form(dd), SealForm::Epoch(1));
    assert_eq!(stage_form(dd), SealForm::Epoch(1));
    assert_eq!(crate::app_store::row_epochs(dd).unwrap(), [Some(1)]);
    assert_eq!(bodies(dd), ["m1"]);
    assert_eq!(staged(dd, 1), "s1");
    assert_eq!(app_page(dd), (vec!["app-1".to_owned()], 0));
    // Writers keep the epoch format.
    ChatHistory::append_persisted(dd, row(2, "in")).unwrap();
    stage(dd, 2);
    ingest(dd, 2);
    assert_eq!(history_form(dd), SealForm::Epoch(1));
    assert_eq!(stage_form(dd), SealForm::Epoch(1));
    assert_eq!(
        crate::app_store::row_epochs(dd).unwrap(),
        [Some(1), Some(1)]
    );
    assert_eq!(rotation_state(dd).old_objects, 0);

    // An older build of the pack writes RVNHIST1 into the sealed profile:
    // the next migration pass (its fast path) moves it again.
    set_mode(dd, Mode::Plain).unwrap();
    ChatHistory::append_persisted(dd, row(3, "out")).unwrap();
    set_mode(dd, Mode::Sealed).unwrap();
    assert_eq!(history_form(dd), SealForm::Other);
    assert_eq!(rotation_state(dd).old_objects, 1);
    migrate_all(dd, T0, MigratePolicy::Allow).unwrap();
    assert_eq!(history_form(dd), SealForm::Epoch(1));
    assert_eq!(bodies(dd), ["m1", "m2", "m3"]);
}

#[test]
fn rotation_reseals_everything_and_drops_the_old_epoch_after_grace() {
    let dir = sealed_with_data();
    let dd = dir.path();
    let before = readers(dd);
    // Nothing is due: no rotation.
    assert_eq!(rotate_data_key(dd, T0).unwrap(), RotationReport::default());
    assert_eq!(epochs(dd), [1]);

    mark_rotation_due(dd).unwrap();
    let started = rotate_data_key(dd, T0).unwrap();
    assert!(started.started && !started.dropped, "{started}");
    // History, stage, app row, contacts, block list, device files...
    assert!(started.resealed >= 5, "{started}");
    assert_eq!((started.pending, started.unreadable), (0, 0));
    assert_eq!(epochs(dd), [1, 2]);
    let state = rotation_state(dd);
    assert_eq!(state.current_epoch, Some(2));
    assert_eq!(state.old_objects, 0, "everything is on epoch 2");
    assert!(state.old_epoch_held());
    assert_eq!(state.started_at_ms, Some(T0));
    assert!(!state.due, "the start took the due mark");
    assert_eq!(history_form(dd), SealForm::Epoch(2));
    assert_eq!(readers(dd), before);

    // During the grace epoch 1 stays.
    let waiting = rotate_data_key(dd, T0 + ROTATION_GRACE_MS - 1).unwrap();
    assert_eq!(waiting, RotationReport::default());
    assert_eq!(epochs(dd), [1, 2]);

    let dropped = rotate_data_key(dd, T0 + ROTATION_GRACE_MS).unwrap();
    assert!(dropped.dropped && dropped.resealed == 0, "{dropped}");
    assert_eq!(epochs(dd), [2]);
    let state = rotation_state(dd);
    assert!(!state.old_epoch_held());
    assert_eq!(state.started_at_ms, None);
    assert_eq!(state.last_rotation_at_ms, Some(T0));
    assert_eq!(readers(dd), before);
    // Done: the next pass does nothing.
    assert_eq!(
        rotate_data_key(dd, T0 + 2 * ROTATION_GRACE_MS).unwrap(),
        RotationReport::default()
    );
}

#[test]
fn old_epoch_ciphertext_unreadable_after_drop() {
    let dir = sealed_with_data();
    let dd = dir.path();
    let copies = tempfile::tempdir().unwrap();
    let copy = |name: &str| {
        let to = copies.path().join(name);
        std::fs::copy(dd.join(name), &to).unwrap();
        to
    };
    let old_history = copy("chat_history.json");
    let old_contacts = copy(crate::contact_book::CONTACTS_FILE);
    let old_key_file = copy(META_KEY_FILE);
    assert_eq!(verify_copy(dd, &old_history).unwrap(), CopyCheck::Opens);
    assert_eq!(verify_copy(dd, &old_contacts).unwrap(), CopyCheck::Opens);

    mark_rotation_due(dd).unwrap();
    rotate_data_key(dd, T0).unwrap();
    // The grace: copies still open (a stale writer's data must).
    assert_eq!(verify_copy(dd, &old_history).unwrap(), CopyCheck::Opens);
    assert!(rotate_data_key(dd, T0 + ROTATION_GRACE_MS).unwrap().dropped);

    assert_eq!(
        verify_copy(dd, &old_history).unwrap(),
        CopyCheck::DoesNotOpen
    );
    assert_eq!(
        verify_copy(dd, &old_contacts).unwrap(),
        CopyCheck::DoesNotOpen
    );
    for current in ["chat_history.json", crate::contact_book::CONTACTS_FILE] {
        assert_eq!(
            verify_copy(dd, &dd.join(current)).unwrap(),
            CopyCheck::Opens
        );
    }
    // The honest limit: an older key file is wrapped by the same K_hist.
    assert_eq!(verify_copy(dd, &old_key_file).unwrap(), CopyCheck::Opens);
    // An old copy put back in place fails closed (never read as empty).
    std::fs::copy(&old_history, dd.join("chat_history.json")).unwrap();
    assert!(matches!(
        ChatHistory::load(dd),
        Err(ChatHistoryError::AuthenticationFailed)
    ));
    let plain = copies.path().join("plain.json");
    std::fs::write(&plain, b"[]").unwrap();
    assert_eq!(verify_copy(dd, &plain).unwrap(), CopyCheck::Plain);
}

/// A sealer that seals with the keys it was given (a writer that read them
/// before step 1).
struct StaleSealer(Arc<crate::at_rest::MetaKeys>);

impl RowSealer for StaleSealer {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut row = vec![crate::app_store::APP_ROW_V2];
        row.extend_from_slice(&crate::at_rest::seal_epoch(
            &self.0,
            crate::at_rest::DataUse::AppRow,
            b"raven/app-inbox/v1",
            plaintext,
        ));
        Ok(row)
    }

    fn open(&self, _sealed: &[u8]) -> Result<Vec<u8>, String> {
        Err("seal only".into())
    }
}

#[test]
fn stale_writer_after_step_1_loses_nothing() {
    let dir = sealed_with_data();
    let dd = dir.path();
    let stale = crate::at_rest::keys_cached(dd).unwrap();
    let contacts_path = dd.join(crate::contact_book::CONTACTS_FILE);
    let contacts_plain = crate::at_rest::load_bytes(dd, &contacts_path, Kind::Contacts)
        .unwrap()
        .unwrap();
    mark_rotation_due(dd).unwrap();
    assert!(rotate_data_key(dd, T0).unwrap().started);
    assert_eq!(rotation_state(dd).old_objects, 0);

    // A thread that loaded the keys before step 1 writes after step 2: an
    // app row and the contact book, sealed under epoch 1.
    let (dd_owned, keys) = (dd.to_path_buf(), Arc::clone(&stale));
    std::thread::spawn(move || {
        ingest_with(&dd_owned, &StaleSealer(Arc::clone(&keys)), 3);
        let sealed = crate::at_rest::seal(&keys, Kind::Contacts, &contacts_plain);
        crate::paths::atomic_write_private(
            &dd_owned.join(crate::contact_book::CONTACTS_FILE),
            &sealed,
        )
        .unwrap();
    })
    .join()
    .unwrap();
    assert_eq!(rotation_state(dd).old_objects, 2);
    // Readable during the grace.
    assert_eq!(app_page(dd).0, ["app-1", "app-3"]);
    assert_eq!(contact_rows(dd).len(), 4);

    // After the grace the re-scan re-seals the two and stops: no drop yet.
    let rescan = rotate_data_key(dd, T0 + ROTATION_GRACE_MS).unwrap();
    assert_eq!((rescan.resealed, rescan.dropped), (2, false), "{rescan}");
    assert_eq!(epochs(dd), [1, 2]);
    assert_eq!(rotation_state(dd).old_objects, 0);
    let dropped = rotate_data_key(dd, T0 + ROTATION_GRACE_MS + 1).unwrap();
    assert!(dropped.dropped, "{dropped}");
    assert_eq!(epochs(dd), [2]);
    assert_eq!(app_page(dd), (vec!["app-1".into(), "app-3".into()], 0));
    assert_eq!(contact_rows(dd).len(), 4);
}

#[test]
fn crash_after_each_step_recovers() {
    for crash in [
        Crash::RotationRecorded,
        Crash::RotationStarted,
        Crash::ResealedHistory,
        Crash::ResealedStage,
        Crash::ResealedAppRows,
        Crash::ResealedFiles,
    ] {
        let dir = sealed_with_data();
        let dd = dir.path();
        let before = readers(dd);
        mark_rotation_due(dd).unwrap();
        arm(crash);
        assert!(rotate_data_key(dd, T0).is_err(), "{crash:?}");
        assert_eq!(
            readers(dd),
            before,
            "{crash:?}: readers work at every point"
        );
        // The same day: the pass finishes this rotation (no second start).
        let again = rotate_data_key(dd, T0 + 1).unwrap();
        assert_eq!(epochs(dd), [1, 2], "{crash:?}");
        assert_eq!(rotation_state(dd).old_objects, 0, "{crash:?}");
        assert_eq!(
            again.started,
            crash == Crash::RotationRecorded,
            "{crash:?}: {again}"
        );
        assert!(!again.dropped);
        let dropped = rotate_data_key(dd, T0 + ROTATION_GRACE_MS + 1).unwrap();
        assert!(dropped.dropped, "{crash:?}: {dropped}");
        assert_eq!(epochs(dd), [2], "{crash:?}");
        assert_eq!(readers(dd), before, "{crash:?}");
        assert!(!rotation_due(dd));
    }

    // Inside step 4: the old epoch left the key file, the record did not.
    let dir = sealed_with_data();
    let dd = dir.path();
    let before = readers(dd);
    mark_rotation_due(dd).unwrap();
    rotate_data_key(dd, T0).unwrap();
    arm(Crash::EpochDropped);
    assert!(rotate_data_key(dd, T0 + ROTATION_GRACE_MS).is_err());
    assert_eq!(epochs(dd), [2]);
    assert_eq!(rotation_state(dd).started_at_ms, Some(T0));
    assert_eq!(readers(dd), before);
    let settled = rotate_data_key(dd, T0 + ROTATION_GRACE_MS + 1).unwrap();
    assert_eq!(settled, RotationReport::default());
    assert_eq!(rotation_state(dd).started_at_ms, None);
    assert_eq!(epochs(dd), [2]);
}

#[test]
fn queued_message_still_goes_out_after_rotation() {
    let dir = sealed_with_data();
    let dd = dir.path();
    // One more waits to be sent while the rotation runs.
    mark_rotation_due(dd).unwrap();
    rotate_data_key(dd, T0).unwrap();
    stage(dd, 2);
    assert!(rotate_data_key(dd, T0 + ROTATION_GRACE_MS).unwrap().dropped);
    assert_eq!(stage_form(dd), SealForm::Epoch(2));
    // The send path finds both bodies, exactly as staged.
    assert_eq!((staged(dd, 1), staged(dd, 2)), ("s1".into(), "s2".into()));
    let guard = crate::chat_history::OutboundStageSendGuard::acquire(dd, "s3", T0).unwrap();
    assert_eq!(
        guard
            .load_staged_outbound_body(&[1; 16])
            .unwrap()
            .unwrap()
            .body,
        "s1"
    );
    drop(guard);
    assert_eq!(list_staged_outbound_bodies(dd).unwrap().len(), 2);
    crate::chat_history::clear_staged_outbound_body(dd, &[1; 16]).unwrap();
    assert_eq!(list_staged_outbound_bodies(dd).unwrap().len(), 1);
}

/// A row the chat-history key sealed directly whose random nonce starts
/// with `0x02` (as an epoch row does) still opens, and moves.
struct FirstByteSealer(Vec<u8>);

impl RowSealer for FirstByteSealer {
    fn seal(&self, _plaintext: &[u8]) -> Result<Vec<u8>, String> {
        Ok(self.0.clone())
    }

    fn open(&self, _sealed: &[u8]) -> Result<Vec<u8>, String> {
        Err("seal only".into())
    }
}

#[test]
fn app_rows_open_after_rotation() {
    let dir = sealed_with_data();
    let dd = dir.path();
    ingest(dd, 2);
    // A K_hist row (as an older build of the pack writes it) that looks like
    // an epoch row; on Windows' path none does, an ordinary one then.
    let item = app_item(4);
    let plaintext = serde_json::to_vec(&item).unwrap();
    let protector = crate::chat_history::DomainProtector::new(b"raven/app-inbox/v1");
    let lookalike = kh_row_like_an_epoch_row(dd, &protector, &plaintext)
        .unwrap_or_else(|| protector.protect(dd, &plaintext).unwrap());
    ingest_with(dd, &FirstByteSealer(lookalike), 4);
    assert_eq!(app_page(dd).0, ["app-1", "app-2", "app-4"]);

    mark_rotation_due(dd).unwrap();
    rotate_data_key(dd, T0).unwrap();
    ingest(dd, 3);
    assert_eq!(
        crate::app_store::row_epochs(dd).unwrap(),
        [Some(2); 4],
        "the lookalike moved too"
    );
    assert!(rotate_data_key(dd, T0 + ROTATION_GRACE_MS).unwrap().dropped);
    let (items, quarantined) = app_page(dd);
    assert_eq!(items, ["app-1", "app-2", "app-3", "app-4"]);
    assert_eq!(quarantined, 0);
}

/// [`app_rows_open_after_rotation`] on Windows' path (its DPAPI stand-in here;
/// the Windows CI job runs the test itself there).
#[test]
fn app_rows_open_after_rotation_on_the_windows_path() {
    let _windows = crate::chat_history::windows_key::ForTests::on();
    app_rows_open_after_rotation();
}

#[test]
fn at_most_one_start_per_day() {
    let dir = sealed_with_data();
    let dd = dir.path();
    mark_rotation_due(dd).unwrap();
    assert!(rotate_data_key(dd, T0).unwrap().started);
    // A deletion during the rotation: due again, no second start meanwhile.
    mark_rotation_due(dd).unwrap();
    assert!(!rotate_data_key(dd, T0 + HOUR_MS).unwrap().started);
    // `raven privacy rotate-now --drop-now` finishes it the same day.
    let now = rotate_data_key_now(dd, T0 + 2 * HOUR_MS, true).unwrap();
    assert!(now.dropped && !now.started, "{now}");
    assert_eq!(epochs(dd), [2]);
    // Due, but a rotation started today already.
    assert!(rotation_due(dd));
    let later = rotate_data_key(dd, T0 + 20 * HOUR_MS).unwrap();
    assert_eq!(later, RotationReport::default());
    // The next day it starts.
    let next = rotate_data_key(dd, T0 + DAY_MS).unwrap();
    assert!(next.started, "{next}");
    assert_eq!(epochs(dd), [2, 3]);
    assert!(!rotation_due(dd));
}

#[test]
fn rotate_now_starts_at_once_and_can_end_the_grace() {
    let dir = sealed_with_data();
    let dd = dir.path();
    let before = readers(dd);
    let started = rotate_data_key_now(dd, T0, false).unwrap();
    assert!(started.started && !started.dropped, "{started}");
    assert_eq!(epochs(dd), [1, 2]);
    let dropped = rotate_data_key_now(dd, T0 + 1, true).unwrap();
    assert!(dropped.dropped, "{dropped}");
    assert_eq!(epochs(dd), [2]);
    assert_eq!(readers(dd), before);
}

#[test]
fn plain_mode_never_rotates() {
    for unsealed in [false, true] {
        let dir = profile();
        let dd = dir.path();
        if unsealed {
            set_mode(dd, Mode::UnsealedByUser).unwrap();
        }
        ChatHistory::append_persisted(dd, row(1, "out")).unwrap();
        stage(dd, 1);
        mark_rotation_due(dd).unwrap();
        assert!(!rotation_due(dd));
        assert_eq!(rotate_data_key(dd, T0).unwrap(), RotationReport::default());
        assert_eq!(
            rotate_data_key_now(dd, T0, true).unwrap(),
            RotationReport::default()
        );
        assert!(!dd.join(META_KEY_FILE).exists());
        assert_eq!(history_form(dd), SealForm::Other, "RVNHIST1 stays");
        assert_eq!(stage_form(dd), SealForm::Other);
        let state = rotation_state(dd);
        assert_eq!((state.current_epoch, state.old_objects), (None, 0));
        let file = read_file(dd).unwrap().unwrap_or_default();
        assert!(file.rotation.is_none() && file.last_rotation_at_ms.is_none());
        assert_eq!(bodies(dd), ["m1"]);
    }
}
