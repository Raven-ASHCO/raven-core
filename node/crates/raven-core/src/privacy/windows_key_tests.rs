//! PP.11 tests: Windows' own K_hist (`chat_history::windows_key`). A profile
//! an older Windows build wrote (every object DPAPI-direct, no K_hist) reads
//! as before and moves under K_hist at the next migration pass, its key file
//! eagerly; new blobs carry the format tag; the data-key rotation works
//! unchanged; a crash between the steps loses nothing; and deleting the
//! wrapped key file makes everything unreadable.
//!
//! These run on every system: the test thread takes Windows' path
//! ([`ForTests`]) with a stand-in for DPAPI; the Windows CI job (`cargo test
//! -p raven-core`) runs them against real DPAPI. Profiles are temp folders;
//! nothing here calls a keystore.

use super::tests::{arm, Crash};
use super::*;
use crate::app_store::{AppInboxItem, AppStore, PlatformRowSealer, RowSealer};
use crate::at_rest::{HistKeySource, MetaKeys};
use crate::chat_history::windows_key::{
    dpapi_direct_for_tests, is_tagged, key_path, load_history_before_pp11, load_stage_before_pp11,
    open_row_before_pp11, save_history_before_pp11, stage_before_pp11, ForTests,
    DPAPI_BLOB_VERSION, TAG,
};
use crate::chat_history::{
    history_form, history_path, load_staged_outbound_body, outbound_body_stage_path, stage_form,
    stage_outbound_body, ChatHistory, ChatHistoryEntry, ChatHistoryError, DomainProtector, HistKey,
    SealForm,
};
use crate::contact_book::tests::{fixture, profile};
use std::path::PathBuf;
use std::sync::Arc;

/// The start of a day, plus an hour.
const T0: u64 = 20_200 * DAY_MS + HOUR_MS;
const APP_ROW_DOMAIN: &[u8] = b"raven/app-inbox/v1";
const META_KEY_DOMAIN: &[u8] = b"raven/meta-key/v1";

fn row(n: u8) -> ChatHistoryEntry {
    ChatHistoryEntry {
        message_id_hex: hex::encode([n; 16]),
        direction: "out".into(),
        peer_petname: String::new(),
        peer_tag: String::new(),
        peer_pub_hex: hex::encode([0x40 + n; 32]),
        created_at_ms: T0,
        delivery: "delivered".into(),
        preview: String::new(),
        body: format!("m{n}"),
        stored_at_ms: None,
    }
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

/// An older Windows build's app rows: DPAPI directly, no format byte.
struct RowsBeforePp11(PathBuf);

impl RowSealer for RowsBeforePp11 {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        Ok(dpapi_direct_for_tests(&self.0, APP_ROW_DOMAIN, plaintext))
    }

    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, String> {
        PlatformRowSealer::new(&self.0).open(sealed)
    }
}

/// The key source of a Windows build of the pack before PP.11: no K_hist, so
/// the key file it creates is DPAPI-direct.
struct KeysBeforePp11;

impl HistKeySource for KeysBeforePp11 {
    fn load(&self, _data_dir: &Path, _create: bool) -> Result<HistKey, AtRestError> {
        Ok(HistKey::Dpapi)
    }
}

/// What a Windows build before PP.11 left in a profile it did not seal: a
/// contact book and block list, and a chat history, an outbound stage and
/// an app row sealed with DPAPI directly. No K_hist.
fn before_pp11() -> tempfile::TempDir {
    let dir = profile();
    let dd = dir.path();
    fixture(dd);
    save_history_before_pp11(
        dd,
        &ChatHistory {
            entries: vec![row(1)],
        },
    );
    stage_before_pp11(dd, 1, T0, "s1");
    let sealer = RowsBeforePp11(dd.to_path_buf());
    assert!(AppStore::open(dd, &sealer)
        .unwrap()
        .ingest(&app_item(1))
        .unwrap());
    assert!(!key_path(dd).exists());
    dir
}

/// [`before_pp11`], which such a build then began to seal: its key file
/// (DPAPI-direct) and the sealed mode are written, the files are not moved
/// yet. A new process opens it next.
fn sealed_before_pp11() -> tempfile::TempDir {
    let dir = before_pp11();
    let dd = dir.path();
    crate::at_rest::tests::expect_key_file(dd);
    crate::at_rest::keys_load_from(dd, MigratePolicy::Allow, &KeysBeforePp11, false).unwrap();
    assert!(crate::at_rest::key_file_dpapi_direct(dd));
    set_mode(dd, Mode::Sealed).unwrap();
    crate::at_rest::forget_cached_keys(dd);
    assert!(!key_path(dd).exists());
    dir
}

/// What every reader of the profile answers: history, staged body, app
/// inbox, contact book.
fn readers(dd: &Path) -> (Vec<String>, String, Vec<String>, Vec<serde_json::Value>) {
    let history = ChatHistory::load(dd)
        .unwrap()
        .entries
        .into_iter()
        .map(|e| e.body)
        .collect();
    let staged = load_staged_outbound_body(dd, &[1; 16])
        .unwrap()
        .expect("still staged")
        .body;
    let sealer = PlatformRowSealer::new(dd);
    let mut store = AppStore::open(dd, &sealer).unwrap();
    let app = store
        .page("test", false, 50, T0, &|_| Ok(None))
        .unwrap()
        .into_iter()
        .map(|item| item.body)
        .collect();
    assert_eq!(store.quarantined, 0, "no row is set aside");
    let contacts = crate::contact_book::read_rows(dd).unwrap().unwrap();
    (history, staged, app, contacts)
}

/// What [`readers`] answers in a profile made by [`before_pp11`]: the
/// fixture's contact book as a fresh copy reads it.
fn expected(_dd: &Path) -> (Vec<String>, String, Vec<String>, Vec<serde_json::Value>) {
    let reference = profile();
    fixture(reference.path());
    (
        vec!["m1".to_owned()],
        "s1".to_owned(),
        vec!["app-1".to_owned()],
        crate::contact_book::read_rows(reference.path())
            .unwrap()
            .unwrap(),
    )
}

/// The inbox rows' first four bytes.
fn row_heads(dd: &Path) -> Vec<Vec<u8>> {
    let conn = rusqlite::Connection::open(crate::app_store::app_store_path(dd)).unwrap();
    let mut stmt = conn
        .prepare("SELECT substr(sealed, 1, 4) FROM app_inbox")
        .unwrap();
    let heads = stmt
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    heads
}

/// Bytes 8..12 of a history or stage file: the start of its body.
fn body_head(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()[8..12].to_vec()
}

/// What a Windows build before PP.11 (DPAPI only, no K_hist) opens here:
/// the history's bodies, how many bodies the stage holds (`None`: it does
/// not open), and whether each app row opens.
type OlderReads = (Option<Vec<String>>, Option<usize>, Vec<bool>);

fn before_pp11_reads(dd: &Path) -> OlderReads {
    let history = load_history_before_pp11(dd)
        .ok()
        .map(|h| h.entries.into_iter().map(|e| e.body).collect());
    let stage = load_stage_before_pp11(dd).ok();
    let conn = rusqlite::Connection::open(crate::app_store::app_store_path(dd)).unwrap();
    let mut stmt = conn
        .prepare("SELECT sealed FROM app_inbox ORDER BY rowid")
        .unwrap();
    let rows = stmt
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|blob| open_row_before_pp11(dd, &blob.unwrap()))
        .collect();
    (history, stage, rows)
}

fn bodies(names: &[&str]) -> Option<Vec<String>> {
    Some(names.iter().map(|name| (*name).to_owned()).collect())
}

/// What ash's `raven send` writes in this process: the staged body, then
/// the queued history row; and one app row received.
fn ordinary_writes(dd: &Path, n: u8) {
    stage_outbound_body(dd, &[n; 32], &[n; 32], &[n; 32], &[n; 16], T0, "staged").unwrap();
    ChatHistory::append_persisted(dd, row(n)).unwrap();
    let sealer = PlatformRowSealer::new(dd);
    assert!(AppStore::open(dd, &sealer)
        .unwrap()
        .ingest(&app_item(n))
        .unwrap());
}

fn key_file(dd: &Path) -> Vec<u8> {
    std::fs::read(dd.join(META_KEY_FILE)).unwrap()
}

fn current_keys(dd: &Path) -> Arc<MetaKeys> {
    crate::at_rest::keys_cached(dd).unwrap()
}

#[test]
fn old_dpapi_blob_reads_and_is_rewrapped_eagerly() {
    let _windows = ForTests::on();

    // A profile that is not sealed (a debug build without the lab switch):
    // everything reads as before, with no K_hist and without creating one.
    let dir = before_pp11();
    let dd = dir.path();
    assert_eq!(readers(dd), expected(dd));
    assert!(!key_path(dd).exists(), "reading creates no key");
    let report = migrate_all(dd, T0, MigratePolicy::Never).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::NotAllowed);
    assert!(key_path(dd).exists());
    assert_eq!(body_head(&history_path(dd)), TAG);
    assert_eq!(body_head(&outbound_body_stage_path(dd)), TAG);
    assert_eq!(row_heads(dd), [TAG.to_vec()]);
    assert_eq!(history_form(dd), SealForm::Other, "still RVNHIST1");
    assert_eq!(readers(dd), expected(dd));
    // Done: the next pass rewrites nothing.
    let history = std::fs::read(history_path(dd)).unwrap();
    migrate_all(dd, T0, MigratePolicy::Never).unwrap();
    assert_eq!(std::fs::read(history_path(dd)).unwrap(), history);

    // An older build's interlock: a profile that is not sealed keeps its
    // files while an older raven-node answers for it.
    let dir = before_pp11();
    let dd = dir.path();
    let older = || true;
    let report = migrate_all_with(dd, T0, MigratePolicy::Never, Some(&older)).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::NotAllowed);
    assert!(!key_path(dd).exists());
    assert!(crate::chat_history::windows_key::dpapi_files_left(dd));

    // A profile an older build began to seal: the first pass of this build
    // puts its key file under K_hist and its history, stage and app row
    // under the epoch keys.
    let dir = sealed_before_pp11();
    let dd = dir.path();
    let report = migrate_all(dd, T0, MigratePolicy::Allow).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::Sealed);
    assert!(key_path(dd).exists());
    let file = key_file(dd);
    assert_eq!(&file[..5], b"RMK1\x01");
    assert_eq!(&file[5..9], TAG);
    assert_eq!(history_form(dd), SealForm::Epoch(1));
    assert_eq!(stage_form(dd), SealForm::Epoch(1));
    assert_eq!(crate::app_store::row_epochs(dd).unwrap(), [Some(1)]);
    assert_eq!(rotation_state(dd).old_objects, 0);
    assert_eq!(readers(dd), expected(dd));
    // A new process (K_hist from its file) reads the same.
    crate::at_rest::forget_cached_keys(dd);
    crate::at_rest::keys_load_with(dd, MigratePolicy::Never).unwrap();
    assert_eq!(readers(dd), expected(dd));
}

#[test]
fn meta_key_is_rewrapped_eagerly_and_erase_destroys_it() {
    let _windows = ForTests::on();
    let dir = sealed_before_pp11();
    let dd = dir.path();
    let copies = tempfile::tempdir().unwrap();
    let before = copies.path().join("meta_key.before.rmk");
    std::fs::copy(dd.join(META_KEY_FILE), &before).unwrap();
    migrate_all(dd, T0, MigratePolicy::Allow).unwrap();

    // Eagerly also in the sealed fast path: a fully sealed profile whose key
    // file alone is still DPAPI-direct (an older build of the pack) gets it
    // re-wrapped by the next pass, which has nothing else to do.
    crate::at_rest::tests::key_file_before_pp11(dd);
    std::fs::remove_file(key_path(dd)).unwrap();
    crate::at_rest::forget_cached_keys(dd);
    assert!(crate::at_rest::key_file_dpapi_direct(dd));
    let index = crate::at_rest::keys_load_with(dd, MigratePolicy::Never)
        .map(|keys| crate::at_rest::index(&keys, crate::at_rest::ValueType::DeviceKey, b"x"))
        .unwrap();
    let report = migrate_all(dd, T0, MigratePolicy::Allow).unwrap();
    assert_eq!(
        (report.outcome, report.sealed),
        (MigrateOutcome::Sealed, 0),
        "the fast path"
    );
    assert!(!crate::at_rest::key_file_dpapi_direct(dd));
    assert_eq!(&key_file(dd)[5..9], TAG);
    // The same payload: every key and keyed lookup stays.
    assert_eq!(
        crate::at_rest::index(
            &current_keys(dd),
            crate::at_rest::ValueType::DeviceKey,
            b"x"
        ),
        index
    );
    assert_eq!(readers(dd), expected(dd));

    let after = copies.path().join("meta_key.after.rmk");
    std::fs::copy(dd.join(META_KEY_FILE), &after).unwrap();
    assert_eq!(verify_copy(dd, &after).unwrap(), CopyCheck::Opens);

    // Erase deletes K_hist first: from then on the copy taken after the
    // migration opens with nothing this account holds, even with DPAPI.
    std::fs::remove_file(key_path(dd)).unwrap();
    crate::at_rest::forget_cached_keys(dd);
    let wrapped = &std::fs::read(&after).unwrap()[5..];
    let protector = DomainProtector::new(META_KEY_DOMAIN);
    assert!(matches!(
        protector.unprotect_with(&HistKey::Dpapi, dd, wrapped),
        Err(ChatHistoryError::MissingProtectedKey)
    ));
    std::fs::copy(&after, dd.join(META_KEY_FILE)).unwrap();
    assert!(matches!(
        crate::at_rest::keys_load_with(dd, MigratePolicy::Never),
        Err(AtRestError::KeyLost(_))
    ));
    // The honest limit: the copy from before the migration was DPAPI-direct
    // and still opens for this Windows account.
    let old = &std::fs::read(&before).unwrap()[5..];
    assert!(protector.unprotect_with(&HistKey::Dpapi, dd, old).is_ok());
    assert!(!key_path(dd).exists(), "nothing re-mints K_hist");
}

#[test]
fn new_blob_has_the_aead_tag() {
    let _windows = ForTests::on();
    let dir = profile();
    let dd = dir.path();
    let protector = DomainProtector::new(APP_ROW_DOMAIN);
    // Before the profile's K_hist exists an ordinary write mints none (review
    // A-keys-format-2: an older raven-node may still share the files) and
    // seals DPAPI-direct, the form every build reads.
    let first = protector.protect(dd, b"row").unwrap();
    assert!(crate::chat_history::windows_key::is_dpapi_direct(&first));
    assert!(!key_path(dd).exists(), "an ordinary write mints no K_hist");
    assert_eq!(protector.unprotect(dd, &first).unwrap(), b"row");
    // Once it exists (the migration or the first sealing created it), a new
    // blob is AEAD under it behind the tag.
    crate::chat_history::windows_key::load(dd, true).unwrap();
    let sealed = protector.protect(dd, b"row").unwrap();
    assert!(is_tagged(&sealed));
    assert_eq!(protector.unprotect(dd, &sealed).unwrap(), b"row");
    // AEAD under K_hist: a changed byte, another domain or another data dir
    // fails; it is no DPAPI blob.
    let mut changed = sealed.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(protector.unprotect(dd, &changed).is_err());
    assert!(DomainProtector::new(b"raven/other/v1")
        .unprotect(dd, &sealed)
        .is_err());
    let other = profile();
    assert!(protector.unprotect(other.path(), &sealed).is_err());
    assert!(!crate::chat_history::windows_key::is_dpapi_direct(&sealed));
    // The history and the stage of a profile that is not sealed.
    ChatHistory::append_persisted(dd, row(1)).unwrap();
    crate::chat_history::stage_outbound_body(dd, &[1; 32], &[1; 32], &[1; 32], &[1; 16], T0, "s1")
        .unwrap();
    assert_eq!(&std::fs::read(history_path(dd)).unwrap()[..8], b"RVNHIST1");
    assert_eq!(body_head(&history_path(dd)), TAG);
    assert_eq!(body_head(&outbound_body_stage_path(dd)), TAG);
    // One K_hist, added once and never replaced.
    let key = std::fs::read(key_path(dd)).unwrap();
    let again = crate::chat_history::windows_key::load(dd, true).unwrap();
    assert_eq!(std::fs::read(key_path(dd)).unwrap(), key);
    assert_eq!(
        crate::chat_history::windows_key::read(dd)
            .unwrap()
            .as_deref(),
        Some(&*again)
    );
    // A key file that does not unwrap is an error, never replaced.
    std::fs::write(key_path(dd), b"not a dpapi blob").unwrap();
    assert!(matches!(
        crate::chat_history::windows_key::load(dd, true),
        Err(ChatHistoryError::CorruptProtectedKey)
    ));
    assert!(ChatHistory::load(dd).is_err());
    assert_eq!(std::fs::read(key_path(dd)).unwrap(), b"not a dpapi blob");
}

#[test]
fn epoch_rotation_works_unchanged_on_windows() {
    let _windows = ForTests::on();
    let dir = sealed_before_pp11();
    let dd = dir.path();
    migrate_all(dd, T0, MigratePolicy::Allow).unwrap();
    let before = readers(dd);
    mark_rotation_due(dd).unwrap();
    let started = rotate_data_key(dd, T0).unwrap();
    assert!(started.started, "{started}");
    assert_eq!(current_keys(dd).epochs(), [1, 2]);
    assert_eq!(&key_file(dd)[5..9], TAG, "rewritten under K_hist");
    assert!(rotate_data_key(dd, T0 + ROTATION_GRACE_MS).unwrap().dropped);
    assert_eq!(current_keys(dd).epochs(), [2]);
    assert_eq!(&key_file(dd)[5..9], TAG);
    assert_eq!(history_form(dd), SealForm::Epoch(2));
    assert_eq!(readers(dd), before);
    crate::at_rest::forget_cached_keys(dd);
    crate::at_rest::keys_load_with(dd, MigratePolicy::Never).unwrap();
    assert_eq!(readers(dd), before);
}

#[test]
fn crash_between_rewrap_steps_recovers() {
    let _windows = ForTests::on();
    // A sealed profile: after K_hist is created, after the key file moved.
    for at in [Crash::WindowsKeyCreated, Crash::WindowsKeyFileRewrapped] {
        let dir = sealed_before_pp11();
        let dd = dir.path();
        arm(at);
        assert!(migrate_all(dd, T0, MigratePolicy::Allow).is_err(), "{at:?}");
        assert!(key_path(dd).exists());
        assert_eq!(
            crate::at_rest::key_file_dpapi_direct(dd),
            at == Crash::WindowsKeyCreated,
            "{at:?}"
        );
        assert!(crate::chat_history::windows_key::dpapi_files_left(dd));
        // Everything opens either way, in a new process too.
        crate::at_rest::forget_cached_keys(dd);
        crate::at_rest::keys_load_with(dd, MigratePolicy::Never).unwrap();
        assert_eq!(readers(dd), expected(dd), "{at:?}");
        // The next pass finishes.
        assert_eq!(
            migrate_all(dd, T0, MigratePolicy::Allow).unwrap().outcome,
            MigrateOutcome::Sealed
        );
        assert!(!crate::at_rest::key_file_dpapi_direct(dd));
        assert_eq!(history_form(dd), SealForm::Epoch(1));
        assert_eq!(rotation_state(dd).old_objects, 0);
        assert_eq!(readers(dd), expected(dd), "{at:?}");
    }
    // A profile that is not sealed: after K_hist is created.
    let dir = before_pp11();
    let dd = dir.path();
    arm(Crash::WindowsKeyCreated);
    assert!(migrate_all(dd, T0, MigratePolicy::Never).is_err());
    assert!(key_path(dd).exists());
    assert!(crate::chat_history::windows_key::dpapi_files_left(dd));
    assert_eq!(readers(dd), expected(dd));
    migrate_all(dd, T0, MigratePolicy::Never).unwrap();
    assert!(!crate::chat_history::windows_key::dpapi_files_left(dd));
    assert_eq!(row_heads(dd), [TAG.to_vec()]);
    assert_eq!(readers(dd), expected(dd));
}

#[test]
fn meta_key_wraps_under_the_new_root() {
    let _windows = ForTests::on();
    // A profile this build seals first: K_hist is created and the key file
    // is wrapped under it from the start.
    let dir = profile();
    let dd = dir.path();
    fixture(dd);
    crate::at_rest::tests::expect_key_file(dd);
    assert_eq!(
        migrate_all(dd, T0, MigratePolicy::Allow).unwrap().outcome,
        MigrateOutcome::Sealed
    );
    assert!(key_path(dd).exists());
    let file = key_file(dd);
    assert_eq!(&file[5..9], TAG);
    // It opens under K_hist alone: not with DPAPI directly ...
    assert!(
        crate::chat_history::windows_key::open(dd, META_KEY_DOMAIN, &file[5..], || Err(
            ChatHistoryError::MissingProtectedKey
        ))
        .is_err()
    );
    // ... but with the key in chat_history_key.dpapi.
    let k_hist = crate::chat_history::windows_key::read(dd).unwrap().unwrap();
    let opened = DomainProtector::new(META_KEY_DOMAIN)
        .unprotect_with(&HistKey::Wrapped(k_hist), dd, &file[5..])
        .unwrap();
    assert!(opened.starts_with(br#"{"v":1,"k_index":""#));
    // Nothing is created in a profile with nothing to protect.
    let fresh = profile();
    assert_eq!(
        migrate_all(fresh.path(), T0, MigratePolicy::Never)
            .unwrap()
            .outcome,
        MigrateOutcome::NotAllowed
    );
    assert!(!key_path(fresh.path()).exists());
}

#[test]
fn deleting_the_wrapped_key_makes_everything_unreadable() {
    let _windows = ForTests::on();
    // Sealed: the key file, and with it every sealed file, the history, the
    // stage and the app rows.
    let dir = sealed_before_pp11();
    let dd = dir.path();
    migrate_all(dd, T0, MigratePolicy::Allow).unwrap();
    assert_eq!(readers(dd), expected(dd));
    let row = {
        let conn = rusqlite::Connection::open(crate::app_store::app_store_path(dd)).unwrap();
        conn.query_row("SELECT sealed FROM app_inbox", [], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .unwrap()
    };
    std::fs::remove_file(key_path(dd)).unwrap();
    crate::at_rest::forget_cached_keys(dd);
    assert!(crate::at_rest::keys_load_with(dd, MigratePolicy::Never).is_err());
    assert!(ChatHistory::load(dd).is_err());
    assert!(load_staged_outbound_body(dd, &[1; 16]).is_err());
    assert!(crate::contact_book::read_rows::<serde_json::Value>(dd).is_err());
    assert!(PlatformRowSealer::new(dd).open(&row).is_err());
    assert!(migrate_all(dd, T0, MigratePolicy::Allow).is_err());
    assert!(!key_path(dd).exists(), "nothing re-mints K_hist");

    // Not sealed: the history, the stage and the app rows under K_hist.
    let dir = before_pp11();
    let dd = dir.path();
    migrate_all(dd, T0, MigratePolicy::Never).unwrap();
    assert_eq!(readers(dd), expected(dd));
    let row = {
        let conn = rusqlite::Connection::open(crate::app_store::app_store_path(dd)).unwrap();
        conn.query_row("SELECT sealed FROM app_inbox", [], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .unwrap()
    };
    std::fs::remove_file(key_path(dd)).unwrap();
    assert!(matches!(
        ChatHistory::load(dd),
        Err(ChatHistoryError::MissingProtectedKey)
    ));
    assert!(load_staged_outbound_body(dd, &[1; 16]).is_err());
    assert!(PlatformRowSealer::new(dd).open(&row).is_err());
    assert!(!key_path(dd).exists());
}

/// `raven privacy unseal` (PP.18) on Windows: the history, the stage and the
/// app rows go back DPAPI-direct (a build before PP.11 knows no K_hist and
/// no format tag), `meta_key.rmk` goes, and what this build writes in the
/// unsealed profile afterwards stays DPAPI-direct; everything reads as
/// before.
#[test]
fn unseal_writes_dpapi_direct_blobs_back() {
    let _windows = ForTests::on();
    let dir = sealed_before_pp11();
    let dd = dir.path();
    migrate_all(dd, T0, MigratePolicy::Allow).unwrap();
    assert_eq!(history_form(dd), SealForm::Epoch(1));
    let report = unseal_all(dd, &|| true).unwrap();
    assert!(report.history && report.stage, "{report:?}");
    assert_eq!(report.app_rows, 1);
    let dpapi = crate::chat_history::windows_key::DPAPI_BLOB_VERSION.to_vec();
    assert_eq!(body_head(&history_path(dd)), dpapi);
    assert_eq!(body_head(&outbound_body_stage_path(dd)), dpapi);
    assert_eq!(row_heads(dd), std::slice::from_ref(&dpapi));
    assert!(!dd.join(META_KEY_FILE).exists());
    assert_eq!(readers(dd), expected(dd));
    // A message stored now is DPAPI-direct too.
    ChatHistory::append_persisted(dd, row(2)).unwrap();
    assert_eq!(body_head(&history_path(dd)), dpapi);
    assert!(!is_tagged(&std::fs::read(history_path(dd)).unwrap()[8..]));
}

/// Review A-keys-format-2: until this build seals the profile, an ordinary
/// write (ash's send while an older raven-node still answers, raven-node
/// while sealing waits for free disk space) mints no K_hist and seals
/// DPAPI-direct: the older build that shares the files still opens the
/// history, the stage and the app rows. The sealing then mints K_hist and
/// moves everything under the epoch keys as before.
#[test]
fn writes_before_the_sealing_stay_readable_to_an_older_build() {
    let _windows = ForTests::on();
    let dir = before_pp11();
    let dd = dir.path();
    // The upgrade interlock holds the sealing back; ash's own send goes on.
    let older = || true;
    let report = migrate_all_with(dd, T0, MigratePolicy::Allow, Some(&older)).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::OlderNodeRunning);
    ordinary_writes(dd, 2);
    assert!(!key_path(dd).exists(), "an ordinary write mints no K_hist");
    assert_eq!(
        before_pp11_reads(dd),
        (bodies(&["m1", "m2"]), Some(2), vec![true, true])
    );
    // Sealing waits for free disk space: raven-node writes on, the same.
    let short = |_: &Path| Some(1u64);
    let report = migrate_inner(dd, T0, MigratePolicy::Allow, Some(&|| false), &short).unwrap();
    assert!(
        matches!(report.outcome, MigrateOutcome::NeedsDiskSpace { .. }),
        "{report:?}"
    );
    ordinary_writes(dd, 3);
    assert!(!key_path(dd).exists());
    assert_eq!(
        before_pp11_reads(dd),
        (bodies(&["m1", "m2", "m3"]), Some(3), vec![true, true, true])
    );
    // Nothing holds it back any more: the sealing mints K_hist and moves the
    // history, the stage and the app rows under the epoch keys.
    crate::at_rest::tests::expect_key_file(dd);
    let report = migrate_all_with(dd, T0 + HOUR_MS, MigratePolicy::Allow, Some(&|| false)).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::Sealed);
    assert!(key_path(dd).exists());
    assert_eq!(&key_file(dd)[5..9], TAG);
    assert_eq!(history_form(dd), SealForm::Epoch(1));
    assert_eq!(stage_form(dd), SealForm::Epoch(1));
    assert_eq!(
        crate::app_store::row_epochs(dd).unwrap(),
        [Some(1), Some(1), Some(1)]
    );
    let history: Vec<String> = ChatHistory::load(dd)
        .unwrap()
        .entries
        .into_iter()
        .map(|e| e.body)
        .collect();
    assert_eq!(history, ["m1", "m2", "m3"]);
    for n in [1u8, 2, 3] {
        assert!(load_staged_outbound_body(dd, &[n; 16]).unwrap().is_some());
    }
}

/// Review A-keys-format-1: `raven privacy unseal` on a profile this build
/// never sealed (no `meta_key.rmk`) whose history, stage and app rows are
/// under K_hist with its tag (a debug build's pass without the lab switch
/// moved them, or K_hist existed before the sealing was held back) writes
/// them back DPAPI-direct, and says it did: the older build opens them
/// afterwards. An unsealed profile that still holds such objects (an unseal
/// that stopped part-way) is finished by running it again.
#[test]
fn unseal_of_a_profile_never_sealed_writes_dpapi_direct_blobs_back() {
    let _windows = ForTests::on();
    let dpapi = DPAPI_BLOB_VERSION.to_vec();
    let tagged = |dd: &Path| {
        // A debug build without the lab switch moves what an older build
        // wrote under K_hist; a message stored afterwards is under it too.
        assert_eq!(
            migrate_all(dd, T0, MigratePolicy::Never).unwrap().outcome,
            MigrateOutcome::NotAllowed
        );
        ChatHistory::append_persisted(dd, row(2)).unwrap();
        assert!(key_path(dd).exists());
        assert!(!dd.join(META_KEY_FILE).exists());
        assert_eq!(body_head(&history_path(dd)), TAG);
        assert_eq!(body_head(&outbound_body_stage_path(dd)), TAG);
        assert_eq!(row_heads(dd), [TAG.to_vec()]);
        assert_eq!(before_pp11_reads(dd), (None, None, vec![false]));
    };
    let written_back = |dd: &Path| {
        assert_eq!(body_head(&history_path(dd)), dpapi);
        assert_eq!(body_head(&outbound_body_stage_path(dd)), dpapi);
        assert_eq!(row_heads(dd), std::slice::from_ref(&dpapi));
        assert_eq!(
            before_pp11_reads(dd),
            (bodies(&["m1", "m2"]), Some(1), vec![true])
        );
        assert_eq!(mode(dd), Mode::UnsealedByUser);
    };

    let dir = before_pp11();
    let dd = dir.path();
    tagged(dd);
    let report = unseal_all(dd, &|| true).unwrap();
    assert!(!report.already_plain, "{report:?}");
    assert!(report.history && report.stage, "{report:?}");
    assert_eq!((report.app_rows, report.unreadable), (1, 0), "{report:?}");
    written_back(dd);
    // This build reads the same, and writes DPAPI-direct from here on.
    ChatHistory::append_persisted(dd, row(3)).unwrap();
    assert_eq!(body_head(&history_path(dd)), dpapi);
    assert_eq!(load_history_before_pp11(dd).unwrap().entries.len(), 3);
    // Nothing is left to write back.
    let again = unseal_all(dd, &|| true).unwrap();
    assert_eq!(
        (again.history, again.stage, again.app_rows),
        (false, false, 0)
    );

    // The unsealing stopped after the mode was recorded: the next run
    // writes them back.
    let dir = before_pp11();
    let dd = dir.path();
    tagged(dd);
    set_mode(dd, Mode::UnsealedByUser).unwrap();
    let report = unseal_all(dd, &|| true).unwrap();
    assert!(report.history && report.stage, "{report:?}");
    assert_eq!(report.app_rows, 1, "{report:?}");
    written_back(dd);

    // A profile whose objects are all DPAPI-direct already: nothing to do.
    let dir = before_pp11();
    let dd = dir.path();
    let report = unseal_all(dd, &|| true).unwrap();
    assert!(report.already_plain, "{report:?}");
    assert_eq!(
        before_pp11_reads(dd),
        (bodies(&["m1"]), Some(1), vec![true])
    );
}

/// Review A-keys-format-4: a sealed profile whose K_hist is gone for good
/// (`chat_history_key.dpapi` deleted, or no longer unwrapping for this
/// account) loads as `KeyLost`, not as a keychain to wait for: status says
/// `key_lost` and the commands say the key is gone. Everything still fails
/// closed (the book is locked, never corrupt; nothing is set aside), and the
/// key put back opens the profile again.
#[test]
fn a_lost_k_hist_is_key_lost_not_a_keychain_wait() {
    let _windows = ForTests::on();
    let dir = sealed_before_pp11();
    let dd = dir.path();
    migrate_all(dd, T0, MigratePolicy::Allow).unwrap();
    let k_hist = std::fs::read(key_path(dd)).unwrap();
    let lost = |dd: &Path| {
        crate::at_rest::forget_cached_keys(dd);
        let e = crate::at_rest::keys_load_with(dd, MigratePolicy::Never).unwrap_err();
        assert!(matches!(e, AtRestError::KeyLost(_)), "{e:?}");
        assert!(e.is_unavailable());
        assert!(crate::at_rest::key_lost(dd));
        assert_eq!(status(dd).state(), STATE_KEY_LOST);
        assert_eq!(key_unavailable_text(dd), KEY_LOST_TEXT);
        assert!(crate::contact_book::read_rows::<serde_json::Value>(dd)
            .unwrap_err()
            .is_locked());
        // The node's attempt says the same.
        let e = migrate_all(dd, T0, MigratePolicy::Allow).unwrap_err();
        assert!(matches!(e, AtRestError::KeyLost(_)), "{e:?}");
    };
    std::fs::remove_file(key_path(dd)).unwrap();
    lost(dd);
    assert!(!key_path(dd).exists(), "nothing re-mints K_hist");
    std::fs::write(key_path(dd), b"not a dpapi blob").unwrap();
    lost(dd);
    // Put back: the profile opens again, and the loss is forgotten.
    std::fs::write(key_path(dd), &k_hist).unwrap();
    crate::at_rest::keys_load_with(dd, MigratePolicy::Never).unwrap();
    assert!(!crate::at_rest::key_lost(dd));
    assert_eq!(status(dd).state(), STATE_SEALED);
    assert_eq!(key_unavailable_text(dd), KEY_UNAVAILABLE_TEXT);
    assert_eq!(readers(dd), expected(dd));
}
