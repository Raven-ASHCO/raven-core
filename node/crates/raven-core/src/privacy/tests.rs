//! PP.3 and PP.4 tests of `privacy.json` and the migration.

use super::*;
use std::cell::Cell;

/// Where a test makes [`migrate_all`] stop as a crash would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Crash {
    /// The mode is sealed, no file sealed yet.
    AfterModeFlip,
    /// The files are sealed (renamed in place), nothing recorded yet.
    AfterSeal,
    /// The policy's sealed sidecar is written, `node_policy.json` still
    /// names the relays (PP.6, [`crate::node_policy::seal_peers`]).
    PolicySidecarWritten,
    /// PP.10: a rotation is recorded (the due mark cleared), its new epoch
    /// not added yet.
    RotationRecorded,
    /// PP.10: the new epoch is current (step 1), nothing re-sealed yet.
    RotationStarted,
    /// PP.10, inside step 2: the history re-sealed ...
    ResealedHistory,
    /// ... the outbound stage ...
    ResealedStage,
    /// ... the app rows ...
    ResealedAppRows,
    /// ... and the sealed files: step 2 is done, the grace not checked yet.
    ResealedFiles,
    /// PP.10, inside step 4: the old epoch left the key file, the record is
    /// not cleared yet.
    EpochDropped,
    /// PP.11 (Windows): K_hist exists, nothing is under it yet.
    WindowsKeyCreated,
    /// PP.11 (Windows): `meta_key.rmk` is under K_hist, the history, stage
    /// and app rows not yet.
    WindowsKeyFileRewrapped,
    /// PP.18 (`raven privacy unseal`): the files are plain, the history, the
    /// stage, the app rows and the stores not yet ...
    UnsealedFiles,
    /// ... the three stores under the at-rest lock are back, the session
    /// store not yet ...
    UnsealedStores,
    /// ... everything is plain, the key file is still there.
    UnsealedAll,
    /// PP.18 (`raven privacy rotate-meta`): the change is recorded, the key
    /// file not changed yet ...
    MetaRotationRecorded,
    /// ... the key file has the new `k_index`, no store is keyed again yet
    /// ...
    MetaKeyChanged,
    /// ... one more store is keyed again.
    MetaStoreRekeyed,
}

thread_local! {
    static CRASH_AT: Cell<Option<Crash>> = const { Cell::new(None) };
}

/// `Err` at the armed point (on this thread, once).
pub(crate) fn crash_point(at: Crash) -> Result<(), AtRestError> {
    if CRASH_AT.with(|armed| armed.get() == Some(at)) {
        CRASH_AT.with(|armed| armed.set(None));
        return Err(AtRestError::Io(format!("injected crash at {at:?}")));
    }
    Ok(())
}

#[test]
fn absent_file_is_plain_and_a_key_without_a_mode_is_sealed() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(mode(dir.path()), Mode::Plain);
    std::fs::write(dir.path().join(PRIVACY_FILE), br#"{"v":1}"#).unwrap();
    assert_eq!(mode(dir.path()), Mode::Plain);
    std::fs::write(dir.path().join(META_KEY_FILE), b"RMK1").unwrap();
    assert_eq!(mode(dir.path()), Mode::Sealed);
    // A recorded mode wins over the key's presence.
    set_mode(dir.path(), Mode::UnsealedByUser).unwrap();
    assert_eq!(mode(dir.path()), Mode::UnsealedByUser);
}

#[test]
fn set_mode_round_trips_and_keeps_unknown_fields() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(PRIVACY_FILE),
        br#"{"v":1,"retention_days":30,"notices":{"sealing_shown":true}}"#,
    )
    .unwrap();
    for wanted in [Mode::Sealed, Mode::UnsealedByUser, Mode::Plain] {
        set_mode(dir.path(), wanted).unwrap();
        assert_eq!(mode(dir.path()), wanted);
    }
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join(PRIVACY_FILE)).unwrap()).unwrap();
    assert_eq!(raw["retention_days"], 30);
    assert_eq!(raw["notices"]["sealing_shown"], true);
    assert_eq!(raw["mode"], "plain");
    assert_eq!(raw["v"], 1);
}

/// Writers never fall back to plaintext because of a bad settings file.
#[test]
fn unreadable_or_unknown_mode_counts_as_sealed_and_is_not_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(PRIVACY_FILE);
    std::fs::write(&path, b"{not json").unwrap();
    assert_eq!(mode(dir.path()), Mode::Sealed);
    assert!(matches!(
        set_mode(dir.path(), Mode::Plain),
        Err(AtRestError::Json(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"{not json");
    std::fs::write(&path, br#"{"v":2,"mode":"sealed_v2"}"#).unwrap();
    assert_eq!(mode(dir.path()), Mode::Sealed);
}

// ── PP.4: the migration ───────────────────────────────────────────────────

use crate::contact_book::tests::{fixture, profile, seal};
use crate::contact_book::{self, CONTACTS_FILE};
use std::path::PathBuf;

const NOW: u64 = 20_000 * DAY_MS;

pub(super) fn arm(at: Crash) {
    CRASH_AT.with(|armed| armed.set(Some(at)));
}

/// An app row as the chat-history key seals it (`protector`) whose first
/// byte is an epoch row's ([`crate::app_store::APP_ROW_V2`]): one random
/// nonce in 256 starts that way. `None` on Windows' path, where every such
/// blob starts with K_hist's tag or DPAPI's version instead
/// ([`crate::chat_history::windows_key::TAG`]), so no row looks like an
/// epoch row there (checked here).
pub(super) fn kh_row_like_an_epoch_row(
    dd: &Path,
    protector: &crate::chat_history::DomainProtector,
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    use crate::chat_history::windows_key::{active, DPAPI_BLOB_VERSION, TAG};
    if active() {
        for _ in 0..64 {
            let blob = protector.protect(dd, plaintext).unwrap();
            assert!(
                blob.starts_with(TAG) || blob.starts_with(&DPAPI_BLOB_VERSION),
                "{:?}",
                &blob[..4]
            );
            assert_ne!(blob[0], crate::app_store::APP_ROW_V2);
        }
        return None;
    }
    let lookalike = (0..4096)
        .map(|_| protector.protect(dd, plaintext).unwrap())
        .find(|blob| blob[0] == crate::app_store::APP_ROW_V2)
        .expect("one in 256 nonces starts with 0x02");
    Some(lookalike)
}

fn book_bytes(dd: &Path) -> Vec<u8> {
    std::fs::read(dd.join(CONTACTS_FILE)).unwrap()
}

fn book_rows(dd: &Path) -> Vec<serde_json::Value> {
    contact_book::read_rows(dd).unwrap().unwrap()
}

fn recorded(dd: &Path) -> PrivacyFile {
    read_file(dd).unwrap().unwrap_or_default()
}

/// What a finished pass records: every kind this build migrates (PP.4's
/// book, PP.5's files) and the noise pins.
fn all_kinds() -> Vec<&'static str> {
    MIGRATED
        .iter()
        .map(|(_, kind)| *kind)
        .chain(RECORDED_EXTRA)
        .map(Kind::name)
        .collect()
}

/// Every entry under `dir` (names, sorted).
fn listing(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    out.sort();
    out
}

#[test]
fn migrate_all_is_idempotent_and_crash_safe() {
    let dir = profile();
    let dd = dir.path();
    fixture(dd);
    let plain = book_bytes(dd);
    let rows = book_rows(dd);
    crate::at_rest::tests::expect_key_file(dd);

    // A crash after the mode flip, before the book's rename: sealed mode, the
    // book still plain (and a stray temp file of the interrupted write).
    arm(Crash::AfterModeFlip);
    assert!(migrate_all(dd, NOW, MigratePolicy::Allow).is_err());
    assert_eq!(mode(dd), Mode::Sealed);
    assert_eq!(book_bytes(dd), plain);
    assert_eq!(book_rows(dd), rows, "readers accept the mix");
    std::fs::write(dd.join(".contacts.json.tmp.0123456789abcdef"), b"[{\"pe").unwrap();

    // A crash after the rename, before anything is recorded.
    arm(Crash::AfterSeal);
    assert!(migrate_all(dd, NOW, MigratePolicy::Allow).is_err());
    let sealed = book_bytes(dd);
    assert!(crate::at_rest::is_sealed(&sealed));
    assert_eq!(book_rows(dd), rows);
    assert!(recorded(dd).kinds.is_empty());

    // The next pass finishes: nothing left to seal, the kinds recorded, and
    // no "older build" note (this build's own crash is no downgrade).
    let report = migrate_all(dd, NOW, MigratePolicy::Allow).unwrap();
    assert_eq!(
        report,
        MigrateReport {
            outcome: MigrateOutcome::Sealed,
            sealed: 0,
            leftovers: 0
        }
    );
    let file = recorded(dd);
    assert_eq!(file.kinds, all_kinds());
    assert_eq!(file.sealed_since_day, Some(NOW / DAY_MS));
    assert!(!file.notices.older_build_wrote_plain);

    // Idempotent: the same bytes, the same record.
    for _ in 0..2 {
        let again = migrate_all(dd, NOW + DAY_MS, MigratePolicy::Allow).unwrap();
        assert_eq!(again.sealed, 0);
        assert_eq!(again.outcome, MigrateOutcome::Sealed);
    }
    assert_eq!(book_bytes(dd), sealed);
    assert_eq!(recorded(dd).sealed_since_day, Some(NOW / DAY_MS));

    // A crash before anything at all (a fresh pass over a plain profile)
    // seals in one go.
    let other = profile();
    fixture(other.path());
    seal(other.path());
    assert!(crate::at_rest::is_sealed(&book_bytes(other.path())));
}

#[test]
fn no_migration_without_identity() {
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    // An empty profile stays a first install.
    assert_eq!(
        migrate_all(dd, NOW, MigratePolicy::Allow).unwrap().outcome,
        MigrateOutcome::NoIdentity
    );
    assert!(listing(dd).is_empty(), "{:?}", listing(dd));
    assert!(crate::identity_store::first_install_allowed(dd));
    // Even with a book (state left behind without an identity): nothing is
    // written, nothing sealed.
    std::fs::write(dd.join(CONTACTS_FILE), b"[]").unwrap();
    let before = listing(dd);
    assert_eq!(
        migrate_all(dd, NOW, MigratePolicy::Allow).unwrap().outcome,
        MigrateOutcome::NoIdentity
    );
    assert_eq!(listing(dd), before);
    assert_eq!(book_bytes(dd), b"[]");
    assert!(!dd.join(META_KEY_FILE).exists() && !dd.join(PRIVACY_FILE).exists());
}

/// The upgrade interlock (review R11): an older raven-node (its Status has no
/// `at_rest`) answers for the profile, so nothing is sealed under it; a node
/// of this build does not hold sealing back, and a sealed profile with
/// nothing plain does not even ask.
#[test]
fn migration_skipped_while_an_older_node_answers() {
    let dir = profile();
    let dd = dir.path();
    fixture(dd);
    let plain = book_bytes(dd);
    // What an older raven-node answers (no `at_rest`).
    let older: IpcResponse = serde_json::from_str(
        r#"{"ok":"status","v":1,"bridge":false,"store":false,"relay":false,"forward_pending":0,"capabilities":["ipc","lan_direct"],"pid":4242,"lan_listen":"127.0.0.1:7499"}"#,
    )
    .unwrap();
    assert!(node_is_older(&older));
    assert!(node_is_older(&IpcResponse::Pong { v: 1 }));
    let asked = Cell::new(0);
    let probe = || {
        asked.set(asked.get() + 1);
        node_is_older(&older)
    };
    let report = migrate_all_with(dd, NOW, MigratePolicy::Allow, Some(&probe)).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::OlderNodeRunning);
    assert_eq!(asked.get(), 1);
    assert_eq!(book_bytes(dd), plain);
    assert!(!dd.join(META_KEY_FILE).exists() && !dd.join(PRIVACY_FILE).exists());
    assert_eq!(mode(dd), Mode::Plain);

    // A node of this build reports `at_rest`: sealing goes ahead.
    let current: IpcResponse = serde_json::from_str(
        r#"{"ok":"status","v":1,"bridge":false,"store":false,"relay":false,"forward_pending":0,"capabilities":["ipc"],"at_rest":{"state":"plain","sealed_files":0,"plain_files":1}}"#,
    )
    .unwrap();
    assert!(!node_is_older(&current));
    crate::at_rest::tests::expect_key_file(dd);
    let probe = || node_is_older(&current);
    let report = migrate_all_with(dd, NOW, MigratePolicy::Allow, Some(&probe)).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::Sealed);
    // The book and the block list (PP.5).
    assert_eq!(report.sealed, 2);

    // Sealed with nothing plain: not even asked.
    let never = || -> bool { panic!("the interlock was asked with nothing to seal") };
    let report = migrate_all_with(dd, NOW, MigratePolicy::Allow, Some(&never)).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::Sealed);
}

/// A debug build without `RAVEN_LAB_AT_REST=1` seals nothing and creates no
/// key (review R02): a debug binary pointed at a real profile changes
/// nothing.
#[cfg(debug_assertions)]
#[test]
fn no_migration_in_debug_without_the_lab_switch() {
    if MigratePolicy::Auto.allows_sealing() {
        // The caller exported RAVEN_LAB_AT_REST=1: nothing to prove here.
        return;
    }
    let dir = profile();
    let dd = dir.path();
    fixture(dd);
    let before = listing(dd);
    let plain = book_bytes(dd);
    let report = migrate_all(dd, NOW, MigratePolicy::Auto).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::NotAllowed);
    assert_eq!(listing(dd), before);
    assert_eq!(book_bytes(dd), plain);
    // And a writer keeps writing today's bytes.
    contact_book::write_rows(dd, &book_rows(dd)).unwrap();
    assert!(!crate::at_rest::is_sealed(&book_bytes(dd)));
}

/// Review R22: less free space than twice the profile plus 64 MiB defers
/// the migration (nothing is changed; status says so), retried at most once
/// an hour.
#[test]
fn free_space_preflight_defers() {
    let dir = profile();
    let dd = dir.path();
    fixture(dd);
    let plain = book_bytes(dd);
    let full = |_: &Path| Some(1u64);
    let report = migrate_inner(dd, NOW, MigratePolicy::Allow, None, &full).unwrap();
    let MigrateOutcome::NeedsDiskSpace { needed } = report.outcome else {
        panic!("{report:?}");
    };
    assert!(
        needed >= SPACE_MARGIN_BYTES + 2 * plain.len() as u64,
        "{needed}"
    );
    assert_eq!(book_bytes(dd), plain);
    assert!(!dd.join(META_KEY_FILE).exists());
    assert_eq!(mode(dd), Mode::Plain);
    let status = status(dd);
    assert_eq!(status.state(), STATE_NEEDS_DISK_SPACE);
    assert_eq!(status.needs_disk_space, Some(needed));
    assert!(disk_space_text(needed).contains(&format!("{} MB", needed.div_ceil(1 << 20))));
    // Within the hour: not checked again, whatever the space now.
    let unasked = |_: &Path| -> Option<u64> { panic!("checked again within the hour") };
    let report =
        migrate_inner(dd, NOW + HOUR_MS - 1, MigratePolicy::Allow, None, &unasked).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::NeedsDiskSpace { needed });
    // An hour later, with room: sealed, and the deferral cleared.
    crate::at_rest::tests::expect_key_file(dd);
    let roomy = |_: &Path| Some(u64::MAX);
    let report = migrate_inner(dd, NOW + HOUR_MS, MigratePolicy::Allow, None, &roomy).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::Sealed);
    assert!(crate::at_rest::is_sealed(&book_bytes(dd)));
    let file = recorded(dd);
    assert_eq!(
        (file.space_deferred_at_ms, file.space_needed_bytes),
        (None, None)
    );
    assert_eq!(status_of(dd), STATE_SEALED);
}

fn status_of(dd: &Path) -> &'static str {
    status(dd).state()
}

#[test]
fn downgrade_leftover_is_resealed_with_a_note() {
    let dir = profile();
    let dd = dir.path();
    fixture(dd);
    seal(dd);
    let rows = book_rows(dd);
    assert!(!status(dd).older_build_wrote_plain);
    // An older build wrote the book in plain (it never reads privacy.json).
    std::fs::write(
        dd.join(CONTACTS_FILE),
        serde_json::to_vec_pretty(&rows).unwrap(),
    )
    .unwrap();
    let st = status(dd);
    // The block list stays sealed; only the book was written in plain.
    assert_eq!((st.sealed_files, st.plain_files), (1, 1));
    let report = migrate_all(dd, NOW, MigratePolicy::Allow).unwrap();
    assert_eq!(
        report,
        MigrateReport {
            outcome: MigrateOutcome::Sealed,
            sealed: 1,
            leftovers: 1
        }
    );
    assert!(crate::at_rest::is_sealed(&book_bytes(dd)));
    assert_eq!(book_rows(dd), rows);
    let st = status(dd);
    assert!(st.older_build_wrote_plain);
    assert_eq!(
        st.to_ipc(st.state()).notes,
        [NOTE_OLDER_BUILD_WROTE_PLAIN.to_owned()]
    );
    // `raven status` says it once.
    assert!(take_older_build_note(dd));
    assert!(!take_older_build_note(dd));
    assert!(!status(dd).older_build_wrote_plain);
}

/// After the migration no file of the profile holds a friend's petname,
/// key, address, routes or PeerId in clear.
#[test]
fn byte_scan_finds_no_petname_key_or_address_after_migration() {
    let dir = profile();
    let dd = dir.path();
    // The book and the block list (sealed since PP.5).
    fixture(dd);
    seal(dd);
    let key = |n: u8| [n; 32];
    let mut needles: Vec<Vec<u8>> = Vec::new();
    for n in 1u8..=4 {
        needles.push(hex::encode(key(n)).into_bytes());
        needles.push(crate::encode_address(&key(n)).into_bytes());
    }
    for text in [
        "Bob",
        "Carol",
        "carol",
        "Dave",
        "Eve",
        "192.168.1.20",
        "10.0.0.5",
        "203.0.113.9",
        "192.168.1.30",
        "11.0.0.1",
        "custodians",
        "lan_dial",
    ] {
        needles.push(text.as_bytes().to_vec());
    }
    needles.push(
        crate::p2p_route::local_peer_id(&crate::identity::Identity::from_seed(&[1; 32]))
            .into_bytes(),
    );
    let mut scanned = 0;
    let mut stack = vec![dd.to_path_buf()];
    while let Some(at) = stack.pop() {
        for entry in std::fs::read_dir(&at).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            scanned += 1;
            for needle in &needles {
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle.as_slice()),
                    "{} holds {:?}",
                    path.display(),
                    String::from_utf8_lossy(needle)
                );
            }
        }
    }
    assert!(
        scanned >= 3,
        "contacts.json, privacy.json, meta_key.rmk at least"
    );
}

#[test]
fn notices_are_said_once() {
    let dir = profile();
    let dd = dir.path();
    fixture(dd);
    // Plain: no sealing notice, and nothing written for asking.
    assert!(!sealing_notice_due(dd));
    assert!(!take_sealing_notice(dd));
    assert!(!dd.join(PRIVACY_FILE).exists());
    seal(dd);
    // Asking whether it is due (the terminal app) takes nothing.
    assert!(sealing_notice_due(dd));
    assert!(sealing_notice_due(dd));
    assert!(take_sealing_notice(dd));
    assert!(!sealing_notice_due(dd));
    assert!(!take_sealing_notice(dd));
    assert!(recorded(dd).notices.sealing_shown);
    // The older-node line: once a day.
    assert!(take_older_node_notice(dd, NOW));
    assert!(!take_older_node_notice(dd, NOW + 1));
    assert!(take_older_node_notice(dd, NOW + DAY_MS));
    // Every field survives the notices' writes.
    let file = recorded(dd);
    assert_eq!(file.kinds, all_kinds());
    assert_eq!(file.mode.as_deref(), Some("sealed"));
}

#[test]
fn status_counts_files_and_names_the_state() {
    let dir = profile();
    let dd = dir.path();
    let st = status(dd);
    assert_eq!(
        (st.state(), st.sealed_files, st.plain_files),
        (STATE_PLAIN, 0, 0)
    );
    fixture(dd);
    // The book and the block list (PP.5).
    let st = status(dd);
    assert_eq!(
        (st.state(), st.sealed_files, st.plain_files),
        (STATE_PLAIN, 0, 2)
    );
    seal(dd);
    let st = status(dd);
    assert_eq!(
        (st.state(), st.sealed_files, st.plain_files),
        (STATE_SEALED, 2, 0)
    );
    let ipc = st.to_ipc(STATE_SEALED);
    assert_eq!(
        serde_json::to_string(&ipc).unwrap(),
        r#"{"state":"sealed","sealed_files":2,"plain_files":0}"#
    );
    // This process lost the key: locked out, never "plain".
    crate::at_rest::forget_cached_keys(dd);
    assert_eq!(status_of(dd), STATE_KEY_UNAVAILABLE);
    set_mode(dd, Mode::UnsealedByUser).unwrap();
    assert_eq!(status_of(dd), STATE_UNSEALED_BY_USER);
    // Unsealed by the user: nothing seals again.
    assert_eq!(
        migrate_all(dd, NOW, MigratePolicy::Allow).unwrap().outcome,
        MigrateOutcome::UnsealedByUser
    );
}
