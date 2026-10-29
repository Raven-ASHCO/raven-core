//! PP.3 tests: the lab K_hist ([`TestKeySource`]) or the cfg(test) platform
//! path (the derived lab key on macOS and Linux, K_hist in its DPAPI-wrapped
//! file on Windows); never a real keychain item. Profiles are temp folders
//! with an identity marker.

use super::*;
use crate::identity_store::{identity_recorded, BACKEND_MARKER_NAME, IDENTITY_BINDING_NAME};
use crate::lan_gate::{LAB_AT_REST, LAB_AT_REST_KEY_FAULT};
use crate::privacy::{set_mode, PRIVACY_FILE};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Barrier;

// ── Acceptance: no test writes meta_key.rmk unless it says so ──

static EXPECTED_KEY_FILES: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());
static KEY_FILES_CREATED: Mutex<BTreeMap<PathBuf, usize>> = Mutex::new(BTreeMap::new());

/// A test that means to create `meta_key.rmk` in `dir` says so first: in
/// raven-core's test build every creation is checked against this list, so
/// no other test (and no existing path) writes one by accident.
pub(crate) fn expect_key_file(dir: &Path) {
    EXPECTED_KEY_FILES
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(canonical_dir(dir));
}

/// Make `dir`'s key file what a Windows build before PP.11 wrote: the same
/// payload, wrapped with DPAPI directly (the stand-in off Windows). The keys
/// must be loaded here.
pub(crate) fn key_file_before_pp11(dir: &Path) {
    let path = dir.join(META_KEY_FILE);
    let keys = unwrap_key_file(
        &cached_hist(dir).unwrap(),
        dir,
        &std::fs::read(&path).unwrap(),
    )
    .unwrap();
    let mut file = b"RMK1\x01".to_vec();
    file.extend(crate::chat_history::windows_key::dpapi_direct_for_tests(
        dir,
        META_KEY_DOMAIN,
        &keys.payload.to_json(),
    ));
    std::fs::write(&path, file).unwrap();
}

/// Called right after `meta_key.rmk` is written (test builds only).
pub(super) fn note_key_file_created(dir: &Path) {
    let canonical = canonical_dir(dir);
    *KEY_FILES_CREATED
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .entry(canonical.clone())
        .or_default() += 1;
    let expected = EXPECTED_KEY_FILES
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains(&canonical);
    assert!(
        expected,
        "a test created {META_KEY_FILE} without at_rest::tests::expect_key_file"
    );
}

fn key_files_created(dir: &Path) -> usize {
    KEY_FILES_CREATED
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&canonical_dir(dir))
        .copied()
        .unwrap_or(0)
}

// ── The fault hook of `migrate_file`'s check ──

thread_local! {
    static SEAL_FAULT: Cell<bool> = const { Cell::new(false) };
}

/// `migrate_file` checks the sealed temp file's bytes through this: armed
/// (on this thread), one byte comes back flipped, as a bad write would.
pub(super) fn seal_fault(written: &[u8]) -> Vec<u8> {
    let mut copy = written.to_vec();
    if SEAL_FAULT.with(|armed| armed.replace(false)) {
        if let Some(last) = copy.last_mut() {
            *last ^= 0x01;
        }
    }
    copy
}

// ── A counting K_hist ──

struct TestKeySource {
    key: [u8; 32],
    calls: AtomicUsize,
    creates: AtomicUsize,
    /// A keystore that lost K_hist: a read without `create` fails.
    missing: bool,
    /// Holds each caller until this many have arrived (racing creators).
    barrier: Option<Barrier>,
}

impl TestKeySource {
    fn new(seed: u8) -> Self {
        Self {
            key: [seed; 32],
            calls: AtomicUsize::new(0),
            creates: AtomicUsize::new(0),
            missing: false,
            barrier: None,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn creates(&self) -> usize {
        self.creates.load(Ordering::SeqCst)
    }

    fn hist(&self) -> HistKey {
        HistKey::Key(Zeroizing::new(self.key))
    }
}

impl HistKeySource for TestKeySource {
    fn load(&self, _data_dir: &Path, create: bool) -> Result<HistKey, AtRestError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if create {
            self.creates.fetch_add(1, Ordering::SeqCst);
        }
        if let Some(barrier) = &self.barrier {
            barrier.wait();
        }
        if self.missing && !create {
            // As the platform source says it (review A-keys-format-4).
            return Err(hist_key_error(ChatHistoryError::MissingProtectedKey, true));
        }
        Ok(self.hist())
    }
}

/// A temp profile with an identity on record (its backend marker only: no
/// seed, so nothing here could read a keystore).
fn profile() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(BACKEND_MARKER_NAME), b"locked-file\n").unwrap();
    dir
}

fn load(dir: &Path, source: &TestKeySource) -> Arc<MetaKeys> {
    expect_key_file(dir);
    keys_load_from(dir, MigratePolicy::Allow, source, false).unwrap()
}

/// A sealed profile with its keys loaded.
fn sealed_profile(source: &TestKeySource) -> (tempfile::TempDir, Arc<MetaKeys>) {
    let dir = profile();
    set_mode(dir.path(), Mode::Sealed).unwrap();
    let keys = load(dir.path(), source);
    (dir, keys)
}

/// Another process rotates (what PP.10 will do): epoch `current + 1` is
/// added and made current; `k_index` stays.
fn rotate(dir: &Path, source: &TestKeySource) {
    let path = dir.join(META_KEY_FILE);
    let bytes = std::fs::read(&path).unwrap();
    let hist = source.hist();
    let mut payload = unwrap_key_file(&hist, dir, &bytes).unwrap().payload;
    let next = payload.current + 1;
    payload.epochs.push((next, random_key()));
    payload.current = next;
    let file = wrap_key_file(&hist, dir, &payload).unwrap();
    crate::paths::atomic_write_private(&path, &file).unwrap();
}

fn names_in(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Epoch 1 under the key `[0x22; 32]`, `k_index` `[0x11; 32]`: the keys the
/// pinned vectors use (here, in `chat_history` and in `app_store`).
pub(crate) fn fixed_keys() -> MetaKeys {
    MetaKeys::from_payload(KeyPayload {
        k_index: Zeroizing::new([0x11; 32]),
        epochs: vec![(1, Zeroizing::new([0x22; 32]))],
        current: 1,
    })
}

// ── Formats ──

/// The formats are fixed forever: these values were computed by an
/// independent stdlib-only Python reference (HKDF, HMAC, HChaCha20,
/// ChaCha20-Poly1305 checked against RFC 8439 and the XChaCha draft vectors).
#[test]
fn formats_are_pinned() {
    let keys = fixed_keys();
    let key = |use_| hex::encode(&keys.data_key(1, use_).unwrap()[..]);
    assert_eq!(
        hex::encode(&keys.index[..]),
        "42f275ca09208e435fe2bbc5d7f057bd8a3bc2d051a02838886ece56d79d094b"
    );
    assert_eq!(
        hex::encode(&keys.lock[..]),
        "82b5ce09ef4f08b831707512bd898e6e82f47407cc4b178c73739cd2377633c0"
    );
    for (use_, expected) in [
        (
            DataUse::MetaFile,
            "050d844a3c9666d505d0858af354680921c1102d5f9a935d7bef1653106e9661",
        ),
        (
            DataUse::MetaRow,
            "860e8e55113f76d8f568ab1f6b7b5d36360ea0da9156cbe177ff7b9aa7aa6ed2",
        ),
        (
            DataUse::History,
            "12b0964828a0ed5f9eb99c95224cdfe5ac11834becbed44db591290a389be76f",
        ),
        (
            DataUse::Stage,
            "ee8646b3cab15026c08a056eaf548f1aadf837fa760f54b0e8c91ff29225f3ea",
        ),
        (
            DataUse::AppRow,
            "f463d55ef165c18a44e22f8b5827ece6be7803b7b748600aa877ca557e5c1f5f",
        ),
    ] {
        assert_eq!(key(use_), expected, "{use_:?}");
    }
    assert_eq!(
        hex::encode(index(&keys, ValueType::DeviceKey, b"device")),
        "05af271b6e425aec3a0d23966f293bc66b579c234ccb935d6bc2a8513643114f"
    );
    assert_eq!(
        lock_name(&keys, &[0x33; 32]),
        ".send_585b2801b65faf50346ab491cd6a48e2.lock.sqlite"
    );
    assert_eq!(
        hex::encode(seal_with(&keys, Kind::Contacts, 1, &[0x44; 24], b"[]")),
        "524d5331010100000001444444444444444444444444444444444444444444444444\
         858ed5c86583468aaac50d6fda961e313af7"
    );
    assert_eq!(
        hex::encode(seal_row_with(
            &keys,
            "owed_acks_v1",
            b"pk",
            1,
            &[0x55; 24],
            b"meta"
        )),
        "0100000001555555555555555555555555555555555555555555555555\
         ca8ca507005eda16525f59d8bd2a05996db87a17"
    );
    let payload = KeyPayload {
        k_index: Zeroizing::new([0xab; 32]),
        epochs: vec![
            (1, Zeroizing::new([0x01; 32])),
            (2, Zeroizing::new([0xfe; 32])),
        ],
        current: 2,
    };
    let json = payload.to_json();
    assert_eq!(
        std::str::from_utf8(&json).unwrap(),
        format!(
            r#"{{"v":1,"k_index":"{}","epochs":[{{"e":1,"k":"{}"}},{{"e":2,"k":"{}"}}],"current":2}}"#,
            "ab".repeat(32),
            "01".repeat(32),
            "fe".repeat(32)
        )
    );
    let parsed = KeyPayload::parse(&json).unwrap();
    assert_eq!(parsed.current, 2);
    assert_eq!(*parsed.k_index, [0xab; 32]);
    assert_eq!(parsed.epochs.len(), 2);
}

#[test]
fn seal_open_round_trip_every_kind() {
    let (_dir, keys) = sealed_profile(&TestKeySource::new(1));
    for kind in Kind::ALL {
        let plain = format!(r#"{{"petname":"Sam","kind":{}}}"#, kind.code());
        let sealed = seal(&keys, kind, plain.as_bytes());
        assert!(is_sealed(&sealed));
        assert_eq!(sealed[4], FORMAT_VERSION);
        assert_eq!(sealed[5], kind.code());
        assert_eq!(sealed[6..10], keys.current_epoch().to_be_bytes());
        assert_eq!(
            sealed.len(),
            SEALED_HEADER_LEN + NONCE_LEN + plain.len() + TAG_LEN
        );
        assert!(!contains(&sealed, b"Sam"));
        assert_ne!(sealed, seal(&keys, kind, plain.as_bytes()), "random nonce");
        assert_eq!(&open(&keys, kind, &sealed).unwrap()[..], plain.as_bytes());
        assert_eq!(Kind::from_code(kind.code()), Some(kind));
        assert!(!kind.name().is_empty());
    }
    // Reserved numbers are no kind (yet).
    for code in [0, 34, 63, 255] {
        assert_eq!(Kind::from_code(code), None, "{code}");
    }
    let mut codes: Vec<u8> = Kind::ALL.iter().map(|k| k.code()).collect();
    codes.dedup();
    assert_eq!(codes.len(), Kind::ALL.len());
    assert!(codes.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn wrong_kind_wrong_key_truncated_and_one_flipped_byte_fail_typed() {
    let (_dir, keys) = sealed_profile(&TestKeySource::new(2));
    // Another profile's keys (the same K_hist does not matter: the payload
    // is random per profile).
    let (_other, other_keys) = sealed_profile(&TestKeySource::new(2));
    let sealed = seal(&keys, Kind::Contacts, br#"[{"petname":"Sam"}]"#);
    assert!(matches!(
        open(&keys, Kind::LanSeen, &sealed),
        Err(AtRestError::WrongKind { want: 2, got: 1 })
    ));
    assert!(matches!(
        open(&other_keys, Kind::Contacts, &sealed),
        Err(AtRestError::Tampered { kind: 1 })
    ));
    for len in [0, 3, 4, 9, 10, 49] {
        assert!(
            matches!(
                open(&keys, Kind::Contacts, &sealed[..len]),
                Err(AtRestError::Truncated)
            ),
            "{len}"
        );
    }
    // The tag alone is cut: authentication fails.
    assert!(matches!(
        open(&keys, Kind::Contacts, &sealed[..sealed.len() - 1]),
        Err(AtRestError::Tampered { kind: 1 })
    ));
    for at in 0..sealed.len() {
        let mut bad = sealed.clone();
        bad[at] ^= 0x01;
        let error = open(&keys, Kind::Contacts, &bad).unwrap_err();
        match at {
            // magic, version 0x00
            0..=4 => assert!(matches!(error, AtRestError::Tampered { kind: 1 }), "{at}"),
            5 => assert!(
                matches!(error, AtRestError::WrongKind { want: 1, got: 0 }),
                "{at}"
            ),
            6..=9 => assert!(
                matches!(error, AtRestError::StaleKeys { epoch } if epoch != 1),
                "{at}"
            ),
            _ => assert!(matches!(error, AtRestError::Tampered { kind: 1 }), "{at}"),
        }
    }
    // Plain JSON handed to open is not sealed data.
    assert!(matches!(
        open(&keys, Kind::Contacts, b"[{\"petname\":\"Sam\"}]"),
        Err(AtRestError::Tampered { kind: 1 })
    ));
}

#[test]
fn row_blobs_are_bound_to_table_and_primary_key() {
    let (_dir, keys) = sealed_profile(&TestKeySource::new(3));
    let blob = seal_row(&keys, "owed_acks_v1", b"kh-peer", b"meta");
    assert_eq!(blob[0], FORMAT_VERSION);
    assert_eq!(blob[1..5], 1u32.to_be_bytes());
    assert_eq!(blob.len(), ROW_HEADER_LEN + NONCE_LEN + 4 + TAG_LEN);
    assert_eq!(
        &open_row(&keys, "owed_acks_v1", b"kh-peer", &blob).unwrap()[..],
        b"meta"
    );
    let tampered = |result: Result<Zeroizing<Vec<u8>>, AtRestError>| {
        matches!(
            result,
            Err(AtRestError::Tampered {
                kind: NOT_A_FILE_KIND
            })
        )
    };
    assert!(tampered(open_row(
        &keys,
        "owed_ack_held_v1",
        b"kh-peer",
        &blob
    )));
    assert!(tampered(open_row(&keys, "owed_acks_v1", b"kh-peeR", &blob)));
    // The 0x00 separator keeps ("ab", "c") apart from ("a", "bc").
    let split = seal_row(&keys, "ab", b"c", b"x");
    assert!(tampered(open_row(&keys, "a", b"bc", &split)));
    assert!(matches!(
        open_row(&keys, "t", b"", &[]),
        Err(AtRestError::Truncated)
    ));
    assert!(matches!(
        open_row(
            &keys,
            "owed_acks_v1",
            b"kh-peer",
            &blob[..ROW_HEADER_LEN + NONCE_LEN + TAG_LEN - 1]
        ),
        Err(AtRestError::Truncated)
    ));
    let mut stale = blob.clone();
    stale[1..5].copy_from_slice(&9u32.to_be_bytes());
    assert!(matches!(
        open_row(&keys, "owed_acks_v1", b"kh-peer", &stale),
        Err(AtRestError::StaleKeys { epoch: 9 })
    ));
    let mut zero = blob.clone();
    zero[0] = 0;
    assert!(tampered(open_row(&keys, "owed_acks_v1", b"kh-peer", &zero)));
}

/// Phase 6b P6.25 (merge amendment, design C C1): a sealed file or row
/// that fails authentication under the loaded keys is noted as
/// `SEC_LOCAL_ROLLBACK` about this computer; one cut short, of a newer
/// format or another epoch is not. Every open fails exactly as before, and
/// nothing is noted while the events gate is shut.
#[test]
fn a_tampered_open_is_noted_as_a_local_rollback() {
    use crate::security_events::{Attribution, SecKind, Via};
    use crate::security_sense::tests::{Capture, Shut};
    let (_dir, keys) = sealed_profile(&TestKeySource::new(5));
    let row = seal_row(&keys, "t", b"k", b"v");
    let mut flipped_row = row.clone();
    *flipped_row.last_mut().unwrap() ^= 1;
    let mut flipped_file = seal(&keys, Kind::LanSeen, b"{}");
    *flipped_file.last_mut().unwrap() ^= 1;
    let tampered = |result: Result<Zeroizing<Vec<u8>>, AtRestError>| {
        matches!(result, Err(AtRestError::Tampered { .. }))
    };
    {
        let shut = Shut::start();
        assert!(tampered(open_row(&keys, "t", b"k", &flipped_row)));
        assert!(tampered(open(&keys, Kind::LanSeen, &flipped_file)));
        assert_eq!(shut.noted(), 0);
    }
    let Some(cap) = Capture::start() else {
        return;
    };
    assert!(tampered(open_row(&keys, "t", b"k", &flipped_row)));
    assert!(tampered(open(&keys, Kind::LanSeen, &flipped_file)));
    assert!(matches!(
        open_row(&keys, "t", b"k", &row[..3]),
        Err(AtRestError::Truncated)
    ));
    let mut stale = row.clone();
    stale[1..5].copy_from_slice(&9u32.to_be_bytes());
    assert!(matches!(
        open_row(&keys, "t", b"k", &stale),
        Err(AtRestError::StaleKeys { epoch: 9 })
    ));
    assert_eq!(&open_row(&keys, "t", b"k", &row).unwrap()[..], b"v");
    let local = (SecKind::LocalRollback, Attribution::Local, Via::Local);
    assert_eq!(cap.kinds(), vec![local, local]);
}

#[test]
fn newer_version_is_refused() {
    let source = TestKeySource::new(4);
    let (dir, keys) = sealed_profile(&source);
    let mut sealed = seal(&keys, Kind::LanSeen, b"{}");
    sealed[4] = 2;
    assert!(matches!(
        open(&keys, Kind::LanSeen, &sealed),
        Err(AtRestError::NewerFormat(2))
    ));
    let mut row = seal_row(&keys, "t", b"k", b"v");
    row[0] = 2;
    assert!(matches!(
        open_row(&keys, "t", b"k", &row),
        Err(AtRestError::NewerFormat(2))
    ));

    // A key file of a newer format costs no keystore call.
    let newer = profile();
    let mut file = std::fs::read(dir.path().join(META_KEY_FILE)).unwrap();
    file[4] = 2;
    std::fs::write(newer.path().join(META_KEY_FILE), &file).unwrap();
    let fresh = TestKeySource::new(4);
    assert!(matches!(
        keys_load_from(newer.path(), MigratePolicy::Allow, &fresh, false),
        Err(AtRestError::NewerFormat(2))
    ));
    assert_eq!(fresh.calls(), 0);
    // A newer payload inside a valid wrap.
    let payload = format!(
        r#"{{"v":2,"k_index":"{}","epochs":[],"current":1,"more":true}}"#,
        "00".repeat(32)
    );
    let wrapped = DomainProtector::new(META_KEY_DOMAIN)
        .protect_with(&fresh.hist(), newer.path(), payload.as_bytes())
        .unwrap();
    let mut file = b"RMK1\x01".to_vec();
    file.extend_from_slice(&wrapped);
    std::fs::write(newer.path().join(META_KEY_FILE), &file).unwrap();
    assert!(matches!(
        keys_load_from(newer.path(), MigratePolicy::Allow, &fresh, false),
        Err(AtRestError::NewerFormat(2))
    ));
    // Never replaced.
    assert_eq!(
        std::fs::read(newer.path().join(META_KEY_FILE)).unwrap(),
        file
    );
}

#[test]
fn plain_json_still_loads() {
    let source = TestKeySource::new(5);
    // A plain profile, nothing loaded: plain files load without any key.
    let dir = profile();
    let path = dir.path().join("lan_seen.json");
    assert!(
        load_json::<serde_json::Value>(dir.path(), &path, Kind::LanSeen)
            .unwrap()
            .is_none()
    );
    std::fs::write(&path, br#"{"a":{"ip":"192.0.2.7"}}"#).unwrap();
    let value: serde_json::Value = load_json(dir.path(), &path, Kind::LanSeen)
        .unwrap()
        .unwrap();
    assert_eq!(value["a"]["ip"], "192.0.2.7");
    // A sealed profile reads a plain file an older build left.
    let (sealed_dir, _keys) = sealed_profile(&source);
    let path = sealed_dir.path().join("learned_routes.json");
    std::fs::write(&path, br#"{"v":1}"#).unwrap();
    let value: serde_json::Value = load_json(sealed_dir.path(), &path, Kind::LearnedRoutes)
        .unwrap()
        .unwrap();
    assert_eq!(value["v"], 1);
    // Unparsable plain JSON is an error, never an empty value.
    std::fs::write(&path, b"{\"v\":").unwrap();
    assert!(matches!(
        load_json::<serde_json::Value>(sealed_dir.path(), &path, Kind::LearnedRoutes),
        Err(AtRestError::Json(_))
    ));
}

#[test]
fn store_json_seals_in_sealed_mode() {
    let source = TestKeySource::new(6);
    let (dir, keys) = sealed_profile(&source);
    let path = dir.path().join("contacts.json");
    let rows =
        serde_json::json!([{"petname": "Sam", "addr": "rvn1qexample", "lan": "192.0.2.7:7420"}]);
    store_json(dir.path(), &path, Kind::Contacts, &rows).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert!(is_sealed(&bytes));
    assert_eq!(bytes[5], Kind::Contacts.code());
    for clear in [&b"Sam"[..], b"rvn1qexample", b"192.0.2.7"] {
        assert!(!contains(&bytes, clear));
    }
    assert_eq!(
        &open(&keys, Kind::Contacts, &bytes).unwrap()[..],
        &serde_json::to_vec_pretty(&rows).unwrap()[..]
    );
    assert_eq!(
        load_json::<serde_json::Value>(dir.path(), &path, Kind::Contacts).unwrap(),
        Some(rows.clone())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // A file in a subfolder, through the lock of a read-modify-write.
    std::fs::create_dir_all(dir.path().join("contact_inbox")).unwrap();
    let wire = dir.path().join("contact_inbox").join("00ff.wire");
    let lock = lock_file(dir.path(), &wire, Kind::ContactInbox).unwrap();
    assert!(lock.load_bytes().unwrap().is_none());
    lock.store_bytes(b"\x01request").unwrap();
    assert_eq!(&lock.load_bytes().unwrap().unwrap()[..], b"\x01request");
    drop(lock);
    assert!(is_sealed(&std::fs::read(&wire).unwrap()));
    // Only registered files, and only under their own kind.
    assert!(matches!(
        store_json(
            dir.path(),
            &dir.path().join("unregistered.json"),
            Kind::Contacts,
            &rows
        ),
        Err(AtRestError::Io(_))
    ));
    assert!(matches!(
        store_json(dir.path(), &path, Kind::LanSeen, &rows),
        Err(AtRestError::Io(_))
    ));
    assert!(matches!(
        store_json(
            dir.path(),
            &dir.path().join("node_policy.json"),
            Kind::Contacts,
            &rows
        ),
        Err(AtRestError::Io(_))
    ));
    // A sealed profile whose keys this process has not loaded: the write
    // fails and nothing is written; the read of a sealed file fails too.
    let unloaded = profile();
    set_mode(unloaded.path(), Mode::Sealed).unwrap();
    let book = unloaded.path().join("contacts.json");
    assert!(matches!(
        store_json(unloaded.path(), &book, Kind::Contacts, &rows),
        Err(AtRestError::KeyUnavailable(_))
    ));
    assert!(!book.exists());
    std::fs::write(&book, &bytes).unwrap();
    assert!(matches!(
        load_json::<serde_json::Value>(unloaded.path(), &book, Kind::Contacts),
        Err(AtRestError::KeyUnavailable(_))
    ));
}

/// Plain and unsealed-by-user profiles get exactly the bytes of today's
/// writers (the files older builds read).
#[test]
fn store_json_in_plain_mode_is_byte_identical_to_todays_writer() {
    let today = tempfile::tempdir().unwrap();
    let pack = profile();
    let mut list = crate::chat_history::BlockList::default();
    list.block(&"ab".repeat(32));
    list.block(&"cd".repeat(32));
    list.save(today.path()).unwrap();
    let mut registry = crate::device_cert::DeviceRegistry::default();
    registry.revoke("old-device");
    crate::device_cert::save_device_registry(today.path(), &registry).unwrap();
    for mode in [Mode::Plain, Mode::UnsealedByUser] {
        if mode == Mode::UnsealedByUser {
            set_mode(pack.path(), mode).unwrap();
        }
        assert_eq!(crate::privacy::mode(pack.path()), mode);
        let blocked = pack.path().join("blocked_pubs.json");
        store_json(pack.path(), &blocked, Kind::BlockedPubs, &list).unwrap();
        assert_eq!(
            std::fs::read(&blocked).unwrap(),
            std::fs::read(today.path().join("blocked_pubs.json")).unwrap()
        );
        let devices = pack.path().join("device_registry.json");
        store_json(pack.path(), &devices, Kind::DeviceRegistry, &registry).unwrap();
        assert_eq!(
            std::fs::read(&devices).unwrap(),
            std::fs::read(today.path().join("device_registry.json")).unwrap()
        );
    }
    assert!(!pack.path().join(META_KEY_FILE).exists());
}

// ── Keys ──

#[test]
fn key_created_once_and_adopted_by_a_racing_creator() {
    let dir = profile();
    expect_key_file(dir.path());
    let source = TestKeySource {
        barrier: Some(Barrier::new(2)),
        ..TestKeySource::new(7)
    };
    // Two processes: the in-process load gate is not in the way.
    let (a, b) = std::thread::scope(|s| {
        let a = s.spawn(|| load_or_create(dir.path(), MigratePolicy::Allow, &source));
        let b = s.spawn(|| load_or_create(dir.path(), MigratePolicy::Allow, &source));
        (a.join().unwrap().unwrap(), b.join().unwrap().unwrap())
    });
    // Both minted (both found no file), one wrote, the other adopted.
    assert_eq!(source.creates(), 2);
    assert_eq!(key_files_created(dir.path()), 1);
    assert_eq!(a.stamp, b.stamp);
    assert_eq!(
        index(&a.keys, ValueType::DeviceKey, b"x"),
        index(&b.keys, ValueType::DeviceKey, b"x")
    );
    let sealed = seal(&a.keys, Kind::Contacts, b"[]");
    assert_eq!(&open(&b.keys, Kind::Contacts, &sealed).unwrap()[..], b"[]");
    assert_eq!(
        names_in(dir.path()),
        [BACKEND_MARKER_NAME, META_KEY_FILE, META_KEY_LOCK]
            .into_iter()
            .map(String::from)
            .collect::<BTreeSet<String>>()
    );
}

#[test]
fn keys_cached_never_calls_the_keystore() {
    let source = TestKeySource::new(8);
    let dir = profile();
    assert!(matches!(
        keys_cached(dir.path()),
        Err(AtRestError::KeyUnavailable(_))
    ));
    assert_eq!(source.calls(), 0);
    let keys = load(dir.path(), &source);
    assert_eq!(source.calls(), 1);
    let probe = index(&keys, ValueType::MessageId, b"m");
    for _ in 0..50 {
        let cached = keys_cached(dir.path()).unwrap();
        assert_eq!(index(&cached, ValueType::MessageId, b"m"), probe);
    }
    // A second load in this process finds the cache: no second keystore call.
    let again = keys_load_from(dir.path(), MigratePolicy::Never, &source, false).unwrap();
    assert_eq!(index(&again, ValueType::MessageId, b"m"), probe);
    assert_eq!(source.calls(), 1);
    // So do readers and writers.
    set_mode(dir.path(), Mode::Sealed).unwrap();
    let path = dir.path().join("route_memory.json");
    store_json(dir.path(), &path, Kind::RouteMemory, &serde_json::json!({})).unwrap();
    load_json::<serde_json::Value>(dir.path(), &path, Kind::RouteMemory).unwrap();
    assert_eq!(source.calls(), 1);
}

/// Debug builds catch a key load under a Raven lock (it may wait on a
/// keychain dialog while every other process waits on the lock).
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "never under a data-dir lock")]
fn keys_load_under_a_data_dir_lock_panics_in_debug() {
    let dir = profile();
    let _held = DataDirLock::acquire(dir.path(), ".contacts.lock.sqlite").unwrap();
    let _ = keys_load_from(
        dir.path(),
        MigratePolicy::Never,
        &TestKeySource::new(9),
        false,
    );
}

#[cfg(debug_assertions)]
#[test]
fn a_held_lock_counts_for_the_thread_that_took_it() {
    let dir = profile();
    assert!(!crate::paths::thread_holds_raven_lock());
    let lock = DataDirLock::acquire(dir.path(), ".contacts.lock.sqlite").unwrap();
    assert!(crate::paths::thread_holds_raven_lock());
    // Dropped on another thread (a lock held across an `.await`): this
    // thread's count still goes back to zero.
    std::thread::spawn(move || {
        assert!(!crate::paths::thread_holds_raven_lock());
        drop(lock);
    })
    .join()
    .unwrap();
    assert!(!crate::paths::thread_holds_raven_lock());
    let source = TestKeySource::new(9);
    assert!(load(dir.path(), &source).current_epoch() >= 1);
}

#[test]
fn stamp_change_reunwraps_without_keystore() {
    let source = TestKeySource::new(10);
    let dir = profile();
    let keys = load(dir.path(), &source);
    assert_eq!(keys.epochs(), [1]);
    let probe = index(&keys, ValueType::Nonce, b"n");
    rotate(dir.path(), &source);
    let fresh = keys_cached(dir.path()).unwrap();
    assert_eq!(fresh.epochs(), [1, 2]);
    assert_eq!(fresh.current_epoch(), 2);
    assert_eq!(index(&fresh, ValueType::Nonce, b"n"), probe);
    assert_eq!(source.calls(), 1);
    // The key file gone (erase or unseal in another process): fail closed.
    std::fs::remove_file(dir.path().join(META_KEY_FILE)).unwrap();
    assert!(matches!(
        keys_cached(dir.path()),
        Err(AtRestError::KeyUnavailable(_))
    ));
    assert_eq!(source.calls(), 1);
}

#[test]
fn unknown_epoch_is_stale_then_refresh_succeeds() {
    let source = TestKeySource::new(11);
    let (dir, old) = sealed_profile(&source);
    rotate(dir.path(), &source);
    // The rotating process seals under epoch 2.
    let rotated = unwrap_key_file(
        &source.hist(),
        dir.path(),
        &std::fs::read(dir.path().join(META_KEY_FILE)).unwrap(),
    )
    .unwrap();
    let sealed = seal(&rotated, Kind::LanSeen, b"{}");
    let row = seal_row(&rotated, "t", b"k", b"v");
    assert!(matches!(
        open(&old, Kind::LanSeen, &sealed),
        Err(AtRestError::StaleKeys { epoch: 2 })
    ));
    assert!(matches!(
        open_row(&old, "t", b"k", &row),
        Err(AtRestError::StaleKeys { epoch: 2 })
    ));
    let refreshed = keys_cached(dir.path()).unwrap();
    assert_eq!(
        &open(&refreshed, Kind::LanSeen, &sealed).unwrap()[..],
        b"{}"
    );
    assert_eq!(&open_row(&refreshed, "t", b"k", &row).unwrap()[..], b"v");
    // The old epoch stays readable (the rotation grace).
    let before = seal(&old, Kind::LanSeen, b"[]");
    assert_eq!(
        &open(&refreshed, Kind::LanSeen, &before).unwrap()[..],
        b"[]"
    );
    // An epoch nobody has stays stale after the refresh: the caller's top
    // level then treats it as tampering.
    let mut forged = sealed.clone();
    forged[6..10].copy_from_slice(&7u32.to_be_bytes());
    assert!(matches!(
        open(&keys_cached(dir.path()).unwrap(), Kind::LanSeen, &forged),
        Err(AtRestError::StaleKeys { epoch: 7 })
    ));
    assert_eq!(source.calls(), 1);
}

/// Review R02: a debug build without `RAVEN_LAB_AT_REST=1` (a debug binary
/// pointed at a real profile by mistake) seals nothing, creates no key file
/// and adds no keystore access.
#[test]
fn debug_auto_policy_without_lab_switch_never_seals() {
    if !cfg!(debug_assertions) {
        assert!(MigratePolicy::Auto.allows_sealing());
        return;
    }
    if crate::p2p_gate::lab_switch(LAB_AT_REST).is_some() {
        eprintln!("skipped: RAVEN_LAB_AT_REST is set in this environment");
        return;
    }
    assert!(!MigratePolicy::Auto.allows_sealing());
    assert!(!MigratePolicy::Never.allows_sealing());
    assert!(MigratePolicy::Allow.allows_sealing());
    let dir = profile();
    let source = TestKeySource::new(12);
    for policy in [MigratePolicy::Auto, MigratePolicy::Never] {
        assert!(matches!(
            keys_load_from(dir.path(), policy, &source, false),
            Err(AtRestError::NotSealedMode)
        ));
    }
    assert_eq!(source.calls(), 0);
    assert_eq!(
        names_in(dir.path()),
        BTreeSet::from([BACKEND_MARKER_NAME.to_owned()])
    );
    // Writers keep today's bytes, and nothing seals in place.
    let path = dir.path().join("lan_seen.json");
    store_json(
        dir.path(),
        &path,
        Kind::LanSeen,
        &serde_json::json!({"a": 1}),
    )
    .unwrap();
    assert!(!is_sealed(&std::fs::read(&path).unwrap()));
    assert!(matches!(
        migrate_file(dir.path(), &path, Kind::LanSeen),
        Err(AtRestError::NotSealedMode)
    ));
    assert!(!dir.path().join(META_KEY_FILE).exists());
    assert!(!dir.path().join(PRIVACY_FILE).exists());
}

#[test]
fn unsealed_by_user_never_creates_a_key() {
    let dir = profile();
    set_mode(dir.path(), Mode::UnsealedByUser).unwrap();
    let source = TestKeySource::new(12);
    assert!(matches!(
        keys_load_from(dir.path(), MigratePolicy::Allow, &source, false),
        Err(AtRestError::NotSealedMode)
    ));
    assert_eq!(source.calls(), 0);
    assert!(!dir.path().join(META_KEY_FILE).exists());
}

#[test]
fn migrate_races_a_writer_without_losing_its_update() {
    let source = TestKeySource::new(13);
    let (dir, keys) = sealed_profile(&source);
    let path = dir.path().join("learned_routes.json");
    std::fs::write(&path, br#"{"v":"old"}"#).unwrap();
    let started = Barrier::new(2);
    let migrated = std::thread::scope(|s| {
        // A writer that read the file just before sealing began (an older
        // build, or one that read the mode first) holds the file's own lock.
        let writer = s.spawn(|| {
            let _lock = DataDirLock::acquire(dir.path(), ".learned_routes.lock.sqlite").unwrap();
            let read = std::fs::read(&path).unwrap();
            started.wait();
            std::thread::sleep(Duration::from_millis(300));
            assert_eq!(read, br#"{"v":"old"}"#);
            crate::paths::atomic_write_private(&path, br#"{"v":"new"}"#).unwrap();
        });
        started.wait();
        let migrated = migrate_file(dir.path(), &path, Kind::LearnedRoutes).unwrap();
        writer.join().unwrap();
        migrated
    });
    assert_eq!(migrated, Migrated::Sealed);
    let bytes = std::fs::read(&path).unwrap();
    assert!(is_sealed(&bytes));
    assert_eq!(
        &open(&keys, Kind::LearnedRoutes, &bytes).unwrap()[..],
        br#"{"v":"new"}"#
    );
}

#[test]
fn verify_after_seal_refuses_a_bad_seal() {
    let (dir, _keys) = sealed_profile(&TestKeySource::new(14));
    let path = dir.path().join("route_memory.json");
    std::fs::write(&path, br#"{"plain":true}"#).unwrap();
    SEAL_FAULT.with(|armed| armed.set(true));
    assert!(matches!(
        migrate_file(dir.path(), &path, Kind::RouteMemory),
        Err(AtRestError::Tampered { kind: 13 })
    ));
    // The plain file is untouched and no temp file is left.
    assert_eq!(std::fs::read(&path).unwrap(), br#"{"plain":true}"#);
    assert!(names_in(dir.path())
        .iter()
        .all(|name| !name.contains(".tmp.")));
    assert_eq!(
        migrate_file(dir.path(), &path, Kind::RouteMemory).unwrap(),
        Migrated::Sealed
    );
    assert_eq!(
        migrate_file(dir.path(), &path, Kind::RouteMemory).unwrap(),
        Migrated::AlreadySealed
    );
    assert_eq!(
        migrate_file(
            dir.path(),
            &dir.path().join("relay_memory.json"),
            Kind::RelayMemory
        )
        .unwrap(),
        Migrated::Missing
    );
}

#[test]
fn migrate_then_unseal_round_trip() {
    let (dir, keys) = sealed_profile(&TestKeySource::new(15));
    std::fs::create_dir_all(dir.path().join("contact_inbox")).unwrap();
    let files: [(&str, Kind, &[u8]); 4] = [
        (
            "contacts.json",
            Kind::Contacts,
            b"[\n  {\n    \"petname\": \"Sam\"\n  }\n]",
        ),
        (
            "contact_inbox/00ff.wire",
            Kind::ContactInbox,
            b"\x00\x01wire\xff",
        ),
        ("device_x25519.secret", Kind::DeviceXSecret, &[9u8; 32]),
        ("node_policy_peers.rms", Kind::NodePolicyPeers, b"{}"),
    ];
    for (name, kind, plain) in files {
        let path = dir.path().join(name);
        std::fs::write(&path, plain).unwrap();
        assert_eq!(
            migrate_file(dir.path(), &path, kind).unwrap(),
            Migrated::Sealed
        );
        let sealed = std::fs::read(&path).unwrap();
        assert!(is_sealed(&sealed), "{name}");
        assert_eq!(&open(&keys, kind, &sealed).unwrap()[..], plain, "{name}");
        assert_eq!(
            &load_bytes(dir.path(), &path, kind).unwrap().unwrap()[..],
            plain
        );
    }
    set_mode(dir.path(), Mode::UnsealedByUser).unwrap();
    for (name, kind, plain) in files {
        let path = dir.path().join(name);
        unseal_file(dir.path(), &path, kind).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), plain, "{name}");
        unseal_file(dir.path(), &path, kind).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), plain, "{name}");
        assert!(matches!(
            migrate_file(dir.path(), &path, kind),
            Err(AtRestError::NotSealedMode)
        ));
    }
    unseal_file(dir.path(), &dir.path().join("lan_seen.json"), Kind::LanSeen).unwrap();
    assert!(!dir.path().join("lan_seen.json").exists());
}

#[test]
fn identity_recorded_never_touches_the_keystore() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!identity_recorded(dir.path()).unwrap());
    // Nothing was created: no identity lock, no keystore marker.
    assert!(names_in(dir.path()).is_empty());
    // The marker alone (no seed anywhere: a keystore read could not succeed).
    std::fs::write(dir.path().join(BACKEND_MARKER_NAME), b"macos-keychain\n").unwrap();
    assert!(identity_recorded(dir.path()).unwrap());
    assert_eq!(
        names_in(dir.path()),
        BTreeSet::from([BACKEND_MARKER_NAME.to_owned()])
    );
    // The binding alone.
    let binding = tempfile::tempdir().unwrap();
    std::fs::write(binding.path().join(IDENTITY_BINDING_NAME), [0u8; 4]).unwrap();
    assert!(identity_recorded(binding.path()).unwrap());
    // A marker that is not canonical is an error, never "no identity".
    std::fs::write(dir.path().join(BACKEND_MARKER_NAME), b"macos-keychain").unwrap();
    assert!(identity_recorded(dir.path()).is_err());
}

#[test]
fn key_survives_restart() {
    let source = TestKeySource::new(16);
    let dir = profile();
    let first = load(dir.path(), &source);
    let sealed = seal(&first, Kind::Contacts, b"[]");
    let probe = index(&first, ValueType::Rvn1Address, b"rvn1qexample");
    let lock = lock_name(&first, &[1; 32]);
    drop(first);
    forget_cached_keys(dir.path());
    let second = keys_load_from(dir.path(), MigratePolicy::Never, &source, false).unwrap();
    assert_eq!(
        index(&second, ValueType::Rvn1Address, b"rvn1qexample"),
        probe
    );
    assert_eq!(lock_name(&second, &[1; 32]), lock);
    assert_eq!(&open(&second, Kind::Contacts, &sealed).unwrap()[..], b"[]");
    // One keystore read per process start; K_hist minted only on creation.
    assert_eq!(source.calls(), 2);
    assert_eq!(source.creates(), 1);
    assert_eq!(key_files_created(dir.path()), 1);
}

#[test]
fn no_identity_no_key_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let source = TestKeySource::new(17);
    expect_key_file(dir.path());
    assert!(matches!(
        keys_load_from(dir.path(), MigratePolicy::Allow, &source, false),
        Err(AtRestError::NoIdentity)
    ));
    assert_eq!(source.calls(), 0, "K_hist is never minted for it");
    assert!(
        names_in(dir.path()).is_empty(),
        "the fresh profile stays empty"
    );
    assert!(crate::identity_store::first_install_allowed(dir.path()));
    // Identity creation still works afterwards (lab backend, or DPAPI; the
    // macOS keychain is never used by this test).
    crate::identity_store::test_enable_locked_file_identity_backend();
    let lab = std::env::var("RAVEN_IDENTITY_BACKEND").is_ok_and(|v| v == "locked-file");
    if lab || cfg!(windows) {
        crate::identity_store::load_or_create_identity(dir.path()).unwrap();
        assert!(identity_recorded(dir.path()).unwrap());
        keys_load_from(dir.path(), MigratePolicy::Allow, &source, false).unwrap();
        assert!(dir.path().join(META_KEY_FILE).exists());
    }
}

#[test]
fn key_fault_switch_gives_key_unavailable() {
    assert!(key_fault_value(Some("unavailable")));
    for value in [
        None,
        Some(""),
        Some("1"),
        Some("Unavailable"),
        Some("unavailable "),
    ] {
        assert!(!key_fault_value(value), "{value:?}");
    }
    let source = TestKeySource::new(18);
    let dir = profile();
    assert!(matches!(
        keys_load_from(dir.path(), MigratePolicy::Allow, &source, true),
        Err(AtRestError::KeyUnavailable(_))
    ));
    assert_eq!(source.calls(), 0);
    assert!(!dir.path().join(META_KEY_FILE).exists());
    // Keys already loaded: the faulted load still fails (the node's
    // fail-closed state), and clearing it recovers.
    load(dir.path(), &source);
    assert!(matches!(
        keys_load_from(dir.path(), MigratePolicy::Allow, &source, true),
        Err(AtRestError::KeyUnavailable(_))
    ));
    assert!(keys_load_from(dir.path(), MigratePolicy::Allow, &source, false).is_ok());
}

/// The release half (CI's release step sets the switch): a release build
/// never reads `RAVEN_LAB_AT_REST_KEY_FAULT`.
#[test]
fn key_fault_switch_is_inert_without_debug_assertions() {
    if cfg!(debug_assertions) {
        let set = std::env::var(LAB_AT_REST_KEY_FAULT).ok();
        assert_eq!(key_fault_requested(), set.as_deref() == Some("unavailable"));
        return;
    }
    // Edition 2021: a plain call. Only release-run tests set it.
    std::env::set_var(LAB_AT_REST_KEY_FAULT, "unavailable");
    assert!(!key_fault_requested());
}

#[test]
fn index_is_equal_across_tables_and_differs_across_types() {
    let (_dir, keys) = sealed_profile(&TestKeySource::new(19));
    let device = [7u8; 32];
    // No table goes into the digest, so the same device key gives the same
    // digest in every table (keys, constraints and joins keep their shape).
    let digest = index(&keys, ValueType::DeviceKey, &device);
    assert_eq!(index(&keys, ValueType::DeviceKey, &device), digest);
    for other in [
        ValueType::Rvn1Address,
        ValueType::MessageId,
        ValueType::ObjectDigest,
        ValueType::Nonce,
        ValueType::ObjectBytes,
    ] {
        assert_ne!(index(&keys, other, &device), digest, "{other:?}");
    }
    assert_ne!(index(&keys, ValueType::DeviceKey, &[8u8; 32]), digest);
    let (_other_dir, other) = sealed_profile(&TestKeySource::new(19));
    assert_ne!(index(&other, ValueType::DeviceKey, &device), digest);
    assert_eq!(
        [
            ValueType::DeviceKey,
            ValueType::Rvn1Address,
            ValueType::MessageId,
            ValueType::ObjectDigest,
            ValueType::Nonce,
            ValueType::ObjectBytes,
        ]
        .map(ValueType::label),
        [
            "device-key",
            "rvn1-address",
            "message-id",
            "object-digest",
            "nonce",
            "object-bytes"
        ]
    );
}

#[test]
fn lock_name_never_contains_the_peer_hex() {
    let (_dir, keys) = sealed_profile(&TestKeySource::new(20));
    let mut names = BTreeSet::new();
    for n in 0..64u8 {
        let mut peer = [n; 32];
        peer[0] = n.wrapping_mul(31);
        let name = lock_name(&keys, &peer);
        let digest = name
            .strip_prefix(".send_")
            .and_then(|rest| rest.strip_suffix(".lock.sqlite"))
            .unwrap();
        assert_eq!(digest.len(), 32);
        assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!name.contains(&hex::encode(peer)));
        assert!(!name.contains(&hex::encode(&peer[..8])));
        // The registry knows it as a send lock (an empty lock file).
        assert_eq!(
            rule_for(&name).map(|rule| rule.name),
            Some(".send_*.lock.sqlite")
        );
        names.insert(name);
    }
    assert_eq!(names.len(), 64);
    let (_other_dir, other) = sealed_profile(&TestKeySource::new(20));
    assert_ne!(lock_name(&other, &[1; 32]), lock_name(&keys, &[1; 32]));
}

#[test]
fn lock_name_is_unchanged_by_an_epoch_rotation() {
    let source = TestKeySource::new(21);
    let dir = profile();
    let before = load(dir.path(), &source);
    let peer = [0x42; 32];
    rotate(dir.path(), &source);
    let after = keys_cached(dir.path()).unwrap();
    assert_eq!(after.current_epoch(), 2);
    assert_eq!(lock_name(&after, &peer), lock_name(&before, &peer));
    assert_eq!(
        index(&after, ValueType::DeviceKey, &peer),
        index(&before, ValueType::DeviceKey, &peer)
    );
    // The data keys did change: new seals name epoch 2.
    let sealed = seal(&after, Kind::Contacts, b"[]");
    assert_eq!(sealed[6..10], 2u32.to_be_bytes());
    assert!(matches!(
        open(&before, Kind::Contacts, &sealed),
        Err(AtRestError::StaleKeys { epoch: 2 })
    ));
}

#[test]
fn forget_cached_keys_zeroizes() {
    let source = TestKeySource::new(22);
    let dir = profile();
    let keys = load(dir.path(), &source);
    let weak = Arc::downgrade(&keys);
    drop(keys);
    assert!(weak.upgrade().is_some(), "the cache holds the keys");
    // Forgotten under another spelling of the same folder.
    forget_cached_keys(&dir.path().join("."));
    assert!(
        weak.upgrade().is_none(),
        "dropped: K_hist and the payload are Zeroizing and wiped on drop"
    );
    assert!(matches!(
        keys_cached(dir.path()),
        Err(AtRestError::KeyUnavailable(_))
    ));
    // A holder keeps its own copy until it drops it.
    let held = keys_load_from(dir.path(), MigratePolicy::Never, &source, false).unwrap();
    forget_cached_keys(dir.path());
    assert_eq!(
        &open(&held, Kind::Contacts, &seal(&held, Kind::Contacts, b"[]")).unwrap()[..],
        b"[]"
    );
    assert!(keys_cached(dir.path()).is_err());
    assert_eq!(source.calls(), 2);
}

/// An unreadable key file is an error, never replaced: here a key file
/// copied into another profile (its wrap is bound to the folder it was made
/// in), and a profile whose keystore lost K_hist (never minted again).
#[test]
fn unreadable_key_file_is_never_replaced() {
    let source = TestKeySource::new(23);
    let dir = profile();
    load(dir.path(), &source);
    let file = std::fs::read(dir.path().join(META_KEY_FILE)).unwrap();
    let moved = profile();
    std::fs::write(moved.path().join(META_KEY_FILE), &file).unwrap();
    expect_key_file(moved.path());
    assert!(matches!(
        keys_load_from(moved.path(), MigratePolicy::Allow, &source, false),
        Err(AtRestError::Tampered {
            kind: NOT_A_FILE_KIND
        })
    ));
    assert_eq!(
        std::fs::read(moved.path().join(META_KEY_FILE)).unwrap(),
        file
    );

    forget_cached_keys(dir.path());
    let lost = TestKeySource {
        missing: true,
        ..TestKeySource::new(23)
    };
    assert!(matches!(
        keys_load_from(dir.path(), MigratePolicy::Allow, &lost, false),
        Err(AtRestError::KeyLost(_))
    ));
    assert_eq!(lost.creates(), 0);
    assert_eq!(std::fs::read(dir.path().join(META_KEY_FILE)).unwrap(), file);
    assert_eq!(key_files_created(moved.path()), 0);
}

/// The production path (in this test build: the derived lab key on macOS and
/// Linux, K_hist from its DPAPI-wrapped file on Windows) writes exactly what
/// `DomainProtector(raven/meta-key/v1)` would.
#[test]
fn the_key_file_is_a_domain_protector_blob() {
    let dir = profile();
    expect_key_file(dir.path());
    let keys = keys_load_with(dir.path(), MigratePolicy::Allow).unwrap();
    let file = std::fs::read(dir.path().join(META_KEY_FILE)).unwrap();
    assert_eq!(&file[..5], b"RMK1\x01");
    let json = DomainProtector::new(META_KEY_DOMAIN)
        .unprotect(dir.path(), &file[5..])
        .unwrap();
    let payload = KeyPayload::parse(&json).unwrap();
    assert_eq!(payload.current, keys.current_epoch());
    assert_eq!(MetaKeys::from_payload(payload).index[..], keys.index[..]);
    forget_cached_keys(dir.path());
}

/// Acceptance: today's writers never create `meta_key.rmk` or
/// `privacy.json` (and the creation check above fails any test that does).
#[test]
fn existing_writers_never_create_the_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let mut list = crate::chat_history::BlockList::default();
    list.block(&"ef".repeat(32));
    list.save(dir.path()).unwrap();
    crate::device_cert::save_device_registry(
        dir.path(),
        &crate::device_cert::DeviceRegistry::default(),
    )
    .unwrap();
    crate::bootstrap::save_bootstrap(dir.path(), &crate::bootstrap::BootstrapConfig::default())
        .unwrap();
    crate::node_policy::save_policy(dir.path(), &crate::node_policy::NodePolicy::default())
        .unwrap();
    crate::chat_history::ChatHistory::append_persisted(
        dir.path(),
        crate::chat_history::ChatHistoryEntry {
            message_id_hex: "00".repeat(16),
            direction: "in".into(),
            peer_petname: "Sam".into(),
            peer_tag: String::new(),
            peer_pub_hex: "ab".repeat(32),
            created_at_ms: 1,
            delivery: "delivered".into(),
            preview: "hello".into(),
            body: "hello".into(),
            stored_at_ms: None,
        },
    )
    .unwrap();
    for name in [META_KEY_FILE, PRIVACY_FILE, META_KEY_LOCK] {
        assert!(!dir.path().join(name).exists(), "{name}");
    }
    assert_eq!(crate::privacy::mode(dir.path()), Mode::Plain);
    assert_eq!(key_files_created(dir.path()), 0);
}

// ── PP.10: epoch bodies and the key file's epochs ──

#[test]
fn epoch_bodies_round_trip_and_fail_typed() {
    let source = TestKeySource::new(30);
    let (_dir, keys) = sealed_profile(&source);
    let body = seal_epoch(
        &keys,
        DataUse::History,
        b"rvn1/history/v2",
        b"{\"entries\":[]}",
    );
    assert_eq!(body.len(), EPOCH_BODY_OVERHEAD + 14);
    assert_eq!(epoch_of(&body), Some(1));
    assert_eq!(
        &open_epoch(&keys, DataUse::History, b"rvn1/history/v2", &body).unwrap()[..],
        b"{\"entries\":[]}"
    );
    // Another use's key, another domain, a flipped byte: a changed byte.
    for (use_, domain) in [
        (DataUse::Stage, &b"rvn1/history/v2"[..]),
        (DataUse::History, &b"rvn1/outbound-stage/v2"[..]),
    ] {
        assert!(matches!(
            open_epoch(&keys, use_, domain, &body),
            Err(AtRestError::Tampered { .. })
        ));
    }
    let mut flipped = body.clone();
    *flipped.last_mut().unwrap() ^= 1;
    assert!(matches!(
        open_epoch(&keys, DataUse::History, b"rvn1/history/v2", &flipped),
        Err(AtRestError::Tampered { .. })
    ));
    assert!(matches!(
        open_epoch(
            &keys,
            DataUse::History,
            b"rvn1/history/v2",
            &body[..EPOCH_BODY_OVERHEAD - 1]
        ),
        Err(AtRestError::Truncated)
    ));
    let mut forged = body.clone();
    forged[..4].copy_from_slice(&9u32.to_be_bytes());
    assert!(matches!(
        open_epoch(&keys, DataUse::History, b"rvn1/history/v2", &forged),
        Err(AtRestError::StaleKeys { epoch: 9 })
    ));
}

/// Step 1 adds epoch 2 beside epoch 1, the last step keeps only the current
/// one; `k_index` (lookups, lock names) never changes and no keystore call
/// is made. A stale `from` changes nothing.
#[test]
fn add_and_drop_epochs_keep_k_index_without_the_keystore() {
    let source = TestKeySource::new(31);
    let (dir, before) = sealed_profile(&source);
    let dd = dir.path();
    let probe = index(&before, ValueType::MessageId, b"m");
    let lock = lock_name(&before, &[7; 32]);
    let old_body = seal_epoch(&before, DataUse::AppRow, b"raven/app-inbox/v1", b"row");
    let old_file = seal(&before, Kind::LanSeen, b"[]");

    let during = add_epoch(dd, 1).unwrap();
    assert_eq!((during.epochs(), during.current_epoch()), (vec![1, 2], 2));
    assert_eq!(keys_cached(dd).unwrap().epochs(), [1, 2]);
    // Again (a racing pass), or from an epoch that is not current: no change.
    let stamp = std::fs::read(dd.join(META_KEY_FILE)).unwrap();
    assert_eq!(add_epoch(dd, 1).unwrap().epochs(), [1, 2]);
    assert_eq!(
        add_epoch(dd, 2).unwrap().epochs(),
        [1, 2],
        "one rotation at a time"
    );
    assert_eq!(std::fs::read(dd.join(META_KEY_FILE)).unwrap(), stamp);
    // Both epochs open during the grace; new seals name epoch 2.
    assert_eq!(
        &open_epoch(&during, DataUse::AppRow, b"raven/app-inbox/v1", &old_body).unwrap()[..],
        b"row"
    );
    assert_eq!(&open(&during, Kind::LanSeen, &old_file).unwrap()[..], b"[]");
    assert_eq!(
        sealed_file_epoch(&seal(&during, Kind::LanSeen, b"[]")),
        Some(2)
    );

    let after = drop_old_epochs(dd).unwrap();
    assert_eq!((after.epochs(), after.current_epoch()), (vec![2], 2));
    assert_eq!(drop_old_epochs(dd).unwrap().epochs(), [2]);
    assert!(matches!(
        open_epoch(&after, DataUse::AppRow, b"raven/app-inbox/v1", &old_body),
        Err(AtRestError::StaleKeys { epoch: 1 })
    ));
    assert!(matches!(
        open(&after, Kind::LanSeen, &old_file),
        Err(AtRestError::StaleKeys { epoch: 1 })
    ));
    assert_eq!(index(&after, ValueType::MessageId, b"m"), probe);
    assert_eq!(lock_name(&after, &[7; 32]), lock);
    assert_eq!(source.calls(), 1, "a rotation never calls the keystore");
    // The next rotation counts on.
    assert_eq!(add_epoch(dd, 2).unwrap().epochs(), [2, 3]);
}

/// A rewrite needs this process's K_hist and the file: none is created.
#[test]
fn rotation_without_loaded_keys_or_a_key_file_fails_closed() {
    let dir = profile();
    assert!(matches!(
        add_epoch(dir.path(), 1),
        Err(AtRestError::KeyUnavailable(_))
    ));
    assert!(!dir.path().join(META_KEY_FILE).exists());
    let source = TestKeySource::new(32);
    let (dir, _) = sealed_profile(&source);
    std::fs::remove_file(dir.path().join(META_KEY_FILE)).unwrap();
    assert!(matches!(
        drop_old_epochs(dir.path()),
        Err(AtRestError::KeyUnavailable(_))
    ));
    assert!(!dir.path().join(META_KEY_FILE).exists());
}

/// `reseal_file` moves an old epoch's file to the current one under its
/// writer lock and leaves plain, missing and current files alone.
#[test]
fn reseal_file_moves_only_old_epoch_files() {
    let source = TestKeySource::new(33);
    let (dir, keys) = sealed_profile(&source);
    let dd = dir.path();
    let path = dd.join("lan_seen.json");
    assert_eq!(
        reseal_file(dd, &path, Kind::LanSeen).unwrap(),
        Resealed::Missing
    );
    std::fs::write(&path, b"[]").unwrap();
    assert_eq!(
        reseal_file(dd, &path, Kind::LanSeen).unwrap(),
        Resealed::Plain
    );
    crate::paths::atomic_write_private(&path, &seal(&keys, Kind::LanSeen, b"[1]")).unwrap();
    assert_eq!(
        reseal_file(dd, &path, Kind::LanSeen).unwrap(),
        Resealed::Current
    );
    add_epoch(dd, 1).unwrap();
    assert_eq!(
        reseal_file(dd, &path, Kind::LanSeen).unwrap(),
        Resealed::Resealed
    );
    let raw = std::fs::read(&path).unwrap();
    assert_eq!(sealed_file_epoch(&raw), Some(2));
    assert_eq!(
        &open(&keys_cached(dd).unwrap(), Kind::LanSeen, &raw).unwrap()[..],
        b"[1]"
    );
    assert_eq!(
        reseal_file(dd, &path, Kind::LanSeen).unwrap(),
        Resealed::Current
    );
}

/// Review A-keys-format-4: with the key file there, a keystore that has no
/// K_hist (or a corrupt one) is `KeyLost`, not the transient
/// `KeyUnavailable` of a keystore that did not answer or was denied; both
/// stay "not now" for the readers (`is_unavailable`: nothing is set aside).
/// This process remembers a loss, for status and the texts, until a load
/// works again.
#[test]
fn a_k_hist_gone_beside_its_key_file_is_lost_not_unavailable() {
    for (error, lost) in [
        (ChatHistoryError::MissingProtectedKey, true),
        (ChatHistoryError::CorruptProtectedKey, true),
        (
            ChatHistoryError::ProtectedStoreUnavailable("keychain read failed: denied".into()),
            false,
        ),
        (
            ChatHistoryError::Io("chat_history_key.dpapi: busy".into()),
            false,
        ),
    ] {
        let text = error.to_string();
        let mapped = hist_key_error(error, true);
        assert_eq!(matches!(mapped, AtRestError::KeyLost(_)), lost, "{text}");
        assert!(mapped.is_unavailable(), "{text}");
    }
    // While the key file is created, a corrupt K_hist is no lost key file.
    assert!(matches!(
        hist_key_error(ChatHistoryError::CorruptProtectedKey, false),
        AtRestError::KeyUnavailable(_)
    ));

    let source = TestKeySource::new(31);
    let dir = profile();
    load(dir.path(), &source);
    assert!(!key_lost(dir.path()));
    forget_cached_keys(dir.path());
    let lost = TestKeySource {
        missing: true,
        ..TestKeySource::new(31)
    };
    assert!(matches!(
        keys_load_from(dir.path(), MigratePolicy::Never, &lost, false),
        Err(AtRestError::KeyLost(_))
    ));
    assert!(key_lost(dir.path()));
    assert!(key_lost(&dir.path().join(".")), "by the canonical folder");
    assert!(keys_cached(dir.path()).is_err());
    // A keystore that did not answer this time (denied): no loss known.
    struct Denied;
    impl HistKeySource for Denied {
        fn load(&self, _data_dir: &Path, _create: bool) -> Result<HistKey, AtRestError> {
            let denied = ChatHistoryError::ProtectedStoreUnavailable("denied".into());
            Err(hist_key_error(denied, true))
        }
    }
    assert!(matches!(
        keys_load_from(dir.path(), MigratePolicy::Never, &Denied, false),
        Err(AtRestError::KeyUnavailable(_))
    ));
    assert!(!key_lost(dir.path()));
    keys_load_from(dir.path(), MigratePolicy::Never, &lost, false).unwrap_err();
    assert!(key_lost(dir.path()));
    // The key is back: the next load works and the loss is forgotten.
    keys_load_from(dir.path(), MigratePolicy::Never, &source, false).unwrap();
    assert!(!key_lost(dir.path()));
    // A new process knows nothing yet.
    forget_cached_keys(dir.path());
    keys_load_from(dir.path(), MigratePolicy::Never, &lost, false).unwrap_err();
    assert!(key_lost(dir.path()));
    forget_cached_keys(dir.path());
    assert!(!key_lost(dir.path()));
}
