//! Session renewal's per-contact state (Phase 3 item 4, the store's
//! `renewal` module) in both layouts: the round trip, the shared re-pair
//! budget (window, cap, 60 s cooldown) counted durably before any PairInit,
//! the kept PairInit and its size limit, the prune, older stores without the
//! table, older builds opening a store with it, a clear table an older build
//! of the pack left in a store it sealed, and `raven privacy rotate-meta`.
//! Phase 6b step P6.27 adds the early re-key (its cap, its columns in an
//! older clear table, its move with the keys) and the reset table's cause 7
//! (widened in place; the ten minutes a re-keyed session still takes).
//! Each test decides the layout itself (the suite's
//! `RAVEN_TEST_SEALED_SESSIONS` switch is off on its thread).

use super::sealed_store::{older_open, profile, seal_profile};
use super::*;
use crate::session_renewal::{code, DAY_MS, REPAIR_COOLDOWN_MS, REPAIR_MAX_PER_DAY};
use crate::sqlite_rebuild as rebuild;

const T: u64 = 1_900_000_000_000;
const HOUR: u64 = 3_600_000;
const PEER: [u8; 32] = [0xB7; 32];

/// A store in a plain or a sealed profile.
fn store_in(sealed_profile: bool) -> (tempfile::TempDir, PathBuf, IndexedSessionStore) {
    let (dir, path) = profile();
    if sealed_profile {
        seal_profile(dir.path());
    }
    let store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
    assert_eq!(store.layout.is_keyed(), sealed_profile);
    (dir, path, store)
}

fn reopen(path: &Path) -> IndexedSessionStore {
    open_test_store(path, Arc::new(MemoryProtectedBackend::default()))
}

fn version(path: &Path) -> i64 {
    rebuild::user_version(&Connection::open(path).unwrap()).unwrap()
}

fn renewal_columns(path: &Path) -> Vec<String> {
    rebuild::columns(&Connection::open(path).unwrap(), "peer_session_renewal").unwrap()
}

#[test]
fn renewal_state_round_trip() {
    for sealed_profile in [false, true] {
        let (_dir, path, mut store) = store_in(sealed_profile);
        assert_eq!(
            store.peer_renewal_state(&PEER).unwrap(),
            PeerRenewalState::default()
        );
        let wire = vec![0x5A; 3000];
        store.note_session_end_seen(&PEER, T + 5 * HOUR).unwrap();
        store.begin_repair_attempt(&PEER, T).unwrap().unwrap();
        store.finish_renewal_attempt(&PEER, false).unwrap();
        store.set_renewal_pending(&PEER, &wire, T + DAY_MS).unwrap();
        // Max-merged: an older end does not move it back.
        store.note_session_end_seen(&PEER, T + 4 * HOUR).unwrap();
        let expected = PeerRenewalState {
            window_start_ms: T,
            attempts_in_window: 1,
            last_attempt_at_ms: Some(T),
            failures: 1,
            last_session_expires_at_ms: Some(T + 5 * HOUR),
            pending_init: Some(wire.clone()),
            pending_expires_at_ms: Some(T + DAY_MS),
            ..PeerRenewalState::default()
        };
        assert_eq!(store.peer_renewal_state(&PEER).unwrap(), expected);
        assert_eq!(
            store.peer_renewal_state(&[0x01; 32]).unwrap(),
            PeerRenewalState::default()
        );
        drop(store);
        let mut store = reopen(&path);
        assert_eq!(store.peer_renewal_state(&PEER).unwrap(), expected);
        store.note_session_end_seen(&PEER, T + 6 * HOUR).unwrap();
        store.finish_renewal_attempt(&PEER, true).unwrap();
        store.clear_renewal_pending(&PEER).unwrap();
        assert_eq!(
            store.peer_renewal_state(&PEER).unwrap(),
            PeerRenewalState {
                failures: 0,
                last_session_expires_at_ms: Some(T + 6 * HOUR),
                pending_init: None,
                pending_expires_at_ms: None,
                ..expected
            }
        );
        // In a sealed profile the device is keyed and nothing is clear.
        let conn = Connection::open(&path).unwrap();
        let stored: Vec<u8> = conn
            .query_row(
                &format!(
                    "SELECT {} FROM peer_session_renewal",
                    if sealed_profile {
                        "kh_peer_device"
                    } else {
                        "peer_device"
                    }
                ),
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored == PEER, !sealed_profile);
        assert_eq!(
            renewal_columns(&path).contains(&"meta".to_owned()),
            sealed_profile
        );
    }
}

/// One budget per contact: rounds at least 60 s apart, at most four in the
/// window, which rolls a day after it started; a refused round counts
/// nothing.
#[test]
fn repair_budget_window_rolls_and_cooldown_holds_60s() {
    for sealed_profile in [false, true] {
        let (_dir, _path, mut store) = store_in(sealed_profile);
        let mut at = T;
        for n in 1..=REPAIR_MAX_PER_DAY {
            store.begin_repair_attempt(&PEER, at).unwrap().unwrap();
            if n < REPAIR_MAX_PER_DAY {
                assert_eq!(
                    store.begin_repair_attempt(&PEER, at + 30_000).unwrap(),
                    Err((at + REPAIR_COOLDOWN_MS, code::REPAIR_COOLDOWN))
                );
            }
            assert_eq!(
                store.peer_renewal_state(&PEER).unwrap().attempts_in_window,
                n
            );
            at += REPAIR_COOLDOWN_MS;
        }
        assert_eq!(
            store.begin_repair_attempt(&PEER, T + 23 * HOUR).unwrap(),
            Err((T + DAY_MS, code::RENEW_DAILY_CAP))
        );
        store
            .begin_repair_attempt(&PEER, T + DAY_MS)
            .unwrap()
            .unwrap();
        let state = store.peer_renewal_state(&PEER).unwrap();
        assert_eq!(
            (
                state.window_start_ms,
                state.attempts_in_window,
                state.last_attempt_at_ms
            ),
            (T + DAY_MS, 1, Some(T + DAY_MS))
        );
        // Another contact has a budget of its own.
        store
            .begin_repair_attempt(&[0x02; 32], T + DAY_MS)
            .unwrap()
            .unwrap();
    }
}

/// The round is on disk before any PairInit exists: a crash right after it
/// (the store dropped, opened again) only over-counts, and its cooldown holds.
#[test]
fn begin_attempt_is_durable_before_the_pairinit() {
    for sealed_profile in [false, true] {
        let (_dir, path, mut store) = store_in(sealed_profile);
        store.begin_repair_attempt(&PEER, T).unwrap().unwrap();
        drop(store);
        let mut store = reopen(&path);
        let state = store.peer_renewal_state(&PEER).unwrap();
        assert_eq!(
            (state.attempts_in_window, state.last_attempt_at_ms),
            (1, Some(T))
        );
        assert_eq!(
            store.begin_repair_attempt(&PEER, T + 1).unwrap(),
            Err((T + REPAIR_COOLDOWN_MS, code::REPAIR_COOLDOWN))
        );
    }
}

#[test]
fn pending_init_set_clear_and_size_check() {
    for sealed_profile in [false, true] {
        let (_dir, _path, mut store) = store_in(sealed_profile);
        // Clearing what is not there writes nothing.
        store.clear_renewal_pending(&PEER).unwrap();
        assert_eq!(
            store.peer_renewal_state(&PEER).unwrap(),
            PeerRenewalState::default()
        );
        let largest = vec![0x11; RENEWAL_PENDING_MAX_BYTES];
        store
            .set_renewal_pending(&PEER, &largest, T + DAY_MS)
            .unwrap();
        for refused in [vec![], vec![0x22; RENEWAL_PENDING_MAX_BYTES + 1]] {
            assert!(matches!(
                store.set_renewal_pending(&PEER, &refused, T + DAY_MS),
                Err(IndexedSessionStoreError::InvalidBinding)
            ));
        }
        let state = store.peer_renewal_state(&PEER).unwrap();
        assert_eq!(state.pending_init.as_deref(), Some(largest.as_slice()));
        assert_eq!(state.pending_expires_at_ms, Some(T + DAY_MS));
        // A newer one replaces it; clearing keeps the rest of the row.
        store.begin_repair_attempt(&PEER, T).unwrap().unwrap();
        store
            .set_renewal_pending(&PEER, &[0x33; 40], T + 2 * DAY_MS)
            .unwrap();
        store.clear_renewal_pending(&PEER).unwrap();
        let state = store.peer_renewal_state(&PEER).unwrap();
        assert_eq!(
            (state.pending_init, state.pending_expires_at_ms),
            (None, None)
        );
        assert_eq!(state.attempts_in_window, 1);
    }
}

/// The prune keeps a row while its kept PairInit is unexpired, the pair's
/// last session ended less than 14 days ago, or its last round is less than
/// a day old; then it goes.
#[test]
fn prune_keeps_rows_with_a_pending_init() {
    for sealed_profile in [false, true] {
        let (_dir, _path, mut store) = store_in(sealed_profile);
        let (ended, pending, recent) = ([0x0A; 32], [0x0B; 32], [0x0C; 32]);
        for peer in [ended, pending] {
            store.note_session_end_seen(&peer, T).unwrap();
            store.begin_repair_attempt(&peer, T).unwrap().unwrap();
        }
        let later = T + 15 * DAY_MS;
        store
            .set_renewal_pending(&pending, &[0x44; 64], later + HOUR)
            .unwrap();
        store
            .note_session_end_seen(&recent, T + 10 * DAY_MS)
            .unwrap();
        assert_eq!(store.prune_renewal_state(T + DAY_MS).unwrap(), 0);
        assert_eq!(store.prune_renewal_state(later).unwrap(), 1);
        assert_eq!(
            store.peer_renewal_state(&ended).unwrap(),
            PeerRenewalState::default()
        );
        assert!(store
            .peer_renewal_state(&pending)
            .unwrap()
            .pending_init
            .is_some());
        assert_eq!(
            store
                .peer_renewal_state(&recent)
                .unwrap()
                .last_session_expires_at_ms,
            Some(T + 10 * DAY_MS)
        );
        assert_eq!(store.prune_renewal_state(later + 2 * HOUR).unwrap(), 1);
        assert_eq!(
            store.peer_renewal_state(&pending).unwrap(),
            PeerRenewalState::default()
        );
        assert_eq!(store.prune_renewal_state(T + 25 * DAY_MS).unwrap(), 1);
    }
}

/// A store an older build made (no renewal table) opens: the table is added
/// in the profile's shape and the version stays (1 plain, 4 sealed). A
/// clear table an older build of the pack left behind when it sealed the
/// store moves into the keyed shape with its rows.
#[test]
fn an_old_store_without_the_table_opens_and_keeps_its_version() {
    for sealed_profile in [false, true] {
        let (_dir, path, store) = store_in(sealed_profile);
        store
            .conn
            .execute_batch("DROP TABLE peer_session_renewal;")
            .unwrap();
        drop(store);
        let expected_version = if sealed_profile {
            METADATA_SCHEMA_VERSION
        } else {
            sealed::CLEAR_VERSION
        };
        assert_eq!(version(&path), expected_version);
        let mut store = reopen(&path);
        assert_eq!(version(&path), expected_version);
        let columns = renewal_columns(&path);
        assert!(columns.contains(&"kh_peer_device".to_owned()) == sealed_profile);
        assert!(columns.contains(&"peer_device".to_owned()) != sealed_profile);
        store.begin_repair_attempt(&PEER, T).unwrap().unwrap();
    }
    let (_dir, path, store) = store_in(true);
    store
        .conn
        .execute_batch(&format!(
            "DROP TABLE peer_session_renewal; {}
             INSERT INTO peer_session_renewal (rowid, peer_device, window_start_ms,
               attempts_in_window, last_attempt_at_ms, failures)
             VALUES (7, X'{}', {T}, 2, {T}, 1);",
            sealed::create_if_missing("peer_session_renewal", sealed::renewal_columns(false)),
            hex::encode(PEER),
        ))
        .unwrap();
    drop(store);
    let store = reopen(&path);
    assert!(renewal_columns(&path).contains(&"kh_peer_device".to_owned()));
    let rowid: i64 = store
        .conn
        .query_row("SELECT rowid FROM peer_session_renewal", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(rowid, 7);
    let state = store.peer_renewal_state(&PEER).unwrap();
    assert_eq!(
        (
            state.attempts_in_window,
            state.failures,
            state.last_attempt_at_ms
        ),
        (2, 1, Some(T))
    );
    assert_eq!(version(&path), METADATA_SCHEMA_VERSION);
}

/// A build before Phase 3 item 4 opens a plain profile's store that has the
/// table: its version check and its batch pass, the version stays 1, and the
/// rows are still there for this build afterwards.
#[test]
fn an_older_binary_opening_the_new_store_ignores_the_table() {
    let (_dir, path, mut store) = store_in(false);
    store.begin_repair_attempt(&PEER, T).unwrap().unwrap();
    drop(store);
    older_open(&path).unwrap();
    assert_eq!(version(&path), sealed::CLEAR_VERSION);
    let store = reopen(&path);
    assert_eq!(
        store.peer_renewal_state(&PEER).unwrap().last_attempt_at_ms,
        Some(T)
    );
}

/// `raven privacy rotate-meta` keys the rows again (a new keyed device) and
/// they read the same; `raven privacy unseal` writes them back clear.
#[test]
fn rotate_meta_and_unseal_keep_the_rows() {
    let (dir, path, mut store) = store_in(true);
    store.note_session_end_seen(&PEER, T + HOUR).unwrap();
    store.begin_repair_attempt(&PEER, T).unwrap().unwrap();
    store
        .set_renewal_pending(&PEER, &[0x66; 99], T + DAY_MS)
        .unwrap();
    let before = store.peer_renewal_state(&PEER).unwrap();
    drop(store);
    let keyed = |path: &Path| -> Vec<u8> {
        Connection::open(path)
            .unwrap()
            .query_row(
                "SELECT kh_peer_device FROM peer_session_renewal",
                [],
                |row| row.get(0),
            )
            .unwrap()
    };
    let old = keyed(&path);
    crate::privacy::rotate_meta(dir.path(), T, &|| true).unwrap();
    assert_ne!(keyed(&path), old);
    assert_eq!(reopen(&path).peer_renewal_state(&PEER).unwrap(), before);
    crate::privacy::unseal_all(dir.path(), &|| true).unwrap();
    assert!(renewal_columns(&path).contains(&"peer_device".to_owned()));
    let store = reopen(&path);
    assert!(!store.layout.is_keyed());
    assert_eq!(store.peer_renewal_state(&PEER).unwrap(), before);
}

/// Removing a contact forgets its renewal row ("real erase"), in either
/// layout, and only that contact's.
#[test]
fn forgetting_a_contact_forgets_its_renewal_row() {
    for sealed_profile in [false, true] {
        let (dir, _path, mut store) = store_in(sealed_profile);
        store.begin_repair_attempt(&PEER, T).unwrap().unwrap();
        store.begin_repair_attempt(&[0x03; 32], T).unwrap().unwrap();
        forget_session_end(dir.path(), &PEER).unwrap();
        assert_eq!(
            store.peer_renewal_state(&PEER).unwrap(),
            PeerRenewalState::default()
        );
        assert_eq!(
            store
                .peer_renewal_state(&[0x03; 32])
                .unwrap()
                .attempts_in_window,
            1
        );
    }
}

/// A clear store's renewal state, the profile sealed after it was written
/// (the first open after `raven privacy seal-now`, or an upgrade).
fn clear_store_with_state_then_sealed() -> (tempfile::TempDir, PathBuf, PeerRenewalState) {
    let (dir, path, mut store) = store_in(false);
    store.note_session_end_seen(&PEER, T + HOUR).unwrap();
    store.begin_repair_attempt(&PEER, T).unwrap().unwrap();
    store
        .set_renewal_pending(&PEER, &[0x5A; 77], T + DAY_MS)
        .unwrap();
    let before = store.peer_renewal_state(&PEER).unwrap();
    drop(store);
    seal_profile(dir.path());
    (dir, path, before)
}

/// Review C-2: an open takes the clear arm of the schema step while another
/// opener's move to schema 4 commits (renewal rows keyed with it). The
/// clear create that follows never drops the now keyed renewal table: the
/// budget, the backoff and the pending PairInit survive.
#[test]
fn a_seal_move_committing_mid_open_keeps_the_renewal_rows() {
    let (dir, path, before) = clear_store_with_state_then_sealed();
    sealed::schema_hook::set(sealed::schema_hook::At::BeforeWrite, {
        let (dir, path) = (dir.path().to_path_buf(), path.clone());
        move || {
            let sealer = sealed::Sealer::cached(&dir).unwrap();
            let moved =
                sealed::migrate_forward(&path, sealer.meta_keys(), &crate::disk_space::free_bytes)
                    .unwrap();
            assert!(!moved.already);
        }
    });
    let store =
        IndexedSessionStore::open_with_backend(&path, Arc::new(MemoryProtectedBackend::default()))
            .expect("the open finds the moved store");
    assert!(store.layout.is_keyed());
    assert_eq!(store.peer_renewal_state(&PEER).unwrap(), before);
    drop(store);
    assert!(renewal_columns(&path).contains(&"kh_peer_device".to_owned()));
    assert_eq!(reopen(&path).peer_renewal_state(&PEER).unwrap(), before);
}

/// Review C-2, the mirror: an open takes the keyed arm while an unseal
/// (`raven privacy unseal`) moves the store back. The open never keys the
/// clear renewal table of an unsealed store (a later clear open would drop
/// it): it opens the clear store, rows intact.
#[test]
fn an_unseal_committing_mid_open_keeps_the_renewal_rows() {
    let (dir, path, mut store) = store_in(true);
    store.note_session_end_seen(&PEER, T + HOUR).unwrap();
    store.begin_repair_attempt(&PEER, T).unwrap().unwrap();
    store
        .set_renewal_pending(&PEER, &[0x5B; 77], T + DAY_MS)
        .unwrap();
    let before = store.peer_renewal_state(&PEER).unwrap();
    drop(store);
    sealed::schema_hook::set(sealed::schema_hook::At::BeforeWrite, {
        let dir = dir.path().to_path_buf();
        let path = path.clone();
        move || {
            let keys = crate::at_rest::keys_cached(&dir).unwrap();
            sealed::migrate_back(&path, &keys, &|_| None).unwrap();
            crate::privacy::set_mode(&dir, crate::at_rest::Mode::UnsealedByUser).unwrap();
        }
    });
    let store =
        IndexedSessionStore::open_with_backend(&path, Arc::new(MemoryProtectedBackend::default()))
            .expect("the open finds the unsealed store");
    assert!(!store.layout.is_keyed());
    assert_eq!(store.peer_renewal_state(&PEER).unwrap(), before);
    drop(store);
    assert!(renewal_columns(&path).contains(&"peer_device".to_owned()));
    assert_eq!(reopen(&path).peer_renewal_state(&PEER).unwrap(), before);
}

// ── Phase 6b R2 (step P6.27): the early re-key ─────────────────────────────

/// The early re-key request in either layout: one per contact per 6 h
/// (either way round on the clock), kept across a reopen, met only by its
/// own time, its cap kept after it is met, the row kept by the prune while
/// the request or the cap lasts; in a sealed profile only the `meta` holds
/// it.
#[test]
fn early_rekey_requests_keep_their_cap_and_finish() {
    use crate::session_renewal::{EARLY_MIN_GAP_MS, EARLY_PENDING_MS};
    for sealed_profile in [false, true] {
        let (_dir, path, mut store) = store_in(sealed_profile);
        store
            .begin_repair_attempt(&PEER, T - DAY_MS)
            .unwrap()
            .unwrap();
        assert!(store.request_early_renewal(&PEER, 20, T).unwrap());
        assert!(!store
            .request_early_renewal(&PEER, 22, T + EARLY_MIN_GAP_MS - 1)
            .unwrap());
        assert!(!store.request_early_renewal(&PEER, 22, T - HOUR).unwrap());
        let asked = store.peer_renewal_state(&PEER).unwrap();
        assert_eq!(
            (
                asked.early_requested_at_ms,
                asked.early_reason,
                asked.last_early_ms,
                asked.attempts_in_window
            ),
            (Some(T), Some(20), Some(T), 1)
        );
        drop(store);
        let mut store = reopen(&path);
        assert_eq!(store.peer_renewal_state(&PEER).unwrap(), asked);
        // Only the request it is about is met.
        store.finish_early_renewal(&PEER, T - 1).unwrap();
        assert_eq!(store.peer_renewal_state(&PEER).unwrap(), asked);
        store.finish_early_renewal(&PEER, T).unwrap();
        assert_eq!(
            store.peer_renewal_state(&PEER).unwrap(),
            PeerRenewalState {
                early_requested_at_ms: None,
                early_reason: None,
                ..asked.clone()
            }
        );
        assert!(!store.request_early_renewal(&PEER, 20, T + HOUR).unwrap());
        let again = T + EARLY_MIN_GAP_MS;
        assert!(store.request_early_renewal(&PEER, 23, again).unwrap());
        // The prune keeps the row while the request (a day) lasts.
        let goes = again + EARLY_PENDING_MS;
        assert_eq!(store.prune_renewal_state(goes - HOUR).unwrap(), 0);
        assert_eq!(store.prune_renewal_state(goes + HOUR).unwrap(), 1);
        assert_eq!(
            store.peer_renewal_state(&PEER).unwrap(),
            PeerRenewalState::default()
        );
        assert_eq!(
            renewal_columns(&path).contains(&"early_reason".to_owned()),
            !sealed_profile
        );
    }
}

/// The renewal table as a build before P6.27 made it (no early re-key
/// columns).
fn older_renewal_shape() -> String {
    let mut shape = sealed::renewal_columns(false).to_owned();
    for (name, definition) in sealed::RENEWAL_EARLY_COLUMNS {
        let column = format!(",\n         {name} {definition}");
        assert!(shape.contains(&column), "{name}");
        shape = shape.replace(&column, "");
    }
    assert!(!shape.contains("early"));
    shape
}

/// A clear table an older build made gets the three columns at the next
/// open (its rows, rowids and version kept); the early re-key then moves
/// into the sealed `meta` with the keys and back out with an unseal. A
/// table that has them is not written at an open.
#[test]
fn an_older_clear_table_gets_the_early_columns_and_they_move_with_the_keys() {
    let (dir, path, store) = store_in(false);
    store
        .conn
        .execute_batch(&format!(
            "DROP TABLE peer_session_renewal; {}
             INSERT INTO peer_session_renewal (rowid, peer_device, window_start_ms,
               attempts_in_window, last_attempt_at_ms, failures)
             VALUES (9, X'{}', {T}, 1, {T}, 0);",
            sealed::create_if_missing("peer_session_renewal", &older_renewal_shape()),
            hex::encode(PEER),
        ))
        .unwrap();
    drop(store);
    assert!(!renewal_columns(&path).contains(&"early_reason".to_owned()));
    let mut store = reopen(&path);
    let columns = renewal_columns(&path);
    for (name, _) in sealed::RENEWAL_EARLY_COLUMNS {
        assert!(columns.contains(&name.to_owned()), "{name}");
    }
    assert_eq!(version(&path), sealed::CLEAR_VERSION);
    let rowid: i64 = store
        .conn
        .query_row("SELECT rowid FROM peer_session_renewal", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(rowid, 9);
    assert_eq!(store.peer_renewal_state(&PEER).unwrap().early_reason, None);
    assert!(store.request_early_renewal(&PEER, 60, T + HOUR).unwrap());
    let before = store.peer_renewal_state(&PEER).unwrap();
    assert_eq!(before.attempts_in_window, 1);
    drop(store);
    // An open of a table that has them changes nothing.
    let schema = |path: &Path| -> String {
        Connection::open(path)
            .unwrap()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = 'peer_session_renewal'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    };
    let sql = schema(&path);
    drop(reopen(&path));
    assert_eq!(schema(&path), sql);
    // Sealed: the meta holds it.
    seal_profile(dir.path());
    let store = reopen(&path);
    assert!(store.layout.is_keyed());
    assert_eq!(store.peer_renewal_state(&PEER).unwrap(), before);
    drop(store);
    assert!(!renewal_columns(&path).contains(&"early_reason".to_owned()));
    // Unsealed: clear columns again.
    crate::privacy::unseal_all(dir.path(), &|| true).unwrap();
    let store = reopen(&path);
    assert!(!store.layout.is_keyed());
    assert_eq!(store.peer_renewal_state(&PEER).unwrap(), before);
    assert!(renewal_columns(&path).contains(&"early_reason".to_owned()));
}

/// `SessionRetireCause` reads every stored value: 7 is the security re-key,
/// one this build does not know is a plain retirement (never an error).
#[test]
fn retire_causes_read_tolerantly() {
    assert_eq!(
        SessionRetireCause::from_i64(7),
        SessionRetireCause::LocalSecurityRekey
    );
    assert_eq!(
        SessionRetireCause::from_i64(1),
        SessionRetireCause::PeerNoSession
    );
    for unknown in [0, 8, 99, -1] {
        assert_eq!(
            SessionRetireCause::from_i64(unknown),
            SessionRetireCause::Other
        );
    }
}

/// The reset table of a store made before P6.27 (causes 1-6 only) is widened
/// in place before its first `LocalSecurityRekey` row: rows, flags, the
/// index and foreign keys kept; an ordinary retirement never touches it.
#[test]
fn a_rekey_retirement_widens_an_older_reset_table() {
    for sealed_profile in [false, true] {
        let (_dir, path, mut store) = store_in(sealed_profile);
        let fixture = endpoint_fixture();
        let peer = fixture.key.responder_device_ed25519;
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        store
            .mark_session_initiated(&fixture.key, &peer, true, false, fixture.now_ms)
            .unwrap();
        let keyed = store.layout.is_keyed();
        let older = sealed::reset_columns(keyed).replace("BETWEEN 1 AND 7", "BETWEEN 1 AND 6");
        store
            .conn
            .execute_batch(&format!(
                "CREATE TABLE reset__older ({older});
                 INSERT INTO reset__older SELECT * FROM indexed_session_reset;
                 DROP TABLE indexed_session_reset;
                 ALTER TABLE reset__older RENAME TO indexed_session_reset;
                 {}",
                sealed::reset_index(keyed)
            ))
            .unwrap();
        let table_sql = |path: &Path| -> String {
            Connection::open(path)
                .unwrap()
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE name = 'indexed_session_reset'",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        };
        assert!(table_sql(&path).contains("BETWEEN 1 AND 6"));
        assert!(store
            .retire_session(
                &fixture.key,
                &peer,
                SessionRetireCause::LocalSecurityRekey,
                fixture.now_ms
            )
            .unwrap());
        drop(store);
        assert!(table_sql(&path).contains("retire_cause BETWEEN 1 AND 7"));
        let conn = Connection::open(&path).unwrap();
        let index: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'index' AND name = 'indexed_session_reset_peer'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(index, 1);
        let orphans: i64 = conn
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(orphans, 0);
        drop(conn);
        let store = reopen(&path);
        let info = store
            .session_reset_info(&fixture.binding.session_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            (info.retire_cause, info.retired_at_ms, info.initiated_local),
            (
                Some(SessionRetireCause::LocalSecurityRekey),
                Some(fixture.now_ms),
                true
            )
        );
    }
}

/// A session retired for a security re-key takes the contact's new objects
/// for ten minutes after the retirement, then refuses them
/// (`SessionRetired`, no event); a duplicate of one it took is still
/// answered. A Phase 2a retirement is unchanged.
#[test]
fn a_rekey_retired_session_takes_new_objects_for_ten_minutes() {
    use crate::session_renewal::EARLY_OLD_ACCEPT_MS;
    for sealed_profile in [false, true] {
        let (_dir, _path, mut store) = store_in(sealed_profile);
        let fixture = endpoint_fixture();
        let peer = fixture.key.responder_device_ed25519;
        let now = fixture.now_ms;
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        // Retired so that the ten minutes end 1 ms after `now`.
        assert!(store
            .retire_session(
                &fixture.key,
                &peer,
                SessionRetireCause::LocalSecurityRekey,
                now + 1 - EARLY_OLD_ACCEPT_MS
            )
            .unwrap());
        accept_text(&mut store, &fixture, 0, [0x71; 16], now);
        let late = inbound_message_envelope(&fixture, 1, [0x72; 16], b"late").pack();
        assert!(matches!(
            store.accept_message_envelope(
                &fixture.key,
                &late,
                &fixture.remote_certificate,
                false,
                now + 1
            ),
            Err(IndexedSessionStoreError::SessionRetired)
        ));
        assert_eq!(
            crate::security_events::classify_store_error(
                &IndexedSessionStoreError::SessionRetired,
                crate::security_events::Via::DirectLink(crate::outbox::OutboxCarrier::Lan)
            ),
            None
        );
        let again = inbound_message_envelope(&fixture, 0, [0x71; 16], b"listed").pack();
        assert!(matches!(
            store.accept_message_envelope(
                &fixture.key,
                &again,
                &fixture.remote_certificate,
                false,
                now + 1
            ),
            Ok(EndpointAcceptance::Duplicate { .. })
        ));
    }
    // A Phase 2a retirement keeps taking objects, as before.
    let (_dir, _path, mut store) = store_in(false);
    let fixture = endpoint_fixture();
    store
        .create_session(fixture.binding.clone(), fixture.root)
        .unwrap();
    store
        .retire_session(
            &fixture.key,
            &fixture.key.responder_device_ed25519,
            SessionRetireCause::PeerNoSession,
            fixture.now_ms - crate::session_renewal::DAY_MS,
        )
        .unwrap();
    accept_text(&mut store, &fixture, 0, [0x73; 16], fixture.now_ms);
}
