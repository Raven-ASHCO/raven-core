//! The letter sessions' table (Phase 5, P5.12, the store's `letters`
//! module) in both layouts: the provisional cap of a session this node
//! started for a letter (indices 0-15, never an ACK, never a provisional
//! responder; every other provisional session still index 0 only), a row
//! marked once and gone with its head, the moves to and from schema 4 and
//! a re-key, an older store without the table, and review C-2's two races.
//! Each test decides the layout itself.

use super::sealed_store::{profile, seal_profile};
use super::*;
use crate::horizon::LETTER_SESSION_MAX_MESSAGES;
use crate::pair_init::INIT_WIRE_LEN;
use crate::sqlite_rebuild as rebuild;

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

fn columns(path: &Path, table: &str) -> Vec<String> {
    rebuild::columns(&Connection::open(path).unwrap(), table).unwrap()
}

/// A stand-in PairInit wire that names both devices and both addresses (a
/// sealed file must not hold them in clear).
fn pair_init_wire(fixture: &EndpointFixture) -> Vec<u8> {
    let mut wire = [
        fixture.key.initiator_address.as_bytes(),
        fixture.key.responder_address.as_bytes(),
        &fixture.key.initiator_device_ed25519,
        &fixture.key.responder_device_ed25519,
    ]
    .concat();
    wire.resize(INIT_WIRE_LEN, 0x5E);
    wire
}

/// The fixture's session, provisional (no PairResponse yet).
fn provisional(fixture: &EndpointFixture, role: LocalRole) -> IndexedSessionBinding {
    let mut binding = fixture.binding.clone();
    binding.lifecycle = SessionLifecycle::Provisional;
    binding.response_hash = None;
    binding.local_role = role;
    binding
}

fn send(
    store: &mut IndexedSessionStore,
    fixture: &EndpointFixture,
    rng: &mut StdRng,
) -> Result<EndpointOutbound, IndexedSessionStoreError> {
    let local_device = authorized_local_device(fixture);
    let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
    store.send_message_envelope(
        &fixture.key,
        "sealed into a letter",
        &local_device,
        fixture.now_ms,
        fixture.now_ms + 60_000,
        fixture.now_ms,
        rng,
        &mut queue,
    )
}

/// A provisional initiator session this node started for a letter seals
/// message indices 0 to 15 (`ATSAM_ENDPOINT_TRANSACTION_V1.md` §4.1
/// addendum); index 16 needs the PairResponse, as index 1 does elsewhere.
/// A retry of a sealed copy passes the same rule.
#[test]
fn provisional_letter_session_allows_indices_0_to_15_only() {
    for sealed_profile in [false, true] {
        let (_dir, _path, mut store) = store_in(sealed_profile);
        let fixture = endpoint_fixture();
        store
            .create_session(provisional(&fixture, LocalRole::Initiator), fixture.root)
            .unwrap();
        store
            .mark_letter_session(
                &fixture.key,
                LetterRole::Initiator,
                Some(&pair_init_wire(&fixture)),
            )
            .unwrap();
        let mut rng = StdRng::from_seed([0xC1; 32]);
        let mut last = None;
        for index in 0..LETTER_SESSION_MAX_MESSAGES {
            let sent = send(&mut store, &fixture, &mut rng).unwrap();
            assert_eq!(sent.ratchet_index, index);
            last = Some(sent);
        }
        assert_eq!(LETTER_SESSION_MAX_MESSAGES, 16);
        assert!(matches!(
            send(&mut store, &fixture, &mut rng),
            Err(IndexedSessionStoreError::SessionNotConfirmed)
        ));
        let last = last.unwrap();
        let local_device = authorized_local_device(&fixture);
        let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        let again = store
            .resend_queued_endpoint_outbound(
                &fixture.key,
                &last.object_digest,
                &local_device,
                fixture.now_ms,
                &mut queue,
            )
            .unwrap();
        assert_eq!(again.ratchet_index, LETTER_SESSION_MAX_MESSAGES - 1);
        // Confirmed, the lane goes on as any session's.
        store.confirm_session(&fixture.key, [0x46; 32]).unwrap();
        assert_eq!(
            send(&mut store, &fixture, &mut rng).unwrap().ratchet_index,
            LETTER_SESSION_MAX_MESSAGES
        );
    }
}

/// The cap is for Messages of a provisional initiator only: an ACK still
/// needs the PairResponse, and so does a provisional responder, letter row
/// or not.
#[test]
fn provisional_letter_session_still_refuses_acks() {
    for sealed_profile in [false, true] {
        let (_dir, _path, mut store) = store_in(sealed_profile);
        let fixture = endpoint_fixture();
        store
            .create_session(provisional(&fixture, LocalRole::Initiator), fixture.root)
            .unwrap();
        store
            .mark_letter_session(
                &fixture.key,
                LetterRole::Initiator,
                Some(&pair_init_wire(&fixture)),
            )
            .unwrap();
        let local_device = authorized_local_device(&fixture);
        let mut rng = StdRng::from_seed([0xC2; 32]);
        let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        assert!(matches!(
            store.enqueue_committed_ack(
                &fixture.key,
                &[0xBA; 32],
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut rng,
                &mut queue,
            ),
            Err(IndexedSessionStoreError::SessionNotConfirmed)
        ));

        // A provisional responder (marked as a letter it accepted).
        let (_dir, _path, mut store) = store_in(sealed_profile);
        store
            .create_session(provisional(&fixture, LocalRole::Responder), fixture.root)
            .unwrap();
        store
            .mark_letter_session(&fixture.key, LetterRole::Responder, None)
            .unwrap();
        assert!(matches!(
            send(&mut store, &fixture, &mut rng),
            Err(IndexedSessionStoreError::SessionNotConfirmed)
        ));
    }
}

/// Without a letter row a provisional initiator still seals index 0 only
/// (the PairInit bootstrap; the full check is
/// `outbound_allows_only_initial_provisional_initiator_message_then_requires_confirmation`).
#[test]
fn non_letter_provisional_still_index_zero_only() {
    for sealed_profile in [false, true] {
        let (_dir, _path, mut store) = store_in(sealed_profile);
        let fixture = endpoint_fixture();
        store
            .create_session(provisional(&fixture, LocalRole::Initiator), fixture.root)
            .unwrap();
        let mut rng = StdRng::from_seed([0xC3; 32]);
        assert_eq!(
            send(&mut store, &fixture, &mut rng).unwrap().ratchet_index,
            0
        );
        assert!(matches!(
            send(&mut store, &fixture, &mut rng),
            Err(IndexedSessionStoreError::SessionNotConfirmed)
        ));
        assert_eq!(
            store.letter_role(&fixture.binding.session_id).unwrap(),
            None
        );
    }
}

/// A row is marked once (the same values again are a no-op, others a
/// conflict, a role without its PairInit or with one it must not have is
/// refused), names the key's other device, is listed while its head lives
/// and goes with the head at the prune (the foreign key cascades).
#[test]
fn letter_rows_mark_once_and_go_with_their_head() {
    for sealed_profile in [false, true] {
        let (_dir, _path, mut store) = store_in(sealed_profile);
        let fixture = endpoint_fixture();
        let peer = fixture.key.responder_device_ed25519;
        let wire = pair_init_wire(&fixture);
        assert!(matches!(
            store.mark_letter_session(&fixture.key, LetterRole::Initiator, Some(&wire)),
            Err(IndexedSessionStoreError::NotFound)
        ));
        store
            .create_session(provisional(&fixture, LocalRole::Initiator), fixture.root)
            .unwrap();
        for (role, init) in [
            (LetterRole::Initiator, None),
            (LetterRole::Initiator, Some(&wire[..100])),
            (LetterRole::Responder, Some(&wire[..])),
        ] {
            assert!(matches!(
                store.mark_letter_session(&fixture.key, role, init),
                Err(IndexedSessionStoreError::InvalidBinding)
            ));
        }
        store
            .mark_letter_session(&fixture.key, LetterRole::Initiator, Some(&wire))
            .unwrap();
        store
            .mark_letter_session(&fixture.key, LetterRole::Initiator, Some(&wire))
            .unwrap();
        let mut other = wire.clone();
        other[0] ^= 1;
        assert!(matches!(
            store.mark_letter_session(&fixture.key, LetterRole::Initiator, Some(&other)),
            Err(IndexedSessionStoreError::BindingConflict)
        ));
        let sid = fixture.binding.session_id;
        let row = LetterSession {
            session_id: sid,
            peer_device: peer,
            role: LetterRole::Initiator,
            pair_init: Some(wire.clone()),
            created_at_ms: fixture.binding.created_at_ms,
        };
        assert_eq!(store.letter_session(&sid).unwrap(), Some(row.clone()));
        assert_eq!(
            store.letter_role(&sid).unwrap(),
            Some(LetterRole::Initiator)
        );
        assert_eq!(
            store
                .live_letter_sessions_for_peer(&peer, LetterRole::Initiator, fixture.now_ms)
                .unwrap(),
            vec![(fixture.key.clone(), row)]
        );
        for (who, role) in [
            (peer, LetterRole::Responder),
            ([0x99; 32], LetterRole::Initiator),
        ] {
            assert!(store
                .live_letter_sessions_for_peer(&who, role, fixture.now_ms)
                .unwrap()
                .is_empty());
        }
        let ends = fixture.binding.expires_at_ms;
        assert!(store
            .live_letter_sessions_for_peer(&peer, LetterRole::Initiator, ends)
            .unwrap()
            .is_empty());
        assert_eq!(store.prune_expired_sessions(ends).unwrap(), 1);
        assert_eq!(store.letter_session(&sid).unwrap(), None);
        let rows: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM indexed_session_letter", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 0);
    }
}

/// A plain store's letter row moves with it into a sealed profile (keyed,
/// the PairInit sealed: no device key or address left in the file), through
/// `raven privacy rotate-meta` (keyed again) and back out with
/// `raven privacy unseal`, rowid kept.
#[test]
fn letter_rows_move_with_the_store() {
    let (dir, path, mut store) = store_in(false);
    let fixture = endpoint_fixture();
    let peer = fixture.key.responder_device_ed25519;
    store
        .create_session(provisional(&fixture, LocalRole::Initiator), fixture.root)
        .unwrap();
    let wire = pair_init_wire(&fixture);
    store
        .mark_letter_session(&fixture.key, LetterRole::Initiator, Some(&wire))
        .unwrap();
    let sid = fixture.binding.session_id;
    let row = store.letter_session(&sid).unwrap().unwrap();
    drop(store);
    let check = |store: &IndexedSessionStore| {
        assert_eq!(store.letter_session(&sid).unwrap(), Some(row.clone()));
        assert_eq!(
            store
                .live_letter_sessions_for_peer(&peer, LetterRole::Initiator, fixture.now_ms)
                .unwrap()
                .len(),
            1
        );
    };
    let keyed = |path: &Path| {
        let names = columns(path, letters::LETTER);
        (
            names.contains(&"kh_peer_device".to_owned()),
            names.contains(&"pair_init".to_owned()),
        )
    };
    seal_profile(dir.path());
    let store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
    assert!(store.layout.is_keyed());
    assert_eq!(keyed(&path), (true, false));
    check(&store);
    drop(store);
    let file = |path: &Path| {
        crate::paths::checkpoint_truncate(&Connection::open(path).unwrap()).unwrap();
        std::fs::read(path).unwrap()
    };
    let raw = file(&path);
    for clear in [
        &wire[..],
        fixture.key.responder_address.as_bytes(),
        &fixture.key.responder_device_ed25519,
    ] {
        assert!(
            !raw.windows(clear.len()).any(|window| window == clear),
            "a clear value is left in the sealed store"
        );
    }
    let kh = |path: &Path| -> Vec<u8> {
        Connection::open(path)
            .unwrap()
            .query_row(
                "SELECT kh_peer_device FROM indexed_session_letter",
                [],
                |row| row.get(0),
            )
            .unwrap()
    };
    let before = kh(&path);
    crate::privacy::rotate_meta(dir.path(), fixture.now_ms, &|| true).unwrap();
    assert_ne!(kh(&path), before);
    check(&open_test_store(
        &path,
        Arc::new(MemoryProtectedBackend::default()),
    ));
    crate::privacy::unseal_all(dir.path(), &|| true).unwrap();
    assert_eq!(keyed(&path), (false, true));
    let store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
    assert!(!store.layout.is_keyed());
    check(&store);
}

/// A store an older build made (no letter table) opens with it added in the
/// profile's shape, its version kept; a clear table an older build of the
/// pack left in a store it sealed moves into the keyed shape with its row.
#[test]
fn an_old_store_without_the_letter_table_opens_and_keeps_its_version() {
    let fixture = endpoint_fixture();
    let wire = pair_init_wire(&fixture);
    for sealed_profile in [false, true] {
        let (_dir, path, mut store) = store_in(sealed_profile);
        store
            .create_session(provisional(&fixture, LocalRole::Initiator), fixture.root)
            .unwrap();
        store
            .conn
            .execute_batch("DROP TABLE indexed_session_letter;")
            .unwrap();
        drop(store);
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        let expected_version = if sealed_profile {
            METADATA_SCHEMA_VERSION
        } else {
            sealed::CLEAR_VERSION
        };
        assert_eq!(
            rebuild::user_version(&store.conn).unwrap(),
            expected_version
        );
        assert_eq!(
            columns(&path, letters::LETTER).contains(&"kh_peer_device".to_owned()),
            sealed_profile
        );
        store
            .mark_letter_session(&fixture.key, LetterRole::Initiator, Some(&wire))
            .unwrap();
    }
    let (_dir, path, mut store) = store_in(true);
    store
        .create_session(provisional(&fixture, LocalRole::Initiator), fixture.root)
        .unwrap();
    let sid = fixture.binding.session_id;
    store
        .conn
        .execute_batch(&format!(
            "DROP TABLE indexed_session_letter; {}
             INSERT INTO indexed_session_letter (rowid, session_id, peer_device, role,
               pair_init, created_at_ms)
             VALUES (7, X'{}', X'{}', 1, X'{}', 10);",
            sealed::create_if_missing(letters::LETTER, letters::letter_columns(false)),
            hex::encode(sid),
            hex::encode(fixture.key.responder_device_ed25519),
            hex::encode(&wire),
        ))
        .unwrap();
    drop(store);
    let store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
    assert!(columns(&path, letters::LETTER).contains(&"kh_peer_device".to_owned()));
    let rowid: i64 = store
        .conn
        .query_row("SELECT rowid FROM indexed_session_letter", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(rowid, 7);
    assert_eq!(
        store.letter_session(&sid).unwrap(),
        Some(LetterSession {
            session_id: sid,
            peer_device: fixture.key.responder_device_ed25519,
            role: LetterRole::Initiator,
            pair_init: Some(wire),
            created_at_ms: 10,
        })
    );
}

/// A store with one letter row in a plain or a sealed profile, and the row.
fn store_with_letter_row(sealed_profile: bool) -> (tempfile::TempDir, PathBuf, LetterSession) {
    let (dir, path, mut store) = store_in(sealed_profile);
    let fixture = endpoint_fixture();
    store
        .create_session(provisional(&fixture, LocalRole::Initiator), fixture.root)
        .unwrap();
    store
        .mark_letter_session(
            &fixture.key,
            LetterRole::Initiator,
            Some(&pair_init_wire(&fixture)),
        )
        .unwrap();
    let row = store
        .letter_session(&fixture.binding.session_id)
        .unwrap()
        .unwrap();
    (dir, path, row)
}

/// Review C-2 for the letter table: an open takes the clear arm of the
/// schema step while another opener's move to schema 4 commits (the letter
/// row keyed with it). The clear create that follows never drops the now
/// keyed table: the row survives.
#[test]
fn a_seal_move_committing_mid_open_keeps_the_letter_rows() {
    let (dir, path, row) = store_with_letter_row(false);
    seal_profile(dir.path());
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
    assert_eq!(
        store.letter_session(&row.session_id).unwrap(),
        Some(row.clone())
    );
    drop(store);
    assert!(columns(&path, letters::LETTER).contains(&"kh_peer_device".to_owned()));
    let store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
    assert_eq!(store.letter_session(&row.session_id).unwrap(), Some(row));
}

/// The mirror: an open takes the keyed arm while an unseal moves the store
/// back. The open never keys the clear letter table of an unsealed store (a
/// later clear open would drop it): it opens the clear store, row intact.
#[test]
fn an_unseal_committing_mid_open_keeps_the_letter_rows() {
    let (dir, path, row) = store_with_letter_row(true);
    sealed::schema_hook::set(sealed::schema_hook::At::BeforeWrite, {
        let (dir, path) = (dir.path().to_path_buf(), path.clone());
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
    assert_eq!(
        store.letter_session(&row.session_id).unwrap(),
        Some(row.clone())
    );
    drop(store);
    assert!(columns(&path, letters::LETTER).contains(&"peer_device".to_owned()));
    let store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
    assert_eq!(store.letter_session(&row.session_id).unwrap(), Some(row));
}

/// A stand-in PairResponse wire naming the responder device (a sealed file
/// must not hold it in clear).
fn pair_response_wire(fixture: &EndpointFixture) -> Vec<u8> {
    let mut wire = fixture.key.responder_device_ed25519.to_vec();
    wire.resize(crate::pair_init::RESPONSE_WIRE_LEN, 0x6E);
    wire
}

/// P5.14: a session accepted from a letter keeps its exact PairResponse in
/// its row, once (the same bytes again are a no-op, other bytes a conflict,
/// a wrong length refused; a row marked without one gets it; a row of the
/// other role is a conflict), in both layouts; other rows have none; it goes
/// with its head.
#[test]
fn responder_rows_keep_their_pair_response_once() {
    for sealed_profile in [false, true] {
        let (_dir, _path, mut store) = store_in(sealed_profile);
        let fixture = endpoint_fixture();
        let reply = pair_response_wire(&fixture);
        let sid = fixture.binding.session_id;
        assert!(matches!(
            store.mark_letter_responder(&fixture.key, &reply),
            Err(IndexedSessionStoreError::NotFound)
        ));
        store
            .create_session(provisional(&fixture, LocalRole::Responder), fixture.root)
            .unwrap();
        assert!(matches!(
            store.mark_letter_responder(&fixture.key, &reply[..100]),
            Err(IndexedSessionStoreError::InvalidBinding)
        ));
        assert_eq!(store.letter_reply(&sid).unwrap(), None);
        store
            .mark_letter_session(&fixture.key, LetterRole::Responder, None)
            .unwrap();
        assert_eq!(store.letter_reply(&sid).unwrap(), None);
        store.mark_letter_responder(&fixture.key, &reply).unwrap();
        store.mark_letter_responder(&fixture.key, &reply).unwrap();
        store
            .mark_letter_session(&fixture.key, LetterRole::Responder, None)
            .unwrap();
        let mut other = reply.clone();
        other[40] ^= 1;
        assert!(matches!(
            store.mark_letter_responder(&fixture.key, &other),
            Err(IndexedSessionStoreError::BindingConflict)
        ));
        assert_eq!(store.letter_reply(&sid).unwrap(), Some(reply.clone()));
        assert_eq!(
            store.letter_role(&sid).unwrap(),
            Some(LetterRole::Responder)
        );
        assert_eq!(
            store
                .prune_expired_sessions(fixture.binding.expires_at_ms)
                .unwrap(),
            1
        );
        assert_eq!(store.letter_reply(&sid).unwrap(), None);

        // A session this node started: never a PairResponse of its own.
        let (_dir, _path, mut store) = store_in(sealed_profile);
        store
            .create_session(provisional(&fixture, LocalRole::Initiator), fixture.root)
            .unwrap();
        store
            .mark_letter_session(
                &fixture.key,
                LetterRole::Initiator,
                Some(&pair_init_wire(&fixture)),
            )
            .unwrap();
        assert!(matches!(
            store.mark_letter_responder(&fixture.key, &reply),
            Err(IndexedSessionStoreError::BindingConflict)
        ));
        assert_eq!(store.letter_reply(&sid).unwrap(), None);
    }
}

/// The kept PairResponse moves with the store into a sealed profile (in the
/// sealed `meta`: no clear copy left), through a re-key and back out; a
/// clear table P5.12 made without its column gains it at the next open
/// (the row kept, no PairResponse) and moves forward from that shape too.
#[test]
fn the_kept_pair_response_moves_with_the_store_and_old_tables_gain_the_column() {
    let (dir, path, mut store) = store_in(false);
    let fixture = endpoint_fixture();
    let reply = pair_response_wire(&fixture);
    let sid = fixture.binding.session_id;
    store
        .create_session(provisional(&fixture, LocalRole::Responder), fixture.root)
        .unwrap();
    store.mark_letter_responder(&fixture.key, &reply).unwrap();
    let row = store.letter_session(&sid).unwrap().unwrap();
    drop(store);
    let check = |store: &IndexedSessionStore| {
        assert_eq!(store.letter_session(&sid).unwrap(), Some(row.clone()));
        assert_eq!(store.letter_reply(&sid).unwrap(), Some(reply.clone()));
    };
    seal_profile(dir.path());
    let store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
    assert!(store.layout.is_keyed());
    assert!(!columns(&path, letters::LETTER).contains(&"pair_response".to_owned()));
    check(&store);
    drop(store);
    crate::paths::checkpoint_truncate(&Connection::open(&path).unwrap()).unwrap();
    let raw = std::fs::read(&path).unwrap();
    assert!(
        !raw.windows(reply.len())
            .any(|window| window == reply.as_slice()),
        "the PairResponse is left in clear"
    );
    crate::privacy::rotate_meta(dir.path(), fixture.now_ms, &|| true).unwrap();
    check(&open_test_store(
        &path,
        Arc::new(MemoryProtectedBackend::default()),
    ));
    crate::privacy::unseal_all(dir.path(), &|| true).unwrap();
    assert!(columns(&path, letters::LETTER).contains(&"pair_response".to_owned()));
    check(&open_test_store(
        &path,
        Arc::new(MemoryProtectedBackend::default()),
    ));

    // P5.12's clear shape: no PairResponse column.
    let p512 = "session_id    BLOB PRIMARY KEY NOT NULL CHECK(length(session_id) = 32),
         peer_device   BLOB NOT NULL CHECK(length(peer_device) = 32),
         role          INTEGER NOT NULL CHECK(role IN (1, 2)),
         pair_init     BLOB CHECK(pair_init IS NULL OR length(pair_init) = 2788),
         created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
         CHECK((role = 1) = (pair_init IS NOT NULL)),
         FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id) ON DELETE CASCADE";
    let old_table = |path: &Path| {
        Connection::open(path)
            .unwrap()
            .execute_batch(&format!(
                "DROP TABLE indexed_session_letter; {}
                 INSERT INTO indexed_session_letter (rowid, session_id, peer_device, role,
                   pair_init, created_at_ms)
                 VALUES (9, X'{}', X'{}', 2, NULL, {});",
                sealed::create_if_missing(letters::LETTER, p512),
                hex::encode(sid),
                hex::encode(fixture.key.initiator_device_ed25519),
                fixture.binding.created_at_ms,
            ))
            .unwrap();
    };
    let old_row = LetterSession {
        session_id: sid,
        peer_device: fixture.key.initiator_device_ed25519,
        role: LetterRole::Responder,
        pair_init: None,
        created_at_ms: fixture.binding.created_at_ms,
    };
    old_table(&path);
    let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
    assert!(!store.layout.is_keyed());
    assert!(columns(&path, letters::LETTER).contains(&"pair_response".to_owned()));
    assert_eq!(store.letter_session(&sid).unwrap(), Some(old_row.clone()));
    assert_eq!(store.letter_reply(&sid).unwrap(), None);
    // ... and takes a PairResponse afterwards.
    store.mark_letter_responder(&fixture.key, &reply).unwrap();
    assert_eq!(store.letter_reply(&sid).unwrap(), Some(reply.clone()));
    drop(store);
    // That shape left by an older build of the pack in a store it sealed
    // moves forward at the next open.
    let (_dir, path, mut store) = store_in(true);
    store
        .create_session(provisional(&fixture, LocalRole::Responder), fixture.root)
        .unwrap();
    drop(store);
    old_table(&path);
    let store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
    assert!(store.layout.is_keyed());
    assert!(columns(&path, letters::LETTER).contains(&"kh_peer_device".to_owned()));
    assert_eq!(store.letter_session(&sid).unwrap(), Some(old_row));
    assert_eq!(store.letter_reply(&sid).unwrap(), None);
}
