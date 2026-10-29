//! The session store at rest (privacy pack PP.13 and PP.14): the move of a
//! populated store to schema 3 (from schema 1, and from a PP.13 build's
//! schema 2) with every row and rowid, the cross-node order, the wait for
//! pending journals, a stop before every statement, the way back, older
//! builds, the bytes on disk, a rotation, the schema guard, and the endpoint
//! tables' blob equalities, insertion order, journal replay, inbox cursors,
//! cleared chats and duplicates. Each
//! test decides the layout itself (the suite's `RAVEN_TEST_SEALED_SESSIONS`
//! switch is off on its thread). Profiles are temp folders whose keys come
//! from the test build's lab K_hist (never a keychain item).

use super::*;
use crate::at_rest::{MigratePolicy, Mode};
use crate::sqlite_rebuild::{self as rebuild, fault, Fault, Shape};

const HOUR: u64 = 3_600_000;

/// A profile folder (an identity marker in it) and its store's path.
pub(super) fn profile() -> (tempfile::TempDir, PathBuf) {
    sealed::test_switch::off();
    let dir = crate::contact_book::tests::profile();
    let path = dir.path().join(INDEXED_SESSION_METADATA_FILE);
    (dir, path)
}

/// Seal `dir` as `privacy::migrate_all` does, without moving any store: the
/// lab key loaded, the mode flipped.
pub(super) fn seal_profile(dir: &Path) {
    crate::at_rest::tests::expect_key_file(dir);
    crate::at_rest::keys_load_with(dir, MigratePolicy::Allow).unwrap();
    crate::privacy::set_mode(dir, Mode::Sealed).unwrap();
}

fn schema(path: &Path) -> (i64, Shape) {
    let conn = Connection::open(path).unwrap();
    (
        rebuild::user_version(&conn).unwrap(),
        rebuild::shape(&conn, sealed::HEADS, sealed::KEYED_COLUMN).unwrap(),
    )
}

/// Every table's rowids, in order.
fn table_rows(path: &Path) -> Vec<(&'static str, Vec<i64>)> {
    let conn = Connection::open(path).unwrap();
    sealed::ALL_TABLES
        .iter()
        .map(|table| {
            let mut statement = conn
                .prepare(&format!("SELECT rowid FROM {table} ORDER BY rowid"))
                .unwrap();
            let rows = statement
                .query_map([], |row| row.get::<_, i64>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            (*table, rows)
        })
        .collect()
}

fn foreign_keys_hold(path: &Path) -> bool {
    let conn = Connection::open(path).unwrap();
    let mut statement = conn.prepare("PRAGMA foreign_key_check").unwrap();
    let found = statement.query([]).unwrap().next().unwrap().is_none();
    found
}

/// A second session with the same contact, created five seconds later.
fn second_binding(fixture: &EndpointFixture) -> IndexedSessionBinding {
    let mut binding = fixture.binding.clone();
    binding.key.init_id = [0x34; 16];
    binding.init_hash = [0x51; 32];
    binding.session_id = session_id(&binding.init_hash);
    binding.created_at_ms += 5_000;
    binding
}

/// A contact whose last session ended, and a removed contact's mark (as the
/// prune and `raven contact remove` write them), in either layout.
fn put_end_and_mark(store: &IndexedSessionStore, ended: (&[u8; 32], i64), mark: (&[u8; 32], i64)) {
    let Some(sealer) = store.layout.keyed() else {
        store
            .conn
            .execute(
                "INSERT INTO peer_session_end (peer_device, ended_at_ms) VALUES (?1, ?2)",
                params![ended.0.as_slice(), ended.1],
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO peer_session_end_erased (peer_device, created_to_ms) VALUES (?1, ?2)",
                params![mark.0.as_slice(), mark.1],
            )
            .unwrap();
        return;
    };
    let kp = sealer.device(ended.0);
    let meta = sealed::SessionEndMeta {
        peer_device: hex::encode(ended.0),
        ended_at_ms: ended.1,
    };
    store
        .conn
        .execute(
            "INSERT INTO peer_session_end (kh_peer_device, prune_after_hour, meta)
             VALUES (?1, ?2, ?3)",
            params![
                kp.as_slice(),
                sealed::prune_hour(horizon::session_end_expiry(ended.1)),
                sealer.seal(sealed::SESSION_END, &kp, &meta)
            ],
        )
        .unwrap();
    let kp = sealer.device(mark.0);
    let meta = sealed::ErasedMeta {
        peer_device: hex::encode(mark.0),
        created_to_ms: mark.1,
    };
    store
        .conn
        .execute(
            "INSERT INTO peer_session_end_erased (kh_peer_device, meta) VALUES (?1, ?2)",
            params![kp.as_slice(), sealer.seal(sealed::ERASED, &kp, &meta)],
        )
        .unwrap();
}

/// A row in every table: two sessions with the contact (one retired by a
/// session reset), received messages (one deleted by the user, one still in
/// the inbox), an ACK going out, a message waiting for its ACK, an
/// acknowledged one, the reset sidecar, the re-seal ledger, the per-peer
/// reset state, a remembered session end and a removal mark.
fn populate(store: &mut IndexedSessionStore, fixture: &EndpointFixture) {
    let local_device = authorized_local_device(fixture);
    let now = fixture.now_ms;
    let peer = fixture.key.responder_device_ed25519;
    store
        .create_session(fixture.binding.clone(), fixture.root)
        .unwrap();
    let second = second_binding(fixture);
    store.create_session(second.clone(), fixture.root).unwrap();
    let intent = accept_text(store, fixture, 0, [0xD0; 16], now);
    accept_text(store, fixture, 1, [0xD1; 16], now);
    let mut rng = StdRng::from_seed([0xD2; 32]);
    let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
    store
        .enqueue_committed_ack(
            &fixture.key,
            &intent,
            &local_device,
            now,
            now + 60_000,
            now,
            &mut rng,
            &mut queue,
        )
        .unwrap();
    store
        .send_message_envelope(
            &fixture.key,
            "waiting",
            &local_device,
            now,
            now + 60_000,
            now,
            &mut rng,
            &mut queue,
        )
        .unwrap();
    // One more in the second session, which a reset then retires.
    store
        .send_message_envelope(
            &second.key,
            "in the old session",
            &local_device,
            now,
            now + 60_000,
            now,
            &mut rng,
            &mut queue,
        )
        .unwrap();
    store
        .register_outstanding_message(&fixture.key, &[0xE0; 16])
        .unwrap();
    let ack = inbound_ack_envelope(fixture, 0, [0xE1; 16], [0xE0; 16], 1, [0xE2; 12]);
    store
        .accept_ack_envelope(
            &fixture.key,
            &ack.pack(),
            &fixture.remote_certificate,
            false,
            now,
        )
        .unwrap();
    assert_eq!(
        store.delete_inbox_for_sender(&peer, None).unwrap().deleted,
        2
    );
    accept_text(store, fixture, 2, [0xD3; 16], now);
    let sid = fixture.binding.session_id;
    reset::note_confirmed(&store.conn, &store.layout, &sid, &peer, now).unwrap();
    store
        .mark_session_initiated(&fixture.key, &peer, true, true, now)
        .unwrap();
    assert!(store
        .retire_session(
            &second.key,
            &peer,
            SessionRetireCause::PeerNoSession,
            now + 1
        )
        .unwrap());
    store
        .bump_reseal_ledger(&peer, &[0xF0; 16], now + 60_000, now)
        .unwrap();
    store
        .bump_reseal_ledger(&peer, &[0xF1; 16], now + 60_000, now + 1)
        .unwrap();
    store
        .bump_reseal_ledger(&peer, &[0xF0; 16], now + 60_000, now + 2)
        .unwrap();
    store.confirm_peer_reset(&peer, now).unwrap();
    put_end_and_mark(
        store,
        (&[0xCC; 32], (now - HOUR) as i64),
        (&peer, second.created_at_ms as i64),
    );
    // Session renewal (Phase 3 item 4): the contact's round and failure, and
    // another device's kept PairInit, which names both devices and addresses.
    store.note_session_end_seen(&peer, now + 20 * HOUR).unwrap();
    store.begin_repair_attempt(&peer, now).unwrap().unwrap();
    store.finish_renewal_attempt(&peer, false).unwrap();
    let kept = [
        fixture.key.initiator_address.as_bytes(),
        fixture.key.responder_address.as_bytes(),
        &fixture.key.initiator_device_ed25519,
        &fixture.key.responder_device_ed25519,
    ]
    .concat();
    store
        .note_session_end_seen(&[0xCC; 32], now - HOUR)
        .unwrap();
    store
        .set_renewal_pending(&[0xCC; 32], &kept, now + 24 * HOUR)
        .unwrap();
    // The long horizon (Phase 5, P5.4): two parked messages (one written
    // later, parked first) and a message id seen from the contact.
    let deadline = now + 7 * 24 * HOUR;
    store
        .park_outbound(&peer, &[0xA2; 16], None, now - 1, deadline, now)
        .unwrap();
    store
        .park_outbound(
            &peer,
            &[0xA1; 16],
            Some(&second.session_id),
            now - 2,
            deadline - 1,
            now,
        )
        .unwrap();
    store
        .note_inbound_seen(&peer, &[0xD0; 16], now, deadline + 24 * HOUR)
        .unwrap();
    // Letter sessions (Phase 5, P5.12): the second session as one this node
    // started for a letter, its PairInit naming both devices and addresses.
    let mut wire = kept.clone();
    wire.resize(crate::pair_init::INIT_WIRE_LEN, 0x5E);
    store
        .mark_letter_session(&second.key, LetterRole::Initiator, Some(&wire))
        .unwrap();
}

/// What every metadata read of the store answers (the inbox rows opened).
fn observe(store: &mut IndexedSessionStore, dir: &Path, fixture: &EndpointFixture) -> Vec<String> {
    let now = fixture.now_ms;
    let peer = fixture.key.responder_device_ed25519;
    let local = fixture.key.initiator_device_ed25519;
    let second = second_binding(fixture);
    let inbox = |rows: Vec<EndpointInboxRow>| {
        rows.into_iter()
            .map(|r| {
                format!(
                    "{} {} {} {} {} {} {}",
                    hex::encode(r.session_id),
                    hex::encode(r.object_digest),
                    hex::encode(r.message_id),
                    hex::encode(r.sender_device),
                    r.created_at_ms,
                    r.received_at_ms,
                    String::from_utf8_lossy(&r.plaintext)
                )
            })
            .collect::<Vec<_>>()
    };
    let outbound = |rows: Vec<EndpointOutbound>| {
        rows.into_iter()
            .map(|r| {
                format!(
                    "{:?} {} {} {} {} {} {:?} {}",
                    r.kind,
                    hex::encode(r.session_id),
                    hex::encode(r.object_digest),
                    hex::encode(r.message_id),
                    hex::encode(r.recipient_device),
                    r.ratchet_index,
                    r.state,
                    hex::encode(&r.immutable_envelope_bytes)
                )
            })
            .collect::<Vec<_>>()
    };
    let retired = store
        .retired_undelivered_messages_for_recipient(&peer)
        .unwrap();
    assert!(!retired.is_empty(), "the fixture leaves a retired copy");
    let copies: Vec<String> = retired
        .iter()
        .map(|row| {
            format!(
                "{:?}",
                store
                    .message_copies_for_recipient(&peer, &row.message_id)
                    .unwrap()
            )
        })
        .collect();
    let reader = SessionMetadataReader::open(dir).unwrap().unwrap();
    vec![
        format!("{:?}", store.list_record_keys().unwrap()),
        format!(
            "{:?} {:?}",
            store.peer_renewal_state(&peer).unwrap(),
            store.peer_renewal_state(&[0xCC; 32]).unwrap()
        ),
        format!(
            "{:?} {:?} {:?} {:?}",
            store.parked_for_recipient(&peer).unwrap(),
            store.parked_peers().unwrap(),
            store.inbound_seen(&peer, &[0xD0; 16]).unwrap(),
            store.inbound_seen(&peer, &[0xD1; 16]).unwrap()
        ),
        format!(
            "{:?} {:?} {:?}",
            store.letter_session(&second.session_id).unwrap(),
            store.letter_role(&fixture.binding.session_id).unwrap(),
            store
                .live_letter_sessions_for_peer(&peer, LetterRole::Initiator, now)
                .unwrap()
        ),
        format!(
            "{:?}",
            store
                .find_confirmed_sessions_for_peer_at(&peer, now)
                .unwrap()
        ),
        format!(
            "{:?}",
            store
                .find_sendable_sessions_for_peer_at(&peer, now)
                .unwrap()
        ),
        format!("{:?}", store.head_expires_at_ms(&fixture.key).unwrap()),
        format!("{:?}", store.head_expires_at_ms(&second.key).unwrap()),
        format!(
            "{:?}",
            store
                .record_key_for_session_id(&fixture.binding.session_id)
                .unwrap()
        ),
        format!(
            "{:?}",
            store.session_created_at_ms(&second.session_id).unwrap()
        ),
        format!(
            "{:?} {:?}",
            store
                .session_reset_info(&fixture.binding.session_id)
                .unwrap(),
            store.session_reset_info(&second.session_id).unwrap()
        ),
        format!(
            "{:?} {:?}",
            store
                .session_is_retired(&fixture.binding.session_id)
                .unwrap(),
            store.session_is_retired(&second.session_id).unwrap()
        ),
        format!(
            "{:?} {:?} {:?}",
            store.reset_rounds_since(&peer, 0).unwrap(),
            store.reset_rounds_since(&peer, now + 1).unwrap(),
            store.last_reset_round_at(&peer).unwrap()
        ),
        format!("{:?}", store.peer_reset_state(&peer).unwrap()),
        format!(
            "{:?} {:?} {:?}",
            store.reseal_count(&peer, &[0xF0; 16]).unwrap(),
            store.reseal_count(&peer, &[0xF1; 16]).unwrap(),
            store.resealed_message_ids(&peer).unwrap()
        ),
        format!("{:?}", store.live_session_heads(&local, now).unwrap()),
        format!("{:?}", inbox(store.list_endpoint_inbox().unwrap())),
        format!(
            "{:?}",
            inbox(
                store
                    .list_endpoint_inbox_for_sender_after(&peer, &InboxPosition::START, 10)
                    .unwrap()
            )
        ),
        format!("{:?}", outbound(store.pending_endpoint_outbound().unwrap())),
        format!(
            "{:?}",
            outbound(store.awaiting_ack_endpoint_outbound().unwrap())
        ),
        format!("{:?}", outbound(retired)),
        format!("{copies:?}"),
        format!(
            "{:?}",
            store.reseal_target_for_peer(&peer, true, now).unwrap()
        ),
        format!(
            "{:?} {:?}",
            reader.peer_horizon(&peer, now).unwrap(),
            reader.peer_horizon(&[0xCC; 32], now).unwrap()
        ),
    ]
}

/// The plan's populated fixture: a clear store moved by the open of a sealed
/// profile keeps every row of every table under its rowid (the endpoint
/// tables refer to the heads; the reset rows cascade with them), and every
/// read answers as before.
#[test]
fn migration_keeps_every_fk_child_row() {
    let (dir, path) = profile();
    let backend = Arc::new(MemoryProtectedBackend::default());
    let fixture = endpoint_fixture();
    let mut store = open_test_store(&path, Arc::clone(&backend));
    assert!(!store.layout.is_keyed());
    populate(&mut store, &fixture);
    let before = observe(&mut store, dir.path(), &fixture);
    drop(store);
    let rows = table_rows(&path);
    for (table, ids) in &rows {
        assert!(!ids.is_empty(), "{table}: the fixture leaves a row");
    }
    assert_eq!(schema(&path), (sealed::CLEAR_VERSION, Shape::Clear));

    seal_profile(dir.path());
    let mut store = open_test_store(&path, Arc::clone(&backend));
    assert!(store.layout.is_keyed() && store.moved_now);
    assert_eq!(schema(&path), (METADATA_SCHEMA_VERSION, Shape::Keyed));
    assert_eq!(table_rows(&path), rows, "every row, under its rowid");
    assert!(foreign_keys_hold(&path));
    assert!(!rebuild::scrub_pending(&path, sealed::STORE));
    assert_eq!(observe(&mut store, dir.path(), &fixture), before);

    // It goes on working: a message in, a re-seal counted, a prune.
    accept_text(&mut store, &fixture, 3, [0xD4; 16], fixture.now_ms);
    let peer = fixture.key.responder_device_ed25519;
    assert_eq!(
        store
            .bump_reseal_ledger(
                &peer,
                &[0xF0; 16],
                fixture.now_ms + 60_000,
                fixture.now_ms + 3
            )
            .unwrap(),
        3
    );
    assert_eq!(store.list_endpoint_inbox().unwrap().len(), 2);
    drop(store);
    let mut store = open_test_store(&path, backend);
    assert!(!store.moved_now, "moved once");
    assert_eq!(
        store
            .prune_expired_sessions(fixture.binding.expires_at_ms + 2 * 86_400_000)
            .unwrap(),
        2
    );
    assert!(store.list_record_keys().unwrap().is_empty());
}

/// Sessions with one contact created in the same millisecond: both nodes
/// pick them in the same order (`created_at_ms DESC, init_id DESC`), before
/// and after each profile's store moved, though each profile keys the
/// devices with its own key.
#[test]
fn tie_break_is_identical_on_both_nodes_after_migration() {
    let created = 1_700_000_000_000u64;
    // (init_id, created): three at the same instant, one a millisecond later
    // with the smallest init_id, one an hour earlier.
    let sessions: [([u8; 16], u64); 5] = [
        ([0x10; 16], created),
        ([0x90; 16], created),
        ([0x50; 16], created),
        ([0x05; 16], created + 1),
        ([0xF0; 16], created - HOUR),
    ];
    let binding = |init_id: [u8; 16], at: u64, role: LocalRole| {
        let mut binding = fixture_binding();
        binding.key.init_id = init_id;
        binding.init_hash = [init_id[0] ^ 0x5A; 32];
        binding.session_id = session_id(&binding.init_hash);
        binding.created_at_ms = at;
        binding.expires_at_ms = created + 86_400_000;
        binding.local_role = role;
        binding.lifecycle = SessionLifecycle::Confirmed;
        binding.response_hash = Some([0x46; 32]);
        binding
    };
    let now = created + 60_000;
    let alice_device = fixture_binding().key.initiator_device_ed25519;
    let bob_device = fixture_binding().key.responder_device_ed25519;
    let order = |store: &mut IndexedSessionStore, peer: &[u8; 32], local: &[u8; 32]| {
        let picked: Vec<[u8; 16]> = store
            .find_confirmed_sessions_for_peer_at(peer, now)
            .unwrap()
            .into_iter()
            .map(|key| key.init_id)
            .collect();
        let heads: Vec<[u8; 16]> = store
            .live_session_heads(local, now)
            .unwrap()
            .into_iter()
            .map(|head| head.key.init_id)
            .collect();
        assert_eq!(picked, heads, "custody walks the heads in the same order");
        picked
    };
    let expected = vec![[0x05; 16], [0x90; 16], [0x50; 16], [0x10; 16], [0xF0; 16]];
    let mut nodes = Vec::new();
    for role in [LocalRole::Initiator, LocalRole::Responder] {
        let (dir, path) = profile();
        let backend = Arc::new(MemoryProtectedBackend::default());
        let mut store = open_test_store(&path, Arc::clone(&backend));
        for (init_id, at) in sessions {
            store
                .create_session(binding(init_id, at, role), [0xA7; 32])
                .unwrap();
        }
        let (peer, local) = match role {
            LocalRole::Initiator => (bob_device, alice_device),
            LocalRole::Responder => (alice_device, bob_device),
        };
        assert_eq!(order(&mut store, &peer, &local), expected, "schema 1");
        drop(store);
        seal_profile(dir.path());
        nodes.push((dir, path, backend, peer, local));
    }
    let mut keyed = Vec::new();
    for (dir, path, backend, peer, local) in &nodes {
        let mut store = open_test_store(path, Arc::clone(backend));
        assert!(store.layout.is_keyed());
        keyed.push(order(&mut store, peer, local));
        let _ = dir;
    }
    assert_eq!(keyed[0], expected);
    assert_eq!(keyed[1], expected, "both nodes, the same order");
    // The keyed device columns differ between the two profiles (each has
    // its own key): the order never comes from them.
    let column = |path: &Path| -> Vec<u8> {
        Connection::open(path)
            .unwrap()
            .query_row(
                "SELECT kh_initiator_device FROM indexed_session_heads LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap()
    };
    assert_ne!(column(&nodes[0].1), column(&nodes[1].1));
}

/// A journal another instance staged after this open's recovery holds the
/// move back (it replays against the schema it was written under); the next
/// open replays it on schema 1, then moves the store.
#[test]
fn migration_waits_for_pending_journals() {
    let (dir, path) = profile();
    let backend = Arc::new(MemoryProtectedBackend::default());
    let fixture = endpoint_fixture();
    open_test_store(&path, Arc::clone(&backend))
        .create_session(fixture.binding.clone(), fixture.root)
        .unwrap();
    seal_profile(dir.path());
    let mut store =
        sealed::test_switch::without_move(|| open_test_store(&path, Arc::clone(&backend)));
    assert!(!store.layout.is_keyed());
    store.inject_after_recovery_hook({
        let path = path.clone();
        let backend = Arc::clone(&backend);
        move || {
            let fixture = endpoint_fixture();
            let mut other = sealed::test_switch::without_move(|| open_test_store(&path, backend));
            other.inject_endpoint_fault(EndpointFaultPoint::BeforeJournalClear);
            let inbound = inbound_message_envelope(&fixture, 0, [0xE5; 16], b"racing");
            let raced = other.accept_message_envelope(
                &fixture.key,
                &inbound.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            );
            assert!(
                matches!(
                    raced,
                    Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
                ),
                "{raced:?}"
            );
        }
    });
    store.move_to_keyed(dir.path()).unwrap();
    assert!(!store.layout.is_keyed(), "a pending journal holds the move");
    assert_eq!(schema(&path), (sealed::CLEAR_VERSION, Shape::Clear));
    assert!(store.journal_pending().unwrap());
    drop(store);

    let mut store = open_test_store(&path, Arc::clone(&backend));
    assert!(store.layout.is_keyed() && store.moved_now);
    assert!(!store.journal_pending().unwrap());
    let inbox = store.list_endpoint_inbox().unwrap();
    assert_eq!(inbox.len(), 1, "the racing message was committed");
    assert_eq!(inbox[0].plaintext, b"racing");
}

/// A store with no head at all moves too (and a profile's first store is
/// created keyed).
#[test]
fn an_empty_store_moves_and_a_new_one_is_created_keyed() {
    let (dir, path) = profile();
    let backend = Arc::new(MemoryProtectedBackend::default());
    drop(open_test_store(&path, Arc::clone(&backend)));
    seal_profile(dir.path());
    let store = open_test_store(&path, Arc::clone(&backend));
    assert!(store.layout.is_keyed() && store.moved_now);
    assert_eq!(
        rebuild::recorded(&store.conn, sealed::STORE).unwrap(),
        Some((METADATA_SCHEMA_VERSION, false))
    );

    let (dir, path) = profile();
    seal_profile(dir.path());
    let store = open_test_store(&path, backend);
    assert!(store.layout.is_keyed() && !store.moved_now);
    assert_eq!(schema(&path), (METADATA_SCHEMA_VERSION, Shape::Keyed));
    for table in sealed::ALL_TABLES {
        assert!(
            !rebuild::columns(&store.conn, table).unwrap().is_empty(),
            "{table}"
        );
    }
}

/// A clear store and the fixture's reads, checkpointed (its file can be
/// copied whole).
fn populated_template() -> (
    tempfile::TempDir,
    PathBuf,
    Arc<MemoryProtectedBackend>,
    EndpointFixture,
    Vec<String>,
) {
    let (dir, path) = profile();
    let backend = Arc::new(MemoryProtectedBackend::default());
    let fixture = endpoint_fixture();
    let mut store = open_test_store(&path, Arc::clone(&backend));
    populate(&mut store, &fixture);
    let reads = observe(&mut store, dir.path(), &fixture);
    crate::paths::checkpoint_truncate(&store.conn).unwrap();
    drop(store);
    (dir, path, backend, fixture, reads)
}

/// A copy of the template's store in a new sealed profile.
fn sealed_copy(template: &Path) -> (tempfile::TempDir, PathBuf) {
    let (dir, path) = profile();
    std::fs::copy(template, &path).unwrap();
    seal_profile(dir.path());
    (dir, path)
}

/// A stop before any statement of the move (a crash) leaves the store as it
/// was (or moved, once the commit is done): every row is still there, and
/// the next open finishes the move.
#[test]
fn migration_crash_at_each_statement_recovers() {
    let (_template_dir, template, backend, fixture, reads) = populated_template();
    let rows = table_rows(&template);
    let mut stops = 0;
    for at in 0.. {
        let (dir, path) = sealed_copy(&template);
        fault::arm(Fault::CrashAt(at));
        let opened = IndexedSessionStore::open_with_backend(&path, backend.clone());
        if fault::armed() {
            fault::disarm();
            assert!(opened.unwrap().layout.is_keyed(), "past the last stop");
            break;
        }
        stops += 1;
        assert!(
            matches!(opened, Err(IndexedSessionStoreError::MetadataMigration(_))),
            "stop {at}"
        );
        let (version, shape) = schema(&path);
        assert!(
            (version, shape) == (sealed::CLEAR_VERSION, Shape::Clear)
                || (version, shape) == (METADATA_SCHEMA_VERSION, Shape::Keyed),
            "stop {at}: {version} {shape:?}"
        );
        assert_eq!(table_rows(&path), rows, "stop {at}");
        assert!(foreign_keys_hold(&path), "stop {at}");
        let mut store = open_test_store(&path, Arc::clone(&backend));
        assert!(store.layout.is_keyed(), "stop {at}");
        assert_eq!(table_rows(&path), rows, "stop {at}");
        assert_eq!(
            observe(&mut store, dir.path(), &fixture),
            reads,
            "stop {at}"
        );
    }
    assert!(stops > 30, "{stops} stops");
}

/// A count that does not match rolls the move back; too little free space
/// defers it (the store works as it is); a full disk mid-move leaves the old
/// store.
#[test]
fn migration_rolls_back_on_count_mismatch_and_disk_full_and_defers_without_space() {
    let (_template_dir, template, backend, fixture, reads) = populated_template();
    let rows = table_rows(&template);
    for armed in [Fault::DropOneRow, Fault::DiskFull, Fault::NoSpace] {
        let (dir, path) = sealed_copy(&template);
        fault::arm(armed);
        let opened = IndexedSessionStore::open_with_backend(&path, backend.clone());
        assert!(!fault::armed(), "{armed:?} reached");
        match armed {
            Fault::NoSpace => {
                let mut store = opened.unwrap();
                assert!(!store.layout.is_keyed(), "deferred");
                assert_eq!(observe(&mut store, dir.path(), &fixture), reads);
            }
            _ => assert!(opened.is_err(), "{armed:?}"),
        }
        assert_eq!(schema(&path), (sealed::CLEAR_VERSION, Shape::Clear));
        assert_eq!(table_rows(&path), rows);
        let mut store = open_test_store(&path, Arc::clone(&backend));
        assert!(store.layout.is_keyed());
        assert_eq!(observe(&mut store, dir.path(), &fixture), reads);
    }
}

/// `raven privacy unseal` (PP.18): back to schema 1 with every row and the
/// same reads; an older build opens it again. A stop before any statement
/// of the way back leaves the keyed store.
#[test]
fn reverse_migration_round_trip() {
    let (_template_dir, template, backend, fixture, reads) = populated_template();
    let rows = table_rows(&template);
    let (dir, path) = sealed_copy(&template);
    drop(open_test_store(&path, Arc::clone(&backend)));
    let keys = crate::at_rest::keys_cached(dir.path()).unwrap();
    let mut stops = 0;
    for at in 0.. {
        fault::arm(Fault::CrashAt(at));
        let back = sealed::migrate_back(&path, &keys, &|_| None);
        if fault::armed() {
            fault::disarm();
            let back = back.unwrap();
            assert!(!back.already);
            assert_eq!(back.dropped, 0);
            break;
        }
        stops += 1;
        assert!(back.is_err(), "stop {at}");
        let (version, shape) = schema(&path);
        if shape == Shape::Keyed {
            assert_eq!(version, METADATA_SCHEMA_VERSION, "stop {at}");
        } else {
            // Stopped after the commit (before the scrub): it is back.
            assert_eq!(version, sealed::CLEAR_VERSION, "stop {at}");
            break;
        }
        assert_eq!(table_rows(&path), rows, "stop {at}");
    }
    assert!(stops > 20, "{stops} stops");
    assert_eq!(schema(&path), (sealed::CLEAR_VERSION, Shape::Clear));
    assert_eq!(table_rows(&path), rows);
    assert!(foreign_keys_hold(&path));
    // An older build opens it: its version check, its batch, its columns.
    older_open(&path).unwrap();
    let conn = Connection::open(&path).unwrap();
    let address: String = conn
        .query_row(
            "SELECT initiator_address FROM indexed_session_heads LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(address, fixture.key.initiator_address);
    drop(conn);
    // The profile is no longer sealed: this build reads it in clear too.
    crate::privacy::set_mode(dir.path(), Mode::UnsealedByUser).unwrap();
    let mut store = open_test_store(&path, backend);
    assert!(!store.layout.is_keyed());
    assert_eq!(observe(&mut store, dir.path(), &fixture), reads);
}

/// The open of every build before PP.13: its version check (it refuses
/// anything above 1), then its `CREATE ... IF NOT EXISTS` batch.
pub(super) fn older_open(path: &Path) -> Result<(), i64> {
    let conn = Connection::open(path).unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    if version > 1 {
        return Err(version);
    }
    conn.execute_batch(&sealed::create_if_missing(
        sealed::HEADS,
        sealed::heads_columns(false),
    ))
    .unwrap();
    conn.execute_batch(sealed::INIT_ID_INDEX).unwrap();
    conn.execute_batch(ENDPOINT_SCHEMA).unwrap();
    reset::create_reset_schema(&conn).unwrap();
    horizon::create_horizon_schema(&conn).unwrap();
    deleted::create_deleted_schema(&conn).unwrap();
    if version < 1 {
        conn.execute_batch("PRAGMA user_version = 1;").unwrap();
    }
    Ok(())
}

/// An older build refuses the moved store (fail closed: it cannot send or
/// receive); an older process that raced the move and stamped its own
/// number is put right by shape, never moved twice (review R06); the older
/// batch run on a moved store is a no-op (the index names are kept).
#[test]
fn older_builds_refuse_and_a_restamp_never_moves_twice() {
    let (_template_dir, template, backend, fixture, reads) = populated_template();
    let rows = table_rows(&template);
    let (dir, path) = sealed_copy(&template);
    drop(open_test_store(&path, Arc::clone(&backend)));
    assert_eq!(older_open(&path), Err(METADATA_SCHEMA_VERSION));
    // A racing older process read version 1 before the move, then ran its
    // batch and stamped 1 after it.
    let conn = Connection::open(&path).unwrap();
    conn.pragma_update(None, "user_version", 1).unwrap();
    drop(conn);
    older_open(&path).unwrap();
    assert_eq!(schema(&path), (1, Shape::Keyed));
    let mut store = open_test_store(&path, backend);
    assert!(store.layout.is_keyed() && !store.moved_now);
    assert_eq!(schema(&path), (METADATA_SCHEMA_VERSION, Shape::Keyed));
    assert_eq!(table_rows(&path), rows);
    assert_eq!(observe(&mut store, dir.path(), &fixture), reads);
}

/// Without the at-rest key a sealed profile's store does not open, and a
/// new one is not created; the read-only view fails the same way.
#[test]
fn a_sealed_store_without_its_key_fails_closed() {
    let (dir, path) = profile();
    let backend = Arc::new(MemoryProtectedBackend::default());
    seal_profile(dir.path());
    drop(open_test_store(&path, Arc::clone(&backend)));
    crate::at_rest::forget_cached_keys(dir.path());
    assert!(matches!(
        IndexedSessionStore::open_with_backend(&path, backend.clone()),
        Err(IndexedSessionStoreError::MetaKeyUnavailable(_))
    ));
    assert!(matches!(
        SessionMetadataReader::open(dir.path()),
        Err(IndexedSessionStoreError::MetaKeyUnavailable(_))
    ));
    std::fs::remove_file(&path).unwrap();
    assert!(IndexedSessionStore::open_with_backend(&path, backend).is_err());
    assert!(!path.exists(), "nothing created without the key");
}

/// After an exchange (messages and ACKs both ways, a reset round, a
/// removed contact) no rvn1 address, device key, message id, object digest,
/// ACK nonce or session `init_id` of the run is anywhere in the store's
/// file or WAL, as bytes or as hex (PP.14: the endpoint tables too; review
/// B-sealed-stores-1: the heads' `init_id`, which with the clear record key
/// named the friend), after a checkpoint and in the free pages alike. The
/// same check finds every one in a clear store.
#[test]
fn byte_scan_finds_no_address_or_device_key() {
    let fixture = endpoint_fixture();
    let addresses = [
        fixture.key.initiator_address.as_bytes().to_vec(),
        fixture.key.responder_address.as_bytes().to_vec(),
    ];
    let holds = |bytes: &[u8], value: &[u8]| {
        let hex = hex::encode(value);
        bytes.windows(value.len()).any(|w| w == value)
            || bytes
                .windows(hex.len())
                .any(|w| w.eq_ignore_ascii_case(hex.as_bytes()))
    };
    let file_and_wal = |path: &Path| {
        let mut bytes = std::fs::read(path).unwrap();
        bytes.extend(std::fs::read(format!("{}-wal", path.display())).unwrap_or_default());
        bytes
    };
    for sealed_profile in [false, true] {
        let (dir, path) = profile();
        if sealed_profile {
            seal_profile(dir.path());
        }
        let backend = Arc::new(MemoryProtectedBackend::default());
        let mut store = open_test_store(&path, backend);
        assert_eq!(store.layout.endpoints().is_some(), sealed_profile);
        populate(&mut store, &fixture);
        crate::indexed_session_store::forget_session_end(
            dir.path(),
            &fixture.key.responder_device_ed25519,
        )
        .unwrap();
        // What the run named: the devices, and every message id and object
        // digest the store still lists.
        let mut values: Vec<Vec<u8>> = vec![
            fixture.key.initiator_device_ed25519.to_vec(),
            fixture.key.responder_device_ed25519.to_vec(),
            vec![0xCC; 32],
            vec![0xE2; 12],
            fixture.key.init_id.to_vec(),
            second_binding(&fixture).key.init_id.to_vec(),
        ];
        for row in store.list_endpoint_inbox().unwrap() {
            values.extend([row.message_id.to_vec(), row.object_digest.to_vec()]);
        }
        let outbound = [
            store.pending_endpoint_outbound().unwrap(),
            store.awaiting_ack_endpoint_outbound().unwrap(),
        ];
        for row in outbound.into_iter().flatten() {
            values.extend([row.message_id.to_vec(), row.object_digest.to_vec()]);
        }
        assert!(values.len() > 8, "{}", values.len());
        let before_checkpoint = file_and_wal(&path);
        crate::paths::checkpoint_truncate(&store.conn).unwrap();
        let after_checkpoint = file_and_wal(&path);
        for bytes in [&before_checkpoint, &after_checkpoint] {
            for address in &addresses {
                assert_eq!(holds(bytes, address), !sealed_profile, "address");
            }
            for value in &values {
                assert_eq!(
                    holds(bytes, value),
                    !sealed_profile,
                    "{} ({} bytes)",
                    hex::encode(value),
                    value.len()
                );
            }
        }
        drop(store);
    }
}

/// A data-key rotation re-seals every meta of the store before the old
/// epoch goes, and the store reads the same after it.
#[test]
fn rotation_reseals_every_meta_and_the_old_epoch_can_go() {
    let (dir, path) = profile();
    seal_profile(dir.path());
    let backend = Arc::new(MemoryProtectedBackend::default());
    let fixture = endpoint_fixture();
    let mut store = open_test_store(&path, Arc::clone(&backend));
    assert!(store.layout.is_keyed());
    populate(&mut store, &fixture);
    let reads = observe(&mut store, dir.path(), &fixture);
    drop(store);
    let current = crate::at_rest::keys_cached(dir.path())
        .unwrap()
        .current_epoch();
    assert_eq!(rows_off_epoch(dir.path(), current).unwrap(), 0);
    let now = fixture.now_ms + HOUR;
    let started = crate::privacy::rotate_data_key_now(dir.path(), now, false).unwrap();
    assert!(started.started, "{started:?}");
    // Two heads, two reset rows, two ledger rows, the peer state, an end, a mark.
    assert!(started.resealed >= 9, "{started:?}");
    let next = crate::at_rest::keys_cached(dir.path())
        .unwrap()
        .current_epoch();
    assert_ne!(next, current);
    assert_eq!(rows_off_epoch(dir.path(), next).unwrap(), 0);
    assert_eq!(crate::privacy::rotation_state(dir.path()).old_objects, 0);
    let dropped = crate::privacy::rotate_data_key_now(dir.path(), now, true).unwrap();
    assert!(dropped.dropped, "{dropped:?}");
    assert_eq!(
        crate::at_rest::keys_cached(dir.path()).unwrap().epochs(),
        [next]
    );
    let mut store = open_test_store(&path, backend);
    assert_eq!(observe(&mut store, dir.path(), &fixture), reads);
}

/// The sealing pass (`privacy::migrate_all`) moves the store after its
/// lock, through a full open (the profile's own session backend); the prune
/// pass finds nothing more to do.
#[test]
fn the_sealing_pass_moves_the_store() {
    let (dir, path) = profile();
    let backend = Arc::new(LockedFileSessionBackend::new(dir.path()).unwrap());
    let fixture = endpoint_fixture();
    let mut store = IndexedSessionStore::open_with_backend(&path, backend.clone()).unwrap();
    store
        .create_session(fixture.binding.clone(), fixture.root)
        .unwrap();
    drop(store);
    assert!(needs_migration(dir.path()));
    crate::contact_book::tests::seal(dir.path());
    assert!(!needs_migration(dir.path()));
    assert_eq!(schema(&path), (METADATA_SCHEMA_VERSION, Shape::Keyed));
    let report = crate::privacy::upkeep_stores(dir.path());
    assert_eq!(report.migrated, 0, "{report}");
    let mut store = IndexedSessionStore::open_with_backend(&path, backend).unwrap();
    assert_eq!(
        store
            .find_confirmed_sessions_for_peer_at(
                &fixture.key.responder_device_ed25519,
                fixture.now_ms
            )
            .unwrap(),
        vec![fixture.key.clone()]
    );
}

/// The schema guard: in a sealed profile, no column of a fresh store of any
/// kind (sessions, owed ACKs, the app store, friend custody, custody
/// handoff, the security ledger) that names a
/// key, an address, a peer, a message id, a digest or a nonce is clear,
/// unless the list below says why. Friend custody's objects and released
/// digests are keyed since PP.17. A table a later phase adds (renewal,
/// horizon, Phase 5's custody letters and handoff tables, the security
/// ledger) has to follow the rule or say why here.
#[test]
fn no_clear_key_address_or_message_id_columns() {
    const NAMES: [&str; 10] = [
        "address",
        "device",
        "peer",
        "sender",
        "recipient",
        "depositor",
        "custodian",
        "message_id",
        "digest",
        "nonce",
    ];
    // (store, table, column, why it stays clear)
    const CLEAR_ON_PURPOSE: &[(&str, &str, &str, &str)] = &[
        (
            "sessions",
            "indexed_session_heads",
            "binding_digest",
            "R20: random, binds the protected state",
        ),
        (
            "app",
            "app_inbox",
            "message_id",
            "random, on the wire (design section 7.2, open item)",
        ),
        (
            "app",
            "app_tombstones",
            "message_id",
            "random, on the wire (design section 7.2, open item)",
        ),
        (
            "app",
            "app_quarantine",
            "message_id",
            "random, on the wire (design section 7.2, open item)",
        ),
        (
            "app",
            "app_outbox",
            "peer_identity",
            "open item, PP.20 (gated off)",
        ),
        (
            "app",
            "app_outbox",
            "peer_device",
            "open item, PP.20 (gated off)",
        ),
        (
            "app",
            "app_outbox",
            "message_id",
            "open item, PP.20 (gated off)",
        ),
        (
            "app",
            "app_outbox",
            "object_digest",
            "open item, PP.20 (gated off)",
        ),
        (
            "app",
            "app_pair_attempts",
            "peer_device",
            "open item, PP.20 (gated off)",
        ),
    ];
    let (dir, path) = profile();
    let dd = dir.path();
    seal_profile(dd);
    drop(open_test_store(
        &path,
        Arc::new(MemoryProtectedBackend::default()),
    ));
    drop(crate::owed_acks::OwedAcks::open(dd).unwrap());
    drop(crate::app_store::AppStore::open(dd, &crate::app_store::MetadataOnly).unwrap());
    drop(crate::friend_custody::CustodyStore::open_or_create(dd).unwrap());
    drop(crate::custody_handoff::HandoffStore::open_or_create(dd).unwrap());
    let mut stores = vec![
        ("sessions", path),
        ("owed_acks", crate::owed_acks::owed_acks_path(dd)),
        ("app", crate::app_store::app_store_path(dd)),
        ("custody", crate::friend_custody::custody_db_path(dd)),
        ("handoff", crate::custody_handoff::handoff_db_path(dd)),
    ];
    // The security ledger (Phase 6b P6.23) exists only while security events
    // are live: a debug build opens the gate for this thread.
    use crate::security_gate::{live, set_lab_for_this_thread, SecGate};
    set_lab_for_this_thread(SecGate::Events, Some(true));
    if live(SecGate::Events) {
        drop(crate::security_ledger::SecurityLedger::open(dd).unwrap());
        stores.push(("security", crate::security_ledger::ledger_path(dd)));
    }
    set_lab_for_this_thread(SecGate::Events, None);
    let mut found = Vec::new();
    let mut allowed_seen = 0;
    for (store, path) in &stores {
        let conn = Connection::open(path).unwrap();
        let tables: Vec<String> = {
            let mut statement = conn
                .prepare(
                    "SELECT name FROM sqlite_master WHERE type = 'table'
                     AND name NOT LIKE 'sqlite_%' ORDER BY name",
                )
                .unwrap();
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap();
            rows.collect::<Result<_, _>>().unwrap()
        };
        assert!(!tables.is_empty(), "{store}");
        for table in tables {
            for column in rebuild::columns(&conn, &table).unwrap() {
                let lower = column.to_ascii_lowercase();
                if lower.starts_with("kh_") || !NAMES.iter().any(|name| lower.contains(name)) {
                    continue;
                }
                if CLEAR_ON_PURPOSE
                    .iter()
                    .any(|(s, t, c, _)| s == store && *t == table && *c == column)
                {
                    allowed_seen += 1;
                    continue;
                }
                found.push(format!("{store}.{table}.{column}"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "clear columns that name someone: {found:?}"
    );
    assert_eq!(
        allowed_seen,
        CLEAR_ON_PURPOSE.len(),
        "every allowance names a column that exists"
    );
}

/// The time sealing adds (`cargo test --release -- --ignored`): the
/// metadata reads every send and poll makes, on a clear and on a keyed
/// store with the same sessions. Prints the ratio; bounds the added time
/// per head read.
#[test]
#[ignore]
fn timing_within_ten_percent() {
    const SESSIONS: usize = 40;
    const ROUNDS: usize = 200;
    let fixture = endpoint_fixture();
    let peer = fixture.key.responder_device_ed25519;
    let mut times = Vec::new();
    for sealed_profile in [false, true] {
        let (dir, path) = profile();
        if sealed_profile {
            seal_profile(dir.path());
        }
        let backend = Arc::new(MemoryProtectedBackend::default());
        let mut store = open_test_store(&path, backend);
        for n in 0..SESSIONS {
            let mut binding = fixture.binding.clone();
            binding.key.init_id = [n as u8 + 1; 16];
            binding.init_hash = [n as u8 + 0x40; 32];
            binding.session_id = session_id(&binding.init_hash);
            store.create_session(binding, fixture.root).unwrap();
        }
        let started = std::time::Instant::now();
        for _ in 0..ROUNDS {
            assert_eq!(
                store
                    .find_confirmed_sessions_for_peer_at(&peer, fixture.now_ms)
                    .unwrap()
                    .len(),
                SESSIONS
            );
            assert_eq!(store.list_record_keys().unwrap().len(), SESSIONS);
        }
        times.push(started.elapsed());
    }
    let ratio = times[1].as_secs_f64() / times[0].as_secs_f64();
    let added_per_head =
        times[1].saturating_sub(times[0]).as_secs_f64() * 1e6 / (ROUNDS * SESSIONS * 2) as f64;
    println!(
        "clear {:?}, keyed {:?}: {ratio:.2}x, {added_per_head:.1} µs added per head read",
        times[0], times[1]
    );
    assert!(
        added_per_head < 60.0,
        "{added_per_head:.1} µs per head read"
    );
}

// ── PP.14: the endpoint tables ───────────────────────────────────────────

fn endpoints_keyed(path: &Path) -> bool {
    endpoints::keyed(&Connection::open(path).unwrap()).unwrap()
}

/// The template's store in a new sealed profile, moved to schema 2 as a
/// PP.13 build moved it (its endpoint tables clear).
fn schema_2_copy(template: &Path) -> (tempfile::TempDir, PathBuf) {
    let (dir, path) = sealed_copy(template);
    let keys = crate::at_rest::keys_cached(dir.path()).unwrap();
    sealed::migrate_to_schema_2(&path, &keys).unwrap();
    assert_eq!(schema(&path), (sealed::HEADS_VERSION, Shape::Keyed));
    assert!(!endpoints_keyed(&path));
    (dir, path)
}

/// A PP.13 build's sealed store (schema 2) works as it is while its move is
/// held back, then moves to schema 3 at its open with every row of every
/// table under its rowid, and every read answers as before.
#[test]
fn a_schema_2_store_moves_to_3_with_every_row() {
    let (_template_dir, template, backend, fixture, reads) = populated_template();
    let rows = table_rows(&template);
    let (dir, path) = schema_2_copy(&template);
    let mut store =
        sealed::test_switch::without_move(|| open_test_store(&path, Arc::clone(&backend)));
    assert!(store.layout.is_keyed() && store.layout.endpoints().is_none());
    assert_eq!(store.inbox_order(), InboxOrder::Received);
    assert_eq!(observe(&mut store, dir.path(), &fixture), reads);
    drop(store);
    assert!(needs_migration(dir.path()));

    let mut store = open_test_store(&path, Arc::clone(&backend));
    assert!(store.layout.endpoints().is_some() && store.moved_now);
    assert_eq!(store.inbox_order(), InboxOrder::Seq);
    assert_eq!(schema(&path), (METADATA_SCHEMA_VERSION, Shape::Keyed));
    assert!(endpoints_keyed(&path));
    assert_eq!(table_rows(&path), rows, "every row, under its rowid");
    assert!(foreign_keys_hold(&path));
    assert_eq!(observe(&mut store, dir.path(), &fixture), reads);
    assert!(!needs_migration(dir.path()));
}

/// A stop before any statement of the 2 -> 3 move leaves the schema-2 store
/// (or the moved one, once committed) with every row; the next open moves it.
#[test]
fn migration_from_schema_2_crash_at_each_statement_recovers() {
    let (_template_dir, template, backend, fixture, reads) = populated_template();
    let rows = table_rows(&template);
    let mut stops = 0;
    for at in 0.. {
        let (dir, path) = schema_2_copy(&template);
        fault::arm(Fault::CrashAt(at));
        let opened = IndexedSessionStore::open_with_backend(&path, backend.clone());
        if fault::armed() {
            fault::disarm();
            assert!(
                opened.unwrap().layout.endpoints().is_some(),
                "past the last stop"
            );
            break;
        }
        stops += 1;
        assert!(
            matches!(opened, Err(IndexedSessionStoreError::MetadataMigration(_))),
            "stop {at}"
        );
        let state = (schema(&path), endpoints_keyed(&path));
        assert!(
            state == ((sealed::HEADS_VERSION, Shape::Keyed), false)
                || state == ((METADATA_SCHEMA_VERSION, Shape::Keyed), true),
            "stop {at}: {state:?}"
        );
        assert_eq!(table_rows(&path), rows, "stop {at}");
        assert!(foreign_keys_hold(&path), "stop {at}");
        let mut store = open_test_store(&path, Arc::clone(&backend));
        assert!(store.layout.endpoints().is_some(), "stop {at}");
        assert_eq!(
            observe(&mut store, dir.path(), &fixture),
            reads,
            "stop {at}"
        );
    }
    assert!(stops > 20, "{stops} stops");
}

// ── Review B-sealed-stores-1: schema 4, the heads' `init_id` keyed ──────

fn init_keyed(path: &Path) -> bool {
    sealed::init_keyed(&Connection::open(path).unwrap()).unwrap()
}

/// The template's store in a new sealed profile, moved to schema 3 as the
/// pack's builds before review B-sealed-stores-1 moved it (the endpoint
/// tables keyed, the heads' `init_id` clear).
fn schema_3_copy(template: &Path) -> (tempfile::TempDir, PathBuf) {
    let (dir, path) = sealed_copy(template);
    let keys = crate::at_rest::keys_cached(dir.path()).unwrap();
    sealed::migrate_to_schema_3(&path, &keys).unwrap();
    assert_eq!(schema(&path), (sealed::ENDPOINTS_VERSION, Shape::Keyed));
    assert!(endpoints_keyed(&path) && !init_keyed(&path));
    (dir, path)
}

/// The two sessions' `init_id`s, raw or hex, anywhere in the store's file
/// or WAL.
fn holds_an_init_id(path: &Path, fixture: &EndpointFixture) -> bool {
    let mut bytes = std::fs::read(path).unwrap();
    bytes.extend(std::fs::read(format!("{}-wal", path.display())).unwrap_or_default());
    [fixture.key.init_id, second_binding(fixture).key.init_id]
        .iter()
        .any(|init_id| {
            let hex = hex::encode(init_id);
            bytes.windows(16).any(|w| w == init_id)
                || bytes
                    .windows(hex.len())
                    .any(|w| w.eq_ignore_ascii_case(hex.as_bytes()))
        })
}

/// A sealed store of the pack's earlier builds (schema 3: its heads'
/// `init_id` clear, which with the clear record key names the friend) works
/// as it is while its move is held back, then moves to schema 4 at its open
/// with every row of every table under its rowid and every read answering
/// as before; the `init_id`s then leave the file (the scrub), and an older
/// build refuses it. A fresh sealed store is at schema 4 from its creation.
#[test]
fn a_schema_3_store_moves_to_4_and_its_init_ids_leave_the_file() {
    let (_template_dir, template, backend, fixture, reads) = populated_template();
    let rows = table_rows(&template);
    let (dir, path) = schema_3_copy(&template);
    assert!(
        holds_an_init_id(&path, &fixture),
        "the control: clear in schema 3"
    );
    let mut store =
        sealed::test_switch::without_move(|| open_test_store(&path, Arc::clone(&backend)));
    assert!(store.layout.endpoints().is_some() && !store.layout.is_current());
    assert_eq!(observe(&mut store, dir.path(), &fixture), reads);
    drop(store);
    assert!(needs_migration(dir.path()));

    let mut store = open_test_store(&path, Arc::clone(&backend));
    assert!(store.layout.is_current() && store.moved_now);
    assert_eq!(schema(&path), (METADATA_SCHEMA_VERSION, Shape::Keyed));
    assert!(init_keyed(&path));
    assert!(!rebuild::columns(&store.conn, sealed::HEADS)
        .unwrap()
        .iter()
        .any(|column| column == "init_id"));
    assert_eq!(table_rows(&path), rows, "every row, under its rowid");
    assert!(foreign_keys_hold(&path));
    assert!(!rebuild::scrub_pending(&path, sealed::STORE));
    assert_eq!(observe(&mut store, dir.path(), &fixture), reads);
    assert!(!needs_migration(dir.path()));
    drop(store);
    assert!(!holds_an_init_id(&path, &fixture));
    assert_eq!(older_open(&path), Err(METADATA_SCHEMA_VERSION));

    let (dir, path) = profile();
    seal_profile(dir.path());
    let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
    assert!(store.layout.is_current() && !store.moved_now);
    populate(&mut store, &fixture);
    drop(store);
    assert!(init_keyed(&path));
    assert!(!holds_an_init_id(&path, &fixture));
}

/// A stop before any statement of the 3 -> 4 move leaves the schema-3 store
/// (or the moved one, once committed) with every row; the next open moves
/// it.
#[test]
fn migration_from_schema_3_crash_at_each_statement_recovers() {
    let (_template_dir, template, backend, fixture, reads) = populated_template();
    let rows = table_rows(&template);
    let mut stops = 0;
    for at in 0.. {
        let (dir, path) = schema_3_copy(&template);
        fault::arm(Fault::CrashAt(at));
        let opened = IndexedSessionStore::open_with_backend(&path, backend.clone());
        if fault::armed() {
            fault::disarm();
            assert!(opened.unwrap().layout.is_current(), "past the last stop");
            break;
        }
        stops += 1;
        assert!(
            matches!(opened, Err(IndexedSessionStoreError::MetadataMigration(_))),
            "stop {at}"
        );
        let state = (schema(&path), init_keyed(&path));
        assert!(
            state == ((sealed::ENDPOINTS_VERSION, Shape::Keyed), false)
                || state == ((METADATA_SCHEMA_VERSION, Shape::Keyed), true),
            "stop {at}: {state:?}"
        );
        assert_eq!(table_rows(&path), rows, "stop {at}");
        assert!(foreign_keys_hold(&path), "stop {at}");
        let mut store = open_test_store(&path, Arc::clone(&backend));
        assert!(store.layout.is_current(), "stop {at}");
        assert_eq!(
            observe(&mut store, dir.path(), &fixture),
            reads,
            "stop {at}"
        );
    }
    assert!(stops > 5, "{stops} stops");
}

/// The queries that compared stored wire bytes compare their keyed digests
/// in schema 3 (review R20): a handoff marks the exact envelope it handed
/// over, the ACK intent whose bytes it carries goes with it, a second
/// materialization with other bytes is refused. The bytes themselves are
/// sealed (never in clear, never twice the same).
#[test]
fn blob_equality_queries_still_match_after_sealing() {
    let (dir, path) = profile();
    seal_profile(dir.path());
    let backend = Arc::new(MemoryProtectedBackend::default());
    let fixture = endpoint_fixture();
    let local_device = authorized_local_device(&fixture);
    let now = fixture.now_ms;
    let mut store = open_test_store(&path, Arc::clone(&backend));
    assert!(store.layout.endpoints().is_some());
    store
        .create_session(fixture.binding.clone(), fixture.root)
        .unwrap();
    let mut rng = StdRng::from_seed([0x5B; 32]);
    let mut refuse = |_: &[u8; 32], _: &[u8]| Err(());
    let mut accept = |digest: &[u8; 32], _: &[u8]| Ok(*digest);

    // A message whose first handoff fails stays prepared; the retry hands
    // over the same bytes and marks exactly them.
    assert!(store
        .send_message_envelope(
            &fixture.key,
            "blob",
            &local_device,
            now,
            now + 60_000,
            now,
            &mut rng,
            &mut refuse,
        )
        .is_err());
    let prepared = store.pending_endpoint_outbound().unwrap();
    assert_eq!(prepared.len(), 1);
    let message = &prepared[0];
    let queued = store
        .retry_endpoint_outbound(
            &fixture.key,
            &message.object_digest,
            &local_device,
            now,
            &mut accept,
        )
        .unwrap();
    assert_eq!(queued.state, EndpointOutboxState::Queued);
    assert_eq!(
        queued.immutable_envelope_bytes,
        message.immutable_envelope_bytes
    );
    assert!(store.pending_endpoint_outbound().unwrap().is_empty());

    // An ACK: its bytes are set once on the intent (kh_ack), the failed
    // handoff keeps both prepared, the second call hands over the same bytes
    // and the intent goes queued with its outbox row.
    let intent = accept_text(&mut store, &fixture, 0, [0xB0; 16], now);
    assert!(store
        .enqueue_committed_ack(
            &fixture.key,
            &intent,
            &local_device,
            now,
            now + 60_000,
            now,
            &mut rng,
            &mut refuse,
        )
        .is_err());
    let pending = store.pending_endpoint_ack_intents().unwrap();
    assert_eq!(pending.len(), 1);
    let ack_bytes = pending[0]
        .immutable_ack_bytes
        .clone()
        .expect("materialized");
    let ack = store
        .enqueue_committed_ack(
            &fixture.key,
            &intent,
            &local_device,
            now,
            now + 60_000,
            now,
            &mut rng,
            &mut accept,
        )
        .unwrap();
    assert_eq!(ack.state, EndpointOutboxState::Queued);
    assert_eq!(ack.immutable_envelope_bytes, ack_bytes, "the same ACK");
    assert!(store.pending_endpoint_ack_intents().unwrap().is_empty());

    // The test-build enqueue: the same bytes again are fine, others are not.
    let second = accept_text(&mut store, &fixture, 1, [0xB1; 16], now);
    let sid = fixture.binding.session_id;
    let bytes = vec![0xAC; 120];
    store
        .enqueue_endpoint_ack(&sid, &second, &bytes, |_| Ok(()))
        .unwrap();
    store
        .enqueue_endpoint_ack(&sid, &second, &bytes, |_| Ok(()))
        .unwrap();
    assert!(matches!(
        store.enqueue_endpoint_ack(&sid, &second, &[0xAD; 120], |_| Ok(())),
        Err(IndexedSessionStoreError::AckBytesConflict)
    ));

    // On disk: sealed, never the clear bytes, digests equal to the keyed
    // digest of the exact bytes.
    let sealer = store.layout.endpoints().unwrap();
    let raw: Vec<(Vec<u8>, Vec<u8>)> = {
        let mut statement = store
            .conn
            .prepare("SELECT immutable_envelope_bytes, kh_envelope FROM endpoint_outbox")
            .unwrap();
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap();
        rows.collect::<Result<_, _>>().unwrap()
    };
    assert_eq!(raw.len(), 2);
    for (stored, digest) in &raw {
        assert!(!stored
            .windows(32)
            .any(|w| message.immutable_envelope_bytes.windows(32).any(|c| c == w)));
        assert!(
            digest.as_slice() == sealer.object_bytes(&message.immutable_envelope_bytes)
                || digest.as_slice() == sealer.object_bytes(&ack_bytes)
        );
    }
    assert_ne!(
        sealer.seal_bytes(endpoints::ENVELOPE_LABEL, b"k", &ack_bytes),
        sealer.seal_bytes(endpoints::ENVELOPE_LABEL, b"k", &ack_bytes),
        "a random nonce each time: equality needs the keyed digest"
    );
    let stored_ack: Vec<u8> = store
        .conn
        .query_row(
            "SELECT immutable_ack_bytes FROM endpoint_ack_intents WHERE kh_ack = ?1",
            params![sealer.object_bytes(&bytes).as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!stored_ack
        .windows(bytes.len())
        .any(|w| w == bytes.as_slice()));
}

/// Every query that lists by rowid (the prepared and the waiting messages,
/// the ACK intents, the first copy of an object to a contact) answers in the
/// same order after the move: the rebuild keeps the rowids.
#[test]
fn rowid_order_preserved() {
    let (dir, path) = profile();
    let backend = Arc::new(MemoryProtectedBackend::default());
    let fixture = endpoint_fixture();
    let local_device = authorized_local_device(&fixture);
    let now = fixture.now_ms;
    let peer = fixture.key.responder_device_ed25519;
    let mut store = open_test_store(&path, Arc::clone(&backend));
    store
        .create_session(fixture.binding.clone(), fixture.root)
        .unwrap();
    let second = second_binding(&fixture);
    store.create_session(second.clone(), fixture.root).unwrap();
    let mut rng = StdRng::from_seed([0x70; 32]);
    let mut accept = |digest: &[u8; 32], _: &[u8]| Ok(*digest);
    let mut refuse = |_: &[u8; 32], _: &[u8]| Err(());
    // Waiting for their ACKs, interleaved across the two sessions.
    for n in 0..6 {
        let key = if n % 2 == 0 {
            &fixture.key
        } else {
            &second.key
        };
        store
            .send_message_envelope(
                key,
                &format!("waiting {n}"),
                &local_device,
                now,
                now + 60_000,
                now,
                &mut rng,
                &mut accept,
            )
            .unwrap();
    }
    // One prepared message in each session, the second session's first.
    for key in [&second.key, &fixture.key] {
        let _ = store.send_message_envelope(
            key,
            "prepared",
            &local_device,
            now,
            now + 60_000,
            now,
            &mut rng,
            &mut refuse,
        );
    }
    for n in 0..4u8 {
        accept_text(&mut store, &fixture, u32::from(n), [0x90 + n; 16], now);
    }
    let reads = |store: &mut IndexedSessionStore| {
        let digests = |rows: Vec<EndpointOutbound>| {
            rows.into_iter()
                .map(|r| (r.session_id, r.object_digest, r.state))
                .collect::<Vec<_>>()
        };
        let waiting = store.awaiting_ack_endpoint_outbound().unwrap();
        let firsts: Vec<_> = waiting
            .iter()
            .map(|row| {
                store
                    .outbound_by_digest_for_recipient(&row.object_digest, &peer)
                    .unwrap()
                    .map(|(row, delivery)| (row.session_id, delivery))
            })
            .collect();
        (
            digests(store.pending_endpoint_outbound().unwrap()),
            digests(
                store
                    .pending_endpoint_outbound_for_recipient(Some(&peer))
                    .unwrap(),
            ),
            digests(waiting),
            digests(
                store
                    .awaiting_ack_endpoint_outbound_for_recipient(Some(&peer))
                    .unwrap(),
            ),
            store
                .pending_endpoint_ack_intents()
                .unwrap()
                .into_iter()
                .map(|i| (i.object_digest, i.message_id))
                .collect::<Vec<_>>(),
            firsts,
        )
    };
    let before = reads(&mut store);
    assert_eq!(before.0.len(), 2);
    assert_eq!(before.2.len(), 6);
    assert_eq!(before.4.len(), 4);
    drop(store);
    let rows = table_rows(&path);
    seal_profile(dir.path());
    let mut store = open_test_store(&path, backend);
    assert!(store.layout.endpoints().is_some() && store.moved_now);
    assert_eq!(table_rows(&path), rows);
    assert_eq!(reads(&mut store), before);
}

/// An acceptance journal staged on a schema-3 store replays there: the
/// replay compares the sealed local row's bytes exactly, with the values
/// its AAD binds taken from `meta`. The rows the move carried keep their
/// sealed local rows byte for byte (they are under the session's key, never
/// sealed again).
#[test]
fn journal_replay_after_migration_matches_sealed_inbox_bytes() {
    let (dir, path) = profile();
    let backend = Arc::new(MemoryProtectedBackend::default());
    let fixture = endpoint_fixture();
    let now = fixture.now_ms;
    let mut store = open_test_store(&path, Arc::clone(&backend));
    store
        .create_session(fixture.binding.clone(), fixture.root)
        .unwrap();
    let first = accept_text(&mut store, &fixture, 0, [0xC0; 16], now);
    let clear_bytes: Vec<u8> = store
        .conn
        .query_row(
            "SELECT sealed_local_row FROM endpoint_inbox WHERE object_digest = ?1",
            params![first.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    drop(store);
    seal_profile(dir.path());
    let mut store = open_test_store(&path, Arc::clone(&backend));
    assert!(store.layout.endpoints().is_some());
    let kd = store.layout.ep_digest(&first);
    let moved_bytes: Vec<u8> = store
        .conn
        .query_row(
            "SELECT sealed_local_row FROM endpoint_inbox WHERE kh_object_digest = ?1",
            params![kd],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(moved_bytes, clear_bytes, "not sealed again");

    // Committed, then the process stops before it clears its journal.
    store.inject_endpoint_fault(EndpointFaultPoint::BeforeJournalClear);
    let inbound = inbound_message_envelope(&fixture, 1, [0xC1; 16], b"replayed");
    assert!(matches!(
        store.accept_message_envelope(
            &fixture.key,
            &inbound.pack(),
            &fixture.remote_certificate,
            false,
            now,
        ),
        Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
    ));
    assert!(store.journal_pending().unwrap());
    drop(store);
    let mut store = open_test_store(&path, Arc::clone(&backend));
    assert!(!store.journal_pending().unwrap(), "replayed and cleared");
    let listed = store.list_endpoint_inbox().unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|r| r.plaintext.clone())
            .collect::<Vec<_>>(),
        vec![b"listed".to_vec(), b"replayed".to_vec()]
    );
    assert!(listed.iter().all(|r| r.position.order == InboxOrder::Seq));
    // The same envelope again is the committed object.
    assert!(matches!(
        store
            .accept_message_envelope(
                &fixture.key,
                &inbound.pack(),
                &fixture.remote_certificate,
                false,
                now,
            )
            .unwrap(),
        EndpointAcceptance::Duplicate { .. }
    ));
}

/// A cursor saved before the move (format 1: the clear order's
/// `(received_at_ms, message_id)`, at a row, before a stamp, at a deleted
/// row, at the start, past every row) is placed at the `seq` that lists
/// exactly the same rows after it; a chat that goes on from there shows
/// every later row once and none twice.
#[test]
fn cursor_v1_maps_to_seq_and_nothing_is_shown_twice() {
    let (dir, path) = profile();
    let backend = Arc::new(MemoryProtectedBackend::default());
    let fixture = endpoint_fixture();
    let now = fixture.now_ms;
    let peer = fixture.key.responder_device_ed25519;
    let mut store = open_test_store(&path, Arc::clone(&backend));
    store
        .create_session(fixture.binding.clone(), fixture.root)
        .unwrap();
    for n in 0..5u8 {
        accept_text(&mut store, &fixture, u32::from(n), [0xA0 + n; 16], now);
    }
    let all = store
        .list_endpoint_inbox_for_sender_after(&peer, &InboxPosition::START, 10)
        .unwrap();
    assert_eq!(all.len(), 5);
    assert!(all.iter().all(|r| r.position.order == InboxOrder::Received));
    // Rows 0 and 1 deleted by the user, up to row 1.
    let deleted_at = all[1].position;
    assert_eq!(
        store
            .delete_inbox_for_sender(&peer, Some(&deleted_at))
            .unwrap()
            .deleted,
        2
    );
    let ids =
        |rows: Vec<EndpointInboxRow>| rows.iter().map(|r| r.message_id[0]).collect::<Vec<_>>();
    let cursors = [
        (all[2].position, vec![0xA3, 0xA4]),
        (
            InboxPosition::received(all[3].received_at_ms, None),
            vec![0xA3, 0xA4],
        ),
        (deleted_at, vec![0xA2, 0xA3, 0xA4]),
        (InboxPosition::START, vec![0xA2, 0xA3, 0xA4]),
        (InboxPosition::received(now + 1_000_000, None), vec![]),
    ];
    for (cursor, expected) in &cursors {
        let rows = store
            .list_endpoint_inbox_for_sender_after(&peer, cursor, 10)
            .unwrap();
        assert_eq!(&ids(rows), expected, "clear {cursor:?}");
    }
    drop(store);
    seal_profile(dir.path());
    let mut store = open_test_store(&path, Arc::clone(&backend));
    assert_eq!(store.inbox_order(), InboxOrder::Seq);
    for (cursor, expected) in &cursors {
        let placed = store.resolve_inbox_position(&peer, cursor).unwrap();
        assert_eq!(placed.order, InboxOrder::Seq, "{cursor:?}");
        for after in [*cursor, placed] {
            let rows = store
                .list_endpoint_inbox_for_sender_after(&peer, &after, 10)
                .unwrap();
            assert_eq!(&ids(rows), expected, "keyed {after:?}");
        }
        // Placing twice is placing once.
        assert_eq!(
            store.resolve_inbox_position(&peer, &placed).unwrap(),
            placed
        );
    }
    // The chat goes on from the cursor at row 2.
    let mut cursor = store.resolve_inbox_position(&peer, &cursors[0].0).unwrap();
    accept_text(&mut store, &fixture, 5, [0xA5; 16], now);
    let mut shown = Vec::new();
    loop {
        let rows = store
            .list_endpoint_inbox_for_sender_after(&peer, &cursor, 2)
            .unwrap();
        if rows.is_empty() {
            break;
        }
        for row in rows {
            shown.push(row.message_id[0]);
            cursor = row.position;
        }
    }
    assert_eq!(shown, vec![0xA3, 0xA4, 0xA5], "every later row, once");
    accept_text(&mut store, &fixture, 6, [0xA6; 16], now);
    assert_eq!(
        ids(store
            .list_endpoint_inbox_for_sender_after(&peer, &cursor, 10)
            .unwrap()),
        vec![0xA6]
    );
}

/// A chat cleared before the move stays cleared after it: the tombstones
/// move (keyed), its cursor lists nothing, a re-delivered copy is a
/// duplicate shown nowhere, and a new message lists once with a stamp above
/// the cleared rows' even when the clock has not moved.
#[test]
fn a_cleared_chat_stays_cleared_across_the_migration() {
    let (dir, path) = profile();
    let backend = Arc::new(MemoryProtectedBackend::default());
    let fixture = endpoint_fixture();
    let now = fixture.now_ms;
    let peer = fixture.key.responder_device_ed25519;
    let sid = fixture.binding.session_id;
    let mut store = open_test_store(&path, Arc::clone(&backend));
    store
        .create_session(fixture.binding.clone(), fixture.root)
        .unwrap();
    let mut digests = Vec::new();
    for n in 0..3u8 {
        digests.push(accept_text(
            &mut store,
            &fixture,
            u32::from(n),
            [0xE0 + n; 16],
            now,
        ));
    }
    let rows = store
        .list_endpoint_inbox_for_sender_after(&peer, &InboxPosition::START, 10)
        .unwrap();
    let tombstone = rows.last().unwrap().position;
    let newest_cleared = rows.last().unwrap().received_at_ms;
    assert_eq!(
        store
            .delete_inbox_for_sender(&peer, Some(&tombstone))
            .unwrap()
            .deleted,
        3
    );
    drop(store);
    seal_profile(dir.path());
    let mut store = open_test_store(&path, Arc::clone(&backend));
    assert!(store.layout.endpoints().is_some());
    let marks: i64 = store
        .conn
        .query_row(
            "SELECT COUNT(*) FROM endpoint_inbox_deleted WHERE kh_sender_device = ?1",
            params![store.layout.ep_device(&peer)],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marks, 3);
    let cursor = store.resolve_inbox_position(&peer, &tombstone).unwrap();
    assert!(store
        .list_endpoint_inbox_for_sender_after(&peer, &cursor, 10)
        .unwrap()
        .is_empty());
    assert!(store.inbox_row_deleted(&sid, &digests[1]).unwrap());
    let again = inbound_message_envelope(&fixture, 1, [0xE1; 16], b"listed");
    assert!(matches!(
        store
            .accept_message_envelope(
                &fixture.key,
                &again.pack(),
                &fixture.remote_certificate,
                false,
                now,
            )
            .unwrap(),
        EndpointAcceptance::Duplicate { .. }
    ));
    assert!(store.list_endpoint_inbox().unwrap().is_empty());
    // A new message at the clock the cleared rows had: stamped above them
    // (their tombstones keep the floor).
    accept_text(&mut store, &fixture, 3, [0xE3; 16], now);
    let listed = store
        .list_endpoint_inbox_for_sender_after(&peer, &cursor, 10)
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].message_id, [0xE3; 16]);
    assert!(listed[0].received_at_ms > newest_cleared);
}

/// A message whose ACK was lost, delivered again after the move, is the
/// same committed object, and its ACK is the same immutable ACK.
#[test]
fn duplicate_after_migration_gets_the_same_ack() {
    let (dir, path) = profile();
    let backend = Arc::new(MemoryProtectedBackend::default());
    let fixture = endpoint_fixture();
    let local_device = authorized_local_device(&fixture);
    let now = fixture.now_ms;
    let mut store = open_test_store(&path, Arc::clone(&backend));
    store
        .create_session(fixture.binding.clone(), fixture.root)
        .unwrap();
    let inbound = inbound_message_envelope(&fixture, 0, [0xF5; 16], b"once");
    let EndpointAcceptance::Committed { object_digest, .. } = store
        .accept_message_envelope(
            &fixture.key,
            &inbound.pack(),
            &fixture.remote_certificate,
            false,
            now,
        )
        .unwrap()
    else {
        panic!("committed");
    };
    let mut rng = StdRng::from_seed([0xF6; 32]);
    let mut accept = |digest: &[u8; 32], _: &[u8]| Ok(*digest);
    let ack = store
        .enqueue_committed_ack(
            &fixture.key,
            &object_digest,
            &local_device,
            now,
            now + 60_000,
            now,
            &mut rng,
            &mut accept,
        )
        .unwrap();
    drop(store);
    seal_profile(dir.path());
    let mut store = open_test_store(&path, Arc::clone(&backend));
    assert!(store.layout.endpoints().is_some());
    let EndpointAcceptance::Duplicate {
        object_digest: again,
        ..
    } = store
        .accept_message_envelope(
            &fixture.key,
            &inbound.pack(),
            &fixture.remote_certificate,
            false,
            now + 1,
        )
        .unwrap()
    else {
        panic!("a duplicate");
    };
    assert_eq!(again, object_digest);
    let mut rng = StdRng::from_seed([0xF7; 32]);
    let resent = store
        .enqueue_committed_ack(
            &fixture.key,
            &object_digest,
            &local_device,
            now + 1,
            now + 60_000,
            now + 1,
            &mut rng,
            &mut accept,
        )
        .unwrap();
    assert_eq!(resent.object_digest, ack.object_digest);
    assert_eq!(
        resent.immutable_envelope_bytes,
        ack.immutable_envelope_bytes
    );
    assert_eq!(resent.state, EndpointOutboxState::Queued);
    assert_eq!(store.list_endpoint_inbox().unwrap().len(), 1);
}

/// The time sealing the endpoint tables adds (`cargo test --release --
/// --ignored`): messages accepted, listed and acknowledged on a clear and
/// on a keyed store. Prints the ratio; bounds the added time per message.
#[test]
#[ignore]
fn endpoint_timing_within_ten_percent() {
    const MESSAGES: u32 = 200;
    let fixture = endpoint_fixture();
    let local_device = authorized_local_device(&fixture);
    let peer = fixture.key.responder_device_ed25519;
    let now = fixture.now_ms;
    let mut times = Vec::new();
    for sealed_profile in [false, true] {
        let (dir, path) = profile();
        if sealed_profile {
            seal_profile(dir.path());
        }
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        assert_eq!(store.layout.endpoints().is_some(), sealed_profile);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let mut rng = StdRng::from_seed([0x3C; 32]);
        let mut accept = |digest: &[u8; 32], _: &[u8]| Ok(*digest);
        let started = std::time::Instant::now();
        let mut cursor = InboxPosition::START;
        for n in 0..MESSAGES {
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&(n + 1).to_be_bytes());
            let digest = accept_text(&mut store, &fixture, n, id, now);
            for row in store
                .list_endpoint_inbox_for_sender_after(&peer, &cursor, 8)
                .unwrap()
            {
                cursor = row.position;
            }
            store
                .enqueue_committed_ack(
                    &fixture.key,
                    &digest,
                    &local_device,
                    now,
                    now + 60_000,
                    now,
                    &mut rng,
                    &mut accept,
                )
                .unwrap();
        }
        times.push(started.elapsed());
        let _ = dir;
    }
    let ratio = times[1].as_secs_f64() / times[0].as_secs_f64();
    let added = times[1].saturating_sub(times[0]).as_secs_f64() * 1e6 / f64::from(MESSAGES);
    println!(
        "clear {:?}, keyed {:?}: {ratio:.2}x, {added:.1} µs added per message",
        times[0], times[1]
    );
    assert!(added < 400.0, "{added:.1} µs per message");
}

/// Endpoint SQL is written once with the keyed names: in schema 1 and 2
/// each `kh_<name>` is `<name>` (whole words only), the two byte digests
/// are the stored bytes.
#[test]
fn endpoint_sql_names_the_clear_columns_in_a_clear_store() {
    assert_eq!(
        Layout::Clear.ep(
            "SELECT o.kh_object_digest, kh_ack, kh_ack_nonce, kh_envelope, xkh_y \
             FROM endpoint_outbox o WHERE kh_message_id = ?1 AND (kh_ack IS NULL)"
        ),
        "SELECT o.object_digest, immutable_ack_bytes, ack_nonce, immutable_envelope_bytes, \
         xkh_y FROM endpoint_outbox o WHERE message_id = ?1 AND (immutable_ack_bytes IS NULL)"
    );
}

/// The way back recreates exactly the columns, keys, constraints and
/// foreign keys every older build creates (`ENDPOINT_SCHEMA`, PP.8's
/// tombstones), so their queries and their `CREATE ... IF NOT EXISTS`
/// batch work on an unsealed store.
#[test]
fn clear_endpoint_columns_are_exactly_schema_1() {
    let older = Connection::open_in_memory().unwrap();
    older.execute_batch(ENDPOINT_SCHEMA).unwrap();
    deleted::create_deleted_schema(&older).unwrap();
    let back = Connection::open_in_memory().unwrap();
    for table in endpoints::TABLES {
        back.execute_batch(&sealed::create_if_missing(
            table,
            endpoints::clear_columns(table),
        ))
        .unwrap();
    }
    let shape = |conn: &Connection, table: &str| -> Vec<String> {
        let mut out = Vec::new();
        for pragma in ["table_info", "index_list", "foreign_key_list"] {
            let mut statement = conn
                .prepare(&format!("SELECT * FROM pragma_{pragma}(?1)"))
                .unwrap();
            let width = statement.column_count();
            let rows = statement
                .query_map(params![table], |row| {
                    let mut line = Vec::new();
                    for at in 0..width {
                        line.push(format!("{:?}", row.get::<_, rusqlite::types::Value>(at)?));
                    }
                    Ok(line.join("|"))
                })
                .unwrap();
            for row in rows {
                out.push(format!("{pragma}: {}", row.unwrap()));
            }
        }
        out.sort();
        out
    };
    let checks: Vec<String> = {
        let mut statement = older
            .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap();
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap();
        rows.map(|r| r.unwrap().split_whitespace().collect::<String>())
            .collect()
    };
    for table in endpoints::TABLES {
        assert_eq!(shape(&back, table), shape(&older, table), "{table}");
        let sql: String = back
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = ?1",
                params![table],
                |row| row.get(0),
            )
            .unwrap();
        let body = sql.split_whitespace().collect::<String>();
        assert!(
            checks.iter().any(|older| older == &body),
            "{table}: the same text (its CHECKs) as every older build's"
        );
    }
}

/// A schema-3 inbox row whose `meta` does not open is that row's damage:
/// the listings go on past it, a deletion leaves it to the session's prune,
/// and the sender's next messages are stamped from the newest row that
/// opens.
#[test]
fn a_damaged_inbox_meta_is_skipped_not_fatal() {
    let (dir, path) = profile();
    seal_profile(dir.path());
    let backend = Arc::new(MemoryProtectedBackend::default());
    let fixture = endpoint_fixture();
    let now = fixture.now_ms;
    let peer = fixture.key.responder_device_ed25519;
    let mut store = open_test_store(&path, backend);
    assert!(store.layout.endpoints().is_some());
    store
        .create_session(fixture.binding.clone(), fixture.root)
        .unwrap();
    let mut digests = Vec::new();
    for n in 0..3u8 {
        digests.push(accept_text(
            &mut store,
            &fixture,
            u32::from(n),
            [0x60 + n; 16],
            now,
        ));
    }
    // One bit of the row's tag flipped (a byte set to a fixed value was that
    // value already once in 256 runs, and the row still opened).
    let damage = |store: &IndexedSessionStore, digest: &[u8; 32]| {
        let kh = store.layout.ep_digest(digest);
        let mut meta: Vec<u8> = store
            .conn
            .query_row(
                "SELECT meta FROM endpoint_inbox WHERE kh_object_digest = ?1",
                params![kh],
                |row| row.get(0),
            )
            .unwrap();
        *meta.last_mut().unwrap() ^= 0x01;
        store
            .conn
            .execute(
                "UPDATE endpoint_inbox SET meta = ?1 WHERE kh_object_digest = ?2",
                params![meta, kh],
            )
            .unwrap();
    };
    damage(&store, &digests[1]);
    let ids =
        |rows: Vec<EndpointInboxRow>| rows.iter().map(|r| r.message_id[0]).collect::<Vec<_>>();
    for limit in [1, 2, 10] {
        let mut cursor = InboxPosition::START;
        let mut shown = Vec::new();
        loop {
            let rows = store
                .list_endpoint_inbox_for_sender_after(&peer, &cursor, limit)
                .unwrap();
            if rows.is_empty() {
                break;
            }
            cursor = rows.last().unwrap().position;
            shown.extend(ids(rows));
        }
        assert_eq!(shown, vec![0x60, 0x62], "limit {limit}");
    }
    assert_eq!(ids(store.list_endpoint_inbox().unwrap()), vec![0x60, 0x62]);
    // The newest row damaged too: the next message is stamped from row 0.
    damage(&store, &digests[2]);
    accept_text(&mut store, &fixture, 3, [0x63; 16], now);
    assert_eq!(ids(store.list_endpoint_inbox().unwrap()), vec![0x60, 0x63]);
    let deleted = store.delete_inbox_for_sender(&peer, None).unwrap();
    assert_eq!(deleted.deleted, 2, "{deleted:?}");
    assert!(store.list_endpoint_inbox().unwrap().is_empty());
}

/// Review B-sealed-stores-2 residual (privacy re-verify): a session head
/// whose `meta` does not open (a changed byte, an epoch no key holds) is
/// that session's damage in the inbox listings too. `raven inbox` (the
/// cross-session listing), the paged reader and a chat deletion go on past
/// its rows, which stay for the session's prune; without the at-rest key
/// the listing still fails (closed). It failed `raven inbox` as a whole
/// until that head's prune hour.
#[test]
fn a_damaged_head_meta_skips_its_session_in_the_inbox_listings() {
    let (dir, path) = profile();
    seal_profile(dir.path());
    let backend = Arc::new(MemoryProtectedBackend::default());
    let fixture = endpoint_fixture();
    let poisoned = second_session_fixture(-1_000);
    let now = fixture.now_ms;
    let peer = fixture.key.responder_device_ed25519;
    let mut store = open_test_store(&path, backend);
    assert!(store.layout.endpoints().is_some());
    store
        .create_session(poisoned.binding.clone(), poisoned.root)
        .unwrap();
    store
        .create_session(fixture.binding.clone(), fixture.root)
        .unwrap();
    // Interleaved: the damaged session's rows come first and in between.
    accept_text(&mut store, &poisoned, 0, [0xA1; 16], now);
    accept_text(&mut store, &fixture, 0, [0xA2; 16], now + 1);
    accept_text(&mut store, &poisoned, 1, [0xA3; 16], now + 2);
    accept_text(&mut store, &fixture, 1, [0xA4; 16], now + 3);
    let ids =
        |rows: Vec<EndpointInboxRow>| rows.iter().map(|r| r.message_id[0]).collect::<Vec<_>>();
    assert_eq!(
        ids(store.list_endpoint_inbox().unwrap()),
        [0xA1, 0xA2, 0xA3, 0xA4]
    );
    let damage = |store: &IndexedSessionStore, epoch: bool| {
        let sid = poisoned.binding.session_id;
        let mut meta: Vec<u8> = store
            .conn
            .query_row(
                "SELECT meta FROM indexed_session_heads WHERE session_id = ?1",
                params![sid.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        if epoch {
            meta[1..5].copy_from_slice(&7u32.to_be_bytes());
        } else {
            let middle = meta.len() / 2;
            meta[middle] ^= 0x01;
        }
        store
            .conn
            .execute(
                "UPDATE indexed_session_heads SET meta = ?1 WHERE session_id = ?2",
                params![meta, sid.as_slice()],
            )
            .unwrap();
    };
    damage(&store, false);
    let healthy = [0xA2, 0xA4];
    assert_eq!(ids(store.list_endpoint_inbox().unwrap()), healthy);
    assert_eq!(
        ids(store.list_endpoint_inbox_for_sender(&peer).unwrap()),
        healthy
    );
    for limit in [1, 2, 10] {
        let mut cursor = InboxPosition::START;
        let mut shown = Vec::new();
        loop {
            let rows = store
                .list_endpoint_inbox_for_sender_after(&peer, &cursor, limit)
                .unwrap();
            if rows.is_empty() {
                break;
            }
            cursor = rows.last().unwrap().position;
            shown.extend(ids(rows));
        }
        assert_eq!(shown, healthy, "limit {limit}");
    }
    // A chat deletion takes the healthy rows; the damaged session's stay.
    let deleted = store.delete_inbox_for_sender(&peer, None).unwrap();
    assert_eq!(deleted.deleted, 2, "{deleted:?}");
    assert!(store.list_endpoint_inbox().unwrap().is_empty());
    let left: i64 = store
        .conn
        .query_row("SELECT COUNT(*) FROM endpoint_inbox", [], |row| row.get(0))
        .unwrap();
    assert_eq!(left, 2);
    // Under an epoch no key holds, with the at-rest key gone from this
    // process: the listing fails closed, never skips.
    damage(&store, true);
    crate::at_rest::forget_cached_keys(dir.path());
    assert!(matches!(
        store.list_endpoint_inbox(),
        Err(IndexedSessionStoreError::MetaKeyUnavailable(_))
    ));
}

/// Every `kh_*` value of every table, in rowid order (a NULL as `None`).
fn keyed_values(path: &Path) -> Vec<(String, Vec<Option<Vec<u8>>>)> {
    let conn = Connection::open(path).unwrap();
    let mut out = Vec::new();
    for table in sealed::ALL_TABLES {
        for column in rebuild::columns(&conn, table).unwrap() {
            if !column.starts_with("kh_") {
                continue;
            }
            let mut statement = conn
                .prepare(&format!("SELECT {column} FROM {table} ORDER BY rowid"))
                .unwrap();
            let values = statement
                .query_map([], |row| row.get::<_, Option<Vec<u8>>>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            out.push((format!("{table}.{column}"), values));
        }
    }
    out
}

/// `raven privacy rotate-meta` (PP.18): the store keyed again under a new
/// `k_index` (the key file's first step, then the store's rebuild): every
/// keyed value changes, every row keeps its rowid (and the inbox its `seq`,
/// the tombstones theirs), every read of the store answers as before, a
/// second re-key is the same store, and the old epochs can then go.
#[test]
fn rotate_meta_changes_every_kh_and_keeps_every_lookup() {
    let (dir, path) = profile();
    seal_profile(dir.path());
    let backend = Arc::new(MemoryProtectedBackend::default());
    let fixture = endpoint_fixture();
    let mut store = open_test_store(&path, Arc::clone(&backend));
    assert!(store.layout.is_keyed());
    populate(&mut store, &fixture);
    let reads = observe(&mut store, dir.path(), &fixture);
    drop(store);
    let rows = table_rows(&path);
    let before = keyed_values(&path);
    assert!(before.len() > 10, "{}", before.len());
    let tombstones = |path: &Path| -> Vec<(i64, i64)> {
        let conn = Connection::open(path).unwrap();
        let mut statement = conn
            .prepare("SELECT rowid, seq FROM endpoint_inbox_deleted ORDER BY rowid")
            .unwrap();
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        rows
    };
    let placed = tombstones(&path);
    assert!(!placed.is_empty(), "the fixture deletes two rows");
    let newest = endpoints::newest_seq(&Connection::open(&path).unwrap()).unwrap();
    let old = crate::at_rest::keys_cached(dir.path()).unwrap();
    let to = old.current_epoch() + 1;
    crate::at_rest::begin_meta_rotation(dir.path(), to).unwrap();
    let moved = rekey(dir.path()).unwrap();
    assert!(!moved.already);
    assert_eq!(moved.dropped, 0);
    assert_eq!(table_rows(&path), rows);
    assert_eq!(tombstones(&path), placed);
    assert_eq!(
        endpoints::newest_seq(&Connection::open(&path).unwrap()).unwrap(),
        newest
    );
    let after = keyed_values(&path);
    assert_eq!(after.len(), before.len());
    for ((column, old_values), (_, new_values)) in before.iter().zip(&after) {
        assert_eq!(old_values.len(), new_values.len(), "{column}");
        for (old_value, new_value) in old_values.iter().zip(new_values) {
            assert_eq!(old_value.is_none(), new_value.is_none(), "{column}");
            if new_value.is_some() {
                assert!(
                    !old_values.contains(new_value),
                    "{column} kept a keyed value"
                );
            }
        }
    }
    assert_eq!(rows_off_epoch(dir.path(), to).unwrap(), 0);
    assert!(foreign_keys_hold(&path));
    // Again: the same store.
    rekey(dir.path()).unwrap();
    assert_eq!(keyed_values(&path), after);
    assert_eq!(table_rows(&path), rows);
    // The old epochs go; every read answers as before.
    crate::at_rest::drop_old_epochs(dir.path()).unwrap();
    assert_eq!(
        crate::at_rest::keys_cached(dir.path()).unwrap().epochs(),
        [to]
    );
    let mut store = open_test_store(&path, backend);
    assert_eq!(observe(&mut store, dir.path(), &fixture), reads);
}

/// `raven privacy unseal` (PP.18) places each chat cursor saved in the
/// schema-3 order before the store moves back: the rows after the placed
/// cursor in the clear store are exactly the rows after it before.
#[test]
fn unseal_places_a_seq_cursor_in_the_received_order() {
    let (dir, path) = profile();
    seal_profile(dir.path());
    let backend = Arc::new(MemoryProtectedBackend::default());
    let fixture = endpoint_fixture();
    let now = fixture.now_ms;
    let peer = fixture.key.responder_device_ed25519;
    let mut store = open_test_store(&path, Arc::clone(&backend));
    store
        .create_session(fixture.binding.clone(), fixture.root)
        .unwrap();
    for n in 0..4u8 {
        accept_text(&mut store, &fixture, u32::from(n), [0xA0 + n; 16], now);
    }
    let all = store
        .list_endpoint_inbox_for_sender_after(&peer, &InboxPosition::START, 10)
        .unwrap();
    assert!(all.iter().all(|r| r.position.order == InboxOrder::Seq));
    // Row 0 deleted by the user: a cursor may stand on a deleted row.
    let first = all[0].position;
    store.delete_inbox_for_sender(&peer, Some(&first)).unwrap();
    let ids =
        |rows: Vec<EndpointInboxRow>| rows.iter().map(|r| r.message_id[0]).collect::<Vec<_>>();
    let mut cases = vec![(0, InboxPosition::START)];
    for row in &all {
        cases.push((
            row.position.seq,
            InboxPosition::received(row.received_at_ms, Some(row.message_id)),
        ));
    }
    let expected: Vec<Vec<u8>> = cases
        .iter()
        .map(|(seq, _)| {
            ids(store
                .list_endpoint_inbox_for_sender_after(&peer, &InboxPosition::seq(*seq), 10)
                .unwrap())
        })
        .collect();
    drop(store);
    let placed: Vec<InboxPosition> = cases
        .iter()
        .map(|(seq, _)| {
            received_position_of(dir.path(), &peer, *seq)
                .unwrap()
                .unwrap()
        })
        .collect();
    // On the row at or before it (the deleted row 0 has none: the start).
    assert_eq!(placed[0], InboxPosition::START);
    assert_eq!(placed[1], InboxPosition::START);
    for at in 2..cases.len() {
        assert_eq!(placed[at], cases[at].1, "seq {}", cases[at].0);
    }
    // Moved back: the same rows after each placed cursor.
    let keys = crate::at_rest::keys_cached(dir.path()).unwrap();
    sealed::migrate_back(&path, &keys, &|_| None).unwrap();
    crate::privacy::set_mode(dir.path(), Mode::UnsealedByUser).unwrap();
    let mut store = open_test_store(&path, backend);
    assert_eq!(store.inbox_order(), InboxOrder::Received);
    for (at, cursor) in placed.iter().enumerate() {
        let rows = store
            .list_endpoint_inbox_for_sender_after(&peer, cursor, 10)
            .unwrap();
        assert_eq!(ids(rows), expected[at], "case {at}");
    }
    // Without a keyed store there is nothing to place.
    assert_eq!(received_position_of(dir.path(), &peer, 3).unwrap(), None);
}

/// A fresh sealed profile's first opens race (raven-node's LAN preflight,
/// its outbox worker and the at-rest loader at start; review C-1): another
/// opener creates the keyed store between this open's reads of the heads'
/// shape and of the other tables. The open reads one snapshot per round and
/// opens the keyed store, never "the tables disagree".
#[test]
fn a_first_open_racing_the_keyed_create_opens_the_keyed_store() {
    let (dir, path) = profile();
    seal_profile(dir.path());
    let backend = Arc::new(MemoryProtectedBackend::default());
    sealed::schema_hook::set(sealed::schema_hook::At::MidRead, {
        let (path, backend) = (path.clone(), Arc::clone(&backend));
        move || {
            std::thread::spawn(move || {
                sealed::test_switch::off();
                drop(open_test_store(&path, backend));
            })
            .join()
            .unwrap();
        }
    });
    let store = IndexedSessionStore::open_with_backend(&path, backend)
        .expect("the racing open finds the keyed store");
    assert!(store.layout.is_keyed());
    drop(store);
    assert_eq!(schema(&path), (METADATA_SCHEMA_VERSION, Shape::Keyed));
}

/// The same race without a hook: many first opens of fresh sealed profiles
/// at once (behind a barrier), every one succeeds on the keyed store.
#[test]
fn concurrent_first_opens_of_a_sealed_profile_all_succeed() {
    const OPENERS: usize = 16;
    const TRIALS: usize = 20;
    for trial in 0..TRIALS {
        let (dir, path) = profile();
        seal_profile(dir.path());
        let barrier = Arc::new(std::sync::Barrier::new(OPENERS));
        let openers: Vec<_> = (0..OPENERS)
            .map(|_| {
                let (data_dir, barrier) = (dir.path().to_path_buf(), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    sealed::test_switch::off();
                    barrier.wait();
                    IndexedSessionStore::open(&data_dir)
                        .map(|store| store.layout.is_keyed())
                        .map_err(|error| error.to_string())
                })
            })
            .collect();
        for opener in openers {
            assert_eq!(opener.join().unwrap(), Ok(true), "trial {trial}");
        }
        assert_eq!(
            schema(&path),
            (METADATA_SCHEMA_VERSION, Shape::Keyed),
            "trial {trial}"
        );
    }
}

/// The read-only view (`SessionMetadataReader`; the Phase 3 re-verify, next
/// to review C-1): an unseal that commits between its read of the heads'
/// shape and of the other tables' is not half seen. Its layout is the keyed
/// store it saw (schema 4), never "keyed heads, clear endpoint tables", a
/// shape the file never had.
#[test]
fn the_read_only_view_reads_its_layout_from_one_snapshot() {
    let (dir, path) = profile();
    seal_profile(dir.path());
    let backend = Arc::new(MemoryProtectedBackend::default());
    drop(open_test_store(&path, backend));
    assert_eq!(schema(&path), (METADATA_SCHEMA_VERSION, Shape::Keyed));
    sealed::schema_hook::set(sealed::schema_hook::At::MidRead, {
        let (data_dir, path) = (dir.path().to_path_buf(), path.clone());
        move || {
            std::thread::spawn(move || {
                let keys = crate::at_rest::keys_cached(&data_dir).unwrap();
                sealed::migrate_back(&path, &keys, &|_| None).unwrap();
            })
            .join()
            .unwrap();
        }
    });
    let conn = Connection::open(&path).unwrap();
    let layout = sealed::reader_layout(&conn, dir.path()).unwrap();
    assert!(layout.is_current(), "a keyed layout of schema 4");
    drop(conn);
    // The unseal did commit meanwhile.
    assert_eq!(schema(&path).1, Shape::Clear);
}
