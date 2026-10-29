//! The long horizon's store tables (Phase 5, P5.4, the store's `parked`
//! module) in both layouts: parking keeps the outstanding row and survives
//! the session prune, the original send order, the re-seal and its unpark
//! in one transaction (a stop before and after the commit, and the journal
//! replay), the inbound-seen rows and their prune (an expired session's
//! K_root still goes), the re-seal target, the moves to and from schema 4
//! and a re-key, and a contact's removal. Each test decides the layout
//! itself (the suite's `RAVEN_TEST_SEALED_SESSIONS` switch is off on its
//! thread).

use super::sealed_store::{profile, seal_profile};
use super::*;
use crate::horizon::{DAY_MS, MESSAGE_HORIZON_MS};
use crate::sqlite_rebuild as rebuild;

/// A store in a plain or a sealed profile, and its protected backend.
fn store_in(
    sealed_profile: bool,
) -> (
    tempfile::TempDir,
    PathBuf,
    Arc<MemoryProtectedBackend>,
    IndexedSessionStore,
) {
    let (dir, path) = profile();
    if sealed_profile {
        seal_profile(dir.path());
    }
    let backend = Arc::new(MemoryProtectedBackend::default());
    let store = open_test_store(&path, Arc::clone(&backend));
    assert_eq!(store.layout.is_keyed(), sealed_profile);
    (dir, path, backend, store)
}

fn columns(path: &Path, table: &str) -> Vec<String> {
    rebuild::columns(&Connection::open(path).unwrap(), table).unwrap()
}

fn parked_mids(store: &IndexedSessionStore, peer: &[u8; 32]) -> Vec<[u8; 16]> {
    store
        .parked_for_recipient(peer)
        .unwrap()
        .into_iter()
        .map(|row| row.message_id)
        .collect()
}

/// Seal the parked `mid` into `target`'s session.
fn reseal_parked(
    store: &mut IndexedSessionStore,
    target: &EndpointFixture,
    mid: &[u8; 16],
) -> Result<EndpointOutbound, IndexedSessionStoreError> {
    let local_device = authorized_local_device(target);
    let mut rng = StdRng::from_seed([0x6d; 32]);
    let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
    store.reseal_parked_envelope(
        &target.key,
        "parked text",
        mid,
        &local_device,
        target.now_ms,
        target.now_ms + 60_000,
        target.now_ms,
        &mut rng,
        &mut queue,
    )
}

/// Parking deletes the copy's outbox row in one transaction and keeps its
/// outstanding row (a late ACK still settles it); the session prune takes
/// the session, never the parked row. A message an ACK settled, or one past
/// its deadline, is not parked.
#[test]
fn park_outbound_moves_row_keeps_outstanding_and_survives_prune() {
    for sealed_profile in [false, true] {
        let (_dir, path, _backend, mut store) = store_in(sealed_profile);
        let fixture = endpoint_fixture();
        let peer = peer_of(&fixture);
        let sid = fixture.binding.session_id;
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let sent = send_text(&mut store, &fixture, "park me", true).unwrap();
        let created = fixture.now_ms - 5;
        let deadline = created + MESSAGE_HORIZON_MS;
        assert!(store
            .park_outbound(
                &peer,
                &sent.message_id,
                Some(&sid),
                created,
                deadline,
                fixture.now_ms
            )
            .unwrap());
        assert!(store
            .outbound_by_digest_for_recipient(&sent.object_digest, &peer)
            .unwrap()
            .is_none());
        let copies = store
            .message_copies_for_recipient(&peer, &sent.message_id)
            .unwrap();
        assert_eq!(copies.len(), 1);
        assert!(!copies[0].has_outbox_row);
        assert_eq!(copies[0].delivery_state, Some(EndpointDeliveryState::Sent));
        let row = ParkedOutbound {
            recipient_device: peer,
            message_id: sent.message_id,
            created_at_ms: created,
            deadline_ms: deadline,
            parked_at_ms: fixture.now_ms,
            from_session: Some(sid),
            send_order: 1,
        };
        assert_eq!(
            store.parked_for_recipient(&peer).unwrap(),
            vec![row.clone()]
        );
        assert_eq!(
            store.parked_peers().unwrap(),
            vec![ParkedPeer {
                peer,
                parked: 1,
                first_deadline_ms: deadline,
                last_deadline_ms: deadline,
            }]
        );
        assert!(store.parked_for_recipient(&[0x01; 32]).unwrap().is_empty());

        // A late deadline, a later copy and a later time do not move it on:
        // the earliest deadline wins, the first times stay.
        assert!(store
            .park_outbound(
                &peer,
                &sent.message_id,
                None,
                created + 9,
                deadline + DAY_MS,
                fixture.now_ms + 7
            )
            .unwrap());
        assert_eq!(
            store.parked_for_recipient(&peer).unwrap(),
            vec![row.clone()]
        );

        // Past its deadline, nothing is parked; a bad window is refused.
        assert!(!store
            .park_outbound(&peer, &[0x0D; 16], None, created, deadline, deadline)
            .unwrap());
        assert!(matches!(
            store.park_outbound(&peer, &[0x0D; 16], None, created, created, fixture.now_ms),
            Err(IndexedSessionStoreError::EndpointNotCurrentlyValid)
        ));

        // An ACK settled the second message: it is not parked, its row stays.
        let settled = send_text(&mut store, &fixture, "settled already", true).unwrap();
        let ack = inbound_ack_envelope(&fixture, 0, [0xE5; 16], settled.message_id, 1, [0xE6; 12]);
        store
            .accept_ack_envelope(
                &fixture.key,
                &ack.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap();
        assert!(!store
            .park_outbound(
                &peer,
                &settled.message_id,
                Some(&sid),
                created,
                deadline,
                fixture.now_ms
            )
            .unwrap());
        assert!(store
            .outbound_by_digest_for_recipient(&settled.object_digest, &peer)
            .unwrap()
            .is_some());
        assert_eq!(parked_mids(&store, &peer), vec![sent.message_id]);

        // The session's prune takes its rows and its head, not the parked row.
        assert_eq!(
            store
                .prune_expired_sessions(fixture.binding.expires_at_ms)
                .unwrap(),
            1
        );
        assert!(store
            .message_copies_for_recipient(&peer, &sent.message_id)
            .unwrap()
            .is_empty());
        assert_eq!(
            store.parked_for_recipient(&peer).unwrap(),
            vec![row.clone()]
        );
        drop(store);
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        assert_eq!(store.parked_for_recipient(&peer).unwrap(), vec![row]);

        // Given up once.
        assert!(store.give_up_parked(&peer, &sent.message_id).unwrap());
        assert!(!store.give_up_parked(&peer, &sent.message_id).unwrap());
        assert!(store.parked_peers().unwrap().is_empty());
    }
}

/// Parked rows come back in the order the messages were written, ties
/// broken by the order they were first parked in, whatever order they were
/// parked in; parking one again keeps its place.
#[test]
fn parked_rows_keep_original_send_order() {
    for sealed_profile in [false, true] {
        let (_dir, path, _backend, mut store) = store_in(sealed_profile);
        let peer = [0x5C; 32];
        let other = [0x5D; 32];
        let t = 1_900_000_000_000u64;
        let deadline = |created: u64| created + MESSAGE_HORIZON_MS;
        // Parked out of order: the third, the first, a tie with the third,
        // then the second.
        for (mid, created) in [
            ([0x03; 16], t + 30),
            ([0x01; 16], t + 10),
            ([0x04; 16], t + 30),
            ([0x02; 16], t + 20),
        ] {
            assert!(store
                .park_outbound(&peer, &mid, None, created, deadline(created), t + 40)
                .unwrap());
        }
        store
            .park_outbound(&other, &[0x09; 16], None, t, deadline(t), t + 40)
            .unwrap();
        let expected = vec![[0x01; 16], [0x02; 16], [0x03; 16], [0x04; 16]];
        assert_eq!(parked_mids(&store, &peer), expected);
        // Parked again (its next copy expired too): its place is kept.
        store
            .park_outbound(&peer, &[0x03; 16], None, t + 30, deadline(t + 30), t + 99)
            .unwrap();
        assert_eq!(parked_mids(&store, &peer), expected);
        let orders: Vec<u64> = store
            .parked_for_recipient(&peer)
            .unwrap()
            .iter()
            .map(|row| row.send_order)
            .collect();
        assert_eq!(orders, vec![2, 4, 1, 3]);
        assert_eq!(parked_mids(&store, &other), vec![[0x09; 16]]);
        let peers = store.parked_peers().unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!((peers[0].peer, peers[0].parked), (peer, 4));
        assert_eq!(
            (peers[0].first_deadline_ms, peers[0].last_deadline_ms),
            (deadline(t + 10), deadline(t + 30))
        );
        // A row given up leaves the others' order as it was; a new one goes
        // after every send order still there.
        store.give_up_parked(&peer, &[0x04; 16]).unwrap();
        store
            .park_outbound(&peer, &[0x05; 16], None, t + 30, deadline(t + 30), t + 99)
            .unwrap();
        drop(store);
        let store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        assert_eq!(
            parked_mids(&store, &peer),
            vec![[0x01; 16], [0x02; 16], [0x03; 16], [0x05; 16]]
        );
    }
}

/// The re-seal of a parked message and its unpark are one transaction: a
/// stop before the commit leaves it parked and sealed nowhere until the
/// journal replays (then sealed and unparked together); a stop after the
/// commit leaves it sealed and unparked. A message no longer parked is not
/// sealed again.
#[test]
fn reseal_parked_is_atomic_with_unpark() {
    for sealed_profile in [false, true] {
        for point in [
            EndpointFaultPoint::BeforeDatabaseCommit,
            EndpointFaultPoint::AfterDatabaseCommit,
        ] {
            let (_dir, _path, _backend, mut store) = store_in(sealed_profile);
            let old = endpoint_fixture();
            let new = second_session_fixture(1_000);
            let peer = peer_of(&old);
            store.create_session(old.binding.clone(), old.root).unwrap();
            store.create_session(new.binding.clone(), new.root).unwrap();
            let sent = send_text(&mut store, &old, "carry me later", true).unwrap();
            let mid = sent.message_id;
            store
                .park_outbound(
                    &peer,
                    &mid,
                    Some(&old.binding.session_id),
                    old.now_ms,
                    old.now_ms + MESSAGE_HORIZON_MS,
                    old.now_ms,
                )
                .unwrap();
            let sealed_in_new = |store: &IndexedSessionStore| {
                store
                    .message_copies_for_recipient(&peer, &mid)
                    .unwrap()
                    .iter()
                    .any(|copy| copy.session_id == new.binding.session_id && copy.has_outbox_row)
            };
            let parked = |store: &IndexedSessionStore| parked_mids(store, &peer) == vec![mid];

            store.inject_endpoint_fault(point);
            assert!(matches!(
                reseal_parked(&mut store, &new, &mid),
                Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
            ));
            let committed = point == EndpointFaultPoint::AfterDatabaseCommit;
            assert_eq!(sealed_in_new(&store), committed, "{point:?}");
            assert_eq!(parked(&store), !committed, "{point:?}");
            // The protected journal replays: sealed and unparked, together.
            store
                .recover_pending_for_digest(&record_key_digest(&new.key).unwrap())
                .unwrap();
            assert!(sealed_in_new(&store), "{point:?}");
            assert!(!parked(&store), "{point:?}");
            // No longer parked: not sealed again.
            assert!(matches!(
                reseal_parked(&mut store, &new, &mid),
                Err(IndexedSessionStoreError::NotFound)
            ));
        }

        // Without a stop: sealed and unparked, the id kept; a message never
        // parked is refused before any key is used.
        let (_dir, _path, _backend, mut store) = store_in(sealed_profile);
        let old = endpoint_fixture();
        let new = second_session_fixture(1_000);
        let peer = peer_of(&old);
        store.create_session(old.binding.clone(), old.root).unwrap();
        store.create_session(new.binding.clone(), new.root).unwrap();
        assert!(matches!(
            reseal_parked(&mut store, &new, &[0x44; 16]),
            Err(IndexedSessionStoreError::NotFound)
        ));
        let sent = send_text(&mut store, &old, "carry me", true).unwrap();
        store
            .park_outbound(
                &peer,
                &sent.message_id,
                Some(&old.binding.session_id),
                old.now_ms,
                old.now_ms + MESSAGE_HORIZON_MS,
                old.now_ms,
            )
            .unwrap();
        let resealed = reseal_parked(&mut store, &new, &sent.message_id).unwrap();
        assert_eq!(resealed.message_id, sent.message_id);
        assert_eq!(resealed.session_id, new.binding.session_id);
        // The new session's first message index: the refused seal used none.
        assert_eq!(resealed.ratchet_index, 0);
        assert!(store.parked_for_recipient(&peer).unwrap().is_empty());
        assert!(!store.give_up_parked(&peer, &sent.message_id).unwrap());
    }
}

/// Inbound-seen rows: the first time stays, a later note only extends the
/// keep; the session prune deletes the rows past it and keeps the others,
/// and still deletes an expired session's K_root on time.
#[test]
fn inbound_seen_pruned_after_keep_until() {
    for sealed_profile in [false, true] {
        let (_dir, path, backend, mut store) = store_in(sealed_profile);
        let fixture = endpoint_fixture();
        let peer = peer_of(&fixture);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let account = hex::encode(record_key_digest(&fixture.key).unwrap());
        assert!(backend.get(&account).unwrap().is_some());
        let now = fixture.now_ms;
        let (early, late) = ([0x71; 16], [0x72; 16]);
        let early_keep = fixture.binding.expires_at_ms - 1;
        let late_keep = fixture.binding.expires_at_ms + MESSAGE_HORIZON_MS + DAY_MS;
        assert!(!store.inbound_seen(&peer, &early).unwrap());
        assert!(store
            .note_inbound_seen(&peer, &early, now, early_keep)
            .unwrap());
        assert!(!store
            .note_inbound_seen(&peer, &early, now + 1, early_keep - 10)
            .unwrap());
        assert!(store.note_inbound_seen(&peer, &late, now, now + 1).unwrap());
        assert!(!store
            .note_inbound_seen(&peer, &late, now + 2, late_keep)
            .unwrap());
        assert!(store.inbound_seen(&peer, &early).unwrap());
        assert!(store.inbound_seen(&peer, &late).unwrap());
        assert!(!store.inbound_seen(&[0x01; 32], &early).unwrap());

        // Nothing has passed yet.
        assert_eq!(store.prune_expired_sessions(now).unwrap(), 0);
        assert!(store.inbound_seen(&peer, &early).unwrap());
        // At its keep_until it is still kept.
        assert_eq!(store.prune_expired_sessions(early_keep).unwrap(), 0);
        assert!(store.inbound_seen(&peer, &early).unwrap());
        // Past it, the row goes; the session expired too: its K_root goes.
        assert_eq!(
            store
                .prune_expired_sessions(fixture.binding.expires_at_ms)
                .unwrap(),
            1
        );
        assert!(backend.get(&account).unwrap().is_none());
        assert!(!store.inbound_seen(&peer, &early).unwrap());
        assert!(store.inbound_seen(&peer, &late).unwrap());
        drop(store);
        let mut store = open_test_store(&path, Arc::clone(&backend));
        assert!(store.inbound_seen(&peer, &late).unwrap());
        store.prune_expired_sessions(late_keep + 1).unwrap();
        assert!(!store.inbound_seen(&peer, &late).unwrap());
        // Every row went: none is left under another key.
        let count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM endpoint_inbound_seen", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }
}

/// The re-seal target: the newest sendable session with at least 10 minutes
/// left; a session the peer started that lives longer than a LAN session
/// is letter-class and never a target.
#[test]
fn horizon_target_skips_short_and_letter_class_sessions() {
    let (_dir, _path, _backend, mut store) = store_in(false);
    let fixture = endpoint_fixture();
    let peer = peer_of(&fixture);
    assert_eq!(
        store
            .horizon_target_for_peer(&peer, fixture.now_ms)
            .unwrap(),
        None
    );
    store
        .create_session(fixture.binding.clone(), fixture.root)
        .unwrap();
    assert_eq!(
        store
            .horizon_target_for_peer(&peer, fixture.now_ms)
            .unwrap(),
        Some(fixture.key.clone())
    );
    let ends = fixture.binding.expires_at_ms;
    let min = crate::horizon::HORIZON_TARGET_MIN_REMAINING_MS;
    assert_eq!(
        store.horizon_target_for_peer(&peer, ends - min).unwrap(),
        Some(fixture.key.clone())
    );
    assert_eq!(
        store
            .horizon_target_for_peer(&peer, ends - min + 1)
            .unwrap(),
        None
    );
    let lan = crate::lan_dispatch::LAN_SESSION_LIFETIME_MS;
    assert!(!parked::session_is_letter_class(false, 0, 7 * DAY_MS));
    assert!(!parked::session_is_letter_class(true, 0, lan));
    assert!(parked::session_is_letter_class(true, 0, lan + 1));
}

/// A plain store's rows move with it into a sealed profile (keyed, nothing
/// clear), through `raven privacy rotate-meta` (keyed again) and back out
/// with `raven privacy unseal`, rowids and send order kept.
#[test]
fn horizon_rows_move_with_the_store() {
    let (dir, path, _backend, mut store) = store_in(false);
    let (peer, t) = ([0x6A; 32], 1_900_000_000_000u64);
    for (mid, created) in [([0x02; 16], t + 2), ([0x01; 16], t + 1)] {
        store
            .park_outbound(
                &peer,
                &mid,
                None,
                created,
                created + MESSAGE_HORIZON_MS,
                t + 3,
            )
            .unwrap();
    }
    store
        .note_inbound_seen(&peer, &[0x0E; 16], t, t + MESSAGE_HORIZON_MS)
        .unwrap();
    let parked = store.parked_for_recipient(&peer).unwrap();
    assert_eq!(parked.len(), 2);
    drop(store);

    let keyed = |path: &Path| {
        let parked = columns(path, parked::PARKED);
        let seen = columns(path, parked::SEEN);
        (
            parked.contains(&"kh_recipient_device".to_owned()),
            seen.contains(&"kh_peer_device".to_owned()),
            parked.contains(&"recipient_device".to_owned())
                || seen.contains(&"peer_device".to_owned()),
        )
    };
    let check = |store: &IndexedSessionStore| {
        assert_eq!(store.parked_for_recipient(&peer).unwrap(), parked);
        assert!(store.inbound_seen(&peer, &[0x0E; 16]).unwrap());
    };
    seal_profile(dir.path());
    let store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
    assert!(store.layout.is_keyed());
    assert_eq!(keyed(&path), (true, true, false));
    check(&store);
    drop(store);
    let kh = |path: &Path| -> Vec<u8> {
        Connection::open(path)
            .unwrap()
            .query_row(
                "SELECT kh_peer_device FROM endpoint_inbound_seen",
                [],
                |row| row.get(0),
            )
            .unwrap()
    };
    let before = kh(&path);
    crate::privacy::rotate_meta(dir.path(), t, &|| true).unwrap();
    assert_ne!(kh(&path), before);
    check(&open_test_store(
        &path,
        Arc::new(MemoryProtectedBackend::default()),
    ));
    crate::privacy::unseal_all(dir.path(), &|| true).unwrap();
    assert_eq!(keyed(&path), (false, false, true));
    let store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
    assert!(!store.layout.is_keyed());
    check(&store);
}

/// A store an older build made (no horizon tables) opens with them added in
/// the profile's shape, its version kept; a clear table an older build of
/// the pack left in a store it sealed moves into the keyed shape with its
/// rows.
#[test]
fn an_old_store_without_the_tables_opens_and_keeps_its_version() {
    for sealed_profile in [false, true] {
        let (_dir, path, _backend, store) = store_in(sealed_profile);
        store
            .conn
            .execute_batch("DROP TABLE endpoint_parked_outbound; DROP TABLE endpoint_inbound_seen;")
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
            columns(&path, parked::PARKED).contains(&"kh_recipient_device".to_owned()),
            sealed_profile
        );
        store
            .park_outbound(&[0x01; 32], &[0x02; 16], None, 1, 2, 1)
            .unwrap();
    }
    let (_dir, path, _backend, store) = store_in(true);
    store
        .conn
        .execute_batch(&format!(
            "DROP TABLE endpoint_parked_outbound; {}
             INSERT INTO endpoint_parked_outbound (rowid, recipient_device, message_id,
               created_at_ms, deadline_ms, parked_at_ms, from_session, send_order)
             VALUES (7, X'{}', X'{}', 10, 20, 11, NULL, 7);",
            sealed::create_if_missing(parked::PARKED, parked::parked_columns(false)),
            hex::encode([0x0F; 32]),
            hex::encode([0x0E; 16]),
        ))
        .unwrap();
    drop(store);
    let store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
    assert!(columns(&path, parked::PARKED).contains(&"kh_recipient_device".to_owned()));
    let rowid: i64 = store
        .conn
        .query_row("SELECT rowid FROM endpoint_parked_outbound", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(rowid, 7);
    assert_eq!(
        store.parked_for_recipient(&[0x0F; 32]).unwrap(),
        vec![ParkedOutbound {
            recipient_device: [0x0F; 32],
            message_id: [0x0E; 16],
            created_at_ms: 10,
            deadline_ms: 20,
            parked_at_ms: 11,
            from_session: None,
            send_order: 7,
        }]
    );
}

/// Removing a contact forgets its parked and inbound-seen rows ("real
/// erase"), in either layout, and only that contact's.
#[test]
fn forgetting_a_contact_forgets_its_horizon_rows() {
    for sealed_profile in [false, true] {
        let (dir, _path, _backend, mut store) = store_in(sealed_profile);
        let (peer, kept) = ([0x21; 32], [0x22; 32]);
        for device in [peer, kept] {
            store
                .park_outbound(&device, &[0x31; 16], None, 1, 1 + MESSAGE_HORIZON_MS, 2)
                .unwrap();
            store
                .note_inbound_seen(&device, &[0x32; 16], 2, 3 + MESSAGE_HORIZON_MS)
                .unwrap();
        }
        forget_session_end(dir.path(), &peer).unwrap();
        assert!(store.parked_for_recipient(&peer).unwrap().is_empty());
        assert!(!store.inbound_seen(&peer, &[0x32; 16]).unwrap());
        assert_eq!(store.parked_for_recipient(&kept).unwrap().len(), 1);
        assert!(store.inbound_seen(&kept, &[0x32; 16]).unwrap());
    }
}

/// Sets this thread's session reset and horizon switches; both back to the
/// suite's on drop.
struct DedupSwitches;

impl DedupSwitches {
    fn set(reset: bool, horizon: bool) -> Self {
        crate::session_reset::set_lab_session_reset_for_this_thread(Some(u8::from(reset)));
        crate::horizon::set_lab_horizon_for_this_thread(Some(horizon));
        Self
    }
}

impl Drop for DedupSwitches {
    fn drop(&mut self) {
        crate::session_reset::set_lab_session_reset_for_this_thread(None);
        crate::horizon::set_lab_horizon_for_this_thread(None);
    }
}

/// `peer`'s inbox rows of `mid`: (session, received at).
fn inbox_copies_of(
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    mid: &[u8; 16],
) -> Vec<([u8; 32], u64)> {
    store
        .list_endpoint_inbox_for_sender(peer)
        .unwrap()
        .into_iter()
        .filter(|row| row.message_id == *mid)
        .map(|row| (row.session_id, row.received_at_ms))
        .collect()
}

/// With the horizon gate on (session reset off), the accept path notes the
/// message id in its own transaction at its receive time (also when its
/// journal replays after a stop before the commit), kept the horizon plus a
/// day. A copy re-sealed under a new session is a later copy, and stays one
/// after the first copy's session (with its inbox row) was pruned; the first
/// copy never is. The note goes after its keep.
#[test]
fn resealed_copy_after_prune_is_marked_received_again() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _switches = DedupSwitches::set(false, true);
    for sealed_profile in [false, true] {
        let (_dir, _path, _backend, mut store) = store_in(sealed_profile);
        let mut old = endpoint_fixture();
        // The first session ends an hour from now; the second outlives it.
        old.binding.expires_at_ms = old.now_ms + 3_600_000;
        let mut new = second_session_fixture(1_000);
        new.now_ms = old.binding.expires_at_ms + 1_000;
        let peer = peer_of(&old);
        store.create_session(old.binding.clone(), old.root).unwrap();
        store.create_session(new.binding.clone(), new.root).unwrap();
        let mid = [0x5A; 16];

        // A stop before the accept's commit: nothing noted until the
        // journal replays, then noted with the row.
        let inbound = inbound_message_envelope(&old, 0, mid, b"hello once");
        store.inject_endpoint_fault(EndpointFaultPoint::BeforeDatabaseCommit);
        assert!(matches!(
            store.accept_message_envelope(
                &old.key,
                &inbound.pack(),
                &old.remote_certificate,
                false,
                old.now_ms,
            ),
            Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
        ));
        assert!(!store.inbound_seen(&peer, &mid).unwrap());
        store
            .recover_pending_for_digest(&record_key_digest(&old.key).unwrap())
            .unwrap();
        let first = inbox_copies_of(&mut store, &peer, &mid);
        assert_eq!(first.len(), 1, "{sealed_profile}");
        let (_, first_at) = first[0];
        assert_eq!(
            store.inbound_first_seen_ms(&peer, &mid).unwrap(),
            Some(first_at)
        );
        assert!(!store.inbound_received_again(&peer, &mid, first_at).unwrap());

        // The re-sealed copy under the new session: a later copy.
        let copy = inbound_message_envelope(&new, 0, mid, b"hello once");
        assert!(matches!(
            store
                .accept_message_envelope(
                    &new.key,
                    &copy.pack(),
                    &new.remote_certificate,
                    false,
                    new.now_ms,
                )
                .unwrap(),
            EndpointAcceptance::Committed { .. }
        ));
        let copies = inbox_copies_of(&mut store, &peer, &mid);
        assert_eq!(copies.len(), 2);
        let (_, again_at) = copies
            .iter()
            .copied()
            .find(|(session, _)| *session == new.binding.session_id)
            .unwrap();
        assert!(again_at > first_at);
        assert!(store.inbound_received_again(&peer, &mid, again_at).unwrap());
        assert_eq!(
            store.inbound_first_seen_ms(&peer, &mid).unwrap(),
            Some(first_at)
        );

        // The first session expires and is pruned with its inbox row: the
        // copy left is still a later copy.
        store.prune_expired_sessions(new.now_ms).unwrap();
        assert_eq!(
            inbox_copies_of(&mut store, &peer, &mid),
            vec![(new.binding.session_id, again_at)]
        );
        assert!(store.inbound_received_again(&peer, &mid, again_at).unwrap());

        // Kept the horizon plus a day from the last copy's receive time.
        let keep = again_at + MESSAGE_HORIZON_MS + DAY_MS;
        store.prune_expired_sessions(keep).unwrap();
        assert!(store.inbound_seen(&peer, &mid).unwrap());
        store.prune_expired_sessions(keep + 1).unwrap();
        assert!(!store.inbound_seen(&peer, &mid).unwrap());
    }
}

/// ATSAM_ENDPOINT_TRANSACTION_V1 §3, with session reset and the horizon
/// both closed (nothing re-seals): the accept path still notes each message
/// id, in either layout, and another object under that id from the same
/// device in a later session is refused as a conflict before any state
/// moves (no inbox row; the session's receive chain does not advance, so its
/// next message is taken). A new id in the later session is taken.
#[test]
fn a_seen_message_id_is_refused_in_a_later_session_while_nothing_reseals() {
    let _switches = DedupSwitches::set(false, false);
    for sealed_profile in [false, true] {
        let (_dir, _path, _backend, mut store) = store_in(sealed_profile);
        let old = endpoint_fixture();
        let new = second_session_fixture(1_000);
        let peer = peer_of(&old);
        store.create_session(old.binding.clone(), old.root).unwrap();
        store.create_session(new.binding.clone(), new.root).unwrap();
        let mid = [0x5B; 16];
        accept_text(&mut store, &old, 0, mid, old.now_ms);
        assert_eq!(inbox_copies_of(&mut store, &peer, &mid).len(), 1);
        assert!(store.inbound_seen(&peer, &mid).unwrap(), "{sealed_profile}");

        let reused = inbound_message_envelope(&new, 0, mid, b"other text");
        assert!(matches!(
            store.accept_message_envelope(
                &new.key,
                &reused.pack(),
                &new.remote_certificate,
                false,
                new.now_ms,
            ),
            Err(IndexedSessionStoreError::LogicalMessageConflict)
        ));
        assert_eq!(inbox_copies_of(&mut store, &peer, &mid).len(), 1);
        // The refusal moved nothing: index 0 of the later session still
        // takes a message with a new id.
        accept_text(&mut store, &new, 0, [0x5C; 16], new.now_ms);
        assert_eq!(inbox_copies_of(&mut store, &peer, &[0x5C; 16]).len(), 1);
    }
}

/// P5.7: a letter-class session (one the peer started that lives longer
/// than a LAN session) takes no new Messages: it is never sendable, so
/// never the reset step's or the horizon step's re-seal target, in either
/// layout. It is still unretired (a renewed certificate retires it), and a
/// peer-started session of a day, or one this node started for longer, is
/// sendable as before. P5.12: a letter row makes any session letter-class,
/// role 1 (one this node started for a letter, whatever its length) and
/// role 2 (one it accepted from a letter, even a day long).
#[test]
fn letter_class_sessions_are_never_send_targets() {
    let lan = crate::lan_dispatch::LAN_SESSION_LIFETIME_MS;
    let created = 1_700_000_000_000u64;
    let now = created + 60_000;
    let alice = fixture_binding().key.initiator_device_ed25519;
    let bob = fixture_binding().key.responder_device_ed25519;
    let binding = |init_id: u8, lifetime: u64, role: LocalRole| {
        let mut binding = fixture_binding();
        binding.key.init_id = [init_id; 16];
        binding.init_hash = [init_id ^ 0x5A; 32];
        binding.session_id = session_id(&binding.init_hash);
        binding.created_at_ms = created;
        binding.expires_at_ms = created + lifetime;
        binding.local_role = role;
        binding.lifecycle = SessionLifecycle::Confirmed;
        binding.response_hash = Some([0x46; 32]);
        binding
    };
    for sealed_profile in [false, true] {
        // Bob's node: Alice started both sessions (her device is the
        // initiator), one for a day and one for a week.
        let (_dir, _path, _backend, mut store) = store_in(sealed_profile);
        let day = binding(0x10, lan, LocalRole::Responder);
        let week = binding(0x20, 7 * DAY_MS, LocalRole::Responder);
        for b in [&week, &day] {
            store.create_session(b.clone(), [0xA7; 32]).unwrap();
        }
        assert_eq!(
            store
                .find_sendable_sessions_for_peer_at(&alice, now)
                .unwrap(),
            vec![day.key.clone()],
            "only the day-long session is sendable"
        );
        let unretired = store.unretired_sessions_for_peer_at(&alice, now).unwrap();
        assert_eq!(unretired.len(), 2);
        assert!(unretired.contains(&week.key));
        assert_eq!(
            store.reseal_target_for_peer(&alice, true, now).unwrap(),
            Some(day.key.clone())
        );
        assert_eq!(
            store.horizon_target_for_peer(&alice, now).unwrap(),
            Some(day.key.clone())
        );
        // Without the day-long one nothing is a target.
        store
            .retire_session(&day.key, &alice, SessionRetireCause::PeerNoSession, now)
            .unwrap();
        assert!(store
            .find_sendable_sessions_for_peer_at(&alice, now)
            .unwrap()
            .is_empty());
        assert_eq!(
            store.reseal_target_for_peer(&alice, true, now).unwrap(),
            None
        );
        assert_eq!(store.horizon_target_for_peer(&alice, now).unwrap(), None);
        assert_eq!(
            store.newest_sendable_summary(&alice, now).unwrap(),
            None,
            "renewal does not count it either"
        );
        // Alice's node: the week-long session she started herself is hers
        // to send in (her own letter sessions are marked by their row, P5.12).
        let (_dir, _path, _backend, mut store) = store_in(sealed_profile);
        let own = binding(0x30, 7 * DAY_MS, LocalRole::Initiator);
        store.create_session(own.clone(), [0xA7; 32]).unwrap();
        assert_eq!(
            store.find_sendable_sessions_for_peer_at(&bob, now).unwrap(),
            vec![own.key.clone()]
        );
        // P5.12, role 1: marked as one she started for a letter, it is no
        // target any more (still unretired).
        store
            .mark_letter_session(
                &own.key,
                LetterRole::Initiator,
                Some(&[0x5E; crate::pair_init::INIT_WIRE_LEN]),
            )
            .unwrap();
        assert!(store
            .find_sendable_sessions_for_peer_at(&bob, now)
            .unwrap()
            .is_empty());
        assert_eq!(store.reseal_target_for_peer(&bob, true, now).unwrap(), None);
        assert_eq!(store.horizon_target_for_peer(&bob, now).unwrap(), None);
        assert_eq!(store.newest_sendable_summary(&bob, now).unwrap(), None);
        assert_eq!(
            store.unretired_sessions_for_peer_at(&bob, now).unwrap(),
            vec![own.key.clone()]
        );
        // Role 2 on Bob's node: a day-long session he accepted from a letter.
        let (_dir, _path, _backend, mut store) = store_in(sealed_profile);
        let day = binding(0x40, lan, LocalRole::Responder);
        store.create_session(day.clone(), [0xA7; 32]).unwrap();
        assert_eq!(
            store
                .find_sendable_sessions_for_peer_at(&alice, now)
                .unwrap(),
            vec![day.key.clone()]
        );
        store
            .mark_letter_session(&day.key, LetterRole::Responder, None)
            .unwrap();
        assert!(store
            .find_sendable_sessions_for_peer_at(&alice, now)
            .unwrap()
            .is_empty());
        assert_eq!(store.horizon_target_for_peer(&alice, now).unwrap(), None);
    }
}

/// P5.7: the re-seal ledger keeps a message's count until a day past the
/// latest expiry it was given: the horizon step gives the deadline, so a
/// count the reset step began (at the envelope's end) is not pruned while
/// the message is still parked; it never shrinks back.
#[test]
fn reseal_ledger_lives_until_the_deadline() {
    for sealed_profile in [false, true] {
        let (_dir, _path, _backend, mut store) = store_in(sealed_profile);
        let peer = [0x22; 32];
        let mid = [0x5C; 16];
        let t = 1_700_000_000_000u64;
        let envelope_end = t + DAY_MS;
        let deadline = t + MESSAGE_HORIZON_MS;
        assert_eq!(
            store
                .bump_reseal_ledger(&peer, &mid, envelope_end, t)
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .bump_reseal_ledger(&peer, &mid, deadline, t + 1)
                .unwrap(),
            2
        );
        // An earlier expiry later on does not shorten it.
        assert_eq!(
            store
                .bump_reseal_ledger(&peer, &mid, envelope_end, t + 2)
                .unwrap(),
            3
        );
        store
            .prune_expired_sessions(envelope_end + DAY_MS + 1)
            .unwrap();
        assert_eq!(store.reseal_count(&peer, &mid).unwrap(), 3, "kept");
        store.prune_expired_sessions(deadline + DAY_MS - 1).unwrap();
        assert_eq!(store.reseal_count(&peer, &mid).unwrap(), 3, "kept");
        store.prune_expired_sessions(deadline + DAY_MS).unwrap();
        assert_eq!(store.reseal_count(&peer, &mid).unwrap(), 0, "gone");
    }
}

/// One parked message and one inbound-seen row in a plain profile's store,
/// and the parked rows as read back.
fn store_with_horizon_rows(
    sealed_profile: bool,
) -> (tempfile::TempDir, PathBuf, Vec<ParkedOutbound>) {
    let (dir, path, _backend, mut store) = store_in(sealed_profile);
    let t = 1_900_000_000_000u64;
    store
        .park_outbound(
            &[0x6B; 32],
            &[0x03; 16],
            None,
            t,
            t + MESSAGE_HORIZON_MS,
            t + 1,
        )
        .unwrap();
    store
        .note_inbound_seen(&[0x6B; 32], &[0x0F; 16], t, t + MESSAGE_HORIZON_MS)
        .unwrap();
    let parked = store.parked_for_recipient(&[0x6B; 32]).unwrap();
    assert_eq!(parked.len(), 1);
    (dir, path, parked)
}

fn check_horizon_rows(store: &IndexedSessionStore, parked: &[ParkedOutbound]) {
    assert_eq!(store.parked_for_recipient(&[0x6B; 32]).unwrap(), parked);
    assert!(store.inbound_seen(&[0x6B; 32], &[0x0F; 16]).unwrap());
}

/// Review C-2 (Phase 3) for the horizon's tables: an open takes the clear
/// arm of the schema step while another opener's move to schema 4 commits
/// (the parked and inbound-seen rows keyed with it). The clear create that
/// follows never drops the now keyed tables: the rows survive.
#[test]
fn a_seal_move_committing_mid_open_keeps_the_horizon_rows() {
    let (dir, path, parked) = store_with_horizon_rows(false);
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
    check_horizon_rows(&store, &parked);
    drop(store);
    assert!(columns(&path, parked::PARKED).contains(&"kh_recipient_device".to_owned()));
    assert!(columns(&path, parked::SEEN).contains(&"kh_peer_device".to_owned()));
    check_horizon_rows(
        &open_test_store(&path, Arc::new(MemoryProtectedBackend::default())),
        &parked,
    );
}

/// The mirror: an open takes the keyed arm while an unseal moves the store
/// back. The open never keys the clear horizon tables of an unsealed store
/// (a later clear open would drop them): it opens the clear store, rows
/// intact.
#[test]
fn an_unseal_committing_mid_open_keeps_the_horizon_rows() {
    let (dir, path, parked) = store_with_horizon_rows(true);
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
    check_horizon_rows(&store, &parked);
    drop(store);
    assert!(columns(&path, parked::PARKED).contains(&"recipient_device".to_owned()));
    assert!(columns(&path, parked::SEEN).contains(&"peer_device".to_owned()));
    check_horizon_rows(
        &open_test_store(&path, Arc::new(MemoryProtectedBackend::default())),
        &parked,
    );
}

/// A removed contact's sessions go at once, in either layout: each one's
/// protected state (its root and chains) leaves the keystore with its head
/// and endpoint rows, and another contact's session stays untouched.
#[test]
fn deleting_a_contacts_sessions_deletes_their_secrets_now() {
    for sealed_profile in [false, true] {
        let (_dir, _path, backend, mut store) = store_in(sealed_profile);
        let first = endpoint_fixture();
        let second = second_session_fixture(1_000);
        let mut other = endpoint_fixture();
        other.binding.key.init_id = [0x36; 16];
        other.binding.key.responder_device_ed25519 = [0x77; 32];
        other.binding.init_hash = [0x56; 32];
        other.binding.session_id = session_id(&other.binding.init_hash);
        other.key = other.binding.key.clone();
        for f in [&first, &second, &other] {
            store.create_session(f.binding.clone(), f.root).unwrap();
        }
        store
            .register_outstanding_message(&first.key, &[0xBA; 16])
            .unwrap();
        let account = |f: &EndpointFixture| hex::encode(record_key_digest(&f.key).unwrap());
        let peer = peer_of(&first);
        assert_eq!(peer_of(&second), peer);
        assert_eq!(store.delete_sessions_with_peer(&peer).unwrap(), 2);
        for gone in [&first, &second] {
            assert!(
                backend.get(&account(gone)).unwrap().is_none(),
                "{sealed_profile}"
            );
        }
        assert!(backend.get(&account(&other)).unwrap().is_some());
        assert_eq!(store.list_record_keys().unwrap(), vec![other.key.clone()]);
        let outstanding: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM endpoint_outstanding_messages",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(outstanding, 0);
        assert_eq!(store.delete_sessions_with_peer(&peer).unwrap(), 0);
    }
}
