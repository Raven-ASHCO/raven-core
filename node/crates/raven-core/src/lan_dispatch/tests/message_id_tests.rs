//! ATSAM_ENDPOINT_TRANSACTION_V1 §3 over [`dispatch_frame`]: a contact's
//! message id names one message across sessions. Another object under an id
//! it used before never rewrites the message Bob received: the first body
//! stays and the row is marked as a conflict.

use super::*;

/// Session reset and the long horizon (what re-seals a message under a new
/// session) set for this thread; both back to the suite's on drop.
struct ReSealing;

impl ReSealing {
    fn set(on: bool) -> Self {
        crate::session_reset::set_lab_session_reset_for_this_thread(Some(0));
        crate::horizon::set_lab_horizon_for_this_thread(Some(on));
        Self
    }
}

impl Drop for ReSealing {
    fn drop(&mut self) {
        crate::session_reset::set_lab_session_reset_for_this_thread(None);
        crate::horizon::set_lab_horizon_for_this_thread(None);
    }
}

struct Pair {
    a_dir: tempfile::TempDir,
    b_dir: tempfile::TempDir,
    alice: Identity,
    bob: Identity,
    a_bundle: LanBundle,
    b_bundle: LanBundle,
}

impl Pair {
    fn new() -> Self {
        let alice = Identity::from_seed(&[0x5a; 32]);
        let bob = Identity::from_seed(&[0x5b; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        Self {
            a_dir,
            b_dir,
            alice,
            bob,
            a_bundle,
            b_bundle,
        }
    }

    /// Alice pairs with Bob once more (a fresh PairInit): a new session.
    fn new_session(&self) -> IndexedSessionRecordKey {
        let (init, key) =
            create_initiator_pair_init(self.a_dir.path(), &self.alice, &self.b_bundle).unwrap();
        let replies = self
            .to_bob(&wrap_pair_init(&self.alice, &init).unwrap())
            .unwrap();
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&replies[0]) else {
            panic!("expected PairResponse");
        };
        IndexedSessionStore::open(self.a_dir.path())
            .unwrap()
            .confirm_verified_pair_response(
                &key,
                &init,
                &crate::pair_init::decode_response(&wire).unwrap(),
                now(),
            )
            .unwrap();
        key
    }

    fn to_bob(&self, frame: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        dispatch_frame(
            self.b_dir.path(),
            &self.bob,
            &self.a_bundle,
            &self.alice.public_key_bytes(),
            frame,
        )
    }

    /// A message sealed by Alice under `key` with the id `mid` of her
    /// choosing (a modified client needs no API; the re-seal of a parked
    /// message is the convenient one here).
    fn seal_with_id(&self, key: &IndexedSessionRecordKey, mid: &[u8; 16], text: &str) -> Vec<u8> {
        let t = now();
        let mut store = IndexedSessionStore::open(self.a_dir.path()).unwrap();
        assert!(store
            .park_outbound(
                &self.b_bundle.cert.device_ed_pub,
                mid,
                None,
                t - 1,
                t + 3_600_000,
                t,
            )
            .unwrap());
        let (cert, reg) =
            ensure_local_device_certificate(self.a_dir.path(), &self.alice, PRIMARY_DEVICE_ID)
                .unwrap();
        let device = AuthorizedEndpointDevice::authorize(&cert, &self.alice, &reg, t).unwrap();
        let expires = envelope_expires(t, store.session_expires_at(key).unwrap()).unwrap();
        let mut packed = None;
        store
            .reseal_parked_envelope(
                key,
                text,
                mid,
                &device,
                t,
                expires,
                t,
                &mut OsRng,
                &mut |digest, bytes| {
                    packed = Some(bytes.to_vec());
                    Ok(*digest)
                },
            )
            .unwrap();
        let packed = packed.unwrap();
        assert_eq!(Envelope::unpack(&packed).unwrap().message_id, *mid);
        packed
    }

    /// Bob's received rows of `mid`: (body, conflict mark).
    fn received(&self, mid: &[u8; 16]) -> Vec<(String, bool)> {
        ChatHistory::load(self.b_dir.path())
            .unwrap()
            .for_peer(&hex::encode(self.a_bundle.cert.device_ed_pub))
            .into_iter()
            .filter(|e| e.direction == "in" && e.message_id_hex == hex::encode(mid))
            .map(|e| (e.body.clone(), e.id_conflict))
            .collect()
    }

    /// Bob's committed inbox rows of `mid`.
    fn inbox_rows(&self, mid: &[u8; 16]) -> usize {
        IndexedSessionStore::open(self.b_dir.path())
            .unwrap()
            .list_endpoint_inbox()
            .unwrap()
            .iter()
            .filter(|r| r.message_id == *mid)
            .count()
    }
}

/// Release posture (nothing re-seals): a contact sends "100" in one
/// session, then another message under the same id with "10" in a new
/// session, then the first bytes again. Bob's message stays "100" the whole
/// time, the second object is refused (no ACK, no inbox row) and the row is
/// marked as a conflict.
#[test]
fn a_reused_message_id_in_a_new_session_never_rewrites_the_message() {
    let _shut = ReSealing::set(false);
    assert!(!crate::horizon::receiver_dedup_live());
    let w = Pair::new();
    let key1 = w.new_session();
    let packed1 = seal_under(w.a_dir.path(), &w.alice, &key1, "I will pay you 100");
    let mid = Envelope::unpack(&packed1).unwrap().message_id;
    assert_eq!(w.to_bob(&packed1).unwrap().len(), 1, "ACK for the original");
    assert_eq!(w.received(&mid), vec![("I will pay you 100".into(), false)]);

    let key2 = w.new_session();
    assert_ne!(key1, key2);
    let packed2 = w.seal_with_id(&key2, &mid, "I will pay you 10");
    let refused = w.to_bob(&packed2);
    assert!(refused.is_err(), "taken under session 2: {refused:?}");
    assert_eq!(w.received(&mid), vec![("I will pay you 100".into(), true)]);
    assert_eq!(w.inbox_rows(&mid), 1);

    // The first bytes again: the duplicate path answers; nothing changes.
    assert_eq!(w.to_bob(&packed1).unwrap().len(), 1);
    assert_eq!(w.received(&mid), vec![("I will pay you 100".into(), true)]);
    // And the second ones again: still refused.
    assert!(w.to_bob(&packed2).is_err());
    assert_eq!(w.received(&mid), vec![("I will pay you 100".into(), true)]);
    assert_eq!(w.inbox_rows(&mid), 1);
}

/// While a re-seal is possible (the long horizon), a copy under a new
/// session is taken and answered. One with the same text changes nothing;
/// one with other text never replaces the first body and marks the row.
#[test]
fn a_resealed_copy_with_other_text_keeps_the_first_body() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = ReSealing::set(true);
    assert!(crate::horizon::receiver_dedup_live());
    let w = Pair::new();
    let key1 = w.new_session();
    let packed1 = seal_under(w.a_dir.path(), &w.alice, &key1, "I will pay you 100");
    let mid = Envelope::unpack(&packed1).unwrap().message_id;
    assert_eq!(w.to_bob(&packed1).unwrap().len(), 1);

    // A genuine re-seal: same text, new session. No conflict.
    let key2 = w.new_session();
    let same = w.seal_with_id(&key2, &mid, "I will pay you 100");
    assert_eq!(w.to_bob(&same).unwrap().len(), 1);
    assert_eq!(w.received(&mid), vec![("I will pay you 100".into(), false)]);

    // Other text under that id in a third session: answered as a copy, the
    // first body stays and the row is marked.
    let key3 = w.new_session();
    let other = w.seal_with_id(&key3, &mid, "I will pay you 10");
    assert_eq!(w.to_bob(&other).unwrap().len(), 1);
    assert_eq!(w.received(&mid), vec![("I will pay you 100".into(), true)]);
    assert_eq!(w.to_bob(&packed1).unwrap().len(), 1);
    assert_eq!(w.received(&mid), vec![("I will pay you 100".into(), true)]);
}
