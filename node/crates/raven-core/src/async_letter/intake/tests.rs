//! RAL1 intake (P5.14) over real profile folders: Alice seals messages into
//! a letter session and wraps them in a letter for Bob; Bob's intake accepts
//! the PairInit and the envelopes and owes the REPLY; Bob's REPLY confirms
//! Alice's session and settles her messages. The fixture is shared with the
//! custody client's letter tests (Carol is the custodian there).
//!
//! The letter gate opens through this thread's debug overrides, which
//! release builds ignore: those tests return early there.

use super::*;
use crate::async_letter::{
    encode_letter_inner, encode_reply_inner, seal, LetterInner, Ral1Kind, ReplyInner, SealInput,
};
use crate::custody_gate::{set_custody_gates_for_this_thread, CustodyGates};
use crate::indexed_session_store::{AuthorizedEndpointDevice, EndpointDeliveryState};
use crate::lan_dispatch::{
    cache_peer_bundle, create_initiator_pair_init, create_letter_pair_init, dispatch_frame,
    local_bundle, wrap_pair_init,
};
use crate::lan_rlb1::LanBundle;
use crate::owed_acks::{OwedAck, OwedAcks};
use crate::pair_init::{decode_response, prekey_bundle_hash, PairInit};
use crate::pair_init_lan_oob::{classify_packed_envelope, PairInitOobClassify};
use std::cell::Cell;

pub(crate) const HOUR_MS: u64 = 3_600_000;
pub(crate) const DAY_MS: u64 = 24 * HOUR_MS;

/// Raven's clock, as the code under test reads it.
pub(crate) fn now() -> u64 {
    crate::clock::now_ms()
}

/// The letter gate open for this thread (custody live, the horizon and
/// letter switches); closed again on drop.
pub(crate) struct LettersOn;

impl LettersOn {
    pub(crate) fn new() -> Self {
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: true,
            wan: false,
        }));
        crate::horizon::set_lab_horizon_for_this_thread(Some(true));
        crate::horizon::set_lab_letter_for_this_thread(Some(true));
        LettersOn
    }
}

impl Drop for LettersOn {
    fn drop(&mut self) {
        crate::horizon::set_lab_horizon_for_this_thread(None);
        crate::horizon::set_lab_letter_for_this_thread(None);
        set_custody_gates_for_this_thread(None);
    }
}

fn contacts(dir: &Path, entries: &[&Identity]) {
    let rows: Vec<serde_json::Value> = entries
        .iter()
        .map(|id| {
            serde_json::json!({
                "petname": hex::encode(&id.public_key_bytes()[..4]),
                "pub_hex": hex::encode(id.public_key_bytes()),
                "pinned": true,
                "lan_dial": "192.168.1.9:7420",
            })
        })
        .collect();
    std::fs::write(
        dir.join("contacts.json"),
        serde_json::Value::Array(rows).to_string(),
    )
    .unwrap();
}

/// Alice, Bob and Carol, each a pinned contact of the others; Alice and Bob
/// hold each other's bundle (they met once); Carol keeps custody.
pub(crate) struct LetterWorld {
    pub(crate) alice: Identity,
    pub(crate) bob: Identity,
    pub(crate) carol: Identity,
    pub(crate) a: tempfile::TempDir,
    pub(crate) b: tempfile::TempDir,
    pub(crate) c: tempfile::TempDir,
    pub(crate) a_bundle: LanBundle,
    pub(crate) b_bundle: LanBundle,
}

pub(crate) fn letter_world(seed: u8) -> LetterWorld {
    crate::identity_store::test_enable_locked_file_identity_backend();
    let id = |n: u8| Identity::from_seed(&[seed.wrapping_add(n); 32]);
    let (alice, bob, carol) = (id(0), id(1), id(2));
    let (a, b, c) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let a_bundle = local_bundle(a.path(), &alice).unwrap();
    let b_bundle = local_bundle(b.path(), &bob).unwrap();
    contacts(a.path(), &[&bob, &carol]);
    contacts(b.path(), &[&alice, &carol]);
    contacts(c.path(), &[&alice, &bob]);
    crate::node_policy::save_policy(
        c.path(),
        &crate::node_policy::NodePolicy {
            custody: true,
            ..Default::default()
        },
    )
    .unwrap();
    cache_peer_bundle(a.path(), &b_bundle).unwrap();
    cache_peer_bundle(b.path(), &a_bundle).unwrap();
    LetterWorld {
        alice,
        bob,
        carol,
        a,
        b,
        c,
        a_bundle,
        b_bundle,
    }
}

impl LetterWorld {
    pub(crate) fn alice_key(&self) -> [u8; 32] {
        self.alice.public_key_bytes()
    }

    pub(crate) fn bob_key(&self) -> [u8; 32] {
        self.bob.public_key_bytes()
    }

    /// Alice's new letter session with Bob.
    pub(crate) fn letter_session(&self) -> (PairInit, IndexedSessionRecordKey) {
        create_letter_pair_init(self.a.path(), &self.alice, &self.b_bundle).unwrap()
    }

    /// `text` sealed by Alice into `key`'s session, valid until `expires`:
    /// the packed envelope.
    pub(crate) fn seal(&self, key: &IndexedSessionRecordKey, text: &str, expires: u64) -> Vec<u8> {
        let mut store = IndexedSessionStore::open(self.a.path()).unwrap();
        let (cert, reg) = crate::device_cert::ensure_local_device_certificate(
            self.a.path(),
            &self.alice,
            crate::paths::PRIMARY_DEVICE_ID,
        )
        .unwrap();
        let device = AuthorizedEndpointDevice::authorize(&cert, &self.alice, &reg, now()).unwrap();
        let t = now();
        let mut out = None;
        store
            .send_message_envelope(
                key,
                text,
                &device,
                t,
                expires,
                t,
                &mut rand::rngs::OsRng,
                &mut |d, bytes| {
                    out = Some(bytes.to_vec());
                    Ok(*d)
                },
            )
            .unwrap();
        out.unwrap()
    }

    /// The exact PairInit Alice's letter row keeps.
    pub(crate) fn kept_pair_init(&self, init: &PairInit) -> Vec<u8> {
        let sid = session_id(init).unwrap();
        IndexedSessionStore::open(self.a.path())
            .unwrap()
            .letter_session(&sid)
            .unwrap()
            .unwrap()
            .pair_init
            .unwrap()
    }

    /// Alice's LETTER for Bob carrying `envelopes` in `init`'s session,
    /// written at `created` and valid until `expires`.
    pub(crate) fn letter(
        &self,
        init: &PairInit,
        envelopes: &[Vec<u8>],
        created: u64,
        expires: u64,
    ) -> Vec<u8> {
        let inner = encode_letter_inner(&LetterInner {
            pair_init: self.kept_pair_init(init),
            envelopes: envelopes.to_vec(),
        })
        .unwrap();
        seal_to(
            &self.alice,
            Ral1Kind::Letter,
            &self.b_bundle,
            &inner,
            created,
            expires,
        )
    }

    /// Bob's REPLY to Alice: `pair_response` and `acks`.
    pub(crate) fn reply(&self, pair_response: Vec<u8>, acks: &[Vec<u8>], expires: u64) -> Vec<u8> {
        let inner = encode_reply_inner(&ReplyInner {
            pair_response,
            acks: acks.to_vec(),
        })
        .unwrap();
        seal_to(
            &self.bob,
            Ral1Kind::Reply,
            &self.a_bundle,
            &inner,
            now(),
            expires,
        )
    }

    /// The ACKs Bob owes Alice for `session_id`.
    pub(crate) fn bob_owes(&self, session_id: &[u8; 32]) -> Vec<OwedAck> {
        let (mut owed, _) = OwedAcks::open(self.b.path()).unwrap();
        owed.list(now())
            .unwrap()
            .into_iter()
            .filter(|ack| ack.session_id == Some(*session_id))
            .collect()
    }

    /// Bob's inbox, as (message id, text), in order.
    pub(crate) fn bob_inbox(&self) -> Vec<([u8; 16], String)> {
        IndexedSessionStore::open(self.b.path())
            .unwrap()
            .list_endpoint_inbox()
            .unwrap()
            .into_iter()
            .map(|row| {
                (
                    row.message_id,
                    String::from_utf8_lossy(&row.plaintext).into_owned(),
                )
            })
            .collect()
    }
}

/// `inner` sealed and signed by `from` to `to`'s signed prekey.
pub(crate) fn seal_to(
    from: &Identity,
    kind: Ral1Kind,
    to: &LanBundle,
    inner: &[u8],
    created: u64,
    expires: u64,
) -> Vec<u8> {
    let mut eph = [0u8; 32];
    let mut letter_id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut eph);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut letter_id);
    seal(
        from,
        &eph,
        &SealInput {
            kind,
            letter_id,
            recipient_device: to.cert.device_ed_pub,
            created_at_ms: created,
            expires_at_ms: expires,
            wrap_bundle_hash: prekey_bundle_hash(&to.prekey).unwrap(),
            recipient_signed_prekey: to.prekey.x25519_pub,
            inner,
        },
    )
    .unwrap()
}

fn message_id(packed: &[u8]) -> [u8; 16] {
    Envelope::unpack(packed).unwrap().message_id
}

/// A letter carrying a PairInit and two messages: Bob's intake accepts the
/// PairInit through the shared core (a new letter session, role 2), takes
/// both messages in order and owes the REPLY durably: the letter row keeps
/// the exact PairResponse (one that confirms Alice's session) and both ACKs
/// are owed, valid past a day (until the session ends).
#[test]
fn letter_accepts_pairinit_and_envelopes_then_owes_reply() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = LettersOn::new();
    let w = letter_world(0x31);
    let (init, a_key) = w.letter_session();
    let t = now();
    let expires = t + 2 * DAY_MS;
    let packed = [
        w.seal(&a_key, "by letter 1", expires),
        w.seal(&a_key, "by letter 2", expires),
    ];
    let letter = w.letter(&init, &packed, t, expires);
    let outcome = intake_letter(w.b.path(), &w.bob, &letter, now());
    let sid = session_id(&init).unwrap();
    let LetterOutcome::Letter(report) = &outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(
        *report,
        LetterReport {
            peer: w.alice_key(),
            session_id: sid,
            new_session: true,
            messages: 2,
            ..LetterReport::default()
        }
    );
    assert!(outcome.releases());
    assert_eq!(
        w.bob_inbox(),
        vec![
            (message_id(&packed[0]), "by letter 1".to_owned()),
            (message_id(&packed[1]), "by letter 2".to_owned()),
        ]
    );
    let store = IndexedSessionStore::open(w.b.path()).unwrap();
    assert_eq!(
        store.letter_role(&sid).unwrap(),
        Some(LetterRole::Responder)
    );
    let reply = store
        .letter_reply(&sid)
        .unwrap()
        .expect("the PairResponse is kept");
    drop(store);
    let response = decode_response(&reply).unwrap();
    assert_eq!(response.init_id, init.init_id);
    assert!(
        response.expires_at_ms > t + DAY_MS,
        "valid as long as the PairInit"
    );
    let owed = w.bob_owes(&sid);
    assert_eq!(owed.len(), 2);
    assert!(owed
        .iter()
        .all(|ack| ack.peer == w.alice_key() && ack.expires_at_ms > now() + DAY_MS));
    // The kept PairResponse confirms Alice's session.
    IndexedSessionStore::open(w.a.path())
        .unwrap()
        .confirm_verified_pair_response(&a_key, &init, &response, now())
        .unwrap();
}

/// The same letter fetched again (its custodian's RELEASE was lost) changes
/// nothing: the PairInit is not claimed again (the core answers an exact
/// replay as DuplicateCompleted and the letter row says it was accepted,
/// also once the core's cached PairResponse is gone), each message is a
/// duplicate whose ACK is owed again, the inbox keeps one row each.
#[test]
fn refetch_is_idempotent() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = LettersOn::new();
    let w = letter_world(0x35);
    let (init, a_key) = w.letter_session();
    let t = now();
    let expires = t + 2 * DAY_MS;
    let packed = [w.seal(&a_key, "once only", expires)];
    let letter = w.letter(&init, &packed, t, expires);
    let sid = session_id(&init).unwrap();
    assert!(matches!(
        intake_letter(w.b.path(), &w.bob, &letter, now()),
        LetterOutcome::Letter(LetterReport { messages: 1, .. })
    ));
    let owed = w.bob_owes(&sid);
    let again = intake_letter(w.b.path(), &w.bob, &letter, now());
    assert_eq!(
        again,
        LetterOutcome::Letter(LetterReport {
            peer: w.alice_key(),
            session_id: sid,
            new_session: false,
            duplicates: 1,
            ..LetterReport::default()
        })
    );
    // The core itself: the exact PairInit again is answered, not claimed.
    let (key, _) = accept_pair_init_core(
        w.b.path(),
        &w.bob,
        &w.a_bundle,
        &init,
        PairOrigin::Letter,
        now(),
    )
    .unwrap();
    assert_eq!(key, record_key_for_init(&init));
    // Past the cached PairResponse's minutes: still accepted, from the row.
    std::fs::remove_dir_all(w.b.path().join("lan_pair_response")).unwrap();
    assert!(matches!(
        intake_letter(w.b.path(), &w.bob, &letter, now()),
        LetterOutcome::Letter(LetterReport {
            duplicates: 1,
            new_session: false,
            ..
        })
    ));
    assert_eq!(w.bob_inbox().len(), 1);
    let owed_after = w.bob_owes(&sid);
    assert_eq!(owed_after.len(), 1);
    assert_eq!(owed_after[0].ack_digest, owed[0].ack_digest);
    let sessions = IndexedSessionStore::open(w.b.path())
        .unwrap()
        .live_letter_sessions_for_peer(&w.alice_key(), LetterRole::Responder, now())
        .unwrap();
    assert_eq!(sessions.len(), 1);
}

/// Two letters of one session fetched in the other order: the later one
/// sets up the session and its messages skip the first indices; the
/// earlier one then takes them from the skipped keys. A letter of a session
/// Bob no longer holds is refused (its PairInit was claimed, its messages
/// have nowhere to go) and leaves no inbox row.
#[test]
fn reordered_letters_same_session_use_skipped_keys() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = LettersOn::new();
    let w = letter_world(0x39);
    let (init, a_key) = w.letter_session();
    let t = now();
    let expires = t + 2 * DAY_MS;
    let packed: Vec<Vec<u8>> = (0..4)
        .map(|i| w.seal(&a_key, &format!("part {i}"), expires))
        .collect();
    let first = w.letter(&init, &packed[..2], t, expires);
    let second = w.letter(&init, &packed[2..], t + 1, expires);
    assert!(matches!(
        intake_letter(w.b.path(), &w.bob, &second, now()),
        LetterOutcome::Letter(LetterReport {
            new_session: true,
            messages: 2,
            ..
        })
    ));
    assert!(matches!(
        intake_letter(w.b.path(), &w.bob, &first, now()),
        LetterOutcome::Letter(LetterReport {
            new_session: false,
            messages: 2,
            ..
        })
    ));
    let mut texts: Vec<String> = w.bob_inbox().into_iter().map(|(_, text)| text).collect();
    texts.sort();
    assert_eq!(texts, ["part 0", "part 1", "part 2", "part 3"]);
    assert_eq!(w.bob_owes(&session_id(&init).unwrap()).len(), 4);
}

#[test]
fn letter_after_responder_session_pruned_is_refused_without_inbox_row() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = LettersOn::new();
    let w = letter_world(0x3d);
    let (init, a_key) = w.letter_session();
    let t = now();
    let expires = t + 2 * DAY_MS;
    let packed: Vec<Vec<u8>> = (0..2)
        .map(|i| w.seal(&a_key, &format!("late {i}"), expires))
        .collect();
    let first = w.letter(&init, &packed[..1], t, expires);
    let later = w.letter(&init, &packed[1..], t + 1, expires);
    assert!(matches!(
        intake_letter(w.b.path(), &w.bob, &first, now()),
        LetterOutcome::Letter(LetterReport { messages: 1, .. })
    ));
    // Bob's session (and its row) goes; the claim stays until the PairInit
    // ends.
    let mut store = IndexedSessionStore::open(w.b.path()).unwrap();
    assert_eq!(store.prune_expired_sessions(init.expires_at_ms).unwrap(), 1);
    let sid = session_id(&init).unwrap();
    assert_eq!(store.letter_role(&sid).unwrap(), None);
    let before = store.list_endpoint_inbox().unwrap().len();
    drop(store);
    let outcome = intake_letter(w.b.path(), &w.bob, &later, now());
    assert_eq!(outcome, LetterOutcome::Refused(Ral1Error::PairRefused));
    assert!(outcome.releases());
    let inbox = w.bob_inbox();
    assert_eq!(inbox.len(), before);
    assert!(!inbox.iter().any(|(id, _)| *id == message_id(&packed[1])));
    assert_eq!(
        IndexedSessionStore::open(w.b.path())
            .unwrap()
            .letter_role(&sid)
            .unwrap(),
        None
    );
}

/// Bob's REPLY (the kept PairResponse and the owed ACKs) confirms Alice's
/// provisional letter session and settles both messages; the same REPLY
/// again is a no-op that still answers.
#[test]
fn reply_confirms_letter_session_and_settles_acks() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = LettersOn::new();
    let w = letter_world(0x41);
    let (init, a_key) = w.letter_session();
    let t = now();
    let expires = t + 2 * DAY_MS;
    let packed = [
        w.seal(&a_key, "reply 1", expires),
        w.seal(&a_key, "reply 2", expires),
    ];
    let letter = w.letter(&init, &packed, t, expires);
    assert!(matches!(
        intake_letter(w.b.path(), &w.bob, &letter, now()),
        LetterOutcome::Letter(_)
    ));
    let sid = session_id(&init).unwrap();
    let wire = IndexedSessionStore::open(w.b.path())
        .unwrap()
        .letter_reply(&sid)
        .unwrap()
        .unwrap();
    let acks: Vec<Vec<u8>> = w.bob_owes(&sid).into_iter().map(|a| a.bytes).collect();
    assert_eq!(acks.len(), 2);
    let reply = w.reply(wire, &acks, now() + DAY_MS);
    // Before the REPLY: provisional, nothing settled.
    assert!(IndexedSessionStore::open(w.a.path())
        .unwrap()
        .find_confirmed_sessions_for_peer_at(&w.bob_key(), now())
        .unwrap()
        .is_empty());
    let outcome = intake_letter(w.a.path(), &w.alice, &reply, now());
    assert_eq!(
        outcome,
        LetterOutcome::Reply(LetterReport {
            peer: w.bob_key(),
            session_id: sid,
            acks: 2,
            ..LetterReport::default()
        })
    );
    let mut store = IndexedSessionStore::open(w.a.path()).unwrap();
    assert_eq!(
        store
            .find_confirmed_sessions_for_peer_at(&w.bob_key(), now())
            .unwrap(),
        vec![a_key.clone()]
    );
    for p in &packed {
        assert_eq!(
            store
                .outstanding_delivery_state(&sid, &message_id(p), &w.bob_key())
                .unwrap(),
            Some(EndpointDeliveryState::Delivered)
        );
    }
    drop(store);
    assert!(matches!(
        intake_letter(w.a.path(), &w.alice, &reply, now()),
        LetterOutcome::Reply(LetterReport { acks: 2, .. })
    ));
}

/// A REPLY whose PairResponse answers no letter session of Alice's with
/// Bob (here: a link session's) is refused as a binding (released) and
/// changes nothing.
#[test]
fn reply_for_unknown_init_is_ignored() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = LettersOn::new();
    let w = letter_world(0x45);
    // A link pairing: Bob's PairResponse to a 24 h PairInit.
    let (init, _key) = create_initiator_pair_init(w.a.path(), &w.alice, &w.b_bundle).unwrap();
    let replies = dispatch_frame(
        w.b.path(),
        &w.bob,
        &w.a_bundle,
        &w.alice_key(),
        &wrap_pair_init(&w.alice, &init).unwrap(),
    )
    .unwrap();
    let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&replies[0]) else {
        panic!("expected a PairResponse")
    };
    let reply = w.reply(wire, &[], now() + DAY_MS);
    let outcome = intake_letter(w.a.path(), &w.alice, &reply, now());
    assert_eq!(outcome, LetterOutcome::Refused(Ral1Error::Binding));
    assert!(outcome.releases());
    assert!(IndexedSessionStore::open(w.a.path())
        .unwrap()
        .find_confirmed_sessions_for_peer_at(&w.bob_key(), now())
        .unwrap()
        .is_empty());
}

/// A letter past its end is refused LETTER_EXPIRED, which releases it.
#[test]
fn expired_letter_released() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = LettersOn::new();
    let w = letter_world(0x49);
    let (init, a_key) = w.letter_session();
    let t = now();
    let packed = [w.seal(&a_key, "too late", t + HOUR_MS)];
    let letter = w.letter(&init, &packed, t, t + HOUR_MS);
    let outcome = intake_letter(w.b.path(), &w.bob, &letter, t + HOUR_MS);
    assert_eq!(outcome, LetterOutcome::Refused(Ral1Error::Expired));
    assert!(outcome.releases());
    assert!(w.bob_inbox().is_empty());
    assert_eq!(
        IndexedSessionStore::open(w.b.path())
            .unwrap()
            .letter_role(&session_id(&init).unwrap())
            .unwrap(),
        None
    );
}

/// Counts step 6's calls, then asks the real actor.
struct CountingKeys<'a> {
    calls: Cell<usize>,
    actor: &'a PrekeyLifecycleActor,
}

impl LetterKeys for CountingKeys<'_> {
    fn wrap_dh(&self, header: &Ral1Header, now_ms: u64) -> Result<Zeroizing<[u8; 32]>, Ral1Error> {
        self.calls.set(self.calls.get() + 1);
        wrap_dh_with_actor(self.actor, header, now_ms)
    }
}

/// The prekey actor is asked nothing for a letter refused at steps 1-5:
/// malformed, for another device, expired, from a stranger, or with a bad
/// signature; a good letter asks it once. With the gate closed nothing is
/// read at all.
#[test]
fn signature_checked_before_actor_is_touched() {
    if !cfg!(debug_assertions) {
        return;
    }
    let on = LettersOn::new();
    let w = letter_world(0x4d);
    let (init, a_key) = w.letter_session();
    let t = now();
    let expires = t + 2 * DAY_MS;
    let packed = [w.seal(&a_key, "signed", expires)];
    let letter = w.letter(&init, &packed, t, expires);
    let actor = PrekeyLifecycleActor::open(w.b.path()).unwrap();
    let keys = CountingKeys {
        calls: Cell::new(0),
        actor: &actor,
    };
    let mut bad_signature = letter.clone();
    *bad_signature.last_mut().unwrap() ^= 1;
    let stranger = Identity::from_seed(&[0x4c; 32]);
    let inner = encode_letter_inner(&LetterInner {
        pair_init: w.kept_pair_init(&init),
        envelopes: packed.to_vec(),
    })
    .unwrap();
    let from_stranger = seal_to(&stranger, Ral1Kind::Letter, &w.b_bundle, &inner, t, expires);
    let c_bundle = local_bundle(w.c.path(), &w.carol).unwrap();
    let for_carol = seal_to(&w.alice, Ral1Kind::Letter, &c_bundle, &inner, t, expires);
    for (bytes, at, code) in [
        (&letter[..100], now(), Ral1Error::Malformed),
        (&for_carol[..], now(), Ral1Error::WrongRecipient),
        (&letter[..], expires, Ral1Error::Expired),
        (&from_stranger[..], now(), Ral1Error::NotContact),
        (&bad_signature[..], now(), Ral1Error::BadSignature),
    ] {
        assert_eq!(
            intake_letter_with(w.b.path(), &w.bob, bytes, &keys, at),
            LetterOutcome::Refused(code)
        );
        assert_eq!(keys.calls.get(), 0, "{code:?}");
    }
    // An unreadable contact book keeps the letter (a store error).
    let book = std::fs::read(w.b.path().join("contacts.json")).unwrap();
    std::fs::write(w.b.path().join("contacts.json"), b"[{").unwrap();
    let kept = intake_letter_with(w.b.path(), &w.bob, &letter, &keys, now());
    assert_eq!(kept, LetterOutcome::Refused(Ral1Error::Store));
    assert!(!kept.releases());
    assert_eq!(keys.calls.get(), 0);
    std::fs::write(w.b.path().join("contacts.json"), book).unwrap();
    assert!(matches!(
        intake_letter_with(w.b.path(), &w.bob, &letter, &keys, now()),
        LetterOutcome::Letter(LetterReport { messages: 1, .. })
    ));
    assert_eq!(keys.calls.get(), 1);
    // Letters off: refused before anything is read.
    drop(on);
    crate::horizon::set_lab_letter_for_this_thread(Some(false));
    assert_eq!(
        intake_letter_with(w.b.path(), &w.bob, &letter, &keys, now()),
        LetterOutcome::Refused(Ral1Error::Gate)
    );
    assert_eq!(keys.calls.get(), 1);
    crate::horizon::set_lab_letter_for_this_thread(None);
}

/// Phase 6b P6.25 (S20, `SEC_LETTER_BAD`): a letter whose signature fails is
/// the fault of the carrier that served it; one Alice signed whose AEAD does
/// not open is hers. Other refusals (a stranger's, an expired one) and a
/// good letter are no one's; every outcome is the plain intake's.
#[test]
fn a_bad_letter_says_whose_fault_it_is() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = LettersOn::new();
    let w = letter_world(0x51);
    let (init, a_key) = w.letter_session();
    let t = now();
    let expires = t + 2 * DAY_MS;
    let packed = [w.seal(&a_key, "signed", expires)];
    let letter = w.letter(&init, &packed, t, expires);
    let mut bad_signature = letter.clone();
    *bad_signature.last_mut().unwrap() ^= 1;
    // Alice's own signature over a changed ciphertext byte.
    let mut ct_tamper = letter.clone();
    ct_tamper[crate::async_letter::HEADER_LEN + 3] ^= 1;
    let split = ct_tamper.len() - crate::async_letter::SIGNATURE_LEN;
    let signature = w
        .alice
        .sign(&crate::async_letter::signing_bytes(&ct_tamper[..split]));
    ct_tamper[split..].copy_from_slice(&signature);
    for (bytes, at, code, bad) in [
        (
            &bad_signature,
            now(),
            Ral1Error::BadSignature,
            Some(BadLetter::Carrier),
        ),
        (
            &ct_tamper,
            now(),
            Ral1Error::Unwrap,
            Some(BadLetter::Sender(w.alice_key())),
        ),
        (&letter, expires, Ral1Error::Expired, None),
    ] {
        assert_eq!(
            intake_letter_sensed(w.b.path(), &w.bob, bytes, at),
            (LetterOutcome::Refused(code), bad)
        );
    }
    let (good, bad) = intake_letter_sensed(w.b.path(), &w.bob, &letter, now());
    assert!(matches!(good, LetterOutcome::Letter(_)), "{good:?}");
    assert_eq!(bad, None);
}
