//! Letter sessions (Phase 5b, P5.12) over two profile folders: the
//! initiator's letter PairInit (its lifetime, the signed prekey only, the
//! row with the exact PairInit), the responder's shared core for a letter's
//! PairInit (the archived generation, no one-time prekey, the per-initiator
//! cap, the session marked) and the direct link's path through the same
//! core, unchanged.

use super::*;
use crate::async_letter::Ral1Error;
use crate::horizon::{
    LETTER_MIN_SESSION_LIFETIME_MS, LETTER_SESSION_LIFETIME_MS, MAX_LETTER_CLAIMS_PER_INITIATOR,
};
use crate::indexed_session_store::{LetterRole, LetterSession};

const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 24 * HOUR_MS;

/// Alice and Bob, each a contact of the other with the other's bundle
/// cached; Bob's published bundle is in his archive (`local_bundle` seeds
/// it).
struct Pair {
    alice: Identity,
    bob: Identity,
    a_dir: tempfile::TempDir,
    b_dir: tempfile::TempDir,
    a_bundle: LanBundle,
    b_bundle: LanBundle,
}

fn pair(seed: u8) -> Pair {
    let alice = Identity::from_seed(&[seed; 32]);
    let bob = Identity::from_seed(&[seed.wrapping_add(1); 32]);
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    publish_and_install(a_dir.path(), &alice);
    publish_and_install(b_dir.path(), &bob);
    let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
    let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
    write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
    write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
    cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
    cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
    Pair {
        alice,
        bob,
        a_dir,
        b_dir,
        a_bundle,
        b_bundle,
    }
}

/// Bob's bundle with a new generation `id`, ending at `expires`, that names
/// a one-time prekey when `otp` says so (signed by Bob; Alice only needs its
/// public half).
fn bob_bundle(p: &Pair, id: u32, expires: u64, otp: bool) -> LanBundle {
    let kp = HybridKeypair::generate(&mut rand::thread_rng());
    let mut prekey = PrekeyBundle::from_hybrid_public(
        PRIMARY_DEVICE_ID,
        kp.x25519_public,
        kp.mlkem_ek_bytes.clone(),
        id,
        now(),
        expires,
    )
    .unwrap();
    if otp {
        prekey.one_time_prekey_id = 5;
        prekey.one_time_x25519_pub = Some([0x09; 32]);
    }
    LanBundle {
        cert: p.b_bundle.cert.clone(),
        prekey: prekey.sign(&p.bob).unwrap(),
    }
}

fn response_of(packed: &[u8]) -> PairResponse {
    let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(packed) else {
        panic!("expected a PairResponse");
    };
    decode_response(&wire).unwrap()
}

/// `init` again with a one-time prekey id, signed again by `signer` (only
/// the letter's rule refuses it).
fn with_one_time_prekey(init: &PairInit, signer: &Identity) -> PairInit {
    let mut init = init.clone();
    init.one_time_prekey_id = 3;
    init.responder_one_time_x25519_pub =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0x5c; 32])).to_bytes();
    init.signature = signer.sign(&init_signing_bytes(&init).unwrap());
    init
}

/// A letter session lasts 7 days, cut to the contact's prekey bundle and
/// both device certificates, and none is started below a day; it uses the
/// signed prekey only and keeps its exact PairInit in its row. A link
/// session still lasts exactly 24 h.
#[test]
fn create_letter_pair_init_lifetime_capped_by_bundle_and_certs_and_refused_below_24h() {
    let t = 1_900_000_000_000u64;
    let far = t + 365 * DAY_MS;
    assert_eq!(
        letter_session_lifetime_ms(t, far, far, far),
        Ok(LETTER_SESSION_LIFETIME_MS)
    );
    assert_eq!(LETTER_SESSION_LIFETIME_MS, 7 * DAY_MS);
    assert_eq!(LETTER_MIN_SESSION_LIFETIME_MS, DAY_MS);
    for (prekey, local, peer, expected) in [
        (t + 3 * DAY_MS, far, far, 3 * DAY_MS),
        (far, t + 2 * DAY_MS, far, 2 * DAY_MS),
        (far, far, t + 30 * HOUR_MS, 30 * HOUR_MS),
        (t + DAY_MS, far, far, DAY_MS),
    ] {
        assert_eq!(
            letter_session_lifetime_ms(t, prekey, local, peer),
            Ok(expected)
        );
    }
    for (prekey, local, peer) in [
        (t + DAY_MS - 1, far, far),
        (far, t + 20 * HOUR_MS, far),
        (far, far, t + HOUR_MS),
        (t - 1, far, far),
    ] {
        assert!(letter_session_lifetime_ms(t, prekey, local, peer)
            .unwrap_err()
            .contains("within a day"));
    }

    let p = pair(0xa1);
    let (a_dir, alice) = (p.a_dir.path(), &p.alice);
    // The bundle lasts 30 days: a week.
    let (init, key) = create_letter_pair_init(a_dir, alice, &p.b_bundle).unwrap();
    assert_eq!(
        init.expires_at_ms - init.created_at_ms,
        LETTER_SESSION_LIFETIME_MS
    );
    assert_eq!(init.one_time_prekey_id, 0);
    assert_eq!(init.responder_one_time_x25519_pub, [0u8; 32]);
    let mut store = IndexedSessionStore::open(a_dir).unwrap();
    assert_eq!(store.session_expires_at(&key).unwrap(), init.expires_at_ms);
    let sid = session_id(&init).unwrap();
    assert_eq!(
        store.letter_session(&sid).unwrap(),
        Some(LetterSession {
            session_id: sid,
            peer_device: p.b_bundle.cert.device_ed_pub,
            role: LetterRole::Initiator,
            pair_init: Some(encode_init(&init).unwrap()),
            created_at_ms: init.created_at_ms,
        })
    );
    drop(store);
    // A link session beside it: exactly 24 h, no row.
    let (link, link_key) = create_initiator_pair_init(a_dir, alice, &p.b_bundle).unwrap();
    assert_eq!(
        link.expires_at_ms - link.created_at_ms,
        LAN_SESSION_LIFETIME_MS
    );
    let store = IndexedSessionStore::open(a_dir).unwrap();
    assert_eq!(
        store.letter_role(&session_id(&link).unwrap()).unwrap(),
        None
    );
    drop(store);

    // A bundle that ends in three days: the session ends with it.
    let short = bob_bundle(&p, 2, now() + 3 * DAY_MS, false);
    let (init, _) = create_letter_pair_init(a_dir, alice, &short).unwrap();
    assert_eq!(init.expires_at_ms, short.prekey.expires_at_ms);
    // One that ends within a day: refused, nothing created.
    let heads = || {
        IndexedSessionStore::open(a_dir)
            .unwrap()
            .list_record_keys()
            .unwrap()
            .len()
    };
    let before = heads();
    let ending = bob_bundle(&p, 3, now() + 20 * HOUR_MS, false);
    let err = create_letter_pair_init(a_dir, alice, &ending).unwrap_err();
    assert!(err.contains("within a day"), "{err}");
    // A bundle that names a one-time prekey: refused (the PairInit binds the
    // bundle's hash, and a letter uses the signed prekey only).
    let otp = bob_bundle(&p, 4, now() + 30 * DAY_MS, true);
    let err = create_letter_pair_init(a_dir, alice, &otp).unwrap_err();
    assert!(err.contains("one-time prekey"), "{err}");
    assert_eq!(heads(), before);
    let _ = link_key;
}

/// A letter sealed to a generation Bob has retired since still pairs: the
/// trust bundle comes from his archive of published bundles (a link's
/// PairInit is checked against his current bundle and refused). The
/// session is marked as a letter he accepted, never a send target, and its
/// PairResponse stays valid as long as the PairInit (Alice confirms it
/// with it); the same letter again gets the same PairResponse back.
#[test]
fn letter_pairinit_against_retained_generation_accepted_via_archive() {
    let p = pair(0xa3);
    let (a_dir, b_dir) = (p.a_dir.path(), p.b_dir.path());
    let (init, a_key) = create_letter_pair_init(a_dir, &p.alice, &p.b_bundle).unwrap();
    // Bob rotates: his current bundle is another generation now.
    let later = now() + 1_000;
    with_prekey_store_lock(b_dir, || {
        rotate_local_prekey_locked(b_dir, &p.bob, PrekeyStore::load_checked(b_dir)?, later)
    })
    .unwrap();
    let current = PrekeyStore::load_checked(b_dir)
        .unwrap()
        .fetch_valid(&p.bob.public_key_bytes(), later)
        .unwrap();
    assert_ne!(
        prekey_bundle_hash(&current).unwrap(),
        init.responder_prekey_bundle_hash
    );
    let t = now();
    let link = accept_pair_init_core(b_dir, &p.bob, &p.a_bundle, &init, PairOrigin::Link, t);
    assert!(
        matches!(&link, Err(PairAcceptError::Refused(text)) if text.starts_with("PairInit validation failed: ")),
        "{link:?}"
    );

    let (b_key, packed) =
        accept_pair_init_core(b_dir, &p.bob, &p.a_bundle, &init, PairOrigin::Letter, t).unwrap();
    assert_eq!(b_key, record_key_for_init(&init));
    let sid = session_id(&init).unwrap();
    let mut b_store = IndexedSessionStore::open(b_dir).unwrap();
    assert_eq!(
        b_store.letter_role(&sid).unwrap(),
        Some(LetterRole::Responder)
    );
    let alice_dev = p.a_bundle.cert.device_ed_pub;
    assert_eq!(
        b_store
            .find_confirmed_sessions_for_peer_at(&alice_dev, t)
            .unwrap(),
        vec![b_key.clone()]
    );
    assert!(b_store
        .find_sendable_sessions_for_peer_at(&alice_dev, t)
        .unwrap()
        .is_empty());
    assert_eq!(
        b_store
            .live_letter_sessions_for_peer(&alice_dev, LetterRole::Responder, t)
            .unwrap()
            .len(),
        1
    );
    drop(b_store);
    let response = response_of(&packed);
    assert_eq!(response.expires_at_ms, init.expires_at_ms);
    let mut a_store = IndexedSessionStore::open(a_dir).unwrap();
    a_store
        .confirm_verified_pair_response(&a_key, &init, &response, now())
        .unwrap();
    // Confirmed, Alice's letter session still takes no direct Message.
    assert!(a_store
        .find_sendable_sessions_for_peer_at(&p.b_bundle.cert.device_ed_pub, now())
        .unwrap()
        .is_empty());
    drop(a_store);
    // The same letter again: the same PairResponse, nothing counted twice.
    let (again_key, again) =
        accept_pair_init_core(b_dir, &p.bob, &p.a_bundle, &init, PairOrigin::Letter, now())
            .unwrap();
    assert_eq!((again_key, again), (b_key, packed));
}

/// A letter's PairInit that names a one-time prekey is refused before
/// anything is claimed or stored (a refusal: the letter is released), even
/// signed; a stranger's is refused too.
#[test]
fn letter_pairinit_with_one_time_prekey_refused() {
    let p = pair(0xa5);
    let (a_dir, b_dir) = (p.a_dir.path(), p.b_dir.path());
    let (init, _) = create_letter_pair_init(a_dir, &p.alice, &p.b_bundle).unwrap();
    let otp = with_one_time_prekey(&init, &p.alice);
    let err = accept_pair_init_core(b_dir, &p.bob, &p.a_bundle, &otp, PairOrigin::Letter, now())
        .unwrap_err();
    assert!(
        matches!(&err, PairAcceptError::Refused(text) if text.contains("one-time prekey")),
        "{err:?}"
    );
    assert_eq!(err.letter_code(), Ral1Error::PairRefused);
    assert!(err.letter_code().releases_letter());
    // A stranger (not a contact of Bob's) is refused as on a link.
    let carol = Identity::from_seed(&[0xa7; 32]);
    let stranger = signed_bundle(&carol, carol.public_key_bytes(), PRIMARY_DEVICE_ID);
    let err = accept_pair_init_core(b_dir, &p.bob, &stranger, &init, PairOrigin::Letter, now())
        .unwrap_err();
    assert_eq!(
        err,
        PairAcceptError::Refused("pair init refused: peer is not a local contact".into())
    );
    let store = IndexedSessionStore::open(b_dir).unwrap();
    assert!(store.list_record_keys().unwrap().is_empty());
    // The same PairInit without the one-time prekey pairs.
    drop(store);
    accept_pair_init_core(b_dir, &p.bob, &p.a_bundle, &init, PairOrigin::Letter, now()).unwrap();
}

/// An initiator holds at most MAX_LETTER_CLAIMS_PER_INITIATOR (8) live
/// letter sessions at a responder: the next letter is refused with
/// LETTER_CLAIM_LIMIT, which keeps the letter at its custodian, and nothing
/// of it is stored. A letter accepted already still answers; a direct
/// link's PairInit is not counted.
#[test]
fn letter_claim_cap_per_initiator_is_8_and_keeps_letter() {
    assert_eq!(MAX_LETTER_CLAIMS_PER_INITIATOR, 8);
    let p = pair(0xa9);
    let (a_dir, b_dir) = (p.a_dir.path(), p.b_dir.path());
    let inits: Vec<PairInit> = (0..=MAX_LETTER_CLAIMS_PER_INITIATOR)
        .map(|_| {
            create_letter_pair_init(a_dir, &p.alice, &p.b_bundle)
                .unwrap()
                .0
        })
        .collect();
    let mut answers = Vec::new();
    for init in &inits[..MAX_LETTER_CLAIMS_PER_INITIATOR] {
        answers.push(
            accept_pair_init_core(b_dir, &p.bob, &p.a_bundle, init, PairOrigin::Letter, now())
                .unwrap(),
        );
    }
    let ninth = &inits[MAX_LETTER_CLAIMS_PER_INITIATOR];
    let err = accept_pair_init_core(b_dir, &p.bob, &p.a_bundle, ninth, PairOrigin::Letter, now())
        .unwrap_err();
    assert_eq!(err, PairAcceptError::ClaimLimit);
    assert_eq!(err.letter_code(), Ral1Error::ClaimLimit);
    assert!(!err.letter_code().releases_letter(), "the letter is kept");
    let store = IndexedSessionStore::open(b_dir).unwrap();
    assert_eq!(
        store.list_record_keys().unwrap().len(),
        MAX_LETTER_CLAIMS_PER_INITIATOR
    );
    assert_eq!(
        store.letter_role(&session_id(ninth).unwrap()).unwrap(),
        None
    );
    drop(store);
    // A letter Bob holds already is answered again, not refused.
    let again = accept_pair_init_core(
        b_dir,
        &p.bob,
        &p.a_bundle,
        &inits[0],
        PairOrigin::Letter,
        now(),
    )
    .unwrap();
    assert_eq!(again, answers[0]);
    // A direct link's PairInit from Alice is no letter claim.
    let (link, _) = create_initiator_pair_init(a_dir, &p.alice, &p.b_bundle).unwrap();
    let (link_key, _) =
        accept_pair_init_core(b_dir, &p.bob, &p.a_bundle, &link, PairOrigin::Link, now()).unwrap();
    let store = IndexedSessionStore::open(b_dir).unwrap();
    let link_sid = session_id(&link).unwrap();
    assert_eq!(store.letter_role(&link_sid).unwrap(), None);
    assert_eq!(link_key, record_key_for_init(&link));
}

/// The direct link's PairInit goes through the shared core unchanged: the
/// reply is the cached PairResponse (an exact replay gets the same bytes),
/// valid at most a day, the session is a sendable link session with no
/// letter row, and the refusals read as they always did.
/// A PairInit that came on a LAN link.
const LINK: Via = Via::DirectLink(crate::outbox::OutboxCarrier::Lan);

#[test]
fn handle_pair_init_link_path_byte_identical() {
    let p = pair(0xab);
    let (a_dir, b_dir) = (p.a_dir.path(), p.b_dir.path());
    let (init, a_key) = create_initiator_pair_init(a_dir, &p.alice, &p.b_bundle).unwrap();
    let wire = encode_init(&init).unwrap();
    let mut clock = None;
    let replies = handle_pair_init(b_dir, &p.bob, &p.a_bundle, &wire, &mut clock, LINK).unwrap();
    assert_eq!(clock, Some(PeerClock::Agrees));
    assert_eq!(replies.len(), 1);
    let bob_pub = p.bob.public_key_bytes();
    assert_eq!(
        load_verified_cached_pair_response(b_dir, &init, &bob_pub).unwrap(),
        replies[0]
    );
    let mut clock = None;
    assert_eq!(
        handle_pair_init(b_dir, &p.bob, &p.a_bundle, &wire, &mut clock, LINK).unwrap(),
        replies
    );
    let response = response_of(&replies[0]);
    assert!(response.expires_at_ms - response.created_at_ms <= LINK_PAIR_RESPONSE_VALIDITY_MS);
    assert_eq!(
        response.expires_at_ms,
        init.expires_at_ms
            .min(response.created_at_ms + LINK_PAIR_RESPONSE_VALIDITY_MS)
    );
    let alice_dev = p.a_bundle.cert.device_ed_pub;
    let mut b_store = IndexedSessionStore::open(b_dir).unwrap();
    let key = record_key_for_init(&init);
    assert_eq!(
        b_store
            .find_sendable_sessions_for_peer_at(&alice_dev, now())
            .unwrap(),
        vec![key]
    );
    assert_eq!(
        b_store.letter_role(&session_id(&init).unwrap()).unwrap(),
        None
    );
    drop(b_store);
    IndexedSessionStore::open(a_dir)
        .unwrap()
        .confirm_verified_pair_response(&a_key, &init, &response, now())
        .unwrap();

    // The refusals' texts.
    let carol = Identity::from_seed(&[0xad; 32]);
    let stranger = signed_bundle(&carol, carol.public_key_bytes(), PRIMARY_DEVICE_ID);
    let mut clock = None;
    assert_eq!(
        handle_pair_init(b_dir, &p.bob, &stranger, &wire, &mut clock, LINK).unwrap_err(),
        "pair init refused: peer is not a local contact"
    );
    let (second, _) = create_initiator_pair_init(a_dir, &p.alice, &p.b_bundle).unwrap();
    let mut forged = second.clone();
    forged.signature[0] ^= 1;
    let mut clock = None;
    let err = handle_pair_init(
        b_dir,
        &p.bob,
        &p.a_bundle,
        &encode_init(&forged).unwrap(),
        &mut clock,
        LINK,
    )
    .unwrap_err();
    assert!(err.starts_with("PairInit validation failed: "), "{err}");
    // A letter's one-time prekey rule is not the link's.
    let otp = with_one_time_prekey(&second, &p.alice);
    let mut clock = None;
    let err = handle_pair_init(
        b_dir,
        &p.bob,
        &p.a_bundle,
        &encode_init(&otp).unwrap(),
        &mut clock,
        LINK,
    )
    .unwrap_err();
    assert!(err.starts_with("PairInit validation failed: "), "{err}");
}
