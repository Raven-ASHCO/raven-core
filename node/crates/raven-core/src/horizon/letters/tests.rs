//! The letter step's store work (P5.15) over real profile folders (the
//! intake's fixture): what waits moves into one letter session in send
//! order and opens at Bob; the session is reused while it has room, and a
//! second one waits a day; REPLY letters carry the kept PairResponse and
//! each owed ACK once.

use super::*;
use crate::async_letter::intake::tests::{letter_world, now, LetterWorld, LettersOn, DAY_MS};
use crate::async_letter::intake::{intake_letter, LetterOutcome};
use crate::device_cert::ensure_local_device_certificate;
use crate::indexed_session_store::AuthorizedEndpointDevice;
use crate::lan_dispatch::{create_initiator_pair_init, dispatch_frame, wrap_pair_init};
use crate::owed_acks::OwedAcks;
use crate::pair_init_lan_oob::{classify_packed_envelope, PairInitOobClassify};

/// Alice's confirmed link session with Bob.
fn link_session(w: &LetterWorld) -> IndexedSessionRecordKey {
    let (init, key) = create_initiator_pair_init(w.a.path(), &w.alice, &w.b_bundle).unwrap();
    let replies = dispatch_frame(
        w.b.path(),
        &w.bob,
        &w.a_bundle,
        &w.alice_key(),
        &wrap_pair_init(&w.alice, &init).unwrap(),
    )
    .unwrap();
    let response = replies
        .iter()
        .find_map(|f| match classify_packed_envelope(f) {
            PairInitOobClassify::PairResponse(wire) => {
                crate::pair_init::decode_response(&wire).ok()
            }
            _ => None,
        })
        .unwrap();
    IndexedSessionStore::open(w.a.path())
        .unwrap()
        .confirm_verified_pair_response(&key, &init, &response, now())
        .unwrap();
    key
}

/// `raven send` of `text` into `key`'s session (history `queued`, body
/// staged): its message id.
fn stage(w: &LetterWorld, key: &IndexedSessionRecordKey, text: &str) -> [u8; 16] {
    let a = w.a.path();
    let (cert, reg) =
        ensure_local_device_certificate(a, &w.alice, crate::paths::PRIMARY_DEVICE_ID).unwrap();
    let t = now();
    let device = AuthorizedEndpointDevice::authorize(&cert, &w.alice, &reg, t).unwrap();
    let mut store = IndexedSessionStore::open(a).unwrap();
    let sid = store.session_id_for_record_key(key).unwrap();
    let bob = w.bob_key();
    let mut mid = None;
    store
        .send_message_envelope(
            key,
            text,
            &device,
            t,
            t + DAY_MS / 2,
            t,
            &mut rand::rngs::OsRng,
            &mut |digest: &[u8; 32], bytes: &[u8]| {
                let env = Envelope::unpack(bytes).unwrap();
                crate::lan_dispatch::ensure_outbound_queued_history(
                    a,
                    &bob,
                    &sid,
                    digest,
                    &env.message_id,
                    t,
                    Some(text),
                )
                .unwrap();
                mid = Some(env.message_id);
                Ok(*digest)
            },
        )
        .unwrap();
    mid.unwrap()
}

fn texts(w: &LetterWorld) -> Vec<String> {
    w.bob_inbox().into_iter().map(|(_, text)| text).collect()
}

/// A parked message and a direct copy move into one new letter session in
/// send order (the direct copy leaves its session), sealed into one letter
/// recorded in the book; Bob's intake opens it and takes both in order.
/// The next build reuses the session while it has room.
#[test]
fn what_waits_moves_into_one_letter_session_in_send_order() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = LettersOn::new();
    let w = letter_world(0x81);
    let link = link_session(&w);
    let first = stage(&w, &link, "parked first");
    let second = stage(&w, &link, "direct second");
    let sid = IndexedSessionStore::open(w.a.path())
        .unwrap()
        .session_id_for_record_key(&link)
        .unwrap();
    let mut store = IndexedSessionStore::open(w.a.path()).unwrap();
    crate::outbox::park_expired_message(
        w.a.path(),
        &mut store,
        &w.bob_key(),
        &first,
        Some(&sid),
        false,
        now(),
    )
    .unwrap()
    .expect("parked");
    let direct = [DirectCopy {
        message_id: second,
        session_id: sid,
    }];
    let t = now();
    let build = build_letters(w.a.path(), &w.alice, &mut store, &w.bob_key(), &direct, t).unwrap();
    assert_eq!(build.held, None);
    assert_eq!(build.moved, vec![first, second]);
    assert_eq!(build.parked, vec![second]);
    assert_eq!(build.letters.len(), 1);
    let row = &build.letters[0];
    assert_eq!(row.message_ids, vec![first, second]);
    assert!(row.expires_at_ms > t + DAY_MS / 2 - 60_000 && row.expires_at_ms <= t + 7 * DAY_MS);
    assert!(store.parked_for_recipient(&w.bob_key()).unwrap().is_empty());
    for mid in [first, second] {
        let copies = store
            .message_copies_for_recipient(&w.bob_key(), &mid)
            .unwrap();
        let live: Vec<_> = copies.iter().filter(|c| c.has_outbox_row).collect();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].session_id, row.session_id);
    }
    assert_eq!(
        store.letter_role(&row.session_id).unwrap(),
        Some(LetterRole::Initiator)
    );
    assert_eq!(
        letter_deposits::load(w.a.path(), now()).unwrap().letters,
        build.letters
    );
    let outcome = intake_letter(w.b.path(), &w.bob, &row.letter, now());
    assert!(matches!(outcome, LetterOutcome::Letter(_)), "{outcome:?}");
    assert_eq!(texts(&w), vec!["parked first", "direct second"]);
    // A third message goes into the same session.
    let third = stage(&w, &link, "same session");
    let direct = [DirectCopy {
        message_id: third,
        session_id: sid,
    }];
    let again = build_letters(
        w.a.path(),
        &w.alice,
        &mut store,
        &w.bob_key(),
        &direct,
        now(),
    )
    .unwrap();
    assert_eq!(again.letters.len(), 1);
    assert_eq!(again.letters[0].session_id, row.session_id);
    assert_eq!(again.letters[0].message_ids, vec![third]);
    let outcome = intake_letter(w.b.path(), &w.bob, &again.letters[0].letter, now());
    assert!(matches!(outcome, LetterOutcome::Letter(_)), "{outcome:?}");
    assert_eq!(
        texts(&w),
        vec!["parked first", "direct second", "same session"]
    );
}

/// A letter session given up takes no new letter, and a second one waits
/// a day: the message is left parked (nothing lost).
#[test]
fn one_new_letter_session_a_day() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = LettersOn::new();
    let w = letter_world(0x85);
    let link = link_session(&w);
    let sid = IndexedSessionStore::open(w.a.path())
        .unwrap()
        .session_id_for_record_key(&link)
        .unwrap();
    let mut store = IndexedSessionStore::open(w.a.path()).unwrap();
    let first = stage(&w, &link, "first");
    let build = build_letters(
        w.a.path(),
        &w.alice,
        &mut store,
        &w.bob_key(),
        &[DirectCopy {
            message_id: first,
            session_id: sid,
        }],
        now(),
    )
    .unwrap();
    let letter_sid = build.letters[0].session_id;
    let key = store
        .record_key_for_session_id(&letter_sid)
        .unwrap()
        .unwrap();
    // Given up (no PairResponse when Bob was reached): its copy is parked.
    let parked = abandon_letter_session(w.a.path(), &mut store, &w.bob_key(), &key, now()).unwrap();
    assert_eq!(parked, vec![first]);
    let book = letter_deposits::load(w.a.path(), now()).unwrap();
    assert!(book.is_abandoned(&letter_sid) && book.letters.iter().all(|r| r.withdraw));
    let next = build_letters(w.a.path(), &w.alice, &mut store, &w.bob_key(), &[], now()).unwrap();
    assert_eq!(next.held, Some(code::LETTER_DAY_CAP));
    assert!(next.letters.is_empty());
    assert_eq!(
        store.parked_for_recipient(&w.bob_key()).unwrap().len(),
        1,
        "still parked"
    );
}

/// Bob's intake owes the REPLY: one REPLY letter carries the kept
/// PairResponse and the owed ACK, once; Alice's intake of it confirms her
/// letter session and settles the message.
#[test]
fn replies_carry_the_kept_pair_response_and_each_ack_once() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = LettersOn::new();
    let w = letter_world(0x89);
    let link = link_session(&w);
    let sid = IndexedSessionStore::open(w.a.path())
        .unwrap()
        .session_id_for_record_key(&link)
        .unwrap();
    let mid = stage(&w, &link, "answered");
    let mut store = IndexedSessionStore::open(w.a.path()).unwrap();
    let build = build_letters(
        w.a.path(),
        &w.alice,
        &mut store,
        &w.bob_key(),
        &[DirectCopy {
            message_id: mid,
            session_id: sid,
        }],
        now(),
    )
    .unwrap();
    let letter = &build.letters[0];
    assert!(matches!(
        intake_letter(w.b.path(), &w.bob, &letter.letter, now()),
        LetterOutcome::Letter(_)
    ));
    let (mut owed, _) = OwedAcks::open(w.b.path()).unwrap();
    let owed = owed.list(now()).unwrap();
    assert_eq!(owed.len(), 1);
    let refs: Vec<OwedAckRef<'_>> = owed
        .iter()
        .map(|o| OwedAckRef {
            digest: o.ack_digest,
            session_id: o.session_id,
            bytes: &o.bytes,
            expires_at_ms: o.expires_at_ms,
        })
        .collect();
    let mut b_store = IndexedSessionStore::open(w.b.path()).unwrap();
    let replies = build_replies(
        w.b.path(),
        &w.bob,
        &mut b_store,
        &w.alice_key(),
        &refs,
        now(),
    )
    .unwrap();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].kind, DepositKind::Reply);
    assert_eq!(replies[0].session_id, letter.session_id);
    assert_eq!(replies[0].acks, vec![owed[0].ack_digest]);
    let again = build_replies(
        w.b.path(),
        &w.bob,
        &mut b_store,
        &w.alice_key(),
        &refs,
        now(),
    )
    .unwrap();
    assert!(again.is_empty(), "each ACK once");
    let outcome = intake_letter(w.a.path(), &w.alice, &replies[0].letter, now());
    let LetterOutcome::Reply(report) = &outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(report.acks, 1);
    let key = store
        .record_key_for_session_id(&letter.session_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        store.session_lifecycle(&key).unwrap(),
        SessionLifecycle::Confirmed
    );
}

/// Review letters-3: every send refuses text over
/// `MAX_LAN_ENDPOINT_TEXT`, and one such message, at that size, fits one
/// letter with its session's PairInit: splitting a build into letters
/// never fails for a single copy (no LETTER_TOO_LARGE after the re-seal).
#[test]
fn the_largest_message_fits_one_letter() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = LettersOn::new();
    let w = letter_world(0x95);
    let (init, key) = w.letter_session();
    let text: String = (0..crate::lan_noise::MAX_LAN_ENDPOINT_TEXT)
        .map(|i| char::from(b'!' + u8::try_from(i * 7919 % 94).unwrap()))
        .collect();
    let expires = now() + DAY_MS;
    let sealed = vec![([1u8; 16], w.seal(&key, &text, expires), expires)];
    let chunks = letter_chunks(&w.kept_pair_init(&init), &sealed).unwrap();
    assert_eq!(chunks.len(), 1);
}

/// Re-verify of letters-3 x letters-4: in one worker attempt the re-letter
/// (copies a build left without a letter) and a new build seal letters of
/// the same session at the same wall time. Both were stamped with that
/// time, so Bob took them in page-token order, not necessarily send order.
/// Now each letter is stamped after every letter already recorded for the
/// contact, and Bob's inbox has them in send order.
#[test]
fn a_reletter_and_a_build_in_one_attempt_stamp_in_send_order() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = LettersOn::new();
    let w = letter_world(0x99);
    let link = link_session(&w);
    let sid = IndexedSessionStore::open(w.a.path())
        .unwrap()
        .session_id_for_record_key(&link)
        .unwrap();
    let mut store = IndexedSessionStore::open(w.a.path()).unwrap();
    let first = stage(&w, &link, "first");
    let build = build_letters(
        w.a.path(),
        &w.alice,
        &mut store,
        &w.bob_key(),
        &[DirectCopy {
            message_id: first,
            session_id: sid,
        }],
        now(),
    )
    .unwrap();
    assert_eq!(build.moved, vec![first]);
    // The build stopped between its two writes: no letter carries `first`.
    std::fs::remove_file(w.a.path().join(letter_deposits::LETTER_DEPOSITS_FILE)).unwrap();
    let second = stage(&w, &link, "second");
    // One attempt: one wall time for the re-letter and the new build.
    let t = now();
    let again = reletter(w.a.path(), &w.alice, &mut store, &w.bob_key(), t).unwrap();
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].message_ids, vec![first]);
    let next = build_letters(
        w.a.path(),
        &w.alice,
        &mut store,
        &w.bob_key(),
        &[DirectCopy {
            message_id: second,
            session_id: sid,
        }],
        t,
    )
    .unwrap();
    assert_eq!(next.letters.len(), 1);
    assert_eq!(next.letters[0].session_id, again[0].session_id);
    assert_eq!(next.letters[0].message_ids, vec![second]);
    assert!(
        next.letters[0].created_at_ms > again[0].created_at_ms,
        "stamped after the re-lettered one: {} vs {}",
        next.letters[0].created_at_ms,
        again[0].created_at_ms
    );
    for letter in [&next.letters[0], &again[0]] {
        let outcome = intake_letter(w.b.path(), &w.bob, &letter.letter, now());
        assert!(matches!(outcome, LetterOutcome::Letter(_)), "{outcome:?}");
    }
    let mut letters = [next.letters[0].clone(), again[0].clone()];
    letters.sort_by_key(|row| row.created_at_ms);
    assert_eq!(letters[0].message_ids, vec![first], "Bob's order");
}
