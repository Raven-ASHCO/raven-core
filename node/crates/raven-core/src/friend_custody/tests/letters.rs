//! Phase 5 P5.13: the letter ops (spec §10) on the custodian, their store
//! table `custody_letters_v1` in both schemas, and their vectors.
//!
//! The handler serves letters only while the letter gate is open, which a
//! test opens with this thread's debug overrides; release builds ignore
//! those, so the handler-level tests that need letters served return early
//! there (the store-level ones run in both builds).

use super::*;
use crate::async_letter::{decode_header, letter_digest, MIN_RAL1_LEN};
use crate::carrier_admission::{opaque_letter_for_tests, MAX_LETTER_CUSTODY_VALIDITY_MS};

const DAY: u64 = 24 * HOUR;

/// The letter gate open for this thread (custody gate, horizon and letter
/// switches) and the base-ops-only knob as `base_only`; restored on drop.
struct Letters {
    _custody: Gates,
}

impl Letters {
    fn on() -> Self {
        Self::with(true, false)
    }

    fn with(letters: bool, base_only: bool) -> Self {
        let custody = Gates::set(true, false);
        crate::horizon::set_lab_horizon_for_this_thread(Some(letters));
        crate::horizon::set_lab_letter_for_this_thread(Some(letters));
        set_lab_base_ops_only_for_this_thread(Some(base_only));
        Letters { _custody: custody }
    }
}

impl Drop for Letters {
    fn drop(&mut self) {
        crate::horizon::set_lab_horizon_for_this_thread(None);
        crate::horizon::set_lab_letter_for_this_thread(None);
        set_lab_base_ops_only_for_this_thread(None);
    }
}

/// A letter from `from` naming `to`, living `life` from NOW, with an
/// `inner_len`-byte inner.
fn letter_of(from: &Identity, to: &Identity, fill: u8, life: u64, inner_len: usize) -> Vec<u8> {
    opaque_letter_for_tests(
        from,
        &to.public_key_bytes(),
        NOW,
        NOW + life,
        inner_len,
        fill,
    )
}

fn small(from: &Identity, to: &Identity, fill: u8) -> Vec<u8> {
    letter_of(from, to, fill, DAY, 512)
}

impl Carol {
    fn deposit_letter(&self, from: &Identity, to: &Identity, letter: Vec<u8>) -> CustodyCode {
        match self
            .call(
                from,
                lan("192.168.1.20"),
                Rfc1Request::DepositLetter {
                    recipient: to.public_key_bytes(),
                    letter,
                },
            )
            .as_slice()
        {
            [Rfc1Reply::DepositResult { code, .. }] => *code,
            other => panic!("{other:?}"),
        }
    }

    fn fetch_letters(&self, who: &Identity, after: Option<[u8; 32]>, max: u8) -> Vec<Rfc1Reply> {
        self.call(
            who,
            lan("192.168.1.21"),
            Rfc1Request::FetchLetters {
                after,
                max_items: max,
            },
        )
    }

    fn withdraw(&self, who: &Identity, digests: Vec<[u8; 32]>) -> Rfc1Reply {
        match self
            .call(
                who,
                lan("192.168.1.20"),
                Rfc1Request::WithdrawLetters { digests },
            )
            .as_slice()
        {
            [reply] => reply.clone(),
            other => panic!("{other:?}"),
        }
    }

    /// The letters `who` fetches in one page of 16.
    fn letters_for(&self, who: &Identity) -> Vec<Vec<u8>> {
        letter_items(&self.fetch_letters(who, None, 16))
    }
}

fn letter_items(replies: &[Rfc1Reply]) -> Vec<Vec<u8>> {
    replies
        .iter()
        .filter_map(|r| match r {
            Rfc1Reply::LetterItem { letter } => Some(letter.clone()),
            _ => None,
        })
        .collect()
}

fn withdrawn(n: u8) -> Rfc1Reply {
    Rfc1Reply::WithdrawResult {
        code: CustodyCode::Ok,
        withdrawn: n,
    }
}

// ── Wire ─────────────────────────────────────────────────────────────────

/// Round trips, the dial classifiers (0x04-0x06 expect replies; LETTER_ITEM
/// never ends a request, WITHDRAW_RESULT does) and the fixed lengths.
#[test]
fn letter_frames_roundtrip_and_classify() {
    let (alice, bob) = (id(0xA0), id(0xB0));
    let letter = small(&alice, &bob, 1);
    let requests = [
        Rfc1Request::DepositLetter {
            recipient: bob.public_key_bytes(),
            letter: letter.clone(),
        },
        Rfc1Request::FetchLetters {
            after: Some([3; 32]),
            max_items: 16,
        },
        Rfc1Request::FetchLetters {
            after: None,
            max_items: 1,
        },
        Rfc1Request::WithdrawLetters {
            digests: vec![[4; 32], [5; 32]],
        },
    ];
    for request in requests {
        let frame = encode_request(&[9; 8], &request);
        assert!(frame_expects_reply(&frame) && !frame_is_terminal_reply(&frame));
        assert!(is_letter_op(frame[5]));
        assert_eq!(
            decode_request(&frame).unwrap(),
            RequestDecode::Request([9; 8], request)
        );
    }
    let item = Rfc1Reply::LetterItem {
        letter: letter.clone(),
    };
    let frame = encode_reply(&[8; 8], &item);
    assert!(!item.is_terminal() && !frame_is_terminal_reply(&frame));
    assert_eq!(frame.len(), 18 + letter.len());
    assert_eq!(decode_reply(&frame).unwrap(), ([8; 8], item));
    let result = Rfc1Reply::WithdrawResult {
        code: CustodyCode::Ok,
        withdrawn: 2,
    };
    let frame = encode_reply(&[8; 8], &result);
    assert!(result.is_terminal() && frame_is_terminal_reply(&frame));
    assert!(!frame_expects_reply(&frame));
    assert_eq!(frame.len(), 16);
    assert_eq!(decode_reply(&frame).unwrap(), ([8; 8], result));
    // FETCH_LETTERS is 48 bytes; DEPOSIT_LETTER is 50 + n.
    assert_eq!(
        encode_request(
            &[0; 8],
            &Rfc1Request::FetchLetters {
                after: None,
                max_items: 1
            }
        )
        .len(),
        48
    );
    // The handoff ops (0x07-0x08, P5.18) are not letter ops; 0x09 is still
    // unknown here: no classifier counts it.
    for op in [OP_HANDOFF, OP_TAGS] {
        let mut f = header(op, &[1; 8]);
        f.resize(48, 0);
        assert!(frame_expects_reply(&f) && !is_letter_op(op));
    }
    let mut f = header(0x09, &[1; 8]);
    f.resize(48, 0);
    assert!(!frame_expects_reply(&f) && !is_letter_op(0x09));
    assert_eq!(
        decode_request(&f).unwrap(),
        RequestDecode::Unsupported([1; 8])
    );
    // A reply that is not a whole letter does not decode.
    let mut short = header(OP_LETTER_ITEM, &[1; 8]);
    short.extend_from_slice(&((MIN_RAL1_LEN - 1) as u32).to_be_bytes());
    short.resize(18 + MIN_RAL1_LEN - 1, 0);
    assert!(decode_reply(&short).is_err());
}

#[test]
fn letter_requests_strict_decoding_negatives() {
    let malformed = |f: &[u8]| {
        assert!(
            matches!(decode_request(f).unwrap(), RequestDecode::Malformed(_, op) if is_letter_op(op)),
            "{f:?}"
        )
    };
    let fetch = |has_after: u8, token: u8, max_items: u8| {
        let mut f = header(OP_FETCH_LETTERS, &[1; 8]);
        f.push(has_after);
        f.extend_from_slice(&[token; 32]);
        f.push(max_items);
        f
    };
    assert!(matches!(
        decode_request(&fetch(0, 0, 1)).unwrap(),
        RequestDecode::Request(_, Rfc1Request::FetchLetters { after: None, .. })
    ));
    malformed(&fetch(0, 5, 1)); // non-zero token without has_after
    malformed(&fetch(2, 0, 1));
    malformed(&fetch(1, 0, 0));
    malformed(&fetch(1, 0, 17));
    let mut trailing = fetch(0, 0, 1);
    trailing.push(0);
    malformed(&trailing);
    malformed(&fetch(0, 0, 1)[..47]);
    // DEPOSIT_LETTER: exact length, 776..=65,288 bytes of letter.
    let letter = small(&id(0xA0), &id(0xB0), 2);
    let mut deposit = encode_request(
        &[1; 8],
        &Rfc1Request::DepositLetter {
            recipient: [0xB0; 32],
            letter: letter.clone(),
        },
    );
    deposit.push(0);
    malformed(&deposit);
    let tiny = encode_request(
        &[1; 8],
        &Rfc1Request::DepositLetter {
            recipient: [0xB0; 32],
            letter: letter[..MIN_RAL1_LEN - 1].to_vec(),
        },
    );
    malformed(&tiny);
    malformed(&header(OP_DEPOSIT_LETTER, &[1; 8]));
    // WITHDRAW_LETTERS: 1..=32 digests, deduplicated.
    let mut none = header(OP_WITHDRAW_LETTERS, &[1; 8]);
    none.push(0);
    malformed(&none);
    let mut many = header(OP_WITHDRAW_LETTERS, &[1; 8]);
    many.push(33);
    many.resize(15 + 32 * 33, 1);
    malformed(&many);
    let mut dup = header(OP_WITHDRAW_LETTERS, &[1; 8]);
    dup.push(2);
    dup.extend_from_slice(&[4; 32]);
    dup.extend_from_slice(&[4; 32]);
    let RequestDecode::Request(_, Rfc1Request::WithdrawLetters { digests }) =
        decode_request(&dup).unwrap()
    else {
        panic!()
    };
    assert_eq!(digests, vec![[4; 32]]);
}

/// Each op's terminal reply answers it alone (a refusal before the op's own
/// work): DEPOSIT and DEPOSIT_LETTER a DEPOSIT_RESULT, FETCH and
/// FETCH_LETTERS a FETCH_END, RELEASE a RELEASE_RESULT, WITHDRAW_LETTERS a
/// WITHDRAW_RESULT; the handler sends exactly that on a closed link gate.
#[test]
fn terminal_for_answers_each_op_with_its_own_reply() {
    let code = CustodyCode::Hold;
    for (op, want) in [
        (OP_DEPOSIT, OP_DEPOSIT_RESULT),
        (OP_DEPOSIT_LETTER, OP_DEPOSIT_RESULT),
        (OP_FETCH, OP_FETCH_END),
        (OP_FETCH_LETTERS, OP_FETCH_END),
        (OP_RELEASE, OP_RELEASE_RESULT),
        (OP_WITHDRAW_LETTERS, OP_WITHDRAW_RESULT),
    ] {
        let reply = terminal_for(op, code);
        assert_eq!(reply.op(), want, "{op:#04x}");
        assert!(reply.is_terminal());
        let frame = encode_reply(&[2; 8], &reply);
        assert!(frame_is_terminal_reply(&frame));
        match decode_reply(&frame).unwrap().1 {
            Rfc1Reply::DepositResult { code: c, .. }
            | Rfc1Reply::FetchEnd { code: c, .. }
            | Rfc1Reply::ReleaseResult { code: c, .. }
            | Rfc1Reply::WithdrawResult { code: c, .. } => assert_eq!(c, code),
            other => panic!("{other:?}"),
        }
    }
    if !cfg!(debug_assertions) {
        return;
    }
    let _l = Letters::on();
    let c = Carol::new();
    let alice = &c.alice;
    // A public source on a LAN link without WAN custody: HOLD, as each op's
    // own reply.
    for request in [
        Rfc1Request::DepositLetter {
            recipient: c.bob.public_key_bytes(),
            letter: small(alice, &c.bob, 3),
        },
        Rfc1Request::FetchLetters {
            after: None,
            max_items: 4,
        },
        Rfc1Request::WithdrawLetters {
            digests: vec![[1; 32]],
        },
    ] {
        let op = request.op();
        let replies = c.call(alice, lan("203.0.113.5"), request);
        assert_eq!(replies, [terminal_for(op, CustodyCode::Hold)], "{op:#04x}");
    }
    // A link peer that is not pinned: NOT_VERIFIED, malformed or not.
    let mut bad = header(OP_FETCH_LETTERS, &[7; 8]);
    bad.push(9);
    let replies = handle_frame(
        c.dir.path(),
        &c.carol,
        &c.dave.public_key_bytes(),
        &lan("192.168.1.20"),
        &bad,
        NOW,
    )
    .unwrap();
    assert_eq!(
        decode_reply(&replies[0]).unwrap().1,
        terminal_for(OP_FETCH_LETTERS, CustodyCode::NotVerified)
    );
    assert!(!custody_db_path(c.dir.path()).exists());
}

// ── The gate and the lab knob ────────────────────────────────────────────

/// With the letter gate closed, or `RAVEN_LAB_CUSTODY_BASE_OPS_ONLY=1`,
/// every letter op, well formed or not, is answered UNSUPPORTED (max_version
/// 1, req_id echoed) before anything else, exactly as by a listener built
/// before them; the base ops are served as before. Nothing is created.
#[test]
fn base_ops_only_listener_answers_unsupported() {
    let c = Carol::new();
    let letter = small(&c.alice, &c.bob, 4);
    let mut malformed = header(OP_FETCH_LETTERS, &[5; 8]);
    malformed.push(7);
    let frames = [
        encode_request(
            &[5; 8],
            &Rfc1Request::DepositLetter {
                recipient: c.bob.public_key_bytes(),
                letter,
            },
        ),
        encode_request(
            &[5; 8],
            &Rfc1Request::FetchLetters {
                after: None,
                max_items: 4,
            },
        ),
        encode_request(
            &[5; 8],
            &Rfc1Request::WithdrawLetters {
                digests: vec![[1; 32]],
            },
        ),
        malformed,
    ];
    // (letter gate, knob): the gate closed (in every build), then open with
    // the knob on (debug only: release builds have no override).
    let mut cases = vec![(false, false)];
    if cfg!(debug_assertions) {
        cases.push((true, true));
    }
    for (letters, base_only) in cases {
        let _l = Letters::with(letters, base_only);
        assert!(!letter_ops_served());
        for frame in &frames {
            let replies = handle_frame(
                c.dir.path(),
                &c.carol,
                &c.alice.public_key_bytes(),
                &lan("192.168.1.20"),
                frame,
                NOW,
            )
            .unwrap();
            assert_eq!(
                replies,
                [unsupported(&[5; 8])],
                "{letters} {base_only} op {:#04x}",
                frame[5]
            );
            assert_eq!(replies[0].len(), 15);
        }
        // The base ops are unaffected.
        let fill = 0x70 + u8::from(letters);
        let env = envelope(&c.alice, fill);
        assert_eq!(
            c.deposit(&c.alice, &c.bob, rso1_for(&env, fill)),
            CustodyCode::Ok
        );
        assert_eq!(items(&c.fetch(&c.bob, &[[fill; 16]], None)), 1);
    }
    if cfg!(debug_assertions) {
        // The knob off with the gate open: served.
        let _l = Letters::on();
        assert!(letter_ops_served());
        assert!(c.letters_for(&c.bob).is_empty());
        assert_eq!(
            CustodyStore::open_existing(c.dir.path())
                .unwrap()
                .unwrap()
                .letter_usage()
                .unwrap(),
            (0, 0),
            "nothing was stored while the ops were off"
        );
    }
}

/// The knob is read only in a debug build with the Lab Test A unlock (the
/// release test job sets every lab variable).
#[test]
fn base_ops_only_knob_is_inert_without_debug_assertions() {
    if !cfg!(debug_assertions) {
        std::env::set_var("RAVEN_LAB_TEST_A", "1");
        std::env::set_var(LAB_BASE_OPS_ONLY, "1");
        assert!(!lab_base_ops_only());
        return;
    }
    set_lab_base_ops_only_for_this_thread(Some(true));
    assert!(lab_base_ops_only());
    set_lab_base_ops_only_for_this_thread(Some(false));
    assert!(!lab_base_ops_only());
    set_lab_base_ops_only_for_this_thread(None);
}

// ── Custodian rules ──────────────────────────────────────────────────────

#[test]
fn deposit_letter_rules() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _l = Letters::on();
    let c = Carol::new();
    let (alice, bob) = (&c.alice, &c.bob);
    // The signer must be the depositor.
    assert_eq!(
        c.deposit_letter(alice, bob, small(bob, alice, 1)),
        CustodyCode::RefusedObject
    );
    // A broken signature.
    let mut forged = small(alice, bob, 2);
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert_eq!(
        c.deposit_letter(alice, bob, forged),
        CustodyCode::RefusedObject
    );
    // The letter names the DEPOSIT's recipient.
    assert_eq!(
        c.deposit_letter(alice, &c.dave, small(alice, bob, 3)),
        CustodyCode::RefusedObject
    );
    // The recipient is a pinned contact other than the depositor and Carol.
    assert_eq!(
        c.deposit_letter(alice, &c.dave, small(alice, &c.dave, 4)),
        CustodyCode::RecipientNotAccepted
    );
    assert_eq!(
        c.deposit_letter(alice, &c.carol, small(alice, &c.carol, 5)),
        CustodyCode::RecipientNotAccepted
    );
    // Header only: a strict decode failure is MALFORMED.
    let mut kind3 = small(alice, bob, 6);
    kind3[5] = 3;
    assert_eq!(c.deposit_letter(alice, bob, kind3), CustodyCode::Malformed);
    // The 7 d + skew cap, from Carol's clock; expired; from the future.
    let edge = NOW + MAX_LETTER_CUSTODY_VALIDITY_MS;
    let at = |created: u64, expires: u64, fill: u8| {
        opaque_letter_for_tests(alice, &bob.public_key_bytes(), created, expires, 512, fill)
    };
    assert_eq!(
        c.deposit_letter(alice, bob, at(edge - 7 * DAY, edge + 1, 7)),
        CustodyCode::RefusedObject
    );
    assert_eq!(
        c.deposit_letter(alice, bob, at(NOW - DAY, NOW, 8)),
        CustodyCode::Expired
    );
    assert_eq!(
        c.deposit_letter(alice, bob, at(NOW + 6 * 60_000, NOW + DAY, 9)),
        CustodyCode::RefusedObject
    );
    assert!(
        CustodyStore::open_existing(c.dir.path()).unwrap().is_none(),
        "no refusal created the store"
    );
    // The edge itself is held, once; the same bytes again are a duplicate.
    let held = at(edge - 7 * DAY, edge, 10);
    assert_eq!(c.deposit_letter(alice, bob, held.clone()), CustodyCode::Ok);
    assert_eq!(
        c.deposit_letter(alice, bob, held.clone()),
        CustodyCode::Duplicate
    );
    // The pair cap: 32 letters from Alice for Bob; refused, never evicted.
    for n in 1..MAX_PAIR_LETTERS {
        assert_eq!(
            c.deposit_letter(alice, bob, small(alice, bob, 0x20 + n as u8)),
            CustodyCode::Ok,
            "{n}"
        );
    }
    assert_eq!(
        c.deposit_letter(alice, bob, small(alice, bob, 0x90)),
        CustodyCode::Quota
    );
    let store = CustodyStore::open_existing(c.dir.path()).unwrap().unwrap();
    assert_eq!(store.letter_usage().unwrap().0, MAX_PAIR_LETTERS);
    assert_eq!(store.usage().unwrap().0, 0, "letters are not objects");
    // Another pair is a separate bucket; objects keep their own pair cap.
    assert_eq!(
        c.deposit_letter(bob, alice, small(bob, alice, 0x91)),
        CustodyCode::Ok
    );
    let env = envelope(alice, 0x92);
    assert_eq!(c.deposit(alice, bob, rso1_for(&env, 0x92)), CustodyCode::Ok);
    // Custody off: POLICY_DENIED; fetch and withdraw still answer.
    c.custody(false);
    assert_eq!(
        c.deposit_letter(bob, alice, small(bob, alice, 0x93)),
        CustodyCode::PolicyDenied
    );
    assert_eq!(c.letters_for(alice).len(), 1);
    assert_eq!(
        c.withdraw(bob, vec![letter_digest(&small(bob, alice, 0x91))]),
        withdrawn(1)
    );
}

/// Letters count toward the node and depositor caps with the objects, in
/// the same transaction; each keeps its own pair cap.
#[test]
fn letters_and_objects_share_the_node_and_depositor_caps() {
    for setup in SETUPS {
        let c = Carol::with(setup);
        let (a, b) = (c.alice.public_key_bytes(), c.bob.public_key_bytes());
        let mut store = CustodyStore::open_or_create(c.dir.path()).unwrap();
        let mut n: u32 = 0;
        let mut next = || {
            n += 1;
            let mut dg = [0u8; 32];
            dg[..4].copy_from_slice(&n.to_be_bytes());
            dg
        };
        // Admitted two minutes ago (out of the byte-rate window), so only
        // the row caps count.
        let past = NOW - 120_000;
        for _ in 0..MAX_PAIR_LETTERS {
            let digest = next();
            assert_eq!(
                store
                    .deposit_letter(&digest, &b, &a, &[1u8; 16], NOW + HOUR, past)
                    .unwrap(),
                CustodyCode::Ok
            );
        }
        let counts = match store.keys.clone() {
            None => clear_counts(&store.conn, &b, &a, NOW).unwrap(),
            Some(keys) => keyed_counts(
                &store.conn,
                &keys,
                &store.device_value(&b),
                &store.device_value(&a),
                NOW,
            )
            .unwrap(),
        };
        assert_eq!(
            (
                counts.node_rows,
                counts.depositor_rows,
                counts.pair_rows,
                counts.pair_letters
            ),
            (MAX_PAIR_LETTERS, MAX_PAIR_LETTERS, 0, MAX_PAIR_LETTERS),
            "{setup:?}"
        );
        // Objects fill the depositor's rows up to the cap with the letters.
        for i in 0..(MAX_DEPOSITOR_ROWS - MAX_PAIR_LETTERS) {
            let digest = next();
            // Eight recipients keep each object pair under its own cap.
            let mut to = [0xE0; 32];
            to[0] = (i % 8) as u8;
            let code = store
                .deposit(&digest, &to, &a, &[2; 16], &[0u8; 16], NOW + HOUR, past)
                .unwrap();
            assert_eq!(code, CustodyCode::Ok, "{setup:?} {i}");
        }
        assert_eq!(
            store
                .deposit(
                    &next(),
                    &[0xEF; 32],
                    &a,
                    &[2; 16],
                    &[0u8; 16],
                    NOW + HOUR,
                    NOW
                )
                .unwrap(),
            CustodyCode::Quota,
            "{setup:?}: the depositor cap counts the letters"
        );
        assert_eq!(
            store
                .deposit_letter(&next(), &[0xEF; 32], &a, &[1u8; 16], NOW + HOUR, NOW)
                .unwrap(),
            CustodyCode::Quota,
            "{setup:?}: and the letters the objects"
        );
    }
}

#[test]
fn fetch_letters_only_link_peer_paged_128kib() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _l = Letters::on();
    let c = Carol::new();
    let (alice, bob) = (&c.alice, &c.bob);
    // Three letters of about 60 KiB: two fit a 128 KiB page.
    let big: Vec<Vec<u8>> = (0..3u8)
        .map(|n| letter_of(alice, bob, 0x40 + n, DAY, 60 * 1024))
        .collect();
    for letter in &big {
        assert_eq!(
            c.deposit_letter(alice, bob, letter.clone()),
            CustodyCode::Ok
        );
    }
    let first = c.fetch_letters(bob, None, 16);
    let got = letter_items(&first);
    assert_eq!(got.len(), 2);
    assert!(got.iter().map(Vec::len).sum::<usize>() <= MAX_FETCH_PAGE_BYTES);
    let Some(Rfc1Reply::FetchEnd {
        code: CustodyCode::Ok,
        returned: 2,
        next: Some(token),
    }) = first.last().cloned()
    else {
        panic!("{:?}", first.last())
    };
    let second = c.fetch_letters(bob, Some(token), 16);
    let rest = letter_items(&second);
    assert_eq!(rest.len(), 1);
    assert!(matches!(
        second.last(),
        Some(Rfc1Reply::FetchEnd { next: None, .. })
    ));
    // Every letter once, in page-token order.
    let all: Vec<Vec<u8>> = got.into_iter().chain(rest).collect();
    let mut want = big.clone();
    want.sort_by_key(|l| crate::async_letter::page_token(l));
    assert_eq!(all, want);
    // Their depositor takes them back (WITHDRAW_LETTERS).
    assert_eq!(
        c.withdraw(alice, big.iter().map(|l| letter_digest(l)).collect()),
        withdrawn(3)
    );
    // max_items bounds a page of small letters.
    for n in 0..5u8 {
        assert_eq!(
            c.deposit_letter(alice, bob, small(alice, bob, 0x50 + n)),
            CustodyCode::Ok
        );
    }
    let page = c.fetch_letters(bob, None, 2);
    assert_eq!(letter_items(&page).len(), 2);
    assert!(matches!(
        page.last(),
        Some(Rfc1Reply::FetchEnd { next: Some(_), .. })
    ));
    // Only the recipient: the depositor and another contact see nothing, and
    // a link peer that is not pinned is refused.
    assert!(c.letters_for(alice).is_empty());
    assert!(matches!(
        c.fetch_letters(&c.dave, None, 16).as_slice(),
        [Rfc1Reply::FetchEnd {
            code: CustodyCode::NotVerified,
            ..
        }]
    ));
    // RELEASE by the recipient releases a letter like an object: gone, and
    // a re-deposit is a duplicate until it would have expired.
    let one = small(alice, bob, 0x50);
    assert_eq!(
        release_by(&c, alice, vec![letter_digest(&one)]),
        released(0)
    );
    assert_eq!(release_by(&c, bob, vec![letter_digest(&one)]), released(1));
    assert_eq!(
        c.deposit_letter(alice, bob, one.clone()),
        CustodyCode::Duplicate
    );
    let left = c.letters_for(bob);
    assert_eq!(left.len(), 4);
    assert!(!left.contains(&one));
}

#[test]
fn withdraw_only_by_depositor() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _l = Letters::on();
    let c = Carol::new();
    let (alice, bob) = (&c.alice, &c.bob);
    // No store yet: nothing withdrawn, nothing created.
    assert_eq!(c.withdraw(alice, vec![[1; 32]]), withdrawn(0));
    assert!(!custody_db_path(c.dir.path()).exists());
    let (one, two) = (small(alice, bob, 0x61), small(alice, bob, 0x62));
    for letter in [&one, &two] {
        assert_eq!(
            c.deposit_letter(alice, bob, letter.clone()),
            CustodyCode::Ok
        );
    }
    let digests = vec![letter_digest(&one), letter_digest(&two)];
    // The recipient, a link peer that is not pinned: nothing.
    assert_eq!(c.withdraw(bob, digests.clone()), withdrawn(0));
    assert!(matches!(
        c.withdraw(&c.dave, digests.clone()),
        Rfc1Reply::WithdrawResult {
            code: CustodyCode::NotVerified,
            withdrawn: 0
        }
    ));
    assert_eq!(c.letters_for(bob).len(), 2);
    // The depositor: both gone; again, nothing.
    assert_eq!(
        c.withdraw(alice, vec![digests[0], [9; 32], digests[0]]),
        withdrawn(1)
    );
    assert_eq!(c.letters_for(bob), std::slice::from_ref(&two));
    assert_eq!(c.withdraw(alice, digests.clone()), withdrawn(1));
    assert_eq!(c.withdraw(alice, digests), withdrawn(0));
    assert!(c.letters_for(bob).is_empty());
    // A withdrawn letter leaves nothing: its depositor may leave it again.
    assert_eq!(c.deposit_letter(alice, bob, one), CustodyCode::Ok);
}

#[test]
fn maintain_drops_expired_letters() {
    for setup in SETUPS {
        let c = Carol::with(setup);
        let (a, b, d) = (
            c.alice.public_key_bytes(),
            c.bob.public_key_bytes(),
            c.dave.public_key_bytes(),
        );
        let mut store = CustodyStore::open_or_create(c.dir.path()).unwrap();
        let start = 500_000 * HOUR;
        for (n, to, expires) in [
            (1u8, b, start + 10),
            (2, b, start + HOUR - 1),
            (3, b, start + 3 * HOUR),
            (4, d, start + 3 * HOUR),
        ] {
            assert_eq!(
                store
                    .deposit_letter(&[n; 32], &to, &a, &[n; 900], expires, start)
                    .unwrap(),
                CustodyCode::Ok
            );
        }
        let held = |store: &CustodyStore, now: u64| -> Vec<u8> {
            let mut held: Vec<u8> = store
                .fetch_letters(&b, None, 16, now)
                .unwrap()
                .items
                .iter()
                .map(|item| item[0])
                .collect();
            held.sort_unstable();
            held
        };
        assert_eq!(held(&store, start), [1, 2, 3], "{setup:?}");
        assert_eq!(held(&store, start + 10), [2, 3], "{setup:?}");
        // Expired letters go, and those of a party no longer pinned.
        assert_eq!(
            store.maintain(start + 10, &|key| *key != d).unwrap(),
            2,
            "{setup:?}"
        );
        assert_eq!(store.letter_usage().unwrap().0, 2, "{setup:?}");
        assert_eq!(store.maintain(start + HOUR, &|_| true).unwrap(), 1);
        assert_eq!(held(&store, start + HOUR), [3], "{setup:?}");
        assert_eq!(store.purge().unwrap(), 1, "{setup:?}");
        assert_eq!(store.letter_usage().unwrap(), (0, 0));
    }
}

/// The recipients a custodian holds letters for (nearby's background
/// advertising): unexpired letters only, newest deposit first, each once,
/// in either shape; the objects' list does not count them, a release takes
/// a recipient off, and a node without a store holds letters for nobody
/// (and none is created).
#[test]
fn held_letter_recipients_newest_first_live_only() {
    for setup in SETUPS {
        let c = Carol::with(setup);
        let (a, b, d) = (
            c.alice.public_key_bytes(),
            c.bob.public_key_bytes(),
            c.dave.public_key_bytes(),
        );
        assert!(held_letter_recipients(c.dir.path(), NOW)
            .unwrap()
            .is_empty());
        if setup != Setup::Migrated {
            assert!(!custody_db_path(c.dir.path()).exists(), "nothing created");
        }
        let mut store = CustodyStore::open_or_create(c.dir.path()).unwrap();
        for (n, to, at, expires) in [
            (1u8, b, NOW, NOW + DAY),
            (2, d, NOW + 1_000, NOW + DAY),
            (3, a, NOW + 2_000, NOW + 5_000),
            (4, b, NOW + 3_000, NOW + DAY),
        ] {
            assert_eq!(
                store
                    .deposit_letter(&[n; 32], &to, &a, &[n; 900], expires, at)
                    .unwrap(),
                CustodyCode::Ok,
                "{setup:?}"
            );
        }
        let now = NOW + 10_000;
        assert_eq!(
            held_letter_recipients(c.dir.path(), now).unwrap(),
            vec![b, d],
            "{setup:?}: newest first, expired skipped"
        );
        assert!(held_recipients(c.dir.path(), now).unwrap().is_empty());
        assert_eq!(store.release(&b, &[[1; 32], [4; 32]]).unwrap(), 2);
        assert_eq!(
            store.held_letter_recipients(now).unwrap(),
            vec![d],
            "{setup:?}"
        );
    }
}

// ── At rest ──────────────────────────────────────────────────────────────

/// The letters' columns as stored: (digest column, recipient column, letter
/// column) by rowid.
fn stored_letters(dir: &Path) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let conn = raw(dir);
    let cols = match rebuild::shape(&conn, LETTERS, LETTERS_KEYED_COLUMN).unwrap() {
        Shape::Keyed => "kh_letter_digest, kh_recipient, letter",
        _ => "letter_digest, recipient, letter",
    };
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {cols} FROM custody_letters_v1 ORDER BY rowid"
        ))
        .unwrap();
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

fn letters_shape(dir: &Path) -> Shape {
    rebuild::shape(&raw(dir), LETTERS, LETTERS_KEYED_COLUMN).unwrap()
}

/// In a sealed profile a held letter names nobody in the file: keyed
/// digest and parties, the letter sealed whole; a plain profile's is clear.
/// RELEASE leaves only the keyed digest.
#[test]
fn sealed_letters_name_nobody_and_release_leaves_the_digest() {
    for setup in SETUPS {
        let c = Carol::with(setup);
        let (a, b) = (c.alice.public_key_bytes(), c.bob.public_key_bytes());
        let letter = small(&c.alice, &c.bob, 0x71);
        let digest = letter_digest(&letter);
        let mut store = CustodyStore::open_or_create(c.dir.path()).unwrap();
        assert_eq!(
            store
                .deposit_letter(&digest, &b, &a, &letter, NOW + DAY, NOW)
                .unwrap(),
            CustodyCode::Ok
        );
        assert!(crate::paths::checkpoint_truncate(&store.conn)
            .unwrap()
            .completed());
        let keyed = setup != Setup::Plain;
        assert_eq!(
            letters_shape(c.dir.path()) == Shape::Keyed,
            keyed,
            "{setup:?}"
        );
        for needle in [a.as_slice(), b.as_slice(), &letter, &digest] {
            assert_eq!(file_or_wal_holds(c.dir.path(), needle), !keyed, "{setup:?}");
        }
        assert_eq!(
            store.fetch_letters(&b, None, 16, NOW).unwrap().items,
            std::slice::from_ref(&letter)
        );
        assert_eq!(store.release(&b, &[digest]).unwrap(), 1);
        assert!(stored_letters(c.dir.path()).is_empty());
        assert_eq!(released_count(&store), 1);
        drop(store);
        for needle in [a.as_slice(), b.as_slice(), &letter] {
            assert!(!file_or_wal_holds(c.dir.path(), needle), "{setup:?}");
        }
    }
}

/// The letters move with the store: sealing migrates a plain profile's
/// clear letters (rowids kept), `unseal` brings them back clear, the next
/// sealed open moves them forward again, `rotate-meta` keys them again and
/// a data-key rotation reseals them.
#[test]
fn letters_move_with_the_store() {
    let c = Carol::with(Setup::Plain);
    let dd = c.dir.path();
    let (a, b) = (c.alice.public_key_bytes(), c.bob.public_key_bytes());
    let letters: Vec<Vec<u8>> = (0..3u8)
        .map(|n| small(&c.alice, &c.bob, 0x80 + n))
        .collect();
    let mut store = CustodyStore::open_or_create(dd).unwrap();
    for letter in &letters {
        store
            .deposit_letter(&letter_digest(letter), &b, &a, letter, NOW + DAY, NOW)
            .unwrap();
    }
    drop(store);
    let mut want = letters.clone();
    want.sort_by_key(|l| crate::async_letter::page_token(l));
    let fetched = |dd: &Path| {
        CustodyStore::open_existing(dd)
            .unwrap()
            .unwrap()
            .fetch_letters(&b, None, 16, NOW)
            .unwrap()
            .items
    };
    let rowids = |dd: &Path| -> Vec<i64> {
        let conn = raw(dd);
        let mut stmt = conn
            .prepare("SELECT rowid FROM custody_letters_v1 ORDER BY rowid")
            .unwrap();
        let mapped = stmt.query_map([], |r| r.get(0)).unwrap();
        mapped.collect::<Result<_, _>>().unwrap()
    };
    let before = rowids(dd);
    assert_eq!(letters_shape(dd), Shape::Clear);
    // Sealing the profile moves the store, letters too.
    crate::contact_book::tests::seal(dd);
    assert_eq!(schema(dd), (SCHEMA_VERSION, Shape::Keyed));
    assert_eq!(letters_shape(dd), Shape::Keyed);
    assert_eq!(rowids(dd), before);
    assert_eq!(fetched(dd), want);
    assert!(!file_or_wal_holds(dd, &a));
    // The way back: clear, rowids kept, every letter readable.
    let back = unseal(dd).unwrap();
    assert_eq!((back.rows, back.dropped), (3, 0));
    assert_eq!(letters_shape(dd), Shape::Clear);
    assert_eq!(rowids(dd), before);
    let clear: Vec<Vec<u8>> = stored_letters(dd).into_iter().map(|r| r.2).collect();
    assert_eq!(clear, letters);
    // Forward again at the next open of the sealed profile.
    assert_eq!(fetched(dd), want);
    assert_eq!(letters_shape(dd), Shape::Keyed);
    // rotate-meta: every keyed value anew, the same letters.
    let keyed_before = stored_letters(dd);
    let to = keys_of(dd).current_epoch() + 1;
    at_rest::begin_meta_rotation(dd, to).unwrap();
    let moved = rekey(dd).unwrap();
    assert_eq!((moved.rows, moved.dropped), (3, 0));
    for (old, new) in keyed_before.iter().zip(stored_letters(dd)) {
        assert!(old.0 != new.0 && old.1 != new.1);
    }
    assert_eq!(rows_off_epoch(dd, to).unwrap(), 0);
    at_rest::drop_old_epochs(dd).unwrap();
    assert_eq!(fetched(dd), want);
    // A data-key rotation reseals them.
    let epoch = keys_of(dd).current_epoch();
    assert_eq!(epoch, to);
    at_rest::add_epoch(dd, epoch).unwrap();
    assert_eq!(rows_off_epoch(dd, epoch + 1).unwrap(), 3);
    let resealed = reseal_rows(dd).unwrap();
    assert_eq!((resealed.resealed, resealed.unreadable), (3, 0));
    assert_eq!(rows_off_epoch(dd, epoch + 1).unwrap(), 0);
    at_rest::drop_old_epochs(dd).unwrap();
    assert_eq!(fetched(dd), want);
}

/// Review C-2's rule for the letters: an older build of the pack moves the
/// objects without knowing the letters. A keyed letters table left in a
/// clear store is dropped and created clear (only while the objects are
/// clear); a clear one left in a keyed store moves forward at the open.
#[test]
fn an_older_build_of_the_pack_leaves_the_letters_behind() {
    // Unsealed by an older build: the objects clear, the letters keyed.
    let c = Carol::with(Setup::Plain);
    let dd = c.dir.path();
    drop(CustodyStore::open_or_create(dd).unwrap());
    {
        let conn = raw(dd);
        conn.execute_batch("DROP TABLE custody_letters_v1;")
            .unwrap();
        conn.execute_batch(&letters_table(LETTERS, true)).unwrap();
    }
    assert_eq!(letters_shape(dd), Shape::Keyed);
    let store = CustodyStore::open_existing(dd).unwrap().unwrap();
    assert_eq!(store.layout, Layout::Clear);
    assert_eq!(letters_shape(dd), Shape::Clear);
    assert_eq!(store.letter_usage().unwrap(), (0, 0));
    drop(store);
    // Sealed by an older build: the objects keyed, a clear letter left.
    let c = Carol::with(Setup::SealedFresh);
    let dd = c.dir.path();
    let (a, b) = (c.alice.public_key_bytes(), c.bob.public_key_bytes());
    drop(CustodyStore::open_or_create(dd).unwrap());
    let letter = small(&c.alice, &c.bob, 0x88);
    {
        let conn = raw(dd);
        conn.execute_batch("DROP TABLE custody_letters_v1;")
            .unwrap();
        conn.execute_batch(&letters_table(LETTERS, false)).unwrap();
        conn.execute(
            "INSERT INTO custody_letters_v1
               (letter_digest, recipient, depositor, page_token, letter, bytes,
                admitted_at_ms, expires_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                letter_digest(&letter).as_slice(),
                b.as_slice(),
                a.as_slice(),
                crate::async_letter::page_token(&letter).as_slice(),
                letter,
                letter.len() as i64,
                ms(NOW),
                ms(NOW + DAY),
            ],
        )
        .unwrap();
    }
    let store = CustodyStore::open_existing(dd).unwrap().unwrap();
    assert_eq!(store.layout, Layout::Keyed);
    assert_eq!(letters_shape(dd), Shape::Keyed);
    assert_eq!(
        store.fetch_letters(&b, None, 16, NOW).unwrap().items,
        [letter]
    );
}

// ── Vectors ──────────────────────────────────────────────────────────────

/// KATs of the letter ops (§10, §9 vectors). Regenerate with
/// `RAVEN_REGEN_RFC1_VECTORS=1` only when the wire format changes on
/// purpose. The base-op vectors (`rfc1_known_answer_vectors`) stay as they
/// are, byte for byte.
#[test]
fn rfc1_letter_known_answer_vectors() {
    let letter_vector = "letter/ral1_reply_001.json";
    let source: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(vectors_dir().parent().unwrap().join(letter_vector)).unwrap(),
    )
    .unwrap();
    let expected_letter = &source["expected"]["letter"];
    let letter = hex::decode(expected_letter["letter_hex"].as_str().unwrap()).unwrap();
    let header = decode_header(&letter).unwrap();
    let digest = letter_digest(&letter);
    assert_eq!(
        hex::encode(digest),
        expected_letter["letter_digest_hex"].as_str().unwrap()
    );
    let token = crate::async_letter::page_token(&letter);
    let req = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let fetch = encode_request(
        &req,
        &Rfc1Request::FetchLetters {
            after: Some([0x77; 32]),
            max_items: 2,
        },
    );
    let item_len = 18 + letter.len();
    let cases: Vec<(&str, &str, Vec<u8>, serde_json::Value)> = vec![
        (
            "rfc1_letter_deposit_001.json",
            "DEPOSIT_LETTER of the REPLY letter of letter/ral1_reply_001.json for its recipient",
            encode_request(
                &req,
                &Rfc1Request::DepositLetter {
                    recipient: header.recipient_device,
                    letter: letter.clone(),
                },
            ),
            serde_json::json!({
                "letter_vector": letter_vector,
                "recipient_hex": hex::encode(header.recipient_device),
                "letter_len": letter.len(),
                "letter_digest_hex": hex::encode(digest),
                "page_token_hex": hex::encode(token),
            }),
        ),
        (
            "rfc1_letter_fetch_001.json",
            "FETCH_LETTERS after a cursor, at most two letters",
            fetch.clone(),
            serde_json::json!({}),
        ),
        (
            "rfc1_letter_withdraw_001.json",
            "WITHDRAW_LETTERS of that letter's digest",
            encode_request(
                &req,
                &Rfc1Request::WithdrawLetters {
                    digests: vec![digest],
                },
            ),
            serde_json::json!({ "letter_digest_hex": hex::encode(digest) }),
        ),
        (
            "rfc1_letter_replies_001.json",
            "DEPOSIT_RESULT STORED for the letter, LETTER_ITEM, FETCH_END and WITHDRAW_RESULT, concatenated",
            [
                encode_reply(
                    &req,
                    &Rfc1Reply::DepositResult {
                        code: CustodyCode::Ok,
                        digest,
                    },
                ),
                encode_reply(
                    &req,
                    &Rfc1Reply::LetterItem {
                        letter: letter.clone(),
                    },
                ),
                encode_reply(
                    &req,
                    &Rfc1Reply::FetchEnd {
                        code: CustodyCode::Ok,
                        returned: 1,
                        next: None,
                    },
                ),
                encode_reply(
                    &req,
                    &Rfc1Reply::WithdrawResult {
                        code: CustodyCode::Ok,
                        withdrawn: 1,
                    },
                ),
            ]
            .concat(),
            serde_json::json!({
                "letter_vector": letter_vector,
                "frame_lengths": [47, item_len, 49, 16],
            }),
        ),
        (
            "rfc1_letter_on_base_listener_001.json",
            "A listener without the letter ops (built before them, letter gate closed, or RAVEN_LAB_CUSTODY_BASE_OPS_ONLY=1) answers FETCH_LETTERS with UNSUPPORTED, max_version 1, echoing req_id",
            unsupported(&req),
            serde_json::json!({ "request_frame_hex": hex::encode(&fetch) }),
        ),
    ];
    for (name, what, bytes, extra) in cases {
        let expected = serde_json::json!({
            "name": what,
            "protocol_version": "rvn1",
            "deterministic": true,
            "description": "RFC1 letter custody frame(s) (RAVEN_FRIEND_CUSTODY_V1.md §10); header magic RFC1 | version 1 | op | req_id[8]",
            "inputs": extra,
            "expected": { "frame_hex": hex::encode(&bytes), "frame_len": bytes.len() },
        });
        let path = vectors_dir().join(name);
        if std::env::var("RAVEN_REGEN_RFC1_VECTORS").as_deref() == Ok("1") {
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&expected).unwrap() + "\n",
            )
            .unwrap();
        }
        let stored: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(stored, expected, "{name}");
    }
    // The bytes mean what they say: the requests decode back, and a listener
    // with the letter ops off answers the FETCH_LETTERS vector's request with
    // exactly the vector's reply.
    assert_eq!(
        decode_request(&fetch).unwrap(),
        RequestDecode::Request(
            req,
            Rfc1Request::FetchLetters {
                after: Some([0x77; 32]),
                max_items: 2
            }
        )
    );
    let c = Carol::new();
    let _l = Letters::with(true, true);
    let replies = handle_frame(
        c.dir.path(),
        &c.carol,
        &c.alice.public_key_bytes(),
        &lan("192.168.1.20"),
        &fetch,
        NOW,
    )
    .unwrap();
    assert_eq!(replies, [unsupported(&req)]);
}
