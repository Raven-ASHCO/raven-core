//! The letter ops from the requester's side (P5.14) against Carol's real
//! handler: deposit, a fetch round that releases a letter only after its
//! intake committed, withdraw, and the capability cache.

use super::*;
use crate::async_letter::intake::tests::{letter_world, now, LetterWorld, LettersOn, DAY_MS};
use crate::friend_custody::{
    handle_frame, set_lab_base_ops_only_for_this_thread, CustodyStore, InboundLink,
};
use crate::outbox::OutboxCarrier;

impl LetterWorld {
    /// A dial to Carol from `who` over a local LAN link, every frame to
    /// Carol's real handler; `log` records each dial's request ops.
    fn dial_carol<'a>(
        &'a self,
        who: &'a Identity,
        log: &'a std::cell::RefCell<Vec<Vec<u8>>>,
    ) -> impl FnMut(&[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> + 'a {
        move |frames: &[Vec<u8>]| {
            log.borrow_mut()
                .push(frames.iter().map(|frame| frame[5]).collect());
            let link = InboundLink {
                carrier: OutboxCarrier::Lan,
                source: Some("192.168.1.30".parse().unwrap()),
            };
            let mut out = vec![b"RLB1-offer".to_vec()];
            let _untouched = crate::lan_gate::lan_user_switch_untouched();
            for frame in frames {
                out.extend(handle_frame(
                    self.c.path(),
                    &self.carol,
                    &who.public_key_bytes(),
                    &link,
                    frame,
                    now(),
                )?);
            }
            Ok(out)
        }
    }

    /// Letters Carol holds.
    fn carol_holds(&self) -> i64 {
        CustodyStore::open_existing(self.c.path())
            .unwrap()
            .map_or(0, |store| store.letter_usage().unwrap().0)
    }

    /// One letter from Alice to Bob in a new letter session, carrying `text`.
    fn one_letter(&self, text: &str) -> Vec<u8> {
        let (init, key) = self.letter_session();
        let t = now();
        let expires = t + 2 * DAY_MS;
        let packed = [self.seal(&key, text, expires)];
        self.letter(&init, &packed, t, expires)
    }
}

const RELEASE: u8 = crate::friend_custody::OP_RELEASE;

/// Alice leaves a letter with Carol; Bob's round fetches it alone (no
/// RELEASE in that dial), takes it, and releases it in a release-only dial
/// that goes out only once the message is in his inbox. A letter
/// whose intake hits a store error (an unreadable contact book) stops the
/// round and stays at Carol, unreleased, until a later round takes it.
#[test]
fn fetch_letters_round_releases_only_after_commit() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = LettersOn::new();
    let w = letter_world(0x51);
    let log = std::cell::RefCell::new(Vec::new());
    let mut caps = CapabilityCache::default();
    let letter = w.one_letter("kept until taken");
    let answers = deposit_letters(
        &w.carol.public_key_bytes(),
        &[LetterDeposit {
            recipient: w.bob_key(),
            letter: letter.clone(),
        }],
        &mut caps,
        now(),
        &mut w.dial_carol(&w.alice, &log),
    )
    .unwrap();
    assert_eq!(answers, vec![Some(LetterAnswer::Code(CustodyCode::Ok))]);
    assert!(answers[0].unwrap().held());
    assert_eq!(caps.letters(&w.carol.public_key_bytes(), now()), Some(true));
    assert_eq!(w.carol_holds(), 1);

    // A store error first: nothing released, the round stops.
    let book = std::fs::read(w.b.path().join("contacts.json")).unwrap();
    std::fs::write(w.b.path().join("contacts.json"), b"[{").unwrap();
    let mut state = LetterFetchState::default();
    let mut bob_caps = CapabilityCache::default();
    let carol = w.carol.public_key_bytes();
    log.borrow_mut().clear();
    let stopped = fetch_letters_round(
        w.b.path(),
        &w.bob,
        &carol,
        &mut state,
        &mut bob_caps,
        now(),
        8,
        &mut w.dial_carol(&w.bob, &log),
    );
    assert_eq!(stopped.letters, 1, "{stopped:?}");
    assert_eq!((stopped.kept, stopped.accepted), (1, 0));
    assert_eq!(stopped.store_trouble, Some("LETTER_STORE"));
    assert_eq!(stopped.codes, vec![Ral1Error::Store]);
    assert!(state.pending_release.is_empty());
    assert_eq!(w.carol_holds(), 1);
    std::fs::write(w.b.path().join("contacts.json"), book).unwrap();

    // Taken, then released in the next dial, after the commit.
    log.borrow_mut().clear();
    let inbox_at_release = std::cell::RefCell::new(None);
    let mut inner = w.dial_carol(&w.bob, &log);
    let mut dial = |frames: &[Vec<u8>]| {
        if frames.iter().any(|frame| frame[5] == RELEASE) {
            *inbox_at_release.borrow_mut() = Some(w.bob_inbox().len());
        }
        inner(frames)
    };
    let report = fetch_letters_round(
        w.b.path(),
        &w.bob,
        &carol,
        &mut LetterFetchState::default(),
        &mut bob_caps,
        now(),
        8,
        &mut dial,
    );
    assert_eq!(
        (
            report.letters,
            report.accepted,
            report.messages,
            report.released
        ),
        (1, 1, 1, 1),
        "{report:?}"
    );
    assert_eq!(report.touched, vec![w.alice_key()]);
    let dials = log.borrow().clone();
    assert_eq!(
        dials,
        vec![vec![crate::friend_custody::OP_FETCH_LETTERS], vec![RELEASE]]
    );
    assert_eq!(*inbox_at_release.borrow(), Some(1));
    assert_eq!(w.carol_holds(), 0);
    // Nothing left: a later round fetches nothing.
    let quiet = fetch_letters_round(
        w.b.path(),
        &w.bob,
        &carol,
        &mut LetterFetchState::default(),
        &mut bob_caps,
        now(),
        8,
        &mut w.dial_carol(&w.bob, &log),
    );
    assert_eq!((quiet.letters, quiet.dials), (0, 1));
}

/// A letter whose end passes while it waits at Carol is refused by Bob's
/// intake as expired and released, so Carol drops it.
#[test]
fn an_expired_letter_is_released_at_the_custodian() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = LettersOn::new();
    let w = letter_world(0x55);
    let log = std::cell::RefCell::new(Vec::new());
    let mut caps = CapabilityCache::default();
    let carol = w.carol.public_key_bytes();
    let (init, key) = w.letter_session();
    let t = now();
    let expires = t + 3_600_000;
    let letter = w.letter(&init, &[w.seal(&key, "an hour", expires)], t, expires);
    let answers = deposit_letters(
        &carol,
        &[LetterDeposit {
            recipient: w.bob_key(),
            letter,
        }],
        &mut caps,
        now(),
        &mut w.dial_carol(&w.alice, &log),
    )
    .unwrap();
    assert!(answers[0].unwrap().held());
    let report = fetch_letters_round(
        w.b.path(),
        &w.bob,
        &carol,
        &mut LetterFetchState::default(),
        &mut caps,
        expires,
        8,
        &mut w.dial_carol(&w.bob, &log),
    );
    assert_eq!(
        (report.letters, report.refused, report.released),
        (1, 1, 1),
        "{report:?}"
    );
    assert_eq!(report.codes, vec![Ral1Error::Expired]);
    assert!(report.touched.is_empty());
    assert_eq!(w.carol_holds(), 0);
}

/// One cache per custodian: an UNSUPPORTED to a letter op says "no
/// letters" for 24 h (no dial meanwhile: deposits answer Unsupported, a
/// round makes no dial), any served answer says "letters"; the handoff
/// family is learned on its own, and a base op teaches nothing.
/// A working copy (`only`) carries one custodian's answers with the times
/// they were learned; `absorb` takes back the newer ones per family and
/// never makes an old answer younger (an UNSUPPORTED still lapses after
/// 24 h however often it is copied).
#[test]
fn capability_cache_copies_one_custodian_and_absorbs_newer_answers() {
    let (c, d) = ([0xC1; 32], [0xD1; 32]);
    let t = 1_000_000;
    let mut cache = CapabilityCache::default();
    cache.note(&c, CustodianCapability::Handoff, false, t);
    cache.note(&c, CustodianCapability::Letters, true, t);
    cache.note(&d, CustodianCapability::Handoff, true, t);
    let copy = cache.only(&c);
    assert_eq!(copy.len(), 1);
    assert_eq!(copy.handoff(&c, t + 1), Some(false));
    assert_eq!(copy.letters(&c, t + 1), Some(true));
    assert_eq!(copy.handoff(&d, t + 1), None);
    // Handed back unchanged later: still learned at `t`.
    let later = t + CAPABILITY_TTL_MS - 1;
    cache.absorb(copy);
    assert_eq!(cache.handoff(&c, later), Some(false));
    assert_eq!(cache.handoff(&c, t + CAPABILITY_TTL_MS), None, "lapsed");
    // A copy that learned something newer wins for that family only.
    let mut copy = cache.only(&c);
    copy.note(&c, CustodianCapability::Handoff, true, t + 5);
    cache.absorb(copy);
    assert_eq!(cache.handoff(&c, t + 6), Some(true));
    assert_eq!(cache.letters(&c, t + 6), Some(true));
    assert_eq!(cache.handoff(&d, t + 6), Some(true), "others untouched");
    // An empty copy (an unknown custodian) adds nothing.
    cache.absorb(cache.only(&[0xEE; 32]));
    assert_eq!(cache.len(), 2);
}

#[test]
fn capability_cache_from_unsupported_and_success() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = LettersOn::new();
    let w = letter_world(0x59);
    let carol = w.carol.public_key_bytes();
    let log = std::cell::RefCell::new(Vec::new());
    let mut caps = CapabilityCache::default();
    let t = now();
    assert_eq!(caps.letters(&carol, t), None);
    // Carol serves the base ops only.
    set_lab_base_ops_only_for_this_thread(Some(true));
    let letter = w.one_letter("base ops only");
    let deposit = || LetterDeposit {
        recipient: w.bob_key(),
        letter: letter.clone(),
    };
    let answers = deposit_letters(
        &carol,
        &[deposit()],
        &mut caps,
        t,
        &mut w.dial_carol(&w.alice, &log),
    )
    .unwrap();
    assert_eq!(answers, vec![Some(LetterAnswer::Unsupported)]);
    assert!(!answers[0].unwrap().held());
    assert_eq!(caps.letters(&carol, t), Some(false));
    assert_eq!(caps.handoff(&carol, t), None);
    assert_eq!(log.borrow().len(), 1);
    // Known without letters: no dial for a deposit, a withdraw or a fetch.
    let again = deposit_letters(
        &carol,
        &[deposit()],
        &mut caps,
        t + 1,
        &mut w.dial_carol(&w.alice, &log),
    )
    .unwrap();
    assert_eq!(again, vec![Some(LetterAnswer::Unsupported)]);
    let withdrawn = withdraw_letters(
        &carol,
        &[[7; 32]],
        &mut caps,
        t + 1,
        &mut w.dial_carol(&w.alice, &log),
    )
    .unwrap();
    assert_eq!(withdrawn.answers, vec![Some(LetterAnswer::Unsupported)]);
    let skipped = fetch_letters_round(
        w.b.path(),
        &w.bob,
        &carol,
        &mut LetterFetchState::default(),
        &mut caps,
        t + 1,
        8,
        &mut w.dial_carol(&w.bob, &log),
    );
    assert_eq!(skipped.dials, 0);
    assert_eq!(log.borrow().len(), 1);
    // A fresh fetch round learns it too.
    let mut bob_caps = CapabilityCache::default();
    let unsupported = fetch_letters_round(
        w.b.path(),
        &w.bob,
        &carol,
        &mut LetterFetchState::default(),
        &mut bob_caps,
        t,
        8,
        &mut w.dial_carol(&w.bob, &log),
    );
    assert!(unsupported.unsupported);
    assert_eq!(unsupported.dials, 1);
    assert_eq!(bob_caps.letters(&carol, t), Some(false));
    // 24 h later it is unknown again; Carol serves letters now: learned yes.
    set_lab_base_ops_only_for_this_thread(None);
    let later = t + CAPABILITY_TTL_MS;
    assert_eq!(caps.letters(&carol, later), None);
    let served = deposit_letters(
        &carol,
        &[deposit()],
        &mut caps,
        later,
        &mut w.dial_carol(&w.alice, &log),
    )
    .unwrap();
    assert_eq!(served, vec![Some(LetterAnswer::Code(CustodyCode::Ok))]);
    assert_eq!(caps.letters(&carol, later), Some(true));
    // A served answer whatever its code: the same letter is DUPLICATE.
    let dup = deposit_letters(
        &carol,
        &[deposit()],
        &mut caps,
        later,
        &mut w.dial_carol(&w.alice, &log),
    )
    .unwrap();
    assert_eq!(dup, vec![Some(LetterAnswer::Code(CustodyCode::Duplicate))]);
    // Withdraw by the depositor: one letter gone, served.
    let gone = withdraw_letters(
        &carol,
        &[crate::async_letter::letter_digest(&letter); 2],
        &mut caps,
        later,
        &mut w.dial_carol(&w.alice, &log),
    )
    .unwrap();
    assert_eq!(gone.withdrawn, 1);
    assert_eq!(
        gone.answers,
        vec![Some(LetterAnswer::Code(CustodyCode::Ok))]
    );
    // The families are learned apart; base ops teach nothing.
    caps.learn(
        &carol,
        0x07,
        &Rfc1Reply::Unsupported { max_version: 1 },
        later,
    );
    assert_eq!(caps.handoff(&carol, later), Some(false));
    assert_eq!(caps.letters(&carol, later), Some(true));
    caps.learn(
        &carol,
        crate::friend_custody::OP_DEPOSIT,
        &Rfc1Reply::Unsupported { max_version: 1 },
        later,
    );
    assert_eq!(caps.letters(&carol, later), Some(true));
    assert_eq!(
        CustodianCapability::of_op(0x08),
        Some(CustodianCapability::Handoff)
    );
    assert_eq!(
        CustodianCapability::of_op(crate::friend_custody::OP_RELEASE),
        None
    );
    // A clock set back by more than a day forgets too; prune drops what is
    // known of nobody any more.
    assert_eq!(caps.letters(&carol, later - CAPABILITY_TTL_MS), None);
    caps.note(&[9; 32], CustodianCapability::Letters, true, t);
    assert_eq!(caps.len(), 2);
    caps.prune(later + 1);
    assert_eq!(caps.len(), 1);
    caps.forget(&carol);
    assert!(caps.is_empty());
}

/// With the letter gate closed nothing is dialled: deposits and withdraws
/// say so (not a dial error), a round does nothing.
#[test]
fn letter_ops_are_not_sent_while_the_gate_is_closed() {
    let w = letter_world(0x5d);
    let carol = w.carol.public_key_bytes();
    let log = std::cell::RefCell::new(Vec::new());
    let mut caps = CapabilityCache::default();
    crate::horizon::set_lab_letter_for_this_thread(Some(false));
    let item = LetterDeposit {
        recipient: w.bob_key(),
        letter: vec![0; 800],
    };
    assert_eq!(
        deposit_letters(
            &carol,
            &[item],
            &mut caps,
            now(),
            &mut w.dial_carol(&w.alice, &log)
        ),
        Err(letter_gate_closed())
    );
    assert!(letter_gate_closed().starts_with("LETTER_GATE"));
    assert_eq!(
        withdraw_letters(
            &carol,
            &[[1; 32]],
            &mut caps,
            now(),
            &mut w.dial_carol(&w.alice, &log)
        ),
        Err(letter_gate_closed())
    );
    let report = fetch_letters_round(
        w.b.path(),
        &w.bob,
        &carol,
        &mut LetterFetchState::default(),
        &mut caps,
        now(),
        8,
        &mut w.dial_carol(&w.bob, &log),
    );
    assert_eq!(report, LetterFetchReport::default());
    assert!(log.borrow().is_empty());
    assert!(caps.is_empty());
    crate::horizon::set_lab_letter_for_this_thread(None);
}

/// Review letters-4: one letter session's letters fall on two FETCH_LETTERS
/// pages (16 letters a page, listed in page-token order, here with its
/// first letter listed last): Bob's round takes every letter of both pages
/// in the order Alice wrote them, so his inbox is in send order, and
/// releases them once taken.
#[test]
fn a_session_split_over_two_pages_reaches_the_inbox_in_order() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _on = LettersOn::new();
    let w = letter_world(0x91);
    let carol = w.carol.public_key_bytes();
    let log = std::cell::RefCell::new(Vec::new());
    let (other, other_key) = w.letter_session();
    let (init, key) = w.letter_session();
    // Written after both sessions started.
    let t = now() + 1;
    let expires = t + 2 * DAY_MS;
    // Another session's letter, written first.
    let earlier = w.letter(
        &other,
        &[w.seal(&other_key, "earlier", expires)],
        t - 1,
        expires,
    );
    let sealed: Vec<Vec<u8>> = (0..16)
        .map(|i| w.seal(&key, &format!("m{i}"), expires))
        .collect();
    let mut letters: Vec<Vec<u8>> = sealed
        .iter()
        .enumerate()
        .map(|(i, env)| w.letter(&init, std::slice::from_ref(env), t + i as u64, expires))
        .collect();
    let token = crate::async_letter::page_token;
    let largest = letters[1..]
        .iter()
        .chain([&earlier])
        .map(|letter| token(letter))
        .max()
        .unwrap();
    while token(&letters[0]) <= largest {
        letters[0] = w.letter(&init, &sealed[..1], t, expires);
    }
    let items: Vec<LetterDeposit> = std::iter::once(earlier)
        .chain(letters)
        .map(|letter| LetterDeposit {
            recipient: w.bob_key(),
            letter,
        })
        .collect();
    let mut caps = CapabilityCache::default();
    for chunk in items.chunks(MAX_DEPOSITS_PER_DIAL) {
        let answers = deposit_letters(
            &carol,
            chunk,
            &mut caps,
            now(),
            &mut w.dial_carol(&w.alice, &log),
        )
        .unwrap();
        assert!(answers.iter().all(|a| a.is_some_and(LetterAnswer::held)));
    }
    assert_eq!(w.carol_holds(), 17);
    log.borrow_mut().clear();
    let report = fetch_letters_round(
        w.b.path(),
        &w.bob,
        &carol,
        &mut LetterFetchState::default(),
        &mut CapabilityCache::default(),
        now(),
        8,
        &mut w.dial_carol(&w.bob, &log),
    );
    assert_eq!(
        (report.letters, report.accepted, report.released),
        (17, 17, 17),
        "{report:?}"
    );
    let want: Vec<String> = std::iter::once("earlier".to_string())
        .chain((0..16).map(|i| format!("m{i}")))
        .collect();
    let inbox: Vec<String> = w.bob_inbox().into_iter().map(|(_, text)| text).collect();
    assert_eq!(inbox, want);
    let fetch = crate::friend_custody::OP_FETCH_LETTERS;
    assert_eq!(
        log.borrow().clone(),
        vec![vec![fetch], vec![fetch], vec![RELEASE]]
    );
    assert_eq!(w.carol_holds(), 0);
}

/// Phase 6b P6.25 (S20): a bad letter is noted as `SEC_LETTER_BAD` about
/// the custodian that served it (its signature failed) or about its sender
/// (signed, but what it carries did not hold), fetched from that custodian.
#[test]
fn a_bad_letter_is_noted_about_its_custodian_or_its_sender() {
    use crate::security_events::{Attribution, CarrierRole, SecKind, Via};
    use crate::security_sense::tests::{Capture, Shut};
    let custodian = [0xCA; 32];
    let sender = [0x5E; 32];
    {
        let shut = Shut::start();
        note_bad_letter(&custodian, Some(BadLetter::Carrier));
        assert_eq!(shut.noted(), 0);
    }
    let Some(cap) = Capture::start() else {
        return;
    };
    note_bad_letter(&custodian, None);
    note_bad_letter(&custodian, Some(BadLetter::Carrier));
    note_bad_letter(&custodian, Some(BadLetter::Sender(sender)));
    let via = Via::Custodian(custodian);
    assert_eq!(
        cap.kinds(),
        vec![
            (
                SecKind::LetterBad,
                Attribution::Carrier {
                    carrier: custodian,
                    role: CarrierRole::Custodian
                },
                via
            ),
            (
                SecKind::LetterBad,
                Attribution::Contact { peer: sender },
                via
            ),
        ]
    );
}
