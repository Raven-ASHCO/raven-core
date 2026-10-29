//! RLK1 knock keys, tags, proofs, the replay cache and both decision tables
//! (RAVEN_LINK_KNOCK_V1), and the vectors `shared-vectors/rvn1/link/rlk1_*`
//! and `link/negative/rlk1_*`. The vectors are written only under
//! `RAVEN_REGEN_SECURITY_VECTORS=1` (a deliberate wire change) and otherwise
//! compared with the committed files; the Python reference
//! (`protocol/reference/raven_protocol/link_knock.py`) checks every one.
//! The full handshake (`lan/noise_xx_handshake_003.json`) is in
//! `crate::lan_vectors`.

use super::*;
use crate::route_hints::{rlx1_caps, EXT_PAD};
use crate::CAP_LINK_RRH1;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::{json, Value};

const REGEN: &str = "RAVEN_REGEN_SECURITY_VECTORS";

/// RFC 8032 section 7.1 tests 1-3 (the people of the beacon vectors).
const ALICE: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const BOB: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const CAROL: &str = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";

/// 2026-10-23 12:00 UTC.
const NOW_MS: u64 = 1_792_756_800_000;

fn id(seed: &str) -> Identity {
    Identity::from_seed(&hex::decode(seed).unwrap().try_into().unwrap())
}

fn keys(own: &str, peer: &str) -> KnockKeys {
    knock_keys(&id(own), &id(peer).public_key_bytes()).unwrap()
}

/// The X25519 public key of a fixed scalar (the vectors' ephemerals and
/// statics).
fn x_pub(scalar: u8) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([scalar; 32])).to_bytes()
}

/// 16 counting bytes from `first`: the vectors' nonces.
fn counting(first: u8) -> [u8; 16] {
    std::array::from_fn(|i| first.wrapping_add(i as u8))
}

fn raw_m1(e: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    [e.as_slice(), payload].concat()
}

fn rng() -> StdRng {
    StdRng::seed_from_u64(0x524c_4b31)
}

/// Both ends derive the same keys in mirror image, each direction its own,
/// and none is the beacon's: medium 0x03.
#[test]
fn keys_mirror_and_directions_differ() {
    let (a, b) = (keys(ALICE, BOB), keys(BOB, ALICE));
    let (nonce, e, s) = (counting(1), x_pub(0x11), x_pub(0x33));
    let day = day_of(NOW_MS);
    assert_eq!(a.tag_out(day, &nonce, &e), b.tag_in(day, &nonce, &e));
    assert_eq!(b.tag_out(day, &nonce, &e), a.tag_in(day, &nonce, &e));
    assert_ne!(a.tag_out(day, &nonce, &e), b.tag_out(day, &nonce, &e));
    assert_eq!(b.proof_out(&nonce, &e, &s), a.proof_in(&nonce, &e, &s));
    assert_ne!(a.proof_out(&nonce, &e, &s), b.proof_out(&nonce, &e, &s));
    // A tag is not a proof (labels and keys differ).
    assert_ne!(a.tag_out(day, &nonce, &e), a.proof_out(&nonce, &e, &s));
    let alice = id(ALICE);
    let bob_pub = id(BOB).public_key_bytes();
    let root = pair_root(&alice, &bob_pub).unwrap();
    assert_eq!(
        *link_key(&alice, &bob_pub).unwrap(),
        *medium_key(&root, 0x03)
    );
    assert_ne!(
        *link_key(&alice, &bob_pub).unwrap(),
        *medium_key(&root, crate::lan_beacon::MEDIUM_LAN)
    );
    assert_eq!(format!("{a:?}"), "KnockKeys(..)");
    // The beacon's key checks: no keys with oneself.
    assert!(knock_keys(&alice, &alice.public_key_bytes()).is_err());
}

/// A knock is 32-63 bytes, matches its contact in a book of many on the
/// listener's day and the days next to it, and nobody else; another length,
/// a changed byte or two matches is no match.
#[test]
fn a_knock_matches_its_contact_only() {
    let mut r = rng();
    let alice_to_bob = keys(ALICE, BOB);
    let bob = id(BOB);
    let others: Vec<KnockKeys> = (1..=40u8)
        .map(|i| knock_keys(&bob, &Identity::from_seed(&[i; 32]).public_key_bytes()).unwrap())
        .collect();
    let mut book = others;
    book.insert(17, keys(BOB, ALICE));
    let alice = id(ALICE).public_key_bytes();
    let day = day_of(NOW_MS);
    let mut lengths = std::collections::BTreeSet::new();
    for _ in 0..200 {
        let e = x_pub(r.next_u32() as u8 | 1);
        let (payload, nonce) = m1_payload(&alice_to_bob, day, &e, &mut r);
        assert!((M1_PAYLOAD_MIN..=M1_PAYLOAD_MAX).contains(&payload.len()));
        lengths.insert(payload.len());
        let m1 = raw_m1(&e, &payload);
        for listener_day in [day - 1, day, day + 1] {
            assert_eq!(
                match_m1(&book, &m1, listener_day),
                Some(M1Match {
                    index: 17,
                    peer: alice,
                    nonce,
                    e
                })
            );
        }
        assert_eq!(match_m1(&book, &m1, day - 2), None);
        assert_eq!(match_m1(&book, &m1, day + 2), None);
    }
    assert!(lengths.len() > 20, "random pads: {lengths:?}");
    let e = x_pub(0x11);
    let (payload, _) = m1_payload(&alice_to_bob, day, &e, &mut r);
    let m1 = raw_m1(&e, &payload);
    // Every byte of e, nonce and tag counts; the pad does not.
    for i in 0..E_LEN + M1_PAYLOAD_MIN {
        let mut bad = m1.clone();
        bad[i] ^= 0x01;
        assert_eq!(match_m1(&book, &bad, day), None, "byte {i}");
    }
    for i in E_LEN + M1_PAYLOAD_MIN..m1.len() {
        let mut padded = m1.clone();
        padded[i] ^= 0x01;
        assert!(match_m1(&book, &padded, day).is_some(), "pad byte {i}");
    }
    // Lengths: no payload (an older dialer), too short, too long.
    assert_eq!(match_m1(&book, &e, day), None);
    assert_eq!(
        match_m1(&book, &m1[..E_LEN + M1_PAYLOAD_MIN - 1], day),
        None
    );
    let mut long = raw_m1(
        &e,
        &m1_payload_with(&alice_to_bob, day, &e, &counting(9), &[]),
    );
    long.extend_from_slice(&[0; PAD_MAX + 1]);
    assert_eq!(match_m1(&book, &long, day), None);
    assert_eq!(match_m1(&book, &m1[..20], day), None);
    assert_eq!(match_m1(&[], &m1, day), None);
    // The same contact twice: two matches, no answer.
    let twice = vec![keys(BOB, ALICE), keys(BOB, ALICE)];
    assert_eq!(match_m1(&twice, &m1, day), None);
    // Only the first MAX_BOOK_KEYS key sets are tried (1,024 contacts with
    // up to three sets each: pair seeds, Phase 6b).
    let mut big: Vec<KnockKeys> = (0..MAX_BOOK_KEYS - 1).map(|_| keys(BOB, CAROL)).collect();
    big.push(keys(BOB, ALICE));
    assert!(match_m1(&big, &m1, day).is_some());
    big.insert(0, keys(BOB, CAROL));
    assert_eq!(match_m1(&big, &m1, day), None);
    // The days at the ends of u32 do not wrap.
    let edge = raw_m1(
        &e,
        &m1_payload_with(&alice_to_bob, 0, &e, &counting(3), &[]),
    );
    assert!(match_m1(&book, &edge, 0).is_some());
    assert!(match_m1(&book, &edge, 1).is_some());
    assert_eq!(match_m1(&book, &edge, u32::MAX), None);
}

/// A proof verifies only for its nonce, ephemeral and static, at any pad;
/// an unmatched message 2 payload has the same lengths and never verifies.
#[test]
fn a_proof_binds_the_knock_and_the_listeners_static() {
    let mut r = rng();
    let (a, b) = (keys(ALICE, BOB), keys(BOB, ALICE));
    let (nonce, e, s) = (counting(1), x_pub(0x11), x_pub(0x33));
    let mut matched = std::collections::BTreeSet::new();
    let mut unmatched = std::collections::BTreeSet::new();
    for _ in 0..300 {
        let p = m2_payload(&b, &nonce, &e, &s, &mut r);
        assert!(check_m2(&a, &nonce, &e, &s, &p));
        matched.insert(p.len());
        let u = m2_payload_unmatched(&mut r);
        assert!(!check_m2(&a, &nonce, &e, &s, &u));
        unmatched.insert(u.len());
    }
    let span: std::collections::BTreeSet<usize> = (M2_PAYLOAD_MIN..=M2_PAYLOAD_MAX).collect();
    assert_eq!(matched, span);
    assert_eq!(unmatched, span, "a replayer cannot tell a match by length");
    let p = m2_payload_with(&b, &nonce, &e, &s, &[0xEE; 5]);
    assert!(!check_m2(&a, &counting(2), &e, &s, &p));
    assert!(!check_m2(&a, &nonce, &x_pub(0x12), &s, &p));
    assert!(
        !check_m2(&a, &nonce, &e, &x_pub(0x34), &p),
        "another static"
    );
    assert!(!check_m2(&keys(ALICE, CAROL), &nonce, &e, &s, &p));
    // Bob's proof for his own knocks' direction is not Alice's.
    assert!(!check_m2(&b, &nonce, &e, &s, &p));
    assert!(!check_m2(&a, &nonce, &e, &s, &p[..PROOF_LEN - 1]));
    assert!(!check_m2(&a, &nonce, &e, &s, &[]));
    let mut long = p.clone();
    long.resize(M2_PAYLOAD_MAX + 1, 0);
    assert!(!check_m2(&a, &nonce, &e, &s, &long));
    // Longer pads are cut to 31.
    assert_eq!(
        m2_payload_with(&b, &nonce, &e, &s, &[1; 40]).len(),
        M2_PAYLOAD_MAX
    );
    assert_eq!(
        m1_payload_with(&a, 1, &e, &nonce, &[1; 40]).len(),
        M1_PAYLOAD_MAX
    );
}

/// A matched nonce is a replay the second time, for three days; past 4,096
/// nonces the oldest goes.
#[test]
fn the_replay_cache_remembers_matched_nonces_for_three_days() {
    let mut cache = ReplayCache::new();
    assert!(cache.is_empty());
    assert!(!cache.replayed(&counting(1), NOW_MS));
    assert!(cache.replayed(&counting(1), NOW_MS + 1));
    assert!(cache.replayed(&counting(1), NOW_MS + REPLAY_TTL_MS - 1));
    assert!(!cache.replayed(&counting(2), NOW_MS + 5));
    assert_eq!(cache.len(), 2);
    // Expired: forgotten (and remembered again from now).
    assert!(!cache.replayed(&counting(1), NOW_MS + REPLAY_TTL_MS));
    assert!(cache.replayed(&counting(1), NOW_MS + REPLAY_TTL_MS + 1));
    // A clock that went back keeps what it has.
    assert!(cache.replayed(&counting(1), NOW_MS));
    let mut full = ReplayCache::new();
    for i in 0..REPLAY_ENTRIES as u32 {
        let mut n = [0u8; 16];
        n[..4].copy_from_slice(&i.to_be_bytes());
        assert!(!full.replayed(&n, NOW_MS));
    }
    assert_eq!(full.len(), REPLAY_ENTRIES);
    assert!(!full.replayed(&[0xFF; 16], NOW_MS));
    assert_eq!(full.len(), REPLAY_ENTRIES);
    assert!(!full.replayed(&[0; 16], NOW_MS), "the oldest went");
    let mut second = [0u8; 16];
    second[3] = 2;
    assert!(full.replayed(&second, NOW_MS));
}

/// Phase 6 review (traffic-9): a knock first matched early on the
/// listener's day D-1, tagged D (a dialer's clock ahead), still matches on
/// day D+1, two and a half days later: it is a replay then, which a cache
/// that forgot it after two days answered as a fresh match.
#[test]
fn a_knock_stays_a_replay_for_its_whole_acceptance_window() {
    let mut r = rng();
    let book = vec![keys(BOB, ALICE)];
    let tag_day = day_of(NOW_MS);
    let first = u64::from(tag_day - 1) * DAY_MS + 3_600_000;
    let e = x_pub(0x21);
    let (payload, _) = m1_payload(&keys(ALICE, BOB), tag_day, &e, &mut r);
    let m1 = raw_m1(&e, &payload);
    let mut replays = ReplayCache::new();
    let heard = bob_hears(
        &book,
        ListenerMode::Legacy,
        &m1,
        first,
        &mut replays,
        &mut r,
    );
    assert!(heard.matched.is_some() && !heard.replay);
    let later = first + 5 * DAY_MS / 2;
    assert_eq!(day_of(later), tag_day + 1, "still in the knock's window");
    let again = bob_hears(
        &book,
        ListenerMode::Legacy,
        &m1,
        later,
        &mut replays,
        &mut r,
    );
    assert!(again.replay, "a replay");
    assert_eq!(again.matched, None);
    // Past the window it matches nothing anyway.
    let gone = first + 3 * DAY_MS;
    assert!(match_m1(&book, &m1, day_of(gone)).is_none());
}

/// Phase 6 review (traffic-9): the cache as raven-node keeps it in the
/// profile: a nonce matched before is still a replay in a cache made from
/// those bytes (a restart); what is past its time is gone; at most 4,096
/// are read, the newest; bytes of another version or length are an empty
/// cache.
#[test]
fn the_replay_cache_survives_its_bytes() {
    let mut cache = ReplayCache::new();
    assert!(!cache.replayed(&counting(1), NOW_MS));
    assert!(!cache.replayed(&counting(2), NOW_MS + 5));
    let bytes = cache.encode();
    assert_eq!(bytes.len(), 1 + 2 * 24);
    assert_eq!(bytes[0], 1, "version 1");
    let mut restarted = ReplayCache::decode(&bytes, NOW_MS + DAY_MS);
    assert_eq!(
        restarted.entries().collect::<Vec<_>>(),
        cache.entries().collect::<Vec<_>>()
    );
    assert!(restarted.replayed(&counting(1), NOW_MS + DAY_MS));
    assert!(restarted.replayed(&counting(2), NOW_MS + DAY_MS));
    assert!(!restarted.replayed(&counting(3), NOW_MS + DAY_MS));
    // Past its time: gone.
    let late = ReplayCache::decode(&bytes, NOW_MS + REPLAY_TTL_MS);
    assert_eq!(
        late.entries().map(|(_, n)| n).collect::<Vec<_>>(),
        [counting(2)]
    );
    // Not ours: empty.
    for bad in [&[][..], &[2u8][..], &bytes[..bytes.len() - 1]] {
        assert!(ReplayCache::decode(bad, NOW_MS).is_empty(), "{bad:?}");
    }
    // A repeated nonce counts once; past 4,096 the oldest go.
    let mut many = vec![1u8];
    for i in 0..(REPLAY_ENTRIES as u32 + 2) {
        many.extend_from_slice(&NOW_MS.to_be_bytes());
        let mut n = [0u8; 16];
        n[..4].copy_from_slice(&i.to_be_bytes());
        many.extend_from_slice(&n);
    }
    many.extend_from_within(1..25);
    let full = ReplayCache::decode(&many, NOW_MS);
    assert_eq!(full.len(), REPLAY_ENTRIES);
    let mut second = [0u8; 16];
    second[3] = 2;
    assert_eq!(full.entries().next().map(|(_, n)| n), Some(second));
}

/// Design B §3's tables, every row: the listener's mode and answer, and the
/// knocking dialer's step after message 2.
#[test]
fn the_decision_tables() {
    use ListenerMode::*;
    assert_eq!(listener_mode(SilentMode::Automatic, false), Legacy);
    assert_eq!(listener_mode(SilentMode::Automatic, true), Strict);
    for every in [false, true] {
        assert_eq!(listener_mode(SilentMode::On, every), Silent);
        assert_eq!(listener_mode(SilentMode::Off, every), Legacy);
    }
    for mode in [Legacy, Strict, Silent] {
        assert_eq!(answer(mode, true), Answer::Fresh { proof: true });
    }
    assert_eq!(answer(Legacy, false), Answer::Derived);
    assert_eq!(answer(Strict, false), Answer::Fresh { proof: false });
    assert_eq!(answer(Silent, false), Answer::Close);
    for pin in [PinCheck::None, PinCheck::Match, PinCheck::Mismatch] {
        for floor in [false, true] {
            assert_eq!(dialer_step(true, pin, floor), DialerStep::Fresh);
        }
    }
    for floor in [false, true] {
        assert_eq!(
            dialer_step(false, PinCheck::Mismatch, floor),
            DialerStep::StopPin
        );
        assert_eq!(
            dialer_step(false, PinCheck::Match, floor),
            DialerStep::Derived
        );
    }
    assert_eq!(
        dialer_step(false, PinCheck::None, true),
        DialerStep::StopKnock
    );
    assert_eq!(
        dialer_step(false, PinCheck::None, false),
        DialerStep::Derived
    );
}

/// Message 3's payload while knocking: RLX1 with the caps (or none) and one
/// PAD entry, at most 64 bytes and of every length in its range; its caps
/// read as before.
#[test]
fn message_3_is_padded_within_rlx1() {
    let mut r = rng();
    for caps in [0, CAP_LINK_RRH1, crate::CAP_LINK_PAD1 | CAP_LINK_RRH1] {
        let min = rlx1_padded_min_len(caps);
        let mut lengths = std::collections::BTreeSet::new();
        for _ in 0..2_000 {
            let p = m3_payload(caps, &mut r);
            assert_eq!(rlx1_caps(&p), caps);
            assert_eq!(&p[..5], b"RLX1\x01");
            let pad_at = if caps == 0 { 5 } else { 11 };
            assert_eq!(p[pad_at], EXT_PAD);
            assert_eq!(usize::from(p[pad_at + 1]) + pad_at + 2, p.len());
            lengths.insert(p.len());
        }
        assert_eq!(lengths, (min..=RLX1_MAX_LEN).collect());
    }
    assert_eq!(rlx1_padded_min_len(0), 7);
    assert_eq!(rlx1_padded_min_len(CAP_LINK_RRH1), 13);
    assert_eq!(
        hex::encode(rlx1_payload_padded(CAP_LINK_RRH1, 16)),
        "524c5831010104000001007e03000000"
    );
}

// ── Whole handshakes ([`Dialing`] and [`hear`]) ───────────────────────

/// Bob's listener answering one raw message 1 in `mode`.
fn bob_hears(
    book: &[KnockKeys],
    mode: ListenerMode,
    m1: &[u8],
    at: u64,
    replays: &mut ReplayCache,
    r: &mut StdRng,
) -> Heard {
    hear(book, mode, &id(BOB), m1, at, replays, r).unwrap()
}

fn public(secret: &StaticSecret) -> [u8; 32] {
    PublicKey::from(secret).to_bytes()
}

/// Alice knocks, Bob matches: Bob answers with a fresh static and the
/// proof, Alice builds the handshake again with a fresh static of her own,
/// and both ends finish XX with the same hash; Bob's two answers to two
/// dials carry two different statics, neither the derived one. Bob's
/// responder needs the static before message 1 is read, which is what
/// [`hear`] gives it.
#[test]
fn a_knocked_handshake_has_fresh_statics_on_both_ends() {
    use crate::lan_noise::{build_responder_with_static, handshake_hash, noise_static_public};
    let mut r = rng();
    let (alice, bob) = (id(ALICE), id(BOB));
    let book = vec![keys(BOB, CAROL), keys(BOB, ALICE)];
    let to_bob = keys(ALICE, BOB);
    let derived_bob = noise_static_public(&crate::lan_noise::derive_noise_static(&bob).unwrap());
    let derived_alice =
        noise_static_public(&crate::lan_noise::derive_noise_static(&alice).unwrap());
    let mut replays = ReplayCache::new();
    let mut seen = Vec::new();
    for mode in [
        ListenerMode::Legacy,
        ListenerMode::Strict,
        ListenerMode::Silent,
    ] {
        let mut dial = Dialing::start(&alice, &to_bob, day_of(NOW_MS), None, &mut r).unwrap();
        assert!(
            (64..=95).contains(&dial.m1().len()),
            "m1 {}",
            dial.m1().len()
        );
        let heard = bob_hears(&book, mode, dial.m1(), NOW_MS, &mut replays, &mut r);
        assert_eq!(
            (heard.matched, heard.replay),
            (Some(alice.public_key_bytes()), false)
        );
        let reply = heard.reply.expect("a contact is answered in every mode");
        let s_b = public(&reply.static_secret);
        assert_ne!(s_b, derived_bob);
        seen.push(s_b);
        let mut resp = build_responder_with_static(&reply.static_secret, None).unwrap();
        assert_eq!(
            handshake_read(&mut resp, dial.m1()).unwrap()[..],
            dial.m1()[E_LEN..]
        );
        let m2 = handshake_write(&mut resp, &reply.payload).unwrap();
        assert!((112..=143).contains(&m2.len()), "m2 {}", m2.len());
        let (remote, proof) = dial.read_m2(&to_bob, &m2).unwrap();
        assert_eq!((remote, proof), (s_b, true));
        let (mut init, local) = dial.finish(true, &m2, &mut r).unwrap();
        assert_ne!(local, derived_alice, "a fresh static of her own");
        let m3 = handshake_write(&mut init, &m3_payload(CAP_LINK_RRH1, &mut r)).unwrap();
        assert!((64..=128).contains(&m3.len()), "m3 {}", m3.len());
        let read = handshake_read(&mut resp, &m3).unwrap();
        assert_eq!(rlx1_caps(&read), CAP_LINK_RRH1);
        assert_eq!(get_remote_static(&resp).unwrap(), local);
        assert_eq!(handshake_hash(&init), handshake_hash(&resp));
    }
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 3, "a static per connection");
}

/// A dialer without the knock (an empty message 1 payload, what every
/// older build sends): the derived static in legacy mode, a fresh one per
/// connection in strict mode, no message 2 in silent mode; message 2 always
/// carries 16-47 random bytes that prove nothing. The same knock sent twice
/// is a replay the second time, answered like a stranger, with a payload of
/// the same lengths.
#[test]
fn a_stranger_and_a_replay_are_answered_by_the_mode() {
    use crate::lan_noise::{build_initiator, derive_noise_static, noise_static_public};
    let mut r = rng();
    let bob = id(BOB);
    let book = vec![keys(BOB, ALICE)];
    let derived_bob = noise_static_public(&derive_noise_static(&bob).unwrap());
    let stranger = Identity::from_seed(&[0x5A; 32]);
    let plain_m1 = || {
        let mut hs = build_initiator(&derive_noise_static(&stranger).unwrap()).unwrap();
        handshake_write(&mut hs, &[]).unwrap()
    };
    let mut replays = ReplayCache::new();
    let mut strict = Vec::new();
    for _ in 0..2 {
        let legacy = bob_hears(
            &book,
            ListenerMode::Legacy,
            &plain_m1(),
            NOW_MS,
            &mut replays,
            &mut r,
        );
        let reply = legacy.reply.unwrap();
        assert_eq!(public(&reply.static_secret), derived_bob);
        assert!((M2_PAYLOAD_MIN..=M2_PAYLOAD_MAX).contains(&reply.payload.len()));
        assert_eq!((legacy.matched, legacy.replay), (None, false));
        let fresh = bob_hears(
            &book,
            ListenerMode::Strict,
            &plain_m1(),
            NOW_MS,
            &mut replays,
            &mut r,
        );
        strict.push(public(&fresh.reply.unwrap().static_secret));
        let silent = bob_hears(
            &book,
            ListenerMode::Silent,
            &plain_m1(),
            NOW_MS,
            &mut replays,
            &mut r,
        );
        assert!(silent.reply.is_none() && silent.matched.is_none());
    }
    assert_ne!(strict[0], strict[1]);
    assert!(!strict.contains(&derived_bob));
    // A knock recorded and sent again an hour later.
    let alice = id(ALICE);
    let dial = Dialing::start(&alice, &keys(ALICE, BOB), day_of(NOW_MS), None, &mut r).unwrap();
    let first = bob_hears(
        &book,
        ListenerMode::Legacy,
        dial.m1(),
        NOW_MS,
        &mut replays,
        &mut r,
    );
    assert_eq!(
        (first.matched, first.replay),
        (Some(alice.public_key_bytes()), false)
    );
    let at = NOW_MS + 3_600_000;
    for mode in [ListenerMode::Legacy, ListenerMode::Strict] {
        let again = bob_hears(&book, mode, dial.m1(), at, &mut replays, &mut r);
        assert_eq!((again.matched, again.replay), (None, true));
        let reply = again.reply.unwrap();
        assert!((M2_PAYLOAD_MIN..=M2_PAYLOAD_MAX).contains(&reply.payload.len()));
        assert_eq!(
            public(&reply.static_secret) == derived_bob,
            mode == ListenerMode::Legacy
        );
    }
    let silent = bob_hears(
        &book,
        ListenerMode::Silent,
        dial.m1(),
        at,
        &mut replays,
        &mut r,
    );
    assert!(silent.reply.is_none() && silent.replay);
}

/// A knocking dialer at a listener without the knock (the derived static,
/// an empty message 2 payload): no proof, and without a fresh static it
/// goes on with the derived one, the static an older listener pins.
#[test]
fn a_listener_without_the_knock_gives_no_proof() {
    use crate::lan_noise::{build_responder, derive_noise_static, noise_static_public};
    let mut r = rng();
    let (alice, bob) = (id(ALICE), id(BOB));
    let to_bob = keys(ALICE, BOB);
    let mut dial = Dialing::start(&alice, &to_bob, day_of(NOW_MS), None, &mut r).unwrap();
    let mut old = build_responder(&derive_noise_static(&bob).unwrap()).unwrap();
    handshake_read(&mut old, dial.m1()).unwrap();
    let m2 = handshake_write(&mut old, &[]).unwrap();
    let (remote, proof) = dial.read_m2(&to_bob, &m2).unwrap();
    assert_eq!(
        remote,
        noise_static_public(&derive_noise_static(&bob).unwrap())
    );
    assert!(!proof);
    let (mut init, local) = dial.finish(false, &m2, &mut r).unwrap();
    assert_eq!(
        local,
        noise_static_public(&derive_noise_static(&alice).unwrap())
    );
    let m3 = handshake_write(&mut init, &[]).unwrap();
    handshake_read(&mut old, &m3).unwrap();
    assert_eq!(get_remote_static(&old).unwrap(), local);
    // A listener's random payload is no proof either.
    let mut dial = Dialing::start(&alice, &to_bob, day_of(NOW_MS), None, &mut r).unwrap();
    let mut fake = build_responder(&derive_noise_static(&bob).unwrap()).unwrap();
    handshake_read(&mut fake, dial.m1()).unwrap();
    let m2 = handshake_write(&mut fake, &m2_payload_unmatched(&mut r)).unwrap();
    assert!(!dial.read_m2(&to_bob, &m2).unwrap().1);
}

// ── Vectors (spec §9) ─────────────────────────────────────────────────

fn rvn1_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.pop();
    p.join("shared-vectors/rvn1")
}

fn vector(name: &str, description: &str, inputs: Value, expected: Value) -> Value {
    json!({
        "name": name,
        "protocol_version": "rvn1",
        "deterministic": true,
        "description": description,
        "inputs": inputs,
        "expected": expected,
    })
}

/// Assert that the committed vector `file` (under shared-vectors/rvn1/link)
/// equals `expected`; write it first under `RAVEN_REGEN_SECURITY_VECTORS=1`.
fn assert_vector(file: &str, expected: &Value) {
    let path = rvn1_dir().join("link").join(file);
    if std::env::var(REGEN).as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(expected).unwrap() + "\n",
        )
        .unwrap();
    }
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing vector {}: {e}", path.display()));
    let stored: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(&stored, expected, "{file}");
}

const KEYS: &str = "K_link = HKDF-Expand-SHA256(PRK K_root, info 'medium' || 0x03, 32 bytes), \
                    K_root the R2 pairwise root of the two Ed25519 identity keys \
                    (RAVEN_PRIVATE_RENDEZVOUS_V1 §5.3a, shared-vectors/rvn1/lan_beacon/\
                    lbcn_pair_keys_001.json). kq_X->Y = HMAC-SHA256(K_link, 'knock-q' || X || Y), \
                    kr_X->Y = HMAC-SHA256(K_link, 'knock-r' || X || Y). Message 1 payload = \
                    nonce16 || tag16 || pad(0..31), tag16 = HMAC-SHA256(kq_A->B, 'rlk1/m1' || \
                    day u32 BE || nonce16 || e_A)[0..16], day = floor(unix_ms / 86400000); \
                    message 2 payload = proof16 || pad(0..31), proof16 = HMAC-SHA256(kr_B->A, \
                    'rlk1/m2' || nonce16 || e_A || s_B)[0..16]; A dials, B listens \
                    (RAVEN_LINK_KNOCK_V1 §3)";

fn people(names: &[(&str, &str)]) -> Value {
    let mut map = serde_json::Map::new();
    for (name, seed) in names {
        map.insert(
            (*name).into(),
            json!({
                "seed_hex": seed,
                "ed_public_hex": hex::encode(id(seed).public_key_bytes()),
                "source": "RFC 8032 section 7.1 (the people of shared-vectors/rvn1/lan_beacon)",
            }),
        );
    }
    Value::Object(map)
}

/// The knock and proof of the vectors: Alice dials Bob.
struct Fixture {
    day: u32,
    nonce: [u8; 16],
    e: [u8; 32],
    s: [u8; 32],
    m1_pad: Vec<u8>,
    m2_pad: Vec<u8>,
    m1: Vec<u8>,
    m2_payload: Vec<u8>,
}

fn fixture() -> Fixture {
    let day = day_of(NOW_MS);
    let (nonce, e, s) = (counting(0x10), x_pub(0x11), x_pub(0x33));
    let m1_pad = vec![0xA5, 0x5A, 0xC3, 0x3C, 0x99];
    let m2_pad = vec![0x0F, 0xF0, 0x66];
    let payload = m1_payload_with(&keys(ALICE, BOB), day, &e, &nonce, &m1_pad);
    let m2_payload = m2_payload_with(&keys(BOB, ALICE), &nonce, &e, &s, &m2_pad);
    Fixture {
        day,
        nonce,
        e,
        s,
        m1_pad,
        m2_pad,
        m1: raw_m1(&e, &payload),
        m2_payload,
    }
}

#[test]
fn rlk1_vectors() {
    let f = fixture();
    let alice = id(ALICE);
    let (ap, bp) = (alice.public_key_bytes(), id(BOB).public_key_bytes());
    let k_link = link_key(&alice, &bp).unwrap();
    let hmac = |label: &[u8], x: &[u8; 32], y: &[u8; 32]| {
        hex::encode(hmac_sha256(&k_link, &[label, x.as_slice(), y.as_slice()]))
    };
    let bob_book = vec![keys(BOB, CAROL), keys(BOB, ALICE)];
    let found = match_m1(&bob_book, &f.m1, f.day).unwrap();
    assert_eq!((found.index, found.peer), (1, ap));
    assert!(check_m2(
        &keys(ALICE, BOB),
        &f.nonce,
        &f.e,
        &f.s,
        &f.m2_payload
    ));
    let m3 = |caps: u32, total: usize| hex::encode(rlx1_payload_padded(caps, total));
    assert_vector(
        "rlk1_tags_001.json",
        &vector(
            "RLK1 knock and proof: Alice dials Bob",
            KEYS,
            json!({
                "people": people(&[("alice", ALICE), ("bob", BOB), ("carol", CAROL)]),
                "dialer": "alice",
                "listener": "bob",
                "unix_ms": NOW_MS,
                "nonce_hex": hex::encode(f.nonce),
                "e_a_hex": hex::encode(f.e),
                "e_a_source": "X25519 public key of the scalar 32 bytes of 0x11",
                "m1_pad_hex": hex::encode(&f.m1_pad),
                "s_b_hex": hex::encode(f.s),
                "s_b_source": "X25519 public key of the scalar 32 bytes of 0x33 (a per-connection static)",
                "m2_pad_hex": hex::encode(&f.m2_pad),
                "listener_book": ["carol", "alice"],
            }),
            json!({
                "k_link_hex": hex::encode(*k_link),
                "kq_alice_to_bob_hex": hmac(b"knock-q", &ap, &bp),
                "kq_bob_to_alice_hex": hmac(b"knock-q", &bp, &ap),
                "kr_bob_to_alice_hex": hmac(b"knock-r", &bp, &ap),
                "kr_alice_to_bob_hex": hmac(b"knock-r", &ap, &bp),
                "day": f.day,
                "tag_hex": hex::encode(keys(ALICE, BOB).tag_out(f.day, &f.nonce, &f.e)),
                "m1_payload_hex": hex::encode(&f.m1[E_LEN..]),
                "raw_m1_hex": hex::encode(&f.m1),
                "accepted_listener_days": [f.day - 1, f.day, f.day + 1],
                "match": {"index": 1, "peer": "alice"},
                "proof_hex": hex::encode(keys(BOB, ALICE).proof_out(&f.nonce, &f.e, &f.s)),
                "m2_payload_hex": hex::encode(&f.m2_payload),
                "m3_payloads": [
                    {"caps": 0, "total": 7, "payload_hex": m3(0, 7)},
                    {"caps": CAP_LINK_RRH1, "total": 40, "payload_hex": m3(CAP_LINK_RRH1, 40)},
                    {"caps": 0x300, "total": 64, "payload_hex": m3(0x300, 64)},
                ],
            }),
        ),
    );
    let neg = |file: &str, v: Value| assert_vector(&format!("negative/{file}"), &v);
    // The listener's day two days off: no match (only day-1..day+1).
    for d in [f.day - 2, f.day + 2] {
        assert_eq!(match_m1(&bob_book, &f.m1, d), None);
    }
    neg(
        "rlk1_wrong_day_001.json",
        vector(
            "RLK1 negative: the listener's day is two days from the knock's",
            KEYS,
            json!({
                "people": people(&[("alice", ALICE), ("bob", BOB), ("carol", CAROL)]),
                "raw_m1_hex": hex::encode(&f.m1),
                "knock_day": f.day,
                "listener": "bob",
                "listener_book": ["carol", "alice"],
                "listener_days": [f.day - 2, f.day + 2],
            }),
            json!({"matched": false, "answer": "as a dialer without a knock"}),
        ),
    );
    // Alice's knock for Carol, read by Bob; and Bob's knock read as Alice's.
    let for_carol = raw_m1(
        &f.e,
        &m1_payload_with(&keys(ALICE, CAROL), f.day, &f.e, &f.nonce, &f.m1_pad),
    );
    assert_eq!(match_m1(&bob_book, &for_carol, f.day), None);
    let bob_to_alice = raw_m1(
        &f.e,
        &m1_payload_with(&keys(BOB, ALICE), f.day, &f.e, &f.nonce, &f.m1_pad),
    );
    assert_eq!(match_m1(&bob_book, &bob_to_alice, f.day), None);
    assert!(match_m1(&[keys(ALICE, BOB)], &bob_to_alice, f.day).is_some());
    neg(
        "rlk1_wrong_pair_001.json",
        vector(
            "RLK1 negative: knocks made with another pair's or the other direction's key",
            KEYS,
            json!({
                "people": people(&[("alice", ALICE), ("bob", BOB), ("carol", CAROL)]),
                "listener": "bob",
                "listener_book": ["carol", "alice"],
                "listener_day": f.day,
                "cases": [
                    {"name": "alice's knock for carol", "raw_m1_hex": hex::encode(&for_carol)},
                    {"name": "bob's own knock for alice (kq_bob->alice)", "raw_m1_hex": hex::encode(&bob_to_alice)},
                ],
            }),
            json!({"matched": [false, false]}),
        ),
    );
    // The same message 1 twice: a replay the second time, answered as no
    // match (legacy: the derived static; strict: a fresh one; both with
    // random bytes for a proof).
    let mut cache = ReplayCache::new();
    assert!(!cache.replayed(&found.nonce, NOW_MS));
    assert!(cache.replayed(&found.nonce, NOW_MS + 3_600_000));
    neg(
        "rlk1_replay_001.json",
        vector(
            "RLK1 negative: a recorded message 1 sent again",
            &format!(
                "{KEYS}. A listener remembers each matched nonce for {REPLAY_TTL_MS} ms (at \
                 most {REPLAY_ENTRIES}); the same nonce matched again is a replay: \
                 SEC_KNOCK_REPLAY, answered as no match"
            ),
            json!({
                "people": people(&[("alice", ALICE), ("bob", BOB), ("carol", CAROL)]),
                "listener": "bob",
                "listener_book": ["carol", "alice"],
                "raw_m1_hex": hex::encode(&f.m1),
                "received_unix_ms": [NOW_MS, NOW_MS + 3_600_000],
            }),
            json!({
                "first": {"matched": true, "answer": "fresh static, proof"},
                "second": {
                    "matched": true,
                    "replay": true,
                    "answer_legacy": "derived static, random proof bytes",
                    "answer_strict": "fresh static, random proof bytes",
                    "answer_silent": "close before message 2",
                },
                "replay_ttl_ms": REPLAY_TTL_MS,
                "replay_entries": REPLAY_ENTRIES,
            }),
        ),
    );
    // An unmatched message 2 payload: random, the same lengths as a proof's,
    // never a proof.
    let mut r = StdRng::seed_from_u64(0x0f00);
    let mut unmatched = vec![0u8; f.m2_payload.len()];
    r.fill_bytes(&mut unmatched);
    assert!(!check_m2(
        &keys(ALICE, BOB),
        &f.nonce,
        &f.e,
        &f.s,
        &unmatched
    ));
    neg(
        "rlk1_unmatched_m2_random_001.json",
        vector(
            "RLK1 negative: the message 2 payload of a listener that matched no knock",
            &format!(
                "{KEYS}. A listener that matched no contact (or saw a replay) sends 16 \
                 random bytes and 0..31 more: the same lengths as a proof's, so the payload \
                 never says whether the knock matched; the dialer finds no proof"
            ),
            json!({
                "people": people(&[("alice", ALICE), ("bob", BOB)]),
                "dialer": "alice",
                "listener": "bob",
                "nonce_hex": hex::encode(f.nonce),
                "e_a_hex": hex::encode(f.e),
                "s_b_hex": hex::encode(f.s),
                "m2_payload_hex": hex::encode(&unmatched),
                "matched_m2_payload_len": f.m2_payload.len(),
            }),
            json!({"proof_ok": false, "len": unmatched.len()}),
        ),
    );
}

/// The committed rlk1 files are exactly the ones [`rlk1_vectors`] writes
/// (`link_padding`'s file test leaves them to this one).
#[test]
fn rlk1_vector_files() {
    if std::env::var(REGEN).as_deref() == Ok("1") {
        return; // being written right now
    }
    let names = |dir: &str| {
        let mut names: Vec<String> = std::fs::read_dir(rvn1_dir().join(dir))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with("rlk1_") && n.ends_with(".json"))
            .collect();
        names.sort();
        names
    };
    assert_eq!(names("link"), ["rlk1_tags_001.json"]);
    assert_eq!(
        names("link/negative"),
        [
            "rlk1_replay_001.json",
            "rlk1_unmatched_m2_random_001.json",
            "rlk1_wrong_day_001.json",
            "rlk1_wrong_pair_001.json",
        ]
    );
}
