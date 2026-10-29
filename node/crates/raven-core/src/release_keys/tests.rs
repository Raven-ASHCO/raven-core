//! Key sets and signature blocks (RAVEN_SECURITY_ADVISORY_V1 §2): every rule
//! of the acceptance tables. The vectors (`shared-vectors/rvn1/update`) are
//! written and checked in `advisory/tests.rs`.

use super::test_keys::{key_set, key_set_of, signer, signers, SEEDS};
use super::*;

/// The compressed identity point (order 1).
const IDENTITY_POINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 1;
    b
};

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn bytes_of(alg: u8, threshold: u8, keys: &[[u8; 32]]) -> Vec<u8> {
    let mut b = vec![alg, threshold, keys.len() as u8];
    for k in keys {
        b.extend_from_slice(k);
    }
    b
}

#[test]
fn test_key_set_encodes_and_digests() {
    let ks = key_set();
    assert_eq!(ks.threshold(), 2);
    let keys: Vec<[u8; 32]> = signers().iter().map(|s| s.public_key_bytes()).collect();
    assert_eq!(ks.keys(), &keys[..]);
    let bytes = ks.encode();
    assert_eq!(bytes, bytes_of(1, 2, &keys));
    assert_eq!(bytes.len(), KEYSET_HEADER_LEN + 96);
    assert_eq!(KeySet::decode(&bytes), Ok(ks.clone()));
    let mut h = Sha256::new();
    h.update(b"rvn1/release-keys/v1\0");
    h.update(&bytes);
    assert_eq!(ks.digest(), <[u8; 32]>::from(h.finalize()));
    // The seeds are the published ones, distinct, and each a usable key.
    assert_eq!(SEEDS, [[0x11; 32], [0x22; 32], [0x33; 32]]);
    assert!(keys.iter().all(usable_key));
    // Another set (other keys, other threshold) has another digest.
    assert_ne!(key_set_of(2, &[0x22, 0x33, 0x44]).digest(), ks.digest());
    assert_ne!(key_set_of(3, &[0x11, 0x22, 0x33]).digest(), ks.digest());
}

/// Spec §2.1, in order: header, algorithm, count, length, threshold, keys.
#[test]
fn key_set_acceptance_table() {
    let k: Vec<[u8; 32]> = (1..=9u8).map(|b| signer(b).public_key_bytes()).collect();
    let three = &k[..3];
    let ok = |b: Vec<u8>| assert!(KeySet::decode(&b).is_ok(), "{}", hex::encode(&b));
    let err = |b: Vec<u8>, e: KeySetError| {
        assert_eq!(KeySet::decode(&b), Err(e), "{}", hex::encode(&b));
    };
    ok(bytes_of(1, 2, three));
    ok(bytes_of(1, 1, &k[..1]));
    ok(bytes_of(1, 8, &k[..8]));
    ok(bytes_of(1, 1, &k[..8]));
    err(Vec::new(), KeySetError::BadLength);
    err(vec![1, 1], KeySetError::BadLength);
    err(bytes_of(0, 2, three), KeySetError::UnsupportedAlg);
    err(bytes_of(2, 2, three), KeySetError::UnsupportedAlg);
    // An unknown algorithm is refused before its (other) key lengths.
    err(vec![2, 1, 1, 0, 0], KeySetError::UnsupportedAlg);
    err(vec![1, 0, 0], KeySetError::BadCount);
    err(bytes_of(1, 2, &k[..9]), KeySetError::BadCount);
    let mut short = bytes_of(1, 2, three);
    short.pop();
    err(short, KeySetError::BadLength);
    let mut long = bytes_of(1, 2, three);
    long.push(0);
    err(long, KeySetError::BadLength);
    err(bytes_of(1, 0, three), KeySetError::BadThreshold);
    err(bytes_of(1, 4, three), KeySetError::BadThreshold);
    err(bytes_of(1, 9, &k[..8]), KeySetError::BadThreshold);
    // Weak: the identity, another small-order point, a point off the curve,
    // a non-canonical encoding (y = p + 3) of a curve point.
    for weak in [
        IDENTITY_POINT,
        hex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex32("0200000000000000000000000000000000000000000000000000000000000000"),
        hex32("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    ] {
        err(bytes_of(1, 2, &[k[0], weak, k[2]]), KeySetError::WeakKey);
        assert_eq!(
            KeySet::new(2, vec![k[0], weak, k[2]]),
            Err(KeySetError::WeakKey)
        );
    }
    err(
        bytes_of(1, 2, &[k[0], k[1], k[0]]),
        KeySetError::DuplicateKey,
    );
    // The first broken rule wins: a weak key before a duplicate.
    err(
        bytes_of(1, 2, &[k[0], IDENTITY_POINT, k[0]]),
        KeySetError::WeakKey,
    );
    assert_eq!(
        KeySet::new(0, three.to_vec()),
        Err(KeySetError::BadThreshold)
    );
    assert_eq!(KeySet::new(1, Vec::new()), Err(KeySetError::BadCount));
    assert_eq!(KeySet::new(1, k.clone()), Err(KeySetError::BadCount));
}

#[test]
fn y_p_plus_3_is_a_curve_point_with_another_encoding() {
    // The non-canonical case above is refused for its encoding, not for
    // being off the curve: dalek decodes it, and encodes it back as y = 3.
    let enc = hex32("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&enc).expect("on the curve");
    assert!(!vk.is_weak());
    let mut y3 = [0u8; 32];
    y3[0] = 3;
    assert_eq!(vk.to_edwards().compress().to_bytes(), y3);
}

#[test]
fn sig_block_framing() {
    assert_eq!(SigBlock::decode(&[]), Err(SigError::Malformed));
    assert_eq!(SigBlock::decode(&[0]), Ok(SigBlock::default()));
    assert_eq!(SigBlock::decode(&[1; 65]), Err(SigError::Malformed));
    let one = [&[1u8, 2][..], &[7; 64]].concat();
    let block = SigBlock::decode(&one).unwrap();
    assert_eq!(block.sigs(), &[(2, [7; 64])]);
    assert_eq!(block.encode(), one);
    assert_eq!(
        SigBlock::decode(&[&one[..], &[0]].concat()),
        Err(SigError::Malformed)
    );
    assert_eq!(SigBlock::decode(&[2; 131]).map(|b| b.sigs().len()), Ok(2));
    assert_eq!(SigBlock::decode(&[2; 130]), Err(SigError::Malformed));
}

/// Spec §2.3, in order: index order, known indexes, threshold, every
/// signature.
#[test]
fn verify_sigs_acceptance_table() {
    let ks = key_set();
    let [a, b, c] = signers();
    let msg = b"rvn1/test/v1\0signed bytes";
    let other = b"rvn1/test/v1\0other bytes";
    let s = |i: u8, id: &Identity| (i, id.sign(msg));
    let check = |sigs: Vec<(u8, [u8; 64])>| ks.verify_sigs(msg, &SigBlock::new(sigs));
    assert_eq!(check(vec![s(0, &a), s(1, &b)]), Ok(()));
    assert_eq!(check(vec![s(0, &a), s(2, &c)]), Ok(()));
    assert_eq!(check(vec![s(1, &b), s(2, &c)]), Ok(()));
    assert_eq!(check(vec![s(0, &a), s(1, &b), s(2, &c)]), Ok(()));
    assert_eq!(check(vec![]), Err(SigError::BelowThreshold));
    assert_eq!(check(vec![s(1, &b)]), Err(SigError::BelowThreshold));
    assert_eq!(
        check(vec![s(0, &a), s(0, &a)]),
        Err(SigError::KeyIndexOrder)
    );
    assert_eq!(
        check(vec![s(2, &c), s(0, &a)]),
        Err(SigError::KeyIndexOrder)
    );
    assert_eq!(
        check(vec![s(0, &a), s(3, &c)]),
        Err(SigError::UnknownKeyIndex)
    );
    // Order is checked before known indexes, and both before the threshold.
    assert_eq!(
        check(vec![s(3, &c), s(3, &c)]),
        Err(SigError::KeyIndexOrder)
    );
    assert_eq!(check(vec![s(5, &a)]), Err(SigError::UnknownKeyIndex));
    // One bad signature fails the block, even with two good ones.
    let bad = (1, b.sign(other));
    assert_eq!(
        check(vec![s(0, &a), bad, s(2, &c)]),
        Err(SigError::BadSignature)
    );
    // A good signature by the wrong key for its index.
    assert_eq!(
        check(vec![s(0, &a), (1, c.sign(msg))]),
        Err(SigError::BadSignature)
    );
    // The threshold counts before signatures are checked.
    assert_eq!(check(vec![bad]), Err(SigError::BelowThreshold));
    // Non-canonical s (s + L) is refused (strict verification).
    let mut malleable = a.sign(msg);
    let l: [u8; 32] = hex32("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let mut carry = 0u16;
    for i in 0..32 {
        let v = u16::from(malleable[32 + i]) + u16::from(l[i]) + carry;
        malleable[32 + i] = v as u8;
        carry = v >> 8;
    }
    assert_eq!(carry, 0, "s + L fits 32 bytes for this signature");
    assert_eq!(
        check(vec![(0, malleable), s(1, &b)]),
        Err(SigError::BadSignature)
    );
    // verify_block reads exactly one block.
    let block = SigBlock::sign(msg, &[(0, &a), (2, &c)]).encode();
    assert_eq!(ks.verify_block(msg, &block), Ok(()));
    assert_eq!(ks.verify_block(other, &block), Err(SigError::BadSignature));
    assert_eq!(
        ks.verify_block(msg, &[&block[..], &[0]].concat()),
        Err(SigError::Malformed)
    );
    assert_eq!(
        ks.verify_block(msg, &block[..block.len() - 1]),
        Err(SigError::Malformed)
    );
}

#[test]
fn threshold_one_and_three() {
    let [a, b, c] = signers();
    let msg = b"rvn1/test/v1\0x";
    let one = key_set_of(1, &[0x11, 0x22, 0x33]);
    assert_eq!(
        one.verify_sigs(msg, &SigBlock::sign(msg, &[(1, &b)])),
        Ok(())
    );
    let all = key_set_of(3, &[0x11, 0x22, 0x33]);
    assert_eq!(
        all.verify_sigs(msg, &SigBlock::sign(msg, &[(0, &a), (2, &c)])),
        Err(SigError::BelowThreshold)
    );
    assert_eq!(
        all.verify_sigs(msg, &SigBlock::sign(msg, &[(0, &a), (1, &b), (2, &c)])),
        Ok(())
    );
}

#[test]
fn error_codes_are_distinct() {
    let ks = [
        KeySetError::UnsupportedAlg,
        KeySetError::BadCount,
        KeySetError::BadLength,
        KeySetError::BadThreshold,
        KeySetError::WeakKey,
        KeySetError::DuplicateKey,
    ]
    .map(KeySetError::code);
    let sig = [
        SigError::WrongKeySet,
        SigError::Malformed,
        SigError::KeyIndexOrder,
        SigError::UnknownKeyIndex,
        SigError::BelowThreshold,
        SigError::BadSignature,
    ]
    .map(SigError::code);
    for codes in [&ks[..], &sig[..]] {
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
    }
}
