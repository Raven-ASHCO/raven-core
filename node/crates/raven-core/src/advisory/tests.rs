//! RAD1 advisories (RAVEN_SECURITY_ADVISORY_V1) and the vectors in
//! `shared-vectors/rvn1/update` (`keyset_*`, `rad1_*`). The vectors are
//! written only under `RAVEN_REGEN_SECURITY_VECTORS=1` (a deliberate wire
//! change) and otherwise compared with the committed files; the Python
//! reference (`protocol/reference/raven_protocol/advisory.py`) checks every
//! one and builds every signed advisory again, byte for byte.

use super::*;
use crate::release_keys::test_keys::{key_set, key_set_of, signer};
use crate::release_keys::{KeySet, KeySetError, SigBlock, SigError};
use serde_json::{json, Value};

const REGEN: &str = "RAVEN_REGEN_SECURITY_VECTORS";
/// 2026-10-23T00:00:00Z; advisory `n` is issued `n - 1` days later.
const ISSUED_AT_MS: u64 = 1_792_713_600_000;
const DAY_MS: u64 = 86_400_000;
/// The test key set's seed bytes, by key index.
const CURRENT: [u8; 3] = [0x11, 0x22, 0x33];
/// The set the rotation names: key 0x11 replaced by 0x44.
const NEXT: [u8; 3] = [0x22, 0x33, 0x44];
/// A set that is not the test set (the wrong-key-set case).
const OTHER: [u8; 3] = [0x44, 0x55, 0x66];

fn rvn1_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.pop();
    p.join("shared-vectors/rvn1")
}

fn e(kind: EntryKind, severity: Severity, target: &str, arg: &[u8], text_id: u16) -> Entry {
    Entry {
        kind,
        severity,
        target: target.to_owned(),
        arg: arg.to_vec(),
        text_id,
    }
}

fn set_of(seeds: &[u8; 3]) -> KeySet {
    key_set_of(2, seeds)
}

fn draft(set: &KeySet, serial: u64, prev: [u8; 32], entries: Vec<Entry>) -> AdvisoryDraft {
    AdvisoryDraft {
        serial,
        issued_at_ms: ISSUED_AT_MS + serial.saturating_sub(1) * DAY_MS,
        key_set_digest: set.digest(),
        prev_digest: prev,
        entries,
    }
}

/// `d` signed by the keys at `indexes` of the set with these seed bytes.
fn signed(d: &AdvisoryDraft, seeds: &[u8; 3], indexes: &[u8]) -> Advisory {
    let ids: Vec<Identity> = indexes
        .iter()
        .map(|i| signer(seeds[usize::from(*i)]))
        .collect();
    let signers: Vec<(u8, &Identity)> = indexes.iter().copied().zip(&ids).collect();
    d.sign(&signers).unwrap()
}

fn entries_one() -> Vec<Entry> {
    vec![
        e(
            EntryKind::SuiteStatus,
            Severity::Deprecated,
            "pairinit/1/1",
            b"",
            1,
        ),
        e(
            EntryKind::Notice,
            Severity::Info,
            "notice",
            "Test notice 1: PairInit V1 is being retired. Nothing changes yet.".as_bytes(),
            0,
        ),
    ]
}

/// Every kind: both statuses, a floor, both holds, a notice and a kind this
/// version does not know.
fn entries_two() -> Vec<Entry> {
    vec![
        e(
            EntryKind::SuiteStatus,
            Severity::Deprecated,
            "pairinit/1/1",
            b"",
            1,
        ),
        e(EntryKind::SuiteStatus, Severity::Broken, "rsr1/1", b"", 2),
        e(
            EntryKind::ReleaseFloor,
            Severity::Info,
            "raven",
            &7u64.to_be_bytes(),
            3,
        ),
        e(
            EntryKind::FeatureHold,
            Severity::Broken,
            "feature/friend-custody",
            b"",
            4,
        ),
        e(
            EntryKind::FeatureHold,
            Severity::Deprecated,
            "feature/lan-beacon",
            b"",
            0,
        ),
        e(
            EntryKind::Notice,
            Severity::Info,
            "notice",
            "Test notice 2: session reset V1 is broken; update Raven.".as_bytes(),
            0,
        ),
        e(
            EntryKind::Other(0x7f),
            Severity::Info,
            "future/kind",
            &[1, 2, 3],
            0,
        ),
    ]
}

/// The test history: #1 (2 of 3), #2 (3 of 3), another #2, #3 naming the
/// next key set, #4 signed by it.
struct History {
    one: Advisory,
    two: Advisory,
    two_alt: Advisory,
    three: Advisory,
    four: Advisory,
}

fn history() -> History {
    let cur = set_of(&CURRENT);
    let next = set_of(&NEXT);
    let one = signed(&draft(&cur, 1, [0; 32], entries_one()), &CURRENT, &[0, 2]);
    let two = signed(
        &draft(&cur, 2, one.digest(), entries_two()),
        &CURRENT,
        &[0, 1, 2],
    );
    let mut alt = entries_one();
    alt.push(e(
        EntryKind::ReleaseFloor,
        Severity::Info,
        "raven",
        &8u64.to_be_bytes(),
        3,
    ));
    let two_alt = signed(&draft(&cur, 2, one.digest(), alt), &CURRENT, &[0, 1]);
    let mut rotate = entries_two();
    rotate.push(e(
        EntryKind::KeySet,
        Severity::Info,
        "keys",
        &next.encode(),
        5,
    ));
    let three = signed(&draft(&cur, 3, two.digest(), rotate), &CURRENT, &[1, 2]);
    let four = signed(
        &draft(&next, 4, three.digest(), entries_two()),
        &NEXT,
        &[0, 2],
    );
    History {
        one,
        two,
        two_alt,
        three,
        four,
    }
}

// ── Decoding, signatures and succession ─────────────────────────────

#[test]
fn history_decodes_verifies_and_reencodes() {
    let h = history();
    let cur = key_set();
    let next = set_of(&NEXT);
    for a in [&h.one, &h.two, &h.two_alt, &h.three] {
        assert_eq!(a.verify(&cur), Ok(()), "#{}", a.serial);
        assert_eq!(a.verify(&next), Err(SigError::WrongKeySet));
        assert_eq!(Advisory::decode(a.bytes()).as_ref(), Ok(a));
        // Canonical: the decoded content re-encodes byte for byte.
        assert_eq!(a.draft().assemble(a.sigs()).unwrap().bytes(), a.bytes());
        assert_eq!(
            a.signing_input(),
            [SIGNING_DOMAIN, &a.bytes()[..a.signed_len()]].concat()
        );
        let mut d = Sha256::new();
        d.update(b"rvn1/advisory/digest/v1\0");
        d.update(a.bytes());
        assert_eq!(a.digest(), <[u8; 32]>::from(d.finalize()));
    }
    assert_eq!(h.four.verify(&next), Ok(()));
    assert_eq!(h.four.verify(&cur), Err(SigError::WrongKeySet));
    assert_eq!(h.one.sigs().sigs().len(), 2);
    assert_eq!(h.two.sigs().sigs().len(), 3);
    // What the entries say.
    let two = &h.two.entries;
    assert_eq!(two[2].release_floor(), Some(7));
    assert_eq!(two[1].release_floor(), None);
    assert!(two[5].notice_text().unwrap().starts_with("Test notice 2"));
    assert!(!two[6].kind.understood());
    let rotation = h.three.entries.last().unwrap();
    assert_eq!(rotation.key_set(), Some(next));
    assert_eq!(two[0].key_set(), None);
}

#[test]
fn succession_rules() {
    let h = history();
    let at = |a: &Advisory| Some((a.serial, a.digest()));
    assert_eq!(succession(None, &h.two), Succession::First);
    assert_eq!(succession(at(&h.one), &h.one), Succession::Same);
    assert_eq!(succession(at(&h.one), &h.two), Succession::Next);
    assert_eq!(succession(at(&h.two), &h.three), Succession::Next);
    assert_eq!(succession(at(&h.three), &h.four), Succession::Next);
    assert_eq!(succession(at(&h.one), &h.three), Succession::Gap);
    assert_eq!(succession(at(&h.one), &h.four), Succession::Gap);
    assert_eq!(succession(at(&h.two), &h.one), Succession::Rollback);
    assert_eq!(succession(at(&h.four), &h.two_alt), Succession::Rollback);
    assert_eq!(succession(at(&h.two), &h.two_alt), Succession::Equivocation);
    assert_eq!(succession(at(&h.two_alt), &h.two), Succession::Equivocation);
    // The next serial whose prev_digest names another #2.
    assert_eq!(
        succession(at(&h.two_alt), &h.three),
        Succession::Equivocation
    );
    // The stored serial at its limit: nothing is newer.
    assert_eq!(
        succession(Some((u64::MAX, [9; 32])), &h.four),
        Succession::Rollback
    );
}

/// Any single-byte change of a signed advisory (and a byte more or less)
/// makes it fail to decode or to verify.
#[test]
fn any_single_byte_change_fails() {
    let h = history();
    let cur = key_set();
    for (a, set) in [
        (&h.one, &cur),
        (&h.two, &cur),
        (&h.three, &cur),
        (&h.four, &set_of(&NEXT)),
    ] {
        let fails = |m: &[u8]| match Advisory::decode(m) {
            Err(_) => true,
            Ok(b) => b.verify(set).is_err(),
        };
        let bytes = a.bytes();
        for i in 0..bytes.len() {
            for x in [0x01u8, 0x80, 0xff] {
                let mut m = bytes.to_vec();
                m[i] ^= x;
                assert!(
                    fails(&m),
                    "#{}: byte {i} ^ {x:#04x} still verifies",
                    a.serial
                );
            }
        }
        assert!(fails(&bytes[..bytes.len() - 1]));
        assert!(fails(&[bytes, &[0]].concat()));
    }
}

#[test]
fn sizes_at_the_limit() {
    // Unknown-kind entries filling an advisory to exactly MAX_RAD1_LEN with
    // a two-signature block.
    let cur = key_set();
    let block = 1 + 2 * 65;
    let mut entries = Vec::new();
    let mut body = RAD1_HEADER_LEN;
    loop {
        let target = format!("x/{}", entries.len());
        let room = MAX_RAD1_LEN - block - body;
        let fixed = 7 + target.len();
        if room < fixed {
            break;
        }
        let arg = (room - fixed).min(MAX_ARG_LEN);
        entries.push(e(
            EntryKind::Other(0x80),
            Severity::Info,
            &target,
            &vec![0x5a; arg],
            0,
        ));
        body += fixed + arg;
    }
    assert!(entries.len() <= MAX_ENTRIES);
    let d = draft(&cur, 1, [0; 32], entries);
    let full = signed(&d, &CURRENT, &[0, 1]);
    assert_eq!(full.bytes().len(), MAX_RAD1_LEN);
    assert_eq!(full.verify(&cur), Ok(()));
    let over = [full.bytes(), &[0]].concat();
    assert_eq!(Advisory::decode(&over), Err(Rad1Error::TooLong));
    // A third signature does not fit.
    let ids = [signer(0x11), signer(0x22), signer(0x33)];
    assert_eq!(
        d.sign(&[(0, &ids[0]), (1, &ids[1]), (2, &ids[2])]),
        Err(Rad1Error::TooLong)
    );
    // 64 entries are allowed, 65 are not; 0 entries are allowed.
    let many = |n: usize| -> Vec<Entry> {
        (0..n)
            .map(|i| {
                e(
                    EntryKind::SuiteStatus,
                    Severity::Info,
                    &format!("s/{i}"),
                    b"",
                    0,
                )
            })
            .collect()
    };
    assert!(draft(&cur, 1, [0; 32], many(64)).body().is_ok());
    assert_eq!(
        draft(&cur, 1, [0; 32], many(65)).body(),
        Err(Rad1Error::TooManyEntries)
    );
    let empty = signed(&draft(&cur, 1, [0; 32], Vec::new()), &CURRENT, &[0, 1]);
    assert!(empty.entries.is_empty());
    assert_eq!(empty.bytes().len(), RAD1_HEADER_LEN + block);
}

#[test]
fn draft_refuses_what_decode_refuses() {
    let cur = key_set();
    let bad = |entries: Vec<Entry>| draft(&cur, 1, [0; 32], entries).body().unwrap_err();
    let long = "a/".repeat(128) + "b";
    assert_eq!(
        bad(vec![e(
            EntryKind::SuiteStatus,
            Severity::Info,
            &long,
            b"",
            0
        )]),
        Rad1Error::BadTarget
    );
    assert_eq!(
        bad(vec![e(
            EntryKind::Other(9),
            Severity::Info,
            "a/b",
            &[0; 70_000],
            0
        )]),
        Rad1Error::BadArg
    );
    assert_eq!(
        bad(vec![e(
            EntryKind::Notice,
            Severity::Broken,
            "notice",
            b"x",
            0
        )]),
        Rad1Error::BadSeverity
    );
    assert_eq!(
        draft(&cur, 2, [0; 32], Vec::new()).body(),
        Err(Rad1Error::BadPrev)
    );
    assert_eq!(
        draft(&cur, 0, [0; 32], Vec::new()).signing_input(),
        Err(Rad1Error::BadSerial)
    );
}

/// Unknown kinds keep the advisory valid; the same target under two kinds
/// is not a duplicate.
#[test]
fn unknown_kinds_and_shared_targets() {
    let cur = key_set();
    let d = draft(
        &cur,
        1,
        [0; 32],
        vec![
            e(EntryKind::SuiteStatus, Severity::Broken, "x/y", b"", 0),
            e(
                EntryKind::Other(0x06),
                Severity::Broken,
                "x/y",
                &[0; 1024],
                0xffff,
            ),
            e(
                EntryKind::Other(0xff),
                Severity::Deprecated,
                "anything",
                b"",
                1,
            ),
        ],
    );
    let a = signed(&d, &CURRENT, &[0, 2]);
    assert_eq!(a.verify(&cur), Ok(()));
    assert!(!a.entries[1].kind.understood());
    assert_eq!(EntryKind::from_byte(0x06), Some(EntryKind::Other(6)));
    assert_eq!(EntryKind::from_byte(0), None);
    for b in 1..=255u8 {
        assert_eq!(EntryKind::from_byte(b).unwrap().byte(), b);
    }
    for b in 0..=2u8 {
        assert_eq!(Severity::from_byte(b).unwrap().byte(), b);
    }
    assert_eq!(Severity::from_byte(3), None);
}

// ── Structural rules (spec §5) ──────────────────────────────────────

/// One raw entry with its own lengths.
fn raw_entry(kind: u8, severity: u8, target: &[u8], arg: &[u8]) -> Vec<u8> {
    let mut b = vec![kind, severity, target.len() as u8];
    b.extend_from_slice(target);
    b.extend((arg.len() as u16).to_be_bytes());
    b.extend_from_slice(arg);
    b.extend(0u16.to_be_bytes());
    b
}

/// A header and raw entries, valid unless a field is changed.
#[derive(Clone)]
struct Raw {
    magic: [u8; 4],
    version: u8,
    flags: u8,
    count: Option<u16>,
    serial: u64,
    prev: [u8; 32],
    entries: Vec<Vec<u8>>,
}

impl Raw {
    fn new() -> Self {
        Self {
            magic: *b"RAD1",
            version: 1,
            flags: 0,
            count: None,
            serial: 1,
            prev: [0; 32],
            entries: Vec::new(),
        }
    }

    fn entry(kind: u8, severity: u8, target: &[u8], arg: &[u8]) -> Self {
        Self::new().with(raw_entry(kind, severity, target, arg))
    }

    fn with(mut self, entry: Vec<u8>) -> Self {
        self.entries.push(entry);
        self
    }

    fn body(&self) -> Vec<u8> {
        let mut b = self.magic.to_vec();
        b.extend([self.version, self.flags]);
        b.extend(
            self.count
                .unwrap_or(self.entries.len() as u16)
                .to_be_bytes(),
        );
        b.extend(self.serial.to_be_bytes());
        b.extend(ISSUED_AT_MS.to_be_bytes());
        b.extend(key_set().digest());
        b.extend(self.prev);
        for entry in &self.entries {
            b.extend_from_slice(entry);
        }
        b
    }

    /// The body and a valid 2-of-3 block over it: only the changed field is
    /// wrong.
    fn signed(&self) -> Vec<u8> {
        let body = self.body();
        let [a, b, _] = crate::release_keys::test_keys::signers();
        let block = SigBlock::sign(&[SIGNING_DOMAIN, &body].concat(), &[(0, &a), (1, &b)]);
        [body, block.encode()].concat()
    }
}

/// A key set's bytes with a raw key list.
fn raw_key_set(alg: u8, threshold: u8, keys: &[[u8; 32]]) -> Vec<u8> {
    let mut b = vec![alg, threshold, keys.len() as u8];
    for k in keys {
        b.extend_from_slice(k);
    }
    b
}

fn key(seed: u8) -> [u8; 32] {
    signer(seed).public_key_bytes()
}

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// The identity point (order 1).
const IDENTITY_POINT: &str = "0100000000000000000000000000000000000000000000000000000000000000";
/// A point of order 8.
const SMALL_ORDER_POINT: &str = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a";
/// y = 2 is not the y of a curve point.
const NOT_ON_CURVE: &str = "0200000000000000000000000000000000000000000000000000000000000000";
/// y = p + 3: a curve point (y = 3) in a non-canonical encoding.
const NON_CANONICAL_Y: &str = "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";

/// Every refusal of spec §5, each the first rule its bytes break. The bytes
/// of `too_long` are the first ones zero-padded to 32,769 bytes.
fn decode_cases() -> Vec<(&'static str, Vec<u8>, Rad1Error)> {
    use Rad1Error::*;
    let ok = Raw::new().signed();
    let floor = 7u64.to_be_bytes();
    let next = set_of(&NEXT).encode();
    let t65 = format!("{}b", "a/".repeat(32));
    let one = |kind: u8, severity: u8, target: &[u8], arg: &[u8]| {
        Raw::entry(kind, severity, target, arg).signed()
    };
    let two = |a: (u8, u8, &[u8], &[u8]), b: (u8, u8, &[u8], &[u8])| {
        Raw::entry(a.0, a.1, a.2, a.3)
            .with(raw_entry(b.0, b.1, b.2, b.3))
            .signed()
    };
    let header = |raw: Raw| raw.signed();
    let weak_set = raw_key_set(1, 2, &[key(0x22), hex32(IDENTITY_POINT), key(0x44)]);
    let zero_threshold = raw_key_set(1, 0, &[key(0x22), key(0x33), key(0x44)]);
    let mut cut = Raw::entry(4, 0, b"notice", b"0123456789").body();
    cut.truncate(cut.len() - 7);
    let mut short_block = Raw::new().signed();
    short_block[RAD1_HEADER_LEN] = 3;
    let mut too_long = ok.clone();
    too_long.resize(MAX_RAD1_LEN + 1, 0);
    vec![
        ("too_long", too_long, TooLong),
        ("empty", Vec::new(), Truncated),
        ("header_87_bytes", ok[..87].to_vec(), Truncated),
        ("entry_cut_in_arg", cut, Truncated),
        (
            "bad_magic",
            header(Raw {
                magic: *b"RAD2",
                ..Raw::new()
            }),
            BadMagic,
        ),
        (
            "bad_version",
            header(Raw {
                version: 2,
                ..Raw::new()
            }),
            BadVersion,
        ),
        (
            "bad_flags",
            header(Raw {
                flags: 1,
                ..Raw::new()
            }),
            BadFlags,
        ),
        (
            "entry_count_65",
            header(Raw {
                count: Some(65),
                ..Raw::new()
            }),
            TooManyEntries,
        ),
        (
            "serial_0",
            header(Raw {
                serial: 0,
                ..Raw::new()
            }),
            BadSerial,
        ),
        (
            "serial_1_with_prev",
            header(Raw {
                prev: [7; 32],
                ..Raw::new()
            }),
            BadPrev,
        ),
        (
            "serial_2_without_prev",
            header(Raw {
                serial: 2,
                ..Raw::new()
            }),
            BadPrev,
        ),
        ("kind_0", one(0, 0, b"a/b", b""), BadKind),
        ("severity_3", one(1, 3, b"pairinit/1/1", b""), BadSeverity),
        (
            "broken_release_floor",
            one(2, 2, b"raven", &floor),
            BadSeverity,
        ),
        ("broken_notice", one(4, 2, b"notice", b"text"), BadSeverity),
        ("broken_key_set", one(5, 2, b"keys", &next), BadSeverity),
        ("target_empty", one(1, 0, b"", b""), BadTarget),
        ("target_65_bytes", one(1, 0, t65.as_bytes(), b""), BadTarget),
        (
            "target_upper_case",
            one(1, 0, b"PairInit/1/1", b""),
            BadTarget,
        ),
        ("target_space", one(1, 0, b"pair init/1", b""), BadTarget),
        (
            "target_empty_segment",
            one(1, 0, b"pairinit//1", b""),
            BadTarget,
        ),
        (
            "target_leading_slash",
            one(1, 0, b"/pairinit/1", b""),
            BadTarget,
        ),
        (
            "target_trailing_slash",
            one(1, 0, b"pairinit/1/", b""),
            BadTarget,
        ),
        (
            "target_not_ascii",
            one(1, 0, "caf\u{e9}/1".as_bytes(), b""),
            BadTarget,
        ),
        ("arg_1025_bytes", one(0x7f, 0, b"a/b", &[0; 1025]), BadArg),
        (
            "suite_status_without_slash",
            one(1, 0, b"pairinit", b""),
            BadEntry,
        ),
        (
            "suite_status_feature",
            one(1, 2, b"feature/p2p", b""),
            BadEntry,
        ),
        (
            "suite_status_with_arg",
            one(1, 0, b"pairinit/1/1", b"x"),
            BadEntry,
        ),
        (
            "release_floor_target",
            one(2, 0, b"ravens", &floor),
            BadEntry,
        ),
        (
            "release_floor_7_bytes",
            one(2, 0, b"raven", &floor[1..]),
            BadEntry,
        ),
        ("release_floor_0", one(2, 0, b"raven", &[0; 8]), BadEntry),
        (
            "feature_hold_nested",
            one(3, 2, b"feature/p2p/x", b""),
            BadEntry,
        ),
        (
            "feature_hold_prefix",
            one(3, 2, b"features/p2p", b""),
            BadEntry,
        ),
        (
            "feature_hold_with_arg",
            one(3, 2, b"feature/p2p", b"x"),
            BadEntry,
        ),
        ("notice_target", one(4, 0, b"notices", b"text"), BadEntry),
        ("notice_empty", one(4, 0, b"notice", b""), BadEntry),
        (
            "notice_not_utf8",
            one(4, 0, b"notice", &[0x66, 0xff]),
            BadEntry,
        ),
        ("key_set_target", one(5, 0, b"key", &next), BadEntry),
        ("key_set_weak_key", one(5, 0, b"keys", &weak_set), BadEntry),
        (
            "key_set_threshold_0",
            one(5, 0, b"keys", &zero_threshold),
            BadEntry,
        ),
        (
            "duplicate_suite_status",
            two((1, 1, b"pairinit/1/1", b""), (1, 2, b"pairinit/1/1", b"")),
            DuplicateEntry,
        ),
        (
            "duplicate_notice",
            two((4, 0, b"notice", b"a"), (4, 1, b"notice", b"b")),
            DuplicateEntry,
        ),
        (
            "duplicate_unknown_kind",
            two((0x7f, 0, b"a/b", b""), (0x7f, 0, b"a/b", b"x")),
            DuplicateEntry,
        ),
        ("no_signature_block", Raw::new().body(), BadSigBlock),
        ("signature_block_short", short_block, BadSigBlock),
        (
            "byte_after_signature_block",
            [ok, vec![0]].concat(),
            BadSigBlock,
        ),
    ]
}

#[test]
fn decode_acceptance_table() {
    assert!(Advisory::decode(&Raw::new().signed()).is_ok());
    let mut names = Vec::new();
    for (name, bytes, want) in decode_cases() {
        assert_eq!(Advisory::decode(&bytes), Err(want), "{name}");
        names.push(name);
    }
    // Every refusal has a case.
    let mut codes: Vec<&str> = decode_cases().iter().map(|c| c.2.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), 15);
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), decode_cases().len());
}

/// Every refusal of spec §2.1.
fn key_set_cases() -> Vec<(&'static str, Vec<u8>, KeySetError)> {
    use KeySetError::*;
    let three = [key(0x11), key(0x22), key(0x33)];
    let nine: Vec<[u8; 32]> = (1..=9).map(key).collect();
    let ok = raw_key_set(1, 2, &three);
    let with_key = |k: &str| raw_key_set(1, 2, &[three[0], hex32(k), three[2]]);
    vec![
        ("empty", Vec::new(), BadLength),
        ("header_2_bytes", vec![1, 2], BadLength),
        ("alg_0", raw_key_set(0, 2, &three), UnsupportedAlg),
        ("alg_2", raw_key_set(2, 2, &three), UnsupportedAlg),
        ("n_0", vec![1, 1, 0], BadCount),
        ("n_9", raw_key_set(1, 2, &nine), BadCount),
        ("one_byte_short", ok[..ok.len() - 1].to_vec(), BadLength),
        ("one_byte_over", [&ok[..], &[0]].concat(), BadLength),
        ("threshold_0", raw_key_set(1, 0, &three), BadThreshold),
        ("threshold_4_of_3", raw_key_set(1, 4, &three), BadThreshold),
        ("identity_point", with_key(IDENTITY_POINT), WeakKey),
        ("small_order_point", with_key(SMALL_ORDER_POINT), WeakKey),
        ("not_on_curve", with_key(NOT_ON_CURVE), WeakKey),
        ("non_canonical_y", with_key(NON_CANONICAL_Y), WeakKey),
        (
            "duplicate_key",
            raw_key_set(1, 2, &[three[0], three[1], three[0]]),
            DuplicateKey,
        ),
    ]
}

#[test]
fn key_set_cases_refuse() {
    for (name, bytes, want) in key_set_cases() {
        assert_eq!(KeySet::decode(&bytes), Err(want), "{name}");
    }
}

// ── Vectors (spec §10) ──────────────────────────────────────────────

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

/// Assert that the committed vector `file` (under shared-vectors/rvn1/update)
/// equals `expected`; write it first under `RAVEN_REGEN_SECURITY_VECTORS=1`.
fn assert_vector(file: &str, expected: &Value) {
    let path = rvn1_dir().join("update").join(file);
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

fn key_set_json(seeds: &[u8; 3]) -> Value {
    let set = set_of(seeds);
    json!({
        "threshold": set.threshold(),
        "seeds_hex": seeds.iter().map(|b| hex::encode([*b; 32])).collect::<Vec<_>>(),
        "public_keys_hex": set.keys().iter().map(hex::encode).collect::<Vec<_>>(),
        "key_set_hex": hex::encode(set.encode()),
        "key_set_digest_hex": hex::encode(set.digest()),
    })
}

/// What a signer builds: the fields, the entries and who signs.
fn advisory_inputs(a: &Advisory, signers: &[u8]) -> Value {
    json!({
        "serial": a.serial,
        "issued_at_ms": a.issued_at_ms,
        "key_set_digest_hex": hex::encode(a.key_set_digest),
        "prev_digest_hex": hex::encode(a.prev_digest),
        "entries": a.entries.iter().map(|e| json!({
            "kind": e.kind.byte(),
            "severity": e.severity.byte(),
            "target": e.target,
            "arg_hex": hex::encode(&e.arg),
            "text_id": e.text_id,
        })).collect::<Vec<_>>(),
        "signers": signers,
    })
}

/// What a verifier gets: the bytes, the digests and what each entry says.
fn advisory_expected(a: &Advisory) -> Value {
    json!({
        "advisory_hex": hex::encode(a.bytes()),
        "signed_len": a.signed_len(),
        "signing_input_hex": hex::encode(a.signing_input()),
        "advisory_digest_hex": hex::encode(a.digest()),
        "entries": a.entries.iter().map(|e| {
            let mut v = json!({
                "kind": e.kind.name(),
                "severity": e.severity.name(),
                "target": e.target,
                "understood": e.kind.understood(),
            });
            if let Some(floor) = e.release_floor() {
                v["release_floor"] = json!(floor);
            }
            if let Some(text) = e.notice_text() {
                v["notice_text"] = json!(text);
            }
            if let Some(set) = e.key_set() {
                v["key_set_digest_hex"] = json!(hex::encode(set.digest()));
            }
            v
        }).collect::<Vec<_>>(),
    })
}

/// An advisory, the key set it is checked under and the outcome.
fn check_vector(name: &str, description: &str, seeds: &[u8; 3], bytes: &[u8], want: &str) -> Value {
    let got = match Advisory::decode(bytes) {
        Err(e) => panic!("{name}: {e}"),
        Ok(a) => a.verify(&set_of(seeds)).err().map_or("OK", SigError::code),
    };
    assert_eq!(got, want, "{name}");
    vector(
        name,
        description,
        json!({ "key_set": key_set_json(seeds), "advisory_hex": hex::encode(bytes) }),
        json!({ "decode": "OK", "verify": want }),
    )
}

/// A stored advisory and a new one, both signed by the test key set.
fn pair_vector(
    name: &str,
    description: &str,
    stored: &Advisory,
    new: &Advisory,
    want: Succession,
) -> Value {
    let cur = key_set();
    assert_eq!((stored.verify(&cur), new.verify(&cur)), (Ok(()), Ok(())));
    let got = succession(Some((stored.serial, stored.digest())), new);
    assert_eq!(got, want, "{name}");
    vector(
        name,
        description,
        json!({
            "key_set": key_set_json(&CURRENT),
            "stored_hex": hex::encode(stored.bytes()),
            "new_hex": hex::encode(new.bytes()),
        }),
        json!({
            "stored_serial": stored.serial,
            "stored_digest_hex": hex::encode(stored.digest()),
            "new_serial": new.serial,
            "new_digest_hex": hex::encode(new.digest()),
            "verify": ["OK", "OK"],
            "succession": want.name(),
        }),
    )
}

const LAYOUT: &str = "RAD1 = \"RAD1\" | 0x01 | flags 0x00 | entry_count u16 | serial u64 | \
                      issued_at_ms u64 | key_set_digest[32] | prev_digest[32] | entries | \
                      sig_count u8 | (key_index u8 | Ed25519 signature[64]) * sig_count; \
                      entry = kind u8 | severity u8 | target_len u8 | target | arg_len u16 | \
                      arg | text_id u16; signing input \"rvn1/advisory/v1\\0\" || bytes before \
                      the signature block; advisory_digest = SHA-256(\"rvn1/advisory/digest/v1\\0\" \
                      || all bytes) (RAVEN_SECURITY_ADVISORY_V1 §3, §6)";

#[test]
fn update_vectors() {
    let h = history();
    let cur = key_set();
    let ks_bytes = cur.encode();
    assert_vector(
        "keyset_001.json",
        &vector(
            "keyset_001",
            "The published test release key set (RAVEN_SECURITY_ADVISORY_V1 §2.1): \
             Ed25519 keys from the seeds 0x11 x 32, 0x22 x 32, 0x33 x 32 (key indexes \
             0, 1, 2), threshold 2. KeySet = alg 0x01 | threshold u8 | n u8 | pubkey[32] * n; \
             key_set_digest = SHA-256(\"rvn1/release-keys/v1\\0\" || KeySet). Anyone can sign \
             with these keys: a production key set never contains one",
            json!({
                "alg": crate::release_keys::KEYSET_ALG_ED25519,
                "threshold": 2,
                "seeds_hex": CURRENT.iter().map(|b| hex::encode([*b; 32])).collect::<Vec<_>>(),
            }),
            json!({
                "public_keys_hex": cur.keys().iter().map(hex::encode).collect::<Vec<_>>(),
                "key_set_hex": hex::encode(&ks_bytes),
                "key_set_digest_hex": hex::encode(cur.digest()),
            }),
        ),
    );
    assert_vector(
        "rad1_two_of_three_001.json",
        &vector(
            "rad1_two_of_three_001",
            &format!(
                "{LAYOUT}. Advisory #1 (prev_digest all zero) signed by keys 0 and 2 of the \
                 test key set (keyset_001): a DEPRECATED PairInit V1 suite and a notice"
            ),
            json!({ "key_set": key_set_json(&CURRENT), "advisory": advisory_inputs(&h.one, &[0, 2]) }),
            json!({ "advisory": advisory_expected(&h.one), "verify": "OK" }),
        ),
    );
    assert_vector(
        "rad1_three_of_three_001.json",
        &vector(
            "rad1_three_of_three_001",
            &format!(
                "{LAYOUT}. Advisory #2 (prev_digest = digest of rad1_two_of_three_001) signed \
                 by all three test keys, with every kind: SUITE_STATUS DEPRECATED and BROKEN, \
                 RELEASE_FLOOR 7, FEATURE_HOLD BROKEN and DEPRECATED, NOTICE, and kind 0x7F, \
                 which this version does not know (valid, shown, never enforced). It follows \
                 #1: succession NEXT"
            ),
            json!({
                "key_set": key_set_json(&CURRENT),
                "advisory": advisory_inputs(&h.two, &[0, 1, 2]),
                "previous_hex": hex::encode(h.one.bytes()),
            }),
            json!({
                "advisory": advisory_expected(&h.two),
                "verify": "OK",
                "succession": succession(Some((1, h.one.digest())), &h.two).name(),
            }),
        ),
    );
    assert_eq!(
        succession(Some((2, h.two.digest())), &h.three),
        Succession::Next
    );
    assert_vector(
        "rad1_key_rotation_001.json",
        &vector(
            "rad1_key_rotation_001",
            &format!(
                "{LAYOUT}. Key rotation (RAVEN_SECURITY_ADVISORY_V1 §6.2): advisory #3 \
                 (after rad1_three_of_three_001), signed by keys 1 and 2 of the test key set, \
                 adds a KEY_SET entry naming the next set (seeds 0x22, 0x33, 0x44 x 32, \
                 threshold 2: key 0x11 replaced). Advisory #4 names the next set's digest and \
                 is signed by its keys 0 and 2 (seeds 0x22 and 0x44): it verifies under the \
                 next set and is WRONG_KEY_SET under the old one"
            ),
            json!({
                "key_set": key_set_json(&CURRENT),
                "next_key_set": key_set_json(&NEXT),
                "rotation": advisory_inputs(&h.three, &[1, 2]),
                "after": advisory_inputs(&h.four, &[0, 2]),
            }),
            json!({
                "rotation": advisory_expected(&h.three),
                "rotation_verify": "OK",
                "after": advisory_expected(&h.four),
                "after_verify_next": "OK",
                "after_verify_old": SigError::WrongKeySet.code(),
                "succession": succession(Some((3, h.three.digest())), &h.four).name(),
            }),
        ),
    );

    // Negatives: forged, rolled back, equivocating.
    let one = h.one.draft();
    let [a, b, c] = crate::release_keys::test_keys::signers();
    let one_input = one.signing_input().unwrap();
    let with = |sigs: Vec<(u8, [u8; 64])>| one.assemble(&SigBlock::new(sigs)).unwrap();
    let only_one = with(vec![(1, b.sign(&one_input))]);
    assert_vector(
        "negative/rad1_one_sig_001.json",
        &check_vector(
            "rad1_one_sig_001",
            "Advisory #1 (rad1_two_of_three_001's content) with one signature (key 1) under \
             the 2-of-3 test key set: BELOW_THRESHOLD, refused (SEC_ADVISORY_FORGED)",
            &CURRENT,
            only_one.bytes(),
            SigError::BelowThreshold.code(),
        ),
    );
    let dup = with(vec![(0, a.sign(&one_input)), (0, a.sign(&one_input))]);
    assert_vector(
        "negative/rad1_dup_key_index_001.json",
        &check_vector(
            "rad1_dup_key_index_001",
            "Advisory #1 with key 0's signature listed twice (key indexes 0, 0): one key \
             must not count twice toward the threshold. KEY_INDEX_ORDER (indexes must be \
             strictly increasing), refused",
            &CURRENT,
            dup.bytes(),
            SigError::KeyIndexOrder.code(),
        ),
    );
    let two_input = h.two.signing_input();
    let bad_among_good = with(vec![
        (0, a.sign(&one_input)),
        (1, b.sign(&two_input)),
        (2, c.sign(&one_input)),
    ]);
    assert_vector(
        "negative/rad1_bad_sig_among_good_001.json",
        &check_vector(
            "rad1_bad_sig_among_good_001",
            "Advisory #1 with three signatures: keys 0 and 2 sign it (enough for the \
             threshold), key 1's signature is over other bytes (advisory #2's signing \
             input). Every listed signature must verify: BAD_SIGNATURE, refused",
            &CURRENT,
            bad_among_good.bytes(),
            SigError::BadSignature.code(),
        ),
    );
    let other = set_of(&OTHER);
    let foreign = signed(
        &AdvisoryDraft {
            key_set_digest: other.digest(),
            ..one.clone()
        },
        &OTHER,
        &[0, 1],
    );
    assert_eq!(foreign.verify(&other), Ok(()));
    let mut wrong = check_vector(
        "rad1_wrong_keyset_001",
        "Advisory #1's content naming another key set (seeds 0x44, 0x55, 0x66 x 32, \
         threshold 2), signed by its keys 0 and 1, checked under the test key set: \
         WRONG_KEY_SET, refused. Under the set it names it verifies",
        &CURRENT,
        foreign.bytes(),
        SigError::WrongKeySet.code(),
    );
    wrong["inputs"]["signed_by_key_set"] = key_set_json(&OTHER);
    wrong["expected"]["verify_under_signed_by"] = json!("OK");
    assert_vector("negative/rad1_wrong_keyset_001.json", &wrong);
    assert_vector(
        "negative/rad1_rollback_pair_001.json",
        &pair_vector(
            "rad1_rollback_pair_001",
            "Both advisories verify; the stored one is #2 (rad1_three_of_three_001), the new \
             one #1 (rad1_two_of_three_001). A lower serial is a rollback: ignored, the \
             stored one kept (SEC_ADVISORY_ROLLBACK)",
            &h.two,
            &h.one,
            Succession::Rollback,
        ),
    );
    assert_vector(
        "negative/rad1_equivocation_pair_001.json",
        &pair_vector(
            "rad1_equivocation_pair_001",
            "Both advisories verify and carry serial 2 with the same prev_digest, but their \
             entries differ: the signers issued two histories. EQUIVOCATION: both kept as \
             evidence, update state frozen (SEC_ADVISORY_EQUIVOCATION)",
            &h.two,
            &h.two_alt,
            Succession::Equivocation,
        ),
    );
    assert_vector(
        "negative/rad1_broken_chain_pair_001.json",
        &pair_vector(
            "rad1_broken_chain_pair_001",
            "Both advisories verify; the stored one is the other #2 (of \
             rad1_equivocation_pair_001), the new one #3 (of rad1_key_rotation_001), whose \
             prev_digest names rad1_three_of_three_001. The next serial chained to another \
             advisory is also EQUIVOCATION",
            &h.two_alt,
            &h.three,
            Succession::Equivocation,
        ),
    );
    assert_vector(
        "negative/rad1_decode_rules_001.json",
        &vector(
            "rad1_decode_rules_001",
            "Every structural refusal of RAVEN_SECURITY_ADVISORY_V1 §5, each case breaking \
             one rule (the first it meets; the signature block, where present, is a valid \
             2-of-3 block of the test keys over the case's bytes). too_long: advisory_hex \
             followed by zero bytes up to zero_pad_to bytes",
            json!({
                "cases": decode_cases().iter().map(|(name, bytes, _)| {
                    if *name == "too_long" {
                        let base = Raw::new().signed();
                        assert_eq!(&bytes[..base.len()], &base[..]);
                        json!({ "name": name, "advisory_hex": hex::encode(&base), "zero_pad_to": bytes.len() })
                    } else {
                        json!({ "name": name, "advisory_hex": hex::encode(bytes) })
                    }
                }).collect::<Vec<_>>(),
            }),
            json!({
                "errors": decode_cases().iter().map(|(name, _, e)| json!({ "name": name, "error": e.code() })).collect::<Vec<_>>(),
            }),
        ),
    );
    assert_vector(
        "negative/keyset_rules_001.json",
        &vector(
            "keyset_rules_001",
            "Every refusal of RAVEN_SECURITY_ADVISORY_V1 §2.1 (header, algorithm, count, \
             length, threshold, then each key: a canonical encoding of a curve point not of \
             small order, and not listed before), each case breaking one rule",
            json!({
                "cases": key_set_cases().iter().map(|(name, bytes, _)| json!({ "name": name, "key_set_hex": hex::encode(bytes) })).collect::<Vec<_>>(),
            }),
            json!({
                "errors": key_set_cases().iter().map(|(name, _, e)| json!({ "name": name, "error": e.code() })).collect::<Vec<_>>(),
            }),
        ),
    );
}

/// The committed `keyset_*` and `rad1_*` files are exactly the ones
/// [`update_vectors`] writes (other update vectors have their own modules).
#[test]
fn update_vector_files() {
    if std::env::var(REGEN).as_deref() == Ok("1") {
        return; // being written right now
    }
    let names = |dir: &str| {
        let mut names: Vec<String> = std::fs::read_dir(rvn1_dir().join(dir))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| {
                (n.starts_with("keyset_") || n.starts_with("rad1_")) && n.ends_with(".json")
            })
            .collect();
        names.sort();
        names
    };
    assert_eq!(
        names("update"),
        [
            "keyset_001.json",
            "rad1_key_rotation_001.json",
            "rad1_three_of_three_001.json",
            "rad1_two_of_three_001.json",
        ]
    );
    assert_eq!(
        names("update/negative"),
        [
            "keyset_rules_001.json",
            "rad1_bad_sig_among_good_001.json",
            "rad1_broken_chain_pair_001.json",
            "rad1_decode_rules_001.json",
            "rad1_dup_key_index_001.json",
            "rad1_equivocation_pair_001.json",
            "rad1_one_sig_001.json",
            "rad1_rollback_pair_001.json",
            "rad1_wrong_keyset_001.json",
        ]
    );
}
