//! RTL1 transparency logs (RAVEN_TRANSPARENCY_LOG_V1) and the vectors in
//! `shared-vectors/rvn1/update` (`rtl1_*`). The vectors are written only
//! under `RAVEN_REGEN_SECURITY_VECTORS=1` (a deliberate wire change) and
//! otherwise compared with the committed files; the Python reference
//! (`protocol/reference/raven_protocol/tlog.py`) checks every one, computes
//! every root on its own and builds every signed tree head and snapshot
//! again, byte for byte.

use super::*;
use crate::release_keys::test_keys::{key_set, key_set_of, signer};
use serde_json::{json, Value};

const REGEN: &str = "RAVEN_REGEN_SECURITY_VECTORS";
/// 2026-10-23T00:00:00Z; entry `i` is logged `i` days later.
const LOGGED_AT_MS: u64 = 1_792_713_600_000;
const DAY_MS: u64 = 86_400_000;
/// The test key set's seed bytes, by key index.
const CURRENT: [u8; 3] = [0x11, 0x22, 0x33];
/// A set that is not the test set (the wrong-key-set case).
const OTHER: [u8; 3] = [0x44, 0x55, 0x66];
/// Domain of the synthetic digests of the test log.
const TEST_DIGEST_DOMAIN: &[u8] = b"rvn1/tlog/test-artifact\0";

fn rvn1_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.pop();
    p.join("shared-vectors/rvn1")
}

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// A synthetic artifact digest: `SHA-256(domain || tag || i as u32)`.
fn artifact(tag: &[u8], i: usize) -> [u8; 32] {
    sha(&[TEST_DIGEST_DOMAIN, tag, &(i as u32).to_be_bytes()])
}

/// Entry `i` of the test log: the test key set first, then advisories (odd
/// `i`) and manifests (even `i`), one a day.
fn entry(i: usize) -> LogEntry {
    let (kind, digest) = match i {
        0 => (EntryType::KeySet, key_set().digest()),
        _ if i % 2 == 1 => (EntryType::Advisory, artifact(b"advisory", i)),
        _ => (EntryType::Manifest, artifact(b"manifest", i)),
    };
    LogEntry {
        kind,
        digest,
        logged_at_ms: LOGGED_AT_MS + i as u64 * DAY_MS,
    }
}

/// The first `n` entries of the test log.
fn log(n: usize) -> Vec<LogEntry> {
    (0..n).map(entry).collect()
}

/// The other entry 4 of the split view: another manifest.
fn alt_entry_4() -> LogEntry {
    LogEntry {
        digest: artifact(b"other manifest", 4),
        ..entry(4)
    }
}

fn set_of(seeds: &[u8]) -> KeySet {
    key_set_of(2, seeds)
}

/// The tree head of `entries`, signed at the day after the last entry by
/// the keys at `indexes` of the set with these seed bytes.
fn sth_of(entries: &[LogEntry], seeds: &[u8], indexes: &[u8]) -> Sth {
    let draft = SthDraft::of_entries(entries, sth_time(entries.len()), set_of(seeds).digest());
    signed(&draft, seeds, indexes)
}

fn sth_time(n: usize) -> u64 {
    LOGGED_AT_MS + n as u64 * DAY_MS
}

fn signed(draft: &SthDraft, seeds: &[u8], indexes: &[u8]) -> Sth {
    let ids: Vec<Identity> = indexes
        .iter()
        .map(|i| signer(seeds[usize::from(*i)]))
        .collect();
    let signers: Vec<(u8, &Identity)> = indexes.iter().copied().zip(&ids).collect();
    draft.sign(&signers).unwrap()
}

/// A snapshot of `entries` with its tree head signed by the test keys at
/// `indexes`.
fn snapshot(entries: Vec<LogEntry>, indexes: &[u8]) -> Snapshot {
    let sth = sth_of(&entries, &CURRENT, indexes);
    Snapshot::new(entries, sth).unwrap()
}

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

// ── Hashing (spec §3) ───────────────────────────────────────────────

/// The leaves of the RFC 6962 reference tests (certificate-transparency's
/// `merkle_tree_test`, also in RFC 9162's drafts).
fn rfc6962_leaves() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0x00],
        vec![0x10],
        vec![0x20, 0x21],
        vec![0x30, 0x31],
        vec![0x40, 0x41, 0x42, 0x43],
        (0x50..=0x57).collect(),
        (0x60..=0x6f).collect(),
    ]
}

/// The published roots of the first 0..=8 of those leaves.
const RFC6962_ROOTS: [&str; 9] = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];

#[test]
fn rfc6962_reference_roots() {
    let leaves: Vec<[u8; 32]> = rfc6962_leaves().iter().map(|l| leaf_hash(l)).collect();
    for (n, want) in RFC6962_ROOTS.iter().enumerate() {
        assert_eq!(root_of_leaf_hashes(&leaves[..n]), hex32(want), "{n} leaves");
    }
}

/// The same root computed another way: hash neighbours level by level,
/// carrying an odd last node up unchanged (equal to RFC 6962's split for
/// every size).
fn level_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return sha(&[]);
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|p| match p {
                [l, r] => node_hash(l, r),
                [one] => *one,
                _ => unreachable!(),
            })
            .collect();
    }
    level[0]
}

#[test]
fn mth_is_rfc6962() {
    // 1..=17 entries by the definition, written out.
    let e = log(17);
    let l: Vec<[u8; 32]> = e.iter().map(LogEntry::leaf_hash).collect();
    let n = |a: [u8; 32], b: [u8; 32]| node_hash(&a, &b);
    assert_eq!(l[0], sha(&[&[0], &e[0].encode()]));
    assert_eq!(
        node_hash(&l[0], &l[1]),
        sha(&[&[1], &l[0], &l[1]]),
        "node = SHA-256(0x01 || left || right)"
    );
    assert_eq!(mth(&e[..1]), l[0]);
    assert_eq!(mth(&e[..2]), n(l[0], l[1]));
    assert_eq!(mth(&e[..3]), n(n(l[0], l[1]), l[2]));
    let four = n(n(l[0], l[1]), n(l[2], l[3]));
    assert_eq!(mth(&e[..4]), four);
    assert_eq!(mth(&e[..5]), n(four, l[4]));
    assert_eq!(mth(&e[..6]), n(four, n(l[4], l[5])));
    assert_eq!(mth(&e[..7]), n(four, n(n(l[4], l[5]), l[6])));
    let eight = n(four, n(n(l[4], l[5]), n(l[6], l[7])));
    assert_eq!(mth(&e[..8]), eight);
    assert_eq!(mth(&e[..9]), n(eight, l[8]));
    let sixteen = n(eight, root_of_leaf_hashes(&l[8..16]));
    assert_eq!(mth(&e[..16]), sixteen);
    assert_eq!(mth(&e), n(sixteen, l[16]));
    for k in 1..=17 {
        assert_eq!(mth(&e[..k]), level_root(&l[..k]), "{k} entries");
    }
    // Every size up to past the cap, by both methods.
    let many: Vec<[u8; 32]> = (0..MAX_LOG_ENTRIES + 3)
        .map(|i| leaf_hash(&(i as u64).to_be_bytes()))
        .collect();
    for k in (0..=64).chain([MAX_LOG_ENTRIES - 1, MAX_LOG_ENTRIES, MAX_LOG_ENTRIES + 3]) {
        assert_eq!(
            root_of_leaf_hashes(&many[..k]),
            level_root(&many[..k]),
            "{k}"
        );
    }
    assert_eq!(mth(&[]), sha(&[]));
}

#[test]
fn entry_codec() {
    for e in log(6) {
        let b = e.encode();
        assert_eq!(b.len(), ENTRY_LEN);
        assert_eq!(b[0], e.kind.byte());
        assert_eq!(LogEntry::decode(&b), Ok(e));
        assert_eq!(e.leaf_hash(), leaf_hash(&b));
    }
    let mut b = entry(1).encode();
    b[0] = 0;
    assert_eq!(LogEntry::decode(&b), Err(Rtl1Error::BadEntryType));
    // A type this version does not know is kept, hashed and never matched.
    b[0] = 0x7f;
    let unknown = LogEntry::decode(&b).unwrap();
    assert_eq!(unknown.kind, EntryType::Other(0x7f));
    assert_eq!(unknown.encode(), b);
    assert_eq!(unknown.kind.name(), "UNKNOWN");
    assert!(!contains(&[unknown], EntryType::Advisory, &unknown.digest));
    assert_eq!(LogEntry::decode(&b[..40]), Err(Rtl1Error::Truncated));
    assert_eq!(
        LogEntry::decode(&[&b[..], &[0]].concat()),
        Err(Rtl1Error::Truncated)
    );
    for (byte, kind) in [
        (1, EntryType::Manifest),
        (2, EntryType::Advisory),
        (3, EntryType::KeySet),
    ] {
        assert_eq!(EntryType::from_byte(byte), Some(kind));
        assert_eq!(kind.byte(), byte);
    }
    assert_eq!(EntryType::from_byte(0), None);
}

// ── Tree heads and snapshots (spec §4-§6) ───────────────────────────

#[test]
fn sth_signs_and_verifies() {
    let five = log(5);
    let sth = sth_of(&five, &CURRENT, &[0, 1]);
    assert_eq!(sth.tree_size, 5);
    assert_eq!(sth.root_hash, mth(&five));
    assert_eq!(sth.bytes().len(), STH_SIGNED_LEN + 1 + 2 * 65);
    assert_eq!(sth.verify(&key_set()), Ok(()));
    assert_eq!(Sth::decode(sth.bytes()).as_ref(), Ok(&sth));
    assert_eq!(
        sth.signing_input(),
        [b"rvn1/tlog/sth/v1\0".as_slice(), &sth.bytes()[..88]].concat()
    );
    // Canonical: the decoded content re-encodes byte for byte.
    assert_eq!(sth.draft().assemble(sth.sigs()).unwrap(), sth);
    assert_eq!(
        sth.verify(&set_of(&OTHER)),
        Err(SigError::WrongKeySet),
        "another key set"
    );
    // The same head signed by the other pairs and by all three.
    for indexes in [&[0, 2][..], &[1, 2], &[0, 1, 2]] {
        let s = signed(&sth.draft(), &CURRENT, indexes);
        assert_eq!(s.verify(&key_set()), Ok(()), "{indexes:?}");
    }
    let one = signed(&sth.draft(), &CURRENT, &[2]);
    assert_eq!(one.verify(&key_set()), Err(SigError::BelowThreshold));
    // Domain separation: the advisory domain over the same bytes fails.
    let body = sth.draft().body().unwrap();
    let [a, b, _] = crate::release_keys::test_keys::signers();
    let other_domain = [crate::advisory::SIGNING_DOMAIN, &body[..]].concat();
    let wrong = sth
        .draft()
        .assemble(&SigBlock::sign(&other_domain, &[(0, &a), (1, &b)]))
        .unwrap();
    assert_eq!(wrong.verify(&key_set()), Err(SigError::BadSignature));
    assert_eq!(
        SthDraft {
            tree_size: 0,
            ..sth.draft()
        }
        .body(),
        Err(Rtl1Error::BadTreeSize)
    );
}

#[test]
fn snapshot_round_trip_and_check() {
    let snap = snapshot(log(5), &[0, 1]);
    let bytes = snap.encode();
    assert_eq!(
        bytes.len(),
        SNAPSHOT_HEADER_LEN + 5 * ENTRY_LEN + 2 + snap.sth().bytes().len()
    );
    assert_eq!(Snapshot::decode(&bytes).as_ref(), Ok(&snap));
    assert_eq!(Snapshot::decode(&bytes).unwrap().encode(), bytes);
    let checked = snap.check(&key_set()).unwrap();
    assert_eq!(checked.entries(), log(5).as_slice());
    assert_eq!(checked.sth(), snap.sth());
    assert_eq!(checked.snapshot(), &snap);
    // What the log lists.
    assert!(checked.contains(EntryType::KeySet, &key_set().digest()));
    assert!(checked.contains(EntryType::Advisory, &entry(3).digest));
    assert!(checked.contains(EntryType::Manifest, &entry(4).digest));
    assert!(!checked.contains(EntryType::Advisory, &entry(4).digest));
    assert!(!checked.contains(EntryType::Manifest, &entry(6).digest));
    assert!(!contains(&[], EntryType::KeySet, &key_set().digest()));
    // An unknown entry type is part of the log like any other.
    let mut odd = log(4);
    odd.push(LogEntry {
        kind: EntryType::Other(0x09),
        ..entry(4)
    });
    let snap = snapshot(odd.clone(), &[1, 2]);
    assert_eq!(snap.check(&key_set()).unwrap().entries(), odd.as_slice());
    assert_eq!(
        snap.check(&set_of(&OTHER)),
        Err(LogCheckError::Sig(SigError::WrongKeySet))
    );
}

#[test]
fn consistency_prefix_both_ways() {
    use Consistency::*;
    let five = log(5);
    let eight = log(8);
    assert_eq!(consistency(&five, &eight), Extends);
    assert_eq!(consistency(&eight, &five), Older);
    assert_eq!(consistency(&five, &five), Same);
    assert_eq!(consistency(&[], &five), Extends, "nothing stored yet");
    assert_eq!(consistency(&five, &[]), Older);
    assert_eq!(consistency(&[], &[]), Same);
    for k in 1..=8 {
        assert_eq!(
            consistency(&eight[..k], &eight),
            if k == 8 { Same } else { Extends }
        );
        assert_eq!(
            consistency(&eight, &eight[..k]),
            if k == 8 { Same } else { Older }
        );
    }
    // Checked snapshots: the same, and a later tree head over the same log.
    let a = snapshot(five.clone(), &[0, 1]).check(&key_set()).unwrap();
    let b = snapshot(eight.clone(), &[0, 2]).check(&key_set()).unwrap();
    assert_eq!(b.consistency(a.entries()), Extends);
    assert_eq!(a.consistency(b.entries()), Older);
    let later = Snapshot::new(
        five.clone(),
        signed(
            &SthDraft::of_entries(&five, sth_time(9), key_set().digest()),
            &CURRENT,
            &[1, 2],
        ),
    )
    .unwrap()
    .check(&key_set())
    .unwrap();
    assert_ne!(later.sth(), a.sth());
    assert_eq!(later.consistency(a.entries()), Same);
}

#[test]
fn split_view_pairs() {
    use Consistency::Split;
    let five = log(5);
    // The same size, another entry 4 (another manifest).
    let mut other = log(4);
    other.push(alt_entry_4());
    // A longer log that is not an extension (entry 4 replaced, then more).
    let mut longer = other.clone();
    longer.extend([entry(5), entry(6)]);
    // Only the time of one entry differs.
    let mut retimed = five.clone();
    retimed[2].logged_at_ms += 1;
    // Only the type of one entry differs.
    let mut retyped = five.clone();
    retyped[3].kind = EntryType::Manifest;
    // A different first entry under a longer log.
    let mut first = log(9);
    first[0] = entry(1);
    for (name, b) in [
        ("other", other),
        ("longer", longer),
        ("retimed", retimed),
        ("retyped", retyped),
        ("first", first),
    ] {
        // Both validly signed: evidence of two histories.
        let a = snapshot(five.clone(), &[0, 1]).check(&key_set()).unwrap();
        let b = snapshot(b, &[1, 2]).check(&key_set()).unwrap();
        assert_eq!(consistency(a.entries(), b.entries()), Split, "{name}");
        assert_eq!(consistency(b.entries(), a.entries()), Split, "{name}");
        assert_eq!(b.consistency(a.entries()), Split, "{name}");
        // The longer one of a split never extends the shorter one's prefix.
        for k in 5..=b.entries().len() {
            assert_eq!(
                consistency(a.entries(), &b.entries()[..k]),
                Split,
                "{name} {k}"
            );
        }
    }
}

#[test]
fn bad_root() {
    let five = log(5);
    let sth = sth_of(&five, &CURRENT, &[0, 1]);
    let refuse = |entries: Vec<LogEntry>| {
        let snap = Snapshot::new(entries, sth.clone()).unwrap();
        assert_eq!(snap.sth().verify(&key_set()), Ok(()));
        snap.check(&key_set())
    };
    // A manifest substituted after signing.
    let mut swapped = five.clone();
    swapped[4] = alt_entry_4();
    assert_eq!(refuse(swapped), Err(LogCheckError::BadRoot));
    // The same entries in another order.
    let mut reordered = five.clone();
    reordered.swap(1, 3);
    assert_eq!(refuse(reordered), Err(LogCheckError::BadRoot));
    // Another log of the same size.
    let other: Vec<LogEntry> = log(6)[1..].to_vec();
    assert_eq!(refuse(other), Err(LogCheckError::BadRoot));
    assert!(refuse(five).is_ok());
    assert_eq!(LogCheckError::BadRoot.code(), "BAD_ROOT");
    // A signature failure is checked first.
    let mut bad = log(5);
    bad[0].logged_at_ms += 1;
    let snap = Snapshot::new(bad, sth_of(&log(5), &OTHER, &[0, 1])).unwrap();
    assert_eq!(
        snap.check(&key_set()),
        Err(LogCheckError::Sig(SigError::WrongKeySet))
    );
}

#[test]
fn the_cap() {
    let entries: Vec<LogEntry> = (0..=MAX_LOG_ENTRIES).map(entry).collect();
    let full = &entries[..MAX_LOG_ENTRIES];
    // 1,400 entries: decoded and checked.
    let snap = snapshot(full.to_vec(), &[0, 1]);
    let bytes = snap.encode();
    assert_eq!(Snapshot::decode(&bytes).as_ref(), Ok(&snap));
    assert!(snap.check(&key_set()).is_ok());
    // With the longest tree head (8 keys, all signing): exactly the limit.
    let seeds: Vec<u8> = (1..=8u8).map(|i| i * 0x11).collect();
    let eight = key_set_of(8, &seeds);
    let draft = SthDraft::of_entries(full, sth_time(MAX_LOG_ENTRIES), eight.digest());
    let sth = signed(&draft, &seeds, &[0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(sth.bytes().len(), MAX_STH_LEN);
    assert_eq!(sth.verify(&eight), Ok(()));
    let longest = Snapshot::new(full.to_vec(), sth).unwrap();
    let bytes = longest.encode();
    assert_eq!(bytes.len(), MAX_SNAPSHOT_LEN);
    assert_eq!(MAX_SNAPSHOT_LEN, 58_023);
    assert_eq!(Snapshot::decode(&bytes).as_ref(), Ok(&longest));
    assert!(longest.check(&eight).is_ok());
    assert_eq!(
        Snapshot::decode(&[&bytes[..], &[0]].concat()),
        Err(Rtl1Error::TooLong)
    );
    // 1,401 entries: refused, however they arrive.
    let over = sth_of(&entries, &CURRENT, &[0, 1]);
    assert_eq!(over.tree_size, 1_401);
    assert_eq!(
        Snapshot::new(entries.clone(), over.clone()),
        Err(Rtl1Error::TooManyEntries)
    );
    let raw = RawSnap {
        entries: entries.iter().map(LogEntry::encode).collect(),
        sth: over.bytes().to_vec(),
        ..RawSnap::new()
    }
    .bytes();
    assert!(raw.len() < MAX_SNAPSHOT_LEN);
    assert_eq!(Snapshot::decode(&raw), Err(Rtl1Error::TooManyEntries));
    assert_eq!(Snapshot::new(Vec::new(), over), Err(Rtl1Error::BadTreeSize));
}

/// Any single-byte change of a signed snapshot (and a byte more or less)
/// makes it fail to decode or to check.
#[test]
fn any_single_byte_change_fails() {
    let set = key_set();
    let bytes = snapshot(log(5), &[0, 1]).encode();
    let fails = |m: &[u8]| match Snapshot::decode(m) {
        Err(_) => true,
        Ok(s) => s.check(&set).is_err(),
    };
    assert!(!fails(&bytes));
    for i in 0..bytes.len() {
        for x in [0x01u8, 0x80, 0xff] {
            let mut m = bytes.clone();
            m[i] ^= x;
            assert!(fails(&m), "byte {i} ^ {x:#04x} still checks");
        }
    }
    assert!(fails(&bytes[..bytes.len() - 1]));
    assert!(fails(&[&bytes[..], &[0]].concat()));
}

// ── Structural rules (spec §4, §5) ──────────────────────────────────

/// A tree head's fields, valid unless one is changed.
#[derive(Clone)]
struct RawSth {
    magic: [u8; 4],
    version: u8,
    kind: u8,
    reserved: u16,
    tree_size: u64,
    root: [u8; 32],
}

impl RawSth {
    /// The head of the 5-entry test log.
    fn new() -> Self {
        Self {
            magic: *b"RTL1",
            version: 1,
            kind: KIND_STH,
            reserved: 0,
            tree_size: 5,
            root: mth(&log(5)),
        }
    }

    fn body(&self) -> Vec<u8> {
        let mut b = self.magic.to_vec();
        b.extend([self.version, self.kind]);
        b.extend(self.reserved.to_be_bytes());
        b.extend(self.tree_size.to_be_bytes());
        b.extend(self.root);
        b.extend(sth_time(5).to_be_bytes());
        b.extend(key_set().digest());
        b
    }

    /// The body and a valid 2-of-3 block over it: only the changed field is
    /// wrong.
    fn signed(&self) -> Vec<u8> {
        let body = self.body();
        let [a, b, _] = crate::release_keys::test_keys::signers();
        let block = SigBlock::sign(&[STH_SIGNING_DOMAIN, &body].concat(), &[(0, &a), (1, &b)]);
        [body, block.encode()].concat()
    }
}

/// A snapshot's fields, valid (the 5-entry test log) unless one is changed.
#[derive(Clone)]
struct RawSnap {
    magic: [u8; 4],
    version: u8,
    kind: u8,
    reserved: u16,
    count: Option<u32>,
    entries: Vec<[u8; ENTRY_LEN]>,
    sth_len: Option<u16>,
    sth: Vec<u8>,
}

impl RawSnap {
    fn new() -> Self {
        Self {
            magic: *b"RTL1",
            version: 1,
            kind: KIND_SNAPSHOT,
            reserved: 0,
            count: None,
            entries: log(5).iter().map(LogEntry::encode).collect(),
            sth_len: None,
            sth: RawSth::new().signed(),
        }
    }

    fn header(&self) -> Vec<u8> {
        let mut b = self.magic.to_vec();
        b.extend([self.version, self.kind]);
        b.extend(self.reserved.to_be_bytes());
        b.extend(
            self.count
                .unwrap_or(self.entries.len() as u32)
                .to_be_bytes(),
        );
        b
    }

    fn bytes(&self) -> Vec<u8> {
        let mut b = self.header();
        for e in &self.entries {
            b.extend_from_slice(e);
        }
        b.extend(self.sth_len.unwrap_or(self.sth.len() as u16).to_be_bytes());
        b.extend_from_slice(&self.sth);
        b
    }
}

/// Which decoder a decode case is for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Object {
    Sth,
    Snapshot,
}

impl Object {
    fn name(self) -> &'static str {
        match self {
            Self::Sth => "sth",
            Self::Snapshot => "snapshot",
        }
    }

    fn decode(self, bytes: &[u8]) -> Result<(), Rtl1Error> {
        match self {
            Self::Sth => Sth::decode(bytes).map(drop),
            Self::Snapshot => Snapshot::decode(bytes).map(drop),
        }
    }
}

/// Every refusal of spec §4 and §5, each the first rule its bytes break.
/// The bytes of `snapshot_too_long` are the valid snapshot zero-padded to
/// 58,024 bytes.
fn decode_cases() -> Vec<(&'static str, Object, Vec<u8>, Rtl1Error)> {
    use Object::{Snapshot as Snap, Sth as Head};
    use Rtl1Error::*;
    let sth = RawSth::new();
    let ok_sth = sth.signed();
    let with_sth = |f: &dyn Fn(&mut RawSth)| {
        let mut s = sth.clone();
        f(&mut s);
        s.signed()
    };
    let snap = RawSnap::new();
    let ok = snap.bytes();
    let with = |f: &dyn Fn(&mut RawSnap)| {
        let mut s = snap.clone();
        f(&mut s);
        s.bytes()
    };
    let mut short_block = ok_sth.clone();
    short_block[STH_SIGNED_LEN] = 3;
    let mut too_long = ok.clone();
    too_long.resize(MAX_SNAPSHOT_LEN + 1, 0);
    let mut sth_too_long = ok_sth.clone();
    sth_too_long.resize(MAX_STH_LEN + 1, 0);
    let mut cut_entry = snap.header();
    for e in &snap.entries[..4] {
        cut_entry.extend_from_slice(e);
    }
    cut_entry.extend_from_slice(&snap.entries[4][..20]);
    let mut no_sth_len = snap.header();
    for e in &snap.entries {
        no_sth_len.extend_from_slice(e);
    }
    let four = RawSth {
        tree_size: 4,
        root: mth(&log(4)),
        ..RawSth::new()
    }
    .signed();
    vec![
        ("sth_too_long", Head, sth_too_long, TooLong),
        ("sth_empty", Head, Vec::new(), Truncated),
        ("sth_87_bytes", Head, ok_sth[..87].to_vec(), Truncated),
        (
            "sth_bad_magic",
            Head,
            with_sth(&|s| s.magic = *b"RAD1"),
            BadMagic,
        ),
        (
            "sth_bad_version",
            Head,
            with_sth(&|s| s.version = 2),
            BadVersion,
        ),
        (
            "sth_kind_snapshot",
            Head,
            with_sth(&|s| s.kind = KIND_SNAPSHOT),
            BadKind,
        ),
        (
            "sth_bad_reserved",
            Head,
            with_sth(&|s| s.reserved = 1),
            BadReserved,
        ),
        (
            "sth_tree_size_zero",
            Head,
            with_sth(&|s| s.tree_size = 0),
            BadTreeSize,
        ),
        ("sth_no_signature_block", Head, sth.body(), BadSigBlock),
        ("sth_signature_block_short", Head, short_block, BadSigBlock),
        (
            "sth_byte_after_signature_block",
            Head,
            [&ok_sth[..], &[0]].concat(),
            BadSigBlock,
        ),
        ("snapshot_too_long", Snap, too_long, TooLong),
        ("snapshot_empty", Snap, Vec::new(), Truncated),
        (
            "snapshot_header_11_bytes",
            Snap,
            ok[..11].to_vec(),
            Truncated,
        ),
        (
            "snapshot_bad_magic",
            Snap,
            with(&|s| s.magic = *b"RTL2"),
            BadMagic,
        ),
        (
            "snapshot_bad_version",
            Snap,
            with(&|s| s.version = 0),
            BadVersion,
        ),
        ("snapshot_given_an_sth", Snap, ok_sth.clone(), BadKind),
        (
            "snapshot_bad_reserved",
            Snap,
            with(&|s| s.reserved = 0x8000),
            BadReserved,
        ),
        (
            "snapshot_no_entries",
            Snap,
            with(&|s| s.entries.clear()),
            BadTreeSize,
        ),
        (
            "snapshot_1401_entries",
            Snap,
            [
                &with(&|s| s.count = Some(1_401))[..SNAPSHOT_HEADER_LEN],
                &[0; ENTRY_LEN],
            ]
            .concat(),
            TooManyEntries,
        ),
        (
            "snapshot_count_u32_max",
            Snap,
            with(&|s| s.count = Some(u32::MAX)),
            TooManyEntries,
        ),
        (
            "snapshot_entry_type_zero",
            Snap,
            with(&|s| s.entries[2][0] = 0),
            BadEntryType,
        ),
        ("snapshot_entry_cut", Snap, cut_entry, Truncated),
        ("snapshot_no_sth_length", Snap, no_sth_len, Truncated),
        (
            "snapshot_sth_cut",
            Snap,
            ok[..ok.len() - 1].to_vec(),
            Truncated,
        ),
        (
            "snapshot_byte_after_sth",
            Snap,
            [&ok[..], &[0]].concat(),
            TrailingBytes,
        ),
        (
            "snapshot_sth_length_short",
            Snap,
            with(&|s| {
                s.sth_len = Some(s.sth.len() as u16 - 1);
            }),
            TrailingBytes,
        ),
        (
            "snapshot_sth_without_signatures",
            Snap,
            with(&|s| s.sth = RawSth::new().body()),
            BadSigBlock,
        ),
        (
            "snapshot_sth_tree_size_4",
            Snap,
            with(&|s| s.sth = four.clone()),
            SizeMismatch,
        ),
    ]
}

#[test]
fn decode_acceptance_table() {
    assert!(Sth::decode(&RawSth::new().signed()).is_ok());
    let ok = Snapshot::decode(&RawSnap::new().bytes()).unwrap();
    assert_eq!(ok, snapshot(log(5), &[0, 1]));
    let mut names = Vec::new();
    for (name, object, bytes, want) in decode_cases() {
        assert_eq!(object.decode(&bytes), Err(want), "{name}");
        names.push(name);
    }
    // Every refusal has a case.
    let mut codes: Vec<&str> = decode_cases().iter().map(|c| c.3.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), 12);
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), decode_cases().len());
}

/// Every refusal of spec §6 for a decoded snapshot of the 5-entry log
/// (the key set it is checked under: the test key set).
fn check_cases() -> Vec<(&'static str, Snapshot, LogCheckError)> {
    use SigError::*;
    let five = log(5);
    let sth = sth_of(&five, &CURRENT, &[0, 1]);
    let with_sth = |s: Sth| Snapshot::new(five.clone(), s).unwrap();
    let [a, b, c] = crate::release_keys::test_keys::signers();
    let input = sth.signing_input();
    let block = |sigs: Vec<(u8, [u8; 64])>| sth.draft().assemble(&SigBlock::new(sigs)).unwrap();
    let advisory_domain = [crate::advisory::SIGNING_DOMAIN, &sth.bytes()[..88]].concat();
    let mut swapped = five.clone();
    swapped[4] = alt_entry_4();
    vec![
        (
            "wrong_key_set",
            with_sth(sth_of(&five, &OTHER, &[0, 1])),
            LogCheckError::Sig(WrongKeySet),
        ),
        (
            "key_index_order",
            with_sth(block(vec![(1, b.sign(&input)), (0, a.sign(&input))])),
            LogCheckError::Sig(KeyIndexOrder),
        ),
        (
            "unknown_key_index",
            with_sth(block(vec![(0, a.sign(&input)), (3, c.sign(&input))])),
            LogCheckError::Sig(UnknownKeyIndex),
        ),
        (
            "one_signature",
            with_sth(block(vec![(2, c.sign(&input))])),
            LogCheckError::Sig(BelowThreshold),
        ),
        (
            "advisory_domain",
            with_sth(block(vec![
                (0, a.sign(&advisory_domain)),
                (1, b.sign(&advisory_domain)),
            ])),
            LogCheckError::Sig(BadSignature),
        ),
        (
            "bad_signature_among_good",
            with_sth(block(vec![
                (0, a.sign(&input)),
                (1, b.sign(&advisory_domain)),
                (2, c.sign(&input)),
            ])),
            LogCheckError::Sig(BadSignature),
        ),
        (
            "substituted_manifest",
            Snapshot::new(swapped, sth.clone()).unwrap(),
            LogCheckError::BadRoot,
        ),
    ]
}

#[test]
fn check_rules() {
    for (name, snap, want) in check_cases() {
        assert_eq!(snap.check(&key_set()), Err(want), "{name}");
        // Each one decodes: only the check refuses it.
        assert_eq!(Snapshot::decode(&snap.encode()).as_ref(), Ok(&snap));
    }
}

// ── Vectors (spec §9) ───────────────────────────────────────────────

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

fn key_set_json(seeds: &[u8]) -> Value {
    let set = set_of(seeds);
    json!({
        "threshold": set.threshold(),
        "seeds_hex": seeds.iter().map(|b| hex::encode([*b; 32])).collect::<Vec<_>>(),
        "public_keys_hex": set.keys().iter().map(hex::encode).collect::<Vec<_>>(),
        "key_set_hex": hex::encode(set.encode()),
        "key_set_digest_hex": hex::encode(set.digest()),
    })
}

fn entries_json(entries: &[LogEntry]) -> Value {
    json!(entries
        .iter()
        .map(|e| json!({
            "type": e.kind.byte(),
            "digest_hex": hex::encode(e.digest),
            "logged_at_ms": e.logged_at_ms,
        }))
        .collect::<Vec<_>>())
}

/// What a signer builds: the head's fields and who signs.
fn sth_inputs(sth: &Sth) -> Value {
    json!({
        "tree_size": sth.tree_size,
        "root_hash_hex": hex::encode(sth.root_hash),
        "timestamp_ms": sth.timestamp_ms,
        "key_set_digest_hex": hex::encode(sth.key_set_digest),
        "signers": sth.sigs().sigs().iter().map(|(i, _)| *i).collect::<Vec<_>>(),
    })
}

/// A snapshot to rebuild: its entries and its head's fields and signers.
fn snapshot_inputs(s: &Snapshot) -> Value {
    json!({ "entries": entries_json(s.entries()), "sth": sth_inputs(s.sth()) })
}

fn snapshot_expected(s: &Snapshot) -> Value {
    json!({
        "snapshot_hex": hex::encode(s.encode()),
        "sth_hex": hex::encode(s.sth().bytes()),
        "tree_size": s.sth().tree_size,
        "root_hex": hex::encode(mth(s.entries())),
        "check": s.check(&key_set()).err().map_or("OK", LogCheckError::code),
    })
}

const LAYOUT: &str = "entry = type u8 (1 manifest, 2 advisory, 3 key set) | digest[32] | \
                      logged_at_ms u64; leaf = SHA-256(0x00 || entry), node = SHA-256(0x01 || \
                      left || right), split at the largest power of two below the size (RFC 6962 \
                      §2.1); STH = \"RTL1\" | 0x01 | kind 0x01 | reserved u16 | tree_size u64 | \
                      root_hash[32] | timestamp_ms u64 | key_set_digest[32] | signature block \
                      over \"rvn1/tlog/sth/v1\\0\" || bytes[0..88]; snapshot = \"RTL1\" | 0x01 | \
                      kind 0x02 | reserved u16 | entry_count u32 | entries | sth_len u16 | STH \
                      (RAVEN_TRANSPARENCY_LOG_V1 §2-§5)";

const TEST_LOG: &str = "The test log: entry 0 is the test key set (type 3, digest of \
                        keyset_001); entry i >= 1 is an advisory (odd i, type 2) or a manifest \
                        (even i, type 1) with the synthetic digest SHA-256(\"rvn1/tlog/\
                        test-artifact\\0\" || \"advisory\" or \"manifest\" || i as u32 BE); entry \
                        i is logged at 1792713600000 + i days (ms). A tree head over n entries \
                        is signed at 1792713600000 + n days";

#[test]
fn update_vectors_rtl1() {
    let seventeen = log(17);
    let rfc_leaves = rfc6962_leaves();
    let rfc_hashes: Vec<[u8; 32]> = rfc_leaves.iter().map(|l| leaf_hash(l)).collect();
    assert_vector(
        "rtl1_mth_001.json",
        &vector(
            "rtl1_mth_001",
            &format!(
                "{LAYOUT}. {TEST_LOG}. The roots of the first 1..=17 entries of the test log, \
                 and the RFC 6962 reference roots (certificate-transparency merkle_tree_test: \
                 0..=8 leaves of the raw byte strings rfc6962_leaves_hex) that the same hashing \
                 gives"
            ),
            json!({
                "entries": entries_json(&seventeen),
                "rfc6962_leaves_hex": rfc_leaves.iter().map(hex::encode).collect::<Vec<_>>(),
            }),
            json!({
                "entries_hex": seventeen.iter().map(|e| hex::encode(e.encode())).collect::<Vec<_>>(),
                "leaf_hashes_hex": seventeen.iter().map(|e| hex::encode(e.leaf_hash())).collect::<Vec<_>>(),
                "roots": (1..=17).map(|n| json!({
                    "tree_size": n,
                    "root_hex": hex::encode(mth(&seventeen[..n])),
                })).collect::<Vec<_>>(),
                "rfc6962_roots": (0..=8).map(|n| {
                    let root = root_of_leaf_hashes(&rfc_hashes[..n]);
                    assert_eq!(root, hex32(RFC6962_ROOTS[n]));
                    json!({ "leaves": n, "root_hex": hex::encode(root) })
                }).collect::<Vec<_>>(),
            }),
        ),
    );
    let five = snapshot(log(5), &[0, 1]);
    assert_vector(
        "rtl1_sth_001.json",
        &vector(
            "rtl1_sth_001",
            &format!(
                "{LAYOUT}. {TEST_LOG}. The tree head of the first 5 entries, signed by keys 0 \
                 and 1 of the test key set (keyset_001)"
            ),
            json!({
                "key_set": key_set_json(&CURRENT),
                "entries": entries_json(five.entries()),
                "sth": sth_inputs(five.sth()),
            }),
            json!({
                "sth_hex": hex::encode(five.sth().bytes()),
                "signing_input_hex": hex::encode(five.sth().signing_input()),
                "verify": five.sth().verify(&key_set()).err().map_or("OK", SigError::code),
            }),
        ),
    );
    let checked = five.check(&key_set()).unwrap();
    let probe = |kind: EntryType, digest: [u8; 32]| {
        json!({
            "type": kind.byte(),
            "digest_hex": hex::encode(digest),
            "contains": checked.contains(kind, &digest),
        })
    };
    assert_vector(
        "rtl1_snapshot_5_001.json",
        &vector(
            "rtl1_snapshot_5_001",
            &format!(
                "{LAYOUT}. {TEST_LOG}. The snapshot of the first 5 entries with the tree head \
                 of rtl1_sth_001: it checks under the test key set (signatures, then the \
                 recomputed root). contains: an entry is found by its type and digest only"
            ),
            json!({ "key_set": key_set_json(&CURRENT), "snapshot": snapshot_inputs(&five) }),
            json!({
                "snapshot": snapshot_expected(&five),
                "contains": [
                    probe(EntryType::KeySet, key_set().digest()),
                    probe(EntryType::Advisory, entry(3).digest),
                    probe(EntryType::Manifest, entry(4).digest),
                    probe(EntryType::Advisory, entry(4).digest),
                    probe(EntryType::Manifest, entry(6).digest),
                ],
            }),
        ),
    );
    let eight = snapshot(log(8), &[0, 2]);
    let pairs = [
        ("five", &five, "eight", &eight),
        ("eight", &eight, "five", &five),
        ("five", &five, "five", &five),
    ];
    assert_vector(
        "rtl1_consistency_001.json",
        &vector(
            "rtl1_consistency_001",
            &format!(
                "{LAYOUT}. {TEST_LOG}. Prefix consistency both ways (RAVEN_TRANSPARENCY_LOG_V1 \
                 §6): the snapshots of the first 5 entries (rtl1_snapshot_5_001) and of the \
                 first 8 (head signed by keys 0 and 2). A longer log that starts with the \
                 stored one EXTENDS it (store it), a shorter prefix is OLDER (keep the stored \
                 one), equal entries are SAME"
            ),
            json!({
                "key_set": key_set_json(&CURRENT),
                "five": snapshot_inputs(&five),
                "eight": snapshot_inputs(&eight),
            }),
            json!({
                "five": snapshot_expected(&five),
                "eight": snapshot_expected(&eight),
                "pairs": pairs.iter().map(|(sn, s, nn, n)| json!({
                    "stored": sn,
                    "new": nn,
                    "consistency": consistency(s.entries(), n.entries()).name(),
                })).collect::<Vec<_>>(),
            }),
        ),
    );

    // Negatives: a split view, a bad root, every check and decode rule.
    let mut other = log(4);
    other.extend([alt_entry_4(), entry(5)]);
    let split = snapshot(other, &[1, 2]);
    assert_vector(
        "negative/rtl1_split_view_pair_001.json",
        &vector(
            "rtl1_split_view_pair_001",
            &format!(
                "{LAYOUT}. {TEST_LOG}. Two snapshots that both check under the test key set: \
                 a, the first 5 entries (rtl1_snapshot_5_001); b, 6 entries whose entry 4 is \
                 another manifest (digest with the tag \"other manifest\") and whose entry 5 \
                 is the test log's. Neither list is a prefix of the other: SPLIT either way, \
                 the signers showed two histories (SEC_LOG_SPLIT_VIEW: both tree heads kept as \
                 evidence, installs and new advisories frozen)"
            ),
            json!({
                "key_set": key_set_json(&CURRENT),
                "a": snapshot_inputs(&five),
                "b": snapshot_inputs(&split),
            }),
            json!({
                "a": snapshot_expected(&five),
                "b": snapshot_expected(&split),
                "first_difference": 4,
                "consistency_a_then_b": consistency(five.entries(), split.entries()).name(),
                "consistency_b_then_a": consistency(split.entries(), five.entries()).name(),
            }),
        ),
    );
    let (_, bad, want) = check_cases().pop().unwrap();
    assert_eq!(want, LogCheckError::BadRoot);
    assert_vector(
        "negative/rtl1_bad_root_001.json",
        &vector(
            "rtl1_bad_root_001",
            &format!(
                "{LAYOUT}. {TEST_LOG}. The tree head of rtl1_sth_001 (validly signed over the \
                 first 5 entries) with entry 4 replaced by another manifest (digest with the \
                 tag \"other manifest\"): the snapshot decodes and its head verifies, but the \
                 entries hash to another root. BAD_ROOT, refused"
            ),
            json!({
                "key_set": key_set_json(&CURRENT),
                "snapshot_hex": hex::encode(bad.encode()),
            }),
            json!({
                "decode": "OK",
                "sth_verify": bad.sth().verify(&key_set()).err().map_or("OK", SigError::code),
                "sth_root_hex": hex::encode(bad.sth().root_hash),
                "computed_root_hex": hex::encode(mth(bad.entries())),
                "check": bad.check(&key_set()).err().map_or("OK", LogCheckError::code),
            }),
        ),
    );
    let mut rules = vector(
        "rtl1_check_rules_001",
        "Every refusal of RAVEN_TRANSPARENCY_LOG_V1 §6 for snapshots that decode: the 5 \
         entries of rtl1_snapshot_5_001 with a tree head that names another key set (seeds \
         0x44, 0x55, 0x66 x 32, signed by its keys 0 and 1), lists key indexes out of order, \
         names key index 3, carries one signature, is signed over the advisory domain \
         \"rvn1/advisory/v1\\0\" instead of \"rvn1/tlog/sth/v1\\0\", or has one bad signature \
         among good ones; and the head of rtl1_sth_001 over a substituted manifest (BAD_ROOT). \
         Checked under the test key set, signatures before the root",
        json!({
            "key_set": key_set_json(&CURRENT),
            "cases": check_cases().iter().map(|(name, s, _)| json!({ "name": name, "snapshot_hex": hex::encode(s.encode()) })).collect::<Vec<_>>(),
        }),
        json!({
            "errors": check_cases().iter().map(|(name, s, e)| {
                assert_eq!(s.check(&key_set()).err(), Some(*e));
                json!({ "name": name, "error": e.code() })
            }).collect::<Vec<_>>(),
        }),
    );
    rules["inputs"]["other_key_set"] = key_set_json(&OTHER);
    assert_vector("negative/rtl1_check_rules_001.json", &rules);
    assert_vector(
        "negative/rtl1_decode_rules_001.json",
        &vector(
            "rtl1_decode_rules_001",
            "Every structural refusal of RAVEN_TRANSPARENCY_LOG_V1 §4 (tree heads) and §5 \
             (snapshots), each case breaking one rule (the first it meets; a tree head's \
             signature block, where present, is a valid 2-of-3 block of the test keys over the \
             case's bytes). object names the decoder. snapshot_too_long: hex followed by zero \
             bytes up to zero_pad_to bytes",
            json!({
                "cases": decode_cases().iter().map(|(name, object, bytes, _)| {
                    if *name == "snapshot_too_long" {
                        let base = RawSnap::new().bytes();
                        assert_eq!(&bytes[..base.len()], &base[..]);
                        json!({ "name": name, "object": object.name(), "hex": hex::encode(&base), "zero_pad_to": bytes.len() })
                    } else {
                        json!({ "name": name, "object": object.name(), "hex": hex::encode(bytes) })
                    }
                }).collect::<Vec<_>>(),
            }),
            json!({
                "errors": decode_cases().iter().map(|(name, _, _, e)| json!({ "name": name, "error": e.code() })).collect::<Vec<_>>(),
            }),
        ),
    );
}

/// The committed `rtl1_*` files are exactly the ones [`update_vectors_rtl1`]
/// writes.
#[test]
fn rtl1_vector_files() {
    if std::env::var(REGEN).as_deref() == Ok("1") {
        return; // being written right now
    }
    let names = |dir: &str| {
        let mut names: Vec<String> = std::fs::read_dir(rvn1_dir().join(dir))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with("rtl1_") && n.ends_with(".json"))
            .collect();
        names.sort();
        names
    };
    assert_eq!(
        names("update"),
        [
            "rtl1_consistency_001.json",
            "rtl1_mth_001.json",
            "rtl1_snapshot_5_001.json",
            "rtl1_sth_001.json",
        ]
    );
    assert_eq!(
        names("update/negative"),
        [
            "rtl1_bad_root_001.json",
            "rtl1_check_rules_001.json",
            "rtl1_decode_rules_001.json",
            "rtl1_split_view_pair_001.json",
        ]
    );
}
