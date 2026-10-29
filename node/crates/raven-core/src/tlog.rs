//! RAVEN Transparency Log V1 (RTL1, `protocol/RAVEN_TRANSPARENCY_LOG_V1.md`;
//! `docs/roadmap/plans/phase6-design.json` step P6.42, design D §3 and wire
//! spec W-D2; owner decision OD6b-22): the public, append-only list of every
//! release artifact (manifests, advisories, key sets) the Raven project
//! signs, so a build made for one group only cannot stay hidden.
//!
//! ```text
//! entry    = type u8 (1 manifest, 2 advisory, 3 key set) || digest[32]
//!         || logged_at_ms u64                                   (41 bytes)
//! leaf     = SHA-256(0x00 || entry)          (RFC 6962 §2.1)
//! node     = SHA-256(0x01 || left || right)  (split at the largest power
//!                                             of two below the size)
//! STH      = "RTL1" || 0x01 || kind 0x01 || reserved u16 0 || tree_size u64
//!         || root_hash[32] || timestamp_ms u64 || key_set_digest[32]
//!         || signature block over "rvn1/tlog/sth/v1\0" || bytes[0..88]
//! snapshot = "RTL1" || 0x01 || kind 0x02 || reserved u16 0
//!         || entry_count u32 (= tree_size, 1..=1,400) || entries
//!         || sth_len u16 || STH
//! ```
//!
//! Version 1 carries whole snapshots instead of audit proofs: an artifact
//! travels with every entry of the log and the signed tree head (STH). The
//! verifier recomputes the root ([`Snapshot::check`]), checks that the
//! entries it stored and the new ones are prefixes of each other
//! ([`consistency`]; either direction) and keeps the longer list. Two
//! validly signed lists that are not prefixes of each other are a split
//! view (`SEC_LOG_SPLIT_VIEW`): the signers showed two histories.
//!
//! Pure: no I/O, no clock. Storing the log and acting on a split view is
//! P6.44's update state, behind the advisory and release bundle gates
//! (`ADVISORY_PRODUCTION_ENABLED`, `RELEASE_BUNDLE_PRODUCTION_ENABLED`, both
//! `false`).

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::identity::Identity;
use crate::release_keys::{KeySet, SigBlock, SigError, KEYSET_MAX_KEYS, SIG_ENTRY_LEN};

/// The magic of tree heads and snapshots.
pub const RTL1_MAGIC: &[u8; 4] = b"RTL1";
/// The version byte this revision writes and reads.
pub const RTL1_VERSION: u8 = 0x01;
/// The kind byte of a signed tree head.
pub const KIND_STH: u8 = 0x01;
/// The kind byte of a snapshot.
pub const KIND_SNAPSHOT: u8 = 0x02;
/// One log entry: type, digest and time.
pub const ENTRY_LEN: usize = 41;
/// The signed part of a tree head.
pub const STH_SIGNED_LEN: usize = 88;
/// The longest tree head: a block of 8 signatures (no key set has more
/// keys, and key indexes never repeat).
pub const MAX_STH_LEN: usize = STH_SIGNED_LEN + 1 + SIG_ENTRY_LEN * KEYSET_MAX_KEYS;
/// Magic, version, kind, reserved and the entry count.
pub const SNAPSHOT_HEADER_LEN: usize = 12;
/// The most entries a snapshot (and so a version 1 log) holds; a version 2
/// with audit proofs comes before the log reaches it.
pub const MAX_LOG_ENTRIES: usize = 1_400;
/// The longest snapshot: 1,400 entries and the longest tree head (58,023
/// bytes).
pub const MAX_SNAPSHOT_LEN: usize =
    SNAPSHOT_HEADER_LEN + ENTRY_LEN * MAX_LOG_ENTRIES + 2 + MAX_STH_LEN;
/// Domain of [`Sth::signing_input`].
pub const STH_SIGNING_DOMAIN: &[u8] = b"rvn1/tlog/sth/v1\0";
/// RFC 6962 leaf hash prefix.
pub const LEAF_PREFIX: u8 = 0x00;
/// RFC 6962 interior node hash prefix.
pub const NODE_PREFIX: u8 = 0x01;

/// What a log entry names (spec §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntryType {
    /// `1`: a release manifest (RRB1), by its manifest digest.
    Manifest,
    /// `2`: a security advisory (RAD1), by its advisory digest.
    Advisory,
    /// `3`: a release key set, by its key set digest.
    KeySet,
    /// A type this version does not know (`4..=255`): kept and hashed like
    /// any entry, never matched.
    Other(u8),
}

impl EntryType {
    /// The type of a type byte; `None` for the reserved `0`.
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => return None,
            1 => Self::Manifest,
            2 => Self::Advisory,
            3 => Self::KeySet,
            other => Self::Other(other),
        })
    }

    /// The type byte.
    pub fn byte(self) -> u8 {
        match self {
            Self::Manifest => 1,
            Self::Advisory => 2,
            Self::KeySet => 3,
            Self::Other(b) => b,
        }
    }

    /// The name the spec and the vectors use.
    pub fn name(self) -> &'static str {
        match self {
            Self::Manifest => "MANIFEST",
            Self::Advisory => "ADVISORY",
            Self::KeySet => "KEY_SET",
            Self::Other(_) => "UNKNOWN",
        }
    }
}

/// One entry of the log (spec §2): a leaf of the tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LogEntry {
    pub kind: EntryType,
    /// The artifact's own digest (manifest, advisory or key set digest).
    pub digest: [u8; 32],
    /// When the signers logged it (Unix ms; shown, never enforced).
    pub logged_at_ms: u64,
}

impl LogEntry {
    /// The 41 entry bytes: the leaf input.
    pub fn encode(&self) -> [u8; ENTRY_LEN] {
        let mut out = [0; ENTRY_LEN];
        out[0] = self.kind.byte();
        out[1..33].copy_from_slice(&self.digest);
        out[33..].copy_from_slice(&self.logged_at_ms.to_be_bytes());
        out
    }

    /// Exactly one entry.
    pub fn decode(bytes: &[u8]) -> Result<Self, Rtl1Error> {
        let b: &[u8; ENTRY_LEN] = bytes.try_into().map_err(|_| Rtl1Error::Truncated)?;
        Ok(Self {
            kind: EntryType::from_byte(b[0]).ok_or(Rtl1Error::BadEntryType)?,
            digest: b[1..33].try_into().expect("32 bytes"),
            logged_at_ms: u64::from_be_bytes(b[33..].try_into().expect("8 bytes")),
        })
    }

    /// `SHA-256(0x00 || entry)`.
    pub fn leaf_hash(&self) -> [u8; 32] {
        leaf_hash(&self.encode())
    }
}

/// RFC 6962 §2.1 leaf hash: `SHA-256(0x00 || leaf)`.
pub fn leaf_hash(leaf: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(leaf);
    h.finalize().into()
}

/// RFC 6962 §2.1 interior node hash: `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The RFC 6962 Merkle tree hash over leaves already hashed with
/// [`leaf_hash`]: one leaf is its own hash; `n > 1` leaves split at the
/// largest power of two `k < n` into `node(MTH(first k), MTH(rest))`; no
/// leaves hash to `SHA-256("")`. Release bundles (RRB1) use it for their
/// chunk root too.
pub fn root_of_leaf_hashes(hashes: &[[u8; 32]]) -> [u8; 32] {
    match hashes {
        [] => Sha256::digest([]).into(),
        [one] => *one,
        _ => {
            let k = 1 << (hashes.len() - 1).ilog2();
            node_hash(
                &root_of_leaf_hashes(&hashes[..k]),
                &root_of_leaf_hashes(&hashes[k..]),
            )
        }
    }
}

/// The Merkle tree hash of a log (RFC 6962 §2.1 over the 41-byte entries).
pub fn mth(entries: &[LogEntry]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = entries.iter().map(LogEntry::leaf_hash).collect();
    root_of_leaf_hashes(&leaves)
}

/// Is an entry of this type and digest in the log?
pub fn contains(entries: &[LogEntry], kind: EntryType, digest: &[u8; 32]) -> bool {
    entries
        .iter()
        .any(|e| e.kind == kind && e.digest == *digest)
}

/// How a new log relates to the stored one (spec §6). Only meaningful when
/// both came in snapshots that passed [`Snapshot::check`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consistency {
    /// The stored log is a prefix of the new, longer one: store the new one.
    Extends,
    /// The same entries.
    Same,
    /// The new log is a prefix of the stored, longer one: keep the stored
    /// one (the sender is behind; it can be offered the stored one).
    Older,
    /// Neither is a prefix of the other: the signers showed two histories
    /// (`SEC_LOG_SPLIT_VIEW`: both tree heads kept as evidence, installs and
    /// new advisories frozen).
    Split,
}

impl Consistency {
    /// The name the spec and the vectors use.
    pub fn name(self) -> &'static str {
        match self {
            Self::Extends => "EXTENDS",
            Self::Same => "SAME",
            Self::Older => "OLDER",
            Self::Split => "SPLIT",
        }
    }
}

/// How the `new` log relates to the `stored` one: prefix consistency in
/// either direction (spec §6). Nothing stored yet (an empty list) is a
/// prefix of every log.
pub fn consistency(stored: &[LogEntry], new: &[LogEntry]) -> Consistency {
    let common = stored.len().min(new.len());
    if stored[..common] != new[..common] {
        return Consistency::Split;
    }
    match new.len().cmp(&stored.len()) {
        std::cmp::Ordering::Greater => Consistency::Extends,
        std::cmp::Ordering::Equal => Consistency::Same,
        std::cmp::Ordering::Less => Consistency::Older,
    }
}

/// Why tree head or snapshot bytes are refused (spec §4, §5), in the order
/// they are checked. Each refusal makes the whole object invalid.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum Rtl1Error {
    /// More than [`MAX_STH_LEN`] (tree head) or [`MAX_SNAPSHOT_LEN`]
    /// (snapshot) bytes.
    #[error("RTL1 TOO_LONG")]
    TooLong,
    /// A field runs past the end.
    #[error("RTL1 TRUNCATED")]
    Truncated,
    /// The bytes do not start with `RTL1`.
    #[error("RTL1 BAD_MAGIC")]
    BadMagic,
    /// The version byte is not [`RTL1_VERSION`].
    #[error("RTL1 BAD_VERSION")]
    BadVersion,
    /// The kind byte is not the expected one ([`KIND_STH`] or
    /// [`KIND_SNAPSHOT`]).
    #[error("RTL1 BAD_KIND")]
    BadKind,
    /// The reserved field is not 0.
    #[error("RTL1 BAD_RESERVED")]
    BadReserved,
    /// A tree head's `tree_size` or a snapshot's `entry_count` is 0.
    #[error("RTL1 BAD_TREE_SIZE")]
    BadTreeSize,
    /// A snapshot's `entry_count` is above [`MAX_LOG_ENTRIES`].
    #[error("RTL1 TOO_MANY_ENTRIES")]
    TooManyEntries,
    /// An entry's type is the reserved `0`.
    #[error("RTL1 BAD_ENTRY_TYPE")]
    BadEntryType,
    /// A tree head does not end in exactly one signature block.
    #[error("RTL1 BAD_SIG_BLOCK")]
    BadSigBlock,
    /// Bytes follow a snapshot's tree head.
    #[error("RTL1 TRAILING_BYTES")]
    TrailingBytes,
    /// A snapshot's `entry_count` is not its tree head's `tree_size`.
    #[error("RTL1 SIZE_MISMATCH")]
    SizeMismatch,
}

impl Rtl1Error {
    /// The name the spec and the vectors use.
    pub fn code(self) -> &'static str {
        match self {
            Self::TooLong => "TOO_LONG",
            Self::Truncated => "TRUNCATED",
            Self::BadMagic => "BAD_MAGIC",
            Self::BadVersion => "BAD_VERSION",
            Self::BadKind => "BAD_KIND",
            Self::BadReserved => "BAD_RESERVED",
            Self::BadTreeSize => "BAD_TREE_SIZE",
            Self::TooManyEntries => "TOO_MANY_ENTRIES",
            Self::BadEntryType => "BAD_ENTRY_TYPE",
            Self::BadSigBlock => "BAD_SIG_BLOCK",
            Self::TrailingBytes => "TRAILING_BYTES",
            Self::SizeMismatch => "SIZE_MISMATCH",
        }
    }
}

/// Why a decoded snapshot is refused by [`Snapshot::check`] (spec §6), in
/// the order checked. Either way the snapshot is forged.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum LogCheckError {
    /// The tree head is not signed by the key set (release key sets §2.3).
    #[error("RTL1 STH {0}")]
    Sig(SigError),
    /// The entries do not hash to the tree head's root.
    #[error("RTL1 BAD_ROOT")]
    BadRoot,
}

impl LogCheckError {
    /// The name the spec and the vectors use.
    pub fn code(self) -> &'static str {
        match self {
            Self::Sig(e) => e.code(),
            Self::BadRoot => "BAD_ROOT",
        }
    }
}

/// Reads fields in order; a field past the end is [`Rtl1Error::Truncated`].
struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Rtl1Error> {
        let end = self.at.checked_add(n).ok_or(Rtl1Error::Truncated)?;
        let out = self.buf.get(self.at..end).ok_or(Rtl1Error::Truncated)?;
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, Rtl1Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Rtl1Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }

    fn u32(&mut self) -> Result<u32, Rtl1Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, Rtl1Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    fn digest(&mut self) -> Result<[u8; 32], Rtl1Error> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }

    /// Magic, version, the expected kind and the reserved field.
    fn header(&mut self, kind: u8) -> Result<(), Rtl1Error> {
        if self.take(4)? != RTL1_MAGIC {
            return Err(Rtl1Error::BadMagic);
        }
        if self.u8()? != RTL1_VERSION {
            return Err(Rtl1Error::BadVersion);
        }
        if self.u8()? != kind {
            return Err(Rtl1Error::BadKind);
        }
        if self.u16()? != 0 {
            return Err(Rtl1Error::BadReserved);
        }
        Ok(())
    }
}

/// A decoded signed tree head (spec §4): every structural rule holds.
/// Whether it is signed by a key set is [`Sth::verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sth {
    /// How many entries the log has, >= 1.
    pub tree_size: u64,
    /// The RFC 6962 root of those entries ([`mth`]).
    pub root_hash: [u8; 32],
    /// When the signers signed it (Unix ms; shown, never enforced).
    pub timestamp_ms: u64,
    /// The key set that signs it ([`KeySet::digest`]).
    pub key_set_digest: [u8; 32],
    sigs: SigBlock,
    bytes: Vec<u8>,
}

impl Sth {
    /// Strict decode in the order of spec §4: size, header, tree size, the
    /// fixed fields, the signature block to the end.
    pub fn decode(bytes: &[u8]) -> Result<Self, Rtl1Error> {
        if bytes.len() > MAX_STH_LEN {
            return Err(Rtl1Error::TooLong);
        }
        let mut r = Reader { buf: bytes, at: 0 };
        r.header(KIND_STH)?;
        let tree_size = r.u64()?;
        if tree_size == 0 {
            return Err(Rtl1Error::BadTreeSize);
        }
        let root_hash = r.digest()?;
        let timestamp_ms = r.u64()?;
        let key_set_digest = r.digest()?;
        let sigs =
            SigBlock::decode(&bytes[STH_SIGNED_LEN..]).map_err(|_| Rtl1Error::BadSigBlock)?;
        Ok(Self {
            tree_size,
            root_hash,
            timestamp_ms,
            key_set_digest,
            sigs,
            bytes: bytes.to_vec(),
        })
    }

    /// The tree head's bytes, as received.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The signature block.
    pub fn sigs(&self) -> &SigBlock {
        &self.sigs
    }

    /// What the release keys sign: `"rvn1/tlog/sth/v1\0"` and the first 88
    /// bytes.
    pub fn signing_input(&self) -> Vec<u8> {
        [STH_SIGNING_DOMAIN, &self.bytes[..STH_SIGNED_LEN]].concat()
    }

    /// Signed by `key_set`: it names that key set, and its signature block
    /// passes [`KeySet::verify_sigs`].
    pub fn verify(&self, key_set: &KeySet) -> Result<(), SigError> {
        if self.key_set_digest != key_set.digest() {
            return Err(SigError::WrongKeySet);
        }
        key_set.verify_sigs(&self.signing_input(), &self.sigs)
    }

    /// The same content, unsigned.
    pub fn draft(&self) -> SthDraft {
        SthDraft {
            tree_size: self.tree_size,
            root_hash: self.root_hash,
            timestamp_ms: self.timestamp_ms,
            key_set_digest: self.key_set_digest,
        }
    }
}

/// A tree head before its signatures: what the release tool (P6.46) and
/// the tests build and sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SthDraft {
    pub tree_size: u64,
    pub root_hash: [u8; 32],
    pub timestamp_ms: u64,
    pub key_set_digest: [u8; 32],
}

impl SthDraft {
    /// The tree head of `entries` (its size and [`mth`]).
    pub fn of_entries(entries: &[LogEntry], timestamp_ms: u64, key_set_digest: [u8; 32]) -> Self {
        Self {
            tree_size: entries.len() as u64,
            root_hash: mth(entries),
            timestamp_ms,
            key_set_digest,
        }
    }

    /// The 88 signed bytes; a tree size of 0 is refused like
    /// [`Sth::decode`] refuses it.
    pub fn body(&self) -> Result<[u8; STH_SIGNED_LEN], Rtl1Error> {
        if self.tree_size == 0 {
            return Err(Rtl1Error::BadTreeSize);
        }
        let mut out = [0; STH_SIGNED_LEN];
        out[..4].copy_from_slice(RTL1_MAGIC);
        out[4] = RTL1_VERSION;
        out[5] = KIND_STH;
        out[8..16].copy_from_slice(&self.tree_size.to_be_bytes());
        out[16..48].copy_from_slice(&self.root_hash);
        out[48..56].copy_from_slice(&self.timestamp_ms.to_be_bytes());
        out[56..88].copy_from_slice(&self.key_set_digest);
        Ok(out)
    }

    /// What the release keys sign.
    pub fn signing_input(&self) -> Result<Vec<u8>, Rtl1Error> {
        Ok([STH_SIGNING_DOMAIN, &self.body()?[..]].concat())
    }

    /// The tree head with this signature block.
    pub fn assemble(&self, sigs: &SigBlock) -> Result<Sth, Rtl1Error> {
        Sth::decode(&[&self.body()?[..], &sigs.encode()].concat())
    }

    /// The tree head signed by each `(key_index, key)` in order.
    pub fn sign(&self, signers: &[(u8, &Identity)]) -> Result<Sth, Rtl1Error> {
        self.assemble(&SigBlock::sign(&self.signing_input()?, signers))
    }
}

/// A decoded snapshot (spec §5): the whole log and its tree head, every
/// structural rule holds. Whether the head is signed and the entries hash
/// to its root is [`Snapshot::check`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    entries: Vec<LogEntry>,
    sth: Sth,
}

impl Snapshot {
    /// Strict decode in the order of spec §5: size, header, entry count,
    /// each entry, the tree head's length and bytes, nothing after them,
    /// the tree head (§4), its size against the entry count.
    pub fn decode(bytes: &[u8]) -> Result<Self, Rtl1Error> {
        if bytes.len() > MAX_SNAPSHOT_LEN {
            return Err(Rtl1Error::TooLong);
        }
        let mut r = Reader { buf: bytes, at: 0 };
        r.header(KIND_SNAPSHOT)?;
        let count = r.u32()?;
        if count == 0 {
            return Err(Rtl1Error::BadTreeSize);
        }
        let count = usize::try_from(count).map_err(|_| Rtl1Error::TooManyEntries)?;
        if count > MAX_LOG_ENTRIES {
            return Err(Rtl1Error::TooManyEntries);
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(LogEntry::decode(r.take(ENTRY_LEN)?)?);
        }
        let sth_len = usize::from(r.u16()?);
        let sth = r.take(sth_len)?;
        if r.at != bytes.len() {
            return Err(Rtl1Error::TrailingBytes);
        }
        let sth = Sth::decode(sth)?;
        if sth.tree_size != count as u64 {
            return Err(Rtl1Error::SizeMismatch);
        }
        Ok(Self { entries, sth })
    }

    /// A snapshot of these entries and this tree head, checked by the rules
    /// of [`Snapshot::decode`] (it is encoded and decoded again).
    pub fn new(entries: Vec<LogEntry>, sth: Sth) -> Result<Self, Rtl1Error> {
        if entries.is_empty() {
            return Err(Rtl1Error::BadTreeSize);
        }
        if entries.len() > MAX_LOG_ENTRIES {
            return Err(Rtl1Error::TooManyEntries);
        }
        Self::decode(&Self { entries, sth }.encode())
    }

    /// The canonical bytes (a decoded snapshot re-encodes byte for byte).
    pub fn encode(&self) -> Vec<u8> {
        let sth = self.sth.bytes();
        let mut out = Vec::with_capacity(
            SNAPSHOT_HEADER_LEN + ENTRY_LEN * self.entries.len() + 2 + sth.len(),
        );
        out.extend_from_slice(RTL1_MAGIC);
        out.extend([RTL1_VERSION, KIND_SNAPSHOT, 0, 0]);
        out.extend(
            u32::try_from(self.entries.len())
                .expect("a snapshot holds at most 1,400 entries")
                .to_be_bytes(),
        );
        for e in &self.entries {
            out.extend(e.encode());
        }
        out.extend(
            u16::try_from(sth.len())
                .expect("a tree head is at most 609 bytes")
                .to_be_bytes(),
        );
        out.extend_from_slice(sth);
        out
    }

    /// The log's entries, oldest first.
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// The signed tree head.
    pub fn sth(&self) -> &Sth {
        &self.sth
    }

    /// Check the snapshot against `key_set` (spec §6): the tree head is
    /// signed by it, then the entries hash to the head's root.
    pub fn check(&self, key_set: &KeySet) -> Result<Checked, LogCheckError> {
        self.sth.verify(key_set).map_err(LogCheckError::Sig)?;
        if mth(&self.entries) != self.sth.root_hash {
            return Err(LogCheckError::BadRoot);
        }
        Ok(Checked(self.clone()))
    }
}

/// A snapshot that passed [`Snapshot::check`]: its entries are the log the
/// key set signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checked(Snapshot);

impl Checked {
    /// The log's entries, oldest first.
    pub fn entries(&self) -> &[LogEntry] {
        &self.0.entries
    }

    /// The signed tree head (kept as evidence on a split view).
    pub fn sth(&self) -> &Sth {
        &self.0.sth
    }

    /// The checked snapshot.
    pub fn snapshot(&self) -> &Snapshot {
        &self.0
    }

    /// Is an entry of this type and digest in the log?
    pub fn contains(&self, kind: EntryType, digest: &[u8; 32]) -> bool {
        contains(self.entries(), kind, digest)
    }

    /// How this log relates to the `stored` one ([`consistency`]).
    pub fn consistency(&self, stored: &[LogEntry]) -> Consistency {
        consistency(stored, self.entries())
    }
}

#[cfg(test)]
mod tests;
