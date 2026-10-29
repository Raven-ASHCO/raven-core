//! RAVEN Security Advisory V1 (RAD1, `protocol/RAVEN_SECURITY_ADVISORY_V1.md`;
//! `docs/roadmap/plans/phase6-design.json` step P6.41, design D §2 and wire
//! spec W-D1; owner decision OD6b-21): the numbered, cumulative list of
//! security notices the Raven project signs with 2 of its 3 offline release
//! keys.
//!
//! ```text
//! RAD1 = "RAD1" || 0x01 || flags 0x00 || entry_count u16 (0..=64)
//!     || serial u64 (>= 1) || issued_at_ms u64 || key_set_digest[32]
//!     || prev_digest[32] (all zero exactly when serial = 1)
//!     || entries || signature block
//! entry = kind u8 || severity u8 || target_len u8 (1..=64) || target
//!      || arg_len u16 (0..=1024) || arg || text_id u16
//! signing input = "rvn1/advisory/v1\0" || bytes before the signature block
//! advisory_digest = SHA-256("rvn1/advisory/digest/v1\0" || all bytes)
//! ```
//!
//! An entry marks a registered suite or protocol version (`SUITE_STATUS`,
//! [`crate::suite_registry`]) or a gated feature (`FEATURE_HOLD`, close-only)
//! INFO, DEPRECATED or BROKEN, names the oldest safe build
//! (`RELEASE_FLOOR`, a warning), carries a short text (`NOTICE`) or the next
//! key set (`KEY_SET`). Kinds this version does not know keep the advisory
//! valid and are never enforced. An advisory can never open a gate, change
//! a contact, a key pin, a block list, a route or a message, run or fetch
//! anything, or name a person (design D §2).
//!
//! Pure: [`Advisory::decode`] checks the structure in the order of spec §5,
//! [`Advisory::verify`] the signatures against a [`KeySet`], and
//! [`succession`] how an advisory relates to the stored one (rollback,
//! equivocation). Storing and applying them is P6.44 and P6.45, behind
//! [`SecGate::Advisory`](crate::security_gate::SecGate::Advisory)
//! (`ADVISORY_PRODUCTION_ENABLED = false`).

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::identity::Identity;
use crate::release_keys::{KeySet, SigBlock, SigError};

/// The magic.
pub const RAD1_MAGIC: &[u8; 4] = b"RAD1";
/// The version byte this revision writes and reads.
pub const RAD1_VERSION: u8 = 0x01;
/// Magic, version, flags, entry count, serial, issue time and both digests.
pub const RAD1_HEADER_LEN: usize = 88;
/// The longest advisory, signature block included.
pub const MAX_RAD1_LEN: usize = 32_768;
/// The most entries an advisory holds.
pub const MAX_ENTRIES: usize = 64;
/// The longest entry target.
pub const MAX_TARGET_LEN: usize = 64;
/// The longest entry argument.
pub const MAX_ARG_LEN: usize = 1_024;
/// Domain of [`Advisory::signing_input`].
pub const SIGNING_DOMAIN: &[u8] = b"rvn1/advisory/v1\0";
/// Domain of [`Advisory::digest`].
pub const DIGEST_DOMAIN: &[u8] = b"rvn1/advisory/digest/v1\0";
/// The target of every `RELEASE_FLOOR` entry.
pub const RELEASE_FLOOR_TARGET: &str = "raven";
/// The target of every `NOTICE` entry.
pub const NOTICE_TARGET: &str = "notice";
/// The target of every `KEY_SET` entry.
pub const KEY_SET_TARGET: &str = "keys";
/// What every `FEATURE_HOLD` target starts with (`feature/<gate>`).
pub const FEATURE_PREFIX: &str = "feature/";

/// What an entry says (spec §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// `0x01`: a registered suite or protocol version is INFO, DEPRECATED
    /// or BROKEN.
    SuiteStatus,
    /// `0x02`: builds below this serial have a known security problem
    /// (a warning; Raven keeps working).
    ReleaseFloor,
    /// `0x03`: a gated feature is held (BROKEN closes it, DEPRECATED warns;
    /// never opens anything).
    FeatureHold,
    /// `0x04`: a short text, shown sanitized.
    Notice,
    /// `0x05`: the next release key set.
    KeySet,
    /// A kind this version does not know (`0x06..=0xFF`): shown as a notice
    /// this version does not understand, never enforced.
    Other(u8),
}

impl EntryKind {
    /// The kind of a kind byte; `None` for the reserved `0x00`.
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0x00 => return None,
            0x01 => Self::SuiteStatus,
            0x02 => Self::ReleaseFloor,
            0x03 => Self::FeatureHold,
            0x04 => Self::Notice,
            0x05 => Self::KeySet,
            other => Self::Other(other),
        })
    }

    /// The kind byte.
    pub fn byte(self) -> u8 {
        match self {
            Self::SuiteStatus => 0x01,
            Self::ReleaseFloor => 0x02,
            Self::FeatureHold => 0x03,
            Self::Notice => 0x04,
            Self::KeySet => 0x05,
            Self::Other(b) => b,
        }
    }

    /// Does this version know what the kind means?
    pub fn understood(self) -> bool {
        !matches!(self, Self::Other(_))
    }

    /// The name the spec and the vectors use.
    pub fn name(self) -> &'static str {
        match self {
            Self::SuiteStatus => "SUITE_STATUS",
            Self::ReleaseFloor => "RELEASE_FLOOR",
            Self::FeatureHold => "FEATURE_HOLD",
            Self::Notice => "NOTICE",
            Self::KeySet => "KEY_SET",
            Self::Other(_) => "UNKNOWN",
        }
    }
}

/// How serious an entry is (spec §3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// `0`: for information.
    Info,
    /// `1`: being retired; warn.
    Deprecated,
    /// `2`: refuse (`SUITE_STATUS`) or close (`FEATURE_HOLD`); no other
    /// known kind may carry it.
    Broken,
}

impl Severity {
    /// The severity of a byte; `None` above 2.
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Info,
            1 => Self::Deprecated,
            2 => Self::Broken,
            _ => return None,
        })
    }

    /// The severity byte.
    pub fn byte(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Deprecated => 1,
            Self::Broken => 2,
        }
    }

    /// The name the spec and the vectors use.
    pub fn name(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Deprecated => "DEPRECATED",
            Self::Broken => "BROKEN",
        }
    }
}

/// One entry of an advisory (spec §3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub kind: EntryKind,
    pub severity: Severity,
    /// 1..=64 bytes of `[a-z0-9._/-]`, `/`-separated, no empty segment.
    pub target: String,
    /// 0..=1024 bytes; its meaning depends on the kind.
    pub arg: Vec<u8>,
    /// The build's text for this entry (0: none; a text id this build does
    /// not have shows its kind's generic text).
    pub text_id: u16,
}

impl Entry {
    /// The minimum safe build serial of a `RELEASE_FLOOR` entry.
    pub fn release_floor(&self) -> Option<u64> {
        match (self.kind, <[u8; 8]>::try_from(self.arg.as_slice())) {
            (EntryKind::ReleaseFloor, Ok(b)) => Some(u64::from_be_bytes(b)),
            _ => None,
        }
    }

    /// The text of a `NOTICE` entry, as signed (sanitize before showing).
    pub fn notice_text(&self) -> Option<&str> {
        match self.kind {
            EntryKind::Notice => std::str::from_utf8(&self.arg).ok(),
            _ => None,
        }
    }

    /// The next key set of a `KEY_SET` entry.
    pub fn key_set(&self) -> Option<KeySet> {
        match self.kind {
            EntryKind::KeySet => KeySet::decode(&self.arg).ok(),
            _ => None,
        }
    }
}

/// Why advisory bytes are refused (spec §5). Each refusal makes the whole
/// advisory invalid.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum Rad1Error {
    /// More than [`MAX_RAD1_LEN`] bytes.
    #[error("RAD1 TOO_LONG")]
    TooLong,
    /// A field runs past the end.
    #[error("RAD1 TRUNCATED")]
    Truncated,
    /// The bytes do not start with `RAD1`.
    #[error("RAD1 BAD_MAGIC")]
    BadMagic,
    /// The version byte is not [`RAD1_VERSION`].
    #[error("RAD1 BAD_VERSION")]
    BadVersion,
    /// The flags byte is not 0.
    #[error("RAD1 BAD_FLAGS")]
    BadFlags,
    /// More than [`MAX_ENTRIES`] entries.
    #[error("RAD1 TOO_MANY_ENTRIES")]
    TooManyEntries,
    /// The serial is 0.
    #[error("RAD1 BAD_SERIAL")]
    BadSerial,
    /// `prev_digest` is all zero for a serial above 1, or not all zero for
    /// serial 1.
    #[error("RAD1 BAD_PREV")]
    BadPrev,
    /// An entry's kind is the reserved `0x00`.
    #[error("RAD1 BAD_KIND")]
    BadKind,
    /// An entry's severity is above 2, or BROKEN on a kind that may not
    /// carry it (`RELEASE_FLOOR`, `NOTICE`, `KEY_SET`).
    #[error("RAD1 BAD_SEVERITY")]
    BadSeverity,
    /// An entry's target is empty, longer than 64 bytes, has a byte
    /// outside `[a-z0-9._/-]` or an empty segment.
    #[error("RAD1 BAD_TARGET")]
    BadTarget,
    /// An entry's argument is longer than 1,024 bytes.
    #[error("RAD1 BAD_ARG")]
    BadArg,
    /// A known kind's target or argument breaks that kind's rule.
    #[error("RAD1 BAD_ENTRY")]
    BadEntry,
    /// Two entries have the same kind and target.
    #[error("RAD1 DUPLICATE_ENTRY")]
    DuplicateEntry,
    /// The signature block is not exactly `1 + 65 * sig_count` bytes to the
    /// end.
    #[error("RAD1 BAD_SIG_BLOCK")]
    BadSigBlock,
}

impl Rad1Error {
    /// The name the spec and the vectors use.
    pub fn code(self) -> &'static str {
        match self {
            Self::TooLong => "TOO_LONG",
            Self::Truncated => "TRUNCATED",
            Self::BadMagic => "BAD_MAGIC",
            Self::BadVersion => "BAD_VERSION",
            Self::BadFlags => "BAD_FLAGS",
            Self::TooManyEntries => "TOO_MANY_ENTRIES",
            Self::BadSerial => "BAD_SERIAL",
            Self::BadPrev => "BAD_PREV",
            Self::BadKind => "BAD_KIND",
            Self::BadSeverity => "BAD_SEVERITY",
            Self::BadTarget => "BAD_TARGET",
            Self::BadArg => "BAD_ARG",
            Self::BadEntry => "BAD_ENTRY",
            Self::DuplicateEntry => "DUPLICATE_ENTRY",
            Self::BadSigBlock => "BAD_SIG_BLOCK",
        }
    }
}

/// Is `target` 1..=64 bytes of `[a-z0-9._/-]` with no empty segment
/// (spec §3.2)? Every registry id is one.
pub fn target_well_formed(target: &str) -> bool {
    (1..=MAX_TARGET_LEN).contains(&target.len())
        && target
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'/' | b'-'))
        && target.split('/').all(|s| !s.is_empty())
}

/// A known kind's own rule for its target and argument (spec §3.2).
fn entry_fits(kind: EntryKind, target: &str, arg: &[u8]) -> bool {
    match kind {
        EntryKind::SuiteStatus => {
            target.contains('/') && !target.starts_with(FEATURE_PREFIX) && arg.is_empty()
        }
        EntryKind::ReleaseFloor => {
            target == RELEASE_FLOOR_TARGET
                && <[u8; 8]>::try_from(arg).is_ok_and(|b| u64::from_be_bytes(b) >= 1)
        }
        EntryKind::FeatureHold => {
            target
                .strip_prefix(FEATURE_PREFIX)
                .is_some_and(|gate| !gate.contains('/'))
                && arg.is_empty()
        }
        EntryKind::Notice => {
            target == NOTICE_TARGET && !arg.is_empty() && std::str::from_utf8(arg).is_ok()
        }
        EntryKind::KeySet => target == KEY_SET_TARGET && KeySet::decode(arg).is_ok(),
        EntryKind::Other(_) => true,
    }
}

/// Reads fields in order; a field past the end is [`Rad1Error::Truncated`].
struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Rad1Error> {
        let end = self.at.checked_add(n).ok_or(Rad1Error::Truncated)?;
        let out = self.buf.get(self.at..end).ok_or(Rad1Error::Truncated)?;
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, Rad1Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Rad1Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, Rad1Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    fn digest(&mut self) -> Result<[u8; 32], Rad1Error> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }
}

/// A decoded advisory: every structural rule holds. Whether it is signed
/// by a key set is [`Advisory::verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advisory {
    pub serial: u64,
    pub issued_at_ms: u64,
    /// The key set that signs it ([`KeySet::digest`]).
    pub key_set_digest: [u8; 32],
    /// The digest of advisory `serial - 1`; all zero for serial 1.
    pub prev_digest: [u8; 32],
    pub entries: Vec<Entry>,
    sigs: SigBlock,
    bytes: Vec<u8>,
    /// Where the signature block starts.
    signed_len: usize,
}

impl Advisory {
    /// Strict decode in the order of spec §5: size, header fields in order,
    /// each entry in order, the signature block to the end.
    pub fn decode(bytes: &[u8]) -> Result<Self, Rad1Error> {
        if bytes.len() > MAX_RAD1_LEN {
            return Err(Rad1Error::TooLong);
        }
        let mut r = Reader { buf: bytes, at: 0 };
        if r.take(4)? != RAD1_MAGIC {
            return Err(Rad1Error::BadMagic);
        }
        if r.u8()? != RAD1_VERSION {
            return Err(Rad1Error::BadVersion);
        }
        if r.u8()? != 0 {
            return Err(Rad1Error::BadFlags);
        }
        let count = usize::from(r.u16()?);
        if count > MAX_ENTRIES {
            return Err(Rad1Error::TooManyEntries);
        }
        let serial = r.u64()?;
        if serial == 0 {
            return Err(Rad1Error::BadSerial);
        }
        let issued_at_ms = r.u64()?;
        let key_set_digest = r.digest()?;
        let prev_digest = r.digest()?;
        if (serial == 1) != (prev_digest == [0; 32]) {
            return Err(Rad1Error::BadPrev);
        }
        let mut entries: Vec<Entry> = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = EntryKind::from_byte(r.u8()?).ok_or(Rad1Error::BadKind)?;
            let severity = Severity::from_byte(r.u8()?).ok_or(Rad1Error::BadSeverity)?;
            let target_len = usize::from(r.u8()?);
            if target_len == 0 || target_len > MAX_TARGET_LEN {
                return Err(Rad1Error::BadTarget);
            }
            let target = std::str::from_utf8(r.take(target_len)?)
                .ok()
                .filter(|t| target_well_formed(t))
                .ok_or(Rad1Error::BadTarget)?;
            let arg_len = usize::from(r.u16()?);
            if arg_len > MAX_ARG_LEN {
                return Err(Rad1Error::BadArg);
            }
            let arg = r.take(arg_len)?;
            let text_id = r.u16()?;
            if severity == Severity::Broken
                && matches!(
                    kind,
                    EntryKind::ReleaseFloor | EntryKind::Notice | EntryKind::KeySet
                )
            {
                return Err(Rad1Error::BadSeverity);
            }
            if !entry_fits(kind, target, arg) {
                return Err(Rad1Error::BadEntry);
            }
            if entries.iter().any(|e| e.kind == kind && e.target == target) {
                return Err(Rad1Error::DuplicateEntry);
            }
            entries.push(Entry {
                kind,
                severity,
                target: target.to_owned(),
                arg: arg.to_vec(),
                text_id,
            });
        }
        let signed_len = r.at;
        let sigs = SigBlock::decode(&bytes[signed_len..]).map_err(|_| Rad1Error::BadSigBlock)?;
        Ok(Self {
            serial,
            issued_at_ms,
            key_set_digest,
            prev_digest,
            entries,
            sigs,
            bytes: bytes.to_vec(),
            signed_len,
        })
    }

    /// The advisory's bytes, as received.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Where the signature block starts.
    pub fn signed_len(&self) -> usize {
        self.signed_len
    }

    /// The signature block.
    pub fn sigs(&self) -> &SigBlock {
        &self.sigs
    }

    /// What the release keys sign: `"rvn1/advisory/v1\0"` and the bytes
    /// before the signature block.
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input_of(&self.bytes[..self.signed_len])
    }

    /// `SHA-256("rvn1/advisory/digest/v1\0" || all bytes)`: how the next
    /// advisory, the transparency log and RUP1 name this one.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DIGEST_DOMAIN);
        h.update(&self.bytes);
        h.finalize().into()
    }

    /// Signed by `key_set` (spec §6): it names that key set, and its
    /// signature block passes [`KeySet::verify_sigs`].
    pub fn verify(&self, key_set: &KeySet) -> Result<(), SigError> {
        if self.key_set_digest != key_set.digest() {
            return Err(SigError::WrongKeySet);
        }
        key_set.verify_sigs(&self.signing_input(), &self.sigs)
    }

    /// The same content, unsigned (to sign again or re-encode).
    pub fn draft(&self) -> AdvisoryDraft {
        AdvisoryDraft {
            serial: self.serial,
            issued_at_ms: self.issued_at_ms,
            key_set_digest: self.key_set_digest,
            prev_digest: self.prev_digest,
            entries: self.entries.clone(),
        }
    }
}

/// `"rvn1/advisory/v1\0" || body`.
fn signing_input_of(body: &[u8]) -> Vec<u8> {
    [SIGNING_DOMAIN, body].concat()
}

/// An advisory before its signatures: what the release tool (P6.46) and the
/// tests build and sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvisoryDraft {
    pub serial: u64,
    pub issued_at_ms: u64,
    pub key_set_digest: [u8; 32],
    pub prev_digest: [u8; 32],
    pub entries: Vec<Entry>,
}

impl AdvisoryDraft {
    /// The bytes before the signature block, checked by the rules of
    /// [`Advisory::decode`] with an empty block ([`AdvisoryDraft::assemble`]
    /// checks the size again with the real one).
    pub fn body(&self) -> Result<Vec<u8>, Rad1Error> {
        let count = u16::try_from(self.entries.len()).map_err(|_| Rad1Error::TooManyEntries)?;
        let mut out = Vec::with_capacity(RAD1_HEADER_LEN + 96 * self.entries.len());
        out.extend_from_slice(RAD1_MAGIC);
        out.extend([RAD1_VERSION, 0]);
        out.extend(count.to_be_bytes());
        out.extend(self.serial.to_be_bytes());
        out.extend(self.issued_at_ms.to_be_bytes());
        out.extend(self.key_set_digest);
        out.extend(self.prev_digest);
        for e in &self.entries {
            let target_len = u8::try_from(e.target.len()).map_err(|_| Rad1Error::BadTarget)?;
            let arg_len = u16::try_from(e.arg.len()).map_err(|_| Rad1Error::BadArg)?;
            out.extend([e.kind.byte(), e.severity.byte(), target_len]);
            out.extend_from_slice(e.target.as_bytes());
            out.extend(arg_len.to_be_bytes());
            out.extend_from_slice(&e.arg);
            out.extend(e.text_id.to_be_bytes());
        }
        let mut check = out.clone();
        check.push(0);
        Advisory::decode(&check)?;
        Ok(out)
    }

    /// What the release keys sign.
    pub fn signing_input(&self) -> Result<Vec<u8>, Rad1Error> {
        Ok(signing_input_of(&self.body()?))
    }

    /// The advisory with this signature block.
    pub fn assemble(&self, sigs: &SigBlock) -> Result<Advisory, Rad1Error> {
        let mut bytes = self.body()?;
        bytes.extend(sigs.encode());
        Advisory::decode(&bytes)
    }

    /// The advisory signed by each `(key_index, key)` in order.
    pub fn sign(&self, signers: &[(u8, &Identity)]) -> Result<Advisory, Rad1Error> {
        self.assemble(&SigBlock::sign(&self.signing_input()?, signers))
    }
}

/// How a verified advisory relates to the one stored before it (spec §7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Succession {
    /// Nothing stored yet.
    First,
    /// The stored advisory itself.
    Same,
    /// The next serial, and its `prev_digest` names the stored one.
    Next,
    /// A later serial with advisories in between that this side never saw
    /// (accepted; the chain is not checked across the gap).
    Gap,
    /// A lower serial: ignored (`SEC_ADVISORY_ROLLBACK`).
    Rollback,
    /// The same serial with another digest, or the next serial whose
    /// `prev_digest` names another advisory: the signers issued two
    /// histories (`SEC_ADVISORY_EQUIVOCATION`, freeze).
    Equivocation,
}

impl Succession {
    /// The name the spec and the vectors use.
    pub fn name(self) -> &'static str {
        match self {
            Self::First => "FIRST",
            Self::Same => "SAME",
            Self::Next => "NEXT",
            Self::Gap => "GAP",
            Self::Rollback => "ROLLBACK",
            Self::Equivocation => "EQUIVOCATION",
        }
    }
}

/// How `new` follows the stored advisory `(serial, digest)` (spec §7). Only
/// for advisories that verified under the current key set.
pub fn succession(stored: Option<(u64, [u8; 32])>, new: &Advisory) -> Succession {
    let Some((serial, digest)) = stored else {
        return Succession::First;
    };
    match new.serial.cmp(&serial) {
        std::cmp::Ordering::Less => Succession::Rollback,
        std::cmp::Ordering::Equal if new.digest() == digest => Succession::Same,
        std::cmp::Ordering::Equal => Succession::Equivocation,
        std::cmp::Ordering::Greater if serial.checked_add(1) == Some(new.serial) => {
            if new.prev_digest == digest {
                Succession::Next
            } else {
                Succession::Equivocation
            }
        }
        std::cmp::Ordering::Greater => Succession::Gap,
    }
}

#[cfg(test)]
mod tests;
