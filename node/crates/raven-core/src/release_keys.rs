//! Release key sets and signature blocks (`protocol/RAVEN_SECURITY_ADVISORY_V1.md`
//! §2; `docs/roadmap/plans/phase6-design.json` step P6.41, design D §1 and its
//! wire specs; owner decision OD6b-20): what every signed update artifact
//! (RAD1 advisories, and later RTL1 tree heads and RRB1 manifests) is checked
//! against.
//!
//! ```text
//! KeySet  = alg u8 (1 = Ed25519) || threshold u8 || n u8 (1..=8) || pubkey[32] * n
//! digest  = SHA-256("rvn1/release-keys/v1\0" || KeySet)
//! block   = sig_count u8 || (key_index u8 || signature[64]) * sig_count
//! ```
//!
//! A key set is strict: every key a canonical point of the curve, not of
//! small order, and no key twice (two encodings of one key would count one
//! holder twice). A signature block passes only when its key indexes are
//! strictly increasing and name keys of the set, at least `threshold` keys
//! signed, and **every** listed signature verifies ([`Identity::verify`]:
//! weak keys and small-order `R` refused, canonical `s`); one bad signature
//! fails the artifact even when the others meet the threshold.
//!
//! Pure: no I/O, no clock. Which key set a build trusts (none until the
//! owner's key ceremony, `RELEASE_KEY_SET_V1 = None`) is P6.44's
//! `update_state`; test keys are in [`test_keys`] (test and debug builds).

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::identity::Identity;

/// The only signature algorithm of key sets V1 (a later `2` may add a
/// post-quantum signature next to Ed25519, design D §8).
pub const KEYSET_ALG_ED25519: u8 = 1;
/// The most keys a key set holds.
pub const KEYSET_MAX_KEYS: usize = 8;
/// `alg`, `threshold` and `n`.
pub const KEYSET_HEADER_LEN: usize = 3;
/// Domain of [`KeySet::digest`].
pub const KEYSET_DIGEST_DOMAIN: &[u8] = b"rvn1/release-keys/v1\0";
/// One signature of a block: the key index and the signature.
pub const SIG_ENTRY_LEN: usize = 65;

/// Why key set bytes are refused (spec §2.1), in the order they are checked
/// (a header shorter than 3 bytes is `BadLength` first).
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum KeySetError {
    /// `alg` is not [`KEYSET_ALG_ED25519`].
    #[error("KEYSET UNSUPPORTED_ALG")]
    UnsupportedAlg,
    /// `n` is 0 or more than [`KEYSET_MAX_KEYS`].
    #[error("KEYSET BAD_COUNT")]
    BadCount,
    /// Shorter than the header, or not exactly `3 + 32 * n` bytes.
    #[error("KEYSET BAD_LENGTH")]
    BadLength,
    /// `threshold` is 0 or more than `n`.
    #[error("KEYSET BAD_THRESHOLD")]
    BadThreshold,
    /// A key is not the canonical encoding of a curve point, or the point
    /// has small order.
    #[error("KEYSET WEAK_KEY")]
    WeakKey,
    /// A key is listed twice.
    #[error("KEYSET DUPLICATE_KEY")]
    DuplicateKey,
}

impl KeySetError {
    /// The name the spec and the vectors use.
    pub fn code(self) -> &'static str {
        match self {
            Self::UnsupportedAlg => "UNSUPPORTED_ALG",
            Self::BadCount => "BAD_COUNT",
            Self::BadLength => "BAD_LENGTH",
            Self::BadThreshold => "BAD_THRESHOLD",
            Self::WeakKey => "WEAK_KEY",
            Self::DuplicateKey => "DUPLICATE_KEY",
        }
    }
}

/// Why a signed artifact's signatures are refused (spec §2.3), in the order
/// they are checked. Each one makes the artifact forged.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SigError {
    /// The artifact names another key set (its `key_set_digest` is not this
    /// set's digest).
    #[error("SIG WRONG_KEY_SET")]
    WrongKeySet,
    /// The block is not exactly `1 + 65 * sig_count` bytes.
    #[error("SIG MALFORMED")]
    Malformed,
    /// The key indexes are not strictly increasing (a key listed twice).
    #[error("SIG KEY_INDEX_ORDER")]
    KeyIndexOrder,
    /// A key index is not below the key set's `n`.
    #[error("SIG UNKNOWN_KEY_INDEX")]
    UnknownKeyIndex,
    /// Fewer signatures than the key set's threshold.
    #[error("SIG BELOW_THRESHOLD")]
    BelowThreshold,
    /// A listed signature does not verify.
    #[error("SIG BAD_SIGNATURE")]
    BadSignature,
}

impl SigError {
    /// The name the spec and the vectors use.
    pub fn code(self) -> &'static str {
        match self {
            Self::WrongKeySet => "WRONG_KEY_SET",
            Self::Malformed => "MALFORMED",
            Self::KeyIndexOrder => "KEY_INDEX_ORDER",
            Self::UnknownKeyIndex => "UNKNOWN_KEY_INDEX",
            Self::BelowThreshold => "BELOW_THRESHOLD",
            Self::BadSignature => "BAD_SIGNATURE",
        }
    }
}

/// Is `key` a canonical, not small-order Ed25519 point? Canonical: the
/// point it decodes to encodes back to the same 32 bytes (no `y >= p`, no
/// sign bit on `x = 0`), so one key has one encoding.
fn usable_key(key: &[u8; 32]) -> bool {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(key) else {
        return false;
    };
    !vk.is_weak() && vk.to_edwards().compress().to_bytes() == *key
}

/// A release key set (spec §2.1): `threshold` of the `keys` must sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySet {
    threshold: u8,
    keys: Vec<[u8; 32]>,
}

impl KeySet {
    /// An Ed25519 key set, checked like [`KeySet::decode`].
    pub fn new(threshold: u8, keys: Vec<[u8; 32]>) -> Result<Self, KeySetError> {
        if keys.is_empty() || keys.len() > KEYSET_MAX_KEYS {
            return Err(KeySetError::BadCount);
        }
        if threshold == 0 || usize::from(threshold) > keys.len() {
            return Err(KeySetError::BadThreshold);
        }
        for (i, key) in keys.iter().enumerate() {
            if !usable_key(key) {
                return Err(KeySetError::WeakKey);
            }
            if keys[..i].contains(key) {
                return Err(KeySetError::DuplicateKey);
            }
        }
        Ok(Self { threshold, keys })
    }

    /// Strict decode (spec §2.1): the header, the algorithm, the count, the
    /// length, the threshold, then each key in order (usable, not seen
    /// before).
    pub fn decode(bytes: &[u8]) -> Result<Self, KeySetError> {
        let [alg, threshold, n, rest @ ..] = bytes else {
            return Err(KeySetError::BadLength);
        };
        if *alg != KEYSET_ALG_ED25519 {
            return Err(KeySetError::UnsupportedAlg);
        }
        if *n == 0 || usize::from(*n) > KEYSET_MAX_KEYS {
            return Err(KeySetError::BadCount);
        }
        if rest.len() != 32 * usize::from(*n) {
            return Err(KeySetError::BadLength);
        }
        let keys = rest.as_chunks::<32>().0.to_vec();
        Self::new(*threshold, keys)
    }

    /// The canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KEYSET_HEADER_LEN + 32 * self.keys.len());
        out.extend([
            KEYSET_ALG_ED25519,
            self.threshold,
            u8::try_from(self.keys.len()).expect("at most 8 keys"),
        ]);
        for key in &self.keys {
            out.extend_from_slice(key);
        }
        out
    }

    /// `SHA-256("rvn1/release-keys/v1\0" || bytes)`: how artifacts name the
    /// key set that signs them.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(KEYSET_DIGEST_DOMAIN);
        h.update(self.encode());
        h.finalize().into()
    }

    /// How many keys must sign.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// The public keys, by key index.
    pub fn keys(&self) -> &[[u8; 32]] {
        &self.keys
    }

    /// Check the signature block bytes `block` (exactly the block: nothing
    /// before or after it) over `signing_input` (spec §2.3).
    pub fn verify_block(&self, signing_input: &[u8], block: &[u8]) -> Result<(), SigError> {
        self.verify_sigs(signing_input, &SigBlock::decode(block)?)
    }

    /// Check a decoded signature block over `signing_input` (spec §2.3):
    /// indexes strictly increasing and below `n`, at least `threshold`
    /// signatures, every one valid.
    pub fn verify_sigs(&self, signing_input: &[u8], block: &SigBlock) -> Result<(), SigError> {
        let sigs = block.sigs();
        if sigs.windows(2).any(|w| w[0].0 >= w[1].0) {
            return Err(SigError::KeyIndexOrder);
        }
        if sigs.iter().any(|(i, _)| usize::from(*i) >= self.keys.len()) {
            return Err(SigError::UnknownKeyIndex);
        }
        if sigs.len() < usize::from(self.threshold) {
            return Err(SigError::BelowThreshold);
        }
        for (index, sig) in sigs {
            if !Identity::verify(&self.keys[usize::from(*index)], signing_input, sig) {
                return Err(SigError::BadSignature);
            }
        }
        Ok(())
    }
}

/// A signature block (spec §2.2): `(key_index, signature)` in the order
/// they travel. Decoding checks only the framing; [`KeySet::verify_sigs`]
/// checks the rest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SigBlock {
    sigs: Vec<(u8, [u8; 64])>,
}

impl SigBlock {
    /// A block of these signatures, in this order (not checked here).
    pub fn new(sigs: Vec<(u8, [u8; 64])>) -> Self {
        Self { sigs }
    }

    /// `signing_input` signed by each `(key_index, key)` in order: the block
    /// an offline signing run produces (the release tool, P6.46, and tests).
    pub fn sign(signing_input: &[u8], signers: &[(u8, &Identity)]) -> Self {
        Self::new(
            signers
                .iter()
                .map(|(i, id)| (*i, id.sign(signing_input)))
                .collect(),
        )
    }

    /// Exactly one block: `sig_count`, then that many signatures, nothing
    /// after them.
    pub fn decode(bytes: &[u8]) -> Result<Self, SigError> {
        let (&count, rest) = bytes.split_first().ok_or(SigError::Malformed)?;
        if rest.len() != SIG_ENTRY_LEN * usize::from(count) {
            return Err(SigError::Malformed);
        }
        Ok(Self::new(
            rest.as_chunks::<SIG_ENTRY_LEN>()
                .0
                .iter()
                .map(|c| (c[0], c[1..].try_into().expect("64-byte signature")))
                .collect(),
        ))
    }

    /// The block bytes. At most 255 signatures travel; [`KeySet::verify_sigs`]
    /// refuses more than 8 anyway.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + SIG_ENTRY_LEN * self.sigs.len());
        out.push(u8::try_from(self.sigs.len()).expect("at most 255 signatures"));
        for (index, sig) in &self.sigs {
            out.push(*index);
            out.extend_from_slice(sig);
        }
        out
    }

    /// The signatures, in block order.
    pub fn sigs(&self) -> &[(u8, [u8; 64])] {
        &self.sigs
    }
}

/// The published test keys (design D §1): seeds `0x11 x 32`, `0x22 x 32`,
/// `0x33 x 32`, a 2-of-3 set. They are in the vectors and in this source,
/// so anyone can sign with them: a production key set must never contain
/// one (P6.44 checks the compiled set). Test and debug builds only.
#[cfg(any(test, debug_assertions))]
pub mod test_keys {
    use super::KeySet;
    use crate::identity::Identity;

    /// The seeds of key indexes 0, 1 and 2 of [`key_set`].
    pub const SEEDS: [[u8; 32]; 3] = [[0x11; 32], [0x22; 32], [0x33; 32]];

    /// A test key from a seed byte (`[byte; 32]`): the three of [`SEEDS`],
    /// and others for rotation and wrong-key cases.
    pub fn signer(seed_byte: u8) -> Identity {
        Identity::from_seed(&[seed_byte; 32])
    }

    /// The three test signers, by key index.
    pub fn signers() -> [Identity; 3] {
        SEEDS.map(|s| Identity::from_seed(&s))
    }

    /// A key set of the test keys with these seed bytes.
    pub fn key_set_of(threshold: u8, seed_bytes: &[u8]) -> KeySet {
        KeySet::new(
            threshold,
            seed_bytes
                .iter()
                .map(|b| signer(*b).public_key_bytes())
                .collect(),
        )
        .expect("test keys form a key set")
    }

    /// The 2-of-3 test key set (`update/keyset_001.json`).
    pub fn key_set() -> KeySet {
        key_set_of(2, &[0x11, 0x22, 0x33])
    }
}

#[cfg(test)]
mod tests;
