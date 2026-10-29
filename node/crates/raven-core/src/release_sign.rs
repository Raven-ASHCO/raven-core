//! Offline release signing (`docs/roadmap/plans/phase6-design.json` step
//! P6.46, design D §9; owner decisions OD6b-20, OD6b-22, OD6b-28): what the
//! `raven-release` tool (ash, feature `release-tool`) does on the offline
//! machine of the key ceremony (`docs/RELEASE_KEY_CEREMONY.md`), and what its
//! tests check against the verifiers of [`crate::advisory`], [`crate::tlog`]
//! and [`crate::release_bundle`].
//!
//! - **Key files** ([`KeyFile`]): one release key per removable medium, its
//!   Ed25519 seed sealed with XChaCha20-Poly1305 under an Argon2id key from
//!   the holder's passphrase (typed at a terminal, never argv or the
//!   environment: the tool's job). The public key and a label (never a
//!   person's name) stay readable, so a key set is built without a
//!   passphrase.
//! - **Drafts** ([`Artifact`]): an RRB1 manifest, a RAD1 advisory or an RTL1
//!   tree head with an empty signature block. They decode like the signed
//!   ones, so the signer sees exactly what the keys sign.
//! - **Detached signatures** ([`DetachedSig`]): one key per signing run, one
//!   file per key and draft; [`combine`] checks each one and builds the
//!   signature block (key indexes in order, exactly the threshold).
//! - **The log kit** ([`ReleaseLog`]): the folder published as the public
//!   `raven-release-log` repository: `entries.bin` (the 41-byte RTL1
//!   entries back to back), `sth/<size>.rtl1` (signed tree heads),
//!   `advisories/<serial>.rad1`, `manifests/<build serial>-<target>.rrb1`,
//!   `keysets/<digest>.keyset` and `snapshot.rtl1` (the newest snapshot).
//!   `scripts/release/check_log.py` audits it.
//! - **Packing** ([`pack`]): the `.rrb` container, byte for byte the same
//!   from the same pieces, verified by [`verify_bundle`] before it is
//!   written.
//!
//! ```text
//! key file = "RVNRKY01" || version 0x01 || kdf 0x01 (Argon2id v0x13)
//!         || aead 0x01 (XChaCha20-Poly1305) || label_len u8 (1..=32)
//!         || m_kib u32 || t u32 || p u32 || salt[16] || nonce[24]
//!         || public_key[32] || label || sealed seed[32 + 16]
//!            (AAD: every byte before the sealed seed)
//! signature = "RVNRSG01" || version 0x01 || kind u8 (1 manifest, 2 advisory,
//!            3 tree head) || key_index u8 || reserved 0
//!         || SHA-256(signing input)[32] || public_key[32] || signature[64]
//! ```
//!
//! Integers are big-endian. These two files never leave the ceremony: no
//! peer reads them, so they are not wire formats. Test and debug builds may
//! use weak Argon2id parameters ([`TEST_KDF`]) and the published test keys
//! ([`test_signer`]); a release build refuses both.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::advisory::{
    Advisory, AdvisoryDraft, Entry, EntryKind, Severity, FEATURE_PREFIX, KEY_SET_TARGET,
    NOTICE_TARGET, RAD1_MAGIC, RELEASE_FLOOR_TARGET,
};
use crate::identity::Identity;
use crate::keystore_vault::{KdfBounds, KdfParams, MAX_PASSPHRASE_BYTES};
use crate::release_bundle::{
    verify_bundle, Container, FileMode, Manifest, ManifestDraft, PackFile, Parts, VerifyCtx,
    RRB1_MAGIC, SOURCE_COMMIT_LEN,
};
use crate::release_keys::{KeySet, SigBlock, SigError};
use crate::sanitize::sanitize_terminal_line;
use crate::suite_registry;
use crate::tlog::{
    EntryType, LogEntry, Snapshot, Sth, SthDraft, ENTRY_LEN, KIND_STH, MAX_LOG_ENTRIES, RTL1_MAGIC,
};

/// The magic of a key file.
pub const KEY_FILE_MAGIC: &[u8; 8] = b"RVNRKY01";
/// The magic of a detached signature file.
pub const SIG_FILE_MAGIC: &[u8; 8] = b"RVNRSG01";
/// The version byte of both files.
pub const FILE_VERSION: u8 = 0x01;
const KDF_ARGON2ID_V13: u8 = 0x01;
const AEAD_XCHACHA20_POLY1305: u8 = 0x01;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// The fixed part of a key file, before the label.
pub const KEY_FILE_HEADER_LEN: usize = 96;
/// The longest key label.
pub const MAX_LABEL_LEN: usize = 32;
/// A detached signature file's length.
pub const SIG_FILE_LEN: usize = 140;
/// The shortest passphrase `keygen` accepts, in characters.
pub const MIN_KEY_PASSPHRASE_CHARS: usize = 12;

/// The Argon2id cost of every new key file: 256 MiB, 3 passes, 1 lane
/// (about a second on the ceremony laptop, a long time for each guess).
pub const KEY_FILE_KDF: KdfParams = KdfParams {
    m_kib: 256 * 1024,
    t: 3,
    p: 1,
};

/// What a key file may ask for when it is read: a planted file outside
/// this range is refused before Argon2id runs.
pub const KEY_FILE_BOUNDS: KdfBounds = KdfBounds {
    min_m_kib: 64 * 1024,
    max_m_kib: 4 * 1024 * 1024,
    min_t: 1,
    max_t: 16,
    min_p: 1,
    max_p: 8,
};

/// Weak parameters for tests and dry runs of a debug build of the tool
/// (`keygen --test-kdf`); a release build refuses to write or read them.
pub const TEST_KDF: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};

/// [`KEY_FILE_BOUNDS`] with [`TEST_KDF`] allowed: what debug builds read
/// (and what the tests pass to [`KeyFile::seal_with`] and
/// [`KeyFile::decode_with`], so they run in release builds too).
pub const TEST_BOUNDS: KdfBounds = KdfBounds {
    min_m_kib: 8,
    ..KEY_FILE_BOUNDS
};

/// The log kit's entries file.
pub const LOG_ENTRIES: &str = "entries.bin";
/// The log kit's folder of signed tree heads (`<size>.rtl1`).
pub const LOG_TREE_HEADS: &str = "sth";
/// The log kit's folder of advisories (`<serial>.rad1`).
pub const LOG_ADVISORIES: &str = "advisories";
/// The log kit's folder of manifests (`<build serial>-<target>.rrb1`).
pub const LOG_MANIFESTS: &str = "manifests";
/// The log kit's folder of key sets (`<digest hex>.keyset`).
pub const LOG_KEY_SETS: &str = "keysets";
/// The log kit's newest snapshot.
pub const LOG_SNAPSHOT: &str = "snapshot.rtl1";

/// Why the tool refuses (the operator's words).
#[derive(Debug, Error)]
pub enum SignError {
    /// A file could not be read or written.
    #[error("{0}")]
    Io(String),
    /// Not a key file, or a damaged one.
    #[error("not a Raven release key file: {0}")]
    BadKeyFile(&'static str),
    /// The key file's Argon2id cost is outside what this build accepts.
    #[error(
        "the key file asks for Argon2id m={m_kib} KiB t={t} p={p}, outside the accepted range"
    )]
    UnsafeKdf { m_kib: u32, t: u32, p: u32 },
    /// The passphrase does not open the key file (or the file was changed).
    #[error("that passphrase does not open this key file (or the file was changed)")]
    WrongPassphrase,
    /// A key label that is not `[a-z0-9-]`, 1 to 32 characters.
    #[error("a key label is 1 to {MAX_LABEL_LEN} characters of a-z, 0-9 and '-', not starting or ending with '-' (never a person's name)")]
    BadLabel,
    /// A passphrase too short or too long.
    #[error("{0}")]
    BadPassphrase(String),
    /// Weak test parameters or test keys in a release build.
    #[error("{0} are refused in a release build of raven-release")]
    TestOnly(&'static str),
    /// Bytes that are no artifact this tool signs.
    #[error("not a draft or artifact raven-release signs (an RRB1 manifest, a RAD1 advisory or an RTL1 tree head): {0}")]
    NotAnArtifact(String),
    /// An artifact that decodes but is refused (its own code).
    #[error("{0}")]
    Artifact(String),
    /// The artifact names another key set than the one given.
    #[error("the artifact names key set {artifact}, not the key set given ({given})")]
    WrongKeySet { artifact: String, given: String },
    /// The signing key is not in the key set.
    #[error("this key ({0}) is not in the key set")]
    KeyNotInSet(String),
    /// Not a detached signature file.
    #[error("not a raven-release signature file: {0}")]
    BadSigFile(&'static str),
    /// A signature that does not belong to the draft, or does not verify.
    #[error("{0}")]
    Signature(String),
    /// Not enough signatures, or two by one key.
    #[error("{0}")]
    Combine(String),
    /// The log folder refuses the change.
    #[error("log: {0}")]
    Log(String),
    /// A bundle that would not verify.
    #[error("bundle: {0}")]
    Bundle(String),
    /// An advisory or manifest description that cannot be built.
    #[error("{0}")]
    Spec(String),
}

fn io(path: &Path, what: &str, e: std::io::Error) -> SignError {
    SignError::Io(format!("{what} {}: {e}", path.display()))
}

/// Lower-case hex.
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// SHA-256.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// `N` bytes from `2 * N` hex digits (either case, surrounding space
/// ignored).
pub fn parse_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let raw = hex::decode(text.trim()).ok()?;
    raw.try_into().ok()
}

// ── Test-only parameters and keys ───────────────────────────────────

/// The Argon2id cost of a new key file: [`KEY_FILE_KDF`], or [`TEST_KDF`]
/// when `test_kdf` is asked for (test and debug builds only).
pub fn keygen_params(test_kdf: bool) -> Result<KdfParams, SignError> {
    keygen_params_for(test_kdf, cfg!(debug_assertions))
}

/// [`keygen_params`] of a debug (`debug`) or a release build.
pub fn keygen_params_for(test_kdf: bool, debug: bool) -> Result<KdfParams, SignError> {
    match (test_kdf, debug) {
        (false, _) => Ok(KEY_FILE_KDF),
        (true, true) => Ok(TEST_KDF),
        (true, false) => Err(SignError::TestOnly("weak test Argon2id parameters")),
    }
}

/// What a key file may ask for when it is read, or sealed, in this build.
pub fn key_file_bounds() -> KdfBounds {
    key_file_bounds_for(cfg!(debug_assertions))
}

/// [`key_file_bounds`] of a debug (`debug`) or a release build.
pub fn key_file_bounds_for(debug: bool) -> KdfBounds {
    if debug {
        TEST_BOUNDS
    } else {
        KEY_FILE_BOUNDS
    }
}

/// Published test key `index` (0, 1 or 2: the seeds `0x11`, `0x22`, `0x33`
/// x 32 of `update/keyset_001.json`): test and debug builds only. Anyone
/// can sign with these keys; [`crate::update_state`] refuses a compiled key
/// set that holds one.
pub fn test_signer(index: u8) -> Result<Identity, SignError> {
    #[cfg(debug_assertions)]
    {
        let seed = crate::release_keys::test_keys::SEEDS
            .get(usize::from(index))
            .ok_or_else(|| SignError::Spec("a test key index is 0, 1 or 2".into()))?;
        Ok(Identity::from_seed(seed))
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = index;
        Err(SignError::TestOnly("the published test keys"))
    }
}

/// Is `key` one of the published test keys?
pub fn is_test_key(key: &[u8; 32]) -> bool {
    crate::update_state::TEST_PUBLIC_KEYS.contains(key)
}

// ── Key files ───────────────────────────────────────────────────────

/// Is `label` a key label: 1..=32 of `[a-z0-9-]`, no `-` at either end?
pub fn label_well_formed(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_LEN
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// A new key's passphrase: at least [`MIN_KEY_PASSPHRASE_CHARS`]
/// characters, at most 1,024 bytes.
pub fn check_new_passphrase(passphrase: &[u8]) -> Result<(), SignError> {
    if passphrase.len() > MAX_PASSPHRASE_BYTES {
        return Err(SignError::BadPassphrase(format!(
            "a passphrase is at most {MAX_PASSPHRASE_BYTES} bytes"
        )));
    }
    let chars = std::str::from_utf8(passphrase)
        .map(|s| s.chars().count())
        .unwrap_or(passphrase.len());
    if chars < MIN_KEY_PASSPHRASE_CHARS {
        return Err(SignError::BadPassphrase(format!(
            "a release key passphrase has at least {MIN_KEY_PASSPHRASE_CHARS} characters \
             (six or more random words are better)"
        )));
    }
    Ok(())
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>, SignError> {
    let unsafe_kdf = || SignError::UnsafeKdf {
        m_kib: params.m_kib,
        t: params.t,
        p: params.p,
    };
    let argon_params = argon2::Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|_| unsafe_kdf())?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, &mut key[..])
        .map_err(|_| unsafe_kdf())?;
    Ok(key)
}

/// A release key file (see the module docs): the public key and label in
/// the clear, the seed sealed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyFile {
    label: String,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    public_key: [u8; 32],
    sealed: Vec<u8>,
}

impl KeyFile {
    /// A new key from the system's random source, sealed under
    /// `passphrase` (checked by [`check_new_passphrase`]).
    pub fn generate(label: &str, passphrase: &[u8], params: KdfParams) -> Result<Self, SignError> {
        Self::generate_with(label, passphrase, params, &key_file_bounds())
    }

    /// [`KeyFile::generate`] with the cost within `bounds`.
    pub fn generate_with(
        label: &str,
        passphrase: &[u8],
        params: KdfParams,
        bounds: &KdfBounds,
    ) -> Result<Self, SignError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut seed[..]);
        Self::seal_with(label, &seed, passphrase, params, bounds)
    }

    /// `seed` sealed under `passphrase` with a fresh salt and nonce, the
    /// cost within [`key_file_bounds`].
    pub fn seal(
        label: &str,
        seed: &[u8; 32],
        passphrase: &[u8],
        params: KdfParams,
    ) -> Result<Self, SignError> {
        Self::seal_with(label, seed, passphrase, params, &key_file_bounds())
    }

    /// [`KeyFile::seal`] with the cost within `bounds`.
    pub fn seal_with(
        label: &str,
        seed: &[u8; 32],
        passphrase: &[u8],
        params: KdfParams,
        bounds: &KdfBounds,
    ) -> Result<Self, SignError> {
        if !label_well_formed(label) {
            return Err(SignError::BadLabel);
        }
        check_new_passphrase(passphrase)?;
        bounds.check(params).map_err(|_| SignError::UnsafeKdf {
            m_kib: params.m_kib,
            t: params.t,
            p: params.p,
        })?;
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let mut file = Self {
            label: label.to_owned(),
            params,
            salt,
            nonce,
            public_key: Identity::from_seed(seed).public_key_bytes(),
            sealed: Vec::new(),
        };
        let key = derive_key(passphrase, &salt, params)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|_| SignError::BadKeyFile("key length"))?;
        file.sealed = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &seed[..],
                    aad: &file.header(),
                },
            )
            .map_err(|_| SignError::BadKeyFile("sealing failed"))?;
        Ok(file)
    }

    /// Every byte before the sealed seed: the AEAD's associated data.
    fn header(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KEY_FILE_HEADER_LEN + self.label.len());
        out.extend_from_slice(KEY_FILE_MAGIC);
        out.extend([
            FILE_VERSION,
            KDF_ARGON2ID_V13,
            AEAD_XCHACHA20_POLY1305,
            u8::try_from(self.label.len()).expect("a label is at most 32 bytes"),
        ]);
        out.extend(self.params.m_kib.to_be_bytes());
        out.extend(self.params.t.to_be_bytes());
        out.extend(self.params.p.to_be_bytes());
        out.extend(self.salt);
        out.extend(self.nonce);
        out.extend(self.public_key);
        out.extend_from_slice(self.label.as_bytes());
        out
    }

    /// The file's bytes.
    pub fn encode(&self) -> Vec<u8> {
        [self.header(), self.sealed.clone()].concat()
    }

    /// Strict decode: the length, the header in order, the label, the
    /// Argon2id cost against [`key_file_bounds`], the public key a usable
    /// Ed25519 key. Nothing is decrypted.
    pub fn decode(bytes: &[u8]) -> Result<Self, SignError> {
        Self::decode_with(bytes, &key_file_bounds())
    }

    /// [`KeyFile::decode`] with the cost checked against `bounds`.
    pub fn decode_with(bytes: &[u8], bounds: &KdfBounds) -> Result<Self, SignError> {
        if bytes.len() < KEY_FILE_HEADER_LEN + 1 + 32 + TAG_LEN {
            return Err(SignError::BadKeyFile("too short"));
        }
        if &bytes[..8] != KEY_FILE_MAGIC {
            return Err(SignError::BadKeyFile("wrong magic"));
        }
        if bytes[8] != FILE_VERSION {
            return Err(SignError::BadKeyFile("unsupported version"));
        }
        if bytes[9] != KDF_ARGON2ID_V13 || bytes[10] != AEAD_XCHACHA20_POLY1305 {
            return Err(SignError::BadKeyFile("unsupported algorithms"));
        }
        let label_len = usize::from(bytes[11]);
        if bytes.len() != KEY_FILE_HEADER_LEN + label_len + 32 + TAG_LEN {
            return Err(SignError::BadKeyFile("wrong length"));
        }
        let u32_at = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().expect("4"));
        let params = KdfParams {
            m_kib: u32_at(12),
            t: u32_at(16),
            p: u32_at(20),
        };
        bounds.check(params).map_err(|_| SignError::UnsafeKdf {
            m_kib: params.m_kib,
            t: params.t,
            p: params.p,
        })?;
        let label =
            std::str::from_utf8(&bytes[KEY_FILE_HEADER_LEN..KEY_FILE_HEADER_LEN + label_len])
                .ok()
                .filter(|l| label_well_formed(l))
                .ok_or(SignError::BadLabel)?;
        let public_key: [u8; 32] = bytes[64..96].try_into().expect("32 bytes");
        if KeySet::new(1, vec![public_key]).is_err() {
            return Err(SignError::BadKeyFile(
                "the public key is not a usable Ed25519 key",
            ));
        }
        Ok(Self {
            label: label.to_owned(),
            params,
            salt: bytes[24..40].try_into().expect("16 bytes"),
            nonce: bytes[40..64].try_into().expect("24 bytes"),
            public_key,
            sealed: bytes[KEY_FILE_HEADER_LEN + label_len..].to_vec(),
        })
    }

    /// Read and decode a key file.
    pub fn read(path: &Path) -> Result<Self, SignError> {
        let meta = fs::symlink_metadata(path).map_err(|e| io(path, "cannot read", e))?;
        if !meta.is_file() || meta.len() > 4_096 {
            return Err(SignError::BadKeyFile(
                "not a regular file of the right size",
            ));
        }
        Self::decode(&fs::read(path).map_err(|e| io(path, "cannot read", e))?)
    }

    /// The key's label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// The Argon2id cost it was sealed with.
    pub fn params(&self) -> KdfParams {
        self.params
    }

    /// The signing key, opened with `passphrase`. A wrong passphrase, or
    /// any changed byte, is [`SignError::WrongPassphrase`].
    pub fn unlock(&self, passphrase: &[u8]) -> Result<Identity, SignError> {
        let key = derive_key(passphrase, &self.salt, self.params)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|_| SignError::BadKeyFile("key length"))?;
        let seed = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&self.nonce),
                    Payload {
                        msg: &self.sealed,
                        aad: &self.header(),
                    },
                )
                .map_err(|_| SignError::WrongPassphrase)?,
        );
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            seed.as_slice()
                .try_into()
                .map_err(|_| SignError::BadKeyFile("the sealed seed has the wrong length"))?,
        );
        let id = Identity::from_seed(&seed);
        if id.public_key_bytes() != self.public_key {
            return Err(SignError::BadKeyFile(
                "the sealed key does not match the public key",
            ));
        }
        Ok(id)
    }
}

/// A public key from a key file, a `.pub` file (its hex on one line), or
/// 64 hex digits.
pub fn read_public_key(arg: &str) -> Result<[u8; 32], SignError> {
    if let Some(key) = parse_hex::<32>(arg) {
        return Ok(key);
    }
    let path = Path::new(arg);
    let bytes = fs::read(path).map_err(|e| io(path, "cannot read", e))?;
    if bytes.starts_with(KEY_FILE_MAGIC) {
        return Ok(KeyFile::decode(&bytes)?.public_key());
    }
    std::str::from_utf8(&bytes)
        .ok()
        .and_then(|t| t.split_whitespace().next())
        .and_then(parse_hex::<32>)
        .ok_or_else(|| {
            SignError::Spec(format!(
                "{}: not a key file, a .pub file or 64 hex digits",
                path.display()
            ))
        })
}

// ── Artifacts and drafts ────────────────────────────────────────────

/// What a detached signature signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactKind {
    /// An RRB1 release manifest.
    Manifest,
    /// A RAD1 security advisory.
    Advisory,
    /// An RTL1 signed tree head.
    TreeHead,
}

impl ArtifactKind {
    /// The byte of a signature file.
    pub fn byte(self) -> u8 {
        match self {
            Self::Manifest => 1,
            Self::Advisory => 2,
            Self::TreeHead => 3,
        }
    }

    /// The kind of a signature file's byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Manifest),
            2 => Some(Self::Advisory),
            3 => Some(Self::TreeHead),
            _ => None,
        }
    }

    /// The operator's word for it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Manifest => "release manifest",
            Self::Advisory => "security advisory",
            Self::TreeHead => "log tree head",
        }
    }
}

/// A draft (no signatures yet) or a signed artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Artifact {
    Manifest(Manifest),
    Advisory(Advisory),
    TreeHead(Sth),
}

impl Artifact {
    /// Decode by the magic: `RRB1`, `RAD1`, or an `RTL1` tree head.
    pub fn decode(bytes: &[u8]) -> Result<Self, SignError> {
        match bytes.get(..4) {
            Some(m) if m == RRB1_MAGIC => Manifest::decode(bytes)
                .map(Self::Manifest)
                .map_err(|e| SignError::Artifact(e.to_string())),
            Some(m) if m == RAD1_MAGIC => Advisory::decode(bytes)
                .map(Self::Advisory)
                .map_err(|e| SignError::Artifact(e.to_string())),
            Some(m) if m == RTL1_MAGIC && bytes.get(5) == Some(&KIND_STH) => Sth::decode(bytes)
                .map(Self::TreeHead)
                .map_err(|e| SignError::Artifact(e.to_string())),
            Some(m) if m == RTL1_MAGIC => Err(SignError::NotAnArtifact(
                "an RTL1 snapshot is not signed itself: sign its tree head".into(),
            )),
            _ => Err(SignError::NotAnArtifact("unknown magic".into())),
        }
    }

    /// Read and decode.
    pub fn read(path: &Path) -> Result<Self, SignError> {
        let bytes = read_capped(path, 1 << 20)?;
        Self::decode(&bytes).map_err(|e| match e {
            SignError::NotAnArtifact(why) => {
                SignError::NotAnArtifact(format!("{}: {why}", path.display()))
            }
            other => other,
        })
    }

    /// Which kind it is.
    pub fn kind(&self) -> ArtifactKind {
        match self {
            Self::Manifest(_) => ArtifactKind::Manifest,
            Self::Advisory(_) => ArtifactKind::Advisory,
            Self::TreeHead(_) => ArtifactKind::TreeHead,
        }
    }

    /// The bytes.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Manifest(m) => m.bytes(),
            Self::Advisory(a) => a.bytes(),
            Self::TreeHead(s) => s.bytes(),
        }
    }

    /// What the release keys sign.
    pub fn signing_input(&self) -> Vec<u8> {
        match self {
            Self::Manifest(m) => m.signing_input(),
            Self::Advisory(a) => a.signing_input(),
            Self::TreeHead(s) => s.signing_input(),
        }
    }

    /// `SHA-256(signing input)`: what the signer compares on both machines.
    pub fn signing_hash(&self) -> [u8; 32] {
        Sha256::digest(self.signing_input()).into()
    }

    /// The key set it names.
    pub fn key_set_digest(&self) -> [u8; 32] {
        match self {
            Self::Manifest(m) => m.key_set_digest,
            Self::Advisory(a) => a.key_set_digest,
            Self::TreeHead(s) => s.key_set_digest,
        }
    }

    /// The signatures it carries.
    pub fn sigs(&self) -> &SigBlock {
        match self {
            Self::Manifest(m) => m.sigs(),
            Self::Advisory(a) => a.sigs(),
            Self::TreeHead(s) => s.sigs(),
        }
    }

    /// No signatures yet.
    pub fn is_draft(&self) -> bool {
        self.sigs().sigs().is_empty()
    }

    /// The same content with this signature block.
    pub fn with_sigs(&self, sigs: &SigBlock) -> Result<Self, SignError> {
        let refused = |e: &dyn std::fmt::Display| SignError::Artifact(e.to_string());
        Ok(match self {
            Self::Manifest(m) => Self::Manifest(m.draft().assemble(sigs).map_err(|e| refused(&e))?),
            Self::Advisory(a) => Self::Advisory(a.draft().assemble(sigs).map_err(|e| refused(&e))?),
            Self::TreeHead(s) => Self::TreeHead(s.draft().assemble(sigs).map_err(|e| refused(&e))?),
        })
    }

    /// The same content with no signatures: the draft.
    pub fn unsigned(&self) -> Result<Self, SignError> {
        self.with_sigs(&SigBlock::default())
    }

    /// Signed by `key_set` (its threshold, every signature valid).
    pub fn verify(&self, key_set: &KeySet) -> Result<(), SigError> {
        match self {
            Self::Manifest(m) => m.verify(key_set),
            Self::Advisory(a) => a.verify(key_set),
            Self::TreeHead(s) => s.verify(key_set),
        }
    }

    /// The log entry it is listed under (a tree head is not listed).
    pub fn log_name(&self) -> Option<(EntryType, [u8; 32])> {
        match self {
            Self::Manifest(m) => Some((EntryType::Manifest, m.digest())),
            Self::Advisory(a) => Some((EntryType::Advisory, a.digest())),
            Self::TreeHead(_) => None,
        }
    }

    /// What the signer reads before typing a passphrase: every field the
    /// keys vouch for (text sanitized for the terminal).
    pub fn summary(&self) -> Vec<String> {
        let mut out = Vec::new();
        match self {
            Self::Manifest(m) => {
                out.push(format!(
                    "release manifest: Raven {} for {}, build serial {}",
                    sanitize_terminal_line(&m.version),
                    sanitize_terminal_line(&m.target),
                    m.build_serial
                ));
                out.push(format!(
                    "  source commit {}, toolchain {}, created at {} ms",
                    to_hex(&m.source_commit),
                    sanitize_terminal_line(&m.toolchain),
                    m.created_at_ms
                ));
                out.push(format!(
                    "  newest advisory known: {}; payload {} bytes, sha256 {}",
                    m.min_advisory_serial,
                    m.payload_len,
                    to_hex(&m.payload_sha256)
                ));
                for f in &m.files {
                    out.push(format!(
                        "  {} ({} bytes, mode {:o}) sha256 {} rebuild {}",
                        f.path,
                        f.size,
                        f.mode.unix_mode(),
                        to_hex(&f.sha256),
                        to_hex(&f.rebuild_sha256)
                    ));
                }
                out.push(format!("  notes: {} bytes", m.notes.len()));
                for line in m.notes.lines() {
                    out.push(format!("    {}", sanitize_terminal_line(line)));
                }
            }
            Self::Advisory(a) => {
                out.push(format!(
                    "security advisory #{}, issued at {} ms, {} entries",
                    a.serial,
                    a.issued_at_ms,
                    a.entries.len()
                ));
                out.push(format!(
                    "  previous advisory digest {}",
                    to_hex(&a.prev_digest)
                ));
                for e in &a.entries {
                    out.push(format!("  {}", entry_line(e)));
                }
            }
            Self::TreeHead(s) => {
                out.push(format!(
                    "log tree head: {} entries, root {}, at {} ms",
                    s.tree_size,
                    to_hex(&s.root_hash),
                    s.timestamp_ms
                ));
            }
        }
        out.push(format!("  key set {}", to_hex(&self.key_set_digest())));
        out.push(format!(
            "  signatures: {}{}",
            self.sigs().sigs().len(),
            if self.is_draft() { " (draft)" } else { "" }
        ));
        out
    }
}

fn entry_line(e: &Entry) -> String {
    let what = match e.kind {
        EntryKind::ReleaseFloor => format!("builds below {}", e.release_floor().unwrap_or(0)),
        EntryKind::Notice => format!(
            "\"{}\"",
            sanitize_terminal_line(e.notice_text().unwrap_or(""))
        ),
        EntryKind::KeySet => e.key_set().map_or_else(
            || "next key set (unreadable)".into(),
            |k| {
                format!(
                    "next key set {} ({} of {})",
                    to_hex(&k.digest()),
                    k.threshold(),
                    k.keys().len()
                )
            },
        ),
        _ => e.target.clone(),
    };
    format!(
        "{} {} {} (text {})",
        e.kind.name(),
        e.severity.name(),
        what,
        e.text_id
    )
}

fn read_capped(path: &Path, cap: u64) -> Result<Vec<u8>, SignError> {
    let meta = fs::metadata(path).map_err(|e| io(path, "cannot read", e))?;
    if !meta.is_file() {
        return Err(SignError::Io(format!("{} is not a file", path.display())));
    }
    if meta.len() > cap {
        return Err(SignError::Io(format!(
            "{} is larger than {cap} bytes",
            path.display()
        )));
    }
    fs::read(path).map_err(|e| io(path, "cannot read", e))
}

/// A key set file: its bytes, or their hex on one line.
pub fn read_key_set(path: &Path) -> Result<KeySet, SignError> {
    let bytes = read_capped(path, 4_096)?;
    crate::update_state::parse_key_set_file(&bytes)
        .ok_or_else(|| SignError::Spec(format!("{} is not a release key set", path.display())))
}

fn check_key_set(artifact: &Artifact, key_set: &KeySet) -> Result<(), SignError> {
    if artifact.key_set_digest() != key_set.digest() {
        return Err(SignError::WrongKeySet {
            artifact: to_hex(&artifact.key_set_digest()),
            given: to_hex(&key_set.digest()),
        });
    }
    Ok(())
}

// ── Detached signatures ─────────────────────────────────────────────

/// One key's signature over one draft (see the module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetachedSig {
    pub kind: ArtifactKind,
    pub key_index: u8,
    /// `SHA-256(signing input)` of the draft it signs.
    pub signed_hash: [u8; 32],
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

impl DetachedSig {
    /// The file's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIG_FILE_LEN);
        out.extend_from_slice(SIG_FILE_MAGIC);
        out.extend([FILE_VERSION, self.kind.byte(), self.key_index, 0]);
        out.extend(self.signed_hash);
        out.extend(self.public_key);
        out.extend(self.signature);
        out
    }

    /// Strict decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, SignError> {
        if bytes.len() != SIG_FILE_LEN {
            return Err(SignError::BadSigFile("wrong length"));
        }
        if &bytes[..8] != SIG_FILE_MAGIC {
            return Err(SignError::BadSigFile("wrong magic"));
        }
        if bytes[8] != FILE_VERSION {
            return Err(SignError::BadSigFile("unsupported version"));
        }
        let kind =
            ArtifactKind::from_byte(bytes[9]).ok_or(SignError::BadSigFile("unknown kind"))?;
        if bytes[11] != 0 {
            return Err(SignError::BadSigFile("reserved byte set"));
        }
        Ok(Self {
            kind,
            key_index: bytes[10],
            signed_hash: bytes[12..44].try_into().expect("32 bytes"),
            public_key: bytes[44..76].try_into().expect("32 bytes"),
            signature: bytes[76..140].try_into().expect("64 bytes"),
        })
    }

    /// Read and decode.
    pub fn read(path: &Path) -> Result<Self, SignError> {
        Self::decode(&read_capped(path, SIG_FILE_LEN as u64)?).map_err(|e| match e {
            SignError::BadSigFile(why) => {
                SignError::Signature(format!("{}: not a signature file ({why})", path.display()))
            }
            other => other,
        })
    }
}

/// Sign `artifact` with one key of `key_set` (the run's only key): the
/// artifact must name `key_set`, and the key must be one of its keys.
pub fn sign_detached(
    artifact: &Artifact,
    key_set: &KeySet,
    signer: &Identity,
) -> Result<DetachedSig, SignError> {
    check_key_set(artifact, key_set)?;
    let public_key = signer.public_key_bytes();
    let key_index = key_set
        .keys()
        .iter()
        .position(|k| *k == public_key)
        .ok_or_else(|| SignError::KeyNotInSet(to_hex(&public_key)))?;
    let input = artifact.signing_input();
    Ok(DetachedSig {
        kind: artifact.kind(),
        key_index: u8::try_from(key_index).expect("at most 8 keys"),
        signed_hash: Sha256::digest(&input).into(),
        public_key,
        signature: signer.sign(&input),
    })
}

/// The signed artifact: `draft`'s content with the signatures it already
/// carries and `sigs`, each checked (made for this draft, by the key at its
/// index, valid), one per key, in key order, exactly the threshold.
pub fn combine(
    draft: &Artifact,
    key_set: &KeySet,
    sigs: &[DetachedSig],
) -> Result<Artifact, SignError> {
    check_key_set(draft, key_set)?;
    let input = draft.signing_input();
    let hash: [u8; 32] = Sha256::digest(&input).into();
    let mut all: Vec<(u8, [u8; 64])> = draft.sigs().sigs().to_vec();
    for s in sigs {
        if s.kind != draft.kind() {
            return Err(SignError::Signature(format!(
                "a signature of a {} cannot sign a {}",
                s.kind.name(),
                draft.kind().name()
            )));
        }
        if s.signed_hash != hash {
            return Err(SignError::Signature(format!(
                "the signature by key {} is for another draft (it signed {}, this draft is {})",
                s.key_index,
                to_hex(&s.signed_hash),
                to_hex(&hash)
            )));
        }
        if key_set.keys().get(usize::from(s.key_index)) != Some(&s.public_key) {
            return Err(SignError::Signature(format!(
                "key index {} of the key set is not the key that made this signature",
                s.key_index
            )));
        }
        all.push((s.key_index, s.signature));
    }
    all.sort_by_key(|(i, _)| *i);
    if all.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(SignError::Combine(
            "two signatures by one key: each key signs once".into(),
        ));
    }
    for (i, sig) in &all {
        if !Identity::verify(&key_set.keys()[usize::from(*i)], &input, sig) {
            return Err(SignError::Signature(format!(
                "the signature by key {i} does not verify"
            )));
        }
    }
    if all.len() < usize::from(key_set.threshold()) {
        return Err(SignError::Combine(format!(
            "{} signatures; this key set needs {}",
            all.len(),
            key_set.threshold()
        )));
    }
    // Exactly the threshold (Phase 6 review updates-protocol-1): anyone can
    // drop a signature from a larger block, which changes the artifact's
    // bytes and digest, so every copy of a signed artifact carries the
    // same block.
    if all.len() > usize::from(key_set.threshold()) {
        return Err(SignError::Combine(format!(
            "{} signatures; this key set takes exactly {}: combine only that many, so every \
             copy has the same bytes",
            all.len(),
            key_set.threshold()
        )));
    }
    let signed = draft.with_sigs(&SigBlock::new(all))?;
    signed
        .verify(key_set)
        .map_err(|e| SignError::Combine(format!("the combined artifact does not verify: {e}")))?;
    Ok(signed)
}

// ── Building drafts ─────────────────────────────────────────────────

/// One file of a release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseFile {
    /// `bin/<name>` (a program, 0755) or `docs/<name>` (0644).
    pub path: String,
    /// The shipped bytes (after platform signing, if any).
    pub bytes: Vec<u8>,
    /// SHA-256 of the file a reproducible build makes (before platform
    /// signing).
    pub rebuild_sha256: [u8; 32],
}

/// What a release manifest says, besides its files' hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestSpec {
    pub build_serial: u64,
    pub created_at_ms: u64,
    pub version: String,
    pub target: String,
    pub source_commit: [u8; SOURCE_COMMIT_LEN],
    pub toolchain: String,
    pub min_advisory_serial: u64,
    pub notes: String,
    pub files: Vec<ReleaseFile>,
}

/// The manifest draft of `spec` under `key_set`, checked by the RRB1
/// decoder (paths, sizes, lengths).
pub fn manifest_draft(spec: &ManifestSpec, key_set: &KeySet) -> Result<Artifact, SignError> {
    let mut draft = ManifestDraft {
        build_serial: spec.build_serial,
        created_at_ms: spec.created_at_ms,
        key_set_digest: key_set.digest(),
        version: spec.version.clone(),
        target: spec.target.clone(),
        source_commit: spec.source_commit,
        toolchain: spec.toolchain.clone(),
        min_advisory_serial: spec.min_advisory_serial,
        chunk_size: 0,
        payload_len: 0,
        payload_chunk_root: [0; 32],
        payload_sha256: [0; 32],
        files: Vec::new(),
        notes: spec.notes.clone(),
    };
    let files: Vec<PackFile<'_>> = spec
        .files
        .iter()
        .map(|f| PackFile {
            path: &f.path,
            mode: if f.path.starts_with("bin/") {
                FileMode::Executable
            } else {
                FileMode::Regular
            },
            bytes: &f.bytes,
            rebuild_sha256: f.rebuild_sha256,
        })
        .collect();
    draft.fill_payload(&files);
    draft
        .assemble(&SigBlock::default())
        .map(Artifact::Manifest)
        .map_err(|e| SignError::Spec(format!("the manifest is refused: {e}")))
}

/// An advisory description (JSON): the whole current list of entries
/// (an advisory is cumulative).
///
/// ```json
/// {"serial": 2, "issued_at_ms": 1792713600000, "entries": [
///   {"kind": "SUITE_STATUS", "target": "pairinit/1/1", "severity": "DEPRECATED"},
///   {"kind": "RELEASE_FLOOR", "min_build_serial": 12},
///   {"kind": "FEATURE_HOLD", "target": "feature/link-knock", "severity": "BROKEN"},
///   {"kind": "NOTICE", "text": "Update Raven when you can."},
///   {"kind": "KEY_SET", "key_set_hex": "0102..."}
/// ]}
/// ```
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisorySpec {
    pub serial: u64,
    pub issued_at_ms: u64,
    pub entries: Vec<EntrySpec>,
}

/// One entry of an [`AdvisorySpec`]; `text_id` defaults to 0 and the
/// severity of the last three kinds to INFO.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum EntrySpec {
    SuiteStatus {
        target: String,
        severity: SeveritySpec,
        #[serde(default)]
        text_id: u16,
        /// Set to say it is meant: this BROKEN entry closes the update
        /// exchange ([`closes_notices`]).
        #[serde(default)]
        stops_notices: bool,
    },
    ReleaseFloor {
        min_build_serial: u64,
        #[serde(default)]
        severity: SeveritySpec,
        #[serde(default)]
        text_id: u16,
    },
    FeatureHold {
        target: String,
        severity: SeveritySpec,
        #[serde(default)]
        text_id: u16,
        /// Set to say it is meant: this BROKEN hold closes the update
        /// exchange ([`closes_notices`]).
        #[serde(default)]
        stops_notices: bool,
    },
    Notice {
        text: String,
        #[serde(default)]
        severity: SeveritySpec,
        #[serde(default)]
        text_id: u16,
    },
    KeySet {
        key_set_hex: String,
        #[serde(default)]
        severity: SeveritySpec,
        #[serde(default)]
        text_id: u16,
    },
}

/// A severity name.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SeveritySpec {
    #[default]
    Info,
    Deprecated,
    Broken,
}

impl From<SeveritySpec> for Severity {
    fn from(s: SeveritySpec) -> Self {
        match s {
            SeveritySpec::Info => Severity::Info,
            SeveritySpec::Deprecated => Severity::Deprecated,
            SeveritySpec::Broken => Severity::Broken,
        }
    }
}

/// Does a BROKEN entry of `kind` on `target` close the update exchange
/// itself (`feature/mesh-update`, or a module suite of its gate such as
/// `rup1/1`)? Then no notice passes between friends any more, this one's
/// successors included, until a new build or a file import (Phase 6 review
/// updates-protocol-4); a hold on release bundles leaves notices passing.
pub fn closes_notices(kind: EntryKind, target: &str) -> bool {
    const GATE: &str = "MESH_UPDATE_PRODUCTION_ENABLED";
    match kind {
        EntryKind::FeatureHold => suite_registry::feature(target).is_some_and(|f| f.gate == GATE),
        EntryKind::SuiteStatus => suite_registry::suite(target)
            .is_some_and(|s| s.layer == suite_registry::Layer::Module && s.gate == Some(GATE)),
        _ => false,
    }
}

/// Refuse an entry that would stop notices between friends unless its
/// description says so (`"stops_notices": true`).
fn check_notices_kept(
    kind: EntryKind,
    target: &str,
    severity: SeveritySpec,
    stops_notices: bool,
) -> Result<(), SignError> {
    if severity == SeveritySpec::Broken && closes_notices(kind, target) && !stops_notices {
        return Err(SignError::Spec(format!(
            "{} {target} BROKEN closes the update exchange: no notice passes between friends \
             any more, the one that lifts it included, so only a new build or a file import \
             lifts it. Add \"stops_notices\": true to the entry if that is meant (a hold on \
             feature/release-bundle stops only bundles)",
            kind.name()
        )));
    }
    Ok(())
}

/// What the new advisory follows.
#[derive(Clone, Copy, Debug)]
pub enum Previous<'a> {
    /// Nothing: the first advisory (serial 1).
    None,
    /// The advisory one serial lower, signed.
    Advisory(&'a Advisory),
    /// Its digest, when the file is not at hand.
    Digest([u8; 32]),
}

impl EntrySpec {
    fn entry(&self) -> Result<Entry, SignError> {
        let (kind, severity, target, arg, text_id) = match self {
            Self::SuiteStatus {
                target,
                severity,
                text_id,
                stops_notices,
            } => {
                check_notices_kept(EntryKind::SuiteStatus, target, *severity, *stops_notices)?;
                if suite_registry::suite(target).is_none() {
                    return Err(SignError::Spec(format!(
                        "SUITE_STATUS {target}: not a suite this build registers (it would never be \
                         enforced; build raven-release from the commit that registers it)"
                    )));
                }
                (
                    EntryKind::SuiteStatus,
                    *severity,
                    target.clone(),
                    Vec::new(),
                    *text_id,
                )
            }
            Self::ReleaseFloor {
                min_build_serial,
                severity,
                text_id,
            } => (
                EntryKind::ReleaseFloor,
                *severity,
                RELEASE_FLOOR_TARGET.to_owned(),
                min_build_serial.to_be_bytes().to_vec(),
                *text_id,
            ),
            Self::FeatureHold {
                target,
                severity,
                text_id,
                stops_notices,
            } => {
                check_notices_kept(EntryKind::FeatureHold, target, *severity, *stops_notices)?;
                if !target.starts_with(FEATURE_PREFIX)
                    || !suite_registry::feature(target).is_some_and(|f| f.holdable())
                {
                    return Err(SignError::Spec(format!(
                        "FEATURE_HOLD {target}: not a feature a hold can close in this build"
                    )));
                }
                (
                    EntryKind::FeatureHold,
                    *severity,
                    target.clone(),
                    Vec::new(),
                    *text_id,
                )
            }
            Self::Notice {
                text,
                severity,
                text_id,
            } => (
                EntryKind::Notice,
                *severity,
                NOTICE_TARGET.to_owned(),
                text.as_bytes().to_vec(),
                *text_id,
            ),
            Self::KeySet {
                key_set_hex,
                severity,
                text_id,
            } => {
                let raw = hex::decode(key_set_hex.trim())
                    .map_err(|_| SignError::Spec("KEY_SET: key_set_hex is not hex".into()))?;
                let next = KeySet::decode(&raw)
                    .map_err(|e| SignError::Spec(format!("KEY_SET: not a key set ({e})")))?;
                if !cfg!(debug_assertions) && next.keys().iter().any(is_test_key) {
                    return Err(SignError::TestOnly("key sets with a published test key"));
                }
                (
                    EntryKind::KeySet,
                    *severity,
                    KEY_SET_TARGET.to_owned(),
                    raw,
                    *text_id,
                )
            }
        };
        Ok(Entry {
            kind,
            severity: severity.into(),
            target,
            arg,
            text_id,
        })
    }
}

/// The advisory draft of `spec` (JSON, [`AdvisorySpec`]) under `key_set`,
/// following `previous`: serial 1 follows nothing, any other serial the
/// signed advisory one serial lower (or its digest).
pub fn advisory_draft(
    spec_json: &[u8],
    key_set: &KeySet,
    previous: Previous<'_>,
) -> Result<Artifact, SignError> {
    let spec: AdvisorySpec = serde_json::from_slice(spec_json)
        .map_err(|e| SignError::Spec(format!("advisory description: {e}")))?;
    let prev_digest = match (spec.serial, previous) {
        (0, _) => return Err(SignError::Spec("an advisory serial starts at 1".into())),
        (1, Previous::None) => [0; 32],
        (1, _) => {
            return Err(SignError::Spec(
                "advisory 1 follows nothing: leave out the previous advisory".into(),
            ))
        }
        (_, Previous::None) => {
            return Err(SignError::Spec(format!(
                "advisory {} follows advisory {}: give that one (or its digest)",
                spec.serial,
                spec.serial - 1
            )))
        }
        (serial, Previous::Advisory(prev)) => {
            if prev.serial + 1 != serial {
                return Err(SignError::Spec(format!(
                    "the previous advisory is #{}, so this one is #{}, not #{serial}",
                    prev.serial,
                    prev.serial + 1
                )));
            }
            if prev.sigs().sigs().is_empty() {
                return Err(SignError::Spec(
                    "the previous advisory is a draft: give the signed one".into(),
                ));
            }
            prev.digest()
        }
        (_, Previous::Digest(d)) if d == [0; 32] => {
            return Err(SignError::Spec(
                "a previous digest is never all zero".into(),
            ))
        }
        (_, Previous::Digest(d)) => d,
    };
    let entries = spec
        .entries
        .iter()
        .map(EntrySpec::entry)
        .collect::<Result<Vec<_>, _>>()?;
    AdvisoryDraft {
        serial: spec.serial,
        issued_at_ms: spec.issued_at_ms,
        key_set_digest: key_set.digest(),
        prev_digest,
        entries,
    }
    .assemble(&SigBlock::default())
    .map(Artifact::Advisory)
    .map_err(|e| SignError::Spec(format!("the advisory is refused: {e}")))
}

// ── The log kit ─────────────────────────────────────────────────────

/// The entries of `entries.bin`: whole 41-byte entries, at most 1,400.
pub fn decode_entries(bytes: &[u8]) -> Result<Vec<LogEntry>, SignError> {
    if !bytes.len().is_multiple_of(ENTRY_LEN) {
        return Err(SignError::Log(format!(
            "{LOG_ENTRIES} is {} bytes, not whole {ENTRY_LEN}-byte entries",
            bytes.len()
        )));
    }
    if bytes.len() / ENTRY_LEN > MAX_LOG_ENTRIES {
        return Err(SignError::Log(format!(
            "{LOG_ENTRIES} has more than {MAX_LOG_ENTRIES} entries"
        )));
    }
    bytes
        .chunks(ENTRY_LEN)
        .map(|c| LogEntry::decode(c).map_err(|e| SignError::Log(format!("{LOG_ENTRIES}: {e}"))))
        .collect()
}

/// `entries.bin`'s bytes.
pub fn encode_entries(entries: &[LogEntry]) -> Vec<u8> {
    entries.iter().flat_map(|e| e.encode()).collect()
}

/// Write `bytes` to `path` through a temporary file in the same folder,
/// synced, then renamed over it.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), SignError> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file")
    ));
    let mut f = fs::File::create(&tmp).map_err(|e| io(&tmp, "cannot write", e))?;
    f.write_all(bytes)
        .map_err(|e| io(&tmp, "cannot write", e))?;
    f.sync_all().map_err(|e| io(&tmp, "cannot sync", e))?;
    drop(f);
    fs::rename(&tmp, path).map_err(|e| io(path, "cannot replace", e))
}

/// Write a new file (never over another one); the same bytes already there
/// are fine.
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<(), SignError> {
    if let Ok(existing) = fs::read(path) {
        if existing == bytes {
            return Ok(());
        }
        return Err(SignError::Io(format!(
            "{} already exists with other contents: move it away first",
            path.display()
        )));
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| io(path, "cannot create", e))?;
    f.write_all(bytes)
        .map_err(|e| io(path, "cannot write", e))?;
    f.sync_all().map_err(|e| io(path, "cannot sync", e))
}

/// The release log folder (see the module docs).
#[derive(Clone, Debug)]
pub struct ReleaseLog {
    dir: PathBuf,
    entries: Vec<LogEntry>,
}

impl ReleaseLog {
    /// Open the folder `dir` (it must exist; a folder without
    /// `entries.bin` is an empty log).
    pub fn open(dir: &Path) -> Result<Self, SignError> {
        if !dir.is_dir() {
            return Err(SignError::Log(format!("{} is not a folder", dir.display())));
        }
        let path = dir.join(LOG_ENTRIES);
        let entries = match fs::read(&path) {
            Ok(bytes) => decode_entries(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(io(&path, "cannot read", e)),
        };
        Ok(Self {
            dir: dir.to_owned(),
            entries,
        })
    }

    /// The folder.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The entries, oldest first.
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// May `entry` be appended: room left, not listed yet, not logged
    /// before the newest entry? Checked before anything is written.
    fn admit(&self, entry: &LogEntry) -> Result<(), SignError> {
        if self.entries.len() >= MAX_LOG_ENTRIES {
            return Err(SignError::Log(format!(
                "the log holds {MAX_LOG_ENTRIES} entries, the most RTL1 v1 carries: \
                 RTL2 (with proofs) must ship first"
            )));
        }
        if self
            .entries
            .iter()
            .any(|e| e.kind == entry.kind && e.digest == entry.digest)
        {
            return Err(SignError::Log(format!(
                "the log already lists this {} ({})",
                entry.kind.name(),
                to_hex(&entry.digest)
            )));
        }
        if let Some(last) = self.entries.last() {
            if entry.logged_at_ms < last.logged_at_ms {
                return Err(SignError::Log(format!(
                    "logged at {} ms, before the newest entry ({} ms)",
                    entry.logged_at_ms, last.logged_at_ms
                )));
            }
        }
        Ok(())
    }

    /// Append an admitted entry and rewrite `entries.bin`.
    fn push(&mut self, entry: LogEntry) -> Result<(), SignError> {
        self.admit(&entry)?;
        self.entries.push(entry);
        write_atomic(&self.dir.join(LOG_ENTRIES), &encode_entries(&self.entries))
    }

    /// Append a signed manifest or advisory (checked against `key_set`),
    /// logged at `logged_at_ms`, and publish its file in the folder.
    /// Returns the entry and the published file.
    pub fn append_artifact(
        &mut self,
        artifact: &Artifact,
        key_set: &KeySet,
        logged_at_ms: u64,
    ) -> Result<(LogEntry, PathBuf), SignError> {
        let (kind, digest) = artifact.log_name().ok_or_else(|| {
            SignError::Log("a tree head is not listed in the log: sign it with `sth`".into())
        })?;
        if artifact.is_draft() {
            return Err(SignError::Log(
                "this is a draft: combine its signatures first".into(),
            ));
        }
        artifact
            .verify(key_set)
            .map_err(|e| SignError::Log(format!("not signed by this key set: {e}")))?;
        let published = match artifact {
            Artifact::Manifest(m) => self
                .dir
                .join(LOG_MANIFESTS)
                .join(format!("{}-{}.rrb1", m.build_serial, m.target)),
            Artifact::Advisory(a) => self
                .dir
                .join(LOG_ADVISORIES)
                .join(format!("{}.rad1", a.serial)),
            Artifact::TreeHead(_) => unreachable!("not listed"),
        };
        let entry = LogEntry {
            kind,
            digest,
            logged_at_ms,
        };
        self.admit(&entry)?;
        let folder = published.parent().expect("a folder");
        fs::create_dir_all(folder).map_err(|e| io(folder, "cannot create", e))?;
        write_new(&published, artifact.bytes())?;
        self.push(entry)?;
        Ok((entry, published))
    }

    /// Append the next key set (named by a KEY_SET entry of an advisory),
    /// and publish it as `keysets/<digest>.keyset`.
    pub fn append_key_set(
        &mut self,
        next: &KeySet,
        logged_at_ms: u64,
    ) -> Result<(LogEntry, PathBuf), SignError> {
        let digest = next.digest();
        let entry = LogEntry {
            kind: EntryType::KeySet,
            digest,
            logged_at_ms,
        };
        self.admit(&entry)?;
        let folder = self.dir.join(LOG_KEY_SETS);
        fs::create_dir_all(&folder).map_err(|e| io(&folder, "cannot create", e))?;
        let published = folder.join(format!("{}.keyset", to_hex(&digest)));
        write_new(&published, &next.encode())?;
        self.push(entry)?;
        Ok((entry, published))
    }

    /// The tree head draft of the whole log under `key_set`.
    pub fn tree_head_draft(
        &self,
        key_set: &KeySet,
        timestamp_ms: u64,
    ) -> Result<Artifact, SignError> {
        if self.entries.is_empty() {
            return Err(SignError::Log(
                "the log is empty: append something first".into(),
            ));
        }
        SthDraft::of_entries(&self.entries, timestamp_ms, key_set.digest())
            .assemble(&SigBlock::default())
            .map(Artifact::TreeHead)
            .map_err(|e| SignError::Log(e.to_string()))
    }

    /// Where the signed tree head of `size` entries is kept.
    pub fn tree_head_path(&self, size: u64) -> PathBuf {
        self.dir.join(LOG_TREE_HEADS).join(format!("{size}.rtl1"))
    }

    /// Keep a signed tree head as `sth/<size>.rtl1`: signed by `key_set`,
    /// and its root that of the log's first `size` entries.
    pub fn store_tree_head(&self, sth: &Sth, key_set: &KeySet) -> Result<PathBuf, SignError> {
        self.check_tree_head(sth, key_set)?;
        let path = self.tree_head_path(sth.tree_size);
        let folder = path.parent().expect("a folder");
        fs::create_dir_all(folder).map_err(|e| io(folder, "cannot create", e))?;
        write_new(&path, sth.bytes())?;
        Ok(path)
    }

    fn check_tree_head(&self, sth: &Sth, key_set: &KeySet) -> Result<(), SignError> {
        sth.verify(key_set).map_err(|e| {
            SignError::Log(format!("the tree head is not signed by this key set: {e}"))
        })?;
        let size = usize::try_from(sth.tree_size).unwrap_or(usize::MAX);
        let entries = self.entries.get(..size).ok_or_else(|| {
            SignError::Log(format!(
                "the tree head has {} entries, the log {}",
                sth.tree_size,
                self.entries.len()
            ))
        })?;
        if crate::tlog::mth(entries) != sth.root_hash {
            return Err(SignError::Log(format!(
                "the tree head's root is not that of the log's first {} entries",
                sth.tree_size
            )));
        }
        Ok(())
    }

    /// The snapshot of the whole log: its entries and `sth/<size>.rtl1`,
    /// checked against `key_set`.
    pub fn snapshot(&self, key_set: &KeySet) -> Result<Snapshot, SignError> {
        let size = self.entries.len() as u64;
        let path = self.tree_head_path(size);
        let bytes = fs::read(&path).map_err(|_| {
            SignError::Log(format!(
                "no signed tree head for the log's {size} entries ({}): run `sth`, sign it and \
                 combine it into the log",
                path.display()
            ))
        })?;
        let sth =
            Sth::decode(&bytes).map_err(|e| SignError::Log(format!("{}: {e}", path.display())))?;
        if sth.tree_size != size {
            return Err(SignError::Log(format!(
                "{} is a tree head of {} entries",
                path.display(),
                sth.tree_size
            )));
        }
        self.check_tree_head(&sth, key_set)?;
        let snapshot =
            Snapshot::new(self.entries.clone(), sth).map_err(|e| SignError::Log(e.to_string()))?;
        snapshot
            .check(key_set)
            .map_err(|e| SignError::Log(e.to_string()))?;
        Ok(snapshot)
    }

    /// Write the snapshot of the whole log as `snapshot.rtl1`.
    pub fn write_snapshot(&self, key_set: &KeySet) -> Result<PathBuf, SignError> {
        let snapshot = self.snapshot(key_set)?;
        let path = self.dir.join(LOG_SNAPSHOT);
        write_atomic(&path, &snapshot.encode())?;
        Ok(path)
    }
}

// ── Packing ─────────────────────────────────────────────────────────

/// Read the files of `manifest` from `files_dir` (`<dir>/bin/...`,
/// `<dir>/docs/...`: regular files of exactly the listed sizes).
pub fn read_payload(manifest: &Manifest, files_dir: &Path) -> Result<Vec<u8>, SignError> {
    let mut payload = Vec::with_capacity(usize::try_from(manifest.payload_len).unwrap_or(0));
    for f in &manifest.files {
        let path = files_dir.join(&f.path);
        let meta = fs::symlink_metadata(&path).map_err(|e| io(&path, "cannot read", e))?;
        if !meta.is_file() {
            return Err(SignError::Bundle(format!(
                "{} is not a regular file",
                path.display()
            )));
        }
        if meta.len() != f.size {
            return Err(SignError::Bundle(format!(
                "{} has {} bytes; the manifest says {}",
                path.display(),
                meta.len(),
                f.size
            )));
        }
        payload.extend(fs::read(&path).map_err(|e| io(&path, "cannot read", e))?);
    }
    Ok(payload)
}

/// The `.rrb` container of a signed manifest, the log snapshot that lists
/// it, the optional advisory and the payload: the same bytes for the same
/// pieces. It is opened again and verified ([`verify_bundle`], for the
/// manifest's own target, as a first install) before it is returned.
pub fn pack(
    key_set: &KeySet,
    manifest: &Manifest,
    snapshot: &Snapshot,
    advisory: Option<&Advisory>,
    payload: Vec<u8>,
) -> Result<Vec<u8>, SignError> {
    let bytes = Parts {
        manifest: manifest.clone(),
        snapshot: snapshot.clone(),
        advisory: advisory.cloned(),
        payload,
    }
    .encode();
    let parts = Container::open(&bytes[..]).map_err(|e| SignError::Bundle(e.to_string()))?;
    verify_bundle(
        &parts,
        &VerifyCtx {
            key_set: Some(key_set),
            stored_log: &[],
            installed_serial: 0,
            target: &manifest.target,
            release_floor: 0,
            allow_downgrade: false,
        },
    )
    .map_err(|e| SignError::Bundle(format!("the bundle would be refused: {e}")))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests;
