//! The learning store (design "Phase 6a", data model "LRN1"): the model in
//! one file, `learning.bin`, sealed from its first write as RMS1 of kind 22
//! ([`Kind::LearningStore`]) under the profile's at-rest key K_meta
//! (`docs/design/2026-10-at-rest-metadata.md`, section 6.1). Learning never
//! writes it in clear: a profile that is not sealed keeps the model in
//! memory only, and `raven privacy unseal` deletes the file
//! (`privacy::unseal_all`) instead of writing it back in plain.
//!
//! - **Plaintext.** [`MAGIC`], then compact JSON
//!   `{"v":1,"secret":<hex32>,"arms":[..],"relays":[..],"enc":[..],"carry":[..]}`.
//!   Every row is an array keyed only by the model's HMAC keys (the row
//!   layouts below): no public key, network tag, address, PeerId or name,
//!   and no time-of-day field. Every time is rounded down to the hour on
//!   save. The secret exists only in this file: an empty model draws it from
//!   the OS and its first save writes it.
//! - **Writer.** raven-node (P6.11); `raven learning reset|off --forget`
//!   (P6.17) only while no raven-node answers for the profile, or one that
//!   holds learning or is older (its learning never loads the file).
//!   [`save`] seals outside the file's lock and takes [`LEARNING_LOCK`] (at
//!   most [`LOCK_WAIT`]) only for the rename
//!   ([`crate::paths::atomic_write_private`], 0600); [`load`] takes it only
//!   to read the bytes and opens them after; [`delete`] removes the file
//!   under it. [`PlatformSealer`] never calls the keystore: it uses the keys
//!   this process loaded at its start ([`at_rest::keys_cached`]).
//! - **Load outcomes** ([`StoreState`]): no file is an empty model, on. A
//!   key that is not here (not loaded, a profile that is not sealed, the
//!   debug hook [`crate::lan_gate::lab_sealer_unavailable`]; with no file
//!   to open, the sealer is asked to seal a few bytes) or an I/O error is
//!   memory-only: nothing is written. A file a newer Raven wrote (RMS1 or
//!   LRN1 version) is memory-only too, and never overwritten. A file that
//!   does not open or parse, or that is refused by its metadata (a symlink,
//!   more than one link, not 0600, over [`MAX_FILE`]), is an empty model,
//!   reset after unreadable, overwritten by the next save (advisory data,
//!   like `route_memory.json`).
//! - **Validation.** A row that does not decode (a key of the wrong length,
//!   an unknown or unranked carrier, an encounter never met) is dropped;
//!   times after `now` become `now`, an encounter's `p` is at most 1.0 and
//!   an RTT's backoff at most [`MAX_BACKOFF`]. Then [`Model::prune`]
//!   (retention and the caps) and [`Beta::sanitize`] for every row.
//! - **Not kept.** The orders last applied, the contradiction pins and the
//!   counters stay in memory (`learning::model`).
//!
//! Row layouts (each a JSON array, in this order):
//! - arm: `[c, n, carrier, beta, ok_ms, fail_ms, connect, reply, paths,
//!   last_obs_ms, last_receipt_ms, last_probe_ms, recent, recent_n]`;
//! - relay: `[r, beta, ok_ms]`;
//! - encounter: `[c, p_q16, at_ms, last_ms]`;
//! - carry: `[c_custodian, c_recipient, beta]`;
//! - beta: `[a_m, b_m, at_ms, streak]`; RTT: `[srtt_ms, rttvar_ms, n,
//!   backoff, at_ms]`; `c`, `r` are 16-byte and `n` 8-byte keys in hex.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
/// What [`Sealer::unprotect`] returns (re-exported for sealers outside this
/// crate, such as raven-node's tests).
pub use zeroize::Zeroizing;

use super::estimate::{Beta, Encounter, Rtt, MAX_BACKOFF, Q16_ONE};
use super::explain::State;
use super::model::{carrier_code, carrier_of, Arm, CarryRow, Model, RelayRow, RECENT_MAX};
use crate::at_rest::{self, AtRestError, Kind, MetaKeys, Mode};
use crate::outbox::OutboxCarrier;
use crate::paths::DataDirLock;

/// The file in the data dir (registered in [`at_rest::FILES`]).
pub const LEARNING_FILE: &str = "learning.bin";
/// Its writer lock (the one [`at_rest::FILES`] names for it).
pub const LEARNING_LOCK: &str = ".learning.lock.sqlite";
/// The first bytes of the plaintext.
pub const MAGIC: &[u8; 8] = b"RVNLRN01";
/// The file on disk is at most this long; a longer one is refused, and a
/// save that would write one fails.
pub const MAX_FILE: u64 = 512 * 1024;
/// How long [`load`], [`save`] and [`delete`] wait for [`LEARNING_LOCK`].
pub const LOCK_WAIT: Duration = Duration::from_secs(2);
/// The plaintext's format version (`v`).
pub const VERSION: u32 = 1;

/// Times are rounded down to this on save.
const HOUR_MS: u64 = 3_600_000;

/// What [`load`] found, and so what may be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreState {
    /// Read (or no file yet): saved as usual.
    On,
    /// Nothing is written while this process runs; the reason is a fixed
    /// token: `keystore` (the key is not here), `newer` (a newer Raven
    /// wrote the file) or `io` (the file or its lock could not be read).
    MemoryOnly(&'static str),
    /// The file could not be read: an empty model, overwritten on the next
    /// save.
    ResetAfterUnreadable,
    /// Learning watches without changing anything (the caller's mode; never
    /// a load outcome).
    Shadow,
}

impl StoreState {
    /// The state as the reason and `raven learning status` name it.
    pub fn state(self) -> State {
        match self {
            StoreState::On => State::On,
            StoreState::MemoryOnly(_) => State::MemoryOnly,
            StoreState::ResetAfterUnreadable => State::ResetAfterUnreadable,
            StoreState::Shadow => State::Shadow,
        }
    }
}

/// Why sealing or opening failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealError {
    /// The key is not here: not loaded in this process, gone from the
    /// keystore, an epoch this process has not loaded, a profile that is not
    /// sealed, or the debug hook. Nothing is written.
    Unavailable,
    /// Not a sealed file this build can read (too short).
    Corrupt,
    /// Authentication failed: a changed byte, another profile's key, another
    /// kind, not sealed at all.
    AuthFailed,
    /// A newer Raven sealed it.
    Newer,
    Other(String),
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealError::Unavailable => f.write_str("the at-rest key is unavailable"),
            SealError::Corrupt => f.write_str("the file is corrupt"),
            SealError::AuthFailed => f.write_str("the file failed authentication"),
            SealError::Newer => f.write_str("a newer Raven wrote the file"),
            SealError::Other(text) => f.write_str(text),
        }
    }
}

impl From<AtRestError> for SealError {
    fn from(e: AtRestError) -> Self {
        match e {
            AtRestError::KeyUnavailable(_)
            | AtRestError::KeyLost(_)
            | AtRestError::NoIdentity
            | AtRestError::NotSealedMode
            | AtRestError::StaleKeys { .. } => SealError::Unavailable,
            AtRestError::Tampered { .. } | AtRestError::WrongKind { .. } => SealError::AuthFailed,
            AtRestError::Truncated => SealError::Corrupt,
            AtRestError::NewerFormat(_) => SealError::Newer,
            AtRestError::Io(text) | AtRestError::Json(text) => SealError::Other(text),
        }
    }
}

/// Seals and opens the plaintext; [`PlatformSealer`] outside tests.
pub trait Sealer {
    fn protect(&self, dd: &Path, pt: &[u8]) -> Result<Vec<u8>, SealError>;
    fn unprotect(&self, dd: &Path, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError>;
}

/// RMS1 of [`Kind::LearningStore`] under the keys this process loaded
/// ([`at_rest::seal`], [`at_rest::open`]); no keystore call. It seals only
/// in a sealed profile (writers follow the profile's mode, and learning
/// never writes in clear).
pub struct PlatformSealer;

impl PlatformSealer {
    /// The cached keys; `fault` is the debug hook's answer.
    fn keys(dd: &Path, fault: bool) -> Result<Arc<MetaKeys>, SealError> {
        if fault {
            return Err(SealError::Unavailable);
        }
        Ok(at_rest::keys_cached(dd)?)
    }
}

impl Sealer for PlatformSealer {
    fn protect(&self, dd: &Path, pt: &[u8]) -> Result<Vec<u8>, SealError> {
        if crate::privacy::mode(dd) != Mode::Sealed {
            return Err(SealError::Unavailable);
        }
        let keys = Self::keys(dd, crate::lan_gate::lab_sealer_unavailable())?;
        Ok(at_rest::seal(&keys, Kind::LearningStore, pt))
    }

    fn unprotect(&self, dd: &Path, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
        let keys = Self::keys(dd, crate::lan_gate::lab_sealer_unavailable())?;
        Ok(at_rest::open(&keys, Kind::LearningStore, ct)?)
    }
}

// ── The plaintext ────────────────────────────────────────────────────────

/// `[a_m, b_m, at_ms, streak]`.
#[derive(Serialize, Deserialize)]
struct BetaRow(u32, u32, u64, u8);

/// `[srtt_ms, rttvar_ms, n, backoff, at_ms]`.
#[derive(Serialize, Deserialize)]
struct RttRow(u32, u32, u16, u8, u64);

/// An arm (module doc).
#[derive(Serialize, Deserialize)]
struct ArmRow(
    String,
    String,
    u8,
    BetaRow,
    u32,
    u32,
    RttRow,
    RttRow,
    [u16; 4],
    u64,
    u64,
    u64,
    u8,
    u8,
);

/// `[r, beta, ok_ms]`.
#[derive(Serialize, Deserialize)]
struct RelayFileRow(String, BetaRow, u32);

/// `[c, p_q16, at_ms, last_ms]`.
#[derive(Serialize, Deserialize)]
struct EncRow(String, u32, u64, u64);

/// `[c_custodian, c_recipient, beta]`.
#[derive(Serialize, Deserialize)]
struct CarryFileRow(String, String, BetaRow);

/// The plaintext after [`MAGIC`]. The secret is wiped when it drops.
#[derive(Serialize, Deserialize)]
struct LearningFile {
    v: u32,
    secret: String,
    #[serde(default)]
    arms: Vec<ArmRow>,
    #[serde(default)]
    relays: Vec<RelayFileRow>,
    #[serde(default)]
    enc: Vec<EncRow>,
    #[serde(default)]
    carry: Vec<CarryFileRow>,
}

impl Drop for LearningFile {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Only the version, read first: a newer file's rows may not parse.
#[derive(Deserialize)]
struct Head {
    v: u32,
}

fn hour(t: u64) -> u64 {
    t - t % HOUR_MS
}

impl BetaRow {
    fn of(b: &Beta) -> Self {
        BetaRow(b.a_m, b.b_m, hour(b.at_ms), b.streak)
    }

    fn beta(&self, now_ms: u64) -> Beta {
        Beta {
            a_m: self.0,
            b_m: self.1,
            at_ms: self.2.min(now_ms),
            streak: self.3,
        }
    }
}

impl RttRow {
    fn of(r: &Rtt) -> Self {
        RttRow(r.srtt_ms, r.rttvar_ms, r.n, r.backoff, hour(r.at_ms))
    }

    fn rtt(&self, now_ms: u64) -> Rtt {
        Rtt {
            srtt_ms: self.0,
            rttvar_ms: self.1,
            n: self.2,
            backoff: self.3.min(MAX_BACKOFF),
            at_ms: self.4.min(now_ms),
        }
    }
}

fn key_from_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let raw = Zeroizing::new(hex::decode(text).ok()?);
    <[u8; N]>::try_from(raw.as_slice()).ok()
}

/// A ranked carrier's code (lan, internet, p2p); nearby is never ranked.
fn ranked(code: u8) -> Option<u8> {
    carrier_of(code)
        .filter(|c| *c != OutboxCarrier::Nearby)
        .map(carrier_code)
}

/// The plaintext of `m` as saved at `now_ms`: retention and caps applied,
/// every time rounded down to the hour.
fn encode(m: &Model, now_ms: u64) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut m = m.clone();
    m.prune(now_ms);
    let file = LearningFile {
        v: VERSION,
        secret: hex::encode(m.secret.as_slice()),
        arms: m
            .arms
            .iter()
            .map(|((c, n, k), a)| {
                ArmRow(
                    hex::encode(c),
                    hex::encode(n),
                    *k,
                    BetaRow::of(&a.beta),
                    a.ok_ms,
                    a.fail_ms,
                    RttRow::of(&a.connect),
                    RttRow::of(&a.reply),
                    a.paths,
                    hour(a.last_obs_ms),
                    hour(a.last_receipt_ms),
                    hour(a.last_probe_ms),
                    a.recent,
                    a.recent_n,
                )
            })
            .collect(),
        relays: m
            .relays
            .iter()
            .map(|(r, row)| RelayFileRow(hex::encode(r), BetaRow::of(&row.beta), row.ok_ms))
            .collect(),
        enc: m
            .encounters
            .iter()
            .map(|(c, e)| EncRow(hex::encode(c), e.p_q16, hour(e.at_ms), hour(e.last_ms)))
            .collect(),
        carry: m
            .carry
            .iter()
            .map(|((f, b), row)| {
                CarryFileRow(hex::encode(f), hex::encode(b), BetaRow::of(&row.beta))
            })
            .collect(),
    };
    let mut plain = Zeroizing::new(MAGIC.to_vec());
    serde_json::to_writer(&mut *plain, &file).map_err(|e| format!("learning store: {e}"))?;
    Ok(plain)
}

/// What a plaintext held.
enum Decoded {
    Model(Model),
    Newer,
    Corrupt,
}

/// The model in `plain` as loaded at `now_ms` (module doc, validation).
fn decode(plain: &[u8], now_ms: u64) -> Decoded {
    let Some(json) = plain.strip_prefix(MAGIC.as_slice()) else {
        return Decoded::Corrupt;
    };
    match serde_json::from_slice::<Head>(json) {
        Ok(head) if head.v == VERSION => {}
        Ok(head) if head.v > VERSION => return Decoded::Newer,
        _ => return Decoded::Corrupt,
    }
    let Ok(file) = serde_json::from_slice::<LearningFile>(json) else {
        return Decoded::Corrupt;
    };
    let Some(secret) = key_from_hex::<32>(&file.secret).map(Zeroizing::new) else {
        return Decoded::Corrupt;
    };
    let mut m = Model::new_empty(*secret);
    for row in &file.arms {
        let ArmRow(c, n, k, beta, ok_ms, fail_ms, connect, reply, paths, lo, lr, lp, recent, rn) =
            row;
        let (Some(c), Some(n), Some(k)) = (key_from_hex::<16>(c), key_from_hex::<8>(n), ranked(*k))
        else {
            continue;
        };
        let arm = Arm {
            beta: beta.beta(now_ms),
            ok_ms: *ok_ms,
            fail_ms: *fail_ms,
            connect: connect.rtt(now_ms),
            reply: reply.rtt(now_ms),
            paths: *paths,
            last_obs_ms: (*lo).min(now_ms),
            last_receipt_ms: (*lr).min(now_ms),
            last_probe_ms: (*lp).min(now_ms),
            recent: *recent,
            recent_n: (*rn).min(RECENT_MAX),
        };
        m.arms.insert((c, n, k), arm);
    }
    for RelayFileRow(r, beta, ok_ms) in &file.relays {
        if let Some(r) = key_from_hex::<16>(r) {
            let row = RelayRow {
                beta: beta.beta(now_ms),
                ok_ms: *ok_ms,
            };
            m.relays.insert(r, row);
        }
    }
    for EncRow(c, p_q16, at_ms, last_ms) in &file.enc {
        if let (Some(c), true) = (key_from_hex::<16>(c), *p_q16 > 0) {
            let e = Encounter {
                p_q16: (*p_q16).min(Q16_ONE),
                at_ms: (*at_ms).min(now_ms),
                last_ms: (*last_ms).min(now_ms),
            };
            m.encounters.insert(c, e);
        }
    }
    for CarryFileRow(f, b, beta) in &file.carry {
        if let (Some(f), Some(b)) = (key_from_hex::<16>(f), key_from_hex::<16>(b)) {
            let row = CarryRow {
                beta: beta.beta(now_ms),
            };
            m.carry.insert((f, b), row);
        }
    }
    m.prune(now_ms);
    m.arms.retain(|_, a| a.beta.sanitize(now_ms));
    m.relays.retain(|_, r| r.beta.sanitize(now_ms));
    m.carry.retain(|_, r| r.beta.sanitize(now_ms));
    Decoded::Model(m)
}

// ── The file ─────────────────────────────────────────────────────────────

fn path(dd: &Path) -> PathBuf {
    dd.join(LEARNING_FILE)
}

/// What [`read_file`] found.
enum OnDisk {
    Missing,
    Bytes(Vec<u8>),
    /// Not a file this store reads: a symlink or not a regular file, more
    /// than one link, not 0600, over [`MAX_FILE`], or changed while read.
    Refused,
}

/// Whether `meta` (of the path itself, not followed) is a file the store
/// reads: a regular file with one link and mode 0600 (unix).
#[cfg(unix)]
fn acceptable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    meta.file_type().is_file() && meta.nlink() == 1 && meta.permissions().mode() & 0o777 == 0o600
}

/// Whether `meta` (of the path itself, not followed) is a regular file.
#[cfg(not(unix))]
fn acceptable(meta: &std::fs::Metadata) -> bool {
    meta.file_type().is_file()
}

/// The same file as `meta` (unix: device and inode).
#[cfg(unix)]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(_a: &std::fs::Metadata, _b: &std::fs::Metadata) -> bool {
    true
}

/// The file's bytes with the checks of `chat_history`'s reader (a symlink,
/// extra links, a size over [`MAX_FILE`], and here a mode other than 0600
/// refused). The caller holds [`LEARNING_LOCK`].
fn read_file(path: &Path) -> Result<OnDisk, String> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(OnDisk::Missing),
        Err(e) => return Err(e.to_string()),
    };
    if !acceptable(&meta) || meta.len() > MAX_FILE {
        return Ok(OnDisk::Refused);
    }
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(OnDisk::Missing),
        Err(e) => return Err(e.to_string()),
    };
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if !opened.is_file() || opened.len() != meta.len() || !same_file(&opened, &meta) {
        return Ok(OnDisk::Refused);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    file.take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_FILE {
        return Ok(OnDisk::Refused);
    }
    Ok(OnDisk::Bytes(bytes))
}

/// An empty model with a new secret from the OS, in `state`.
fn fresh(state: StoreState) -> (Model, StoreState) {
    let mut secret = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(secret.as_mut_slice());
    let mut m = Model::new_empty(*secret);
    m.state = state.state();
    (m, state)
}

/// An empty model in `state` when `s` can seal here; memory-only when it
/// cannot (a file that was never opened says nothing about the key, so the
/// sealer is asked with a few bytes, and nothing is written).
fn fresh_if_sealable(dd: &Path, s: &dyn Sealer, state: StoreState) -> (Model, StoreState) {
    match s.protect(dd, MAGIC) {
        Ok(_) => fresh(state),
        Err(SealError::Unavailable) => fresh(StoreState::MemoryOnly("keystore")),
        Err(_) => fresh(StoreState::MemoryOnly("io")),
    }
}

/// The model saved in `dd`, loaded at `now_ms`, and what may be written
/// (module doc, load outcomes). Never fails: the worst case is an empty
/// model that is never written.
pub fn load(dd: &Path, s: &dyn Sealer, now_ms: u64) -> (Model, StoreState) {
    let path = path(dd);
    // No file needs no lock (and leaves no lock file).
    if std::fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return fresh_if_sealable(dd, s, StoreState::On);
    }
    let read = DataDirLock::acquire_within(dd, LEARNING_LOCK, LOCK_WAIT)
        .and_then(|_lock| read_file(&path));
    let bytes = match read {
        Ok(OnDisk::Missing) => return fresh_if_sealable(dd, s, StoreState::On),
        Ok(OnDisk::Refused) => return fresh_if_sealable(dd, s, StoreState::ResetAfterUnreadable),
        Ok(OnDisk::Bytes(bytes)) => bytes,
        Err(_) => return fresh(StoreState::MemoryOnly("io")),
    };
    let plain = match s.unprotect(dd, &bytes) {
        Ok(plain) => plain,
        Err(SealError::Unavailable) => return fresh(StoreState::MemoryOnly("keystore")),
        Err(SealError::Newer) => return fresh(StoreState::MemoryOnly("newer")),
        Err(SealError::Corrupt | SealError::AuthFailed) => {
            return fresh(StoreState::ResetAfterUnreadable)
        }
        Err(SealError::Other(_)) => return fresh(StoreState::MemoryOnly("io")),
    };
    match decode(&plain, now_ms) {
        Decoded::Model(m) => (m, StoreState::On),
        Decoded::Newer => fresh(StoreState::MemoryOnly("newer")),
        Decoded::Corrupt => fresh(StoreState::ResetAfterUnreadable),
    }
}

/// Writes `m` as of `now_ms` (retention and caps applied, times rounded
/// down to the hour): sealed outside the lock, renamed into place under it.
/// Refused for a memory-only model; a sealed file over [`MAX_FILE`] is not
/// written.
pub fn save(dd: &Path, s: &dyn Sealer, m: &Model, now_ms: u64) -> Result<(), String> {
    if m.state == State::MemoryOnly {
        return Err("learning store: memory only, nothing is written".into());
    }
    let plain = encode(m, now_ms)?;
    let sealed = s
        .protect(dd, &plain)
        .map_err(|e| format!("learning store: {e}"))?;
    drop(plain);
    if sealed.len() as u64 > MAX_FILE {
        return Err(format!(
            "learning store: {} bytes is over the {MAX_FILE}-byte limit",
            sealed.len()
        ));
    }
    let _lock = DataDirLock::acquire_within(dd, LEARNING_LOCK, LOCK_WAIT)?;
    crate::paths::atomic_write_private(&path(dd), &sealed)
}

/// Removes the file (`raven learning off --forget`) under [`LEARNING_LOCK`];
/// no file is not an error.
pub fn delete(dd: &Path) -> Result<(), String> {
    let _lock = DataDirLock::acquire_within(dd, LEARNING_LOCK, LOCK_WAIT)?;
    match std::fs::remove_file(path(dd)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("learning store: {e}")),
    }
}

#[cfg(test)]
mod tests;
