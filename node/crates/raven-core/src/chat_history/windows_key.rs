//! Windows' chat-history key K_hist (privacy pack PP.11;
//! docs/design/2026-10-at-rest-metadata.md section 4.9).
//!
//! Before PP.11 a Windows profile had no K_hist: the chat history, the
//! outbound stage, the app rows and `meta_key.rmk` were each user-scoped
//! DPAPI directly (entropy: the path-bound scope), so no per-profile key
//! existed whose deletion makes them unreadable, and anyone who can use the
//! user's DPAPI master key could open freed copies. Now K_hist is a random
//! 32-byte key, DPAPI-wrapped for the user (entropy: the path-bound scope of
//! `raven/chat-history-key/v1`) in `chat_history_key.dpapi`, created
//! add-only under the key-init lock like the keychain item, and never
//! rotated or replaced (PP.10 rotates the epoch keys inside `meta_key.rmk`).
//! Those blobs are AEAD under it exactly as on macOS and Linux, behind the
//! 4-byte format tag [`TAG`]; a blob without the tag is an older build's
//! DPAPI-direct one and still opens. `privacy::migrate_all` moves every such
//! object under K_hist eagerly (`meta_key.rmk` is never rewritten otherwise,
//! review R18), so deleting the key file (erase, PP.16) is a crypto-erase.
//! An ordinary write mints no K_hist outside a sealed profile (review
//! A-keys-format-2): until the sealing (or the migration's move, after the
//! upgrade interlock) mints it, a write is DPAPI-direct, which an older
//! raven-node still sharing the files reads. `raven privacy unseal` writes
//! a profile's tagged blobs back DPAPI-direct, with a key file or without
//! one (review A-keys-format-1).
//!
//! Unit tests on every system run this code: a test thread turns it on
//! (`ForTests`) and DPAPI is a stand-in there; the Windows CI job runs the
//! same tests against real DPAPI.

use std::io::Read;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::{
    aead_protect, aead_unprotect, dpapi_protect_blob, dpapi_unprotect_blob, history_path,
    init_protected_key, outbound_body_stage_path, ChatHistory, ChatHistoryError,
    ChatHistoryProtector, HistKey, HistoryLock, OperationKeyCache, PlatformChatHistoryProtector,
    PlatformOutboundStageProtector, ProtectedKeyStore, StageLock, HISTORY_AAD_DOMAIN,
    HISTORY_MAGIC, STAGE_AAD_DOMAIN, STAGE_MAGIC, WINDOWS_HISTORY_KEY_FILE,
};

/// The first four bytes of a blob K_hist seals on Windows. Every DPAPI blob
/// starts with its version, 1 as a little-endian u32
/// ([`DPAPI_BLOB_VERSION`]), so the two forms never meet: no trial
/// decryption is needed to tell them apart.
pub(crate) const TAG: &[u8; 4] = b"RKH1";
/// The first four bytes of every DPAPI blob (`dwVersion` = 1).
pub(crate) const DPAPI_BLOB_VERSION: [u8; 4] = [1, 0, 0, 0];
const _: () = assert!(TAG[0] != DPAPI_BLOB_VERSION[0]);
/// The key file's DPAPI entropy is the path-bound scope of this domain.
const KEY_FILE_DOMAIN: &[u8] = b"raven/chat-history-key/v1";
/// A DPAPI blob of 32 bytes is a few hundred bytes; a bigger file is not one.
const MAX_KEY_FILE_BYTES: u64 = 16 * 1024;

/// Whether this code runs: always on Windows; in a unit test on another
/// system, on a thread that turned it on (`ForTests`).
pub(crate) fn active() -> bool {
    #[cfg(windows)]
    {
        true
    }
    #[cfg(not(windows))]
    {
        FOR_TESTS.with(std::cell::Cell::get)
    }
}

#[cfg(not(windows))]
thread_local! {
    static FOR_TESTS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A unit test's switch: this thread runs Windows' path (with the DPAPI
/// stand-in on other systems) until the guard drops. Changes nothing on
/// Windows.
#[cfg(test)]
pub(crate) struct ForTests {
    #[cfg(not(windows))]
    was: bool,
}

#[cfg(test)]
impl ForTests {
    pub(crate) fn on() -> Self {
        #[cfg(not(windows))]
        {
            Self {
                was: FOR_TESTS.with(|on| on.replace(true)),
            }
        }
        #[cfg(windows)]
        {
            Self {}
        }
    }
}

#[cfg(all(test, not(windows)))]
impl Drop for ForTests {
    fn drop(&mut self) {
        FOR_TESTS.with(|on| on.set(self.was));
    }
}

// ── K_hist: the DPAPI-wrapped key file ────────────────────────────────────

pub(crate) fn key_path(data_dir: &Path) -> PathBuf {
    data_dir.join(WINDOWS_HISTORY_KEY_FILE)
}

/// K_hist from its file; `None` when there is none. A file that does not
/// unwrap to 32 bytes for this Windows account is
/// [`ChatHistoryError::CorruptProtectedKey`], and is never replaced.
pub(crate) fn read(data_dir: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, ChatHistoryError> {
    let io = |e: std::io::Error| ChatHistoryError::Io(format!("{WINDOWS_HISTORY_KEY_FILE}: {e}"));
    let mut blob = Vec::new();
    match std::fs::File::open(key_path(data_dir)) {
        Ok(file) => {
            file.take(MAX_KEY_FILE_BYTES + 1)
                .read_to_end(&mut blob)
                .map_err(io)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(e)),
    }
    if blob.len() as u64 > MAX_KEY_FILE_BYTES {
        return Err(ChatHistoryError::CorruptProtectedKey);
    }
    let plain = Zeroizing::new(
        dpapi_unprotect_blob(data_dir, KEY_FILE_DOMAIN, &blob).map_err(|e| match e {
            ChatHistoryError::AuthenticationFailed => ChatHistoryError::CorruptProtectedKey,
            other => other,
        })?,
    );
    if plain.len() != 32 {
        return Err(ChatHistoryError::CorruptProtectedKey);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plain);
    Ok(Some(key))
}

/// The key file as a [`ProtectedKeyStore`] for `init_protected_key`.
struct KeyFile;

impl ProtectedKeyStore for KeyFile {
    fn get(&self, data_dir: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, ChatHistoryError> {
        read(data_dir)
    }

    /// Written whole to a temp file (owner-only, fsynced), then hard-linked
    /// to its name, which fails when the name exists: the key file appears
    /// complete or not at all, and never over another one.
    fn add(&self, data_dir: &Path, key: &[u8; 32]) -> Result<bool, ChatHistoryError> {
        let path = key_path(data_dir);
        if std::fs::symlink_metadata(&path).is_ok() {
            return Ok(false);
        }
        let blob = dpapi_protect_blob(data_dir, KEY_FILE_DOMAIN, key)?;
        // The temp name `paths::atomic_write_private` uses, so the migration
        // removes one an interrupted creation left behind.
        let temp = data_dir.join(format!(
            ".{WINDOWS_HISTORY_KEY_FILE}.tmp.{:016x}",
            rand::random::<u64>()
        ));
        crate::paths::create_new_private(&temp, &blob).map_err(ChatHistoryError::Io)?;
        let linked = std::fs::hard_link(&temp, &path);
        let _ = std::fs::remove_file(&temp);
        match linked {
            Ok(()) => {
                crate::paths::sync_dir_best_effort(data_dir);
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(ChatHistoryError::Io(format!(
                "{WINDOWS_HISTORY_KEY_FILE}: {e}"
            ))),
        }
    }
}

/// K_hist; with `create` a profile without one gets it (add-only, under the
/// key-init lock, exactly as the keychain item is minted). Without `create`
/// a missing key is [`ChatHistoryError::MissingProtectedKey`].
pub(crate) fn load(data_dir: &Path, create: bool) -> Result<Zeroizing<[u8; 32]>, ChatHistoryError> {
    if let Some(key) = read(data_dir)? {
        return Ok(key);
    }
    if !create {
        return Err(ChatHistoryError::MissingProtectedKey);
    }
    init_protected_key(&KeyFile, data_dir)
}

/// `DomainProtector::load_hist_key` on Windows: K_hist, or without `create`
/// in a profile that has none yet [`HistKey::Dpapi`] (its DPAPI-direct
/// blobs still open).
pub(crate) fn hist_key(data_dir: &Path, create: bool) -> Result<HistKey, ChatHistoryError> {
    match load(data_dir, create) {
        Ok(key) => Ok(HistKey::Wrapped(key)),
        Err(ChatHistoryError::MissingProtectedKey) if !create => Ok(HistKey::Dpapi),
        Err(error) => Err(error),
    }
}

// ── The blobs ─────────────────────────────────────────────────────────────

/// `TAG || nonce[12] || ct || tag[16]`: AEAD under K_hist with the scoped
/// AAD, exactly as on macOS and Linux, behind [`TAG`]. In a profile the user
/// unsealed (`raven privacy unseal`, PP.18) DPAPI directly instead, as
/// before PP.11: the older build the user goes back to reads only that.
pub(crate) fn seal(
    key: &[u8; 32],
    data_dir: &Path,
    domain: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, ChatHistoryError> {
    if crate::privacy::mode(data_dir) == crate::at_rest::Mode::UnsealedByUser {
        return dpapi_protect_blob(data_dir, domain, plaintext);
    }
    let body = aead_protect(key, data_dir, domain, plaintext)?;
    let mut blob = Vec::with_capacity(TAG.len() + body.len());
    blob.extend_from_slice(TAG);
    blob.extend_from_slice(&body);
    Ok(blob)
}

/// [`HistKey::Dpapi`]'s seal: under K_hist once its file exists (another
/// process created it), otherwise DPAPI-direct as before PP.11, which every
/// build reads and the next migration pass moves under K_hist.
pub(crate) fn seal_without_loaded_key(
    data_dir: &Path,
    domain: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, ChatHistoryError> {
    match read(data_dir)? {
        Some(key) => seal(&key, data_dir, domain, plaintext),
        None => dpapi_protect_blob(data_dir, domain, plaintext),
    }
}

/// A blob [`seal`] wrote opens under K_hist (`key` is asked for only then);
/// any other is an older build's DPAPI-direct one and opens with DPAPI. A
/// wrong key or a changed byte is [`ChatHistoryError::AuthenticationFailed`].
pub(crate) fn open(
    data_dir: &Path,
    domain: &[u8],
    blob: &[u8],
    key: impl FnOnce() -> Result<Zeroizing<[u8; 32]>, ChatHistoryError>,
) -> Result<Vec<u8>, ChatHistoryError> {
    match blob.strip_prefix(TAG) {
        Some(body) => aead_unprotect(&*key()?, data_dir, domain, body),
        None => dpapi_unprotect_blob(data_dir, domain, blob),
    }
}

/// Whether K_hist sealed `blob` ([`seal`]).
#[cfg(test)]
pub(crate) fn is_tagged(blob: &[u8]) -> bool {
    blob.starts_with(TAG)
}

/// The platform protectors' seal. In a sealed profile K_hist, minted on
/// first use. Outside one an ordinary write never mints it (review
/// A-keys-format-2): before the first sealing an older raven-node may still
/// share these files (the upgrade interlock, or free disk space, holds the
/// sealing back), so a profile without K_hist gets DPAPI-direct blobs as
/// before PP.11, which every build reads ([`seal_without_loaded_key`]).
/// K_hist is minted by the sealing (`at_rest::create_key_file`) and by the
/// migration's move of a profile that is not sealed, after its interlock.
pub(super) fn protect(
    keys: &OperationKeyCache,
    data_dir: &Path,
    domain: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, ChatHistoryError> {
    let sealed = crate::privacy::mode(data_dir) == crate::at_rest::Mode::Sealed;
    match keys.key(data_dir, sealed) {
        Ok(key) => seal(&key, data_dir, domain, plaintext),
        Err(ChatHistoryError::MissingProtectedKey) if !sealed => {
            dpapi_protect_blob(data_dir, domain, plaintext)
        }
        Err(error) => Err(error),
    }
}

/// The platform protectors' open: a DPAPI-direct blob needs no K_hist.
pub(super) fn unprotect(
    keys: &OperationKeyCache,
    data_dir: &Path,
    domain: &[u8],
    blob: &[u8],
) -> Result<Vec<u8>, ChatHistoryError> {
    open(data_dir, domain, blob, || keys.key(data_dir, false))
}

/// The stage's open: its own domain, then the history domain of one prior
/// generation, as on macOS and Linux. `true`: it was the history domain, and
/// the stage is to be written again.
pub(super) fn unprotect_stage(
    keys: &OperationKeyCache,
    data_dir: &Path,
    blob: &[u8],
) -> Result<(Vec<u8>, bool), ChatHistoryError> {
    match unprotect(keys, data_dir, STAGE_AAD_DOMAIN, blob) {
        Ok(plaintext) => Ok((plaintext, false)),
        Err(ChatHistoryError::AuthenticationFailed) => {
            Ok((unprotect(keys, data_dir, HISTORY_AAD_DOMAIN, blob)?, true))
        }
        Err(error) => Err(error),
    }
}

// ── The migration's part in a profile that is not sealed ─────────────────

/// Whether `blob` is a DPAPI blob (by its version field): what an older
/// Windows build sealed directly.
pub(crate) fn is_dpapi_direct(blob: &[u8]) -> bool {
    blob.starts_with(&DPAPI_BLOB_VERSION)
}

/// The first four bytes of the body of the file at `path` when it is
/// K_hist-direct (`magic`, RVNHIST1 or RVNOSTG1): its first bytes only, no
/// key.
fn body_head(path: &Path, magic: &[u8; 8]) -> Option<Vec<u8>> {
    let mut head = Vec::with_capacity(12);
    std::fs::File::open(path)
        .and_then(|file| file.take(12).read_to_end(&mut head))
        .ok()
        .filter(|got| *got == 12 && head.starts_with(magic))
        .map(|_| head[8..].to_vec())
}

/// Whether the file at `path` is K_hist-direct (`magic`) with a
/// DPAPI-direct body.
fn dpapi_direct_file(path: &Path, magic: &[u8; 8]) -> bool {
    body_head(path, magic).is_some_and(|body| is_dpapi_direct(&body))
}

/// Whether the file at `path` is K_hist-direct (`magic`) with a body K_hist
/// sealed behind [`TAG`].
fn tagged_file(path: &Path, magic: &[u8; 8]) -> bool {
    body_head(path, magic).is_some_and(|body| body.starts_with(TAG))
}

/// Whether the chat history or the outbound stage is still DPAPI-direct.
pub(crate) fn dpapi_files_left(data_dir: &Path) -> bool {
    dpapi_direct_file(&history_path(data_dir), HISTORY_MAGIC)
        || dpapi_direct_file(&outbound_body_stage_path(data_dir), STAGE_MAGIC)
}

/// The migration in a profile that is not sealed (PP.11): a chat history an
/// older Windows build sealed with DPAPI directly is saved again under
/// K_hist (RVNHIST1, the tagged body), entries unchanged, under the history
/// lock. `Ok(true)` when rewritten. A sealed profile moves it under the epoch
/// keys instead (`ChatHistory::reseal`).
pub(crate) fn rewrap_history(data_dir: &Path) -> Result<bool, ChatHistoryError> {
    let path = history_path(data_dir);
    if super::sealed_mode(data_dir) || !dpapi_direct_file(&path, HISTORY_MAGIC) {
        return Ok(false);
    }
    let protector = PlatformChatHistoryProtector::default();
    protector.prepare(data_dir);
    let _lock = HistoryLock::acquire(data_dir)?;
    if !dpapi_direct_file(&path, HISTORY_MAGIC) {
        return Ok(false);
    }
    let history = ChatHistory::load_unlocked(data_dir, &protector)?;
    history.save_unlocked(data_dir, &protector)?;
    Ok(true)
}

/// [`rewrap_history`] for the outbound stage (RVNOSTG1), under the stage
/// lock; a sealed profile's goes to `reseal_stage`.
pub(crate) fn rewrap_stage(data_dir: &Path) -> Result<bool, ChatHistoryError> {
    let path = outbound_body_stage_path(data_dir);
    if super::sealed_mode(data_dir) || !dpapi_direct_file(&path, STAGE_MAGIC) {
        return Ok(false);
    }
    let protector = PlatformOutboundStageProtector::default();
    protector.prepare(data_dir);
    let _lock = StageLock::acquire(data_dir)?;
    if !dpapi_direct_file(&path, STAGE_MAGIC) {
        return Ok(false);
    }
    let file = super::load_stage_file_with_protector(data_dir, &protector)?;
    super::save_stage_file_with_protector(data_dir, &file, &protector)?;
    Ok(true)
}

// ── `raven privacy unseal` in a profile without a key file ───────────────

/// `raven privacy unseal` (PP.18) in a profile without `meta_key.rmk`
/// (review A-keys-format-1: the sealing was held back, or never ran, while
/// K_hist existed): a chat history K_hist sealed behind [`TAG`] (RVNHIST1)
/// is saved again under the history lock, entries unchanged. In a profile
/// the user unsealed [`seal`] writes it DPAPI-direct, the form a build
/// before PP.11 reads. K_hist from its file: no at-rest keys exist here.
/// `Ok(true)` when it was rewritten.
pub(crate) fn untag_history(data_dir: &Path) -> Result<bool, ChatHistoryError> {
    let path = history_path(data_dir);
    if crate::privacy::mode(data_dir) != crate::at_rest::Mode::UnsealedByUser
        || !tagged_file(&path, HISTORY_MAGIC)
    {
        return Ok(false);
    }
    let protector = PlatformChatHistoryProtector::default();
    protector.prepare(data_dir);
    let _lock = HistoryLock::acquire(data_dir)?;
    if !tagged_file(&path, HISTORY_MAGIC) {
        return Ok(false);
    }
    let history = ChatHistory::load_unlocked(data_dir, &protector)?;
    history.save_unlocked(data_dir, &protector)?;
    Ok(true)
}

/// [`untag_history`] for the outbound stage (RVNOSTG1), under the stage
/// lock.
pub(crate) fn untag_stage(data_dir: &Path) -> Result<bool, ChatHistoryError> {
    let path = outbound_body_stage_path(data_dir);
    if crate::privacy::mode(data_dir) != crate::at_rest::Mode::UnsealedByUser
        || !tagged_file(&path, STAGE_MAGIC)
    {
        return Ok(false);
    }
    let protector = PlatformOutboundStageProtector::default();
    protector.prepare(data_dir);
    let _lock = StageLock::acquire(data_dir)?;
    if !tagged_file(&path, STAGE_MAGIC) {
        return Ok(false);
    }
    let file = super::load_stage_file_with_protector(data_dir, &protector)?;
    super::save_stage_file_with_protector(data_dir, &file, &protector)?;
    Ok(true)
}

// ── Tests: what an older Windows build wrote ──────────────────────────────

/// A blob sealed with DPAPI directly, as Windows builds before PP.11 sealed
/// every object (here the stand-in, on Windows real DPAPI).
#[cfg(test)]
pub(crate) fn dpapi_direct_for_tests(data_dir: &Path, domain: &[u8], plaintext: &[u8]) -> Vec<u8> {
    dpapi_protect_blob(data_dir, domain, plaintext).unwrap()
}

/// The protector of a Windows build before PP.11: DPAPI directly.
#[cfg(test)]
struct DpapiDirect(&'static [u8]);

#[cfg(test)]
impl ChatHistoryProtector for DpapiDirect {
    fn protect(&self, data_dir: &Path, plaintext: &[u8]) -> Result<Vec<u8>, ChatHistoryError> {
        dpapi_protect_blob(data_dir, self.0, plaintext)
    }

    fn unprotect(&self, data_dir: &Path, ciphertext: &[u8]) -> Result<Vec<u8>, ChatHistoryError> {
        dpapi_unprotect_blob(data_dir, self.0, ciphertext)
    }
}

/// Save `history` as a Windows build before PP.11 did (RVNHIST1 with a
/// DPAPI-direct body), in a profile that is not sealed.
#[cfg(test)]
pub(crate) fn save_history_before_pp11(data_dir: &Path, history: &ChatHistory) {
    assert!(
        !super::sealed_mode(data_dir),
        "RVNHIST1 is a plain profile's"
    );
    history
        .save_with_protector(data_dir, &DpapiDirect(HISTORY_AAD_DOMAIN))
        .unwrap();
}

/// The history as a Windows build before PP.11 reads it (DPAPI directly).
#[cfg(test)]
pub(crate) fn load_history_before_pp11(data_dir: &Path) -> Result<ChatHistory, ChatHistoryError> {
    let _lock = HistoryLock::acquire(data_dir)?;
    ChatHistory::load_unlocked(data_dir, &DpapiDirect(HISTORY_AAD_DOMAIN))
}

/// How many bodies the outbound stage holds as a Windows build before PP.11
/// reads it (DPAPI directly).
#[cfg(test)]
pub(crate) fn load_stage_before_pp11(data_dir: &Path) -> Result<usize, ChatHistoryError> {
    let _lock = StageLock::acquire(data_dir)?;
    super::load_stage_file_with_protector(data_dir, &DpapiDirect(STAGE_AAD_DOMAIN))
        .map(|file| file.entries.len())
}

/// An app row's body as a Windows build before PP.11 opens it (DPAPI
/// directly, under the inbox's domain).
#[cfg(test)]
pub(crate) fn open_row_before_pp11(data_dir: &Path, sealed: &[u8]) -> bool {
    dpapi_unprotect_blob(data_dir, b"raven/app-inbox/v1", sealed).is_ok()
}

/// Stage a body for friend `n` as a Windows build before PP.11 did
/// (RVNOSTG1 with a DPAPI-direct body), in a profile that is not sealed.
#[cfg(test)]
pub(crate) fn stage_before_pp11(data_dir: &Path, n: u8, created_at_ms: u64, body: &str) {
    assert!(
        !super::sealed_mode(data_dir),
        "RVNOSTG1 is a plain profile's"
    );
    super::stage_outbound_body_with_protector(
        data_dir,
        &[n; 32],
        &[n; 32],
        &[n; 32],
        &[n; 16],
        created_at_ms,
        body,
        &DpapiDirect(STAGE_AAD_DOMAIN),
    )
    .unwrap();
}
