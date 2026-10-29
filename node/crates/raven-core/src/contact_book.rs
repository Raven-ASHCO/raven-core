//! The contact book, `contacts.json` (privacy pack PP.4;
//! docs/design/2026-10-at-rest-metadata.md section 4.2).
//!
//! The one reader and writer of the book, which holds every friend's petname,
//! key, addresses, relays and custodians. Readers accept the sealed form
//! (RMS1, [`Kind::Contacts`]) and plain JSON (an old profile, or an older
//! build wrote it); writers write what the profile's mode says
//! ([`crate::privacy::mode`]), under the book's writer lock
//! ([`CONTACTS_LOCK`]).
//!
//! A book that cannot be opened is an error of the operation that needed it
//! ([`BookError`]), never "no contacts": a missing file is the only empty
//! book.
//!
//! Long-lived processes (raven-node) cache the decrypted book and the block
//! list's bytes as they are on disk, which its reader opens (sealed since
//! PP.5) ([`enable_process_cache`]), keyed by each file's stamp (length,
//! write time, file id); a changed stamp re-reads before answering. raven-node also
//! holds every read of the book while it waits for the at-rest key at start
//! ([`hold`]): its listeners then admit nobody, exactly as for an unreadable
//! book.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::de::DeserializeOwned;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::at_rest::{self, AtRestError, FileStamp, Kind};

/// The book's file name in the data dir.
pub const CONTACTS_FILE: &str = "contacts.json";
/// Its writer lock (`at_rest::FILES` names it): every write, and a
/// read-modify-write that must not lose a concurrent one ([`lock`]).
pub const CONTACTS_LOCK: &str = ".contacts.lock.sqlite";

/// Why the book could not be read or written. The texts keep today's
/// prefixes (`contacts.json: ...`, `contacts.json corrupt: ...`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BookError {
    /// Reading or writing the file failed.
    Io(String),
    /// Not a contact book: it does not parse, or a sealed book does not open
    /// (a changed byte, another profile's book, a newer format).
    Corrupt(String),
    /// Sealed, and this process cannot open it now: the at-rest key is not
    /// loaded (the keychain or passphrase did not give it), it names a key
    /// epoch this process has not loaded, or raven-node is still waiting for
    /// the key. Retryable; never "no contacts".
    Locked(String),
}

impl BookError {
    /// The book is sealed and its key is not available in this process now.
    pub fn is_locked(&self) -> bool {
        matches!(self, BookError::Locked(_))
    }

    fn from_at_rest(e: AtRestError) -> BookError {
        match e {
            AtRestError::KeyUnavailable(_)
            | AtRestError::KeyLost(_)
            | AtRestError::StaleKeys { .. } => BookError::Locked(e.to_string()),
            AtRestError::Io(text) => BookError::Io(
                text.strip_prefix("contacts.json: ")
                    .map(str::to_owned)
                    .unwrap_or(text),
            ),
            AtRestError::Tampered { .. }
            | AtRestError::WrongKind { .. }
            | AtRestError::Truncated
            | AtRestError::NewerFormat(_)
            | AtRestError::Json(_)
            | AtRestError::NoIdentity
            | AtRestError::NotSealedMode => BookError::Corrupt(e.to_string()),
        }
    }
}

impl std::fmt::Display for BookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BookError::Io(e) => write!(f, "{CONTACTS_FILE}: {e}"),
            BookError::Corrupt(e) => write!(f, "{CONTACTS_FILE} corrupt: {e}"),
            BookError::Locked(e) => write!(f, "{CONTACTS_FILE}: locked ({e})"),
        }
    }
}

impl std::error::Error for BookError {}

impl From<BookError> for String {
    fn from(e: BookError) -> String {
        e.to_string()
    }
}

/// The book's plaintext (a JSON array): RMS1 opened with this process's
/// at-rest keys ([`at_rest::keys_cached`]), plain JSON as it is. `None`: no
/// book yet.
pub fn read_plain(data_dir: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, BookError> {
    match process_state(data_dir) {
        Some(state) => read_through(&state, data_dir, Which::Book),
        None => read_book_now(data_dir),
    }
}

/// The book's rows as `T` (each reader declares the fields it needs; serde
/// ignores the rest). `None`: no book yet.
pub fn read_rows<T: DeserializeOwned>(data_dir: &Path) -> Result<Option<Vec<T>>, BookError> {
    read_plain(data_dir)?
        .map(|plain| parse_rows(&plain))
        .transpose()
}

/// Replace the book with `rows`, under [`CONTACTS_LOCK`]: sealed (RMS1) in a
/// sealed profile, exactly today's pretty JSON otherwise. In a sealed profile
/// whose key this process has not loaded it fails ([`BookError::Locked`]):
/// never a plaintext fallback.
pub fn write_rows<T: Serialize>(data_dir: &Path, rows: &[T]) -> Result<(), BookError> {
    lock(data_dir)?.write_rows(rows)
}

/// Take the book's writer lock for a read-modify-write that must not lose a
/// concurrent write (a device-sync import). Never call [`write_rows`] while
/// holding it: write through [`BookLock::write_rows`].
pub fn lock(data_dir: &Path) -> Result<BookLock, BookError> {
    let file = at_rest::lock_file(data_dir, &data_dir.join(CONTACTS_FILE), Kind::Contacts)
        .map_err(BookError::from_at_rest)?;
    Ok(BookLock {
        file,
        data_dir: data_dir.to_path_buf(),
    })
}

/// The book's writer lock, held ([`lock`]).
pub struct BookLock {
    file: at_rest::FileLock,
    data_dir: PathBuf,
}

impl BookLock {
    /// The rows as they are on disk now (never this process's cache).
    pub fn read_rows<T: DeserializeOwned>(&self) -> Result<Option<Vec<T>>, BookError> {
        if let Some(why) = process_state(&self.data_dir).and_then(|s| lock_state(&s).held.clone()) {
            return Err(BookError::Locked(why));
        }
        read_book_now(&self.data_dir)?
            .map(|plain| parse_rows(&plain))
            .transpose()
    }

    /// [`write_rows`] under this lock.
    pub fn write_rows<T: Serialize>(&self, rows: &[T]) -> Result<(), BookError> {
        let result = self.file.store_json(&rows).map_err(BookError::from_at_rest);
        if let Some(state) = process_state(&self.data_dir) {
            lock_state(&state).book = None;
        }
        result
    }
}

fn parse_rows<T: DeserializeOwned>(plain: &[u8]) -> Result<Vec<T>, BookError> {
    serde_json::from_slice(plain).map_err(|e| BookError::Corrupt(e.to_string()))
}

/// Read the book now: one read, opened when it is sealed.
fn read_book_now(data_dir: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, BookError> {
    let path = data_dir.join(CONTACTS_FILE);
    let raw = match read_capped(&path, at_rest::MAX_SEALED_FILE_BYTES) {
        Ok(Some(raw)) => raw,
        Ok(None) => return Ok(None),
        Err(e) => return Err(BookError::Io(e.to_string())),
    };
    if raw.len() as u64 > at_rest::MAX_SEALED_FILE_BYTES {
        return Err(BookError::Io("exceeds the local size limit".into()));
    }
    open_book(data_dir, raw).map(Some)
}

fn open_book(data_dir: &Path, raw: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, BookError> {
    if !at_rest::is_sealed(&raw) {
        return Ok(raw);
    }
    let keys = at_rest::keys_cached(data_dir).map_err(BookError::from_at_rest)?;
    at_rest::open(&keys, Kind::Contacts, &raw).map_err(BookError::from_at_rest)
}

/// At most `max + 1` bytes of `path` (the caller checks the limit). `None`
/// when it is missing.
fn read_capped(path: &Path, max: u64) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
    use std::io::Read;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(max + 1).read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

fn stat(path: &Path) -> std::io::Result<Option<FileStamp>> {
    match std::fs::metadata(path) {
        Ok(meta) => Ok(Some(FileStamp::of(&meta))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// A file's bytes and the stamp they belong to: stat, read, stat, retried
/// while a write lands in between (review R29). `(None, None)`: missing.
fn read_stable(path: &Path, max: u64) -> std::io::Result<CachedFile> {
    for _ in 0..8 {
        let before = stat(path)?;
        let bytes = read_capped(path, max)?;
        if stat(path)? == before && before.is_some() == bytes.is_some() {
            return Ok(CachedFile {
                stamp: before,
                bytes,
            });
        }
    }
    Err(std::io::Error::other("kept changing while it was read"))
}

// ── The long-lived process's state of one profile's book ──────────────────

/// What this process keeps for one profile: raven-node's hold while it waits
/// for the at-rest key, and the cached book and block list.
#[derive(Default)]
struct DirState {
    /// Every read of the book refuses with this ([`hold`]).
    held: Option<String>,
    /// [`enable_process_cache`] was called.
    cache: bool,
    book: Option<CachedFile>,
    blocked: Option<CachedFile>,
    /// Moves on every hold and release ([`reload_generation`]).
    generation: u64,
}

/// One file as last read: its stamp (`None`: missing) and its plaintext.
#[derive(Clone)]
struct CachedFile {
    stamp: Option<FileStamp>,
    bytes: Option<Zeroizing<Vec<u8>>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Which {
    Book,
    BlockList,
}

/// Per data dir, under the name it was registered by and its canonical
/// name (one shared state): readers look it up by the name they hold, with
/// no system call.
static PROCESS: Mutex<BTreeMap<PathBuf, Arc<Mutex<DirState>>>> = Mutex::new(BTreeMap::new());

fn lock_process() -> MutexGuard<'static, BTreeMap<PathBuf, Arc<Mutex<DirState>>>> {
    PROCESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_state(state: &Mutex<DirState>) -> MutexGuard<'_, DirState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn process_state(data_dir: &Path) -> Option<Arc<Mutex<DirState>>> {
    let process = lock_process();
    if process.is_empty() {
        return None;
    }
    process.get(data_dir).cloned()
}

fn register(data_dir: &Path) -> Arc<Mutex<DirState>> {
    let canonical = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    let mut process = lock_process();
    let state = process
        .get(data_dir)
        .or_else(|| process.get(&canonical))
        .cloned()
        .unwrap_or_default();
    process.insert(data_dir.to_path_buf(), Arc::clone(&state));
    process.insert(canonical, Arc::clone(&state));
    state
}

/// raven-node at service start, in a profile that is sealed (or that this
/// build will seal), and when Lock v2 locks it (P6.40): every read of the
/// book in this process refuses ([`BookError::Locked`] with `why`) until
/// [`enable_process_cache`], so the listeners admit nobody while the
/// at-rest key loads. The decrypted book and block list it cached go (they
/// are wiped as they drop).
pub fn hold(data_dir: &Path, why: &str) {
    let state = register(data_dir);
    let mut st = lock_state(&state);
    st.held = Some(why.to_owned());
    st.book = None;
    st.blocked = None;
    st.generation += 1;
}

/// Whether this process holds the book ([`hold`]): Lock v2 locked it, or
/// raven-node waits for the at-rest key. Every read refuses until it opens;
/// a reader that keeps what it derived must read it again then.
pub fn is_held(data_dir: &Path) -> bool {
    process_state(data_dir).is_some_and(|state| lock_state(&state).held.is_some())
}

/// Whether this process holds the book cached in plaintext: the decrypted
/// book or block list (Lock v2's tests, P6.40).
pub fn holds_plaintext(data_dir: &Path) -> bool {
    process_state(data_dir).is_some_and(|state| {
        let st = lock_state(&state);
        st.book.is_some() || st.blocked.is_some()
    })
}

/// Long-lived processes only (raven-node, at service start, once the
/// at-rest key is loaded): release any [`hold`] and cache the decrypted book
/// and `blocked_pubs.json` of this profile, keyed by each file's stamp
/// (length, write time in ns, file id) read stat, read, stat (review R29). A
/// changed stamp re-reads before answering; an error is never cached.
/// Admission still does the same work on every path: one book lookup and one
/// block-list lookup.
pub fn enable_process_cache(data_dir: &Path) {
    let state = register(data_dir);
    let mut st = lock_state(&state);
    st.cache = true;
    if st.held.take().is_some() {
        st.generation += 1;
    }
}

/// Changes whenever this process sets or releases a [`hold`] on this
/// profile's book (0 while it has none). Readers that keep what they derived
/// from the book until its file changes (the p2p peer gate, the friend
/// relay's members) add it to their file stamps, so they read it again once
/// the key is loaded.
pub fn reload_generation(data_dir: &Path) -> u64 {
    process_state(data_dir).map_or(0, |state| lock_state(&state).generation)
}

fn read_through(
    state: &Mutex<DirState>,
    data_dir: &Path,
    which: Which,
) -> Result<Option<Zeroizing<Vec<u8>>>, BookError> {
    let mut st = lock_state(state);
    if which == Which::Book {
        if let Some(why) = &st.held {
            return Err(BookError::Locked(why.clone()));
        }
    }
    // Without the cache only the book comes here ([`cached_block_list`]
    // asks first), held or read now.
    if !st.cache {
        drop(st);
        return read_book_now(data_dir);
    }
    let (path, max) = match which {
        Which::Book => (data_dir.join(CONTACTS_FILE), at_rest::MAX_SEALED_FILE_BYTES),
        Which::BlockList => (
            crate::chat_history::blocked_path(data_dir),
            crate::chat_history::MAX_BLOCK_LIST_FILE_BYTES,
        ),
    };
    let io = |e: std::io::Error| BookError::Io(e.to_string());
    let now = stat(&path).map_err(io)?;
    let slot = match which {
        Which::Book => &mut st.book,
        Which::BlockList => &mut st.blocked,
    };
    if let Some(cached) = slot.as_ref().filter(|c| c.stamp == now) {
        return Ok(cached.bytes.clone());
    }
    let read = read_stable(&path, max).map_err(io)?;
    let bytes = match (which, read.bytes) {
        (Which::Book, Some(raw)) if raw.len() as u64 <= max => Some(open_book(data_dir, raw)?),
        (Which::Book, Some(_)) => {
            return Err(BookError::Io("exceeds the local size limit".into()));
        }
        // The block list's own reader opens it (sealed, PP.5) and checks its
        // limit, as it always did.
        (Which::BlockList, raw) => raw,
        (Which::Book, None) => None,
    };
    *slot = Some(CachedFile {
        stamp: read.stamp,
        bytes: bytes.clone(),
    });
    Ok(bytes)
}

/// `blocked_pubs.json` through this process's cache: `None` when this
/// process keeps none for the profile (read the file); else its bytes as
/// last read, as they are on disk (sealed or plain; at most
/// `MAX_BLOCK_LIST_FILE_BYTES` + 1: the caller opens them and checks the
/// limit) or the read error.
pub(crate) fn cached_block_list(
    data_dir: &Path,
) -> Option<Result<Option<Zeroizing<Vec<u8>>>, String>> {
    let state = process_state(data_dir)?;
    if !lock_state(&state).cache {
        return None;
    }
    Some(
        read_through(&state, data_dir, Which::BlockList).map_err(|e| match e {
            BookError::Io(text) => text,
            other => other.to_string(),
        }),
    )
}

#[cfg(test)]
pub(crate) mod tests;
