//! The attachment store (`docs/design/2026-11-attachments.md` §14): one
//! sealed row per attachment, and its blob of sealed chunks.
//!
//! ```text
//! attachment_rows/<handle>.row   the row: who, which message, the key and the
//!                                root, the stored offer, the state. Sealed
//!                                with the profile (RMS1) like every sealed
//!                                file; plain in a profile that is not sealed.
//! attachments/<handle>/blob      the sealed chunks as they travel, back to
//!                                back (ciphertext under the attachment's own
//!                                key: it needs no second encryption)
//! attachments/<handle>/have      a friend's attachment only: one bit per
//!                                chunk that is here and checked
//! attachments_staging/<name>     a file an app wrote for Raven to send:
//!                                sealed into a blob and deleted at once
//! ```
//!
//! Folder names are handles, never roots: the root appears only in the
//! sealed row. A chunk is checked against the root with its audit path
//! before a byte of it is written, and written in the order of the update
//! exchange: the chunk at its place, a sync, then its bit. Progress changes
//! these files, never the history file.
//!
//! (The design sketched one SQLite file. A row of its own per attachment
//! keeps every write small, needs no table to re-seal and rides the sealed
//! file rules the profile already has: key rotation, unseal and erase find
//! the rows through the at-rest registry.)

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use super::blob::{self, Key, Sealed, Shape, HANDLE_LEN, KEY_LEN, SEGMENT_LEN};
use super::offer::{self, Offer, Ref};
use crate::at_rest::{self, Kind};
use crate::paths;
use crate::release_bundle::ChunkTree;

/// The folder of the rows.
pub const ROWS_DIR: &str = "attachment_rows";
/// The folder of the blob folders.
pub const BLOBS_DIR: &str = "attachments";
/// The folder an app writes a file into before `attachments.send`.
pub const STAGING_DIR: &str = "attachments_staging";
/// Every writer of a row takes it (`at_rest::FILES`); a chunk's bit too.
pub const ATTACHMENTS_LOCK: &str = ".attachments.lock.sqlite";
/// The sealed chunks of one attachment.
pub const BLOB_FILE: &str = "blob";
/// The bitmap of a friend's attachment.
pub const HAVE_FILE: &str = "have";
const ROW_EXT: &str = "row";
const ROW_VERSION: u8 = 1;
/// The most attachments a profile keeps rows for.
pub const MAX_ROWS: usize = 4_096;

/// Why the store refuses.
#[derive(Debug, Error)]
pub enum StoreError {
    /// A file could not be read or written.
    #[error("ATTACHMENT STORE: {0}")]
    Io(String),
    /// A row that does not read, or whose parts do not fit each other.
    #[error("ATTACHMENT STORE: row corrupt")]
    Corrupt,
    /// No such attachment.
    #[error("ATTACHMENT NOT_FOUND")]
    NotFound,
    /// A chunk index past the last, or bytes of the wrong length.
    #[error("ATTACHMENT RANGE")]
    Range,
    /// The store holds [`MAX_ROWS`] attachments.
    #[error("ATTACHMENT STORE: full")]
    Full,
}

fn io(e: impl std::fmt::Display) -> StoreError {
    StoreError::Io(e.to_string())
}

/// Where an attachment is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Mine: sealed and written; its offer is on its way.
    Staged,
    /// Mine: the friend has the offer, not yet every chunk.
    Offered,
    /// Mine: the friend's node has every chunk.
    Delivered,
    /// A friend's: the offer is here, chunks are missing.
    Incoming,
    /// A friend's: every chunk is here and checked.
    Complete,
    /// The author deleted it before every chunk was here.
    Gone,
    /// A check failed, or sending was given up.
    Failed,
}

/// The row of one attachment. A local file, not a frame: a member this
/// build does not know (a later build wrote the row) is passed over, so a
/// profile opened by an older build keeps its attachments.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    v: u8,
    /// The handle, in hex: the row's and the blob folder's name.
    pub handle: String,
    /// The id of the message that carries the offer, in hex.
    pub message_id: String,
    /// The friend, in hex (a chat); `None` in a group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// The group, in hex; `None` in a chat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Mine (true) or a friend's.
    pub outgoing: bool,
    key: String,
    root: String,
    /// SHA-256 of the offer as it travelled, in hex: a copy that comes
    /// again is compared with this, never with the stored form.
    pub offer_sha256: String,
    /// The stored `ref` frame: kind, sizes, type, name, caption, preview.
    pub reference: String,
    /// Where it is in its life.
    pub state: State,
    /// A friend's: the user asked for it (a file waits for that tap; a
    /// photo or a voice note comes by itself).
    #[serde(default, skip_serializing_if = "is_false")]
    pub asked: bool,
    /// Mine: how many chunks the friend's node said it has.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub friend_has: u32,
    /// Mine: when a send of its offer last set out (0: never). The link
    /// that carries the offer takes the chunks along right behind its
    /// answer, while this is fresh.
    #[serde(default, skip_serializing_if = "is_zero64")]
    pub going_ms: u64,
    /// When the row was made.
    pub created_ms: u64,
    /// When it last changed.
    pub updated_ms: u64,
}

impl std::fmt::Debug for Row {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Row")
            .field("handle", &self.handle)
            .field("outgoing", &self.outgoing)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Which chat an attachment belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chat<'a> {
    /// A friend's key.
    Friend(&'a [u8; 32]),
    /// A group's id.
    Group(&'a [u8; 16]),
}

impl Row {
    /// The row of an offer: `text` is the offer as it travels, for its
    /// digest. `None` for an offer with no blob (the empty profile form).
    pub fn of_offer(
        offer: &Offer,
        text: &str,
        chat: Chat<'_>,
        message_id: &[u8; 16],
        outgoing: bool,
        now_ms: u64,
    ) -> Option<Row> {
        let blob = offer.blob.as_ref()?;
        let (peer, group) = match chat {
            Chat::Friend(key) => (Some(hex::encode(key)), None),
            Chat::Group(id) => (None, Some(hex::encode(id))),
        };
        Some(Row {
            v: ROW_VERSION,
            handle: hex::encode(offer.handle),
            message_id: hex::encode(message_id),
            peer,
            group,
            outgoing,
            key: hex::encode(blob.key.bytes()),
            root: hex::encode(blob.root),
            offer_sha256: hex::encode(Sha256::digest(text.as_bytes())),
            reference: offer.stored().encode(),
            state: if outgoing {
                State::Staged
            } else {
                State::Incoming
            },
            asked: false,
            friend_has: 0,
            going_ms: 0,
            created_ms: now_ms,
            updated_ms: now_ms,
        })
    }

    /// The handle's bytes.
    pub fn handle_bytes(&self) -> Option<[u8; HANDLE_LEN]> {
        hex_n(&self.handle)
    }

    /// The key of the attachment.
    pub fn key(&self) -> Option<Key> {
        hex_n::<KEY_LEN>(&self.key).map(Key::from_bytes)
    }

    /// The root of its tree.
    pub fn root(&self) -> Option<[u8; 32]> {
        hex_n(&self.root)
    }

    /// The stored offer.
    pub fn stored(&self) -> Option<Ref> {
        offer::parse_ref(self.reference.as_bytes())
    }

    /// The sizes of the blob.
    pub fn shape(&self) -> Option<Shape> {
        self.stored()?.shape
    }

    /// The friend's key (a chat's attachment).
    pub fn peer_key(&self) -> Option<[u8; 32]> {
        self.peer.as_deref().and_then(hex_n)
    }

    /// The id of the message that carries the offer.
    pub fn message_id_bytes(&self) -> Option<[u8; 16]> {
        hex_n(&self.message_id)
    }

    fn well_formed(&self) -> bool {
        self.v == ROW_VERSION
            && self.handle_bytes().is_some()
            && hex_n::<16>(&self.message_id).is_some()
            && self.peer.is_some() != self.group.is_some()
            && self
                .peer
                .as_deref()
                .is_none_or(|p| hex_n::<32>(p).is_some())
            && self
                .group
                .as_deref()
                .is_none_or(|g| hex_n::<16>(g).is_some())
            && hex_n::<32>(&self.offer_sha256).is_some()
            && self.root().is_some()
            && self.shape().is_some()
            && self
                .key()
                .zip(self.handle_bytes())
                .is_some_and(|(key, handle)| key.handle() == handle)
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

fn is_zero64(n: &u64) -> bool {
    *n == 0
}

fn hex_n<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

fn row_path(data_dir: &Path, handle: &[u8; HANDLE_LEN]) -> PathBuf {
    data_dir
        .join(ROWS_DIR)
        .join(format!("{}.{ROW_EXT}", hex::encode(handle)))
}

/// The folder of one attachment's blob.
pub fn blob_dir(data_dir: &Path, handle: &[u8; HANDLE_LEN]) -> PathBuf {
    data_dir.join(BLOBS_DIR).join(hex::encode(handle))
}

fn blob_path(data_dir: &Path, handle: &[u8; HANDLE_LEN]) -> PathBuf {
    blob_dir(data_dir, handle).join(BLOB_FILE)
}

fn have_path(data_dir: &Path, handle: &[u8; HANDLE_LEN]) -> PathBuf {
    blob_dir(data_dir, handle).join(HAVE_FILE)
}

fn open_private(path: &Path, create: bool) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Writes a row: a new one, or over the one with its handle.
pub fn put(data_dir: &Path, row: &Row) -> Result<(), StoreError> {
    let handle = row
        .handle_bytes()
        .filter(|_| row.well_formed())
        .ok_or(StoreError::Corrupt)?;
    paths::ensure_private_dir(&data_dir.join(ROWS_DIR)).map_err(io)?;
    let path = row_path(data_dir, &handle);
    if !path.exists() && count(data_dir) >= MAX_ROWS {
        return Err(StoreError::Full);
    }
    at_rest::lock_file(data_dir, &path, Kind::Attachments)
        .and_then(|lock| lock.store_json(row))
        .map_err(io)
}

fn count(data_dir: &Path) -> usize {
    std::fs::read_dir(data_dir.join(ROWS_DIR)).map_or(0, |entries| entries.flatten().count())
}

/// The row of `handle`.
pub fn get(data_dir: &Path, handle: &[u8; HANDLE_LEN]) -> Result<Option<Row>, StoreError> {
    let row: Option<Row> =
        at_rest::load_json(data_dir, &row_path(data_dir, handle), Kind::Attachments)
            .map_err(|_| StoreError::Corrupt)?;
    match row {
        Some(row) if row.well_formed() && row.handle_bytes() == Some(*handle) => Ok(Some(row)),
        Some(_) => Err(StoreError::Corrupt),
        None => Ok(None),
    }
}

/// Every row that reads, oldest first; a row that does not read is left
/// out (and stays on disk for a look).
pub fn list(data_dir: &Path) -> Result<Vec<Row>, StoreError> {
    let Ok(entries) = std::fs::read_dir(data_dir.join(ROWS_DIR)) else {
        return Ok(Vec::new());
    };
    let mut rows = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(handle) = name
            .strip_suffix(&format!(".{ROW_EXT}"))
            .and_then(hex_n::<HANDLE_LEN>)
        else {
            continue;
        };
        if let Ok(Some(row)) = get(data_dir, &handle) {
            rows.push(row);
        }
    }
    rows.sort_by(|a, b| (a.created_ms, &a.handle).cmp(&(b.created_ms, &b.handle)));
    Ok(rows)
}

/// Changes the row of `handle` under its writer lock. `false`: no such row.
pub fn update(
    data_dir: &Path,
    handle: &[u8; HANDLE_LEN],
    now_ms: u64,
    change: impl FnOnce(&mut Row),
) -> Result<bool, StoreError> {
    let path = row_path(data_dir, handle);
    let lock = at_rest::lock_file(data_dir, &path, Kind::Attachments).map_err(io)?;
    let Some(mut row) = lock.load_json::<Row>().map_err(|_| StoreError::Corrupt)? else {
        return Ok(false);
    };
    let before = row.clone();
    change(&mut row);
    if row == before {
        return Ok(true);
    }
    row.updated_ms = now_ms;
    if !row.well_formed() || row.handle != before.handle {
        return Err(StoreError::Corrupt);
    }
    lock.store_json(&row).map_err(io)?;
    Ok(true)
}

/// Sets the state of `handle`'s row. `false`: no such row.
pub fn set_state(
    data_dir: &Path,
    handle: &[u8; HANDLE_LEN],
    state: State,
    now_ms: u64,
) -> Result<bool, StoreError> {
    update(data_dir, handle, now_ms, |row| row.state = state)
}

/// Removes an attachment: its row first (the key goes with it, so what a
/// disk keeps of the blob cannot be read), then its blob folder.
pub fn remove(data_dir: &Path, handle: &[u8; HANDLE_LEN]) -> Result<(), StoreError> {
    let path = row_path(data_dir, handle);
    if path.exists() {
        let _lock = at_rest::lock_file(data_dir, &path, Kind::Attachments).map_err(io)?;
        std::fs::remove_file(&path).map_err(io)?;
        paths::sync_dir_best_effort(&data_dir.join(ROWS_DIR));
    }
    let dir = blob_dir(data_dir, handle);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(io)?;
        paths::sync_dir_best_effort(&data_dir.join(BLOBS_DIR));
    }
    Ok(())
}

/// Writes the blob of an attachment of mine, whole.
pub fn write_blob(
    data_dir: &Path,
    handle: &[u8; HANDLE_LEN],
    sealed: &Sealed,
) -> Result<(), StoreError> {
    paths::ensure_private_dir(&data_dir.join(BLOBS_DIR)).map_err(io)?;
    paths::ensure_private_dir(&blob_dir(data_dir, handle)).map_err(io)?;
    paths::atomic_write_private(&blob_path(data_dir, handle), &sealed.blob).map_err(io)
}

/// Makes the room for a friend's attachment: a blob file of its full size
/// and an empty bitmap. Nothing changes when they are there already.
pub fn prepare_incoming(
    data_dir: &Path,
    handle: &[u8; HANDLE_LEN],
    shape: &Shape,
) -> Result<(), StoreError> {
    paths::ensure_private_dir(&data_dir.join(BLOBS_DIR)).map_err(io)?;
    paths::ensure_private_dir(&blob_dir(data_dir, handle)).map_err(io)?;
    let blob = blob_path(data_dir, handle);
    if !blob.exists() {
        let file = open_private(&blob, true).map_err(io)?;
        file.set_len(shape.sealed_len()).map_err(io)?;
        file.sync_all().map_err(io)?;
    }
    let have = have_path(data_dir, handle);
    if !have.exists() {
        paths::atomic_write_private(&have, &vec![0u8; bitmap_len(shape)]).map_err(io)?;
    }
    Ok(())
}

fn bitmap_len(shape: &Shape) -> usize {
    (shape.chunks() as usize).div_ceil(8)
}

/// Which chunks of an attachment are here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Have {
    bits: Vec<u8>,
    chunks: u32,
}

impl Have {
    /// Every chunk (an attachment of mine, or a complete one).
    pub fn all(shape: &Shape) -> Have {
        let mut have = Have {
            bits: vec![0u8; bitmap_len(shape)],
            chunks: shape.chunks(),
        };
        for index in 0..shape.chunks() {
            have.set(index);
        }
        have
    }

    /// Is chunk `index` here?
    pub fn has(&self, index: u32) -> bool {
        index < self.chunks && self.bits[(index / 8) as usize] & (1 << (index % 8)) != 0
    }

    fn set(&mut self, index: u32) {
        if index < self.chunks {
            self.bits[(index / 8) as usize] |= 1 << (index % 8);
        }
    }

    /// How many chunks are here.
    pub fn count(&self) -> u32 {
        (0..self.chunks).filter(|i| self.has(*i)).count() as u32
    }

    /// Is every chunk here?
    pub fn complete(&self) -> bool {
        self.count() == self.chunks
    }

    /// The chunks still missing, in order.
    pub fn missing(&self) -> Vec<u32> {
        (0..self.chunks).filter(|i| !self.has(*i)).collect()
    }

    /// The bitmap as it travels in a LACK: one bit per chunk still wanted.
    pub fn wanted_bits(&self) -> Vec<u8> {
        let mut bits = vec![0u8; self.bits.len()];
        for index in self.missing() {
            bits[(index / 8) as usize] |= 1 << (index % 8);
        }
        bits
    }
}

/// Which chunks of `handle` are here. An attachment of mine has all of
/// them once its blob is written.
pub fn have(
    data_dir: &Path,
    handle: &[u8; HANDLE_LEN],
    shape: &Shape,
    outgoing: bool,
) -> Result<Have, StoreError> {
    if outgoing {
        return match std::fs::metadata(blob_path(data_dir, handle)) {
            Ok(meta) if meta.len() == shape.sealed_len() => Ok(Have::all(shape)),
            _ => Err(StoreError::NotFound),
        };
    }
    let bits = match std::fs::read(have_path(data_dir, handle)) {
        Ok(bits) if bits.len() == bitmap_len(shape) => bits,
        Ok(_) => return Err(StoreError::Corrupt),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![0u8; bitmap_len(shape)],
        Err(e) => return Err(io(e)),
    };
    Ok(Have {
        bits,
        chunks: shape.chunks(),
    })
}

/// What became of a chunk that landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Taken {
    /// Written; `complete` when it was the last one missing.
    Written {
        /// Every chunk is here now.
        complete: bool,
    },
    /// It was here already; nothing was written.
    Already,
    /// It does not prove its place under the root: dropped.
    Bad,
}

/// Takes a chunk of a friend's attachment that landed, whoever sent it:
/// checked against `root` with its audit `path` first, then written at its
/// place, synced, and only then marked in the bitmap.
pub fn take_chunk(
    data_dir: &Path,
    handle: &[u8; HANDLE_LEN],
    shape: &Shape,
    root: &[u8; 32],
    index: u32,
    chunk: &[u8],
    path: &[[u8; 32]],
) -> Result<Taken, StoreError> {
    if !blob::check_chunk(root, shape, index, chunk, path) {
        return Ok(Taken::Bad);
    }
    let _lock = paths::DataDirLock::acquire(data_dir, ATTACHMENTS_LOCK).map_err(io)?;
    prepare_incoming(data_dir, handle, shape)?;
    let mut have = have(data_dir, handle, shape, false)?;
    if have.has(index) {
        return Ok(Taken::Already);
    }
    let offset = shape.chunk_offset(index).ok_or(StoreError::Range)?;
    let mut file = open_private(&blob_path(data_dir, handle), false).map_err(io)?;
    file.seek(SeekFrom::Start(offset)).map_err(io)?;
    file.write_all(chunk).map_err(io)?;
    file.sync_data().map_err(io)?;
    have.set(index);
    paths::atomic_write_private(&have_path(data_dir, handle), &have.bits).map_err(io)?;
    Ok(Taken::Written {
        complete: have.complete(),
    })
}

/// Chunk `index` of the blob as it travels. For a friend's attachment only
/// a chunk whose bit is set.
pub fn read_chunk(
    data_dir: &Path,
    handle: &[u8; HANDLE_LEN],
    shape: &Shape,
    outgoing: bool,
    index: u32,
) -> Result<Vec<u8>, StoreError> {
    let len = shape.chunk_len(index).ok_or(StoreError::Range)?;
    let offset = shape.chunk_offset(index).ok_or(StoreError::Range)?;
    if !have(data_dir, handle, shape, outgoing)?.has(index) {
        return Err(StoreError::NotFound);
    }
    let mut file =
        std::fs::File::open(blob_path(data_dir, handle)).map_err(|_| StoreError::NotFound)?;
    file.seek(SeekFrom::Start(offset)).map_err(io)?;
    let mut chunk = vec![0u8; len];
    file.read_exact(&mut chunk).map_err(io)?;
    Ok(chunk)
}

/// The tree over a whole blob that is here: what a node serving the
/// attachment takes each chunk's audit path from. Refused unless its root
/// is the row's.
pub fn tree(data_dir: &Path, row: &Row) -> Result<ChunkTree, StoreError> {
    let (handle, shape, root) = parts(row)?;
    if !have(data_dir, &handle, &shape, row.outgoing)?.complete() {
        return Err(StoreError::NotFound);
    }
    let mut leaves = Vec::with_capacity(shape.chunks() as usize);
    for index in 0..shape.chunks() {
        leaves.push(blob::leaf(&read_chunk(
            data_dir,
            &handle,
            &shape,
            row.outgoing,
            index,
        )?));
    }
    let tree = ChunkTree::of_leaf_hashes(leaves);
    if tree.root() != root {
        return Err(StoreError::Corrupt);
    }
    Ok(tree)
}

fn parts(row: &Row) -> Result<([u8; HANDLE_LEN], Shape, [u8; 32]), StoreError> {
    match (row.handle_bytes(), row.shape(), row.root()) {
        (Some(handle), Some(shape), Some(root)) => Ok((handle, shape, root)),
        _ => Err(StoreError::Corrupt),
    }
}

/// `length` bytes of the attachment's own bytes from `offset` (fewer at
/// the end), opened in memory chunk by chunk. Only a whole attachment is
/// read: mine, or a friend's that is complete.
pub fn read_plain(
    data_dir: &Path,
    row: &Row,
    offset: u64,
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let (handle, shape, _) = parts(row)?;
    let key = row.key().ok_or(StoreError::Corrupt)?;
    if !have(data_dir, &handle, &shape, row.outgoing)?.complete() {
        return Err(StoreError::NotFound);
    }
    if offset > shape.len() {
        return Err(StoreError::Range);
    }
    let end = shape.len().min(offset.saturating_add(length as u64));
    let mut out = Zeroizing::new(Vec::with_capacity((end - offset) as usize));
    let mut at = offset;
    while at < end {
        let index = u32::try_from(at / SEGMENT_LEN as u64).map_err(|_| StoreError::Range)?;
        let chunk = read_chunk(data_dir, &handle, &shape, row.outgoing, index)?;
        let segment =
            blob::open_chunk(&key, &shape, index, &chunk).map_err(|_| StoreError::Corrupt)?;
        let from = (at % SEGMENT_LEN as u64) as usize;
        let upto = segment.len().min(from + (end - at) as usize);
        out.extend_from_slice(&segment[from..upto]);
        at += (upto - from) as u64;
    }
    Ok(out)
}

/// Does a whole blob that is here open under the row's key, every chunk,
/// with nothing but zeros after its last byte? A chunk proves its place
/// under the root when it lands; this proves the root was made over this
/// attachment and not over other bytes.
pub fn opens(data_dir: &Path, row: &Row) -> Result<bool, StoreError> {
    let (handle, shape, _) = parts(row)?;
    let key = row.key().ok_or(StoreError::Corrupt)?;
    if !have(data_dir, &handle, &shape, row.outgoing)?.complete() {
        return Err(StoreError::NotFound);
    }
    for index in 0..shape.chunks() {
        let chunk = read_chunk(data_dir, &handle, &shape, row.outgoing, index)?;
        let Ok(segment) = blob::open_chunk(&key, &shape, index, &chunk) else {
            return Ok(false);
        };
        // What lies past the attachment's last byte is padding: zeros.
        let start = u64::from(index) * SEGMENT_LEN as u64;
        let own = shape.len().saturating_sub(start).min(segment.len() as u64) as usize;
        if segment[own..].iter().any(|b| *b != 0) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// How many of the attachment's own bytes are here (a friend's), or at the
/// friend's node as far as it said (mine); and how many there are.
pub fn progress(data_dir: &Path, row: &Row) -> (u64, u64) {
    let Some(shape) = row.shape() else {
        return (0, 0);
    };
    let chunks = if row.outgoing {
        row.friend_has.min(shape.chunks())
    } else {
        row.handle_bytes()
            .and_then(|handle| have(data_dir, &handle, &shape, false).ok())
            .map_or(0, |have| have.count())
    };
    let done = if chunks >= shape.chunks() {
        shape.len()
    } else {
        (u64::from(chunks) * SEGMENT_LEN as u64).min(shape.len())
    };
    (done, shape.len())
}

/// When a chunk of a friend's attachment last landed (the bitmap's time on
/// disk), in ms; 0 when none did.
pub fn last_chunk_ms(data_dir: &Path, handle: &[u8; HANDLE_LEN]) -> u64 {
    std::fs::metadata(have_path(data_dir, handle))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_millis() as u64)
}

/// The handles of the rows on disk and when each row's file last changed:
/// what a watcher compares with its last look, without opening a row.
pub fn rows_on_disk(data_dir: &Path) -> Vec<([u8; HANDLE_LEN], std::time::SystemTime)> {
    let Ok(entries) = std::fs::read_dir(data_dir.join(ROWS_DIR)) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let handle = name
                .strip_suffix(&format!(".{ROW_EXT}"))
                .and_then(hex_n::<HANDLE_LEN>)?;
            let changed = entry.metadata().and_then(|m| m.modified()).ok()?;
            Some((handle, changed))
        })
        .collect()
}

/// A new, empty file in the staging folder for an app to write what it
/// wants sent. `name` only gives the file its ending.
pub fn stage(data_dir: &Path, name: &str) -> Result<PathBuf, StoreError> {
    use rand::RngCore;
    let dir = data_dir.join(STAGING_DIR);
    paths::ensure_private_dir(&dir).map_err(io)?;
    let mut id = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut id);
    let ending: String = name
        .rsplit_once('.')
        .map(|(_, e)| e)
        .filter(|e| !e.is_empty() && e.len() <= 8 && e.bytes().all(|b| b.is_ascii_alphanumeric()))
        .map(|e| format!(".{}", e.to_ascii_lowercase()))
        .unwrap_or_default();
    let path = dir.join(format!("{}{ending}", hex::encode(id)));
    paths::create_new_private(&path, &[]).map_err(io)?;
    Ok(path)
}

/// Is `path` a file of this profile's staging folder (and nothing else,
/// whatever its name pretends)?
pub fn is_staged(data_dir: &Path, path: &Path) -> bool {
    let dir = data_dir.join(STAGING_DIR);
    path.parent() == Some(dir.as_path())
        && path.file_name().is_some()
        && std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attachment::offer::BlobRef;

    fn bytes(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 % 253) as u8).collect()
    }

    /// A photo of `len` bytes sealed under `seed`, its offer and its text.
    fn photo(seed: u8, len: usize) -> (Sealed, Offer, String) {
        let key = Key::from_bytes([seed; KEY_LEN]);
        let sealed = blob::seal(&key, &bytes(len)).unwrap();
        let blob = BlobRef {
            shape: sealed.shape,
            key,
            root: sealed.root(),
        };
        let offer = Offer::photo(blob, "hi", 640, 480, &[1, 2, 3]).unwrap();
        let text = offer.encode().unwrap();
        (sealed, offer, text)
    }

    const FRIEND: [u8; 32] = [9u8; 32];
    const MID: [u8; 16] = [5u8; 16];

    #[test]
    fn a_row_with_a_member_of_a_later_build_still_reads() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let (sealed, offer, text) = photo(3, 50_000);
        let row = Row::of_offer(&offer, &text, Chat::Friend(&FRIEND), &MID, true, 10).unwrap();
        put(d, &row).unwrap();
        write_blob(d, &offer.handle, &sealed).unwrap();
        // The row as a later build would write it: one member more.
        let path = row_path(d, &offer.handle);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        value["a_member_of_tomorrow"] = serde_json::json!({"n": 1});
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        assert_eq!(get(d, &offer.handle).unwrap(), Some(row));
    }

    #[test]
    fn a_row_is_written_read_changed_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let (sealed, offer, text) = photo(1, 200_000);
        let row = Row::of_offer(&offer, &text, Chat::Friend(&FRIEND), &MID, true, 10).unwrap();
        assert_eq!(row.state, State::Staged);
        assert_eq!(get(d, &offer.handle).unwrap(), None);
        put(d, &row).unwrap();
        write_blob(d, &offer.handle, &sealed).unwrap();
        let back = get(d, &offer.handle).unwrap().unwrap();
        assert_eq!(back, row);
        assert_eq!(back.key().unwrap().bytes(), &[1u8; KEY_LEN]);
        assert_eq!(back.root().unwrap(), sealed.root());
        assert_eq!(back.shape().unwrap(), sealed.shape);
        assert_eq!(back.stored().unwrap(), offer.stored());
        assert_eq!(
            back.offer_sha256,
            hex::encode(Sha256::digest(text.as_bytes()))
        );
        assert!(
            !format!("{back:?}").contains(&hex::encode([1u8; KEY_LEN])),
            "a row never prints its key"
        );
        assert!(set_state(d, &offer.handle, State::Offered, 20).unwrap());
        let back = get(d, &offer.handle).unwrap().unwrap();
        assert_eq!(
            (back.state, back.updated_ms, back.created_ms),
            (State::Offered, 20, 10)
        );
        assert_eq!(list(d).unwrap().len(), 1);
        // The stored row never holds the offer, only its stored form.
        assert!(!back.reference.contains("\"key\"") && !back.reference.contains("\"pad\""));
        remove(d, &offer.handle).unwrap();
        assert_eq!(get(d, &offer.handle).unwrap(), None);
        assert!(!blob_dir(d, &offer.handle).exists());
        assert!(list(d).unwrap().is_empty());
        assert!(!set_state(d, &offer.handle, State::Failed, 30).unwrap());
        // Removing what is not there is fine.
        remove(d, &offer.handle).unwrap();
    }

    #[test]
    fn an_attachment_of_mine_reads_back_whole_and_in_pieces() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let data = bytes(300_000);
        let (sealed, offer, text) = photo(2, data.len());
        let row = Row::of_offer(&offer, &text, Chat::Friend(&FRIEND), &MID, true, 1).unwrap();
        put(d, &row).unwrap();
        // No blob yet: nothing to read or serve.
        assert!(matches!(
            read_plain(d, &row, 0, 10),
            Err(StoreError::NotFound)
        ));
        write_blob(d, &offer.handle, &sealed).unwrap();
        assert!(have(d, &offer.handle, &sealed.shape, true)
            .unwrap()
            .complete());
        assert_eq!(&read_plain(d, &row, 0, 1_000_000).unwrap()[..], &data[..]);
        // Across a chunk edge, to the end, at the end, past the end.
        let edge = SEGMENT_LEN as u64 - 5;
        assert_eq!(
            &read_plain(d, &row, edge, 10).unwrap()[..],
            &data[edge as usize..edge as usize + 10]
        );
        assert_eq!(
            &read_plain(d, &row, 299_990, 100).unwrap()[..],
            &data[299_990..]
        );
        assert!(read_plain(d, &row, 300_000, 10).unwrap().is_empty());
        assert!(matches!(
            read_plain(d, &row, 300_001, 10),
            Err(StoreError::Range)
        ));
        // Each chunk as it travels, and the tree a node serves paths from.
        let tree = tree(d, &row).unwrap();
        assert_eq!(tree.root(), sealed.root());
        for index in 0..sealed.shape.chunks() {
            assert_eq!(
                read_chunk(d, &offer.handle, &sealed.shape, true, index).unwrap(),
                sealed.chunk(index).unwrap()
            );
        }
        assert!(matches!(
            read_chunk(d, &offer.handle, &sealed.shape, true, sealed.shape.chunks()),
            Err(StoreError::Range)
        ));
    }

    #[test]
    fn a_friends_attachment_fills_chunk_by_chunk_in_any_order_and_only_with_chunks_that_prove_their_place(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let data = bytes(250_000);
        let (sealed, offer, text) = photo(3, data.len());
        let row = Row::of_offer(&offer, &text, Chat::Friend(&FRIEND), &MID, false, 1).unwrap();
        assert_eq!(row.state, State::Incoming);
        put(d, &row).unwrap();
        let (shape, root) = (sealed.shape, sealed.root());
        let take = |index: u32, chunk: &[u8]| {
            take_chunk(
                d,
                &offer.handle,
                &shape,
                &root,
                index,
                chunk,
                &sealed.path(index).unwrap(),
            )
            .unwrap()
        };
        let n = shape.chunks();
        assert!(n >= 4);
        assert_eq!(have(d, &offer.handle, &shape, false).unwrap().count(), 0);
        // A changed chunk, a chunk at another place, another attachment's chunk: dropped.
        let mut bad = sealed.chunk(1).unwrap().to_vec();
        bad[10] ^= 1;
        assert_eq!(take(1, &bad), Taken::Bad);
        assert_eq!(take(2, sealed.chunk(1).unwrap()), Taken::Bad);
        let (other, _, _) = photo(4, data.len());
        assert_eq!(take(1, other.chunk(1).unwrap()), Taken::Bad);
        assert_eq!(have(d, &offer.handle, &shape, false).unwrap().count(), 0);
        // Not readable before it is whole.
        assert!(matches!(
            read_plain(d, &row, 0, 10),
            Err(StoreError::NotFound)
        ));
        // Out of order, one twice.
        let order: Vec<u32> = (0..n).rev().collect();
        for (k, index) in order.iter().enumerate() {
            let last = k + 1 == order.len();
            assert_eq!(
                take(*index, sealed.chunk(*index).unwrap()),
                Taken::Written { complete: last },
                "{index}"
            );
            assert_eq!(take(*index, sealed.chunk(*index).unwrap()), Taken::Already);
            let have = have(d, &offer.handle, &shape, false).unwrap();
            assert_eq!(have.count(), k as u32 + 1);
            assert!(have.has(*index));
            assert_eq!(have.missing().len(), (n as usize) - k - 1);
            // A chunk that is not here is not served; one that is, is.
            if !last {
                assert!(matches!(
                    read_chunk(d, &offer.handle, &shape, false, 0),
                    Err(StoreError::NotFound)
                ));
            }
            assert_eq!(
                read_chunk(d, &offer.handle, &shape, false, *index).unwrap(),
                sealed.chunk(*index).unwrap()
            );
        }
        let have = have(d, &offer.handle, &shape, false).unwrap();
        assert!(have.complete() && have.wanted_bits().iter().all(|b| *b == 0));
        assert_eq!(&read_plain(d, &row, 0, usize::MAX).unwrap()[..], &data[..]);
        assert_eq!(tree(d, &row).unwrap().root(), root);
    }

    #[test]
    fn what_is_still_wanted_is_one_bit_a_chunk() {
        let shape = Shape::of(1_048_576).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let handle = [1u8; HANDLE_LEN];
        let none = have(dir.path(), &handle, &shape, false).unwrap();
        assert_eq!(none.count(), 0);
        assert_eq!(none.wanted_bits().len(), 3);
        assert_eq!(none.wanted_bits(), vec![0xFF, 0xFF, 0x03], "18 chunks");
        let all = Have::all(&shape);
        assert!(all.complete() && all.missing().is_empty());
        assert!(!all.has(18));
        // An attachment of mine without its blob has nothing.
        assert!(matches!(
            have(dir.path(), &handle, &shape, true),
            Err(StoreError::NotFound)
        ));
    }

    #[test]
    fn a_row_whose_parts_do_not_fit_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let (_, offer, text) = photo(5, 100_000);
        let row = Row::of_offer(&offer, &text, Chat::Group(&[7u8; 16]), &MID, false, 1).unwrap();
        assert!(row.peer.is_none() && row.group.is_some());
        put(d, &row).unwrap();
        // Another attachment's key under this handle.
        let mut wrong = row.clone();
        wrong.key = hex::encode([6u8; KEY_LEN]);
        assert!(matches!(put(d, &wrong), Err(StoreError::Corrupt)));
        // Both a friend and a group, or neither.
        let mut both = row.clone();
        both.peer = Some(hex::encode(FRIEND));
        assert!(matches!(put(d, &both), Err(StoreError::Corrupt)));
        let mut neither = row.clone();
        neither.group = None;
        assert!(matches!(put(d, &neither), Err(StoreError::Corrupt)));
        // A change that would break the row is not written.
        assert!(matches!(
            update(d, &offer.handle, 5, |r| r.reference =
                "RVNATT/1 ref\n{}".into()),
            Err(StoreError::Corrupt)
        ));
        assert_eq!(get(d, &offer.handle).unwrap().unwrap(), row);
        // The empty profile form has no blob and so no row.
        let none = Offer::no_profile([1; HANDLE_LEN], 5, 0).unwrap();
        assert!(Row::of_offer(
            &none,
            &none.encode().unwrap(),
            Chat::Friend(&FRIEND),
            &MID,
            false,
            1
        )
        .is_none());
    }

    #[test]
    fn a_staged_file_is_a_new_empty_file_of_the_staging_folder() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let a = stage(d, "photo.JPG").unwrap();
        let b = stage(d, "no ending").unwrap();
        let c = stage(d, "x.../../evil").unwrap();
        assert_ne!(a, b);
        assert!(a.to_string_lossy().ends_with(".jpg"));
        for path in [&a, &b, &c] {
            assert!(is_staged(d, path), "{path:?}");
            assert_eq!(std::fs::metadata(path).unwrap().len(), 0);
            assert_eq!(path.parent().unwrap(), d.join(STAGING_DIR));
        }
        assert!(!is_staged(d, &d.join("contacts.json")));
        assert!(!is_staged(d, &d.join(STAGING_DIR).join("missing")));
        assert!(!is_staged(
            d,
            &d.join(STAGING_DIR).join("..").join("contacts.json")
        ));
    }
}
