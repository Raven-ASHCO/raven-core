//! The releases friends offered this computer and the person's download
//! approvals (`docs/roadmap/plans/phase6-design.json` step P6.49; design D
//! §6, owner decisions OD6b-24 and OD6b-25): what raven-node's update
//! exchange (RUP1, [`crate::update_exchange`]) and `raven update download`
//! share.
//!
//! - **Offers.** A pinned contact's HAVE that offers a release for this
//!   computer's target with a build serial above the installed one becomes a
//!   row ([`Downloads::note_offer`]): the release's manifest digest, build
//!   serial, target and size, and the friends who offered it. Nothing is
//!   fetched for it yet.
//! - **Approval.** The person approves a row (`raven update download`, or
//!   the terminal app; [`approve`]); raven-node is woken (IPC
//!   `UpdateKick`) and fetches the manifest first, then the chunks, into
//!   [`INCOMING_DIR`]`/<digest>/` ([`incoming_dir`]), checking each before
//!   it is written. A complete download is verified in full and the row
//!   says so; installing it is a separate approval in the CLI or the
//!   terminal app, which stage it first.
//! - **Storage.** [`INCOMING_DIR`] holds at most [`MAX_INCOMING_BYTES`]; a
//!   download untouched for [`INCOMING_IDLE_MS`] is removed.
//!   [`QUARANTINE_DIR`] keeps what failed its checks, at most
//!   [`MAX_QUARANTINE_BYTES`] for [`QUARANTINE_AGE_MS`], counted, never run
//!   or shown.
//!
//! The rows name contacts, so [`DOWNLOADS_FILE`] is RMS1 kind 120 in a
//! sealed profile (`at_rest::FILES`) and plain JSON (0600) in a plain one,
//! written under its own lock ([`DOWNLOADS_LOCK`]) by raven-node (offers,
//! progress) and ash (approvals, staging). An advisory file: one this
//! process cannot read reads as empty and is never written over. At most
//! [`MAX_ROWS`] rows and [`MAX_FROM`] friends a row are kept. Nothing reads
//! or writes it while [`SecGate::MeshUpdate`] is shut.
//!
//! [`LAB_UPDATE_AUTO_APPROVE`] (debug builds with the Lab Test A unlock
//! only) approves every offer as it arrives and lets `raven update install`
//! go on without the typed word, for the update harness (P6.51, C89); a
//! release build never reads it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::at_rest::{self, Advisory, Kind};
use crate::release_bundle::THIS_TARGET;
use crate::security_gate::{self, SecGate};
use crate::update_exchange::Offer;

/// The file, below the profile folder.
pub const DOWNLOADS_FILE: &str = "updates/downloads";
/// Every writer of [`DOWNLOADS_FILE`] takes it (`at_rest::FILES`).
pub const DOWNLOADS_LOCK: &str = ".at_rest.update_downloads.lock.sqlite";
/// Downloads under way or complete: `<manifest digest hex>/` each.
pub const INCOMING_DIR: &str = "updates/incoming";
/// What failed its checks: kept a while, counted, never run or shown.
pub const QUARANTINE_DIR: &str = "updates/quarantine";
/// A download's verified manifest, in its folder.
pub const INCOMING_MANIFEST: &str = "manifest.rrb1";
/// The log snapshot that listed the manifest, in its folder.
pub const INCOMING_SNAPSHOT: &str = "snapshot.rtl1";
/// The payload as it arrives: `payload_len` bytes, each chunk written at its
/// offset once its audit path checked.
pub const INCOMING_PAYLOAD: &str = "payload";
/// Which chunks are written: one bit per chunk, chunk 0 the high bit of
/// byte 0.
pub const INCOMING_CHUNKS: &str = "chunks";
/// Written (empty) once every chunk arrived and the whole release verified:
/// raven-node serves the folder from then on.
pub const INCOMING_VERIFIED: &str = "verified";
/// The most [`INCOMING_DIR`] holds (design D §6).
pub const MAX_INCOMING_BYTES: u64 = 256 * 1024 * 1024;
/// A download untouched this long is removed (design D §6: 7 idle days).
pub const INCOMING_IDLE_MS: u64 = 7 * DAY_MS;
/// The most [`QUARANTINE_DIR`] holds (design D §6).
pub const MAX_QUARANTINE_BYTES: u64 = 64 * 1024 * 1024;
/// What [`QUARANTINE_DIR`] holds goes after this (design D §6: 7 days).
pub const QUARANTINE_AGE_MS: u64 = 7 * DAY_MS;
/// Rows kept at most: past it, the oldest offer not approved goes first.
pub const MAX_ROWS: usize = 16;
/// Friends kept per row at most (the latest first).
pub const MAX_FROM: usize = 8;
/// The format of [`DOWNLOADS_FILE`] this build writes.
pub const DOWNLOADS_VERSION: u32 = 1;
/// A row's `failed` code when [`INCOMING_DIR`] had no room for it
/// (raven-node): nothing about the friend's copy.
pub const FAILED_NO_ROOM: &str = "NO_ROOM";
/// A row's `failed` code when a complete, checked download could not be
/// staged on this computer (the CLI or the terminal app: an install, a
/// security notice or a freeze since it was checked): nothing about the
/// friend's copy either.
pub const FAILED_NOT_STAGED: &str = "NOT_STAGED";

/// A row's `failed` code when no release log listed the release: neither
/// the one the friend sent with it nor the one this computer has (the
/// manifest is unlogged, or under another key set no log lists), and no
/// other friend that offered it was left to ask (Phase 6 review re-verify,
/// updates-protocol-6). That is no proof the release itself is bad (its
/// log may be newer than any seen here), so raven-node approves it again by
/// itself once the stored log lists it, or a friend it may ask offers it.
pub const FAILED_NOT_LOGGED: &str = "NOT_LOGGED";

/// Does a row's `failed` code name a cause on this computer rather than
/// the friend's copy (Phase 6 review updates-protocol-7)? `REFUSED` is what
/// staging wrote before that code had a name of its own.
pub fn failed_here(code: &str) -> bool {
    matches!(code, FAILED_NO_ROOM | FAILED_NOT_STAGED | "REFUSED")
}

const DAY_MS: u64 = 86_400_000;

/// `=1` (debug, with `RAVEN_LAB_TEST_A=1`): every offer is approved as it
/// arrives, and `raven update install` needs no typed word (P6.51's C89).
pub const LAB_UPDATE_AUTO_APPROVE: &str = "RAVEN_LAB_UPDATE_AUTO_APPROVE";

/// The lab auto-approval is on: a debug build with the Lab Test A unlock and
/// [`LAB_UPDATE_AUTO_APPROVE`] exactly `1` (or this thread's override). A
/// release build reads nothing.
pub fn lab_auto_approve() -> bool {
    cfg!(debug_assertions)
        && AUTO_APPROVE_OVERRIDE
            .with(std::cell::Cell::get)
            .unwrap_or_else(|| {
                lab_auto_approve_from(true, crate::pair_init::lab_test_a_enabled, || {
                    std::env::var(LAB_UPDATE_AUTO_APPROVE).ok()
                })
            })
}

/// [`lab_auto_approve`] with the build, the unlock and the variable passed
/// in: neither is called in a release build.
fn lab_auto_approve_from(
    debug: bool,
    test_a: impl FnOnce() -> bool,
    value: impl FnOnce() -> Option<String>,
) -> bool {
    debug && test_a() && crate::p2p_gate::lab_flag(true, value)
}

thread_local! {
    static AUTO_APPROVE_OVERRIDE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// In-process tests turn the lab auto-approval on or off for the current
/// thread only, in place of the variable (`None`: the variable again).
/// Ignored in release builds, like the variable.
#[doc(hidden)]
pub fn set_lab_auto_approve_for_this_thread(on: Option<bool>) {
    AUTO_APPROVE_OVERRIDE.with(|cell| cell.set(on));
}

/// Where a download stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowState {
    /// A friend offered it; the person has not approved it.
    Offered,
    /// Approved: raven-node fetches it (the manifest first).
    Approved,
    /// The manifest verified; chunks are coming in.
    Downloading,
    /// Every chunk arrived and the whole release verified: it waits for the
    /// install approval (the CLI or the terminal app stage it first).
    Complete,
    /// The CLI or the terminal app staged it (`updates/staged/<serial>/`)
    /// and removed its folder in [`INCOMING_DIR`].
    Staged,
    /// It failed its checks (`failed` says which); its pieces went to
    /// [`QUARANTINE_DIR`].
    Failed,
}

impl RowState {
    /// The name the CLI and the tests use.
    pub fn name(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Approved => "approved",
            Self::Downloading => "downloading",
            Self::Complete => "complete",
            Self::Staged => "staged",
            Self::Failed => "failed",
        }
    }
}

/// One release offered to this computer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    /// The manifest's digest: RUP1 names the bundle by it.
    #[serde(with = "crate::update_state::hex_array")]
    pub digest: [u8; 32],
    pub build_serial: u64,
    pub target: String,
    pub payload_len: u64,
    /// The pinned contacts (device keys) that offered it, the latest first.
    #[serde(with = "crate::update_state::hex_list")]
    pub from: Vec<[u8; 32]>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub state: RowState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_ms: Option<u64>,
    /// The release's version, once its manifest verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Chunks written so far, of `chunks_total` (0 until the manifest).
    #[serde(default)]
    pub chunks_have: u32,
    #[serde(default)]
    pub chunks_total: u32,
    /// Why it failed (a stable code), while [`RowState::Failed`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<String>,
}

impl Row {
    /// The friend who offered it last.
    pub fn offered_by(&self) -> Option<&[u8; 32]> {
        self.from.first()
    }

    /// Approved and not finished: raven-node fetches it.
    pub fn wanted(&self) -> bool {
        matches!(self.state, RowState::Approved | RowState::Downloading)
    }
}

/// The file's JSON.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Downloads {
    #[serde(default)]
    pub v: u32,
    #[serde(default)]
    pub rows: Vec<Row>,
}

/// Why an approval was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApproveError {
    /// No row has that digest (or prefix).
    Unknown,
    /// More than one row starts with that prefix.
    Ambiguous,
    /// It is approved, downloading, complete or staged already.
    Already(RowState),
}

/// Is `offer` a release for this computer newer than `installed` (design D
/// §6: offers for this target with a newer build serial raise the prompt)?
pub fn for_this_computer(offer: &Offer, installed: u64) -> bool {
    offer.target == THIS_TARGET && offer.build_serial > installed
}

impl Downloads {
    /// Note `peer`'s offer (one for this computer: [`for_this_computer`]) at
    /// `now_ms`: a new row, or the friend added to its row. `true`: the rows
    /// changed. The lab auto-approval approves a new row at once.
    pub fn note_offer(&mut self, peer: &[u8; 32], offer: &Offer, now_ms: u64) -> bool {
        if let Some(row) = self
            .rows
            .iter_mut()
            .find(|r| r.digest == offer.manifest_digest)
        {
            let changed = row.from.first() != Some(peer);
            if changed {
                row.from.retain(|f| f != peer);
                row.from.insert(0, *peer);
                row.from.truncate(MAX_FROM);
            }
            // Seen again: only the day counts (no write per link), so the
            // time moves only with a change that is written anyway.
            let day_changed = row.last_seen_ms / DAY_MS != now_ms / DAY_MS;
            if changed || day_changed {
                row.last_seen_ms = row.last_seen_ms.max(now_ms);
            }
            return changed || day_changed;
        }
        let auto = lab_auto_approve();
        self.rows.push(Row {
            digest: offer.manifest_digest,
            build_serial: offer.build_serial,
            target: offer.target.clone(),
            payload_len: offer.payload_len,
            from: vec![*peer],
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            state: if auto {
                RowState::Approved
            } else {
                RowState::Offered
            },
            approved_ms: auto.then_some(now_ms),
            version: None,
            chunks_have: 0,
            chunks_total: 0,
            failed: None,
        });
        self.bound();
        true
    }

    /// Approve the row whose digest starts with `prefix` (lowercase hex,
    /// at least 1 digit; the whole digest names it exactly) at `now_ms`.
    pub fn approve(&mut self, prefix: &str, now_ms: u64) -> Result<&Row, ApproveError> {
        let prefix = prefix.trim().to_ascii_lowercase();
        let mut found = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| !prefix.is_empty() && hex::encode(r.digest).starts_with(&prefix));
        let (at, _) = found.next().ok_or(ApproveError::Unknown)?;
        if found.next().is_some() {
            return Err(ApproveError::Ambiguous);
        }
        let row = &mut self.rows[at];
        match row.state {
            RowState::Offered | RowState::Failed => {
                row.state = RowState::Approved;
                row.approved_ms = Some(now_ms);
                row.failed = None;
                Ok(&self.rows[at])
            }
            other => Err(ApproveError::Already(other)),
        }
    }

    /// The row of `digest`.
    pub fn row(&self, digest: &[u8; 32]) -> Option<&Row> {
        self.rows.iter().find(|r| r.digest == *digest)
    }

    /// The row of `digest`, to change.
    pub fn row_mut(&mut self, digest: &[u8; 32]) -> Option<&mut Row> {
        self.rows.iter_mut().find(|r| r.digest == *digest)
    }

    /// Forget the rows a build at `installed` no longer needs: offers and
    /// unfinished downloads of builds not above it. Complete rows stay
    /// while their folder does (raven-node serves them to friends).
    pub fn forget_installed(&mut self, installed: u64) -> bool {
        let before = self.rows.len();
        self.rows
            .retain(|r| r.build_serial > installed || r.state == RowState::Complete);
        self.rows.len() != before
    }

    /// Keep at most [`MAX_ROWS`]: the oldest offers not approved go first,
    /// then the oldest of the rest.
    fn bound(&mut self) {
        while self.rows.len() > MAX_ROWS {
            let at = self
                .rows
                .iter()
                .enumerate()
                .filter(|(_, r)| r.state == RowState::Offered)
                .min_by_key(|(_, r)| r.last_seen_ms)
                .or_else(|| {
                    self.rows
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, r)| r.last_seen_ms)
                })
                .map(|(i, _)| i)
                .expect("more rows than the cap");
            self.rows.remove(at);
        }
    }
}

fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(DOWNLOADS_FILE)
}

fn file_error(e: impl std::fmt::Display) -> String {
    format!("{DOWNLOADS_FILE}: {e}")
}

/// The rows; empty for a missing file or plain bytes that do not parse, an
/// error for a file this process cannot read. Empty while the mesh-update
/// gate is shut.
pub fn load(data_dir: &Path) -> Result<Downloads, String> {
    if !security_gate::live(SecGate::MeshUpdate) {
        return Ok(Downloads::default());
    }
    match at_rest::load_json_advisory::<Downloads>(data_dir, &path(data_dir), Kind::UpdateDownloads)
    {
        Advisory::Missing | Advisory::CorruptPlain => Ok(Downloads::default()),
        Advisory::Loaded(rows) if rows.v > DOWNLOADS_VERSION => Err(file_error("a later format")),
        Advisory::Loaded(rows) => Ok(rows),
        Advisory::Unreadable(e) => Err(file_error(e)),
    }
}

/// Change the rows under their lock: written only when `edit` changed them.
/// Nothing while the mesh-update gate is shut.
pub fn change<T>(data_dir: &Path, edit: impl FnOnce(&mut Downloads) -> T) -> Result<T, String> {
    if !security_gate::live(SecGate::MeshUpdate) {
        return Err(file_error("updates from friends are off"));
    }
    let path = path(data_dir);
    let lock = at_rest::lock_file(data_dir, &path, Kind::UpdateDownloads).map_err(file_error)?;
    let mut rows: Downloads =
        at_rest::load_json_for_write(data_dir, &path, Kind::UpdateDownloads).map_err(file_error)?;
    if rows.v > DOWNLOADS_VERSION {
        return Err(file_error("a later format"));
    }
    let before = rows.clone();
    let out = edit(&mut rows);
    if rows != before {
        rows.v = DOWNLOADS_VERSION;
        lock.store_json(&rows).map_err(file_error)?;
    }
    Ok(out)
}

/// Approve the row whose digest starts with `prefix` ([`Downloads::approve`])
/// and write it: the approved row.
pub fn approve(
    data_dir: &Path,
    prefix: &str,
    now_ms: u64,
) -> Result<Result<Row, ApproveError>, String> {
    change(data_dir, |rows| rows.approve(prefix, now_ms).cloned())
}

/// A download's folder: [`INCOMING_DIR`]`/<digest hex>/`.
pub fn incoming_dir(data_dir: &Path, digest: &[u8; 32]) -> PathBuf {
    data_dir.join(INCOMING_DIR).join(hex::encode(digest))
}

/// Chunk `index`'s bit in a bitmap of `bitmap.len()` bytes.
pub fn chunk_written(bitmap: &[u8], index: u64) -> bool {
    usize::try_from(index / 8)
        .ok()
        .and_then(|at| bitmap.get(at))
        .is_some_and(|b| b & (0x80 >> (index % 8)) != 0)
}

/// Mark chunk `index` written in `bitmap`.
pub fn mark_chunk(bitmap: &mut [u8], index: u64) {
    if let Some(b) = usize::try_from(index / 8)
        .ok()
        .and_then(|at| bitmap.get_mut(at))
    {
        *b |= 0x80 >> (index % 8);
    }
}

/// The bytes of a bitmap of `chunks` chunks.
pub fn bitmap_len(chunks: u64) -> usize {
    usize::try_from(chunks.div_ceil(8)).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests;
