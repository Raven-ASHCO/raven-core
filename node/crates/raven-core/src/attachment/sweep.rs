//! An attachment goes with its message
//! (`docs/design/2026-11-attachments.md` §14).
//!
//! The history is the list of what a profile keeps: a message that was
//! deleted, cleared with its chat, aged out by the retention setting or
//! pushed out by the history's own limit is no longer in it. [`sweep`]
//! removes every attachment whose message is gone: its row first (the key
//! goes with it, so what a disk keeps of the blob cannot be read), then its
//! blob. It also removes what was left half done: a blob folder with no
//! row, and a staged file nobody sent.
//!
//! Nothing is removed that may still get its message: an attachment of
//! mine whose message is being made (its row has no message id yet) is
//! kept for an hour, and any row for a minute after it was written (a
//! friend's offer gets its row a moment before its history row).
//!
//! raven-node sweeps when it starts and every hour. An app that deletes a
//! message removes its attachment itself ([`store::remove`]), and one that
//! clears or deletes a chat removes that friend's ([`forget_peer`]), so
//! they are gone at once.

use std::collections::HashSet;
use std::path::Path;
use std::time::{Duration, SystemTime};

use super::blob::HANDLE_LEN;
use super::offer::{self, Frame};
use super::store::{self, StoreError, BLOBS_DIR, STAGING_DIR};
use crate::chat_history::ChatHistory;

/// A row is never removed sooner than this after it was written.
pub const ROW_GRACE_MS: u64 = 60_000;
/// An attachment of mine whose message was never made, and a blob folder
/// with no row, are removed after this.
pub const UNSENT_GRACE_MS: u64 = 3_600_000;
/// A staged file nobody sent is removed after this. It is the photo as the
/// app wrote it, not sealed: an app writes it and sends it within moments,
/// so one this old was left behind (the app ended in between).
pub const STAGED_GRACE_MS: u64 = 600_000;

/// What a sweep removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Swept {
    /// Attachments whose message is gone (row and blob).
    pub attachments: usize,
    /// Blob folders that had no row.
    pub blobs: usize,
    /// Staged files nobody sent.
    pub staged: usize,
}

impl Swept {
    /// Was anything removed?
    pub fn any(&self) -> bool {
        self.attachments + self.blobs + self.staged > 0
    }
}

/// The handle a history body names: of a stored form, or of an offer kept
/// as it came.
fn handle_of(body: &str) -> Option<[u8; HANDLE_LEN]> {
    if !offer::is_att_text(body.as_bytes()) {
        return None;
    }
    if let Some(stored) = offer::parse_ref(body.as_bytes()) {
        return Some(stored.handle);
    }
    match offer::parse_frame(body.as_bytes())? {
        Frame::Offer(offer) => Some(offer.handle),
        Frame::Gone(_) => None,
    }
}

fn older_than(at: SystemTime, age_ms: u64, now: SystemTime) -> bool {
    now.duration_since(at)
        .is_ok_and(|d| d >= Duration::from_millis(age_ms))
}

/// Removes every attachment of the chat with the friend `peer`, at once:
/// what clearing or deleting that chat calls, so nothing waits for the
/// next sweep. The attachments removed. A profile picture is not a chat's:
/// it belongs to the friend, and stays ([`super::picture`]).
pub fn forget_peer(data_dir: &Path, peer: &[u8; 32]) -> Result<usize, StoreError> {
    let mut removed = 0;
    for (handle, _) in store::rows_on_disk(data_dir) {
        let theirs = matches!(
            store::get(data_dir, &handle),
            Ok(Some(row)) if row.peer_key() == Some(*peer) && !super::picture::is_picture_row(&row)
        );
        if theirs {
            store::remove(data_dir, &handle)?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Removes every attachment whose message the history no longer holds,
/// and what was left half done. Without a readable history nothing is
/// removed. Rows of group attachments are left alone (their messages live
/// in the group store), and so is a profile picture's row while the
/// picture files name it: it follows its friend, not a message.
pub fn sweep(data_dir: &Path, now_ms: u64) -> Result<Swept, StoreError> {
    let mut swept = Swept::default();
    let rows = store::rows_on_disk(data_dir);
    let blobs_dir = data_dir.join(BLOBS_DIR);
    let staging_dir = data_dir.join(STAGING_DIR);
    if rows.is_empty() && !blobs_dir.exists() && !staging_dir.exists() {
        // A profile with no attachments pays nothing: no history read.
        return Ok(swept);
    }
    let history = ChatHistory::load(data_dir).map_err(|e| StoreError::Io(e.to_string()))?;
    let named: HashSet<[u8; HANDLE_LEN]> = history
        .entries
        .iter()
        .filter_map(|e| handle_of(&e.body))
        .collect();
    let mut kept: HashSet<[u8; HANDLE_LEN]> = HashSet::new();
    // The rows the picture files name: read only when a picture's row is met.
    let mut pictures: Option<HashSet<[u8; HANDLE_LEN]>> = None;
    for (handle, _) in rows {
        if named.contains(&handle) {
            kept.insert(handle);
            continue;
        }
        let row = match store::get(data_dir, &handle) {
            Ok(Some(row)) => row,
            // A row that does not read stays for a look, with its blob.
            _ => {
                kept.insert(handle);
                continue;
            }
        };
        let age = now_ms.saturating_sub(row.created_ms);
        let unsent = row.outgoing && row.message_id_bytes() == Some([0u8; 16]);
        let grace = if unsent {
            UNSENT_GRACE_MS
        } else {
            ROW_GRACE_MS
        };
        let pictures_own = super::picture::is_picture_row(&row)
            && pictures
                .get_or_insert_with(|| super::picture::handles(data_dir))
                .contains(&handle);
        if row.group.is_some() || pictures_own || age < grace {
            kept.insert(handle);
            continue;
        }
        store::remove(data_dir, &handle)?;
        swept.attachments += 1;
    }
    // Against file times the OS stamped: the system's own clock, not a moved test clock.
    let now = crate::clock::system_now();
    // Blob folders with no row: a write that stopped half way.
    if let Ok(entries) = std::fs::read_dir(&blobs_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let mut handle = [0u8; HANDLE_LEN];
            let known = name.len() == 2 * HANDLE_LEN
                && hex::decode_to_slice(&name, &mut handle).is_ok()
                && (kept.contains(&handle)
                    || store::get(data_dir, &handle).is_ok_and(|r| r.is_some()));
            let old = entry
                .metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|at| older_than(at, UNSENT_GRACE_MS, now));
            if !known && old && std::fs::remove_dir_all(entry.path()).is_ok() {
                swept.blobs += 1;
            }
        }
    }
    // Staged files nobody sent.
    if let Ok(entries) = std::fs::read_dir(&staging_dir) {
        for entry in entries.flatten() {
            let old = entry
                .metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|at| older_than(at, STAGED_GRACE_MS, now));
            if old && std::fs::remove_file(entry.path()).is_ok() {
                swept.staged += 1;
            }
        }
    }
    Ok(swept)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attachment::flow::{self, Media};
    use crate::attachment::store::Row;
    use crate::attachment_gate;

    const FRIEND: [u8; 32] = [7u8; 32];

    struct Live;
    impl Live {
        fn on() -> Option<Live> {
            cfg!(debug_assertions).then(|| {
                attachment_gate::set_lab_attachments_for_this_thread(Some(true));
                Live
            })
        }
    }
    impl Drop for Live {
        fn drop(&mut self) {
            attachment_gate::set_lab_attachments_for_this_thread(None);
        }
    }

    fn jpeg(len: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = (0..len).map(|i| (i * 11 % 239) as u8).collect();
        bytes[..3].copy_from_slice(&[0xFF, 0xD8, 0xFF]);
        bytes
    }

    fn photo<'a>() -> Media<'a> {
        Media::Photo {
            caption: "",
            width: 100,
            height: 100,
            preview: &[1],
        }
    }

    /// A photo of mine sent as message `mid`: its row, its blob and its
    /// history row.
    fn sent_photo(d: &Path, mid: u8, now: u64) -> Row {
        let made = flow::prepare(d, &FRIEND, &jpeg(50_000), &photo(), now).unwrap();
        flow::sent(d, &made.handle, &[mid; 16], now).unwrap();
        crate::lan_dispatch::persist_lan_chat_history(
            d,
            "out",
            &FRIEND,
            &[mid; 16],
            now,
            "queued",
            made.offer.as_bytes(),
        )
        .unwrap();
        store::get(d, &made.handle).unwrap().unwrap()
    }

    fn exists(d: &Path, row: &Row) -> bool {
        let handle = row.handle_bytes().unwrap();
        store::get(d, &handle).unwrap().is_some() && store::blob_dir(d, &handle).exists()
    }

    #[test]
    fn a_profile_without_attachments_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(sweep(dir.path(), 1).unwrap(), Swept::default());
        assert!(!crate::chat_history::history_path(dir.path()).exists());
    }

    #[test]
    fn an_attachment_goes_when_its_message_is_gone_and_stays_while_it_is_there() {
        let Some(_live) = Live::on() else { return };
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::write(
            d.join("contacts.json"),
            format!(
                r#"[{{"petname":"Friend","pub_hex":"{}","address":"","pinned":true}}]"#,
                hex::encode(FRIEND)
            ),
        )
        .unwrap();
        let now = crate::clock::now_ms();
        let (first, second) = (sent_photo(d, 1, now), sent_photo(d, 2, now));
        // Both messages are there: nothing goes, however old the rows.
        assert_eq!(
            sweep(d, now + 10 * UNSENT_GRACE_MS).unwrap(),
            Swept::default()
        );
        assert!(exists(d, &first) && exists(d, &second));
        // The first message is deleted from the history.
        let mut history = ChatHistory::load(d).unwrap();
        history
            .entries
            .retain(|e| e.message_id_hex != hex::encode([1u8; 16]));
        history.save(d).unwrap();
        // Not within a minute of the row's writing (a friend's offer gets
        // its row a moment before its history row) ...
        assert_eq!(sweep(d, now + ROW_GRACE_MS - 1).unwrap(), Swept::default());
        // ... then it goes: the row (with the key) and the blob.
        let swept = sweep(d, now + ROW_GRACE_MS).unwrap();
        assert_eq!(
            swept,
            Swept {
                attachments: 1,
                ..Swept::default()
            }
        );
        assert!(swept.any());
        assert!(!exists(d, &first) && exists(d, &second));
        assert!(store::get(d, &first.handle_bytes().unwrap())
            .unwrap()
            .is_none());
        assert!(!store::blob_dir(d, &first.handle_bytes().unwrap()).exists());
    }

    #[test]
    fn clearing_a_chat_removes_that_friends_attachments_at_once() {
        let Some(_live) = Live::on() else { return };
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let now = crate::clock::now_ms();
        let mine = flow::prepare(d, &FRIEND, &jpeg(10_000), &photo(), now).unwrap();
        let other = flow::prepare(d, &[8u8; 32], &jpeg(10_000), &photo(), now).unwrap();
        // However new the rows are.
        assert_eq!(forget_peer(d, &FRIEND).unwrap(), 1);
        assert!(store::get(d, &mine.handle).unwrap().is_none());
        assert!(!store::blob_dir(d, &mine.handle).exists());
        assert!(store::get(d, &other.handle).unwrap().is_some());
        assert_eq!(forget_peer(d, &FRIEND).unwrap(), 0);
    }

    #[test]
    fn what_was_left_half_done_goes_after_an_hour() {
        let Some(_live) = Live::on() else { return };
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let now = crate::clock::now_ms();
        // Mine, sealed, and its message never made.
        let made = flow::prepare(d, &FRIEND, &jpeg(10_000), &photo(), now).unwrap();
        let row = store::get(d, &made.handle).unwrap().unwrap();
        assert_eq!(
            sweep(d, now + UNSENT_GRACE_MS - 1).unwrap(),
            Swept::default()
        );
        assert!(exists(d, &row), "its message may still be made");
        assert_eq!(sweep(d, now + UNSENT_GRACE_MS).unwrap().attachments, 1);
        assert!(!exists(d, &row));
        // A staged file and a blob folder with no row: kept while new.
        let staged = store::stage(d, "photo.jpg").unwrap();
        let orphan = d.join(BLOBS_DIR).join("ab".repeat(HANDLE_LEN));
        std::fs::create_dir_all(&orphan).unwrap();
        assert_eq!(sweep(d, now).unwrap(), Swept::default());
        assert!(staged.exists() && orphan.exists());
        // Old ones go.
        let old = SystemTime::now() - Duration::from_millis(UNSENT_GRACE_MS + 60_000);
        let touch = |path: &Path| {
            std::fs::File::open(path)
                .and_then(|f| f.set_modified(old))
                .unwrap();
        };
        touch(&staged);
        touch(&orphan);
        let swept = sweep(d, now).unwrap();
        assert_eq!((swept.staged, swept.blobs), (1, 1));
        assert!(!staged.exists() && !orphan.exists());
        // A staged file goes sooner than the rest: it is not sealed.
        let staged = store::stage(d, "photo.jpg").unwrap();
        let recent = SystemTime::now() - Duration::from_millis(STAGED_GRACE_MS - 60_000);
        std::fs::File::open(&staged)
            .and_then(|f| f.set_modified(recent))
            .unwrap();
        assert_eq!(sweep(d, now).unwrap().staged, 0);
        let left = SystemTime::now() - Duration::from_millis(STAGED_GRACE_MS + 60_000);
        std::fs::File::open(&staged)
            .and_then(|f| f.set_modified(left))
            .unwrap();
        assert_eq!(sweep(d, now).unwrap().staged, 1);
        // And all of them go when an app starts to stage anew.
        let (one, two) = (
            store::stage(d, "a.jpg").unwrap(),
            store::stage(d, "b.jpg").unwrap(),
        );
        assert_eq!(store::clear_staging(d), 2);
        assert!(!one.exists() && !two.exists());
        assert_eq!(store::clear_staging(d), 0);
    }
}
