//! Making an offer of mine and keeping a friend's
//! (`docs/design/2026-11-attachments.md` §8.2, §8.3).
//!
//! - **Mine.** [`prepare`] seals what an app handed over into a blob,
//!   writes the blob and the row, and gives back the offer: the text that
//!   travels as a chat message. The sender tells the row the message's id
//!   once the message exists ([`sent`]), or takes everything back when it
//!   could not be made ([`discard`]).
//! - **A friend's.** [`history_body`] is what the history write calls for
//!   every body: an offer of a photo, a voice note or a file becomes its
//!   stored form there (never the key), and, while attachments are live and
//!   the sender is a verified friend, its row is kept so the chunks can
//!   come ([`keep_offer`]).
//!
//! With the gate shut nothing here sends or keeps anything: a friend's
//! offer stays as it came (phase 1a).

use std::path::Path;
use std::sync::{Mutex, OnceLock};

use sha2::{Digest, Sha256};
use thiserror::Error;

use super::blob::{self, BlobError, Key};
use super::exchange::LIVE_MAX_LEN;
use super::link::Handle;
use super::offer::{self, BlobRef, Content, Frame, Offer, OfferError, LEVELS};
use super::store::{self, Chat, Row, StoreError};
use crate::attachment_gate;

/// What an app hands over with the bytes.
#[derive(Debug, Clone)]
pub enum Media<'a> {
    /// A JPEG the app shrank and stripped.
    Photo {
        /// Words under the photo; may be empty.
        caption: &'a str,
        /// Pixels.
        width: u32,
        /// Pixels.
        height: u32,
        /// The same photo at 32 px, at most 1,536 bytes.
        preview: &'a [u8],
    },
    /// A voice note (Opus in Ogg).
    Voice {
        /// Words under the player; may be empty.
        caption: &'a str,
        /// Its length.
        duration_ms: u32,
        /// 64 loudness levels.
        levels: [u8; LEVELS],
    },
    /// A file.
    File {
        /// The type the sender's system gave.
        mime: &'a str,
        /// Its name.
        name: &'a str,
        /// Words under the file; may be empty.
        caption: &'a str,
    },
}

/// Why an attachment was not made.
#[derive(Debug, Error)]
pub enum FlowError {
    /// The gate is shut.
    #[error("{}", attachment_gate::ATTACHMENTS_HOLD)]
    Hold,
    /// Nothing to send.
    #[error("ATTACHMENT_BAD: there is nothing in it")]
    Empty,
    /// More than this build sends.
    #[error("ATTACHMENT_TOO_BIG: at most {LIVE_MAX_LEN} bytes")]
    TooBig,
    /// A photo that is not a JPEG.
    #[error("ATTACHMENT_BAD: a photo is sent as a JPEG")]
    NotJpeg,
    /// A field the offer does not take.
    #[error("ATTACHMENT_BAD: {0}")]
    Offer(#[from] OfferError),
    /// The blob could not be sealed.
    #[error("ATTACHMENT_BAD: {0}")]
    Blob(#[from] BlobError),
    /// The store refused.
    #[error("{0}")]
    Store(#[from] StoreError),
}

/// An attachment of mine, sealed and written, with the message still to
/// be made.
pub struct Prepared {
    /// Its handle: the name of its row and its blob.
    pub handle: Handle,
    /// The offer as it travels: the text of the message. It holds the key.
    pub offer: String,
}

/// JPEG's first bytes.
fn is_jpeg(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xFF, 0xD8, 0xFF])
}

/// Seals `bytes` for the friend `peer`: the blob and the row are written,
/// and the offer comes back to be sent as a message.
pub fn prepare(
    data_dir: &Path,
    peer: &[u8; 32],
    bytes: &[u8],
    media: &Media<'_>,
    now_ms: u64,
) -> Result<Prepared, FlowError> {
    if !attachment_gate::attachments_live() {
        return Err(FlowError::Hold);
    }
    if bytes.is_empty() {
        return Err(FlowError::Empty);
    }
    if bytes.len() as u64 > LIVE_MAX_LEN {
        return Err(FlowError::TooBig);
    }
    if matches!(media, Media::Photo { .. }) && !is_jpeg(bytes) {
        return Err(FlowError::NotJpeg);
    }
    let key = Key::random();
    let sealed = blob::seal(&key, bytes)?;
    let blob = BlobRef {
        shape: sealed.shape,
        key,
        root: sealed.root(),
    };
    let offer = match media {
        Media::Photo {
            caption,
            width,
            height,
            preview,
        } => Offer::photo(blob, caption, *width, *height, preview)?,
        Media::Voice {
            caption,
            duration_ms,
            levels,
        } => Offer::voice(blob, caption, *duration_ms, *levels)?,
        Media::File {
            mime,
            name,
            caption,
        } => Offer::file(blob, mime, name, caption)?,
    };
    let text = offer.encode()?;
    // The message's id is not known yet: [`sent`] writes it.
    let row = Row::of_offer(&offer, &text, Chat::Friend(peer), &[0u8; 16], true, now_ms)
        .ok_or(StoreError::Corrupt)?;
    store::write_blob(data_dir, &offer.handle, &sealed)?;
    if let Err(e) = store::put(data_dir, &row) {
        let _ = store::remove(data_dir, &offer.handle);
        return Err(e.into());
    }
    Ok(Prepared {
        handle: offer.handle,
        offer: text,
    })
}

/// The offer of `handle` went out as message `message_id`.
pub fn sent(
    data_dir: &Path,
    handle: &Handle,
    message_id: &[u8; 16],
    now_ms: u64,
) -> Result<(), StoreError> {
    store::update(data_dir, handle, now_ms, |row| {
        row.message_id = hex::encode(message_id);
    })
    .map(|_| ())
}

/// The offer of an attachment of mine as it travels, made again from its
/// row: byte for byte the text [`prepare`] gave (an offer has one form).
/// For a send that is taken up again after the app ended: the history
/// keeps only the stored form.
pub fn offer_text(row: &Row) -> Option<String> {
    if !row.outgoing {
        return None;
    }
    let stored = row.stored()?;
    let offer = Offer {
        handle: stored.handle,
        content: stored.content,
        blob: Some(BlobRef {
            shape: stored.shape?,
            key: row.key()?,
            root: row.root()?,
        }),
    };
    let text = offer.encode().ok()?;
    (hex::encode(Sha256::digest(text.as_bytes())) == row.offer_sha256).then_some(text)
}

/// The message of `handle` could not be made: its row and its blob go.
pub fn discard(data_dir: &Path, handle: &Handle) {
    let _ = store::remove(data_dir, handle);
}

/// What became of a friend's offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kept {
    /// Its row is written: the chunks may come.
    New,
    /// The same offer was kept before (a copy sent again).
    Again,
    /// No row: no blob to fetch, the store is full, or its handle belongs
    /// to another attachment already.
    NotKept,
}

/// Keeps the offer the verified friend `peer` sent as message
/// `message_id`. `text` is the offer as it came.
pub fn keep_offer(
    data_dir: &Path,
    peer: &[u8; 32],
    message_id: &[u8; 16],
    offer: &Offer,
    text: &str,
    now_ms: u64,
) -> Result<Kept, StoreError> {
    if matches!(
        offer.content,
        Content::Profile { .. } | Content::NoProfile { .. }
    ) {
        return Ok(Kept::NotKept);
    }
    let Some(row) = Row::of_offer(offer, text, Chat::Friend(peer), message_id, false, now_ms)
    else {
        return Ok(Kept::NotKept);
    };
    match store::get(data_dir, &offer.handle) {
        Ok(Some(old)) => {
            let same =
                !old.outgoing && old.peer == row.peer && old.offer_sha256 == row.offer_sha256;
            return Ok(if same { Kept::Again } else { Kept::NotKept });
        }
        Ok(None) => {}
        // A row that does not read stays for a look; the offer has none.
        Err(StoreError::Corrupt) => return Ok(Kept::NotKept),
        Err(e) => return Err(e),
    }
    match store::put(data_dir, &row) {
        Ok(()) => Ok(Kept::New),
        Err(StoreError::Full) => Ok(Kept::NotKept),
        Err(e) => Err(e),
    }
}

/// A chat offer of a photo, a voice note or a file in `text`.
fn chat_offer(text: &str) -> Option<Offer> {
    match offer::parse_frame(text.as_bytes())? {
        Frame::Offer(offer)
            if !matches!(
                offer.content,
                Content::Profile { .. } | Content::NoProfile { .. }
            ) =>
        {
            Some(*offer)
        }
        _ => None,
    }
}

/// What the history keeps for the body `text` of a message with `peer`
/// (`direction` "in" or "out"): for an attachment's offer its stored form
/// and its list words ("Photo"); `None` for everything else, which is kept
/// as it is.
///
/// An offer of mine is always stored so: a history row never holds a key.
/// A friend's offer is while attachments are live, and then its row is
/// kept too when the friend is verified; with the gate shut it stays as it
/// came, for a later build to open (phase 1a). An error means the row
/// could not be written now: the message is not answered and comes again.
pub fn history_body(
    data_dir: &Path,
    direction: &str,
    peer: &[u8; 32],
    message_id: &[u8; 16],
    delivery: &str,
    text: &str,
    now_ms: u64,
) -> Result<Option<(String, String)>, String> {
    if !offer::is_att_text(text.as_bytes()) {
        return Ok(None);
    }
    let Some(offer) = chat_offer(text) else {
        return Ok(None);
    };
    if direction == "out" {
        // An offer of mine: delivered now, or on its way (its delivery may
        // be written later without its body: [`message_delivered`]).
        if delivery == "delivered" {
            offer_delivered(data_dir, &offer.handle, now_ms);
        } else {
            remember_offer(message_id, &offer.handle);
        }
    }
    if direction == "in" {
        if !attachment_gate::attachments_live() {
            return Ok(None);
        }
        // Fail closed: an unreadable contact book verifies nobody.
        if crate::contact_is_pinned(data_dir, peer).unwrap_or(false) {
            keep_offer(data_dir, peer, message_id, &offer, text, now_ms)
                .map_err(|e| e.to_string())?;
        }
    }
    let stored = offer.stored();
    let words = stored.list_words().unwrap_or_default();
    Ok(Some((stored.encode(), words)))
}

/// Attachments went live in this profile after a build that only kept
/// offers (phase 1a): every friend's offer the history kept as it came
/// takes its stored form now, and a verified friend's gets its row, so its
/// chunks can come. The rows rewritten. Nothing happens while the gate is
/// shut, and nothing is written when no row holds an offer.
pub fn adopt_kept_offers(data_dir: &Path, now_ms: u64) -> Result<usize, String> {
    if !attachment_gate::attachments_live() {
        return Ok(0);
    }
    crate::chat_history::ChatHistory::rewrite_bodies_persisted(data_dir, |entry| {
        if entry.direction != "in" || !offer::is_att_text(entry.body.as_bytes()) {
            return None;
        }
        let offer = chat_offer(&entry.body)?;
        let mut peer = [0u8; 32];
        let mut mid = [0u8; 16];
        hex::decode_to_slice(&entry.peer_pub_hex, &mut peer).ok()?;
        hex::decode_to_slice(&entry.message_id_hex, &mut mid).ok()?;
        if crate::contact_is_pinned(data_dir, &peer).unwrap_or(false) {
            // A row that cannot be written now leaves the offer as it is:
            // the next start tries again.
            keep_offer(data_dir, &peer, &mid, &offer, &entry.body, now_ms).ok()?;
        }
        let stored = offer.stored();
        Some((stored.encode(), stored.list_words().unwrap_or_default()))
    })
    .map_err(|e| e.to_string())
}

/// Offers of mine on their way, by message id: the newest of this process.
/// A delivery that is written without the message's body finds its
/// attachment here ([`message_delivered`]); one it does not find is asked
/// for by the exchange a few seconds later.
static ON_THEIR_WAY: Mutex<Vec<([u8; 16], Handle)>> = Mutex::new(Vec::new());
/// Offers remembered at most.
const MAX_ON_THEIR_WAY: usize = 64;
static DELIVERED_HOOK: OnceLock<fn()> = OnceLock::new();

/// What raven-node does when an offer of mine was delivered in its own
/// process: wake the task that moves the chunks (set once; later calls are
/// ignored). Another process's delivery is found by its row.
pub fn set_delivered_hook(hook: fn()) {
    let _ = DELIVERED_HOOK.set(hook);
}

fn remember_offer(message_id: &[u8; 16], handle: &Handle) {
    let mut list = ON_THEIR_WAY.lock().unwrap_or_else(|e| e.into_inner());
    list.retain(|(mid, _)| mid != message_id);
    if list.len() >= MAX_ON_THEIR_WAY {
        list.remove(0);
    }
    list.push((*message_id, *handle));
}

/// The message `message_id` of mine was delivered: when it carried an
/// offer this process remembers, its attachment's chunks may go now. No
/// file is read for any other message.
pub fn message_delivered(data_dir: &Path, message_id: &[u8; 16], now_ms: u64) {
    let handle = {
        let mut list = ON_THEIR_WAY.lock().unwrap_or_else(|e| e.into_inner());
        let Some(at) = list.iter().position(|(mid, _)| mid == message_id) else {
            return;
        };
        list.remove(at).1
    };
    offer_delivered(data_dir, &handle, now_ms);
}

/// The offer of the attachment `handle` of mine reached the friend's node:
/// its row says so (the exchange pushes every chunk at once, without
/// asking first), and raven-node's task is woken when this is its process.
fn offer_delivered(data_dir: &Path, handle: &Handle, now_ms: u64) {
    if !attachment_gate::attachments_live() {
        return;
    }
    ON_THEIR_WAY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|(_, h)| h != handle);
    let _ = store::update(data_dir, handle, now_ms, |row| {
        if row.outgoing && row.state == store::State::Staged {
            row.state = store::State::Offered;
        }
    });
    if let Some(hook) = DELIVERED_HOOK.get() {
        hook();
    }
}

/// Is a copy of a friend's offer that came again under the same message id
/// another offer than the one kept: the same handle with another key, root
/// or pad? (What a reader shows is compared by the history itself.)
pub fn copy_differs(data_dir: &Path, text: &str) -> bool {
    let Some(offer) = chat_offer(text) else {
        return false;
    };
    match store::get(data_dir, &offer.handle) {
        Ok(Some(row)) => row.offer_sha256 != hex::encode(Sha256::digest(text.as_bytes())),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attachment::store::State;

    fn jpeg(len: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
        bytes[..3].copy_from_slice(&[0xFF, 0xD8, 0xFF]);
        bytes
    }

    const FRIEND: [u8; 32] = [7u8; 32];

    fn photo<'a>() -> Media<'a> {
        Media::Photo {
            caption: "the bridge",
            width: 1_600,
            height: 1_200,
            preview: &[1, 2, 3, 4],
        }
    }

    /// The lab switch for this test's thread; back to the variables when
    /// dropped.
    struct Live;
    impl Live {
        fn on() -> Live {
            attachment_gate::set_lab_attachments_for_this_thread(Some(true));
            Live
        }
    }
    impl Drop for Live {
        fn drop(&mut self) {
            attachment_gate::set_lab_attachments_for_this_thread(None);
        }
    }

    #[test]
    fn nothing_is_prepared_while_the_gate_is_shut() {
        attachment_gate::set_lab_attachments_for_this_thread(Some(false));
        let dir = tempfile::tempdir().unwrap();
        let got = prepare(dir.path(), &FRIEND, &jpeg(1_000), &photo(), 1);
        attachment_gate::set_lab_attachments_for_this_thread(None);
        assert!(matches!(got, Err(FlowError::Hold)));
        assert!(store::list(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn a_photo_of_mine_is_sealed_written_and_offered() {
        if !cfg!(debug_assertions) {
            return;
        }
        let _live = Live::on();
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bytes = jpeg(300_000);
        let made = prepare(d, &FRIEND, &bytes, &photo(), 10).unwrap();
        assert_eq!(made.offer.len(), offer::OFFER_LEN);
        let row = store::get(d, &made.handle).unwrap().unwrap();
        assert!(row.outgoing);
        assert_eq!(row.state, State::Staged);
        assert_eq!(row.peer_key(), Some(FRIEND));
        assert_eq!(row.message_id_bytes(), Some([0u8; 16]));
        sent(d, &made.handle, &[9u8; 16], 11).unwrap();
        let row = store::get(d, &made.handle).unwrap().unwrap();
        assert_eq!(row.message_id_bytes(), Some([9u8; 16]));
        // The offer can be made again from the row, byte for byte.
        assert_eq!(offer_text(&row).as_deref(), Some(made.offer.as_str()));
        // What was written opens to what was handed over.
        let back = store::read_plain(d, &row, 0, bytes.len()).unwrap();
        assert_eq!(&back[..], &bytes[..]);
        assert!(store::opens(d, &row).unwrap());
        // The history keeps the stored form: no key, no root.
        let (body, words) = history_body(d, "out", &FRIEND, &[9u8; 16], "queued", &made.offer, 12)
            .unwrap()
            .unwrap();
        assert_eq!(words, "Photo");
        assert!(body.starts_with("RVNATT/1 ref\n"));
        let key = hex::encode(row.key().unwrap().bytes());
        let root = hex::encode(row.root().unwrap());
        assert!(!body.contains(&key) && !body.contains(&root));
        assert!(made.offer.contains(&key));
        // Taken back: nothing stays.
        discard(d, &made.handle);
        assert!(store::get(d, &made.handle).unwrap().is_none());
        assert!(!store::blob_dir(d, &made.handle).exists());
    }

    #[test]
    fn what_cannot_be_sent_is_refused_and_nothing_is_written() {
        if !cfg!(debug_assertions) {
            return;
        }
        let _live = Live::on();
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert!(matches!(
            prepare(d, &FRIEND, &[], &photo(), 1),
            Err(FlowError::Empty)
        ));
        assert!(matches!(
            prepare(d, &FRIEND, &jpeg(LIVE_MAX_LEN as usize + 1), &photo(), 1),
            Err(FlowError::TooBig)
        ));
        assert!(matches!(
            prepare(d, &FRIEND, &[0u8; 100], &photo(), 1),
            Err(FlowError::NotJpeg)
        ));
        let long = "x".repeat(offer::MAX_CAPTION_BYTES + 1);
        let bad = Media::Photo {
            caption: &long,
            width: 10,
            height: 10,
            preview: &[],
        };
        assert!(matches!(
            prepare(d, &FRIEND, &jpeg(100), &bad, 1),
            Err(FlowError::Offer(_))
        ));
        assert!(store::list(d).unwrap().is_empty());
        assert!(
            !d.join(store::BLOBS_DIR).exists()
                || std::fs::read_dir(d.join(store::BLOBS_DIR)).unwrap().count() == 0
        );
    }

    #[test]
    fn a_friends_offer_is_kept_once() {
        if !cfg!(debug_assertions) {
            return;
        }
        let _live = Live::on();
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let made = prepare(a.path(), &FRIEND, &jpeg(100_000), &photo(), 1).unwrap();
        let offer = chat_offer(&made.offer).unwrap();
        let d = b.path();
        let mid = [3u8; 16];
        assert_eq!(
            keep_offer(d, &FRIEND, &mid, &offer, &made.offer, 5).unwrap(),
            Kept::New
        );
        let row = store::get(d, &made.handle).unwrap().unwrap();
        assert!(!row.outgoing);
        assert_eq!(row.state, State::Incoming);
        assert_eq!(row.message_id_bytes(), Some(mid));
        // The same offer again: nothing changes.
        assert_eq!(
            keep_offer(d, &FRIEND, &mid, &offer, &made.offer, 6).unwrap(),
            Kept::Again
        );
        assert!(!copy_differs(d, &made.offer));
        // Another friend names the same handle: the first row stays.
        assert_eq!(
            keep_offer(d, &[8u8; 32], &mid, &offer, &made.offer, 7).unwrap(),
            Kept::NotKept
        );
        assert_eq!(store::get(d, &made.handle).unwrap().unwrap(), row);
        // An offer with the same handle and other bytes is another offer.
        let other = prepare(a.path(), &FRIEND, &jpeg(100_000), &photo(), 2).unwrap();
        assert!(
            !copy_differs(d, &other.offer),
            "no row: nothing to differ from"
        );
        assert_eq!(store::list(d).unwrap().len(), 1);
    }
}
