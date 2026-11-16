//! Photos (and, with the same operations later, voice messages and files):
//! `attachments.*`, what a message row says about its attachment, and the
//! `attachment` event.
//!
//! An attachment is one message, its offer, and sealed bytes that never
//! travel as messages (`raven_core::attachment`). The engine makes the
//! offer (`attachments.send`), reads the bytes for the app
//! (`attachments.read`) and tells where each attachment stands. raven-node
//! moves the bytes by itself: it watches the attachment store, and so does
//! the engine.
//!
//! - **The offer is never text.** A history row holds the offer's stored
//!   form, which has no key. A row that holds one shows its caption as its
//!   text and carries an `attachment` member. Nothing an app reads holds
//!   text that starts with `RVNATT/`.
//! - **A send keeps the stored form only.** `attachments.send` seals the
//!   bytes, and the message goes through the same queue, keeping row and
//!   worker as `messages.send`. The offer holds the attachment's key: it is
//!   made again from the attachment's row when the send's turn comes, and
//!   so it is after a restart.
//! - **Delivered means every byte.** A photo of yours reads `delivered`,
//!   and its message with it, only once the friend's Raven has all of it.
//! - **An attachment goes with its message.** Deleting a message removes
//!   its attachment at once, and clearing a chat removes that chat's.
//! - **Off in this release.** While the attachments gate is shut every
//!   operation but `attachments.can_send` answers `NOT_AVAILABLE_YET`, and a
//!   row with an attachment says `needs_update` with a line of plain words.
//! - **Nothing new for a profile without attachments.** A look at the
//!   profile opens the store only for the attachments its rows carry, and
//!   reads a row again only when its file changed.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use ash_engine::engine::ContactView;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use raven_core::attachment::exchange::LIVE_MAX_LEN;
use raven_core::attachment::flow::{self, FlowError, Media};
use raven_core::attachment::link::Handle;
use raven_core::attachment::offer::{self, Content, Kind};
use raven_core::attachment::store::{self, Row, StoreError};
use raven_core::attachment::{peers, shown, sweep};
use raven_core::attachment_gate;
use raven_core::chat_history::{ChatHistory, ChatHistoryEntry};
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use crate::engine::{now_ms, Inner};
use crate::envelope::{code, ApiError, Args, OpResult};
use crate::messages::{Job, Pending, State, View};
use crate::safety;

/// The most bytes one `attachments.read` gives.
const READ_MAX: u64 = 524_288;
/// `attachments.export` writes in pieces of this size.
const EXPORT_PIECE: usize = 262_144;
/// A photo's row that changed this lately is not yet marked as no longer
/// on its way, whatever its messages say: Send again writes the row a
/// moment before it makes the new message.
const ENDED_GRACE_MS: u64 = 10_000;
/// `attachment` events for one attachment are at least this far apart: four
/// a second at most.
const TOLD_EVERY: Duration = Duration::from_millis(250);

/// API's `attachment.state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttState {
    /// A friend's: its message is here, no byte yet.
    Offered,
    /// A friend's: bytes are coming.
    Downloading,
    /// A friend's: every byte is here and checked.
    Ready,
    /// A friend's: the friend deleted it before it was all here.
    Gone,
    /// A friend's: a check failed. Yours: not sent.
    Failed,
    /// Yours: its message or its bytes are going.
    Sending,
    /// Yours: the friend has the message, not yet every byte.
    Sent,
    /// Yours: the friend's Raven has every byte.
    Delivered,
    /// Yours: the friend is away.
    Waiting,
    /// This build does not open it: the row's text says so in plain words.
    NeedsUpdate,
}

impl AttState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            AttState::Offered => "offered",
            AttState::Downloading => "downloading",
            AttState::Ready => "ready",
            AttState::Gone => "gone",
            AttState::Failed => "failed",
            AttState::Sending => "sending",
            AttState::Sent => "sent",
            AttState::Delivered => "delivered",
            AttState::Waiting => "waiting",
            AttState::NeedsUpdate => "needs_update",
        }
    }
}

/// What the stored form of an attachment says: all an app needs to draw
/// its bubble before a byte is here. It holds no key.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Meta {
    /// The name of its row and its sealed bytes in the attachment store.
    pub(crate) handle: Handle,
    /// API's `id`: the handle in 32 lower case hex characters.
    pub(crate) id: String,
    pub(crate) kind: Kind,
    /// The words under it; may be empty. The row's `text`.
    pub(crate) caption: String,
    /// What a chat list says for it ("Photo").
    pub(crate) words: String,
    /// Its own bytes, in all.
    pub(crate) bytes: u64,
    detail: Detail,
    /// Of the stored form itself: a row of the store is this attachment's
    /// only when its stored form has the same one.
    digest: u64,
}

/// What only one kind has.
#[derive(Debug, PartialEq, Eq)]
enum Detail {
    Photo {
        width: u32,
        height: u32,
        preview_b64: String,
    },
    Voice {
        duration_ms: u32,
        levels_b64: String,
    },
    File {
        name: String,
        mime: String,
    },
}

/// A short digest of a stored form, to tell two of them apart without
/// keeping either (not a security check: the handle already comes from the
/// attachment's key).
fn digest(stored: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    stored.hash(&mut hasher);
    hasher.finish()
}

impl Meta {
    /// Reads a stored form (`RVNATT/1 ref`): of a photo, a voice message or
    /// a file. None for anything else.
    pub(crate) fn parse(stored: &str) -> Option<Meta> {
        let parsed = offer::parse_ref(stored.as_bytes())?;
        let bytes = parsed.shape.as_ref()?.len();
        let words = parsed.list_words()?;
        let detail = match &parsed.content {
            Content::Photo {
                width,
                height,
                preview,
                ..
            } => Detail::Photo {
                width: *width,
                height: *height,
                preview_b64: BASE64.encode(preview),
            },
            Content::Voice {
                duration_ms,
                levels,
                ..
            } => Detail::Voice {
                duration_ms: *duration_ms,
                levels_b64: BASE64.encode(levels),
            },
            Content::File { mime, name, .. } => Detail::File {
                name: name.clone(),
                mime: mime.clone(),
            },
            // A profile picture is never a message.
            Content::Profile { .. } | Content::NoProfile { .. } => return None,
        };
        // A caption follows the chat text rules: one that starts with a
        // reserved prefix (no app sends one) is not shown.
        let caption = parsed.content.caption();
        let caption = if raven_core::app_channel::chat_text_allowed(caption) {
            caption.to_owned()
        } else {
            String::new()
        };
        Some(Meta {
            handle: parsed.handle,
            id: hex::encode(parsed.handle),
            kind: parsed.kind(),
            caption,
            words,
            bytes,
            detail,
            digest: digest(stored),
        })
    }
}

/// The attachment of one message row, as the app sees it.
#[derive(Debug, Clone)]
pub(crate) struct AttView {
    /// What its stored form says; none for an offer a build without
    /// attachments kept as it came (only its kind is known).
    meta: Option<Arc<Meta>>,
    kind: Kind,
    pub(crate) state: AttState,
    /// Of its own bytes: here (a friend's) or at the friend's Raven (yours).
    pub(crate) bytes_done: u64,
}

impl AttView {
    /// The attachment a row's stored form names, before the store was
    /// asked: with no row in the store it is failed.
    pub(crate) fn of(meta: &Arc<Meta>) -> AttView {
        AttView {
            meta: Some(Arc::clone(meta)),
            kind: meta.kind,
            state: AttState::Failed,
            bytes_done: 0,
        }
    }

    /// An offer kept as it came: this build only knows its kind.
    fn kept(kind: Kind) -> AttView {
        AttView {
            meta: None,
            kind,
            state: AttState::NeedsUpdate,
            bytes_done: 0,
        }
    }

    /// What it says, when this build opens it (not `needs_update`).
    fn open(&self) -> Option<&Arc<Meta>> {
        match self.state {
            AttState::NeedsUpdate => None,
            _ => self.meta.as_ref(),
        }
    }

    /// Its handle in the attachment store, when its stored form is known.
    pub(crate) fn handle(&self) -> Option<Handle> {
        self.meta.as_ref().map(|meta| meta.handle)
    }

    /// API's `attachment` member of a message row.
    pub(crate) fn json(&self) -> Value {
        let Some(meta) = self.open() else {
            return json!({
                "kind": self.kind.word(),
                "state": AttState::NeedsUpdate.as_str(),
            });
        };
        let mut m = Map::new();
        m.insert("id".into(), meta.id.clone().into());
        m.insert("kind".into(), meta.kind.word().into());
        m.insert("state".into(), self.state.as_str().into());
        m.insert("bytes".into(), meta.bytes.into());
        m.insert("bytes_done".into(), self.bytes_done.min(meta.bytes).into());
        match &meta.detail {
            Detail::Photo {
                width,
                height,
                preview_b64,
            } => {
                m.insert("width".into(), (*width).into());
                m.insert("height".into(), (*height).into());
                m.insert("preview_b64".into(), preview_b64.clone().into());
            }
            Detail::Voice {
                duration_ms,
                levels_b64,
            } => {
                m.insert("duration_ms".into(), (*duration_ms).into());
                m.insert("levels_b64".into(), levels_b64.clone().into());
            }
            Detail::File { name, mime } => {
                m.insert("name".into(), safety::line(name).into());
                m.insert("mime".into(), safety::line(mime).into());
            }
        }
        m.insert("caption".into(), safety::text(&meta.caption).into());
        Value::Object(m)
    }
}

/// What one row of the history carries.
#[derive(Debug, Clone)]
pub(crate) enum RowAtt {
    /// An attachment: its stored form, read once.
    Stored(Arc<Meta>),
    /// An offer kept as it came (a build with the gate shut took it): its
    /// kind. The row's text is a line of plain words.
    Kept(Kind),
}

/// What the rows of the history carry, by direction (yours, a friend's),
/// then the friend's key and the message id, both in lower case hex. Read
/// once with the history and kept with it: a lock lets both go.
#[derive(Debug, Default)]
pub(crate) struct RowAtts {
    rows: [HashMap<String, HashMap<String, RowAtt>>; 2],
}

impl RowAtts {
    pub(crate) fn is_empty(&self) -> bool {
        self.rows.iter().all(HashMap::is_empty)
    }

    fn put(&mut self, incoming: bool, peer: &str, mid: &str, att: RowAtt) {
        self.rows[usize::from(incoming)]
            .entry(peer.to_ascii_lowercase())
            .or_default()
            .insert(mid.to_ascii_lowercase(), att);
    }

    /// What the row `mid` of the chat with `peer` carries (both lower case).
    pub(crate) fn get(&self, incoming: bool, peer: &str, mid: &str) -> Option<&RowAtt> {
        self.rows[usize::from(incoming)].get(peer)?.get(mid)
    }
}

/// The history as the engine shows it, and what its rows carry. The rows
/// are `ChatHistory::shown_with_attachments`: no hidden rows, an offer
/// kept as it came as its line of words, and a stored form left as the
/// row's body, for [`RowAtts`] to say what it is. A row without an
/// attachment costs one look at how its body starts.
pub(crate) fn shown_history(history: ChatHistory) -> (Vec<ChatHistoryEntry>, RowAtts) {
    let mut atts = RowAtts::default();
    for e in &history.entries {
        if !offer::is_att_text(e.body.as_bytes()) {
            continue;
        }
        let att = match Meta::parse(&e.body) {
            Some(meta) => RowAtt::Stored(Arc::new(meta)),
            None => match offer::offer_kind(e.body.as_bytes()) {
                Some(kind) if kind != Kind::Profile => RowAtt::Kept(kind),
                // Never shown: `shown_with_attachments` drops the row.
                _ => continue,
            },
        };
        atts.put(
            e.direction != "out",
            &e.peer_pub_hex,
            &e.message_id_hex,
            att,
        );
    }
    (history.shown_with_attachments().entries, atts)
}

/// The text of a row with the stored body `body`: the body itself, but
/// never an attachment text (`RVNATT/`). A row that carries an attachment
/// gets its caption from [`Inner::attach`].
pub(crate) fn row_text(body: &str) -> String {
    if offer::is_att_text(body.as_bytes()) {
        String::new()
    } else {
        body.to_owned()
    }
}

/// The text of a send that has no history row yet: a photo's send shows
/// its caption.
pub(crate) fn pending_text(pending: &Pending) -> String {
    match &pending.attachment {
        Some(meta) => meta.caption.clone(),
        None => row_text(&pending.body),
    }
}

/// Is the history row with the body `row` the row of the send whose body
/// is `sent`, an attachment's? An offer and its stored form name the same
/// attachment.
pub(crate) fn same_body(row: &str, sent: &str) -> bool {
    offer::is_att_text(sent.as_bytes())
        && offer::is_att_text(row.as_bytes())
        && shown::same_attachment(row, sent)
}

/// What a row of the attachment store said when it was last read: no key.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Brief {
    outgoing: bool,
    /// The friend's key, lower case hex; empty in a group.
    peer: String,
    state: store::State,
    friend_has: u32,
    /// When the row last changed.
    updated_ms: u64,
    digest: u64,
}

impl Brief {
    fn of(row: &Row) -> Brief {
        Brief {
            outgoing: row.outgoing,
            peer: row
                .peer
                .as_deref()
                .map(str::to_ascii_lowercase)
                .unwrap_or_default(),
            state: row.state,
            friend_has: row.friend_has,
            updated_ms: row.updated_ms,
            digest: digest(&row.reference),
        }
    }
}

/// One attachment as the store had it at the last read.
#[derive(Debug)]
struct Known {
    /// The time its row's file had then; none: no row.
    at: Option<SystemTime>,
    /// A friend's that still comes: its bitmap is looked at each time.
    coming: bool,
    /// The time its bitmap had then.
    chunk_ms: u64,
    row: Option<Brief>,
    /// Of its own bytes: here (a friend's) or at the friend's node (mine).
    done: u64,
    /// The look that last used it.
    turn: u64,
}

impl Known {
    fn read(dir: &Path, handle: &Handle, at: Option<SystemTime>) -> Known {
        // A row that is not there, or does not read, is no row.
        let row = at.and_then(|_| store::get(dir, handle).ok().flatten());
        let coming = row
            .as_ref()
            .is_some_and(|row| !row.outgoing && row.state == store::State::Incoming);
        // The bitmap's time before its bits: a chunk that lands in between
        // is seen at the next look.
        let chunk_ms = if coming {
            store::last_chunk_ms(dir, handle)
        } else {
            0
        };
        let done = row.as_ref().map_or(0, |row| store::progress(dir, row).0);
        Known {
            at,
            coming,
            chunk_ms,
            row: row.as_ref().map(Brief::of),
            done,
            turn: 0,
        }
    }
}

/// What the apps were last told of one row's attachment.
#[derive(Debug)]
struct Told {
    state: AttState,
    done: u64,
    /// When its last `attachment` event went; none: only its row said it.
    at: Option<Instant>,
}

/// What the engine remembers of attachments between two looks at the
/// profile (a part of the message book, under its lock). No key, no text,
/// no preview: states and counts only.
#[derive(Debug, Default)]
pub(crate) struct AttBook {
    /// The attachments the rows of the last look carried, by handle.
    rows: HashMap<Handle, Known>,
    /// By the row's id.
    told: HashMap<String, Told>,
    /// Sends of this run whose message has its id now: the attachment's
    /// row is told at the next look (`flow::sent`).
    named: Vec<(Handle, [u8; 16])>,
    turn: u64,
}

impl AttBook {
    /// A photo's send was taken in under the row id `id`: the app was told
    /// `sending`, and hears of every change from there.
    pub(crate) fn sending(&mut self, id: &str) {
        self.told.insert(
            id.to_owned(),
            Told {
                state: AttState::Sending,
                done: 0,
                at: None,
            },
        );
    }

    /// The message that carries the attachment `handle` has the id `mid`
    /// (hex) now.
    pub(crate) fn message_named(&mut self, handle: Handle, mid: &str) {
        let mut id = [0u8; 16];
        if hex::decode_to_slice(mid, &mut id).is_ok() && !self.named.contains(&(handle, id)) {
            self.named.push((handle, id));
        }
    }

    /// No row carries an attachment this build opens: nothing is kept.
    fn forget(&mut self) {
        if !self.rows.is_empty() {
            self.rows.clear();
        }
        if !self.told.is_empty() {
            self.told.clear();
        }
        self.named.clear();
    }

    /// The attachment `handle` as the store has it, read again only when
    /// its row's file changed (`at`: the file's time now, none: no file)
    /// or, for a friend's that still comes, when its bitmap did.
    fn known(&mut self, dir: &Path, handle: &Handle, at: Option<SystemTime>, turn: u64) -> &Known {
        let stale = |known: &Known| {
            known.turn != turn
                && (known.at != at
                    || (known.coming && store::last_chunk_ms(dir, handle) != known.chunk_ms))
        };
        let known = match self.rows.entry(*handle) {
            Entry::Occupied(mut entry) => {
                if stale(entry.get()) {
                    entry.insert(Known::read(dir, handle, at));
                }
                entry.into_mut()
            }
            Entry::Vacant(entry) => entry.insert(Known::read(dir, handle, at)),
        };
        known.turn = turn;
        known
    }
}

/// Where a friend's attachment stands, from its row (none: no row of this
/// friend's for it here) and how many of its bytes are here.
fn state_in(row: Option<&Brief>, done: u64) -> AttState {
    match row.map(|row| row.state) {
        Some(store::State::Complete) => AttState::Ready,
        Some(store::State::Gone) => AttState::Gone,
        Some(store::State::Incoming) if done == 0 => AttState::Offered,
        Some(store::State::Incoming) => AttState::Downloading,
        // A check failed, or there is no row for it.
        _ => AttState::Failed,
    }
}

/// Where an attachment of yours stands, from its row (none: no row of
/// yours for it here) and its message's own state.
///
/// It reads delivered only when both say so: the friend's Raven has every
/// byte (the row, written by raven-node), and the signed receipt of its
/// message is here (the message, written by whoever sent it). The two are
/// written by different hands and in either order, so neither alone is
/// enough, and the `receipt` event always comes before an attachment's
/// `delivered`.
fn state_out(row: Option<&Brief>, message: State) -> AttState {
    let Some(row) = row else {
        return AttState::Failed;
    };
    let whole = row.state == store::State::Delivered;
    match row.state {
        store::State::Staged | store::State::Offered | store::State::Delivered => {
            // The friend has the offer: its message was delivered, or the
            // friend's node said so.
            let offered = message == State::Delivered || row.state != store::State::Staged;
            match message {
                State::Failed | State::TimeRanOut | State::NotSentMeetFirst => AttState::Failed,
                State::Delivered if whole => AttState::Delivered,
                // Every byte is with the friend, and the receipt of its
                // message is still to come.
                _ if whole => AttState::Sending,
                State::Waiting => AttState::Waiting,
                State::Sending => AttState::Sending,
                State::Sent | State::Delivered if offered && row.friend_has == 0 => AttState::Sent,
                State::Sent | State::Delivered => AttState::Sending,
            }
        }
        // Stopped, deleted, or not a row of yours.
        _ => AttState::Failed,
    }
}

/// The refusal while the attachments gate is shut.
fn not_yet() -> ApiError {
    ApiError::new(
        code::NOT_AVAILABLE_YET,
        "Photos are not in this version of Raven yet. Nothing was changed.",
        attachment_gate::ATTACHMENTS_HOLD,
    )
}

/// Every operation but `attachments.can_send` asks this first.
fn gate() -> Result<(), ApiError> {
    if attachment_gate::attachments_live() {
        Ok(())
    } else {
        Err(not_yet())
    }
}

fn gone(detail: impl Into<String>) -> ApiError {
    ApiError::of(code::ATTACHMENT_GONE, detail)
}

fn bad(detail: impl Into<String>) -> ApiError {
    ApiError::of(code::ATTACHMENT_BAD, detail)
}

/// A failure's text says the disk is full.
fn no_room(why: &str) -> bool {
    why.contains("os error 28") || why.contains("os error 112") || why.contains("No space left")
}

fn store_error(e: StoreError) -> ApiError {
    let why = e.to_string();
    match e {
        StoreError::Full => ApiError::of(code::STORAGE_FULL, why),
        StoreError::Io(_) if no_room(&why) => ApiError::of(code::STORAGE_FULL, why),
        StoreError::NotFound => gone(why),
        StoreError::Corrupt => bad(why),
        StoreError::Range => ApiError::bad_request(why),
        StoreError::Io(_) => ApiError::internal(why),
    }
}

fn flow_error(e: FlowError) -> ApiError {
    let why = e.to_string();
    match e {
        FlowError::Hold => not_yet(),
        FlowError::TooBig => ApiError::of(code::ATTACHMENT_TOO_BIG, why),
        FlowError::Store(e) => store_error(e),
        FlowError::Empty | FlowError::NotJpeg | FlowError::Offer(_) | FlowError::Blob(_) => {
            ApiError::new(
                code::ATTACHMENT_BAD,
                "This photo could not be sent. Choose it again.",
                why,
            )
        }
    }
}

/// `id`: an attachment's handle in 32 hex characters.
fn id_arg(args: &Args) -> Result<Handle, ApiError> {
    let id = args.str("id")?.trim().to_ascii_lowercase();
    let mut handle = [0u8; 16];
    if id.len() != 32 || hex::decode_to_slice(&id, &mut handle).is_err() {
        return Err(ApiError::bad_request(
            "\"id\" must be an attachment id (32 hex characters)",
        ));
    }
    Ok(handle)
}

/// A friend's key from its hex.
fn key_of(pub_hex: &str) -> Option<[u8; 32]> {
    let mut key = [0u8; 32];
    hex::decode_to_slice(pub_hex.trim(), &mut key).ok()?;
    Some(key)
}

/// Why photos do not go to the contact `c` now: the code `attachments.send`
/// refuses with, and plain words (`attachments.can_send`'s `why`). None
/// when they do. `friend`: raven-core says attachments are exchanged with
/// this contact (`flow::is_friend`: verified and not blocked; it decides,
/// the contact as the engine read it only picks the words). `speaks`: the
/// friend's Raven said it takes attachments.
fn cannot_send(c: &ContactView, friend: bool, speaks: bool) -> Option<(&'static str, String)> {
    let name = safety::line(&c.label);
    let (who, whom) = if name.is_empty() {
        ("Your friend".to_owned(), "your friend".to_owned())
    } else {
        (name.clone(), name)
    };
    if c.blocked {
        return Some((
            code::CONTACT_BLOCKED,
            format!("Unblock {whom} to send photos"),
        ));
    }
    if !c.pinned {
        return Some((
            code::BAD_REQUEST,
            format!("Verify {whom} first to send photos"),
        ));
    }
    if !friend {
        // The friends list or the block list could not be read just now.
        return Some((
            code::BAD_REQUEST,
            format!("Raven cannot send photos to {whom} right now"),
        ));
    }
    if !speaks {
        // An older Raven, or one that has not been in touch since photos
        // came: this Raven cannot tell which.
        return Some((
            code::FRIEND_NEEDS_NEWER_RAVEN,
            format!("{who} cannot get photos yet. Their Raven has not said that it takes them"),
        ));
    }
    None
}

/// Whether photos go to the contact `c` now, asked of the profile:
/// [`cannot_send`] with raven-core's own answers.
fn cannot_send_now(dir: &Path, c: &ContactView) -> Option<(&'static str, String)> {
    let key = key_of(&c.pub_hex);
    let friend = key.is_some_and(|key| flow::is_friend(dir, &key));
    let speaks = key.is_some_and(|key| peers::speaks(dir, &key));
    cannot_send(c, friend, speaks)
}

/// [`cannot_send_now`] as the refusal of a send.
fn may_send(dir: &Path, c: &ContactView) -> Result<(), ApiError> {
    match cannot_send_now(dir, c) {
        Some((code, why)) => Err(ApiError::new(
            code,
            format!("{why}."),
            "photos do not go to this contact now",
        )),
        None => Ok(()),
    }
}

/// A caption follows the chat text rules.
fn check_caption(caption: &str) -> Result<(), ApiError> {
    if caption.len() > offer::MAX_CAPTION_BYTES {
        return Err(ApiError::new(
            code::MESSAGE_TOO_LONG,
            "This caption is too long. Make it shorter, then send the photo again.",
            format!(
                "{} bytes; at most {}",
                caption.len(),
                offer::MAX_CAPTION_BYTES
            ),
        ));
    }
    if !offer::caption_ok(caption) {
        return Err(ApiError::new(
            code::BAD_REQUEST,
            "This caption has characters Raven cannot send. Remove them, then send the photo \
             again.",
            "a control character in the caption",
        ));
    }
    if !raven_core::app_channel::chat_text_allowed(caption) {
        return Err(ApiError::new(
            code::BAD_REQUEST,
            "A caption cannot start with RVNAPP/, RVNGRP/ or RVNATT/. Change how it starts.",
            "reserved prefix",
        ));
    }
    Ok(())
}

/// A staged file that goes when this does: whatever became of the send, the
/// photo's own bytes do not stay in the staging folder.
struct Staged(PathBuf);

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The bytes of a staged file: at most what Raven sends, wiped when let go.
fn read_staged(path: &Path) -> Result<Zeroizing<Vec<u8>>, ApiError> {
    let unreadable = |e: std::io::Error| {
        ApiError::new(
            code::ATTACHMENT_BAD,
            "Raven could not read the photo to send. Choose it again.",
            format!("staged file: {e}"),
        )
    };
    let too_big = |len: u64| {
        ApiError::of(
            code::ATTACHMENT_TOO_BIG,
            format!("{len} bytes; at most {LIVE_MAX_LEN}"),
        )
    };
    let file = std::fs::File::open(path).map_err(unreadable)?;
    let len = file.metadata().map_err(unreadable)?.len();
    if len > LIVE_MAX_LEN {
        return Err(too_big(len));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(len as usize));
    // One byte more than the most: a file that grew meanwhile is refused,
    // never cut.
    file.take(LIVE_MAX_LEN + 1)
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if bytes.len() as u64 > LIVE_MAX_LEN {
        return Err(too_big(bytes.len() as u64));
    }
    Ok(bytes)
}

/// The first row of a photo's send just taken in.
fn first_row(pending: &Pending, meta: &Arc<Meta>) -> View {
    View {
        id: pending.id.clone(),
        mid: None,
        peer: pending.peer.clone(),
        address: pending.address.clone(),
        incoming: false,
        text: meta.caption.clone(),
        at_ms: pending.created_ms,
        state: State::Sending,
        until_ms: None,
        path: None,
        via_name: None,
        via_friend: false,
        delivered_at_ms: None,
        attempts: None,
        history: None,
        outbox: None,
        pending: None,
        attachment: Some(AttView {
            meta: Some(Arc::clone(meta)),
            kind: meta.kind,
            state: AttState::Sending,
            bytes_done: 0,
        }),
    }
}

/// The offer of the attachment `handle` of yours for the friend with the
/// key `peer` (hex), made again from its row: byte for byte the text that
/// was made when it was sealed. `Err`: why no offer goes: the gate is
/// shut, the row is gone or is not this friend's, sending was stopped, or
/// the friend is not one photos go to any more (fail closed: a friends
/// list that cannot be read verifies nobody).
fn offer_for(dir: &Path, handle: &Handle, peer: &str) -> Result<Zeroizing<String>, String> {
    if !attachment_gate::attachments_live() {
        return Err(attachment_gate::ATTACHMENTS_HOLD.into());
    }
    let row = match store::get(dir, handle) {
        Ok(Some(row)) => row,
        Ok(None) => {
            return Err("ATTACHMENT_GONE: the photo is no longer on this device".into());
        }
        Err(e) => return Err(e.to_string()),
    };
    let theirs = row
        .peer
        .as_deref()
        .is_some_and(|p| p.eq_ignore_ascii_case(peer.trim()));
    if !row.outgoing || !theirs {
        return Err("ATTACHMENT_GONE: no such photo of yours for this friend".into());
    }
    if matches!(row.state, store::State::Failed | store::State::Gone) {
        return Err("ATTACHMENT_GONE: sending this photo was stopped".into());
    }
    let Some(key) = key_of(peer) else {
        return Err("NOT SENT: the friend's key is not 32 bytes".into());
    };
    if !flow::is_friend(dir, &key) {
        return Err("NOT SENT: photos go only to a friend you verified and did not block".into());
    }
    if !peers::speaks(dir, &key) {
        return Err("FRIEND_NEEDS_NEWER_RAVEN: the friend's Raven does not take photos".into());
    }
    flow::offer_text(&row)
        .map(Zeroizing::new)
        .ok_or_else(|| "ATTACHMENT_BAD: the offer could not be made again from its row".to_owned())
}

/// The row of an attachment whose bytes can be read now: one of yours, or
/// a friend's that is all here.
fn readable(dir: &Path, handle: &Handle) -> Result<Row, ApiError> {
    let row = store::get(dir, handle)
        .map_err(store_error)?
        .ok_or_else(|| gone("no such attachment on this device"))?;
    if row.outgoing {
        return Ok(row);
    }
    match row.state {
        store::State::Complete => Ok(row),
        store::State::Gone => Err(gone("the friend deleted it before it was all here")),
        store::State::Failed => Err(bad("a check of its bytes failed")),
        _ => {
            let (done, bytes) = store::progress(dir, &row);
            Err(ApiError::new(
                code::BAD_REQUEST,
                "This photo is not all here yet. It opens once it is ready.",
                format!("attachment not ready: {done} of {bytes} bytes"),
            ))
        }
    }
}

/// Where `attachments.export` may write: the full path of a new file, in a
/// folder that is there and is not inside the profile.
fn export_place(dir: &Path, to: &Path) -> Result<(), ApiError> {
    let parent = match (to.is_absolute(), to.file_name(), to.parent()) {
        (true, Some(_), Some(parent)) => parent,
        _ => {
            return Err(ApiError::bad_request(
                "\"to_path\" must be the full path of the new file",
            ))
        }
    };
    let parent = parent.canonicalize().map_err(|e| {
        ApiError::new(
            code::BAD_REQUEST,
            "Raven could not find that folder. Choose another place.",
            format!("to_path: {e}"),
        )
    })?;
    let profile = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    if parent.starts_with(&profile) {
        return Err(ApiError::new(
            code::BAD_REQUEST,
            "Choose a place outside the folder Raven keeps its data in.",
            "to_path is inside the profile folder",
        ));
    }
    Ok(())
}

fn export_error(e: &std::io::Error) -> ApiError {
    let detail = format!("to_path: {e}");
    if e.kind() == std::io::ErrorKind::AlreadyExists {
        ApiError::new(
            code::BAD_REQUEST,
            "A file with this name is already there. Choose another name.",
            detail,
        )
    } else if no_room(&detail) {
        ApiError::of(code::STORAGE_FULL, detail)
    } else {
        ApiError::new(
            code::INTERNAL,
            "Raven could not save the photo there. Choose another place.",
            detail,
        )
    }
}

/// Writes the bytes of the attachment `row` to the new file `to`: never
/// over a file that is there, and nothing stays of a write that failed.
fn export_to(dir: &Path, row: &Row, to: &Path) -> Result<(), ApiError> {
    let total = row.shape().map_or(0, |shape| shape.len());
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)
        .map_err(|e| export_error(&e))?;
    let mut write = || -> Result<(), ApiError> {
        let mut at = 0u64;
        while at < total {
            let piece = store::read_plain(dir, row, at, EXPORT_PIECE).map_err(store_error)?;
            if piece.is_empty() {
                return Err(bad("the attachment ended early"));
            }
            file.write_all(&piece).map_err(|e| export_error(&e))?;
            at += piece.len() as u64;
        }
        file.sync_all().map_err(|e| export_error(&e))
    };
    let written = write();
    if written.is_err() {
        drop(file);
        let _ = std::fs::remove_file(to);
    }
    written
}

/// Does this profile hold any attachment (one look at a folder)?
pub(crate) fn any_on_disk(dir: &Path) -> bool {
    !store::rows_on_disk(dir).is_empty()
}

/// Removes every attachment of the chat with the friend whose key is
/// `pub_hex`, at once (`messages.clear`, `chats.delete`): an attachment
/// goes with its message.
pub(crate) fn forget_chat(dir: &Path, pub_hex: &str) -> Result<(), String> {
    let peer = key_of(pub_hex).ok_or("the friend's key is not 32 bytes")?;
    sweep::forget_peer(dir, &peer)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

impl Inner {
    /// Gives each row that carries an attachment its attachment: its
    /// caption as the row's text, where it stands and how many of its bytes
    /// are there. A photo of yours reads delivered, and its message with
    /// it, only once the friend's Raven has every byte: until then a
    /// delivered message reads sent. With the gate shut each such row says
    /// `needs_update` and its plain words. Before anything looks at the
    /// rows' states.
    ///
    /// The store is asked only for the attachments the rows carry: one
    /// look at the names and times of the rows on disk, and a row is read
    /// again only when its file changed (a friend's that still comes: when
    /// its bitmap did).
    pub(crate) fn attach(&self, book: &mut AttBook, views: &mut [View], atts: &RowAtts, now: u64) {
        if !atts.is_empty() {
            for v in views.iter_mut() {
                let Some(mid) = v.mid.as_deref() else {
                    continue;
                };
                match atts.get(v.incoming, &v.peer, mid) {
                    Some(RowAtt::Stored(meta)) => {
                        v.text.clone_from(&meta.caption);
                        v.attachment = Some(AttView::of(meta));
                    }
                    Some(RowAtt::Kept(kind)) => v.attachment = Some(AttView::kept(*kind)),
                    None => {}
                }
            }
        }
        let opens = |v: &View| v.attachment.as_ref().is_some_and(|a| a.open().is_some());
        if !views.iter().any(opens) {
            book.forget();
            return;
        }
        // Shut (this release, or a security notice holds attachments): each
        // says its words, as a build without attachments shows it.
        if !attachment_gate::attachments_live() {
            for v in views.iter_mut() {
                let Some(att) = v.attachment.as_mut() else {
                    continue;
                };
                if let Some(meta) = att.open().cloned() {
                    v.text.clone_from(&meta.words);
                    att.state = AttState::NeedsUpdate;
                }
            }
            book.forget();
            return;
        }
        let Ok(dir) = self.data_dir() else {
            return;
        };
        // A send's message has its id: its attachment's row is told, once.
        for (handle, mid) in std::mem::take(&mut book.named) {
            let _ = flow::sent(dir, &handle, &mid, now);
        }
        let on_disk: HashMap<Handle, SystemTime> = store::rows_on_disk(dir).into_iter().collect();
        book.turn = book.turn.wrapping_add(1);
        let turn = book.turn;
        for v in views.iter_mut() {
            let Some(att) = v.attachment.as_mut() else {
                continue;
            };
            let Some(meta) = att.open().cloned() else {
                continue;
            };
            let known = book.known(dir, &meta.handle, on_disk.get(&meta.handle).copied(), turn);
            // Its row, when that row is this row's attachment: the same
            // chat, the same way, the same offer.
            let row = known.row.as_ref().filter(|row| {
                row.outgoing != v.incoming && row.peer == v.peer && row.digest == meta.digest
            });
            let done = row.map_or(0, |_| known.done.min(meta.bytes));
            if v.incoming {
                att.state = state_in(row, done);
                att.bytes_done = match att.state {
                    AttState::Ready => meta.bytes,
                    _ => done,
                };
            } else {
                att.state = state_out(row, v.state);
                // Every byte is with the friend once the row says so, with
                // or without the receipt of its message.
                let whole = row.is_some_and(|row| row.state == store::State::Delivered);
                att.bytes_done = if whole { meta.bytes } else { done };
                // Two ticks mean the friend has every byte.
                if v.state == State::Delivered && att.state != AttState::Delivered {
                    v.state = State::Sent;
                }
            }
        }
        // A photo of yours whose message ended without arriving, with no
        // other message of yours still carrying it (Send again makes one):
        // its row says so, and raven-node stops asking the friend about
        // it. Send again takes it up again (`attachment_to_retry`): it
        // writes the row first and makes the new message a moment later,
        // so a row that changed just now is left alone.
        let ended = |state: State| {
            matches!(
                state,
                State::Failed | State::TimeRanOut | State::NotSentMeetFirst
            )
        };
        let mut carried: HashMap<Handle, bool> = HashMap::new();
        for v in views.iter().filter(|v| !v.incoming) {
            let Some(handle) = v.attachment.as_ref().and_then(AttView::handle) else {
                continue;
            };
            *carried.entry(handle).or_insert(true) &= ended(v.state);
        }
        for (handle, all_ended) in carried {
            let staged = book.rows.get(&handle).is_some_and(|known| {
                known.row.as_ref().is_some_and(|row| {
                    row.outgoing
                        && row.state == store::State::Staged
                        && now.saturating_sub(row.updated_ms) >= ENDED_GRACE_MS
                })
            });
            if all_ended && staged {
                let _ = store::update(dir, &handle, now, |row| {
                    if row.outgoing && row.state == store::State::Staged {
                        row.state = store::State::Failed;
                    }
                });
            }
        }
        book.rows.retain(|_, known| known.turn == turn);
    }

    /// An `attachment` event for each row whose attachment changed its
    /// state or its progress since the apps were last told, four a second
    /// at most for one row (a change that comes sooner is told at the next
    /// look). A row seen for the first time is only noted: its own row, or
    /// the event that brings it, says where it stands.
    pub(crate) fn observe_attachments(&self, book: &mut AttBook, views: &[View]) {
        let mut live = 0usize;
        for v in views {
            let Some(att) = &v.attachment else {
                continue;
            };
            let Some(meta) = att.open() else {
                continue;
            };
            live += 1;
            if let Some(told) = book.told.get_mut(&v.id) {
                if (told.state, told.done) == (att.state, att.bytes_done)
                    || told.at.is_some_and(|at| at.elapsed() < TOLD_EVERY)
                {
                    continue;
                }
                *told = Told {
                    state: att.state,
                    done: att.bytes_done,
                    at: Some(Instant::now()),
                };
                self.emit(
                    "attachment",
                    json!({
                        "id": meta.id,
                        "message_id": v.id,
                        "address": v.address,
                        "state": att.state.as_str(),
                        "bytes": meta.bytes,
                        "bytes_done": att.bytes_done.min(meta.bytes),
                    }),
                );
            } else {
                book.told.insert(
                    v.id.clone(),
                    Told {
                        state: att.state,
                        done: att.bytes_done,
                        at: None,
                    },
                );
            }
        }
        // Rows that are gone are forgotten.
        if book.told.len() > live {
            let shown: HashSet<&str> = views
                .iter()
                .filter(|v| v.attachment.as_ref().is_some_and(|a| a.open().is_some()))
                .map(|v| v.id.as_str())
                .collect();
            book.told.retain(|id, _| shown.contains(id.as_str()));
        }
    }

    /// The offer of the attachment `handle` of yours, for the send to the
    /// friend with the key `peer` (hex) whose turn has come: made again
    /// from the attachment's row, as the send keeps only the stored form.
    /// `Err`: why it does not go (the send ends as not sent): the row is
    /// gone, sending was stopped, or the friend is not one photos go to
    /// any more.
    pub(crate) fn offer_to_send(
        &self,
        handle: &Handle,
        peer: &str,
    ) -> Result<Zeroizing<String>, String> {
        let dir = self.data_dir().map_err(|e| e.detail)?;
        offer_for(dir, handle, peer)
    }

    /// `messages.retry` on the row `view`: its attachment of yours, when it
    /// carries one, and whether sending it was taken up again here (it was
    /// stopped with `attachments.cancel`; the node then asks the friend
    /// what it has). None: a row without an attachment. `Err`: one that
    /// cannot go again: this build does not open it, or its sealed bytes
    /// are no longer on this device.
    pub(crate) fn attachment_to_retry(
        &self,
        view: &View,
    ) -> Result<Option<(Arc<Meta>, bool)>, ApiError> {
        let Some(att) = &view.attachment else {
            return Ok(None);
        };
        // One this build does not open is never sent again as its words.
        let Some(meta) = att.open().cloned() else {
            return Err(not_yet());
        };
        gate()?;
        let dir = self.data_dir()?;
        let row = store::get(dir, &meta.handle)
            .map_err(store_error)?
            .map(|row| (Brief::of(&row), row))
            .filter(|(brief, _)| {
                brief.outgoing && brief.peer == view.peer && brief.digest == meta.digest
            })
            .ok_or_else(|| gone("the photo's sealed bytes are no longer on this device"))?
            .1;
        let resumed = match row.state {
            store::State::Gone => return Err(gone("the photo was deleted")),
            store::State::Failed => store::update(dir, &meta.handle, now_ms(), |row| {
                if row.outgoing && row.state == store::State::Failed {
                    row.state = store::State::Staged;
                }
            })
            .map_err(store_error)?,
            _ => false,
        };
        Ok(Some((meta, resumed)))
    }

    /// The attachment `meta` of the ended row `view` goes again, as a new
    /// message that carries the same offer: `{"message": ...}` as
    /// `attachments.send` answers.
    pub(crate) fn attachment_sent_again(&self, view: &View, meta: &Arc<Meta>) -> OpResult {
        let c = self.contact(&view.address)?;
        let dir = self.data_dir()?;
        may_send(dir, &c)?;
        let row = store::get(dir, &meta.handle)
            .map_err(store_error)?
            .ok_or_else(|| gone("the photo's sealed bytes are no longer on this device"))?;
        let pending = self.take_send(&c, row.reference.clone(), Some(Arc::clone(meta)))?;
        Ok(json!({"message": first_row(&pending, meta).json()}))
    }

    /// `messages.delete` on the ended row `view` of yours: its attachment
    /// goes with it, at once. The row of the store first (the key goes with
    /// it), then the sealed bytes. Nothing for a row without one, and
    /// nothing while another message of yours among `rows` that has not
    /// ended carries the same attachment (Send again made it): it goes
    /// with that one.
    pub(crate) fn forget_attachment(&self, view: &View, rows: &[View]) -> Result<(), String> {
        let handle_of = |v: &View| v.attachment.as_ref().and_then(AttView::handle);
        let Some(handle) = handle_of(view) else {
            return Ok(());
        };
        let still_carried = rows.iter().any(|v| {
            v.id != view.id
                && !v.incoming
                && handle_of(v) == Some(handle)
                && !matches!(
                    v.state,
                    State::Failed | State::TimeRanOut | State::NotSentMeetFirst
                )
        });
        if still_carried {
            return Ok(());
        }
        let dir = self.data_dir().map_err(|e| e.detail)?;
        store::remove(dir, &handle).map_err(|e| e.to_string())
    }

    /// `attachments.can_send {address | group}`: `{photos, max_bytes,
    /// why?}`. Photos go to a friend you verified and did not block, whose
    /// Raven said it takes them; `why` says in plain words what is missing.
    pub(crate) fn attachments_can_send(&self, args: &Args) -> OpResult {
        let answer = |why: Option<String>| {
            let mut v = json!({"photos": why.is_none(), "max_bytes": LIVE_MAX_LEN});
            if let Some(why) = why {
                v["why"] = why.into();
            }
            v
        };
        if args.has("group") && !args.has("address") {
            crate::groups::group_arg(args)?;
            return Ok(answer(Some(
                "Photos in groups are not in this version of Raven yet".into(),
            )));
        }
        let address = args.str("address")?;
        if !attachment_gate::attachments_live() {
            return Ok(answer(Some(
                "Photos are not in this version of Raven yet".into(),
            )));
        }
        let c = self.contact(address)?;
        let dir = self.data_dir()?;
        Ok(answer(cannot_send_now(dir, &c).map(|(_, why)| why)))
    }

    /// `attachments.stage {name?}`: `{path}`, a new empty file in the
    /// profile's staging folder for the app to write what it wants sent.
    /// `name` only gives the file its ending.
    pub(crate) fn attachments_stage(&self, args: &Args) -> OpResult {
        gate()?;
        self.identity()?;
        let name = args.opt_str("name")?.unwrap_or("");
        let dir = self.data_dir()?;
        // The first file this run stages: what an earlier run left in the
        // staging folder (the app ended between staging and sending) goes
        // first. Those are photos as the app wrote them, not sealed.
        {
            static CLEARED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
            let mut cleared = CLEARED.lock().unwrap_or_else(|e| e.into_inner());
            if !cleared.iter().any(|done| done == dir) {
                cleared.push(dir.to_path_buf());
                store::clear_staging(dir);
            }
        }
        let path = store::stage(dir, name).map_err(store_error)?;
        // The app must get the path as it is: every string of an answer is
        // cleaned for display on its way out.
        match path.to_str().filter(|p| safety::text(p) == *p) {
            Some(path) => Ok(json!({"path": path})),
            None => {
                let _ = std::fs::remove_file(&path);
                Err(ApiError::internal(
                    "the profile folder's path has characters an answer cannot carry",
                ))
            }
        }
    }

    /// `attachments.send {address, path, kind: "photo", mime?, caption?,
    /// preview_b64, width, height}`: `{"message": ...}`, the new row with
    /// its attachment, at once. The staged file `path` is sealed into the
    /// attachment store and deleted, whatever comes next; the message that
    /// carries the offer goes as `messages.send` sends one.
    pub(crate) fn attachments_send(&self, args: &Args) -> OpResult {
        gate()?;
        self.identity()?;
        let dir = self.data_dir()?.to_path_buf();
        let path = PathBuf::from(args.str("path")?);
        if !store::is_staged(&dir, &path) {
            return Err(ApiError::new(
                code::BAD_REQUEST,
                "Raven could not find the photo to send. Choose it again.",
                "\"path\" is not a file attachments.stage gave",
            ));
        }
        let _staged = Staged(path.clone());
        if args.has("group") {
            return Err(ApiError::new(
                code::NOT_AVAILABLE_YET,
                "Photos in groups are not in this version of Raven yet. Nothing was sent.",
                "attachments.send: groups are not built yet",
            ));
        }
        let address = args.str("address")?;
        match args.str("kind")? {
            "photo" => {}
            "voice" | "file" => {
                return Err(ApiError::new(
                    code::NOT_AVAILABLE_YET,
                    "Only photos can be sent in this version of Raven. Nothing was sent.",
                    "attachments.send: only kind \"photo\" is built yet",
                ))
            }
            other => {
                return Err(ApiError::bad_request(format!(
                    "\"kind\" {} is not known",
                    safety::line(other)
                )))
            }
        }
        if args
            .opt_str("mime")?
            .is_some_and(|mime| mime != offer::MIME_JPEG)
        {
            return Err(ApiError::new(
                code::ATTACHMENT_BAD,
                "This photo could not be sent. Choose it again.",
                "a photo is sent as image/jpeg",
            ));
        }
        let caption = args.opt_str("caption")?.unwrap_or("");
        check_caption(caption)?;
        let side = |key: &str| -> Result<u32, ApiError> {
            args.opt_u64(key)?
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| {
                    ApiError::bad_request(format!("\"{key}\" must be the photo's size in pixels"))
                })
        };
        let (width, height) = (side("width")?, side("height")?);
        let preview = match args.opt_str("preview_b64")? {
            Some(text) => BASE64.decode(text.trim()).map_err(|e| {
                ApiError::bad_request(format!("\"preview_b64\" is not base64: {e}"))
            })?,
            None => Vec::new(),
        };
        let c = self.contact(address)?;
        let peer = key_of(&c.pub_hex)
            .ok_or_else(|| ApiError::internal("the friend's key is not 32 bytes"))?;
        may_send(&dir, &c)?;
        let bytes = read_staged(&path)?;
        let media = Media::Photo {
            caption,
            width,
            height,
            preview: &preview,
        };
        let flow::Prepared { handle, offer } =
            flow::prepare(&dir, &peer, &bytes, &media, now_ms()).map_err(flow_error)?;
        // The send keeps the stored form, as the attachment's row has it:
        // the offer (it holds the key) is made again when its turn comes.
        drop(Zeroizing::new(offer));
        drop(bytes);
        let taken = store::get(&dir, &handle)
            .map_err(store_error)
            .and_then(|row| row.ok_or_else(|| gone("the photo's row is gone")))
            .and_then(|row| match Meta::parse(&row.reference) {
                Some(meta) => Ok((row.reference.clone(), Arc::new(meta))),
                None => Err(bad("the photo's row does not read")),
            })
            .and_then(|(stored, meta)| {
                self.take_send(&c, stored, Some(Arc::clone(&meta)))
                    .map(|pending| (pending, meta))
            });
        match taken {
            Ok((pending, meta)) => Ok(json!({"message": first_row(&pending, &meta).json()})),
            Err(e) => {
                // Its message could not be made: nothing of it stays.
                flow::discard(&dir, &handle);
                Err(e)
            }
        }
    }

    /// `attachments.get {id}`: `{"attachment": ...}` as a message row has
    /// it.
    pub(crate) fn attachments_get(&self, args: &Args) -> OpResult {
        gate()?;
        let handle = id_arg(args)?;
        self.identity()?;
        let snap = self.refresh(Duration::from_millis(1500))?;
        // The newest row that carries it says where it stands.
        let shown = snap
            .views
            .iter()
            .rev()
            .filter_map(|v| v.attachment.as_ref())
            .find(|att| att.handle() == Some(handle));
        if let Some(att) = shown {
            return Ok(json!({"attachment": att.json()}));
        }
        // No row carries it (any more): what its own row says.
        let dir = self.data_dir()?;
        let row = store::get(dir, &handle)
            .map_err(store_error)?
            .ok_or_else(|| gone("no such attachment on this device"))?;
        let meta =
            Meta::parse(&row.reference).ok_or_else(|| bad("the attachment's row does not read"))?;
        let brief = Brief::of(&row);
        let done = store::progress(dir, &row).0;
        let state = if brief.outgoing {
            // No message row to ask: the friend's node took the offer, so
            // its message arrived.
            let message = match brief.state {
                store::State::Offered | store::State::Delivered => State::Delivered,
                _ => State::Sending,
            };
            state_out(Some(&brief), message)
        } else {
            state_in(Some(&brief), done)
        };
        let att = AttView {
            kind: meta.kind,
            meta: Some(Arc::new(meta)),
            state,
            bytes_done: done,
        };
        Ok(json!({"attachment": att.json()}))
    }

    /// `attachments.read {id, offset?, length?}`: `{bytes_b64, eof}`, a
    /// piece of the attachment's own bytes, opened in memory. At most
    /// 524,288 bytes a call. Only an attachment of yours, or a friend's
    /// that is ready.
    pub(crate) fn attachments_read(&self, args: &Args) -> OpResult {
        gate()?;
        let handle = id_arg(args)?;
        let offset = args.opt_u64("offset")?.unwrap_or(0);
        let length = args.opt_u64("length")?.unwrap_or(READ_MAX);
        if length > READ_MAX {
            return Err(ApiError::bad_request(format!(
                "\"length\" must be at most {READ_MAX}"
            )));
        }
        self.identity()?;
        let dir = self.data_dir()?;
        let row = readable(dir, &handle)?;
        let total = row.shape().map_or(0, |shape| shape.len());
        let piece = store::read_plain(dir, &row, offset, length as usize).map_err(store_error)?;
        let eof = offset.saturating_add(piece.len() as u64) >= total;
        Ok(json!({"bytes_b64": BASE64.encode(&piece[..]), "eof": eof}))
    }

    /// `attachments.download {id}`: `{}`. A friend's attachment that is
    /// not all here is asked for now: raven-node fetches it at once (a
    /// photo comes by itself; this is for a retry).
    pub(crate) fn attachments_download(&self, args: &Args) -> OpResult {
        gate()?;
        let handle = id_arg(args)?;
        self.identity()?;
        let dir = self.data_dir()?;
        let row = store::get(dir, &handle)
            .map_err(store_error)?
            .ok_or_else(|| gone("no such attachment on this device"))?;
        if !row.outgoing {
            match row.state {
                store::State::Incoming => {
                    let now = now_ms();
                    // Asked for, now: also one asked for before, so that
                    // the node tries again at once.
                    store::update(dir, &handle, now, |row| {
                        if !row.outgoing && row.state == store::State::Incoming {
                            row.asked = true;
                            row.updated_ms = now;
                        }
                    })
                    .map_err(store_error)?;
                }
                store::State::Gone => {
                    return Err(gone("the friend deleted it before it was all here"))
                }
                store::State::Failed => return Err(bad("a check of its bytes failed")),
                _ => {}
            }
        }
        Ok(json!({}))
    }

    /// `attachments.cancel {id}`: `{}`. Sending an attachment of yours
    /// that the friend does not have yet is stopped, and its message with
    /// it when that has not gone yet (`messages.retry` on the row takes it
    /// up again). A friend's attachment is not asked for any more.
    pub(crate) fn attachments_cancel(&self, args: &Args) -> OpResult {
        gate()?;
        let handle = id_arg(args)?;
        self.identity()?;
        let dir = self.data_dir()?;
        let row = store::get(dir, &handle)
            .map_err(store_error)?
            .ok_or_else(|| gone("no such attachment on this device"))?;
        let unsent = |row: &Row| {
            row.outgoing && matches!(row.state, store::State::Staged | store::State::Offered)
        };
        if unsent(&row) {
            store::update(dir, &handle, now_ms(), |row| {
                if unsent(row) {
                    row.state = store::State::Failed;
                }
            })
            .map_err(store_error)?;
            self.stop_offer_of(&handle);
        } else if !row.outgoing && row.asked {
            store::update(dir, &handle, now_ms(), |row| {
                if !row.outgoing {
                    row.asked = false;
                }
            })
            .map_err(store_error)?;
        }
        // The apps hear of it at once.
        let _ = self.refresh(Duration::ZERO);
        Ok(json!({}))
    }

    /// The message that carries the offer of the attachment `handle` of
    /// yours is stopped when it has not gone yet (it waits for its turn
    /// here, or for the friend in raven-node's outbox): an offer whose
    /// bytes will not come is not left with the friend. Best effort.
    fn stop_offer_of(&self, handle: &Handle) {
        let Ok(snap) = self.refresh(Duration::ZERO) else {
            return;
        };
        let waits = |v: &&View| {
            !v.incoming
                && v.attachment.as_ref().and_then(AttView::handle) == Some(*handle)
                && (v.state == State::Waiting
                    || v.pending.as_ref().is_some_and(|p| p.job == Job::Queued))
        };
        for v in snap.views.iter().filter(waits) {
            let stop = json!({"id": v.id});
            if let Value::Object(map) = &stop {
                let _ = self.messages_stop(&Args(map));
            }
        }
    }

    /// `attachments.export {id, to_path}`: `{}`. Writes the attachment's
    /// own bytes to a new file where the user chose: never over a file
    /// that is there, never inside the profile folder.
    pub(crate) fn attachments_export(&self, args: &Args) -> OpResult {
        gate()?;
        let handle = id_arg(args)?;
        let to = PathBuf::from(args.str("to_path")?);
        self.identity()?;
        let dir = self.data_dir()?;
        export_place(dir, &to)?;
        let row = readable(dir, &handle)?;
        export_to(dir, &row, &to)?;
        Ok(json!({}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::OutboxSnap;
    use crate::messages::{views, MessageBook};
    use raven_core::attachment::blob::{Key, Shape, KEY_LEN, SEGMENT_LEN};
    use raven_core::attachment::offer::{BlobRef, Offer};
    use raven_core::attachment::store::State as Stored;

    /// The friend of these tests, and somebody else.
    const FRIEND: [u8; 32] = [7u8; 32];
    const OTHER: [u8; 32] = [8u8; 32];

    /// The attachments gate for this test's thread; back to the build's own
    /// when dropped. A release build follows its const alone: there the
    /// gate is shut, and a test that needs it open has nothing to do.
    struct Gate;

    impl Gate {
        fn open() -> Option<Gate> {
            cfg!(debug_assertions).then(|| {
                attachment_gate::set_lab_attachments_for_this_thread(Some(true));
                Gate
            })
        }

        fn shut() -> Gate {
            attachment_gate::set_lab_attachments_for_this_thread(Some(false));
            Gate
        }
    }

    impl Drop for Gate {
        fn drop(&mut self) {
            attachment_gate::set_lab_attachments_for_this_thread(None);
        }
    }

    fn jpeg(len: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
        bytes[..3].copy_from_slice(&[0xFF, 0xD8, 0xFF]);
        bytes
    }

    /// A profile folder in which Max (the key `friend`) is a friend:
    /// verified when `pinned`, and his Raven takes photos.
    fn profile_with(friend: &[u8; 32], pinned: bool) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let rows = json!([{
            "petname": "Max",
            "pub_hex": hex::encode(friend),
            "address": "",
            "pinned": pinned,
        }]);
        std::fs::write(dir.path().join("contacts.json"), rows.to_string()).unwrap();
        raven_core::chat_history::BlockList::default()
            .save(dir.path())
            .unwrap();
        peers::note(dir.path(), friend, true, 1).unwrap();
        dir
    }

    fn profile(friend: &[u8; 32]) -> tempfile::TempDir {
        profile_with(friend, true)
    }

    /// A photo of mine for `friend`, sealed in `dir` (the gate is open):
    /// its handle, its offer and its own bytes.
    fn photo(
        dir: &Path,
        friend: &[u8; 32],
        len: usize,
        caption: &str,
    ) -> (Handle, String, Vec<u8>) {
        let bytes = jpeg(len);
        let media = Media::Photo {
            caption,
            width: 1_600,
            height: 1_200,
            preview: &[1, 2, 3, 4],
        };
        let made = flow::prepare(dir, friend, &bytes, &media, 10).unwrap();
        (made.handle, made.offer, bytes)
    }

    /// A photo's offer as it travels, made without a store (any gate).
    fn offer_text(caption: &str) -> String {
        let blob = BlobRef {
            shape: Shape::of(200_000).unwrap(),
            key: Key::from_bytes([3u8; KEY_LEN]),
            root: [4u8; 32],
        };
        Offer::photo(blob, caption, 800, 600, &[9, 9])
            .unwrap()
            .encode()
            .unwrap()
    }

    fn history_row(
        dir: &Path,
        direction: &str,
        peer: &[u8; 32],
        mid: u8,
        delivery: &str,
        body: &str,
    ) {
        raven_core::persist_lan_chat_history(
            dir,
            direction,
            peer,
            &[mid; 16],
            5,
            delivery,
            body.as_bytes(),
        )
        .unwrap();
    }

    /// The rows of the profile as a look at it gives them: what `refresh`
    /// does with the history, without the parts that need an identity.
    fn look(inner: &Inner, book: &mut MessageBook, dir: &Path) -> Vec<View> {
        let (entries, atts) = shown_history(ChatHistory::load(dir).unwrap());
        let mut rows = views(book, &entries, &OutboxSnap::default(), &[], 20);
        inner.attach(&mut book.att, &mut rows, &atts, 20);
        inner.observe_attachments(&mut book.att, &rows);
        rows
    }

    /// The events since `after`.
    fn events(inner: &Inner, after: &mut u64) -> Vec<Value> {
        let batch = inner.events.poll(*after);
        *after = batch.seq;
        batch.events
    }

    fn pending(body: &str, attachment: Option<Arc<Meta>>) -> Pending {
        Pending {
            id: "pending-1".into(),
            peer: hex::encode(FRIEND),
            address: "rvn1x".into(),
            body: body.into(),
            created_ms: 1,
            started: Instant::now(),
            snapshot: HashSet::new(),
            bound_mid: None,
            job: Job::Running,
            outcome: None,
            raw: String::new(),
            path: None,
            via: None,
            finished: None,
            kept: None,
            kept_before: None,
            attachment,
        }
    }

    fn brief(outgoing: bool, state: Stored, friend_has: u32) -> Brief {
        Brief {
            outgoing,
            peer: hex::encode(FRIEND),
            state,
            friend_has,
            updated_ms: 0,
            digest: 1,
        }
    }

    fn max(pinned: bool, blocked: bool) -> ContactView {
        ContactView {
            pub_hex: hex::encode(FRIEND),
            address: "rvn1max".into(),
            label: "Max".into(),
            petname: "Max".into(),
            pinned,
            blocked,
            lan_dial: String::new(),
            internet_dial: String::new(),
            p2p: String::new(),
        }
    }

    /// Plain words: no hyphen, dash or apostrophe.
    fn plain(words: &str) -> bool {
        !words.contains(['-', '\u{2013}', '\u{2014}', '\'', '\u{2019}'])
    }

    #[test]
    fn a_friends_attachment_stands_as_its_row_says() {
        assert_eq!(state_in(None, 0), AttState::Failed);
        let coming = brief(false, Stored::Incoming, 0);
        assert_eq!(state_in(Some(&coming), 0), AttState::Offered);
        assert_eq!(state_in(Some(&coming), 61_424), AttState::Downloading);
        let at = |state| state_in(Some(&brief(false, state, 0)), 5);
        assert_eq!(at(Stored::Complete), AttState::Ready);
        assert_eq!(at(Stored::Gone), AttState::Gone);
        assert_eq!(at(Stored::Failed), AttState::Failed);
        // A row of mine is never a friend's attachment.
        for mine in [Stored::Staged, Stored::Offered, Stored::Delivered] {
            assert_eq!(at(mine), AttState::Failed, "{mine:?}");
        }
    }

    #[test]
    fn an_attachment_of_yours_stands_as_its_row_and_its_message_say() {
        use State as M;
        let every = [
            M::Sending,
            M::Sent,
            M::Delivered,
            M::Waiting,
            M::TimeRanOut,
            M::NotSentMeetFirst,
            M::Failed,
        ];
        let staged = brief(true, Stored::Staged, 0);
        let offered = brief(true, Stored::Offered, 0);
        let going = brief(true, Stored::Offered, 2);
        for message in every {
            // No row: it cannot go. The friend has every byte: delivered
            // once the receipt of its message is here too, and never before
            // it (the row and the receipt are written by different hands, in
            // either order). Stopped or deleted: failed.
            assert_eq!(state_out(None, message), AttState::Failed);
            let at = |state| state_out(Some(&brief(true, state, 0)), message);
            let whole = match message {
                M::Delivered => AttState::Delivered,
                M::Failed | M::TimeRanOut | M::NotSentMeetFirst => AttState::Failed,
                M::Sending | M::Sent | M::Waiting => AttState::Sending,
            };
            assert_eq!(at(Stored::Delivered), whole, "{message:?}");
            assert_eq!(at(Stored::Failed), AttState::Failed, "{message:?}");
            assert_eq!(at(Stored::Gone), AttState::Failed, "{message:?}");
            // Not a row of mine.
            assert_eq!(at(Stored::Complete), AttState::Failed, "{message:?}");
            assert_eq!(at(Stored::Incoming), AttState::Failed, "{message:?}");
        }
        // Else by the message: still being sent, waiting, not sent.
        for row in [&staged, &offered, &going] {
            assert_eq!(state_out(Some(row), M::Sending), AttState::Sending);
            assert_eq!(state_out(Some(row), M::Waiting), AttState::Waiting);
            for ended in [M::Failed, M::TimeRanOut, M::NotSentMeetFirst] {
                assert_eq!(state_out(Some(row), ended), AttState::Failed, "{ended:?}");
            }
        }
        // The offer was delivered: sent, and sending once the friend's node
        // has some of the bytes.
        assert_eq!(state_out(Some(&staged), M::Delivered), AttState::Sent);
        assert_eq!(state_out(Some(&offered), M::Delivered), AttState::Sent);
        assert_eq!(state_out(Some(&going), M::Delivered), AttState::Sending);
        // Written to the friend's computer, no receipt yet: still sending,
        // until the friend's node says it has the offer.
        assert_eq!(state_out(Some(&staged), M::Sent), AttState::Sending);
        assert_eq!(state_out(Some(&offered), M::Sent), AttState::Sent);
        assert_eq!(state_out(Some(&going), M::Sent), AttState::Sending);
        for state in [
            AttState::Offered,
            AttState::Downloading,
            AttState::Ready,
            AttState::Gone,
            AttState::Failed,
            AttState::Sending,
            AttState::Sent,
            AttState::Delivered,
            AttState::Waiting,
            AttState::NeedsUpdate,
        ] {
            let word = state.as_str();
            assert!(
                word.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{word}"
            );
        }
    }

    #[test]
    fn photos_go_to_a_verified_friend_whose_raven_takes_them() {
        assert_eq!(cannot_send(&max(true, false), true, true), None);
        let why = |c: ContactView, friend, speaks| cannot_send(&c, friend, speaks).unwrap();
        assert_eq!(
            why(max(true, false), true, false),
            (
                code::FRIEND_NEEDS_NEWER_RAVEN,
                "Max cannot get photos yet. Their Raven has not said that it takes them".to_owned()
            )
        );
        assert_eq!(
            why(max(false, false), false, true),
            (
                code::BAD_REQUEST,
                "Verify Max first to send photos".to_owned()
            )
        );
        assert_eq!(
            why(max(true, true), false, true),
            (
                code::CONTACT_BLOCKED,
                "Unblock Max to send photos".to_owned()
            )
        );
        // raven-core decides: a friends list it could not read sends nothing,
        // whatever the engine read before.
        let unreadable = why(max(true, false), false, true);
        assert_eq!(unreadable.0, code::BAD_REQUEST);
        let mut nameless = max(true, false);
        nameless.label = " ".into();
        let words = [
            why(max(true, false), true, false).1,
            why(max(false, false), false, true).1,
            why(max(true, true), false, true).1,
            unreadable.1,
            why(nameless.clone(), true, false).1,
            why(nameless, false, true).1,
        ];
        assert_eq!(
            words[4],
            "Your friend cannot get photos yet. Their Raven has not said that it takes them"
        );
        assert_eq!(
            words[5],
            "Raven cannot send photos to your friend right now"
        );
        for w in &words {
            assert!(plain(w), "{w}");
        }

        // Asked of a profile: the contact book and the friend's record.
        let home = profile(&FRIEND);
        assert_eq!(cannot_send_now(home.path(), &max(true, false)), None);
        let old = tempfile::tempdir().unwrap();
        std::fs::copy(
            home.path().join("contacts.json"),
            old.path().join("contacts.json"),
        )
        .unwrap();
        assert_eq!(
            cannot_send_now(old.path(), &max(true, false)).unwrap().0,
            code::FRIEND_NEEDS_NEWER_RAVEN,
            "no record of the friend's Raven"
        );
        // The engine read "verified" a moment ago; the book says no now.
        let stale = profile_with(&FRIEND, false);
        assert_eq!(
            cannot_send_now(stale.path(), &max(true, false)).unwrap().0,
            code::BAD_REQUEST
        );
        assert!(may_send(home.path(), &max(true, false)).is_ok());
        let refused = may_send(stale.path(), &max(false, false)).unwrap_err();
        assert_eq!(refused.code, code::BAD_REQUEST);
        assert_eq!(refused.message, "Verify Max first to send photos.");
    }

    #[test]
    fn every_operation_but_can_send_is_refused_while_the_gate_is_shut() {
        let _gate = Gate::shut();
        let dir = tempfile::tempdir().unwrap();
        let inner = Inner::new(Ok(dir.path().to_path_buf()));
        let call = |op: &str, args: Value| {
            inner.handle(&json!({"v": 1, "op": op, "args": args}).to_string())
        };
        let id = "ab".repeat(16);
        let send = json!({
            "address": "rvn1whoever", "path": "/nowhere/photo.jpg", "kind": "photo",
            "mime": "image/jpeg", "width": 10, "height": 10,
        });
        for (op, args) in [
            ("attachments.stage", json!({"name": "photo.jpg"})),
            ("attachments.send", send),
            ("attachments.get", json!({"id": id})),
            (
                "attachments.read",
                json!({"id": id, "offset": 0, "length": 10}),
            ),
            ("attachments.download", json!({"id": id})),
            ("attachments.cancel", json!({"id": id})),
            (
                "attachments.export",
                json!({"id": id, "to_path": "/nowhere/p.jpg"}),
            ),
        ] {
            let answer = call(op, args);
            assert_eq!(answer["ok"], false, "{op}: {answer}");
            assert_eq!(
                answer["error"]["code"],
                code::NOT_AVAILABLE_YET,
                "{op}: {answer}"
            );
            let message = answer["error"]["message"].as_str().unwrap();
            assert!(plain(message) && message.ends_with('.'), "{op}: {message}");
        }
        // Nothing was made for them.
        assert!(!dir.path().join(store::STAGING_DIR).exists());
        assert!(!dir.path().join(store::ROWS_DIR).exists());
        // `can_send` answers, so that an app shows no attach button.
        for args in [
            json!({"address": "rvn1whoever"}),
            json!({"group": "ab".repeat(16)}),
        ] {
            let can = call("attachments.can_send", args);
            assert_eq!(can["ok"], true, "{can}");
            assert_eq!(can["result"]["photos"], false, "{can}");
            assert_eq!(can["result"]["max_bytes"], 1_048_576, "{can}");
            let why = can["result"]["why"].as_str().unwrap();
            assert!(!why.is_empty() && plain(why), "{why}");
        }
        assert_eq!(
            call("attachments.can_send", json!({}))["error"]["code"],
            code::BAD_REQUEST
        );
    }

    /// A build with the gate shut (every release today): a row that holds a
    /// photo says plain words and `needs_update`, an offer it kept as it
    /// came the line that asks for an update, and nothing an app reads
    /// starts with `RVNATT/`. With the gate open the same rows carry their
    /// attachment.
    #[test]
    fn a_row_never_shows_an_attachment_text_whatever_the_gate() {
        let home = profile(&FRIEND);
        let d = home.path();
        let offer = offer_text("on the bridge");
        {
            // What a build with the gate shut writes: mine as its stored
            // form, a friend's as it came.
            let _gate = Gate::shut();
            history_row(d, "out", &FRIEND, 1, "delivered", &offer);
            history_row(d, "in", &FRIEND, 2, "received", &offer);
            history_row(d, "in", &FRIEND, 3, "received", "hello");
        }
        // A friend's profile offer is kept in a row no reader shows.
        let profile_offer = Offer::no_profile([5u8; 16], 7, 0)
            .unwrap()
            .encode()
            .unwrap();
        raven_core::lan_dispatch::persist_profile_offer(
            d,
            &FRIEND,
            &[4u8; 16],
            5,
            7,
            profile_offer.as_bytes(),
        )
        .unwrap();
        let on_disk = ChatHistory::load(d).unwrap();
        assert_eq!(on_disk.entries.len(), 4);
        assert!(on_disk.entries[0].body.starts_with("RVNATT/1 ref\n"));
        assert!(on_disk.entries[1].body.starts_with("RVNATT/1 offer\n"));

        let (entries, atts) = shown_history(on_disk);
        assert_eq!(entries.len(), 3, "the profile offer's row is never shown");
        let peer = hex::encode(FRIEND);
        let mid = |n: u8| hex::encode([n; 16]);
        assert!(matches!(
            atts.get(false, &peer, &mid(1)),
            Some(RowAtt::Stored(_))
        ));
        assert!(matches!(
            atts.get(true, &peer, &mid(2)),
            Some(RowAtt::Kept(Kind::Photo))
        ));
        assert!(atts.get(true, &peer, &mid(3)).is_none());
        assert!(atts.get(true, &peer, &mid(4)).is_none());
        assert!(atts.get(true, &peer, &mid(1)).is_none(), "by direction");

        let inner = Inner::new(Ok(d.to_path_buf()));
        let shown = |gate: &str| -> Vec<Value> {
            let mut book = MessageBook::default();
            // The rows alone never hold the stored form as text ...
            let (entries, _) = shown_history(ChatHistory::load(d).unwrap());
            for v in views(&mut book, &entries, &OutboxSnap::default(), &[], 20) {
                assert!(!v.text.contains("RVNATT/"), "{gate}: {}", v.text);
            }
            // ... and with their attachments nothing an app reads does.
            let rows: Vec<Value> = look(&inner, &mut book, d).iter().map(View::json).collect();
            assert_eq!(rows.len(), 3, "{gate}");
            for row in &rows {
                assert!(!row.to_string().contains("RVNATT/"), "{gate}: {row}");
            }
            assert_eq!(rows[2]["text"], "hello");
            assert!(rows[2].get("attachment").is_none(), "{gate}");
            rows
        };

        let needs_update = json!({"kind": "photo", "state": "needs_update"});
        {
            let _gate = Gate::shut();
            let rows = shown("shut");
            assert_eq!(rows[0]["text"], "Photo");
            assert_eq!(rows[0]["attachment"], needs_update);
            assert_eq!(
                rows[0]["state"], "delivered",
                "a plain bubble with its own state"
            );
            assert_eq!(rows[1]["text"], "Max sent a photo. Update Raven to see it.");
            assert_eq!(rows[1]["attachment"], needs_update);
        }
        let Some(_gate) = Gate::open() else { return };
        let rows = shown("open");
        // Mine: its caption and its attachment. Its sealed bytes are not on
        // this device (it was never sealed here): failed, and its message
        // reads sent, never delivered.
        assert_eq!(rows[0]["text"], "on the bridge");
        let att = &rows[0]["attachment"];
        assert_eq!(att["state"], "failed");
        assert_eq!(att["kind"], "photo");
        assert_eq!(att["id"].as_str().unwrap().len(), 32);
        assert_eq!(
            (att["bytes"].as_u64(), att["bytes_done"].as_u64()),
            (Some(200_000), Some(0))
        );
        assert_eq!(
            (att["width"].as_u64(), att["height"].as_u64()),
            (Some(800), Some(600))
        );
        assert_eq!(att["preview_b64"], BASE64.encode([9u8, 9]));
        assert_eq!(att["caption"], "on the bridge");
        assert_eq!(rows[0]["state"], "sent");
        // The offer kept as it came stays so until raven-node takes it up.
        assert_eq!(rows[1]["text"], "Max sent a photo. Update Raven to see it.");
        assert_eq!(rows[1]["attachment"], needs_update);
    }

    #[test]
    fn a_friends_photo_goes_from_offered_to_ready_and_each_step_is_told() {
        let Some(_gate) = Gate::open() else { return };
        let (theirs, home) = (tempfile::tempdir().unwrap(), profile(&FRIEND));
        let (a, b) = (theirs.path(), home.path());
        let (handle, offer, bytes) = photo(a, &OTHER, 200_000, "the bridge");
        history_row(b, "in", &FRIEND, 3, "received", &offer);
        let inner = Inner::new(Ok(b.to_path_buf()));
        let mut book = MessageBook::default();
        let mut after = 0;
        let later = || std::thread::sleep(TOLD_EVERY + Duration::from_millis(60));

        let rows = look(&inner, &mut book, b);
        assert_eq!(rows.len(), 1);
        let row = rows[0].json();
        assert_eq!(row["text"], "the bridge");
        assert_eq!(row["direction"], "in");
        let att = &row["attachment"];
        assert_eq!(att["id"], hex::encode(handle));
        assert_eq!(att["kind"], "photo");
        assert_eq!(att["state"], "offered");
        assert_eq!(
            (att["bytes"].as_u64(), att["bytes_done"].as_u64()),
            (Some(200_000), Some(0))
        );
        assert_eq!(
            (att["width"].as_u64(), att["height"].as_u64()),
            (Some(1_600), Some(1_200))
        );
        assert_eq!(att["preview_b64"], BASE64.encode([1u8, 2, 3, 4]));
        assert_eq!(att["caption"], "the bridge");
        assert!(!row.to_string().contains("RVNATT/"), "{row}");
        // Seen for the first time: its row said it. No event.
        assert!(events(&inner, &mut after).is_empty());
        // Not readable before it is all here.
        assert_eq!(readable(b, &handle).unwrap_err().code, code::BAD_REQUEST);

        // Chunks land (raven-node takes them), a moment apart.
        let sealed = store::get(a, &handle).unwrap().unwrap();
        let (shape, root) = (sealed.shape().unwrap(), sealed.root().unwrap());
        let tree = store::tree(a, &sealed).unwrap();
        let land = |index: u32| {
            std::thread::sleep(Duration::from_millis(3));
            let chunk = store::read_chunk(a, &handle, &shape, true, index).unwrap();
            let path = tree.chunk_path(index as usize).unwrap();
            store::take_chunk(b, &handle, &shape, &root, index, &chunk, &path).unwrap();
        };
        assert!(shape.chunks() >= 3);
        land(0);
        let rows = look(&inner, &mut book, b);
        let att = rows[0].json()["attachment"].clone();
        assert_eq!(att["state"], "downloading");
        assert_eq!(att["bytes_done"], SEGMENT_LEN as u64);
        let told = events(&inner, &mut after);
        assert_eq!(told.len(), 1, "{told:?}");
        assert_eq!(told[0]["kind"], "attachment");
        assert_eq!(told[0]["id"], hex::encode(handle));
        assert_eq!(told[0]["message_id"], rows[0].id.as_str());
        assert_eq!(told[0]["address"], rows[0].address.as_str());
        assert_eq!(told[0]["state"], "downloading");
        assert_eq!(told[0]["bytes"], 200_000);
        assert_eq!(told[0]["bytes_done"], SEGMENT_LEN as u64);
        // Four a second at most: a change that comes sooner shows in the
        // row at once and is told at the next look after its time.
        land(1);
        let rows = look(&inner, &mut book, b);
        assert_eq!(
            rows[0].json()["attachment"]["bytes_done"],
            2 * SEGMENT_LEN as u64
        );
        assert!(events(&inner, &mut after).is_empty());
        later();
        look(&inner, &mut book, b);
        let told = events(&inner, &mut after);
        assert_eq!(told.len(), 1, "{told:?}");
        assert_eq!(told[0]["bytes_done"], 2 * SEGMENT_LEN as u64);
        // Nothing changed: nothing told.
        later();
        look(&inner, &mut book, b);
        assert!(events(&inner, &mut after).is_empty());

        // The rest lands, and raven-node finds that it opens.
        for index in 2..shape.chunks() {
            land(index);
        }
        let row = store::get(b, &handle).unwrap().unwrap();
        assert!(store::opens(b, &row).unwrap());
        store::set_state(b, &handle, Stored::Complete, 30).unwrap();
        let rows = look(&inner, &mut book, b);
        let att = rows[0].json()["attachment"].clone();
        assert_eq!(att["state"], "ready");
        assert_eq!(att["bytes_done"], 200_000);
        let told = events(&inner, &mut after);
        assert_eq!(told.len(), 1, "{told:?}");
        assert_eq!(told[0]["state"], "ready");
        assert_eq!(told[0]["bytes_done"], 200_000);
        let row = readable(b, &handle).unwrap();
        assert_eq!(
            &store::read_plain(b, &row, 0, usize::MAX).unwrap()[..],
            &bytes[..]
        );

        // The friend deleted it; a check failed; its row is gone.
        store::set_state(b, &handle, Stored::Gone, 40).unwrap();
        assert_eq!(
            look(&inner, &mut book, b)[0].json()["attachment"]["state"],
            "gone"
        );
        assert_eq!(
            readable(b, &handle).unwrap_err().code,
            code::ATTACHMENT_GONE
        );
        store::set_state(b, &handle, Stored::Failed, 50).unwrap();
        assert_eq!(
            look(&inner, &mut book, b)[0].json()["attachment"]["state"],
            "failed"
        );
        assert_eq!(readable(b, &handle).unwrap_err().code, code::ATTACHMENT_BAD);
        store::remove(b, &handle).unwrap();
        let rows = look(&inner, &mut book, b);
        let att = rows[0].json()["attachment"].clone();
        assert_eq!(
            (att["state"].as_str(), att["bytes_done"].as_u64()),
            (Some("failed"), Some(0))
        );
        assert_eq!(
            readable(b, &handle).unwrap_err().code,
            code::ATTACHMENT_GONE
        );
    }

    /// raven-node writes that the friend has every byte; whoever sent the
    /// message writes its receipt. Either can be first. A photo whose bytes
    /// are there first reads sending with every byte, and delivered only in
    /// the look that also sees the receipt.
    #[test]
    fn a_photo_whose_bytes_are_there_before_its_receipt_is_not_delivered_before_it() {
        let Some(_gate) = Gate::open() else { return };
        let home = profile(&FRIEND);
        let d = home.path();
        let (handle, offer, _) = photo(d, &FRIEND, 200_000, "");
        // Its message is on its way: no receipt yet.
        history_row(d, "out", &FRIEND, 6, "queued", &offer);
        let chunks = store::get(d, &handle)
            .unwrap()
            .unwrap()
            .shape()
            .unwrap()
            .chunks();
        store::update(d, &handle, 30, |row| {
            row.state = Stored::Delivered;
            row.friend_has = chunks;
        })
        .unwrap();
        let inner = Inner::new(Ok(d.to_path_buf()));
        let mut book = MessageBook::default();
        let mut after = 0;
        let row = look(&inner, &mut book, d)[0].json();
        assert_ne!(row["state"], "delivered", "{row}");
        assert_eq!(row["attachment"]["state"], "sending", "{row}");
        assert_eq!(row["attachment"]["bytes_done"], 200_000);
        assert!(events(&inner, &mut after).is_empty());
        // The receipt: the message and its photo read delivered together.
        history_row(d, "out", &FRIEND, 6, "delivered", &offer);
        let row = look(&inner, &mut book, d)[0].json();
        assert_eq!(row["state"], "delivered", "{row}");
        assert_eq!(row["attachment"]["state"], "delivered");
        assert_eq!(row["attachment"]["bytes_done"], 200_000);
        let told = events(&inner, &mut after);
        assert_eq!(told.len(), 1, "{told:?}");
        assert_eq!(told[0]["state"], "delivered");
    }

    #[test]
    fn a_photo_of_yours_reads_delivered_only_once_the_friend_has_every_byte() {
        let Some(_gate) = Gate::open() else { return };
        let home = profile(&FRIEND);
        let d = home.path();
        let (handle, offer, bytes) = photo(d, &FRIEND, 200_000, "");
        // Its message was delivered: the friend has the offer, no byte yet.
        history_row(d, "out", &FRIEND, 4, "delivered", &offer);
        let inner = Inner::new(Ok(d.to_path_buf()));
        let mut book = MessageBook::default();
        let mut after = 0;
        let later = || std::thread::sleep(TOLD_EVERY + Duration::from_millis(60));
        let row_of = |book: &mut MessageBook| look(&inner, book, d)[0].json();

        let row = row_of(&mut book);
        assert_eq!(row["direction"], "out");
        assert_eq!(row["text"], "", "no caption");
        assert_eq!(
            row["state"], "sent",
            "one tick until every byte is there: {row}"
        );
        assert_eq!(row["attachment"]["state"], "sent");
        assert_eq!(row["attachment"]["bytes_done"], 0);
        assert!(!row.to_string().contains("RVNATT/"), "{row}");
        assert!(events(&inner, &mut after).is_empty());

        // The friend's node has two chunks.
        store::update(d, &handle, 30, |row| row.friend_has = 2).unwrap();
        let row = row_of(&mut book);
        assert_eq!(row["state"], "sent");
        assert_eq!(row["attachment"]["state"], "sending");
        assert_eq!(row["attachment"]["bytes_done"], 2 * SEGMENT_LEN as u64);
        let told = events(&inner, &mut after);
        assert_eq!(told.len(), 1, "{told:?}");
        assert_eq!(
            (told[0]["kind"].as_str(), told[0]["state"].as_str()),
            (Some("attachment"), Some("sending"))
        );

        // A row whose file did not change is not opened again: the row is
        // written anew, and its file is given the time it had.
        let file = d
            .join(store::ROWS_DIR)
            .join(format!("{}.row", hex::encode(handle)));
        let before = std::fs::metadata(&file).unwrap().modified().unwrap();
        let chunks = store::get(d, &handle)
            .unwrap()
            .unwrap()
            .shape()
            .unwrap()
            .chunks();
        store::update(d, &handle, 40, |row| {
            row.state = Stored::Delivered;
            row.friend_has = chunks;
        })
        .unwrap();
        let touch = |at: SystemTime| {
            std::fs::File::options()
                .write(true)
                .open(&file)
                .and_then(|f| f.set_modified(at))
                .unwrap();
        };
        touch(before);
        later();
        let row = row_of(&mut book);
        assert_eq!(row["attachment"]["state"], "sending", "not read again");
        assert!(events(&inner, &mut after).is_empty());
        // Its file changed: every byte is with the friend. Two ticks.
        touch(before + Duration::from_secs(2));
        let row = row_of(&mut book);
        assert_eq!(row["state"], "delivered", "{row}");
        assert_eq!(row["attachment"]["state"], "delivered");
        assert_eq!(row["attachment"]["bytes_done"], 200_000);
        let told = events(&inner, &mut after);
        assert_eq!(told.len(), 1, "{told:?}");
        assert_eq!(told[0]["state"], "delivered");
        assert_eq!(told[0]["bytes_done"], 200_000);
        // A photo of yours is always readable.
        let mine = readable(d, &handle).unwrap();
        assert_eq!(
            &store::read_plain(d, &mine, 0, usize::MAX).unwrap()[..],
            &bytes[..]
        );

        // Sending was stopped, or its row is gone: failed, and the message
        // is not delivered.
        store::set_state(d, &handle, Stored::Failed, 50).unwrap();
        let row = row_of(&mut book);
        assert_eq!(
            (row["state"].as_str(), row["attachment"]["state"].as_str()),
            (Some("sent"), Some("failed"))
        );
        store::remove(d, &handle).unwrap();
        let row = row_of(&mut book);
        assert_eq!(
            (row["state"].as_str(), row["attachment"]["state"].as_str()),
            (Some("sent"), Some("failed"))
        );
        assert_eq!(row["attachment"]["bytes_done"], 0);

        // Another friend's row under the same handle is not this row's
        // attachment, and neither is a friend's own (the same chat, the
        // same way, the same offer).
        let other = profile(&FRIEND);
        let o = other.path();
        let (_, offer, _) = photo(o, &OTHER, 50_000, "");
        history_row(o, "out", &FRIEND, 5, "delivered", &offer);
        history_row(o, "in", &OTHER, 6, "received", &offer);
        let inner = Inner::new(Ok(o.to_path_buf()));
        let rows = look(&inner, &mut MessageBook::default(), o);
        assert_eq!(rows.len(), 2);
        for row in rows.iter().map(View::json) {
            assert_eq!(row["attachment"]["state"], "failed", "{row}");
        }
    }

    #[test]
    fn a_photo_whose_message_ended_is_no_longer_on_its_way_unless_another_carries_it() {
        let Some(_gate) = Gate::open() else { return };
        let home = profile(&FRIEND);
        let d = home.path();
        let (handle, offer, _) = photo(d, &FRIEND, 50_000, "");
        // Its message ended without arriving.
        history_row(d, "out", &FRIEND, 4, "failed", &offer);
        let inner = Inner::new(Ok(d.to_path_buf()));
        let mut book = MessageBook::default();
        let look_at = |book: &mut MessageBook, now: u64| {
            let (entries, atts) = shown_history(ChatHistory::load(d).unwrap());
            let mut rows = views(book, &entries, &OutboxSnap::default(), &[], now);
            inner.attach(&mut book.att, &mut rows, &atts, now);
            rows
        };
        let state = || store::get(d, &handle).unwrap().unwrap().state;
        // A moment after its row was written it is left alone (Send again
        // writes the row before it makes the new message).
        let rows = look_at(&mut book, 20);
        assert_eq!(rows[0].json()["attachment"]["state"], "failed");
        assert_eq!(state(), Stored::Staged);
        // Later its row says that it is no longer on its way: raven-node
        // stops asking the friend about it.
        look_at(&mut book, 10 + ENDED_GRACE_MS);
        assert_eq!(state(), Stored::Failed);
        let rows = look_at(&mut book, 11 + ENDED_GRACE_MS);
        assert_eq!(rows[0].json()["attachment"]["state"], "failed");
        // Send again: the row is taken up, and a new message carries the
        // same photo. While that one is on its way the row stays.
        store::update(d, &handle, 50_000, |row| row.state = Stored::Staged).unwrap();
        history_row(d, "out", &FRIEND, 5, "queued", &offer);
        look_at(&mut book, 50_000 + ENDED_GRACE_MS);
        assert_eq!(state(), Stored::Staged, "another message carries it");
    }

    #[test]
    fn a_photos_send_binds_to_the_row_that_holds_its_attachment() {
        let Some(_gate) = Gate::open() else { return };
        let home = profile(&FRIEND);
        let d = home.path();
        let (handle, offer, _) = photo(d, &FRIEND, 50_000, "hi");
        let stored = store::get(d, &handle).unwrap().unwrap().reference.clone();
        let meta = Arc::new(Meta::parse(&stored).unwrap());
        assert_eq!(
            (meta.handle, meta.caption.as_str(), meta.words.as_str()),
            (handle, "hi", "Photo")
        );
        assert_eq!(meta.bytes, 50_000);
        assert!(same_body(&stored, &offer) && same_body(&stored, &stored));
        assert!(!same_body(&stored, "hi") && !same_body("hi", "hi"));
        let inner = Inner::new(Ok(d.to_path_buf()));
        let no_rows = RowAtts::default();

        // Before its row is there the send shows by itself: its caption,
        // its attachment, sending.
        let mut book = MessageBook::default();
        book.pendings
            .push(pending(&stored, Some(Arc::clone(&meta))));
        let mut rows = views(&mut book, &[], &OutboxSnap::default(), &[], 20);
        inner.attach(&mut book.att, &mut rows, &no_rows, 20);
        assert_eq!(rows.len(), 1);
        let row = rows[0].json();
        assert_eq!(
            (row["id"].as_str(), row["text"].as_str()),
            (Some("pending-1"), Some("hi"))
        );
        assert_eq!(row["state"], "sending");
        assert_eq!(row["attachment"]["state"], "sending");
        assert_eq!(row["attachment"]["id"], hex::encode(handle));
        assert!(!row.to_string().contains("RVNATT/"), "{row}");

        // The send wrote its row (the history keeps the stored form), and a
        // text row with the caption's words is there too.
        history_row(d, "out", &FRIEND, 7, "queued", "hi");
        history_row(d, "out", &FRIEND, 6, "queued", &offer);
        let (entries, atts) = shown_history(ChatHistory::load(d).unwrap());
        let photo_row = hex::encode([6u8; 16]);
        // Whatever form the send holds: the stored form, or the offer.
        for body in [stored.as_str(), offer.as_str()] {
            let mut book = MessageBook::default();
            book.pendings.push(pending(body, Some(Arc::clone(&meta))));
            let mut rows = views(&mut book, &entries, &OutboxSnap::default(), &[], 20);
            assert_eq!(
                book.pendings[0].bound_mid.as_deref(),
                Some(photo_row.as_str())
            );
            assert!(rows.iter().all(|v| !v.text.contains("RVNATT/")));
            inner.attach(&mut book.att, &mut rows, &atts, 20);
            let ids: Vec<&str> = rows.iter().map(|v| v.id.as_str()).collect();
            assert_eq!(ids.len(), 2, "one bubble for the photo: {ids:?}");
            let row = rows.iter().find(|v| v.id == "pending-1").unwrap().json();
            assert_eq!(row["text"], "hi");
            assert_eq!(row["attachment"]["id"], hex::encode(handle));
            // The attachment's row learned its message's id.
            let row = store::get(d, &handle).unwrap().unwrap();
            assert_eq!(row.message_id_bytes(), Some([6u8; 16]));
        }
        // A text send with the same words takes the text row, never the
        // photo's.
        let mut book = MessageBook::default();
        book.pendings.push(pending("hi", None));
        views(&mut book, &entries, &OutboxSnap::default(), &[], 20);
        assert_eq!(
            book.pendings[0].bound_mid.as_deref(),
            Some(hex::encode([7u8; 16]).as_str())
        );
        assert_eq!(pending_text(&pending("hi", None)), "hi");
        assert_eq!(pending_text(&pending(&stored, Some(meta))), "hi");
        assert_eq!(
            pending_text(&pending(&stored, None)),
            "",
            "never the stored form"
        );
        assert_eq!(row_text(&offer), "");
        assert_eq!(row_text("RVNATT/"), "");
        assert_eq!(row_text("rvnatt/ in lower case"), "rvnatt/ in lower case");
    }

    #[test]
    fn a_deleted_message_takes_its_photo_and_a_cleared_chat_takes_all_of_them() {
        let Some(_gate) = Gate::open() else { return };
        let home = profile(&FRIEND);
        let d = home.path();
        let (handle, _, _) = photo(d, &FRIEND, 50_000, "");
        let stored = store::get(d, &handle).unwrap().unwrap().reference.clone();
        let meta = Arc::new(Meta::parse(&stored).unwrap());
        let inner = Inner::new(Ok(d.to_path_buf()));
        let row = |id: &str, state: State, incoming: bool| {
            let mut v = first_row(&pending(&stored, Some(Arc::clone(&meta))), &meta);
            v.id = id.into();
            v.state = state;
            v.incoming = incoming;
            v
        };
        let here = |handle: &Handle| {
            store::get(d, handle).unwrap().is_some() && store::blob_dir(d, handle).exists()
        };
        let ended = row("old", State::Failed, false);
        // Send again made a new message for the same photo, and that one
        // still goes: the photo stays for it.
        let rows = [ended.clone(), row("new", State::Waiting, false)];
        inner.forget_attachment(&ended, &rows).unwrap();
        assert!(here(&handle));
        // Every message of yours that carried it has ended (a friend's row
        // that names the same handle counts for nothing): it goes, its row
        // with the key and its sealed bytes.
        let rows = [
            ended.clone(),
            row("newer", State::TimeRanOut, false),
            row("theirs", State::Delivered, true),
        ];
        inner.forget_attachment(&ended, &rows).unwrap();
        assert!(store::get(d, &handle).unwrap().is_none());
        assert!(!store::blob_dir(d, &handle).exists());
        // Gone already, or a row without a photo: nothing to do.
        inner.forget_attachment(&ended, &rows).unwrap();
        let mut text = ended.clone();
        text.attachment = None;
        inner.forget_attachment(&text, &[]).unwrap();

        // Clearing a chat forgets every photo of that friend, and only
        // that friend's.
        let (mine, _, _) = photo(d, &FRIEND, 50_000, "");
        let (others, _, _) = photo(d, &OTHER, 50_000, "");
        assert!(any_on_disk(d));
        forget_chat(d, &hex::encode(FRIEND)).unwrap();
        assert!(store::get(d, &mine).unwrap().is_none());
        assert!(!store::blob_dir(d, &mine).exists());
        assert!(here(&others));
        forget_chat(d, &hex::encode(OTHER)).unwrap();
        assert!(!any_on_disk(d));
        assert!(forget_chat(d, "not a key").is_err());
    }

    #[test]
    fn an_offer_is_made_again_from_its_row_only_for_a_send_that_may_go() {
        let Some(_gate) = Gate::open() else { return };
        let home = profile(&FRIEND);
        let d = home.path();
        let (handle, offer, _) = photo(d, &FRIEND, 50_000, "hi");
        let peer = hex::encode(FRIEND);
        assert_eq!(offer_for(d, &handle, &peer).unwrap().as_str(), offer);
        assert_eq!(
            offer_for(d, &handle, &peer.to_ascii_uppercase())
                .unwrap()
                .as_str(),
            offer
        );
        let refused =
            |dir: &Path, handle: &Handle, peer: &str| offer_for(dir, handle, peer).unwrap_err();
        // Somebody else's key: not their photo.
        assert!(refused(d, &handle, &hex::encode(OTHER)).starts_with("ATTACHMENT_GONE"));
        // A contact that is not verified.
        let stranger = profile_with(&FRIEND, false);
        let (theirs, _, _) = photo(stranger.path(), &FRIEND, 50_000, "");
        assert!(refused(stranger.path(), &theirs, &peer).starts_with("NOT SENT"));
        // A friend whose Raven does not take photos (any more).
        let old = profile(&FRIEND);
        let (theirs, _, _) = photo(old.path(), &FRIEND, 50_000, "");
        peers::note(old.path(), &FRIEND, false, 2).unwrap();
        assert!(refused(old.path(), &theirs, &peer).starts_with("FRIEND_NEEDS_NEWER_RAVEN"));
        // Sending was stopped; then its row is gone.
        store::set_state(d, &handle, Stored::Failed, 20).unwrap();
        assert!(refused(d, &handle, &peer).contains("stopped"));
        store::remove(d, &handle).unwrap();
        assert!(refused(d, &handle, &peer).starts_with("ATTACHMENT_GONE"));
        // The gate shut: nothing is made.
        let (handle, _, _) = photo(d, &FRIEND, 50_000, "");
        drop(_gate);
        let _gate = Gate::shut();
        assert_eq!(
            refused(d, &handle, &peer),
            attachment_gate::ATTACHMENTS_HOLD
        );
    }

    #[test]
    fn a_photo_is_saved_only_to_a_new_file_outside_the_profile() {
        let Some(_gate) = Gate::open() else { return };
        let home = profile(&FRIEND);
        let d = home.path();
        let (handle, _, bytes) = photo(d, &FRIEND, 300_000, "");
        let row = readable(d, &handle).unwrap();
        let out = tempfile::tempdir().unwrap();
        let to = out.path().join("photo.jpg");
        export_place(d, &to).unwrap();
        export_to(d, &row, &to).unwrap();
        assert_eq!(std::fs::read(&to).unwrap(), bytes);
        // Never over a file that is there.
        std::fs::write(&to, b"kept").unwrap();
        let again = export_to(d, &row, &to).unwrap_err();
        assert_eq!(again.code, code::BAD_REQUEST);
        assert!(plain(&again.message), "{}", again.message);
        assert_eq!(std::fs::read(&to).unwrap(), b"kept");
        // Never inside the profile folder, by any way to name it.
        std::fs::create_dir_all(d.join("sub")).unwrap();
        for inside in [
            d.join("photo.jpg"),
            d.join("sub").join("photo.jpg"),
            d.join("sub").join("..").join("photo.jpg"),
            out.path()
                .join("..")
                .join(d.file_name().unwrap())
                .join("photo.jpg"),
        ] {
            let refused = export_place(d, &inside).unwrap_err();
            assert_eq!(refused.code, code::BAD_REQUEST, "{inside:?}");
            assert!(plain(&refused.message), "{}", refused.message);
            assert!(!inside.exists(), "{inside:?}");
        }
        // Only the full path of a file, in a folder that is there.
        for bad in [
            PathBuf::from("photo.jpg"),
            out.path().join("missing").join("photo.jpg"),
            PathBuf::from("/"),
        ] {
            assert_eq!(
                export_place(d, &bad).unwrap_err().code,
                code::BAD_REQUEST,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn what_is_handed_over_is_checked_before_anything_is_sealed() {
        // A caption follows the chat text rules.
        assert!(check_caption("").is_ok());
        assert!(check_caption("on the bridge\nat night").is_ok());
        let long = "x".repeat(offer::MAX_CAPTION_BYTES + 1);
        assert_eq!(
            check_caption(&long).unwrap_err().code,
            code::MESSAGE_TOO_LONG
        );
        for bad in [
            "bell\u{7}",
            "RVNATT/1 offer\n{}",
            "RVNGRP/1 msg",
            "RVNAPP/1 x",
        ] {
            let refused = check_caption(bad).unwrap_err();
            assert_eq!(refused.code, code::BAD_REQUEST, "{bad:?}");
            assert!(plain(&refused.message), "{}", refused.message);
        }
        // A staged file: at most what Raven sends, and it goes when the
        // send is over, whatever became of it.
        let dir = tempfile::tempdir().unwrap();
        let path = store::stage(dir.path(), "photo.jpg").unwrap();
        std::fs::write(&path, jpeg(1_000)).unwrap();
        assert_eq!(&read_staged(&path).unwrap()[..], &jpeg(1_000)[..]);
        std::fs::write(&path, vec![0u8; LIVE_MAX_LEN as usize + 1]).unwrap();
        assert_eq!(
            read_staged(&path).unwrap_err().code,
            code::ATTACHMENT_TOO_BIG
        );
        drop(Staged(path.clone()));
        assert!(!path.exists());
        assert_eq!(read_staged(&path).unwrap_err().code, code::ATTACHMENT_BAD);
        // An id is a handle in hex.
        let args = |id: &str| json!({"id": id}).as_object().unwrap().clone();
        assert_eq!(id_arg(&Args(&args(&"AB".repeat(16)))).unwrap(), [0xab; 16]);
        for bad in ["", "ab", &"zz".repeat(16), &"ab".repeat(17)] {
            assert_eq!(
                id_arg(&Args(&args(bad))).unwrap_err().code,
                code::BAD_REQUEST,
                "{bad}"
            );
        }
        // The store's and the sealing's refusals, as the API says them.
        assert_eq!(store_error(StoreError::Full).code, code::STORAGE_FULL);
        let no_space = StoreError::Io("No space left on device (os error 28)".into());
        assert_eq!(store_error(no_space).code, code::STORAGE_FULL);
        assert_eq!(
            store_error(StoreError::Io("other".into())).code,
            code::INTERNAL
        );
        assert_eq!(
            store_error(StoreError::NotFound).code,
            code::ATTACHMENT_GONE
        );
        assert_eq!(store_error(StoreError::Corrupt).code, code::ATTACHMENT_BAD);
        assert_eq!(flow_error(FlowError::TooBig).code, code::ATTACHMENT_TOO_BIG);
        assert_eq!(flow_error(FlowError::NotJpeg).code, code::ATTACHMENT_BAD);
        assert_eq!(flow_error(FlowError::Hold).code, code::NOT_AVAILABLE_YET);
        assert_eq!(
            flow_error(FlowError::Store(StoreError::Full)).code,
            code::STORAGE_FULL
        );
        for e in [
            not_yet(),
            flow_error(FlowError::NotJpeg),
            flow_error(FlowError::TooBig),
            store_error(StoreError::Full),
            gone("x"),
            bad("x"),
        ] {
            assert!(
                plain(&e.message) && e.message.ends_with('.'),
                "{}",
                e.message
            );
        }
    }
}
