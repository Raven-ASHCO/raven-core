//! Profile pictures, version 1: one picture of mine for the friends I
//! verified, and one from each friend I verified
//! (`docs/design/2026-11-profile-pictures.md`; the owner's wish of
//! 2026-11-15: simple, a person picks one photo, verified friends see it).
//!
//! A picture is a small square JPEG ([`super::jpeg`]). It travels as an
//! attachment of the `profile` kind: an offer that is never a chat message
//! ([`super::shown`]) and one sealed chunk, to each verified friend under a
//! key of its own, so that no two copies can be told to be the same
//! picture. The chunk rides the exchange every attachment rides
//! ([`super::exchange`]), and lies in the attachment store under its handle.
//! This module keeps what is around that, in three small sealed files:
//!
//! ```text
//! pictures_mine.json    my picture, and the number of my newest choice
//! pictures_sent.json    for each friend: which choice went, and how far
//! pictures_theirs.json  for each friend: the newest offer they sent me
//! ```
//!
//! - **Only verified friends.** An offer of mine is made only for a
//!   contact that is verified and not blocked and whose node takes
//!   attachments. A friend's offer is taken into the store only while I
//!   have them verified; from anyone else it stays where a build without
//!   pictures keeps it ([`crate::lan_dispatch::persist_profile_offer`]) and
//!   is taken up when the words match ([`adopt_kept`]).
//! - **From state, not from events.** [`pass`] looks at the contact book
//!   and the three files and finds who is due an offer: a friend newly
//!   verified, a friend whose node learned attachments, a choice that
//!   changed, a friend who says it lost my picture. It also forgets
//!   everything about a friend who is no longer one. A friend verified
//!   after the store's first look gets an offer even when I have no
//!   picture (the empty form): it tells them what I hold of theirs.
//! - **No history.** A newer choice replaces the picture everywhere: mine
//!   on this device at once, and the copy at each friend when its offer
//!   arrives.
//!
//! Nothing here sends: [`pass`] hands back the offers, and whoever called
//! it sends each as a message (the engine, or `raven lab picture`).
//! Everything is behind [`attachment_gate::pictures_live`].

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use super::blob::{self, Key, HANDLE_LEN};
use super::flow;
use super::jpeg::{self, JpegError};
use super::link::Handle;
use super::offer::{self, BlobRef, Content, Frame, Offer, MAX_SEQ};
use super::peers;
use super::store::{self, Chat, Row, State, StoreError};
use crate::at_rest::{self, Kind};
use crate::attachment_gate;

/// My picture and the number of my newest choice.
pub const MINE_FILE: &str = "pictures_mine.json";
/// For each friend, which choice of mine went to them.
pub const SENT_FILE: &str = "pictures_sent.json";
/// For each friend, the newest offer they sent me.
pub const THEIRS_FILE: &str = "pictures_theirs.json";
/// Every writer of the three files takes it (`at_rest::FILES`). A lock of
/// its own: a writer holds it while it asks the attachment store.
pub const PICTURES_LOCK: &str = ".pictures.lock.sqlite";

const VERSION: u8 = 1;
const DAY_MS: u64 = 86_400_000;
/// How often a picture can be set in a day. Removing it is never refused
/// and uses up none of them: taking a picture away must always work.
pub const CHANGES_A_DAY: u8 = 3;
/// Offers made for one friend in a day, every reason counted: three
/// pictures, each taken away again, and one more for a friend verified anew
/// or one that lost mine. Below what a receiver takes ([`TAKEN_A_DAY`]).
pub const OFFERS_A_DAY: u8 = 7;
/// Offers taken from one friend in a day; more are dropped.
pub const TAKEN_A_DAY: u8 = 8;
/// Bad pictures from one friend in a day before none of theirs is opened
/// until the next.
pub const BAD_A_DAY: u8 = 3;
/// An offer that was made and never became a message is made again after
/// this long.
const UNSENT_AGAIN_MS: u64 = 10 * 60 * 1_000;

/// Why a picture was refused or cannot be read.
#[derive(Debug, Error)]
pub enum PictureError {
    /// The gate is shut.
    #[error("{}", attachment_gate::PROFILE_PICTURES_HOLD)]
    Hold,
    /// More bytes or pixels than a picture may have.
    #[error("PICTURE_TOO_BIG: a picture is at most 60000 bytes and 512 pixels a side")]
    TooBig,
    /// Not a picture this build takes.
    #[error("PICTURE_BAD: {0}")]
    Bad(JpegError),
    /// Set too often today.
    #[error("CHANGE_LIMIT: a picture can be set {CHANGES_A_DAY} times a day")]
    ChangeLimit,
    /// Not a friend whose picture is shown: not verified, or blocked.
    #[error("NOT_VERIFIED: only a verified friend's picture is shown")]
    NotVerified,
    /// There is no picture.
    #[error("NO_PICTURE: there is no picture")]
    NoPicture,
    /// The store refused.
    #[error("{0}")]
    Store(#[from] StoreError),
}

impl From<JpegError> for PictureError {
    fn from(e: JpegError) -> PictureError {
        match e {
            JpegError::TooLong | JpegError::Side => PictureError::TooBig,
            JpegError::Refused(_) => PictureError::Bad(e),
        }
    }
}

/// A file of this module: it says which version wrote it.
trait Versioned {
    fn v(&self) -> u8;
    fn set_v(&mut self, v: u8);
}

macro_rules! versioned {
    ($($file:ty),*) => {$(
        impl Versioned for $file {
            fn v(&self) -> u8 {
                self.v
            }
            fn set_v(&mut self, v: u8) {
                self.v = v;
            }
        }
    )*};
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Mine {
    v: u8,
    /// The number of my newest choice, a picture or none. 0: none was ever
    /// made, and nothing is sent to anyone.
    #[serde(default)]
    choice: u64,
    /// The picture of that choice as it travels, in base64. `None`: no
    /// picture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jpeg: Option<String>,
    /// Its preview, in base64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    preview: Option<String>,
    #[serde(default)]
    side: u16,
    #[serde(default)]
    changed_ms: u64,
    /// The `seq` of the last offer made, for any friend: one count for all.
    #[serde(default)]
    seq: u64,
    /// The day of the changes counted in `changes`.
    #[serde(default)]
    day: u64,
    #[serde(default)]
    changes: u8,
    /// The first look at the contact book was taken ([`pass`]): the
    /// friends verified by then were noted, and none of them is told
    /// anything before the first choice.
    #[serde(default)]
    looked: bool,
}

/// How far an offer of mine is with a friend.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Reached {
    /// Made; its message has not arrived yet.
    #[default]
    Waiting,
    /// The friend's node has the offer, not yet the picture's bytes.
    Taken,
    /// The friend's node has all of it (or was told there is none).
    Has,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Sent {
    /// Which choice of mine the offer carried.
    choice: u64,
    /// The offer's `seq`.
    seq: u64,
    /// The handle of its row in the attachment store, in hex. `None` for No
    /// picture, and once the friend has the bytes (the row and its key go).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    handle: Option<String>,
    /// The message that carries the offer, in hex, once there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message_id: Option<String>,
    #[serde(default)]
    reached: Reached,
    made_ms: u64,
    /// The day of the offers counted in `offers`.
    #[serde(default)]
    day: u64,
    #[serde(default)]
    offers: u8,
    /// The day an offer was last made because the friend had lost mine.
    #[serde(default)]
    repair_day: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SentBook {
    v: u8,
    /// By the friend's key in hex.
    #[serde(default)]
    friends: BTreeMap<String, Sent>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Theirs {
    /// The `seq` of the newest offer taken from this friend.
    seq: u64,
    /// SHA-256 of that offer as it came, in hex: a copy that comes again
    /// is known by it.
    sha256: String,
    /// The handle of the row that holds its chunk, in hex. `None`: the
    /// friend has no picture, or theirs was bad and went.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    handle: Option<String>,
    #[serde(default)]
    side: u16,
    /// The preview the offer carried, in base64 (the stored form of a
    /// profile offer keeps none).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    preview: Option<String>,
    /// The newest `seq` of mine the friend said it holds; 0: none.
    #[serde(default)]
    held: u64,
    came_ms: u64,
    /// The day of the offers and bad pictures counted below.
    #[serde(default)]
    day: u64,
    #[serde(default)]
    taken: u8,
    #[serde(default)]
    bad: u8,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TheirsBook {
    v: u8,
    /// By the friend's key in hex.
    #[serde(default)]
    friends: BTreeMap<String, Theirs>,
}

versioned!(Mine, SentBook, TheirsBook);

fn path(data_dir: &Path, file: &str) -> PathBuf {
    data_dir.join(file)
}

fn io(e: at_rest::AtRestError) -> StoreError {
    StoreError::Io(e.to_string())
}

/// A file as it is now, for a look: one that is not there, does not read
/// or is of another version reads as empty.
fn load<T: DeserializeOwned + Default + Versioned>(data_dir: &Path, file: &str) -> T {
    current(
        at_rest::load_json::<T>(data_dir, &path(data_dir, file), Kind::Attachments)
            .ok()
            .flatten(),
    )
}

/// What a file holds when it is of this version; else an empty one.
fn current<T: Default + Versioned>(read: Option<T>) -> T {
    match read {
        Some(value) if value.v() == VERSION => value,
        _ => T::default(),
    }
}

/// Changes a file under the writers' lock. A file that cannot be read is
/// an error and stays as it is: it is never written over with an empty one.
/// The three files share one lock, so `change` never calls `edit` itself;
/// it may ask the attachment store, whose lock is another.
fn edit<T, R>(
    data_dir: &Path,
    file: &str,
    change: impl FnOnce(&mut T) -> R,
) -> Result<R, StoreError>
where
    T: DeserializeOwned + Serialize + Default + Versioned + Clone + PartialEq,
{
    let lock =
        at_rest::lock_file(data_dir, &path(data_dir, file), Kind::Attachments).map_err(io)?;
    let mut value: T = current(lock.load_json::<T>().map_err(io)?);
    value.set_v(VERSION);
    let before = value.clone();
    let out = change(&mut value);
    if value != before || !path(data_dir, file).exists() {
        lock.store_json(&value).map_err(io)?;
    }
    Ok(out)
}

fn day_of(now_ms: u64) -> u64 {
    now_ms / DAY_MS
}

fn key_of(peer: &[u8; 32]) -> String {
    hex::encode(peer)
}

fn handle_of(hex_handle: &str) -> Option<Handle> {
    let mut out = [0u8; HANDLE_LEN];
    (hex_handle.len() == 2 * HANDLE_LEN)
        .then(|| hex::decode_to_slice(hex_handle, &mut out).ok())
        .flatten()
        .map(|()| out)
}

fn mid_of(hex_id: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    (hex_id.len() == 32)
        .then(|| hex::decode_to_slice(hex_id, &mut out).ok())
        .flatten()
        .map(|()| out)
}

fn peer_of(hex_key: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    (hex_key.len() == 64)
        .then(|| hex::decode_to_slice(hex_key, &mut out).ok())
        .flatten()
        .map(|()| out)
}

/// The friends pictures are exchanged with: verified and not blocked. A
/// contact book or a block list that cannot be read is nobody: no picture
/// is shown on it.
fn friends(data_dir: &Path) -> Vec<[u8; 32]> {
    friends_now(data_dir).unwrap_or_default()
}

/// The same friends, or `None` while the contact book or the block list
/// cannot be read. Whoever forgets or offers asks this one: on a book that
/// does not read just now nothing is shown ([`friends`]), and nothing is
/// forgotten or sent either, so one bad read never costs every friend's
/// picture.
fn friends_now(data_dir: &Path) -> Option<Vec<[u8; 32]>> {
    crate::outbox::pinned_unblocked_contacts(data_dir).ok()
}

/// Forgets every friend whose key is not in `current`: what they sent me,
/// what I sent them, and the rows of both in the attachment store. A book
/// is written only when it holds somebody to forget, and never made; the
/// rows go once the books are written. How many were forgotten.
fn forget_all_but(data_dir: &Path, current: &HashSet<String>) -> Result<usize, PictureError> {
    let mut gone: HashSet<String> = HashSet::new();
    let mut rows: Vec<String> = Vec::new();
    let theirs_names_one = path(data_dir, THEIRS_FILE).exists()
        && load::<TheirsBook>(data_dir, THEIRS_FILE)
            .friends
            .keys()
            .any(|key| !current.contains(key));
    if theirs_names_one {
        edit(data_dir, THEIRS_FILE, |book: &mut TheirsBook| {
            book.friends.retain(|key, theirs| {
                let stays = current.contains(key);
                if !stays {
                    gone.insert(key.clone());
                    rows.extend(theirs.handle.take());
                }
                stays
            });
        })?;
    }
    let sent_names_one = path(data_dir, SENT_FILE).exists()
        && load::<SentBook>(data_dir, SENT_FILE)
            .friends
            .keys()
            .any(|key| !current.contains(key));
    if sent_names_one {
        edit(data_dir, SENT_FILE, |book: &mut SentBook| {
            book.friends.retain(|key, sent| {
                let stays = current.contains(key);
                if !stays {
                    gone.insert(key.clone());
                    rows.extend(sent.handle.take());
                }
                stays
            });
        })?;
    }
    for handle in &rows {
        remove_row(data_dir, Some(handle));
    }
    Ok(gone.len())
}

/// A contact who is a verified friend no longer (not verified any more,
/// blocked, removed) keeps no picture on this device, and none of mine is
/// kept for them: their entries and the rows of both go now. A picture of
/// theirs is hidden from the moment they are no friend
/// ([`Views::theirs`]); this takes its bytes and its key off the disk.
///
/// raven-node calls it every few seconds, so it holds whichever program
/// changed the contact, and with no app open. It costs a profile without
/// picture files nothing, writes nothing while every entry is a friend's,
/// and does nothing while the contact book cannot be read. How many
/// contacts were forgotten.
pub fn forget_strangers(data_dir: &Path) -> Result<usize, PictureError> {
    if !attachment_gate::pictures_live() {
        return Ok(0);
    }
    if !path(data_dir, THEIRS_FILE).exists() && !path(data_dir, SENT_FILE).exists() {
        return Ok(0);
    }
    let Some(friends) = friends_now(data_dir) else {
        return Ok(0);
    };
    let current: HashSet<String> = friends.iter().map(key_of).collect();
    forget_all_but(data_dir, &current)
}

// ── Mine ────────────────────────────────────────────────────────────────

/// What an app shows about my picture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MineView {
    /// Whether I have a picture.
    pub set: bool,
    /// The number of my newest choice; it changes with every change.
    pub choice: u64,
    /// When it was last changed.
    pub changed_ms: u64,
    /// How many more times a picture can be set today.
    pub changes_left: u8,
    /// My verified friends who are not blocked.
    pub friends: usize,
    /// Those whose Raven has my newest choice. None before a first choice.
    pub have_it: usize,
    /// Those it has not reached yet. None before a first choice.
    pub waiting: usize,
    /// Those whose Raven is too old for pictures: counted from the start,
    /// also before a first choice.
    pub need_newer: usize,
}

/// How far my picture is with one friend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Their Raven has my newest choice.
    Has,
    /// It has not reached them yet.
    Waiting,
    /// Their Raven is too old for pictures.
    NeedsNewer,
}

fn changes_left(mine: &Mine, now_ms: u64) -> u8 {
    if mine.day == day_of(now_ms) {
        CHANGES_A_DAY.saturating_sub(mine.changes)
    } else {
        CHANGES_A_DAY
    }
}

fn reach_of(data_dir: &Path, mine: &Mine, sent: &SentBook, speaks: bool, peer: &[u8; 32]) -> Reach {
    if !speaks {
        return Reach::NeedsNewer;
    }
    let key = key_of(peer);
    let Some(sent) = sent.friends.get(&key).filter(|s| s.choice == mine.choice) else {
        return Reach::Waiting;
    };
    if sent.reached == Reached::Has {
        return Reach::Has;
    }
    let Some(handle) = sent.handle.as_deref().and_then(handle_of) else {
        return Reach::Waiting;
    };
    match store::get(data_dir, &handle) {
        // The friend's node has the chunk of this offer, though no [`pass`]
        // has noted it yet: raven-node wrote so in the offer's row.
        Ok(Some(row)) if row.outgoing && row.state == State::Delivered => Reach::Has,
        // The row is gone: a [`pass`] noted what became of the offer after
        // this book was read (it writes the book first, then removes the
        // row). What the book says now is the answer, so that a friend who
        // has my picture never reads as waiting for a moment.
        Ok(None) => match load::<SentBook>(data_dir, SENT_FILE).friends.get(&key) {
            Some(now) if now.choice == mine.choice && now.reached == Reached::Has => Reach::Has,
            _ => Reach::Waiting,
        },
        _ => Reach::Waiting,
    }
}

/// An entry of the friends' pictures names a row that is not in the
/// attachment store.
struct RowGone;

/// The picture files, the friends and whose node takes attachments, as
/// they are at one moment: read once, and asked for every friend of a list.
/// With the gate shut nothing is read and every answer is none.
pub struct Views {
    data_dir: PathBuf,
    now_ms: u64,
    live: bool,
    friends: Vec<[u8; 32]>,
    speakers: HashSet<String>,
    mine: Mine,
    sent: SentBook,
    theirs: TheirsBook,
}

impl Views {
    /// Reads everything once.
    pub fn load(data_dir: &Path, now_ms: u64) -> Views {
        let live = attachment_gate::pictures_live();
        let read = |on: bool| on.then_some(());
        Views {
            data_dir: data_dir.to_path_buf(),
            now_ms,
            live,
            friends: read(live).map(|()| friends(data_dir)).unwrap_or_default(),
            speakers: read(live)
                .map(|()| peers::speakers(data_dir))
                .unwrap_or_default(),
            mine: read(live)
                .map(|()| load(data_dir, MINE_FILE))
                .unwrap_or_default(),
            sent: read(live)
                .map(|()| load(data_dir, SENT_FILE))
                .unwrap_or_default(),
            theirs: read(live)
                .map(|()| load(data_dir, THEIRS_FILE))
                .unwrap_or_default(),
        }
    }

    fn is_friend(&self, peer: &[u8; 32]) -> bool {
        self.live && self.friends.contains(peer)
    }

    /// My picture and how far it is. `None`: the gate is shut.
    pub fn mine(&self) -> Option<MineView> {
        if !self.live {
            return None;
        }
        let mut view = MineView {
            set: self.mine.jpeg.is_some(),
            choice: self.mine.choice,
            changed_ms: self.mine.changed_ms,
            changes_left: changes_left(&self.mine, self.now_ms),
            friends: self.friends.len(),
            ..MineView::default()
        };
        for peer in &self.friends {
            if self.mine.choice == 0 {
                // Before a first choice nothing is on its way to anybody. Who
                // could not take a picture is known all the same, so an app
                // can say how many friends will see the one being chosen.
                if !self.speakers.contains(&key_of(peer)) {
                    view.need_newer += 1;
                }
                continue;
            }
            match self.reach_of(peer) {
                Reach::Has => view.have_it += 1,
                Reach::Waiting => view.waiting += 1,
                Reach::NeedsNewer => view.need_newer += 1,
            }
        }
        Some(view)
    }

    fn reach_of(&self, peer: &[u8; 32]) -> Reach {
        reach_of(
            &self.data_dir,
            &self.mine,
            &self.sent,
            self.speakers.contains(&key_of(peer)),
            peer,
        )
    }

    /// How far my picture is with the friend `peer`. `None`: not a verified
    /// friend, or I never chose a picture.
    pub fn reach(&self, peer: &[u8; 32]) -> Option<Reach> {
        (self.is_friend(peer) && self.mine.choice != 0).then(|| self.reach_of(peer))
    }

    /// The picture the verified friend `peer` sent, if there is one to
    /// show. Whether it shows is worked out here each time, never stored:
    /// no path leaves a picture showing for a contact that is not verified.
    pub fn theirs(&self, peer: &[u8; 32]) -> Option<TheirView> {
        if !self.is_friend(peer) {
            return None;
        }
        let key = key_of(peer);
        match self.their_view(self.theirs.friends.get(&key)?) {
            Ok(view) => view,
            // The picture's row is gone: a newer offer took its place (or
            // took the picture away) after this book was read. What the
            // book says now is the answer, so that the picture held until
            // then never reads as announced only for a moment.
            Err(RowGone) => {
                let now: TheirsBook = load(&self.data_dir, THEIRS_FILE);
                let theirs = now.friends.get(&key)?;
                self.their_view(theirs).unwrap_or(Some(TheirView {
                    seq: theirs.seq,
                    ready: false,
                }))
            }
        }
    }

    /// What one entry of the friends' pictures shows: nothing (no picture,
    /// or too many bad ones today), or the picture and whether its bytes
    /// are here. [`RowGone`]: the entry names a row that is not in the
    /// attachment store.
    fn their_view(&self, theirs: &Theirs) -> Result<Option<TheirView>, RowGone> {
        let Some(handle) = theirs.handle.as_deref().and_then(handle_of) else {
            return Ok(None);
        };
        if not_today(theirs, self.now_ms) {
            return Ok(None);
        }
        match store::get(&self.data_dir, &handle) {
            Ok(Some(row)) => Ok(Some(TheirView {
                seq: theirs.seq,
                ready: !row.outgoing && row.state == State::Complete,
            })),
            Ok(None) => Err(RowGone),
            Err(_) => Ok(Some(TheirView {
                seq: theirs.seq,
                ready: false,
            })),
        }
    }
}

/// My picture and how far it is, for an app.
pub fn mine(data_dir: &Path, now_ms: u64) -> Result<MineView, PictureError> {
    Views::load(data_dir, now_ms)
        .mine()
        .ok_or(PictureError::Hold)
}

/// How far my picture is with the friend `peer`. `None`: not a verified
/// friend, or I never chose a picture.
pub fn reach(data_dir: &Path, peer: &[u8; 32]) -> Option<Reach> {
    Views::load(data_dir, 0).reach(peer)
}

fn next_choice(mine: &mut Mine, now_ms: u64) -> Result<(), PictureError> {
    let today = day_of(now_ms);
    if mine.day != today {
        mine.day = today;
        mine.changes = 0;
    }
    if mine.changes >= CHANGES_A_DAY {
        return Err(PictureError::ChangeLimit);
    }
    mine.changes += 1;
    mine.choice = now_ms.max(mine.choice.saturating_add(1)).min(MAX_SEQ);
    mine.changed_ms = now_ms;
    Ok(())
}

/// Sets my picture. `jpeg` and `preview` are what an app made; both are
/// checked and written again as a picture travels ([`jpeg::clean`]), so
/// what is kept here is exactly what every friend's Raven takes. Nothing is
/// sent by this: the next [`pass`] finds every friend due.
pub fn set_mine(
    data_dir: &Path,
    picture: &[u8],
    preview: &[u8],
    now_ms: u64,
) -> Result<(), PictureError> {
    if !attachment_gate::pictures_live() {
        return Err(PictureError::Hold);
    }
    let clean = jpeg::clean(picture, &jpeg::PICTURE)?;
    let side = jpeg::check(&clean, &jpeg::PICTURE)?.side;
    let small = jpeg::clean(preview, &jpeg::PREVIEW)?;
    edit(data_dir, MINE_FILE, |mine: &mut Mine| {
        next_choice(mine, now_ms)?;
        mine.jpeg = Some(BASE64.encode(&clean));
        mine.preview = Some(BASE64.encode(&small));
        mine.side = side;
        Ok(())
    })?
}

/// Removes my picture. The next [`pass`] tells every friend who has it.
/// With no picture set nothing changes. Never refused for the day's count,
/// and it uses up none of it.
pub fn clear_mine(data_dir: &Path, now_ms: u64) -> Result<(), PictureError> {
    if !attachment_gate::pictures_live() {
        return Err(PictureError::Hold);
    }
    edit(data_dir, MINE_FILE, |mine: &mut Mine| {
        if mine.jpeg.is_none() {
            return;
        }
        mine.choice = now_ms.max(mine.choice.saturating_add(1)).min(MAX_SEQ);
        mine.changed_ms = now_ms;
        mine.jpeg = None;
        mine.preview = None;
        mine.side = 0;
    })?;
    Ok(())
}

/// My picture's bytes, or its preview's.
pub fn read_mine(data_dir: &Path, preview: bool) -> Result<Vec<u8>, PictureError> {
    if !attachment_gate::pictures_live() {
        return Err(PictureError::Hold);
    }
    let mine: Mine = load(data_dir, MINE_FILE);
    let stored = if preview { mine.preview } else { mine.jpeg };
    stored
        .and_then(|text| BASE64.decode(text).ok())
        .ok_or(PictureError::NoPicture)
}

// ── Sending ─────────────────────────────────────────────────────────────

/// An offer [`pass`] made, to be sent to `peer` as a message. It holds the
/// picture's key: zeroed when dropped.
pub struct ToSend {
    /// The friend.
    pub peer: [u8; 32],
    /// The offer as it travels: the message's text.
    pub offer: Zeroizing<String>,
    /// The offer's `seq`: its name for [`offer_sent`] and [`offer_unsent`].
    pub seq: u64,
    /// The handle of its row in the attachment store; `None` for No picture.
    pub handle: Option<Handle>,
}

impl std::fmt::Debug for ToSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToSend")
            .field("seq", &self.seq)
            .field("picture", &self.handle.is_some())
            .finish_non_exhaustive()
    }
}

/// How a message of mine stands, as far as its history row says.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fate {
    Arrived,
    Ended,
    OnItsWay,
}

fn fates(data_dir: &Path, wanted: &HashSet<String>) -> BTreeMap<String, Fate> {
    let mut out = BTreeMap::new();
    if wanted.is_empty() {
        return out;
    }
    let Ok(history) = crate::chat_history::ChatHistory::load(data_dir) else {
        return out;
    };
    for entry in &history.entries {
        if entry.direction != "out" || !wanted.contains(&entry.message_id_hex) {
            continue;
        }
        let fate = match entry.delivery.as_str() {
            "delivered" | "read" => Fate::Arrived,
            "failed" | "expired" | "cancelled" => Fate::Ended,
            _ => Fate::OnItsWay,
        };
        out.insert(entry.message_id_hex.clone(), fate);
    }
    out
}

fn remove_row(data_dir: &Path, handle: Option<&str>) {
    if let Some(handle) = handle.and_then(handle_of) {
        let _ = store::remove(data_dir, &handle);
    }
}

/// One look at everything, and the offers that are due.
///
/// 1. A friend who is no longer one (not verified any more, blocked,
///    removed) is forgotten: what I sent them, what they sent me, and the
///    rows of both in the attachment store ([`forget_strangers`] does the
///    same between looks).
/// 2. What was sent is followed: an offer whose message arrived is taken,
///    one whose chunk the friend's node has is there (its row and its key
///    go), one whose message ended or was never made is due again.
/// 3. Every verified friend whose node takes attachments and who does not
///    have my newest choice gets an offer: a new key, the next `seq`, and
///    the `seq` of theirs I hold. So does a friend whose offer, come
///    after mine was made, says it holds an older one of mine than it
///    took: once a day. No more than [`OFFERS_A_DAY`] for one friend in a
///    day.
///
/// The first look of a store only notes who is verified by then: with no
/// choice ever made, those friends are told nothing, so a new or lost store
/// never tells them that there is no picture. A friend verified after that
/// look is due an offer like any other, the empty form when there is no
/// picture: it carries what I hold of theirs, and lets them send theirs
/// again when I hold none.
pub fn pass(data_dir: &Path, now_ms: u64) -> Result<Vec<ToSend>, PictureError> {
    if !attachment_gate::pictures_live() {
        return Ok(Vec::new());
    }
    let today = day_of(now_ms);
    // A contact book that does not read just now: nobody is forgotten and
    // nobody is offered anything at this look.
    let Some(friends) = friends_now(data_dir) else {
        return Ok(Vec::new());
    };
    let current: HashSet<String> = friends.iter().map(key_of).collect();
    adopt_kept(data_dir, now_ms);

    // 1. Friends who are no longer friends.
    forget_all_but(data_dir, &current)?;
    let theirs: TheirsBook = load(data_dir, THEIRS_FILE);

    let waiting: HashSet<String> = load::<SentBook>(data_dir, SENT_FILE)
        .friends
        .values()
        .filter(|s| s.handle.is_none() && s.reached != Reached::Has)
        .filter_map(|s| s.message_id.clone())
        .collect();
    let fates = fates(data_dir, &waiting);

    // My choice as it is now. Offers made below count its `seq` on; the
    // count is written back at the end, never the choice itself.
    let mut mine: Mine = load(data_dir, MINE_FILE);
    let mut made = Vec::new();
    let mut failure = None;
    let mut first_look = false;
    // The rows of offers that are at their friends: removed once the book
    // says so.
    let mut there: Vec<Handle> = Vec::new();
    edit(data_dir, SENT_FILE, |book: &mut SentBook| {
        // 2. What was sent.
        for sent in book.friends.values_mut() {
            follow(data_dir, sent, &fates, now_ms, &mut there);
        }
        // 3. Who is due. The first look of a store (a new one, or one made
        // again after the old was lost) only notes the friends who are
        // verified already: with no choice made they are told nothing, so
        // a lost store never takes my picture off their devices.
        if !mine.looked {
            if mine.choice == 0 {
                for peer in &friends {
                    book.friends.entry(key_of(peer)).or_insert_with(|| Sent {
                        reached: Reached::Has,
                        ..Sent::default()
                    });
                }
            }
            mine.looked = true;
            first_look = true;
        }
        for peer in &friends {
            if !peers::speaks(data_dir, peer) {
                continue;
            }
            let key = key_of(peer);
            let before = book.friends.get(&key).cloned();
            let from_them = theirs.friends.get(&key);
            // A friend whose newest offer says it holds an older one of
            // mine than it took has lost mine: an offer of theirs that came
            // after mine was made. One that came before says only what
            // they held then.
            let repair = before.as_ref().is_some_and(|s| {
                s.choice == mine.choice
                    && s.reached == Reached::Has
                    && s.repair_day != today
                    && from_them.is_some_and(|t| t.held < s.seq && t.came_ms > s.made_ms)
            });
            let due = before.as_ref().is_none_or(|s| s.choice != mine.choice) || repair;
            let offers_today = before
                .as_ref()
                .filter(|s| s.day == today)
                .map_or(0, |s| s.offers);
            if !due || offers_today >= OFFERS_A_DAY {
                continue;
            }
            let held = from_them.map_or(0, |t| t.seq);
            match make(data_dir, &mut mine, peer, held, now_ms) {
                Ok(to_send) => {
                    remove_row(data_dir, before.as_ref().and_then(|s| s.handle.as_deref()));
                    let repair_day = if repair {
                        today
                    } else {
                        before.as_ref().map_or(0, |s| s.repair_day)
                    };
                    book.friends.insert(
                        key,
                        Sent {
                            choice: mine.choice,
                            seq: to_send.seq,
                            handle: to_send.handle.map(hex::encode),
                            message_id: None,
                            reached: Reached::Waiting,
                            made_ms: now_ms,
                            day: today,
                            offers: offers_today + 1,
                            repair_day,
                        },
                    );
                    made.push(to_send);
                }
                Err(e) => {
                    // The store is full, say: the rest of the friends wait
                    // for the next look too.
                    failure = Some(e);
                    break;
                }
            }
        }
    })?;
    for handle in there {
        let _ = store::remove(data_dir, &handle);
    }
    let last = made.iter().map(|to_send| to_send.seq).max();
    if last.is_some() || first_look {
        edit(data_dir, MINE_FILE, |kept: &mut Mine| {
            kept.seq = kept.seq.max(last.unwrap_or(0));
            kept.looked = true;
        })?;
    }
    match failure {
        Some(e) if made.is_empty() => Err(e),
        _ => Ok(made),
    }
}

/// Follows one offer of mine: what its row in the attachment store, or its
/// message, says by now.
fn follow(
    data_dir: &Path,
    sent: &mut Sent,
    fates: &BTreeMap<String, Fate>,
    now_ms: u64,
    there: &mut Vec<Handle>,
) {
    if sent.reached == Reached::Has {
        return;
    }
    let unsent_long =
        sent.message_id.is_none() && now_ms.saturating_sub(sent.made_ms) >= UNSENT_AGAIN_MS;
    let again = |sent: &mut Sent| {
        remove_row(data_dir, sent.handle.as_deref());
        sent.handle = None;
        // No choice has the number 0: the friend is due again.
        sent.choice = 0;
    };
    let handle = sent.handle.as_deref().map(handle_of);
    match handle {
        // A picture: its row says how far it is.
        Some(Some(handle)) => match store::get(data_dir, &handle) {
            Ok(Some(row)) if row.outgoing => match row.state {
                State::Delivered => {
                    // Its row goes once the book is written (the caller):
                    // whoever reads in between finds the row or the book's
                    // word, never neither.
                    there.push(handle);
                    sent.handle = None;
                    sent.reached = Reached::Has;
                }
                State::Offered => sent.reached = Reached::Taken,
                State::Staged if unsent_long => again(sent),
                State::Staged => {}
                _ => again(sent),
            },
            // Its row is gone or does not read: it cannot be served.
            Ok(_) | Err(StoreError::Corrupt) => again(sent),
            Err(_) => {}
        },
        Some(None) => again(sent),
        // No picture: its message says whether the friend was told.
        None => match sent.message_id.as_ref().and_then(|mid| fates.get(mid)) {
            Some(Fate::Arrived) => sent.reached = Reached::Has,
            Some(Fate::Ended) => again(sent),
            Some(Fate::OnItsWay) => {}
            None if unsent_long => again(sent),
            None => {}
        },
    }
}

/// Makes the offer of my newest choice for `peer`: sealed under a key of
/// its own and written to the attachment store, or the empty form.
fn make(
    data_dir: &Path,
    mine: &mut Mine,
    peer: &[u8; 32],
    held: u64,
    now_ms: u64,
) -> Result<ToSend, PictureError> {
    let seq = now_ms.max(mine.seq.saturating_add(1)).min(MAX_SEQ);
    let bad = || PictureError::Store(StoreError::Corrupt);
    let picture = match (&mine.jpeg, &mine.preview) {
        (Some(picture), Some(preview)) => Some((
            Zeroizing::new(BASE64.decode(picture).map_err(|_| bad())?),
            BASE64.decode(preview).map_err(|_| bad())?,
        )),
        _ => None,
    };
    let (offer, sealed) = match &picture {
        Some((bytes, preview)) => {
            let key = Key::random();
            let sealed = blob::seal_one_chunk(&key, bytes).map_err(|_| bad())?;
            let blob = BlobRef {
                shape: sealed.shape,
                key,
                root: sealed.root(),
            };
            let offer = Offer::profile(blob, seq, held, u32::from(mine.side), preview)
                .map_err(|_| bad())?;
            (offer, Some(sealed))
        }
        None => {
            let mut handle = [0u8; HANDLE_LEN];
            rand::rngs::OsRng.fill_bytes(&mut handle);
            (
                Offer::no_profile(handle, seq, held).map_err(|_| bad())?,
                None,
            )
        }
    };
    let text = Zeroizing::new(offer.encode().map_err(|_| bad())?);
    let handle = match &sealed {
        Some(sealed) => {
            // The message's id is not known yet: [`offer_sent`] writes it.
            let row = Row::of_offer(&offer, &text, Chat::Friend(peer), &[0u8; 16], true, now_ms)
                .ok_or_else(bad)?;
            store::write_blob(data_dir, &offer.handle, sealed)?;
            if let Err(e) = store::put(data_dir, &row) {
                let _ = store::remove(data_dir, &offer.handle);
                return Err(e.into());
            }
            Some(offer.handle)
        }
        None => None,
    };
    mine.seq = seq;
    Ok(ToSend {
        peer: *peer,
        offer: text,
        seq,
        handle,
    })
}

/// The offer `seq` for `peer` went out as message `message_id`.
pub fn offer_sent(
    data_dir: &Path,
    peer: &[u8; 32],
    seq: u64,
    message_id: &[u8; 16],
    now_ms: u64,
) -> Result<(), StoreError> {
    let handle = edit(data_dir, SENT_FILE, |book: &mut SentBook| {
        let sent = book
            .friends
            .get_mut(&key_of(peer))
            .filter(|s| s.seq == seq)?;
        sent.message_id = Some(hex::encode(message_id));
        sent.handle.as_deref().and_then(handle_of)
    })?;
    match handle {
        Some(handle) => flow::sent(data_dir, &handle, message_id, now_ms),
        None => Ok(()),
    }
}

/// Did the offer `seq` for `peer` become a message ([`offer_sent`] was
/// told its id)? A send that failed after its message was made is the
/// outbox's to finish; one that made no message is [`offer_unsent`].
pub fn offer_has_message(data_dir: &Path, peer: &[u8; 32], seq: u64) -> bool {
    load::<SentBook>(data_dir, SENT_FILE)
        .friends
        .get(&key_of(peer))
        .is_some_and(|sent| sent.seq == seq && sent.message_id.is_some())
}

/// No message could be made for the offer `seq` for `peer`: its row goes,
/// and the friend is due again at the next [`pass`].
pub fn offer_unsent(data_dir: &Path, peer: &[u8; 32], seq: u64) -> Result<(), StoreError> {
    edit(data_dir, SENT_FILE, |book: &mut SentBook| {
        if let Some(sent) = book.friends.get_mut(&key_of(peer)).filter(|s| s.seq == seq) {
            remove_row(data_dir, sent.handle.as_deref());
            sent.handle = None;
            sent.choice = 0;
        }
    })
}

// ── Theirs ──────────────────────────────────────────────────────────────

/// What became of a friend's profile offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Taken {
    /// It is the friend's newest: kept, and its chunk may come (or, the
    /// empty form: their picture went).
    New,
    /// The same offer was taken before (a copy sent again).
    Again,
    /// Older than the one held, over the day's count, or not a profile
    /// offer: dropped.
    Dropped,
    /// Not taken into the store: pictures are off, or the sender is not a
    /// verified friend. The caller keeps it as a build without pictures
    /// does, for [`adopt_kept`].
    Kept,
}

/// Takes the profile offer `text` that `peer` sent as message
/// `message_id`. The newest `seq` of a friend wins: it replaces the one
/// held at once, picture and all. Nothing is decrypted or decoded here.
pub fn take_offer(
    data_dir: &Path,
    peer: &[u8; 32],
    message_id: &[u8; 16],
    text: &str,
    now_ms: u64,
) -> Result<Taken, StoreError> {
    let Some(Frame::Offer(offer)) = offer::parse_frame(text.as_bytes()) else {
        return Ok(Taken::Dropped);
    };
    let (seq, held, picture) = match &offer.content {
        Content::Profile {
            seq,
            held,
            side,
            preview,
        } => (*seq, *held, Some((*side, preview.clone()))),
        Content::NoProfile { seq, held } => (*seq, *held, None),
        _ => return Ok(Taken::Dropped),
    };
    if !attachment_gate::pictures_live() || !flow::is_friend(data_dir, peer) {
        return Ok(Taken::Kept);
    }
    let sha256 = hex::encode(Sha256::digest(text.as_bytes()));
    let today = day_of(now_ms);
    let mut old_row: Option<String> = None;
    let taken = edit(data_dir, THEIRS_FILE, |book: &mut TheirsBook| {
        let key = key_of(peer);
        let old = book.friends.get(&key);
        if old.is_some_and(|t| t.sha256 == sha256) {
            return Ok(Taken::Again);
        }
        let taken_today = old.filter(|t| t.day == today).map_or(0, |t| t.taken);
        if old.is_some_and(|t| t.seq >= seq) || taken_today >= TAKEN_A_DAY {
            return Ok(Taken::Dropped);
        }
        let mut next = Theirs {
            seq,
            sha256,
            handle: None,
            side: 0,
            preview: None,
            held,
            came_ms: now_ms,
            day: today,
            taken: taken_today + 1,
            bad: old.filter(|t| t.day == today).map_or(0, |t| t.bad),
        };
        if let Some((side, preview)) = picture {
            let Some(row) =
                Row::of_offer(&offer, text, Chat::Friend(peer), message_id, false, now_ms)
            else {
                return Ok(Taken::Dropped);
            };
            match store::get(data_dir, &offer.handle) {
                // The handle is another attachment's already.
                Ok(Some(_)) | Err(StoreError::Corrupt) => return Ok(Taken::Dropped),
                Ok(None) => {}
                Err(e) => return Err(e),
            }
            match store::put(data_dir, &row) {
                Ok(()) => {}
                // No room now: it stays where a build without pictures
                // keeps it, and is taken up later.
                Err(StoreError::Full) => return Ok(Taken::Kept),
                Err(e) => return Err(e),
            }
            next.handle = Some(hex::encode(offer.handle));
            next.side = u16::try_from(side).unwrap_or(0);
            next.preview = Some(BASE64.encode(preview));
        }
        // The picture held until now goes, with its row and its key: once
        // the book names the new one (below).
        old_row = old.and_then(|t| t.handle.clone());
        book.friends.insert(key, next);
        Ok(Taken::New)
    })?;
    // Whoever reads between the two writes finds the old picture whole or
    // the new one announced, never the old one without its bytes.
    if matches!(taken, Ok(Taken::New)) {
        remove_row(data_dir, old_row.as_deref());
    }
    taken
}

/// Takes up the profile offers the history kept as they came, from friends
/// who are verified by now ([`take_offer`]): pictures went live after a
/// build that only kept them, or the words matched after the offer came.
/// A row whose offer was taken, or is older than what is held, goes from
/// the history. How many were taken.
pub fn adopt_kept(data_dir: &Path, now_ms: u64) -> usize {
    if !attachment_gate::pictures_live() {
        return 0;
    }
    let mut taken = 0;
    let _ =
        crate::chat_history::ChatHistory::retain_kept_profile_offers_persisted(data_dir, |entry| {
            let (Some(peer), Some(mid)) = (
                peer_of(&entry.peer_pub_hex.to_ascii_lowercase()),
                mid_of(&entry.message_id_hex),
            ) else {
                return true;
            };
            match take_offer(data_dir, &peer, &mid, &entry.body, now_ms) {
                Ok(Taken::New) => {
                    taken += 1;
                    false
                }
                Ok(Taken::Again | Taken::Dropped) => false,
                Ok(Taken::Kept) | Err(_) => true,
            }
        });
    taken
}

/// A friend's picture, for an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TheirView {
    /// Changes whenever what is shown changes.
    pub seq: u64,
    /// The bytes are here and checked; else only the preview is.
    pub ready: bool,
}

fn not_today(theirs: &Theirs, now_ms: u64) -> bool {
    theirs.day == day_of(now_ms) && theirs.bad >= BAD_A_DAY
}

/// The picture the verified friend `peer` sent, if there is one to show.
/// Whether it shows is worked out here each time, never stored: no path
/// leaves a picture showing for a contact that is not verified.
pub fn theirs(data_dir: &Path, peer: &[u8; 32], now_ms: u64) -> Option<TheirView> {
    Views::load(data_dir, now_ms).theirs(peer)
}

/// The bytes of the picture the verified friend `peer` sent, or of its
/// preview: opened in memory and checked ([`jpeg::check`]) before anything
/// may decode them. A picture that fails the check goes at once, and after
/// [`BAD_A_DAY`] of them none of that friend's is opened until the next
/// day.
pub fn read_theirs(
    data_dir: &Path,
    peer: &[u8; 32],
    preview: bool,
    now_ms: u64,
) -> Result<Vec<u8>, PictureError> {
    if !attachment_gate::pictures_live() {
        return Err(PictureError::Hold);
    }
    if !flow::is_friend(data_dir, peer) {
        return Err(PictureError::NotVerified);
    }
    let book: TheirsBook = load(data_dir, THEIRS_FILE);
    let theirs = book
        .friends
        .get(&key_of(peer))
        .ok_or(PictureError::NoPicture)?;
    let handle = theirs
        .handle
        .as_deref()
        .and_then(handle_of)
        .ok_or(PictureError::NoPicture)?;
    if not_today(theirs, now_ms) {
        return Err(PictureError::NoPicture);
    }
    let checked = if preview {
        theirs
            .preview
            .as_deref()
            .and_then(|text| BASE64.decode(text).ok())
            .ok_or(JpegError::Refused("no preview"))
            .and_then(|bytes| jpeg::check(&bytes, &jpeg::PREVIEW).map(|_| bytes))
    } else {
        let row = match store::get(data_dir, &handle) {
            Ok(Some(row)) if !row.outgoing && row.state == State::Complete => row,
            Ok(_) => return Err(PictureError::NoPicture),
            Err(e) => return Err(e.into()),
        };
        let len = row
            .shape()
            .and_then(|shape| usize::try_from(shape.len()).ok())
            .ok_or(PictureError::NoPicture)?;
        let plain = store::read_plain(data_dir, &row, 0, len)?;
        jpeg::check(&plain, &jpeg::PICTURE).and_then(|found| {
            if found.side == theirs.side {
                Ok(plain.to_vec())
            } else {
                Err(JpegError::Refused("a side that is not the offer's"))
            }
        })
    };
    match checked {
        Ok(bytes) => Ok(bytes),
        Err(e) => {
            let seq = theirs.seq;
            let today = day_of(now_ms);
            let _ = edit(data_dir, THEIRS_FILE, |book: &mut TheirsBook| {
                if let Some(t) = book.friends.get_mut(&key_of(peer)).filter(|t| t.seq == seq) {
                    remove_row(data_dir, t.handle.as_deref());
                    t.handle = None;
                    t.preview = None;
                    if t.day != today {
                        t.day = today;
                        t.taken = 0;
                        t.bad = 0;
                    }
                    t.bad = t.bad.saturating_add(1);
                }
            });
            Err(PictureError::Bad(e))
        }
    }
}

/// Is this the row of a profile picture: one that follows its friend and
/// not a chat's messages? A cleared chat leaves such a row alone, and so
/// does the sweep while [`handles`] names it.
pub fn is_picture_row(row: &Row) -> bool {
    row.stored()
        .is_some_and(|stored| stored.kind() == offer::Kind::Profile)
}

/// The rows of the attachment store the picture files name: my offers on
/// their way and the friends' pictures. A picture's row that none of them
/// names (a write that stopped half way) is the sweep's to remove.
pub fn handles(data_dir: &Path) -> HashSet<Handle> {
    let sent: SentBook = load(data_dir, SENT_FILE);
    let theirs: TheirsBook = load(data_dir, THEIRS_FILE);
    sent.friends
        .values()
        .filter_map(|s| s.handle.as_deref())
        .chain(theirs.friends.values().filter_map(|t| t.handle.as_deref()))
        .filter_map(handle_of)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attachment::jpeg::testing::{parts, picture};

    const FRIEND: [u8; 32] = [9u8; 32];
    const OTHER: [u8; 32] = [7u8; 32];
    const ME: [u8; 32] = [5u8; 32];
    const DAY: u64 = DAY_MS;
    const T0: u64 = 20_000 * DAY_MS + 1_000;

    /// Both gates open for this test's thread; back to the variables when
    /// dropped. `None` in a release build, where no switch opens them.
    struct Live;
    impl Live {
        fn on() -> Option<Live> {
            if !cfg!(debug_assertions) {
                return None;
            }
            attachment_gate::set_lab_attachments_for_this_thread(Some(true));
            attachment_gate::set_lab_pictures_for_this_thread(Some(true));
            Some(Live)
        }
    }
    impl Drop for Live {
        fn drop(&mut self) {
            attachment_gate::set_lab_attachments_for_this_thread(None);
            attachment_gate::set_lab_pictures_for_this_thread(None);
        }
    }

    /// A profile whose contact book holds these contacts: (key, verified).
    fn profile(contacts: &[([u8; 32], bool)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        write_contacts(dir.path(), contacts);
        dir
    }

    fn write_contacts(d: &Path, contacts: &[([u8; 32], bool)]) {
        let rows: Vec<String> = contacts
            .iter()
            .map(|(key, pinned)| {
                format!(
                    r#"{{"petname":"Friend","pub_hex":"{}","address":"","pinned":{pinned}}}"#,
                    hex::encode(key)
                )
            })
            .collect();
        std::fs::write(d.join("contacts.json"), format!("[{}]", rows.join(","))).unwrap();
    }

    fn speaks(d: &Path, peer: &[u8; 32]) {
        peers::note(d, peer, true, 1).unwrap();
    }

    fn face(side: u16) -> Vec<u8> {
        picture(side)
    }

    fn small() -> Vec<u8> {
        parts(32, 3, 0).bytes()
    }

    /// Every chunk of the outgoing row `handle` is with the friend.
    fn delivered(d: &Path, handle: &Handle) {
        store::update(d, handle, 5, |row| row.state = State::Delivered).unwrap();
    }

    /// The one chunk of the friend's picture `handle` lands in `to`, as the
    /// exchange writes it: checked against the root, then the row is whole.
    fn land(to: &Path, handle: &Handle, chunk: &[u8], now: u64) {
        let row = store::get(to, handle).unwrap().unwrap();
        let taken = store::take_chunk(
            to,
            handle,
            &row.shape().unwrap(),
            &row.root().unwrap(),
            0,
            chunk,
            &[],
        )
        .unwrap();
        assert!(matches!(taken, store::Taken::Written { complete: true }));
        store::set_state(to, handle, State::Complete, now).unwrap();
    }

    /// The chunk of the picture `handle` as `from` keeps it to serve.
    fn chunk_at(from: &Path, handle: &Handle) -> Vec<u8> {
        std::fs::read(store::blob_dir(from, handle).join(store::BLOB_FILE)).unwrap()
    }

    /// The friend's side of one offer: `b` takes what `a` made for it, and
    /// its chunk lands.
    fn carry(a: &Path, b: &Path, from: &[u8; 32], send: &ToSend, mid: u8, now: u64) -> Taken {
        let taken = take_offer(b, from, &[mid; 16], &send.offer, now).unwrap();
        if let (Taken::New, Some(handle)) = (taken, send.handle) {
            land(b, &handle, &chunk_at(a, &handle), now);
        }
        taken
    }

    #[test]
    fn nothing_is_kept_or_offered_while_the_gate_is_shut() {
        attachment_gate::set_lab_pictures_for_this_thread(Some(false));
        let home = profile(&[(FRIEND, true)]);
        let d = home.path();
        assert!(matches!(
            set_mine(d, &face(64), &small(), T0),
            Err(PictureError::Hold)
        ));
        assert!(matches!(mine(d, T0), Err(PictureError::Hold)));
        assert!(pass(d, T0).unwrap().is_empty());
        assert!(theirs(d, &FRIEND, T0).is_none());
        attachment_gate::set_lab_pictures_for_this_thread(None);
        assert!(!d.join(MINE_FILE).exists());
    }

    #[test]
    fn my_picture_is_checked_cleaned_and_kept_and_three_changes_a_day_are_all() {
        let Some(_live) = Live::on() else { return };
        let home = profile(&[]);
        let d = home.path();
        assert!(matches!(read_mine(d, false), Err(PictureError::NoPicture)));
        // What an encoder wrote: the frame first, and an Exif block.
        let p = parts(384, 3, 24);
        let mut raw = vec![0xFF, 0xD8];
        raw.extend_from_slice(&p.jfif);
        raw.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x08, b'E', b'x', b'i', b'f', 0, 0]);
        for part in [
            &p.frame,
            &p.huffs,
            &p.quant,
            &p.restart,
            &p.scan_header,
            &p.scan,
        ] {
            raw.extend_from_slice(part);
        }
        raw.extend_from_slice(&[0xFF, 0xD9]);
        set_mine(d, &raw, &small(), T0).unwrap();
        assert_eq!(
            read_mine(d, false).unwrap(),
            p.bytes(),
            "kept as it travels"
        );
        assert_eq!(read_mine(d, true).unwrap(), small());
        let view = mine(d, T0).unwrap();
        assert!(view.set);
        assert_eq!((view.choice, view.changes_left, view.friends), (T0, 2, 0));

        // What is not a picture is refused, and nothing changes.
        assert!(matches!(
            set_mine(d, b"GIF89a", &small(), T0),
            Err(PictureError::Bad(_))
        ));
        assert!(matches!(
            set_mine(d, &face(520), &small(), T0),
            Err(PictureError::TooBig)
        ));
        assert!(matches!(
            set_mine(d, &face(64), &face(128), T0),
            Err(PictureError::TooBig)
        ));
        assert_eq!(mine(d, T0).unwrap().choice, T0);

        // The same instant again: the number still rises.
        set_mine(d, &face(64), &small(), T0).unwrap();
        assert_eq!(mine(d, T0).unwrap().choice, T0 + 1);
        // Taking it away is a new choice, and uses up none of the day's.
        clear_mine(d, T0 + 5).unwrap();
        let view = mine(d, T0 + 5).unwrap();
        assert!(!view.set);
        assert_eq!((view.choice, view.changes_left), (T0 + 5, 1));
        assert!(matches!(read_mine(d, false), Err(PictureError::NoPicture)));
        // Clearing what is not set changes nothing.
        clear_mine(d, T0 + 6).unwrap();
        assert_eq!(mine(d, T0 + 6).unwrap().choice, T0 + 5);
        // The third picture of the day is the last; the fourth is refused,
        // and taking the third away still works.
        set_mine(d, &face(64), &small(), T0 + 7).unwrap();
        assert_eq!(mine(d, T0 + 7).unwrap().changes_left, 0);
        assert!(matches!(
            set_mine(d, &face(64), &small(), T0 + 8),
            Err(PictureError::ChangeLimit)
        ));
        assert_eq!(mine(d, T0 + 8).unwrap().choice, T0 + 7);
        clear_mine(d, T0 + 9).unwrap();
        assert!(!mine(d, T0 + 9).unwrap().set);
        // The next day takes a picture again.
        set_mine(d, &face(64), &small(), T0 + DAY).unwrap();
        assert_eq!(mine(d, T0 + DAY).unwrap().changes_left, 2);
    }

    #[test]
    fn only_verified_friends_whose_raven_takes_attachments_are_offered_my_picture() {
        let Some(_live) = Live::on() else { return };
        let stranger = [3u8; 32];
        let old = [4u8; 32];
        let home = profile(&[(FRIEND, true), (OTHER, false), (old, true)]);
        let d = home.path();
        speaks(d, &FRIEND);
        speaks(d, &OTHER);
        speaks(d, &stranger);
        // No choice yet: the friends verified by the first look are told
        // nothing.
        assert!(pass(d, T0).unwrap().is_empty());
        assert!(pass(d, T0).unwrap().is_empty());
        // Who could not take a picture is counted all the same: an app says
        // how many friends will see the picture being chosen.
        let before = mine(d, T0).unwrap();
        assert_eq!(
            (
                before.friends,
                before.have_it,
                before.waiting,
                before.need_newer
            ),
            (2, 0, 0, 1)
        );
        assert_eq!(reach(d, &old), None, "nothing to say of one friend yet");
        set_mine(d, &face(64), &small(), T0).unwrap();
        let made = pass(d, T0 + 1).unwrap();
        assert_eq!(made.len(), 1, "{made:?}");
        assert_eq!(made[0].peer, FRIEND);
        let view = mine(d, T0 + 1).unwrap();
        assert_eq!(
            (view.friends, view.have_it, view.waiting, view.need_newer),
            (2, 0, 1, 1)
        );
        assert_eq!(reach(d, &FRIEND), Some(Reach::Waiting));
        assert_eq!(reach(d, &old), Some(Reach::NeedsNewer));
        assert_eq!(reach(d, &OTHER), None, "not verified");
        assert_eq!(reach(d, &stranger), None);
        // The offer is a profile offer under a key of its own, with its row.
        let handle = made[0].handle.unwrap();
        let row = store::get(d, &handle).unwrap().unwrap();
        assert!(row.outgoing && is_picture_row(&row));
        assert_eq!(row.peer_key(), Some(FRIEND));
        let Some(Frame::Offer(offer)) = offer::parse_frame(made[0].offer.as_bytes()) else {
            panic!("not an offer");
        };
        assert!(matches!(
            offer.content,
            Content::Profile { seq, held: 0, side: 64, .. } if seq == made[0].seq
        ));
        // Nothing more is due while that offer is on its way.
        offer_sent(d, &FRIEND, made[0].seq, &[1u8; 16], T0 + 2).unwrap();
        assert!(pass(d, T0 + 3).unwrap().is_empty());
        assert_eq!(
            store::get(d, &handle).unwrap().unwrap().message_id_bytes(),
            Some([1u8; 16])
        );
        // The friend whose Raven learns attachments is due then; the one
        // verified now is due too.
        speaks(d, &old);
        write_contacts(d, &[(FRIEND, true), (OTHER, true), (old, true)]);
        let made = pass(d, T0 + 4).unwrap();
        let mut to: Vec<[u8; 32]> = made.iter().map(|m| m.peer).collect();
        to.sort();
        assert_eq!(to, vec![old, OTHER]);
        // Two friends never get the same handle, key or seq.
        assert_ne!(made[0].handle, made[1].handle);
        assert_ne!(made[0].seq, made[1].seq);
        assert_ne!(*made[0].offer, *made[1].offer);
    }

    #[test]
    fn a_friend_verified_after_the_first_look_is_told_even_that_there_is_no_picture() {
        let Some(_live) = Live::on() else { return };
        let home = profile(&[(FRIEND, true), (OTHER, false)]);
        let d = home.path();
        speaks(d, &FRIEND);
        speaks(d, &OTHER);
        // The first look of a store with no choice: nothing for the friend
        // who is verified already, however often it looks.
        assert!(pass(d, T0).unwrap().is_empty());
        assert!(pass(d, T0 + 1).unwrap().is_empty());
        assert_eq!(reach(d, &FRIEND), None, "nothing to tell");
        // A friend verified after it gets the empty form, which carries the
        // `seq` of theirs I hold (none: 0).
        write_contacts(d, &[(FRIEND, true), (OTHER, true)]);
        let made = pass(d, T0 + 2).unwrap();
        assert_eq!(made.len(), 1);
        assert_eq!(made[0].peer, OTHER);
        assert!(made[0].handle.is_none());
        let Some(Frame::Offer(offer)) = offer::parse_frame(made[0].offer.as_bytes()) else {
            panic!("not an offer");
        };
        assert!(matches!(offer.content, Content::NoProfile { held: 0, .. }));
        assert!(pass(d, T0 + 3).unwrap().is_empty());
        // The first picture goes to both.
        set_mine(d, &face(64), &small(), T0 + 4).unwrap();
        assert_eq!(pass(d, T0 + 4).unwrap().len(), 2);

        // A store that was lost and is made again: the friends verified by
        // its first look are told nothing, so none of them loses my picture.
        for file in [MINE_FILE, SENT_FILE, THEIRS_FILE] {
            let _ = std::fs::remove_file(d.join(file));
        }
        assert!(pass(d, T0 + 10).unwrap().is_empty());
        assert!(pass(d, T0 + 11).unwrap().is_empty());
        // And a store whose first act is a picture sends it to everyone.
        let fresh = profile(&[(FRIEND, true)]);
        speaks(fresh.path(), &FRIEND);
        set_mine(fresh.path(), &face(64), &small(), T0).unwrap();
        assert_eq!(pass(fresh.path(), T0).unwrap().len(), 1);
    }

    #[test]
    fn an_offer_is_followed_until_the_friend_has_it_and_then_its_key_goes() {
        let Some(_live) = Live::on() else { return };
        let home = profile(&[(FRIEND, true)]);
        let d = home.path();
        speaks(d, &FRIEND);
        set_mine(d, &face(64), &small(), T0).unwrap();
        let made = pass(d, T0).unwrap();
        let handle = made[0].handle.unwrap();
        offer_sent(d, &FRIEND, made[0].seq, &[1u8; 16], T0).unwrap();
        // The friend's node has the offer.
        store::update(d, &handle, 3, |row| row.state = State::Offered).unwrap();
        assert!(pass(d, T0 + 1).unwrap().is_empty());
        assert_eq!(reach(d, &FRIEND), Some(Reach::Waiting));
        // And then the chunk: the friend has it, as a reader sees at once;
        // the next look lets the row and its key go.
        delivered(d, &handle);
        assert_eq!(reach(d, &FRIEND), Some(Reach::Has));
        assert_eq!(mine(d, T0 + 2).unwrap().have_it, 1);
        assert!(pass(d, T0 + 2).unwrap().is_empty());
        assert_eq!(reach(d, &FRIEND), Some(Reach::Has));
        assert!(store::get(d, &handle).unwrap().is_none());
        assert!(!store::blob_dir(d, &handle).exists());
        let view = mine(d, T0 + 2).unwrap();
        assert_eq!((view.have_it, view.waiting), (1, 0));
        assert!(pass(d, T0 + 3).unwrap().is_empty(), "nothing is sent twice");
    }

    #[test]
    fn a_new_choice_goes_to_every_friend_again_and_removing_it_tells_them() {
        let Some(_live) = Live::on() else { return };
        let home = profile(&[(FRIEND, true)]);
        let d = home.path();
        speaks(d, &FRIEND);
        set_mine(d, &face(64), &small(), T0).unwrap();
        let first = pass(d, T0).unwrap();
        // Changed before the first one arrived: its row goes, a new one is made.
        set_mine(d, &face(128), &small(), T0 + 10).unwrap();
        let second = pass(d, T0 + 11).unwrap();
        assert_eq!(second.len(), 1);
        assert!(second[0].seq > first[0].seq);
        assert!(store::get(d, &first[0].handle.unwrap()).unwrap().is_none());
        assert!(store::get(d, &second[0].handle.unwrap()).unwrap().is_some());
        delivered(d, &second[0].handle.unwrap());
        assert!(pass(d, T0 + 12).unwrap().is_empty());
        assert_eq!(reach(d, &FRIEND), Some(Reach::Has));
        // Removed: the empty form goes, with no row and no key.
        clear_mine(d, T0 + 20).unwrap();
        assert_eq!(reach(d, &FRIEND), Some(Reach::Waiting));
        let third = pass(d, T0 + 21).unwrap();
        assert_eq!(third.len(), 1);
        assert!(third[0].handle.is_none());
        let Some(Frame::Offer(offer)) = offer::parse_frame(third[0].offer.as_bytes()) else {
            panic!("not an offer");
        };
        assert!(matches!(offer.content, Content::NoProfile { .. }));
        assert_eq!(store::count(d), 0);
        // One friend is offered so many in a day and no more.
        assert_eq!(
            load::<SentBook>(d, SENT_FILE).friends[&key_of(&FRIEND)].offers,
            3
        );
        let due_again = || {
            edit(d, SENT_FILE, |b: &mut SentBook| {
                b.friends.get_mut(&key_of(&FRIEND)).unwrap().choice = 0;
            })
            .unwrap();
        };
        for offer in 4..=u64::from(OFFERS_A_DAY) {
            due_again();
            assert_eq!(pass(d, T0 + 30 + offer).unwrap().len(), 1, "offer {offer}");
        }
        due_again();
        assert!(pass(d, T0 + 50).unwrap().is_empty(), "no more today");
        assert_eq!(pass(d, T0 + DAY).unwrap().len(), 1, "the next day");
    }

    #[test]
    fn an_offer_whose_message_was_never_made_or_ended_is_made_again() {
        let Some(_live) = Live::on() else { return };
        let home = profile(&[(FRIEND, true)]);
        let d = home.path();
        speaks(d, &FRIEND);
        set_mine(d, &face(64), &small(), T0).unwrap();
        let first = pass(d, T0).unwrap();
        // The sender said at once that no message was made.
        offer_unsent(d, &FRIEND, first[0].seq).unwrap();
        assert!(store::get(d, &first[0].handle.unwrap()).unwrap().is_none());
        let second = pass(d, T0 + 1).unwrap();
        assert_eq!(second.len(), 1);
        // The sender ended without a word: made again after a while.
        assert!(pass(d, T0 + 2).unwrap().is_empty());
        let third = pass(d, T0 + 2 + UNSENT_AGAIN_MS).unwrap();
        assert_eq!(third.len(), 1);
        assert!(store::get(d, &second[0].handle.unwrap()).unwrap().is_none());
        // Its message ended without arriving (the engine marks the row).
        offer_sent(d, &FRIEND, third[0].seq, &[2u8; 16], T0).unwrap();
        store::update(d, &third[0].handle.unwrap(), 9, |row| {
            row.state = State::Failed
        })
        .unwrap();
        let fourth = pass(d, T0 + 3 + UNSENT_AGAIN_MS).unwrap();
        assert_eq!(fourth.len(), 1);
        assert_eq!(store::count(d), 1, "one row for one friend, never more");
    }

    #[test]
    fn a_friends_picture_is_taken_shown_and_replaced_by_the_newest() {
        let Some(_live) = Live::on() else { return };
        let (theirs_home, my_home) = (profile(&[(ME, true)]), profile(&[(FRIEND, true)]));
        let (a, b) = (theirs_home.path(), my_home.path());
        speaks(a, &ME);
        set_mine(a, &face(64), &small(), T0).unwrap();
        let first = pass(a, T0).unwrap();
        assert!(theirs(b, &FRIEND, T0).is_none());
        // The offer alone: the preview can be shown, the picture not yet.
        assert_eq!(
            take_offer(b, &FRIEND, &[1u8; 16], &first[0].offer, T0).unwrap(),
            Taken::New
        );
        let seen = theirs(b, &FRIEND, T0).unwrap();
        assert_eq!((seen.seq, seen.ready), (first[0].seq, false));
        assert_eq!(read_theirs(b, &FRIEND, true, T0).unwrap(), small());
        assert!(matches!(
            read_theirs(b, &FRIEND, false, T0),
            Err(PictureError::NoPicture)
        ));
        // A copy sent again changes nothing.
        assert_eq!(
            take_offer(b, &FRIEND, &[1u8; 16], &first[0].offer, T0).unwrap(),
            Taken::Again
        );
        // Its chunk: the picture reads back as the friend set it.
        let handle = first[0].handle.unwrap();
        let row = store::get(b, &handle).unwrap().unwrap();
        assert!(!row.outgoing && is_picture_row(&row));
        land(b, &handle, &chunk_at(a, &handle), T0);
        assert!(theirs(b, &FRIEND, T0).unwrap().ready);
        assert_eq!(read_theirs(b, &FRIEND, false, T0).unwrap(), face(64));

        // A newer one replaces it at once: the old row and its bytes go.
        set_mine(a, &face(128), &small(), T0 + 10).unwrap();
        let second = pass(a, T0 + 10).unwrap();
        assert_eq!(carry(a, b, &FRIEND, &second[0], 2, T0 + 11), Taken::New);
        assert!(store::get(b, &first[0].handle.unwrap()).unwrap().is_none());
        assert_eq!(read_theirs(b, &FRIEND, false, T0 + 11).unwrap(), face(128));
        assert_eq!(theirs(b, &FRIEND, T0 + 11).unwrap().seq, second[0].seq);
        // The older offer, late: dropped.
        assert_eq!(
            take_offer(b, &FRIEND, &[1u8; 16], &first[0].offer, T0 + 12).unwrap(),
            Taken::Dropped
        );
        assert_eq!(read_theirs(b, &FRIEND, false, T0 + 12).unwrap(), face(128));
        // The friend removes its picture: mine of theirs goes.
        clear_mine(a, T0 + 20).unwrap();
        let third = pass(a, T0 + 20).unwrap();
        assert_eq!(carry(a, b, &FRIEND, &third[0], 3, T0 + 21), Taken::New);
        assert!(theirs(b, &FRIEND, T0 + 21).is_none());
        assert!(matches!(
            read_theirs(b, &FRIEND, false, T0 + 21),
            Err(PictureError::NoPicture)
        ));
        assert_eq!(store::count(b), 0);
    }

    /// What a row is built from may be a moment old (an app's engine reads
    /// the files once for a list of friends): a picture replaced or removed
    /// since then reads as it is now, never as the old one without its bytes.
    #[test]
    fn a_look_from_before_a_newer_offer_reads_the_picture_as_it_is_now() {
        let Some(_live) = Live::on() else { return };
        let (theirs_home, my_home) = (profile(&[(ME, true)]), profile(&[(FRIEND, true)]));
        let (a, b) = (theirs_home.path(), my_home.path());
        speaks(a, &ME);
        set_mine(a, &face(64), &small(), T0).unwrap();
        let first = pass(a, T0).unwrap();
        assert_eq!(carry(a, b, &FRIEND, &first[0], 1, T0), Taken::New);
        let seen = |views: &Views| views.theirs(&FRIEND).map(|v| (v.seq, v.ready));
        // A look taken now, asked after the friend's newer picture came.
        let before = Views::load(b, T0 + 1);
        assert_eq!(seen(&before), Some((first[0].seq, true)));
        set_mine(a, &face(128), &small(), T0 + 10).unwrap();
        let second = pass(a, T0 + 10).unwrap();
        assert_eq!(
            take_offer(b, &FRIEND, &[2u8; 16], &second[0].offer, T0 + 11).unwrap(),
            Taken::New
        );
        // The newer one, announced: not the older one announced once more.
        assert_eq!(seen(&before), Some((second[0].seq, false)));
        // A look from before the friend removed its picture: no picture.
        let handle = second[0].handle.unwrap();
        land(b, &handle, &chunk_at(a, &handle), T0 + 11);
        let before = Views::load(b, T0 + 12);
        assert_eq!(seen(&before), Some((second[0].seq, true)));
        clear_mine(a, T0 + 20).unwrap();
        let third = pass(a, T0 + 20).unwrap();
        assert_eq!(carry(a, b, &FRIEND, &third[0], 3, T0 + 21), Taken::New);
        assert_eq!(seen(&before), None);
    }

    /// The same for my own picture: a look from before the pass that noted
    /// the friend has it, and let the offer's row go, still says so.
    #[test]
    fn a_look_from_before_the_pass_that_noted_it_says_the_friend_has_my_picture() {
        let Some(_live) = Live::on() else { return };
        let home = profile(&[(FRIEND, true)]);
        let d = home.path();
        speaks(d, &FRIEND);
        set_mine(d, &face(64), &small(), T0).unwrap();
        let made = pass(d, T0).unwrap();
        let handle = made[0].handle.unwrap();
        offer_sent(d, &FRIEND, made[0].seq, &[1u8; 16], T0).unwrap();
        delivered(d, &handle);
        let before = Views::load(d, T0 + 1);
        assert_eq!(before.reach(&FRIEND), Some(Reach::Has));
        // The pass writes what it found, then lets the row go.
        assert!(pass(d, T0 + 2).unwrap().is_empty());
        assert!(store::get(d, &handle).unwrap().is_none());
        assert_eq!(before.reach(&FRIEND), Some(Reach::Has));
        assert_eq!(before.mine().unwrap().have_it, 1);
    }

    #[test]
    fn a_picture_shows_only_for_a_friend_i_have_verified_and_goes_when_they_are_not() {
        let Some(_live) = Live::on() else { return };
        let (theirs_home, my_home) = (profile(&[(ME, true)]), profile(&[(FRIEND, false)]));
        let (a, b) = (theirs_home.path(), my_home.path());
        speaks(a, &ME);
        speaks(b, &FRIEND);
        set_mine(a, &face(64), &small(), T0).unwrap();
        let first = pass(a, T0).unwrap();
        // Not verified by me: not taken into the store.
        assert_eq!(
            take_offer(b, &FRIEND, &[1u8; 16], &first[0].offer, T0).unwrap(),
            Taken::Kept
        );
        assert!(!b.join(THEIRS_FILE).exists());
        assert_eq!(store::count(b), 0);
        assert!(matches!(
            read_theirs(b, &FRIEND, false, T0),
            Err(PictureError::NotVerified)
        ));
        // Verified: taken and shown.
        write_contacts(b, &[(FRIEND, true)]);
        assert_eq!(carry(a, b, &FRIEND, &first[0], 1, T0 + 1), Taken::New);
        assert!(theirs(b, &FRIEND, T0 + 1).unwrap().ready);
        // I also sent them mine.
        set_mine(b, &face(64), &small(), T0 + 2).unwrap();
        let mine_out = pass(b, T0 + 2).unwrap();
        assert_eq!(mine_out.len(), 1);
        // No longer verified: nothing of theirs shows, at once, and the
        // next look forgets both ways.
        write_contacts(b, &[(FRIEND, false)]);
        assert!(theirs(b, &FRIEND, T0 + 3).is_none());
        assert!(matches!(
            read_theirs(b, &FRIEND, false, T0 + 3),
            Err(PictureError::NotVerified)
        ));
        assert!(pass(b, T0 + 3).unwrap().is_empty());
        assert_eq!(store::count(b), 0, "their picture and my offer's row went");
        assert!(load::<TheirsBook>(b, THEIRS_FILE).friends.is_empty());
        assert!(load::<SentBook>(b, SENT_FILE).friends.is_empty());
        // Verified again: they are due my picture again.
        write_contacts(b, &[(FRIEND, true)]);
        assert_eq!(pass(b, T0 + 4).unwrap().len(), 1);
    }

    /// Between looks: a friend whose verification is taken back keeps no
    /// picture here, and none of mine is kept for them, with no look at
    /// what is due. A friend who stays one is not touched, nothing is
    /// written for them, and a profile with no picture files gets none.
    #[test]
    fn a_friend_who_is_one_no_longer_is_forgotten_between_looks() {
        let Some(_live) = Live::on() else { return };
        let (theirs_home, my_home) = (
            profile(&[(ME, true)]),
            profile(&[(FRIEND, true), (OTHER, true)]),
        );
        let (a, b) = (theirs_home.path(), my_home.path());
        speaks(a, &ME);
        speaks(b, &FRIEND);
        speaks(b, &OTHER);
        // No picture files yet: nothing is read and none is made.
        assert_eq!(forget_strangers(b).unwrap(), 0);
        assert!(!b.join(THEIRS_FILE).exists() && !b.join(SENT_FILE).exists());
        // The friend's picture is here, and mine is on its way to both.
        set_mine(a, &face(64), &small(), T0).unwrap();
        let first = pass(a, T0).unwrap();
        assert_eq!(carry(a, b, &FRIEND, &first[0], 1, T0 + 1), Taken::New);
        set_mine(b, &face(64), &small(), T0 + 2).unwrap();
        assert_eq!(pass(b, T0 + 2).unwrap().len(), 2);
        assert_eq!(store::count(b), 3, "theirs, and my offer for each friend");
        // Everybody is a friend: nothing goes, and no file is written.
        let written = |file: &str| std::fs::metadata(b.join(file)).unwrap().modified().unwrap();
        let before = (written(THEIRS_FILE), written(SENT_FILE));
        assert_eq!(forget_strangers(b).unwrap(), 0);
        assert_eq!((written(THEIRS_FILE), written(SENT_FILE)), before);
        assert_eq!(store::count(b), 3);
        // The verification is taken back: both ways go, the other friend's stay.
        write_contacts(b, &[(FRIEND, false), (OTHER, true)]);
        assert_eq!(forget_strangers(b).unwrap(), 1);
        assert_eq!(store::count(b), 1, "my offer for the friend who stays");
        assert!(load::<TheirsBook>(b, THEIRS_FILE).friends.is_empty());
        let sent: SentBook = load(b, SENT_FILE);
        assert_eq!(
            sent.friends.keys().collect::<Vec<_>>(),
            vec![&key_of(&OTHER)]
        );
        assert!(mine(b, T0 + 3).unwrap().set, "my own picture stays");
        assert_eq!(forget_strangers(b).unwrap(), 0, "once");
        // Blocked or removed is the same: no contact is a friend's entry.
        write_contacts(b, &[]);
        assert_eq!(forget_strangers(b).unwrap(), 1);
        assert_eq!(store::count(b), 0);
    }

    /// A contact book that does not read just now is nobody's friend for
    /// what is shown, and costs no picture: nothing is forgotten, nothing
    /// is offered, and all is as before once it reads again.
    #[test]
    fn a_contact_book_that_does_not_read_forgets_nobody() {
        let Some(_live) = Live::on() else { return };
        let (theirs_home, my_home) = (profile(&[(ME, true)]), profile(&[(FRIEND, true)]));
        let (a, b) = (theirs_home.path(), my_home.path());
        speaks(a, &ME);
        speaks(b, &FRIEND);
        set_mine(a, &face(64), &small(), T0).unwrap();
        let first = pass(a, T0).unwrap();
        assert_eq!(carry(a, b, &FRIEND, &first[0], 1, T0 + 1), Taken::New);
        set_mine(b, &face(64), &small(), T0 + 2).unwrap();
        assert_eq!(pass(b, T0 + 2).unwrap().len(), 1);
        let books = || {
            (
                load::<TheirsBook>(b, THEIRS_FILE),
                load::<SentBook>(b, SENT_FILE),
                store::count(b),
            )
        };
        let before = books();
        std::fs::write(b.join("contacts.json"), "[{ not a contact book").unwrap();
        assert!(theirs(b, &FRIEND, T0 + 3).is_none(), "nothing shows");
        assert_eq!(forget_strangers(b).unwrap(), 0);
        assert!(pass(b, T0 + 3).unwrap().is_empty());
        assert_eq!(books(), before);
        write_contacts(b, &[(FRIEND, true)]);
        assert!(theirs(b, &FRIEND, T0 + 4).unwrap().ready);
        assert!(pass(b, T0 + 4).unwrap().is_empty(), "nobody is due again");
        assert_eq!(books(), before);
    }

    #[test]
    fn a_friend_that_lost_my_picture_gets_it_again_once_a_day() {
        let Some(_live) = Live::on() else { return };
        let (theirs_home, my_home) = (profile(&[(ME, true)]), profile(&[(FRIEND, true)]));
        let (a, b) = (theirs_home.path(), my_home.path());
        speaks(a, &ME);
        speaks(b, &FRIEND);
        // Mine reached the friend.
        set_mine(b, &face(64), &small(), T0).unwrap();
        let mine_out = pass(b, T0).unwrap();
        delivered(b, &mine_out[0].handle.unwrap());
        assert!(pass(b, T0 + 1).unwrap().is_empty());
        // The friend's offer says it holds mine: nothing to repair.
        set_mine(a, &face(64), &small(), T0 + 2).unwrap();
        edit(a, THEIRS_FILE, |book: &mut TheirsBook| {
            book.friends.insert(
                key_of(&ME),
                Theirs {
                    seq: mine_out[0].seq,
                    ..Theirs::default()
                },
            );
        })
        .unwrap();
        let knows = pass(a, T0 + 2).unwrap();
        assert_eq!(carry(a, b, &FRIEND, &knows[0], 1, T0 + 3), Taken::New);
        assert!(pass(b, T0 + 4).unwrap().is_empty());
        // The friend lost its store: its next offer holds nothing of mine.
        edit(a, THEIRS_FILE, |book: &mut TheirsBook| book.friends.clear()).unwrap();
        set_mine(a, &face(128), &small(), T0 + 5).unwrap();
        let lost = pass(a, T0 + 5).unwrap();
        assert_eq!(carry(a, b, &FRIEND, &lost[0], 2, T0 + 6), Taken::New);
        let again = pass(b, T0 + 7).unwrap();
        assert_eq!(again.len(), 1, "mine goes again");
        assert!(again[0].seq > mine_out[0].seq);
        // That word is answered: it asks for nothing more, today or later.
        delivered(b, &again[0].handle.unwrap());
        assert!(pass(b, T0 + 8).unwrap().is_empty());
        assert!(pass(b, T0 + DAY).unwrap().is_empty());
        // The same day, the friend says once more that it holds nothing
        // (a newer offer of theirs): once a day is enough.
        let lost_again = |at: u64, mid: u8| {
            edit(a, THEIRS_FILE, |book: &mut TheirsBook| book.friends.clear()).unwrap();
            edit(a, SENT_FILE, |book: &mut SentBook| {
                book.friends.get_mut(&key_of(&ME)).unwrap().choice = 0;
            })
            .unwrap();
            let offer = pass(a, at).unwrap();
            assert_eq!(carry(a, b, &FRIEND, &offer[0], mid, at + 1), Taken::New);
        };
        lost_again(T0 + 20, 3);
        assert!(pass(b, T0 + 22).unwrap().is_empty(), "once a day");
        // The next day it says so again: mine goes again.
        lost_again(T0 + DAY + 20, 4);
        assert_eq!(pass(b, T0 + DAY + 22).unwrap().len(), 1);
    }

    #[test]
    fn what_a_friend_held_before_my_newest_was_made_asks_for_nothing() {
        let Some(_live) = Live::on() else { return };
        let (theirs_home, my_home) = (profile(&[(ME, true)]), profile(&[(FRIEND, true)]));
        let (a, b) = (theirs_home.path(), my_home.path());
        speaks(a, &ME);
        speaks(b, &FRIEND);
        // My first picture reached the friend, and the friend's offer, made
        // then, says it holds that one.
        set_mine(b, &face(64), &small(), T0).unwrap();
        let first = pass(b, T0).unwrap();
        assert_eq!(carry(b, a, &ME, &first[0], 1, T0 + 1), Taken::New);
        delivered(b, &first[0].handle.unwrap());
        set_mine(a, &face(64), &small(), T0 + 2).unwrap();
        let theirs_offer = pass(a, T0 + 2).unwrap();
        assert_eq!(
            carry(a, b, &FRIEND, &theirs_offer[0], 2, T0 + 3),
            Taken::New
        );
        assert!(pass(b, T0 + 4).unwrap().is_empty());
        // I change mine. The friend has the new one; its offer, which I
        // still hold, names the older one: it was made before.
        set_mine(b, &face(128), &small(), T0 + 10).unwrap();
        let second = pass(b, T0 + 10).unwrap();
        assert_eq!(carry(b, a, &ME, &second[0], 3, T0 + 11), Taken::New);
        delivered(b, &second[0].handle.unwrap());
        assert!(
            pass(b, T0 + 12).unwrap().is_empty(),
            "nothing is sent twice"
        );
        assert!(pass(b, T0 + DAY).unwrap().is_empty());
        assert_eq!(reach(b, &FRIEND), Some(Reach::Has));
    }

    #[test]
    fn a_picture_that_fails_its_check_goes_and_three_a_day_close_the_door() {
        let Some(_live) = Live::on() else { return };
        let home = profile(&[(FRIEND, true)]);
        let d = home.path();
        // A friend's node that seals something that is not a picture.
        let bad = |seq: u64, mid: u8, bytes: &[u8], preview: &[u8]| {
            let key = Key::random();
            let sealed = blob::seal_one_chunk(&key, bytes).unwrap();
            let blob = BlobRef {
                shape: sealed.shape,
                key,
                root: sealed.root(),
            };
            let offer = Offer::profile(blob, seq, 0, 64, preview).unwrap();
            let text = offer.encode().unwrap();
            assert_eq!(
                take_offer(d, &FRIEND, &[mid; 16], &text, T0).unwrap(),
                Taken::New
            );
            land(d, &offer.handle, sealed.chunk(0).unwrap(), T0);
            offer.handle
        };
        // A GIF's bytes under a good preview.
        let handle = bad(1, 1, b"GIF89a not a picture at all", &small());
        assert!(theirs(d, &FRIEND, T0).unwrap().ready);
        assert!(matches!(
            read_theirs(d, &FRIEND, false, T0),
            Err(PictureError::Bad(_))
        ));
        assert!(theirs(d, &FRIEND, T0).is_none(), "it went");
        assert!(store::get(d, &handle).unwrap().is_none());
        // A side that is not the offer's; a preview that is not a JPEG.
        bad(2, 2, &face(128), &small());
        assert!(matches!(
            read_theirs(d, &FRIEND, false, T0),
            Err(PictureError::Bad(_))
        ));
        bad(3, 3, &face(64), b"junk");
        assert!(matches!(
            read_theirs(d, &FRIEND, true, T0),
            Err(PictureError::Bad(_))
        ));
        // Three today: a good one is not opened until tomorrow.
        bad(4, 4, &face(64), &small());
        assert!(theirs(d, &FRIEND, T0).is_none());
        assert!(matches!(
            read_theirs(d, &FRIEND, false, T0),
            Err(PictureError::NoPicture)
        ));
        assert!(theirs(d, &FRIEND, T0 + DAY).unwrap().ready);
        assert_eq!(read_theirs(d, &FRIEND, false, T0 + DAY).unwrap(), face(64));
    }

    #[test]
    fn a_pictures_row_stays_when_its_chat_is_cleared_and_goes_when_nothing_names_it() {
        let Some(_live) = Live::on() else { return };
        let (theirs_home, my_home) = (profile(&[(ME, true)]), profile(&[(FRIEND, true)]));
        let (a, b) = (theirs_home.path(), my_home.path());
        speaks(a, &ME);
        set_mine(a, &face(64), &small(), T0).unwrap();
        let first = pass(a, T0).unwrap();
        assert_eq!(carry(a, b, &FRIEND, &first[0], 1, T0), Taken::New);
        let handle = first[0].handle.unwrap();
        // Clearing the chat with that friend, and a sweep long after, leave
        // the picture alone: no message row holds it, and none has to.
        assert_eq!(
            crate::attachment::sweep::forget_peer(b, &FRIEND).unwrap(),
            0
        );
        let late = T0 + 30 * DAY;
        crate::attachment::sweep::sweep(b, late).unwrap();
        assert!(theirs(b, &FRIEND, late).unwrap().ready);
        assert_eq!(read_theirs(b, &FRIEND, false, late).unwrap(), face(64));
        // The same for the offer's row on the sender.
        crate::attachment::sweep::sweep(a, late).unwrap();
        assert!(store::get(a, &handle).unwrap().is_some());
        assert!(handles(a).contains(&handle) && handles(b).contains(&handle));
        // A picture's row that no file names goes with the sweep.
        edit(b, THEIRS_FILE, |book: &mut TheirsBook| book.friends.clear()).unwrap();
        let swept = crate::attachment::sweep::sweep(b, late).unwrap();
        assert_eq!(swept.attachments, 1);
        assert!(store::get(b, &handle).unwrap().is_none());
    }

    #[test]
    fn the_receive_path_hands_a_verified_friends_offer_to_the_picture_files() {
        let Some(_live) = Live::on() else { return };
        let (theirs_home, my_home) = (profile(&[(ME, true)]), profile(&[(FRIEND, false)]));
        let (a, b) = (theirs_home.path(), my_home.path());
        speaks(a, &ME);
        set_mine(a, &face(64), &small(), T0).unwrap();
        let first = pass(a, T0).unwrap();
        let comes = |mid: u8, send: &ToSend| {
            crate::lan_dispatch::persist_profile_offer(
                b,
                &FRIEND,
                &[mid; 16],
                T0,
                send.seq,
                send.offer.as_bytes(),
            )
            .unwrap();
        };
        let hidden_rows = || {
            crate::chat_history::ChatHistory::load(b)
                .unwrap()
                .entries
                .len()
        };
        // Not verified by me: kept as a build without pictures keeps it, in
        // a row no reader shows. Nothing reaches the picture files.
        comes(1, &first[0]);
        assert_eq!(hidden_rows(), 1);
        assert!(theirs(b, &FRIEND, T0).is_none());
        assert_eq!(store::count(b), 0);
        assert_eq!(adopt_kept(b, T0), 0, "still not verified");
        assert_eq!(hidden_rows(), 1);
        // The words match: the next look takes it up, and the row goes.
        write_contacts(b, &[(FRIEND, true)]);
        assert_eq!(adopt_kept(b, T0 + 1), 1);
        assert_eq!(hidden_rows(), 0);
        let seen = theirs(b, &FRIEND, T0 + 1).unwrap();
        assert_eq!((seen.seq, seen.ready), (first[0].seq, false));
        // From now on an offer goes straight to the picture files.
        set_mine(a, &face(128), &small(), T0 + 5).unwrap();
        let second = pass(a, T0 + 5).unwrap();
        comes(2, &second[0]);
        assert_eq!(hidden_rows(), 0);
        assert_eq!(theirs(b, &FRIEND, T0 + 6).unwrap().seq, second[0].seq);
        assert_eq!(store::count(b), 1, "the older picture's row went");
    }

    #[test]
    fn an_offer_of_mine_is_kept_in_the_history_without_its_key_in_a_row_nobody_sees() {
        let Some(_live) = Live::on() else { return };
        let home = profile(&[(FRIEND, true)]);
        let d = home.path();
        speaks(d, &FRIEND);
        set_mine(d, &face(64), &small(), T0).unwrap();
        let made = pass(d, T0).unwrap();
        let handle = made[0].handle.unwrap();
        let key = hex::encode(
            store::get(d, &handle)
                .unwrap()
                .unwrap()
                .key()
                .unwrap()
                .bytes(),
        );
        assert!(made[0].offer.contains(&key));
        let (body, words) =
            flow::history_body(d, "out", &FRIEND, &[1u8; 16], "queued", &made[0].offer, T0)
                .unwrap()
                .unwrap();
        assert!(body.starts_with("RVNATT/1 ref\n"));
        assert!(!body.contains(&key), "the stored form holds no key");
        assert_eq!(words, "");
        assert!(crate::attachment::shown::is_hidden_body(&body));
        // A friend's profile offer is not a chat row of the history write.
        assert!(
            flow::history_body(d, "in", &FRIEND, &[2u8; 16], "received", &made[0].offer, T0)
                .unwrap()
                .is_none()
        );
        // Its delivery moves the row on: the exchange may push the chunk.
        flow::history_body(
            d,
            "out",
            &FRIEND,
            &[1u8; 16],
            "delivered",
            &made[0].offer,
            T0,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            store::get(d, &handle).unwrap().unwrap().state,
            State::Offered
        );
        // The empty form too is stored and hidden.
        clear_mine(d, T0 + 1).unwrap();
        let none = pass(d, T0 + 1).unwrap();
        let (body, _) = flow::history_body(
            d,
            "out",
            &FRIEND,
            &[3u8; 16],
            "queued",
            &none[0].offer,
            T0 + 1,
        )
        .unwrap()
        .unwrap();
        assert!(crate::attachment::shown::is_hidden_body(&body));
    }

    #[test]
    fn nine_offers_a_day_from_one_friend_are_one_too_many() {
        let Some(_live) = Live::on() else { return };
        let home = profile(&[(FRIEND, true)]);
        let d = home.path();
        let empty = |seq: u64| {
            Offer::no_profile([seq as u8; HANDLE_LEN], seq, 0)
                .unwrap()
                .encode()
                .unwrap()
        };
        for seq in 1..=u64::from(TAKEN_A_DAY) {
            assert_eq!(
                take_offer(d, &FRIEND, &[seq as u8; 16], &empty(seq), T0).unwrap(),
                Taken::New,
                "{seq}"
            );
        }
        assert_eq!(
            take_offer(d, &FRIEND, &[20u8; 16], &empty(20), T0).unwrap(),
            Taken::Dropped
        );
        assert_eq!(
            take_offer(d, &FRIEND, &[21u8; 16], &empty(21), T0 + DAY).unwrap(),
            Taken::New
        );
        // What is not a profile offer is not this module's.
        assert_eq!(
            take_offer(d, &FRIEND, &[22u8; 16], "RVNATT/1 offer\n{}", T0).unwrap(),
            Taken::Dropped
        );
        assert_eq!(
            take_offer(
                d,
                &FRIEND,
                &[23u8; 16],
                &crate::attachment::testing::photo_offer(),
                T0
            )
            .unwrap(),
            Taken::Dropped
        );
    }
}
