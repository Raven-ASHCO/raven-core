//! The group store, `groups.json` (design §6): every group's roster,
//! status, messages with their delivery lines, ids seen, held frames and
//! intents, in one file. At-rest kind [`Kind::Groups`]: RMS1 in a sealed
//! profile, plain JSON before, always written under its writer lock
//! ([`GROUPS_LOCK`]). The lock is a leaf: nothing else is taken while it is
//! held (callers read the contact book and park copies outside it).
//!
//! The file never grows past [`STORE_BUDGET_BYTES`], half the at-rest read
//! cap: every part has a bound in bytes or keys ([`GroupsFile::enforce_caps`]),
//! and a write that would pass the budget anyway sheds held frames, done
//! markers and intents first, else is refused ([`edit`], [`edit_received`]).
//! A store an older build let grow past the read cap is repaired once when
//! it is next read ([`load`], [`edit`]).

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::wire::{hex_n, MemberWire, StateWire};
use super::{GroupError, GroupId, GroupState, Key};
use crate::at_rest::{self, Kind};

/// The store's file name in the data dir.
pub const GROUPS_FILE: &str = "groups.json";
/// Its writer lock (`at_rest::FILES` names it).
pub const GROUPS_LOCK: &str = ".at_rest.groups.lock.sqlite";

/// The most the store may take when written, sealed (its JSON plus
/// [`at_rest::SEALED_OVERHEAD`]): half the at-rest read cap
/// ([`at_rest::MAX_SEALED_FILE_BYTES`]), so the store always reads back and
/// a key rotation can always seal it again. The bounds below together stay
/// under it; a write that would pass it anyway sheds held frames, done
/// markers and intents first, and is refused when that is not enough.
pub const STORE_BUDGET_BYTES: u64 = 32 * 1024 * 1024;
/// The layout written: 3 keeps seen keys compactly, each with a tag of its
/// author ([`SeenKeys`]); a store of layout 1 or 2 is read and converted.
pub const STORE_VERSION: u32 = 3;
/// A store over the read cap (only an older build could write one) is read
/// once with this cap and repaired ([`load`]).
const REPAIR_READ_CAP: u64 = 2 * at_rest::MAX_SEALED_FILE_BYTES;

/// Groups kept here, active, left or removed (a forgotten one holds no
/// place): an invitation past it is refused (not ACKed, so it comes
/// again), and so is a new group of this profile ([`GroupError::TooManyGroups`]).
/// [`forget`] frees a place.
pub const MAX_GROUPS: usize = 64;
/// Groups of one admin kept here, active, left or removed (a forgotten one
/// does not count, as for [`MAX_GROUPS`]): its next invitation (or a roster
/// that names this profile again in one of its forgotten groups) is
/// refused, not ACKed, until one of them is forgotten. A group left or
/// removed keeps counting, so one friend cannot take every place by
/// inviting and removing again; a roster that makes such a group active
/// again takes nothing new. Other admins' invitations are not affected.
pub const MAX_GROUPS_PER_ADMIN: usize = 8;
/// Forgotten groups kept ([`forget`]): their ids, epochs and seen keys, so
/// their old frames do not bring them back. Over it, the one forgotten
/// first goes for good.
pub const MAX_FORGOTTEN: usize = 64;
/// Seen keys the forgotten groups keep in all (8 groups' worth): over it,
/// the group forgotten first loses its keys first.
pub const MAX_FORGOTTEN_SEEN: usize = 8 * MAX_SEEN_PER_GROUP;
pub const MAX_MESSAGES_TOTAL: usize = 2_000;
/// Messages kept across groups, by the bytes they take in the store
/// ([`StoredMsg::stored_bytes`]). Over this or [`MAX_MESSAGES_TOTAL`], the
/// admin whose groups hold the most (every group of one admin together;
/// by count while over the count, else by bytes) loses the oldest message of
/// its group holding the most.
pub const MAX_MESSAGE_BYTES_TOTAL: usize = 8 * 1024 * 1024;
/// Message keys kept per group after their messages left `messages`
/// ([`GroupRecord::seen`]): each until its message is older than
/// [`REPLAY_HORIZON_MS`]. Every member's share ([`GroupRecord::share`])
/// fits; over it, the keys of authors who are no member go first (this
/// profile's own, former members'), so a message a member could still
/// replay is not forgotten ([`SeenKeys::trim_to`]).
pub const MAX_SEEN_PER_GROUP: usize = 8_192;
/// The least share of one author in a group's room for message keys
/// ([`GroupRecord::share`]: the room over the roster's members, at least
/// this; 512 in a group of 16, 4,096 in a group of two). An author's share
/// holds its messages kept here and its keys seen, each until its message
/// is older than [`REPLAY_HORIZON_MS`]. An author at its share has its
/// next message refused when it carried it itself (not stored and not
/// ACKed, so it sends it again later) and dropped when another member
/// forwarded it, until some of its keys expire; every other author's
/// messages are still taken. This profile sends no message past its own
/// share ([`GroupError::ShareFull`]), so no copy of its own waits refused
/// in its queue for a friend.
pub const MAX_SEEN_PER_AUTHOR: usize = 512;
const _: () = assert!(MAX_SEEN_PER_AUTHOR * super::MAX_GROUP_MEMBERS <= MAX_SEEN_PER_GROUP);
/// A message whose `sent_ms` is older than this is refused (an old signed
/// message replayed after its id was forgotten is not taken as new); the
/// message horizon (7 days).
pub const REPLAY_HORIZON_MS: u64 = crate::horizon::MESSAGE_HORIZON_MS;
/// How far in this computer's future a message's `sent_ms` may be (clocks
/// differ); later is refused.
pub const MAX_FUTURE_SKEW_MS: u64 = 24 * 3_600_000;
pub const MAX_HELD_PER_GROUP: usize = 64;
pub const MAX_UNKNOWN_HELD: usize = 32;
/// Held frames by the bytes they take in the store: per group, for groups
/// not known yet, and in all. Over a bound, the carrier (the friend that
/// brought them) holding the most loses its oldest frame first, so one
/// carrier's frames never push out another's.
pub const MAX_HELD_BYTES_PER_GROUP: usize = 256 * 1024;
pub const MAX_UNKNOWN_HELD_BYTES: usize = 256 * 1024;
pub const MAX_HELD_BYTES_TOTAL: usize = 1024 * 1024;
pub const MAX_INTENTS_PER_GROUP: usize = 512;
/// Intents across groups, by the bytes they take in the store. Over it, the
/// admin whose groups hold the most loses first: forwards (and receipts
/// passed on) first, then the oldest (a copy of an own message that goes
/// fails its line).
pub const MAX_INTENT_BYTES_TOTAL: usize = 4 * 1024 * 1024;
/// Forwards of one author's messages that may wait per group, receipts
/// that member signed and this profile passes on counted with them (one
/// member's forward requests and receipts cannot evict every other pending
/// intent): 15 authors at most use under half of [`MAX_INTENTS_PER_GROUP`].
pub const MAX_FORWARDS_PER_AUTHOR: usize = 16;
pub const MAX_DONE_PER_GROUP: usize = 4_096;
/// Done markers across groups, by bytes: over it, the admin whose groups
/// hold the most loses its oldest markers first.
pub const MAX_DONE_BYTES_TOTAL: usize = 2 * 1024 * 1024;
pub const MAX_COPIES: usize = 8_192;
/// Held frames and intents end after the message horizon.
pub const WORK_TTL_MS: u64 = crate::horizon::MESSAGE_HORIZON_MS;

pub const STATUS_ACTIVE: &str = "active";
pub const STATUS_REMOVED: &str = "removed";
pub const STATUS_LEFT: &str = "left";
/// Forgotten on this device ([`forget`]): in no list and no operation,
/// holding no place; what tells its frames apart stays (its id, admin,
/// epoch, seen keys). Like a group left, a roster naming this profile after
/// one that did not is a new invitation.
pub const STATUS_FORGOTTEN: &str = "forgotten";
/// The name a forgotten group's roster keeps (its own goes).
const FORGOTTEN_NAME: &str = "forgotten";

pub const LINE_WAITING: &str = "waiting";
pub const LINE_SENT: &str = "sent";
pub const LINE_DELIVERED: &str = "delivered";
pub const LINE_FAILED: &str = "failed";

pub const VIA_DIRECT: &str = "direct";
pub const VIA_RELAY: &str = "relay";

pub const INTENT_SEND: &str = "send";
pub const INTENT_RECEIPT: &str = "receipt";
pub const INTENT_LEAVER: &str = "leaver";
/// A leave of this profile to make again: it left, and a newer roster that
/// still names it came before the admin took the leave (the admin drops a
/// leave of an older epoch, protocol §4.2). The receive path has no
/// identity key, so the leave is signed for the roster held when the
/// intents are processed ([`super::process_intents`]), and only while
/// [`GroupRecord::leave_unanswered`]. An older build drops it unread.
pub const INTENT_LEAVE: &str = "leave";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupsFile {
    pub v: u32,
    /// This profile's identity key (hex), noted by every writer that knows it.
    #[serde(default)]
    pub me: String,
    #[serde(default)]
    pub groups: Vec<GroupRecord>,
    /// Frames for groups not known yet (the roster may come later).
    #[serde(default)]
    pub unknown_held: Vec<Held>,
    /// Message ids of the copies this profile parked (newest last): a late
    /// delivery change of one whose history row is gone is no error.
    #[serde(default)]
    pub copies: Vec<String>,
    /// Frames dropped as invalid (a bad signature, a stranger), counted.
    #[serde(default)]
    pub dropped: u64,
    /// Rosters of an epoch already held with other content (an admin
    /// conflict), counted and ignored.
    #[serde(default)]
    pub conflicts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupRecord {
    pub id: String,
    pub state: StateWire,
    pub status: String,
    /// After a leave: a roster without this profile came (so a later one
    /// with it is a new invitation).
    #[serde(default)]
    pub left_seen_out: bool,
    pub joined_ms: u64,
    pub updated_ms: u64,
    /// Members who left the roster (hex keys): their messages are dropped.
    #[serde(default)]
    pub removed: Vec<String>,
    #[serde(default)]
    pub messages: Vec<StoredMsg>,
    /// Keys of messages that left `messages` (duplicate drop), compact.
    #[serde(default)]
    pub seen: SeenKeys,
    #[serde(default)]
    pub held: Vec<Held>,
    #[serde(default)]
    pub intents: Vec<Intent>,
    /// Forwards and relayed receipts made (`<author>/<id>:<target>`,
    /// `r:<author>/<id>:<signer>`, keys in hex): a receipt is passed on
    /// only for a forward made to its signer.
    #[serde(default)]
    pub done: Vec<String>,
    /// Messages received after this are unread.
    #[serde(default)]
    pub read_ms: u64,
    /// The last `sync` this profile sent for the group.
    #[serde(default)]
    pub sync_ms: u64,
    /// The admin's last answer to each member's `sync`.
    #[serde(default)]
    pub answered: Vec<Answered>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoredMsg {
    pub id: String,
    pub from: String,
    pub epoch: u32,
    pub sent_ms: u64,
    pub received_ms: u64,
    pub body: String,
    pub sig: String,
    #[serde(default)]
    pub mine: bool,
    /// The carrier peer when it was not the author (a forwarded copy).
    #[serde(default)]
    pub via: String,
    /// Mine only: one line per member the message was for.
    #[serde(default)]
    pub lines: Vec<Line>,
    /// How the copy that brought it came (`crate::arrivals::ArrivedVia`'s
    /// token: `lan`, `tor`, `keeper`, ...; E2 r9 #15); empty for yours and
    /// when not known. Not written while empty, so a store without a path
    /// reads as before.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Line {
    pub member: String,
    /// The device the copy was parked for, and the copy's message id
    /// (direct lines, once parked).
    #[serde(default)]
    pub device: String,
    #[serde(default)]
    pub copy: String,
    pub via: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Held {
    pub frame: String,
    pub peer: String,
    pub at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub id: String,
    pub kind: String,
    /// The member the copy goes to (send), the author (receipt), the member
    /// who left (leaver) or the admin (leave).
    pub to: String,
    #[serde(default)]
    pub frame: String,
    /// A receipt's message id.
    #[serde(default)]
    pub of: String,
    /// A receipt goes to this carrier peer (the forwarder).
    #[serde(default)]
    pub via: String,
    /// A copy of this profile's own message `line_of`: its line for `to`
    /// gets the copy's id once parked.
    #[serde(default)]
    pub line_of: String,
    pub made_ms: u64,
    #[serde(default)]
    pub tries: u32,
    /// A forward's author, or the signer of a receipt passed on (hex): they
    /// are counted per key ([`MAX_FORWARDS_PER_AUTHOR`]) and are the first
    /// to go when the intents are over their cap. Empty for every other
    /// intent.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub author: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Answered {
    pub key: String,
    pub at_ms: u64,
}

pub fn groups_path(data_dir: &Path) -> PathBuf {
    data_dir.join(GROUPS_FILE)
}

fn store_err(e: impl std::fmt::Display) -> GroupError {
    GroupError::Store(e.to_string())
}

fn full_err() -> GroupError {
    GroupError::Store(format!("{GROUPS_FILE} is full"))
}

/// The store as it is (empty without a file). Never written, except once to
/// repair a store an older build let grow past the read cap.
pub fn load(data_dir: &Path) -> Result<GroupsFile, GroupError> {
    let path = groups_path(data_dir);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() => {
            if meta.len() > at_rest::MAX_SEALED_FILE_BYTES {
                return repair(data_dir);
            }
        }
        Ok(_) => {
            return Err(GroupError::Store(format!(
                "{GROUPS_FILE} is not a regular file"
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(GroupsFile::default()),
        Err(e) => return Err(store_err(e)),
    }
    let file = at_rest::load_json::<GroupsFile>(data_dir, &path, Kind::Groups)
        .map_err(store_err)?
        .unwrap_or_default();
    Ok(file)
}

/// What a change does that leaves the store over its budget even after
/// held frames, done markers and intents were shed.
enum WhenFull<T> {
    /// A local operation is refused ([`GroupError::Store`]).
    Refuse,
    /// A received frame is dropped (counted in `dropped`) with this answer,
    /// so it is ACKed and not sent again for ever.
    Drop(T),
}

/// Read, change and write the store under its writer lock. A store that
/// cannot be read is never written over. A change that leaves the store
/// over [`STORE_BUDGET_BYTES`] after shedding held frames, done markers and
/// intents is refused ([`GroupError::Store`]).
pub fn edit<T>(
    data_dir: &Path,
    change: impl FnOnce(&mut GroupsFile) -> Result<T, GroupError>,
) -> Result<T, GroupError> {
    edit_with(data_dir, WhenFull::Refuse, change)
}

/// [`edit`] for a received frame: when the store has no room for the
/// change, the frame is dropped instead (counted in `dropped`) and
/// `dropped_answer` returned, so the frame is ACKed rather than sent again
/// until its horizon.
pub fn edit_received<T>(
    data_dir: &Path,
    dropped_answer: T,
    change: impl FnOnce(&mut GroupsFile) -> Result<T, GroupError>,
) -> Result<T, GroupError> {
    edit_with(data_dir, WhenFull::Drop(dropped_answer), change)
}

fn edit_with<T>(
    data_dir: &Path,
    when_full: WhenFull<T>,
    change: impl FnOnce(&mut GroupsFile) -> Result<T, GroupError>,
) -> Result<T, GroupError> {
    let path = groups_path(data_dir);
    let lock = at_rest::lock_file(data_dir, &path, Kind::Groups).map_err(store_err)?;
    let (mut file, repaired) = read_locked(data_dir, &lock, &path)?;
    let before = file.clone();
    let write = |file: &mut GroupsFile| -> Result<(), GroupError> {
        let bytes = fitted(file, repaired)?.ok_or_else(full_err)?;
        lock.store_bytes(&bytes).map_err(store_err)
    };
    let out = match change(&mut file) {
        Ok(out) => out,
        Err(e) => {
            if repaired {
                write(&mut before.clone())?;
            }
            return Err(e);
        }
    };
    if file == before && !repaired {
        return Ok(out);
    }
    if let Some(bytes) = fitted(&mut file, repaired)? {
        lock.store_bytes(&bytes).map_err(store_err)?;
        return Ok(out);
    }
    match when_full {
        WhenFull::Refuse => {
            if repaired {
                write(&mut before.clone())?;
            }
            Err(full_err())
        }
        WhenFull::Drop(answer) => {
            // The frame is dropped in any case; it is counted when the
            // store as it was has room for the count.
            let mut kept = before;
            kept.dropped = kept.dropped.saturating_add(1);
            if let Some(bytes) = fitted(&mut kept, repaired)? {
                lock.store_bytes(&bytes).map_err(store_err)?;
            }
            Ok(answer)
        }
    }
}

/// [`load`] of a store over the read cap: repaired under its writer lock
/// and written back within the budget.
fn repair(data_dir: &Path) -> Result<GroupsFile, GroupError> {
    let path = groups_path(data_dir);
    let lock = at_rest::lock_file(data_dir, &path, Kind::Groups).map_err(store_err)?;
    let (mut file, repaired) = read_locked(data_dir, &lock, &path)?;
    if repaired {
        let bytes = fitted(&mut file, true)?.ok_or_else(full_err)?;
        lock.store_bytes(&bytes).map_err(store_err)?;
    }
    Ok(file)
}

/// The store, read under its writer lock, and whether it must be written
/// even without a change: one over the read cap (only an older build could
/// write it) is read once with [`REPAIR_READ_CAP`], and writing it back
/// repairs it ([`fitted`]: its bounds, then the budget). A store of the
/// older layout is converted as it is read.
fn read_locked(
    data_dir: &Path,
    lock: &at_rest::FileLock,
    path: &Path,
) -> Result<(GroupsFile, bool), GroupError> {
    #[cfg(test)]
    READS_FOR_TESTS.with(|n| n.set(n.get() + 1));
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => {
            if meta.len() > at_rest::MAX_SEALED_FILE_BYTES {
                return Ok((read_oversize(data_dir, path)?, true));
            }
            let file = lock
                .load_json::<GroupsFile>()
                .map_err(store_err)?
                .unwrap_or_default();
            Ok((file, false))
        }
        Ok(_) => Err(GroupError::Store(format!(
            "{GROUPS_FILE} is not a regular file"
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((GroupsFile::default(), false)),
        Err(e) => Err(store_err(e)),
    }
}

/// A store over the read cap, read with [`REPAIR_READ_CAP`]: RMS1 opened
/// with the loaded keys, plain JSON as it is.
fn read_oversize(data_dir: &Path, path: &Path) -> Result<GroupsFile, GroupError> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(store_err)?;
    let mut raw = Zeroizing::new(Vec::new());
    file.take(REPAIR_READ_CAP + 1)
        .read_to_end(&mut raw)
        .map_err(store_err)?;
    if raw.len() as u64 > REPAIR_READ_CAP {
        return Err(GroupError::Store(format!(
            "{GROUPS_FILE} is too large to repair"
        )));
    }
    let plain = if at_rest::is_sealed_as(Kind::Groups, &raw) {
        let keys = at_rest::keys_cached(data_dir).map_err(store_err)?;
        at_rest::open(&keys, Kind::Groups, &raw).map_err(store_err)?
    } else {
        raw
    };
    serde_json::from_slice(&plain)
        .map_err(|e| GroupError::Store(format!("{GROUPS_FILE} corrupt: {e}")))
}

/// The store's bytes as written: its bounds applied, then, while it is over
/// the budget sealed, held frames, done markers and intents shed (and, when
/// `repairing`, the oldest messages, whose keys stay seen). `None` when it
/// still does not fit.
fn fitted(
    file: &mut GroupsFile,
    repairing: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>, GroupError> {
    file.v = STORE_VERSION;
    file.enforce_caps();
    let budget = store_budget();
    loop {
        let bytes = Zeroizing::new(serde_json::to_vec_pretty(file).map_err(store_err)?);
        let sealed = bytes.len() as u64 + at_rest::SEALED_OVERHEAD;
        if sealed <= budget {
            return Ok(Some(bytes));
        }
        let over = usize::try_from(sealed - budget).unwrap_or(usize::MAX);
        let mut shed = file.shed_work(over);
        if shed < over && repairing {
            shed += file.shed_history(over - shed);
        }
        if shed == 0 {
            return Ok(None);
        }
    }
}

#[cfg(test)]
thread_local! {
    static BUDGET_FOR_TESTS: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    static READS_FOR_TESTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How often this thread read the store to change it (the group tests count
/// the reads an ingest makes).
#[cfg(test)]
pub(crate) fn reads_for_tests() -> usize {
    READS_FOR_TESTS.with(std::cell::Cell::get)
}

/// The group tests lower the budget on their thread (`None`: the real one).
#[cfg(test)]
pub(crate) fn set_budget_for_tests(budget: Option<u64>) {
    BUDGET_FOR_TESTS.with(|b| b.set(budget));
}

fn store_budget() -> u64 {
    #[cfg(test)]
    if let Some(budget) = BUDGET_FOR_TESTS.with(std::cell::Cell::get) {
        return budget;
    }
    STORE_BUDGET_BYTES
}

pub(crate) fn hex_key(s: &str) -> Option<Key> {
    hex_n::<32>(s)
}

impl GroupsFile {
    pub fn note_me(&mut self, me: &Key) {
        let hex = hex::encode(me);
        if self.me != hex {
            self.me = hex;
        }
    }

    pub fn group(&self, id: &GroupId) -> Option<&GroupRecord> {
        let hex = hex::encode(id);
        self.groups.iter().find(|g| g.id == hex)
    }

    pub fn group_mut(&mut self, id: &GroupId) -> Option<&mut GroupRecord> {
        let hex = hex::encode(id);
        self.groups.iter_mut().find(|g| g.id == hex)
    }

    /// Group `id` as this profile's own operations and views see it: a
    /// forgotten group is not there (the receive rules still see it).
    pub fn shown(&self, id: &GroupId) -> Option<&GroupRecord> {
        self.group(id).filter(|g| !g.is_forgotten())
    }

    /// [`GroupsFile::shown`], to change.
    pub fn shown_mut(&mut self, id: &GroupId) -> Option<&mut GroupRecord> {
        self.group_mut(id).filter(|g| !g.is_forgotten())
    }

    /// The places taken ([`MAX_GROUPS`]): every group but the forgotten.
    pub fn places_used(&self) -> usize {
        self.groups.iter().filter(|g| !g.is_forgotten()).count()
    }

    /// The groups of `admin` kept here, active, left or removed (a
    /// forgotten one does not count): [`MAX_GROUPS_PER_ADMIN`].
    pub fn records_of(&self, admin: &Key) -> usize {
        let hex = hex::encode(admin);
        self.groups
            .iter()
            .filter(|g| !g.is_forgotten() && g.state.admin == hex)
            .count()
    }

    /// [`forget`] on the file.
    pub fn forget(&mut self, id: &GroupId, now_ms: u64) -> Result<(), GroupError> {
        let g = self.shown_mut(id).ok_or(GroupError::NotFound)?;
        if !g.can_forget() {
            return Err(GroupError::StillMember);
        }
        g.forget(now_ms);
        Ok(())
    }

    /// A copy parked by this profile.
    pub fn note_copy(&mut self, mid: &str) {
        self.copies.push(mid.to_owned());
        if self.copies.len() > MAX_COPIES {
            let over = self.copies.len() - MAX_COPIES;
            self.copies.drain(..over);
        }
    }

    /// [`super::mark_copy`] on the file.
    pub fn mark_copy(&mut self, mid: &str, delivery: &str) -> bool {
        if !self.copies.iter().any(|c| c == mid) {
            return false;
        }
        for g in &mut self.groups {
            for m in g.messages.iter_mut().filter(|m| m.mine) {
                for line in m.lines.iter_mut().filter(|l| l.copy == mid) {
                    line.state = line_after(&line.state, delivery);
                }
            }
        }
        true
    }

    /// Every bound of design §6, each with its unit of fairness, so one
    /// friend's groups or frames only push out their own: messages across
    /// groups (by admin, the oldest first, its key remembered), held frames
    /// (by carrier), intents and done markers (by admin), ids seen (by
    /// author, members last), rosters' side lists, forgotten groups. Together
    /// they keep the store under [`STORE_BUDGET_BYTES`].
    pub fn enforce_caps(&mut self) {
        self.trim_messages(MAX_MESSAGES_TOTAL, MAX_MESSAGE_BYTES_TOTAL);
        self.trim_forgotten(MAX_FORGOTTEN, MAX_FORGOTTEN_SEEN);
        for g in &mut self.groups {
            if g.seen.len() > MAX_SEEN_PER_GROUP {
                let members = g.member_tags(&self.me);
                g.seen.trim_to(MAX_SEEN_PER_GROUP, &members);
            }
            trim_held(
                &mut [&mut g.held],
                MAX_HELD_PER_GROUP,
                MAX_HELD_BYTES_PER_GROUP,
            );
            trim_intents(g);
            trim_front(&mut g.done, MAX_DONE_PER_GROUP);
            trim_front(&mut g.answered, super::MAX_GROUP_MEMBERS * 4);
            trim_front(&mut g.removed, super::MAX_GROUP_MEMBERS * 8);
        }
        trim_held(
            &mut [&mut self.unknown_held],
            MAX_UNKNOWN_HELD,
            MAX_UNKNOWN_HELD_BYTES,
        );
        self.trim_all_held(MAX_HELD_BYTES_TOTAL);
        self.trim_done(MAX_DONE_BYTES_TOTAL);
        self.trim_all_intents(MAX_INTENT_BYTES_TOTAL);
        trim_front(&mut self.copies, MAX_COPIES);
    }

    /// Messages over `max_count` or `max_bytes` go: the admin whose groups
    /// hold the most (by count while over the count, else by bytes) loses
    /// the oldest message of its group holding the most; each key is
    /// remembered ([`GroupRecord::seen`]). Returns the bytes that went.
    fn trim_messages(&mut self, max_count: usize, max_bytes: usize) -> usize {
        let units = admin_units(&self.groups);
        let sizes: Vec<Vec<usize>> = self
            .groups
            .iter()
            .map(|g| g.messages.iter().map(StoredMsg::stored_bytes).collect())
            .collect();
        let gone = water_fill(&sizes, &units, max_count, max_bytes);
        let mut shed = 0;
        for ((g, n), sizes) in self.groups.iter_mut().zip(gone).zip(&sizes) {
            shed += sizes[..n].iter().sum::<usize>();
            for m in g.messages.drain(..n) {
                g.seen.push(&m.from, &m.id, m.sent_ms);
            }
        }
        shed
    }

    /// Every held frame (each group's and the unknown groups') over
    /// `max_bytes` in all: the carrier holding the most loses its oldest
    /// frame first. Returns the bytes that went.
    fn trim_all_held(&mut self, max_bytes: usize) -> usize {
        let mut lists: Vec<&mut Vec<Held>> = Vec::with_capacity(self.groups.len() + 1);
        lists.push(&mut self.unknown_held);
        lists.extend(self.groups.iter_mut().map(|g| &mut g.held));
        trim_held(&mut lists, usize::MAX, max_bytes)
    }

    /// Done markers over `max_bytes` in all: the admin whose groups hold
    /// the most loses its oldest first. Returns the bytes that went.
    fn trim_done(&mut self, max_bytes: usize) -> usize {
        let units = admin_units(&self.groups);
        let sizes: Vec<Vec<usize>> = self
            .groups
            .iter()
            .map(|g| g.done.iter().map(|d| mark_bytes(d)).collect())
            .collect();
        let gone = water_fill(&sizes, &units, usize::MAX, max_bytes);
        let mut shed = 0;
        for ((g, n), sizes) in self.groups.iter_mut().zip(gone).zip(&sizes) {
            shed += sizes[..n].iter().sum::<usize>();
            g.done.drain(..n);
        }
        shed
    }

    /// Intents over `max_bytes` in all: the admin whose groups hold the
    /// most loses first, forwards first, then the oldest; a copy of an own
    /// message that goes fails its line. Returns the bytes that went.
    fn trim_all_intents(&mut self, max_bytes: usize) -> usize {
        let units = admin_units(&self.groups);
        let orders: Vec<Vec<usize>> = self.groups.iter().map(intent_order).collect();
        let sizes: Vec<Vec<usize>> = self
            .groups
            .iter()
            .zip(&orders)
            .map(|(g, order)| order.iter().map(|&i| g.intents[i].stored_bytes()).collect())
            .collect();
        let gone = water_fill(&sizes, &units, usize::MAX, max_bytes);
        let mut shed = 0;
        for (((g, n), order), sizes) in self.groups.iter_mut().zip(gone).zip(&orders).zip(&sizes) {
            shed += sizes[..n].iter().sum::<usize>();
            drop_intents(g, &order[..n]);
        }
        shed
    }

    /// Forgotten groups over `max` go for good, the one forgotten first
    /// first; while they keep more than `max_seen` keys in all, the group
    /// forgotten first loses its keys first.
    fn trim_forgotten(&mut self, max: usize, max_seen: usize) {
        let order = forgotten_order(&self.groups);
        if order.len() > max {
            let gone: HashSet<usize> = order[..order.len() - max].iter().copied().collect();
            let mut at = 0;
            self.groups.retain(|_| {
                at += 1;
                !gone.contains(&(at - 1))
            });
        }
        let order = forgotten_order(&self.groups);
        let mut kept: usize = order.iter().map(|&i| self.groups[i].seen.len()).sum();
        for i in order {
            if kept <= max_seen {
                break;
            }
            let seen = &mut self.groups[i].seen;
            let n = (kept - max_seen).min(seen.len());
            seen.drop_first(n);
            kept -= n;
        }
    }

    fn held_bytes(&self) -> usize {
        self.unknown_held
            .iter()
            .chain(self.groups.iter().flat_map(|g| g.held.iter()))
            .map(Held::stored_bytes)
            .sum()
    }

    fn done_bytes(&self) -> usize {
        self.groups
            .iter()
            .flat_map(|g| g.done.iter())
            .map(|d| mark_bytes(d))
            .sum()
    }

    fn intent_bytes(&self) -> usize {
        self.groups
            .iter()
            .flat_map(|g| g.intents.iter())
            .map(Intent::stored_bytes)
            .sum()
    }

    /// A store over its budget sheds what it can lose, at least `over`
    /// bytes when it holds that much: held frames, then done markers, then
    /// intents, each with its unit of fairness. Returns the bytes that went.
    fn shed_work(&mut self, over: usize) -> usize {
        let mut shed = 0;
        if shed < over {
            let held = self.held_bytes();
            shed += self.trim_all_held(held.saturating_sub(over - shed));
        }
        if shed < over {
            let done = self.done_bytes();
            shed += self.trim_done(done.saturating_sub(over - shed));
        }
        if shed < over {
            let intents = self.intent_bytes();
            shed += self.trim_all_intents(intents.saturating_sub(over - shed));
        }
        shed
    }

    /// Only for a repair: the oldest messages go too, as [`MAX_MESSAGE_BYTES_TOTAL`]
    /// chooses them (their keys stay seen). Returns the bytes that went.
    fn shed_history(&mut self, over: usize) -> usize {
        let bytes: usize = self
            .groups
            .iter()
            .flat_map(|g| g.messages.iter())
            .map(StoredMsg::stored_bytes)
            .sum();
        self.trim_messages(usize::MAX, bytes.saturating_sub(over))
    }

    /// Held frames and intents past [`WORK_TTL_MS`] go.
    pub fn expire(&mut self, now_ms: u64) {
        let fresh = |at: u64| now_ms < at.saturating_add(WORK_TTL_MS);
        self.unknown_held.retain(|h| fresh(h.at_ms));
        for g in &mut self.groups {
            g.held.retain(|h| fresh(h.at_ms));
            // A message key goes once its message could no longer be taken
            // (older than the replay horizon).
            g.seen.retain_fresh(now_ms);
            let mut gone = Vec::new();
            g.intents.retain(|i| {
                let keep = fresh(i.made_ms);
                if !keep && !i.line_of.is_empty() {
                    gone.push((i.line_of.clone(), i.to.clone()));
                }
                keep
            });
            for (of, to) in gone {
                g.set_line(&of, &to, |line| {
                    if line.state != LINE_DELIVERED {
                        line.state = LINE_FAILED.into();
                    }
                });
            }
        }
    }
}

/// The intents over [`MAX_INTENTS_PER_GROUP`] go, forwards first (oldest
/// first), then the oldest others; a copy of this profile's own message
/// that goes fails its line (it does not stay "waiting" for ever).
fn trim_intents(g: &mut GroupRecord) {
    if g.intents.len() > MAX_INTENTS_PER_GROUP {
        let over = g.intents.len() - MAX_INTENTS_PER_GROUP;
        let order = intent_order(g);
        drop_intents(g, &order[..over]);
    }
}

/// The order a group's intents go in: forwards and receipts passed on
/// (they carry another member's frame) first, then the others, each oldest
/// first.
fn intent_order(g: &GroupRecord) -> Vec<usize> {
    let (forwards, others): (Vec<usize>, Vec<usize>) =
        (0..g.intents.len()).partition(|&i| !g.intents[i].author.is_empty());
    forwards.into_iter().chain(others).collect()
}

/// Remove the intents at `gone` (indexes); a copy of this profile's own
/// message that goes fails its line.
fn drop_intents(g: &mut GroupRecord, gone: &[usize]) {
    if gone.is_empty() {
        return;
    }
    let mut out = vec![false; g.intents.len()];
    for &i in gone {
        out[i] = true;
    }
    let lines: Vec<(String, String)> = gone
        .iter()
        .map(|&i| &g.intents[i])
        .filter(|i| !i.line_of.is_empty())
        .map(|i| (i.line_of.clone(), i.to.clone()))
        .collect();
    let mut at = 0;
    g.intents.retain(|_| {
        at += 1;
        !out[at - 1]
    });
    for (of, to) in lines {
        g.set_line(&of, &to, |line| {
            if line.state != LINE_DELIVERED {
                line.state = LINE_FAILED.into();
            }
        });
    }
}

/// Held frames of `lists` over `max_count` or `max_bytes` in all go: the
/// carrier holding the most (frames while over the count, else bytes)
/// loses its oldest frame, from the list where it holds the most. Returns
/// the bytes that went.
fn trim_held(lists: &mut [&mut Vec<Held>], max_count: usize, max_bytes: usize) -> usize {
    let mut carriers: HashMap<&str, usize> = HashMap::new();
    let mut slot_of: HashMap<(usize, usize), usize> = HashMap::new();
    // Per slot (one carrier in one list): its frames oldest first, their
    // sizes, its list and its carrier.
    let mut frames: Vec<Vec<usize>> = Vec::new();
    let mut sizes: Vec<Vec<usize>> = Vec::new();
    let mut list_of: Vec<usize> = Vec::new();
    let mut units: Vec<usize> = Vec::new();
    for (l, list) in lists.iter().enumerate() {
        let mut order: Vec<usize> = (0..list.len()).collect();
        order.sort_by_key(|&i| (list[i].at_ms, i));
        for i in order {
            let next = carriers.len();
            let carrier = *carriers.entry(list[i].peer.as_str()).or_insert(next);
            let slot = *slot_of.entry((l, carrier)).or_insert_with(|| {
                frames.push(Vec::new());
                sizes.push(Vec::new());
                list_of.push(l);
                units.push(carrier);
                frames.len() - 1
            });
            frames[slot].push(i);
            sizes[slot].push(list[i].stored_bytes());
        }
    }
    let gone = water_fill(&sizes, &units, max_count, max_bytes);
    let mut out: Vec<Vec<bool>> = lists.iter().map(|l| vec![false; l.len()]).collect();
    let mut shed = 0;
    for (slot, n) in gone.into_iter().enumerate() {
        for k in 0..n {
            out[list_of[slot]][frames[slot][k]] = true;
            shed += sizes[slot][k];
        }
    }
    for (list, out) in lists.iter_mut().zip(out) {
        let mut at = 0;
        list.retain(|_| {
            at += 1;
            !out[at - 1]
        });
    }
    shed
}

/// The forgotten groups' indexes, the one forgotten first first.
fn forgotten_order(groups: &[GroupRecord]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..groups.len())
        .filter(|&i| groups[i].is_forgotten())
        .collect();
    order.sort_by_key(|&i| (groups[i].updated_ms, i));
    order
}

/// Each group's unit of fairness: its admin, so all the groups one friend
/// made count together (a friend can make many groups, but is one admin).
fn admin_units(groups: &[GroupRecord]) -> Vec<usize> {
    let mut admins: HashMap<&str, usize> = HashMap::new();
    groups
        .iter()
        .map(|g| {
            let next = admins.len();
            *admins.entry(g.state.admin.as_str()).or_insert(next)
        })
        .collect()
}

/// Water filling over `slots` (each slot's item sizes, in the order they
/// may go) owned by `units` (one per slot): while more than `max_count`
/// items or `max_bytes` bytes remain, the unit holding the most (items
/// while over the count, else bytes) gives up the next item of its slot
/// holding the most; equal sizes: the earlier unit and slot. Returns how
/// many items of each slot go.
fn water_fill(
    slots: &[Vec<usize>],
    units: &[usize],
    max_count: usize,
    max_bytes: usize,
) -> Vec<usize> {
    let n_units = units.iter().copied().max().map_or(0, |u| u + 1);
    let mut gone = vec![0; slots.len()];
    let mut slot_count: Vec<usize> = slots.iter().map(Vec::len).collect();
    let mut slot_bytes: Vec<usize> = slots.iter().map(|s| s.iter().sum()).collect();
    let mut unit_count = vec![0usize; n_units];
    let mut unit_bytes = vec![0usize; n_units];
    for (slot, &unit) in units.iter().enumerate() {
        unit_count[unit] += slot_count[slot];
        unit_bytes[unit] += slot_bytes[slot];
    }
    let mut count: usize = slot_count.iter().sum();
    let mut bytes: usize = slot_bytes.iter().sum();
    while count > max_count || bytes > max_bytes {
        let by_bytes = count <= max_count;
        let size = |n: usize, b: usize| if by_bytes { b } else { n };
        let Some(unit) = (0..n_units)
            .filter(|&u| unit_count[u] > 0)
            .max_by_key(|&u| (size(unit_count[u], unit_bytes[u]), Reverse(u)))
        else {
            break;
        };
        let Some(slot) = (0..slots.len())
            .filter(|&s| units[s] == unit && slot_count[s] > 0)
            .max_by_key(|&s| (size(slot_count[s], slot_bytes[s]), Reverse(s)))
        else {
            break;
        };
        let item = slots[slot][gone[slot]];
        gone[slot] += 1;
        slot_count[slot] -= 1;
        slot_bytes[slot] -= item;
        unit_count[unit] -= 1;
        unit_bytes[unit] -= item;
        count -= 1;
        bytes -= item;
    }
    gone
}

fn trim_front<T>(list: &mut Vec<T>, max: usize) {
    if list.len() > max {
        let over = list.len() - max;
        list.drain(..over);
    }
}

// ------------------------------------------------------------------ sizes

/// The bytes an entry takes in the store as written beyond its strings
/// (pretty JSON at the depth it sits, numbers at their widest, its share of
/// the list around it even as the only entry): upper bounds, so the bounds
/// above hold for the file itself.
const MSG_FIXED: usize = 320;
const LINE_FIXED: usize = 160;
const HELD_FIXED: usize = 112;
const INTENT_FIXED: usize = 264;
const MARK_FIXED: usize = 16;

/// The length of `s` written as a JSON string, quotes included
/// (serde_json's escapes).
fn json_len(s: &str) -> usize {
    2 + s
        .bytes()
        .map(|b| match b {
            b'"' | b'\\' | b'\n' | b'\r' | b'\t' | 0x08 | 0x0c => 2,
            0..=0x1f => 6,
            _ => 1,
        })
        .sum::<usize>()
}

/// The bytes a done marker takes in the store (an upper bound).
pub(crate) fn mark_bytes(marker: &str) -> usize {
    MARK_FIXED + json_len(marker)
}

impl StoredMsg {
    /// The bytes it takes in the store (an upper bound).
    pub fn stored_bytes(&self) -> usize {
        MSG_FIXED
            + [
                &self.id, &self.from, &self.body, &self.sig, &self.via, &self.path,
            ]
            .into_iter()
            .map(|s| json_len(s))
            .sum::<usize>()
            + self
                .lines
                .iter()
                .map(|l| {
                    LINE_FIXED
                        + [&l.member, &l.device, &l.copy, &l.via, &l.state]
                            .into_iter()
                            .map(|s| json_len(s))
                            .sum::<usize>()
                })
                .sum::<usize>()
    }
}

impl Held {
    /// The bytes it takes in the store (an upper bound).
    pub fn stored_bytes(&self) -> usize {
        HELD_FIXED + json_len(&self.frame) + json_len(&self.peer)
    }
}

impl Intent {
    /// The bytes it takes in the store (an upper bound).
    pub fn stored_bytes(&self) -> usize {
        INTENT_FIXED
            + [
                &self.id,
                &self.kind,
                &self.to,
                &self.frame,
                &self.of,
                &self.via,
                &self.line_of,
                &self.author,
            ]
            .into_iter()
            .map(|s| json_len(s))
            .sum::<usize>()
    }
}

// ------------------------------------------------------------------ seen keys

/// One seen key (layout 3): its author's tag, a digest of its author and
/// id, then the second its message was sent (rounded up, big endian).
const SEEN_KEY_BYTES: usize = 16;
const SEEN_TAG_BYTES: usize = 6;
/// Where the digest ends and the second starts.
const SEEN_TIME_AT: usize = 12;
/// Keys per written string.
const SEEN_CHUNK: usize = 256;
/// What starts a written string of keys (a key of layout 1 holds no `:`).
const SEEN_CHUNK_PREFIX: &str = "v3:";
/// What starts a string of layout 2 (12 bytes of the digest a key, no
/// author).
const SEEN_CHUNK_PREFIX_2: &str = "v2:";
const SEEN_DOMAIN: &[u8] = b"rvn1/group-seen";
const SEEN_AUTHOR_DOMAIN: &[u8] = b"rvn1/group-seen-author";
/// The tag of a key read from layout 2, which kept no author: it counts for
/// no author's share and matches its digest whoever the author.
const NO_AUTHOR: AuthorTag = [0; SEEN_TAG_BYTES];

/// An author's tag in [`SeenKeys`].
pub(crate) type AuthorTag = [u8; SEEN_TAG_BYTES];

fn seen_hash(domain: &[u8], text: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((domain.len() as u16).to_be_bytes());
    h.update(domain);
    h.update(text.as_bytes());
    h.finalize().into()
}

/// The tag of author `from` (hex) in [`SeenKeys`]: the first 6 bytes of
/// SHA-256 over a domain and the author, never [`NO_AUTHOR`].
pub(crate) fn author_tag(from: &str) -> AuthorTag {
    let mut tag = NO_AUTHOR;
    tag.copy_from_slice(&seen_hash(SEEN_AUTHOR_DOMAIN, from)[..SEEN_TAG_BYTES]);
    if tag == NO_AUTHOR {
        tag[SEEN_TAG_BYTES - 1] = 1;
    }
    tag
}

/// [`GroupRecord::seen`]: the messages that left `messages`, oldest first,
/// each kept until it is older than [`REPLAY_HORIZON_MS`]. A key is 16
/// bytes: its author's tag ([`author_tag`]), the first 6 bytes of SHA-256
/// over a domain and [`seen_key`] (its author and id), then the second it
/// was sent, rounded up. A message is known by its author's tag and its
/// digest, and an author's keys count toward its share
/// ([`MAX_SEEN_PER_AUTHOR`]). Written as strings of up to [`SEEN_CHUNK`]
/// keys in base64 after `v3:` (about 21 bytes a key). Strings of layout 2
/// (`v2:`, keys of 12 digest bytes and no author) are read as keys of no
/// author, which match their digest whoever the author; strings of layout 1
/// (`<author>/<id>@<sent_ms>`, one key each, about 120 bytes) are read with
/// their author; both are converted. An older build reading this layout
/// drops the `v3:` strings as keys it cannot read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeenKeys(Vec<[u8; SEEN_KEY_BYTES]>);

impl SeenKeys {
    fn key(from: &str, id: &str, sent_ms: u64) -> [u8; SEEN_KEY_BYTES] {
        let digest = seen_hash(SEEN_DOMAIN, &seen_key(from, id));
        Self::compose(&author_tag(from), &digest, sent_ms)
    }

    fn compose(tag: &AuthorTag, digest: &[u8], sent_ms: u64) -> [u8; SEEN_KEY_BYTES] {
        let second = u32::try_from(sent_ms.div_ceil(1000)).unwrap_or(u32::MAX);
        let mut out = [0u8; SEEN_KEY_BYTES];
        out[..SEEN_TAG_BYTES].copy_from_slice(tag);
        out[SEEN_TAG_BYTES..SEEN_TIME_AT].copy_from_slice(&digest[..SEEN_TIME_AT - SEEN_TAG_BYTES]);
        out[SEEN_TIME_AT..].copy_from_slice(&second.to_be_bytes());
        out
    }

    fn tag(key: &[u8; SEEN_KEY_BYTES]) -> AuthorTag {
        let mut tag = NO_AUTHOR;
        tag.copy_from_slice(&key[..SEEN_TAG_BYTES]);
        tag
    }

    fn sent_ms(key: &[u8; SEEN_KEY_BYTES]) -> u64 {
        let mut second = [0u8; 4];
        second.copy_from_slice(&key[SEEN_TIME_AT..]);
        u64::from(u32::from_be_bytes(second)) * 1000
    }

    /// Its message could still be taken: sent less than
    /// [`REPLAY_HORIZON_MS`] before `now_ms`.
    fn fresh(key: &[u8; SEEN_KEY_BYTES], now_ms: u64) -> bool {
        now_ms < Self::sent_ms(key).saturating_add(REPLAY_HORIZON_MS)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Note message `id` by `from` (both hex), sent at `sent_ms`.
    pub fn push(&mut self, from: &str, id: &str, sent_ms: u64) {
        self.0.push(Self::key(from, id, sent_ms));
    }

    /// Whether message `id` by `from` (both hex) is noted.
    pub fn contains(&self, from: &str, id: &str) -> bool {
        let want = Self::key(from, id, 0);
        self.0.iter().any(|k| {
            k[SEEN_TAG_BYTES..SEEN_TIME_AT] == want[SEEN_TAG_BYTES..SEEN_TIME_AT]
                && (k[..SEEN_TAG_BYTES] == want[..SEEN_TAG_BYTES]
                    || k[..SEEN_TAG_BYTES] == NO_AUTHOR)
        })
    }

    /// The keys of author `from` (hex) whose messages could still be taken.
    pub fn count_by(&self, from: &str, now_ms: u64) -> usize {
        let tag = author_tag(from);
        self.0
            .iter()
            .filter(|k| k[..SEEN_TAG_BYTES] == tag && Self::fresh(k, now_ms))
            .count()
    }

    /// Keys of messages that could still be taken stay: sent less than
    /// [`REPLAY_HORIZON_MS`] before `now_ms`.
    pub fn retain_fresh(&mut self, now_ms: u64) {
        self.0.retain(|k| Self::fresh(k, now_ms));
    }

    /// The first `n` keys noted go.
    pub(crate) fn drop_first(&mut self, n: usize) {
        self.0.drain(..n.min(self.0.len()));
    }

    /// Keys over `max` go: first those of authors `members` does not name
    /// (this profile's own messages, former members', keys of layout 2),
    /// then any; each time, the author holding the most loses the key whose
    /// message was sent first. Every member's share fits in
    /// [`MAX_SEEN_PER_GROUP`], so a member's key goes only from a group
    /// holding more than its members' shares.
    pub(crate) fn trim_to(&mut self, max: usize, members: &HashSet<AuthorTag>) {
        if self.0.len() <= max {
            return;
        }
        let over = self.0.len() - max;
        let gone = self.trim_where(over, |tag| !members.contains(tag));
        if gone < over {
            self.trim_where(over - gone, |_| true);
        }
    }

    /// `over` keys of the authors `which` takes go, by water filling over
    /// those authors (the one holding the most loses the key sent first).
    /// Returns how many went.
    fn trim_where(&mut self, over: usize, which: impl Fn(&AuthorTag) -> bool) -> usize {
        let mut unit_of: HashMap<AuthorTag, usize> = HashMap::new();
        let mut slots: Vec<Vec<usize>> = Vec::new();
        for (i, k) in self.0.iter().enumerate() {
            let tag = Self::tag(k);
            if !which(&tag) {
                continue;
            }
            let unit = *unit_of.entry(tag).or_insert_with(|| {
                slots.push(Vec::new());
                slots.len() - 1
            });
            slots[unit].push(i);
        }
        for slot in &mut slots {
            slot.sort_by_key(|&i| (Self::sent_ms(&self.0[i]), i));
        }
        let held: usize = slots.iter().map(Vec::len).sum();
        let sizes: Vec<Vec<usize>> = slots
            .iter()
            .map(|s| vec![SEEN_KEY_BYTES; s.len()])
            .collect();
        let units: Vec<usize> = (0..slots.len()).collect();
        let gone = water_fill(&sizes, &units, held.saturating_sub(over), usize::MAX);
        let mut out = vec![false; self.0.len()];
        let mut n = 0;
        for (slot, count) in slots.iter().zip(gone) {
            for &i in &slot[..count] {
                out[i] = true;
                n += 1;
            }
        }
        let mut at = 0;
        self.0.retain(|_| {
            at += 1;
            !out[at - 1]
        });
        n
    }

    /// A key of layout 2 (12 bytes of the digest, then the second), kept as
    /// a key of no author.
    fn from_layout_2(key: &[u8; SEEN_KEY_BYTES]) -> [u8; SEEN_KEY_BYTES] {
        let mut out = [0u8; SEEN_KEY_BYTES];
        out[SEEN_TAG_BYTES..SEEN_TIME_AT].copy_from_slice(&key[..SEEN_TIME_AT - SEEN_TAG_BYTES]);
        out[SEEN_TIME_AT..].copy_from_slice(&key[SEEN_TIME_AT..]);
        out
    }

    /// A key of layout 1, `<author>/<id>@<sent_ms>`; `None` without a time
    /// (an older store's entry, which expiry dropped).
    fn parse_older(entry: &str) -> Option<[u8; SEEN_KEY_BYTES]> {
        let (key, at) = entry.rsplit_once('@')?;
        let sent_ms = at.parse::<u64>().ok()?;
        Some(match key.split_once('/') {
            Some((from, id)) => Self::key(from, id, sent_ms),
            None => Self::compose(&NO_AUTHOR, &seen_hash(SEEN_DOMAIN, key), sent_ms),
        })
    }
}

impl Serialize for SeenKeys {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use base64::Engine;
        let chunks: Vec<String> = self
            .0
            .chunks(SEEN_CHUNK)
            .map(|chunk| {
                let bytes: Vec<u8> = chunk.iter().flatten().copied().collect();
                format!(
                    "{SEEN_CHUNK_PREFIX}{}",
                    base64::engine::general_purpose::STANDARD.encode(bytes)
                )
            })
            .collect();
        chunks.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SeenKeys {
    /// Strings of any layout; one that is none is left out (a lost key only
    /// lets its message be taken as new, while a store that does not read
    /// stops every group).
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use base64::Engine;
        let entries = Vec::<String>::deserialize(deserializer)?;
        let mut keys = Vec::new();
        for entry in &entries {
            let (chunk, layout_2) = if let Some(chunk) = entry.strip_prefix(SEEN_CHUNK_PREFIX) {
                (chunk, false)
            } else if let Some(chunk) = entry.strip_prefix(SEEN_CHUNK_PREFIX_2) {
                (chunk, true)
            } else {
                keys.extend(Self::parse_older(entry));
                continue;
            };
            let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(chunk) else {
                continue;
            };
            let (whole, rest) = bytes.as_chunks::<SEEN_KEY_BYTES>();
            if !rest.is_empty() {
                continue;
            }
            if layout_2 {
                keys.extend(whole.iter().map(Self::from_layout_2));
            } else {
                keys.extend_from_slice(whole);
            }
        }
        Ok(SeenKeys(keys))
    }
}

/// A line's state after its copy's history delivery word: `delivered` is
/// final; a give-up (`failed`, `expired`, `cancelled`) fails it unless it
/// was delivered.
pub fn line_after(current: &str, delivery: &str) -> String {
    if current == LINE_DELIVERED {
        return current.into();
    }
    match delivery {
        "delivered" | "read" => LINE_DELIVERED,
        crate::outbox::HISTORY_FAILED
        | crate::outbox::HISTORY_EXPIRED
        | crate::outbox::HISTORY_CANCELLED => LINE_FAILED,
        "sent" if current != LINE_FAILED => LINE_SENT,
        _ => current,
    }
    .into()
}

impl GroupRecord {
    pub fn new(state: &GroupState, now_ms: u64) -> GroupRecord {
        GroupRecord {
            id: hex::encode(state.group),
            state: StateWire::from(state),
            status: STATUS_ACTIVE.into(),
            left_seen_out: false,
            joined_ms: now_ms,
            updated_ms: now_ms,
            removed: Vec::new(),
            messages: Vec::new(),
            seen: SeenKeys::default(),
            held: Vec::new(),
            intents: Vec::new(),
            done: Vec::new(),
            read_ms: now_ms,
            sync_ms: 0,
            answered: Vec::new(),
        }
    }

    /// The roster held (it was verified before it was stored).
    pub fn roster(&self) -> Option<GroupState> {
        self.state.typed()
    }

    pub fn is_active(&self) -> bool {
        self.status == STATUS_ACTIVE
    }

    pub fn is_forgotten(&self) -> bool {
        self.status == STATUS_FORGOTTEN
    }

    /// This profile left the group (and may have forgotten it since), and no
    /// roster without it came: the admin has not taken its leave yet.
    pub fn leave_unanswered(&self) -> bool {
        (self.status == STATUS_LEFT || self.status == STATUS_FORGOTTEN) && !self.left_seen_out
    }

    /// Whether message `id` by `from` (both hex) is known here: a message is
    /// known by its author and its id, so a member who sends another author's
    /// message id first cannot have the real message dropped as a duplicate
    /// (and ACKed).
    pub fn has_seen(&self, from: &str, id: &str) -> bool {
        self.messages.iter().any(|m| m.id == id && m.from == from) || self.seen.contains(from, id)
    }

    /// What author `from` (hex) holds of this group's room for message keys
    /// ([`MAX_SEEN_PER_AUTHOR`]): its messages kept here and its keys seen,
    /// each while its message could still be taken (sent less than
    /// [`REPLAY_HORIZON_MS`] before `now_ms`). A message that leaves
    /// `messages` leaves its key in `seen`, so the share stays the same.
    pub fn author_share(&self, from: &str, now_ms: u64) -> usize {
        let fresh = |sent_ms: u64| now_ms < sent_ms.saturating_add(REPLAY_HORIZON_MS);
        self.messages
            .iter()
            .filter(|m| m.from == from && fresh(m.sent_ms))
            .count()
            + self.seen.count_by(from, now_ms)
    }

    /// One author's share of this group's room for message keys
    /// ([`MAX_SEEN_PER_AUTHOR`]): [`MAX_SEEN_PER_GROUP`] over the roster's
    /// members (this profile included), at least [`MAX_SEEN_PER_AUTHOR`],
    /// so every member's share fits in the room together.
    pub fn share(&self) -> usize {
        let members = self.state.members.len().clamp(1, super::MAX_GROUP_MEMBERS);
        (MAX_SEEN_PER_GROUP / members).max(MAX_SEEN_PER_AUTHOR)
    }

    /// The seen-key tags of the roster's members but `me` (hex): the keys
    /// [`SeenKeys::trim_to`] keeps longest.
    fn member_tags(&self, me: &str) -> HashSet<AuthorTag> {
        self.roster()
            .map(|r| {
                r.members
                    .iter()
                    .map(|m| hex::encode(m.key))
                    .filter(|k| k != me)
                    .map(|k| author_tag(&k))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// [`forget`] takes it: this profile left it or was removed, or it is
    /// dead (its roster unreadable, or no member but its admin).
    pub fn can_forget(&self) -> bool {
        !self.is_active() || self.roster().is_none_or(|r| r.members.len() <= 1)
    }

    /// [`forget`]'s change: its messages go (their keys stay seen), and so
    /// do its held frames, done markers, answers and removals; its roster
    /// keeps only what tells its frames apart (id, salt, admin, epoch, time).
    /// Intents still waiting stay (a leave still reaches the admin). A group
    /// this profile was removed from had a roster without it, so the next
    /// one with it is a new invitation.
    pub(crate) fn forget(&mut self, now_ms: u64) {
        for m in std::mem::take(&mut self.messages) {
            self.seen.push(&m.from, &m.id, m.sent_ms);
        }
        self.held.clear();
        self.done.clear();
        self.answered.clear();
        self.removed.clear();
        if self.status == STATUS_REMOVED {
            self.left_seen_out = true;
        }
        self.status = STATUS_FORGOTTEN.into();
        self.state = forgotten_roster(&self.state);
        self.updated_ms = now_ms;
        self.read_ms = now_ms;
        self.sync_ms = 0;
    }

    /// A newer roster `state` that leaves a forgotten group forgotten: only
    /// what tells its frames apart moves on, and whether a roster without
    /// this profile came.
    pub(crate) fn keep_forgotten(&mut self, state: &GroupState, left_seen_out: bool) {
        self.state = forgotten_roster(&StateWire::from(state));
        self.left_seen_out = left_seen_out;
    }

    pub fn was_removed(&self, key: &Key) -> bool {
        let hex = hex::encode(key);
        self.removed.contains(&hex)
    }

    pub fn is_done(&self, marker: &str) -> bool {
        self.done.iter().any(|d| d == marker)
    }

    pub fn mark_done(&mut self, marker: String) {
        if !self.is_done(&marker) {
            self.done.push(marker);
        }
    }

    /// [`clear`]'s change to one group: `(cleared, pending_kept)`.
    pub fn clear_messages(&mut self, include_pending: bool) -> (usize, usize) {
        let on_its_way = |m: &StoredMsg| {
            m.mine
                && m.lines
                    .iter()
                    .any(|l| l.state != LINE_DELIVERED && l.state != LINE_FAILED)
        };
        let (kept, gone): (Vec<StoredMsg>, Vec<StoredMsg>) = std::mem::take(&mut self.messages)
            .into_iter()
            .partition(|m| !include_pending && on_its_way(m));
        if include_pending {
            let mine: HashSet<&str> = gone
                .iter()
                .filter(|m| m.mine)
                .map(|m| m.id.as_str())
                .collect();
            self.intents
                .retain(|i| !(i.kind == INTENT_SEND && mine.contains(i.line_of.as_str())));
        }
        // Their keys stay seen (the store's bounds keep `seen` to its size
        // when it is written).
        for m in &gone {
            self.seen.push(&m.from, &m.id, m.sent_ms);
        }
        let counts = (gone.len(), kept.len());
        self.messages = kept;
        counts
    }

    pub fn push_intent(&mut self, intent: Intent) {
        self.intents.push(intent);
    }

    /// Change this profile's line for `member` of its message `of`.
    pub fn set_line(&mut self, of: &str, member: &str, change: impl FnOnce(&mut Line)) {
        if let Some(line) = self
            .messages
            .iter_mut()
            .filter(|m| m.mine && m.id == of)
            .flat_map(|m| m.lines.iter_mut())
            .find(|l| l.member == member)
        {
            change(line);
        }
    }
}

/// What a forgotten group keeps of its roster `state`: what tells its
/// frames apart (its id, salt, admin, epoch and time), no name, no label,
/// no member but the admin, no signature (it is never sent).
fn forgotten_roster(state: &StateWire) -> StateWire {
    StateWire {
        group: state.group.clone(),
        salt: state.salt.clone(),
        epoch: state.epoch,
        name: FORGOTTEN_NAME.into(),
        admin: state.admin.clone(),
        issued_ms: state.issued_ms,
        members: vec![MemberWire {
            key: state.admin.clone(),
            label: String::new(),
        }],
        sig: hex::encode([0u8; 64]),
    }
}

/// What a message is known by in [`GroupRecord::seen`] (as a digest there):
/// its author and id (hex).
pub fn seen_key(from: &str, id: &str) -> String {
    format!("{from}/{id}")
}

pub fn new_intent_id() -> String {
    hex::encode(rand::random::<[u8; 8]>())
}

// ------------------------------------------------------------------ views

/// One group in a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSummary {
    pub id: GroupId,
    pub name: String,
    pub admin: Key,
    pub i_am_admin: bool,
    pub status: String,
    pub epoch: u32,
    pub members: usize,
    pub unread: usize,
    /// The newest message's time (or when the group changed), for ordering.
    pub last_ms: u64,
    /// The newest message: its author and text.
    pub last: Option<(Key, String)>,
}

/// One member as this profile sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberView {
    pub key: Key,
    /// The admin's name for the member.
    pub label: String,
    /// This profile's own name for the member, when it is a friend.
    pub friend_name: Option<String>,
    pub admin: bool,
    pub me: bool,
}

impl MemberView {
    /// What to call the member: "you", the friend's name, the admin's label,
    /// else the start of the key.
    pub fn display(&self) -> String {
        if self.me {
            return "you".into();
        }
        if let Some(name) = self.friend_name.as_deref().filter(|n| !n.trim().is_empty()) {
            return name.to_owned();
        }
        if !self.label.trim().is_empty() {
            return self.label.clone();
        }
        hex::encode(&self.key[..4])
    }
}

/// A group with its members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupView {
    pub summary: GroupSummary,
    pub members: Vec<MemberView>,
}

impl GroupView {
    pub fn member(&self, key: &Key) -> Option<&MemberView> {
        self.members.iter().find(|m| m.key == *key)
    }

    /// The name to show for `key` (a member, a former member, or a key the
    /// roster never held).
    pub fn name_of(&self, key: &Key, names: &HashMap<Key, String>) -> String {
        if let Some(m) = self.member(key) {
            return m.display();
        }
        names
            .get(key)
            .cloned()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| format!("a former member ({})", hex::encode(&key[..4])))
    }
}

/// One message as a chat shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageView {
    pub id: [u8; 16],
    pub from: Key,
    pub mine: bool,
    pub body: String,
    pub sent_ms: u64,
    pub received_ms: u64,
    /// The member that passed it on, when it was not the author.
    pub via: Option<Key>,
    /// Mine only: each member's state (`waiting`, `sent`, `delivered`,
    /// `failed`) and how it is reached (`direct`, `relay`).
    pub lines: Vec<(Key, String, String)>,
    /// Mine only: the message id of the copy parked for each member reached
    /// directly, once parked (the outbox's record of that copy says which
    /// friends hold it while the member is away).
    pub copies: Vec<(Key, [u8; 16])>,
    pub delivered: usize,
    pub total: usize,
    /// A received one: how the copy that brought it came, when known.
    pub path: Option<crate::arrivals::ArrivedVia>,
}

fn summary(g: &GroupRecord, me: Option<&Key>) -> Option<GroupSummary> {
    let roster = g.roster()?;
    let last = g.messages.last();
    let unread = g
        .messages
        .iter()
        .filter(|m| !m.mine && m.received_ms > g.read_ms)
        .count();
    Some(GroupSummary {
        id: roster.group,
        name: roster.name.clone(),
        admin: roster.admin,
        i_am_admin: me == Some(&roster.admin),
        status: g.status.clone(),
        epoch: roster.epoch,
        members: roster.members.len(),
        unread,
        last_ms: last.map_or(g.updated_ms, |m| m.received_ms),
        last: last.and_then(|m| Some((hex_key(&m.from)?, m.body.clone()))),
    })
}

fn me_of(file: &GroupsFile, data_dir: &Path) -> Option<Key> {
    hex_key(&file.me).or_else(|| super::local_identity_key(data_dir))
}

/// Every group, the newest activity first.
pub fn list(data_dir: &Path) -> Result<Vec<GroupSummary>, GroupError> {
    let file = load(data_dir)?;
    let me = me_of(&file, data_dir);
    let mut out: Vec<GroupSummary> = file
        .groups
        .iter()
        .filter(|g| !g.is_forgotten())
        .filter_map(|g| summary(g, me.as_ref()))
        .collect();
    out.sort_by(|a, b| b.last_ms.cmp(&a.last_ms).then_with(|| a.name.cmp(&b.name)));
    Ok(out)
}

/// One group with its members (friend names from the contact book).
pub fn view(data_dir: &Path, id: &GroupId) -> Result<GroupView, GroupError> {
    let file = load(data_dir)?;
    let me = me_of(&file, data_dir);
    let g = file.shown(id).ok_or(GroupError::NotFound)?;
    let roster = g.roster().ok_or(GroupError::NotFound)?;
    let names = super::friend_names(data_dir);
    let friends = super::friend_keys(data_dir);
    let members = roster
        .members
        .iter()
        .map(|m| MemberView {
            key: m.key,
            label: m.label.clone(),
            friend_name: friends
                .contains(&m.key)
                .then(|| names.get(&m.key).cloned())
                .flatten(),
            admin: m.key == roster.admin,
            me: me == Some(m.key),
        })
        .collect();
    Ok(GroupView {
        summary: summary(g, me.as_ref()).ok_or(GroupError::NotFound)?,
        members,
    })
}

/// A group's messages, oldest first: at most `limit` of those received
/// before `before_ms` (all when `None`).
pub fn history(
    data_dir: &Path,
    id: &GroupId,
    before_ms: Option<u64>,
    limit: usize,
) -> Result<Vec<MessageView>, GroupError> {
    let file = load(data_dir)?;
    let g = file.shown(id).ok_or(GroupError::NotFound)?;
    let rows: Vec<&StoredMsg> = g
        .messages
        .iter()
        .filter(|m| before_ms.is_none_or(|b| m.received_ms < b))
        .collect();
    let start = rows.len().saturating_sub(limit);
    Ok(rows[start..]
        .iter()
        .filter_map(|m| {
            let lines: Vec<(Key, String, String)> = m
                .lines
                .iter()
                .filter_map(|l| Some((hex_key(&l.member)?, l.state.clone(), l.via.clone())))
                .collect();
            Some(MessageView {
                id: hex_n::<16>(&m.id)?,
                from: hex_key(&m.from)?,
                mine: m.mine,
                body: m.body.clone(),
                sent_ms: m.sent_ms,
                received_ms: m.received_ms,
                via: hex_key(&m.via),
                delivered: lines.iter().filter(|l| l.1 == LINE_DELIVERED).count(),
                total: lines.len(),
                lines,
                copies: m
                    .lines
                    .iter()
                    .filter_map(|l| Some((hex_key(&l.member)?, hex_n::<16>(&l.copy)?)))
                    .collect(),
                path: crate::arrivals::ArrivedVia::parse(&m.path),
            })
        })
        .collect())
}

/// Every message received up to `now_ms` is read.
pub fn mark_read(data_dir: &Path, id: &GroupId, now_ms: u64) -> Result<usize, GroupError> {
    edit(data_dir, |file| {
        let g = file.shown_mut(id).ok_or(GroupError::NotFound)?;
        let newest = g
            .messages
            .iter()
            .map(|m| m.received_ms)
            .max()
            .unwrap_or(0)
            .max(now_ms);
        if newest > g.read_ms {
            g.read_ms = newest;
        }
        Ok(0)
    })
}

/// Clear group `id`'s chat on this device (0.1.1 chat controls; the other
/// members are not told): its messages go, each remembered as seen
/// (by its author and id, as the caps drop them) so a copy that comes
/// again is a duplicate, never shown again. This profile's own messages
/// still on their way to a member (a line neither delivered nor failed) stay
/// unless `include_pending`; with it they go too, and so do the intents
/// still sending their copies. `(cleared, pending_kept)`.
pub fn clear(
    data_dir: &Path,
    id: &GroupId,
    include_pending: bool,
) -> Result<(usize, usize), GroupError> {
    edit(data_dir, |file| {
        let g = file.shown_mut(id).ok_or(GroupError::NotFound)?;
        Ok(g.clear_messages(include_pending))
    })
}

/// Forget group `id` on this device: one this profile left or was
/// removed from, or a dead one (its roster unreadable, or no member but its
/// admin); a group this profile is still in is [`GroupError::StillMember`].
/// It leaves every list and operation and frees its place
/// ([`MAX_GROUPS`]); its messages go, their keys stay seen until they
/// expire, and its id and epoch stay ([`STATUS_FORGOTTEN`]), so its old
/// frames (a roster again, a message again) do not bring it back. As for a
/// group left, a newer roster that names this profile after one that did
/// not is a new invitation. Copies still on their way (a leave to the
/// admin) go on. The other members are not told.
pub fn forget(data_dir: &Path, id: &GroupId, now_ms: u64) -> Result<(), GroupError> {
    edit(data_dir, |file| file.forget(id, now_ms))
}

/// The group `query` names: its whole id, the start of its id (at least 4
/// hex characters), or its name (any case). Several matches are
/// [`GroupError::Ambiguous`].
pub fn find(data_dir: &Path, query: &str) -> Result<GroupId, GroupError> {
    let file = load(data_dir)?;
    find_in(&file, query)
}

pub(crate) fn find_in(file: &GroupsFile, query: &str) -> Result<GroupId, GroupError> {
    let q = query.trim();
    if q.is_empty() {
        return Err(GroupError::NotFound);
    }
    let lower = q.to_ascii_lowercase();
    let shown = || file.groups.iter().filter(|g| !g.is_forgotten());
    let ids: Vec<GroupId> = shown().filter_map(|g| hex_n::<16>(&g.id)).collect();
    if let Some(id) = ids.iter().find(|id| hex::encode(id) == lower) {
        return Ok(*id);
    }
    let by_name: Vec<GroupId> = shown()
        .filter(|g| g.state.name.to_lowercase() == q.to_lowercase())
        .filter_map(|g| hex_n::<16>(&g.id))
        .collect();
    let by_prefix: Vec<GroupId> =
        if lower.len() >= 4 && lower.bytes().all(|b| b.is_ascii_hexdigit()) {
            ids.iter()
                .filter(|id| hex::encode(id).starts_with(&lower))
                .copied()
                .collect()
        } else {
            Vec::new()
        };
    let mut all: Vec<GroupId> = by_name;
    for id in by_prefix {
        if !all.contains(&id) {
            all.push(id);
        }
    }
    let unique: HashSet<GroupId> = all.iter().copied().collect();
    match unique.len() {
        0 => Err(GroupError::NotFound),
        1 => Ok(all[0]),
        _ => Err(GroupError::Ambiguous),
    }
}
