//! The group store, `groups.json` (design §6): every group's roster,
//! status, messages with their delivery lines, ids seen, held frames and
//! intents, in one file. At-rest kind [`Kind::Groups`]: RMS1 in a sealed
//! profile, plain JSON before, always written under its writer lock
//! ([`GROUPS_LOCK`]). The lock is a leaf: nothing else is taken while it is
//! held (callers read the contact book and park copies outside it).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::wire::{hex_n, StateWire};
use super::{GroupError, GroupId, GroupState, Key};
use crate::at_rest::{self, Kind};

/// The store's file name in the data dir.
pub const GROUPS_FILE: &str = "groups.json";
/// Its writer lock (`at_rest::FILES` names it).
pub const GROUPS_LOCK: &str = ".at_rest.groups.lock.sqlite";

pub const MAX_GROUPS: usize = 64;
pub const MAX_MESSAGES_TOTAL: usize = 2_000;
pub const MAX_MESSAGE_BYTES_TOTAL: usize = 8 * 1024 * 1024;
/// Message keys kept per group after their messages left `messages`
/// ([`GroupRecord::seen`]): each until its message is older than
/// [`REPLAY_HORIZON_MS`]. A group at this many takes no new message until
/// some expire: a message that could still be replayed is never forgotten.
pub const MAX_SEEN_PER_GROUP: usize = 8_192;
/// A message whose `sent_ms` is older than this is refused (an old signed
/// message replayed after its id was forgotten is not taken as new); the
/// message horizon (7 days).
pub const REPLAY_HORIZON_MS: u64 = crate::horizon::MESSAGE_HORIZON_MS;
/// How far in this computer's future a message's `sent_ms` may be (clocks
/// differ); later is refused.
pub const MAX_FUTURE_SKEW_MS: u64 = 24 * 3_600_000;
pub const MAX_HELD_PER_GROUP: usize = 64;
pub const MAX_UNKNOWN_HELD: usize = 32;
pub const MAX_INTENTS_PER_GROUP: usize = 512;
/// Forwards of one author's messages that may wait per group (one member's
/// forward requests cannot evict every other pending intent): 15 authors at
/// most use under half of [`MAX_INTENTS_PER_GROUP`].
pub const MAX_FORWARDS_PER_AUTHOR: usize = 16;
pub const MAX_DONE_PER_GROUP: usize = 4_096;
pub const MAX_COPIES: usize = 8_192;
/// Held frames and intents end after the message horizon.
pub const WORK_TTL_MS: u64 = crate::horizon::MESSAGE_HORIZON_MS;

pub const STATUS_ACTIVE: &str = "active";
pub const STATUS_REMOVED: &str = "removed";
pub const STATUS_LEFT: &str = "left";

pub const LINE_WAITING: &str = "waiting";
pub const LINE_SENT: &str = "sent";
pub const LINE_DELIVERED: &str = "delivered";
pub const LINE_FAILED: &str = "failed";

pub const VIA_DIRECT: &str = "direct";
pub const VIA_RELAY: &str = "relay";

pub const INTENT_SEND: &str = "send";
pub const INTENT_RECEIPT: &str = "receipt";
pub const INTENT_LEAVER: &str = "leaver";

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
    /// Ids of messages that left `messages` (duplicate drop).
    #[serde(default)]
    pub seen: Vec<String>,
    #[serde(default)]
    pub held: Vec<Held>,
    #[serde(default)]
    pub intents: Vec<Intent>,
    /// Forwards and relayed receipts made (`<id>:<target>`, `r:<of>:<from>`).
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
    /// The member the copy goes to (send), the author (receipt) or the
    /// member who left (leaver).
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
    /// A forward's author (hex): forwards are counted per author
    /// ([`MAX_FORWARDS_PER_AUTHOR`]) and are the first to go when the
    /// intents are over their cap. Empty for every other intent.
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

/// The store as it is (empty without a file). Never written.
pub fn load(data_dir: &Path) -> Result<GroupsFile, GroupError> {
    let path = groups_path(data_dir);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() => {}
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

/// Read, change and write the store under its writer lock. A store that
/// cannot be read is never written over.
pub fn edit<T>(
    data_dir: &Path,
    change: impl FnOnce(&mut GroupsFile) -> Result<T, GroupError>,
) -> Result<T, GroupError> {
    let path = groups_path(data_dir);
    let lock = at_rest::lock_file(data_dir, &path, Kind::Groups).map_err(store_err)?;
    let mut file = match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() => lock
            .load_json::<GroupsFile>()
            .map_err(store_err)?
            .unwrap_or_default(),
        Ok(_) => {
            return Err(GroupError::Store(format!(
                "{GROUPS_FILE} is not a regular file"
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => GroupsFile::default(),
        Err(e) => return Err(store_err(e)),
    };
    let before = file.clone();
    let out = change(&mut file)?;
    if file != before {
        file.v = 1;
        file.enforce_caps();
        lock.store_json(&file).map_err(store_err)?;
    }
    Ok(out)
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

    /// Every bound of design §6: messages across groups (the oldest of the
    /// largest group first, its id remembered), ids seen, held frames,
    /// intents and markers.
    pub fn enforce_caps(&mut self) {
        let size = |m: &StoredMsg| m.body.len() + 256 + m.lines.len() * 200;
        let mut total: usize = self.groups.iter().map(|g| g.messages.len()).sum();
        let mut bytes: usize = self
            .groups
            .iter()
            .flat_map(|g| g.messages.iter())
            .map(size)
            .sum();
        while total > MAX_MESSAGES_TOTAL || bytes > MAX_MESSAGE_BYTES_TOTAL {
            let Some(g) = self
                .groups
                .iter_mut()
                .filter(|g| !g.messages.is_empty())
                .max_by_key(|g| g.messages.len())
            else {
                break;
            };
            let gone = g.messages.remove(0);
            bytes = bytes.saturating_sub(size(&gone));
            total -= 1;
            g.seen.push(format!(
                "{}@{}",
                seen_key(&gone.from, &gone.id),
                gone.sent_ms
            ));
        }
        for g in &mut self.groups {
            trim_front(&mut g.held, MAX_HELD_PER_GROUP);
            trim_intents(g);
            trim_front(&mut g.done, MAX_DONE_PER_GROUP);
            trim_front(&mut g.answered, super::MAX_GROUP_MEMBERS * 4);
            trim_front(&mut g.removed, super::MAX_GROUP_MEMBERS * 8);
        }
        trim_front(&mut self.unknown_held, MAX_UNKNOWN_HELD);
        trim_front(&mut self.copies, MAX_COPIES);
    }

    /// Held frames and intents past [`WORK_TTL_MS`] go.
    pub fn expire(&mut self, now_ms: u64) {
        let fresh = |at: u64| now_ms < at.saturating_add(WORK_TTL_MS);
        self.unknown_held.retain(|h| fresh(h.at_ms));
        for g in &mut self.groups {
            g.held.retain(|h| fresh(h.at_ms));
            // A message key goes once its message could no longer be taken
            // (older than the replay horizon); an entry without its time
            // (an older store) goes too.
            g.seen.retain(|s| {
                s.rsplit_once('@')
                    .and_then(|(_, at)| at.parse::<u64>().ok())
                    .is_some_and(|sent| now_ms < sent.saturating_add(REPLAY_HORIZON_MS))
            });
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
    while g.intents.len() > MAX_INTENTS_PER_GROUP {
        let at = g
            .intents
            .iter()
            .position(|i| !i.author.is_empty())
            .unwrap_or(0);
        let gone = g.intents.remove(at);
        if !gone.line_of.is_empty() {
            g.set_line(&gone.line_of, &gone.to, |line| {
                if line.state != LINE_DELIVERED {
                    line.state = LINE_FAILED.into();
                }
            });
        }
    }
}

fn trim_front<T>(list: &mut Vec<T>, max: usize) {
    if list.len() > max {
        let over = list.len() - max;
        list.drain(..over);
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
            seen: Vec::new(),
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

    /// Whether message `id` by `from` (both hex) is known here: a message is
    /// known by its author and its id, so a member who sends another author's
    /// message id first cannot have the real message dropped as a duplicate
    /// (and ACKed).
    pub fn has_seen(&self, from: &str, id: &str) -> bool {
        let key = seen_key(from, id);
        let at = format!("{key}@");
        self.messages.iter().any(|m| m.id == id && m.from == from)
            || self.seen.iter().any(|s| s.starts_with(&at))
    }

    /// No room for another message key ([`MAX_SEEN_PER_GROUP`]).
    pub fn seen_full(&self) -> bool {
        self.seen.len() >= MAX_SEEN_PER_GROUP
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

/// A message's entry in [`GroupRecord::seen`]: its author and id (hex).
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
        .filter_map(|g| summary(g, me.as_ref()))
        .collect();
    out.sort_by(|a, b| b.last_ms.cmp(&a.last_ms).then_with(|| a.name.cmp(&b.name)));
    Ok(out)
}

/// One group with its members (friend names from the contact book).
pub fn view(data_dir: &Path, id: &GroupId) -> Result<GroupView, GroupError> {
    let file = load(data_dir)?;
    let me = me_of(&file, data_dir);
    let g = file.group(id).ok_or(GroupError::NotFound)?;
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
    let g = file.group(id).ok_or(GroupError::NotFound)?;
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
                path: crate::arrivals::ArrivedVia::parse(&m.path),
            })
        })
        .collect())
}

/// Every message received up to `now_ms` is read.
pub fn mark_read(data_dir: &Path, id: &GroupId, now_ms: u64) -> Result<usize, GroupError> {
    edit(data_dir, |file| {
        let g = file.group_mut(id).ok_or(GroupError::NotFound)?;
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
    let ids: Vec<GroupId> = file
        .groups
        .iter()
        .filter_map(|g| hex_n::<16>(&g.id))
        .collect();
    if let Some(id) = ids.iter().find(|id| hex::encode(id) == lower) {
        return Ok(*id);
    }
    let by_name: Vec<GroupId> = file
        .groups
        .iter()
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
