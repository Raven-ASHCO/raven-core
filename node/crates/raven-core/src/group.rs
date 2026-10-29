//! Group messaging v1 (`docs/design/2026-10-groups.md`,
//! `protocol/RAVEN_GROUP_V1.md`): an `RVNGRP/1` frame is the ATSAM plaintext
//! of an ordinary indexed-session Message between two friends.
//!
//! - **Delivery** is pairwise fan-out: one sealed copy per member, each
//!   parked with the long message horizon's park step ([`park`]) and sealed
//!   by raven-node's outbox, so every carrier, custody, the session reset
//!   and the pairwise ACK work for groups unchanged.
//! - **Authorship** is signed with the author's identity key, so a member
//!   that is not the author's friend verifies a forwarded copy with the
//!   author's key from the admin-signed roster.
//! - **Forwarding** is one hop and bounded ([`rules`]): only a copy that came
//!   straight from its author, only to members on that copy's `relay` list
//!   who are the forwarder's friends.
//! - **Work later.** The receive path has no identity key and never dials:
//!   it records intents in the group store ([`store`]), and
//!   [`run_pending`] (raven-node's outbox scan, the CLI, the engine) turns
//!   them into parked copies.
//!
//! **Gate:** [`GROUPS_PRODUCTION_ENABLED`] was switched on in release builds
//! in 2026-10, after the three-machine field test (debug builds with the lab
//! switches on); not independently reviewed. A debug build closes it with
//! `RAVEN_LAB_GROUPS=0`. Groups need the horizon (every copy is parked).

use std::cell::Cell;
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::Identity;

pub mod park;
pub mod rules;
pub mod store;
#[cfg(test)]
mod tests;

pub use store::{GroupsFile, Line, StoredMsg};

/// Groups production gate (up to [`MAX_GROUP_MEMBERS`], the creator the only
/// admin). Switched on 2026-10 after the three-machine field test; not
/// independently reviewed.
pub const GROUPS_PRODUCTION_ENABLED: bool = true;
// Every copy is parked with the horizon's park step.
const _: () =
    assert!(!GROUPS_PRODUCTION_ENABLED || crate::horizon::LONG_HORIZON_PRODUCTION_ENABLED);

/// The groups' debug lab switch: "0" closes them
/// ([`crate::pair_init::lab_gate`]).
pub const LAB_GROUPS: &str = "RAVEN_LAB_GROUPS";

thread_local! {
    static GROUPS_LAB: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Groups are live: [`GROUPS_PRODUCTION_ENABLED`]; in a debug build this
/// thread's override decides, else `RAVEN_LAB_GROUPS` ("0" closes them,
/// [`crate::pair_init::lab_gate`]); always with the long message horizon
/// live; unless a security notice holds groups (close-only).
pub fn group_live_enabled() -> bool {
    let over = if cfg!(debug_assertions) {
        GROUPS_LAB.with(Cell::get)
    } else {
        None
    };
    over.unwrap_or_else(|| crate::pair_init::lab_gate(GROUPS_PRODUCTION_ENABLED, LAB_GROUPS))
        && crate::horizon::horizon_live_enabled()
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_GROUPS)
}

/// In-process tests switch groups on or off for the current thread only
/// (with [`crate::horizon::set_lab_horizon_for_this_thread`]); `None` goes
/// back to the const and the environment. Ignored in release builds.
#[doc(hidden)]
pub fn set_lab_groups_for_this_thread(on: Option<bool>) {
    GROUPS_LAB.with(|c| c.set(on));
}

/// This thread's override ([`set_lab_groups_for_this_thread`]), for test
/// helpers that pin it only where a test did not; `None` in a release build.
#[doc(hidden)]
pub fn lab_groups_for_this_thread() -> Option<bool> {
    if cfg!(debug_assertions) {
        GROUPS_LAB.with(Cell::get)
    } else {
        None
    }
}

pub const GROUP_FRAME_MAGIC: &str = "RVNGRP/1";
pub const GROUP_RESERVED_PREFIX: &str = "RVNGRP/";
/// Members of a group, the admin included (design §7).
pub const MAX_GROUP_MEMBERS: usize = 16;
pub const MAX_GROUP_BODY_BYTES: usize = 8 * 1024;
pub const MAX_GROUP_NAME_CHARS: usize = 64;
pub const MAX_MEMBER_LABEL_CHARS: usize = 64;
const MAX_HEADER_BYTES: usize = 16;
pub const MAX_GROUP_FRAME_BYTES: usize = crate::lan_noise::MAX_LAN_ENDPOINT_TEXT;
/// The largest time a frame may carry: JSON numbers stay exact in every
/// reader.
const MAX_TIME_MS: u64 = (1 << 53) - 1;

const DOMAIN_STATE: &[u8] = b"rvn1/group-state";
const DOMAIN_MSG: &[u8] = b"rvn1/group-msg";
const DOMAIN_RECEIPT: &[u8] = b"rvn1/group-receipt";
const DOMAIN_LEAVE: &[u8] = b"rvn1/group-leave";
const DOMAIN_GROUP_ID: &[u8] = b"rvn1/group-id";

/// Protocol §1: a group's id, `SHA-256(lp("rvn1/group-id") || admin ||
/// salt)[..16]`. Bound to the admin: nobody else can sign a roster for it
/// (security review 2026-10-29 #2: a member could claim a group's id at a
/// friend first and have the real admin's roster refused for good).
pub fn group_id_for(admin: &Key, salt: &[u8; 16]) -> GroupId {
    let mut h = Sha256::new();
    let mut domain = Vec::new();
    lp(&mut domain, DOMAIN_GROUP_ID);
    h.update(&domain);
    h.update(admin);
    h.update(salt);
    let digest = h.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

pub type Key = [u8; 32];
pub type GroupId = [u8; 16];

// ------------------------------------------------------------------ frames

/// One roster entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub key: Key,
    /// The admin's name for this member (0..=64 characters).
    pub label: String,
}

/// `state`: the roster, signed by the admin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupState {
    /// [`group_id_for`] of `admin` and `salt`: a group id names one admin
    /// for good (security review 2026-10-29 #2).
    pub group: GroupId,
    /// The admin's random salt for the group id.
    pub salt: [u8; 16],
    pub epoch: u32,
    pub name: String,
    pub admin: Key,
    pub issued_ms: u64,
    /// The admin first.
    pub members: Vec<Member>,
    pub sig: [u8; 64],
}

/// `msg`: a group message, signed by its author `from`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMsg {
    pub group: GroupId,
    pub id: [u8; 16],
    pub epoch: u32,
    pub from: Key,
    pub sent_ms: u64,
    pub body: String,
    pub sig: [u8; 64],
    /// Not signed: the members the author asks this one recipient to pass
    /// the message on to.
    pub relay: Vec<Key>,
}

/// `receipt`: `from` has message `of` by `to`, signed by `from`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupReceipt {
    pub group: GroupId,
    pub of: [u8; 16],
    pub epoch: u32,
    pub from: Key,
    pub to: Key,
    pub at_ms: u64,
    pub sig: [u8; 64],
    pub relay: Vec<Key>,
}

/// `leave`: `from` leaves the group, signed by `from`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupLeave {
    pub group: GroupId,
    pub epoch: u32,
    pub from: Key,
    pub at_ms: u64,
    pub sig: [u8; 64],
}

/// `sync`: "send me your roster" (to the admin; unsigned, the pairwise
/// session authenticates it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSync {
    pub group: GroupId,
    pub epoch: u32,
}

/// A parsed `RVNGRP/1` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupFrame {
    State(GroupState),
    Msg(GroupMsg),
    Receipt(GroupReceipt),
    Leave(GroupLeave),
    Sync(GroupSync),
}

fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&bytes[..usize::from(len)]);
}

impl GroupState {
    /// Protocol §3.1.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.members.len() * 48);
        lp(&mut out, DOMAIN_STATE);
        out.extend_from_slice(&self.group);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.admin);
        out.extend_from_slice(&self.issued_ms.to_be_bytes());
        lp(&mut out, self.name.as_bytes());
        let n = u16::try_from(self.members.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&n.to_be_bytes());
        for m in &self.members {
            out.extend_from_slice(&m.key);
            lp(&mut out, m.label.as_bytes());
        }
        out
    }

    pub fn sign(&mut self, admin: &Identity) {
        self.admin = admin.public_key_bytes();
        self.sig = admin.sign(&self.signing_bytes());
    }

    /// Well formed (§1) and signed by `admin`.
    pub fn verify(&self) -> bool {
        self.well_formed() && Identity::verify(&self.admin, &self.signing_bytes(), &self.sig)
    }

    /// Protocol §1: the id is the admin's ([`group_id_for`]), 1..=16
    /// members, the admin first, distinct keys, a valid name and labels,
    /// epoch at least 1.
    pub fn well_formed(&self) -> bool {
        let mut keys = HashSet::new();
        self.group == group_id_for(&self.admin, &self.salt)
            && self.epoch >= 1
            && self.issued_ms <= MAX_TIME_MS
            && name_ok(&self.name)
            && (1..=MAX_GROUP_MEMBERS).contains(&self.members.len())
            && self.members.first().is_some_and(|m| m.key == self.admin)
            && self
                .members
                .iter()
                .all(|m| label_ok(&m.label) && keys.insert(m.key))
    }

    pub fn has(&self, key: &Key) -> bool {
        self.members.iter().any(|m| m.key == *key)
    }

    pub fn label_of(&self, key: &Key) -> Option<&str> {
        self.members
            .iter()
            .find(|m| m.key == *key)
            .map(|m| m.label.as_str())
    }
}

impl GroupMsg {
    /// Protocol §3.2.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        lp(&mut out, DOMAIN_MSG);
        out.extend_from_slice(&self.group);
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.from);
        out.extend_from_slice(&self.sent_ms.to_be_bytes());
        out.extend_from_slice(&Sha256::digest(self.body.as_bytes()));
        out
    }

    pub fn sign(&mut self, author: &Identity) {
        self.from = author.public_key_bytes();
        self.sig = author.sign(&self.signing_bytes());
    }

    /// Signed by `from` (the caller checks `from` is a member).
    pub fn verify(&self) -> bool {
        body_ok(&self.body)
            && self.sent_ms <= MAX_TIME_MS
            && Identity::verify(&self.from, &self.signing_bytes(), &self.sig)
    }
}

impl GroupReceipt {
    /// Protocol §3.3.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        lp(&mut out, DOMAIN_RECEIPT);
        out.extend_from_slice(&self.group);
        out.extend_from_slice(&self.of);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.from);
        out.extend_from_slice(&self.to);
        out.extend_from_slice(&self.at_ms.to_be_bytes());
        out
    }

    pub fn sign(&mut self, member: &Identity) {
        self.from = member.public_key_bytes();
        self.sig = member.sign(&self.signing_bytes());
    }

    pub fn verify(&self) -> bool {
        self.at_ms <= MAX_TIME_MS && Identity::verify(&self.from, &self.signing_bytes(), &self.sig)
    }
}

impl GroupLeave {
    /// Protocol §3.4.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        lp(&mut out, DOMAIN_LEAVE);
        out.extend_from_slice(&self.group);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.from);
        out.extend_from_slice(&self.at_ms.to_be_bytes());
        out
    }

    pub fn sign(&mut self, member: &Identity) {
        self.from = member.public_key_bytes();
        self.sig = member.sign(&self.signing_bytes());
    }

    pub fn verify(&self) -> bool {
        self.at_ms <= MAX_TIME_MS && Identity::verify(&self.from, &self.signing_bytes(), &self.sig)
    }
}

impl GroupFrame {
    pub fn group(&self) -> &GroupId {
        match self {
            GroupFrame::State(s) => &s.group,
            GroupFrame::Msg(m) => &m.group,
            GroupFrame::Receipt(r) => &r.group,
            GroupFrame::Leave(l) => &l.group,
            GroupFrame::Sync(s) => &s.group,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            GroupFrame::State(_) => "state",
            GroupFrame::Msg(_) => "msg",
            GroupFrame::Receipt(_) => "receipt",
            GroupFrame::Leave(_) => "leave",
            GroupFrame::Sync(_) => "sync",
        }
    }

    /// `RVNGRP/1 <kind>\n<json>`.
    pub fn encode(&self) -> String {
        let json = match self {
            GroupFrame::State(s) => serde_json::to_string(&wire::StateWire::from(s)),
            GroupFrame::Msg(m) => serde_json::to_string(&wire::MsgWire::from(m)),
            GroupFrame::Receipt(r) => serde_json::to_string(&wire::ReceiptWire::from(r)),
            GroupFrame::Leave(l) => serde_json::to_string(&wire::LeaveWire::from(l)),
            GroupFrame::Sync(s) => serde_json::to_string(&wire::SyncWire::from(s)),
        }
        .unwrap_or_default();
        format!("{GROUP_FRAME_MAGIC} {}\n{json}", self.kind())
    }
}

/// Does `plaintext` start with the reserved `RVNGRP/` prefix?
pub fn is_group_text(plaintext: &[u8]) -> bool {
    plaintext.starts_with(GROUP_RESERVED_PREFIX.as_bytes())
}

/// Strict parse of a group frame (§1, §2); `None` for anything else,
/// including every other `RVNGRP/` text.
pub fn parse_frame(plaintext: &[u8]) -> Option<GroupFrame> {
    if plaintext.len() > MAX_GROUP_FRAME_BYTES {
        return None;
    }
    let lf = plaintext.iter().position(|b| *b == b'\n')?;
    if lf > MAX_HEADER_BYTES {
        return None;
    }
    let header = std::str::from_utf8(&plaintext[..lf]).ok()?;
    let (magic, kind) = header.split_once(' ')?;
    if magic != GROUP_FRAME_MAGIC {
        return None;
    }
    let json = std::str::from_utf8(&plaintext[lf + 1..]).ok()?;
    let frame = match kind {
        "state" => GroupFrame::State(
            serde_json::from_str::<wire::StateWire>(json)
                .ok()?
                .typed()?,
        ),
        "msg" => GroupFrame::Msg(serde_json::from_str::<wire::MsgWire>(json).ok()?.typed()?),
        "receipt" => GroupFrame::Receipt(
            serde_json::from_str::<wire::ReceiptWire>(json)
                .ok()?
                .typed()?,
        ),
        "leave" => GroupFrame::Leave(
            serde_json::from_str::<wire::LeaveWire>(json)
                .ok()?
                .typed()?,
        ),
        "sync" => GroupFrame::Sync(serde_json::from_str::<wire::SyncWire>(json).ok()?.typed()?),
        _ => return None,
    };
    Some(frame)
}

/// The JSON forms (§2): lowercase hex for every binary value.
pub mod wire {
    use super::*;

    pub fn hex_n<const N: usize>(s: &str) -> Option<[u8; N]> {
        if s.len() != 2 * N || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        let mut out = [0u8; N];
        hex::decode_to_slice(s, &mut out).ok()?;
        Some(out)
    }

    fn keys(list: &[String], max: usize) -> Option<Vec<Key>> {
        if list.len() > max {
            return None;
        }
        let mut seen = HashSet::new();
        list.iter()
            .map(|k| hex_n::<32>(k).filter(|k| seen.insert(*k)))
            .collect()
    }

    fn hex_keys(list: &[Key]) -> Vec<String> {
        list.iter().map(hex::encode).collect()
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct MemberWire {
        pub key: String,
        pub label: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct StateWire {
        pub group: String,
        #[serde(default)]
        pub salt: String,
        pub epoch: u32,
        pub name: String,
        pub admin: String,
        pub issued_ms: u64,
        pub members: Vec<MemberWire>,
        pub sig: String,
    }

    impl From<&GroupState> for StateWire {
        fn from(s: &GroupState) -> Self {
            StateWire {
                group: hex::encode(s.group),
                salt: hex::encode(s.salt),
                epoch: s.epoch,
                name: s.name.clone(),
                admin: hex::encode(s.admin),
                issued_ms: s.issued_ms,
                members: s
                    .members
                    .iter()
                    .map(|m| MemberWire {
                        key: hex::encode(m.key),
                        label: m.label.clone(),
                    })
                    .collect(),
                sig: hex::encode(s.sig),
            }
        }
    }

    impl StateWire {
        pub fn typed(&self) -> Option<GroupState> {
            if self.members.len() > MAX_GROUP_MEMBERS {
                return None;
            }
            let members = self
                .members
                .iter()
                .map(|m| {
                    Some(Member {
                        key: hex_n(&m.key)?,
                        label: m.label.clone(),
                    })
                })
                .collect::<Option<Vec<_>>>()?;
            let state = GroupState {
                group: hex_n(&self.group)?,
                salt: hex_n(&self.salt)?,
                epoch: self.epoch,
                name: self.name.clone(),
                admin: hex_n(&self.admin)?,
                issued_ms: self.issued_ms,
                members,
                sig: hex_n(&self.sig)?,
            };
            state.well_formed().then_some(state)
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct MsgWire {
        pub group: String,
        pub id: String,
        pub epoch: u32,
        pub from: String,
        pub sent_ms: u64,
        pub body: String,
        pub sig: String,
        pub relay: Vec<String>,
    }

    impl From<&GroupMsg> for MsgWire {
        fn from(m: &GroupMsg) -> Self {
            MsgWire {
                group: hex::encode(m.group),
                id: hex::encode(m.id),
                epoch: m.epoch,
                from: hex::encode(m.from),
                sent_ms: m.sent_ms,
                body: m.body.clone(),
                sig: hex::encode(m.sig),
                relay: hex_keys(&m.relay),
            }
        }
    }

    impl MsgWire {
        pub fn typed(&self) -> Option<GroupMsg> {
            let msg = GroupMsg {
                group: hex_n(&self.group)?,
                id: hex_n(&self.id)?,
                epoch: self.epoch,
                from: hex_n(&self.from)?,
                sent_ms: self.sent_ms,
                body: self.body.clone(),
                sig: hex_n(&self.sig)?,
                relay: keys(&self.relay, MAX_GROUP_MEMBERS - 1)?,
            };
            (msg.epoch >= 1 && msg.sent_ms <= MAX_TIME_MS && body_ok(&msg.body)).then_some(msg)
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct ReceiptWire {
        pub group: String,
        pub of: String,
        pub epoch: u32,
        pub from: String,
        pub to: String,
        pub at_ms: u64,
        pub sig: String,
        pub relay: Vec<String>,
    }

    impl From<&GroupReceipt> for ReceiptWire {
        fn from(r: &GroupReceipt) -> Self {
            ReceiptWire {
                group: hex::encode(r.group),
                of: hex::encode(r.of),
                epoch: r.epoch,
                from: hex::encode(r.from),
                to: hex::encode(r.to),
                at_ms: r.at_ms,
                sig: hex::encode(r.sig),
                relay: hex_keys(&r.relay),
            }
        }
    }

    impl ReceiptWire {
        pub fn typed(&self) -> Option<GroupReceipt> {
            let r = GroupReceipt {
                group: hex_n(&self.group)?,
                of: hex_n(&self.of)?,
                epoch: self.epoch,
                from: hex_n(&self.from)?,
                to: hex_n(&self.to)?,
                at_ms: self.at_ms,
                sig: hex_n(&self.sig)?,
                relay: keys(&self.relay, MAX_GROUP_MEMBERS - 1)?,
            };
            (r.epoch >= 1 && r.at_ms <= MAX_TIME_MS).then_some(r)
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct LeaveWire {
        pub group: String,
        pub epoch: u32,
        pub from: String,
        pub at_ms: u64,
        pub sig: String,
    }

    impl From<&GroupLeave> for LeaveWire {
        fn from(l: &GroupLeave) -> Self {
            LeaveWire {
                group: hex::encode(l.group),
                epoch: l.epoch,
                from: hex::encode(l.from),
                at_ms: l.at_ms,
                sig: hex::encode(l.sig),
            }
        }
    }

    impl LeaveWire {
        pub fn typed(&self) -> Option<GroupLeave> {
            let l = GroupLeave {
                group: hex_n(&self.group)?,
                epoch: self.epoch,
                from: hex_n(&self.from)?,
                at_ms: self.at_ms,
                sig: hex_n(&self.sig)?,
            };
            (l.epoch >= 1 && l.at_ms <= MAX_TIME_MS).then_some(l)
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct SyncWire {
        pub group: String,
        pub epoch: u32,
    }

    impl From<&GroupSync> for SyncWire {
        fn from(s: &GroupSync) -> Self {
            SyncWire {
                group: hex::encode(s.group),
                epoch: s.epoch,
            }
        }
    }

    impl SyncWire {
        pub fn typed(&self) -> Option<GroupSync> {
            Some(GroupSync {
                group: hex_n(&self.group)?,
                epoch: self.epoch,
            })
        }
    }
}

// ------------------------------------------------------------------ text rules

fn no_control(c: char) -> bool {
    c >= '\u{20}' && c != '\u{7f}'
}

/// A group name: 1..=64 characters, no control character, no space at
/// either end.
pub fn name_ok(name: &str) -> bool {
    let n = name.chars().count();
    (1..=MAX_GROUP_NAME_CHARS).contains(&n) && name.chars().all(no_control) && name.trim() == name
}

/// A member label: 0..=64 characters, the name rules otherwise.
pub fn label_ok(label: &str) -> bool {
    label.is_empty()
        || (label.chars().count() <= MAX_MEMBER_LABEL_CHARS
            && label.chars().all(no_control)
            && label.trim() == label)
}

/// A message body: 1..=8,192 bytes of endpoint text, not only white space.
pub fn body_ok(body: &str) -> bool {
    !body.trim().is_empty()
        && body.len() <= MAX_GROUP_BODY_BYTES
        && body
            .chars()
            .all(|c| matches!(c, '\t' | '\n' | '\r') || no_control(c))
}

/// A name or label as the CLI and the apps take it: control characters out,
/// trimmed, cut at the limit.
pub fn clean_text(text: &str, max_chars: usize) -> String {
    let kept: String = text.chars().filter(|c| no_control(*c)).collect();
    kept.trim()
        .chars()
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_owned()
}

// ------------------------------------------------------------------ errors

/// Why a group operation was refused. [`GroupError::code`] is the stable
/// token (`protocol/RAVEN_ERROR_CODES_V1.md`, `GROUP_*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupError {
    /// The gate is closed in this build.
    Hold,
    NotFound,
    /// Several groups match the name or id prefix.
    Ambiguous,
    NotAdmin,
    /// This profile left the group or was removed.
    NotMember,
    TooMany,
    /// A member to add is not a current, unblocked friend.
    NotAFriend(Key),
    AlreadyMember(Key),
    BadName,
    BadBody,
    AdminCannotLeave,
    /// Too many copies wait already (the friend's queue or the groups'
    /// share of the outbound stage).
    QueueFull,
    /// No member of the group is this profile's friend.
    NoRoute,
    /// No identity yet.
    NoIdentity,
    Store(String),
}

impl GroupError {
    pub fn code(&self) -> &'static str {
        match self {
            GroupError::Hold => "GROUP_HOLD",
            GroupError::NotFound => "GROUP_NOT_FOUND",
            GroupError::Ambiguous => "GROUP_AMBIGUOUS",
            GroupError::NotAdmin => "GROUP_NOT_ADMIN",
            GroupError::NotMember => "GROUP_NOT_MEMBER",
            GroupError::TooMany => "GROUP_TOO_LARGE",
            GroupError::NotAFriend(_) => "GROUP_NOT_A_FRIEND",
            GroupError::AlreadyMember(_) => "GROUP_ALREADY_MEMBER",
            GroupError::BadName => "GROUP_BAD_NAME",
            GroupError::BadBody => "GROUP_BAD_BODY",
            GroupError::AdminCannotLeave => "GROUP_ADMIN_CANNOT_LEAVE",
            GroupError::QueueFull => "GROUP_QUEUE_FULL",
            GroupError::NoRoute => "GROUP_NO_ROUTE",
            GroupError::NoIdentity => "GROUP_NO_IDENTITY",
            GroupError::Store(_) => "GROUP_STORE",
        }
    }

    /// A plain sentence (no key, no id).
    pub fn sentence(&self) -> String {
        match self {
            GroupError::Hold => format!(
                "Groups are not part of this build yet (lab: a debug build with RAVEN_LAB_TEST_A=1, \
                 RAVEN_LAB_HORIZON=1 and {LAB_GROUPS}=1)."
            ),
            GroupError::NotFound => "No group by that name or id.".into(),
            GroupError::Ambiguous => {
                "More than one group matches; use more of its id (raven group list).".into()
            }
            GroupError::NotAdmin => "Only the group's admin can change who is in it.".into(),
            GroupError::NotMember => "You are no longer in this group.".into(),
            GroupError::TooMany => {
                format!("A group has at most {MAX_GROUP_MEMBERS} members, you included.")
            }
            GroupError::NotAFriend(_) => {
                "Only your friends can be added (a saved contact you have not blocked).".into()
            }
            GroupError::AlreadyMember(_) => "That friend is in the group already.".into(),
            GroupError::BadName => format!(
                "A group name has 1 to {MAX_GROUP_NAME_CHARS} characters and no control characters."
            ),
            GroupError::BadBody => format!(
                "A group message has 1 to {MAX_GROUP_BODY_BYTES} bytes of text and no control \
                 characters."
            ),
            GroupError::AdminCannotLeave => {
                "The admin can't leave the group; remove the others instead.".into()
            }
            GroupError::QueueFull => {
                "Too many group messages are still waiting to go out; try again once some are \
                 delivered."
                    .into()
            }
            GroupError::NoRoute => {
                "None of the other members is your friend, so nobody can pass it on.".into()
            }
            GroupError::NoIdentity => "Create your identity first (raven init).".into(),
            GroupError::Store(_) => "The group store could not be read or written.".into(),
        }
    }
}

impl std::fmt::Display for GroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GroupError::Store(detail) => {
                write!(f, "{}: {} ({detail})", self.code(), self.sentence())
            }
            _ => write!(f, "{}: {}", self.code(), self.sentence()),
        }
    }
}

// ------------------------------------------------------------------ work notifier

static NOTIFIER: OnceLock<fn()> = OnceLock::new();

/// raven-node registers how a receive that recorded work asks for an outbox
/// scan (which runs [`run_pending`]). Set once per process.
pub fn set_work_notifier(notify: fn()) {
    let _ = NOTIFIER.set(notify);
}

pub(crate) fn notify_work() {
    if let Some(notify) = NOTIFIER.get() {
        notify();
    }
}

/// This profile's identity key, read without the seed: the primary device
/// certificate's user key (a profile that took a message has one).
pub fn local_identity_key(data_dir: &Path) -> Option<Key> {
    let registry = crate::device_cert::load_device_registry_checked(data_dir).ok()?;
    registry
        .certs
        .get(crate::paths::PRIMARY_DEVICE_ID)
        .map(|cert| cert.user_ed_pub)
}

/// The current, unblocked friends (identity keys), as
/// [`crate::outbox::admitted_contact_keys`] reads them; an unreadable book
/// is no friend.
pub fn friend_keys(data_dir: &Path) -> HashSet<Key> {
    crate::outbox::admitted_contact_keys(data_dir)
        .unwrap_or_default()
        .iter()
        .filter_map(|k| wire::hex_n::<32>(k))
        .collect()
}

/// The petnames of this profile's friends, by key (empty for an unreadable
/// book): what a group view shows for a member who is a friend.
pub fn friend_names(data_dir: &Path) -> std::collections::HashMap<Key, String> {
    #[derive(Deserialize)]
    struct Row {
        #[serde(default)]
        pub_hex: String,
        #[serde(default)]
        petname: String,
    }
    crate::contact_book::read_rows::<Row>(data_dir)
        .ok()
        .flatten()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| {
            let key = wire::hex_n::<32>(r.pub_hex.trim().to_ascii_lowercase().as_str())?;
            Some((key, r.petname))
        })
        .collect()
}

// ------------------------------------------------------------------ receive

/// After commit: the frame `frame` arrived on the session `key` from the
/// friend's device `sender_device`. The carrier peer is the session-bound
/// certificate's user key, never a link bundle. `Ok(true)`: handled (stored,
/// held, or dropped as invalid: ACK it); `Ok(false)`: the store could not
/// take it now (no ACK; the endpoint row stays and a retry or the archive
/// brings it back).
pub fn deliver(
    data_dir: &Path,
    sessions: &mut crate::indexed_session_store::IndexedSessionStore,
    key: &crate::indexed_session_store::IndexedSessionRecordKey,
    sender_device: &[u8; 32],
    frame: &GroupFrame,
    now_ms: u64,
) -> Result<bool, String> {
    let Some(cert) = crate::lan_dispatch::session_bound_peer_certificate(
        data_dir,
        sessions,
        key,
        sender_device,
    )?
    else {
        return Ok(false);
    };
    Ok(ingest(data_dir, &cert.user_ed_pub, frame, now_ms).is_ok())
}

/// Apply one received frame from the carrier peer `peer` to the group store
/// (protocol §4.2). Asks raven-node for a scan when it left work.
pub fn ingest(
    data_dir: &Path,
    peer: &Key,
    frame: &GroupFrame,
    now_ms: u64,
) -> Result<(), GroupError> {
    let me = local_identity_key(data_dir).ok_or(GroupError::NoIdentity)?;
    let friends = friend_keys(data_dir);
    let work = store::edit(data_dir, |file| {
        file.note_me(&me);
        Ok(rules::apply(file, &me, peer, frame, &friends, now_ms).work)
    })?;
    if work {
        notify_work();
    }
    Ok(())
}

pub use park::{process_intents, refresh_deliveries, run_pending, Pending};
pub use rules::{add_members, create, leave, remove_members, send, SendReport};
pub use store::{
    find, history, list, mark_read, view, GroupSummary, GroupView, MemberView, MessageView,
};

/// A copy this profile parked (its own message's, a forward, a receipt, a
/// roster) changed delivery after its chat-history row was deleted:
/// `Ok(true)` when it is a group copy (so a missing history row is not an
/// error), with the line of an own message updated.
pub fn mark_copy(data_dir: &Path, message_id: &[u8; 16], delivery: &str) -> Result<bool, String> {
    if !store::groups_path(data_dir).exists() {
        return Ok(false);
    }
    let mid = hex::encode(message_id);
    store::edit(data_dir, |file| Ok(file.mark_copy(&mid, delivery))).map_err(|e| e.to_string())
}
