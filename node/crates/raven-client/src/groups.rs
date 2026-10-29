//! Group chats in the engine (desktop/api/API.md, "Groups"): the `groups.*`
//! operations over raven-core's group store (`raven_core::group`, the same
//! code `raven group` runs), and the `group_message` / `group_changed`
//! events the watcher makes from the store.
//!
//! Lab only: with raven-core's gate closed `groups.list` says
//! `available: false` and every other op is NOT_AVAILABLE_YET, nothing
//! read or written. Members are named by Raven address; a friend by this
//! profile's name for them, anyone else by the admin's label.

use std::collections::{HashMap, HashSet};

use ash_engine::engine as bridge;
use raven_core::group::{
    self, GroupError, GroupId, GroupSummary, GroupView, Key, MessageView, MAX_GROUP_BODY_BYTES,
};
use serde_json::{json, Map, Value};

use crate::engine::{lock, now_ms, Inner, Stamp};
use crate::envelope::{code, ApiError, Args, OpResult};
use crate::safety;

/// `groups.history`'s default and largest page.
const HISTORY_DEFAULT: usize = 100;
const HISTORY_MAX: usize = 500;

/// What the watcher last saw of the group store.
#[derive(Default)]
pub(crate) struct GroupWatch {
    stamp: Option<Stamp>,
    /// The first look only notes what is there.
    looked: bool,
    /// Message ids seen, by group.
    seen: HashSet<(GroupId, [u8; 16])>,
    /// A digest of what a group shows (roster, status, unread, receipts).
    shown: HashMap<GroupId, String>,
}

fn group_error(e: GroupError) -> ApiError {
    let (c, message): (&'static str, &str) = match &e {
        GroupError::Hold => (code::NOT_AVAILABLE_YET, ""),
        GroupError::NotFound => (
            "GROUP_NOT_FOUND",
            "That group isn't on this computer any more.",
        ),
        GroupError::Ambiguous => (
            "GROUP_NOT_FOUND",
            "That group isn't on this computer any more.",
        ),
        GroupError::NotAdmin => (
            "GROUP_NOT_ADMIN",
            "Only the group's admin can add or remove members.",
        ),
        GroupError::NotMember => (
            "GROUP_NOT_MEMBER",
            "You're no longer in this group, so nothing can be sent to it.",
        ),
        GroupError::TooMany => (
            "GROUP_TOO_LARGE",
            "A group has at most 16 members, you included.",
        ),
        GroupError::NotAFriend(_) => (code::NOT_A_CONTACT, ""),
        GroupError::AlreadyMember(_) => (
            "GROUP_ALREADY_MEMBER",
            "That friend is in the group already.",
        ),
        GroupError::BadName => (
            "GROUP_BAD_NAME",
            "Give the group a name of 1 to 64 characters.",
        ),
        GroupError::BadBody => (code::MESSAGE_TOO_LONG, ""),
        GroupError::AdminCannotLeave => (
            "GROUP_ADMIN_CANNOT_LEAVE",
            "The admin can't leave the group. Remove the other members instead.",
        ),
        GroupError::QueueFull => (
            "GROUP_QUEUE_FULL",
            "Too many group messages are still waiting to go out. Try again once some are \
             delivered.",
        ),
        GroupError::NoRoute => (
            "GROUP_NO_ROUTE",
            "None of the other members is your friend, so nobody can pass it on.",
        ),
        GroupError::NoIdentity => (code::NOT_INITIALIZED, ""),
        GroupError::Store(_) => (code::PROFILE_UNREADABLE, ""),
    };
    if message.is_empty() {
        ApiError::of(c, e.to_string())
    } else {
        ApiError::new(c, message, e.to_string())
    }
}

fn gate() -> Result<(), ApiError> {
    if group::group_live_enabled() {
        Ok(())
    } else {
        Err(group_error(GroupError::Hold))
    }
}

fn group_arg(args: &Args) -> Result<GroupId, ApiError> {
    let raw = args.str("group")?.trim().to_ascii_lowercase();
    group::wire::hex_n::<16>(&raw)
        .ok_or_else(|| ApiError::bad_request("\"group\" must be a group id (32 hex characters)"))
}

fn short_id(id: &GroupId) -> String {
    hex::encode(&id[..4])
}

fn short_address(address: &str) -> String {
    let chars: Vec<char> = address.chars().collect();
    if chars.len() <= 14 {
        return address.to_owned();
    }
    let head: String = chars[..8].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}\u{2026}{tail}")
}

/// Names the engine shows: friends by this profile's name, this profile as
/// its display name (else "You").
struct Names {
    friends: HashMap<Key, String>,
    me: String,
}

impl Names {
    fn of(&self, view: &GroupView, key: &Key) -> String {
        if let Some(m) = view.member(key) {
            if m.me {
                return self.me.clone();
            }
        }
        if let Some(name) = self.friends.get(key) {
            return name.clone();
        }
        let shown = view.name_of(key, &HashMap::new());
        safety::line(&shown)
    }
}

impl Inner {
    fn group_names(&self) -> Result<Names, ApiError> {
        let contacts = self.contacts()?;
        let friends = contacts
            .iter()
            .filter(|c| !c.blocked)
            .filter_map(|c| {
                let key = group::wire::hex_n::<32>(&c.pub_hex.trim().to_ascii_lowercase())?;
                Some((key, safety::line(&c.label)))
            })
            .collect();
        let me = self
            .settings_view()
            .display_name
            .map(|n| safety::line(&n))
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| "You".to_owned());
        Ok(Names { friends, me })
    }

    /// A friend's key from its address: NOT_A_CONTACT for anyone else
    /// (blocked friends included).
    fn friend_key(&self, address: &str) -> Result<(Key, String), ApiError> {
        let contacts = self.contacts()?;
        let want = address.trim();
        let c = contacts
            .iter()
            .find(|c| c.address == want)
            .ok_or_else(|| ApiError::of(code::NOT_A_CONTACT, format!("no friend {want}")))?;
        if c.blocked {
            return Err(ApiError::of(code::CONTACT_BLOCKED, "blocked"));
        }
        let key = group::wire::hex_n::<32>(&c.pub_hex.trim().to_ascii_lowercase())
            .ok_or_else(|| ApiError::of(code::NOT_A_CONTACT, "no valid key saved"))?;
        Ok((key, c.petname.clone()))
    }

    fn group_json(&self, s: &GroupSummary, view: Option<&GroupView>, names: &Names) -> Value {
        let mut map = Map::new();
        map.insert("id".into(), hex::encode(s.id).into());
        map.insert("name".into(), safety::line(&s.name).into());
        map.insert("short_id".into(), short_id(&s.id).into());
        map.insert("status".into(), s.status.clone().into());
        map.insert("admin".into(), s.i_am_admin.into());
        map.insert(
            "admin_address".into(),
            raven_core::encode_address(&s.admin).into(),
        );
        let admin_name = match view {
            Some(v) => names.of(v, &s.admin),
            None => names
                .friends
                .get(&s.admin)
                .cloned()
                .unwrap_or_else(|| short_address(&raven_core::encode_address(&s.admin))),
        };
        map.insert("admin_name".into(), admin_name.into());
        map.insert("members".into(), s.members.into());
        map.insert("unread".into(), s.unread.into());
        if let Some((from, text)) = &s.last {
            map.insert("last_ms".into(), s.last_ms.into());
            map.insert("last_text".into(), safety::line(text).into());
            let who = match view {
                Some(v) => names.of(v, from),
                None => names.friends.get(from).cloned().unwrap_or_default(),
            };
            map.insert("last_from".into(), who.into());
        }
        Value::Object(map)
    }

    fn members_json(&self, view: &GroupView, names: &Names) -> Value {
        Value::Array(
            view.members
                .iter()
                .map(|m| {
                    let address = raven_core::encode_address(&m.key);
                    json!({
                        "address": address,
                        "short_address": short_address(&address),
                        "name": names.of(view, &m.key),
                        "label": safety::line(&m.label),
                        "friend": names.friends.contains_key(&m.key),
                        "admin": m.admin,
                        "me": m.me,
                    })
                })
                .collect(),
        )
    }

    fn message_json(
        &self,
        id: &GroupId,
        view: &GroupView,
        m: &MessageView,
        names: &Names,
    ) -> Value {
        let mut map = Map::new();
        map.insert("id".into(), hex::encode(m.id).into());
        map.insert("group".into(), hex::encode(id).into());
        map.insert(
            "from_address".into(),
            raven_core::encode_address(&m.from).into(),
        );
        map.insert(
            "from_name".into(),
            if m.mine {
                names.me.clone()
            } else {
                names.of(view, &m.from)
            }
            .into(),
        );
        map.insert("mine".into(), m.mine.into());
        map.insert("text".into(), safety::text(&m.body).into());
        map.insert(
            "at_ms".into(),
            (if m.mine { m.sent_ms } else { m.received_ms }).into(),
        );
        if let Some(via) = &m.via {
            map.insert("via_name".into(), names.of(view, via).into());
        }
        map.insert("delivered".into(), m.delivered.into());
        map.insert("total".into(), m.total.into());
        if m.mine {
            let receipts: Vec<Value> = m
                .lines
                .iter()
                .map(|(key, state, via)| {
                    json!({
                        "address": raven_core::encode_address(key),
                        "name": names.of(view, key),
                        "state": state,
                        "via": via,
                    })
                })
                .collect();
            map.insert("receipts".into(), receipts.into());
        }
        Value::Object(map)
    }

    /// `{group, members}` for one group.
    fn group_with_members(&self, id: &GroupId) -> OpResult {
        let dir = self.data_dir()?;
        let view = group::view(dir, id).map_err(group_error)?;
        let names = self.group_names()?;
        Ok(json!({
            "group": self.group_json(&view.summary, Some(&view), &names),
            "members": self.members_json(&view, &names),
        }))
    }

    /// raven-node sends what was parked: kicked, and started first when
    /// none runs (as a send starts it). A start that fails leaves the
    /// copies waiting; the note says why.
    fn deliver_parked(&self) -> Option<String> {
        let dir = self.data_dir().ok()?;
        if bridge::outbox_kick_all(dir) {
            return None;
        }
        match self.ensure_node_for_send() {
            Ok(()) if bridge::outbox_kick_all(dir) => None,
            Ok(()) => {
                Some("raven-node did not take the kick; it sends them at its next look".into())
            }
            Err(why) => Some(why),
        }
    }

    /// The identity and the copies' latest delivery (raven-node's scan does
    /// the same; this one makes a view current).
    fn group_identity(&self) -> Result<std::sync::Arc<raven_core::identity::Identity>, ApiError> {
        let id = self.identity()?;
        if let Ok(dir) = self.data_dir() {
            let _ = group::run_pending(dir, &id, now_ms());
        }
        Ok(id)
    }

    pub(crate) fn groups_list(&self) -> OpResult {
        let dir = self.data_dir()?;
        let available = group::group_live_enabled();
        if !available {
            return Ok(json!({"available": false, "groups": []}));
        }
        self.group_identity()?;
        let names = self.group_names()?;
        let groups: Vec<Value> = group::list(dir)
            .map_err(group_error)?
            .iter()
            .map(|s| {
                let view = group::view(dir, &s.id).ok();
                self.group_json(s, view.as_ref(), &names)
            })
            .collect();
        Ok(json!({"available": true, "groups": groups}))
    }

    pub(crate) fn groups_get(&self, args: &Args) -> OpResult {
        gate()?;
        let id = group_arg(args)?;
        self.group_identity()?;
        self.group_with_members(&id)
    }

    pub(crate) fn groups_create(&self, args: &Args) -> OpResult {
        gate()?;
        let name = group::clean_text(args.str("name")?, group::MAX_GROUP_NAME_CHARS);
        let list = self.member_list(args)?;
        if list.is_empty() {
            return Err(ApiError::bad_request("\"members\" names no friend"));
        }
        let me = self.identity()?;
        let dir = self.data_dir()?;
        let id = group::create(dir, &me, &name, &list, now_ms()).map_err(group_error)?;
        let out = self.group_with_members(&id)?;
        let _ = self.deliver_parked();
        self.note_groups_seen();
        Ok(out)
    }

    fn member_list(&self, args: &Args) -> Result<Vec<(Key, String)>, ApiError> {
        let Some(Value::Array(items)) = args.get("members") else {
            return Err(ApiError::bad_request(
                "\"members\" must be a list of addresses",
            ));
        };
        let mut out: Vec<(Key, String)> = Vec::new();
        for item in items {
            let address = item
                .as_str()
                .ok_or_else(|| ApiError::bad_request("\"members\" must be a list of addresses"))?;
            let (key, name) = self.friend_key(address)?;
            if !out.iter().any(|(k, _)| *k == key) {
                out.push((key, name));
            }
        }
        Ok(out)
    }

    pub(crate) fn groups_add(&self, args: &Args) -> OpResult {
        gate()?;
        let id = group_arg(args)?;
        let list = self.member_list(args)?;
        let me = self.identity()?;
        group::add_members(self.data_dir()?, &me, &id, &list, now_ms()).map_err(group_error)?;
        let out = self.group_with_members(&id)?;
        let _ = self.deliver_parked();
        Ok(out)
    }

    pub(crate) fn groups_remove(&self, args: &Args) -> OpResult {
        gate()?;
        let id = group_arg(args)?;
        let address = args.str("member")?.trim().to_owned();
        let dir = self.data_dir()?;
        let view = group::view(dir, &id).map_err(group_error)?;
        let key = view
            .members
            .iter()
            .find(|m| raven_core::encode_address(&m.key) == address)
            .map(|m| m.key)
            .ok_or_else(|| ApiError::bad_request(format!("{address} is not in this group")))?;
        let me = self.identity()?;
        group::remove_members(dir, &me, &id, &[key], now_ms()).map_err(group_error)?;
        let out = self.group_with_members(&id)?;
        let _ = self.deliver_parked();
        Ok(out)
    }

    pub(crate) fn groups_leave(&self, args: &Args) -> OpResult {
        gate()?;
        let id = group_arg(args)?;
        let me = self.identity()?;
        group::leave(self.data_dir()?, &me, &id, now_ms()).map_err(group_error)?;
        let out = self.group_with_members(&id)?;
        let _ = self.deliver_parked();
        Ok(json!({"group": out["group"].clone()}))
    }

    pub(crate) fn groups_history(&self, args: &Args) -> OpResult {
        gate()?;
        let id = group_arg(args)?;
        let limit = args
            .opt_u64("limit")?
            .map_or(HISTORY_DEFAULT, |l| (l as usize).clamp(1, HISTORY_MAX));
        self.group_identity()?;
        let dir = self.data_dir()?;
        let view = group::view(dir, &id).map_err(group_error)?;
        let before = match args.opt_str("before")? {
            None => None,
            Some(mid) => {
                let all = group::history(dir, &id, None, usize::MAX).map_err(group_error)?;
                let at = all
                    .iter()
                    .find(|m| hex::encode(m.id) == mid.trim().to_ascii_lowercase())
                    .map(|m| m.received_ms)
                    .ok_or_else(|| {
                        ApiError::bad_request("\"before\" is no message of this group")
                    })?;
                Some(at)
            }
        };
        let names = self.group_names()?;
        let messages: Vec<Value> = group::history(dir, &id, before, limit)
            .map_err(group_error)?
            .iter()
            .map(|m| self.message_json(&id, &view, m, &names))
            .collect();
        Ok(json!({"messages": messages}))
    }

    pub(crate) fn groups_send(&self, args: &Args) -> OpResult {
        gate()?;
        let id = group_arg(args)?;
        let text = args.str("text")?;
        if text.trim().is_empty() {
            return Err(ApiError::new(
                code::BAD_REQUEST,
                "Type a message first.",
                "the message is empty",
            ));
        }
        if text.len() > MAX_GROUP_BODY_BYTES {
            return Err(ApiError::of(
                code::MESSAGE_TOO_LONG,
                format!("{} bytes; at most {MAX_GROUP_BODY_BYTES}", text.len()),
            ));
        }
        let me = self.identity()?;
        let dir = self.data_dir()?;
        let report = group::send(dir, &me, &id, text, now_ms()).map_err(group_error)?;
        let view = group::view(dir, &id).map_err(group_error)?;
        let names = self.group_names()?;
        let message = group::history(dir, &id, None, HISTORY_MAX)
            .map_err(group_error)?
            .into_iter()
            .find(|m| m.id == report.id)
            .map(|m| self.message_json(&id, &view, &m, &names))
            .ok_or_else(|| ApiError::internal("the message was not stored"))?;
        lock(&self.groups).seen.insert((id, report.id));
        let mut out = json!({"message": message});
        if let Some(note) = self.deliver_parked() {
            out["note"] = safety::line(&note).into();
        }
        Ok(out)
    }

    pub(crate) fn groups_mark_read(&self, args: &Args) -> OpResult {
        gate()?;
        let id = group_arg(args)?;
        group::mark_read(self.data_dir()?, &id, now_ms()).map_err(group_error)?;
        Ok(json!({"group": hex::encode(id), "unread": 0}))
    }

    /// After this engine changed the store itself: what is there now counts
    /// as seen (its own groups and messages are no `group_message`).
    fn note_groups_seen(&self) {
        let Ok(dir) = self.data_dir() else {
            return;
        };
        let mut w = lock(&self.groups);
        if let Ok(file) = group::store::load(dir) {
            for g in &file.groups {
                let Some(gid) = group::wire::hex_n::<16>(&g.id) else {
                    continue;
                };
                for m in &g.messages {
                    if let Some(mid) = group::wire::hex_n::<16>(&m.id) {
                        w.seen.insert((gid, mid));
                    }
                }
            }
        }
    }

    /// The watcher's look at the group store (about once a second): a new
    /// message from a member is a `group_message`, any other change a
    /// `group_changed`. The first look only notes what is there.
    pub(crate) fn refresh_groups(&self) {
        if !group::group_live_enabled() {
            return;
        }
        let Ok(dir) = self.data_dir() else {
            return;
        };
        // The copies' delivery, kept current here too (raven-node's scan
        // does the same).
        let _ = group::refresh_deliveries(dir);
        let stamp = Stamp::of(&group::store::groups_path(dir));
        {
            let w = lock(&self.groups);
            if w.looked && w.stamp == Some(stamp) {
                return;
            }
        }
        let Ok(file) = group::store::load(dir) else {
            return;
        };
        let Ok(names) = self.group_names() else {
            return;
        };
        let mut emit: Vec<(&'static str, Map<String, Value>)> = Vec::new();
        let mut w = lock(&self.groups);
        let first = !w.looked;
        for g in &file.groups {
            let Some(gid) = group::wire::hex_n::<16>(&g.id) else {
                continue;
            };
            let unread = g
                .messages
                .iter()
                .filter(|m| !m.mine && m.received_ms > g.read_ms)
                .count();
            let lines: Vec<String> = g
                .messages
                .iter()
                .filter(|m| m.mine)
                .flat_map(|m| m.lines.iter().map(|l| l.state.clone()))
                .collect();
            let digest = format!(
                "{}|{}|{}|{}|{}",
                g.state.epoch,
                g.status,
                unread,
                g.messages.len(),
                lines.join(",")
            );
            let changed = w.shown.get(&gid) != Some(&digest);
            w.shown.insert(gid, digest);
            let mut new_messages = Vec::new();
            for m in &g.messages {
                let Some(mid) = group::wire::hex_n::<16>(&m.id) else {
                    continue;
                };
                if w.seen.insert((gid, mid)) && !first && !m.mine {
                    new_messages.push(mid);
                }
            }
            if first {
                continue;
            }
            if !new_messages.is_empty() {
                if let (Ok(view), Ok(history)) = (
                    group::view(dir, &gid),
                    group::history(dir, &gid, None, HISTORY_MAX),
                ) {
                    for m in history.iter().filter(|m| new_messages.contains(&m.id)) {
                        let mut fields = Map::new();
                        fields.insert("group".into(), hex::encode(gid).into());
                        fields.insert("message".into(), self.message_json(&gid, &view, m, &names));
                        emit.push(("group_message", fields));
                    }
                }
            }
            if changed {
                let mut fields = Map::new();
                fields.insert("group".into(), hex::encode(gid).into());
                emit.push(("group_changed", fields));
            }
        }
        w.looked = true;
        w.stamp = Some(stamp);
        drop(w);
        let now = now_ms();
        for (kind, mut fields) in emit {
            let mut v = Value::Object(std::mem::take(&mut fields));
            safety::sanitize_strings(&mut v);
            if let Value::Object(map) = v {
                self.events.emit(kind, map, now);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_forms_keep_both_ends() {
        assert_eq!(short_id(&[0xAB; 16]), "abababab");
        assert_eq!(short_address("rvn1short"), "rvn1short");
        let long = "rvn1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzzzz";
        assert_eq!(short_address(long), "rvn1qqqq\u{2026}zzzz");
    }

    #[test]
    fn every_group_error_has_a_code_and_a_sentence() {
        for e in [
            GroupError::Hold,
            GroupError::NotFound,
            GroupError::NotAdmin,
            GroupError::NotMember,
            GroupError::TooMany,
            GroupError::NotAFriend([0; 32]),
            GroupError::AlreadyMember([0; 32]),
            GroupError::BadName,
            GroupError::BadBody,
            GroupError::AdminCannotLeave,
            GroupError::QueueFull,
            GroupError::NoRoute,
            GroupError::NoIdentity,
            GroupError::Store("x".into()),
        ] {
            let api = group_error(e);
            assert!(!api.code.is_empty());
            assert!(api.message.ends_with('.'), "{api:?}");
        }
        assert_eq!(group_error(GroupError::Hold).code, code::NOT_AVAILABLE_YET);
        assert_eq!(
            group_error(GroupError::NotAFriend([0; 32])).code,
            code::NOT_A_CONTACT
        );
    }
}
