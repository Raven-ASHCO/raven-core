//! The chat controls (0.1.1, the owner's): block a contact, remove a
//! verification, clear a chat's history, delete a chat from the chat list
//! and pin one to its top. Everything is local to this device: the other
//! person is never told (API.md, "Chat controls").
//!
//! - **Block** puts the friend's key on the profile's block list, which
//!   raven-node already refuses on every carrier, in the outbox, custody and
//!   groups (`raven_core::outbox::contact_admission`); ash's `contact block`
//!   path also forgets its routes and it as a mail friend. The contact stays.
//! - **Remove verification** unpins the friend's key (ash's `contact
//!   unverify`); what needs both verified stops by itself.
//! - **Clear** is the privacy pack's delete-chat (PP.8, a clear that sticks)
//!   for a friend, and `raven_core::group::store::clear` for a group.
//! - **Delete chat** is clear, and the chat leaves the chat list until a new
//!   message comes; **pin** puts it at the top. Both are kept in
//!   `chat_prefs.json` ([`raven_core::chat_prefs`]), which every UI on this
//!   device reads.

use std::collections::HashMap;
use std::time::Duration;

use ash_engine::engine as bridge;
use raven_core::chat_prefs::{self, ChatPrefs};
use raven_core::group;
use serde_json::{json, Value};

use crate::engine::{lock, now_ms, Inner};
use crate::envelope::{code, ApiError, Args, OpResult};
use crate::messages::{Snapshot, State};
use crate::safety;

/// The chat an op names: a friend (`address`) or a group (`group`).
enum Target {
    Contact(String),
    Group(group::GroupId),
}

fn target(args: &Args) -> Result<Target, ApiError> {
    match (args.opt_str("address")?, args.opt_str("group")?) {
        (Some(address), None) => Ok(Target::Contact(address.to_owned())),
        (None, Some(_)) => Ok(Target::Group(crate::groups::group_arg(args)?)),
        _ => Err(ApiError::bad_request(
            "name one chat: \"address\" (a friend) or \"group\"",
        )),
    }
}

/// The newest message of each friend, by key in lower case.
pub(crate) fn newest_by_peer(snap: &Snapshot) -> HashMap<String, u64> {
    let mut newest: HashMap<String, u64> = HashMap::new();
    for v in &snap.views {
        let at = newest.entry(v.peer.clone()).or_insert(0);
        *at = (*at).max(v.at_ms);
    }
    newest
}

/// `pinned` and `hidden` (deleted from the chat list, no message since) of
/// one chat, into its Contact or Group object.
pub(crate) fn add_chat_fields(obj: &mut Value, prefs: &ChatPrefs, chat: &str, newest_ms: u64) {
    if let Value::Object(map) = obj {
        map.insert("pinned".into(), prefs.is_pinned(chat).into());
        map.insert("hidden".into(), prefs.is_hidden(chat, newest_ms).into());
    }
}

fn prefs_error(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        code::PROFILE_UNREADABLE,
        "Raven couldn't read or save your chat list settings on this device.",
        e.to_string(),
    )
}

impl Inner {
    /// The chat controls file; nothing pinned or hidden while it cannot be
    /// read (a sealed profile's key not loaded yet).
    pub(crate) fn chat_prefs(&self) -> ChatPrefs {
        self.data_dir()
            .ok()
            .and_then(|dir| chat_prefs::load(dir).ok())
            .unwrap_or_default()
    }

    fn contact_change(
        &self,
        args: &Args,
        change: fn(&std::path::Path, &str) -> Result<(), String>,
        what: &str,
    ) -> OpResult {
        let address = args.str("address")?;
        let dir = self.data_dir()?;
        self.identity()?;
        {
            let _guard = lock(&self.contacts_lock);
            let c = self.contact(address)?;
            change(dir, &c.pub_hex).map_err(|why| {
                ApiError::new(code::INTERNAL, format!("Raven couldn't {what}."), why)
            })?;
            self.invalidate_contacts();
        }
        self.contact_result(address)
    }

    /// `contacts.block {address}`: the friend's messages, contact requests
    /// and group messages are dropped and nothing goes to them; the contact
    /// stays. `{"contact": Contact}` with `blocked: true`.
    pub(crate) fn contacts_block(&self, args: &Args) -> OpResult {
        self.contact_change(
            args,
            |dir, key| bridge::block_contact(dir, key).map(|_| ()),
            "block this contact",
        )
    }

    /// `contacts.unblock {address}`.
    pub(crate) fn contacts_unblock(&self, args: &Args) -> OpResult {
        self.contact_change(
            args,
            |dir, key| bridge::unblock_contact(dir, key).map(|_| ()),
            "unblock this contact",
        )
    }

    /// `contacts.unverify {address}`: not verified any more; contact,
    /// history and routes stay. `{"contact": Contact}` with
    /// `verified: false`.
    pub(crate) fn contacts_unverify(&self, args: &Args) -> OpResult {
        self.contact_change(
            args,
            |dir, key| bridge::unverify_contact(dir, key).map(|_| ()),
            "remove the verification",
        )
    }

    /// Stops every message to `pub_hex` still waiting to be sent (the
    /// `include_pending` of a clear): how many were stopped.
    fn stop_waiting_to(&self, pub_hex: &str) -> Result<usize, ApiError> {
        let snap = self.refresh(Duration::ZERO)?;
        let peer = pub_hex.to_ascii_lowercase();
        let ids: Vec<String> = snap
            .views
            .iter()
            .filter(|v| {
                v.peer == peer
                    && !v.incoming
                    && matches!(v.state, State::Sending | State::Sent | State::Waiting)
            })
            .map(|v| v.id.clone())
            .collect();
        let mut stopped = 0;
        for id in ids {
            let one = json!({ "id": id });
            if let Value::Object(map) = &one {
                if self.messages_stop(&Args(map)).is_ok() {
                    stopped += 1;
                }
            }
        }
        Ok(stopped)
    }

    /// Clears one chat on this device: `(cleared, pending_kept)`.
    fn clear_target(&self, t: &Target, include_pending: bool) -> Result<(u64, u64), ApiError> {
        let dir = self.data_dir()?;
        self.identity()?;
        let (cleared, kept) = match t {
            Target::Contact(address) => {
                let c = self.contact(address)?;
                if include_pending {
                    self.stop_waiting_to(&c.pub_hex)?;
                }
                let (cleared, kept) = bridge::clear_chat(dir, &c.pub_hex).map_err(|why| {
                    ApiError::new(code::INTERNAL, "Raven couldn't clear this chat.", why)
                })?;
                (u64::from(cleared), kept as u64)
            }
            Target::Group(id) => {
                let (cleared, kept) = group::store::clear(dir, id, include_pending)
                    .map_err(crate::groups::group_error)?;
                (cleared as u64, kept as u64)
            }
        };
        let _ = self.refresh(Duration::ZERO);
        Ok((cleared, kept))
    }

    /// `messages.clear {address, include_pending?}`.
    pub(crate) fn messages_clear(&self, args: &Args) -> OpResult {
        let t = Target::Contact(args.str("address")?.to_owned());
        let pending = args.opt_bool("include_pending")?.unwrap_or(false);
        let (cleared, kept) = self.clear_target(&t, pending)?;
        Ok(json!({"cleared": cleared, "pending_kept": kept}))
    }

    /// `groups.clear {group, include_pending?}`.
    pub(crate) fn groups_clear(&self, args: &Args) -> OpResult {
        let t = Target::Group(crate::groups::group_arg(args)?);
        let pending = args.opt_bool("include_pending")?.unwrap_or(false);
        let (cleared, kept) = self.clear_target(&t, pending)?;
        Ok(json!({"cleared": cleared, "pending_kept": kept}))
    }

    fn chat_of(&self, t: &Target) -> Result<String, ApiError> {
        Ok(match t {
            Target::Contact(address) => chat_prefs::contact_chat(&self.contact(address)?.pub_hex),
            Target::Group(id) => chat_prefs::group_chat(&hex::encode(id)),
        })
    }

    /// `chats.delete {address} | {group}`: cleared, and out of the chat list
    /// until a new message comes.
    pub(crate) fn chats_delete(&self, args: &Args) -> OpResult {
        let t = target(args)?;
        let chat = self.chat_of(&t)?;
        let (cleared, kept) = self.clear_target(&t, false)?;
        chat_prefs::hide(self.data_dir()?, &chat, now_ms()).map_err(prefs_error)?;
        Ok(json!({"deleted": true, "cleared": cleared, "pending_kept": kept}))
    }

    /// `chats.pin {address | group, pinned}`.
    pub(crate) fn chats_pin(&self, args: &Args) -> OpResult {
        let t = target(args)?;
        let pinned = args
            .opt_bool("pinned")?
            .ok_or_else(|| ApiError::bad_request("\"pinned\" is required (true or false)"))?;
        self.identity()?;
        let chat = self.chat_of(&t)?;
        let pinned =
            chat_prefs::set_pinned(self.data_dir()?, &chat, pinned).map_err(prefs_error)?;
        Ok(json!({ "pinned": pinned }))
    }

    /// `chats.list {}`: every chat with a friend and every group, pinned
    /// first (the newest pin first), then the newest message first; a chat
    /// deleted from the list is left out until a new message.
    pub(crate) fn chats_list(&self) -> OpResult {
        self.identity()?;
        let dir = self.data_dir()?;
        let snap = self.refresh(Duration::from_millis(1500))?;
        let prefs = self.chat_prefs();
        let newest = newest_by_peer(&snap);
        let mut chats: Vec<(String, u64, Value)> = Vec::new();
        for c in snap.contacts.iter() {
            let peer = c.pub_hex.to_ascii_lowercase();
            let last = newest.get(&peer).copied().unwrap_or(0);
            let chat = chat_prefs::contact_chat(&peer);
            if prefs.is_hidden(&chat, last) {
                continue;
            }
            let name: String = safety::line(&c.label).chars().take(200).collect();
            let entry = json!({
                "kind": "contact",
                "address": c.address,
                "name": name,
                "pinned": prefs.is_pinned(&chat),
                "last_ms": last,
                "unread": snap.unread.get(&peer).copied().unwrap_or(0),
            });
            chats.push((chat, last, entry));
        }
        if group::group_live_enabled() {
            for s in group::list(dir).map_err(crate::groups::group_error)? {
                let chat = chat_prefs::group_chat(&hex::encode(s.id));
                if prefs.is_hidden(&chat, s.last_ms) {
                    continue;
                }
                let entry = json!({
                    "kind": "group",
                    "group": hex::encode(s.id),
                    "name": safety::line(&s.name),
                    "pinned": prefs.is_pinned(&chat),
                    "last_ms": s.last_ms,
                    "unread": s.unread,
                });
                chats.push((chat, s.last_ms, entry));
            }
        }
        let pin_rank = |chat: &str| prefs.pinned.iter().position(|p| p == chat);
        chats.sort_by(|a, b| match (pin_rank(&a.0), pin_rank(&b.0)) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => b.1.cmp(&a.1),
        });
        Ok(json!({"chats": chats.into_iter().map(|(_, _, v)| v).collect::<Vec<_>>()}))
    }
}
