//! Groups in the terminal app (lab only; docs/design/2026-10-groups.md §8,
//! the CLI's `raven group`).
//!
//! - **Gate.** Read once, when the identity is ready
//!   (`raven_core::group::group_live_enabled`). While it is closed nothing
//!   here shows, no key does anything and no job goes out: Home is exactly
//!   as it was.
//! - **Home.** Under the friends, the GROUPS section: each group's name,
//!   its member count where the row has room, and its unread count, or
//!   'left' / 'removed'. The highlight moves over friends and groups alike;
//!   Enter on a group opens its chat in the conversation pane, C starts a
//!   new group and E (or I) on a group shows its members.
//! - **Reads** run on the store worker ([`StoreJob::LoadGroups`]): every
//!   group, and the open one's members and newest messages. groups.json
//!   changing (the poller, while groups are live) reads them again. A read
//!   that first refreshes the copies' delivery and parks the work waiting
//!   (`group::run_pending`, as `raven group show` does) runs when the app
//!   starts, when a group opens, when the chat history changed (a copy's
//!   receipt) and once a minute; a plain read writes nothing, so the store
//!   settles.
//! - **Sends and changes** run on the send worker, as chat sends do
//!   ([`SendJob::GroupSend`], [`SendJob::GroupChange`]): each copy is parked
//!   for raven-node, which is then asked to send them (started first when
//!   none runs, as a chat send starts it). A message shows at once with
//!   'Sending…' until a read has it; one refused comes back into the
//!   composer, with a toast saying why.
//! - **Read here.** While a group's chat is on screen it is marked read
//!   ([`StoreJob::MarkGroupRead`]) whenever it has unread messages. Nothing
//!   about reading is sent.
//! - **NEW GROUP** (C): a name, then the friend picker (unblocked friends,
//!   at most 15). **MEMBERS** (M in the chat, E on the list): who is in it;
//!   the admin adds friends (the same picker) and removes a member, anyone
//!   else may leave; both after a yes. **WHO HAS IT** (Enter or D on a
//!   message of yours): each member's copy.
//! - A group you left or were removed from keeps its messages and has no
//!   composer: the pane says so.

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent};
use raven_core::group::{
    self as core_group, GroupError, GroupId, GroupSummary, Key, MAX_GROUP_BODY_BYTES,
    MAX_GROUP_MEMBERS, MAX_GROUP_NAME_CHARS,
};

use super::controller::{GroupChange, GroupChat, GroupDone, GroupMessage, GroupsRead};
use super::workers::FileStamp;
use super::{
    bridge, display, has_ctrl_or_alt, home, is_ctrl, plain_char, App, BubbleKey, Cmd, Composer,
    ContactView, Focus, IdentityStatus, Overlay, Screen, SendJob, StoreJob, CONTROL_REFUSED,
};

/// NEW GROUP's name field, left empty.
pub(in super::super) const NAME_EMPTY: &str = "Type a name for the group.";
/// The picker's Enter with nobody picked.
pub(in super::super) const PICK_NONE: &str =
    "Pick at least one friend: Space picks the one marked.";
/// A group message over raven-core's limit (8 KiB).
pub(in super::super) const TOO_LONG: &str = "A group message has at most 8 KB of text.";
/// A send or change went into the store, and no background program took
/// its copies.
pub(in super::super) const GROUP_WAITS: &str = "Raven's background program isn't running, so \
                                                these group messages wait on this computer \
                                                until it runs.";

/// What the app knows of the groups.
#[derive(Debug, Clone, Default)]
pub(in super::super) struct GroupsState {
    /// Groups are live in this build: read once, when the identity is ready.
    live: bool,
    /// Every group, the newest activity first, as the last read found them.
    list: Vec<GroupSummary>,
    /// Why the last read of the list failed (the list stays as it was).
    error: Option<String>,
    loading: bool,
    /// Another read is wanted once the one running ends: with a refresh
    /// (`Some(true)`) or without.
    due: Option<bool>,
    /// groups.json as the last read and the poller last saw it.
    stamp: Option<FileStamp>,
    seen: Option<FileStamp>,
    /// The group whose chat is open in Home's conversation pane, and its
    /// chat as the last read found it (or why it can't be read).
    open: Option<GroupId>,
    chat: Option<GroupChat>,
    chat_error: Option<String>,
    /// What is typed to each group: a draft never goes to another one.
    drafts: HashMap<GroupId, Composer>,
    /// This session's sends, oldest first, until a read has them.
    sends: Vec<GroupSend>,
    next_send: u64,
    /// A mark-read job runs; the group and unread count it was asked for
    /// (asked again only once that changed).
    marking: bool,
    marked: Option<(GroupId, usize)>,
    /// A group just created: highlighted once a read lists it.
    created: Option<GroupId>,
}

/// A message of yours sent in this session, shown until a read has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in super::super) struct GroupSend {
    pub(in super::super) local_id: u64,
    pub(in super::super) group: GroupId,
    /// Raw: shaped by display.rs when drawn.
    pub(in super::super) body: String,
    pub(in super::super) at_ms: u64,
    /// Its message id once its job answered.
    pub(in super::super) id: Option<[u8; 16]>,
}

/// One message of the open group's chat as its pane draws it.
#[derive(Debug, Clone, Copy)]
pub(in super::super) enum GroupItem<'a> {
    Message(&'a GroupMessage),
    /// Sent in this session; no read has it yet.
    Sending(&'a GroupSend),
}

impl GroupItem<'_> {
    /// Raw: shaped by display.rs when drawn.
    pub(in super::super) fn body(&self) -> &str {
        match self {
            GroupItem::Message(m) => &m.body,
            GroupItem::Sending(send) => &send.body,
        }
    }

    pub(in super::super) fn at_ms(&self) -> u64 {
        match self {
            GroupItem::Message(m) => m.at_ms,
            GroupItem::Sending(send) => send.at_ms,
        }
    }

    /// For a body shown whole (Enter on a clipped one).
    pub(in super::super) fn key(&self) -> BubbleKey {
        match self {
            GroupItem::Message(m) => BubbleKey::Mid(format!("group:{}", hex::encode(m.id))),
            GroupItem::Sending(send) => BubbleKey::Mid(format!("group-send:{}", send.local_id)),
        }
    }
}

/// The groups' boxes over Home; the last one gets the keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in super::super) enum GroupOverlay {
    /// NEW GROUP's first step: the name as typed, and why it can't be used.
    Name {
        typed: String,
        problem: Option<String>,
    },
    /// The friend picker, for a new group or to add to one.
    Pick(PickState),
    /// MEMBERS: who is in a group, and the admin's add and remove, or leave.
    Members(MembersState),
    /// WHO HAS IT: one message of yours, member by member.
    Delivery { group: GroupId, message: [u8; 16] },
}

impl GroupOverlay {
    /// A field takes the keys as text (NEW GROUP's name).
    pub(in super::super) fn takes_text(&self) -> bool {
        matches!(self, GroupOverlay::Name { .. })
    }
}

/// The friend picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in super::super) struct PickState {
    pub(in super::super) purpose: PickFor,
    /// The friend marked, by place in the list.
    pub(in super::super) cursor: usize,
    /// The friends picked (keys, lower case), in the order picked.
    pub(in super::super) picked: Vec<String>,
    pub(in super::super) problem: Option<String>,
    /// Its change runs: the keys wait for the answer.
    pub(in super::super) busy: bool,
}

impl PickState {
    fn new(purpose: PickFor) -> PickState {
        PickState {
            purpose,
            cursor: 0,
            picked: Vec::new(),
            problem: None,
            busy: false,
        }
    }
}

/// What the picker is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in super::super) enum PickFor {
    /// A new group with this name.
    Create { name: String },
    /// Friends added to a group this profile is the admin of.
    Add { group: GroupId },
}

/// MEMBERS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in super::super) struct MembersState {
    pub(in super::super) group: GroupId,
    /// The member marked, by place in the list.
    pub(in super::super) cursor: usize,
    /// A question before a remove or a leave.
    pub(in super::super) ask: Option<MemberAsk>,
    /// Its change runs: the keys wait for the answer.
    pub(in super::super) busy: bool,
}

impl MembersState {
    fn new(group: GroupId) -> MembersState {
        MembersState {
            group,
            cursor: 0,
            ask: None,
            busy: false,
        }
    }
}

/// MEMBERS' question: Y does it, N keeps things as they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in super::super) enum MemberAsk {
    /// The admin removes `key` (shown as `name`).
    Remove { key: Key, name: String },
    /// This profile leaves the group.
    Leave,
}

/// Why a group message can't go as it is: a control character (cli.rs's
/// own check, a backstop: none can be typed), or more than raven-core takes.
pub(in super::super) fn text_problem(text: &str) -> Option<&'static str> {
    if bridge::tty_message_problem(text).is_some() {
        Some(CONTROL_REFUSED)
    } else if text.len() > MAX_GROUP_BODY_BYTES {
        Some(TOO_LONG)
    } else {
        None
    }
}

/// A friend's key as raven-core takes it.
fn key_of(pub_hex: &str) -> Option<Key> {
    core_group::wire::hex_n::<32>(&pub_hex.trim().to_ascii_lowercase())
}

impl App {
    // ── What the screens read ───────────────────────────────────────────────

    /// Groups are live in this build (read when the identity was ready).
    pub(in super::super) fn groups_live(&self) -> bool {
        self.groups.live
    }

    /// Every group, the newest activity first; empty while groups are not
    /// live.
    pub(in super::super) fn group_list(&self) -> &[GroupSummary] {
        &self.groups.list
    }

    /// Why the last read of the groups failed.
    pub(in super::super) fn groups_error(&self) -> Option<&str> {
        self.groups.error.as_deref()
    }

    /// The group whose chat is open.
    pub(in super::super) fn open_group(&self) -> Option<GroupId> {
        self.groups.open
    }

    /// The open group as the list (or else its chat) has it.
    pub(in super::super) fn open_group_summary(&self) -> Option<&GroupSummary> {
        let open = self.groups.open?;
        self.groups
            .list
            .iter()
            .find(|g| g.id == open)
            .or_else(|| self.group_chat().map(|chat| &chat.view.summary))
    }

    /// The open group's chat, once read.
    pub(in super::super) fn group_chat(&self) -> Option<&GroupChat> {
        let open = self.groups.open?;
        self.groups
            .chat
            .as_ref()
            .filter(|chat| chat.view.summary.id == open)
    }

    /// Why the open group's chat can't be read.
    pub(in super::super) fn group_chat_error(&self) -> Option<&str> {
        self.groups.chat_error.as_deref()
    }

    /// The group `id` takes messages from here: listed as active, or not
    /// listed yet (just created).
    pub(in super::super) fn group_active(&self, id: &GroupId) -> bool {
        let status = |g: &GroupSummary| g.status == core_group::store::STATUS_ACTIVE;
        match self.groups.list.iter().find(|g| g.id == *id) {
            Some(g) => status(g),
            None => self
                .groups
                .chat
                .as_ref()
                .filter(|chat| chat.view.summary.id == *id)
                .is_none_or(|chat| status(&chat.view.summary)),
        }
    }

    /// The open group's chat, oldest first: the messages read, then this
    /// session's sends no read has yet.
    pub(in super::super) fn group_items(&self) -> Vec<GroupItem<'_>> {
        let Some(open) = self.groups.open else {
            return Vec::new();
        };
        let messages = self.group_chat().map_or(&[][..], |chat| &chat.messages);
        let mut items: Vec<GroupItem<'_>> = messages.iter().map(GroupItem::Message).collect();
        items.extend(
            self.groups
                .sends
                .iter()
                .filter(|send| send.group == open)
                .filter(|send| {
                    send.id
                        .is_none_or(|id| !messages.iter().any(|m| m.id == id))
                })
                .map(GroupItem::Sending),
        );
        items
    }

    /// The group a send of yours runs to now (its job hasn't answered), by
    /// name: Home's ticker says so (Calm).
    pub(in super::super) fn group_sending_to(&self) -> Option<&str> {
        let send = self.groups.sends.iter().find(|send| send.id.is_none())?;
        self.groups
            .list
            .iter()
            .find(|group| group.id == send.group)
            .map(|group| group.name.as_str())
    }

    /// Per group, by name, how many of your messages are not with every
    /// member yet, as far as this app knows: this session's sends no read
    /// has yet, and in the open group's chat those with a copy still waiting
    /// or not confirmed. Home's ticker counts them (never 'all quiet'
    /// meanwhile).
    pub(in super::super) fn groups_waiting(&self) -> Vec<(String, usize)> {
        use core_group::store::{LINE_SENT, LINE_WAITING};
        let chat = self.group_chat();
        self.groups
            .list
            .iter()
            .filter_map(|group| {
                let read = |id: &[u8; 16]| {
                    chat.is_some_and(|chat| {
                        chat.view.summary.id == group.id
                            && chat.messages.iter().any(|m| m.id == *id)
                    })
                };
                let sends = self
                    .groups
                    .sends
                    .iter()
                    .filter(|send| send.group == group.id && !send.id.as_ref().is_some_and(read))
                    .count();
                let going =
                    chat.filter(|chat| chat.view.summary.id == group.id)
                        .map_or(0, |chat| {
                            chat.messages
                                .iter()
                                .filter(|m| {
                                    m.mine
                                        && m.lines.iter().any(|line| {
                                            matches!(line.state.as_str(), LINE_WAITING | LINE_SENT)
                                        })
                                })
                                .count()
                        });
                let n = sends + going;
                (n > 0).then(|| (group.name.clone(), n))
            })
            .collect()
    }

    /// The open group's draft; None with no group open, or one that takes
    /// no messages from here.
    pub(in super::super) fn group_composer(&self) -> Option<&Composer> {
        let open = self.groups.open.filter(|id| self.group_active(id))?;
        Some(
            self.groups
                .drafts
                .get(&open)
                .unwrap_or(&super::EMPTY_COMPOSER),
        )
    }

    /// The highlight is on a group: its place in the list.
    pub(in super::super) fn highlighted_group_at(&self) -> Option<usize> {
        let at = self.highlight.checked_sub(self.friends.len())?;
        (at < self.groups.list.len()).then_some(at)
    }

    fn highlighted_group(&self) -> Option<GroupId> {
        self.highlighted_group_at()
            .map(|at| self.groups.list[at].id)
    }

    /// The open group's chat is on screen.
    pub(in super::super) fn group_visible(&self) -> bool {
        self.screen == Screen::Home
            && !self.too_small()
            && self.groups.open.is_some()
            && (home::two_panes(self.size) || self.focus != Focus::Friends)
    }

    /// The friends the picker offers: saved, not blocked, with a key, and
    /// for an add not in the group already.
    pub(in super::super) fn pick_candidates(&self, purpose: &PickFor) -> Vec<&ContactView> {
        let members: Vec<Key> = match purpose {
            PickFor::Create { .. } => Vec::new(),
            PickFor::Add { .. } => self
                .group_chat()
                .map(|chat| chat.view.members.iter().map(|m| m.key).collect())
                .unwrap_or_default(),
        };
        self.contacts
            .iter()
            .filter(|c| !c.blocked)
            .filter(|c| key_of(&c.pub_hex).is_some_and(|key| !members.contains(&key)))
            .collect()
    }

    /// How many friends the picker takes: 15 for a new group, else what
    /// the group has room for.
    pub(in super::super) fn pick_cap(&self, purpose: &PickFor) -> usize {
        match purpose {
            PickFor::Create { .. } => MAX_GROUP_MEMBERS - 1,
            PickFor::Add { .. } => MAX_GROUP_MEMBERS.saturating_sub(
                self.group_chat()
                    .map_or(MAX_GROUP_MEMBERS, |chat| chat.view.members.len()),
            ),
        }
    }

    // ── Reads ───────────────────────────────────────────────────────────────

    /// The identity is ready: whether groups are live, and if so the first
    /// read (with a refresh).
    pub(super) fn groups_begin(&mut self) {
        self.groups.live = core_group::group_live_enabled();
        self.load_groups(true);
    }

    /// Reads the groups (and the open one's chat) on the store worker; with
    /// `refresh`, after the copies' delivery and the waiting work. One read
    /// at a time: one asked for meanwhile runs after it.
    pub(super) fn load_groups(&mut self, refresh: bool) {
        if !self.groups.live || self.identity != IdentityStatus::Ready || self.erasing() {
            return;
        }
        if self.groups.loading {
            let due = self.groups.due.get_or_insert(false);
            *due |= refresh;
            return;
        }
        self.groups.loading = true;
        self.job(Cmd::Store(StoreJob::LoadGroups {
            open: self.groups.open,
            refresh,
        }));
    }

    /// The poller saw groups.json at `stamp`.
    pub(super) fn groups_file_seen(&mut self, stamp: FileStamp) {
        self.groups.seen = Some(stamp);
        if self.groups.stamp != Some(stamp) {
            self.load_groups(false);
        }
    }

    /// A read's answer. The highlight stays on the group it was on (the
    /// list is ordered by activity); a group just created gets it. A failure
    /// keeps what was read before.
    pub(super) fn groups_loaded(&mut self, read: GroupsRead) {
        self.groups.loading = false;
        if !self.groups.live {
            return;
        }
        self.groups.stamp = Some(read.stamp);
        match read.groups {
            Ok(list) => {
                let highlighted = self.groups.created.or(self.highlighted_group());
                self.groups.list = list;
                self.groups.error = None;
                let total = self.friends.len() + self.groups.list.len();
                match highlighted.and_then(|id| self.groups.list.iter().position(|g| g.id == id)) {
                    Some(at) => {
                        self.highlight = self.friends.len() + at;
                        self.groups.created = None;
                    }
                    None => self.highlight = self.highlight.min(total.saturating_sub(1)),
                }
            }
            Err(why) => self.groups.error = Some(why),
        }
        if let Some((id, chat)) = read.open {
            if self.groups.open == Some(id) {
                match chat {
                    Ok(chat) => {
                        self.groups.chat = Some(chat);
                        self.groups.chat_error = None;
                    }
                    Err(why) => self.groups.chat_error = Some(why),
                }
            }
        }
        // A send shows until a read has it.
        let open = self.groups.open;
        let read_ids: Vec<[u8; 16]> = self
            .group_chat()
            .map(|chat| chat.messages.iter().map(|m| m.id).collect())
            .unwrap_or_default();
        self.groups.sends.retain(|send| match send.id {
            None => true,
            Some(id) => Some(send.group) == open && !read_ids.contains(&id),
        });
        if self.groups.open.is_some() {
            self.scroll = home::clamp_scroll(self, self.scroll);
        }
        self.dirty = true;
        if let Some(refresh) = self.groups.due.take() {
            self.load_groups(refresh);
        } else if self
            .groups
            .seen
            .is_some_and(|seen| Some(seen) != self.groups.stamp)
        {
            self.load_groups(false);
        }
    }

    /// A read's job failed (it panicked): read again at the next change.
    pub(super) fn groups_load_failed(&mut self, why: String) {
        self.groups.loading = false;
        self.groups.error = Some(why);
        self.dirty = true;
    }

    /// The open group's chat is on screen with unread messages: they are
    /// marked read, once for each count.
    pub(super) fn groups_upkeep(&mut self) {
        if !self.groups.live || self.groups.marking || !self.group_visible() {
            return;
        }
        let Some(open) = self.groups.open else {
            return;
        };
        let unread = self
            .groups
            .list
            .iter()
            .find(|g| g.id == open)
            .map_or(0, |g| g.unread);
        if unread == 0 {
            self.groups.marked = None;
            return;
        }
        if self.groups.marked == Some((open, unread)) {
            return;
        }
        self.groups.marked = Some((open, unread));
        self.groups.marking = true;
        self.job(Cmd::Store(StoreJob::MarkGroupRead { group: open }));
    }

    /// A mark-read answered: the counts are read again.
    pub(super) fn group_marked(&mut self, result: Result<(), String>) {
        self.groups.marking = false;
        if result.is_ok() {
            self.load_groups(false);
        }
    }

    /// A mark-read's job failed: not asked again for the same count.
    pub(super) fn group_mark_failed(&mut self) {
        self.groups.marking = false;
    }

    // ── Opening ─────────────────────────────────────────────────────────────

    /// Home with the group `id`'s chat open: the composer has the keys (a
    /// group that takes no messages from here: the messages), and its chat
    /// is read with a refresh.
    pub(super) fn show_group(&mut self, id: GroupId) {
        if self.groups.open != Some(id) {
            self.scroll = 0;
            self.groups.chat = None;
            self.groups.chat_error = None;
        }
        self.groups.open = Some(id);
        self.open_friend = None;
        self.focus = if self.group_active(&id) {
            Focus::Composer
        } else {
            Focus::Messages
        };
        self.chosen = (self.focus == Focus::Messages).then_some(0);
        self.dirty = true;
        self.load_groups(true);
    }

    /// A friend's conversation opens instead: the group closes.
    pub(super) fn close_group(&mut self) {
        if self.groups.open.take().is_some() {
            self.groups.chat = None;
            self.groups.chat_error = None;
            self.dirty = true;
        }
    }

    /// Enter on the friend list when the highlight is on a group.
    pub(super) fn open_highlighted_group(&mut self) -> bool {
        match self.highlighted_group() {
            Some(id) => {
                self.show_group(id);
                true
            }
            None => false,
        }
    }

    /// E (or I) on the friend list when the highlight is on a group: its
    /// chat and MEMBERS over it.
    pub(super) fn group_page_from_list(&mut self) -> bool {
        match self.highlighted_group() {
            Some(id) => {
                self.show_group(id);
                self.open_members();
                true
            }
            None => false,
        }
    }

    /// The highlighted group keeps the highlight after the friends changed.
    pub(super) fn keep_group_highlight(&mut self, group: Option<GroupId>) {
        if let Some(at) = group.and_then(|id| self.groups.list.iter().position(|g| g.id == id)) {
            self.highlight = self.friends.len() + at;
        }
    }

    /// The group whose row the highlight is on, before the friends change.
    pub(super) fn group_under_highlight(&self) -> Option<GroupId> {
        self.highlighted_group()
    }

    /// Tab and Shift+Tab while a group is open: a group that takes no
    /// messages from here has no composer to go to.
    pub(super) fn group_move_focus(&mut self, step: fn(Focus) -> Focus) {
        let mut next = step(self.focus);
        if next == Focus::Composer && !self.groups.open.is_some_and(|id| self.group_active(&id)) {
            next = step(next);
        }
        self.set_focus(next);
    }

    // ── The composer ────────────────────────────────────────────────────────

    /// The group composer can take text: an open group that takes messages
    /// from here.
    pub(super) fn group_takes_text(&self) -> bool {
        self.groups.open.is_some_and(|id| self.group_active(&id))
    }

    /// Edits the open group's draft; a change is drawn. An edit that would
    /// pass raven-core's limit is undone.
    pub(super) fn group_compose(&mut self, edit: impl FnOnce(&mut Composer) -> bool) {
        let Some(open) = self.groups.open.filter(|id| self.group_active(id)) else {
            return;
        };
        let draft = self.groups.drafts.entry(open).or_default();
        let before = draft.clone();
        if edit(draft) {
            if draft.text().len() > MAX_GROUP_BODY_BYTES && draft.text().len() > before.text().len()
            {
                *draft = before;
                return;
            }
            self.dirty = true;
        }
    }

    /// Typed or pasted text into the open group's draft, cut where it would
    /// pass raven-core's limit.
    pub(super) fn group_insert(&mut self, raw: &str) {
        let mut add = display::field_input(raw, true);
        self.group_compose(|draft| {
            let room = MAX_GROUP_BODY_BYTES.saturating_sub(draft.text().len());
            if add.len() > room {
                let mut cut = room;
                while !add.is_char_boundary(cut) {
                    cut -= 1;
                }
                add.truncate(cut);
            }
            draft.insert(&add)
        });
    }

    /// The group composer's keys: typing is text; Ctrl+J a new line; Enter
    /// sends (not right after a paste); Backspace, Delete, Left, Right, Home
    /// and End edit; Up, Down, PgUp and PgDn scroll; Esc goes back to the
    /// list; ? on an empty draft opens HELP. A group that takes no messages
    /// from here has only the messages' keys.
    pub(super) fn on_group_composer_key(&mut self, key: KeyEvent) {
        if !self.group_takes_text() {
            match key.code {
                KeyCode::Esc => self.set_focus(Focus::Friends),
                _ => self.on_group_messages_key(key),
            }
            return;
        }
        if is_ctrl(key, 'j') {
            self.group_insert("\n");
            return;
        }
        let empty = self.group_composer().is_none_or(Composer::is_empty);
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => self.set_focus(Focus::Friends),
            (_, Some('?')) if empty => self.open_overlay(Overlay::Help { scroll: 0 }),
            (_, Some(c)) => self.group_insert(c.encode_utf8(&mut [0; 4])),
            _ if self.confirms(key) => self.group_enter(),
            (KeyCode::Backspace, _) if !has_ctrl_or_alt(key) => {
                self.group_compose(Composer::backspace);
            }
            (KeyCode::Delete, _) => self.group_compose(Composer::delete),
            (KeyCode::Left, _) => self.group_compose(Composer::left),
            (KeyCode::Right, _) => self.group_compose(Composer::right),
            (KeyCode::Home, _) => self.group_compose(Composer::line_start),
            (KeyCode::End, _) => self.group_compose(Composer::line_end),
            _ => self.scroll_key(key),
        }
    }

    /// Enter in the group composer: the draft goes to the open group as a
    /// new message, shown at once, its job behind any before it on the send
    /// worker. Nothing for an empty draft or one that can't go as it is
    /// (the hint says why).
    fn group_enter(&mut self) {
        let Some(open) = self.groups.open.filter(|id| self.group_active(id)) else {
            return;
        };
        let Some(draft) = self.groups.drafts.get(&open) else {
            return;
        };
        if draft.text().trim().is_empty() || text_problem(draft.text()).is_some() {
            return;
        }
        let text = draft.text().to_owned();
        self.groups.drafts.remove(&open);
        self.groups.next_send += 1;
        let local_id = self.groups.next_send;
        self.groups.sends.push(GroupSend {
            local_id,
            group: open,
            body: text.clone(),
            at_ms: self.now_ms,
            id: None,
        });
        self.scroll = 0;
        if self.chosen.is_some() {
            self.chosen = Some(0);
        }
        self.dirty = true;
        self.queue_send_job(SendJob::GroupSend {
            local_id,
            group: open,
            text,
        });
    }

    /// A group send answered: its message id (shown until a read has it),
    /// or why not: then the text goes back into an empty draft and a toast
    /// says why.
    pub(super) fn group_sent(&mut self, local_id: u64, done: GroupDone<[u8; 16]>) {
        let Some(at) = self
            .groups
            .sends
            .iter()
            .position(|send| send.local_id == local_id)
        else {
            return;
        };
        match done.result {
            Ok(id) => {
                self.groups.sends[at].id = Some(id);
                if !done.kicked {
                    self.push_toast(GROUP_WAITS);
                }
            }
            Err(why) => {
                let send = self.groups.sends.remove(at);
                self.restore_group_draft(&send);
                self.push_toast(&format!("Not sent: {why}"));
            }
        }
        self.dirty = true;
        self.load_groups(false);
    }

    /// A group send's job failed (it panicked): the oldest send not
    /// answered goes back into its draft (the toast said so).
    pub(super) fn group_send_failed(&mut self) {
        if let Some(at) = self.groups.sends.iter().position(|send| send.id.is_none()) {
            let send = self.groups.sends.remove(at);
            self.restore_group_draft(&send);
        }
        self.dirty = true;
    }

    fn restore_group_draft(&mut self, send: &GroupSend) {
        let draft = self.groups.drafts.entry(send.group).or_default();
        if draft.is_empty() {
            draft.insert(&send.body);
        }
    }

    // ── The messages ────────────────────────────────────────────────────────

    /// The group's messages: Up and Down choose one, PgUp and PgDn scroll;
    /// Enter shows a clipped body whole, then (or D) WHO HAS IT for one of
    /// yours; M shows MEMBERS; Esc goes back to the composer (or the list,
    /// for a group that takes no messages from here); ?, Q, L and W as in a
    /// chat.
    pub(super) fn on_group_messages_key(&mut self, key: KeyEvent) {
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => {
                let back = if self.group_takes_text() {
                    Focus::Composer
                } else {
                    Focus::Friends
                };
                self.set_focus(back);
            }
            (_, Some('?')) => self.open_overlay(Overlay::Help { scroll: 0 }),
            (_, Some('q' | 'Q')) => self.open_overlay(Overlay::Quit),
            (_, Some('l' | 'L')) => self.open_lock(),
            (_, Some('w' | 'W')) => self.open_security(None),
            (_, Some('m' | 'M')) => self.open_members(),
            (KeyCode::Up, _) => self.group_choose(1),
            (KeyCode::Down, _) => self.group_choose(-1),
            _ => {
                let chosen = self.chosen_group_item().map(|item| {
                    let id = match item {
                        GroupItem::Message(m) if m.mine => Some(m.id),
                        _ => None,
                    };
                    let clipped = display::body_lines(item.body(), false).more_chars > 0;
                    (item.key(), id, clipped)
                });
                let Some((bubble, id, clipped)) = chosen else {
                    self.scroll_key(key);
                    return;
                };
                match (key.code, plain_char(key)) {
                    (_, Some('d' | 'D')) if id.is_some() => self.open_delivery(id),
                    _ if self.confirms(key) => {
                        if clipped && !self.expanded.contains(&bubble) {
                            self.expanded.insert(bubble);
                            self.dirty = true;
                        } else {
                            self.open_delivery(id);
                        }
                    }
                    _ => self.scroll_key(key),
                }
            }
        }
    }

    /// The message chosen in Messages focus.
    fn chosen_group_item(&self) -> Option<GroupItem<'_>> {
        let items = self.group_items();
        let at = self.chosen?;
        items.len().checked_sub(at + 1).map(|index| items[index])
    }

    /// Up (`by` 1: older) or Down: another message, and the window scrolled
    /// as little as it takes to show it.
    fn group_choose(&mut self, by: isize) {
        let count = self.group_items().len();
        if count == 0 {
            return;
        }
        let at = self.chosen.unwrap_or(0).min(count - 1);
        let new = at.saturating_add_signed(by).min(count - 1);
        if self.chosen != Some(new) {
            self.chosen = Some(new);
            self.dirty = true;
        }
        let scroll = home::scroll_to_message(self, new);
        if scroll != self.scroll {
            self.scroll = scroll;
            self.dirty = true;
        }
    }

    /// WHO HAS IT for the open group's message `id` (of yours).
    fn open_delivery(&mut self, id: Option<[u8; 16]>) {
        if let (Some(group), Some(message)) = (self.groups.open, id) {
            self.open_overlay(Overlay::Group(GroupOverlay::Delivery { group, message }));
        }
    }

    // ── New group, members ──────────────────────────────────────────────────

    /// C on the friend list: NEW GROUP, its name first.
    pub(super) fn open_new_group(&mut self) {
        if self.groups.live {
            self.open_overlay(Overlay::Group(GroupOverlay::Name {
                typed: String::new(),
                problem: None,
            }));
        }
    }

    /// MEMBERS for the open group.
    pub(super) fn open_members(&mut self) {
        if let Some(group) = self.groups.open {
            self.open_overlay(Overlay::Group(GroupOverlay::Members(MembersState::new(
                group,
            ))));
        }
    }

    /// The groups' box on top, to change it.
    fn group_overlay_mut(&mut self) -> Option<&mut GroupOverlay> {
        match self.overlays.last_mut() {
            Some(Overlay::Group(overlay)) => Some(overlay),
            _ => None,
        }
    }

    /// The groups' box, wherever it is (QUIT may be over it).
    fn group_overlay_any(&mut self) -> Option<&mut GroupOverlay> {
        self.overlays
            .iter_mut()
            .rev()
            .find_map(|overlay| match overlay {
                Overlay::Group(group) => Some(group),
                _ => None,
            })
    }

    /// The groups' box on top becomes `next`.
    fn replace_group_overlay(&mut self, next: GroupOverlay) {
        if let Some(top) = self.group_overlay_mut() {
            *top = next;
            self.dirty = true;
        }
    }

    fn close_group_overlay(&mut self) {
        self.overlays
            .retain(|overlay| !matches!(overlay, Overlay::Group(_)));
        self.dirty = true;
    }

    /// A paste while NEW GROUP's name field is on top: one line, into it.
    /// Whether it took it.
    pub(super) fn group_paste(&mut self, text: &str) -> bool {
        let Some(GroupOverlay::Name { typed, problem }) = self.group_overlay_mut() else {
            return false;
        };
        for c in display::field_input(text, false).chars() {
            if typed.chars().count() >= MAX_GROUP_NAME_CHARS {
                break;
            }
            typed.push(c);
        }
        *problem = None;
        self.dirty = true;
        true
    }

    /// The groups' boxes' keys; Ctrl+C opens QUIT.
    pub(super) fn on_group_overlay_key(&mut self, key: KeyEvent, overlay: GroupOverlay) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        match overlay {
            GroupOverlay::Name { typed, .. } => self.on_group_name_key(key, &typed),
            GroupOverlay::Pick(pick) => self.on_pick_key(key, &pick),
            GroupOverlay::Members(members) => self.on_members_key(key, &members),
            GroupOverlay::Delivery { .. } => {
                if key.code == KeyCode::Esc || self.confirms(key) {
                    self.close_overlay();
                }
            }
        }
    }

    /// NEW GROUP's name: letters are text, Backspace takes one back, Enter
    /// (not right after a paste) goes on to the picker once the name is one
    /// raven-core takes, Esc cancels.
    fn on_group_name_key(&mut self, key: KeyEvent, typed: &str) {
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => self.close_overlay(),
            (KeyCode::Backspace, _) if !has_ctrl_or_alt(key) => {
                if let Some(GroupOverlay::Name { typed, problem }) = self.group_overlay_mut() {
                    typed.pop();
                    *problem = None;
                }
                self.dirty = true;
            }
            (_, Some(c)) => {
                if let Some(GroupOverlay::Name { typed, problem }) = self.group_overlay_mut() {
                    if typed.chars().count() < MAX_GROUP_NAME_CHARS && !c.is_control() {
                        typed.push(c);
                    }
                    *problem = None;
                }
                self.dirty = true;
            }
            _ if self.confirms(key) => {
                let name = core_group::clean_text(typed, MAX_GROUP_NAME_CHARS);
                let problem = if name.is_empty() {
                    Some(NAME_EMPTY.to_owned())
                } else if !core_group::name_ok(&name) {
                    Some(GroupError::BadName.sentence())
                } else {
                    None
                };
                match problem {
                    Some(problem) => {
                        if let Some(GroupOverlay::Name { problem: shown, .. }) =
                            self.group_overlay_mut()
                        {
                            *shown = Some(problem);
                        }
                        self.dirty = true;
                    }
                    None => self.replace_group_overlay(GroupOverlay::Pick(PickState::new(
                        PickFor::Create { name },
                    ))),
                }
            }
            _ => {}
        }
    }

    /// The picker: Up and Down (or k and j) mark a friend, Space picks or
    /// unpicks them, Enter (not right after a paste) creates the group or
    /// adds them; Esc goes back (to the name, or MEMBERS). Nothing while its
    /// change runs.
    fn on_pick_key(&mut self, key: KeyEvent, pick: &PickState) {
        if pick.busy {
            return;
        }
        let candidates: Vec<(String, String)> = self
            .pick_candidates(&pick.purpose)
            .into_iter()
            .map(|c| (c.pub_hex.to_ascii_lowercase(), c.label.clone()))
            .collect();
        let cap = self.pick_cap(&pick.purpose);
        let last = candidates.len().saturating_sub(1);
        let mut next = pick.clone();
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => {
                let back = match &pick.purpose {
                    PickFor::Create { name } => GroupOverlay::Name {
                        typed: name.clone(),
                        problem: None,
                    },
                    PickFor::Add { group } => GroupOverlay::Members(MembersState::new(*group)),
                };
                self.replace_group_overlay(back);
                return;
            }
            (KeyCode::Up, _) | (_, Some('k')) => next.cursor = next.cursor.saturating_sub(1),
            (KeyCode::Down, _) | (_, Some('j')) => next.cursor = (next.cursor + 1).min(last),
            (_, Some(' ')) => {
                let Some((key, _)) = candidates.get(next.cursor) else {
                    return;
                };
                next.problem = None;
                if let Some(at) = next.picked.iter().position(|k| k == key) {
                    next.picked.remove(at);
                } else if next.picked.len() >= cap {
                    next.problem = Some(GroupError::TooMany.sentence());
                } else {
                    next.picked.push(key.clone());
                }
            }
            _ if self.confirms(key) => {
                let members: Vec<(Key, String)> = next
                    .picked
                    .iter()
                    .filter_map(|picked| candidates.iter().find(|(k, _)| k == picked))
                    .filter_map(|(k, label)| Some((key_of(k)?, label.clone())))
                    .collect();
                if members.is_empty() {
                    next.problem = Some(PICK_NONE.to_owned());
                } else {
                    next.problem = None;
                    next.busy = true;
                    let change = match &pick.purpose {
                        PickFor::Create { name } => GroupChange::Create {
                            name: name.clone(),
                            members,
                        },
                        PickFor::Add { group } => GroupChange::Add {
                            group: *group,
                            members,
                        },
                    };
                    self.queue_send_job(SendJob::GroupChange(change));
                }
            }
            _ => return,
        }
        self.replace_group_overlay(GroupOverlay::Pick(next));
    }

    /// MEMBERS: Up and Down (or k and j) mark a member; the admin's A adds
    /// friends (the picker) and X removes the member marked, anyone else's L
    /// leaves the group; both ask first (Y does it, N or Esc keeps things
    /// as they are). Esc or M closes. Nothing while a change runs.
    fn on_members_key(&mut self, key: KeyEvent, members: &MembersState) {
        if members.busy {
            return;
        }
        let mut next = members.clone();
        if let Some(ask) = &members.ask {
            match (key.code, plain_char(key)) {
                (_, Some('y' | 'Y')) => {
                    let change = match ask {
                        MemberAsk::Remove { key, name } => GroupChange::Remove {
                            group: members.group,
                            member: *key,
                            name: name.clone(),
                        },
                        MemberAsk::Leave => GroupChange::Leave {
                            group: members.group,
                        },
                    };
                    next.busy = true;
                    self.queue_send_job(SendJob::GroupChange(change));
                }
                (KeyCode::Esc, _) | (_, Some('n' | 'N')) => next.ask = None,
                _ => return,
            }
            self.replace_group_overlay(GroupOverlay::Members(next));
            return;
        }
        let chat = self
            .group_chat()
            .filter(|chat| chat.view.summary.id == members.group);
        let admin = chat.is_some_and(|chat| chat.view.summary.i_am_admin);
        let active = self.group_active(&members.group);
        let count = chat.map_or(0, |chat| chat.view.members.len());
        let marked = chat
            .and_then(|chat| chat.view.members.get(members.cursor))
            .map(|m| (m.key, m.display(), m.me));
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) | (_, Some('m' | 'M')) => {
                self.close_overlay();
                return;
            }
            (KeyCode::Up, _) | (_, Some('k')) => next.cursor = next.cursor.saturating_sub(1),
            (KeyCode::Down, _) | (_, Some('j')) => {
                next.cursor = (next.cursor + 1).min(count.saturating_sub(1));
            }
            (_, Some('a' | 'A')) if admin && active => {
                self.replace_group_overlay(GroupOverlay::Pick(PickState::new(PickFor::Add {
                    group: members.group,
                })));
                return;
            }
            (_, Some('x' | 'X')) if admin && active => match marked {
                Some((key, name, false)) => next.ask = Some(MemberAsk::Remove { key, name }),
                _ => return,
            },
            (_, Some('l' | 'L')) if !admin && active && chat.is_some() => {
                next.ask = Some(MemberAsk::Leave);
            }
            _ => return,
        }
        self.replace_group_overlay(GroupOverlay::Members(next));
    }

    /// A change answered. Done: NEW GROUP closes and the new group opens,
    /// an add goes back to MEMBERS, a remove stays there, a leave closes
    /// it; a toast says what happened. Refused: the box says why (the
    /// picker), or a toast does. The groups are read again.
    pub(super) fn group_changed(&mut self, change: GroupChange, done: GroupDone<GroupId>) {
        let group_name = |app: &App, id: &GroupId| {
            app.groups
                .list
                .iter()
                .find(|g| g.id == *id)
                .map(|g| g.name.clone())
                .unwrap_or_else(|| "the group".to_owned())
        };
        match done.result {
            Ok(id) => {
                let toast = match &change {
                    GroupChange::Create { name, .. } => {
                        self.close_group_overlay();
                        self.groups.created = Some(id);
                        self.show_group(id);
                        format!("Created {name}. You are its admin.")
                    }
                    GroupChange::Add { group, members } => {
                        if let Some(overlay) = self.group_overlay_any() {
                            *overlay = GroupOverlay::Members(MembersState::new(*group));
                        }
                        let names: Vec<&str> = members.iter().map(|(_, n)| n.as_str()).collect();
                        format!("Added {} to {}.", names.join(", "), group_name(self, group))
                    }
                    GroupChange::Remove { group, name, .. } => {
                        if let Some(GroupOverlay::Members(members)) = self.group_overlay_any() {
                            members.busy = false;
                            members.ask = None;
                            members.cursor = 0;
                        }
                        format!(
                            "Removed {name} from {}. They keep what they already received.",
                            group_name(self, group)
                        )
                    }
                    GroupChange::Leave { group } => {
                        self.close_group_overlay();
                        format!(
                            "You left {}. What you received stays here.",
                            group_name(self, group)
                        )
                    }
                };
                self.push_toast(&toast);
                if !done.kicked {
                    self.push_toast(GROUP_WAITS);
                }
            }
            Err(why) => {
                self.group_change_failed();
                match self.group_overlay_any() {
                    Some(GroupOverlay::Pick(pick)) => pick.problem = Some(why),
                    _ => self.push_toast(&why),
                }
            }
        }
        self.dirty = true;
        self.load_groups(false);
    }

    /// A change's job ended without its answer (or refused): its box takes
    /// keys again.
    pub(super) fn group_change_failed(&mut self) {
        match self.group_overlay_any() {
            Some(GroupOverlay::Pick(pick)) => pick.busy = false,
            Some(GroupOverlay::Members(members)) => {
                members.busy = false;
                members.ask = None;
            }
            _ => {}
        }
        self.dirty = true;
    }
}
