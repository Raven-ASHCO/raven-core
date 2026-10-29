//! Messages: `messages.*`, the send worker, honest delivery states and the
//! events they cause.
//!
//! Where each message stands comes from three sources, strongest first (the
//! terminal app's `tui/delivery.rs` `tick`, branch feature/terminal-app):
//! the chat history (raven-core marks a row `delivered` only after the
//! friend's signed receipt was verified), raven-node's outbox (`queued`,
//! `sent`, `held`) and this session's own send jobs. "sent" means handed to
//! the friend's computer and not confirmed; "delivered" appears only after a
//! signed receipt, and the `receipt` event always comes first.
//!
//! A message sent in this session has an id of its own (`pending-N`) from
//! the start; once the history shows its row, the row is bound to it and
//! keeps that id for the rest of the session.
//!
//! What is unread is the terminal app's own count, from the read markers
//! both apps share (ash's tui/read_marks.rs): the friend's messages after
//! the one last read on this computer, in either app. `messages.mark_read`
//! moves a marker (never back), and an `unread` event follows every change
//! of a count, the terminal app's reads among them.

use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ash_engine::engine::{self as bridge, Carrier, ContactView, ReadMark, ReadMarks};
use raven_core::chat_history::ChatHistoryEntry;
use raven_core::ipc::OutboxItem;
use serde_json::{json, Map, Value};

use crate::engine::{lock, now_ms, Inner, OutboxSnap};
use crate::envelope::{code, ApiError, Args, OpResult};
use crate::explain::{self, OutcomeKind};
use crate::safety;
use crate::settings::Delivery;

/// How long a friend counts as in touch after a message arrived from them or
/// one of theirs was delivered (the terminal app's presence.rs).
const IN_TOUCH_FOR: Duration = Duration::from_secs(15 * 60);
/// Messages one `messages.history` returns at most.
const HISTORY_MAX: u64 = 1000;
const HISTORY_DEFAULT: u64 = 100;

/// API.md's `Message.state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Sending,
    Sent,
    Delivered,
    Waiting,
    TimeRanOut,
    NotSentMeetFirst,
    Failed,
}

impl State {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            State::Sending => "sending",
            State::Sent => "sent",
            State::Delivered => "delivered",
            State::Waiting => "waiting",
            State::TimeRanOut => "time_ran_out",
            State::NotSentMeetFirst => "not_sent_meet_first",
            State::Failed => "failed",
        }
    }
}

/// Where a send job is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Job {
    Queued,
    Running,
    Done,
}

/// How a send job ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The friend's signed receipt came back, over `path`.
    Delivered { path: PathLabel },
    /// Queued on this computer. `background`: raven-node keeps trying it.
    /// `connect`: the dial never reached the friend's Raven.
    Waiting { background: bool, connect: bool },
    /// Written to the friend's computer, not confirmed.
    Sent,
    /// Nothing was queued. `meet_first`: no secure connection with the
    /// friend, and their computer couldn't be reached to set one up.
    NotSent { meet_first: bool },
    /// The background program could not be started or reached: nothing was
    /// dialled or written.
    NodeUnavailable,
    /// Stopped before it ran.
    Stopped,
}

impl Outcome {
    /// The send queued nothing and wrote no history row: no row is its own.
    fn wrote_nothing(&self) -> bool {
        matches!(
            self,
            Outcome::NotSent { .. } | Outcome::NodeUnavailable | Outcome::Stopped
        )
    }

    /// Nothing of the message can have reached the friend's computer.
    fn never_written(&self) -> bool {
        matches!(
            self,
            Outcome::NotSent { .. }
                | Outcome::NodeUnavailable
                | Outcome::Stopped
                | Outcome::Waiting { connect: true, .. }
        )
    }
}

/// One message sent in this session.
#[derive(Debug, Clone)]
pub(crate) struct Pending {
    pub id: String,
    /// The friend's key in lower case.
    pub peer: String,
    pub address: String,
    pub body: String,
    pub created_ms: u64,
    pub started: Instant,
    /// The ids of the friend's rows of yours when it was sent: none of them
    /// is its row.
    pub snapshot: HashSet<String>,
    pub bound_mid: Option<String>,
    pub job: Job,
    pub outcome: Option<Outcome>,
    /// The send's own text (the CLI's outcome sentence), for Details.
    pub raw: String,
    /// How it travelled, once raven-node's outbox delivered it (its last
    /// path to the friend then): kept, so a later delivery to the same
    /// friend does not change it.
    pub path: Option<PathLabel>,
    pub finished: Option<Instant>,
}

/// What the last observation saw, to tell what changed.
#[derive(Debug, Default)]
struct Observed {
    /// Each message's state, attempts and deadline (`until_ms`).
    states: HashMap<String, (State, u32, Option<u64>)>,
    incoming: HashSet<String>,
    presence: HashMap<String, &'static str>,
    receipts: HashSet<String>,
    /// Each friend's unread count, by key.
    unread: HashMap<String, usize>,
}

#[derive(Debug, Default)]
pub(crate) struct MessageBook {
    next: u64,
    pub(crate) pendings: Vec<Pending>,
    /// History row id → the session id it is shown under.
    alias: HashMap<String, String>,
    observed: Option<Observed>,
    /// When each friend was last in touch (this session): (when, wall ms).
    touches: HashMap<String, (Instant, u64)>,
    /// Ended messages Send again replaced with a new one (`messages.retry`'s
    /// `replaces`): `messages.history` leaves them out, so a chat shows one
    /// bubble for the text, the new one.
    replaced: HashSet<String>,
    /// Messages of yours another program on this profile sent (the terminal
    /// app, the CLI) after this engine's first look, by id.
    foreign: HashSet<String>,
    /// The path each of those was delivered on, read once (None: looked,
    /// none found).
    foreign_paths: HashMap<String, Option<PathLabel>>,
    /// Ended messages the person deleted (`messages.delete`) or replaced
    /// with Send again, read from `desktop_hidden.json` on first use: the
    /// chats leave them out.
    hidden: Option<HashSet<String>>,
    /// How each delivered message of yours travelled and when its receipt
    /// came, by history id, as `desktop_private.rms` keeps them (read on
    /// first use; settings.rs).
    deliveries: Option<Deliveries>,
    /// Where this run's sends last delivered to each friend on the local
    /// network (the address, when), by key in lower case: Routes shows the
    /// address in use (E1).
    pub(crate) lan_used: HashMap<String, (String, u64)>,
}

/// [`MessageBook::deliveries`]: the records, whether the file could be
/// read (one that can't is never written over), and whether a record
/// changed since the last save.
#[derive(Debug, Default)]
struct Deliveries {
    records: HashMap<String, Delivery>,
    readable: bool,
    changed: bool,
}

/// One message as the app sees it.
#[derive(Debug, Clone)]
pub(crate) struct View {
    pub id: String,
    /// Its history row id, once it has one.
    pub mid: Option<String>,
    pub peer: String,
    pub address: String,
    pub incoming: bool,
    pub text: String,
    pub at_ms: u64,
    pub state: State,
    pub until_ms: Option<u64>,
    pub path: Option<PathLabel>,
    /// When the engine saw its receipt (yours, delivered), when it did.
    pub delivered_at_ms: Option<u64>,
    pub attempts: Option<u32>,
    pub history: Option<String>,
    pub outbox: Option<OutboxItem>,
    pub pending: Option<Pending>,
}

impl View {
    /// When its receipt came, when that was noticeably later than it was
    /// written (`bridge::LATE_DELIVERY_MS`): the apps then say when (E1: a
    /// message that waited an hour said only "Delivered").
    pub(crate) fn late_delivery(&self) -> Option<u64> {
        self.delivered_at_ms
            .filter(|at| *at >= self.at_ms.saturating_add(bridge::LATE_DELIVERY_MS))
    }

    pub(crate) fn json(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), self.id.clone().into());
        m.insert("address".into(), self.address.clone().into());
        m.insert(
            "direction".into(),
            if self.incoming { "in" } else { "out" }.into(),
        );
        m.insert("text".into(), safety::text(&self.text).into());
        m.insert("at_ms".into(), self.at_ms.into());
        m.insert("state".into(), self.state.as_str().into());
        if let Some(until) = self.until_ms {
            m.insert("until_ms".into(), until.into());
        }
        if let Some(path) = &self.path {
            m.insert("path".into(), path.text.clone().into());
            m.insert("path_kind".into(), path.kind.into());
        }
        if let Some(at) = self.late_delivery() {
            m.insert("delivered_at_ms".into(), at.into());
        }
        if let Some(attempts) = self.attempts {
            m.insert("attempts".into(), attempts.into());
        }
        Value::Object(m)
    }
}

/// A friend's mark (API.md's `presence`), and what goes with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PresenceInfo {
    pub presence: &'static str,
    pub last_contact_ms: Option<u64>,
    /// (count, until_ms): until is None when no node says (it is 0 in the
    /// JSON then).
    pub waiting: Option<(usize, Option<u64>)>,
}

/// What one refresh read and worked out.
pub(crate) struct Snapshot {
    pub contacts: Arc<Vec<ContactView>>,
    pub views: Vec<View>,
    /// By the friend's key in lower case.
    pub presence: HashMap<String, PresenceInfo>,
    /// Each friend's unread messages, by key in lower case.
    pub unread: HashMap<String, usize>,
    pub outbox: Arc<OutboxSnap>,
}

/// The address of a key given as hex (rvn1), or the hex itself.
fn address_of(pub_hex: &str, contacts: &[ContactView]) -> String {
    if let Some(c) = contacts
        .iter()
        .find(|c| c.pub_hex.eq_ignore_ascii_case(pub_hex))
    {
        return c.address.clone();
    }
    hex::decode(pub_hex)
        .ok()
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
        .map_or_else(|| pub_hex.to_owned(), |k| raven_core::encode_address(&k))
}

/// How a message travelled: a stable kind (API.md's `path_kind`) and its
/// words (`path`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathLabel {
    pub kind: &'static str,
    pub text: String,
}

impl PathLabel {
    pub(crate) fn of(kind: &'static str, text: &str) -> PathLabel {
        PathLabel {
            kind,
            text: text.to_owned(),
        }
    }
}

/// Every path kind and its words (API.md lists the same).
pub(crate) const PATH_KINDS: [(&str, &str); 13] = [
    ("lan", "LAN direct"),
    ("internet", "Internet direct"),
    ("p2p", "p2p"),
    ("p2p_direct", "p2p \u{00B7} direct"),
    ("p2p_reversed", "p2p \u{00B7} reversed"),
    ("p2p_relayed", "p2p \u{00B7} relayed"),
    ("p2p_hole_punched", "p2p \u{00B7} hole punched"),
    ("websocket", "p2p \u{00B7} relayed over WebSocket"),
    ("nearby", "Bluetooth nearby"),
    ("onion", "via Tor"),
    ("friend", "Held by a friend"),
    ("handoff", "Passed on between friends"),
    ("letter", "Sealed letter with a friend"),
];

/// The words of path kind `kind`.
pub(crate) fn path_words(kind: &'static str) -> PathLabel {
    let text = PATH_KINDS
        .iter()
        .find(|(k, _)| *k == kind)
        .map_or(kind, |(_, t)| t);
    PathLabel::of(kind, text)
}

/// The words of a path kind kept as text (`desktop_private.rms`); None for
/// a kind this engine doesn't know.
fn path_of_kind(kind: &str) -> Option<PathLabel> {
    PATH_KINDS
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(k, text)| PathLabel::of(k, text))
}

/// How a carrier and raven-node's path read (`LAN direct`, `p2p · relayed`).
/// `relay_paths`: the transports of the relays raven-node uses now; a
/// relayed path while every one of them is WebSocket reads as such.
pub(crate) fn path_label(carrier: &str, path: &str, relay_paths: &[String]) -> Option<PathLabel> {
    let kind = match carrier {
        "lan_dial" | "lan" => "lan",
        "internet_dial" | "internet" => "internet",
        "nearby_dial" | "nearby" => "nearby",
        "onion_dial" | "onion" => "onion",
        "p2p_dial" | "p2p" => match path.trim() {
            "direct" => "p2p_direct",
            "reversed" => "p2p_reversed",
            "relayed"
                if !relay_paths.is_empty() && relay_paths.iter().all(|t| t.starts_with("wss")) =>
            {
                "websocket"
            }
            "relayed" => "p2p_relayed",
            "hole_punched" => "p2p_hole_punched",
            _ => "p2p",
        },
        _ => return None,
    };
    Some(path_words(kind))
}

/// How the last delivery to `peer` travelled, from raven-node's Status read
/// at `now_ms`, when that delivery came after `since_ms` (the message was
/// written then). Its age counts whole seconds, so the delivery is placed at
/// most a second late: one to the same friend in the second before the
/// message was written could be taken for it, but a delivered message is the
/// last one raven-node noted for that friend, unless a friend carried it
/// (said from the outbox before: `friend`, `handoff`, `letter`).
fn last_path_since(
    paths: &[raven_core::ipc::ContactPath],
    relay_paths: &[String],
    peer: &str,
    since_ms: u64,
    now_ms: u64,
) -> Option<PathLabel> {
    paths
        .iter()
        .find(|p| {
            p.peer_pub_hex.eq_ignore_ascii_case(peer)
                && now_ms.saturating_sub(p.age_s.saturating_mul(1000)) >= since_ms
        })
        .and_then(|p| path_label(&p.carrier, &p.path, relay_paths))
}

/// How a message friends carry travels, from raven-node's outbox: a letter
/// a friend holds, a copy passed on between friends, or a copy a friend
/// holds.
pub(crate) fn carried_label(item: &OutboxItem, letter: bool) -> Option<PathLabel> {
    if letter {
        Some(path_words("letter"))
    } else if item.in_custody > 0 && item.custody_forwarded {
        Some(path_words("handoff"))
    } else if item.in_custody > 0 {
        Some(path_words("friend"))
    } else {
        None
    }
}

/// The state of one message from what is known of it (strongest first).
fn state_of(
    history: Option<&str>,
    outbox: Option<&OutboxItem>,
    pending: Option<&Pending>,
    now_ms: u64,
) -> (State, Option<u64>) {
    let ob = outbox.map_or("", |i| i.state.as_str());
    let outcome = pending.and_then(|p| p.outcome.as_ref());
    let until = outbox.map(|i| i.expires_at_ms).filter(|ms| *ms > 0);
    if matches!(history, Some("delivered" | "read"))
        || ob == "delivered"
        || matches!(outcome, Some(Outcome::Delivered { .. }))
    {
        return (State::Delivered, None);
    }
    if history == Some("expired") || ob == "expired" {
        return (State::TimeRanOut, None);
    }
    // A send of this run that queued nothing keeps its own word over the
    // `failed` row the engine wrote to keep it in the chat (record_not_sent).
    if matches!(outcome, Some(Outcome::NotSent { meet_first: true }))
        && matches!(history, None | Some("failed"))
        && ob.is_empty()
    {
        return (State::NotSentMeetFirst, None);
    }
    if matches!(history, Some("failed" | "cancelled")) || matches!(ob, "failed" | "cancelled") {
        return (State::Failed, None);
    }
    if ob == "sent" || matches!(outcome, Some(Outcome::Sent)) {
        return (State::Sent, None);
    }
    if ob == "held" {
        return (State::Waiting, until);
    }
    if pending.is_some_and(|p| matches!(p.job, Job::Queued | Job::Running)) {
        return (State::Sending, None);
    }
    if ob == "queued"
        || history == Some("queued")
        || matches!(outcome, Some(Outcome::Waiting { .. }))
    {
        // Honest deadlines: past its time it is not waiting anymore, even
        // before raven-node writes `expired`.
        if until.is_some_and(|u| now_ms >= u) {
            return (State::TimeRanOut, None);
        }
        return (State::Waiting, until);
    }
    match outcome {
        Some(Outcome::NotSent { meet_first: true }) => return (State::NotSentMeetFirst, None),
        Some(Outcome::NotSent { .. } | Outcome::NodeUnavailable | Outcome::Stopped) => {
            return (State::Failed, None)
        }
        _ => {}
    }
    // A row with no delivery state (written before Raven kept one) or an
    // unknown one: it left this computer, no receipt is known.
    (State::Sent, None)
}

/// Binds this session's sends to the history rows that are theirs: the
/// oldest unbound send takes the first row of yours to the same friend that
/// is not in its snapshot, holds the same text and is no other send's. A
/// send that wrote nothing takes none (the terminal app's delivery.rs
/// `bind`).
fn bind(book: &mut MessageBook, history: &[ChatHistoryEntry]) {
    let mut taken: HashSet<String> = book.alias.keys().cloned().collect();
    let mut new_alias = Vec::new();
    for send in book.pendings.iter_mut().filter(|p| {
        p.bound_mid.is_none() && !p.outcome.as_ref().is_some_and(Outcome::wrote_nothing)
    }) {
        let found = history.iter().find_map(|e| {
            let mid = e.message_id_hex.to_ascii_lowercase();
            let body = if e.body.is_empty() {
                &e.preview
            } else {
                &e.body
            };
            (e.direction == "out"
                && e.peer_pub_hex.eq_ignore_ascii_case(&send.peer)
                && !mid.is_empty()
                && body.trim_end() == send.body.trim_end()
                && !send.snapshot.contains(&mid)
                && !taken.contains(&mid))
            .then_some(mid)
        });
        if let Some(mid) = found {
            taken.insert(mid.clone());
            send.bound_mid = Some(mid.clone());
            new_alias.push((mid, send.id.clone()));
        }
    }
    book.alias.extend(new_alias);
}

/// Every message: the history's rows in written order, then this session's
/// sends that have no row.
fn views(
    book: &mut MessageBook,
    history: &[ChatHistoryEntry],
    outbox: &OutboxSnap,
    contacts: &[ContactView],
    now_ms: u64,
) -> Vec<View> {
    bind(book, history);
    let mut out = Vec::with_capacity(history.len() + book.pendings.len());
    for e in history {
        let mid = e.message_id_hex.to_ascii_lowercase();
        let peer = e.peer_pub_hex.to_ascii_lowercase();
        let incoming = e.direction != "out";
        let text = if e.body.is_empty() {
            e.preview.clone()
        } else {
            e.body.clone()
        };
        if incoming {
            out.push(View {
                id: mid.clone(),
                mid: Some(mid),
                address: address_of(&peer, contacts),
                peer,
                incoming,
                text,
                at_ms: e.created_at_ms,
                state: State::Delivered,
                until_ms: None,
                path: None,
                delivered_at_ms: None,
                attempts: None,
                history: Some(e.delivery.clone()),
                outbox: None,
                pending: None,
            });
            continue;
        }
        let pending = book
            .alias
            .get(&mid)
            .and_then(|id| book.pendings.iter().find(|p| &p.id == id))
            .cloned();
        // The deadline the outbox applies (with the long message horizon
        // live, 7 days after it was written, not its envelope's day: E1).
        let item = outbox.items.get(&mid).cloned().map(|mut i| {
            i.expires_at_ms = bridge::waits_until(&i, Some(e.created_at_ms));
            i
        });
        let (state, until_ms) =
            state_of(Some(&e.delivery), item.as_ref(), pending.as_ref(), now_ms);
        let letter = outbox.letters.contains(&mid);
        let mut path = match pending.as_ref().and_then(|p| p.outcome.as_ref()) {
            Some(Outcome::Delivered { path }) if !path.text.is_empty() => Some(path.clone()),
            _ => item.as_ref().and_then(|i| {
                // Friends carry it (held, passed on, or a letter): said
                // while it waits too; else how the last write travelled.
                carried_label(i, letter).or_else(|| {
                    matches!(state, State::Sent | State::Delivered)
                        .then(|| path_label(&i.carrier, &i.path, &[]))
                        .flatten()
                })
            }),
        };
        // A message of this session: friends carrying it is kept from when
        // it was seen; once raven-node's outbox delivered it, its last path
        // to the friend (a delivery after the message was written), read
        // once.
        if let Some(p) = pending.as_ref() {
            let carried = path
                .clone()
                .filter(|l| matches!(l.kind, "friend" | "handoff" | "letter"));
            let found = match (&p.path, carried, state) {
                (Some(_), _, _) => None,
                (None, Some(l), _) => Some(l),
                (None, None, State::Delivered) => path.clone(),
                _ => None,
            };
            if let Some(found) = found {
                if let Some(send) = book.pendings.iter_mut().find(|s| s.id == p.id) {
                    send.path = Some(found);
                }
            }
            let kept = book
                .pendings
                .iter()
                .find(|s| s.id == p.id)
                .and_then(|s| s.path.clone());
            if kept.is_some() && (state == State::Delivered || path.is_none()) {
                path = kept;
            }
        }
        out.push(View {
            id: pending
                .as_ref()
                .map_or_else(|| mid.clone(), |p| p.id.clone()),
            mid: Some(mid),
            address: address_of(&peer, contacts),
            peer,
            incoming,
            text,
            at_ms: e.created_at_ms,
            state,
            until_ms,
            path,
            delivered_at_ms: None,
            attempts: item.as_ref().map(|i| i.attempts).filter(|n| *n > 0),
            history: Some(e.delivery.clone()),
            outbox: item,
            pending,
        });
    }
    for p in book.pendings.iter().filter(|p| p.bound_mid.is_none()) {
        let (state, until_ms) = state_of(None, None, Some(p), now_ms);
        let path = match &p.outcome {
            Some(Outcome::Delivered { path }) if !path.text.is_empty() => Some(path.clone()),
            _ => None,
        };
        out.push(View {
            id: p.id.clone(),
            mid: None,
            peer: p.peer.clone(),
            address: p.address.clone(),
            incoming: false,
            text: p.body.clone(),
            at_ms: p.created_ms,
            state,
            until_ms,
            path,
            delivered_at_ms: None,
            attempts: None,
            history: None,
            outbox: None,
            pending: Some(p.clone()),
        });
    }
    out
}

/// Each saved friend's mark, from their addresses, their messages and this
/// session's touches (the terminal app's presence.rs).
fn presence_map(
    book: &MessageBook,
    contacts: &[ContactView],
    views: &[View],
    now_ms: u64,
) -> HashMap<String, PresenceInfo> {
    let mut out = HashMap::new();
    for c in contacts {
        let peer = c.pub_hex.to_ascii_lowercase();
        let theirs: Vec<&View> = views.iter().filter(|v| v.peer == peer).collect();
        let newest = theirs.iter().map(|v| v.at_ms.min(now_ms)).max();
        // The friend was last heard from: a message from them, or one of
        // yours they confirmed. Kept in the history, so a friend whose
        // messages came before this engine's first look still counts as in
        // touch (E1: "No recent contact" beside their messages).
        let heard = theirs
            .iter()
            .filter(|v| v.incoming || v.state == State::Delivered)
            .map(|v| v.at_ms.min(now_ms))
            .max();
        let heard_recently =
            heard.filter(|ms| now_ms.saturating_sub(*ms) < IN_TOUCH_FOR.as_millis() as u64);
        let waiting: Vec<&&View> = theirs
            .iter()
            .filter(|v| !v.incoming && v.state == State::Waiting)
            .collect();
        let until = waiting.iter().filter_map(|v| v.until_ms).min();
        let touch = book
            .touches
            .get(&peer)
            .filter(|(at, _)| at.elapsed() < IN_TOUCH_FOR)
            .map(|(_, ms)| *ms)
            .max(heard_recently);
        let no_address = [&c.lan_dial, &c.internet_dial, &c.p2p]
            .iter()
            .all(|r| r.trim().is_empty());
        let info = if no_address {
            PresenceInfo {
                presence: "no_address",
                last_contact_ms: heard,
                waiting: None,
            }
        } else if !waiting.is_empty() {
            PresenceInfo {
                presence: "waiting",
                last_contact_ms: touch.or(newest),
                waiting: Some((waiting.len(), until)),
            }
        } else if let Some(ms) = touch {
            PresenceInfo {
                presence: "in_touch",
                last_contact_ms: Some(ms),
                waiting: None,
            }
        } else {
            PresenceInfo {
                presence: "none",
                last_contact_ms: heard,
                waiting: None,
            }
        };
        out.insert(peer, info);
    }
    out
}

/// Each saved friend's unread messages, as the terminal app counts them
/// (`bridge::unread`): theirs after the one their marker names.
fn unread_map(
    contacts: &[ContactView],
    views: &[View],
    marks: &ReadMarks,
) -> HashMap<String, usize> {
    contacts
        .iter()
        .map(|c| {
            let peer = c.pub_hex.to_ascii_lowercase();
            let rows = views
                .iter()
                .filter(|v| v.peer == peer)
                .map(|v| bridge::Row {
                    id: v.mid.as_deref().unwrap_or_default(),
                    outgoing: !v.incoming,
                    at_ms: v.at_ms,
                });
            let n = bridge::unread(rows, marks.get(&peer));
            (peer, n)
        })
        .collect()
}

impl Inner {
    /// Reads the profile (cached reads), works out every message's state and
    /// each friend's mark and unread count, and emits the events for what
    /// changed since the last time. The first time only notes what is there.
    pub(crate) fn refresh(&self, outbox_age: Duration) -> Result<Snapshot, ApiError> {
        let contacts = self.contacts()?;
        let history = self.history()?;
        let outbox = self.outbox(outbox_age);
        let marks = self.read_marks();
        let now = now_ms();
        let mut book = lock(&self.book);
        let mut views = views(&mut book, &history, &outbox, &contacts, now);
        self.label_outbox_deliveries(&mut book, &mut views);
        self.apply_deliveries(&mut book, &mut views, now);
        self.observe_messages(&mut book, &views, now);
        let presence = presence_map(&book, &contacts, &views, now);
        self.observe_presence(&mut book, &contacts, &presence);
        let unread = unread_map(&contacts, &views, &marks);
        self.observe_unread(&mut book, &contacts, &unread);
        Ok(Snapshot {
            contacts,
            views,
            presence,
            unread,
            outbox,
        })
    }

    /// The messages of this session raven-node's outbox delivered with no
    /// path known: its last path to the friend, from one fresh Status, when
    /// that delivery came after the message was written (kept with the
    /// message from then on).
    fn label_outbox_deliveries(&self, book: &mut MessageBook, views: &mut [View]) {
        // Yours sent by another program on this profile since the first
        // look: the path read for it before, else it is due once delivered
        // (looked up once).
        let mut foreign_due: Vec<usize> = Vec::new();
        for (i, v) in views.iter_mut().enumerate() {
            if v.incoming || v.pending.is_some() || v.path.is_some() {
                continue;
            }
            let new = book
                .observed
                .as_ref()
                .is_some_and(|o| !o.states.contains_key(&v.id));
            match book.foreign_paths.get(&v.id) {
                Some(found) => v.path = found.clone(),
                None if (new || book.foreign.contains(&v.id)) && v.state == State::Delivered => {
                    foreign_due.push(i)
                }
                None => {}
            }
        }
        let due: Vec<usize> = views
            .iter()
            .enumerate()
            .filter(|(_, v)| {
                v.state == State::Delivered
                    && v.path.is_none()
                    && v.pending.as_ref().is_some_and(|p| p.path.is_none())
            })
            .map(|(i, _)| i)
            .collect();
        if due.is_empty() && foreign_due.is_empty() {
            return;
        }
        let Ok(dir) = self.data_dir() else {
            return;
        };
        let probe = crate::node::probe(dir);
        let now = now_ms();
        for i in due {
            let v = &mut views[i];
            let Some(p) = v.pending.as_ref() else {
                continue;
            };
            let Some(found) = last_path_since(
                &probe.last_paths,
                &probe.relay_paths,
                &v.peer,
                p.created_ms,
                now,
            ) else {
                continue;
            };
            if let Some(send) = book.pendings.iter_mut().find(|s| s.id == p.id) {
                send.path = Some(found.clone());
            }
            v.path = Some(found);
        }
        for i in foreign_due {
            let v = &mut views[i];
            let found =
                last_path_since(&probe.last_paths, &probe.relay_paths, &v.peer, v.at_ms, now);
            book.foreign_paths.insert(v.id.clone(), found.clone());
            v.path = found;
        }
    }

    /// The delivered messages of yours: each takes the way it travelled
    /// and when its receipt came from `desktop_private.rms` when nothing
    /// newer says (E1: path chips were gone after a restart), and what this
    /// look learned goes there (a receipt seen now: a message that turned
    /// delivered since the last look, or one of this run's sends when its
    /// job ended). The first look only reads.
    fn apply_deliveries(&self, book: &mut MessageBook, views: &mut [View], now: u64) {
        let Ok(dir) = self.data_dir() else {
            return;
        };
        let baseline = book.observed.is_none();
        let observed: HashMap<String, State> = book
            .observed
            .as_ref()
            .map(|o| {
                o.states
                    .iter()
                    .map(|(id, (state, _, _))| (id.clone(), *state))
                    .collect()
            })
            .unwrap_or_default();
        let deliveries =
            book.deliveries
                .get_or_insert_with(|| match crate::settings::load_deliveries(dir) {
                    Ok(records) => Deliveries {
                        records,
                        readable: true,
                        changed: false,
                    },
                    Err(_) => Deliveries::default(),
                });
        for v in views
            .iter_mut()
            .filter(|v| !v.incoming && v.state == State::Delivered)
        {
            let Some(mid) = v.mid.clone() else {
                continue;
            };
            let known = deliveries.records.get(&mid).cloned().unwrap_or_default();
            let mut record = known.clone();
            match &v.path {
                None => v.path = record.path_kind.as_deref().and_then(path_of_kind),
                Some(path) => record.path_kind = Some(path.kind.to_owned()),
            }
            if record.at_ms.is_none() && !baseline {
                let job_end = v
                    .pending
                    .as_ref()
                    .and_then(|p| match (&p.outcome, p.finished) {
                        (Some(Outcome::Delivered { .. }), Some(at)) => {
                            Some(now.saturating_sub(at.elapsed().as_millis() as u64))
                        }
                        _ => None,
                    });
                let turned = observed.get(&v.id).is_none_or(|s| *s != State::Delivered);
                record.at_ms = job_end.or(turned.then_some(now));
            }
            v.delivered_at_ms = record.at_ms;
            if record != known {
                deliveries.records.insert(mid, record);
                deliveries.changed = true;
            }
        }
        if deliveries.readable && deliveries.changed {
            let kept: HashSet<&str> = views.iter().filter_map(|v| v.mid.as_deref()).collect();
            if crate::settings::save_deliveries(dir, &deliveries.records, &|id| kept.contains(id))
                .is_ok()
            {
                deliveries.changed = false;
            }
        }
    }

    fn observe_messages(&self, book: &mut MessageBook, views: &[View], now: u64) {
        let baseline = book.observed.is_none();
        let observed = book.observed.get_or_insert_with(Observed::default);
        let mut touched: Vec<String> = Vec::new();
        let mut foreign: Vec<String> = Vec::new();
        for v in views {
            if v.incoming {
                if observed.incoming.insert(v.id.clone()) && !baseline {
                    touched.push(v.peer.clone());
                    self.emit("incoming", json!({"message": v.json()}));
                }
                continue;
            }
            let attempts = v.attempts.unwrap_or(0);
            let before = observed
                .states
                .insert(v.id.clone(), (v.state, attempts, v.until_ms));
            if baseline {
                if v.state == State::Delivered {
                    observed.receipts.insert(v.id.clone());
                }
                continue;
            }
            match before {
                Some((state, old_attempts, old_until)) if state == v.state => {
                    if v.state == State::Waiting && attempts > old_attempts {
                        self.emit(
                            "retry",
                            json!({"id": v.id, "address": v.address, "attempts": attempts}),
                        );
                    }
                    // A waiting message whose deadline became known (or
                    // changed) after it started waiting: the apps' "until"
                    // follows it (E1: "Waiting for … · until –").
                    if v.state == State::Waiting && v.until_ms.is_some() && v.until_ms != old_until
                    {
                        self.emit(
                            "state",
                            json!({"id": v.id, "address": v.address, "state": v.state.as_str(),
                                   "until_ms": v.until_ms}),
                        );
                    }
                }
                _ => {
                    // Yours, sent by another program on this profile (the
                    // terminal app, the CLI): the open chat shows it at once,
                    // as it shows its own sends (E1).
                    if before.is_none() && v.pending.is_none() {
                        foreign.push(v.id.clone());
                        self.emit("outgoing", json!({"message": v.json()}));
                    }
                    if v.state == State::Delivered && observed.receipts.insert(v.id.clone()) {
                        // Only a verified, signed receipt makes a row
                        // delivered (raven-core); it is told first.
                        let ms = match &v.pending {
                            Some(p) => p
                                .finished
                                .unwrap_or_else(Instant::now)
                                .saturating_duration_since(p.started)
                                .as_millis() as u64,
                            None => now.saturating_sub(v.at_ms),
                        };
                        let mut receipt = json!({"id": v.id, "address": v.address,
                               "path": v.path.as_ref().map(|p| p.text.clone()).unwrap_or_default(),
                               "path_kind": v.path.as_ref().map_or("", |p| p.kind),
                               "ms": ms});
                        if let Some(at) = v.late_delivery() {
                            receipt["delivered_at_ms"] = at.into();
                        }
                        self.emit("receipt", receipt);
                        touched.push(v.peer.clone());
                    }
                    let mut fields =
                        json!({"id": v.id, "address": v.address, "state": v.state.as_str()});
                    if let Some(until) = v.until_ms {
                        fields["until_ms"] = until.into();
                    }
                    self.emit("state", fields);
                }
            }
        }
        for peer in touched {
            book.touches.insert(peer, (Instant::now(), now));
        }
        book.foreign.extend(foreign);
    }

    fn observe_presence(
        &self,
        book: &mut MessageBook,
        contacts: &[ContactView],
        presence: &HashMap<String, PresenceInfo>,
    ) {
        let Some(observed) = book.observed.as_mut() else {
            return;
        };
        let first = observed.presence.is_empty();
        for c in contacts {
            let peer = c.pub_hex.to_ascii_lowercase();
            let Some(info) = presence.get(&peer) else {
                continue;
            };
            let before = observed.presence.insert(peer, info.presence);
            if !first && before.is_some_and(|b| b != info.presence) {
                self.emit(
                    "presence",
                    json!({"address": c.address, "presence": info.presence}),
                );
            }
        }
    }

    /// An `unread` event for each friend whose count changed since the last
    /// look (a message came, or a chat was read here or in the terminal
    /// app); the first look only notes the counts.
    fn observe_unread(
        &self,
        book: &mut MessageBook,
        contacts: &[ContactView],
        unread: &HashMap<String, usize>,
    ) {
        let Some(observed) = book.observed.as_mut() else {
            return;
        };
        let first = observed.unread.is_empty();
        for c in contacts {
            let peer = c.pub_hex.to_ascii_lowercase();
            let Some(&n) = unread.get(&peer) else {
                continue;
            };
            let before = observed.unread.insert(peer, n);
            if !first && before != Some(n) {
                self.emit("unread", json!({"address": c.address, "unread": n}));
            }
        }
    }

    /// `messages.mark_read`: the friend's chat read up to the message `id`
    /// (a session id or a history row id; default the newest), in this app
    /// and the terminal app. The marker names the newest history row up to
    /// there (a send of this run with no row yet leaves the one before it),
    /// and never moves back. A marker that could not be saved counts in this
    /// run, and `note` says why.
    pub(crate) fn messages_mark_read(&self, args: &Args) -> OpResult {
        let address = args.str("address")?;
        let upto = args.opt_str("id")?.map(|s| s.trim().to_ascii_lowercase());
        let c = self.contact(address)?;
        let dir = self.data_dir()?.to_path_buf();
        let peer = c.pub_hex.to_ascii_lowercase();
        let snap = self.refresh(Duration::from_millis(1500))?;
        let theirs: Vec<&View> = snap.views.iter().filter(|v| v.peer == peer).collect();
        let end = match &upto {
            None => theirs.len(),
            Some(id) => {
                theirs
                    .iter()
                    .position(|v| v.id == *id || v.mid.as_deref() == Some(id.as_str()))
                    .ok_or_else(|| {
                        ApiError::new(
                            code::BAD_REQUEST,
                            "That message isn't on this computer anymore.",
                            format!("no message {} with this friend", safety::line(id)),
                        )
                    })?
                    + 1
            }
        };
        let newest = theirs[..end].iter().rev().find_map(|v| {
            v.mid.as_ref().map(|mid| ReadMark {
                id: mid.clone(),
                at_ms: Some(v.at_ms),
            })
        });
        let mut result = json!({"address": c.address});
        if let Some(mark) = newest {
            let place = |id: &str| {
                theirs
                    .iter()
                    .position(|v| v.mid.as_deref().is_some_and(|m| m.eq_ignore_ascii_case(id)))
            };
            match bridge::mark_read(&dir, &peer, mark.clone(), &place) {
                Ok(_) => {
                    lock(&self.marks_unsaved).remove(&peer);
                }
                Err(why) => {
                    lock(&self.marks_unsaved).insert(peer.clone(), mark);
                    result["note"] = format!("read marker not saved: {why}").into();
                }
            }
            self.invalidate_read_marks();
        }
        // The count as it stands now (an `unread` event says the change).
        let snap = self.refresh(Duration::from_millis(1500))?;
        result["unread"] = snap.unread.get(&peer).copied().unwrap_or(0).into();
        Ok(result)
    }

    /// The message with `id` (a session id or a history row id).
    fn find_view(&self, id: &str) -> Result<(Snapshot, View), ApiError> {
        let snap = self.refresh(Duration::from_millis(500))?;
        let want = id.trim().to_ascii_lowercase();
        let view = snap
            .views
            .iter()
            .find(|v| v.id == want || v.mid.as_deref() == Some(want.as_str()))
            .cloned()
            .ok_or_else(|| {
                ApiError::new(
                    code::BAD_REQUEST,
                    "That message isn't on this computer anymore.",
                    format!("no message {}", safety::line(id)),
                )
            })?;
        Ok((snap, view))
    }

    pub(crate) fn messages_history(&self, args: &Args) -> OpResult {
        let address = args.str("address")?;
        let before = args
            .opt_str("before")?
            .map(|s| s.trim().to_ascii_lowercase());
        let limit = args
            .opt_u64("limit")?
            .unwrap_or(HISTORY_DEFAULT)
            .clamp(1, HISTORY_MAX) as usize;
        let c = self.contact(address)?;
        let snap = self.refresh(Duration::from_millis(1500))?;
        let (replaced, hidden) = {
            let dir = self.data_dir()?;
            let mut book = lock(&self.book);
            let hidden = book
                .hidden
                .get_or_insert_with(|| crate::settings::load_hidden(dir).into_iter().collect())
                .clone();
            (book.replaced.clone(), hidden)
        };
        let peer = c.pub_hex.to_ascii_lowercase();
        let mut theirs: Vec<&View> = snap
            .views
            .iter()
            .filter(|v| {
                v.peer == peer
                    && !replaced.contains(&v.id)
                    && !hidden.contains(&v.id)
                    && !v.mid.as_ref().is_some_and(|m| hidden.contains(m))
            })
            .collect();
        if let Some(before) = before {
            if let Some(cut) = theirs
                .iter()
                .position(|v| v.id == before || v.mid.as_deref() == Some(before.as_str()))
            {
                theirs.truncate(cut);
            }
        }
        let start = theirs.len().saturating_sub(limit);
        let list: Vec<Value> = theirs[start..].iter().map(|v| v.json()).collect();
        Ok(json!({"messages": list}))
    }

    pub(crate) fn messages_send(&self, args: &Args) -> OpResult {
        let address = args.str("address")?;
        let text = args.str("text")?.to_owned();
        self.identity()?;
        let c = self.contact(address)?;
        if c.blocked {
            return Err(ApiError::of(
                code::CONTACT_BLOCKED,
                "the friend is on this profile's block list",
            ));
        }
        check_text(&text)?;
        // The first look at the profile only notes what is there: take it
        // before this send exists, so its receipt is always news.
        let _ = self.refresh(Duration::from_millis(1500));
        let snapshot: HashSet<String> = self
            .history()?
            .iter()
            .filter(|e| e.direction == "out" && e.peer_pub_hex.eq_ignore_ascii_case(&c.pub_hex))
            .map(|e| e.message_id_hex.to_ascii_lowercase())
            .collect();
        let pending = {
            let mut book = lock(&self.book);
            book.next += 1;
            let p = Pending {
                id: format!("pending-{}", book.next),
                peer: c.pub_hex.to_ascii_lowercase(),
                address: c.address.clone(),
                body: text,
                created_ms: now_ms(),
                started: Instant::now(),
                snapshot,
                bound_mid: None,
                job: Job::Queued,
                outcome: None,
                raw: String::new(),
                path: None,
                finished: None,
            };
            if let Some(observed) = book.observed.as_mut() {
                observed
                    .states
                    .insert(p.id.clone(), (State::Sending, 0, None));
            }
            book.pendings.push(p.clone());
            p
        };
        self.emit(
            "send_started",
            json!({"id": pending.id, "address": pending.address}),
        );
        self.enqueue_send(&pending.id)?;
        let view = View {
            id: pending.id.clone(),
            mid: None,
            peer: pending.peer.clone(),
            address: pending.address.clone(),
            incoming: false,
            text: pending.body.clone(),
            at_ms: pending.created_ms,
            state: State::Sending,
            until_ms: None,
            path: None,
            delivered_at_ms: None,
            attempts: None,
            history: None,
            outbox: None,
            pending: None,
        };
        Ok(json!({"message": view.json()}))
    }

    /// Hands a send to the worker (started the first time).
    fn enqueue_send(&self, id: &str) -> Result<(), ApiError> {
        let mut tx = lock(&self.send_tx);
        for _ in 0..2 {
            if tx.is_none() {
                let (sender, receiver) = mpsc::channel::<String>();
                let me = self.me.clone();
                std::thread::Builder::new()
                    .name("raven-client-send".into())
                    .spawn(move || send_worker(me, receiver))
                    .map_err(|e| ApiError::internal(format!("send worker: {e}")))?;
                *tx = Some(sender);
            }
            match tx.as_ref().map(|s| s.send(id.to_owned())) {
                Some(Ok(())) => return Ok(()),
                // The worker is gone (it panicked): start a new one.
                _ => *tx = None,
            }
        }
        Err(ApiError::internal("the send worker could not be started"))
    }

    /// One send, on the worker: the background program first (as a send
    /// starts it), then the CLI's send to a saved friend.
    pub(crate) fn run_send_job(&self, id: &str) {
        let job = {
            let mut book = lock(&self.book);
            let Some(p) = book.pendings.iter_mut().find(|p| p.id == id) else {
                return;
            };
            if p.job != Job::Queued {
                return;
            }
            p.job = Job::Running;
            p.started = Instant::now();
            (p.peer.clone(), p.body.clone())
        };
        let (outcome, raw) = self.send_now(&job.0, &job.1);
        {
            let mut book = lock(&self.book);
            if let Some(p) = book.pendings.iter_mut().find(|p| p.id == id) {
                p.job = Job::Done;
                p.outcome = Some(outcome);
                p.raw = raw;
                p.finished = Some(Instant::now());
            }
        }
        self.keep_unsent(id);
        self.invalidate_history();
        self.invalidate_contacts();
        self.invalidate_outbox();
        let _ = self.refresh(Duration::ZERO);
    }

    /// A send of this run that queued and wrote nothing (not sent, the
    /// background program unavailable, stopped before it ran) stays in the
    /// chat after the app starts again (E1: "Not sent: meet first" was
    /// gone): the history keeps it as `failed` (`record_not_sent`, as a
    /// message raven-node gave up on), and the send is bound to that row, so
    /// it keeps its own words in this run. Nothing while the profile can't be
    /// opened (an erase or a key change is unfinished), and nothing more when
    /// the row can't be written (the send then stays this run's only).
    fn keep_unsent(&self, id: &str) {
        let (peer, body, written) = {
            let book = lock(&self.book);
            let Some(p) = book.pendings.iter().find(|p| p.id == id) else {
                return;
            };
            if p.bound_mid.is_some() || !p.outcome.as_ref().is_some_and(Outcome::wrote_nothing) {
                return;
            }
            (p.peer.clone(), p.body.clone(), p.created_ms)
        };
        if self.open().is_err() {
            return;
        }
        let Ok(dir) = self.data_dir() else {
            return;
        };
        let Ok(mid) = bridge::record_not_sent(dir, &peer, &body, written) else {
            return;
        };
        {
            let mut book = lock(&self.book);
            if let Some(p) = book.pendings.iter_mut().find(|p| p.id == id) {
                p.bound_mid = Some(mid.clone());
            }
            book.alias.insert(mid, id.to_owned());
        }
        self.invalidate_history();
    }

    fn send_now(&self, peer: &str, body: &str) -> (Outcome, String) {
        // The profile as an operation opens it: refused while an erase or a
        // key change is unfinished (profile.rs).
        if let Err(e) = self.open() {
            return (Outcome::NotSent { meet_first: false }, e.detail);
        }
        let identity = match self.identity() {
            Ok(id) => id,
            Err(e) => return (Outcome::NotSent { meet_first: false }, e.detail),
        };
        let dir = match self.data_dir() {
            Ok(dir) => dir.to_path_buf(),
            Err(e) => return (Outcome::NotSent { meet_first: false }, e.detail),
        };
        if let Err(why) = self.ensure_node_for_send() {
            return (Outcome::NodeUnavailable, why);
        }
        match bridge::send_to_contact(&dir, &identity, peer, body) {
            Ok(done) => {
                {
                    let _guard = lock(&self.contacts_lock);
                    if let Some(dial) = &done.save_lan {
                        let _ = bridge::save_learned_lan(&dir, peer, dial);
                    }
                    if let Some(peer_id) = &done.save_p2p {
                        let _ = bridge::save_learned_p2p(&dir, peer, peer_id);
                    }
                }
                if done.carrier == Carrier::Lan {
                    lock(&self.book)
                        .lan_used
                        .insert(peer.to_ascii_lowercase(), (done.dial.clone(), now_ms()));
                }
                let path = match done.carrier {
                    Carrier::Lan => path_words("lan"),
                    Carrier::Internet => path_words("internet"),
                    Carrier::P2p => self.last_path(peer).unwrap_or_else(|| path_words("p2p")),
                    Carrier::Nearby => path_words("nearby"),
                    Carrier::Onion => path_words("onion"),
                };
                (
                    Outcome::Delivered { path },
                    format!("delivered with a signed receipt over {}", done.dial),
                )
            }
            Err(text) => {
                let outcome = match explain::explain_send(&text, "").0 {
                    OutcomeKind::Waiting { background } => Outcome::Waiting {
                        background,
                        connect: explain::never_reached(&text),
                    },
                    OutcomeKind::Sent => Outcome::Sent,
                    OutcomeKind::NotSent => Outcome::NotSent {
                        meet_first: explain::needs_meeting(&text),
                    },
                };
                (outcome, text)
            }
        }
    }

    /// How the last delivery to `peer` travelled, as raven-node's Status says.
    fn last_path(&self, peer: &str) -> Option<PathLabel> {
        let dir = self.data_dir().ok()?;
        let probe = crate::node::probe(dir);
        probe
            .last_paths
            .iter()
            .find(|p| p.peer_pub_hex.eq_ignore_ascii_case(peer))
            .and_then(|p| path_label(&p.carrier, &p.path, &probe.relay_paths))
    }

    pub(crate) fn messages_retry(&self, args: &Args) -> OpResult {
        let id = args.str("id")?;
        self.identity()?;
        let (_, view) = self.find_view(id)?;
        if view.incoming {
            return Ok(json!({"message": view.json(), "changed": false}));
        }
        // Never written by this session's send: the same message goes again.
        let unbound_unwritten = view.mid.is_none()
            && view
                .pending
                .as_ref()
                .and_then(|p| p.outcome.as_ref())
                .is_some_and(Outcome::never_written);
        match view.state {
            State::Delivered | State::Sending | State::Sent => {
                Ok(json!({"message": view.json(), "changed": false}))
            }
            _ if unbound_unwritten => {
                {
                    let mut book = lock(&self.book);
                    if let Some(p) = book.pendings.iter_mut().find(|p| p.id == view.id) {
                        p.job = Job::Queued;
                        p.outcome = None;
                        p.raw.clear();
                        p.finished = None;
                        p.started = Instant::now();
                    }
                }
                self.emit(
                    "send_started",
                    json!({"id": view.id, "address": view.address}),
                );
                self.enqueue_send(&view.id)?;
                let (_, again) = self.find_view(&view.id)?;
                Ok(json!({"message": again.json(), "changed": true}))
            }
            State::Waiting => {
                let mid = view
                    .mid
                    .clone()
                    .ok_or_else(|| ApiError::internal("a waiting message has no id"))?;
                self.ensure_node_for_send().map_err(|why| {
                    let plain = explain::explain_node_start(&why);
                    ApiError::new(
                        code::NODE_NOT_RUNNING,
                        format!("{} {}", plain.headline, plain.next)
                            .trim()
                            .to_owned(),
                        why,
                    )
                })?;
                let dir = self.data_dir()?;
                // The CLI's `outbox retry` finds the message in raven-node's
                // list first; a message its worker has not listed yet is
                // tried by asking for the friend's waiting messages at once.
                if let Err(why) = bridge::outbox_retry(dir, &mid) {
                    if !bridge::outbox_retry_kick(dir, &view.peer) {
                        return Err(ApiError::new(
                            code::NODE_NOT_RUNNING,
                            "Raven's background program isn't retrying messages right now. \
                             Start it from Network, then try again.",
                            why,
                        ));
                    }
                }
                self.emit(
                    "send_started",
                    json!({"id": view.id, "address": view.address}),
                );
                Ok(json!({"message": view.json(), "changed": true}))
            }
            // It ended (failed, time ran out, or not sent): the same text goes
            // again as a new message. It may arrive twice when the first one
            // was written to the friend's computer.
            _ => {
                let may_arrive_twice = !view
                    .pending
                    .as_ref()
                    .and_then(|p| p.outcome.as_ref())
                    .is_some_and(Outcome::never_written);
                let mut send_args = Map::new();
                send_args.insert("address".into(), view.address.clone().into());
                send_args.insert("text".into(), view.text.clone().into());
                let mut sent = self.messages_send(&Args(&send_args))?;
                lock(&self.book).replaced.insert(view.id.clone());
                // Left out after a restart too, and in the terminal app: one
                // bubble for the text (E1).
                let _ = self.hide(&view);
                sent["changed"] = true.into();
                sent["replaces"] = view.id.clone().into();
                sent["may_arrive_twice"] = may_arrive_twice.into();
                Ok(sent)
            }
        }
    }

    pub(crate) fn messages_stop(&self, args: &Args) -> OpResult {
        let id = args.str("id")?;
        self.identity()?;
        let (_, view) = self.find_view(id)?;
        let queued_job = view.pending.as_ref().is_some_and(|p| p.job == Job::Queued);
        if queued_job {
            {
                let mut book = lock(&self.book);
                if let Some(p) = book.pendings.iter_mut().find(|p| p.id == view.id) {
                    if p.job == Job::Queued {
                        p.job = Job::Done;
                        p.outcome = Some(Outcome::Stopped);
                        p.raw = "stopped before it was sent".into();
                        p.finished = Some(Instant::now());
                    }
                }
            }
            self.keep_unsent(&view.id);
            let _ = self.refresh(Duration::ZERO);
            let (_, after) = self.find_view(&view.id)?;
            return Ok(
                json!({"message": after.json(), "changed": true, "may_have_arrived": false}),
            );
        }
        // raven-node's store holds it (its worker may not list it yet): the
        // CLI's cancel finds it there.
        let cancellable = matches!(view.state, State::Waiting | State::Sent) && view.mid.is_some();
        if !cancellable {
            return Ok(json!({"message": view.json(), "changed": false}));
        }
        let mid = view.mid.clone().unwrap_or_default();
        let written = match &view.outbox {
            Some(item) => item.state == "sent" || item.attempts > 0,
            None => view.state == State::Sent,
        };
        let may_have_arrived = written
            && !view
                .pending
                .as_ref()
                .and_then(|p| p.outcome.as_ref())
                .is_some_and(Outcome::never_written);
        let dir = self.data_dir()?;
        bridge::outbox_cancel(dir, &mid).map_err(|why| {
            ApiError::new(
                code::INTERNAL,
                "Raven couldn't stop trying this message. Open Details.",
                why,
            )
        })?;
        self.invalidate_history();
        self.invalidate_outbox();
        let (_, after) = self.find_view(&view.id)?;
        Ok(json!({"message": after.json(), "changed": true, "may_have_arrived": may_have_arrived}))
    }

    /// `messages.delete {id}`: takes an ended message of yours (not sent,
    /// failed, time ran out) out of the chat for good: a send of this run is
    /// forgotten, and a message Raven's history keeps is left out of every
    /// chat the desktop apps show (`desktop_hidden.json`; its history row
    /// goes when the chat-keeping time ends). Anything else is refused:
    /// stop a waiting message first.
    pub(crate) fn messages_delete(&self, args: &Args) -> OpResult {
        let id = args.str("id")?;
        self.identity()?;
        let (_, view) = self.find_view(id)?;
        let ended = matches!(
            view.state,
            State::Failed | State::TimeRanOut | State::NotSentMeetFirst
        );
        if view.incoming || !ended {
            return Err(ApiError::new(
                code::BAD_REQUEST,
                "Only a message that wasn't sent can be deleted. Stop a waiting message first.",
                format!(
                    "message {} is {}",
                    safety::line(&view.id),
                    view.state.as_str()
                ),
            ));
        }
        // A send of this run that has no history row is forgotten; one
        // with a row keeps its binding (so the row is not taken for another
        // program's message) and is left out as hidden.
        lock(&self.book)
            .pendings
            .retain(|p| p.id != view.id || p.bound_mid.is_some());
        self.hide(&view).map_err(|why| {
            ApiError::new(code::INTERNAL, "Raven couldn't delete this message.", why)
        })?;
        Ok(json!({"id": view.id, "deleted": true}))
    }

    /// Leaves `view` out of every chat for good: in this run, and once it
    /// has a history row in the next runs and in the terminal app too
    /// (`desktop_hidden.json`, which ash's tui/hidden.rs reads).
    fn hide(&self, view: &View) -> Result<(), String> {
        let dir = self.data_dir().map_err(|e| e.detail)?.to_path_buf();
        let mut book = lock(&self.book);
        let mut hidden: Vec<String> = crate::settings::load_hidden(&dir);
        let mut add = |x: &str| {
            if !hidden.iter().any(|h| h == x) {
                hidden.push(x.to_owned());
            }
        };
        add(&view.id);
        if let Some(mid) = &view.mid {
            add(mid);
        }
        if view.mid.is_some() {
            crate::settings::save_hidden(&dir, &hidden)?;
        }
        book.hidden = Some(hidden.into_iter().collect());
        Ok(())
    }

    pub(crate) fn messages_details(&self, args: &Args) -> OpResult {
        let id = args.str("id")?;
        self.identity()?;
        let (snap, view) = self.find_view(id)?;
        let name = snap
            .contacts
            .iter()
            .find(|c| c.pub_hex.eq_ignore_ascii_case(&view.peer))
            .map(|c| safety::line(&c.label))
            .unwrap_or_default();
        let retrying = snap.outbox.answered && snap.outbox.worker_running;
        let (status, why, action) = details_text(&view, &name, retrying, now_ms());
        let (detail, technical) = detail_texts(&view, &snap.outbox);
        Ok(json!({
            "message": view.json(),
            "status_text": status,
            "why_text": why,
            "action_text": action,
            "detail": detail,
            "technical": technical,
        }))
    }
}

/// `messages.details`' `detail` (plain words: the message's stored id, the
/// way it went, tries, what the last send said) and `technical` (the
/// developer fields, shown only under "Technical details").
fn detail_texts(view: &View, outbox: &OutboxSnap) -> (String, String) {
    let mut plain = Vec::new();
    match &view.mid {
        Some(mid) => plain.push(format!("Message ID: {mid}")),
        None if !view.incoming => plain.push("Message ID: none yet (not stored)".to_owned()),
        None => {}
    }
    if let Some(path) = view.path.as_ref().filter(|p| !p.text.is_empty()) {
        plain.push(format!("Way: {}", path.text));
    }
    if let Some(n) = view.attempts.filter(|n| *n > 0) {
        plain.push(format!("Tries so far: {n}"));
    }
    if let Some(p) = view.pending.as_ref().filter(|p| !p.raw.is_empty()) {
        plain.push(format!("Last try: {}", p.raw));
    }
    let mut detail = vec![format!("id={}", view.id)];
    if let Some(mid) = &view.mid {
        detail.push(format!("mid={mid}"));
    }
    detail.push(format!("state={}", view.state.as_str()));
    if let Some(h) = &view.history {
        detail.push(format!("history={}", if h.is_empty() { "-" } else { h }));
    }
    if let Some(item) = &view.outbox {
        detail.push(format!(
            "outbox={} attempts={} carrier={} last_error={} expires_at_ms={}",
            item.state,
            item.attempts,
            if item.carrier.is_empty() {
                "-"
            } else {
                &item.carrier
            },
            if item.last_error_code.is_empty() {
                "-"
            } else {
                &item.last_error_code
            },
            item.expires_at_ms
        ));
    }
    if view.outbox.is_none() && !view.incoming {
        detail.push(format!(
            "outbox: {}",
            if !outbox.answered {
                "no answer from raven-node".to_owned()
            } else {
                format!(
                    "not listed ({} listed, worker {})",
                    outbox.items.len(),
                    if outbox.worker_running {
                        "running"
                    } else {
                        "stopped"
                    }
                )
            }
        ));
    }
    if let Some(p) = &view.pending {
        if !p.raw.is_empty() {
            detail.push(format!("send: {}", p.raw));
        }
    }
    (
        safety::hide_codes(&plain.join("\n"), &[]),
        safety::hide_codes(&detail.join("\n"), &[]),
    )
}

/// What a message may not be (the CLI's checks, before anything is sent).
fn check_text(text: &str) -> Result<(), ApiError> {
    if text.trim().is_empty() {
        return Err(ApiError::new(
            code::BAD_REQUEST,
            "Type a message first.",
            "the message is empty",
        ));
    }
    let max = raven_core::lan_noise::MAX_LAN_ENDPOINT_TEXT;
    if text.len() > max {
        return Err(ApiError::of(
            code::MESSAGE_TOO_LONG,
            format!("{} bytes; at most {max}", text.len()),
        ));
    }
    if let Some(problem) = bridge::message_problem(text) {
        return Err(ApiError::new(
            code::BAD_REQUEST,
            "This message has characters Raven can't send. Remove them, then send it again.",
            problem,
        ));
    }
    if !raven_core::app_channel::chat_text_allowed(text) {
        return Err(ApiError::new(
            code::BAD_REQUEST,
            "Messages can't start with RVNAPP/ or RVNGRP/. Change how it starts.",
            "reserved prefix",
        ));
    }
    Ok(())
}

/// The status, why and what-to-do lines of `messages.details`.
fn details_text(view: &View, name: &str, retrying: bool, now_ms: u64) -> (String, String, String) {
    let who = if name.is_empty() { "" } else { name };
    if view.incoming {
        return (
            explain::fill("Received from {who}.", who),
            String::new(),
            String::new(),
        );
    }
    let outcome = view.pending.as_ref().and_then(|p| p.outcome.as_ref());
    let raw = view.pending.as_ref().map(|p| p.raw.as_str()).unwrap_or("");
    let held_code = view
        .outbox
        .as_ref()
        .map(|i| i.last_error_code.as_str())
        .filter(|c| !c.is_empty());
    let plain = match (outcome, held_code) {
        (_, Some(code)) => Some(explain::explain_outbox_code(code, who)),
        (Some(Outcome::NodeUnavailable), _) => Some(explain::explain_node_unavailable(raw)),
        (Some(Outcome::Delivered { .. }), _) | (None, None) => None,
        (Some(Outcome::Stopped), _) => None,
        (Some(_), _) if !raw.is_empty() => Some(explain::explain_send(raw, who).1),
        _ => None,
    };
    let (why, action) = plain.map_or((String::new(), String::new()), |p| (p.headline, p.next));
    let status = match view.state {
        State::Sending => "Sending\u{2026}".to_owned(),
        State::Sent => explain::fill(
            "Sent, not confirmed yet. It left this computer, but {whose} Raven hasn't confirmed it.",
            who,
        ),
        State::Delivered => match view.late_delivery() {
            // A late delivery says when it came (E1).
            Some(at) => explain::fill(
                &format!(
                    "Delivered {}. {{whose}} Raven confirmed it with a signed receipt.",
                    bridge::ended_text(at, now_ms)
                ),
                who,
            ),
            None => explain::fill(
                "Delivered. {whose} Raven confirmed it with a signed receipt.",
                who,
            ),
        },
        State::Waiting => {
            let until = view
                .until_ms
                .map(|u| format!(" until {}", deadline_words(u, now_ms)))
                .unwrap_or_default();
            let who_part = explain::fill("Waiting for {who}", who);
            if retrying {
                format!("{who_part}{until}. Raven keeps trying in the background.")
            } else {
                format!(
                    "{who_part}{until}. Nothing retries it while Raven's background program is \
                     stopped."
                )
            }
        }
        State::TimeRanOut => "Time ran out: Raven stopped trying.".to_owned(),
        State::NotSentMeetFirst => explain::fill(
            "Not sent: {who} isn't reachable. A first message needs you both online: Raven has \
             no secure connection with {who} yet, and {whose} computer couldn't be reached to set \
             one up.",
            who,
        ),
        State::Failed => "Not delivered.".to_owned(),
    };
    let action = if action.is_empty() {
        match view.state {
            State::Sent => "Wait. Don't send it again.".to_owned(),
            State::Waiting => "Try now, or stop trying.".to_owned(),
            State::TimeRanOut | State::Failed => "Send it again if it still matters.".to_owned(),
            State::NotSentMeetFirst => {
                explain::fill("Send it when you and {who} are on the same network.", who)
            }
            _ => String::new(),
        }
    } else {
        action
    };
    (status, why, action)
}

/// When a waiting message runs out of time, in words that read after "until"
/// (the terminal app's bridge.rs `deadline_text`: relative, no time zone).
pub(crate) fn deadline_words(expires_at_ms: u64, now_ms: u64) -> String {
    let minutes = expires_at_ms.saturating_sub(now_ms) / 60_000;
    let span = match minutes {
        0 => "less than a minute".to_owned(),
        1 => "about a minute".to_owned(),
        2..=119 => format!("about {minutes} minutes"),
        _ => format!("about {} hours", (minutes + 30) / 60),
    };
    format!("{span} from now")
}

/// The send worker: one send at a time, in the order they were asked for.
fn send_worker(me: std::sync::Weak<Inner>, jobs: mpsc::Receiver<String>) {
    while let Ok(id) = jobs.recv() {
        let Some(inner) = me.upgrade() else {
            return;
        };
        let run =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.run_send_job(&id)));
        if run.is_err() {
            let mut book = lock(&inner.book);
            if let Some(p) = book.pendings.iter_mut().find(|p| p.id == id) {
                if p.job != Job::Done {
                    p.job = Job::Done;
                    p.outcome = Some(Outcome::NotSent { meet_first: false });
                    p.raw = "the send stopped unexpectedly inside Raven".into();
                    p.finished = Some(Instant::now());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(state: &str, expires: u64) -> OutboxItem {
        OutboxItem {
            message_id_hex: "ab".into(),
            state: state.into(),
            kind: "message".into(),
            expires_at_ms: expires,
            ..Default::default()
        }
    }

    fn pending(job: Job, outcome: Option<Outcome>) -> Pending {
        Pending {
            id: "pending-1".into(),
            peer: "aa".into(),
            address: "rvn1x".into(),
            body: "hi".into(),
            created_ms: 1,
            started: Instant::now(),
            snapshot: HashSet::new(),
            bound_mid: None,
            job,
            outcome,
            raw: String::new(),
            path: None,
            finished: None,
        }
    }

    fn out_view(id: &str, mid: Option<&str>, state: State, until_ms: Option<u64>) -> View {
        View {
            id: id.into(),
            mid: mid.map(Into::into),
            peer: "aa".into(),
            address: "rvn1x".into(),
            incoming: false,
            text: "hi".into(),
            at_ms: 1,
            state,
            until_ms,
            path: None,
            delivered_at_ms: None,
            attempts: None,
            history: None,
            outbox: None,
            pending: None,
        }
    }

    /// E1: a delivered message's Details showed "id=pending-4" and
    /// "outbox: not listed (0 listed, worker running)". The plain text gives
    /// the stored id and plain words; the developer fields go under
    /// Technical details only.
    #[test]
    fn details_are_plain_words_with_the_technical_fields_apart() {
        let mut view = out_view("pending-4", Some("c0ffee12"), State::Delivered, None);
        view.history = Some("delivered".into());
        view.path = Some(path_words("lan"));
        let mut p = pending(
            Job::Done,
            Some(Outcome::Delivered {
                path: path_words("lan"),
            }),
        );
        p.id = "pending-4".into();
        p.raw = "delivered with a signed receipt".into();
        view.pending = Some(p);
        let outbox = OutboxSnap {
            answered: true,
            worker_running: true,
            ..Default::default()
        };
        let (plain, technical) = detail_texts(&view, &outbox);
        assert!(plain.contains("Message ID: c0ffee12"), "{plain}");
        assert!(plain.contains("Way: LAN direct"), "{plain}");
        assert!(
            plain.contains("Last try: delivered with a signed receipt"),
            "{plain}"
        );
        for developer in [
            "pending-4",
            "mid=",
            "state=",
            "history=",
            "outbox",
            "worker",
        ] {
            assert!(!plain.contains(developer), "{developer} in {plain}");
        }
        assert!(technical.contains("id=pending-4"), "{technical}");
        assert!(technical.contains("mid=c0ffee12"), "{technical}");
        assert!(technical.contains("outbox: not listed (0 listed, worker running)"));
        // Never stored: said plainly, no pending id.
        let unsent = out_view("pending-5", None, State::NotSentMeetFirst, None);
        let (plain, _) = detail_texts(&unsent, &outbox);
        assert_eq!(plain, "Message ID: none yet (not stored)");
    }

    /// E1: "Not sent: meet first" told a user nothing; the status says who
    /// isn't reachable and that a first message needs both online.
    #[test]
    fn not_sent_says_both_must_be_online() {
        let view = out_view("pending-1", None, State::NotSentMeetFirst, None);
        let (status, _, action) = details_text(&view, "mac-b", false, 1);
        assert!(
            status.starts_with("Not sent: mac-b isn't reachable."),
            "{status}"
        );
        assert!(
            status.contains("A first message needs you both online"),
            "{status}"
        );
        assert!(!status.contains("meet first"), "{status}");
        assert!(!action.is_empty());
    }

    /// E1: "Waiting for win-c · until –". A message that starts waiting
    /// before raven-node's outbox lists it has no deadline yet; when the
    /// deadline shows up, a `state` event carries it to the apps.
    #[test]
    fn a_deadline_that_shows_up_later_is_told() {
        let inner = Inner::new(Err("no profile in this test".into()));
        let mut book = MessageBook::default();
        let seen = |inner: &Inner, after: u64| inner.events.poll(after);
        // The first look only notes what is there.
        inner.observe_messages(
            &mut book,
            &[out_view("pending-1", None, State::Sending, None)],
            5,
        );
        let start = seen(&inner, 0).seq;
        inner.observe_messages(
            &mut book,
            &[out_view("pending-1", None, State::Waiting, None)],
            6,
        );
        let b = seen(&inner, start);
        assert_eq!(b.events.len(), 1, "{:?}", b.events);
        assert_eq!(b.events[0]["kind"], "state");
        assert!(b.events[0].get("until_ms").is_none_or(Value::is_null));
        let waiting = out_view("pending-1", Some("ab"), State::Waiting, Some(9_000_000));
        inner.observe_messages(&mut book, std::slice::from_ref(&waiting), 7);
        let b2 = seen(&inner, b.seq);
        assert_eq!(b2.events.len(), 1, "{:?}", b2.events);
        assert_eq!(b2.events[0]["kind"], "state");
        assert_eq!(b2.events[0]["state"], "waiting");
        assert_eq!(b2.events[0]["until_ms"], 9_000_000);
        // Nothing changed: nothing told.
        inner.observe_messages(&mut book, std::slice::from_ref(&waiting), 8);
        assert!(seen(&inner, b2.seq).events.is_empty());
    }

    #[test]
    fn delivered_needs_a_receipt_and_beats_everything() {
        let now = 1_000_000;
        // A send that only wrote the message is sent, never delivered.
        assert_eq!(
            state_of(Some("queued"), Some(&item("sent", 0)), None, now).0,
            State::Sent
        );
        assert_eq!(
            state_of(
                None,
                None,
                Some(&pending(Job::Done, Some(Outcome::Sent))),
                now
            )
            .0,
            State::Sent
        );
        // The history's verified receipt wins over an older outbox answer.
        assert_eq!(
            state_of(Some("delivered"), Some(&item("queued", 0)), None, now).0,
            State::Delivered
        );
        assert_eq!(state_of(Some("read"), None, None, now).0, State::Delivered);
        let delivered = pending(
            Job::Done,
            Some(Outcome::Delivered {
                path: path_words("lan"),
            }),
        );
        assert_eq!(
            state_of(None, None, Some(&delivered), now).0,
            State::Delivered
        );
    }

    #[test]
    fn waiting_has_its_deadline_and_runs_out_honestly() {
        let now = 1_000_000;
        assert_eq!(
            state_of(Some("queued"), Some(&item("queued", now + 5)), None, now),
            (State::Waiting, Some(now + 5))
        );
        assert_eq!(
            state_of(Some("queued"), Some(&item("queued", now - 5)), None, now).0,
            State::TimeRanOut
        );
        assert_eq!(
            state_of(Some("expired"), None, None, now).0,
            State::TimeRanOut
        );
        assert_eq!(
            state_of(Some("cancelled"), None, None, now).0,
            State::Failed
        );
        assert_eq!(
            state_of(Some("queued"), Some(&item("held", 0)), None, now).0,
            State::Waiting
        );
        // While its own job runs it is sending, whatever the row says.
        assert_eq!(
            state_of(
                Some("queued"),
                None,
                Some(&pending(Job::Running, None)),
                now
            )
            .0,
            State::Sending
        );
    }

    #[test]
    fn not_sent_tells_meet_first_apart() {
        let now = 1;
        let meet = pending(Job::Done, Some(Outcome::NotSent { meet_first: true }));
        assert_eq!(
            state_of(None, None, Some(&meet), now).0,
            State::NotSentMeetFirst
        );
        let other = pending(Job::Done, Some(Outcome::NodeUnavailable));
        assert_eq!(state_of(None, None, Some(&other), now).0, State::Failed);
        assert_eq!(state_of(Some(""), None, None, now).0, State::Sent);
        // The `failed` row kept for it after a restart (E1) doesn't change
        // what this run says; the row alone, after a restart, is failed.
        assert_eq!(
            state_of(Some("failed"), None, Some(&meet), now).0,
            State::NotSentMeetFirst
        );
        assert_eq!(
            state_of(Some("failed"), None, Some(&other), now).0,
            State::Failed
        );
        assert_eq!(state_of(Some("failed"), None, None, now).0, State::Failed);
    }

    /// E1: a delivery more than a minute after the message was written says
    /// when it came (API.md `delivered_at_ms`, Details); a quick one doesn't.
    #[test]
    fn a_late_delivery_says_when_it_came() {
        let written = 1_000_000;
        let mut v = out_view("pending-1", Some("ab"), State::Delivered, None);
        v.at_ms = written;
        v.delivered_at_ms = Some(written + 30_000);
        assert_eq!(v.late_delivery(), None);
        assert!(v.json().get("delivered_at_ms").is_none());
        let (status, _, _) = details_text(&v, "win-c", true, written + 40_000);
        assert_eq!(
            status,
            "Delivered. win-c's Raven confirmed it with a signed receipt."
        );
        v.delivered_at_ms = Some(written + 2 * 60_000);
        assert_eq!(v.json()["delivered_at_ms"], written + 2 * 60_000);
        let (status, _, _) = details_text(&v, "win-c", true, written + 3 * 60_000);
        assert!(
            status.starts_with("Delivered ")
                && status.ends_with(". win-c's Raven confirmed it with a signed receipt."),
            "{status}"
        );
    }

    fn entry(mid: &str, direction: &str, body: &str, delivery: &str) -> ChatHistoryEntry {
        ChatHistoryEntry {
            message_id_hex: mid.into(),
            direction: direction.into(),
            peer_petname: String::new(),
            peer_tag: String::new(),
            peer_pub_hex: "aa".into(),
            created_at_ms: 5,
            delivery: delivery.into(),
            preview: body.into(),
            body: body.into(),
            stored_at_ms: None,
            id_conflict: false,
        }
    }

    #[test]
    fn a_send_binds_to_its_own_new_row_only() {
        let mut book = MessageBook::default();
        let mut p = pending(Job::Running, None);
        p.snapshot.insert("old".into());
        book.pendings.push(p);
        let history = vec![
            entry("old", "out", "hi", "delivered"),
            entry("other", "out", "different", "queued"),
            entry("mine", "out", "hi", "queued"),
        ];
        bind(&mut book, &history);
        assert_eq!(book.pendings[0].bound_mid.as_deref(), Some("mine"));
        let v = views(&mut book, &history, &OutboxSnap::default(), &[], 10);
        let ids: Vec<&str> = v.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, ["old", "other", "pending-1"]);
        assert_eq!(v[2].state, State::Sending);
        // A send that wrote nothing never takes a row.
        let mut book = MessageBook::default();
        book.pendings
            .push(pending(Job::Done, Some(Outcome::NodeUnavailable)));
        bind(&mut book, &history);
        assert_eq!(book.pendings[0].bound_mid, None);
    }

    #[test]
    fn deadlines_read_after_until() {
        let now = 1_760_000_000_000;
        assert_eq!(
            deadline_words(now + 30_000, now),
            "less than a minute from now"
        );
        assert_eq!(
            deadline_words(now + 45 * 60_000, now),
            "about 45 minutes from now"
        );
        assert_eq!(
            deadline_words(now + 22 * 3_600_000, now),
            "about 22 hours from now"
        );
        assert_eq!(deadline_words(now - 1, now), "less than a minute from now");
    }

    #[test]
    fn paths_read_as_the_design_names_them() {
        let text = |c: &str, p: &str, relays: &[&str]| {
            let relays: Vec<String> = relays.iter().map(|r| (*r).to_owned()).collect();
            path_label(c, p, &relays).map(|l| (l.kind, l.text))
        };
        assert_eq!(
            text("lan_dial", "", &[]),
            Some(("lan", "LAN direct".into()))
        );
        assert_eq!(
            text("internet_dial", "", &[]),
            Some(("internet", "Internet direct".into()))
        );
        assert_eq!(
            text("p2p_dial", "hole_punched", &[]),
            Some(("p2p_hole_punched", "p2p \u{00B7} hole punched".into()))
        );
        assert_eq!(
            text("p2p_dial", "relayed", &["tcp", "wss"]),
            Some(("p2p_relayed", "p2p \u{00B7} relayed".into()))
        );
        assert_eq!(
            text("p2p_dial", "relayed", &["wss", "wss-proxy"]),
            Some(("websocket", "p2p \u{00B7} relayed over WebSocket".into()))
        );
        assert_eq!(text("p2p_dial", "", &[]), Some(("p2p", "p2p".into())));
        assert_eq!(
            text("nearby_dial", "", &[]),
            Some(("nearby", "Bluetooth nearby".into()))
        );
        assert_eq!(text("", "", &[]), None);
        // Friends carrying it: a letter first, then passed on, then held.
        let mut held = item("sent", 0);
        assert_eq!(carried_label(&held, false), None);
        held.in_custody = 1;
        assert_eq!(carried_label(&held, false).unwrap().kind, "friend");
        held.custody_forwarded = true;
        assert_eq!(carried_label(&held, false).unwrap().kind, "handoff");
        assert_eq!(carried_label(&held, true).unwrap().kind, "letter");
        // Every kind has its words.
        for (kind, words) in PATH_KINDS {
            assert_eq!(path_words(kind).text, words);
        }
    }
}
