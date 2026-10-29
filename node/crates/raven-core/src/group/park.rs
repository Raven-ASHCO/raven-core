//! Sending group copies (design §3.1, §4.3): every copy is parked for its
//! friend with the long message horizon's park step, exactly as `raven
//! send` parks a chat message to a friend it cannot reach, and raven-node's
//! outbox seals and sends it. [`process_intents`] turns the store's intents
//! into parked copies; [`refresh_deliveries`] reads the copies' delivery
//! from chat history into the store and deletes the finished rows.

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use super::rules::{fail_line, remove_leaver};
use super::store::{
    self, hex_key, line_after, Intent, INTENT_LEAVER, INTENT_RECEIPT, INTENT_SEND, LINE_WAITING,
};
use super::{group_live_enabled, GroupFrame, GroupId, GroupReceipt, Key, GROUP_RESERVED_PREFIX};
use crate::identity::Identity;
use crate::indexed_session_store::{EndpointOutboundKind, IndexedSessionStore};

/// Group copies may fill at most this many of the outbound stage's 256
/// entries: half, so 1:1 chat keeps the other half (four friends' full
/// queues of 32). At 16 members a message takes 15 copies, so eight
/// messages to an all-offline group fit (design §7).
pub const GROUP_STAGE_BUDGET: usize = 128;
/// Messages that may wait for one friend (as `MAX_QUEUED_PER_PEER` in ash).
pub const MAX_WAITING_PER_FRIEND: usize = 32;
/// A busy friend (its send lock held) is tried again on the next run.
const SEND_LOCK_WAIT: Duration = Duration::from_millis(300);
/// One run of the intents at a time, across processes
/// ([`process_intents`]): dot-prefixed `*.lock.sqlite`, the inert lock
/// shape the first-install check tolerates.
const RUN_LOCK: &str = ".groups_run.lock.sqlite";
/// [`RUN_LOCK`] for the group tests.
#[cfg(test)]
pub(crate) const RUN_LOCK_NAME_FOR_TESTS: &str = RUN_LOCK;
/// How long a run waits for another one to end; what it leaves goes on the
/// next run (raven-node's outbox scan runs them after every kick).
const RUN_LOCK_WAIT: Duration = if cfg!(test) {
    Duration::from_millis(200)
} else {
    Duration::from_secs(5)
};

/// What parking one copy did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parked {
    /// Parked for `device` under the copy's own message id.
    Yes { device: Key, mid: [u8; 16] },
    /// Not now (busy, full, a store error): the intent stays.
    Later(String),
    /// Never (not a friend any more, revoked, too large): the intent goes.
    Never(String),
}

/// Park `text` for the friend `member` (design §3.1): admitted contact,
/// room, then the parked row, the staged body with the sentinel binding and
/// a `queued` history row, and the route record (any carrier, friend
/// custody when its gate is live).
pub fn park_copy(data_dir: &Path, member: &Key, text: &str, now_ms: u64) -> Parked {
    use crate::horizon::{message_deadline, SENTINEL_BINDING};
    use crate::outbox::{contact_admission, ContactAdmission};
    if !crate::horizon::horizon_live_enabled() {
        return Parked::Later("the long message horizon is held".into());
    }
    if text.len() > crate::lan_noise::MAX_LAN_ENDPOINT_TEXT {
        return Parked::Never("too large".into());
    }
    let bundle = crate::lan_dispatch::load_cached_peer_bundle(data_dir, member)
        .ok()
        .flatten()
        .filter(|b| b.cert.user_ed_pub == *member || b.cert.device_ed_pub == *member);
    let device = bundle.as_ref().map_or(*member, |b| b.cert.device_ed_pub);
    match contact_admission(data_dir, &device) {
        ContactAdmission::Allowed(_) => {}
        ContactAdmission::Unreadable => return Parked::Later("contact book unreadable".into()),
        ContactAdmission::NotContact | ContactAdmission::Blocked => {
            return Parked::Never("not a friend".into())
        }
    }
    let revoked = crate::device_sync::RevocationStore::load_checked(data_dir)
        .map(|r| r.identity_has_revocation(&device) || r.identity_has_revocation(member))
        .unwrap_or(true)
        || bundle
            .as_ref()
            .is_some_and(|b| crate::outbox::peer_lineage_denied(data_dir, &b.cert).unwrap_or(true));
    if revoked {
        return Parked::Never("revoked".into());
    }
    // Security review 2026-10-29 #4: every group copy (forwards, receipts,
    // rosters too, not only this profile's own messages) counts against
    // the group budget of the outbound stage, so forwards cannot take the
    // half kept for 1:1 chat.
    match crate::chat_history::list_staged_outbound_bodies(data_dir) {
        Ok(staged) if staged.len() < GROUP_STAGE_BUDGET => {}
        Ok(_) => return Parked::Later("the group share of the outbound stage is full".into()),
        Err(e) => return Parked::Later(e.to_string()),
    }
    let _lock = match crate::outbox::PeerSendLock::acquire_within(data_dir, &device, SEND_LOCK_WAIT)
    {
        Ok(lock) => lock,
        Err(e) => return Parked::Later(e),
    };
    let mut sessions = match IndexedSessionStore::open(data_dir) {
        Ok(s) => s,
        Err(e) => return Parked::Later(e.redacted_display()),
    };
    match waiting_for(&sessions, &device) {
        Ok(n) if n < MAX_WAITING_PER_FRIEND => {}
        Ok(_) => return Parked::Later("the friend's queue is full".into()),
        Err(e) => return Parked::Later(e),
    }
    let guard = match crate::OutboundStageSendGuard::acquire(data_dir, text, now_ms) {
        Ok(guard) => guard,
        Err(e) => return Parked::Later(e.to_string()),
    };
    let mut mid = [0u8; 16];
    while mid == [0u8; 16] {
        mid = rand::random();
    }
    let deadline = message_deadline(now_ms);
    match sessions.park_outbound(&device, &mid, None, now_ms, deadline, now_ms) {
        Ok(true) => {}
        Ok(false) => return Parked::Later("the copy could not be parked".into()),
        Err(e) => return Parked::Later(e.redacted_display()),
    }
    if let Err(e) = crate::lan_dispatch::ensure_outbound_queued_history_under_send_guard(
        &guard,
        &device,
        &SENTINEL_BINDING,
        &SENTINEL_BINDING,
        &mid,
        now_ms,
        Some(text),
    ) {
        drop(guard);
        let _ = crate::chat_history::clear_staged_outbound_body(data_dir, &mid);
        let _ = sessions.give_up_parked(&device, &mid);
        return Parked::Later(e);
    }
    drop(guard);
    // The worker plans the friend's routes at each attempt (any carrier its
    // gates allow), as for AppSubmit; never written by a carrier yet.
    let _ = crate::outbox::record_object_routes(
        data_dir,
        &mid,
        &device,
        crate::outbox::CarrierChoice::Auto,
        &[],
        deadline,
        now_ms,
    );
    let _ = crate::outbox::set_object_unsent(data_dir, &mid, true, now_ms);
    if crate::custody_gate::CustodyGates::current().live {
        let _ = crate::outbox::set_object_custody(data_dir, &mid, now_ms);
    }
    Parked::Yes { device, mid }
}

/// Messages waiting for `device`: prepared, sent without an ACK, parked.
fn waiting_for(sessions: &IndexedSessionStore, device: &Key) -> Result<usize, String> {
    let rows = sessions
        .pending_endpoint_outbound_for_recipient(Some(device))
        .map_err(|e| e.redacted_display())?
        .into_iter()
        .chain(
            sessions
                .awaiting_ack_endpoint_outbound_for_recipient(Some(device))
                .map_err(|e| e.redacted_display())?,
        )
        .filter(|row| row.kind == EndpointOutboundKind::Message)
        .count();
    let parked = sessions
        .parked_for_recipient(device)
        .map_err(|e| e.redacted_display())?
        .len();
    Ok(rows + parked)
}

/// What a run of [`process_intents`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pending {
    /// Copies parked: the group, the own message the copy belongs to (if
    /// any) and the friend's device.
    pub parked: Vec<(GroupId, Option<[u8; 16]>, Key)>,
    /// Intents left for a later run.
    pub waiting: usize,
    /// Intents that can never go (dropped).
    pub dropped: usize,
}

impl Pending {
    /// Copies parked of the own message `id`.
    pub fn parked_for(&self, id: &[u8; 16]) -> usize {
        self.parked.iter().filter(|p| p.1 == Some(*id)).count()
    }

    /// The friends' devices with a new parked copy (each once): what to
    /// kick raven-node's outbox for.
    pub fn devices(&self) -> Vec<Key> {
        let mut seen = HashSet::new();
        self.parked
            .iter()
            .map(|p| p.2)
            .filter(|d| seen.insert(*d))
            .collect()
    }
}

/// Turn the store's intents into parked copies: receipts are signed and
/// leaves applied (the admin) under the store lock, then each copy is
/// parked outside it, then the outcomes are written. Best effort: a store
/// that cannot be read leaves everything for the next run.
///
/// One run at a time (E2 r40: `raven group send` and raven-node's outbox
/// scan each read the same intent and parked a copy of it, so the sender
/// held two copies of a message for one friend; the receiver showed it
/// once): a run that cannot have the run lock within [`RUN_LOCK_WAIT`]
/// leaves everything to the run that holds it, or to the next one.
pub fn process_intents(data_dir: &Path, identity: &Identity, now_ms: u64) -> Pending {
    let mut pending = Pending::default();
    if !group_live_enabled() || !store::groups_path(data_dir).exists() {
        return pending;
    }
    // A sealed profile's key is loaded before any Raven lock is held.
    if crate::privacy::mode(data_dir) == crate::at_rest::Mode::Sealed {
        let _ = crate::at_rest::keys_load(data_dir);
    }
    let Ok(_run) = crate::paths::DataDirLock::acquire_within(data_dir, RUN_LOCK, RUN_LOCK_WAIT)
    else {
        return pending;
    };
    let me = identity.public_key_bytes();
    let todo = store::edit(data_dir, |file| {
        file.note_me(&me);
        file.expire(now_ms);
        let mut todo: Vec<(GroupId, Intent)> = Vec::new();
        let ids: Vec<GroupId> = file
            .groups
            .iter()
            .filter_map(|g| super::wire::hex_n::<16>(&g.id))
            .collect();
        for gid in ids {
            // The admin applies leaves first: they queue the new roster.
            let leavers: Vec<Key> = file
                .group(&gid)
                .map(|g| {
                    g.intents
                        .iter()
                        .filter(|i| i.kind == INTENT_LEAVER)
                        .filter_map(|i| hex_key(&i.to))
                        .collect()
                })
                .unwrap_or_default();
            for leaver in leavers {
                remove_leaver(file, identity, &gid, &leaver, now_ms);
            }
            let Some(g) = file.group_mut(&gid) else {
                continue;
            };
            g.intents.retain(|i| i.kind != INTENT_LEAVER);
            let epoch = g.roster().map_or(1, |r| r.epoch);
            for intent in &mut g.intents {
                if intent.kind != INTENT_RECEIPT {
                    continue;
                }
                let (Some(of), Some(author), Some(_via)) = (
                    super::wire::hex_n::<16>(&intent.of),
                    hex_key(&intent.to),
                    hex_key(&intent.via),
                ) else {
                    intent.kind = String::new();
                    continue;
                };
                let mut receipt = GroupReceipt {
                    group: gid,
                    of,
                    epoch,
                    from: me,
                    to: author,
                    at_ms: now_ms,
                    sig: [0u8; 64],
                    relay: vec![author],
                };
                receipt.sign(identity);
                intent.kind = INTENT_SEND.into();
                intent.frame = GroupFrame::Receipt(receipt).encode();
                intent.to = std::mem::take(&mut intent.via);
                intent.of = String::new();
            }
            g.intents.retain(|i| i.kind == INTENT_SEND);
            todo.extend(g.intents.iter().map(|i| (gid, i.clone())));
        }
        Ok(todo)
    });
    let Ok(todo) = todo else {
        return pending;
    };
    let mut outcomes: Vec<(GroupId, String, Parked)> = Vec::new();
    for (gid, intent) in &todo {
        let outcome = match hex_key(&intent.to) {
            Some(to) => park_copy(data_dir, &to, &intent.frame, now_ms),
            None => Parked::Never("bad target".into()),
        };
        outcomes.push((*gid, intent.id.clone(), outcome));
    }
    let written = store::edit(data_dir, |file| {
        for (gid, intent_id, outcome) in &outcomes {
            let Some(g) = file.group_mut(gid) else {
                continue;
            };
            let Some(pos) = g.intents.iter().position(|i| i.id == *intent_id) else {
                continue;
            };
            match outcome {
                Parked::Yes { device, mid } => {
                    let intent = g.intents.remove(pos);
                    let mid_hex = hex::encode(mid);
                    if !intent.line_of.is_empty() {
                        let device_hex = hex::encode(device);
                        let copy = mid_hex.clone();
                        g.set_line(&intent.line_of, &intent.to, |line| {
                            line.device = device_hex;
                            line.copy = copy;
                            if line.state.is_empty() {
                                line.state = LINE_WAITING.into();
                            }
                        });
                    }
                    let own = super::wire::hex_n::<16>(&intent.line_of);
                    pending.parked.push((*gid, own, *device));
                    file.note_copy(&mid_hex);
                }
                Parked::Later(_) => {
                    g.intents[pos].tries = g.intents[pos].tries.saturating_add(1);
                    pending.waiting += 1;
                }
                Parked::Never(_) => {
                    let intent = g.intents.remove(pos);
                    if !intent.line_of.is_empty() {
                        fail_line(g, &intent.line_of, &intent.to);
                    }
                    pending.dropped += 1;
                }
            }
        }
        Ok(())
    });
    if written.is_err() {
        // The copies are parked; their intents stay and may park a second
        // copy later, which receivers drop by message id.
        pending.waiting += pending.parked.len();
    }
    pending
}

/// Read the delivery of the copies this profile parked from chat history
/// into the store (own messages' lines), then delete the rows that are
/// final, so group copies never fill 1:1 chat history (design §3.1).
/// Returns how many rows went.
pub fn refresh_deliveries(data_dir: &Path) -> Result<u32, String> {
    if !store::groups_path(data_dir).exists() {
        return Ok(0);
    }
    let history = crate::ChatHistory::load(data_dir).map_err(|e| e.to_string())?;
    let rows: Vec<(String, String, String)> = history
        .entries
        .iter()
        .filter(|e| e.direction == "out" && e.body.starts_with(GROUP_RESERVED_PREFIX))
        .map(|e| {
            (
                e.peer_pub_hex.to_ascii_lowercase(),
                e.message_id_hex.to_ascii_lowercase(),
                e.delivery.clone(),
            )
        })
        .collect();
    if rows.is_empty() {
        return Ok(0);
    }
    let finals: HashSet<(String, String)> = store::edit(data_dir, |file| {
        let mut finals = HashSet::new();
        for (peer, mid, delivery) in &rows {
            for g in &mut file.groups {
                for m in g.messages.iter_mut().filter(|m| m.mine) {
                    for line in m
                        .lines
                        .iter_mut()
                        .filter(|l| l.copy == *mid && l.device == *peer)
                    {
                        line.state = line_after(&line.state, delivery);
                    }
                }
            }
            if is_final(delivery) {
                finals.insert((peer.clone(), mid.clone()));
            }
        }
        Ok(finals)
    })
    .map_err(|e| e.to_string())?;
    if finals.is_empty() {
        return Ok(0);
    }
    crate::ChatHistory::delete_outbound_rows(data_dir, &finals).map_err(|e| e.to_string())
}

fn is_final(delivery: &str) -> bool {
    matches!(
        delivery,
        "delivered"
            | "read"
            | crate::outbox::HISTORY_FAILED
            | crate::outbox::HISTORY_EXPIRED
            | crate::outbox::HISTORY_CANCELLED
    )
}

/// Everything waiting: the copies' delivery from history, then the intents.
/// raven-node runs it in its outbox scan; the CLI and the engine before a
/// group view and after a change.
pub fn run_pending(data_dir: &Path, identity: &Identity, now_ms: u64) -> Pending {
    let _ = refresh_deliveries(data_dir);
    process_intents(data_dir, identity, now_ms)
}
