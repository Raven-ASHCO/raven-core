//! The receive rules (protocol §4.2, design §4-§5) as pure changes of the
//! group store, and the operations of this profile as author or admin
//! (create, add, remove, leave, send), which record their copies as
//! intents and then park them ([`super::process_intents`]).

use std::collections::HashSet;
use std::path::Path;

use super::store::{
    self, hex_key, new_intent_id, Answered, GroupRecord, GroupsFile, Held, Intent, Line, StoredMsg,
    INTENT_LEAVER, INTENT_RECEIPT, INTENT_SEND, LINE_DELIVERED, LINE_FAILED, LINE_WAITING,
    STATUS_ACTIVE, STATUS_LEFT, STATUS_REMOVED, VIA_DIRECT, VIA_RELAY,
};
use super::{
    body_ok, group_live_enabled, name_ok, GroupError, GroupFrame, GroupId, GroupLeave, GroupMsg,
    GroupReceipt, GroupState, GroupSync, Key, Member, MAX_GROUP_MEMBERS,
};
use crate::identity::Identity;

/// A member may ask the admin for the roster once an hour per group.
pub const SYNC_SPACING_MS: u64 = 3_600_000;
/// The admin answers one member's `sync` once per 10 minutes.
pub const SYNC_ANSWER_SPACING_MS: u64 = 600_000;

/// What applying a frame did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Applied {
    /// The store changed.
    pub changed: bool,
    /// Intents were recorded (raven-node should scan).
    pub work: bool,
}

impl Applied {
    fn merge(&mut self, other: Applied) {
        self.changed |= other.changed;
        self.work |= other.work;
    }
}

fn send_intent(to: &Key, frame: &GroupFrame, line_of: Option<&[u8; 16]>, now_ms: u64) -> Intent {
    Intent {
        id: new_intent_id(),
        kind: INTENT_SEND.into(),
        to: hex::encode(to),
        frame: frame.encode(),
        of: String::new(),
        via: String::new(),
        line_of: line_of.map(hex::encode).unwrap_or_default(),
        made_ms: now_ms,
        tries: 0,
        author: String::new(),
    }
}

/// Apply `frame` from the carrier peer `peer` to `file` for this profile
/// `me`; `friends` are this profile's current, unblocked friends.
pub fn apply(
    file: &mut GroupsFile,
    me: &Key,
    peer: &Key,
    frame: &GroupFrame,
    friends: &HashSet<Key>,
    now_ms: u64,
) -> Applied {
    file.expire(now_ms);
    let mut done = match frame {
        GroupFrame::State(s) => apply_state(file, me, peer, s, friends, now_ms),
        GroupFrame::Msg(m) => apply_msg(file, me, peer, m, frame, friends, now_ms),
        GroupFrame::Receipt(r) => apply_receipt(file, me, peer, r, friends, now_ms),
        GroupFrame::Leave(l) => apply_leave(file, me, peer, l, now_ms),
        GroupFrame::Sync(s) => apply_sync(file, me, peer, s, now_ms),
    };
    // Expiry alone is a change worth saving too.
    done.changed = true;
    done
}

fn dropped(file: &mut GroupsFile) -> Applied {
    file.dropped = file.dropped.saturating_add(1);
    Applied {
        changed: true,
        work: false,
    }
}

fn hold(list: &mut Vec<Held>, frame: &GroupFrame, peer: &Key, now_ms: u64) {
    let text = frame.encode();
    if list.iter().any(|h| h.frame == text) {
        return;
    }
    list.push(Held {
        frame: text,
        peer: hex::encode(peer),
        at_ms: now_ms,
    });
}

fn apply_state(
    file: &mut GroupsFile,
    me: &Key,
    peer: &Key,
    state: &GroupState,
    friends: &HashSet<Key>,
    now_ms: u64,
) -> Applied {
    if !state.verify() {
        return dropped(file);
    }
    let mut done = Applied::default();
    match file.group_mut(&state.group) {
        None => {
            // An invitation comes from the admin itself, to a member.
            if state.admin != *peer || !state.has(me) || file.groups.len() >= store::MAX_GROUPS {
                return dropped(file);
            }
            file.groups.push(GroupRecord::new(state, now_ms));
            done.changed = true;
        }
        Some(g) => {
            let Some(held) = g.roster() else {
                return dropped(file);
            };
            if state.admin != held.admin {
                return dropped(file);
            }
            if state.epoch <= held.epoch {
                if state.epoch == held.epoch && *state != held {
                    file.conflicts = file.conflicts.saturating_add(1);
                }
                return Applied {
                    changed: true,
                    work: false,
                };
            }
            for gone in held.members.iter().filter(|m| !state.has(&m.key)) {
                let hex = hex::encode(gone.key);
                if !g.removed.contains(&hex) {
                    g.removed.push(hex);
                }
            }
            // A member back in the roster is no longer removed.
            g.removed
                .retain(|k| hex_key(k).is_none_or(|k| !state.has(&k)));
            g.state = (state).into();
            g.updated_ms = now_ms;
            let in_it = state.has(me);
            g.status = match g.status.as_str() {
                STATUS_LEFT if !in_it => {
                    g.left_seen_out = true;
                    STATUS_LEFT
                }
                STATUS_LEFT if g.left_seen_out => STATUS_ACTIVE,
                STATUS_LEFT => STATUS_LEFT,
                _ if in_it => STATUS_ACTIVE,
                _ => STATUS_REMOVED,
            }
            .into();
            done.changed = true;
        }
    }
    done.merge(retry_held(file, me, &state.group, friends, now_ms));
    done
}

/// Try again the frames held for `group` (after a newer roster).
fn retry_held(
    file: &mut GroupsFile,
    me: &Key,
    group: &GroupId,
    friends: &HashSet<Key>,
    now_ms: u64,
) -> Applied {
    let gid = hex::encode(group);
    let mut held: Vec<Held> = Vec::new();
    if let Some(g) = file.group_mut(group) {
        held.append(&mut g.held);
    }
    let (mine, others): (Vec<Held>, Vec<Held>) = std::mem::take(&mut file.unknown_held)
        .into_iter()
        .partition(|h| {
            super::parse_frame(h.frame.as_bytes()).is_some_and(|f| hex::encode(f.group()) == gid)
        });
    file.unknown_held = others;
    held.extend(mine);
    let mut done = Applied::default();
    for h in held {
        let (Some(frame), Some(peer)) = (super::parse_frame(h.frame.as_bytes()), hex_key(&h.peer))
        else {
            continue;
        };
        if let GroupFrame::Msg(m) = &frame {
            let mut d = apply_msg(file, me, &peer, m, &frame, friends, now_ms);
            // Keep the original hold time, so a frame never outlives 7 days.
            if let Some(g) = file.group_mut(group) {
                for again in g.held.iter_mut().filter(|x| x.frame == h.frame) {
                    again.at_ms = h.at_ms;
                }
            }
            d.changed = true;
            done.merge(d);
        }
    }
    done
}

fn apply_msg(
    file: &mut GroupsFile,
    me: &Key,
    peer: &Key,
    msg: &GroupMsg,
    frame: &GroupFrame,
    friends: &HashSet<Key>,
    now_ms: u64,
) -> Applied {
    if msg.from == *me {
        return dropped(file);
    }
    let Some(g) = file.group_mut(&msg.group) else {
        // The roster may come later.
        hold(&mut file.unknown_held, frame, peer, now_ms);
        return Applied {
            changed: true,
            work: false,
        };
    };
    if !g.is_active() {
        return dropped(file);
    }
    let id = hex::encode(msg.id);
    if g.has_seen(&hex::encode(msg.from), &id) {
        return Applied::default();
    }
    let Some(roster) = g.roster() else {
        return dropped(file);
    };
    if !roster.has(&msg.from) {
        if g.was_removed(&msg.from) || msg.epoch <= roster.epoch {
            return dropped(file);
        }
        // A newer roster than this one names the author: hold, and ask the
        // admin for it.
        hold(&mut g.held, frame, peer, now_ms);
        let mut done = Applied {
            changed: true,
            work: false,
        };
        if roster.admin != *me && now_ms >= g.sync_ms.saturating_add(SYNC_SPACING_MS) {
            g.sync_ms = now_ms;
            let sync = GroupFrame::Sync(GroupSync {
                group: msg.group,
                epoch: roster.epoch,
            });
            g.push_intent(send_intent(&roster.admin, &sync, None, now_ms));
            done.work = true;
        }
        return done;
    }
    if !msg.verify() {
        return dropped(file);
    }
    // Security review 2026-10-29 #8: a signed message older than the replay
    // horizon (or dated far in the future) is refused, and its key is kept
    // until then, so an old message cannot come back as new.
    if msg.sent_ms.saturating_add(store::REPLAY_HORIZON_MS) <= now_ms
        || msg.sent_ms > now_ms.saturating_add(store::MAX_FUTURE_SKEW_MS)
        || g.seen_full()
    {
        return dropped(file);
    }
    let forwarded = *peer != msg.from;
    g.messages.push(StoredMsg {
        id: id.clone(),
        from: hex::encode(msg.from),
        epoch: msg.epoch,
        sent_ms: msg.sent_ms,
        received_ms: now_ms,
        body: msg.body.clone(),
        sig: hex::encode(msg.sig),
        mine: false,
        via: if forwarded {
            hex::encode(peer)
        } else {
            String::new()
        },
        lines: Vec::new(),
        // How the copy came (E2 r9 #15): the receive path says it while the
        // group store takes the frame.
        path: crate::arrivals::current().map_or(String::new(), |v| v.token().to_owned()),
    });
    g.updated_ms = now_ms;
    let mut done = Applied {
        changed: true,
        work: false,
    };
    if forwarded {
        // Tell the author through the member that passed it on.
        g.push_intent(Intent {
            id: new_intent_id(),
            kind: INTENT_RECEIPT.into(),
            to: hex::encode(msg.from),
            frame: String::new(),
            of: id.clone(),
            via: hex::encode(peer),
            line_of: String::new(),
            made_ms: now_ms,
            tries: 0,
            author: String::new(),
        });
        done.work = true;
    } else {
        // Only the author's own word asks for a forward; one hop.
        let mut copy = msg.clone();
        copy.relay.clear();
        let forward = GroupFrame::Msg(copy);
        let author = hex::encode(msg.from);
        // Security review 2026-10-29 #4: one author's forwards that may wait
        // here are bounded; more are not taken on.
        let mut waiting = g.intents.iter().filter(|i| i.author == author).count();
        for target in &msg.relay {
            if !roster.has(target)
                || target == me
                || *target == msg.from
                || !friends.contains(target)
            {
                continue;
            }
            // Per author too: another author's message with the same id
            // must not stop this forward (security review 2026-10-29 #7).
            let marker = format!("{}/{id}:{}", hex::encode(msg.from), hex::encode(target));
            if g.is_done(&marker) {
                continue;
            }
            if waiting >= store::MAX_FORWARDS_PER_AUTHOR {
                break;
            }
            g.mark_done(marker);
            let mut intent = send_intent(target, &forward, None, now_ms);
            intent.author.clone_from(&author);
            g.push_intent(intent);
            waiting += 1;
            done.work = true;
        }
    }
    done
}

fn apply_receipt(
    file: &mut GroupsFile,
    me: &Key,
    peer: &Key,
    r: &GroupReceipt,
    friends: &HashSet<Key>,
    now_ms: u64,
) -> Applied {
    let Some(g) = file.group_mut(&r.group) else {
        return dropped(file);
    };
    let Some(roster) = g.roster() else {
        return dropped(file);
    };
    if !roster.has(&r.from) || !r.verify() {
        return dropped(file);
    }
    if r.to == *me {
        let of = hex::encode(r.of);
        let member = hex::encode(r.from);
        g.set_line(&of, &member, |line| line.state = LINE_DELIVERED.into());
        g.updated_ms = now_ms;
        return Applied {
            changed: true,
            work: false,
        };
    }
    // Pass it on: only for its signer, to the author it names, once.
    if *peer != r.from
        || !r.relay.contains(&r.to)
        || !roster.has(&r.to)
        || !friends.contains(&r.to)
        || !g.is_active()
    {
        return dropped(file);
    }
    let marker = format!(
        "r:{}/{}:{}",
        hex::encode(r.to),
        hex::encode(r.of),
        hex::encode(r.from)
    );
    if g.is_done(&marker) {
        return Applied::default();
    }
    g.mark_done(marker);
    let mut copy = r.clone();
    copy.relay.clear();
    g.push_intent(send_intent(&r.to, &GroupFrame::Receipt(copy), None, now_ms));
    Applied {
        changed: true,
        work: true,
    }
}

fn apply_leave(
    file: &mut GroupsFile,
    me: &Key,
    peer: &Key,
    l: &GroupLeave,
    now_ms: u64,
) -> Applied {
    let Some(g) = file.group_mut(&l.group) else {
        return dropped(file);
    };
    let Some(roster) = g.roster() else {
        return dropped(file);
    };
    if roster.admin != *me
        || l.from == roster.admin
        || *peer != l.from
        || !roster.has(&l.from)
        || !l.verify()
    {
        return dropped(file);
    }
    let to = hex::encode(l.from);
    if g.intents
        .iter()
        .any(|i| i.kind == INTENT_LEAVER && i.to == to)
    {
        return Applied::default();
    }
    g.push_intent(Intent {
        id: new_intent_id(),
        kind: INTENT_LEAVER.into(),
        to,
        frame: String::new(),
        of: String::new(),
        via: String::new(),
        line_of: String::new(),
        made_ms: now_ms,
        tries: 0,
        author: String::new(),
    });
    Applied {
        changed: true,
        work: true,
    }
}

fn apply_sync(file: &mut GroupsFile, me: &Key, peer: &Key, s: &GroupSync, now_ms: u64) -> Applied {
    let Some(g) = file.group_mut(&s.group) else {
        return dropped(file);
    };
    let Some(roster) = g.roster() else {
        return dropped(file);
    };
    if roster.admin != *me || !(roster.has(peer) || g.was_removed(peer)) {
        return dropped(file);
    }
    let key = hex::encode(peer);
    if g.answered
        .iter()
        .any(|a| a.key == key && now_ms < a.at_ms.saturating_add(SYNC_ANSWER_SPACING_MS))
    {
        return Applied::default();
    }
    g.answered.retain(|a| a.key != key);
    g.answered.push(Answered { key, at_ms: now_ms });
    g.push_intent(send_intent(peer, &GroupFrame::State(roster), None, now_ms));
    Applied {
        changed: true,
        work: true,
    }
}

// ------------------------------------------------------------------ this profile's operations

fn gate() -> Result<(), GroupError> {
    if group_live_enabled() {
        Ok(())
    } else {
        Err(GroupError::Hold)
    }
}

/// Queue the roster `state` to `to` (every member but this profile, plus
/// any extra recipient such as removed members).
fn publish(g: &mut GroupRecord, state: &GroupState, to: &[Key], me: &Key, now_ms: u64) {
    let frame = GroupFrame::State(state.clone());
    for key in to.iter().filter(|k| *k != me) {
        g.push_intent(send_intent(key, &frame, None, now_ms));
    }
}

fn check_new_members(
    friends: &HashSet<Key>,
    me: &Key,
    members: &[(Key, String)],
) -> Result<(), GroupError> {
    for (key, _) in members {
        if key == me {
            continue;
        }
        if !friends.contains(key) {
            return Err(GroupError::NotAFriend(*key));
        }
    }
    Ok(())
}

/// Create a group named `name` with this profile as admin and `members`
/// (friends, each with the label the others will see). Returns its id.
pub fn create(
    data_dir: &Path,
    identity: &Identity,
    name: &str,
    members: &[(Key, String)],
    now_ms: u64,
) -> Result<GroupId, GroupError> {
    gate()?;
    if !name_ok(name) {
        return Err(GroupError::BadName);
    }
    let me = identity.public_key_bytes();
    let friends = super::friend_keys(data_dir);
    check_new_members(&friends, &me, members)?;
    let mut roster = vec![Member {
        key: me,
        label: String::new(),
    }];
    for (key, label) in members {
        if roster.iter().any(|m| m.key == *key) {
            continue;
        }
        roster.push(Member {
            key: *key,
            label: super::clean_text(label, super::MAX_MEMBER_LABEL_CHARS),
        });
    }
    if roster.len() > MAX_GROUP_MEMBERS {
        return Err(GroupError::TooMany);
    }
    let salt: [u8; 16] = rand::random();
    let mut state = GroupState {
        group: super::group_id_for(&me, &salt),
        salt,
        epoch: 1,
        name: name.to_owned(),
        admin: me,
        issued_ms: now_ms,
        members: roster,
        sig: [0u8; 64],
    };
    state.sign(identity);
    let id = state.group;
    store::edit(data_dir, |file| {
        file.note_me(&me);
        if file.groups.len() >= store::MAX_GROUPS {
            return Err(GroupError::TooMany);
        }
        let mut g = GroupRecord::new(&state, now_ms);
        let to: Vec<Key> = state.members.iter().map(|m| m.key).collect();
        publish(&mut g, &state, &to, &me, now_ms);
        file.groups.push(g);
        Ok(())
    })?;
    super::process_intents(data_dir, identity, now_ms);
    Ok(id)
}

/// The admin's change of the roster: `change` edits the member list; the
/// next epoch is signed and sent to every member and to `also`.
fn change_roster(
    data_dir: &Path,
    identity: &Identity,
    group: &GroupId,
    now_ms: u64,
    change: impl FnOnce(&GroupState, &mut Vec<Member>) -> Result<Vec<Key>, GroupError>,
) -> Result<GroupState, GroupError> {
    gate()?;
    let me = identity.public_key_bytes();
    let state = store::edit(data_dir, |file| {
        file.note_me(&me);
        let g = file.group_mut(group).ok_or(GroupError::NotFound)?;
        let held = g.roster().ok_or(GroupError::NotFound)?;
        if held.admin != me {
            return Err(GroupError::NotAdmin);
        }
        if !g.is_active() {
            return Err(GroupError::NotMember);
        }
        let mut members = held.members.clone();
        let also = change(&held, &mut members)?;
        if members.len() > MAX_GROUP_MEMBERS {
            return Err(GroupError::TooMany);
        }
        let mut next = GroupState {
            epoch: held.epoch.checked_add(1).ok_or(GroupError::TooMany)?,
            issued_ms: now_ms.max(held.issued_ms),
            members,
            ..held.clone()
        };
        next.sign(identity);
        for gone in held.members.iter().filter(|m| !next.has(&m.key)) {
            let hex = hex::encode(gone.key);
            if !g.removed.contains(&hex) {
                g.removed.push(hex);
            }
        }
        g.removed
            .retain(|k| hex_key(k).is_none_or(|k| !next.has(&k)));
        g.state = (&next).into();
        g.updated_ms = now_ms;
        let mut to: Vec<Key> = next.members.iter().map(|m| m.key).collect();
        to.extend(also);
        publish(g, &next, &to, &me, now_ms);
        Ok(next)
    })?;
    super::process_intents(data_dir, identity, now_ms);
    Ok(state)
}

/// Add friends to a group this profile is the admin of.
pub fn add_members(
    data_dir: &Path,
    identity: &Identity,
    group: &GroupId,
    members: &[(Key, String)],
    now_ms: u64,
) -> Result<GroupState, GroupError> {
    let me = identity.public_key_bytes();
    let friends = super::friend_keys(data_dir);
    check_new_members(&friends, &me, members)?;
    change_roster(data_dir, identity, group, now_ms, |held, list| {
        for (key, label) in members {
            if held.has(key) {
                return Err(GroupError::AlreadyMember(*key));
            }
            list.push(Member {
                key: *key,
                label: super::clean_text(label, super::MAX_MEMBER_LABEL_CHARS),
            });
        }
        Ok(Vec::new())
    })
}

/// Remove members from a group this profile is the admin of; they are told
/// (the new roster goes to them too).
pub fn remove_members(
    data_dir: &Path,
    identity: &Identity,
    group: &GroupId,
    members: &[Key],
    now_ms: u64,
) -> Result<GroupState, GroupError> {
    let me = identity.public_key_bytes();
    change_roster(data_dir, identity, group, now_ms, |held, list| {
        for key in members {
            if *key == me {
                return Err(GroupError::AdminCannotLeave);
            }
            if !held.has(key) {
                return Err(GroupError::NotFound);
            }
        }
        list.retain(|m| !members.contains(&m.key));
        Ok(members.to_vec())
    })
}

/// The admin applies a verified `leave` (an intent of the receive path).
pub(crate) fn remove_leaver(
    file: &mut GroupsFile,
    identity: &Identity,
    group: &GroupId,
    leaver: &Key,
    now_ms: u64,
) {
    let me = identity.public_key_bytes();
    let Some(g) = file.group_mut(group) else {
        return;
    };
    let Some(held) = g.roster() else {
        return;
    };
    if held.admin != me || !held.has(leaver) || *leaver == me || !g.is_active() {
        return;
    }
    let Some(epoch) = held.epoch.checked_add(1) else {
        return;
    };
    let mut next = GroupState {
        epoch,
        issued_ms: now_ms.max(held.issued_ms),
        members: held
            .members
            .iter()
            .filter(|m| m.key != *leaver)
            .cloned()
            .collect(),
        ..held.clone()
    };
    next.sign(identity);
    let hex = hex::encode(leaver);
    if !g.removed.contains(&hex) {
        g.removed.push(hex);
    }
    g.state = (&next).into();
    g.updated_ms = now_ms;
    let mut to: Vec<Key> = next.members.iter().map(|m| m.key).collect();
    to.push(*leaver);
    publish(g, &next, &to, &me, now_ms);
}

/// Leave a group: a signed `leave` to the admin, and the group turns
/// `left` here at once (its history stays).
pub fn leave(
    data_dir: &Path,
    identity: &Identity,
    group: &GroupId,
    now_ms: u64,
) -> Result<(), GroupError> {
    gate()?;
    let me = identity.public_key_bytes();
    store::edit(data_dir, |file| {
        file.note_me(&me);
        let g = file.group_mut(group).ok_or(GroupError::NotFound)?;
        let held = g.roster().ok_or(GroupError::NotFound)?;
        if held.admin == me {
            return Err(GroupError::AdminCannotLeave);
        }
        if !g.is_active() {
            return Err(GroupError::NotMember);
        }
        let mut leave = GroupLeave {
            group: *group,
            epoch: held.epoch,
            from: me,
            at_ms: now_ms,
            sig: [0u8; 64],
        };
        leave.sign(identity);
        g.status = STATUS_LEFT.into();
        g.left_seen_out = false;
        g.updated_ms = now_ms;
        // Nothing of ours waits to be forwarded any more.
        g.intents
            .retain(|i| i.kind == INTENT_SEND && !i.line_of.is_empty());
        g.push_intent(send_intent(
            &held.admin,
            &GroupFrame::Leave(leave),
            None,
            now_ms,
        ));
        Ok(())
    })?;
    super::process_intents(data_dir, identity, now_ms);
    Ok(())
}

/// What a send did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendReport {
    pub id: [u8; 16],
    /// Members this profile sealed a copy for (its friends).
    pub direct: usize,
    /// Members reached through a forward.
    pub relayed: usize,
    /// Copies parked now (the rest wait as intents and go on the next run).
    pub parked: usize,
}

/// Send `body` to a group this profile is an active member of: one signed
/// message, a copy for each member who is a friend, the others named in
/// the forwarders' copies (design §4.1).
pub fn send(
    data_dir: &Path,
    identity: &Identity,
    group: &GroupId,
    body: &str,
    now_ms: u64,
) -> Result<SendReport, GroupError> {
    gate()?;
    if !body_ok(body) {
        return Err(GroupError::BadBody);
    }
    let me = identity.public_key_bytes();
    let friends = super::friend_keys(data_dir);
    let staged = crate::chat_history::list_staged_outbound_bodies(data_dir)
        .map(|s| s.len())
        .map_err(|e| GroupError::Store(e.to_string()))?;
    let (id, direct_n, relay_n) = store::edit(data_dir, |file| {
        file.note_me(&me);
        let g = file.group_mut(group).ok_or(GroupError::NotFound)?;
        let roster = g.roster().ok_or(GroupError::NotFound)?;
        if !g.is_active() || !roster.has(&me) {
            return Err(GroupError::NotMember);
        }
        let targets: Vec<Key> = roster
            .members
            .iter()
            .map(|m| m.key)
            .filter(|k| *k != me)
            .collect();
        let direct: Vec<Key> = targets
            .iter()
            .copied()
            .filter(|k| friends.contains(k))
            .collect();
        let relay: Vec<Key> = targets
            .iter()
            .copied()
            .filter(|k| !friends.contains(k))
            .collect();
        if direct.is_empty() && !targets.is_empty() {
            return Err(GroupError::NoRoute);
        }
        if staged + direct.len() > super::park::GROUP_STAGE_BUDGET {
            return Err(GroupError::QueueFull);
        }
        let forwarders: Vec<Key> = if relay.is_empty() {
            Vec::new()
        } else if direct.contains(&roster.admin) {
            vec![roster.admin]
        } else {
            direct.clone()
        };
        let mut msg = GroupMsg {
            group: *group,
            id: rand::random(),
            epoch: roster.epoch,
            from: me,
            sent_ms: now_ms,
            body: body.to_owned(),
            sig: [0u8; 64],
            relay: Vec::new(),
        };
        msg.sign(identity);
        let id = msg.id;
        let mut lines = Vec::new();
        for key in &targets {
            let via = if direct.contains(key) {
                VIA_DIRECT
            } else {
                VIA_RELAY
            };
            lines.push(Line {
                member: hex::encode(key),
                device: String::new(),
                copy: String::new(),
                via: via.into(),
                state: LINE_WAITING.into(),
            });
        }
        g.messages.push(StoredMsg {
            id: hex::encode(id),
            from: hex::encode(me),
            epoch: roster.epoch,
            sent_ms: now_ms,
            received_ms: now_ms,
            body: body.to_owned(),
            sig: hex::encode(msg.sig),
            mine: true,
            via: String::new(),
            lines,
            path: String::new(),
        });
        g.read_ms = g.read_ms.max(now_ms);
        g.updated_ms = now_ms;
        for key in &direct {
            let mut copy = msg.clone();
            if forwarders.contains(key) {
                copy.relay = relay.clone();
            }
            g.push_intent(send_intent(key, &GroupFrame::Msg(copy), Some(&id), now_ms));
        }
        Ok((id, direct.len(), relay.len()))
    })?;
    let pending = super::process_intents(data_dir, identity, now_ms);
    Ok(SendReport {
        id,
        direct: direct_n,
        relayed: relay_n,
        parked: pending.parked_for(&id),
    })
}

/// Mark lines of messages that will never go (a member no longer reachable).
pub(crate) fn fail_line(g: &mut GroupRecord, of: &str, member: &str) {
    g.set_line(of, member, |line| {
        if line.state != LINE_DELIVERED {
            line.state = LINE_FAILED.into();
        }
    });
}
