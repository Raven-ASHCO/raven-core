//! Group v1 unit tests (design §10): the frame codec and its limits, the
//! signatures, the receive rules (roster, messages, holds, the forward rule,
//! receipts, leave, sync), the store's bounds and lookups, the classifier
//! and composer guard, and parking a copy against a real session store.

use std::collections::HashSet;
use std::path::Path;

use super::rules::{apply, SYNC_SPACING_MS};
use super::store::{
    self, find_in, line_after, GroupsFile, INTENT_LEAVER, INTENT_RECEIPT, INTENT_SEND,
    LINE_DELIVERED, LINE_FAILED, LINE_SENT, LINE_WAITING, STATUS_ACTIVE, STATUS_LEFT,
    STATUS_REMOVED,
};
use super::*;

const NOW: u64 = 1_800_000_000_000;

fn id(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

fn key(seed: u8) -> Key {
    id(seed).public_key_bytes()
}

/// A roster signed by `admin` with `members` (the admin first).
/// The tests' group salt: admin 1's group is [`gid`].
const SALT: [u8; 16] = [0x47; 16];

/// Admin 1's test group.
fn gid() -> GroupId {
    super::group_id_for(&key(1), &SALT)
}

fn roster(admin: u8, members: &[u8], epoch: u32) -> GroupState {
    let mut list = vec![Member {
        key: key(admin),
        label: String::new(),
    }];
    for m in members.iter().filter(|m| **m != admin) {
        list.push(Member {
            key: key(*m),
            label: format!("member {m}"),
        });
    }
    let mut s = GroupState {
        group: super::group_id_for(&key(admin), &SALT),
        salt: SALT,
        epoch,
        name: "Team".into(),
        admin: key(admin),
        issued_ms: NOW,
        members: list,
        sig: [0; 64],
    };
    s.sign(&id(admin));
    s
}

fn msg(author: u8, epoch: u32, body: &str, relay: &[u8]) -> GroupMsg {
    let mut m = GroupMsg {
        group: gid(),
        id: [author; 16],
        epoch,
        from: key(author),
        sent_ms: NOW,
        body: body.into(),
        sig: [0; 64],
        relay: relay.iter().map(|r| key(*r)).collect(),
    };
    m.sign(&id(author));
    m
}

fn friends(of: &[u8]) -> HashSet<Key> {
    of.iter().map(|s| key(*s)).collect()
}

/// `me` received the roster from its admin.
fn joined(me: u8, state: &GroupState) -> GroupsFile {
    let mut file = GroupsFile::default();
    let done = apply(
        &mut file,
        &key(me),
        &state.admin,
        &GroupFrame::State(state.clone()),
        &HashSet::new(),
        NOW,
    );
    assert!(done.changed);
    assert_eq!(file.groups.len(), 1, "{file:?}");
    file
}

fn group(file: &GroupsFile) -> &store::GroupRecord {
    &file.groups[0]
}

fn intents_of<'a>(file: &'a GroupsFile, kind: &str) -> Vec<&'a store::Intent> {
    file.groups[0]
        .intents
        .iter()
        .filter(|i| i.kind == kind)
        .collect()
}

// ------------------------------------------------------------------ codec

#[test]
fn every_kind_round_trips_through_its_frame() {
    let state = roster(1, &[2, 3], 4);
    let mut receipt = GroupReceipt {
        group: gid(),
        of: [9; 16],
        epoch: 4,
        from: [0; 32],
        to: key(1),
        at_ms: NOW,
        sig: [0; 64],
        relay: vec![key(1)],
    };
    receipt.sign(&id(3));
    let mut leave = GroupLeave {
        group: gid(),
        epoch: 4,
        from: [0; 32],
        at_ms: NOW,
        sig: [0; 64],
    };
    leave.sign(&id(2));
    let frames = [
        GroupFrame::State(state),
        GroupFrame::Msg(msg(2, 4, "hello\nline two\ttab", &[3])),
        GroupFrame::Receipt(receipt),
        GroupFrame::Leave(leave),
        GroupFrame::Sync(GroupSync {
            group: gid(),
            epoch: 3,
        }),
    ];
    for frame in frames {
        let text = frame.encode();
        assert!(text.starts_with("RVNGRP/1 "), "{text}");
        assert!(text.len() <= MAX_GROUP_FRAME_BYTES);
        assert_eq!(parse_frame(text.as_bytes()), Some(frame.clone()), "{text}");
        assert!(matches!(
            crate::app_channel::classify(text.as_bytes()),
            crate::app_channel::PayloadClass::Group(f) if *f == frame
        ));
    }
}

#[test]
fn malformed_frames_are_refused() {
    let good = GroupFrame::Msg(msg(2, 1, "hi", &[])).encode();
    let (head, json) = good.split_once('\n').unwrap();
    let cases: Vec<String> = vec![
        format!("RVNGRP/2 msg\n{json}"),
        format!("RVNGRP/1 nope\n{json}"),
        format!("RVNGRP/1  msg\n{json}"),
        format!("{head}{json}"),
        format!(
            "{head}\n{}",
            json.replace("\"relay\":[]", "\"relay\":[],\"x\":1")
        ),
        format!("{head}\n{}", json.replace("\"relay\":[]", "")),
        format!("{head}\n{}", json.to_uppercase()),
        format!(
            "{head}\n{}",
            json.replace("\"body\":\"hi\"", "\"body\":\"\"")
        ),
        format!(
            "{head}\n{}",
            json.replace("\"body\":\"hi\"", "\"body\":\"a\\u0007b\"")
        ),
        format!("{head}\n{}", json.replace("\"epoch\":1", "\"epoch\":0")),
        format!("{head}\n{json} trailing"),
        "RVNGRP/1 msg".into(),
        "RVNGRP/".into(),
    ];
    for case in &cases {
        assert_eq!(parse_frame(case.as_bytes()), None, "{case}");
        assert_eq!(
            crate::app_channel::classify(case.as_bytes()),
            crate::app_channel::PayloadClass::ReservedInvalid,
            "{case}"
        );
    }
    // A body over the limit, a relay naming one key twice.
    let mut long = msg(2, 1, "x", &[]);
    long.body = "x".repeat(MAX_GROUP_BODY_BYTES + 1);
    assert_eq!(parse_frame(GroupFrame::Msg(long).encode().as_bytes()), None);
    let twice = msg(2, 1, "x", &[3, 3]);
    assert_eq!(
        parse_frame(GroupFrame::Msg(twice).encode().as_bytes()),
        None
    );
}

#[test]
fn a_roster_has_at_most_16_members_with_the_admin_first() {
    let members: Vec<u8> = (2..=16).collect();
    let full = roster(1, &members, 1);
    assert_eq!(full.members.len(), MAX_GROUP_MEMBERS);
    assert!(full.verify());
    let mut over = full.clone();
    over.members.push(Member {
        key: key(99),
        label: String::new(),
    });
    over.sign(&id(1));
    assert!(!over.well_formed());
    assert_eq!(
        parse_frame(GroupFrame::State(over).encode().as_bytes()),
        None
    );
    let mut not_first = roster(1, &[2], 1);
    not_first.members.swap(0, 1);
    not_first.sign(&id(1));
    assert!(!not_first.verify());
    let mut twice = roster(1, &[2], 1);
    twice.members.push(twice.members[1].clone());
    twice.sign(&id(1));
    assert!(!twice.verify());
    assert!(!name_ok(""));
    assert!(!name_ok(" Team"));
    assert!(!name_ok(&"n".repeat(MAX_GROUP_NAME_CHARS + 1)));
    assert!(name_ok(&"n".repeat(MAX_GROUP_NAME_CHARS)));
    assert_eq!(clean_text("  a\u{7}b\n ", 64), "ab");
}

#[test]
fn signatures_bind_every_signed_field_and_never_the_relay_list() {
    let m = msg(2, 1, "hello", &[3]);
    assert!(m.verify());
    let mut other = m.clone();
    other.body = "hellO".into();
    assert!(!other.verify(), "the body is bound through its hash");
    let mut other = m.clone();
    other.epoch = 2;
    assert!(!other.verify());
    let mut other = m.clone();
    other.from = key(3);
    assert!(!other.verify(), "another key never verifies it");
    let mut relayed = m.clone();
    relayed.relay = vec![key(4), key(5)];
    assert!(relayed.verify(), "relay is the sender's per-copy word");
    let state = roster(1, &[2], 1);
    let mut renamed = state.clone();
    renamed.name = "Other".into();
    assert!(!renamed.verify());
    let mut relabelled = state.clone();
    relabelled.members[1].label = "x".into();
    assert!(!relabelled.verify());
}

#[test]
fn no_group_signing_input_can_be_another_formats() {
    let mut r = GroupReceipt {
        group: [1; 16],
        of: [2; 16],
        epoch: 1,
        from: key(1),
        to: key(2),
        at_ms: 1,
        sig: [0; 64],
        relay: vec![],
    };
    r.sign(&id(1));
    let mut l = GroupLeave {
        group: [1; 16],
        epoch: 1,
        from: key(1),
        at_ms: 1,
        sig: [0; 64],
    };
    l.sign(&id(1));
    let inputs = [
        (
            roster(1, &[2], 1).signing_bytes(),
            &b"\x00\x10rvn1/group-state"[..],
        ),
        (
            msg(1, 1, "x", &[]).signing_bytes(),
            &b"\x00\x0ervn1/group-msg"[..],
        ),
        (r.signing_bytes(), &b"\x00\x12rvn1/group-receipt"[..]),
        (l.signing_bytes(), &b"\x00\x10rvn1/group-leave"[..]),
    ];
    for (bytes, prefix) in inputs {
        assert!(bytes.starts_with(prefix));
        assert!(!bytes.starts_with(&crate::agent_sign::AGENT_DELEGATION_PREFIX));
    }
}

// ------------------------------------------------------------------ roster

#[test]
fn an_invitation_comes_only_from_the_admin_to_a_member() {
    let state = roster(1, &[2, 3], 1);
    let frame = GroupFrame::State(state.clone());
    // From a member who is not the admin: dropped.
    let mut file = GroupsFile::default();
    apply(&mut file, &key(2), &key(3), &frame, &HashSet::new(), NOW);
    assert!(file.groups.is_empty());
    assert_eq!(file.dropped, 1);
    // To someone not on the list: dropped.
    apply(&mut file, &key(9), &key(1), &frame, &HashSet::new(), NOW);
    assert!(file.groups.is_empty());
    // A forged signature: dropped.
    let mut forged = state.clone();
    forged.sig[0] ^= 1;
    apply(
        &mut file,
        &key(2),
        &key(1),
        &GroupFrame::State(forged),
        &HashSet::new(),
        NOW,
    );
    assert!(file.groups.is_empty());
    let file = joined(2, &state);
    assert_eq!(group(&file).status, STATUS_ACTIVE);
    assert_eq!(group(&file).roster(), Some(state));
}

#[test]
fn rosters_move_forward_only_and_removal_is_remembered() {
    let mut file = joined(2, &roster(1, &[2, 3, 4], 1));
    let me = key(2);
    let none = HashSet::new();
    // Epoch 2 drops member 4; any member may carry it.
    let two = roster(1, &[2, 3], 2);
    apply(
        &mut file,
        &me,
        &key(3),
        &GroupFrame::State(two.clone()),
        &none,
        NOW,
    );
    assert_eq!(group(&file).roster().unwrap().epoch, 2);
    assert!(group(&file).was_removed(&key(4)));
    // An older epoch changes nothing; the same epoch with other content is
    // a conflict, ignored.
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::State(roster(1, &[2, 3, 4], 1)),
        &none,
        NOW,
    );
    assert_eq!(group(&file).roster().unwrap(), two);
    let mut conflict = roster(1, &[2, 3, 5], 2);
    conflict.sign(&id(1));
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::State(conflict),
        &none,
        NOW,
    );
    assert_eq!(group(&file).roster().unwrap(), two);
    assert_eq!(file.conflicts, 1);
    // A roster signed by anyone else than the group's admin: dropped.
    let mut usurper = roster(3, &[2], 3);
    usurper.group = two.group;
    usurper.sign(&id(3));
    apply(
        &mut file,
        &me,
        &key(3),
        &GroupFrame::State(usurper),
        &none,
        NOW,
    );
    assert_eq!(group(&file).roster().unwrap(), two);
    // Removed: no more messages; re-added later: active again.
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::State(roster(1, &[3], 3)),
        &none,
        NOW,
    );
    assert_eq!(group(&file).status, STATUS_REMOVED);
    let m = msg(3, 3, "after removal", &[]);
    apply(&mut file, &me, &key(3), &GroupFrame::Msg(m), &none, NOW);
    assert!(group(&file).messages.is_empty());
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::State(roster(1, &[2, 3], 4)),
        &none,
        NOW,
    );
    assert_eq!(group(&file).status, STATUS_ACTIVE);
}

#[test]
fn a_leaver_stays_out_until_a_roster_without_it_then_one_with_it() {
    let mut file = joined(2, &roster(1, &[2, 3], 1));
    let me = key(2);
    let none = HashSet::new();
    file.groups[0].status = STATUS_LEFT.into();
    // The admin added someone before it took the leave: still left.
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::State(roster(1, &[2, 3, 4], 2)),
        &none,
        NOW,
    );
    assert_eq!(group(&file).status, STATUS_LEFT);
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::State(roster(1, &[3, 4], 3)),
        &none,
        NOW,
    );
    assert_eq!(group(&file).status, STATUS_LEFT);
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::State(roster(1, &[2, 3, 4], 4)),
        &none,
        NOW,
    );
    assert_eq!(group(&file).status, STATUS_ACTIVE);
}

// ------------------------------------------------------------------ messages

#[test]
fn a_message_is_stored_once_and_only_from_a_member_with_its_signature() {
    let mut file = joined(2, &roster(1, &[2, 3], 1));
    let me = key(2);
    let none = HashSet::new();
    let m = msg(3, 1, "hi all", &[]);
    apply(
        &mut file,
        &me,
        &key(3),
        &GroupFrame::Msg(m.clone()),
        &none,
        NOW,
    );
    apply(
        &mut file,
        &me,
        &key(3),
        &GroupFrame::Msg(m.clone()),
        &none,
        NOW + 1,
    );
    assert_eq!(group(&file).messages.len(), 1);
    let stored = &group(&file).messages[0];
    assert_eq!(
        (stored.body.as_str(), stored.mine, stored.via.as_str()),
        ("hi all", false, "")
    );
    // A stranger, a tampered body, our own key: dropped.
    apply(
        &mut file,
        &me,
        &key(3),
        &GroupFrame::Msg(msg(9, 1, "x", &[])),
        &none,
        NOW,
    );
    let mut tampered = msg(1, 1, "real", &[]);
    tampered.body = "fake".into();
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::Msg(tampered),
        &none,
        NOW,
    );
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::Msg(msg(2, 1, "echo", &[])),
        &none,
        NOW,
    );
    assert_eq!(group(&file).messages.len(), 1);
    assert_eq!(file.dropped, 3);
}

#[test]
fn a_message_ahead_of_the_roster_is_held_and_the_admin_asked_once() {
    let mut file = joined(2, &roster(1, &[2, 3], 1));
    let me = key(2);
    let none = HashSet::new();
    // Member 4 joined at epoch 2, which has not reached us yet.
    let early = msg(4, 2, "I'm new", &[]);
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::Msg(early.clone()),
        &none,
        NOW,
    );
    assert!(group(&file).messages.is_empty());
    assert_eq!(group(&file).held.len(), 1);
    let syncs = intents_of(&file, INTENT_SEND);
    assert_eq!(syncs.len(), 1);
    assert_eq!(syncs[0].to, hex::encode(key(1)));
    assert!(syncs[0].frame.starts_with("RVNGRP/1 sync\n"));
    // A second early frame within the hour asks nothing more.
    let early2 = msg(5, 3, "me too", &[]);
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::Msg(early2),
        &none,
        NOW + 10,
    );
    assert_eq!(intents_of(&file, INTENT_SEND).len(), 1);
    const { assert!(SYNC_SPACING_MS >= 3_600_000) };
    // The roster arrives: the held message is taken.
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::State(roster(1, &[2, 3, 4], 2)),
        &none,
        NOW + 20,
    );
    let bodies: Vec<&str> = group(&file)
        .messages
        .iter()
        .map(|m| m.body.as_str())
        .collect();
    assert_eq!(bodies, vec!["I'm new"]);
    // Member 5 claims epoch 3, still ahead: held, and gone after 7 days.
    assert_eq!(group(&file).held.len(), 1);
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::Sync(GroupSync {
            group: gid(),
            epoch: 1,
        }),
        &none,
        NOW + store::WORK_TTL_MS + 21,
    );
    assert!(group(&file).held.is_empty());
}

#[test]
fn a_message_for_an_unknown_group_waits_for_its_invitation() {
    let mut file = GroupsFile::default();
    let me = key(2);
    let none = HashSet::new();
    apply(
        &mut file,
        &me,
        &key(3),
        &GroupFrame::Msg(msg(3, 1, "early", &[])),
        &none,
        NOW,
    );
    assert_eq!(file.unknown_held.len(), 1);
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::State(roster(1, &[2, 3], 1)),
        &none,
        NOW + 1,
    );
    assert!(file.unknown_held.is_empty());
    assert_eq!(group(&file).messages.len(), 1);
}

#[test]
fn the_admin_forwards_to_listed_friends_once_and_never_a_forwarded_copy() {
    // Admin 1 is friends with 2 and 3; author 2 is not friends with 3.
    let mut file = joined(1, &roster(1, &[2, 3, 4], 1));
    let me = key(1);
    let mine = friends(&[2, 3]);
    let m = msg(2, 1, "for everyone", &[3, 4, 1]);
    apply(
        &mut file,
        &me,
        &key(2),
        &GroupFrame::Msg(m.clone()),
        &mine,
        NOW,
    );
    let sends = intents_of(&file, INTENT_SEND);
    // 3 is a friend: forwarded; 4 is not; never back to the author or us.
    assert_eq!(sends.len(), 1, "{sends:?}");
    assert_eq!(sends[0].to, hex::encode(key(3)));
    let Some(GroupFrame::Msg(fwd)) = parse_frame(sends[0].frame.as_bytes()) else {
        panic!("not a msg");
    };
    assert!(fwd.relay.is_empty(), "one hop");
    assert!(fwd.verify());
    // The same copy again (a re-sealed copy): no second forward.
    file.groups[0].messages.clear();
    apply(&mut file, &me, &key(2), &GroupFrame::Msg(m), &mine, NOW + 1);
    assert_eq!(intents_of(&file, INTENT_SEND).len(), 1);

    // A copy that did not come from its author is never forwarded, whatever
    // its relay list says; it asks for a receipt to the author instead.
    let mut file = joined(3, &roster(1, &[2, 3, 4], 1));
    let me = key(3);
    let hop = msg(2, 1, "via the admin", &[4]);
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::Msg(hop),
        &friends(&[1, 4]),
        NOW,
    );
    assert!(intents_of(&file, INTENT_SEND).is_empty());
    let receipts = intents_of(&file, INTENT_RECEIPT);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].to, hex::encode(key(2)));
    assert_eq!(receipts[0].via, hex::encode(key(1)));
    assert_eq!(group(&file).messages[0].via, hex::encode(key(1)));
}

#[test]
fn a_receipt_reaches_the_author_through_the_forwarder() {
    // Author 2, forwarder (admin) 1, receiver 3.
    let state = roster(1, &[2, 3], 1);
    let mut receipt = GroupReceipt {
        group: state.group,
        of: [2; 16],
        epoch: 1,
        from: [0; 32],
        to: key(2),
        at_ms: NOW,
        sig: [0; 64],
        relay: vec![key(2)],
    };
    receipt.sign(&id(3));
    // The forwarder passes it on to the author, once.
    let mut admin = joined(1, &state);
    let frame = GroupFrame::Receipt(receipt.clone());
    apply(&mut admin, &key(1), &key(3), &frame, &friends(&[2, 3]), NOW);
    apply(
        &mut admin,
        &key(1),
        &key(3),
        &frame,
        &friends(&[2, 3]),
        NOW + 1,
    );
    let sends = intents_of(&admin, INTENT_SEND);
    assert_eq!(sends.len(), 1);
    assert_eq!(sends[0].to, hex::encode(key(2)));
    // Not from its signer: not passed on.
    let mut other = joined(1, &state);
    apply(&mut other, &key(1), &key(2), &frame, &friends(&[2, 3]), NOW);
    assert!(intents_of(&other, INTENT_SEND).is_empty());
    // The author marks member 3 delivered.
    let mut author = joined(2, &state);
    author.groups[0].messages.push(store::StoredMsg {
        id: hex::encode([2u8; 16]),
        from: hex::encode(key(2)),
        epoch: 1,
        sent_ms: NOW,
        received_ms: NOW,
        body: "x".into(),
        sig: String::new(),
        mine: true,
        via: String::new(),
        lines: vec![store::Line {
            member: hex::encode(key(3)),
            device: String::new(),
            copy: String::new(),
            via: store::VIA_RELAY.into(),
            state: LINE_WAITING.into(),
        }],
        path: String::new(),
    });
    apply(&mut author, &key(2), &key(1), &frame, &HashSet::new(), NOW);
    assert_eq!(author.groups[0].messages[0].lines[0].state, LINE_DELIVERED);
    // A forged receipt changes nothing.
    let mut forged = receipt;
    forged.of = [7; 16];
    apply(
        &mut author,
        &key(2),
        &key(1),
        &GroupFrame::Receipt(forged),
        &HashSet::new(),
        NOW,
    );
    assert_eq!(author.dropped, 1);
}

#[test]
fn the_admin_takes_a_leave_from_the_member_itself_and_answers_sync_sparingly() {
    let state = roster(1, &[2, 3], 1);
    let mut admin = joined(1, &state);
    let mut leave = GroupLeave {
        group: state.group,
        epoch: 1,
        from: [0; 32],
        at_ms: NOW,
        sig: [0; 64],
    };
    leave.sign(&id(2));
    let frame = GroupFrame::Leave(leave);
    // Carried by someone else: dropped.
    apply(&mut admin, &key(1), &key(3), &frame, &HashSet::new(), NOW);
    assert!(intents_of(&admin, INTENT_LEAVER).is_empty());
    apply(&mut admin, &key(1), &key(2), &frame, &HashSet::new(), NOW);
    apply(&mut admin, &key(1), &key(2), &frame, &HashSet::new(), NOW);
    assert_eq!(intents_of(&admin, INTENT_LEAVER).len(), 1);
    // A non-admin ignores a leave.
    let mut member = joined(3, &state);
    apply(&mut member, &key(3), &key(2), &frame, &HashSet::new(), NOW);
    assert!(member.groups[0].intents.is_empty());
    // Sync: answered once per 10 minutes per member, never to a stranger.
    let sync = GroupFrame::Sync(GroupSync {
        group: state.group,
        epoch: 0,
    });
    apply(&mut admin, &key(1), &key(3), &sync, &HashSet::new(), NOW);
    apply(
        &mut admin,
        &key(1),
        &key(3),
        &sync,
        &HashSet::new(),
        NOW + 1,
    );
    apply(&mut admin, &key(1), &key(9), &sync, &HashSet::new(), NOW);
    let answers: Vec<_> = intents_of(&admin, INTENT_SEND);
    assert_eq!(answers.len(), 1);
    assert!(answers[0].frame.starts_with("RVNGRP/1 state\n"));
}

#[test]
fn the_admin_publishes_the_next_roster_without_a_leaver() {
    let state = roster(1, &[2, 3], 1);
    let mut admin = joined(1, &state);
    super::rules::remove_leaver(&mut admin, &id(1), &state.group, &key(2), NOW);
    let next = group(&admin).roster().unwrap();
    assert_eq!(next.epoch, 2);
    assert!(!next.has(&key(2)) && next.has(&key(3)));
    assert!(next.verify());
    let to: HashSet<String> = intents_of(&admin, INTENT_SEND)
        .iter()
        .map(|i| i.to.clone())
        .collect();
    // The remaining member and the leaver hear of it; not the admin itself.
    assert_eq!(to, [key(2), key(3)].iter().map(hex::encode).collect());
}

// ------------------------------------------------------------------ store

#[test]
fn messages_are_bounded_across_groups_and_evicted_ids_still_drop_copies() {
    let mut file = joined(2, &roster(1, &[2, 3], 1));
    let mut other = roster(1, &[2], 1);
    other.group = [0x48; 16];
    other.sign(&id(1));
    file.groups.push(store::GroupRecord::new(&other, NOW));
    let push = |g: &mut store::GroupRecord, n: usize| {
        for i in 0..n {
            g.messages.push(store::StoredMsg {
                id: format!("{:032x}", i + 1),
                from: hex::encode(key(3)),
                epoch: 1,
                sent_ms: NOW,
                received_ms: NOW,
                body: "b".into(),
                sig: String::new(),
                mine: false,
                via: String::new(),
                lines: Vec::new(),
                path: String::new(),
            });
        }
    };
    push(&mut file.groups[0], store::MAX_MESSAGES_TOTAL);
    push(&mut file.groups[1], 10);
    file.enforce_caps();
    let total: usize = file.groups.iter().map(|g| g.messages.len()).sum();
    assert_eq!(total, store::MAX_MESSAGES_TOTAL);
    // The largest group lost its oldest; the small one kept everything.
    assert_eq!(file.groups[1].messages.len(), 10);
    assert!(file.groups[0].has_seen(&hex::encode(key(3)), &format!("{:032x}", 1)));
    assert!(!file.groups[0]
        .messages
        .iter()
        .any(|m| m.id == format!("{:032x}", 1)));
}

#[test]
fn groups_are_found_by_id_prefix_or_name() {
    let mut file = joined(2, &roster(1, &[2], 1));
    let mut other = roster(1, &[2], 1);
    other.group = [0x48; 16];
    other.name = "Family".into();
    other.sign(&id(1));
    file.groups.push(store::GroupRecord::new(&other, NOW));
    assert_eq!(find_in(&file, "team"), Ok(gid()));
    assert_eq!(find_in(&file, "FAMILY"), Ok([0x48; 16]));
    assert_eq!(find_in(&file, &hex::encode(gid())[..4]), Ok(gid()));
    assert_eq!(find_in(&file, &hex::encode([0x48u8; 16])), Ok([0x48; 16]));
    assert_eq!(
        find_in(&file, &hex::encode(gid())[..3]),
        Err(GroupError::NotFound)
    );
    assert_eq!(find_in(&file, "nobody"), Err(GroupError::NotFound));
    let mut twin = roster(1, &[2], 1);
    twin.group = [0x49; 16];
    twin.sign(&id(1));
    file.groups.push(store::GroupRecord::new(&twin, NOW));
    assert_eq!(find_in(&file, "team"), Err(GroupError::Ambiguous));
}

#[test]
fn line_states_follow_history_and_delivered_is_final() {
    assert_eq!(line_after(LINE_WAITING, "queued"), LINE_WAITING);
    assert_eq!(line_after(LINE_WAITING, "sent"), LINE_SENT);
    assert_eq!(line_after(LINE_SENT, "delivered"), LINE_DELIVERED);
    assert_eq!(line_after(LINE_SENT, "expired"), LINE_FAILED);
    assert_eq!(line_after(LINE_FAILED, "delivered"), LINE_DELIVERED);
    assert_eq!(line_after(LINE_DELIVERED, "failed"), LINE_DELIVERED);
    assert_eq!(line_after(LINE_FAILED, "sent"), LINE_FAILED);
}

// ------------------------------------------------------------------ guards

#[test]
fn chat_composers_refuse_the_reserved_prefix() {
    assert!(!crate::app_channel::chat_text_allowed("RVNGRP/1 msg\n{}"));
    assert!(!crate::app_channel::chat_text_allowed("RVNGRP/anything"));
    assert!(!crate::app_channel::chat_text_allowed("RVNAPP/1 x"));
    assert!(crate::app_channel::chat_text_allowed(
        "rvngrp/ is fine in lower case"
    ));
    assert!(crate::app_channel::chat_text_allowed(
        "a RVNGRP/ later in the text"
    ));
}

#[test]
fn the_gate_needs_the_groups_switch_and_the_horizon() {
    let set = |groups: Option<bool>, horizon: Option<bool>| {
        set_lab_groups_for_this_thread(groups);
        crate::horizon::set_lab_horizon_for_this_thread(horizon);
        group_live_enabled()
    };
    const { assert!(!GROUPS_PRODUCTION_ENABLED) };
    assert!(!set(Some(true), Some(false)));
    assert!(!set(Some(false), Some(true)));
    assert_eq!(set(Some(true), Some(true)), cfg!(debug_assertions));
    set(None, None);
}

/// CI sets every lab switch (`RAVEN_LAB_GROUPS`, `RAVEN_LAB_HORIZON`,
/// `RAVEN_LAB_TEST_A`) and runs this in a release build: groups stay held.
#[test]
fn the_lab_switch_is_inert_without_debug_assertions() {
    if cfg!(debug_assertions) {
        return;
    }
    set_lab_groups_for_this_thread(Some(true));
    assert!(!group_live_enabled());
    set_lab_groups_for_this_thread(None);
    assert!(!group_live_enabled());
}

// ------------------------------------------------------------------ disk

struct Lab;

impl Lab {
    fn on() -> Lab {
        set_lab_groups_for_this_thread(Some(true));
        crate::horizon::set_lab_horizon_for_this_thread(Some(true));
        Lab
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        set_lab_groups_for_this_thread(None);
        crate::horizon::set_lab_horizon_for_this_thread(None);
    }
}

fn write_friends(dir: &Path, list: &[(u8, &str)]) {
    let rows: Vec<serde_json::Value> = list
        .iter()
        .map(|(seed, name)| {
            serde_json::json!({
                "petname": name,
                "address": id(*seed).address(),
                "pub_hex": hex::encode(key(*seed)),
            })
        })
        .collect();
    crate::contact_book::write_rows(dir, &rows).unwrap();
}

fn profile(seed: u8) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    crate::device_cert::ensure_local_device_certificate(
        dir.path(),
        &id(seed),
        crate::paths::PRIMARY_DEVICE_ID,
    )
    .unwrap();
    dir
}

#[test]
fn create_send_and_view_on_a_profile() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _lab = Lab::on();
    let dir = profile(1);
    let d = dir.path();
    write_friends(d, &[(2, "Bea"), (3, "Cy")]);
    // Only friends can be added.
    assert_eq!(
        create(d, &id(1), "Team", &[(key(9), "x".into())], NOW),
        Err(GroupError::NotAFriend(key(9)))
    );
    assert_eq!(create(d, &id(1), "", &[], NOW), Err(GroupError::BadName));
    let gid = create(
        d,
        &id(1),
        "Team",
        &[(key(2), "Bea".into()), (key(3), "Cy".into())],
        NOW,
    )
    .unwrap();
    assert_eq!(find(d, "team"), Ok(gid));
    let v = view(d, &gid).unwrap();
    assert!(v.summary.i_am_admin);
    assert_eq!(v.members.len(), 3);
    assert_eq!(v.member(&key(2)).unwrap().display(), "Bea");
    assert_eq!(v.member(&key(1)).unwrap().display(), "you");
    // The rosters to both members wait as intents or parked copies.
    let report = send(d, &id(1), &gid, "hello team", NOW + 1).unwrap();
    assert_eq!((report.direct, report.relayed), (2, 0));
    let h = history(d, &gid, None, 10).unwrap();
    assert_eq!(h.len(), 1);
    assert!(h[0].mine);
    assert_eq!(h[0].total, 2);
    assert_eq!(h[0].delivered, 0);
    assert_eq!(send(d, &id(1), &gid, "  ", NOW), Err(GroupError::BadBody));
    // The admin cannot leave; members can be removed, and then are gone.
    assert_eq!(
        leave(d, &id(1), &gid, NOW),
        Err(GroupError::AdminCannotLeave)
    );
    let next = remove_members(d, &id(1), &gid, &[key(3)], NOW + 2).unwrap();
    assert_eq!(next.epoch, 2);
    assert_eq!(view(d, &gid).unwrap().members.len(), 2);
    assert_eq!(
        add_members(d, &id(1), &gid, &[(key(2), String::new())], NOW + 3),
        Err(GroupError::AlreadyMember(key(2)))
    );
    // The file is the store's, readable again.
    let file = store::load(d).unwrap();
    assert_eq!(file.me, hex::encode(key(1)));
    // Gate off: refused, nothing written.
    set_lab_groups_for_this_thread(Some(false));
    assert_eq!(send(d, &id(1), &gid, "x", NOW), Err(GroupError::Hold));
}

/// E2 r40 #B: two runs of the intents at once never park two copies of
/// one: a run that cannot have the run lock leaves the intent to the one
/// that holds it.
#[test]
fn one_run_of_the_intents_at_a_time_parks_each_copy_once() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _lab = Lab::on();
    let dir = profile(1);
    let d = dir.path();
    write_friends(d, &[(2, "Bea")]);
    let gid = create(d, &id(1), "Team", &[(key(2), "Bea".into())], NOW).unwrap();
    let parked = |d: &std::path::Path| {
        crate::IndexedSessionStore::open(d)
            .unwrap()
            .parked_for_recipient(&key(2))
            .unwrap()
            .len()
    };
    let before = parked(d);
    // Another run holds the lock: this send's copy waits as an intent.
    let other = crate::paths::DataDirLock::acquire(d, park::RUN_LOCK_NAME_FOR_TESTS).unwrap();
    let report = send(d, &id(1), &gid, "hello", NOW + 1).unwrap();
    assert_eq!((report.direct, report.parked), (1, 0));
    assert_eq!(parked(d), before);
    drop(other);
    // The next run parks it, once; a run after that has nothing left.
    let first = park::process_intents(d, &id(1), NOW + 2);
    assert_eq!(first.parked.len(), 1);
    assert_eq!(park::process_intents(d, &id(1), NOW + 3).parked.len(), 0);
    assert_eq!(parked(d), before + 1);
}

#[test]
fn a_copy_is_parked_for_a_friend_and_never_for_a_stranger() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _lab = Lab::on();
    let dir = profile(1);
    let d = dir.path();
    write_friends(d, &[(2, "Bea")]);
    let text = GroupFrame::Msg(msg(1, 1, "copy", &[])).encode();
    assert!(matches!(
        park::park_copy(d, &key(9), &text, NOW),
        park::Parked::Never(_)
    ));
    let park::Parked::Yes { device, mid } = park::park_copy(d, &key(2), &text, NOW) else {
        panic!("not parked");
    };
    assert_eq!(
        device,
        key(2),
        "a friend without a cached certificate: its own key"
    );
    let sessions = crate::IndexedSessionStore::open(d).unwrap();
    let parked = sessions.parked_for_recipient(&device).unwrap();
    assert_eq!(parked.len(), 1);
    assert_eq!(parked[0].message_id, mid);
    let staged = crate::chat_history::load_staged_outbound_body(d, &mid)
        .unwrap()
        .unwrap();
    assert_eq!(staged.body, text);
    // The history row is never a chat view's, and goes once it is final.
    let row = |d: &Path| {
        crate::ChatHistory::load(d)
            .unwrap()
            .entries
            .into_iter()
            .find(|e| e.message_id_hex == hex::encode(mid))
    };
    assert_eq!(row(d).unwrap().delivery, "queued");
    // The store knows its own copies (a late delivery word is no error).
    store::edit(d, |f| {
        f.note_copy(&hex::encode(mid));
        Ok(())
    })
    .unwrap();
    crate::ChatHistory::set_delivery_persisted(
        d,
        &hex::encode(device),
        "out",
        &hex::encode(mid),
        "delivered",
    )
    .unwrap();
    assert_eq!(refresh_deliveries(d).unwrap(), 1);
    assert!(row(d).is_none());
    assert!(mark_copy(d, &mid, "delivered").unwrap());
    assert!(!mark_copy(d, &[0x55; 16], "delivered").unwrap());
    crate::lan_dispatch::mark_lan_chat_history_delivery(d, "out", &device, &mid, "delivered")
        .unwrap();
}

#[test]
fn ingest_reads_this_profiles_key_and_asks_raven_node_for_work() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    fn note() {
        CALLS.fetch_add(1, Ordering::SeqCst);
    }
    set_work_notifier(note);
    let dir = profile(3);
    let d = dir.path();
    write_friends(d, &[(1, "Admin")]);
    assert_eq!(local_identity_key(d), Some(key(3)));
    let state = roster(1, &[2, 3], 1);
    ingest(d, &key(1), &GroupFrame::State(state), NOW).unwrap();
    let before = CALLS.load(Ordering::SeqCst);
    // A copy forwarded by the admin: stored, and a receipt intent is work.
    ingest(
        d,
        &key(1),
        &GroupFrame::Msg(msg(2, 1, "via admin", &[])),
        NOW + 1,
    )
    .unwrap();
    assert!(CALLS.load(Ordering::SeqCst) > before);
    let gid = gid();
    let h = history(d, &gid, None, 10).unwrap();
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].via, Some(key(1)));
    assert_eq!(list(d).unwrap()[0].unread, 1);
    mark_read(d, &gid, NOW + 2).unwrap();
    assert_eq!(list(d).unwrap()[0].unread, 0);
}

// ------------------------------------------------------------------ vector

/// `shared-vectors/rvn1/group/group_v1_001.json`: a roster and a message
/// with fixed seeds (Ed25519 is deterministic), their signing bytes, the
/// signatures and the frames. Regenerate with `RAVEN_REGEN_GROUP_VECTORS=1`
/// only when the wire format changes on purpose.
#[test]
fn the_committed_vector_matches() {
    let admin = Identity::from_seed(&[0x11; 32]);
    let author = Identity::from_seed(&[0x22; 32]);
    let mut state = GroupState {
        group: super::group_id_for(&admin.public_key_bytes(), &[0xA2; 16]),
        salt: [0xA2; 16],
        epoch: 3,
        name: "Reading club".into(),
        admin: [0; 32],
        issued_ms: 1_767_225_600_000,
        members: vec![
            Member {
                key: admin.public_key_bytes(),
                label: String::new(),
            },
            Member {
                key: author.public_key_bytes(),
                label: "Sam".into(),
            },
        ],
        sig: [0; 64],
    };
    state.sign(&admin);
    let mut m = GroupMsg {
        group: state.group,
        id: [0xB2; 16],
        epoch: 3,
        from: [0; 32],
        sent_ms: 1_767_225_660_000,
        body: "See you at eight.".into(),
        sig: [0; 64],
        relay: vec![],
    };
    m.sign(&author);
    let state_frame = GroupFrame::State(state.clone()).encode();
    let msg_frame = GroupFrame::Msg(m.clone()).encode();
    let expected = serde_json::json!({
        "description": "RAVEN Group V1 (protocol/RAVEN_GROUP_V1.md): a roster and a message",
        "admin_seed": hex::encode([0x11u8; 32]),
        "author_seed": hex::encode([0x22u8; 32]),
        "state_signing_bytes": hex::encode(state.signing_bytes()),
        "state_sig": hex::encode(state.sig),
        "state_frame": state_frame,
        "msg_signing_bytes": hex::encode(m.signing_bytes()),
        "msg_sig": hex::encode(m.sig),
        "msg_frame": msg_frame,
    });
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for _ in 0..3 {
        path.pop();
    }
    let path = path.join("shared-vectors/rvn1/group/group_v1_001.json");
    if std::env::var("RAVEN_REGEN_GROUP_VECTORS").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&expected).unwrap() + "\n",
        )
        .unwrap();
    }
    let stored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(stored, expected);
    assert_eq!(
        parse_frame(state_frame.as_bytes()),
        Some(GroupFrame::State(state))
    );
    assert_eq!(parse_frame(msg_frame.as_bytes()), Some(GroupFrame::Msg(m)));
}

/// E2 r9 #15: a received message keeps how the copy that brought it came
/// (the receive path says it while the store takes the frame); without
/// one, or for yours, nothing, and the store then writes no `path` at all.
#[test]
fn a_received_message_keeps_how_it_came() {
    let state = roster(1, &[2, 3], 1);
    let mut file = joined(3, &state);
    let tor = crate::arrivals::during(Some(crate::arrivals::ArrivedVia::Tor), || {
        apply(
            &mut file,
            &key(3),
            &key(2),
            &GroupFrame::Msg(msg(2, 1, "over Tor", &[])),
            &friends(&[1, 2]),
            NOW,
        )
    });
    assert!(tor.changed);
    let plain = apply(
        &mut file,
        &key(3),
        &key(1),
        &GroupFrame::Msg(msg(1, 1, "no path known", &[])),
        &friends(&[1, 2]),
        NOW,
    );
    assert!(plain.changed);
    let paths: Vec<(&str, &str)> = group(&file)
        .messages
        .iter()
        .map(|m| (m.body.as_str(), m.path.as_str()))
        .collect();
    assert_eq!(paths, [("over Tor", "tor"), ("no path known", "")]);
    let json = serde_json::to_string(&group(&file).messages[1]).unwrap();
    assert!(!json.contains("\"path\""), "{json}");
    let back: store::StoredMsg =
        serde_json::from_str(&serde_json::to_string(&group(&file).messages[0]).unwrap()).unwrap();
    assert_eq!(back.path, "tor");
}

/// Security review 2026-10-29 #2: a member (2) learned a group's id and
/// sent a friend (3) its own roster for that id first; the real admin's
/// roster was then refused for good, and real members' messages landed in
/// the squatter's record. Now a group id is bound to its admin
/// ([`group_id_for`]): a roster for another admin's id is not well formed,
/// and the real admin's roster is taken.
#[test]
fn a_roster_for_another_admins_group_id_is_refused() {
    let me = key(3);
    let none = HashSet::new();
    // Member 2 signs a roster under the real group's id (admin 1's).
    let mut fake = roster(2, &[3, 1], 1);
    fake.group = gid();
    fake.sign(&id(2));
    assert!(!fake.verify());
    let mut file = GroupsFile::default();
    let before = file.dropped;
    apply(
        &mut file,
        &me,
        &key(2),
        &GroupFrame::State(fake),
        &none,
        NOW,
    );
    assert_eq!(file.dropped, before + 1, "the squatter's roster is dropped");
    assert!(file.groups.is_empty());
    // A roster of its own (its own id) is another group, not this one.
    apply(
        &mut file,
        &me,
        &key(2),
        &GroupFrame::State(roster(2, &[3, 1], 1)),
        &none,
        NOW,
    );
    assert!(file.group(&gid()).is_none());
    // The real admin's invitation is taken.
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::State(roster(1, &[2, 3], 2)),
        &none,
        NOW + 1,
    );
    let real = file
        .group(&gid())
        .expect("the real group")
        .roster()
        .unwrap();
    assert_eq!(real.admin, key(1));
    // Changing the salt or the admin changes the id.
    assert_ne!(group_id_for(&key(1), &[0x48; 16]), gid());
    assert_ne!(group_id_for(&key(2), &SALT), gid());
}

fn msg_with_id(author: u8, epoch: u32, body: &str, id_bytes: [u8; 16], relay: &[u8]) -> GroupMsg {
    let mut m = msg(author, epoch, body, relay);
    m.id = id_bytes;
    m.sign(&id(author));
    m
}

/// Security review 2026-10-29 #7: messages were deduplicated by id alone:
/// a member (2) that saw author 1's message first could send its own
/// message under the same id, and the real one was then dropped as a
/// duplicate (and ACKed). Now a message is known by (author, id): both are
/// kept, and the same author's copy again is still a duplicate.
#[test]
fn another_authors_message_with_the_same_id_does_not_hide_the_real_one() {
    let me = key(3);
    let none = HashSet::new();
    let mut file = joined(3, &roster(1, &[2, 3], 1));
    let target_id = [0x11; 16];
    let decoy = msg_with_id(2, 1, "decoy by 2", target_id, &[]);
    apply(&mut file, &me, &key(2), &GroupFrame::Msg(decoy), &none, NOW);
    let real = msg_with_id(1, 1, "real by 1", target_id, &[]);
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::Msg(real.clone()),
        &none,
        NOW + 1,
    );
    let bodies: Vec<&str> = group(&file)
        .messages
        .iter()
        .map(|m| m.body.as_str())
        .collect();
    assert_eq!(bodies, ["decoy by 2", "real by 1"]);
    // The real author's copy again: a duplicate.
    apply(
        &mut file,
        &me,
        &key(2),
        &GroupFrame::Msg(real),
        &none,
        NOW + 2,
    );
    assert_eq!(group(&file).messages.len(), 2);
    // Pushed out of `messages`, both stay known by (author, id).
    let g = &file.groups[0];
    assert!(g.has_seen(&hex::encode(key(1)), &hex::encode(target_id)));
    assert!(g.has_seen(&hex::encode(key(2)), &hex::encode(target_id)));
    assert!(!g.has_seen(&hex::encode(key(4)), &hex::encode(target_id)));
}

/// Security review 2026-10-29 #8: once a message's id had left `messages`
/// and `seen`, the original signed frame was taken again from any carrier
/// and shown as new (sent_ms was never checked). Now a message older than
/// the replay horizon is refused, one dated far ahead too, and a message's
/// key stays in `seen` until the horizon has passed.
#[test]
fn an_old_message_replayed_later_is_refused() {
    let me = key(3);
    let none = HashSet::new();
    let mut file = joined(3, &roster(1, &[2, 3], 1));
    let old = msg_with_id(1, 1, "transfer approved", [0xee; 16], &[]);
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::Msg(old.clone()),
        &none,
        NOW,
    );
    assert_eq!(group(&file).messages.len(), 1);
    // Its message pushed out (as the caps would): its key stays.
    let gone = file.groups[0].messages.remove(0);
    file.groups[0].seen.push(format!(
        "{}@{}",
        store::seen_key(&gone.from, &gone.id),
        gone.sent_ms
    ));
    let within = NOW + store::REPLAY_HORIZON_MS - 1;
    apply(
        &mut file,
        &me,
        &key(2),
        &GroupFrame::Msg(old.clone()),
        &none,
        within,
    );
    assert!(group(&file).messages.is_empty(), "still known: a duplicate");
    // Past the horizon the key may go, and the old message is refused.
    let later = NOW + 30 * 24 * 3_600_000;
    let before = file.dropped;
    apply(&mut file, &me, &key(2), &GroupFrame::Msg(old), &none, later);
    assert!(
        group(&file).messages.is_empty(),
        "an old message is not new"
    );
    assert!(
        group(&file).seen.is_empty(),
        "its key expired with the horizon"
    );
    assert_eq!(file.dropped, before + 1);
    // Dated more than a day ahead: refused.
    let mut ahead = msg_with_id(1, 1, "from the future", [0xef; 16], &[]);
    ahead.sent_ms = NOW + 2 * 24 * 3_600_000;
    ahead.sign(&id(1));
    apply(&mut file, &me, &key(1), &GroupFrame::Msg(ahead), &none, NOW);
    assert!(group(&file).messages.is_empty());
}

/// A group whose `seen` is full of keys still inside the horizon takes no
/// new message (never forget one that could be replayed).
#[test]
fn a_full_seen_list_refuses_new_messages_until_keys_expire() {
    let me = key(3);
    let none = HashSet::new();
    let mut file = joined(3, &roster(1, &[2, 3], 1));
    for i in 0..store::MAX_SEEN_PER_GROUP {
        file.groups[0].seen.push(format!("k{i}@{NOW}"));
    }
    let m = msg_with_id(1, 1, "hello", [0x01; 16], &[]);
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::Msg(m.clone()),
        &none,
        NOW,
    );
    assert!(group(&file).messages.is_empty());
    file.groups[0].seen.truncate(10);
    apply(&mut file, &me, &key(1), &GroupFrame::Msg(m), &none, NOW);
    assert_eq!(group(&file).messages.len(), 1);
}

/// Security review 2026-10-29 #4: one member's forward requests evicted
/// every other pending intent (here the admin's roster answer) from the
/// 512-intent cap, and a dropped copy of an own message left its line
/// "waiting" for ever. Now one author's waiting forwards are bounded, the
/// cap drops forwards first, and a dropped own copy fails its line.
#[test]
fn one_members_forwards_cannot_evict_other_work() {
    let state = roster(1, &[2, 3, 4], 1);
    let mut admin = joined(1, &state);
    let me = key(1);
    let mine = friends(&[2, 3, 4]);
    let sync = GroupFrame::Sync(GroupSync {
        group: state.group,
        epoch: 0,
    });
    apply(&mut admin, &me, &key(2), &sync, &mine, NOW);
    assert_eq!(intents_of(&admin, INTENT_SEND).len(), 1);
    let roster_intent = intents_of(&admin, INTENT_SEND)[0].id.clone();
    for i in 0..store::MAX_INTENTS_PER_GROUP {
        let mut idb = [0u8; 16];
        idb[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
        let m = msg_with_id(3, 1, "x", idb, &[4]);
        apply(&mut admin, &me, &key(3), &GroupFrame::Msg(m), &mine, NOW);
        admin.enforce_caps();
    }
    let g = &admin.groups[0];
    assert!(
        g.intents.iter().any(|i| i.id == roster_intent),
        "the roster answer stays"
    );
    let forwards = g
        .intents
        .iter()
        .filter(|i| i.author == hex::encode(key(3)))
        .count();
    assert_eq!(forwards, store::MAX_FORWARDS_PER_AUTHOR);
    // Over the cap: forwards go first; an own copy that goes fails its line.
    let mut file = joined(1, &state);
    let g = &mut file.groups[0];
    g.messages.push(store::StoredMsg {
        id: "aa".repeat(16),
        from: hex::encode(key(1)),
        epoch: 1,
        sent_ms: NOW,
        received_ms: NOW,
        body: "mine".into(),
        sig: String::new(),
        mine: true,
        via: String::new(),
        lines: vec![store::Line {
            member: hex::encode(key(2)),
            device: String::new(),
            copy: String::new(),
            via: store::VIA_DIRECT.into(),
            state: store::LINE_WAITING.into(),
        }],
        path: String::new(),
    });
    let mut own = send_intent_for_tests(&key(2), NOW);
    own.line_of = "aa".repeat(16);
    g.intents.push(own);
    for _ in 0..store::MAX_INTENTS_PER_GROUP {
        g.intents.push(send_intent_for_tests(&key(3), NOW));
    }
    file.enforce_caps();
    assert_eq!(file.groups[0].intents.len(), store::MAX_INTENTS_PER_GROUP);
    assert_eq!(
        file.groups[0].messages[0].lines[0].state,
        store::LINE_FAILED,
        "the dropped copy's line failed"
    );
}

fn send_intent_for_tests(to: &Key, now_ms: u64) -> store::Intent {
    store::Intent {
        id: store::new_intent_id(),
        kind: INTENT_SEND.into(),
        to: hex::encode(to),
        frame: String::new(),
        of: String::new(),
        via: String::new(),
        line_of: String::new(),
        made_ms: now_ms,
        tries: 0,
        author: String::new(),
    }
}
