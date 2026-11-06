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

/// Clear (0.1.1 chat controls): every message goes and is remembered as
/// seen, so a copy that comes again is a duplicate; my own message still on
/// its way stays unless asked, and then the intent sending it goes too.
#[test]
fn a_cleared_group_keeps_only_my_messages_on_their_way_and_drops_copies() {
    let mut file = joined(2, &roster(1, &[2, 3], 1));
    let stored = |n: u8, mine: bool, state: &str| store::StoredMsg {
        id: format!("{n:032x}"),
        from: hex::encode(key(if mine { 2 } else { 3 })),
        epoch: 1,
        sent_ms: NOW,
        received_ms: NOW,
        body: "b".into(),
        sig: String::new(),
        mine,
        via: String::new(),
        lines: if mine {
            vec![store::Line {
                member: hex::encode(key(3)),
                device: String::new(),
                copy: String::new(),
                via: store::VIA_DIRECT.into(),
                state: state.into(),
            }]
        } else {
            Vec::new()
        },
        path: String::new(),
    };
    let g = &mut file.groups[0];
    g.messages = vec![
        stored(1, false, ""),
        stored(2, true, LINE_DELIVERED),
        stored(3, true, LINE_WAITING),
        stored(4, true, LINE_FAILED),
    ];
    g.intents.push(store::Intent {
        id: "i".into(),
        kind: INTENT_SEND.into(),
        to: hex::encode(key(3)),
        frame: String::new(),
        of: String::new(),
        via: String::new(),
        line_of: format!("{:032x}", 3),
        made_ms: NOW,
        tries: 0,
        author: String::new(),
    });
    let mut all = g.clone();
    assert_eq!(g.clear_messages(false), (3, 1));
    assert_eq!(g.messages.len(), 1);
    assert_eq!(g.messages[0].id, format!("{:032x}", 3));
    assert_eq!(g.intents.len(), 1, "its copy still goes");
    assert!(g.has_seen(&hex::encode(key(3)), &format!("{:032x}", 1)));
    assert!(g.has_seen(&hex::encode(key(2)), &format!("{:032x}", 2)));
    assert_eq!(all.clear_messages(true), (4, 0));
    assert!(all.messages.is_empty() && all.intents.is_empty());
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
    // 2026-10: both on in release builds, where the overrides are never
    // read; a debug build's overrides close either.
    const { assert!(GROUPS_PRODUCTION_ENABLED && crate::horizon::LONG_HORIZON_PRODUCTION_ENABLED) };
    let release = !cfg!(debug_assertions);
    assert_eq!(set(Some(true), Some(false)), release);
    assert_eq!(set(Some(false), Some(true)), release);
    assert!(set(Some(true), Some(true)));
    set(None, None);
}

/// CI sets every lab switch (`RAVEN_LAB_GROUPS`, `RAVEN_LAB_HORIZON`,
/// `RAVEN_LAB_TEST_A`) and runs this in a release build: groups stay on as
/// the consts say (2026-10), whatever the switches and overrides say.
#[test]
fn the_lab_switch_is_inert_without_debug_assertions() {
    if cfg!(debug_assertions) {
        // A debug build: the thread's override decides, else the const and
        // `RAVEN_LAB_GROUPS` ("0" closes), with the horizon.
        set_lab_groups_for_this_thread(Some(false));
        assert!(!group_live_enabled());
        crate::horizon::set_lab_horizon_for_this_thread(Some(true));
        set_lab_groups_for_this_thread(Some(true));
        assert!(group_live_enabled());
        crate::horizon::set_lab_horizon_for_this_thread(Some(false));
        assert!(!group_live_enabled(), "groups need the horizon");
        crate::horizon::set_lab_horizon_for_this_thread(None);
        set_lab_groups_for_this_thread(None);
        let set = std::env::var(LAB_GROUPS).ok();
        assert_eq!(
            group_live_enabled(),
            crate::pair_init::lab_gate_value(
                true,
                GROUPS_PRODUCTION_ENABLED,
                crate::pair_init::lab_test_a_enabled(),
                set.as_deref()
            ) && crate::horizon::horizon_live_enabled()
        );
        return;
    }
    // A release build (2026-10: groups and the horizon on): the overrides and
    // the switch ("0" too) are never read.
    const {
        assert!(GROUPS_PRODUCTION_ENABLED);
    }
    std::env::set_var(LAB_GROUPS, "0");
    set_lab_groups_for_this_thread(Some(false));
    assert!(group_live_enabled());
    set_lab_groups_for_this_thread(None);
    assert!(group_live_enabled());
    std::env::set_var(LAB_GROUPS, "1");
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

/// A group id is bound to its admin ([`group_id_for`]): a member (2) that
/// learned a group's id and sends a friend (3) its own roster for that id
/// first sends one that is not well formed, and the real admin's roster is
/// taken (no other record gets the real members' messages).
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

/// A message is known by (author, id), not by id alone: a member (2) that
/// saw author 1's message first and sends its own message under the same id
/// does not get the real one dropped as a duplicate (and ACKed). Both are
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

/// A message older than the replay horizon is refused, one dated far ahead
/// too, and a message's key stays in `seen` until the horizon has passed:
/// the original signed frame, offered again by any carrier once its id has
/// left `messages`, is never shown as new.
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
    file.groups[0].seen.push(&gone.from, &gone.id, gone.sent_ms);
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
        file.groups[0].seen.push(&format!("k{i}"), "", NOW);
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
    file.groups[0].seen.trim_front(10);
    apply(&mut file, &me, &key(1), &GroupFrame::Msg(m), &none, NOW);
    assert_eq!(group(&file).messages.len(), 1);
}

/// One author's waiting forwards are bounded and the 512-intent cap drops
/// forwards first, so one member's forward requests cannot evict every other
/// pending intent (here the admin's roster answer); a dropped copy of an own
/// message fails its line instead of staying "waiting" for ever.
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

/// Only members are answered: a removed member's sync does not get the
/// current roster (who joined after its removal).
#[test]
fn a_removed_member_gets_no_later_roster() {
    let mut admin = joined(1, &roster(1, &[2, 3], 1));
    let me = key(1);
    let none = HashSet::new();
    let next = roster(1, &[3, 5], 2);
    apply(
        &mut admin,
        &me,
        &key(1),
        &GroupFrame::State(next),
        &none,
        NOW,
    );
    assert!(admin.groups[0].was_removed(&key(2)));
    admin.groups[0].intents.clear();
    let sync = GroupFrame::Sync(GroupSync {
        group: gid(),
        epoch: 1,
    });
    apply(&mut admin, &me, &key(2), &sync, &none, NOW + 1);
    assert!(intents_of(&admin, INTENT_SEND).is_empty());
    // A member is still answered.
    apply(&mut admin, &me, &key(3), &sync, &none, NOW + 2);
    assert_eq!(intents_of(&admin, INTENT_SEND).len(), 1);
}

/// No receipt goes to a non-member: a non-member carrier (9) holding a
/// genuine signed message gets no signed receipt back (no membership
/// oracle).
#[test]
fn no_receipt_goes_to_a_non_member_carrier() {
    let me = key(3);
    let mut file = joined(3, &roster(1, &[2, 3], 1));
    let m = msg(2, 1, "old text", &[]);
    apply(
        &mut file,
        &me,
        &key(9),
        &GroupFrame::Msg(m),
        &HashSet::new(),
        NOW,
    );
    assert!(intents_of(&file, INTENT_RECEIPT).is_empty());
    // From a member that forwarded it: a receipt, through that member.
    let m = msg_with_id(2, 1, "via 1", [0x77; 16], &[]);
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::Msg(m),
        &HashSet::new(),
        NOW,
    );
    let r = intents_of(&file, INTENT_RECEIPT);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].via, hex::encode(key(1)));
}

/// A leave is tied to its epoch: the same frame delivered again after the
/// member was added back does not remove it again (an older leave of a
/// member removed since is refused).
#[test]
fn an_old_leave_after_a_readd_is_refused() {
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
    apply(&mut admin, &key(1), &key(2), &frame, &HashSet::new(), NOW);
    assert_eq!(intents_of(&admin, INTENT_LEAVER).len(), 1);
    super::rules::remove_leaver(&mut admin, &id(1), &state.group, &key(2), NOW);
    admin.groups[0].intents.clear();
    let back = roster(1, &[2, 3], 3);
    apply(
        &mut admin,
        &key(1),
        &key(1),
        &GroupFrame::State(back),
        &HashSet::new(),
        NOW + 1,
    );
    assert!(group(&admin).roster().unwrap().has(&key(2)));
    apply(
        &mut admin,
        &key(1),
        &key(2),
        &frame,
        &HashSet::new(),
        NOW + 2,
    );
    assert!(
        intents_of(&admin, INTENT_LEAVER).is_empty(),
        "the old leave is not acted on again"
    );
}

// ------------------------------------------------------------------ store bytes

/// The largest `msg` frame a friend can send: a body that JSON escapes to
/// twice its size (every byte a quote), the largest numbers and a full relay
/// list. The group store escapes it once more.
fn largest_msg_frame(group: GroupId) -> String {
    let m = GroupMsg {
        group,
        id: [0x5a; 16],
        epoch: u32::MAX,
        from: [0xf0; 32],
        sent_ms: (1 << 53) - 1,
        body: "\"".repeat(MAX_GROUP_BODY_BYTES),
        sig: [0xab; 64],
        relay: (1..MAX_GROUP_MEMBERS as u8).map(|i| [i; 32]).collect(),
    };
    let text = GroupFrame::Msg(m).encode();
    assert!(text.len() <= MAX_GROUP_FRAME_BYTES, "{}", text.len());
    text
}

/// Admin `admin`'s roster for a group of its own salt, signed.
fn roster_salted(admin: u8, members: &[u8], salt: [u8; 16]) -> GroupState {
    let mut s = roster(admin, members, 1);
    s.salt = salt;
    s.group = super::group_id_for(&key(admin), &salt);
    s.sign(&id(admin));
    s
}

/// The largest roster: 16 members, every name and label 64 four byte
/// characters, the largest numbers.
fn largest_roster(admin: Key, me: Key, salt: [u8; 16]) -> GroupState {
    let label = "\u{1d11e}".repeat(MAX_MEMBER_LABEL_CHARS);
    let mut members = vec![
        Member {
            key: admin,
            label: label.clone(),
        },
        Member {
            key: me,
            label: label.clone(),
        },
    ];
    for i in 0..MAX_GROUP_MEMBERS - 2 {
        members.push(Member {
            key: [0x40 + i as u8; 32],
            label: label.clone(),
        });
    }
    GroupState {
        group: super::group_id_for(&admin, &salt),
        salt,
        epoch: u32::MAX,
        name: "\u{1d11e}".repeat(MAX_GROUP_NAME_CHARS),
        admin,
        issued_ms: (1 << 53) - 1,
        members,
        sig: [0xcd; 64],
    }
}

/// A received message as the store keeps it.
fn stored_msg(n: usize, from: &Key, body: &str, received_ms: u64) -> store::StoredMsg {
    store::StoredMsg {
        id: format!("{n:032x}"),
        from: hex::encode(from),
        epoch: 1,
        sent_ms: NOW,
        received_ms,
        body: body.into(),
        sig: String::new(),
        mine: false,
        via: String::new(),
        lines: Vec::new(),
        path: String::new(),
    }
}

/// `file` as the older layout (1) writes it, with `seen` keys as one
/// `<author>/<id>@<sent_ms>` string each for the groups listed.
fn older_layout(file: &GroupsFile, seen: &[(usize, Vec<String>)]) -> serde_json::Value {
    let mut value = serde_json::to_value(file).unwrap();
    value["v"] = serde_json::json!(1);
    for (g, keys) in seen {
        value["groups"][*g]["seen"] = serde_json::json!(keys);
    }
    value
}

/// [`older_layout`] as this build reads it.
fn with_seen(file: &GroupsFile, seen: &[(usize, Vec<String>)]) -> GroupsFile {
    serde_json::from_value(older_layout(file, seen)).unwrap()
}

/// The store `value` as an older build could have left it: its first
/// group's held list (empty in `value`) padded with the largest frames past
/// the at-rest read cap.
fn oversize(value: &serde_json::Value) -> Vec<u8> {
    let held = serde_json::to_string(&store::Held {
        frame: largest_msg_frame([0x77; 16]),
        peer: hex::encode(key(1)),
        at_ms: NOW,
    })
    .unwrap();
    let n = crate::at_rest::MAX_SEALED_FILE_BYTES as usize / held.len() + 1;
    let list = format!("\"held\":[{}]", vec![held.as_str(); n].join(","));
    let text = serde_json::to_string(value)
        .unwrap()
        .replacen("\"held\":[]", &list, 1);
    assert!(text.len() as u64 > crate::at_rest::MAX_SEALED_FILE_BYTES);
    text.into_bytes()
}

/// A lower store budget on this test's thread, while it lives.
struct Budget;

impl Budget {
    fn set(bytes: u64) -> Budget {
        store::set_budget_for_tests(Some(bytes));
        Budget
    }
}

impl Drop for Budget {
    fn drop(&mut self) {
        store::set_budget_for_tests(None);
    }
}

/// What the store at `d` takes on disk, sealed.
fn on_disk(d: &Path) -> u64 {
    let plain = std::fs::metadata(store::groups_path(d)).unwrap().len();
    plain + crate::at_rest::SEALED_OVERHEAD
}

/// The bytes the held frames of `file` take in the store.
fn held_bytes(file: &GroupsFile) -> usize {
    file.unknown_held
        .iter()
        .chain(file.groups.iter().flat_map(|g| g.held.iter()))
        .map(store::Held::stored_bytes)
        .sum()
}

fn sealed_size(file: &GroupsFile) -> u64 {
    serde_json::to_vec_pretty(file).unwrap().len() as u64 + crate::at_rest::SEALED_OVERHEAD
}

/// A store with every count bound full and the largest entries: 64 groups
/// of the largest roster, 64 of the largest held frames each (32 more for
/// groups not known yet), every intent, done marker, answer, removal and
/// copy, 8,192 seen keys a group (the older layout), and more of the
/// largest messages than the count bound.
fn full_store() -> GroupsFile {
    let me = key(3);
    let admin = key(1);
    let mut file = GroupsFile {
        me: hex::encode(me),
        ..GroupsFile::default()
    };
    for g in 0..store::MAX_GROUPS {
        let state = largest_roster(admin, me, [g as u8; 16]);
        file.groups.push(store::GroupRecord::new(&state, NOW));
    }
    let author = "ab".repeat(32);
    let seen: Vec<(usize, Vec<String>)> = (0..store::MAX_GROUPS)
        .map(|g| {
            let keys = (0..store::MAX_SEEN_PER_GROUP)
                .map(|i| format!("{author}/{i:032x}@{NOW}"))
                .collect();
            (g, keys)
        })
        .collect();
    let mut file = with_seen(&file, &seen);
    drop(seen);
    let frame = largest_msg_frame([0x77; 16]);
    let wide = |n: usize| format!("{n:064x}");
    let mut receipt = GroupReceipt {
        group: [0x77; 16],
        of: [0x11; 16],
        epoch: u32::MAX,
        from: key(2),
        to: admin,
        at_ms: (1 << 53) - 1,
        sig: [0xee; 64],
        relay: vec![admin],
    };
    receipt.sign(&id(2));
    let receipt = GroupFrame::Receipt(receipt).encode();
    let line = |n: usize| store::Line {
        member: wide(n),
        device: wide(n + 1),
        copy: format!("{n:032x}"),
        via: store::VIA_DIRECT.into(),
        state: LINE_DELIVERED.into(),
    };
    for (g, rec) in file.groups.iter_mut().enumerate() {
        rec.held = (0..store::MAX_HELD_PER_GROUP)
            .map(|i| store::Held {
                frame: frame.clone(),
                peer: hex::encode(admin),
                at_ms: NOW + i as u64,
            })
            .collect();
        rec.done = (0..store::MAX_DONE_PER_GROUP)
            .map(|i| format!("r:{}/{i:032x}:{}", wide(g), wide(i)))
            .collect();
        rec.intents = (0..store::MAX_INTENTS_PER_GROUP)
            .map(|i| store::Intent {
                id: format!("{i:016x}"),
                kind: INTENT_SEND.into(),
                to: wide(i),
                frame: if i < store::MAX_FORWARDS_PER_AUTHOR {
                    frame.clone()
                } else {
                    receipt.clone()
                },
                of: format!("{i:032x}"),
                via: wide(i + 1),
                line_of: format!("{i:032x}"),
                made_ms: NOW,
                tries: u32::MAX,
                author: if i < store::MAX_FORWARDS_PER_AUTHOR {
                    wide(i + 2)
                } else {
                    String::new()
                },
            })
            .collect();
        rec.answered = (0..MAX_GROUP_MEMBERS * 4)
            .map(|i| store::Answered {
                key: wide(i),
                at_ms: u64::MAX,
            })
            .collect();
        rec.removed = (0..MAX_GROUP_MEMBERS * 8).map(wide).collect();
        // More messages than the count bound, the largest bodies, half of
        // them this profile's own with a line per member.
        for i in 0..store::MAX_MESSAGES_TOTAL / store::MAX_GROUPS + 1 {
            let mut m = stored_msg(i, &admin, &"\"".repeat(MAX_GROUP_BODY_BYTES), NOW);
            m.sig = "ef".repeat(64);
            m.via = wide(i);
            m.path = "keeper".into();
            if i % 2 == 0 {
                m.mine = true;
                m.lines = (0..MAX_GROUP_MEMBERS - 1).map(line).collect();
            }
            rec.messages.push(m);
        }
    }
    file.unknown_held = (0..store::MAX_UNKNOWN_HELD)
        .map(|i| store::Held {
            frame: frame.clone(),
            peer: wide(i),
            at_ms: NOW,
        })
        .collect();
    file.copies = (0..store::MAX_COPIES)
        .map(|i| format!("{i:032x}"))
        .collect();
    file
}

/// G1: every count bound full, the largest frames held everywhere: the
/// store, sealed, still fits the at-rest read cap, so it can always be read
/// back (and sealed again by a key rotation).
#[test]
fn a_store_at_every_count_cap_fits_the_read_cap() {
    let mut file = full_store();
    file.enforce_caps();
    let size = sealed_size(&file);
    assert!(
        size <= crate::at_rest::MAX_SEALED_FILE_BYTES,
        "{size} bytes sealed, over the read cap"
    );
    // By the bounds alone, under the budget (nothing had to be shed).
    assert!(size <= store::STORE_BUDGET_BYTES, "{size} bytes sealed");
    let held = held_bytes(&file);
    assert!(held <= store::MAX_HELD_BYTES_TOTAL, "{held}");
}

/// G1 on disk: the edit that writes a store with every count bound full
/// (as above) leaves a store that reads back within the budget, and the
/// store still takes frames.
#[test]
fn a_store_at_every_count_cap_reads_back_after_the_edit() {
    let dir = profile(3);
    let d = dir.path();
    write_friends(d, &[(1, "Admin")]);
    let full = full_store();
    store::edit(d, move |f| {
        *f = full;
        Ok(())
    })
    .unwrap();
    let file = store::load(d).expect("the store reads back");
    assert_eq!(file.groups.len(), store::MAX_GROUPS);
    assert!(on_disk(d) <= store::STORE_BUDGET_BYTES, "{}", on_disk(d));
    // A message from the admin: its group has no room for another key
    // yet, so it is dropped and counted, and `ingest` is Ok (ACKed).
    let mut m = msg(1, 1, "after the edit", &[]);
    m.group = super::group_id_for(&key(1), &[0; 16]);
    m.sign(&id(1));
    ingest(d, &key(1), &GroupFrame::Msg(m), NOW + 1).unwrap();
    assert_eq!(store::load(d).unwrap().dropped, file.dropped + 1);
}

/// G1 on disk: an edit that would grow the store past the read cap leaves a
/// store that reads back, and frames still go in (so they are ACKed).
#[test]
fn the_store_on_disk_stays_readable_after_any_edit() {
    let dir = profile(3);
    let d = dir.path();
    write_friends(d, &[(1, "Admin")]);
    let frame = largest_msg_frame([0x77; 16]);
    let mut big = GroupsFile::default();
    for g in 0..31u8 {
        let mut rec = store::GroupRecord::new(&roster_salted(1, &[3], [g; 16]), NOW);
        rec.held = (0..store::MAX_HELD_PER_GROUP)
            .map(|i| store::Held {
                frame: frame.clone(),
                peer: hex::encode(key(1)),
                at_ms: NOW + i as u64,
            })
            .collect();
        big.groups.push(rec);
    }
    store::edit(d, |f| {
        *f = big;
        Ok(())
    })
    .unwrap();
    let file = store::load(d).expect("the store reads back");
    assert_eq!(file.groups.len(), 31);
    let size = std::fs::metadata(store::groups_path(d)).unwrap().len();
    assert!(size <= crate::at_rest::MAX_SEALED_FILE_BYTES, "{size}");
    // A roster for one more group goes in.
    ingest(
        d,
        &key(1),
        &GroupFrame::State(roster_salted(1, &[3], [0xf0; 16])),
        NOW,
    )
    .unwrap();
    assert_eq!(store::load(d).unwrap().groups.len(), 32);
}

/// G1 repair: a `groups.json` an older build let grow past the read cap
/// (held frames, the older layout) is read once with a higher cap and
/// repaired: the rosters, the messages, the seen keys and the done markers
/// stay, the held frames are cut to their bounds, it is written back within
/// the budget, and the store works again.
#[test]
fn an_oversize_store_from_an_older_build_is_recovered_once() {
    let dir = profile(3);
    let d = dir.path();
    write_friends(d, &[(1, "Admin")]);
    let mut old = GroupsFile {
        me: hex::encode(key(3)),
        ..GroupsFile::default()
    };
    for g in 0..31u8 {
        let rec = store::GroupRecord::new(&roster_salted(1, &[3], [g; 16]), NOW);
        old.groups.push(rec);
    }
    old.groups[0]
        .messages
        .push(stored_msg(1, &key(1), "still here", NOW));
    old.groups[1].done.push(format!("r:{}", "ab".repeat(80)));
    let author = hex::encode(key(1));
    let seen_id = "11".repeat(16);
    let value = older_layout(&old, &[(0, vec![format!("{author}/{seen_id}@{NOW}")])]);
    std::fs::write(store::groups_path(d), oversize(&value)).unwrap();
    let back = store::load(d).expect("an oversize store is recovered");
    assert_eq!(back.groups.len(), 31);
    for (back, old) in back.groups.iter().zip(&old.groups) {
        assert_eq!(back.roster(), old.roster());
        assert_eq!(back.status, old.status);
    }
    assert_eq!(back.groups[0].messages, old.groups[0].messages);
    assert!(back.groups[0].has_seen(&author, &seen_id));
    assert_eq!(back.groups[1].done, old.groups[1].done);
    let held = held_bytes(&back);
    assert!(
        !back.groups[0].held.is_empty(),
        "the newest held frames stay"
    );
    assert!(held <= store::MAX_HELD_BYTES_PER_GROUP, "{held}");
    assert!(on_disk(d) <= store::STORE_BUDGET_BYTES, "{}", on_disk(d));
    // Once: the store on disk is the repaired one.
    assert_eq!(store::load(d).unwrap(), back);
    // The store works as before: a message from the admin goes in.
    let mut m = msg(1, 1, "after the repair", &[]);
    m.group = old.groups[0].roster().unwrap().group;
    m.sign(&id(1));
    ingest(d, &key(1), &GroupFrame::Msg(m), NOW + 1).unwrap();
    assert_eq!(store::load(d).unwrap().groups[0].messages.len(), 2);
}

/// G1 repair within the budget: when the rosters, messages and seen keys
/// alone are over it, the oldest messages go (their keys stay seen); no
/// roster and no seen key goes.
#[test]
fn a_repair_sheds_the_oldest_messages_last_and_keeps_rosters_and_seen_keys() {
    let dir = profile(3);
    let d = dir.path();
    let mut old = GroupsFile {
        me: hex::encode(key(3)),
        ..GroupsFile::default()
    };
    for g in 0..4u8 {
        let rec = store::GroupRecord::new(&roster_salted(1, &[3], [g; 16]), NOW);
        old.groups.push(rec);
    }
    let body = "m".repeat(2_000);
    for i in 0..400 {
        let m = stored_msg(i, &key(1), &body, NOW + i as u64);
        old.groups[i % 4].messages.push(m);
    }
    let author = hex::encode(key(1));
    let seen_id = "11".repeat(16);
    let value = older_layout(&old, &[(0, vec![format!("{author}/{seen_id}@{NOW}")])]);
    std::fs::write(store::groups_path(d), oversize(&value)).unwrap();
    let budget = 256 * 1024;
    let back = {
        let _budget = Budget::set(budget);
        store::load(d).expect("repaired")
    };
    assert!(on_disk(d) <= budget, "{}", on_disk(d));
    assert_eq!(held_bytes(&back), 0, "held frames go before history");
    assert_eq!(back.groups.len(), 4);
    for (back, old) in back.groups.iter().zip(&old.groups) {
        assert_eq!(back.roster(), old.roster());
    }
    assert!(back.groups[0].has_seen(&author, &seen_id));
    let kept: usize = back.groups.iter().map(|g| g.messages.len()).sum();
    assert!(kept > 0 && kept < 400, "{kept}");
    // The oldest went, and each is still known (a copy again is a duplicate).
    for (i, g) in back.groups.iter().enumerate() {
        assert!(g.has_seen(&author, &format!("{i:032x}")));
        let newest = format!("{:032x}", 396 + i);
        assert_eq!(
            g.messages.last().map(|m| m.id.as_str()),
            Some(newest.as_str())
        );
    }
}

/// G1: a frame is held (author not in the roster yet, or the group not
/// known yet) only when its author's signature verifies.
#[test]
fn a_frame_is_held_only_with_its_authors_signature() {
    let me = key(2);
    let none = HashSet::new();
    let mut file = joined(2, &roster(1, &[2, 3], 1));
    let mut forged = msg(4, 2, "signed by 4", &[]);
    forged.body = "changed by the carrier".into();
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::Msg(forged),
        &none,
        NOW,
    );
    assert!(group(&file).held.is_empty(), "{:?}", group(&file).held);
    assert_eq!(file.dropped, 1);
    apply(
        &mut file,
        &me,
        &key(1),
        &GroupFrame::Msg(msg(4, 2, "signed by 4", &[])),
        &none,
        NOW,
    );
    assert_eq!(group(&file).held.len(), 1);
    // A group not known yet: the same.
    let mut fresh = GroupsFile::default();
    let mut forged = msg(3, 1, "early", &[]);
    forged.body = "changed".into();
    apply(
        &mut fresh,
        &me,
        &key(3),
        &GroupFrame::Msg(forged),
        &none,
        NOW,
    );
    assert!(fresh.unknown_held.is_empty());
    apply(
        &mut fresh,
        &me,
        &key(3),
        &GroupFrame::Msg(msg(3, 1, "early", &[])),
        &none,
        NOW,
    );
    assert_eq!(fresh.unknown_held.len(), 1);
}

/// G1: one carrier filling a group's held frames (the largest frames, as
/// many as the bounds take) does not push out a frame another carrier
/// brought earlier.
#[test]
fn one_carriers_held_frames_cannot_push_out_anothers() {
    let mut file = joined(2, &roster(1, &[2, 3], 1));
    let early = GroupFrame::Msg(msg(4, 2, "from a new member", &[])).encode();
    file.groups[0].held.push(store::Held {
        frame: early.clone(),
        peer: hex::encode(key(3)),
        at_ms: NOW,
    });
    let big = largest_msg_frame(gid());
    for i in 0..store::MAX_HELD_PER_GROUP {
        file.groups[0].held.push(store::Held {
            frame: big.clone(),
            peer: hex::encode(key(9)),
            at_ms: NOW + 1 + i as u64,
        });
    }
    // And for groups not known yet.
    file.unknown_held.push(store::Held {
        frame: early.clone(),
        peer: hex::encode(key(3)),
        at_ms: NOW,
    });
    for i in 0..store::MAX_UNKNOWN_HELD {
        file.unknown_held.push(store::Held {
            frame: big.clone(),
            peer: hex::encode(key(9)),
            at_ms: NOW + 1 + i as u64,
        });
    }
    file.enforce_caps();
    let kept = |list: &[store::Held]| list.iter().any(|h| h.frame == early);
    assert!(
        kept(&file.groups[0].held),
        "the other carrier's frame stays"
    );
    assert!(kept(&file.unknown_held), "the other carrier's frame stays");
}

/// G3: one admin's groups (here 30 of them, full of the largest messages)
/// do not push most of another admin's group's history out.
#[test]
fn one_admins_groups_cannot_push_out_another_groups_history() {
    let mut file = GroupsFile::default();
    let mut ours = store::GroupRecord::new(&roster_salted(2, &[3], [0xa0; 16]), NOW);
    for i in 0..1_500 {
        ours.messages
            .push(stored_msg(i, &key(2), "ok", NOW + i as u64));
    }
    file.groups.push(ours);
    let large = "x".repeat(MAX_GROUP_BODY_BYTES);
    for g in 0..30u8 {
        let mut rec = store::GroupRecord::new(&roster_salted(1, &[3], [g; 16]), NOW);
        for i in 0..33 {
            rec.messages
                .push(stored_msg(i, &key(1), &large, NOW + 2_000 + i as u64));
        }
        file.groups.push(rec);
    }
    file.enforce_caps();
    let kept = file.groups[0].messages.len();
    assert!(kept >= 1_000, "group kept {kept} of 1500");
    let total: usize = file.groups.iter().map(|g| g.messages.len()).sum();
    assert!(total <= store::MAX_MESSAGES_TOTAL);
}

/// G3 by count: one admin's 63 groups of 32 short messages each do not cut
/// another admin's group down to their size.
#[test]
fn one_admins_many_groups_cannot_cut_another_groups_history_by_count() {
    let mut file = GroupsFile::default();
    let mut ours = store::GroupRecord::new(&roster_salted(2, &[3], [0xa0; 16]), NOW);
    for i in 0..1_000 {
        ours.messages
            .push(stored_msg(i, &key(2), "ok", NOW + i as u64));
    }
    file.groups.push(ours);
    for g in 0..63u8 {
        let mut rec = store::GroupRecord::new(&roster_salted(1, &[3], [g; 16]), NOW);
        for i in 0..32 {
            rec.messages
                .push(stored_msg(i, &key(1), "spam", NOW + 2_000 + i as u64));
        }
        file.groups.push(rec);
    }
    file.enforce_caps();
    let kept = file.groups[0].messages.len();
    assert!(kept >= 900, "group kept {kept} of 1000");
}

/// G1: seen keys take a few bytes each when written, and keys in the older
/// layout (`<author>/<id>@<sent_ms>`, one string each) are read.
#[test]
fn seen_keys_are_written_compactly_and_read_from_the_older_layout() {
    let file = joined(3, &roster(1, &[2, 3], 1));
    let base = serde_json::to_vec_pretty(&file).unwrap().len();
    let from = hex::encode(key(2));
    let keys: Vec<String> = (0..store::MAX_SEEN_PER_GROUP)
        .map(|i| format!("{from}/{i:032x}@{NOW}"))
        .collect();
    let file = with_seen(&file, &[(0, keys)]);
    let g = &file.groups[0];
    assert!(g.has_seen(&from, &format!("{:032x}", 0)));
    assert!(g.has_seen(&from, &format!("{:032x}", store::MAX_SEEN_PER_GROUP - 1)));
    assert!(!g.has_seen(&from, &format!("{:032x}", store::MAX_SEEN_PER_GROUP)));
    assert!(!g.has_seen(&hex::encode(key(4)), &format!("{:032x}", 0)));
    assert!(g.seen_full());
    let bytes = serde_json::to_vec_pretty(&file).unwrap();
    let per_key = (bytes.len() - base) / store::MAX_SEEN_PER_GROUP;
    assert!(per_key <= 24, "{per_key} bytes per seen key");
    let back: GroupsFile = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back, file);
    assert!(back.groups[0].has_seen(&from, &format!("{:032x}", 7)));
}

/// G1 budget: a change that would leave the store over its budget after
/// held frames, done markers and intents were shed is refused, and the
/// store stays as it was: a received frame is dropped and counted (and
/// ACKed: `ingest` is `Ok`), a local send fails with `GROUP_STORE`.
#[test]
fn a_full_store_drops_a_received_message_and_refuses_a_local_send() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _lab = Lab::on();
    let dir = profile(3);
    let d = dir.path();
    write_friends(d, &[(1, "Admin")]);
    ingest(d, &key(1), &GroupFrame::State(roster(1, &[3], 1)), NOW).unwrap();
    let budget = on_disk(d) + 2_048;
    let _budget = Budget::set(budget);
    let big = "x".repeat(MAX_GROUP_BODY_BYTES);
    let before = store::load(d).unwrap();
    ingest(d, &key(1), &GroupFrame::Msg(msg(1, 1, &big, &[])), NOW).unwrap();
    let after = store::load(d).unwrap();
    assert!(after.groups[0].messages.is_empty());
    assert_eq!(after.dropped, before.dropped + 1);
    let err = send(d, &id(3), &gid(), &big, NOW).unwrap_err();
    assert_eq!(err.code(), "GROUP_STORE", "{err:?}");
    assert_eq!(store::load(d).unwrap(), after, "nothing written");
    // What fits still goes in.
    let mut short = msg(1, 1, "short", &[]);
    short.id = [9; 16];
    short.sign(&id(1));
    ingest(d, &key(1), &GroupFrame::Msg(short), NOW).unwrap();
    assert_eq!(store::load(d).unwrap().groups[0].messages.len(), 1);
    assert!(on_disk(d) <= budget, "{}", on_disk(d));
}

/// G1 budget: held frames give way before a message is refused.
#[test]
fn held_frames_give_way_before_a_message_is_refused() {
    let dir = profile(3);
    let d = dir.path();
    write_friends(d, &[(1, "Admin")]);
    ingest(d, &key(1), &GroupFrame::State(roster(1, &[3], 1)), NOW).unwrap();
    // A message from an author only a newer roster names: held.
    let early = msg(4, 2, &"y".repeat(4_000), &[]);
    ingest(d, &key(1), &GroupFrame::Msg(early), NOW).unwrap();
    assert_eq!(store::load(d).unwrap().groups[0].held.len(), 1);
    let _budget = Budget::set(on_disk(d) + 1_024);
    let later = msg(1, 1, &"z".repeat(3_000), &[]);
    ingest(d, &key(1), &GroupFrame::Msg(later), NOW).unwrap();
    let after = store::load(d).unwrap();
    assert_eq!(after.groups[0].messages.len(), 1, "the message went in");
    assert!(after.groups[0].held.is_empty(), "the held frame gave way");
    assert_eq!(after.dropped, 0);
}

/// How many bytes `change` adds to the store `base` as written.
fn grown(base: &GroupsFile, change: impl FnOnce(&mut GroupsFile)) -> usize {
    let size = |f: &GroupsFile| serde_json::to_vec_pretty(f).unwrap().len();
    let mut file = base.clone();
    change(&mut file);
    size(&file) - size(base)
}

/// The byte measures the bounds use are upper bounds of what entries take
/// in the store as written (every escape, the widest numbers, a list of
/// one), so the bounds hold for the file itself.
#[test]
fn the_byte_measures_bound_what_entries_take_in_the_file() {
    let base = joined(3, &roster(1, &[2, 3], 1));
    let odd = "\"\\\n\u{1}\u{1f}\u{e9}\u{1d11e}x".repeat(40);
    let wide = |n: usize| format!("{n:064x}");
    let mut m = stored_msg(1, &key(1), &odd, u64::MAX);
    m.epoch = u32::MAX;
    m.sent_ms = u64::MAX;
    m.sig = "ef".repeat(64);
    m.via = odd.clone();
    m.path = odd.clone();
    m.lines = (0..MAX_GROUP_MEMBERS - 1)
        .map(|n| store::Line {
            member: wide(n),
            device: odd.clone(),
            copy: odd.clone(),
            via: store::VIA_RELAY.into(),
            state: LINE_DELIVERED.into(),
        })
        .collect();
    let mut one_line = m.clone();
    one_line.lines.truncate(1);
    let plain = stored_msg(2, &key(1), "", 0);
    for list in [
        vec![m.clone()],
        vec![one_line],
        vec![plain.clone()],
        vec![m, plain],
    ] {
        let measured: usize = list.iter().map(store::StoredMsg::stored_bytes).sum();
        let added = grown(&base, |f| f.groups[0].messages = list);
        assert!(added <= measured, "messages: {added} over {measured}");
    }
    let held = store::Held {
        frame: odd.clone(),
        peer: odd.clone(),
        at_ms: u64::MAX,
    };
    let bare_held = store::Held {
        frame: String::new(),
        peer: String::new(),
        at_ms: 0,
    };
    for list in [
        vec![held.clone()],
        vec![bare_held.clone()],
        vec![held.clone(), bare_held],
    ] {
        let measured: usize = list.iter().map(store::Held::stored_bytes).sum();
        let added = grown(&base, |f| f.groups[0].held = list.clone());
        assert!(added <= measured, "held: {added} over {measured}");
        let added = grown(&base, |f| f.unknown_held = list);
        assert!(added <= measured, "unknown held: {added} over {measured}");
    }
    let intent = store::Intent {
        id: odd.clone(),
        kind: odd.clone(),
        to: odd.clone(),
        frame: odd.clone(),
        of: odd.clone(),
        via: odd.clone(),
        line_of: odd.clone(),
        made_ms: u64::MAX,
        tries: u32::MAX,
        author: odd.clone(),
    };
    let bare = store::Intent {
        id: String::new(),
        kind: String::new(),
        to: String::new(),
        frame: String::new(),
        of: String::new(),
        via: String::new(),
        line_of: String::new(),
        made_ms: 0,
        tries: 0,
        author: String::new(),
    };
    for list in [vec![intent.clone()], vec![bare.clone()], vec![intent, bare]] {
        let measured: usize = list.iter().map(store::Intent::stored_bytes).sum();
        let added = grown(&base, |f| f.groups[0].intents = list);
        assert!(added <= measured, "intents: {added} over {measured}");
    }
    for list in [
        vec![odd.clone()],
        vec![String::new()],
        vec![odd, String::new()],
    ] {
        let measured: usize = list.iter().map(|d| store::mark_bytes(d)).sum();
        let added = grown(&base, |f| f.groups[0].done = list);
        assert!(added <= measured, "done: {added} over {measured}");
    }
}

/// G1 layout: a store of the older layout on disk is read as it is, and
/// its next edit writes layout 2 (seen keys compact) with every key kept.
/// `seen` stays a list of strings, so an older build still reads the file.
#[test]
fn an_older_store_on_disk_is_converted_on_its_next_edit() {
    let dir = profile(3);
    let d = dir.path();
    write_friends(d, &[(1, "Admin")]);
    let file = joined(3, &roster(1, &[3], 1));
    let author = hex::encode(key(1));
    let keys: Vec<String> = (0..300)
        .map(|i| format!("{author}/{i:032x}@{NOW}"))
        .collect();
    let value = older_layout(&file, &[(0, keys)]);
    let text = serde_json::to_vec_pretty(&value).unwrap();
    std::fs::write(store::groups_path(d), &text).unwrap();
    let read = store::load(d).unwrap();
    assert!(read.groups[0].has_seen(&author, &format!("{:032x}", 299)));
    assert_eq!(
        std::fs::read(store::groups_path(d)).unwrap(),
        text,
        "a read writes nothing"
    );
    // A copy of a key seen in the older layout is still a duplicate.
    let mut again = msg(1, 1, "again", &[]);
    again.id = [0; 16];
    again.id[15] = 7;
    again.sign(&id(1));
    ingest(d, &key(1), &GroupFrame::Msg(again), NOW).unwrap();
    assert!(store::load(d).unwrap().groups[0].messages.is_empty());
    // An edit converts it.
    ingest(d, &key(1), &GroupFrame::Msg(msg(1, 1, "hi", &[])), NOW).unwrap();
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(store::groups_path(d)).unwrap()).unwrap();
    assert_eq!(raw["v"], serde_json::json!(store::STORE_VERSION));
    let older: Vec<String> = serde_json::from_value(raw["groups"][0]["seen"].clone()).unwrap();
    assert_eq!(older.len(), 2, "300 keys in two strings");
    assert!(older.iter().all(|s| s.starts_with("v2:")));
    let back = store::load(d).unwrap();
    assert_eq!(back.groups[0].messages.len(), 1);
    assert_eq!(back.groups[0].seen.len(), 300);
    for i in [0, 7, 299] {
        assert!(back.groups[0].has_seen(&author, &format!("{i:032x}")));
    }
}

/// G1 repair in a sealed profile: an RMS1 store past the read cap is opened
/// with the loaded keys, repaired and written back sealed within the budget.
#[test]
fn an_oversize_sealed_store_is_recovered_sealed() {
    use crate::at_rest::Kind;
    let dir = crate::contact_book::tests::profile();
    let d = dir.path();
    crate::contact_book::tests::seal(d);
    let mut old = GroupsFile::default();
    for g in 0..4u8 {
        let rec = store::GroupRecord::new(&roster_salted(1, &[3], [g; 16]), NOW);
        old.groups.push(rec);
    }
    old.groups[0]
        .messages
        .push(stored_msg(1, &key(1), "still here", NOW));
    let plain = oversize(&older_layout(&old, &[]));
    let keys = crate::at_rest::keys_cached(d).unwrap();
    let sealed = crate::at_rest::seal(&keys, Kind::Groups, &plain);
    drop(plain);
    std::fs::write(store::groups_path(d), &sealed).unwrap();
    drop(sealed);
    let back = store::load(d).expect("an oversize sealed store is recovered");
    assert_eq!(back.groups.len(), 4);
    assert_eq!(back.groups[0].messages, old.groups[0].messages);
    let held = held_bytes(&back);
    assert!(held <= store::MAX_HELD_BYTES_PER_GROUP, "{held}");
    let raw = std::fs::read(store::groups_path(d)).unwrap();
    assert!(
        crate::at_rest::is_sealed_as(Kind::Groups, &raw),
        "written back sealed"
    );
    assert!(
        raw.len() as u64 <= store::STORE_BUDGET_BYTES,
        "{}",
        raw.len()
    );
    assert_eq!(store::load(d).unwrap(), back);
}
