//! The chat controls (0.1.1): block, remove verification, clear history,
//! delete a chat and pin one, through the engine API. Everything is local to
//! this device. The first test needs no raven-node; the second sends between
//! two real raven-node processes on 127.0.0.1 (without them it says so and
//! passes).

mod common;

use std::time::{Duration, Instant};

use common::net::{binaries_ready, Peer};
use serde_json::{json, Value};

fn contact_of(p: &Peer, friend: &Peer) -> Value {
    let list = p.ok("contacts.list", json!({}));
    list["contacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["address"] == friend.address().as_str())
        .cloned()
        .unwrap_or_else(|| panic!("{} not in {list}", friend.name))
}

fn chats(p: &Peer) -> Vec<Value> {
    p.ok("chats.list", json!({}))["chats"]
        .as_array()
        .unwrap()
        .clone()
}

/// Every op on a saved friend: the shapes API.md promises, the block list
/// and the pin as the CLI reads them, and the errors.
#[test]
fn block_unverify_pin_and_delete_change_only_this_device() {
    let a = Peer::new("Ctl A");
    let b = Peer::new("Ctl B");
    let c = Peer::new("Ctl C");
    a.befriend(&b, None);
    a.befriend(&c, None);
    let bob = json!({"address": b.address()});

    // Block: the contact stays, blocked; the CLI's block list has the key.
    let blocked = a.ok("contacts.block", bob.clone());
    assert_eq!(blocked["contact"]["blocked"], true, "{blocked}");
    assert_eq!(blocked["contact"]["verified"], true, "{blocked}");
    assert_eq!(contact_of(&a, &b)["blocked"], true);
    let key = ash_engine::engine::contact_views(&a.path)
        .unwrap()
        .into_iter()
        .find(|v| v.address == b.address())
        .unwrap()
        .pub_hex
        .to_ascii_lowercase();
    assert!(raven_core::BlockList::load_checked(&a.path)
        .unwrap()
        .is_blocked(&key));
    let unblocked = a.ok("contacts.unblock", bob.clone());
    assert_eq!(unblocked["contact"]["blocked"], false, "{unblocked}");
    assert!(!raven_core::BlockList::load_checked(&a.path)
        .unwrap()
        .is_blocked(&key));

    // Remove verification: still a contact, not verified; the words again
    // verify it.
    let unverified = a.ok("contacts.unverify", bob.clone());
    assert_eq!(unverified["contact"]["verified"], false, "{unverified}");
    assert_eq!(contact_of(&a, &b)["verified"], false);
    let checked = a.ok(
        "verify.check_words",
        json!({"address": b.address(), "words": b.me["words"]}),
    );
    assert_eq!(checked["result"], "match", "{checked}");
    assert_eq!(contact_of(&a, &b)["verified"], true);

    // Pin: first in the chat list, on the contact too.
    let pinned = a.ok("chats.pin", json!({"address": c.address(), "pinned": true}));
    assert_eq!(pinned["pinned"], true);
    let list = chats(&a);
    assert_eq!(list.len(), 2, "{list:?}");
    assert_eq!(list[0]["address"], c.address().as_str(), "{list:?}");
    assert_eq!(list[0]["kind"], "contact");
    assert_eq!(list[0]["pinned"], true);
    assert_eq!(list[1]["pinned"], false);
    assert_eq!(contact_of(&a, &c)["pinned"], true);
    assert!(a
        .path
        .join(raven_core::chat_prefs::CHAT_PREFS_FILE)
        .exists());

    // Delete chat: cleared, out of the chat list, the contact stays.
    let deleted = a.ok("chats.delete", bob.clone());
    assert_eq!(deleted["deleted"], true, "{deleted}");
    assert_eq!(deleted["cleared"], 0, "{deleted}");
    let list = chats(&a);
    assert_eq!(list.len(), 1, "{list:?}");
    assert_eq!(list[0]["address"], c.address().as_str());
    assert_eq!(contact_of(&a, &b)["hidden"], true);
    let cleared = a.ok("messages.clear", bob.clone());
    assert_eq!(cleared, json!({"cleared": 0, "pending_kept": 0}));

    // Unpinned again: nothing left, the file goes.
    a.ok(
        "chats.pin",
        json!({"address": c.address(), "pinned": false}),
    );
    raven_core::chat_prefs::forget(&a.path, &raven_core::chat_prefs::contact_chat(&key)).unwrap();
    assert!(!a
        .path
        .join(raven_core::chat_prefs::CHAT_PREFS_FILE)
        .exists());

    // Errors: one chat, a known one, `pinned` given.
    for (op, args) in [
        ("chats.pin", json!({"address": b.address()})),
        ("chats.pin", json!({"pinned": true})),
        (
            "chats.delete",
            json!({"address": b.address(), "group": "00".repeat(16)}),
        ),
        ("groups.clear", json!({"group": "nothex"})),
    ] {
        let why = a.err(op, args.clone());
        assert_eq!(why, "BAD_REQUEST", "{op} {args}");
    }
    let stranger = Peer::new("Ctl D");
    let why = a.err("contacts.block", json!({"address": stranger.address()}));
    assert_eq!(why, "NOT_A_CONTACT");
}

/// A blocked friend's message never reaches the inbox: raven-node refuses
/// its link, so it stays undelivered at the sender. Clearing then empties
/// the chat; what came before the block goes with it.
#[test]
fn a_blocked_friends_message_never_arrives_and_clear_empties_the_chat() {
    if !binaries_ready() {
        return;
    }
    let a = Peer::new("Blk A");
    let b = Peer::new("Blk B");
    a.befriend(&b, None);
    b.befriend(&a, None);
    let (la, lb) = (a.start(), b.start());
    a.set_lan(&b, &lb);
    b.set_lan(&a, &la);

    let before = b.send_until(
        &a,
        "before-block",
        &["delivered", "failed"],
        Duration::from_secs(90),
    );
    assert_eq!(before["state"], "delivered", "{before}");
    assert!(a.wait_incoming(&b, "before-block", Duration::from_secs(30)));

    a.ok("contacts.block", json!({"address": b.address()}));
    let after = b.send_until(
        &a,
        "after-block",
        &[
            "delivered",
            "waiting",
            "sent",
            "failed",
            "not_sent_meet_first",
        ],
        Duration::from_secs(90),
    );
    assert_ne!(after["state"], "delivered", "{after}");
    // Some time for a late copy: none may come.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        assert!(
            !a.wait_incoming(&b, "after-block", Duration::from_millis(500)),
            "a blocked friend's message arrived ({})",
            a.service_log()
        );
    }

    let cleared = a.ok("messages.clear", json!({"address": b.address()}));
    assert!(cleared["cleared"].as_u64().unwrap() >= 1, "{cleared}");
    let history = a.ok(
        "messages.history",
        json!({"address": b.address(), "limit": 50}),
    );
    assert!(
        history["messages"].as_array().unwrap().is_empty(),
        "{history}"
    );
}
