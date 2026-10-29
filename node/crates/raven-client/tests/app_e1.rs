//! What the desktop apps needed after the three-machine test's E1 feedback:
//! a friend whose messages are in the chat is in touch, a message another
//! program on the same profile sent shows up in the open chat at once (an
//! `outgoing` event), an ended message can be deleted for good, and Check
//! network speaks plain words with the commands kept apart.
//!
//! No raven-node is needed: the history rows are written as raven-node or
//! the terminal app would write them.

mod common;

use std::path::Path;
use std::time::Duration;

use common::net::Peer;
use raven_core::chat_history::{ChatHistory, ChatHistoryEntry};
use serde_json::{json, Value};

/// The friend's key, as the profile in `dir` saved it.
fn key_hex(dir: &Path, address: &str) -> String {
    ash_engine::engine::contact_views(dir)
        .expect("contacts")
        .into_iter()
        .find(|c| c.address == address)
        .expect("a saved friend")
        .pub_hex
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Writes one history row, as raven-node (incoming) or another program
/// (outgoing) does.
fn write_row(dir: &Path, friend: &str, mid: &str, direction: &str, body: &str, delivery: &str) {
    ChatHistory::append_persisted(
        dir,
        ChatHistoryEntry {
            message_id_hex: mid.into(),
            direction: direction.into(),
            peer_petname: String::new(),
            peer_tag: String::new(),
            peer_pub_hex: key_hex(dir, friend),
            created_at_ms: now_ms(),
            delivery: delivery.into(),
            preview: body.into(),
            body: body.into(),
            stored_at_ms: None,
        },
    )
    .expect("history row written");
}

fn contact<'a>(list: &'a Value, address: &str) -> &'a Value {
    list["contacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["address"] == address)
        .expect("the friend is listed")
}

fn texts(history: &Value) -> Vec<String> {
    history["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["text"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn a_friend_whose_messages_are_in_the_chat_is_in_touch() {
    let a = Peer::new("a");
    let b = Peer::new("b");
    a.befriend(&b, None);
    a.set_lan(&b, "127.0.0.1:9");
    let before = a.ok("contacts.list", json!({}));
    assert_eq!(contact(&before, &b.address())["presence"], "none");
    // A message that came before this engine's first look.
    write_row(
        &a.path,
        &b.address(),
        &"11".repeat(16),
        "in",
        "hello from b",
        "delivered",
    );
    let after = a.ok("contacts.list", json!({}));
    let c = contact(&after, &b.address());
    assert_eq!(c["presence"], "in_touch", "{c}");
    assert!(
        c["last_contact_ms"].as_u64().is_some_and(|ms| ms > 0),
        "{c}"
    );
}

#[test]
fn a_message_sent_by_another_program_shows_up_with_an_event() {
    let a = Peer::new("a");
    let b = Peer::new("b");
    a.befriend(&b, None);
    a.set_lan(&b, "127.0.0.1:9");
    let mut after = 0;
    // The engine's first look only notes what is there.
    common::events_until(&a.client, &mut after, Duration::from_millis(1500), |_| {
        false
    });
    write_row(
        &a.path,
        &b.address(),
        &"22".repeat(16),
        "out",
        "sent from the terminal",
        "sent",
    );
    let seen = common::events_until(&a.client, &mut after, Duration::from_secs(10), |evs| {
        evs.iter().any(|e| e["kind"] == "outgoing")
    });
    let out = seen
        .iter()
        .find(|e| e["kind"] == "outgoing")
        .unwrap_or_else(|| panic!("no outgoing event: {seen:?}"));
    assert_eq!(out["message"]["text"], "sent from the terminal");
    assert_eq!(out["message"]["direction"], "out");
    assert_eq!(out["message"]["address"], b.address());
    let history = a.ok("messages.history", json!({"address": b.address()}));
    assert!(texts(&history).contains(&"sent from the terminal".to_owned()));
}

#[test]
fn an_ended_message_can_be_deleted_for_good() {
    let a = Peer::new("a");
    let b = Peer::new("b");
    a.befriend(&b, None);
    let failed = "33".repeat(16);
    write_row(
        &a.path,
        &b.address(),
        &failed,
        "out",
        "never went",
        "failed",
    );
    write_row(
        &a.path,
        &b.address(),
        &"44".repeat(16),
        "in",
        "an answer",
        "delivered",
    );
    let history = a.ok("messages.history", json!({"address": b.address()}));
    assert_eq!(texts(&history), ["never went", "an answer"]);
    // An incoming message is not one to delete.
    assert_eq!(
        a.err("messages.delete", json!({"id": "44".repeat(16)})),
        "BAD_REQUEST"
    );
    let done = a.ok("messages.delete", json!({"id": failed}));
    assert_eq!(done["deleted"], true);
    let history = a.ok("messages.history", json!({"address": b.address()}));
    assert_eq!(texts(&history), ["an answer"]);
    // It stays deleted for the next engine on this profile.
    let again = raven_client::Client::with_data_dir(&a.path);
    let history = common::ok(&again, "messages.history", json!({"address": b.address()}));
    assert_eq!(texts(&history), ["an answer"]);
}

#[test]
fn check_network_speaks_plain_words() {
    let a = Peer::new("a");
    let b = Peer::new("b");
    a.befriend(&b, None);
    let check = a.ok("network.check", json!({}));
    let step = check["next_step"].as_str().unwrap();
    assert!(!step.is_empty(), "{check}");
    for shown in [step.to_owned(), common::all_text(&check["summary"])] {
        for command in ["`", "ash ", "raven ", "Ctrl-Z"] {
            assert!(!shown.contains(command), "{command:?} in {shown:?}");
        }
    }
    // The next step is said once, not again in the summary.
    assert!(check["summary"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["key"] != "next_step"));
    // The CLI's own words stay under Technical details.
    assert!(
        check["technical"].as_array().is_some_and(|t| !t.is_empty()),
        "{check}"
    );
}
