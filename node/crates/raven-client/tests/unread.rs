//! Read and unread, shared with the terminal app (E1 round two: the terminal
//! app showed six unread messages the desktop app had read). Both apps keep
//! one read marker per friend in the profile (ash's tui/read_marks.rs):
//! `Contact.unread` counts the friend's messages after it, wherever they were
//! read, `messages.mark_read` moves it (never back), and an `unread` event
//! follows a change made by the terminal app.
//!
//! No raven-node is needed: the history rows are written as raven-node
//! writes them, and the terminal app's marker as it saves it.

mod common;

use std::path::Path;
use std::time::Duration;

use common::net::Peer;
use raven_client::Client;
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

/// Writes one history row with the friend at `address`, made at `at_ms`.
fn write_row(dir: &Path, address: &str, mid: &str, direction: &str, at_ms: u64) {
    ChatHistory::append_persisted(
        dir,
        ChatHistoryEntry {
            message_id_hex: mid.into(),
            direction: direction.into(),
            peer_petname: String::new(),
            peer_tag: String::new(),
            peer_pub_hex: key_hex(dir, address),
            created_at_ms: at_ms,
            delivery: "delivered".into(),
            preview: format!("message {mid}"),
            body: format!("message {mid}"),
            stored_at_ms: None,
        },
    )
    .expect("history row written");
}

fn unread_of(client: &Client, address: &str) -> u64 {
    let list = common::ok(client, "contacts.list", json!({}));
    list["contacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["address"] == address)
        .expect("the friend is listed")["unread"]
        .as_u64()
        .expect("a count")
}

/// tui_state.json as the terminal app saves it after reading the friend
/// `key` up to `mid`: `with_time` false is an older app's file (an id only).
fn terminal_app_read(dir: &Path, key: &str, mid: &str, at_ms: u64, with_time: bool) {
    let mut state = json!({"version": 1, "motion": "reduced", "last_read": {key: mid}});
    if with_time {
        state["last_read_at"] = json!({key: {"id": mid, "at_ms": at_ms}});
    }
    let text = serde_json::to_vec_pretty(&state).unwrap();
    raven_core::atomic_write_private(&dir.join("tui_state.json"), &text).expect("written");
}

fn mid(n: u8) -> String {
    format!("{n:02x}").repeat(16)
}

/// Bob's friend Alice, with four messages from her and one of his between.
fn alice_wrote() -> (Peer, Peer) {
    let bob = Peer::new("b");
    let alice = Peer::new("a");
    bob.befriend(&alice, None);
    let at = alice.address();
    write_row(&bob.path, &at, &mid(1), "in", 1_000);
    write_row(&bob.path, &at, &mid(2), "in", 2_000);
    write_row(&bob.path, &at, &mid(3), "out", 3_000);
    write_row(&bob.path, &at, &mid(4), "in", 4_000);
    write_row(&bob.path, &at, &mid(5), "in", 5_000);
    (bob, alice)
}

#[test]
fn a_chat_read_in_the_terminal_app_is_read_here() {
    let (bob, alice) = alice_wrote();
    let at = alice.address();
    let key = key_hex(&bob.path, &at);
    assert_eq!(unread_of(&bob.client, &at), 4, "theirs only, none read");
    let mut after = 0;
    // The engine's first look only notes the counts.
    common::events_until(&bob.client, &mut after, Duration::from_millis(1500), |_| {
        false
    });
    // The terminal app read her up to message 4 while the window is open.
    terminal_app_read(&bob.path, &key, &mid(4), 4_000, true);
    let seen = common::events_until(&bob.client, &mut after, Duration::from_secs(10), |evs| {
        evs.iter().any(|e| e["kind"] == "unread")
    });
    let event = seen
        .iter()
        .find(|e| e["kind"] == "unread")
        .unwrap_or_else(|| panic!("no unread event: {seen:?}"));
    assert_eq!(event["address"], at);
    assert_eq!(event["unread"], 1);
    assert_eq!(unread_of(&bob.client, &at), 1);
    // An older terminal app's file (an id only) counts the same way.
    terminal_app_read(&bob.path, &key, &mid(2), 0, false);
    assert_eq!(unread_of(&bob.client, &at), 2);
    // A marker whose message is gone counts what came after its time.
    terminal_app_read(&bob.path, &key, &"ee".repeat(16), 4_500, true);
    assert_eq!(unread_of(&bob.client, &at), 1);
}

#[test]
fn a_chat_read_here_is_read_in_the_terminal_app_and_after_a_restart() {
    let (bob, alice) = alice_wrote();
    let at = alice.address();
    let key = key_hex(&bob.path, &at);
    // Read up to message 2 (the newest the window showed), then all.
    let read = bob.ok("messages.mark_read", json!({"address": at, "id": mid(2)}));
    assert_eq!(read["unread"], 2, "{read}");
    assert!(read.get("note").is_none(), "{read}");
    let read = bob.ok("messages.mark_read", json!({"address": at}));
    assert_eq!(
        (read["address"].clone(), read["unread"].clone()),
        (json!(at), json!(0))
    );
    // What the terminal app reads: its own file, with the marker's time.
    let marks = ash_engine::engine::read_marks(&bob.path);
    let mark = marks.get(&key).expect("a marker for her");
    assert_eq!(
        (mark.id.as_str(), mark.at_ms),
        (mid(5).as_str(), Some(5_000))
    );
    let text = std::fs::read_to_string(bob.path.join("tui_state.json")).unwrap();
    let file: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(file["last_read"][&key], mid(5));
    // Never back: an older message marked later changes nothing.
    let read = bob.ok("messages.mark_read", json!({"address": at, "id": mid(1)}));
    assert_eq!(read["unread"], 0);
    assert_eq!(ash_engine::engine::read_marks(&bob.path)[&key].id, mid(5));
    // A message of yours is never unread; a new one of hers is.
    write_row(&bob.path, &at, &mid(6), "out", 6_000);
    assert_eq!(unread_of(&bob.client, &at), 0);
    write_row(&bob.path, &at, &mid(7), "in", 7_000);
    assert_eq!(unread_of(&bob.client, &at), 1);
    // The count survives the app: a new engine on the same profile.
    let again = Client::with_data_dir(&bob.path);
    assert_eq!(unread_of(&again, &at), 1);
    // A message that is not in the chat is refused.
    let code = bob.err(
        "messages.mark_read",
        json!({"address": at, "id": "ff".repeat(16)}),
    );
    assert_eq!(code, "BAD_REQUEST");
}

#[test]
fn a_terminal_app_setting_survives_a_mark_read_here() {
    let (bob, alice) = alice_wrote();
    let at = alice.address();
    let key = key_hex(&bob.path, &at);
    terminal_app_read(&bob.path, &key, &mid(1), 1_000, true);
    bob.ok("messages.mark_read", json!({"address": at}));
    let text = std::fs::read_to_string(bob.path.join("tui_state.json")).unwrap();
    let file: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        file["motion"], "reduced",
        "the terminal app's settings stay"
    );
    assert_eq!(file["last_read"][&key], mid(5));
    assert_eq!(file["last_read_at"][&key]["at_ms"], 5_000);
}
