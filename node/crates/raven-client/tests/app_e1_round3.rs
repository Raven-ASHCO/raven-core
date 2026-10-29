//! What the desktop apps needed after round 3 of the three-machine test's E1
//! feedback: a message that was not sent stays in the chat after a restart
//! (with Send again and Delete), the way each delivered message travelled
//! and when a late one came stay too, Routes says where the friend is
//! reached now (and that the saved address is old), and how long a message
//! could wait for an away friend comes from the rule the terminal app uses,
//! which tells a first message from a secure connection that ended.

mod common;

use std::path::Path;
use std::time::Duration;

use common::net::Peer;
use raven_core::chat_history::{ChatHistory, ChatHistoryEntry};
use raven_core::outbox::QueueReach;
use serde_json::{json, Value};

/// The long message horizon closed for this test binary (a debug build's
/// `RAVEN_LAB_HORIZON=0`): release builds have it on since 2026-10, and then
/// a message to an away friend waits up to 7 days, first or not (raven-client
/// `network::tests::away_tells_a_first_message_from_an_ended_connection`,
/// ash's bridge tests).
/// These E1 checks pin the words and states without it.
fn horizon_closed() {
    common::lab_env();
    std::env::set_var("RAVEN_LAB_HORIZON", "0");
}

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

fn write_out_row(dir: &Path, friend: &str, mid: &str, body: &str, delivery: &str, at_ms: u64) {
    ChatHistory::append_persisted(
        dir,
        ChatHistoryEntry {
            message_id_hex: mid.into(),
            direction: "out".into(),
            peer_petname: String::new(),
            peer_tag: String::new(),
            peer_pub_hex: key_hex(dir, friend),
            created_at_ms: at_ms,
            delivery: delivery.into(),
            preview: body.into(),
            body: body.into(),
            stored_at_ms: None,
        },
    )
    .expect("history row written");
}

fn history(client: &raven_client::Client, friend: &str) -> Vec<Value> {
    common::ok(
        client,
        "messages.history",
        json!({"address": friend, "limit": 50}),
    )["messages"]
        .as_array()
        .unwrap()
        .clone()
}

fn texts(list: &[Value]) -> Vec<String> {
    list.iter()
        .map(|m| m["text"].as_str().unwrap().to_owned())
        .collect()
}

/// E1 (round 2): "Not sent: meet first" was gone after the app started
/// again; only delivered messages were left. It stays now, as not
/// delivered, with Send again (which replaces it for good) and Delete.
#[test]
fn a_message_that_was_not_sent_stays_after_a_restart() {
    horizon_closed();
    if common::raven_node().is_none() {
        eprintln!("skipped: raven-node is not built (run `cargo build` in node/)");
        return;
    }
    let a = Peer::new("a");
    let b = Peer::new("b");
    a.befriend(&b, None);
    // Nothing listens there, and the two never had a secure connection.
    a.set_lan(&b, &format!("127.0.0.1:{}", common::net::free_port()));
    let sent = a.send_until(
        &b,
        "a first message",
        &["not_sent_meet_first", "failed", "waiting", "delivered"],
        Duration::from_secs(120),
    );
    let state = sent["state"].as_str().unwrap().to_owned();
    assert!(
        matches!(state.as_str(), "not_sent_meet_first" | "failed"),
        "{sent}"
    );
    // The app starts again: the message is still there, not delivered.
    let again = raven_client::Client::with_data_dir(&a.path);
    let list = history(&again, &b.address());
    assert_eq!(texts(&list), ["a first message"], "{list:?}");
    assert_eq!(list[0]["state"], "failed", "{list:?}");
    let old = list[0]["id"].as_str().unwrap().to_owned();
    // Send again: a new message in its place, the old one gone for good.
    let retried = common::ok(&again, "messages.retry", json!({"id": old}));
    assert_eq!(retried["replaces"], old.as_str(), "{retried}");
    assert_eq!(retried["may_arrive_twice"], true, "{retried}");
    let new_id = retried["message"]["id"].as_str().unwrap().to_owned();
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let list = history(&again, &b.address());
        let new = list.iter().find(|m| m["id"] == new_id.as_str());
        if new.is_some_and(|m| m["state"] != "sending") {
            assert_eq!(texts(&list), ["a first message"], "{list:?}");
            break;
        }
        assert!(std::time::Instant::now() < deadline, "{list:?}");
        std::thread::sleep(Duration::from_millis(300));
    }
    let third = raven_client::Client::with_data_dir(&a.path);
    let list = history(&third, &b.address());
    assert_eq!(texts(&list), ["a first message"], "{list:?}");
    assert_ne!(list[0]["id"], old.as_str());
    // Delete takes it out for good too.
    let id = list[0]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        common::ok(&third, "messages.delete", json!({"id": id}))["deleted"],
        true
    );
    let fourth = raven_client::Client::with_data_dir(&a.path);
    assert!(history(&fourth, &b.address()).is_empty());
}

/// E1: path chips of older messages were gone after a restart, and a
/// message that waited said only "Delivered". The way each delivered
/// message travelled and, for one delivered more than a minute after it was
/// written, when its receipt came are kept and come back.
#[test]
fn deliveries_keep_their_way_and_late_time_after_a_restart() {
    let a = Peer::new("a");
    let b = Peer::new("b");
    a.befriend(&b, None);
    let late = "51".repeat(16);
    let quick = "52".repeat(16);
    let written = now_ms() - 10 * 60_000;
    write_out_row(&a.path, &b.address(), &late, "waited", "queued", written);
    // How an earlier run of the app saw the other one travel.
    std::fs::write(
        a.path.join("desktop_private.rms"),
        json!({"version": 1, "delivered": {quick.clone(): {"path_kind": "lan"}}}).to_string(),
    )
    .unwrap();
    write_out_row(&a.path, &b.address(), &quick, "went", "delivered", now_ms());
    // The app starts: its engine's first look only reads.
    let app = raven_client::Client::with_data_dir(&a.path);
    let first = history(&app, &b.address());
    assert_eq!(first[0]["state"], "waiting", "{first:?}");
    assert_eq!(first[1]["path"], "LAN direct", "{first:?}");
    assert!(first[1].get("delivered_at_ms").is_none(), "{first:?}");
    // raven-node delivers the waiting one now.
    let peer = key_hex(&a.path, &b.address());
    assert!(
        ChatHistory::set_delivery_persisted(&a.path, &peer, "out", &late, "delivered").unwrap()
    );
    let before = now_ms();
    let now = history(&app, &b.address());
    let at = now[0]["delivered_at_ms"]
        .as_u64()
        .expect("a late delivery's time");
    assert!(at >= before && at <= now_ms(), "{now:?}");
    let details = common::ok(&app, "messages.details", json!({"id": late}));
    let status = details["status_text"].as_str().unwrap();
    assert!(
        status.starts_with("Delivered ") && !status.starts_with("Delivered."),
        "{status}"
    );
    // The app starts again: both come back as they were.
    let again = raven_client::Client::with_data_dir(&a.path);
    let list = history(&again, &b.address());
    assert_eq!(list[0]["delivered_at_ms"], at, "{list:?}");
    assert_eq!(list[1]["path"], "LAN direct", "{list:?}");
    assert_eq!(list[1]["path_kind"], "lan", "{list:?}");
    assert!(list[1].get("delivered_at_ms").is_none(), "{list:?}");
}

/// E1: Routes showed the friend's old saved address while every message
/// went to its new one. It says where the friend is reached now, that the
/// saved one is old, and how long a message could wait for the friend by
/// the terminal app's rule (no secure connection yet: a first message needs
/// you both online; `meet_first` stays set for an app that knows only it).
#[test]
fn routes_say_where_the_friend_is_reached_now() {
    horizon_closed();
    let a = Peer::new("a");
    let b = Peer::new("b");
    a.befriend(&b, None);
    a.set_lan(&b, "192.168.1.146:17420");
    let quiet = a.ok("contacts.routes", json!({"address": b.address()}));
    assert!(quiet.get("lan_now").is_none(), "{quiet}");
    assert_eq!(
        quiet["carriers"]["away"],
        json!({"meet_first": true, "first_message": true}),
        "{quiet}"
    );
    // The friend reached this computer from its new address.
    let key = hex::decode(key_hex(&a.path, &b.address())).unwrap();
    let key: [u8; 32] = key.try_into().unwrap();
    raven_core::lan_seen::record_contact_seen(
        &a.path,
        &key,
        "192.168.0.24".parse().unwrap(),
        None,
        now_ms(),
    )
    .unwrap();
    let routes = a.ok("contacts.routes", json!({"address": b.address()}));
    let now = &routes["lan_now"];
    assert_eq!(now["addr"], "192.168.0.24:17420", "{routes}");
    assert_eq!(now["saved_stale"], true, "{routes}");
    assert!(now["at_ms"].as_u64().is_some_and(|ms| ms > 0), "{routes}");
    // The saved address is replaced with it (contacts.set_address).
    a.set_lan(&b, "192.168.0.24:17420");
    let saved = a.ok("contacts.routes", json!({"address": b.address()}));
    assert_ne!(saved["lan_now"]["saved_stale"], true, "{saved}");
    let lan = saved["routes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "lan")
        .unwrap_or_else(|| panic!("{saved}"));
    assert_eq!(lan["value"], "192.168.0.24:17420");
}

/// E1 (three-machine test): Routes said "meet first" for a friend Raven had
/// never connected with, where the terminal app says a first message needs
/// you both online. A first message is that rule; once a secure connection
/// was set up a message can wait, and after it ended it is meet first.
#[test]
fn routes_tell_a_first_message_from_an_ended_connection() {
    horizon_closed();
    if common::raven_node().is_none() {
        eprintln!("skipped: raven-node is not built (run `cargo build` in node/)");
        return;
    }
    let a = Peer::new("a");
    let b = Peer::new("b");
    a.befriend(&b, None);
    b.befriend(&a, None);
    let key = key_hex(&a.path, &b.address());
    let first = a.ok("contacts.routes", json!({"address": b.address()}));
    assert_eq!(
        first["carriers"]["away"],
        json!({"meet_first": true, "first_message": true}),
        "{first}"
    );
    assert_eq!(
        ash_engine::engine::away_reach(&a.path, &key, now_ms()),
        Some(QueueReach::NeverPaired)
    );
    // Both online: the first message goes, over a new secure connection.
    let listen = b.start();
    a.set_lan(&b, &listen);
    let sent = a.send_until(
        &b,
        "a first message",
        &["delivered", "failed", "not_sent_meet_first", "waiting"],
        Duration::from_secs(120),
    );
    assert_eq!(sent["state"], "delivered", "{sent}");
    let paired = a.ok("contacts.routes", json!({"address": b.address()}));
    let away = &paired["carriers"]["away"];
    assert!(away["until_ms"].as_u64().is_some(), "{paired}");
    assert!(away.get("meet_first").is_none(), "{paired}");
    // Two days on that connection has ended: meet first, not a first message.
    let later = now_ms() + 2 * 24 * 3_600_000;
    assert!(
        matches!(
            ash_engine::engine::away_reach(&a.path, &key, later),
            Some(QueueReach::Ended { .. })
        ),
        "{:?}",
        ash_engine::engine::away_reach(&a.path, &key, later)
    );
}
