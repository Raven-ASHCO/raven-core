//! A message from profile A to profile B through two real raven-node
//! processes on 127.0.0.1 (free ports, file-backed secret stores), started
//! and stopped by the engine itself: the flow tests/delivery.rs runs on
//! plain profiles and tests/privacy.rs on sealed ones.
//!
//! "delivered" must appear only after a `receipt` event, and a message to a
//! friend whose computer is off must never read delivered.
//!
//! Needs the raven-node that `cargo build` puts next to the test binaries'
//! folder; without it the flow says so and passes.

use std::path::Path;
use std::time::Duration;

use raven_client::Client;
use serde_json::{json, Value};

use super::{err, ok, short_dir, NodeGuard};

struct Profile {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    client: Client,
    me: Value,
}

fn profile(name: &str) -> Profile {
    let dir = short_dir();
    let path = dir.path().join("p");
    let client = Client::with_data_dir(&path);
    // Receiving off: a node the app starts listens on this computer only.
    ok(&client, "settings.set", json!({"receive": false}));
    ok(&client, "identity.create", json!({"display_name": name}));
    let me = ok(&client, "identity.me", json!({}));
    Profile {
        _dir: dir,
        path,
        client,
        me,
    }
}

fn of_kind<'a>(events: &'a [Value], kind: &str, id: &str) -> Vec<&'a Value> {
    events
        .iter()
        .filter(|e| e["kind"] == kind && e["id"] == id)
        .collect()
}

/// The last state event of `id`, once it is one of `ends`.
fn final_state(events: &[Value], id: &str, ends: &[&str]) -> Option<String> {
    of_kind(events, "state", id)
        .last()
        .map(|e| e["state"].as_str().unwrap().to_owned())
        .filter(|s| ends.contains(&s.as_str()))
}

/// States a message does not leave by itself while nothing changes.
const SETTLED: &[&str] = &["delivered", "failed", "time_ran_out", "not_sent_meet_first"];

/// The flow, on the lab environment the caller set up (`common::lab_env`,
/// and any lab switch the caller adds). `each` sees both profiles' folders
/// and engines once everything was checked, before they are stopped.
pub fn delivered_only_after_a_signed_receipt(each: impl Fn(&Path, &Client)) {
    if super::raven_node().is_none() {
        eprintln!("skipped: raven-node is not built (run `cargo build` in node/)");
        return;
    }
    let a = profile("Desk A");
    let b = profile("Desk B");
    let _guard_a = NodeGuard {
        client: a.client.clone(),
        dir: a.path.clone(),
    };
    let _guard_b = NodeGuard {
        client: b.client.clone(),
        dir: b.path.clone(),
    };
    ok(
        &a.client,
        "contacts.add",
        json!({"text": b.me["invite"], "name": "Friend B"}),
    );
    ok(
        &b.client,
        "contacts.add",
        json!({"text": a.me["invite"], "name": "Friend A"}),
    );

    // Nothing runs yet; a send needs nothing started by hand, but B must
    // listen to receive.
    let before = ok(&b.client, "node.status", json!({}));
    assert_eq!(before["running"], false, "{before}");
    let started = ok(&b.client, "node.start", json!({}));
    assert_eq!(started["running"], true, "{started}");
    assert_eq!(started["started_by_app"], true, "{started}");
    assert_eq!(started["state"], "local_only", "{started}");
    let b_listen = started["listening"].as_str().expect("listening").to_owned();
    assert!(b_listen.starts_with("127.0.0.1:"), "{b_listen}");
    assert_ne!(b_listen, "127.0.0.1:7420");
    // A second start finds it running.
    assert_eq!(
        ok(&b.client, "node.start", json!({}))["pid"],
        started["pid"]
    );

    let set = ok(
        &a.client,
        "contacts.set_address",
        json!({"address": b.me["address"], "lan": b_listen}),
    );
    assert_eq!(set["contact"]["lan"], b_listen.as_str());

    // B's watcher has its first look before anything is sent.
    let mut b_after = 0;
    super::events_until(&b.client, &mut b_after, Duration::from_secs(10), |evs| {
        evs.iter().any(|e| e["kind"] == "status_ok")
    });

    // A sends: the node it needs is started by the send itself.
    let mut a_after = ok(&a.client, "events.poll", json!({"after_seq": 0}))["seq"]
        .as_u64()
        .unwrap();
    let text = "hello over loopback";
    let sent = ok(
        &a.client,
        "messages.send",
        json!({"address": b.me["address"], "text": text}),
    );
    let msg = &sent["message"];
    assert_eq!(msg["state"], "sending", "{sent}");
    assert_eq!(msg["direction"], "out");
    let id = msg["id"].as_str().unwrap().to_owned();
    let events = super::events_until(&a.client, &mut a_after, Duration::from_secs(120), |evs| {
        final_state(evs, &id, SETTLED).is_some()
    });
    assert_eq!(
        of_kind(&events, "send_started", &id).len(),
        1,
        "{events:#?}"
    );
    assert_eq!(
        final_state(&events, &id, SETTLED).as_deref(),
        Some("delivered"),
        "{events:#?}"
    );
    let receipts = of_kind(&events, "receipt", &id);
    assert_eq!(receipts.len(), 1, "{events:#?}");
    let receipt_seq = receipts[0]["seq"].as_u64().unwrap();
    assert_eq!(receipts[0]["path"], "LAN direct");
    for state in of_kind(&events, "state", &id) {
        if state["state"] == "delivered" {
            assert!(state["seq"].as_u64().unwrap() > receipt_seq, "{events:#?}");
        }
    }
    // The history agrees, under the same id.
    let history = ok(
        &a.client,
        "messages.history",
        json!({"address": b.me["address"], "limit": 10}),
    );
    let mine = history["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == id.as_str())
        .unwrap_or_else(|| panic!("{history}"));
    assert_eq!(mine["state"], "delivered");
    assert_eq!(mine["text"], text);
    assert_eq!(mine["path"], "LAN direct");
    let a_status = ok(&a.client, "node.status", json!({}));
    assert_eq!(a_status["started_by_app"], true, "{a_status}");
    let friend = &ok(&a.client, "contacts.list", json!({}))["contacts"][0];
    assert_eq!(friend["presence"], "in_touch", "{friend}");

    // B received it: in its history, and as an `incoming` event.
    let b_events = super::events_until(&b.client, &mut b_after, Duration::from_secs(20), |evs| {
        evs.iter()
            .any(|e| e["kind"] == "incoming" && e["message"]["text"] == text)
    });
    let incoming = b_events
        .iter()
        .find(|e| e["kind"] == "incoming")
        .unwrap_or_else(|| panic!("{b_events:#?}"));
    assert_eq!(incoming["message"]["direction"], "in");
    assert_eq!(incoming["message"]["address"], a.me["address"]);
    let b_history = ok(
        &b.client,
        "messages.history",
        json!({"address": a.me["address"]}),
    );
    assert!(b_history["messages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["text"] == text && m["direction"] == "in"));

    // B stops: only its own node, by the rules.
    let stopped = ok(&b.client, "node.stop", json!({}));
    assert_eq!(stopped["stop"], "stopped", "{stopped}");
    assert_eq!(stopped["running"], false);

    // A message to B now waits (or is not sent): never delivered, no receipt.
    let second = ok(
        &a.client,
        "messages.send",
        json!({"address": b.me["address"], "text": "are you there?"}),
    );
    let id2 = second["message"]["id"].as_str().unwrap().to_owned();
    let events = super::events_until(&a.client, &mut a_after, Duration::from_secs(120), |evs| {
        final_state(
            evs,
            &id2,
            &["waiting", "failed", "not_sent_meet_first", "delivered"],
        )
        .is_some()
    });
    let end = final_state(
        &events,
        &id2,
        &["waiting", "failed", "not_sent_meet_first", "delivered"],
    )
    .unwrap_or_else(|| panic!("{events:#?}"));
    assert_ne!(end, "delivered", "{events:#?}");
    assert!(of_kind(&events, "receipt", &id2).is_empty(), "{events:#?}");
    let details = ok(&a.client, "messages.details", json!({"id": id2}));
    assert!(
        !details["status_text"].as_str().unwrap().is_empty(),
        "{details}"
    );
    // The plain lines never show the session id; the technical ones do.
    assert!(details["detail"].as_str().unwrap().contains("Message ID: "));
    assert!(!details["detail"].as_str().unwrap().contains(&id2));
    assert!(details["technical"].as_str().unwrap().contains(&id2));
    if end == "waiting" {
        // Stop trying: raven-node gives it up.
        let stop = ok(&a.client, "messages.stop", json!({"id": id2}));
        assert_eq!(stop["changed"], true, "{stop}");
        assert_eq!(stop["message"]["state"], "failed", "{stop}");
    }
    assert_eq!(
        err(&a.client, "messages.details", json!({"id": "no-such-id"})),
        "BAD_REQUEST"
    );

    each(&a.path, &a.client);
    each(&b.path, &b.client);

    let a_stop = ok(&a.client, "node.stop", json!({}));
    assert_eq!(a_stop["stop"], "stopped", "{a_stop}");
}
