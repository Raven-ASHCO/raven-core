//! `messages.handoff` through the engine API (docs/IOS.md §3: what an app
//! does before it goes to the background), with three raven-node processes
//! on 127.0.0.1: B is away, so A's message and A's group copy for B wait on
//! A's computer; a friend would take them only after a minute, and the
//! hand-off leaves them with C (a friend all three verified, who carries for
//! friends and whom A and B list for each other) at once. A's message then
//! says who holds it (`via_name`, also on its `state` event), and so does
//! the group receipt for B (`held_by`). B, back, collects both from C.
//! Then C is away, and a message to C, whose mail nobody holds, is left
//! at once: the hand-off does not wait out its time for it.
//!
//! Lab switches for this test binary only: `RAVEN_LAB_TEST_A=1` (its
//! harness values), `RAVEN_LAB_CUSTODY_FETCH_MS=1000` (collect every
//! second) and `RAVEN_LAB_TOR=0` (no Tor network). `RAVEN_LAB_CUSTODY_AFTER_MS`
//! stays unset: the minute before a friend takes a copy is what the hand-off
//! skips.
//!
//! Needs the raven-node and raven that `cargo build` puts next to the test
//! binaries' folder; without them the test says so and passes.

mod common;

use std::time::{Duration, Instant};

use common::net::{binaries_ready, Peer};
use serde_json::{json, Value};

/// `who`'s group `group` as `groups.history` has it.
fn group_history(who: &Peer, group: &str) -> Vec<Value> {
    who.ok("groups.history", json!({"group": group}))["messages"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn a_handoff_leaves_what_waits_with_a_friend_now() {
    if !binaries_ready() {
        return;
    }
    if !cfg!(debug_assertions) {
        eprintln!("skipped: a release engine reads no lab switch (tests/net_gates.rs)");
        return;
    }
    common::lab_env();
    std::env::set_var("RAVEN_LAB_TEST_A", "1");
    std::env::set_var("RAVEN_LAB_CUSTODY_FETCH_MS", "1000");
    // No Tor (its gate is open in this build: a raven-tor-helper next to
    // raven-node would reach the real Tor network); this is about friends.
    std::env::set_var("RAVEN_LAB_TOR", "0");
    let a = Peer::new("Sender");
    let b = Peer::new("Recipient");
    let c = Peer::new("Carrier");
    for (x, y) in [(&a, &b), (&a, &c), (&b, &a), (&b, &c), (&c, &a), (&c, &b)] {
        x.befriend(y, None);
    }
    c.ok(
        "network.set",
        json!({"carry_for_friends": true, "agreed": true}),
    );
    let (la, lb, lc) = (a.start(), b.start(), c.start());
    for (x, y, l) in [
        (&a, &b, &lb),
        (&a, &c, &lc),
        (&b, &a, &la),
        (&b, &c, &lc),
        (&c, &a, &la),
        (&c, &b, &lb),
    ] {
        x.set_lan(y, l);
    }
    for (x, y) in [(&a, &b), (&b, &a)] {
        x.ok(
            "contacts.set_routes",
            json!({"address": y.address(), "custodians": [c.address()]}),
        );
    }
    // Who a mail check asks, by name: the friend listed for a contact.
    let names = &a.ok("network.status", json!({}))["carry"]["friends_carry_mine"]["names"];
    assert_eq!(*names, json!(["Friend Carrier"]), "{names}");

    // A group of the three, its roster with everyone, and a warm-up: the
    // sessions exist before B goes away.
    let created = a.ok(
        "groups.create",
        json!({"name": "Trio", "members": [b.address(), c.address()]}),
    );
    let group = created["group"]["id"].as_str().unwrap().to_owned();
    for p in [&b, &c] {
        let deadline = Instant::now() + Duration::from_secs(120);
        while !p.ok("groups.list", json!({}))["groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["id"] == group.as_str())
        {
            assert!(Instant::now() < deadline, "{}: no roster", p.name);
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    let warm = a.send_until(
        &b,
        "warmup",
        &["delivered", "failed"],
        Duration::from_secs(90),
    );
    assert_eq!(warm["state"], "delivered", "{warm}");
    b.stop();

    // B is away: the message waits on A's computer, nobody holds it yet.
    let waiting = a.send_until(
        &b,
        "via-handoff",
        &["waiting", "sent", "failed", "not_sent_meet_first"],
        Duration::from_secs(90),
    );
    assert_eq!(waiting["state"], "waiting", "{waiting}");
    assert!(waiting.get("via_name").is_none(), "{waiting}");
    let sent = a.ok(
        "groups.send",
        json!({"group": group, "text": "group-handoff"}),
    );
    let group_id = sent["message"]["id"].as_str().unwrap().to_owned();
    let mut after = a.ok("events.poll", json!({"after_seq": 0}))["seq"]
        .as_u64()
        .unwrap();

    // The app goes to the background: the hand-off, within its time.
    let began = Instant::now();
    let handed = a.ok("messages.handoff", json!({"budget_ms": 15000}));
    assert!(began.elapsed() < Duration::from_secs(17), "{handed}");
    assert_eq!(handed["custody"], "on", "{handed}");
    assert_eq!(handed["completed"], true, "{handed}\n{}", a.service_log());
    assert_eq!(handed["left"], 0, "{handed}");
    // The message and the group copy for B (and B's roster copy, when it
    // still waited), each with C.
    assert!(
        handed["handed"].as_u64().unwrap() >= 2,
        "{handed}\n{}\n{}",
        String::from_utf8_lossy(&a.cli(&["outbox", "list"]).stdout),
        a.service_log()
    );
    assert_eq!(handed["holders"], json!(["Friend Carrier"]), "{handed}");

    // A's message says who holds it, and a state event told the app.
    let history = a.ok(
        "messages.history",
        json!({"address": b.address(), "limit": 10}),
    );
    let mine = history["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["text"] == "via-handoff")
        .cloned()
        .unwrap_or_default();
    assert_eq!(mine["path_kind"], "friend", "{mine}");
    assert_eq!(mine["via_name"], "Friend Carrier", "{mine}");
    let id = mine["id"].as_str().unwrap().to_owned();
    let events = common::events_until(&a.client, &mut after, Duration::from_secs(10), |seen| {
        seen.iter()
            .any(|e| e["kind"] == "state" && e["id"] == id.as_str() && e["via_name"].is_string())
    });
    let told = events
        .iter()
        .find(|e| e["kind"] == "state" && e["id"] == id.as_str() && e["via_name"].is_string())
        .unwrap_or_else(|| panic!("no state event with via_name: {events:#?}"));
    assert_eq!(told["via_name"], "Friend Carrier", "{told}");
    assert_eq!(told["path_kind"], "friend", "{told}");

    // The group receipt for B: held by C.
    let deadline = Instant::now() + Duration::from_secs(20);
    let receipt_b = loop {
        let mine = group_history(&a, &group)
            .into_iter()
            .find(|m| m["id"] == group_id.as_str())
            .unwrap_or_default();
        let r = mine["receipts"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|r| r["address"] == b.address().as_str())
            .cloned()
            .unwrap_or_default();
        if r["held_by"].is_string() || Instant::now() >= deadline {
            break r;
        }
        std::thread::sleep(Duration::from_millis(400));
    };
    assert_eq!(receipt_b["held_by"], "Friend Carrier", "{receipt_b}");

    // Again: nothing new waits, nothing is handed.
    let again = a.ok("messages.handoff", json!({"budget_ms": 1000}));
    assert_eq!(
        (&again["handed"], &again["left"], &again["completed"]),
        (&json!(0), &json!(0), &json!(true)),
        "{again}"
    );

    // B is back and collects both from C.
    b.start();
    assert!(
        b.wait_incoming(&a, "via-handoff", Duration::from_secs(90)),
        "B never got it from C:\n{}",
        b.service_log()
    );
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let at_b = group_history(&b, &group)
            .into_iter()
            .find(|m| m["id"] == group_id.as_str());
        if let Some(m) = at_b {
            assert_eq!(m["text"], "group-handoff", "{m}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "B never got the group message:\n{}",
            b.service_log()
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    // C is away now, and nobody holds mail for C (C told of no mail friend,
    // A listed none for C): the hand-off does not wait out its time for it.
    c.stop();
    let stuck = a.send_until(
        &c,
        "nobody-holds-this",
        &["waiting", "sent", "failed", "not_sent_meet_first"],
        Duration::from_secs(90),
    );
    assert_eq!(stuck["state"], "waiting", "{stuck}");
    let began = Instant::now();
    let r = a.ok("messages.handoff", json!({"budget_ms": 15000}));
    assert!(began.elapsed() < Duration::from_secs(8), "{r}");
    assert_eq!(
        (&r["handed"], &r["left"], &r["completed"]),
        (&json!(0), &json!(1), &json!(false)),
        "{r}"
    );
}
