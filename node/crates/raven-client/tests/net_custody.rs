//! (d) Friend custody through the engine API, the s30 "via a friend" flow
//! of scripts/lan_fault_matrix.py: B is offline, A's message is left with C
//! (a friend both verified and listed for each other), A goes offline too,
//! and B collects it from C once B starts. Lab switches for this test binary
//! only: `RAVEN_LAB_TEST_A=1` (the custody gate), `RAVEN_LAB_CUSTODY_AFTER_MS=0`
//! (leave a copy at once) and `RAVEN_LAB_CUSTODY_FETCH_MS=1000` (collect every
//! second). Every node listens on 127.0.0.1, any free port.
//!
//! Needs the raven-node and raven that `cargo build` puts next to the test
//! binaries' folder; without them the test says so and passes.

mod common;

use std::time::{Duration, Instant};

use common::net::{binaries_ready, carrier_of, Peer};
use serde_json::json;

#[test]
fn a_friend_holds_the_message_until_the_recipient_starts() {
    if !binaries_ready() {
        return;
    }
    if !cfg!(debug_assertions) {
        eprintln!("skipped: a release engine reads no lab switch (tests/net_gates.rs)");
        return;
    }
    common::lab_env();
    std::env::set_var("RAVEN_LAB_TEST_A", "1");
    std::env::set_var("RAVEN_LAB_CUSTODY_AFTER_MS", "0");
    std::env::set_var("RAVEN_LAB_CUSTODY_FETCH_MS", "1000");
    let a = Peer::new("Sender");
    let b = Peer::new("Recipient");
    let c = Peer::new("Carrier");
    for (x, y) in [(&a, &b), (&a, &c), (&b, &a), (&b, &c), (&c, &a), (&c, &b)] {
        x.befriend(y, None);
    }

    // C carries for friends: the consent first, then the yes.
    let custody = c.carrier("custody");
    assert_eq!(custody["lab"], true, "{custody}");
    let net = c.ok("network.status", json!({}));
    assert!(
        net["texts"]["carry_for_friends"]
            .as_str()
            .is_some_and(|t| t.contains("sealed")),
        "{net}"
    );
    assert_eq!(
        c.err("network.set", json!({"carry_for_friends": true})),
        "CONSENT_NEEDED"
    );
    let set = c.ok(
        "network.set",
        json!({"carry_for_friends": true, "agreed": true}),
    );
    assert_eq!(set["changes"][0]["setting"], "carry_for_friends", "{set}");
    assert_eq!(
        set["status"]["carry"]["carry_for_friends"]["on"], true,
        "{set}"
    );
    assert!(
        raven_core::node_policy::try_load_policy(&c.path)
            .unwrap()
            .custody
    );

    // Every node runs; each knows where the others listen.
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
    // A and B list C as the friend who holds their mail for each other
    // (`raven contact set-addr --custodian`).
    for (x, y) in [(&a, &b), (&b, &a)] {
        let r = x.ok(
            "contacts.set_routes",
            json!({"address": y.address(), "custodians": [c.address()]}),
        );
        let listed = &r["routes"]["carriers"]["listed"];
        assert_eq!(listed[0]["address"], c.address().as_str(), "{r}");
        assert_eq!(listed[0]["usable"], true, "{r}");
    }

    // A warm-up: the session exists before B goes away.
    let warm = a.send_until(
        &b,
        "warmup",
        &["delivered", "failed"],
        Duration::from_secs(90),
    );
    assert_eq!(warm["state"], "delivered", "{warm}");
    b.stop();

    // B is away: the message waits, and C holds a sealed copy of it.
    let held = a.send_until(
        &b,
        "via-carrier",
        &["waiting", "sent", "failed", "not_sent_meet_first"],
        Duration::from_secs(90),
    );
    assert!(
        matches!(held["state"].as_str(), Some("waiting" | "sent")),
        "{held}"
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut c_net = serde_json::Value::Null;
    while Instant::now() < deadline {
        c_net = c.ok("network.status", json!({}));
        if c_net["carry"]["carry_for_friends"]["held_messages"]
            .as_i64()
            .unwrap_or(0)
            >= 1
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(
        c_net["carry"]["carry_for_friends"]["held_messages"]
            .as_i64()
            .unwrap_or(0)
            >= 1,
        "C holds nothing: {c_net}\n{}",
        a.service_log()
    );
    // A's message says a friend holds it.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut mine = serde_json::Value::Null;
    while Instant::now() < deadline {
        let history = a.ok(
            "messages.history",
            json!({"address": b.address(), "limit": 10}),
        );
        mine = history["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["text"] == "via-carrier")
            .cloned()
            .unwrap_or_default();
        if mine["path_kind"] == "friend" {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert_eq!(mine["path_kind"], "friend", "{mine}");
    assert_eq!(mine["path"], "Held by a friend", "{mine}");
    let details = a.ok("messages.details", json!({"id": mine["id"]}));
    assert!(
        details["why_text"]
            .as_str()
            .is_some_and(|t| t.contains("friend's computer is holding")),
        "{details}"
    );

    // A goes away too: only C can hand the message to B now.
    a.stop();
    b.start();
    assert!(
        b.wait_incoming(&a, "via-carrier", Duration::from_secs(60)),
        "B never got it from C:\n{}",
        b.service_log()
    );
    // From C: B's raven-node says it fetched (logged right after the
    // message is stored).
    assert!(
        b.wait_log("custody: fetched messages=", Duration::from_secs(15)),
        "{}",
        b.service_log()
    );
    let custody = carrier_of(&b.ok("network.status", json!({})), "custody");
    assert_eq!(custody["lab"], true, "{custody}");
}
