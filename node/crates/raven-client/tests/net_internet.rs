//! (b) Internet direct over 127.0.0.1 through the engine API, with the lab
//! switch a debug build needs (`RAVEN_LAB_TEST_A=1`, set for this test
//! binary only): `network.set {internet}` saves what `raven node internet
//! on` saves, the raven-node the engine starts inherits the switch and opens
//! the listener, and a friend with only an Internet route gets the message.
//!
//! Needs the raven-node and raven that `cargo build` puts next to the test
//! binaries' folder; without them the test says so and passes.

mod common;

use std::time::Duration;

use common::net::{binaries_ready, carrier_of, free_port, Peer};
use serde_json::json;

#[test]
fn internet_direct_over_loopback_with_the_lab_switch() {
    if !binaries_ready() {
        return;
    }
    if !cfg!(debug_assertions) {
        eprintln!("skipped: a release engine reads no lab switch (tests/net_gates.rs)");
        return;
    }
    common::lab_env();
    std::env::set_var("RAVEN_LAB_TEST_A", "1");
    let a = Peer::new("Inet A");
    let b = Peer::new("Inet B");
    // Internet direct only between verified friends (owner decision).
    a.befriend(&b, None);
    b.befriend(&a, None);

    // The debug engine shows the way as on for testing, and says why.
    let before = b.carrier("internet");
    assert_eq!(before["state"], "off", "{before}");
    assert_eq!(before["lab"], true, "{before}");
    let node = b.ok("node.status", json!({}));
    assert!(
        node["lab"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w == "internet"),
        "{node}"
    );
    assert!(
        node["lab_switches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "RAVEN_LAB_TEST_A"),
        "{node}"
    );

    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let set = b.ok(
        "network.set",
        json!({"internet": true, "internet_listen": listen}),
    );
    assert_eq!(set["changes"][0]["applies"], "restart", "{set}");
    assert_eq!(
        set["changes"][0]["value"]["listen"],
        listen.as_str(),
        "{set}"
    );
    // What `raven node internet on --listen` saves, read by the CLI's code.
    let policy = raven_core::node_policy::try_load_policy(&b.path).unwrap();
    assert_eq!(policy.internet_listen, listen);

    // B's raven-node (started by the engine) inherited the switch: it
    // opens the Internet listener and says so in its Status.
    b.start();
    let mut net = serde_json::Value::Null;
    let up = (0..50).any(|_| {
        net = b.ok("network.status", json!({}));
        if carrier_of(&net, "internet")["running"] == true {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
        false
    });
    assert!(
        up,
        "the Internet listener never came up: {net}\n{}",
        b.service_log()
    );
    let inet = carrier_of(&net, "internet");
    assert_eq!(inet["state"], "lab", "{inet}");
    assert_eq!(inet["setting"], true, "{inet}");
    assert!(
        net["listening"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l == listen.as_str()),
        "{net}"
    );

    // A knows B only by its Internet address: no LAN route at all.
    let routes = a.ok(
        "contacts.set_routes",
        json!({"address": b.address(), "internet": listen}),
    );
    let kinds: Vec<&str> = routes["routes"]["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["internet", "nearby"], "{routes}");
    assert_eq!(routes["routes"]["routes"][0]["state"], "lab", "{routes}");
    assert!(routes["contact"]["lan"].is_null(), "{routes}");

    let m = a.send_until(
        &b,
        "over the internet port",
        &["delivered", "failed", "not_sent_meet_first"],
        Duration::from_secs(120),
    );
    assert_eq!(m["state"], "delivered", "{m}\n{}", a.service_log());
    assert_eq!(m["path_kind"], "internet", "{m}");
    assert_eq!(m["path"], "Internet direct", "{m}");
    assert!(b.wait_incoming(&a, "over the internet port", Duration::from_secs(20)));

    // Off again: saved for the next start, as `raven node internet off`.
    let off = b.ok("network.set", json!({"internet": false}));
    assert_eq!(off["restart_needed"], true, "{off}");
    assert!(raven_core::node_policy::try_load_policy(&b.path)
        .unwrap()
        .internet_listen
        .is_empty());
}
