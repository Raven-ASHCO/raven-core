//! The network ops on a debug engine with no lab switch (desktop/api/API.md,
//! NETWORK_PARITY.md): LAN direct between two profiles through the engine
//! API, the help-friends flags the CLI reads, the released ways (2026-10)
//! and every held way shown as `preview` and refused.
//!
//! Needs the raven-node and raven that `cargo build` puts next to the test
//! binaries' folder; without them the tests say so and pass.

mod common;

use std::time::Duration;

use common::net::{binaries_ready, carrier_of, Peer};
use serde_json::json;

/// (a) Two profiles exchange a message over LAN direct through the engine
/// API; the network views say what carried it.
#[test]
fn lan_direct_between_two_profiles() {
    if !binaries_ready() {
        return;
    }
    let a = Peer::new("Lan A");
    let b = Peer::new("Lan B");
    a.befriend(&b, None);
    b.befriend(&a, None);
    let b_listen = b.start();
    assert!(b_listen.starts_with("127.0.0.1:"), "{b_listen}");
    a.set_lan(&b, &b_listen);

    let m = a.send_until(
        &b,
        "over the LAN",
        &["delivered", "failed"],
        Duration::from_secs(90),
    );
    assert_eq!(m["state"], "delivered", "{m}");
    assert_eq!(m["path"], "LAN direct", "{m}");
    assert_eq!(m["path_kind"], "lan", "{m}");
    assert!(b.wait_incoming(&a, "over the LAN", Duration::from_secs(20)));

    // B's view: LAN on and in use, listening where node.status says.
    let net = b.ok("network.status", json!({}));
    let lan = carrier_of(&net, "lan");
    assert_eq!(lan["state"], "on", "{lan}");
    assert_eq!(lan["running"], true, "{lan}");
    assert_eq!(lan["lab"], false, "{lan}");
    assert!(
        lan["detail"].as_str().is_some_and(|d| !d.is_empty()),
        "{lan}"
    );
    assert!(
        net["listening"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l == b_listen.as_str()),
        "{net}"
    );
    assert_eq!(net["node"], "running");
    assert!(net["port"].as_u64().is_some_and(|p| p > 0), "{net}");
    assert_eq!(net["lab_switches"], json!([]), "{net}");

    // A's routes for B: the saved LAN address, and nearby (verified): held
    // except on macOS, where release builds have it (off until enabled).
    let routes = a.ok("contacts.routes", json!({"address": b.address()}));
    assert_eq!(routes["verified"], true, "{routes}");
    let kinds: Vec<&str> = routes["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["lan", "nearby"], "{routes}");
    assert_eq!(routes["routes"][0]["value"], b_listen.as_str());
    assert_eq!(routes["routes"][0]["state"], "on");
    let nearby_state = if cfg!(target_os = "macos") {
        "off"
    } else {
        "preview"
    };
    assert_eq!(routes["routes"][1]["state"], nearby_state, "{routes}");
    assert_eq!(routes["hide_ip"], false);
    // Friends carry mail for verified contacts: a class is given.
    assert!(
        routes["carriers"]["coverage"]["kind"].is_string(),
        "{routes}"
    );
    // The friend's words and old code are never part of it (the words as a
    // run: one alone may be any English word in a label).
    let text = common::all_text(&routes);
    let words: Vec<&str> = b.me["words"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap())
        .collect();
    assert!(!text.contains(&words[..3].join(" ")), "{text}");
    assert!(!text.contains(b.me["old_code"].as_str().unwrap()), "{text}");

    // The doctor's summary and network lines, as data.
    let check = a.ok("network.check", json!({}));
    let keys: Vec<&str> = check["summary"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["key"].as_str().unwrap())
        .collect();
    for want in ["identity", "raven_node", "lan", "contacts", "disk"] {
        assert!(keys.contains(&want), "{want} missing: {check}");
    }
    // The next step is its own field, said once (E1).
    assert!(!keys.contains(&"next_step"), "{check}");
    assert!(!check["next_step"].as_str().unwrap().is_empty());
    let receiving = check["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == "receiving")
        .unwrap_or_else(|| panic!("{check}"));
    assert!(receiving["value"].is_string(), "{receiving}");
    assert!(
        check["router"].is_null(),
        "the router is asked only on request"
    );
    assert!(check["rows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["key"] == "policy"));
}

/// (e) `network.set` for bridge, store and relay changes the node policy the
/// CLI reads (`raven doctor`'s `policy` line), with AUTO off as `raven node
/// bridge|store|relay` sets it, and honest words for each.
#[test]
fn help_flags_change_the_policy_the_cli_reads() {
    if !binaries_ready() {
        return;
    }
    let p = Peer::new("Flags");
    let before = p.ok("network.status", json!({}));
    assert_eq!(before["help"]["bridge"], true, "{before}");
    assert_eq!(before["help"]["store"], true, "{before}");
    assert_eq!(before["help"]["relay"], false, "{before}");
    let set = p.ok(
        "network.set",
        json!({"bridge": false, "store": false, "relay": true}),
    );
    let changes = set["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 3, "{set}");
    for c in changes {
        assert_eq!(c["applies"], "now", "{c}");
        assert!(!c["effect"].as_str().unwrap().is_empty(), "{c}");
    }
    let store = changes.iter().find(|c| c["setting"] == "store").unwrap();
    assert!(
        store["effect"]
            .as_str()
            .unwrap()
            .contains("changes nothing yet"),
        "{store}"
    );
    assert_eq!(set["status"]["help"]["bridge"], false);
    assert_eq!(set["status"]["help"]["relay"], true);
    assert_eq!(set["status"]["help"]["automatic"], false);
    // The CLI reads the same file.
    let policy = raven_core::node_policy::try_load_policy(&p.path).unwrap();
    assert!(!policy.bridge && !policy.store && policy.relay && !policy.auto_policy);
    let doctor = p.cli(&["doctor"]);
    let out = String::from_utf8_lossy(&doctor.stdout);
    assert!(
        out.contains("policy bridge=false store=false relay=true"),
        "{out}"
    );
    // And back.
    p.ok(
        "network.set",
        json!({"bridge": true, "store": true, "relay": false}),
    );
    let doctor = p.cli(&["doctor"]);
    let out = String::from_utf8_lossy(&doctor.stdout);
    assert!(
        out.contains("policy bridge=true store=true relay=false"),
        "{out}"
    );
    // LAN off and on again, as `raven lan off|on` (the CLI reads it).
    let off = p.ok("network.set", json!({"lan": false}));
    assert_eq!(carrier_of(&off["status"], "lan")["state"], "off", "{off}");
    assert!(
        raven_core::node_policy::try_load_policy(&p.path)
            .unwrap()
            .lan_off
    );
    let on = p.ok("network.set", json!({"lan": true}));
    assert_eq!(carrier_of(&on["status"], "lan")["state"], "on", "{on}");
    // Hide my IP, as `raven node hide-ip`.
    p.ok("network.set", json!({"hide_ip": true}));
    assert!(
        raven_core::node_policy::try_load_policy(&p.path)
            .unwrap()
            .hide_ip
    );
    assert_eq!(p.ok("network.status", json!({}))["hide_ip"], true);
    // Nothing to set, or a wrong type: BAD_REQUEST, nothing changed.
    assert_eq!(p.err("network.set", json!({})), "BAD_REQUEST");
    assert_eq!(p.err("network.set", json!({"store": "yes"})), "BAD_REQUEST");
}

/// Without a lab switch a debug engine holds what a release holds: since
/// 2026-10 the field-tested ways are released (off until the person turns
/// one on, or on by themselves), Bluetooth nearby on macOS only; every other
/// way is `preview`, turning one on is NOT_AVAILABLE_YET and changes
/// nothing, turning one off is fine; the Phase 6 views say they are not in
/// this version.
#[test]
fn held_ways_are_preview_and_refused_without_a_lab_switch() {
    if !binaries_ready() {
        return;
    }
    let p = Peer::new("Held");
    let net = p.ok("network.status", json!({}));
    let released = [
        "lan",
        "internet",
        "port_mapping",
        "p2p",
        "friend_relay",
        "custody",
        "route_hints",
        "tor",
    ];
    for c in net["carriers"]
        .as_array()
        .unwrap()
        .iter()
        .chain(net["protections"].as_array().unwrap())
    {
        let id = c["id"].as_str().unwrap();
        let nearby_here = cfg!(any(
            target_os = "macos",
            windows,
            all(target_os = "linux", target_env = "gnu")
        ));
        if id == "nearby" && !nearby_here {
            assert_eq!(c["state"], "not_on_this_os", "{c}");
        } else if released.contains(&id) || (id == "nearby" && cfg!(target_os = "macos")) {
            assert_ne!(c["state"], "preview", "{c}");
            assert_ne!(c["state"], "lab", "{c}");
        } else {
            assert_eq!(c["state"], "preview", "{c}");
        }
        assert_eq!(c["lab"], false, "{c}");
    }
    assert_eq!(carrier_of(&net, "lan")["state"], "on", "{net}");
    let node = p.ok("node.status", json!({}));
    assert_eq!(node["lab"], json!([]), "{node}");
    assert_eq!(node["lab_switches"], json!([]), "{node}");
    let before = std::fs::read(p.path.join("node_policy.json")).ok();
    let mut held = vec![
        json!({"proxy": "auto"}),
        json!({"handoff": true, "agreed": true}),
        // One held way among allowed ones: nothing at all is changed.
        json!({"bridge": false, "handoff": true, "agreed": true}),
    ];
    if !cfg!(target_os = "macos") {
        held.push(json!({"nearby": true}));
    }
    for on in held {
        assert_eq!(
            p.err("network.set", on.clone()),
            "NOT_AVAILABLE_YET",
            "{on}"
        );
    }
    assert_eq!(
        std::fs::read(p.path.join("node_policy.json")).ok(),
        before,
        "a refusal changed node_policy.json"
    );
    // A released way turns on as the CLI turns it on (node_policy.json).
    p.ok("network.set", json!({"p2p": true}));
    let policy = raven_core::node_policy::try_load_policy(&p.path).unwrap();
    assert!(!policy.p2p_listen.trim().is_empty(), "{policy:?}");
    // Turning a held way off is no change of carrier: allowed.
    let off = p.ok("network.set", json!({"p2p": false, "proxy": "off"}));
    assert_eq!(off["changes"].as_array().unwrap().len(), 2, "{off}");
    // Lock v2, security notices and updates: not in this version.
    assert_eq!(p.err("lock.now", json!({})), "NOT_AVAILABLE_YET");
    assert_eq!(p.err("lock.unlock", json!({})), "NOT_AVAILABLE_YET");
    let lock = p.ok("lock.state", json!({}));
    assert_eq!(lock["available"], false, "{lock}");
    assert_eq!(lock["locked"], false, "{lock}");
    let sec = p.ok("security.status", json!({}));
    assert_eq!(sec["available"], false, "{sec}");
    assert_eq!(sec["kept"], "off", "{sec}");
    let upd = p.ok("updates.status", json!({}));
    assert_eq!(upd["available"], false, "{upd}");
    assert_eq!(upd["install"], "cli_only", "{upd}");
    assert!(!upd["lines"].as_array().unwrap().is_empty(), "{upd}");
}
