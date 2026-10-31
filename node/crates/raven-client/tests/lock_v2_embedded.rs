//! Lock v2 in the app's own process (docs/IOS.md): the iPhone app's launch
//! while it says asleep. `lock.now` with the embedded node stopped holds
//! the lock in the process: the engine loads no key and queues no event,
//! and the next `node.start` (or a `node.resume` after a pause) starts the
//! node locked, a keychain profile too; `lock.unlock` then opens both. An
//! unlock with the node still stopped or paused starts it first. Lab
//! switches for this test binary only: `RAVEN_LAB_TEST_A=1` and
//! `RAVEN_LAB_LOCAL_PROTECTION=1`. The node listens on 127.0.0.1, any free
//! port; there is no raven-node program to find.

mod common;

use raven_client::Client;
use serde_json::json;

#[test]
fn a_lock_while_the_embedded_node_is_stopped_starts_it_locked() {
    if !cfg!(debug_assertions) {
        eprintln!("skipped: a release engine reads no lab switch");
        return;
    }
    common::lab_env();
    std::env::set_var(raven_client::NODE_MODE_ENV, "embedded");
    std::env::set_var(raven_client::NODE_PROGRAM_ENV, "/nonexistent/raven-node");
    std::env::set_var("RAVEN_LAB_TEST_A", "1");
    std::env::set_var(raven_core::security_gate::LAB_LOCAL_PROTECTION, "1");
    let root = common::short_dir();
    let c = Client::with_data_dir(root.path().join("a"));
    common::ok(&c, "settings.set", json!({"receive": false}));
    common::ok(&c, "identity.create", json!({"display_name": "Sleeper"}));

    // The launch while asleep: the lock comes before anything loads.
    let locked = common::ok(&c, "lock.now", json!({}));
    assert_eq!(locked["locked"], true, "{locked}");
    assert_eq!(locked["supported"], true, "{locked}");
    let state = common::ok(&c, "profile.state", json!({}));
    assert_eq!(state["state"], "locked", "{state}");
    let poll = common::ok(&c, "events.poll", json!({"after_seq": 0}));
    assert_eq!(poll["locked"], true, "{poll}");
    assert_eq!(common::err(&c, "identity.me", json!({})), "PROFILE_LOCKED");
    // The wake after Face ID, with no node yet (the iPhone app starts none
    // while asleep): the unlock starts the node locked, then opens it.
    let opened = common::ok(&c, "lock.unlock", json!({}));
    assert_eq!(opened["locked"], false, "{opened}");
    let st = common::ok(&c, "node.status", json!({}));
    assert_eq!(st["running"], true, "{st}");
    assert_eq!(st["embedded"], true, "{st}");
    assert!(common::ok(&c, "identity.me", json!({}))["address"].is_string());

    // Stopped and locked again: the start finds the lock, the node runs
    // locked.
    common::ok(&c, "node.stop", json!({}));
    assert_eq!(common::ok(&c, "lock.now", json!({}))["locked"], true);
    let st = common::ok(&c, "node.start", json!({}));
    assert_eq!(st["running"], true, "{st}");
    assert_eq!(st["embedded"], true, "{st}");
    assert_eq!(common::ok(&c, "lock.state", json!({}))["locked"], true);
    assert_eq!(common::err(&c, "identity.me", json!({})), "PROFILE_LOCKED");

    let opened = common::ok(&c, "lock.unlock", json!({}));
    assert_eq!(opened["locked"], false, "{opened}");
    assert!(common::ok(&c, "identity.me", json!({}))["address"].is_string());

    // Paused (the app in the background), locked meanwhile, resumed: the
    // node starts locked again.
    common::ok(&c, "node.pause", json!({}));
    assert_eq!(common::ok(&c, "lock.now", json!({}))["locked"], true);
    let st = common::ok(&c, "node.resume", json!({}));
    assert_eq!(st["running"], true, "{st}");
    assert_eq!(common::ok(&c, "lock.state", json!({}))["locked"], true);
    assert_eq!(common::ok(&c, "lock.unlock", json!({}))["locked"], false);

    // Paused and locked, then unlocked before any resume: the pause ends
    // and the node runs open.
    common::ok(&c, "node.pause", json!({}));
    assert_eq!(common::ok(&c, "lock.now", json!({}))["locked"], true);
    assert_eq!(common::ok(&c, "lock.unlock", json!({}))["locked"], false);
    assert_eq!(common::ok(&c, "node.status", json!({}))["running"], true);
    assert!(common::ok(&c, "identity.me", json!({}))["address"].is_string());
    common::ok(&c, "node.stop", json!({}));
}
