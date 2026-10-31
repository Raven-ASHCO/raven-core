//! Lock v2 through the engine API (desktop/api/API.md "Security, Lock and
//! updates"; its gate, `LOCAL_PROTECTION`, is shut in every release build):
//! a lock lets go of the engine's identity and of every event not read yet
//! (an `incoming` event carries a message's text), refuses every op that
//! reads the profile with PROFILE_LOCKED and queues no event; an unlock
//! brings them back, and `events.poll` says `reset` once. A lock and an
//! unlock made by the CLI are followed too. The Raven passphrase ops say
//! where they do not apply. Lab switches for this test binary only:
//! `RAVEN_LAB_TEST_A=1` and `RAVEN_LAB_LOCAL_PROTECTION=1`. Every node
//! listens on 127.0.0.1, any free port.
//!
//! Needs the raven-node and raven that `cargo build` puts next to the test
//! binaries' folder; without them the test says so and passes.

mod common;

use std::time::{Duration, Instant};

use common::net::{binaries_ready, Peer};
use common::{all_text, events_until};
use serde_json::{json, Value};

/// The message the reader's engine holds when the lock comes.
const BEFORE: &str = "written before the lock";

fn has_incoming(events: &[Value], text: &str) -> bool {
    events
        .iter()
        .any(|e| e["kind"] == "incoming" && e["message"]["text"] == text)
}

/// Polls `events.poll` from `after` (up to `limit`) until `done` says so
/// of one answer; that answer.
fn poll_until(p: &Peer, after: u64, limit: Duration, done: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + limit;
    loop {
        let poll = p.ok("events.poll", json!({"after_seq": after}));
        if done(&poll) {
            return poll;
        }
        assert!(Instant::now() < deadline, "{}: {poll}", p.name);
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[test]
fn a_lock_lets_go_of_the_identity_and_the_events_until_the_unlock() {
    if !binaries_ready() {
        return;
    }
    if !cfg!(debug_assertions) {
        eprintln!("skipped: a release engine reads no lab switch (tests/net_gates.rs)");
        return;
    }
    common::lab_env();
    std::env::set_var("RAVEN_LAB_TEST_A", "1");
    std::env::set_var(raven_core::security_gate::LAB_LOCAL_PROTECTION, "1");
    let a = Peer::new("Writer");
    let b = Peer::new("Reader");

    // The Raven passphrase: the lab's file backends take none, and the ops
    // say so (on a real profile: Windows, iPhone and keyring profiles the
    // same way). No passphrase comes back in any answer.
    let pass = b.ok("lock.passphrase_state", json!({}));
    assert_eq!(pass["available"], true, "{pass}");
    assert_eq!(pass["lab"], true, "{pass}");
    assert_eq!(pass["offer"], "none", "{pass}");
    assert_eq!(pass["why"], "lab_files", "{pass}");
    assert_eq!(pass["has_passphrase"], false, "{pass}");
    for (op, args) in [
        (
            "lock.set_passphrase",
            json!({"new": "a long new passphrase"}),
        ),
        (
            "lock.set_passphrase",
            json!({"new": "a long new passphrase", "old": "the old passphrase"}),
        ),
        (
            "lock.remove_passphrase",
            json!({"old": "the old passphrase"}),
        ),
    ] {
        let r = common::raw(&b.client, op, args);
        assert_eq!(r["error"]["code"], "NOT_ON_THIS_SYSTEM", "{op}: {r}");
        let text = all_text(&r);
        assert!(!text.contains("a long new") && !text.contains("the old passphrase"));
    }
    assert_eq!(b.err("lock.set_passphrase", json!({})), "BAD_REQUEST");
    assert_eq!(b.err("lock.remove_passphrase", json!({})), "BAD_REQUEST");

    a.befriend(&b, None);
    b.befriend(&a, None);
    let lb = b.start();
    a.set_lan(&b, &lb);
    assert_eq!(b.ok("lock.state", json!({}))["supported"], true);

    // B's watcher had its first look (it only notes what is there), so a
    // message that comes now is an `incoming` event, its text in it.
    let mut after = 0;
    events_until(&b.client, &mut after, Duration::from_secs(20), |ev| {
        ev.iter().any(|e| e["kind"] == "status_ok")
    });
    std::thread::sleep(Duration::from_millis(1500));
    let m = a.send_until(
        &b,
        BEFORE,
        &["delivered", "failed"],
        Duration::from_secs(90),
    );
    assert_eq!(m["state"], "delivered", "{m}");
    let seen = events_until(&b.client, &mut after, Duration::from_secs(20), |ev| {
        has_incoming(ev, BEFORE)
    });
    assert!(has_incoming(&seen, BEFORE), "{seen:?}");
    let all = b.ok("events.poll", json!({"after_seq": 0}));
    assert!(has_incoming(all["events"].as_array().unwrap(), BEFORE));

    // The lock: the queue goes, nothing reads the profile, the node stays.
    let locked = b.ok("lock.now", json!({}));
    assert_eq!(locked["locked"], true, "{locked}");
    let poll = b.ok("events.poll", json!({"after_seq": 0}));
    assert_eq!(poll["locked"], true, "{poll}");
    assert_eq!(poll["events"], json!([]), "{poll}");
    assert!(!all_text(&poll).contains(BEFORE), "{poll}");
    for (op, args) in [
        ("identity.me", json!({})),
        ("contacts.list", json!({})),
        ("chats.list", json!({})),
        (
            "messages.history",
            json!({"address": a.address(), "limit": 10}),
        ),
        (
            "messages.send",
            json!({"address": a.address(), "text": "not while locked"}),
        ),
        ("card.make", json!({"include_address": false})),
        ("network.status", json!({})),
        (
            "lock.set_passphrase",
            json!({"new": "a long new passphrase"}),
        ),
    ] {
        assert_eq!(b.err(op, args), "PROFILE_LOCKED", "{op}");
    }
    let state = b.ok("profile.state", json!({}));
    assert_eq!(state["state"], "locked", "{state}");
    assert_eq!(state["lock_v2"], true, "{state}");
    assert_eq!(b.ok("node.status", json!({}))["running"], true);
    assert_eq!(b.ok("lock.state", json!({}))["locked"], true);
    assert_eq!(b.ok("lock.passphrase_state", json!({}))["offer"], "none");
    // A few beats of the watcher: still nothing is queued.
    std::thread::sleep(Duration::from_millis(2500));
    let poll = b.ok("events.poll", json!({"after_seq": 0}));
    assert_eq!(poll["events"], json!([]), "{poll}");
    let locked_seq = poll["seq"].as_u64().unwrap();

    // The unlock: one reset, then the profile reads as before.
    let opened = b.ok("lock.unlock", json!({}));
    assert_eq!(opened["locked"], false, "{opened}");
    let poll = b.ok("events.poll", json!({"after_seq": locked_seq}));
    assert_eq!(poll["reset"], true, "{poll}");
    assert!(poll.get("locked").is_none(), "{poll}");
    assert!(!has_incoming(poll["events"].as_array().unwrap(), BEFORE));
    assert_eq!(b.ok("profile.state", json!({}))["state"], "ready");
    assert_eq!(b.ok("identity.me", json!({}))["address"], b.me["address"]);
    assert!(b.wait_incoming(&a, BEFORE, Duration::from_secs(10)));

    // A lock and an unlock made elsewhere (the CLI): the engine follows at
    // its watcher's next beat.
    let out = b.cli(&["lock", "--yes"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let after = poll["seq"].as_u64().unwrap();
    let poll = poll_until(&b, after, Duration::from_secs(20), |p| p["locked"] == true);
    assert_eq!(poll["events"], json!([]), "{poll}");
    assert_eq!(b.err("contacts.list", json!({})), "PROFILE_LOCKED");
    let out = b.cli(&["unlock"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let seq = poll["seq"].as_u64().unwrap();
    let poll = poll_until(&b, seq, Duration::from_secs(20), |p| {
        p.get("locked").is_none()
    });
    assert_eq!(poll["reset"], true, "{poll}");
    assert!(b.wait_incoming(&a, BEFORE, Duration::from_secs(10)));
}
