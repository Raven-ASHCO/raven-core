//! Groups through three real raven-node processes on 127.0.0.1 (design
//! docs/design/2026-10-groups.md §10, the harness row): A and C are not
//! friends, both are B's. B (the admin) creates the group; A's message
//! reaches C only through B's forward, C verifies A's signature with A's key
//! from B's roster and stores it exactly once, and A sees C delivered by
//! C's signed receipt (passed back by B).
//!
//! Lab switches for this process and the raven-nodes it starts:
//! `RAVEN_LAB_TEST_A=1 RAVEN_LAB_HORIZON=1 RAVEN_LAB_GROUPS=1` (one test
//! binary of its own: the variables are process-wide). Needs the raven-node
//! `cargo build` puts next to the test binaries' folder; without it the test
//! says so and passes.

mod common;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use raven_client::Client;
use serde_json::{json, Value};

use common::{ok, short_dir, NodeGuard};

struct Profile {
    _dir: tempfile::TempDir,
    path: PathBuf,
    client: Client,
    me: Value,
}

fn profile(name: &str) -> Profile {
    let dir = short_dir();
    let path = dir.path().join("p");
    let client = Client::with_data_dir(&path);
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

fn guard(p: &Profile) -> NodeGuard {
    NodeGuard {
        client: p.client.clone(),
        dir: p.path.clone(),
    }
}

/// `who` saves `friend` as `name`, verified (the words checked).
fn befriend(who: &Profile, friend: &Profile, name: &str) {
    ok(
        &who.client,
        "contacts.add",
        json!({"text": friend.me["invite"], "name": name}),
    );
    let checked = ok(
        &who.client,
        "verify.check_words",
        json!({"address": friend.me["address"], "words": friend.me["words"]}),
    );
    assert_eq!(checked["result"], "match", "{checked}");
}

fn start(p: &Profile) -> String {
    let started = ok(&p.client, "node.start", json!({}));
    assert_eq!(started["running"], true, "{started}");
    started["listening"].as_str().expect("listening").to_owned()
}

/// Polls `check` every 250 ms until it returns `Some` or `limit` runs out.
fn wait_for<T>(limit: Duration, what: &str, mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(found) = check() {
            return found;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn history(p: &Profile, group: &str) -> Vec<Value> {
    ok(&p.client, "groups.history", json!({"group": group}))["messages"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

#[test]
fn a_message_reaches_a_non_friend_through_the_admins_forward_exactly_once() {
    common::lab_env();
    if common::raven_node().is_none() {
        eprintln!("skipped: raven-node is not built (run `cargo build` in node/)");
        return;
    }
    if !cfg!(debug_assertions) {
        eprintln!("skipped: the lab switches need a debug build");
        return;
    }
    for switch in ["RAVEN_LAB_TEST_A", "RAVEN_LAB_HORIZON", "RAVEN_LAB_GROUPS"] {
        std::env::set_var(switch, "1");
    }
    let a = profile("Desk A");
    let b = profile("Desk B");
    let c = profile("Desk C");
    let _guards = [guard(&a), guard(&b), guard(&c)];
    // B is friends with both; A and C only with B.
    befriend(&a, &b, "Friend B");
    befriend(&b, &a, "Friend A");
    befriend(&b, &c, "Friend C");
    befriend(&c, &b, "Friend B");
    let (a_at, b_at, c_at) = (start(&a), start(&b), start(&c));
    for (who, friend, at) in [
        (&a, &b, &b_at),
        (&b, &a, &a_at),
        (&b, &c, &c_at),
        (&c, &b, &b_at),
    ] {
        ok(
            &who.client,
            "contacts.set_address",
            json!({"address": friend.me["address"], "lan": at}),
        );
    }
    let available = ok(&a.client, "groups.list", json!({}));
    assert_eq!(available["available"], true, "{available}");

    // B creates the group: the roster goes to A and C.
    let created = ok(
        &b.client,
        "groups.create",
        json!({"name": "Trio", "members": [a.me["address"], c.me["address"]]}),
    );
    let group = created["group"]["id"].as_str().unwrap().to_owned();
    assert_eq!(created["group"]["admin"], true, "{created}");
    assert_eq!(created["members"].as_array().unwrap().len(), 3);
    for p in [&a, &c] {
        wait_for(Duration::from_secs(120), "the roster to arrive", || {
            let list = ok(&p.client, "groups.list", json!({}));
            list["groups"]
                .as_array()
                .unwrap()
                .iter()
                .any(|g| g["id"] == group.as_str())
                .then_some(())
        });
    }
    // A sees C as a member named by the admin, not as a friend.
    let a_view = ok(&a.client, "groups.get", json!({"group": group}));
    let c_seen = a_view["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["address"] == c.me["address"])
        .cloned()
        .unwrap_or_else(|| panic!("{a_view}"));
    assert_eq!(c_seen["friend"], false, "{a_view}");
    assert_eq!(c_seen["name"], "Friend C", "the admin's label: {a_view}");

    // A writes; it seals one copy (for B) and B passes it on to C.
    let mut c_after = ok(&c.client, "events.poll", json!({"after_seq": 0}))["seq"]
        .as_u64()
        .unwrap();
    let text = "hello from A to the trio";
    let sent = ok(
        &a.client,
        "groups.send",
        json!({"group": group, "text": text}),
    );
    let id = sent["message"]["id"].as_str().unwrap().to_owned();
    assert_eq!(sent["message"]["total"], 2, "{sent}");
    let receipts = sent["message"]["receipts"].as_array().unwrap().clone();
    let via_of = |addr: &Value| {
        receipts
            .iter()
            .find(|r| r["address"] == *addr)
            .map(|r| r["via"].as_str().unwrap().to_owned())
    };
    assert_eq!(via_of(&b.me["address"]).as_deref(), Some("direct"));
    assert_eq!(via_of(&c.me["address"]).as_deref(), Some("relay"));

    let at_c = wait_for(Duration::from_secs(180), "C to get A's message", || {
        history(&c, &group)
            .into_iter()
            .find(|m| m["id"] == id.as_str())
    });
    assert_eq!(at_c["text"], text);
    assert_eq!(at_c["from_address"], a.me["address"], "{at_c}");
    assert_eq!(at_c["via_name"], "Friend B", "passed on by B: {at_c}");
    assert_eq!(at_c["mine"], false);
    // B has it too, straight from A.
    let at_b = wait_for(Duration::from_secs(60), "B to hold A's message", || {
        history(&b, &group)
            .into_iter()
            .find(|m| m["id"] == id.as_str())
    });
    assert!(at_b.get("via_name").is_none(), "{at_b}");

    // A sees both delivered: B by the pairwise receipt, C by C's signed
    // group receipt that B passed back.
    let mine = wait_for(Duration::from_secs(180), "A's receipts", || {
        history(&a, &group)
            .into_iter()
            .find(|m| m["id"] == id.as_str() && m["delivered"] == 2)
    });
    assert_eq!(mine["total"], 2, "{mine}");

    // Exactly once at C: one row, one group_message event, after more time
    // for any second copy to show.
    std::thread::sleep(Duration::from_secs(5));
    let copies = history(&c, &group)
        .into_iter()
        .filter(|m| m["text"] == text)
        .count();
    assert_eq!(copies, 1);
    let events = common::events_until(&c.client, &mut c_after, Duration::from_secs(3), |_| false);
    let arrivals = events
        .iter()
        .filter(|e| e["kind"] == "group_message" && e["message"]["id"] == id.as_str())
        .count();
    assert_eq!(arrivals, 1, "{events:#?}");
    // Group copies never show in a 1:1 chat.
    for (p, friend) in [(&a, &b), (&b, &c), (&c, &b)] {
        let chat = ok(
            &p.client,
            "messages.history",
            json!({"address": friend.me["address"]}),
        );
        let all = common::all_text(&chat);
        assert!(!all.contains("RVNGRP"), "{chat}");
    }
}
