//! Tor through the engine API, as a phone or the macOS app sends: friends
//! reached only over the onion carrier, on the loopback Tor helper (no Tor
//! network; every connect takes as long as a warm Tor rendezvous).
//!
//! Needs the raven-node and raven that `cargo build` puts next to the test
//! binaries' folder; without them the test says so and passes.

mod common;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use common::net::{binaries_ready, Peer};
use serde_json::{json, Value};

/// How long one connect through the loopback helper takes, in ms (a warm
/// Tor link in the field).
const RENDEZVOUS_MS: &str = "1500";

/// `p`'s card once its node signed its onion binding (`onion=` in it).
fn onion_card(p: &Peer) -> String {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let card = p.ok("card.make", json!({}))["card"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if card.contains(" onion=") {
            return card;
        }
        assert!(
            Instant::now() < deadline,
            "{}: no onion= in its card: {card}\n{}",
            p.name,
            p.service_log()
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn wait_tor_ready(p: &Peer) {
    let deadline = Instant::now() + Duration::from_secs(90);
    while p.carrier("tor")["running"] != true {
        assert!(
            Instant::now() < deadline,
            "{}: Tor never ready\n{}",
            p.name,
            p.service_log()
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn send(p: &Peer, friend: &Peer, text: &str) -> String {
    let sent = p.ok(
        "messages.send",
        json!({"address": friend.address(), "text": text}),
    );
    sent["message"]["id"].as_str().unwrap().to_owned()
}

/// Message `id` to `friend`, as `messages.history` says.
fn message(p: &Peer, friend: &Peer, id: &str) -> Option<Value> {
    let history = p.ok(
        "messages.history",
        json!({"address": friend.address(), "limit": 50}),
    );
    history["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == id)
        .cloned()
}

/// The owner's four-device test (2026-11-01): a message to one friend over
/// Tor, and at once one to another friend over Tor. Both are delivered, one
/// after the other, each about as fast as one send alone, and neither turns
/// `waiting` because of the other. Each send's Tor check reads the friend's
/// route hints only when it asked for them, so it never sits out Tor's 5 s
/// reply wait for one that is not due (it did: 7.6 s per check, not 2.6 s).
#[test]
fn tor_sends_to_two_friends_one_after_the_other_both_deliver_at_once() {
    if !binaries_ready() {
        return;
    }
    if !cfg!(debug_assertions) {
        eprintln!("skipped: the loopback Tor helper is in debug builds only");
        return;
    }
    common::lab_env();
    let registry = common::short_dir();
    std::env::set_var("RAVEN_LAB_TOR", "1");
    std::env::set_var("RAVEN_LAB_TOR_LOOPBACK", registry.path());
    std::env::set_var("RAVEN_LAB_TOR_LOOPBACK_DELAY_MS", RENDEZVOUS_MS);
    let a = Peer::new("Tor A");
    let b = Peer::new("Tor B");
    let c = Peer::new("Tor C");
    for p in [&a, &b, &c] {
        p.start();
    }
    for p in [&a, &b, &c] {
        wait_tor_ready(p);
    }
    let (card_a, card_b, card_c) = (onion_card(&a), onion_card(&b), onion_card(&c));
    // Only Tor reaches them: their cards name no LAN or Internet address.
    for card in [&card_a, &card_b, &card_c] {
        assert!(
            !card.contains(" lan=") && !card.contains(" inet="),
            "{card}"
        );
    }
    a.befriend(&b, Some(&card_b));
    a.befriend(&c, Some(&card_c));
    b.befriend(&a, Some(&card_a));
    c.befriend(&a, Some(&card_a));

    // A first message to each: the connection set up over Tor.
    for (friend, text) in [(&b, "hello B over tor"), (&c, "hello C over tor")] {
        let m = a.send_until(
            friend,
            text,
            &["delivered", "failed", "not_sent_meet_first"],
            Duration::from_secs(180),
        );
        assert_eq!(m["state"], "delivered", "{m}\n{}", a.service_log());
        assert!(friend.wait_incoming(&a, text, Duration::from_secs(60)));
    }
    // A warm Tor link: one send alone.
    let began = Instant::now();
    let m = a.send_until(
        &b,
        "one alone",
        &["delivered", "waiting", "failed"],
        Duration::from_secs(120),
    );
    let alone = began.elapsed();
    assert_eq!(m["state"], "delivered", "{m}\n{}", a.service_log());

    // The owner's steps: send to B, go to C's chat, send to C.
    let began = Instant::now();
    let to_b = send(&a, &b, "first to B");
    std::thread::sleep(Duration::from_millis(400));
    let to_c = send(&a, &c, "then to C");
    let mut seen: HashMap<String, Vec<String>> = HashMap::new();
    let mut done: HashMap<String, Duration> = HashMap::new();
    let limit = Duration::from_secs(150);
    let mut after = 0;
    while done.len() < 2 {
        let batch = a.ok("events.poll", json!({"after_seq": after}));
        after = batch["seq"].as_u64().unwrap();
        for (friend, id) in [(&b, &to_b), (&c, &to_c)] {
            if done.contains_key(id.as_str()) {
                continue;
            }
            let Some(m) = message(&a, friend, id) else {
                continue;
            };
            let state = m["state"].as_str().unwrap_or("").to_owned();
            let states = seen.entry(id.clone()).or_default();
            if states.last() != Some(&state) {
                states.push(state.clone());
            }
            if matches!(state.as_str(), "delivered" | "failed" | "time_ran_out") {
                done.insert(id.clone(), began.elapsed());
            }
        }
        assert!(
            began.elapsed() < limit,
            "not both delivered in {limit:?}: {seen:?}\n{}",
            a.service_log()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    for id in [&to_b, &to_c] {
        let states = &seen[id.as_str()];
        assert_eq!(
            states.last().map(String::as_str),
            Some("delivered"),
            "{id}: {states:?}\n{}",
            a.service_log()
        );
        assert!(
            !states.iter().any(|s| s == "waiting"),
            "{id} went waiting: {seen:?} (one send alone took {alone:?})\n{}",
            a.service_log()
        );
    }
    // The engine sends one after the other: the second ends within two
    // sends alone, with room for a slow machine, but well inside one Tor
    // reply wait more per check.
    let first = done[to_b.as_str()];
    let both = done[to_c.as_str()];
    assert!(
        first < alone + Duration::from_secs(4),
        "the first took {first:?}, one alone {alone:?}: {seen:?}"
    );
    assert!(
        both < alone * 2 + Duration::from_secs(6),
        "both took {both:?}, one alone {alone:?}: {seen:?}"
    );
    assert!(b.wait_incoming(&a, "first to B", Duration::from_secs(30)));
    assert!(c.wait_incoming(&a, "then to C", Duration::from_secs(30)));
}
