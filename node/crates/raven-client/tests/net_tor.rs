//! Tor through the engine API, as a phone or the macOS app sends: friends
//! reached only over the onion carrier, on the loopback Tor helper (no Tor
//! network; every connect takes as long as a warm Tor rendezvous).
//!
//! Needs the raven-node and raven that `cargo build` puts next to the test
//! binaries' folder; without them the test says so and passes.

mod common;

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use common::net::{binaries_ready, Peer};
use serde_json::{json, Value};

/// How long one connect through the loopback helper takes, in ms (a warm
/// Tor link in the field).
const RENDEZVOUS_MS: &str = "1500";
/// A slower Tor for the tests that tell "side by side" from "one after
/// the other" (connect ms, one-way ms): a send alone takes about 7 s, so
/// one that waits for another takes about 14.
const SLOW_TOR: (&str, &str) = ("2500", "150");

/// One test at a time: each starts its own raven-nodes, and their timings
/// are what the tests measure.
static SERIAL: Mutex<()> = Mutex::new(());

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

/// Profiles named `names`, each with its raven-node started and Tor ready
/// on the loopback helper (one registry for the whole test binary), and
/// their cards: only Tor reaches them (no LAN or Internet address).
fn tor_peers(names: &[&str]) -> (Vec<Peer>, Vec<String>) {
    let plan: Vec<(&str, &str, &str)> = names.iter().map(|n| (*n, RENDEZVOUS_MS, "0")).collect();
    tor_peers_with(&plan)
}

/// [`tor_peers`] with each profile's own Tor: (name, connect ms, one-way
/// latency ms): every connect its Tor helper makes takes that long, and
/// each byte on those streams arrives that much later.
fn tor_peers_with(plan: &[(&str, &str, &str)]) -> (Vec<Peer>, Vec<String>) {
    static REGISTRY: OnceLock<tempfile::TempDir> = OnceLock::new();
    common::lab_env();
    let registry = REGISTRY.get_or_init(common::short_dir);
    std::env::set_var("RAVEN_LAB_TOR", "1");
    std::env::set_var("RAVEN_LAB_TOR_LOOPBACK", registry.path());
    // As Arti does: a helper's streams to one onion service share one
    // rendezvous circuit, which the service side counts as one source.
    std::env::set_var("RAVEN_LAB_TOR_LOOPBACK_ONE_CIRCUIT", "1");
    let peers: Vec<Peer> = plan.iter().map(|(n, _, _)| Peer::new(n)).collect();
    for (p, (_, delay, latency)) in peers.iter().zip(plan) {
        // The helper the node starts reads them at its start.
        std::env::set_var("RAVEN_LAB_TOR_LOOPBACK_DELAY_MS", delay);
        std::env::set_var("RAVEN_LAB_TOR_LOOPBACK_LATENCY_MS", latency);
        p.start();
    }
    std::env::set_var("RAVEN_LAB_TOR_LOOPBACK_DELAY_MS", RENDEZVOUS_MS);
    std::env::set_var("RAVEN_LAB_TOR_LOOPBACK_LATENCY_MS", "0");
    for p in &peers {
        wait_tor_ready(p);
    }
    let cards: Vec<String> = peers.iter().map(onion_card).collect();
    for card in &cards {
        assert!(
            !card.contains(" lan=") && !card.contains(" inet="),
            "{card}"
        );
    }
    (peers, cards)
}

/// Whether this build can run the loopback Tor tests (it says why not).
fn tor_lab_ready() -> bool {
    if !binaries_ready() {
        return false;
    }
    if !cfg!(debug_assertions) {
        eprintln!("skipped: the loopback Tor helper is in debug builds only");
        return false;
    }
    true
}

/// `p`'s first message to `friend`, which sets the connection up over Tor,
/// and its arrival there.
fn first_message(p: &Peer, friend: &Peer, text: &str) {
    let m = p.send_until(
        friend,
        text,
        &["delivered", "failed", "not_sent_meet_first"],
        Duration::from_secs(180),
    );
    assert_eq!(m["state"], "delivered", "{m}\n{}", p.service_log());
    assert!(friend.wait_incoming(p, text, Duration::from_secs(60)));
}

/// One send from `p` to `friend` over a warm Tor link, alone: how long
/// it took to be delivered.
fn one_alone(p: &Peer, friend: &Peer, text: &str) -> Duration {
    let began = Instant::now();
    let m = p.send_until(
        friend,
        text,
        &["delivered", "waiting", "failed"],
        Duration::from_secs(120),
    );
    let took = began.elapsed();
    assert_eq!(m["state"], "delivered", "{m}\n{}", p.service_log());
    took
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

/// Whether `p` has a message from `friend` with `text`.
fn has_incoming(p: &Peer, friend: &Peer, text: &str) -> bool {
    let history = p.ok(
        "messages.history",
        json!({"address": friend.address(), "limit": 50}),
    );
    history["messages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["direction"] == "in" && m["text"] == text)
}

/// A send to follow: `from`'s message `text` (id `id`) to `to`.
struct Out<'a> {
    from: &'a Peer,
    to: &'a Peer,
    text: String,
    id: String,
}

/// What [`watch`] saw of one send.
#[derive(Debug, Default, Clone)]
struct Seen {
    /// Its states, in the order they showed.
    states: Vec<String>,
    /// When it ended (delivered, failed, time ran out), since the start.
    ended: Option<Duration>,
    /// When its text showed in the friend's chat, since the start.
    arrived: Option<Duration>,
}

/// Starts every send of `plan` (from, to, text) at once, then follows each
/// one, on its sender's side and in its friend's chat, until every one
/// ended and arrived (or `limit`). Keyed by text.
fn sends_at_once<'a>(
    plan: &[(&'a Peer, &'a Peer, &str)],
    limit: Duration,
) -> (HashMap<String, Seen>, Instant) {
    let began = Instant::now();
    let outs: Vec<Out<'a>> = plan
        .iter()
        .map(|(from, to, text)| Out {
            from,
            to,
            text: (*text).to_owned(),
            id: send(from, to, text),
        })
        .collect();
    let seen = watch(&outs, began, limit);
    (seen, began)
}

fn watch(outs: &[Out<'_>], began: Instant, limit: Duration) -> HashMap<String, Seen> {
    let mut seen: HashMap<String, Seen> = outs
        .iter()
        .map(|o| (o.text.clone(), Seen::default()))
        .collect();
    // Polling keeps every engine's watcher running.
    let mut after: HashMap<String, u64> = HashMap::new();
    loop {
        for o in outs {
            for p in [o.from, o.to] {
                let seq = after.entry(p.name.clone()).or_insert(0);
                let batch = p.ok("events.poll", json!({"after_seq": *seq}));
                *seq = batch["seq"].as_u64().unwrap();
            }
        }
        for o in outs {
            let s = seen.get_mut(&o.text).unwrap();
            if s.ended.is_none() {
                if let Some(m) = message(o.from, o.to, &o.id) {
                    let state = m["state"].as_str().unwrap_or("").to_owned();
                    if s.states.last() != Some(&state) {
                        s.states.push(state.clone());
                    }
                    if matches!(state.as_str(), "delivered" | "failed" | "time_ran_out") {
                        s.ended = Some(began.elapsed());
                    }
                }
            }
            if s.arrived.is_none() && has_incoming(o.to, o.from, &o.text) {
                s.arrived = Some(began.elapsed());
            }
        }
        if seen
            .values()
            .all(|s| s.ended.is_some() && s.arrived.is_some())
            || began.elapsed() > limit
        {
            return seen;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

/// Every send of `seen` was delivered, never waiting, and arrived.
fn all_delivered(seen: &HashMap<String, Seen>, alone: Duration, logs: &[&Peer]) {
    let logs = || {
        logs.iter()
            .map(|p| format!("--- {} ---\n{}", p.name, p.service_log()))
            .collect::<Vec<_>>()
            .join("\n")
    };
    for (text, s) in seen {
        assert_eq!(
            s.states.last().map(String::as_str),
            Some("delivered"),
            "{text}: {s:?} (one send alone took {alone:?})\nall: {seen:#?}\n{}",
            logs()
        );
        assert!(
            !s.states.iter().any(|st| st == "waiting"),
            "{text} went waiting: {s:?} (one send alone took {alone:?})\nall: {seen:#?}\n{}",
            logs()
        );
        assert!(
            s.arrived.is_some(),
            "{text} never showed in the friend's chat: {seen:#?}\n{}",
            logs()
        );
    }
}

/// The owner's four-device test (2026-11-01): a message to one friend over
/// Tor, and at once one to another friend over Tor. Both are delivered, one
/// after the other, each about as fast as one send alone, and neither turns
/// `waiting` because of the other. Each send's Tor check reads the friend's
/// route hints only when it asked for them, so it never sits out Tor's 5 s
/// reply wait for one that is not due (it did: 7.6 s per check, not 2.6 s).
#[test]
fn tor_sends_to_two_friends_one_after_the_other_both_deliver_at_once() {
    let _one = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !tor_lab_ready() {
        return;
    }
    let (peers, cards) = tor_peers(&["Tor A", "Tor B", "Tor C"]);
    let (a, b, c) = (&peers[0], &peers[1], &peers[2]);
    let (card_a, card_b, card_c) = (&cards[0], &cards[1], &cards[2]);
    a.befriend(b, Some(card_b));
    a.befriend(c, Some(card_c));
    b.befriend(a, Some(card_a));
    c.befriend(a, Some(card_a));

    // A first message to each: the connection set up over Tor.
    first_message(a, b, "hello B over tor");
    first_message(a, c, "hello C over tor");
    // A warm Tor link: one send alone.
    let alone = one_alone(a, b, "one alone");

    // The owner's steps: send to B, go to C's chat, send to C.
    let began = Instant::now();
    let to_b = send(a, b, "first to B");
    std::thread::sleep(Duration::from_millis(400));
    let to_c = send(a, c, "then to C");
    let mut seen: HashMap<String, Vec<String>> = HashMap::new();
    let mut done: HashMap<String, Duration> = HashMap::new();
    let limit = Duration::from_secs(150);
    let mut after = 0;
    while done.len() < 2 {
        let batch = a.ok("events.poll", json!({"after_seq": after}));
        after = batch["seq"].as_u64().unwrap();
        for (friend, id) in [(b, &to_b), (c, &to_c)] {
            if done.contains_key(id.as_str()) {
                continue;
            }
            let Some(m) = message(a, friend, id) else {
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
    // Each within about one send alone (each friend's sends have a worker
    // of their own: tor_several_friends_both_ways_at_once_no_send_waits_for_another
    // tells side by side from one after the other); within two at most,
    // with room for a slow machine, but well inside one Tor reply wait more
    // per check.
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
    assert!(b.wait_incoming(a, "first to B", Duration::from_secs(30)));
    assert!(c.wait_incoming(a, "then to C", Duration::from_secs(30)));
}

/// The owner's report (2026-11-01): over Tor a device could not receive and
/// send at the same time. A sends to B while B sends to A, both at the same
/// moment: both are delivered and arrive, neither turns `waiting`, and
/// neither takes much longer than one send alone (a receive that waits for
/// the send, or a send that waits for the receive, is one send alone more).
#[test]
fn tor_same_friend_both_ways_at_once_neither_waits_for_the_other() {
    let _one = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !tor_lab_ready() {
        return;
    }
    let (peers, cards) = tor_peers(&["Tor A", "Tor B"]);
    let (a, b) = (&peers[0], &peers[1]);
    a.befriend(b, Some(&cards[1]));
    b.befriend(a, Some(&cards[0]));
    first_message(a, b, "hello B over tor");
    first_message(b, a, "hello A over tor");
    let alone = one_alone(a, b, "A alone").max(one_alone(b, a, "B alone"));

    let (seen, _) = sends_at_once(
        &[(a, b, "A to B at once"), (b, a, "B to A at once")],
        Duration::from_secs(150),
    );
    eprintln!("both ways at once (one send alone {alone:?}): {seen:#?}");
    all_delivered(&seen, alone, &[a, b]);
    for (text, s) in &seen {
        let (ended, arrived) = (s.ended.unwrap(), s.arrived.unwrap());
        assert!(
            ended < alone + Duration::from_secs(4),
            "{text} took {ended:?} to be delivered, one alone {alone:?}: {seen:#?}"
        );
        assert!(
            arrived < alone + Duration::from_secs(4),
            "{text} took {arrived:?} to arrive, one alone {alone:?}: {seen:#?}"
        );
    }
}

/// Several friends into one: B and C each send to A while A sends to B.
/// Everything is delivered and arrives, and what B and C send shows in A's
/// chat about as fast as one send alone: it is not held until A's own send
/// ends (nor A's send until they end).
#[test]
fn tor_two_friends_send_in_while_it_sends_out_nothing_waits() {
    let _one = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !tor_lab_ready() {
        return;
    }
    let (peers, cards) = tor_peers(&["Tor A", "Tor B", "Tor C"]);
    let (a, b, c) = (&peers[0], &peers[1], &peers[2]);
    a.befriend(b, Some(&cards[1]));
    a.befriend(c, Some(&cards[2]));
    b.befriend(a, Some(&cards[0]));
    c.befriend(a, Some(&cards[0]));
    first_message(a, b, "hello B over tor");
    first_message(a, c, "hello C over tor");
    first_message(b, a, "hello A from B");
    first_message(c, a, "hello A from C");
    let alone = [
        one_alone(a, b, "A alone"),
        one_alone(b, a, "B alone"),
        one_alone(c, a, "C alone"),
    ]
    .into_iter()
    .max()
    .unwrap();

    let (seen, _) = sends_at_once(
        &[
            (a, b, "A to B at once"),
            (b, a, "B to A at once"),
            (c, a, "C to A at once"),
        ],
        Duration::from_secs(150),
    );
    eprintln!("two in, one out (one send alone {alone:?}): {seen:#?}");
    all_delivered(&seen, alone, &[a, b, c]);
    for (text, s) in &seen {
        let (ended, arrived) = (s.ended.unwrap(), s.arrived.unwrap());
        assert!(
            ended < alone + Duration::from_secs(4),
            "{text} took {ended:?} to be delivered, one alone {alone:?}: {seen:#?}"
        );
        assert!(
            arrived < alone + Duration::from_secs(4),
            "{text} took {arrived:?} to arrive, one alone {alone:?}: {seen:#?}"
        );
    }
}

/// A burst each way: A sends three to B while B sends three to A. Every one
/// is delivered and arrives in the order it was written, none turns
/// `waiting`, and the whole burst ends within three sends alone (one after
/// the other per sender), not six.
#[test]
fn tor_burst_both_ways_every_message_arrives() {
    let _one = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !tor_lab_ready() {
        return;
    }
    let (peers, cards) = tor_peers(&["Tor A", "Tor B"]);
    let (a, b) = (&peers[0], &peers[1]);
    a.befriend(b, Some(&cards[1]));
    b.befriend(a, Some(&cards[0]));
    first_message(a, b, "hello B over tor");
    first_message(b, a, "hello A over tor");
    let alone = one_alone(a, b, "A alone").max(one_alone(b, a, "B alone"));

    let plan: Vec<(&Peer, &Peer, String)> = (1..=3)
        .flat_map(|i| [(a, b, format!("A to B {i}")), (b, a, format!("B to A {i}"))])
        .collect();
    let plan: Vec<(&Peer, &Peer, &str)> = plan
        .iter()
        .map(|(from, to, text)| (*from, *to, text.as_str()))
        .collect();
    let (seen, _) = sends_at_once(&plan, Duration::from_secs(240));
    eprintln!("a burst each way (one send alone {alone:?}): {seen:#?}");
    all_delivered(&seen, alone, &[a, b]);
    // A friend's messages keep their order.
    for from in ["A to B", "B to A"] {
        let came: Vec<Duration> = (1..=3)
            .map(|i| seen[&format!("{from} {i}")].arrived.unwrap())
            .collect();
        assert!(
            came.windows(2).all(|w| w[0] < w[1]),
            "{from}: out of order {came:?}: {seen:#?}"
        );
    }
    let last = seen
        .values()
        .map(|s| s.ended.unwrap().max(s.arrived.unwrap()))
        .max()
        .unwrap();
    assert!(
        last < alone * 3 + Duration::from_secs(6),
        "the burst took {last:?}, one alone {alone:?}: {seen:#?}"
    );
}

/// Several friends at once, both ways (the owner's four-device test,
/// 2026-11-01: "it must be seamless, with one friend and with several
/// friends"): A writes to B and to C while B and C write to A. Every
/// message is delivered and arrives about as fast as one send alone: A's
/// message to C does not wait for A's message to B to end, nor the other
/// way round (sends to one friend keep their order; sends to different
/// friends go side by side).
#[test]
fn tor_several_friends_both_ways_at_once_no_send_waits_for_another() {
    let _one = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    if !tor_lab_ready() {
        return;
    }
    let (connect, latency) = SLOW_TOR;
    let (peers, cards) = tor_peers_with(&[
        ("Tor A", connect, latency),
        ("Tor B", connect, latency),
        ("Tor C", connect, latency),
    ]);
    let (a, b, c) = (&peers[0], &peers[1], &peers[2]);
    a.befriend(b, Some(&cards[1]));
    a.befriend(c, Some(&cards[2]));
    b.befriend(a, Some(&cards[0]));
    c.befriend(a, Some(&cards[0]));
    first_message(a, b, "hello B over tor");
    first_message(a, c, "hello C over tor");
    first_message(b, a, "hello A from B");
    first_message(c, a, "hello A from C");
    let alone = one_alone(a, b, "A alone").max(one_alone(b, a, "B alone"));

    let (seen, _) = sends_at_once(
        &[
            (a, b, "A to B with C"),
            (a, c, "A to C with B"),
            (b, a, "B to A with C"),
            (c, a, "C to A with B"),
        ],
        Duration::from_secs(200),
    );
    eprintln!("several friends at once (one send alone {alone:?}): {seen:#?}");
    all_delivered(&seen, alone, &[a, b, c]);
    for (text, s) in &seen {
        let (ended, arrived) = (s.ended.unwrap(), s.arrived.unwrap());
        assert!(
            ended < alone + Duration::from_secs(4),
            "{text} took {ended:?} to be delivered, one alone {alone:?}: {seen:#?}"
        );
        assert!(
            arrived < alone + Duration::from_secs(4),
            "{text} took {arrived:?} to arrive, one alone {alone:?}: {seen:#?}"
        );
    }
}
