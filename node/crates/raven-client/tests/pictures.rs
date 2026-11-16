//! Your picture through the engine API (src/pictures.rs): two engines, each
//! with its own raven-node process on 127.0.0.1 (free ports, file-backed
//! secret stores), friends verified by their security words.
//!
//! Lab switches for this test binary only: `RAVEN_LAB_TEST_A=1`,
//! `RAVEN_LAB_ATTACHMENTS=1` and `RAVEN_LAB_PROFILE_PICTURES=1` (the two
//! gates, off in release builds).
//!
//! Needs the raven-node and raven that `cargo build` puts next to the test
//! binaries' folder; without them a test says so and passes.

mod common;

use std::sync::Once;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use common::net::{binaries_ready, Peer};
use raven_core::attachment::jpeg;
use serde_json::{json, Value};

/// The lab environment of this binary: both gates open, here and in every
/// raven-node it starts. False: nothing to test with (no built programs, or
/// a release engine, which reads no lab switch).
fn lab() -> bool {
    if !binaries_ready() {
        return false;
    }
    if !cfg!(debug_assertions) {
        eprintln!("skipped: a release engine reads no lab switch (the gates are shut)");
        return false;
    }
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        common::lab_env();
        std::env::set_var("RAVEN_LAB_TEST_A", "1");
        std::env::set_var("RAVEN_LAB_ATTACHMENTS", "1");
        std::env::set_var("RAVEN_LAB_PROFILE_PICTURES", "1");
    });
    true
}

/// The events of one engine since the watch began. Asking for them is also
/// what keeps the engine's watcher going, as an open app does.
struct Watch<'a> {
    peer: &'a Peer,
    after: u64,
    events: Vec<Value>,
}

impl<'a> Watch<'a> {
    fn new(peer: &'a Peer) -> Self {
        let after = peer.ok("events.poll", json!({"after_seq": 0}))["seq"]
            .as_u64()
            .unwrap();
        Watch {
            peer,
            after,
            events: Vec::new(),
        }
    }

    fn poll(&mut self) {
        let batch = self
            .peer
            .ok("events.poll", json!({"after_seq": self.after}));
        self.after = batch["seq"].as_u64().unwrap();
        self.events
            .extend(batch["events"].as_array().unwrap().iter().cloned());
    }

    fn of_kind(&self, kind: &str) -> Vec<&Value> {
        self.events.iter().filter(|e| e["kind"] == kind).collect()
    }
}

fn wait_until(
    limit: Duration,
    watches: &mut [&mut Watch<'_>],
    mut done: impl FnMut() -> bool,
) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        for w in watches.iter_mut() {
            w.poll();
        }
        if done() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The row of `friend` in `p`'s list of friends.
fn row(p: &Peer, friend: &Peer) -> Value {
    p.ok("contacts.list", json!({}))["contacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["address"] == friend.address())
        .cloned()
        .unwrap_or_else(|| panic!("{} is not in the list", friend.name))
}

fn mine(p: &Peer) -> Value {
    p.ok("picture.mine", json!({}))["mine"].clone()
}

fn read(p: &Peer, args: Value) -> Vec<u8> {
    let got = p.ok("picture.read", args);
    BASE64.decode(got["jpeg_b64"].as_str().unwrap()).unwrap()
}

/// A picture set on one engine arrives on the verified friend's, is read
/// back byte for byte, is replaced by a newer one, and goes when it is
/// removed. What is not a picture is refused, and a friend that is no
/// longer verified has none.
#[test]
fn a_picture_is_set_seen_by_the_verified_friend_replaced_and_removed() {
    if !lab() {
        return;
    }
    let a = Peer::new("Ay");
    let b = Peer::new("Bee");
    a.befriend(&b, None);
    b.befriend(&a, None);
    let (la, lb) = (a.start(), b.start());
    a.set_lan(&b, &lb);
    b.set_lan(&a, &la);
    let limit = Duration::from_secs(120);
    // A message each way: each node learns that the other takes
    // attachments, without which nothing is offered.
    a.send_until(&b, "hello from ay", &["delivered"], limit);
    assert!(b.wait_incoming(&a, "hello from ay", limit));
    b.send_until(&a, "hello from bee", &["delivered"], limit);
    assert!(a.wait_incoming(&b, "hello from bee", limit));
    let (mut wa, mut wb) = (Watch::new(&a), Watch::new(&b));

    // Nothing yet: no picture, no member in a row.
    let before = mine(&a);
    assert_eq!(before["set"], false, "{before}");
    assert_eq!(before["friends"], 1, "{before}");
    assert_eq!(before["changes_left"], 3, "{before}");
    assert!(row(&b, &a).get("picture").is_none());
    assert!(row(&a, &b).get("my_picture").is_none());
    assert_eq!(a.err("picture.read", json!({})), "NO_PICTURE");
    assert_eq!(
        b.err("picture.read", json!({"address": a.address()})),
        "NO_PICTURE"
    );

    // What is not a picture is refused, and nothing changes.
    let small = BASE64.encode(jpeg::flat(32, true));
    for (bytes, code) in [
        (b"\x89PNG\r\n\x1a\n not a jpeg".to_vec(), "PICTURE_BAD"),
        (jpeg::flat(520, true), "PICTURE_TOO_BIG"),
        (vec![0u8; 80_000], "PICTURE_TOO_BIG"),
    ] {
        let refused = a.err(
            "picture.set",
            json!({"jpeg_b64": BASE64.encode(&bytes), "preview_b64": small}),
        );
        assert_eq!(refused, code);
    }
    assert_eq!(mine(&a)["set"], false);

    // Ay sets a picture.
    let first = jpeg::flat(384, true);
    let set = a.ok(
        "picture.set",
        json!({"jpeg_b64": BASE64.encode(&first), "preview_b64": small}),
    );
    assert_eq!(set["mine"]["set"], true, "{set}");
    assert_eq!(set["mine"]["changes_left"], 2, "{set}");
    assert_eq!(read(&a, json!({})), first, "kept as it travels");
    assert_eq!(read(&a, json!({"preview": true})), jpeg::flat(32, true));

    // It arrives at Bee: the row says so, and the bytes read back.
    let ready = wait_until(limit, &mut [&mut wa, &mut wb], || {
        row(&b, &a)["picture"]["state"] == "ready"
    });
    assert!(ready, "{} / {:#?}", row(&b, &a), wb.events);
    let seen = row(&b, &a)["picture"].clone();
    assert!(seen["seq"].as_u64().unwrap() > 0, "{seen}");
    assert_eq!(read(&b, json!({"address": a.address()})), first);
    assert_eq!(
        read(&b, json!({"address": a.address(), "preview": true})),
        jpeg::flat(32, true)
    );
    // Bee's app is told at the watcher's next beat, and nothing of it is a
    // chat message.
    let ay = a.address();
    let said_ready = |w: &Watch<'_>| {
        w.of_kind("picture")
            .iter()
            .any(|e| e["address"] == ay.as_str() && e["picture"]["state"] == "ready")
    };
    let mut told = false;
    wait_until(Duration::from_secs(20), &mut [&mut wa], || {
        wb.poll();
        told = said_ready(&wb);
        told
    });
    assert!(told, "{:#?}", wb.events);
    assert!(wb.of_kind("incoming").is_empty(), "{:#?}", wb.events);
    let history = |p: &Peer, friend: &Peer| {
        p.ok("messages.history", json!({"address": friend.address()}))["messages"]
            .as_array()
            .unwrap()
            .len()
    };
    assert_eq!(history(&b, &a), 2, "the two hellos and nothing else");
    assert_eq!(history(&a, &b), 2);

    // Ay learns that Bee has it.
    let has = wait_until(limit, &mut [&mut wa, &mut wb], || {
        row(&a, &b)["my_picture"] == "has"
    });
    assert!(has, "{} / {:#?}", row(&a, &b), wa.events);
    let now = mine(&a);
    assert_eq!(
        (now["have_it"].as_u64(), now["waiting"].as_u64()),
        (Some(1), Some(0)),
        "{now}"
    );
    let mut counted = false;
    wait_until(Duration::from_secs(20), &mut [&mut wb], || {
        wa.poll();
        counted = wa
            .of_kind("picture_mine")
            .iter()
            .any(|e| e["mine"]["have_it"] == 1);
        counted
    });
    assert!(counted, "{:#?}", wa.events);
    let has_event = wa
        .of_kind("picture")
        .iter()
        .any(|e| e["address"] == b.address().as_str() && e["my_picture"] == "has");
    assert!(has_event, "{:#?}", wa.events);

    // A newer picture replaces it on Bee's side.
    let second = jpeg::flat(256, true);
    a.ok(
        "picture.set",
        json!({"jpeg_b64": BASE64.encode(&second), "preview_b64": small}),
    );
    let newer = seen["seq"].as_u64().unwrap();
    let replaced = wait_until(limit, &mut [&mut wa, &mut wb], || {
        let picture = row(&b, &a)["picture"].clone();
        picture["state"] == "ready" && picture["seq"].as_u64().is_some_and(|seq| seq > newer)
    });
    assert!(replaced, "{}", row(&b, &a));
    assert_eq!(read(&b, json!({"address": a.address()})), second);

    // Bee no longer has Ay verified: no member, no bytes, at once.
    b.ok("contacts.unverify", json!({"address": a.address()}));
    assert!(row(&b, &a).get("picture").is_none(), "{}", row(&b, &a));
    assert_eq!(
        b.err("picture.read", json!({"address": a.address()})),
        "NOT_VERIFIED"
    );

    // Ay removes its picture: that uses up none of the day's three.
    let cleared = a.ok("picture.clear", json!({}));
    assert_eq!(cleared["mine"]["set"], false, "{cleared}");
    assert_eq!(cleared["mine"]["changes_left"], 1, "{cleared}");
    assert_eq!(a.err("picture.read", json!({})), "NO_PICTURE");
    // The third picture of the day is the last, and can still be removed.
    let third = a.ok(
        "picture.set",
        json!({"jpeg_b64": BASE64.encode(&first), "preview_b64": small}),
    );
    assert_eq!(third["mine"]["changes_left"], 0, "{third}");
    assert_eq!(
        a.err(
            "picture.set",
            json!({"jpeg_b64": BASE64.encode(&second), "preview_b64": small}),
        ),
        "CHANGE_LIMIT"
    );
    assert_eq!(
        read(&a, json!({})),
        first,
        "the refused one changed nothing"
    );
    assert_eq!(a.ok("picture.clear", json!({}))["mine"]["set"], false);
}
