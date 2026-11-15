//! Photos through the engine API (src/attachments.rs): two engines, each
//! with its own raven-node process on 127.0.0.1 (free ports, file-backed
//! secret stores), friends verified by their security words.
//!
//! Lab switches for this test binary only: `RAVEN_LAB_TEST_A=1` and
//! `RAVEN_LAB_ATTACHMENTS=1` (the attachments gate, off in release builds).
//!
//! Needs the raven-node and raven that `cargo build` puts next to the test
//! binaries' folder; without them a test says so and passes.

mod common;

use std::path::Path;
use std::sync::Once;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use common::net::{binaries_ready, Peer};
use raven_core::attachment::blob::{Key, Shape};
use raven_core::attachment::flow::{self, Media};
use raven_core::attachment::offer::{BlobRef, Offer};
use raven_core::attachment::{peers, store};
use serde_json::{json, Value};

/// The lab environment of this binary: the attachments gate open, here and
/// in every raven-node it starts. False: nothing to test with (no built
/// programs, or a release engine, which reads no lab switch).
fn lab() -> bool {
    if !binaries_ready() {
        return false;
    }
    if !cfg!(debug_assertions) {
        eprintln!("skipped: a release engine reads no lab switch (the attachments gate is shut)");
        return false;
    }
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        common::lab_env();
        std::env::set_var("RAVEN_LAB_TEST_A", "1");
        std::env::set_var("RAVEN_LAB_ATTACHMENTS", "1");
    });
    true
}

/// Bytes that start as a JPEG does; the rest is arbitrary.
fn jpeg(len: usize, salt: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..len).map(|i| ((i * 31 + salt) % 251) as u8).collect();
    bytes[..3].copy_from_slice(&[0xFF, 0xD8, 0xFF]);
    bytes
}

/// What an app hands over as the 32 px preview.
const PREVIEW: [u8; 8] = [0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3, 4];

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The chat with `friend` as `messages.history` gives it.
fn history(p: &Peer, friend: &Peer) -> Vec<Value> {
    p.ok(
        "messages.history",
        json!({"address": friend.address(), "limit": 50}),
    )["messages"]
        .as_array()
        .unwrap()
        .clone()
}

/// The row that carries the attachment `id`.
fn photo_row(p: &Peer, friend: &Peer, id: &str) -> Option<Value> {
    history(p, friend)
        .into_iter()
        .find(|m| m["attachment"]["id"] == id)
}

/// The row with the id `id`.
fn row(p: &Peer, friend: &Peer, id: &str) -> Option<Value> {
    history(p, friend).into_iter().find(|m| m["id"] == id)
}

/// The key of the one friend `p` saved, from its (plain) contact book.
fn friend_key(p: &Peer) -> [u8; 32] {
    let book = std::fs::read_to_string(p.path.join("contacts.json")).unwrap();
    let rows: Value = serde_json::from_str(&book).unwrap();
    let mut key = [0u8; 32];
    hex::decode_to_slice(rows[0]["pub_hex"].as_str().unwrap().trim(), &mut key).unwrap();
    key
}

fn handle_of(id: &str) -> [u8; 16] {
    let mut handle = [0u8; 16];
    hex::decode_to_slice(id, &mut handle).unwrap();
    handle
}

/// The ids of the messages of `p` that still wait to be delivered, as its
/// session store has them: a copy in the outbox, or one parked until its
/// deadline.
fn waiting_ids(p: &Peer) -> Vec<[u8; 16]> {
    let store = raven_core::IndexedSessionStore::open(&p.path).unwrap();
    let mut rows = store.pending_endpoint_outbound().unwrap();
    rows.extend(store.awaiting_ack_endpoint_outbound().unwrap());
    let mut ids: Vec<[u8; 16]> = rows
        .into_iter()
        .filter(|r| r.kind == raven_core::EndpointOutboundKind::Message)
        .map(|r| r.message_id)
        .collect();
    for parked in store.parked_peers().unwrap() {
        for row in store.parked_for_recipient(&parked.peer).unwrap() {
            ids.push(row.message_id);
        }
    }
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// The events of one engine since this was made. Polling keeps its watcher
/// running.
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

/// Stages `bytes` and sends them to `friend` as a photo: the answer.
fn send_photo(p: &Peer, friend: &Peer, bytes: &[u8], caption: &str) -> Value {
    let staged = p.ok("attachments.stage", json!({"name": "photo.JPG"}));
    let path = staged["path"].as_str().unwrap().to_owned();
    assert!(path.ends_with(".jpg"), "the name only gives the ending");
    assert!(
        Path::new(&path).starts_with(p.path.join(store::STAGING_DIR)),
        "inside the profile's staging folder"
    );
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    std::fs::write(&path, bytes).unwrap();
    let sent = p.ok(
        "attachments.send",
        json!({
            "address": friend.address(), "path": path, "kind": "photo",
            "mime": "image/jpeg", "caption": caption,
            "preview_b64": BASE64.encode(PREVIEW), "width": 1600, "height": 1200,
        }),
    );
    assert!(!Path::new(&path).exists(), "the staged file is deleted");
    sent
}

/// The attachment's own bytes, read in pieces of `piece` bytes.
fn read_all(p: &Peer, id: &str, piece: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let r = p.ok(
            "attachments.read",
            json!({"id": id, "offset": out.len(), "length": piece}),
        );
        let part = BASE64.decode(r["bytes_b64"].as_str().unwrap()).unwrap();
        assert!(part.len() as u64 <= piece);
        out.extend_from_slice(&part);
        if r["eof"] == true {
            return out;
        }
        assert!(!part.is_empty(), "a piece before the end is not empty");
    }
}

/// The attachment is gone from this profile: its row (with the key), its
/// sealed bytes, and for the app.
fn assert_gone(p: &Peer, id: &str, what: &str) {
    let handle = handle_of(id);
    assert!(
        store::get(&p.path, &handle).unwrap().is_none(),
        "{what}: the row stays"
    );
    assert!(
        !store::blob_dir(&p.path, &handle).exists(),
        "{what}: the sealed bytes stay"
    );
    assert_eq!(
        p.err("attachments.read", json!({"id": id})),
        "ATTACHMENT_GONE",
        "{what}"
    );
}

/// Waits (up to `limit`) until `done` says so; polls `watches` meanwhile.
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

/// A photo from A to B, end to end: the offer as a message, the sealed
/// bytes between the two nodes, and what each app is told and can read.
/// Then an attachment goes with its message: clearing a chat, deleting a
/// message and deleting a chat each remove it at once.
#[test]
fn a_photo_travels_between_two_friends_and_goes_with_its_message() {
    if !lab() {
        return;
    }
    let a = Peer::new("Sender");
    let b = Peer::new("Receiver");
    a.befriend(&b, None);
    b.befriend(&a, None);
    let (la, lb) = (a.start(), b.start());
    a.set_lan(&b, &lb);
    b.set_lan(&a, &la);

    // Not before each node has seen the other's: a friend's Raven says that
    // it takes photos on a link it makes. One message each way does it.
    let can = |p: &Peer, friend: &Peer| {
        p.ok("attachments.can_send", json!({"address": friend.address()}))
    };
    let early = can(&a, &b);
    assert_eq!(early["max_bytes"], 1_048_576, "{early}");
    if early["photos"] == false {
        assert_eq!(
            early["why"],
            "Friend Receiver cannot get photos yet. Their Raven has not said that it takes them",
            "{early}"
        );
    }
    let limit = Duration::from_secs(120);
    a.send_until(&b, "hello from the sender", &["delivered"], limit);
    assert!(b.wait_incoming(&a, "hello from the sender", limit));
    b.send_until(&a, "hello from the receiver", &["delivered"], limit);
    assert!(a.wait_incoming(&b, "hello from the receiver", limit));
    let both = wait_until(Duration::from_secs(60), &mut [], || {
        can(&a, &b)["photos"] == true && can(&b, &a)["photos"] == true
    });
    assert!(both, "{} / {}", can(&a, &b), can(&b, &a));
    assert!(can(&a, &b).get("why").is_none());

    // A sends a photo of about 300 KB.
    let bytes = jpeg(300_123, 0);
    let caption = "the bridge at night";
    let (mut wa, mut wb) = (Watch::new(&a), Watch::new(&b));
    let sent_at = Instant::now();
    let sent = send_photo(&a, &b, &bytes, caption);
    let first = &sent["message"];
    assert_eq!(first["direction"], "out", "{sent}");
    assert_eq!(first["state"], "sending", "{sent}");
    assert_eq!(first["text"], caption, "{sent}");
    let row_id = first["id"].as_str().unwrap().to_owned();
    let att = &first["attachment"];
    let id = att["id"].as_str().unwrap().to_owned();
    assert_eq!(id.len(), 32, "{sent}");
    assert!(id.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));
    assert_eq!(att["kind"], "photo", "{sent}");
    assert_eq!(att["state"], "sending", "{sent}");
    assert_eq!(att["bytes"], bytes.len(), "{sent}");
    assert_eq!(att["bytes_done"], 0, "{sent}");
    assert_eq!(
        (att["width"].as_u64(), att["height"].as_u64()),
        (Some(1600), Some(1200))
    );
    assert_eq!(att["preview_b64"], BASE64.encode(PREVIEW), "{sent}");
    assert_eq!(att["caption"], caption, "{sent}");

    // B's row turns ready; A's turns delivered, and its message with it.
    let (mut ready_at, mut delivered_at) = (None, None);
    let arrived = wait_until(limit, &mut [&mut wa, &mut wb], || {
        if ready_at.is_none()
            && photo_row(&b, &a, &id).is_some_and(|m| m["attachment"]["state"] == "ready")
        {
            ready_at = Some(sent_at.elapsed());
        }
        if delivered_at.is_none()
            && row(&a, &b, &row_id).is_some_and(|m| {
                m["attachment"]["state"] == "delivered" && m["state"] == "delivered"
            })
        {
            delivered_at = Some(sent_at.elapsed());
        }
        ready_at.is_some() && delivered_at.is_some()
    });
    assert!(
        arrived,
        "receiver {:?}, sender {:?}; sender's node: {}; receiver's node: {}",
        photo_row(&b, &a, &id),
        row(&a, &b, &row_id),
        a.service_log(),
        b.service_log()
    );
    eprintln!(
        "a photo of {} bytes: ready at the receiver {:.1} s after attachments.send, delivered \
         at the sender after {:.1} s (the test looks ten times a second)",
        bytes.len(),
        ready_at.unwrap().as_secs_f64(),
        delivered_at.unwrap().as_secs_f64()
    );

    // The receiver's row, and the photo's own bytes in pieces.
    let theirs = photo_row(&b, &a, &id).unwrap();
    assert_eq!(theirs["direction"], "in", "{theirs}");
    assert_eq!(theirs["text"], caption, "{theirs}");
    let att = &theirs["attachment"];
    assert_eq!(att["kind"], "photo", "{theirs}");
    assert_eq!(att["state"], "ready", "{theirs}");
    assert_eq!(att["bytes"], bytes.len(), "{theirs}");
    assert_eq!(att["bytes_done"], bytes.len(), "{theirs}");
    assert_eq!(
        (att["width"].as_u64(), att["height"].as_u64()),
        (Some(1600), Some(1200))
    );
    assert_eq!(att["preview_b64"], BASE64.encode(PREVIEW), "{theirs}");
    assert_eq!(att["caption"], caption, "{theirs}");
    assert_eq!(
        b.ok("attachments.get", json!({"id": id}))["attachment"],
        *att
    );
    assert_eq!(read_all(&b, &id, 100_000), bytes, "in pieces of 100,000");
    assert_eq!(read_all(&b, &id, 524_288), bytes, "in the largest pieces");
    assert_eq!(
        b.err("attachments.read", json!({"id": id, "length": 524_289})),
        "BAD_REQUEST"
    );
    assert_eq!(
        b.err(
            "attachments.read",
            json!({"id": id, "offset": bytes.len() + 1})
        ),
        "BAD_REQUEST"
    );
    // Nothing more to fetch: asking again is fine.
    assert_eq!(b.ok("attachments.download", json!({"id": id})), json!({}));

    // The sender's row: two ticks, and its own photo is readable.
    let mine = row(&a, &b, &row_id).unwrap();
    assert_eq!(mine["state"], "delivered", "{mine}");
    assert_eq!(mine["text"], caption, "{mine}");
    assert_eq!(mine["attachment"]["state"], "delivered", "{mine}");
    assert_eq!(mine["attachment"]["bytes_done"], bytes.len(), "{mine}");
    assert_eq!(mine["attachment"]["id"], id.as_str(), "{mine}");
    assert_eq!(read_all(&a, &id, 200_000), bytes);
    assert_eq!(
        a.ok("attachments.get", json!({"id": id}))["attachment"],
        mine["attachment"]
    );

    // What the apps were told. An `attachment` event that came too soon
    // after the one before it is told at the next look: wait for the last.
    let told = |w: &Watch<'_>, state: &str| {
        w.events
            .iter()
            .any(|e| e["kind"] == "attachment" && e["id"] == id.as_str() && e["state"] == state)
    };
    let came_ready = |w: &Watch<'_>| {
        w.events.iter().any(|e| {
            e["kind"] == "incoming"
                && e["message"]["attachment"]["id"] == id.as_str()
                && e["message"]["attachment"]["state"] == "ready"
        })
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        wa.poll();
        wb.poll();
        let all = told(&wa, "delivered") && (told(&wb, "ready") || came_ready(&wb));
        if all || Instant::now() >= deadline {
            break;
        }
        let _ = (history(&a, &b), history(&b, &a));
        std::thread::sleep(Duration::from_millis(100));
    }
    // The sender's app: the receipt only once the friend has every byte,
    // before any `delivered`, and `attachment` events up to delivered.
    let of_row = |events: Vec<&Value>| -> Vec<Value> {
        events
            .into_iter()
            .filter(|e| e["id"] == row_id.as_str())
            .cloned()
            .collect()
    };
    let receipts = of_row(wa.of_kind("receipt"));
    assert_eq!(receipts.len(), 1, "{:#?}", wa.events);
    let receipt_seq = receipts[0]["seq"].as_u64().unwrap();
    for state in of_row(wa.of_kind("state")) {
        if state["state"] == "delivered" {
            assert!(
                state["seq"].as_u64().unwrap() > receipt_seq,
                "{:#?}",
                wa.events
            );
        }
    }
    let told_a: Vec<&Value> = wa
        .of_kind("attachment")
        .into_iter()
        .filter(|e| e["id"] == id.as_str())
        .collect();
    assert!(!told_a.is_empty(), "{:#?}", wa.events);
    for e in &told_a {
        assert_eq!(e["message_id"], row_id.as_str(), "{e}");
        assert_eq!(e["address"], b.address(), "{e}");
        assert_eq!(e["bytes"], bytes.len(), "{e}");
    }
    let last = told_a.last().unwrap();
    assert_eq!(last["state"], "delivered", "{:#?}", told_a);
    assert_eq!(last["bytes_done"], bytes.len(), "{last}");
    assert!(
        last["seq"].as_u64().unwrap() > receipt_seq,
        "the receipt comes first: {:#?}",
        wa.events
    );
    // The receiver's app: the message as `incoming`, with its attachment,
    // and every later step as an `attachment` event up to ready (none when
    // the photo was all there at the first look).
    let incoming: Vec<&Value> = wb
        .of_kind("incoming")
        .into_iter()
        .filter(|e| e["message"]["attachment"]["id"] == id.as_str())
        .collect();
    assert_eq!(incoming.len(), 1, "{:#?}", wb.events);
    assert_eq!(incoming[0]["message"]["text"], caption);
    let first_state = incoming[0]["message"]["attachment"]["state"]
        .as_str()
        .unwrap()
        .to_owned();
    let told_b: Vec<&Value> = wb
        .of_kind("attachment")
        .into_iter()
        .filter(|e| e["id"] == id.as_str())
        .collect();
    // When each app was told, counted from the sender's `send_started`
    // (both engines share this computer's clock).
    let started = of_row(wa.of_kind("send_started"))[0]["at_ms"]
        .as_u64()
        .unwrap();
    let steps = |events: &[&Value]| -> String {
        events
            .iter()
            .map(|e| {
                let state = e["state"].as_str().unwrap_or("?");
                let at = e["at_ms"].as_u64().unwrap().saturating_sub(started);
                format!("{state} at {at} ms")
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    eprintln!(
        "the sender's app: receipt at {} ms; attachment events: {}",
        receipts[0]["at_ms"]
            .as_u64()
            .unwrap()
            .saturating_sub(started),
        steps(&told_a)
    );
    eprintln!(
        "the receiver's app: incoming at {} ms with the photo {first_state}; attachment events: {}",
        incoming[0]["at_ms"]
            .as_u64()
            .unwrap()
            .saturating_sub(started),
        steps(&told_b)
    );
    if first_state == "ready" {
        assert!(told_b.is_empty(), "{:#?}", wb.events);
    } else {
        assert!(matches!(first_state.as_str(), "offered" | "downloading"));
        let last = told_b.last().unwrap_or_else(|| panic!("{:#?}", wb.events));
        assert_eq!(last["state"], "ready", "{:#?}", told_b);
        assert_eq!(last["bytes_done"], bytes.len(), "{last}");
        assert_eq!(last["address"], a.address(), "{last}");
        assert_eq!(last["message_id"], theirs["id"], "{last}");
    }

    // Never the offer or its stored form as text: not in a row, not in an
    // event.
    for (who, rows) in [("sender", history(&a, &b)), ("receiver", history(&b, &a))] {
        for m in &rows {
            assert!(!common::all_text(m).contains("RVNATT/"), "{who}: {m}");
        }
    }
    for e in wa.events.iter().chain(wb.events.iter()) {
        assert!(!common::all_text(e).contains("RVNATT/"), "{e}");
    }
    // The attachment's key is in the sender's sealed row and in no history:
    // not in the file as it lies on disk, and not in its rows once opened
    // (the history file is sealed with the history's own key). Each side's
    // row holds the stored form: the handle, never the key or the root.
    let handle = handle_of(&id);
    let sealed = store::get(&a.path, &handle).unwrap().expect("the row");
    let key = hex::encode(sealed.key().expect("its key").bytes());
    let root = hex::encode(sealed.root().expect("its root"));
    for p in [&a, &b] {
        let file = raven_core::chat_history::history_path(&p.path);
        let raw = std::fs::read(&file).unwrap();
        assert!(!contains(&raw, key.as_bytes()), "{}: the key", p.name);
        assert!(!contains(&raw, root.as_bytes()), "{}: the root", p.name);
        let opened = raven_core::chat_history::ChatHistory::load(&p.path).unwrap();
        let photo: Vec<_> = opened
            .entries
            .iter()
            .filter(|e| e.body.starts_with("RVNATT/"))
            .collect();
        assert_eq!(photo.len(), 1, "{}: one row holds the photo", p.name);
        assert!(photo[0].body.starts_with("RVNATT/1 ref\n"), "{}", p.name);
        assert!(photo[0].body.contains(&id), "{}: the handle", p.name);
        assert_eq!(photo[0].preview, "Photo", "{}", p.name);
        let rows = serde_json::to_string(&opened.entries).unwrap();
        assert!(!rows.contains(&key), "{}: the key in a row", p.name);
        assert!(!rows.contains(&root), "{}: the root in a row", p.name);
        assert!(!rows.contains("RVNATT/1 offer"), "{}: an offer", p.name);
        assert!(!contains(p.service_log().as_bytes(), key.as_bytes()));
    }

    // Saved where the user chose: a new file outside the profile, never
    // over one that is there.
    let out = tempfile::tempdir().unwrap();
    let to = out.path().join("saved.jpg");
    assert_eq!(
        b.ok("attachments.export", json!({"id": id, "to_path": to})),
        json!({})
    );
    assert_eq!(std::fs::read(&to).unwrap(), bytes);
    assert_eq!(
        b.err("attachments.export", json!({"id": id, "to_path": to})),
        "BAD_REQUEST"
    );
    let inside = b.path.join("saved.jpg");
    assert_eq!(
        b.err("attachments.export", json!({"id": id, "to_path": inside})),
        "BAD_REQUEST"
    );
    assert!(!inside.exists());

    // An attachment goes with its message. The receiver clears the chat:
    // its copy of the photo is gone at once.
    let cleared = b.ok("messages.clear", json!({"address": a.address()}));
    assert!(cleared["cleared"].as_u64().unwrap() >= 1, "{cleared}");
    assert_gone(&b, &id, "messages.clear");
    assert!(photo_row(&b, &a, &id).is_none());

    // The sender deletes a photo that was not sent: B is off, a second
    // photo waits, sending it is stopped, and its message is deleted.
    b.stop();
    let second = jpeg(120_000, 7);
    let sent = send_photo(&a, &b, &second, "");
    let row2 = sent["message"]["id"].as_str().unwrap().to_owned();
    let id2 = sent["message"]["attachment"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(id2, id);
    let settled = wait_until(limit, &mut [&mut wa], || {
        row(&a, &b, &row2).is_some_and(|m| {
            matches!(
                m["state"].as_str(),
                Some("waiting" | "failed" | "not_sent_meet_first")
            )
        })
    });
    let before = row(&a, &b, &row2).unwrap();
    assert!(settled, "{before}");
    assert_ne!(before["attachment"]["state"], "delivered", "{before}");
    eprintln!(
        "a photo to a friend who is off: its message reads {}, the photo {}",
        before["state"], before["attachment"]["state"]
    );
    assert_eq!(read_all(&a, &id2, 524_288), second, "mine is readable");
    assert_eq!(a.ok("attachments.cancel", json!({"id": id2})), json!({}));
    let stopped = wait_until(limit, &mut [&mut wa], || {
        row(&a, &b, &row2).is_some_and(|m| {
            m["attachment"]["state"] == "failed"
                && matches!(m["state"].as_str(), Some("failed" | "not_sent_meet_first"))
        })
    });
    assert!(stopped, "{:?}", row(&a, &b, &row2));
    let deleted = a.ok("messages.delete", json!({"id": row2}));
    assert_eq!(deleted["deleted"], true, "{deleted}");
    assert_gone(&a, &id2, "messages.delete");
    assert!(row(&a, &b, &row2).is_none());
    // The first photo is still the sender's.
    assert_eq!(read_all(&a, &id, 524_288), bytes);

    // The sender deletes the chat while a third photo still waits and a
    // text does too: the photos go at once, the first with its message and
    // the third with its message stopped (a photo whose bytes are gone is
    // not left on its way); the text keeps waiting, as a clear leaves it.
    let third = jpeg(80_000, 9);
    let sent = send_photo(&a, &b, &third, "one more");
    let row3 = sent["message"]["id"].as_str().unwrap().to_owned();
    let id3 = sent["message"]["attachment"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let text = a.ok(
        "messages.send",
        json!({"address": b.address(), "text": "see you"}),
    );
    let text_row = text["message"]["id"].as_str().unwrap().to_owned();
    let waits = |id: &str| row(&a, &b, id).is_some_and(|m| m["state"] == "waiting");
    let waiting = wait_until(limit, &mut [&mut wa], || waits(&row3) && waits(&text_row));
    assert!(
        waiting,
        "{:?} {:?}",
        row(&a, &b, &row3),
        row(&a, &b, &text_row)
    );
    // The photo's row knows the message that carries it, and that message
    // waits in the sender's store (asked of the store itself: raven-node's
    // own list is a moment behind a cancel).
    let mid3 = store::get(&a.path, &handle_of(&id3))
        .unwrap()
        .expect("its row")
        .message_id_bytes()
        .unwrap();
    assert_ne!(mid3, [0u8; 16], "the photo's row knows its message");
    let before = waiting_ids(&a);
    assert!(before.contains(&mid3), "the photo's message waits");
    assert_eq!(before.len(), 2, "the photo and the text wait");
    let gone = a.ok("chats.delete", json!({"address": b.address()}));
    assert_eq!(gone["deleted"], true, "{gone}");
    assert_gone(&a, &id, "chats.delete");
    assert_gone(&a, &id3, "chats.delete, a photo that waited");
    let after = waiting_ids(&a);
    assert!(
        !after.contains(&mid3),
        "the photo's message is stopped with the chat"
    );
    assert_eq!(after.len(), 1, "the text still waits");
    // What still waits may show again, as a clear leaves it: never a photo.
    let _ = wait_until(Duration::from_secs(3), &mut [&mut wa], || false);
    let left = history(&a, &b);
    assert!(
        left.iter().all(|m| m.get("attachment").is_none()),
        "{left:?}"
    );
    assert!(left.iter().all(|m| m["text"] != "one more"), "{left:?}");
    a.stop();
}

/// What an app that ended before a photo's send went leaves behind: the
/// sealed photo with its row, and the history row that kept the message as
/// not sent, which holds the stored form (never the offer). After the next
/// launch Send again makes the offer again from the attachment's row and
/// the photo arrives. When the sealed bytes are gone the send fails
/// cleanly: nothing goes, least of all the caption as a text.
#[test]
fn a_photo_whose_send_did_not_go_before_the_app_ended_goes_again() {
    if !lab() {
        return;
    }
    let a = Peer::new("Sender");
    let b = Peer::new("Receiver");
    a.befriend(&b, None);
    b.befriend(&a, None);
    let (la, lb) = (a.start(), b.start());
    a.set_lan(&b, &lb);
    b.set_lan(&a, &la);
    let friend = friend_key(&a);
    // B's Raven takes photos (the test above shows how a node learns it).
    let now = raven_core::clock::now_ms();
    peers::note(&a.path, &friend, true, now).unwrap();
    let can = a.ok("attachments.can_send", json!({"address": b.address()}));
    assert_eq!(can["photos"], true, "{can}");

    // The photo sealed, and its message kept as not sent: the attachment's
    // id and its own bytes.
    let kept = |salt: usize, mid: u8, caption: &str| -> (String, Vec<u8>) {
        let bytes = jpeg(90_000, salt);
        let media = Media::Photo {
            caption,
            width: 640,
            height: 480,
            preview: &PREVIEW,
        };
        let made = flow::prepare(&a.path, &friend, &bytes, &media, now).unwrap();
        let stored = store::get(&a.path, &made.handle)
            .unwrap()
            .expect("its row")
            .reference;
        assert!(stored.starts_with("RVNATT/1 ref\n"));
        raven_core::persist_lan_chat_history(
            &a.path,
            "out",
            &friend,
            &[mid; 16],
            now,
            "failed",
            stored.as_bytes(),
        )
        .unwrap();
        (hex::encode(made.handle), bytes)
    };
    let (id, bytes) = kept(1, 0x71, "again");
    let (lost, _) = kept(2, 0x72, "lost");
    store::remove(&a.path, &handle_of(&lost)).unwrap();

    // The next launch shows both as not sent, each with its caption.
    let not_sent = photo_row(&a, &b, &id).expect("the kept row");
    assert_eq!(not_sent["id"], hex::encode([0x71u8; 16]), "{not_sent}");
    assert_eq!(not_sent["state"], "failed", "{not_sent}");
    assert_eq!(not_sent["text"], "again", "{not_sent}");
    assert_eq!(not_sent["attachment"]["state"], "failed", "{not_sent}");
    assert_eq!(read_all(&a, &id, 524_288), bytes, "mine is readable");
    let lost_row = photo_row(&a, &b, &lost).expect("the kept row");
    assert_eq!(lost_row["attachment"]["state"], "failed", "{lost_row}");

    // Send again: a new message carries the same photo.
    let again = a.ok("messages.retry", json!({"id": not_sent["id"]}));
    assert_eq!(again["changed"], true, "{again}");
    assert_eq!(again["replaces"], not_sent["id"], "{again}");
    let new = &again["message"];
    assert_eq!(new["text"], "again", "{again}");
    assert_eq!(new["state"], "sending", "{again}");
    assert_eq!(new["attachment"]["id"], id.as_str(), "{again}");
    assert_eq!(new["attachment"]["state"], "sending", "{again}");
    let new_row = new["id"].as_str().unwrap().to_owned();
    assert_ne!(new_row, not_sent["id"].as_str().unwrap());
    let (mut wa, mut wb) = (Watch::new(&a), Watch::new(&b));
    let arrived = wait_until(Duration::from_secs(120), &mut [&mut wa, &mut wb], || {
        photo_row(&b, &a, &id).is_some_and(|m| m["attachment"]["state"] == "ready")
            && row(&a, &b, &new_row).is_some_and(|m| {
                m["state"] == "delivered" && m["attachment"]["state"] == "delivered"
            })
    });
    assert!(
        arrived,
        "receiver {:?}, sender {:?}; sender's node: {}",
        photo_row(&b, &a, &id),
        row(&a, &b, &new_row),
        a.service_log()
    );
    assert_eq!(read_all(&b, &id, 524_288), bytes);
    let theirs = photo_row(&b, &a, &id).unwrap();
    assert_eq!(theirs["text"], "again", "{theirs}");
    // One bubble for the photo: the row it replaces is left out. And the
    // attachment's row knows the message that carried it.
    let mine: Vec<Value> = history(&a, &b)
        .into_iter()
        .filter(|m| m["attachment"]["id"] == id.as_str())
        .collect();
    assert_eq!(mine.len(), 1, "{mine:?}");
    assert_eq!(mine[0]["id"], new_row.as_str());
    let sealed = store::get(&a.path, &handle_of(&id)).unwrap().unwrap();
    let carried = sealed.message_id_bytes().unwrap();
    assert!(
        carried != [0u8; 16] && carried != [0x71u8; 16],
        "its new message"
    );

    // The other photo's sealed bytes are gone: it cannot go again, and
    // nothing of it reaches the friend.
    assert_eq!(
        a.err("messages.retry", json!({"id": lost_row["id"]})),
        "ATTACHMENT_GONE"
    );
    let _ = wait_until(Duration::from_secs(3), &mut [&mut wa, &mut wb], || false);
    let got = history(&b, &a);
    assert_eq!(got.len(), 1, "{got:?}");
    for m in history(&a, &b).iter().chain(got.iter()) {
        assert!(!common::all_text(m).contains("RVNATT/"), "{m}");
    }
    for e in wa.events.iter().chain(wb.events.iter()) {
        assert!(!common::all_text(e).contains("RVNATT/"), "{e}");
    }
}

/// One engine, no node: who photos can be sent to, what is refused before
/// anything is sealed, and a row that holds an offer this build only kept.
#[test]
fn what_cannot_be_sent_is_refused_and_nothing_stays() {
    if !lab() {
        return;
    }
    let a = Peer::new("Sender");
    let b = Peer::new("Receiver");
    let address = b.address();
    let can = || a.ok("attachments.can_send", json!({"address": address}));
    let plain = |words: &str| !words.contains(['-', '\u{2013}', '\u{2014}', '\'', '\u{2019}']);

    // Not a friend; a friend not verified; verified, no word from their
    // Raven yet; then a friend photos go to; then blocked.
    assert_eq!(
        a.err("attachments.can_send", json!({"address": address})),
        "NOT_A_CONTACT"
    );
    a.ok(
        "contacts.add",
        json!({"text": b.me["invite"], "name": "Max"}),
    );
    let unverified = can();
    assert_eq!(unverified["photos"], false, "{unverified}");
    assert_eq!(unverified["why"], "Verify Max first to send photos");
    let checked = a.ok(
        "verify.check_words",
        json!({"address": address, "words": b.me["words"]}),
    );
    assert_eq!(checked["result"], "match", "{checked}");
    let old = can();
    assert_eq!(old["photos"], false, "{old}");
    assert_eq!(
        old["why"],
        "Max cannot get photos yet. Their Raven has not said that it takes them"
    );
    let group = a.ok("attachments.can_send", json!({"group": "ab".repeat(16)}));
    assert_eq!(group["photos"], false, "{group}");
    for why in [&unverified["why"], &old["why"], &group["why"]] {
        assert!(plain(why.as_str().unwrap()), "{why}");
    }

    // A staged file and what `attachments.send` refuses: the file goes in
    // every outcome, and nothing is sealed or queued.
    let stage = || -> String {
        a.ok("attachments.stage", json!({}))["path"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let send = |path: &str, change: Value| -> String {
        let mut args = json!({
            "address": address, "path": path, "kind": "photo", "mime": "image/jpeg",
            "preview_b64": BASE64.encode(PREVIEW), "width": 800, "height": 600,
        });
        for (k, v) in change.as_object().unwrap() {
            args[k] = v.clone();
        }
        a.err("attachments.send", args)
    };
    let staged = |bytes: &[u8]| -> String {
        let path = stage();
        std::fs::write(&path, bytes).unwrap();
        path
    };
    let good = jpeg(10_000, 1);
    // The friend's Raven did not say it takes photos.
    let path = staged(&good);
    assert_eq!(send(&path, json!({})), "FRIEND_NEEDS_NEWER_RAVEN");
    assert!(!Path::new(&path).exists());
    // It did: photos go.
    peers::note(&a.path, &friend_key(&a), true, 1).unwrap();
    let yes = can();
    assert_eq!(yes["photos"], true, "{yes}");
    assert!(yes.get("why").is_none(), "{yes}");

    // Only a file `attachments.stage` gave: another file is left alone.
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(outside.path(), &good).unwrap();
    assert_eq!(
        send(outside.path().to_str().unwrap(), json!({})),
        "BAD_REQUEST"
    );
    assert_eq!(std::fs::read(outside.path()).unwrap(), good);
    let secrets = a.path.join("contacts.json");
    assert_eq!(send(secrets.to_str().unwrap(), json!({})), "BAD_REQUEST");
    assert!(secrets.exists(), "a file of the profile is never taken");
    for (what, bytes, change, code) in [
        ("not a JPEG", vec![1u8; 5_000], json!({}), "ATTACHMENT_BAD"),
        ("empty", Vec::new(), json!({}), "ATTACHMENT_BAD"),
        (
            "too big",
            jpeg(1_048_577, 2),
            json!({}),
            "ATTACHMENT_TOO_BIG",
        ),
        (
            "no preview",
            good.clone(),
            json!({"preview_b64": null}),
            "ATTACHMENT_BAD",
        ),
        (
            "a preview that is not base64",
            good.clone(),
            json!({"preview_b64": "!!"}),
            "BAD_REQUEST",
        ),
        (
            "another type",
            good.clone(),
            json!({"mime": "image/png"}),
            "ATTACHMENT_BAD",
        ),
        (
            "a voice message",
            good.clone(),
            json!({"kind": "voice"}),
            "NOT_AVAILABLE_YET",
        ),
        (
            "a file",
            good.clone(),
            json!({"kind": "file"}),
            "NOT_AVAILABLE_YET",
        ),
        (
            "an unknown kind",
            good.clone(),
            json!({"kind": "hologram"}),
            "BAD_REQUEST",
        ),
        (
            "no size",
            good.clone(),
            json!({"width": null}),
            "BAD_REQUEST",
        ),
        (
            "a size no photo has",
            good.clone(),
            json!({"height": 100_000}),
            "ATTACHMENT_BAD",
        ),
        (
            "a caption too long",
            good.clone(),
            json!({"caption": "x".repeat(2_001)}),
            "MESSAGE_TOO_LONG",
        ),
        (
            "a caption that is a frame",
            good.clone(),
            json!({"caption": "RVNATT/1 offer\n{}"}),
            "BAD_REQUEST",
        ),
        (
            "a group",
            good.clone(),
            json!({"group": "ab".repeat(16)}),
            "NOT_AVAILABLE_YET",
        ),
        (
            "nobody",
            good.clone(),
            json!({"address": "rvn1nobody"}),
            "NOT_A_CONTACT",
        ),
    ] {
        let path = staged(&bytes);
        assert_eq!(send(&path, change), code, "{what}");
        assert!(!Path::new(&path).exists(), "{what}: the staged file stays");
    }
    // Exactly the most Raven sends would go; one more byte did not.
    assert!(
        store::rows_on_disk(&a.path).is_empty(),
        "nothing was sealed"
    );
    let staging: Vec<_> = std::fs::read_dir(a.path.join(store::STAGING_DIR))
        .unwrap()
        .flatten()
        .collect();
    assert!(staging.is_empty(), "{staging:?}");
    assert!(history(&a, &b).is_empty(), "nothing was queued");

    // An attachment nobody has here.
    let nothing = "ab".repeat(16);
    for op in ["get", "read", "download", "cancel"] {
        assert_eq!(
            a.err(&format!("attachments.{op}"), json!({"id": nothing})),
            "ATTACHMENT_GONE",
            "{op}"
        );
        assert_eq!(
            a.err(&format!("attachments.{op}"), json!({"id": "not an id"})),
            "BAD_REQUEST",
            "{op}"
        );
    }
    let out = tempfile::tempdir().unwrap();
    assert_eq!(
        a.err(
            "attachments.export",
            json!({"id": nothing, "to_path": out.path().join("x.jpg")})
        ),
        "ATTACHMENT_GONE"
    );

    // Blocked: nothing goes to them.
    a.ok("contacts.block", json!({"address": address}));
    let blocked = can();
    assert_eq!(blocked["photos"], false, "{blocked}");
    assert_eq!(blocked["why"], "Unblock Max to send photos");
    let path = staged(&good);
    assert_eq!(send(&path, json!({})), "CONTACT_BLOCKED");
    assert!(!Path::new(&path).exists());
    a.ok("contacts.unblock", json!({"address": address}));
    assert_eq!(can()["photos"], true);

    // An offer that a build with the gate shut took and kept as it came
    // (every release today): the row says plain words and `needs_update`,
    // and never the offer.
    let offer = {
        let blob = BlobRef {
            shape: Shape::of(200_000).unwrap(),
            key: Key::from_bytes([3u8; 32]),
            root: [4u8; 32],
        };
        Offer::photo(blob, "seen later", 800, 600, &PREVIEW)
            .unwrap()
            .encode()
            .unwrap()
    };
    raven_core::attachment_gate::set_lab_attachments_for_this_thread(Some(false));
    let kept = raven_core::persist_lan_chat_history(
        &a.path,
        "in",
        &friend_key(&a),
        &[0x55; 16],
        raven_core::clock::now_ms(),
        "received",
        offer.as_bytes(),
    );
    raven_core::attachment_gate::set_lab_attachments_for_this_thread(None);
    kept.unwrap();
    let rows = history(&a, &b);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["direction"], "in");
    assert_eq!(rows[0]["text"], "Max sent a photo. Update Raven to see it.");
    assert_eq!(
        rows[0]["attachment"],
        json!({"kind": "photo", "state": "needs_update"})
    );
    assert!(!common::all_text(&rows[0]).contains("RVNATT/"), "{rows:?}");
    let friends = a.ok("contacts.list", json!({}));
    assert_eq!(friends["contacts"][0]["unread"], 1, "{friends}");
    assert!(!common::all_text(&friends).contains("RVNATT/"), "{friends}");
    let chats = a.ok("chats.list", json!({}));
    assert!(!common::all_text(&chats).contains("RVNATT/"), "{chats}");
    let details = a.ok("messages.details", json!({"id": rows[0]["id"]}));
    assert!(!common::all_text(&details).contains("RVNATT/"), "{details}");
}
