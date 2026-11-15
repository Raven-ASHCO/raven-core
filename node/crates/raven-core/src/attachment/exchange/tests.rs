//! Two profiles exchange an attachment's chunks, with the frames carried
//! by hand: what a link would carry, in the order it would.

use std::sync::Mutex;

use super::*;
use crate::attachment::blob::{self, Key, KEY_LEN, SEGMENT_LEN};
use crate::attachment::flow::{self, Media};
use crate::attachment::offer::{self, BlobRef, Frame as OfferFrame, Offer};
use crate::attachment::store::Chat;
use crate::attachment_gate;

const KA: [u8; 32] = [0xA1; 32];
const KB: [u8; 32] = [0xB2; 32];
const KX: [u8; 32] = [0xC3; 32];
const MID: [u8; 16] = [0x4D; 16];

/// Attachments live for this test's thread.
struct Live;
impl Live {
    fn on() -> Option<Live> {
        // The lab switch opens nothing in a release build.
        cfg!(debug_assertions).then(|| {
            attachment_gate::set_lab_attachments_for_this_thread(Some(true));
            Live
        })
    }
}
impl Drop for Live {
    fn drop(&mut self) {
        attachment_gate::set_lab_attachments_for_this_thread(None);
    }
}

fn jpeg(len: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..len).map(|i| (i * 13 % 247) as u8).collect();
    bytes[..3].copy_from_slice(&[0xFF, 0xD8, 0xFF]);
    bytes
}

fn photo<'a>() -> Media<'a> {
    Media::Photo {
        caption: "",
        width: 1_600,
        height: 1_200,
        preview: &[1, 2, 3],
    }
}

/// One profile: its folder and what its exchange remembers.
struct Side {
    dir: tempfile::TempDir,
    memory: Mutex<Memory>,
}

impl Side {
    fn new() -> Side {
        Side {
            dir: tempfile::tempdir().unwrap(),
            memory: Mutex::default(),
        }
    }

    fn d(&self) -> &Path {
        self.dir.path()
    }

    fn x(&self) -> Exchange<'_> {
        Exchange::new(self.dir.path(), &self.memory)
    }

    fn row(&self, handle: &Handle) -> Row {
        store::get(self.d(), handle).unwrap().unwrap()
    }

    /// The dials due now, every friend taking attachments.
    fn plans(&self, now: u64) -> Vec<Plan> {
        self.x().plans(now, &|_| true).plans
    }
}

/// `a` sends `bytes` to `b` as a photo and the offer is delivered: a's row
/// and blob, the offer kept by `b` as it would be when the message came,
/// and its delivery written on `a` as it is when the ACK comes back.
fn offered(a: &Side, b: &Side, bytes: &[u8], now: u64) -> Handle {
    let (handle, offer) = staged(a, bytes, now);
    keep(b, &offer, now);
    delivered(a, &offer, now);
    handle
}

/// `a` sealed `bytes` for `b` and its offer is on its way: nothing says
/// yet that it arrived.
fn staged(a: &Side, bytes: &[u8], now: u64) -> (Handle, String) {
    let made = flow::prepare(a.d(), &KB, bytes, &photo(), now).unwrap();
    flow::sent(a.d(), &made.handle, &MID, now).unwrap();
    (made.handle, made.offer)
}

/// The offer's ACK came back to `a`: what the history write does then.
fn delivered(a: &Side, offer: &str, now: u64) {
    flow::history_body(a.d(), "out", &KB, &MID, "delivered", offer, now)
        .unwrap()
        .unwrap();
}

fn keep(b: &Side, text: &str, now: u64) {
    let Some(OfferFrame::Offer(offer)) = offer::parse_frame(text.as_bytes()) else {
        panic!("an offer");
    };
    assert_eq!(
        flow::keep_offer(b.d(), &KA, &MID, &offer, text, now).unwrap(),
        flow::Kept::New
    );
}

/// The dial of `plan` from `from` (whose key is `from_key`) to `to`: every
/// frame handed to the listener, its replies back in order.
fn dial(to: &Side, from_key: &[u8; 32], plan: &Plan, now: u64) -> Vec<Vec<u8>> {
    plan.frames
        .iter()
        .flat_map(|f| to.x().listener_frame(from_key, f, now))
        .collect()
}

/// Runs `a`'s push to `b` until `a` has nothing more to say; the dials made.
fn push_all(a: &Side, b: &Side, now: u64) -> usize {
    let mut dials = 0;
    loop {
        let plans = a.plans(now);
        let Some(plan) = plans.first() else {
            return dials;
        };
        dials += 1;
        assert!(dials < 20, "the push does not end");
        let replies = dial(b, &KA, plan, now);
        if !a.x().took(plan, Some(&replies), now) {
            return dials;
        }
    }
}

fn ops(plan: &Plan) -> Vec<u8> {
    plan.frames.iter().map(|f| f[5]).collect()
}

#[test]
fn a_photo_goes_over_in_one_dial_once_its_offer_is_delivered() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let bytes = jpeg(300_000);
    let (handle, offer) = staged(&a, &bytes, now);
    let chunks = a.row(&handle).shape().unwrap().chunks();
    assert_eq!(chunks, 5, "300,000 bytes, padded, in chunks of 61,424");

    // While the offer is on its way nothing is said: no dial, no question.
    let planned = a.x().plans(now, &|_| true);
    assert!(planned.plans.is_empty() && planned.waiting);

    // The offer arrives and its ACK comes back: every chunk goes at once,
    // with HAVE behind them. No question first.
    keep(&b, &offer, now);
    delivered(&a, &offer, now);
    assert_eq!(a.row(&handle).state, State::Offered);
    let plan = a.plans(now).remove(0);
    assert_eq!((plan.peer, plan.handle), (KB, handle));
    assert_eq!(ops(&plan), [0x04, 0x04, 0x04, 0x04, 0x04, 0x01]);
    let replies = dial(&b, &KA, &plan, now);
    assert_eq!(
        replies.len(),
        1,
        "a PUSH has no answer; the HAVE has its LACK"
    );
    assert!(!a.x().took(&plan, Some(&replies), now));
    let mine = a.row(&handle);
    assert_eq!((mine.state, mine.friend_has), (State::Delivered, chunks));
    assert_eq!(store::progress(a.d(), &mine), (300_000, 300_000));

    // The friend has the photo, byte for byte.
    let theirs = b.row(&handle);
    assert_eq!(theirs.state, State::Complete);
    assert_eq!(store::progress(b.d(), &theirs), (300_000, 300_000));
    assert_eq!(
        &store::read_plain(b.d(), &theirs, 0, bytes.len()).unwrap()[..],
        &bytes[..]
    );

    // It says DONE once; the sender has nothing more to say.
    assert!(a.plans(now).is_empty());
    let done = b.plans(now).remove(0);
    assert_eq!((done.peer, ops(&done)), (KA, vec![0x03]));
    assert!(dial(&a, &KB, &done, now).is_empty());
    assert!(!b.x().took(&done, Some(&[]), now));
    assert!(b.plans(now).is_empty());
    assert_eq!(a.row(&handle).state, State::Delivered);
}

#[test]
fn a_delivery_written_without_the_body_starts_the_push_too() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let (handle, offer) = staged(&a, &jpeg(100_000), now);
    keep(&b, &offer, now);
    // The message is written as queued with its body (the offer), and its
    // delivery later by its id alone.
    flow::history_body(a.d(), "out", &KB, &MID, "queued", &offer, now)
        .unwrap()
        .unwrap();
    assert_eq!(a.row(&handle).state, State::Staged);
    flow::message_delivered(a.d(), &[0x77; 16], now);
    assert_eq!(
        a.row(&handle).state,
        State::Staged,
        "another message's delivery"
    );
    flow::message_delivered(a.d(), &MID, now);
    assert_eq!(a.row(&handle).state, State::Offered);
    assert_eq!(push_all(&a, &b, now), 1);
    assert_eq!(a.row(&handle).state, State::Delivered);
}

#[test]
fn an_offer_whose_delivery_was_not_seen_is_asked_for_after_a_while() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let bytes = jpeg(300_000);
    let (handle, offer) = staged(&a, &bytes, now);
    keep(&b, &offer, now);
    // The delivery was noted by a process that ended: the row still says
    // staged. After a few seconds the friend is asked: one small frame.
    assert!(a.plans(now + STAGED_PROBE_AFTER_MS - 1).is_empty());
    let later = now + STAGED_PROBE_AFTER_MS;
    let plan = a.plans(later).remove(0);
    assert_eq!(ops(&plan), [0x01], "HAVE alone");
    let replies = dial(&b, &KA, &plan, later);
    assert!(
        a.x().took(&plan, Some(&replies), later),
        "the friend wants all of it"
    );
    assert_eq!(a.row(&handle).state, State::Offered);
    assert_eq!(a.row(&handle).friend_has, 0);
    // Then every chunk, and HAVE again.
    let plan = a.plans(later).remove(0);
    assert_eq!(ops(&plan), [0x04, 0x04, 0x04, 0x04, 0x04, 0x01]);
    assert!(!a.x().took(&plan, Some(&dial(&b, &KA, &plan, later)), later));
    assert_eq!(a.row(&handle).state, State::Delivered);
    assert_eq!(b.row(&handle).state, State::Complete);
}

#[test]
fn a_friend_that_does_not_know_the_offer_yet_is_asked_again_later() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let (handle, offer) = staged(&a, &jpeg(100_000), now);
    // Asked after a while (the delivery was not seen): not known there.
    let asked = now + STAGED_PROBE_AFTER_MS;
    let plan = a.plans(asked).remove(0);
    let replies = dial(&b, &KA, &plan, asked);
    assert!(!a.x().took(&plan, Some(&replies), asked));
    assert_eq!(
        a.row(&handle).state,
        State::Staged,
        "the offer is not there"
    );
    // Not at once, and not for ever.
    let planned = a.x().plans(asked + 1_000, &|_| true);
    assert!(planned.plans.is_empty() && planned.waiting);
    assert_eq!(a.plans(asked + 2_000).len(), 1);
    // The offer arrives: the same question gets the other answer.
    keep(&b, &offer, now);
    assert_eq!(push_all(&a, &b, asked + 2_000), 2);
    assert_eq!(a.row(&handle).state, State::Delivered);
    assert_eq!(b.row(&handle).state, State::Complete);
}

#[test]
fn an_offer_never_delivered_is_asked_about_ever_less_often_and_then_no_more() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let (handle, _offer) = staged(&a, &jpeg(50_000), now);
    // The friend never gets the offer. Each question is answered "not
    // known", and the wait doubles past the five minutes of other tries.
    let mut at = now + STAGED_PROBE_AFTER_MS;
    let mut waits = Vec::new();
    for _ in 0..16 {
        let plan = a.plans(at).remove(0);
        assert_eq!(ops(&plan), [0x01]);
        assert!(!a.x().took(&plan, Some(&dial(&b, &KA, &plan, at)), at));
        // The next question is not asked a moment before its time.
        let mut wait = 1_000u64;
        while a.plans(at + wait).is_empty() {
            wait *= 2;
            assert!(wait < 2 * DAY_MS, "it is asked again within a day");
        }
        waits.push(wait);
        at += wait;
    }
    assert!(waits[0] <= 2_000 && waits[5] >= 60_000, "{waits:?}");
    assert!(*waits.last().unwrap() > RETRY_MAX_MS, "{waits:?}");
    assert!(
        *waits.last().unwrap() <= 2 * STAGED_RETRY_MAX_MS,
        "{waits:?}"
    );
    assert_eq!(a.row(&handle).state, State::Staged);
    // Past its message's time to arrive, nothing is asked any more.
    let planned = a.x().plans(now + STAGED_MAX_AGE_MS, &|_| true);
    assert!(planned.plans.is_empty() && !planned.waiting);
}

#[test]
fn a_delivery_that_comes_after_an_early_question_is_not_held_back_by_its_wait() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let (handle, offer) = staged(&a, &jpeg(100_000), now);
    let asked = now + STAGED_PROBE_AFTER_MS;
    let plan = a.plans(asked).remove(0);
    assert!(!a.x().took(&plan, Some(&dial(&b, &KA, &plan, asked)), asked));
    assert!(
        a.plans(asked + 100).is_empty(),
        "waiting after the early question"
    );
    // The offer lands and its ACK comes back a moment later.
    keep(&b, &offer, asked);
    delivered(&a, &offer, asked + 100);
    let plan = a.plans(asked + 100).remove(0);
    // Something was tried before: the friend is asked first, not pushed at.
    assert_eq!(ops(&plan), [0x01]);
    assert!(a
        .x()
        .took(&plan, Some(&dial(&b, &KA, &plan, asked)), asked + 100));
    assert_eq!(push_all(&a, &b, asked + 100), 1);
    assert_eq!(a.row(&handle).state, State::Delivered);
}

#[test]
fn nothing_is_said_to_a_friend_whose_node_does_not_take_attachments() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    offered(&a, &b, &jpeg(50_000), now);
    let planned = a.x().plans(now, &|_| false);
    assert!(planned.plans.is_empty() && planned.waiting);
    let planned = b.x().plans(now + PULL_AFTER_MS, &|_| false);
    assert!(planned.plans.is_empty() && planned.waiting);
}

#[test]
fn a_cut_resumes_from_what_landed() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let bytes = jpeg(400_000);
    let handle = offered(&a, &b, &bytes, now);
    let chunks = a.row(&handle).shape().unwrap().chunks();
    // The link is cut after two chunks: no answer comes back.
    let plan = a.plans(now).remove(0);
    assert_eq!(plan.frames.len() as u32, chunks + 1, "every chunk and HAVE");
    for frame in &plan.frames[..2] {
        assert!(b.x().listener_frame(&KA, frame, now).is_empty());
    }
    assert!(!a.x().took(&plan, None, now));
    assert_eq!(
        store::progress(b.d(), &b.row(&handle)).0,
        2 * SEGMENT_LEN as u64
    );
    // The next try asks first, and pushes only what is missing.
    assert!(
        a.plans(now + 1_000).is_empty(),
        "a moment's wait after a cut"
    );
    let plan = a.plans(now + 2_000).remove(0);
    assert_eq!(ops(&plan), [0x01]);
    assert!(a
        .x()
        .took(&plan, Some(&dial(&b, &KA, &plan, now)), now + 2_000));
    assert_eq!(a.row(&handle).friend_has, 2);
    let plan = a.plans(now + 2_000).remove(0);
    assert_eq!(plan.frames.len() as u32, chunks - 2 + 1);
    assert!(!a
        .x()
        .took(&plan, Some(&dial(&b, &KA, &plan, now)), now + 2_000));
    assert_eq!(a.row(&handle).state, State::Delivered);
    let theirs = b.row(&handle);
    assert_eq!(
        &store::read_plain(b.d(), &theirs, 0, bytes.len()).unwrap()[..],
        &bytes[..]
    );
}

#[test]
fn a_friend_seen_again_is_tried_at_once() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let handle = offered(&a, &b, &jpeg(50_000), now);
    let plan = a.plans(now).remove(0);
    assert!(!a.x().took(&plan, None, now), "the friend is away");
    assert!(a.plans(now + 100).is_empty());
    a.x().peer_seen(&KX);
    assert!(
        a.plans(now + 100).is_empty(),
        "another friend's link changes nothing"
    );
    a.x().peer_seen(&KB);
    assert_eq!(push_all(&a, &b, now + 100), 2);
    assert_eq!(a.row(&handle).state, State::Delivered);
}

#[test]
fn a_bad_chunk_is_dropped_and_three_end_that_source() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let handle = offered(&a, &b, &jpeg(300_000), now);
    let plan = a.plans(now).remove(0);
    // Each chunk with one byte changed: none proves its place.
    for frame in &plan.frames[..3] {
        let mut bad = frame.clone();
        let at = link::HEADER_LEN + 16 + 2 + 4 + 100;
        bad[at] ^= 1;
        assert!(b.x().listener_frame(&KA, &bad, now).is_empty());
    }
    let theirs = b.row(&handle);
    assert_eq!(store::progress(b.d(), &theirs).0, 0, "nothing was written");
    // After three, that source is not listened to for this attachment.
    assert!(b.x().listener_frame(&KA, &plan.frames[3], now).is_empty());
    assert_eq!(store::progress(b.d(), &theirs).0, 0);
    let have = plan.frames.last().unwrap();
    let lack = b.x().listener_frame(&KA, have, now).remove(0);
    let Body::Lack(entries) = link::decode_for_dialer(&lack).unwrap().body else {
        panic!("a LACK");
    };
    assert_eq!(entries, vec![(handle, Lack::Declined)]);
    assert!(b.plans(now + PULL_AFTER_MS).is_empty(), "nor asked for it");
}

#[test]
fn only_the_friend_who_offered_it_can_fill_it_and_only_the_one_offered_is_served() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let handle = offered(&a, &b, &jpeg(100_000), now);
    let plan = a.plans(now).remove(0);
    // The right chunks from another friend: not taken, and not known.
    let replies = dial(&b, &KX, &plan, now);
    let Body::Lack(entries) = link::decode_for_dialer(&replies[0]).unwrap().body else {
        panic!("a LACK");
    };
    assert_eq!(entries, vec![(handle, Lack::NotKnown)]);
    assert_eq!(store::progress(b.d(), &b.row(&handle)).0, 0);
    // Another friend asks the holder for it: there is no such attachment.
    let want = encode(
        [9; 4],
        Body::Want {
            handle,
            first: 0,
            count: 1,
        },
    );
    let reply = a.x().listener_frame(&KX, &want, now).remove(0);
    assert_eq!(
        link::decode_for_dialer(&reply).unwrap().body,
        Body::Error(ErrorCode::NotFound)
    );
    // DONE from someone else changes nothing.
    assert!(a
        .x()
        .listener_frame(&KX, &encode([9; 4], Body::Done(handle)), now)
        .is_empty());
    assert_eq!(a.row(&handle).state, State::Offered);
    // The receiver is not served its own incoming attachment back.
    let reply = b.x().listener_frame(&KA, &want, now).remove(0);
    assert_eq!(
        link::decode_for_dialer(&reply).unwrap().body,
        Body::Error(ErrorCode::NotFound)
    );
}

#[test]
fn a_pull_fetches_what_is_missing_and_says_done() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let bytes = jpeg(LIVE_MAX_LEN as usize);
    // The sender's node is not dialing (it cannot reach the receiver, and
    // the offer's delivery was not seen by it).
    let (handle, offer) = staged(&a, &bytes, now);
    keep(&b, &offer, now);
    let chunks = b.row(&handle).shape().unwrap().chunks();
    assert_eq!(chunks, 18);
    // Not while the sender may still be pushing.
    let planned = b.x().plans(now + 1_000, &|_| true);
    assert!(planned.plans.is_empty() && planned.waiting);
    // Nothing landed for a while: the receiver asks, 16 chunks a dial.
    let later = now + PULL_AFTER_MS;
    let plan = b.plans(later).remove(0);
    assert_eq!((plan.peer, ops(&plan)), (KA, vec![0x02]));
    let replies = dial(&a, &KB, &plan, later);
    assert_eq!(replies.len(), 17, "16 chunks and the end");
    assert!(b.x().took(&plan, Some(&replies), later));
    assert_eq!(
        store::progress(b.d(), &b.row(&handle)).0,
        16 * SEGMENT_LEN as u64
    );
    // The rest at once (a chunk just landed, but the pull is under way).
    let even_later = crate::clock::now_ms() + PULL_AFTER_MS;
    let plan = b.plans(even_later).remove(0);
    let replies = dial(&a, &KB, &plan, even_later);
    assert_eq!(replies.len(), 3);
    assert!(
        b.x().took(&plan, Some(&replies), even_later),
        "DONE goes next"
    );
    let theirs = b.row(&handle);
    assert_eq!(theirs.state, State::Complete);
    assert_eq!(
        &store::read_plain(b.d(), &theirs, 0, bytes.len()).unwrap()[..],
        &bytes[..]
    );
    assert_eq!(a.row(&handle).state, State::Staged);
    let done = b.plans(even_later).remove(0);
    assert_eq!(ops(&done), [0x03]);
    dial(&a, &KB, &done, even_later);
    assert!(!b.x().took(&done, Some(&[]), even_later));
    assert_eq!(a.row(&handle).state, State::Delivered);
    assert!(a.plans(even_later).is_empty() && b.plans(even_later).is_empty());
}

#[test]
fn a_file_waits_until_the_user_asks_for_it() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let file = Media::File {
        mime: "application/pdf",
        name: "plan.pdf",
        caption: "",
    };
    let made = flow::prepare(a.d(), &KB, &jpeg(100_000), &file, now).unwrap();
    keep(&b, &made.offer, now);
    delivered(&a, &made.offer, now);
    // Pushed like a photo; the friend's node does not take a file unasked.
    let plan = a.plans(now).remove(0);
    assert!(!a.x().took(&plan, Some(&dial(&b, &KA, &plan, now)), now));
    assert_eq!(store::progress(b.d(), &b.row(&made.handle)).0, 0);
    assert_eq!(
        a.row(&made.handle).state,
        State::Offered,
        "sent, not delivered"
    );
    assert!(
        b.plans(now + PULL_AFTER_MS).is_empty(),
        "a file is not fetched unasked"
    );
    // The tap: asked for, it is fetched at once.
    store::update(b.d(), &made.handle, now + 1, |row| row.asked = true).unwrap();
    let plan = b.plans(now + 2).remove(0);
    assert_eq!(ops(&plan), [0x02]);
    let replies = dial(&a, &KB, &plan, now + 2);
    assert!(b.x().took(&plan, Some(&replies), now + 2));
    assert_eq!(b.row(&made.handle).state, State::Complete);
}

#[test]
fn a_blob_that_does_not_open_under_the_offers_key_fails() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    // Chunks sealed under one key, offered under another: every chunk
    // proves its place under the root, and none opens.
    let bytes = jpeg(100_000);
    let sealed = blob::seal(&Key::from_bytes([1u8; KEY_LEN]), &bytes).unwrap();
    let offer = Offer::photo(
        BlobRef {
            shape: sealed.shape,
            key: Key::from_bytes([2u8; KEY_LEN]),
            root: sealed.root(),
        },
        "",
        100,
        100,
        &[1],
    )
    .unwrap();
    let text = offer.encode().unwrap();
    let row = Row::of_offer(&offer, &text, Chat::Friend(&KB), &MID, true, now).unwrap();
    store::write_blob(a.d(), &offer.handle, &sealed).unwrap();
    store::put(a.d(), &row).unwrap();
    keep(&b, &text, now);
    delivered(&a, &text, now);
    push_all(&a, &b, now);
    assert_eq!(b.row(&offer.handle).state, State::Failed);
    assert_eq!(
        a.row(&offer.handle).state,
        State::Offered,
        "never delivered"
    );
    assert!(b.plans(now).is_empty(), "no DONE for it");
}

#[test]
fn a_dialer_that_is_no_verified_friend_gets_a_refusal_for_a_request_and_nothing_else() {
    let have = encode([7; 4], Body::Have(vec![([1; 16], 3)]));
    let refused = refuse(&have);
    assert_eq!(refused.len(), 1);
    let reply = link::decode_for_dialer(&refused[0]).unwrap();
    assert_eq!(
        (reply.req, reply.body),
        ([7; 4], Body::Error(ErrorCode::PolicyDenied))
    );
    assert!(refuse(&encode([7; 4], Body::Done([1; 16]))).is_empty());
    assert!(refuse(b"RAX1").is_empty());
    assert!(refuse(b"RUP1\x01\x01aaaa").is_empty());
    // A request that does not read is answered so, not left waiting.
    let side = Side::new();
    let mut broken = have.clone();
    broken.push(0);
    let reply = side.x().listener_frame(&KA, &broken, 1).remove(0);
    assert_eq!(
        link::decode_for_dialer(&reply).unwrap().body,
        Body::Error(ErrorCode::Malformed)
    );
}
