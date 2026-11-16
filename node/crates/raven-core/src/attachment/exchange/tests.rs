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

    // Neither has anything more to say: the sender heard "complete" as
    // the answer to its own HAVE, so the receiver dials nobody to say DONE.
    assert!(a.plans(now).is_empty());
    assert!(b.plans(now).is_empty());
    assert_eq!(a.row(&handle).state, State::Delivered);
}

#[test]
fn the_link_that_carried_the_offer_takes_the_chunks_along() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let bytes = jpeg(300_000);
    let (handle, offer) = staged(&a, &bytes, now);
    // No send of the offer set out: a link with that friend carries no chunks.
    assert!(a.x().link_push(&KB, now).is_none());
    // The send sets out; the offer arrives and is answered on a link.
    flow::offer_going(a.d(), &handle, now);
    assert!(a.x().link_push(&KX, now).is_none(), "another friend's link");
    keep(&b, &offer, now);
    let plan = a
        .x()
        .link_push(&KB, now + 500)
        .expect("the chunks ride the link");
    assert_eq!(ops(&plan), [0x04, 0x04, 0x04, 0x04, 0x04, 0x01]);
    // Once only: a second link, or the task, does not push it whole again.
    assert!(a.x().link_push(&KB, now + 600).is_none());
    let replies = dial(&b, &KA, &plan, now + 500);
    assert!(!a.x().took(&plan, Some(&replies), now + 500));
    assert_eq!(a.row(&handle).state, State::Delivered);
    assert_eq!(b.row(&handle).state, State::Complete);
    assert_eq!(
        &store::read_plain(b.d(), &b.row(&handle), 0, bytes.len()).unwrap()[..],
        &bytes[..]
    );
    // The offer's delivery is written a moment later: nothing more to do.
    delivered(&a, &offer, now + 700);
    assert_eq!(a.row(&handle).state, State::Delivered);
    assert!(a.plans(now + 700).is_empty());
}

#[test]
fn nothing_is_asked_beside_a_send_of_the_offer_that_is_under_way() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let (handle, offer) = staged(&a, &jpeg(300_000), now);
    // The send set out and takes its time (over Tor a quarter of a minute
    // is usual): the task asks nothing meanwhile.
    flow::offer_going(a.d(), &handle, now);
    for later in [1_000, STAGED_PROBE_AFTER_MS, 30_000, GOING_FRESH_MS - 1] {
        let planned = a.x().plans(now + later, &|_| true);
        assert!(planned.plans.is_empty() && planned.waiting, "{later} ms in");
        assert_eq!(planned.waits.offer, 1);
    }
    // So the link that at last carries the offer still takes the chunks.
    keep(&b, &offer, now);
    let plan = a
        .x()
        .link_push(&KB, now + 15_000)
        .expect("the chunks ride the link");
    let replies = dial(&b, &KA, &plan, now + 15_000);
    assert!(!a.x().took(&plan, Some(&replies), now + 15_000));
    assert_eq!(a.row(&handle).state, State::Delivered);
    // A send that set out and was never heard of again: asked after a while.
    let (lost, _) = staged(&a, &jpeg(50_000), now);
    flow::offer_going(a.d(), &lost, now);
    let plan = a.plans(now + GOING_FRESH_MS).remove(0);
    assert_eq!((plan.handle, ops(&plan)), (lost, vec![0x01]));
}

#[test]
fn a_question_asked_before_the_offer_arrived_does_not_stop_the_chunks_riding_its_link() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let (handle, offer) = staged(&a, &jpeg(300_000), now);
    // No send under way that the task knows of: it asks, and the friend
    // does not know the offer yet.
    let asked = now + STAGED_PROBE_AFTER_MS;
    let plan = a.plans(asked).remove(0);
    assert_eq!(ops(&plan), [0x01]);
    assert!(!a.x().took(&plan, Some(&dial(&b, &KA, &plan, asked)), asked));
    // Then the send goes, the offer arrives, and its link takes the chunks:
    // a question pushed nothing, so nothing was tried yet.
    flow::offer_going(a.d(), &handle, asked + 100);
    keep(&b, &offer, asked + 100);
    let plan = a
        .x()
        .link_push(&KB, asked + 200)
        .expect("the chunks ride the link");
    assert_eq!(plan.frames.len(), 6);
    let replies = dial(&b, &KA, &plan, asked + 200);
    assert!(!a.x().took(&plan, Some(&replies), asked + 200));
    assert_eq!(a.row(&handle).state, State::Delivered);
}

#[test]
fn chunks_that_rode_a_link_too_early_or_were_cut_are_taken_up_by_the_task() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let (handle, offer) = staged(&a, &jpeg(300_000), now);
    flow::offer_going(a.d(), &handle, now);
    // The answer on the link was to another message: the friend's node
    // does not know the offer yet.
    let plan = a.x().link_push(&KB, now).unwrap();
    let replies = dial(&b, &KA, &plan, now);
    assert!(!a.x().took(&plan, Some(&replies), now));
    assert_eq!(a.row(&handle).state, State::Staged);
    // The offer arrives and its delivery is written: the task asks first
    // (something was tried), then pushes what is wanted.
    keep(&b, &offer, now);
    delivered(&a, &offer, now + 1_000);
    assert_eq!(push_all(&a, &b, now + 1_000), 2);
    assert_eq!(a.row(&handle).state, State::Delivered);
    // A send that set out long ago is not taken along any more.
    let (old, _) = staged(&a, &jpeg(50_000), now);
    flow::offer_going(a.d(), &old, now);
    assert!(a.x().link_push(&KB, now + GOING_FRESH_MS).is_none());
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
    // The question pushed nothing, so every chunk goes at once now.
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

// ── What a friend's node cannot make this node do (the review of 2026-11-15) ──

/// The request id of a plan's last frame (the HAVE of a push).
fn last_req(plan: &Plan) -> [u8; 4] {
    plan.frames.last().unwrap()[6..link::HEADER_LEN]
        .try_into()
        .unwrap()
}

/// Makes every dial `a` plans to `b`, look after look, until `a` plans no
/// more; the dials made. (Every plan a look gives is dialled, as raven-node
/// does: a plan that is made counts its chunks as pushed.)
fn run_all(a: &Side, b: &Side, now: u64) -> usize {
    let mut dials = 0;
    loop {
        let plans = a.plans(now);
        if plans.is_empty() {
            return dials;
        }
        for plan in &plans {
            dials += 1;
            assert!(dials < 40, "the dials do not end");
            let replies = dial(b, &KA, plan, now);
            a.x().took(plan, Some(&replies), now);
        }
    }
}

/// The next time from `from` on, in steps of `step`, at which `side` plans
/// a dial, and that dial; `None` when none comes before `until`.
fn next_plan(side: &Side, from: u64, step: u64, until: u64) -> Option<(u64, Plan)> {
    let mut at = from;
    while at <= until {
        if let Some(plan) = side.plans(at).into_iter().next() {
            return Some((at, plan));
        }
        at += step;
    }
    None
}

#[test]
fn a_friend_that_asks_for_everything_again_and_again_gets_a_days_worth_and_no_more() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let handle = offered(&a, &b, &jpeg(300_000), now);
    let chunks = 5u32;
    let all: Vec<u32> = (0..chunks).collect();
    // The friend's node answers a push with "not known" and a question
    // with "I lack every chunk": no push ever counts as one that moved
    // nothing, and every question is answered with a call for everything.
    let answer = |plan: &Plan, at: u64| {
        let lack = if ops(plan).len() > 1 {
            Lack::NotKnown
        } else {
            Lack::wanting(chunks as u16, &all)
        };
        let reply = encode(last_req(plan), Body::Lack(vec![(handle, lack)]));
        a.x().took(plan, Some(&[reply]), at);
    };
    let day_end = now + DAY_MS - 60_000;
    let (mut at, mut pushed, mut dials) = (now, 0usize, 0usize);
    while let Some((due, plan)) = next_plan(&a, at, 20_000, day_end) {
        dials += 1;
        assert!(dials < 500, "the dials do not end");
        pushed += ops(&plan).iter().filter(|op| **op == 0x04).count();
        answer(&plan, due);
        at = due;
    }
    assert_eq!(
        pushed,
        (PUSH_ROUNDS_PER_DAY * chunks) as usize,
        "every chunk eight times in a day, and no more ({dials} dials)"
    );
    // Whatever the friend's node says, nothing more goes that day, and a
    // link with it coming up changes nothing.
    a.x().peer_seen(&KB);
    assert!(a.plans(day_end).is_empty());
    let planned = a.x().plans(day_end, &|_| true);
    assert!(planned.waiting && planned.waits.turn == 1, "{planned:?}");
    assert!(a.x().link_push(&KB, day_end).is_none());
    // The next day it is tried again.
    let (_, plan) =
        next_plan(&a, now + DAY_MS + 60_000, 20_000, now + DAY_MS + 3_600_000).expect("a new day");
    assert_eq!(ops(&plan), [0x01], "a question first");
    assert_eq!(a.row(&handle).state, State::Offered);
    // An honest answer then, and it goes over as any other.
    let replies = dial(&b, &KA, &plan, now + DAY_MS + 3_600_000);
    assert!(a.x().took(&plan, Some(&replies), now + DAY_MS + 3_600_000));
    assert_eq!(run_all(&a, &b, now + DAY_MS + 3_600_000), 1);
    assert_eq!(a.row(&handle).state, State::Delivered);
    assert_eq!(b.row(&handle).state, State::Complete);
}

#[test]
fn a_wait_the_friends_own_answer_set_is_not_ended_by_a_new_link() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let handle = offered(&a, &b, &jpeg(100_000), now);
    // A dial that did not reach the friend, then one it answers "later".
    let plan = a.plans(now).remove(0);
    assert!(!a.x().took(&plan, None, now));
    let (at, plan) = next_plan(&a, now, 500, now + 10_000).expect("the next try");
    let later = encode(last_req(&plan), Body::Lack(vec![(handle, Lack::Later)]));
    assert!(!a.x().took(&plan, Some(&[later]), at));
    // The friend's link comes up: the wait its answer set stands.
    a.x().peer_seen(&KB);
    assert!(a.plans(at + 1_000).is_empty());
    assert!(a.plans(at + LATER_MS - 1_000).is_empty());
    assert_eq!(a.plans(at + LATER_MS).len(), 1);
    // A wait after a dial that failed is ended by the link, as before.
    let plan = a.plans(at + LATER_MS).remove(0);
    assert!(!a.x().took(&plan, None, at + LATER_MS));
    assert!(a.plans(at + LATER_MS + 100).is_empty());
    a.x().peer_seen(&KB);
    assert_eq!(a.plans(at + LATER_MS + 100).len(), 1);
}

#[test]
fn tries_that_fail_grow_apart_until_a_friend_that_is_gone_is_dialled_a_few_times_a_day() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    offered(&a, &b, &jpeg(100_000), now);
    // Every dial fails. The times of the dials, over five days.
    let end = now + 5 * DAY_MS;
    let (mut at, mut dials) = (now, Vec::new());
    while let Some((due, plan)) = next_plan(&a, at, 1_000, end) {
        dials.push(due - now);
        assert!(!a.x().took(&plan, None, due));
        // Past the wait just set, in one step where it is long.
        let wait = a.memory.lock().unwrap().parked[&plan.handle].until_ms;
        at = wait.max(due + 1_000);
    }
    let within = |from: u64, to: u64| dials.iter().filter(|t| **t >= from && **t < to).count();
    assert!(within(0, 600_000) >= 8, "quick at first: {dials:?}");
    let first_hour = within(0, 3_600_000);
    assert!(
        (15..=25).contains(&first_hour),
        "{first_hour} in the first hour"
    );
    let first_day = within(0, DAY_MS);
    assert!(
        (40..=70).contains(&first_day),
        "{first_day} in the first day"
    );
    let fifth_day = within(4 * DAY_MS, 5 * DAY_MS);
    assert!((3..=5).contains(&fifth_day), "{fifth_day} on the fifth day");
    // The friend is there again: tried at once, and quick again after it.
    a.x().peer_seen(&KB);
    let plan = a.plans(end).remove(0);
    assert!(!a.x().took(&plan, None, end));
    assert_eq!(a.plans(end + RETRY_MS).len(), 1);
}

#[test]
fn a_friend_that_was_not_reached_is_not_dialled_again_for_its_other_attachments() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let handles = [
        offered(&a, &b, &jpeg(100_000), now),
        offered(&a, &b, &jpeg(100_001), now),
        offered(&a, &b, &jpeg(100_002), now),
    ];
    // One dial per friend in a look; it does not reach the friend.
    let planned = a.x().plans(now, &|_| true);
    assert_eq!(planned.plans.len(), 1);
    assert_eq!(planned.waits.turn, 2, "the other two wait their turn");
    assert_eq!(
        a.memory.lock().unwrap().tried.len(),
        1,
        "only the one in the dial counts as pushed"
    );
    assert!(!a.x().took(&planned.plans[0], None, now));
    // The other two are not tried in its place: all three wait as long.
    let planned = a.x().plans(now + 100, &|_| true);
    assert!(planned.plans.is_empty() && planned.waiting, "{planned:?}");
    assert_eq!(planned.waits.turn, 3);
    assert_eq!(a.plans(now + RETRY_MS).len(), 1);
    // A second failure: the wait doubles for all of them, whichever was tried.
    let plan = a.plans(now + RETRY_MS).remove(0);
    assert!(!a.x().took(&plan, None, now + RETRY_MS));
    assert!(a.plans(now + 2 * RETRY_MS + RETRY_MS - 100).is_empty());
    let third = a.plans(now + 3 * RETRY_MS);
    assert_eq!(third.len(), 1);
    assert!(!a.x().took(&third[0], None, now + 3 * RETRY_MS));
    // The friend is there again: one after the other they go. One that
    // was pushed into a dial that failed asks first, as after a cut; one
    // that only waited its turn was never counted as pushed, and is pushed
    // whole at once. (The three failed dials carried one, two or all
    // three of them.)
    let cut = a.memory.lock().unwrap().tried.len();
    assert!((1..=3).contains(&cut), "{cut}");
    a.x().peer_seen(&KB);
    let dials = run_all(&a, &b, now + 10_000);
    assert_eq!(
        dials,
        3 + cut,
        "ask and then push for a cut one, one dial for the others"
    );
    for handle in handles {
        assert_eq!(a.row(&handle).state, State::Delivered);
        assert_eq!(b.row(&handle).state, State::Complete);
    }
    assert!(a.plans(now + 10_000).is_empty());
}

#[test]
fn a_late_answer_that_says_gone_does_not_undo_a_photo_that_is_whole() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let bytes = jpeg(200_000);
    let handle = offered(&a, &b, &bytes, now);
    // The receiver asks (nothing landed for a while); the holder keeps its
    // answer back, pushes every chunk over a dial of its own, and only then
    // answers the question: "gone".
    let asked = now + PULL_AFTER_MS;
    let pull = b.plans(asked).remove(0);
    assert_eq!(ops(&pull), [0x02]);
    assert_eq!(push_all(&a, &b, asked), 1);
    assert_eq!(b.row(&handle).state, State::Complete);
    let gone = encode(last_req(&pull), Body::Error(ErrorCode::Gone));
    assert!(!b.x().took(&pull, Some(&[gone]), asked));
    let theirs = b.row(&handle);
    assert_eq!(theirs.state, State::Complete, "the photo stays");
    assert_eq!(
        &store::read_plain(b.d(), &theirs, 0, bytes.len()).unwrap()[..],
        &bytes[..]
    );
    // One that is still on its way does turn gone on that answer.
    let (c, d) = (Side::new(), Side::new());
    let (other, offer) = staged(&c, &bytes, now);
    keep(&d, &offer, now);
    let pull = d.plans(asked).remove(0);
    let gone = encode(last_req(&pull), Body::Error(ErrorCode::Gone));
    assert!(!d.x().took(&pull, Some(&[gone]), asked));
    assert_eq!(d.row(&other).state, State::Gone);
    assert!(d.plans(asked + DAY_MS).is_empty());
}

#[test]
fn every_chunk_here_and_the_last_step_not_run_is_finished_at_the_next_look() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let bytes = jpeg(200_000);
    let (handle, offer) = staged(&a, &bytes, now);
    keep(&b, &offer, now);
    // Every chunk lands in the store, and the process stops before the
    // step that opens the blob and marks the row.
    let mine = a.row(&handle);
    let shape = mine.shape().unwrap();
    let tree = store::tree(a.d(), &mine).unwrap();
    let root = b.row(&handle).root().unwrap();
    for index in 0..shape.chunks() {
        let chunk = store::read_chunk(a.d(), &handle, &shape, true, index).unwrap();
        let path = tree.chunk_path(index as usize).unwrap();
        store::take_chunk(b.d(), &handle, &shape, &root, index, &chunk, &path).unwrap();
    }
    assert_eq!(b.row(&handle).state, State::Incoming);
    // The next look, once the time to be pushed is over, runs that step:
    // nothing is asked of the holder, the photo is there, and the holder is
    // told with DONE.
    let later = crate::clock::now_ms() + PULL_AFTER_MS;
    let planned = b.x().plans(later, &|_| true);
    assert!(planned.plans.is_empty(), "{planned:?}");
    let theirs = b.row(&handle);
    assert_eq!(theirs.state, State::Complete);
    assert_eq!(
        &store::read_plain(b.d(), &theirs, 0, bytes.len()).unwrap()[..],
        &bytes[..]
    );
    let done = b.plans(later).remove(0);
    assert_eq!(ops(&done), [0x03]);
    dial(&a, &KB, &done, later);
    assert!(!b.x().took(&done, Some(&[]), later));
    assert_eq!(a.row(&handle).state, State::Delivered);
    assert!(b.plans(later).is_empty());
}

#[test]
fn a_row_written_again_within_the_same_tick_of_the_file_clock_is_read_again() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let (handle, offer) = staged(&a, &jpeg(100_000), now);
    keep(&b, &offer, now);
    let file = a
        .d()
        .join(store::ROWS_DIR)
        .join(format!("{}.row", hex::encode(handle)));
    let stamped = std::fs::metadata(&file).unwrap().modified().unwrap();
    // The exchange reads the row while the offer is on its way.
    assert!(a.plans(now).is_empty());
    // Another process writes its delivery, and the file keeps the time it
    // had (a second write within one tick of a coarse file clock).
    delivered(&a, &offer, now);
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(stamped)
        .unwrap();
    assert_eq!(
        std::fs::metadata(&file).unwrap().modified().unwrap(),
        stamped
    );
    // The next look sees it all the same: every chunk goes.
    let plan = a
        .plans(now)
        .into_iter()
        .next()
        .expect("the delivery is seen");
    assert!(ops(&plan).len() > 1, "{:?}", ops(&plan));
}

#[test]
fn a_friend_whose_day_is_used_up_is_refused_before_anything_is_read() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let (handle, offer) = staged(&a, &jpeg(200_000), now);
    keep(&b, &offer, now);
    let want = |first: u16| {
        encode(
            req(),
            Body::Want {
                handle,
                first,
                count: 2,
            },
        )
    };
    // A request is served, and the tree it needed is kept for the next.
    let replies = a.x().listener_frame(&KB, &want(0), now);
    assert_eq!(replies.len(), 3, "two chunks and the end");
    assert!(a
        .memory
        .lock()
        .unwrap()
        .tree
        .as_ref()
        .is_some_and(|(h, _)| *h == handle));
    // The friend's day is used up: refused at once, the bytes not read
    // (they are not even there any more).
    a.memory.lock().unwrap().served.insert(
        KB,
        Served {
            day_start_ms: now,
            bytes: SERVE_BYTES_PER_DAY,
        },
    );
    std::fs::remove_dir_all(store::blob_dir(a.d(), &handle)).unwrap();
    a.memory.lock().unwrap().tree = None;
    let replies = a.x().listener_frame(&KB, &want(2), now);
    assert_eq!(replies.len(), 1);
    let Ok(Frame { body, .. }) = link::decode_for_dialer(&replies[0]) else {
        panic!("an answer");
    };
    assert!(
        matches!(body, Body::Error(ErrorCode::RateLimited)),
        "{body:?}"
    );
    // The next day it is served again (here: the bytes are gone).
    let replies = a.x().listener_frame(&KB, &want(2), now + DAY_MS);
    let Ok(Frame { body, .. }) = link::decode_for_dialer(&replies[0]) else {
        panic!("an answer");
    };
    assert!(matches!(body, Body::Error(ErrorCode::NotFound)), "{body:?}");
}

#[test]
fn an_attachment_a_month_old_is_dialled_for_no_more_unless_the_user_asks() {
    let Some(_live) = Live::on() else { return };
    let (a, b) = (Side::new(), Side::new());
    let now = crate::clock::now_ms();
    let bytes = jpeg(100_000);
    // Mine, offered, never taken whole; a friend's, never pushed.
    let handle = offered(&a, &b, &bytes, now);
    let month = now + AUTO_MAX_AGE_MS;
    assert_eq!(a.plans(month - 60_000).len(), 1);
    let planned = a.x().plans(month, &|_| true);
    assert!(planned.plans.is_empty() && !planned.waiting, "{planned:?}");
    assert_eq!(b.plans(month - 60_000).len(), 1);
    let planned = b.x().plans(month, &|_| true);
    assert!(planned.plans.is_empty() && !planned.waiting, "{planned:?}");
    // The friend's own dial still moves it: it is served, and taken.
    let pull = b.plans(month - 60_000).remove(0);
    let replies = dial(&a, &KB, &pull, month);
    assert!(replies.len() > 1);
    // And one the user asks for is fetched whatever its age.
    let (c, d) = (Side::new(), Side::new());
    let (other, offer) = staged(&c, &bytes, now);
    keep(&d, &offer, now);
    assert!(d.plans(month).is_empty());
    store::update(d.d(), &other, month, |row| row.asked = true).unwrap();
    let plan = d.plans(month).remove(0);
    assert_eq!(ops(&plan), [0x02]);
    assert_eq!(handle.len(), other.len());
}

/// A profile's contact book with `friend` in it, verified.
fn befriend(side: &Side, friend: &[u8; 32]) {
    std::fs::write(
        side.d().join("contacts.json"),
        format!(
            r#"[{{"petname":"Friend","pub_hex":"{}","address":"","pinned":true}}]"#,
            hex::encode(friend)
        ),
    )
    .unwrap();
}

/// A profile picture is one more attachment to the exchange: its offer is
/// delivered like a message, its one chunk is pushed behind it, and both
/// ends then know that it is there
/// (`docs/design/2026-11-profile-pictures.md` §10.3, §11.3).
#[test]
fn a_profile_picture_travels_between_two_verified_friends() {
    use crate::attachment::{jpeg, peers, picture};
    let Some(_live) = Live::on() else { return };
    struct Pictures;
    impl Drop for Pictures {
        fn drop(&mut self) {
            attachment_gate::set_lab_pictures_for_this_thread(None);
        }
    }
    attachment_gate::set_lab_pictures_for_this_thread(Some(true));
    let _pictures = Pictures;
    const T: u64 = 1_763_000_000_000;
    let (a, b) = (Side::new(), Side::new());
    befriend(&a, &KB);
    befriend(&b, &KA);
    peers::note(a.d(), &KB, true, 1).unwrap();
    let face = jpeg::testing::picture(384);
    let small = jpeg::testing::parts(32, 3, 0).bytes();
    picture::set_mine(a.d(), &face, &small, T).unwrap();
    let made = picture::pass(a.d(), T).unwrap();
    assert_eq!(made.len(), 1);
    let handle = made[0].handle.unwrap();
    picture::offer_sent(a.d(), &KB, made[0].seq, &MID, T).unwrap();
    // Nothing is pushed for an offer whose message has not arrived.
    assert!(a.plans(T).iter().all(|plan| plan.frames.len() <= 1));

    // The message arrives at b, and its answer comes back to a.
    assert_eq!(
        picture::take_offer(b.d(), &KA, &MID, &made[0].offer, T).unwrap(),
        picture::Taken::New
    );
    let seen = picture::theirs(b.d(), &KA, T).unwrap();
    assert!(!seen.ready, "the preview only");
    delivered(&a, &made[0].offer, T);

    // a's node pushes the one chunk; b checks it against the root.
    assert!(push_all(&a, &b, T) >= 1);
    assert_eq!(b.row(&handle).state, store::State::Complete);
    assert_eq!(a.row(&handle).state, store::State::Delivered);
    assert!(picture::theirs(b.d(), &KA, T).unwrap().ready);
    assert_eq!(picture::read_theirs(b.d(), &KA, false, T).unwrap(), face);

    // a's next look: the friend has it, and the row with its key is gone.
    assert!(picture::pass(a.d(), T + 1).unwrap().is_empty());
    assert_eq!(picture::reach(a.d(), &KB), Some(picture::Reach::Has));
    assert!(store::get(a.d(), &handle).unwrap().is_none());
    // Asked for once more by b (a second device, say): a no longer has it.
    assert!(a.plans(T + 2).is_empty());
}
