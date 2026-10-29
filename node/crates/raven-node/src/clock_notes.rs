//! Contacts whose clock runs ahead of ours (cutoff pack CP.7, F10 / M11), for
//! `raven status` and the send texts: in memory only (it starts over when
//! raven-node restarts), bounded, the contact's key and a number of minutes;
//! never an address or a time of day.
//!
//! Raven refuses what is dated more than five minutes in its future
//! ([`raven_core::clock_skew`]), so each side sees only the half where the
//! **other** side is ahead. A note is made when something from a contact is
//! refused as from the future: a PairInit, message or ACK it sent us (the
//! side value of the inbound refusal), a reply to one of our dials (a
//! PairResponse or ACK, which ash or the outbox then refuses), or its RLB1
//! offer (checked by our dial, and by our listener when it dials us). It is
//! cleared by the next envelope from that contact dated in time: one this
//! node accepted, or a reply to our dial (whoever made the dial checks it).
//! A note not seen again within [`NOTE_TTL`] is no longer listed: a contact
//! that set its clock right but never sent us anything since must not have
//! a later, unrelated failure blamed on the clocks. Nothing here changes a
//! refusal, and nothing corrects a clock.
//!
//! Beside it, how many times in a row a contact took our PairInit or message
//! on a link it accepted and gave no answer (closed the link, or stayed
//! silent): with nothing measured, two of those are the hint that the two
//! clocks may differ (an answer clears it; something it sends us does not,
//! since a contact whose clock is behind takes nothing from us while we take
//! its messages).
//!
//! The LAN beacon sees both halves (Phase 3 P3.C3, F11b): a contact whose
//! queries match only at the epoch next to ours, round after round, at a
//! time in our epoch that shows more than the five-minute limit, runs at
//! least that much ahead or behind ([`beacon_skew`]; review A-3: a match
//! next door near an epoch's edge shows only seconds). Such a note says
//! "or more" (`ContactSkew.at_least`); a note measured from a
//! refusal on the same side is more exact and stays. A note that the
//! contact is behind is cleared by its answer to one of our PairInits or
//! messages (it took what we dated), not by an envelope from it in time.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use raven_core::clock_skew::{
    bundle_future_by_ms, frame_future_by_ms, frame_in_time, minutes, PeerClock,
};
use raven_core::envelope::{EnvType, Envelope};
use raven_core::ipc::{ContactSkew, ContactUnanswered};
use raven_core::pair_init_lan_oob::{classify_packed_envelope, PairInitOobClassify};
use raven_core::LanBundle;

/// Contacts remembered (each list); a new one beyond this drops the oldest.
const MAX_CONTACTS: usize = 256;
/// Rows `Status` lists, newest first.
pub(crate) const LIST_MAX: usize = 64;
/// How long a note (a skew, or a run of unanswered frames) counts after it
/// was last seen (review C-time-deadlines-6): long enough for a send soon
/// after the refusal, short enough that an old note does not explain a
/// failure days later.
pub(crate) const NOTE_TTL: Duration = Duration::from_secs(60 * 60);

/// Was something noted `at` still current at `now`?
fn fresh(at: Instant, now: Instant) -> bool {
    now.saturating_duration_since(at) < NOTE_TTL
}

/// Insert `value` for `contact`, noted at `now`; a new contact beyond
/// [`MAX_CONTACTS`] drops the one noted longest ago.
fn insert_bounded<V>(
    map: &mut HashMap<[u8; 32], (V, Instant)>,
    contact: [u8; 32],
    value: V,
    now: Instant,
) {
    if map.len() >= MAX_CONTACTS && !map.contains_key(&contact) {
        let oldest = map.iter().min_by_key(|(_, (_, at))| *at).map(|(k, _)| *k);
        if let Some(oldest) = oldest {
            map.remove(&oldest);
        }
    }
    map.insert(contact, (value, now));
}

/// The newest [`LIST_MAX`] entries of `map` still [`fresh`] at `now`,
/// newest first.
fn newest<V: Copy>(map: &HashMap<[u8; 32], (V, Instant)>, now: Instant) -> Vec<([u8; 32], V)> {
    let mut rows: Vec<_> = map.iter().filter(|(_, (_, at))| fresh(*at, now)).collect();
    rows.sort_by(|(ka, (_, a)), (kb, (_, b))| b.cmp(a).then(ka.cmp(kb)));
    rows.into_iter()
        .take(LIST_MAX)
        .map(|(k, (v, _))| (*k, *v))
        .collect()
}

/// How far a contact's clock is ahead of ours.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Skew {
    /// In ms: + ahead, - behind.
    ms: i64,
    /// The LAN beacon's estimate: about this much or more.
    at_least: bool,
}

impl Skew {
    fn measured(ms: i64) -> Skew {
        Skew {
            ms,
            at_least: false,
        }
    }
}

/// One LAN beacon epoch in ms ([`raven_core::lan_beacon::EPOCH_SECS`]).
#[cfg(test)]
const EPOCH_MS: i64 = raven_core::lan_beacon::EPOCH_SECS as i64 * 1000;

#[derive(Default)]
struct Notes {
    /// How far each contact's clock is ahead of ours, and when noted.
    ahead: HashMap<[u8; 32], (Skew, Instant)>,
    /// Our PairInits and messages a contact took without an answer, in a row.
    unanswered: HashMap<[u8; 32], (u32, Instant)>,
}

static NOTES: Mutex<Option<Notes>> = Mutex::new(None);

fn notes() -> MutexGuard<'static, Option<Notes>> {
    NOTES.lock().unwrap_or_else(|e| e.into_inner())
}

fn with_notes<T>(f: impl FnOnce(&mut Notes) -> T) -> T {
    f(notes().get_or_insert_with(Notes::default))
}

/// Something from `contact` was refused as dated `ahead_ms` in our future
/// (+ = its clock is ahead of ours). The newest note replaces an older one.
pub(crate) fn note(contact: &[u8; 32], ahead_ms: i64) {
    with_notes(|n| {
        insert_bounded(
            &mut n.ahead,
            *contact,
            Skew::measured(ahead_ms),
            Instant::now(),
        )
    });
}

/// The LAN beacon matched `contact`'s queries only at the epoch after ours
/// or only at the one before, round after round, and they show that its
/// clock runs at least `ahead_ms` ahead of ours (behind when negative), past
/// the five-minute limit (Phase 3 P3.C3, F11b, review A-3). A note measured
/// from a refusal on the same side, still current, is more exact and stays;
/// else this one is kept (or kept current) as that much or more.
pub(crate) fn beacon_skew(contact: &[u8; 32], ahead_ms: i64) {
    beacon_skew_at(contact, ahead_ms, Instant::now());
}

fn beacon_skew_at(contact: &[u8; 32], ms: i64, now: Instant) {
    if ms == 0 {
        return;
    }
    with_notes(|n| {
        let measured = n.ahead.get(contact).is_some_and(|(skew, at)| {
            !skew.at_least && fresh(*at, now) && skew.ms.signum() == ms.signum()
        });
        if !measured {
            let skew = Skew { ms, at_least: true };
            insert_bounded(&mut n.ahead, *contact, skew, now);
        }
    });
}

/// An envelope from `contact` was dated in time: its clock is not ahead of
/// ours, so a note that it is goes (one that it is behind stays: we take
/// what it sends either way).
pub(crate) fn clear(contact: &[u8; 32]) {
    with_notes(|n| {
        if n.ahead.get(contact).is_some_and(|(skew, _)| skew.ms > 0) {
            n.ahead.remove(contact);
        }
    });
}

/// What one inbound frame from `contact` showed about its clock (the side
/// value of `lan_dispatch::dispatch_frame_clocked`).
pub(crate) fn seen(contact: &[u8; 32], clock: Option<PeerClock>) {
    match clock {
        Some(PeerClock::Ahead(ms)) => note(contact, i64::try_from(ms).unwrap_or(i64::MAX)),
        Some(PeerClock::Agrees) => clear(contact),
        None => {}
    }
}

/// A link with `contact` refused its RLB1 offer (our dial, or our listener):
/// noted when the offer's prekey bundle is dated past the window
/// (`PREKEY_NOT_YET_VALID`).
pub(crate) fn offer_refused(contact: &[u8; 32], offer: &LanBundle) {
    if let Some(ms) = bundle_future_by_ms(offer, raven_core::clock::now_ms()) {
        note(contact, i64::try_from(ms).unwrap_or(i64::MAX));
    }
}

/// A frame that asks the contact for an answer: a PairInit (a PairResponse
/// comes back) or a message (a sealed ACK comes back).
fn asks(frame: &[u8]) -> bool {
    match classify_packed_envelope(frame) {
        PairInitOobClassify::PairInit(_) => true,
        PairInitOobClassify::PairResponse(_) => false,
        PairInitOobClassify::NotPairInitOob => {
            Envelope::unpack(frame).is_some_and(|e| e.env_type == EnvType::Message as u8)
        }
    }
}

/// A reply that answers one: a PairResponse or a sealed ACK.
fn answers(frame: &[u8]) -> bool {
    match classify_packed_envelope(frame) {
        PairInitOobClassify::PairResponse(_) => true,
        PairInitOobClassify::PairInit(_) => false,
        PairInitOobClassify::NotPairInitOob => {
            Envelope::unpack(frame).is_some_and(|e| e.env_type == EnvType::Ack as u8)
        }
    }
}

/// The dial error for a link the contact accepted, took our frames on and
/// closed without a word (`LAN_DIAL_PEER_CLOSED`, `INTERNET_DIAL_…`, …).
fn closed_after_frames(error: &str) -> bool {
    error.contains("_DIAL_PEER_CLOSED")
}

/// One of our dials to `contact` that carried `frames` ended with `result`
/// (every carrier's dial, for ash's IPC dials and the outbox alike): replies
/// from the future are noted, a reply dated in time clears the note, and a
/// PairInit or message the contact took without an answer counts once.
pub(crate) fn dialled(
    contact: &[u8; 32],
    frames: &[Vec<u8>],
    result: &Result<Vec<Vec<u8>>, String>,
) {
    dialled_at(contact, frames, result, raven_core::clock::now_ms());
}

fn dialled_at(
    contact: &[u8; 32],
    frames: &[Vec<u8>],
    result: &Result<Vec<Vec<u8>>, String>,
    now_ms: u64,
) {
    let asked = frames.iter().any(|f| asks(f));
    match result {
        Ok(replies) => {
            match replies
                .iter()
                .filter_map(|f| frame_future_by_ms(f, now_ms))
                .max()
            {
                Some(ms) => note(contact, i64::try_from(ms).unwrap_or(i64::MAX)),
                None if replies.iter().any(|f| frame_in_time(f, now_ms)) => clear(contact),
                None => {}
            }
            if replies.iter().any(|f| answers(f)) {
                answered(contact);
            } else if asked {
                unanswered(contact);
            }
        }
        Err(e) if asked && closed_after_frames(e) => unanswered(contact),
        Err(_) => {}
    }
}

fn unanswered(contact: &[u8; 32]) {
    unanswered_at(contact, Instant::now());
}

/// One more in a row, or the first again when the last was not [`fresh`].
fn unanswered_at(contact: &[u8; 32], now: Instant) {
    with_notes(|n| {
        let times = n
            .unanswered
            .get(contact)
            .filter(|(_, at)| fresh(*at, now))
            .map_or(0, |(t, _)| *t);
        insert_bounded(&mut n.unanswered, *contact, times.saturating_add(1), now);
    });
}

/// `contact` answered one of our PairInits or messages: the run of silences
/// ends, and so does a note that its clock is behind ours (it took what we
/// dated).
fn answered(contact: &[u8; 32]) {
    with_notes(|n| {
        n.unanswered.remove(contact);
        if n.ahead.get(contact).is_some_and(|(skew, _)| skew.ms < 0) {
            n.ahead.remove(contact);
        }
    });
}

/// The rows for IPC `Status` (`clock_skew`), newest first.
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
pub(crate) fn snapshot() -> Vec<ContactSkew> {
    snapshot_at(Instant::now())
}

fn snapshot_at(now: Instant) -> Vec<ContactSkew> {
    with_notes(|n| {
        newest(&n.ahead, now)
            .into_iter()
            .map(|(key, skew)| ContactSkew {
                peer_pub_hex: hex::encode(key),
                minutes: minutes(skew.ms),
                at_least: skew.at_least,
            })
            .collect()
    })
}

/// The rows for IPC `Status` (`unanswered`), newest first.
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
pub(crate) fn unanswered_snapshot() -> Vec<ContactUnanswered> {
    unanswered_snapshot_at(Instant::now())
}

fn unanswered_snapshot_at(now: Instant) -> Vec<ContactUnanswered> {
    with_notes(|n| {
        newest(&n.unanswered, now)
            .into_iter()
            .map(|(key, times)| ContactUnanswered {
                peer_pub_hex: hex::encode(key),
                times,
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::identity::Identity;
    use raven_core::pair_init_lan_oob::{wrap_oob_wire, PairInitOobKind};

    const NOW: u64 = 1_800_000_000_000;
    const MIN: u64 = 60_000;

    /// The notes are one process-wide map: these tests take turns (the
    /// bounded one fills it).
    static TURN: Mutex<()> = Mutex::new(());

    fn turn() -> MutexGuard<'static, ()> {
        TURN.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn envelope(kind: EnvType, created_at: u64) -> Vec<u8> {
        let mut env = Envelope {
            env_type: kind as u8,
            flags: 0,
            message_id: [3; 16],
            routing_tag: [4; 16],
            dest_device_hint: 0,
            created_at,
            expires_at: created_at + 3_600_000,
            hop_limit: 0,
            replication_budget: 0,
            anti_replay_nonce: [5; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: vec![1, 2, 3],
            sender_authentication: vec![],
        };
        env.sign_with(&Identity::from_seed(&[0x33; 32]));
        env.pack()
    }

    /// A PairResponse as it travels: in an envelope stamped `created_at`.
    fn pair_response(created_at: u64) -> Vec<u8> {
        let mut wire = raven_core::pair_init::RESPONSE_MAGIC.to_vec();
        wire.resize(raven_core::pair_init::RESPONSE_WIRE_LEN, 7);
        wrap_oob_wire(
            &wire,
            PairInitOobKind::PairResponse,
            &Identity::from_seed(&[0x34; 32]),
            [9; 16],
            created_at,
            &mut rand::rngs::OsRng,
        )
        .expect("wrap")
    }

    fn skew_of(key: &[u8; 32]) -> Option<i32> {
        snapshot()
            .into_iter()
            .find(|r| r.peer_pub_hex == hex::encode(key))
            .map(|r| r.minutes)
    }

    fn times_of(key: &[u8; 32]) -> Option<u32> {
        unanswered_snapshot()
            .into_iter()
            .find(|r| r.peer_pub_hex == hex::encode(key))
            .map(|r| r.times)
    }

    /// Noted from a refusal's side value, replaced by a newer one, cleared
    /// by an accepted envelope; listed newest first in whole minutes.
    #[test]
    fn a_note_is_kept_until_an_envelope_in_time() {
        let _turn = turn();
        let (a, b) = ([0xC1; 32], [0xC2; 32]);
        seen(&a, Some(PeerClock::Ahead(10 * MIN - 1_000)));
        seen(&b, Some(PeerClock::Ahead(7 * MIN)));
        assert_eq!(skew_of(&a), Some(10));
        assert_eq!(skew_of(&b), Some(7));
        let rows = snapshot();
        let pos = |k: &[u8; 32]| rows.iter().position(|r| r.peer_pub_hex == hex::encode(k));
        assert!(pos(&b) < pos(&a), "newest first: {rows:?}");
        // A later refusal replaces the minutes; nothing said keeps it.
        seen(&a, Some(PeerClock::Ahead(12 * MIN)));
        seen(&a, None);
        assert_eq!(skew_of(&a), Some(12));
        seen(&a, Some(PeerClock::Agrees));
        assert_eq!(skew_of(&a), None);
        clear(&b);
        assert_eq!(skew_of(&b), None);
    }

    /// Review C-time-deadlines-6: a note not seen again within NOTE_TTL is
    /// no longer listed, and a run of unanswered frames starts over after
    /// it.
    #[test]
    fn notes_age_out() {
        let _turn = turn();
        let c = [0xC7; 32];
        let now = Instant::now();
        let later = now + NOTE_TTL + Duration::from_secs(1);
        note(&c, 10 * MIN as i64);
        unanswered_at(&c, now);
        unanswered_at(&c, now);
        let listed = |rows: Vec<ContactSkew>| rows.iter().any(|r| r.peer_pub_hex == hex::encode(c));
        assert!(listed(snapshot_at(now)));
        assert!(listed(snapshot_at(now + NOTE_TTL - Duration::from_secs(1))));
        assert!(
            !listed(snapshot_at(later)),
            "an hour-old note is not listed"
        );
        let times = |rows: Vec<ContactUnanswered>| {
            rows.into_iter()
                .find(|r| r.peer_pub_hex == hex::encode(c))
                .map(|r| r.times)
        };
        assert_eq!(times(unanswered_snapshot_at(now)), Some(2));
        assert_eq!(times(unanswered_snapshot_at(later)), None);
        // A silence after the gap counts as the first again.
        unanswered_at(&c, later);
        assert_eq!(times(unanswered_snapshot_at(later)), Some(1));
        clear(&c);
        answered(&c);
    }

    /// At most 256 contacts: a new one drops the one noted longest ago, and
    /// `Status` lists at most 64.
    #[test]
    fn notes_are_bounded() {
        let _turn = turn();
        let key = |i: u16| {
            let mut k = [0xD0; 32];
            k[0..2].copy_from_slice(&i.to_be_bytes());
            k[2] = 0x5A;
            k
        };
        for i in 0..(MAX_CONTACTS as u16 + 10) {
            note(&key(i), 6 * MIN as i64);
            unanswered(&key(i));
        }
        let (kept, counted) = with_notes(|n| {
            (
                n.ahead.keys().filter(|k| k[2] == 0x5A).count(),
                n.unanswered.keys().filter(|k| k[2] == 0x5A).count(),
            )
        });
        assert!(kept <= MAX_CONTACTS && counted <= MAX_CONTACTS);
        assert_eq!(skew_of(&key(MAX_CONTACTS as u16 + 9)), Some(6));
        assert!(with_notes(|n| !n.ahead.contains_key(&key(0))));
        assert!(snapshot().len() <= LIST_MAX);
        assert!(unanswered_snapshot().len() <= LIST_MAX);
        for i in 0..(MAX_CONTACTS as u16 + 10) {
            clear(&key(i));
            answered(&key(i));
        }
    }

    fn row_of(key: &[u8; 32]) -> Option<(i32, bool)> {
        snapshot()
            .into_iter()
            .find(|r| r.peer_pub_hex == hex::encode(key))
            .map(|r| (r.minutes, r.at_least))
    }

    /// Phase 3 P3.C3 (F11b): the LAN beacon's note is the bound its matches
    /// show "or more" (review A-3), ahead or behind. Ahead goes with an envelope from the contact in
    /// time; behind stays then and goes when the contact answers one of our
    /// messages. A measured note on the same side stays (more exact), one on
    /// the other side or no longer current is replaced.
    #[test]
    fn beacon_notes_say_or_more_and_keep_a_measured_note() {
        let _turn = turn();
        let c = [0xE5; 32];
        let message = vec![envelope(EnvType::Message, NOW)];
        beacon_skew(&c, EPOCH_MS);
        assert_eq!(row_of(&c), Some((10, true)));
        seen(&c, Some(PeerClock::Agrees));
        assert_eq!(row_of(&c), None);
        beacon_skew(&c, -EPOCH_MS);
        assert_eq!(row_of(&c), Some((-10, true)));
        seen(&c, Some(PeerClock::Agrees));
        clear(&c);
        assert_eq!(row_of(&c), Some((-10, true)), "we take what it sends");
        // It took our message and answered: not behind (beyond the window).
        let acked = Ok(vec![envelope(EnvType::Ack, NOW)]);
        dialled_at(&c, &message, &acked, NOW);
        assert_eq!(row_of(&c), None);
        // Measured on the same side: kept; on the other side: replaced.
        note(&c, 12 * MIN as i64);
        beacon_skew(&c, EPOCH_MS);
        assert_eq!(row_of(&c), Some((12, false)));
        beacon_skew(&c, -EPOCH_MS);
        assert_eq!(row_of(&c), Some((-10, true)));
        // A measured note no longer current gives way.
        note(&c, 12 * MIN as i64);
        let later = Instant::now() + NOTE_TTL + Duration::from_secs(1);
        beacon_skew_at(&c, EPOCH_MS, later);
        let row = snapshot_at(later)
            .into_iter()
            .find(|r| r.peer_pub_hex == hex::encode(c))
            .map(|r| (r.minutes, r.at_least));
        assert_eq!(row, Some((10, true)));
        // The bound the beacon shows, as it is (review A-3).
        clear(&c);
        beacon_skew(&c, 6 * MIN as i64);
        assert_eq!(row_of(&c), Some((6, true)));
        // Nothing shown says nothing.
        clear(&c);
        beacon_skew(&c, 0);
        assert_eq!(row_of(&c), None);
    }

    /// A dial's replies: an ACK or PairResponse from the future is noted
    /// (the largest), one in time clears it; a PairInit or message the
    /// contact took without an answer counts, an answer clears the count.
    #[test]
    fn dials_note_replies_and_count_silence() {
        let _turn = turn();
        let c = [0xE1; 32];
        let message = vec![envelope(EnvType::Message, NOW)];
        let offer = b"RLB1-offer".to_vec();
        let closed: Result<Vec<Vec<u8>>, String> = Err(
            "LAN_DIAL_PEER_CLOSED: the peer closed the connection without replying; the frames \
             were sent, delivery is unconfirmed and a retry is safe"
                .into(),
        );
        dialled_at(&c, &message, &closed, NOW);
        assert_eq!(times_of(&c), Some(1));
        // Only the offer came back (no answer in time): a second silence.
        dialled_at(&c, &message, &Ok(vec![offer.clone()]), NOW);
        assert_eq!(times_of(&c), Some(2));
        assert_eq!(skew_of(&c), None, "silence measures nothing");
        // Unreachable, or a probe with no frames: not counted.
        dialled_at(&c, &message, &Err("lan connect: timed out".into()), NOW);
        dialled_at(&c, &[], &closed, NOW);
        assert_eq!(times_of(&c), Some(2));
        // An ACK from 10 min ahead answers (the count goes) and is noted.
        let ahead = Ok(vec![offer.clone(), envelope(EnvType::Ack, NOW + 10 * MIN)]);
        dialled_at(&c, &message, &ahead, NOW);
        assert_eq!(times_of(&c), None);
        assert_eq!(skew_of(&c), Some(10));
        // A PairResponse from 8 min ahead: noted as such.
        dialled_at(&c, &message, &Ok(vec![pair_response(NOW + 8 * MIN)]), NOW);
        assert_eq!(skew_of(&c), Some(8));
        // A reply dated in time clears the note.
        dialled_at(
            &c,
            &message,
            &Ok(vec![envelope(EnvType::Ack, NOW + 4 * MIN)]),
            NOW,
        );
        assert_eq!(skew_of(&c), None);
        assert_eq!(times_of(&c), None);
    }
}
