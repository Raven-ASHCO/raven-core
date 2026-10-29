//! The long message horizon's step (Phase 5a, P5.7,
//! [`crate::horizon::run_horizon_step`]) end to end over two profile folders:
//! Alice's messages to Bob ran out and were parked; a step dials Bob's folder
//! through [`Link`], which answers exactly as the listener does
//! ([`dispatch_frame`]), like the reset step's `LinkTo`. Time moves on the lab
//! clock (this thread's offset, [`crate::clock::set_for_this_thread`]), which
//! both folders read.

use super::*;
use crate::device_sync::RevocationRecord;
use crate::horizon::{
    message_deadline, run_horizon_step, set_lab_horizon_for_this_thread, HorizonEnv, HorizonReport,
    HorizonStep, HORIZON_MAX_COPIES, SENTINEL_BINDING,
};
use crate::indexed_session_store::{
    EndpointOutbound, ParkedOutbound, PeerRenewalState, SessionRetireCause,
};
use crate::outbox::{
    park_or_give_up_expired, record_object_routes, CarrierChoice, ExpiredMessage, OutboxCarrier,
    OutboxRoute,
};
use crate::session_renewal::{code as renew_code, set_lab_session_renewal_for_this_thread};
use crate::session_reset::{reconcile_resealed_outbound, ResetIo};

const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 24 * HOUR_MS;
const LOOPBACK: &str = "127.0.0.1:9";

/// The horizon on for this test thread, the reset step and renewal off
/// whatever the environment says, the LAN switch as the build sets it; the
/// clock and every switch restored when dropped.
struct Lab {
    _untouched: std::sync::RwLockReadGuard<'static, ()>,
}

impl Lab {
    fn on() -> Self {
        set_lab_horizon_for_this_thread(Some(true));
        set_lab_session_reset_for_this_thread(Some(0));
        set_lab_session_renewal_for_this_thread(Some(false));
        Lab {
            _untouched: crate::lan_gate::lan_user_switch_untouched(),
        }
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        set_lab_horizon_for_this_thread(None);
        set_lab_session_reset_for_this_thread(None);
        set_lab_session_renewal_for_this_thread(None);
        crate::clock::set_for_this_thread(None);
    }
}

/// This thread's clock `offset` ms off the system clock (both folders' clock).
fn at(offset: i64) {
    crate::clock::set_for_this_thread(Some(offset));
}

/// This thread's clock at `wall_ms` (Raven's time) from now on.
fn at_time(wall_ms: u64) {
    let system = crate::clock::system_now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    at(wall_ms as i64 - system);
}

/// Alice and Bob, contacts of each other, and the day-long session Alice
/// started.
struct Pair {
    alice: Identity,
    bob: Identity,
    a_dir: tempfile::TempDir,
    b_dir: tempfile::TempDir,
    a_bundle: LanBundle,
    b_bundle: LanBundle,
}

fn pair(seed: u8) -> Pair {
    let alice = Identity::from_seed(&[seed; 32]);
    let bob = Identity::from_seed(&[seed.wrapping_add(1); 32]);
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    publish_and_install(a_dir.path(), &alice);
    publish_and_install(b_dir.path(), &bob);
    let (a_bundle, b_bundle) = confirm_alice_to_bob(a_dir.path(), b_dir.path(), &alice, &bob);
    Pair {
        alice,
        bob,
        a_dir,
        b_dir,
        a_bundle,
        b_bundle,
    }
}

fn lan() -> Vec<OutboxRoute> {
    vec![OutboxRoute {
        carrier: OutboxCarrier::Lan,
        dial: LOOPBACK.into(),
    }]
}

impl Pair {
    fn a(&self) -> &Path {
        self.a_dir.path()
    }

    fn bob_pub(&self) -> [u8; 32] {
        self.bob.public_key_bytes()
    }

    fn store(&self) -> IndexedSessionStore {
        IndexedSessionStore::open(self.a()).unwrap()
    }

    /// Alice sends `text` the way `ash send` does to an unreachable Bob:
    /// sealed under her newest session, staged, history `queued`.
    fn send(&self, text: &str) -> ([u8; 16], Vec<u8>) {
        let key = self
            .store()
            .find_sendable_session_for_peer(&self.bob_pub())
            .unwrap()
            .expect("a session");
        let packed = seal_under(self.a(), &self.alice, &key, text);
        let env = Envelope::unpack(&packed).unwrap();
        let sid = self.store().session_id_for_record_key(&key).unwrap();
        ensure_outbound_queued_history(
            self.a(),
            &self.bob_pub(),
            &sid,
            &crate::bridge::authenticated_object_digest(&env),
            &env.message_id,
            env.created_at,
            Some(text),
        )
        .unwrap();
        (env.message_id, packed)
    }

    /// Alice's outbox rows to Bob (prepared or queued), in write order.
    fn rows(&self, store: &IndexedSessionStore) -> Vec<EndpointOutbound> {
        let mut rows = store
            .pending_endpoint_outbound_for_recipient(Some(&self.bob_pub()))
            .unwrap();
        rows.extend(
            store
                .awaiting_ack_endpoint_outbound_for_recipient(Some(&self.bob_pub()))
                .unwrap(),
        );
        rows.sort_by_key(|r| r.ratchet_index);
        rows
    }

    /// Every row to Bob ran out: each is parked (the worker's expiry step,
    /// `never_sent`), in the order sent.
    fn park_expired(&self) -> Vec<[u8; 16]> {
        let mut store = self.store();
        let rows = self.rows(&store);
        for row in &rows {
            let key = store
                .record_key_for_session_id(&row.session_id)
                .unwrap()
                .unwrap();
            let parked = park_or_give_up_expired(
                self.a(),
                &mut store,
                &key,
                &self.bob_pub(),
                &row.session_id,
                &row.object_digest,
                &row.message_id,
                true,
                now(),
            )
            .unwrap();
            assert!(
                matches!(parked, ExpiredMessage::Parked { .. }),
                "{parked:?}"
            );
        }
        rows.iter().map(|r| r.message_id).collect()
    }

    fn parked(&self) -> Vec<ParkedOutbound> {
        self.store().parked_for_recipient(&self.bob_pub()).unwrap()
    }

    fn link(&self) -> Link<'_> {
        Link {
            pair: self,
            dials: Vec::new(),
            fail: false,
        }
    }

    /// A verified contact's step over a loopback LAN route, now.
    fn step(&self, link: &mut Link<'_>) -> (HorizonStep, HorizonReport) {
        let routes = lan();
        let env = HorizonEnv {
            data_dir: self.a(),
            identity: &self.alice,
            peer: self.bob_pub(),
            routes: &routes,
            pinned: true,
            now_ms: now(),
        };
        run_horizon_step(&env, link).unwrap()
    }

    /// Bob takes each re-sealed copy and Alice accepts his ACK; Bob's inbox.
    fn deliver(&self, report: &HorizonReport) -> Vec<String> {
        for r in &report.resealed {
            let replies = dispatch_frame(
                self.b_dir.path(),
                &self.bob,
                &self.a_bundle,
                &self.alice.public_key_bytes(),
                &r.new.immutable_envelope_bytes,
            )
            .unwrap();
            let mut store = self.store();
            let key = store
                .record_key_for_session_id(&r.new.session_id)
                .unwrap()
                .unwrap();
            crate::outbox::finish_outbound_delivered(
                self.a(),
                &mut store,
                &key,
                &self.b_bundle.cert,
                &r.new.session_id,
                &r.new.object_digest,
                &r.message_id,
                &replies[0],
                now(),
                crate::outbox::OutboxCarrier::Lan,
            )
            .unwrap();
        }
        self.bob_inbox()
    }

    fn bob_inbox(&self) -> Vec<String> {
        IndexedSessionStore::open(self.b_dir.path())
            .unwrap()
            .list_endpoint_inbox()
            .unwrap()
            .into_iter()
            .map(|r| String::from_utf8_lossy(&r.plaintext).into_owned())
            .collect()
    }

    /// Alice's history row of `mid`: (delivery, body).
    fn history(&self, mid: &[u8; 16]) -> Option<(String, String)> {
        crate::ChatHistory::load(self.a())
            .unwrap()
            .entries
            .into_iter()
            .find(|e| e.direction == "out" && e.message_id_hex == hex::encode(mid))
            .map(|e| (e.delivery, e.body))
    }

    fn delivery(&self, mid: &[u8; 16]) -> String {
        self.history(mid).expect("a history row").0
    }

    fn heads(&self) -> usize {
        self.store().list_record_keys().unwrap().len()
    }

    fn budget(&self) -> PeerRenewalState {
        self.store().peer_renewal_state(&self.bob_pub()).unwrap()
    }
}

/// Alice's side of the link to Bob's folder: a probe returns Bob's offer,
/// frames are dispatched there exactly as the listener does.
struct Link<'a> {
    pair: &'a Pair,
    /// Frames per dial (a probe sends none).
    dials: Vec<usize>,
    /// Every dial fails (Bob is away).
    fail: bool,
}

impl ResetIo for Link<'_> {
    fn locked(
        &mut self,
        f: &mut dyn FnMut(&mut IndexedSessionStore) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut store =
            IndexedSessionStore::open(self.pair.a()).map_err(|e| e.redacted_display())?;
        f(&mut store)
    }

    fn dial(&mut self, _route: &OutboxRoute, frames: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        self.dials.push(frames.len());
        if self.fail {
            return Err("connection refused".into());
        }
        let p = self.pair;
        let mut replies = vec![crate::lan_rlb1::encode_offer(&local_bundle(
            p.b_dir.path(),
            &p.bob,
        )?)?];
        for frame in frames {
            replies.extend(dispatch_frame(
                p.b_dir.path(),
                &p.bob,
                &p.a_bundle,
                &p.alice.public_key_bytes(),
                frame,
            )?);
        }
        Ok(replies)
    }
}

fn mids(report: &HorizonReport) -> Vec<[u8; 16]> {
    report.resealed.iter().map(|r| r.message_id).collect()
}

/// The headline (s50 in one process): two messages to Bob ran out while he
/// was away and were parked; he is back a day later. One step re-pairs (a
/// probe, then one PairInit, counted once in the shared re-pair budget) and
/// seals both again under their own message ids into the new session, in
/// the order sent; Bob takes them, Alice's history says delivered, and a
/// second step does nothing.
#[test]
fn contact_return_repairs_and_reseals_in_order_same_mid() {
    let _lab = Lab::on();
    let p = pair(0x71);
    let (m1, _) = p.send("d0-a");
    let (m2, _) = p.send("d0-b");
    let old = p
        .store()
        .find_sendable_session_for_peer(&p.bob_pub())
        .unwrap()
        .unwrap();
    let old_sid = p.store().session_id_for_record_key(&old).unwrap();
    at(25 * HOUR_MS as i64);
    assert_eq!(p.park_expired(), vec![m1, m2]);
    assert_eq!(p.delivery(&m1), "queued");
    let heads = p.heads();
    let mut link = p.link();
    let (step, report) = p.step(&mut link);
    assert_eq!(
        step,
        HorizonStep::Repaired {
            carrier: OutboxCarrier::Lan
        }
    );
    assert_eq!(link.dials, vec![0, 1], "a probe, then one PairInit");
    assert!(p.heads() >= heads, "the ended session may be pruned");
    assert_eq!(mids(&report), vec![m1, m2], "send order, same message ids");
    assert_eq!(report.parked, 0);
    assert!(p.parked().is_empty());
    let new_sid = report.resealed[0].new.session_id;
    assert_ne!(new_sid, old_sid, "a new session");
    assert!(report.resealed.iter().all(|r| r.new.session_id == new_sid));
    assert_eq!(
        report
            .resealed
            .iter()
            .map(|r| r.new.ratchet_index)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    // One round of the shared budget; each message re-sealed once.
    assert_eq!(p.budget().attempts_in_window, 1);
    for mid in [m1, m2] {
        assert_eq!(p.store().reseal_count(&p.bob_pub(), &mid).unwrap(), 1);
        assert_eq!(p.delivery(&mid), "queued");
    }
    assert_eq!(p.deliver(&report), vec!["d0-a", "d0-b"]);
    assert_eq!(p.delivery(&m1), "delivered");
    assert_eq!(p.history(&m2).unwrap(), ("delivered".into(), "d0-b".into()));
    let mut again = p.link();
    let (step, report) = p.step(&mut again);
    assert_eq!(step, HorizonStep::Nothing);
    assert!(report.is_empty());
    assert!(again.dials.is_empty());
}

/// Bob came back and paired with Alice himself (a fresh session he
/// started, a day long: not letter-class): the parked message is sealed
/// into it at once, with no dial and no round of the budget.
#[test]
fn fresh_peer_initiated_session_is_target_without_pairinit() {
    let _lab = Lab::on();
    let p = pair(0x73);
    let (m, _) = p.send("while away");
    at(25 * HOUR_MS as i64);
    assert_eq!(p.park_expired(), vec![m]);
    confirm_alice_to_bob(p.b_dir.path(), p.a(), &p.bob, &p.alice);
    let mut link = p.link();
    let (step, report) = p.step(&mut link);
    assert_eq!(step, HorizonStep::Resealed);
    assert!(link.dials.is_empty(), "no dial");
    assert_eq!(p.budget().attempts_in_window, 0, "no round");
    assert_eq!(mids(&report), vec![m]);
    let key = p
        .store()
        .record_key_for_session_id(&report.resealed[0].new.session_id)
        .unwrap()
        .unwrap();
    assert_eq!(key.initiator_device_ed25519, p.bob_pub(), "Bob's session");
    assert_eq!(p.deliver(&report), vec!["while away"]);
}

/// Bob is still away: the probe fails, so no PairInit exists, no round is
/// counted, nothing changes and the message stays parked (the worker backs
/// off).
#[test]
fn unreachable_backs_off_without_pairinit() {
    let _lab = Lab::on();
    let p = pair(0x75);
    let (m, _) = p.send("still away");
    at(25 * HOUR_MS as i64);
    p.park_expired();
    let heads = p.heads();
    let mut link = p.link();
    link.fail = true;
    let (step, report) = p.step(&mut link);
    assert!(matches!(step, HorizonStep::Unreachable(_)), "{step:?}");
    assert_eq!(link.dials, vec![0], "the probe only");
    assert_eq!(p.heads(), heads, "no PairInit");
    assert_eq!(p.budget(), PeerRenewalState::default(), "nothing counted");
    assert!(report.is_empty());
    assert_eq!(report.parked, 1);
    assert_eq!(p.parked()[0].message_id, m);
    assert_eq!(p.delivery(&m), "queued");
}

/// Past its deadline a parked message is given up as `expired` (its body
/// kept in the history, the stage gone, `never_sent` from its route record)
/// before anything is dialled.
#[test]
fn deadline_passed_gives_up_expired_without_dial() {
    let _lab = Lab::on();
    let p = pair(0x77);
    let (m, _) = p.send("too late");
    record_object_routes(
        p.a(),
        &m,
        &p.bob_pub(),
        CarrierChoice::Auto,
        &[],
        now() + DAY_MS,
        now(),
    )
    .unwrap();
    at(25 * HOUR_MS as i64);
    p.park_expired();
    let deadline = p.parked()[0].deadline_ms;
    at((7 * DAY_MS + HOUR_MS) as i64);
    assert!(now() > deadline);
    let mut link = p.link();
    let (step, report) = p.step(&mut link);
    assert_eq!(step, HorizonStep::Nothing);
    assert!(link.dials.is_empty(), "no dial");
    assert_eq!(
        report.expired,
        vec![(m, true)],
        "it never left this computer"
    );
    assert_eq!(report.finished(), vec![m]);
    assert!(p.parked().is_empty());
    assert_eq!(
        p.history(&m).unwrap(),
        ("expired".into(), "too late".into())
    );
    assert!(crate::chat_history::load_staged_outbound_body(p.a(), &m)
        .unwrap()
        .is_none());
    assert_eq!(p.budget(), PeerRenewalState::default());
}

/// At most HORIZON_MAX_COPIES (8) sealed copies of one message: one already
/// re-sealed 7 times is given up (`failed`), one re-sealed 6 times gets its
/// eighth copy.
#[test]
fn copies_cap_8() {
    let _lab = Lab::on();
    let p = pair(0x79);
    let (capped, _) = p.send("eight copies already");
    let (last, _) = p.send("one more copy");
    at(25 * HOUR_MS as i64);
    p.park_expired();
    let mut store = p.store();
    for (mid, n) in [
        (capped, HORIZON_MAX_COPIES - 1),
        (last, HORIZON_MAX_COPIES - 2),
    ] {
        for _ in 0..n {
            store
                .bump_reseal_ledger(&p.bob_pub(), &mid, now() + DAY_MS, now())
                .unwrap();
        }
    }
    drop(store);
    let mut link = p.link();
    let (step, report) = p.step(&mut link);
    assert!(matches!(step, HorizonStep::Repaired { .. }), "{step:?}");
    assert_eq!(report.capped, vec![capped]);
    assert_eq!(mids(&report), vec![last]);
    assert_eq!(p.delivery(&capped), "failed");
    assert_eq!(
        p.store().reseal_count(&p.bob_pub(), &last).unwrap(),
        HORIZON_MAX_COPIES - 1
    );
    assert!(p.parked().is_empty());
    assert_eq!(p.deliver(&report), vec!["one more copy"]);
}

/// The cooldown and the day cap are one budget per contact, shared with
/// Phase 3's renewal: a renewal round a moment ago holds the horizon's
/// PairInit (no dial) for 60 s; the horizon's round counts for renewal too;
/// four rounds in the window (whoever began them) hold it until the window
/// rolls.
#[test]
fn cooldown_60s_and_4_rounds_per_day() {
    let _lab = Lab::on();
    let t = 25 * HOUR_MS as i64;
    // The cooldown.
    let p = pair(0x7b);
    p.send("after the cooldown");
    at(t);
    p.park_expired();
    p.store()
        .begin_repair_attempt(&p.bob_pub(), now())
        .unwrap()
        .unwrap();
    at(t + 1_000);
    let mut link = p.link();
    let (step, _) = p.step(&mut link);
    assert_eq!(step, HorizonStep::Held(renew_code::REPAIR_COOLDOWN));
    assert!(link.dials.is_empty(), "no dial while cooling down");
    at(t + 61_000);
    let (step, report) = p.step(&mut link);
    assert!(matches!(step, HorizonStep::Repaired { .. }), "{step:?}");
    assert_eq!(report.resealed.len(), 1);
    let state = p.budget();
    assert_eq!(state.attempts_in_window, 2);
    // Renewal sees the horizon's round.
    assert_eq!(
        crate::session_renewal::repair_budget(&state, now() + 1).map_err(|(_, c)| c),
        Err(renew_code::REPAIR_COOLDOWN)
    );
    // The day cap.
    at(0);
    let q = pair(0x7c);
    q.send("after the window");
    at(t);
    q.park_expired();
    for k in 0..4 {
        at(t + k * 61_000);
        q.store()
            .begin_repair_attempt(&q.bob_pub(), now())
            .unwrap()
            .unwrap();
    }
    at(t + 4 * 61_000);
    let mut link = q.link();
    let (step, _) = q.step(&mut link);
    assert_eq!(step, HorizonStep::Held(renew_code::RENEW_DAILY_CAP));
    assert!(link.dials.is_empty());
    assert_eq!(q.parked().len(), 1);
    at(t + DAY_MS as i64 + 1_000);
    let (step, report) = q.step(&mut link);
    assert!(matches!(step, HorizonStep::Repaired { .. }), "{step:?}");
    assert_eq!(q.deliver(&report), vec!["after the window"]);
    assert_eq!(q.budget().attempts_in_window, 1, "a new window");
}

/// A revoked contact's parked messages are never sealed again: given up
/// (`failed`) without a dial.
#[test]
fn revoked_lineage_gives_up_parked() {
    let _lab = Lab::on();
    let p = pair(0x7d);
    let (m1, _) = p.send("r1");
    let (m2, _) = p.send("r2");
    at(25 * HOUR_MS as i64);
    p.park_expired();
    let rec =
        RevocationRecord::issue(&p.bob, &p.b_bundle.cert.device_id, 1, now(), "lost").unwrap();
    let mut rev = RevocationStore::load_checked(p.a()).unwrap();
    assert!(rev.apply(rec).unwrap());
    rev.save(p.a()).unwrap();
    let mut link = p.link();
    let (step, report) = p.step(&mut link);
    assert_eq!(step, HorizonStep::Nothing);
    assert!(link.dials.is_empty());
    assert_eq!(report.revoked, vec![m1, m2]);
    assert!(p.parked().is_empty());
    assert_eq!(p.delivery(&m1), "failed");
    assert_eq!(p.history(&m2).unwrap(), ("failed".into(), "r2".into()));
}

/// The deadline is the message's write time plus the horizon, set once: a
/// clock stepped back while it waits does not move it, a re-sealed copy
/// never outlives it, and past it the message ends.
#[test]
fn clock_step_back_never_extends_deadline() {
    let _lab = Lab::on();
    let p = pair(0x7f);
    let written = now();
    let (m, _) = p.send("on time");
    at(25 * HOUR_MS as i64);
    p.park_expired();
    // The worker's prune takes the ended session.
    p.store().prune_expired_sessions(now()).unwrap();
    let deadline = p.parked()[0].deadline_ms;
    let staged_at = crate::chat_history::load_staged_outbound_body(p.a(), &m)
        .unwrap()
        .unwrap()
        .created_at_ms;
    assert_eq!(deadline, message_deadline(staged_at));
    assert!(deadline.abs_diff(message_deadline(written)) < 60_000);
    // Two days back: still away; the deadline stays.
    at(25 * HOUR_MS as i64 - 2 * DAY_MS as i64);
    let mut away = p.link();
    away.fail = true;
    assert!(matches!(p.step(&mut away).0, HorizonStep::Unreachable(_)));
    // Parking it again (a later expiry) keeps the earliest deadline.
    assert_eq!(p.parked()[0].deadline_ms, deadline);
    // Back two hours before the deadline: the new copy ends at the deadline.
    at_time(deadline - 2 * HOUR_MS);
    let mut link = p.link();
    let (step, report) = p.step(&mut link);
    assert!(matches!(step, HorizonStep::Repaired { .. }), "{step:?}");
    let envelope = Envelope::unpack(&report.resealed[0].new.immutable_envelope_bytes).unwrap();
    assert_eq!(envelope.expires_at, deadline, "never past the deadline");
    let stage = crate::chat_history::load_staged_outbound_body(p.a(), &m)
        .unwrap()
        .unwrap();
    assert_eq!(stage.created_at_ms, staged_at, "the write time stays");
    // That copy ran out too: past the deadline the message is not parked
    // again but ends.
    at_time(deadline + 1_000);
    let mut store = p.store();
    let row = p.rows(&store).remove(0);
    let key = store
        .record_key_for_session_id(&row.session_id)
        .unwrap()
        .unwrap();
    let gone = park_or_give_up_expired(
        p.a(),
        &mut store,
        &key,
        &p.bob_pub(),
        &row.session_id,
        &row.object_digest,
        &m,
        false,
        now(),
    )
    .unwrap();
    assert!(matches!(gone, ExpiredMessage::GaveUp(_)), "{gone:?}");
    assert!(store.parked_for_recipient(&p.bob_pub()).unwrap().is_empty());
}

/// Crash repair (the reconcile under the peer's lock): a parked message
/// with a live copy elsewhere is no longer parked; a stage that names no
/// copy (the sentinel) is bound to the live copy; a parked message that a
/// late ACK under its old session settled is delivered, not sealed again.
#[test]
fn reconcile_handles_parked_with_live_copy() {
    let _lab = Lab::on();
    let p = pair(0x81);
    let peer = p.bob_pub();
    let (live, _) = p.send("live elsewhere");
    let (acked, acked_bytes) = p.send("acked late");
    let mut store = p.store();
    let rows = p.rows(&store);
    let row_of = |mid: &[u8; 16]| rows.iter().find(|r| r.message_id == *mid).unwrap().clone();
    let (live_row, acked_row) = (row_of(&live), row_of(&acked));
    let deadline = now() + 6 * DAY_MS;
    // A parked row next to its live copy (none was named), and a stage that
    // names no copy.
    assert!(store
        .park_outbound(&peer, &live, None, now(), deadline, now())
        .unwrap());
    let staged = crate::chat_history::load_staged_outbound_body(p.a(), &live)
        .unwrap()
        .unwrap();
    crate::chat_history::stage_outbound_body(
        p.a(),
        &peer,
        &SENTINEL_BINDING,
        &SENTINEL_BINDING,
        &live,
        staged.created_at_ms,
        &staged.body,
    )
    .unwrap();
    // Parked from its session; then Bob's ACK of that copy comes in late.
    assert!(store
        .park_outbound(
            &peer,
            &acked,
            Some(&acked_row.session_id),
            now(),
            deadline,
            now()
        )
        .unwrap());
    drop(store);
    let replies = dispatch_frame(
        p.b_dir.path(),
        &p.bob,
        &p.a_bundle,
        &p.alice.public_key_bytes(),
        &acked_bytes,
    )
    .unwrap();
    let mut store = p.store();
    let key = store
        .record_key_for_session_id(&acked_row.session_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        crate::outbox::accept_sealed_ack(
            p.a(),
            &mut store,
            &key,
            &p.b_bundle.cert,
            &replies[0],
            crate::outbox::OutboxCarrier::Lan,
        )
        .unwrap(),
        acked
    );
    assert_eq!(store.parked_for_recipient(&peer).unwrap().len(), 2);
    assert_eq!(
        reconcile_resealed_outbound(p.a(), &p.alice, &mut store, &peer, now()).unwrap(),
        2
    );
    assert!(store.parked_for_recipient(&peer).unwrap().is_empty());
    let stage = crate::chat_history::load_staged_outbound_body(p.a(), &live)
        .unwrap()
        .unwrap();
    assert_eq!(
        (stage.session_id_hex, stage.object_digest_hex),
        (
            hex::encode(live_row.session_id),
            hex::encode(live_row.object_digest)
        ),
        "bound to the live copy"
    );
    assert_eq!(
        p.history(&acked).unwrap(),
        ("delivered".into(), "acked late".into())
    );
    assert!(
        crate::chat_history::load_staged_outbound_body(p.a(), &acked)
            .unwrap()
            .is_none()
    );
    // Idempotent; and the step reports the late delivery once.
    assert_eq!(
        reconcile_resealed_outbound(p.a(), &p.alice, &mut store, &peer, now()).unwrap(),
        0
    );
    drop(store);
    let mut link = p.link();
    let (step, report) = p.step(&mut link);
    assert_eq!(step, HorizonStep::Nothing);
    assert!(link.dials.is_empty());
    assert!(report.is_empty());
}

/// With the gate off the step reads nothing and does nothing, whatever is
/// parked.
#[test]
fn gate_off_step_does_nothing() {
    let lab = Lab::on();
    let p = pair(0x83);
    p.send("parked in the lab");
    at(25 * HOUR_MS as i64);
    p.park_expired();
    set_lab_horizon_for_this_thread(Some(false));
    let mut link = p.link();
    let (step, report) = p.step(&mut link);
    assert_eq!(step, HorizonStep::Nothing);
    assert!(report.is_empty() && report.parked == 0);
    assert!(link.dials.is_empty());
    assert_eq!(p.parked().len(), 1);
    drop(lab);
}

/// The reset step's own expiry parks too (its gate and the horizon's on): a
/// retired row whose envelope ran out is parked from its session, not given
/// up; with the horizon off it is `expired` exactly as before.
#[test]
fn reset_step_parks_expired_retired_rows() {
    for horizon in [true, false] {
        let _lab = Lab::on();
        set_lab_session_reset_for_this_thread(Some(1));
        set_lab_horizon_for_this_thread(Some(horizon));
        let p = pair(if horizon { 0x85 } else { 0x87 });
        let (m, _) = p.send("retired then expired");
        let key = p
            .store()
            .find_sendable_session_for_peer(&p.bob_pub())
            .unwrap()
            .unwrap();
        p.store()
            .retire_session(&key, &p.bob_pub(), SessionRetireCause::PeerNoSession, now())
            .unwrap();
        at(25 * HOUR_MS as i64);
        let routes = lan();
        let env = crate::session_reset::ResetEnv {
            data_dir: p.a(),
            identity: &p.alice,
            peer: p.bob_pub(),
            routes: &routes,
            user_confirmed: false,
            now_ms: now(),
        };
        let mut link = p.link();
        let step = crate::session_reset::run_reset_step(&env, &mut link).unwrap();
        let crate::session_reset::ResetStep::Resealed(report) = step else {
            panic!("{step:?}");
        };
        assert!(link.dials.is_empty());
        if horizon {
            assert_eq!(report.parked, vec![m]);
            assert!(report.expired.is_empty());
            assert_eq!(
                p.parked()[0].from_session,
                Some(p.store().session_id_for_record_key(&key).unwrap())
            );
            assert_eq!(p.delivery(&m), "queued");
        } else {
            assert_eq!(report.expired, vec![m]);
            assert!(report.parked.is_empty());
            assert!(p.parked().is_empty());
            assert_eq!(p.delivery(&m), "expired");
        }
    }
}

// ── Review 5a: cancel, contact removal, sentinel stages, receiver dedup ────

impl Pair {
    /// A message to Bob parked the way a send without a session parks it
    /// (P5.8): the row first, then the body staged with the zero sentinel
    /// binding and history `queued`; no sealed copy exists.
    fn park_sentinel(&self, text: &str) -> [u8; 16] {
        let mut mid = [0u8; 16];
        rand::RngCore::fill_bytes(&mut OsRng, &mut mid);
        let written = now();
        assert!(self
            .store()
            .park_outbound(
                &self.bob_pub(),
                &mid,
                None,
                written,
                message_deadline(written),
                written
            )
            .unwrap());
        ensure_outbound_queued_history(
            self.a(),
            &self.bob_pub(),
            &SENTINEL_BINDING,
            &SENTINEL_BINDING,
            &mid,
            written,
            Some(text),
        )
        .unwrap();
        mid
    }

    fn staged(&self, mid: &[u8; 16]) -> bool {
        crate::chat_history::load_staged_outbound_body(self.a(), mid)
            .unwrap()
            .is_some()
    }

    /// Bob's received history rows from Alice: (message id, body).
    fn bob_history_in(&self) -> Vec<(String, String)> {
        crate::ChatHistory::load(self.b_dir.path())
            .unwrap()
            .entries
            .into_iter()
            .filter(|e| e.direction == "in")
            .map(|e| (e.message_id_hex, e.body))
            .collect()
    }
}

/// Review 5a-1: `raven outbox cancel` of a parked message (one parked from
/// its session, one parked before any session existed) gives it up as the
/// step gives one up, with history `cancelled`: no parked row, no stage, the
/// body kept in the history. A second cancel finds nothing, and the next
/// step neither dials nor seals anything: Bob never gets them.
#[test]
fn cancel_parked_gives_it_up_for_good() {
    let _lab = Lab::on();
    let p = pair(0x89);
    let (from_session, _) = p.send("parked from its session");
    at(25 * HOUR_MS as i64);
    assert_eq!(p.park_expired(), vec![from_session]);
    let sentinel = p.park_sentinel("parked without a session");
    assert_eq!(p.parked().len(), 2);
    let peer = p.bob_pub();
    let mut store = p.store();
    for mid in [from_session, sentinel] {
        assert_eq!(
            crate::horizon::cancel_parked(p.a(), &mut store, &peer, &mid).unwrap(),
            Some(crate::outbox::GiveUp::Abandoned)
        );
        assert_eq!(
            crate::horizon::cancel_parked(p.a(), &mut store, &peer, &mid).unwrap(),
            None,
            "not parked any more"
        );
    }
    drop(store);
    assert!(p.parked().is_empty());
    for (mid, body) in [
        (from_session, "parked from its session"),
        (sentinel, "parked without a session"),
    ] {
        assert!(!p.staged(&mid));
        assert_eq!(p.history(&mid).unwrap(), ("cancelled".into(), body.into()));
    }
    // A restart's stage reconcile changes nothing.
    reconcile_outbound_stage_history(p.a()).unwrap();
    assert_eq!(p.delivery(&sentinel), "cancelled");
    let mut link = p.link();
    let (step, report) = p.step(&mut link);
    assert_eq!(step, HorizonStep::Nothing);
    assert!(report.is_empty());
    assert!(link.dials.is_empty(), "nothing to re-pair for");
    assert!(p.bob_inbox().is_empty());
}

/// Review 5a-1: a parked message whose copy Bob confirmed late (an ACK the
/// step has not settled yet) is not cancelled: it was delivered.
#[test]
fn cancel_parked_after_a_late_ack_says_delivered() {
    let _lab = Lab::on();
    let p = pair(0x8b);
    let (m, bytes) = p.send("acked late");
    let row = p.rows(&p.store()).remove(0);
    let replies = dispatch_frame(
        p.b_dir.path(),
        &p.bob,
        &p.a_bundle,
        &p.alice.public_key_bytes(),
        &bytes,
    )
    .unwrap();
    let mut store = p.store();
    assert!(store
        .park_outbound(
            &p.bob_pub(),
            &m,
            Some(&row.session_id),
            now(),
            now() + 6 * DAY_MS,
            now()
        )
        .unwrap());
    let key = store
        .record_key_for_session_id(&row.session_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        crate::outbox::accept_sealed_ack(
            p.a(),
            &mut store,
            &key,
            &p.b_bundle.cert,
            &replies[0],
            crate::outbox::OutboxCarrier::Lan,
        )
        .unwrap(),
        m
    );
    assert_eq!(
        crate::horizon::cancel_parked(p.a(), &mut store, &p.bob_pub(), &m).unwrap(),
        Some(crate::outbox::GiveUp::Delivered)
    );
    drop(store);
    assert!(p.parked().is_empty());
    assert!(!p.staged(&m));
    assert_eq!(p.delivery(&m), "delivered");
}

/// Review 5a-2: removing a contact gives up every message parked for it
/// (history `cancelled`, the stage cleared, the route record cleared) before
/// its parked rows are forgotten; neither a stage (with the body and the
/// removed contact's key) nor a `queued` row is left, also after the stage
/// reconcile of a restart and past the deadline.
#[test]
fn removing_a_contact_leaves_no_parked_stage_behind() {
    let _lab = Lab::on();
    let p = pair(0x8d);
    let (from_session, _) = p.send("to be removed, sent");
    at(25 * HOUR_MS as i64);
    p.park_expired();
    let sentinel = p.park_sentinel("to be removed, never sealed");
    for mid in [from_session, sentinel] {
        record_object_routes(
            p.a(),
            &mid,
            &p.bob_pub(),
            CarrierChoice::Auto,
            &[],
            now() + DAY_MS,
            now(),
        )
        .unwrap();
    }
    let mut store = p.store();
    let gone = crate::horizon::give_up_parked_for_contact(p.a(), &mut store, &p.bob_pub()).unwrap();
    drop(store);
    assert_eq!(gone, vec![from_session, sentinel]);
    crate::indexed_session_store::forget_session_end(p.a(), &p.bob_pub()).unwrap();
    let records = crate::outbox::object_route_records(p.a(), now()).unwrap();
    for when in [0, 8 * DAY_MS] {
        at((25 * HOUR_MS + when) as i64);
        reconcile_outbound_stage_history(p.a()).unwrap();
        assert!(crate::chat_history::list_staged_outbound_bodies(p.a())
            .unwrap()
            .is_empty());
        for mid in [from_session, sentinel] {
            assert_eq!(p.delivery(&mid), "cancelled");
            assert!(!records.contains_key(&mid), "route record cleared");
        }
    }
    assert!(p.parked().is_empty());
}

/// Review 5a-2, defence in depth: a stage that names no copy (the zero
/// sentinel binding) waits only while its message is parked or a live copy
/// of it exists. One whose parked row is gone (an older build's contact
/// removal dropped the row only) is finished: `failed`, or `expired` past
/// its deadline, its stage cleared. One with a live copy (a re-seal's crash
/// window) keeps waiting, and the re-seal reconcile binds it to that copy.
#[test]
fn a_sentinel_stage_without_a_parked_row_is_finished_unless_a_live_copy_exists() {
    let _lab = Lab::on();
    let p = pair(0x8f);
    let peer = p.bob_pub();
    let sentinel_stage = |mid: &[u8; 16], written: u64, body: &str| {
        crate::chat_history::stage_outbound_body(
            p.a(),
            &peer,
            &SENTINEL_BINDING,
            &SENTINEL_BINDING,
            mid,
            written,
            body,
        )
        .unwrap();
        ensure_outbound_queued_history(
            p.a(),
            &peer,
            &SENTINEL_BINDING,
            &SENTINEL_BINDING,
            mid,
            written,
            None,
        )
        .unwrap();
    };
    let orphan = [0x51; 16];
    sentinel_stage(&orphan, now(), "row gone");
    let old = [0x52; 16];
    sentinel_stage(&old, now() - 8 * DAY_MS, "row gone long ago");
    let parked = p.park_sentinel("still parked");
    let (live, _) = p.send("a live copy");
    let staged = crate::chat_history::load_staged_outbound_body(p.a(), &live)
        .unwrap()
        .unwrap();
    sentinel_stage(&live, staged.created_at_ms, &staged.body);
    reconcile_outbound_stage_history(p.a()).unwrap();
    assert_eq!(
        p.history(&orphan).unwrap(),
        ("failed".into(), "row gone".into())
    );
    assert_eq!(
        p.history(&old).unwrap(),
        ("expired".into(), "row gone long ago".into())
    );
    assert!(!p.staged(&orphan) && !p.staged(&old));
    for mid in [parked, live] {
        assert_eq!(p.delivery(&mid), "queued");
        assert!(p.staged(&mid));
    }
    // The re-seal reconcile binds the live copy's stage to it.
    let row = p
        .rows(&p.store())
        .into_iter()
        .find(|r| r.message_id == live)
        .unwrap();
    let mut store = p.store();
    reconcile_resealed_outbound(p.a(), &p.alice, &mut store, &peer, now()).unwrap();
    drop(store);
    let stage = crate::chat_history::load_staged_outbound_body(p.a(), &live)
        .unwrap()
        .unwrap();
    assert_eq!(
        (stage.session_id_hex, stage.object_digest_hex),
        (hex::encode(row.session_id), hex::encode(row.object_digest))
    );
}

/// Review 5a-4: Bob took Alice's message, his ACK was lost, and its history
/// row went (the chat was deleted, or the 2,000-entry cap evicted it);
/// Alice's horizon re-seals it under a new session. Bob answers the copy
/// (Alice's history says delivered) but writes no history row for it: the
/// terminal app and `raven messages` read the history only and would show
/// it as a new message.
#[test]
fn a_resealed_copy_is_not_written_to_the_history_again() {
    for evicted in [false, true] {
        let _lab = Lab::on();
        let p = pair(if evicted { 0x91 } else { 0x93 });
        let (m, bytes) = p.send("taken once");
        // Bob takes copy 1; its ACK never reaches Alice.
        dispatch_frame(
            p.b_dir.path(),
            &p.bob,
            &p.a_bundle,
            &p.alice.public_key_bytes(),
            &bytes,
        )
        .unwrap();
        assert_eq!(
            p.bob_history_in(),
            vec![(hex::encode(m), "taken once".into())]
        );
        at(25 * HOUR_MS as i64);
        assert_eq!(p.park_expired(), vec![m]);
        let mut link = p.link();
        let (step, report) = p.step(&mut link);
        assert!(matches!(step, HorizonStep::Repaired { .. }), "{step:?}");
        assert_eq!(mids(&report), vec![m]);
        let alice = p.alice.public_key_bytes();
        if evicted {
            // 2,000 newer rows from Alice push copy 1's out (the cap is
            // enforced on the last one's write).
            let mut history = crate::ChatHistory::load(p.b_dir.path()).unwrap();
            let filler = |i: u32| {
                let mut mid = [0x77; 16];
                mid[..4].copy_from_slice(&i.to_be_bytes());
                crate::chat_history::ChatHistoryEntry {
                    message_id_hex: hex::encode(mid),
                    direction: "in".into(),
                    peer_petname: String::new(),
                    peer_tag: String::new(),
                    peer_pub_hex: hex::encode(alice),
                    created_at_ms: now() + 1 + u64::from(i),
                    delivery: "received".into(),
                    preview: "filler".into(),
                    body: "filler".into(),
                    stored_at_ms: None,
                    id_conflict: false,
                }
            };
            history.entries.extend((0..1_999).map(filler));
            history.append(filler(1_999));
            history.save(p.b_dir.path()).unwrap();
        } else {
            crate::privacy::delete_chat(p.b_dir.path(), &alice, None).unwrap();
        }
        let before = p.bob_history_in();
        assert!(!before.iter().any(|(mid, _)| *mid == hex::encode(m)));
        // Copy 2 is committed and answered.
        assert!(p.deliver(&report).contains(&"taken once".to_string()));
        assert_eq!(p.delivery(&m), "delivered");
        assert_eq!(p.bob_history_in(), before, "no row for the later copy");
    }
}
