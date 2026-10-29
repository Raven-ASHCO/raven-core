//! Session renewal (Phase 3 item 4, [`crate::session_renewal`]) end to end
//! over two profile folders: a renewer's [`run_renewal_step`] dials the
//! other folder through [`RenewLink`], which answers exactly as the listener
//! does ([`dispatch_frame`]), like the reset step's `LinkTo`. Sessions start
//! shorter than a day through the thread's lifetime override (the tests'
//! "the session ends in 11 h"); the renewal clock is injected (`now_ms`).
//! Phase 6b step P6.27 adds the early re-key (R2) and the rollback recovery
//! (R3) on the same fixture.

use std::cell::RefCell;

use super::*;
use crate::indexed_session_store::SessionLifecycle;
use crate::outbox::{OutboxCarrier, OutboxRoute};
use crate::session_renewal::{
    code as renew_code, request_early, request_early_for_live_peers, run_renewal_step,
    set_lab_session_renewal_for_this_thread, set_response_retry_gap_for_this_thread, RenewEnv,
    RenewStep, Role, DAY_MS, RENEW_FALLBACK_BELOW_MS, RENEW_NO_ROUTE_WAIT_MS, REPAIR_MAX_PER_DAY,
};
use crate::session_reset::ResetIo;

const HOUR_MS: u64 = 3_600_000;
const MIN_MS: u64 = 60_000;

/// Renewal on for this test thread, quick resends 20 ms apart, the reset
/// step off whatever `RAVEN_LAB_SESSION_RESET` says (a test that wants it
/// takes a [`ResetGate`] after this); restored when dropped. The LAN switch
/// is held as the test needs it.
struct RenewGate {
    _untouched: Option<std::sync::RwLockReadGuard<'static, ()>>,
    _lan_off: Option<crate::lan_gate::LanUserOffForTest>,
}

impl RenewGate {
    fn on() -> Self {
        Self::switch_on();
        RenewGate {
            _untouched: Some(crate::lan_gate::lan_user_switch_untouched()),
            _lan_off: None,
        }
    }

    /// `raven lan off` in effect while the gate lives.
    fn lan_off() -> Self {
        Self::switch_on();
        RenewGate {
            _untouched: None,
            _lan_off: Some(crate::lan_gate::lan_user_off_for_test(true)),
        }
    }

    fn switch_on() {
        set_lab_session_renewal_for_this_thread(Some(true));
        set_response_retry_gap_for_this_thread(Some(20));
        set_lab_session_reset_for_this_thread(Some(0));
    }
}

impl Drop for RenewGate {
    fn drop(&mut self) {
        set_lab_session_renewal_for_this_thread(None);
        set_response_retry_gap_for_this_thread(None);
        set_lab_session_lifetime_for_this_thread(None);
        set_lab_session_reset_for_this_thread(None);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Who {
    Alice,
    Bob,
}

impl Who {
    fn other(self) -> Who {
        match self {
            Who::Alice => Who::Bob,
            Who::Bob => Who::Alice,
        }
    }
}

/// Alice and Bob, contacts of each other, and the session Alice started.
struct Pair {
    alice: Identity,
    bob: Identity,
    a_dir: tempfile::TempDir,
    b_dir: tempfile::TempDir,
    a_bundle: LanBundle,
    b_bundle: LanBundle,
}

/// Alice pairs with Bob (Bob's prekey `bob_prekey_id`); the session lasts
/// `lifetime` (the thread's override, for that pairing only).
fn pair_with(seed: u8, lifetime: u64, bob_prekey_id: u32) -> Pair {
    let alice = Identity::from_seed(&[seed; 32]);
    let bob = Identity::from_seed(&[seed.wrapping_add(1); 32]);
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    publish_and_install(a_dir.path(), &alice);
    publish_and_install_with(b_dir.path(), &bob, bob_prekey_id, now());
    set_lab_session_lifetime_for_this_thread(Some(lifetime));
    let (a_bundle, b_bundle) = confirm_alice_to_bob(a_dir.path(), b_dir.path(), &alice, &bob);
    set_lab_session_lifetime_for_this_thread(None);
    Pair {
        alice,
        bob,
        a_dir,
        b_dir,
        a_bundle,
        b_bundle,
    }
}

fn pair(seed: u8, lifetime: u64) -> Pair {
    pair_with(seed, lifetime, 1)
}

fn lan(dial: &str) -> Vec<OutboxRoute> {
    vec![OutboxRoute {
        carrier: OutboxCarrier::Lan,
        dial: dial.into(),
    }]
}

const LOOPBACK: &str = "127.0.0.1:9";

impl Pair {
    fn dir(&self, who: Who) -> &Path {
        match who {
            Who::Alice => self.a_dir.path(),
            Who::Bob => self.b_dir.path(),
        }
    }

    fn id(&self, who: Who) -> &Identity {
        match who {
            Who::Alice => &self.alice,
            Who::Bob => &self.bob,
        }
    }

    fn bundle(&self, who: Who) -> &LanBundle {
        match who {
            Who::Alice => &self.a_bundle,
            Who::Bob => &self.b_bundle,
        }
    }

    fn key_of(&self, who: Who) -> [u8; 32] {
        self.id(who).public_key_bytes()
    }

    /// `from`'s link to the other side's folder.
    fn link(&self, from: Who) -> RenewLink<'_> {
        self.link_to(from, self.dir(from.other()))
    }

    /// `from`'s link to `to_dir`, which answers as the other side.
    fn link_to<'a>(&'a self, from: Who, to_dir: &'a Path) -> RenewLink<'a> {
        RenewLink {
            from_dir: self.dir(from),
            to_dir,
            to: self.id(from.other()),
            from_bundle: self.bundle(from),
            from: self.id(from),
            dials: Vec::new(),
            drop_replies: 0,
            fail: false,
            responder_gate_off: false,
            before_pair_init: None,
            locks: 0,
            busy_locks: Vec::new(),
        }
    }

    fn step_at(
        &self,
        who: Who,
        link: &mut RenewLink<'_>,
        routes: &[OutboxRoute],
        pinned: bool,
        lapsed: Option<u64>,
        at: u64,
    ) -> RenewStep {
        let env = RenewEnv {
            data_dir: self.dir(who),
            identity: self.id(who),
            peer: self.key_of(who.other()),
            routes,
            pinned,
            lapsed_noticed_at_ms: lapsed,
            now_ms: at,
        };
        run_renewal_step(&env, link).unwrap()
    }

    /// A verified contact's step over a loopback LAN route, now.
    fn step(&self, who: Who, link: &mut RenewLink<'_>) -> RenewStep {
        self.step_at(who, link, &lan(LOOPBACK), true, None, now())
    }

    /// `who`'s newest sendable session with the other side: key, created, expires.
    fn newest(&self, who: Who) -> Option<(IndexedSessionRecordKey, u64, u64)> {
        IndexedSessionStore::open(self.dir(who))
            .unwrap()
            .newest_sendable_summary(&self.key_of(who.other()), now())
            .unwrap()
    }

    fn heads(&self, who: Who) -> usize {
        IndexedSessionStore::open(self.dir(who))
            .unwrap()
            .list_record_keys()
            .unwrap()
            .len()
    }

    fn renewal_state(&self, who: Who) -> crate::indexed_session_store::PeerRenewalState {
        IndexedSessionStore::open(self.dir(who))
            .unwrap()
            .peer_renewal_state(&self.key_of(who.other()))
            .unwrap()
    }

    /// `from` sends `text` as `ash send` does: sealed under its newest
    /// session, its body kept, `queued`; not delivered. Its message id.
    fn stage(&self, from: Who, text: &str) -> (IndexedSessionRecordKey, [u8; 16]) {
        let (key, packed) = self.staged(from, text);
        (key, Envelope::unpack(&packed).unwrap().message_id)
    }

    /// [`Self::stage`], giving the sealed bytes.
    fn staged(&self, from: Who, text: &str) -> (IndexedSessionRecordKey, Vec<u8>) {
        let (key, packed) = self.seal(from, text);
        let env = Envelope::unpack(&packed).unwrap();
        let sid = IndexedSessionStore::open(self.dir(from))
            .unwrap()
            .session_id_for_record_key(&key)
            .unwrap();
        ensure_outbound_queued_history(
            self.dir(from),
            &self.key_of(from.other()),
            &sid,
            &crate::bridge::authenticated_object_digest(&env),
            &env.message_id,
            env.created_at,
            Some(text),
        )
        .unwrap();
        (key, packed)
    }

    /// `from` seals `text` under its newest session (what `raven send` picks).
    fn seal(&self, from: Who, text: &str) -> (IndexedSessionRecordKey, Vec<u8>) {
        let key = self.newest(from).expect("a session").0;
        let packed = seal_under(self.dir(from), self.id(from), &key, text);
        (key, packed)
    }

    /// The other side takes `packed` from `from` and its ACK passes at `from`.
    fn deliver(&self, from: Who, key: &IndexedSessionRecordKey, packed: &[u8]) {
        let to = from.other();
        let acks = dispatch_frame(
            self.dir(to),
            self.id(to),
            self.bundle(from),
            &self.key_of(from),
            packed,
        )
        .unwrap();
        assert_eq!(acks.len(), 1);
        let mut store = IndexedSessionStore::open(self.dir(from)).unwrap();
        let acked = crate::outbox::accept_sealed_ack(
            self.dir(from),
            &mut store,
            key,
            &self.bundle(to).cert,
            &acks[0],
            crate::outbox::OutboxCarrier::Lan,
        )
        .unwrap();
        assert_eq!(acked, Envelope::unpack(packed).unwrap().message_id);
    }
}

/// A renewer's side of the link to the contact's folder: a probe returns the
/// contact's offer, frames are dispatched there exactly as the listener does.
struct RenewLink<'a> {
    from_dir: &'a Path,
    to_dir: &'a Path,
    to: &'a Identity,
    from_bundle: &'a LanBundle,
    from: &'a Identity,
    /// Frames per dial (a probe sends none).
    dials: Vec<usize>,
    /// The replies of this many PairInit dials are lost after the contact
    /// handled them (only the offer comes back).
    drop_replies: usize,
    /// Every dial fails.
    fail: bool,
    /// The contact answers with renewal off (an older build, or its gate off).
    responder_gate_off: bool,
    /// Runs once, before the first PairInit reaches the contact.
    before_pair_init: Option<Box<dyn FnOnce() + 'a>>,
    /// The send-lock calls made so far, and those (1-based) that find the
    /// lock busy (an `ash send` to the contact holds it past the wait).
    locks: usize,
    busy_locks: Vec<usize>,
}

impl ResetIo for RenewLink<'_> {
    fn locked(
        &mut self,
        f: &mut dyn FnMut(&mut IndexedSessionStore) -> Result<(), String>,
    ) -> Result<(), String> {
        self.locks += 1;
        if self.busy_locks.contains(&self.locks) {
            return Err("data-dir lock (peer send): database is locked".into());
        }
        let mut store =
            IndexedSessionStore::open(self.from_dir).map_err(|e| e.redacted_display())?;
        f(&mut store)
    }

    fn dial(&mut self, _route: &OutboxRoute, frames: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        self.dials.push(frames.len());
        if self.fail {
            return Err("connection refused".into());
        }
        if !frames.is_empty() {
            if let Some(hook) = self.before_pair_init.take() {
                hook();
            }
        }
        let offer = crate::lan_rlb1::encode_offer(&local_bundle(self.to_dir, self.to)?)?;
        let mut replies = vec![offer];
        if self.responder_gate_off {
            set_lab_session_renewal_for_this_thread(Some(false));
        }
        let mut answered = Ok(());
        for frame in frames {
            match dispatch_frame(
                self.to_dir,
                self.to,
                self.from_bundle,
                &self.from.public_key_bytes(),
                frame,
            ) {
                Ok(more) => replies.extend(more),
                Err(e) => {
                    answered = Err(e);
                    break;
                }
            }
        }
        if self.responder_gate_off {
            set_lab_session_renewal_for_this_thread(Some(true));
        }
        answered?;
        if !frames.is_empty() && self.drop_replies > 0 {
            self.drop_replies -= 1;
            replies.truncate(1);
        }
        Ok(replies)
    }
}

/// The headline: the session Alice started ends in 11 h; Bob (the primary
/// side) renews it on a live link; a message Alice sealed before (under the
/// old session) and one after (under the new one) are both taken, both ACKs
/// pass, and a second step dials nothing.
#[test]
fn session_ends_in_11h_renews_and_messages_continue() {
    let _gate = RenewGate::on();
    let p = pair(0x91, 11 * HOUR_MS);
    let (s1, m1) = p.seal(Who::Alice, "sealed before the renewal");
    let mut link = p.link(Who::Bob);
    assert_eq!(
        p.step(Who::Bob, &mut link),
        RenewStep::Renewed {
            role: Role::Primary,
            carrier: OutboxCarrier::Lan,
            retried_pending: false,
        }
    );
    assert_eq!(link.dials, [0, 1], "a probe, then the PairInit");
    let (s2, _, expires) = p.newest(Who::Bob).unwrap();
    assert_ne!(s2, s1);
    assert_eq!(s2.initiator_device_ed25519, p.key_of(Who::Bob));
    assert!(expires - now() >= DAY_MS - MIN_MS);
    assert_eq!(p.newest(Who::Alice).unwrap().0, s2);
    assert_eq!(p.renewal_state(Who::Bob).pending_init, None);
    let (key, m2) = p.seal(Who::Alice, "sealed after the renewal");
    assert_eq!(key, s2);
    let sid = |key: &IndexedSessionRecordKey| {
        IndexedSessionStore::open(p.dir(Who::Alice))
            .unwrap()
            .session_id_for_record_key(key)
            .unwrap()
    };
    assert_ne!(sid(&s1), sid(&s2));
    p.deliver(Who::Alice, &s1, &m1);
    p.deliver(Who::Alice, &s2, &m2);
    // Not due on either side now, and nothing is dialled again.
    for who in [Who::Alice, Who::Bob] {
        let mut again = p.link(who);
        assert!(
            matches!(
                p.step(who, &mut again),
                RenewStep::NotDue {
                    recheck_at_ms: Some(_)
                }
            ),
            "{who:?}"
        );
        assert!(again.dials.is_empty(), "{who:?}");
    }
}

/// The side that started the newest session renews below 10 h when the
/// primary side has not (it cannot dial, or runs an older build), and not
/// above.
#[test]
fn fallback_side_renews_below_10h_when_the_primary_does_not() {
    let _gate = RenewGate::on();
    let p = pair(0x93, 9 * HOUR_MS + 30 * MIN_MS);
    let mut link = p.link(Who::Alice);
    assert_eq!(
        p.step(Who::Alice, &mut link),
        RenewStep::Renewed {
            role: Role::Fallback,
            carrier: OutboxCarrier::Lan,
            retried_pending: false,
        }
    );
    assert_eq!(
        p.newest(Who::Alice).unwrap().0,
        p.newest(Who::Bob).unwrap().0
    );

    let p = pair(0x95, 10 * HOUR_MS + 30 * MIN_MS);
    let (_, _, expires) = p.newest(Who::Alice).unwrap();
    let mut link = p.link(Who::Alice);
    assert_eq!(
        p.step(Who::Alice, &mut link),
        RenewStep::NotDue {
            recheck_at_ms: Some(expires - RENEW_FALLBACK_BELOW_MS)
        }
    );
    assert!(link.dials.is_empty());
}

/// After the last session ended: the smaller device key sets the pair up
/// again first; the larger one waits 10 min for it, then does it itself,
/// and both sides agree on the newest session.
#[test]
fn lapsed_pair_is_reestablished_smaller_key_first() {
    let _gate = RenewGate::on();
    // Sessions of 5 s (room for the pairing on a loaded machine).
    let first = pair(0x97, 5_000);
    let second = pair(0x99, 5_000);
    // What an earlier step recorded while the session was live.
    let mut ended = 0;
    for p in [&first, &second] {
        for who in [Who::Alice, Who::Bob] {
            let mut store = IndexedSessionStore::open(p.dir(who)).unwrap();
            let key = store.list_record_keys().unwrap().remove(0);
            let expires = store.head_expires_at_ms(&key).unwrap();
            store
                .note_session_end_seen(&p.key_of(who.other()), expires)
                .unwrap();
            ended = ended.max(expires);
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(
        ended.saturating_sub(now()) + 100,
    ));
    let order = |p: &Pair| {
        if p.key_of(Who::Alice) < p.key_of(Who::Bob) {
            (Who::Alice, Who::Bob)
        } else {
            (Who::Bob, Who::Alice)
        }
    };
    let (smaller, larger) = order(&first);
    assert!(first.newest(smaller).is_none());
    let at = now();
    let mut link = first.link(larger);
    assert_eq!(
        first.step_at(larger, &mut link, &lan(LOOPBACK), true, None, at),
        RenewStep::Wait {
            until_ms: at + 10 * MIN_MS,
            code: renew_code::RENEW_WAIT_PEER
        }
    );
    assert!(link.dials.is_empty());
    let mut link = first.link(smaller);
    assert!(matches!(
        first.step(smaller, &mut link),
        RenewStep::Renewed {
            role: Role::Primary,
            ..
        }
    ));
    let newest = first.newest(smaller).unwrap().0;
    assert_eq!(newest.initiator_device_ed25519, first.key_of(smaller));
    assert_eq!(first.newest(larger).unwrap().0, newest);

    // The smaller key never comes: the larger one, 10 min after it noticed.
    let (_, larger) = order(&second);
    let at = now();
    let mut link = second.link(larger);
    assert!(matches!(
        second.step_at(
            larger,
            &mut link,
            &lan(LOOPBACK),
            true,
            Some(at - 10 * MIN_MS),
            at
        ),
        RenewStep::Renewed {
            role: Role::Fallback,
            ..
        }
    ));
    assert_eq!(
        second.newest(Who::Alice).unwrap().0,
        second.newest(Who::Bob).unwrap().0
    );
}

/// With retired rows waiting for a re-seal (reset gate on), the reset step
/// owns the contact: renewal holds, dials nothing and spends nothing.
#[test]
fn renewal_yields_to_reset_when_rows_are_retired() {
    let _gate = RenewGate::on();
    let _reset = ResetGate::on();
    let p = pair(0x9b, 9 * HOUR_MS);
    let (s1, _) = p.seal(Who::Alice, "waits in a retired session");
    assert!(IndexedSessionStore::open(p.dir(Who::Alice))
        .unwrap()
        .retire_session(
            &s1,
            &p.key_of(Who::Bob),
            crate::indexed_session_store::SessionRetireCause::PeerNoSession,
            now()
        )
        .unwrap());
    let mut link = p.link(Who::Alice);
    assert_eq!(
        p.step(Who::Alice, &mut link),
        RenewStep::Held(renew_code::RENEW_RESET_PENDING)
    );
    assert!(link.dials.is_empty());
    assert_eq!(
        p.renewal_state(Who::Alice),
        crate::indexed_session_store::PeerRenewalState::default()
    );
}

/// The probe shows the contact renewed its certificate (it reinstalled, the
/// E2 path): the old sessions retire and the reset step takes over; no
/// PairInit is made.
#[test]
fn renewed_cert_retires_then_yields() {
    let _gate = RenewGate::on();
    let _reset = ResetGate::on();
    set_lab_session_lifetime_for_this_thread(Some(9 * HOUR_MS));
    let w = wiped(0x9d);
    set_lab_session_lifetime_for_this_thread(None);
    let mut link = RenewLink {
        from_dir: w.a_dir.path(),
        to_dir: w.b2_dir.path(),
        to: &w.bob,
        from_bundle: &w.a_bundle,
        from: &w.alice,
        dials: Vec::new(),
        drop_replies: 0,
        fail: false,
        responder_gate_off: false,
        before_pair_init: None,
        locks: 0,
        busy_locks: Vec::new(),
    };
    let routes = lan(LOOPBACK);
    let env = RenewEnv {
        data_dir: w.a_dir.path(),
        identity: &w.alice,
        peer: w.bob.public_key_bytes(),
        routes: &routes,
        pinned: true,
        lapsed_noticed_at_ms: None,
        now_ms: now(),
    };
    assert_eq!(
        run_renewal_step(&env, &mut link).unwrap(),
        RenewStep::Held(renew_code::RENEW_RESET_PENDING)
    );
    assert_eq!(link.dials, [0], "the probe only");
    let mut store = IndexedSessionStore::open(w.a_dir.path()).unwrap();
    assert_eq!(store.list_record_keys().unwrap(), vec![w.key.clone()]);
    let sid = store.session_id_for_record_key(&w.key).unwrap();
    assert_eq!(
        store
            .session_reset_info(&sid)
            .unwrap()
            .unwrap()
            .retire_cause,
        Some(crate::indexed_session_store::SessionRetireCause::PeerCertRenewed)
    );
    assert!(store
        .find_sendable_sessions_for_peer_at(&w.bob.public_key_bytes(), now())
        .unwrap()
        .is_empty());
}

/// A contact whose new prekey the durable pin refuses (it reinstalled with
/// its counter reset): no new session is started on it; the round counts as
/// a failure.
#[test]
fn prekey_pin_refusal_holds_without_a_session() {
    let _gate = RenewGate::on();
    let p = pair_with(0x9f, 9 * HOUR_MS, 3);
    // Bob reinstalls: the same identity, a fresh folder, the counter at 1.
    let b2 = tempfile::tempdir().unwrap();
    publish_and_install_with(b2.path(), &p.bob, 1, now() + 1);
    write_contact(b2.path(), &p.key_of(Who::Alice), "Alice");
    let mut link = p.link_to(Who::Alice, b2.path());
    assert_eq!(
        p.step(Who::Alice, &mut link),
        RenewStep::Held(PEER_PREKEY_RESET)
    );
    assert_eq!(link.dials, [0], "the probe only");
    assert_eq!(p.heads(Who::Alice), 1, "no new session");
    let state = p.renewal_state(Who::Alice);
    assert_eq!((state.attempts_in_window, state.failures), (1, 1));
    assert_eq!(state.pending_init, None);
}

/// The PairResponse is lost after Bob handled the PairInit (and the quick
/// resends are lost too): Alice keeps the PairInit, and the next step sends
/// exactly it again; Bob answers with the response he kept, Alice confirms
/// the same session (no third one), and Bob's messages under it reach her.
#[test]
fn lost_pair_response_is_finished_with_the_same_init() {
    let _gate = RenewGate::on();
    let p = pair(0xa1, 9 * HOUR_MS);
    let mut link = p.link(Who::Alice);
    link.drop_replies = 3;
    assert!(matches!(
        p.step(Who::Alice, &mut link),
        RenewStep::Unreachable(_)
    ));
    assert_eq!(
        link.dials,
        [0, 1, 1, 1],
        "a probe, the PairInit, two resends"
    );
    let state = p.renewal_state(Who::Alice);
    let kept = state.pending_init.clone().expect("the PairInit is kept");
    let init = crate::pair_init::decode_init(&kept).unwrap();
    let s2 = crate::indexed_session_store::record_key_for_init(&init);
    assert_eq!(state.failures, 1);
    // Bob holds S2 confirmed; Alice only as provisional.
    assert_eq!(p.newest(Who::Bob).unwrap().0, s2);
    assert_ne!(p.newest(Who::Alice).unwrap().0, s2);
    assert_eq!(
        IndexedSessionStore::open(p.dir(Who::Alice))
            .unwrap()
            .session_lifecycle(&s2)
            .unwrap(),
        SessionLifecycle::Provisional
    );
    // The next live link (within the failure backoff: a kept PairInit is
    // always worth finishing).
    let mut link = p.link(Who::Alice);
    assert!(matches!(
        p.step(Who::Alice, &mut link),
        RenewStep::Renewed {
            retried_pending: true,
            ..
        }
    ));
    assert_eq!(link.dials, [0, 1]);
    assert_eq!(p.newest(Who::Alice).unwrap().0, s2);
    assert_eq!(p.heads(Who::Alice), 2, "S1 and S2, no S3");
    assert_eq!(p.heads(Who::Bob), 2);
    let state = p.renewal_state(Who::Alice);
    assert_eq!((state.pending_init, state.failures), (None, 0));
    let (key, packed) = p.seal(Who::Bob, "under the renewed session");
    assert_eq!(key, s2);
    p.deliver(Who::Bob, &key, &packed);
}

/// Both sides renew at the same moment (S1 at 9 h: Alice as fallback, Bob as
/// primary): two new sessions, the same newest on both sides, and messages
/// both ways.
#[test]
fn crossed_renewals_converge() {
    let _gate = RenewGate::on();
    let p = pair(0xa3, 9 * HOUR_MS);
    let bob_step = RefCell::new(None);
    let mut link = p.link(Who::Alice);
    link.before_pair_init = Some(Box::new(|| {
        let mut bob_link = p.link(Who::Bob);
        *bob_step.borrow_mut() = Some(p.step(Who::Bob, &mut bob_link));
    }));
    assert!(matches!(
        p.step(Who::Alice, &mut link),
        RenewStep::Renewed {
            role: Role::Fallback,
            ..
        }
    ));
    drop(link);
    assert!(matches!(
        bob_step.into_inner(),
        Some(RenewStep::Renewed {
            role: Role::Primary,
            ..
        })
    ));
    assert_eq!(p.heads(Who::Alice), 3);
    assert_eq!(p.heads(Who::Bob), 3);
    let newest = p.newest(Who::Alice).unwrap().0;
    assert_eq!(p.newest(Who::Bob).unwrap().0, newest);
    for from in [Who::Alice, Who::Bob] {
        let (key, packed) = p.seal(from, "after the crossing");
        assert_eq!(key, newest);
        p.deliver(from, &key, &packed);
    }
}

/// An unverified contact renews only over a LAN route on the local
/// network: an Internet route and a public LAN address are not tried.
#[test]
fn unverified_contact_renews_only_on_a_local_lan_route() {
    let _gate = RenewGate::on();
    let p = pair(0xa5, 9 * HOUR_MS);
    let wide = [
        OutboxRoute {
            carrier: OutboxCarrier::Internet,
            dial: "203.0.113.5:7420".into(),
        },
        OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial: "203.0.113.9:7420".into(),
        },
    ];
    let at = now();
    let mut link = p.link(Who::Alice);
    assert!(matches!(
        p.step_at(Who::Alice, &mut link, &wide, false, None, at),
        RenewStep::Unreachable(_)
    ));
    assert!(link.dials.is_empty());
    // Past the failure's backoff, over a loopback LAN route.
    let mut link = p.link(Who::Alice);
    assert!(matches!(
        p.step_at(
            Who::Alice,
            &mut link,
            &lan(LOOPBACK),
            false,
            None,
            at + 31 * MIN_MS
        ),
        RenewStep::Renewed { .. }
    ));
}

/// A contact on a build without renewal (or with its gate off) answers the
/// renewal's PairInit like any other.
#[test]
fn old_peer_without_renewal_still_answers() {
    let _gate = RenewGate::on();
    let p = pair(0xa7, 9 * HOUR_MS);
    let mut link = p.link(Who::Alice);
    link.responder_gate_off = true;
    assert!(matches!(
        p.step(Who::Alice, &mut link),
        RenewStep::Renewed { .. }
    ));
    assert_eq!(
        p.newest(Who::Bob).unwrap().0,
        p.newest(Who::Alice).unwrap().0
    );
}

/// A link that always fails, with the clock injected over a day in 15 min
/// steps: rounds at 0, 30 min, 1 h 30 and 3 h 30 (the backoff), then the
/// day's cap until the window rolls.
#[test]
fn renewal_respects_the_daily_cap_with_a_failing_link() {
    let _gate = RenewGate::on();
    let p = pair(0xa9, 9 * HOUR_MS);
    let start = now();
    let mut rounds = Vec::new();
    let mut at = start;
    while at <= start + DAY_MS {
        let mut link = p.link(Who::Alice);
        link.fail = true;
        match p.step_at(Who::Alice, &mut link, &lan(LOOPBACK), true, Some(start), at) {
            RenewStep::Unreachable(_) => {
                assert_eq!(link.dials, [0]);
                rounds.push(at - start);
            }
            RenewStep::Wait { code, .. } => {
                assert!(link.dials.is_empty());
                assert!(
                    code == renew_code::RENEW_BACKOFF || code == renew_code::RENEW_DAILY_CAP,
                    "{code}"
                );
            }
            other => panic!("{other:?}"),
        }
        at += 15 * MIN_MS;
    }
    assert_eq!(
        rounds,
        [0, 30 * MIN_MS, 90 * MIN_MS, 210 * MIN_MS, DAY_MS],
        "four rounds a day"
    );
}

/// No planned route may carry a PairInit (`raven lan off` closes the LAN):
/// a wait, no dial, and the day's budget untouched.
#[test]
fn no_route_returns_wait_without_spending_the_budget() {
    let _gate = RenewGate::lan_off();
    let p = pair(0xab, 9 * HOUR_MS);
    for routes in [lan(LOOPBACK), Vec::new()] {
        let at = now();
        let mut link = p.link(Who::Alice);
        assert_eq!(
            p.step_at(Who::Alice, &mut link, &routes, true, None, at),
            RenewStep::Wait {
                until_ms: at + RENEW_NO_ROUTE_WAIT_MS,
                code: renew_code::RENEW_NO_ROUTE
            }
        );
        assert!(link.dials.is_empty());
    }
    assert_eq!(
        p.renewal_state(Who::Alice),
        crate::indexed_session_store::PeerRenewalState::default()
    );
}

/// Review C-4: an `ash send` to the contact holds its send lock (past the
/// renewer's wait) when the renewal creates its PairInit, or when it
/// confirms the PairResponse. A local lock is not the contact: the step
/// returns the busy error for a quick retry, no failure is counted (no
/// backoff), a round whose PairInit was never created is given back (the
/// retry is not held by the cooldown), and the retry renews.
#[test]
fn a_busy_send_lock_is_neither_a_failure_nor_a_spent_round() {
    let _gate = RenewGate::on();
    let p = pair(0xad, 11 * HOUR_MS);
    let routes = lan(LOOPBACK);
    let start = now();
    let step = |link: &mut RenewLink<'_>, at: u64| {
        let env = RenewEnv {
            data_dir: p.dir(Who::Bob),
            identity: p.id(Who::Bob),
            peer: p.key_of(Who::Alice),
            routes: &routes,
            pinned: true,
            lapsed_noticed_at_ms: None,
            now_ms: at,
        };
        run_renewal_step(&env, link)
    };
    // Busy at the create: nothing created, nothing counted.
    let mut link = p.link(Who::Bob);
    link.busy_locks = vec![2];
    let busy = step(&mut link, start).unwrap_err();
    assert!(crate::outbox::send_lock_busy(&busy), "{busy}");
    assert_eq!(link.dials, [0], "the probe only");
    let state = p.renewal_state(Who::Bob);
    assert_eq!(
        (
            state.failures,
            state.attempts_in_window,
            state.last_attempt_at_ms
        ),
        (0, 0, None)
    );
    assert_eq!(state.pending_init, None);
    // Busy at the confirm: the PairInit went out and stays kept; the round
    // it used stays counted, no failure.
    let mut link = p.link(Who::Bob);
    link.busy_locks = vec![3];
    let busy = step(&mut link, start + 5_000).unwrap_err();
    assert!(crate::outbox::send_lock_busy(&busy), "{busy}");
    let state = p.renewal_state(Who::Bob);
    assert_eq!(
        (
            state.failures,
            state.attempts_in_window,
            state.last_attempt_at_ms
        ),
        (0, 1, Some(start + 5_000))
    );
    assert!(state.pending_init.is_some());
    // The retry 5 s later finishes it with the same PairInit.
    let mut link = p.link(Who::Bob);
    assert_eq!(
        step(&mut link, start + 10_000).unwrap(),
        RenewStep::Renewed {
            role: Role::Primary,
            carrier: OutboxCarrier::Lan,
            retried_pending: true,
        }
    );
    let state = p.renewal_state(Who::Bob);
    assert_eq!((state.failures, state.attempts_in_window), (0, 1));
    assert_eq!(state.pending_init, None);
}

// ── Phase 6b R2 and R3 (step P6.27): the early re-key ──────────────────────

use crate::security_events::{Attribution, SecKind, Via};
use crate::security_gate::SecGate;
use crate::security_sense::tests::{Capture, Shut};

/// The responses gate open for this test thread, with the events gate it
/// sits on (and what this thread notes kept); `None` in a release build,
/// where neither can open. Both shut again on drop.
struct Responses(Capture);

impl Responses {
    fn on() -> Option<Self> {
        let capture = Capture::start()?;
        crate::security_gate::set_lab_for_this_thread(SecGate::Responses, Some(true));
        Some(Self(capture))
    }
}

impl Drop for Responses {
    fn drop(&mut self) {
        crate::security_gate::set_lab_for_this_thread(SecGate::Responses, None);
    }
}

/// R2 end to end: Alice signs an object whose ciphertext fails under the
/// session they share (made here with her own key, as a lab injection
/// would) -> Bob notes SEC_OBJECT_AUTH_FAIL about her and asks for an
/// early re-key (raven-node's responder does that part, its own tests show
/// it) -> his next step on the live link renews though 20 h are left -> the
/// old session is retired for a security re-key, the message Bob had
/// waiting in it is re-sealed under the new one and reaches Alice once,
/// and a new message under the new session is taken. A second request
/// within 6 h is refused.
#[test]
fn a_bad_object_under_a_valid_signature_rekeys_early_and_reseals_the_backlog() {
    let _gate = RenewGate::on();
    let _reset = ResetGate::on();
    let Some(responses) = Responses::on() else {
        return;
    };
    let p = pair(0xb1, 20 * HOUR_MS);
    let (s1, m1) = p.stage(Who::Bob, "waits in the old session");
    let mut link = p.link(Who::Bob);
    assert!(matches!(
        p.step(Who::Bob, &mut link),
        RenewStep::NotDue { .. }
    ));
    assert!(link.dials.is_empty());
    // Alice's signature over a ciphertext whose AEAD tag changed.
    let (_, packed) = p.seal(Who::Alice, "changed on the way");
    let mut env = Envelope::unpack(&packed).unwrap();
    *env.message_ciphertext.last_mut().unwrap() ^= 1;
    env.sign_with(p.id(Who::Alice));
    assert!(dispatch_frame(
        p.dir(Who::Bob),
        p.id(Who::Bob),
        p.bundle(Who::Alice),
        &p.key_of(Who::Alice),
        &env.pack()
    )
    .is_err());
    let alice = Attribution::Contact {
        peer: p.key_of(Who::Alice),
    };
    assert_eq!(
        responses.0.kinds(),
        vec![(
            SecKind::ObjectAuthFail,
            alice,
            Via::DirectLink(OutboxCarrier::Lan)
        )]
    );
    let mut store = IndexedSessionStore::open(p.dir(Who::Bob)).unwrap();
    assert!(request_early(
        &mut store,
        &p.key_of(Who::Alice),
        SecKind::ObjectAuthFail,
        now()
    )
    .unwrap());
    assert!(!request_early(
        &mut store,
        &p.key_of(Who::Alice),
        SecKind::ObjectReplay,
        now()
    )
    .unwrap());
    drop(store);
    // The next live link renews, Bob first.
    let mut link = p.link(Who::Bob);
    assert_eq!(
        p.step(Who::Bob, &mut link),
        RenewStep::Renewed {
            role: Role::Early,
            carrier: OutboxCarrier::Lan,
            retried_pending: false,
        }
    );
    assert_eq!(link.dials, [0, 1], "a probe, then the PairInit");
    let (s2, _, _) = p.newest(Who::Bob).unwrap();
    assert_ne!(s2, s1);
    assert_eq!(s2.initiator_device_ed25519, p.key_of(Who::Bob));
    assert_eq!(p.newest(Who::Alice).unwrap().0, s2);
    let state = p.renewal_state(Who::Bob);
    assert_eq!(
        (state.early_requested_at_ms, state.early_reason),
        (None, None)
    );
    assert!(state.last_early_ms.is_some());
    let mut bob_store = IndexedSessionStore::open(p.dir(Who::Bob)).unwrap();
    let old = bob_store.session_id_for_record_key(&s1).unwrap();
    let new = bob_store.session_id_for_record_key(&s2).unwrap();
    assert_eq!(
        bob_store
            .session_reset_info(&old)
            .unwrap()
            .unwrap()
            .retire_cause,
        Some(crate::indexed_session_store::SessionRetireCause::LocalSecurityRekey)
    );
    drop(bob_store);
    // The reset step owns the backlog now (the renewer kicks the outbox).
    let mut again = p.link(Who::Bob);
    assert_eq!(
        p.step(Who::Bob, &mut again),
        RenewStep::Held(renew_code::RENEW_RESET_PENDING)
    );
    let routes = lan(LOOPBACK);
    let reset_env = crate::session_reset::ResetEnv {
        data_dir: p.dir(Who::Bob),
        identity: p.id(Who::Bob),
        peer: p.key_of(Who::Alice),
        routes: &routes,
        user_confirmed: false,
        now_ms: now(),
    };
    let mut io = p.link(Who::Bob);
    let step = crate::session_reset::run_reset_step(&reset_env, &mut io).unwrap();
    let crate::session_reset::ResetStep::Resealed(report) = step else {
        panic!("{step:?}");
    };
    assert!(io.dials.is_empty(), "the new session is the target");
    assert_eq!(
        report
            .resealed
            .iter()
            .map(|r| r.message_id)
            .collect::<Vec<_>>(),
        vec![m1]
    );
    assert_eq!(report.resealed[0].new.session_id, new);
    let acks = dispatch_frame(
        p.dir(Who::Alice),
        p.id(Who::Alice),
        p.bundle(Who::Bob),
        &p.key_of(Who::Bob),
        &report.resealed[0].new.immutable_envelope_bytes,
    )
    .unwrap();
    assert_eq!(acks.len(), 1);
    let (key, m2) = p.seal(Who::Bob, "after the re-key");
    assert_eq!(key, s2);
    p.deliver(Who::Bob, &key, &m2);
    let inbox: Vec<Vec<u8>> = IndexedSessionStore::open(p.dir(Who::Alice))
        .unwrap()
        .list_endpoint_inbox()
        .unwrap()
        .into_iter()
        .map(|row| row.plaintext)
        .collect();
    let once = inbox
        .iter()
        .filter(|text| text.as_slice() == b"waits in the old session")
        .count();
    assert_eq!(once, 1, "re-sealed and delivered once");
    assert!(inbox.contains(&b"after the re-key".to_vec()));
}

/// This thread's clock `offset` ms on (`crate::clock`'s test override),
/// back to the system clock on drop.
struct ClockAhead;

impl ClockAhead {
    fn by(offset: u64) -> Self {
        crate::clock::set_for_this_thread(Some(i64::try_from(offset).unwrap()));
        Self
    }
}

impl Drop for ClockAhead {
    fn drop(&mut self) {
        crate::clock::set_for_this_thread(None);
    }
}

/// Phase 6 review (sensing-1): Bob's early re-key retires s1, the session
/// Alice started, while two of her messages sealed in it have not reached
/// him yet (they wait at a friend's, say). He takes the first within the
/// ten minutes; his ACK to it is still on its way to her. Past the ten
/// minutes he refuses the second and answers her SESSION_QUERY about it
/// NO_SESSION (it said PRESENT: she kept the copy until it was given up as
/// superseded, and the message was lost). She retires s1; his late ACK
/// settles the first and is no fork evidence (it was made before she
/// retired s1); her reset step re-seals the second into a new session,
/// where Bob takes it once.
#[test]
fn a_message_sealed_before_an_early_rekey_comes_back_after_the_close() {
    use crate::indexed_session_store::SessionRetireCause;
    use crate::session_renewal::EARLY_OLD_ACCEPT_MS;
    use crate::session_reset::{
        apply_query_replies, run_reset_step, session_query_frame, QueryOutcome, ResetEnv,
        ResetStep, SessionStatusCode,
    };
    let _gate = RenewGate::on();
    let _reset = ResetGate::on();
    let Some(_responses) = Responses::on() else {
        return;
    };
    let p = pair(0xbd, 20 * HOUR_MS);
    let (alice, bob) = (p.key_of(Who::Alice), p.key_of(Who::Bob));
    let (s1, first) = p.staged(Who::Alice, "taken in the ten minutes");
    let (_, second) = p.staged(Who::Alice, "waits at a friend's");
    // Bob's early re-key: a new session, and s1 retired for a security
    // re-key.
    let mut store = IndexedSessionStore::open(p.dir(Who::Bob)).unwrap();
    assert!(request_early(&mut store, &alice, SecKind::ObjectAuthFail, now()).unwrap());
    drop(store);
    let mut link = p.link(Who::Bob);
    assert!(matches!(
        p.step(Who::Bob, &mut link),
        RenewStep::Renewed {
            role: Role::Early,
            ..
        }
    ));
    let mut store = IndexedSessionStore::open(p.dir(Who::Bob)).unwrap();
    let s1_id = store.session_id_for_record_key(&s1).unwrap();
    assert_eq!(
        store
            .session_reset_info(&s1_id)
            .unwrap()
            .unwrap()
            .retire_cause,
        Some(SessionRetireCause::LocalSecurityRekey)
    );
    drop(store);
    let to_bob = |packed: &[u8]| {
        dispatch_frame(
            p.dir(Who::Bob),
            p.id(Who::Bob),
            p.bundle(Who::Alice),
            &alice,
            packed,
        )
    };
    let query = |packed: &[u8]| {
        let frame = session_query_frame(p.id(Who::Alice), &bob, packed, now()).unwrap();
        let replies = to_bob(&frame).unwrap();
        (status_of(&replies[0]).0, replies)
    };
    // Five minutes on: s1 still takes her objects, and a query about the
    // second finds it.
    let five = ClockAhead::by(5 * MIN_MS);
    let late_ack = to_bob(&first).unwrap().remove(0);
    assert_eq!(query(&second).0, SessionStatusCode::Present);
    drop(five);
    // Past the ten minutes: the second is refused, and the query about it
    // finds no session.
    let _late = ClockAhead::by(EARLY_OLD_ACCEPT_MS + MIN_MS);
    assert!(to_bob(&second).is_err());
    let (status, replies) = query(&second);
    assert_eq!(status, SessionStatusCode::NoSession);
    let mut a_store = IndexedSessionStore::open(p.dir(Who::Alice)).unwrap();
    let outcome =
        apply_query_replies(&mut a_store, &alice, &bob, &second, &replies, now()).unwrap();
    assert!(
        matches!(
            outcome,
            QueryOutcome::Retired {
                cause: SessionRetireCause::PeerNoSession,
                ..
            }
        ),
        "{outcome:?}"
    );
    // Bob's ACK to the first comes late (a friend held it): it settles the
    // first, and it is no fork evidence.
    let _later = ClockAhead::by(EARLY_OLD_ACCEPT_MS + 5 * MIN_MS);
    let acked = crate::outbox::accept_sealed_ack(
        p.dir(Who::Alice),
        &mut a_store,
        &s1,
        &p.bundle(Who::Bob).cert,
        &late_ack,
        OutboxCarrier::Lan,
    )
    .unwrap();
    assert_eq!(acked, Envelope::unpack(&first).unwrap().message_id);
    assert_eq!(
        a_store.peer_reset_state(&bob).unwrap().fork_evidence_at_ms,
        None
    );
    drop(a_store);
    // Her reset step re-seals the second into a new session of hers.
    let routes = lan(LOOPBACK);
    let env = ResetEnv {
        data_dir: p.dir(Who::Alice),
        identity: p.id(Who::Alice),
        peer: bob,
        routes: &routes,
        user_confirmed: false,
        now_ms: now(),
    };
    let mut io = p.link(Who::Alice);
    let step = run_reset_step(&env, &mut io).unwrap();
    let ResetStep::Resealed(report) = step else {
        panic!("{step:?}");
    };
    assert_eq!(
        report
            .resealed
            .iter()
            .map(|r| r.message_id)
            .collect::<Vec<_>>(),
        vec![Envelope::unpack(&second).unwrap().message_id]
    );
    assert_eq!(
        to_bob(&report.resealed[0].new.immutable_envelope_bytes)
            .unwrap()
            .len(),
        1
    );
    let inbox: Vec<Vec<u8>> = IndexedSessionStore::open(p.dir(Who::Bob))
        .unwrap()
        .list_endpoint_inbox()
        .unwrap()
        .into_iter()
        .map(|row| row.plaintext)
        .collect();
    for text in ["taken in the ten minutes", "waits at a friend's"] {
        let n = inbox
            .iter()
            .filter(|t| t.as_slice() == text.as_bytes())
            .count();
        assert_eq!(n, 1, "{text}");
    }
}

/// Phase 6 review re-verify (sensing-1): the same close for a contact that
/// is not on this network (its mail waits at a friend's). Bob's answer is
/// NO_SESSION, and his log says he replaced that connection in a security
/// re-key (not "RAVEN was reset here"). Alice retires s1; with no local
/// route her reset step holds the message for her (P2: Bob's own newer
/// session is no target), and her store tells that Bob replaced the
/// connection (a newer session he started, same certificate), so ash says
/// so instead of "lost ... if they reinstalled or restored RAVEN".
#[test]
fn an_early_rekey_reads_as_a_replaced_connection_on_both_sides() {
    use crate::indexed_session_store::{InboundSessionMatch, SessionRetireCause};
    use crate::session_renewal::EARLY_OLD_ACCEPT_MS;
    use crate::session_reset::{
        apply_query_replies, no_session_note, run_reset_step, session_query_frame, QueryOutcome,
        ResetEnv, ResetStep,
    };
    let _gate = RenewGate::on();
    let _reset = ResetGate::on();
    let Some(_responses) = Responses::on() else {
        return;
    };
    let p = pair(0xbe, 20 * HOUR_MS);
    let (alice, bob) = (p.key_of(Who::Alice), p.key_of(Who::Bob));
    let (_s1, waiting) = p.staged(Who::Alice, "waits at a friend's");
    let mut store = IndexedSessionStore::open(p.dir(Who::Alice)).unwrap();
    assert!(
        !store.contact_replaced_retired_session(&bob, now()).unwrap(),
        "nothing retired yet"
    );
    drop(store);
    let mut store = IndexedSessionStore::open(p.dir(Who::Bob)).unwrap();
    assert!(request_early(&mut store, &alice, SecKind::ObjectAuthFail, now()).unwrap());
    drop(store);
    let mut link = p.link(Who::Bob);
    assert!(matches!(
        p.step(Who::Bob, &mut link),
        RenewStep::Renewed {
            role: Role::Early,
            ..
        }
    ));
    let _late = ClockAhead::by(EARLY_OLD_ACCEPT_MS + MIN_MS);
    // Bob: closed by his own re-key, and his log says so.
    let found = IndexedSessionStore::open(p.dir(Who::Bob))
        .unwrap()
        .match_inbound_session_detail(&alice, &waiting, now())
        .unwrap();
    assert_eq!(found, InboundSessionMatch::ClosedByRekey);
    let note = no_session_note(true);
    assert!(note.contains("security re-key") && note.contains("nothing needs doing"));
    assert!(!note.contains("reset here"), "{note}");
    assert!(no_session_note(false).contains("reset here"));
    let frame = session_query_frame(p.id(Who::Alice), &bob, &waiting, now()).unwrap();
    let replies = dispatch_frame(
        p.dir(Who::Bob),
        p.id(Who::Bob),
        p.bundle(Who::Alice),
        &alice,
        &frame,
    )
    .unwrap();
    // Alice: s1 retired, held for her, and Bob replaced it.
    let mut a_store = IndexedSessionStore::open(p.dir(Who::Alice)).unwrap();
    let outcome =
        apply_query_replies(&mut a_store, &alice, &bob, &waiting, &replies, now()).unwrap();
    assert!(
        matches!(
            outcome,
            QueryOutcome::Retired {
                cause: SessionRetireCause::PeerNoSession,
                ..
            }
        ),
        "{outcome:?}"
    );
    drop(a_store);
    let routes = lan("203.0.113.5:7420");
    let env = ResetEnv {
        data_dir: p.dir(Who::Alice),
        identity: p.id(Who::Alice),
        peer: bob,
        routes: &routes,
        user_confirmed: false,
        now_ms: now(),
    };
    let mut io = p.link(Who::Alice);
    let step = run_reset_step(&env, &mut io).unwrap();
    assert!(
        matches!(
            step,
            ResetStep::Held {
                code: "PEER_RESET_CONFIRM",
                rows: 1
            }
        ),
        "{step:?}"
    );
    assert!(IndexedSessionStore::open(p.dir(Who::Alice))
        .unwrap()
        .contact_replaced_retired_session(&bob, now())
        .unwrap());
}

/// Phase 6 review (sensing-1): with the reset step shut, nobody can ask
/// Bob about what Alice sealed in s1 (no SESSION_QUERY), so his early
/// re-key renews but retires nothing: s1 takes her objects until it ends,
/// as after any renewal.
#[test]
fn an_early_rekey_retires_nothing_while_the_reset_step_is_shut() {
    let _gate = RenewGate::on();
    let Some(_responses) = Responses::on() else {
        return;
    };
    let p = pair(0xbf, 20 * HOUR_MS);
    let alice = p.key_of(Who::Alice);
    let (s1, waiting) = p.seal(Who::Alice, "sealed in the old session");
    let mut store = IndexedSessionStore::open(p.dir(Who::Bob)).unwrap();
    assert!(request_early(&mut store, &alice, SecKind::ObjectReplay, now()).unwrap());
    drop(store);
    let mut link = p.link(Who::Bob);
    assert!(matches!(
        p.step(Who::Bob, &mut link),
        RenewStep::Renewed {
            role: Role::Early,
            ..
        }
    ));
    let mut store = IndexedSessionStore::open(p.dir(Who::Bob)).unwrap();
    let s1_id = store.session_id_for_record_key(&s1).unwrap();
    assert_eq!(
        store
            .session_reset_info(&s1_id)
            .unwrap()
            .and_then(|info| info.retire_cause),
        None
    );
    drop(store);
    let _late = ClockAhead::by(crate::session_renewal::EARLY_OLD_ACCEPT_MS + MIN_MS);
    p.deliver(Who::Alice, &s1, &waiting);
}

/// The early re-key draws on the shared re-pair budget: with the day's
/// rounds spent it waits for the window to roll (the request stays), then
/// renews. With the responses gate shut nothing is noted and nothing renews
/// early.
#[test]
fn an_early_rekey_waits_for_the_budget_and_needs_the_responses_gate() {
    let _gate = RenewGate::on();
    let p = pair(0xb3, 20 * HOUR_MS);
    let alice = p.key_of(Who::Alice);
    let at = now();
    {
        let _shut = Shut::start();
        let mut store = IndexedSessionStore::open(p.dir(Who::Bob)).unwrap();
        assert!(!request_early(&mut store, &alice, SecKind::ObjectAuthFail, at).unwrap());
        drop(store);
        assert_eq!(
            p.renewal_state(Who::Bob),
            crate::indexed_session_store::PeerRenewalState::default()
        );
        let mut link = p.link(Who::Bob);
        assert!(matches!(
            p.step(Who::Bob, &mut link),
            RenewStep::NotDue { .. }
        ));
        assert!(link.dials.is_empty());
    }
    let Some(_responses) = Responses::on() else {
        return;
    };
    // The day's rounds went to renewals (or the horizon's re-pair).
    let window = at - 20 * HOUR_MS;
    let mut store = IndexedSessionStore::open(p.dir(Who::Bob)).unwrap();
    for n in 0..u64::from(REPAIR_MAX_PER_DAY) {
        store
            .begin_repair_attempt(&alice, window + n * 2 * MIN_MS)
            .unwrap()
            .unwrap();
    }
    assert!(request_early(&mut store, &alice, SecKind::IndexJump, at).unwrap());
    drop(store);
    let mut link = p.link(Who::Bob);
    assert_eq!(
        p.step_at(Who::Bob, &mut link, &lan(LOOPBACK), true, None, at),
        RenewStep::Wait {
            until_ms: window + DAY_MS,
            code: renew_code::RENEW_DAILY_CAP
        }
    );
    assert!(link.dials.is_empty());
    assert_eq!(p.renewal_state(Who::Bob).early_requested_at_ms, Some(at));
    let mut link = p.link(Who::Bob);
    assert!(matches!(
        p.step_at(
            Who::Bob,
            &mut link,
            &lan(LOOPBACK),
            true,
            None,
            window + DAY_MS
        ),
        RenewStep::Renewed {
            role: Role::Early,
            ..
        }
    ));
    assert_eq!(p.renewal_state(Who::Bob).early_requested_at_ms, None);
}

/// R3: this computer's protected session state is put back to an older
/// copy (a backup restore) -> the store refuses it as a rollback
/// (SEC_LOCAL_ROLLBACK about this computer) -> the prekey is rotated now
/// and an early re-key is noted for each contact with a live session, both
/// of Alice's (the one whose state rolled back included), once per 6 h.
/// The rolled-back contact's next step renews though no session is left to
/// send in.
#[test]
fn a_restored_older_protected_state_rotates_the_prekey_and_asks_every_live_peer() {
    let _gate = RenewGate::on();
    let Some(responses) = Responses::on() else {
        return;
    };
    let p = pair(0xb5, 20 * HOUR_MS);
    let carol = Identity::from_seed(&[0xb9; 32]);
    let c_dir = tempfile::tempdir().unwrap();
    publish_and_install(c_dir.path(), &carol);
    confirm_alice_to_bob(p.dir(Who::Alice), c_dir.path(), p.id(Who::Alice), &carol);
    let a_dir = p.dir(Who::Alice);
    // Alice's book holds both again (the helper writes one contact).
    let book = serde_json::json!([
        {"petname": "Bob", "pub_hex": hex::encode(p.key_of(Who::Bob)), "address": ""},
        {"petname": "Carol", "pub_hex": hex::encode(carol.public_key_bytes()), "address": ""},
    ]);
    std::fs::write(
        a_dir.join("contacts.json"),
        serde_json::to_string_pretty(&book).unwrap(),
    )
    .unwrap();
    let secrets = a_dir.join("indexed-session-secrets");
    let copy: Vec<(std::path::PathBuf, Vec<u8>)> = std::fs::read_dir(&secrets)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    assert_eq!(copy.len(), 2, "one protected state per session");
    // Alice's state with Bob moves on, then the older copy is put back.
    p.seal(Who::Alice, "moves the state on");
    for (path, bytes) in &copy {
        std::fs::write(path, bytes).unwrap();
    }
    let (_, packed) = p.seal(Who::Bob, "finds the rollback");
    assert!(dispatch_frame(
        a_dir,
        p.id(Who::Alice),
        p.bundle(Who::Bob),
        &p.key_of(Who::Bob),
        &packed
    )
    .is_err());
    assert!(responses.0.kinds().contains(&(
        SecKind::LocalRollback,
        Attribution::Local,
        Via::Local
    )));
    // What raven-node's responder does for it.
    let before = local_bundle(a_dir, p.id(Who::Alice))
        .unwrap()
        .prekey
        .signed_prekey_id;
    rotate_local_prekey_now(a_dir, p.id(Who::Alice), "SEC_LOCAL_ROLLBACK").unwrap();
    let after = local_bundle(a_dir, p.id(Who::Alice))
        .unwrap()
        .prekey
        .signed_prekey_id;
    assert!(after > before, "{before} -> {after}");
    let alice = p.key_of(Who::Alice);
    let mut store = IndexedSessionStore::open(a_dir).unwrap();
    let mut asked =
        request_early_for_live_peers(&mut store, &alice, SecKind::LocalRollback, now()).unwrap();
    asked.sort();
    let mut both = vec![p.key_of(Who::Bob), carol.public_key_bytes()];
    both.sort();
    assert_eq!(asked, both);
    assert!(
        request_early_for_live_peers(&mut store, &alice, SecKind::LocalRollback, now())
            .unwrap()
            .is_empty(),
        "once per 6 h"
    );
    assert_eq!(
        store
            .peer_renewal_state(&p.key_of(Who::Bob))
            .unwrap()
            .early_reason,
        Some(SecKind::LocalRollback.code())
    );
    drop(store);
    // Bob's session with Alice is unreadable on her side now: the early
    // re-key still renews it, and the new session carries messages again.
    let mut link = p.link(Who::Alice);
    assert!(matches!(
        p.step(Who::Alice, &mut link),
        RenewStep::Renewed {
            role: Role::Early,
            ..
        }
    ));
    let (key, packed) = p.seal(Who::Bob, "after the recovery");
    assert_eq!(key, p.newest(Who::Alice).unwrap().0);
    p.deliver(Who::Bob, &key, &packed);
}

/// Acceptance (OD6b-6, "never auto-block"): the security modules and
/// session renewal never block, unpin or remove a contact: none of them
/// names the block list, a contact book writer or a pin removal (raven-node
/// checks its own `security.rs` and `renewal.rs` the same way).
#[test]
fn security_and_renewal_never_block_unpin_or_remove_a_contact() {
    const SOURCES: [(&str, &str); 7] = [
        (
            "security_events.rs",
            include_str!("../../security_events.rs"),
        ),
        ("security_gate.rs", include_str!("../../security_gate.rs")),
        (
            "security_ledger.rs",
            include_str!("../../security_ledger.rs"),
        ),
        ("security_sense.rs", include_str!("../../security_sense.rs")),
        (
            "session_renewal.rs",
            include_str!("../../session_renewal.rs"),
        ),
        (
            "indexed_session_store/renewal.rs",
            include_str!("../../indexed_session_store/renewal.rs"),
        ),
        (
            "indexed_session_store/reset.rs",
            include_str!("../../indexed_session_store/reset.rs"),
        ),
    ];
    for (file, source) in SOURCES {
        for needle in NEVER_BLOCK_UNPIN_OR_REMOVE {
            assert!(!source.contains(needle), "{file} names {needle}");
        }
    }
}

/// What blocking, unpinning or removing a contact would have to name.
const NEVER_BLOCK_UNPIN_OR_REMOVE: [&str; 8] = [
    "BlockList",
    ".block(",
    "contact_book::write_rows",
    "contact_book::lock(",
    "forget_peer_prekey_pin",
    "pinned = false",
    "save_contact",
    "remove_contact",
];
