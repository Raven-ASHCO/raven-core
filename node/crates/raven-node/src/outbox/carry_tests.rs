//! Carry choice in the worker (Phase 6a P6.16, design §7) over real profile
//! folders: the letters rig (`crate::letters::tests::World`: Alice, Bob, and
//! Carol and Dave, the friends both list as custodians), every frame to the
//! real handlers, with a learning service of the test's own on Alice's
//! folder (learning on; friend custody live and in use, as Alice lists Carol
//! and Dave for Bob). The gates open through this thread's debug overrides,
//! which release builds ignore: these tests return early there. Custody
//! parks, windows and the letters capability cache are process-wide, keyed
//! by key, and the one-byte identity seeds are nearly all taken in this
//! crate (this file's 0x26.., 0x2a.., 0x36.., 0x3a.., 0x3e and 0xf0.. keys
//! overlap outbox's Learned and the handoff tests' fixtures), so the
//! base-deposit tests hold the letters ([`CustodyOn`], as outbox's
//! LearnedGates and custody's Gates do).

use super::*;
use crate::learning::TestService;
use crate::letters::tests::{LettersOn, World};
use crate::outbox::test_rig::lab_backends;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use raven_core::custody_client::PlanStep;
use raven_core::custody_gate::{
    set_carrier_gates_for_this_thread, set_custody_gates_for_this_thread,
    set_custody_hints_for_this_thread, CustodyGates,
};
use raven_core::friend_custody::{OP_DEPOSIT, OP_DEPOSIT_LETTER};
use std::sync::atomic::Ordering;

const HOUR: u64 = 3_600_000;

/// Friend custody live on this thread over LAN (the base deposit: no
/// letters, no handoff); closed again on drop.
struct CustodyOn {
    _lan: crate::lan_direct::LanSwitchUntouched,
}

impl CustodyOn {
    fn new() -> Self {
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: true,
            wan: false,
        }));
        set_carrier_gates_for_this_thread(Some(CarrierGates {
            lan: true,
            internet: false,
            p2p: false,
            nearby: false,
            onion: false,
        }));
        raven_core::horizon::set_lab_letter_for_this_thread(Some(false));
        Self {
            _lan: crate::lan_direct::lan_switch_untouched(),
        }
    }
}

impl Drop for CustodyOn {
    fn drop(&mut self) {
        raven_core::horizon::set_lab_letter_for_this_thread(None);
        set_custody_hints_for_this_thread(None);
        set_carrier_gates_for_this_thread(None);
        set_custody_gates_for_this_thread(None);
    }
}

/// Learning on for Alice with carry choice live: custody in use (she lists
/// Carol and Dave for Bob) and every one of them a verified contact.
fn carry_on(w: &World) -> TestService {
    let t = TestService::loaded(w.a.path(), None);
    t.set_carry(true, &[w.bob_pub, w.carol_pub, w.dave_pub]);
    t
}

/// An authenticated link with `who`, as `custody::peer_seen` hears of one
/// (a trusted inbound link, a beacon answer), applied.
fn met(t: &mut TestService, who: &[u8; 32]) {
    crate::custody::peer_seen(who);
    t.drain();
}

/// The custodians Alice's dials so far carried `op` to, first dialled
/// first, each once.
fn left_with(w: &World, op: u8) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = Vec::new();
    for (key, ops) in w.net.log.lock().unwrap().iter() {
        let key: [u8; 32] = hex::decode(key).unwrap().try_into().unwrap();
        if ops.contains(&op) && !out.contains(&key) {
            out.push(key);
        }
    }
    out
}

/// `holder`'s carry row for `recipient`: (success, failure) evidence.
fn carry_row(t: &TestService, holder: &[u8; 32], recipient: &[u8; 32]) -> Option<(u32, u32)> {
    t.model()
        .unwrap()
        .carry_of(holder, recipient)
        .map(|r| (r.beta.a_m, r.beta.b_m))
}

fn only(report: &PeerReport) -> Outcome {
    assert_eq!(report.outcomes.len(), 1, "{:?}", report.outcomes);
    report.outcomes.values().next().unwrap().clone()
}

/// The custodians the worker uses for Bob now, and why.
fn picked(w: &World) -> (CustodySet, Option<CarryChoice>) {
    custodians_for(w.a.path(), &w.alice_pub, &w.bob_pub, now_ms())
}

/// Nothing learned yet: the static choice (`deposit_custodians`, book
/// order), the same as with learning off, and the worker leaves the message
/// with Carol, then Dave.
#[test]
fn cold_carry_picks_are_static() {
    if !lab_backends() {
        return;
    }
    let _on = CustodyOn::new();
    let w = World::new(0xf0, true, true);
    let today = raven_core::custody_client::deposit_custodians(
        w.a.path(),
        &w.alice_pub,
        &w.bob_pub,
        now_ms(),
    );
    assert_eq!(today, [(w.carol_pub, None), (w.dave_pub, None)]);
    let (set, carry) = picked(&w);
    assert_eq!(set, today);
    assert!(carry.is_none(), "learning off: today's choice");
    let _t = carry_on(&w);
    let (set, carry) = picked(&w);
    assert_eq!(set, today);
    let carry = carry.expect("carry choice is live");
    assert_eq!(carry.why, Why::Cold);
    assert_eq!(carry.candidates, [w.carol_pub, w.dave_pub]);
    w.stage("cold");
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 2 });
    assert_eq!(left_with(&w, OP_DEPOSIT), [w.carol_pub, w.dave_pub]);
}

/// Alice met Dave (Carol never): Dave goes first, before the book's order,
/// in the plan and in the dials, and the record names him first.
#[test]
fn a_frequently_met_carrier_is_picked_over_book_order() {
    if !lab_backends() {
        return;
    }
    let _on = CustodyOn::new();
    let w = World::new(0xf4, true, true);
    let mut t = carry_on(&w);
    met(&mut t, &w.dave_pub);
    let (set, carry) = picked(&w);
    assert_eq!(set, [(w.dave_pub, None), (w.carol_pub, None)]);
    assert_eq!(carry.unwrap().why, Why::Faster);
    let mid = w.stage("Dave first");
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 2 });
    assert_eq!(left_with(&w, OP_DEPOSIT), [w.dave_pub, w.carol_pub]);
    let records = object_route_records(w.a.path(), now_ms()).unwrap();
    assert_eq!(
        records[&mid].custodians_held,
        [hex::encode(w.dave_pub), hex::encode(w.carol_pub)]
    );
    // Not again: both hold it.
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 2 });
    assert_eq!(
        (w.objects_at(w.carol_pub), w.objects_at(w.dave_pub)),
        (1, 1)
    );
}

/// Picks are at most two, distinct, each a candidate with its own offer,
/// whatever was learned; and an object already held by two of the
/// candidates gets no third copy, while one whose holder is no candidate
/// any more (unverified since) goes to the next candidate.
#[test]
fn picks_never_exceed_two_and_never_leave_the_candidates() {
    if !lab_backends() {
        return;
    }
    let _on = CustodyOn::new();
    // The pick itself, over random encounters, outcomes and candidates.
    {
        let dir = tempfile::tempdir().unwrap();
        let mut t = TestService::loaded(dir.path(), None);
        let pool: Vec<[u8; 32]> = (1..=10u8).map(|i| [i; 32]).collect();
        t.set_carry(true, &pool);
        let bob = [0xB0; 32];
        let mut rng = StdRng::seed_from_u64(0x0ca2);
        let mut at = 1_800_000_000_000u64;
        for round in 0..300 {
            at += rng.gen_range(0..6 * HOUR);
            t.set_now(at);
            let f = pool[rng.gen_range(0..pool.len())];
            if rng.gen_bool(0.5) {
                crate::learning::encounter(&f);
            } else {
                let g = pool[rng.gen_range(0..pool.len())];
                crate::learning::carry_outcome(&bob, &[f, g], rng.gen_bool(0.5));
            }
            t.drain();
            let cands: Vec<([u8; 32], Option<u8>)> = (0..rng.gen_range(0..=8))
                .map(|_| {
                    let key = pool[rng.gen_range(0..pool.len())];
                    (key, rng.gen_bool(0.5).then_some(0x01))
                })
                .collect();
            let mut distinct: Vec<([u8; 32], Option<u8>)> = Vec::new();
            for c in &cands {
                if !distinct.iter().any(|(k, _)| *k == c.0) {
                    distinct.push(*c);
                }
            }
            let (pick, _) = crate::learning::carry_pick(&bob, &cands).expect("live");
            assert_eq!(pick.len(), distinct.len().min(CARRY_CAP), "{round}");
            assert!(pick.iter().all(|p| distinct.contains(p)), "{round}");
            assert!(pick.len() < 2 || pick[0].0 != pick[1].0, "{round}");
        }
    }
    // The copy cap in the worker. Alice uses friends as mailboxes and Bob
    // announced Carol, Dave and Erin (each offers custody): three
    // candidates. Carol and Erin hold the message already; Alice met Dave.
    set_custody_hints_for_this_thread(Some(true));
    let w = World::new(0xf8, true, true);
    let erin = bob_names_three(&w);
    let book = |erin_verified: bool| three_book(&w, &erin, erin_verified);
    let mut t = TestService::loaded(w.a.path(), None);
    t.set_carry(true, &[w.bob_pub, w.carol_pub, w.dave_pub, erin]);
    met(&mut t, &w.dave_pub);
    let (set, carry) = picked(&w);
    assert_eq!(set, [(w.dave_pub, Some(1)), (w.carol_pub, Some(1))]);
    let carry = carry.unwrap();
    assert_eq!(carry.candidates, [w.carol_pub, w.dave_pub, erin]);
    let mid = w.stage("two copies at most");
    raven_core::outbox::add_object_custodians(w.a.path(), &mid, &[erin, w.carol_pub], now_ms())
        .unwrap();
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 2 });
    assert!(left_with(&w, OP_DEPOSIT).is_empty(), "no third copy");
    assert_eq!(w.objects_at(w.dave_pub), 0);
    // Erin is no verified contact any more: her copy does not count, and
    // the next candidate (Dave, picked) takes one.
    book(false);
    assert_eq!(picked(&w).1.unwrap().candidates, [w.carol_pub, w.dave_pub]);
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 3 });
    assert_eq!(left_with(&w, OP_DEPOSIT), [w.dave_pub]);
    assert_eq!(
        (w.objects_at(w.dave_pub), w.objects_at(w.carol_pub)),
        (1, 0)
    );
}

/// Alice's contact book for [`bob_names_three`]: Bob (Alice lists Carol
/// and Dave for him), Carol and Dave verified, Erin verified or not.
fn three_book(w: &World, erin: &[u8; 32], erin_verified: bool) {
    let row = |key: &[u8; 32], pinned: bool, custodians: &[[u8; 32]]| {
        serde_json::json!({
            "petname": hex::encode(&key[..4]),
            "pub_hex": hex::encode(key),
            "pinned": pinned,
            "lan_dial": "192.168.1.50:7420",
            "custodians": custodians.iter().map(hex::encode).collect::<Vec<_>>(),
        })
    };
    let rows = serde_json::json!([
        row(&w.bob_pub, true, &[w.carol_pub, w.dave_pub]),
        row(&w.carol_pub, true, &[]),
        row(&w.dave_pub, true, &[]),
        row(erin, erin_verified, &[]),
    ]);
    std::fs::write(w.a.path().join("contacts.json"), rows.to_string()).unwrap();
}

/// Alice uses friends as mailboxes and Bob announced Carol and Dave (by
/// tag) and Erin (by Phase 2's plain key; RRH1 names at most two by tag),
/// each offering custody: three candidates for Bob's mail, of which today's
/// choice (`deposit_custodians`) takes the first two. Needs learned custody
/// live on the thread. Returns Erin's key.
fn bob_names_three(w: &World) -> [u8; 32] {
    let erin = Identity::from_seed(&[0x3e; 32]).public_key_bytes();
    three_book(w, &erin, true);
    raven_core::save_policy(
        w.a.path(),
        &raven_core::NodePolicy {
            custody_use: Some(true),
            ..Default::default()
        },
    )
    .unwrap();
    let t0 = now_ms();
    let told = |key: &[u8; 32], extra: serde_json::Value| {
        let mut row = serde_json::json!({
            "pub_hex": hex::encode(key),
            "generation": t0,
            "received_at_ms": t0,
            "expires_at_ms": t0 + 600_000,
            "via": "lan",
        });
        for (k, v) in extra.as_object().unwrap() {
            row[k] = v.clone();
        }
        row
    };
    let tags: Vec<String> = [w.carol_pub, w.dave_pub]
        .iter()
        .map(|c| {
            hex::encode(raven_core::route_hints::custodian_tag(
                &w.bob_pub,
                &w.alice_pub,
                c,
            ))
        })
        .collect();
    let rows = serde_json::json!([
        told(
            &w.bob_pub,
            serde_json::json!({
                "custodian_tags": tags,
                "custodian_tag_flags": [0, 0],
                "custodians": [hex::encode(erin)],
            })
        ),
        told(&w.carol_pub, serde_json::json!({"custody_offer": 1})),
        told(&w.dave_pub, serde_json::json!({"custody_offer": 1})),
        told(&erin, serde_json::json!({"custody_offer": 1})),
    ]);
    std::fs::write(
        w.a.path()
            .join(raven_core::learned_routes::LEARNED_ROUTES_FILE),
        rows.to_string(),
    )
    .unwrap();
    erin
}

/// Phase 5 P5.33 under carry choice: an encounter with a custodian makes
/// due the waiting contacts whose mail the worker may leave with it. With
/// carry choice live that is any contact it is a candidate of (meeting it
/// is what raises it in carry choice's pick), not only one whose first two
/// in book order (today's choice) name it.
#[test]
fn an_encounter_kicks_whom_carry_choice_may_leave_mail_with() {
    if !lab_backends() {
        return;
    }
    let _on = CustodyOn::new();
    set_custody_hints_for_this_thread(Some(true));
    let w = World::new(0x2a, true, true);
    let erin = bob_names_three(&w);
    let wall = now_ms();
    let kicked = |custodian: &[u8; 32]| {
        crate::custody::carried_from(
            w.a.path(),
            &w.alice_pub,
            custodian,
            |_| vec![w.carol_pub, w.bob_pub],
            wall,
        )
    };
    let t = TestService::loaded(w.a.path(), None);
    // Carry choice not live: today's choice, Carol and Dave.
    t.set_carry(false, &[w.bob_pub, w.carol_pub, w.dave_pub, erin]);
    assert_eq!(kicked(&w.carol_pub), [w.bob_pub]);
    assert!(kicked(&erin).is_empty());
    // Live: Erin is one of Bob's candidates too.
    t.set_carry(true, &[w.bob_pub, w.carol_pub, w.dave_pub, erin]);
    assert_eq!(kicked(&w.carol_pub), [w.bob_pub]);
    assert_eq!(kicked(&erin), [w.bob_pub]);
    // Never the custodian itself, nor for a custodian of nobody.
    assert!(kicked(&w.bob_pub).is_empty());
    assert!(kicked(&[0x77; 32]).is_empty());
}

/// Carry choice changes who, never when: a message younger than 60 s is not
/// left with anyone, one Bob can take directly is delivered and never left,
/// and one two minutes old whose direct try failed goes to Dave first.
#[test]
fn deposit_timing_is_unchanged_60s_and_failed_direct_try() {
    if !lab_backends() {
        return;
    }
    let _on = CustodyOn::new();
    let w = World::new(0xfc, true, true);
    let mut t = carry_on(&w);
    met(&mut t, &w.dave_pub);
    w.stage_at("too young", now_ms() - 30_000);
    let report = w.attempt();
    assert!(
        matches!(only(&report), Outcome::Unreachable { .. }),
        "{:?}",
        report.outcomes
    );
    assert!(left_with(&w, OP_DEPOSIT).is_empty());
    w.net.bob_down.store(false, Ordering::SeqCst);
    assert!(matches!(only(&w.attempt()), Outcome::Delivered { .. }));
    assert!(left_with(&w, OP_DEPOSIT).is_empty(), "delivered directly");
    w.net.bob_down.store(true, Ordering::SeqCst);
    w.stage("old enough");
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 2 });
    assert_eq!(left_with(&w, OP_DEPOSIT), [w.dave_pub, w.carol_pub]);
    // A delivery of a message no friend held is no carry evidence.
    let model = t.model().unwrap();
    assert!(model.carry_of(&w.dave_pub, &w.bob_pub).is_none());
    assert!(model.carry_of(&w.carol_pub, &w.bob_pub).is_none());
}

/// A message's holders share each outcome: a delivery +1000/|H| each, a
/// message whose time ran out (expired, or parked by the horizon) -1000/|H|
/// each; the holders come from the record when the attempt began and from
/// the entry's memory once the record is gone. Nothing else is evidence:
/// a message still waiting, given up or gone, an ACK, a message no friend
/// held, or anything while carry choice is not live.
#[test]
fn receipts_and_expiries_credit_holders_by_share() {
    let _on = CustodyOn::new();
    let dir = tempfile::tempdir().unwrap();
    let mut t = TestService::loaded(dir.path(), None);
    let (bob, carol, dave) = ([0xB0; 32], [0xCA; 32], [0xDA; 32]);
    t.set_carry(true, &[bob, carol, dave]);
    t.set_now(1_800_000_000_000);
    let entry = |n: u8, kind: EndpointOutboundKind, carried: &[[u8; 32]]| {
        let row = ScanRow {
            object_digest: [n; 32],
            kind,
            session_id: [1; 32],
            message_id: [n; 16],
            recipient: bob,
            expires_at_ms: u64::MAX,
            created_at_ms: 0,
            ratchet_index: 0,
            state: EntryState::Sent,
            never_sent: false,
        };
        let mut e = Entry::from_row(&row, Instant::now());
        e.carried = carried.to_vec();
        e
    };
    let message = EndpointOutboundKind::Message;
    let attempt = |t: &mut TestService, due: &[Entry], outcomes: &[(u8, Outcome, &[[u8; 32]])]| {
        let mut report = PeerReport::default();
        for (n, outcome, held) in outcomes {
            report.outcomes.insert([*n; 32], outcome.clone());
            if !held.is_empty() {
                report.carried.insert([*n; 32], held.to_vec());
            }
        }
        carry_outcomes(&bob, due, &report);
        t.drain();
    };
    // Delivered, the record naming Carol and Dave: half each.
    attempt(
        &mut t,
        &[entry(1, message, &[])],
        &[(1, Outcome::Delivered { carrier: None }, &[carol, dave])],
    );
    assert_eq!(carry_row(&t, &carol, &bob), Some((500, 0)));
    assert_eq!(carry_row(&t, &dave, &bob), Some((500, 0)));
    // Expired, its record gone: the entry remembers both.
    attempt(
        &mut t,
        &[entry(2, message, &[carol, dave])],
        &[(2, Outcome::Expired, &[])],
    );
    assert_eq!(carry_row(&t, &carol, &bob), Some((500, 500)));
    assert_eq!(carry_row(&t, &dave, &bob), Some((500, 500)));
    // Parked by the horizon (P5.6), Dave alone held it: all of it his.
    attempt(
        &mut t,
        &[entry(3, message, &[])],
        &[(3, Outcome::Parked, &[dave])],
    );
    assert_eq!(carry_row(&t, &dave, &bob), Some((500, 1_500)));
    // No evidence: still waiting, given up, gone, an ACK, no holder.
    attempt(
        &mut t,
        &[
            entry(4, message, &[carol]),
            entry(5, message, &[carol]),
            entry(6, message, &[carol]),
            entry(7, EndpointOutboundKind::Ack, &[carol]),
            entry(8, message, &[]),
        ],
        &[
            (4, Outcome::Deposited { held: 1 }, &[carol]),
            (5, Outcome::Failed(code::SUPERSEDED), &[carol]),
            (6, Outcome::Gone, &[carol]),
            (7, Outcome::Delivered { carrier: None }, &[carol]),
            (8, Outcome::Delivered { carrier: None }, &[]),
        ],
    );
    assert_eq!(carry_row(&t, &carol, &bob), Some((500, 500)));
    assert_eq!(t.model().unwrap().sizes().carry, 2);
    // The record's holders and the entry's memory together, each once.
    attempt(
        &mut t,
        &[entry(9, message, &[dave, carol])],
        &[(9, Outcome::Delivered { carrier: None }, &[carol])],
    );
    assert_eq!(carry_row(&t, &carol, &bob), Some((1_000, 500)));
    assert_eq!(carry_row(&t, &dave, &bob), Some((1_000, 1_500)));
    // Carry choice not live (custody not in use): nothing.
    t.set_carry(false, &[bob, carol, dave]);
    attempt(
        &mut t,
        &[entry(10, message, &[])],
        &[(10, Outcome::Expired, &[carol])],
    );
    assert_eq!(carry_row(&t, &carol, &bob), Some((1_000, 500)));
}

/// Review handoff-3 under carry choice: a message a friend took to pass on
/// to the contact's own friend (custody handoff) whose time ran out was not
/// confirmed, not shown to be uncarried, so it debits nobody, whether the
/// entry remembers the forward or this attempt's report names it; its
/// receipt still credits the holders.
#[test]
fn a_forwarded_message_whose_time_ran_out_debits_nobody() {
    let _on = CustodyOn::new();
    let dir = tempfile::tempdir().unwrap();
    let mut t = TestService::loaded(dir.path(), None);
    let (bob, carol, dave) = ([0xB1; 32], [0xCB; 32], [0xDB; 32]);
    t.set_carry(true, &[bob, carol, dave]);
    t.set_now(1_800_000_000_000);
    let entry = |n: u8, forwarded: bool| {
        let row = ScanRow {
            object_digest: [n; 32],
            kind: EndpointOutboundKind::Message,
            session_id: [1; 32],
            message_id: [n; 16],
            recipient: bob,
            expires_at_ms: u64::MAX,
            created_at_ms: 0,
            ratchet_index: 0,
            state: EntryState::Sent,
            never_sent: false,
        };
        let mut e = Entry::from_row(&row, Instant::now());
        e.carried = vec![carol];
        e.custody_forwarded = forwarded;
        e
    };
    let attempt = |t: &mut TestService, due: &[Entry], outcome: Outcome, reported: bool| {
        let mut report = PeerReport::default();
        for e in due {
            report.outcomes.insert(e.object_digest, outcome.clone());
            if reported {
                report.custody_forwarded.insert(e.object_digest);
            }
        }
        carry_outcomes(&bob, due, &report);
        t.drain();
    };
    // Expired and parked, the forward remembered by the entry or named by
    // this attempt: no row at all.
    attempt(&mut t, &[entry(1, true)], Outcome::Expired, false);
    attempt(&mut t, &[entry(2, false)], Outcome::Expired, true);
    attempt(&mut t, &[entry(3, true)], Outcome::Parked, false);
    assert_eq!(carry_row(&t, &carol, &bob), None);
    // A receipt for a forwarded message still credits its holder.
    attempt(
        &mut t,
        &[entry(4, true)],
        Outcome::Delivered { carrier: None },
        true,
    );
    assert_eq!(carry_row(&t, &carol, &bob), Some((1_000, 0)));
    // Not forwarded: the expiry debits as before.
    attempt(&mut t, &[entry(5, false)], Outcome::Expired, false);
    assert_eq!(carry_row(&t, &carol, &bob), Some((1_000, 1_000)));
    assert_eq!(carry_row(&t, &dave, &bob), None);
}

/// The letter step sends letters to the same picks in the same order: Dave
/// (met) first, then Carol.
#[test]
fn letters_use_the_same_picks() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0x36, true, true);
    w.letters_known();
    let mut t = carry_on(&w);
    met(&mut t, &w.dave_pub);
    w.stage("by letter, Dave first");
    assert_eq!(only(&w.attempt()), Outcome::Resealed);
    assert_eq!(left_with(&w, OP_DEPOSIT_LETTER), [w.dave_pub, w.carol_pub]);
    assert_eq!(
        w.book(false).letters[0].held_by,
        vec![w.dave_pub, w.carol_pub]
    );
    assert_eq!((w.held_at(w.dave_pub), w.held_at(w.carol_pub)), (1, 1));
    assert!(left_with(&w, OP_DEPOSIT).is_empty(), "no base deposit");
}

/// The custody plan (`custody_plan`, handoff spec §3.5) gets the custodians
/// in carry order: book order while cold, Dave first once met.
#[test]
fn custody_plan_gets_carry_order() {
    if !lab_backends() {
        return;
    }
    let _on = CustodyOn::new();
    let w = World::new(0x3a, true, true);
    let mut t = carry_on(&w);
    let ctx = w.ctx();
    let plan = |w: &World| {
        let (set, _) = picked(w);
        custody_steps(&ctx, &w.bob_pub, &set, now_ms())
    };
    assert_eq!(
        plan(&w),
        [
            PlanStep::Deposit(w.carol_pub),
            PlanStep::Deposit(w.dave_pub)
        ]
    );
    met(&mut t, &w.dave_pub);
    assert_eq!(
        plan(&w),
        [
            PlanStep::Deposit(w.dave_pub),
            PlanStep::Deposit(w.carol_pub)
        ]
    );
}

/// s30 (via a friend, its letter form) with learning on: Bob is away,
/// Alice's message is left with Carol (met, first) and Dave; Bob takes it
/// from Carol, his ACK comes back in his REPLY letter through Carol; the
/// message is delivered exactly once, and when Alice's worker finds it
/// delivered both holders are credited.
#[test]
fn s30_still_passes_with_learning_on() {
    if !lab_backends() {
        return;
    }
    let _on = LettersOn::new();
    let w = World::new(0x26, true, true);
    w.letters_known();
    let mut t = carry_on(&w);
    met(&mut t, &w.carol_pub);
    let mid = w.stage("via-carol");
    assert_eq!(only(&w.attempt()), Outcome::Resealed);
    assert_eq!(left_with(&w, OP_DEPOSIT_LETTER), [w.carol_pub, w.dave_pub]);
    // The worker tracks the letter's copy (held by both).
    let tracked = World::due_of(w.a.path());
    assert_eq!(only(&w.attempt()), Outcome::Deposited { held: 2 });
    // Bob back: he takes it from Carol, his REPLY letter carries the ACK.
    assert_eq!(w.fetch(true, w.carol_pub).accepted, 1);
    assert_eq!(w.bob_inbox(), vec!["via-carol".to_string()]);
    w.bob_attempt();
    let fetched = w.fetch(false, w.carol_pub);
    assert_eq!((fetched.replies, fetched.acks), (1, 1));
    assert_eq!(w.history(&mid).as_deref(), Some("delivered"));
    // Alice's worker finds it delivered (its row gone): Carol and Dave
    // each get half of the receipt.
    let report = attempt_peer(&w.ctx(), &w.bob_pub, &tracked, &[]);
    assert!(
        matches!(only(&report), Outcome::Delivered { .. }),
        "{:?}",
        report.outcomes
    );
    t.drain();
    assert_eq!(carry_row(&t, &w.carol_pub, &w.bob_pub), Some((500, 0)));
    assert_eq!(carry_row(&t, &w.dave_pub, &w.bob_pub), Some((500, 0)));
    // Exactly once, and nothing left with a friend again.
    assert_eq!(w.bob_inbox(), vec!["via-carol".to_string()]);
    let before = w.net.log.lock().unwrap().len();
    w.attempt();
    assert!(w.net.log.lock().unwrap()[before..]
        .iter()
        .all(|(_, ops)| !ops.contains(&OP_DEPOSIT_LETTER) && !ops.contains(&OP_DEPOSIT)));
}
