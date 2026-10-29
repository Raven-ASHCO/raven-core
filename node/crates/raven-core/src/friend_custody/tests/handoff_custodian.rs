//! Phase 5 P5.19: the custodian's handoff handlers
//! (`protocol/RAVEN_CUSTODY_HANDOFF_V1.md` §3.1, §3.3, §3.4): FORWARD into
//! the handoff store, DELIVER into the RFC1 custody store for the tag's
//! registered recipient, TAGS REGISTER and WITHDRAW, and the dispatch from
//! `handle_frame`.
//!
//! The handlers are called directly (they need no gate: `handle_frame`
//! checks it first), except where the dispatch itself is under test.

use super::*;
use crate::custody_handoff::{
    self as handoff, HandoffStore, Rhw1, TagState, MAX_FORWARD_DEPOSITOR_ROWS,
    MAX_FORWARD_PAIR_ROWS, MAX_NODE_TAGS, MAX_TAGS_PER_MINUTE, MAX_TAGS_PER_RECIPIENT,
    MAX_TAG_TTL_MS, TAGS_WINDOWS,
};

/// Carol (`Setup::Plain` or `Setup::SealedFresh`) with custody and custody
/// handoff on; besides Alice and Bob, Erin and Frank are pinned contacts
/// (Dave is not), and so are the callers of the two window tests.
struct Hub {
    c: Carol,
    erin: Identity,
    frank: Identity,
    /// The FORWARD window test's caller ([`FORWARD_WINDOW_SEED`]).
    forward_window: Identity,
    /// The TAGS window test's caller ([`TAGS_WINDOW_SEED`]).
    tags_window: Identity,
}

/// The seeds of the fixture's identities: Carol, Alice, Bob, Dave, Erin,
/// Frank.
const HUB_SEEDS: [u8; 6] = [0xC0, 0xA0, 0xB0, 0xD0, 0xE0, 0xF0];

/// The handlers' rate windows are process-wide maps keyed by the caller,
/// and the tests run in parallel threads of one process: a test that fills
/// a window does so as a caller no other test uses, so no other test can
/// reset or fill it meanwhile (review handoff-6: the FORWARD and the TAGS
/// window tests both used Frank and raced each other).
const FORWARD_WINDOW_SEED: u8 = 0xF5;
const TAGS_WINDOW_SEED: u8 = 0xF6;

impl Hub {
    fn new(setup: Setup) -> Self {
        let dir = match setup {
            Setup::Plain => tempfile::tempdir().unwrap(),
            _ => crate::contact_book::tests::profile(),
        };
        let [carol, alice, bob, dave, erin, frank] = HUB_SEEDS.map(id);
        let (forward_window, tags_window) = (id(FORWARD_WINDOW_SEED), id(TAGS_WINDOW_SEED));
        let row = |who: &Identity, name: &str, pinned: bool| {
            format!(
                r#"{{"petname":"{name}","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":{pinned},"lan_dial":"192.168.1.9:7420","internet_dial":""}}"#,
                hex::encode(who.public_key_bytes())
            )
        };
        std::fs::write(
            dir.path().join("contacts.json"),
            format!(
                "[{},{},{},{},{},{},{}]",
                row(&alice, "Alice", true),
                row(&bob, "Bob", true),
                row(&dave, "Dave", false),
                row(&erin, "Erin", true),
                row(&frank, "Frank", true),
                row(&forward_window, "Fay", true),
                row(&tags_window, "Tom", true)
            ),
        )
        .unwrap();
        if setup != Setup::Plain {
            crate::contact_book::tests::seal(dir.path());
        }
        let hub = Hub {
            c: Carol {
                dir,
                carol,
                alice,
                bob,
                dave,
            },
            erin,
            frank,
            forward_window,
            tags_window,
        };
        hub.policy(true, true);
        hub
    }

    fn dir(&self) -> &Path {
        self.c.dir.path()
    }

    fn policy(&self, custody: bool, custody_handoff: bool) {
        let policy = crate::node_policy::NodePolicy {
            custody,
            custody_handoff,
            ..Default::default()
        };
        crate::node_policy::save_policy(self.dir(), &policy).unwrap();
    }

    fn forward(&self, from: &Identity, next_hop: &[u8; 32], rso1: Vec<u8>) -> CustodyCode {
        fresh(&from.public_key_bytes());
        let (code, _) = handoff::forward(
            self.dir(),
            &self.c.carol,
            &from.public_key_bytes(),
            &Rhw1::forward(*next_hop, rso1),
            NOW,
        );
        code
    }

    fn deliver(&self, from: &Identity, rso1: Vec<u8>) -> CustodyCode {
        fresh(&from.public_key_bytes());
        let (code, _) = handoff::deliver(
            self.dir(),
            &self.c.carol,
            &from.public_key_bytes(),
            &Rhw1::deliver(rso1),
            NOW,
        );
        code
    }

    fn tags(
        &self,
        who: &[u8; 32],
        action: TagsAction,
        entries: &[([u8; 16], u64)],
    ) -> (CustodyCode, u8, u8) {
        fresh(who);
        match handoff::tags(self.dir(), who, action, entries, NOW) {
            Rfc1Reply::TagsResult {
                code,
                accepted,
                conflicts,
            } => (code, accepted, conflicts),
            other => panic!("{other:?}"),
        }
    }

    fn register(&self, who: &Identity, tag: u8) -> (CustodyCode, u8, u8) {
        self.tags(
            &who.public_key_bytes(),
            TagsAction::Register,
            &[([tag; 16], NOW + HOUR)],
        )
    }

    fn handoff_file(&self) -> bool {
        handoff::handoff_db_path(self.dir()).exists()
    }

    fn store(&self) -> HandoffStore {
        HandoffStore::open_existing(self.dir()).unwrap().unwrap()
    }
}

/// Every per-key window this module's handlers charge, for `key`.
fn fresh(key: &[u8; 32]) {
    fresh_windows(key);
    if let Some(map) = TAGS_WINDOWS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
    {
        map.remove(key);
    }
}

fn pk(who: &Identity) -> [u8; 32] {
    who.public_key_bytes()
}

// ── FORWARD (spec §3.1) ──────────────────────────────────────────────────

/// Every refusal before the store, in a plain and a sealed profile: none
/// creates the store; then STORED, DUPLICATE, a second next hop, a third
/// one QUOTA, and CONFLICT under another tag.
#[test]
fn forward_checks_in_order_and_the_store_rules() {
    for setup in [Setup::Plain, Setup::SealedFresh] {
        let h = Hub::new(setup);
        let c = &h.c;
        let env = envelope(&c.alice, 1);
        let rso1 = rso1_for(&env, 0x11);
        // POLICY_DENIED: handoff off, and custody off.
        h.policy(true, false);
        assert_eq!(
            h.forward(&c.alice, &pk(&c.bob), rso1.clone()),
            CustodyCode::PolicyDenied
        );
        h.policy(false, true);
        assert_eq!(
            h.forward(&c.alice, &pk(&c.bob), rso1.clone()),
            CustodyCode::PolicyDenied
        );
        h.policy(true, true);
        // MALFORMED: not an RSO1.
        assert_eq!(
            h.forward(&c.alice, &pk(&c.bob), vec![0x5A; 200]),
            CustodyCode::Malformed
        );
        // HOP_REFUSED: Alice asks for a further hop of Bob's object (a
        // forwarder re-forwarding).
        let by_bob = envelope(&c.bob, 2);
        assert_eq!(
            h.forward(&c.alice, &pk(&h.erin), rso1_for(&by_bob, 0x12)),
            CustodyCode::HopRefused
        );
        // NEXT_HOP_UNKNOWN: the depositor, Carol herself, Dave (not
        // pinned), a stranger.
        for next_hop in [pk(&c.alice), pk(&c.carol), pk(&c.dave), [0x77; 32]] {
            assert_eq!(
                h.forward(&c.alice, &next_hop, rso1.clone()),
                CustodyCode::NextHopUnknown,
                "{setup:?}"
            );
        }
        // REFUSED_OBJECT: non-canonical hop fields.
        let mut hop = envelope(&c.alice, 3);
        hop.hop_limit = 7;
        hop.sign_with(&c.alice);
        assert_eq!(
            h.forward(&c.alice, &pk(&c.bob), rso1_for(&hop, 0x11)),
            CustodyCode::RefusedObject
        );
        // EXPIRED.
        let mut old = envelope(&c.alice, 4);
        old.created_at = NOW - 7_200_000;
        old.expires_at = NOW - 1;
        old.sign_with(&c.alice);
        assert_eq!(
            h.forward(&c.alice, &pk(&c.bob), rso1_for(&old, 0x11)),
            CustodyCode::Expired
        );
        assert!(!h.handoff_file(), "{setup:?}: a refusal created the store");
        // STORED, with the object's digest; then DUPLICATE.
        fresh(&pk(&c.alice));
        let (code, digest) = handoff::forward(
            h.dir(),
            &c.carol,
            &pk(&c.alice),
            &Rhw1::forward(pk(&c.bob), rso1.clone()),
            NOW,
        );
        assert_eq!(code, CustodyCode::Ok);
        assert_eq!(digest, custody_digest(&env.pack()));
        assert_eq!(
            h.forward(&c.alice, &pk(&c.bob), rso1.clone()),
            CustodyCode::Duplicate
        );
        // A second next hop is allowed, a third is not.
        assert_eq!(
            h.forward(&c.alice, &pk(&h.erin), rso1.clone()),
            CustodyCode::Ok
        );
        assert_eq!(
            h.forward(&c.alice, &pk(&h.frank), rso1.clone()),
            CustodyCode::Quota
        );
        // The same object under another tag.
        assert_eq!(
            h.forward(&c.alice, &pk(&c.bob), rso1_for(&env, 0x13)),
            CustodyCode::Conflict
        );
        let usage = h.store().usage().unwrap();
        assert_eq!((usage.pending, usage.handed, usage.tags), (2, 0, 0));
        // Nothing went to the RFC1 store.
        assert!(!custody_db_path(h.dir()).exists());
    }
}

/// The per-(depositor, next hop) and per-depositor caps refuse and never
/// evict; the attempt window is DEPOSIT's and counts every outcome.
#[test]
fn forward_caps_refuse_without_eviction_and_share_the_deposit_window() {
    let h = Hub::new(Setup::Plain);
    let c = &h.c;
    let mut fill = 0u32;
    let mut next = |signer: &Identity| {
        fill += 1;
        let mut env = envelope(signer, 0);
        env.message_id[..4].copy_from_slice(&fill.to_be_bytes());
        env.sign_with(signer);
        rso1_for(&env, 0x21)
    };
    for _ in 0..MAX_FORWARD_PAIR_ROWS {
        assert_eq!(
            h.forward(&c.alice, &pk(&c.bob), next(&c.alice)),
            CustodyCode::Ok
        );
    }
    assert_eq!(
        h.forward(&c.alice, &pk(&c.bob), next(&c.alice)),
        CustodyCode::Quota
    );
    for _ in MAX_FORWARD_PAIR_ROWS..MAX_FORWARD_DEPOSITOR_ROWS {
        assert_eq!(
            h.forward(&c.alice, &pk(&h.erin), next(&c.alice)),
            CustodyCode::Ok
        );
    }
    assert_eq!(
        h.forward(&c.alice, &pk(&h.frank), next(&c.alice)),
        CustodyCode::Quota
    );
    // Bob is under his own caps.
    assert_eq!(
        h.forward(&c.bob, &pk(&h.frank), next(&c.bob)),
        CustodyCode::Ok
    );
    let usage = h.store().usage().unwrap();
    assert_eq!(usage.pending, MAX_FORWARD_DEPOSITOR_ROWS as i64 + 1);
    // The window: 119 refused FORWARDs and one DEPOSIT fill it, as this
    // test's own caller (the windows are process-wide: merge I.5, review
    // handoff-6).
    let fay = &h.forward_window;
    let caller = pk(fay);
    fresh(&caller);
    let refused = rso1_for(&envelope(fay, 0x30), 0x22);
    for _ in 0..MAX_DEPOSITS_PER_MINUTE - 1 {
        let (code, _) = handoff::forward(
            h.dir(),
            &c.carol,
            &caller,
            &Rhw1::forward(pk(&c.dave), refused.clone()),
            NOW,
        );
        assert_eq!(code, CustodyCode::NextHopUnknown);
    }
    let frame = encode_request(
        &[3; 8],
        &Rfc1Request::Deposit {
            recipient: pk(&c.bob),
            rso1: rso1_for(&envelope(fay, 0x31), 0x23),
        },
    );
    let _g = Gates::set(true, false);
    let replies = handle_frame(
        h.dir(),
        &c.carol,
        &caller,
        &lan("192.168.1.20"),
        &frame,
        NOW,
    )
    .unwrap();
    assert!(matches!(
        decode_reply(&replies[0]).unwrap().1,
        Rfc1Reply::DepositResult {
            code: CustodyCode::Ok,
            ..
        }
    ));
    let (code, _) = handoff::forward(
        h.dir(),
        &c.carol,
        &caller,
        &Rhw1::forward(pk(&c.bob), next(fay)),
        NOW,
    );
    assert_eq!(code, CustodyCode::RateLimited);
}

// ── DELIVER (spec §3.3) ──────────────────────────────────────────────────

#[test]
fn deliver_resolves_the_tag_and_stores_as_an_rfc1_deposit() {
    for setup in [Setup::Plain, Setup::SealedFresh] {
        let h = Hub::new(setup);
        let c = &h.c;
        // The origin is nobody Carol knows: DELIVER has no signer check.
        let origin = id(0x0A);
        let env = envelope(&origin, 1);
        let rso1 = rso1_for(&env, 0x31);
        // No registration (and no store): TAG_UNKNOWN, nothing created.
        assert_eq!(h.deliver(&c.alice, rso1.clone()), CustodyCode::TagUnknown);
        assert!(!h.handoff_file() && !custody_db_path(h.dir()).exists());
        // Bob registers the tag; Alice (the forwarder) delivers.
        assert_eq!(h.register(&c.bob, 0x31), (CustodyCode::Ok, 1, 0));
        assert_eq!(h.deliver(&c.alice, rso1.clone()), CustodyCode::Ok);
        // A second forwarder's copy is a duplicate.
        assert_eq!(h.deliver(&h.erin, rso1.clone()), CustodyCode::Duplicate);
        // Bob's RFC1 FETCH returns it; a co-custodian naming the tag gets
        // nothing (the recipient binding holds).
        let _g = Gates::set(true, false);
        let fetched = c.fetch(&c.bob, &[[0x31; 16]], None);
        assert_eq!(
            fetched.first(),
            Some(&Rfc1Reply::FetchItem { rso1: rso1.clone() })
        );
        assert_eq!(items(&fetched), 1);
        assert_eq!(items(&c.fetch(&h.erin, &[[0x31; 16]], None)), 0);
        // A DELIVER never creates a forward row.
        assert_eq!(h.store().usage().unwrap().pending, 0);
        // A conflicted tag.
        assert_eq!(h.register(&c.bob, 0x32), (CustodyCode::Ok, 1, 0));
        assert_eq!(h.register(&h.erin, 0x32), (CustodyCode::Ok, 0, 1));
        assert_eq!(
            h.deliver(&c.alice, rso1_for(&envelope(&origin, 2), 0x32)),
            CustodyCode::Conflict
        );
        // A forwarder squatting a tag cannot deliver to itself.
        assert_eq!(h.register(&c.alice, 0x33), (CustodyCode::Ok, 1, 0));
        assert_eq!(
            h.deliver(&c.alice, rso1_for(&envelope(&origin, 3), 0x33)),
            CustodyCode::RecipientNotAccepted
        );
        // An unpinned recipient, and Carol herself (registrations the link
        // rules would never let in; the store alone does not know).
        assert_eq!(
            h.tags(
                &pk(&c.dave),
                TagsAction::Register,
                &[([0x34; 16], NOW + HOUR)]
            )
            .0,
            CustodyCode::Ok
        );
        assert_eq!(
            h.tags(
                &pk(&c.carol),
                TagsAction::Register,
                &[([0x35; 16], NOW + HOUR)]
            )
            .0,
            CustodyCode::Ok
        );
        for tag in [0x34, 0x35] {
            assert_eq!(
                h.deliver(&c.alice, rso1_for(&envelope(&origin, tag), tag)),
                CustodyCode::RecipientNotAccepted,
                "{setup:?} {tag:#x}"
            );
        }
        // An honest F2 never forwards again: F1 (Alice here) asking Carol
        // for a further hop of the origin's object is refused.
        assert_eq!(
            h.forward(&c.alice, &pk(&c.bob), rso1.clone()),
            CustodyCode::HopRefused
        );
        assert_eq!(h.store().usage().unwrap().pending, 0);
    }
}

// ── TAGS (spec §3.4) ─────────────────────────────────────────────────────

#[test]
fn tags_register_extend_clamp_conflict_and_withdraw_own_only() {
    for setup in [Setup::Plain, Setup::SealedFresh] {
        let h = Hub::new(setup);
        let c = &h.c;
        let (bob, erin) = (pk(&c.bob), pk(&h.erin));
        let at = |tag: u8, now: u64| h.store().tag_recipient(&[tag; 16], now).unwrap();
        // Register, then extend: the later expiry wins, an earlier one
        // never shortens it.
        assert_eq!(h.register(&c.bob, 1), (CustodyCode::Ok, 1, 0));
        assert_eq!(
            h.tags(&bob, TagsAction::Register, &[([1; 16], NOW + 2 * HOUR)]),
            (CustodyCode::Ok, 1, 0)
        );
        assert_eq!(
            h.tags(&bob, TagsAction::Register, &[([1; 16], NOW + 60_000)]),
            (CustodyCode::Ok, 1, 0)
        );
        assert_eq!(at(1, NOW + 90 * 60_000), TagState::Live(bob));
        assert_eq!(at(1, NOW + 2 * HOUR), TagState::Unknown);
        // Clamped to 72 h; an entry already past is skipped.
        assert_eq!(
            h.tags(
                &bob,
                TagsAction::Register,
                &[([2; 16], NOW + 100 * HOUR), ([3; 16], NOW - 1)]
            ),
            (CustodyCode::Ok, 1, 0)
        );
        assert_eq!(at(2, NOW + MAX_TAG_TTL_MS - 1), TagState::Live(bob));
        assert_eq!(at(2, NOW + MAX_TAG_TTL_MS), TagState::Unknown);
        assert_eq!(at(3, NOW), TagState::Unknown);
        // Another recipient: conflicted until expiry, both lose.
        assert_eq!(h.register(&h.erin, 1), (CustodyCode::Ok, 0, 1));
        assert_eq!(at(1, NOW), TagState::Conflicted);
        assert_eq!(h.register(&c.bob, 1), (CustodyCode::Ok, 0, 1));
        // WITHDRAW: only the registrant's own unconflicted tags.
        assert_eq!(
            h.tags(&bob, TagsAction::Withdraw, &[([1; 16], 0)]),
            (CustodyCode::Ok, 0, 0)
        );
        assert_eq!(h.register(&c.bob, 4), (CustodyCode::Ok, 1, 0));
        assert_eq!(
            h.tags(&erin, TagsAction::Withdraw, &[([4; 16], 0)]),
            (CustodyCode::Ok, 0, 0)
        );
        assert_eq!(
            h.tags(&bob, TagsAction::Withdraw, &[([4; 16], 0), ([2; 16], 0)]),
            (CustodyCode::Ok, 2, 0)
        );
        assert_eq!(at(4, NOW), TagState::Unknown);
        assert_eq!(at(1, NOW), TagState::Conflicted);
        // Policy off.
        h.policy(true, false);
        assert_eq!(h.register(&c.bob, 5).0, CustodyCode::PolicyDenied);
    }
}

/// 30 TAGS frames a minute per registrant (its own window, not DEPOSIT's);
/// a frame whose entries are all past creates no store.
#[test]
fn tags_rate_limit_and_lazy_store() {
    let h = Hub::new(Setup::Plain);
    // This test's own caller (the windows are process-wide: merge I.5,
    // review handoff-6).
    let caller = pk(&h.tags_window);
    fresh(&caller);
    for n in 0..MAX_TAGS_PER_MINUTE {
        let reply = handoff::tags(
            h.dir(),
            &caller,
            TagsAction::Register,
            &[([9; 16], NOW - 1)],
            NOW,
        );
        assert_eq!(
            reply,
            Rfc1Reply::TagsResult {
                code: CustodyCode::Ok,
                accepted: 0,
                conflicts: 0
            },
            "{n}"
        );
    }
    assert!(!h.handoff_file());
    let reply = handoff::tags(
        h.dir(),
        &caller,
        TagsAction::Register,
        &[([9; 16], NOW + HOUR)],
        NOW,
    );
    assert!(matches!(
        reply,
        Rfc1Reply::TagsResult {
            code: CustodyCode::RateLimited,
            ..
        }
    ));
    // DEPOSIT's window is untouched.
    assert!(charge(
        &DEPOSIT_WINDOWS,
        caller,
        MAX_DEPOSITS_PER_MINUTE,
        NOW
    ));
    // A minute later the window is new.
    let reply = handoff::tags(
        h.dir(),
        &caller,
        TagsAction::Register,
        &[([9; 16], NOW + HOUR)],
        NOW + 60_000,
    );
    assert!(matches!(
        reply,
        Rfc1Reply::TagsResult {
            code: CustodyCode::Ok,
            accepted: 1,
            ..
        }
    ));
}

/// Review handoff-6: the two window tests' callers are their own: not the
/// same, and none of the fixture's other identities (which other tests
/// call as, each starting that caller's windows afresh).
#[test]
fn window_tests_call_as_callers_of_their_own() {
    assert_ne!(FORWARD_WINDOW_SEED, TAGS_WINDOW_SEED);
    for seed in [FORWARD_WINDOW_SEED, TAGS_WINDOW_SEED] {
        assert!(!HUB_SEEDS.contains(&seed), "{seed:#04x}");
    }
    let h = Hub::new(Setup::Plain);
    let keys = [pk(&h.forward_window), pk(&h.tags_window)];
    for other in [
        &h.c.carol, &h.c.alice, &h.c.bob, &h.c.dave, &h.erin, &h.frank,
    ] {
        assert!(!keys.contains(&pk(other)));
    }
}

/// 512 live tags per recipient and 8,192 per node: QUOTA, nothing evicted.
#[test]
fn tags_caps_refuse_without_eviction() {
    let h = Hub::new(Setup::Plain);
    let mut store = HandoffStore::open_or_create(h.dir()).unwrap();
    let entries = |recipient: u16, n: usize| -> Vec<([u8; 16], u64)> {
        (0..n)
            .map(|i| {
                let mut tag = [0u8; 16];
                tag[..2].copy_from_slice(&recipient.to_be_bytes());
                tag[2..4].copy_from_slice(&(i as u16).to_be_bytes());
                (tag, NOW + HOUR)
            })
            .collect()
    };
    let who = |n: u16| {
        let mut key = [0x40u8; 32];
        key[..2].copy_from_slice(&n.to_be_bytes());
        key
    };
    let full = store
        .register(&who(0), &entries(0, MAX_TAGS_PER_RECIPIENT), NOW)
        .unwrap();
    assert_eq!(
        (full.code, usize::from(full.accepted)),
        (CustodyCode::Ok, MAX_TAGS_PER_RECIPIENT.min(255))
    );
    let over = store.register(&who(0), &entries(1, 1), NOW).unwrap();
    assert_eq!((over.code, over.accepted), (CustodyCode::Quota, 0));
    // The recipient's own tags are still extended at its cap.
    let again = store.register(&who(0), &entries(0, 1), NOW).unwrap();
    assert_eq!((again.code, again.accepted), (CustodyCode::Ok, 1));
    let recipients = (MAX_NODE_TAGS as usize / MAX_TAGS_PER_RECIPIENT) as u16;
    for r in 1..recipients {
        let outcome = store
            .register(&who(r), &entries(r, MAX_TAGS_PER_RECIPIENT), NOW)
            .unwrap();
        assert_eq!(outcome.code, CustodyCode::Ok);
    }
    assert_eq!(store.usage().unwrap().tags, MAX_NODE_TAGS);
    let over = store
        .register(&who(recipients), &entries(recipients, 1), NOW)
        .unwrap();
    assert_eq!((over.code, over.accepted), (CustodyCode::Quota, 0));
    assert_eq!(store.usage().unwrap().tags, MAX_NODE_TAGS);
    assert_eq!(
        store.tag_recipient(&entries(0, 1)[0].0, NOW).unwrap(),
        TagState::Live(who(0))
    );
}

// ── The dispatch (handle_frame) ──────────────────────────────────────────

/// Custody live and the handoff gate open for this thread (debug builds
/// only); restored on drop.
struct Open {
    _custody: Gates,
}

impl Open {
    fn new() -> Self {
        let custody = Gates::set(true, false);
        crate::custody_gate::set_handoff_gate_for_this_thread(Some(true));
        set_lab_base_ops_only_for_this_thread(Some(false));
        Open { _custody: custody }
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        crate::custody_gate::set_handoff_gate_for_this_thread(None);
        set_lab_base_ops_only_for_this_thread(None);
    }
}

/// HOLD on a closed link gate (a public source on a LAN link) creates no
/// file; over a local link TAGS and HANDOFF reach their handlers.
#[test]
fn handle_frame_serves_tags_and_handoff_after_the_gate() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _open = Open::new();
    let h = Hub::new(Setup::Plain);
    let c = &h.c;
    let env = envelope(&c.alice, 7);
    let forward = Rfc1Request::Handoff {
        record: Rhw1::forward(pk(&c.bob), rso1_for(&env, 0x41)),
    };
    let register = Rfc1Request::Tags {
        action: TagsAction::Register,
        entries: vec![([0x41; 16], NOW + HOUR)],
    };
    for request in [forward.clone(), register.clone()] {
        let op = request.op();
        let replies = c.call(&c.alice, lan("203.0.113.5"), request);
        assert_eq!(replies, [terminal_for(op, CustodyCode::Hold)]);
    }
    assert!(!h.handoff_file() && !custody_db_path(h.dir()).exists());
    fresh(&pk(&c.bob));
    assert_eq!(
        c.call(&c.bob, lan("192.168.1.21"), register),
        [Rfc1Reply::TagsResult {
            code: CustodyCode::Ok,
            accepted: 1,
            conflicts: 0
        }]
    );
    assert_eq!(
        c.call(&c.alice, lan("192.168.1.20"), forward),
        [Rfc1Reply::HandoffResult {
            code: CustodyCode::Ok,
            digest: custody_digest(&env.pack())
        }]
    );
    let usage = h.store().usage().unwrap();
    assert_eq!((usage.pending, usage.tags), (1, 1));
}
