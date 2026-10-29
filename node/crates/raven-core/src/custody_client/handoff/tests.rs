//! Phase 5 P5.20: the requester and forwarder side of custody handoff
//! (`protocol/RAVEN_CUSTODY_HANDOFF_V1.md` §3.2, §3.5, §3.6): the plan, the
//! announced custodians, the mixed batch, tag registration on the fetch
//! dial, the forwarder's DELIVER dial, and an in-process world of four
//! nodes (A -> F1 -> F2 -> B) whose frames go to the real handlers.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use super::*;
use crate::custody_client::{
    custody_batch, deposit_batch, fetch_round, fetch_round_with, inbound_register_tags,
    inbound_tags, listed_custodians, register_expiry, CustodyItem, DepositItem, FetchState,
    Registered, TagRegistration, MAX_PAGES_PER_TRIGGER, TAG_CONFIRM_MS, TAG_REFRESH_MS,
};
use crate::custody_gate::{
    handoff_live, set_custody_gates_for_this_thread, set_custody_hints_for_this_thread,
    set_handoff_gate_for_this_thread, CustodyGates,
};
use crate::custody_handoff::{HandoffStore, Rhw1Kind, TagsAction, MAX_TAG_TTL_MS};
use crate::friend_custody::{
    custody_digest, decode_request, encode_reply, handle_frame, rfc1_rso1, CustodyCode,
    InboundLink, RequestDecode, OP_DEPOSIT, OP_FETCH, OP_HANDOFF, OP_RELEASE, OP_TAGS,
};
use crate::identity::Identity;
use crate::indexed_session_store::{
    register_days, AuthorizedEndpointDevice, EndpointDeliveryState, IndexedSessionRecordKey,
    IndexedSessionStore,
};
use crate::lan_dispatch::{
    cache_peer_bundle, create_initiator_pair_init, dispatch_frame, local_bundle, wrap_pair_init,
};
use crate::outbox::OutboxCarrier;
use crate::owed_acks::OwedAcks;
use crate::pair_init_lan_oob::{classify_packed_envelope, PairInitOobClassify};
use crate::relayed_ingest::RelayHint;
use crate::route_hints::ValidHints;

const DAY: u64 = 86_400_000;
const HOUR: u64 = 3_600_000;
const MIN: u64 = 60_000;

/// Raven's clock, as the code under test reads it.
fn now() -> u64 {
    crate::clock::now_ms()
}

/// A test key (not a real identity: these never sign).
fn k(n: u8) -> [u8; 32] {
    [n; 32]
}

fn ann(key: [u8; 32], handoff_inbox: bool) -> Announced {
    Announced { key, handoff_inbox }
}

/// Friend custody (LAN only), learned custody and custody handoff on for
/// this thread; the build's own gates again on drop.
struct Gates;

impl Gates {
    fn on() -> Self {
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: true,
            wan: false,
        }));
        set_custody_hints_for_this_thread(Some(true));
        set_handoff_gate_for_this_thread(Some(true));
        Gates
    }
}

impl Drop for Gates {
    fn drop(&mut self) {
        set_custody_gates_for_this_thread(None);
        set_custody_hints_for_this_thread(None);
        set_handoff_gate_for_this_thread(None);
    }
}

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

#[test]
fn custody_plan_truth_table() {
    use PlanStep::{Deposit, Forward};
    let (peer, local) = (k(0xB0), k(0xA0));
    let (c1, c2, h1, h2) = (k(0xC1), k(0xC2), k(0xE1), k(0xE2));
    let no_park = |_: &[u8; 32]| false;
    let no_handoff_park = |_: &[u8; 32], _: Option<&[u8; 32]>| false;
    let plan = |listed: &[[u8; 32]],
                announced: Option<&[Announced]>,
                live: bool,
                plain: &dyn Fn(&[u8; 32]) -> bool,
                handoff: &HandoffParked<'_>| {
        custody_plan(listed, announced, live, &peer, &local, plain, handoff)
    };
    let both = [c1, c2];

    // No announcement from the peer: DEPOSIT at every listed custodian
    // (Phase 3), whatever the gate.
    for live in [false, true] {
        assert_eq!(
            plan(&both, None, live, &no_park, &no_handoff_park),
            [Deposit(c1), Deposit(c2)]
        );
    }
    // An announced C: DEPOSIT there, even with a handoff inbox on offer.
    let told = [ann(c1, false), ann(h1, true)];
    assert_eq!(
        plan(&[c1], Some(&told), true, &no_park, &no_handoff_park),
        [Deposit(c1)]
    );
    // An unannounced C with an announced H (HANDOFF_INBOX): FORWARD{C, H}.
    assert_eq!(
        plan(&both, Some(&told), true, &no_park, &no_handoff_park),
        [
            Deposit(c1),
            Forward {
                via: c2,
                next_hop: h1
            }
        ]
    );
    // One next hop per C, the first in the peer's order; two Cs may share it.
    let inboxes = [ann(h1, true), ann(h2, true)];
    assert_eq!(
        plan(&both, Some(&inboxes), true, &no_park, &no_handoff_park),
        [
            Forward {
                via: c1,
                next_hop: h1
            },
            Forward {
                via: c2,
                next_hop: h1
            }
        ]
    );
    // An H without HANDOFF_INBOX is never a next hop: no FORWARD, so the
    // Phase 3 DEPOSIT.
    assert_eq!(
        plan(
            &[c2],
            Some(&[ann(h1, false)]),
            true,
            &no_park,
            &no_handoff_park
        ),
        [Deposit(c2)]
    );
    // The H is never this node or the peer (C itself is announced, so a
    // DEPOSIT, never its own next hop).
    let odd = [ann(local, true), ann(peer, true)];
    assert_eq!(
        plan(&[c2], Some(&odd), true, &no_park, &no_handoff_park),
        [Deposit(c2)]
    );
    let odd_then_h2 = [ann(local, true), ann(peer, true), ann(h2, true)];
    assert_eq!(
        plan(&[c2], Some(&odd_then_h2), true, &no_park, &no_handoff_park),
        [Forward {
            via: c2,
            next_hop: h2
        }]
    );
    assert_eq!(
        plan(
            &[c2],
            Some(&[ann(c2, true)]),
            true,
            &no_park,
            &no_handoff_park
        ),
        [Deposit(c2)]
    );
    // A parked pair (C, H) moves on to the next H; every pair parked: DEPOSIT.
    let c2_h1 = |c: &[u8; 32], h: Option<&[u8; 32]>| *c == c2 && h == Some(&h1);
    assert_eq!(
        plan(&both, Some(&inboxes), true, &no_park, &c2_h1),
        [
            Forward {
                via: c1,
                next_hop: h1
            },
            Forward {
                via: c2,
                next_hop: h2
            }
        ]
    );
    let every_pair = |_: &[u8; 32], h: Option<&[u8; 32]>| h.is_some();
    assert_eq!(
        plan(&both, Some(&inboxes), true, &no_park, &every_pair),
        [Deposit(c1), Deposit(c2)]
    );
    // Handoff parked at C (UNSUPPORTED, HOLD, ...): plain custody there
    // stays usable; another C still forwards.
    let c2_parked = |c: &[u8; 32], h: Option<&[u8; 32]>| *c == c2 && h.is_none();
    assert_eq!(
        plan(&both, Some(&inboxes), true, &no_park, &c2_parked),
        [
            Forward {
                via: c1,
                next_hop: h1
            },
            Deposit(c2)
        ]
    );
    // The gate off gives no FORWARD ever: the plan is Phase 3's.
    for told in [&told[..], &inboxes[..], &odd_then_h2[..], &[][..]] {
        assert_eq!(
            plan(&both, Some(told), false, &no_park, &no_handoff_park),
            [Deposit(c1), Deposit(c2)],
            "{told:?}"
        );
    }
    // A plain pair park (RECIPIENT_NOT_ACCEPTED) blocks only DEPOSIT steps.
    let plain_both = |c: &[u8; 32]| *c == c1 || *c == c2;
    assert_eq!(
        plan(&both, Some(&told), true, &plain_both, &no_handoff_park),
        [Forward {
            via: c2,
            next_hop: h1
        }]
    );
    assert!(plan(&both, None, true, &plain_both, &no_handoff_park).is_empty());
    assert!(plan(&both, Some(&told), false, &plain_both, &no_handoff_park).is_empty());
    assert_eq!(
        plan(&both, None, true, &|c| *c == c1, &no_handoff_park),
        [Deposit(c2)]
    );
    // Nothing listed: nothing planned.
    assert!(plan(&[], Some(&inboxes), true, &no_park, &no_handoff_park).is_empty());
}

// ---------------------------------------------------------------------------
// The announced custodians
// ---------------------------------------------------------------------------

#[test]
fn announced_from_resolves_tags_against_the_book_with_the_inbox_bit() {
    let (local, peer) = (k(0xA0), k(0xB0));
    let (f2, x, y, stranger) = (k(0x21), k(0x22), k(0x23), k(0x24));
    let tag = |c: &[u8; 32]| custodian_tag(&peer, &local, c);
    let book = [peer, x, f2, y, local];
    let told = LearnedCustody {
        tags: vec![tag(&stranger), tag(&f2), tag(&y)],
        // Unknown bits are ignored: y's 0x02 is no inbox.
        tag_flags: vec![0x01, 0x03, 0x02],
        plain: vec![x, peer, local, f2, stranger],
        offer: None,
        heard_ms: 0,
    };
    assert_eq!(
        announced_from(&told, &book, &local, &peer),
        [ann(f2, true), ann(y, false), ann(x, false)],
        "a stranger's tag teaches nothing; plain keys have no flags"
    );
    // A tag stored without flags, or for the other direction, or for this
    // node or the peer.
    let short = LearnedCustody {
        tags: vec![
            tag(&f2),
            custodian_tag(&local, &peer, &x),
            tag(&peer),
            tag(&local),
        ],
        tag_flags: Vec::new(),
        ..Default::default()
    };
    assert_eq!(
        announced_from(&short, &book, &local, &peer),
        [ann(f2, false)]
    );
}

/// `dir`'s contact book: each key with its pinned bit.
fn pinned_book(dir: &Path, rows: &[([u8; 32], bool)]) {
    let rows: Vec<serde_json::Value> = rows
        .iter()
        .map(|(key, pinned)| {
            serde_json::json!({
                "pub_hex": hex::encode(key),
                "pinned": pinned,
                "lan_dial": "192.168.1.9:7420",
            })
        })
        .collect();
    std::fs::write(
        dir.join("contacts.json"),
        serde_json::Value::Array(rows).to_string(),
    )
    .unwrap();
}

/// `sender` (a pinned contact) told `local` (this node) `v` over a LAN link.
fn told(dir: &Path, local: &[u8; 32], sender: &[u8; 32], v: &ValidHints) {
    let link = crate::route_hints::HintLink {
        carrier: OutboxCarrier::Lan,
        peer_ip: Some("192.168.1.9".parse().unwrap()),
        peer_zone: None,
        link_peer_id: None,
        book_peer_id: None,
        pinned: true,
        sender: *sender,
        local: *local,
        local_p2p: [0x53; 32],
        local_relay: None,
        lab_local: false,
        lab_loopback: false,
    };
    let applied = crate::learned_routes::apply_ungated(dir, sender, v, &link, None, now()).unwrap();
    assert!(
        matches!(
            applied,
            crate::learned_routes::Applied::Changed { .. }
                | crate::learned_routes::Applied::Refreshed
        ),
        "stored: {applied:?}"
    );
}

/// RRH1 custodian tags (with their flags) as a receiver keeps them.
fn tag_hints(generation: u64, tags: &[([u8; 32], u8)]) -> ValidHints {
    ValidHints {
        generation,
        ttl_s: crate::route_hints::RRH1_DEFAULT_TTL_S,
        custodian_tags: tags.iter().map(|(t, _)| *t).collect(),
        custodian_tag_flags: tags.iter().map(|(_, f)| *f).collect(),
        ..Default::default()
    }
}

#[test]
fn announced_custodians_read_the_learned_snapshot() {
    let _gates = Gates::on();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (local, peer, other) = (k(0xA1), k(0xB1), k(0xB2));
    let (f2, unpinned) = (k(0x31), k(0x32));
    pinned_book(
        d,
        &[(peer, true), (other, true), (f2, true), (unpinned, false)],
    );
    // Nothing heard from the peer: no announcement.
    assert_eq!(announced_custodians(d, &local, &peer, now()), None);
    // A snapshot without custodian entries is no announcement either.
    told(d, &local, &other, &tag_hints(1, &[]));
    assert_eq!(announced_custodians(d, &local, &other, now()), None);
    // The peer's tags: F2 with HANDOFF_INBOX, and one for a friend this node
    // has not verified (not resolved).
    told(
        d,
        &local,
        &peer,
        &tag_hints(
            1,
            &[
                (custodian_tag(&peer, &local, &f2), 0x01),
                (custodian_tag(&peer, &local, &unpinned), 0x01),
            ],
        ),
    );
    assert_eq!(
        announced_custodians(d, &local, &peer, now()),
        Some(vec![ann(f2, true)])
    );
    // A tag for none of this node's contacts: an announcement naming nobody
    // it knows.
    told(
        d,
        &local,
        &peer,
        &tag_hints(2, &[(custodian_tag(&peer, &local, &unpinned), 0x01)]),
    );
    assert_eq!(announced_custodians(d, &local, &peer, now()), Some(vec![]));
    // Learned custody off: nothing is read.
    set_custody_hints_for_this_thread(Some(false));
    assert_eq!(announced_custodians(d, &local, &peer, now()), None);
}

// ---------------------------------------------------------------------------
// A fake custodian
// ---------------------------------------------------------------------------

/// A request as a fake custodian decoded it: its req_id and the request.
type Seen = RefCell<Vec<([u8; 8], Rfc1Request)>>;

/// A custodian that answers each request with `answer` (`None`: no reply),
/// logs it in `seen`, and sends its replies in reverse order (they are
/// matched by `req_id`). `Err` on a frame it cannot decode.
fn fake<'a>(
    seen: &'a Seen,
    answer: impl Fn(usize, &Rfc1Request) -> Option<Rfc1Reply> + 'a,
) -> impl FnMut(&[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> + 'a {
    move |frames: &[Vec<u8>]| {
        let mut out = vec![b"RLB1-offer".to_vec()];
        for frame in frames {
            let Ok(RequestDecode::Request(id, request)) = decode_request(frame) else {
                return Err("bad frame".into());
            };
            let n = seen.borrow().len();
            if let Some(reply) = answer(n, &request) {
                out.push(encode_reply(&id, &reply));
            }
            seen.borrow_mut().push((id, request));
        }
        out.reverse();
        Ok(out)
    }
}

/// A dial that must not happen.
fn no_dial(_: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
    panic!("dialled")
}

/// A fake RSO1: only its length is checked on the wire.
fn rso1(n: u8) -> Vec<u8> {
    vec![n; 200]
}

fn handoff_result(code: CustodyCode) -> Option<Rfc1Reply> {
    Some(Rfc1Reply::HandoffResult {
        code,
        digest: [0; 32],
    })
}

fn deposit_result(code: CustodyCode) -> Option<Rfc1Reply> {
    Some(Rfc1Reply::DepositResult {
        code,
        digest: [0; 32],
    })
}

fn unsupported() -> Option<Rfc1Reply> {
    Some(Rfc1Reply::Unsupported { max_version: 1 })
}

// ---------------------------------------------------------------------------
// custody_batch
// ---------------------------------------------------------------------------

#[test]
fn custody_batch_maps_answers_by_req_id_in_a_mixed_batch() {
    let _gates = Gates::on();
    let (c, r, h, h2) = (k(0xC3), k(0xB3), k(0xE3), k(0xE4));
    let items = [
        CustodyItem::Deposit {
            recipient: r,
            rso1: rso1(1),
        },
        CustodyItem::Forward {
            next_hop: h,
            rso1: rso1(2),
        },
        CustodyItem::Deposit {
            recipient: r,
            rso1: rso1(3),
        },
        CustodyItem::Forward {
            next_hop: h2,
            rso1: rso1(4),
        },
        CustodyItem::Forward {
            next_hop: h,
            rso1: rso1(5),
        },
    ];
    // DEPOSIT_RESULT for the deposits, HANDOFF_RESULT for the forwards; the
    // fourth goes unanswered and the fifth gets a DEPOSIT_RESULT (another
    // op's reply: no answer).
    let seen = Seen::default();
    let mut caps = CapabilityCache::default();
    let answers = custody_batch(
        &c,
        &items,
        &mut caps,
        now(),
        &mut fake(&seen, |n, request| match (n, request) {
            (3, _) => None,
            (4, _) => deposit_result(CustodyCode::Ok),
            (_, Rfc1Request::Deposit { .. }) => deposit_result(CustodyCode::Duplicate),
            (_, Rfc1Request::Handoff { .. }) => handoff_result(CustodyCode::Ok),
            _ => None,
        }),
    )
    .unwrap();
    assert_eq!(
        answers,
        [
            Some(ItemAnswer::Code(CustodyCode::Duplicate)),
            Some(ItemAnswer::Code(CustodyCode::Ok)),
            Some(ItemAnswer::Code(CustodyCode::Duplicate)),
            None,
            None,
        ]
    );
    assert!(answers[1].unwrap().held() && !ItemAnswer::Unsupported.held());
    let seen = seen.into_inner();
    for (i, (id, request)) in seen.iter().enumerate() {
        assert_eq!(id[0], 0xD0);
        assert_eq!(index_of(id, 0xD0), Some(i));
        match (&items[i], request) {
            (
                CustodyItem::Deposit { recipient, rso1 },
                Rfc1Request::Deposit {
                    recipient: r2,
                    rso1: o2,
                },
            ) => assert!(recipient == r2 && rso1 == o2),
            (CustodyItem::Forward { next_hop, rso1 }, Rfc1Request::Handoff { record }) => {
                assert_eq!(record.kind, Rhw1Kind::Forward);
                assert!(record.next_hop == *next_hop && record.rso1 == *rso1);
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(caps.handoff(&c, now()), Some(true));

    // A custodian without the handoff ops: UNSUPPORTED to each HANDOFF,
    // deposits served. The cache learns it ...
    let old = |_: usize, request: &Rfc1Request| match request {
        Rfc1Request::Deposit { .. } => deposit_result(CustodyCode::Ok),
        _ => unsupported(),
    };
    let seen = Seen::default();
    let mut caps = CapabilityCache::default();
    let answers = custody_batch(&c, &items[..2], &mut caps, now(), &mut fake(&seen, old)).unwrap();
    assert_eq!(
        answers,
        [
            Some(ItemAnswer::Code(CustodyCode::Ok)),
            Some(ItemAnswer::Unsupported)
        ]
    );
    assert_eq!(caps.handoff(&c, now()), Some(false));
    // ... and the next batch sends it no FORWARD (answered from the cache),
    // a FORWARD-only batch no dial at all.
    let seen = Seen::default();
    let answers = custody_batch(&c, &items[..2], &mut caps, now(), &mut fake(&seen, old)).unwrap();
    assert_eq!(answers[1], Some(ItemAnswer::Unsupported));
    assert_eq!(seen.borrow().len(), 1, "only the DEPOSIT");
    let answers = custody_batch(&c, &items[3..], &mut caps, now(), &mut no_dial).unwrap();
    assert_eq!(answers, [Some(ItemAnswer::Unsupported); 2]);
    // An UNSUPPORTED to a base DEPOSIT is no answer (as before handoff).
    let seen = Seen::default();
    let answers = custody_batch(
        &c,
        &items[..1],
        &mut CapabilityCache::default(),
        now(),
        &mut fake(&seen, |_, _| unsupported()),
    )
    .unwrap();
    assert_eq!(answers, [None]);

    // The handoff gate closed: FORWARDs are not sent (no answer), DEPOSITs
    // are; a FORWARD-only batch dials nothing.
    set_handoff_gate_for_this_thread(Some(false));
    assert!(!handoff_live());
    let seen = Seen::default();
    let mut caps = CapabilityCache::default();
    let answers = custody_batch(
        &c,
        &items[..2],
        &mut caps,
        now(),
        &mut fake(&seen, |_, _| deposit_result(CustodyCode::Ok)),
    )
    .unwrap();
    assert_eq!(answers, [Some(ItemAnswer::Code(CustodyCode::Ok)), None]);
    assert!(matches!(
        seen.borrow()[..],
        [(_, Rfc1Request::Deposit { .. })]
    ));
    assert_eq!(caps.handoff(&c, now()), None, "nothing learned");
    let answers = custody_batch(&c, &items[3..], &mut caps, now(), &mut no_dial).unwrap();
    assert_eq!(answers, [None, None]);
    assert!(custody_batch(&c, &[], &mut caps, now(), &mut no_dial)
        .unwrap()
        .is_empty());
}

#[test]
fn deposit_batch_is_custody_batch_with_deposits_only() {
    let _gates = Gates::on();
    let deposits: Vec<DepositItem> = (0..20u8)
        .map(|i| DepositItem {
            recipient: k(0xB4),
            rso1: rso1(i),
        })
        .collect();
    let frames = |f: &mut dyn FnMut(&mut CustodianDial<'_>)| {
        let sent = RefCell::new(Vec::new());
        let mut dial = |frames: &[Vec<u8>]| -> Result<Vec<Vec<u8>>, String> {
            sent.borrow_mut().extend(frames.iter().cloned());
            Ok(frames
                .iter()
                .filter(|f| f[5] == OP_DEPOSIT)
                .map(|f| {
                    let id: [u8; 8] = f[6..14].try_into().unwrap();
                    encode_reply(&id, &deposit_result(CustodyCode::Ok).unwrap())
                })
                .collect())
        };
        f(&mut dial);
        sent.into_inner()
    };
    let mut old = Vec::new();
    let a = frames(&mut |dial| old = deposit_batch(&deposits, dial).unwrap());
    let items: Vec<CustodyItem> = deposits
        .iter()
        .map(|d| CustodyItem::Deposit {
            recipient: d.recipient,
            rso1: d.rso1.clone(),
        })
        .collect();
    let mut new = Vec::new();
    let b = frames(&mut |dial| {
        new = custody_batch(
            &k(0xC4),
            &items,
            &mut CapabilityCache::default(),
            now(),
            dial,
        )
        .unwrap()
    });
    assert_eq!(a, b, "the same frames, byte for byte");
    assert_eq!(a.len(), 16, "cut to 16 per dial");
    assert_eq!(old, vec![Some(CustodyCode::Ok); 16]);
    assert_eq!(new, vec![Some(ItemAnswer::Code(CustodyCode::Ok)); 16]);
}

// ---------------------------------------------------------------------------
// Tag registration on the fetch dial
// ---------------------------------------------------------------------------

fn tag(n: u16) -> [u8; 16] {
    let mut t = [0u8; 16];
    t[..2].copy_from_slice(&n.to_be_bytes());
    t
}

/// `n` fetch tags with placeholder hints (a fake custodian never returns
/// an item, so nothing is ingested).
fn fetch_tags(n: u16) -> BTreeMap<[u8; 16], RelayHint> {
    (0..n)
        .map(|i| {
            let hint = RelayHint {
                record_key: IndexedSessionRecordKey {
                    profile_id: Vec::new(),
                    initiator_address: String::new(),
                    responder_address: String::new(),
                    initiator_device_ed25519: [0; 32],
                    responder_device_ed25519: [0; 32],
                    init_id: [0; 16],
                },
                peer_device: [0; 32],
                store_tag: tag(i),
            };
            (tag(i), hint)
        })
        .collect()
}

/// A custodian answering TAGS with `tags_reply` (`None`: TAGS_RESULT OK
/// with every entry accepted) and every FETCH with an empty page, more to
/// come when `more`.
fn tag_custodian<'a>(
    seen: &'a Seen,
    tags_reply: Option<Rfc1Reply>,
    more: bool,
) -> impl FnMut(&[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> + 'a {
    fake(seen, move |_, request| match request {
        Rfc1Request::Tags { entries, .. } => tags_reply.clone().or(Some(Rfc1Reply::TagsResult {
            code: CustodyCode::Ok,
            accepted: entries.len() as u8,
            conflicts: 0,
        })),
        Rfc1Request::Fetch { .. } => Some(Rfc1Reply::FetchEnd {
            code: CustodyCode::Ok,
            returned: 0,
            next: more.then_some([0x5A; 32]),
        }),
        Rfc1Request::Release { .. } => Some(Rfc1Reply::ReleaseResult {
            code: CustodyCode::Ok,
            released: 0,
        }),
        _ => None,
    })
}

/// The TAGS entries of each dial `seen` logged since `from`.
fn tags_sent(seen: &Seen, from: usize) -> Vec<Vec<([u8; 16], u64)>> {
    seen.borrow()[from..]
        .iter()
        .filter_map(|(_, request)| match request {
            Rfc1Request::Tags {
                action: TagsAction::Register,
                entries,
            } => Some(entries.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn fetch_round_with_registers_each_tag_once_and_refreshes_near_expiry() {
    let _gates = Gates::on();
    let dir = tempfile::tempdir().unwrap();
    let me = Identity::from_seed(&[0x62; 32]);
    let custodian = k(0xC6);
    let t0 = 20_000 * DAY + 3 * HOUR;
    let fetching = fetch_tags(1);
    // Two tags within the TTL, one past it (clamped to 72 h).
    let wanted = BTreeMap::from([
        (tag(1), t0 + 30 * HOUR),
        (tag(2), t0 + 50 * HOUR),
        (tag(3), t0 + 80 * HOUR),
    ]);
    let mut caps = CapabilityCache::default();
    let mut state = FetchState::default();
    let seen = Seen::default();
    let round = |at: u64, caps: &mut CapabilityCache, state: &mut FetchState| {
        let from = seen.borrow().len();
        let report = fetch_round_with(
            dir.path(),
            &me,
            &fetching,
            Some(TagRegistration {
                custodian,
                tags: &wanted,
                caps,
            }),
            state,
            at,
            MAX_PAGES_PER_TRIGGER,
            &mut tag_custodian(&seen, None, false),
        );
        let ops: Vec<u8> = seen.borrow()[from..].iter().map(|(id, _)| id[0]).collect();
        (report, ops, tags_sent(&seen, from))
    };
    // The first round: one TAGS frame ahead of the FETCH, in one dial.
    let (report, ops, sent) = round(t0, &mut caps, &mut state);
    assert_eq!(report.dials, 1);
    assert_eq!(ops, [0xA0, 0xF0], "TAGS first, then FETCH");
    assert_eq!(
        sent,
        [vec![
            (tag(1), t0 + 30 * HOUR),
            (tag(2), t0 + 50 * HOUR),
            (tag(3), t0 + MAX_TAG_TTL_MS)
        ]]
    );
    assert!(report.tags_ok && report.tags_code.is_none() && !report.tags_unsupported);
    assert_eq!(state.registered.len(), 3);
    assert_eq!(caps.handoff(&custodian, t0), Some(true));
    // Registered: not sent again while the custodian's OK is younger than
    // TAG_CONFIRM_MS (review handoff-1: then it is, with the same expiry).
    for at in [t0 + MIN, t0 + TAG_CONFIRM_MS - MIN] {
        let (report, ops, sent) = round(at, &mut caps, &mut state);
        assert!(sent.is_empty() && !report.tags_ok, "{at}");
        assert_eq!(ops, [0xF0]);
    }
    assert_eq!(TAG_CONFIRM_MS, 6 * HOUR);
    // Under 24 h left of a clamped registration (confirmed just now):
    // registered again, now for the whole wanted time. Tag 1 has expired
    // (dropped); tag 2's own expiry is near but it is all that was wanted
    // (not sent).
    let late = t0 + MAX_TAG_TTL_MS - TAG_REFRESH_MS + MIN;
    let confirmed = |expiry: u64| Registered {
        expiry,
        confirmed_ms: late,
    };
    state.registered.insert(tag(2), confirmed(t0 + 50 * HOUR));
    state
        .registered
        .insert(tag(3), confirmed(t0 + MAX_TAG_TTL_MS));
    let (report, _, sent) = round(late, &mut caps, &mut state);
    assert_eq!(sent, [vec![(tag(3), t0 + 80 * HOUR)]]);
    assert!(report.tags_ok);
    assert_eq!(state.registered.get(&tag(1)), None);
    assert_eq!(
        state.registered.get(&tag(3)),
        Some(&Registered {
            expiry: t0 + 80 * HOUR,
            confirmed_ms: late
        })
    );
    let (_, _, sent) = round(late + MIN, &mut caps, &mut state);
    assert!(sent.is_empty());

    // A refusal leaves the tags unregistered (sent again next round), and
    // the code is reported once.
    let mut state = FetchState::default();
    let seen = Seen::default();
    let refused = Rfc1Reply::TagsResult {
        code: CustodyCode::PolicyDenied,
        accepted: 0,
        conflicts: 0,
    };
    for _ in 0..2 {
        let report = fetch_round_with(
            dir.path(),
            &me,
            &fetching,
            Some(TagRegistration {
                custodian,
                tags: &wanted,
                caps: &mut caps,
            }),
            &mut state,
            t0,
            MAX_PAGES_PER_TRIGGER,
            &mut tag_custodian(&seen, Some(refused.clone()), false),
        );
        assert_eq!(report.tags_code, Some(CustodyCode::PolicyDenied));
        assert!(!report.tags_ok);
        assert!(state.registered.is_empty());
    }
    assert_eq!(tags_sent(&seen, 0).len(), 2);
    // Conflicts are counted (both lose the tag; the rest is registered).
    let mut state = FetchState::default();
    let seen = Seen::default();
    let report = fetch_round_with(
        dir.path(),
        &me,
        &fetching,
        Some(TagRegistration {
            custodian,
            tags: &wanted,
            caps: &mut caps,
        }),
        &mut state,
        t0,
        MAX_PAGES_PER_TRIGGER,
        &mut tag_custodian(
            &seen,
            Some(Rfc1Reply::TagsResult {
                code: CustodyCode::Ok,
                accepted: 2,
                conflicts: 1,
            }),
            false,
        ),
    );
    assert!(report.tags_ok);
    assert_eq!(report.tag_conflicts, 1);
}

/// Review handoff-1: a custodian that lost this node's registrations
/// (custody turned off and on with `--purge`, its store set aside) says
/// nothing, since FETCH works by tag. So a registered tag is sent again,
/// with the same expiry, once the custodian's OK for it is 6 h old (and not
/// before); and a round the custodian refused (its FETCH answered
/// POLICY_DENIED, HOLD or NOT_VERIFIED: custody off there, this node no
/// longer its verified contact, its link gate closed) forgets every
/// registration there, so all of them go again once it takes this node.
/// A busy answer (RATE_LIMITED) forgets nothing.
#[test]
fn fetch_round_with_registers_again_once_the_ok_is_six_hours_old() {
    let _gates = Gates::on();
    let dir = tempfile::tempdir().unwrap();
    let me = Identity::from_seed(&[0x64; 32]);
    let custodian = k(0xC8);
    let t0 = 20_000 * DAY + 3 * HOUR;
    let fetching = fetch_tags(1);
    let wanted = BTreeMap::from([(tag(1), t0 + 30 * HOUR), (tag(2), t0 + 50 * HOUR)]);
    let mut caps = CapabilityCache::default();
    let mut state = FetchState::default();
    let seen = Seen::default();
    // The custodian answers TAGS OK and the FETCH with `fetch`.
    let mut round = |at: u64, state: &mut FetchState, fetch: CustodyCode| {
        let from = seen.borrow().len();
        let report = fetch_round_with(
            dir.path(),
            &me,
            &fetching,
            Some(TagRegistration {
                custodian,
                tags: &wanted,
                caps: &mut caps,
            }),
            state,
            at,
            MAX_PAGES_PER_TRIGGER,
            &mut fake(&seen, move |_, request| match request {
                Rfc1Request::Tags { entries, .. } => Some(Rfc1Reply::TagsResult {
                    code: CustodyCode::Ok,
                    accepted: entries.len() as u8,
                    conflicts: 0,
                }),
                Rfc1Request::Fetch { .. } => Some(Rfc1Reply::FetchEnd {
                    code: fetch,
                    returned: 0,
                    next: None,
                }),
                _ => None,
            }),
        );
        (report, tags_sent(&seen, from))
    };
    let all = vec![(tag(1), t0 + 30 * HOUR), (tag(2), t0 + 50 * HOUR)];
    let (report, sent) = round(t0, &mut state, CustodyCode::Ok);
    assert_eq!(sent, std::slice::from_ref(&all));
    assert!(report.tags_ok);
    // Confirmed within 6 h: not sent again.
    for at in [t0 + MIN, t0 + 6 * HOUR - MIN] {
        let (report, sent) = round(at, &mut state, CustodyCode::Ok);
        assert!(sent.is_empty() && !report.tags_ok, "{at}");
    }
    // The OK is 6 h old: both again, with the expiry they had.
    let (report, sent) = round(t0 + 6 * HOUR, &mut state, CustodyCode::Ok);
    assert_eq!(sent, std::slice::from_ref(&all));
    assert!(report.tags_ok);
    let (_, sent) = round(t0 + 7 * HOUR, &mut state, CustodyCode::Ok);
    assert!(sent.is_empty(), "confirmed again at 6 h");
    // A busy custodian keeps them.
    let (report, _) = round(t0 + 8 * HOUR, &mut state, CustodyCode::RateLimited);
    assert_eq!(report.custodian_code, Some(CustodyCode::RateLimited));
    assert_eq!(state.registered.len(), 2);
    // Turned away: forgotten, so sent again on the very next round.
    for (i, refusal) in [
        CustodyCode::PolicyDenied,
        CustodyCode::Hold,
        CustodyCode::NotVerified,
    ]
    .into_iter()
    .enumerate()
    {
        let at = t0 + 8 * HOUR + (i as u64 + 1) * MIN;
        let (report, _) = round(at, &mut state, refusal);
        assert_eq!(report.custodian_code, Some(refusal));
        assert!(state.registered.is_empty(), "{refusal:?}");
        let (report, sent) = round(at + 1, &mut state, CustodyCode::Ok);
        assert_eq!(sent, std::slice::from_ref(&all), "{refusal:?}");
        assert!(report.tags_ok);
    }
}

#[test]
fn fetch_round_with_unsupported_caps_and_frame_budget() {
    let _gates = Gates::on();
    let dir = tempfile::tempdir().unwrap();
    let me = Identity::from_seed(&[0x63; 32]);
    let custodian = k(0xC7);
    let t0 = 20_000 * DAY;
    let fetching = fetch_tags(1);
    let wanted: BTreeMap<[u8; 16], u64> = (0..70).map(|i| (tag(i), t0 + DAY)).collect();

    // UNSUPPORTED: reported and cached; the FETCH is still served; the next
    // round sends no TAGS.
    let mut caps = CapabilityCache::default();
    let mut state = FetchState::default();
    let seen = Seen::default();
    let report = fetch_round_with(
        dir.path(),
        &me,
        &fetching,
        Some(TagRegistration {
            custodian,
            tags: &wanted,
            caps: &mut caps,
        }),
        &mut state,
        t0,
        MAX_PAGES_PER_TRIGGER,
        &mut tag_custodian(&seen, unsupported(), false),
    );
    assert!(report.tags_unsupported && !report.tags_ok);
    assert_eq!(report.tags_code, None);
    assert_eq!(caps.handoff(&custodian, t0), Some(false));
    assert!(state.registered.is_empty());
    assert!(seen
        .borrow()
        .iter()
        .any(|(_, r)| matches!(r, Rfc1Request::Fetch { .. })));
    let from = seen.borrow().len();
    fetch_round_with(
        dir.path(),
        &me,
        &fetching,
        Some(TagRegistration {
            custodian,
            tags: &wanted,
            caps: &mut caps,
        }),
        &mut state,
        t0 + MIN,
        MAX_PAGES_PER_TRIGGER,
        &mut tag_custodian(&seen, None, false),
    );
    assert!(tags_sent(&seen, from).is_empty(), "cached: not asked again");

    // 70 due tags: two frames of 32 in the first dial only (a second page
    // dial carries none); the other 6 go next round.
    let mut caps = CapabilityCache::default();
    let mut state = FetchState::default();
    let seen = Seen::default();
    let report = fetch_round_with(
        dir.path(),
        &me,
        &fetching,
        Some(TagRegistration {
            custodian,
            tags: &wanted,
            caps: &mut caps,
        }),
        &mut state,
        t0,
        2,
        &mut tag_custodian(&seen, None, true),
    );
    assert_eq!(report.dials, 2);
    let ops: Vec<u8> = seen.borrow().iter().map(|(id, _)| id[0]).collect();
    assert_eq!(ops, [0xA0, 0xA0, 0xF0, 0xF0]);
    let sent = tags_sent(&seen, 0);
    assert_eq!(sent.iter().map(Vec::len).collect::<Vec<_>>(), [32, 32]);
    assert_eq!(state.registered.len(), 64);
    let from = seen.borrow().len();
    fetch_round_with(
        dir.path(),
        &me,
        &fetching,
        Some(TagRegistration {
            custodian,
            tags: &wanted,
            caps: &mut caps,
        }),
        &mut state,
        t0 + MIN,
        2,
        &mut tag_custodian(&seen, None, false),
    );
    assert_eq!(
        tags_sent(&seen, from)
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>(),
        [6]
    );
    assert_eq!(state.registered.len(), 70);

    // Nothing to fetch or release: a TAGS-only dial.
    let seen = Seen::default();
    let report = fetch_round_with(
        dir.path(),
        &me,
        &BTreeMap::new(),
        Some(TagRegistration {
            custodian,
            tags: &wanted,
            caps: &mut CapabilityCache::default(),
        }),
        &mut FetchState::default(),
        t0,
        MAX_PAGES_PER_TRIGGER,
        &mut tag_custodian(&seen, None, false),
    );
    assert_eq!(report.dials, 1);
    assert!(seen
        .borrow()
        .iter()
        .all(|(_, r)| matches!(r, Rfc1Request::Tags { .. })));

    // The gate closed, or no registration: no TAGS frame at all.
    for gate in [Some(false), None] {
        set_handoff_gate_for_this_thread(gate);
        let seen = Seen::default();
        let mut state = FetchState::default();
        if gate.is_some() {
            fetch_round_with(
                dir.path(),
                &me,
                &fetching,
                Some(TagRegistration {
                    custodian,
                    tags: &wanted,
                    caps: &mut CapabilityCache::default(),
                }),
                &mut state,
                t0,
                MAX_PAGES_PER_TRIGGER,
                &mut tag_custodian(&seen, None, false),
            );
        } else {
            set_handoff_gate_for_this_thread(Some(true));
            fetch_round(
                dir.path(),
                &me,
                &fetching,
                &mut state,
                t0,
                MAX_PAGES_PER_TRIGGER,
                &mut tag_custodian(&seen, None, false),
            );
        }
        assert!(tags_sent(&seen, 0).is_empty(), "{gate:?}");
        assert!(state.registered.is_empty());
    }
}

// ---------------------------------------------------------------------------
// The forwarder's dial
// ---------------------------------------------------------------------------

fn due(n: u8, next_hop: [u8; 32], len: usize) -> DueForward {
    DueForward {
        digest: [n; 32],
        next_hop,
        depositor: k(0xA9),
        store_tag: [n; 16],
        rso1: vec![n; len],
        expires_at_ms: u64::MAX,
        attempts: 0,
        last_code: None,
    }
}

#[test]
fn forward_round_sends_delivers_with_a_zero_next_hop() {
    let _gates = Gates::on();
    let (h, other) = (k(0xE5), k(0xE6));
    let mut rows: Vec<DueForward> = (0..18u8).map(|i| due(i, h, 200)).collect();
    rows.insert(2, due(0x77, other, 200));
    let seen = Seen::default();
    let mut caps = CapabilityCache::default();
    let answers = forward_round(
        &h,
        &rows,
        &mut caps,
        now(),
        &mut fake(&seen, |n, _| match n {
            3 => handoff_result(CustodyCode::TagUnknown),
            5 => None,
            _ => handoff_result(CustodyCode::Ok),
        }),
    )
    .unwrap();
    // The first 16 rows held for H, in order (the other next hop's skipped).
    let mine: Vec<&DueForward> = rows.iter().filter(|r| r.next_hop == h).take(16).collect();
    assert_eq!(answers.len(), 16);
    for (i, ((digest, answer), row)) in answers.iter().zip(&mine).enumerate() {
        assert_eq!(*digest, row.digest);
        let want = match i {
            3 => Some(ItemAnswer::Code(CustodyCode::TagUnknown)),
            5 => None,
            _ => Some(ItemAnswer::Code(CustodyCode::Ok)),
        };
        assert_eq!(*answer, want, "{i}");
    }
    for (i, (id, request)) in seen.borrow().iter().enumerate() {
        assert_eq!(index_of(id, 0xB0), Some(i));
        let Rfc1Request::Handoff { record } = request else {
            panic!("{request:?}")
        };
        assert_eq!(record.kind, Rhw1Kind::Deliver);
        assert_eq!(record.next_hop, [0; 32]);
        assert_eq!(record.rso1, mine[i].rso1);
    }
    assert_eq!(caps.handoff(&h, now()), Some(true));

    // At most 512 KiB a dial: 8 objects of 60,000 bytes.
    let big: Vec<DueForward> = (0..16u8).map(|i| due(i, h, 60_000)).collect();
    let seen = Seen::default();
    let answers = forward_round(
        &h,
        &big,
        &mut caps,
        now(),
        &mut fake(&seen, |_, _| handoff_result(CustodyCode::Ok)),
    )
    .unwrap();
    assert_eq!((answers.len(), seen.borrow().len()), (8, 8));

    // An old final custodian: UNSUPPORTED, cached; the next round does not
    // dial it.
    let seen = Seen::default();
    let mut caps = CapabilityCache::default();
    let answers = forward_round(
        &h,
        &rows[..4],
        &mut caps,
        now(),
        &mut fake(&seen, |_, _| unsupported()),
    )
    .unwrap();
    assert_eq!(answers.len(), 3);
    assert!(answers
        .iter()
        .all(|(_, a)| *a == Some(ItemAnswer::Unsupported)));
    assert_eq!(caps.handoff(&h, now()), Some(false));
    let again = forward_round(&h, &rows[..4], &mut caps, now(), &mut no_dial).unwrap();
    assert_eq!(again, answers);
    // No row for H: no dial.
    assert!(
        forward_round(&other, &rows[..2], &mut caps, now(), &mut no_dial)
            .unwrap()
            .is_empty()
    );
    // The gate closed: refused before any dial.
    set_handoff_gate_for_this_thread(Some(false));
    assert_eq!(
        forward_round(&h, &rows, &mut caps, now(), &mut no_dial),
        Err(handoff_gate_closed())
    );
}

// ---------------------------------------------------------------------------
// Four nodes in one process: A -> F1 -> F2 -> B and the ACK back
// ---------------------------------------------------------------------------

/// Node indices: Alice, Bob, then the custodians F1, F2, F3.
const A: usize = 0;
const B: usize = 1;
const F1: usize = 2;
const F2: usize = 3;
const F3: usize = 4;

/// Nodes in one process: Alice and Bob share a confirmed session; every
/// node from F1 on runs custody and custody handoff.
struct Net {
    ids: Vec<Identity>,
    dirs: Vec<tempfile::TempDir>,
    key: IndexedSessionRecordKey,
}

/// One contact row: the node, and the nodes listed as its custodians.
type Row<'a> = (usize, &'a [usize]);

/// `books[n]`: node n's pinned contacts. Alice and Bob pair first.
fn net(seed: u8, books: &[&[Row<'_>]]) -> Net {
    crate::identity_store::test_enable_locked_file_identity_backend();
    let ids: Vec<Identity> = (0..books.len() as u8)
        .map(|n| Identity::from_seed(&[seed.wrapping_add(n); 32]))
        .collect();
    let dirs: Vec<tempfile::TempDir> = ids.iter().map(|_| tempfile::tempdir().unwrap()).collect();
    let hex_of = |n: usize| hex::encode(ids[n].public_key_bytes());
    for (n, rows) in books.iter().enumerate() {
        let rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|(who, custodians)| {
                serde_json::json!({
                    "petname": format!("node{who}"),
                    "public_tag": "",
                    "alias": "",
                    "address": "",
                    "pub_hex": hex_of(*who),
                    "pinned": true,
                    "lan_dial": "192.168.1.9:7420",
                    "internet_dial": "",
                    "custodians": custodians.iter().map(|c| hex_of(*c)).collect::<Vec<_>>(),
                })
            })
            .collect();
        std::fs::write(
            dirs[n].path().join("contacts.json"),
            serde_json::Value::Array(rows).to_string(),
        )
        .unwrap();
        if n >= F1 {
            crate::node_policy::save_policy(
                dirs[n].path(),
                &crate::node_policy::NodePolicy {
                    custody: true,
                    custody_handoff: true,
                    ..Default::default()
                },
            )
            .unwrap();
        }
    }
    let (a, b) = (dirs[A].path(), dirs[B].path());
    let a_bundle = local_bundle(a, &ids[A]).unwrap();
    let b_bundle = local_bundle(b, &ids[B]).unwrap();
    cache_peer_bundle(a, &b_bundle).unwrap();
    cache_peer_bundle(b, &a_bundle).unwrap();
    let (init, key) = create_initiator_pair_init(a, &ids[A], &b_bundle).unwrap();
    let replies = dispatch_frame(
        b,
        &ids[B],
        &a_bundle,
        &ids[A].public_key_bytes(),
        &wrap_pair_init(&ids[A], &init).unwrap(),
    )
    .unwrap();
    let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&replies[0]) else {
        panic!()
    };
    IndexedSessionStore::open(a)
        .unwrap()
        .confirm_verified_pair_response(
            &key,
            &init,
            &crate::pair_init::decode_response(&wire).unwrap(),
            now(),
        )
        .unwrap();
    Net { ids, dirs, key }
}

/// The two-friend world: Alice lists F1 for Bob and Bob lists F2 for Alice;
/// F1 knows Alice and F2, F2 knows F1 and Bob. Alice and Bob each hold
/// the far custodian's key (never the other way round), and each heard
/// the other announce its custodian with HANDOFF_INBOX.
fn two_friends(seed: u8) -> Net {
    let n = net(
        seed,
        &[
            &[(B, &[F1]), (F1, &[]), (F2, &[])],
            &[(A, &[F2]), (F2, &[]), (F1, &[])],
            &[(A, &[]), (F2, &[])],
            &[(F1, &[]), (B, &[])],
        ],
    );
    let (a, b, f1, f2) = (n.key_of(A), n.key_of(B), n.key_of(F1), n.key_of(F2));
    told(
        n.dir(A),
        &a,
        &b,
        &tag_hints(1, &[(custodian_tag(&b, &a, &f2), 0x01)]),
    );
    told(
        n.dir(B),
        &b,
        &a,
        &tag_hints(1, &[(custodian_tag(&a, &b, &f1), 0x01)]),
    );
    n
}

impl Net {
    fn dir(&self, n: usize) -> &Path {
        self.dirs[n].path()
    }

    fn key_of(&self, n: usize) -> [u8; 32] {
        self.ids[n].public_key_bytes()
    }

    /// A dial from node `from` to custodian `to` over a local LAN link:
    /// every frame goes to `to`'s real handler.
    fn dial(
        &self,
        to: usize,
        from: usize,
    ) -> impl FnMut(&[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> + '_ {
        move |frames: &[Vec<u8>]| {
            let link = InboundLink {
                carrier: OutboxCarrier::Lan,
                source: Some("192.168.1.30".parse().unwrap()),
            };
            let mut out = vec![b"RLB1-offer".to_vec()];
            let _untouched = crate::lan_gate::lan_user_switch_untouched();
            for f in frames {
                out.extend(handle_frame(
                    self.dir(to),
                    &self.ids[to],
                    &self.key_of(from),
                    &link,
                    f,
                    now(),
                )?);
            }
            Ok(out)
        }
    }

    /// Alice seals `text` for Bob.
    fn seal(&self, text: &str) -> Vec<u8> {
        let (a, alice) = (self.dir(A), &self.ids[A]);
        let mut store = IndexedSessionStore::open(a).unwrap();
        let (cert, reg) = crate::device_cert::ensure_local_device_certificate(
            a,
            alice,
            crate::paths::PRIMARY_DEVICE_ID,
        )
        .unwrap();
        let device = AuthorizedEndpointDevice::authorize(&cert, alice, &reg, now()).unwrap();
        let t = now();
        let end = store.session_expires_at(&self.key).unwrap();
        let expires = crate::outbox::envelope_expires_at(t, end).unwrap();
        let mut out = None;
        store
            .send_message_envelope(
                &self.key,
                text,
                &device,
                t,
                expires,
                t,
                &mut rand::rngs::OsRng,
                &mut |d, bytes| {
                    out = Some(bytes.to_vec());
                    Ok(*d)
                },
            )
            .unwrap();
        out.unwrap()
    }

    /// The RSO1 node `n` (Alice or Bob) leaves `packed` in, under its
    /// outbound store tag.
    fn rso1(&self, n: usize, packed: &[u8]) -> Vec<u8> {
        let tag = IndexedSessionStore::open(self.dir(n))
            .unwrap()
            .outbound_store_tag_for_object(&self.key, packed, now())
            .unwrap();
        rfc1_rso1(tag, packed).unwrap()
    }

    /// Node `n`'s plan for its peer: its listed custodians against what the
    /// peer announced.
    fn plan(&self, n: usize) -> Vec<PlanStep> {
        let peer = self.key_of(if n == A { B } else { A });
        let local = self.key_of(n);
        let listed = listed_custodians(self.dir(n), &peer, &local).unwrap();
        let announced = announced_custodians(self.dir(n), &local, &peer, now());
        custody_plan(
            &listed,
            announced.as_deref(),
            handoff_live(),
            &peer,
            &local,
            &|_| false,
            &|_, _| false,
        )
    }

    /// Node `n` leaves `rso1` at `via` for a FORWARD to `next_hop`.
    fn forward(&self, n: usize, via: usize, next_hop: [u8; 32], rso1: &[u8]) -> ItemAnswer {
        let answers = custody_batch(
            &self.key_of(via),
            &[CustodyItem::Forward {
                next_hop,
                rso1: rso1.to_vec(),
            }],
            &mut CapabilityCache::default(),
            now(),
            &mut self.dial(via, n),
        )
        .unwrap();
        answers[0].unwrap()
    }

    /// Custodian `from`'s forward rows due now.
    fn due(&self, from: usize) -> Vec<DueForward> {
        HandoffStore::open_existing(self.dir(from))
            .unwrap()
            .map(|s| s.forward_due(now(), 16).unwrap())
            .unwrap_or_default()
    }

    /// Every forward row custodian `n` holds (any state).
    fn forward_rows(&self, n: usize) -> i64 {
        HandoffStore::open_existing(self.dir(n))
            .unwrap()
            .map(|s| {
                let u = s.usage().unwrap();
                u.pending + u.handed + u.refused
            })
            .unwrap_or(0)
    }

    /// Custodian `from` hands its due rows on to `to`, marking each held
    /// one handed (as the forwarder does).
    fn hand_on(&self, from: usize, to: usize) -> ForwardAnswers {
        let rows = self.due(from);
        let next_hop = self.key_of(to);
        let answers = forward_round(
            &next_hop,
            &rows,
            &mut CapabilityCache::default(),
            now(),
            &mut self.dial(to, from),
        )
        .unwrap();
        let mut store = HandoffStore::open_existing(self.dir(from))
            .unwrap()
            .unwrap();
        for (digest, answer) in &answers {
            if let Some(ItemAnswer::Code(code)) = answer {
                if code.held() {
                    assert!(store.mark_handed(digest, &next_hop, *code).unwrap());
                }
            }
        }
        answers
    }

    /// Node `n` fetches at custodian `c` for its peer, registering its
    /// inbound tags there first; the TAGS frames sent are counted in `tags`.
    fn fetch(
        &self,
        n: usize,
        c: usize,
        state: &mut FetchState,
        tags: &Cell<usize>,
    ) -> crate::custody_client::FetchReport {
        let peer = self.key_of(if n == A { B } else { A });
        let fetching = inbound_tags(self.dir(n), &self.ids[n], &[peer], now()).unwrap();
        let register = inbound_register_tags(self.dir(n), &self.ids[n], &[peer], now()).unwrap();
        let mut inner = self.dial(c, n);
        let mut counted = |frames: &[Vec<u8>]| {
            tags.set(tags.get() + frames.iter().filter(|f| f[5] == OP_TAGS).count());
            inner(frames)
        };
        fetch_round_with(
            self.dir(n),
            &self.ids[n],
            &fetching,
            Some(TagRegistration {
                custodian: self.key_of(c),
                tags: &register,
                caps: &mut CapabilityCache::default(),
            }),
            state,
            now(),
            MAX_PAGES_PER_TRIGGER,
            &mut counted,
        )
    }
}

/// The whole chain: Alice's message reaches Bob through F1 and F2, and
/// Bob's ACK comes back through F2 and F1. Returns the message text.
fn run_two_friends(w: &Net) -> &'static str {
    let text = "two friends carried this";
    let (f1, f2) = (w.key_of(F1), w.key_of(F2));
    // Alice's plan: F1 is listed, Bob announced only F2 (HANDOFF_INBOX).
    assert_eq!(
        announced_custodians(w.dir(A), &w.key_of(A), &w.key_of(B), now()),
        Some(vec![ann(f2, true)])
    );
    assert_eq!(
        w.plan(A),
        [PlanStep::Forward {
            via: f1,
            next_hop: f2
        }]
    );
    let packed = w.seal(text);
    let rso1 = w.rso1(A, &packed);
    let digest = custody_digest(&packed);
    assert_eq!(
        w.forward(A, F1, f2, &rso1),
        ItemAnswer::Code(CustodyCode::Ok)
    );
    // F1 holds one forward row for F2 and no RFC1 object.
    assert_eq!(w.due(F1).len(), 1);
    assert!(!crate::friend_custody::custody_db_path(w.dir(F1)).exists());

    // Before Bob registered: TAG_UNKNOWN, the row stays pending.
    assert_eq!(
        w.hand_on(F1, F2),
        [(digest, Some(ItemAnswer::Code(CustodyCode::TagUnknown)))]
    );
    // Bob's fetch at F2 registers his inbound tags (TAGS before FETCH).
    let tags = Cell::new(0);
    let mut b_state = FetchState::default();
    let report = w.fetch(B, F2, &mut b_state, &tags);
    assert!(report.tags_ok, "{report:?}");
    assert_eq!((report.items, tags.get()), (0, 1));
    // F1 hands it on: STORED at F2; a DELIVER made no forward row there.
    assert_eq!(
        w.hand_on(F1, F2),
        [(digest, Some(ItemAnswer::Code(CustodyCode::Ok)))]
    );
    assert!(w.due(F1).is_empty());
    assert_eq!(w.forward_rows(F2), 0);
    // Alice's FORWARD again: DUPLICATE, nothing new to hand on.
    assert_eq!(
        w.forward(A, F1, f2, &rso1),
        ItemAnswer::Code(CustodyCode::Duplicate)
    );
    assert!(w.due(F1).is_empty());
    // Bob's next fetch takes it (no TAGS again: already registered).
    let report = w.fetch(B, F2, &mut b_state, &tags);
    assert_eq!(report.accepted_messages, 1, "{report:?}");
    assert_eq!(tags.get(), 1);
    let inbox = IndexedSessionStore::open(w.dir(B))
        .unwrap()
        .list_endpoint_inbox()
        .unwrap();
    assert_eq!(inbox.len(), 1);

    // Bob owes the ACK: the mirrored plan, FORWARD at F2 to F1.
    let (mut owed, _) = OwedAcks::open(w.dir(B)).unwrap();
    let acks = owed.list(now()).unwrap();
    assert_eq!(acks.len(), 1);
    assert_eq!(
        w.plan(B),
        [PlanStep::Forward {
            via: f2,
            next_hop: f1
        }]
    );
    let ack_rso1 = w.rso1(B, &acks[0].bytes);
    assert_eq!(
        w.forward(B, F2, f1, &ack_rso1),
        ItemAnswer::Code(CustodyCode::Ok)
    );
    // Alice registers at F1, F2 hands the ACK on, Alice fetches it.
    let a_tags = Cell::new(0);
    let mut a_state = FetchState::default();
    assert!(w.fetch(A, F1, &mut a_state, &a_tags).tags_ok);
    let ack_digest = custody_digest(&acks[0].bytes);
    assert_eq!(
        w.hand_on(F2, F1),
        [(ack_digest, Some(ItemAnswer::Code(CustodyCode::Ok)))]
    );
    let back = w.fetch(A, F1, &mut a_state, &a_tags);
    assert_eq!(back.accepted_acks, 1, "{back:?}");
    assert_eq!(a_tags.get(), 1);
    let mut store = IndexedSessionStore::open(w.dir(A)).unwrap();
    let sid = store.session_id_for_record_key(&w.key).unwrap();
    let mid = crate::envelope::Envelope::unpack(&packed)
        .unwrap()
        .message_id;
    assert_eq!(
        store
            .outstanding_delivery_state(&sid, &mid, &w.key_of(B))
            .unwrap(),
        Some(EndpointDeliveryState::Delivered)
    );
    text
}

#[test]
fn a_message_and_its_ack_travel_through_two_friends() {
    let _gates = Gates::on();
    let w = two_friends(0x41);
    run_two_friends(&w);
    // Each custodian handed on once and holds the object for its own
    // friend only.
    assert_eq!(w.forward_rows(F1), 1);
    assert_eq!(w.forward_rows(F2), 1);
}

#[test]
fn register_tags_cover_yesterday_to_tomorrow_with_their_expiry() {
    let _gates = Gates::on();
    let w = two_friends(0x51);
    let (b, a) = (w.dir(B), w.key_of(A));
    let register = inbound_register_tags(b, &w.ids[B], &[a], now()).unwrap();
    let fetching = inbound_tags(b, &w.ids[B], &[a], now()).unwrap();
    let local = crate::device_cert::ensure_local_device_certificate(
        b,
        &w.ids[B],
        crate::paths::PRIMARY_DEVICE_ID,
    )
    .unwrap()
    .0
    .device_ed_pub;
    let heads = IndexedSessionStore::open(b)
        .unwrap()
        .live_session_heads(&local, now())
        .unwrap();
    let days = register_days(heads[0].created_at_ms, heads[0].expires_at_ms, now());
    assert!(!days.is_empty() && days.len() <= 3);
    assert_eq!(register.len(), days.len());
    let mut expiries: Vec<u64> = register.values().copied().collect();
    expiries.sort_unstable();
    let want: Vec<u64> = days.iter().map(|d| register_expiry(*d)).collect();
    assert_eq!(expiries, want);
    // Today's tag is the one a fetch asks for; tomorrow's is registered
    // ahead of it.
    let today = now() / DAY;
    let today_tag = register
        .iter()
        .find(|(_, e)| **e == register_expiry(today))
        .map(|(t, _)| *t)
        .unwrap();
    assert!(fetching.contains_key(&today_tag));
    // Nobody else's sessions: no tags.
    assert!(inbound_register_tags(b, &w.ids[B], &[w.key_of(F1)], now())
        .unwrap()
        .is_empty());
}

/// The files of custodian `n`'s two stores (and their journals).
fn store_files(w: &Net, n: usize) -> Vec<std::path::PathBuf> {
    let mut out: Vec<std::path::PathBuf> = std::fs::read_dir(w.dir(n))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            name.starts_with("custody_handoff.sqlite") || name.starts_with("friend_custody.sqlite")
        })
        .collect();
    out.sort();
    out
}

/// Every file under `dir`.
fn all_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(all_files(&path));
        } else {
            out.push(path);
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn two_friends_never_learn_the_far_end() {
    let _gates = Gates::on();
    let w = two_friends(0x61);
    let text = run_two_friends(&w);
    for (custodian, near, far) in [(F1, A, B), (F2, B, A)] {
        let files = store_files(&w, custodian);
        assert!(
            files
                .iter()
                .any(|p| p.ends_with(crate::custody_handoff::HANDOFF_DB_FILE)),
            "{files:?}"
        );
        // The scan sees what a plain profile stores: the near end's key
        // (depositor and registrant) is there.
        let near = w.key_of(near);
        assert!(files.iter().any(|p| {
            let bytes = std::fs::read(p).unwrap();
            contains(&bytes, &near) || contains(&bytes, hex::encode(near).as_bytes())
        }));
        let key = w.key_of(far);
        for path in &files {
            let bytes = std::fs::read(path).unwrap();
            assert!(!contains(&bytes, &key), "{path:?} holds the far end's key");
            for hex_key in [hex::encode(key), hex::encode_upper(key)] {
                assert!(!contains(&bytes, hex_key.as_bytes()), "{path:?}");
            }
        }
        for path in all_files(w.dir(custodian)) {
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !contains(&bytes, text.as_bytes()),
                "{path:?} holds the text"
            );
        }
    }
}

#[test]
fn no_frame_sequence_builds_a_longer_chain() {
    let _gates = Gates::on();
    // Three custodians that all know each other, Alice and Bob.
    let w = net(
        0x71,
        &[
            &[(B, &[F1]), (F1, &[]), (F2, &[]), (F3, &[])],
            &[(A, &[]), (F1, &[]), (F2, &[]), (F3, &[])],
            &[(A, &[]), (B, &[]), (F2, &[]), (F3, &[])],
            &[(A, &[]), (B, &[]), (F1, &[]), (F3, &[])],
            &[(A, &[]), (B, &[]), (F1, &[]), (F2, &[])],
        ],
    );
    let custodians = [F1, F2, F3];
    let packed = w.seal("loop free");
    let rso1 = w.rso1(A, &packed);
    // Alice's FORWARD with next hop herself or F1 itself: NEXT_HOP_UNKNOWN.
    for next_hop in [w.key_of(A), w.key_of(F1)] {
        assert_eq!(
            w.forward(A, F1, next_hop, &rso1),
            ItemAnswer::Code(CustodyCode::NextHopUnknown)
        );
    }
    assert_eq!(w.forward_rows(F1), 0);
    // The one hop Alice may ask for.
    assert_eq!(
        w.forward(A, F1, w.key_of(F2), &rso1),
        ItemAnswer::Code(CustodyCode::Ok)
    );
    // Bob registers his inbound tags at every custodian, so a DELIVER is
    // stored wherever it goes.
    for c in custodians {
        let report = w.fetch(B, c, &mut FetchState::default(), &Cell::new(0));
        assert!(report.tags_ok, "{report:?}");
    }
    // Every custodian, as a link peer, tries every frame on every other:
    // a FORWARD (any next hop) is HOP_REFUSED (it is not the signer) and a
    // DELIVER is stored or a duplicate; neither ever makes a forward row.
    let everyone = [A, B, F1, F2, F3];
    for s in custodians {
        for r in custodians.into_iter().filter(|r| *r != s) {
            for next_hop in everyone.into_iter().filter(|h| *h != s) {
                assert_eq!(
                    w.forward(s, r, w.key_of(next_hop), &rso1),
                    ItemAnswer::Code(CustodyCode::HopRefused),
                    "{s} -> {r} next hop {next_hop}"
                );
            }
            let answers = forward_round(
                &w.key_of(r),
                &[DueForward {
                    digest: custody_digest(&packed),
                    next_hop: w.key_of(r),
                    depositor: w.key_of(A),
                    store_tag: [0; 16],
                    rso1: rso1.clone(),
                    expires_at_ms: u64::MAX,
                    attempts: 0,
                    last_code: None,
                }],
                &mut CapabilityCache::default(),
                now(),
                &mut w.dial(r, s),
            )
            .unwrap();
            assert!(
                matches!(answers[..], [(_, Some(ItemAnswer::Code(code)))] if code.held()),
                "{s} -> {r}: {answers:?}"
            );
        }
    }
    // The only forward row anywhere is Alice's at F1: a path has at most
    // two custodians.
    assert_eq!(
        custodians.map(|c| w.forward_rows(c)),
        [1, 0, 0],
        "rows at F1, F2, F3"
    );
    let rows = w.due(F1);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].depositor, w.key_of(A));
}

/// The frames a requester's dial carries, by op.
#[test]
fn a_fetch_dial_carries_tags_then_release_then_fetch() {
    let _gates = Gates::on();
    let dir = tempfile::tempdir().unwrap();
    let me = Identity::from_seed(&[0x64; 32]);
    let seen = Seen::default();
    let mut state = FetchState {
        pending_release: vec![[0x11; 32]],
        ..Default::default()
    };
    let wanted = BTreeMap::from([(tag(9), now() + DAY)]);
    fetch_round_with(
        dir.path(),
        &me,
        &fetch_tags(1),
        Some(TagRegistration {
            custodian: k(0xC8),
            tags: &wanted,
            caps: &mut CapabilityCache::default(),
        }),
        &mut state,
        now(),
        MAX_PAGES_PER_TRIGGER,
        &mut tag_custodian(&seen, None, false),
    );
    let ops: Vec<u8> = seen
        .borrow()
        .iter()
        .map(|(_, request)| match request {
            Rfc1Request::Tags { .. } => OP_TAGS,
            Rfc1Request::Release { .. } => OP_RELEASE,
            Rfc1Request::Fetch { .. } => OP_FETCH,
            Rfc1Request::Handoff { .. } => OP_HANDOFF,
            _ => 0,
        })
        .collect();
    assert_eq!(ops, [OP_TAGS, OP_RELEASE, OP_FETCH]);
}
