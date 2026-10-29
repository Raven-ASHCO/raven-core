use super::*;
use crate::carrier_admission::{opaque_indexed_body_for_tests, RelayableKind};
use crate::custody_gate::{set_custody_gates_for_this_thread, CustodyGates};
use crate::envelope::EnvType;
use std::net::IpAddr;

const NOW: u64 = 1_800_000_000_000;

/// Gates for this test thread; restored on drop. The LAN carrier gate is
/// the build's: no test turns `raven lan off` on meanwhile.
struct Gates {
    _lan: std::sync::RwLockReadGuard<'static, ()>,
}
impl Gates {
    fn set(live: bool, wan: bool) -> Self {
        let untouched = crate::lan_gate::lan_user_switch_untouched();
        set_custody_gates_for_this_thread(Some(CustodyGates { live, wan }));
        Gates { _lan: untouched }
    }
}
impl Drop for Gates {
    fn drop(&mut self) {
        set_custody_gates_for_this_thread(None);
    }
}

fn id(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

fn envelope(signer: &Identity, fill: u8) -> Envelope {
    let mut env = Envelope {
        env_type: EnvType::Message as u8,
        flags: 0,
        message_id: [fill; 16],
        routing_tag: [0x22; 16],
        dest_device_hint: 0,
        created_at: NOW,
        expires_at: NOW + 3_600_000,
        hop_limit: 8,
        replication_budget: 2,
        anti_replay_nonce: [0x33; 12],
        ratchet_header_ciphertext: vec![],
        message_ciphertext: opaque_indexed_body_for_tests(RelayableKind::Message, &[fill]),
        sender_authentication: vec![],
    };
    env.sign_with(signer);
    env
}

fn rso1_for(env: &Envelope, tag: u8) -> Vec<u8> {
    rfc1_rso1([tag; 16], &env.pack()).unwrap()
}

fn lan(ip: &str) -> InboundLink {
    InboundLink {
        carrier: OutboxCarrier::Lan,
        source: Some(ip.parse::<IpAddr>().unwrap()),
    }
}

/// Carol's data dir: Alice and Bob are pinned contacts, Dave is not pinned,
/// custody on.
struct Carol {
    dir: tempfile::TempDir,
    carol: Identity,
    alice: Identity,
    bob: Identity,
    dave: Identity,
}

impl Carol {
    fn new() -> Self {
        Self::in_dir(tempfile::tempdir().unwrap(), Setup::Plain)
    }

    /// Carol in a profile set up as `setup` (PP.17): plain, sealed from its
    /// first store, or with a store an older build created before sealing.
    fn with(setup: Setup) -> Self {
        Self::in_dir(crate::contact_book::tests::profile(), setup)
    }

    fn in_dir(dir: tempfile::TempDir, setup: Setup) -> Self {
        let (carol, alice, bob, dave) = (id(0xC0), id(0xA0), id(0xB0), id(0xD0));
        let row = |who: &Identity, name: &str, pinned: bool| {
            format!(
                r#"{{"petname":"{name}","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":{pinned},"lan_dial":"192.168.1.9:7420","internet_dial":""}}"#,
                hex::encode(who.public_key_bytes())
            )
        };
        std::fs::write(
            dir.path().join("contacts.json"),
            format!(
                "[{},{},{}]",
                row(&alice, "Alice", true),
                row(&bob, "Bob", true),
                row(&dave, "Dave", false)
            ),
        )
        .unwrap();
        if setup == Setup::Migrated {
            drop(older_open_at(&custody_db_path(dir.path())).unwrap());
        }
        if setup != Setup::Plain {
            crate::contact_book::tests::seal(dir.path());
        }
        if setup == Setup::Migrated {
            assert_eq!(schema(dir.path()), (SCHEMA_VERSION, Shape::Keyed));
        }
        let carol_dir = Self {
            dir,
            carol,
            alice,
            bob,
            dave,
        };
        carol_dir.custody(true);
        carol_dir
    }

    fn custody(&self, on: bool) {
        let policy = crate::node_policy::NodePolicy {
            custody: on,
            ..Default::default()
        };
        crate::node_policy::save_policy(self.dir.path(), &policy).unwrap();
    }

    fn call(&self, from: &Identity, link: InboundLink, request: Rfc1Request) -> Vec<Rfc1Reply> {
        fresh_windows(&from.public_key_bytes());
        let frame = encode_request(&[7; 8], &request);
        handle_frame(
            self.dir.path(),
            &self.carol,
            &from.public_key_bytes(),
            &link,
            &frame,
            NOW,
        )
        .unwrap()
        .iter()
        .map(|r| {
            let (req_id, reply) = decode_reply(r).unwrap();
            assert_eq!(req_id, [7; 8]);
            reply
        })
        .collect()
    }

    fn deposit(&self, from: &Identity, to: &Identity, rso1: Vec<u8>) -> CustodyCode {
        match self
            .call(
                from,
                lan("192.168.1.20"),
                Rfc1Request::Deposit {
                    recipient: to.public_key_bytes(),
                    rso1,
                },
            )
            .as_slice()
        {
            [Rfc1Reply::DepositResult { code, .. }] => *code,
            other => panic!("{other:?}"),
        }
    }

    fn fetch(&self, who: &Identity, tags: &[[u8; 16]], after: Option<[u8; 32]>) -> Vec<Rfc1Reply> {
        self.call(
            who,
            lan("192.168.1.21"),
            Rfc1Request::Fetch {
                tags: tags.to_vec(),
                after,
                max_items: 16,
            },
        )
    }
}

/// The handler's per-key rate windows are process-wide, and every test here
/// runs at NOW: a test's request must not count against another test's
/// window (no test here expects the handler's own throttle, nor the
/// depositor throttle of Phase 6b R7 a lab run's responses gate opens).
fn fresh_windows(key: &[u8; 32]) {
    for windows in [&DEPOSIT_WINDOWS, &FETCH_WINDOWS] {
        if let Some(map) = windows.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            map.remove(key);
        }
    }
    with_bad_deposits(|b| {
        b.windows.remove(key);
        b.throttled.remove(key);
    });
}

fn items(replies: &[Rfc1Reply]) -> usize {
    replies
        .iter()
        .filter(|r| matches!(r, Rfc1Reply::FetchItem { .. }))
        .count()
}

#[test]
fn requests_and_replies_roundtrip() {
    let env = envelope(&id(0xA0), 1);
    let requests = [
        Rfc1Request::Deposit {
            recipient: [0xB0; 32],
            rso1: rso1_for(&env, 9),
        },
        Rfc1Request::Fetch {
            tags: vec![[1; 16], [2; 16]],
            after: Some([3; 32]),
            max_items: 16,
        },
        Rfc1Request::Fetch {
            tags: vec![[1; 16]],
            after: None,
            max_items: 1,
        },
        Rfc1Request::Release {
            digests: vec![[4; 32], [5; 32]],
        },
    ];
    for request in requests {
        let frame = encode_request(&[9; 8], &request);
        assert!(frame_expects_reply(&frame) && !frame_is_terminal_reply(&frame));
        assert_eq!(
            decode_request(&frame).unwrap(),
            RequestDecode::Request([9; 8], request)
        );
    }
    let replies = [
        Rfc1Reply::DepositResult {
            code: CustodyCode::Duplicate,
            digest: [6; 32],
        },
        Rfc1Reply::FetchItem {
            rso1: rso1_for(&env, 9),
        },
        Rfc1Reply::FetchEnd {
            code: CustodyCode::Ok,
            returned: 3,
            next: Some([7; 32]),
        },
        Rfc1Reply::FetchEnd {
            code: CustodyCode::RateLimited,
            returned: 0,
            next: None,
        },
        Rfc1Reply::ReleaseResult {
            code: CustodyCode::Ok,
            released: 2,
        },
        Rfc1Reply::Unsupported { max_version: 1 },
    ];
    for reply in replies {
        let frame = encode_reply(&[8; 8], &reply);
        assert_eq!(frame_is_terminal_reply(&frame), reply.is_terminal());
        assert!(!frame_expects_reply(&frame));
        assert_eq!(decode_reply(&frame).unwrap(), ([8; 8], reply));
    }
    // Fixed lengths (§5).
    assert_eq!(
        encode_reply(
            &[0; 8],
            &Rfc1Reply::DepositResult {
                code: CustodyCode::Ok,
                digest: [0; 32]
            }
        )
        .len(),
        47
    );
    assert_eq!(
        encode_reply(
            &[0; 8],
            &Rfc1Reply::FetchEnd {
                code: CustodyCode::Ok,
                returned: 0,
                next: None
            }
        )
        .len(),
        49
    );
    assert_eq!(
        encode_reply(
            &[0; 8],
            &Rfc1Reply::ReleaseResult {
                code: CustodyCode::Ok,
                released: 0
            }
        )
        .len(),
        16
    );
    assert_eq!(
        encode_reply(&[0; 8], &Rfc1Reply::Unsupported { max_version: 1 }).len(),
        15
    );
}

#[test]
fn strict_decoding_negatives() {
    let fetch = |count: u8, has_after: u8, token: u8, max_items: u8| {
        let mut f = header(OP_FETCH, &[1; 8]);
        f.push(count);
        for i in 0..count {
            f.extend_from_slice(&[i; 16]);
        }
        f.push(has_after);
        f.extend_from_slice(&[token; 32]);
        f.push(max_items);
        f
    };
    let malformed = |f: &[u8]| {
        assert!(
            matches!(decode_request(f).unwrap(), RequestDecode::Malformed(_, _)),
            "{f:?}"
        )
    };
    assert!(decode_request(b"RFC1").is_err());
    assert!(decode_request(b"XXXX\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00").is_err());
    malformed(&fetch(0, 0, 0, 1));
    malformed(&fetch(33, 0, 0, 1));
    malformed(&fetch(1, 0, 5, 1)); // non-zero token without has_after
    malformed(&fetch(1, 2, 0, 1));
    malformed(&fetch(1, 0, 0, 0));
    malformed(&fetch(1, 0, 0, 17));
    let mut trailing = fetch(1, 0, 0, 1);
    trailing.push(0);
    malformed(&trailing);
    // Repeated tags are deduplicated.
    let mut dup = header(OP_FETCH, &[1; 8]);
    dup.push(2);
    dup.extend_from_slice(&[4; 16]);
    dup.extend_from_slice(&[4; 16]);
    dup.push(0);
    dup.extend_from_slice(&[0; 32]);
    dup.push(1);
    let RequestDecode::Request(_, Rfc1Request::Fetch { tags, .. }) = decode_request(&dup).unwrap()
    else {
        panic!()
    };
    assert_eq!(tags, vec![[4; 16]]);
    // Unknown version, unknown op, a reply op as a request: UNSUPPORTED.
    let mut v2 = fetch(1, 0, 0, 1);
    v2[4] = 2;
    assert_eq!(
        decode_request(&v2).unwrap(),
        RequestDecode::Unsupported([1; 8])
    );
    let reply_as_request = encode_reply(
        &[1; 8],
        &Rfc1Reply::ReleaseResult {
            code: CustodyCode::Ok,
            released: 0,
        },
    );
    assert_eq!(
        decode_request(&reply_as_request).unwrap(),
        RequestDecode::Unsupported([1; 8])
    );
    // DEPOSIT length must be exact; RELEASE count bounded.
    let env = envelope(&id(0xA0), 1);
    let mut deposit = encode_request(
        &[1; 8],
        &Rfc1Request::Deposit {
            recipient: [0; 32],
            rso1: rso1_for(&env, 1),
        },
    );
    deposit.push(0);
    malformed(&deposit);
    let mut release = header(OP_RELEASE, &[1; 8]);
    release.push(0);
    malformed(&release);
}

#[test]
fn rso1_inside_rfc1_is_stricter_than_store_object_v1() {
    let alice = id(0xA0);
    let env = envelope(&alice, 2);
    let good = rso1_for(&env, 3);
    assert!(check_rfc1_rso1(&good).is_ok());
    // A custody signature (flags) is refused.
    let mut signed = StoreObject::unpack(&good).unwrap();
    signed.sign_custody(&id(0x99)).unwrap();
    assert_eq!(
        check_rfc1_rso1(&signed.pack().unwrap()).unwrap_err(),
        "RFC1_RSO1_FLAGS"
    );
    // A lifetime other than the envelope's is refused.
    let mut later = StoreObject::unpack(&good).unwrap();
    later.created_at_ms += 1;
    assert_eq!(
        check_rfc1_rso1(&later.pack().unwrap()).unwrap_err(),
        "RFC1_RSO1_LIFETIME"
    );
}

#[test]
fn deposit_fetch_release_end_to_end() {
    let _g = Gates::set(true, false);
    let c = Carol::new();
    let env = envelope(&c.alice, 1);
    let rso1 = rso1_for(&env, 0x11);
    assert_eq!(c.deposit(&c.alice, &c.bob, rso1.clone()), CustodyCode::Ok);
    assert_eq!(
        c.deposit(&c.alice, &c.bob, rso1.clone()),
        CustodyCode::Duplicate
    );
    // Same object under another tag, or for another recipient: CONFLICT.
    assert_eq!(
        c.deposit(&c.alice, &c.bob, rso1_for(&env, 0x12)),
        CustodyCode::Conflict
    );
    assert_eq!(
        c.deposit(&c.alice, &c.alice, rso1.clone()),
        CustodyCode::RecipientNotAccepted
    );
    // Only Bob, with the tag, sees it.
    let got = c.fetch(&c.bob, &[[0x11; 16]], None);
    assert_eq!(items(&got), 1);
    assert!(matches!(
        got.last(),
        Some(Rfc1Reply::FetchEnd {
            code: CustodyCode::Ok,
            returned: 1,
            next: None
        })
    ));
    assert_eq!(items(&c.fetch(&c.bob, &[[0x12; 16]], None)), 0);
    // A co-custodian / third party with the tag sees and releases nothing.
    let other = id(0xE0);
    let digest = custody_digest(&env.pack());
    let mut store = CustodyStore::open_existing(c.dir.path()).unwrap().unwrap();
    assert_eq!(
        store
            .fetch(&other.public_key_bytes(), &[[0x11; 16]], None, 16, NOW)
            .unwrap()
            .items
            .len(),
        0
    );
    assert_eq!(
        store.release(&other.public_key_bytes(), &[digest]).unwrap(),
        0
    );
    // Bob releases it: deleted with its payload and both parties (PP.17);
    // only the digest stays.
    match c
        .call(
            &c.bob,
            lan("192.168.1.21"),
            Rfc1Request::Release {
                digests: vec![digest],
            },
        )
        .as_slice()
    {
        [Rfc1Reply::ReleaseResult {
            code: CustodyCode::Ok,
            released: 1,
        }] => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(items(&c.fetch(&c.bob, &[[0x11; 16]], None)), 0);
    assert_eq!(store.usage().unwrap().0, 0);
    // A re-deposit of a released object is a duplicate, not a resurrection.
    assert_eq!(c.deposit(&c.alice, &c.bob, rso1), CustodyCode::Duplicate);
    assert_eq!(items(&c.fetch(&c.bob, &[[0x11; 16]], None)), 0);
}

#[test]
fn deposit_admission_rules() {
    let _g = Gates::set(true, false);
    let c = Carol::new();
    // The depositor must be the outer signer.
    let by_bob = envelope(&c.bob, 3);
    assert_eq!(
        c.deposit(&c.alice, &c.dave, rso1_for(&by_bob, 1)),
        CustodyCode::RefusedObject
    );
    // Canonical hop fields only.
    let mut hop = envelope(&c.alice, 4);
    hop.hop_limit = 7;
    hop.sign_with(&c.alice);
    assert_eq!(
        c.deposit(&c.alice, &c.bob, rso1_for(&hop, 1)),
        CustodyCode::RefusedObject
    );
    // Recipient must be a pinned contact, not the depositor, not Carol.
    let env = envelope(&c.alice, 5);
    assert_eq!(
        c.deposit(&c.alice, &c.dave, rso1_for(&env, 1)),
        CustodyCode::RecipientNotAccepted
    );
    assert_eq!(
        c.deposit(&c.alice, &c.carol, rso1_for(&env, 1)),
        CustodyCode::RecipientNotAccepted
    );
    // Expired.
    let mut old = envelope(&c.alice, 6);
    old.created_at = NOW - 7_200_000;
    old.expires_at = NOW - 1;
    old.sign_with(&c.alice);
    assert_eq!(
        c.deposit(&c.alice, &c.bob, rso1_for(&old, 1)),
        CustodyCode::Expired
    );
    // Custody off: POLICY_DENIED, nothing stored; FETCH still answers.
    c.custody(false);
    assert_eq!(
        c.deposit(&c.alice, &c.bob, rso1_for(&env, 2)),
        CustodyCode::PolicyDenied
    );
    assert!(CustodyStore::open_existing(c.dir.path()).unwrap().is_none());
    assert_eq!(items(&c.fetch(&c.bob, &[[2; 16]], None)), 0);
    assert!(
        CustodyStore::open_existing(c.dir.path()).unwrap().is_none(),
        "FETCH never creates the store"
    );
}

#[test]
fn gate_and_peer_rules_apply_to_every_op() {
    let c = Carol::new();
    let env = envelope(&c.alice, 7);
    let deposit = || Rfc1Request::Deposit {
        recipient: c.bob.public_key_bytes(),
        rso1: rso1_for(&env, 1),
    };
    // Gate closed: HOLD, nothing touched.
    {
        let _g = Gates::set(false, false);
        assert!(matches!(
            c.call(&c.alice, lan("192.168.1.20"), deposit()).as_slice(),
            [Rfc1Reply::DepositResult {
                code: CustodyCode::Hold,
                ..
            }]
        ));
    }
    let _g = Gates::set(true, false);
    // LAN from a public source without WAN custody: HOLD.
    assert!(matches!(
        c.call(&c.alice, lan("203.0.113.5"), deposit()).as_slice(),
        [Rfc1Reply::DepositResult {
            code: CustodyCode::Hold,
            ..
        }]
    ));
    // Internet links without WAN custody: HOLD.
    let inet = InboundLink {
        carrier: OutboxCarrier::Internet,
        source: None,
    };
    assert!(matches!(
        c.call(&c.alice, inet, deposit()).as_slice(),
        [Rfc1Reply::DepositResult {
            code: CustodyCode::Hold,
            ..
        }]
    ));
    // A link peer that is not pinned: NOT_VERIFIED, on FETCH too.
    assert!(matches!(
        c.call(&c.dave, lan("192.168.1.20"), deposit()).as_slice(),
        [Rfc1Reply::DepositResult {
            code: CustodyCode::NotVerified,
            ..
        }]
    ));
    assert!(matches!(
        c.fetch(&c.dave, &[[1; 16]], None).as_slice(),
        [Rfc1Reply::FetchEnd {
            code: CustodyCode::NotVerified,
            ..
        }]
    ));
    assert!(CustodyStore::open_existing(c.dir.path()).unwrap().is_none());
    // Unknown version: UNSUPPORTED, echoing req_id.
    let mut frame = encode_request(&[5; 8], &deposit());
    frame[4] = 9;
    let replies = handle_frame(
        c.dir.path(),
        &c.carol,
        &c.alice.public_key_bytes(),
        &lan("192.168.1.20"),
        &frame,
        NOW,
    )
    .unwrap();
    assert_eq!(
        decode_reply(&replies[0]).unwrap(),
        ([5; 8], Rfc1Reply::Unsupported { max_version: 1 })
    );
}

/// Phase 3 P3.19: a p2p link as `gate_and_peer` sees it, with the custody
/// gates `(live, wan)` and the p2p carrier gate `p2p` set for this thread
/// (the LAN and Internet carriers open), restored on drop.
struct P2pGates {
    _custody: Gates,
}

impl P2pGates {
    fn set(wan: bool, p2p: bool) -> Self {
        let custody = Gates::set(true, wan);
        crate::custody_gate::set_carrier_gates_for_this_thread(Some(crate::outbox::CarrierGates {
            lan: true,
            internet: true,
            p2p,
            nearby: false,
            onion: false,
        }));
        P2pGates { _custody: custody }
    }
}

impl Drop for P2pGates {
    fn drop(&mut self) {
        crate::custody_gate::set_carrier_gates_for_this_thread(None);
    }
}

const P2P_LINK: InboundLink = InboundLink {
    carrier: OutboxCarrier::P2p,
    source: None,
};

fn deposit_code(replies: &[Rfc1Reply]) -> CustodyCode {
    match replies {
        [Rfc1Reply::DepositResult { code, .. }] => *code,
        other => panic!("{other:?}"),
    }
}

#[test]
fn p2p_link_with_wan_and_p2p_gate_stores() {
    let _g = P2pGates::set(true, true);
    let c = Carol::new();
    let env = envelope(&c.alice, 0x61);
    let deposit = Rfc1Request::Deposit {
        recipient: c.bob.public_key_bytes(),
        rso1: rso1_for(&env, 0x61),
    };
    assert_eq!(
        deposit_code(&c.call(&c.alice, P2P_LINK, deposit)),
        CustodyCode::Ok
    );
    assert!(CustodyStore::open_existing(c.dir.path()).unwrap().is_some());
    // Bob fetches it over a p2p link too.
    let fetched = c.call(
        &c.bob,
        P2P_LINK,
        Rfc1Request::Fetch {
            tags: vec![[0x61; 16]],
            after: None,
            max_items: 16,
        },
    );
    assert_eq!(items(&fetched), 1, "{fetched:?}");
}

#[test]
fn p2p_link_without_wan_is_hold_and_creates_no_file() {
    let _g = P2pGates::set(false, true);
    let c = Carol::new();
    let env = envelope(&c.alice, 0x62);
    let deposit = Rfc1Request::Deposit {
        recipient: c.bob.public_key_bytes(),
        rso1: rso1_for(&env, 0x62),
    };
    assert_eq!(
        deposit_code(&c.call(&c.alice, P2P_LINK, deposit)),
        CustodyCode::Hold
    );
    assert!(matches!(
        c.call(
            &c.bob,
            P2P_LINK,
            Rfc1Request::Fetch {
                tags: vec![[0x62; 16]],
                after: None,
                max_items: 16,
            },
        )
        .as_slice(),
        [Rfc1Reply::FetchEnd {
            code: CustodyCode::Hold,
            ..
        }]
    ));
    assert!(CustodyStore::open_existing(c.dir.path()).unwrap().is_none());
    assert!(!custody_db_path(c.dir.path()).exists());
}

#[test]
fn p2p_link_with_wan_but_p2p_carrier_gate_off_is_hold() {
    let _g = P2pGates::set(true, false);
    let c = Carol::new();
    let env = envelope(&c.alice, 0x63);
    let deposit = Rfc1Request::Deposit {
        recipient: c.bob.public_key_bytes(),
        rso1: rso1_for(&env, 0x63),
    };
    assert_eq!(
        deposit_code(&c.call(&c.alice, P2P_LINK, deposit)),
        CustodyCode::Hold
    );
    assert!(CustodyStore::open_existing(c.dir.path()).unwrap().is_none());
    assert!(!custody_db_path(c.dir.path()).exists());
}

#[test]
fn fetch_pages_resume_from_the_cursor() {
    let _g = Gates::set(true, false);
    let c = Carol::new();
    let mut store = CustodyStore::open_or_create(c.dir.path()).unwrap();
    for i in 0..20u8 {
        let env = envelope(&c.alice, i);
        let rso1 = rso1_for(&env, 0x31);
        let digest = custody_digest(&env.pack());
        assert_eq!(
            store
                .deposit(
                    &digest,
                    &c.bob.public_key_bytes(),
                    &c.alice.public_key_bytes(),
                    &[0x31; 16],
                    &rso1,
                    env.expires_at,
                    NOW
                )
                .unwrap(),
            CustodyCode::Ok
        );
    }
    let first = c.fetch(&c.bob, &[[0x31; 16]], None);
    assert_eq!(items(&first), 16);
    let Some(Rfc1Reply::FetchEnd {
        next: Some(token), ..
    }) = first.last().cloned()
    else {
        panic!("{:?}", first.last())
    };
    let second = c.fetch(&c.bob, &[[0x31; 16]], Some(token));
    assert_eq!(items(&second), 4);
    assert!(matches!(
        second.last(),
        Some(Rfc1Reply::FetchEnd { next: None, .. })
    ));
}

#[test]
fn caps_refuse_and_never_evict() {
    let c = Carol::new();
    let mut store = CustodyStore::open_or_create(c.dir.path()).unwrap();
    let (a, b) = (c.alice.public_key_bytes(), c.bob.public_key_bytes());
    for i in 0..MAX_PAIR_ROWS {
        let env = envelope(&c.alice, (i % 250) as u8);
        let mut digest = custody_digest(&env.pack());
        digest[0] = (i >> 8) as u8;
        digest[1] = i as u8;
        // A tiny RSO1 stand-in keeps this fast (the store does not re-parse).
        assert_eq!(
            store
                .deposit(
                    &digest,
                    &b,
                    &a,
                    &[1; 16],
                    &[0u8; 16],
                    NOW + 1_000,
                    NOW - 120_000
                )
                .unwrap(),
            CustodyCode::Ok,
            "{i}"
        );
    }
    let over = store
        .deposit(&[0xFF; 32], &b, &a, &[1; 16], &[0u8; 16], NOW + 1_000, NOW)
        .unwrap();
    assert_eq!(over, CustodyCode::Quota);
    assert_eq!(store.usage().unwrap().0, MAX_PAIR_ROWS);
    // The reverse pair is a separate bucket.
    assert_eq!(
        store
            .deposit(&[0xFE; 32], &a, &b, &[1; 16], &[0u8; 16], NOW + 1_000, NOW)
            .unwrap(),
        CustodyCode::Ok
    );
}

#[test]
fn deposit_rate_window_counts_every_attempt() {
    let key = [0x42; 32];
    let windows: Mutex<Option<HashMap<[u8; 32], Window>>> = Mutex::new(None);
    for _ in 0..MAX_DEPOSITS_PER_MINUTE {
        assert!(charge(&windows, key, MAX_DEPOSITS_PER_MINUTE, NOW));
    }
    assert!(!charge(&windows, key, MAX_DEPOSITS_PER_MINUTE, NOW + 1));
    assert!(charge(
        &windows,
        key,
        MAX_DEPOSITS_PER_MINUTE,
        NOW + WINDOW_MS
    ));
}

/// Phase 6b P6.25 (S19, S20): a pinned contact's requests this custodian
/// refuses for its rate, its quota or what it sent are noted about it (as
/// depositor; a forward it had no right to ask, as the forwarder), via its
/// link; the answers are exactly as before, and nothing is noted while the
/// events gate is shut or for a refusal of the gate or the contact rule.
#[test]
fn a_depositors_flood_and_bad_objects_are_noted_about_it() {
    use crate::security_events::{Attribution, CarrierRole, SecKind, Via};
    use crate::security_sense::tests::{Capture, Shut};
    let _g = Gates::set(true, false);
    let c = Carol::new();
    // Erin: a pinned contact only this test deposits as, her rate window
    // full at NOW.
    let erin = id(0xE5);
    let book = c.dir.path().join("contacts.json");
    let rows = std::fs::read_to_string(&book).unwrap();
    std::fs::write(
        &book,
        rows.replacen(
            "[",
            &format!(
                r#"[{{"petname":"Erin","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":true,"lan_dial":"","internet_dial":""}},"#,
                hex::encode(erin.public_key_bytes())
            ),
            1,
        ),
    )
    .unwrap();
    for _ in 0..MAX_DEPOSITS_PER_MINUTE {
        charge(
            &DEPOSIT_WINDOWS,
            erin.public_key_bytes(),
            MAX_DEPOSITS_PER_MINUTE,
            NOW,
        );
    }
    let erin_deposits = || {
        let frame = encode_request(
            &[7; 8],
            &Rfc1Request::Deposit {
                recipient: c.bob.public_key_bytes(),
                rso1: rso1_for(&envelope(&erin, 9), 1),
            },
        );
        handle_frame(
            c.dir.path(),
            &c.carol,
            &erin.public_key_bytes(),
            &lan("192.168.1.22"),
            &frame,
            NOW,
        )
        .unwrap()
    };
    let rate_limited = vec![encode_reply(
        &[7; 8],
        &Rfc1Reply::DepositResult {
            code: CustodyCode::RateLimited,
            digest: [0; 32],
        },
    )];
    {
        let shut = Shut::start();
        assert_eq!(erin_deposits(), rate_limited);
        assert_eq!(shut.noted(), 0);
    }
    let Some(cap) = Capture::start() else {
        return;
    };
    let link = Via::DirectLink(OutboxCarrier::Lan);
    // S19: over her rate.
    assert_eq!(erin_deposits(), rate_limited);
    // S19: Bob's object deposited by Alice (only its signer may deposit it).
    let by_bob = envelope(&c.bob, 3);
    assert_eq!(
        c.deposit(&c.alice, &c.dave, rso1_for(&by_bob, 1)),
        CustodyCode::RefusedObject
    );
    // A request that breaks the rules from a pinned contact: MALFORMED.
    let mut malformed = encode_request(
        &[7; 8],
        &Rfc1Request::Fetch {
            tags: vec![[1; 16]],
            after: None,
            max_items: 1,
        },
    );
    malformed.push(0);
    let replies = handle_frame(
        c.dir.path(),
        &c.carol,
        &c.alice.public_key_bytes(),
        &lan("192.168.1.20"),
        &malformed,
        NOW,
    )
    .unwrap();
    assert!(matches!(
        decode_reply(&replies[0]).unwrap().1,
        Rfc1Reply::FetchEnd {
            code: CustodyCode::Malformed,
            ..
        }
    ));
    // Not a contact Carol pinned: the contact rule's refusal is no event.
    assert_eq!(
        c.deposit(&c.dave, &c.bob, rso1_for(&envelope(&c.dave, 2), 1)),
        CustodyCode::NotVerified
    );
    let alice = Attribution::Contact {
        peer: c.alice.public_key_bytes(),
    };
    assert_eq!(
        cap.kinds(),
        vec![
            (
                SecKind::DepositorFlood,
                Attribution::Contact {
                    peer: erin.public_key_bytes()
                },
                link
            ),
            (SecKind::DepositorBadObject, alice, link),
            (SecKind::DepositorBadObject, alice, link),
        ]
    );
    // A forward refused for its signer is about the forwarder.
    cap.clear();
    note_depositor(
        &c.alice.public_key_bytes(),
        &lan("192.168.1.20"),
        &[
            Rfc1Reply::HandoffResult {
                code: CustodyCode::HopRefused,
                digest: [1; 32],
            },
            Rfc1Reply::FetchEnd {
                code: CustodyCode::Quota,
                returned: 0,
                next: None,
            },
            Rfc1Reply::DepositResult {
                code: CustodyCode::Ok,
                digest: [2; 32],
            },
        ],
        NOW,
    );
    assert_eq!(
        cap.kinds(),
        vec![
            (
                SecKind::HandoffRefused,
                Attribution::Carrier {
                    carrier: c.alice.public_key_bytes(),
                    role: CarrierRole::Depositor,
                },
                link
            ),
            (SecKind::DepositorFlood, alice, link),
        ]
    );
}

/// Phase 6b R7 (design A, step P6.28): the tenth object from one depositor
/// refused within an hour (REFUSED_OBJECT or MALFORMED) makes this custodian
/// answer RATE_LIMITED to its deposits (plain and letters here; handoff
/// FORWARDs share the check) for an hour; then they are taken again. A refusal of the window's ninth
/// or another depositor's changes nothing, nor does anything while the
/// responses gate is shut.
#[test]
fn ten_refused_objects_throttle_a_depositor_for_an_hour() {
    use crate::security_sense::tests::{Responses, Shut};
    let _g = Gates::set(true, false);
    let c = Carol::new();
    // Frank and Grace: pinned contacts only this test deposits as (other
    // tests reset Alice's windows while they run).
    let (frank, grace) = (id(0xF4), id(0xF5));
    let book = c.dir.path().join("contacts.json");
    let rows = std::fs::read_to_string(&book).unwrap();
    let row = |who: &Identity, name: &str| {
        format!(
            r#"{{"petname":"{name}","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":true,"lan_dial":"","internet_dial":""}},"#,
            hex::encode(who.public_key_bytes())
        )
    };
    std::fs::write(
        &book,
        rows.replacen(
            "[",
            &format!("[{}{}", row(&frank, "Frank"), row(&grace, "Grace")),
            1,
        ),
    )
    .unwrap();
    let key = frank.public_key_bytes();
    // Bob's object deposited by Frank: refused (only its signer may).
    let refused = rso1_for(&envelope(&c.bob, 0x31), 1);
    let deposit_by = |who: &[u8; 32], rso1: &[u8], at: u64| {
        let frame = encode_request(
            &[7; 8],
            &Rfc1Request::Deposit {
                recipient: c.bob.public_key_bytes(),
                rso1: rso1.to_vec(),
            },
        );
        let replies = handle_frame(
            c.dir.path(),
            &c.carol,
            who,
            &lan("192.168.1.23"),
            &frame,
            at,
        )
        .unwrap();
        match decode_reply(&replies[0]).unwrap().1 {
            Rfc1Reply::DepositResult { code, .. } => code,
            other => panic!("{other:?}"),
        }
    };
    let deposit_at = |rso1: &[u8], at: u64| deposit_by(&key, rso1, at);
    fresh_windows(&key);
    {
        let _shut = Shut::start();
        for _ in 0..DEPOSITOR_BAD_OBJECTS {
            assert_eq!(deposit_at(&refused, NOW), CustodyCode::RefusedObject);
        }
        assert!(!depositor_throttled(&key, NOW));
    }
    fresh_windows(&key);
    let Some(_on) = Responses::on() else {
        return;
    };
    for _ in 1..DEPOSITOR_BAD_OBJECTS {
        assert_eq!(deposit_at(&refused, NOW), CustodyCode::RefusedObject);
    }
    // Another depositor's refusal counts for that one only.
    let other = grace.public_key_bytes();
    fresh_windows(&other);
    assert_eq!(
        deposit_by(&other, &refused, NOW),
        CustodyCode::RefusedObject
    );
    assert!(!depositor_throttled(&key, NOW));
    // Frank's own object, valid past the throttle.
    let mut good = envelope(&frank, 0x33);
    good.expires_at = NOW + 3 * DEPOSITOR_THROTTLE_MS;
    good.sign_with(&frank);
    let own = rso1_for(&good, 2);
    assert_eq!(deposit_at(&refused, NOW + 1), CustodyCode::RefusedObject);
    assert!(depositor_throttled(&key, NOW + 1));
    assert!(!depositor_throttled(&other, NOW + 1));
    // Throttled: even a good object waits, and a letter.
    assert_eq!(deposit_at(&own, NOW + 2), CustodyCode::RateLimited);
    let letter = deposit_letter(
        c.dir.path(),
        &c.carol,
        &key,
        &c.bob.public_key_bytes(),
        b"x",
        NOW + 2,
    );
    assert_eq!(letter.0, CustodyCode::RateLimited);
    // An hour after the tenth: taken again.
    let open = NOW + 1 + DEPOSITOR_THROTTLE_MS;
    assert!(depositor_throttled(&key, open - 1));
    assert!(!depositor_throttled(&key, open));
    fresh_windows_rate_only(&key);
    assert_eq!(deposit_at(&own, open), CustodyCode::Ok);
}

/// Phase 6 review (sensing-5): a depositor whose clock runs ahead (its own
/// signed object dated 6 minutes past this custodian's clock) is answered
/// REFUSED_OBJECT as before, but each is noted as SEC_CLOCK_SKEW about it,
/// never as a bad object, and ten of them do not throttle it. Someone
/// else's object dated ahead is still a bad object; a letter is told
/// apart the same way.
#[test]
fn a_depositor_clock_ahead_is_clock_skew_not_a_bad_object() {
    use crate::security_events::{Attribution, SecKind, Via};
    use crate::security_sense::tests::Responses;
    let _g = Gates::set(true, false);
    let c = Carol::new();
    // Heidi: a pinned contact only this test deposits as.
    let heidi = id(0xF6);
    let book = c.dir.path().join("contacts.json");
    let rows = std::fs::read_to_string(&book).unwrap();
    std::fs::write(
        &book,
        rows.replacen(
            "[",
            &format!(
                r#"[{{"petname":"Heidi","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":true,"lan_dial":"","internet_dial":""}},"#,
                hex::encode(heidi.public_key_bytes())
            ),
            1,
        ),
    )
    .unwrap();
    let key = heidi.public_key_bytes();
    fresh_windows(&key);
    let Some(on) = Responses::on() else {
        return;
    };
    let ahead = NOW + 6 * 60_000;
    let dated = |signer: &Identity, fill: u8| {
        let mut env = envelope(signer, fill);
        env.created_at = ahead;
        env.sign_with(signer);
        rso1_for(&env, fill)
    };
    let deposit = |rso1: Vec<u8>| {
        fresh_windows_rate_only(&key);
        let frame = encode_request(
            &[7; 8],
            &Rfc1Request::Deposit {
                recipient: c.bob.public_key_bytes(),
                rso1,
            },
        );
        let replies = handle_frame(
            c.dir.path(),
            &c.carol,
            &key,
            &lan("192.168.1.24"),
            &frame,
            NOW,
        )
        .unwrap();
        match decode_reply(&replies[0]).unwrap().1 {
            Rfc1Reply::DepositResult { code, .. } => code,
            other => panic!("{other:?}"),
        }
    };
    let own = dated(&heidi, 0x36);
    for n in 0..DEPOSITOR_BAD_OBJECTS {
        assert_eq!(deposit(own.clone()), CustodyCode::RefusedObject, "{n}");
    }
    assert!(
        !depositor_throttled(&key, NOW + 1),
        "a clock is no bad object"
    );
    let who = Attribution::Contact { peer: key };
    let link = Via::DirectLink(OutboxCarrier::Lan);
    assert_eq!(
        on.0.kinds(),
        vec![(SecKind::ClockSkew, who, link); DEPOSITOR_BAD_OBJECTS as usize]
    );
    // Bob's object dated ahead, deposited by Heidi: a bad object still.
    on.0.clear();
    assert_eq!(deposit(dated(&c.bob, 0x37)), CustodyCode::RefusedObject);
    assert_eq!(on.0.kinds(), vec![(SecKind::DepositorBadObject, who, link)]);
    // A letter: her own dated ahead is her clock, Bob's is not.
    let letter = |signer: &Identity| {
        crate::carrier_admission::opaque_letter_for_tests(
            signer,
            &c.alice.public_key_bytes(),
            ahead,
            ahead + 3_600_000,
            512,
            0x38,
        )
    };
    let alice = c.alice.public_key_bytes();
    fresh_windows_rate_only(&key);
    let mine = deposit_letter(c.dir.path(), &c.carol, &key, &alice, &letter(&heidi), NOW);
    assert_eq!((mine.0, mine.2), (CustodyCode::RefusedObject, true));
    fresh_windows_rate_only(&key);
    let bobs = deposit_letter(c.dir.path(), &c.carol, &key, &alice, &letter(&c.bob), NOW);
    assert_eq!((bobs.0, bobs.2), (CustodyCode::RefusedObject, false));
    fresh_windows(&key);
}

/// [`fresh_windows`] for the rate windows only (the R7 test keeps its
/// throttle).
fn fresh_windows_rate_only(key: &[u8; 32]) {
    for windows in [&DEPOSIT_WINDOWS, &FETCH_WINDOWS] {
        if let Some(map) = windows.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            map.remove(key);
        }
    }
}

#[test]
fn maintenance_drops_expired_and_unpinned_parties() {
    let c = Carol::new();
    let mut store = CustodyStore::open_or_create(c.dir.path()).unwrap();
    let (a, b, d) = (
        c.alice.public_key_bytes(),
        c.bob.public_key_bytes(),
        c.dave.public_key_bytes(),
    );
    store
        .deposit(&[1; 32], &b, &a, &[1; 16], &[0u8; 16], NOW + 10, NOW)
        .unwrap();
    store
        .deposit(&[2; 32], &b, &a, &[1; 16], &[0u8; 16], NOW + 100_000, NOW)
        .unwrap();
    store
        .deposit(&[3; 32], &d, &a, &[1; 16], &[0u8; 16], NOW + 100_000, NOW)
        .unwrap();
    let removed = store.maintain(NOW + 50, &|key| *key != d).unwrap();
    assert_eq!(removed, 2);
    assert_eq!(store.usage().unwrap().0, 1);
    assert_eq!(store.purge().unwrap(), 1);
}

#[test]
fn canonical_fields_are_what_the_sealer_writes() {
    let env = envelope(&id(0xA0), 1);
    assert!(canonical_outbound_fields(&env));
    for edit in [
        |e: &mut Envelope| e.flags = 1,
        |e: &mut Envelope| e.dest_device_hint = 5,
        |e: &mut Envelope| e.hop_limit = 9,
        |e: &mut Envelope| e.replication_budget = 1,
        |e: &mut Envelope| e.ratchet_header_ciphertext = vec![1],
    ] {
        let mut e = env.clone();
        edit(&mut e);
        assert!(!canonical_outbound_fields(&e));
    }
}

fn vectors_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.pop();
    p.join("shared-vectors/rvn1/custody")
}

/// KATs (§5 vectors). Regenerate with `RAVEN_REGEN_RFC1_VECTORS=1` only when
/// the wire format changes on purpose.
#[test]
fn rfc1_known_answer_vectors() {
    let alice_seed = [0xA0u8; 32];
    let alice = Identity::from_seed(&alice_seed);
    let env = envelope(&alice, 1);
    let rso1 = rso1_for(&env, 0x11);
    let req = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let cases: Vec<(&str, &str, Vec<u8>, serde_json::Value)> = vec![
        (
            "rfc1_deposit_001.json",
            "DEPOSIT of one RSO1 for recipient 0xb0..",
            encode_request(
                &req,
                &Rfc1Request::Deposit {
                    recipient: [0xB0; 32],
                    rso1: rso1.clone(),
                },
            ),
            serde_json::json!({
                "signer_seed_hex": hex::encode(alice_seed),
                "custody_digest_hex": hex::encode(custody_digest(&env.pack())),
                "page_token_hex": hex::encode(page_token(&rso1)),
            }),
        ),
        (
            "rfc1_fetch_001.json",
            "FETCH two tags after a cursor",
            encode_request(
                &req,
                &Rfc1Request::Fetch {
                    tags: vec![[0x11; 16], [0x12; 16]],
                    after: Some([0x77; 32]),
                    max_items: 16,
                },
            ),
            serde_json::json!({}),
        ),
        (
            "rfc1_fetch_nocursor_001.json",
            "FETCH one tag, no cursor",
            encode_request(
                &req,
                &Rfc1Request::Fetch {
                    tags: vec![[0x11; 16]],
                    after: None,
                    max_items: 4,
                },
            ),
            serde_json::json!({}),
        ),
        (
            "rfc1_release_001.json",
            "RELEASE one digest",
            encode_request(
                &req,
                &Rfc1Request::Release {
                    digests: vec![custody_digest(&env.pack())],
                },
            ),
            serde_json::json!({}),
        ),
        (
            "rfc1_replies_001.json",
            "DEPOSIT_RESULT STORED, then FETCH_END and RELEASE_RESULT, concatenated",
            [
                encode_reply(
                    &req,
                    &Rfc1Reply::DepositResult {
                        code: CustodyCode::Ok,
                        digest: custody_digest(&env.pack()),
                    },
                ),
                encode_reply(
                    &req,
                    &Rfc1Reply::FetchEnd {
                        code: CustodyCode::Ok,
                        returned: 1,
                        next: None,
                    },
                ),
                encode_reply(
                    &req,
                    &Rfc1Reply::ReleaseResult {
                        code: CustodyCode::Ok,
                        released: 1,
                    },
                ),
            ]
            .concat(),
            serde_json::json!({ "frame_lengths": [47, 49, 16] }),
        ),
    ];
    for (name, what, bytes, extra) in cases {
        let expected = serde_json::json!({
            "name": what,
            "protocol_version": "rvn1",
            "deterministic": true,
            "description": "RFC1 v1 custody frame(s); header magic RFC1 | version | op | req_id[8]",
            "inputs": extra,
            "expected": { "frame_hex": hex::encode(&bytes), "frame_len": bytes.len() },
        });
        let path = vectors_dir().join(name);
        if std::env::var("RAVEN_REGEN_RFC1_VECTORS").as_deref() == Ok("1") {
            std::fs::create_dir_all(vectors_dir()).unwrap();
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&expected).unwrap() + "\n",
            )
            .unwrap();
        }
        let stored: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(stored, expected, "{name}");
    }
}

/// Expired rows never hold a pair at its quota: caps count only live rows,
/// and a refused deposit keeps its expiry purge (review finding 1).
#[test]
fn expired_rows_never_wedge_a_pair_at_quota() {
    let c = Carol::new();
    let mut store = CustodyStore::open_or_create(c.dir.path()).unwrap();
    let (a, b) = (c.alice.public_key_bytes(), c.bob.public_key_bytes());
    let mut n: u32 = 0;
    let mut next = || {
        n += 1;
        let mut dg = [0u8; 32];
        dg[..4].copy_from_slice(&n.to_be_bytes());
        dg
    };
    for _ in 0..MAX_PAIR_ROWS {
        let dg = next();
        assert_eq!(
            store
                .deposit(&dg, &b, &a, &[1; 16], &[0u8; 16], NOW + 20, NOW - 120_000)
                .unwrap(),
            CustodyCode::Ok
        );
    }
    // Live: the pair is at its cap.
    let dg = next();
    assert_eq!(
        store
            .deposit(&dg, &b, &a, &[1; 16], &[0u8; 16], NOW + 3_600_000, NOW)
            .unwrap(),
        CustodyCode::Quota
    );
    // A day later every row has expired: room again, and the purge stuck.
    let later = NOW + 86_400_000;
    let dg = next();
    assert_eq!(
        store
            .deposit(&dg, &b, &a, &[1; 16], &[0u8; 16], later + 3_600_000, later)
            .unwrap(),
        CustodyCode::Ok
    );
    assert!(store.usage().unwrap().0 <= MAX_PAIR_ROWS - 64 + 1);
}

/// The durable prune's custodian maintenance removes the objects of a
/// depositor that is no longer a pinned contact (review finding 1).
#[test]
fn maintenance_drops_objects_of_a_removed_depositor() {
    let _g = Gates::set(true, false);
    let c = Carol::new();
    let env = envelope(&c.alice, 7);
    assert_eq!(
        c.deposit(&c.alice, &c.bob, rso1_for(&env, 5)),
        CustodyCode::Ok
    );
    let row = |who: &Identity, name: &str| {
        format!(
            r#"{{"petname":"{name}","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":true,"lan_dial":"192.168.1.9:7420","internet_dial":""}}"#,
            hex::encode(who.public_key_bytes())
        )
    };
    std::fs::write(
        c.dir.path().join("contacts.json"),
        format!("[{}]", row(&c.bob, "Bob")),
    )
    .unwrap();
    assert_eq!(maintain(c.dir.path(), NOW).unwrap(), 1);
    assert_eq!(items(&c.fetch(&c.bob, &[[5; 16]], None)), 0);
}

/// Review handoff-2: while the contact book is held (raven-node's start in
/// a profile it seals, until the key is loaded) or the block list is
/// corrupt, every party would read as no contact: the prune drops no
/// object for that, only expired ones. Readable again, a depositor that is
/// no contact any more still loses its objects.
#[test]
fn maintenance_drops_nothing_while_the_book_cannot_be_read() {
    let _g = Gates::set(true, false);
    let c = Carol::new();
    let d = c.dir.path();
    let env = envelope(&c.alice, 8);
    assert_eq!(
        c.deposit(&c.alice, &c.bob, rso1_for(&env, 6)),
        CustodyCode::Ok
    );
    let blocked = crate::chat_history::blocked_path(d);
    std::fs::write(&blocked, b"{ not a block list").unwrap();
    assert_eq!(maintain(d, NOW).unwrap(), 0);
    std::fs::remove_file(&blocked).unwrap();
    crate::contact_book::hold(d, "the at-rest key is loading");
    assert_eq!(maintain(d, NOW).unwrap(), 0);
    crate::contact_book::enable_process_cache(d);
    assert_eq!(items(&c.fetch(&c.bob, &[[6; 16]], None)), 1, "still held");
    let row = |who: &Identity, name: &str| {
        format!(
            r#"{{"petname":"{name}","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":true,"lan_dial":"192.168.1.9:7420","internet_dial":""}}"#,
            hex::encode(who.public_key_bytes())
        )
    };
    std::fs::write(d.join("contacts.json"), format!("[{}]", row(&c.bob, "Bob"))).unwrap();
    assert_eq!(maintain(d, NOW).unwrap(), 1);
}

/// Cutoff F8: the recipients a custodian holds mail for are the
/// unreleased, unexpired rows' recipients, each once, newest deposit first
/// and at most [`MAX_HELD_RECIPIENTS`]; a node without a store holds mail
/// for nobody (and none is created).
#[test]
fn held_recipients_is_bounded_and_skips_released() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        held_recipients(dir.path(), NOW).unwrap(),
        Vec::<[u8; 32]>::new()
    );
    assert!(!custody_db_path(dir.path()).exists(), "nothing created");
    let mut store = CustodyStore::open_or_create(dir.path()).unwrap();
    let depositor = [0xA0; 32];
    let recipient = |n: u8| {
        let mut r = [0x10; 32];
        r[0] = n;
        r
    };
    let mut digest = 0u32;
    let mut deposit = |store: &mut CustodyStore, to: [u8; 32], at: u64, expires: u64| {
        digest += 1;
        let mut dg = [0u8; 32];
        dg[..4].copy_from_slice(&digest.to_be_bytes());
        assert_eq!(
            store
                .deposit(&dg, &to, &depositor, &[1; 16], &[0u8; 16], expires, at)
                .unwrap(),
            CustodyCode::Ok
        );
        dg
    };
    // 70 recipients, recipient n deposited at NOW + n s (n = 1 newest last).
    for n in 1..=70u8 {
        let at = NOW + u64::from(n) * 1_000;
        deposit(&mut store, recipient(n), at, NOW + 3_600_000);
    }
    // Recipient 70 also has an older row: it stays where its newest is.
    deposit(&mut store, recipient(70), NOW, NOW + 3_600_000);
    // Recipient 69's only row is released, 68's has expired.
    let mut digest_of_69 = [0u8; 32];
    digest_of_69[..4].copy_from_slice(&69u32.to_be_bytes());
    assert_eq!(store.release(&recipient(69), &[digest_of_69]).unwrap(), 1);
    store
        .conn
        .execute(
            "UPDATE custody_objects_v1 SET expires_at_ms = ?1 WHERE recipient = ?2",
            params![ms(NOW + 90_000), recipient(68).as_slice()],
        )
        .unwrap();
    let now = NOW + 100_000;
    let held = held_recipients(dir.path(), now).unwrap();
    assert_eq!(held.len(), MAX_HELD_RECIPIENTS, "bounded");
    let want: Vec<[u8; 32]> = [70u8]
        .into_iter()
        .chain((1..=67u8).rev())
        .take(MAX_HELD_RECIPIENTS)
        .map(recipient)
        .collect();
    assert_eq!(
        held, want,
        "newest first, each once, released and expired skipped"
    );
    // Once everything is released, nobody is held for.
    let all: Vec<[u8; 32]> = (1..=digest)
        .map(|n| {
            let mut dg = [0u8; 32];
            dg[..4].copy_from_slice(&n.to_be_bytes());
            dg
        })
        .collect();
    for n in 1..=70u8 {
        store.release(&recipient(n), &all).unwrap();
    }
    assert_eq!(
        held_recipients(dir.path(), now).unwrap(),
        Vec::<[u8; 32]>::new()
    );
    // Released objects are gone (PP.17); their 71 digests stay until expiry.
    assert_eq!(store.usage().unwrap(), (0, 0));
    assert_eq!(released_count(&store), 71);
}

#[test]
fn secure_delete_is_on_after_open() {
    let dir = tempfile::tempdir().unwrap();
    let store = CustodyStore::open_or_create(dir.path()).unwrap();
    assert_eq!(crate::paths::scrub_test::secure_delete(&store.conn), 1);
}

/// PP.2: `maintain` overwrites an expired object and `purge` every object;
/// each ends with a checkpoint that takes that into the main file and
/// empties the WAL.
#[test]
fn a_deleted_row_leaves_no_bytes_after_checkpoint() {
    use crate::paths::scrub_test;
    let dir = tempfile::tempdir().unwrap();
    let path = custody_db_path(dir.path());
    let (expiring, purged) = (scrub_test::marker(), scrub_test::marker());
    let (alice, bob) = ([0xA1; 32], [0xB2; 32]);
    let mut store = CustodyStore::open_or_create(dir.path()).unwrap();
    for (digest, rso1, expires) in [(1u8, &expiring, NOW + 10), (2, &purged, NOW + 100_000)] {
        assert_eq!(
            store
                .deposit(&[digest; 32], &bob, &alice, &[1; 16], rso1, expires, NOW)
                .unwrap(),
            CustodyCode::Ok
        );
    }
    scrub_test::assert_written(&store.conn, &path, &expiring);
    scrub_test::assert_written(&store.conn, &path, &purged);
    assert_eq!(store.maintain(NOW + 50, &|_| true).unwrap(), 1);
    scrub_test::assert_scrubbed(&path, &expiring);
    assert!(scrub_test::main_file_holds(&path, &purged));
    assert_eq!(store.purge().unwrap(), 1);
    scrub_test::assert_scrubbed(&path, &purged);
}

// ── PP.17: RELEASE deletes; the sealed store and its migration ──────────
//
// The PP.17 tests run on a plain profile's clear store, a sealed profile's
// new schema-2 store and one an older build created before the profile was
// sealed (migrated by the sealing pass). The older build's side is the
// PP.16 build's exact SQL. Profiles are temp folders whose keys come from
// the test build's lab K_hist (never a keychain item).

use crate::paths::scrub_test;
use crate::sqlite_rebuild::{fault, Fault};

const HOUR: u64 = 3_600_000;

/// Where a test runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Setup {
    /// A profile that is not sealed: schema 1, as before the pack.
    Plain,
    /// A sealed profile's first store: created at schema 2.
    SealedFresh,
    /// A schema-1 store from before the profile was sealed, migrated by the
    /// sealing pass.
    Migrated,
}

const SETUPS: [Setup; 3] = [Setup::Plain, Setup::SealedFresh, Setup::Migrated];

/// The batch every build before PP.17 runs at each open, after its version
/// check, outside a transaction.
const OLDER_BATCH: &str = "PRAGMA auto_vacuum=INCREMENTAL;
     PRAGMA journal_mode=WAL;
     PRAGMA synchronous=FULL;
     CREATE TABLE IF NOT EXISTS custody_objects_v1 (
       object_digest  BLOB PRIMARY KEY NOT NULL CHECK(length(object_digest)=32),
       recipient      BLOB NOT NULL CHECK(length(recipient)=32),
       depositor      BLOB NOT NULL CHECK(length(depositor)=32),
       store_tag      BLOB NOT NULL CHECK(length(store_tag)=16),
       page_token     BLOB NOT NULL CHECK(length(page_token)=32),
       rso1           BLOB NOT NULL,
       bytes          INTEGER NOT NULL,
       admitted_at_ms INTEGER NOT NULL,
       expires_at_ms  INTEGER NOT NULL,
       released_at_ms INTEGER
     );
     CREATE INDEX IF NOT EXISTS idx_custody_fetch ON custody_objects_v1(recipient, page_token);
     CREATE INDEX IF NOT EXISTS idx_custody_pair  ON custody_objects_v1(depositor, recipient);
     CREATE INDEX IF NOT EXISTS idx_custody_exp   ON custody_objects_v1(expires_at_ms);
     PRAGMA user_version = 1;";

/// An older build's `CustodyStore::open_at`: its user_version check (it
/// refuses anything above 1), then the batch.
fn older_open_at(path: &Path) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    conn.busy_timeout(std::time::Duration::from_secs(10))
        .map_err(|e| e.to_string())?;
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if version > 1 {
        return Err("friend custody store is newer than this build".into());
    }
    conn.execute_batch(OLDER_BATCH).map_err(|e| e.to_string())?;
    Ok(conn)
}

/// One object as an older build stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    digest: [u8; 32],
    recipient: [u8; 32],
    depositor: [u8; 32],
    tag: [u8; 16],
    rso1: Vec<u8>,
    admitted: u64,
    expires: u64,
    released: Option<u64>,
}

fn older_deposit(conn: &Connection, row: &Row) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO custody_objects_v1
           (object_digest, recipient, depositor, store_tag, page_token, rso1, bytes,
            admitted_at_ms, expires_at_ms, released_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            row.digest.as_slice(),
            row.recipient.as_slice(),
            row.depositor.as_slice(),
            row.tag.as_slice(),
            page_token(&row.rso1).as_slice(),
            row.rso1,
            row.rso1.len() as i64,
            ms(row.admitted),
            ms(row.expires),
            row.released.map(ms),
        ],
    )
}

/// An older build's rows, by rowid.
fn older_rows(conn: &Connection) -> Vec<Row> {
    let mut stmt = conn
        .prepare(
            "SELECT object_digest, recipient, depositor, store_tag, rso1, admitted_at_ms,
                    expires_at_ms, released_at_ms
             FROM custody_objects_v1 ORDER BY rowid",
        )
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok(Row {
                digest: r.get::<_, Vec<u8>>(0)?.try_into().unwrap(),
                recipient: r.get::<_, Vec<u8>>(1)?.try_into().unwrap(),
                depositor: r.get::<_, Vec<u8>>(2)?.try_into().unwrap(),
                tag: r.get::<_, Vec<u8>>(3)?.try_into().unwrap(),
                rso1: r.get(4)?,
                admitted: u64::try_from(r.get::<_, i64>(5)?).unwrap(),
                expires: u64::try_from(r.get::<_, i64>(6)?).unwrap(),
                released: r
                    .get::<_, Option<i64>>(7)?
                    .map(|v| u64::try_from(v).unwrap()),
            })
        })
        .unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

fn raw(dir: &Path) -> Connection {
    Connection::open(custody_db_path(dir)).unwrap()
}

/// `(user_version, shape)` of the store as it is on disk.
fn schema(dir: &Path) -> (i64, Shape) {
    let conn = raw(dir);
    (
        rebuild::user_version(&conn).unwrap(),
        rebuild::shape(&conn, OBJECTS, KEYED_COLUMN).unwrap(),
    )
}

/// The released digests a store keeps.
fn released_count(store: &CustodyStore) -> i64 {
    rebuild::count(&store.conn, RELEASED).unwrap()
}

fn keys_of(dir: &Path) -> Arc<MetaKeys> {
    at_rest::keys_cached(dir).unwrap()
}

/// The store's main file or its WAL holds `needle` (raw, or as hex in
/// either case).
fn file_or_wal_holds(dir: &Path, needle: &[u8]) -> bool {
    let path = custody_db_path(dir);
    let mut wal = path.clone().into_os_string();
    wal.push("-wal");
    let hex = hex::encode(needle);
    [path, PathBuf::from(wal)].iter().any(|p| {
        std::fs::read(p).is_ok_and(|bytes| {
            bytes.windows(needle.len()).any(|w| w == needle)
                || bytes
                    .windows(hex.len())
                    .any(|w| w.eq_ignore_ascii_case(hex.as_bytes()))
        })
    })
}

/// The object as stored: (digest column, store tag, payload column).
fn stored(dir: &Path) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let conn = raw(dir);
    let digest = if rebuild::shape(&conn, OBJECTS, KEYED_COLUMN).unwrap() == Shape::Keyed {
        KEYED_COLUMN
    } else {
        "object_digest"
    };
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {digest}, store_tag, rso1 FROM custody_objects_v1 ORDER BY rowid"
        ))
        .unwrap();
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

/// What the digest column holds for `digest` in this store.
fn digest_column(dir: &Path, digest: &[u8; 32]) -> Vec<u8> {
    if schema(dir).1 == Shape::Keyed {
        kh_digest(&keys_of(dir), digest).to_vec()
    } else {
        digest.to_vec()
    }
}

fn release_by(c: &Carol, who: &Identity, digests: Vec<[u8; 32]>) -> Rfc1Reply {
    match c
        .call(who, lan("192.168.1.21"), Rfc1Request::Release { digests })
        .as_slice()
    {
        [reply] => reply.clone(),
        other => panic!("{other:?}"),
    }
}

fn released(n: u8) -> Rfc1Reply {
    Rfc1Reply::ReleaseResult {
        code: CustodyCode::Ok,
        released: n,
    }
}

#[test]
fn release_deletes_payload_and_pair_columns_and_keeps_the_digest() {
    let _g = Gates::set(true, false);
    for setup in SETUPS {
        let c = Carol::with(setup);
        let env = envelope(&c.alice, 0x31);
        let digest = custody_digest(&env.pack());
        assert_eq!(
            c.deposit(&c.alice, &c.bob, rso1_for(&env, 0x41)),
            CustodyCode::Ok
        );
        let before = stored(c.dir.path());
        assert_eq!(before.len(), 1, "{setup:?}");
        // Only the recipient releases it.
        assert_eq!(release_by(&c, &c.alice, vec![digest]), released(0));
        assert_eq!(stored(c.dir.path()), before, "{setup:?}");
        assert_eq!(release_by(&c, &c.bob, vec![digest]), released(1));
        // The row is gone: payload, recipient, depositor, size, both times.
        assert!(stored(c.dir.path()).is_empty(), "{setup:?}");
        let conn = raw(c.dir.path());
        let digest_col = if setup == Setup::Plain {
            "object_digest"
        } else {
            KEYED_COLUMN
        };
        assert_eq!(
            rebuild::columns(&conn, RELEASED).unwrap(),
            [digest_col, "prune_after_hour"],
            "{setup:?}: the released digest keeps nothing else"
        );
        let kept: Vec<(Vec<u8>, i64)> = {
            let mut stmt = conn.prepare("SELECT * FROM custody_released_v1").unwrap();
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            rows.collect::<Result<_, _>>().unwrap()
        };
        assert_eq!(
            kept,
            [(
                digest_column(c.dir.path(), &digest),
                rebuild::prune_after_hour(env.expires_at)
            )],
            "{setup:?}"
        );
        // Released twice: nothing changes.
        assert_eq!(release_by(&c, &c.bob, vec![digest]), released(0));
        let store = CustodyStore::open_existing(c.dir.path()).unwrap().unwrap();
        assert_eq!(store.usage().unwrap(), (0, 0), "{setup:?}");
        assert_eq!(released_count(&store), 1);
    }
}

#[test]
fn redeposit_after_release_is_a_duplicate_until_expiry() {
    let _g = Gates::set(true, false);
    for setup in SETUPS {
        let c = Carol::with(setup);
        let env = envelope(&c.alice, 0x32);
        let rso1 = rso1_for(&env, 0x42);
        assert_eq!(c.deposit(&c.alice, &c.bob, rso1.clone()), CustodyCode::Ok);
        assert_eq!(items(&c.fetch(&c.bob, &[[0x42; 16]], None)), 1);
        let digest = custody_digest(&env.pack());
        assert_eq!(release_by(&c, &c.bob, vec![digest]), released(1));
        // The same deposit again (a replay), and under another tag: neither
        // is stored again, and nothing about the tag was kept to tell them
        // apart.
        assert_eq!(
            c.deposit(&c.alice, &c.bob, rso1.clone()),
            CustodyCode::Duplicate,
            "{setup:?}"
        );
        assert_eq!(
            c.deposit(&c.alice, &c.bob, rso1_for(&env, 0x43)),
            CustodyCode::Duplicate,
            "{setup:?}"
        );
        assert_eq!(items(&c.fetch(&c.bob, &[[0x42; 16], [0x43; 16]], None)), 0);
        let mut store = CustodyStore::open_existing(c.dir.path()).unwrap().unwrap();
        assert_eq!(store.usage().unwrap().0, 0, "{setup:?}");
        // Until the hour the object would have expired in has passed: the
        // prune keeps the digest before, and drops it then.
        let (a, b) = (c.alice.public_key_bytes(), c.bob.public_key_bytes());
        let expires = NOW + 2 * HOUR + 5;
        let dg = [0x77; 32];
        let deposit = |store: &mut CustodyStore, now: u64, expires: u64| {
            store
                .deposit(&dg, &b, &a, &[9; 16], &[0u8; 16], expires, now)
                .unwrap()
        };
        assert_eq!(deposit(&mut store, NOW, expires), CustodyCode::Ok);
        assert_eq!(store.release(&b, &[dg]).unwrap(), 1);
        // (The envelope's own digest, an hour of life, has gone by then.)
        store.maintain(expires, &|_| true).unwrap();
        assert_eq!(released_count(&store), 1, "{setup:?}: not before the hour");
        assert_eq!(
            deposit(&mut store, expires, expires),
            CustodyCode::Duplicate
        );
        let hour_end = rebuild::prune_after_hour(expires) as u64 * HOUR;
        store.maintain(hour_end, &|_| true).unwrap();
        assert_eq!(released_count(&store), 0, "{setup:?}: its hour has passed");
        assert_eq!(
            deposit(&mut store, hour_end, hour_end + HOUR),
            CustodyCode::Ok,
            "{setup:?}"
        );
    }
}

#[test]
fn fetch_after_release_is_empty() {
    let _g = Gates::set(true, false);
    for setup in SETUPS {
        let c = Carol::with(setup);
        let (one, two) = (envelope(&c.alice, 0x33), envelope(&c.alice, 0x34));
        for env in [&one, &two] {
            assert_eq!(
                c.deposit(&c.alice, &c.bob, rso1_for(env, 0x44)),
                CustodyCode::Ok
            );
        }
        let got = c.fetch(&c.bob, &[[0x44; 16]], None);
        assert_eq!(items(&got), 2, "{setup:?}");
        let fetched: Vec<Vec<u8>> = got
            .iter()
            .filter_map(|r| match r {
                Rfc1Reply::FetchItem { rso1 } => Some(rso1.clone()),
                _ => None,
            })
            .collect();
        assert!(fetched.contains(&rso1_for(&one, 0x44)), "{setup:?}");
        assert!(fetched.contains(&rso1_for(&two, 0x44)), "{setup:?}");
        assert_eq!(
            release_by(&c, &c.bob, vec![custody_digest(&one.pack())]),
            released(1)
        );
        let got = c.fetch(&c.bob, &[[0x44; 16]], None);
        assert_eq!(
            got,
            [
                Rfc1Reply::FetchItem {
                    rso1: rso1_for(&two, 0x44)
                },
                Rfc1Reply::FetchEnd {
                    code: CustodyCode::Ok,
                    returned: 1,
                    next: None
                }
            ],
            "{setup:?}"
        );
        assert_eq!(
            release_by(&c, &c.bob, vec![custody_digest(&two.pack())]),
            released(1)
        );
        assert_eq!(
            c.fetch(&c.bob, &[[0x44; 16]], None),
            [Rfc1Reply::FetchEnd {
                code: CustodyCode::Ok,
                returned: 0,
                next: None
            }],
            "{setup:?}"
        );
    }
}

#[test]
fn custody_file_byte_scan_after_release_has_no_friend_key() {
    let _g = Gates::set(true, false);
    for setup in SETUPS {
        // Migrated: Alice's object was left with Carol by an older build,
        // in clear, before the profile was sealed.
        let c = Carol::with(if setup == Setup::Migrated {
            Setup::Plain
        } else {
            setup
        });
        let (a, b) = (c.alice.public_key_bytes(), c.bob.public_key_bytes());
        let env = envelope(&c.alice, 0x35);
        let rso1 = rso1_for(&env, 0x45);
        if setup == Setup::Migrated {
            let conn = older_open_at(&custody_db_path(c.dir.path())).unwrap();
            older_deposit(
                &conn,
                &Row {
                    digest: custody_digest(&env.pack()),
                    recipient: b,
                    depositor: a,
                    tag: [0x45; 16],
                    rso1: rso1.clone(),
                    admitted: NOW,
                    expires: env.expires_at,
                    released: None,
                },
            )
            .unwrap();
            crate::paths::checkpoint_truncate(&conn).unwrap();
            drop(conn);
            assert!(file_or_wal_holds(c.dir.path(), &a), "the fixture is clear");
            crate::contact_book::tests::seal(c.dir.path());
        } else {
            assert_eq!(c.deposit(&c.alice, &c.bob, rso1.clone()), CustodyCode::Ok);
        }
        let keyed = setup != Setup::Plain;
        assert_eq!(schema(c.dir.path()).1 == Shape::Keyed, keyed, "{setup:?}");
        let store = CustodyStore::open_existing(c.dir.path()).unwrap().unwrap();
        assert!(crate::paths::checkpoint_truncate(&store.conn)
            .unwrap()
            .completed());
        drop(store);
        // Before the release: a sealed profile's store names nobody; a
        // plain one does.
        for needle in [a.as_slice(), b.as_slice(), &rso1] {
            assert_eq!(
                file_or_wal_holds(c.dir.path(), needle),
                !keyed,
                "{setup:?}: before the release"
            );
        }
        let payload = stored(c.dir.path()).remove(0).2;
        assert!(file_or_wal_holds(c.dir.path(), &payload));
        assert_eq!(
            release_by(&c, &c.bob, vec![custody_digest(&env.pack())]),
            released(1)
        );
        // The release's own checkpoint took the delete into the main file.
        assert_eq!(scrub_test::wal_len(&custody_db_path(c.dir.path())), 0);
        for (what, needle) in [
            ("Alice's key", a.as_slice()),
            ("Bob's key", b.as_slice()),
            ("the object", &rso1),
            ("the stored payload", &payload),
        ] {
            assert!(
                !file_or_wal_holds(c.dir.path(), needle),
                "{setup:?}: {what} is still readable in the store after the release"
            );
        }
    }
}

/// A sealed profile with a schema-1 store an older build wrote: two objects
/// Alice left for Bob and one it released already (payload kept, as before
/// PP.17).
fn sealed_with_clear_store() -> (Carol, Vec<Row>) {
    let c = Carol::with(Setup::SealedFresh);
    let rows = older_fixture(&c);
    let conn = older_open_at(&custody_db_path(c.dir.path())).unwrap();
    for row in &rows {
        older_deposit(&conn, row).unwrap();
    }
    drop(conn);
    assert_eq!(schema(c.dir.path()), (CLEAR_VERSION, Shape::Clear));
    (c, rows)
}

fn older_fixture(c: &Carol) -> Vec<Row> {
    let (a, b) = (c.alice.public_key_bytes(), c.bob.public_key_bytes());
    let row = |fill: u8, released: Option<u64>| {
        let env = envelope(&c.alice, fill);
        Row {
            digest: custody_digest(&env.pack()),
            recipient: b,
            depositor: a,
            tag: [0x46; 16],
            rso1: rso1_for(&env, 0x46),
            admitted: NOW - u64::from(fill),
            expires: env.expires_at,
            released,
        }
    };
    vec![row(0x51, None), row(0x52, Some(NOW)), row(0x53, None)]
}

/// Bob's fetch of the fixture's tag, the payloads in page order.
fn fetched(c: &Carol) -> Vec<Vec<u8>> {
    c.fetch(&c.bob, &[[0x46; 16]], None)
        .into_iter()
        .filter_map(|r| match r {
            Rfc1Reply::FetchItem { rso1 } => Some(rso1),
            _ => None,
        })
        .collect()
}

/// What Bob fetches from the fixture: its open objects, in page order.
fn expected_fetch(rows: &[Row]) -> Vec<Vec<u8>> {
    let mut open: Vec<&Row> = rows.iter().filter(|r| r.released.is_none()).collect();
    open.sort_by_key(|r| page_token(&r.rso1));
    open.iter().map(|r| r.rso1.clone()).collect()
}

#[test]
fn old_version_store_migrates_with_rows_intact() {
    let _g = Gates::set(true, false);
    let (c, rows) = sealed_with_clear_store();
    let before: Vec<(i64, Vec<u8>)> = {
        let conn = raw(c.dir.path());
        let mut stmt = conn
            .prepare("SELECT rowid, object_digest FROM custody_objects_v1 WHERE released_at_ms IS NULL ORDER BY rowid")
            .unwrap();
        let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        mapped.collect::<Result<_, _>>().unwrap()
    };
    assert!(needs_migration(c.dir.path()));
    let store = CustodyStore::open_existing(c.dir.path()).unwrap().unwrap();
    assert_eq!(store.layout, Layout::Keyed);
    assert_eq!(store.usage().unwrap().0, 2, "the released one is gone");
    assert_eq!(released_count(&store), 1);
    assert_eq!(
        store.held_recipients(NOW).unwrap(),
        [c.bob.public_key_bytes()]
    );
    drop(store);
    assert_eq!(schema(c.dir.path()), (SCHEMA_VERSION, Shape::Keyed));
    assert_eq!(fetched(&c), expected_fetch(&rows));
    // Rowids kept: each open object has its rowid, under its keyed digest.
    let keys = keys_of(c.dir.path());
    let after: Vec<(i64, Vec<u8>)> = {
        let conn = raw(c.dir.path());
        let mut stmt = conn
            .prepare("SELECT rowid, kh_object_digest FROM custody_objects_v1 ORDER BY rowid")
            .unwrap();
        let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        mapped.collect::<Result<_, _>>().unwrap()
    };
    let mapped: Vec<(i64, Vec<u8>)> = before
        .iter()
        .map(|(rowid, digest)| (*rowid, kh_digest(&keys, digest).to_vec()))
        .collect();
    assert_eq!(after, mapped);
    assert_eq!(
        rebuild::recorded(&raw(c.dir.path()), STORE).unwrap(),
        Some((SCHEMA_VERSION, false)),
        "recorded, and scrubbed"
    );
    // What the older build released is a duplicate, never stored again.
    assert_eq!(
        c.deposit(&c.alice, &c.bob, rows[1].rso1.clone()),
        CustodyCode::Duplicate
    );
    // The sealing pass of a sealed profile does it eagerly too.
    let (c, _) = sealed_with_clear_store();
    assert!(needs_migration(c.dir.path()));
    assert!(migrate(c.dir.path()).unwrap());
    assert!(!needs_migration(c.dir.path()));
    assert!(!migrate(c.dir.path()).unwrap(), "once");
    // And migrate_all's store pass.
    let (c, _) = sealed_with_clear_store();
    let report = crate::privacy::upkeep_stores(c.dir.path());
    assert_eq!(report.migrated, 1, "{report}");
    assert_eq!(schema(c.dir.path()), (SCHEMA_VERSION, Shape::Keyed));
}

#[test]
fn migration_crash_at_each_statement_recovers() {
    let _g = Gates::set(true, false);
    let mut stops = 0;
    for at in 0.. {
        let (c, rows) = sealed_with_clear_store();
        fault::arm(Fault::CrashAt(at));
        let opened = CustodyStore::open_existing(c.dir.path());
        if fault::armed() {
            // Past the last statement: the migration went through.
            fault::disarm();
            assert_eq!(opened.unwrap().unwrap().layout, Layout::Keyed);
            break;
        }
        stops += 1;
        let err = opened.err().expect("an injected stop fails the open");
        assert!(err.contains("injected stop"), "{err}");
        // Either the old store as it was, or the new one complete.
        match schema(c.dir.path()) {
            (CLEAR_VERSION, Shape::Clear) => {
                assert_eq!(older_rows(&raw(c.dir.path())), rows, "stop at {at}");
            }
            (SCHEMA_VERSION, Shape::Keyed) => {
                assert!(scrub_pending(c.dir.path()), "stop at {at}: scrub left");
            }
            other => panic!("stop at {at} left {other:?}"),
        }
        assert_eq!(fetched(&c), expected_fetch(&rows), "stop at {at}");
        assert_eq!(
            c.deposit(&c.alice, &c.bob, rows[1].rso1.clone()),
            CustodyCode::Duplicate,
            "stop at {at}"
        );
        finish_scrub(c.dir.path());
        assert!(!scrub_pending(c.dir.path()), "stop at {at}");
    }
    // The tables, every row, the checks and the commit: each was a stop.
    assert!(stops >= 12, "only {stops} statements");
}

#[test]
fn migration_rolls_back_on_count_mismatch() {
    let _g = Gates::set(true, false);
    let (c, rows) = sealed_with_clear_store();
    fault::arm(Fault::DropOneRow);
    let err = CustodyStore::open_existing(c.dir.path())
        .err()
        .expect("the count check stops it");
    assert!(err.contains("would hold 1 rows instead of 2"), "{err}");
    assert_eq!(schema(c.dir.path()), (CLEAR_VERSION, Shape::Clear));
    assert_eq!(older_rows(&raw(c.dir.path())), rows);
    assert_eq!(rebuild::recorded(&raw(c.dir.path()), STORE).unwrap(), None);
    assert_eq!(fetched(&c), expected_fetch(&rows));
    assert_eq!(schema(c.dir.path()), (SCHEMA_VERSION, Shape::Keyed));
}

#[test]
fn disk_full_or_no_space_leaves_the_old_store() {
    let _g = Gates::set(true, false);
    // Too little free space: not started; the store works as it is.
    let (c, rows) = sealed_with_clear_store();
    fault::arm(Fault::NoSpace);
    let store = CustodyStore::open_existing(c.dir.path()).unwrap().unwrap();
    assert_eq!(store.layout, Layout::Clear);
    drop(store);
    assert_eq!(schema(c.dir.path()), (CLEAR_VERSION, Shape::Clear));
    assert_eq!(fetched(&c), expected_fetch(&rows), "moved at the next open");
    assert_eq!(schema(c.dir.path()), (SCHEMA_VERSION, Shape::Keyed));
    // The disk fills up during the rebuild: rolled back, nothing lost.
    let (c, rows) = sealed_with_clear_store();
    fault::arm(Fault::DiskFull);
    let err = CustodyStore::open_existing(c.dir.path())
        .err()
        .expect("SQLITE_FULL");
    assert!(err.contains("full"), "{err}");
    assert_eq!(schema(c.dir.path()), (CLEAR_VERSION, Shape::Clear));
    assert_eq!(older_rows(&raw(c.dir.path())), rows);
    assert_eq!(fetched(&c), expected_fetch(&rows));
}

#[test]
fn older_code_refuses_the_migrated_store_and_a_restamp_is_put_right() {
    let _g = Gates::set(true, false);
    let (c, rows) = sealed_with_clear_store();
    drop(CustodyStore::open_existing(c.dir.path()).unwrap());
    // The PP.16 build's user_version check: "newer" (it then answers every
    // request PERSISTENCE).
    let err = older_open_at(&custody_db_path(c.dir.path())).err().unwrap();
    assert_eq!(err, "friend custody store is newer than this build");
    // An older process that read user_version 1 before the migration now
    // runs its batch: every CREATE is a no-op, the stamp is not, and its
    // writes fail closed.
    let older = raw(c.dir.path());
    older.execute_batch(OLDER_BATCH).unwrap();
    assert_eq!(schema(c.dir.path()), (CLEAR_VERSION, Shape::Keyed));
    let err = older_deposit(&older, &rows[0]).unwrap_err();
    assert!(
        err.to_string().contains("no column named object_digest"),
        "{err}"
    );
    drop(older);
    // This build trusts the shape and its raven_schema row: stamped again,
    // not migrated twice.
    assert_eq!(fetched(&c), expected_fetch(&rows));
    assert_eq!(schema(c.dir.path()), (SCHEMA_VERSION, Shape::Keyed));
}

#[test]
fn reverse_migration_round_trip() {
    let _g = Gates::set(true, false);
    let (c, rows) = sealed_with_clear_store();
    let before: Vec<i64> = {
        let conn = raw(c.dir.path());
        let mut stmt = conn
            .prepare(
                "SELECT rowid FROM custody_objects_v1 WHERE released_at_ms IS NULL ORDER BY rowid",
            )
            .unwrap();
        let mapped = stmt.query_map([], |r| r.get(0)).unwrap();
        mapped.collect::<Result<_, _>>().unwrap()
    };
    drop(CustodyStore::open_existing(c.dir.path()).unwrap());
    let back = unseal(c.dir.path()).unwrap();
    // The two open objects come back; the released digest cannot be named
    // in clear and is left out (counted).
    assert_eq!((back.rows, back.dropped), (2, 1));
    assert!(!back.scrub_pending);
    assert_eq!(schema(c.dir.path()), (CLEAR_VERSION, Shape::Clear));
    // Exactly what an older build reads, rowids kept.
    let older = older_open_at(&custody_db_path(c.dir.path())).unwrap();
    let open: Vec<Row> = rows
        .iter()
        .filter(|r| r.released.is_none())
        .cloned()
        .collect();
    assert_eq!(older_rows(&older), open);
    let rowids: Vec<i64> = {
        let mut stmt = older
            .prepare("SELECT rowid FROM custody_objects_v1 ORDER BY rowid")
            .unwrap();
        let mapped = stmt.query_map([], |r| r.get(0)).unwrap();
        mapped.collect::<Result<_, _>>().unwrap()
    };
    assert_eq!(rowids, before);
    assert_eq!(rebuild::count(&older, RELEASED).unwrap(), 0);
    drop(older);
    assert!(unseal(c.dir.path()).unwrap().already);
    // And forward again.
    assert_eq!(fetched(&c), expected_fetch(&rows));
    assert_eq!(schema(c.dir.path()), (SCHEMA_VERSION, Shape::Keyed));
}

#[test]
fn a_sealed_store_without_its_key_fails_closed() {
    let c = Carol::with(Setup::SealedFresh);
    let dd = c.dir.path();
    assert!(!custody_db_path(dd).exists());
    at_rest::forget_cached_keys(dd);
    // No key: no store is created, clear or not.
    assert!(CustodyStore::open_or_create(dd)
        .err()
        .unwrap()
        .contains("friend custody store"));
    assert!(!custody_db_path(dd).exists());
    at_rest::keys_load_with(dd, at_rest::MigratePolicy::Never).unwrap();
    let mut store = CustodyStore::open_or_create(dd).unwrap();
    let (a, b) = (c.alice.public_key_bytes(), c.bob.public_key_bytes());
    assert_eq!(
        store
            .deposit(&[1; 32], &b, &a, &[1; 16], b"object", NOW + HOUR, NOW)
            .unwrap(),
        CustodyCode::Ok
    );
    drop(store);
    at_rest::forget_cached_keys(dd);
    let before = std::fs::read(custody_db_path(dd)).unwrap();
    assert!(CustodyStore::open_existing(dd).is_err());
    assert!(held_recipients(dd, NOW).is_err());
    assert_eq!(std::fs::read(custody_db_path(dd)).unwrap(), before);
    at_rest::keys_load_with(dd, at_rest::MigratePolicy::Never).unwrap();
    let store = CustodyStore::open_existing(dd).unwrap().unwrap();
    assert_eq!(
        store.fetch(&b, &[[1; 16]], None, 16, NOW).unwrap().items,
        [b"object".to_vec()]
    );
}

#[test]
fn rotation_reseals_every_value_and_the_old_epoch_can_go() {
    let c = Carol::with(Setup::SealedFresh);
    let dd = c.dir.path();
    let (a, b) = (c.alice.public_key_bytes(), c.bob.public_key_bytes());
    let mut store = CustodyStore::open_or_create(dd).unwrap();
    for n in 1..=3u8 {
        store
            .deposit(&[n; 32], &b, &a, &[1; 16], &[n; 40], NOW + HOUR, NOW)
            .unwrap();
    }
    assert_eq!(store.release(&b, &[[3; 32]]).unwrap(), 1);
    let want = store.fetch(&b, &[[1; 16]], None, 16, NOW).unwrap();
    assert_eq!(want.items.len(), 2);
    assert_eq!(rows_off_epoch(dd, 1).unwrap(), 0);
    at_rest::add_epoch(dd, 1).unwrap();
    assert_eq!(rows_off_epoch(dd, 2).unwrap(), 2);
    let resealed = reseal_rows(dd).unwrap();
    assert_eq!((resealed.resealed, resealed.unreadable), (2, 0));
    assert_eq!(rows_off_epoch(dd, 2).unwrap(), 0);
    assert_eq!(reseal_rows(dd).unwrap(), RowReseal::default());
    at_rest::drop_old_epochs(dd).unwrap();
    let store = CustodyStore::open_existing(dd).unwrap().unwrap();
    assert_eq!(store.fetch(&b, &[[1; 16]], None, 16, NOW).unwrap(), want);
    assert_eq!(store.held_recipients(NOW).unwrap(), [b]);
}

/// The coarse hour prunes only objects whose exact expiry has passed; the
/// rest of that hour is decided from `meta`, for the fetch, the caps, the
/// held recipients and the maintenance alike.
#[test]
fn the_prune_hour_never_drops_a_live_object() {
    let c = Carol::with(Setup::SealedFresh);
    let dd = c.dir.path();
    let (a, b) = (c.alice.public_key_bytes(), c.bob.public_key_bytes());
    let mut store = CustodyStore::open_or_create(dd).unwrap();
    let start = 500_000 * HOUR;
    for (d, expires) in [(1u8, start + 10), (2, start + HOUR - 1), (3, start + HOUR)] {
        assert_eq!(
            store
                .deposit(&[d; 32], &b, &a, &[1; 16], &[d; 8], expires, start)
                .unwrap(),
            CustodyCode::Ok
        );
    }
    let held = |store: &CustodyStore, now: u64| -> Vec<u8> {
        let mut held: Vec<u8> = store
            .fetch(&b, &[[1; 16]], None, 16, now)
            .unwrap()
            .items
            .iter()
            .map(|item| item[0])
            .collect();
        held.sort_unstable();
        held
    };
    assert_eq!(held(&store, start), [1, 2, 3]);
    assert_eq!(held(&store, start + 10), [2, 3]);
    assert_eq!(held(&store, start + HOUR - 1), [3]);
    assert!(held(&store, start + HOUR).is_empty());
    assert_eq!(store.held_recipients(start + HOUR - 1).unwrap(), [b]);
    assert!(store.held_recipients(start + HOUR).unwrap().is_empty());
    // The pair cap counts the live ones only.
    let counts = keyed_counts(
        &store.conn,
        &keys_of(dd),
        &kh_device(&keys_of(dd), &b),
        &kh_device(&keys_of(dd), &a),
        start + 10,
    )
    .unwrap();
    assert_eq!((counts.node_rows, counts.pair_rows), (2, 2));
    assert_eq!(counts.recent, 16, "admitted within the minute");
    assert_eq!(store.maintain(start + 10, &|_| true).unwrap(), 1);
    assert_eq!(store.usage().unwrap().0, 2);
    assert_eq!(store.maintain(start + HOUR, &|_| true).unwrap(), 2);
    assert_eq!(store.usage().unwrap().0, 0);
}

/// The custodian maintenance of a sealed store names the parties from
/// `meta`: the objects of a pair with a party that is no longer a pinned
/// contact go, the others stay.
#[test]
fn sealed_maintenance_drops_objects_of_a_removed_party() {
    let c = Carol::with(Setup::SealedFresh);
    let dd = c.dir.path();
    let (a, b, d) = (
        c.alice.public_key_bytes(),
        c.bob.public_key_bytes(),
        c.dave.public_key_bytes(),
    );
    let mut store = CustodyStore::open_or_create(dd).unwrap();
    for (n, to) in [(1u8, b), (2, b), (3, d)] {
        store
            .deposit(&[n; 32], &to, &a, &[1; 16], &[n; 8], NOW + HOUR, NOW)
            .unwrap();
    }
    assert_eq!(store.maintain(NOW, &|key| *key != d).unwrap(), 1);
    assert_eq!(store.usage().unwrap().0, 2);
    assert_eq!(store.held_recipients(NOW).unwrap(), [b]);
    assert_eq!(store.purge().unwrap(), 2);
    assert_eq!(released_count(&store), 0);
}

/// `raven privacy rotate-meta` (PP.18): the store keyed again under a new
/// `k_index` keeps every open object (its keyed digest, recipient and
/// depositor change; Bob fetches the same objects); a released digest
/// cannot be keyed again and goes (counted), as on the way back; a second
/// re-key is the same store.
#[test]
fn rekey_keeps_every_open_object_and_lookup() {
    let _g = Gates::set(true, false);
    let (c, rows) = sealed_with_clear_store();
    assert_eq!(fetched(&c), expected_fetch(&rows));
    assert_eq!(schema(c.dir.path()), (SCHEMA_VERSION, Shape::Keyed));
    let keyed = |dir: &Path| -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let conn = raw(dir);
        let mut stmt = conn
            .prepare(
                "SELECT kh_object_digest, kh_recipient, kh_depositor FROM custody_objects_v1
                 ORDER BY rowid",
            )
            .unwrap();
        let mapped = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        mapped.collect::<Result<_, _>>().unwrap()
    };
    let before = keyed(c.dir.path());
    let to = keys_of(c.dir.path()).current_epoch() + 1;
    at_rest::begin_meta_rotation(c.dir.path(), to).unwrap();
    let moved = rekey(c.dir.path()).unwrap();
    assert_eq!((moved.rows, moved.dropped), (2, 1));
    let after = keyed(c.dir.path());
    assert_eq!(after.len(), before.len());
    for ((d0, r0, p0), (d1, r1, p1)) in before.iter().zip(&after) {
        assert!(d0 != d1 && r0 != r1 && p0 != p1);
    }
    assert_eq!(rows_off_epoch(c.dir.path(), to).unwrap(), 0);
    assert_eq!(rebuild::count(&raw(c.dir.path()), RELEASED).unwrap(), 0);
    assert_eq!(fetched(&c), expected_fetch(&rows));
    rekey(c.dir.path()).unwrap();
    assert_eq!(keyed(c.dir.path()), after);
    assert_eq!(fetched(&c), expected_fetch(&rows));
}

mod handoff;
mod handoff_custodian;
mod letters;
