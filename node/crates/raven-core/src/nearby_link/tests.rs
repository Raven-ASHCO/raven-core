use super::*;
use serde_json::{json, Value};

/// The vectors' people (the LAN beacon vectors' alice, bob and carol, so the
/// R2 root they pin is the same bytes as `lbcn_pair_keys_001.json`'s).
const ALICE: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const BOB: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const CAROL: &str = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
/// The vectors' time; [`E0`] is its epoch.
const NOW_MS: u64 = 1_700_000_000_000;
/// `epoch_of(1_700_000_000_000)`.
const E0: u64 = 1_888_888;

/// The eight small-order Ed25519 points, canonically encoded.
const SMALL_ORDER: [&str; 8] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
];

/// Montgomery u-coordinates whose X25519 is all zero for every scalar.
const NON_CONTRIBUTORY_U: [&str; 7] = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

/// The Bluetooth Base UUID (`00000000-0000-1000-8000-00805f9b34fb`) after
/// its 16- or 32-bit alias: no token or characteristic may look like it.
const BASE_UUID_TAIL: [u8; 12] = [
    0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
];

fn bytes32(hex_text: &str) -> [u8; 32] {
    hex::decode(hex_text).unwrap().try_into().unwrap()
}

fn id(seed: &str) -> Identity {
    Identity::from_seed(&bytes32(seed))
}

fn keys(own: &Identity, peer: &Identity) -> PairKeys {
    pair_keys(own, &peer.public_key_bytes()).unwrap()
}

/// 16 counting bytes from `first`: the vectors' nonces.
fn counting(first: u8) -> [u8; 16] {
    std::array::from_fn(|i| first.wrapping_add(i as u8))
}

/// A DATA payload of `len` counting bytes.
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| i as u8).collect()
}

#[test]
fn pair_keys_are_symmetric_and_take_the_ble_medium_of_the_r2_root() {
    let (a, b, c) = (id(ALICE), id(BOB), id(CAROL));
    let (ab, ba) = (keys(&a, &b), keys(&b, &a));
    assert_eq!(*ab.k_tok, *ba.k_tok);
    assert_eq!(*ab.k_knock, *ba.k_knock);
    assert_ne!(*ab.k_tok, *ab.k_knock);
    assert_eq!((ab.me, ab.peer), (ba.peer, ba.me));
    // From Phase 3's root with the BLE medium byte, never the LAN one's.
    let root = lan_beacon::pair_root(&a, &b.public_key_bytes()).unwrap();
    let ble = lan_beacon::medium_key(&root, lan_beacon::MEDIUM_BLE);
    let lan = lan_beacon::medium_key(&root, lan_beacon::MEDIUM_LAN);
    assert_eq!(*ab.k_tok, *expand(&ble, b"RNB1-token"));
    assert_eq!(*ab.k_knock, *expand(&ble, b"RNB1-knock"));
    for k in [&*ab.k_tok, &*ab.k_knock] {
        assert!(![*root, *ble, *lan].contains(k));
        assert_ne!(*k, *expand(&lan, b"RNB1-token"));
    }
    // Another pair, other keys.
    let ac = keys(&a, &c);
    assert_ne!(*ac.k_tok, *ab.k_tok);
    assert_ne!(*ac.k_knock, *ab.k_knock);
    assert_eq!(format!("{ab:?}"), "PairKeys(..)");
}

#[test]
fn bad_contact_keys_get_no_pair_keys() {
    let a = id(ALICE);
    for point in SMALL_ORDER {
        assert_eq!(
            pair_keys(&a, &bytes32(point)).unwrap_err(),
            BeaconError::BadKey,
            "{point}"
        );
    }
    assert_eq!(
        pair_keys(&a, &a.public_key_bytes()).unwrap_err(),
        BeaconError::BadKey
    );
    // The second line, reached below the key checks: an all-zero secret.
    let scalar = a.x25519_agreement_scalar();
    for u in NON_CONTRIBUTORY_U {
        assert_eq!(x25519_dalek::x25519(*scalar, bytes32(u)), [0u8; 32], "{u}");
    }
}

#[test]
fn tokens_differ_by_direction_epoch_and_pair_and_carry_the_v4_bits() {
    let (a, b, c) = (id(ALICE), id(BOB), id(CAROL));
    let (ab, ba, ac) = (keys(&a, &b), keys(&b, &a), keys(&a, &c));
    let mut all = Vec::new();
    for e in [0, 1, E0, E0 + 1, u64::MAX] {
        // A's token for B is what B scans for, and the other way round.
        assert_eq!(ab.token_out(e), ba.token_in(e));
        assert_eq!(ab.token_in(e), ba.token_out(e));
        assert_eq!(ab.token_out(e), token(&ab, e, &a.public_key_bytes()));
        all.extend([
            ab.token_out(e),
            ab.token_in(e),
            ac.token_out(e),
            ac.token_in(e),
        ]);
    }
    for t in &all {
        let ch = char_uuid(t);
        for u in [t, &ch] {
            assert_eq!(u[6] >> 4, 4, "version 4");
            assert_eq!(u[8] >> 6, 0b10, "RFC 9562 variant");
            assert_ne!(u[4..], BASE_UUID_TAIL);
        }
        assert_ne!(ch, *t);
    }
    let n = all.len();
    let mut distinct = all.clone();
    distinct.extend(all.iter().map(char_uuid));
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), 2 * n, "every token and char UUID differs");
}

#[test]
fn a_scanner_accepts_the_epochs_next_to_its_own_only() {
    let (a, b, c) = (id(ALICE), id(BOB), id(CAROL));
    // Alice's book: carol, then bob.
    let book = [keys(&a, &c), keys(&a, &b)];
    let bob_for_alice = keys(&b, &a);
    for (e, found) in [
        (E0 - 2, None),
        (E0 - 1, Some((1, E0 - 1))),
        (E0, Some((1, E0))),
        (E0 + 1, Some((1, E0 + 1))),
        (E0 + 2, None),
    ] {
        assert_eq!(match_token(&bob_for_alice.token_out(e), E0, &book), found);
    }
    // Alice's own token for bob is not one bob advertises for her.
    assert_eq!(match_token(&book[1].token_out(E0), E0, &book), None);
    assert_eq!(scan_epochs(0), 0..=1);
    assert_eq!(scan_epochs(u64::MAX), u64::MAX - 1..=u64::MAX);
    assert_eq!(
        match_token(&bob_for_alice.token_out(u64::MAX), u64::MAX, &book),
        Some((1, u64::MAX))
    );
    assert_eq!(epoch_of(NOW_MS), E0);
    assert_eq!(epoch_of(E0 * EPOCH_MS - 1), E0 - 1);
}

#[test]
fn uuid_text_air_and_windows_forms() {
    let u: [u8; 16] = std::array::from_fn(|i| (i as u8) * 0x11);
    assert_eq!(uuid_string(&u), "00112233-4455-6677-8899-aabbccddeeff");
    let le = uuid_ota_le(&u);
    assert_eq!(le[0], 0xff);
    assert_eq!(le[15], 0x00);
    assert_eq!(uuid_ota_le(&le), u);
    assert_eq!(
        windows_guid_u128(&u),
        0x0011_2233_4455_6677_8899_aabb_ccdd_eeff
    );
}

/// One full knock between alice (central) and bob (peripheral, advertising
/// T(e, bob)).
#[test]
fn a_knock_with_the_pair_key_comes_up_and_anything_else_is_silent() {
    let (a, b, c) = (id(ALICE), id(BOB), id(CAROL));
    let (at_a, at_b) = (keys(&a, &b), keys(&b, &a));
    let t = at_b.token_out(E0);
    let central = CentralKnock::new(t, counting(0x10));
    let hello = central.hello(&at_a);
    let mut replay = KnockReplay::new();
    let (peripheral, challenge) = PeripheralKnock::answer(
        &at_b,
        t,
        &decode(&hello, 185).unwrap(),
        counting(0x20),
        &mut replay,
    )
    .expect("a valid HELLO is answered");
    let proof = central
        .proof(&at_a, &decode(&challenge, 185).unwrap())
        .expect("a valid CHALLENGE gets a PROOF");
    assert!(peripheral.accepts_proof(&at_b, &decode(&proof, 185).unwrap()));

    // The same HELLO again: silent (replay), and the cache was not grown.
    let again = |replay: &mut KnockReplay, frame: &[u8]| {
        PeripheralKnock::answer(&at_b, t, &decode(frame, 185).unwrap(), [9; 16], replay).is_none()
    };
    assert!(again(&mut replay, &hello));
    assert_eq!(replay.tokens(), 1);
    // A stranger's HELLO (carol has no key of this pair), a flipped flag or
    // nonce bit, another version, or the same HELLO on another service.
    let carol_keys = keys(&c, &b);
    let stranger = CentralKnock::new(t, counting(0x30)).hello(&carol_keys);
    let mut flipped_flag = central.hello(&at_a);
    flipped_flag[2] ^= 0x01;
    let mut flipped_nonce = CentralKnock::new(t, counting(0x40)).hello(&at_a);
    flipped_nonce[3] ^= 0x80;
    let mut version_2 = CentralKnock::new(t, counting(0x50)).hello(&at_a);
    version_2[1] = 0x02;
    for frame in [stranger, flipped_flag, flipped_nonce, version_2] {
        assert!(again(&mut KnockReplay::new(), &frame));
    }
    let other_service = at_b.token_out(E0 + 1);
    assert!(PeripheralKnock::answer(
        &at_b,
        other_service,
        &decode(&hello, 185).unwrap(),
        [9; 16],
        &mut KnockReplay::new(),
    )
    .is_none());
    // Not a HELLO at all.
    assert!(again(&mut KnockReplay::new(), &challenge));

    // A tampered CHALLENGE, or one of another knock, gets no PROOF.
    let mut bad = challenge;
    bad[34] ^= 0x01;
    assert!(central.proof(&at_a, &decode(&bad, 185).unwrap()).is_none());
    let other = CentralKnock::new(t, counting(0x60));
    assert!(other
        .proof(&at_a, &decode(&challenge, 185).unwrap())
        .is_none());
    assert!(central
        .proof(&carol_keys, &decode(&challenge, 185).unwrap())
        .is_none());
    assert!(central
        .proof(&at_a, &decode(&hello, 185).unwrap())
        .is_none());
    // A tampered PROOF, or another knock's, is refused.
    let mut bad_proof = proof;
    bad_proof[1] ^= 0x01;
    assert!(!peripheral.accepts_proof(&at_b, &decode(&bad_proof, 185).unwrap()));
    let other_proof = {
        let mut r = KnockReplay::new();
        let hello = other.hello(&at_a);
        let (_, ch) =
            PeripheralKnock::answer(&at_b, t, &decode(&hello, 185).unwrap(), [7; 16], &mut r)
                .unwrap();
        other.proof(&at_a, &decode(&ch, 185).unwrap()).unwrap()
    };
    assert!(!peripheral.accepts_proof(&at_b, &decode(&other_proof, 185).unwrap()));
    assert!(!peripheral.accepts_proof(&at_b, &decode(&hello, 185).unwrap()));
}

#[test]
fn the_replay_cache_keeps_256_nonces_per_token_and_drops_old_tokens() {
    let mut r = KnockReplay::new();
    let (t1, t2) = ([1u8; 16], [2u8; 16]);
    assert!(r.insert(&t1, &[0; 16]));
    assert!(!r.insert(&t1, &[0; 16]));
    assert!(r.insert(&t2, &[0; 16]), "per token");
    for i in 1..REPLAY_PER_TOKEN {
        let mut n = [0u8; 16];
        n[..8].copy_from_slice(&(i as u64).to_be_bytes());
        assert!(r.insert(&t1, &n));
    }
    // 256 remembered: all still refused; one more pushes out the oldest.
    assert!(!r.insert(&t1, &[0; 16]));
    assert!(r.insert(&t1, &[0xff; 16]));
    assert!(r.insert(&t1, &[0; 16]), "the oldest was dropped");
    r.retain(|t| *t == t2);
    assert_eq!(r.tokens(), 1);
    assert!(r.insert(&t1, &[0xff; 16]), "t1 forgotten");
}

#[test]
fn every_kind_round_trips_and_malformed_frames_are_refused() {
    let p = payload(508);
    let frames = [
        Frame::Hello {
            version: 1,
            flags: 0,
            nonce: counting(1),
            tag: counting(2),
        },
        Frame::Challenge {
            version: 7,
            flags: 0xff,
            nonce: counting(3),
            tag: counting(4),
        },
        Frame::Proof { tag: counting(5) },
        Frame::Open { chan: 1 },
        Frame::Data {
            chan: 0,
            seq: 0xbeef,
            payload: &p,
        },
        Frame::Data {
            chan: 1,
            seq: 0,
            payload: &p[..1],
        },
        Frame::Credit { chan: 0, add: 64 },
        Frame::Fin {
            chan: 1,
            next_seq: 65535,
        },
        Frame::Reset { code: 0xee },
    ];
    for f in frames {
        let bytes = f.to_vec();
        assert!(bytes.len() <= MAX_FRAME);
        assert_eq!(decode(&bytes, 512), Ok(f));
        assert_eq!(decode(&bytes, 4096), Ok(f), "max_rx caps at 512");
    }
    let protocol: &[&[u8]] = &[
        &[],
        &[0x00],
        &[0x04],
        &[0x14, 0x00],
        &[0x1e, 0x01],
        &[0x10],
        &[0x10, 0x02],
        &[0x10, 0x00, 0x00],
        &[0x11, 0x00, 0x00, 0x00],
        &[0x11, 0x02, 0x00, 0x00, 0x01],
        &[0x12, 0x00, 0x00, 0x00],
        &[0x12, 0x00, 0x00, 0x41],
        &[0x12, 0x00, 0x00],
        &[0x13, 0x02, 0x00, 0x00],
        &[0x13, 0x00, 0x00],
        &[0x1f],
        &[0x1f, 0x01, 0x00],
        &[0x01; 34],
        &[0x02; 36],
        &[0x03; 16],
        &[0x03; 18],
    ];
    for bad in protocol {
        assert_eq!(decode(bad, 64), Err(PipeError::Protocol), "{bad:02x?}");
    }
    // Longer than max_rx: MTU, whatever the kind.
    let mut long = vec![KIND_DATA, 0, 0, 0];
    long.extend(payload(61));
    assert_eq!(long.len(), 65);
    assert_eq!(decode(&long, 64), Err(PipeError::Mtu));
    assert!(decode(&long, 65).is_ok());
    assert_eq!(decode(&[0x14; 600], 4096), Err(PipeError::Mtu));
    for code in 1..=6 {
        let e = PipeError::from_code(code).unwrap();
        assert_eq!(e.code(), code);
        assert_eq!(e.reset().to_vec(), [KIND_RESET, code]);
    }
    assert_eq!(PipeError::from_code(0), None);
    assert_eq!(PipeError::from_code(7), None);
}

/// A central and a peripheral pipe with the peripheral's channel 1 open
/// (OPEN went peripheral -> central).
fn pipes(max: usize) -> (PipeState, PipeState) {
    let mut c = PipeState::new(Role::Central, max, max).unwrap();
    let mut p = PipeState::new(Role::Peripheral, max, max).unwrap();
    let open = p.open().unwrap();
    assert_eq!(open, Frame::Open { chan: 1 });
    assert_eq!(c.on_rx(&open), Ok(RxAction::Opened { chan: 1 }));
    (c, p)
}

fn data(chan: u8, seq: u16) -> Vec<u8> {
    Frame::Data {
        chan,
        seq,
        payload: &[0xab],
    }
    .to_vec()
}

#[test]
fn credit_runs_out_and_resumes() {
    let (mut c, mut p) = pipes(185);
    // Both directions start with W0.
    assert_eq!((c.tx_credit(1), p.tx_credit(1)), (W0, W0));
    for seq in 0..W0 {
        assert_eq!(p.on_tx_data(1), Some(seq));
        assert!(matches!(
            c.on_rx_bytes(&data(1, seq)),
            Ok(RxAction::Deliver { chan: 1, .. })
        ));
    }
    assert!(!p.can_send(1));
    assert_eq!(p.on_tx_data(1), None);
    // The receiver delivers them; at W0 / 2 it grants them back.
    for i in 1..=W0 {
        let grant = c.consumed(1, 1);
        if i % (W0 / 2) == 0 {
            let f = grant.expect("a CREDIT every W0 / 2");
            assert_eq!(f, Frame::Credit { chan: 1, add: 4 });
            assert_eq!(p.on_rx(&f), Ok(RxAction::Credit { chan: 1 }));
        } else {
            assert_eq!(grant, None);
        }
    }
    assert!(p.can_send(1));
    assert_eq!(p.tx_credit(1), W0);
    assert_eq!(p.on_tx_data(1), Some(W0));
}

#[test]
fn credit_beyond_64_and_data_without_credit_are_protocol_errors() {
    let (mut c, _) = pipes(185);
    assert_eq!(
        c.on_rx(&Frame::Credit { chan: 1, add: 56 }),
        Ok(RxAction::Credit { chan: 1 })
    );
    assert_eq!(c.tx_credit(1), W_MAX);
    assert_eq!(
        c.on_rx(&Frame::Credit { chan: 1, add: 1 }),
        Err(PipeError::Protocol)
    );
    assert!(c.is_dead());
    assert_eq!(c.on_rx(&Frame::Open { chan: 1 }), Err(PipeError::Protocol));

    let (mut c, _) = pipes(185);
    for seq in 0..W0 {
        assert!(c.on_rx_bytes(&data(1, seq)).is_ok());
    }
    assert_eq!(c.on_rx_bytes(&data(1, W0)), Err(PipeError::Protocol));
    // CREDIT on a channel never opened.
    let (mut c, _) = pipes(185);
    assert_eq!(
        c.on_rx(&Frame::Credit { chan: 0, add: 1 }),
        Err(PipeError::Protocol)
    );
}

#[test]
fn a_sequence_gap_or_duplicate_is_a_protocol_error() {
    for bad in [2u16, 0] {
        let (mut c, _) = pipes(185);
        assert!(c.on_rx_bytes(&data(1, 0)).is_ok());
        assert_eq!(c.on_rx_bytes(&data(1, bad)), Err(PipeError::Protocol));
    }
    // FIN must name the next sequence number.
    let (mut c, _) = pipes(185);
    assert!(c.on_rx_bytes(&data(1, 0)).is_ok());
    assert_eq!(
        c.on_rx(&Frame::Fin {
            chan: 1,
            next_seq: 0
        }),
        Err(PipeError::Protocol)
    );
    // DATA on a channel that is not open.
    let (mut c, _) = pipes(185);
    assert_eq!(c.on_rx_bytes(&data(0, 0)), Err(PipeError::Protocol));
}

#[test]
fn only_the_owner_opens_a_channel_and_only_once_per_instance() {
    let (mut c, mut p) = pipes(185);
    // The central owns 0, the peripheral 1: no side opens the other's.
    let mut c2 = PipeState::new(Role::Central, 185, 185).unwrap();
    assert_eq!(c2.on_rx(&Frame::Open { chan: 0 }), Err(PipeError::Protocol));
    let mut p2 = PipeState::new(Role::Peripheral, 185, 185).unwrap();
    assert_eq!(p2.on_rx(&Frame::Open { chan: 1 }), Err(PipeError::Protocol));
    // A second OPEN of a live instance.
    assert_eq!(c.on_rx(&Frame::Open { chan: 1 }), Err(PipeError::Protocol));
    assert_eq!(p.open(), None, "its instance is still open");
    // The central's own channel.
    let mut c3 = PipeState::new(Role::Central, 185, 185).unwrap();
    assert_eq!(c3.open(), Some(Frame::Open { chan: 0 }));
    assert_eq!(c3.open(), None);
    assert!(c3.is_open(0) && !c3.is_open(1));
}

#[test]
fn fin_both_ways_then_reopen_restarts_the_sequence_numbers() {
    let (mut c, mut p) = pipes(185);
    for seq in 0..3 {
        assert_eq!(p.on_tx_data(1), Some(seq));
        assert!(c.on_rx_bytes(&data(1, seq)).is_ok());
    }
    assert_eq!(c.on_tx_data(1), Some(0));
    assert!(p.on_rx_bytes(&data(1, 0)).is_ok());
    // The peripheral FINs: the central's receive side ends ...
    let fin = p.fin(1).unwrap();
    assert_eq!(
        fin,
        Frame::Fin {
            chan: 1,
            next_seq: 3
        }
    );
    assert_eq!(p.fin(1), None, "once");
    assert!(!p.can_send(1));
    assert_eq!(c.on_rx(&fin), Ok(RxAction::Fined { chan: 1 }));
    assert_eq!(c.on_rx_bytes(&data(1, 3)), Err(PipeError::Protocol));
    let (mut c, mut p) = pipes(185);
    for seq in 0..3 {
        assert_eq!(p.on_tx_data(1), Some(seq));
        assert!(c.on_rx_bytes(&data(1, seq)).is_ok());
    }
    assert_eq!(c.on_rx(&p.fin(1).unwrap()), Ok(RxAction::Fined { chan: 1 }));
    assert!(c.is_open(1), "half closed");
    assert_eq!(c.consumed(1, 3), None, "no credit after the FIN");
    // ... and with the central's FIN the instance is over.
    let back = c.fin(1).unwrap();
    assert_eq!(
        back,
        Frame::Fin {
            chan: 1,
            next_seq: 0
        }
    );
    assert_eq!(p.on_rx(&back), Ok(RxAction::Fined { chan: 1 }));
    assert!(!c.is_open(1) && !p.is_open(1) && !c.any_open());
    // A new instance starts at 0 with W0 credit.
    let open = p.open().unwrap();
    assert_eq!(c.on_rx(&open), Ok(RxAction::Opened { chan: 1 }));
    assert_eq!(p.on_tx_data(1), Some(0));
    assert!(c.on_rx_bytes(&data(1, 0)).is_ok());
    assert_eq!((c.tx_credit(1), p.tx_credit(1)), (W0, W0 - 1));
}

/// What happens on the central's pipe after control frame `after`.
#[derive(Clone, Copy, Debug)]
enum Between {
    Nothing,
    Sent,
    Received,
}

/// The central receives `frames` control frames in a row: pipes()'s OPEN of
/// channel 1, then the peripheral's FIN and (after the central's own FIN)
/// OPEN by turns; `between` happens after frame `after`.
fn control_run(frames: u16, after: u16, between: Between) -> Result<(), (u16, PipeError)> {
    let (mut c, _) = pipes(185);
    let mut rx_seq = 0;
    for n in 2..=frames {
        if n - 1 == after {
            match between {
                Between::Nothing => {}
                Between::Sent => assert!(c.on_tx_data(1).is_some()),
                Between::Received => {
                    assert!(c.on_rx_bytes(&data(1, rx_seq)).is_ok());
                    rx_seq += 1;
                }
            }
        }
        let r = if n % 2 == 0 {
            c.on_rx(&Frame::Fin {
                chan: 1,
                next_seq: rx_seq,
            })
        } else {
            rx_seq = 0;
            c.fin(1).unwrap();
            c.on_rx(&Frame::Open { chan: 1 })
        };
        r.map_err(|e| (n, e))?;
    }
    Ok(())
}

#[test]
fn sixty_five_control_frames_in_a_row_are_a_limit() {
    assert_eq!(control_run(64, 0, Between::Nothing), Ok(()));
    assert_eq!(
        control_run(65, 0, Between::Nothing),
        Err((65, PipeError::Limit))
    );
    // DATA either way starts a new run (the sender of a one-way transfer
    // receives nothing but CREDITs).
    for between in [Between::Sent, Between::Received] {
        assert_eq!(control_run(41 + 64, 41, between), Ok(()), "{between:?}");
        assert_eq!(
            control_run(41 + 65, 41, between),
            Err((41 + 65, PipeError::Limit)),
            "{between:?}"
        );
    }
}

#[test]
fn a_knock_frame_after_up_is_a_protocol_error() {
    let hello = CentralKnock::new([1; 16], [2; 16]).hello(&keys(&id(ALICE), &id(BOB)));
    for f in [
        decode(&hello, 64).unwrap(),
        Frame::Proof { tag: [0; 16] },
        Frame::Challenge {
            version: 1,
            flags: 0,
            nonce: [0; 16],
            tag: [0; 16],
        },
    ] {
        let (mut c, _) = pipes(64);
        assert_eq!(c.on_rx(&f), Err(PipeError::Protocol));
        assert!(c.is_dead());
    }
}

#[test]
fn reset_kills_the_pipe_both_ways() {
    let (mut c, mut p) = pipes(185);
    let r = p.reset(PipeError::Shutdown);
    assert!(p.is_dead() && p.open().is_none() && !p.can_send(1));
    assert_eq!(c.on_rx(&r), Ok(RxAction::Reset(4)));
    assert!(c.is_dead());
    assert_eq!(c.fin(1), None);
    assert_eq!(c.consumed(1, 8), None);
    assert_eq!(
        PipeState::new(Role::Central, 63, 512).unwrap_err(),
        PipeError::Mtu
    );
    assert_eq!(
        PipeState::new(Role::Central, 512, 23).unwrap_err(),
        PipeError::Mtu
    );
    let big = PipeState::new(Role::Peripheral, 4096, 4096).unwrap();
    assert_eq!(
        (big.max_tx(), big.max_rx(), big.max_payload()),
        (512, 512, 508)
    );
}

#[test]
fn sequence_numbers_never_wrap() {
    let (mut c, mut p) = pipes(64);
    let mut sent = 0u32;
    while p.can_send(1) {
        let seq = p.on_tx_data(1).unwrap();
        assert!(c.on_rx_bytes(&data(1, seq)).is_ok());
        if let Some(f) = c.consumed(1, 1) {
            p.on_rx(&f).unwrap();
        }
        sent += 1;
    }
    assert_eq!(sent, 65_535, "seq 0..=65534");
    assert_eq!(
        p.fin(1),
        Some(Frame::Fin {
            chan: 1,
            next_seq: u16::MAX
        })
    );
    // A DATA with seq 65535 is refused even when it is the next one.
    assert_eq!(c.on_rx_bytes(&data(1, u16::MAX)), Err(PipeError::Protocol));
}

/// One Internet-direct link message (`u32be length || Noise message`) of
/// 65535 bytes, through two pipes at each frame size: every byte arrives in
/// order with the credits flowing back.
#[test]
fn a_65535_byte_noise_message_round_trips_at_every_frame_size() {
    let noise: Vec<u8> = (0..65_535u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    let mut stream = (noise.len() as u32).to_be_bytes().to_vec();
    stream.extend_from_slice(&noise);
    for max in [64, 185, 512] {
        let mut c = PipeState::new(Role::Central, max, max).unwrap();
        let mut p = PipeState::new(Role::Peripheral, max, max).unwrap();
        // The central opens its channel 0 and writes the link stream.
        let open = c.open().unwrap().to_vec();
        assert_eq!(p.on_rx_bytes(&open), Ok(RxAction::Opened { chan: 0 }));
        let mut got = Vec::new();
        let mut rest = &stream[..];
        let mut frames = 0;
        let mut wire = Vec::new();
        while !rest.is_empty() {
            assert!(c.can_send(0), "credit flows back ({max})");
            let n = rest.len().min(c.max_payload());
            let seq = c.on_tx_data(0).unwrap();
            wire.clear();
            encode(
                &Frame::Data {
                    chan: 0,
                    seq,
                    payload: &rest[..n],
                },
                &mut wire,
            );
            assert!(wire.len() <= max);
            rest = &rest[n..];
            match p.on_rx_bytes(&wire) {
                Ok(RxAction::Deliver { chan: 0, bytes }) => got.extend_from_slice(bytes),
                other => panic!("{other:?}"),
            }
            if let Some(credit) = p.consumed(0, 1) {
                assert_eq!(
                    c.on_rx_bytes(&credit.to_vec()),
                    Ok(RxAction::Credit { chan: 0 })
                );
            }
            frames += 1;
        }
        assert_eq!(got, stream, "{max}");
        assert_eq!(frames, stream.len().div_ceil(max - DATA_HEADER));
        let fin = c.fin(0).unwrap().to_vec();
        assert_eq!(p.on_rx_bytes(&fin), Ok(RxAction::Fined { chan: 0 }));
    }
}

// RAVEN_NEARBY_LINK_V1 §10: the known-answer vectors in
// shared-vectors/rvn1/nearby. This test writes them only under
// RAVEN_REGEN_NEARBY_VECTORS=1 (a deliberate wire change) and otherwise
// compares them with the committed files. The Python reference
// (protocol/reference/raven_protocol/nearby.py) recomputes them.

/// The vectors' people: (name, seed, where the seed comes from).
const PEOPLE: [(&str, &str, &str); 3] = [
    (
        "alice",
        ALICE,
        "shared-vectors/v1/identities.json alice (RFC 8032 section 7.1 test 1)",
    ),
    (
        "bob",
        BOB,
        "shared-vectors/v1/identities.json bob (RFC 8032 section 7.1 test 2)",
    ),
    ("carol", CAROL, "inline: RFC 8032 section 7.1 test 3"),
];

fn person(name: &str) -> Identity {
    let (_, seed, _) = PEOPLE
        .iter()
        .find(|p| p.0 == name)
        .expect("one of the vectors' people");
    id(seed)
}

fn people_json(names: &[&str]) -> Value {
    let mut map = serde_json::Map::new();
    for (name, seed, source) in PEOPLE {
        if names.contains(&name) {
            map.insert(
                name.into(),
                json!({
                    "seed_hex": seed,
                    "ed_public_hex": hex::encode(person(name).public_key_bytes()),
                    "source": source,
                }),
            );
        }
    }
    Value::Object(map)
}

fn vectors_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.pop();
    p.join("shared-vectors/rvn1/nearby")
}

fn vector(name: &str, description: &str, inputs: Value, expected: Value) -> Value {
    json!({
        "name": name,
        "protocol_version": "rvn1",
        "deterministic": true,
        "description": description,
        "inputs": inputs,
        "expected": expected,
    })
}

/// Assert that the committed vector `file` (under shared-vectors/rvn1/nearby)
/// equals `expected`; write it first under `RAVEN_REGEN_NEARBY_VECTORS=1`.
fn assert_vector(file: &str, expected: &Value) {
    let path = vectors_dir().join(file);
    if std::env::var("RAVEN_REGEN_NEARBY_VECTORS").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(expected).unwrap() + "\n",
        )
        .unwrap();
    }
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing vector {}: {e}", path.display()));
    let stored: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(&stored, expected, "{file}");
}

/// rnb1_pair_keys_001.json (§2): alice's pairs with bob and carol, computed
/// from both sides.
fn pair_keys_vector() -> Value {
    let pairs = [("alice", "bob"), ("alice", "carol")];
    let rows: Vec<Value> = pairs
        .iter()
        .map(|&(an, bn)| {
            let (a, b) = (person(an), person(bn));
            let (ap, bp) = (a.public_key_bytes(), b.public_key_bytes());
            let root = lan_beacon::pair_root(&a, &bp).unwrap();
            assert_eq!(*root, *lan_beacon::pair_root(&b, &ap).unwrap());
            let ble = lan_beacon::medium_key(&root, MEDIUM_BLE);
            let (ab, ba) = (keys(&a, &b), keys(&b, &a));
            assert_eq!((*ab.k_tok, *ab.k_knock), (*ba.k_tok, *ba.k_knock));
            json!({
                "a": an,
                "b": bn,
                "k_root_hex": hex::encode(*root),
                "k_ble_hex": hex::encode(*ble),
                "k_tok_hex": hex::encode(*ab.k_tok),
                "k_knock_hex": hex::encode(*ab.k_knock),
            })
        })
        .collect();
    vector(
        "RNB1 pair keys: the R2 pairwise root, its Bluetooth LE medium key, K_tok and K_knock",
        "RAVEN_NEARBY_LINK_V1 §2. K_root is the R2 pairwise root of RAVEN_LAN_BEACON_V1 §2.2 \
         (RAVEN_PRIVATE_RENDEZVOUS_V1 §5.3a item 2): Z = X25519 of one identity's Ed25519 \
         secret scalar with the Montgomery form of the other identity key, K_root = \
         HKDF-SHA256(salt 'rvn1/r2-pair/v1', ikm Z, info 'root' || lo || hi, 32 bytes) with lo \
         and hi the two Ed25519 keys sorted bytewise; the same bytes as \
         lan_beacon/lbcn_pair_keys_001.json for the same pair. K_ble = \
         HKDF-Expand-SHA256(PRK K_root, info 'medium' || 0x01, 32 bytes). K_tok = \
         HKDF-Expand-SHA256(PRK K_ble, info 'RNB1-token', 32 bytes) and K_knock = \
         HKDF-Expand-SHA256(PRK K_ble, info 'RNB1-knock', 32 bytes). Both sides of a pair \
         compute the same keys. These keys only make beacon tokens and knock tags: never a \
         message, session, route, mailbox or ACK key",
        json!({
            "people": people_json(&["alice", "bob", "carol"]),
            "pairs": pairs.map(|(a, b)| [a, b]),
            "r2_pair_salt_ascii": std::str::from_utf8(lan_beacon::R2_PAIR_SALT).unwrap(),
            "medium_ble": MEDIUM_BLE,
            "token_info_ascii": "RNB1-token",
            "knock_info_ascii": "RNB1-knock",
        }),
        json!({ "pairs": rows }),
    )
}

/// rnb1_tokens_001.json (§2, §3): the pair alice-bob at epochs e0 and
/// e0 + 1, each side advertising.
fn tokens_vector() -> Value {
    let (a, b) = (person("alice"), person("bob"));
    let k = keys(&a, &b);
    let mut rows = Vec::new();
    for e in [E0, E0 + 1] {
        for (name, who) in [("alice", &a), ("bob", &b)] {
            let adv = who.public_key_bytes();
            let t = token(&k, e, &adv);
            let ch = char_uuid(&t);
            let hmac_input =
                [&b"RNB1"[..], &[VERSION, MEDIUM_BLE], &e.to_be_bytes(), &adv].concat();
            rows.push(json!({
                "epoch": e,
                "advertiser": name,
                "hmac_input_hex": hex::encode(hmac_input),
                "token_hex": hex::encode(t),
                "uuid_string": uuid_string(&t),
                "ota_le_hex": hex::encode(uuid_ota_le(&t)),
                "windows_guid_u128_hex": format!("{:032x}", windows_guid_u128(&t)),
                "char_uuid_hex": hex::encode(ch),
                "char_uuid_string": uuid_string(&ch),
            }));
        }
    }
    vector(
        "RNB1 tokens and characteristic UUIDs of the pair alice-bob at two epochs",
        "RAVEN_NEARBY_LINK_V1 §2. epoch = floor(unix_ms / 900000). T(epoch, advertiser) = \
         HMAC-SHA256(K_tok, 'RNB1' || 0x01 version || 0x01 medium || epoch as u64 big-endian || \
         the advertiser's Ed25519 key)[0..16], then T[6] = (T[6] & 0x0f) | 0x40 and T[8] = \
         (T[8] & 0x3f) | 0x80 (RFC 9562 version 4). The advertiser hosts the service and \
         advertises T as its one 128-bit service UUID; its contact scans for it. C = \
         SHA-256('RNB1-char' || T)[0..16] with the same bits is the characteristic UUID. \
         uuid_string: lowercase 8-4-4-4-12 over the 16 bytes in order; ota_le_hex: the bytes \
         reversed, as an advertisement (AD type 0x06/0x07) carries them; \
         windows_guid_u128_hex: the u128 a Windows GUID is built from (GUID::from_u128 of \
         u128::from_be_bytes(T)). A scanner at epoch e accepts e-1, e and e+1. K_tok is \
         rnb1_pair_keys_001.json's alice-bob k_tok_hex",
        json!({
            "people": people_json(&["alice", "bob"]),
            "pair": ["alice", "bob"],
            "unix_ms": NOW_MS,
            "epoch_ms": EPOCH_MS,
        }),
        json!({
            "epoch": E0,
            "scanner_accepts": scan_epochs(E0).collect::<Vec<_>>(),
            "tokens": rows,
        }),
    )
}

/// rnk1_knock_001.json (§5): alice (central) knocks on bob's service
/// T(e0, bob); then frames the peripheral does not answer.
fn knock_vector() -> Value {
    let (a, b, c) = (person("alice"), person("bob"), person("carol"));
    let (at_a, at_b) = (keys(&a, &b), keys(&b, &a));
    let t = at_b.token_out(E0);
    let (nonce_c, nonce_p) = (counting(0x10), counting(0x20));
    let central = CentralKnock::new(t, nonce_c);
    let hello = central.hello(&at_a);
    let mut replay = KnockReplay::new();
    let (peripheral, challenge) = PeripheralKnock::answer(
        &at_b,
        t,
        &decode(&hello, MIN_FRAME).unwrap(),
        nonce_p,
        &mut replay,
    )
    .unwrap();
    let proof = central
        .proof(&at_a, &decode(&challenge, MIN_FRAME).unwrap())
        .unwrap();
    assert!(peripheral.accepts_proof(&at_b, &decode(&proof, MIN_FRAME).unwrap()));
    // HELLOs bob stays silent to.
    let mut flag = hello;
    flag[2] ^= 0x01;
    let mut version = hello;
    version[1] = 0x02;
    let mut tag = hello;
    tag[34] ^= 0x01;
    let carol_hello = CentralKnock::new(t, nonce_c).hello(&keys(&c, &b));
    let silent: Vec<Value> = [
        ("a replay of the HELLO above", hello),
        (
            "flags_c bit 0 flipped (the MAC covers every flag bit)",
            flag,
        ),
        ("version 0x02", version),
        ("tag_h with its last bit flipped", tag),
        ("carol's HELLO (no key of this pair)", carol_hello),
    ]
    .into_iter()
    .map(|(what, frame)| {
        assert!(PeripheralKnock::answer(
            &at_b,
            t,
            &decode(&frame, MIN_FRAME).unwrap(),
            nonce_p,
            &mut replay
        )
        .is_none());
        json!({ "what": what, "hello_hex": hex::encode(frame), "answered": false })
    })
    .collect();
    vector(
        "RNK1 knock: HELLO, CHALLENGE and PROOF on bob's service, and HELLOs that get silence",
        "RAVEN_NEARBY_LINK_V1 §5. T is bob's token at e0 (rnb1_tokens_001.json), alice is the \
         central. HELLO = 0x01 || 0x01 version || flags_c || nonce_c || tag_h, tag_h = \
         HMAC-SHA256(K_knock, 'RNK1/hello' || T || flags_c || nonce_c)[0..16]. CHALLENGE = \
         0x02 || 0x01 || flags_p || nonce_p || tag_p, tag_p = HMAC-SHA256(K_knock, 'RNK1/resp' \
         || T || flags_c || nonce_c || flags_p || nonce_p)[0..16]. PROOF = 0x03 || tag_c, tag_c \
         = HMAC-SHA256(K_knock, 'RNK1/proof' || T || flags_c || nonce_c || flags_p || \
         nonce_p)[0..16]. K_knock is the alice-bob k_knock_hex of rnb1_pair_keys_001.json. The \
         nonces are fixed here; a real knock draws them fresh. silent: HELLOs on the same \
         service, after the one above, that the peripheral does not answer (version other than \
         1, a tag that does not verify, or a nonce_c it answered before)",
        json!({
            "people": people_json(&["alice", "bob", "carol"]),
            "central": "alice",
            "peripheral": "bob",
            "epoch": E0,
            "flags_c": FLAGS_V1,
            "nonce_c_hex": hex::encode(nonce_c),
            "flags_p": FLAGS_V1,
            "nonce_p_hex": hex::encode(nonce_p),
        }),
        json!({
            "token_hex": hex::encode(t),
            "hello_hex": hex::encode(hello),
            "challenge_hex": hex::encode(challenge),
            "proof_hex": hex::encode(proof),
            "silent": silent,
        }),
    )
}

fn frame_json(f: &Frame<'_>) -> Value {
    match *f {
        Frame::Open { chan } => json!({ "kind": "OPEN", "chan": chan }),
        Frame::Data { chan, seq, payload } => json!({
            "kind": "DATA",
            "chan": chan,
            "seq": seq,
            "payload_hex": hex::encode(payload),
        }),
        Frame::Credit { chan, add } => json!({ "kind": "CREDIT", "chan": chan, "add": add }),
        Frame::Fin { chan, next_seq } => {
            json!({ "kind": "FIN", "chan": chan, "next_seq": next_seq })
        }
        Frame::Reset { code } => json!({ "kind": "RESET", "code": code }),
        _ => unreachable!("knock frames are in rnk1_knock_001.json"),
    }
}

/// rnp1_frames_001.json (§6): one frame of each kind; DATA at the largest
/// payload of max_tx 64, 185 and 512.
fn frames_vector() -> Value {
    let payloads: Vec<Vec<u8>> = [64usize, 185, 512]
        .iter()
        .map(|m| payload(m - DATA_HEADER))
        .collect();
    let mut cases: Vec<(&str, usize, Frame<'_>)> = vec![("open", 64, Frame::Open { chan: 0 })];
    for (i, max) in [64usize, 185, 512].into_iter().enumerate() {
        let name = ["data_max_tx_64", "data_max_tx_185", "data_max_tx_512"][i];
        let seq = [0u16, 1, 0x1234][i];
        cases.push((
            name,
            max,
            Frame::Data {
                chan: (i % 2) as u8,
                seq,
                payload: &payloads[i],
            },
        ));
    }
    cases.extend([
        ("credit", 64, Frame::Credit { chan: 1, add: 4 }),
        (
            "fin",
            64,
            Frame::Fin {
                chan: 0,
                next_seq: 1093,
            },
        ),
        ("reset_limit", 64, PipeError::Limit.reset()),
    ]);
    let rows: Vec<Value> = cases
        .iter()
        .map(|(name, max, f)| {
            let bytes = f.to_vec();
            assert!(bytes.len() <= *max);
            assert_eq!(decode(&bytes, *max), Ok(*f));
            json!({
                "name": name,
                "max_tx": max,
                "frame": frame_json(f),
                "frame_hex": hex::encode(&bytes),
            })
        })
        .collect();
    vector(
        "RNP1 frames: one of each kind, DATA at the largest payload of three frame sizes",
        "RAVEN_NEARBY_LINK_V1 §6. OPEN = 0x10 || chan; DATA = 0x11 || chan || seq u16 \
         big-endian || payload (1 to max_tx - 4 bytes); CREDIT = 0x12 || chan || add u16 \
         big-endian (1 to 64); FIN = 0x13 || chan || next_seq u16 big-endian; RESET = 0x1f || \
         code (1 PROTOCOL, 2 IDLE, 3 LIMIT, 4 SHUTDOWN, 5 MTU, 6 DUPLICATE). chan is 0 or 1. \
         max_tx = min(ATT_MTU - 3, 512) of the sending direction; each frame is one ATT PDU \
         value. DATA payloads are counting bytes 0x00, 0x01, ... (mod 256)",
        json!({ "max_tx_values": [64, 185, 512] }),
        json!({ "frames": rows }),
    )
}

/// One negative RNP1 vector: `role` receives `frames` on a pipe that just
/// came UP with `max_rx`; frame `fails_at` gets `error`, and the pipe sends
/// RESET with its code.
fn pipe_negative(
    file: &str,
    what: &str,
    role: Role,
    max_rx: usize,
    frames: &[Vec<u8>],
    fails_at: usize,
    error: PipeError,
) -> (String, Value) {
    let mut st = PipeState::new(role, max_rx, max_rx).unwrap();
    for (i, f) in frames.iter().enumerate() {
        let r = st.on_rx_bytes(f).map(|_| ());
        if i < fails_at {
            assert_eq!(r, Ok(()), "{file} frame {i}");
        } else {
            assert_eq!(r, Err(error), "{file} frame {i}");
        }
    }
    assert_eq!(frames.len(), fails_at + 1, "{file}");
    let role_name = match role {
        Role::Central => "central",
        Role::Peripheral => "peripheral",
    };
    let v = vector(
        &format!("RNP1 negative: {what}"),
        "RAVEN_NEARBY_LINK_V1 §6. The receiver has the given role on a pipe that just came UP \
         (no channel open; the central owns channel 0, the peripheral channel 1; W0 = 8 \
         credits each way of a new channel instance; at most 64 outstanding) and frames are at \
         most max_rx bytes. It applies the frames in order: every frame before fails_at is \
         accepted, frame fails_at is refused with the error, and the receiver sends \
         reset_hex; the pipe is then dead",
        json!({
            "role": role_name,
            "max_rx": max_rx,
            "frames_hex": frames.iter().map(hex::encode).collect::<Vec<_>>(),
        }),
        json!({
            "fails_at": fails_at,
            "error": error.name(),
            "reset_hex": hex::encode(error.reset().to_vec()),
        }),
    );
    (format!("negative/{file}"), v)
}

fn negative_vectors() -> Vec<(String, Value)> {
    use PipeError::{Mtu, Protocol};
    let open1 = Frame::Open { chan: 1 }.to_vec();
    let one = |seq: u16| {
        Frame::Data {
            chan: 1,
            seq,
            payload: &[0x5a],
        }
        .to_vec()
    };
    let (a, b) = (person("alice"), person("bob"));
    let hello = CentralKnock::new(keys(&b, &a).token_out(E0), counting(0x10)).hello(&keys(&a, &b));
    let mut too_long = vec![KIND_DATA, 1, 0, 0];
    too_long.extend(payload(61));
    let mut no_credit = vec![open1.clone()];
    no_credit.extend((0..=W0).map(one));
    let c = Role::Central;
    let mut out = vec![
        pipe_negative(
            "rnp1_bad_kind_001.json",
            "an unknown kind (0x14)",
            c,
            185,
            &[vec![0x14, 0x00]],
            0,
            Protocol,
        ),
        pipe_negative(
            "rnp1_short_data_001.json",
            "a DATA frame with no payload",
            c,
            185,
            &[open1.clone(), vec![KIND_DATA, 1, 0, 0]],
            1,
            Protocol,
        ),
        pipe_negative(
            "rnp1_credit_overflow_001.json",
            "CREDIT past 64 outstanding (8 + 57)",
            c,
            185,
            &[open1.clone(), Frame::Credit { chan: 1, add: 57 }.to_vec()],
            1,
            Protocol,
        ),
        pipe_negative(
            "rnp1_data_without_credit_001.json",
            "a ninth DATA frame with no CREDIT",
            c,
            185,
            &no_credit,
            9,
            Protocol,
        ),
        pipe_negative(
            "rnp1_seq_gap_001.json",
            "DATA seq 2 after seq 0",
            c,
            185,
            &[open1.clone(), one(0), one(2)],
            2,
            Protocol,
        ),
        pipe_negative(
            "rnp1_chan_owner_001.json",
            "the peripheral opens the central's channel 0",
            c,
            185,
            &[Frame::Open { chan: 0 }.to_vec()],
            0,
            Protocol,
        ),
        pipe_negative(
            "rnp1_data_too_long_001.json",
            "a 65-byte DATA frame on a link of max_rx 64",
            c,
            64,
            &[open1.clone(), too_long],
            1,
            Mtu,
        ),
        pipe_negative(
            "rnp1_knock_after_up_001.json",
            "a HELLO after the pipe is UP",
            Role::Peripheral,
            185,
            &[hello.to_vec()],
            0,
            Protocol,
        ),
    ];
    // Small-order contact keys and the all-zero secret (§2).
    let alice = person("alice");
    let scalar = alice.x25519_agreement_scalar();
    let keys_rows: Vec<Value> = SMALL_ORDER
        .iter()
        .map(|k| {
            assert_eq!(
                pair_keys(&alice, &bytes32(k)).unwrap_err(),
                BeaconError::BadKey
            );
            json!({ "peer_pub_hex": k, "result": "BAD_KEY" })
        })
        .collect();
    let u_rows: Vec<Value> = NON_CONTRIBUTORY_U
        .iter()
        .map(|u| {
            assert_eq!(x25519_dalek::x25519(*scalar, bytes32(u)), [0u8; 32]);
            json!({ "montgomery_u_hex": u, "result": "NONCONTRIBUTORY" })
        })
        .collect();
    out.push((
        "negative/rnb1_noncontributory_001.json".into(),
        vector(
            "RNB1 negative: small-order contact keys and the all-zero pairwise secret",
            "RAVEN_NEARBY_LINK_V1 §2 (the checks of RAVEN_LAN_BEACON_V1 §2.1). contact_keys: \
             alice derives no RNB1 keys for an Ed25519 contact key of small order (BAD_KEY, \
             refused before X25519). shared_secrets: Montgomery u-coordinates for which X25519 \
             with alice's scalar gives the all-zero Z (NONCONTRIBUTORY); no key that passes the \
             contact-key checks maps to one, so this is the second line",
            json!({ "people": people_json(&["alice"]), "own": "alice" }),
            json!({ "contact_keys": keys_rows, "shared_secrets": u_rows }),
        ),
    ));
    out
}

#[test]
fn nearby_known_answer_vectors() {
    let mut files: Vec<(String, Value)> = vec![
        ("rnb1_pair_keys_001.json".into(), pair_keys_vector()),
        ("rnb1_tokens_001.json".into(), tokens_vector()),
        ("rnk1_knock_001.json".into(), knock_vector()),
        ("rnp1_frames_001.json".into(), frames_vector()),
    ];
    files.extend(negative_vectors());
    for (file, v) in &files {
        assert_vector(file, v);
    }
    // No stale file: the directory holds exactly these.
    let mut on_disk = Vec::new();
    for sub in ["", "negative"] {
        for entry in std::fs::read_dir(vectors_dir().join(sub)).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                let name = entry.file_name().into_string().unwrap();
                on_disk.push(if sub.is_empty() {
                    name
                } else {
                    format!("{sub}/{name}")
                });
            }
        }
    }
    on_disk.sort();
    let mut want: Vec<String> = files.into_iter().map(|(f, _)| f).collect();
    want.sort();
    assert_eq!(on_disk, want);
}
