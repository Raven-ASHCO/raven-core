//! Phase 5 P5.18: the custody handoff ops on the RFC1 wire (0x07 HANDOFF
//! with its RHW1 record, 0x08 TAGS; replies 0x87 HANDOFF_RESULT and 0x88
//! TAGS_RESULT), codes 14-16, the gate, and their vectors
//! (`protocol/RAVEN_CUSTODY_HANDOFF_V1.md`).
//!
//! The handler serves the handoff ops only while the handoff gate is open,
//! which a test opens with this thread's debug overrides; release builds
//! ignore those, so the handler-level tests that need the ops served return
//! early there.

use super::*;
use crate::custody_handoff::{
    check_rhw1_rso1, Rhw1, MAX_RHW1_ENVELOPE, MAX_RHW1_RSO1, RHW1_FIXED_LEN,
};

/// Custody live for this thread with the handoff gate as `handoff` and the
/// base-ops-only knob as `base_only`; restored on drop.
struct Handoff {
    _custody: Gates,
}

impl Handoff {
    fn on() -> Self {
        Self::with(true, false)
    }

    fn with(handoff: bool, base_only: bool) -> Self {
        let custody = Gates::set(true, false);
        crate::custody_gate::set_handoff_gate_for_this_thread(Some(handoff));
        set_lab_base_ops_only_for_this_thread(Some(base_only));
        Handoff { _custody: custody }
    }
}

impl Drop for Handoff {
    fn drop(&mut self) {
        crate::custody_gate::set_handoff_gate_for_this_thread(None);
        set_lab_base_ops_only_for_this_thread(None);
    }
}

fn next_hop() -> [u8; 32] {
    id(0xF2).public_key_bytes()
}

fn forward(env: &Envelope, tag: u8) -> Rfc1Request {
    Rfc1Request::Handoff {
        record: Rhw1::forward(next_hop(), rso1_for(env, tag)),
    }
}

fn tags(action: u8, entries: &[([u8; 16], u64)]) -> Vec<u8> {
    let mut f = header(OP_TAGS, &[1; 8]);
    f.push(action);
    f.push(entries.len() as u8);
    for (tag, expires_at_ms) in entries {
        f.extend_from_slice(tag);
        f.extend_from_slice(&expires_at_ms.to_be_bytes());
    }
    f
}

fn handoff_frame(record_bytes: &[u8]) -> Vec<u8> {
    [header(OP_HANDOFF, &[1; 8]), record_bytes.to_vec()].concat()
}

// ── Wire ─────────────────────────────────────────────────────────────────

/// Round trips, the dial classifiers (0x07-0x08 expect replies, 0x87-0x88
/// end a request), the fixed lengths and codes 14-16.
#[test]
fn handoff_frames_roundtrip_and_classify() {
    let env = envelope(&id(0xA0), 1);
    let rso1 = rso1_for(&env, 0x11);
    let requests = [
        forward(&env, 0x11),
        Rfc1Request::Handoff {
            record: Rhw1::deliver(rso1.clone()),
        },
        Rfc1Request::Tags {
            action: TagsAction::Register,
            entries: vec![([1; 16], NOW + 1), ([2; 16], NOW + 2)],
        },
        Rfc1Request::Tags {
            action: TagsAction::Withdraw,
            entries: vec![([3; 16], 0)],
        },
    ];
    for request in requests {
        let frame = encode_request(&[9; 8], &request);
        assert!(frame_expects_reply(&frame) && !frame_is_terminal_reply(&frame));
        assert!(is_handoff_op(frame[5]) && !is_letter_op(frame[5]));
        assert_eq!(is_handoff_request(&frame), frame[5] == OP_HANDOFF);
        match &request {
            Rfc1Request::Handoff { record } => {
                assert_eq!(frame.len(), 58 + record.rso1.len());
                assert_eq!(&frame[14..], &record.encode()[..]);
            }
            Rfc1Request::Tags { entries, .. } => {
                assert_eq!(frame.len(), 16 + 24 * entries.len())
            }
            _ => unreachable!(),
        }
        assert_eq!(
            decode_request(&frame).unwrap(),
            RequestDecode::Request([9; 8], request)
        );
    }
    // Only an RFC1 v1 frame with op 0x07 is a HANDOFF request.
    let frame = encode_request(&[9; 8], &forward(&env, 0x11));
    assert!(is_handoff_request(&frame));
    assert!(!is_handoff_request(&frame[..13]));
    let mut v2 = frame.clone();
    v2[4] = 2;
    assert!(!is_handoff_request(&v2));
    let mut other = frame.clone();
    other[..4].copy_from_slice(b"RFC2");
    assert!(!is_handoff_request(&other));
    for (reply, len) in [
        (
            Rfc1Reply::HandoffResult {
                code: CustodyCode::Ok,
                digest: custody_digest(&env.pack()),
            },
            47,
        ),
        (
            Rfc1Reply::HandoffResult {
                code: CustodyCode::HopRefused,
                digest: [0; 32],
            },
            47,
        ),
        (
            Rfc1Reply::TagsResult {
                code: CustodyCode::Ok,
                accepted: 3,
                conflicts: 1,
            },
            17,
        ),
    ] {
        let frame = encode_reply(&[8; 8], &reply);
        assert!(reply.is_terminal() && frame_is_terminal_reply(&frame));
        assert!(!frame_expects_reply(&frame) && !is_handoff_request(&frame));
        assert_eq!(frame.len(), len);
        assert_eq!(decode_reply(&frame).unwrap(), ([8; 8], reply));
        // A body of another length does not decode.
        let mut long = frame.clone();
        long.push(0);
        assert!(decode_reply(&long).is_err());
        assert!(decode_reply(&frame[..len - 1]).is_err());
    }
    // Codes 14-16 and their registry strings; 17 is still unknown.
    for (value, code, name) in [
        (14, CustodyCode::NextHopUnknown, "CUSTODY_NEXT_HOP_UNKNOWN"),
        (15, CustodyCode::TagUnknown, "CUSTODY_TAG_UNKNOWN"),
        (16, CustodyCode::HopRefused, "CUSTODY_HOP_REFUSED"),
    ] {
        assert_eq!(CustodyCode::from_u8(value), code);
        assert_eq!(code as u8, value);
        assert_eq!(code.registry(), name);
        assert!(!code.held());
    }
    assert_eq!(CustodyCode::from_u8(17), CustodyCode::Persistence);
}

/// TAGS: count 0 or 33, exact-length violations, an unknown action, a
/// WITHDRAW with an expiry and a REGISTER with a zero expiry are MALFORMED;
/// a HANDOFF whose record breaks a rule is MALFORMED; merging repeated tags
/// is a fixed point.
#[test]
fn handoff_requests_strict_decoding_negatives() {
    let malformed = |f: &[u8], op: u8| {
        assert_eq!(
            decode_request(f).unwrap(),
            RequestDecode::Malformed([1; 8], op),
            "{f:?}"
        )
    };
    let register = |n: usize| -> Vec<([u8; 16], u64)> {
        (0..n)
            .map(|i| ([i as u8; 16], NOW + i as u64 + 1))
            .collect()
    };
    // TAGS counts.
    malformed(&tags(1, &[]), OP_TAGS);
    malformed(&tags(1, &register(33)), OP_TAGS);
    assert!(matches!(
        decode_request(&tags(1, &register(32))).unwrap(),
        RequestDecode::Request(_, Rfc1Request::Tags { entries, .. }) if entries.len() == 32
    ));
    // Exact length: one byte short, one trailing, the header alone, the
    // action alone.
    let good = tags(1, &register(2));
    malformed(&good[..good.len() - 1], OP_TAGS);
    malformed(&[good.clone(), vec![0]].concat(), OP_TAGS);
    malformed(&header(OP_TAGS, &[1; 8]), OP_TAGS);
    malformed(&good[..15], OP_TAGS);
    // Unknown actions.
    for action in [0u8, 3, 0xFF] {
        malformed(&tags(action, &register(1)), OP_TAGS);
    }
    // WITHDRAW carries no expiry; REGISTER always one (each entry checked).
    malformed(&tags(2, &[([1; 16], 0), ([2; 16], 5)]), OP_TAGS);
    malformed(&tags(1, &[([1; 16], NOW), ([2; 16], 0)]), OP_TAGS);
    assert!(matches!(
        decode_request(&tags(2, &[([1; 16], 0), ([2; 16], 0)])).unwrap(),
        RequestDecode::Request(
            _,
            Rfc1Request::Tags {
                action: TagsAction::Withdraw,
                ..
            }
        )
    ));
    // Merge: repeats keep their latest expiry, entries come out sorted, and
    // decoding the re-encoded request changes nothing.
    let repeated = tags(
        1,
        &[
            ([9; 16], NOW + 5),
            ([2; 16], NOW + 9),
            ([9; 16], NOW + 7),
            ([2; 16], NOW + 1),
        ],
    );
    let RequestDecode::Request(req_id, request) = decode_request(&repeated).unwrap() else {
        panic!()
    };
    assert_eq!(
        request,
        Rfc1Request::Tags {
            action: TagsAction::Register,
            entries: vec![([2; 16], NOW + 9), ([9; 16], NOW + 7)],
        }
    );
    let again = encode_request(&req_id, &request);
    assert_eq!(again.len(), 16 + 24 * 2);
    assert_eq!(
        decode_request(&again).unwrap(),
        RequestDecode::Request(req_id, request.clone())
    );
    assert_eq!(encode_request(&req_id, &request), again);
    let mut dup_withdraw = tags(2, &[([4; 16], 0), ([4; 16], 0)]);
    let RequestDecode::Request(_, Rfc1Request::Tags { entries, .. }) =
        decode_request(&dup_withdraw).unwrap()
    else {
        panic!()
    };
    assert_eq!(entries, vec![([4; 16], 0)]);
    dup_withdraw[15] = 3; // the count no longer matches the length
    malformed(&dup_withdraw, OP_TAGS);
    // HANDOFF: an empty body, a broken record, the RSO1 bound.
    malformed(&header(OP_HANDOFF, &[1; 8]), OP_HANDOFF);
    let record = Rhw1::forward(next_hop(), rso1_for(&envelope(&id(0xA0), 2), 0x11)).encode();
    let mut kind3 = record.clone();
    kind3[5] = 3;
    malformed(&handoff_frame(&kind3), OP_HANDOFF);
    malformed(&handoff_frame(&record[..record.len() - 1]), OP_HANDOFF);
    let mut big = record[..RHW1_FIXED_LEN].to_vec();
    big[40..44].copy_from_slice(&((MAX_RHW1_RSO1 + 1) as u32).to_be_bytes());
    big.resize(RHW1_FIXED_LEN + MAX_RHW1_RSO1 + 1, 0);
    malformed(&handoff_frame(&big), OP_HANDOFF);
    // A reply op sent as a request stays unknown.
    for op in [OP_HANDOFF_RESULT, OP_TAGS_RESULT] {
        let mut f = header(op, &[1; 8]);
        f.resize(47, 0);
        assert!(!frame_expects_reply(&f));
        assert_eq!(
            decode_request(&f).unwrap(),
            RequestDecode::Unsupported([1; 8])
        );
    }
}

/// The RSO1 inside RHW1 obeys RFC1's rules within the tighter handoff
/// bound: an RSO1 RFC1 DEPOSIT would take is refused one byte over it.
#[test]
fn rhw1_rso1_rules() {
    let env = envelope(&id(0xA0), 3);
    let rso1 = rso1_for(&env, 0x11);
    let (object, unpacked) = check_rhw1_rso1(&rso1).unwrap();
    assert_eq!(object.packed_envelope, env.pack());
    assert_eq!(unpacked.message_id, env.message_id);
    // The RFC1 rules apply (lifetime equal to the envelope's).
    let mut later = StoreObject::unpack(&rso1).unwrap();
    later.created_at_ms += 1;
    assert_eq!(
        check_rhw1_rso1(&later.pack().unwrap()).unwrap_err(),
        "RFC1_RSO1_LIFETIME"
    );
    // An envelope whose RSO1 is one byte over MAX_RHW1_RSO1: RFC1 takes it,
    // RHW1 does not.
    let sized = |rso1_len: usize| {
        let mut e = env.clone();
        e.message_ciphertext = vec![0x44; 16];
        let base = e.pack().len();
        let want = rso1_len - 59;
        e.message_ciphertext = vec![0x44; 16 + want - base];
        e.sign_with(&id(0xA0));
        let object = StoreObject {
            store_tag: [0x11; 16],
            message_id: e.message_id,
            created_at_ms: e.created_at,
            expires_at_ms: e.expires_at,
            flags: 0,
            packed_envelope: e.pack(),
            custody_sig: None,
        };
        let bytes = object.pack().unwrap();
        assert_eq!(bytes.len(), rso1_len);
        bytes
    };
    let at = sized(MAX_RHW1_RSO1);
    let (object, _) = check_rhw1_rso1(&at).unwrap();
    assert_eq!(object.packed_envelope.len(), MAX_RHW1_ENVELOPE);
    let over = sized(MAX_RHW1_RSO1 + 1);
    assert!(check_rfc1_rso1(&over).is_ok());
    assert_eq!(check_rhw1_rso1(&over).unwrap_err(), "RHW1_RSO1_TOO_LARGE");
}

/// Regression (handoff design Step 3 (f)): HOLD, NOT_VERIFIED and MALFORMED
/// to a HANDOFF come back as HANDOFF_RESULT and to TAGS as TAGS_RESULT,
/// never as another op's reply; the handler sends exactly those.
#[test]
fn terminal_for_answers_handoff_ops_with_their_own_replies() {
    for code in [
        CustodyCode::Hold,
        CustodyCode::NotVerified,
        CustodyCode::Malformed,
    ] {
        assert_eq!(
            terminal_for(OP_HANDOFF, code),
            Rfc1Reply::HandoffResult {
                code,
                digest: [0; 32]
            }
        );
        assert_eq!(
            terminal_for(OP_TAGS, code),
            Rfc1Reply::TagsResult {
                code,
                accepted: 0,
                conflicts: 0
            }
        );
        for op in [OP_HANDOFF, OP_TAGS] {
            let frame = encode_reply(&[2; 8], &terminal_for(op, code));
            assert!(frame_is_terminal_reply(&frame));
            assert_eq!(frame[5], op | 0x80);
        }
    }
    // The ops before them keep their own replies.
    assert_eq!(
        terminal_for(OP_RELEASE, CustodyCode::Hold).op(),
        OP_RELEASE_RESULT
    );
    assert_eq!(
        terminal_for(OP_WITHDRAW_LETTERS, CustodyCode::Hold).op(),
        OP_WITHDRAW_RESULT
    );
    if !cfg!(debug_assertions) {
        return;
    }
    let _h = Handoff::on();
    assert!(handoff_ops_served());
    let c = Carol::new();
    let env = envelope(&c.alice, 4);
    let register = Rfc1Request::Tags {
        action: TagsAction::Register,
        entries: vec![([0x11; 16], NOW + HOUR)],
    };
    // A public source on a LAN link without WAN custody: HOLD.
    for request in [forward(&env, 0x11), register.clone()] {
        let op = request.op();
        let replies = c.call(&c.alice, lan("203.0.113.5"), request);
        assert_eq!(replies, [terminal_for(op, CustodyCode::Hold)], "{op:#04x}");
    }
    // A link peer that is not pinned: NOT_VERIFIED, malformed or not.
    let replies = c.call(&c.dave, lan("192.168.1.20"), register);
    assert_eq!(replies, [terminal_for(OP_TAGS, CustodyCode::NotVerified)]);
    let mut kind3 = Rhw1::forward(next_hop(), rso1_for(&env, 0x11)).encode();
    kind3[5] = 3;
    let answer = |from: &Identity, frame: &[u8]| {
        fresh_windows(&from.public_key_bytes());
        let replies = handle_frame(
            c.dir.path(),
            &c.carol,
            &from.public_key_bytes(),
            &lan("192.168.1.20"),
            frame,
            NOW,
        )
        .unwrap();
        assert_eq!(replies.len(), 1);
        decode_reply(&replies[0]).unwrap().1
    };
    assert_eq!(
        answer(&c.dave, &handoff_frame(&kind3)),
        terminal_for(OP_HANDOFF, CustodyCode::NotVerified)
    );
    // A pinned contact on a local source: MALFORMED in the op's own reply.
    assert_eq!(
        answer(&c.alice, &handoff_frame(&kind3)),
        terminal_for(OP_HANDOFF, CustodyCode::Malformed)
    );
    assert_eq!(
        answer(&c.alice, &tags(1, &[])),
        terminal_for(OP_TAGS, CustodyCode::Malformed)
    );
    // A well-formed op is answered by its own terminal reply.
    let served = answer(&c.alice, &encode_request(&[1; 8], &forward(&env, 0x11)));
    assert!(
        matches!(served, Rfc1Reply::HandoffResult { .. }),
        "{served:?}"
    );
    assert!(!custody_db_path(c.dir.path()).exists());
}

// ── The gate and the lab knob ────────────────────────────────────────────

/// With the handoff gate closed, or `RAVEN_LAB_CUSTODY_BASE_OPS_ONLY=1`,
/// every handoff op, well formed or not, is answered UNSUPPORTED (max_version
/// 1, req_id echoed) before anything else, as by a listener built before
/// them (RFC1 §4), not HOLD; the base ops are served as before. Nothing is
/// created.
#[test]
fn handoff_ops_answer_unsupported_while_the_gate_is_closed() {
    let c = Carol::new();
    let env = envelope(&c.alice, 5);
    let mut bad_record = Rhw1::deliver(rso1_for(&env, 0x15)).encode();
    bad_record[4] = 2;
    let mut bad_tags = tags(2, &[([1; 16], 9)]);
    bad_tags[6..14].copy_from_slice(&[5; 8]);
    let mut bad_handoff = handoff_frame(&bad_record);
    bad_handoff[6..14].copy_from_slice(&[5; 8]);
    let frames = [
        encode_request(&[5; 8], &forward(&env, 0x15)),
        encode_request(
            &[5; 8],
            &Rfc1Request::Handoff {
                record: Rhw1::deliver(rso1_for(&env, 0x15)),
            },
        ),
        encode_request(
            &[5; 8],
            &Rfc1Request::Tags {
                action: TagsAction::Register,
                entries: vec![([0x15; 16], NOW + HOUR)],
            },
        ),
        bad_handoff,
        bad_tags,
    ];
    // (handoff gate, knob): the gate closed (in every build), then open
    // with the knob on (debug only: release builds have no override).
    let mut cases = vec![(false, false)];
    if cfg!(debug_assertions) {
        cases.push((true, true));
    }
    for (handoff, base_only) in cases {
        let _h = Handoff::with(handoff, base_only);
        assert!(!handoff_ops_served());
        for frame in &frames {
            let replies = handle_frame(
                c.dir.path(),
                &c.carol,
                &c.alice.public_key_bytes(),
                &lan("192.168.1.20"),
                frame,
                NOW,
            )
            .unwrap();
            assert_eq!(
                replies,
                [unsupported(&[5; 8])],
                "{handoff} {base_only} op {:#04x}",
                frame[5]
            );
            assert_eq!(replies[0].len(), 15);
        }
        // The base ops are unaffected.
        let fill = 0x70 + u8::from(handoff);
        let env = envelope(&c.alice, fill);
        assert_eq!(
            c.deposit(&c.alice, &c.bob, rso1_for(&env, fill)),
            CustodyCode::Ok
        );
        assert_eq!(items(&c.fetch(&c.bob, &[[fill; 16]], None)), 1);
    }
    if cfg!(debug_assertions) {
        // The handoff gate needs custody live: with custody held it stays
        // closed whatever its own switch says.
        let _h = Handoff::on();
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: false,
            wan: false,
        }));
        assert!(!handoff_ops_served());
    }
}

// ── Vectors ──────────────────────────────────────────────────────────────

fn check_vector(path: std::path::PathBuf, expected: serde_json::Value) {
    if std::env::var("RAVEN_REGEN_RHW1_VECTORS").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&expected).unwrap() + "\n",
        )
        .unwrap();
    }
    let stored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(stored, expected, "{}", path.display());
}

/// KATs (handoff spec §8). Regenerate with `RAVEN_REGEN_RHW1_VECTORS=1` only
/// when the wire format changes on purpose. The RFC1 and letter vectors are
/// checked unchanged by their own tests.
#[test]
fn rhw1_known_answer_vectors() {
    let alice_seed = [0xA0u8; 32];
    let alice = Identity::from_seed(&alice_seed);
    let env = envelope(&alice, 1);
    let rso1 = rso1_for(&env, 0x11);
    let digest = custody_digest(&env.pack());
    let req = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let hop_seed = [0xF2u8; 32];
    let forward = Rhw1::forward(
        Identity::from_seed(&hop_seed).public_key_bytes(),
        rso1.clone(),
    );
    let deliver = Rhw1::deliver(rso1.clone());
    let day = 24 * HOUR;
    let description =
        "RFC1 v1 custody handoff frame(s) (RAVEN_CUSTODY_HANDOFF_V1.md); header magic RFC1 | version 1 | op | req_id[8]";
    let record_case = |what: &str, record: &Rhw1, extra: serde_json::Value| {
        let frame = encode_request(
            &req,
            &Rfc1Request::Handoff {
                record: record.clone(),
            },
        );
        let mut inputs = serde_json::json!({
            "signer_seed_hex": hex::encode(alice_seed),
            "store_tag_hex": hex::encode([0x11u8; 16]),
            "custody_digest_hex": hex::encode(digest),
            "page_token_hex": hex::encode(page_token(&rso1)),
            "rso1_len": rso1.len(),
        });
        inputs
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::json!({
            "name": what,
            "protocol_version": "rvn1",
            "deterministic": true,
            "description": description,
            "inputs": inputs,
            "expected": {
                "frame_hex": hex::encode(&frame),
                "frame_len": frame.len(),
                "record_hex": hex::encode(record.encode()),
            },
        })
    };
    let frame_case = |what: &str, bytes: Vec<u8>, inputs: serde_json::Value| {
        serde_json::json!({
            "name": what,
            "protocol_version": "rvn1",
            "deterministic": true,
            "description": description,
            "inputs": inputs,
            "expected": { "frame_hex": hex::encode(&bytes), "frame_len": bytes.len() },
        })
    };
    let positives = [
        (
            "rhw1_forward_001.json",
            record_case(
                "HANDOFF FORWARD of one RSO1 to the final custodian 0xf2.. (the next hop is that seed's Ed25519 key)",
                &forward,
                serde_json::json!({ "kind": "FORWARD", "next_hop_seed_hex": hex::encode(hop_seed) }),
            ),
        ),
        (
            "rhw1_deliver_001.json",
            record_case(
                "HANDOFF DELIVER of the same RSO1 (next_hop all zero)",
                &deliver,
                serde_json::json!({ "kind": "DELIVER" }),
            ),
        ),
        (
            "rfc1_tags_register_001.json",
            frame_case(
                "TAGS REGISTER of two store tags, sorted, each with its expiry",
                encode_request(
                    &req,
                    &Rfc1Request::Tags {
                        action: TagsAction::Register,
                        entries: vec![([0x11; 16], NOW + day), ([0x12; 16], NOW + 2 * day)],
                    },
                ),
                serde_json::json!({ "action": "REGISTER", "count": 2 }),
            ),
        ),
        (
            "rfc1_tags_withdraw_001.json",
            frame_case(
                "TAGS WITHDRAW of one store tag (expiry zero)",
                encode_request(
                    &req,
                    &Rfc1Request::Tags {
                        action: TagsAction::Withdraw,
                        entries: vec![([0x11; 16], 0)],
                    },
                ),
                serde_json::json!({ "action": "WITHDRAW", "count": 1 }),
            ),
        ),
        (
            "rfc1_handoff_replies_001.json",
            frame_case(
                "HANDOFF_RESULT STORED with the digest, HANDOFF_RESULT HOP_REFUSED (16) with the digest, then TAGS_RESULT OK (2 accepted, 1 conflict), concatenated",
                [
                    encode_reply(
                        &req,
                        &Rfc1Reply::HandoffResult {
                            code: CustodyCode::Ok,
                            digest,
                        },
                    ),
                    encode_reply(
                        &req,
                        &Rfc1Reply::HandoffResult {
                            code: CustodyCode::HopRefused,
                            digest,
                        },
                    ),
                    encode_reply(
                        &req,
                        &Rfc1Reply::TagsResult {
                            code: CustodyCode::Ok,
                            accepted: 2,
                            conflicts: 1,
                        },
                    ),
                ]
                .concat(),
                serde_json::json!({ "frame_lengths": [47, 47, 17] }),
            ),
        ),
    ];
    for (name, expected) in positives {
        check_vector(vectors_dir().join(name), expected);
    }

    // Negatives: each frame's decode and the reply a listener serving the
    // handoff ops sends once the link gate and the contact rule passed.
    let fwd = forward.encode();
    let edit = |at: usize, value: u8| {
        let mut b = fwd.clone();
        b[at] = value;
        b
    };
    let mut deliver_with_hop = deliver.encode();
    deliver_with_hop[8..40].copy_from_slice(&[0x5A; 32]);
    let mut forward_zero_hop = fwd.clone();
    forward_zero_hop[8..40].copy_from_slice(&[0; 32]);
    let handoff = |record: Vec<u8>| [header(OP_HANDOFF, &req), record].concat();
    let malformed_handoff = encode_reply(&req, &terminal_for(OP_HANDOFF, CustodyCode::Malformed));
    let malformed_tags = encode_reply(&req, &terminal_for(OP_TAGS, CustodyCode::Malformed));
    let tags_frame = |action: u8, entries: &[([u8; 16], u64)]| {
        let mut f = tags(action, entries);
        f[6..14].copy_from_slice(&req);
        f
    };
    let mut count0 = header(OP_TAGS, &req);
    count0.extend_from_slice(&[1, 0]);
    // (file, what, frame, the RHW1 decode error, the reply)
    type Negative<'a> = (&'a str, &'a str, Vec<u8>, Option<&'a str>, Vec<u8>);
    let negatives: Vec<Negative> = vec![
        (
            "rhw1_neg_deliver_next_hop_001.json",
            "HANDOFF DELIVER with a non-zero next_hop: MALFORMED",
            handoff(deliver_with_hop),
            Some("RHW1_DELIVER_HOP"),
            malformed_handoff.clone(),
        ),
        (
            "rhw1_neg_forward_zero_hop_001.json",
            "HANDOFF FORWARD with an all-zero next_hop: MALFORMED",
            handoff(forward_zero_hop),
            Some("RHW1_FORWARD_NO_HOP"),
            malformed_handoff.clone(),
        ),
        (
            "rhw1_neg_kind3_001.json",
            "RHW1 kind 3: MALFORMED",
            handoff(edit(5, 3)),
            Some("RHW1_KIND"),
            malformed_handoff.clone(),
        ),
        (
            "rhw1_neg_version2_001.json",
            "RHW1 version 2: MALFORMED (a later record format takes a new RFC1 op)",
            handoff(edit(4, 2)),
            Some("RHW1_VERSION"),
            malformed_handoff.clone(),
        ),
        (
            "rhw1_neg_flags_001.json",
            "RHW1 flags 0x01: MALFORMED",
            handoff(edit(6, 1)),
            Some("RHW1_FLAGS"),
            malformed_handoff.clone(),
        ),
        (
            "rhw1_neg_len_mismatch_001.json",
            "RHW1 with one byte after its rso1_len bytes: MALFORMED",
            handoff([fwd.clone(), vec![0]].concat()),
            Some("RHW1_LENGTH"),
            malformed_handoff,
        ),
        (
            "rfc1_neg_tags_count0_001.json",
            "TAGS REGISTER with count 0: MALFORMED",
            count0,
            None,
            malformed_tags.clone(),
        ),
        (
            "rfc1_neg_tags_withdraw_expiry_001.json",
            "TAGS WITHDRAW whose entry carries an expiry: MALFORMED",
            tags_frame(2, &[([0x11; 16], NOW + day)]),
            None,
            malformed_tags,
        ),
        (
            "rfc1_neg_handoff_result_as_request_001.json",
            "A HANDOFF_RESULT (reply op 0x87) sent as a request: UNSUPPORTED, max_version 1, echoing req_id",
            encode_reply(
                &req,
                &Rfc1Reply::HandoffResult {
                    code: CustodyCode::Ok,
                    digest,
                },
            ),
            None,
            unsupported(&req),
        ),
    ];
    for (name, what, frame, rhw1_error, reply) in negatives {
        let decode = match decode_request(&frame).unwrap() {
            RequestDecode::Malformed(id, op) => {
                assert_eq!((id, op), (req, frame[5]), "{name}");
                "MALFORMED"
            }
            RequestDecode::Unsupported(id) => {
                assert_eq!(id, req, "{name}");
                "UNSUPPORTED"
            }
            other => panic!("{name}: {other:?}"),
        };
        if let Some(err) = rhw1_error {
            assert_eq!(Rhw1::decode(&frame[RFC1_HEADER_LEN..]), Err(err), "{name}");
        }
        let mut expected = serde_json::json!({
            "decode": decode,
            "reply_frame_hex": hex::encode(&reply),
            "reply_frame_len": reply.len(),
        });
        if let Some(err) = rhw1_error {
            expected["rhw1_error"] = serde_json::json!(err);
        }
        check_vector(
            vectors_dir().join("negative").join(name),
            serde_json::json!({
                "name": what,
                "protocol_version": "rvn1",
                "deterministic": true,
                "description": "Negative RFC1 v1 custody handoff frame (RAVEN_CUSTODY_HANDOFF_V1.md); the reply is what a listener serving the handoff ops sends once its link gate and contact rule passed",
                "inputs": { "frame_hex": hex::encode(&frame), "frame_len": frame.len() },
                "expected": expected,
            }),
        );
    }
}
