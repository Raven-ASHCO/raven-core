//! RUP1 update exchange frames (RAVEN_UPDATE_EXCHANGE_V1) and the vectors in
//! `shared-vectors/rvn1/update` (`rup1_*`). The vectors are written only
//! under `RAVEN_REGEN_SECURITY_VECTORS=1` (a deliberate wire change) and
//! otherwise compared with the committed files; the Python reference
//! (`protocol/reference/raven_protocol/update_exchange.py`) checks every one,
//! builds every frame again byte for byte, computes every chunk's audit path
//! on its own and replays every refusal and every listener decision.
//!
//! The artifacts inside the frames are the test release of
//! `update/rrbc_small_001.json` (its advisory, log snapshot, manifest and
//! payload); the chunk frames cut the synthetic payloads of
//! `update/rrb1_chunk_tree_001.json` (byte j = j mod 251).

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::*;
use crate::internet::{hello_caps, LinkFeatures, CAP_LINK_RUP1};
use crate::link_padding::{wrap, PAD1_BUCKETS};
use crate::release_bundle::{
    chunk_count, chunk_leaf_hashes, verify_chunk_path, Container, FileMode, ManifestDraft,
    PackFile, Parts,
};
use crate::release_keys::test_keys::{key_set, signer};
use crate::route_hints::{rlx1_caps, rlx1_payload};
use crate::tlog::{leaf_hash, node_hash};

const REGEN: &str = "RAVEN_REGEN_SECURITY_VECTORS";
/// The small synthetic payload: 4 full chunks and 1,000 bytes.
const SMALL_PAYLOAD_LEN: usize = 4 * CHUNK_SIZE as usize + 1_000;
/// The request ids the vectors use.
const REQ: [u8; 4] = [0x52, 0x55, 0x00, 0x01];
const REQ_CHUNKS: [u8; 4] = [0x52, 0x55, 0x00, 0x05];

fn rvn1_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.pop();
    p.join("shared-vectors/rvn1")
}

fn read_vector(file: &str) -> Value {
    let path = rvn1_dir().join("update").join(file);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing vector {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap()
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// `len` bytes, byte `j` = `(start + j) mod 251`: the synthetic payloads'
/// bytes from offset `start`.
fn pattern(len: usize, start: usize) -> Vec<u8> {
    (0..len).map(|j| ((start + j) % 251) as u8).collect()
}

/// The test release of `update/rrbc_small_001.json`.
fn test_release() -> Parts {
    let v = read_vector("rrbc_small_001.json");
    let bytes = hex::decode(v["expected"]["container_hex"].as_str().unwrap()).unwrap();
    Container::open(&bytes[..]).unwrap()
}

fn frame(req_id: &[u8; 4], msg: &Rup1Msg) -> Vec<u8> {
    encode(req_id, msg).unwrap_or_else(|e| panic!("{msg:?}: {e}"))
}

/// A frame of any version and op with this body.
fn raw(version: u8, op: u8, req_id: [u8; 4], body: &[u8]) -> Vec<u8> {
    [&RUP1_MAGIC[..], &[version, op], &req_id, body].concat()
}

fn v1(op: u8, body: &[u8]) -> Vec<u8> {
    raw(RUP1_VERSION, op, REQ, body)
}

/// The test release's HAVE: its advisory, its log and the bundle itself.
fn release_have(p: &Parts) -> Have {
    let advisory = p.advisory.as_ref().unwrap();
    Have {
        adv_serial: advisory.serial,
        adv_digest: advisory.digest(),
        log_size: p.snapshot.sth().tree_size as u32,
        log_root: p.snapshot.sth().root_hash,
        offers: vec![Offer {
            build_serial: p.manifest.build_serial,
            target: p.manifest.target.clone(),
            manifest_digest: p.manifest.digest(),
            payload_len: p.manifest.payload_len,
        }],
    }
}

/// A target of exactly 64 bytes.
fn longest_target(c: char) -> String {
    format!("{}-{}", c.to_string().repeat(31), "b".repeat(32))
}

fn offer(serial: u64, target: &str, digest_byte: u8, payload_len: u64) -> Offer {
    Offer {
        build_serial: serial,
        target: target.into(),
        manifest_digest: [digest_byte; 32],
        payload_len,
    }
}

fn four_offers() -> Have {
    Have {
        adv_serial: 7,
        adv_digest: [0xAD; 32],
        log_size: 40,
        log_root: [0x10; 32],
        offers: vec![
            offer(9, "aarch64-apple-darwin", 0xA1, 34_000_000),
            offer(9, "x86_64-apple-darwin", 0xA2, 35_000_000),
            offer(9, "x86_64-unknown-linux-gnu", 0xA3, 31_000_000),
            offer(8, "x86_64-pc-windows-msvc", 0xA4, MAX_PAYLOAD_LEN),
        ],
    }
}

fn longest_have() -> Have {
    Have {
        adv_serial: u64::MAX,
        adv_digest: [0xFF; 32],
        log_size: MAX_LOG_ENTRIES as u32,
        log_root: [0xEE; 32],
        offers: ['a', 'c', 'd', 'e']
            .iter()
            .enumerate()
            .map(|(i, c)| {
                offer(
                    u64::MAX,
                    &longest_target(*c),
                    0xB0 + i as u8,
                    MAX_PAYLOAD_LEN,
                )
            })
            .collect(),
    }
}

/// The synthetic small payload and its chunk tree.
fn small() -> (Vec<u8>, ChunkTree) {
    let payload = pattern(SMALL_PAYLOAD_LEN, 0);
    let tree = ChunkTree::new(&payload, CHUNK_SIZE);
    (payload, tree)
}

/// Chunk 0 and chunk 1,092 of the 64 MiB payload with their paths, from
/// its leaf hashes (each distinct chunk hashed once: the payload repeats
/// every 251 bytes).
fn max_chunks() -> (ChunkTree, Vec<Chunk>) {
    let size = CHUNK_SIZE as usize;
    let len = MAX_PAYLOAD_LEN as usize;
    let mut seen = std::collections::HashMap::new();
    let leaves: Vec<[u8; 32]> = (0..len.div_ceil(size))
        .map(|k| {
            let (start, n) = (k * size, size.min(len - k * size));
            *seen
                .entry((start % 251, n))
                .or_insert_with(|| leaf_hash(&pattern(n, start)))
        })
        .collect();
    let tree = ChunkTree::of_leaf_hashes(leaves);
    let chunks = [0usize, MAX_CHUNKS as usize - 1]
        .iter()
        .map(|&i| {
            let start = i * size;
            Chunk {
                index: i as u32,
                bytes: pattern(size.min(len - start), start),
                path: tree.chunk_path(i).unwrap(),
            }
        })
        .collect();
    (tree, chunks)
}

fn listener(frame: &[u8]) -> String {
    match decode_for_listener(frame) {
        ListenerDecode::Request(..) => "REQUEST".into(),
        ListenerDecode::Have(_) => "HAVE".into(),
        ListenerDecode::Refuse(_, code) => format!("ERROR {}", code.name()),
        ListenerDecode::Drop => "DROP".into(),
    }
}

fn role_name(msg: &Rup1Msg) -> &'static str {
    match msg.role() {
        Role::OneWay => "ONE_WAY",
        Role::Request => "REQUEST",
        Role::Reply { terminal: true } => "TERMINAL_REPLY",
        Role::Reply { terminal: false } => "REPLY",
    }
}

fn op_name(op: u8) -> &'static str {
    match op {
        OP_HAVE => "HAVE",
        OP_GET_ADVISORY => "GET_ADVISORY",
        OP_GET_LOG => "GET_LOG",
        OP_GET_MANIFEST => "GET_MANIFEST",
        OP_GET_CHUNKS => "GET_CHUNKS",
        OP_GET_ROTATION => "GET_ROTATION",
        OP_ADVISORY => "ADVISORY",
        OP_LOG => "LOG",
        OP_MANIFEST => "MANIFEST",
        OP_CHUNK => "CHUNK",
        OP_CHUNKS_END => "CHUNKS_END",
        OP_ERROR => "ERROR",
        _ => "UNKNOWN",
    }
}

/// The fields of a frame as the vectors give them.
fn msg_json(msg: &Rup1Msg) -> Value {
    match msg {
        Rup1Msg::Have(h) => json!({
            "adv_serial": h.adv_serial,
            "adv_digest_hex": hex::encode(h.adv_digest),
            "log_size": h.log_size,
            "log_root_hex": hex::encode(h.log_root),
            "offers": h.offers.iter().map(|o| json!({
                "build_serial": o.build_serial,
                "target": o.target,
                "manifest_digest_hex": hex::encode(o.manifest_digest),
                "payload_len": o.payload_len,
            })).collect::<Vec<_>>(),
        }),
        Rup1Msg::GetAdvisory | Rup1Msg::GetLog => json!({}),
        Rup1Msg::GetManifest { manifest_digest } => {
            json!({ "manifest_digest_hex": hex::encode(manifest_digest) })
        }
        Rup1Msg::GetRotation { key_set_digest } => {
            json!({ "key_set_digest_hex": hex::encode(key_set_digest) })
        }
        Rup1Msg::GetChunks {
            manifest_digest,
            first,
            count,
        } => json!({
            "manifest_digest_hex": hex::encode(manifest_digest),
            "first": first,
            "count": count,
        }),
        Rup1Msg::Advisory { rad1, snapshot } => json!({
            "rad1_hex": hex::encode(rad1),
            "snapshot_hex": hex::encode(snapshot),
        }),
        Rup1Msg::Log { snapshot } => json!({ "snapshot_hex": hex::encode(snapshot) }),
        Rup1Msg::Manifest { manifest, snapshot } => json!({
            "manifest_hex": hex::encode(manifest),
            "snapshot_hex": hex::encode(snapshot),
        }),
        Rup1Msg::Chunk(c) => json!({
            "index": c.index,
            "bytes_hex": hex::encode(&c.bytes),
            "path_hex": c.path.iter().map(hex::encode).collect::<Vec<_>>(),
        }),
        Rup1Msg::ChunksEnd { stopped, sent } => json!({
            "code": stopped.map_or(0, ErrorCode::byte),
            "sent": sent,
        }),
        Rup1Msg::Error(code) => json!({ "code": code.byte(), "code_name": code.name() }),
    }
}

/// One frame of every op (the test release's artifacts), and the ERROR and
/// CHUNKS_END codes.
fn frame_cases(p: &Parts) -> Vec<(String, [u8; 4], Rup1Msg)> {
    let rad1 = p.advisory.as_ref().unwrap().bytes().to_vec();
    let snapshot = p.snapshot.encode();
    let digest = p.manifest.digest();
    let tree = ChunkTree::new(&p.payload, CHUNK_SIZE);
    let chunk = Chunk::of_payload(&p.payload, &tree, 0).unwrap();
    let mut cases = vec![
        (
            "have_nothing".into(),
            NO_REQ_ID,
            Rup1Msg::Have(Have::nothing()),
        ),
        (
            "have_test_release".into(),
            NO_REQ_ID,
            Rup1Msg::Have(release_have(p)),
        ),
        ("get_advisory".into(), REQ, Rup1Msg::GetAdvisory),
        (
            "advisory".into(),
            REQ,
            Rup1Msg::Advisory {
                rad1,
                snapshot: snapshot.clone(),
            },
        ),
        ("get_log".into(), REQ, Rup1Msg::GetLog),
        (
            "log".into(),
            REQ,
            Rup1Msg::Log {
                snapshot: snapshot.clone(),
            },
        ),
        (
            "get_manifest".into(),
            REQ,
            Rup1Msg::GetManifest {
                manifest_digest: digest,
            },
        ),
        (
            "manifest".into(),
            REQ,
            Rup1Msg::Manifest {
                manifest: p.manifest.bytes().to_vec(),
                snapshot,
            },
        ),
        (
            "get_chunks".into(),
            REQ,
            Rup1Msg::GetChunks {
                manifest_digest: digest,
                first: 0,
                count: 1,
            },
        ),
        ("chunk".into(), REQ, Rup1Msg::Chunk(chunk)),
        (
            "chunks_end_ok".into(),
            REQ,
            Rup1Msg::ChunksEnd {
                stopped: None,
                sent: 1,
            },
        ),
        (
            "chunks_end_busy".into(),
            REQ,
            Rup1Msg::ChunksEnd {
                stopped: Some(ErrorCode::Busy),
                sent: 0,
            },
        ),
        (
            "get_rotation".into(),
            REQ,
            Rup1Msg::GetRotation {
                key_set_digest: p.manifest.key_set_digest,
            },
        ),
    ];
    for b in [1u8, 2, 3, 4, 5, 6, 42] {
        let code = ErrorCode::from_byte(b).unwrap();
        cases.push((
            format!("error_{}", code.name().to_lowercase()),
            REQ,
            Rup1Msg::Error(code),
        ));
    }
    cases
}

// ── Rules ───────────────────────────────────────────────────────────

#[test]
fn constants() {
    assert_eq!(HEADER_LEN, 10);
    assert_eq!(MAX_FRAME_LEN, 65_511);
    assert_eq!(MAX_FRAME_LEN, PAD1_MAX_INNER);
    assert_eq!(HAVE_FIXED_LEN, 77);
    assert_eq!(OFFER_FIXED_LEN, 49);
    assert_eq!(MAX_HAVE_LEN, 539);
    assert_eq!(GET_CHUNKS_LEN, 47);
    assert_eq!(GET_ROTATION_LEN, 42);
    assert_eq!(MAX_CHUNK_FRAME_LEN, 61_811);
    assert_eq!(MAX_MANIFEST_FRAME_LEN, 63_233);
    assert_eq!(MAX_LOG_FRAME_LEN, 58_033);
    assert_eq!(ADVISORY_ALWAYS_FITS, 7_476);
    assert_eq!(MAX_CHUNKS, 1_093);
    assert_eq!(MAX_CHUNK_PATH_LEN, 11);
    assert_eq!(MAX_OFFERS, 4);
    assert_eq!(MAX_CHUNKS_PER_REQUEST, 8);
    assert_eq!(MAX_CHUNKS_PER_DIAL, 16);
    assert_eq!(CAP_LINK_RUP1, 0x0000_0400);
    assert_eq!(LinkFeatures::RUP1.bits(), CAP_LINK_RUP1);
    // The deepest tree a version 1 payload has: 1,093 chunks, 11 levels.
    assert_eq!((MAX_CHUNKS - 1).ilog2() + 1, 11);
    assert_eq!(ErrorCode::from_byte(0), None);
    for b in 1..=255u8 {
        assert_eq!(ErrorCode::from_byte(b).unwrap().byte(), b);
    }
}

#[test]
fn every_op_round_trips() {
    let p = test_release();
    for (name, req_id, msg) in frame_cases(&p) {
        let bytes = frame(&req_id, &msg);
        assert_eq!(decode(&bytes), Ok((req_id, msg.clone())), "{name}");
        assert_eq!(&bytes[..4], RUP1_MAGIC);
        assert_eq!(bytes[4], RUP1_VERSION);
        assert_eq!(bytes[5], msg.op());
        assert_eq!(bytes[6..10], req_id);
        let body = bytes.len() - HEADER_LEN;
        let expected = match &msg {
            Rup1Msg::Have(h) => {
                HAVE_FIXED_LEN
                    + h.offers
                        .iter()
                        .map(|o| OFFER_FIXED_LEN + o.target.len())
                        .sum::<usize>()
            }
            Rup1Msg::GetAdvisory | Rup1Msg::GetLog => 0,
            Rup1Msg::GetManifest { .. } => 32,
            Rup1Msg::GetRotation { .. } => GET_ROTATION_LEN - HEADER_LEN,
            Rup1Msg::GetChunks { .. } => GET_CHUNKS_LEN - HEADER_LEN,
            Rup1Msg::Advisory { rad1, snapshot } => 2 + rad1.len() + snapshot.len(),
            Rup1Msg::Log { snapshot } => snapshot.len(),
            Rup1Msg::Manifest { manifest, snapshot } => 2 + manifest.len() + snapshot.len(),
            Rup1Msg::Chunk(c) => 8 + c.bytes.len() + 1 + 32 * c.path.len(),
            Rup1Msg::ChunksEnd { .. } => 2,
            Rup1Msg::Error(_) => 1,
        };
        assert_eq!(body, expected, "{name}");
    }
    for have in [four_offers(), longest_have()] {
        let bytes = frame(&NO_REQ_ID, &Rup1Msg::Have(have.clone()));
        assert_eq!(decode(&bytes), Ok((NO_REQ_ID, Rup1Msg::Have(have))));
    }
    assert_eq!(
        frame(&NO_REQ_ID, &Rup1Msg::Have(longest_have())).len(),
        MAX_HAVE_LEN
    );
}

#[test]
fn classifiers_agree_with_the_ops() {
    let p = test_release();
    for (name, req_id, msg) in frame_cases(&p) {
        let bytes = frame(&req_id, &msg);
        assert!(is_rup1(&bytes));
        assert_eq!(
            frame_expects_reply(&bytes),
            msg.role() == Role::Request,
            "{name}"
        );
        assert_eq!(frame_is_terminal_reply(&bytes), msg.is_terminal(), "{name}");
        // Another version, or a frame cut inside its header, is neither.
        let mut other = bytes.clone();
        other[4] = 2;
        assert!(!frame_expects_reply(&other) && !frame_is_terminal_reply(&other));
        for cut in 0..HEADER_LEN {
            assert!(!frame_expects_reply(&bytes[..cut]));
            assert!(!frame_is_terminal_reply(&bytes[..cut]));
        }
    }
    // HAVE is one-way; CHUNK is the only reply that does not end a request.
    assert!(!frame_expects_reply(&v1(OP_HAVE, &[])));
    assert!(!frame_is_terminal_reply(&v1(OP_HAVE, &[])));
    assert!(!frame_is_terminal_reply(&v1(OP_CHUNK, &[])));
    // Other protocols are not RUP1.
    for other in [&b"RFC1\x01\x01"[..], b"RSR1\x01\x01", b"RUP", b""] {
        assert!(!is_rup1(other));
    }
}

/// A decode case: its name, its frame, the expected result and what a
/// listener does with it.
struct Case {
    name: String,
    frame: Vec<u8>,
    /// How the vectors give the frame: whole, or a head, a pattern fill and
    /// a tail.
    spec: Value,
    result: Result<(), Rup1Error>,
    listener: &'static str,
}

fn whole(frame: Vec<u8>) -> (Vec<u8>, Value) {
    let spec = json!({ "frame_hex": hex::encode(&frame) });
    (frame, spec)
}

/// `head || pattern(fill_len, fill_start) || tail`, optionally with the
/// byte at `xor_at` flipped (`^ 0x01`).
fn filled(
    head: &[u8],
    fill_len: usize,
    fill_start: usize,
    tail: &[u8],
    xor_at: Option<usize>,
) -> (Vec<u8>, Value) {
    let mut frame = [head, &pattern(fill_len, fill_start), tail].concat();
    if let Some(at) = xor_at {
        frame[at] ^= 1;
    }
    let spec = json!({
        "frame": {
            "head_hex": hex::encode(head),
            "fill_len": fill_len,
            "fill_start": fill_start,
            "tail_hex": hex::encode(tail),
            "xor_at": xor_at,
            "len": frame.len(),
            "sha256_hex": hex::encode(sha(&frame)),
        }
    });
    (frame, spec)
}

fn case(
    name: &str,
    (frame, spec): (Vec<u8>, Value),
    result: Result<(), Rup1Error>,
    listener: &'static str,
) -> Case {
    Case {
        name: name.into(),
        frame,
        spec,
        result,
        listener,
    }
}

fn have_bytes(
    adv: (u64, [u8; 32]),
    log: (u32, [u8; 32]),
    n: u8,
    offers: &[(u64, &[u8], [u8; 32], u64)],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(adv.0.to_be_bytes());
    b.extend(adv.1);
    b.extend(log.0.to_be_bytes());
    b.extend(log.1);
    b.push(n);
    for (serial, target, digest, len) in offers {
        b.extend(serial.to_be_bytes());
        b.push(target.len() as u8);
        b.extend_from_slice(target);
        b.extend(digest);
        b.extend(len.to_be_bytes());
    }
    b
}

fn have_frame(body: &[u8]) -> Vec<u8> {
    raw(RUP1_VERSION, OP_HAVE, NO_REQ_ID, body)
}

/// Every refusal of spec §4 and the accepted edges, for every op.
fn decode_cases() -> Vec<Case> {
    use Rup1Error as E;
    let ok = Ok(());
    let t = b"aarch64-apple-darwin".as_slice();
    let adv = (1, [0xAD; 32]);
    let log = (3, [0x10; 32]);
    let one = |serial, target: &'static [u8], len| [(serial, target, [0xA1; 32], len)];
    let have = |adv, log, offers: &[(u64, &[u8], [u8; 32], u64)]| {
        whole(have_frame(&have_bytes(
            adv,
            log,
            offers.len() as u8,
            offers,
        )))
    };
    let digest = [0x5A; 32];
    let chunks = |first: u32, count: u8| {
        whole(v1(
            OP_GET_CHUNKS,
            &[&digest[..], &first.to_be_bytes(), &[count]].concat(),
        ))
    };
    let end = |code: u8, sent: u8| whole(v1(OP_CHUNKS_END, &[code, sent]));
    let head = |op: u8| raw(RUP1_VERSION, op, REQ, &[]);
    let t65 = format!("{}-x", longest_target('a'));
    let mut v = vec![
        // The header.
        case(
            "other_magic",
            whole(b"RUP2\x01\x03RU\x00\x01".to_vec()),
            Err(E::NotRup1),
            "DROP",
        ),
        case(
            "rfc1_frame",
            whole(b"RFC1\x01\x01RU\x00\x01\x00\x00\x00\x00".to_vec()),
            Err(E::NotRup1),
            "DROP",
        ),
        case(
            "header_cut",
            whole(b"RUP1\x01\x03".to_vec()),
            Err(E::Truncated),
            "DROP",
        ),
        case(
            "header_only_magic",
            whole(b"RUP1".to_vec()),
            Err(E::Truncated),
            "DROP",
        ),
        case(
            "version_0",
            whole(raw(0, OP_GET_LOG, REQ, &[])),
            Err(E::BadVersion),
            "ERROR UNSUPPORTED",
        ),
        case(
            "version_2",
            whole(raw(2, OP_GET_LOG, REQ, &[])),
            Err(E::BadVersion),
            "ERROR UNSUPPORTED",
        ),
        case(
            "version_2_reply",
            whole(raw(2, OP_LOG, REQ, &[1])),
            Err(E::BadVersion),
            "ERROR UNSUPPORTED",
        ),
        case(
            "op_0x00",
            whole(head(0x00)),
            Err(E::UnknownOp),
            "ERROR UNSUPPORTED",
        ),
        case(
            "op_0x07",
            whole(head(0x07)),
            Err(E::UnknownOp),
            "ERROR UNSUPPORTED",
        ),
        case(
            "op_0x7f",
            whole(head(0x7F)),
            Err(E::UnknownOp),
            "ERROR UNSUPPORTED",
        ),
        case("op_0x80", whole(head(0x80)), Err(E::UnknownOp), "DROP"),
        case("op_0x81", whole(head(0x81)), Err(E::UnknownOp), "DROP"),
        case("op_0x87", whole(head(0x87)), Err(E::UnknownOp), "DROP"),
        case("op_0xfe", whole(head(0xFE)), Err(E::UnknownOp), "DROP"),
        case(
            "too_long_get_log",
            filled(
                &head(OP_GET_LOG),
                MAX_FRAME_LEN + 1 - HEADER_LEN,
                0,
                &[],
                None,
            ),
            Err(E::TooLong),
            "ERROR MALFORMED",
        ),
        case(
            "too_long_log",
            filled(&head(OP_LOG), MAX_FRAME_LEN + 1 - HEADER_LEN, 0, &[], None),
            Err(E::TooLong),
            "DROP",
        ),
        case(
            "too_long_version_2",
            filled(
                &raw(2, OP_GET_LOG, REQ, &[]),
                MAX_FRAME_LEN + 1 - HEADER_LEN,
                0,
                &[],
                None,
            ),
            Err(E::TooLong),
            "ERROR UNSUPPORTED",
        ),
        // HAVE.
        case(
            "have_nothing",
            have((0, [0; 32]), (0, [0; 32]), &[]),
            ok,
            "HAVE",
        ),
        case(
            "have_one_offer",
            have(adv, log, &one(5, t, 2_170)),
            ok,
            "HAVE",
        ),
        case(
            "have_req_id",
            whole(raw(
                RUP1_VERSION,
                OP_HAVE,
                REQ,
                &have_bytes(adv, log, 0, &[]),
            )),
            Err(E::NonzeroReqId),
            "DROP",
        ),
        case(
            "have_serial_without_digest",
            have((1, [0; 32]), log, &[]),
            Err(E::BadAdvisoryRef),
            "DROP",
        ),
        case(
            "have_digest_without_serial",
            have((0, [0xAD; 32]), log, &[]),
            Err(E::BadAdvisoryRef),
            "DROP",
        ),
        case(
            "have_log_size_1400",
            have(adv, (1_400, [0x10; 32]), &[]),
            ok,
            "HAVE",
        ),
        case(
            "have_log_size_1401",
            have(adv, (1_401, [0x10; 32]), &[]),
            Err(E::BadLogRef),
            "DROP",
        ),
        case(
            "have_log_size_max",
            have(adv, (u32::MAX, [0x10; 32]), &[]),
            Err(E::BadLogRef),
            "DROP",
        ),
        case(
            "have_root_without_log",
            have(adv, (0, [0x10; 32]), &[]),
            Err(E::BadLogRef),
            "DROP",
        ),
        case(
            "have_log_without_root",
            have(adv, (3, [0; 32]), &[]),
            Err(E::BadLogRef),
            "DROP",
        ),
        case(
            "have_five_offers",
            whole(have_frame(&have_bytes(adv, log, 5, &[]))),
            Err(E::TooManyOffers),
            "DROP",
        ),
        case(
            "have_255_offers",
            whole(have_frame(&have_bytes(adv, log, 255, &[]))),
            Err(E::TooManyOffers),
            "DROP",
        ),
        case(
            "have_build_serial_0",
            have(adv, log, &one(0, t, 2_170)),
            Err(E::BadSerial),
            "DROP",
        ),
        case(
            "have_target_empty",
            have(adv, log, &one(5, b"", 2_170)),
            Err(E::BadTarget),
            "DROP",
        ),
        case(
            "have_target_65",
            have(adv, log, &[(5, t65.as_bytes(), [0xA1; 32], 2_170)]),
            Err(E::BadTarget),
            "DROP",
        ),
        case(
            "have_target_upper_case",
            have(adv, log, &one(5, b"AARCH64-apple-darwin", 2_170)),
            Err(E::BadTarget),
            "DROP",
        ),
        case(
            "have_target_one_part",
            have(adv, log, &one(5, b"aarch64", 2_170)),
            Err(E::BadTarget),
            "DROP",
        ),
        case(
            "have_target_empty_part",
            have(adv, log, &one(5, b"aarch64--darwin", 2_170)),
            Err(E::BadTarget),
            "DROP",
        ),
        case(
            "have_target_slash",
            have(adv, log, &one(5, b"aarch64-apple/darwin", 2_170)),
            Err(E::BadTarget),
            "DROP",
        ),
        case(
            "have_target_not_utf8",
            have(adv, log, &one(5, b"aarch64-\xff", 2_170)),
            Err(E::BadTarget),
            "DROP",
        ),
        case(
            "have_payload_0",
            have(adv, log, &one(5, t, 0)),
            Err(E::BadPayloadLen),
            "DROP",
        ),
        case(
            "have_payload_64_mib",
            have(adv, log, &one(5, t, MAX_PAYLOAD_LEN)),
            ok,
            "HAVE",
        ),
        case(
            "have_payload_over_64_mib",
            have(adv, log, &one(5, t, MAX_PAYLOAD_LEN + 1)),
            Err(E::BadPayloadLen),
            "DROP",
        ),
        case(
            "have_duplicate_offer",
            have(
                adv,
                log,
                &[
                    (5, t, [0xA1; 32], 2_170),
                    (6, b"x86_64-apple-darwin", [0xA1; 32], 2_170),
                ],
            ),
            Err(E::DuplicateOffer),
            "DROP",
        ),
        case(
            "have_offer_cut",
            whole(have_frame(&have_bytes(adv, log, 1, &[]))),
            Err(E::Truncated),
            "DROP",
        ),
        case(
            "have_target_cut",
            {
                let mut f = have_frame(&have_bytes(adv, log, 1, &one(5, t, 2_170)));
                f.truncate(HEADER_LEN + HAVE_FIXED_LEN + 9 + 4);
                whole(f)
            },
            Err(E::Truncated),
            "DROP",
        ),
        case(
            "have_fixed_cut",
            whole(have_frame(
                &have_bytes(adv, log, 0, &[])[..HAVE_FIXED_LEN - 1],
            )),
            Err(E::Truncated),
            "DROP",
        ),
        case(
            "have_trailing",
            whole([have_frame(&have_bytes(adv, log, 0, &[])), vec![0]].concat()),
            Err(E::TrailingBytes),
            "DROP",
        ),
        case(
            "have_longest",
            whole(frame(&NO_REQ_ID, &Rup1Msg::Have(longest_have()))),
            ok,
            "HAVE",
        ),
        // GET_ADVISORY, GET_LOG, GET_MANIFEST.
        case("get_advisory", whole(head(OP_GET_ADVISORY)), ok, "REQUEST"),
        case(
            "get_advisory_trailing",
            whole(v1(OP_GET_ADVISORY, &[0])),
            Err(E::TrailingBytes),
            "ERROR MALFORMED",
        ),
        case("get_log", whole(head(OP_GET_LOG)), ok, "REQUEST"),
        case(
            "get_log_trailing",
            whole(v1(OP_GET_LOG, &[0])),
            Err(E::TrailingBytes),
            "ERROR MALFORMED",
        ),
        case(
            "get_manifest",
            whole(v1(OP_GET_MANIFEST, &digest)),
            ok,
            "REQUEST",
        ),
        case(
            "get_manifest_cut",
            whole(v1(OP_GET_MANIFEST, &digest[..31])),
            Err(E::Truncated),
            "ERROR MALFORMED",
        ),
        case(
            "get_manifest_trailing",
            whole(v1(OP_GET_MANIFEST, &[&digest[..], &[0]].concat())),
            Err(E::TrailingBytes),
            "ERROR MALFORMED",
        ),
        // GET_ROTATION (added under version 1, Phase 6 review).
        case(
            "get_rotation",
            whole(v1(OP_GET_ROTATION, &digest)),
            ok,
            "REQUEST",
        ),
        case(
            "get_rotation_empty",
            whole(head(OP_GET_ROTATION)),
            Err(E::Truncated),
            "ERROR MALFORMED",
        ),
        case(
            "get_rotation_cut",
            whole(v1(OP_GET_ROTATION, &digest[..31])),
            Err(E::Truncated),
            "ERROR MALFORMED",
        ),
        case(
            "get_rotation_trailing",
            whole(v1(OP_GET_ROTATION, &[&digest[..], &[0]].concat())),
            Err(E::TrailingBytes),
            "ERROR MALFORMED",
        ),
        // GET_CHUNKS.
        case("get_chunks_8", chunks(0, 8), ok, "REQUEST"),
        case(
            "get_chunks_last_8",
            chunks(MAX_CHUNKS as u32 - 8, 8),
            ok,
            "REQUEST",
        ),
        case(
            "get_chunks_count_0",
            chunks(0, 0),
            Err(E::BadCount),
            "ERROR MALFORMED",
        ),
        case(
            "get_chunks_count_9",
            chunks(0, 9),
            Err(E::BadCount),
            "ERROR MALFORMED",
        ),
        case(
            "get_chunks_past_the_last",
            chunks(MAX_CHUNKS as u32 - 1, 2),
            Err(E::BadIndex),
            "ERROR MALFORMED",
        ),
        case(
            "get_chunks_first_max",
            chunks(u32::MAX, 1),
            Err(E::BadIndex),
            "ERROR MALFORMED",
        ),
        case(
            "get_chunks_cut",
            {
                let (mut f, _) = chunks(0, 1);
                f.pop();
                whole(f)
            },
            Err(E::Truncated),
            "ERROR MALFORMED",
        ),
        case(
            "get_chunks_trailing",
            {
                let (f, _) = chunks(0, 1);
                whole([f, vec![0]].concat())
            },
            Err(E::TrailingBytes),
            "ERROR MALFORMED",
        ),
        // ADVISORY.
        case(
            "advisory_small",
            whole(v1(OP_ADVISORY, &[0, 2, 0xAA, 0xBB, 0xCC])),
            ok,
            "DROP",
        ),
        case(
            "advisory_rad1_0",
            whole(v1(OP_ADVISORY, &[0, 0, 0xCC])),
            Err(E::BadRad1Len),
            "DROP",
        ),
        case(
            "advisory_rad1_32769",
            filled(
                &v1(OP_ADVISORY, &32_769u16.to_be_bytes()),
                32_770,
                0,
                &[],
                None,
            ),
            Err(E::BadRad1Len),
            "DROP",
        ),
        case(
            "advisory_rad1_65535",
            whole(v1(OP_ADVISORY, &[0xFF, 0xFF, 1])),
            Err(E::BadRad1Len),
            "DROP",
        ),
        case(
            "advisory_rad1_cut",
            whole(v1(OP_ADVISORY, &[0, 9, 0xAA])),
            Err(E::Truncated),
            "DROP",
        ),
        case(
            "advisory_len_cut",
            whole(v1(OP_ADVISORY, &[0])),
            Err(E::Truncated),
            "DROP",
        ),
        case(
            "advisory_no_snapshot",
            whole(v1(OP_ADVISORY, &[0, 1, 0xAA])),
            Err(E::BadSnapshotLen),
            "DROP",
        ),
        case(
            "advisory_snapshot_58024",
            filled(
                &v1(OP_ADVISORY, &[0, 1, 0xAA]),
                MAX_SNAPSHOT_LEN + 1,
                0,
                &[],
                None,
            ),
            Err(E::BadSnapshotLen),
            "DROP",
        ),
        case(
            "advisory_at_the_frame_limit",
            filled(
                &v1(OP_ADVISORY, &(MAX_RAD1_LEN as u16).to_be_bytes()),
                MAX_FRAME_LEN - HEADER_LEN - 2,
                0,
                &[],
                None,
            ),
            ok,
            "DROP",
        ),
        case(
            "advisory_over_the_frame_limit",
            filled(
                &v1(OP_ADVISORY, &(MAX_RAD1_LEN as u16).to_be_bytes()),
                MAX_FRAME_LEN - HEADER_LEN - 1,
                0,
                &[],
                None,
            ),
            Err(E::TooLong),
            "DROP",
        ),
        case(
            "advisory_always_fits",
            filled(
                &v1(OP_ADVISORY, &(ADVISORY_ALWAYS_FITS as u16).to_be_bytes()),
                ADVISORY_ALWAYS_FITS + MAX_SNAPSHOT_LEN,
                0,
                &[],
                None,
            ),
            ok,
            "DROP",
        ),
        // LOG.
        case("log_one_byte", whole(v1(OP_LOG, &[0x52])), ok, "DROP"),
        case(
            "log_empty",
            whole(head(OP_LOG)),
            Err(E::BadSnapshotLen),
            "DROP",
        ),
        case(
            "log_58023",
            filled(&head(OP_LOG), MAX_SNAPSHOT_LEN, 0, &[], None),
            ok,
            "DROP",
        ),
        case(
            "log_58024",
            filled(&head(OP_LOG), MAX_SNAPSHOT_LEN + 1, 0, &[], None),
            Err(E::BadSnapshotLen),
            "DROP",
        ),
        // MANIFEST.
        case(
            "manifest_small",
            whole(v1(OP_MANIFEST, &[0, 1, 0xAA, 0xBB])),
            ok,
            "DROP",
        ),
        case(
            "manifest_len_0",
            whole(v1(OP_MANIFEST, &[0, 0, 0xBB])),
            Err(E::BadManifestLen),
            "DROP",
        ),
        case(
            "manifest_len_5199",
            filled(
                &v1(OP_MANIFEST, &5_199u16.to_be_bytes()),
                5_200,
                0,
                &[],
                None,
            ),
            Err(E::BadManifestLen),
            "DROP",
        ),
        case(
            "manifest_cut",
            whole(v1(OP_MANIFEST, &[0, 5, 0xAA])),
            Err(E::Truncated),
            "DROP",
        ),
        case(
            "manifest_no_snapshot",
            whole(v1(OP_MANIFEST, &[0, 1, 0xAA])),
            Err(E::BadSnapshotLen),
            "DROP",
        ),
        case(
            "manifest_longest",
            filled(
                &v1(OP_MANIFEST, &(MAX_MANIFEST_LEN as u16).to_be_bytes()),
                MAX_MANIFEST_LEN + MAX_SNAPSHOT_LEN,
                0,
                &[],
                None,
            ),
            ok,
            "DROP",
        ),
        case(
            "manifest_snapshot_58024",
            filled(
                &v1(OP_MANIFEST, &[0, 1, 0xAA]),
                MAX_SNAPSHOT_LEN + 1,
                0,
                &[],
                None,
            ),
            Err(E::BadSnapshotLen),
            "DROP",
        ),
        // CHUNKS_END.
        case("chunks_end_ok_8", end(0, 8), ok, "DROP"),
        case("chunks_end_unknown_code", end(200, 0), ok, "DROP"),
        case("chunks_end_sent_9", end(0, 9), Err(E::BadCount), "DROP"),
        case(
            "chunks_end_cut",
            whole(v1(OP_CHUNKS_END, &[0])),
            Err(E::Truncated),
            "DROP",
        ),
        case(
            "chunks_end_trailing",
            whole(v1(OP_CHUNKS_END, &[0, 1, 0])),
            Err(E::TrailingBytes),
            "DROP",
        ),
        // ERROR.
        case("error_255", whole(v1(OP_ERROR, &[255])), ok, "DROP"),
        case(
            "error_code_0",
            whole(v1(OP_ERROR, &[0])),
            Err(E::BadCode),
            "DROP",
        ),
        case(
            "error_cut",
            whole(head(OP_ERROR)),
            Err(E::Truncated),
            "DROP",
        ),
        case(
            "error_trailing",
            whole(v1(OP_ERROR, &[2, 0])),
            Err(E::TrailingBytes),
            "DROP",
        ),
    ];
    // CHUNK (the oversize rules are `rup1_oversize_chunk_001`'s).
    let c = |index: u32, bytes: &[u8], path: &[[u8; 32]]| {
        let mut b = index.to_be_bytes().to_vec();
        b.extend((bytes.len() as u32).to_be_bytes());
        b.extend_from_slice(bytes);
        b.push(path.len() as u8);
        path.iter().for_each(|h| b.extend(h));
        v1(OP_CHUNK, &b)
    };
    v.push(case(
        "chunk_small",
        whole(c(1, &[1, 2, 3], &[[0x77; 32]])),
        ok,
        "DROP",
    ));
    v.push(case("chunk_no_path", whole(c(0, &[1], &[])), ok, "DROP"));
    v.push(case(
        "chunk_cut_in_index",
        whole(v1(OP_CHUNK, &[0, 0])),
        Err(E::Truncated),
        "DROP",
    ));
    v.push(case(
        "chunk_trailing",
        whole([c(0, &[1], &[]), vec![0]].concat()),
        Err(E::TrailingBytes),
        "DROP",
    ));
    v
}

#[test]
fn decode_rules() {
    let cases = decode_cases();
    let mut names = std::collections::HashSet::new();
    for c in &cases {
        assert!(names.insert(c.name.clone()), "duplicate case {}", c.name);
        assert_eq!(decode(&c.frame).map(|_| ()), c.result, "{}", c.name);
        assert_eq!(listener(&c.frame), c.listener, "{}", c.name);
        if let Ok((req_id, msg)) = decode(&c.frame) {
            // Accepted frames are canonical: they re-encode byte for byte.
            assert_eq!(frame(&req_id, &msg), c.frame, "{}", c.name);
        }
    }
    // Every error code is reached by some case here or in the oversize file.
    let mut reached: std::collections::HashSet<&str> = cases
        .iter()
        .filter_map(|c| c.result.err().map(Rup1Error::code))
        .collect();
    reached.extend(
        oversize_cases()
            .iter()
            .filter_map(|c| c.result.err().map(Rup1Error::code)),
    );
    let mut all = vec![
        "NOT_RUP1",
        "TRUNCATED",
        "TOO_LONG",
        "BAD_VERSION",
        "UNKNOWN_OP",
        "TRAILING_BYTES",
        "NONZERO_REQ_ID",
        "BAD_ADVISORY_REF",
        "BAD_LOG_REF",
        "TOO_MANY_OFFERS",
        "BAD_SERIAL",
        "BAD_TARGET",
        "BAD_PAYLOAD_LEN",
        "DUPLICATE_OFFER",
        "BAD_RAD1_LEN",
        "BAD_MANIFEST_LEN",
        "BAD_SNAPSHOT_LEN",
        "BAD_COUNT",
        "BAD_INDEX",
        "BAD_CHUNK_LEN",
        "BAD_PATH_LEN",
        "BAD_CODE",
    ];
    let mut reached: Vec<&str> = reached.into_iter().collect();
    reached.sort_unstable();
    all.sort_unstable();
    assert_eq!(reached, all);
}

/// The CHUNK refusals: every cap is checked before anything is read, and
/// a listener drops every CHUNK (it never answers a reply).
#[test]
fn oversize_chunk_rules() {
    let (_, chunks) = max_chunks();
    for c in oversize_cases() {
        assert_eq!(decode(&c.frame).map(|_| ()), c.result, "{}", c.name);
        assert_eq!(listener(&c.frame), c.listener, "{}", c.name);
    }
    let max = &oversize_cases()[0];
    assert_eq!(max.name, "chunk_max");
    assert_eq!(max.frame, frame(&REQ, &Rup1Msg::Chunk(chunks[0].clone())));
    assert_eq!(max.frame.len(), MAX_CHUNK_FRAME_LEN);
}

/// Encoding refuses exactly what decoding refuses, with the same code, so
/// a node cannot send a frame its friends would refuse.
#[test]
fn encode_refuses_what_decode_refuses() {
    use Rup1Error as E;
    let have = |f: &dyn Fn(&mut Have)| {
        let mut h = four_offers();
        f(&mut h);
        Rup1Msg::Have(h)
    };
    let chunk = |index: u32, len: usize, path: usize| {
        Rup1Msg::Chunk(Chunk {
            index,
            bytes: vec![7; len],
            path: vec![[1; 32]; path],
        })
    };
    let get_chunks = |first, count| Rup1Msg::GetChunks {
        manifest_digest: [0; 32],
        first,
        count,
    };
    let cases: Vec<(Rup1Msg, [u8; 4], Rup1Error)> = vec![
        (Rup1Msg::Have(Have::nothing()), REQ, E::NonzeroReqId),
        (
            have(&|h| h.adv_digest = [0; 32]),
            NO_REQ_ID,
            E::BadAdvisoryRef,
        ),
        (have(&|h| h.adv_serial = 0), NO_REQ_ID, E::BadAdvisoryRef),
        (have(&|h| h.log_size = 1_401), NO_REQ_ID, E::BadLogRef),
        (have(&|h| h.log_root = [0; 32]), NO_REQ_ID, E::BadLogRef),
        (have(&|h| h.log_size = 0), NO_REQ_ID, E::BadLogRef),
        (
            have(&|h| h.offers.push(offer(1, "a-b", 0xC1, 1))),
            NO_REQ_ID,
            E::TooManyOffers,
        ),
        (
            have(&|h| h.offers[2].build_serial = 0),
            NO_REQ_ID,
            E::BadSerial,
        ),
        (
            have(&|h| h.offers[0].target.clear()),
            NO_REQ_ID,
            E::BadTarget,
        ),
        (
            have(&|h| h.offers[0].target = format!("{}-x", longest_target('a'))),
            NO_REQ_ID,
            E::BadTarget,
        ),
        (
            have(&|h| h.offers[1].target = "X86_64-apple-darwin".into()),
            NO_REQ_ID,
            E::BadTarget,
        ),
        (
            have(&|h| h.offers[3].payload_len = 0),
            NO_REQ_ID,
            E::BadPayloadLen,
        ),
        (
            have(&|h| h.offers[3].payload_len = MAX_PAYLOAD_LEN + 1),
            NO_REQ_ID,
            E::BadPayloadLen,
        ),
        (
            have(&|h| h.offers[3].manifest_digest = [0xA1; 32]),
            NO_REQ_ID,
            E::DuplicateOffer,
        ),
        (get_chunks(0, 0), REQ, E::BadCount),
        (get_chunks(0, 9), REQ, E::BadCount),
        (get_chunks(1_092, 2), REQ, E::BadIndex),
        (
            Rup1Msg::Advisory {
                rad1: vec![],
                snapshot: vec![1],
            },
            REQ,
            E::BadRad1Len,
        ),
        (
            Rup1Msg::Advisory {
                rad1: vec![1; MAX_RAD1_LEN + 1],
                snapshot: vec![1],
            },
            REQ,
            E::BadRad1Len,
        ),
        (
            Rup1Msg::Advisory {
                rad1: vec![1],
                snapshot: vec![],
            },
            REQ,
            E::BadSnapshotLen,
        ),
        (
            Rup1Msg::Advisory {
                rad1: vec![1; MAX_RAD1_LEN],
                snapshot: vec![1; MAX_SNAPSHOT_LEN],
            },
            REQ,
            E::TooLong,
        ),
        (
            Rup1Msg::Log {
                snapshot: vec![1; MAX_SNAPSHOT_LEN + 1],
            },
            REQ,
            E::BadSnapshotLen,
        ),
        (
            Rup1Msg::Manifest {
                manifest: vec![],
                snapshot: vec![1],
            },
            REQ,
            E::BadManifestLen,
        ),
        (
            Rup1Msg::Manifest {
                manifest: vec![1; MAX_MANIFEST_LEN + 1],
                snapshot: vec![1],
            },
            REQ,
            E::BadManifestLen,
        ),
        (
            Rup1Msg::Manifest {
                manifest: vec![1],
                snapshot: vec![],
            },
            REQ,
            E::BadSnapshotLen,
        ),
        (chunk(MAX_CHUNKS as u32, 1, 0), REQ, E::BadIndex),
        (chunk(0, 0, 0), REQ, E::BadChunkLen),
        (chunk(0, CHUNK_SIZE as usize + 1, 0), REQ, E::BadChunkLen),
        (chunk(0, 1, MAX_CHUNK_PATH_LEN + 1), REQ, E::BadPathLen),
        (
            Rup1Msg::ChunksEnd {
                stopped: None,
                sent: 9,
            },
            REQ,
            E::BadCount,
        ),
        (Rup1Msg::Error(ErrorCode::Other(0)), REQ, E::BadCode),
    ];
    for (msg, req_id, err) in cases {
        assert_eq!(encode(&req_id, &msg), Err(err), "{msg:?}");
    }
}

/// The largest frames of every op fit one PAD1 inner frame: a CHUNK at
/// the maximum size (a full chunk and an 11-hash path) is 61,811 bytes,
/// and pads into the 65,519-byte bucket.
#[test]
fn the_largest_frames_fit_pad1() {
    let (tree, chunks) = max_chunks();
    let biggest = frame(&REQ_CHUNKS, &Rup1Msg::Chunk(chunks[0].clone()));
    assert_eq!(chunks[0].path.len(), MAX_CHUNK_PATH_LEN);
    assert_eq!(biggest.len(), MAX_CHUNK_FRAME_LEN);
    assert!(biggest.len() <= PAD1_MAX_INNER);
    let padded = wrap(&biggest).unwrap();
    assert_eq!(padded.len(), PAD1_BUCKETS[3]);
    assert_eq!(
        decode(&biggest),
        Ok((REQ_CHUNKS, Rup1Msg::Chunk(chunks[0].clone())))
    );
    // Both checks against the 64 MiB tree's root (rrb1_chunk_tree_001).
    for c in &chunks {
        assert!(verify_chunk_path(
            &tree.root(),
            MAX_CHUNKS,
            u64::from(c.index),
            &leaf_hash(&c.bytes),
            &c.path
        ));
    }
    let longest_manifest = encode(
        &REQ,
        &Rup1Msg::Manifest {
            manifest: vec![1; MAX_MANIFEST_LEN],
            snapshot: vec![2; MAX_SNAPSHOT_LEN],
        },
    )
    .unwrap();
    assert_eq!(longest_manifest.len(), MAX_MANIFEST_FRAME_LEN);
    let longest_log = encode(
        &REQ,
        &Rup1Msg::Log {
            snapshot: vec![2; MAX_SNAPSHOT_LEN],
        },
    )
    .unwrap();
    assert_eq!(longest_log.len(), MAX_LOG_FRAME_LEN);
    let fits = encode(
        &REQ,
        &Rup1Msg::Advisory {
            rad1: vec![1; ADVISORY_ALWAYS_FITS],
            snapshot: vec![2; MAX_SNAPSHOT_LEN],
        },
    )
    .unwrap();
    assert_eq!(fits.len(), MAX_FRAME_LEN);
    for f in [&longest_manifest, &longest_log, &fits] {
        assert!(wrap(f).is_ok());
    }
    assert_eq!(
        encode(
            &REQ,
            &Rup1Msg::Advisory {
                rad1: vec![1; ADVISORY_ALWAYS_FITS + 1],
                snapshot: vec![2; MAX_SNAPSHOT_LEN],
            }
        ),
        Err(Rup1Error::TooLong)
    );
    assert_eq!(
        frame(&NO_REQ_ID, &Rup1Msg::Have(longest_have())).len(),
        MAX_HAVE_LEN
    );
}

#[test]
fn which_reply_answers_which_request() {
    let p = test_release();
    let cases = frame_cases(&p);
    let requests: Vec<&Rup1Msg> = cases
        .iter()
        .map(|c| &c.2)
        .filter(|m| m.role() == Role::Request)
        .collect();
    assert_eq!(requests.len(), 5);
    for request in &requests {
        for (name, _, reply) in &cases {
            let expected = matches!(
                (request, reply),
                (_, Rup1Msg::Error(_))
                    | (Rup1Msg::GetAdvisory, Rup1Msg::Advisory { .. })
                    | (Rup1Msg::GetRotation { .. }, Rup1Msg::Advisory { .. })
                    | (Rup1Msg::GetLog, Rup1Msg::Log { .. })
                    | (Rup1Msg::GetManifest { .. }, Rup1Msg::Manifest { .. })
                    | (Rup1Msg::GetChunks { .. }, Rup1Msg::Chunk(_))
                    | (Rup1Msg::GetChunks { .. }, Rup1Msg::ChunksEnd { .. })
            );
            assert_eq!(request.answered_by(reply), expected, "{request:?} {name}");
        }
    }
    // Nothing answers a HAVE or a reply.
    for (_, _, msg) in &cases {
        if msg.role() != Role::Request {
            assert!(cases.iter().all(|(_, _, r)| !msg.answered_by(r)));
        }
    }
    // A CHUNK must be one asked for; CHUNKS_END never counts more.
    let ask = Rup1Msg::GetChunks {
        manifest_digest: [0; 32],
        first: 4,
        count: 3,
    };
    let at = |index| {
        Rup1Msg::Chunk(Chunk {
            index,
            bytes: vec![1],
            path: vec![],
        })
    };
    let ends = |sent| Rup1Msg::ChunksEnd {
        stopped: None,
        sent,
    };
    assert!(!ask.answered_by(&at(3)));
    assert!(ask.answered_by(&at(4)) && ask.answered_by(&at(6)));
    assert!(!ask.answered_by(&at(7)));
    assert!(ask.answered_by(&ends(0)) && ask.answered_by(&ends(3)));
    assert!(!ask.answered_by(&ends(4)));
}

/// Chunks served from a payload check against its manifest; a changed
/// byte, another chunk's path, a short path or another index do not.
#[test]
fn chunks_check_against_their_manifest() {
    let (payload, tree) = small();
    let files = [PackFile {
        path: "bin/raven",
        mode: FileMode::Executable,
        bytes: &payload,
        rebuild_sha256: [0x42; 32],
    }];
    let mut draft = ManifestDraft {
        build_serial: 5,
        created_at_ms: 1_792_713_600_000,
        key_set_digest: key_set().digest(),
        version: "1.5.0".into(),
        target: "aarch64-apple-darwin".into(),
        source_commit: [0x5C; 20],
        toolchain: "1.98.0".into(),
        min_advisory_serial: 1,
        chunk_size: 0,
        payload_len: 0,
        payload_chunk_root: [0; 32],
        payload_sha256: [0; 32],
        files: Vec::new(),
        notes: String::new(),
    };
    assert_eq!(draft.fill_payload(&files), payload);
    let (a, b) = (signer(0x11), signer(0x22));
    let manifest = draft.sign(&[(0, &a), (1, &b)]).unwrap();
    assert_eq!(manifest.payload_chunk_root, tree.root());
    assert_eq!(chunk_count(payload.len() as u64, CHUNK_SIZE), 5);
    let chunks: Vec<Chunk> = (0..5)
        .map(|i| Chunk::of_payload(&payload, &tree, i).unwrap())
        .collect();
    assert_eq!(Chunk::of_payload(&payload, &tree, 5), None);
    assert_eq!(Chunk::of_payload(&payload, &tree, u32::MAX), None);
    let leaves = chunk_leaf_hashes(&payload, CHUNK_SIZE);
    for (i, c) in chunks.iter().enumerate() {
        assert!(c.check(&manifest), "chunk {i}");
        assert_eq!(leaf_hash(&c.bytes), leaves[i]);
        assert_eq!(c.path.len(), if i == 4 { 1 } else { 3 });
        // Over the wire and back.
        let f = frame(&REQ_CHUNKS, &Rup1Msg::Chunk(c.clone()));
        assert_eq!(decode(&f), Ok((REQ_CHUNKS, Rup1Msg::Chunk(c.clone()))));
    }
    assert_eq!(chunks[4].bytes.len(), 1_000);
    let mut forged = chunks[1].clone();
    forged.bytes[100] ^= 1;
    assert!(!forged.check(&manifest));
    let mut wrong_path = chunks[0].clone();
    wrong_path.path = chunks[1].path.clone();
    assert!(!wrong_path.check(&manifest));
    let mut short_path = chunks[0].clone();
    short_path.path.pop();
    assert!(!short_path.check(&manifest));
    let mut long_path = chunks[4].clone();
    long_path.path.push([0; 32]);
    assert!(!long_path.check(&manifest));
    let mut moved = chunks[1].clone();
    moved.index = 2;
    assert!(!moved.check(&manifest));
    let mut past = chunks[4].clone();
    past.index = 5;
    assert!(!past.check(&manifest));
    // The short last chunk named as a full one fails on its length.
    let mut short_at_full = chunks[4].clone();
    short_at_full.index = 3;
    short_at_full.path = chunks[3].path.clone();
    assert!(!short_at_full.check(&manifest));
    // RFC 6962 by hand: chunk 4's path is the root of chunks 0..4.
    let left = node_hash(
        &node_hash(&leaves[0], &leaves[1]),
        &node_hash(&leaves[2], &leaves[3]),
    );
    assert_eq!(chunks[4].path, vec![left]);
    assert_eq!(node_hash(&left, &leaves[4]), tree.root());
}

/// A listener answers requests, takes HAVEs, refuses unknown and malformed
/// requests with an ERROR echoing the request id, and never answers a
/// reply, so two nodes cannot answer each other forever.
#[test]
fn listener_decisions() {
    let p = test_release();
    for (name, req_id, msg) in frame_cases(&p) {
        let f = frame(&req_id, &msg);
        let expected = match msg.role() {
            Role::OneWay => "HAVE",
            Role::Request => "REQUEST",
            Role::Reply { .. } => "DROP",
        };
        assert_eq!(listener(&f), expected, "{name}");
    }
    let id = [9, 8, 7, 6];
    assert_eq!(
        decode_for_listener(&raw(RUP1_VERSION, 0x33, id, &[])),
        ListenerDecode::Refuse(id, ErrorCode::Unsupported)
    );
    assert_eq!(
        decode_for_listener(&raw(RUP1_VERSION, OP_GET_MANIFEST, id, &[1])),
        ListenerDecode::Refuse(id, ErrorCode::Malformed)
    );
    assert_eq!(
        decode_for_listener(&raw(7, OP_GET_MANIFEST, id, &[1])),
        ListenerDecode::Refuse(id, ErrorCode::Unsupported)
    );
    assert_eq!(
        decode_for_listener(&raw(RUP1_VERSION, OP_GET_LOG, id, &[])),
        ListenerDecode::Request(id, Rup1Msg::GetLog)
    );
    assert_eq!(
        decode_for_listener(b"RUP1\x01\x03\x00"),
        ListenerDecode::Drop
    );
    assert_eq!(
        decode_for_listener(b"RFC1\x01\x01\0\0\0\0"),
        ListenerDecode::Drop
    );
    // An ERROR the listener sends back is itself never answered.
    let refusal = frame(&id, &Rup1Msg::Error(ErrorCode::Malformed));
    assert_eq!(decode_for_listener(&refusal), ListenerDecode::Drop);
}

/// Every strict prefix of a fixed-layout frame is refused, and so is every
/// frame with a byte appended (a snapshot or a CHUNK's tail aside, whose
/// length the frame gives).
#[test]
fn cut_and_padded_frames_are_refused() {
    let p = test_release();
    for (name, req_id, msg) in frame_cases(&p) {
        let f = frame(&req_id, &msg);
        let open_ended = matches!(
            msg,
            Rup1Msg::Advisory { .. } | Rup1Msg::Log { .. } | Rup1Msg::Manifest { .. }
        );
        if !open_ended {
            for cut in 0..f.len() {
                assert!(decode(&f[..cut]).is_err(), "{name} cut at {cut}");
            }
            let mut longer = f.clone();
            longer.push(0);
            assert_eq!(decode(&longer), Err(Rup1Error::TrailingBytes), "{name}");
        }
    }
}

/// Runs in both builds: the release test job sets Lab Test A and the
/// advisory, release bundle and mesh update switches, and a release build
/// still keeps the exchange shut; a debug build opens it only with all
/// three gates (this thread's overrides).
#[test]
fn the_exchange_is_inert_without_debug_assertions() {
    use crate::security_gate::{self, SecGate, MESH_UPDATE_PRODUCTION_ENABLED};
    const { assert!(!MESH_UPDATE_PRODUCTION_ENABLED) };
    if !cfg!(debug_assertions) {
        // Edition 2021: plain calls. No other release test reads these.
        std::env::set_var("RAVEN_LAB_TEST_A", "1");
        std::env::set_var(security_gate::LAB_ADVISORY, "1");
        std::env::set_var(security_gate::LAB_RELEASE_BUNDLE, "1");
        std::env::set_var(security_gate::LAB_MESH_UPDATE, "1");
        assert!(!live());
        return;
    }
    let gates = [
        SecGate::MeshUpdate,
        SecGate::ReleaseBundle,
        SecGate::Advisory,
    ];
    for g in gates {
        security_gate::set_lab_for_this_thread(g, Some(true));
    }
    assert!(live());
    security_gate::set_lab_for_this_thread(SecGate::ReleaseBundle, Some(false));
    assert!(!live(), "the release bundle gate shut");
    security_gate::set_lab_for_this_thread(SecGate::ReleaseBundle, Some(true));
    security_gate::set_lab_for_this_thread(SecGate::MeshUpdate, Some(false));
    assert!(!live(), "its own switch off");
    for g in gates {
        security_gate::set_lab_for_this_thread(g, None);
    }
}

// ── Vectors (spec §10) ──────────────────────────────────────────────

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

/// Assert that the committed vector `file` (under shared-vectors/rvn1/update)
/// equals `expected`; write it first under `RAVEN_REGEN_SECURITY_VECTORS=1`.
fn assert_vector(file: &str, expected: &Value) {
    let path = rvn1_dir().join("update").join(file);
    if std::env::var(REGEN).as_deref() == Ok("1") {
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

const LAYOUT: &str = "header = \"RUP1\" | version 0x01 | op u8 | req_id[4]; 0x01 HAVE \
     (one-way, req_id zero) adv_serial u64 | adv_digest[32] | log_size u32 | log_root[32] | \
     n u8 (0..=4) | offers (build_serial u64 | target_len u8 | target | manifest_digest[32] | \
     payload_len u64); 0x02 GET_ADVISORY, 0x03 GET_LOG (empty); 0x04 GET_MANIFEST \
     manifest_digest[32]; 0x05 GET_CHUNKS manifest_digest[32] | first u32 | count u8 (1..=8); \
     0x06 GET_ROTATION key_set_digest[32] (answered ADVISORY); 0x82 ADVISORY rad1_len u16 | \
     RAD1 | RTL1 snapshot; 0x83 LOG snapshot; 0x84 MANIFEST manifest_len u16 | RRB1 | \
     snapshot; 0x85 CHUNK (non-terminal) index u32 | len u32 | \
     bytes | path_len u8 (0..=11) | path[32] x path_len; 0x86 CHUNKS_END code u8 (0 OK) | \
     sent u8 (0..=8); 0xFF ERROR code u8 (1 UNSUPPORTED, 2 NOT_FOUND, 3 BUSY, 4 RATE_LIMITED, \
     5 POLICY_DENIED, 6 MALFORMED, others kept as unknown); every frame at most 65,511 bytes \
     (RAVEN_UPDATE_EXCHANGE_V1 §3)";

fn frame_entry(name: &str, req_id: &[u8; 4], msg: &Rup1Msg) -> Value {
    let f = frame(req_id, msg);
    json!({
        "name": name,
        "op": msg.op(),
        "op_name": op_name(msg.op()),
        "req_id_hex": hex::encode(req_id),
        "fields": msg_json(msg),
        "frame_hex": hex::encode(&f),
        "frame_len": f.len(),
        "role": role_name(msg),
        "expects_reply": frame_expects_reply(&f),
        "terminal_reply": frame_is_terminal_reply(&f),
        "listener": listener(&f),
    })
}

/// A CHUNK frame for the vectors: its head (header, index, length), the
/// chunk as a pattern fill and its tail (path length and path).
fn chunk_entry(c: &Chunk, start: usize) -> Value {
    let f = frame(&REQ_CHUNKS, &Rup1Msg::Chunk(c.clone()));
    let tail_at = HEADER_LEN + 8 + c.bytes.len();
    let (built, spec) = filled(
        &f[..HEADER_LEN + 8],
        c.bytes.len(),
        start,
        &f[tail_at..],
        None,
    );
    assert_eq!(built, f);
    json!({
        "index": c.index,
        "len": c.bytes.len(),
        "leaf_hex": hex::encode(leaf_hash(&c.bytes)),
        "path_hex": c.path.iter().map(hex::encode).collect::<Vec<_>>(),
        "frame": spec["frame"],
        "pad1_len": wrap(&f).unwrap().len(),
    })
}

/// The CHUNK refusals: lengths, indexes and paths over their caps, a frame
/// over the frame limit, and chunks that decode but fail their check.
fn oversize_cases() -> Vec<Case> {
    use Rup1Error as E;
    let size = CHUNK_SIZE as usize;
    let head = |index: u32, len: u32| {
        [
            &v1(OP_CHUNK, &[])[..],
            &index.to_be_bytes(),
            &len.to_be_bytes(),
        ]
        .concat()
    };
    let tail = |n: usize, byte: u8| [vec![n as u8], vec![byte; 32 * n]].concat();
    let path_tail = |path: &[[u8; 32]], n: u8| {
        let mut t = vec![n];
        path.iter().for_each(|h| t.extend(h));
        t
    };
    let (_, chunks) = max_chunks();
    let max_tail = path_tail(&chunks[0].path, 11);
    let over_tail = [
        tail(11, 0x77),
        vec![0; MAX_FRAME_LEN + 1 - MAX_CHUNK_FRAME_LEN],
    ]
    .concat();
    vec![
        case(
            "chunk_max",
            filled(&head(0, CHUNK_SIZE), size, 0, &max_tail, None),
            Ok(()),
            "DROP",
        ),
        case(
            "chunk_61441",
            filled(&head(0, CHUNK_SIZE + 1), size + 1, 0, &max_tail, None),
            Err(E::BadChunkLen),
            "DROP",
        ),
        case(
            "chunk_len_u32_max",
            filled(&head(0, u32::MAX), 16, 0, &[], None),
            Err(E::BadChunkLen),
            "DROP",
        ),
        case(
            "chunk_len_0",
            whole([head(0, 0), vec![0]].concat()),
            Err(E::BadChunkLen),
            "DROP",
        ),
        case(
            "chunk_path_12",
            filled(&head(0, CHUNK_SIZE), size, 0, &tail(12, 0x77), None),
            Err(E::BadPathLen),
            "DROP",
        ),
        case(
            "chunk_path_255",
            filled(&head(0, CHUNK_SIZE), size, 0, &[255], None),
            Err(E::BadPathLen),
            "DROP",
        ),
        case(
            "chunk_index_1093",
            filled(&head(MAX_CHUNKS as u32, CHUNK_SIZE), size, 0, &[0], None),
            Err(E::BadIndex),
            "DROP",
        ),
        case(
            "chunk_index_u32_max",
            whole([head(u32::MAX, 1), vec![1, 0]].concat()),
            Err(E::BadIndex),
            "DROP",
        ),
        case(
            "chunk_bytes_cut",
            filled(&head(0, CHUNK_SIZE), 100, 0, &[], None),
            Err(E::Truncated),
            "DROP",
        ),
        case(
            "chunk_path_cut",
            filled(
                &head(0, CHUNK_SIZE),
                size,
                0,
                &max_tail[..max_tail.len() - 1],
                None,
            ),
            Err(E::Truncated),
            "DROP",
        ),
        case(
            "chunk_trailing",
            filled(
                &head(0, CHUNK_SIZE),
                size,
                0,
                &[&max_tail[..], &[0]].concat(),
                None,
            ),
            Err(E::TrailingBytes),
            "DROP",
        ),
        case(
            "chunk_frame_65512",
            filled(&head(0, CHUNK_SIZE), size, 0, &over_tail, None),
            Err(E::TooLong),
            "DROP",
        ),
    ]
}

/// Chunks that decode but fail their check against the small payload's
/// root: each is `(name, chunk, start of its bytes in the payload, flip)`.
fn forged_chunks() -> Vec<(&'static str, Chunk, usize, Option<usize>)> {
    let (payload, tree) = small();
    let size = CHUNK_SIZE as usize;
    let at = |i: u32| Chunk::of_payload(&payload, &tree, i).unwrap();
    let with = |mut c: Chunk, f: &dyn Fn(&mut Chunk)| {
        f(&mut c);
        c
    };
    vec![
        ("byte_flipped", at(1), size, Some(HEADER_LEN + 8 + 100)),
        (
            "another_chunks_path",
            with(at(0), &|c| c.path = at(1).path),
            0,
            None,
        ),
        (
            "path_short",
            with(at(0), &|c| {
                c.path.pop();
            }),
            0,
            None,
        ),
        (
            "path_long",
            with(at(4), &|c| c.path.push([0; 32])),
            4 * size,
            None,
        ),
        ("moved_index", with(at(1), &|c| c.index = 2), size, None),
        (
            "past_the_last",
            with(at(4), &|c| c.index = 5),
            4 * size,
            None,
        ),
        (
            "short_chunk_at_a_full_index",
            with(at(4), &|c| {
                c.index = 3;
                c.path = at(3).path;
            }),
            4 * size,
            None,
        ),
    ]
}

/// The check a fetcher makes before writing a chunk (the manifest's
/// `check_chunk`): its length is the chunk's, and its path leads to the
/// root.
fn chunk_checks(root: &[u8; 32], payload_len: usize, c: &Chunk) -> bool {
    let size = CHUNK_SIZE as usize;
    let start = c.index as usize * size;
    let expected = (start < payload_len).then(|| (payload_len - start).min(size));
    expected == Some(c.bytes.len())
        && verify_chunk_path(
            root,
            chunk_count(payload_len as u64, CHUNK_SIZE),
            u64::from(c.index),
            &leaf_hash(&c.bytes),
            &c.path,
        )
}

fn case_json(c: &Case) -> Value {
    let mut out = json!({
        "name": c.name,
        "result": c.result.err().map_or("OK", Rup1Error::code),
        "listener": c.listener,
    });
    for (k, v) in c.spec.as_object().unwrap() {
        out[k] = v.clone();
    }
    out
}

#[test]
fn update_vectors_rup1() {
    let p = test_release();

    // Every op, the classifiers, the listener and the link caps.
    let cases = frame_cases(&p);
    let frames: Vec<Value> = cases
        .iter()
        .map(|(name, req_id, msg)| frame_entry(name, req_id, msg))
        .collect();
    let answers: Vec<Value> = cases
        .iter()
        .filter(|c| c.2.role() == Role::Request)
        .map(|(name, _, request)| {
            json!({
                "request": name,
                "answered_by": cases
                    .iter()
                    .filter(|(_, _, reply)| request.answered_by(reply))
                    .map(|(n, ..)| n.clone())
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    let classify: Vec<Value> = [
        b"RUP1".to_vec(),
        b"RUP1\x01\x02\x00\x00\x00".to_vec(),
        raw(2, OP_GET_LOG, REQ, &[]),
        raw(2, OP_ERROR, REQ, &[1]),
        raw(RUP1_VERSION, 0x07, REQ, &[]),
        raw(RUP1_VERSION, 0x87, REQ, &[]),
        b"RFC1\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
    ]
    .iter()
    .map(|f| {
        json!({
            "frame_hex": hex::encode(f),
            "expects_reply": frame_expects_reply(f),
            "terminal_reply": frame_is_terminal_reply(f),
            "listener": listener(f),
        })
    })
    .collect();
    let all_links = LinkFeatures::RRH1
        .with(LinkFeatures::PAD1, true)
        .with(LinkFeatures::RUP1, true);
    let rlx1 = rlx1_payload(all_links.bits());
    assert_eq!(rlx1_caps(&rlx1), 0x0000_0700);
    assert_vector(
        "rup1_frames_001.json",
        &vector(
            "rup1_frames_001",
            &format!(
                "{LAYOUT}. One frame of every op carrying the test release of \
                 rrbc_small_001.json (its advisory, log snapshot, manifest and one-chunk \
                 payload), CHUNKS_END with and without a code, ERROR with each code and an \
                 unknown one; for each its role, what raven-node's dial classifier says \
                 (expects_reply: a request; terminal_reply: ends a request) and what a \
                 listener does (REQUEST, HAVE, ERROR <code>, DROP: it never answers a reply \
                 or a HAVE). answers: the replies that can answer each request. link_caps: \
                 caps bit 10 = RUP1 in the RIH1 hello and in RLX1 LINK_CAPS"
            ),
            json!({ "source": "rrbc_small_001.json" }),
            json!({
                "frames": frames,
                "answers": answers,
                "classify": classify,
                "link_caps": {
                    "cap_link_rup1": CAP_LINK_RUP1,
                    "hello_caps_rup1": hello_caps(LinkFeatures::RUP1),
                    "hello_caps_rrh1_pad1_rup1": hello_caps(all_links),
                    "rlx1_payload_rrh1_pad1_rup1_hex": hex::encode(&rlx1),
                },
            }),
        ),
    );

    // HAVE: nothing, the test release, four offers and the longest.
    let haves: Vec<Value> = [
        ("nothing", Have::nothing()),
        ("test_release", release_have(&p)),
        ("four_offers", four_offers()),
        ("longest", longest_have()),
    ]
    .iter()
    .map(|(name, have)| frame_entry(name, &NO_REQ_ID, &Rup1Msg::Have(have.clone())))
    .collect();
    assert_vector(
        "rup1_have_001.json",
        &vector(
            "rup1_have_001",
            "HAVE = \"RUP1\" | 0x01 | op 0x01 | req_id 00000000 | adv_serial u64 | \
             adv_digest[32] | log_size u32 | log_root[32] | n u8 (0..=4) | offers \
             (build_serial u64 >= 1 | target_len u8 (1..=64) | target | manifest_digest[32] | \
             payload_len u64 (1..=67,108,864)); adv_serial 0 exactly when adv_digest is zero, \
             log_size (0..=1,400) 0 exactly when log_root is zero, each manifest digest once \
             (RAVEN_UPDATE_EXCHANGE_V1 §3.1). nothing: a node that holds nothing; \
             test_release: the advisory (serial and advisory_digest), log (tree_size and \
             root_hash) and bundle (build_serial, target, manifest_digest, payload_len) of \
             rrbc_small_001.json; four_offers: four targets; longest: four 64-byte targets \
             (539 bytes, the longest HAVE)",
            json!({ "source": "rrbc_small_001.json" }),
            json!({ "haves": haves, "max_have_len": MAX_HAVE_LEN }),
        ),
    );

    // CHUNK frames of the small and the 64 MiB payloads.
    let (payload, tree) = small();
    let size = CHUNK_SIZE as usize;
    let small_chunks: Vec<Value> = (0..5u32)
        .map(|i| {
            let c = Chunk::of_payload(&payload, &tree, i).unwrap();
            assert!(chunk_checks(&tree.root(), payload.len(), &c));
            chunk_entry(&c, i as usize * size)
        })
        .collect();
    let last = Chunk::of_payload(&payload, &tree, 4).unwrap();
    let digest = [0x5A; 32];
    let request = Rup1Msg::GetChunks {
        manifest_digest: digest,
        first: 0,
        count: 5,
    };
    let (max_tree, max) = max_chunks();
    let max_entries: Vec<Value> = max
        .iter()
        .map(|c| {
            assert!(chunk_checks(&max_tree.root(), MAX_PAYLOAD_LEN as usize, c));
            chunk_entry(c, c.index as usize * size)
        })
        .collect();
    assert_vector(
        "rup1_chunk_path_001.json",
        &vector(
            "rup1_chunk_path_001",
            "CHUNK = \"RUP1\" | 0x01 | op 0x85 | req_id | index u32 (< 1,093) | len u32 \
             (1..=61,440) | chunk | path_len u8 (0..=11) | path[32] x path_len, the chunk's \
             RFC 6962 audit path from the leaf's sibling up, checked as RFC 9162 §2.1.3.2 \
             against the manifest's chunk root before the chunk is written \
             (RAVEN_UPDATE_EXCHANGE_V1 §3.3, RAVEN_RELEASE_BUNDLE_V1 §5). The payloads of \
             rrb1_chunk_tree_001.json (byte j = j mod 251): small, 246,760 bytes in 5 chunks, \
             answers GET_CHUNKS first 0 count 5 with 5 CHUNK frames and CHUNKS_END OK 5 \
             (req_id 52550005); max, 64 MiB in 1,093 chunks: chunk 0 has an 11-hash path and \
             the longest CHUNK frame (61,811 bytes), which pads into PAD1's 65,519-byte \
             bucket. Each frame is given as head_hex | the chunk (fill_len bytes, byte j = \
             (fill_start + j) mod 251) | tail_hex, with its length and SHA-256; the last small \
             chunk also whole",
            json!({
                "chunk_size": CHUNK_SIZE,
                "small_payload_len": SMALL_PAYLOAD_LEN,
                "max_payload_len": MAX_PAYLOAD_LEN,
                "req_id_hex": hex::encode(REQ_CHUNKS),
            }),
            json!({
                "small": {
                    "root_hex": hex::encode(tree.root()),
                    "chunk_count": 5,
                    "request": frame_entry("get_chunks", &REQ_CHUNKS, &request),
                    "chunks": small_chunks,
                    "last_frame_hex": hex::encode(frame(&REQ_CHUNKS, &Rup1Msg::Chunk(last))),
                    "end": frame_entry(
                        "chunks_end",
                        &REQ_CHUNKS,
                        &Rup1Msg::ChunksEnd { stopped: None, sent: 5 },
                    ),
                },
                "max": {
                    "root_hex": hex::encode(max_tree.root()),
                    "chunk_count": MAX_CHUNKS,
                    "chunks": max_entries,
                    "max_chunk_frame_len": MAX_CHUNK_FRAME_LEN,
                    "pad1_max_inner": PAD1_MAX_INNER,
                },
            }),
        ),
    );

    // Refusals.
    let oversize: Vec<Value> = oversize_cases().iter().map(case_json).collect();
    let forged: Vec<Value> = forged_chunks()
        .iter()
        .map(|(name, c, start, flip)| {
            let f = frame(&REQ_CHUNKS, &Rup1Msg::Chunk(c.clone()));
            let tail_at = HEADER_LEN + 8 + c.bytes.len();
            let (mut built, spec) = filled(
                &f[..HEADER_LEN + 8],
                c.bytes.len(),
                *start,
                &f[tail_at..],
                *flip,
            );
            let decoded = match decode(&built) {
                Ok((_, Rup1Msg::Chunk(d))) => d,
                other => panic!("{name}: {other:?}"),
            };
            assert!(
                !chunk_checks(&tree.root(), payload.len(), &decoded),
                "{name}"
            );
            if let Some(at) = flip {
                built[*at] ^= 1;
            }
            assert_eq!(built, f, "{name}");
            json!({
                "name": name,
                "result": "OK",
                "check": false,
                "frame": spec["frame"],
            })
        })
        .collect();
    assert_vector(
        "negative/rup1_oversize_chunk_001.json",
        &vector(
            "rup1_oversize_chunk_001",
            "CHUNK = \"RUP1\" | 0x01 | op 0x85 | req_id | index u32 | len u32 | chunk | \
             path_len u8 | path[32] x path_len (RAVEN_UPDATE_EXCHANGE_V1 §3.3, §4): every \
             length is checked against its cap before anything is read or copied. refused: \
             a chunk over 61,440 bytes or of 0, a declared length of 2^32 - 1, a path over 11 \
             hashes, an index of 1,093 or more, a chunk or path cut short, a trailing byte, \
             a frame over 65,511 bytes (BAD_CHUNK_LEN, BAD_PATH_LEN, BAD_INDEX, TRUNCATED, \
             TRAILING_BYTES, TOO_LONG); chunk_max is the longest CHUNK, accepted. forged: \
             CHUNK frames of the small payload of rrb1_chunk_tree_001.json that decode but \
             fail the fetcher's check against its chunk root (root and 5 chunks as in \
             rup1_chunk_path_001.json): a flipped byte (xor_at: that frame byte ^ 0x01), \
             another chunk's path, a path one hash short or long, another index, an index \
             past the last, and the short last chunk named as a full one. A listener drops \
             every CHUNK; a fetcher never writes a refused one. Frames given as head_hex | \
             fill | tail_hex as in rup1_chunk_path_001.json",
            json!({
                "small_root_hex": hex::encode(tree.root()),
                "small_payload_len": SMALL_PAYLOAD_LEN,
                "chunk_size": CHUNK_SIZE,
            }),
            json!({ "refused": oversize, "forged": forged }),
        ),
    );
    let rules: Vec<Value> = decode_cases().iter().map(case_json).collect();
    assert_vector(
        "negative/rup1_decode_rules_001.json",
        &vector(
            "rup1_decode_rules_001",
            &format!(
                "{LAYOUT}. Decode order (§4): the magic (NOT_RUP1), the header and the frame \
                 length 10..=65,511 (TRUNCATED, TOO_LONG), the version (BAD_VERSION), the op \
                 (UNKNOWN_OP), then each field in order with its cap, then nothing after \
                 (TRAILING_BYTES). result: OK or the refusal; listener: what a listener does \
                 with the frame (§6): REQUEST, HAVE, ERROR UNSUPPORTED (another version, an \
                 op below 0x80 it does not know), ERROR MALFORMED (a known request breaking a \
                 rule), DROP (anything else: replies and HAVEs are never answered). Frames are \
                 whole (frame_hex) or head_hex | fill | tail_hex as in rup1_chunk_path_001.json"
            ),
            json!({}),
            json!({ "cases": rules }),
        ),
    );
}

/// The committed `rup1_*` files are exactly the ones
/// [`update_vectors_rup1`] writes.
#[test]
fn rup1_vector_files() {
    if std::env::var(REGEN).as_deref() == Ok("1") {
        return; // being written right now
    }
    let names = |dir: &str| {
        let mut names: Vec<String> = std::fs::read_dir(rvn1_dir().join(dir))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with("rup1_") && n.ends_with(".json"))
            .collect();
        names.sort();
        names
    };
    assert_eq!(
        names("update"),
        [
            "rup1_chunk_path_001.json",
            "rup1_frames_001.json",
            "rup1_have_001.json",
        ]
    );
    assert_eq!(
        names("update/negative"),
        ["rup1_decode_rules_001.json", "rup1_oversize_chunk_001.json"]
    );
}
