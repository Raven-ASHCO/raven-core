//! PAD1 codec and link state (RAVEN_LINK_PADDING_V1), and the vectors in
//! `shared-vectors/rvn1/link`. The vectors are written only under
//! `RAVEN_REGEN_SECURITY_VECTORS=1` (a deliberate wire change) and otherwise
//! compared with the committed files; the Python reference
//! (`protocol/reference/raven_protocol/link_padding.py`) checks every one.

use super::*;
use crate::identity::Identity;
use crate::internet::{
    hello_caps, hello_signing_bytes, pack_hello, unpack_verify_hello, HelloBinding, HelloRole,
    LinkFeatures, HELLO_WIRE_LEN,
};
use crate::lan_noise::{derive_noise_static, noise_static_public};
use crate::route_hints::{rlx1_caps, rlx1_payload};
use crate::{CAP_INTERNET, CAP_LINK_PAD1, CAP_LINK_RRH1};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const REGEN: &str = "RAVEN_REGEN_SECURITY_VECTORS";

/// The inner frame lengths at the bucket edges, with their frame lengths.
const EDGES: [(usize, usize); 8] = [
    (1, 512),
    (504, 512),
    (505, 4_096),
    (4_088, 4_096),
    (4_089, 16_384),
    (16_376, 16_384),
    (16_377, 65_519),
    (65_511, 65_519),
];

fn rvn1_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.pop();
    p.join("shared-vectors/rvn1")
}

/// A hex field of a committed rvn1 vector (`file` under shared-vectors/rvn1).
fn source_hex(file: &str, section: &str, field: &str) -> Vec<u8> {
    let raw = std::fs::read_to_string(rvn1_dir().join(file)).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    hex::decode(v[section][field].as_str().unwrap()).unwrap()
}

/// The 293-byte RVN1 envelope of a sealed ACK.
fn ack() -> Vec<u8> {
    let ack = source_hex(
        "atsam/indexed_session_v1_sealed_ack_001.json",
        "expected",
        "packed_envelope_hex",
    );
    assert_eq!(ack.len(), 293);
    ack
}

/// The 2,788-byte PairInit V1 frame.
fn pair_init() -> Vec<u8> {
    let p = source_hex(
        "atsam/pair_init_v1_001.json",
        "expected",
        "pair_init_wire_hex",
    );
    assert_eq!(p.len(), 2_788);
    p
}

/// `n` bytes, byte i = i mod 251 (the max vector's inner frame).
fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

/// A hand-built frame of length `total`: header fields as given, `inner`,
/// then zeros.
fn raw_frame(version: u8, reserved: u8, inner_len: u16, inner: &[u8], total: usize) -> Vec<u8> {
    let mut f = Vec::with_capacity(total);
    f.extend_from_slice(PAD1_MAGIC);
    f.extend_from_slice(&[version, reserved]);
    f.extend_from_slice(&inner_len.to_be_bytes());
    f.extend_from_slice(inner);
    f.resize(total, 0);
    f
}

#[test]
fn buckets_and_their_edges() {
    assert_eq!(PAD1_BUCKETS, [512, 4_096, 16_384, 65_519]);
    assert_eq!(PAD1_MAX_INNER, 65_511);
    assert_eq!(bucket_for(0), None);
    assert_eq!(bucket_for(PAD1_MAX_INNER + 1), None);
    assert_eq!(bucket_for(usize::MAX), None);
    for (inner_len, total) in EDGES {
        assert_eq!(bucket_for(inner_len), Some(total), "{inner_len}");
    }
    // Design B §2: an ACK and a short text share 512, a PairInit 4,096.
    assert_eq!(bucket_for(ack().len()), Some(512));
    assert_eq!(bucket_for(pair_init().len()), Some(4_096));
}

/// Every inner length 1..=65,511 round trips in the smallest bucket that
/// holds it, the padding all zeros.
#[test]
fn round_trip_every_inner_length() {
    let inner = pattern(PAD1_MAX_INNER);
    let mut bucket = 0;
    for n in 1..=PAD1_MAX_INNER {
        let frame = wrap(&inner[..n]).unwrap();
        let want = PAD1_BUCKETS[bucket..]
            .iter()
            .copied()
            .find(|&t| t >= n + PAD1_HEADER_LEN)
            .unwrap();
        bucket = PAD1_BUCKETS.iter().position(|&t| t == want).unwrap();
        assert_eq!(frame.len(), want, "{n}");
        assert_eq!(&frame[..6], b"RPD1\x01\x00");
        assert_eq!(usize::from(u16::from_be_bytes([frame[6], frame[7]])), n);
        assert_eq!(unwrap(&frame), Ok(&inner[..n]), "{n}");
    }
}

#[test]
fn wrap_refuses_what_cannot_be_padded() {
    assert_eq!(wrap(&[]), Err(Pad1Error::BadLength));
    assert_eq!(
        wrap(&pattern(PAD1_MAX_INNER + 1)),
        Err(Pad1Error::BadLength)
    );
    // Today a link carries frames up to 65,519 bytes (RFC1 with the largest
    // RSO1): one of those cannot go on a padded link.
    assert_eq!(
        wrap(&vec![0x52; MAX_TRANSPORT_PLAINTEXT]),
        Err(Pad1Error::BadLength)
    );
    // Never nested: a padded frame is not an inner frame.
    let padded = wrap(&ack()).unwrap();
    assert_eq!(wrap(&padded), Err(Pad1Error::Nested));
    assert_eq!(wrap(b"RPD1"), Err(Pad1Error::Nested));
    // A prefix of the magic is not the magic.
    assert_eq!(wrap(b"RPD").unwrap().len(), 512);
}

/// Each rejection rule of spec §6, one at a time, and the order they are
/// checked in.
#[test]
fn unwrap_rejection_rules() {
    let ack = ack();
    let n = ack.len() as u16;
    let good = raw_frame(1, 0, n, &ack, 512);
    assert_eq!(good, wrap(&ack).unwrap());
    assert_eq!(unwrap(&good), Ok(&ack[..]));

    let mut magic = good.clone();
    magic[3] = b'2';
    assert_eq!(unwrap(&magic), Err(Pad1Error::BadMagic));
    assert_eq!(unwrap(&ack), Err(Pad1Error::BadMagic));
    assert_eq!(unwrap(b"RPD"), Err(Pad1Error::BadMagic));
    assert_eq!(unwrap(&[]), Err(Pad1Error::BadMagic));

    for total in [4, 8, 511, 513, 4_095, 16_383, 65_518, 65_520, 70_000] {
        let f = raw_frame(1, 0, 1, &[0x52], total.max(9));
        let f = &f[..total];
        assert_eq!(unwrap(f), Err(Pad1Error::BadBucket), "{total}");
    }
    assert_eq!(
        unwrap(&raw_frame(2, 0, n, &ack, 512)),
        Err(Pad1Error::BadVersion)
    );
    assert_eq!(
        unwrap(&raw_frame(0, 0, n, &ack, 512)),
        Err(Pad1Error::BadVersion)
    );
    assert_eq!(
        unwrap(&raw_frame(1, 1, n, &ack, 512)),
        Err(Pad1Error::BadReserved)
    );
    assert_eq!(
        unwrap(&raw_frame(1, 0, 0, &[], 512)),
        Err(Pad1Error::BadLength)
    );
    assert_eq!(
        unwrap(&raw_frame(1, 0, 505, &ack, 512)),
        Err(Pad1Error::BadLength)
    );
    assert_eq!(
        unwrap(&raw_frame(1, 0, u16::MAX, &ack, 65_519)),
        Err(Pad1Error::BadLength)
    );
    // inner_len = T - 8 exactly: no padding at all.
    let full = pattern(504);
    assert_eq!(unwrap(&raw_frame(1, 0, 504, &full, 512)), Ok(&full[..]));
    for at in [usize::from(n) + PAD1_HEADER_LEN, 400, 511] {
        let mut f = good.clone();
        f[at] = 0x01;
        assert_eq!(unwrap(&f), Err(Pad1Error::NonZeroPadding), "{at}");
    }
    let nested = raw_frame(1, 0, 512, &good, 4_096);
    assert_eq!(unwrap(&nested), Err(Pad1Error::Nested));
    // A larger bucket than needed is not refused (spec §6).
    let roomy = raw_frame(1, 0, n, &ack, 4_096);
    assert_eq!(unwrap(&roomy), Ok(&ack[..]));
    // Order: bucket before version, version before reserved, reserved
    // before length, length before padding, padding before nesting.
    let mut f = raw_frame(2, 1, 0, &[], 513);
    assert_eq!(unwrap(&f), Err(Pad1Error::BadBucket));
    f.truncate(512);
    assert_eq!(unwrap(&f), Err(Pad1Error::BadVersion));
    f[4] = 1;
    assert_eq!(unwrap(&f), Err(Pad1Error::BadReserved));
    f[5] = 0;
    f[511] = 9;
    assert_eq!(unwrap(&f), Err(Pad1Error::BadLength));
    let mut f = raw_frame(1, 0, 4, b"RPD1", 512);
    f[511] = 9;
    assert_eq!(unwrap(&f), Err(Pad1Error::NonZeroPadding));
    f[511] = 0;
    assert_eq!(unwrap(&f), Err(Pad1Error::Nested));
}

#[test]
fn error_codes() {
    let all = [
        (Pad1Error::BadMagic, "BAD_MAGIC"),
        (Pad1Error::BadBucket, "BAD_BUCKET"),
        (Pad1Error::BadVersion, "BAD_VERSION"),
        (Pad1Error::BadReserved, "BAD_RESERVED"),
        (Pad1Error::BadLength, "BAD_LENGTH"),
        (Pad1Error::NonZeroPadding, "NONZERO_PADDING"),
        (Pad1Error::Nested, "NESTED"),
        (Pad1Error::Unpadded, "UNPADDED"),
    ];
    for (e, code) in all {
        assert_eq!(e.code(), code);
        assert_eq!(e.to_string(), format!("PAD1 {code}"));
    }
}

/// With PAD1 off nothing changes either way: frames go out as they are and
/// every frame comes in untouched, an RPD1 one too (the link then treats it
/// as any frame it does not know).
#[test]
fn off_passes_everything_through() {
    let ack = ack();
    let padded = wrap(&ack).unwrap();
    for mut s in [
        PadState::OFF,
        PadState::default(),
        PadState::agreed(false),
        PadState::lan_dialer(false),
    ] {
        assert_eq!(s, PadState::OFF);
        assert!(matches!(s.on_send(&ack), Ok(Cow::Borrowed(b)) if b == &ack[..]));
        assert_eq!(s.on_send(&[]).unwrap().as_ref(), b"");
        assert_eq!(s.on_send(&padded).unwrap().as_ref(), &padded[..]);
        assert_eq!(s.on_recv(&padded), Ok(&padded[..]));
        assert_eq!(s.on_recv(&ack), Ok(&ack[..]));
        assert_eq!(s.on_recv(b"RPD1"), Ok(&b"RPD1"[..]));
        assert!(!s.negotiated() && !s.peer_started());
    }
}

/// Internet direct, p2p, nearby and the LAN listener: wrap from the start;
/// unpadded frames are read until the peer's first RPD1 frame, refused
/// after it.
#[test]
fn agreed_wraps_and_turns_strict_after_the_peers_first_rpd1() {
    let ack = ack();
    let padded = wrap(&ack).unwrap();
    let mut s = PadState::agreed(true);
    assert!(s.negotiated() && !s.peer_started());
    assert_eq!(s.on_send(&ack).unwrap().as_ref(), &padded[..]);
    assert_eq!(s.on_send(&[]), Err(Pad1Error::BadLength));
    assert_eq!(s.on_send(&padded), Err(Pad1Error::Nested));
    // Before the peer pads: unpadded frames are read as they are.
    assert_eq!(s.on_recv(&ack), Ok(&ack[..]));
    assert_eq!(s.on_recv(&ack), Ok(&ack[..]));
    assert!(!s.peer_started());
    assert_eq!(s.on_recv(&padded), Ok(&ack[..]));
    assert!(s.peer_started());
    assert_eq!(s.on_recv(&padded), Ok(&ack[..]));
    // After: an unpadded frame closes the link.
    assert_eq!(s.on_recv(&ack), Err(Pad1Error::Unpadded));
    assert_eq!(s.on_recv(b""), Err(Pad1Error::Unpadded));
    // A malformed RPD1 frame is refused before the peer started too.
    let mut s = PadState::agreed(true);
    let mut bad = padded.clone();
    bad[511] = 1;
    assert_eq!(s.on_recv(&bad), Err(Pad1Error::NonZeroPadding));
    assert!(!s.peer_started());
}

/// The LAN dialer offered PAD1 in its LINK_CAPS: it reads RPD1 at once but
/// wraps only after the listener's first RPD1 frame (an old listener never
/// sends one, and gets bare frames to the end).
#[test]
fn lan_dialer_wraps_after_the_listeners_first_rpd1() {
    let ack = ack();
    let padded = wrap(&ack).unwrap();
    let mut s = PadState::lan_dialer(true);
    assert!(!s.negotiated());
    assert!(matches!(s.on_send(&ack), Ok(Cow::Borrowed(_))));
    assert_eq!(s.on_recv(&ack), Ok(&ack[..]));
    assert!(!s.negotiated(), "a bare frame says nothing");
    assert_eq!(s.on_recv(&padded), Ok(&ack[..]));
    assert!(s.negotiated() && s.peer_started());
    assert_eq!(s.on_send(&ack).unwrap().as_ref(), &padded[..]);
    assert_eq!(s.on_recv(&ack), Err(Pad1Error::Unpadded));

    // An old listener: bare frames both ways, to the end.
    let mut s = PadState::lan_dialer(true);
    for _ in 0..3 {
        assert_eq!(s.on_recv(&ack), Ok(&ack[..]));
        assert_eq!(s.on_send(&ack).unwrap().as_ref(), &ack[..]);
    }
}

// ── Vectors (spec §9) ─────────────────────────────────────────────────

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

/// Assert that the committed vector `file` (under shared-vectors/rvn1/link)
/// equals `expected`; write it first under `RAVEN_REGEN_SECURITY_VECTORS=1`.
fn assert_vector(file: &str, expected: &Value) {
    let path = rvn1_dir().join("link").join(file);
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

const LAYOUT: &str = "frame = \"RPD1\" | version 0x01 | reserved 0x00 | inner_len u16 BE | \
                      inner | 0x00 padding; the frame length is the smallest bucket of \
                      512, 4096, 16384, 65519 that holds 8 + inner_len \
                      (RAVEN_LINK_PADDING_V1 §2)";

/// A padded frame of a committed inner frame.
fn frame_vector(name: &str, source: &str, inner: &[u8]) -> Value {
    let frame = wrap(inner).unwrap();
    assert_eq!(unwrap(&frame), Ok(inner));
    vector(
        name,
        &format!("{LAYOUT}. The inner frame is {source}"),
        json!({
            "inner_source": source,
            "inner_hex": hex::encode(inner),
            "inner_len": inner.len(),
        }),
        json!({
            "bucket": frame.len(),
            "header_hex": hex::encode(&frame[..PAD1_HEADER_LEN]),
            "padding_len": frame.len() - PAD1_HEADER_LEN - inner.len(),
            "frame_hex": hex::encode(&frame),
            "frame_len": frame.len(),
        }),
    )
}

/// The negative vectors of one frame each: (file, name, frame, error).
fn negative_frames() -> Vec<(&'static str, &'static str, Vec<u8>, Pad1Error)> {
    let ack = ack();
    let n = ack.len() as u16;
    let good = wrap(&ack).unwrap();
    let mut nonzero = good.clone();
    nonzero[511] = 0x01;
    let mut bad_bucket = good.clone();
    bad_bucket.push(0);
    vec![
        (
            "pad1_nonzero_padding_001.json",
            "PAD1 negative: the last padding byte is 0x01",
            nonzero,
            Pad1Error::NonZeroPadding,
        ),
        (
            "pad1_bad_bucket_001.json",
            "PAD1 negative: a 513-byte frame (not a bucket)",
            bad_bucket,
            Pad1Error::BadBucket,
        ),
        (
            "pad1_nested_001.json",
            "PAD1 negative: the inner frame is itself an RPD1 frame",
            raw_frame(1, 0, 512, &good, 4_096),
            Pad1Error::Nested,
        ),
        (
            "pad1_len_overflow_001.json",
            "PAD1 negative: inner_len 505 in a 512-byte frame (at most 504 fit)",
            raw_frame(1, 0, 505, &ack, 512),
            Pad1Error::BadLength,
        ),
        (
            "pad1_zero_len_001.json",
            "PAD1 negative: inner_len 0",
            raw_frame(1, 0, 0, &[], 512),
            Pad1Error::BadLength,
        ),
        (
            "pad1_bad_version_001.json",
            "PAD1 negative: version 0x02",
            raw_frame(2, 0, n, &ack, 512),
            Pad1Error::BadVersion,
        ),
        (
            "pad1_reserved_001.json",
            "PAD1 negative: reserved byte 0x01",
            raw_frame(1, 1, n, &ack, 512),
            Pad1Error::BadReserved,
        ),
    ]
}

#[test]
fn link_padding_vectors() {
    let ack = ack();
    assert_vector(
        "pad1_ack_512_001.json",
        &frame_vector(
            "PAD1 frame of a sealed ACK (bucket 512)",
            "the 293-byte RVN1 envelope of atsam/indexed_session_v1_sealed_ack_001.json \
             (expected.packed_envelope_hex)",
            &ack,
        ),
    );
    assert_vector(
        "pad1_pairinit_4096_001.json",
        &frame_vector(
            "PAD1 frame of a PairInit (bucket 4096)",
            "the 2788-byte PairInit V1 frame of atsam/pair_init_v1_001.json \
             (expected.pair_init_wire_hex)",
            &pair_init(),
        ),
    );

    // The largest frame, by digest (no padding at all), and the bucket edges.
    let inner = pattern(PAD1_MAX_INNER);
    let frame = wrap(&inner).unwrap();
    assert_eq!(frame.len(), 65_519);
    assert_eq!(unwrap(&frame), Ok(&inner[..]));
    let edges: Vec<Value> = EDGES
        .iter()
        .map(|&(inner_len, total)| {
            assert_eq!(wrap(&pattern(inner_len)).unwrap().len(), total);
            json!({ "inner_len": inner_len, "frame_len": total })
        })
        .collect();
    let refused: Vec<Value> = [0, PAD1_MAX_INNER + 1]
        .iter()
        .map(|&inner_len| {
            let e = wrap(&pattern(inner_len)).unwrap_err();
            json!({ "inner_len": inner_len, "error": e.code() })
        })
        .collect();
    assert_vector(
        "pad1_max_001.json",
        &vector(
            "PAD1 frame of the longest inner frame (bucket 65519) and the bucket edges",
            &format!(
                "{LAYOUT}. The inner frame is 65511 bytes, byte i = i mod 251; its frame \
                 is 65519 bytes (the largest bucket, MAX_TRANSPORT_PLAINTEXT) with no \
                 padding, given by its first bytes and its SHA-256. edges: the frame \
                 length of inner frames at each bucket's edges; refused: inner lengths \
                 a sender cannot pad (0, and 65512 or more)"
            ),
            json!({
                "inner_rule": "byte i = i mod 251",
                "inner_len": inner.len(),
                "inner_sha256_hex": hex::encode(Sha256::digest(&inner)),
            }),
            json!({
                "frame_len": frame.len(),
                "padding_len": 0,
                "frame_head_hex": hex::encode(&frame[..40]),
                "frame_sha256_hex": hex::encode(Sha256::digest(&frame)),
                "edges": edges,
                "refused": refused,
            }),
        ),
    );

    // LAN: the dialer's RLX1 LINK_CAPS with RRH1 and PAD1 (§3.2 of
    // RAVEN_ROUTE_HINTS_V1, bit 9 registered by this spec).
    let encodings: Vec<Value> = [CAP_LINK_RRH1 | CAP_LINK_PAD1, CAP_LINK_PAD1]
        .into_iter()
        .map(|caps| {
            let payload = rlx1_payload(caps);
            assert_eq!(rlx1_caps(&payload), caps);
            json!({
                "caps": caps,
                "payload_hex": hex::encode(&payload),
                "rrh1": caps & CAP_LINK_RRH1 != 0,
                "pad1": caps & CAP_LINK_PAD1 != 0,
            })
        })
        .collect();
    assert_eq!(
        hex::encode(rlx1_payload(0x0000_0300)),
        "524c583101010400000300"
    );
    assert_vector(
        "rlx1_caps_002.json",
        &vector(
            "RLX1 LINK_CAPS with PAD1 (RAVEN_ROUTE_HINTS_V1 §3.2, RAVEN_LINK_PADDING_V1 §3)",
            "payload = \"RLX1\" | version 0x01 | entries (type u8 | len u8 | value), at most \
             64 bytes; LINK_CAPS (type 0x01, len 4) is u32 BE in the RIH1 caps namespace, \
             bit 8 = RRH1, bit 9 = PAD1. A listener built before PAD1 reads the same caps \
             and ignores bit 9 (only bits it knows count), so it never pads",
            json!({}),
            json!({ "encodings": encodings }),
        ),
    );

    // Internet direct, p2p, nearby: the signed RIH1 hello with RRH1 and PAD1.
    let id = Identity::from_seed(&[0x51; 32]);
    let binding = HelloBinding {
        role: HelloRole::Initiator,
        handshake_hash: [0x48; 32],
        noise_static_pub: noise_static_public(&derive_noise_static(&id).unwrap()),
    };
    let caps = hello_caps(LinkFeatures::RRH1.with(LinkFeatures::PAD1, true));
    assert_eq!(caps, 0x0000_0302);
    let hello = pack_hello(&id, caps, &binding);
    assert_eq!(hello.len(), HELLO_WIRE_LEN);
    let signing = hello_signing_bytes(caps, &binding, &id.public_key_bytes());
    assert_vector(
        "rih1_hello_pad1_001.json",
        &vector(
            "RIH1 hello with link feature bits 8 (RRH1) and 9 (PAD1)",
            "hello = RIH1 | caps u32 BE | ed25519_pub32 | sig64; sig = Ed25519(signer, \
             \"rvn1/internet-hello/v1\" | role u8 | caps u32 BE | handshake_hash32 | \
             signer_noise_static32 | ed25519_pub32) (RAVEN_TRANSPORT_INTERFACE_V1 §3). \
             Caps = CAP_INTERNET | CAP_LINK_RRH1 | CAP_LINK_PAD1. The noise static is \
             X25519(HKDF-SHA256(salt = \"rvn1/lan-noise/v1\", ikm = seed, info = \
             \"static-x25519\")). Same signer and binding as \
             route_hints/rih1_hello_rrh1_001.json",
            json!({
                "signer_seed_hex": hex::encode([0x51u8; 32]),
                "role": "initiator",
                "role_u8": binding.role.wire(),
                "caps": caps,
                "handshake_hash_hex": hex::encode(binding.handshake_hash),
                "noise_static_pub_hex": hex::encode(binding.noise_static_pub),
                "ed25519_pub_hex": hex::encode(id.public_key_bytes()),
            }),
            json!({
                "signing_bytes_hex": hex::encode(&signing),
                "signature_hex": hex::encode(&hello[40..]),
                "hello_hex": hex::encode(&hello),
                "hello_len": hello.len(),
            }),
        ),
    );
    // Old peers: a build that knows only CAP_INTERNET (and RRH1) verifies
    // the hello and ignores bit 9.
    let (got, pk) = unpack_verify_hello(&hello, &binding).unwrap();
    assert_eq!((got, pk), (caps, id.public_key_bytes()));
    assert_ne!(got & CAP_INTERNET, 0);
    assert_ne!(got & CAP_LINK_PAD1, 0);

    // Negatives: one broken rule each.
    for (file, name, frame, error) in negative_frames() {
        assert_eq!(unwrap(&frame), Err(error), "{file}");
        assert_eq!(PadState::agreed(true).on_recv(&frame), Err(error), "{file}");
        assert_vector(
            &format!("negative/{file}"),
            &vector(
                name,
                &format!(
                    "{LAYOUT}. The frame breaks one rule of RAVEN_LINK_PADDING_V1 §6: the \
                     receiver refuses it with the error and closes the link"
                ),
                json!({ "frame_hex": hex::encode(&frame), "frame_len": frame.len() }),
                json!({ "error": error.code() }),
            ),
        );
    }

    // The state rule: unpadded frames before the peer's first RPD1 frame
    // are read, one after it closes the link.
    let padded = wrap(&ack).unwrap();
    let frames = [ack.clone(), padded.clone(), padded, ack.clone()];
    let mut s = PadState::agreed(true);
    let mut accepted = Vec::new();
    let mut fails = None;
    for (i, f) in frames.iter().enumerate() {
        match s.on_recv(f) {
            Ok(inner) => accepted.push(hex::encode(inner)),
            Err(e) => {
                fails = Some((i, e));
                break;
            }
        }
    }
    assert_eq!(fails, Some((3, Pad1Error::Unpadded)));
    assert_eq!(accepted, vec![hex::encode(&ack); 3]);
    assert_vector(
        "negative/pad1_unpadded_after_pad1_001.json",
        &vector(
            "PAD1 negative: a bare frame after the peer's first RPD1 frame",
            &format!(
                "{LAYOUT}. A receiver that agreed PAD1 on this link (RAVEN_LINK_PADDING_V1 \
                 §6) reads the frames in order: a bare frame before the peer's first RPD1 \
                 frame is read as it is, every RPD1 frame is unwrapped, and the bare frame \
                 after it (frame fails_at) is refused with the error, which closes the \
                 link. accepted_inner_hex: what the receiver read before"
            ),
            json!({
                "side": "agreed",
                "frames_hex": frames.iter().map(hex::encode).collect::<Vec<_>>(),
            }),
            json!({
                "accepted_inner_hex": accepted,
                "fails_at": 3,
                "error": Pad1Error::Unpadded.code(),
            }),
        ),
    );
}

/// The committed files are exactly the ones [`link_padding_vectors`] writes
/// (the RLK1 ones, `rlk1_*`, are `link_knock`'s).
#[test]
fn link_vector_files() {
    if std::env::var(REGEN).as_deref() == Ok("1") {
        return; // being written right now
    }
    let names = |dir: &str| {
        let mut names: Vec<String> = std::fs::read_dir(rvn1_dir().join(dir))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.ends_with(".json") && !n.starts_with("rlk1_"))
            .collect();
        names.sort();
        names
    };
    assert_eq!(
        names("link"),
        [
            "pad1_ack_512_001.json",
            "pad1_max_001.json",
            "pad1_pairinit_4096_001.json",
            "rih1_hello_pad1_001.json",
            "rlx1_caps_002.json",
        ]
    );
    let mut negative: Vec<String> = negative_frames()
        .iter()
        .map(|(file, ..)| (*file).to_owned())
        .collect();
    negative.push("pad1_unpadded_after_pad1_001.json".into());
    negative.sort();
    assert_eq!(names("link/negative"), negative);
}
