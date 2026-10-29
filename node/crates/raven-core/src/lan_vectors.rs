//! Assert `shared-vectors/rvn1/lan` fixtures against `lan_noise` / `lan_rlb1`.
//!
//! `noise_xx_handshake_002` is the same handshake with the RLX1 message-3
//! payload (`protocol/RAVEN_ROUTE_HINTS_V1.md` §3.2); 001 keeps pinning the
//! empty payload every build sends with route hints off.
//!
//! CI: `.github/workflows/raven-serverless.yml` runs `cargo test -p raven-core --lib lan_`.
//! iOS KAT: `node/scripts/ios_lan_kat.sh` (Swift `RavenSecureLanNoiseTests` / `RavenSecureLanRlb1Tests`).
//! Manual lab order: `node/scripts/ios_lan_lab_checklist.md` (design §11).
//!
//! Test fixtures only: the public seeds and the fixed-ephemeral handshake KAT
//! must not ship in a default/release build, so the module compiles under
//! `cfg(test)` or the `test-helpers` feature.
#![cfg(any(test, feature = "test-helpers"))]

use serde_json::Value;
use std::path::PathBuf;

use crate::identity::Identity;
use crate::lan_noise::{
    build_initiator_with_ephemeral, build_responder_with_ephemeral, derive_noise_static,
    encode_bind, get_remote_static, handshake_hash, handshake_read, handshake_write,
    into_transport, noise_static_public, transport_decrypt, transport_encrypt, verify_bind,
    BIND_LEN, HKDF_INFO, HKDF_SALT, NOISE_PATTERN,
};
use crate::lan_rlb1::{decode_offer, encode_offer, LanBundle, MAX_OFFER_WIRE, RLB1_HEADER_LEN};
use crate::prekey_bundle::{PrekeyBundle, MLKEM768_EK_LEN};

pub const ALICE_DEVICE_SEED: &str =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
pub const BOB_DEVICE_SEED: &str =
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const INITIATOR_EPHEMERAL: [u8; 32] = [0x11; 32];
const RESPONDER_EPHEMERAL: [u8; 32] = [0x22; 32];
const FIRST_APP_PLAINTEXT: &[u8] = b"rvn1/lan-vector/app-001";

fn vectors_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.pop();
    p.join("shared-vectors").join("rvn1").join("lan")
}

fn load_json(name: &str) -> Value {
    let path = vectors_root().join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing vector {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("json")
}

fn hex_to_vec(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

fn hex_to_arr32(s: &str) -> [u8; 32] {
    let v = hex_to_vec(s);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn identity_from_hex(seed_hex: &str) -> Identity {
    Identity::from_seed(&hex_to_arr32(seed_hex))
}

pub fn fixture_offer_bundle() -> LanBundle {
    let user = identity_from_hex(ALICE_DEVICE_SEED);
    let now = 1_700_000_000_000u64;
    let device_x = [0x71; 32];
    let cert = crate::device_cert::DeviceCertificate::issue(
        &user,
        user.public_key_bytes(),
        device_x,
        "alice-lan-device-1",
        now - 60_000,
        now + 86_400_000,
        7,
    )
    .unwrap();
    let prekey = PrekeyBundle::from_hybrid_public(
        "alice-lan-device-1",
        device_x,
        vec![0x02; MLKEM768_EK_LEN],
        1,
        now,
        now + 86_400_000,
    )
    .unwrap()
    .sign(&user)
    .unwrap();
    LanBundle { cert, prekey }
}

pub struct HandshakeKat {
    pub m1: Vec<u8>,
    pub m2: Vec<u8>,
    pub m3: Vec<u8>,
    /// What the responder's `handshake_read` of message 3 returned.
    pub m3_payload_read: Vec<u8>,
    pub initiator_static_pub: [u8; 32],
    pub responder_static_pub: [u8; 32],
    pub initiator_remote_static: [u8; 32],
    pub responder_remote_static: [u8; 32],
    pub handshake_hash: [u8; 32],
    pub initiator_bind_ct: Vec<u8>,
    pub responder_bind_ct: Vec<u8>,
    pub first_app_ct: Vec<u8>,
}

pub fn compute_handshake_kat() -> HandshakeKat {
    compute_handshake_kat_with(&[])
}

/// [`compute_handshake_kat`] with `m3_payload` as the initiator's message-3
/// payload (`noise_xx_handshake_002`: [`rlx1_m3_payload`]).
pub fn compute_handshake_kat_with(m3_payload: &[u8]) -> HandshakeKat {
    let initiator = identity_from_hex(ALICE_DEVICE_SEED);
    let responder = identity_from_hex(BOB_DEVICE_SEED);
    let init_priv = derive_noise_static(&initiator).expect("init static");
    let resp_priv = derive_noise_static(&responder).expect("resp static");
    let init_pub = noise_static_public(&init_priv);
    let resp_pub = noise_static_public(&resp_priv);

    let mut init_hs =
        build_initiator_with_ephemeral(&init_priv, Some(&INITIATOR_EPHEMERAL)).expect("init hs");
    let mut resp_hs =
        build_responder_with_ephemeral(&resp_priv, Some(&RESPONDER_EPHEMERAL)).expect("resp hs");

    let m1 = handshake_write(&mut init_hs, &[]).expect("m1");
    handshake_read(&mut resp_hs, &m1).expect("read m1");
    let m2 = handshake_write(&mut resp_hs, &[]).expect("m2");
    handshake_read(&mut init_hs, &m2).expect("read m2");
    let m3 = handshake_write(&mut init_hs, m3_payload).expect("m3");
    let m3_payload_read = handshake_read(&mut resp_hs, &m3).expect("read m3");

    let hash = handshake_hash(&init_hs);
    assert_eq!(hash, handshake_hash(&resp_hs));

    let init_remote = get_remote_static(&init_hs).expect("init remote static");
    let resp_remote = get_remote_static(&resp_hs).expect("resp remote static");
    assert_eq!(init_remote, resp_pub);
    assert_eq!(resp_remote, init_pub);

    let mut init_t = into_transport(init_hs).expect("init transport");
    let mut resp_t = into_transport(resp_hs).expect("resp transport");

    let init_bind = encode_bind(&initiator, &init_pub);
    let init_bind_ct = transport_encrypt(&mut init_t, &init_bind).expect("init bind ct");
    let resp_bind = encode_bind(&responder, &resp_pub);
    let resp_bind_ct = transport_encrypt(&mut resp_t, &resp_bind).expect("resp bind ct");
    let first_app_ct = transport_encrypt(&mut init_t, FIRST_APP_PLAINTEXT).expect("first app ct");

    HandshakeKat {
        m1,
        m2,
        m3,
        m3_payload_read,
        initiator_static_pub: init_pub,
        responder_static_pub: resp_pub,
        initiator_remote_static: init_remote,
        responder_remote_static: resp_remote,
        handshake_hash: hash,
        initiator_bind_ct: init_bind_ct,
        responder_bind_ct: resp_bind_ct,
        first_app_ct,
    }
}

pub fn assert_noise_static_vector() {
    let v = load_json("noise_static_001.json");
    assert_eq!(v["protocol_version"].as_str().unwrap(), "rvn1");
    assert_eq!(
        v["inputs"]["hkdf_salt"].as_str().unwrap(),
        "rvn1/lan-noise/v1"
    );
    assert_eq!(v["inputs"]["hkdf_info"].as_str().unwrap(), "static-x25519");
    let seed = hex_to_arr32(v["inputs"]["device_seed_hex"].as_str().unwrap());
    let id = Identity::from_seed(&seed);
    let priv_key = derive_noise_static(&id).expect("derive");
    let pub_key = noise_static_public(&priv_key);
    assert_eq!(
        hex::encode(pub_key),
        v["expected"]["noise_static_pub_hex"].as_str().unwrap()
    );
    assert_eq!(HKDF_SALT, b"rvn1/lan-noise/v1");
    assert_eq!(HKDF_INFO, b"static-x25519");
    assert_ne!(*priv_key, seed);
}

pub fn assert_noise_bind_vector() {
    let v = load_json("noise_bind_001.json");
    let seed = hex_to_arr32(v["inputs"]["device_seed_hex"].as_str().unwrap());
    let id = Identity::from_seed(&seed);
    let static_priv = derive_noise_static(&id).expect("derive");
    let static_pub = noise_static_public(&static_priv);
    assert_eq!(
        hex::encode(static_pub),
        v["inputs"]["noise_static_pub_hex"].as_str().unwrap()
    );
    let bind = encode_bind(&id, &static_pub);
    assert_eq!(bind.len(), BIND_LEN);
    assert_eq!(
        hex::encode(bind),
        v["expected"]["bind_hex"].as_str().unwrap()
    );
    verify_bind(&bind, &static_pub, Some(&id.public_key_bytes())).expect("bind ok");
}

pub fn assert_rlb1_offer_vector() {
    let v = load_json("rlb1_offer_001.json");
    assert_eq!(
        v["canonical_json_policy"].as_str().unwrap(),
        "serde_json::to_vec field order; lowercase hex; omit null otp"
    );
    let bundle = fixture_offer_bundle();
    let wire = encode_offer(&bundle).expect("encode");
    assert_eq!(
        hex::encode(&wire),
        v["expected"]["offer_wire_hex"].as_str().unwrap()
    );
    assert!(wire.len() <= MAX_OFFER_WIRE);
    let back = decode_offer(&wire).expect("decode");
    assert_eq!(back.cert, bundle.cert);
    assert_eq!(back.prekey, bundle.prekey);

    let reject = &v["reject_cases"]["combined_cap_ge_65519"];
    let mut oversize = wire.clone();
    oversize.resize(MAX_OFFER_WIRE + 1, 0);
    assert_eq!(
        oversize.len(),
        reject["offer_wire_len"].as_u64().unwrap() as usize
    );
    assert!(oversize.len() > MAX_OFFER_WIRE);
    assert_eq!(
        decode_offer(&oversize),
        Err(reject["decode_error"].as_str().unwrap().into())
    );
    let cert_len = reject["cert_json_len"].as_u64().unwrap() as usize;
    let prekey_len = reject["prekey_json_len"].as_u64().unwrap() as usize;
    assert!(RLB1_HEADER_LEN + cert_len + prekey_len > MAX_OFFER_WIRE);
    assert_eq!(
        reject["encode_error"].as_str().unwrap(),
        "rlb1 offer exceeds transport plaintext"
    );
}

pub fn assert_noise_xx_handshake_vector() {
    let v = load_json("noise_xx_handshake_001.json");
    assert_eq!(
        v["inputs"]["noise_pattern"].as_str().unwrap(),
        NOISE_PATTERN
    );
    assert_eq!(v["inputs"]["prologue"].as_str().unwrap(), "");
    assert_eq!(
        v["inputs"]["initiator_device_seed_hex"].as_str().unwrap(),
        ALICE_DEVICE_SEED
    );
    assert_eq!(
        v["inputs"]["responder_device_seed_hex"].as_str().unwrap(),
        BOB_DEVICE_SEED
    );
    assert_eq!(
        hex::encode(INITIATOR_EPHEMERAL),
        v["inputs"]["initiator_ephemeral_priv_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        hex::encode(RESPONDER_EPHEMERAL),
        v["inputs"]["responder_ephemeral_priv_hex"]
            .as_str()
            .unwrap()
    );

    let kat = compute_handshake_kat();
    let exp = &v["expected"];
    assert_eq!(hex::encode(&kat.m1), exp["m1_hex"].as_str().unwrap());
    assert_eq!(hex::encode(&kat.m2), exp["m2_hex"].as_str().unwrap());
    assert_eq!(hex::encode(&kat.m3), exp["m3_hex"].as_str().unwrap());
    assert_eq!(
        hex::encode(kat.initiator_static_pub),
        exp["initiator_static_pub_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(kat.responder_static_pub),
        exp["responder_static_pub_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(kat.initiator_remote_static),
        exp["initiator_remote_static_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(kat.responder_remote_static),
        exp["responder_remote_static_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(kat.handshake_hash),
        exp["handshake_hash_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(&kat.initiator_bind_ct),
        exp["initiator_bind_transport_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(&kat.responder_bind_ct),
        exp["responder_bind_transport_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(&kat.first_app_ct),
        exp["first_application_ciphertext_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(FIRST_APP_PLAINTEXT),
        exp["first_application_plaintext_hex"].as_str().unwrap()
    );

    let initiator = identity_from_hex(ALICE_DEVICE_SEED);
    let responder = identity_from_hex(BOB_DEVICE_SEED);
    let init_priv = derive_noise_static(&initiator).unwrap();
    let resp_priv = derive_noise_static(&responder).unwrap();
    let mut init_hs =
        build_initiator_with_ephemeral(&init_priv, Some(&INITIATOR_EPHEMERAL)).unwrap();
    let mut resp_hs =
        build_responder_with_ephemeral(&resp_priv, Some(&RESPONDER_EPHEMERAL)).unwrap();
    let m1 = handshake_write(&mut init_hs, &[]).unwrap();
    assert_eq!(m1, kat.m1);
    handshake_read(&mut resp_hs, &m1).unwrap();
    let m2 = handshake_write(&mut resp_hs, &[]).unwrap();
    assert_eq!(m2, kat.m2);
    handshake_read(&mut init_hs, &m2).unwrap();
    let m3 = handshake_write(&mut init_hs, &[]).unwrap();
    assert_eq!(m3, kat.m3);
    handshake_read(&mut resp_hs, &m3).unwrap();
    let mut init_t = into_transport(init_hs).unwrap();
    let mut resp_t = into_transport(resp_hs).unwrap();

    let init_bind_pt = transport_decrypt(&mut resp_t, &kat.initiator_bind_ct).unwrap();
    verify_bind(
        &init_bind_pt,
        &kat.initiator_static_pub,
        Some(&initiator.public_key_bytes()),
    )
    .unwrap();
    let resp_bind_pt = transport_decrypt(&mut init_t, &kat.responder_bind_ct).unwrap();
    verify_bind(
        &resp_bind_pt,
        &kat.responder_static_pub,
        Some(&responder.public_key_bytes()),
    )
    .unwrap();
    let app_pt = transport_decrypt(&mut resp_t, &kat.first_app_ct).unwrap();
    assert_eq!(app_pt, FIRST_APP_PLAINTEXT);
}

/// The message-3 payload of `noise_xx_handshake_002`: RLX1 with LINK_CAPS
/// bit 8 (RRH1), what a LAN dialer that accepts route hints sends.
pub fn rlx1_m3_payload() -> Vec<u8> {
    crate::route_hints::rlx1_payload(crate::CAP_LINK_RRH1)
}

/// `noise_xx_handshake_002.json` as the KAT computes it.
pub fn noise_xx_handshake_002_expected() -> Value {
    let payload = rlx1_m3_payload();
    let kat = compute_handshake_kat_with(&payload);
    serde_json::json!({
        "name": "LAN Noise XX handshake KAT, RLX1 message-3 payload",
        "description": "Same seeds and fixed ephemerals as noise_xx_handshake_001; the initiator's \
                        message 3 carries RLX1 LINK_CAPS 0x00000100 (RAVEN_ROUTE_HINTS_V1 §3.2). \
                        m1 and m2 equal 001 and m3 grows from 64 to 75 bytes. The payload is \
                        MixHash'd, so the handshake hash differs from 001; it does not touch ck, \
                        so the transport keys, both binds and the first application ciphertext \
                        equal 001",
        "protocol_version": "rvn1",
        "deterministic": true,
        "kat_production": "snow-0.9.6 fixed_ephemeral_key_for_testing_only per side",
        "inputs": {
            "noise_pattern": NOISE_PATTERN,
            "prologue": "",
            "initiator_device_seed_hex": ALICE_DEVICE_SEED,
            "responder_device_seed_hex": BOB_DEVICE_SEED,
            "initiator_ephemeral_priv_hex": hex::encode(INITIATOR_EPHEMERAL),
            "responder_ephemeral_priv_hex": hex::encode(RESPONDER_EPHEMERAL),
            "first_application_plaintext_utf8": "rvn1/lan-vector/app-001",
            "m3_payload_hex": hex::encode(&payload)
        },
        "expected": {
            "m1_hex": hex::encode(&kat.m1),
            "m2_hex": hex::encode(&kat.m2),
            "m3_hex": hex::encode(&kat.m3),
            "m3_len": kat.m3.len(),
            "m3_payload_read_hex": hex::encode(&kat.m3_payload_read),
            "initiator_static_pub_hex": hex::encode(kat.initiator_static_pub),
            "responder_static_pub_hex": hex::encode(kat.responder_static_pub),
            "initiator_remote_static_hex": hex::encode(kat.initiator_remote_static),
            "responder_remote_static_hex": hex::encode(kat.responder_remote_static),
            "handshake_hash_hex": hex::encode(kat.handshake_hash),
            "initiator_bind_transport_hex": hex::encode(&kat.initiator_bind_ct),
            "responder_bind_transport_hex": hex::encode(&kat.responder_bind_ct),
            "first_application_plaintext_hex": hex::encode(FIRST_APP_PLAINTEXT),
            "first_application_ciphertext_hex": hex::encode(&kat.first_app_ct)
        }
    })
}

pub fn assert_noise_xx_handshake_002_vector() {
    let v = load_json("noise_xx_handshake_002.json");
    assert_eq!(v, noise_xx_handshake_002_expected());
    let v1 = load_json("noise_xx_handshake_001.json");
    // The same inputs as 001, plus the message-3 payload.
    for (key, value) in v1["inputs"].as_object().unwrap() {
        assert_eq!(&v["inputs"][key], value, "{key}");
    }
    let (e1, e2) = (&v1["expected"], &v["expected"]);
    let bytes = |e: &Value, key: &str| hex_to_vec(e[key].as_str().unwrap());
    for key in ["m1_hex", "m2_hex"] {
        assert_eq!(e2[key], e1[key], "{key}");
    }
    assert_eq!(bytes(e1, "m3_hex").len(), 64);
    assert_eq!(bytes(e2, "m3_hex").len(), 75);
    // MixHash covers the payload ...
    assert_ne!(e2["handshake_hash_hex"], e1["handshake_hash_hex"]);
    // ... but ck does not, nor does the bind (it signs only the static key).
    for key in [
        "initiator_static_pub_hex",
        "responder_static_pub_hex",
        "initiator_remote_static_hex",
        "responder_remote_static_hex",
        "initiator_bind_transport_hex",
        "responder_bind_transport_hex",
        "first_application_ciphertext_hex",
    ] {
        assert_eq!(e2[key], e1[key], "{key}");
    }
    // The responder reads exactly the 11 RLX1 bytes.
    let read = bytes(e2, "m3_payload_read_hex");
    assert_eq!(read, rlx1_m3_payload());
    assert_eq!(read.len(), 11);
    assert_eq!(crate::route_hints::rlx1_caps(&read), crate::CAP_LINK_RRH1);
    assert!(compute_handshake_kat().m3_payload_read.is_empty());
}

/// `noise_xx_handshake_003` (RAVEN_LINK_KNOCK_V1 §9): the knock's day
/// (2026-10-23), nonce and trailing bytes, the per-connection statics and the
/// padded message 3 payload. Alice dials Bob, the people and the knock of
/// `link/rlk1_tags_001.json`.
const KNOCK_UNIX_MS: u64 = 1_792_756_800_000;
const KNOCK_NONCE: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const KNOCK_M1_PAD: [u8; 5] = [0xA5, 0x5A, 0xC3, 0x3C, 0x99];
const KNOCK_M2_PAD: [u8; 3] = [0x0F, 0xF0, 0x66];
/// The listener's fresh static for this connection (it matched the knock).
const RESPONDER_FRESH_STATIC: [u8; 32] = [0x33; 32];
/// The dialer's fresh static for message 3 (the proof verified).
const INITIATOR_FRESH_STATIC: [u8; 32] = [0x44; 32];
/// Message 3's payload length: RLX1 LINK_CAPS 0x00000100 and a PAD entry.
const KNOCK_M3_LEN: usize = 40;

/// The knocked handshake of `noise_xx_handshake_003`, with what each step
/// showed.
pub struct KnockKat {
    pub hs: HandshakeKat,
    pub m1_payload: Vec<u8>,
    pub m2_payload: Vec<u8>,
    pub m3_payload: Vec<u8>,
    /// Message 1 and 2 as the dialer's first state (its derived static)
    /// wrote and read them: the same bytes.
    pub derived_m1: Vec<u8>,
    pub initiator_derived_static_pub: [u8; 32],
}

/// The RLK1 handshake: Alice knocks in message 1 (her derived static in the
/// state that writes it), Bob matches it and answers with a fresh static and
/// the proof, Alice checks the proof and builds the handshake again with a
/// fresh static of her own and the same ephemeral (the same messages 1 and
/// 2), then sends message 3 with the padded RLX1.
pub fn compute_knock_kat() -> KnockKat {
    use crate::lan_noise::{
        build_initiator_with_static, build_responder_with_static_and_ephemeral,
        derived_static_secret, static_public,
    };
    use crate::link_knock::{check_m2, day_of, knock_keys, m1_payload_with, m2_payload_with};
    use x25519_dalek::StaticSecret;

    let initiator = identity_from_hex(ALICE_DEVICE_SEED);
    let responder = identity_from_hex(BOB_DEVICE_SEED);
    let alice_keys = knock_keys(&initiator, &responder.public_key_bytes()).expect("keys");
    let bob_keys = knock_keys(&responder, &initiator.public_key_bytes()).expect("keys");
    let eph = StaticSecret::from(INITIATOR_EPHEMERAL);
    let e_pub = static_public(&eph);
    let day = day_of(KNOCK_UNIX_MS);
    let m1_payload = m1_payload_with(&alice_keys, day, &e_pub, &KNOCK_NONCE, &KNOCK_M1_PAD);

    let derived = derived_static_secret(&initiator).expect("derived");
    let mut first = build_initiator_with_static(&derived, &eph, None).expect("init hs");
    let derived_m1 = handshake_write(&mut first, &m1_payload).expect("m1");

    let book = [bob_keys];
    let found = crate::link_knock::match_m1(&book, &derived_m1, day).expect("a match");
    assert_eq!(found.peer, initiator.public_key_bytes());
    let s_b = StaticSecret::from(RESPONDER_FRESH_STATIC);
    let s_b_pub = static_public(&s_b);
    let mut resp_hs = build_responder_with_static_and_ephemeral(&s_b, &RESPONDER_EPHEMERAL, None)
        .expect("resp hs");
    assert!(handshake_read(&mut resp_hs, &derived_m1)
        .expect("read m1")
        .eq(&m1_payload));
    let m2_payload = m2_payload_with(&book[0], &found.nonce, &found.e, &s_b_pub, &KNOCK_M2_PAD);
    let m2 = handshake_write(&mut resp_hs, &m2_payload).expect("m2");
    let read = handshake_read(&mut first, &m2).expect("read m2");
    let remote = get_remote_static(&first).expect("remote static");
    assert_eq!(remote, s_b_pub);
    assert!(check_m2(&alice_keys, &KNOCK_NONCE, &e_pub, &remote, &read));
    drop(first);

    let fresh = StaticSecret::from(INITIATOR_FRESH_STATIC);
    let mut init_hs = build_initiator_with_static(&fresh, &eph, None).expect("init hs");
    let m1 = handshake_write(&mut init_hs, &m1_payload).expect("m1 again");
    assert_eq!(m1, derived_m1, "the static is not in message 1");
    assert_eq!(handshake_read(&mut init_hs, &m2).expect("m2 again"), read);
    let m3_payload = crate::route_hints::rlx1_payload_padded(crate::CAP_LINK_RRH1, KNOCK_M3_LEN);
    let m3 = handshake_write(&mut init_hs, &m3_payload).expect("m3");
    let m3_payload_read = handshake_read(&mut resp_hs, &m3).expect("read m3");

    let hash = handshake_hash(&init_hs);
    assert_eq!(hash, handshake_hash(&resp_hs));
    let init_pub = static_public(&fresh);
    let init_remote = get_remote_static(&init_hs).expect("init remote static");
    let resp_remote = get_remote_static(&resp_hs).expect("resp remote static");
    assert_eq!(resp_remote, init_pub);
    let mut init_t = into_transport(init_hs).expect("init transport");
    let mut resp_t = into_transport(resp_hs).expect("resp transport");
    let init_bind_ct =
        transport_encrypt(&mut init_t, &encode_bind(&initiator, &init_pub)).expect("bind");
    let resp_bind_ct =
        transport_encrypt(&mut resp_t, &encode_bind(&responder, &s_b_pub)).expect("bind");
    let first_app_ct = transport_encrypt(&mut init_t, FIRST_APP_PLAINTEXT).expect("app ct");
    KnockKat {
        hs: HandshakeKat {
            m1,
            m2,
            m3,
            m3_payload_read,
            initiator_static_pub: init_pub,
            responder_static_pub: s_b_pub,
            initiator_remote_static: init_remote,
            responder_remote_static: resp_remote,
            handshake_hash: hash,
            initiator_bind_ct: init_bind_ct,
            responder_bind_ct: resp_bind_ct,
            first_app_ct,
        },
        m1_payload,
        m2_payload,
        m3_payload,
        derived_m1,
        initiator_derived_static_pub: noise_static_public(
            &derive_noise_static(&initiator).expect("derived"),
        ),
    }
}

/// `noise_xx_handshake_003.json` as the KAT computes it.
pub fn noise_xx_handshake_003_expected() -> Value {
    let k = compute_knock_kat();
    let kat = &k.hs;
    serde_json::json!({
        "name": "LAN Noise XX handshake KAT, RLK1 link knock and per-connection statics",
        "description": "Same seeds and fixed ephemerals as noise_xx_handshake_001; Alice knocks \
                        (RAVEN_LINK_KNOCK_V1): message 1 payload = nonce16 || tag16 || pad, \
                        the knock of link/rlk1_tags_001.json. Bob matched it and answers with a \
                        fresh static (scalar 32 bytes of 0x33) and message 2 payload = proof16 \
                        || pad. Alice's first handshake state holds her derived static; once \
                        the proof verified she builds it again with a fresh static (scalar 32 \
                        bytes of 0x44) and the same ephemeral, which writes the same message 1 \
                        and reads the same message 2, and sends message 3 with RLX1 LINK_CAPS \
                        0x00000100 and a PAD entry (type 0x7E) to 40 bytes. Both binds sign \
                        the fresh statics",
        "protocol_version": "rvn1",
        "deterministic": true,
        "kat_production": "snow-0.9.6 fixed_ephemeral_key_for_testing_only per side",
        "inputs": {
            "noise_pattern": NOISE_PATTERN,
            "prologue": "",
            "initiator_device_seed_hex": ALICE_DEVICE_SEED,
            "responder_device_seed_hex": BOB_DEVICE_SEED,
            "initiator_ephemeral_priv_hex": hex::encode(INITIATOR_EPHEMERAL),
            "responder_ephemeral_priv_hex": hex::encode(RESPONDER_EPHEMERAL),
            "knock_unix_ms": KNOCK_UNIX_MS,
            "knock_nonce_hex": hex::encode(KNOCK_NONCE),
            "m1_pad_hex": hex::encode(KNOCK_M1_PAD),
            "m2_pad_hex": hex::encode(KNOCK_M2_PAD),
            "responder_static_priv_hex": hex::encode(RESPONDER_FRESH_STATIC),
            "initiator_static_priv_hex": hex::encode(INITIATOR_FRESH_STATIC),
            "first_application_plaintext_utf8": "rvn1/lan-vector/app-001",
            "m3_payload_hex": hex::encode(&k.m3_payload)
        },
        "expected": {
            "m1_hex": hex::encode(&kat.m1),
            "m1_len": kat.m1.len(),
            "m1_payload_hex": hex::encode(&k.m1_payload),
            "m2_hex": hex::encode(&kat.m2),
            "m2_len": kat.m2.len(),
            "m2_payload_hex": hex::encode(&k.m2_payload),
            "m3_hex": hex::encode(&kat.m3),
            "m3_len": kat.m3.len(),
            "m3_payload_read_hex": hex::encode(&kat.m3_payload_read),
            "initiator_derived_static_pub_hex": hex::encode(k.initiator_derived_static_pub),
            "initiator_static_pub_hex": hex::encode(kat.initiator_static_pub),
            "responder_static_pub_hex": hex::encode(kat.responder_static_pub),
            "initiator_remote_static_hex": hex::encode(kat.initiator_remote_static),
            "responder_remote_static_hex": hex::encode(kat.responder_remote_static),
            "handshake_hash_hex": hex::encode(kat.handshake_hash),
            "initiator_bind_transport_hex": hex::encode(&kat.initiator_bind_ct),
            "responder_bind_transport_hex": hex::encode(&kat.responder_bind_ct),
            "first_application_plaintext_hex": hex::encode(FIRST_APP_PLAINTEXT),
            "first_application_ciphertext_hex": hex::encode(&kat.first_app_ct)
        }
    })
}

pub fn assert_noise_xx_handshake_003_vector() {
    let v = load_json("noise_xx_handshake_003.json");
    assert_eq!(v, noise_xx_handshake_003_expected());
    let v1 = load_json("noise_xx_handshake_001.json");
    let (e1, e3) = (&v1["expected"], &v["expected"]);
    let bytes = |e: &Value, key: &str| hex_to_vec(e[key].as_str().unwrap());
    // Message 1: the same ephemeral as 001, then the knock.
    let (m1_1, m1_3) = (bytes(e1, "m1_hex"), bytes(e3, "m1_hex"));
    assert_eq!(m1_3[..32], m1_1[..]);
    assert_eq!(m1_3[32..], bytes(e3, "m1_payload_hex")[..]);
    assert_eq!(m1_3.len(), 32 + 32 + KNOCK_M1_PAD.len());
    // The shapes of RLK1 §6: m1 64-95, m2 112-143, m3 within 64 + 64.
    assert!((64..=95).contains(&m1_3.len()));
    assert!((112..=143).contains(&bytes(e3, "m2_hex").len()));
    assert_eq!(bytes(e3, "m3_hex").len(), 64 + KNOCK_M3_LEN);
    // Fresh statics both ways: neither is the derived one of 001.
    assert_ne!(
        e3["responder_static_pub_hex"],
        e1["responder_static_pub_hex"]
    );
    assert_ne!(
        e3["initiator_static_pub_hex"],
        e1["initiator_static_pub_hex"]
    );
    assert_eq!(
        e3["initiator_derived_static_pub_hex"],
        e1["initiator_static_pub_hex"]
    );
    // The listener reads the padded RLX1 and its caps as before.
    let read = bytes(e3, "m3_payload_read_hex");
    assert_eq!(read.len(), KNOCK_M3_LEN);
    assert_eq!(crate::route_hints::rlx1_caps(&read), crate::CAP_LINK_RRH1);
    // The knock is rlk1_tags_001's.
    let tags = {
        let mut p = vectors_root();
        p.pop();
        let raw = std::fs::read_to_string(p.join("link").join("rlk1_tags_001.json")).unwrap();
        serde_json::from_str::<Value>(&raw).unwrap()
    };
    assert_eq!(tags["expected"]["raw_m1_hex"], e3["m1_hex"]);
    assert_eq!(tags["expected"]["m2_payload_hex"], e3["m2_payload_hex"]);
    assert_eq!(tags["inputs"]["s_b_hex"], e3["responder_static_pub_hex"]);
}

pub fn assert_all_lan_vectors() {
    assert_noise_static_vector();
    assert_noise_bind_vector();
    assert_rlb1_offer_vector();
    assert_noise_xx_handshake_vector();
    assert_noise_xx_handshake_002_vector();
    assert_noise_xx_handshake_003_vector();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_vectors_root_exists() {
        assert!(vectors_root().is_dir());
    }

    #[test]
    fn noise_static_001_vector() {
        assert_noise_static_vector();
    }

    #[test]
    fn noise_bind_001_vector() {
        assert_noise_bind_vector();
    }

    #[test]
    fn rlb1_offer_001_vector() {
        assert_rlb1_offer_vector();
    }

    #[test]
    fn noise_xx_handshake_001_vector() {
        assert_noise_xx_handshake_vector();
    }

    /// Regenerate with `RAVEN_REGEN_RRH1_VECTORS=1` only when the RLX1
    /// payload or the handshake changes on purpose.
    #[test]
    fn noise_xx_handshake_002_vector() {
        if std::env::var("RAVEN_REGEN_RRH1_VECTORS").as_deref() == Ok("1") {
            let path = vectors_root().join("noise_xx_handshake_002.json");
            let json = serde_json::to_string_pretty(&noise_xx_handshake_002_expected()).unwrap();
            std::fs::write(path, json + "\n").unwrap();
        }
        assert_noise_xx_handshake_002_vector();
    }

    /// Regenerate with `RAVEN_REGEN_SECURITY_VECTORS=1` only when RLK1 or
    /// the handshake changes on purpose.
    #[test]
    fn noise_xx_handshake_003_vector() {
        if std::env::var("RAVEN_REGEN_SECURITY_VECTORS").as_deref() == Ok("1") {
            let path = vectors_root().join("noise_xx_handshake_003.json");
            let json = serde_json::to_string_pretty(&noise_xx_handshake_003_expected()).unwrap();
            std::fs::write(path, json + "\n").unwrap();
        }
        assert_noise_xx_handshake_003_vector();
    }

    /// The knock's builders with the derived statics and empty payloads are
    /// today's handshake byte for byte (`noise_xx_handshake_001`): the gate
    /// shut, or a dialer that cannot knock, changes nothing.
    #[test]
    fn the_static_builders_give_handshake_001_with_empty_payloads() {
        use crate::lan_noise::{
            build_initiator_with_static, build_responder_with_static_and_ephemeral,
            derived_static_secret,
        };
        let kat = compute_handshake_kat();
        let alice = derived_static_secret(&identity_from_hex(ALICE_DEVICE_SEED)).unwrap();
        let bob = derived_static_secret(&identity_from_hex(BOB_DEVICE_SEED)).unwrap();
        let eph = x25519_dalek::StaticSecret::from(INITIATOR_EPHEMERAL);
        let mut init_hs = build_initiator_with_static(&alice, &eph, None).unwrap();
        let mut resp_hs =
            build_responder_with_static_and_ephemeral(&bob, &RESPONDER_EPHEMERAL, None).unwrap();
        let m1 = handshake_write(&mut init_hs, &[]).unwrap();
        assert_eq!(m1, kat.m1);
        handshake_read(&mut resp_hs, &m1).unwrap();
        let m2 = handshake_write(&mut resp_hs, &[]).unwrap();
        assert_eq!(m2, kat.m2);
        handshake_read(&mut init_hs, &m2).unwrap();
        let m3 = handshake_write(&mut init_hs, &[]).unwrap();
        assert_eq!(m3, kat.m3);
        handshake_read(&mut resp_hs, &m3).unwrap();
        assert_eq!(handshake_hash(&init_hs), kat.handshake_hash);
    }

    /// A responder that discards the message-3 payload (every pre-RLX1
    /// build, and raven-node's LAN listener before the contact gate) still
    /// completes the bind exchange with an RLX1 initiator.
    #[test]
    fn noise_xx_handshake_002_old_responder_discards_the_payload() {
        let kat = compute_handshake_kat();
        let initiator = identity_from_hex(ALICE_DEVICE_SEED);
        let responder = identity_from_hex(BOB_DEVICE_SEED);
        let init_priv = derive_noise_static(&initiator).unwrap();
        let resp_priv = derive_noise_static(&responder).unwrap();
        let mut init_hs =
            build_initiator_with_ephemeral(&init_priv, Some(&INITIATOR_EPHEMERAL)).unwrap();
        let mut resp_hs =
            build_responder_with_ephemeral(&resp_priv, Some(&RESPONDER_EPHEMERAL)).unwrap();
        let m1 = handshake_write(&mut init_hs, &[]).unwrap();
        handshake_read(&mut resp_hs, &m1).unwrap();
        let m2 = handshake_write(&mut resp_hs, &[]).unwrap();
        handshake_read(&mut init_hs, &m2).unwrap();
        let m3 = handshake_write(&mut init_hs, &rlx1_m3_payload()).unwrap();
        assert_eq!(m3.len(), kat.m3.len() + 11);
        // The old listener: `handshake_read(&mut hs, &m3)?;`, result unused.
        let _ = handshake_read(&mut resp_hs, &m3).unwrap();
        let mut init_t = into_transport(init_hs).unwrap();
        let mut resp_t = into_transport(resp_hs).unwrap();

        let init_bind = encode_bind(&initiator, &kat.initiator_static_pub);
        let ct = transport_encrypt(&mut init_t, &init_bind).unwrap();
        assert_eq!(ct, kat.initiator_bind_ct);
        let pt = transport_decrypt(&mut resp_t, &ct).unwrap();
        verify_bind(
            &pt,
            &kat.initiator_static_pub,
            Some(&initiator.public_key_bytes()),
        )
        .unwrap();
        let resp_bind = encode_bind(&responder, &kat.responder_static_pub);
        let ct = transport_encrypt(&mut resp_t, &resp_bind).unwrap();
        assert_eq!(ct, kat.responder_bind_ct);
        let pt = transport_decrypt(&mut init_t, &ct).unwrap();
        verify_bind(
            &pt,
            &kat.responder_static_pub,
            Some(&responder.public_key_bytes()),
        )
        .unwrap();
        let ct = transport_encrypt(&mut init_t, FIRST_APP_PLAINTEXT).unwrap();
        assert_eq!(ct, kat.first_app_ct);
        assert_eq!(
            transport_decrypt(&mut resp_t, &ct).unwrap(),
            FIRST_APP_PLAINTEXT
        );
    }

    #[test]
    fn all_lan_vectors() {
        assert_all_lan_vectors();
    }

    /// Regenerate JSON fixtures: `cargo test -p raven-core lan_vector_dump -- --ignored --nocapture`
    /// (`noise_xx_handshake_002.json` comes from `noise_xx_handshake_002_vector`).
    #[test]
    #[ignore]
    fn lan_vector_dump() {
        use std::io::Write;

        let out_dir = vectors_root();
        std::fs::create_dir_all(&out_dir).expect("mkdir lan vectors");

        let alice = identity_from_hex(ALICE_DEVICE_SEED);
        let alice_static = noise_static_public(&derive_noise_static(&alice).unwrap());
        let bind = encode_bind(&alice, &alice_static);
        let offer = fixture_offer_bundle();
        let offer_wire = encode_offer(&offer).unwrap();
        let kat = compute_handshake_kat();

        let huge_id = "x".repeat(60_000);
        let user = identity_from_hex(ALICE_DEVICE_SEED);
        let now = 1_700_000_000_000u64;
        let oversize_cert = crate::device_cert::DeviceCertificate::issue(
            &user,
            user.public_key_bytes(),
            [0x71; 32],
            &huge_id,
            now - 60_000,
            now + 86_400_000,
            7,
        )
        .unwrap();
        let oversize_prekey = PrekeyBundle::from_hybrid_public(
            &huge_id,
            [0x71; 32],
            vec![0x02; MLKEM768_EK_LEN],
            1,
            now,
            now + 86_400_000,
        )
        .unwrap()
        .sign(&user)
        .unwrap();
        let oversize_cert_json = serde_json::to_vec(&oversize_cert).unwrap();
        let oversize_prekey_json = serde_json::to_vec(&oversize_prekey.to_json()).unwrap();

        let write_json = |name: &str, value: serde_json::Value| {
            let path = out_dir.join(name);
            let mut f = std::fs::File::create(&path).expect("create json");
            writeln!(f, "{}", serde_json::to_string_pretty(&value).expect("json")).expect("write");
        };

        write_json(
            "noise_static_001.json",
            serde_json::json!({
                "name": "LAN Noise static X25519 derive",
                "description": "Device signing seed HKDF-SHA256 to Noise XX static key",
                "protocol_version": "rvn1",
                "deterministic": true,
                "inputs": {
                    "device_seed_hex": ALICE_DEVICE_SEED,
                    "hkdf_salt": "rvn1/lan-noise/v1",
                    "hkdf_info": "static-x25519"
                },
                "expected": {
                    "noise_static_pub_hex": hex::encode(alice_static)
                }
            }),
        );

        write_json(
            "noise_bind_001.json",
            serde_json::json!({
                "name": "LAN Noise identity bind",
                "description": "ed25519_pub || sig(rvn1/lan-noise/v1 || noise_static_pub)",
                "protocol_version": "rvn1",
                "deterministic": true,
                "inputs": {
                    "device_seed_hex": ALICE_DEVICE_SEED,
                    "noise_static_pub_hex": hex::encode(alice_static),
                    "bind_domain": "rvn1/lan-noise/v1"
                },
                "expected": {
                    "bind_len": BIND_LEN,
                    "bind_hex": hex::encode(bind)
                }
            }),
        );

        write_json(
            "rlb1_offer_001.json",
            serde_json::json!({
                "name": "RLB1 offer wire bytes",
                "description": "Exact offer under serde_json canonical field order",
                "protocol_version": "rvn1",
                "deterministic": true,
                "canonical_json_policy": "serde_json::to_vec field order; lowercase hex; omit null otp",
                "inputs": {
                    "device_seed_hex": ALICE_DEVICE_SEED,
                    "device_id": "alice-lan-device-1",
                    "epoch_ms": now
                },
                "expected": {
                    "offer_wire_len": offer_wire.len(),
                    "offer_wire_hex": hex::encode(&offer_wire),
                    "max_offer_wire": MAX_OFFER_WIRE
                },
                "reject_cases": {
                    "combined_cap_ge_65519": {
                        "description": "Whole offer must fit in one Noise transport plaintext",
                        "cert_json_len": oversize_cert_json.len(),
                        "prekey_json_len": oversize_prekey_json.len(),
                        "combined_json_len": oversize_cert_json.len() + oversize_prekey_json.len(),
                        "encode_error": "rlb1 offer exceeds transport plaintext",
                        "offer_wire_len": MAX_OFFER_WIRE + 1,
                        "decode_error": "rlb1 offer exceeds transport plaintext"
                    }
                }
            }),
        );

        write_json(
            "noise_xx_handshake_001.json",
            serde_json::json!({
                "name": "LAN Noise XX handshake KAT",
                "description": "Fixed ephemerals via snow fixed_ephemeral_key_for_testing_only; empty prologue",
                "protocol_version": "rvn1",
                "deterministic": true,
                "kat_production": "snow-0.9.6 fixed_ephemeral_key_for_testing_only per side",
                "inputs": {
                    "noise_pattern": NOISE_PATTERN,
                    "prologue": "",
                    "initiator_device_seed_hex": ALICE_DEVICE_SEED,
                    "responder_device_seed_hex": BOB_DEVICE_SEED,
                    "initiator_ephemeral_priv_hex": hex::encode(INITIATOR_EPHEMERAL),
                    "responder_ephemeral_priv_hex": hex::encode(RESPONDER_EPHEMERAL),
                    "first_application_plaintext_utf8": "rvn1/lan-vector/app-001"
                },
                "expected": {
                    "m1_hex": hex::encode(&kat.m1),
                    "m2_hex": hex::encode(&kat.m2),
                    "m3_hex": hex::encode(&kat.m3),
                    "initiator_static_pub_hex": hex::encode(kat.initiator_static_pub),
                    "responder_static_pub_hex": hex::encode(kat.responder_static_pub),
                    "initiator_remote_static_hex": hex::encode(kat.initiator_remote_static),
                    "responder_remote_static_hex": hex::encode(kat.responder_remote_static),
                    "handshake_hash_hex": hex::encode(kat.handshake_hash),
                    "initiator_bind_transport_hex": hex::encode(&kat.initiator_bind_ct),
                    "responder_bind_transport_hex": hex::encode(&kat.responder_bind_ct),
                    "first_application_plaintext_hex": hex::encode(FIRST_APP_PLAINTEXT),
                    "first_application_ciphertext_hex": hex::encode(&kat.first_app_ct)
                }
            }),
        );

        eprintln!("wrote LAN vectors to {}", out_dir.display());
    }

    /// Used by `ios_swift_rust_lan_integration.sh` to register the Swift test client.
    #[test]
    fn integration_swift_client_pub_hex() {
        let seed = [0x21u8; 32];
        let id = identity_from_hex(&hex::encode(seed));
        eprintln!(
            "RAVEN_INTEGRATION_CLIENT_PUB={}",
            hex::encode(id.public_key_bytes())
        );
        eprintln!("RAVEN_INTEGRATION_CLIENT_ADDR={}", id.address());
    }
}
