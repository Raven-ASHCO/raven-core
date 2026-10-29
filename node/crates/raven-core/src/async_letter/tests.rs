//! RAL1 codec tests and the Rust-generated KATs under
//! `shared-vectors/rvn1/letter/`. Regenerate with
//! `RAVEN_REGEN_LETTER_VECTORS=1` only when the wire format changes on
//! purpose; `protocol/reference/tests/test_async_letter.py` checks every
//! vector byte for byte.

use super::*;
use crate::ack::{Ack, STATUS_DELIVERED};
use crate::atsam_indexed_session::{
    decode_signed_ack, encode_signed_ack, message_key_at_index, open_ack,
    open_indexed_message_with_key, seal_ack, seal_indexed_message_with_key, SignedAck,
    ACK_PLAINTEXT_LEN,
};
use crate::pair_init::{
    confirmation_tag, derive_provisional_root, encode_init, encode_response, init_hash,
    init_signing_bytes, prekey_bundle_hash, response_signing_bytes, session_id, verify_response,
};
use crate::prekey_bundle::PrekeyBundle;
use rand::{Rng, RngCore, SeedableRng};
use serde_json::{json, Value};
use std::path::PathBuf;

const EPOCH_MS: u64 = 1_700_000_000_000;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// The fixed identity seeds of `protocol/reference/generate_rvn1.py`.
const ALICE_ED_PRIV: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const BOB_ED_PRIV: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const REGEN: &str = "RAVEN_REGEN_LETTER_VECTORS";

fn repo_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.pop();
    path
}

fn vectors_dir() -> PathBuf {
    repo_root().join("shared-vectors/rvn1/letter")
}

fn load(relative: &str) -> Value {
    let path = repo_root().join("shared-vectors/rvn1").join(relative);
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn hex_of(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex string")).unwrap()
}

fn arr32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().unwrap()
}

fn x25519_pub(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// Writes `expected` under `RAVEN_REGEN_LETTER_VECTORS=1`, then compares it
/// with the committed file.
fn check_vector(relative: &str, expected: &Value) {
    let path = vectors_dir().join(relative);
    if std::env::var(REGEN).as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(expected).unwrap() + "\n",
        )
        .unwrap();
    }
    let stored: Value = serde_json::from_str(
        &std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
    )
    .unwrap();
    assert_eq!(&stored, expected, "{relative}");
}

/// One carried message of the letter session.
struct EnvelopeSpec {
    index: u32,
    message_id: [u8; 16],
    plaintext: &'static [u8],
    seal_nonce: [u8; 12],
    anti_replay_nonce: [u8; 12],
    created_at_ms: u64,
    expires_at_ms: u64,
}

impl EnvelopeSpec {
    fn to_json(&self) -> Value {
        json!({
            "index": self.index,
            "message_id_hex": hex::encode(self.message_id),
            "plaintext_hex": hex::encode(self.plaintext),
            "seal_nonce_hex": hex::encode(self.seal_nonce),
            "anti_replay_nonce_hex": hex::encode(self.anti_replay_nonce),
            "created_at_ms": self.created_at_ms,
            "expires_at_ms": self.expires_at_ms,
        })
    }
}

const ENVELOPE_HOP_LIMIT: u8 = 8;
const ENVELOPE_REPLICATION_BUDGET: u8 = 2;

fn session_envelope(
    init: &PairInit,
    root: &[u8; 32],
    spec: &EnvelopeSpec,
    signer: &Identity,
) -> Envelope {
    let direction = Direction::InitiatorToResponder;
    let key = message_key_at_index(
        root,
        &init.initiator_address,
        &init.responder_address,
        direction,
        spec.index,
    )
    .unwrap();
    let sealed = seal_indexed_message_with_key(
        &key,
        &init.initiator_address,
        &init.responder_address,
        direction,
        spec.index,
        &spec.message_id,
        spec.plaintext,
        &spec.seal_nonce,
    )
    .unwrap();
    let mut envelope = Envelope {
        env_type: EnvType::Message as u8,
        flags: 0,
        message_id: spec.message_id,
        routing_tag: derive_route_tag(
            root,
            spec.created_at_ms,
            spec.index,
            EnvType::Message as u8,
            direction,
        )
        .unwrap(),
        dest_device_hint: 0,
        created_at: spec.created_at_ms,
        expires_at: spec.expires_at_ms,
        hop_limit: ENVELOPE_HOP_LIMIT,
        replication_budget: ENVELOPE_REPLICATION_BUDGET,
        anti_replay_nonce: spec.anti_replay_nonce,
        ratchet_header_ciphertext: Vec::new(),
        message_ciphertext: sealed,
        sender_authentication: vec![0; 64],
    };
    envelope.sign_with(signer);
    envelope
}

/// A recipient's view for [`open`]: its device, clock, contacts and the
/// signed-prekey secrets of its retained bundles.
struct Ctx {
    local_device: [u8; 32],
    now_ms: u64,
    contacts: Vec<[u8; 32]>,
    prekeys: Vec<([u8; 32], [u8; 32])>,
}

impl Ctx {
    fn open_at(&self, bytes: &[u8], now_ms: u64) -> Result<Opened, Ral1Error> {
        open(
            bytes,
            &self.local_device,
            now_ms,
            |device| self.contacts.contains(device),
            |header| {
                let (_, secret) = self
                    .prekeys
                    .iter()
                    .find(|(hash, _)| *hash == header.wrap_bundle_hash)
                    .ok_or(Ral1Error::UnknownPrekey)?;
                wrap_dh_with_secret(secret, &header.wrap_ephemeral)
            },
        )
    }

    fn open(&self, bytes: &[u8]) -> Result<Opened, Ral1Error> {
        self.open_at(bytes, self.now_ms)
    }

    fn to_json(&self) -> Value {
        json!({
            "local_device_hex": hex::encode(self.local_device),
            "now_ms": self.now_ms,
            "contacts_hex": self.contacts.iter().map(hex::encode).collect::<Vec<_>>(),
            "prekeys": self.prekeys.iter().map(|(hash, secret)| json!({
                "bundle_hash_hex": hex::encode(hash),
                "signed_prekey_secret_hex": hex::encode(secret),
            })).collect::<Vec<_>>(),
        })
    }
}

/// Everything the KATs and negatives are built from (see the derivation
/// text of `ral1_letter_001.json`).
struct Fixture {
    alice_device: Identity,
    bob_device: Identity,
    carol_device: Identity,
    dave_device: Identity,
    alice_ephemeral_secret: [u8; 32],
    source_init: PairInit,
    source_bundle_hash: [u8; 32],
    bob_spk_secret: [u8; 32],
    bob_bundle: PrekeyBundle,
    bob_bundle_hash: [u8; 32],
    init: PairInit,
    init_wire: Vec<u8>,
    z_x: [u8; 32],
    z_pq: [u8; 32],
    root: [u8; 32],
    envelope_specs: Vec<EnvelopeSpec>,
    envelopes: Vec<Envelope>,
    letter_inner: LetterInner,
    letter_inner_bytes: Vec<u8>,
    letter_id: [u8; 16],
    letter_created: u64,
    letter_expires: u64,
    letter_eph: [u8; 32],
    letter: Vec<u8>,
    alice_spk_secret: [u8; 32],
    alice_bundle: PrekeyBundle,
    alice_bundle_hash: [u8; 32],
    response: PairResponse,
    response_wire: Vec<u8>,
    ack_record: Ack,
    ack_plaintext: [u8; ACK_PLAINTEXT_LEN],
    ack_outer_id: [u8; 16],
    ack_seal_nonce: [u8; 12],
    ack_anti_replay: [u8; 12],
    ack_envelope: Envelope,
    reply_inner_bytes: Vec<u8>,
    reply_id: [u8; 16],
    reply_created: u64,
    reply_expires: u64,
    reply_eph: [u8; 32],
    reply: Vec<u8>,
    bob_ctx: Ctx,
    alice_ctx: Ctx,
}

fn pattern<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|i| start.wrapping_add(i as u8))
}

fn fixture() -> Fixture {
    let pair_vector = load("atsam/pair_init_v1_001.json");
    let hybrid = load("atsam/mlkem768_hybrid_kat_001.json");
    let source_init = decode_init(&hex_of(&pair_vector["expected"]["pair_init_wire_hex"])).unwrap();
    let alice_device = Identity::from_seed(&pattern(0));
    let bob_device = Identity::from_seed(&pattern(32));
    assert_eq!(
        alice_device.public_key_bytes(),
        source_init.initiator_device_ed_pub
    );
    assert_eq!(
        bob_device.public_key_bytes(),
        source_init.responder_device_ed_pub
    );
    let carol_device = Identity::from_seed(&[0x63; 32]);
    let dave_device = Identity::from_seed(&[0x64; 32]);
    let alice_identity = Identity::from_seed(&arr32(&hex::decode(ALICE_ED_PRIV).unwrap()));
    let bob_identity = Identity::from_seed(&arr32(&hex::decode(BOB_ED_PRIV).unwrap()));
    let alice_ephemeral_secret = arr32(&hex_of(&hybrid["input"]["alice_x25519_secret_hex"]));
    assert_eq!(
        x25519_pub(&alice_ephemeral_secret),
        source_init.initiator_ephemeral_x25519_pub
    );

    // Bob's bundle as published, then the same generation without the
    // one-time prekey: the bundle a letter's PairInit names.
    let bob_spk_secret = [0x52u8; 32];
    assert_eq!(
        x25519_pub(&bob_spk_secret),
        source_init.responder_signed_x25519_pub
    );
    let bob_bundle_with = |one_time: u32, one_time_pub: Option<[u8; 32]>| {
        PrekeyBundle {
            identity_ed25519_pub: bob_identity.public_key_bytes(),
            device_id: "bob-device-1".into(),
            x25519_pub: source_init.responder_signed_x25519_pub,
            mlkem768_ek: source_init.responder_mlkem768_ek.clone(),
            signed_prekey_id: 42,
            one_time_prekey_id: one_time,
            one_time_x25519_pub: one_time_pub,
            created_at_ms: EPOCH_MS - 60_000,
            expires_at_ms: EPOCH_MS + 7 * DAY_MS,
            signature: [0; 64],
        }
        .sign(&bob_identity)
        .unwrap()
    };
    let source_bundle = bob_bundle_with(7, Some(source_init.responder_one_time_x25519_pub));
    let source_bundle_hash = prekey_bundle_hash(&source_bundle).unwrap();
    assert_eq!(source_bundle_hash, source_init.responder_prekey_bundle_hash);
    let bob_bundle = bob_bundle_with(0, None);
    let bob_bundle_hash = prekey_bundle_hash(&bob_bundle).unwrap();

    // The letter's PairInit: the source PairInit with the one-time prekey
    // slot zeroed, the signed-only bundle, a 7-day lifetime, re-signed.
    let mut init = PairInit {
        one_time_prekey_id: 0,
        responder_one_time_x25519_pub: [0; 32],
        responder_prekey_bundle_hash: bob_bundle_hash,
        expires_at_ms: EPOCH_MS + 7 * DAY_MS,
        signature: [0; 64],
        ..source_init.clone()
    };
    init.signature = alice_device.sign(&init_signing_bytes(&init).unwrap());
    let init_wire = encode_init(&init).unwrap();
    let z_x =
        x25519_shared_checked(&alice_ephemeral_secret, &init.responder_signed_x25519_pub).unwrap();
    let z_pq = arr32(&hex_of(&hybrid["expected"]["z_pq_hex"]));
    assert_eq!(z_pq.to_vec(), hex_of(&pair_vector["input"]["z_pq_hex"]));
    let root = derive_provisional_root(&z_x, &z_pq, &init).unwrap();

    let envelope_specs = vec![
        EnvelopeSpec {
            index: 0,
            message_id: pattern(0xE0),
            plaintext: b"RAL1 letter message 0",
            seal_nonce: [0xC0; 12],
            anti_replay_nonce: [0xD0; 12],
            created_at_ms: EPOCH_MS + 1_000,
            expires_at_ms: EPOCH_MS + 3 * DAY_MS,
        },
        EnvelopeSpec {
            index: 1,
            message_id: pattern(0xF0),
            plaintext: b"RAL1 letter message 1, a little longer",
            seal_nonce: [0xC1; 12],
            anti_replay_nonce: [0xD1; 12],
            created_at_ms: EPOCH_MS + 2_000,
            expires_at_ms: EPOCH_MS + 3 * DAY_MS,
        },
    ];
    let envelopes: Vec<Envelope> = envelope_specs
        .iter()
        .map(|spec| session_envelope(&init, &root, spec, &alice_device))
        .collect();
    let letter_inner = LetterInner {
        pair_init: init_wire.clone(),
        envelopes: envelopes.iter().map(Envelope::pack).collect(),
    };
    let letter_inner_bytes = encode_letter_inner(&letter_inner).unwrap();
    let letter_id = pattern(0xA0);
    let letter_created = EPOCH_MS + 5_000;
    let letter_expires = EPOCH_MS + 3 * DAY_MS;
    let letter_eph = [0x71u8; 32];
    let letter = seal(
        &alice_device,
        &letter_eph,
        &SealInput {
            kind: Ral1Kind::Letter,
            letter_id,
            recipient_device: bob_device.public_key_bytes(),
            created_at_ms: letter_created,
            expires_at_ms: letter_expires,
            wrap_bundle_hash: bob_bundle_hash,
            recipient_signed_prekey: bob_bundle.x25519_pub,
            inner: &letter_inner_bytes,
        },
    )
    .unwrap();

    // The REPLY: Bob's PairResponse and one ACK for message 0, wrapped to
    // Alice's own signed-only bundle.
    let alice_spk_secret = [0x61u8; 32];
    let alice_bundle = PrekeyBundle {
        identity_ed25519_pub: alice_identity.public_key_bytes(),
        device_id: "alice-device-1".into(),
        x25519_pub: x25519_pub(&alice_spk_secret),
        mlkem768_ek: source_init.responder_mlkem768_ek.clone(),
        signed_prekey_id: 17,
        one_time_prekey_id: 0,
        one_time_x25519_pub: None,
        created_at_ms: EPOCH_MS - 60_000,
        expires_at_ms: EPOCH_MS + 7 * DAY_MS,
        signature: [0; 64],
    }
    .sign(&alice_identity)
    .unwrap();
    let alice_bundle_hash = prekey_bundle_hash(&alice_bundle).unwrap();
    let init_digest = init_hash(&init).unwrap();
    let reply_created = EPOCH_MS + 2 * DAY_MS;
    let reply_expires = EPOCH_MS + 7 * DAY_MS;
    let mut response = PairResponse {
        init_id: init.init_id,
        init_hash: init_digest,
        responder_device_ed_pub: bob_device.public_key_bytes(),
        created_at_ms: reply_created,
        expires_at_ms: init.expires_at_ms,
        confirmation_tag: confirmation_tag(&root, &init_digest),
        signature: [0; 64],
    };
    response.signature = bob_device.sign(&response_signing_bytes(&response).unwrap());
    let response_wire = encode_response(&response).unwrap();
    verify_response(&response, &init, &root, reply_created + 1_000).unwrap();
    let ack_record = Ack {
        acked_message_id: envelope_specs[0].message_id,
        status: STATUS_DELIVERED,
        ack_nonce: [0xB2; 12],
        created_at: reply_created,
    };
    let ack_plaintext = encode_signed_ack(&SignedAck {
        signature: ack_record.sign(&bob_device),
        record: ack_record.clone(),
    })
    .unwrap();
    let ack_outer_id = pattern(0x40);
    let ack_seal_nonce = [0xB3u8; 12];
    let ack_anti_replay = [0xB4u8; 12];
    let ack_direction = Direction::ResponderToInitiator;
    let mut ack_envelope = Envelope {
        env_type: EnvType::Ack as u8,
        flags: 0,
        message_id: ack_outer_id,
        routing_tag: derive_route_tag(&root, reply_created, 0, EnvType::Ack as u8, ack_direction)
            .unwrap(),
        dest_device_hint: 0,
        created_at: reply_created,
        expires_at: reply_expires,
        hop_limit: ENVELOPE_HOP_LIMIT,
        replication_budget: ENVELOPE_REPLICATION_BUDGET,
        anti_replay_nonce: ack_anti_replay,
        ratchet_header_ciphertext: Vec::new(),
        message_ciphertext: seal_ack(
            &root,
            &init.initiator_address,
            &init.responder_address,
            ack_direction,
            0,
            &ack_outer_id,
            &ack_plaintext,
            &ack_seal_nonce,
        )
        .unwrap(),
        sender_authentication: vec![0; 64],
    };
    ack_envelope.sign_with(&bob_device);
    let reply_inner_bytes = encode_reply_inner(&ReplyInner {
        pair_response: response_wire.clone(),
        acks: vec![ack_envelope.pack()],
    })
    .unwrap();
    let reply_id = pattern(0xB0);
    let reply_eph = [0x72u8; 32];
    let reply = seal(
        &bob_device,
        &reply_eph,
        &SealInput {
            kind: Ral1Kind::Reply,
            letter_id: reply_id,
            recipient_device: alice_device.public_key_bytes(),
            created_at_ms: reply_created,
            expires_at_ms: reply_expires,
            wrap_bundle_hash: alice_bundle_hash,
            recipient_signed_prekey: alice_bundle.x25519_pub,
            inner: &reply_inner_bytes,
        },
    )
    .unwrap();

    let bob_ctx = Ctx {
        local_device: bob_device.public_key_bytes(),
        now_ms: EPOCH_MS + 60_000,
        contacts: vec![
            alice_device.public_key_bytes(),
            carol_device.public_key_bytes(),
        ],
        prekeys: vec![
            (bob_bundle_hash, bob_spk_secret),
            (source_bundle_hash, bob_spk_secret),
        ],
    };
    let alice_ctx = Ctx {
        local_device: alice_device.public_key_bytes(),
        now_ms: reply_created + 60_000,
        contacts: vec![
            bob_device.public_key_bytes(),
            carol_device.public_key_bytes(),
        ],
        prekeys: vec![(alice_bundle_hash, alice_spk_secret)],
    };
    Fixture {
        alice_device,
        bob_device,
        carol_device,
        dave_device,
        alice_ephemeral_secret,
        source_init,
        source_bundle_hash,
        bob_spk_secret,
        bob_bundle,
        bob_bundle_hash,
        init,
        init_wire,
        z_x,
        z_pq,
        root,
        envelope_specs,
        envelopes,
        letter_inner,
        letter_inner_bytes,
        letter_id,
        letter_created,
        letter_expires,
        letter_eph,
        letter,
        alice_spk_secret,
        alice_bundle,
        alice_bundle_hash,
        response,
        response_wire,
        ack_record,
        ack_plaintext,
        ack_outer_id,
        ack_seal_nonce,
        ack_anti_replay,
        ack_envelope,
        reply_inner_bytes,
        reply_id,
        reply_created,
        reply_expires,
        reply_eph,
        reply,
        bob_ctx,
        alice_ctx,
    }
}

/// The header, keys, nonce, ciphertext and signature of one sealed letter.
fn letter_parts(bytes: &[u8], dh: &[u8; 32]) -> Value {
    let letter = decode(bytes).unwrap();
    let keys = wrap_keys(dh, &letter.header.prefix_bytes());
    json!({
        "header_hex": hex::encode(letter.header.to_bytes()),
        "k_wrap_hex": hex::encode(*keys.k_wrap),
        "k_nonce_hex": hex::encode(*keys.k_nonce),
        "wrap_nonce_hex": hex::encode(letter.header.wrap_nonce),
        "ciphertext_hex": hex::encode(&letter.ciphertext),
        "signature_hex": hex::encode(letter.signature),
        "letter_hex": hex::encode(bytes),
        "letter_len": bytes.len(),
        "letter_digest_hex": hex::encode(letter_digest(bytes)),
        "page_token_hex": hex::encode(page_token(bytes)),
    })
}

fn bundle_json(bundle: &PrekeyBundle, identity_seed_hex: &str) -> Value {
    json!({
        "identity_seed_hex": identity_seed_hex,
        "identity_ed25519_pub_hex": hex::encode(bundle.identity_ed25519_pub),
        "device_id": bundle.device_id,
        "x25519_pub_hex": hex::encode(bundle.x25519_pub),
        "signed_prekey_id": bundle.signed_prekey_id,
        "one_time_prekey_id": bundle.one_time_prekey_id,
        "created_at_ms": bundle.created_at_ms,
        "expires_at_ms": bundle.expires_at_ms,
    })
}

#[test]
fn ral1_known_answer_vectors() {
    let f = fixture();

    // 1. The wrap key schedule on its own.
    let kdf_eph = [0x11u8; 32];
    let kdf_spk = [0x22u8; 32];
    let kdf_header = Ral1Header {
        kind: Ral1Kind::Letter,
        letter_id: pattern(0x01),
        sender_device: f.alice_device.public_key_bytes(),
        recipient_device: f.bob_device.public_key_bytes(),
        created_at_ms: EPOCH_MS,
        expires_at_ms: EPOCH_MS + DAY_MS,
        wrap_bundle_hash: [0x33; 32],
        wrap_ephemeral: x25519_pub(&kdf_eph),
        wrap_nonce: [0; 12],
        ct_len: 0,
    };
    let prefix = kdf_header.prefix_bytes();
    let dh = x25519_shared_checked(&kdf_eph, &x25519_pub(&kdf_spk)).unwrap();
    assert_eq!(
        *wrap_dh_with_secret(&kdf_spk, &kdf_header.wrap_ephemeral).unwrap(),
        dh
    );
    let keys = wrap_keys(&dh, &prefix);
    let mut okm = [0u8; 64];
    Hkdf::<Sha256>::new(Some(&wrap_salt(&kdf_header.wrap_bundle_hash)), &dh)
        .expand(&wrap_info(&prefix), &mut okm)
        .unwrap();
    assert_eq!(&okm[..32], &keys.k_wrap[..]);
    let inner_a: Vec<u8> = (0..512u32).map(|i| (i * 7) as u8).collect();
    let mut inner_b = inner_a.clone();
    inner_b[511] ^= 1;
    let (nonce_a, nonce_b) = (
        wrap_nonce(&keys.k_nonce, &inner_a),
        wrap_nonce(&keys.k_nonce, &inner_b),
    );
    assert_ne!(nonce_a, nonce_b);
    check_vector(
        "ral1_wrap_kdf_001.json",
        &json!({
            "id": "ral1_wrap_kdf_001",
            "protocol_version": "rvn1",
            "deterministic": true,
            "description": "RAL1 wrap key schedule: dh = X25519(e_w, spk_R); salt = SHA-256(\"rvn1/async-letter/v1/salt\" || wrap_bundle_hash); okm = HKDF-SHA256(dh, salt, \"rvn1/async-letter/v1/wrap\" || 0x00 || header[0..168], 64); wrap_nonce = HMAC-SHA256(okm[32..64], \"rvn1/async-letter/v1/nonce\" || 0x00 || inner)[0..12]. inner_b differs from inner_a in its last byte only.",
            "inputs": {
                "wrap_ephemeral_secret_hex": hex::encode(kdf_eph),
                "recipient_signed_prekey_secret_hex": hex::encode(kdf_spk),
                "kind": kdf_header.kind as u8,
                "letter_id_hex": hex::encode(kdf_header.letter_id),
                "sender_device_hex": hex::encode(kdf_header.sender_device),
                "recipient_device_hex": hex::encode(kdf_header.recipient_device),
                "created_at_ms": kdf_header.created_at_ms,
                "expires_at_ms": kdf_header.expires_at_ms,
                "wrap_bundle_hash_hex": hex::encode(kdf_header.wrap_bundle_hash),
                "inner_a_hex": hex::encode(&inner_a),
                "inner_b_hex": hex::encode(&inner_b),
            },
            "expected": {
                "wrap_ephemeral_pub_hex": hex::encode(kdf_header.wrap_ephemeral),
                "recipient_signed_prekey_pub_hex": hex::encode(x25519_pub(&kdf_spk)),
                "header_prefix_hex": hex::encode(prefix),
                "dh_hex": hex::encode(dh),
                "salt_hex": hex::encode(wrap_salt(&kdf_header.wrap_bundle_hash)),
                "info_hex": hex::encode(wrap_info(&prefix)),
                "okm_hex": hex::encode(okm),
                "k_wrap_hex": hex::encode(*keys.k_wrap),
                "k_nonce_hex": hex::encode(*keys.k_nonce),
                "wrap_nonce_a_hex": hex::encode(nonce_a),
                "wrap_nonce_b_hex": hex::encode(nonce_b),
            },
        }),
    );

    // 2. The LETTER: it opens, its PairInit and envelopes are the session's,
    // the route tags match and each message opens under the session root.
    let opened = match f.bob_ctx.open(&f.letter).unwrap() {
        Opened::Letter(opened) => opened,
        other => panic!("{other:?}"),
    };
    assert_eq!(opened.pair_init, f.init);
    assert_eq!(opened.pair_init_wire, f.init_wire);
    check_route_tags(&f.root, Ral1Kind::Letter, &opened.envelopes).unwrap();
    for (carried, spec) in opened.envelopes.iter().zip(&f.envelope_specs) {
        let key = message_key_at_index(
            &f.root,
            &f.init.initiator_address,
            &f.init.responder_address,
            Direction::InitiatorToResponder,
            spec.index,
        )
        .unwrap();
        let plain = open_indexed_message_with_key(
            &key,
            &f.init.initiator_address,
            &f.init.responder_address,
            Direction::InitiatorToResponder,
            &spec.message_id,
            &carried.envelope.message_ciphertext,
        )
        .unwrap();
        assert_eq!(plain, spec.plaintext);
    }
    assert!(check_route_tags(&[0x5a; 32], Ral1Kind::Letter, &opened.envelopes).is_err());
    let letter_dh = x25519_shared_checked(&f.letter_eph, &f.bob_bundle.x25519_pub).unwrap();
    check_vector(
        "ral1_letter_001.json",
        &json!({
            "id": "ral1_letter_001",
            "protocol_version": "rvn1",
            "deterministic": true,
            "description": "RAL1 kind 1 LETTER from Alice's device to Bob's: a letter-shaped PairInit V1 and two RVNA1 0x03 messages (indices 0 and 1) of its session, wrapped to Bob's signed prekey and signed by Alice's device.",
            "derivation": [
                "Bob's bundle: the bundle of atsam/pair_init_v1_001.json (x25519_pub and mlkem768_ek of its PairInit) re-issued without the one-time prekey (one_time_prekey_id 0) and signed by the responder identity seed.",
                "PairInit: the PairInit of atsam/pair_init_v1_001.json with one_time_prekey_id 0, the one-time key slot all-zero, responder_prekey_bundle_hash of that bundle and expires_at_ms below, signed by the sender device.",
                "z_x = X25519(initiator ephemeral secret, responder signed prekey); z_pq from atsam/mlkem768_hybrid_kat_001.json; root = derive_provisional_root(z_x, z_pq, PairInit).",
                "Each envelope: RVNA1 0x03 sealed under message_key_at_index(root, direction 0, index) with seal_nonce, route tag derive_route_tag(root, created_at_ms, index, 1, 0), dest_device_hint 0, hop_limit 8, replication_budget 2, signed by the sender device.",
                "Letter: seal(kind 1) with wrap_ephemeral_secret to Bob's signed prekey; then the recipient context opens it."
            ],
            "inputs": {
                "source_vector": "atsam/pair_init_v1_001.json",
                "hybrid_source_vector": "atsam/mlkem768_hybrid_kat_001.json",
                "sender_device_seed_hex": hex::encode(pattern::<32>(0)),
                "recipient_device_seed_hex": hex::encode(pattern::<32>(32)),
                "initiator_ephemeral_secret_hex": hex::encode(f.alice_ephemeral_secret),
                "responder_signed_prekey_secret_hex": hex::encode(f.bob_spk_secret),
                "responder_bundle": bundle_json(&f.bob_bundle, BOB_ED_PRIV),
                "pair_init": {
                    "one_time_prekey_id": f.init.one_time_prekey_id,
                    "expires_at_ms": f.init.expires_at_ms,
                },
                "envelopes": f.envelope_specs.iter().map(EnvelopeSpec::to_json).collect::<Vec<_>>(),
                "letter": {
                    "kind": 1,
                    "letter_id_hex": hex::encode(f.letter_id),
                    "created_at_ms": f.letter_created,
                    "expires_at_ms": f.letter_expires,
                    "wrap_ephemeral_secret_hex": hex::encode(f.letter_eph),
                },
                "recipient_context": f.bob_ctx.to_json(),
            },
            "expected": {
                "source_bundle_hash_hex": hex::encode(f.source_bundle_hash),
                "responder_prekey_signature_hex": hex::encode(f.bob_bundle.signature),
                "responder_prekey_bundle_hash_hex": hex::encode(f.bob_bundle_hash),
                "pair_init_wire_hex": hex::encode(&f.init_wire),
                "pair_init_hash_hex": hex::encode(init_hash(&f.init).unwrap()),
                "session_id_hex": hex::encode(session_id(&f.init).unwrap()),
                "z_x_hex": hex::encode(f.z_x),
                "z_pq_hex": hex::encode(f.z_pq),
                "provisional_k_root_hex": hex::encode(f.root),
                "envelopes_hex": f.letter_inner.envelopes.iter().map(hex::encode).collect::<Vec<_>>(),
                "inner_hex": hex::encode(&f.letter_inner_bytes),
                "inner_len": f.letter_inner_bytes.len(),
                "wrap_ephemeral_pub_hex": hex::encode(x25519_pub(&f.letter_eph)),
                "dh_hex": hex::encode(letter_dh),
                "letter": letter_parts(&f.letter, &letter_dh),
            },
        }),
    );

    // 3. The REPLY: it opens, the PairResponse confirms the session and the
    // ACK opens under the root.
    let opened = match f.alice_ctx.open(&f.reply).unwrap() {
        Opened::Reply(opened) => opened,
        other => panic!("{other:?}"),
    };
    assert_eq!(opened.pair_response, f.response);
    verify_response(&opened.pair_response, &f.init, &f.root, f.alice_ctx.now_ms).unwrap();
    check_route_tags(&f.root, Ral1Kind::Reply, &opened.acks).unwrap();
    assert_eq!(opened.acks[0].envelope, f.ack_envelope);
    let ack_plain = open_ack(
        &f.root,
        &f.init.initiator_address,
        &f.init.responder_address,
        Direction::ResponderToInitiator,
        &f.ack_outer_id,
        &opened.acks[0].envelope.message_ciphertext,
    )
    .unwrap();
    assert_eq!(ack_plain, f.ack_plaintext);
    assert_eq!(decode_signed_ack(&ack_plain).unwrap().record, f.ack_record);
    let reply_dh = x25519_shared_checked(&f.reply_eph, &f.alice_bundle.x25519_pub).unwrap();
    check_vector(
        "ral1_reply_001.json",
        &json!({
            "id": "ral1_reply_001",
            "protocol_version": "rvn1",
            "deterministic": true,
            "description": "RAL1 kind 2 REPLY from Bob's device to Alice's: the PairResponse confirming the session of ral1_letter_001 and one sealed ACK (index 0, direction 1) for its message 0, wrapped to Alice's signed prekey and signed by Bob's device.",
            "derivation": [
                "Session: the PairInit and provisional root of letter/ral1_letter_001.json.",
                "PairResponse: init_id and init_hash of that PairInit, responder Bob's device, created_at_ms below, expires_at_ms of the PairInit, confirmation_tag(root, init_hash), signed by Bob's device.",
                "ACK: the signed ACK record (rvn1/ack, signed by Bob's device) sealed with seal_ack(root, direction 1, index 0, ack_outer_message_id, ack_seal_nonce); route tag derive_route_tag(root, created_at_ms, 0, 2, 1); dest_device_hint 0, hop_limit 8, replication_budget 2; envelope signed by Bob's device.",
                "Alice's bundle: x25519_pub of the signed prekey secret below, mlkem768_ek of the source PairInit, signed by the identity seed below."
            ],
            "inputs": {
                "letter_vector": "letter/ral1_letter_001.json",
                "sender_device_seed_hex": hex::encode(pattern::<32>(32)),
                "initiator_signed_prekey_secret_hex": hex::encode(f.alice_spk_secret),
                "initiator_bundle": bundle_json(&f.alice_bundle, ALICE_ED_PRIV),
                "pair_response_created_at_ms": f.response.created_at_ms,
                "ack": {
                    "acked_message_id_hex": hex::encode(f.ack_record.acked_message_id),
                    "status": f.ack_record.status,
                    "ack_nonce_hex": hex::encode(f.ack_record.ack_nonce),
                    "created_at_ms": f.ack_record.created_at,
                    "index": 0,
                    "outer_message_id_hex": hex::encode(f.ack_outer_id),
                    "seal_nonce_hex": hex::encode(f.ack_seal_nonce),
                    "anti_replay_nonce_hex": hex::encode(f.ack_anti_replay),
                    "expires_at_ms": f.reply_expires,
                },
                "letter": {
                    "kind": 2,
                    "letter_id_hex": hex::encode(f.reply_id),
                    "created_at_ms": f.reply_created,
                    "expires_at_ms": f.reply_expires,
                    "wrap_ephemeral_secret_hex": hex::encode(f.reply_eph),
                },
                "recipient_context": f.alice_ctx.to_json(),
            },
            "expected": {
                "initiator_prekey_signature_hex": hex::encode(f.alice_bundle.signature),
                "initiator_prekey_bundle_hash_hex": hex::encode(f.alice_bundle_hash),
                "pair_response_wire_hex": hex::encode(&f.response_wire),
                "confirmation_tag_hex": hex::encode(f.response.confirmation_tag),
                "ack_plaintext_hex": hex::encode(f.ack_plaintext),
                "ack_envelope_hex": hex::encode(f.ack_envelope.pack()),
                "inner_hex": hex::encode(&f.reply_inner_bytes),
                "inner_len": f.reply_inner_bytes.len(),
                "wrap_ephemeral_pub_hex": hex::encode(x25519_pub(&f.reply_eph)),
                "dh_hex": hex::encode(reply_dh),
                "letter": letter_parts(&f.reply, &reply_dh),
            },
        }),
    );
}

/// An inner built byte by byte, for the negatives the encoder refuses.
fn raw_inner(pair_kind: u8, pair: &[u8], items: &[Vec<u8>], extra_pad: usize) -> Vec<u8> {
    let mut out = vec![INNER_VERSION, pair_kind];
    out.extend_from_slice(&(pair.len() as u16).to_be_bytes());
    out.extend_from_slice(pair);
    out.push(items.len() as u8);
    for item in items {
        out.extend_from_slice(&(item.len() as u32).to_be_bytes());
        out.extend_from_slice(item);
    }
    let unpadded = out.len() + 2;
    let pad = (PAD_BLOCK - unpadded % PAD_BLOCK) % PAD_BLOCK + extra_pad;
    out.extend_from_slice(&(pad as u16).to_be_bytes());
    out.resize(unpadded + pad, 0);
    out
}

/// Seals without the sender-side lifetime rule, for negatives.
#[allow(clippy::too_many_arguments)]
fn seal_raw(
    sender: &Identity,
    eph: &[u8; 32],
    kind: Ral1Kind,
    letter_id: [u8; 16],
    recipient: [u8; 32],
    (created, expires): (u64, u64),
    (bundle_hash, spk_pub): ([u8; 32], [u8; 32]),
    inner: &[u8],
) -> Vec<u8> {
    seal_unchecked_lifetime(
        sender,
        eph,
        &SealInput {
            kind,
            letter_id,
            recipient_device: recipient,
            created_at_ms: created,
            expires_at_ms: expires,
            wrap_bundle_hash: bundle_hash,
            recipient_signed_prekey: spk_pub,
            inner,
        },
    )
    .unwrap()
}

fn resign(bytes: &mut [u8], signer: &Identity) {
    let split = bytes.len() - SIGNATURE_LEN;
    let signature = signer.sign(&signing_bytes(&bytes[..split]));
    bytes[split..].copy_from_slice(&signature);
}

struct Negative {
    name: &'static str,
    context: &'static str,
    now_ms: Option<u64>,
    letter: Vec<u8>,
    expected: Ral1Error,
}

fn negatives(f: &Fixture) -> Vec<Negative> {
    let alice = &f.alice_device;
    let bob_pub = f.bob_device.public_key_bytes();
    let alice_pub = alice.public_key_bytes();
    let times = (f.letter_created, f.letter_expires);
    let wrap = (f.bob_bundle_hash, f.bob_bundle.x25519_pub);
    let letter_with = |sender: &Identity, eph: &[u8; 32], times, wrap, inner: &[u8]| {
        seal_raw(
            sender,
            eph,
            Ral1Kind::Letter,
            f.letter_id,
            bob_pub,
            times,
            wrap,
            inner,
        )
    };
    let inner_of = |items: Vec<Vec<u8>>| raw_inner(PAIR_KIND_INIT_V1, &f.init_wire, &items, 0);
    let mutate = |at: usize, value: u8| {
        let mut bytes = f.letter.clone();
        bytes[at] = value;
        bytes
    };
    let packed = &f.letter_inner.envelopes;
    let mut cases = Vec::new();
    let mut add = |name, context, now_ms, letter, expected| {
        cases.push(Negative {
            name,
            context,
            now_ms,
            letter,
            expected,
        })
    };
    use Ral1Error::*;

    // Step 1: strict decode.
    add("bad_magic", "bob", None, mutate(0, b'r'), Malformed);
    add("version_2", "bob", None, mutate(4, 2), Malformed);
    add("kind_3", "bob", None, mutate(5, 3), Malformed);
    add("flags_nonzero", "bob", None, mutate(7, 1), Malformed);
    let mut ct_len = f.letter.clone();
    let claimed = u32::from_be_bytes(ct_len[180..184].try_into().unwrap()) + PAD_BLOCK as u32;
    ct_len[180..184].copy_from_slice(&claimed.to_be_bytes());
    add("ct_len_mismatch", "bob", None, ct_len, Malformed);
    let mut trailing = f.letter.clone();
    trailing.push(0);
    add("trailing_byte", "bob", None, trailing, Malformed);
    add(
        "truncated",
        "bob",
        None,
        f.letter[..f.letter.len() - 1].to_vec(),
        Malformed,
    );
    // ct_len and the total length agree, but the inner is over 65,024.
    let mut oversize = f.letter[..HEADER_LEN].to_vec();
    let big_ct = (MAX_RAL1_INNER + PAD_BLOCK + TAG_LEN) as u32;
    oversize[180..184].copy_from_slice(&big_ct.to_be_bytes());
    oversize.resize(HEADER_LEN + big_ct as usize + SIGNATURE_LEN, 0);
    add("oversize", "bob", None, oversize, Malformed);
    let mut zero_id = f.letter.clone();
    zero_id[8..24].fill(0);
    add("zero_letter_id", "bob", None, zero_id, Malformed);
    let mut small_order = f.letter.clone();
    small_order[136..168].copy_from_slice(&pattern_point_one());
    add(
        "small_order_wrap_ephemeral",
        "bob",
        None,
        small_order,
        Malformed,
    );

    // Steps 2-6.
    add(
        "wrong_recipient",
        "bob",
        None,
        seal_raw(
            alice,
            &f.letter_eph,
            Ral1Kind::Letter,
            f.letter_id,
            f.carol_device.public_key_bytes(),
            times,
            wrap,
            &f.letter_inner_bytes,
        ),
        WrongRecipient,
    );
    add(
        "expired",
        "bob",
        Some(f.letter_expires),
        f.letter.clone(),
        Expired,
    );
    add(
        "future_dated",
        "bob",
        Some(f.letter_created - MAX_LETTER_FUTURE_SKEW_MS - 1),
        f.letter.clone(),
        Time,
    );
    add(
        "lifetime_over_7_days",
        "bob",
        None,
        letter_with(
            alice,
            &f.letter_eph,
            (
                f.letter_created,
                f.letter_created + MAX_LETTER_LIFETIME_MS + 1,
            ),
            wrap,
            &f.letter_inner_bytes,
        ),
        Time,
    );
    add(
        "not_a_contact",
        "bob",
        None,
        letter_with(
            &f.dave_device,
            &f.letter_eph,
            times,
            wrap,
            &f.letter_inner_bytes,
        ),
        NotContact,
    );
    add(
        "bad_signature",
        "bob",
        None,
        mutate(f.letter.len() - 1, f.letter[f.letter.len() - 1] ^ 1),
        BadSignature,
    );
    add(
        "unknown_prekey",
        "bob",
        None,
        letter_with(
            alice,
            &f.letter_eph,
            times,
            ([0x99; 32], f.bob_bundle.x25519_pub),
            &f.letter_inner_bytes,
        ),
        UnknownPrekey,
    );

    // Step 7: the header and the ciphertext are bound by the AEAD.
    let mut header_tamper = mutate(8, f.letter[8] ^ 1);
    resign(&mut header_tamper, alice);
    add("header_tamper", "bob", None, header_tamper, Unwrap);
    let mut ct_tamper = mutate(HEADER_LEN + 3, f.letter[HEADER_LEN + 3] ^ 1);
    resign(&mut ct_tamper, alice);
    add("ciphertext_tamper", "bob", None, ct_tamper, Unwrap);

    // Step 8: the inner.
    let mut nonzero_pad = f.letter_inner_bytes.clone();
    *nonzero_pad.last_mut().unwrap() = 1;
    let sealed = |inner: &[u8]| letter_with(alice, &f.letter_eph, times, wrap, inner);
    add("nonzero_padding", "bob", None, sealed(&nonzero_pad), Inner);
    add(
        "padding_not_minimal",
        "bob",
        None,
        sealed(&raw_inner(
            PAIR_KIND_INIT_V1,
            &f.init_wire,
            packed,
            PAD_BLOCK,
        )),
        Inner,
    );
    add("count_0", "bob", None, sealed(&inner_of(vec![])), Inner);
    add(
        "count_17",
        "bob",
        None,
        sealed(&inner_of(vec![packed[0].clone(); 17])),
        Inner,
    );
    add(
        "ack_in_letter",
        "bob",
        None,
        sealed(&inner_of(vec![packed[0].clone(), f.ack_envelope.pack()])),
        Inner,
    );
    let mut not_0x03 = f.envelopes[0].clone();
    not_0x03.message_ciphertext[8] = 0x02;
    not_0x03.sign_with(alice);
    add(
        "non_0x03_envelope",
        "bob",
        None,
        sealed(&inner_of(vec![not_0x03.pack(), packed[1].clone()])),
        Inner,
    );
    add(
        "reserved_pair_kind_3",
        "bob",
        None,
        sealed(&raw_inner(
            PAIR_KIND_INIT_V3_RESERVED,
            &f.init_wire,
            packed,
            0,
        )),
        Inner,
    );

    // Step 9: the bindings.
    add(
        "signer_differs_from_pairinit_initiator",
        "bob",
        None,
        letter_with(
            &f.carol_device,
            &f.letter_eph,
            times,
            wrap,
            &f.letter_inner_bytes,
        ),
        Binding,
    );
    add(
        "bundle_hash_mismatch",
        "bob",
        None,
        letter_with(
            alice,
            &f.letter_eph,
            times,
            (f.source_bundle_hash, f.bob_bundle.x25519_pub),
            &f.letter_inner_bytes,
        ),
        Binding,
    );
    // The source PairInit of atsam/pair_init_v1_001.json uses one-time
    // prekey 7 (its bundle is retained too); the letter nests in its 24 h.
    add(
        "one_time_prekey_nonzero",
        "bob",
        None,
        letter_with(
            alice,
            &f.letter_eph,
            (f.letter_created, EPOCH_MS + 20 * 60 * 60 * 1000),
            (f.source_bundle_hash, f.bob_bundle.x25519_pub),
            &raw_inner(
                PAIR_KIND_INIT_V1,
                &encode_init(&f.source_init).unwrap(),
                packed,
                0,
            ),
        ),
        Binding,
    );
    add(
        "wrap_ephemeral_equals_pairinit_ephemeral",
        "bob",
        None,
        letter_with(
            alice,
            &f.alice_ephemeral_secret,
            times,
            wrap,
            &f.letter_inner_bytes,
        ),
        Binding,
    );
    add(
        "letter_starts_before_pairinit",
        "bob",
        None,
        letter_with(
            alice,
            &f.letter_eph,
            (f.init.created_at_ms - 1_000, f.letter_expires),
            wrap,
            &f.letter_inner_bytes,
        ),
        Binding,
    );
    add(
        "envelope_outlives_letter",
        "bob",
        None,
        letter_with(
            alice,
            &f.letter_eph,
            (f.letter_created, f.envelopes[0].expires_at - 1),
            wrap,
            &f.letter_inner_bytes,
        ),
        Binding,
    );
    let mut foreign = f.envelopes[0].clone();
    foreign.sign_with(&f.carol_device);
    add(
        "envelope_signer_mismatch",
        "bob",
        None,
        sealed(&inner_of(vec![foreign.pack(), packed[1].clone()])),
        Binding,
    );

    // REPLY cases, opened by Alice.
    let reply_with = |sender: &Identity, inner: &[u8]| {
        seal_raw(
            sender,
            &f.reply_eph,
            Ral1Kind::Reply,
            f.reply_id,
            alice_pub,
            (f.reply_created, f.reply_expires),
            (f.alice_bundle_hash, f.alice_bundle.x25519_pub),
            inner,
        )
    };
    add(
        "reply_with_pair_kind_1",
        "alice",
        None,
        reply_with(&f.bob_device, &f.letter_inner_bytes),
        Inner,
    );
    add(
        "reply_responder_mismatch",
        "alice",
        None,
        reply_with(&f.carol_device, &f.reply_inner_bytes),
        Binding,
    );
    cases
}

/// u = 1: a small-order X25519 point other than zero.
fn pattern_point_one() -> [u8; 32] {
    let mut point = [0u8; 32];
    point[0] = 1;
    point
}

/// Every listed negative maps to its stable code; the file under
/// `letter/negative/` holds them all with the two recipient contexts.
#[test]
fn ral1_negative_vectors() {
    let f = fixture();
    let cases = negatives(&f);
    let mut seen = std::collections::BTreeSet::new();
    let mut json_cases = Vec::new();
    for case in &cases {
        let ctx = match case.context {
            "bob" => &f.bob_ctx,
            _ => &f.alice_ctx,
        };
        let now = case.now_ms.unwrap_or(ctx.now_ms);
        assert_eq!(
            ctx.open_at(&case.letter, now).map(|_| ()),
            Err(case.expected),
            "{}",
            case.name
        );
        seen.insert(case.expected.code());
        json_cases.push(json!({
            "name": case.name,
            "context": case.context,
            "now_ms": now,
            "letter_hex": hex::encode(&case.letter),
            "expected_code": case.expected.code(),
        }));
    }
    // Every refusal of steps 1-9 has at least one vector.
    for error in &Ral1Error::ALL[..10] {
        assert!(seen.contains(error.code()), "{}", error.code());
    }
    check_vector(
        "negative/ral1_negatives_001.json",
        &json!({
            "id": "ral1_negatives_001",
            "protocol_version": "rvn1",
            "deterministic": true,
            "description": "RAL1 letters every recipient refuses, each with the stable code of the first failing check of the verification order (RAVEN_ASYNC_LETTER_V1.md §6). Built from the fixture of ral1_letter_001 and ral1_reply_001. A context's contacts are device keys; each prekey maps a retained bundle hash to its signed-prekey secret.",
            "contexts": {
                "bob": f.bob_ctx.to_json(),
                "alice": f.alice_ctx.to_json(),
            },
            "cases": json_cases,
        }),
    );
}

fn random_envelope(rng: &mut impl RngCore, kind: Ral1Kind, signer: &Identity) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&SEAL_MAGIC_RVNA1);
    body.extend_from_slice(&[RVNA1_PROTO, RVNA1_SUITE]);
    let len = match kind {
        Ral1Kind::Letter => INDEXED_SEALED_MIN_WIRE_LEN + (rng.next_u32() % 900) as usize,
        Ral1Kind::Reply => ACK_SEALED_WIRE_LEN,
    };
    while body.len() < len {
        body.push(rng.next_u32() as u8);
    }
    let created = EPOCH_MS + u64::from(rng.next_u32());
    let mut envelope = Envelope {
        env_type: match kind {
            Ral1Kind::Letter => EnvType::Message as u8,
            Ral1Kind::Reply => EnvType::Ack as u8,
        },
        flags: 0,
        message_id: rng.gen(),
        routing_tag: rng.gen(),
        dest_device_hint: rng.gen(),
        created_at: created,
        expires_at: created + 1 + u64::from(rng.next_u32()),
        hop_limit: rng.gen(),
        replication_budget: rng.gen(),
        anti_replay_nonce: rng.gen(),
        ratchet_header_ciphertext: Vec::new(),
        message_ciphertext: body,
        sender_authentication: vec![0; 64],
    };
    envelope.sign_with(signer);
    envelope.pack()
}

/// Random letters and inners round-trip exactly; a random byte flip either
/// fails strictly or decodes to bytes that re-encode identically.
#[test]
fn decode_encode_roundtrip_property() {
    let f = fixture();
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x5241_4c31);
    for round in 0..64 {
        let kind = if round % 2 == 0 {
            Ral1Kind::Letter
        } else {
            Ral1Kind::Reply
        };
        let count = match kind {
            Ral1Kind::Letter => 1 + rng.gen_range(0..MAX_LETTER_ENVELOPES),
            Ral1Kind::Reply => rng.gen_range(0..=MAX_REPLY_ACKS),
        };
        let items: Vec<Vec<u8>> = (0..count)
            .map(|_| random_envelope(&mut rng, kind, &f.alice_device))
            .collect();
        let inner = match kind {
            Ral1Kind::Letter => encode_letter_inner(&LetterInner {
                pair_init: f.init_wire.clone(),
                envelopes: items.clone(),
            }),
            Ral1Kind::Reply => encode_reply_inner(&ReplyInner {
                pair_response: f.response_wire.clone(),
                acks: items.clone(),
            }),
        };
        let inner = match inner {
            Ok(inner) => inner,
            Err(error) => {
                // Over the cap: refused as a whole, never truncated.
                assert_eq!(error, Ral1Error::TooLarge);
                continue;
            }
        };
        assert!(inner.len().is_multiple_of(PAD_BLOCK));
        let decoded = decode_inner(kind, &inner).unwrap();
        let again = match &decoded {
            Ral1Inner::Letter(value) => {
                assert_eq!(value.envelopes, items);
                encode_letter_inner(value).unwrap()
            }
            Ral1Inner::Reply(value) => {
                assert_eq!(value.acks, items);
                encode_reply_inner(value).unwrap()
            }
        };
        assert_eq!(again, inner);
        let letter = seal(
            &f.alice_device,
            &rng.gen(),
            &SealInput {
                kind,
                letter_id: rng.gen(),
                recipient_device: f.bob_device.public_key_bytes(),
                created_at_ms: EPOCH_MS,
                expires_at_ms: EPOCH_MS + 1 + rng.gen_range(0..MAX_LETTER_LIFETIME_MS),
                wrap_bundle_hash: rng.gen(),
                recipient_signed_prekey: f.bob_bundle.x25519_pub,
                inner: &inner,
            },
        )
        .unwrap();
        let decoded = decode(&letter).unwrap();
        assert_eq!(decoded.encode(), letter);
        assert_eq!(
            decoded.header.ct_len as usize,
            inner.len() + TAG_LEN,
            "ct_len"
        );
        for _ in 0..16 {
            let mut flipped = letter.clone();
            let at = rng.gen_range(0..flipped.len());
            flipped[at] ^= 1 << rng.gen_range(0..8);
            if let Ok(value) = decode(&flipped) {
                assert_eq!(value.encode(), flipped);
            }
            let mut inner_flipped = inner.clone();
            let at = rng.gen_range(0..inner_flipped.len());
            inner_flipped[at] ^= 1 << rng.gen_range(0..8);
            match decode_inner(kind, &inner_flipped) {
                Ok(Ral1Inner::Letter(value)) => {
                    assert_eq!(encode_letter_inner(&value).unwrap(), inner_flipped)
                }
                Ok(Ral1Inner::Reply(value)) => {
                    assert_eq!(encode_reply_inner(&value).unwrap(), inner_flipped)
                }
                Err(error) => assert_eq!(error, Ral1Error::Inner),
            }
        }
    }
    // Random bytes never decode, and every length is refused below the floor.
    for len in [0, 1, HEADER_LEN, MIN_RAL1_LEN - 1] {
        assert_eq!(decode(&vec![0; len]), Err(Ral1Error::Malformed));
    }
}

/// The nonce is derived from the plaintext: with the RNG replayed (the same
/// ephemeral and header), a different inner still gets a different nonce,
/// and the same inner gives the same letter.
#[test]
fn wrap_nonce_differs_for_different_inner_under_replayed_rng() {
    let f = fixture();
    let input = |inner| SealInput {
        kind: Ral1Kind::Letter,
        letter_id: f.letter_id,
        recipient_device: f.bob_device.public_key_bytes(),
        created_at_ms: f.letter_created,
        expires_at_ms: f.letter_expires,
        wrap_bundle_hash: f.bob_bundle_hash,
        recipient_signed_prekey: f.bob_bundle.x25519_pub,
        inner,
    };
    let other_inner = encode_letter_inner(&LetterInner {
        pair_init: f.init_wire.clone(),
        envelopes: vec![f.letter_inner.envelopes[1].clone()],
    })
    .unwrap();
    let a = seal(
        &f.alice_device,
        &f.letter_eph,
        &input(&f.letter_inner_bytes),
    )
    .unwrap();
    let b = seal(&f.alice_device, &f.letter_eph, &input(&other_inner)).unwrap();
    let (ha, hb) = (decode(&a).unwrap().header, decode(&b).unwrap().header);
    assert_eq!(ha.wrap_ephemeral, hb.wrap_ephemeral);
    assert_eq!(ha.prefix_bytes(), hb.prefix_bytes());
    assert_ne!(ha.wrap_nonce, hb.wrap_nonce);
    assert_eq!(a, f.letter, "the same inputs give the same letter");
    // One flipped bit of the inner changes the nonce too.
    let mut flipped = f.letter_inner_bytes.clone();
    *flipped.last_mut().unwrap() ^= 1;
    let dh = x25519_shared_checked(&f.letter_eph, &f.bob_bundle.x25519_pub).unwrap();
    let keys = wrap_keys(&dh, &ha.prefix_bytes());
    assert_ne!(
        wrap_nonce(&keys.k_nonce, &flipped),
        wrap_nonce(&keys.k_nonce, &f.letter_inner_bytes)
    );
    assert_eq!(
        wrap_nonce(&keys.k_nonce, &f.letter_inner_bytes),
        ha.wrap_nonce
    );
}

/// Every inner is a multiple of 512 bytes; the smallest REPLY is
/// MIN_RAL1_LEN, the largest inner exactly MAX_RAL1_INNER, and nothing over
/// the caps is built or accepted.
#[test]
fn size_caps_and_padding_multiple_of_512() {
    let f = fixture();
    let empty_reply = encode_reply_inner(&ReplyInner {
        pair_response: f.response_wire.clone(),
        acks: vec![],
    })
    .unwrap();
    assert_eq!(empty_reply.len(), MIN_RAL1_INNER);
    let reply = seal(
        &f.bob_device,
        &f.reply_eph,
        &SealInput {
            kind: Ral1Kind::Reply,
            letter_id: f.reply_id,
            recipient_device: f.alice_device.public_key_bytes(),
            created_at_ms: f.reply_created,
            expires_at_ms: f.reply_expires,
            wrap_bundle_hash: f.alice_bundle_hash,
            recipient_signed_prekey: f.alice_bundle.x25519_pub,
            inner: &empty_reply,
        },
    )
    .unwrap();
    assert_eq!(reply.len(), MIN_RAL1_LEN);
    assert!(matches!(f.alice_ctx.open(&reply), Ok(Opened::Reply(r)) if r.acks.is_empty()));

    // One envelope whose sealed body grows a byte at a time: the inner stays
    // a multiple of 512 up to the cap, and one byte more is refused.
    let fixed = 4 + INIT_WIRE_LEN + 1 + 4 + 2;
    let body_for = |envelope_len: usize| {
        let mut env = f.envelopes[0].clone();
        let body_len = envelope_len - ENVELOPE_PREFIX_LEN - SIGNATURE_LEN;
        env.message_ciphertext.resize(body_len, 0x5a);
        env.sign_with(&f.alice_device);
        env.pack()
    };
    let largest = MAX_RAL1_INNER - fixed;
    for envelope_len in [largest - 511, largest - 300, largest - 1, largest] {
        let inner = encode_letter_inner(&LetterInner {
            pair_init: f.init_wire.clone(),
            envelopes: vec![body_for(envelope_len)],
        })
        .unwrap();
        assert!(inner.len().is_multiple_of(PAD_BLOCK));
        assert_eq!(inner.len(), MAX_RAL1_INNER);
        assert!(decode_inner(Ral1Kind::Letter, &inner).is_ok());
    }
    let over = LetterInner {
        pair_init: f.init_wire.clone(),
        envelopes: vec![body_for(largest + 1)],
    };
    assert_eq!(encode_letter_inner(&over), Err(Ral1Error::TooLarge));
    for len in (200..2_000).step_by(37) {
        let inner = encode_letter_inner(&LetterInner {
            pair_init: f.init_wire.clone(),
            envelopes: vec![body_for(len)],
        })
        .unwrap();
        assert!(inner.len().is_multiple_of(PAD_BLOCK), "{len}");
        assert!(inner.len() - (fixed + len) < PAD_BLOCK, "smallest padding");
    }
    let max_inner = encode_letter_inner(&LetterInner {
        pair_init: f.init_wire.clone(),
        envelopes: vec![body_for(largest)],
    })
    .unwrap();
    let max_letter = seal(
        &f.alice_device,
        &f.letter_eph,
        &SealInput {
            kind: Ral1Kind::Letter,
            letter_id: f.letter_id,
            recipient_device: f.bob_device.public_key_bytes(),
            created_at_ms: f.letter_created,
            expires_at_ms: f.letter_expires,
            wrap_bundle_hash: f.bob_bundle_hash,
            recipient_signed_prekey: f.bob_bundle.x25519_pub,
            inner: &max_inner,
        },
    )
    .unwrap();
    assert_eq!(max_letter.len(), MAX_RAL1_LEN);
    assert!(decode(&max_letter).is_ok());

    // Seal refuses an inner over the cap, an unpadded inner and a lifetime
    // over 7 days.
    let mut too_big = max_inner.clone();
    too_big.resize(MAX_RAL1_INNER + PAD_BLOCK, 0);
    let seal_inner = |inner: &[u8], expires| {
        seal(
            &f.alice_device,
            &f.letter_eph,
            &SealInput {
                kind: Ral1Kind::Letter,
                letter_id: f.letter_id,
                recipient_device: f.bob_device.public_key_bytes(),
                created_at_ms: f.letter_created,
                expires_at_ms: expires,
                wrap_bundle_hash: f.bob_bundle_hash,
                recipient_signed_prekey: f.bob_bundle.x25519_pub,
                inner,
            },
        )
    };
    assert_eq!(
        seal_inner(&too_big, f.letter_expires),
        Err(Ral1Error::TooLarge)
    );
    assert_eq!(
        seal_inner(&max_inner[..1000], f.letter_expires),
        Err(Ral1Error::Inner)
    );
    assert_eq!(
        seal_inner(
            &f.letter_inner_bytes,
            f.letter_created + MAX_LETTER_LIFETIME_MS + 1
        ),
        Err(Ral1Error::Seal)
    );
    assert!(seal_inner(
        &f.letter_inner_bytes,
        f.letter_created + MAX_LETTER_LIFETIME_MS
    )
    .is_ok());

    // Count caps: 16 envelopes and 32 ACKs are the most.
    let envelopes = vec![f.letter_inner.envelopes[0].clone(); MAX_LETTER_ENVELOPES];
    assert!(encode_letter_inner(&LetterInner {
        pair_init: f.init_wire.clone(),
        envelopes: envelopes.clone(),
    })
    .is_ok());
    let mut seventeen = envelopes;
    seventeen.push(f.letter_inner.envelopes[0].clone());
    assert_eq!(
        encode_letter_inner(&LetterInner {
            pair_init: f.init_wire.clone(),
            envelopes: seventeen,
        }),
        Err(Ral1Error::Inner)
    );
    let acks = vec![f.ack_envelope.pack(); MAX_REPLY_ACKS];
    assert!(encode_reply_inner(&ReplyInner {
        pair_response: f.response_wire.clone(),
        acks: acks.clone(),
    })
    .is_ok());
    let mut thirty_three = acks;
    thirty_three.push(f.ack_envelope.pack());
    assert_eq!(
        encode_reply_inner(&ReplyInner {
            pair_response: f.response_wire.clone(),
            acks: thirty_three,
        }),
        Err(Ral1Error::Inner)
    );
    // A LETTER inner without envelopes is refused at encode too.
    assert_eq!(
        encode_letter_inner(&LetterInner {
            pair_init: f.init_wire.clone(),
            envelopes: vec![],
        }),
        Err(Ral1Error::Inner)
    );
}

/// No other Raven domain is a prefix of the RAL1 signing domain and the RAL1
/// domain is a prefix of none; a signature over the same bytes under another
/// domain, or none, never verifies as a letter.
#[test]
fn signing_domain_prefix_free() {
    let others: &[&[u8]] = &[
        b"",
        b"RVN1",
        b"rvn1/ack",
        b"rvn1/alias",
        b"rvn1/caps",
        crate::contact_request::CONTACT_ACCEPT_DOMAIN,
        crate::contact_request::CONTACT_ACCEPT_WIRE,
        crate::contact_request::CONTACT_REQ_DOMAIN,
        crate::contact_request::CONTACT_REQ_INNER,
        crate::contact_request::CONTACT_REQ_WIRE,
        b"rvn1/devcert",
        crate::device_revocation::SIGNING_DOMAIN,
        b"rvn1/devrevoke/v1",
        crate::discovery::ALIAS_HINT_DOMAIN,
        crate::discovery::PEER_DOMAIN,
        b"rvn1/internet-hello/v1",
        crate::introduction::INTRO_DOMAIN,
        b"rvn1/lan-noise-pin/v1",
        b"rvn1/lan-noise/v1",
        crate::pair_init::INIT_SIGNING_DOMAIN,
        crate::pair_init::RESPONSE_SIGNING_DOMAIN,
        crate::pair_init::DEVICE_CERT_HASH_DOMAIN,
        crate::pair_init::PREKEY_BUNDLE_HASH_DOMAIN,
        crate::pair_init::SESSION_ID_DOMAIN,
        crate::prekey_bundle::PREKEY_DOMAIN,
        crate::profile_record::PROFILE_DOMAIN,
        crate::routing_tag::LABEL,
        crate::store_object::CUSTODY_DOMAIN,
        crate::store_object::MAILBOX_LABEL,
        b"rvn1/session-reset/v1\0",
        b"rvn1/session-reset/v1",
        b"rvn1/async-letter/v1",
        SALT_LABEL,
        WRAP_LABEL,
        NONCE_LABEL,
        PAGE_TOKEN_DOMAIN,
        &crate::agent_sign::AGENT_DELEGATION_PREFIX,
    ];
    for other in &others[1..] {
        let label = String::from_utf8_lossy(other);
        assert!(!other.starts_with(SIGNING_DOMAIN), "RAL1 prefixes {label}");
        // The domain without its NUL is a prefix by construction (the reason
        // the NUL is there); nothing signs under it.
        if *other != b"rvn1/async-letter/v1" {
            assert!(
                !SIGNING_DOMAIN.starts_with(other),
                "{label} prefixes the RAL1 domain"
            );
        }
    }
    let f = fixture();
    let split = f.letter.len() - SIGNATURE_LEN;
    let unsigned = &f.letter[..split];
    // `Identity::sign` refuses the AgentSign prefix itself.
    for other in &others[..others.len() - 1] {
        let mut message = other.to_vec();
        message.extend_from_slice(unsigned);
        let mut forged = unsigned.to_vec();
        forged.extend_from_slice(&f.alice_device.sign(&message));
        assert_eq!(
            f.bob_ctx.open(&forged).map(|_| ()),
            Err(Ral1Error::BadSignature),
            "{}",
            String::from_utf8_lossy(other)
        );
    }
}

#[test]
fn codes_are_stable_and_disposition_follows_the_spec() {
    let codes: Vec<&str> = Ral1Error::ALL.iter().map(|e| e.code()).collect();
    assert_eq!(
        codes,
        [
            "LETTER_MALFORMED",
            "LETTER_WRONG_RECIPIENT",
            "LETTER_EXPIRED",
            "LETTER_TIME",
            "LETTER_NOT_CONTACT",
            "LETTER_BAD_SIGNATURE",
            "LETTER_UNKNOWN_PREKEY",
            "LETTER_UNWRAP",
            "LETTER_INNER",
            "LETTER_BINDING",
            "LETTER_PAIR_REFUSED",
            "LETTER_CLAIM_LIMIT",
            "LETTER_STORE",
            "LETTER_GATE",
            "LETTER_TOO_LARGE",
            "LETTER_SEAL",
        ]
    );
    for error in Ral1Error::ALL {
        assert_eq!(Ral1Error::from_code(error.code()), Some(error));
        assert_eq!(error.to_string(), error.code());
    }
    assert_eq!(Ral1Error::from_code("LETTER_NOPE"), None);
    let kept: Vec<_> = Ral1Error::ALL
        .into_iter()
        .filter(|e| !e.releases_letter())
        .collect();
    assert_eq!(
        kept,
        [
            Ral1Error::ClaimLimit,
            Ral1Error::Store,
            Ral1Error::TooLarge,
            Ral1Error::Seal
        ]
    );
}

/// Step 5 runs before step 6: a letter with a bad signature never reaches
/// the prekey lookup, and neither does one refused earlier.
#[test]
fn signature_is_checked_before_the_prekey_lookup() {
    let f = fixture();
    let calls = std::cell::Cell::new(0);
    let mut bad = f.letter.clone();
    *bad.last_mut().unwrap() ^= 1;
    for (bytes, contact) in [(&bad, true), (&f.letter, false)] {
        let result = open(
            bytes,
            &f.bob_ctx.local_device,
            f.bob_ctx.now_ms,
            |_| contact,
            |_| {
                calls.set(calls.get() + 1);
                Err(Ral1Error::UnknownPrekey)
            },
        );
        assert!(result.is_err());
    }
    assert_eq!(calls.get(), 0);
    let result = open(
        &f.letter,
        &f.bob_ctx.local_device,
        f.bob_ctx.now_ms,
        |_| true,
        |_| {
            calls.set(calls.get() + 1);
            wrap_dh_with_secret(
                &f.bob_spk_secret,
                &decode(&f.letter).unwrap().header.wrap_ephemeral,
            )
        },
    );
    assert!(matches!(result, Ok(Opened::Letter(_))));
    assert_eq!(calls.get(), 1);
}
