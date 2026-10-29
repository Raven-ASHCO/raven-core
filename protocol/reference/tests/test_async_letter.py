"""RAL1 (RAVEN Async Letter V1): every Rust-generated vector byte for byte."""

import dataclasses
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from raven_protocol import ack, async_letter as ral1, envelope, indexed_session, pair_init, prekey

ROOT = Path(__file__).resolve().parents[3] / "shared-vectors" / "rvn1"


def load(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text())


def h(value: str) -> bytes:
    return bytes.fromhex(value)


def ed_pub(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def ed_sign(seed: bytes, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def signed_bundle(spec: dict, x25519_pub: bytes, ek: bytes, one_time=(0, None)):
    bundle = prekey.PrekeyBundle(
        identity_ed25519_pub=ed_pub(h(spec["identity_seed_hex"])),
        device_id=spec["device_id"],
        x25519_pub=x25519_pub,
        mlkem768_ek=ek,
        signed_prekey_id=spec["signed_prekey_id"],
        one_time_prekey_id=one_time[0],
        one_time_x25519_pub=one_time[1],
        created_at_ms=spec["created_at_ms"],
        expires_at_ms=spec["expires_at_ms"],
    )
    assert bundle.identity_ed25519_pub.hex() == spec["identity_ed25519_pub_hex"]
    signing = prekey.signing_bytes(bundle)
    signature = ed_sign(h(spec["identity_seed_hex"]), signing)
    return signature, pair_init.prekey_bundle_hash(signing, signature)


def context_of(ctx: dict):
    prekeys = {h(p["bundle_hash_hex"]): h(p["signed_prekey_secret_hex"]) for p in ctx["prekeys"]}
    contacts = {h(c) for c in ctx["contacts_hex"]}

    def wrap_dh(header):
        secret = prekeys.get(header.wrap_bundle_hash)
        if secret is None:
            raise ral1.LetterError(ral1.UNKNOWN_PREKEY)
        return ral1.x25519_shared(secret, header.wrap_ephemeral)

    return h(ctx["local_device_hex"]), ctx["now_ms"], contacts.__contains__, wrap_dh


def open_in(ctx: dict, letter: bytes, now_ms: int | None = None):
    local, now, is_contact, wrap_dh = context_of(ctx)
    return ral1.open_letter(letter, local, now if now_ms is None else now_ms, is_contact, wrap_dh)


def check_letter_parts(expected: dict, letter: bytes, dh: bytes) -> None:
    assert letter.hex() == expected["letter_hex"]
    assert len(letter) == expected["letter_len"]
    header = ral1.decode_header(letter)
    okm = ral1.wrap_okm(dh, header.prefix_bytes())
    assert header.to_bytes().hex() == expected["header_hex"]
    assert okm[:32].hex() == expected["k_wrap_hex"]
    assert okm[32:].hex() == expected["k_nonce_hex"]
    assert header.wrap_nonce.hex() == expected["wrap_nonce_hex"]
    split = len(letter) - ral1.SIGNATURE_LEN
    assert letter[ral1.HEADER_LEN:split].hex() == expected["ciphertext_hex"]
    assert letter[split:].hex() == expected["signature_hex"]
    assert ral1.letter_digest(letter).hex() == expected["letter_digest_hex"]
    assert ral1.page_token(letter).hex() == expected["page_token_hex"]


def session_envelope(pair, root: bytes, spec: dict, signer_seed: bytes) -> bytes:
    index = spec["index"]
    message_id = h(spec["message_id_hex"])
    nonce = h(spec["seal_nonce_hex"])
    key = indexed_session.message_key_at_index(
        root, pair.initiator_address, pair.responder_address, 0, index
    )
    aad = indexed_session.build_aad(index, pair.initiator_address, pair.responder_address, message_id)
    sealed = (
        indexed_session.RVNA1_MAGIC
        + bytes([indexed_session.RVNA1_PROTO, indexed_session.RVNA1_SUITE])
        + index.to_bytes(4, "big")
        + nonce
        + ChaCha20Poly1305(key).encrypt(nonce, h(spec["plaintext_hex"]), aad)
    )
    return packed_signed(
        ral1.ENV_TYPE_MESSAGE,
        message_id,
        indexed_session.derive_route_tag(root, spec["created_at_ms"], index, 1, 0),
        spec["created_at_ms"],
        spec["expires_at_ms"],
        h(spec["anti_replay_nonce_hex"]),
        sealed,
        signer_seed,
    )


def packed_signed(env_type, message_id, tag, created, expires, nonce, body, seed) -> bytes:
    env = envelope.Envelope(
        env_type, 0, message_id, tag, 0, created, expires, 8, 2, nonce, b"", body, b""
    )
    env.sender_authentication = ed_sign(seed, envelope.signing_bytes(env))
    return envelope.pack(env)


@pytest.fixture(scope="module")
def letter_kat():
    return load("letter/ral1_letter_001.json")


@pytest.fixture(scope="module")
def session(letter_kat):
    """The letter session of ral1_letter_001, rebuilt from its inputs."""
    inputs, expected = letter_kat["inputs"], letter_kat["expected"]
    source = pair_init.decode_init(
        h(load(inputs["source_vector"])["expected"]["pair_init_wire_hex"])
    )
    hybrid = load(inputs["hybrid_source_vector"])
    spk_secret = h(inputs["responder_signed_prekey_secret_hex"])
    assert ral1.x25519_public(spk_secret) == source.responder_signed_x25519_pub
    bundle = inputs["responder_bundle"]
    assert bundle["x25519_pub_hex"] == source.responder_signed_x25519_pub.hex()
    ek = source.responder_mlkem768_ek
    _, source_hash = signed_bundle(
        bundle,
        source.responder_signed_x25519_pub,
        ek,
        (source.one_time_prekey_id, source.responder_one_time_x25519_pub),
    )
    assert source_hash == source.responder_prekey_bundle_hash
    assert source_hash.hex() == expected["source_bundle_hash_hex"]
    signature, bundle_hash = signed_bundle(bundle, source.responder_signed_x25519_pub, ek)
    assert signature.hex() == expected["responder_prekey_signature_hex"]
    assert bundle_hash.hex() == expected["responder_prekey_bundle_hash_hex"]

    sender_seed = h(inputs["sender_device_seed_hex"])
    assert ed_pub(sender_seed) == source.initiator_device_ed_pub
    assert ed_pub(h(inputs["recipient_device_seed_hex"])) == source.responder_device_ed_pub
    pair = dataclasses.replace(
        source,
        one_time_prekey_id=inputs["pair_init"]["one_time_prekey_id"],
        responder_one_time_x25519_pub=bytes(32),
        responder_prekey_bundle_hash=bundle_hash,
        expires_at_ms=inputs["pair_init"]["expires_at_ms"],
        signature=b"",
    )
    pair.signature = ed_sign(sender_seed, pair_init.init_signing_bytes(pair))
    wire = pair_init.encode_init(pair)
    assert wire.hex() == expected["pair_init_wire_hex"]
    assert pair_init.init_hash(pair).hex() == expected["pair_init_hash_hex"]
    assert pair_init.session_id(pair).hex() == expected["session_id_hex"]

    eph_secret = h(inputs["initiator_ephemeral_secret_hex"])
    assert ral1.x25519_public(eph_secret) == pair.initiator_ephemeral_x25519_pub
    z_x = ral1.x25519_shared(eph_secret, pair.responder_signed_x25519_pub)
    z_pq = h(hybrid["expected"]["z_pq_hex"])
    assert z_x.hex() == expected["z_x_hex"]
    assert z_pq.hex() == expected["z_pq_hex"]
    root = pair_init.derive_provisional_root(z_x, z_pq, pair)
    assert root.hex() == expected["provisional_k_root_hex"]
    envelopes = [session_envelope(pair, root, spec, sender_seed) for spec in inputs["envelopes"]]
    assert [e.hex() for e in envelopes] == expected["envelopes_hex"]
    return {
        "pair": pair,
        "wire": wire,
        "root": root,
        "envelopes": envelopes,
        "bundle_hash": bundle_hash,
        "sender_seed": sender_seed,
        "recipient_seed": h(inputs["recipient_device_seed_hex"]),
    }


def test_wrap_kdf_vector():
    kat = load("letter/ral1_wrap_kdf_001.json")
    inputs, expected = kat["inputs"], kat["expected"]
    eph = h(inputs["wrap_ephemeral_secret_hex"])
    spk = h(inputs["recipient_signed_prekey_secret_hex"])
    header = ral1.Header(
        kind=inputs["kind"],
        letter_id=h(inputs["letter_id_hex"]),
        sender_device=h(inputs["sender_device_hex"]),
        recipient_device=h(inputs["recipient_device_hex"]),
        created_at_ms=inputs["created_at_ms"],
        expires_at_ms=inputs["expires_at_ms"],
        wrap_bundle_hash=h(inputs["wrap_bundle_hash_hex"]),
        wrap_ephemeral=ral1.x25519_public(eph),
        wrap_nonce=bytes(12),
        ct_len=0,
    )
    prefix = header.prefix_bytes()
    assert len(prefix) == ral1.HEADER_PREFIX_LEN
    assert header.wrap_ephemeral.hex() == expected["wrap_ephemeral_pub_hex"]
    assert ral1.x25519_public(spk).hex() == expected["recipient_signed_prekey_pub_hex"]
    assert prefix.hex() == expected["header_prefix_hex"]
    dh = ral1.x25519_shared(eph, ral1.x25519_public(spk))
    assert dh == ral1.x25519_shared(spk, header.wrap_ephemeral)
    assert dh.hex() == expected["dh_hex"]
    assert ral1.wrap_salt(header.wrap_bundle_hash).hex() == expected["salt_hex"]
    assert ral1.wrap_info(prefix).hex() == expected["info_hex"]
    okm = ral1.wrap_okm(dh, prefix)
    assert okm.hex() == expected["okm_hex"]
    assert okm[:32].hex() == expected["k_wrap_hex"]
    assert okm[32:].hex() == expected["k_nonce_hex"]
    nonce_a = ral1.wrap_nonce(okm[32:], h(inputs["inner_a_hex"]))
    nonce_b = ral1.wrap_nonce(okm[32:], h(inputs["inner_b_hex"]))
    assert nonce_a.hex() == expected["wrap_nonce_a_hex"]
    assert nonce_b.hex() == expected["wrap_nonce_b_hex"]
    assert nonce_a != nonce_b


def test_letter_vector(letter_kat, session):
    inputs, expected = letter_kat["inputs"], letter_kat["expected"]
    inner = ral1.encode_inner(ral1.KIND_LETTER, session["wire"], session["envelopes"])
    assert inner.hex() == expected["inner_hex"]
    assert len(inner) == expected["inner_len"] and len(inner) % ral1.PAD_BLOCK == 0
    spec = inputs["letter"]
    eph = h(spec["wrap_ephemeral_secret_hex"])
    spk_pub = session["pair"].responder_signed_x25519_pub
    letter = ral1.seal(
        session["sender_seed"],
        eph,
        kind=spec["kind"],
        letter_id=h(spec["letter_id_hex"]),
        recipient_device=session["pair"].responder_device_ed_pub,
        created_at_ms=spec["created_at_ms"],
        expires_at_ms=spec["expires_at_ms"],
        wrap_bundle_hash=session["bundle_hash"],
        recipient_signed_prekey=spk_pub,
        inner=inner,
    )
    assert ral1.x25519_public(eph).hex() == expected["wrap_ephemeral_pub_hex"]
    dh = ral1.x25519_shared(eph, spk_pub)
    assert dh.hex() == expected["dh_hex"]
    check_letter_parts(expected["letter"], letter, dh)
    header, opened_inner, init, envelopes = open_in(inputs["recipient_context"], letter)
    assert opened_inner == inner
    assert init == session["pair"]
    ral1.check_route_tags(session["root"], header.kind, envelopes)
    with pytest.raises(ral1.LetterError):
        ral1.check_route_tags(bytes([0x5A]) * 32, header.kind, envelopes)
    assert ral1.decode_inner(ral1.KIND_LETTER, inner) == (session["wire"], session["envelopes"])


def test_reply_vector(session):
    kat = load("letter/ral1_reply_001.json")
    inputs, expected = kat["inputs"], kat["expected"]
    pair, root = session["pair"], session["root"]
    bob_seed = h(inputs["sender_device_seed_hex"])
    assert bob_seed == session["recipient_seed"]
    alice_spk = h(inputs["initiator_signed_prekey_secret_hex"])
    alice_bundle = inputs["initiator_bundle"]
    assert alice_bundle["x25519_pub_hex"] == ral1.x25519_public(alice_spk).hex()
    signature, alice_hash = signed_bundle(
        alice_bundle, ral1.x25519_public(alice_spk), pair.responder_mlkem768_ek
    )
    assert signature.hex() == expected["initiator_prekey_signature_hex"]
    assert alice_hash.hex() == expected["initiator_prekey_bundle_hash_hex"]

    init_digest = pair_init.init_hash(pair)
    response = pair_init.PairResponse(
        init_id=pair.init_id,
        init_hash=init_digest,
        responder_device_ed_pub=ed_pub(bob_seed),
        created_at_ms=inputs["pair_response_created_at_ms"],
        expires_at_ms=pair.expires_at_ms,
        confirmation_tag=pair_init.confirmation_tag(root, init_digest),
    )
    response.signature = ed_sign(bob_seed, pair_init.response_signing_bytes(response))
    response_wire = pair_init.encode_response(response)
    assert response_wire.hex() == expected["pair_response_wire_hex"]
    assert response.confirmation_tag.hex() == expected["confirmation_tag_hex"]

    spec = inputs["ack"]
    record = ack.Ack(
        acked_message_id=h(spec["acked_message_id_hex"]),
        status=spec["status"],
        ack_nonce=h(spec["ack_nonce_hex"]),
        created_at=spec["created_at_ms"],
    )
    plaintext = indexed_session.encode_signed_ack(record, ed_sign(bob_seed, ack.signing_bytes(record)))
    assert plaintext.hex() == expected["ack_plaintext_hex"]
    outer_id = h(spec["outer_message_id_hex"])
    sealed = indexed_session.seal_ack(
        root,
        pair.initiator_address,
        pair.responder_address,
        1,
        spec["index"],
        outer_id,
        plaintext,
        h(spec["seal_nonce_hex"]),
    )
    ack_envelope = packed_signed(
        ral1.ENV_TYPE_ACK,
        outer_id,
        indexed_session.derive_route_tag(root, spec["created_at_ms"], spec["index"], 2, 1),
        spec["created_at_ms"],
        spec["expires_at_ms"],
        h(spec["anti_replay_nonce_hex"]),
        sealed,
        bob_seed,
    )
    assert ack_envelope.hex() == expected["ack_envelope_hex"]
    inner = ral1.encode_inner(ral1.KIND_REPLY, response_wire, [ack_envelope])
    assert inner.hex() == expected["inner_hex"]
    assert len(inner) == expected["inner_len"]

    letter_spec = inputs["letter"]
    eph = h(letter_spec["wrap_ephemeral_secret_hex"])
    letter = ral1.seal(
        bob_seed,
        eph,
        kind=letter_spec["kind"],
        letter_id=h(letter_spec["letter_id_hex"]),
        recipient_device=pair.initiator_device_ed_pub,
        created_at_ms=letter_spec["created_at_ms"],
        expires_at_ms=letter_spec["expires_at_ms"],
        wrap_bundle_hash=alice_hash,
        recipient_signed_prekey=ral1.x25519_public(alice_spk),
        inner=inner,
    )
    assert ral1.x25519_public(eph).hex() == expected["wrap_ephemeral_pub_hex"]
    dh = ral1.x25519_shared(eph, ral1.x25519_public(alice_spk))
    assert dh.hex() == expected["dh_hex"]
    check_letter_parts(expected["letter"], letter, dh)
    header, _, opened, acks = open_in(inputs["recipient_context"], letter)
    assert opened == response
    ral1.check_route_tags(root, header.kind, acks)
    assert indexed_session.open_ack(
        root, pair.initiator_address, pair.responder_address, 1, outer_id, acks[0].message_ciphertext
    ) == plaintext


def test_negative_vectors():
    kat = load("letter/negative/ral1_negatives_001.json")
    seen = set()
    for case in kat["cases"]:
        with pytest.raises(ral1.LetterError) as refused:
            open_in(kat["contexts"][case["context"]], h(case["letter_hex"]), case["now_ms"])
        assert refused.value.code == case["expected_code"], case["name"]
        seen.add(case["expected_code"])
    assert seen == {
        ral1.MALFORMED,
        ral1.WRONG_RECIPIENT,
        ral1.EXPIRED,
        ral1.TIME,
        ral1.NOT_CONTACT,
        ral1.BAD_SIGNATURE,
        ral1.UNKNOWN_PREKEY,
        ral1.UNWRAP,
        ral1.INNER,
        ral1.BINDING,
    }


def test_sizes_and_domains():
    assert ral1.MIN_RAL1_LEN == 776 and ral1.MAX_RAL1_LEN == 65_288
    assert ral1.MAX_RAL1_INNER % ral1.PAD_BLOCK == 0
    assert not ral1.PRODUCTION_ENABLED
    for other in (b"rvn1/ack", b"rvn1/alias", b"rvn1/pair-init", b"rvn1/session-reset/v1\x00"):
        assert not ral1.SIGNING_DOMAIN.startswith(other)
        assert not other.startswith(ral1.SIGNING_DOMAIN)
