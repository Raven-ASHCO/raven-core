"""RAVEN Link Knock V1 (RAVEN_LINK_KNOCK_V1.md, draft): the Python reference
checks every shared-vectors/rvn1/link/rlk1_* vector and the knock in
lan/noise_xx_handshake_003.json (written by Rust under
RAVEN_REGEN_SECURITY_VECTORS=1) against its own keys, tags, proofs, tables and
message 3 encoding. Noise itself (the ciphertexts of message 2 and 3) is
checked by Rust; here, what the knock adds."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from raven_protocol import lan_beacon as lb
from raven_protocol import link_knock as lk
from raven_protocol import link_padding as lp

REPO = Path(__file__).resolve().parents[3]
RVN1 = REPO / "shared-vectors/rvn1"
VEC = RVN1 / "link"
FILES = ("rlk1_tags_001.json",)
NEGATIVE = (
    "rlk1_replay_001.json",
    "rlk1_unmatched_m2_random_001.json",
    "rlk1_wrong_day_001.json",
    "rlk1_wrong_pair_001.json",
)


def load(name):
    return json.loads((VEC / name).read_text(encoding="utf-8"))


def x_pub(scalar: bytes) -> bytes:
    key = X25519PrivateKey.from_private_bytes(scalar).public_key()
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def people(vector):
    """name -> seed of a vector's inputs, its public key checked."""
    out = {}
    for name, person in vector["inputs"]["people"].items():
        seed = bytes.fromhex(person["seed_hex"])
        assert lb.ed25519_public(seed).hex() == person["ed_public_hex"], name
        out[name] = seed
    return out


def book(seeds, owner, names):
    return [lk.knock_keys(seeds[owner], lb.ed25519_public(seeds[n])) for n in names]


def test_the_files():
    assert sorted(p.name for p in VEC.glob("rlk1_*.json")) == sorted(FILES)
    assert sorted(p.name for p in (VEC / "negative").glob("rlk1_*.json")) == sorted(NEGATIVE)
    for name in list(FILES) + [f"negative/{n}" for n in NEGATIVE]:
        v = load(name)
        assert v["protocol_version"] == "rvn1" and v["deterministic"] is True, name


def test_tags_and_proof():
    v = load("rlk1_tags_001.json")
    i, e = v["inputs"], v["expected"]
    seeds = people(v)
    alice, bob = lb.ed25519_public(seeds["alice"]), lb.ed25519_public(seeds["bob"])
    k = lk.link_key(seeds["alice"], bob)
    assert k == lk.link_key(seeds["bob"], alice)
    assert k.hex() == e["k_link_hex"]
    assert k != lb.medium_key(lb.pair_root(seeds["alice"], bob), lb.MEDIUM_LAN)
    a = lk.knock_keys(seeds["alice"], bob)
    b = lk.knock_keys(seeds["bob"], alice)
    assert a.q_out.hex() == b.q_in.hex() == e["kq_alice_to_bob_hex"]
    assert b.q_out.hex() == a.q_in.hex() == e["kq_bob_to_alice_hex"]
    assert b.r_out.hex() == a.r_in.hex() == e["kr_bob_to_alice_hex"]
    assert a.r_out.hex() == b.r_in.hex() == e["kr_alice_to_bob_hex"]
    day = lk.day_of(i["unix_ms"])
    assert day == e["day"]
    nonce = bytes.fromhex(i["nonce_hex"])
    e_a = bytes.fromhex(i["e_a_hex"])
    assert e_a == x_pub(bytes([0x11]) * 32)
    tag = lk.m1_tag(a.q_out, day, nonce, e_a)
    assert tag.hex() == e["tag_hex"]
    payload = lk.m1_payload(a, day, e_a, nonce, bytes.fromhex(i["m1_pad_hex"]))
    assert payload.hex() == e["m1_payload_hex"]
    raw = e_a + payload
    assert raw.hex() == e["raw_m1_hex"]
    assert 64 <= len(raw) <= 95
    listener = book(seeds, "bob", i["listener_book"])
    for d in e["accepted_listener_days"]:
        found = lk.match_m1(listener, raw, d)
        assert found is not None
        assert found.index == e["match"]["index"]
        assert found.peer == lb.ed25519_public(seeds[e["match"]["peer"]])
        assert (found.nonce, found.e) == (nonce, e_a)
    s_b = bytes.fromhex(i["s_b_hex"])
    assert s_b == x_pub(bytes([0x33]) * 32)
    proof = lk.m2_proof(b.r_out, nonce, e_a, s_b)
    assert proof.hex() == e["proof_hex"]
    m2 = lk.m2_payload(b, nonce, e_a, s_b, bytes.fromhex(i["m2_pad_hex"]))
    assert m2.hex() == e["m2_payload_hex"]
    assert lk.check_m2(a, nonce, e_a, s_b, m2)
    assert not lk.check_m2(a, nonce, e_a, x_pub(bytes([0x34]) * 32), m2)
    assert not lk.check_m2(b, nonce, e_a, s_b, m2), "the other direction"
    for case in e["m3_payloads"]:
        p = lk.rlx1_payload_padded(case["caps"], case["total"])
        assert p.hex() == case["payload_hex"]
        assert len(p) == case["total"] <= 64
        assert lp.rlx1_caps(p) == case["caps"]


def test_wrong_day():
    v = load("negative/rlk1_wrong_day_001.json")
    i = v["inputs"]
    seeds = people(v)
    raw = bytes.fromhex(i["raw_m1_hex"])
    listener = book(seeds, i["listener"], i["listener_book"])
    for d in i["listener_days"]:
        assert abs(d - i["knock_day"]) == 2
        assert lk.match_m1(listener, raw, d) is None
    assert v["expected"]["matched"] is False
    for d in (i["knock_day"] - 1, i["knock_day"], i["knock_day"] + 1):
        assert lk.match_m1(listener, raw, d) is not None


def test_wrong_pair():
    v = load("negative/rlk1_wrong_pair_001.json")
    i = v["inputs"]
    seeds = people(v)
    listener = book(seeds, i["listener"], i["listener_book"])
    for case, matched in zip(i["cases"], v["expected"]["matched"]):
        raw = bytes.fromhex(case["raw_m1_hex"])
        assert (lk.match_m1(listener, raw, i["listener_day"]) is not None) == matched
    # Carol does recognise Alice's knock for her.
    raw = bytes.fromhex(i["cases"][0]["raw_m1_hex"])
    carol_book = book(seeds, "carol", ["alice"])
    assert lk.match_m1(carol_book, raw, i["listener_day"]) is not None


def test_replay():
    v = load("negative/rlk1_replay_001.json")
    i, e = v["inputs"], v["expected"]
    seeds = people(v)
    raw = bytes.fromhex(i["raw_m1_hex"])
    listener = book(seeds, i["listener"], i["listener_book"])
    cache = lk.ReplayCache()
    first_ms, second_ms = i["received_unix_ms"]
    found = lk.match_m1(listener, raw, lk.day_of(first_ms))
    assert found is not None and e["first"]["matched"]
    assert not cache.replayed(found.nonce, first_ms)
    again = lk.match_m1(listener, raw, lk.day_of(second_ms))
    assert again is not None and e["second"]["matched"]
    assert cache.replayed(again.nonce, second_ms) is e["second"]["replay"]
    assert e["replay_ttl_ms"] == lk.REPLAY_TTL_MS
    assert e["replay_entries"] == lk.REPLAY_ENTRIES
    # Answered as no match in each mode.
    assert lk.answer(lk.LEGACY, False) == "derived"
    assert lk.answer(lk.STRICT, False) == "fresh"
    assert lk.answer(lk.SILENT, False) == "close"


def test_unmatched_m2():
    v = load("negative/rlk1_unmatched_m2_random_001.json")
    i, e = v["inputs"], v["expected"]
    seeds = people(v)
    a = lk.knock_keys(seeds["alice"], lb.ed25519_public(seeds["bob"]))
    payload = bytes.fromhex(i["m2_payload_hex"])
    assert len(payload) == i["matched_m2_payload_len"] == e["len"]
    ok = lk.check_m2(
        a,
        bytes.fromhex(i["nonce_hex"]),
        bytes.fromhex(i["e_a_hex"]),
        bytes.fromhex(i["s_b_hex"]),
        payload,
    )
    assert ok is e["proof_ok"] is False


def test_handshake_003_knock():
    v = json.loads((RVN1 / "lan/noise_xx_handshake_003.json").read_text(encoding="utf-8"))
    tags = load("rlk1_tags_001.json")
    i, e = v["inputs"], v["expected"]
    alice_seed = bytes.fromhex(i["initiator_device_seed_hex"])
    bob_seed = bytes.fromhex(i["responder_device_seed_hex"])
    alice, bob = lb.ed25519_public(alice_seed), lb.ed25519_public(bob_seed)
    e_a = x_pub(bytes.fromhex(i["initiator_ephemeral_priv_hex"]))
    m1 = bytes.fromhex(e["m1_hex"])
    assert m1[:32] == e_a and len(m1) == e["m1_len"]
    a = lk.knock_keys(alice_seed, bob)
    day = lk.day_of(i["knock_unix_ms"])
    nonce = bytes.fromhex(i["knock_nonce_hex"])
    payload = lk.m1_payload(a, day, e_a, nonce, bytes.fromhex(i["m1_pad_hex"]))
    assert m1[32:] == payload and payload.hex() == e["m1_payload_hex"]
    assert m1.hex() == tags["expected"]["raw_m1_hex"]
    found = lk.match_m1([lk.knock_keys(bob_seed, alice)], m1, day)
    assert found is not None and found.peer == alice
    s_b = x_pub(bytes.fromhex(i["responder_static_priv_hex"]))
    assert s_b.hex() == e["responder_static_pub_hex"] == e["initiator_remote_static_hex"]
    m2_payload = bytes.fromhex(e["m2_payload_hex"])
    assert lk.check_m2(a, nonce, e_a, s_b, m2_payload)
    assert m2_payload == lk.m2_payload(
        lk.knock_keys(bob_seed, alice), nonce, e_a, s_b, bytes.fromhex(i["m2_pad_hex"])
    )
    # e, the encrypted static and the encrypted payload, with their tags.
    assert e["m2_len"] == 32 + 48 + len(m2_payload) + 16
    s_a = x_pub(bytes.fromhex(i["initiator_static_priv_hex"]))
    assert s_a.hex() == e["initiator_static_pub_hex"] == e["responder_remote_static_hex"]
    assert e["initiator_derived_static_pub_hex"] == lp.noise_static_public(alice_seed).hex()
    assert s_a.hex() != e["initiator_derived_static_pub_hex"]
    assert s_b != lp.noise_static_public(bob_seed)
    m3_payload = bytes.fromhex(i["m3_payload_hex"])
    assert e["m3_payload_read_hex"] == i["m3_payload_hex"]
    assert e["m3_len"] == 48 + len(m3_payload) + 16
    assert lp.rlx1_caps(m3_payload) == lp.CAP_LINK_RRH1
    assert m3_payload == lk.rlx1_payload_padded(lp.CAP_LINK_RRH1, len(m3_payload))
    # Shapes (spec §6).
    assert 64 <= e["m1_len"] <= 95 and 112 <= e["m2_len"] <= 143 and e["m3_len"] <= 128


@pytest.mark.parametrize(
    "setting, every, mode",
    [
        ("automatic", False, lk.LEGACY),
        ("automatic", True, lk.STRICT),
        ("on", False, lk.SILENT),
        ("on", True, lk.SILENT),
        ("off", False, lk.LEGACY),
        ("off", True, lk.LEGACY),
    ],
)
def test_listener_mode(setting, every, mode):
    assert lk.listener_mode(setting, every) == mode
    assert lk.answer(mode, True) == "fresh+proof"


def test_dialer_table():
    for pin in ("none", "match", "mismatch"):
        for floor in (False, True):
            assert lk.dialer_step(True, pin, floor) == "fresh"
            if pin == "mismatch":
                assert lk.dialer_step(False, pin, floor) == "stop_pin"
            if pin == "match":
                assert lk.dialer_step(False, pin, floor) == "derived"
    assert lk.dialer_step(False, "none", True) == "stop_knock"
    assert lk.dialer_step(False, "none", False) == "derived"


def test_replay_cache_bounds():
    cache = lk.ReplayCache()
    assert not cache.replayed(b"\x01" * 16, 0)
    assert cache.replayed(b"\x01" * 16, lk.REPLAY_TTL_MS - 1)
    assert not cache.replayed(b"\x01" * 16, lk.REPLAY_TTL_MS)
