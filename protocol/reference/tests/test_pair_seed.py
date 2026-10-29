"""RAVEN Route Hints V1 §14 pair seeds (RAVEN_ROUTE_HINTS_V1.md, draft): the
Python reference recomputes the KDF vector (shared-vectors/rvn1/pair_seed,
written by Rust under RAVEN_REGEN_SECURITY_VECTORS=1) from the identity seeds,
and re-reads the PAIR_SEED frames (route_hints, written by Rust under
RAVEN_REGEN_RRH1_VECTORS=1): the entry's layout, a decoder built before §14
that skips type 0x08, and the negative that drops the entry alone."""

import json
from pathlib import Path

from raven_protocol import lan_beacon as lb
from raven_protocol import pair_seed as ps

REPO = Path(__file__).resolve().parents[3]
RVN1 = REPO / "shared-vectors/rvn1"


def load(path):
    return json.loads((RVN1 / path).read_text(encoding="utf-8"))


def entries(frame):
    """(type, value) of a well-formed RRH1 frame, in frame order."""
    assert frame[:5] == b"RRH1\x01"
    out, rest = [], frame[17:]
    while rest:
        kind, length = rest[0], int.from_bytes(rest[1:3], "big")
        value = rest[3 : 3 + length]
        assert len(value) == length
        out.append((kind, value))
        rest = rest[3 + length :]
    return out


def test_kdf_vector():
    v = load("pair_seed/kdf_001.json")
    i, x = v["inputs"], v["expected"]
    assert i["kdf_info"].encode() == ps.KDF_INFO
    alice_seed, bob_seed = bytes.fromhex(i["alice_seed_hex"]), bytes.fromhex(i["bob_seed_hex"])
    alice, bob = lb.ed25519_public(alice_seed), lb.ed25519_public(bob_seed)
    assert (alice.hex(), bob.hex()) == (x["alice_pub_hex"], x["bob_pub_hex"])
    root = lb.pair_root(alice_seed, bob)
    assert root == lb.pair_root(bob_seed, alice)
    assert root.hex() == x["k_root_hex"]
    leader = "alice" if ps.is_leader(alice, bob) else "bob"
    assert leader == x["leader"]
    assert ps.is_leader(alice, bob) != ps.is_leader(bob, alice)
    assert len(x["generations"]) == len(i["seeds"]) == 2
    for given, want in zip(i["seeds"], x["generations"]):
        seed = bytes.fromhex(given["seed_hex"])
        assert given["generation"] == want["generation"]
        k = ps.pair_key(root, seed)
        assert k.hex() == want["k_pair_hex"]
        assert lb.medium_key(k, 0x01).hex() == want["k_ble_hex"]
        assert lb.medium_key(k, 0x02).hex() == want["k_lan_hex"]
        assert lb.medium_key(k, 0x03).hex() == want["k_link_hex"]
        # Never the root's medium keys.
        assert lb.medium_key(k, 0x02) != lb.medium_key(root, 0x02)


def test_pair_seed_frame():
    v = load("route_hints/rrh1_pair_seed_001.json")
    x = v["expected"]
    frame = bytes.fromhex(x["frame_hex"])
    assert len(frame) == x["frame_len"]
    found = [(k, val) for k, val in entries(frame) if k == ps.T_PAIR_SEED]
    assert len(found) == 1
    value = found[0][1]
    want = x["decoded"]["pair_seed"]
    assert value.hex() == want["value_hex"]
    e = ps.decode_entry(value)
    assert e == ps.SeedEntry(want["generation"], bytes.fromhex(want["seed_hex"]), want["acked_generation"])
    assert ps.encode_entry(e) == value
    # Ascending type order, and a decoder built before §14 skips 0x08: the
    # frame without it is the Phase 2 frame byte for byte.
    kinds = [k for k, _ in entries(frame)]
    assert kinds == sorted(kinds)
    older = [(k, val) for k, val in entries(frame) if k != ps.T_PAIR_SEED]
    body = b"".join(bytes([k]) + len(val).to_bytes(2, "big") + val for k, val in older)
    assert frame[:17] + body == bytes.fromhex(x["phase2_frame_hex"])


def test_pair_seed_negative():
    v = load("route_hints/negative/rrh1_pair_seed_short_001.json")
    frame = bytes.fromhex(v["inputs"]["frame_hex"])
    kinds = entries(frame)
    assert kinds[0][0] == 0x01 and len(kinds) == 2
    assert kinds[1][0] == ps.T_PAIR_SEED and len(kinds[1][1]) == 39
    assert ps.decode_entry(kinds[1][1]) is None
    assert v["expected"]["frame_kept"] is True and v["expected"]["pair_seed"] is None
    # The other entry rules.
    good = ps.encode_entry(ps.SeedEntry(1, bytes(range(1, 33)), 0))
    assert ps.decode_entry(good) is not None
    assert ps.decode_entry(bytes(4) + good[4:]) is None
    assert ps.decode_entry(good[:4] + bytes(32) + good[36:]) is None
    assert ps.decode_entry(good + b"\x00") is None
