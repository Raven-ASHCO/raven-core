"""RAVEN Route Hints V1 custody entries (RAVEN_ROUTE_HINTS_V1.md §4, §12, draft):
the Python reference recomputes the CUSTODIAN_TAG vectors and re-reads the
custody frames (all written by Rust under RAVEN_REGEN_RRH1_VECTORS=1)."""

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[3]
VEC = REPO / "shared-vectors/rvn1/route_hints"

DOMAIN = b"raven/rrh1/custodian-tag/v1"
T_CUSTODY_OFFER = 0x06
T_CUSTODIAN_TAG = 0x07
CUSTODY_OFFER_KNOWN = 0x03  # WAN | REACHABLE
CUSTODIAN_TAG_KNOWN_FLAGS = 0x01  # bit 0 HANDOFF_INBOX (Phase 5); bit 1 reserved
PHASE3_CUSTODIAN_TAG_KNOWN_FLAGS = 0x00  # what a receiver built before Phase 5 keeps


def load(name):
    return json.loads((VEC / name).read_text(encoding="utf-8"))


def public(seed_hex):
    seed = bytes.fromhex(seed_hex)
    key = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def custodian_tag(sender, receiver, custodian):
    return hashlib.sha256(DOMAIN + sender + receiver + custodian).digest()


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


def test_custodian_tag_rows():
    v = load("rrh1_custodian_tag_001.json")
    assert v["inputs"]["domain"].encode() == DOMAIN
    seeds = v["inputs"]["seeds_hex"]
    keys = {name: public(seed) for name, seed in seeds.items()}
    rows = v["expected"]["rows"]
    assert len(rows) == 3
    for row in rows:
        s, r, c = (bytes.fromhex(row[k]) for k in ("sender_pub_hex", "receiver_pub_hex", "custodian_pub_hex"))
        assert {s, r, c} <= set(keys.values())
        assert custodian_tag(s, r, c).hex() == row["tag_hex"]
    # Row 3 is row 1 in the other direction: an unrelated tag.
    assert rows[0]["tag_hex"] != rows[2]["tag_hex"]
    assert custodian_tag(bytes([1]) * 32, bytes([2]) * 32, bytes([3]) * 32).hex() == (
        "6ee6500b2012797421f0d005b91b8285817a0140a9c3be000342a88163cde807"
    )


def test_custody_frame():
    v = load("rrh1_custody_001.json")
    frame = bytes.fromhex(v["expected"]["frame_hex"])
    assert len(frame) == v["expected"]["frame_len"]
    inputs = v["inputs"]
    sender = bytes.fromhex(inputs["sender_device_hex"])
    receiver = bytes.fromhex(inputs["receiver_device_hex"])
    want_tags = [custodian_tag(sender, receiver, bytes.fromhex(c)) for c in inputs["custodian_devices_hex"]]
    es = entries(frame)
    assert [k for k, _ in es] == sorted(k for k, _ in es), "ascending type order"
    offers = [value for kind, value in es if kind == T_CUSTODY_OFFER]
    tags = [value for kind, value in es if kind == T_CUSTODIAN_TAG]
    assert offers == [bytes([v["expected"]["decoded"]["custody_offer"]])]
    assert all(len(t) == 33 for t in tags)
    decoded = v["expected"]["decoded"]["custodian_tags"]
    assert [t[:32] for t in tags] == want_tags
    assert [(t[:32].hex(), t[32]) for t in tags] == [(d["tag_hex"], d["flags"]) for d in decoded]
    kept = v["expected"]["kept"]
    assert kept["custody_offer"] == offers[0][0] & CUSTODY_OFFER_KNOWN
    assert kept["custodian_tags_hex"] == [t[:32].hex() for t in tags]
    assert kept["custodian_tag_flags"] == [t[32] & CUSTODIAN_TAG_KNOWN_FLAGS for t in tags]


def test_phase2_decoder_view_drops_only_the_custody_entries():
    v = load("rrh1_phase2_decoder_skips_custody_001.json")
    for case in v["expected"]["cases"]:
        frame = bytes.fromhex(case["frame_hex"])
        kinds = {k for k, _ in entries(frame)}
        assert {T_CUSTODY_OFFER, T_CUSTODIAN_TAG} <= kinds
        then, now = case["phase2_decoded"], case["phase3_decoded"]
        assert "custody_offer" not in then and "custodian_tags" not in then
        assert {k: val for k, val in now.items() if k not in ("custody_offer", "custodian_tags")} == then


def test_ignored_and_validated_custody_rows():
    ignored = {c["name"]: bytes.fromhex(c["frame_hex"]) for c in load("rrh1_ignored_001.json")["expected"]["cases"]}
    for name, length in (("CUSTODY_OFFER len 0", 0), ("CUSTODY_OFFER len 2", 2), ("CUSTODIAN_TAG len 32", 32), ("CUSTODIAN_TAG len 34", 34)):
        (kind, value), = entries(ignored[name])
        assert kind in (T_CUSTODY_OFFER, T_CUSTODIAN_TAG) and len(value) == length
    assert [k for k, _ in entries(ignored["a second CUSTODY_OFFER"])] == [T_CUSTODY_OFFER] * 2
    assert [k for k, _ in entries(ignored["3 CUSTODIAN_TAG"])] == [T_CUSTODIAN_TAG] * 3
    for case in load("rrh1_validated_001.json")["expected"]["cases"]:
        kept = case["kept"]
        if "custody_offer" not in kept:
            continue
        es = entries(bytes.fromhex(case["frame_hex"]))
        offers = [value[0] for kind, value in es if kind == T_CUSTODY_OFFER]
        if not case["link"]["pinned"]:
            assert kept["custody_offer"] is None and kept["custodian_tags_hex"] == []
            continue
        assert kept["custody_offer"] == (offers[0] & CUSTODY_OFFER_KNOWN if offers else None)
        tags, flags = [], {}
        for kind, value in es:
            if kind == T_CUSTODIAN_TAG and value[:32] != bytes(32):
                tag = value[:32].hex()
                if tag not in tags:
                    tags.append(tag)
                # A repeated tag's flags are OR-ed into the first.
                flags[tag] = flags.get(tag, 0) | value[32]
        assert kept["custodian_tags_hex"] == tags[:2], case["name"]
        want = [flags[t] & CUSTODIAN_TAG_KNOWN_FLAGS for t in kept["custodian_tags_hex"]]
        assert kept["custodian_tag_flags"] == want, case["name"]


def test_handoff_inbox_flag_and_the_old_reader():
    v = load("rrh1_custody_handoff_inbox_001.json")
    frame = bytes.fromhex(v["expected"]["frame_hex"])
    assert len(frame) == v["expected"]["frame_len"]
    inputs = v["inputs"]
    sender = bytes.fromhex(inputs["sender_device_hex"])
    receiver = bytes.fromhex(inputs["receiver_device_hex"])
    want_tags = [custodian_tag(sender, receiver, bytes.fromhex(c)) for c in inputs["custodian_devices_hex"]]
    tags = [value for kind, value in entries(frame) if kind == T_CUSTODIAN_TAG]
    assert [t[:32] for t in tags] == want_tags
    assert [t[32] for t in tags] == [0x01, 0xFE]
    decoded = v["expected"]["decoded"]["custodian_tags"]
    assert [(d["tag_hex"], d["flags"]) for d in decoded] == [(t[:32].hex(), t[32]) for t in tags]
    kept = v["expected"]["kept"]
    assert kept["custodian_tags_hex"] == [t[:32].hex() for t in tags]
    assert kept["custodian_tag_flags"] == [t[32] & CUSTODIAN_TAG_KNOWN_FLAGS for t in tags] == [0x01, 0x00]
    # An old (Phase 3) reader keeps both tags and clears every bit.
    phase3 = v["expected"]["phase3_kept_flags"]
    assert phase3 == [t[32] & PHASE3_CUSTODIAN_TAG_KNOWN_FLAGS for t in tags] == [0, 0]
