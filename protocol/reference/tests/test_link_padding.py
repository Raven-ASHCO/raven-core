"""RAVEN Link Padding V1 (RAVEN_LINK_PADDING_V1.md, draft): the Python
reference checks every shared-vectors/rvn1/link vector (written by Rust under
RAVEN_REGEN_SECURITY_VECTORS=1) against its own codec, state and
negotiation code."""

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from raven_protocol import link_padding as lp

REPO = Path(__file__).resolve().parents[3]
RVN1 = REPO / "shared-vectors/rvn1"
VEC = RVN1 / "link"
FILES = (
    "pad1_ack_512_001.json",
    "pad1_max_001.json",
    "pad1_pairinit_4096_001.json",
    "rih1_hello_pad1_001.json",
    "rlx1_caps_002.json",
)
NEGATIVE = (
    "pad1_bad_bucket_001.json",
    "pad1_bad_version_001.json",
    "pad1_len_overflow_001.json",
    "pad1_nested_001.json",
    "pad1_nonzero_padding_001.json",
    "pad1_reserved_001.json",
    "pad1_unpadded_after_pad1_001.json",
    "pad1_zero_len_001.json",
)


def load(name):
    return json.loads((VEC / name).read_text(encoding="utf-8"))


def pattern(n):
    return bytes(i % 251 for i in range(n))


def own(paths):
    """The PAD1 files of a listing (the RLK1 ones are test_link_knock's)."""
    return sorted(p.name for p in paths if not p.name.startswith("rlk1_"))


def test_the_files():
    assert own(VEC.glob("*.json")) == sorted(FILES)
    assert own((VEC / "negative").glob("*.json")) == sorted(NEGATIVE)
    for name in list(FILES) + [f"negative/{n}" for n in NEGATIVE]:
        v = load(name)
        assert v["protocol_version"] == "rvn1" and v["deterministic"] is True, name


@pytest.mark.parametrize(
    "name, source, field",
    [
        ("pad1_ack_512_001.json", "atsam/indexed_session_v1_sealed_ack_001.json", "packed_envelope_hex"),
        ("pad1_pairinit_4096_001.json", "atsam/pair_init_v1_001.json", "pair_init_wire_hex"),
    ],
)
def test_frames_of_committed_inner_frames(name, source, field):
    v = load(name)
    inner = bytes.fromhex(v["inputs"]["inner_hex"])
    committed = json.loads((RVN1 / source).read_text(encoding="utf-8"))
    assert inner.hex() == committed["expected"][field]
    assert v["inputs"]["inner_source"].startswith(f"the {len(inner)}-byte")
    assert source in v["inputs"]["inner_source"]
    assert v["inputs"]["inner_len"] == len(inner)
    frame = lp.wrap(inner)
    e = v["expected"]
    assert frame.hex() == e["frame_hex"]
    assert len(frame) == e["frame_len"] == e["bucket"] == lp.bucket_for(len(inner))
    assert frame[:8].hex() == e["header_hex"]
    assert e["padding_len"] == len(frame) - 8 - len(inner)
    assert lp.unwrap(frame) == inner


def test_ack_and_pairinit_buckets():
    assert load("pad1_ack_512_001.json")["expected"]["bucket"] == 512
    assert load("pad1_pairinit_4096_001.json")["expected"]["bucket"] == 4096


def test_max_frame_and_edges():
    v = load("pad1_max_001.json")
    inner = pattern(v["inputs"]["inner_len"])
    assert v["inputs"]["inner_rule"] == "byte i = i mod 251"
    assert hashlib.sha256(inner).hexdigest() == v["inputs"]["inner_sha256_hex"]
    frame = lp.wrap(inner)
    e = v["expected"]
    assert len(frame) == e["frame_len"] == 65_519 == lp.BUCKETS[-1]
    assert e["padding_len"] == 0
    assert frame[:40].hex() == e["frame_head_hex"]
    assert hashlib.sha256(frame).hexdigest() == e["frame_sha256_hex"]
    assert lp.unwrap(frame) == inner
    for row in e["edges"]:
        n = row["inner_len"]
        assert len(lp.wrap(pattern(n))) == row["frame_len"] == lp.bucket_for(n)
        # The edge is exact: one byte more needs the next bucket.
        if n < lp.MAX_INNER:
            assert lp.bucket_for(n + 1) >= row["frame_len"]
    for row in e["refused"]:
        with pytest.raises(lp.Pad1Error) as err:
            lp.wrap(pattern(row["inner_len"]))
        assert err.value.code == row["error"]


@pytest.mark.parametrize("n", [1, 2, 503, 504, 505, 506, 4_087, 4_088, 4_089, 16_376, 16_377, 40_000, 65_510, 65_511])
def test_round_trip_at_the_edges(n):
    inner = pattern(n)
    frame = lp.wrap(inner)
    assert len(frame) == min(t for t in lp.BUCKETS if t >= n + 8)
    assert lp.unwrap(frame) == inner


@pytest.mark.parametrize("name", [n for n in NEGATIVE if n != "pad1_unpadded_after_pad1_001.json"])
def test_negative_frames(name):
    v = load(f"negative/{name}")
    frame = bytes.fromhex(v["inputs"]["frame_hex"])
    assert len(frame) == v["inputs"]["frame_len"]
    with pytest.raises(lp.Pad1Error) as err:
        lp.unwrap(frame)
    assert err.value.code == v["expected"]["error"]
    with pytest.raises(lp.Pad1Error) as err:
        lp.PadState.agreed(True).on_recv(frame)
    assert err.value.code == v["expected"]["error"]
    # Every negative starts with the magic, so a receiver that reads PAD1
    # unwraps it (and refuses it) whether or not the peer padded before.
    assert frame.startswith(lp.MAGIC)
    with pytest.raises(lp.Pad1Error):
        lp.PadState.lan_dialer(True).on_recv(frame)
    assert lp.PadState.off().on_recv(frame) == frame


def test_unpadded_after_the_peers_first_rpd1():
    v = load("negative/pad1_unpadded_after_pad1_001.json")
    assert v["inputs"]["side"] == "agreed"
    frames = [bytes.fromhex(f) for f in v["inputs"]["frames_hex"]]
    e = v["expected"]
    state = lp.PadState.agreed(True)
    accepted = []
    for i, frame in enumerate(frames):
        if i == e["fails_at"]:
            with pytest.raises(lp.Pad1Error) as err:
                state.on_recv(frame)
            assert err.value.code == e["error"]
            break
        accepted.append(state.on_recv(frame).hex())
    assert accepted == e["accepted_inner_hex"]
    # The same frames to a side without PAD1 pass untouched.
    off = lp.PadState.off()
    assert [off.on_recv(f) for f in frames] == frames


def test_pad_state_sides():
    ack = bytes.fromhex(load("pad1_ack_512_001.json")["inputs"]["inner_hex"])
    padded = lp.wrap(ack)
    dialer = lp.PadState.lan_dialer(True)
    assert dialer.on_send(ack) == ack
    assert dialer.on_recv(ack) == ack
    assert dialer.on_recv(padded) == ack
    assert dialer.on_send(ack) == padded
    with pytest.raises(lp.Pad1Error):
        dialer.on_recv(ack)
    assert lp.PadState.agreed(True).on_send(ack) == padded
    assert lp.PadState.agreed(False).on_send(ack) == ack


def test_rlx1_link_caps_with_pad1():
    v = load("rlx1_caps_002.json")
    for row in v["expected"]["encodings"]:
        payload = bytes.fromhex(row["payload_hex"])
        assert lp.rlx1_payload(row["caps"]) == payload
        assert lp.rlx1_caps(payload) == row["caps"]
        assert row["pad1"] == bool(row["caps"] & lp.CAP_LINK_PAD1)
        assert row["rrh1"] == bool(row["caps"] & lp.CAP_LINK_RRH1)
    # A listener built before PAD1 keeps only the bit it knows.
    assert lp.rlx1_caps(lp.rlx1_payload(0x300)) & lp.CAP_LINK_RRH1 == lp.CAP_LINK_RRH1


def test_rlx1_parser_agrees_with_the_route_hints_vector():
    v = json.loads((RVN1 / "route_hints/rlx1_caps_001.json").read_text(encoding="utf-8"))
    for row in v["expected"]["cases"]:
        assert lp.rlx1_caps(bytes.fromhex(row["payload_hex"])) == row["caps"], row["name"]
    for row in v["expected"]["encodings"]:
        assert lp.rlx1_payload(row["caps"]).hex() == row["payload_hex"]


@pytest.mark.parametrize(
    "name, caps",
    [
        ("link/rih1_hello_pad1_001.json", lp.CAP_INTERNET | lp.CAP_LINK_RRH1 | lp.CAP_LINK_PAD1),
        ("route_hints/rih1_hello_rrh1_001.json", lp.CAP_INTERNET | lp.CAP_LINK_RRH1),
    ],
)
def test_rih1_hello(name, caps):
    v = json.loads((RVN1 / name).read_text(encoding="utf-8"))
    i, e = v["inputs"], v["expected"]
    seed = bytes.fromhex(i["signer_seed_hex"])
    assert i["caps"] == caps
    assert lp.ed25519_public(seed).hex() == i["ed25519_pub_hex"]
    assert lp.noise_static_public(seed).hex() == i["noise_static_pub_hex"]
    hh = bytes.fromhex(i["handshake_hash_hex"])
    signing = lp.hello_signing_bytes(i["role_u8"], caps, hh, lp.noise_static_public(seed), lp.ed25519_public(seed))
    assert signing.hex() == e["signing_bytes_hex"]
    hello = lp.pack_hello(seed, i["role_u8"], caps, hh)
    assert hello.hex() == e["hello_hex"] and len(hello) == e["hello_len"] == 104
    assert hello[40:].hex() == e["signature_hex"]
    Ed25519PublicKey.from_public_bytes(lp.ed25519_public(seed)).verify(hello[40:], signing)
    # Old peers need CAP_INTERNET only and ignore the link bits.
    assert int.from_bytes(hello[4:8], "big") & lp.CAP_INTERNET
