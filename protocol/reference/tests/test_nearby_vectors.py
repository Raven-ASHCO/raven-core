"""RAVEN Nearby Link V1 (RAVEN_NEARBY_LINK_V1.md, draft): the Python reference
recomputes every shared-vectors/rvn1/nearby vector (written by Rust) from its
inputs. Rust and Python per RAVEN_PRIVATE_RENDEZVOUS_V1 §13.1; Swift does not
apply in this repository (no Apple nearby code here)."""

import json
from pathlib import Path

import pytest

from raven_protocol import lan_beacon as lb
from raven_protocol import nearby as nb

REPO = Path(__file__).resolve().parents[3]
VEC = REPO / "shared-vectors/rvn1/nearby"
FILES = (
    "rnb1_pair_keys_001.json",
    "rnb1_tokens_001.json",
    "rnk1_knock_001.json",
    "rnp1_frames_001.json",
)
NEGATIVE = (
    "rnb1_noncontributory_001.json",
    "rnp1_bad_kind_001.json",
    "rnp1_chan_owner_001.json",
    "rnp1_credit_overflow_001.json",
    "rnp1_data_too_long_001.json",
    "rnp1_data_without_credit_001.json",
    "rnp1_knock_after_up_001.json",
    "rnp1_seq_gap_001.json",
    "rnp1_short_data_001.json",
)


def load(name):
    return json.loads((VEC / name).read_text(encoding="utf-8"))


def seeds(vector):
    """name -> seed of a vector's people, with each public key checked."""
    out = {}
    for name, person in vector["inputs"]["people"].items():
        seed = bytes.fromhex(person["seed_hex"])
        assert lb.ed25519_public(seed).hex() == person["ed_public_hex"], name
        out[name] = seed
    return out


def test_the_files_and_their_people():
    assert sorted(p.name for p in VEC.glob("*.json")) == sorted(FILES)
    assert sorted(p.name for p in (VEC / "negative").glob("*.json")) == sorted(NEGATIVE)
    # The people are the LAN beacon vectors' people.
    lan = json.loads((REPO / "shared-vectors/rvn1/lan_beacon/lbcn_pair_keys_001.json").read_text())
    for name in list(FILES) + [f"negative/{n}" for n in NEGATIVE]:
        v = load(name)
        assert v["protocol_version"] == "rvn1" and v["deterministic"] is True
        for who, person in v["inputs"].get("people", {}).items():
            assert person == lan["inputs"]["people"][who], (name, who)


def test_pair_keys_vector_pins_the_r2_root():
    v = load("rnb1_pair_keys_001.json")
    i, e = v["inputs"], v["expected"]
    folks = seeds(v)
    assert i["r2_pair_salt_ascii"].encode() == lb.R2_PAIR_SALT
    assert i["medium_ble"] == lb.MEDIUM_BLE == 0x01
    assert (i["token_info_ascii"], i["knock_info_ascii"]) == ("RNB1-token", "RNB1-knock")
    lan = json.loads((REPO / "shared-vectors/rvn1/lan_beacon/lbcn_pair_keys_001.json").read_text())
    lan_roots = {(r["a"], r["b"]): r["k_root_hex"] for r in lan["expected"]["pairs"]}
    assert [[r["a"], r["b"]] for r in e["pairs"]] == i["pairs"]
    for row in e["pairs"]:
        a, b = folks[row["a"]], folks[row["b"]]
        ab = nb.pair_keys(a, lb.ed25519_public(b))
        ba = nb.pair_keys(b, lb.ed25519_public(a))
        assert (ab.k_tok, ab.k_knock) == (ba.k_tok, ba.k_knock)
        root = lb.pair_root(a, lb.ed25519_public(b))
        assert root.hex() == row["k_root_hex"] == lan_roots[(row["a"], row["b"])]
        assert ab.k_ble.hex() == row["k_ble_hex"]
        assert ab.k_tok.hex() == row["k_tok_hex"]
        assert ab.k_knock.hex() == row["k_knock_hex"]
        assert len({root, ab.k_ble, ab.k_tok, ab.k_knock, lb.medium_key(root, lb.MEDIUM_LAN)}) == 5


def test_tokens_vector():
    v = load("rnb1_tokens_001.json")
    i, e = v["inputs"], v["expected"]
    folks = seeds(v)
    a, b = (folks[n] for n in i["pair"])
    k = nb.pair_keys(a, lb.ed25519_public(b))
    assert i["epoch_ms"] == nb.EPOCH_MS
    e0 = nb.epoch_of(i["unix_ms"])
    assert e0 == e["epoch"] == 1888888
    assert e["scanner_accepts"] == nb.scan_epochs(e0) == [e0 - 1, e0, e0 + 1]
    assert nb.scan_epochs(0) == [0, 1]
    seen = []
    assert [(r["epoch"], r["advertiser"]) for r in e["tokens"]] == [
        (e0, "alice"),
        (e0, "bob"),
        (e0 + 1, "alice"),
        (e0 + 1, "bob"),
    ]
    for row in e["tokens"]:
        adv = lb.ed25519_public(folks[row["advertiser"]])
        assert nb.token_hmac_input(row["epoch"], adv).hex() == row["hmac_input_hex"]
        t = nb.token(k.k_tok, row["epoch"], adv)
        assert t.hex() == row["token_hex"]
        assert nb.uuid_string(t) == row["uuid_string"]
        assert nb.uuid_ota_le(t).hex() == row["ota_le_hex"]
        assert f"{nb.windows_guid_u128(t):032x}" == row["windows_guid_u128_hex"]
        c = nb.char_uuid(t)
        assert c.hex() == row["char_uuid_hex"]
        assert nb.uuid_string(c) == row["char_uuid_string"]
        for u in (t, c):
            assert u[6] >> 4 == 4 and u[8] >> 6 == 0b10
        seen += [t, c]
    assert len(set(seen)) == len(seen)


def test_knock_vector():
    v = load("rnk1_knock_001.json")
    i, e = v["inputs"], v["expected"]
    folks = seeds(v)
    central, peripheral = folks[i["central"]], folks[i["peripheral"]]
    at_c = nb.pair_keys(central, lb.ed25519_public(peripheral))
    at_p = nb.pair_keys(peripheral, lb.ed25519_public(central))
    # The peripheral advertises (and hosts) T(e, peripheral).
    t = nb.token(at_p.k_tok, i["epoch"], lb.ed25519_public(peripheral))
    assert t.hex() == e["token_hex"]
    nonce_c, nonce_p = bytes.fromhex(i["nonce_c_hex"]), bytes.fromhex(i["nonce_p_hex"])
    flags_c, flags_p = i["flags_c"], i["flags_p"]
    hello = nb.hello(at_c.k_knock, t, flags_c, nonce_c)
    assert hello.hex() == e["hello_hex"] and len(hello) == nb.HELLO_LEN
    replay = set()
    challenge = nb.answer_hello(at_p.k_knock, t, hello, nonce_p, replay)
    assert challenge is not None and challenge.hex() == e["challenge_hex"]
    assert challenge == nb.challenge(at_p.k_knock, t, flags_c, nonce_c, flags_p, nonce_p)
    proof = nb.proof_for(at_c.k_knock, t, flags_c, nonce_c, challenge)
    assert proof is not None and proof.hex() == e["proof_hex"] and len(proof) == nb.PROOF_LEN
    assert proof == nb.proof(at_p.k_knock, t, flags_c, nonce_c, flags_p, nonce_p)
    for row in e["silent"]:
        frame = bytes.fromhex(row["hello_hex"])
        assert row["answered"] is False
        assert nb.answer_hello(at_p.k_knock, t, frame, nonce_p, replay) is None, row["what"]
    # A tampered CHALLENGE gets no PROOF; nor does one for another nonce_c.
    bad = bytearray(challenge)
    bad[-1] ^= 1
    assert nb.proof_for(at_c.k_knock, t, flags_c, nonce_c, bytes(bad)) is None
    assert nb.proof_for(at_c.k_knock, t, flags_c, bytes(16), challenge) is None
    # The HELLO on the other side's token (another service) is not answered.
    other = nb.token(at_p.k_tok, i["epoch"], lb.ed25519_public(central))
    assert nb.answer_hello(at_p.k_knock, other, hello, nonce_p, set()) is None


def test_frames_vector():
    v = load("rnp1_frames_001.json")
    assert v["inputs"]["max_tx_values"] == [64, 185, 512]
    names = [r["name"] for r in v["expected"]["frames"]]
    assert names == [
        "open",
        "data_max_tx_64",
        "data_max_tx_185",
        "data_max_tx_512",
        "credit",
        "fin",
        "reset_limit",
    ]
    for row in v["expected"]["frames"]:
        f = dict(row["frame"])
        if "payload_hex" in f:
            f["payload"] = bytes.fromhex(f.pop("payload_hex"))
            # The largest payload of its frame size, counting bytes.
            assert len(f["payload"]) == row["max_tx"] - nb.DATA_HEADER
            assert f["payload"] == bytes(i % 256 for i in range(len(f["payload"])))
        raw = bytes.fromhex(row["frame_hex"])
        assert nb.encode(f) == raw, row["name"]
        assert nb.decode(raw, row["max_tx"]) == f, row["name"]
        assert len(raw) <= row["max_tx"]
    assert v["expected"]["frames"][-1]["frame"] == {"kind": "RESET", "code": nb.RESET_CODES["LIMIT"]}


@pytest.mark.parametrize("name", [n for n in NEGATIVE if n.startswith("rnp1_")])
def test_pipe_negative_vectors(name):
    v = load(f"negative/{name}")
    i, e = v["inputs"], v["expected"]
    st = nb.PipeState(i["role"], i["max_rx"], i["max_rx"])
    frames = [bytes.fromhex(h) for h in i["frames_hex"]]
    assert len(frames) == e["fails_at"] + 1
    for n, frame in enumerate(frames):
        if n < e["fails_at"]:
            st.on_rx_bytes(frame)
        else:
            with pytest.raises(nb.PipeError) as err:
                st.on_rx_bytes(frame)
            assert err.value.name == e["error"], name
            assert err.value.reset().hex() == e["reset_hex"]
    assert st.dead


def test_noncontributory_negative_vector():
    v = load("negative/rnb1_noncontributory_001.json")
    folks = seeds(v)
    own = folks[v["inputs"]["own"]]
    me = lb.ed25519_public(own)
    for row in v["expected"]["contact_keys"]:
        assert row["result"] == "BAD_KEY"
        with pytest.raises(lb.BadKey):
            nb.pair_keys(own, bytes.fromhex(row["peer_pub_hex"]))
    scalar = lb.x25519_scalar(own)
    for row in v["expected"]["shared_secrets"]:
        assert row["result"] == "NONCONTRIBUTORY"
        with pytest.raises(lb.NonContributory):
            lb.root_from(scalar, bytes.fromhex(row["montgomery_u_hex"]), me, bytes(32))


def test_a_pipe_carries_a_65535_byte_noise_message_at_every_frame_size():
    noise = bytes((i * 2654435761 >> 24) & 0xFF for i in range(65535))
    stream = len(noise).to_bytes(4, "big") + noise
    for size in (64, 185, 512):
        c = nb.PipeState("central", size, size)
        p = nb.PipeState("peripheral", size, size)
        assert p.on_rx_bytes(c.open()) == ("opened", 0)
        got, rest, delivered = b"", stream, 0
        while rest:
            n = min(len(rest), size - nb.DATA_HEADER)
            frame = c.send_data(0, rest[:n])
            assert frame is not None and len(frame) <= size
            rest = rest[n:]
            kind, chan, payload = p.on_rx_bytes(frame)
            assert (kind, chan) == ("deliver", 0)
            got += payload
            delivered += 1
            if delivered == nb.W0 // 2:
                assert c.on_rx_bytes(p.grant(0, delivered)) == ("credit", 0)
                delivered = 0
        assert got == stream, size
