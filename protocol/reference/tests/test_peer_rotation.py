# tests/test_peer_rotation.py
"""P2P PeerId rotation V1 (RAVEN_P2P_PEER_ROTATION_V1.md, draft): epoch keys, phase and boundaries,
the announced schedule, the relay schedule text, the card p2pn= vector and the generator."""
import json, pathlib, subprocess, sys, tempfile

import pytest

from raven_protocol import address, fingerprint, via
from raven_protocol import peer_rotation as pr

REF = pathlib.Path(__file__).resolve().parents[1]  # protocol/reference
REPO = REF.parents[1]
VEC = REPO / "shared-vectors/rvn1"
GEN = REF / "generate_peer_rotation.py"


def load(name):
    return json.loads((VEC / name).read_text(encoding="utf-8"))


def test_epoch_peer_id_vectors_replay():
    v = load("p2p/epoch_peer_id_001.json")
    seed = bytes.fromhex(v["inputs"]["raven_seed_hex"])
    assert v["expected"]["legacy_peer_id"] == pr.legacy_peer_id(seed)
    for case in v["expected"]["epochs"]:
        e = case["epoch"]
        assert pr.epoch_seed(seed, e).hex() == case["epoch_seed_hex"]
        assert pr.epoch_public(seed, e).hex() == case["ed25519_public_hex"]
        assert pr.epoch_peer_id(seed, e) == case["peer_id"]
        assert via.normalize_peer_id(case["peer_id"]) == case["peer_id"]
        assert case["peer_id"] != v["expected"]["legacy_peer_id"]
    assert len({c["peer_id"] for c in v["expected"]["epochs"]}) == len(v["expected"]["epochs"])
    sched = pr.own_schedule(seed, v["inputs"]["schedule_active"])
    assert [(e, k.hex()) for e, k in sched] == [(c["epoch"], c["ed25519_public_hex"])
                                               for c in v["expected"]["own_schedule"]]
    assert [e for e, _ in sched] == list(range(22, 30)) and len(sched) == pr.MAX_SCHEDULE
    assert v["expected"]["own_schedule_at_0"] == list(range(0, 7))


def test_epoch_phase_vectors_replay():
    v = load("p2p/epoch_phase_001.json")
    for case in v["expected"]["cases"]:
        seed, length = bytes.fromhex(case["raven_seed_hex"]), case["epoch_len_s"]
        phase = pr.phase_s(seed, length)
        assert phase == case["phase_s"] and 0 <= phase < length
        for t in case["times"]:
            assert pr.epoch_at(seed, t["unix_s"], length) == t["epoch"]
            nb = pr.next_boundary_unix(seed, t["unix_s"], length)
            assert nb == t["next_boundary_unix"] and nb > t["unix_s"]
            # The boundary starts the next epoch; the second before it is still this one.
            assert pr.epoch_at(seed, nb, length) == t["epoch"] + 1
            assert pr.epoch_at(seed, nb - 1, length) == t["epoch"]


def test_relay_schedule_vectors_replay():
    v = load("p2p/relay_schedule_text_001.json")
    seed = bytes.fromhex(v["inputs"]["raven_seed_hex"])
    assert v["inputs"]["max_len"] == pr.RELAY_SCHEDULE_MAX_LEN
    for f in v["inputs"]["format"]:
        assert pr.format_relay_schedule(seed, f["from"], f["n"]) == f["text"]
    for case in v["expected"]["accept"]:
        got = pr.parse_relay_schedule(case["input"])
        assert [{"epoch": e, "peer_id": p} for e, p in got] == case["entries"], case["input"]
    for case in v["expected"]["reject"]:
        with pytest.raises(pr.RelayScheduleError) as e:
            pr.parse_relay_schedule(case["input"])
        assert e.value.code == case["error"], case["input"]
    codes = {case["error"] for case in v["expected"]["reject"]}
    assert codes == {pr.NOT_ONE_LINE, pr.VERSION, pr.PREFIX, pr.ENTRY, pr.EPOCH, pr.PEER_ID, pr.ORDER,
                     pr.DUPLICATE, pr.EMPTY, pr.TOO_MANY}


def test_relay_schedule_round_trip():
    seed = bytes([0x52]) * 32
    for start, n in ((0, 1), (5, 13), (2**64 - 3, 13)):
        text = pr.format_relay_schedule(seed, start, n)
        got = pr.parse_relay_schedule(text)
        assert [e for e, _ in got] == list(range(start, min(start + n, 2**64)))
        assert all(p == pr.epoch_peer_id(seed, e) for e, p in got)
        assert len(text) <= pr.RELAY_SCHEDULE_MAX_LEN


def test_card_p2pn_vector_replay():
    v = load("p2p/card_p2pn_001.json")
    i, x = v["inputs"], v["expected"]
    seed = bytes.fromhex(i["raven_seed_hex"])
    e = pr.epoch_at(seed, i["now_unix"], i["epoch_len_s"])
    assert (e, pr.phase_s(seed, i["epoch_len_s"])) == (x["epoch"], x["phase_s"])
    assert (pr.epoch_peer_id(seed, e), pr.epoch_peer_id(seed, e + 1)) == (x["p2p"], x["p2pn"])
    fields = dict(t.split("=", 1) for t in x["card"].split(" ")[1:])
    assert x["card"].startswith("raven-card/3 ") and len(x["card"]) == x["card_len"] <= 1530
    assert (fields["p2p"], fields["p2pn"], fields["relay"]) == (x["p2p"], x["p2pn"], i["relay"])
    pub = bytes.fromhex(fields["pub_hex"])
    assert fields["address"] == address.encode(pub)
    assert fields["fingerprint"] == fingerprint.device_fingerprint_v1(pub)


def test_generator_check_and_byte_identical_runs():
    done = subprocess.run([sys.executable, "-I", str(GEN), "--check"], capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
    with tempfile.TemporaryDirectory() as t1:
        subprocess.run([sys.executable, "-I", str(GEN), "--out", t1], check=True, capture_output=True)
        out = pathlib.Path(t1)
        names = sorted(p.relative_to(out).as_posix() for p in out.rglob("*.json"))
        assert names == ["p2p/card_p2pn_001.json", "p2p/epoch_peer_id_001.json", "p2p/epoch_phase_001.json",
                         "p2p/relay_schedule_text_001.json"]
        for n in names:
            assert (out / n).read_bytes() == (VEC / n).read_bytes(), n
        # Another generator's file under p2p/ is not this one's business; a stray epoch_ file is.
        (out / "p2p/via_001.json").write_text("{}\n", encoding="utf-8")
        ok = subprocess.run([sys.executable, "-I", str(GEN), "--out", t1, "--check"], capture_output=True)
        assert ok.returncode == 0
        (out / "p2p/epoch_phase_002.json").write_text("{}\n", encoding="utf-8")
        bad = subprocess.run([sys.executable, "-I", str(GEN), "--out", t1, "--check"], capture_output=True)
        assert bad.returncode == 1
