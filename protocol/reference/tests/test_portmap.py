# tests/test_portmap.py
"""Raven Port Mapping Profile V1 (RAVEN_PORT_MAPPING_V1.md, draft): reference codec and vectors."""
import ast, json, pathlib, subprocess, sys, tempfile

import pytest

from raven_protocol import portmap as pm

REF = pathlib.Path(__file__).resolve().parents[1]  # protocol/reference
REPO = REF.parents[1]
VEC = REPO / "shared-vectors/rvn1/portmap"
GEN = REF / "generate_portmap.py"


def load(name):
    return json.loads((VEC / name).read_text(encoding="utf-8"))


def test_requests_match_vectors():
    assert pm.natpmp_request(0).hex() == load("natpmp_extaddr_req_001.json")["expected"]["request_hex"]
    v = load("natpmp_map_tcp_req_001.json")
    i = v["inputs"]
    assert pm.natpmp_request(i["op"], i["internal_port"], i["suggested_port"], i["lifetime"]).hex() \
        == v["expected"]["request_hex"]
    v = load("pcp_announce_req_001.json")
    assert pm.pcp_request(0, 0, v["inputs"]["client_ip"]).hex() == v["expected"]["request_hex"]
    for name in ("pcp_map_v4_req_001.json", "pcp_map_v4_delete_001.json", "pcp_map_v6_req_001.json"):
        v = load(name)
        i = v["inputs"]
        nonce = pm.pcp_nonce(pm.nonce_key(bytes.fromhex(i["seed_hex"])), i["gateway_ip"], i["client_ip"],
                             i["protocol"], i["internal_port"])
        assert nonce.hex() == i["nonce_hex"], name
        req = pm.pcp_request(pm.PCP_OP_MAP, i["lifetime"], i["client_ip"], {
            "nonce": nonce, "proto": i["protocol"], "internal_port": i["internal_port"],
            "suggested_port": i["suggested_port"], "suggested_ip": pm.unspecified_external(i["client_ip"])})
        assert req.hex() == v["expected"]["request_hex"], name
        assert len(req) == 60


def test_pinhole_vector_asks_the_shorter_lease():
    # Section 6: an IPv4 mapping asks 7200 s, an IPv6 pinhole 3600 s.
    assert load("pcp_map_v4_req_001.json")["inputs"]["lifetime"] == pm.REQUESTED_LIFETIME_S == 7200
    assert load("pcp_map_v6_req_001.json")["inputs"]["lifetime"] == pm.PINHOLE_LIFETIME_S == 3600


def test_replies_decode_like_the_vectors():
    names = sorted(p.name for p in VEC.glob("*.json") if "reply_hex" in load(p.name)["inputs"])
    assert len(names) == 7
    for name in names:
        i = load(name)["inputs"]
        got = pm.decode_reply(bytes.fromhex(i["reply_hex"]), i["sent_pcp_op"], i["sent_natpmp_op"])
        assert got == load(name)["expected"], name


def test_negative_vectors_are_refused_with_their_reason():
    names = sorted((VEC / "negative").glob("*.json"))
    assert len(names) == 7
    for path in names:
        v = json.loads(path.read_text(encoding="utf-8"))
        i = v["inputs"]
        with pytest.raises(pm.ReplyError) as e:
            pm.decode_reply(bytes.fromhex(i["reply_hex"]), i["sent_pcp_op"], i["sent_natpmp_op"])
        assert e.value.code == v["expected"]["error"], path.name
    codes = {json.loads(p.read_text(encoding="utf-8"))["expected"]["error"] for p in names}
    assert {"version", "not_response", "opcode", "length", "mandatory_option"} <= codes


def test_a_natpmp_only_router_is_recognised_only_as_an_answer_to_pcp():
    for name in ("pcp_reply_natpmp_only_001.json", "pcp_reply_natpmp_only_002.json"):
        reply = bytes.fromhex(load(name)["inputs"]["reply_hex"])
        assert len(reply) == 8
        with pytest.raises(pm.ReplyError):
            pm.decode_reply(reply, None, pm.NATPMP_OP_MAP_TCP)
        with pytest.raises(pm.ReplyError):
            pm.decode_reply(reply, None, None)
    for op_byte, sent, ok in ((0x81, 1, True), (0x80, 0, True), (0x00, 1, True), (0x80, 1, False),
                              (0x82, 1, False)):
        reply = pm.natpmp_unsupported_version(op_byte, 9)
        if ok:
            assert pm.decode_reply(reply, sent, None) == {"kind": "natpmp_only"}
        else:
            with pytest.raises(pm.ReplyError):
                pm.decode_reply(reply, sent, None)
    # Another result code is no version answer.
    with pytest.raises(pm.ReplyError):
        pm.decode_reply(bytes([0, 0x81, 0, 2, 0, 0, 0, 9]), 1, None)


def test_option_and_length_bounds():
    head = pm.pcp_reply(pm.PCP_OP_ANNOUNCE, 0, 0, 1)
    assert pm.decode_reply(head + bytes([0x80, 0, 0, 0]), 0)["kind"] == "pcp"
    for options, code in ((bytes([0x80, 0, 0, 5, 0, 0, 0, 0]), "malformed_option"),
                          (bytes([0x80, 0, 0xFF, 0xFF]), "malformed_option"),
                          (bytes([0x01, 0, 0, 0]), "mandatory_option")):
        with pytest.raises(pm.ReplyError) as e:
            pm.decode_reply(head + options, 0)
        assert e.value.code == code
    longest = head + bytes([0x80, 0, 0x04, 0x30]) + bytes(1072)
    assert len(longest) == pm.MAX_PCP
    assert pm.decode_reply(longest, 0)["kind"] == "pcp"
    with pytest.raises(pm.ReplyError) as e:
        pm.decode_reply(longest + bytes(4), 0)
    assert e.value.code == "length"
    # A MAP error may come without the MAP data; SUCCESS may not.
    assert pm.decode_reply(pm.pcp_reply(pm.PCP_OP_MAP, pm.PCP_NOT_AUTHORIZED, 0, 1), 1)["map"] is None


def test_epoch_validity_vector():
    v = load("pcp_epoch_validity_001.json")
    got = []
    for case in v["inputs"]["cases"]:
        prev = None if case["prev"] is None else (case["prev"]["server"], case["prev"]["client_s"])
        got.append(pm.epoch_lost(prev, (case["curr"]["server"], case["curr"]["client_s"])))
    assert got == v["expected"]["lost"]
    assert got[0] is False and True in got and got.count(True) == 4


def test_nonce_vector_and_properties():
    v = load("pcp_nonce_001.json")
    key = pm.nonce_key(bytes.fromhex(v["inputs"]["seed_hex"]))
    other = pm.nonce_key(bytes.fromhex(v["inputs"]["other_seed_hex"]))
    assert key.hex() == v["expected"]["key_hex"] and other.hex() == v["expected"]["other_key_hex"]
    nonces = set()
    for case in v["expected"]["cases"]:
        n = pm.pcp_nonce(key, case["gateway_ip"], case["internal_ip"], case["protocol"], case["port"])
        assert n.hex() == case["nonce_hex"]
        assert pm.pcp_nonce(other, case["gateway_ip"], case["internal_ip"], case["protocol"], case["port"]).hex() \
            == case["other_profile_nonce_hex"] != case["nonce_hex"]
        nonces.add(n)
    assert len(nonces) == len(v["expected"]["cases"])
    # The same internal endpoint behind two routers: two nonces.
    same = [c for c in v["expected"]["cases"] if (c["internal_ip"], c["protocol"], c["port"]) == ("192.168.1.20", 6, 7423)]
    assert len({c["gateway_ip"] for c in same}) == 2 and len({c["nonce_hex"] for c in same}) == 2


def test_generator_check_and_byte_identical_runs():
    done = subprocess.run([sys.executable, "-I", str(GEN), "--check"], capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
    with tempfile.TemporaryDirectory() as t1:
        subprocess.run([sys.executable, "-I", str(GEN), "--out", t1], check=True, capture_output=True)
        out = pathlib.Path(t1) / "portmap"
        names = sorted(p.relative_to(out).as_posix() for p in out.rglob("*.json"))
        assert names == sorted(p.relative_to(VEC).as_posix() for p in VEC.rglob("*.json"))
        for n in names:
            assert (out / n).read_bytes() == (VEC / n).read_bytes(), n
        (out / "negative/extra_001.json").write_text("{}\n", encoding="utf-8")
        bad = subprocess.run([sys.executable, "-I", str(GEN), "--out", t1, "--check"], capture_output=True)
        assert bad.returncode == 1


def test_new_python_imports_only_stdlib():
    for path in (pm.__file__, GEN):
        tree = ast.parse(pathlib.Path(path).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                assert top in sys.stdlib_module_names or top == "raven_protocol", (path, name)
