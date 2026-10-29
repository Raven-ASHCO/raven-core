"""RAVEN Update Exchange V1 (RAVEN_UPDATE_EXCHANGE_V1.md, draft): the Python
reference checks every shared-vectors/rvn1/update/rup1_* vector (written by
Rust under RAVEN_REGEN_SECURITY_VECTORS=1) against its own codec: it builds
every frame again byte for byte, checks that the frames carry the test
release of rrbc_small_001.json, computes every chunk's audit path by the RFC
6962 definitions, and replays every refusal, every listener decision and the
dial classifier."""

import hashlib
import json
from pathlib import Path

from raven_protocol import link_padding as lp
from raven_protocol import release_bundle as rb
from raven_protocol import tlog
from raven_protocol import update_exchange as ux

REPO = Path(__file__).resolve().parents[3]
VEC = REPO / "shared-vectors/rvn1/update"
FILES = (
    "rup1_chunk_path_001.json",
    "rup1_frames_001.json",
    "rup1_have_001.json",
)
NEGATIVE = (
    "rup1_decode_rules_001.json",
    "rup1_oversize_chunk_001.json",
)
ALL_CODES = {
    "NOT_RUP1",
    "TRUNCATED",
    "TOO_LONG",
    "BAD_VERSION",
    "UNKNOWN_OP",
    "TRAILING_BYTES",
    "NONZERO_REQ_ID",
    "BAD_ADVISORY_REF",
    "BAD_LOG_REF",
    "TOO_MANY_OFFERS",
    "BAD_SERIAL",
    "BAD_TARGET",
    "BAD_PAYLOAD_LEN",
    "DUPLICATE_OFFER",
    "BAD_RAD1_LEN",
    "BAD_MANIFEST_LEN",
    "BAD_SNAPSHOT_LEN",
    "BAD_COUNT",
    "BAD_INDEX",
    "BAD_CHUNK_LEN",
    "BAD_PATH_LEN",
    "BAD_CODE",
}


def load(name):
    return json.loads((VEC / name).read_text(encoding="utf-8"))


_BASE = bytes(range(251))


def pattern(n, start):
    """``n`` bytes, byte j = (start + j) mod 251."""
    s = start % 251
    reps = (s + n) // 251 + 1
    return (_BASE * reps)[s : s + n]


def fields_of(j):
    """A vector's ``fields`` as :func:`raven_protocol.update_exchange.decode`
    returns them."""
    out = {}
    for k, v in j.items():
        if k == "code_name":
            continue
        if k == "offers":
            out[k] = [
                ux.Offer(o["build_serial"], o["target"].encode(), bytes.fromhex(o["manifest_digest_hex"]), o["payload_len"])
                for o in v
            ]
        elif k == "path_hex":
            out["path"] = [bytes.fromhex(h) for h in v]
        elif k.endswith("_hex"):
            out[k[:-4]] = bytes.fromhex(v)
        else:
            out[k] = v
    return out


def frame_of(case):
    """A case's frame: whole, or head | pattern fill | tail (one byte flipped
    at ``xor_at``), checked against its length and SHA-256."""
    if "frame_hex" in case:
        return bytes.fromhex(case["frame_hex"])
    spec = case["frame"]
    frame = bytearray(
        bytes.fromhex(spec["head_hex"]) + pattern(spec["fill_len"], spec["fill_start"]) + bytes.fromhex(spec["tail_hex"])
    )
    if spec["xor_at"] is not None:
        frame[spec["xor_at"]] ^= 1
    frame = bytes(frame)
    assert len(frame) == spec["len"]
    assert hashlib.sha256(frame).hexdigest() == spec["sha256_hex"]
    return frame


def result_of(frame):
    try:
        ux.decode(frame)
        return "OK"
    except ux.Rup1Error as e:
        return e.code


def release_parts():
    v = load("rrbc_small_001.json")
    return rb.open_container(bytes.fromhex(v["expected"]["container_hex"]))


def snapshot_bytes(parts):
    return tlog.encode_snapshot(parts.snapshot.entries, parts.snapshot.sth.data)


def check_entry(e):
    """One frame entry: built again from its fields byte for byte, decoded
    back to them, and classified as the vector says."""
    req_id, op, fields = bytes.fromhex(e["req_id_hex"]), e["op"], fields_of(e["fields"])
    frame = bytes.fromhex(e["frame_hex"])
    assert ux.encode(req_id, op, fields) == frame, e["name"]
    assert ux.decode(frame) == (req_id, op, fields), e["name"]
    assert len(frame) == e["frame_len"]
    assert ux.OP_NAMES[op] == e["op_name"]
    assert ux.role(op) == e["role"]
    assert ux.expects_reply(frame) == e["expects_reply"]
    assert ux.is_terminal_reply(frame) == e["terminal_reply"]
    assert ux.listener(frame) == e["listener"]
    if op == ux.OP_ERROR:
        assert e["fields"]["code_name"] == ux.ERROR_NAMES.get(fields["code"], "UNKNOWN")
    return op, fields


def test_the_files():
    def mine(d):
        return sorted(p.name for p in d.glob("rup1_*.json"))

    assert mine(VEC) == sorted(FILES)
    assert mine(VEC / "negative") == sorted(NEGATIVE)
    for name in list(FILES) + [f"negative/{n}" for n in NEGATIVE]:
        v = load(name)
        assert v["protocol_version"] == "rvn1" and v["deterministic"] is True, name


def test_constants():
    assert ux.MAX_FRAME_LEN == 65_511 == lp.MAX_INNER
    assert ux.HAVE_FIXED_LEN == 77 and ux.OFFER_FIXED_LEN == 49
    assert ux.MAX_HAVE_LEN == 539
    assert ux.GET_CHUNKS_LEN == 47
    assert ux.GET_ROTATION_LEN == 42
    assert ux.MAX_CHUNK_FRAME_LEN == 61_811
    assert ux.MAX_MANIFEST_FRAME_LEN == 63_233
    assert ux.MAX_LOG_FRAME_LEN == 58_033
    assert ux.ADVISORY_ALWAYS_FITS == 7_476
    assert rb.MAX_CHUNKS == 1_093 and rb.MAX_CHUNK_PATH_LEN == 11
    assert ux.MAX_CHUNKS_PER_DIAL == 2 * ux.MAX_CHUNKS_PER_REQUEST == 16


def test_rup1_frames_001():
    v = load("rup1_frames_001.json")
    assert v["inputs"]["source"] == "rrbc_small_001.json"
    parts = release_parts()
    snapshot = snapshot_bytes(parts)
    by_name = {e["name"]: check_entry(e) for e in v["expected"]["frames"]}
    ops = {op for op, _ in by_name.values()}
    assert ops == set(ux.OP_NAMES), "one frame of every op"

    # The frames carry the test release.
    m = parts.manifest
    have = by_name["have_test_release"][1]
    assert have["adv_serial"] == parts.advisory.serial
    assert have["adv_digest"] == parts.advisory.digest()
    assert have["log_size"] == parts.snapshot.sth.tree_size
    assert have["log_root"] == parts.snapshot.sth.root_hash
    assert have["offers"] == [ux.Offer(m.build_serial, m.target, m.digest(), m.payload_len)]
    assert by_name["advisory"][1] == {"rad1": parts.advisory.data, "snapshot": snapshot}
    assert by_name["log"][1] == {"snapshot": snapshot}
    assert by_name["manifest"][1] == {"manifest": m.data, "snapshot": snapshot}
    assert by_name["get_manifest"][1] == {"manifest_digest": m.digest()}
    # GET_ROTATION names a key set (the test release's).
    assert by_name["get_rotation"][1] == {"key_set_digest": m.key_set_digest}
    chunk = by_name["chunk"][1]
    assert chunk == {"index": 0, "bytes": parts.payload, "path": []}
    assert m.check_chunk(0, chunk["bytes"], chunk["path"])
    assert ux.chunk_checks(m.payload_chunk_root, m.payload_len, chunk)

    # Which reply answers which request.
    answers = v["expected"]["answers"]
    assert sorted(a["request"] for a in answers) == sorted(n for n, (op, _) in by_name.items() if op in ux.REQUESTS)
    for a in answers:
        req = by_name[a["request"]]
        got = [n for n, r in by_name.items() if ux.answered_by(req, r)]
        assert sorted(got) == sorted(a["answered_by"]), a["request"]

    for c in v["expected"]["classify"]:
        f = bytes.fromhex(c["frame_hex"])
        assert ux.expects_reply(f) == c["expects_reply"]
        assert ux.is_terminal_reply(f) == c["terminal_reply"]
        assert ux.listener(f) == c["listener"]

    caps = v["expected"]["link_caps"]
    assert caps["cap_link_rup1"] == ux.CAP_LINK_RUP1 == 0x400
    assert caps["hello_caps_rup1"] == lp.CAP_INTERNET | ux.CAP_LINK_RUP1
    links = lp.CAP_LINK_RRH1 | lp.CAP_LINK_PAD1 | ux.CAP_LINK_RUP1
    assert caps["hello_caps_rrh1_pad1_rup1"] == lp.CAP_INTERNET | links == 0x702
    rlx1 = lp.rlx1_payload(links)
    assert rlx1.hex() == caps["rlx1_payload_rrh1_pad1_rup1_hex"]
    assert lp.rlx1_caps(rlx1) == links


def test_rup1_have_001():
    v = load("rup1_have_001.json")
    parts = release_parts()
    haves = {e["name"]: check_entry(e) for e in v["expected"]["haves"]}
    nothing = haves["nothing"][1]
    assert nothing == {"adv_serial": 0, "adv_digest": bytes(32), "log_size": 0, "log_root": bytes(32), "offers": []}
    m = parts.manifest
    release = haves["test_release"][1]
    assert release["offers"] == [ux.Offer(m.build_serial, m.target, m.digest(), m.payload_len)]
    assert release["adv_digest"] == parts.advisory.digest()
    assert release["log_root"] == tlog.mth(parts.snapshot.entries)
    assert len(haves["four_offers"][1]["offers"]) == ux.MAX_OFFERS
    longest = [e for e in v["expected"]["haves"] if e["name"] == "longest"][0]
    assert longest["frame_len"] == ux.MAX_HAVE_LEN == v["expected"]["max_have_len"]
    assert all(len(o.target) == rb.MAX_TARGET_LEN for o in haves["longest"][1]["offers"])


def max_payload_leaves():
    """The leaf hashes of the 64 MiB payload (byte j = j mod 251), each
    distinct chunk hashed once."""
    size, length = rb.CHUNK_SIZE, rb.MAX_PAYLOAD_LEN
    seen, leaves = {}, []
    for k in range(-(-length // size)):
        start = k * size
        n = min(size, length - start)
        key = (start % 251, n)
        if key not in seen:
            seen[key] = tlog.leaf_hash(pattern(n, start))
        leaves.append(seen[key])
    return leaves


def check_chunk_entry(e, req_id, payload_bytes, leaves, root, payload_len):
    i = e["index"]
    path = rb.chunk_path(i, leaves)
    assert [bytes.fromhex(h) for h in e["path_hex"]] == path
    assert bytes.fromhex(e["leaf_hex"]) == tlog.leaf_hash(payload_bytes) == leaves[i]
    assert e["len"] == len(payload_bytes)
    fields = {"index": i, "bytes": payload_bytes, "path": path}
    frame = ux.encode(req_id, ux.OP_CHUNK, fields)
    assert frame_of(e) == frame
    assert ux.decode(frame) == (req_id, ux.OP_CHUNK, fields)
    assert len(lp.wrap(frame)) == e["pad1_len"]
    assert ux.chunk_checks(root, payload_len, fields)
    assert not ux.expects_reply(frame) and not ux.is_terminal_reply(frame)
    return frame


def test_rup1_chunk_path_001():
    v = load("rup1_chunk_path_001.json")
    tree = load("rrb1_chunk_tree_001.json")["expected"]
    inputs, exp = v["inputs"], v["expected"]
    req_id = bytes.fromhex(inputs["req_id_hex"])
    size = inputs["chunk_size"]
    assert size == rb.CHUNK_SIZE

    # Small: 5 chunks, answered after GET_CHUNKS first 0 count 5.
    payload = pattern(inputs["small_payload_len"], 0)
    leaves = rb.chunk_leaf_hashes(payload)
    root = tlog.root_of_leaf_hashes(leaves)
    small = exp["small"]
    assert small["root_hex"] == root.hex() == tree["small"]["root_hex"]
    assert small["chunk_count"] == len(leaves) == 5
    request = check_entry(small["request"])
    assert request[1]["first"] == 0 and request[1]["count"] == 5
    frames = []
    for e in small["chunks"]:
        i = e["index"]
        frame = check_chunk_entry(e, req_id, payload[i * size : (i + 1) * size], leaves, root, len(payload))
        assert ux.answered_by(request, (ux.OP_CHUNK, ux.decode(frame)[2]))
        frames.append(frame)
    assert [e["index"] for e in small["chunks"]] == list(range(5))
    assert bytes.fromhex(small["last_frame_hex"]) == frames[-1]
    end = check_entry(small["end"])
    assert end[1] == {"code": 0, "sent": 5} and ux.answered_by(request, end)

    # Max: 64 MiB, chunk 0 has the longest path and the longest frame.
    big = max_payload_leaves()
    big_root = tlog.root_of_leaf_hashes(big)
    mx = exp["max"]
    assert mx["root_hex"] == big_root.hex() == tree["max"]["root_hex"]
    assert mx["chunk_count"] == len(big) == rb.MAX_CHUNKS
    for e in mx["chunks"]:
        i = e["index"]
        n = min(size, rb.MAX_PAYLOAD_LEN - i * size)
        frame = check_chunk_entry(e, req_id, pattern(n, i * size), big, big_root, rb.MAX_PAYLOAD_LEN)
        if i == 0:
            assert len(e["path_hex"]) == rb.MAX_CHUNK_PATH_LEN
            assert len(frame) == mx["max_chunk_frame_len"] == ux.MAX_CHUNK_FRAME_LEN
            assert len(frame) <= mx["pad1_max_inner"] == lp.MAX_INNER
            assert e["pad1_len"] == lp.BUCKETS[-1]
    assert [e["index"] for e in mx["chunks"]] == [0, rb.MAX_CHUNKS - 1]


def test_rup1_oversize_chunk_001():
    v = load("negative/rup1_oversize_chunk_001.json")
    inputs, exp = v["inputs"], v["expected"]
    for c in exp["refused"]:
        frame = frame_of(c)
        assert result_of(frame) == c["result"], c["name"]
        assert ux.listener(frame) == c["listener"], c["name"]
        if c["result"] == "OK":
            req_id, op, fields = ux.decode(frame)
            assert ux.encode(req_id, op, fields) == frame
    chunk_max = [c for c in exp["refused"] if c["name"] == "chunk_max"][0]
    assert chunk_max["frame"]["len"] == ux.MAX_CHUNK_FRAME_LEN
    payload_len = inputs["small_payload_len"]
    root = bytes.fromhex(inputs["small_root_hex"])
    assert root == rb.chunk_root(pattern(payload_len, 0))
    assert exp["forged"]
    for c in exp["forged"]:
        frame = frame_of(c)
        _, op, fields = ux.decode(frame)
        assert op == ux.OP_CHUNK and c["result"] == "OK"
        assert ux.chunk_checks(root, payload_len, fields) is c["check"] is False, c["name"]
        assert ux.listener(frame) == "DROP"


def test_rup1_decode_rules_001():
    v = load("negative/rup1_decode_rules_001.json")
    names = set()
    for c in v["expected"]["cases"]:
        assert c["name"] not in names
        names.add(c["name"])
        frame = frame_of(c)
        assert result_of(frame) == c["result"], c["name"]
        assert ux.listener(frame) == c["listener"], c["name"]
        if c["result"] == "OK":
            req_id, op, fields = ux.decode(frame)
            assert ux.encode(req_id, op, fields) == frame, c["name"]


def test_every_refusal_is_in_the_vectors():
    reached = set()
    for name, key in (("negative/rup1_decode_rules_001.json", "cases"), ("negative/rup1_oversize_chunk_001.json", "refused")):
        reached |= {c["result"] for c in load(name)["expected"][key]}
    assert reached - {"OK"} == ALL_CODES


def test_encode_refuses():
    """The reference refuses to build what it would refuse to read."""
    for req_id, op, fields, code in [
        (b"RU\x00\x01", ux.OP_HAVE, {"adv_serial": 0, "adv_digest": bytes(32), "log_size": 0, "log_root": bytes(32), "offers": []}, "NONZERO_REQ_ID"),
        (ux.NO_REQ_ID, ux.OP_HAVE, {"adv_serial": 1, "adv_digest": bytes(32), "log_size": 0, "log_root": bytes(32), "offers": []}, "BAD_ADVISORY_REF"),
        (b"RU\x00\x01", ux.OP_GET_CHUNKS, {"manifest_digest": bytes(32), "first": 0, "count": 9}, "BAD_COUNT"),
        (b"RU\x00\x01", ux.OP_ERROR, {"code": 0}, "BAD_CODE"),
        (b"RU\x00\x01", ux.OP_ADVISORY, {"rad1": b"\x01" * 32_768, "snapshot": b"\x02" * 58_023}, "TOO_LONG"),
    ]:
        try:
            ux.encode(req_id, op, fields)
        except ux.Rup1Error as e:
            assert e.code == code
        else:
            raise AssertionError(code)
