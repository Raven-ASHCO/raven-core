"""RAVEN Release Bundle V1 (RAVEN_RELEASE_BUNDLE_V1.md, draft): the Python
reference checks every shared-vectors/rvn1/update/rrb1_* and rrbc_* vector
(written by Rust under RAVEN_REGEN_SECURITY_VECTORS=1) against its own codec:
it builds every signed manifest and container again byte for byte, computes
every chunk root and audit path by the RFC 6962 definitions, checks every
refusal and runs every verification case."""

import hashlib
import json
import posixpath
import random
from pathlib import Path

from raven_protocol import advisory as ad
from raven_protocol import release_bundle as rb
from raven_protocol import tlog

REPO = Path(__file__).resolve().parents[3]
VEC = REPO / "shared-vectors/rvn1/update"
FILES = (
    "rrb1_chunk_tree_001.json",
    "rrb1_manifest_001.json",
    "rrbc_small_001.json",
)
NEGATIVE = (
    "rrb1_decode_rules_001.json",
    "rrb1_overlap_001.json",
    "rrb1_path_traversal_001.json",
    "rrb1_unlogged_001.json",
    "rrb1_wrong_target_001.json",
    "rrbc_chunk_tamper_001.json",
    "rrbc_decode_rules_001.json",
    "rrbc_verify_rules_001.json",
)


def load(name):
    return json.loads((VEC / name).read_text(encoding="utf-8"))


def key_set(v):
    """The key set of a vector's ``key_set`` object, built from its seeds."""
    ks = ad.KeySet.of_seeds(v["threshold"], [bytes.fromhex(s) for s in v["seeds_hex"]])
    assert ks.encode().hex() == v["key_set_hex"]
    assert ks.digest().hex() == v["key_set_digest_hex"]
    assert [k.hex() for k in ks.keys] == v["public_keys_hex"]
    return ks


def seeds(v):
    return [bytes.fromhex(s) for s in v["seeds_hex"]]


def entries_of(rows):
    return [tlog.Entry(r["type"], bytes.fromhex(r["digest_hex"]), r["logged_at_ms"]) for r in rows]


def ctx_of(c):
    return rb.Ctx(
        ad.KeySet.decode(bytes.fromhex(c["key_set"])) if c["key_set"] is not None else None,
        entries_of(c["stored_log"]),
        c["installed_serial"],
        c["target"].encode(),
        c["release_floor"],
        c["allow_downgrade"],
    )


def verify_result(parts, ctx):
    """The ``verify`` object a vector expects."""
    try:
        v = rb.verify_bundle(parts, ctx)
    except rb.BundleError as e:
        out = {"result": e.code, "inner": e.inner}
        if e.file_index is not None:
            out["file_index"] = e.file_index
        return out
    return {
        "result": "OK",
        "authority": v.authority,
        "consistency": v.consistency,
        "release_floor": v.release_floor,
    }


def build_manifest(inputs, signer_seeds):
    """The manifest and payload built and signed from a vector's ``manifest``
    inputs."""
    files, payload = rb.pack(
        [
            (f["path"].encode(), f["mode"], bytes.fromhex(f["hex"]), bytes.fromhex(f["rebuild_sha256_hex"]))
            for f in inputs["files"]
        ]
    )
    body = rb.encode_manifest_body(
        build_serial=inputs["build_serial"],
        created_at_ms=inputs["created_at_ms"],
        key_set_digest=bytes.fromhex(inputs["key_set_digest_hex"]),
        version=inputs["version"].encode(),
        target=inputs["target"].encode(),
        source_commit=bytes.fromhex(inputs["source_commit_hex"]),
        toolchain=inputs["toolchain"].encode(),
        min_advisory_serial=inputs["min_advisory_serial"],
        payload_len=len(payload),
        payload_chunk_root=rb.chunk_root(payload),
        payload_sha256=hashlib.sha256(payload).digest(),
        files=files,
        notes=inputs["notes"].encode(),
    )
    return rb.build_manifest(body, [(i, signer_seeds[i]) for i in inputs["signers"]]), payload


def check_manifest(inputs, expected, ks, signer_seeds):
    data, payload = build_manifest(inputs, signer_seeds)
    assert data.hex() == expected["manifest_hex"]
    m = rb.decode_manifest(data)
    assert m.signing_input().hex() == expected["signing_input_hex"]
    assert m.signing_input() == b"rvn1/release-manifest/v1\0" + data[: m.signed_len]
    assert m.digest().hex() == expected["digest_hex"]
    assert m.digest() == hashlib.sha256(b"rvn1/release-manifest/digest/v1\0" + data).digest()
    assert m.chunk_size == expected["chunk_size"] == rb.CHUNK_SIZE
    assert m.payload_len == expected["payload_len"] == len(payload)
    assert m.payload_chunk_root.hex() == expected["payload_chunk_root_hex"]
    assert m.payload_sha256.hex() == expected["payload_sha256_hex"]
    got = [{"path": f.path.decode(), "offset": f.offset, "size": f.size, "sha256_hex": f.sha256.hex()} for f in m.files]
    assert got == expected["files"]
    assert expected["verify"] == "OK"
    m.verify(ks)
    return m, payload


def test_the_files():
    def mine(d):
        return sorted(p.name for p in d.glob("*.json") if p.name.startswith(("rrb1_", "rrbc_")))

    assert mine(VEC) == sorted(FILES)
    assert mine(VEC / "negative") == sorted(NEGATIVE)
    for name in list(FILES) + [f"negative/{n}" for n in NEGATIVE]:
        v = load(name)
        assert v["protocol_version"] == "rvn1" and v["deterministic"] is True, name


def test_constants():
    assert rb.MANIFEST_FIXED_LEN == 165
    assert rb.MAX_MANIFEST_LEN == 5_198
    assert rb.MAX_CHUNKS == 1_093
    assert (rb.MAX_CHUNKS - 1).bit_length() == rb.MAX_CHUNK_PATH_LEN


def test_rrb1_manifest_001():
    v = load("rrb1_manifest_001.json")
    ks = key_set(v["inputs"]["key_set"])
    m, payload = check_manifest(v["inputs"]["manifest"], v["expected"]["manifest"], ks, seeds(v["inputs"]["key_set"]))
    assert payload.hex() == v["expected"]["payload_hex"]
    assert m.chunk_count() == 1
    assert m.check_chunk(0, payload, [])
    for f in m.files:
        assert rb.path_well_formed(f.path)


def test_rrbc_small_001():
    v = load("rrbc_small_001.json")
    i, e = v["inputs"], v["expected"]
    ks = key_set(i["key_set"])
    signer_seeds = seeds(i["key_set"])
    manifest, payload = build_manifest(i["manifest"], signer_seeds)
    m = rb.decode_manifest(manifest)
    assert m.digest().hex() == e["manifest_digest_hex"]
    advisory = bytes.fromhex(i["advisory_hex"])
    a = ad.decode(advisory)
    a.verify(ks)
    assert a.digest().hex() == e["advisory_digest_hex"]
    # The log: the key set, the advisory, the manifest.
    entries = entries_of(i["log"]["entries"])
    assert [(x.type, x.digest) for x in entries] == [
        (tlog.KEY_SET, ks.digest()),
        (tlog.ADVISORY, a.digest()),
        (tlog.MANIFEST, m.digest()),
    ]
    body = tlog.encode_sth_body(len(entries), tlog.mth(entries), i["log"]["sth"]["timestamp_ms"], ks.digest())
    sth = tlog.build_sth(body, [(k, signer_seeds[k]) for k in i["log"]["sth"]["signers"]])
    snapshot = tlog.encode_snapshot(entries, sth)
    assert snapshot.hex() == e["snapshot_hex"]
    data = rb.encode_container(manifest, snapshot, advisory, payload)
    assert data.hex() == e["container_hex"]
    assert (len(manifest), len(snapshot), len(advisory), len(payload)) == (
        e["manifest_len"],
        e["snapshot_len"],
        e["advisory_len"],
        e["payload_len"],
    )
    parts = rb.open_container(data)
    assert parts.manifest.data == manifest and parts.payload == payload
    assert parts.advisory.data == advisory and parts.snapshot.sth.data == sth
    assert verify_result(parts, ctx_of(i["ctx"])) == e["verify"]
    # Without the advisory: advisory_len 0.
    bare = rb.open_container(rb.encode_container(manifest, snapshot, b"", payload))
    assert bare.advisory is None


def pattern(n):
    """Byte j = j mod 251."""
    return (bytes(range(251)) * (n // 251 + 1))[:n]


def test_rrb1_chunk_tree_001():
    v = load("rrb1_chunk_tree_001.json")
    i, e = v["inputs"], v["expected"]
    assert i["chunk_size"] == rb.CHUNK_SIZE
    small = pattern(i["small_payload_len"])
    leaves = rb.chunk_leaf_hashes(small)
    assert len(leaves) == e["small"]["chunk_count"] == 5
    assert [x.hex() for x in leaves] == e["small"]["leaf_hashes_hex"]
    root = rb.chunk_root(small)
    assert root.hex() == e["small"]["root_hex"]
    for p in e["small"]["paths"]:
        path = rb.chunk_path(p["index"], leaves)
        assert [x.hex() for x in path] == p["path_hex"]
        assert rb.verify_chunk_path(root, len(leaves), p["index"], leaves[p["index"]], path)
        assert not rb.verify_chunk_path(root, len(leaves), p["index"], leaves[(p["index"] + 1) % 5], path)
    assert i["max_payload_len"] == rb.MAX_PAYLOAD_LEN
    big = pattern(rb.MAX_PAYLOAD_LEN)
    leaves = rb.chunk_leaf_hashes(big)
    assert len(leaves) == e["max"]["chunk_count"] == rb.MAX_CHUNKS
    root = tlog.root_of_leaf_hashes(leaves)
    assert root.hex() == e["max"]["root_hex"]
    assert [p["index"] for p in e["max"]["paths"]] == i["max_path_indexes"]
    for p in e["max"]["paths"]:
        path = rb.chunk_path(p["index"], leaves)
        assert [x.hex() for x in path] == p["path_hex"]
        assert len(path) <= rb.MAX_CHUNK_PATH_LEN
        assert rb.verify_chunk_path(root, len(leaves), p["index"], leaves[p["index"]], path)
    assert len(rb.chunk_path(0, leaves)) == rb.MAX_CHUNK_PATH_LEN


def test_chunk_paths_by_definition():
    for n in range(1, 40):
        leaves = [tlog.leaf_hash(k.to_bytes(4, "big")) for k in range(n)]
        root = tlog.root_of_leaf_hashes(leaves)
        for m in range(n):
            path = rb.chunk_path(m, leaves)
            assert rb.verify_chunk_path(root, n, m, leaves[m], path), (n, m)
            assert not rb.verify_chunk_path(root, n, m, leaves[m], path + [b"\0" * 32])
            if path:
                assert not rb.verify_chunk_path(root, n, m, leaves[m], path[:-1])
            assert not rb.verify_chunk_path(root, n, n, leaves[m], path)


def errors_of(v):
    return {x["name"]: x for x in v["expected"]["errors"]}


def manifest_case_bytes(case):
    data = bytes.fromhex(case.get("hex", case.get("manifest_hex", "")))
    if "zero_pad_to" in case:
        data += b"\0" * (case["zero_pad_to"] - len(data))
    return data


def check_manifest_refusals(name):
    v = load(name)
    errors = errors_of(v)
    assert [c["name"] for c in v["inputs"]["cases"]] == list(errors)
    for case in v["inputs"]["cases"]:
        try:
            rb.decode_manifest(manifest_case_bytes(case))
        except rb.Rrb1Error as e:
            assert e.code == errors[case["name"]]["error"], case["name"]
        else:
            raise AssertionError(f"{case['name']} decoded")
    return v


def test_rrb1_decode_rules_001():
    v = check_manifest_refusals("negative/rrb1_decode_rules_001.json")
    codes = {x["error"] for x in v["expected"]["errors"]}
    assert len(codes) == 21


def test_rrb1_path_traversal_001():
    v = check_manifest_refusals("negative/rrb1_path_traversal_001.json")
    for case in v["inputs"]["cases"]:
        path = bytes.fromhex(case["path_hex"])
        if errors_of(v)[case["name"]]["error"] == "BAD_PATH":
            assert not rb.path_well_formed(path), case["name"]


def test_rrb1_overlap_001():
    v = check_manifest_refusals("negative/rrb1_overlap_001.json")
    for case in v["inputs"]["cases"]:
        layout = [(x["offset"], x["size"]) for x in case["layout"]]
        tiles = (
            layout[0][0] == 0
            and all(a[0] + a[1] == b[0] for a, b in zip(layout, layout[1:]))
            and layout[-1][0] + layout[-1][1] == case["payload_len"]
        )
        assert not tiles, case["name"]


def test_path_traversal_property():
    """Every path the rule accepts stays inside any directory it is joined
    under, by posixpath alone."""
    rng = random.Random(6043)
    alphabet = ["a", "B", "0", "-", "_", ".", "..", "/", "\\", ":", " ", "~", "ä", "con", "x."]
    accepted = 0
    for _ in range(20_000):
        p = rng.choice(["bin/", "docs/", "bin/x/", ""]) + "".join(rng.choice(alphabet) for _ in range(rng.randrange(8)))
        raw = p.encode()
        if not rb.path_well_formed(raw):
            continue
        accepted += 1
        joined = posixpath.normpath(posixpath.join("/staged", p))
        assert joined.startswith("/staged/") and joined == "/staged/" + p, p
        assert p.split("/")[0] in ("bin", "docs") and 2 <= len(p.split("/")) <= 3
        assert not any(c in p for c in "\\: ")
    assert accepted > 1_000


def test_rrbc_decode_rules_001():
    v = load("negative/rrbc_decode_rules_001.json")
    errors = errors_of(v)
    assert [c["name"] for c in v["inputs"]["cases"]] == list(errors)
    for case in v["inputs"]["cases"]:
        try:
            rb.open_container(bytes.fromhex(case["hex"]))
        except rb.RrbcError as e:
            want = errors[case["name"]]
            assert (e.code, e.inner) == (want["error"], want["inner"]), case["name"]
        else:
            raise AssertionError(f"{case['name']} opened")
    assert len({x["error"] for x in v["expected"]["errors"]}) == 11


def test_rrb1_unlogged_001():
    v = load("negative/rrb1_unlogged_001.json")
    ks = key_set(v["inputs"]["key_set"])
    parts = rb.open_container(bytes.fromhex(v["inputs"]["container_hex"]))
    e = v["expected"]
    assert e["open"] == "OK"
    parts.manifest.verify(ks)
    assert e["manifest_verify"] == "OK"
    tlog.check(parts.snapshot, ks)
    assert e["log_check"] == "OK"
    assert parts.manifest.digest().hex() == e["manifest_digest_hex"]
    assert not tlog.contains(parts.snapshot.entries, tlog.MANIFEST, parts.manifest.digest())
    assert verify_result(parts, ctx_of(v["inputs"]["ctx"])) == e["verify"] == {"result": "UNLOGGED", "inner": None}


def test_rrb1_wrong_target_001():
    v = load("negative/rrb1_wrong_target_001.json")
    key_set(v["inputs"]["key_set"])
    parts = rb.open_container(bytes.fromhex(v["inputs"]["container_hex"]))
    assert parts.manifest.target == b"aarch64-apple-darwin"
    ctx = ctx_of(v["inputs"]["ctx"])
    assert ctx.target == b"x86_64-unknown-linux-gnu"
    assert verify_result(parts, ctx) == v["expected"]["verify"] == {"result": "WRONG_TARGET", "inner": None}
    good = load("rrbc_small_001.json")
    assert v["inputs"]["container_hex"] == good["expected"]["container_hex"]


def test_rrbc_chunk_tamper_001():
    v = load("negative/rrbc_chunk_tamper_001.json")
    key_set(v["inputs"]["key_set"])
    data = bytes.fromhex(v["inputs"]["container_hex"])
    parts = rb.open_container(data)
    e = v["expected"]
    assert e["open"] == "OK"
    assert rb.chunk_root(parts.payload).hex() == e["chunk_root_hex"]
    assert parts.manifest.payload_chunk_root.hex() == e["manifest_chunk_root_hex"] != e["chunk_root_hex"]
    assert parts.manifest.check_chunk(0, parts.payload, []) is e["check_chunk_0"] is False
    assert verify_result(parts, ctx_of(v["inputs"]["ctx"])) == e["verify"]
    # One bit away from the good container.
    good = bytes.fromhex(load("rrbc_small_001.json")["expected"]["container_hex"])
    diff = [i for i in range(len(good)) if good[i] != data[i]]
    assert len(diff) == 1 and bin(good[diff[0]] ^ data[diff[0]]).count("1") == 1


def test_rrbc_verify_rules_001():
    v = load("negative/rrbc_verify_rules_001.json")
    key_set(v["inputs"]["key_set"])
    key_set(v["inputs"]["other_key_set"])
    good_payload = bytes.fromhex(v["inputs"]["good_payload_hex"])
    results = {r["name"]: r for r in v["expected"]["results"]}
    assert [c["name"] for c in v["inputs"]["cases"]] == list(results)
    for case in v["inputs"]["cases"]:
        p = case["parts"]
        parts = rb.Parts(
            rb.decode_manifest(bytes.fromhex(p["manifest_hex"])),
            tlog.decode_snapshot(bytes.fromhex(p["snapshot_hex"])),
            ad.decode(bytes.fromhex(p["advisory_hex"])) if p["advisory_hex"] is not None else None,
            bytes.fromhex(p["payload_hex"]) if p["payload_hex"] is not None else good_payload,
        )
        want = dict(results[case["name"]])
        del want["name"]
        assert verify_result(parts, ctx_of(case["ctx"])) == want, case["name"]
    codes = {r["result"] for r in v["expected"]["results"]} - {"OK"}
    assert len(codes) == 14
