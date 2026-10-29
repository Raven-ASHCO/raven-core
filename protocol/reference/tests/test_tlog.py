"""RAVEN Transparency Log V1 (RAVEN_TRANSPARENCY_LOG_V1.md, draft): the
Python reference checks every shared-vectors/rvn1/update/rtl1_* vector
(written by Rust under RAVEN_REGEN_SECURITY_VECTORS=1) against its own
codec, computes every root on its own, builds every signed tree head and
snapshot again byte for byte, and checks every refusal."""

import json
from pathlib import Path

import pytest

from raven_protocol import advisory as ad
from raven_protocol import tlog

REPO = Path(__file__).resolve().parents[3]
VEC = REPO / "shared-vectors/rvn1/update"
FILES = (
    "rtl1_consistency_001.json",
    "rtl1_mth_001.json",
    "rtl1_snapshot_5_001.json",
    "rtl1_sth_001.json",
)
NEGATIVE = (
    "rtl1_bad_root_001.json",
    "rtl1_check_rules_001.json",
    "rtl1_decode_rules_001.json",
    "rtl1_split_view_pair_001.json",
)
# The RFC 6962 reference roots of 0..=8 leaves (certificate-transparency's
# merkle_tree_test), as published.
RFC6962_ROOTS = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
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


def build_sth(inputs, signer_seeds):
    """A tree head built and signed from a vector's ``sth`` inputs."""
    body = tlog.encode_sth_body(
        inputs["tree_size"],
        bytes.fromhex(inputs["root_hash_hex"]),
        inputs["timestamp_ms"],
        bytes.fromhex(inputs["key_set_digest_hex"]),
    )
    return tlog.build_sth(body, [(i, signer_seeds[i]) for i in inputs["signers"]])


def check_snapshot(inputs, expected, ks, signer_seeds):
    """Rebuild a snapshot from its entries and head inputs, compare byte for
    byte, decode, check; return the decoded snapshot."""
    entries = entries_of(inputs["entries"])
    root = tlog.mth(entries)
    assert root.hex() == expected["root_hex"]
    assert inputs["sth"]["root_hash_hex"] == root.hex()
    assert inputs["sth"]["tree_size"] == len(entries) == expected["tree_size"]
    sth = build_sth(inputs["sth"], signer_seeds)
    assert sth.hex() == expected["sth_hex"]
    data = tlog.encode_snapshot(entries, sth)
    assert data.hex() == expected["snapshot_hex"]
    snap = tlog.decode_snapshot(data)
    assert snap.entries == entries
    assert snap.sth.data == sth
    assert tlog.encode_snapshot(snap.entries, snap.sth.data) == data
    assert expected["check"] == "OK"
    tlog.check(snap, ks)
    return snap


def test_the_files():
    assert sorted(p.name for p in VEC.glob("rtl1_*.json")) == sorted(FILES)
    assert sorted(p.name for p in (VEC / "negative").glob("rtl1_*.json")) == sorted(NEGATIVE)
    for name in list(FILES) + [f"negative/{n}" for n in NEGATIVE]:
        v = load(name)
        assert v["protocol_version"] == "rvn1" and v["deterministic"] is True, name


def test_constants():
    assert tlog.MAX_STH_LEN == 609
    assert tlog.MAX_SNAPSHOT_LEN == 58_023


def test_rtl1_mth_001():
    v = load("rtl1_mth_001.json")
    entries = entries_of(v["inputs"]["entries"])
    assert len(entries) == 17
    assert [e.encode().hex() for e in entries] == v["expected"]["entries_hex"]
    assert [tlog.leaf_hash(e.encode()).hex() for e in entries] == v["expected"]["leaf_hashes_hex"]
    assert [tlog.decode_entry(e.encode()) for e in entries] == entries
    roots = v["expected"]["roots"]
    assert [r["tree_size"] for r in roots] == list(range(1, 18))
    for r in roots:
        assert tlog.mth(entries[: r["tree_size"]]).hex() == r["root_hex"], r["tree_size"]
    # By hand for the first sizes.
    l = [tlog.leaf_hash(e.encode()) for e in entries]
    n = tlog.node_hash
    assert roots[0]["root_hex"] == l[0].hex()
    assert roots[1]["root_hex"] == n(l[0], l[1]).hex()
    assert roots[2]["root_hex"] == n(n(l[0], l[1]), l[2]).hex()
    four = n(n(l[0], l[1]), n(l[2], l[3]))
    assert roots[4]["root_hex"] == n(four, l[4]).hex()
    assert roots[6]["root_hex"] == n(four, n(n(l[4], l[5]), l[6])).hex()
    # The RFC 6962 reference.
    leaves = [bytes.fromhex(h) for h in v["inputs"]["rfc6962_leaves_hex"]]
    hashes = [tlog.leaf_hash(x) for x in leaves]
    got = [{"leaves": k, "root_hex": tlog.root_of_leaf_hashes(hashes[:k]).hex()} for k in range(9)]
    assert got == v["expected"]["rfc6962_roots"]
    assert [g["root_hex"] for g in got] == list(RFC6962_ROOTS)


def test_rtl1_sth_001():
    v = load("rtl1_sth_001.json")
    ks = key_set(v["inputs"]["key_set"])
    entries = entries_of(v["inputs"]["entries"])
    inputs = v["inputs"]["sth"]
    assert inputs["root_hash_hex"] == tlog.mth(entries).hex()
    assert inputs["tree_size"] == len(entries) == 5
    assert inputs["key_set_digest_hex"] == ks.digest().hex()
    data = build_sth(inputs, seeds(v["inputs"]["key_set"]))
    assert data.hex() == v["expected"]["sth_hex"]
    sth = tlog.decode_sth(data)
    assert sth.signing_input().hex() == v["expected"]["signing_input_hex"]
    assert sth.signing_input() == b"rvn1/tlog/sth/v1\0" + data[:88]
    assert [i for i, _ in sth.sigs] == inputs["signers"]
    assert v["expected"]["verify"] == "OK"
    sth.verify(ks)


def test_rtl1_snapshot_5_001():
    v = load("rtl1_snapshot_5_001.json")
    ks = key_set(v["inputs"]["key_set"])
    snap = check_snapshot(v["inputs"]["snapshot"], v["expected"]["snapshot"], ks, seeds(v["inputs"]["key_set"]))
    for probe in v["expected"]["contains"]:
        assert tlog.contains(snap.entries, probe["type"], bytes.fromhex(probe["digest_hex"])) == probe["contains"]
    # The first entry is the test key set itself.
    assert snap.entries[0] == tlog.Entry(tlog.KEY_SET, ks.digest(), snap.entries[0].logged_at_ms)


def test_rtl1_consistency_001():
    v = load("rtl1_consistency_001.json")
    ks = key_set(v["inputs"]["key_set"])
    s = seeds(v["inputs"]["key_set"])
    snaps = {name: check_snapshot(v["inputs"][name], v["expected"][name], ks, s) for name in ("five", "eight")}
    got = [
        {"stored": p["stored"], "new": p["new"], "consistency": tlog.consistency(snaps[p["stored"]].entries, snaps[p["new"]].entries)}
        for p in v["expected"]["pairs"]
    ]
    assert got == v["expected"]["pairs"]
    assert [p["consistency"] for p in got] == ["EXTENDS", "OLDER", "SAME"]


def test_rtl1_split_view_pair_001():
    v = load("negative/rtl1_split_view_pair_001.json")
    ks = key_set(v["inputs"]["key_set"])
    s = seeds(v["inputs"]["key_set"])
    a = check_snapshot(v["inputs"]["a"], v["expected"]["a"], ks, s)
    b = check_snapshot(v["inputs"]["b"], v["expected"]["b"], ks, s)
    first = next(i for i, (x, y) in enumerate(zip(a.entries, b.entries)) if x != y)
    assert first == v["expected"]["first_difference"]
    assert tlog.consistency(a.entries, b.entries) == v["expected"]["consistency_a_then_b"] == "SPLIT"
    assert tlog.consistency(b.entries, a.entries) == v["expected"]["consistency_b_then_a"] == "SPLIT"


def test_rtl1_bad_root_001():
    v = load("negative/rtl1_bad_root_001.json")
    ks = key_set(v["inputs"]["key_set"])
    snap = tlog.decode_snapshot(bytes.fromhex(v["inputs"]["snapshot_hex"]))
    assert v["expected"]["decode"] == "OK"
    snap.sth.verify(ks)
    assert v["expected"]["sth_verify"] == "OK"
    assert snap.sth.root_hash.hex() == v["expected"]["sth_root_hex"]
    assert tlog.mth(snap.entries).hex() == v["expected"]["computed_root_hex"]
    assert v["expected"]["sth_root_hex"] != v["expected"]["computed_root_hex"]
    with pytest.raises(tlog.LogCheckError) as err:
        tlog.check(snap, ks)
    assert err.value.code == v["expected"]["check"] == "BAD_ROOT"
    # The head is rtl1_sth_001's.
    assert snap.sth.data.hex() == load("rtl1_sth_001.json")["expected"]["sth_hex"]


def test_rtl1_check_rules_001():
    v = load("negative/rtl1_check_rules_001.json")
    ks = key_set(v["inputs"]["key_set"])
    other = key_set(v["inputs"]["other_key_set"])
    errors = {e["name"]: e["error"] for e in v["expected"]["errors"]}
    assert len(errors) == len(v["inputs"]["cases"])
    for case in v["inputs"]["cases"]:
        snap = tlog.decode_snapshot(bytes.fromhex(case["snapshot_hex"]))
        with pytest.raises(tlog.LogCheckError) as err:
            tlog.check(snap, ks)
        assert err.value.code == errors[case["name"]], case["name"]
        if case["name"] == "wrong_key_set":
            tlog.check(snap, other)
    assert set(errors.values()) == {
        "WRONG_KEY_SET",
        "KEY_INDEX_ORDER",
        "UNKNOWN_KEY_INDEX",
        "BELOW_THRESHOLD",
        "BAD_SIGNATURE",
        "BAD_ROOT",
    }


def test_rtl1_decode_rules_001():
    v = load("negative/rtl1_decode_rules_001.json")
    errors = {e["name"]: e["error"] for e in v["expected"]["errors"]}
    assert len(errors) == len(v["inputs"]["cases"])
    decoders = {"sth": tlog.decode_sth, "snapshot": tlog.decode_snapshot}
    for case in v["inputs"]["cases"]:
        data = bytes.fromhex(case["hex"])
        if "zero_pad_to" in case:
            data = data + bytes(case["zero_pad_to"] - len(data))
        with pytest.raises(tlog.Rtl1Error) as err:
            decoders[case["object"]](data)
        assert err.value.code == errors[case["name"]], case["name"]
    assert len(set(errors.values())) == 12


def test_entry_types_and_the_cap():
    e = tlog.Entry(tlog.ADVISORY, bytes(range(32)), 7)
    assert tlog.decode_entry(e.encode()) == e
    with pytest.raises(tlog.Rtl1Error) as err:
        tlog.decode_entry(b"\x00" + e.encode()[1:])
    assert err.value.code == "BAD_ENTRY_TYPE"
    # A type this version does not know is kept and never matched.
    unknown = tlog.decode_entry(b"\x7f" + e.encode()[1:])
    assert unknown.type == 0x7F and not tlog.contains([unknown], tlog.ADVISORY, e.digest)
    # The cap: 1,400 entries decode, 1,401 do not.
    v = load("rtl1_sth_001.json")
    s = seeds(v["inputs"]["key_set"])
    ks = key_set(v["inputs"]["key_set"])
    for count, want in ((1_400, None), (1_401, "TOO_MANY_ENTRIES")):
        entries = [tlog.Entry(1 + i % 3, i.to_bytes(32, "big"), i) for i in range(count)]
        body = tlog.encode_sth_body(count, tlog.mth(entries), 0, ks.digest())
        data = tlog.encode_snapshot(entries, tlog.build_sth(body, [(0, s[0]), (2, s[2])]))
        if want is None:
            tlog.check(tlog.decode_snapshot(data), ks)
        else:
            with pytest.raises(tlog.Rtl1Error) as err:
                tlog.decode_snapshot(data)
            assert err.value.code == want
