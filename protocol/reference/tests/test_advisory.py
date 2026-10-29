"""RAVEN Security Advisory V1 (RAVEN_SECURITY_ADVISORY_V1.md, draft): the
Python reference checks every shared-vectors/rvn1/update vector (written by
Rust under RAVEN_REGEN_SECURITY_VECTORS=1) against its own codec, builds
every signed advisory again byte for byte, and checks every refusal."""

import hashlib
import json
from pathlib import Path

import pytest

from raven_protocol import advisory as ad

REPO = Path(__file__).resolve().parents[3]
VEC = REPO / "shared-vectors/rvn1/update"
FILES = (
    "keyset_001.json",
    "rad1_key_rotation_001.json",
    "rad1_three_of_three_001.json",
    "rad1_two_of_three_001.json",
)
NEGATIVE = (
    "keyset_rules_001.json",
    "rad1_bad_sig_among_good_001.json",
    "rad1_broken_chain_pair_001.json",
    "rad1_decode_rules_001.json",
    "rad1_dup_key_index_001.json",
    "rad1_equivocation_pair_001.json",
    "rad1_one_sig_001.json",
    "rad1_rollback_pair_001.json",
    "rad1_wrong_keyset_001.json",
)


def load(name):
    return json.loads((VEC / name).read_text(encoding="utf-8"))


def key_set(v):
    """The key set of a vector's ``key_set`` object, built from its seeds."""
    ks = ad.KeySet.of_seeds(v["threshold"], [bytes.fromhex(s) for s in v["seeds_hex"]])
    assert ks.encode().hex() == v["key_set_hex"]
    assert ks.digest().hex() == v["key_set_digest_hex"]
    assert [k.hex() for k in ks.keys] == v["public_keys_hex"]
    assert ad.KeySet.decode(ks.encode()).encode() == ks.encode()
    return ks


def seeds(v):
    return [bytes.fromhex(s) for s in v["seeds_hex"]]


def rebuild(inputs, signer_seeds):
    """An advisory built and signed from a vector's inputs."""
    entries = [
        ad.Entry(e["kind"], e["severity"], e["target"], bytes.fromhex(e["arg_hex"]), e["text_id"])
        for e in inputs["entries"]
    ]
    body = ad.encode_body(
        inputs["serial"],
        inputs["issued_at_ms"],
        bytes.fromhex(inputs["key_set_digest_hex"]),
        bytes.fromhex(inputs["prev_digest_hex"]),
        entries,
    )
    return ad.build(body, [(i, signer_seeds[i]) for i in inputs["signers"]])


def summary(a):
    """What each entry says, as the vectors write it."""
    out = []
    for e in a.entries:
        v = {
            "kind": ad.kind_name(e.kind),
            "severity": ad.SEVERITY_NAMES[e.severity],
            "target": e.target,
            "understood": ad.understood(e.kind),
        }
        if e.kind == ad.RELEASE_FLOOR:
            v["release_floor"] = int.from_bytes(e.arg, "big")
        if e.kind == ad.NOTICE:
            v["notice_text"] = e.arg.decode("utf-8")
        if e.kind == ad.KEY_SET:
            v["key_set_digest_hex"] = ad.KeySet.decode(e.arg).digest().hex()
        out.append(v)
    return out


def check_advisory(inputs, expected, ks, signer_seeds):
    """Build, compare byte for byte, decode, verify; return the advisory."""
    data = rebuild(inputs, signer_seeds)
    assert data.hex() == expected["advisory_hex"]
    a = ad.decode(data)
    assert a.signed_len == expected["signed_len"]
    assert a.signing_input().hex() == expected["signing_input_hex"]
    assert a.signing_input() == ad.SIGNING_DOMAIN + data[: a.signed_len]
    assert a.digest().hex() == expected["advisory_digest_hex"]
    assert a.digest() == hashlib.sha256(b"rvn1/advisory/digest/v1\0" + data).digest()
    assert summary(a) == expected["entries"]
    assert [i for i, _ in a.sigs] == inputs["signers"]
    a.verify(ks)
    return a


def test_the_files():
    # The keyset_* and rad1_* files (other update vectors have their own tests).
    def mine(d):
        return sorted(p.name for p in d.glob("*.json") if p.name.startswith(("keyset_", "rad1_")))

    assert mine(VEC) == sorted(FILES)
    assert mine(VEC / "negative") == sorted(NEGATIVE)
    for name in list(FILES) + [f"negative/{n}" for n in NEGATIVE]:
        v = load(name)
        assert v["protocol_version"] == "rvn1" and v["deterministic"] is True, name


def test_keyset_001():
    v = load("keyset_001.json")
    assert v["inputs"]["alg"] == ad.KEYSET_ALG_ED25519
    assert v["inputs"]["seeds_hex"] == [bytes([b] * 32).hex() for b in (0x11, 0x22, 0x33)]
    ks = ad.KeySet.of_seeds(2, seeds(v["inputs"]))
    assert [k.hex() for k in ks.keys] == v["expected"]["public_keys_hex"]
    assert ks.encode().hex() == v["expected"]["key_set_hex"]
    assert ks.digest() == hashlib.sha256(b"rvn1/release-keys/v1\0" + ks.encode()).digest()
    assert ks.digest().hex() == v["expected"]["key_set_digest_hex"]


def test_two_and_three_of_three():
    v1 = load("rad1_two_of_three_001.json")
    ks = key_set(v1["inputs"]["key_set"])
    s = seeds(v1["inputs"]["key_set"])
    one = check_advisory(v1["inputs"]["advisory"], v1["expected"]["advisory"], ks, s)
    assert v1["expected"]["verify"] == "OK"
    assert one.serial == 1 and one.prev_digest == bytes(32)
    v2 = load("rad1_three_of_three_001.json")
    assert v2["inputs"]["previous_hex"] == one.data.hex()
    two = check_advisory(v2["inputs"]["advisory"], v2["expected"]["advisory"], ks, s)
    assert two.prev_digest == one.digest()
    assert ad.succession((one.serial, one.digest()), two) == v2["expected"]["succession"] == "NEXT"
    # Every kind, and one this version does not know.
    assert sorted({e.kind for e in two.entries}) == [1, 2, 3, 4, 0x7F]
    assert not ad.understood(0x7F)


def test_key_rotation():
    v = load("rad1_key_rotation_001.json")
    cur = key_set(v["inputs"]["key_set"])
    nxt = key_set(v["inputs"]["next_key_set"])
    three = check_advisory(
        v["inputs"]["rotation"], v["expected"]["rotation"], cur, seeds(v["inputs"]["key_set"])
    )
    named = [ad.KeySet.decode(e.arg) for e in three.entries if e.kind == ad.KEY_SET]
    assert [k.encode() for k in named] == [nxt.encode()]
    four = check_advisory(
        v["inputs"]["after"], v["expected"]["after"], nxt, seeds(v["inputs"]["next_key_set"])
    )
    with pytest.raises(ad.SigError) as e:
        four.verify(cur)
    assert e.value.code == v["expected"]["after_verify_old"] == "WRONG_KEY_SET"
    assert ad.succession((three.serial, three.digest()), four) == v["expected"]["succession"] == "NEXT"


@pytest.mark.parametrize(
    "name, code",
    [
        ("rad1_one_sig_001.json", "BELOW_THRESHOLD"),
        ("rad1_dup_key_index_001.json", "KEY_INDEX_ORDER"),
        ("rad1_bad_sig_among_good_001.json", "BAD_SIGNATURE"),
        ("rad1_wrong_keyset_001.json", "WRONG_KEY_SET"),
    ],
)
def test_forged(name, code):
    v = load(f"negative/{name}")
    ks = key_set(v["inputs"]["key_set"])
    a = ad.decode(bytes.fromhex(v["inputs"]["advisory_hex"]))
    assert v["expected"]["decode"] == "OK"
    with pytest.raises(ad.SigError) as e:
        a.verify(ks)
    assert e.value.code == v["expected"]["verify"] == code
    if "signed_by_key_set" in v["inputs"]:
        a.verify(key_set(v["inputs"]["signed_by_key_set"]))
        assert v["expected"]["verify_under_signed_by"] == "OK"


@pytest.mark.parametrize(
    "name, result",
    [
        ("rad1_rollback_pair_001.json", "ROLLBACK"),
        ("rad1_equivocation_pair_001.json", "EQUIVOCATION"),
        ("rad1_broken_chain_pair_001.json", "EQUIVOCATION"),
    ],
)
def test_pairs(name, result):
    v = load(f"negative/{name}")
    ks = key_set(v["inputs"]["key_set"])
    stored = ad.decode(bytes.fromhex(v["inputs"]["stored_hex"]))
    new = ad.decode(bytes.fromhex(v["inputs"]["new_hex"]))
    stored.verify(ks)
    new.verify(ks)
    assert v["expected"]["verify"] == ["OK", "OK"]
    assert stored.serial == v["expected"]["stored_serial"]
    assert stored.digest().hex() == v["expected"]["stored_digest_hex"]
    assert new.serial == v["expected"]["new_serial"]
    assert new.digest().hex() == v["expected"]["new_digest_hex"]
    assert ad.succession((stored.serial, stored.digest()), new) == v["expected"]["succession"] == result


def test_succession_cases():
    v1 = load("rad1_two_of_three_001.json")
    v2 = load("rad1_three_of_three_001.json")
    v3 = load("rad1_key_rotation_001.json")
    one = ad.decode(bytes.fromhex(v1["expected"]["advisory"]["advisory_hex"]))
    two = ad.decode(bytes.fromhex(v2["expected"]["advisory"]["advisory_hex"]))
    four = ad.decode(bytes.fromhex(v3["expected"]["after"]["advisory_hex"]))
    assert ad.succession(None, two) == "FIRST"
    assert ad.succession((1, one.digest()), one) == "SAME"
    assert ad.succession((1, one.digest()), four) == "GAP"


def test_decode_rules():
    v = load("negative/rad1_decode_rules_001.json")
    errors = {e["name"]: e["error"] for e in v["expected"]["errors"]}
    assert len(errors) == len(v["inputs"]["cases"])
    seen = set()
    for case in v["inputs"]["cases"]:
        data = bytes.fromhex(case["advisory_hex"])
        if "zero_pad_to" in case:
            ad.decode(data)  # the base decodes
            data = data + bytes(case["zero_pad_to"] - len(data))
        with pytest.raises(ad.Rad1Error) as e:
            ad.decode(data)
        assert e.value.code == errors[case["name"]], case["name"]
        seen.add(e.value.code)
    assert len(seen) == 15


def test_keyset_rules():
    v = load("negative/keyset_rules_001.json")
    errors = {e["name"]: e["error"] for e in v["expected"]["errors"]}
    for case in v["inputs"]["cases"]:
        with pytest.raises(ad.KeySetError) as e:
            ad.KeySet.decode(bytes.fromhex(case["key_set_hex"]))
        assert e.value.code == errors[case["name"]], case["name"]


def test_single_byte_changes_fail():
    """Any single-byte change of a signed advisory fails to decode or verify."""
    v = load("rad1_three_of_three_001.json")
    ks = key_set(v["inputs"]["key_set"])
    data = bytes.fromhex(v["expected"]["advisory"]["advisory_hex"])

    def fails(m):
        try:
            ad.decode(m).verify(ks)
        except (ad.Rad1Error, ad.SigError):
            return True
        return False

    assert not fails(data)
    for i in range(len(data)):
        m = bytearray(data)
        m[i] ^= 0x01
        assert fails(bytes(m)), i
    assert fails(data[:-1]) and fails(data + b"\0")


def test_points():
    """§2.1 rule 6 agrees with the strict blocklist and the curve equation."""
    base = ad.public_key(bytes([0x11] * 32))
    assert ad.usable_key(base)
    for bad in (
        "01" + "00" * 31,  # identity
        "ecff" + "ff" * 29 + "7f",  # y = p - 1, order 2
        "02" + "00" * 31,  # not on the curve
        "f0" + "ff" * 30 + "7f",  # y = p + 3: non-canonical
    ):
        assert not ad.usable_key(bytes.fromhex(bad)), bad
    # y = 3 itself is a curve point of large order.
    assert ad.usable_key(bytes([3]) + bytes(31))
