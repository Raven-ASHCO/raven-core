"""RAVEN LAN Beacon V1 (RAVEN_LAN_BEACON_V1.md, draft): the Python reference
recomputes every shared-vectors/rvn1/lan_beacon vector (written by Rust) from
its inputs. Three-language parity per RAVEN_PRIVATE_RENDEZVOUS_V1 §13.1; Swift
is pending."""

import ipaddress
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from raven_protocol import ed25519_strict
from raven_protocol import lan_beacon as lb

REPO = Path(__file__).resolve().parents[3]
VEC = REPO / "shared-vectors/rvn1/lan_beacon"
FILES = (
    "lbcn_pair_keys_001.json",
    "lbcn_query_001.json",
    "lbcn_answer_001.json",
    "lbcn_negative_001.json",
    "lbcn_query_padded_001.json",
    "lbcn_answer_padded_001.json",
)
RFC8032_TEST3_SEED = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"


def load(name):
    return json.loads((VEC / name).read_text(encoding="utf-8"))


def ip(text):
    return ipaddress.ip_address(text)


def people(vector):
    """name -> (seed, Ed25519 public key) of a vector's inputs, checked."""
    out = {}
    for name, person in vector["inputs"]["people"].items():
        seed = bytes.fromhex(person["seed_hex"])
        public = lb.ed25519_public(seed)
        assert public.hex() == person["ed_public_hex"], name
        out[name] = (seed, public)
    return out


def test_the_six_files_and_their_people():
    assert sorted(p.name for p in VEC.glob("*.json")) == sorted(FILES)
    v1 = json.loads((REPO / "shared-vectors/v1/identities.json").read_text())["identities"]
    first = load(FILES[0])["inputs"]["people"]
    for name in ("alice", "bob"):
        assert first[name]["seed_hex"] == v1[name]["ed_private_hex"]
        assert first[name]["ed_public_hex"] == v1[name]["ed_public_hex"]
    assert first["carol"]["seed_hex"] == RFC8032_TEST3_SEED
    assert first["dave"]["seed_hex"] == "44" * 32 != v1["dave"]["ed_private_hex"]
    for name in FILES:
        v = load(name)
        assert v["protocol_version"] == "rvn1" and v["deterministic"] is True
        for who, person in v["inputs"]["people"].items():
            assert person == first[who], (name, who)


def test_pair_keys_vector():
    v = load("lbcn_pair_keys_001.json")
    i, e = v["inputs"], v["expected"]
    folks = people(v)
    assert i["r2_pair_salt_ascii"].encode() == lb.R2_PAIR_SALT
    assert i["medium_lan"] == lb.MEDIUM_LAN == 0x02
    assert i["epoch_len_s"] == lb.EPOCH_SECS
    epoch = lb.epoch_at(i["epoch_seconds"])
    assert epoch == e["epoch"] == 2833333
    for name, (seed, public) in folks.items():
        row = e["people"][name]
        scalar = lb.x25519_scalar(seed)
        assert scalar.hex() == row["x25519_scalar_hex"]
        # The map by hand equals X25519's own public key of the scalar.
        u = lb.montgomery_u(public)
        assert u == X25519PrivateKey.from_private_bytes(scalar).public_key().public_bytes_raw()
        assert u.hex() == row["montgomery_u_hex"]
    assert [[r["a"], r["b"]] for r in e["pairs"]] == i["pairs"]
    for row in e["pairs"]:
        (a, ap), (b, bp) = folks[row["a"]], folks[row["b"]]
        z_by_a = lb.x25519(lb.x25519_scalar(a), lb.montgomery_u(bp))
        z_by_b = lb.x25519(lb.x25519_scalar(b), lb.montgomery_u(ap))
        assert z_by_a == z_by_b != bytes(32)
        assert (z_by_a.hex(), z_by_b.hex()) == (row["z_by_a_hex"], row["z_by_b_hex"])
        (lo_key, lo), (hi_key, hi) = sorted([(ap, row["a"]), (bp, row["b"])])
        assert (row["lo"], row["hi"]) == (lo, hi)
        assert row["root_info_hex"] == (b"root" + lo_key + hi_key).hex()
        root = lb.pair_root(a, bp)
        assert root == lb.pair_root(b, ap)
        assert root.hex() == row["k_root_hex"]
        lan = lb.medium_key(root, lb.MEDIUM_LAN)
        assert lan.hex() == row["k_lan_hex"]
        assert lan != lb.medium_key(root, lb.MEDIUM_BLE) and lan != root
        k, mirror = lb.pair_keys(a, bp), lb.pair_keys(b, ap)
        assert k.peer == bp and mirror.peer == ap
        assert (k.q_out, k.q_in, k.r_out, k.r_in) == (mirror.q_in, mirror.q_out, mirror.r_in, mirror.r_out)
        assert k.q_out.hex() == row["k_query_a_to_b_hex"]
        assert k.q_in.hex() == row["k_query_b_to_a_hex"]
        assert k.r_out.hex() == row["k_reply_a_to_b_hex"]
        assert k.r_in.hex() == row["k_reply_b_to_a_hex"]
        assert len({k.q_out, k.q_in, k.r_out, k.r_in, lan, root}) == 6
        assert lb.epoch_key(k.q_out, epoch).hex() == row["k_query_epoch_a_to_b_hex"]
        assert lb.epoch_key(k.q_in, epoch).hex() == row["k_query_epoch_b_to_a_hex"]


def test_query_vector():
    v = load("lbcn_query_001.json")
    i, e = v["inputs"], v["expected"]
    folks = people(v)
    epoch = lb.epoch_at(i["epoch_seconds"])
    assert epoch == e["epoch"]
    src = ip(i["src"])
    assert lb.ip16(src).hex() == e["src_ip16_hex"]
    querier = folks[i["querier"]][0]
    targets = [lb.pair_keys(querier, folks[t["name"]][1]) for t in i["targets"]]
    positions = [t["slot"] for t in i["targets"]]
    assert [p["slot"] for p in i["padding"]] == [s for s in range(lb.SLOTS) if s not in positions]
    padding = [bytes.fromhex(p["hex"]) for p in i["padding"]]
    nonce = bytes.fromhex(i["nonce_hex"])
    q = lb.build_query(nonce, positions, padding, epoch, src, i["port"], targets)
    assert len(q) == e["query_len"] == lb.QUERY_LEN == 160
    assert q.hex() == e["query_hex"]
    for row in e["slots"]:
        k = lb.pair_keys(querier, folks[row["target"]][1])
        h = lb.query_tag(k.q_out, epoch, nonce, src)
        assert h.hex() == row["h_hex"]
        at = lb.NONCE_LEN + row["slot"] * lb.SLOT_LEN
        assert q[at : at + lb.SLOT_LEN].hex() == row["slot_hex"]

    def found(receiver, at_src, now):
        names = i["books"][receiver]
        book = [lb.pair_keys(folks[receiver][0], folks[n][1]) for n in names]
        return [{"contact": names[ix], "port": port} for ix, port in lb.match_query(q, at_src, now, book)]

    def bob_port(at_src, now):
        hits = found("bob", at_src, now)
        assert all(hit["contact"] == "alice" for hit in hits)
        return hits[0]["port"] if hits else None

    for row in e["matches"]:
        assert found(row["receiver"], src, epoch) == row["found"], row["receiver"]
    for row in e["epoch_window_bob"]:
        assert bob_port(src, row["receiver_epoch"]) == row["port"], row["receiver_epoch"]
    for row in e["other_sources_bob"]:
        assert bob_port(ip(row["src"]), epoch) == row["port"], row["src"]
    # What RAVEN_LAN_BEACON_V1 §6 asks: bob and carol get alice's port, dave
    # (not named) and alice herself (her echo) nobody; e +- 1 found, e +- 2
    # not; another source not.
    alice = [{"contact": "alice", "port": 7420}]
    assert {r["receiver"]: r["found"] for r in e["matches"]} == {
        "alice": [], "bob": alice, "carol": alice, "dave": []
    }
    assert [r["port"] for r in e["epoch_window_bob"]] == [None, 7420, 7420, 7420, None]
    assert [r["port"] for r in e["other_sources_bob"]] == [None, None, 7420, None, None]


def test_answer_vector():
    v = load("lbcn_answer_001.json")
    i, e = v["inputs"], v["expected"]
    folks = people(v)
    assert i["q_nonce_hex"] == load("lbcn_query_001.json")["inputs"]["nonce_hex"]
    keys = lb.pair_keys(folks[i["answerer"]][0], folks[i["querier"]][1])
    q_nonce, r_nonce = bytes.fromhex(i["q_nonce_hex"]), bytes.fromhex(i["r_nonce_hex"])
    src, dst = ip(i["src"]), ip(i["dst"])
    assert (lb.ip16(src).hex(), lb.ip16(dst).hex()) == (e["src_ip16_hex"], e["dst_ip16_hex"])
    h = lb.answer_tag(keys.r_out, q_nonce, r_nonce, src, dst)
    assert h.hex() == e["h_hex"]
    a = lb.build_answer(r_nonce, keys, q_nonce, src, dst, i["port"])
    assert len(a) == e["answer_len"] == lb.ANSWER_LEN == 48
    assert a.hex() == e["answer_hex"]
    for row in e["opens"]:
        k = lb.pair_keys(folks[row["opener"]][0], folks[row["peer"]][1])
        got = lb.open_answer(a, k, bytes.fromhex(row["q_nonce_hex"]), ip(row["src"]), ip(row["dst"]))
        assert got == row["port"], row["what"]
    assert [r["port"] for r in e["opens"]] == [7420, 7420] + [None] * 6


def test_negative_vector():
    v = load("lbcn_negative_001.json")
    i, e = v["inputs"], v["expected"]
    folks = people(v)
    own, own_public = folks[i["own"]]
    for row in e["contact_keys"]:
        key = bytes.fromhex(row["peer_pub_hex"])
        assert len(key) == row["len"] and row["result"] == "bad_key"
        with pytest.raises(lb.BadKey):
            lb.pair_root(own, key)
        with pytest.raises(lb.BadKey):
            lb.pair_keys(own, key)
    scalar = lb.x25519_scalar(own)
    for row in e["shared_secrets"]:
        u = bytes.fromhex(row["u_hex"])
        assert row["result"] == "non_contributory"
        assert lb.x25519(scalar, u).hex() == row["z_hex"] == "00" * 32
        with pytest.raises(lb.NonContributory):
            lb.root_from(scalar, u, own_public, folks["bob"][1])
    epoch = lb.epoch_at(i["epoch_seconds"])
    bob_book = [lb.pair_keys(folks["bob"][0], folks[n][1]) for n in i["books"]["bob"]]
    alice_for_bob = lb.pair_keys(own, folks["bob"][1])
    q_nonce = bytes.fromhex(i["q_nonce_hex"])
    lengths = []
    for row in e["datagrams"]:
        d = bytes.fromhex(row["datagram_hex"])
        assert len(d) == row["len"]
        lengths.append(len(d))
        assert lb.match_query(d, ip(i["query_src"]), epoch, bob_book) == row["bob_finds"] == []
        opened = lb.open_answer(d, alice_for_bob, q_nonce, ip(i["answer_src"]), ip(i["answer_dst"]))
        assert opened is None and row["alice_opens"] is None, row["what"]
    assert sorted(lengths) == [0, 47, 48, 64, 159, 192]


def test_small_order_and_canonical_rules_agree_with_the_strict_verifier():
    """The beacon's small-order points are the strict Ed25519 verifier's
    blocklist (with the sign bit), and every other refused 32-byte key is
    refused for another reason: not canonical, not a point or the own key."""
    v = load("lbcn_negative_001.json")
    own_public = people(v)[v["inputs"]["own"]][1]
    for row in v["expected"]["contact_keys"]:
        key = bytes.fromhex(row["peer_pub_hex"])
        if row["what"].startswith("small order"):
            point = lb._decompress(key)
            assert lb._compress(point) == key and lb._small_order(point), row["what"]
            assert ed25519_strict.is_small_order_encoding(key), row["what"]
        elif row["what"].startswith("not canonical"):
            assert lb._compress(lb._decompress(key)) != key, row["what"]
        elif row["what"].startswith("not a point"):
            with pytest.raises(lb.BadKey, match="not a point"):
                lb._decompress(key)
        elif len(key) == 32:
            assert key == own_public
    # A real contact key passes every check.
    folks = people(load("lbcn_pair_keys_001.json"))
    for name in ("bob", "carol", "dave"):
        point = lb.check_contact_key(own_public, folks[name][1])
        assert not lb._small_order(point)


def test_wrong_lengths_and_port_zero_are_refused():
    folks = people(load("lbcn_pair_keys_001.json"))
    (a, ap), (b, bp) = folks["alice"], folks["bob"]
    a_b, b_a = lb.pair_keys(a, bp), lb.pair_keys(b, ap)
    src, bob_ip = ip("192.168.1.20"), ip("192.168.1.30")
    q = lb.build_query(bytes(16), [0], [bytes(18)] * 7, 1, src, 7420, [a_b])
    assert lb.match_query(q, src, 1, [b_a]) == [(0, 7420)]
    for cut in (q[:-1], q + bytes(32), q[:48], b""):
        assert lb.match_query(cut, src, 1, [b_a]) == []
    ans = lb.build_answer(bytes(16), b_a, bytes(16), bob_ip, src, 7420)
    assert lb.open_answer(ans, a_b, bytes(16), bob_ip, src) == 7420
    for cut in (ans[:-1], ans + bytes(16), q, b""):
        assert lb.open_answer(cut, a_b, bytes(16), bob_ip, src) is None
    # Any tail of up to 31 (15) bytes is ignored, whatever its bytes.
    for n in range(lb.QUERY_TAIL_MAX + 1):
        for fill in (b"\x00", b"\xff"):
            assert lb.match_query(lb.with_tail(q, fill * n), src, 1, [b_a]) == [(0, 7420)]
    for n in range(lb.ANSWER_TAIL_MAX + 1):
        for fill in (b"\x00", b"\xff"):
            assert lb.open_answer(lb.with_tail(ans, fill * n), a_b, bytes(16), bob_ip, src) == 7420
    zero = lb.build_answer(bytes(16), b_a, bytes(16), bob_ip, src, 0)
    assert lb.open_answer(zero, a_b, bytes(16), bob_ip, src) is None
    # The epoch window does not wrap at the ends of u64.
    q0 = lb.build_query(bytes(16), [3], [bytes(18)] * 7, 0, src, 1, [a_b])
    assert lb.match_query(q0, src, 0, [b_a]) == [(0, 1)]
    assert lb.match_query(q0, src, lb.U64_MAX, [b_a]) == []
    # An IPv6 zone is never part of ip16.
    assert lb.ip16(ip("fe80::1%en0")) == lb.ip16(ip("fe80::1")) == bytes.fromhex("fe80" + "00" * 13 + "01")


def test_length_ranges_and_tails():
    """RAVEN_LAN_BEACON_V1 §3 (the Phase 6b amendment): 160..=191 bytes is a
    query, 48..=63 an answer, anything else nothing; a tail goes only after a
    whole query or answer and is at most 31 (15) bytes."""
    for length in range(300):
        want = "query" if 160 <= length <= 191 else "answer" if 48 <= length <= 63 else None
        assert lb.kind_of(length) == want, length
    assert (lb.QUERY_MAX_LEN, lb.ANSWER_MAX_LEN) == (191, 63)
    assert lb.with_tail(bytes(160), bytes(31)) == bytes(191)
    assert lb.with_tail(bytes(48), b"") == bytes(48)
    for datagram, tail in ((bytes(160), bytes(32)), (bytes(48), bytes(16)), (bytes(161), b"")):
        with pytest.raises(ValueError):
            lb.with_tail(datagram, tail)


def test_query_padded_vector():
    v = load("lbcn_query_padded_001.json")
    i, e = v["inputs"], v["expected"]
    folks = people(v)
    base = load(i["query_vector"])
    assert i["query_hex"] == base["expected"]["query_hex"]
    q = bytes.fromhex(i["query_hex"])
    epoch = lb.epoch_at(i["epoch_seconds"])
    assert epoch == e["epoch"] and e["max_len"] == lb.QUERY_MAX_LEN
    src = ip(i["src"])
    assert [row["tail_len"] for row in e["padded"]] == i["tail_lens"] == [1, 16, 31]
    alone = {row["receiver"]: row["found"] for row in base["expected"]["matches"]}
    for row in e["padded"]:
        n = row["tail_len"]
        tail = bytes((i["tail_first_byte"] + k) & 0xFF for k in range(n))
        d = lb.with_tail(q, tail)
        assert d.hex() == row["datagram_hex"] and len(d) == row["len"] == 160 + n
        assert lb.kind_of(len(d)) == "query"
        for m in row["matches"]:
            names = i["books"][m["receiver"]]
            book = [lb.pair_keys(folks[m["receiver"]][0], folks[name][1]) for name in names]
            found = [{"contact": names[ix], "port": port}
                     for ix, port in lb.match_query(d, src, epoch, book)]
            assert found == m["found"] == alone[m["receiver"]], (n, m["receiver"])


def test_answer_padded_vector():
    v = load("lbcn_answer_padded_001.json")
    i, e = v["inputs"], v["expected"]
    folks = people(v)
    base = load(i["answer_vector"])
    assert i["answer_hex"] == base["expected"]["answer_hex"]
    assert i["q_nonce_hex"] == base["inputs"]["q_nonce_hex"]
    ans = bytes.fromhex(i["answer_hex"])
    keys = lb.pair_keys(folks[i["opener"]][0], folks[i["peer"]][1])
    q_nonce, other = bytes.fromhex(i["q_nonce_hex"]), bytes.fromhex(i["other_q_nonce_hex"])
    assert q_nonce != other and e["max_len"] == lb.ANSWER_MAX_LEN
    src, dst = ip(i["src"]), ip(i["dst"])
    assert [row["tail_len"] for row in e["padded"]] == i["tail_lens"] == [1, 8, 15]
    for row in e["padded"]:
        n = row["tail_len"]
        tail = bytes((i["tail_first_byte"] + k) & 0xFF for k in range(n))
        d = lb.with_tail(ans, tail)
        assert d.hex() == row["datagram_hex"] and len(d) == row["len"] == 48 + n
        assert lb.kind_of(len(d)) == "answer"
        assert lb.open_answer(d, keys, q_nonce, src, dst) == row["alice_opens"] == 7420
        assert lb.open_answer(d, keys, other, src, dst) is None
        assert row["alice_opens_with_another_q_nonce"] is None
