# tests/test_security_words.py
"""Raven security words v1 (RAVEN_SECURITY_WORDS_V1.md, draft): reference, list rules and vectors."""
import ast, filecmp, hashlib, json, pathlib, subprocess, sys, tempfile

from raven_protocol import fingerprint, security_words as sw

REF = pathlib.Path(__file__).resolve().parents[1]  # protocol/reference
REPO = REF.parents[1]
VEC = REPO / "shared-vectors/rvn1/security_words"
GEN = REF / "generate_security_words.py"
TOOL = REF / "tools/build_security_words_list.py"
CANDIDATES = REF / "tools/security_words_candidates.txt"
sys.path.insert(0, str(TOOL.parent))
import build_security_words_list as build  # noqa: E402

WORDS = sw.load_wordlist()
IX = sw.Index(WORDS)
RESERVES = ["cobra", "heron", "ostrich", "bacon", "pretzel", "vanilla", "ginger", "mint", "avocado", "waffle",
            "baker", "nurse", "sailor", "dentist", "circle", "pyramid", "fossil"]
ALICE_ED_PUB = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

def load(name):
    return json.loads((VEC / name).read_text(encoding="utf-8"))

def test_list_hash_pinned():
    v = load("wordlist_v1.json")
    assert hashlib.sha256(sw.DEFAULT_LIST.read_bytes()).hexdigest() == v["expected"]["sha256"]
    assert REPO / v["inputs"]["path"] == sw.DEFAULT_LIST
    assert {int(i): w for i, w in v["expected"]["spot"].items()} == {i: WORDS[i] for i in (0, 1, 127, 128, 254, 255)}

def test_list_file_format():
    raw = sw.DEFAULT_LIST.read_bytes()
    assert raw.isascii() and b"\r" not in raw and raw.endswith(b"\n")
    assert raw.splitlines()[0] == b"# SPDX-License-Identifier: CC0-1.0"
    assert len(WORDS) == len(set(WORDS)) == 256

def test_list_follows_the_build_rules():
    assert build.list_violations(WORDS) == []
    assert len({w[:3] for w in WORDS}) == 256                      # unique 3-letter prefixes
    assert all(3 <= len(w) <= 8 for w in WORDS)

def test_a_list_that_breaks_a_rule_is_not_v1():
    for bad_word in (WORDS[1] + "s", "key", "Apple", "ox", "turtles"):
        broken = WORDS[:]
        broken[0] = bad_word
        assert build.list_violations(broken), bad_word

def test_builder_reproduces_the_list_and_the_reserves():
    words, reserves, _ = build.build(build.read_candidates(CANDIDATES))
    assert words == WORDS
    assert reserves == RESERVES
    assert build.list_violations(words) == []
    for r in reserves:
        assert not build.word_violations(r) and not any(build.pair_violations(r, w) for w in WORDS), r
    done = subprocess.run([sys.executable, "-I", str(TOOL), str(CANDIDATES)], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert "reserves: " + " ".join(RESERVES) in done.stdout

def test_words_vectors():
    for who in ("alice", "bob", "carol", "dave"):
        v = load(f"words_{who}_001.json")
        e = v["expected"]
        ed = bytes.fromhex(v["inputs"]["ed_public_hex"])
        assert v["inputs"]["label_ascii"].encode() == sw.LABEL_RAVEN
        assert v["inputs"]["wordlist_sha256"] == load("wordlist_v1.json")["expected"]["sha256"]
        assert hashlib.sha256(sw.LABEL_RAVEN + ed).hexdigest() == e["digest_hex"]
        assert list(bytes.fromhex(e["digest_hex"])[:9]) == e["data_indexes"]
        assert sw.gf_check(e["data_indexes"]) == e["check_index"]
        assert sw.derive_indexes(ed) == e["indexes"] == e["data_indexes"] + [e["check_index"]]
        assert sw.words_for(ed, WORDS) == e["words"] and " ".join(e["words"]) == e["text"]
        assert sw.check_ok(e["indexes"])
        assert e["device_fingerprint_v1"] == fingerprint.device_fingerprint_v1(ed)
        assert sw.compare(e["text"], ed, IX) == {"status": "match"}

def test_alice_words_and_old_code_side_by_side():
    e = load("words_alice_001.json")["expected"]
    assert e["device_fingerprint_v1"] == "If4x-36FU-omFi"
    assert e["text"] == "turtle frog bread wolf paper laptop funnel mango honey wagon"
    # dave takes the code's '+'/'/' strip branch; his words still have 10 entries (a repeated word is normal)
    d = load("words_dave_001.json")["expected"]
    assert d["device_fingerprint_v1"] == "NN72-hvSx-N7W" and len(d["words"]) == 10

def test_parse_and_resolve_vectors():
    v = load("parse_001.json")
    alice = bytes.fromhex(v["inputs"]["ed_public_hex"])
    assert len(v["expected"]["cases"]) == 14
    for c in v["expected"]["cases"]:
        assert sw.looks_like_words(c["input"]) == c["expected"]["looks_like_words"], c["case"]
        if c["expected"]["looks_like_words"]:
            assert sw.parse(c["input"], IX) == c["expected"]["parse"], c["case"]
            assert sw.compare(c["input"], alice, IX)["status"] == c["expected"]["compare_with_alice"], c["case"]
    statuses = {c["expected"].get("compare_with_alice") for c in v["expected"]["cases"]}
    assert statuses == {"match", "mismatch", "non_latin", "bad_check", "wrong_count", "unknown", "ambiguous", None}
    cases = load("resolve_001.json")["expected"]["cases"]
    assert len(cases) == 14
    for c in cases:
        assert list(IX.resolve(c["token"])) == c["result"], c["token"]

def test_check_word_guarantees():
    for c in load("check_word_001.json")["expected"]["cases"]:
        assert sw.gf_check(c["data_indexes"]) == c["check_index"]
    for seed in range(64):
        code = sw.derive_indexes(bytes([seed]) * 32)
        for p in range(10):                      # every single wrong word
            for v in range(256):
                if v != code[p]:
                    bad = code[:]
                    bad[p] = v
                    assert not sw.check_ok(bad)
        for i in range(10):                      # every swap of two different words
            for j in range(i + 1, 10):
                if code[i] != code[j]:
                    bad = code[:]
                    bad[i], bad[j] = bad[j], bad[i]
                    assert not sw.check_ok(bad)

def test_every_word_resolves():
    for i, w in enumerate(WORDS):
        for t in (w, w.upper(), w.capitalize(), w[:3], w + "s", w + "es"):
            assert IX.resolve(t) == ("ok", i), t
        assert IX.resolve(w[:2]) == ("ambiguous", w[:2])
        assert i in IX.candidates(w[:1]) and IX.candidates(w[:3]) == [i]

def test_entry_folds():
    a = load("words_alice_001.json")["expected"]["words"]
    # invisible characters are dropped before splitting, so "1<ZWSP>" is still a position number
    assert sw.split_tokens("1\u200b. turtle\u200c \u06f2\u2014frog\u00a0\u0663) bread") == ["turtle", "frog", "bread"]
    assert sw.split_tokens("") == [] and sw.parse(" 1. 2. ", IX) == {"status": "empty"}
    assert sw.parse(" ".join(a[:3] + ["turtle1"] + a[4:]), IX) == {"status": "non_latin", "position": 4}
    assert not sw.looks_like_words("If4x 36FU omFi") and sw.looks_like_words("a b c d")
    # the outcome of a comparison never carries the expected words or indexes
    bob = load("words_bob_001.json")["expected"]["text"]
    assert sw.compare(bob, ALICE_ED_PUB, IX) == {"status": "mismatch"}
    assert sw.compare(" ".join(a[:9]), ALICE_ED_PUB, IX) == {"status": "wrong_count", "count": 9}

def test_generator_check_and_byte_identical_runs():
    done = subprocess.run([sys.executable, "-I", str(GEN), "--check"], capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
    with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
        for out in (t1, t2):
            subprocess.run([sys.executable, "-I", str(GEN), "--out", out], check=True, capture_output=True)
        names = sorted(p.name for p in (pathlib.Path(t1) / "security_words").glob("*.json"))
        assert names == sorted(p.name for p in VEC.glob("*.json"))
        for n in names:
            assert filecmp.cmp(pathlib.Path(t1) / "security_words" / n, pathlib.Path(t2) / "security_words" / n,
                               shallow=False), n
            assert json.loads((VEC / n).read_text(encoding="utf-8"))["status"] == "draft", n
        # --check fails on drift and on files it does not generate
        (pathlib.Path(t1) / "security_words/extra_001.json").write_text("{}\n", encoding="utf-8")
        (pathlib.Path(t2) / "security_words/parse_001.json").write_text("{}\n", encoding="utf-8")
        for out in (t1, t2):
            bad = subprocess.run([sys.executable, "-I", str(GEN), "--out", out, "--check"], capture_output=True)
            assert bad.returncode == 1

def test_new_python_imports_only_stdlib():
    for path in (sw.__file__, GEN, TOOL, __file__):
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
                assert top in sys.stdlib_module_names or top in ("raven_protocol", "build_security_words_list"), \
                    (path, name)
