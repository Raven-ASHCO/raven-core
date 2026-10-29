#!/usr/bin/env python3
# protocol/reference/generate_security_words.py
"""Deterministic generator for the Raven security words v1 vectors (Python standard library only).

Source of truth: raven_protocol.security_words  |  Spec: protocol/RAVEN_SECURITY_WORDS_V1.md
Writes <out>/security_words/*.json (default out: shared-vectors/rvn1). Every file carries
"status": "draft" until the list is frozen after the English listening test.

    python3 -I generate_security_words.py            # write the vectors
    python3 -I generate_security_words.py --check    # exit 1 if any file on disk differs
"""
import argparse, hashlib, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from raven_protocol import fingerprint, security_words as sw  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SUBDIR = "security_words"
STATUS = "draft"
LIST_PATH = "protocol/reference/raven_protocol/security_words_v1.txt"
KEYS = {  # the fixed Ed25519 public keys of generate_rvn1.py (shared-vectors identities)
    "alice": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "bob": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "carol": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    "dave": "e61a185bcef2613a6c7cb79763ce945d3b245d76114dd440bcf5f2dc1aa57057",
}
# What the Latin letter keys type with a Persian keyboard layout on (ISIRI 9147),
# the realistic way a Raven word arrives in another alphabet.
PERSIAN_LAYOUT = dict(zip(
    "qwertyuiopasdfghjklzxcvbnm",
    "\u0636\u0635\u062b\u0642\u0641\u063a\u0639\u0647\u062e\u062d"
    "\u0634\u0633\u06cc\u0628\u0644\u0627\u062a\u0646\u0645"
    "\u0638\u0637\u0632\u0631\u0630\u062f\u067e"))

def on_persian_layout(word):
    return "".join(PERSIAN_LAYOUT[c] for c in word)

def vec(name, desc, inputs, expected):
    return {"name": name, "description": desc, "protocol_version": "rvn1", "status": STATUS,
            "spec_reference": "RAVEN_SECURITY_WORDS_V1.md", "deterministic": True,
            "inputs": inputs, "expected": expected}

def build():
    words = sw.load_wordlist()
    ix = sw.Index(words)
    list_sha = hashlib.sha256(sw.DEFAULT_LIST.read_bytes()).hexdigest()
    out = {"wordlist_v1.json": vec(
        "Security words v1 list", f"SHA-256 of {LIST_PATH} (the whole file) and spot rows",
        {"path": LIST_PATH},
        {"sha256": list_sha, "rows": sw.LIST_ROWS, "spot": {str(i): words[i] for i in (0, 1, 127, 128, 254, 255)}})}
    sets = {}
    for who, hexkey in KEYS.items():
        ed = bytes.fromhex(hexkey)
        idx = sw.derive_indexes(ed)
        sets[who] = [words[i] for i in idx]
        out[f"words_{who}_001.json"] = vec(
            f"Security words, {who}",
            "SHA-256(label || ed_pub): the first 9 bytes are 9 indexes; the 10th is the GF(2^8) check. "
            "device_fingerprint_v1 of the same key alongside: both MUST be shown for the same key.",
            {"ed_public_hex": hexkey, "label_ascii": sw.LABEL_RAVEN.decode("ascii"), "wordlist_sha256": list_sha},
            {"digest_hex": hashlib.sha256(sw.LABEL_RAVEN + ed).hexdigest(), "data_indexes": idx[:9],
             "check_index": idx[9], "indexes": idx, "words": sets[who], "text": " ".join(sets[who]),
             "device_fingerprint_v1": fingerprint.device_fingerprint_v1(ed)})
    a = sets["alice"]
    swapped = a[:]
    k = next(i for i in range(9) if swapped[i] != swapped[i + 1])
    swapped[k], swapped[k + 1] = swapped[k + 1], swapped[k]
    replaced = a[:]
    replaced[4] = words[(words.index(a[4]) + 1) % 256]
    alice = bytes.fromhex(KEYS["alice"])
    cases = [
        ("canonical", " ".join(a)),
        ("upper case, hyphens, position numbers", " ".join(f"{i + 1}. {w.capitalize()}-" for i, w in enumerate(a))),
        ("first 3 letters", " ".join(w[:3] for w in a)),
        ("plurals", " ".join(w + ("es" if w.endswith(("s", "x", "ch", "sh", "o")) else "s") for w in a)),
        ("full-width letters", " ".join("".join(chr(ord(c) - 0x61 + 0xFF41) for c in w) for w in a)),
        ("Persian digits as position numbers (silently ignored)",
         " ".join(f"{chr(0x06F1 + i) if i < 9 else chr(0x06F1) + chr(0x06F0)} {w}" for i, w in enumerate(a))),
        ("a token in another alphabet (word 2 typed with a Persian keyboard layout)",
         " ".join(a[:1] + [on_persian_layout(a[1])] + a[2:])),
        ("two adjacent words swapped", " ".join(swapped)),
        ("one word left out", " ".join(a[:3] + a[4:])),
        ("one word replaced by another list word", " ".join(replaced)),
        ("unknown word", " ".join(a[:2] + ["xyzzy"] + a[3:])),
        ("prefix too short", " ".join([a[0][:2]] + a[1:])),
        ("bob's words against alice's key", " ".join(sets["bob"])),
        ("old code (not words)", fingerprint.device_fingerprint_v1(alice)),
    ]
    items = []
    for label, text in cases:
        r = {"looks_like_words": sw.looks_like_words(text)}
        if r["looks_like_words"]:
            r["parse"] = sw.parse(text, ix)
            r["compare_with_alice"] = sw.compare(text, alice, ix)["status"]
        items.append({"case": label, "input": text, "expected": r})
    out["parse_001.json"] = vec(
        "Security words entry parsing", "tokens, tolerances and error statuses; compared with alice's key",
        {"ed_public_hex": KEYS["alice"]}, {"cases": items})
    toks = [words[0], words[0].upper(), words[0][:3], words[0][:2], words[0] + "s", "pens", "boxes", "tomatoes",
            "\uff41\uff50\uff50\uff4c\uff45", "app\u200ble", "xyzzy", "s", on_persian_layout(words[0]), "caf\u00e9"]
    out["resolve_001.json"] = vec(
        "Security words single-token resolution", "exact, plural, prefix, errors",
        {}, {"cases": [{"token": t, "result": list(ix.resolve(t))} for t in toks]})
    checks = [{"data_indexes": d, "check_index": sw.gf_check(d)}
              for d in ([0] * 9, [255] * 9, list(range(9)), sw.derive_indexes(alice)[:9])]
    out["check_word_001.json"] = vec(
        "GF(2^8) check index", "acc=0; acc=xtime(acc)^d for each data index; check=xtime(acc)",
        {}, {"cases": checks})
    return out

def render(obj):
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(REPO_ROOT / "shared-vectors/rvn1"))
    ap.add_argument("--check", action="store_true", help="exit 1 if any file on disk differs")
    args = ap.parse_args()
    base = pathlib.Path(args.out) / SUBDIR
    files = build()
    if args.check:
        drift = [name for name, obj in files.items()
                 if not (base / name).is_file() or (base / name).read_text(encoding="utf-8") != render(obj)]
        extra = sorted(p.name for p in base.glob("*.json") if p.name not in files) if base.is_dir() else []
        for name in drift:
            print("DRIFT", base / name)
        for name in extra:
            print("NOT GENERATED", base / name)
        if drift or extra:
            sys.exit(1)
        print(f"security words vectors OK ({len(files)} files)")
        return
    base.mkdir(parents=True, exist_ok=True)
    for name, obj in files.items():
        (base / name).write_text(render(obj), encoding="utf-8")
    print("wrote", base)

if __name__ == "__main__":
    main()
