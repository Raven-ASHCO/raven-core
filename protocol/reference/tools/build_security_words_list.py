#!/usr/bin/env python3
"""Rebuild the Raven security words v1 list from its candidate file (Python standard library only).

RAVEN_SECURITY_WORDS_V1.md section 4: the build rules below are normative. A
list that breaks one of them is not v1.

    python3 -I tools/build_security_words_list.py tools/security_words_candidates.txt
    python3 -I tools/build_security_words_list.py CANDIDATES --print      # the list in file format
    python3 -I tools/build_security_words_list.py CANDIDATES --verbose    # why words were rejected

One greedy pass over the candidates in file order (commonness tiers, A1 first)
keeps each word that breaks no rule against the words kept before it. The first
256 kept, sorted alphabetically, are the list; the words kept after them are
the reserves (each passes every rule against the 256). Exit 0 when the rebuilt
list equals the list file word for word, 1 otherwise.
"""
import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from raven_protocol import security_words as sw  # noqa: E402

ROWS = sw.LIST_ROWS
MIN_LEN = 3
MAX_LEN = 8
PREFIX = sw.MIN_PREFIX

EXCLUDE = {
    # homophones / near-homophones of common words
    "bear", "deer", "pea", "pear", "sea", "sun", "bee", "rose", "flower", "flour", "tea", "whale", "horse", "date",
    "road", "steak", "sail", "plane", "nail", "knight", "night", "hair", "hare", "mail", "tail", "berry", "cereal",
    "jeans", "chili", "board", "pail", "peace", "piece", "pole", "roll", "sole", "stair", "toad", "hole", "meat",
    "nose", "knot", "rain", "wood", "flu", "suite", "mole", "seal",
    # US/UK spelling or name variants
    "harbor", "pajamas", "yogurt", "donut", "axe", "airplane", "color", "aluminum", "tire", "jail", "cookie",
    "candy", "fries", "soccer", "football", "faucet", "tap", "sweets", "biscuit", "flashlight", "torch", "cracker",
    # spelling hides the sound (first 3 letters not guessable)
    "knife", "wrench", "pheasant", "rhubarb", "cypress", "gnome", "wrist", "psalm", "scissors", "whistle",
    # security-sounding or confusing in a security screen
    "key", "lock", "secret", "code", "password", "ghost", "pirate",
    # violence, symbols, slang, branding
    "sword", "gun", "drill", "flag", "crown", "trophy", "wizard", "pot", "screw", "raven", "hose", "giant",
    "dragon", "sushi", "taco", "curry", "judo", "karate", "hockey", "golf", "tennis",
    # synonyms or near-duplicates of a kept word, US/UK meaning splits, other homophones
    "bathtub", "sled", "jelly", "couch", "purse", "stool", "ant", "rhino", "weasel", "skunk",
}

def lev(a, b):
    """Edit distance (insert, delete, substitute)."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]

def sound_key(w):
    """Rough English sound key: catches pairs that look different but sound close."""
    s = w
    for a, b in (("ph", "f"), ("ck", "k"), ("qu", "kw"), ("wh", "w"), ("gh", "g"), ("x", "ks"),
                 ("ce", "se"), ("ci", "si"), ("cy", "si"), ("c", "k"), ("z", "s"), ("ee", "i"), ("ea", "i"),
                 ("oo", "u"), ("ou", "u"), ("y", "i"), ("ay", "ai")):
        s = s.replace(a, b)
    if len(s) > 3 and s.endswith("e"):
        s = s[:-1]
    out = []
    for c in s:
        if not out or out[-1] != c:
            out.append(c)
    return "".join(out)

def word_violations(w):
    """Rules on one word alone."""
    why = []
    if w in EXCLUDE:
        why.append("excluded")
    if not (w.isascii() and w.isalpha() and w.islower()):
        why.append("charset")
    if not MIN_LEN <= len(w) <= MAX_LEN:
        why.append("length")
    return why

def pair_violations(w, a):
    """Rules between two words (symmetric)."""
    why = []
    if w[:PREFIX] == a[:PREFIX] or w.startswith(a) or a.startswith(w):
        why.append("prefix " + a)
    if lev(w, a) < 2:
        why.append("close " + a)
    if lev(sound_key(w), sound_key(a)) < 2:
        why.append("sounds like " + a)
    return why

def read_candidates(path):
    """Candidate words in file order, first occurrence only; '#' lines are comments."""
    words, seen = [], set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#"):
                continue
            for w in line.split():
                if w not in seen:
                    seen.add(w)
                    words.append(w)
    return words

def build(candidates, rows=ROWS):
    """(list sorted, reserves in kept order, [(word, reasons)] rejected)."""
    kept, rejected = [], []
    for w in candidates:
        why = word_violations(w)
        for a in kept:
            why += pair_violations(w, a)
        if why:
            rejected.append((w, why))
        else:
            kept.append(w)
    return sorted(kept[:rows]), kept[rows:], rejected

def list_violations(words):
    """Every rule a finished list breaks ([] for a valid v1 list)."""
    bad = []
    if len(words) != ROWS or len(set(words)) != ROWS:
        bad.append(("*", ["the list must have 256 distinct words"]))
    for i, w in enumerate(words):
        why = word_violations(w)
        for a in words[i + 1:]:
            why += pair_violations(w, a)
        if why:
            bad.append((w, why))
    return bad

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("candidates", help="tools/security_words_candidates.txt")
    ap.add_argument("--list", default=str(sw.DEFAULT_LIST), help="the list file to compare with")
    ap.add_argument("--print", action="store_true", help="print the rebuilt list in file format")
    ap.add_argument("--verbose", action="store_true", help="print why each word was rejected")
    args = ap.parse_args()

    cands = read_candidates(args.candidates)
    words, reserves, rejected = build(cands)
    if args.verbose:
        for w, why in rejected:
            if why != ["excluded"]:
                print("REJ", w, "::", "; ".join(why)[:120])
    if args.print:
        for i, w in enumerate(words):
            print(f"{i}\t{w}")
        return 0
    print(f"{len(cands)} candidates: {len(words)} words, {len(reserves)} reserves, {len(rejected)} rejected")
    print("reserves:", " ".join(reserves))
    if len(words) != ROWS:
        print(f"FAIL: only {len(words)} candidates pass the rules", file=sys.stderr)
        return 1
    committed = sw.load_wordlist(args.list)
    if committed != words:
        diff = " ".join(sorted(set(committed) ^ set(words))) or "(same words, other order)"
        print(f"FAIL: the rebuilt list differs from {args.list}: {diff}", file=sys.stderr)
        return 1
    print(f"OK: the rebuilt list equals {args.list} word for word")
    return 0

if __name__ == "__main__":
    sys.exit(main())
