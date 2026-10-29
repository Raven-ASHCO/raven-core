"""Raven security words v1 (RAVEN_SECURITY_WORDS_V1.md): reference implementation.

Status: DRAFT until the English listening test; vectors carry "status": "draft".
Python standard library only.

A display and comparison encoding of the SAME 32-byte Ed25519 user-identity
public key that fingerprint.device_fingerprint_v1 encodes. No wire change:
the words are derived locally from the key.

    digest  = SHA-256(LABEL_RAVEN || ed_pub)      ed_pub = 32 raw bytes
    data    = digest[0:9]                         9 indexes, 8 bits each = 72 bits
    check   = gf_check(data)                      1 index (GF(2^8) Damm/Horner check)
    indexes = data + [check]                      10 words
"""
import hashlib
import hmac
import pathlib

LABEL_RAVEN = b"rvn1/security-words/v1"
DATA_WORDS = 9
TOTAL_WORDS = 10
MIN_PREFIX = 3
LIST_ROWS = 256
DEFAULT_LIST = pathlib.Path(__file__).with_name("security_words_v1.txt")

# ---------------------------------------------------------------- word list

def load_wordlist(path=DEFAULT_LIST):
    """index<TAB>word per line, indexes 0..255 in order; '#' lines are comments."""
    words = []
    with open(path, encoding="utf-8", newline="") as f:
        for line in f:
            if not line.endswith("\n") or line.endswith("\r\n"):
                raise ValueError("wordlist lines must end with LF: " + repr(line))
            line = line[:-1]
            if line.startswith("#"):
                continue
            i, w = line.split("\t")
            if i != str(len(words)) or not (w.isascii() and w.isalpha() and w.islower()):
                raise ValueError("bad wordlist row: " + repr(line))
            words.append(w)
    if len(words) != LIST_ROWS:
        raise ValueError("wordlist must have 256 rows")
    return words

# ---------------------------------------------------------------- derivation

def xtime(v):
    """Multiply by 2 in GF(2^8) mod x^8+x^4+x^3+x+1 (0x11B, the AES field)."""
    v <<= 1
    return (v ^ 0x11B) if v & 0x100 else v

def gf_check(data):
    """Check index of 9 data indexes: acc = xtime(acc) ^ d for each d, then xtime(acc)."""
    acc = 0
    for d in data:
        acc = xtime(acc) ^ d
    return xtime(acc)

def check_ok(indexes):
    """True when the indexes (data + check) fold to 0."""
    acc = 0
    for d in indexes:
        acc = xtime(acc) ^ d
    return acc == 0

def derive_indexes(ed_pub, label=LABEL_RAVEN):
    """The 10 list indexes of a 32-byte user-identity key."""
    if len(ed_pub) != 32:
        raise ValueError("ed_pub must be 32 bytes")
    data = list(hashlib.sha256(label + ed_pub).digest()[:DATA_WORDS])
    return data + [gf_check(data)]

def words_for(ed_pub, words, label=LABEL_RAVEN):
    return [words[i] for i in derive_indexes(ed_pub, label)]

# ---------------------------------------------------------------- input

# Dropped everywhere before splitting: zero-width space, ZWNJ, ZWJ, LRM, RLM,
# word joiner and BOM.
INVISIBLE = frozenset("\u200b\u200c\u200d\u200e\u200f\u2060\ufeff")
# Persian (U+06F0..9), Arabic-Indic (U+0660..9) and full-width (U+FF10..9)
# digits read as 0-9. A token of digits only is a position number ("1.") and
# is ignored.
DIGIT_FOLD = {**{chr(0x06F0 + i): str(i) for i in range(10)},
              **{chr(0x0660 + i): str(i) for i in range(10)},
              **{chr(0xFF10 + i): str(i) for i in range(10)}}
# Whitespace (ASCII, NBSP, U+1680, U+2000..U+200A, U+2028, U+2029, U+202F,
# U+205F, U+3000), dashes (hyphen-minus, U+2010..U+2015, U+2212) and
# punctuation.
SEPARATORS = frozenset(
    " \t\r\n\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
    "-\u2010\u2011\u2012\u2013\u2014\u2015\u2212"
    ",;.\u00b7\u2022/|:()[]\"'`")

def fold_latin(token):
    """ASCII and full-width letters -> a-z; None if the token holds anything else."""
    out = []
    for c in token:
        if c in INVISIBLE:
            continue
        if "A" <= c <= "Z":
            c = chr(ord(c) + 32)
        elif "\uff21" <= c <= "\uff3a":
            c = chr(ord(c) - 0xFF21 + 0x61)
        elif "\uff41" <= c <= "\uff5a":
            c = chr(ord(c) - 0xFF41 + 0x61)
        if not "a" <= c <= "z":
            return None
        out.append(c)
    return "".join(out)

def split_tokens(text):
    """Entry text -> tokens: drop invisible characters, fold digits, split, drop position numbers."""
    text = "".join(DIGIT_FOLD.get(c, c) for c in text if c not in INVISIBLE)
    toks, cur = [], []
    for c in text:
        if c in SEPARATORS:
            if cur:
                toks.append("".join(cur))
                cur = []
        else:
            cur.append(c)
    if cur:
        toks.append("".join(cur))
    return [t for t in toks if not all("0" <= c <= "9" for c in t)]

class Index:
    def __init__(self, words):
        self.words = words
        self.exact = {w: i for i, w in enumerate(words)}
        if len(words) != LIST_ROWS or len(self.exact) != LIST_ROWS:
            raise ValueError("wordlist must have 256 distinct words")

    def candidates(self, token):
        """Autocomplete: every list index the token can still become (never depends on a friend's key)."""
        p = fold_latin(token)
        if p is None:
            return []
        return [i for i, w in enumerate(self.words) if w.startswith(p)]

    def resolve(self, token):
        """('ok', index) | ('ambiguous'|'unknown'|'non_latin', token).

        1. the exact word;  2. a plural of a word (word+'es' or word+'s');
        3. a prefix of >= 3 letters (always unique: the list has unique 3-letter prefixes)."""
        p = fold_latin(token)
        if p is None:
            return ("non_latin", token)
        if p in self.exact:
            return ("ok", self.exact[p])
        for suffix in ("es", "s"):
            if p.endswith(suffix) and p[: -len(suffix)] in self.exact:
                return ("ok", self.exact[p[: -len(suffix)]])
        c = self.candidates(p)
        if not c:
            return ("unknown", token)
        if len(p) >= MIN_PREFIX and len(c) == 1:
            return ("ok", c[0])
        return ("ambiguous", token)

def parse(text, ix):
    """{'status': 'ok', 'indexes': [...]} or an error status computed from the typed text alone."""
    toks = split_tokens(text)
    if not toks:
        return {"status": "empty"}
    out = []
    for pos, t in enumerate(toks, 1):
        st, val = ix.resolve(t)
        if st != "ok":
            return {"status": st, "position": pos}
        out.append(val)
    if len(out) != TOTAL_WORDS:
        return {"status": "wrong_count", "count": len(out)}
    if not check_ok(out):
        return {"status": "bad_check"}
    return {"status": "ok", "indexes": out}

def looks_like_words(text):
    """4 or more tokens: words. Fewer: the old code (device_fingerprint_v1 has at most 3 groups)."""
    return len(split_tokens(text)) >= 4

def compare(text, ed_pub, ix, label=LABEL_RAVEN):
    """match | mismatch | a parse status. Never reveals the expected words."""
    r = parse(text, ix)
    if r["status"] != "ok":
        return r
    want = bytes(derive_indexes(ed_pub, label))
    return {"status": "match" if hmac.compare_digest(want, bytes(r["indexes"])) else "mismatch"}
