# RAVEN Security Words V1

**Version:** 1 (label `rvn1/security-words/v1`)
**Status:** **Draft** until the English listening test (people read sets aloud over a phone call);
then a **frozen display contract, not wire**. Until the freeze every vector file carries
`"status": "draft"`: the list and the vectors may change before the freeze, never after (the
`v2-draft` precedent in [`shared-vectors/VERSIONING.md`](../shared-vectors/VERSIONING.md)).
**Audience:** every Raven app, port or third-party verifier that shows a Raven identity key to a
person or compares a key with what a person typed.
**Reference:** `protocol/reference/raven_protocol/security_words.py` (Python standard library
only) and the vectors in `shared-vectors/rvn1/security_words/`.

---

## 0. Status and scope

- Security words are a **display and comparison encoding** of the rvn1 user-identity key: ten
  everyday English nouns. Nine of them carry 72 bits of a hash of the key; the tenth, the check
  word, catches a misheard or swapped word.
- **No wire change.** Contact cards, invites and every frame are unchanged: cards keep
  `fingerprint=` and `pub_hex`. The words are computed locally from the 32-byte key.
- **Relationship with `RavenDeviceFingerprintV1`** ([`RAVEN_IDENTITY_V1.md`](RAVEN_IDENTITY_V1.md)
  §3, called the *old code* or *old-style code* below): both are pure functions of the same key,
  so they never disagree. Both are shown, and both are accepted wherever a person compares a key.
  The old code is the fallback for a friend with an older Raven.
- **English only.** There is one list of 256 English words. No translated list exists and nothing
  is displayed in another script. The input tolerance for other digit scripts (§6) is silent.

## 1. Terms

| Term | Meaning |
|---|---|
| key | the 32-byte Ed25519 user-identity public key (§2) |
| index | a row of the word list, 0..255 |
| data words | words 1-9 of a set: indexes `d0`..`d8`, taken from the hash of the key |
| check word | word 10 of a set: index `c`, computed from the 9 data indexes |
| set | the 10 words of one key, in order |
| entry | text a person typed or pasted to compare with a key |
| token | one piece of an entry after splitting (§6) |

## 2. Input key

`ed_pub` is the **32 raw bytes of the Ed25519 user-identity public key**: exactly the bytes behind
`device_fingerprint_v1`, the rvn1 address and the card's `pub_hex`. It is **never**
`device_ed_pub` or any other device or session key. Another key type gets its own label (§10).

## 3. Derivation

Byte-exact:

```
LABEL    = ASCII "rvn1/security-words/v1"      22 bytes, no terminator
digest   = SHA-256(LABEL || ed_pub)            54 bytes hashed
d[k]     = digest[k]                           k = 0 .. 8: 9 data indexes, 0..255

xtime(v) = (v << 1) XOR 0x11B   if v & 0x80    multiply by 2 in GF(2^8),
         = (v << 1)             otherwise      polynomial x^8 + x^4 + x^3 + x + 1 (the AES field)

acc = 0
for k = 0 .. 8:  acc = xtime(acc) XOR d[k]
c   = xtime(acc)                               the check index

indexes = [d0, d1, ..., d8, c]
words   = [LIST[i] for i in indexes]
```

**Validity of 10 indexes** `x0..x9`: `acc = 0; for k = 0 .. 9: acc = xtime(acc) XOR x[k]`; the
indexes are valid if and only if `acc == 0` at the end. Every derived set is valid.

Properties (each one is checked by `protocol/reference/tests/test_security_words.py`):

- One byte per index: the 9 data indexes are uniform and independent, with no modulo bias.
  **Every key gets exactly 72 bits.**
- The check is Damm's construction over the totally anti-symmetric quasigroup `a∘b = 2a ⊕ b` in
  GF(2^8). It catches **every** single wrong word, and **every** swap of two different words at
  any two positions (2 has order 51 in GF(2^8)*, and positions are at most 9 apart). Errors in
  two random words pass the check with probability about 1/256 and then compare as `mismatch`,
  never as a false `match`.
- The check word adds no bits against an attacker (§9).

**Signatures.**

```python
# protocol/reference/raven_protocol/security_words.py
LABEL_RAVEN = b"rvn1/security-words/v1"
def derive_indexes(ed_pub: bytes, label=LABEL_RAVEN) -> list[int]   # 10 indexes
def words_for(ed_pub: bytes, words: list[str], label=LABEL_RAVEN) -> list[str]
def gf_check(data: list[int]) -> int                                # check index of 9 data indexes
def check_ok(indexes: list[int]) -> bool
```

```rust
// raven_core::security_words (the Rust port; no new crates)
pub const LABEL_V1: &[u8] = b"rvn1/security-words/v1";
pub fn indexes_v1(ed_pub: &[u8; 32]) -> [u8; 10];
pub fn words_v1(ed_pub: &[u8; 32]) -> [&'static str; 10];
pub fn gf_check(data: &[u8]) -> u8;
pub fn check_ok(indexes: &[u8]) -> bool;
```

**Worked example** (`words_alice_001.json`):

```
ed_pub   d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
digest   f15019fd9972517d626aa11ab5eded396fdbd7da5297f600bcd035d4fdeac25e
indexes  241 80 25 253 153 114 81 125 98 | 248
words    turtle frog bread wolf paper laptop funnel mango honey wagon
old code If4x-36FU-omFi
```

The indexes depend only on the key. If the draft list changes before the freeze, only the words
change.

## 4. Word list

- **File:** `protocol/reference/raven_protocol/security_words_v1.txt`. The `.txt` extension keeps it
  inside `scripts/freeze_protocol_hashes.sh`.
- **Format:** UTF-8 (ASCII in practice), LF line ends. A line starting with `#` is a comment.
  Every other line is `index<TAB>word`, with indexes 0..255 in order: 256 rows, words of the
  letters a-z only, no blank lines.
- **Pin:** the SHA-256 of the whole file (comments included) is pinned in `wordlist_v1.json`. An
  implementation embeds the 256 words and MUST check its copy against the vectors.
- **Licence:** the list data is dedicated to the public domain, `SPDX-License-Identifier:
  CC0-1.0` (first line of the file), so every app, port and verifier can embed it without
  attribution. Code that uses it keeps its own licence.
- **Build rules (normative).** A list that breaks one of them is not v1:
  1. lower-case letters a-z only, 3 to 8 letters;
  2. the first 3 letters of every word are unique;
  3. no word is a prefix of another;
  4. edit distance at least 2 between any two words;
  5. sound-key distance at least 2 between any two words (`sound_key` of the build tool: `ph`→`f`,
     `c`/`k`, `ee`/`ea`→`i`, `oo`/`ou`→`u`, a final silent `e`, doubled letters and similar),
     which rejects near-rhymes such as house/mouse or paper/pepper;
  6. no word of the tool's exclusion list: homophones, US/UK variants, synonyms of a kept word,
     spellings that hide the sound, security-sounding or negative words, violence, symbols and
     brands.
- **How the list is built:** `protocol/reference/tools/build_security_words_list.py` reads
  `tools/security_words_candidates.txt` (401 nouns in commonness tiers, A1 first). One greedy pass
  keeps each word that breaks no rule against the words kept before it. The first 256 kept,
  sorted alphabetically, are the list. Running the tool MUST reproduce the file word for word.
- **Reserves (draft only):** the 17 words kept after the 256, each passing every rule against the
  256: cobra, heron, ostrich, bacon, pretzel, vanilla, ginger, mint, avocado, waffle, baker,
  nurse, sailor, dentist, circle, pyramid, fossil. They can replace words that fail the listening
  test before the freeze. After the freeze the list never changes (§10).
- **Draft list facts:** 5.4 letters per word on average; 23 different first letters (the most
  common, `s`, starts 34 words); animals, food, home objects, clothes, nature and places, a few
  people. A repeated word inside one set is normal (about 16% of sets).

## 5. Display

- Always all **10 words**, in order, never truncated, numbered 1-10. Two rows of 5; one word per
  line below 40 columns.
- **Canonical text:** the 10 words in lower case, joined by one ASCII space.
- The **old-style code** is shown under the words, for friends with an older Raven.
- **JSON:** `"security_words": {"version": 1, "words": ["turtle", ...]}`.
- **CLI:** the line label `words` is reserved for the canonical text (for example in
  `raven whoami`). The existing `fingerprint` line stays byte-identical.
- Words come only from the list, never from a card, a message or anything a person typed, so no
  bidi or confusable character can reach the words area.
- The words and the copy around them MUST NOT be called a seed, secret, recovery phrase or
  mnemonic (§9).

## 6. Input

An entry is turned into tokens in this order:

1. **Drop invisible characters** anywhere in the entry: U+200B, U+200C, U+200D, U+200E, U+200F,
   U+2060, U+FEFF.
2. **Fold digits:** Persian (U+06F0..U+06F9), Arabic-Indic (U+0660..U+0669) and full-width
   (U+FF10..U+FF19) digits become ASCII 0-9.
3. **Split** on separators; a run of separators gives no empty token. Separators:
   - whitespace: U+0009, U+000A, U+000D, U+0020, U+00A0, U+1680, U+2000..U+200A, U+2028, U+2029,
     U+202F, U+205F, U+3000;
   - dashes: U+002D, U+2010..U+2015, U+2212;
   - punctuation: `,` `;` `.` U+00B7 U+2022 `/` `|` `:` `(` `)` `[` `]` `"` `'` `` ` ``.
4. **Drop position numbers:** a token made only of ASCII digits is ignored, so
   `1. turtle 2. frog` reads as `turtle frog`.
5. **Fold letters** in each token: ASCII A-Z and full-width letters (U+FF21..U+FF3A,
   U+FF41..U+FF5A) become a-z. A token that holds any other character (another script, an accented
   letter, a digit next to letters) has the status **`non_latin`**. No Unicode database is used:
   the list has no accents, so nothing else is folded.

`non_latin` says nothing about the friend's key. Its hint is "Type the words with English
letters."; it never gets the mismatch warning.

## 7. Resolution and parse statuses

**Resolving one token** (after the letter fold); the first rule that applies wins:

1. the exact word → `ok`;
2. a plural: the token is a list word + `es`, else a list word + `s` → `ok` (pens → pen,
   boxes → box, tomatoes → tomato). This is unambiguous because no list word is a prefix of
   another;
3. a prefix of at least 3 letters → `ok`. It always resolves to exactly one word, because the
   first 3 letters are unique;
4. otherwise `ambiguous` when the token is shorter than 3 letters and at least one word starts
   with it ("keep typing"), else `unknown`.

Token statuses (normative names): `ok`, `ambiguous`, `unknown`, `non_latin`.

**Parsing an entry** gives the first status that applies, in this order:

| Status | When | Extra |
|---|---|---|
| `empty` | no token | |
| `non_latin`, `ambiguous`, `unknown` | the first token that does not resolve | its 1-based `position` |
| `wrong_count` | the number of tokens is not 10 | the `count` |
| `bad_check` | the 10 indexes fail the validity check (§3) | |
| `ok` | otherwise | the 10 indexes |

Every one of these statuses depends only on the typed text.

**Autocomplete.** `candidates(token)` is every list index whose word starts with the folded
token, from the whole list, in list order (`tur` → turtle). It takes no key: candidates are
**never** filtered or ordered by a friend's words. Tab, or Space when one candidate is left,
completes the word. Completed words may show as numbered chips with a neutral "a Raven word"
mark and a counter ("4 of 10").

## 8. Comparison

**Words or old code.** An entry with **4 or more tokens** (after §6 step 4) is words; fewer is
the old code, which has at most 3 groups.

**Words.** Parse the entry (§7). Any status but `ok` is the result, and it says nothing about the
key. On `ok`, compare the 10 typed indexes with the key's 10 indexes in **constant time**
(Python `hmac.compare_digest`; Rust an XOR/OR fold over the 10 bytes): `match` or `mismatch`. The
result never carries the expected words or indexes.

**Old code.** Unchanged: the old code is compared case-sensitively with `device_fingerprint_v1`,
separators ignored. Persian and Arabic-Indic digits are read as 0-9 first (silent input
tolerance). Right letters in the wrong case still get the existing case hint.

**Blind entry.** These rules apply wherever a person types what a friend reads aloud and the
result can mark the friend as verified (the terminal app's verify screen, `raven contact verify`
at a terminal, the RDAP guided UI). They are MUST rules:

1. Before a full `match`, show no part of the friend's words or code: not in autocomplete, chips
   or error text. After a `match`, show both.
2. No per-word right/wrong marks against the friend's words. A mark may only say "a Raven word"
   or "not a Raven word". (Per-word marks would let anyone solve the friend's words one word at a
   time, at most 256 tries each.)
3. `unknown`, `ambiguous`, `non_latin`, `wrong_count` and `bad_check` depend only on the typed
   text and may be shown in detail.
4. **Attempt limit:** after 3 well-formed `mismatch` results, stop offering the check. Show the
   stop text and leave only cancel or "later".
5. A paste is accepted as text and never submits. Enter is ignored for 300 ms after a paste.
6. The save path checks again: nothing pins a key unless the comparator returns `match` for the
   entry being saved.

Non-interactive output (scripts) may keep printing the old code, plus the words for a contact
that is already verified.

## 9. Security considerations

- **Bits against the old code.** The old code takes 9 bytes of `SHA-256(ed_pub)` (72 bits) to 12
  base64 characters and then deletes every `+` and `/`, which loses information:

  | Old code length | Share of keys | Bits to match it (second preimage) |
  |---|---|---|
  | 12 | 68.3% | 72.00 |
  | 11 | 26.4% | 67.42 |
  | 10 | 4.69% | 63.96 |
  | 9 | 0.50% | 61.22 |
  | 8 or fewer | 0.04% | 59.05 or less |

  On average the old code carries 70.35 bits. Words carry **exactly 72 bits for every key**, so
  they are never weaker than the old code, and stronger for the 31.7% of keys with a shortened
  code.
- **The check word adds no bits:** it is a function of the 9 data words. It catches every single
  wrong word and every swap; a 2-word error passes it with probability about 1/256 and is then a
  `mismatch`.
- **Second preimage:** about 2^72 Ed25519 key generations plus SHA-256, about 150,000 GPU-years
  at 10^9 keys per second.
- **Multi-target:** 2^72/N work finds a key whose words equal those of *any* of N known keys.
  This is the same as for the old code; longer or pairwise words are noted for a v2. The attacker
  must then still sit in the middle of that user's next pairing.
- **Partial comparison:** keys whose first 6 words match cost about 2^48. Machine comparison of
  all 10 words defeats this, and the copy for reading aloud says "all ten".
- **Per-word feedback** would leak the friend's words one by one, so it is forbidden (§8 rule 2).
  Validity and check feedback never touch the friend's key.
- **Accepting words or the old code** weakens nothing: an attacker must match what the person
  actually compares.
- **Domain separation:** the label separates the words from the unlabelled `SHA-256(ed_pub)`
  behind the old code (32 bytes hashed against 54), from the address hash and from every other
  `rvn1/*` digest. Grinding keys for one encoding gives no head start on the other.
- **Display spoofing:** words come only from the frozen ASCII list (§5).
- **Words are public**, like the old code. The copy says they are not a password and that Raven
  never asks for secret words. They are never called seed, secret, recovery phrase or mnemonic,
  and the list is not BIP-39, so a set cannot be taken for a wallet recovery phrase.
- **Version skew:** older apps show only the old code. New apps show the words with the old-style
  code under them and accept either.

## 10. Versioning

- `v1` is in the label, and the SHA-256 of the list file is pinned in `wordlist_v1.json`.
- **Draft → frozen.** After the English listening test the list is frozen: the vectors are
  regenerated once with the final list and their status changes from `draft`; from then on they
  never change.
- After the freeze, any change to the list or the algorithm is `rvn1/security-words/v2`, with new
  vectors and a visibly different shape (for example another word count), so v1 and v2 cannot be
  confused when read aloud. The old code is the fallback between versions.
- **Other key types** get their own label. `rdap/security-words/v1` is reserved for a future key
  type that is not an rvn1 identity key. RDAP uses `rvn1/security-words/v1` for every rvn1
  identity key it shows, so the same identity shows the same words in Raven and RDAP.

## 11. Vectors

`shared-vectors/rvn1/security_words/`, written by `protocol/reference/generate_security_words.py`
(`"status": "draft"`, `"spec_reference": "RAVEN_SECURITY_WORDS_V1.md"`):

| File | Content |
|---|---|
| `wordlist_v1.json` | SHA-256 of the list file, row count, spot rows |
| `words_alice_001.json`, `words_bob_001.json`, `words_carol_001.json`, `words_dave_001.json` | key → digest → data and check indexes → words and canonical text, plus `device_fingerprint_v1` of the same key (dave takes the old code's `+`/`/` strip branch) |
| `parse_001.json` | 14 entries compared with alice's key: canonical; case, hyphens and position numbers; 3-letter prefixes; plurals; full-width letters; Persian digits as position numbers; a word in another alphabet; a swap; an omission; a substitution; an unknown word; a prefix too short; bob's words; the old code |
| `resolve_001.json` | 14 single tokens: exact, upper case, prefixes, plurals, full-width, an invisible character, unknown, non-Latin |
| `check_word_001.json` | data indexes → check index |

The JSON is ASCII (non-ASCII input is written as `\uXXXX` escapes).

## 12. Reference

- `protocol/reference/raven_protocol/security_words.py`: derivation, check word, input folds,
  resolution, parsing, comparison (standard library only).
- `protocol/reference/generate_security_words.py [--check]`: writes the vectors; `--check` exits 1
  when a file on disk differs or is not generated. Safe to run with `python3 -I`.
- `protocol/reference/tests/test_security_words.py`: vectors, list rules, check-word guarantees,
  byte-identical regeneration.
- `protocol/reference/tools/build_security_words_list.py` with
  `tools/security_words_candidates.txt`: the build rules and the candidates; it reproduces the
  list and the reserves.

```sh
cd protocol/reference
python3 -m pytest -q tests/test_security_words.py
python3 -I generate_security_words.py --check
python3 -I tools/build_security_words_list.py tools/security_words_candidates.txt
```
