//! Raven security words v1 (`protocol/RAVEN_SECURITY_WORDS_V1.md`).
//!
//! A display and comparison encoding of the SAME 32-byte Ed25519 user-identity
//! key that [`crate::fingerprint::device_fingerprint_v1`] shows: 10 English
//! words, 9 data words (72 bits of `SHA-256(LABEL_V1 || ed_pub)`) and 1 GF(2^8)
//! check word. No wire change: the words are derived locally from the key, and
//! the old code stays shown and accepted.
//!
//! Status: DRAFT until the English listening test. The list and the vectors in
//! `shared-vectors/rvn1/security_words/` may still change before the freeze,
//! never after it. The Python reference is
//! `protocol/reference/raven_protocol/security_words.py`; every input fold and
//! status here matches it.

use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Domain-separation label hashed in front of the key.
pub const LABEL_V1: &[u8] = b"rvn1/security-words/v1";
/// Data words: 9 indexes of 8 bits = 72 bits of the digest.
pub const DATA_WORDS: usize = 9;
/// Words shown and typed: the data words plus the check word.
pub const WORDS: usize = 10;
/// A prefix of this many letters always names exactly one word.
pub const MIN_PREFIX: usize = 3;
/// An entry with this many tokens or more is words; fewer is the old code,
/// which has at most 3 groups.
const MIN_WORD_TOKENS: usize = 4;
const LIST_ROWS: usize = 256;

/// Byte copy of `protocol/reference/raven_protocol/security_words_v1.txt`
/// (a test checks both copies and the pinned SHA-256).
const LIST_V1_TXT: &str = include_str!("security_words_v1.txt");

// ---------------------------------------------------------------- word list

/// The 256 words of the v1 list, in index order.
pub fn list_v1() -> &'static [&'static str; LIST_ROWS] {
    static LIST: OnceLock<[&'static str; LIST_ROWS]> = OnceLock::new();
    LIST.get_or_init(|| {
        parse_list(LIST_V1_TXT).expect("embedded security words list is valid (tested)")
    })
}

/// `index<TAB>word` per LF-terminated line, indexes 0..255 in order, words of
/// a-z only; `#` lines are comments. `None` for anything else.
fn parse_list(text: &str) -> Option<[&str; LIST_ROWS]> {
    let mut words = [""; LIST_ROWS];
    let mut rows = 0usize;
    for line in text.split_inclusive('\n') {
        let line = line.strip_suffix('\n')?;
        if line.ends_with('\r') {
            return None;
        }
        if line.starts_with('#') {
            continue;
        }
        let (index, word) = line.split_once('\t')?;
        if rows == LIST_ROWS
            || index != rows.to_string()
            || word.is_empty()
            || !word.bytes().all(|b| b.is_ascii_lowercase())
        {
            return None;
        }
        words[rows] = word;
        rows += 1;
    }
    (rows == LIST_ROWS).then_some(words)
}

/// `(index, word)` for every list row.
fn indexed_words() -> impl Iterator<Item = (u8, &'static str)> {
    (0..=u8::MAX).zip(list_v1().iter().copied())
}

fn index_of(word: &str) -> Option<u8> {
    indexed_words().find(|(_, w)| *w == word).map(|(i, _)| i)
}

// ---------------------------------------------------------------- derivation

/// Multiply by 2 in GF(2^8) mod x^8+x^4+x^3+x+1 (0x11B, the AES field).
const fn xtime(v: u8) -> u8 {
    let shifted = v << 1;
    if v & 0x80 != 0 {
        shifted ^ 0x1B
    } else {
        shifted
    }
}

/// Check index of the data indexes: `acc = xtime(acc) ^ d` for each `d`, then
/// `xtime(acc)`.
pub fn gf_check(data: &[u8]) -> u8 {
    xtime(data.iter().fold(0, |acc, d| xtime(acc) ^ d))
}

/// True when the indexes (data + check) fold to 0. Catches every single wrong
/// word and every swap of two different words.
pub fn check_ok(indexes: &[u8]) -> bool {
    indexes.iter().fold(0, |acc, d| xtime(acc) ^ d) == 0
}

/// The 10 list indexes of a user-identity key: 9 digest bytes and the check.
pub fn indexes_v1(ed_pub: &[u8; 32]) -> [u8; WORDS] {
    let digest = Sha256::new()
        .chain_update(LABEL_V1)
        .chain_update(ed_pub)
        .finalize();
    let mut out = [0u8; WORDS];
    out[..DATA_WORDS].copy_from_slice(&digest[..DATA_WORDS]);
    out[DATA_WORDS] = gf_check(&out[..DATA_WORDS]);
    out
}

/// The 10 words of a user-identity key, in display order.
pub fn words_v1(ed_pub: &[u8; 32]) -> [&'static str; WORDS] {
    let list = list_v1();
    indexes_v1(ed_pub).map(|i| list[usize::from(i)])
}

// ---------------------------------------------------------------- input

/// Dropped everywhere: zero-width space, ZWNJ, ZWJ, LRM, RLM, word joiner and
/// BOM.
fn is_invisible(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{2060}' | '\u{FEFF}')
}

/// Persian, Arabic-Indic and full-width digits read as 0-9 (also for text
/// next to the words, such as the old code or an address typed on the same
/// keyboard).
pub fn fold_digit(c: char) -> char {
    let zero = match c {
        '\u{06F0}'..='\u{06F9}' => 0x06F0,
        '\u{0660}'..='\u{0669}' => 0x0660,
        '\u{FF10}'..='\u{FF19}' => 0xFF10,
        _ => return c,
    };
    shift_ascii(c, zero, b'0')
}

/// Whitespace (ASCII, NBSP, U+1680, U+2000..U+200A, U+2028, U+2029, U+202F,
/// U+205F, U+3000), dashes (hyphen-minus, U+2010..U+2015, U+2212) and
/// punctuation.
fn is_separator(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n'
            | '\r'
            | ' '
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '-'
            | '\u{2010}'..='\u{2015}'
            | '\u{2212}'
            | ','
            | ';'
            | '.'
            | '\u{00B7}'
            | '\u{2022}'
            | '/'
            | '|'
            | ':'
            | '('
            | ')'
            | '['
            | ']'
            | '"'
            | '\''
            | '`'
    )
}

/// `c` at the same offset from `base` as from `first` (callers match a range
/// of at most 26 characters starting at `first`).
fn shift_ascii(c: char, first: u32, base: u8) -> char {
    char::from(base + (u32::from(c) - first) as u8)
}

/// ASCII and full-width letters -> a-z; `None` if the token holds anything
/// else (another script, an accented letter, a digit).
fn fold_latin(token: &str) -> Option<String> {
    let mut out = String::with_capacity(token.len());
    for c in token.chars().filter(|c| !is_invisible(*c)) {
        let c = match c {
            'A'..='Z' => c.to_ascii_lowercase(),
            '\u{FF21}'..='\u{FF3A}' => shift_ascii(c, 0xFF21, b'a'),
            '\u{FF41}'..='\u{FF5A}' => shift_ascii(c, 0xFF41, b'a'),
            _ => c,
        };
        if !c.is_ascii_lowercase() {
            return None;
        }
        out.push(c);
    }
    Some(out)
}

/// Entry text -> tokens: drop invisible characters, fold digits, split on
/// separators, drop position numbers (tokens of digits only, as in "1.").
pub fn split_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for c in text.chars().filter(|c| !is_invisible(*c)).map(fold_digit) {
        if is_separator(c) {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens.retain(|t| !t.bytes().all(|b| b.is_ascii_digit()));
    tokens
}

// ---------------------------------------------------------------- resolution

/// Why one token is not a list word. Depends only on the typed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Shorter than 3 letters and the start of a word: keep typing.
    Ambiguous,
    /// No list word starts with it.
    Unknown,
    /// Holds a character that is not an English letter.
    NonLatin,
}

impl TokenError {
    /// The normative status name (spec section 7).
    pub fn status(self) -> &'static str {
        match self {
            Self::Ambiguous => "ambiguous",
            Self::Unknown => "unknown",
            Self::NonLatin => "non_latin",
        }
    }
}

/// Autocomplete: every list index the token can still become, in list order.
/// It takes no key, so it can never depend on a friend's words.
pub fn candidates(token: &str) -> Vec<u8> {
    fold_latin(token).map_or_else(Vec::new, |prefix| candidates_folded(&prefix))
}

fn candidates_folded(prefix: &str) -> Vec<u8> {
    indexed_words()
        .filter(|(_, w)| w.starts_with(prefix))
        .map(|(i, _)| i)
        .collect()
}

/// One token -> its list index: the exact word, else a plural (word + `es`,
/// else word + `s`), else a prefix of at least 3 letters (always unique: the
/// list has unique 3-letter prefixes).
pub fn resolve(token: &str) -> Result<u8, TokenError> {
    let folded = fold_latin(token).ok_or(TokenError::NonLatin)?;
    if let Some(i) = index_of(&folded) {
        return Ok(i);
    }
    for suffix in ["es", "s"] {
        if let Some(i) = folded.strip_suffix(suffix).and_then(index_of) {
            return Ok(i);
        }
    }
    match candidates_folded(&folded).as_slice() {
        [] => Err(TokenError::Unknown),
        [i] if folded.len() >= MIN_PREFIX => Ok(*i),
        _ => Err(TokenError::Ambiguous),
    }
}

// ---------------------------------------------------------------- parsing

/// Why an entry is not 10 valid words. Every variant depends only on the
/// typed text, never on a friend's key; positions are 1-based tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    Unknown { position: usize },
    Ambiguous { position: usize },
    NonLatin { position: usize },
    WrongCount { count: usize },
    BadCheck,
}

impl ParseError {
    fn at(error: TokenError, position: usize) -> Self {
        match error {
            TokenError::Ambiguous => Self::Ambiguous { position },
            TokenError::Unknown => Self::Unknown { position },
            TokenError::NonLatin => Self::NonLatin { position },
        }
    }

    /// The normative status name (spec section 7).
    pub fn status(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Unknown { .. } => "unknown",
            Self::Ambiguous { .. } => "ambiguous",
            Self::NonLatin { .. } => "non_latin",
            Self::WrongCount { .. } => "wrong_count",
            Self::BadCheck => "bad_check",
        }
    }

    /// The 1-based token the error is about, when it is about one.
    pub fn position(&self) -> Option<usize> {
        match *self {
            Self::Unknown { position }
            | Self::Ambiguous { position }
            | Self::NonLatin { position } => Some(position),
            Self::Empty | Self::WrongCount { .. } | Self::BadCheck => None,
        }
    }
}

/// An entry -> 10 indexes. The first error wins: `Empty`, then the first
/// token that does not resolve, then the count, then the check word.
pub fn parse(text: &str) -> Result<[u8; WORDS], ParseError> {
    let tokens = split_tokens(text);
    if tokens.is_empty() {
        return Err(ParseError::Empty);
    }
    let mut indexes = Vec::with_capacity(tokens.len());
    for (n, token) in tokens.iter().enumerate() {
        indexes.push(resolve(token).map_err(|e| ParseError::at(e, n + 1))?);
    }
    let indexes: [u8; WORDS] = indexes
        .try_into()
        .map_err(|all: Vec<u8>| ParseError::WrongCount { count: all.len() })?;
    if !check_ok(&indexes) {
        return Err(ParseError::BadCheck);
    }
    Ok(indexes)
}

/// 4 or more tokens: words. Fewer: the old code (`device_fingerprint_v1` has
/// at most 3 groups).
pub fn looks_like_words(text: &str) -> bool {
    split_tokens(text).len() >= MIN_WORD_TOKENS
}

// ---------------------------------------------------------------- comparison

/// The result of comparing typed words with a key. It never carries the
/// key's words or indexes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Match,
    Mismatch,
    Invalid(ParseError),
}

/// Typed words against a user-identity key: parse first (every error depends
/// only on the typed text), then a constant-time XOR/OR fold over the 10
/// indexes.
pub fn compare(text: &str, ed_pub: &[u8; 32]) -> Verdict {
    let typed = match parse(text) {
        Ok(typed) => typed,
        Err(e) => return Verdict::Invalid(e),
    };
    let want = indexes_v1(ed_pub);
    let diff = typed
        .iter()
        .zip(want.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    // Through black_box, so the compiler cannot turn the fold into an early
    // exit at the first index that differs.
    if std::hint::black_box(diff) == 0 {
        Verdict::Match
    } else {
        Verdict::Mismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::device_fingerprint_v1;
    use hex::FromHex;
    use serde_json::Value;

    const WORDLIST: &str =
        include_str!("../../../../shared-vectors/rvn1/security_words/wordlist_v1.json");
    const WORDS_FILES: [&str; 4] = [
        include_str!("../../../../shared-vectors/rvn1/security_words/words_alice_001.json"),
        include_str!("../../../../shared-vectors/rvn1/security_words/words_bob_001.json"),
        include_str!("../../../../shared-vectors/rvn1/security_words/words_carol_001.json"),
        include_str!("../../../../shared-vectors/rvn1/security_words/words_dave_001.json"),
    ];
    const PARSE: &str =
        include_str!("../../../../shared-vectors/rvn1/security_words/parse_001.json");
    const RESOLVE: &str =
        include_str!("../../../../shared-vectors/rvn1/security_words/resolve_001.json");
    const CHECK_WORD: &str =
        include_str!("../../../../shared-vectors/rvn1/security_words/check_word_001.json");
    const PROTOCOL_LIST: &[u8] =
        include_bytes!("../../../../protocol/reference/raven_protocol/security_words_v1.txt");

    fn json(raw: &str) -> Value {
        serde_json::from_str(raw).unwrap()
    }

    fn key(hex: &Value) -> [u8; 32] {
        <[u8; 32]>::from_hex(hex.as_str().unwrap()).unwrap()
    }

    fn bytes(v: &Value) -> Vec<u8> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|n| u8::try_from(n.as_u64().unwrap()).unwrap())
            .collect()
    }

    fn alice() -> [u8; 32] {
        key(&json(WORDS_FILES[0])["inputs"]["ed_public_hex"])
    }

    fn token_status(r: Result<u8, TokenError>) -> &'static str {
        r.map_or_else(TokenError::status, |_| "ok")
    }

    #[test]
    fn crate_copy_is_the_protocol_list_byte_for_byte() {
        assert_eq!(LIST_V1_TXT.as_bytes(), PROTOCOL_LIST);
    }

    #[test]
    fn list_matches_the_pinned_hash_and_spot_rows() {
        let v = json(WORDLIST);
        let want = &v["expected"];
        assert_eq!(
            hex::encode(Sha256::digest(LIST_V1_TXT.as_bytes())),
            want["sha256"].as_str().unwrap()
        );
        assert_eq!(list_v1().len() as u64, want["rows"].as_u64().unwrap());
        let spot = want["spot"].as_object().unwrap();
        assert_eq!(spot.len(), 6);
        for (i, w) in spot {
            assert_eq!(list_v1()[i.parse::<usize>().unwrap()], w.as_str().unwrap());
        }
        assert!(LIST_V1_TXT.starts_with("# SPDX-License-Identifier: CC0-1.0\n"));
    }

    /// The rules resolution relies on: 3-8 letters a-z, unique 3-letter
    /// prefixes, no word a prefix of another (so plurals are unambiguous).
    #[test]
    fn list_follows_the_build_rules() {
        let list = list_v1();
        for (i, w) in list.iter().enumerate() {
            assert!((3..=8).contains(&w.len()), "{w}");
            assert!(w.bytes().all(|b| b.is_ascii_lowercase()), "{w}");
            for other in &list[i + 1..] {
                assert_ne!(w[..3], other[..3], "{w} {other}");
                assert!(
                    !other.starts_with(w) && !w.starts_with(other),
                    "{w} {other}"
                );
            }
        }
    }

    #[test]
    fn malformed_lists_are_refused() {
        let good: String = (0..LIST_ROWS).map(|i| format!("{i}\tw\n")).collect();
        assert!(parse_list(&good).is_some());
        assert!(parse_list(&format!("# comment\n{good}")).is_some());
        for bad in [
            good.replace("\n", "\r\n"),
            good.trim_end_matches('\n').to_string(),
            format!("\n{good}"),
            good.replacen("7\tw", "7\tW", 1),
            good.replacen("7\tw", "07\tw", 1),
            good.replacen("7\tw", "7\tw\tx", 1),
            good.replacen("7\tw", "7\t", 1),
            good.replacen("255\tw\n", "", 1),
            format!("{good}256\tw\n"),
        ] {
            assert!(parse_list(&bad).is_none(), "{bad:?}");
        }
    }

    /// Every vector key: digest, indexes, words and canonical text, and the
    /// old code of the same key next to them.
    #[test]
    fn words_vectors_and_the_old_code_agree() {
        let list_sha = &json(WORDLIST)["expected"]["sha256"];
        for raw in WORDS_FILES {
            assert_words_vector(&json(raw), list_sha);
        }
    }

    /// One `words_*` vector, made with the list whose SHA-256 is `list_sha`.
    fn assert_words_vector(v: &Value, list_sha: &Value) {
        let (inputs, want) = (&v["inputs"], &v["expected"]);
        let ed = key(&inputs["ed_public_hex"]);
        assert_eq!(inputs["label_ascii"].as_str().unwrap().as_bytes(), LABEL_V1);
        assert_eq!(&inputs["wordlist_sha256"], list_sha);
        let digest = Sha256::new()
            .chain_update(LABEL_V1)
            .chain_update(ed)
            .finalize();
        assert_eq!(hex::encode(digest), want["digest_hex"].as_str().unwrap());
        let indexes = indexes_v1(&ed);
        assert_eq!(indexes.to_vec(), bytes(&want["indexes"]));
        assert_eq!(indexes[..DATA_WORDS].to_vec(), bytes(&want["data_indexes"]));
        assert_eq!(
            u64::from(indexes[DATA_WORDS]),
            want["check_index"].as_u64().unwrap()
        );
        let words = words_v1(&ed);
        let want_words: Vec<&str> = want["words"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap())
            .collect();
        assert_eq!(words.to_vec(), want_words);
        assert_eq!(words.join(" "), want["text"].as_str().unwrap());
        assert_eq!(
            device_fingerprint_v1(&ed),
            want["device_fingerprint_v1"].as_str().unwrap()
        );
        assert!(check_ok(&indexes));
        assert_eq!(compare(&words.join(" "), &ed), Verdict::Match);
    }

    #[test]
    fn check_word_vectors() {
        let v = json(CHECK_WORD);
        assert_eq!(v["expected"]["cases"].as_array().unwrap().len(), 4);
        assert_check_word_vector(&v);
    }

    fn assert_check_word_vector(v: &Value) {
        for c in v["expected"]["cases"].as_array().unwrap() {
            let data = bytes(&c["data_indexes"]);
            assert_eq!(
                u64::from(gf_check(&data)),
                c["check_index"].as_u64().unwrap()
            );
        }
    }

    /// Exhaustive on 64 codes: every single wrong word and every swap of two
    /// different words fails the check.
    #[test]
    fn check_word_catches_every_substitution_and_swap() {
        for seed in 0..64u8 {
            let code = indexes_v1(&[seed; 32]);
            assert!(check_ok(&code));
            for (p, &right) in code.iter().enumerate() {
                for v in (0..=u8::MAX).filter(|v| *v != right) {
                    let mut bad = code;
                    bad[p] = v;
                    assert!(!check_ok(&bad), "seed {seed} position {p} value {v}");
                }
            }
            for (i, a) in code.iter().enumerate() {
                for (j, b) in code.iter().enumerate().skip(i + 1) {
                    if a != b {
                        let mut bad = code;
                        bad.swap(i, j);
                        assert!(!check_ok(&bad), "seed {seed} swap {i} {j}");
                    }
                }
            }
        }
    }

    #[test]
    fn resolve_vectors() {
        let v = json(RESOLVE);
        assert_eq!(v["expected"]["cases"].as_array().unwrap().len(), 14);
        assert_resolve_vector(&v);
    }

    fn assert_resolve_vector(v: &Value) {
        for c in v["expected"]["cases"].as_array().unwrap() {
            let token = c["token"].as_str().unwrap();
            let want = c["result"].as_array().unwrap();
            let got = resolve(token);
            assert_eq!(token_status(got), want[0].as_str().unwrap(), "{token:?}");
            match got {
                Ok(i) => assert_eq!(u64::from(i), want[1].as_u64().unwrap()),
                // The reference echoes the typed token for every error.
                Err(_) => assert_eq!(want[1].as_str().unwrap(), token),
            }
        }
    }

    #[test]
    fn parse_vectors() {
        let v = json(PARSE);
        assert_eq!(key(&v["inputs"]["ed_public_hex"]), alice());
        assert_eq!(v["expected"]["cases"].as_array().unwrap().len(), 14);
        assert_parse_vector(&v);
    }

    /// Every case of a `parse_*` vector; its key is alice's.
    fn assert_parse_vector(v: &Value) {
        let ed = key(&v["inputs"]["ed_public_hex"]);
        for c in v["expected"]["cases"].as_array().unwrap() {
            let input = c["input"].as_str().unwrap();
            let name = c["case"].as_str().unwrap();
            let want = &c["expected"];
            assert_eq!(
                looks_like_words(input),
                want["looks_like_words"].as_bool().unwrap(),
                "{name}"
            );
            let Some(parse_want) = want.get("parse") else {
                continue;
            };
            match parse(input) {
                Ok(indexes) => {
                    assert_eq!(parse_want["status"], "ok", "{name}");
                    assert_eq!(indexes.to_vec(), bytes(&parse_want["indexes"]), "{name}");
                }
                Err(e) => {
                    assert_eq!(parse_want["status"], e.status(), "{name}");
                    match e {
                        ParseError::Unknown { position }
                        | ParseError::Ambiguous { position }
                        | ParseError::NonLatin { position } => {
                            assert_eq!(parse_want["position"], position, "{name}")
                        }
                        ParseError::WrongCount { count } => {
                            assert_eq!(parse_want["count"], count, "{name}")
                        }
                        ParseError::Empty | ParseError::BadCheck => {
                            assert_eq!(parse_want.as_object().unwrap().len(), 1, "{name}")
                        }
                    }
                }
            }
            let verdict = match compare(input, &ed) {
                Verdict::Match => "match",
                Verdict::Mismatch => "mismatch",
                Verdict::Invalid(e) => e.status(),
            };
            assert_eq!(want["compare_with_alice"], verdict, "{name}");
        }
    }

    /// The desktop apps' copy of the list (`desktop/design/raven-security-words-v1.txt`,
    /// which their debug-only mock engines embed) differs from this one only in
    /// its `#` lines: its rows must be this list's, and its bytes are pinned
    /// (the Windows app's tests pin the same SHA-256).
    #[test]
    fn desktop_word_list_has_these_rows() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../desktop/design/raven-security-words-v1.txt");
        let list_text =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(parse_list(&list_text).as_ref(), Some(list_v1()));
        assert_eq!(
            hex::encode(Sha256::digest(list_text.as_bytes())),
            "560cbd462be90ca14769d06c52a0e4afa23ae60152ee880ead38d76fd61ef145"
        );
    }

    #[test]
    fn every_word_resolves() {
        for (i, w) in indexed_words() {
            let mut title = w.to_string();
            title[..1].make_ascii_uppercase();
            for t in [
                w.to_string(),
                w.to_ascii_uppercase(),
                title,
                w[..3].to_string(),
                format!("{w}s"),
                format!("{w}es"),
            ] {
                assert_eq!(resolve(&t), Ok(i), "{t}");
            }
            assert_eq!(resolve(&w[..2]), Err(TokenError::Ambiguous), "{w}");
            assert!(candidates(&w[..1]).contains(&i));
            assert_eq!(candidates(&w[..3]), vec![i]);
        }
    }

    #[test]
    fn entry_folds() {
        let alice = alice();
        let a = words_v1(&alice);
        // Invisible characters are dropped before splitting, so "1<ZWSP>" is
        // still a position number.
        assert_eq!(
            split_tokens("1\u{200b}. turtle\u{200c} \u{06f2}\u{2014}frog\u{a0}\u{0663}) bread"),
            ["turtle", "frog", "bread"]
        );
        assert!(split_tokens("").is_empty());
        assert_eq!(parse(" 1. 2. "), Err(ParseError::Empty));
        let with_digit = [&a[..3], &["turtle1"], &a[4..]].concat().join(" ");
        assert_eq!(
            parse(&with_digit),
            Err(ParseError::NonLatin { position: 4 })
        );
        assert!(!looks_like_words("If4x 36FU omFi"));
        assert!(looks_like_words("a b c d"));
        let bob = json(WORDS_FILES[1])["expected"]["text"].clone();
        assert_eq!(compare(bob.as_str().unwrap(), &alice), Verdict::Mismatch);
        assert_eq!(
            compare(&a[..9].join(" "), &alice),
            Verdict::Invalid(ParseError::WrongCount { count: 9 })
        );
        // Every separator class and the full-width digits.
        let mixed = format!(
            "\u{ff11}\u{ff10}){}\u{3000}{}\u{2212}{}\u{2022}{}|{}`{}[{}]{}\"{}'{}",
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9]
        );
        assert_eq!(compare(&mixed, &alice), Verdict::Match);
        // A token that resolves too late: errors keep their order.
        let late = format!("{} xyzzy", a.join(" "));
        assert_eq!(parse(&late), Err(ParseError::Unknown { position: 11 }));
    }

    #[test]
    fn candidates_fold_like_resolve_and_never_take_a_key() {
        let all = candidates("");
        assert_eq!(all.len(), LIST_ROWS);
        assert!(all.iter().copied().eq(0..=u8::MAX));
        let tur = candidates("tur");
        assert_eq!(tur.len(), 1);
        assert_eq!(list_v1()[usize::from(tur[0])], "turtle");
        assert_eq!(candidates("\u{ff34}\u{ff35}R"), tur);
        assert_eq!(candidates("t\u{200b}ur"), tur);
        assert!(candidates("t1").is_empty());
        assert!(candidates("caf\u{e9}").is_empty());
        assert!(candidates("xyz").is_empty());
        let s = candidates("s");
        assert!(s.len() > 1 && s.windows(2).all(|p| p[0] < p[1]));
    }

    #[test]
    fn status_names_are_the_spec_names() {
        let names: Vec<&str> = [
            ParseError::Empty,
            ParseError::Unknown { position: 1 },
            ParseError::Ambiguous { position: 1 },
            ParseError::NonLatin { position: 1 },
            ParseError::WrongCount { count: 1 },
            ParseError::BadCheck,
        ]
        .iter()
        .map(ParseError::status)
        .collect();
        assert_eq!(
            names,
            [
                "empty",
                "unknown",
                "ambiguous",
                "non_latin",
                "wrong_count",
                "bad_check"
            ]
        );
        assert_eq!(TokenError::Ambiguous.status(), "ambiguous");
        assert_eq!(TokenError::Unknown.status(), "unknown");
        assert_eq!(TokenError::NonLatin.status(), "non_latin");
    }

    #[test]
    fn positions_are_the_token_errors_own() {
        let positions: Vec<Option<usize>> = [
            ParseError::Empty,
            ParseError::Unknown { position: 2 },
            ParseError::Ambiguous { position: 3 },
            ParseError::NonLatin { position: 4 },
            ParseError::WrongCount { count: 9 },
            ParseError::BadCheck,
        ]
        .iter()
        .map(ParseError::position)
        .collect();
        assert_eq!(positions, [None, Some(2), Some(3), Some(4), None, None]);
        let a = words_v1(&alice());
        let typo = [&a[..1], &["xyzzy"], &a[2..]].concat().join(" ");
        assert_eq!(parse(&typo).unwrap_err().position(), Some(2));
    }

    #[test]
    fn digits_of_every_script_fold() {
        for zero in [0x06F0, 0x0660, 0xFF10] {
            let folded: String = (0..10)
                .map(|d| fold_digit(char::from_u32(zero + d).unwrap()))
                .collect();
            assert_eq!(folded, "0123456789");
        }
        for c in ['7', 'a', '\u{06EF}', '\u{066A}', '\u{FF1A}'] {
            assert_eq!(fold_digit(c), c);
        }
    }
}
