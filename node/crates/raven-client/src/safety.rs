//! What every response goes through: display text sanitised (control
//! characters, bidi controls and zero-width characters removed, but for the
//! two joiners where writing itself needs them: [`joiner_stays`]), and no
//! field named like a secret.

use serde_json::Value;

/// Substrings refused in response field names (raven-node's IPC rule,
/// `raven_core::ipc::FORBIDDEN_FIELD_TOKENS`, plus `secret`).
pub const FORBIDDEN_FIELD_TOKENS: [&str; 5] =
    ["seed", "private_key", "secret", "plaintext", "recovery"];

/// The first field name in `value` that holds a forbidden token (compared in
/// lower case), at any depth.
pub fn forbidden_field(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => map.iter().find_map(|(key, v)| {
            let lower = key.to_ascii_lowercase();
            if FORBIDDEN_FIELD_TOKENS.iter().any(|bad| lower.contains(bad)) {
                Some(key.clone())
            } else {
                forbidden_field(v)
            }
        }),
        Value::Array(items) => items.iter().find_map(forbidden_field),
        _ => None,
    }
}

/// Bidi embeddings, overrides, isolates and marks.
fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}'
    )
}

/// Zero-width and other invisible format characters that can hide or fake
/// text (raven-core's single-line list, plus ZWNJ and ZWJ: the contract
/// removes every zero-width character).
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200D}'
            | '\u{2060}'..='\u{2064}'
            | '\u{206A}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0E}'
            | '\u{FFA0}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

fn is_control(c: char) -> bool {
    let u = c as u32;
    u < 0x20 || u == 0x7f || (0x80..=0x9f).contains(&u)
}

/// A letter (or its mark) of a script whose letters join, and that writes a
/// zero-width non-joiner inside its words: Arabic script (Persian, Urdu,
/// Kurdish and the rest; never its digits or punctuation) and the scripts of
/// India from Devanagari to Sinhala.
fn joins_letters(c: char) -> bool {
    matches!(
        c,
        '\u{0620}'..='\u{065F}'
            | '\u{066E}'..='\u{06D3}'
            | '\u{06D5}'..='\u{06DC}'
            | '\u{06DF}'..='\u{06E8}'
            | '\u{06EA}'..='\u{06EF}'
            | '\u{06FA}'..='\u{06FF}'
            | '\u{0750}'..='\u{077F}'
            | '\u{08A0}'..='\u{08FF}'
            | '\u{0900}'..='\u{0DFF}'
    )
}

/// A picture character: what a zero-width joiner may stand between to make
/// one emoji of several (a family, a flag, a profession).
fn is_picture(c: char) -> bool {
    matches!(
        c,
        '\u{1F000}'..='\u{1FAFF}'
            | '\u{2190}'..='\u{21FF}'
            | '\u{2300}'..='\u{23FF}'
            | '\u{25A0}'..='\u{27BF}'
            | '\u{2B00}'..='\u{2BFF}'
    )
}

/// Whether a zero-width non-joiner (U+200C) or joiner (U+200D) stays: only
/// where writing itself needs it. The non-joiner between two joining letters
/// (Persian writes its half-space with it: without it the two halves of a
/// word run into one wrong shape), the joiner between two joining letters or
/// between two pictures (after a picture's own selector too), so that one
/// emoji made of several stays one. `before` is the last character kept,
/// `after` the next one as written: at the start or the end of a text, next
/// to a space, a digit or a Latin letter, or beside another invisible
/// character, both go as every zero-width character does, so that neither
/// can hide in a name, an address or a code.
fn joiner_stays(before: Option<char>, joiner: char, after: Option<char>) -> bool {
    let (Some(before), Some(after)) = (before, after) else {
        return false;
    };
    if joins_letters(before) && joins_letters(after) {
        return true;
    }
    joiner == '\u{200D}' && (is_picture(before) || before == '\u{FE0F}') && is_picture(after)
}

fn sanitize(input: &str, multi_line: bool) -> String {
    let stripped = raven_core::sanitize::strip_ansi(input);
    let mut out = String::with_capacity(stripped.len());
    let mut chars = stripped.chars().peekable();
    let line_break = if multi_line { '\n' } else { ' ' };
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push(line_break);
            }
            '\n' | '\u{0B}' | '\u{0C}' | '\u{85}' | '\u{2028}' | '\u{2029}' => out.push(line_break),
            '\t' => out.push(if multi_line { '\t' } else { ' ' }),
            '\u{200C}' | '\u{200D}'
                if joiner_stays(out.chars().next_back(), c, chars.peek().copied()) =>
            {
                out.push(c);
            }
            c if is_control(c) || is_bidi_control(c) || is_invisible(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// Text shown on one line (a name, an address, a status): line breaks and
/// tabs become spaces.
pub fn line(input: &str) -> String {
    sanitize(input, false).trim().to_owned()
}

/// Text shown as a block (a message body, details): line breaks and tabs
/// kept, as `\n` and `\t`.
pub fn text(input: &str) -> String {
    sanitize(input, true)
}

/// Every string in `value`, sanitised as text (keys are the engine's own).
pub fn sanitize_strings(value: &mut Value) {
    match value {
        Value::String(s) => {
            let clean = text(s);
            if clean != *s {
                *s = clean;
            }
        }
        Value::Array(items) => items.iter_mut().for_each(sanitize_strings),
        Value::Object(map) => map.values_mut().for_each(sanitize_strings),
        _ => {}
    }
}

/// What error texts show instead of a security code the user has not
/// verified.
pub const HIDDEN_CODE: &str = "[security code hidden until verified]";

/// `text` with every one of `codes` replaced by [`HIDDEN_CODE`] (the
/// terminal app's controller.rs `hide_codes`).
pub fn hide_codes(text: &str, codes: &[String]) -> String {
    let mut text = text.to_owned();
    for code in codes.iter().filter(|code| looks_like_code(code)) {
        text = text.replace(code.as_str(), HIDDEN_CODE);
    }
    hide_code_shapes(&text)
}

fn looks_like_code(code: &str) -> bool {
    code.len() >= 8 && code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// `text` with everything shaped like a security code (`If4x-36FU-omFi`:
/// groups of 4, 4 and 1 to 4 letters and digits) replaced (the terminal
/// app's errors.rs `hide_security_codes`).
pub fn hide_code_shapes(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while at < chars.len() {
        match code_len_at(&chars, at) {
            Some(len) => {
                out.push_str(HIDDEN_CODE);
                at += len;
            }
            None => {
                out.push(chars[at]);
                at += 1;
            }
        }
    }
    out
}

fn code_len_at(chars: &[char], at: usize) -> Option<usize> {
    let joined = |c: &char| c.is_ascii_alphanumeric() || *c == '-';
    if at > 0 && joined(&chars[at - 1]) {
        return None;
    }
    let run = |from: usize| {
        chars
            .get(from..)
            .unwrap_or(&[])
            .iter()
            .take_while(|c| c.is_ascii_alphanumeric())
            .count()
    };
    if run(at) != 4 || chars.get(at + 4) != Some(&'-') {
        return None;
    }
    if run(at + 5) != 4 || chars.get(at + 9) != Some(&'-') {
        return None;
    }
    let last = run(at + 10);
    let end = at + 10 + last;
    if !(1..=4).contains(&last) || chars.get(end) == Some(&'-') {
        return None;
    }
    Some(end - at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn display_text_loses_controls_bidi_and_zero_width() {
        let evil = "Ali\u{202E}gnp.exe\u{200B}\u{200D}\u{FEFF}\u{1b}[31m!\u{7}\u{2066}x\u{2069}";
        assert_eq!(line(evil), "Alignp.exe!x");
        assert_eq!(line("two\nlines\r\nhere\tok"), "two lines here ok");
        assert_eq!(text("two\nlines\r\nhere\tok\r"), "two\nlines\nhere\tok\n");
        assert_eq!(line("\u{E0041}\u{E0042}tag"), "tag");
        // Text in other alphabets stays.
        assert_eq!(
            line("Ren\u{00E9} \u{0645}\u{0647}\u{0631}"),
            "Ren\u{00E9} \u{0645}\u{0647}\u{0631}"
        );
    }

    /// W5N.6 (2026-11-15): a Persian half-space and an emoji made of several
    /// were shown without their joiners: wrong words, a family as four
    /// people. They stay where writing needs them and nowhere else.
    #[test]
    fn the_two_joiners_stay_where_writing_needs_them() {
        // Persian: the half-space inside a word, twice.
        let persian = "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645} \u{062E}\u{0627}\u{0646}\u{0647}\u{200C}\u{0647}\u{0627}";
        assert_eq!(text(persian), persian);
        assert_eq!(line(persian), persian);
        // One family, one flag, one profession.
        let emoji = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466} \u{1F3F3}\u{FE0F}\u{200D}\u{1F308} \u{1F469}\u{200D}\u{1F4BB}";
        assert_eq!(text(emoji), emoji);
        // A heart with its selector, joined to a flame.
        let heart = "\u{2764}\u{FE0F}\u{200D}\u{1F525}";
        assert_eq!(text(heart), heart);
        // Devanagari: a joiner after the virama.
        let hindi = "\u{0915}\u{094D}\u{200D}\u{0937}";
        assert_eq!(text(hindi), hindi);
        // Nowhere else: between Latin letters, digits, at an end, beside a
        // space, in a run, between a letter and a picture.
        assert_eq!(text("pay\u{200C}pal"), "paypal");
        assert_eq!(text("12\u{200D}34"), "1234");
        assert_eq!(
            text("\u{200C}\u{0633}\u{0644}\u{0627}\u{0645}\u{200C}"),
            "\u{0633}\u{0644}\u{0627}\u{0645}"
        );
        assert_eq!(
            text("\u{0645}\u{06CC}\u{200C} \u{0631}"),
            "\u{0645}\u{06CC} \u{0631}"
        );
        assert_eq!(
            text("\u{0645}\u{200C}\u{200C}\u{200B}\u{06CC}"),
            "\u{0645}\u{06CC}"
        );
        assert_eq!(text("a\u{200D}\u{1F600}"), "a\u{1F600}");
        assert_eq!(text("\u{1F600}\u{200D}a"), "\u{1F600}a");
        // A run between two joining letters comes out as one: only the last
        // of the run has a letter on both sides once the others are gone.
        assert_eq!(
            text("\u{0645}\u{06CC}\u{200C}\u{200C}\u{200C}\u{0631}"),
            "\u{0645}\u{06CC}\u{200C}\u{0631}"
        );
        // Arabic digits and punctuation are not joining letters.
        assert_eq!(text("\u{06F1}\u{200C}\u{06F2}"), "\u{06F1}\u{06F2}");
        assert_eq!(text("\u{0645}\u{200C}\u{060C}"), "\u{0645}\u{060C}");
        // The other zero-width characters and the bidi controls go as before.
        assert_eq!(
            text("\u{0645}\u{200B}\u{06CC} \u{202E}\u{0645}\u{2060}\u{06CC}\u{FEFF}"),
            "\u{0645}\u{06CC} \u{0645}\u{06CC}"
        );
    }

    #[test]
    fn forbidden_fields_are_found_at_any_depth() {
        assert_eq!(forbidden_field(&json!({"a": 1, "b": [{"c": 2}]})), None);
        for key in [
            "seed",
            "Seed_hex",
            "private_key",
            "SECRET",
            "plaintext_body",
            "recovery",
        ] {
            let v = json!({"ok": {"list": [{"x": {key: 1}}]}});
            assert_eq!(forbidden_field(&v).as_deref(), Some(key), "{key}");
        }
        // Values are data, never refused.
        assert_eq!(forbidden_field(&json!({"text": "my seed is secret"})), None);
    }

    #[test]
    fn security_codes_are_hidden() {
        let codes = vec!["If4x-36FU-omFi".to_string()];
        let t = "fingerprint mismatch: got If4x-36FU-omFi, expected NN72-hvSx-N7W";
        let hidden = hide_codes(t, &codes);
        assert!(
            !hidden.contains("If4x") && !hidden.contains("NN72"),
            "{hidden}"
        );
        assert_eq!(hidden.matches(HIDDEN_CODE).count(), 2);
        // A UUID-like dashed run is not a code.
        let uuid = "id 1234-5678-9abc-def0";
        assert_eq!(hide_code_shapes(uuid), uuid);
    }

    #[test]
    fn strings_in_a_response_are_sanitised() {
        let mut v = json!({"name": "a\u{202E}b", "list": ["c\u{200B}d"], "n": 5});
        sanitize_strings(&mut v);
        assert_eq!(v, json!({"name": "ab", "list": ["cd"], "n": 5}));
    }
}
