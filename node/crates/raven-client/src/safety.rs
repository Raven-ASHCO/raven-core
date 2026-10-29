//! What every response goes through: display text sanitised (control
//! characters, bidi controls and zero-width characters removed), and no field
//! named like a secret.

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
