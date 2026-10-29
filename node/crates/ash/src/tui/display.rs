//! Text shaping for every untrusted string the screen shows: message bodies,
//! names, tags, addresses, captured output and service-log lines.
//!
//! Untrusted text reaches the screen only through these functions, and then
//! only as a Paragraph, Line or Span. Each one runs the same passes, in order:
//!
//! 1. raven-core's `sanitize_terminal_line`: escape sequences, C0, C1, DEL,
//!    bidi controls and invisible format characters go, TAB becomes a space
//!    and a line break inside one line becomes a visible ⏎;
//! 2. [`extra_pass`]: what that leaves which still draws nothing, or draws on
//!    top of its neighbours;
//! 3. [`emoji_normalize`]: the emoji whose width terminals disagree on are
//!    taken apart, so ratatui's count and the terminal's agree;
//! 4. [`cap_graphemes`]: a grapheme of more than 8 scalars becomes U+FFFD.
//!
//! ratatui alone draws `A ESC[2J x` as `A[2Jx` and passes bidi and tag
//! characters through, so nothing skips these passes.

use ratatui::buffer::CellWidth;
use ratatui::style::Style;
use ratatui::text::Span;
use raven_core::sanitize::sanitize_terminal_line;

use super::bridge;
#[cfg(test)]
use super::testkit;

/// Most lines one message body shows, even when it is shown in full.
const MAX_BODY_LINES: usize = 200;
/// Most scalars one grapheme may hold (zalgo marks, long jamo runs); a longer
/// one is drawn as U+FFFD.
const MAX_GRAPHEME_SCALARS: usize = 8;
/// What a security code in not-yet-parsed pasted text is shown as.
const CODE_MASK: &str = "\u{2022}\u{2022}\u{2022}";
/// The key in front of a security code in a card, a whoami block or JSON
/// (ASCII, matched in any case).
const CODE_KEY: &str = "fingerprint";
/// Length of a security code: three groups of 4, joined by '-'.
const CODE_LEN: usize = 14;
const ZWJ: char = '\u{200D}';

/// A message body ready to draw, one entry per line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BodyView {
    pub(super) lines: Vec<String>,
    /// Characters not shown (line breaks count), 0 when the body is whole.
    /// The last line then ends in cli.rs's `… (+N more characters)`.
    pub(super) more_chars: usize,
}

/// A message body as display lines.
///
/// CRLF and a lone CR break lines like LF, and each line goes through every
/// pass. The text is then clipped by cli.rs's own `clip_body`, so the marker
/// reads as it does in the CLI: at `TTY_BODY_MAX_CHARS` characters unless
/// `show_all`, and always at [`MAX_BODY_LINES`] lines.
pub(super) fn body_lines(raw: &str, show_all: bool) -> BodyView {
    let lines = shaped_lines(raw);
    let shown = lines.len().min(MAX_BODY_LINES);
    // Characters up to the end of the last line that may show, counting the
    // line breaks between them as clip_body does.
    let line_cap = lines[..shown]
        .iter()
        .map(|line| line.chars().count())
        .sum::<usize>()
        + shown
        - 1;
    let keep = if show_all {
        line_cap
    } else {
        line_cap.min(bridge::TTY_BODY_MAX_CHARS)
    };
    let text = lines.join("\n");
    let more_chars = text.chars().count().saturating_sub(keep);
    let text = bridge::clip_body(text, Some(keep));
    BodyView {
        lines: text.split('\n').map(str::to_owned).collect(),
        more_chars,
    }
}

/// Untrusted text for one row (a name, tag, address, captured or log line):
/// every pass, with line breaks shown as ⏎, then cut to `max_cells` terminal
/// cells. A cut line ends in `ellipsis` (the glyph set's), counted in the cap;
/// when even that does not fit, the text is cut bare.
pub(super) fn one_line(raw: &str, max_cells: u16, ellipsis: &str) -> String {
    let text = shape(raw);
    let max = usize::from(max_cells);
    if cells(&text) <= max {
        return text;
    }
    let mark = if cells(ellipsis) <= max { ellipsis } else { "" };
    let room = max - cells(mark);
    let mut out = String::new();
    let mut used = 0;
    for grapheme in Span::raw(text.as_str()).styled_graphemes(Style::default()) {
        let width = usize::from(grapheme.symbol.cell_width());
        if used + width > room {
            break;
        }
        used += width;
        out.push_str(grapheme.symbol);
    }
    out.push_str(mark);
    out
}

/// [`one_line`], except that a cut takes out the middle, so both ends stay:
/// a folder keeps its root and its own name. The two kept ends share the
/// room, the start taking the odd cell.
pub(super) fn one_line_middle(raw: &str, max_cells: u16, ellipsis: &str) -> String {
    let text = shape(raw);
    let max = usize::from(max_cells);
    if cells(&text) <= max {
        return text;
    }
    let mark = if cells(ellipsis) <= max { ellipsis } else { "" };
    let room = max - cells(mark);
    let span = Span::raw(text.as_str());
    let graphemes: Vec<(&str, usize)> = span
        .styled_graphemes(Style::default())
        .map(|g| (g.symbol, usize::from(g.symbol.cell_width())))
        .collect();
    // Whole graphemes only, as many as fit in each end's share.
    let mut used = 0;
    let head: String = graphemes
        .iter()
        .take_while(|(_, width)| {
            used += width;
            used <= room - room / 2
        })
        .map(|(symbol, _)| *symbol)
        .collect();
    let mut used = 0;
    let mut tail: Vec<&str> = graphemes
        .iter()
        .rev()
        .take_while(|(_, width)| {
            used += width;
            used <= room / 2
        })
        .map(|(symbol, _)| *symbol)
        .collect();
    tail.reverse();
    format!("{head}{mark}{}", tail.concat())
}

/// Cells untrusted `raw` takes once shaped for one row, as [`one_line`]
/// would draw it uncut.
pub(super) fn width(raw: &str) -> usize {
    cells(&shape(raw))
}

/// Typed or pasted text for an input field: C0, DEL and C1 are dropped and
/// TAB becomes a space. A multi-line field keeps line breaks, with CRLF and a
/// lone CR (what most terminals paste) as LF; a one-line field drops them.
/// Showing the field still goes through the passes above.
pub(super) fn field_input(raw: &str, multiline: bool) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\t' => out.push(' '),
            '\r' if multiline => {
                chars.next_if_eq(&'\n');
                out.push('\n');
            }
            '\n' if multiline => out.push('\n'),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Pasted text that has not parsed yet, with the security code hidden: the
/// value after `fingerprint` (a card's `fingerprint=…`, a whoami block's
/// `fingerprint  …`, JSON's `"fingerprint": "…"`) becomes •••. The friend's
/// code must not be on screen before the user has typed it as the friend
/// reads it out.
///
/// Every pass runs first, line by line, so the mask sees what the screen
/// would show: an invisible character inside `fingerprint=` hides nothing.
/// A code wrapped onto the next line is masked there too.
pub(super) fn mask_card_fingerprint(raw: &str) -> String {
    let chars: Vec<char> = shaped_lines(raw).join("\n").chars().collect();
    let key_len = CODE_KEY.len();
    let mut out = String::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        if !starts_with_code_key(&chars[i..]) {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let mut at = i + key_len;
        while chars
            .get(at)
            .is_some_and(|c| matches!(c, '=' | ':' | '"' | '\'' | ' ' | '\n'))
        {
            at += 1;
        }
        out.extend(&chars[i..at]);
        if at == i + key_len {
            // `fingerprints`, `fingerprinted`: not a key.
            i = at;
            continue;
        }
        let mut taken = 0;
        let mut breaks = 0;
        loop {
            match chars.get(at) {
                Some(&c) if is_code_char(c) => taken += 1,
                Some('\n')
                    if taken < CODE_LEN && chars.get(at + 1).is_some_and(|&c| is_code_char(c)) =>
                {
                    breaks += 1
                }
                _ => break,
            }
            at += 1;
        }
        if taken > 0 {
            out.push_str(CODE_MASK);
        }
        out.extend(std::iter::repeat_n('\n', breaks));
        i = at;
    }
    out
}

/// True when `chars` starts with [`CODE_KEY`], in any ASCII case.
fn starts_with_code_key(chars: &[char]) -> bool {
    chars.len() >= CODE_KEY.len()
        && chars
            .iter()
            .zip(CODE_KEY.chars())
            .all(|(c, k)| c.eq_ignore_ascii_case(&k))
}

/// A character a masked value may hold: anything but white space, quotes and
/// the punctuation around a value. Masking too much is harmless.
fn is_code_char(c: char) -> bool {
    !c.is_whitespace() && !matches!(c, '"' | '\'' | ',' | ';' | '{' | '}' | '[' | ']')
}

/// `raw` split at CRLF, CR and LF, each line through every pass.
fn shaped_lines(raw: &str) -> Vec<String> {
    let text = raw.replace("\r\n", "\n").replace('\r', "\n");
    text.split('\n').map(shape).collect()
}

/// Every pass, in order, for text drawn on one line.
///
/// The grapheme cap runs last: before emoji_normalize a skin-toned family
/// (11 scalars in one grapheme) would be lost to U+FFFD instead of coming
/// apart into its emoji.
fn shape(line: &str) -> String {
    let line = sanitize_terminal_line(line);
    let line = extra_pass(&line);
    let line = emoji_normalize(&line);
    cap_graphemes(&line)
}

/// Drops what raven-core's sanitizer leaves that still draws nothing, or
/// draws on top of its neighbours.
fn extra_pass(text: &str) -> String {
    text.chars().filter(|&c| !is_hidden_extra(c)).collect()
}

fn is_hidden_extra(c: char) -> bool {
    matches!(
        c,
        // Prepended concatenation marks (the Arabic number signs and their
        // kin): each draws across the digits that follow it.
        '\u{0600}'..='\u{0605}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{110BD}'
            | '\u{110CD}'
            // Mongolian free variation selectors (U+180E is already gone).
            | '\u{180B}'..='\u{180F}'
            // Unassigned, and ignored (drawn as nothing) by default.
            | '\u{2065}'
            | '\u{FFF0}'..='\u{FFF8}'
            // Egyptian hieroglyph and shorthand format controls.
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            // Variation selectors 17-256, inside the ignorable block around
            // them.
            | '\u{E0080}'..='\u{E0FFF}'
            // Noncharacters: U+FDD0-FDEF and the last two of every plane.
            | '\u{FDD0}'..='\u{FDEF}'
    ) || u32::from(c) & 0xFFFE == 0xFFFE
}

/// Takes apart the emoji whose width terminals disagree on, so each one
/// stands alone at the width ratatui counts:
///
/// - VS15 and VS16 (text and emoji presentation) and the skin-tone modifiers
///   U+1F3FB-1F3FF are dropped;
/// - a ZWJ in front of an emoji is dropped, so a family or any other ZWJ
///   sequence becomes its separate emoji. A ZWJ joins a grapheme only in
///   front of a pictograph, so this never splits a word;
/// - regional indicators become ASCII: a pair (a flag) `[DE]`, a lone one
///   `[D]`.
///
/// ZWJ and ZWNJ between letters, which Arabic and Indic scripts need for
/// shaping, are kept.
fn emoji_normalize(text: &str) -> String {
    let chars: Vec<char> = text
        .chars()
        .filter(|&c| !matches!(c, '\u{FE0E}' | '\u{FE0F}' | '\u{1F3FB}'..='\u{1F3FF}'))
        .collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == ZWJ {
            // A run of joiners is one joiner: what follows the run decides.
            let end = chars[i..]
                .iter()
                .position(|&n| n != ZWJ)
                .map_or(chars.len(), |n| i + n);
            if !chars.get(end).is_some_and(|&n| is_pictograph(n)) {
                out.extend(&chars[i..end]);
            }
            i = end;
            continue;
        }
        match regional_letter(c) {
            Some(first) => {
                out.push('[');
                out.push(first);
                if let Some(second) = chars.get(i + 1).and_then(|&n| regional_letter(n)) {
                    out.push(second);
                    i += 1;
                }
                out.push(']');
            }
            None => out.push(c),
        }
        i += 1;
    }
    out
}

/// The emoji blocks (U+1F000-1FAFF, U+2600-27BF, U+2B00-2BFF), plus the
/// other symbol blocks and single symbols that ZWJ sequences join to (the
/// arrows of 'head shaking', ©, ™ and the like).
fn is_pictograph(c: char) -> bool {
    matches!(
        c,
        '\u{1F000}'..='\u{1FAFF}'
            | '\u{2600}'..='\u{27BF}'
            | '\u{2B00}'..='\u{2BFF}'
            | '\u{2190}'..='\u{21FF}'
            | '\u{2300}'..='\u{23FF}'
            | '\u{25A0}'..='\u{25FF}'
            | '\u{2900}'..='\u{297F}'
            | '\u{00A9}'
            | '\u{00AE}'
            | '\u{203C}'
            | '\u{2049}'
            | '\u{2122}'
            | '\u{2139}'
            | '\u{24C2}'
            | '\u{3030}'
            | '\u{303D}'
            | '\u{3297}'
            | '\u{3299}'
    )
}

/// 'A'-'Z' for the regional indicators U+1F1E6-1F1FF.
fn regional_letter(c: char) -> Option<char> {
    let u = u32::from(c);
    if (0x1F1E6..=0x1F1FF).contains(&u) {
        char::from_u32(u - 0x1F1E6 + u32::from(b'A'))
    } else {
        None
    }
}

/// Replaces each grapheme of more than [`MAX_GRAPHEME_SCALARS`] scalars with
/// U+FFFD.
fn cap_graphemes(text: &str) -> String {
    Span::raw(text)
        .styled_graphemes(Style::default())
        .map(|grapheme| {
            if grapheme.symbol.chars().count() > MAX_GRAPHEME_SCALARS {
                "\u{FFFD}"
            } else {
                grapheme.symbol
            }
        })
        .collect()
}

/// Cells `text` takes, counted per grapheme as ratatui's buffer counts them
/// when it draws, so a cut line never draws wider than its cap.
/// `Span::width` measures the whole string at once and can count less: one
/// cell for an Arabic lam-alef pair that the buffer draws in two.
fn cells(text: &str) -> usize {
    Span::raw(text)
        .styled_graphemes(Style::default())
        .map(|grapheme| usize::from(grapheme.symbol.cell_width()))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;
    use ratatui::text::Line;
    use ratatui::widgets::{Paragraph, Widget};

    /// General categories Cf, Zl and Zp, as of Unicode 15.
    const FORMAT_AND_SEPARATORS: &[(u32, u32)] = &[
        (0x00AD, 0x00AD),
        (0x0600, 0x0605),
        (0x061C, 0x061C),
        (0x06DD, 0x06DD),
        (0x070F, 0x070F),
        (0x0890, 0x0891),
        (0x08E2, 0x08E2),
        (0x180E, 0x180E),
        (0x200B, 0x200F),
        (0x2028, 0x202E),
        (0x2060, 0x2064),
        (0x2066, 0x206F),
        (0xFEFF, 0xFEFF),
        (0xFFF9, 0xFFFB),
        (0x110BD, 0x110BD),
        (0x110CD, 0x110CD),
        (0x13430, 0x1343F),
        (0x1BCA0, 0x1BCA3),
        (0x1D173, 0x1D17A),
        (0xE0001, 0xE0001),
        (0xE0020, 0xE007F),
    ];

    /// The Simple and Ascii glyph sets' ellipsis; Fancy's is '…'.
    const DOTS: &str = "...";

    /// What one untrusted line becomes in each of the two shapes.
    fn both(raw: &str) -> [String; 2] {
        [
            one_line(raw, u16::MAX, "\u{2026}"),
            body_lines(raw, true).lines.join("\n"),
        ]
    }

    #[test]
    fn escape_sequences_go_whole() {
        for raw in [
            "A \u{1b}[2J x",
            "Bob\u{1b}]0;pwned\u{07}",
            "Bob\u{1b}]0;pwned\u{1b}\\",
            "\u{1b}[38;5;196mred\u{1b}[0m",
            "\u{1b}]8;;https://e.example\u{1b}\\link\u{1b}]8;;\u{1b}\\",
            "\u{1b}]52;c;cGF5bG9hZA==\u{07}copy",
            "lone\u{1b}",
        ] {
            for shown in both(raw) {
                assert!(!shown.contains('\u{1b}'), "{raw:?} -> {shown:?}");
                assert!(!shown.contains("[2J"), "{raw:?} -> {shown:?}");
                assert!(!shown.contains("]0;"), "{raw:?} -> {shown:?}");
                assert!(!shown.contains("]8;"), "{raw:?} -> {shown:?}");
                assert!(!shown.contains("]52;"), "{raw:?} -> {shown:?}");
            }
        }
        assert_eq!(one_line("A \u{1b}[2J x", 80, DOTS), "A  x");
        assert_eq!(one_line("Bob\u{1b}]0;pwned\u{07}", 80, DOTS), "Bob");
        assert_eq!(
            one_line(
                "\u{1b}]8;;https://e.example\u{1b}\\link\u{1b}]8;;\u{1b}\\",
                80,
                DOTS
            ),
            "link"
        );
        assert_eq!(one_line("\u{1b}[38;5;196mred\u{1b}[0m", 80, DOTS), "red");
    }

    #[test]
    fn controls_and_del_go() {
        let breaks = ['\n', '\r', '\u{0b}', '\u{0c}', '\u{85}'];
        for u in (0..0x20).chain(0x7f..0xa0) {
            let c = char::from_u32(u).unwrap();
            if c == '\t' || breaks.contains(&c) {
                continue;
            }
            let raw = format!("a{c}b");
            assert_eq!(both(&raw), ["ab", "ab"], "U+{u:04X}");
        }
        // An 8-bit CSI goes; what follows it is plain, harmless text.
        assert_eq!(one_line("A\u{9b}2Jx", 80, DOTS), "A2Jx");
    }

    #[test]
    fn bidi_zero_width_variation_and_tag_characters_go() {
        for (raw, want) in [
            ("evila\u{202E}ecila", "evilaecila"),
            ("x\u{2066}y\u{2069}", "xy"),
            ("al\u{200B}ice", "alice"),
            ("a\u{E0100}b\u{E01EF}", "ab"),
            ("hi\u{E0041}\u{E0042}\u{E007F}", "hi"),
            ("\u{0600}123", "123"),
            ("a\u{180B}\u{180F}b", "ab"),
            ("a\u{13430}\u{1BCA0}b", "ab"),
            ("a\u{FDD0}\u{FFFE}\u{FFFF}\u{1FFFF}\u{10FFFE}b", "ab"),
            ("a\u{2065}\u{FFF0}\u{E0080}\u{E0FFF}b", "ab"),
        ] {
            assert_eq!(both(raw), [want, want], "{raw:?}");
        }
    }

    #[test]
    fn no_format_or_separator_character_survives_but_joiners_between_letters() {
        for &(first, last) in FORMAT_AND_SEPARATORS {
            for u in first..=last {
                let c = char::from_u32(u).unwrap();
                let raw = format!("a{c}b");
                for shown in both(&raw) {
                    if c == '\u{200C}' || c == ZWJ {
                        assert_eq!(shown, raw, "U+{u:04X}");
                    } else {
                        assert!(!shown.contains(c), "U+{u:04X} survived: {shown:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn a_zalgo_grapheme_becomes_one_replacement_character() {
        let zalgo = format!("ae{}b", "\u{0301}".repeat(40));
        assert_eq!(both(&zalgo), ["a\u{FFFD}b", "a\u{FFFD}b"]);
        // A long conjoining-jamo run is one grapheme too.
        let jamo = format!("{}\u{1161}", "\u{1100}".repeat(10));
        assert_eq!(one_line(&jamo, 80, DOTS), "\u{FFFD}");
        // Eight scalars are still fine.
        let eight = format!("e{}", "\u{0301}".repeat(7));
        assert_eq!(one_line(&eight, 80, DOTS), eight);
    }

    #[test]
    fn emoji_come_apart() {
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}";
        let apart = "\u{1F468}\u{1F469}\u{1F467}\u{1F466}";
        assert_eq!(both(family), [apart, apart]);
        // Skin tones go first, so the 11-scalar family is not lost to U+FFFD.
        let toned = "\u{1F468}\u{1F3FB}\u{200D}\u{1F469}\u{1F3FD}\u{200D}\
                     \u{1F467}\u{1F3FF}\u{200D}\u{1F466}\u{1F3FC}";
        assert_eq!(both(toned), [apart, apart]);
        for (raw, want) in [
            ("\u{2764}\u{FE0F}", "\u{2764}"),
            ("\u{2764}\u{FE0E}", "\u{2764}"),
            ("\u{1F44D}\u{1F3FD}", "\u{1F44D}"),
            ("\u{1F1E9}\u{1F1EA}", "[DE]"),
            ("\u{1F1E9}\u{1F1EA}\u{1F1EB}", "[DE][F]"),
            ("flag \u{1F1FA}!", "flag [U]!"),
            // Rainbow flag, heart on fire, head shaking (an arrow).
            ("\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}", "\u{1F3F3}\u{1F308}"),
            ("\u{2764}\u{FE0F}\u{200D}\u{1F525}", "\u{2764}\u{1F525}"),
            ("\u{1F642}\u{200D}\u{2194}\u{FE0F}", "\u{1F642}\u{2194}"),
            // A mark or a run of joiners in between joins nothing either.
            (
                "\u{1F468}\u{0301}\u{200D}\u{1F469}",
                "\u{1F468}\u{0301}\u{1F469}",
            ),
            ("\u{1F468}\u{200D}\u{200D}\u{1F469}", "\u{1F468}\u{1F469}"),
        ] {
            assert_eq!(both(raw), [want, want], "{raw:?}");
        }
        // Every emoji left is one grapheme of one scalar, two cells wide.
        for grapheme in Span::raw(apart).styled_graphemes(Style::default()) {
            assert_eq!(grapheme.symbol.chars().count(), 1);
            assert_eq!(grapheme.symbol.cell_width(), 2);
        }
    }

    #[test]
    fn arabic_and_indic_joiners_stay() {
        for text in [
            // Persian "mikhaham" with ZWNJ.
            "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}",
            // Arabic beh + ZWJ + beh, and a beh's joining form on its own.
            "\u{0628}\u{200D}\u{0628}",
            "\u{0628}\u{200D}",
            // Devanagari half form: KA VIRAMA ZWJ SSA, and ZWNJ after a virama.
            "\u{0915}\u{094D}\u{200D}\u{0937}",
            "\u{0915}\u{094D}\u{200C}\u{0937}",
        ] {
            assert_eq!(both(text), [text, text], "{text:?}");
        }
    }

    #[test]
    fn bodies_split_at_every_line_break_and_tabs_become_spaces() {
        let view = body_lines("a\r\nb\rc\nd\te\n", false);
        assert_eq!(view.lines, ["a", "b", "c", "d e", ""]);
        assert_eq!(view.more_chars, 0);
        // Other breaks stay on their line, shown as ⏎.
        assert_eq!(
            body_lines("a\u{2028}b\u{0b}c", false).lines,
            ["a\u{23CE}b\u{23CE}c"]
        );
        assert_eq!(one_line("a\r\nb\nc\td", 80, DOTS), "a\u{23CE}b\u{23CE}c d");
        assert_eq!(body_lines("", false).lines, [""]);
    }

    #[test]
    fn long_bodies_are_clipped_like_the_cli() {
        let max = bridge::TTY_BODY_MAX_CHARS;
        assert_eq!(max, 2000);
        let raw = "x".repeat(max + 500);
        let view = body_lines(&raw, false);
        assert_eq!(view.more_chars, 500);
        assert_eq!(
            view.lines,
            [format!(
                "{}\u{2026} (+500 more characters)",
                "x".repeat(max)
            )]
        );
        let all = body_lines(&raw, true);
        assert_eq!((all.lines, all.more_chars), (vec![raw.clone()], 0));
        // Exactly at the limit nothing is clipped.
        let full = "y".repeat(max);
        assert_eq!(body_lines(&full, false).lines, [full]);

        // Line breaks count, as in clip_body.
        let raw = format!("{}\n{}", "a".repeat(1500), "b".repeat(1000));
        let view = body_lines(&raw, false);
        assert_eq!(view.more_chars, 501);
        assert_eq!(view.lines.len(), 2);
        assert_eq!(
            view.lines[1],
            format!("{}\u{2026} (+501 more characters)", "b".repeat(499))
        );

        // Clipping counts what is drawn: an escape sequence costs nothing.
        let raw = format!("{}{}", "\u{1b}[31m".repeat(1000), "z".repeat(max));
        assert_eq!(body_lines(&raw, false).more_chars, 0);
    }

    #[test]
    fn bodies_stop_at_200_lines_even_shown_in_full() {
        let raw = vec!["x"; 300].join("\n");
        for show_all in [false, true] {
            let view = body_lines(&raw, show_all);
            assert_eq!(view.lines.len(), MAX_BODY_LINES);
            // 300 x and 299 breaks; 200 x and 199 breaks are shown.
            assert_eq!(view.more_chars, 200);
            assert_eq!(view.lines[0], "x");
            assert_eq!(
                view.lines[MAX_BODY_LINES - 1],
                "x\u{2026} (+200 more characters)"
            );
        }
        let at_cap = vec!["x"; MAX_BODY_LINES].join("\n");
        assert_eq!(body_lines(&at_cap, false).more_chars, 0);
        // 2000 line breaks: the line cap comes first.
        let breaks = "\n".repeat(bridge::TTY_BODY_MAX_CHARS);
        let view = body_lines(&breaks, false);
        assert_eq!(view.lines.len(), MAX_BODY_LINES);
        assert!(view.lines[MAX_BODY_LINES - 1].starts_with('\u{2026}'));
    }

    #[test]
    fn one_line_cuts_by_cells_with_the_glyph_sets_ellipsis() {
        let name = "Alexander the Great";
        assert_eq!(one_line(name, 19, "\u{2026}"), name);
        assert_eq!(one_line(name, 10, "\u{2026}"), "Alexander\u{2026}");
        assert_eq!(one_line(name, 10, DOTS), "Alexand...");
        // Wide characters: a cut never splits one, and never overruns.
        let wide = "\u{65E5}\u{672C}\u{8A9E}\u{306E}\u{540D}\u{524D}";
        assert_eq!(one_line(wide, 12, "\u{2026}"), wide);
        assert_eq!(
            one_line(wide, 7, "\u{2026}"),
            "\u{65E5}\u{672C}\u{8A9E}\u{2026}"
        );
        assert_eq!(
            one_line(wide, 8, "\u{2026}"),
            "\u{65E5}\u{672C}\u{8A9E}\u{2026}"
        );
        assert_eq!(one_line(wide, 8, DOTS), "\u{65E5}\u{672C}...");
        // Too narrow for the ellipsis: cut bare.
        assert_eq!(one_line(name, 2, DOTS), "Al");
        assert_eq!(one_line(name, 0, "\u{2026}"), "");
        // What is dropped costs no cell.
        assert_eq!(one_line("Bo\u{202E}b\u{1b}[2J", 3, "\u{2026}"), "Bob");
        // Cells are counted as the buffer draws them: Span::width counts a
        // lam-alef pair as one cell, the buffer draws it in two.
        let lam_alef = "\u{0644}\u{0627}";
        assert_eq!((Span::raw(lam_alef).width(), cells(lam_alef)), (1, 2));
        let cut = one_line(&lam_alef.repeat(2), 3, "\u{2026}");
        assert_eq!(cut, format!("{lam_alef}\u{2026}"));
        let area = Rect::new(0, 0, 3, 1);
        let mut buf = Buffer::empty(area);
        Paragraph::new(cut).render(area, &mut buf);
        assert_eq!(testkit::buffer_lines(&buf), [format!("{lam_alef}\u{2026}")]);

        let samples = [
            name,
            wide,
            "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467} family",
            "\u{1F1E9}\u{1F1EA} Berlin",
            "e\u{0301}\u{0301} accents",
            "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}",
        ];
        for raw in samples {
            for max in 0..=24u16 {
                for mark in ["\u{2026}", DOTS] {
                    let shown = one_line(raw, max, mark);
                    assert!(
                        cells(&shown) <= usize::from(max),
                        "{raw:?} at {max}: {shown:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn one_line_middle_keeps_both_ends() {
        let folder = "/home/sam/Library/Application Support/raven";
        assert_eq!(one_line_middle(folder, 80, DOTS), folder);
        assert_eq!(one_line_middle(folder, 20, DOTS), "/home/sam...rt/raven");
        assert_eq!(
            one_line_middle(folder, 21, "\u{2026}"),
            "/home/sam/\u{2026}port/raven"
        );
        // Wide characters are kept whole: a share too small for one is
        // left a cell short.
        let wide = "\u{65E5}\u{672C}\u{8A9E}\u{306E}\u{540D}\u{524D}";
        assert_eq!(
            one_line_middle(wide, 8, "\u{2026}"),
            "\u{65E5}\u{672C}\u{2026}\u{524D}"
        );
        // Shaped first, as every untrusted line is; too narrow for the mark,
        // cut bare.
        assert_eq!(one_line_middle("/a\u{1b}[2J/b\u{202E}", 80, DOTS), "/a/b");
        assert_eq!(one_line_middle(folder, 2, DOTS), "/n");
        assert_eq!(one_line_middle(folder, 0, DOTS), "");
        for max in 0..=48u16 {
            for raw in [folder, wide, "\u{0644}\u{0627}".repeat(9).as_str()] {
                let shown = one_line_middle(raw, max, DOTS);
                assert!(cells(&shown) <= usize::from(max), "{raw:?} at {max}");
            }
        }
        // `width` counts what one_line would draw.
        assert_eq!(width(folder), folder.len());
        assert_eq!(width(wide), 12);
        assert_eq!(width("Bo\u{202E}b\u{1b}[2J"), 3);
    }

    #[test]
    fn field_input_keeps_text_and_drops_controls() {
        assert_eq!(
            field_input("a\u{1b}[2Jb\u{7f}\u{9b}c\u{0}", false),
            "a[2Jbc"
        );
        assert_eq!(field_input("a\tb", false), "a b");
        assert_eq!(
            field_input("line one\nline two\r\n", false),
            "line oneline two"
        );
        assert_eq!(
            field_input("one\r\ntwo\rthree\nfour\t!", true),
            "one\ntwo\nthree\nfour !"
        );
        // Text that only looks odd is the user's: kept.
        let text = "caf\u{e9} \u{1F44D} \u{0645}\u{06CC}\u{200C}";
        assert_eq!(field_input(text, true), text);
    }

    #[test]
    fn security_codes_in_pasted_text_are_masked() {
        let code = "If4x-36FU-omFi";
        let groups = ["If4x", "36FU", "omFi"];
        let card = format!(
            "raven-card/1 address=rvn1qexample pub_hex=00aa fingerprint={code} lan=192.168.1.5:7420"
        );
        let masked = mask_card_fingerprint(&card);
        assert_eq!(
            masked,
            "raven-card/1 address=rvn1qexample pub_hex=00aa fingerprint=\u{2022}\u{2022}\u{2022} \
             lan=192.168.1.5:7420"
        );
        let whoami = format!("address      rvn1qexample\nfingerprint  {code}\npub_hex      00aa\n");
        let json = format!("{{\"address\": \"rvn1qexample\", \"fingerprint\": \"{code}\"}}");
        for raw in [
            card.clone(),
            card.to_uppercase(),
            whoami.clone(),
            json,
            // Wrapped by the terminal inside the code, or before it.
            card.replace("36FU-", "36\nFU-"),
            card.replace("36FU-", "36\r\nFU-"),
            card.replace("fingerprint=", "fingerprint=\n"),
            // Hidden characters inside the key hide nothing.
            card.replace("fingerprint", "finger\u{200B}print"),
            card.replace("fingerprint", "finger\u{1b}[0mprint"),
        ] {
            let masked = mask_card_fingerprint(&raw);
            for group in groups {
                assert!(
                    !masked.to_lowercase().contains(&group.to_lowercase()),
                    "{raw:?} -> {masked:?}"
                );
            }
            assert!(masked.contains(CODE_MASK), "{raw:?} -> {masked:?}");
            assert_eq!(
                masked.matches('\n').count(),
                raw.replace("\r\n", "\n").matches('\n').count(),
                "{raw:?} -> {masked:?}"
            );
        }
        // The line after a whoami code is left alone.
        assert_eq!(
            mask_card_fingerprint(&whoami),
            "address      rvn1qexample\nfingerprint  \u{2022}\u{2022}\u{2022}\npub_hex      00aa\n"
        );
        // Text with no key is only shaped.
        assert_eq!(
            mask_card_fingerprint("raven:rvn1q:00aa\nfingerprints are\u{202E} codes"),
            "raven:rvn1q:00aa\nfingerprints are codes"
        );
        assert_eq!(mask_card_fingerprint("fingerprint="), "fingerprint=");
    }

    #[test]
    fn a_paragraph_of_shaped_text_draws_no_escape_sequence() {
        let hostile = "A \u{1b}[2J x\nBob\u{1b}]0;pwned\u{07} says \u{202E}olleh\n\
                       \u{1b}]8;;https://e.example\u{1b}\\link\u{1b}]8;;\u{1b}\\ \u{1F1E9}\u{1F1EA}";
        let area = Rect::new(0, 0, 40, 4);
        let draw = |lines: Vec<Line<'static>>| {
            let mut buf = Buffer::empty(area);
            Paragraph::new(lines).render(area, &mut buf);
            testkit::buffer_lines(&buf)
        };

        // Unshaped, ratatui drops the ESC itself and draws the rest.
        let raw = draw(
            hostile
                .split('\n')
                .map(|l| Line::raw(l.to_owned()))
                .collect(),
        );
        assert!(raw.iter().any(|row| row.contains("[2J")), "{raw:#?}");

        let shaped = draw(
            body_lines(hostile, false)
                .lines
                .into_iter()
                .map(Line::raw)
                .collect(),
        );
        for row in &shaped {
            for bad in ["\u{1b}", "[2J", "]0;", "]8;", "\u{202E}"] {
                assert!(!row.contains(bad), "{bad:?} drawn: {shaped:#?}");
            }
        }
        assert_eq!(
            shaped,
            [
                format!("{:<40}", "A  x"),
                format!("{:<40}", "Bob says olleh"),
                format!("{:<40}", "link [DE]"),
                " ".repeat(40),
            ]
        );
    }
}
