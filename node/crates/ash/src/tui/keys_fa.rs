//! Shortcuts on a Persian keyboard layout (UXF.4).
//!
//! A key arrives as the character its layout makes: with a Persian layout
//! on, the Q key gives U+0636 (DAD), so no letter shortcut would work until
//! the layout is switched. [`shortcut`] reads such a key as the Latin letter
//! on the same key, by one table: the Persian standard layout (ISIRI 9147),
//! plus the Arabic 101 keys that differ. The number row types Persian or
//! Arabic-Indic digits there, read as 0-9 (AF-3's 1). The app's key
//! dispatch uses it only while no field takes text (`App::field_takes_text`),
//! so the composer and the name, paste, code and address fields keep the
//! character typed.
//!
//! Only unshifted keys are in the table: shifted keys give diacritics,
//! marks and other letters, so a shortcut that needs Shift (`?` among them)
//! still needs the Latin layout. On macOS's ISIRI 2901 layout a few shifted
//! keys type letters of the Arabic 101 entries (Shift+A reads as C): the
//! layout check is in the terminal app's design doc. This is input
//! tolerance only: nothing is ever shown in Persian.

use crossterm::event::{KeyCode, KeyEvent};

use super::bridge;
#[cfg(test)]
use super::testkit;

/// Each letter a Persian or Arabic 101 layout types on a letter key without
/// Shift, and the Latin letter on that key, in the order of the design.
const KEYS: [(char, char); 32] = [
    ('\u{0636}', 'q'), // DAD
    ('\u{0635}', 'w'), // SAD
    ('\u{062B}', 'e'), // THEH
    ('\u{0642}', 'r'), // QAF
    ('\u{0641}', 't'), // FEH
    ('\u{063A}', 'y'), // GHAIN
    ('\u{0639}', 'u'), // AIN
    ('\u{0647}', 'i'), // HEH
    ('\u{062E}', 'o'), // KHAH
    ('\u{062D}', 'p'), // HAH
    ('\u{0634}', 'a'), // SHEEN
    ('\u{0633}', 's'), // SEEN
    ('\u{06CC}', 'd'), // FARSI YEH
    ('\u{064A}', 'd'), // YEH (Arabic 101)
    ('\u{0628}', 'f'), // BEH
    ('\u{0644}', 'g'), // LAM
    ('\u{0627}', 'h'), // ALEF
    ('\u{062A}', 'j'), // TEH
    ('\u{0646}', 'k'), // NOON
    ('\u{0645}', 'l'), // MEEM
    ('\u{0638}', 'z'), // ZAH
    ('\u{0637}', 'x'), // TAH
    ('\u{0632}', 'c'), // ZAIN
    ('\u{0631}', 'v'), // REH
    ('\u{0630}', 'b'), // THAL
    ('\u{062F}', 'n'), // DAL
    ('\u{0649}', 'n'), // ALEF MAKSURA (Arabic 101)
    ('\u{067E}', 'm'), // PEH
    ('\u{0626}', 'z'), // YEH WITH HAMZA ABOVE (Arabic 101)
    ('\u{0621}', 'x'), // HAMZA (Arabic 101)
    ('\u{0624}', 'c'), // WAW WITH HAMZA ABOVE (Arabic 101)
    ('\u{0629}', 'm'), // TEH MARBUTA (Arabic 101)
];

/// What a Latin layout types on the key that types `c` with a Persian or
/// Arabic 101 layout on: the letter, in lower case, for a letter of the
/// table, and 0-9 for a Persian or Arabic-Indic digit (as a code reads
/// them); None for any other character.
pub(crate) fn latin(c: char) -> Option<char> {
    KEYS.iter()
        .find(|&&(letter, _)| letter == c)
        .map(|&(_, latin)| latin)
        .or_else(|| {
            let folded = bridge::fold_code_digits(c.encode_utf8(&mut [0; 4]));
            folded.chars().next().filter(|&digit| digit != c)
        })
}

/// `key` read as a shortcut: a letter of the table, or a Persian or
/// Arabic-Indic digit, is what a Latin layout types on that key
/// ([`latin`]), with the same modifiers; any other key stays as it is.
pub(super) fn shortcut(key: KeyEvent) -> KeyEvent {
    match key.code {
        KeyCode::Char(c) => latin(c).map_or(key, |latin| KeyEvent {
            code: KeyCode::Char(latin),
            ..key
        }),
        _ => key,
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};

    use super::*;

    /// The Persian standard layout's letter keys, row by row: the Latin
    /// letters, and what the layout types on those keys without Shift.
    const PERSIAN_ROWS: [(&str, &str); 3] = [
        (
            "qwertyuiop",
            "\u{0636}\u{0635}\u{062B}\u{0642}\u{0641}\u{063A}\u{0639}\u{0647}\u{062E}\u{062D}",
        ),
        (
            "asdfghjkl",
            "\u{0634}\u{0633}\u{06CC}\u{0628}\u{0644}\u{0627}\u{062A}\u{0646}\u{0645}",
        ),
        (
            "zxcvbnm",
            "\u{0638}\u{0637}\u{0632}\u{0631}\u{0630}\u{062F}\u{067E}",
        ),
    ];

    /// The Arabic 101 keys that type another letter than the Persian
    /// standard layout does there.
    const ARABIC_101: [(char, char); 6] = [
        ('d', '\u{064A}'),
        ('n', '\u{0649}'),
        ('z', '\u{0626}'),
        ('x', '\u{0621}'),
        ('c', '\u{0624}'),
        ('m', '\u{0629}'),
    ];

    #[test]
    fn each_letter_key_reads_as_its_latin_letter() {
        let mut keys = 0;
        for (latin_row, persian_row) in PERSIAN_ROWS {
            assert_eq!(latin_row.chars().count(), persian_row.chars().count());
            for (on_key, letter) in latin_row.chars().zip(persian_row.chars()) {
                assert_eq!(latin(letter), Some(on_key), "{letter:?}");
                keys += 1;
            }
        }
        assert_eq!(keys, 26);
        for (on_key, letter) in ARABIC_101 {
            assert_eq!(latin(letter), Some(on_key), "{letter:?}");
        }
        // The table is those 32 keys: no other entry, and none twice.
        assert_eq!(KEYS.len(), keys + ARABIC_101.len());
        for (at, (letter, _)) in KEYS.iter().enumerate() {
            assert!(
                KEYS[..at].iter().all(|(before, _)| before != letter),
                "{letter:?} twice"
            );
        }
    }

    #[test]
    fn testkit_types_on_the_same_layout() {
        // The app's tests type keys with it (UXF.3's codes, the shortcuts).
        for on_key in 'a'..='z' {
            let typed = testkit::on_persian_keyboard(&on_key.to_string());
            let mut letters = typed.chars();
            let (Some(letter), None) = (letters.next(), letters.next()) else {
                panic!("{on_key}: {typed:?}");
            };
            assert_eq!(latin(letter), Some(on_key), "{letter:?}");
        }
    }

    #[test]
    fn the_number_row_reads_as_0_to_9() {
        for d in 0..10 {
            let digit = char::from_digit(d, 10).expect("a digit");
            for zero in [testkit::PERSIAN_ZERO, testkit::ARABIC_INDIC_ZERO] {
                let typed = char::from_u32(zero + d).expect("a digit");
                assert_eq!(latin(typed), Some(digit), "{typed:?}");
            }
        }
    }

    #[test]
    fn other_characters_are_no_shortcut() {
        for c in [
            // Latin letters, digits and marks: shortcuts as they are.
            'q', 'Q', 'k', '1', '?', ' ',
            // What shifted Persian keys give: diacritics and marks.
            '\u{064B}', '\u{064E}', '\u{0651}', '\u{0652}', '\u{0654}', '\u{0670}', '\u{061F}',
            '\u{060C}', '\u{061B}', '\u{200C}',
            // Letters on other keys than letter keys, or on shifted ones.
            '\u{0698}', '\u{06A9}', '\u{06AF}', '\u{0686}', '\u{062C}', '\u{0622}', '\u{0623}',
            '\u{0625}', '\u{0643}', '\u{0648}',
        ] {
            assert_eq!(latin(c), None, "{c:?}");
        }
    }

    #[test]
    fn a_shortcut_keeps_its_modifiers_and_other_keys_stay() {
        let dad = KeyEvent::new_with_kind_and_state(
            KeyCode::Char('\u{0636}'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
            KeyEventState::KEYPAD,
        );
        let read = shortcut(dad);
        assert_eq!(read.code, KeyCode::Char('q'));
        assert_eq!(
            (read.modifiers, read.kind, read.state),
            (dad.modifiers, dad.kind, dad.state)
        );
        assert_eq!(
            shortcut(KeyEvent::new(KeyCode::Char('\u{06F1}'), KeyModifiers::NONE)).code,
            KeyCode::Char('1')
        );
        for code in [
            KeyCode::Char('q'),
            KeyCode::Char('1'),
            KeyCode::Enter,
            KeyCode::Esc,
            KeyCode::Tab,
            KeyCode::Backspace,
            KeyCode::Up,
        ] {
            let key = KeyEvent::new(code, KeyModifiers::NONE);
            assert_eq!(shortcut(key), key, "{code:?}");
        }
    }
}
