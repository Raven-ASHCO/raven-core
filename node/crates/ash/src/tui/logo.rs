//! The Raven mark (UXF.10): the website's logo drawn with Braille dots, 26
//! columns by 14 rows, and the wordmark that stands in for it.
//!
//! The mark is `docs/design/raven-logo-braille.txt`, made by
//! `docs/roadmap/research/prototypes/logo/braille.py` (the logo resized to 72
//! pixels, a dot wherever its alpha is over 30); it is the Calm prototype's
//! mark too. It needs Braille, so the Fancy glyph set; anywhere else Raven
//! shows the wordmark `R A V E N` in its place.
//!
//! WZ-1 (wizard.rs) assembles the mark dot by dot: the one motion in the app
//! that no event of Raven's starts.

/// The mark, top row first: each row 26 Braille cells (U+2800 is a blank
/// one).
pub(super) const MARK: [&str; 14] = [
    "⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⣴⣶⣶⣦⣤⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⢀⣤⣾⠿⠛⠉⠁⠀⠀⠀⠀⠈⠉⠛⠿⣶⣄⡀⠀⠀⠀⠀",
    "⠀⠀⢀⣴⡿⠋⠀⠀⣀⣀⣀⣀⣀⣀⣀⣀⣀⠀⠀⠀⠙⢿⣦⠀⠀⠀",
    "⠀⠀⠾⠏⣀⣤⣶⣿⠟⠛⠛⠛⠿⣿⡟⠛⠛⠿⣷⣄⠀⠀⠹⣷⡀⠀",
    "⠠⣾⡿⠿⠛⠉⢸⣿⠀⠀⠀⠀⠀⠘⠿⠿⣶⣄⠈⢻⣷⠀⠀⠹⣷⡀",
    "⠀⠙⢻⣿⠇⠀⢸⣿⠀⠀⠀⠀⠀⢀⣀⣀⣈⣿⡇⠀⣿⡇⠀⠀⢿⣇",
    "⠀⢠⣿⠏⠀⠀⢸⣿⠀⠀⠀⣠⣾⣿⡿⠛⠻⣿⠇⢠⣿⠃⠀⠀⢸⣿",
    "⠀⣼⡟⠀⢠⣄⢸⣿⠀⠀⣼⡟⠁⣿⡇⠀⠀⢀⣤⣿⠋⠀⠀⠀⢸⡿",
    "⠀⣿⡇⣰⣿⡇⢸⣿⠀⣼⡟⠀⠀⢻⣿⡿⠿⣿⣏⠀⠀⠀⠀⢀⣿⠇",
    "⠀⢻⣷⣿⣿⡇⢸⣿⠀⣿⡇⢠⣄⠀⠙⢿⣦⣜⣿⣦⠀⠀⢀⣼⡟⠀",
    "⠀⠈⠛⠋⢿⣇⢸⣿⠀⣿⡇⣿⡿⢷⣦⣤⣈⣙⣿⣿⡷⣠⣾⠟⠀⠀",
    "⠀⠀⠀⠀⠈⢿⣾⣿⠀⢹⣷⣿⡇⠀⠈⠉⢻⣿⣉⣡⣾⣿⣇⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠙⢿⣦⣄⣻⣿⡇⣀⣤⣤⣴⡿⢿⣯⣁⣈⣻⣧⡀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠁⠉⠉⠉⠁⠀⠀⠉⠛⠛⠛⠛⠃⠀",
];

/// The mark's size in cells.
pub(super) const MARK_COLS: u16 = 26;
pub(super) const MARK_ROWS: u16 = 14;

/// The wordmark: where the mark can't be drawn, and beside it.
pub(super) const WORDMARK: &str = "R A V E N";

/// The wordmark's first `letters` letters, spaced as it is: `R A V`.
pub(super) fn wordmark(letters: usize) -> String {
    WORDMARK
        .split(' ')
        .take(letters)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::text::Span;

    #[test]
    fn the_mark_is_the_design_file() {
        let file = include_str!("../../../../../docs/design/raven-logo-braille.txt");
        let rows: Vec<&str> = file.lines().collect();
        assert_eq!(rows, MARK, "docs/design/raven-logo-braille.txt changed");
        for row in MARK {
            assert_eq!(Span::raw(row).width(), usize::from(MARK_COLS), "{row}");
            assert!(row.chars().all(|c| ('\u{2800}'..='\u{28ff}').contains(&c)));
        }
        assert_eq!(MARK.len(), usize::from(MARK_ROWS));
    }

    #[test]
    fn the_wordmark_spells_raven() {
        assert_eq!(wordmark(0), "");
        assert_eq!(wordmark(1), "R");
        assert_eq!(wordmark(3), "R A V");
        assert_eq!(wordmark(5), WORDMARK);
        assert_eq!(wordmark(9), WORDMARK);
    }
}
