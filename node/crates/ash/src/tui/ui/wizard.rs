//! The first run, WZ-1 to WZ-6, and ERR-ID: one card of the app's own copy
//! each, centred under the header row. Their only untrusted text is the
//! profile's folder, the user's own name and a failure's technical text, and
//! each is drawn through display.rs.
//!
//! WZ-1's letters and WZ-5's security words appear one by one, and WZ-4
//! spins ([`moving`] tells anim.rs); under reduced motion all three stand
//! still.
//!
//! WZ-1 in the Calm design (the prototype's WZ-1; logo.rs, tokens:
//! `terminal.welcomeMs`): from 80 by 24, the Raven mark on the left (the
//! wordmark where the glyph set has no Braille) and the text on the right.
//! The mark's dots assemble in a fixed shuffled order, the newest in the
//! accent; the letters R A V E N come one by one on the card's border; then
//! 'Welcome to Raven', the tagline typing itself, the copy with the steps
//! that come next, and the keys: the one motion in the app no event of
//! Raven's starts. Under reduced motion (which a terminal that is not one
//! asks for too), and back from WZ-2, all of it at once. In a smaller
//! window the card has the letters on its top border, as before.

use std::time::{Duration, Instant};

use ratatui::layout::{Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Padding, Paragraph};
use ratatui::Frame;

use super::anim::{self, Moving};
use super::app::{App, Creating, Failure, WizardStep, NAME_CELLS};
#[cfg(test)]
use super::app::{IdentityStart, JobResult, LookEnv, Msg, NewIdentity, Screen, Session};
#[cfg(test)]
use super::render as render_frame;
use super::state_file::Receive;
#[cfg(test)]
use super::state_file::TuiState;
#[cfg(test)]
use super::testkit;
use super::theme::{self, Motion};
use super::{cells, display, logo, overlays, render_header, widgets, wrap, Look};

/// The card's largest size, in cells; smaller in a smaller terminal. A card
/// with its technical text shown may take every row there is.
const CARD_WIDTH: u16 = 64;
const CARD_HEIGHT: u16 = 18;

/// WZ-1's letters, on its top border: one more every 100 ms.
const LETTERS: [&str; 5] = ["R", "A", "V", "E", "N"];
const LETTER_FRAMES: u32 = LETTERS.len() as u32;
const LETTERS_TIME: Duration = Duration::from_millis(500);
/// WZ-5: one more security word every 120 ms.
const WORD_GAP: Duration = Duration::from_millis(120);

/// WZ-1 in two columns (Calm, from 80 by 24): the card's widest, and its
/// spacing: around the mark, between the columns, after the text; less in
/// a narrower card.
const WELCOME_WIDTH: u16 = 104;
const WELCOME_ROOMY_FROM: u16 = 100;
const WELCOME_SPACING: (u16, u16, u16) = (4, 7, 5);
const WELCOME_SPACING_NARROW: (u16, u16, u16) = (2, 3, 2);
/// The window the two columns need.
const WELCOME_MIN: (u16, u16) = (80, 24);
const TAGLINE: &str = "Messages straight to your friends. No server.";
/// What comes next, numbered (the prototype's WZ-1): the wizard's own steps.
const WELCOME_STEPS: [&str; 3] = [
    "Choose the name Raven shows only on this computer",
    "Allow Raven on your local network",
    "See your security words",
];
/// The newest dots of the mark, while it assembles, in the accent colour.
const FRESH_DOTS: usize = 70;

/// WZ-1. Its second paragraph is the first run's line on networks (UXF.9):
/// it took the place of the one that said only 'the same Wi-Fi or office
/// network'.
const WELCOME_TITLE: &str = "Welcome to Raven";
const WELCOME_BODY: [&str; 3] = [
    "Raven sends messages straight from this computer to your friends' computers. There is no \
     server, no account and no phone number.",
    "Raven doesn't need the internet. It reaches friends on the same network as you: a Wi-Fi, a \
     hotspot, or a cable.",
    "Everything Raven keeps is stored in this folder on this computer:",
];
const WELCOME_KEYS: [(&str, &str); 3] = [
    ("[Enter]", " Get started"),
    ("[C]", " Classic menu"),
    ("[Q]", " Quit"),
];

/// WZ-2.
const NAME_TITLE: &str = "What should Raven call you?";
const NAME_BODY: &str = "This name is only shown on this computer, to greet you. It is never \
                         sent to anyone. Your friends choose their own name for you.";
const NAME_PLACEHOLDER: &str = "Your name (optional)";
const NAME_LIMIT: &str = "That's the longest name Raven shows.";
const NAME_KEYS: [(&str, &str); 2] = [("[Enter]", " Continue"), ("[Esc]", " Back")];

/// WZ-4: the spinner's words take the glyph set's ellipsis.
const CREATING: &str = "Creating your Raven identity";
const CREATING_KEY: &str = "This makes a private key that never leaves this computer.";
const CREATING_MAC: &str = "If your Mac asks for your password, enter it and choose Always Allow.";
const CREATE_FAILED: &str = "Raven could not create your identity.";
const FAILED_KEYS: [(&str, &str); 3] =
    [("[R]", " Try again"), ("[D]", " Details"), ("[Q]", " Quit")];

/// WZ-5. The code's case-sensitivity note is VF's, on the old-code path.
const WORDS_TITLE: &str = "Your security words";
const OLD_CODE_LABEL: &str = "Old-style code (for friends with an older Raven):";
const WORDS_BODY: [&str; 3] = [
    "These 10 words belong to your Raven identity. When you add a friend, you each read your own \
     words to the other, in person or on a phone call, and type what you hear. If they match, \
     nobody swapped the key in between.",
    "They are not a password: anyone may know them. Raven never asks you for secret words.",
    "Raven never checks this for you, and never marks a friend as verified by itself.",
];
const WORDS_KEYS: [(&str, &str); 1] = [("[Enter]", " Next")];
/// WZ-5's card is taller than the others: the words and the old-style code
/// come before its copy.
const WORDS_CARD_HEIGHT: u16 = 21;

/// Security words go one to a line in fewer cells than this
/// (`protocol/RAVEN_SECURITY_WORDS_V1.md` section 5); otherwise two rows of
/// [`WORDS_PER_ROW`], when they fit.
const WORDS_NARROW: u16 = 40;
const WORDS_PER_ROW: usize = 5;
/// The cells between two columns of words, widest first: the first that
/// fits the width.
const WORD_COLUMN_GAPS: [usize; 3] = [3, 2, 1];

/// WZ-6.
const READY_NEXT: &str = "Next, add a friend: you send them your invite and paste theirs.";
const READY_LISTENING: &str =
    "Raven starts listening for your friend as soon as you open Add a friend.";
const READY_KEYS: [(&str, &str); 2] = [("[A]", " Add a friend now"), ("[Enter]", " Open Raven")];

/// ERR-ID.
const ERR_TITLE: &str = "Raven can't open this profile";
const ERR_FOLDER: &str = "Folder: ";
const ERR_KEYS: [(&str, &str); 3] = [
    ("[D]", " Details"),
    ("[C]", " Classic menu"),
    ("[Q]", " Quit"),
];

/// What moves on wizard step `step` (anim.rs asks): WZ-1's letters (and,
/// with the mark in a window of `size` in `look`, the mark's rows and the
/// tagline), WZ-4's spinner, WZ-5's security words (`words`, the user's
/// own).
pub(crate) fn moving(
    step: &WizardStep,
    words: Option<&[String]>,
    look: &Look,
    size: (u16, u16),
) -> Vec<Moving> {
    match step {
        WizardStep::Welcome { since: Some(since) } => {
            if welcome_columns(Rect::new(0, 0, size.0, size.1)) {
                mark_reveal(*since, look.glyphs == theme::Glyphs::fancy())
            } else {
                vec![Moving::Transition {
                    start: *since,
                    frames: LETTER_FRAMES,
                    length: LETTERS_TIME,
                }]
            }
        }
        WizardStep::Creating(Creating::Working { since }) => {
            vec![Moving::Spinner { since: *since }]
        }
        WizardStep::Words { since } => {
            let gaps = words.map_or(0, word_gaps);
            if gaps == 0 {
                return Vec::new();
            }
            vec![Moving::Transition {
                start: *since,
                frames: gaps,
                length: WORD_GAP * gaps,
            }]
        }
        _ => Vec::new(),
    }
}

/// WZ-1's reveal from `since` (tokens: `terminal.welcomeMs`): the mark's
/// dots, the letters, the title, the tagline's characters, the copy, the
/// keys. Each wakes anim.rs for its frames; the frame budget keeps them 80
/// ms apart. The dots only where the glyph set has Braille (`braille`).
fn mark_reveal(since: Instant, braille: bool) -> Vec<Moving> {
    let w = theme::WELCOME_MS;
    let ms = Duration::from_millis;
    let chars = tagline_chars();
    // A change at `at` alone: one frame then.
    let once = |at: u64| Moving::Transition {
        start: since + ms(at.saturating_sub(1)),
        frames: 1,
        length: ms(1),
    };
    let mut reveal = vec![
        Moving::Transition {
            start: since + ms(w.letters_from),
            frames: LETTER_FRAMES,
            length: ms(w.letter_every * u64::from(LETTER_FRAMES)),
        },
        once(w.title_at),
        Moving::Transition {
            start: since + ms(w.tagline_from),
            frames: chars,
            length: ms(w.tagline_char_every * u64::from(chars)),
        },
        once(w.body_at),
        once(w.keys_at),
    ];
    if braille {
        reveal.push(Moving::Transition {
            start: since,
            frames: MARK_FRAMES,
            length: ms(w.mark_assemble),
        });
    }
    reveal
}

/// The mark's assembly, in frames: one each 80 ms (the frame budget).
const MARK_FRAMES: u32 = 19;

/// The tagline's length in characters.
fn tagline_chars() -> u32 {
    u32::try_from(TAGLINE.chars().count()).unwrap_or(0)
}

/// Whether WZ-1 has its two columns in a window of `area`: from 80 by 24.
fn welcome_columns(area: Rect) -> bool {
    area.width >= WELCOME_MIN.0 && area.height >= WELCOME_MIN.1
}

/// Every dot of the mark (row, column, bit of its Braille cell), in the
/// order they appear: a shuffle that is the same on every computer.
fn mark_dots() -> Vec<(usize, usize, u8)> {
    let mut dots = Vec::new();
    for (r, row) in logo::MARK.iter().enumerate() {
        for (c, ch) in row.chars().enumerate() {
            let bits = u32::from(ch).saturating_sub(0x2800);
            for b in 0..8u8 {
                if bits & (1 << b) != 0 {
                    dots.push((r, c, b));
                }
            }
        }
    }
    // Fisher-Yates with a fixed xorshift: deterministic, no float maths.
    let mut state: u32 = 0x9E37_79B9;
    for i in (1..dots.len()).rev() {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        let j = usize::try_from(state).unwrap_or(0) % (i + 1);
        dots.swap(i, j);
    }
    dots
}

/// The mark with its first `shown` dots (of [`mark_dots`]), as rows of
/// spans: the newest [`FRESH_DOTS`] in the accent while it assembles.
fn assembling_mark(look: &Look, shown: usize) -> Vec<Line<'static>> {
    let dots = mark_dots();
    let shown = shown.min(dots.len());
    let assembling = shown < dots.len();
    let cols = usize::from(logo::MARK_COLS);
    let mut cells = vec![vec![0u32; cols]; usize::from(logo::MARK_ROWS)];
    let mut fresh = vec![vec![false; cols]; usize::from(logo::MARK_ROWS)];
    for (i, &(r, c, b)) in dots[..shown].iter().enumerate() {
        if let Some(cell) = cells.get_mut(r).and_then(|row| row.get_mut(c)) {
            *cell |= 1 << b;
        }
        if assembling && i + FRESH_DOTS >= shown {
            if let Some(cell) = fresh.get_mut(r).and_then(|row| row.get_mut(c)) {
                *cell = true;
            }
        }
    }
    cells
        .iter()
        .zip(&fresh)
        .map(|(row, fresh)| {
            Line::from(
                row.iter()
                    .zip(fresh)
                    .map(|(bits, fresh)| {
                        let ch = char::from_u32(0x2800 + bits).unwrap_or(' ');
                        let style = if *fresh {
                            look.theme.accent
                        } else {
                            look.theme.text
                        };
                        Span::styled(ch.to_string(), style)
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

/// A security code in groups of 4, its separators taken out (`If4x-36FU-omFi`
/// is If4x, 36FU, omFi): WZ-5's old-style code and VF's.
pub(crate) fn code_groups(fingerprint: &str) -> Vec<String> {
    let chars: Vec<char> = fingerprint
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    chars
        .chunks(4)
        .map(|group| group.iter().collect())
        .collect()
}

/// The pauses between WZ-5's words: one fewer than there are words.
fn word_gaps(words: &[String]) -> u32 {
    u32::try_from(words.len().saturating_sub(1)).unwrap_or(0)
}

/// Security words numbered from 1, in rows for `width` cells: two rows of
/// [`WORDS_PER_ROW`], each column as wide as its widest number and word and
/// [`WORD_COLUMN_GAPS`] apart; one word to a line under [`WORDS_NARROW`]
/// cells, or when two rows don't fit. A word is never split or cut. The
/// first `shown` are drawn, the others leave their place blank, so nothing
/// moves as they appear. WZ-5's; VF's word lists are to use it too.
pub(crate) fn word_rows(
    look: &Look,
    words: &[String],
    width: u16,
    shown: usize,
) -> Vec<Line<'static>> {
    let numbered: Vec<(String, &str)> = words
        .iter()
        .enumerate()
        .map(|(i, word)| ((i + 1).to_string(), word.as_str()))
        .collect();
    let (per_row, gap) = match grid_gap(&numbered, width) {
        Some(gap) => (WORDS_PER_ROW, gap),
        None => (1, 0),
    };
    let columns: Vec<(usize, usize)> = (0..per_row)
        .map(|column| column_cells(&numbered, column, per_row))
        .collect();
    let bold = Style::default().add_modifier(Modifier::BOLD);
    numbered
        .chunks(per_row)
        .enumerate()
        .map(|(row, row_words)| {
            // The grid stands in from the copy by a cell less than its gaps.
            let mut spans = vec![Span::raw(" ".repeat(gap.saturating_sub(1)))];
            for (column, (number, word)) in row_words.iter().enumerate() {
                let (number_cells, word_cells) = columns[column];
                if column > 0 {
                    spans.push(Span::raw(" ".repeat(gap)));
                }
                // The last column needs no padding after its word.
                let pad = if column + 1 < row_words.len() {
                    word_cells - cells(word)
                } else {
                    0
                };
                if row * per_row + column < shown {
                    spans.extend([
                        Span::styled(format!("{number:>number_cells$}"), look.theme.secondary),
                        Span::raw(" "),
                        Span::styled((*word).to_owned(), bold),
                        Span::raw(" ".repeat(pad)),
                    ]);
                } else {
                    spans.push(Span::raw(" ".repeat(number_cells + 1 + cells(word) + pad)));
                }
            }
            Line::from(spans)
        })
        .collect()
}

/// The gap that lets two rows of numbered words fit in `width` cells, the
/// widest that does; None under [`WORDS_NARROW`] cells, or when none does.
fn grid_gap(numbered: &[(String, &str)], width: u16) -> Option<usize> {
    if width < WORDS_NARROW {
        return None;
    }
    let columns: usize = (0..WORDS_PER_ROW)
        .map(|column| {
            let (number_cells, word_cells) = column_cells(numbered, column, WORDS_PER_ROW);
            number_cells + 1 + word_cells
        })
        .sum();
    let gaps = WORDS_PER_ROW - 1;
    WORD_COLUMN_GAPS
        .into_iter()
        .find(|gap| (gap - 1) + columns + gap * gaps <= usize::from(width))
}

/// The widest number and the widest word in column `column` of rows of
/// `per_row` words.
fn column_cells(numbered: &[(String, &str)], column: usize, per_row: usize) -> (usize, usize) {
    numbered.iter().skip(column).step_by(per_row).fold(
        (0, 0),
        |(number_cells, word_cells), (number, word)| {
            (number_cells.max(cells(number)), word_cells.max(cells(word)))
        },
    )
}

/// Draws wizard step `step`: the header row (with the help key on WZ-1, the
/// one step that has it), then the step's card. On WZ-2 the terminal's own
/// cursor sits in the name field, unless an overlay is on top.
pub(super) fn render(f: &mut Frame, area: Rect, app: &App, step: &WizardStep, now: Instant) {
    if area.is_empty() {
        return;
    }
    render_header(
        f,
        area,
        app,
        now,
        matches!(step, WizardStep::Welcome { .. }),
    );
    let body = under_header(area);
    let look = app.look();
    let width = text_width(body);
    let (title, lines, height) = match step {
        WizardStep::Welcome { since } if welcome_columns(area) => {
            return render_welcome_calm(f, body, app, *since, now);
        }
        WizardStep::Name => return render_name(f, body, app, width),
        WizardStep::Welcome { since } => {
            (letters(look, *since, now), welcome(app, width), CARD_HEIGHT)
        }
        WizardStep::Receive { yes } => (
            None,
            overlays::receive_lines(look, width, *yes, app.receive_port()),
            CARD_HEIGHT,
        ),
        WizardStep::Creating(Creating::Working { since }) => {
            (None, creating(app, width, *since, now), CARD_HEIGHT)
        }
        WizardStep::Creating(Creating::Failed(failure)) => (
            None,
            create_failed(look, width, failure),
            card_height(failure, body),
        ),
        WizardStep::Words { since } => {
            let room = usize::from(WORDS_CARD_HEIGHT.min(body.height).saturating_sub(2));
            (
                None,
                security_words(app, width, room, *since, now),
                WORDS_CARD_HEIGHT,
            )
        }
        WizardStep::Ready => (None, ready(app, width), CARD_HEIGHT),
    };
    draw_card(f, body, look, title, lines, height);
}

/// WZ-2's card in `body`, with the terminal's cursor after the name.
fn render_name(f: &mut Frame, body: Rect, app: &App, width: u16) {
    let (lines, field) = name(app, width);
    let (inner, drawn) = draw_card(f, body, app.look(), None, lines, CARD_HEIGHT);
    let Some(row) = drawn.iter().position(|line| *line == field) else {
        return;
    };
    let y = u16::try_from(row).unwrap_or(u16::MAX);
    if y < inner.height && app.overlays().is_empty() {
        // After the field's left border and its space, and what is typed.
        let typed = u16::try_from(display::width(app.name())).unwrap_or(u16::MAX);
        let x = inner.x.saturating_add(2).saturating_add(typed);
        f.set_cursor_position(Position::new(x, inner.y + y));
    }
}

/// ERR-ID: what is wrong with the profile, what the user can do, and its
/// folder; [D] shows the technical text. Never an offer to make a new
/// identity.
pub(super) fn render_identity_error(
    f: &mut Frame,
    area: Rect,
    app: &App,
    failure: &Failure,
    now: Instant,
) {
    if area.is_empty() {
        return;
    }
    render_header(f, area, app, now, false);
    let body = under_header(area);
    let look = app.look();
    let width = text_width(body);
    let mut lines = vec![Line::styled(ERR_TITLE, look.theme.title), Line::default()];
    lines.extend(rows(&failure.plain.headline, width));
    if !failure.plain.next.is_empty() {
        lines.push(Line::default());
        lines.extend(rows(&failure.plain.next, width));
    }
    lines.push(Line::default());
    lines.push(folder_line(app, width, ERR_FOLDER));
    if failure.details {
        lines.extend(details(look, &failure.plain.technical, width));
    }
    lines.push(Line::default());
    lines.push(overlays::keys_line(look, &ERR_KEYS));
    draw_card(f, body, look, None, lines, card_height(failure, body));
}

/// WZ-1's top border: 'R A V E N', a letter more every 100 ms from `since`;
/// all of them at once without it, or under reduced motion.
fn letters(look: &Look, since: Option<Instant>, now: Instant) -> Option<Span<'static>> {
    let shown = since.map_or(LETTER_FRAMES, |since| {
        anim::transition_frame(since, now, LETTER_FRAMES, LETTERS_TIME, look.motion)
    });
    let shown = usize::try_from(shown)
        .unwrap_or(LETTERS.len())
        .min(LETTERS.len());
    (shown > 0).then(|| {
        Span::styled(
            format!(" {} ", LETTERS[..shown].join(" ")),
            look.theme.accent,
        )
    })
}

/// WZ-1 in two columns (Calm, the prototype's WZ-1) in `body`: the card
/// with R A V E N on its border; the mark on the left (the wordmark where
/// the glyph set has no Braille); on the right 'Welcome to Raven', the
/// tagline, WZ-1's copy and, where they fit, the steps that come next; the
/// keys under the text. At `now` from `since` (tokens: `welcomeMs`): the
/// mark's dots assemble, the letters come one by one, then the title, the
/// tagline typing itself, the copy and the keys. Without `since` (back
/// from WZ-2) and under reduced motion all of it at once.
fn render_welcome_calm(f: &mut Frame, body: Rect, app: &App, since: Option<Instant>, now: Instant) {
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    let w = theme::WELCOME_MS;
    // How far in, in ms: the end without a start, or under reduced motion.
    let at = match since {
        Some(since) if look.motion == Motion::Full => {
            u64::try_from(now.saturating_duration_since(since).as_millis()).unwrap_or(u64::MAX)
        }
        _ => u64::MAX,
    };
    let width = WELCOME_WIDTH.min(body.width);
    let (pad, gap, after) = if width >= WELCOME_ROOMY_FROM {
        WELCOME_SPACING
    } else {
        WELCOME_SPACING_NARROW
    };
    let text_width = width.saturating_sub(2 + pad + logo::MARK_COLS + gap + after);
    // The text column at rest: its rows decide the card's height, so
    // nothing moves as they appear.
    let mut copy: Vec<Line<'static>> = Vec::new();
    for (i, paragraph) in WELCOME_BODY.iter().enumerate() {
        if i > 0 {
            copy.push(Line::default());
        }
        copy.extend(rows(paragraph, text_width));
    }
    copy.push(folder_line(app, text_width, ""));
    let steps: Vec<Line<'static>> = WELCOME_STEPS
        .iter()
        .enumerate()
        .map(|(i, step)| {
            Line::from(vec![
                Span::styled(format!(" {} ", i + 1), t.key),
                Span::styled(format!("  {step}"), t.text),
            ])
        })
        .collect();
    let head = 3; // the title, the tagline, a blank row
    let rest = |text: usize| u16::try_from(head + text).unwrap_or(u16::MAX);
    // The border, a row above, a blank row and the keys and a row below.
    let card = |content: u16| content.max(logo::MARK_ROWS) + 6;
    let steps_fit = steps
        .iter()
        .all(|line| line.width() <= usize::from(text_width))
        && card(rest(copy.len() + 1 + 2 * steps.len() - 1)) <= body.height;
    if steps_fit {
        copy.push(Line::default());
        for (i, step) in steps.into_iter().enumerate() {
            if i > 0 {
                copy.push(Line::default());
            }
            copy.push(step);
        }
    }
    let height = card(rest(copy.len())).min(body.height);
    let rect = overlays::centered(body, width, height);
    // The letters on the border, one every 100 ms.
    let letters = at
        .checked_sub(w.letters_from)
        .map_or(0, |into| into / w.letter_every)
        .min(u64::from(LETTER_FRAMES));
    let mut block = widgets::pane(look, false);
    if letters > 0 {
        let shown = usize::try_from(letters).unwrap_or(LETTERS.len());
        block = block.title(Span::styled(
            format!(" {} ", logo::wordmark(shown)),
            t.title,
        ));
    }
    let inner = block.inner(rect);
    widgets::clear(f, rect, look);
    f.render_widget(block, rect);
    // The mark's column: its dots assemble over 1.5 s; the wordmark in a
    // glyph set without Braille.
    let mark_rect = Rect {
        x: inner.x + pad,
        y: inner.y + 1,
        width: logo::MARK_COLS,
        height: logo::MARK_ROWS,
    }
    .intersection(inner);
    if *g == theme::Glyphs::fancy() {
        let dots = mark_dots().len();
        let shown = if at >= w.mark_assemble {
            dots
        } else {
            usize::try_from(u128::from(at) * dots as u128 / u128::from(w.mark_assemble))
                .unwrap_or(dots)
        };
        f.render_widget(Paragraph::new(assembling_mark(look, shown)), mark_rect);
    } else {
        let middle = Rect {
            y: mark_rect.y + logo::MARK_ROWS / 2,
            height: 1,
            ..mark_rect
        }
        .intersection(inner);
        f.render_widget(
            Paragraph::new(Span::styled(logo::WORDMARK, t.title)).centered(),
            middle,
        );
    }
    // The text's column: the title, the tagline as it types, the copy.
    let chars = u64::from(tagline_chars());
    let typed = at
        .checked_sub(w.tagline_from)
        .map_or(0, |into| into / w.tagline_char_every)
        .min(chars);
    let mut text = vec![
        if at >= w.title_at {
            Line::styled(WELCOME_TITLE, t.title)
        } else {
            Line::default()
        },
        {
            let mut tagline = vec![Span::styled(
                TAGLINE
                    .chars()
                    .take(usize::try_from(typed).unwrap_or(usize::MAX))
                    .collect::<String>(),
                t.accent,
            )];
            if typed > 0 && typed < chars {
                tagline.push(Span::styled(" ", t.text.add_modifier(Modifier::REVERSED)));
            }
            Line::from(tagline)
        },
        Line::default(),
    ];
    if at >= w.body_at {
        text.extend(copy);
    }
    let text_x = inner.x + pad + logo::MARK_COLS + gap;
    let text_rect = Rect {
        x: text_x,
        y: inner.y + 1,
        width: text_width,
        height: inner.height.saturating_sub(4),
    }
    .intersection(inner);
    f.render_widget(Paragraph::new(text), text_rect);
    if at >= w.keys_at && inner.height > 2 {
        // Under the text where they fit, else under both columns.
        let line = overlays::keys_line(look, &WELCOME_KEYS);
        let x = if usize::from(inner.right().saturating_sub(text_x)) >= line.width() {
            text_x
        } else {
            inner.x + pad
        };
        let keys = Rect {
            x,
            y: inner.bottom() - 2,
            width: inner.right().saturating_sub(x),
            height: 1,
        };
        f.render_widget(Paragraph::new(line), keys);
    }
}

/// WZ-1: what Raven is, that this version needs one network, and where it
/// keeps everything.
fn welcome(app: &App, width: u16) -> Vec<Line<'static>> {
    let look = app.look();
    let mut lines = vec![
        Line::styled(WELCOME_TITLE, look.theme.title),
        Line::default(),
    ];
    for (i, paragraph) in WELCOME_BODY.iter().enumerate() {
        if i > 0 {
            lines.push(Line::default());
        }
        lines.extend(rows(paragraph, width));
    }
    // Right under the sentence that names it.
    lines.push(folder_line(app, width, ""));
    lines.push(Line::default());
    lines.push(overlays::keys_line(look, &WELCOME_KEYS));
    lines
}

/// WZ-2's rows, and the field's middle row (where the cursor goes).
fn name(app: &App, width: u16) -> (Vec<Line<'static>>, Line<'static>) {
    let look = app.look();
    let mut lines = vec![Line::styled(NAME_TITLE, look.theme.title), Line::default()];
    lines.extend(rows(NAME_BODY, width));
    lines.push(Line::default());
    let [top, field, bottom] = name_field(look, app.name(), NAME_PLACEHOLDER);
    lines.extend([top, field.clone(), bottom]);
    if app.name_full() {
        lines.push(Line::styled(NAME_LIMIT, look.theme.secondary));
    }
    lines.push(Line::default());
    lines.push(overlays::keys_line(look, &NAME_KEYS));
    (lines, field)
}

/// A name field (WZ-2's, AF-2's): the name, or `placeholder` dimmed, in a
/// box: a space, then room for the longest name and one cell more, so the
/// cursor always has a cell after it.
pub(super) fn name_field(look: &Look, name: &str, placeholder: &str) -> [Line<'static>; 3] {
    let border = &look.glyphs.border;
    let inside = 1 + NAME_CELLS + 1;
    let (text, style) = if name.is_empty() {
        (placeholder.to_owned(), look.theme.secondary)
    } else {
        let room = u16::try_from(NAME_CELLS).unwrap_or(u16::MAX);
        (display::one_line(name, room, ""), Style::default())
    };
    let pad = " ".repeat(inside.saturating_sub(1 + display::width(&text)));
    [
        Line::raw(format!(
            "{}{}{}",
            border.top_left,
            border.horizontal_top.repeat(inside),
            border.top_right
        )),
        Line::from(vec![
            Span::raw(border.vertical_left),
            Span::raw(" "),
            Span::styled(text, style),
            Span::raw(pad),
            Span::raw(border.vertical_right),
        ]),
        Line::raw(format!(
            "{}{}{}",
            border.bottom_left,
            border.horizontal_bottom.repeat(inside),
            border.bottom_right
        )),
    ]
}

/// WZ-4 while the identity is made: the spinner, then what is happening.
fn creating(app: &App, width: u16, since: Instant, now: Instant) -> Vec<Line<'static>> {
    let look = app.look();
    let mut lines = vec![
        Line::from(vec![
            widgets::spinner(look, since, now),
            Span::raw(" "),
            Span::styled(
                format!("{CREATING}{}", look.glyphs.ellipsis),
                look.theme.accent,
            ),
        ]),
        Line::default(),
    ];
    lines.extend(rows(CREATING_KEY, width));
    if app.on_mac() {
        lines.push(Line::default());
        lines.extend(rows(CREATING_MAC, width));
    }
    lines
}

/// WZ-4 after a failure: that it failed, why in plain words, and the keys;
/// [D] shows the technical text.
fn create_failed(look: &Look, width: u16, failure: &Failure) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::styled(CREATE_FAILED, look.theme.title),
        Line::default(),
    ];
    lines.extend(rows(&failure.plain.headline, width));
    if failure.details {
        lines.extend(details(look, &failure.plain.technical, width));
    }
    lines.push(Line::default());
    lines.push(overlays::keys_line(look, &FAILED_KEYS));
    lines
}

/// WZ-5: the user's own security words, numbered, one more every 120 ms
/// (all at once under reduced motion), the old-style code under them, then
/// how a friend checks them. All public: it is what friends compare. The
/// copy goes a whole paragraph at a time, from the last, when the card's
/// `room` rows can't hold it with the words, the code and the keys.
fn security_words(
    app: &App,
    width: u16,
    room: usize,
    since: Instant,
    now: Instant,
) -> Vec<Line<'static>> {
    let look = app.look();
    let (words, fingerprint) = app.me().map_or((&[][..], ""), |me| {
        (me.words.as_slice(), me.fingerprint.as_str())
    });
    let gaps = word_gaps(words);
    let pauses = anim::transition_frame(since, now, gaps, WORD_GAP * gaps, look.motion);
    let shown = usize::try_from(pauses)
        .map_or(words.len(), |pauses| pauses + 1)
        .min(words.len());
    let mut lines = vec![Line::styled(WORDS_TITLE, look.theme.title), Line::default()];
    lines.extend(word_rows(look, words, width, shown));
    lines.extend(old_code(fingerprint, width));
    // Blank rows go first when the card is short (`overlays::fit`): count
    // the others, the keys' row with them.
    let mut filled = lines.iter().filter(|line| line.width() > 0).count() + 1;
    for paragraph in WORDS_BODY {
        let paragraph: Vec<Line<'static>> = rows(paragraph, width).collect();
        filled += paragraph.len();
        if filled > room {
            break;
        }
        lines.push(Line::default());
        lines.extend(paragraph);
    }
    lines.push(Line::default());
    lines.push(overlays::keys_line(look, &WORDS_KEYS));
    lines
}

/// The old-style code under the words, in groups (`If4x 36FU omFi`): after
/// its label when the row has room, else on a row of its own. Never split.
fn old_code(fingerprint: &str, width: u16) -> Vec<Line<'static>> {
    let code = code_groups(fingerprint).join(" ");
    if cells(OLD_CODE_LABEL) + 1 + cells(&code) <= usize::from(width) {
        return vec![Line::raw(format!("{OLD_CODE_LABEL} {code}"))];
    }
    let mut lines: Vec<Line<'static>> = rows(OLD_CODE_LABEL, width).collect();
    lines.push(Line::raw(code));
    lines
}

/// WZ-6: ready, by the user's own name, and the first thing to do.
fn ready(app: &App, width: u16) -> Vec<Line<'static>> {
    let look = app.look();
    let name = app.settings().display_name.trim();
    let heading = if name.is_empty() {
        "You're ready.".to_owned()
    } else {
        let around = u16::try_from(cells("You're ready, .")).unwrap_or(u16::MAX);
        let name = display::one_line(name, width.saturating_sub(around), look.glyphs.ellipsis);
        format!("You're ready, {name}.")
    };
    let mut lines = vec![Line::styled(heading, look.theme.title), Line::default()];
    lines.extend(rows(READY_NEXT, width));
    if app.settings().receive != Receive::Off {
        lines.push(Line::default());
        lines.extend(rows(READY_LISTENING, width));
    }
    lines.push(Line::default());
    lines.push(overlays::keys_line(look, &READY_KEYS));
    lines
}

/// The profile's folder after `label`, dimmed, its middle taken out when it
/// is too long for the row.
fn folder_line(app: &App, width: u16, label: &'static str) -> Line<'static> {
    let look = app.look();
    let room = width.saturating_sub(u16::try_from(cells(label)).unwrap_or(u16::MAX));
    let folder = app.folder().to_string_lossy();
    Line::from(vec![
        Span::raw(label),
        Span::styled(
            display::one_line_middle(&folder, room, look.glyphs.ellipsis),
            look.theme.secondary,
        ),
    ])
}

/// The technical text under [D], after a blank row: dimmed, each line
/// through display.rs, broken to the card's width so none of it is cut off.
pub(super) fn details(look: &Look, technical: &str, width: u16) -> Vec<Line<'static>> {
    let mut lines = vec![Line::default()];
    for line in display::body_lines(technical, false).lines {
        lines.extend(
            overlays::wrap_command(&line, width)
                .into_iter()
                .map(|row| Line::styled(row, look.theme.secondary)),
        );
    }
    lines
}

/// The app's own copy in rows of `width` cells.
pub(super) fn rows(text: &str, width: u16) -> impl Iterator<Item = Line<'static>> {
    wrap(text, width, 0).into_iter().map(Line::raw)
}

/// The rows under the header row.
pub(super) fn under_header(area: Rect) -> Rect {
    Rect {
        y: area.y.saturating_add(1),
        height: area.height.saturating_sub(1),
        ..area
    }
}

/// Cells for text inside a card in `area`.
pub(super) fn text_width(area: Rect) -> u16 {
    overlays::inner_width(CARD_WIDTH.min(area.width))
}

/// How tall a failure's card may grow: every row of `area` while its
/// technical text shows, else the usual card.
fn card_height(failure: &Failure, area: Rect) -> u16 {
    if failure.details {
        area.height
    } else {
        CARD_HEIGHT
    }
}

/// Draws `lines` in a card centred in `area`, at most `max_height` rows tall,
/// with `title` on its top border. Returns the card's inside and the lines
/// as drawn: when they don't fit, blank rows go first and the keys stay.
pub(super) fn draw_card(
    f: &mut Frame,
    area: Rect,
    look: &Look,
    title: Option<Span<'static>>,
    lines: Vec<Line<'static>>,
    max_height: u16,
) -> (Rect, Vec<Line<'static>>) {
    let height = overlays::height_of(&lines).min(max_height);
    let rect = overlays::centered(area, CARD_WIDTH, height);
    let lines = overlays::fit(lines, rect.height);
    let mut block = widgets::screen_box(look).padding(Padding::horizontal(1));
    if let Some(title) = title {
        block = block.title(title);
    }
    let inner = block.inner(rect);
    widgets::clear(f, rect, look);
    f.render_widget(Paragraph::new(lines.clone()).block(block), rect);
    (inner, lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyCode;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use theme::{Glyphs, Motion, TermEnv};

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// The wizard at 80x24, `keys` pressed in turn.
    fn after(keys: &[KeyCode]) -> App {
        let mut app = testkit::wizard_app((80, 24));
        for &key in keys {
            testkit::press(&mut app, key);
        }
        app
    }

    /// The same, in `look`.
    fn after_in(look: Look, keys: &[KeyCode]) -> App {
        let mut app = App::new(look, (80, 24), Instant::now(), 0);
        app.set_mac_for_tests(false);
        app.start(Session {
            identity: IdentityStart::Missing,
            ..testkit::session(Receive::Unset)
        });
        for &key in keys {
            testkit::press(&mut app, key);
        }
        app
    }

    /// `app` with its identity made (seed 9), on WZ-5.
    fn made(mut app: App) -> App {
        testkit::send(
            &mut app,
            Msg::Job(JobResult::VaultChecked { prompts: false }),
        );
        testkit::send(
            &mut app,
            Msg::Job(JobResult::Created {
                result: Ok(NewIdentity {
                    me: testkit::me(9),
                    prekey_warning: None,
                }),
                captured: String::new(),
            }),
        );
        app
    }

    /// Where the terminal's cursor is after a draw of `app` at 80x24, if it
    /// shows.
    fn cursor(app: &App) -> Option<(u16, u16)> {
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("a test terminal");
        terminal
            .draw(|f| render_frame(f, app, app.now()))
            .expect("draw");
        let shown = format!("{:?}", terminal.backend()).contains("cursor: true");
        let at = terminal.get_cursor_position().expect("the cursor");
        shown.then_some((at.x, at.y))
    }

    /// What a card's row (a border row too) holds, its frame taken off.
    fn inside(row: &str) -> String {
        row.trim()
            .trim_matches(|c| "┌┐│─╭╮".contains(c))
            .trim()
            .to_owned()
    }

    const AT_WELCOME: &[KeyCode] = &[];
    const TO_NAME: &[KeyCode] = &[KeyCode::Enter];
    const TO_RECEIVE: &[KeyCode] = &[KeyCode::Enter, KeyCode::Enter];
    const TO_CREATING: &[KeyCode] = &[KeyCode::Enter, KeyCode::Enter, KeyCode::Char('y')];

    #[test]
    fn welcome_simple_mono() {
        let app = after(AT_WELCOME);
        testkit::assert_rows(
            &testkit::render_at(&app, 80, 24, app.now() + ms(500)),
            &[
                "                                                                          ? Help",
                "                                                                                ",
                "┌──────────────────────────────────────────────────────────────────────────────┐",
                "│                                                                              │",
                "│                                                                              │",
                "│                                                                              │",
                "│                                                                              │",
                "│                                                                              │",
                "│                                                                              │",
                "│                                                                              │",
                "│                                                                              │",
                "│           R A V E N                                                          │",
                "│                                                                              │",
                "│                                                                              │",
                "│                                                                              │",
                "│                                                                              │",
                "│                                                                              │",
                "│                                                                              │",
                "│                                                                              │",
                "│                                                                              │",
                "│                                                                              │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "                                                                                ",
                "                                                                                ",
            ],
        );
    }

    #[test]
    fn welcome_letters_appear_one_by_one_in_a_small_window() {
        // Under 80 by 24: one card, R A V E N on its border a letter every
        // 100 ms.
        let mut app = after(AT_WELCOME);
        testkit::resize(&mut app, 70, 20);
        let border = |app: &App, at: u64| {
            let rows = testkit::render_at(app, 70, 20, app.now() + ms(at));
            rows.into_iter()
                .find(|row| row.contains('┌'))
                .expect("the card's border")
        };
        let frames: Vec<String> = [0, 99, 100, 250, 499, 500, 2000]
            .into_iter()
            .map(|at| inside(&border(&app, at)))
            .collect();
        assert_eq!(
            frames,
            ["", "", "R", "R A", "R A V E", "R A V E N", "R A V E N"]
        );
        // Under reduced motion they are all there at once; back from WZ-2 too.
        let mut still = after_in(
            Look {
                motion: Motion::Reduced,
                ..testkit::simple_mono()
            },
            AT_WELCOME,
        );
        testkit::resize(&mut still, 70, 20);
        assert_eq!(border(&still, 0), border(&app, 500));
        let mut back = after(&[KeyCode::Enter, KeyCode::Esc]);
        testkit::resize(&mut back, 70, 20);
        assert_eq!(border(&back, 0), border(&app, 500));
        // What moves, for anim.rs.
        let t0 = app.now();
        assert_eq!(
            anim::next_change(&anim::moving(&app), app.look(), t0),
            Some(t0 + ms(100))
        );
        assert_eq!(
            anim::next_change(&anim::moving(&app), app.look(), t0 + ms(500)),
            None
        );
        assert!(anim::moving(&back).is_empty());
    }

    #[test]
    fn welcome_at_the_smallest_size() {
        let app = after(AT_WELCOME);
        testkit::assert_rows(
            &testkit::render_at(&app, 60, 16, app.now() + ms(500)),
            &[
                "                                                      ? Help",
                "┌ R A V E N ───────────────────────────────────────────────┐",
                "│ Welcome to Raven                                         │",
                "│                                                          │",
                "│ Raven sends messages straight from this computer to your │",
                "│ friends' computers. There is no server, no account and   │",
                "│ no phone number.                                         │",
                "│                                                          │",
                "│ Raven doesn't need the internet. It reaches friends on   │",
                "│ the same network as you: a Wi-Fi, a hotspot, or a cable. │",
                "│                                                          │",
                "│ Everything Raven keeps is stored in this folder on this  │",
                "│ computer:                                                │",
                "│ /home/sam/.raven                                         │",
                "│ [Enter] Get started   [C] Classic menu   [Q] Quit        │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
    }

    /// The wizard in the Fancy glyph set at `size`, on WZ-1.
    fn fancy_at(size: (u16, u16), motion: Motion) -> App {
        let mut app = App::new(
            Look {
                glyphs: Glyphs::fancy(),
                motion,
                ..testkit::simple_mono()
            },
            size,
            Instant::now(),
            0,
        );
        app.set_mac_for_tests(false);
        app.start(Session {
            identity: IdentityStart::Missing,
            ..testkit::session(Receive::Unset)
        });
        app
    }

    #[test]
    fn welcome_with_the_mark() {
        // At rest (Calm): R A V E N on the border; the mark on the left;
        // the title, the tagline and the copy on the right (the steps where
        // the window has room for them); the keys under both.
        let app = fancy_at((80, 24), Motion::Full);
        testkit::assert_rows(
            &testkit::render_at(&app, 80, 24, app.now() + ms(4000)),
            &[
                "                                                                          ? Help",
                "                                                                                ",
                "╭ R A V E N ───────────────────────────────────────────────────────────────────╮",
                "│                                                                              │",
                "│  ⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⣴⣶⣶⣦⣤⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀   Welcome to Raven                               │",
                "│  ⠀⠀⠀⠀⢀⣤⣾⠿⠛⠉⠁⠀⠀⠀⠀⠈⠉⠛⠿⣶⣄⡀⠀⠀⠀⠀   Messages straight to your friends. No server.  │",
                "│  ⠀⠀⢀⣴⡿⠋⠀⠀⣀⣀⣀⣀⣀⣀⣀⣀⣀⠀⠀⠀⠙⢿⣦⠀⠀⠀                                                  │",
                "│  ⠀⠀⠾⠏⣀⣤⣶⣿⠟⠛⠛⠛⠿⣿⡟⠛⠛⠿⣷⣄⠀⠀⠹⣷⡀⠀   Raven sends messages straight from this        │",
                "│  ⠠⣾⡿⠿⠛⠉⢸⣿⠀⠀⠀⠀⠀⠘⠿⠿⣶⣄⠈⢻⣷⠀⠀⠹⣷⡀   computer to your friends' computers. There is  │",
                "│  ⠀⠙⢻⣿⠇⠀⢸⣿⠀⠀⠀⠀⠀⢀⣀⣀⣈⣿⡇⠀⣿⡇⠀⠀⢿⣇   no server, no account and no phone number.     │",
                "│  ⠀⢠⣿⠏⠀⠀⢸⣿⠀⠀⠀⣠⣾⣿⡿⠛⠻⣿⠇⢠⣿⠃⠀⠀⢸⣿                                                  │",
                "│  ⠀⣼⡟⠀⢠⣄⢸⣿⠀⠀⣼⡟⠁⣿⡇⠀⠀⢀⣤⣿⠋⠀⠀⠀⢸⡿   Raven doesn't need the internet. It reaches    │",
                "│  ⠀⣿⡇⣰⣿⡇⢸⣿⠀⣼⡟⠀⠀⢻⣿⡿⠿⣿⣏⠀⠀⠀⠀⢀⣿⠇   friends on the same network as you: a Wi-Fi,   │",
                "│  ⠀⢻⣷⣿⣿⡇⢸⣿⠀⣿⡇⢠⣄⠀⠙⢿⣦⣜⣿⣦⠀⠀⢀⣼⡟⠀   a hotspot, or a cable.                         │",
                "│  ⠀⠈⠛⠋⢿⣇⢸⣿⠀⣿⡇⣿⡿⢷⣦⣤⣈⣙⣿⣿⡷⣠⣾⠟⠀⠀                                                  │",
                "│  ⠀⠀⠀⠀⠈⢿⣾⣿⠀⢹⣷⣿⡇⠀⠈⠉⢻⣿⣉⣡⣾⣿⣇⠀⠀⠀   Everything Raven keeps is stored in this       │",
                "│  ⠀⠀⠀⠀⠀⠀⠙⢿⣦⣄⣻⣿⡇⣀⣤⣤⣴⡿⢿⣯⣁⣈⣻⣧⡀⠀   folder on this computer:                       │",
                "│  ⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠁⠉⠉⠉⠁⠀⠀⠉⠛⠛⠛⠛⠃⠀   /home/sam/.raven                               │",
                "│                                                                              │",
                "│  [Enter] Get started   [C] Classic menu   [Q] Quit                           │",
                "│                                                                              │",
                "╰──────────────────────────────────────────────────────────────────────────────╯",
                "                                                                                ",
                "                                                                                ",
            ],
        );
    }

    #[test]
    fn welcome_without_room_for_the_mark_has_the_wordmark() {
        // One column short of 80 by 24: the card with R A V E N on its
        // border, as in the other glyph sets.
        let app = fancy_at((79, 24), Motion::Full);
        testkit::assert_rows(
            &testkit::render_at(&app, 79, 24, app.now() + ms(4000)),
            &[
                "                                                                         ? Help",
                "                                                                               ",
                "                                                                               ",
                "                                                                               ",
                "       ╭ R A V E N ───────────────────────────────────────────────────╮        ",
                "       │ Welcome to Raven                                             │        ",
                "       │                                                              │        ",
                "       │ Raven sends messages straight from this computer to your     │        ",
                "       │ friends' computers. There is no server, no account and no    │        ",
                "       │ phone number.                                                │        ",
                "       │                                                              │        ",
                "       │ Raven doesn't need the internet. It reaches friends on the   │        ",
                "       │ same network as you: a Wi-Fi, a hotspot, or a cable.         │        ",
                "       │                                                              │        ",
                "       │ Everything Raven keeps is stored in this folder on this      │        ",
                "       │ computer:                                                    │        ",
                "       │ /home/sam/.raven                                             │        ",
                "       │                                                              │        ",
                "       │ [Enter] Get started   [C] Classic menu   [Q] Quit            │        ",
                "       ╰──────────────────────────────────────────────────────────────╯        ",
                "                                                                               ",
                "                                                                               ",
                "                                                                               ",
                "                                                                               ",
            ],
        );
    }

    /// The dots of the mark drawn in `rows` (WZ-1 at 80 by 24).
    fn mark_dots_in(rows: &[String]) -> usize {
        rows[4..18]
            .iter()
            .map(|row| {
                row.chars()
                    .skip(3)
                    .take(26)
                    .map(|c| u32::from(c).saturating_sub(0x2800).count_ones() as usize)
                    .sum::<usize>()
            })
            .sum()
    }

    /// The text column's row `y` (WZ-1 at 80 by 24).
    fn text_at(rows: &[String], y: usize) -> String {
        let row: String = rows[y].chars().skip(32).take(46).collect();
        row.trim_end().to_owned()
    }

    #[test]
    fn the_welcome_assembles_then_types_itself() {
        // WZ-1 (Calm, tokens' welcomeMs): the mark's dots assemble over
        // 1.5 s; the letters come from 1.5 s, one every 100 ms; the title at
        // 2.1 s; the tagline types from 2.2 s, 25 ms a character; the copy
        // at 3 s; the keys at 3.3 s.
        let app = fancy_at((80, 24), Motion::Full);
        let t = app.now();
        let frame = |at: u64| testkit::render_at(&app, 80, 24, t + ms(at));
        let all = mark_dots().len();
        let start = frame(0);
        assert_eq!(mark_dots_in(&start), 0, "the start: an empty card");
        assert_eq!(inside(&start[2]), "");
        assert_eq!(text_at(&start, 4), "");
        assert!(!start.iter().any(|row| row.contains("[Enter]")));
        // Halfway through the mark: half its dots.
        let mid = frame(750);
        assert_eq!(mark_dots_in(&mid), all / 2);
        assert_eq!(text_at(&mid, 4), "");
        assert_eq!(mark_dots_in(&frame(1500)), all);
        let letters: Vec<String> = [1_500, 1_599, 1_600, 1_850, 2_000]
            .into_iter()
            .map(|at| inside(&frame(at)[2]))
            .collect();
        assert_eq!(letters, ["", "", "R", "R A V", "R A V E N"]);
        assert_eq!(text_at(&frame(2_099), 4), "");
        assert_eq!(text_at(&frame(2_100), 4), "Welcome to Raven");
        let tagline = "Messages straight to your friends. No server.";
        assert_eq!(text_at(&frame(2_224), 5), "");
        assert_eq!(text_at(&frame(2_225), 5), "M");
        assert_eq!(text_at(&frame(2_450), 5), "Messages s");
        assert_eq!(text_at(&frame(3_324), 5), &tagline[..44]);
        assert_eq!(text_at(&frame(3_325), 5), tagline);
        assert!(!frame(2_999)[7].contains("Raven sends"));
        assert!(frame(3_000)[7].contains("Raven sends"));
        assert!(!frame(3_299)[19].contains("[Enter] Get started"));
        assert!(frame(3_300)[19].contains("[Enter] Get started"));
        // At rest: the frame reduced motion draws at once, and back from
        // WZ-2 too.
        let still = fancy_at((80, 24), Motion::Reduced);
        assert_eq!(frame(3_325), testkit::render(&still, 80, 24));
        let mut back = fancy_at((80, 24), Motion::Full);
        testkit::press(&mut back, KeyCode::Enter);
        testkit::press(&mut back, KeyCode::Esc);
        assert_eq!(frame(3_325), testkit::render(&back, 80, 24));
        // What moves, for anim.rs: frames from the start (the budget keeps
        // them 80 ms apart), then nothing.
        let moving = anim::moving(&app);
        let first = anim::next_change(&moving, app.look(), t).expect("a frame");
        assert!(first > t && first <= t + ms(80), "{:?}", first - t);
        assert_eq!(anim::next_change(&moving, app.look(), t + ms(3_325)), None);
        assert_eq!(
            anim::next_change(&anim::moving(&still), still.look(), t),
            None
        );
        assert!(anim::moving(&back).is_empty());
    }

    #[test]
    fn the_newest_dots_are_in_the_accent_while_the_mark_assembles() {
        let look = Look {
            glyphs: Glyphs::fancy(),
            theme: theme::Theme::calm(&theme::DARK, theme::Depth::True),
            ..testkit::simple_mono()
        };
        let mut app = App::new(look, (80, 24), Instant::now(), 0);
        app.set_mac_for_tests(false);
        app.start(Session {
            identity: IdentityStart::Missing,
            ..testkit::session(Receive::Unset)
        });
        let accent_cells = |at: u64| {
            let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("a terminal");
            terminal
                .draw(|f| render_frame(f, &app, app.now() + ms(at)))
                .expect("a draw");
            let buf = terminal.backend().buffer().clone();
            (4..18)
                .flat_map(|y| (3..29).map(move |x| (x, y)))
                .filter(|&at| buf[at].fg == look.theme.accent.fg.expect("a colour"))
                .count()
        };
        let mid = accent_cells(750);
        assert!(mid > 0 && mid <= FRESH_DOTS, "{mid}");
        assert_eq!(accent_cells(1_500), 0, "at rest, none");
    }

    #[test]
    fn a_terminal_that_is_not_one_gets_the_finished_welcome_at_once() {
        let env = LookEnv {
            term: TermEnv {
                not_a_tty: true,
                ..TermEnv::default()
            },
            code_page: None,
            screen_reader: false,
        };
        let look = Look {
            glyphs: Glyphs::fancy(),
            ..Look::of(&TuiState::default(), &env)
        };
        assert_eq!(look.motion, Motion::Reduced);
        let mut app = App::new(look, (80, 24), Instant::now(), 0);
        app.set_mac_for_tests(false);
        app.start(Session {
            identity: IdentityStart::Missing,
            ..testkit::session(Receive::Unset)
        });
        let rows = testkit::render(&app, 80, 24);
        assert_eq!(mark_dots_in(&rows), mark_dots().len());
        assert_eq!(inside(&rows[2]), "R A V E N");
        assert!(rows[19].contains("[Enter] Get started"));
        assert!(anim::moving(&app)
            .iter()
            .all(|m| anim::next_change(&[*m], app.look(), app.now()).is_none()));
    }

    #[test]
    fn simple_and_ascii_welcomes_have_the_wordmark_and_no_braille() {
        for glyphs in [Glyphs::simple(), Glyphs::ascii()] {
            let app = after_in(
                Look {
                    glyphs,
                    ..testkit::simple_mono()
                },
                AT_WELCOME,
            );
            for at in [0, 750, 2_000, 4_000] {
                let rows = testkit::render_at(&app, 80, 24, app.now() + ms(at));
                let braille = rows
                    .iter()
                    .flat_map(|row| row.chars())
                    .any(|c| ('\u{2800}'..='\u{28ff}').contains(&c));
                assert!(!braille, "{glyphs:?} at {at} ms: {rows:#?}");
                // The wordmark stands in for the mark from the start.
                assert!(rows[11].contains("R A V E N"), "{rows:#?}");
            }
        }
    }

    #[test]
    fn welcome_ascii() {
        let app = after_in(
            Look {
                glyphs: Glyphs::ascii(),
                ..testkit::simple_mono()
            },
            AT_WELCOME,
        );
        testkit::assert_rows(
            &testkit::render_at(&app, 80, 24, app.now() + ms(500)),
            &[
                "                                                                          ? Help",
                "                                                                                ",
                "+------------------------------------------------------------------------------+",
                "|                                                                              |",
                "|                                                                              |",
                "|                                                                              |",
                "|                                                                              |",
                "|                                                                              |",
                "|                                                                              |",
                "|                                                                              |",
                "|                                                                              |",
                "|           R A V E N                                                          |",
                "|                                                                              |",
                "|                                                                              |",
                "|                                                                              |",
                "|                                                                              |",
                "|                                                                              |",
                "|                                                                              |",
                "|                                                                              |",
                "|                                                                              |",
                "|                                                                              |",
                "+------------------------------------------------------------------------------+",
                "                                                                                ",
                "                                                                                ",
            ],
        );
    }

    #[test]
    fn a_long_folder_loses_its_middle() {
        let mut app = testkit::app((70, 20));
        let long = format!("/home/sam/{}raven-profile", "deep/".repeat(20));
        app.start(Session {
            identity: IdentityStart::Missing,
            data_dir: long.into(),
            ..testkit::session(Receive::Unset)
        });
        let rows = testkit::render(&app, 70, 20);
        let folder = rows
            .iter()
            .find(|row| row.contains("/home/sam/"))
            .expect("the folder's row");
        assert_eq!(
            inside(folder),
            "/home/sam/deep/deep/deep/deep...deep/deep/deep/raven-profile"
        );
        assert_eq!(display::width(&inside(folder)), 60, "the row's width");
    }

    #[test]
    fn name_empty_shows_the_placeholder_and_the_cursor() {
        let app = after(TO_NAME);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                                       ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ What should Raven call you?                                  │        ",
                "        │                                                              │        ",
                "        │ This name is only shown on this computer, to greet you. It   │        ",
                "        │ is never sent to anyone. Your friends choose their own name  │        ",
                "        │ for you.                                                     │        ",
                "        │                                                              │        ",
                "        │ ┌──────────────────────────────────┐                         │        ",
                "        │ │ Your name (optional)             │                         │        ",
                "        │ └──────────────────────────────────┘                         │        ",
                "        │                                                              │        ",
                "        │ [Enter] Continue   [Esc] Back                                │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        // On the field's row, right after its border and space.
        assert_eq!(cursor(&app), Some((12, 14)));
        // Under an overlay the cursor hides.
        let mut over = after(TO_NAME);
        testkit::ctrl(&mut over, 'c');
        assert_eq!(cursor(&over), None);
    }

    #[test]
    fn name_full_says_so() {
        let mut keys = TO_NAME.to_vec();
        keys.extend(std::iter::repeat_n(KeyCode::Char('x'), 40));
        let app = after(&keys);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                                       ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ What should Raven call you?                                  │        ",
                "        │                                                              │        ",
                "        │ This name is only shown on this computer, to greet you. It   │        ",
                "        │ is never sent to anyone. Your friends choose their own name  │        ",
                "        │ for you.                                                     │        ",
                "        │                                                              │        ",
                "        │ ┌──────────────────────────────────┐                         │        ",
                "        │ │ xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx │                         │        ",
                "        │ └──────────────────────────────────┘                         │        ",
                "        │ That's the longest name Raven shows.                         │        ",
                "        │                                                              │        ",
                "        │ [Enter] Continue   [Esc] Back                                │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        // After the 32nd cell, still inside the field.
        assert_eq!(cursor(&app), Some((44, 13)));
    }

    #[test]
    fn receive_question() {
        testkit::assert_rows(
            &testkit::render(&after(TO_RECEIVE), 80, 24),
            &[
                "R A V E N                                                                       ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Receive messages on this computer?                           │        ",
                "        │                                                              │        ",
                "        │ To get messages, Raven keeps a small background program      │        ",
                "        │ running that listens on your network (port 7420). Only       │        ",
                "        │ friends you add can send you anything.                       │        ",
                "        │                                                              │        ",
                "        │ Your computer may ask whether to allow this. On Windows,     │        ",
                "        │ choose Private networks and Allow.                           │        ",
                "        │                                                              │        ",
                "        │ You can change this later in Settings.                       │        ",
                "        │                                                              │        ",
                "        │ > [Y] Yes, receive messages (recommended)                    │        ",
                "        │   [N] Not now, I only want to send                           │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
    }

    #[test]
    fn creating_spins_until_it_is_done() {
        let app = after(TO_CREATING);
        let t0 = app.now();
        let mut rows = testkit::render(&app, 80, 24);
        testkit::assert_rows(
            &rows,
            &[
                "R A V E N                                                                       ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ | Creating your Raven identity...                            │        ",
                "        │                                                              │        ",
                "        │ This makes a private key that never leaves this computer.    │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        let frames: Vec<String> = [0, 80, 160]
            .into_iter()
            .map(|at| inside(&testkit::render_at(&app, 80, 24, t0 + ms(at))[11]))
            .collect();
        assert_eq!(
            frames,
            [
                "| Creating your Raven identity...",
                "/ Creating your Raven identity...",
                "- Creating your Raven identity...",
            ]
        );
        let still = after_in(
            Look {
                motion: Motion::Reduced,
                ..testkit::simple_mono()
            },
            TO_CREATING,
        );
        let frames: Vec<String> = [0, 80, 160]
            .into_iter()
            .map(|at| inside(&testkit::render_at(&still, 80, 24, t0 + ms(at))[11]))
            .collect();
        assert_eq!(frames, ["... Creating your Raven identity..."; 3]);
        // The UI wakes for each frame, and for none under reduced motion.
        assert_eq!(
            anim::next_change(&anim::moving(&app), app.look(), t0),
            Some(t0 + ms(80))
        );
        assert_eq!(
            anim::next_change(&anim::moving(&still), still.look(), t0),
            None
        );
        // On a Mac it says what to do when the Mac asks for its password.
        let mut mac = after(TO_CREATING);
        mac.set_mac_for_tests(true);
        rows = testkit::render(&mac, 80, 24);
        testkit::assert_rows(
            &rows,
            &[
                "R A V E N                                                                       ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ | Creating your Raven identity...                            │        ",
                "        │                                                              │        ",
                "        │ This makes a private key that never leaves this computer.    │        ",
                "        │                                                              │        ",
                "        │ If your Mac asks for your password, enter it and choose      │        ",
                "        │ Always Allow.                                                │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
    }

    #[test]
    fn creating_failed_with_details() {
        let mut app = after(TO_CREATING);
        testkit::send(
            &mut app,
            Msg::Job(JobResult::VaultChecked { prompts: false }),
        );
        let denied = raven_core::IdentityStoreError::SecureStore(
            "keychain get status -25293\u{1b}[2J".into(),
        );
        testkit::send(
            &mut app,
            Msg::Job(JobResult::Created {
                result: Err(denied.redacted_display()),
                captured: String::new(),
            }),
        );
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                                       ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Raven could not create your identity.                        │        ",
                "        │                                                              │        ",
                "        │ Raven wasn't allowed to read your identity from the system   │        ",
                "        │ keychain.                                                    │        ",
                "        │                                                              │        ",
                "        │ [R] Try again   [D] Details   [Q] Quit                       │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        testkit::press(&mut app, KeyCode::Char('d'));
        let rows = testkit::render(&app, 80, 24);
        testkit::assert_rows(
            &rows,
            &[
                "R A V E N                                                                       ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Raven could not create your identity.                        │        ",
                "        │                                                              │        ",
                "        │ Raven wasn't allowed to read your identity from the system   │        ",
                "        │ keychain.                                                    │        ",
                "        │                                                              │        ",
                "        │ secure store unavailable: keychain get status -25293         │        ",
                "        │                                                              │        ",
                "        │ [R] Try again   [D] Details   [Q] Quit                       │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        assert!(rows.iter().all(|row| !row.contains("[2J")), "{rows:#?}");
    }

    /// WZ-5 drawn on its own in a `cols` x `rows` terminal at `now`. Under
    /// MIN_COLS by MIN_ROWS the app shows SMALL instead: this pins the words'
    /// layout under 40 columns itself.
    fn words_alone(app: &App, cols: u16, rows: u16, now: Instant) -> Vec<String> {
        let Screen::Wizard(step) = app.screen() else {
            panic!("not the wizard: {:?}", app.screen());
        };
        let mut terminal = Terminal::new(TestBackend::new(cols, rows)).expect("a test terminal");
        terminal
            .draw(|f| render(f, f.area(), app, step, now))
            .expect("draw");
        testkit::buffer_lines(terminal.backend().buffer())
    }

    /// `lines` as text, a row each.
    fn texts(lines: &[Line]) -> Vec<String> {
        lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect()
            })
            .collect()
    }

    /// Whether `partial` is `full` with some of its cells left blank.
    fn blanks_of(full: &str, partial: &str) -> bool {
        full.chars().count() == partial.chars().count()
            && full
                .chars()
                .zip(partial.chars())
                .all(|(f, p)| f == p || p == ' ')
    }

    #[test]
    fn the_words_appear_one_by_one() {
        let app = made(after(TO_CREATING));
        let t0 = app.now();
        let full = testkit::render_at(&app, 80, 24, t0 + ms(1080));
        testkit::assert_rows(
            &full,
            &[
                "R A V E N                                                                       ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Your security words                                          │        ",
                "        │                                                              │        ",
                "        │   1 lemon   2 sofa      3 pickle   4 mirror    5 thread      │        ",
                "        │   6 train   7 sausage   8 pig      9 fork     10 frog        │        ",
                "        │ Old-style code (for friends with an older Raven):            │        ",
                "        │ 28KY JRxR Mhty                                               │        ",
                "        │                                                              │        ",
                "        │ These 10 words belong to your Raven identity. When you add a │        ",
                "        │ friend, you each read your own words to the other, in person │        ",
                "        │ or on a phone call, and type what you hear. If they match,   │        ",
                "        │ nobody swapped the key in between.                           │        ",
                "        │                                                              │        ",
                "        │ They are not a password: anyone may know them. Raven never   │        ",
                "        │ asks you for secret words.                                   │        ",
                "        │                                                              │        ",
                "        │ Raven never checks this for you, and never marks a friend as │        ",
                "        │ verified by itself.                                          │        ",
                "        │                                                              │        ",
                "        │ [Enter] Next                                                 │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
            ],
        );
        // The code's case note is VF's now, on the old-code path.
        assert!(!testkit::screen_text(&full).contains("case-sensitive"));
        // One more word every 120 ms, in reading order, each in its place
        // from the start: nothing moves as they come.
        let words = |at: u64| {
            let rows = testkit::render_at(&app, 80, 24, t0 + ms(at));
            for (row, full) in rows.iter().zip(&full) {
                assert!(blanks_of(full, row), "{at} ms: {row:?}");
            }
            testkit::screen_text(&rows[5..7])
        };
        let all =
            "1 lemon 2 sofa 3 pickle 4 mirror 5 thread 6 train 7 sausage 8 pig 9 fork 10 frog";
        let first = |n: usize| all.split(' ').take(2 * n).collect::<Vec<_>>().join(" ");
        for (at, shown) in [
            (0, 1),
            (119, 1),
            (120, 2),
            (600, 6),
            (1079, 9),
            (1080, 10),
            (5000, 10),
        ] {
            assert_eq!(words(at), first(shown), "{at} ms");
        }
        assert_eq!(
            anim::next_change(&anim::moving(&app), app.look(), t0),
            Some(t0 + ms(120))
        );
        assert_eq!(
            anim::next_change(&anim::moving(&app), app.look(), t0 + ms(1080)),
            None
        );
        // Under reduced motion they are all there at once.
        let still = made(after_in(
            Look {
                motion: Motion::Reduced,
                ..testkit::simple_mono()
            },
            TO_CREATING,
        ));
        assert_eq!(testkit::render(&still, 80, 24), full);
        assert_eq!(
            anim::next_change(&anim::moving(&still), still.look(), still.now()),
            None
        );
        assert_eq!(code_groups("If4x-36FU-omFi"), ["If4x", "36FU", "omFi"]);
    }

    #[test]
    fn the_words_at_the_smallest_size() {
        // The copy that does not fit goes a paragraph at a time, from the
        // last; the words, the code and the keys stay.
        let app = made(after(TO_CREATING));
        testkit::assert_rows(
            &testkit::render_at(&app, 60, 16, app.now() + ms(1080)),
            &[
                "R A V E N                                                   ",
                "┌──────────────────────────────────────────────────────────┐",
                "│ Your security words                                      │",
                "│                                                          │",
                "│   1 lemon   2 sofa      3 pickle   4 mirror    5 thread  │",
                "│   6 train   7 sausage   8 pig      9 fork     10 frog    │",
                "│ Old-style code (for friends with an older Raven):        │",
                "│ 28KY JRxR Mhty                                           │",
                "│ These 10 words belong to your Raven identity. When you   │",
                "│ add a friend, you each read your own words to the other, │",
                "│ in person or on a phone call, and type what you hear. If │",
                "│ they match, nobody swapped the key in between.           │",
                "│ They are not a password: anyone may know them. Raven     │",
                "│ never asks you for secret words.                         │",
                "│ [Enter] Next                                             │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
    }

    #[test]
    fn the_words_one_to_a_line_under_40_columns() {
        let app = made(after(TO_CREATING));
        testkit::assert_rows(
            &words_alone(&app, 40, 20, app.now() + ms(1080)),
            &[
                "R A V E N                               ",
                "┌──────────────────────────────────────┐",
                "│ Your security words                  │",
                "│                                      │",
                "│  1 lemon                             │",
                "│  2 sofa                              │",
                "│  3 pickle                            │",
                "│  4 mirror                            │",
                "│  5 thread                            │",
                "│  6 train                             │",
                "│  7 sausage                           │",
                "│  8 pig                               │",
                "│  9 fork                              │",
                "│ 10 frog                              │",
                "│ Old-style code (for friends with an  │",
                "│ older Raven):                        │",
                "│ 28KY JRxR Mhty                       │",
                "│                                      │",
                "│ [Enter] Next                         │",
                "└──────────────────────────────────────┘",
            ],
        );
    }

    #[test]
    fn the_grid_never_splits_a_word() {
        let look = testkit::simple_mono();
        // The words of 256 keys, and the ten longest of the list together.
        let mut sets: Vec<Vec<String>> = (0..=u8::MAX)
            .map(|seed| testkit::me(seed).words.to_vec())
            .collect();
        let mut longest: Vec<&str> = raven_core::security_words::list_v1().to_vec();
        longest.sort_by_key(|word| std::cmp::Reverse(word.len()));
        sets.push(
            longest[..10]
                .iter()
                .map(|word| (*word).to_owned())
                .collect(),
        );
        for words in &sets {
            let read: Vec<String> = words
                .iter()
                .enumerate()
                .flat_map(|(i, word)| [(i + 1).to_string(), word.clone()])
                .collect();
            for width in 20..=60 {
                let rows = texts(&word_rows(&look, words, width, words.len()));
                // Each row within the width; read row by row, every number
                // and word whole and in order.
                assert!(
                    rows.iter().all(|row| cells(row) <= usize::from(width)),
                    "{width}: {rows:#?}"
                );
                let tokens: Vec<String> = rows
                    .iter()
                    .flat_map(|row| row.split_whitespace().map(str::to_owned))
                    .collect();
                assert_eq!(tokens, read, "{width}: {rows:#?}");
                // Two rows of 5, always in a card of the smallest window
                // (56 cells); one word to a line under 40 cells.
                match width {
                    ..40 => assert_eq!(rows.len(), 10, "{width}: {rows:#?}"),
                    56.. => assert_eq!(rows.len(), 2, "{width}: {rows:#?}"),
                    _ => assert!(matches!(rows.len(), 2 | 10), "{width}: {rows:#?}"),
                }
                // Words still to come leave their place blank.
                for shown in 0..words.len() {
                    let partial = texts(&word_rows(&look, words, width, shown));
                    assert_eq!(partial.len(), rows.len());
                    for (row, full) in partial.iter().zip(&rows) {
                        assert!(blanks_of(full, row), "{width}, {shown}: {row:?}");
                    }
                    let tokens = partial.iter().flat_map(|row| row.split_whitespace());
                    assert!(tokens.eq(read[..2 * shown].iter().map(String::as_str)));
                }
            }
        }
    }

    #[test]
    fn ready_by_name() {
        let mut keys = TO_NAME.to_vec();
        keys.extend("Sam".chars().map(KeyCode::Char));
        keys.extend([KeyCode::Enter, KeyCode::Char('y')]);
        let mut app = made(after(&keys));
        testkit::press(&mut app, KeyCode::Enter);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                                       ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ You're ready, Sam.                                           │        ",
                "        │                                                              │        ",
                "        │ Next, add a friend: you send them your invite and paste      │        ",
                "        │ theirs.                                                      │        ",
                "        │                                                              │        ",
                "        │ Raven starts listening for your friend as soon as you open   │        ",
                "        │ Add a friend.                                                │        ",
                "        │                                                              │        ",
                "        │ [A] Add a friend now   [Enter] Open Raven                    │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
    }

    #[test]
    fn ready_without_a_name_or_receiving() {
        let mut keys = TO_RECEIVE.to_vec();
        keys.push(KeyCode::Char('n'));
        let mut app = made(after(&keys));
        testkit::press(&mut app, KeyCode::Enter);
        testkit::tick(&mut app, Duration::from_secs(5));
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                                       ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ You're ready.                                                │        ",
                "        │                                                              │        ",
                "        │ Next, add a friend: you send them your invite and paste      │        ",
                "        │ theirs.                                                      │        ",
                "        │                                                              │        ",
                "        │ [A] Add a friend now   [Enter] Open Raven                    │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
    }

    #[test]
    fn a_hostile_name_shows_as_text() {
        let mut keys = TO_NAME.to_vec();
        keys.extend("Sam\u{202E}live".chars().map(KeyCode::Char));
        keys.extend([KeyCode::Enter, KeyCode::Char('y')]);
        let mut app = made(after(&keys));
        testkit::press(&mut app, KeyCode::Enter);
        let rows = testkit::render(&app, 80, 24);
        let heading = rows
            .iter()
            .find(|row| row.contains("You're ready"))
            .expect("WZ-6");
        assert_eq!(inside(heading), "You're ready, Samlive.");
    }

    #[test]
    fn err_id_for_leftover_files() {
        let mut app = testkit::app((80, 24));
        let continuity = raven_core::IdentityStoreError::Continuity(
            "profile contains state but has no identity continuity record",
        );
        app.start(Session {
            identity: IdentityStart::Unavailable(continuity.redacted_display()),
            ..testkit::session(Receive::Unset)
        });
        assert!(matches!(app.screen(), Screen::IdentityError(_)));
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                                       ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Raven can't open this profile                                │        ",
                "        │                                                              │        ",
                "        │ This folder has Raven files but no identity. Raven will not  │        ",
                "        │ make a new identity over them: to your friends it would look │        ",
                "        │ like someone else using your name.                           │        ",
                "        │                                                              │        ",
                "        │ What you can do: move this folder aside and start fresh, or  │        ",
                "        │ put back a backup of it.                                     │        ",
                "        │                                                              │        ",
                "        │ Folder: /home/sam/.raven                                     │        ",
                "        │                                                              │        ",
                "        │ [D] Details   [C] Classic menu   [Q] Quit                    │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        testkit::press(&mut app, KeyCode::Char('d'));
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                                       ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Raven can't open this profile                                │        ",
                "        │                                                              │        ",
                "        │ This folder has Raven files but no identity. Raven will not  │        ",
                "        │ make a new identity over them: to your friends it would look │        ",
                "        │ like someone else using your name.                           │        ",
                "        │                                                              │        ",
                "        │ What you can do: move this folder aside and start fresh, or  │        ",
                "        │ put back a backup of it.                                     │        ",
                "        │                                                              │        ",
                "        │ Folder: /home/sam/.raven                                     │        ",
                "        │                                                              │        ",
                "        │ identity continuity violation: profile contains state but    │        ",
                "        │ has no identity continuity record                            │        ",
                "        │                                                              │        ",
                "        │ [D] Details   [C] Classic menu   [Q] Quit                    │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N                                                   ",
                "┌──────────────────────────────────────────────────────────┐",
                "│ Raven can't open this profile                            │",
                "│                                                          │",
                "│ This folder has Raven files but no identity. Raven will  │",
                "│ not make a new identity over them: to your friends it    │",
                "│ would look like someone else using your name.            │",
                "│                                                          │",
                "│ What you can do: move this folder aside and start fresh, │",
                "│ or put back a backup of it.                              │",
                "│                                                          │",
                "│ Folder: /home/sam/.raven                                 │",
                "│ identity continuity violation: profile contains state    │",
                "│ but has no identity continuity record                    │",
                "│ [D] Details   [C] Classic menu   [Q] Quit                │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
    }

    #[test]
    fn quit_while_the_identity_is_made() {
        let mut app = after(TO_CREATING);
        testkit::ctrl(&mut app, 'c');
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                                       ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "          ┌──────────────────────────────────────────────────────────┐          ",
                "        ┌─│ Raven is finishing setting up your identity. Please      │─┐        ",
                "        │ │ wait...                                                  │ │        ",
                "        │ │                                                          │ │        ",
                "        │ │ [Esc] Stay                                               │ │        ",
                "        └─└──────────────────────────────────────────────────────────┘─┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
    }

    #[test]
    fn help_over_welcome_lists_its_keys() {
        let app = after(&[KeyCode::Char('?')]);
        let rows = testkit::render_at(&app, 80, 24, app.now() + ms(500));
        testkit::assert_rows(
            &rows[..10],
            &[
                "                                                                          ? Help",
                "                                                                                ",
                "┌───┌ Help ────────────────────────────────────────────────────────────────┐───┐",
                "│   │ Keys                                                                 │   │",
                "│   │ Enter   Get started                                                  │   │",
                "│   │ C       Classic menu                                                 │   │",
                "│   │ Q, Esc  Quit                                                         │   │",
                "│   │ Ctrl+L  Redraw the screen                                            │   │",
                "│   │ Shortcuts also work with a Persian keyboard.                         │   │",
                "│   │                                                                      │   │",
            ],
        );
    }
}
