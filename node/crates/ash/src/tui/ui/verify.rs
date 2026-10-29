//! VF, AF-3 and CI: a friend's security words compared out loud, the friend
//! added, and a saved friend's page.
//!
//! - VF shows my security words, numbered, and a field for the friend's
//!   words as they read them: each word typed so far as a numbered chip with
//!   a dot that only says "a Raven word" (never "right"), the word being
//!   typed with its suggestions from the whole list, and how many are typed.
//!   With Ctrl+O it takes their old code instead: my code in groups, with a
//!   read-aloud helper for one of them, and each group of theirs typed so
//!   far with its mark. Their words and code themselves are drawn only once
//!   they matched (the App's [`VerifyView`] holds them only then); after
//!   that, and for Later, a fresh confirmation code is asked for. Letters of
//!   another alphabet get the keyboard hint, never the mismatch's warning.
//!   After 3 entries that were not theirs, VF says to stop. Two columns from
//!   80 terminal columns, one above the other below that.
//! - AF-3 says the friend is added, verified or not, and that they must add
//!   the user too.
//! - CI shows one friend's public facts, their security words and old-style
//!   code only once they are verified, and opens one field at a time: a new
//!   name, their address, or the 'remove' question. Its Security row
//!   (Phase 6b P6.31) counts the problems of the last 7 days and says
//!   whether sending to them is paused.
//! - For a verified friend VF checks again (P6.31): Enter on 'Already
//!   verified', or at once while a security notice about them is open. A
//!   match resolves their notices; while their Raven offers an older
//!   security method than before, VF then asks for 'accept' (design A R9).
//!
//! Every untrusted string (names, addresses, what was typed, a failure's
//! technical text) is drawn through display.rs.

use std::cmp::Reverse;
use std::time::{Duration, Instant};

use ratatui::layout::{Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::anim::{self, Moving};
use super::app::{
    AddedState, App, CodeProblem, EntryMode, Failure, PageEdit, PageState, Screen, VerifyStep,
    VerifyView,
};
#[cfg(test)]
use super::app::{Cmd, FriendChange, JobResult, Key, Msg, Overlay, PasteVia, Session, StoreJob};
use super::bridge::{self, ContactView, ParseError, WORDS};
#[cfg(test)]
use super::bridge::{ChatKeepView, DeleteChatOutcome};
#[cfg(test)]
use super::controller::Conversations;
#[cfg(test)]
use super::state_file::Receive;
use super::Look;
use super::{
    add_friend, cells, controller, display, home, overlays, render_header, widgets, wizard, wrap,
};
#[cfg(test)]
use super::{testkit, theme};

/// VF's columns stand side by side from this many terminal columns.
const COLUMNS_FROM: u16 = 80;
/// Cells between VF's columns.
const GAP: u16 = 4;
/// A match makes both columns stand out this long.
const MATCH_TIME: Duration = Duration::from_millis(600);
/// A group's mark draws in over this long: 2 frames.
const MARK_TIME: Duration = Duration::from_millis(120);
/// AF-3's check mark draws in over this long: 3 frames (0 to 2).
const CHECK_TIME: Duration = Duration::from_millis(300);
const CHECK_FRAMES: u32 = 2;

/// VF.
const CASE_ONLY: &str = "Upper and lower case differ: codes are case-sensitive (W is not w).";
const WRONG_CODE: &str = "That code didn't match. Nothing was saved.";
/// Letters of another alphabet in a code (VF, and AF-1's [U] question):
/// said instead of the mismatch, in the CLI's words.
pub(super) const LATIN_KEYBOARD: &str = super::bridge::CODE_KEYBOARD_HINT;
/// Switch your keyboard (words mode).
const WORDS_KEYBOARD: &str = "Type the words with English letters.";
/// Where the words field offers the old code.
const OLD_CODE: &str = "[Ctrl+O] Use the old code instead (for a friend with an older Raven)";
const COMPARE_KEYS: [(&str, &str); 3] = [
    ("[Enter]", " Check"),
    ("[Tab]", " Later (not verified)"),
    ("[Esc]", " Cancel"),
];
const PICK_KEYS: [(&str, &str); 3] = [
    ("[Enter]", " Check"),
    ("[Tab]", " Pick word"),
    ("[Esc]", " Cancel"),
];
const SAVED_COMPARE_KEYS: [(&str, &str); 2] = [("[Enter]", " Check"), ("[Esc]", " Cancel")];
/// After 3 entries that were not theirs: no more checks.
const STOPPED_KEYS: [(&str, &str); 2] = [("[Tab]", " Later (not verified)"), ("[Esc]", " Cancel")];
const STOPPED_SAVED_KEYS: [(&str, &str); 1] = [("[Esc]", " Cancel")];
const WORDS_VERIFIED_KEYS: [(&str, &str); 3] = [
    ("[Enter]", " Check again"),
    ("[Ctrl+O]", " Old code"),
    ("[Esc]", " Back"),
];
const VERIFIED_KEYS: [(&str, &str); 2] = [("[Enter]", " Check again"), ("[Esc]", " Back")];
/// The older-method question (P6.31).
const OLDER_KEYS: [(&str, &str); 2] = [("[Enter]", " OK"), ("[Esc]", " Keep the newer one")];
const CONFIRM_KEYS: [(&str, &str); 2] = [("[Enter]", " Save"), ("[Esc]", " Cancel")];
const LATER_KEYS: [(&str, &str); 3] = [
    ("[Enter]", " Save"),
    ("[Tab]", " Back"),
    ("[Esc]", " Cancel"),
];
const FAILED_KEYS: [(&str, &str); 2] = [("[D]", " Details"), ("[Esc]", " Back")];
const BACK_KEYS: [(&str, &str); 1] = [("[Esc]", " Back")];

/// AF-3.
const ADDED_KEYS: [(&str, &str); 3] = [
    ("[Enter]", " Open chat"),
    ("[1]", " Show my invite"),
    ("[A]", " Add another friend"),
];

/// CI.
const PREVIEW: &str = " (Preview, not in this release)";
const ADDRESS_HINT: &str = "Their address on your network, like 192.168.1.30:7420.";
/// An address typed that Raven can't use (CI's E, and MEET's step 3).
pub(super) const ADDRESS_BAD: &str =
    "That isn't an address Raven can use. It looks like 192.168.1.30:7420.";
const GONE: &str = "This friend isn't saved on this computer anymore.";
const SAVE_KEYS: [(&str, &str); 2] = [("[Enter]", " Save"), ("[Esc]", " Back")];
const REMOVE_KEYS: [(&str, &str); 2] = [("[Enter]", " Remove"), ("[Esc]", " Back")];

/// VF's rows that give way, lowest first, when the window is short.
const DROP_BLANK: u8 = 0;
const DROP_INTRO: u8 = 1;
/// The line that offers the old code (words mode).
const DROP_OLD_CODE: u8 = 2;
const DROP_TITLE: u8 = 3;
const DROP_HEADING: u8 = 4;

/// What moves on VF and AF-3 (anim.rs asks): a match standing out, a
/// group's mark drawing in, AF-3's check mark drawing in.
pub(crate) fn moving(app: &App) -> Vec<Moving> {
    let mut moving = Vec::new();
    match app.screen() {
        Screen::Verify(vf) => {
            if let VerifyStep::Matched { at, .. } = vf.step {
                moving.push(Moving::Transition {
                    start: at,
                    frames: 1,
                    length: MATCH_TIME,
                });
            }
            if let (VerifyStep::Comparing(_), Some((_, at))) = (&vf.step, vf.marked) {
                moving.push(Moving::Transition {
                    start: at,
                    frames: 1,
                    length: MARK_TIME,
                });
            }
        }
        Screen::Added(added) if added.verified => moving.push(Moving::Transition {
            start: added.at,
            frames: CHECK_FRAMES,
            length: CHECK_TIME,
        }),
        _ => {}
    }
    moving
}

/// One of VF's rows, and whether it may give way in a short window.
struct Row {
    line: Line<'static>,
    /// When it gives way, lowest first; None: it stays.
    drop: Option<u8>,
    /// The terminal's cursor goes after this many cells of it.
    cursor: Option<u16>,
    /// A row of the keys at the bottom: never cut.
    keys: bool,
}

impl Row {
    fn keep(line: Line<'static>) -> Row {
        Row {
            line,
            drop: None,
            cursor: None,
            keys: false,
        }
    }

    fn blank() -> Row {
        Row {
            drop: Some(DROP_BLANK),
            ..Row::keep(Line::default())
        }
    }

    fn keys(line: Line<'static>) -> Row {
        Row {
            keys: true,
            ..Row::keep(line)
        }
    }
}

/// Draws VF: the header row, then one panel with the title, how to compare,
/// my code and theirs (side by side, or one above the other), what the last
/// check found, and the keys. The cursor sits in the field that takes text.
pub(super) fn render(f: &mut Frame, area: Rect, app: &App, now: Instant) {
    if area.is_empty() {
        return;
    }
    render_header(f, area, app, now, true);
    let Some(view) = app.verify_view() else {
        return;
    };
    let body = wizard::under_header(area);
    let block = overlays::overlay_block(app.look());
    let room = block.inner(body);
    let columns = area.width >= COLUMNS_FROM;
    let rows = fit(
        verify_rows(app, &view, room.width, columns, now),
        usize::from(room.height),
    );
    // As wide as the window, as tall as the rows, centred.
    let height = u16::try_from(rows.len())
        .unwrap_or(u16::MAX)
        .saturating_add(2);
    let rect = overlays::centered(body, body.width, height);
    let inner = block.inner(rect);
    let cursor = rows
        .iter()
        .enumerate()
        .find_map(|(y, row)| Some((y, row.cursor?)));
    let lines: Vec<Line<'static>> = rows.into_iter().map(|row| row.line).collect();
    f.render_widget(Paragraph::new(lines).block(block), rect);
    if let Some((y, x)) = cursor {
        let y = u16::try_from(y).unwrap_or(u16::MAX);
        if app.overlays().is_empty() && y < inner.height {
            let x = inner.x + x.min(inner.width.saturating_sub(1));
            f.set_cursor_position(Position::new(x, inner.y + y));
        }
    }
}

/// CI's Security row (P6.31): how many security problems the last 7 days
/// counted about the friend (as a contact, a mailbox or a depositor), with
/// the key to compare words again (or to verify); and that sending to them
/// is paused. Nothing while neither is so.
fn page_security_rows(
    app: &App,
    friend: &ContactView,
    name: &str,
    width: u16,
) -> Vec<Line<'static>> {
    let t = &app.look().theme;
    let mut lines = Vec::new();
    let n = app.problems_this_week(&friend.pub_hex);
    if n > 0 {
        let what = if n == 1 { "problem" } else { "problems" };
        let again = if friend.pinned {
            "[V] Compare words again"
        } else {
            "[V] Verify"
        };
        lines.extend(add_friend::styled_rows(
            &format!("Security: {n} {what} in the last 7 days. {again}"),
            width,
            t.warn,
        ));
    }
    if app.paused(&friend.pub_hex) {
        lines.extend(add_friend::styled_rows(
            &format!("Sending to {name} is paused: Raven sends them nothing until you resume it."),
            width,
            t.warn,
        ));
    }
    lines
}

/// Takes rows out until `rows` fit in `room`: the lowest rank first (the
/// lowest on the screen of a rank first), then the text right above the
/// keys. The keys stay.
fn fit(mut rows: Vec<Row>, room: usize) -> Vec<Row> {
    while rows.len() > room {
        let lowest = rows
            .iter()
            .enumerate()
            .filter_map(|(i, row)| row.drop.map(|rank| (rank, Reverse(i))))
            .min()
            .map(|(_, Reverse(i))| i);
        match lowest.or_else(|| rows.iter().rposition(|row| !row.keys)) {
            Some(i) => {
                rows.remove(i);
            }
            None => {
                rows.truncate(room);
                break;
            }
        }
    }
    rows
}

/// All of VF's rows at `width` cells.
fn verify_rows(app: &App, view: &VerifyView, width: u16, columns: bool, now: Instant) -> Vec<Row> {
    let look = app.look();
    let name = &view.name;
    let mut rows = vec![
        Row {
            drop: Some(DROP_TITLE),
            ..Row::keep(Line::styled(
                format!("Check it's really {name}"),
                look.theme.accent,
            ))
        },
        Row::blank(),
    ];
    let intro = match view.state.entry.mode {
        EntryMode::Words => format!(
            "Call {name} or meet in person. Each of you reads all 10 of your words to the \
             other."
        ),
        EntryMode::Code => {
            format!("Call {name} or meet in person. Each of you reads your own code to the other.")
        }
    };
    rows.extend(text_rows(&intro, width, Style::default(), Some(DROP_INTRO)));
    rows.push(Row::blank());
    if let VerifyStep::Failed(failure) = &view.state.step {
        rows.extend(
            failure_rows(look, failure, width)
                .into_iter()
                .map(Row::keep),
        );
    } else {
        let column = if columns {
            width.saturating_sub(GAP) / 2
        } else {
            width
        };
        let (mine_heading, mine) = mine_rows(look, view, column, now);
        let (theirs_heading, theirs) = theirs_rows(look, view, column, now);
        if columns {
            // The columns' bodies start on the same row.
            rows.extend(side_by_side(mine_heading, theirs_heading, column));
            rows.push(Row::blank());
            rows.extend(side_by_side(mine, theirs, column));
        } else {
            rows.extend(mine_heading);
            rows.extend(mine);
            rows.push(Row::blank());
            rows.extend(theirs_heading);
            rows.extend(theirs);
        }
        let said = said_rows(look, view, width);
        if !said.is_empty() {
            rows.push(Row::blank());
            rows.extend(said);
        }
    }
    let words = view.state.entry.mode == EntryMode::Words;
    // Tab picks a word while one is being typed, else it is Later.
    let picks = words && !view.state.entry.current.is_empty();
    let keys: &[(&'static str, &'static str)] = match &view.state.step {
        VerifyStep::Comparing(_) if view.state.stopped() && view.new => &STOPPED_KEYS,
        VerifyStep::Comparing(_) if view.state.stopped() => &STOPPED_SAVED_KEYS,
        VerifyStep::Comparing(_) if picks => &PICK_KEYS,
        VerifyStep::Comparing(_) if view.new => &COMPARE_KEYS,
        VerifyStep::Comparing(_) => &SAVED_COMPARE_KEYS,
        VerifyStep::Matched { .. } => &CONFIRM_KEYS,
        VerifyStep::Later(_) => &LATER_KEYS,
        VerifyStep::Saving { .. } => &[],
        VerifyStep::Failed(_) => &FAILED_KEYS,
        VerifyStep::AlreadyVerified if words => &WORDS_VERIFIED_KEYS,
        VerifyStep::AlreadyVerified => &VERIFIED_KEYS,
        VerifyStep::OlderMethod { .. } => &OLDER_KEYS,
    };
    if !keys.is_empty() {
        rows.push(Row::blank());
        rows.extend(
            key_rows(look, keys, "   ", width)
                .into_iter()
                .map(Row::keys),
        );
    }
    rows
}

/// The left column, its heading and its body: my words, numbered, read to
/// the friend; or my code, its groups in bold (the one being spelled
/// marked), and how to say that group.
fn mine_rows(look: &Look, view: &VerifyView, width: u16, now: Instant) -> (Vec<Row>, Vec<Row>) {
    if view.state.entry.mode == EntryMode::Words {
        let heading = text_rows(
            &format!("Your words: read these to {}", view.name),
            width,
            Style::default().add_modifier(Modifier::BOLD),
            Some(DROP_HEADING),
        );
        let rows = wizard::word_rows(look, &view.mine_words, width, WORDS)
            .into_iter()
            .map(Row::keep)
            .collect();
        return (heading, rows);
    }
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let lit = lit(view, look, now);
    let heading = text_rows(
        &format!("Your code: read this to {}", view.name),
        width,
        bold,
        Some(DROP_HEADING),
    );
    let mut rows = Vec::new();
    let mut spans = Vec::new();
    for (i, group) in view.mine.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        let mut style = bold;
        if i == view.state.helper {
            style = style.patch(look.theme.selected);
        }
        if lit {
            style = style.patch(look.theme.ok);
        }
        spans.push(Span::styled(group.clone(), style));
    }
    rows.push(Row::keep(Line::from(spans)));
    if let Some(group) = view.mine.get(view.state.helper) {
        rows.push(Row::blank());
        rows.extend(text_rows(
            &format!("Say it like: {}", spell(group)),
            width,
            Style::default(),
            None,
        ));
    }
    (heading, rows)
}

/// The right column, its heading and its body: the friend's code. While it
/// is typed, the field with the groups so far and their marks; once it
/// matched, the code itself and the confirmation question; for Later, the
/// question alone. In words mode, [`their_words_rows`].
fn theirs_rows(look: &Look, view: &VerifyView, width: u16, now: Instant) -> (Vec<Row>, Vec<Row>) {
    if view.state.entry.mode == EntryMode::Words {
        return their_words_rows(look, view, width, now);
    }
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let name = &view.name;
    let heading = text_rows(
        &format!("{name}'s code: ask {name} to read it to you"),
        width,
        bold,
        Some(DROP_HEADING),
    );
    let mut rows = Vec::new();
    let theirs = view.theirs.as_ref().map(|groups| groups.join("  "));
    let matches = |style: Style| {
        Row::keep(Line::from(vec![
            Span::styled("It matches: ", style),
            Span::styled(theirs.clone().unwrap_or_default(), style.patch(bold)),
        ]))
    };
    match &view.state.step {
        VerifyStep::Comparing(_) => {
            rows.extend(text_rows(
                &format!("Type {name}'s code as they read it:"),
                width,
                Style::default(),
                None,
            ));
            rows.push(code_field(look, view, now));
        }
        VerifyStep::Matched { confirm, .. } => {
            let style = if lit(view, look, now) {
                look.theme.ok.add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            rows.push(matches(style));
            rows.push(Row::blank());
            rows.extend(question_rows(
                &format!("To save {name} as verified, type {}:", confirm.code),
                &confirm.typed,
                width,
            ));
        }
        VerifyStep::Later(confirm) => rows.extend(question_rows(
            &format!(
                "Save {name} without verifying? You can verify later from {name}'s page. Type {} \
                 to confirm:",
                confirm.code
            ),
            &confirm.typed,
            width,
        )),
        VerifyStep::Saving { verified: true } => rows.push(matches(Style::default())),
        VerifyStep::AlreadyVerified => {
            rows.push(Row::keep(Line::styled(
                format!("Already verified {}", look.glyphs.tick_sent),
                look.theme.ok,
            )));
            rows.push(Row::keep(Line::styled(theirs.unwrap_or_default(), bold)));
        }
        VerifyStep::OlderMethod { typed } => {
            rows.push(matches(Style::default()));
            rows.push(Row::blank());
            rows.extend(older_method_rows(view, typed, width));
        }
        VerifyStep::Saving { verified: false } | VerifyStep::Failed(_) => {}
    }
    (heading, rows)
}

/// The older-method question after "Check again" matched (design A R9,
/// security_text.rs's words): why it is asked, and 'accept' typed.
fn older_method_rows(view: &VerifyView, typed: &str, width: u16) -> Vec<Row> {
    let name = &view.name;
    let mut rows = text_rows(&bridge::floor_intro(name), width, Style::default(), None);
    rows.push(Row::blank());
    rows.extend(question_rows(&bridge::floor_question(name), typed, width));
    rows
}

/// The right column in words mode, its heading and its body. While the
/// words are typed: the chips, the field ('Word 4 of 10: tur'), the
/// suggestion and the offer of the old code. Once they matched: 'They
/// match', their words, and the confirmation question; for Later, the
/// question alone.
fn their_words_rows(
    look: &Look,
    view: &VerifyView,
    width: u16,
    now: Instant,
) -> (Vec<Row>, Vec<Row>) {
    let name = &view.name;
    let heading = text_rows(
        &format!("{name}'s words: type what {name} reads"),
        width,
        Style::default().add_modifier(Modifier::BOLD),
        Some(DROP_HEADING),
    );
    let theirs = |rows: &mut Vec<Row>| {
        let words = view.theirs_words.clone().unwrap_or_default();
        rows.extend(
            wizard::word_rows(look, &words, width, words.len())
                .into_iter()
                .map(Row::keep),
        );
    };
    let mut rows = Vec::new();
    match &view.state.step {
        VerifyStep::Comparing(_) => {
            rows.extend(chip_rows(look, &view.chips, width));
            rows.push(words_field(view, width));
            // Once VF has stopped, Tab is Later: nothing to pick.
            if let Some(row) = suggestion_row(look, view, width).filter(|_| !view.state.stopped()) {
                rows.push(row);
            }
            if !view.state.stopped() {
                rows.extend(text_rows(
                    OLD_CODE,
                    width,
                    look.theme.secondary,
                    Some(DROP_OLD_CODE),
                ));
            }
        }
        VerifyStep::Matched { confirm, .. } => {
            let style = if lit(view, look, now) {
                look.theme.ok.add_modifier(Modifier::BOLD)
            } else {
                look.theme.ok
            };
            rows.push(Row::keep(Line::styled(
                format!("They match {}", look.glyphs.tick_sent),
                style,
            )));
            theirs(&mut rows);
            rows.push(Row::blank());
            rows.extend(question_rows(
                &format!("To save {name} as verified, type {}:", confirm.code),
                &confirm.typed,
                width,
            ));
        }
        VerifyStep::Later(confirm) => rows.extend(question_rows(
            &format!(
                "Save {name} without verifying? You can verify later from {name}'s page. Type {} \
                 to confirm:",
                confirm.code
            ),
            &confirm.typed,
            width,
        )),
        VerifyStep::Saving { verified: true } => {
            rows.push(Row::keep(Line::styled(
                format!("They match {}", look.glyphs.tick_sent),
                look.theme.ok,
            )));
            theirs(&mut rows);
        }
        VerifyStep::AlreadyVerified => {
            rows.push(Row::keep(Line::styled(
                format!("Already verified {}", look.glyphs.tick_sent),
                look.theme.ok,
            )));
            theirs(&mut rows);
        }
        VerifyStep::OlderMethod { typed } => {
            rows.push(Row::keep(Line::styled(
                format!("They match {}", look.glyphs.tick_sent),
                look.theme.ok,
            )));
            theirs(&mut rows);
            rows.push(Row::blank());
            rows.extend(older_method_rows(view, typed, width));
        }
        VerifyStep::Saving { verified: false } | VerifyStep::Failed(_) => {}
    }
    (heading, rows)
}

/// The words typed so far as numbered chips, '1 turtle *  2 frog *', on as
/// many rows of `width` cells as they take; a chip is never split. The dot
/// says "a Raven word", never that it is the friend's.
fn chip_rows(look: &Look, chips: &[&str], width: u16) -> Vec<Row> {
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let mut rows: Vec<Vec<Span<'static>>> = Vec::new();
    let mut used = 0;
    for (i, word) in chips.iter().enumerate() {
        let number = (i + 1).to_string();
        let dot = look.glyphs.dot_recent;
        let wide = cells(&number) + 1 + cells(word) + 1 + cells(dot);
        match rows.last_mut() {
            Some(row) if used + 2 + wide <= usize::from(width) => {
                row.push(Span::raw("  "));
                used += 2;
            }
            _ => {
                rows.push(Vec::new());
                used = 0;
            }
        }
        if let Some(row) = rows.last_mut() {
            row.extend([
                Span::styled(number, look.theme.secondary),
                Span::raw(" "),
                Span::styled((*word).to_owned(), bold),
                Span::raw(" "),
                Span::styled(dot, look.theme.secondary),
            ]);
        }
        used += wide;
    }
    rows.into_iter()
        .map(|spans| Row::keep(Line::from(spans)))
        .collect()
}

/// The words field: 'Word 4 of 10: ' and the word being typed, the cursor
/// after it.
fn words_field(view: &VerifyView, width: u16) -> Row {
    let next = view.chips.len() + 1;
    let label = if next <= WORDS {
        format!("Word {next} of {WORDS}: ")
    } else {
        format!("Word {next}: ")
    };
    let room = width.saturating_sub(u16::try_from(cells(&label)).unwrap_or(u16::MAX));
    // Only a-z and spaces are kept: shaped all the same.
    let typed = display::one_line(view.state.entry.current.trim_end(), room, "");
    let col = u16::try_from(cells(&label) + cells(&typed)).unwrap_or(u16::MAX);
    Row {
        cursor: Some(col),
        ..Row::keep(Line::from(vec![Span::raw(label), Span::raw(typed)]))
    }
}

/// Under the field: the Raven word the one being typed stands for
/// ('-> turtle   [Tab] pick'), the words it can still become (from the
/// whole list), or that it is not a Raven word. None while nothing is typed
/// after the chips.
fn suggestion_row(look: &Look, view: &VerifyView, width: u16) -> Option<Row> {
    let current = &view.state.entry.current;
    if current.is_empty() || current.contains(' ') {
        return None;
    }
    let arrow = format!("{} ", look.glyphs.arrow);
    let line = match view.suggestions[..] {
        [] => Line::styled("Not one of Raven's words", look.theme.warn),
        [word] => Line::from(vec![
            Span::styled(arrow, look.theme.secondary),
            Span::styled(word, Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("   "),
            widgets::key(look, "[Tab]"),
            widgets::key_words(look, " pick"),
        ]),
        ref several => {
            let mut text = arrow;
            let room = usize::from(width).saturating_sub(cells(look.glyphs.ellipsis) + 2);
            for (i, word) in several.iter().enumerate() {
                let sep = if i == 0 { "" } else { "  " };
                if cells(&text) + cells(sep) + cells(word) > room {
                    text.push_str("  ");
                    text.push_str(look.glyphs.ellipsis);
                    break;
                }
                text.push_str(sep);
                text.push_str(word);
            }
            Line::styled(text, look.theme.secondary)
        }
    };
    Some(Row::keep(line))
}

/// The field the friend's code is typed into: '> ', then each group typed
/// so far (letters and digits only, as the App keeps them) with its mark
/// once complete. The cursor goes after the last letter, or where the next
/// group starts.
fn code_field(look: &Look, view: &VerifyView, now: Instant) -> Row {
    let mut spans = vec![Span::raw("> ")];
    for (i, (group, mark)) in view.typed.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::raw(group.clone()));
        if let Some(right) = mark {
            let drawing_in = view.state.marked.is_some_and(|(at_group, at)| {
                at_group == i && anim::transition_frame(at, now, 1, MARK_TIME, look.motion) == 0
            });
            let (glyph, style) = if *right {
                (look.glyphs.tick_sent, look.theme.ok)
            } else {
                (look.glyphs.tick_failed, look.theme.bad)
            };
            let style = if drawing_in {
                look.theme.secondary
            } else {
                style
            };
            spans.push(Span::raw(" "));
            spans.push(Span::styled(glyph, style));
        }
    }
    if view.typed.last().is_some_and(|(_, mark)| mark.is_some()) {
        spans.push(Span::raw("  "));
    }
    let line = Line::from(spans);
    let col = u16::try_from(line.width()).unwrap_or(u16::MAX);
    Row {
        cursor: Some(col),
        ..Row::keep(line)
    }
}

/// A confirmation question, then its field ('> ' and what is typed), the
/// cursor after it.
fn question_rows(question: &str, typed: &str, width: u16) -> Vec<Row> {
    let mut rows = text_rows(question, width, Style::default(), None);
    let field = format!(
        "> {}",
        display::one_line(typed, width.saturating_sub(2), "")
    );
    let col = u16::try_from(cells(&field)).unwrap_or(u16::MAX);
    rows.push(Row {
        cursor: Some(col),
        ..Row::keep(Line::raw(field))
    });
    rows
}

/// What the last check found, under both columns: the keyboard hint, why
/// typed words are not 10 valid ones, the case hint, the mismatch, a wrong
/// confirmation code; that VF has stopped; or that the save runs. None of
/// it holds the friend's words or code.
fn said_rows(look: &Look, view: &VerifyView, width: u16) -> Vec<Row> {
    let name = &view.name;
    let words = view.state.entry.mode == EntryMode::Words;
    let text = match &view.state.step {
        VerifyStep::Comparing(Some(CodeProblem::Keyboard)) if words => WORDS_KEYBOARD.to_owned(),
        VerifyStep::Comparing(Some(CodeProblem::Keyboard)) => LATIN_KEYBOARD.to_owned(),
        VerifyStep::Comparing(Some(CodeProblem::Words(why))) => words_said(view, *why),
        VerifyStep::Comparing(Some(CodeProblem::CaseOnly)) => CASE_ONLY.to_owned(),
        VerifyStep::Comparing(Some(CodeProblem::Mismatch)) if words && view.new => format!(
            "These are real Raven words, but not {name}'s. Do not verify: someone may have \
             swapped {name}'s key, or this is the wrong invite. Nothing was saved."
        ),
        // Saved already: no invite to check.
        VerifyStep::Comparing(Some(CodeProblem::Mismatch)) if words => format!(
            "These are real Raven words, but not {name}'s. Do not verify: someone may have \
             swapped {name}'s key. Nothing was saved."
        ),
        VerifyStep::Comparing(Some(CodeProblem::Mismatch)) if view.new => format!(
            "That doesn't match. Do not verify: someone may have swapped {name}'s key. Check you \
             pasted the right invite, or save {name} as not verified."
        ),
        // Saved already: no invite to check, and nothing to save.
        VerifyStep::Comparing(Some(CodeProblem::Mismatch)) => {
            format!("That doesn't match. Do not verify: someone may have swapped {name}'s key.")
        }
        VerifyStep::Matched { confirm, .. } | VerifyStep::Later(confirm) if confirm.keyboard => {
            LATIN_KEYBOARD.to_owned()
        }
        VerifyStep::Matched { confirm, .. } | VerifyStep::Later(confirm) if confirm.wrong => {
            WRONG_CODE.to_owned()
        }
        VerifyStep::Saving { .. } => {
            return text_rows(
                &format!("Saving{}", look.glyphs.ellipsis),
                width,
                Style::default(),
                None,
            )
        }
        _ => String::new(),
    };
    let mut rows = text_rows(&text, width, look.theme.warn, None);
    if text.is_empty() {
        rows.clear();
    }
    if matches!(view.state.step, VerifyStep::Comparing(_)) && view.state.stopped() {
        let stop = if view.new {
            format!(
                "Stop here. Check with {name} another way (in person), or save {name} as not \
                 verified."
            )
        } else {
            format!("Stop here. Check with {name} another way (in person).")
        };
        rows.extend(text_rows(&stop, width, look.theme.bad, None));
    }
    rows
}

/// Why the words typed are not 10 valid ones: it depends only on what was
/// typed, so it may say which word.
fn words_said(view: &VerifyView, why: ParseError) -> String {
    let name = &view.name;
    match why {
        ParseError::Empty => format!("Type the {WORDS} words {name} reads."),
        ParseError::Unknown { position } => {
            // The chips are Raven words: the word is one typed after them.
            let word = view
                .state
                .entry
                .current
                .split_whitespace()
                .nth(position.saturating_sub(view.chips.len() + 1))
                .unwrap_or_default();
            format!(
                "'{}' isn't one of Raven's words. Type the first 3 letters and pick one.",
                display::one_line(word, 24, "")
            )
        }
        ParseError::NonLatin { .. } => WORDS_KEYBOARD.to_owned(),
        ParseError::Ambiguous { position } => {
            format!("Type at least 3 letters of word {position}.")
        }
        ParseError::WrongCount { count } if count < WORDS => format!(
            "You typed {count} {}. A set has {WORDS}: ask {name} which one you missed.",
            if count == 1 { "word" } else { "words" }
        ),
        ParseError::WrongCount { count } => {
            format!("You typed {count} words. A set has {WORDS}: ask {name} to read them again.")
        }
        ParseError::BadCheck => format!(
            "These {WORDS} words don't fit together: one may be misheard, or two swapped. Ask \
             {name} to read them again, slowly."
        ),
    }
}

/// A save that failed: why, what to do, and with D its technical text.
fn failure_rows(look: &Look, failure: &Failure, width: u16) -> Vec<Line<'static>> {
    let mut lines = add_friend::styled_rows(&failure.plain.headline, width, look.theme.warn);
    if !failure.plain.next.is_empty() {
        lines.extend(wizard::rows(&failure.plain.next, width));
    }
    if failure.details {
        lines.extend(wizard::details(look, &failure.plain.technical, width));
    }
    lines
}

/// The columns' rows side by side, the right one starting [`GAP`] cells
/// after the left one's `column` cells. A row is blank (and goes first)
/// only where both are; it gives way only where both of its halves may.
fn side_by_side(left: Vec<Row>, right: Vec<Row>, column: u16) -> Vec<Row> {
    let rows = left.len().max(right.len());
    let (mut left, mut right) = (left.into_iter(), right.into_iter());
    let start = column + GAP;
    (0..rows)
        .map(|_| {
            let halves = [left.next(), right.next()];
            let mut spans = Vec::new();
            let mut ranks = Vec::new();
            let mut cursor = None;
            for (i, half) in halves.iter().enumerate() {
                let Some(half) = half else {
                    continue;
                };
                if i == 1 {
                    let pad = usize::from(start).saturating_sub(Line::from(spans.clone()).width());
                    spans.push(Span::raw(" ".repeat(pad)));
                    cursor = cursor.or(half.cursor.map(|col| start + col));
                } else {
                    cursor = half.cursor;
                }
                if half.line.width() > 0 {
                    ranks.push(half.drop);
                }
                let style = half.line.style;
                spans.extend(
                    half.line
                        .spans
                        .iter()
                        .map(|span| Span::styled(span.content.clone(), style.patch(span.style))),
                );
            }
            let drop = if ranks.is_empty() {
                Some(DROP_BLANK)
            } else {
                ranks
                    .into_iter()
                    .try_fold(0, |most, rank| Some(most.max(rank?)))
            };
            Row {
                line: Line::from(spans),
                drop,
                cursor,
                keys: false,
            }
        })
        .collect()
}

/// While a match stands out: both columns' codes.
fn lit(view: &VerifyView, look: &Look, now: Instant) -> bool {
    match view.state.step {
        VerifyStep::Matched { at, .. } => {
            anim::transition_frame(at, now, 1, MATCH_TIME, look.motion) == 0
        }
        _ => false,
    }
}

/// How to read a group out loud: 'capital W, small u, digit 4'.
fn spell(group: &str) -> String {
    group
        .chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                format!("capital {c}")
            } else if c.is_ascii_lowercase() {
                format!("small {c}")
            } else if c.is_ascii_digit() {
                format!("digit {c}")
            } else {
                c.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The app's copy in rows of `width` cells, each giving way at `drop`.
fn text_rows(text: &str, width: u16, style: Style, drop: Option<u8>) -> Vec<Row> {
    wrap(text, width, 0)
        .into_iter()
        .map(|row| Row {
            drop,
            ..Row::keep(Line::styled(row, style))
        })
        .collect()
}

/// A card's keys, `gap` between them, on as many rows of `width` cells as
/// they take: a key and its words are never parted.
pub(super) fn key_rows(
    look: &Look,
    keys: &[(&str, &str)],
    gap: &'static str,
    width: u16,
) -> Vec<Line<'static>> {
    let mut rows: Vec<Vec<Span<'static>>> = Vec::new();
    let mut used = 0;
    for (key, words) in keys {
        let (key, words) = (widgets::key(look, key), widgets::key_words(look, words));
        let wide = key.width() + words.width();
        match rows.last_mut() {
            Some(row) if used + cells(gap) + wide <= usize::from(width) => {
                row.push(Span::raw(gap));
                used += cells(gap);
            }
            _ => {
                rows.push(Vec::new());
                used = 0;
            }
        }
        if let Some(row) = rows.last_mut() {
            row.push(key);
            row.push(words);
        }
        used += wide;
    }
    rows.into_iter().map(Line::from).collect()
}

/// Draws AF-3: who is added, verified (the check mark drawing in) or not,
/// that they must add the user too, and the keys.
pub(super) fn render_added(f: &mut Frame, area: Rect, app: &App, added: &AddedState, now: Instant) {
    if area.is_empty() {
        return;
    }
    render_header(f, area, app, now, true);
    let body = wizard::under_header(area);
    let look = app.look();
    let width = wizard::text_width(body);
    let name = display::one_line(&added.name, home::NAME_CELLS, look.glyphs.ellipsis);
    let heading = if added.verified {
        let tick = look.glyphs.tick_sent;
        let check =
            match anim::transition_frame(added.at, now, CHECK_FRAMES, CHECK_TIME, look.motion) {
                0 => Span::raw(" ".repeat(cells(tick))),
                1 => Span::styled(tick, look.theme.secondary),
                _ => Span::styled(tick, look.theme.ok),
            };
        Line::from(vec![
            Span::styled(format!("{name} is added "), look.theme.accent),
            check,
            Span::styled(" Verified", look.theme.ok),
        ])
    } else {
        Line::styled(
            format!("{name} is added (not verified yet)"),
            look.theme.accent,
        )
    };
    let mut lines = vec![heading, Line::default()];
    lines.extend(wizard::rows(
        &format!(
            "{name} needs to add you too, or your messages will be refused. If you haven't yet, \
             send {name} your invite (press 1)."
        ),
        width,
    ));
    lines.push(Line::default());
    lines.extend(key_rows(look, &ADDED_KEYS, "   ", width));
    wizard::draw_card(f, body, look, None, lines, body.height);
}

/// Draws CI: the friend's name, their security code only once verified, their
/// address and routes (Internet and p2p labelled Preview while their
/// carriers are off), whether they are blocked, how the last change went,
/// and the keys, or the one field that is open with its own.
pub(super) fn render_page(f: &mut Frame, area: Rect, app: &App, page: &PageState, now: Instant) {
    if area.is_empty() {
        return;
    }
    render_header(f, area, app, now, true);
    let body = wizard::under_header(area);
    let look = app.look();
    let width = wizard::text_width(body);
    let Some(friend) = app.friend(&page.pub_hex) else {
        let lines = vec![
            Line::raw(GONE),
            Line::default(),
            overlays::keys_line(look, &BACK_KEYS),
        ];
        wizard::draw_card(f, body, look, None, lines, body.height);
        return;
    };
    let (g, t) = (&look.glyphs, &look.theme);
    let name = app.shown_name(&friend.pub_hex);
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let mut lines = vec![Line::styled(name.clone(), t.accent), Line::default()];
    match app.verified_words(&friend.pub_hex) {
        Some(words) => {
            lines.extend(verified_words_rows(look, &words.join(" "), width));
            lines.push(Line::from(vec![
                Span::styled("Old-style code: ", t.secondary),
                Span::styled(wizard::code_groups(&friend.fingerprint).join("  "), bold),
            ]));
        }
        None => lines.extend(add_friend::styled_rows(
            &format!("Security words: hidden until you verify {name} (press V)"),
            width,
            t.warn,
        )),
    }
    lines.push(Line::raw(format!(
        "Raven address: {}",
        add_friend::short(&friend.address, g.ellipsis)
    )));
    lines.push(Line::raw(if friend.lan_dial.is_empty() {
        "Local network: not set".to_owned()
    } else {
        format!(
            "Local network: {}",
            display::one_line(&friend.lan_dial, u16::MAX, "")
        )
    }));
    let preview = |off: bool| if off { PREVIEW } else { "" };
    if !friend.internet_dial.is_empty() {
        lines.extend(wizard::rows(
            &format!(
                "Internet: {}{}",
                display::one_line(&friend.internet_dial, u16::MAX, ""),
                preview(controller::INTERNET_PREVIEW)
            ),
            width,
        ));
    }
    if !friend.p2p.is_empty() {
        lines.extend(wizard::rows(
            &format!(
                "p2p: {}{}",
                add_friend::short(&friend.p2p, g.ellipsis),
                preview(controller::P2P_PREVIEW)
            ),
            width,
        ));
    }
    if friend.blocked {
        lines.extend(add_friend::styled_rows(
            &format!("Blocked: Raven refuses messages from {name}."),
            width,
            t.warn,
        ));
    }
    lines.extend(page_security_rows(app, friend, &name, width));
    if let Some(failure) = &page.failure {
        lines.push(Line::default());
        lines.extend(failure_rows(look, failure, width));
    }
    lines.push(Line::default());
    if page.saving {
        lines.push(Line::raw(format!("Saving{}", g.ellipsis)));
        wizard::draw_card(f, body, look, None, lines, body.height);
        return;
    }
    let (field, col) = match &page.edit {
        None => {
            // The privacy pack's actions (PP.21), once its read answered.
            let delete = format!(" Delete chat with {name}");
            let forget = format!(" Forget {name}'s address");
            let mut keys = vec![
                ("[R]", " Rename"),
                ("[E]", " Edit address"),
                ("[V]", " Verify"),
                ("[X]", " Remove"),
            ];
            if friend.blocked {
                keys.push(("[U]", " Unblock"));
            }
            if app.privacy().is_some() {
                keys.push(("[C]", &delete));
                keys.push(("[F]", &forget));
            }
            // The security notices about them, and pausing sending (P6.31).
            if app.notices_about(&friend.pub_hex).next().is_some() {
                keys.push(("[W]", " Security"));
            }
            if app.paused(&friend.pub_hex) {
                keys.push(("[P]", " Resume sending"));
            } else if app.pause_offered(&friend.pub_hex) {
                keys.push(("[P]", " Pause sending"));
            }
            if page.failure.is_some() {
                keys.push(("[D]", " Details"));
            }
            keys.push(("[Esc]", " Back"));
            lines.extend(key_rows(look, &keys, "  ", width));
            wizard::draw_card(f, body, look, None, lines, body.height);
            return;
        }
        Some(PageEdit::Rename {
            name: typed,
            full,
            problem,
        }) => {
            lines.push(Line::raw(add_friend::NAME_QUESTION));
            let [top, field, bottom] =
                wizard::name_field(look, typed, add_friend::NAME_PLACEHOLDER);
            lines.extend([top, field.clone(), bottom]);
            lines.extend(add_friend::styled_rows(
                add_friend::NAME_LOCAL,
                width,
                t.secondary,
            ));
            if *full {
                lines.push(Line::styled(add_friend::NAME_LIMIT, t.secondary));
            }
            if let Some(said) = add_friend::name_said(app, problem.as_ref(), typed, &friend.pub_hex)
            {
                lines.extend(add_friend::styled_rows(&said, width, t.warn));
            }
            lines.push(Line::default());
            lines.extend(key_rows(look, &SAVE_KEYS, "   ", width));
            // After the field's left border and its space, and the name.
            (field, 2 + display::width(typed))
        }
        Some(PageEdit::Address { text, bad }) => {
            lines.extend(add_friend::styled_rows(ADDRESS_HINT, width, t.secondary));
            let field = Line::raw(format!("> {}", display::one_line(text, u16::MAX, "")));
            lines.push(field.clone());
            if *bad {
                lines.extend(add_friend::styled_rows(ADDRESS_BAD, width, t.warn));
            }
            lines.push(Line::default());
            lines.extend(key_rows(look, &SAVE_KEYS, "   ", width));
            let col = field.width();
            (field, col)
        }
        Some(PageEdit::Remove { typed }) => {
            lines.extend(wizard::rows(
                &format!(
                    "Remove {name}? This deletes their contact and verification on this \
                     computer. Your messages with them stay. Type remove to confirm:"
                ),
                width,
            ));
            let field = Line::raw(format!("> {}", display::one_line(typed, u16::MAX, "")));
            lines.push(field.clone());
            lines.push(Line::default());
            lines.extend(key_rows(look, &REMOVE_KEYS, "   ", width));
            let col = field.width();
            (field, col)
        }
    };
    let (inner, drawn) = wizard::draw_card(f, body, look, None, lines, body.height);
    let Some(row) = drawn.iter().position(|line| *line == field) else {
        return;
    };
    let y = u16::try_from(row).unwrap_or(u16::MAX);
    if y < inner.height && app.overlays().is_empty() {
        let x = u16::try_from(col).unwrap_or(u16::MAX);
        let x = inner.x.saturating_add(x.min(inner.width.saturating_sub(1)));
        f.set_cursor_position(Position::new(x, inner.y + y));
    }
}

/// CI's 'Security words: turtle frog bread …   v Verified', on as many rows
/// of `width` cells as it takes, the words bold; 'Verified' on the last row
/// when it fits there, else on its own.
fn verified_words_rows(look: &Look, words: &str, width: u16) -> Vec<Line<'static>> {
    let (g, t) = (&look.glyphs, &look.theme);
    let bold = Style::default().add_modifier(Modifier::BOLD);
    const LABEL: &str = "Security words:";
    let mut lines: Vec<Line<'static>> = wrap(&format!("{LABEL} {words}"), width, 0)
        .into_iter()
        .enumerate()
        .map(
            |(i, row)| match row.strip_prefix(LABEL).filter(|_| i == 0) {
                Some(rest) => {
                    Line::from(vec![Span::raw(LABEL), Span::styled(rest.to_owned(), bold)])
                }
                None => Line::styled(row, bold),
            },
        )
        .collect();
    let verified = Span::styled(format!("{} Verified", g.tick_sent), t.ok);
    match lines.last_mut() {
        Some(last) if last.width() + 3 + verified.width() <= usize::from(width) => {
            last.spans.push(Span::raw("   "));
            last.spans.push(verified);
        }
        _ => lines.push(Line::from(verified)),
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyCode;

    use theme::{Glyphs, Motion, Theme};

    /// Bob, a friend to add or saved; Alice, saved and not verified.
    const BOB: u8 = 0xB0;
    const ALICE: u8 = 0xA1;

    /// VF for Bob's card from AF-2, `friends` saved, at `size`, in `look`,
    /// taking his old code (Ctrl+O).
    fn vf_new_in(look: Look, size: (u16, u16), friends: Vec<ContactView>) -> App {
        let mut app = vf_words_in(look, size, friends);
        testkit::ctrl(&mut app, 'o');
        app
    }

    /// VF for Bob's card from AF-2, `friends` saved, at `size`, in `look`:
    /// his words.
    fn vf_words_in(look: Look, size: (u16, u16), friends: Vec<ContactView>) -> App {
        let mut app = testkit::home_app_in(look, size, Receive::Off, friends, Conversations::new());
        testkit::press(&mut app, KeyCode::Char('a'));
        testkit::paste(
            &mut app,
            &testkit::card(BOB, "192.168.1.30:7420"),
            PasteVia::Bracketed,
        );
        testkit::tick(&mut app, Duration::from_millis(300));
        testkit::press(&mut app, KeyCode::Enter);
        for c in "Bob".chars() {
            testkit::press(&mut app, KeyCode::Char(c));
        }
        testkit::press(&mut app, KeyCode::Enter);
        assert!(
            matches!(app.screen(), Screen::Verify(_)),
            "{:?}",
            app.screen()
        );
        app
    }

    fn vf_new(size: (u16, u16)) -> App {
        vf_new_in(testkit::simple_mono(), size, Vec::new())
    }

    /// `text` typed key by key.
    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            testkit::press(app, KeyCode::Char(c));
        }
    }

    /// Bob's security code, without its separators.
    fn bob_code() -> String {
        testkit::me(BOB).fingerprint.replace('-', "")
    }

    /// `code` with the case of its first letter turned round.
    fn wrong_case(code: &str) -> String {
        let at = code
            .find(|c: char| c.is_ascii_alphabetic())
            .expect("a letter");
        let mut chars: Vec<char> = code.chars().collect();
        let c = chars[at];
        chars[at] = if c.is_ascii_uppercase() {
            c.to_ascii_lowercase()
        } else {
            c.to_ascii_uppercase()
        };
        chars.into_iter().collect()
    }

    /// The rows drawn once every animation has come to rest.
    fn at_rest(app: &App, width: u16, height: u16) -> Vec<String> {
        testkit::render_at(app, width, height, app.now() + Duration::from_secs(1))
    }

    /// Home with Bob (verified), Alice (not verified, blocked) saved.
    fn home_with_friends(size: (u16, u16)) -> App {
        let bob = testkit::saved_as(BOB, "Bob", true, "192.168.1.30:7420");
        let alice = ContactView {
            blocked: true,
            internet_dial: "203.0.113.9:7420".into(),
            ..testkit::saved_as(ALICE, "Alice", false, "")
        };
        testkit::home_app(size, Receive::Off, vec![bob, alice], Conversations::new())
    }

    #[test]
    fn spells_each_letter_and_digit() {
        assert_eq!(spell("Wu4X"), "capital W, small u, digit 4, capital X");
    }

    /// Bob's security words, as he reads them out.
    fn bob_words() -> Vec<String> {
        testkit::me(BOB).words.to_vec()
    }

    /// VF for Bob's words with `typed` typed key by key, then Enter, at
    /// rest: the words that show.
    fn words_said(typed: &str) -> String {
        let mut app = vf_words_in(testkit::simple_mono(), (80, 24), Vec::new());
        type_text(&mut app, typed);
        testkit::press(&mut app, KeyCode::Enter);
        testkit::screen_text(&at_rest(&app, 80, 24))
    }

    #[test]
    fn vf_words_partial_simple_mono() {
        let mut app = vf_words_in(testkit::simple_mono(), (80, 24), Vec::new());
        let bob = bob_words();
        // Three words, then the first 2 letters of the fourth.
        type_text(&mut app, &format!("{} {} {} ", bob[0], bob[1], bob[2]));
        type_text(&mut app, &bob[3][..2]);
        testkit::assert_rows(
            &at_rest(&app, 80, 24),
            &[
                "R A V E N - Security words                            o Receiving is off  ? Help",
                "                                                                                ",
                "┌──────────────────────────────────────────────────────────────────────────────┐",
                "│ Check it's really Bob                                                        │",
                "│                                                                              │",
                "│ Call Bob or meet in person. Each of you reads all 10 of your words to the    │",
                "│ other.                                                                       │",
                "│                                                                              │",
                "│ Your words: read these to Bob           Bob's words: type what Bob reads     │",
                "│                                                                              │",
                "│  1 song                                 1 orange *  2 soap *  3 swan *       │",
                "│  2 moon                                 Word 4 of 10: gl                     │",
                "│  3 plum                                 -> glove  glue                       │",
                "│  4 curtain                              [Ctrl+O] Use the old code instead    │",
                "│  5 peanut                               (for a friend with an older Raven)   │",
                "│  6 giraffe                                                                   │",
                "│  7 lime                                                                      │",
                "│  8 thread                                                                    │",
                "│  9 sweater                                                                   │",
                "│ 10 moon                                                                      │",
                "│                                                                              │",
                "│ [Enter] Check   [Tab] Pick word   [Esc] Cancel                               │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "                                                                                ",
            ],
        );
    }

    #[test]
    fn vf_words_suggest_one_word_at_the_smallest_size() {
        let mut app = vf_words_in(testkit::simple_mono(), (60, 16), Vec::new());
        let bob = bob_words();
        type_text(&mut app, &format!("{} {} ", bob[0], bob[1]));
        type_text(&mut app, &bob[2][..3]);
        testkit::assert_rows(
            &at_rest(&app, 60, 16),
            &[
                "R A V E N - Security words        o Receiving is off  ? Help",
                "┌──────────────────────────────────────────────────────────┐",
                "│ Check it's really Bob                                    │",
                "│ Call Bob or meet in person. Each of you reads all 10 of  │",
                "│ your words to the other.                                 │",
                "│ Your words: read these to Bob                            │",
                "│   1 song      2 moon   3 plum     4 curtain    5 peanut  │",
                "│   6 giraffe   7 lime   8 thread   9 sweater   10 moon    │",
                "│ Bob's words: type what Bob reads                         │",
                "│ 1 orange *  2 soap *                                     │",
                "│ Word 3 of 10: swa                                        │",
                "│ -> swan   [Tab] pick                                     │",
                "│ [Ctrl+O] Use the old code instead (for a friend with an  │",
                "│ older Raven)                                             │",
                "│ [Enter] Check   [Tab] Pick word   [Esc] Cancel           │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
    }

    #[test]
    fn vf_words_match_shows_both_lists_and_asks_for_the_confirmation_code() {
        let mut app = vf_words_in(testkit::simple_mono(), (80, 24), Vec::new());
        type_text(&mut app, &bob_words().join(" "));
        testkit::press(&mut app, KeyCode::Enter);
        let code = app.verify_code_for_tests().expect("a code").to_owned();
        let rows = at_rest(&app, 80, 24);
        let text = testkit::screen_text(&rows);
        assert!(text.contains("They match v"), "{text}");
        testkit::assert_rows(
            &rows
                .iter()
                .map(|row| row.replace(&code, "K7Q3M"))
                .collect::<Vec<_>>(),
            &[
                "R A V E N - Security words                            o Receiving is off  ? Help",
                "┌──────────────────────────────────────────────────────────────────────────────┐",
                "│ Check it's really Bob                                                        │",
                "│                                                                              │",
                "│ Call Bob or meet in person. Each of you reads all 10 of your words to the    │",
                "│ other.                                                                       │",
                "│                                                                              │",
                "│ Your words: read these to Bob           Bob's words: type what Bob reads     │",
                "│                                                                              │",
                "│  1 song                                 They match v                         │",
                "│  2 moon                                  1 orange                            │",
                "│  3 plum                                  2 soap                              │",
                "│  4 curtain                               3 swan                              │",
                "│  5 peanut                                4 glove                             │",
                "│  6 giraffe                               5 hammer                            │",
                "│  7 lime                                  6 eagle                             │",
                "│  8 thread                                7 milk                              │",
                "│  9 sweater                               8 beetle                            │",
                "│ 10 moon                                  9 train                             │",
                "│                                         10 lime                              │",
                "│                                         To save Bob as verified, type K7Q3M: │",
                "│                                         >                                    │",
                "│ [Enter] Save   [Esc] Cancel                                                  │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
            ],
        );
    }

    #[test]
    fn vf_words_stop_after_three_that_are_not_bobs() {
        let mut app = vf_words_in(testkit::simple_mono(), (80, 24), Vec::new());
        let carol = testkit::me(0xC0).words.join(" ");
        for _ in 0..3 {
            type_text(&mut app, &carol);
            testkit::press(&mut app, KeyCode::Enter);
            // Backspace takes a letter, then a whole word.
            for _ in 0..20 {
                testkit::press(&mut app, KeyCode::Backspace);
            }
        }
        type_text(&mut app, &carol);
        let rows = at_rest(&app, 80, 24);
        let text = testkit::screen_text(&rows);
        assert!(!text.contains("[Enter]"), "{text}");
        testkit::assert_rows(
            &rows,
            &[
                "R A V E N - Security words                            o Receiving is off  ? Help",
                "┌──────────────────────────────────────────────────────────────────────────────┐",
                "│ Check it's really Bob                                                        │",
                "│                                                                              │",
                "│ Call Bob or meet in person. Each of you reads all 10 of your words to the    │",
                "│ other.                                                                       │",
                "│                                                                              │",
                "│ Your words: read these to Bob           Bob's words: type what Bob reads     │",
                "│                                                                              │",
                "│  1 song                                 1 ferret *  2 saw *  3 ring *        │",
                "│  2 moon                                 4 parrot *  5 lion *  6 puppy *      │",
                "│  3 plum                                 7 koala *  8 shoe *  9 wolf *        │",
                "│  4 curtain                              Word 10 of 10: candle                │",
                "│  5 peanut                                                                    │",
                "│  6 giraffe                                                                   │",
                "│  7 lime                                                                      │",
                "│  8 thread                                                                    │",
                "│  9 sweater                                                                   │",
                "│ 10 moon                                                                      │",
                "│                                                                              │",
                "│ Stop here. Check with Bob another way (in person), or save Bob as not        │",
                "│ verified.                                                                    │",
                "│ [Tab] Later (not verified)   [Esc] Cancel                                    │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
            ],
        );
    }

    #[test]
    fn every_words_status_has_its_copy() {
        let bob = bob_words();
        let swapped = format!("{} {} {}", bob[1], bob[0], bob[2..].join(" "));
        let eleven = format!("{} {}", bob.join(" "), bob[0]);
        let carol = testkit::me(0xC0).words.join(" ");
        let first = testkit::on_persian_keyboard("t");
        for (typed, said) in [
            (
                "zzz ",
                "'zzz' isn't one of Raven's words. Type the first 3 letters and pick one.",
            ),
            ("s", "Type at least 3 letters of word 1."),
            (
                &bob[..3].join(" "),
                "You typed 3 words. A set has 10: ask Bob which one you missed.",
            ),
            (
                &bob[..9].join(" "),
                "You typed 9 words. A set has 10: ask Bob which one you missed.",
            ),
            (
                &eleven,
                "You typed 11 words. A set has 10: ask Bob to read them again.",
            ),
            (
                &swapped,
                "These 10 words don't fit together: one may be misheard, or two swapped. Ask Bob \
                 to read them again, slowly.",
            ),
            (
                &carol,
                "These are real Raven words, but not Bob's. Do not verify: someone may have \
                 swapped Bob's key, or this is the wrong invite. Nothing was saved.",
            ),
            (&first, "Type the words with English letters."),
        ] {
            let text = words_said(typed);
            assert!(text.contains(said), "{typed:?}: {said}\n{text}");
            assert!(!text.contains("They match"), "{typed:?}: {text}");
        }
        // Bob's own words, then Enter: they match.
        assert!(words_said(&bob.join(" ")).contains("They match v"));
    }

    #[test]
    fn vf_words_already_verified() {
        let mut app = testkit::home_app(
            (80, 24),
            Receive::Off,
            vec![testkit::saved_as(BOB, "Bob", true, "192.168.1.30:7420")],
            Conversations::new(),
        );
        testkit::press(&mut app, KeyCode::Char('v'));
        testkit::assert_rows(
            &at_rest(&app, 80, 24),
            &[
                "R A V E N - Security words                            o Receiving is off  ? Help",
                "┌──────────────────────────────────────────────────────────────────────────────┐",
                "│ Check it's really Bob                                                        │",
                "│                                                                              │",
                "│ Call Bob or meet in person. Each of you reads all 10 of your words to the    │",
                "│ other.                                                                       │",
                "│                                                                              │",
                "│ Your words: read these to Bob           Bob's words: type what Bob reads     │",
                "│                                                                              │",
                "│  1 song                                 Already verified v                   │",
                "│  2 moon                                  1 orange                            │",
                "│  3 plum                                  2 soap                              │",
                "│  4 curtain                               3 swan                              │",
                "│  5 peanut                                4 glove                             │",
                "│  6 giraffe                               5 hammer                            │",
                "│  7 lime                                  6 eagle                             │",
                "│  8 thread                                7 milk                              │",
                "│  9 sweater                               8 beetle                            │",
                "│ 10 moon                                  9 train                             │",
                "│                                         10 lime                              │",
                "│                                                                              │",
                "│ [Enter] Check again   [Ctrl+O] Old code   [Esc] Back                         │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "                                                                                ",
            ],
        );
    }

    #[test]
    fn vf_partial_simple_mono() {
        let mut app = vf_new((80, 24));
        let code = bob_code();
        // The first group right, the second wrong, the third begun.
        let typed = format!("{}zzzz{}", &code[..4], &code[8..9]);
        type_text(&mut app, &typed);
        testkit::assert_rows(
            &at_rest(&app, 80, 24),
            &[
                "R A V E N - Security words                            o Receiving is off  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "┌──────────────────────────────────────────────────────────────────────────────┐",
                "│ Check it's really Bob                                                        │",
                "│                                                                              │",
                "│ Call Bob or meet in person. Each of you reads your own code to the other.    │",
                "│                                                                              │",
                "│ Your code: read this to Bob             Bob's code: ask Bob to read it to    │",
                "│                                         you                                  │",
                "│                                                                              │",
                "│ oEsE  vOrT  Oas                         Type Bob's code as they read it:     │",
                "│                                         > M026 v  zzzz x  N                  │",
                "│ Say it like: small o, capital E,                                             │",
                "│ small s, capital E                                                           │",
                "│                                                                              │",
                "│ [Enter] Check   [Tab] Later (not verified)   [Esc] Cancel                    │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
    }

    #[test]
    fn vf_partial_stacked_at_the_smallest_size() {
        let mut app = vf_new((60, 16));
        type_text(&mut app, "zzzz");
        testkit::assert_rows(
            &at_rest(&app, 60, 16),
            &[
                "R A V E N - Security words        o Receiving is off  ? Help",
                "┌──────────────────────────────────────────────────────────┐",
                "│ Check it's really Bob                                    │",
                "│                                                          │",
                "│ Call Bob or meet in person. Each of you reads your own   │",
                "│ code to the other.                                       │",
                "│                                                          │",
                "│ Your code: read this to Bob                              │",
                "│ oEsE  vOrT  Oas                                          │",
                "│ Say it like: small o, capital E, small s, capital E      │",
                "│ Bob's code: ask Bob to read it to you                    │",
                "│ Type Bob's code as they read it:                         │",
                "│ > zzzz x                                                 │",
                "│ [Enter] Check   [Tab] Later (not verified)               │",
                "│ [Esc] Cancel                                             │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
    }

    #[test]
    fn vf_match_shows_the_code_and_asks_for_the_confirmation_code() {
        let mut app = vf_new((80, 24));
        type_text(&mut app, &bob_code());
        testkit::press(&mut app, KeyCode::Enter);
        let code = app.verify_code_for_tests().expect("a code").to_owned();
        let rows = at_rest(&app, 80, 24);
        let text = testkit::screen_text(&rows);
        assert!(
            text.contains(&format!("To save Bob as verified, type {code}:")),
            "{text}"
        );
        testkit::assert_rows(
            &rows
                .iter()
                .map(|row| row.replace(&code, "K7Q3M"))
                .collect::<Vec<_>>(),
            &[
                "R A V E N - Security words                            o Receiving is off  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "┌──────────────────────────────────────────────────────────────────────────────┐",
                "│ Check it's really Bob                                                        │",
                "│                                                                              │",
                "│ Call Bob or meet in person. Each of you reads your own code to the other.    │",
                "│                                                                              │",
                "│ Your code: read this to Bob             Bob's code: ask Bob to read it to    │",
                "│                                         you                                  │",
                "│                                                                              │",
                "│ oEsE  vOrT  Oas                         It matches: M026  RjXE  NoLA         │",
                "│                                                                              │",
                "│ Say it like: small o, capital E,        To save Bob as verified, type K7Q3M: │",
                "│ small s, capital E                      >                                    │",
                "│                                                                              │",
                "│ [Enter] Save   [Esc] Cancel                                                  │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
    }

    #[test]
    fn vf_case_mismatch() {
        let mut app = vf_new((60, 16));
        type_text(&mut app, &wrong_case(&bob_code()));
        testkit::press(&mut app, KeyCode::Enter);
        testkit::assert_rows(
            &at_rest(&app, 60, 16),
            &[
                "R A V E N - Security words        o Receiving is off  ? Help",
                "┌──────────────────────────────────────────────────────────┐",
                "│ Check it's really Bob                                    │",
                "│ Call Bob or meet in person. Each of you reads your own   │",
                "│ code to the other.                                       │",
                "│ Your code: read this to Bob                              │",
                "│ oEsE  vOrT  Oas                                          │",
                "│ Say it like: small o, capital E, small s, capital E      │",
                "│ Bob's code: ask Bob to read it to you                    │",
                "│ Type Bob's code as they read it:                         │",
                "│ > m026 x  RjXE v  NoLA v                                 │",
                "│ Upper and lower case differ: codes are case-sensitive (W │",
                "│ is not w).                                               │",
                "│ [Enter] Check   [Tab] Later (not verified)               │",
                "│ [Esc] Cancel                                             │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
    }

    #[test]
    fn vf_mismatch() {
        let mut app = vf_new((80, 24));
        type_text(&mut app, "zzzzyyyyxx");
        testkit::press(&mut app, KeyCode::Enter);
        testkit::assert_rows(
            &at_rest(&app, 80, 24),
            &[
                "R A V E N - Security words                            o Receiving is off  ? Help",
                "                                                                                ",
                "                                                                                ",
                "┌──────────────────────────────────────────────────────────────────────────────┐",
                "│ Check it's really Bob                                                        │",
                "│                                                                              │",
                "│ Call Bob or meet in person. Each of you reads your own code to the other.    │",
                "│                                                                              │",
                "│ Your code: read this to Bob             Bob's code: ask Bob to read it to    │",
                "│                                         you                                  │",
                "│                                                                              │",
                "│ oEsE  vOrT  Oas                         Type Bob's code as they read it:     │",
                "│                                         > zzzz x  yyyy x  xx                 │",
                "│ Say it like: small o, capital E,                                             │",
                "│ small s, capital E                                                           │",
                "│                                                                              │",
                "│ That doesn't match. Do not verify: someone may have swapped Bob's key. Check │",
                "│ you pasted the right invite, or save Bob as not verified.                    │",
                "│                                                                              │",
                "│ [Enter] Check   [Tab] Later (not verified)   [Esc] Cancel                    │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
    }

    /// Bob's code typed with a Persian keyboard: the keyboard hint.
    fn keyboard_hint_in(look: Look, size: (u16, u16)) -> App {
        let mut app = vf_new_in(look, size, Vec::new());
        type_text(
            &mut app,
            &testkit::on_persian_keyboard(&testkit::me(BOB).fingerprint),
        );
        app
    }

    #[test]
    fn vf_keyboard_hint_simple_mono() {
        let mut app = keyboard_hint_in(testkit::simple_mono(), (80, 24));
        let rows: &[&str] = &[
            "R A V E N - Security words                            o Receiving is off  ? Help",
            "                                                                                ",
            "                                                                                ",
            "┌──────────────────────────────────────────────────────────────────────────────┐",
            "│ Check it's really Bob                                                        │",
            "│                                                                              │",
            "│ Call Bob or meet in person. Each of you reads your own code to the other.    │",
            "│                                                                              │",
            "│ Your code: read this to Bob             Bob's code: ask Bob to read it to    │",
            "│                                         you                                  │",
            "│                                                                              │",
            "│ oEsE  vOrT  Oas                         Type Bob's code as they read it:     │",
            "│                                         > 026                                │",
            "│ Say it like: small o, capital E,                                             │",
            "│ small s, capital E                                                           │",
            "│                                                                              │",
            "│ Switch your keyboard to English (Latin) letters for this code. Digits can    │",
            "│ stay as they are.                                                            │",
            "│                                                                              │",
            "│ [Enter] Check   [Tab] Later (not verified)   [Esc] Cancel                    │",
            "└──────────────────────────────────────────────────────────────────────────────┘",
            "                                                                                ",
            "                                                                                ",
            "                                                                                ",
        ];
        testkit::assert_rows(&at_rest(&app, 80, 24), rows);
        // Enter: the same rows. Never the mismatch's warning.
        testkit::press(&mut app, KeyCode::Enter);
        let after = at_rest(&app, 80, 24);
        testkit::assert_rows(&after, rows);
        assert!(!testkit::screen_text(&after).contains("swapped"));
    }

    #[test]
    fn vf_keyboard_hint_in_every_glyph_set_at_the_smallest_size() {
        let simple: &[&str] = &[
            "R A V E N - Security words        o Receiving is off  ? Help",
            "┌──────────────────────────────────────────────────────────┐",
            "│ Check it's really Bob                                    │",
            "│ Call Bob or meet in person. Each of you reads your own   │",
            "│ code to the other.                                       │",
            "│ Your code: read this to Bob                              │",
            "│ oEsE  vOrT  Oas                                          │",
            "│ Say it like: small o, capital E, small s, capital E      │",
            "│ Bob's code: ask Bob to read it to you                    │",
            "│ Type Bob's code as they read it:                         │",
            "│ > 026                                                    │",
            "│ Switch your keyboard to English (Latin) letters for this │",
            "│ code. Digits can stay as they are.                       │",
            "│ [Enter] Check   [Tab] Later (not verified)               │",
            "│ [Esc] Cancel                                             │",
            "└──────────────────────────────────────────────────────────┘",
        ];
        let fancy: &[&str] = &[
            "R A V E N · Security words       ○ Receiving is off · ? Help",
            "╭──────────────────────────────────────────────────────────╮",
            "│ Check it's really Bob                                    │",
            "│ Call Bob or meet in person. Each of you reads your own   │",
            "│ code to the other.                                       │",
            "│ Your code: read this to Bob                              │",
            "│ oEsE  vOrT  Oas                                          │",
            "│ Say it like: small o, capital E, small s, capital E      │",
            "│ Bob's code: ask Bob to read it to you                    │",
            "│ Type Bob's code as they read it:                         │",
            "│ > 026                                                    │",
            "│ Switch your keyboard to English (Latin) letters for this │",
            "│ code. Digits can stay as they are.                       │",
            "│ [Enter] Check   [Tab] Later (not verified)               │",
            "│ [Esc] Cancel                                             │",
            "╰──────────────────────────────────────────────────────────╯",
        ];
        let ascii: &[&str] = &[
            "R A V E N - Security words        o Receiving is off  ? Help",
            "+----------------------------------------------------------+",
            "| Check it's really Bob                                    |",
            "| Call Bob or meet in person. Each of you reads your own   |",
            "| code to the other.                                       |",
            "| Your code: read this to Bob                              |",
            "| oEsE  vOrT  Oas                                          |",
            "| Say it like: small o, capital E, small s, capital E      |",
            "| Bob's code: ask Bob to read it to you                    |",
            "| Type Bob's code as they read it:                         |",
            "| > 026                                                    |",
            "| Switch your keyboard to English (Latin) letters for this |",
            "| code. Digits can stay as they are.                       |",
            "| [Enter] Check   [Tab] Later (not verified)               |",
            "| [Esc] Cancel                                             |",
            "+----------------------------------------------------------+",
        ];
        for (glyphs, rows) in [
            (Glyphs::simple(), simple),
            (Glyphs::fancy(), fancy),
            (Glyphs::ascii(), ascii),
        ] {
            let look = Look {
                glyphs,
                ..testkit::simple_mono()
            };
            let mut app = keyboard_hint_in(look, (60, 16));
            testkit::assert_rows(&at_rest(&app, 60, 16), rows);
            testkit::press(&mut app, KeyCode::Enter);
            testkit::assert_rows(&at_rest(&app, 60, 16), rows);
        }
    }

    #[test]
    fn vf_confirmation_code_keyboard_hint() {
        let mut app = vf_new((80, 24));
        type_text(&mut app, &bob_code());
        testkit::press(&mut app, KeyCode::Enter);
        let code = app.verify_code_for_tests().expect("a code").to_owned();
        type_text(&mut app, &testkit::on_persian_keyboard("x2"));
        testkit::press(&mut app, KeyCode::Enter);
        // The same code is asked for, what was typed stays, and the hint
        // takes the place of 'didn't match'.
        assert_eq!(app.verify_code_for_tests(), Some(code.as_str()));
        let rows = at_rest(&app, 80, 24);
        assert!(!testkit::screen_text(&rows).contains("didn't match"));
        testkit::assert_rows(
            &rows
                .iter()
                .map(|row| row.replace(&code, "K7Q3M"))
                .collect::<Vec<_>>(),
            &[
                "R A V E N - Security words                            o Receiving is off  ? Help",
                "                                                                                ",
                "                                                                                ",
                "┌──────────────────────────────────────────────────────────────────────────────┐",
                "│ Check it's really Bob                                                        │",
                "│                                                                              │",
                "│ Call Bob or meet in person. Each of you reads your own code to the other.    │",
                "│                                                                              │",
                "│ Your code: read this to Bob             Bob's code: ask Bob to read it to    │",
                "│                                         you                                  │",
                "│                                                                              │",
                "│ oEsE  vOrT  Oas                         It matches: M026  RjXE  NoLA         │",
                "│                                                                              │",
                "│ Say it like: small o, capital E,        To save Bob as verified, type K7Q3M: │",
                "│ small s, capital E                      > \u{0637}2                                 │",
                "│                                                                              │",
                "│ Switch your keyboard to English (Latin) letters for this code. Digits can    │",
                "│ stay as they are.                                                            │",
                "│                                                                              │",
                "│ [Enter] Save   [Esc] Cancel                                                  │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
    }

    #[test]
    fn vf_later_asks_for_the_confirmation_code() {
        let mut app = vf_new((80, 24));
        testkit::press(&mut app, KeyCode::Tab);
        let code = app.verify_code_for_tests().expect("a code").to_owned();
        let rows = at_rest(&app, 80, 24);
        testkit::assert_rows(
            &rows
                .iter()
                .map(|row| row.replace(&code, "K7Q3M"))
                .collect::<Vec<_>>(),
            &[
                "R A V E N - Security words                            o Receiving is off  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "┌──────────────────────────────────────────────────────────────────────────────┐",
                "│ Check it's really Bob                                                        │",
                "│                                                                              │",
                "│ Call Bob or meet in person. Each of you reads your own code to the other.    │",
                "│                                                                              │",
                "│ Your code: read this to Bob             Bob's code: ask Bob to read it to    │",
                "│                                         you                                  │",
                "│                                                                              │",
                "│ oEsE  vOrT  Oas                         Save Bob without verifying? You can  │",
                "│                                         verify later from Bob's page. Type   │",
                "│ Say it like: small o, capital E,        K7Q3M to confirm:                    │",
                "│ small s, capital E                      >                                    │",
                "│                                                                              │",
                "│ [Enter] Save   [Tab] Back   [Esc] Cancel                                     │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
    }

    #[test]
    fn vf_already_verified_fancy() {
        let look = Look {
            glyphs: Glyphs::fancy(),
            ..testkit::simple_mono()
        };
        let mut app = testkit::home_app_in(
            look,
            (80, 24),
            Receive::Off,
            vec![testkit::saved_as(BOB, "Bob", true, "192.168.1.30:7420")],
            Conversations::new(),
        );
        testkit::press(&mut app, KeyCode::Char('v'));
        testkit::ctrl(&mut app, 'o');
        testkit::assert_rows(
            &at_rest(&app, 80, 24),
            &[
                "R A V E N · Security words                           ○ Receiving is off · ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "╭──────────────────────────────────────────────────────────────────────────────╮",
                "│ Check it's really Bob                                                        │",
                "│                                                                              │",
                "│ Call Bob or meet in person. Each of you reads your own code to the other.    │",
                "│                                                                              │",
                "│ Your code: read this to Bob             Bob's code: ask Bob to read it to    │",
                "│                                         you                                  │",
                "│                                                                              │",
                "│ oEsE  vOrT  Oas                         Already verified ✓                   │",
                "│                                         M026  RjXE  NoLA                     │",
                "│ Say it like: small o, capital E,                                             │",
                "│ small s, capital E                                                           │",
                "│                                                                              │",
                "│ [Enter] Check again   [Esc] Back                                             │",
                "╰──────────────────────────────────────────────────────────────────────────────╯",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
    }

    #[test]
    fn vf_marks_draw_in_and_a_match_stands_out() {
        let mut app = vf_new((80, 24));
        let code = bob_code();
        type_text(&mut app, &code[..4]);
        let t0 = app.now();
        assert_eq!(
            moving(&app),
            [Moving::Transition {
                start: t0,
                frames: 1,
                length: MARK_TIME
            }]
        );
        type_text(&mut app, &code[4..]);
        testkit::press(&mut app, KeyCode::Enter);
        assert!(matches!(
            moving(&app)[..],
            [Moving::Transition {
                length: MATCH_TIME,
                ..
            }]
        ));
        // Only styles change: the words are the same while it stands out.
        let now = app.now();
        assert_eq!(
            testkit::render_at(&app, 80, 24, now),
            testkit::render_at(&app, 80, 24, now + MATCH_TIME)
        );
    }

    #[test]
    fn reduced_motion_draws_vf_and_af3_still() {
        let look = Look {
            motion: Motion::Reduced,
            ..testkit::simple_mono()
        };
        let mut app = vf_new_in(look, (80, 24), Vec::new());
        type_text(&mut app, &bob_code());
        testkit::press(&mut app, KeyCode::Enter);
        let code = app.verify_code_for_tests().expect("a code").to_owned();
        let now = app.now();
        assert_eq!(anim::next_change(&moving(&app), &look, now), None);
        type_text(&mut app, &code);
        testkit::press(&mut app, KeyCode::Enter);
        testkit::send(
            &mut app,
            Msg::Job(JobResult::FriendChanged {
                change: FriendChange::Add,
                pub_hex: testkit::me(BOB).pub_hex,
                result: Ok(()),
                notes: Vec::new(),
            }),
        );
        assert_eq!(anim::next_change(&moving(&app), &look, app.now()), None);
        // The check mark is there at once.
        assert!(testkit::render(&app, 80, 24)
            .iter()
            .any(|row| row.contains("Bob is added v Verified")));
    }

    #[test]
    fn af3_verified_and_not() {
        for (verified, look) in [
            (true, testkit::simple_mono()),
            (
                false,
                Look {
                    glyphs: Glyphs::ascii(),
                    ..testkit::simple_mono()
                },
            ),
        ] {
            let mut app = vf_new_in(look, (80, 24), Vec::new());
            if verified {
                type_text(&mut app, &bob_code());
            } else {
                testkit::press(&mut app, KeyCode::Tab);
            }
            testkit::press(&mut app, KeyCode::Enter);
            let code = app.verify_code_for_tests().map(str::to_owned);
            if let Some(code) = code {
                type_text(&mut app, &code);
            }
            testkit::press(&mut app, KeyCode::Enter);
            testkit::send(
                &mut app,
                Msg::Job(JobResult::FriendChanged {
                    change: FriendChange::Add,
                    pub_hex: testkit::me(BOB).pub_hex,
                    result: Ok(()),
                    notes: Vec::new(),
                }),
            );
            assert!(
                matches!(app.screen(), Screen::Added(_)),
                "{:?}",
                app.screen()
            );
            if verified {
                // The check mark draws in: nothing, dim, then there.
                let t0 = app.now();
                let heading = |ms: u64| {
                    testkit::render_at(&app, 80, 24, t0 + Duration::from_millis(ms))
                        .into_iter()
                        .find(|row| row.contains("is added"))
                        .expect("the heading")
                };
                assert!(
                    heading(0).contains("Bob is added   Verified"),
                    "{}",
                    heading(0)
                );
                assert!(heading(300).contains("Bob is added v Verified"));
                testkit::assert_rows(&at_rest(&app, 80, 24), &[
                    "R A V E N - Add a friend                              o Receiving is off  ? Help",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "        ┌──────────────────────────────────────────────────────────────┐        ",
                    "        │ Bob is added v Verified                                      │        ",
                    "        │                                                              │        ",
                    "        │ Bob needs to add you too, or your messages will be refused.  │        ",
                    "        │ If you haven't yet, send Bob your invite (press 1).          │        ",
                    "        │                                                              │        ",
                    "        │ [Enter] Open chat   [1] Show my invite                       │        ",
                    "        │ [A] Add another friend                                       │        ",
                    "        └──────────────────────────────────────────────────────────────┘        ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                ]);
            } else {
                testkit::assert_rows(&at_rest(&app, 80, 24), &[
                    "R A V E N - Add a friend                              o Receiving is off  ? Help",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "        +--------------------------------------------------------------+        ",
                    "        | Bob is added (not verified yet)                              |        ",
                    "        |                                                              |        ",
                    "        | Bob needs to add you too, or your messages will be refused.  |        ",
                    "        | If you haven't yet, send Bob your invite (press 1).          |        ",
                    "        |                                                              |        ",
                    "        | [Enter] Open chat   [1] Show my invite                       |        ",
                    "        | [A] Add another friend                                       |        ",
                    "        +--------------------------------------------------------------+        ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                    "                                                                                ",
                ]);
            }
        }
    }

    #[test]
    fn ci_verified_simple_mono() {
        let mut app = home_with_friends((80, 24));
        testkit::press(&mut app, KeyCode::Char('e'));
        // Bob is verified: his words are on his page, from his key.
        let bob = testkit::me(BOB);
        assert_eq!(app.verified_words(&bob.pub_hex), Some(bob.words));
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Friend page                               o Receiving is off  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Bob                                                          │        ",
                "        │                                                              │        ",
                "        │ Security words: orange soap swan glove hammer eagle milk     │        ",
                "        │ beetle train lime   v Verified                               │        ",
                "        │ Old-style code: M026  RjXE  NoLA                             │        ",
                "        │ Raven address: rvn1qye5mw...mu82td                           │        ",
                "        │ Local network: 192.168.1.30:7420                             │        ",
                "        │                                                              │        ",
                "        │ [R] Rename  [E] Edit address  [V] Verify  [X] Remove         │        ",
                "        │ [Esc] Back                                                   │        ",
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
    fn ci_unverified_and_blocked_shows_no_code() {
        let mut app = home_with_friends((80, 24));
        testkit::press(&mut app, KeyCode::Down);
        testkit::press(&mut app, KeyCode::Char('i'));
        let rows = testkit::render(&app, 80, 24);
        let code = testkit::me(ALICE).fingerprint;
        let text = rows.join("\n");
        for group in code.split('-') {
            assert!(!text.contains(group), "{group} of {code}:\n{text}");
        }
        // Nor her words: the App gives them only once she is verified.
        let alice = testkit::me(ALICE);
        assert_eq!(app.verified_words(&alice.pub_hex), None);
        for word in alice.words.iter() {
            let whole = |w: &str| w.trim_matches(|c: char| !c.is_ascii_alphabetic()) == word;
            assert!(!text.split_whitespace().any(whole), "{word}:\n{text}");
        }
        testkit::assert_rows(
            &rows,
            &[
                "R A V E N - Friend page                               o Receiving is off  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Alice                                                        │        ",
                "        │                                                              │        ",
                "        │ Security words: hidden until you verify Alice (press V)      │        ",
                "        │ Raven address: rvn1q9es5h...gl7en8                           │        ",
                "        │ Local network: not set                                       │        ",
                "        │ Internet: 203.0.113.9:7420 (Preview, not in this release)    │        ",
                "        │ Blocked: Raven refuses messages from Alice.                  │        ",
                "        │                                                              │        ",
                "        │ [R] Rename  [E] Edit address  [V] Verify  [X] Remove         │        ",
                "        │ [U] Unblock  [Esc] Back                                      │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        // At the smallest size, ASCII.
        let look = Look {
            glyphs: Glyphs::ascii(),
            theme: Theme::color(),
            ..testkit::simple_mono()
        };
        let alice = ContactView {
            blocked: true,
            internet_dial: "203.0.113.9:7420".into(),
            ..testkit::saved_as(ALICE, "Alice", false, "")
        };
        let mut app = testkit::home_app_in(
            look,
            (60, 16),
            Receive::Off,
            vec![alice],
            Conversations::new(),
        );
        testkit::press(&mut app, KeyCode::Char('e'));
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N - Friend page           o Receiving is off  ? Help",
                "                                                            ",
                "+----------------------------------------------------------+",
                "| Alice                                                    |",
                "|                                                          |",
                "| Security words: hidden until you verify Alice (press V)  |",
                "| Raven address: rvn1q9es5h...gl7en8                       |",
                "| Local network: not set                                   |",
                "| Internet: 203.0.113.9:7420 (Preview, not in this         |",
                "| release)                                                 |",
                "| Blocked: Raven refuses messages from Alice.              |",
                "|                                                          |",
                "| [R] Rename  [E] Edit address  [V] Verify  [X] Remove     |",
                "| [U] Unblock  [Esc] Back                                  |",
                "+----------------------------------------------------------+",
                "                                                            ",
            ],
        );
    }

    #[test]
    fn ci_rename_warns_of_a_mixed_alphabet() {
        let mut app = home_with_friends((80, 24));
        testkit::press(&mut app, KeyCode::Char('e'));
        testkit::press(&mut app, KeyCode::Char('r'));
        // A Latin B with a Cyrillic о.
        type_text(&mut app, "B\u{043E}bby");
        let rows = testkit::render(&app, 80, 24);
        assert!(testkit::screen_text(&rows).contains(
            "This name mixes letters from different alphabets, so it can look like another name."
        ));
        testkit::assert_rows(
            &rows,
            &[
                "R A V E N - Friend page                               o Receiving is off  ? Help",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Bob                                                          │        ",
                "        │                                                              │        ",
                "        │ Security words: orange soap swan glove hammer eagle milk     │        ",
                "        │ beetle train lime   v Verified                               │        ",
                "        │ Old-style code: M026  RjXE  NoLA                             │        ",
                "        │ Raven address: rvn1qye5mw...mu82td                           │        ",
                "        │ Local network: 192.168.1.30:7420                             │        ",
                "        │                                                              │        ",
                "        │ What do you want to call them?                               │        ",
                "        │ ┌──────────────────────────────────┐                         │        ",
                "        │ │ Bоbby                            │                         │        ",
                "        │ └──────────────────────────────────┘                         │        ",
                "        │ This name is only on this computer.                          │        ",
                "        │ This name mixes letters from different alphabets, so it can  │        ",
                "        │ look like another name. Check it before you save.            │        ",
                "        │                                                              │        ",
                "        │ [Enter] Save   [Esc] Back                                    │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
    }

    #[test]
    fn ci_remove_asks_for_the_word() {
        let mut app = home_with_friends((80, 24));
        testkit::press(&mut app, KeyCode::Char('e'));
        testkit::press(&mut app, KeyCode::Char('x'));
        type_text(&mut app, "rem");
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Friend page                               o Receiving is off  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Bob                                                          │        ",
                "        │                                                              │        ",
                "        │ Security words: orange soap swan glove hammer eagle milk     │        ",
                "        │ beetle train lime   v Verified                               │        ",
                "        │ Old-style code: M026  RjXE  NoLA                             │        ",
                "        │ Raven address: rvn1qye5mw...mu82td                           │        ",
                "        │ Local network: 192.168.1.30:7420                             │        ",
                "        │                                                              │        ",
                "        │ Remove Bob? This deletes their contact and verification on   │        ",
                "        │ this computer. Your messages with them stay. Type remove to  │        ",
                "        │ confirm:                                                     │        ",
                "        │ > rem                                                        │        ",
                "        │                                                              │        ",
                "        │ [Enter] Remove   [Esc] Back                                  │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        // The address field, with a bad address.
        testkit::press(&mut app, KeyCode::Esc);
        testkit::press(&mut app, KeyCode::Char('e'));
        type_text(&mut app, "192.168.1.44");
        testkit::press(&mut app, KeyCode::Enter);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Friend page                               o Receiving is off  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Bob                                                          │        ",
                "        │                                                              │        ",
                "        │ Security words: orange soap swan glove hammer eagle milk     │        ",
                "        │ beetle train lime   v Verified                               │        ",
                "        │ Old-style code: M026  RjXE  NoLA                             │        ",
                "        │ Raven address: rvn1qye5mw...mu82td                           │        ",
                "        │ Local network: 192.168.1.30:7420                             │        ",
                "        │                                                              │        ",
                "        │ Their address on your network, like 192.168.1.30:7420.       │        ",
                "        │ > 192.168.1.44                                               │        ",
                "        │ That isn't an address Raven can use. It looks like           │        ",
                "        │ 192.168.1.30:7420.                                           │        ",
                "        │                                                              │        ",
                "        │ [Enter] Save   [Esc] Back                                    │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
    }

    // ── Delete chat and Forget address (privacy pack PP.21) ─────────────────

    /// Bob's page (verified, with an address), at `size`, his read marker
    /// saved and the privacy read answered (`privacy`) or not.
    fn ci_privacy(size: (u16, u16), privacy: bool) -> App {
        let bob = testkit::saved_as(BOB, "Bob", true, "192.168.1.30:7420");
        let mut settings = testkit::session(Receive::Off).settings;
        settings
            .last_read
            .insert(bob.pub_hex.clone(), "msg-7".into());
        let session = Session {
            settings,
            ..testkit::session(Receive::Off)
        };
        let mut app = testkit::home_app_from(
            testkit::simple_mono(),
            size,
            session,
            vec![bob],
            Conversations::new(),
        );
        if privacy {
            testkit::privacy_on(&mut app, ChatKeepView::Days30, Default::default());
        }
        testkit::press(&mut app, KeyCode::Char('e'));
        assert!(matches!(app.screen(), Screen::FriendPage(_)));
        app
    }

    fn bob_key() -> String {
        testkit::me(BOB).pub_hex
    }

    /// The store jobs `cmds` ask for that delete a chat or forget an address.
    fn privacy_jobs(cmds: &[Cmd]) -> Vec<StoreJob> {
        cmds.iter()
            .filter_map(|cmd| match cmd {
                Cmd::Store(
                    job @ (StoreJob::DeleteChat { .. } | StoreJob::ForgetAddress { .. }),
                ) => Some(job.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn ci_privacy_actions_wait_for_the_privacy_read() {
        // Not available: no keys for them, and C and F do nothing.
        let mut app = ci_privacy((80, 24), false);
        for c in ['c', 'f', 'C', 'F'] {
            assert!(testkit::press(&mut app, KeyCode::Char(c)).is_empty());
            assert!(app.overlays().is_empty());
        }
        let text = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(
            !text.contains("Delete chat") && !text.contains("Forget"),
            "{text}"
        );
        let help = |app: &mut App| {
            testkit::press(app, KeyCode::Char('?'));
            let text = testkit::screen_text(&testkit::render(app, 80, 24));
            testkit::press(app, KeyCode::Esc);
            text
        };
        let text = help(&mut app);
        assert!(
            !text.contains("Delete your chat") && !text.contains("Forget"),
            "{text}"
        );
        // Available: both, with Bob's name, and in HELP.
        testkit::privacy_on(&mut app, ChatKeepView::Days30, Default::default());
        let text = help(&mut app);
        assert!(
            text.contains("C Delete your chat on this computer"),
            "{text}"
        );
        assert!(text.contains("F Forget their address"), "{text}");
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Friend page                               o Receiving is off  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Bob                                                          │        ",
                "        │                                                              │        ",
                "        │ Security words: orange soap swan glove hammer eagle milk     │        ",
                "        │ beetle train lime   v Verified                               │        ",
                "        │ Old-style code: M026  RjXE  NoLA                             │        ",
                "        │ Raven address: rvn1qye5mw...mu82td                           │        ",
                "        │ Local network: 192.168.1.30:7420                             │        ",
                "        │                                                              │        ",
                "        │ [R] Rename  [E] Edit address  [V] Verify  [X] Remove         │        ",
                "        │ [C] Delete chat with Bob  [F] Forget Bob's address           │        ",
                "        │ [Esc] Back                                                   │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        let app = ci_privacy((60, 16), true);
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N - Friend page           o Receiving is off  ? Help",
                "                                                            ",
                "┌──────────────────────────────────────────────────────────┐",
                "│ Bob                                                      │",
                "│                                                          │",
                "│ Security words: orange soap swan glove hammer eagle milk │",
                "│ beetle train lime   v Verified                           │",
                "│ Old-style code: M026  RjXE  NoLA                         │",
                "│ Raven address: rvn1qye5mw...mu82td                       │",
                "│ Local network: 192.168.1.30:7420                         │",
                "│                                                          │",
                "│ [R] Rename  [E] Edit address  [V] Verify  [X] Remove     │",
                "│ [C] Delete chat with Bob  [F] Forget Bob's address       │",
                "│ [Esc] Back                                               │",
                "└──────────────────────────────────────────────────────────┘",
                "                                                            ",
            ],
        );
    }

    #[test]
    fn ci_delete_chat_asks_for_the_typed_word() {
        let mut app = ci_privacy((80, 24), true);
        testkit::press(&mut app, KeyCode::Char('c'));
        assert_eq!(
            app.overlays(),
            [Overlay::DeleteChat {
                peer: bob_key(),
                typed: String::new()
            }]
        );
        type_text(&mut app, "dele");
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Friend page                               o Receiving is off  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Bob                                                          │        ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Delete your chat with Bob on this computer? Bob keeps their  │        ",
                "        │ copy. Type delete to confirm:                                │        ",
                "        │ > dele                                                       │        ",
                "        │                                                              │        ",
                "        │ [Enter] Delete   [Esc] Cancel                                │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "        │ [R] Rename  [E] Edit address  [V] Verify  [X] Remove         │        ",
                "        │ [C] Delete chat with Bob  [F] Forget Bob's address           │        ",
                "        │ [Esc] Back                                                   │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        // Not the word yet: Enter does nothing.
        assert!(privacy_jobs(&testkit::press(&mut app, KeyCode::Enter)).is_empty());
        assert!(matches!(app.overlays(), [Overlay::DeleteChat { .. }]));
        // Esc keeps the chat.
        assert!(testkit::press(&mut app, KeyCode::Esc).is_empty());
        assert!(app.overlays().is_empty());
        // In any case: one delete, and CI waits for it.
        testkit::press(&mut app, KeyCode::Char('c'));
        type_text(&mut app, "DeLeTe");
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(
            privacy_jobs(&cmds),
            [StoreJob::DeleteChat { pub_hex: bob_key() }]
        );
        assert!(app.overlays().is_empty());
        assert!(matches!(app.screen(), Screen::FriendPage(page) if page.saving));
        // It went: the toasts say how many, CI's keys come back, Bob's read
        // marker goes (saved now) and the history is read again.
        let cmds = testkit::send(
            &mut app,
            Msg::Job(JobResult::ChatDeleted {
                pub_hex: bob_key(),
                result: Ok(DeleteChatOutcome {
                    deleted: 3,
                    still_waiting: 1,
                    skipped_pending: 0,
                }),
            }),
        );
        assert!(
            cmds.contains(&Cmd::Store(StoreJob::LoadHistory)),
            "{cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|cmd| matches!(cmd, Cmd::Store(StoreJob::SaveReadMarks(state)) if state.last_read.is_empty())),
            "{cmds:?}"
        );
        assert!(app.settings().last_read.is_empty());
        assert!(matches!(app.screen(), Screen::FriendPage(page) if !page.saving));
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Friend page                               o Receiving is off  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Bob                                                          │        ",
                "        │                                                              │        ",
                "        │ Security words: orange soap swan glove hammer eagle milk     │        ",
                "        │ beetle train lime   v Verified                               │        ",
                "        │ Old-style code: M026  RjXE  NoLA                             │        ",
                "        │ Raven address: rvn1qye5mw...mu82td                           │        ",
                "        │ Local network: 192.168.1.30:7420                             │        ",
                "        │                                                              │        ",
                "        │ [R] Rename  [E] Edit address  [V] Verify  [X] Remove         │        ",
                "        │ [C] Delete chat with Bob  [F] Forget Bob's address           │        ",
                "        │ [Esc] Back                                                   │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "Deleted your chat with Bob on this computer (3 messages).                       ",
            ],
        );
        testkit::tick(&mut app, Duration::from_secs(4));
        assert_eq!(
            app.toast().map(|toast| toast.text.as_str()),
            Some("1 message to Bob is still waiting to be sent.")
        );
        // At the smallest size.
        let mut small = ci_privacy((60, 16), true);
        testkit::press(&mut small, KeyCode::Char('c'));
        type_text(&mut small, "delete");
        testkit::assert_rows(
            &testkit::render(&small, 60, 16),
            &[
                "R A V E N - Friend page           o Receiving is off  ? Help",
                "                                                            ",
                "┌──────────────────────────────────────────────────────────┐",
                "│ Bob                                                      │",
                "┌──────────────────────────────────────────────────────────┐",
                "│ Delete your chat with Bob on this computer? Bob keeps    │",
                "│ their copy. Type delete to confirm:                      │",
                "│ > delete                                                 │",
                "│                                                          │",
                "│ [Enter] Delete   [Esc] Cancel                            │",
                "└──────────────────────────────────────────────────────────┘",
                "│ [R] Rename  [E] Edit address  [V] Verify  [X] Remove     │",
                "│ [C] Delete chat with Bob  [F] Forget Bob's address       │",
                "│ [Esc] Back                                               │",
                "└──────────────────────────────────────────────────────────┘",
                "                                                            ",
            ],
        );
        testkit::press(&mut small, KeyCode::Enter);
        testkit::send(
            &mut small,
            Msg::Job(JobResult::ChatDeleted {
                pub_hex: bob_key(),
                result: Ok(DeleteChatOutcome::default()),
            }),
        );
        testkit::assert_rows(
            &testkit::render(&small, 60, 16),
            &[
                "R A V E N - Friend page           o Receiving is off  ? Help",
                "                                                            ",
                "┌──────────────────────────────────────────────────────────┐",
                "│ Bob                                                      │",
                "│                                                          │",
                "│ Security words: orange soap swan glove hammer eagle milk │",
                "│ beetle train lime   v Verified                           │",
                "│ Old-style code: M026  RjXE  NoLA                         │",
                "│ Raven address: rvn1qye5mw...mu82td                       │",
                "│ Local network: 192.168.1.30:7420                         │",
                "│                                                          │",
                "│ [R] Rename  [E] Edit address  [V] Verify  [X] Remove     │",
                "│ [C] Delete chat with Bob  [F] Forget Bob's address       │",
                "│ [Esc] Back                                               │",
                "└──────────────────────────────────────────────────────────┘",
                "Deleted your chat with Bob on this computer (0 messages).   ",
            ],
        );
    }

    #[test]
    fn ci_delete_chat_takes_the_word_only_typed() {
        // On a Persian keyboard the same keys are the word.
        let mut app = ci_privacy((80, 24), true);
        testkit::press(&mut app, KeyCode::Char('c'));
        type_text(&mut app, &testkit::on_persian_keyboard("delete"));
        assert_eq!(
            app.overlays(),
            [Overlay::DeleteChat {
                peer: bob_key(),
                typed: "delete".into()
            }]
        );
        assert_eq!(
            privacy_jobs(&testkit::press(&mut app, KeyCode::Enter)),
            [StoreJob::DeleteChat { pub_hex: bob_key() }]
        );
        // A paste clears the word, and Enter right after it means nothing.
        let mut app = ci_privacy((80, 24), true);
        testkit::press(&mut app, KeyCode::Char('c'));
        type_text(&mut app, "delete");
        for via in [PasteVia::Bracketed, PasteVia::Keystrokes] {
            testkit::send(
                &mut app,
                Msg::Paste {
                    text: "delete".into(),
                    via,
                },
            );
            assert!(
                matches!(app.overlays(), [Overlay::DeleteChat { typed, .. }] if typed.is_empty())
            );
        }
        type_text(&mut app, "delete");
        assert!(privacy_jobs(&testkit::press(&mut app, KeyCode::Enter)).is_empty());
        assert!(matches!(app.overlays(), [Overlay::DeleteChat { .. }]));
        testkit::tick(&mut app, Duration::from_millis(300));
        assert_eq!(
            privacy_jobs(&testkit::press(&mut app, KeyCode::Enter)),
            [StoreJob::DeleteChat { pub_hex: bob_key() }]
        );
        // An Enter that came with a paste clears it too.
        let mut app = ci_privacy((80, 24), true);
        testkit::press(&mut app, KeyCode::Char('c'));
        type_text(&mut app, "delete");
        testkit::send(&mut app, Msg::Key(Key::PastedEnter));
        assert!(matches!(app.overlays(), [Overlay::DeleteChat { typed, .. }] if typed.is_empty()));
        // A failure stays on CI, with Details.
        testkit::tick(&mut app, Duration::from_millis(300));
        type_text(&mut app, "delete");
        testkit::press(&mut app, KeyCode::Enter);
        testkit::send(
            &mut app,
            Msg::Job(JobResult::ChatDeleted {
                pub_hex: bob_key(),
                result: Err("chat history is locked by another process".into()),
            }),
        );
        let Screen::FriendPage(page) = app.screen() else {
            panic!("not on CI: {:?}", app.screen());
        };
        let failure = page.failure.as_ref().expect("a failure");
        assert!(failure
            .plain
            .headline
            .starts_with("Raven couldn't delete the chat."));
        assert_eq!(app.settings().last_read.len(), 1, "nothing was deleted");
    }

    #[test]
    fn ci_forget_address_asks_first() {
        let mut app = ci_privacy((80, 24), true);
        testkit::press(&mut app, KeyCode::Char('f'));
        assert_eq!(app.overlays(), [Overlay::ForgetAddress { peer: bob_key() }]);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Friend page                               o Receiving is off  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Bob                                                          │        ",
                "        │                                                              │        ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Forget Bob's saved address? Raven can then reach Bob only    │        ",
                "        │ after Bob connects to you, or after you save a new address.  │        ",
                "        │                                                              │        ",
                "        │ [Enter] Forget   [Esc] Cancel                                │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "        │ [R] Rename  [E] Edit address  [V] Verify  [X] Remove         │        ",
                "        │ [C] Delete chat with Bob  [F] Forget Bob's address           │        ",
                "        │ [Esc] Back                                                   │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        // Esc keeps it; Enter right after a paste means nothing.
        assert!(testkit::press(&mut app, KeyCode::Esc).is_empty());
        testkit::press(&mut app, KeyCode::Char('f'));
        testkit::send(&mut app, Msg::Key(Key::PastedEnter));
        assert!(privacy_jobs(&testkit::press(&mut app, KeyCode::Enter)).is_empty());
        testkit::tick(&mut app, Duration::from_millis(300));
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(
            privacy_jobs(&cmds),
            [StoreJob::ForgetAddress { pub_hex: bob_key() }]
        );
        assert!(matches!(app.screen(), Screen::FriendPage(page) if page.saving));
        testkit::send(
            &mut app,
            Msg::Job(JobResult::FriendChanged {
                change: FriendChange::ForgetAddress,
                pub_hex: bob_key(),
                result: Ok(()),
                notes: Vec::new(),
            }),
        );
        assert_eq!(
            app.toast().map(|toast| toast.text.as_str()),
            Some("Raven forgot Bob's saved address.")
        );
        assert_eq!(
            app.friend(&bob_key()).map(|bob| bob.lan_dial.as_str()),
            Some("")
        );
        assert!(
            testkit::screen_text(&testkit::render(&app, 80, 24)).contains("Local network: not set")
        );
        let mut small = ci_privacy((60, 16), true);
        testkit::press(&mut small, KeyCode::Char('f'));
        testkit::assert_rows(
            &testkit::render(&small, 60, 16),
            &[
                "R A V E N - Friend page           o Receiving is off  ? Help",
                "                                                            ",
                "┌──────────────────────────────────────────────────────────┐",
                "│ Bob                                                      │",
                "┌──────────────────────────────────────────────────────────┐",
                "│ Forget Bob's saved address? Raven can then reach Bob     │",
                "│ only after Bob connects to you, or after you save a new  │",
                "│ address.                                                 │",
                "│                                                          │",
                "│ [Enter] Forget   [Esc] Cancel                            │",
                "└──────────────────────────────────────────────────────────┘",
                "│ [R] Rename  [E] Edit address  [V] Verify  [X] Remove     │",
                "│ [C] Delete chat with Bob  [F] Forget Bob's address       │",
                "│ [Esc] Back                                               │",
                "└──────────────────────────────────────────────────────────┘",
                "                                                            ",
            ],
        );
    }

    /// Review D-lock-tui-8: the saved address went, but part of what Raven
    /// learned about reaching Bob could not be forgotten. CI says so, with
    /// what is left in Details, instead of the plain success toast.
    #[test]
    fn ci_forget_address_says_what_it_could_not_forget() {
        let mut app = ci_privacy((80, 24), true);
        testkit::press(&mut app, KeyCode::Char('f'));
        testkit::tick(&mut app, Duration::from_millis(300));
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(
            privacy_jobs(&cmds),
            [StoreJob::ForgetAddress { pub_hex: bob_key() }]
        );
        let note = "could not forget where it last connected from (lan_seen.json: Is a directory \
                    (os error 21))";
        testkit::send(
            &mut app,
            Msg::Job(JobResult::FriendChanged {
                change: FriendChange::ForgetAddress,
                pub_hex: bob_key(),
                result: Ok(()),
                notes: vec![note.to_owned()],
            }),
        );
        assert_ne!(
            app.toast().map(|toast| toast.text.as_str()),
            Some("Raven forgot Bob's saved address.")
        );
        assert_eq!(
            app.friend(&bob_key()).map(|bob| bob.lan_dial.as_str()),
            Some(""),
            "the saved address went all the same"
        );
        let Screen::FriendPage(page) = app.screen() else {
            panic!("not on CI: {:?}", app.screen());
        };
        assert!(!page.saving);
        let failure = page.failure.as_ref().expect("what is left");
        assert_eq!(
            failure.plain.headline,
            "Raven forgot Bob's saved address, but couldn't forget everything it learned about \
             reaching Bob."
        );
        assert_eq!(failure.plain.technical, note);
        let text = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(
            text.contains("Raven forgot Bob's saved address, but couldn't forget"),
            "{text}"
        );
        assert!(text.contains("[D] Details"), "{text}");
        assert!(!text.contains("lan_seen.json"), "{text}");
        // D shows what is left.
        testkit::press(&mut app, KeyCode::Char('d'));
        let text = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(text.contains("lan_seen.json"), "{text}");
    }
}
