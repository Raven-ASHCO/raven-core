//! LOCKED and PASS (Lock now v2, Phase 6 P6.40; design C §6's UX copy).
//!
//! LOCKED covers the whole screen while this profile's raven-node runs
//! locked: nothing of the profile shows behind it. A profile with a Raven
//! passphrase types it there; a keychain profile's Enter resumes, and the
//! screen says plainly that a lock does not keep its keys from anyone who
//! can log in as the user. PASS is SET's 'Raven passphrase': set, change or
//! remove it. A typed passphrase is drawn as one '*' per character, never
//! as itself.

use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::Frame;

use super::app::{App, LockedView, PassState, PassStep};
#[cfg(test)]
use super::app::{Cmd, JobResult, LockSettingsView, Msg, NodeJob, Overlay, Screen, SetRow};
use super::bridge::{self, PassOp};
#[cfg(test)]
use super::state_file::Receive;
use super::{overlays, verify, widgets, wrap};
#[cfg(test)]
use super::{testkit, workers};

/// LOCKED's and PASS's width, in cells (smaller in a smaller window).
const WIDTH: u16 = 64;

/// LOCKED's copy.
const TYPE_IT: &str = "Type your Raven passphrase to unlock:";
const UNLOCKING: &str = "Unlocking";
const LOCKED_KEYS: [(&str, &str); 2] = [("[Enter]", " Unlock"), ("[Ctrl+C]", " Quit")];

/// PASS's copy.
const SET_TITLE: &str = "Set a Raven passphrase";
const SET_BODY: &str = "Raven's keys on this computer move into a vault that only your Raven \
                        passphrase opens. Raven can't open them without it: there is no way to \
                        recover a forgotten one.";
const CHANGE_TITLE: &str = "Change your Raven passphrase";
const REMOVE_TITLE: &str = "Remove your Raven passphrase";
const REMOVE_BODY: &str = "Raven's keys go back to your login keychain.";
const CHOOSE_TITLE: &str = "Raven passphrase";
const CHOOSE_BODY: &str =
    "This profile has a Raven passphrase: Raven's keys on this computer open only with it.";
const CURRENT: &str = "Current passphrase:";
const NEW: &str = "New passphrase (at least 8 characters):";
const AGAIN: &str = "Type it again:";
const CHANGING: &str = "Changing it. Raven is locked meanwhile";
const CHOOSE_KEYS: [(&str, &str); 3] =
    [("[C]", " Change"), ("[R]", " Remove"), ("[Esc]", " Cancel")];
const NEXT_KEYS: [(&str, &str); 2] = [("[Enter]", " Next"), ("[Esc]", " Cancel")];
const SAVE_KEYS: [(&str, &str); 2] = [("[Enter]", " Save"), ("[Esc]", " Cancel")];
const GAP: &str = "   ";

/// A field's row: its marks and the cursor.
fn field(chars: usize, active: bool) -> Line<'static> {
    let cursor = if active { "_" } else { "" };
    Line::raw(format!("> {}{cursor}", "*".repeat(chars)))
}

/// Draws LOCKED over the whole of `area`.
pub(super) fn render_locked(f: &mut Frame, area: Rect, app: &App, view: &LockedView) {
    let look = app.look();
    widgets::clear(f, area, look);
    let width = overlays::inner_width(WIDTH.min(area.width));
    let text = |copy: &str| -> Vec<Line<'static>> {
        wrap(copy, width, 0).into_iter().map(Line::raw).collect()
    };
    let mut lines = text(bridge::LOCKED_SCREEN);
    lines.push(Line::default());
    if view.passphrase {
        lines.extend(text(TYPE_IT));
        lines.push(field(view.typed.chars(), !view.unlocking));
    } else {
        lines.extend(text(bridge::keys_open_to_login_text()));
    }
    if view.unlocking {
        lines.push(Line::default());
        lines.extend(text(&format!("{UNLOCKING}{}", look.glyphs.ellipsis)));
    } else if let Some(note) = &view.note {
        lines.push(Line::default());
        lines.push(Line::styled(
            wrap(note, width, 0).join(" "),
            look.theme.warn,
        ));
    }
    lines.push(Line::default());
    lines.extend(verify::key_rows(look, &LOCKED_KEYS, GAP, width));
    let rect = overlays::centered(area, WIDTH, overlays::height_of(&lines));
    overlays::draw_card(f, rect, look, overlays::fit(lines, rect.height));
}

/// Draws PASS at its step.
pub(super) fn render_passphrase(f: &mut Frame, area: Rect, app: &App, pass: &PassState) {
    let look = app.look();
    let width = overlays::inner_width(WIDTH.min(area.width));
    let text = |copy: &str| -> Vec<Line<'static>> {
        wrap(copy, width, 0).into_iter().map(Line::raw).collect()
    };
    let (title, body): (&str, Vec<&str>) = match pass.op {
        None => (CHOOSE_TITLE, vec![CHOOSE_BODY]),
        Some(PassOp::Set) => (SET_TITLE, vec![SET_BODY]),
        Some(PassOp::Change) => (CHANGE_TITLE, Vec::new()),
        Some(PassOp::Remove) => (
            REMOVE_TITLE,
            vec![REMOVE_BODY, bridge::keys_open_to_login_text()],
        ),
    };
    let mut lines = vec![Line::styled(title.to_owned(), look.theme.accent)];
    for paragraph in body {
        lines.push(Line::default());
        lines.extend(text(paragraph));
    }
    let typing = pass.step != PassStep::Changing;
    let steps = [
        (PassStep::Current, CURRENT, pass.current.chars()),
        (PassStep::New, NEW, pass.new.chars()),
        (PassStep::Again, AGAIN, pass.again.chars()),
    ];
    let shown = steps.iter().filter(|(step, ..)| match pass.op {
        Some(op) => match step {
            PassStep::Current => op.needs_current(),
            _ => op.needs_new(),
        },
        None => false,
    });
    let reached = |step: PassStep| order(step) <= order(pass.step);
    let mut first = true;
    for &(step, label, chars) in shown {
        if !reached(step) {
            continue;
        }
        if first {
            lines.push(Line::default());
            first = false;
        }
        lines.extend(text(label));
        lines.push(field(chars, typing && step == pass.step));
    }
    if pass.step == PassStep::Changing {
        lines.push(Line::default());
        lines.extend(text(&format!("{CHANGING}{}", look.glyphs.ellipsis)));
    } else if let Some(note) = &pass.note {
        lines.push(Line::default());
        lines.push(Line::styled(
            wrap(note, width, 0).join(" "),
            look.theme.warn,
        ));
    }
    let keys: &[(&str, &str)] = match pass.step {
        PassStep::Choose => &CHOOSE_KEYS,
        PassStep::Changing => &[],
        PassStep::Again => &SAVE_KEYS,
        PassStep::Current if pass.op == Some(PassOp::Remove) => &SAVE_KEYS,
        PassStep::Current | PassStep::New => &NEXT_KEYS,
    };
    if !keys.is_empty() {
        lines.push(Line::default());
        lines.extend(verify::key_rows(look, keys, GAP, width));
    }
    let rect = overlays::centered(area, WIDTH, overlays::height_of(&lines));
    overlays::draw_card(f, rect, look, overlays::fit(lines, rect.height));
}

/// The steps in the order they come.
fn order(step: PassStep) -> u8 {
    match step {
        PassStep::Choose => 0,
        PassStep::Current => 1,
        PassStep::New => 2,
        PassStep::Again => 3,
        PassStep::Changing => 4,
    }
}

#[cfg(test)]
mod tests;
