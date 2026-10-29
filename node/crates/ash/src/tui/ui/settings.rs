//! SET: the app's settings as rows of a label and its value, the chosen one
//! marked with '>' and a short help line under it where one says more.
//! Enter, Left or Right changes a value, and each change is saved at once
//! (app.rs). Motion, colours and symbols are drawn in their new look at
//! once.
//!
//! The rows scroll to keep the chosen one and its help line in view; the
//! keys stay on the bottom row. The user's own name is the only untrusted
//! text here, drawn through display.rs.

use std::time::Instant;

use ratatui::layout::{Position, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

#[cfg(test)]
use super::anim;
use super::app::{App, SetRow, SettingsState};
#[cfg(test)]
use super::app::{
    Cmd, EraseState, IdentityStart, JobResult, Key, ListenOverride, Look, LookEnv, Msg, NodeJob,
    Overlay, PasteVia, Screen, Session, StoreJob, NAME_CELLS,
};
use super::bridge::{self, ChatKeepView, PassOffer};
#[cfg(test)]
use super::controller::{Controller, IdentityState};
#[cfg(test)]
use super::gate::{self, GateInput, UiChoice};
#[cfg(test)]
use super::node::{Managed, NodeState, Probe, Vault};
#[cfg(test)]
use super::render as render_frame;
#[cfg(test)]
use super::state_file::{self, ColorSetting, MotionSetting, PaletteSetting, TuiState};
use super::state_file::{ColorChoice, OnQuit, Receive, SymbolSetting};
#[cfg(test)]
use super::testkit;
use super::theme::Motion;
#[cfg(test)]
use super::theme::{self, Depth, Glyphs, TermEnv, Theme};
#[cfg(test)]
use super::workers::{self, FileStamp, PollUpdate, Watched};
use super::{add_friend, cells, display, overlays, render_header, verify, widgets, wizard, wrap};

const TITLE: &str = " Settings ";

/// The rows' labels and values.
const NAME: &str = "Your name (only on this computer)";
const NAME_UNSET: &str = "not set";
const MOTION: &str = "Motion";
const MOTION_FULL: &str = "Full";
const MOTION_REDUCED: &str = "Reduced: no spinners or animations";
const COLORS: &str = "Colors";
const COLORS_AUTO: &str = "Automatic";
const COLORS_DARK: &str = "Dark";
const COLORS_LIGHT: &str = "Light";
const COLORS_NONE: &str = "No colors";
const COLORS_FORCED: &str = "No colors (set by NO_COLOR)";
const SYMBOLS: &str = "Symbols";
const ON_QUIT: &str = "When I quit";
const RECEIVE: &str = "Receive messages on this computer";
const SHARE: &str = "Share my network address in my invite";
const DETAILS: &str = "Show technical details";
const LOGIN: &str = "Start Raven when I log in";
const LOGIN_UNSET: &str = "Not set up";
const LOGIN_SET: &str = "Set up";
const CLASSIC_NOW: &str = "Switch to the classic menu now";
const ALWAYS_CLASSIC: &str = "Always open the classic menu";
const LOCK_NOW: &str = "Lock now";
/// The last row (privacy pack PP.22): opens ERASE. Shown once the privacy
/// read answered.
const ERASE: &str = "Erase Raven from this computer";
/// 'Keep chats for' (privacy pack PP.21): shown once the privacy read
/// answered; its value as KEEP lists it.
const KEEP_CHATS: &str = "Keep chats for";
/// 'Keep' as the row's value: it reads on after the label.
const KEEP_ALWAYS: &str = "Always (until you delete them)";
const ON: &str = "On";
const OFF: &str = "Off";
/// Lock now v2's rows (P6.40), shown once the lock settings were read.
const SLEEP_LOCK: &str = "Lock Raven when the computer sleeps";
const IDLE_LOCK: &str = "Lock Raven when this app is idle";
const PASSPHRASE: &str = "Raven passphrase";
const PASSPHRASE_SET: &str = "Set";
const PASSPHRASE_CHANGE_REMOVE: &str = "Change | Remove";
const PASSPHRASE_CHANGE: &str = "Change";
const PASSPHRASE_NONE: &str = "Not available";

/// Help lines under the chosen row.
const RECEIVE_OFF_HELP: &str =
    "Friends can't send you messages. Applies the next time you open Raven.";
const RECEIVE_UNSET_HELP: &str = "Raven asks you before it starts receiving.";
/// Receiving is off, but the background program still listens.
const RECEIVE_OFF_STILL: &str = "Off, but still receiving";
const RECEIVE_STILL_HELP: &str = "Friends can reach you until Raven's background program stops. \
                                  After that they can't send you messages.";
const RECEIVE_RESTART_HELP: &str = "Applies the next time you open Raven.";
const LOGIN_UNSET_HELP: &str = "Raven can be set to start at login with the installer for your \
                                system (macOS launch agent, Linux systemd user service, Windows \
                                logon task). This app doesn't change login settings itself.";
const LOGIN_SET_HELP: &str = "Raven's installer set its background program to start when you \
                              log in. This app doesn't change login settings itself.";
const CLASSIC_HELP: &str = "The plain line-by-line menu. Works best with screen readers.";
const SLEEP_LOCK_HELP: &str = "When this computer wakes from sleep, Raven forgets its keys \
                               until you unlock it: friends can't reach you meanwhile.";
const IDLE_LOCK_HELP: &str = "Raven locks after this app has had no key for that long.";
const PASSPHRASE_HAS_HELP: &str =
    "Raven's keys on this computer open only with your Raven passphrase.";
/// The help the Calm design adds for the rows that had none.
const NAME_HELP: &str =
    "This name is only shown on this computer. It is never sent to anyone. Enter edits it.";
const MOTION_HELP: &str = "Under Reduced only text changes. Raven also follows this terminal: \
                           NO_COLOR, the Linux console and screen readers.";
const COLORS_HELP: &str =
    "Colours never carry meaning alone: every state also has its glyph or word.";
const SYMBOLS_HELP: &str = "Simple drops Braille and ✓ for fonts that lack them; ASCII draws \
                            boxes with + - | for terminals that draw them two cells wide.";
const KEEP_RUNNING_HELP: &str = "Raven's background program keeps running while this computer \
                                 is on, so friends can still reach you and waiting messages \
                                 keep trying.";
const SHARE_HELP: &str = "Anyone you send your invite to can see it.";

/// The stop question after receiving was turned off, in place of the keys.
const STOP_QUESTION: &str = "Stop the background program this app started? Friends can't reach \
                             you until it runs again.";
const STOP_KEYS: [(&str, &str); 2] = [("[Y]", " Stop"), ("[N]", " Keep it running")];
/// The name field's keys.
const NAME_KEYS: [(&str, &str); 2] = [("[Enter]", " Save"), ("[Esc]", " Cancel")];
/// The rows' inset: the marker and two spaces.
const INSET: &str = "   ";
/// The values' column: this far after the longest label, and needing this
/// many cells of room; else each value follows its label.
const VALUE_GAP: usize = 3;
const VALUE_ROOM: usize = 24;
/// The help area's rows, at least.
const HELP_ROWS: usize = 2;

/// Draws SET under the header row (Calm): its rows in a box under faint
/// group labels, scrolled to the chosen one; the chosen row's help (or the
/// stop question) under a rule at the bottom of the box; its keys under
/// the box.
pub(super) fn render(f: &mut Frame, area: Rect, app: &App, set: &SettingsState, now: Instant) {
    if area.is_empty() {
        return;
    }
    render_header(f, area, app, now, true);
    let look = app.look();
    let body = wizard::under_header(area);
    let keys = key_lines(app, set, body.width);
    let keys_height = u16::try_from(keys.len())
        .unwrap_or(u16::MAX)
        .min(body.height.saturating_sub(3));
    let boxed = Rect {
        height: body.height - keys_height,
        ..body
    };
    f.render_widget(
        Paragraph::new(keys),
        Rect {
            y: boxed.bottom(),
            height: keys_height,
            ..body
        },
    );
    let block = widgets::pane(look, true).title(widgets::pane_title(look, TITLE, true));
    let inner = block.inner(boxed);
    f.render_widget(block, boxed);
    if inner.is_empty() {
        return;
    }
    let width = inner.width;
    // The help area: a rule, then the help's rows (two at least, so the
    // list doesn't move as the help changes).
    let help = help_rows(app, set, width.saturating_sub(cells(INSET) as u16));
    let help_height = u16::try_from(help.len().max(HELP_ROWS))
        .unwrap_or(u16::MAX)
        .min(inner.height.saturating_sub(2) / 2);
    let rows_height = inner.height - help_height - u16::from(help_height > 0);
    let Rows {
        lines: rows,
        chosen,
        field,
    } = rows(app, set, width);
    let top = top_row(chosen, rows_height);
    let rows_rect = Rect {
        height: rows_height,
        ..inner
    };
    f.render_widget(Paragraph::new(rows).scroll((top, 0)), rows_rect);
    if help_height > 0 {
        let rule = look.glyphs.border.horizontal_top.repeat(usize::from(width));
        f.render_widget(
            Paragraph::new(Line::styled(rule, look.theme.faint)),
            Rect {
                y: rows_rect.bottom(),
                height: 1,
                ..inner
            },
        );
        let help: Vec<Line<'static>> = help
            .into_iter()
            .map(|row| {
                let mut spans = vec![Span::raw(INSET)];
                spans.extend(row.spans);
                Line::from(spans).style(row.style)
            })
            .collect();
        f.render_widget(
            Paragraph::new(help),
            Rect {
                y: rows_rect.bottom() + 1,
                height: help_height,
                ..inner
            },
        );
    }
    // The terminal's own cursor in the name field, while it shows.
    if let Some((y, x)) = field {
        let y = u16::try_from(y).unwrap_or(u16::MAX);
        if y >= top && y - top < rows_height && app.overlays().is_empty() {
            let x = u16::try_from(x).unwrap_or(u16::MAX);
            let x = inner.x.saturating_add(x.min(width.saturating_sub(1)));
            f.set_cursor_position(Position::new(x, inner.y + (y - top)));
        }
    }
}

/// The first row drawn: 0, or as far down as keeps the chosen row's block
/// (`chosen`, its first and last row) in view, its first row first; its
/// group's label too when there is room.
fn top_row(chosen: (usize, usize), height: u16) -> u16 {
    let (first, last) = chosen;
    let height = usize::from(height).max(1);
    let top = (last + 1).saturating_sub(height).min(first);
    u16::try_from(top).unwrap_or(u16::MAX)
}

/// SET's rows as drawn.
struct Rows {
    /// Every row under its group's label, the chosen one's name field under
    /// it while it shows.
    lines: Vec<Line<'static>>,
    /// The chosen row's block: its first and last line.
    chosen: (usize, usize),
    /// Where the cursor goes in the name field (line, column), while it
    /// shows.
    field: Option<(usize, usize)>,
}

/// The group a row is shown in (Calm): its label goes over the first row
/// of each.
fn group(row: SetRow) -> &'static str {
    match row {
        SetRow::Name => "You",
        SetRow::Motion | SetRow::Colors | SetRow::Symbols => "Look",
        SetRow::OnQuit | SetRow::Receive | SetRow::ShareAddress | SetRow::Details => "Receiving",
        SetRow::KeepChats | SetRow::LoginStart => "Privacy",
        SetRow::ClassicNow | SetRow::AlwaysClassic => "Classic menu",
        SetRow::LockNow
        | SetRow::SleepLock
        | SetRow::IdleLock
        | SetRow::Passphrase
        | SetRow::Erase => "Lock",
    }
}

/// Whether Left and Right step `row`'s value: the chosen one shows '‹ ›'
/// around it.
fn steps(app: &App, row: SetRow) -> bool {
    match row {
        SetRow::Colors => !app.no_color_env(),
        SetRow::Motion
        | SetRow::Symbols
        | SetRow::OnQuit
        | SetRow::Receive
        | SetRow::ShareAddress
        | SetRow::Details
        | SetRow::AlwaysClassic
        | SetRow::SleepLock
        | SetRow::IdleLock => true,
        SetRow::Name
        | SetRow::KeepChats
        | SetRow::LoginStart
        | SetRow::ClassicNow
        | SetRow::LockNow
        | SetRow::Passphrase
        | SetRow::Erase => false,
    }
}

fn rows(app: &App, set: &SettingsState, width: u16) -> Rows {
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    let shown = app.set_rows();
    let mut lines = Vec::new();
    let mut chosen = (0, 0);
    let mut field = None;
    let inset = cells(INSET);
    // The values in a column of their own where it leaves them room, else
    // after their label.
    let labels = shown
        .iter()
        .map(|row| cells(label_and_value(app, *row).0))
        .max()
        .unwrap_or(0);
    let column = inset + labels + VALUE_GAP;
    let columns = column + VALUE_ROOM <= usize::from(width);
    let mut last_group = None;
    for row in shown {
        let picked = row == set.row;
        // The group's label over its first row, which keeps it in view.
        let mut label_at = None;
        if last_group != Some(group(row)) {
            if last_group.is_some() {
                lines.push(Line::default());
            }
            label_at = Some(lines.len());
            lines.push(Line::styled(format!("{INSET}{}", group(row)), t.faint));
            last_group = Some(group(row));
        }
        let (label, value, value_style) = label_and_value(app, row);
        let label_style = if row == SetRow::Erase { t.bad } else { t.text };
        let mut spans = vec![
            if picked {
                widgets::marker(look)
            } else {
                Span::raw(" ")
            },
            Span::raw(&INSET[1..]),
            Span::styled(label, label_style),
        ];
        if let Some(value) = value {
            // '‹ value ›' where the value fits with them.
            let at_most = if columns {
                column
            } else {
                inset + cells(label) + 2
            };
            let around = picked
                && steps(app, row)
                && at_most + display::width(&value) + 4 <= usize::from(width);
            let (before, after) = if around {
                (
                    format!("{} ", g.value_before),
                    format!(" {}", g.value_after),
                )
            } else {
                (String::new(), String::new())
            };
            let at = if columns {
                spans.push(Span::raw(
                    " ".repeat(column - inset - cells(label) - cells(&before)),
                ));
                column
            } else {
                spans.push(Span::raw(": "));
                inset + cells(label) + 2 + cells(&before)
            };
            let left = usize::from(width).saturating_sub(at + cells(&after));
            let value =
                display::one_line(&value, u16::try_from(left).unwrap_or(u16::MAX), g.ellipsis);
            if around {
                spans.push(Span::styled(before, t.accent));
            }
            spans.push(Span::styled(value, value_style));
            if around {
                spans.push(Span::styled(after, t.accent));
            }
        }
        let first = lines.len();
        let mut line = Line::from(spans);
        if picked {
            // The selection across the box's width.
            let pad = usize::from(width).saturating_sub(line.width());
            line.spans.push(Span::raw(" ".repeat(pad)));
            line = line.style(t.selected);
        }
        lines.push(line);
        if picked {
            if let Some(typed) = &set.name {
                let [top, middle, bottom] = wizard::name_field(look, typed, NAME_UNSET);
                for part in [top, middle, bottom] {
                    let mut indented = vec![Span::raw(INSET)];
                    indented.extend(part.spans);
                    lines.push(Line::from(indented));
                }
                // After the inset, the field's left border and its space,
                // and the name.
                field = Some((first + 2, inset + 2 + display::width(typed)));
                if set.name_full {
                    let limit = add_friend::NAME_LIMIT;
                    lines.push(Line::styled(format!("{INSET}{limit}"), t.secondary));
                }
            }
            chosen = (label_at.unwrap_or(first), lines.len() - 1);
        }
    }
    Rows {
        lines,
        chosen,
        field,
    }
}

/// The help area's rows for the chosen row: the stop question while it is
/// asked, else what the row says more, dim.
fn help_rows(app: &App, set: &SettingsState, width: u16) -> Vec<Line<'static>> {
    let t = &app.look().theme;
    if set.asking_stop {
        return wrap(STOP_QUESTION, width, 0)
            .into_iter()
            .map(Line::raw)
            .collect();
    }
    if set.name.is_some() {
        return Vec::new();
    }
    help_line(app, set.row)
        .map(|help| {
            wrap(help, width, 0)
                .into_iter()
                .map(|row| Line::styled(row, t.secondary))
                .collect()
        })
        .unwrap_or_default()
}

/// A row's label, and its value (None for an action) with the value's
/// style.
fn label_and_value(app: &App, row: SetRow) -> (&'static str, Option<String>, Style) {
    let look = app.look();
    let settings = app.settings();
    let on_off = |on: bool| Some(if on { ON } else { OFF }.to_owned());
    let plain = Style::default();
    match row {
        SetRow::Name if settings.display_name.trim().is_empty() => {
            (NAME, Some(NAME_UNSET.to_owned()), look.theme.secondary)
        }
        SetRow::Name => (NAME, Some(settings.display_name.clone()), plain),
        SetRow::Motion => {
            let value = match look.motion {
                Motion::Full => MOTION_FULL,
                Motion::Reduced => MOTION_REDUCED,
            };
            (MOTION, Some(value.to_owned()), plain)
        }
        SetRow::Colors => {
            let value = if app.no_color_env() {
                COLORS_FORCED
            } else {
                match ColorChoice::of(settings) {
                    ColorChoice::Auto => COLORS_AUTO,
                    ColorChoice::Dark => COLORS_DARK,
                    ColorChoice::Light => COLORS_LIGHT,
                    ColorChoice::NoColors => COLORS_NONE,
                }
            };
            (COLORS, Some(value.to_owned()), plain)
        }
        SetRow::Symbols => {
            let value = match settings.symbols {
                SymbolSetting::Auto => "Automatic",
                SymbolSetting::Ascii => "ASCII (for any terminal)",
                SymbolSetting::Simple => "Simple (for older terminals)",
                SymbolSetting::Fancy => "Fancy",
            };
            (SYMBOLS, Some(value.to_owned()), plain)
        }
        SetRow::OnQuit => {
            let value = match settings.on_quit {
                OnQuit::KeepRunning => "Keep Raven running (recommended)",
                OnQuit::StopIfStarted => "Stop Raven if this app started it",
                OnQuit::Ask => "Ask me",
            };
            (ON_QUIT, Some(value.to_owned()), plain)
        }
        // What the background program does, as `raven status` reads it
        // (E1: Off while messages arrived): it receives while it listens on
        // the network, whatever was saved.
        SetRow::Receive if settings.receive != Receive::On && app.node().receiving() => {
            (RECEIVE, Some(RECEIVE_OFF_STILL.to_owned()), plain)
        }
        SetRow::Receive => (RECEIVE, on_off(settings.receive == Receive::On), plain),
        SetRow::ShareAddress => (SHARE, on_off(settings.include_lan_in_card), plain),
        SetRow::Details => (DETAILS, on_off(settings.show_details), plain),
        SetRow::LoginStart => {
            let value = if app.node().managed.is_some() {
                LOGIN_SET
            } else {
                LOGIN_UNSET
            };
            (LOGIN, Some(value.to_owned()), plain)
        }
        SetRow::ClassicNow => (CLASSIC_NOW, None, plain),
        SetRow::AlwaysClassic => (ALWAYS_CLASSIC, on_off(settings.always_classic), plain),
        SetRow::LockNow => (LOCK_NOW, None, plain),
        SetRow::SleepLock => (
            SLEEP_LOCK,
            on_off(app.lock_settings().is_some_and(|read| read.sleep_lock)),
            plain,
        ),
        SetRow::IdleLock => {
            let value = match settings.idle_lock_minutes {
                0 => OFF.to_owned(),
                minutes => format!("After {minutes} minutes"),
            };
            (IDLE_LOCK, Some(value), plain)
        }
        SetRow::Passphrase => {
            let (value, style) = match app.lock_settings().map(|read| &read.offer) {
                Some(PassOffer::Set) => (PASSPHRASE_SET, plain),
                Some(PassOffer::ChangeOrRemove) => (PASSPHRASE_CHANGE_REMOVE, plain),
                Some(PassOffer::Change) => (PASSPHRASE_CHANGE, plain),
                Some(PassOffer::No(_)) | None => (PASSPHRASE_NONE, look.theme.secondary),
            };
            (PASSPHRASE, Some(value.to_owned()), style)
        }
        SetRow::Erase => (ERASE, None, plain),
        SetRow::KeepChats => {
            let value = match app.privacy().map(|read| read.keep) {
                Some(ChatKeepView::Keep) => KEEP_ALWAYS,
                Some(keep) => overlays::keep_label(keep),
                None => "",
            };
            (KEEP_CHATS, Some(value.to_owned()), plain)
        }
    }
}

/// What the chosen row says under it, if anything.
fn help_line(app: &App, row: SetRow) -> Option<&'static str> {
    match row {
        SetRow::Name => Some(NAME_HELP),
        SetRow::Motion => Some(MOTION_HELP),
        SetRow::Colors => Some(COLORS_HELP),
        SetRow::Symbols => Some(SYMBOLS_HELP),
        SetRow::OnQuit if app.settings().on_quit == OnQuit::KeepRunning => Some(KEEP_RUNNING_HELP),
        SetRow::ShareAddress if app.settings().include_lan_in_card => Some(SHARE_HELP),
        SetRow::Receive => match app.settings().receive {
            Receive::Off | Receive::Unset if app.node().receiving() => Some(RECEIVE_STILL_HELP),
            Receive::Off => Some(RECEIVE_OFF_HELP),
            Receive::Unset => Some(RECEIVE_UNSET_HELP),
            Receive::On if app.receive_waits_for_restart() => Some(RECEIVE_RESTART_HELP),
            Receive::On => None,
        },
        SetRow::LoginStart if app.node().managed.is_some() => Some(LOGIN_SET_HELP),
        SetRow::LoginStart => Some(LOGIN_UNSET_HELP),
        SetRow::ClassicNow | SetRow::AlwaysClassic => Some(CLASSIC_HELP),
        SetRow::KeepChats => app.privacy().map(|read| overlays::keep_help(read.keep)),
        SetRow::SleepLock => Some(SLEEP_LOCK_HELP),
        SetRow::IdleLock => Some(IDLE_LOCK_HELP),
        SetRow::Passphrase => match app.lock_settings().map(|read| &read.offer) {
            Some(PassOffer::Set) => Some(bridge::keys_open_to_login_text()),
            Some(PassOffer::ChangeOrRemove | PassOffer::Change) => Some(PASSPHRASE_HAS_HELP),
            Some(PassOffer::No(why)) => Some(why),
            None => None,
        },
        _ => None,
    }
}

/// The keys for the chosen row, or the name field's, or the stop
/// question's; in rows of `width` cells.
fn key_lines(app: &App, set: &SettingsState, width: u16) -> Vec<Line<'static>> {
    let look = app.look();
    if set.asking_stop {
        return verify::key_rows(look, &STOP_KEYS, "  ", width);
    }
    if set.name.is_some() {
        return verify::key_rows(look, &NAME_KEYS, "  ", width);
    }
    let mut keys = vec![(look.glyphs.up_down, " Choose")];
    match set.row {
        SetRow::LoginStart => {}
        SetRow::Colors if app.no_color_env() => {}
        SetRow::ClassicNow => keys.push(("[Enter]", " Open it")),
        SetRow::LockNow => keys.push(("[Enter]", " Lock")),
        SetRow::Passphrase
            if app
                .lock_settings()
                .is_some_and(|read| matches!(read.offer, PassOffer::No(_))) => {}
        SetRow::Passphrase => keys.push(("[Enter]", " Open")),
        SetRow::Erase => keys.push(("[Enter]", " Erase")),
        _ => keys.push(("[Enter]", " Change")),
    }
    keys.push(("[Esc]", " Back"));
    verify::key_rows(look, &keys, "  ", width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::Path;
    use std::time::Duration;

    /// SET at `size`, receiving `receive`, `friends` friends, no node running.
    fn set_at(size: (u16, u16), receive: Receive, friends: u8) -> App {
        let mut app = testkit::settled_app(size, receive, friends);
        open(&mut app);
        app
    }

    /// S on the friend list.
    fn open(app: &mut App) {
        testkit::press(app, KeyCode::Char('s'));
        assert!(
            matches!(app.screen(), Screen::Settings(_)),
            "{:?}",
            app.screen()
        );
    }

    fn state(app: &App) -> &SettingsState {
        match app.screen() {
            Screen::Settings(set) => set,
            other => panic!("not on SET: {other:?}"),
        }
    }

    /// Down until `row` is chosen.
    fn choose(app: &mut App, row: SetRow) {
        while state(app).row != row {
            let before = state(app).row;
            testkit::press(app, KeyCode::Down);
            assert_ne!(state(app).row, before, "{row:?} is not below {before:?}");
        }
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

    /// The settings `cmds` ask to save; None when they save nothing.
    fn saved(cmds: &[Cmd]) -> Option<TuiState> {
        let saves: Vec<TuiState> = cmds
            .iter()
            .filter_map(|cmd| match cmd {
                Cmd::Store(StoreJob::SaveSettings(state)) => Some(state.clone()),
                _ => None,
            })
            .collect();
        assert!(saves.len() <= 1, "saved twice: {cmds:?}");
        saves.into_iter().next()
    }

    fn ensures(cmds: &[Cmd]) -> bool {
        cmds.contains(&Cmd::Node(NodeJob::Ensure))
    }

    #[test]
    fn set_simple_mono() {
        let app = set_at((80, 24), Receive::Off, 1);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Settings                                  o Receiving is off  ? Help",
                "┌ Settings ────────────────────────────────────────────────────────────────────┐",
                "│   You                                                                        │",
                "│>  Your name (only on this computer)       not set                            │",
                "│                                                                              │",
                "│   Look                                                                       │",
                "│   Motion                                  Full                               │",
                "│   Colors                                  Automatic                          │",
                "│   Symbols                                 Automatic                          │",
                "│                                                                              │",
                "│   Receiving                                                                  │",
                "│   When I quit                             Keep Raven running (recommended)   │",
                "│   Receive messages on this computer       Off                                │",
                "│   Share my network address in my invite   On                                 │",
                "│   Show technical details                  Off                                │",
                "│                                                                              │",
                "│   Privacy                                                                    │",
                "│   Start Raven when I log in               Not set up                         │",
                "│                                                                              │",
                "│──────────────────────────────────────────────────────────────────────────────│",
                "│   This name is only shown on this computer. It is never sent to anyone. Enter│",
                "│   edits it.                                                                  │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "Up/Down Choose  [Enter] Change  [Esc] Back                                      ",
            ],
        );
    }

    #[test]
    fn set_scrolls_to_the_chosen_row_at_60_by_16() {
        let mut app = set_at((60, 16), Receive::Off, 1);
        choose(&mut app, SetRow::Receive);
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N - Settings              o Receiving is off  ? Help",
                "┌ Settings ────────────────────────────────────────────────┐",
                "│                                                          │",
                "│   Look                                                   │",
                "│   Motion: Full                                           │",
                "│   Colors: Automatic                                      │",
                "│   Symbols: Automatic                                     │",
                "│                                                          │",
                "│   Receiving                                              │",
                "│   When I quit: Keep Raven running (recommended)          │",
                "│>  Receive messages on this computer: < Off >             │",
                "│──────────────────────────────────────────────────────────│",
                "│   Friends can't send you messages. Applies the next time │",
                "│   you open Raven.                                        │",
                "└──────────────────────────────────────────────────────────┘",
                "Up/Down Choose  [Enter] Change  [Esc] Back                  ",
            ],
        );
        choose(&mut app, SetRow::LoginStart);
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N - Settings              o Receiving is off  ? Help",
                "┌ Settings ────────────────────────────────────────────────┐",
                "│   When I quit: Keep Raven running (recommended)          │",
                "│   Receive messages on this computer: Off                 │",
                "│   Share my network address in my invite: On              │",
                "│   Show technical details: Off                            │",
                "│                                                          │",
                "│   Privacy                                                │",
                "│>  Start Raven when I log in: Not set up                  │",
                "│──────────────────────────────────────────────────────────│",
                "│   Raven can be set to start at login with the installer  │",
                "│   for your system (macOS launch agent, Linux systemd user│",
                "│   service, Windows logon task). This app doesn't change  │",
                "│   login settings itself.                                 │",
                "└──────────────────────────────────────────────────────────┘",
                "Up/Down Choose  [Esc] Back                                  ",
            ],
        );
        choose(&mut app, SetRow::AlwaysClassic);
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N - Settings              o Receiving is off  ? Help",
                "┌ Settings ────────────────────────────────────────────────┐",
                "│   Share my network address in my invite: On              │",
                "│   Show technical details: Off                            │",
                "│                                                          │",
                "│   Privacy                                                │",
                "│   Start Raven when I log in: Not set up                  │",
                "│                                                          │",
                "│   Classic menu                                           │",
                "│   Switch to the classic menu now                         │",
                "│>  Always open the classic menu: < Off >                  │",
                "│──────────────────────────────────────────────────────────│",
                "│   The plain line-by-line menu. Works best with screen    │",
                "│   readers.                                               │",
                "└──────────────────────────────────────────────────────────┘",
                "Up/Down Choose  [Enter] Change  [Esc] Back                  ",
            ],
        );
        // Lock now is the last row: an action, with no value.
        choose(&mut app, SetRow::LockNow);
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N - Settings              o Receiving is off  ? Help",
                "┌ Settings ────────────────────────────────────────────────┐",
                "│   Privacy                                                │",
                "│   Start Raven when I log in: Not set up                  │",
                "│                                                          │",
                "│   Classic menu                                           │",
                "│   Switch to the classic menu now                         │",
                "│   Always open the classic menu: Off                      │",
                "│                                                          │",
                "│   Lock                                                   │",
                "│>  Lock now                                               │",
                "│──────────────────────────────────────────────────────────│",
                "│                                                          │",
                "│                                                          │",
                "└──────────────────────────────────────────────────────────┘",
                "Up/Down Choose  [Enter] Lock  [Esc] Back                    ",
            ],
        );
        // Up stops at the top, Down at the bottom.
        for _ in 0..20 {
            testkit::press(&mut app, KeyCode::Down);
        }
        assert_eq!(state(&app).row, SetRow::LockNow);
        for _ in 0..20 {
            testkit::press(&mut app, KeyCode::Char('k'));
        }
        assert_eq!(state(&app).row, SetRow::Name);
        testkit::press(&mut app, KeyCode::Char('j'));
        assert_eq!(state(&app).row, SetRow::Motion);
    }

    #[test]
    fn set_fancy_with_a_login_service() {
        let look = Look {
            glyphs: Glyphs::fancy(),
            theme: Theme::color(),
            ..testkit::simple_mono()
        };
        let mut app =
            testkit::home_app_in(look, (80, 24), Receive::On, Vec::new(), Default::default());
        testkit::send(
            &mut app,
            Msg::Job(JobResult::Managed(Some(Managed::LaunchAgent))),
        );
        open(&mut app);
        choose(&mut app, SetRow::LoginStart);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N · Settings                     ○ Starts when you add a friend · ? Help",
                "╭ Settings ────────────────────────────────────────────────────────────────────╮",
                "│   You                                                                        │",
                "│   Your name (only on this computer)       not set                            │",
                "│                                                                              │",
                "│   Look                                                                       │",
                "│   Motion                                  Full                               │",
                "│   Colors                                  Automatic                          │",
                "│   Symbols                                 Automatic                          │",
                "│                                                                              │",
                "│   Receiving                                                                  │",
                "│   When I quit                             Keep Raven running (recommended)   │",
                "│   Receive messages on this computer       On                                 │",
                "│   Share my network address in my invite   On                                 │",
                "│   Show technical details                  Off                                │",
                "│                                                                              │",
                "│   Privacy                                                                    │",
                "│>  Start Raven when I log in               Set up                             │",
                "│                                                                              │",
                "│──────────────────────────────────────────────────────────────────────────────│",
                "│   Raven's installer set its background program to start when you log in. This│",
                "│   app doesn't change login settings itself.                                  │",
                "╰──────────────────────────────────────────────────────────────────────────────╯",
                "↑↓ Choose  [Esc] Back                                                           ",
            ],
        );
    }

    #[test]
    fn keys_esc_help_and_quit() {
        let mut app = set_at((80, 24), Receive::Off, 1);
        testkit::press(&mut app, KeyCode::Char('?'));
        assert_eq!(app.overlays(), [Overlay::Help { scroll: 0 }]);
        let help = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(help.contains("Up, Down Choose"), "{help}");
        testkit::press(&mut app, KeyCode::Esc);
        testkit::press(&mut app, KeyCode::Char('q'));
        assert_eq!(app.overlays(), [Overlay::Quit]);
        testkit::press(&mut app, KeyCode::Esc);
        testkit::ctrl(&mut app, 'c');
        assert_eq!(app.overlays(), [Overlay::Quit]);
        testkit::press(&mut app, KeyCode::Esc);
        // A paste on a row is nothing.
        assert!(testkit::paste(&mut app, "q\n", PasteVia::Bracketed).is_empty());
        assert!(app.overlays().is_empty());
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(*app.screen(), Screen::Home);
    }

    #[test]
    fn motion_colors_and_symbols_apply_at_once_and_are_saved() {
        let mut app = set_at((80, 24), Receive::Off, 1);
        choose(&mut app, SetRow::Motion);
        // Automatic shows the motion in use; a change chooses the other.
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(app.look().motion, Motion::Reduced);
        assert_eq!(saved(&cmds).map(|s| s.motion), Some(MotionSetting::Reduced));
        // Too long for '< >' beside it at 80 columns.
        assert!(testkit::screen_text(&testkit::render(&app, 80, 24))
            .contains("Motion Reduced: no spinners or animations"));
        let cmds = testkit::press(&mut app, KeyCode::Left);
        assert_eq!(app.look().motion, Motion::Full);
        assert_eq!(saved(&cmds).map(|s| s.motion), Some(MotionSetting::Full));

        // Colors: Automatic, Dark, Light, No colors (Calm); the palette is
        // a field of its own, so an older app still reads the file.
        choose(&mut app, SetRow::Colors);
        let both = |state: &TuiState| (state.colors, state.palette);
        let cmds = testkit::press(&mut app, KeyCode::Right);
        assert_eq!(
            saved(&cmds).as_ref().map(both),
            Some((ColorSetting::Auto, PaletteSetting::Dark))
        );
        assert_eq!(app.look().theme, Theme::calm(&theme::DARK, Depth::Indexed));
        assert!(testkit::screen_text(&testkit::render(&app, 80, 24)).contains("Colors < Dark >"));
        let cmds = testkit::press(&mut app, KeyCode::Right);
        assert_eq!(
            saved(&cmds).as_ref().map(both),
            Some((ColorSetting::Auto, PaletteSetting::Light))
        );
        assert_eq!(app.look().theme, Theme::calm(&theme::LIGHT, Depth::Indexed));
        let cmds = testkit::press(&mut app, KeyCode::Right);
        assert_eq!(
            saved(&cmds).as_ref().map(both),
            Some((ColorSetting::NoColors, PaletteSetting::Light))
        );
        assert_eq!(app.look().theme, Theme::mono());
        testkit::press(&mut app, KeyCode::Right);
        assert_eq!(
            both(app.settings()),
            (ColorSetting::Auto, PaletteSetting::Auto)
        );
        assert_eq!(app.look().theme, Theme::color(), "no NO_COLOR here");
        testkit::press(&mut app, KeyCode::Left);
        assert_eq!(
            both(app.settings()),
            (ColorSetting::NoColors, PaletteSetting::Auto)
        );
        testkit::press(&mut app, KeyCode::Right);
        assert_eq!(
            both(app.settings()),
            (ColorSetting::Auto, PaletteSetting::Auto)
        );

        choose(&mut app, SetRow::Symbols);
        for (want, glyphs) in [
            (SymbolSetting::Ascii, Glyphs::ascii()),
            (SymbolSetting::Simple, Glyphs::simple()),
            (SymbolSetting::Fancy, Glyphs::fancy()),
            // Automatic: Fancy, for a terminal with nothing set.
            (SymbolSetting::Auto, Glyphs::fancy()),
        ] {
            let cmds = testkit::press(&mut app, KeyCode::Enter);
            assert_eq!(saved(&cmds).map(|s| s.symbols), Some(want));
            assert_eq!(app.look().glyphs, glyphs, "{want:?}");
        }
        // Drawn in the new look at once.
        assert!(testkit::render(&app, 80, 24)[1].starts_with("╭ Settings ─"));
        testkit::press(&mut app, KeyCode::Left);
        assert_eq!(app.settings().symbols, SymbolSetting::Fancy);

        choose(&mut app, SetRow::OnQuit);
        for want in [OnQuit::StopIfStarted, OnQuit::Ask, OnQuit::KeepRunning] {
            let cmds = testkit::press(&mut app, KeyCode::Right);
            assert_eq!(saved(&cmds).map(|s| s.on_quit), Some(want));
        }
        testkit::press(&mut app, KeyCode::Left);
        assert_eq!(app.settings().on_quit, OnQuit::Ask);

        choose(&mut app, SetRow::ShareAddress);
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(saved(&cmds).map(|s| s.include_lan_in_card), Some(false));
        choose(&mut app, SetRow::Details);
        let cmds = testkit::press(&mut app, KeyCode::Right);
        assert_eq!(saved(&cmds).map(|s| s.show_details), Some(true));
        choose(&mut app, SetRow::LoginStart);
        for code in [KeyCode::Enter, KeyCode::Left, KeyCode::Right] {
            assert!(testkit::press(&mut app, code).is_empty(), "shown only");
        }
        choose(&mut app, SetRow::AlwaysClassic);
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        let last = saved(&cmds).expect("saved");
        assert!(last.always_classic);
        assert_eq!(
            (last.motion, last.colors, last.symbols, last.on_quit),
            (
                MotionSetting::Full,
                ColorSetting::Auto,
                SymbolSetting::Fancy,
                OnQuit::Ask
            ),
            "every change is in the save"
        );
        // The gate reads it at the next start.
        let input = GateInput {
            stdin_tty: true,
            stdout_tty: true,
            term: Some("xterm-256color".into()),
            ui_env: None,
            saved_classic: last.always_classic,
            windows_console_ok: true,
            screen_reader: false,
            default_on: true,
        };
        assert_eq!(gate::decide(&input), UiChoice::Classic);
        // Ctrl+Right and Alt+Left change nothing.
        for modifiers in [KeyModifiers::CONTROL, KeyModifiers::ALT] {
            for code in [KeyCode::Right, KeyCode::Left] {
                let key = Msg::Key(Key::Event(KeyEvent::new(code, modifiers)));
                assert!(testkit::send(&mut app, key).is_empty());
            }
        }
        assert!(app.settings().always_classic);
    }

    #[test]
    fn no_color_shows_mono_and_holds_the_colors_row() {
        let env = LookEnv {
            term: TermEnv {
                no_color: true,
                term: Some("xterm-256color".into()),
                ..TermEnv::default()
            },
            ..LookEnv::default()
        };
        let chosen = TuiState {
            symbols: SymbolSetting::Simple,
            ..TuiState::default()
        };
        let look = Look::of(&chosen, &env);
        assert_eq!(look.theme, Theme::mono(), "NO_COLOR shows mono");
        assert_eq!(look.motion, Motion::Reduced, "and moves nothing");
        let mut app = testkit::app_in(look, (80, 24));
        app.start(Session {
            look_env: env,
            settings: TuiState {
                receive: Receive::Off,
                ..chosen
            },
            ..testkit::session(Receive::Off)
        });
        open(&mut app);
        choose(&mut app, SetRow::Colors);
        let rows = testkit::render(&app, 80, 24);
        // Chosen, with no '< >': nothing changes it.
        assert!(rows.contains(
            &"│>  Colors                                  No colors (set by NO_COLOR)        │"
                .to_owned()
        ));
        assert_eq!(
            rows[23],
            "Up/Down Choose  [Esc] Back                                                      "
        );
        for code in [KeyCode::Enter, KeyCode::Left, KeyCode::Right] {
            assert!(testkit::press(&mut app, code).is_empty());
        }
        assert_eq!(app.settings().colors, ColorSetting::Auto);
        assert_eq!(app.look().theme, Theme::mono());
    }

    #[test]
    fn your_name_is_typed_then_saved_or_left() {
        let mut app = set_at((80, 24), Receive::Off, 1);
        // Enter opens the field; letters are text there, not keys.
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        for c in "Sq?".chars() {
            testkit::press(&mut app, KeyCode::Char(c));
        }
        assert!(app.overlays().is_empty());
        testkit::press(&mut app, KeyCode::Backspace);
        testkit::press(&mut app, KeyCode::Backspace);
        for c in "am ".chars() {
            testkit::press(&mut app, KeyCode::Char(c));
        }
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Settings                                  o Receiving is off  ? Help",
                "┌ Settings ────────────────────────────────────────────────────────────────────┐",
                "│   You                                                                        │",
                "│>  Your name (only on this computer)       not set                            │",
                "│   ┌──────────────────────────────────┐                                       │",
                "│   │ Sam                              │                                       │",
                "│   └──────────────────────────────────┘                                       │",
                "│                                                                              │",
                "│   Look                                                                       │",
                "│   Motion                                  Full                               │",
                "│   Colors                                  Automatic                          │",
                "│   Symbols                                 Automatic                          │",
                "│                                                                              │",
                "│   Receiving                                                                  │",
                "│   When I quit                             Keep Raven running (recommended)   │",
                "│   Receive messages on this computer       Off                                │",
                "│   Share my network address in my invite   On                                 │",
                "│   Show technical details                  Off                                │",
                "│                                                                              │",
                "│──────────────────────────────────────────────────────────────────────────────│",
                "│                                                                              │",
                "│                                                                              │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "[Enter] Save  [Esc] Cancel                                                      ",
            ],
        );
        // The terminal's own cursor after 'Sam ' in the field, under the
        // group's label and the row.
        assert_eq!(cursor(&app), Some((10, 5)));
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(saved(&cmds).map(|s| s.display_name), Some("Sam".into()));
        assert_eq!(cursor(&app), None);
        assert_eq!(state(&app).name, None);
        assert!(testkit::render(&app, 80, 24)[3]
            .starts_with("│>  Your name (only on this computer)       Sam "));
        // Esc leaves it as it was, and saves nothing.
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(state(&app).name.as_deref(), Some("Sam"));
        testkit::press(&mut app, KeyCode::Char('x'));
        assert!(testkit::press(&mut app, KeyCode::Esc).is_empty());
        assert_eq!(app.settings().display_name, "Sam");
        assert!(
            matches!(app.screen(), Screen::Settings(_)),
            "Esc closed the field only"
        );
        // A paste is one line of text, and Enter right after it is not a yes.
        testkit::press(&mut app, KeyCode::Enter);
        testkit::paste(&mut app, "\tKim\nLee\u{1b}[2J", PasteVia::Bracketed);
        assert_eq!(state(&app).name.as_deref(), Some("Sam KimLee[2J"));
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        testkit::tick(&mut app, Duration::from_millis(400));
        // The longest name Raven shows, and no more.
        for _ in 0..NAME_CELLS {
            testkit::press(&mut app, KeyCode::Char('w'));
        }
        assert!(state(&app).name_full);
        assert_eq!(
            display::width(state(&app).name.as_deref().unwrap()),
            NAME_CELLS
        );
        assert!(testkit::screen_text(&testkit::render(&app, 80, 24))
            .contains("That's the longest name Raven shows."));
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(
            saved(&cmds).map(|s| display::width(&s.display_name)),
            Some(NAME_CELLS)
        );
    }

    /// E1: the row says what the background program does, as `raven status`
    /// reads it: never Off while it receives; and one of this folder that
    /// receives answers the question never asked (On, saved).
    #[test]
    fn the_receive_row_follows_the_background_program() {
        let row = |app: &App| {
            testkit::render(app, 80, 24)
                .into_iter()
                .find(|row| row.contains(RECEIVE))
                .expect("the row")
        };
        let mut app = set_at((80, 24), Receive::Off, 1);
        testkit::send(
            &mut app,
            Msg::Poll(PollUpdate::Status(testkit::status(77, "0.0.0.0:17420"))),
        );
        assert!(
            row(&app).contains(" Off, but still receiving"),
            "{}",
            row(&app)
        );
        // Never answered, RX on screen: it closes, On is saved.
        let mut app = testkit::settled_app((80, 24), Receive::Unset, 1);
        assert!(!app.overlays().is_empty());
        let cmds = testkit::send(
            &mut app,
            Msg::Poll(PollUpdate::Status(testkit::status(77, "0.0.0.0:17420"))),
        );
        assert_eq!(saved(&cmds).map(|s| s.receive), Some(Receive::On));
        assert!(app.overlays().is_empty());
        open(&mut app);
        let words: Vec<String> = row(&app).split_whitespace().map(str::to_owned).collect();
        assert_eq!(words[words.len() - 2], "On", "{}", row(&app));
    }

    #[test]
    fn receive_off_waits_for_the_next_start_and_offers_a_stop() {
        let mut app = set_at((80, 24), Receive::On, 1);
        testkit::started_here(&mut app, 4242);
        choose(&mut app, SetRow::Receive);
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(saved(&cmds).map(|s| s.receive), Some(Receive::Off));
        assert!(!cmds.contains(&Cmd::ApplyListenLoopback), "{cmds:?}");
        assert!(state(&app).asking_stop);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Settings                            * Listening on port 7420  ? Help",
                "┌ Settings ────────────────────────────────────────────────────────────────────┐",
                "│   You                                                                        │",
                "│   Your name (only on this computer)       not set                            │",
                "│                                                                              │",
                "│   Look                                                                       │",
                "│   Motion                                  Full                               │",
                "│   Colors                                  Automatic                          │",
                "│   Symbols                                 Automatic                          │",
                "│                                                                              │",
                "│   Receiving                                                                  │",
                "│   When I quit                             Keep Raven running (recommended)   │",
                "│>  Receive messages on this computer     < Off, but still receiving >         │",
                "│   Share my network address in my invite   On                                 │",
                "│   Show technical details                  Off                                │",
                "│                                                                              │",
                "│   Privacy                                                                    │",
                "│   Start Raven when I log in               Not set up                         │",
                "│                                                                              │",
                "│──────────────────────────────────────────────────────────────────────────────│",
                "│   Stop the background program this app started? Friends can't reach you until│",
                "│   it runs again.                                                             │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "[Y] Stop  [N] Keep it running                                                   ",
            ],
        );
        // N keeps it running.
        assert!(testkit::press(&mut app, KeyCode::Char('n')).is_empty());
        assert!(!state(&app).asking_stop);
        assert!(app.node().running());
        // On again: it runs already, so nothing starts.
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(saved(&cmds).map(|s| s.receive), Some(Receive::On));
        assert!(!ensures(&cmds));
        // Off, and Y stops it.
        testkit::press(&mut app, KeyCode::Enter);
        let cmds = testkit::press(&mut app, KeyCode::Char('y'));
        assert_eq!(
            cmds,
            [Cmd::Node(NodeJob::Stop {
                started_by_app: Some(4242),
                managed: false,
            })]
        );
        assert!(app.stopping());
        // A node that ran before the app is not offered a stop.
        let mut earlier = testkit::settled_app((80, 24), Receive::On, 1);
        testkit::send(
            &mut earlier,
            Msg::Job(JobResult::Probed(testkit::status(77, "0.0.0.0:7420"))),
        );
        assert_eq!(earlier.node().started_by_app, None);
        open(&mut earlier);
        choose(&mut earlier, SetRow::Receive);
        testkit::press(&mut earlier, KeyCode::Enter);
        assert_eq!(earlier.settings().receive, Receive::Off);
        assert!(!state(&earlier).asking_stop);
    }

    #[test]
    fn receive_on_starts_now_unless_this_session_listens_locally() {
        // Off at launch, no listen override: on applies now, and the
        // background program starts as it would at launch.
        let mut app = set_at((80, 24), Receive::Off, 1);
        choose(&mut app, SetRow::Receive);
        let cmds = testkit::press(&mut app, KeyCode::Right);
        assert_eq!(saved(&cmds).map(|s| s.receive), Some(Receive::On));
        assert!(ensures(&cmds), "{cmds:?}");
        assert!(matches!(app.node().state, NodeState::Starting { .. }));
        // With no friend yet, it starts when Add a friend opens.
        let mut alone = set_at((80, 24), Receive::Off, 0);
        choose(&mut alone, SetRow::Receive);
        let cmds = testkit::press(&mut alone, KeyCode::Enter);
        assert_eq!(saved(&cmds).map(|s| s.receive), Some(Receive::On));
        assert!(!ensures(&cmds));
        // The loopback listen address was set this session: from the next
        // start, as the help line says.
        let mut local = testkit::app((80, 24));
        local.start(Session {
            listen: ListenOverride::Loopback,
            ..testkit::session(Receive::Off)
        });
        for result in [
            JobResult::Vault(Vault::default()),
            JobResult::Probed(Probe::of(
                &Err("raven-node is not running; start it".into()),
            )),
            JobResult::Managed(None),
            JobResult::Contacts {
                contacts: Ok(vec![testkit::friend(1)]),
                stamp: FileStamp::default(),
            },
        ] {
            testkit::send(&mut local, Msg::Job(result));
        }
        open(&mut local);
        choose(&mut local, SetRow::Receive);
        let cmds = testkit::press(&mut local, KeyCode::Enter);
        assert_eq!(saved(&cmds).map(|s| s.receive), Some(Receive::On));
        assert!(!ensures(&cmds), "{cmds:?}");
        let text = testkit::screen_text(&testkit::render(&local, 80, 24));
        assert!(
            text.contains("Receive messages on this computer < On >"),
            "{text}"
        );
        assert!(
            text.contains("Applies the next time you open Raven."),
            "{text}"
        );
    }

    #[test]
    fn receive_on_undoes_a_no_not_carried_out_yet() {
        // RX answered No while a load runs: the loopback listen address waits
        // for it, and so does the save.
        let mut app = testkit::settled_app((80, 24), Receive::Unset, 1);
        assert!(matches!(app.overlays(), [Overlay::Receive(_)]));
        let dir = tempfile::tempdir().unwrap();
        let stamp = FileStamp::of(dir.path());
        let cmds = testkit::send(
            &mut app,
            Msg::Poll(PollUpdate::File {
                watched: Watched::Contacts,
                stamp,
            }),
        );
        assert!(
            cmds.contains(&Cmd::Store(StoreJob::LoadContacts)),
            "{cmds:?}"
        );
        let cmds = testkit::press(&mut app, KeyCode::Char('n'));
        assert!(
            saved(&cmds).is_none() && !cmds.contains(&Cmd::ApplyListenLoopback),
            "{cmds:?}"
        );
        open(&mut app);
        choose(&mut app, SetRow::Receive);
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        // The No's save goes out, then this one's; the address is never set.
        let saves: Vec<Receive> = cmds
            .iter()
            .filter_map(|cmd| match cmd {
                Cmd::Store(StoreJob::SaveSettings(s)) => Some(s.receive),
                _ => None,
            })
            .collect();
        assert_eq!(saves, [Receive::Off, Receive::On], "{cmds:?}");
        let cmds = testkit::send(
            &mut app,
            Msg::Job(JobResult::Contacts {
                contacts: Ok(vec![testkit::friend(1)]),
                stamp,
            }),
        );
        assert!(!cmds.contains(&Cmd::ApplyListenLoopback), "{cmds:?}");
        assert_eq!(app.settings().receive, Receive::On);
    }

    #[test]
    fn the_classic_menu_now_and_nothing_after_it() {
        let mut app = set_at((80, 24), Receive::Off, 1);
        choose(&mut app, SetRow::ClassicNow);
        assert!(testkit::screen_text(&testkit::render(&app, 80, 24)).contains("[Enter] Open it"));
        // Not while a message is being sent.
        testkit::press(&mut app, KeyCode::Esc);
        testkit::press(&mut app, KeyCode::Enter);
        assert!(testkit::type_and_send(&mut app, "hi").is_some());
        testkit::press(&mut app, KeyCode::Esc);
        open(&mut app);
        choose(&mut app, SetRow::ClassicNow);
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        assert_eq!(
            app.toast().map(|t| t.text.as_str()),
            Some("Raven is still finishing (saving, or sending a message). Try again in a moment.")
        );
        testkit::send(
            &mut app,
            testkit::sent(1, testkit::delivered_to("192.168.1.11:7420")),
        );
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::SwitchToClassic]
        );
        // From then on the app asks for nothing: no job, no word to the
        // poller, whatever comes.
        for msg in [
            Msg::Tick,
            Msg::Poll(PollUpdate::File {
                watched: Watched::History,
                stamp: FileStamp::of(Path::new("/")),
            }),
            testkit::node_up(),
            Msg::Job(JobResult::Managed(None)),
        ] {
            assert!(testkit::send(&mut app, msg.clone()).is_empty(), "{msg:?}");
        }
        assert!(testkit::tick(&mut app, Duration::from_secs(60)).is_empty());
        // Only the way out itself.
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::SwitchToClassic]
        );
    }

    #[test]
    fn reduced_motion_wakes_for_no_frame() {
        let mut app = set_at((80, 24), Receive::On, 1);
        assert!(matches!(app.node().state, NodeState::Starting { .. }));
        let now = app.now();
        app.mark_drawn(now);
        let wait = anim::next_wait(&app, now).expect("the chip's spinner turns");
        assert!(wait <= Duration::from_millis(83), "{wait:?}");
        choose(&mut app, SetRow::Motion);
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(app.look().motion, Motion::Reduced);
        app.mark_drawn(app.now());
        assert_eq!(anim::next_wait(&app, app.now()), None);
        testkit::press(&mut app, KeyCode::Esc);
        // Home wakes for its clock's text alone, on the next whole second
        // (UXF.10): no animation frame.
        assert_eq!(
            anim::next_wait(&app, app.now()),
            Some(Duration::from_secs(1)),
            "Home: its clock alone"
        );
        let frames: Vec<Vec<String>> = [0, 83, 166]
            .into_iter()
            .map(|ms| testkit::render_at(&app, 80, 24, now + Duration::from_millis(ms)))
            .collect();
        assert!(frames.windows(2).all(|w| w[0] == w[1]));
    }

    #[test]
    fn technical_details_show_at_once_when_asked() {
        let mut app = testkit::app((80, 24));
        let denied =
            raven_core::IdentityStoreError::SecureStore("keychain get status -25293".into());
        app.start(Session {
            identity: IdentityStart::Unavailable(denied.redacted_display()),
            settings: TuiState {
                show_details: true,
                ..TuiState::default()
            },
            ..testkit::session(Receive::Off)
        });
        assert!(matches!(app.screen(), Screen::IdentityError(failure) if failure.details));
    }

    #[test]
    fn settings_persist_across_a_restart() {
        testkit::lab_backends();
        let dir = testkit::short_dir();
        let controller = Controller::new(dir.path());
        let me = controller.create_identity().result.expect("create").me;
        let mut app = testkit::app((80, 24));
        app.start(Session {
            identity: IdentityStart::Ready(me),
            data_dir: dir.path().into(),
            settings: state_file::peek(dir.path()),
            ..testkit::session(Receive::On)
        });
        open(&mut app);
        let mut keys = vec![KeyCode::Enter];
        keys.extend("Sam".chars().map(KeyCode::Char));
        keys.extend([
            KeyCode::Enter,
            KeyCode::Down,
            KeyCode::Enter, // Motion: Reduced
            KeyCode::Down,
            KeyCode::Left, // Colors: No colors (Automatic, Dark, Light, No colors)
            KeyCode::Down,
            KeyCode::Left, // Symbols: Fancy
            KeyCode::Down,
            KeyCode::Right, // When I quit: Stop Raven if this app started it
            KeyCode::Down,
            KeyCode::Enter, // Receive: On (never answered before)
            KeyCode::Down,
            KeyCode::Enter, // Share my address: Off
            KeyCode::Down,
            KeyCode::Enter, // Details: On
            KeyCode::Down,
            KeyCode::Down,
            KeyCode::Down,
            KeyCode::Enter, // Always open the classic menu: On
        ]);
        for key in keys {
            for cmd in testkit::press(&mut app, key) {
                if let Cmd::Store(job) = cmd {
                    let result = workers::store_job(&controller, job);
                    assert!(
                        !matches!(result, JobResult::SettingsSaved(Err(_))),
                        "{result:?}"
                    );
                    testkit::send(&mut app, Msg::Job(result));
                }
            }
        }
        let chosen = app.settings().clone();
        assert_eq!(chosen.display_name, "Sam");
        assert!(chosen.always_classic && chosen.show_details && !chosen.include_lan_in_card);
        assert_eq!(chosen.receive, Receive::On);

        // Raven opens again: the same settings, and the same look.
        let back = state_file::peek(dir.path());
        assert_eq!(back, chosen);
        let again = Controller::new(dir.path());
        let IdentityState::Ready { me, .. } = again.load_identity() else {
            panic!("the identity is there");
        };
        let look = Look::of(&back, &LookEnv::default());
        assert_eq!(
            (look.motion, look.theme, look.glyphs),
            (Motion::Reduced, Theme::mono(), Glyphs::fancy())
        );
        let mut restarted = testkit::app_in(look, (80, 24));
        restarted.start(Session {
            identity: IdentityStart::Ready(me),
            data_dir: dir.path().into(),
            settings: back,
            ..testkit::session(Receive::On)
        });
        open(&mut restarted);
        testkit::press(&mut app, KeyCode::Esc);
        open(&mut app);
        assert_eq!(
            testkit::render(&restarted, 80, 24)[2..13],
            testkit::render(&app, 80, 24)[2..13]
        );
    }

    // ── Keep chats for (privacy pack PP.21) ─────────────────────────────────

    /// SET at `size` once the privacy read answered: chats kept for `keep`.
    fn keep_set_at(size: (u16, u16), keep: ChatKeepView) -> App {
        let mut app = testkit::settled_app(size, Receive::Off, 1);
        testkit::privacy_on(&mut app, keep, Default::default());
        open(&mut app);
        app
    }

    /// The chat-keeping saves `cmds` ask for.
    fn keep_saves(cmds: &[Cmd]) -> Vec<ChatKeepView> {
        cmds.iter()
            .filter_map(|cmd| match cmd {
                Cmd::Store(StoreJob::SetChatKeep(keep)) => Some(*keep),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn keep_chats_for_is_a_row_once_the_privacy_read_answered() {
        // Not available: no row, and the rows go round without it.
        let mut hidden = set_at((80, 24), Receive::Off, 1);
        assert!(!hidden.set_rows().contains(&SetRow::KeepChats));
        assert!(!testkit::screen_text(&testkit::render(&hidden, 80, 24)).contains("Keep chats"));
        choose(&mut hidden, SetRow::Details);
        testkit::press(&mut hidden, KeyCode::Down);
        assert_eq!(state(&hidden).row, SetRow::LoginStart);
        // Available: after 'Show technical details', its help line under it.
        let mut app = keep_set_at((80, 24), ChatKeepView::Days30);
        choose(&mut app, SetRow::KeepChats);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Settings                                  o Receiving is off  ? Help",
                "┌ Settings ────────────────────────────────────────────────────────────────────┐",
                "│   You                                                                        │",
                "│   Your name (only on this computer)       not set                            │",
                "│                                                                              │",
                "│   Look                                                                       │",
                "│   Motion                                  Full                               │",
                "│   Colors                                  Automatic                          │",
                "│   Symbols                                 Automatic                          │",
                "│                                                                              │",
                "│   Receiving                                                                  │",
                "│   When I quit                             Keep Raven running (recommended)   │",
                "│   Receive messages on this computer       Off                                │",
                "│   Share my network address in my invite   On                                 │",
                "│   Show technical details                  Off                                │",
                "│                                                                              │",
                "│   Privacy                                                                    │",
                "│>  Keep chats for                          30 days                            │",
                "│   Start Raven when I log in               Not set up                         │",
                "│──────────────────────────────────────────────────────────────────────────────│",
                "│   Older chats are deleted from this computer. Your friends' copies aren't.   │",
                "│                                                                              │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "Up/Down Choose  [Enter] Change  [Esc] Back                                      ",
            ],
        );
        let mut app = keep_set_at((60, 16), ChatKeepView::Keep);
        choose(&mut app, SetRow::KeepChats);
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N - Settings              o Receiving is off  ? Help",
                "┌ Settings ────────────────────────────────────────────────┐",
                "│                                                          │",
                "│   Receiving                                              │",
                "│   When I quit: Keep Raven running (recommended)          │",
                "│   Receive messages on this computer: Off                 │",
                "│   Share my network address in my invite: On              │",
                "│   Show technical details: Off                            │",
                "│                                                          │",
                "│   Privacy                                                │",
                "│>  Keep chats for: Always (until you delete them)         │",
                "│──────────────────────────────────────────────────────────│",
                "│   Raven keeps your chats on this computer until you      │",
                "│   delete them.                                           │",
                "└──────────────────────────────────────────────────────────┘",
                "Up/Down Choose  [Enter] Change  [Esc] Back                  ",
            ],
        );
        // A read that says not available later takes it away again.
        testkit::send(
            &mut app,
            Msg::Job(JobResult::Privacy(Err(bridge::NotAvailable))),
        );
        assert_eq!(state(&app).row, SetRow::Details);
        assert!(!app.set_rows().contains(&SetRow::KeepChats));
    }

    #[test]
    fn keep_opens_a_chooser_and_saves_once_per_change() {
        let mut app = keep_set_at((80, 24), ChatKeepView::Days30);
        choose(&mut app, SetRow::KeepChats);
        // Enter, Right and Left each open KEEP on the setting; nothing saves.
        for code in [KeyCode::Enter, KeyCode::Right, KeyCode::Left] {
            let cmds = testkit::press(&mut app, code);
            assert!(cmds.is_empty(), "{cmds:?}");
            assert_eq!(
                app.overlays(),
                [Overlay::KeepChats {
                    choice: ChatKeepView::Days30
                }]
            );
            testkit::press(&mut app, KeyCode::Esc);
            assert!(app.overlays().is_empty());
        }
        testkit::press(&mut app, KeyCode::Enter);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Settings                                  o Receiving is off  ? Help",
                "┌ Settings ────────────────────────────────────────────────────────────────────┐",
                "│   You                                                                        │",
                "│   Your name (only on this computer)       not set                            │",
                "│                                                                              │",
                "│   Look┌──────────────────────────────────────────────────────────────┐       │",
                "│   Moti│ Keep chats for                                               │       │",
                "│   Colo│                                                              │       │",
                "│   Symb│   7 days                                                     │       │",
                "│       │ > 30 days                                                    │       │",
                "│   Rece│   90 days                                                    │       │",
                "│   When│   Keep                                                       │ded)   │",
                "│   Rece│                                                              │       │",
                "│   Shar│ Older chats are deleted from this computer. Your friends'    │       │",
                "│   Show│ copies aren't.                                               │       │",
                "│       │                                                              │       │",
                "│   Priv│ Up/Down Choose   [Enter] Save   [Esc] Cancel                 │       │",
                "│>  Keep└──────────────────────────────────────────────────────────────┘       │",
                "│   Start Raven when I log in               Not set up                         │",
                "│──────────────────────────────────────────────────────────────────────────────│",
                "│   Older chats are deleted from this computer. Your friends' copies aren't.   │",
                "│                                                                              │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "Up/Down Choose  [Enter] Change  [Esc] Back                                      ",
            ],
        );
        // Moving saves nothing; Esc keeps the setting.
        assert!(testkit::press(&mut app, KeyCode::Down).is_empty());
        assert!(testkit::press(&mut app, KeyCode::Esc).is_empty());
        assert_eq!(
            app.privacy().map(|read| read.keep),
            Some(ChatKeepView::Days30)
        );
        // The same value again: no save.
        testkit::press(&mut app, KeyCode::Enter);
        assert!(keep_saves(&testkit::press(&mut app, KeyCode::Enter)).is_empty());
        // 90 days: exactly one save, and the row says it at once.
        testkit::press(&mut app, KeyCode::Enter);
        testkit::press(&mut app, KeyCode::Down);
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(keep_saves(&cmds), [ChatKeepView::Days90]);
        assert_eq!(cmds.len(), 1, "{cmds:?}");
        assert!(app.overlays().is_empty());
        assert_eq!(
            app.privacy().map(|read| read.keep),
            Some(ChatKeepView::Days90)
        );
        assert!(
            testkit::screen_text(&testkit::render(&app, 80, 24)).contains("Keep chats for 90 days")
        );
        // Its answer reads the setting again, and saves nothing more.
        let cmds = testkit::send(
            &mut app,
            Msg::Job(JobResult::ChatKeepSaved {
                keep: ChatKeepView::Days90,
                result: Ok(()),
            }),
        );
        assert_eq!(cmds, [Cmd::Store(StoreJob::LoadPrivacy)]);
        // KEEP shows the chooser at 60x16 too, on 'Keep' (k and j move).
        let mut small = keep_set_at((60, 16), ChatKeepView::Days7);
        choose(&mut small, SetRow::KeepChats);
        testkit::press(&mut small, KeyCode::Enter);
        for _ in 0..5 {
            testkit::press(&mut small, KeyCode::Char('j'));
        }
        testkit::assert_rows(
            &testkit::render(&small, 60, 16),
            &[
                "R A V E N - Settings              o Receiving is off  ? Help",
                "┌──────────────────────────────────────────────────────────┐",
                "│ Keep chats for                                           │",
                "│                                                          │",
                "│   7 days                                                 │",
                "│   30 days                                                │",
                "│   90 days                                                │",
                "│ > Keep                                                   │",
                "│                                                          │",
                "│ Raven keeps your chats on this computer until you delete │",
                "│ them.                                                    │",
                "│                                                          │",
                "│ Up/Down Choose   [Enter] Save   [Esc] Cancel             │",
                "└──────────────────────────────────────────────────────────┘",
                "└──────────────────────────────────────────────────────────┘",
                "Up/Down Choose  [Enter] Change  [Esc] Back                  ",
            ],
        );
        let cmds = testkit::press(&mut small, KeyCode::Enter);
        assert_eq!(keep_saves(&cmds), [ChatKeepView::Keep]);
        // A save that failed: a toast, and the setting is read again.
        let cmds = testkit::send(
            &mut small,
            Msg::Job(JobResult::ChatKeepSaved {
                keep: ChatKeepView::Keep,
                result: Err("privacy.json corrupt".into()),
            }),
        );
        assert_eq!(cmds, [Cmd::Store(StoreJob::LoadPrivacy)]);
        assert!(small.toast().is_some_and(|toast| toast
            .text
            .starts_with("Raven couldn't save how long chats are kept")));
    }

    // ── Erase Raven from this computer (privacy pack PP.22) ─────────────────

    #[test]
    fn erase_is_the_last_row_once_the_privacy_read_answered() {
        // Not available: no row; Lock now stays the last.
        let mut hidden = set_at((80, 24), Receive::Off, 1);
        assert!(!hidden.set_rows().contains(&SetRow::Erase));
        assert!(!testkit::screen_text(&testkit::render(&hidden, 80, 24)).contains("Erase Raven"));
        choose(&mut hidden, SetRow::LockNow);
        testkit::press(&mut hidden, KeyCode::Down);
        assert_eq!(state(&hidden).row, SetRow::LockNow);
        // Available: the last row, an action with no value.
        let mut app = keep_set_at((80, 24), ChatKeepView::Days30);
        assert_eq!(app.set_rows().last(), Some(&SetRow::Erase));
        choose(&mut app, SetRow::Erase);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24)[13..],
            &[
                "│   Switch to the classic menu now                                             │",
                "│   Always open the classic menu            Off                                │",
                "│                                                                              │",
                "│   Lock                                                                       │",
                "│   Lock now                                                                   │",
                "│>  Erase Raven from this computer                                             │",
                "│──────────────────────────────────────────────────────────────────────────────│",
                "│                                                                              │",
                "│                                                                              │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "Up/Down Choose  [Enter] Erase  [Esc] Back                                       ",
            ],
        );
        let mut small = keep_set_at((60, 16), ChatKeepView::Days30);
        choose(&mut small, SetRow::Erase);
        testkit::assert_rows(
            &testkit::render(&small, 60, 16),
            &[
                "R A V E N - Settings              o Receiving is off  ? Help",
                "┌ Settings ────────────────────────────────────────────────┐",
                "│   Start Raven when I log in: Not set up                  │",
                "│                                                          │",
                "│   Classic menu                                           │",
                "│   Switch to the classic menu now                         │",
                "│   Always open the classic menu: Off                      │",
                "│                                                          │",
                "│   Lock                                                   │",
                "│   Lock now                                               │",
                "│>  Erase Raven from this computer                         │",
                "│──────────────────────────────────────────────────────────│",
                "│                                                          │",
                "│                                                          │",
                "└──────────────────────────────────────────────────────────┘",
                "Up/Down Choose  [Enter] Erase  [Esc] Back                   ",
            ],
        );
        // Right and Left change nothing; Enter opens ERASE and reads what
        // goes, nothing more.
        assert!(testkit::press(&mut app, KeyCode::Right).is_empty());
        assert!(testkit::press(&mut app, KeyCode::Left).is_empty());
        assert!(app.overlays().is_empty());
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Store(StoreJob::ErasePlan)]
        );
        assert_eq!(app.overlays(), [Overlay::Erase(EraseState::Reading)]);
        // A read that says not available later takes the row away, and
        // ERASE before its erase began.
        testkit::send(
            &mut app,
            Msg::Job(JobResult::Privacy(Err(bridge::NotAvailable))),
        );
        assert!(app.overlays().is_empty());
        assert_eq!(state(&app).row, SetRow::LockNow);
        assert!(!app.set_rows().contains(&SetRow::Erase));
        assert!(testkit::press(&mut app, KeyCode::Enter)
            .iter()
            .all(|cmd| *cmd != Cmd::Store(StoreJob::ErasePlan)));
    }

    #[test]
    fn keep_waits_out_the_paste_guard() {
        let mut app = keep_set_at((80, 24), ChatKeepView::Days30);
        choose(&mut app, SetRow::KeepChats);
        testkit::press(&mut app, KeyCode::Enter);
        testkit::press(&mut app, KeyCode::Up);
        // A pasted line break, then Enter at once: no answer.
        testkit::send(&mut app, Msg::Key(Key::PastedEnter));
        assert!(keep_saves(&testkit::press(&mut app, KeyCode::Enter)).is_empty());
        assert!(matches!(app.overlays(), [Overlay::KeepChats { .. }]));
        testkit::tick(&mut app, Duration::from_millis(300));
        assert_eq!(
            keep_saves(&testkit::press(&mut app, KeyCode::Enter)),
            [ChatKeepView::Days7]
        );
    }
}
