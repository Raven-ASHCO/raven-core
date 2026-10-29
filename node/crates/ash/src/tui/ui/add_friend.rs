//! AF-1, COPY, AF-2 and NAME-CLASH: a friend added from their invite or
//! card.
//!
//! - AF-1 shares my invite and takes theirs. The share box shows my card
//!   with this computer's address only once a node listens on the network
//!   (the App's [`ShareView`]); otherwise why not, and S for the invite
//!   without one. The paste box shows what was pasted with any security code
//!   in it masked, and once it parses only a summary: the friend's code is
//!   never on screen before the user has typed it as the friend reads it.
//! - COPY's lines ([`copy_lines`]) are printed on the plain terminal, where
//!   the terminal tracks the soft wraps of a long line, so it copies whole.
//! - AF-2 asks what to call the friend (the first time, its hint says to
//!   use a nickname: UXF.9); NAME-CLASH warns when the name is a verified
//!   friend's and the key is not.
//!
//! When a window is short, AF-1's least needed rows give way first (the
//! title, then the explanations), never the card, the keys or the field's
//! last row. Every untrusted string (the pasted text, addresses, names) goes
//! through display.rs.

use std::time::{Duration, Instant};

use ratatui::layout::{Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Padding, Paragraph};
use ratatui::Frame;

use super::anim::{self, Moving};
use super::app::{
    self, AddFocus, AddFriendState, App, ClashState, NameProblem, Screen, ShareState, ShareView,
};
#[cfg(test)]
use super::app::{JobResult, Msg, PasteVia};
use super::bridge::{ContactView, FriendPreview};
use super::controller::{self, NameWarning, PasteProblem};
#[cfg(test)]
use super::render as render_frame;
#[cfg(test)]
use super::state_file::Receive;
#[cfg(test)]
use super::{bridge, node};
use super::{cells, display, overlays, render_header, verify, widgets, wizard, wrap, Look};
#[cfg(test)]
use super::{testkit, theme};

/// The summary of a paste fades from bold to normal over this long.
const FADE_TIME: Duration = Duration::from_millis(600);
/// The paste box shows this many rows of what was pasted, at most: its end.
const FIELD_ROWS: usize = 4;
/// A shortened address or PeerId keeps this many characters of each end.
const SHORT_HEAD: usize = 10;
const SHORT_TAIL: usize = 6;

/// AF-1.
const TITLE: &str = "Add a friend";
const STEPS: [&str; 3] = ["1 Share yours", "2 Paste theirs", "3 Check codes"];
const NETWORK: &str = "In this version, you and your friend must be on the same network (the \
                       same Wi-Fi or office network).";
const SHARE_TITLE: &str = " Share yours ";
const PASTE_TITLE: &str = " Paste theirs ";
const SEND_THIS: &str = "Send this to your friend (in a message, an email, or show them):";
const PUBLIC_ONLY: &str =
    "It holds only public information. Your private key never leaves this computer.";
const COPY_KEY: &str = "[C] Show it alone so you can copy it";
const VPN_NOTE: &str = "This address doesn't look like a home or office network address. If \
                        your friend can't reach you, a VPN may be on.";
/// The spinner's words take the glyph set's ellipsis.
const STARTING: &str = "Starting Raven so your friend can reach you";
const RECEIVE_OFF: &str = "Receiving is off on this computer, so your invite would have no \
                           address and your friend couldn't send you the first message. Turn \
                           receiving on in Settings, or [S] show my invite anyway.";
const NEEDS_SETUP: &str = "Raven's background program can't start on this computer yet: it \
                           needs your passphrase in a private file. Press N to see how. [S] \
                           Show my invite anyway";
const NO_ADDRESS: &str =
    "Raven can't tell this computer's network address. [S] Show my invite anyway";
const SHOW_ANYWAY: &str = "[S] Show my invite anyway";
/// Under an invite with no address (after S, or with L off).
const WITHOUT_ADDRESS: &str = "Your invite has no address, so your friend can't send you the \
                               first message. You can send first once you have their invite.";
const PASTE_LABEL: &str = "Paste your friend's invite or card:";
const PLACEHOLDER: &str =
    "Paste here with your terminal's paste (for example Ctrl+Shift+V, Cmd+V or right-click)";
const NOT_A_CARD: &str = "That doesn't look like a Raven invite or card.";
const OWN_INVITE: &str = "That's your own invite. Paste your friend's instead.";
const TAMPERED: &str = "This invite doesn't add up: its address and key don't match. Ask your \
                        friend to send it again.";
const WRONG_CODE: &str = "That code didn't match, so here is a new one.";
const KEYS: [(&str, &str); 5] = [
    ("Tab", "Switch box"),
    ("L", "Address on/off"),
    ("C", "Copy view"),
    ("Enter", "Continue"),
    ("Esc", "Cancel"),
];

/// COPY.
const COPY_HEADING: &str =
    "Your Raven invite. Select the line below and copy it with your terminal:";
const COPY_FOOTER: &str = "It holds only public information. Press any key to go back to Raven.";
/// The first time only (UXF.9): the invite carries this computer's address.
const COPY_CLEAR: &str = "Clear this from the terminal afterwards (it stays in the scrollback).";
const COPY_WINDOWS: &str =
    "In this window: select the line with the mouse, then press Enter or right-click to copy.";

/// AF-2.
const NAME_TITLE: &str = "Who is this?";
const NO_ROUTE: &str = "No network address included. You can add one later.";
const LAN_ONLY_HERE: &str = "This invite has no local-network address, and this version of \
                             Raven can only use the local network.";
const REACHED_AT: &str = "Can be reached at: ";
const PREVIEW: &str = ", Preview, not in this release";
pub(super) const NAME_QUESTION: &str = "What do you want to call them?";
pub(super) const NAME_PLACEHOLDER: &str = "Name";
pub(super) const NAME_LOCAL: &str = "This name is only on this computer.";
/// AF-2's hint in NAME_LOCAL's place, the first time (UXF.9).
const NAME_NICKNAME: &str =
    "Names here stay on this computer. Use a nickname if someone may look at this laptop.";
pub(super) const NAME_LIMIT: &str = "That's the longest name Raven shows.";
const NAME_EMPTY: &str = "Give your friend a name.";
const MIXED_SCRIPT: &str = "This name mixes letters from different alphabets, so it can look \
                            like another name. Check it before you save.";
const NAME_KEYS: [(&str, &str); 2] = [("[Enter]", " Next"), ("[Esc]", " Back")];

/// AF-1's rows that give way, lowest first, when the window is short.
const DROP_TITLE: u8 = 1;
const DROP_PUBLIC: u8 = 2;
const DROP_NETWORK: u8 = 3;
const DROP_FIELD: u8 = 4;
const DROP_SEND_THIS: u8 = 5;
const DROP_PASTE_LABEL: u8 = 6;
const DROP_VPN: u8 = 7;

/// What moves on AF-1 (anim.rs asks): the share box's spinner while Raven
/// starts, and the summary of a paste fading from bold.
pub(crate) fn moving(app: &App) -> Vec<Moving> {
    let mut moving = Vec::new();
    let Screen::AddFriend(add) = app.screen() else {
        return moving;
    };
    if add.naming {
        return moving;
    }
    if let Some(ShareState::Starting { since }) = app.share_view().map(|view| view.state) {
        moving.push(Moving::Spinner { since });
    }
    if let (Some(start), Some(_)) = (add.parsed_at, add.friend()) {
        moving.push(Moving::Transition {
            start,
            frames: 1,
            length: FADE_TIME,
        });
    }
    moving
}

/// COPY's lines for my invite `line`: a heading, a blank line, the line, a
/// blank line, with `clear` the note to clear it afterwards, and the footer;
/// on Windows how its console copies.
pub(crate) fn copy_lines(line: &str, windows: bool, clear: bool) -> Vec<String> {
    let mut lines = vec![
        COPY_HEADING.to_owned(),
        String::new(),
        display::one_line(line, u16::MAX, ""),
        String::new(),
    ];
    if clear {
        lines.push(COPY_CLEAR.to_owned());
    }
    lines.push(COPY_FOOTER.to_owned());
    if windows {
        lines.push(COPY_WINDOWS.to_owned());
    }
    lines
}

/// Rows of AF-1 that stay or go together.
struct Part {
    lines: Vec<Line<'static>>,
    /// When it gives way in a short window, lowest first; None: it stays.
    drop: Option<u8>,
    /// The terminal's cursor goes after this many cells of its last row.
    cursor: Option<u16>,
}

impl Part {
    fn keep(lines: Vec<Line<'static>>) -> Part {
        Part {
            lines,
            drop: None,
            cursor: None,
        }
    }

    fn droppable(lines: Vec<Line<'static>>, rank: u8) -> Part {
        Part {
            drop: Some(rank),
            ..Part::keep(lines)
        }
    }

    fn rows(parts: &[Part]) -> usize {
        parts.iter().map(|part| part.lines.len()).sum()
    }
}

/// Draws AF-1 (or AF-2, once the paste parsed and Enter went on): the header
/// row, the title and the network sentence, the share box, the paste box
/// and the key hints. The cursor sits in the paste box while it has the
/// keys and takes text.
pub(super) fn render(f: &mut Frame, area: Rect, app: &App, add: &AddFriendState, now: Instant) {
    if area.is_empty() {
        return;
    }
    if add.naming {
        return render_name(f, area, app, add, now);
    }
    let look = app.look();
    render_header(f, area, app, now, false);
    if area.height > 1 {
        let last = Rect {
            y: area.bottom() - 1,
            height: 1,
            ..area
        };
        f.render_widget(
            Paragraph::new(widgets::key_bar(look, &KEYS, area.width)),
            last,
        );
    }
    let body = Rect {
        y: area.y.saturating_add(1),
        height: area.height.saturating_sub(2),
        ..area
    };
    if body.is_empty() {
        return;
    }
    // Inside a box: its border and padding take four cells.
    let width = body.width.saturating_sub(4);
    let mut top = top_parts(look, add, body.width);
    let mut share = share_parts(app, width, now);
    let mut paste = paste_parts(app, add, width, now);
    fit([&mut top, &mut share, &mut paste], usize::from(body.height));

    let room = body.height;
    let top_rows = u16::try_from(Part::rows(&top))
        .unwrap_or(u16::MAX)
        .min(room);
    let paste_rows = u16::try_from(Part::rows(&paste) + 2)
        .unwrap_or(u16::MAX)
        .min(room - top_rows);
    let share_rows = u16::try_from(Part::rows(&share) + 2)
        .unwrap_or(u16::MAX)
        .min(room - top_rows - paste_rows);
    let top_rect = Rect {
        height: top_rows,
        ..body
    };
    let share_rect = Rect {
        y: top_rect.bottom(),
        height: share_rows,
        ..body
    };
    let paste_rect = Rect {
        y: share_rect.bottom(),
        height: paste_rows,
        ..body
    };
    f.render_widget(Paragraph::new(lines_of(top)), top_rect);
    let focused = add.focus;
    f.render_widget(
        Paragraph::new(lines_of(share)).block(box_block(
            look,
            SHARE_TITLE,
            focused == AddFocus::Share,
        )),
        share_rect,
    );
    let cursor = cursor_row(&paste);
    let paste_block = box_block(look, PASTE_TITLE, focused == AddFocus::Paste);
    let inner = paste_block.inner(paste_rect);
    f.render_widget(
        Paragraph::new(lines_of(paste)).block(paste_block),
        paste_rect,
    );
    if let Some((row, col)) = cursor {
        let y = u16::try_from(row).unwrap_or(u16::MAX);
        if focused == AddFocus::Paste && app.overlays().is_empty() && y < inner.height {
            let x = inner.x + col.min(inner.width.saturating_sub(1));
            f.set_cursor_position(Position::new(x, inner.y + y));
        }
    }
}

/// Takes the droppable parts out, lowest rank first (the first of a rank
/// first), until the parts and the two boxes' borders fit in `room` rows.
fn fit(groups: [&mut Vec<Part>; 3], room: usize) {
    loop {
        let rows: usize = groups.iter().map(|parts| Part::rows(parts)).sum::<usize>() + 4;
        if rows <= room {
            return;
        }
        let lowest = groups
            .iter()
            .enumerate()
            .flat_map(|(g, parts)| {
                parts
                    .iter()
                    .enumerate()
                    .filter_map(move |(i, part)| part.drop.map(|rank| (rank, g, i)))
            })
            .min();
        let Some((_, g, i)) = lowest else {
            return;
        };
        groups[g].remove(i);
    }
}

fn lines_of(parts: Vec<Part>) -> Vec<Line<'static>> {
    parts.into_iter().flat_map(|part| part.lines).collect()
}

/// The row (from the top of the parts) and the column the cursor goes to.
fn cursor_row(parts: &[Part]) -> Option<(usize, u16)> {
    let mut row = 0;
    for part in parts {
        row += part.lines.len();
        if let Some(col) = part.cursor {
            return Some((row.saturating_sub(1), col));
        }
    }
    None
}

/// A box with `title` on its border (Calm): the accent colour and a bold
/// title on the one with the keys, faint with a dim title otherwise.
fn box_block(look: &Look, title: &'static str, focused: bool) -> Block<'static> {
    let t = &look.theme;
    let (border, title_style) = if focused {
        (t.accent, t.accent.add_modifier(Modifier::BOLD))
    } else {
        (t.faint, t.secondary)
    };
    Block::bordered()
        .border_set(look.glyphs.border)
        .border_style(border)
        .padding(Padding::horizontal(1))
        .title(Span::styled(title, title_style))
}

/// AF-1's title with the step strip (the step the focused box is in shown
/// bold), then the network sentence.
fn top_parts(look: &Look, add: &AddFriendState, width: u16) -> Vec<Part> {
    let current = match add.focus {
        AddFocus::Share => 0,
        AddFocus::Paste => 1,
    };
    let mut strip = Vec::new();
    for (i, step) in STEPS.iter().enumerate() {
        if i > 0 {
            strip.push(Span::styled(look.glyphs.separator, look.theme.secondary));
        }
        let style = if i == current {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            look.theme.secondary
        };
        strip.push(Span::styled(*step, style));
    }
    let strip = Line::from(strip);
    let title = Span::styled(TITLE, look.theme.title);
    let separator = look.glyphs.separator;
    let lines = if cells(TITLE) + cells(separator) + strip.width() <= usize::from(width) {
        let mut spans = vec![title, Span::raw(separator)];
        spans.extend(strip.spans);
        vec![Line::from(spans)]
    } else {
        vec![Line::from(title), strip]
    };
    vec![
        Part::droppable(lines, DROP_TITLE),
        Part::droppable(rows(NETWORK, width), DROP_NETWORK),
    ]
}

/// The share box's rows: my card (dimmed) with what it holds and the keys
/// for it, or why it can't be shared yet and S.
fn share_parts(app: &App, width: u16, now: Instant) -> Vec<Part> {
    let Some(view) = app.share_view() else {
        return Vec::new();
    };
    let look = app.look();
    match &view.state {
        ShareState::Starting { since } => vec![Part::keep(vec![Line::from(vec![
            widgets::spinner(look, *since, now),
            Span::raw(" "),
            Span::raw(format!("{STARTING}{}", look.glyphs.ellipsis)),
        ])])],
        ShareState::Ready { lan } => {
            let mut parts = card_parts(look, &view, width);
            parts.push(Part::droppable(rows(PUBLIC_ONLY, width), DROP_PUBLIC));
            let lan = display::one_line(lan, u16::MAX, "");
            let toggle = if app.settings().include_lan_in_card {
                format!(
                    "[L] Include my network address ({lan}): On. Anyone you send this to can \
                     see it."
                )
            } else {
                format!("[L] Include my network address ({lan}): Off.")
            };
            parts.push(Part::keep(keyed_rows(&toggle, width, look)));
            if !view.with_address {
                parts.push(Part::keep(rows(WITHOUT_ADDRESS, width)));
            } else if !private_address(&lan) {
                parts.push(Part::droppable(
                    styled_rows(VPN_NOTE, width, look.theme.warn),
                    DROP_VPN,
                ));
            }
            if view.line.is_some() {
                parts.push(Part::keep(keyed_rows(COPY_KEY, width, look)));
            }
            parts
        }
        // After S: the invite without an address, and what that means.
        _ if view.line.is_some() => {
            let mut parts = card_parts(look, &view, width);
            parts.push(Part::keep(rows(WITHOUT_ADDRESS, width)));
            parts.push(Part::droppable(rows(PUBLIC_ONLY, width), DROP_PUBLIC));
            parts.push(Part::keep(keyed_rows(COPY_KEY, width, look)));
            parts
        }
        state => vec![Part::keep(keyed_rows(&not_ready(state), width, look))],
    }
}

/// 'Send this to your friend' and the card, dimmed, broken to the box so
/// none of it is cut off (COPY shows it as one line).
fn card_parts(look: &Look, view: &ShareView, width: u16) -> Vec<Part> {
    let mut parts = vec![Part::droppable(rows(SEND_THIS, width), DROP_SEND_THIS)];
    if let Some(line) = &view.line {
        let card = display::one_line(line, u16::MAX, "");
        parts.push(Part::keep(
            overlays::wrap_command(&card, width)
                .into_iter()
                .map(|row| Line::styled(row, look.theme.secondary))
                .collect(),
        ));
    }
    parts
}

/// What the share box says in a state that can't share my address.
fn not_ready(state: &ShareState) -> String {
    match state {
        ShareState::LocalOnly { ip } => format!(
            "Raven's background program is only listening on this computer ({ip}), so your \
             friend can't reach you. Press N to see how to change it. {SHOW_ANYWAY} (without an \
             address)"
        ),
        ShareState::ReceiveOff => RECEIVE_OFF.to_owned(),
        ShareState::NeedsSetup => NEEDS_SETUP.to_owned(),
        ShareState::Failed(why) => format!("{why}. {SHOW_ANYWAY}"),
        ShareState::NoAddress => NO_ADDRESS.to_owned(),
        ShareState::Starting { .. } | ShareState::Ready { .. } => String::new(),
    }
}

/// Whether `lan` (`ip:port`) is on a home or office network: 10/8,
/// 172.16/12 or 192.168/16. Anything else may be a VPN's.
fn private_address(lan: &str) -> bool {
    match lan.parse::<std::net::SocketAddr>() {
        Ok(std::net::SocketAddr::V4(at)) => {
            let [a, b, ..] = at.ip().octets();
            a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
        }
        _ => false,
    }
}

/// The paste box's rows: the label, the field (the summary once the paste
/// parsed, else what was pasted with its code masked, or the placeholder)
/// and what the paste is.
fn paste_parts(app: &App, add: &AddFriendState, width: u16, now: Instant) -> Vec<Part> {
    let look = app.look();
    let takes_text = add.update.is_none() && add.friend().is_none();
    let mut parts = vec![Part::droppable(rows(PASTE_LABEL, width), DROP_PASTE_LABEL)];
    if let Some(friend) = add.friend() {
        let fading = add.parsed_at.is_some_and(|start| {
            anim::transition_frame(start, now, 1, FADE_TIME, look.motion) == 0
        });
        let style = if fading {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        parts.push(Part::keep(
            rows(&summary(friend, look), width)
                .into_iter()
                .map(|line| line.style(style))
                .collect(),
        ));
    } else {
        let (field, style): (Vec<String>, Style) = if add.text.is_empty() {
            (wrap(PLACEHOLDER, width, 0), look.theme.secondary)
        } else {
            let masked = display::mask_card_fingerprint(&add.text);
            let all: Vec<String> = masked
                .split('\n')
                .flat_map(|line| overlays::wrap_command(line, width))
                .collect();
            let start = all.len().saturating_sub(FIELD_ROWS);
            (all[start..].to_vec(), Style::default())
        };
        // The cursor: at the placeholder's start, or after the text.
        let (cursor_at, col) = if add.text.is_empty() {
            (0, 0)
        } else {
            let last = field.len().saturating_sub(1);
            (last, cells(field.get(last).map_or("", String::as_str)))
        };
        for (i, row) in field.into_iter().enumerate() {
            let mut part = if i == cursor_at {
                Part::keep(vec![Line::styled(row, style)])
            } else {
                Part::droppable(vec![Line::styled(row, style)], DROP_FIELD)
            };
            if i == cursor_at && takes_text {
                part.cursor = Some(u16::try_from(col).unwrap_or(u16::MAX));
            }
            parts.push(part);
        }
    }
    parts.extend(result_parts(app, add, width));
    parts
}

/// 'Invite for <address>, with a network address': the paste once it parsed,
/// without its security code.
fn summary(friend: &FriendPreview, look: &Look) -> String {
    let address = short(&friend.address, look.glyphs.ellipsis);
    if friend.lan.is_empty() {
        format!("Invite for {address}, with no network address")
    } else {
        format!("Invite for {address}, with a network address")
    }
}

/// What the paste is, under the field: why it can't be added, a friend
/// already saved (O and U), [U]'s question, or a [U] save's answer.
fn result_parts(app: &App, add: &AddFriendState, width: u16) -> Vec<Part> {
    let look = app.look();
    let warn = |text: &str| Part::keep(styled_rows(text, width, look.theme.warn));
    if add.updating {
        return vec![Part::keep(rows(
            &format!("Saving{}", look.glyphs.ellipsis),
            width,
        ))];
    }
    let mut parts = Vec::new();
    if let Some(why) = &add.update_error {
        parts.push(warn(why));
    }
    match &add.parsed {
        None => {}
        Some(Err(PasteProblem::NotACard(_))) => parts.push(warn(NOT_A_CARD)),
        Some(Err(PasteProblem::OwnInvite)) => parts.push(warn(OWN_INVITE)),
        Some(Err(PasteProblem::Tampered(_))) => parts.push(warn(TAMPERED)),
        Some(Ok(friend)) => {
            if let Some(saved) = app.friend(&friend.pub_hex) {
                parts.extend(known_parts(app, add, friend, saved, width));
            }
        }
    }
    parts
}

/// A friend already saved: O and U, or [U]'s question with its code field
/// (the cursor after what is typed).
fn known_parts(
    app: &App,
    add: &AddFriendState,
    friend: &FriendPreview,
    saved: &ContactView,
    width: u16,
) -> Vec<Part> {
    let look = app.look();
    let name = app.shown_name(&saved.pub_hex);
    let Some(update) = &add.update else {
        let mut text = format!("You already have this person as {name}. [O] Open chat");
        if app::routes_differ(friend, saved) {
            text.push_str("   [U] Update their addresses");
        }
        return vec![Part::keep(keyed_rows(&text, width, look))];
    };
    let mut parts = Vec::new();
    if update.keyboard {
        parts.push(Part::keep(styled_rows(
            verify::LATIN_KEYBOARD,
            width,
            look.theme.warn,
        )));
    } else if update.wrong {
        parts.push(Part::keep(styled_rows(WRONG_CODE, width, look.theme.warn)));
    }
    let (old, new) = route_change(friend, saved, look.glyphs.ellipsis);
    let typed = display::one_line(&update.typed, u16::MAX, "");
    let question = format!(
        "Change {name}'s address from {old} to {new}? Only do this if {name} told you their \
         address changed. Type {} to confirm: > {typed}",
        update.code
    );
    let lines = rows(&question, width);
    let last = lines.last().map_or(0, Line::width);
    // The row ends '>' while nothing is typed: the cursor after its space.
    let col = last + usize::from(typed.is_empty());
    parts.push(Part {
        cursor: Some(u16::try_from(col).unwrap_or(u16::MAX)),
        ..Part::keep(lines)
    });
    parts
}

/// The saved route a [U] replaces and the pasted one: the local network's
/// when the paste has one, else the Internet's, else the p2p PeerId.
fn route_change(friend: &FriendPreview, saved: &ContactView, ellipsis: &str) -> (String, String) {
    let shown = |text: &str| {
        if text.is_empty() {
            "no address".to_owned()
        } else {
            short(text, ellipsis)
        }
    };
    if !friend.lan.is_empty() && friend.lan != saved.lan_dial {
        (shown(&saved.lan_dial), shown(&friend.lan))
    } else if !friend.internet.is_empty() && friend.internet != saved.internet_dial {
        (shown(&saved.internet_dial), shown(&friend.internet))
    } else {
        let peer = friend.p2p.as_ref().map_or("", |p2p| p2p.peer_id.as_str());
        (shown(&saved.p2p), shown(peer))
    }
}

/// AF-2: who the paste is (the address shortened, the routes in plain
/// words; never the security code), and the name field, with what is wrong
/// with the name or what to check about it. The cursor sits in the field.
fn render_name(f: &mut Frame, area: Rect, app: &App, add: &AddFriendState, now: Instant) {
    render_header(f, area, app, now, false);
    let Some(friend) = add.friend() else {
        return;
    };
    let body = wizard::under_header(area);
    let look = app.look();
    let width = wizard::text_width(body);
    let mut lines = vec![Line::styled(NAME_TITLE, look.theme.title), Line::default()];
    lines.push(Line::raw(format!(
        "Raven address: {}",
        short(&friend.address, look.glyphs.ellipsis)
    )));
    lines.extend(route_rows(friend, look, width));
    lines.push(Line::default());
    lines.push(Line::raw(NAME_QUESTION));
    let [top, field, bottom] = wizard::name_field(look, &add.name, NAME_PLACEHOLDER);
    lines.extend([top, field.clone(), bottom]);
    let hint = if add.names_note {
        NAME_NICKNAME
    } else {
        NAME_LOCAL
    };
    lines.extend(styled_rows(hint, width, look.theme.secondary));
    if add.name_full {
        lines.push(Line::styled(NAME_LIMIT, look.theme.secondary));
    }
    let said = name_said(app, add.name_problem.as_ref(), &add.name, &friend.pub_hex);
    if let Some(said) = said {
        lines.extend(styled_rows(&said, width, look.theme.warn));
    }
    lines.push(Line::default());
    lines.push(overlays::keys_line(look, &NAME_KEYS));
    let (inner, drawn) = wizard::draw_card(f, body, look, None, lines, body.height);
    let Some(row) = drawn.iter().position(|line| *line == field) else {
        return;
    };
    let y = u16::try_from(row).unwrap_or(u16::MAX);
    if y < inner.height && app.overlays().is_empty() {
        // After the field's left border and its space, and what is typed.
        let typed = u16::try_from(display::width(&add.name)).unwrap_or(u16::MAX);
        let x = inner.x.saturating_add(2).saturating_add(typed);
        f.set_cursor_position(Position::new(x, inner.y + y));
    }
}

/// What is wrong with the name typed for the friend `pub_hex` (AF-2, CI's
/// rename), else what to check about it before it is saved; None when all
/// is well.
pub(super) fn name_said(
    app: &App,
    problem: Option<&NameProblem>,
    name: &str,
    pub_hex: &str,
) -> Option<String> {
    match problem {
        Some(NameProblem::Empty) => Some(NAME_EMPTY.to_owned()),
        Some(NameProblem::Taken(other)) => Some(format!(
            "You already have a friend called {}. Pick another name.",
            app.shown_name(other)
        )),
        None => match controller::name_warning(app.contacts(), name, pub_hex) {
            Some(NameWarning::MixedScript) => Some(MIXED_SCRIPT.to_owned()),
            Some(NameWarning::LooksLike(other)) => Some(format!(
                "This name looks just like {}, another friend's name. Check it before you save.",
                app.shown_name(&other)
            )),
            None => None,
        },
    }
}

/// The paste's routes in plain words: the local network's, and the Internet
/// and p2p ones labelled Preview while their carriers are off; or none.
fn route_rows(friend: &FriendPreview, look: &Look, width: u16) -> Vec<Line<'static>> {
    let preview = |off: bool| if off { PREVIEW } else { "" };
    let mut routes = Vec::new();
    if !friend.lan.is_empty() {
        routes.push(format!(
            "{} (local network)",
            display::one_line(&friend.lan, u16::MAX, "")
        ));
    }
    if !friend.internet.is_empty() {
        routes.push(format!(
            "{} (internet{})",
            display::one_line(&friend.internet, u16::MAX, ""),
            preview(controller::INTERNET_PREVIEW)
        ));
    }
    if let Some(p2p) = &friend.p2p {
        routes.push(format!(
            "{} (p2p{})",
            short(&p2p.peer_id, look.glyphs.ellipsis),
            preview(controller::P2P_PREVIEW)
        ));
    }
    if routes.is_empty() {
        return rows(NO_ROUTE, width);
    }
    // The routes after the first line up under it.
    let indent = u16::try_from(cells(REACHED_AT)).unwrap_or(0);
    let pad = " ".repeat(usize::from(indent));
    let mut lines: Vec<Line<'static>> = wrap(&format!("{REACHED_AT}{}", routes[0]), width, indent)
        .into_iter()
        .map(Line::raw)
        .collect();
    for route in &routes[1..] {
        lines.extend(
            wrap(route, width.saturating_sub(indent), 0)
                .into_iter()
                .map(|row| Line::raw(format!("{pad}{row}"))),
        );
    }
    if friend.lan.is_empty() && lan_only_build() {
        lines.extend(rows(LAN_ONLY_HERE, width));
    }
    lines
}

/// This build reaches friends over the local network alone (Internet direct
/// and p2p both held, as before 2026-10).
fn lan_only_build() -> bool {
    controller::INTERNET_PREVIEW && controller::P2P_PREVIEW
}

/// NAME-CLASH: the verified friend's name was typed for another key. It
/// warns, in a card, and offers only their page (O) and Back.
pub(super) fn render_clash(f: &mut Frame, area: Rect, app: &App, clash: &ClashState, now: Instant) {
    if area.is_empty() {
        return;
    }
    render_header(f, area, app, now, false);
    let body = wizard::under_header(area);
    let look = app.look();
    let width = wizard::text_width(body);
    let name = app.shown_name(&clash.verified);
    let mut lines = styled_rows(
        &format!("Careful: you already have a verified friend called {name}"),
        width,
        look.theme.warn,
    );
    for paragraph in [
        format!("This invite has a different key from the {name} you verified."),
        format!(
            "If {name} reinstalled Raven or got a new computer, check with {name} in person or \
             by phone first. Then remove the old {name} on their page (X), add them again and \
             compare security words."
        ),
        format!("If you didn't expect a new key, someone else may be pretending to be {name}."),
    ] {
        lines.push(Line::default());
        lines.extend(rows(&paragraph, width));
    }
    lines.push(Line::default());
    let open = format!(" Open the old {name}'s page");
    let keys = vec![
        widgets::key(look, "[O]"),
        widgets::key_words(look, &open),
        Span::raw("   "),
        widgets::key(look, "[Esc]"),
        widgets::key_words(look, " Back"),
    ];
    if cells("[O]") + cells(&open) + cells("   [Esc] Back") <= usize::from(width) {
        lines.push(Line::from(keys));
    } else {
        lines.push(Line::from(vec![
            widgets::key(look, "[O]"),
            widgets::key_words(look, &open),
        ]));
        lines.push(overlays::keys_line(look, &[("[Esc]", " Back")]));
    }
    wizard::draw_card(f, body, look, None, lines, body.height);
}

/// `text` (untrusted) shaped, with its middle taken out when it is longer
/// than [`SHORT_HEAD`] and [`SHORT_TAIL`] characters and the ellipsis.
pub(super) fn short(text: &str, ellipsis: &str) -> String {
    let text = display::one_line(text, u16::MAX, "");
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= SHORT_HEAD + SHORT_TAIL + 1 {
        return text;
    }
    let head: String = chars[..SHORT_HEAD].iter().collect();
    let tail: String = chars[chars.len() - SHORT_TAIL..].iter().collect();
    format!("{head}{ellipsis}{tail}")
}

/// The app's own copy in rows of `width` cells.
fn rows(text: &str, width: u16) -> Vec<Line<'static>> {
    wizard::rows(text, width).collect()
}

pub(super) fn styled_rows(text: &str, width: u16, style: Style) -> Vec<Line<'static>> {
    wrap(text, width, 0)
        .into_iter()
        .map(|row| Line::styled(row, style))
        .collect()
}

/// The app's copy in rows of `width` cells, each `[X]` key in it in the
/// accent style.
fn keyed_rows(text: &str, width: u16, look: &Look) -> Vec<Line<'static>> {
    wrap(text, width, 0)
        .into_iter()
        .map(|row| keyed(&row, look))
        .collect()
}

/// One row with its `[X]` keys (a few letters in brackets) in the accent
/// style.
fn keyed(row: &str, look: &Look) -> Line<'static> {
    let mut spans = Vec::new();
    let mut rest = row;
    while let Some(open) = rest.find('[') {
        let Some(len) = rest[open..].find(']') else {
            break;
        };
        let key = &rest[open..=open + len];
        let inside = &key[1..key.len() - 1];
        if (1..=6).contains(&inside.len()) && inside.chars().all(|c| c.is_ascii_alphanumeric()) {
            spans.push(Span::raw(rest[..open].to_owned()));
            spans.push(widgets::key(look, key));
        } else {
            spans.push(Span::raw(rest[..=open + len].to_owned()));
        }
        rest = &rest[open + len + 1..];
    }
    spans.push(Span::raw(rest.to_owned()));
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyCode;
    use raven_core::ipc::{IpcResponse, IPC_VERSION};

    use super::controller::{Conversations, NoCardLan, Share};
    use super::theme::Glyphs;

    /// This profile's own identity in a test session (testkit's seed 7).
    const ME: u8 = 7;
    /// Bob, a friend to add.
    const BOB: u8 = 0xB0;
    /// Someone else, whose key Bob's name is typed for.
    const EVE: u8 = 0xE0;

    /// Status for a node listening at `listen`.
    fn probe(listen: &str) -> node::Probe {
        node::Probe::of(&Ok(IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into(), "lan_direct".into()],
            p2p: None,
            pid: Some(4242),
            lan_listen: Some(listen.into()),
            last_paths: Vec::new(),
            route_hints: None,
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: None,
            lan: None,
            security: None,
            nearby: None,
            tor: None,
            learning: None,
            locked: None,
            updates: None,
        }))
    }

    /// AF-1 at `size`, opened with A from Home, for a profile with
    /// `friends`, receiving `receive`.
    fn af1(size: (u16, u16), receive: Receive, friends: Vec<ContactView>) -> App {
        let mut app = testkit::home_app(size, receive, friends, Conversations::new());
        testkit::press(&mut app, KeyCode::Char('a'));
        assert!(matches!(app.screen(), Screen::AddFriend(_)));
        app
    }

    /// The start AF-1 asked for ended: a node listening at `listen`.
    fn started(app: &mut App, listen: &str) {
        start_ended(app, Ok(()), probe(listen));
    }

    fn start_ended(app: &mut App, result: Result<(), String>, after: node::Probe) {
        testkit::send(
            app,
            Msg::Job(JobResult::Ensured(node::Ensured {
                result,
                after,
                started_by_app: Some(4242),
                captured: String::new(),
                ring: 0..0,
            })),
        );
    }

    /// The card job for `listen` answered: the address `lan` for it, and my
    /// cards with and without it.
    fn shared(app: &mut App, listen: Option<&str>, lan: Option<Result<&str, NoCardLan>>) {
        let with_lan = match lan {
            Some(Ok(lan)) => Some(Ok(testkit::card(ME, lan))),
            _ => None,
        };
        testkit::send(
            app,
            Msg::Job(JobResult::Shared {
                listen: listen.map(str::to_owned),
                share: Share {
                    lan: lan.map(|lan| lan.map(str::to_owned)),
                    with_lan,
                    plain: Ok(testkit::card(ME, "")),
                },
            }),
        );
    }

    /// AF-1 with my card ready: a node listening on every address, this
    /// computer at `lan`.
    fn ready(size: (u16, u16), lan: &str) -> App {
        let mut app = af1(size, Receive::On, Vec::new());
        started(&mut app, "0.0.0.0:7420");
        shared(&mut app, Some("0.0.0.0:7420"), Some(Ok(lan)));
        app
    }

    /// `text` pasted, then the paste guard over.
    fn paste(app: &mut App, text: &str) {
        testkit::paste(app, text, PasteVia::Bracketed);
        testkit::tick(app, Duration::from_millis(300));
    }

    /// AF-2 for Bob's card, `friends` saved, `name` typed.
    fn af2(friends: Vec<ContactView>, card: &str, name: &str) -> App {
        let mut app = af1((80, 24), Receive::Off, friends);
        paste(&mut app, card);
        testkit::press(&mut app, KeyCode::Enter);
        for c in name.chars() {
            testkit::press(&mut app, KeyCode::Char(c));
        }
        app
    }

    fn screen(app: &App) -> String {
        testkit::screen_text(&testkit::render(app, 80, 24))
    }

    /// Neither Bob's security code nor any group of it on `rows`.
    fn assert_no_code(rows: &[String]) {
        let code = testkit::me(BOB).fingerprint;
        let text = rows.join("\n");
        assert!(!text.contains(&code), "{code} on screen:\n{text}");
        for group in code.split('-') {
            assert!(
                !text.contains(group),
                "{group} of {code} on screen:\n{text}"
            );
        }
    }

    #[test]
    fn af1_ready_simple_mono() {
        let app = ready((80, 24), "192.168.1.20:7420");
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Add a friend                                * Listening on port 7420",
                "Add a friend  1 Share yours  2 Paste theirs  3 Check codes                      ",
                "In this version, you and your friend must be on the same network (the same Wi-Fi",
                "or office network).                                                             ",
                "┌ Share yours ─────────────────────────────────────────────────────────────────┐",
                "│ Send this to your friend (in a message, an email, or show them):             │",
                "│ raven-card/1 address=rvn1q8lgztqj7w45ee4vtkmf4s6jlyrvkxc3au8ayw4a            │",
                "│ pub_hex=ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c     │",
                "│ fingerprint=oEsE-vOrT-Oas lan=192.168.1.20:7420                              │",
                "│ It holds only public information. Your private key never leaves this         │",
                "│ computer.                                                                    │",
                "│ [L] Include my network address (192.168.1.20:7420): On. Anyone you send this │",
                "│ to can see it.                                                               │",
                "│ [C] Show it alone so you can copy it                                         │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "┌ Paste theirs ────────────────────────────────────────────────────────────────┐",
                "│ Paste your friend's invite or card:                                          │",
                "│ Paste here with your terminal's paste (for example Ctrl+Shift+V, Cmd+V or    │",
                "│ right-click)                                                                 │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "Tab Switch box  L Address on/off  C Copy view  Enter Continue  Esc Cancel       ",
            ],
        );
    }

    #[test]
    fn af1_ready_at_the_smallest_size() {
        let app = ready((60, 16), "192.168.1.20:7420");
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N - Add a friend            * Listening on port 7420",
                "┌ Share yours ─────────────────────────────────────────────┐",
                "│ raven-card/1                                             │",
                "│ address=rvn1q8lgztqj7w45ee4vtkmf4s6jlyrvkxc3au8ayw4a     │",
                "│ pub_hex=ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92 │",
                "│ 421eea691446d22c                                         │",
                "│ fingerprint=oEsE-vOrT-Oas lan=192.168.1.20:7420          │",
                "│ [L] Include my network address (192.168.1.20:7420): On.  │",
                "│ Anyone you send this to can see it.                      │",
                "│ [C] Show it alone so you can copy it                     │",
                "└──────────────────────────────────────────────────────────┘",
                "┌ Paste theirs ────────────────────────────────────────────┐",
                "│ Paste your friend's invite or card:                      │",
                "│ Paste here with your terminal's paste (for example       │",
                "└──────────────────────────────────────────────────────────┘",
                "Tab Switch box  L Address on/off  C Copy view               ",
            ],
        );
    }

    #[test]
    fn af1_ready_fancy_with_a_vpn_note_and_the_cursor() {
        let look = Look {
            glyphs: Glyphs::fancy(),
            ..testkit::simple_mono()
        };
        let mut app = testkit::home_app_in(
            look,
            (80, 24),
            Receive::On,
            Vec::new(),
            Conversations::new(),
        );
        testkit::press(&mut app, KeyCode::Char('a'));
        started(&mut app, "0.0.0.0:7420");
        shared(&mut app, Some("0.0.0.0:7420"), Some(Ok("100.64.0.7:7420")));
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N · Add a friend                                ● Listening on port 7420",
                "Add a friend · 1 Share yours · 2 Paste theirs · 3 Check codes                   ",
                "In this version, you and your friend must be on the same network (the same Wi-Fi",
                "or office network).                                                             ",
                "╭ Share yours ─────────────────────────────────────────────────────────────────╮",
                "│ Send this to your friend (in a message, an email, or show them):             │",
                "│ raven-card/1 address=rvn1q8lgztqj7w45ee4vtkmf4s6jlyrvkxc3au8ayw4a            │",
                "│ pub_hex=ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c     │",
                "│ fingerprint=oEsE-vOrT-Oas lan=100.64.0.7:7420                                │",
                "│ It holds only public information. Your private key never leaves this         │",
                "│ computer.                                                                    │",
                "│ [L] Include my network address (100.64.0.7:7420): On. Anyone you send this   │",
                "│ to can see it.                                                               │",
                "│ This address doesn't look like a home or office network address. If your     │",
                "│ friend can't reach you, a VPN may be on.                                     │",
                "│ [C] Show it alone so you can copy it                                         │",
                "╰──────────────────────────────────────────────────────────────────────────────╯",
                "╭ Paste theirs ────────────────────────────────────────────────────────────────╮",
                "│ Paste your friend's invite or card:                                          │",
                "│ Paste here with your terminal's paste (for example Ctrl+Shift+V, Cmd+V or    │",
                "│ right-click)                                                                 │",
                "╰──────────────────────────────────────────────────────────────────────────────╯",
                "                                                                                ",
                "Tab Switch box · L Address on/off · C Copy view · Enter Continue · Esc Cancel   ",
            ],
        );
        assert_eq!(cursor(&app, 80, 24), Some((2, 19)));
    }

    /// Where the terminal's cursor is after a draw, if it shows.
    fn cursor(app: &App, width: u16, height: u16) -> Option<(u16, u16)> {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("a terminal");
        terminal
            .draw(|f| render_frame(f, app, app.now()))
            .expect("draw");
        let shown = format!("{:?}", terminal.backend()).contains("cursor: true");
        let at = terminal.get_cursor_position().expect("the cursor");
        shown.then_some((at.x, at.y))
    }

    #[test]
    fn af1_starting() {
        let app = af1((80, 24), Receive::On, Vec::new());
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Add a friend                                     | Starting Raven...",
                "Add a friend  1 Share yours  2 Paste theirs  3 Check codes                      ",
                "In this version, you and your friend must be on the same network (the same Wi-Fi",
                "or office network).                                                             ",
                "┌ Share yours ─────────────────────────────────────────────────────────────────┐",
                "│ | Starting Raven so your friend can reach you...                             │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "┌ Paste theirs ────────────────────────────────────────────────────────────────┐",
                "│ Paste your friend's invite or card:                                          │",
                "│ Paste here with your terminal's paste (for example Ctrl+Shift+V, Cmd+V or    │",
                "│ right-click)                                                                 │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "Tab Switch box  L Address on/off  C Copy view  Enter Continue  Esc Cancel       ",
            ],
        );
    }

    /// The share box's words in each state that can't share my address, and
    /// after S the invite without one: never in Starting.
    #[test]
    fn af1_every_share_state() {
        let anyway = "[S] Show my invite anyway";
        // Receiving is off.
        let mut app = af1((80, 24), Receive::Off, Vec::new());
        assert!(screen(&app).contains(
            "Receiving is off on this computer, so your invite would have no address and your \
             friend couldn't send you the first message. Turn receiving on in Settings, or [S] \
             show my invite anyway."
        ));
        // S, from the share box: the invite without an address (the
        // invite line until my card is there).
        testkit::press(&mut app, KeyCode::Tab);
        testkit::press(&mut app, KeyCode::Char('s'));
        assert!(screen(&app).contains(&testkit::me(ME).invite[..60]));
        shared(&mut app, None, None);
        let shown = screen(&app);
        for words in [
            "Send this to your friend (in a message, an email, or show them):",
            "raven-card/1 address=",
            "Your invite has no address, so your friend can't send you the first message. You \
             can send first once you have their invite.",
            "It holds only public information. Your private key never leaves this computer.",
            "[C] Show it alone so you can copy it",
        ] {
            assert!(shown.contains(words), "{words}: {shown}");
        }
        assert!(!shown.contains("lan="), "{shown}");

        // Listening on this computer only.
        let mut app = af1((80, 24), Receive::On, Vec::new());
        started(&mut app, "127.0.0.1:55001");
        assert!(screen(&app).contains(&format!(
            "Raven's background program is only listening on this computer (127.0.0.1), so \
             your friend can't reach you. Press N to see how to change it. {anyway} (without an \
             address)"
        )));
        // Every address, and this computer's own can't be told.
        let mut app = af1((80, 24), Receive::On, Vec::new());
        started(&mut app, "0.0.0.0:7420");
        assert!(screen(&app).contains("Starting Raven so your friend can reach you"));
        shared(
            &mut app,
            Some("0.0.0.0:7420"),
            Some(Err(NoCardLan::NoAddress)),
        );
        assert!(screen(&app).contains(&format!(
            "Raven can't tell this computer's network address. {anyway}"
        )));
        // The start failed.
        let mut app = af1((80, 24), Receive::On, Vec::new());
        let not_running = node::Probe::of(&Err("raven-node is not running; start it".to_owned()));
        start_ended(
            &mut app,
            Err("raven-node exited during startup".into()),
            not_running,
        );
        assert!(
            screen(&app).contains(&format!(
                "Raven's background program stopped while starting. {anyway}"
            )),
            "{}",
            screen(&app)
        );
        // A vault profile without its passphrase file.
        let mut app = testkit::home_app((80, 24), Receive::On, Vec::new(), Conversations::new());
        testkit::send(
            &mut app,
            Msg::Job(JobResult::Vault(node::Vault {
                profile: true,
                needs_passphrase_file: true,
                ..node::Vault::default()
            })),
        );
        testkit::press(&mut app, KeyCode::Char('a'));
        testkit::press(&mut app, KeyCode::Esc);
        assert!(screen(&app).contains(&format!(
            "Raven's background program can't start on this computer yet: it needs your \
             passphrase in a private file. Press N to see how. {anyway}"
        )));
    }

    #[test]
    fn l_turns_my_address_off_and_on() {
        let mut app = ready((80, 24), "192.168.1.20:7420");
        testkit::press(&mut app, KeyCode::Tab);
        let cmds = testkit::press(&mut app, KeyCode::Char('l'));
        assert!(
            cmds.iter().any(|cmd| matches!(
                cmd,
                app::Cmd::Store(app::StoreJob::SaveSettings(state)) if !state.include_lan_in_card
            )),
            "{cmds:?}"
        );
        let rows = testkit::render(&app, 80, 24);
        testkit::assert_rows(
            &rows[4..15],
            &[
                "┌ Share yours ─────────────────────────────────────────────────────────────────┐",
                "│ Send this to your friend (in a message, an email, or show them):             │",
                "│ raven-card/1 address=rvn1q8lgztqj7w45ee4vtkmf4s6jlyrvkxc3au8ayw4a            │",
                "│ pub_hex=ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c     │",
                "│ fingerprint=oEsE-vOrT-Oas                                                    │",
                "│ It holds only public information. Your private key never leaves this         │",
                "│ computer.                                                                    │",
                "│ [L] Include my network address (192.168.1.20:7420): Off.                     │",
                "│ Your invite has no address, so your friend can't send you the first message. │",
                "│ You can send first once you have their invite.                               │",
                "│ [C] Show it alone so you can copy it                                         │",
            ],
        );
        testkit::press(&mut app, KeyCode::Char('L'));
        assert!(screen(&app).contains("lan=192.168.1.20:7420"));
    }

    #[test]
    fn af1_error_lines() {
        let (_, eve) = (testkit::me(BOB), testkit::me(EVE));
        let bob_card = testkit::card(BOB, "192.168.1.30:7420");
        let mine = testkit::me(ME).invite;
        let forged = bob_card.replace(&testkit::me(BOB).pub_hex, &eve.pub_hex);
        for (text, words) in [
            ("hello, it's Bob", NOT_A_CARD),
            (mine.as_str(), OWN_INVITE),
            (forged.as_str(), TAMPERED),
        ] {
            let mut app = af1((80, 24), Receive::Off, Vec::new());
            paste(&mut app, text);
            let rows = testkit::render(&app, 80, 24);
            assert!(
                testkit::screen_text(&rows).contains(words),
                "{text}: {rows:#?}"
            );
            assert_no_code(&rows);
        }
        // The forged card as it was pasted, its code masked.
        let mut app = af1((80, 24), Receive::Off, Vec::new());
        paste(&mut app, &forged);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24)[8..15],
            &[
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "┌ Paste theirs ────────────────────────────────────────────────────────────────┐",
                "│ Paste your friend's invite or card:                                          │",
                "│ raven-card/1 address=rvn1qye5mwjxxhzrdqkqzzu4wr9myarmckj865mu82td            │",
                "│ pub_hex=9ff6204d61b59a9e61afdd64fdf294bfe8a16687ba0538823ba59db6cb7b21ff     │",
                "│ fingerprint=••• lan=192.168.1.30:7420                                        │",
                "│ This invite doesn't add up: its address and key don't match. Ask your friend │",
            ],
        );
    }

    #[test]
    fn a_parsed_paste_shows_only_its_summary_fading_from_bold() {
        let mut app = af1((80, 24), Receive::Off, Vec::new());
        testkit::paste(
            &mut app,
            &testkit::card(BOB, "192.168.1.30:7420"),
            PasteVia::Keystrokes,
        );
        let rows = testkit::render(&app, 80, 24);
        assert_no_code(&rows);
        testkit::assert_rows(
            &rows[8..12],
            &[
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "┌ Paste theirs ────────────────────────────────────────────────────────────────┐",
                "│ Paste your friend's invite or card:                                          │",
                "│ Invite for rvn1qye5mw...mu82td, with a network address                       │",
            ],
        );
        // Bold for 600 ms, then normal; still under reduced motion.
        let bold = |app: &App, at: Duration| {
            let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24))
                .expect("a terminal");
            terminal
                .draw(|f| render_frame(f, app, app.now() + at))
                .expect("draw");
            let buffer = terminal.backend().buffer().clone();
            let row = (0..24)
                .find(|&y| testkit::buffer_lines(&buffer)[y].contains("Invite for"))
                .expect("the summary");
            buffer[(2, u16::try_from(row).unwrap())]
                .modifier
                .contains(Modifier::BOLD)
        };
        assert!(bold(&app, Duration::ZERO));
        assert!(bold(&app, Duration::from_millis(599)));
        assert!(!bold(&app, Duration::from_millis(600)));
        let t0 = app.now();
        assert_eq!(
            anim::next_change(&anim::moving(&app), app.look(), t0),
            Some(t0 + FADE_TIME)
        );
        // No address in it: said so.
        let mut app = af1((80, 24), Receive::Off, Vec::new());
        paste(&mut app, &testkit::me(BOB).invite);
        assert!(screen(&app).contains(", with no network address"));
    }

    #[test]
    fn a_saved_friend_offers_their_chat_and_new_addresses() {
        let bob = testkit::saved_as(BOB, "Bob", true, "192.168.1.30:7420");
        let mut app = af1((80, 24), Receive::Off, vec![bob]);
        paste(&mut app, &testkit::card(BOB, "192.168.1.44:7420"));
        assert!(screen(&app).contains(
            "You already have this person as Bob. [O] Open chat [U] Update their addresses"
        ));
        testkit::press(&mut app, KeyCode::Char('u'));
        let code = app.update_code_for_tests().expect("a code").to_owned();
        let rows = testkit::render(&app, 80, 24);
        assert_no_code(&rows);
        // The code is drawn when the question appears.
        let asks = format!(
            "│ this if Bob told you their address changed. Type {code} to confirm: >         │"
        );
        testkit::assert_rows(
            &rows[8..14],
            &[
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "┌ Paste theirs ────────────────────────────────────────────────────────────────┐",
                "│ Paste your friend's invite or card:                                          │",
                "│ Invite for rvn1qye5mw...mu82td, with a network address                       │",
                "│ Change Bob's address from 192.168.1.30:7420 to 192.168.1.44:7420? Only do    │",
                &asks,
            ],
        );
        // The cursor in the code field, after '> '.
        let y = rows
            .iter()
            .position(|row| row.contains("to confirm: >"))
            .expect("the question");
        let x = rows[y].chars().position(|c| c == '>').expect("its field") + 2;
        assert_eq!(
            cursor(&app, 80, 24),
            Some((u16::try_from(x).unwrap(), u16::try_from(y).unwrap()))
        );
        for c in "WRONG".chars() {
            testkit::press(&mut app, KeyCode::Char(c));
        }
        testkit::press(&mut app, KeyCode::Enter);
        let shown = screen(&app);
        assert!(shown.contains("That code didn't match, so here is a new one."));
        assert!(
            !shown.contains("WRONG"),
            "a new code takes a new answer: {shown}"
        );
        // The same addresses again: only O.
        let bob = testkit::saved_as(BOB, "Bob", true, "192.168.1.30:7420");
        let mut app = af1((80, 24), Receive::Off, vec![bob]);
        paste(&mut app, &testkit::card(BOB, "192.168.1.30:7420"));
        let shown = screen(&app);
        assert!(shown.contains("You already have this person as Bob. [O] Open chat"));
        assert!(!shown.contains("[U]"), "{shown}");
    }

    #[test]
    fn the_update_question_hints_at_the_keyboard() {
        let bob = testkit::saved_as(BOB, "Bob", true, "192.168.1.30:7420");
        let mut app = af1((80, 24), Receive::Off, vec![bob]);
        paste(&mut app, &testkit::card(BOB, "192.168.1.44:7420"));
        testkit::press(&mut app, KeyCode::Char('u'));
        let code = app.update_code_for_tests().expect("a code").to_owned();
        for c in testkit::on_persian_keyboard("x2").chars() {
            testkit::press(&mut app, KeyCode::Char(c));
        }
        testkit::press(&mut app, KeyCode::Enter);
        // The hint in place of 'here is a new one': the same code, and what
        // was typed stays in its field.
        assert_eq!(app.update_code_for_tests(), Some(code.as_str()));
        let rows: Vec<String> = testkit::render(&app, 80, 24)
            .iter()
            .map(|row| row.replace(&code, "K7Q3M"))
            .collect();
        assert!(!testkit::screen_text(&rows).contains("new one"));
        testkit::assert_rows(
            &rows,
            &[
                "R A V E N - Add a friend                                      o Receiving is off",
                "Add a friend  1 Share yours  2 Paste theirs  3 Check codes                      ",
                "In this version, you and your friend must be on the same network (the same Wi-Fi",
                "or office network).                                                             ",
                "┌ Share yours ─────────────────────────────────────────────────────────────────┐",
                "│ Receiving is off on this computer, so your invite would have no address and  │",
                "│ your friend couldn't send you the first message. Turn receiving on in        │",
                "│ Settings, or [S] show my invite anyway.                                      │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "┌ Paste theirs ────────────────────────────────────────────────────────────────┐",
                "│ Paste your friend's invite or card:                                          │",
                "│ Invite for rvn1qye5mw...mu82td, with a network address                       │",
                "│ Switch your keyboard to English (Latin) letters for this code. Digits can    │",
                "│ stay as they are.                                                            │",
                "│ Change Bob's address from 192.168.1.30:7420 to 192.168.1.44:7420? Only do    │",
                "│ this if Bob told you their address changed. Type K7Q3M to confirm: > \u{0637}2      │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "Tab Switch box  L Address on/off  C Copy view  Enter Continue  Esc Cancel       ",
            ],
        );
        // At the smallest size the hint and the field's row still show.
        testkit::resize(&mut app, 60, 16);
        let rows: Vec<String> = testkit::render(&app, 60, 16)
            .iter()
            .map(|row| row.replace(&code, "K7Q3M"))
            .collect();
        testkit::assert_rows(
            &rows,
            &[
                "R A V E N - Add a friend                  o Receiving is off",
                "┌ Share yours ─────────────────────────────────────────────┐",
                "│ Receiving is off on this computer, so your invite would  │",
                "│ have no address and your friend couldn't send you the    │",
                "│ first message. Turn receiving on in Settings, or [S]     │",
                "│ show my invite anyway.                                   │",
                "└──────────────────────────────────────────────────────────┘",
                "┌ Paste theirs ────────────────────────────────────────────┐",
                "│ Invite for rvn1qye5mw...mu82td, with a network address   │",
                "│ Switch your keyboard to English (Latin) letters for this │",
                "│ code. Digits can stay as they are.                       │",
                "│ Change Bob's address from 192.168.1.30:7420 to           │",
                "│ 192.168.1.44:7420? Only do this if Bob told you their    │",
                "│ address changed. Type K7Q3M to confirm: > \u{0637}2             │",
                "└──────────────────────────────────────────────────────────┘",
                "Tab Switch box  L Address on/off  C Copy view               ",
            ],
        );
    }

    #[test]
    fn af2_simple_mono() {
        let app = af2(Vec::new(), &testkit::card(BOB, "192.168.1.30:7420"), "Bob");
        let rows = testkit::render(&app, 80, 24);
        assert_no_code(&rows);
        testkit::assert_rows(
            &rows,
            &[
                "R A V E N - Add a friend                                      o Receiving is off",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Who is this?                                                 │        ",
                "        │                                                              │        ",
                "        │ Raven address: rvn1qye5mw...mu82td                           │        ",
                "        │ Can be reached at: 192.168.1.30:7420 (local network)         │        ",
                "        │                                                              │        ",
                "        │ What do you want to call them?                               │        ",
                "        │ ┌──────────────────────────────────┐                         │        ",
                "        │ │ Bob                              │                         │        ",
                "        │ └──────────────────────────────────┘                         │        ",
                "        │ This name is only on this computer.                          │        ",
                "        │                                                              │        ",
                "        │ [Enter] Next   [Esc] Back                                    │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        assert_eq!(cursor(&app, 80, 24), Some((15, 13)));
    }

    /// AF-1 with Bob's card pasted, for a profile that has not named a
    /// friend on AF-2 yet (UXF.9); the other notes were seen.
    fn before_naming() -> App {
        let mut session = testkit::session(Receive::Off);
        session.settings.names_note_shown = false;
        let mut app = testkit::home_app_from(
            testkit::simple_mono(),
            (80, 24),
            session,
            Vec::new(),
            Conversations::new(),
        );
        testkit::press(&mut app, KeyCode::Char('a'));
        paste(&mut app, &testkit::card(BOB, "192.168.1.30:7420"));
        app
    }

    fn saves_notes(cmds: &[app::Cmd]) -> bool {
        cmds.iter().any(|cmd| {
            matches!(
                cmd,
                app::Cmd::Store(app::StoreJob::SaveReadMarks(state)) if state.names_note_shown
            )
        })
    }

    #[test]
    fn af2_says_to_use_a_nickname_the_first_time() {
        let mut app = before_naming();
        assert!(saves_notes(&testkit::press(&mut app, KeyCode::Enter)));
        for c in "Bob".chars() {
            testkit::press(&mut app, KeyCode::Char(c));
        }
        let rows = testkit::render(&app, 80, 24);
        assert_no_code(&rows);
        testkit::assert_rows(
            &rows,
            &[
                "R A V E N - Add a friend                                      o Receiving is off",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Who is this?                                                 │        ",
                "        │                                                              │        ",
                "        │ Raven address: rvn1qye5mw...mu82td                           │        ",
                "        │ Can be reached at: 192.168.1.30:7420 (local network)         │        ",
                "        │                                                              │        ",
                "        │ What do you want to call them?                               │        ",
                "        │ ┌──────────────────────────────────┐                         │        ",
                "        │ │ Bob                              │                         │        ",
                "        │ └──────────────────────────────────┘                         │        ",
                "        │ Names here stay on this computer. Use a nickname if someone  │        ",
                "        │ may look at this laptop.                                     │        ",
                "        │                                                              │        ",
                "        │ [Enter] Next   [Esc] Back                                    │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N - Add a friend                  o Receiving is off",
                "┌──────────────────────────────────────────────────────────┐",
                "│ Who is this?                                             │",
                "│                                                          │",
                "│ Raven address: rvn1qye5mw...mu82td                       │",
                "│ Can be reached at: 192.168.1.30:7420 (local network)     │",
                "│                                                          │",
                "│ What do you want to call them?                           │",
                "│ ┌──────────────────────────────────┐                     │",
                "│ │ Bob                              │                     │",
                "│ └──────────────────────────────────┘                     │",
                "│ Names here stay on this computer. Use a nickname if      │",
                "│ someone may look at this laptop.                         │",
                "│                                                          │",
                "│ [Enter] Next   [Esc] Back                                │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
        // Back on AF-1 and on again: still, on this visit, and saved once.
        testkit::press(&mut app, KeyCode::Esc);
        assert!(!saves_notes(&testkit::press(&mut app, KeyCode::Enter)));
        assert!(screen(&app).contains(NAME_NICKNAME));
        // The next time: the usual hint.
        testkit::press(&mut app, KeyCode::Esc);
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen(), &Screen::Home);
        testkit::press(&mut app, KeyCode::Char('a'));
        paste(&mut app, &testkit::card(BOB, "192.168.1.30:7420"));
        assert!(!saves_notes(&testkit::press(&mut app, KeyCode::Enter)));
        let shown = screen(&app);
        assert!(
            shown.contains(NAME_LOCAL) && !shown.contains("nickname"),
            "{shown}"
        );
    }

    #[test]
    fn af2_routes_in_plain_words() {
        // No address at all.
        let app = af2(Vec::new(), &testkit::me(BOB).invite, "");
        let shown = screen(&app);
        assert!(shown.contains("No network address included. You can add one later."));
        assert!(shown.contains("Raven address: rvn1"), "{shown}");
        // Only an Internet address: usable in a release build (2026-10:
        // Internet direct is on), so nothing says local network only.
        let id = raven_core::identity::Identity::from_seed(&[BOB; 32]);
        let card = bridge::format_card_with(&id, "203.0.113.9:7420", "", None).expect("a card");
        let app = af2(Vec::new(), &card, "");
        let shown = screen(&app);
        if lan_only_build() {
            assert!(
                shown.contains(
                    "Can be reached at: 203.0.113.9:7420 (internet, Preview, not in this release) \
                     This invite has no local-network address, and this version of Raven can only \
                     use the local network."
                ),
                "{shown}"
            );
        } else {
            assert!(
                shown.contains("Can be reached at: 203.0.113.9:7420 (internet) What do"),
                "{shown}"
            );
            assert!(!shown.contains("can only use the local network"), "{shown}");
        }
        assert_no_code(&testkit::render(&app, 80, 24));
    }

    #[test]
    fn af2_says_what_is_wrong_with_a_name() {
        // Empty.
        let mut app = af2(Vec::new(), &testkit::card(BOB, ""), "");
        testkit::press(&mut app, KeyCode::Enter);
        assert!(screen(&app).contains("Give your friend a name."));
        // A friend not verified has it.
        let carol = testkit::saved_as(0xC0, "Carol", false, "");
        let mut app = af2(vec![carol], &testkit::card(BOB, ""), "carol");
        testkit::press(&mut app, KeyCode::Enter);
        assert!(screen(&app).contains("You already have a friend called Carol. Pick another name."));
        // Mixed alphabets: a warning while typing, before Enter.
        let app = af2(Vec::new(), &testkit::card(BOB, ""), "B\u{043E}b");
        let rows = testkit::render(&app, 80, 24);
        assert!(testkit::screen_text(&rows).contains(
            "This name mixes letters from different alphabets, so it can look like another \
             name. Check it before you save."
        ));
        // All Cyrillic, but it looks like a friend's name.
        let cop = testkit::saved_as(0xC0, "cop", false, "");
        let app = af2(
            vec![cop],
            &testkit::card(BOB, ""),
            "\u{0441}\u{043E}\u{0440}",
        );
        assert!(screen(&app).contains(
            "This name looks just like cop, another friend's name. Check it before you save."
        ));
    }

    #[test]
    fn name_clash_simple_mono() {
        let bob = testkit::saved_as(BOB, "Bob", true, "192.168.1.30:7420");
        let mut app = af2(vec![bob], &testkit::card(EVE, "192.168.1.66:7420"), "bob");
        testkit::press(&mut app, KeyCode::Enter);
        assert!(matches!(app.screen(), Screen::NameClash(_)));
        let rows = testkit::render(&app, 80, 24);
        testkit::assert_rows(
            &rows,
            &[
                "R A V E N - Add a friend                                      o Receiving is off",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Careful: you already have a verified friend called Bob       │        ",
                "        │                                                              │        ",
                "        │ This invite has a different key from the Bob you verified.   │        ",
                "        │                                                              │        ",
                "        │ If Bob reinstalled Raven or got a new computer, check with   │        ",
                "        │ Bob in person or by phone first. Then remove the old Bob on  │        ",
                "        │ their page (X), add them again and compare security words.   │        ",
                "        │                                                              │        ",
                "        │ If you didn't expect a new key, someone else may be          │        ",
                "        │ pretending to be Bob.                                        │        ",
                "        │                                                              │        ",
                "        │ [O] Open the old Bob's page   [Esc] Back                     │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        assert_no_code(&rows);
        let eve = testkit::me(EVE).fingerprint;
        assert!(!rows.join("").contains(&eve));
    }

    #[test]
    fn copy_shows_my_invite_alone() {
        let card = testkit::card(ME, "192.168.1.20:7420");
        assert_eq!(
            copy_lines(&card, false, false),
            [
                "Your Raven invite. Select the line below and copy it with your terminal:",
                "",
                card.as_str(),
                "",
                "It holds only public information. Press any key to go back to Raven.",
            ]
        );
        // The first time (UXF.9): clear it afterwards.
        assert_eq!(
            copy_lines(&card, false, true),
            [
                "Your Raven invite. Select the line below and copy it with your terminal:",
                "",
                card.as_str(),
                "",
                "Clear this from the terminal afterwards (it stays in the scrollback).",
                "It holds only public information. Press any key to go back to Raven.",
            ]
        );
        let windows = copy_lines(&card, true, true);
        assert_eq!(
            windows.last().map(String::as_str),
            Some(
                "In this window: select the line with the mouse, then press Enter or \
                 right-click to copy."
            )
        );
        // Shaped like any line: nothing in it can reach the terminal as a
        // command.
        assert_eq!(
            copy_lines("raven-card/1 \u{1b}[2J", false, false)[2],
            "raven-card/1 "
        );
    }

    #[test]
    fn keys_in_the_copy_take_the_accent() {
        let look = Look {
            theme: theme::Theme::color(),
            ..testkit::simple_mono()
        };
        let line = keyed("Press [S] now, [not a key] or [", &look);
        let styled: Vec<(&str, bool)> = line
            .spans
            .iter()
            .map(|span| (span.content.as_ref(), span.style == look.theme.accent))
            .collect();
        assert_eq!(
            styled,
            [
                ("Press ", false),
                ("[S]", true),
                (" now, [not a key]", false),
                (" or [", false),
            ]
        );
        assert_eq!(
            short("rvn1q8lgztqj7w45ee4vtkmf4s6jlyrvkxc3", "..."),
            "rvn1q8lgzt...lyrvkxc3".replace("lyrvkxc3", "rvkxc3")
        );
        assert!(private_address("192.168.1.20:7420"));
        assert!(private_address("10.1.2.3:7420"));
        assert!(private_address("172.31.0.1:7420"));
        for vpn in [
            "172.32.0.1:7420",
            "100.64.0.7:7420",
            "[fd00::1]:7420",
            "nonsense",
        ] {
            assert!(!private_address(vpn), "{vpn}");
        }
    }
}
