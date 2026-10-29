//! Groups on Home (lab only; app/groups.rs): the GROUPS section under the
//! friends, a group's chat in the conversation pane, and the groups' boxes
//! (NEW GROUP's name and the friend picker, MEMBERS, WHO HAS IT).
//!
//! - Nothing here is drawn while groups are not live: Home is as it was.
//! - A group's row: the highlight's '>' marker, '#', the name (at most 14
//!   cells), its member count where the row has room, and at the right
//!   the unread count, or 'left' / 'removed'.
//! - A group's chat: the name with the member count, then the messages,
//!   each under its author's name ('You' for yours; a member who is your
//!   friend by your name for them, any other by the name the admin gave
//!   them) and its age, with 'passed on by <member>' when another member
//!   forwarded it. Yours have a tick and 'Delivered to 1 of 2'; WHO HAS IT
//!   lists each member's copy. A group you left or were removed from has
//!   a notice where the composer was.
//! - Every name and body is untrusted and drawn through display.rs.

use std::time::Instant;

use ratatui::layout::{Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use raven_core::group::store::{
    LINE_DELIVERED, LINE_FAILED, LINE_SENT, LINE_WAITING, STATUS_LEFT, STATUS_REMOVED,
};
use raven_core::group::GroupSummary;

use super::app::{
    group_text_problem, App, Focus, GroupItem, GroupOverlay, MemberAsk, MembersState, PickFor,
    PickState,
};
#[cfg(test)]
use super::app::{Cmd, JobResult, Msg, Overlay, SendJob, StoreJob};
use super::controller::{GroupMessage, MemberLine};
use super::home::{self, ComposerView};
#[cfg(test)]
use super::render as render_frame;
use super::theme::PathKind;
use super::widgets::{self, TickMark};
#[cfg(test)]
use super::{app, bridge, controller, state_file, testkit, theme, workers};
use super::{cells, display, overlays, wrap, Look};

/// A group's mark in the list, in every glyph set.
const GROUP_MARK: &str = "#";
/// The section's title row.
const SECTION_TITLE: &str = " Groups";
/// The list's second footer row while groups are live.
pub(super) const FOOTER: (&str, &str) = ("C", "  New group");
const LIST_UNREADABLE: &str = "Raven can't read your groups right now.";
const LEFT: &str = "left";
const REMOVED: &str = "removed";
const CHAT_UNREADABLE: &str = "Raven can't read this group right now.";
const LEFT_NOTICE: &str =
    "You left this group. What you received stays here; nothing more comes or goes.";
const REMOVED_NOTICE: &str =
    "You were removed from this group. What you received stays here; nothing more comes or goes.";
/// From this many bytes the separator says how much of the 8 KB is used.
const COUNTER_FROM: usize = 6 * 1024;
/// The groups' boxes: their largest size, smaller in a smaller terminal.
const BOX_WIDTH: u16 = 60;
const BOX_HEIGHT: u16 = 22;

// ── The list ────────────────────────────────────────────────────────────────

/// The GROUPS section of the friend list: its title and one row per group,
/// and which row (counted in it) has the highlight.
pub(super) struct Section {
    pub(super) lines: Vec<Line<'static>>,
    pub(super) highlighted: Option<usize>,
}

/// The section at `width` cells (the list's border taken out); empty while
/// there is no group to show.
pub(super) fn section(app: &App, width: u16, focused: bool) -> Section {
    let look = app.look();
    let mut lines = Vec::new();
    let mut highlighted = None;
    let groups = app.group_list();
    if groups.is_empty() {
        if app.groups_error().is_some() {
            lines.push(Line::styled(SECTION_TITLE, look.theme.faint));
            lines.extend(
                wrap(LIST_UNREADABLE, width.saturating_sub(1), 0)
                    .into_iter()
                    .map(|row| Line::styled(format!(" {row}"), look.theme.warn)),
            );
        }
        return Section { lines, highlighted };
    }
    lines.push(Line::styled(SECTION_TITLE, look.theme.faint));
    for (i, group) in groups.iter().enumerate() {
        let marked = app.highlighted_group_at() == Some(i);
        if marked {
            highlighted = Some(lines.len());
        }
        lines.push(group_row(app, group, marked, width, focused));
    }
    Section { lines, highlighted }
}

/// One group's row in `width` cells: '>' when highlighted, '#', the name,
/// the member count where there is room, and the badge at the right: the
/// unread count, or 'left' / 'removed'.
fn group_row(
    app: &App,
    group: &GroupSummary,
    highlighted: bool,
    width: u16,
    focused: bool,
) -> Line<'static> {
    let (g, t) = (&app.look().glyphs, &app.look().theme);
    let (badge, badge_style) = match group.status.as_str() {
        STATUS_LEFT => (LEFT.to_owned(), t.secondary),
        STATUS_REMOVED => (REMOVED.to_owned(), t.secondary),
        _ if group.unread > 0 && t.chips => {
            (format!(" {} ", home::unread_count(group.unread)), t.unread)
        }
        _ if group.unread > 0 => (home::unread_count(group.unread), t.unread),
        _ => (String::new(), Style::default()),
    };
    let width = usize::from(width);
    let lead = 4;
    let badge_room = if badge.is_empty() {
        0
    } else {
        cells(&badge) + 1
    };
    let name_room = width
        .saturating_sub(lead + badge_room)
        .min(usize::from(home::LIST_NAME_CELLS));
    let name = display::one_line(
        &group.name,
        u16::try_from(name_room).unwrap_or(0),
        g.ellipsis,
    );
    let free = width.saturating_sub(lead + cells(&name) + cells(&badge));
    let count = format!("{} members", group.members);
    let gap = usize::from(!badge.is_empty());
    let info = (free >= 2 + cells(&count) + gap).then(|| format!("  {count}"));
    let pad = free.saturating_sub(info.as_deref().map_or(0, cells));
    let marker = if highlighted {
        widgets::marker(app.look())
    } else {
        Span::raw(" ")
    };
    // The open group in the accent where there are colours (Calm).
    let open = app
        .open_group_summary()
        .is_some_and(|open| open.id == group.id);
    let name_style = if open && t.decor { t.accent } else { t.text };
    let mut spans = vec![
        marker,
        Span::raw(" "),
        Span::styled(GROUP_MARK, t.secondary),
        Span::raw(" "),
        Span::styled(name, name_style),
    ];
    if let Some(info) = info {
        spans.push(Span::styled(info, t.secondary));
    }
    spans.push(Span::raw(" ".repeat(pad)));
    spans.push(Span::styled(badge, badge_style));
    let line = Line::from(spans);
    if highlighted && focused {
        line.style(t.selected)
    } else {
        line
    }
}

// ── The chat ────────────────────────────────────────────────────────────────

/// Where the group chat pane's parts go, inside its border.
struct Parts {
    header: Rect,
    messages: Rect,
    separator: Rect,
    hint: (Rect, Vec<Line<'static>>),
    composer: (Rect, ComposerView),
}

/// The pane's parts, top to bottom: the group's header, the messages, a
/// separator, the composer's hint and the composer (or the notice of a
/// group you are no longer in). The messages get what the others leave.
fn parts(app: &App, rect: Rect) -> Parts {
    let inner = home::chat_block(app.look(), false).inner(rect);
    let width = inner.width;
    let composer = composer_view(app, width);
    let hint = hint_lines(app, width);
    let mut left = inner.height;
    let mut take = |rows: usize| {
        let rows = u16::try_from(rows).unwrap_or(u16::MAX).min(left);
        left -= rows;
        rows
    };
    let header_h = take(1);
    let composer_h = take(composer.rows.len().max(1));
    let separator_h = take(1);
    let hint_h = take(hint.len());
    let messages_h = left;
    let at = |y: u16, height: u16| Rect { y, height, ..inner };
    let header = at(inner.y, header_h);
    let messages = at(header.bottom(), messages_h);
    let separator = at(messages.bottom(), separator_h);
    let hint_rect = at(separator.bottom(), hint_h);
    let composer_rect = at(hint_rect.bottom(), composer_h);
    Parts {
        header,
        messages,
        separator,
        hint: (hint_rect, hint),
        composer: (composer_rect, composer),
    }
}

/// The open group's chat in the conversation pane, drawn at `now`.
pub(super) fn render_chat(f: &mut Frame, rect: Rect, app: &App, now: Instant) {
    let look = app.look();
    let focused = matches!(app.focus(), Focus::Composer | Focus::Messages);
    f.render_widget(home::chat_block(look, focused), rect);
    let parts = parts(app, rect);
    f.render_widget(
        Paragraph::new(header_line(app, parts.header.width)),
        parts.header,
    );
    render_messages(f, parts.messages, app, now);
    f.render_widget(
        Paragraph::new(separator_line(app, parts.separator.width)),
        parts.separator,
    );
    let (hint_rect, hint) = parts.hint;
    f.render_widget(Paragraph::new(hint), hint_rect);
    let (composer_rect, composer) = parts.composer;
    if let Some((row, column)) = composer.cursor {
        let typing = app.focus() == Focus::Composer && app.overlays().is_empty();
        if typing && row < composer_rect.height {
            f.set_cursor_position(Position::new(
                composer_rect.x + column,
                composer_rect.y + row,
            ));
        }
    }
    f.render_widget(Paragraph::new(composer.rows), composer_rect);
}

/// The group's header row: its name, how many members it has, and whether
/// you are its admin, or no longer in it.
fn header_line(app: &App, width: u16) -> Line<'static> {
    let (g, t) = (&app.look().glyphs, &app.look().theme);
    let Some(group) = app.open_group_summary() else {
        return Line::default();
    };
    let mut spans = vec![
        Span::styled(
            display::one_line(&group.name, home::NAME_CELLS, g.ellipsis),
            t.title,
        ),
        Span::raw("  "),
        Span::styled(format!("{} members", group.members), t.secondary),
    ];
    let state = match group.status.as_str() {
        STATUS_LEFT => Some(("you left", t.warn)),
        STATUS_REMOVED => Some(("you were removed", t.warn)),
        _ if group.i_am_admin => Some(("you are the admin", t.secondary)),
        _ => None,
    };
    if let Some((words, style)) = state {
        let used = Line::from(spans.clone()).width();
        if used + cells(g.inline_separator) + cells(words) <= usize::from(width) {
            spans.push(Span::styled(g.inline_separator, t.secondary));
            spans.push(Span::styled(words, style));
        }
    }
    Line::from(spans)
}

/// The messages, newest at the bottom, scrolled up by the App's scroll; or
/// why there are none to show.
fn render_messages(f: &mut Frame, rect: Rect, app: &App, now: Instant) {
    let look = app.look();
    let rows = |text: &str, style: Style| -> Vec<Line<'static>> {
        wrap(text, rect.width, 0)
            .into_iter()
            .map(|row| Line::styled(row, style))
            .collect()
    };
    let items = app.group_items();
    let lines = if app.group_chat().is_none() && app.group_chat_error().is_some() {
        rows(CHAT_UNREADABLE, look.theme.warn)
    } else if app.group_chat().is_none() && items.is_empty() {
        rows(
            &format!("{}{}", home::LOADING, look.glyphs.ellipsis),
            look.theme.secondary,
        )
    } else if items.is_empty() {
        let name = app.open_group_summary().map_or(String::new(), |g| {
            display::one_line(&g.name, home::NAME_CELLS, look.glyphs.ellipsis)
        });
        let text = if app.group_composer().is_some() {
            format!("No messages in {name} yet. Say hello!")
        } else {
            format!("No messages in {name}.")
        };
        rows(&text, look.theme.secondary)
    } else {
        let height = usize::from(rect.height);
        let lines = tail(app, rect.width, app.scroll() + height, now);
        let scroll = app.scroll().min(lines.len().saturating_sub(height));
        let end = lines.len() - scroll;
        let start = end.saturating_sub(height);
        let shown = &lines[start..end];
        // Newest at the bottom.
        let top = u16::try_from(height - shown.len()).unwrap_or(0);
        let rect = Rect {
            y: rect.y + top,
            height: rect.height - top,
            ..rect
        };
        f.render_widget(Paragraph::new(shown.to_vec()), rect);
        return;
    };
    f.render_widget(Paragraph::new(lines), rect);
}

/// The last rows of the chat at `width` cells: whole messages, from the
/// newest back until there are at least `needed` rows (or none is left).
fn tail(app: &App, width: u16, needed: usize, now: Instant) -> Vec<Line<'static>> {
    let chosen = app.chosen();
    let mut messages = Vec::new();
    let mut count = 0;
    let items = app.group_items();
    for (from_newest, index) in (0..items.len()).rev().enumerate() {
        if count >= needed {
            break;
        }
        let older = index.checked_sub(1).map(|i| items[i]);
        let rule = home::day_rule_at(app, older.map(|o| o.at_ms()), items[index].at_ms(), width);
        let continued = rule.is_none() && continues(older, items[index]);
        let marked = chosen == Some(from_newest);
        let mut lines = message_lines(app, items[index], continued, marked, width, now);
        if let Some(rule) = rule {
            lines.insert(0, rule);
        }
        count += lines.len();
        messages.push(lines);
    }
    messages.into_iter().rev().flatten().collect()
}

/// Who `item` is from, as its header row says it: yours, or its author and
/// the member that passed it on.
fn sender(item: GroupItem<'_>) -> Option<(&str, Option<&str>)> {
    match item {
        GroupItem::Message(m) if !m.mine => Some((m.author.as_str(), m.via.as_deref())),
        _ => None,
    }
}

/// Whether `item` goes on from the `older` one before it: the same sender
/// (and the same member passing it on), less than [`home::RUN_GAP_MS`]
/// after it. Its sender and age aren't said again.
fn continues(older: Option<GroupItem<'_>>, item: GroupItem<'_>) -> bool {
    older.is_some_and(|older| {
        sender(older) == sender(item) && item.at_ms().abs_diff(older.at_ms()) < home::RUN_GAP_MS
    })
}

/// One message: its header row ('<author> · 5 min ago', with 'passed on by
/// <member>' for a forwarded one, and for yours the tick and 'Delivered to
/// 1 of 2'; the '>' marker first when `marked`), what did not fit on it
/// under it, then the body, indented and wrapped. When it `continued` its
/// sender's run, the sender, age and who passed it on aren't said again: a
/// member's message is its body alone, one of yours keeps its delivery line
/// (unless it is the chosen one: then all of its header).
fn message_lines(
    app: &App,
    item: GroupItem,
    continued: bool,
    marked: bool,
    width: u16,
    now: Instant,
) -> Vec<Line<'static>> {
    let continued = continued && !marked;
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    let who = match item {
        GroupItem::Message(m) if !m.mine => {
            display::one_line(&m.author, home::NAME_CELLS, g.ellipsis)
        }
        _ => "You".to_owned(),
    };
    let mut head = Vec::new();
    if marked {
        head.push(Span::styled(format!("{} ", g.selected), t.accent));
    }
    // Calm: yours in the accent, a member's name bold.
    let mine = !matches!(item, GroupItem::Message(m) if !m.mine);
    let who_style = if mine {
        t.accent.add_modifier(Modifier::BOLD)
    } else {
        t.title
    };
    if !continued {
        head.push(Span::styled(who, who_style));
        let age = super::bridge::short_age(app.now_ms(), item.at_ms());
        if !age.is_empty() {
            head.push(Span::styled(g.inline_separator, t.secondary));
            head.push(Span::styled(age, t.secondary));
        }
    }
    let fits = |head: &[Span<'static>], more: usize| {
        Line::from(head.to_vec()).width() + more <= usize::from(width)
    };
    let mut below: Vec<Line<'static>> = Vec::new();
    // How and when it came (E2 r9: no path, only "2 min ago"): a member's
    // way ("via Tor", "from a keeper"), who passed it on, when it arrived;
    // yours, when you sent it. The clock time only with this computer's
    // offset. Not said again when it `continued` its sender's run (Calm).
    let mut details = Vec::new();
    if let (GroupItem::Message(m), false) = (item, continued) {
        let now_ms = app.now_ms();
        if m.mine {
            details.extend(
                super::bridge::happened_text(m.sent_ms, now_ms).map(|at| format!("sent {at}")),
            );
        } else {
            details.extend(m.path.map(|p| p.phrase()));
            details.extend(m.via.as_ref().map(|via| {
                format!(
                    "passed on by {}",
                    display::one_line(via, home::NAME_CELLS, g.ellipsis)
                )
            }));
            details.extend(
                super::bridge::happened_text(m.at_ms, now_ms).map(|at| format!("arrived {at}")),
            );
        }
    }
    for text in details {
        if below.is_empty() && fits(&head, cells(g.inline_separator) + cells(&text)) {
            head.push(Span::styled(g.inline_separator, t.secondary));
            head.push(Span::styled(text, t.secondary));
        } else {
            below.extend(styled(
                &text,
                width.saturating_sub(home::BODY_INDENT),
                t.secondary,
            ));
        }
    }
    let mut waiting = false;
    if let Some((mark, label)) = tick(item, look) {
        // A send no read has yet is under way: the accent, as a friend's.
        let sending = matches!(item, GroupItem::Sending(_));
        let some_have_it = matches!(item, GroupItem::Message(m) if m.delivered > 0);
        let style = if sending {
            t.accent
        } else if some_have_it {
            // Delivered to some: the colour of things that went.
            t.ok
        } else {
            widgets::tick_label_style(mark, look)
        };
        waiting = matches!(mark, TickMark::Waiting) && !sending;
        head.push(Span::raw("  "));
        head.push(widgets::tick(mark, look, now));
        if fits(&head, 1 + cells(&label)) {
            head.push(Span::raw(" "));
            head.push(Span::styled(label, style));
        } else {
            below.extend(styled(
                &label,
                width.saturating_sub(home::BODY_INDENT),
                style,
            ));
        }
        // Who is still waiting for it, as raven-node reports each copy.
        if let GroupItem::Message(m) = item {
            let note = waiting_note(look, m);
            let note_cells: usize = note.iter().map(Span::width).sum();
            if !note.is_empty() {
                if fits(&head, cells(g.inline_separator) + note_cells) {
                    head.push(Span::styled(g.inline_separator, t.secondary));
                    head.extend(note);
                } else {
                    below.push(Line::from(note));
                }
            }
        }
    }
    let head = Line::from(head);
    let mut lines = Vec::new();
    if !head.spans.is_empty() {
        lines.push(if marked { head.style(t.selected) } else { head });
    }
    let indent = " ".repeat(usize::from(home::BODY_INDENT));
    for row in below {
        let mut spans = vec![Span::raw(indent.clone())];
        spans.extend(row.spans);
        lines.push(Line::from(spans).style(row.style));
    }
    // Your own lines behind the bar where the theme draws it (Calm).
    let lead = mine
        .then(|| widgets::own_bar(look, waiting))
        .flatten()
        .unwrap_or_else(|| Span::raw(indent.clone()));
    let body = display::body_lines(item.body(), app.expanded(&item.key()));
    let last = body.lines.len().saturating_sub(1);
    for (i, mut text) in body.lines.into_iter().enumerate() {
        if i == last && body.more_chars > 0 {
            text.push_str(home::CLIPPED_HINT);
        }
        let room = usize::from(width.saturating_sub(home::BODY_INDENT));
        lines.extend(
            home::wrap_text(&text, room)
                .into_iter()
                .map(|piece| Line::from(vec![lead.clone(), Span::styled(piece, t.text)])),
        );
    }
    lines
}

/// Who a message of yours still waits for (Calm), as raven-node reports
/// each member's copy: the member by name when one waits ('Sam waiting'),
/// else how many; and, in the friends' colour, that another member passes
/// a copy on where the node says so. Nothing while none waits, nor while
/// every copy still waits and none goes through another member ('Delivered
/// to 0 of 2' says it).
fn waiting_note(look: &Look, m: &GroupMessage) -> Vec<Span<'static>> {
    let t = &look.theme;
    let waiting: Vec<&MemberLine> = m
        .lines
        .iter()
        .filter(|line| line.state == LINE_WAITING)
        .collect();
    let relayed = waiting.iter().filter(|line| line.relayed).count();
    if waiting.len() == m.lines.len() && relayed == 0 {
        return Vec::new();
    }
    let friend = t.path(PathKind::Friend);
    match waiting[..] {
        [] => Vec::new(),
        [one] => {
            let name = display::one_line(&one.name, home::NAME_CELLS, look.glyphs.ellipsis);
            let mut note = vec![Span::styled(format!("{name} waiting"), t.warn)];
            if one.relayed {
                note.push(Span::styled(": another member passes it on", friend));
            }
            note
        }
        _ => {
            let mut note = vec![Span::styled(format!("{} waiting", waiting.len()), t.warn)];
            if relayed > 0 {
                note.push(Span::styled(
                    format!(" ({relayed} passed on by other members)"),
                    friend,
                ));
            }
            note
        }
    }
}

/// The tick and label of a message of yours: the mark of how far its copies
/// got (all delivered; none left to go; one at least left this computer;
/// all waiting) and 'Delivered to d of n'. A send no read has yet:
/// 'Sending…'. None for a member's message, and for one to nobody else.
fn tick(item: GroupItem, look: &Look) -> Option<(TickMark, String)> {
    let m = match item {
        GroupItem::Sending(_) => {
            return Some((
                TickMark::Waiting,
                format!("Sending{}", look.glyphs.ellipsis),
            ))
        }
        GroupItem::Message(m) if m.mine && m.total > 0 => m,
        GroupItem::Message(_) => return None,
    };
    let going = m
        .lines
        .iter()
        .filter(|line| matches!(line.state.as_str(), LINE_WAITING | LINE_SENT))
        .count();
    let mark = if m.delivered >= m.total {
        TickMark::Delivered
    } else if going == 0 {
        TickMark::Failed
    } else if m.delivered > 0 || m.lines.iter().any(|line| line.state == LINE_SENT) {
        TickMark::Sent
    } else {
        TickMark::Waiting
    };
    Some((mark, format!("Delivered to {} of {}", m.delivered, m.total)))
}

/// The composer: 'To <group>: ' and what is typed; for a group you are no
/// longer in, the notice instead.
fn composer_view(app: &App, width: u16) -> ComposerView {
    let look = app.look();
    let summary = app.open_group_summary();
    match app.group_composer() {
        Some(composer) => {
            let name = summary.map_or(String::new(), |g| {
                display::one_line(&g.name, home::NAME_CELLS, look.glyphs.ellipsis)
            });
            home::composer_for(app, &name, composer, width)
        }
        None => {
            let notice = match summary.map(|g| g.status.as_str()) {
                Some(STATUS_REMOVED) => REMOVED_NOTICE,
                _ => LEFT_NOTICE,
            };
            ComposerView {
                rows: wrap(notice, width, 0)
                    .into_iter()
                    .map(|row| Line::styled(row, look.theme.secondary))
                    .collect(),
                cursor: None,
            }
        }
    }
}

/// Between the separator and the composer: why the draft can't go as it is.
fn hint_lines(app: &App, width: u16) -> Vec<Line<'static>> {
    let Some(problem) = app
        .group_composer()
        .and_then(|composer| group_text_problem(composer.text()))
    else {
        return Vec::new();
    };
    wrap(problem, width, 0)
        .into_iter()
        .map(|row| Line::styled(row, app.look().theme.warn))
        .collect()
}

/// The line over the composer; from 6 KB it says how much of the 8 KB a
/// group message may have is used.
fn separator_line(app: &App, width: u16) -> Line<'static> {
    let look = app.look();
    let rule = look.glyphs.border.horizontal_top;
    let width = usize::from(width);
    let used = app.group_composer().map_or(0, |c| c.text().len());
    if used > COUNTER_FROM {
        let counter = format!(
            " {} KB of {} KB ",
            used / 1024,
            raven_core::group::MAX_GROUP_BODY_BYTES / 1024
        );
        if cells(&counter) < width {
            return Line::from(vec![
                Span::styled(rule.repeat(width - cells(&counter)), look.theme.faint),
                Span::styled(counter, look.theme.warn),
            ]);
        }
    }
    Line::styled(rule.repeat(width), look.theme.faint)
}

/// Home's [`home::clamp_scroll`] while a group is open.
pub(super) fn clamp_scroll(app: &App, wanted: usize) -> usize {
    let parts = parts(app, home::chat_area(app));
    let height = usize::from(parts.messages.height);
    let total = tail(app, parts.messages.width, wanted + height, app.now()).len();
    wanted.min(total.saturating_sub(height))
}

/// Home's [`home::scroll_to_message`] while a group is open.
pub(super) fn scroll_to_message(app: &App, chosen: usize) -> usize {
    let parts = parts(app, home::chat_area(app));
    let (width, height) = (parts.messages.width, usize::from(parts.messages.height));
    let items = app.group_items();
    // A message's rows, with the day line over it when it starts a day.
    let rows = |from_newest: usize, item: GroupItem| {
        let marked = app.chosen() == Some(from_newest);
        let index = items.len() - 1 - from_newest;
        let older = index.checked_sub(1).map(|i| items[i]);
        let rule = home::day_rule_at(app, older.map(|o| o.at_ms()), item.at_ms(), width);
        let continued = rule.is_none() && continues(older, item);
        message_lines(app, item, continued, marked, width, app.now()).len()
            + usize::from(rule.is_some())
    };
    let below: usize = items
        .iter()
        .rev()
        .take(chosen)
        .enumerate()
        .map(|(i, item)| rows(i, *item))
        .sum();
    let Some(item) = items
        .len()
        .checked_sub(chosen + 1)
        .map(|index| items[index])
    else {
        return app.scroll();
    };
    let tall = rows(chosen, item);
    let mut scroll = app.scroll();
    if below + tall > scroll + height {
        scroll = (below + tall).saturating_sub(height);
    }
    if below < scroll && tall <= height {
        scroll = below;
    }
    clamp_scroll(app, scroll)
}

/// Home's [`home::page_rows`] while a group is open.
pub(super) fn page_rows(app: &App) -> usize {
    let parts = parts(app, home::chat_area(app));
    usize::from(parts.messages.height).saturating_sub(1).max(1)
}

/// Home's key hints while a group's composer or messages have the keys;
/// W for the security notices while one is `open` (P6.31).
pub(super) fn hints(app: &App, open: bool) -> Vec<(&'static str, &'static str)> {
    let up_down = app.look().glyphs.up_down;
    if app.focus() == Focus::Composer && app.group_composer().is_some() {
        return vec![
            ("?", "Help"),
            ("Esc", "Friends"),
            ("Enter", "Send"),
            ("Ctrl+J", "New line"),
            ("Tab", "Messages"),
            ("PgUp/PgDn", "Scroll"),
        ];
    }
    let mut hints = vec![
        ("?", "Help"),
        ("Esc", "Back"),
        (up_down, "Choose"),
        ("M", "Members"),
        ("Enter", "Who has it"),
    ];
    if open {
        hints.insert(2, ("W", "Security"));
    }
    hints
}

// ── The boxes ───────────────────────────────────────────────────────────────

/// Draws the groups' box `overlay` over the screen.
pub(super) fn render_overlay(f: &mut Frame, area: Rect, app: &App, overlay: &GroupOverlay) {
    match overlay {
        GroupOverlay::Name { typed, problem } => {
            render_name(f, area, app, typed, problem.as_deref());
        }
        GroupOverlay::Pick(pick) => render_pick(f, area, app, pick),
        GroupOverlay::Members(members) => render_members(f, area, app, members),
        GroupOverlay::Delivery { message, .. } => render_delivery(f, area, app, message),
    }
}

/// A box with `title` on its border, `lines` in it (cut to fit, the keys at
/// the bottom kept), centred; where it was drawn.
fn draw_box(
    f: &mut Frame,
    area: Rect,
    look: &Look,
    title: &str,
    lines: Vec<Line<'static>>,
) -> Rect {
    let rect = overlays::centered(area, BOX_WIDTH, overlays::height_of(&lines));
    let title = display::one_line(title, rect.width.saturating_sub(4), look.glyphs.ellipsis);
    let block =
        overlays::overlay_block(look).title(Span::styled(format!(" {title} "), look.theme.title));
    widgets::clear(f, rect, look);
    f.render_widget(
        Paragraph::new(overlays::fit(lines, rect.height)).block(block),
        rect,
    );
    rect
}

/// Cells for text inside a box in `area`.
fn box_inner(area: Rect) -> u16 {
    overlays::inner_width(BOX_WIDTH.min(area.width))
}

/// `text` wrapped to `width` cells in `style`.
fn styled(text: &str, width: u16, style: Style) -> Vec<Line<'static>> {
    wrap(text, width, 0)
        .into_iter()
        .map(|row| Line::styled(row, style))
        .collect()
}

/// NEW GROUP's first step: the name, typed into a field.
fn render_name(f: &mut Frame, area: Rect, app: &App, typed: &str, problem: Option<&str>) {
    let look = app.look();
    let width = box_inner(area);
    let mut lines = styled(
        "Its name. Everyone in the group sees it.",
        width,
        Style::default(),
    );
    lines.push(Line::default());
    let field = format!(
        "> {}",
        display::one_line(typed, width.saturating_sub(3), look.glyphs.ellipsis)
    );
    let field_row = lines.len();
    lines.push(Line::raw(field.clone()));
    if let Some(problem) = problem {
        lines.extend(styled(problem, width, look.theme.warn));
    }
    lines.push(Line::default());
    lines.push(overlays::keys_line(
        look,
        &[("[Enter]", " Next"), ("[Esc]", " Cancel")],
    ));
    let rect = draw_box(f, area, look, "New group", lines);
    let inner = overlays::overlay_block(look).inner(rect);
    if let Ok(y) = u16::try_from(field_row) {
        let x = u16::try_from(cells(&field)).unwrap_or(u16::MAX);
        if y < inner.height && x < inner.width {
            f.set_cursor_position(Position::new(inner.x + x, inner.y + y));
        }
    }
}

/// The friend picker: the friends, the ones picked marked [x], the one the
/// cursor is on '>'; what Enter does, and why it can't yet.
fn render_pick(f: &mut Frame, area: Rect, app: &App, pick: &PickState) {
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    let width = box_inner(area);
    let candidates = app.pick_candidates(&pick.purpose);
    let (title, intro, enter, busy, none) = match &pick.purpose {
        PickFor::Create { name } => (
            format!("New group: {name}"),
            format!(
                "Pick the friends in it, at most {}. They are in it at once, and can leave.",
                app.pick_cap(&pick.purpose)
            ),
            " Create",
            "Creating the group",
            "No friends to pick yet: add a friend first (A on the list).",
        ),
        PickFor::Add { group } => (
            format!(
                "Add to {}",
                app.group_list()
                    .iter()
                    .find(|s| s.id == *group)
                    .map_or("the group", |s| s.name.as_str())
            ),
            "Pick the friends to add.".to_owned(),
            " Add",
            "Adding them",
            "Every friend of yours is in the group already.",
        ),
    };
    let mut head = styled(&intro, width, Style::default());
    head.push(Line::default());
    let mut foot = vec![Line::default()];
    if pick.busy {
        foot.push(Line::styled(format!("{busy}{}", g.ellipsis), t.secondary));
    } else if let Some(problem) = &pick.problem {
        foot.extend(styled(problem, width, t.warn));
    } else {
        foot.push(Line::styled(
            format!("{} picked", pick.picked.len()),
            t.secondary,
        ));
    }
    foot.push(overlays::keys_line(
        look,
        &[("[Space]", " Pick"), ("[Enter]", enter), ("[Esc]", " Back")],
    ));
    let room = usize::from(BOX_HEIGHT.min(area.height))
        .saturating_sub(2 + head.len() + foot.len())
        .max(1);
    let rows: Vec<Line<'static>> = if candidates.is_empty() {
        styled(none, width, t.secondary)
    } else {
        let first = (pick.cursor + 1).saturating_sub(room);
        candidates
            .iter()
            .enumerate()
            .skip(first)
            .take(room)
            .map(|(i, friend)| {
                let on = i == pick.cursor;
                let picked = pick
                    .picked
                    .iter()
                    .any(|k| k.eq_ignore_ascii_case(&friend.pub_hex));
                let marker = if on {
                    widgets::marker(look)
                } else {
                    Span::raw(" ")
                };
                let check = if picked { "[x]" } else { "[ ]" };
                let name = display::one_line(&friend.label, width.saturating_sub(6), g.ellipsis);
                let line = Line::from(vec![
                    marker,
                    Span::raw(" "),
                    Span::styled(check, if picked { t.accent } else { t.secondary }),
                    Span::styled(format!(" {name}"), t.text),
                ]);
                if on {
                    line.style(t.selected)
                } else {
                    line
                }
            })
            .collect()
    };
    let mut lines = head;
    lines.extend(rows);
    lines.extend(foot);
    draw_box(f, area, look, &title, lines);
}

/// MEMBERS: each member with what they are to you; the admin's keys (add,
/// remove) or a member's (leave), and a question before either is done.
fn render_members(f: &mut Frame, area: Rect, app: &App, members: &MembersState) {
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    let width = box_inner(area);
    let chat = app
        .group_chat()
        .filter(|chat| chat.view.summary.id == members.group);
    let Some(chat) = chat else {
        let lines = vec![
            Line::styled(format!("Reading the group{}", g.ellipsis), t.secondary),
            Line::default(),
            overlays::keys_line(look, &[("[Esc]", " Close")]),
        ];
        draw_box(f, area, look, "Members", lines);
        return;
    };
    let group = &chat.view.summary;
    let active = app.group_active(&group.id);
    let title = format!(
        "{} {} {} members",
        group.name,
        g.inline_separator.trim(),
        group.members
    );
    let mut lines = Vec::new();
    let room = usize::from(BOX_HEIGHT.min(area.height))
        .saturating_sub(8)
        .max(1);
    let first = (members.cursor + 1).saturating_sub(room);
    for (i, member) in chat.view.members.iter().enumerate().skip(first).take(room) {
        let on = i == members.cursor;
        let mut tags = Vec::new();
        if member.admin {
            tags.push("admin");
        }
        if !member.me {
            tags.push(if member.friend_name.is_some() {
                "your friend"
            } else {
                "not your friend"
            });
        }
        let name = if member.me {
            "You".to_owned()
        } else {
            display::one_line(&member.display(), home::NAME_CELLS, g.ellipsis)
        };
        let marker = if on {
            widgets::marker(look)
        } else {
            Span::raw(" ")
        };
        let mut spans = vec![marker, Span::styled(format!(" {name}"), t.text)];
        if !tags.is_empty() {
            spans.push(Span::styled(
                format!("{}{}", g.inline_separator, tags.join(", ")),
                t.secondary,
            ));
        }
        let line = Line::from(spans);
        lines.push(if on { line.style(t.selected) } else { line });
    }
    lines.push(Line::default());
    if !active {
        let notice = if group.status == STATUS_REMOVED {
            REMOVED_NOTICE
        } else {
            LEFT_NOTICE
        };
        lines.extend(styled(notice, width, t.secondary));
        lines.push(Line::default());
    }
    if let Some(ask) = &members.ask {
        let (question, yes, no) = match ask {
            MemberAsk::Remove { name, .. } => (
                format!(
                    "Remove {} from {}? They keep what they already received.",
                    display::one_line(name, home::NAME_CELLS, g.ellipsis),
                    display::one_line(&group.name, home::NAME_CELLS, g.ellipsis)
                ),
                " Remove",
                " Keep them",
            ),
            MemberAsk::Leave => (
                format!(
                    "Leave {}? You get none of its new messages and send none; what you \
                     received stays here.",
                    display::one_line(&group.name, home::NAME_CELLS, g.ellipsis)
                ),
                " Leave",
                " Stay",
            ),
        };
        lines.extend(styled(&question, width, Style::default()));
        lines.push(Line::default());
        if members.busy {
            lines.push(Line::styled(format!("Saving{}", g.ellipsis), t.secondary));
        } else {
            lines.push(overlays::keys_line(look, &[("[Y]", yes), ("[N]", no)]));
        }
    } else {
        let keys: &[(&'static str, &'static str)] = match (active, group.i_am_admin) {
            (true, true) => &[("[A]", " Add"), ("[X]", " Remove"), ("[Esc]", " Close")],
            (true, false) => &[("[L]", " Leave the group"), ("[Esc]", " Close")],
            (false, _) => &[("[Esc]", " Close")],
        };
        lines.push(overlays::keys_line(look, keys));
    }
    draw_box(f, area, look, &title, lines);
}

/// WHO HAS IT: a message of yours, member by member.
fn render_delivery(f: &mut Frame, area: Rect, app: &App, message: &[u8; 16]) {
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    let width = box_inner(area);
    let found = app
        .group_chat()
        .and_then(|chat| chat.messages.iter().find(|m| m.id == *message));
    let mut lines = Vec::new();
    match found {
        None => lines.extend(styled(
            "This message isn't in the group's chat any more.",
            width,
            t.secondary,
        )),
        Some(m) => {
            lines.push(Line::raw(format!(
                "Delivered to {} of {}.",
                m.delivered, m.total
            )));
            lines.push(Line::default());
            let names: Vec<String> = m
                .lines
                .iter()
                .map(|line| display::one_line(&line.name, home::NAME_CELLS, g.ellipsis))
                .collect();
            let column = names.iter().map(|n| cells(n)).max().unwrap_or(0) + 2;
            for (name, line) in names.iter().zip(&m.lines) {
                let pad = " ".repeat(column.saturating_sub(cells(name)));
                let (words, style) = line_words(line, t);
                lines.push(Line::from(vec![
                    Span::raw(format!("{name}{pad}")),
                    Span::styled(words, style),
                ]));
            }
        }
    }
    lines.push(Line::default());
    lines.push(overlays::keys_line(look, &[("[Esc]", " Close")]));
    draw_box(f, area, look, "Who has it", lines);
}

/// One member's copy in words.
fn line_words(line: &MemberLine, t: &super::theme::Theme) -> (&'static str, Style) {
    match line.state.as_str() {
        LINE_DELIVERED => ("delivered", t.ok),
        LINE_SENT => ("sent, not confirmed yet", t.secondary),
        LINE_FAILED => ("not delivered", t.bad),
        _ if line.relayed => (
            "waiting: another member passes it on",
            t.path(super::theme::PathKind::Friend),
        ),
        _ => ("waiting", t.warn),
    }
}

#[cfg(test)]
mod tests;
