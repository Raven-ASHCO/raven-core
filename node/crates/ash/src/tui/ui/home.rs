//! HOME: the friend list, the open conversation and the composer, between
//! the header row and the key hints.
//!
//! - From 80 columns the list (22 columns) and the conversation sit side by
//!   side; from 60 to 79 one shows at a time: the list, or the open
//!   conversation (Enter opens it, Esc goes back).
//! - The highlight in the list is not the open friend: only Enter changes
//!   whom the conversation shows and the composer writes to, and the
//!   composer row always starts 'To <name>: '. The terminal's own cursor
//!   sits in it while it has the keys.
//! - Every name and body is untrusted and drawn through display.rs. Bodies
//!   are wrapped to the pane, so no text reaches the pane beside it.
//! - A friend's mark (presence.rs) is green while in touch and breathes,
//!   the warning's colour while messages wait, faint when quiet (Calm);
//!   the glyph says it too.
//! - Message rows keep the order the history wrote them in, and their times
//!   are ages only (`bridge::short_age`). A message sent in this session
//!   shows at the bottom until its history row is there. A run of messages
//!   from one sender, each less than 5 minutes after the one before, has one
//!   sender line; yours keep their delivery line each.
//! - Each message of yours has its delivery tick and label (delivery.rs): a
//!   spinner while it sends, Delivered typing itself then the path it went
//!   by when this app knows it, a failure's mark blinking twice; all still
//!   under reduced motion. A message raven-node keeps trying says until
//!   when it can wait, and what the outbox says of its last try. Your own
//!   lines have the bar before them where the theme draws it; day lines
//!   when this computer's calendar can be read. In Messages focus the
//!   chosen message has the '>' marker.
//! - Under the open friend's name, dim: until when Raven keeps trying a
//!   message written to them now, that they have to meet first, or the rule
//!   a first message goes by (then the composer's hint says when Raven can
//!   send), as the store worker last read it. A draw never reads it; not
//!   known, no line.
//! - The live feel (UXF.10, live.rs): the header says 'R A V E N · <name>'
//!   and, on the right, the heartbeat with 'node ok · <age>' while the
//!   background program listens and answers (else the node chip), then the
//!   clock. Under the open friend's name, the route line from you to them
//!   and how the last delivery went; a message travels it while its send
//!   runs, the receipt travels back once it came, a friend's message
//!   travels in before it shows. In the list, an in-touch mark breathes, a
//!   friend's row blinks with news, and a waiting mark rings when Raven
//!   tries again. From 20 rows the footer names the latest event and draws
//!   the activity line. Under reduced motion only text changes.
//! - Security (Phase 6b P6.31): the header's chip counts the open alerts
//!   and warnings ('⚠ 2', ASCII '!2'; W opens SEC); a friend's badge says
//!   one is open about them (over 'not verified'); the open friend's
//!   banner says what happened, with [V] [D] [P]; while sending to them is
//!   paused the banner and the composer's hint say how to resume. The
//!   words are security_text.rs's, through bridge.rs.
//! - Groups (lab only, ui/groups.rs): while they are live, the list has a
//!   GROUPS section under the friends and a second footer row (C, a new
//!   group), the highlight moves over both, and an open group's chat takes
//!   the conversation pane. While they are not, nothing here changes.

use std::time::{Duration, Instant};

use ratatui::buffer::CellWidth;
use ratatui::layout::{Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Padding, Paragraph};
use ratatui::Frame;

use super::anim::{self, Moving};
use super::app::{App, Bubble, Composer, Focus, Row, Screen, TickView};
#[cfg(test)]
use super::app::{Cmd, JobResult, Msg, PasteVia, SendJob, Session};
use super::bridge::{self, ContactView};
#[cfg(test)]
use super::controller::{Conversations, Horizons, RowView, SendResult};
use super::delivery::{self, Tick};
use super::groups;
#[cfg(test)]
use super::node::Probe;
use super::presence::{self, Presence};
#[cfg(test)]
use super::render as render_frame;
#[cfg(test)]
use super::state_file::{Receive, TuiState};
use super::theme::{Motion, BREATHE};
use super::widgets::{self, Chip, Dot, TickMark};
#[cfg(test)]
use super::workers::PollUpdate;
use super::{cells, display, errors, live, logo, wrap, Look};
#[cfg(test)]
use super::{testkit, theme};

/// From this many columns, the list and the conversation side by side.
pub(crate) const TWO_PANES_FROM: u16 = 80;
/// The list's width beside the conversation; from [`WIDE_LIST_FROM`]
/// columns, [`WIDE_LIST_WIDTH`] (room for the path a friend was last
/// reached by).
const LIST_WIDTH: u16 = 22;
const WIDE_LIST_FROM: u16 = 120;
const WIDE_LIST_WIDTH: u16 = 30;
/// Cells a friend's name takes in the list, at most.
pub(super) const LIST_NAME_CELLS: u16 = 14;
/// Cells a friend's name takes anywhere else, at most.
pub(crate) const NAME_CELLS: u16 = 24;
/// Message bodies sit this far in under their header row.
pub(super) const BODY_INDENT: u16 = 2;
/// The composer grows to this many rows, then scrolls with its cursor.
const COMPOSER_ROWS: usize = 3;
/// Above this many bytes the composer shows how much of the limit is used.
const COUNTER_FROM: usize = 40 * 1024;

const LIST_TITLE: &str = " Friends ";
/// The list's title while it holds the groups too (groups, lab).
const CHATS_TITLE: &str = " Chats ";
const LIST_EMPTY: [&str; 2] = ["No friends yet.", "Press A to add one."];
const LIST_FOOTER: (&str, &str) = ("A", "  Add a friend");
const LIST_UNREADABLE: &str = "Raven can't read your list of friends right now.";
const BLOCKED: &str = "blocked";
/// A friend's badge while not verified, where the name leaves room (else
/// the alert mark).
const NOT_VERIFIED: &str = "not verified";
/// A friend's badge while sending to them is paused (P6.31).
const PAUSED: &str = "paused";
/// The security banner's keys (P6.31): they act on the friend highlighted
/// in the list, as V and E do.
const SECURITY_KEYS: &str = "[V] Compare words  [D] Details  [P] Pause sending";
const PAUSED_KEYS: &str = "[V] Compare words  [D] Details  [P] Resume sending";
const RESUME_KEYS: &str = "[P] Resume sending";
const COMPOSER_OFF: &str = "Pick a friend on the left and press Enter to start writing.";
pub(super) const LOADING: &str = "Loading messages";
/// After a clipped body's `… (+N more characters)`.
pub(super) const CLIPPED_HINT: &str = ". Press Enter on this message to show all.";
/// A failure's mark blinks twice: off and on, twice, in a second.
const BLINK_FRAMES: u32 = 4;
const BLINK_TIME: Duration = Duration::from_secs(1);
/// From this many rows the footer has its status row (the ticker and the
/// activity line) above the key hints; below, the conversation keeps it.
pub(crate) const STATUS_ROW_FROM: u16 = 20;
/// The route line's longest stretch between you and the friend.
const ROUTE_CELLS: usize = 26;
/// Before the activity line.
const ACTIVITY: &str = "activity ";
/// A message less than this after the one before it, from the same
/// sender, goes on its run: no sender line of its own.
pub(super) const RUN_GAP_MS: u64 = 5 * 60_000;

/// Whether a terminal of `size` shows the list and the conversation side by
/// side.
pub(crate) fn two_panes(size: (u16, u16)) -> bool {
    size.0 >= TWO_PANES_FROM
}

/// Draws Home: the live header with the user's own name, the panes, the
/// status row, the key hints for the focus, and the cursor in the composer
/// while it has the keys.
pub(super) fn render(f: &mut Frame, area: Rect, app: &App, now: Instant) {
    if area.is_empty() {
        return;
    }
    let look = app.look();
    render_header(f, area, app, now);
    let (list, chat) = panes(app, body_area(area));
    if let Some(list) = list {
        render_list(f, list, app, now);
    }
    if let Some(chat) = chat {
        if app.open_group().is_some() {
            groups::render_chat(f, chat, app, now);
        } else {
            render_chat(f, chat, app, list.is_none(), now);
        }
    }
    if area.height >= STATUS_ROW_FROM {
        let status = Rect {
            y: area.bottom() - 2,
            height: 1,
            ..area
        };
        render_status(f, status, app, now);
    }
    if area.height > 1 {
        let last = Rect {
            y: area.bottom() - 1,
            height: 1,
            ..area
        };
        let open = !app.notices().is_empty();
        let keys = if app.open_group().is_some() && app.focus() != Focus::Friends {
            groups::hints(app, open)
        } else {
            let mut keys = hints(look, app.focus(), open);
            // A new group (lab), next to adding a friend.
            if app.groups_live() && app.focus() == Focus::Friends {
                let at = keys
                    .iter()
                    .position(|k| k.0 == "A")
                    .map_or(keys.len(), |a| a + 1);
                keys.insert(at, ("C", "New group"));
            }
            keys
        };
        let hints = widgets::key_bar(look, &keys, area.width);
        f.render_widget(Paragraph::new(hints), last);
    }
}

/// Home's header row (UXF.10): 'R A V E N · <name>' on the left; on the
/// right the heartbeat and 'node ok · <age>' while the background program
/// listens and its last Status answered (any other state: the node chip),
/// then the clock with seconds when this computer's time can be read. The
/// name is cut to the room the right side leaves; none when empty.
fn render_header(f: &mut Frame, area: Rect, app: &App, now: Instant) {
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    let header = Rect { height: 1, ..area };
    let wall = app.wall_ms(now);
    let mut right = Vec::new();
    // The security chip (P6.31), next to the node's.
    if let Some(alarm) = widgets::alarm_chip(look, app.notices().len()) {
        right.push(alarm);
        right.push(Span::styled(g.inline_separator, t.secondary));
    }
    match (app.chip(), app.live().beat) {
        (Some(Chip::Listening { .. }), Some(beat)) => {
            let heart = if live::pulse_on(beat.at_ms, wall, look.motion) {
                t.ok.add_modifier(Modifier::BOLD)
            } else {
                t.ok
            };
            right.extend([
                Span::styled(g.heart, heart),
                Span::styled(" node ok", t.secondary),
                Span::styled(g.inline_separator, t.secondary),
                Span::styled(live::live_age(wall, beat.at_ms), t.secondary),
            ]);
        }
        (Some(chip), _) => right.extend(widgets::chip(chip, look, now).spans),
        (None, _) => {}
    }
    if let Some(clock) = bridge::clock_text(wall) {
        if !right.is_empty() {
            right.push(Span::styled(g.inline_separator, t.secondary));
        }
        right.push(Span::styled(clock, t.secondary));
    }
    let right = Line::from(right);
    let own_name = app.settings().display_name.trim();
    let mut left = vec![Span::styled(logo::WORDMARK, t.title)];
    let used = cells(logo::WORDMARK) + cells(g.inline_separator) + right.width() + 1;
    let room = u16::try_from(usize::from(area.width).saturating_sub(used)).unwrap_or(0);
    let name = display::one_line(own_name, room, g.ellipsis);
    if !own_name.is_empty() && !name.is_empty() {
        left.push(Span::styled(g.inline_separator, t.secondary));
        left.push(Span::styled(name, t.secondary));
    }
    f.render_widget(Paragraph::new(Line::from(left)), header);
    f.render_widget(Paragraph::new(right).right_aligned(), header);
}

/// The status row (UXF.10): the ticker on the left, cut to the room left,
/// and the activity line on the right.
fn render_status(f: &mut Frame, rect: Rect, app: &App, now: Instant) {
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    let wall = app.wall_ms(now);
    let buckets = live::activity(app.message_times(), wall);
    let right = Line::from(vec![
        Span::styled(ACTIVITY, t.faint),
        Span::styled(live::sparkline(&buckets, g), t.secondary),
    ]);
    let (texts, style) = ticker(app, now);
    let room = usize::from(rect.width).saturating_sub(right.width() + 2);
    let room = u16::try_from(room).unwrap_or(0);
    // The first that fits the room, else the shortest cut to it.
    let text = texts
        .iter()
        .find(|text| display::width(text) <= usize::from(room))
        .cloned()
        .unwrap_or_else(|| {
            let shortest = texts.last().map_or("", String::as_str);
            display::one_line(shortest, room, g.ellipsis)
        });
    f.render_widget(Paragraph::new(Span::styled(text, style)), rect);
    f.render_widget(Paragraph::new(right).right_aligned(), rect);
}

/// The ticker's words, longest first, and style at `now`: the send running
/// now, else the latest event while it is news (about a saved friend), else
/// how things stand.
fn ticker(app: &App, now: Instant) -> (Vec<String>, Style) {
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    if let Some(peer) = app.sending_to().filter(|peer| app.friend(peer).is_some()) {
        let name = app.shown_name(peer);
        return (vec![format!("Sending to {name}{}", g.ellipsis)], t.accent);
    }
    // A group's send running (groups, lab).
    if let Some(group) = app.group_sending_to() {
        let name = display::one_line(group, NAME_CELLS, g.ellipsis);
        return (vec![format!("Sending to {name}{}", g.ellipsis)], t.accent);
    }
    if let Some(event) = app
        .live()
        .news(now)
        .filter(|event| app.friend(event.peer()).is_some())
    {
        let style = match event {
            live::Event::Delivered { .. } => t.ok,
            live::Event::TriedAgain { .. } => t.warn,
            live::Event::Received { .. } => t.accent,
            live::Event::Sent { .. } => t.secondary,
        };
        let name = app.shown_name(event.peer());
        return (
            event.texts(&name, g.inline_separator, app.wall_ms(now)),
            style,
        );
    }
    let listening = matches!(app.chip(), Some(Chip::Listening { .. }));
    let mut waiting: Vec<(String, usize)> = app
        .contacts()
        .iter()
        .filter_map(|friend| {
            match presence::presence(friend, app.rows(&friend.pub_hex), app.now(), app.now_ms()) {
                Presence::Waiting(n) => Some((app.shown_name(&friend.pub_hex), n)),
                _ => None,
            }
        })
        .collect();
    // Your group messages not with every member yet: not 'all quiet'.
    waiting.extend(
        app.groups_waiting()
            .into_iter()
            .map(|(name, n)| (display::one_line(&name, NAME_CELLS, g.ellipsis), n)),
    );
    let texts = live::idle_texts(
        listening,
        app.contacts().len(),
        &waiting,
        g.inline_separator,
    );
    (texts, t.secondary)
}

/// The furthest the open conversation scrolls up to `wanted` rows in the
/// App's window: never past its oldest row.
pub(crate) fn clamp_scroll(app: &App, wanted: usize) -> usize {
    if app.open_group().is_some() {
        return groups::clamp_scroll(app, wanted);
    }
    let Some(friend) = open_friend(app) else {
        return 0;
    };
    if !app.history_ready() || app.history_error().is_some() {
        return 0;
    }
    let parts = chat_parts(app, chat_area(app));
    let height = usize::from(parts.messages.height);
    let total = conversation_tail(
        app,
        friend,
        parts.messages.width,
        wanted + height,
        app.now(),
    )
    .len();
    wanted.min(total.saturating_sub(height))
}

/// The scroll that shows the `chosen`-th message from the newest whole (its
/// top, when it is taller than the window), moving the window as little as
/// it takes.
pub(crate) fn scroll_to_message(app: &App, chosen: usize) -> usize {
    if app.open_group().is_some() {
        return groups::scroll_to_message(app, chosen);
    }
    let Some(friend) = open_friend(app) else {
        return 0;
    };
    if !app.history_ready() || app.history_error().is_some() {
        return 0;
    }
    let parts = chat_parts(app, chat_area(app));
    let (width, height) = (parts.messages.width, usize::from(parts.messages.height));
    let bubbles = app.bubbles(&friend.pub_hex);
    // A message's rows, with the day line over it when it starts a day.
    let rows = |from_newest: usize| {
        let index = bubbles.len() - 1 - from_newest;
        let marked = app.chosen() == Some(from_newest);
        let older = index.checked_sub(1).map(|i| bubbles[i]);
        let rule = day_rule(app, older, bubbles[index], width);
        let continued = rule.is_none() && continues(older, bubbles[index]);
        message_lines(
            app,
            friend,
            bubbles[index],
            continued,
            marked,
            width,
            app.now(),
        )
        .len()
            + usize::from(rule.is_some())
    };
    let below: usize = (0..chosen.min(bubbles.len())).map(rows).sum();
    if chosen >= bubbles.len() {
        return app.scroll();
    }
    let tall = rows(chosen);
    let mut scroll = app.scroll();
    if below + tall > scroll + height {
        scroll = (below + tall).saturating_sub(height);
    }
    if below < scroll && tall <= height {
        scroll = below;
    }
    clamp_scroll(app, scroll)
}

/// What turns on Home by itself (anim.rs wakes for each): in the open
/// conversation, a send's spinner, a Delivered typing itself and a failure's
/// blink. How long a waiting message has left changes with the minute,
/// which the app redraws for anyway. And the live feel (UXF.10): the clock
/// and the ages each second, the ticker's news going, the friends' blinks
/// and retry rings, and what travels the route line.
pub(crate) fn moving(app: &App) -> Vec<Moving> {
    let mut moving = Vec::new();
    if app.screen() != &Screen::Home || !app.ready() || app.too_small() {
        return moving;
    }
    // The clock, the heartbeat's age and pulse, the in-touch ages and the
    // breathing marks all change on the clock's whole seconds.
    moving.push(Moving::Clock {
        at: app.now(),
        at_ms: app.now_ms(),
    });
    moving.extend(app.live().news_until().map(Moving::Deadline));

    if list_visible(app) {
        for friend in app.contacts() {
            // In touch: the mark breathes (Calm), from when they came in
            // touch, while they are.
            let rows = app.rows(&friend.pub_hex);
            if let Presence::Recent { at_ms } =
                presence::presence(friend, rows, app.now(), app.now_ms())
            {
                let ago = Duration::from_millis(app.now_ms().saturating_sub(at_ms));
                moving.push(Moving::Steps {
                    since: app.now().checked_sub(ago).unwrap_or(app.now()),
                    every: BREATHE,
                });
            }
            if let Some(touch) = newest_touch(app.rows(&friend.pub_hex)) {
                moving.push(Moving::Transition {
                    start: touch,
                    frames: live::NEWS_FRAMES,
                    length: live::NEWS_TIME,
                });
            }
            if let Some(&start) = app.live().rings.get(&friend.pub_hex.to_ascii_lowercase()) {
                moving.push(Moving::Transition {
                    start,
                    frames: live::RING_FRAMES,
                    length: live::RING_TIME,
                });
            }
        }
    }
    let Some(friend) = open_friend(app).filter(|_| app.conversation_visible()) else {
        return moving;
    };
    moving.extend(route_moving(app, friend));
    for bubble in app.bubbles(&friend.pub_hex) {
        let Some(view) = app.tick_view(bubble) else {
            continue;
        };
        match (&view.tick, view.since) {
            (Tick::Sending | Tick::Connecting, _) => moving.push(Moving::Spinner {
                since: spinner_since(app, &view),
            }),
            (Tick::Delivered, Some(start)) => moving.push(Moving::Transition {
                start,
                frames: widgets::DELIVERED_FRAMES,
                length: widgets::DELIVERED_TYPING,
            }),
            (tick, Some(start)) if tick.failed() => moving.push(Moving::Transition {
                start,
                frames: BLINK_FRAMES,
                length: BLINK_TIME,
            }),
            _ => {}
        }
    }
    moving
}

/// Where a send's spinner turns from: when Enter sent it.
fn spinner_since(app: &App, view: &TickView) -> Instant {
    view.pending.map_or(app.now(), |send| send.sent_at)
}

/// The friend list is on screen: beside the conversation, or in one pane
/// in its place.
fn list_visible(app: &App) -> bool {
    let (cols, rows) = app.size();
    panes(app, body_area(Rect::new(0, 0, cols, rows)))
        .0
        .is_some()
}

/// When this app last saw news in `rows`: a message from the friend
/// arrived, or one of yours was delivered.
fn newest_touch(rows: &[Row]) -> Option<Instant> {
    rows.iter()
        .filter_map(|row| row.touched)
        .map(|t| t.at)
        .max()
}

/// How far PgUp and PgDn scroll: a window of messages, less one row.
pub(crate) fn page_rows(app: &App) -> usize {
    if app.open_group().is_some() {
        return groups::page_rows(app);
    }
    let parts = chat_parts(app, chat_area(app));
    usize::from(parts.messages.height).saturating_sub(1).max(1)
}

/// Home's key hints for `focus`, in priority order; W for the security
/// notices while one is `open` (P6.31).
fn hints(look: &Look, focus: Focus, open: bool) -> Vec<(&'static str, &'static str)> {
    let up_down = look.glyphs.up_down;
    let mut hints = match focus {
        Focus::Friends => vec![
            ("?", "Help"),
            ("Q", "Quit"),
            (up_down, "Choose"),
            ("Enter", "Open"),
            ("A", "Add"),
            ("V", "Verify"),
            ("E", "Friend page"),
            ("N", "Network"),
            ("S", "Settings"),
            ("G", "Meet"),
        ],
        Focus::Composer => vec![
            ("?", "Help"),
            ("Esc", "Friends"),
            ("Enter", "Send"),
            ("Ctrl+J", "New line"),
            ("Tab", "Messages"),
            ("PgUp/PgDn", "Scroll"),
        ],
        Focus::Messages => vec![
            ("?", "Help"),
            ("Esc", "Back"),
            (up_down, "Choose"),
            ("R", "Retry"),
            ("C", "Stop trying"),
            ("D", "Details"),
        ],
    };
    if open && focus != Focus::Composer {
        hints.insert(2, ("W", "Security"));
    }
    hints
}

/// The rows between the header and the footer: the hints, and from
/// [`STATUS_ROW_FROM`] rows the status row above them.
fn body_area(area: Rect) -> Rect {
    let footer = if area.height >= STATUS_ROW_FROM { 2 } else { 1 };
    Rect {
        y: area.y.saturating_add(1),
        height: area.height.saturating_sub(1 + footer),
        ..area
    }
}

/// The list and the conversation in `body`: side by side from
/// [`TWO_PANES_FROM`] columns, else the one that has the keys.
fn panes(app: &App, body: Rect) -> (Option<Rect>, Option<Rect>) {
    if body.width >= TWO_PANES_FROM {
        let list_width = if body.width >= WIDE_LIST_FROM {
            WIDE_LIST_WIDTH
        } else {
            LIST_WIDTH
        };
        let list = Rect {
            width: list_width,
            ..body
        };
        let chat = Rect {
            x: body.x + list_width,
            width: body.width - list_width,
            ..body
        };
        (Some(list), Some(chat))
    } else if (app.open_friend().is_some() || app.open_group().is_some())
        && app.focus() != Focus::Friends
    {
        (None, Some(body))
    } else {
        (Some(body), None)
    }
}

/// The conversation pane in the App's window, as it is or would be once
/// opened in one pane.
pub(super) fn chat_area(app: &App) -> Rect {
    let (cols, rows) = app.size();
    let body = body_area(Rect::new(0, 0, cols, rows));
    panes(app, body).1.unwrap_or(body)
}

/// The open friend, saved.
fn open_friend(app: &App) -> Option<&ContactView> {
    app.open_friend().and_then(|key| app.friend(key))
}

/// A pane's border: faint, dim with a bold title on the one with the keys.
fn pane_block(look: &Look, focused: bool) -> Block<'static> {
    widgets::pane(look, focused)
}

// ── The friend list ─────────────────────────────────────────────────────────

/// The list: one row per friend (the highlight's '>' marker, the mark, the
/// name and a badge), scrolled to keep the highlight in view, with 'A  Add a
/// friend' at the bottom. Drawn at `now`: the marks' and rows' live feel.
fn render_list(f: &mut Frame, rect: Rect, app: &App, now: Instant) {
    let look = app.look();
    let focused = app.focus() == Focus::Friends;
    // It holds the groups too while they are live: 'Chats'.
    let title = if app.groups_live() {
        CHATS_TITLE
    } else {
        LIST_TITLE
    };
    let block = pane_block(look, focused).title(widgets::pane_title(look, title, focused));
    let inner = block.inner(rect);
    f.render_widget(block, rect);
    if inner.is_empty() {
        return;
    }
    // While groups are live (lab), a second footer row: C, a new group.
    let mut footers = vec![LIST_FOOTER];
    if app.groups_live() {
        footers.push(groups::FOOTER);
    }
    let footer_rows = u16::try_from(footers.len()).unwrap_or(1).min(inner.height);
    let footer = Rect {
        y: inner.bottom() - footer_rows,
        height: footer_rows,
        ..inner
    };
    f.render_widget(
        Paragraph::new(
            footers
                .iter()
                .map(|(key, words)| {
                    Line::from(vec![
                        Span::raw(" "),
                        widgets::key(look, key),
                        widgets::key_words(look, words),
                    ])
                })
                .collect::<Vec<_>>(),
        ),
        footer,
    );
    let rows = Rect {
        height: inner.height - footer_rows,
        ..inner
    };
    // The list's own words start a cell in, under the marks.
    let words = |text: &str| -> Vec<String> {
        wrap(text, rows.width.saturating_sub(1), 0)
            .into_iter()
            .map(|row| format!(" {row}"))
            .collect()
    };
    let lines: Vec<Line<'static>> = if !app.contacts_ready() {
        match app.contacts_error() {
            Some(_) => words(LIST_UNREADABLE)
                .into_iter()
                .map(|row| Line::styled(row, look.theme.warn))
                .collect(),
            None => Vec::new(),
        }
    } else if app.contacts().is_empty() {
        LIST_EMPTY
            .iter()
            .flat_map(|text| words(text))
            .map(Line::raw)
            .collect()
    } else if app.groups_live() {
        app.contacts()
            .iter()
            .enumerate()
            .map(|(i, friend)| friend_row(app, i, friend, rows.width, focused, now))
            .collect()
    } else {
        let visible = usize::from(rows.height);
        let first = (app.highlight() + 1).saturating_sub(visible);
        app.contacts()
            .iter()
            .enumerate()
            .skip(first)
            .take(visible)
            .map(|(i, friend)| friend_row(app, i, friend, rows.width, focused, now))
            .collect()
    };
    if !app.groups_live() {
        f.render_widget(Paragraph::new(lines), rows);
        return;
    }
    // Groups (lab): the GROUPS section under the friends, the whole list
    // scrolled to keep the highlighted row in view.
    let section = groups::section(app, rows.width, focused);
    let marked = if app.highlighted_group_at().is_some() {
        section.highlighted.map(|row| lines.len() + row)
    } else {
        (!app.contacts().is_empty()).then_some(app.highlight())
    };
    let visible = usize::from(rows.height);
    let first = marked.map_or(0, |row| (row + 1).saturating_sub(visible));
    let mut all = lines;
    all.extend(section.lines);
    let shown: Vec<Line<'static>> = all.into_iter().skip(first).take(visible).collect();
    f.render_widget(Paragraph::new(shown), rows);
}

/// One friend's row in `width` cells: '>' when highlighted, the mark, the
/// name (at most 14 cells, less when the badge needs the room) and the badge
/// at the right: 'blocked', the alarm while a security alert or warning
/// about them is open (P6.31), the unread count, 'paused' while sending to
/// them is paused, or '!' while not verified.
///
/// At `now` (UXF.10): the in-touch mark breathes with the clock's seconds,
/// the waiting mark rings for a moment when Raven tried them again, and the
/// name blinks three frames when news came (a message from them arrived,
/// one of yours was delivered). Still under reduced motion.
fn friend_row(
    app: &App,
    index: usize,
    friend: &ContactView,
    width: u16,
    focused: bool,
    now: Instant,
) -> Line<'static> {
    let (g, t) = (&app.look().glyphs, &app.look().theme);
    let highlighted = index == app.highlight();
    let presence = presence::presence(friend, app.rows(&friend.pub_hex), app.now(), app.now_ms());
    let unread = app.unread(&friend.pub_hex);
    // The marker, the mark, and a space after each.
    let lead = 4;
    // In the wide list, words in place of a one-cell badge where they
    // leave the name whole.
    let wide = app.size().0 >= WIDE_LIST_FROM;
    let name_cells = display::width(&friend.label).min(usize::from(LIST_NAME_CELLS));
    let roomy = |words: &str| wide && lead + name_cells + 1 + cells(words) <= usize::from(width);
    let (badge, badge_style) = if friend.blocked {
        (BLOCKED.to_owned(), t.secondary)
    } else if app.notices_about(&friend.pub_hex).next().is_some() {
        (g.alarm_badge.to_owned(), t.warn)
    } else if unread > 0 && t.chips {
        (format!(" {} ", unread_count(unread)), t.unread)
    } else if unread > 0 {
        (unread_count(unread), t.unread)
    } else if app.paused(&friend.pub_hex) {
        (PAUSED.to_owned(), t.secondary)
    } else if !friend.pinned && roomy(NOT_VERIFIED) {
        (NOT_VERIFIED.to_owned(), t.warn)
    } else if !friend.pinned {
        (g.dot_alert.to_owned(), t.warn)
    } else if let Some(route) = last_route(app, friend).filter(|r| roomy(r.carrier_words())) {
        (
            route.carrier_words().to_owned(),
            t.path(widgets::path_kind(route)),
        )
    } else {
        (String::new(), Style::default())
    };
    let badge_room = if badge.is_empty() {
        0
    } else {
        cells(&badge) + 1
    };
    let name_room = usize::from(width)
        .saturating_sub(lead + badge_room)
        .min(usize::from(LIST_NAME_CELLS));
    let name = display::one_line(
        &friend.label,
        u16::try_from(name_room).unwrap_or(0),
        g.ellipsis,
    );
    let pad = usize::from(width).saturating_sub(lead + cells(&name) + cells(&badge));
    let marker = if highlighted {
        widgets::marker(app.look())
    } else {
        Span::raw(" ")
    };
    let motion = app.look().motion;
    let mut mark = widgets::dot(dot(presence), app.look());
    match presence {
        // In touch: the mark breathes (Calm: 1.5 s bright, 1.5 s quiet).
        Presence::Recent { at_ms } if motion == Motion::Full => {
            if !widgets::breath_bright(at_ms, app.wall_ms(now), motion) {
                mark.style = mark.style.patch(t.breath);
            }
        }
        Presence::Waiting(_) => {
            let ring = app
                .live()
                .rings
                .get(&friend.pub_hex.to_ascii_lowercase())
                .map(|&start| {
                    anim::transition_frame(start, now, live::RING_FRAMES, live::RING_TIME, motion)
                });
            if let Some(frame) = ring.and_then(|frame| usize::try_from(frame).ok()) {
                if let Some(ring) = g.ring.get(frame) {
                    mark = Span::styled(*ring, t.warn);
                }
            }
        }
        _ => {}
    }
    let news = newest_touch(app.rows(&friend.pub_hex)).map(|start| {
        anim::transition_frame(start, now, live::NEWS_FRAMES, live::NEWS_TIME, motion)
    });
    let open = app
        .open_friend()
        .is_some_and(|key| key.eq_ignore_ascii_case(&friend.pub_hex));
    // The open friend in the accent where there are colours (in mono the
    // accent is bold, which the news blink uses).
    let name_style = if open && t.decor { t.accent } else { t.text };
    let name = if news.is_some_and(|frame| frame < live::NEWS_FRAMES && frame % 2 == 0) {
        Span::styled(name, name_style.add_modifier(Modifier::BOLD))
    } else {
        Span::styled(name, name_style)
    };
    let line = Line::from(vec![
        marker,
        Span::raw(" "),
        mark,
        Span::raw(" "),
        name,
        Span::raw(" ".repeat(pad)),
        Span::styled(badge, badge_style),
    ]);
    if highlighted && focused {
        line.style(t.selected)
    } else {
        line
    }
}

/// A friend's mark in the list, for where they stand.
fn dot(presence: Presence) -> Dot {
    match presence {
        Presence::NoAddress => Dot::NoAddress,
        Presence::Waiting(_) => Dot::Waiting,
        Presence::Recent { .. } => Dot::Recent,
        Presence::Quiet { .. } => Dot::Quiet,
    }
}

/// An unread count as the badge shows it.
pub(super) fn unread_count(n: usize) -> String {
    if n > 99 {
        "99+".to_owned()
    } else {
        n.to_string()
    }
}

// ── The conversation ────────────────────────────────────────────────────────

/// Where the conversation pane's parts go, inside its border.
struct ChatParts {
    header: Rect,
    /// The route line and, when known, how the last delivery went (UXF.10);
    /// drawn at the frame's time ([`route_lines`]).
    route: Rect,
    horizon: (Rect, Vec<Line<'static>>),
    banners: (Rect, Vec<Line<'static>>),
    messages: Rect,
    separator: Rect,
    hint: (Rect, Vec<Line<'static>>),
    composer: (Rect, ComposerView),
}

/// The composer's rows as drawn, and where the cursor goes among them.
pub(super) struct ComposerView {
    pub(super) rows: Vec<Line<'static>>,
    /// (row, column) in the rows above; None without an open friend.
    pub(super) cursor: Option<(u16, u16)>,
}

/// The conversation pane's block: its border, and a cell of room each side.
pub(super) fn chat_block(look: &Look, focused: bool) -> Block<'static> {
    pane_block(look, focused).padding(Padding::horizontal(1))
}

/// The pane's parts, top to bottom: the friend's header, the route line,
/// how long a message to them could wait, the banners, the messages, a
/// separator, the composer's hint and the composer. The messages get what
/// the others leave.
fn chat_parts(app: &App, rect: Rect) -> ChatParts {
    let inner = chat_block(app.look(), false).inner(rect);
    let width = inner.width;
    let friend = open_friend(app);
    let horizon = friend
        .map(|friend| horizon_lines(app, friend, width))
        .unwrap_or_default();
    let banners = friend
        .map(|friend| banner_lines(app, friend, width))
        .unwrap_or_default();
    let composer = composer_view(app, friend, width);
    let hint = composer_hint(app, friend, width);
    let route_rows = friend.map_or(0, |friend| route_rows(app, friend));
    let mut left = inner.height;
    let mut take = |rows: usize| {
        let rows = u16::try_from(rows).unwrap_or(u16::MAX).min(left);
        left -= rows;
        rows
    };
    let header_h = take(1);
    let composer_h = take(composer.rows.len().max(1));
    let separator_h = take(1);
    let route_h = take(route_rows);
    let hint_h = take(hint.len());
    let horizon_h = take(horizon.len());
    let banners_h = take(banners.len());
    let messages_h = left;
    let at = |y: u16, height: u16| Rect { y, height, ..inner };
    let header = at(inner.y, header_h);
    let route = at(header.bottom(), route_h);
    let horizon_rect = at(route.bottom(), horizon_h);
    let banners_rect = at(horizon_rect.bottom(), banners_h);
    let messages = at(banners_rect.bottom(), messages_h);
    let separator = at(messages.bottom(), separator_h);
    let hint_rect = at(separator.bottom(), hint_h);
    let composer_rect = at(hint_rect.bottom(), composer_h);
    ChatParts {
        header,
        route,
        horizon: (horizon_rect, horizon),
        banners: (banners_rect, banners),
        messages,
        separator,
        hint: (hint_rect, hint),
        composer: (composer_rect, composer),
    }
}

/// The conversation pane: its border, the open friend's header and
/// banners, the messages, the separator and the composer. `alone`: in the
/// list's place (one pane).
fn render_chat(f: &mut Frame, rect: Rect, app: &App, alone: bool, now: Instant) {
    let look = app.look();
    let focused = matches!(app.focus(), Focus::Composer | Focus::Messages);
    f.render_widget(chat_block(look, focused), rect);
    let parts = chat_parts(app, rect);
    let friend = open_friend(app);
    if let Some(friend) = friend {
        render_chat_header(f, parts.header, app, friend, alone);
        let route = route_lines(app, friend, parts.route.width, now);
        f.render_widget(Paragraph::new(route), parts.route);
    }
    let (horizon_rect, horizon) = parts.horizon;
    f.render_widget(Paragraph::new(horizon), horizon_rect);
    let (banner_rect, banners) = parts.banners;
    f.render_widget(Paragraph::new(banners), banner_rect);
    render_messages(f, parts.messages, app, friend, now);
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

/// The open friend's header row: the name, Verified or Not verified, and
/// the mark in words. In one pane (`alone`), '<n> new from <friend>' at the
/// right when another friend has unread messages.
fn render_chat_header(f: &mut Frame, rect: Rect, app: &App, friend: &ContactView, alone: bool) {
    let (g, t) = (&app.look().glyphs, &app.look().theme);
    let presence = presence::presence(friend, app.rows(&friend.pub_hex), app.now(), app.now_ms());
    let (badge, badge_style) = if friend.pinned {
        (format!("{} Verified", g.tick_sent), t.ok)
    } else {
        (format!("{} Not verified", g.dot_alert), t.warn)
    };
    let left = Line::from(vec![
        Span::styled(
            display::one_line(&friend.label, NAME_CELLS, g.ellipsis),
            t.title,
        ),
        Span::raw("  "),
        Span::styled(badge, badge_style),
        Span::styled(g.inline_separator, t.secondary),
        Span::styled(presence.meaning(app.now_ms()), t.secondary),
    ]);
    let used = left.width();
    f.render_widget(Paragraph::new(left), rect);
    if !alone {
        return;
    }
    if let Some((n, other)) = app.unread_elsewhere() {
        let name = display::one_line(&other.label, LIST_NAME_CELLS, g.ellipsis);
        let right = format!("{n} new from {name}");
        if used + 2 + cells(&right) <= usize::from(rect.width) {
            f.render_widget(
                Paragraph::new(Span::styled(right, t.accent)).right_aligned(),
                rect,
            );
        }
    }
}

/// The route line's rows for `friend` (UXF.10): none for a blocked friend
/// (nothing goes to them) or one Raven has no address for (nothing can
/// travel), else the line, and how the last delivery went when this app
/// knows it.
fn route_rows(app: &App, friend: &ContactView) -> usize {
    if !route_shown(friend) {
        0
    } else if last_route(app, friend).is_some() {
        2
    } else {
        1
    }
}

/// Whether the route line to `friend` shows: not for a blocked friend, nor
/// one Raven has no address for.
fn route_shown(friend: &ContactView) -> bool {
    !friend.blocked && presence::has_address(friend)
}

/// How the last delivery to `friend` went, as this app saw it.
fn last_route<'a>(app: &'a App, friend: &ContactView) -> Option<&'a live::Route> {
    app.live().routes.get(&friend.pub_hex.to_ascii_lowercase())
}

/// What travels the route line at `now`, if anything: which way, and the
/// step of its trip (of [`live::ROUTE_STEPS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Travel {
    /// Your message, out, while its send runs (around again until it ends).
    Out(u32),
    /// The signed receipt, back, once it came.
    Receipt(u32),
    /// A friend's message, in, before it shows.
    In(u32),
}

/// The newest of `friend`'s messages that arrived less than a trip ago: it
/// travels in, and shows once it is here. None under reduced motion, and
/// where the route line doesn't show.
fn arriving(app: &App, friend: &ContactView, now: Instant) -> Option<Instant> {
    if app.look().motion != Motion::Full || !route_shown(friend) {
        return None;
    }
    app.rows(&friend.pub_hex)
        .iter()
        .filter(|row| !row.view.outgoing)
        .filter_map(|row| row.touched)
        .map(|touch| touch.at)
        .filter(|at| now.saturating_duration_since(*at) < live::ROUTE_TIME)
        .max()
}

/// Whether `bubble` is a message from `friend` still travelling the route
/// line in at `now`: not drawn yet.
fn still_arriving(app: &App, friend: &ContactView, bubble: Bubble, now: Instant) -> bool {
    let Bubble::Row(row) = bubble else {
        return false;
    };
    app.look().motion == Motion::Full
        && route_shown(friend)
        && !row.view.outgoing
        && row
            .touched
            .is_some_and(|touch| now.saturating_duration_since(touch.at) < live::ROUTE_TIME)
}

/// The newest of your messages to `friend` whose receipt came less than a
/// trip ago, and the newest whose send runs (since Enter).
fn receipt_and_send(
    app: &App,
    friend: &ContactView,
    now: Instant,
) -> (Option<Instant>, Option<Instant>) {
    let (mut receipt, mut send) = (None, None);
    for bubble in app.bubbles(&friend.pub_hex) {
        let Some(view) = app.tick_view(bubble) else {
            continue;
        };
        match (&view.tick, view.since) {
            (Tick::Delivered, Some(at)) if now.saturating_duration_since(at) < live::ROUTE_TIME => {
                receipt = receipt.max(Some(at));
            }
            (Tick::Sending | Tick::Connecting, _) => {
                send = send.max(Some(spinner_since(app, &view)));
            }
            _ => {}
        }
    }
    (receipt, send)
}

/// What travels the route line to `friend` at `now`: a message coming in
/// first, then a receipt coming back, then a send going out. Nothing under
/// reduced motion, and nothing once a trip is over.
fn travel(app: &App, friend: &ContactView, now: Instant) -> Option<Travel> {
    let motion = app.look().motion;
    if motion != Motion::Full {
        return None;
    }
    let step = |start| {
        let frame = anim::transition_frame(start, now, live::ROUTE_STEPS, live::ROUTE_TIME, motion);
        (frame < live::ROUTE_STEPS).then_some(frame)
    };
    if let Some(frame) = arriving(app, friend, now).and_then(step) {
        return Some(Travel::In(frame));
    }
    let (receipt, send) = receipt_and_send(app, friend, now);
    if let Some(frame) = receipt.and_then(step) {
        return Some(Travel::Receipt(frame));
    }
    send.map(|since| {
        let every = live::ROUTE_TIME / live::ROUTE_STEPS;
        let frame = anim::spinner_frame(since, now, every) % u64::from(live::ROUTE_STEPS);
        Travel::Out(u32::try_from(frame).unwrap_or(0))
    })
}

/// What on the route line to `friend` moves by itself (anim.rs): a message
/// coming in, a receipt coming back, a send going out. Nothing where the
/// line doesn't show.
fn route_moving(app: &App, friend: &ContactView) -> Vec<Moving> {
    let now = app.now();
    let mut moving = Vec::new();
    if !route_shown(friend) {
        return moving;
    }
    let trip = |start| Moving::Transition {
        start,
        frames: live::ROUTE_STEPS,
        length: live::ROUTE_TIME,
    };
    moving.extend(arriving(app, friend, now).map(trip));
    let (receipt, send) = receipt_and_send(app, friend, now);
    moving.extend(receipt.map(trip));
    moving.extend(send.map(|since| Moving::Steps {
        since,
        every: live::ROUTE_TIME / live::ROUTE_STEPS,
    }));
    moving
}

/// The route line to `friend` in `width` cells at `now` (UXF.10, Calm):
/// 'You ◉──────◉ <name>', solid while in touch and dashed otherwise, with
/// what travels it, then, in the path's colour, how the last delivery went
/// ('LAN direct · 192.168.1.30:7420', 'p2p · relayed') when this app knows
/// it. None of it where [`route_rows`] says none.
fn route_lines(app: &App, friend: &ContactView, width: u16, now: Instant) -> Vec<Line<'static>> {
    if route_rows(app, friend) == 0 {
        return Vec::new();
    }
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    let name = display::one_line(&friend.label, LIST_NAME_CELLS, g.ellipsis);
    let fixed = cells("You ") + 2 * cells(g.route_end) + 1 + cells(&name);
    let steps = usize::from(width).saturating_sub(fixed).min(ROUTE_CELLS);
    // Solid while you are in touch; dashed otherwise (Calm), the friend's
    // end in the colour of the path the last delivery took.
    let rows = app.rows(&friend.pub_hex);
    let in_touch = matches!(
        presence::presence(friend, rows, app.now(), app.now_ms()),
        Presence::Recent { .. }
    );
    let rule = if in_touch { g.route } else { g.route_dash };
    let end =
        last_route(app, friend).map_or(t.secondary, |route| t.path(widgets::path_kind(route)));
    let mut line: Vec<Span<'static>> = vec![
        Span::styled("You ", t.secondary),
        Span::styled(g.route_end, t.accent),
    ];
    let at = |frame: u32| {
        usize::try_from(frame).unwrap_or(0) * steps
            / usize::try_from(live::ROUTE_STEPS).unwrap_or(1)
    };
    let (cell, mark, style) = match travel(app, friend, now) {
        Some(Travel::Out(frame)) => (Some(at(frame)), g.route_out, t.accent),
        Some(Travel::Receipt(frame)) => {
            (Some(steps.saturating_sub(1 + at(frame))), g.tick_sent, t.ok)
        }
        Some(Travel::In(frame)) => (
            Some(steps.saturating_sub(1 + at(frame))),
            g.route_in,
            t.accent,
        ),
        None => (None, "", Style::default()),
    };
    match cell.filter(|cell| *cell < steps) {
        Some(cell) => {
            line.push(Span::styled(rule.repeat(cell), t.faint));
            line.push(Span::styled(mark, style.add_modifier(Modifier::BOLD)));
            line.push(Span::styled(rule.repeat(steps - cell - 1), t.faint));
        }
        None => line.push(Span::styled(rule.repeat(steps), t.faint)),
    }
    line.push(Span::styled(g.route_end, end));
    line.push(Span::styled(format!(" {name}"), t.title));
    let mut lines = vec![Line::from(line)];
    if let Some(route) = last_route(app, friend) {
        let label = display::one_line(&route.label(g.inline_separator), width, g.ellipsis);
        lines.push(Line::styled(label, t.path(widgets::path_kind(route))));
    }
    lines
}

/// What a message written to a friend now could do ([`horizon`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Horizon {
    /// Wait until then.
    Until(bridge::DeadlineText),
    /// Not wait at all: the last secure connection ended, so meet first.
    MeetFirst,
    /// Not wait at all: Raven hasn't connected with them yet, so a first
    /// message goes only while you are both online (E1).
    FirstMessage,
}

/// What a message written to `friend` now could do, as the store worker
/// last read it. None, so no line, when it is not known, when the time read
/// has passed (the next read tells), and for a blocked friend (nothing is
/// sent to them).
fn horizon(app: &App, friend: &ContactView) -> Option<Horizon> {
    if friend.blocked {
        return None;
    }
    match app.horizon(&friend.pub_hex)? {
        bridge::QueueReach::CanWait { until_ms } if until_ms > app.now_ms() => Some(
            Horizon::Until(bridge::deadline_text(until_ms, app.now_ms())),
        ),
        bridge::QueueReach::CanWait { .. } => None,
        bridge::QueueReach::Ended { .. } => Some(Horizon::MeetFirst),
        bridge::QueueReach::NeverPaired => Some(Horizon::FirstMessage),
    }
}

/// The dim line under the friend's name: how long a message to them could
/// wait, that they have to meet first, or the rule a first message goes by
/// (the CLI's words); nothing when that is not known. It names the friend
/// and a time only, never a key or an address.
fn horizon_lines(app: &App, friend: &ContactView, width: u16) -> Vec<Line<'static>> {
    let look = app.look();
    let name = display::one_line(&friend.label, NAME_CELLS, look.glyphs.ellipsis);
    let text = match horizon(app, friend) {
        None => return Vec::new(),
        Some(Horizon::Until(until)) => format!(
            "If {name} is away, Raven keeps trying until {}.",
            until.short
        ),
        Some(Horizon::MeetFirst) => {
            format!("To write to {name}, meet first: Raven can't hold new messages for them now.")
        }
        Some(Horizon::FirstMessage) => errors::first_message_rule(&name),
    };
    wrap(&text, width, 0)
        .into_iter()
        .map(|row| Line::styled(row, look.theme.secondary))
        .collect()
}

/// The rows between the separator and the composer: what the composer
/// refuses, else, when the friend has to be met first, when Raven can send
/// (Enter still sends, and the outcome says what happened).
fn composer_hint(app: &App, friend: Option<&ContactView>, width: u16) -> Vec<Line<'static>> {
    let look = app.look();
    let (text, style) = if let Some(problem) = app.composer().and_then(Composer::problem) {
        (problem.to_owned(), look.theme.warn)
    } else if let Some(friend) = friend.filter(|friend| app.paused(&friend.pub_hex)) {
        let name = display::one_line(&friend.label, NAME_CELLS, look.glyphs.ellipsis);
        (
            format!(
                "You paused sending to {name}: Enter sends nothing. To send again, press Esc, \
                 then P."
            ),
            look.theme.warn,
        )
    } else if let Some((friend, unmet)) = friend.and_then(|friend| {
        horizon(app, friend)
            .filter(|h| !matches!(h, Horizon::Until(_)))
            .map(|h| (friend, h))
    }) {
        let name = display::one_line(&friend.label, NAME_CELLS, look.glyphs.ellipsis);
        let text = if unmet == Horizon::FirstMessage {
            format!("Raven can send this only while you and {name} are both online.")
        } else {
            format!("Raven can send this only when you're on the same network as {name}.")
        };
        (text, look.theme.secondary)
    } else {
        return Vec::new();
    };
    wrap(&text, width, 0)
        .into_iter()
        .map(|row| Line::styled(row, style))
        .collect()
}

/// The banners under the header: a security alert or warning about the
/// friend, or that sending to them is paused (P6.31), with its keys; not
/// verified yet; and no address to reach the friend.
fn banner_lines(app: &App, friend: &ContactView, width: u16) -> Vec<Line<'static>> {
    let look = app.look();
    let name = display::one_line(&friend.label, NAME_CELLS, look.glyphs.ellipsis);
    let mut lines = security_banner(app, friend, &name, width);
    let mut texts = Vec::new();
    if !friend.pinned {
        texts.push(format!(
            "You haven't checked this is really {name}. Compare security words with {name}: \
             press V."
        ));
    }
    let rows = app.rows(&friend.pub_hex);
    if presence::presence(friend, rows, app.now(), app.now_ms()) == Presence::NoAddress {
        texts.push(format!(
            "Raven doesn't know where to reach {name} yet. Ask them for their invite again, or \
             press E to enter their address."
        ));
    }
    lines.extend(
        texts
            .iter()
            .flat_map(|text| wrap(text, width, 0))
            .map(|row| Line::styled(row, look.theme.warn)),
    );
    lines
}

/// The security banner for `friend` (`name`, shaped): the most severe open
/// notice about them, what happened and when (with how many more), or that
/// sending to them is paused; then its keys. Nothing while neither is so.
pub(crate) fn security_banner(
    app: &App,
    friend: &ContactView,
    name: &str,
    width: u16,
) -> Vec<Line<'static>> {
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    let paused = app.paused(&friend.pub_hex);
    let mut notices = app.notices_about(&friend.pub_hex);
    let first = notices.next();
    let more = notices.count();
    let mut texts: Vec<String> = Vec::new();
    if let Some(notice) = first {
        let also = if more > 0 {
            format!(" (and {more} more: W)")
        } else {
            String::new()
        };
        texts.push(format!(
            "{} {} ({}).{also}",
            g.alarm, notice.text.headline, notice.when
        ));
    }
    if paused {
        texts.push(format!("Sending to {name} is paused until you resume it."));
    }
    if texts.is_empty() {
        return Vec::new();
    }
    let keys = match (first.is_some(), paused) {
        (true, false) => SECURITY_KEYS,
        (true, true) => PAUSED_KEYS,
        (false, _) => RESUME_KEYS,
    };
    let mut lines: Vec<Line<'static>> = texts
        .iter()
        .flat_map(|text| wrap(&display::one_line(text, u16::MAX, ""), width, 0))
        .map(|row| Line::styled(row, t.warn))
        .collect();
    // The keys keep their gaps while they fit on one row.
    let key_rows = if cells(keys) <= usize::from(width) {
        vec![keys.to_owned()]
    } else {
        wrap(keys, width, 0)
    };
    lines.extend(key_rows.into_iter().map(|row| Line::styled(row, t.accent)));
    lines
}

/// The messages with the open friend, newest at the bottom, scrolled up by
/// the App's scroll; or why there are none to show.
fn render_messages(
    f: &mut Frame,
    rect: Rect,
    app: &App,
    friend: Option<&ContactView>,
    now: Instant,
) {
    let Some(friend) = friend else {
        return;
    };
    let look = app.look();
    let note = |rows: Vec<String>| -> Vec<Line<'static>> {
        rows.into_iter()
            .map(|row| Line::styled(row, look.theme.secondary))
            .collect()
    };
    let lines = if let Some(why) = app.history_error() {
        history_error_lines(app, why, rect.width)
    } else if !app.history_ready() {
        note(vec![format!("{LOADING}{}", look.glyphs.ellipsis)])
    } else if app.bubbles(&friend.pub_hex).is_empty() {
        let name = display::one_line(&friend.label, NAME_CELLS, look.glyphs.ellipsis);
        note(wrap(
            &format!("No messages with {name} yet. Say hello!"),
            rect.width,
            0,
        ))
    } else {
        let height = usize::from(rect.height);
        let lines = conversation_tail(app, friend, rect.width, app.scroll() + height, now);
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

/// The history can't be read: in plain words, and its technical text under D.
fn history_error_lines(app: &App, why: &str, width: u16) -> Vec<Line<'static>> {
    let look = app.look();
    let plain = errors::explain_history(why);
    let mut lines: Vec<Line<'static>> = wrap(&plain.headline, width, 0)
        .into_iter()
        .map(|row| Line::styled(row, look.theme.warn))
        .collect();
    if !plain.next.is_empty() {
        lines.extend(wrap(&plain.next, width, 0).into_iter().map(Line::raw));
    }
    if app.history_details() {
        lines.push(Line::default());
        for line in display::body_lines(&plain.technical, false).lines {
            lines.extend(
                wrap_text(&line, usize::from(width))
                    .into_iter()
                    .map(|row| Line::styled(row, look.theme.secondary)),
            );
        }
    }
    lines
}

/// The last rows of the conversation with `friend` at `width` cells, drawn
/// at `now`: whole messages, from the newest back until there are at least
/// `needed` rows (or none is left). A message of theirs still travelling
/// the route line in is not here yet.
fn conversation_tail(
    app: &App,
    friend: &ContactView,
    width: u16,
    needed: usize,
    now: Instant,
) -> Vec<Line<'static>> {
    let chosen = app.chosen();
    let mut messages = Vec::new();
    let mut count = 0;
    let bubbles = app.bubbles(&friend.pub_hex);
    let shown: Vec<Bubble> = bubbles
        .into_iter()
        .filter(|bubble| !still_arriving(app, friend, *bubble, now))
        .collect();
    for (from_newest, index) in (0..shown.len()).rev().enumerate() {
        if count >= needed {
            break;
        }
        let marked = chosen == Some(from_newest);
        let older = index.checked_sub(1).map(|i| shown[i]);
        let rule = day_rule(app, older, shown[index], width);
        let continued = rule.is_none() && continues(older, shown[index]);
        let mut lines = message_lines(app, friend, shown[index], continued, marked, width, now);
        if let Some(rule) = rule {
            lines.insert(0, rule);
        }
        count += lines.len();
        messages.push(lines);
    }
    messages.into_iter().rev().flatten().collect()
}

/// Whether `bubble` goes on from the `older` one before it: the same
/// sender, less than [`RUN_GAP_MS`] after it. Its sender and age aren't said
/// again (a chat app's run of messages).
fn continues(older: Option<Bubble>, bubble: Bubble) -> bool {
    older.is_some_and(|older| {
        older.outgoing() == bubble.outgoing()
            && bubble.created_at_ms().abs_diff(older.created_at_ms()) < RUN_GAP_MS
    })
}

/// The day line over `bubble` (Calm), when it starts a day on this
/// computer's calendar: the first message, or one on another day than the
/// `older` one before it. None when the calendar can't be read.
fn day_rule(app: &App, older: Option<Bubble>, bubble: Bubble, width: u16) -> Option<Line<'static>> {
    day_rule_at(
        app,
        older.map(|older| older.created_at_ms()),
        bubble.created_at_ms(),
        width,
    )
}

/// [`day_rule`] by the messages' times (`older_ms`, `at_ms`): a group's
/// chat draws them too.
pub(super) fn day_rule_at(
    app: &App,
    older_ms: Option<u64>,
    at_ms: u64,
    width: u16,
) -> Option<Line<'static>> {
    let now_ms = app.now_ms();
    let day = bridge::day_text(at_ms, now_ms)?;
    let same = older_ms
        .is_some_and(|older| bridge::day_text(older, now_ms).as_deref() == Some(day.as_str()));
    (!same).then(|| widgets::day_line(app.look(), &day, width))
}

/// One message: its header row ('<name> · 5 min ago', or 'You · just now'
/// with the delivery mark and label; the '>' marker first when `marked`),
/// then its body, indented and wrapped. A body clipped at the terminal limit
/// ends in the marker and the hint, unless Enter showed it whole. When it
/// `continued` the sender's run, the sender and age aren't said again: a
/// friend's message is its body alone, one of yours keeps its delivery
/// mark and label (unless it is the chosen one: then all of its header).
fn message_lines(
    app: &App,
    friend: &ContactView,
    bubble: Bubble,
    continued: bool,
    marked: bool,
    width: u16,
    now: Instant,
) -> Vec<Line<'static>> {
    let continued = continued && !marked;
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    let name = display::one_line(&friend.label, NAME_CELLS, g.ellipsis);
    let who = if bubble.outgoing() {
        "You".to_owned()
    } else {
        name.clone()
    };
    let mut head = Vec::new();
    if marked {
        head.push(Span::styled(format!("{} ", g.selected), t.accent));
    }
    let who_style = if bubble.outgoing() {
        t.accent.add_modifier(Modifier::BOLD)
    } else {
        t.title
    };
    if !continued {
        head.push(Span::styled(who, who_style));
        let age = bridge::short_age(app.now_ms(), bubble.created_at_ms());
        if !age.is_empty() {
            head.push(Span::styled(g.inline_separator, t.secondary));
            head.push(Span::styled(age, t.secondary));
        }
    }
    let mut lines = Vec::new();
    let mut label_rows = Vec::new();
    let mut waiting = false;
    if let Some(view) = app.tick_view(bubble) {
        let (mark, label, shown) = tick_parts(app, &view, &name, now);
        let style = widgets::tick_label_style(tick_mark(app, &view), look);
        waiting = matches!(tick_mark(app, &view), TickMark::Waiting);
        // After the label: the path it went by, or what the outbox says of
        // a waiting one (Calm); shown once Delivered has typed itself.
        let after = tick_after(look, &view);
        let after_cells = after
            .as_ref()
            .map_or(0, |span| cells(g.inline_separator) + span.width());
        let after = after.filter(|_| shown == label);
        head.push(Span::raw("  "));
        head.push(mark);
        let head_width = Line::from(head.clone()).width();
        if head_width + 1 + cells(&label) + after_cells <= usize::from(width) {
            head.push(Span::raw(" "));
            head.push(Span::styled(shown, style));
            if let Some(after) = after {
                head.push(Span::styled(g.inline_separator, t.secondary));
                head.push(after);
            }
        } else {
            // Too long for the row: under it.
            label_rows = wrap(&label, width.saturating_sub(BODY_INDENT), 0)
                .into_iter()
                .map(|row| Line::styled(row, style))
                .collect();
            label_rows.extend(after.map(Line::from));
        }
    }
    let head = Line::from(head);
    if !head.spans.is_empty() {
        lines.push(if marked { head.style(t.selected) } else { head });
    }
    let indent = " ".repeat(usize::from(BODY_INDENT));
    lines.extend(label_rows.into_iter().map(|label| {
        let mut row = vec![Span::raw(indent.clone())];
        row.extend(label.spans);
        Line::from(row)
    }));
    // Your own lines behind the bar where the theme draws it (Calm).
    let lead = bubble
        .outgoing()
        .then(|| widgets::own_bar(look, waiting))
        .flatten()
        .unwrap_or_else(|| Span::raw(indent.clone()));
    let body = display::body_lines(bubble.body(), app.expanded(&bubble.key()));
    let last = body.lines.len().saturating_sub(1);
    for (i, mut text) in body.lines.into_iter().enumerate() {
        if i == last && body.more_chars > 0 {
            text.push_str(CLIPPED_HINT);
        }
        let room = usize::from(width.saturating_sub(BODY_INDENT));
        lines.extend(
            wrap_text(&text, room)
                .into_iter()
                .map(|piece| Line::from(vec![lead.clone(), Span::styled(piece, t.text)])),
        );
    }
    if bubble.id_conflict() {
        let room = usize::from(width.saturating_sub(BODY_INDENT));
        lines.extend(
            wrap_text(bridge::ID_CONFLICT_NOTE, room)
                .into_iter()
                .map(|piece| Line::from(vec![lead.clone(), Span::styled(piece, t.secondary)])),
        );
    }
    lines
}

/// The mark of one of your messages' ticks.
fn tick_mark(app: &App, view: &TickView) -> TickMark {
    match &view.tick {
        Tick::Sending | Tick::Connecting => TickMark::Spinner {
            since: spinner_since(app, view),
        },
        Tick::WaitingToSend | Tick::Waiting(_) | Tick::OnHold { .. } => TickMark::Waiting,
        Tick::Sent => TickMark::Sent,
        Tick::Delivered => TickMark::Delivered,
        Tick::Ended { .. } | Tick::NotSent => TickMark::Failed,
    }
}

/// What follows a tick's label (Calm): for Delivered the path it went by
/// when this app knows it (its own send's, or raven-node's outbox's), in
/// its path's colour; for a message raven-node keeps trying, that friends
/// hold a sealed copy, or that the last try found nobody. Nothing else is
/// guessed: a delivery from before this session says no path.
fn tick_after(look: &Look, view: &TickView) -> Option<Span<'static>> {
    match &view.tick {
        Tick::Delivered => {
            let route = view
                .pending
                .and_then(|send| send.route.clone())
                .or_else(|| view.outbox.and_then(live::Route::of_outbox))?;
            Some(widgets::path_tag(look, &route))
        }
        Tick::Waiting(_) => {
            let item = view.outbox?;
            widgets::waiting_note(
                look,
                item.in_custody,
                item.last_error_code == "NOT_REACHABLE",
            )
        }
        _ => None,
    }
}

/// The tick of one of your messages as drawn at `now`: its mark, its whole
/// label (which decides the layout), and the part of the label showing.
///
/// - Sending and connecting: the spinner, turning since Enter.
/// - Delivered, when this app saw it come: it types itself, a character
///   every 45 ms, the sent mark for the first two (widgets.rs).
/// - A failure this app saw happen: the mark blinks twice.
///
/// Under reduced motion none of it moves: anim.rs draws the end at once.
fn tick_parts(
    app: &App,
    view: &TickView,
    name: &str,
    now: Instant,
) -> (Span<'static>, String, String) {
    let look = app.look();
    let mut label = delivery::label(
        &view.tick,
        view.evidence,
        view.outcome(),
        name,
        &look.glyphs,
        app.now_ms(),
    );
    // A late delivery says when it came (E1).
    if let (Tick::Delivered, Some((written, Some(at)))) = (&view.tick, view.delivered) {
        if let Some(when) = bridge::delivered_text(at, written, app.now_ms()) {
            label = format!("{label} {when}");
        }
    }
    let mark = tick_mark(app, view);
    let mut span = widgets::tick(mark, look, now);
    let mut shown = label.clone();
    match (&view.tick, view.since) {
        (Tick::Delivered, since @ Some(_)) => {
            (span, shown) = widgets::delivered_typing(look, &label, since, now);
        }
        (tick, Some(start)) if tick.failed() => {
            let frame = anim::transition_frame(start, now, BLINK_FRAMES, BLINK_TIME, look.motion);
            if frame % 2 == 1 {
                span = Span::raw(" ".repeat(cells(&span.content)));
            }
        }
        _ => {}
    }
    (span, label, shown)
}

/// Shaped text in rows of at most `width` cells: broken after a space where
/// one is, else between graphemes.
pub(super) fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut rows = Vec::new();
    let (mut row, mut used) = (String::new(), 0);
    // Where `row` can break: just after its last space, and the cells to it.
    let mut space: Option<(usize, usize)> = None;
    let span = Span::raw(text);
    for grapheme in span.styled_graphemes(Style::default()) {
        let cells = usize::from(grapheme.symbol.cell_width());
        if used > 0 && used + cells > width {
            if grapheme.symbol == " " {
                // The break itself: the spaces there go.
                rows.push(std::mem::take(&mut row).trim_end_matches(' ').to_owned());
                (used, space) = (0, None);
                continue;
            }
            match space.take() {
                Some((at, before)) => {
                    let rest = row.split_off(at);
                    rows.push(row.trim_end_matches(' ').to_owned());
                    (row, used) = (rest, used - before);
                }
                None => {
                    rows.push(std::mem::take(&mut row));
                    used = 0;
                }
            }
            if used > 0 && used + cells > width {
                rows.push(std::mem::take(&mut row));
                used = 0;
            }
        }
        row.push_str(grapheme.symbol);
        used += cells;
        if grapheme.symbol == " " {
            space = Some((row.len(), used));
        }
    }
    rows.push(row);
    rows
}

/// The line between the messages and the composer; above 40 KiB it says how
/// much of the 48 KiB a message may have is used.
fn separator_line(app: &App, width: u16) -> Line<'static> {
    let look = app.look();
    let rule = look.glyphs.border.horizontal_top;
    let width = usize::from(width);
    let used = app.composer().map_or(0, |c| c.text().len());
    if used > COUNTER_FROM {
        let counter = format!(
            " {} KB of {} KB ",
            used / 1024,
            bridge::MAX_LAN_ENDPOINT_TEXT / 1024
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

/// The composer in `width` cells: 'To <name>: ' and what is typed (or the
/// placeholder), wrapped, at most [`COMPOSER_ROWS`] rows around the cursor,
/// the first always with the name; without an open friend, how to start.
fn composer_view(app: &App, friend: Option<&ContactView>, width: u16) -> ComposerView {
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    let (Some(friend), Some(composer)) = (friend, app.composer()) else {
        return ComposerView {
            rows: wrap(COMPOSER_OFF, width, 0)
                .into_iter()
                .map(|row| Line::styled(row, t.secondary))
                .collect(),
            cursor: None,
        };
    };
    let name = display::one_line(&friend.label, NAME_CELLS, g.ellipsis);
    composer_for(app, &name, composer, width)
}

/// The composer for `composer`, written to `name` (shaped): 'To <name>: '
/// and what is typed (or the placeholder), wrapped, at most
/// [`COMPOSER_ROWS`] rows around the cursor, the first always with the name.
pub(super) fn composer_for(app: &App, name: &str, composer: &Composer, width: u16) -> ComposerView {
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    let prefix = format!("To {name}: ");
    let prefix_cells = cells(&prefix);
    let prefix_style = if app.focus() == Focus::Composer {
        t.accent.add_modifier(Modifier::BOLD)
    } else {
        t.secondary
    };
    let lead = |first: bool| {
        if first {
            Span::styled(prefix.clone(), prefix_style)
        } else {
            Span::raw(" ".repeat(prefix_cells))
        }
    };
    let cursor_column = |column: usize| u16::try_from(prefix_cells + column).unwrap_or(u16::MAX);
    if composer.is_empty() {
        let placeholder = format!("write here  (Enter sends{}Ctrl+J new line)", g.separator);
        return ComposerView {
            rows: vec![Line::from(vec![
                lead(true),
                Span::styled(placeholder, t.faint),
            ])],
            cursor: Some((0, cursor_column(0))),
        };
    }
    // One cell stays free for the cursor after the last character.
    let room = usize::from(width).saturating_sub(prefix_cells + 1).max(1);
    let (rows, (cursor_row, column)) = composer_rows(composer, room);
    let end = (cursor_row + 1).max(COMPOSER_ROWS).min(rows.len());
    let start = end.saturating_sub(COMPOSER_ROWS);
    let lines = rows[start..end]
        .iter()
        .enumerate()
        .map(|(i, text)| Line::from(vec![lead(i == 0), Span::styled(text.clone(), t.text)]))
        .collect();
    ComposerView {
        rows: lines,
        cursor: Some((
            u16::try_from(cursor_row - start).unwrap_or(u16::MAX),
            cursor_column(column),
        )),
    }
}

/// What is typed, shaped and broken into rows of `room` cells, each line
/// break starting a row; and the cursor's (row, column) among them.
fn composer_rows(composer: &Composer, room: usize) -> (Vec<String>, (usize, usize)) {
    let text = composer.text();
    let cursor = composer.cursor();
    let mut rows = Vec::new();
    let mut cursor_at = (0, 0);
    let mut start = 0;
    for line in text.split('\n') {
        let end = start + line.len();
        let shaped = display::one_line(line, u16::MAX, "");
        let first = rows.len();
        rows.extend(hard_wrap(&shaped, room));
        if (start..=end).contains(&cursor) {
            // Cells before the cursor, then down the rows they fill.
            let mut column = display::width(&text[start..cursor]);
            let mut row = first;
            while row + 1 < rows.len() && column >= cells(&rows[row]) {
                column -= cells(&rows[row]);
                row += 1;
            }
            cursor_at = (row, column.min(cells(&rows[row])));
        }
        start = end + 1;
    }
    (rows, cursor_at)
}

/// Shaped text in rows of at most `room` cells, broken between graphemes.
fn hard_wrap(text: &str, room: usize) -> Vec<String> {
    let mut rows = vec![String::new()];
    let mut used = 0;
    let span = Span::raw(text);
    for grapheme in span.styled_graphemes(Style::default()) {
        let cells = usize::from(grapheme.symbol.cell_width());
        if used > 0 && used + cells > room {
            rows.push(String::new());
            used = 0;
        }
        if let Some(row) = rows.last_mut() {
            row.push_str(grapheme.symbol);
        }
        used += cells;
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyCode;
    use ratatui::backend::TestBackend;
    use ratatui::style::Modifier;
    use ratatui::Terminal;

    use theme::{Glyphs, Motion};

    /// Bob (verified, with an address), Alice (not verified, with an
    /// address) and Carol (not verified, no address).
    fn three() -> Vec<ContactView> {
        vec![
            ContactView {
                label: "Bob".into(),
                pinned: true,
                ..testkit::reachable(1)
            },
            ContactView {
                label: "Alice".into(),
                ..testkit::reachable(2)
            },
            ContactView {
                label: "Carol".into(),
                ..testkit::friend(3)
            },
        ]
    }

    /// Two conversations: three messages with Bob (the newest 5 minutes
    /// ago), one from Alice three days ago.
    fn chats() -> Vec<(u8, RowView)> {
        vec![
            (
                1,
                testkit::row(1, false, "", 90, "Hi! Are you coming tonight?"),
            ),
            (1, testkit::row(2, true, "delivered", 85, "Yes, at eight.")),
            (
                1,
                testkit::row(3, false, "", 5, "Great, see you there.\nBring the map."),
            ),
            (
                2,
                testkit::row(4, false, "", 3 * 24 * 60, "hello from Alice"),
            ),
        ]
    }

    /// No conversation at all.
    const NO_ROWS: &[(u8, RowView)] = &[];

    /// Home in a window of `size`, receiving off, with `friends` and `rows`.
    fn home(size: (u16, u16), friends: Vec<ContactView>, rows: &[(u8, RowView)]) -> App {
        testkit::home_app(size, Receive::Off, friends, testkit::conversations(rows))
    }

    /// `app` with `keys` pressed in turn.
    fn pressed(mut app: App, keys: &[KeyCode]) -> App {
        for &key in keys {
            testkit::press(&mut app, key);
        }
        app
    }

    /// Where the terminal's cursor is after a draw of `app`, if it shows.
    fn cursor(app: &App) -> Option<(u16, u16)> {
        let (cols, rows) = app.size();
        let mut terminal = Terminal::new(TestBackend::new(cols, rows)).expect("a test terminal");
        terminal
            .draw(|f| render_frame(f, app, app.now()))
            .expect("draw");
        let backend = terminal.backend();
        backend.cursor_visible().then(|| {
            let at = backend.cursor_position();
            (at.x, at.y)
        })
    }

    #[test]
    fn home_with_no_friends_at_100_by_30() {
        let app = home((100, 30), Vec::new(), NO_ROWS);
        testkit::assert_rows(&testkit::render(&app, 100, 30), &[
            "R A V E N                                                                         o Receiving is off",
            "┌ Friends ───────────┐┌────────────────────────────────────────────────────────────────────────────┐",
            "│ No friends yet.    ││                                                                            │",
            "│ Press A to add one.││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││ ────────────────────────────────────────────────────────────────────────── │",
            "│ A  Add a friend    ││ Pick a friend on the left and press Enter to start writing.                │",
            "└────────────────────┘└────────────────────────────────────────────────────────────────────────────┘",
            "No friends yet - all quiet                                         activity ........................",
            "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page  N Network  S Settings   ",
        ]);
        assert_eq!(cursor(&app), None, "nothing to type in");
    }

    #[test]
    fn home_with_no_friends_at_80_by_24_and_70_by_20() {
        let app = home((80, 24), Vec::new(), NO_ROWS);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                     o Receiving is off",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│ No friends yet.    ││                                                        │",
                "│ Press A to add one.││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│                    ││ Pick a friend on the left and press Enter to start     │",
                "│ A  Add a friend    ││ writing.                                               │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "No friends yet - all quiet                     activity ........................",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
            ],
        );
        let app = home((70, 20), Vec::new(), NO_ROWS);
        testkit::assert_rows(
            &testkit::render(&app, 70, 20),
            &[
                "R A V E N                                           o Receiving is off",
                "┌ Friends ───────────────────────────────────────────────────────────┐",
                "│ No friends yet.                                                    │",
                "│ Press A to add one.                                                │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│ A  Add a friend                                                    │",
                "└────────────────────────────────────────────────────────────────────┘",
                "No friends yet - all quiet           activity ........................",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify           ",
            ],
        );
    }

    #[test]
    fn home_with_friends_before_one_is_open() {
        let app = home((80, 24), three(), &chats());
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                     o Receiving is off",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> o Bob            2││                                                        │",
                "│  o Alice          1││                                                        │",
                "│  x Carol          !││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│                    ││ Pick a friend on the left and press Enter to start     │",
                "│ A  Add a friend    ││ writing.                                               │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                          activity .....................:..",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
            ],
        );
    }

    #[test]
    fn home_with_a_conversation_at_100_by_30() {
        let app = pressed(home((100, 30), three(), &chats()), &[KeyCode::Enter]);
        testkit::assert_rows(&testkit::render(&app, 100, 30), &[
            "R A V E N                                                                         o Receiving is off",
            "┌ Friends ───────────┐┌────────────────────────────────────────────────────────────────────────────┐",
            "│> o Bob             ││ Bob  v Verified - Last message 5 min ago                                   │",
            "│  o Alice          1││ You *--------------------------* Bob                                       │",
            "│  x Carol          !││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││                                                                            │",
            "│                    ││ Bob - 1 h ago                                                              │",
            "│                    ││   Hi! Are you coming tonight?                                              │",
            "│                    ││ You - 1 h ago  vv Delivered                                                │",
            "│                    ││   Yes, at eight.                                                           │",
            "│                    ││ Bob - 5 min ago                                                            │",
            "│                    ││   Great, see you there.                                                    │",
            "│                    ││   Bring the map.                                                           │",
            "│                    ││ ────────────────────────────────────────────────────────────────────────── │",
            "│ A  Add a friend    ││ To Bob: write here  (Enter sends  Ctrl+J new line)                         │",
            "└────────────────────┘└────────────────────────────────────────────────────────────────────────────┘",
            "3 friends - all quiet                                              activity .....................:..",
            "? Help  Esc Friends  Enter Send  Ctrl+J New line  Tab Messages  PgUp/PgDn Scroll                    ",
        ]);
        // After 'To Bob: ' in the composer's row.
        assert_eq!(cursor(&app), Some((32, 26)));
    }

    #[test]
    fn home_with_a_conversation_at_80_by_24() {
        let app = pressed(home((80, 24), three(), &chats()), &[KeyCode::Enter]);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                     o Receiving is off",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> o Bob             ││ Bob  v Verified - Last message 5 min ago               │",
                "│  o Alice          1││ You *--------------------------* Bob                   │",
                "│  x Carol          !││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││ Bob - 1 h ago                                          │",
                "│                    ││   Hi! Are you coming tonight?                          │",
                "│                    ││ You - 1 h ago  vv Delivered                            │",
                "│                    ││   Yes, at eight.                                       │",
                "│                    ││ Bob - 5 min ago                                        │",
                "│                    ││   Great, see you there.                                │",
                "│                    ││   Bring the map.                                       │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│ A  Add a friend    ││ To Bob: write here  (Enter sends  Ctrl+J new line)     │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                          activity .....................:..",
                "? Help  Esc Friends  Enter Send  Ctrl+J New line  Tab Messages  PgUp/PgDn Scroll",
            ],
        );
    }

    #[test]
    fn home_in_one_pane_at_70_by_20() {
        let app = home((70, 20), three(), &chats());
        testkit::assert_rows(
            &testkit::render(&app, 70, 20),
            &[
                "R A V E N                                           o Receiving is off",
                "┌ Friends ───────────────────────────────────────────────────────────┐",
                "│> o Bob                                                            2│",
                "│  o Alice                                                          1│",
                "│  x Carol                                                          !│",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│ A  Add a friend                                                    │",
                "└────────────────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                activity .....................:..",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify           ",
            ],
        );
        // Enter opens the conversation in the list's place.
        let mut app = pressed(app, &[KeyCode::Enter]);
        testkit::assert_rows(
            &testkit::render(&app, 70, 20),
            &[
                "R A V E N                                           o Receiving is off",
                "┌────────────────────────────────────────────────────────────────────┐",
                "│ Bob  v Verified - Last message 5 min ago          1 new from Alice │",
                "│ You *--------------------------* Bob                               │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│ Bob - 1 h ago                                                      │",
                "│   Hi! Are you coming tonight?                                      │",
                "│ You - 1 h ago  vv Delivered                                        │",
                "│   Yes, at eight.                                                   │",
                "│ Bob - 5 min ago                                                    │",
                "│   Great, see you there.                                            │",
                "│   Bring the map.                                                   │",
                "│ ────────────────────────────────────────────────────────────────── │",
                "│ To Bob: write here  (Enter sends  Ctrl+J new line)                 │",
                "└────────────────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                activity .....................:..",
                "? Help  Esc Friends  Enter Send  Ctrl+J New line  Tab Messages        ",
            ],
        );
        // Esc goes back to the list.
        testkit::press(&mut app, KeyCode::Esc);
        assert!(testkit::render(&app, 70, 20)[1].contains(LIST_TITLE));
    }

    #[test]
    fn one_pane_says_when_another_friend_wrote() {
        // Bob open; Alice's message is still unread.
        let app = pressed(home((70, 20), three(), &chats()), &[KeyCode::Enter]);
        assert_eq!(app.unread(&testkit::friend(2).pub_hex), 1);
        let rows = testkit::render(&app, 70, 20);
        assert!(rows[2].ends_with("1 new from Alice │"), "{:?}", rows[2]);
        // Beside the list there is no need.
        let app = pressed(home((80, 24), three(), &chats()), &[KeyCode::Enter]);
        assert!(!testkit::render(&app, 80, 24)[2].contains("new from"));
    }

    #[test]
    fn an_unverified_friend_has_a_banner() {
        let app = pressed(
            home((80, 24), three(), &chats()),
            &[KeyCode::Down, KeyCode::Enter],
        );
        assert_eq!(app.open_friend(), Some(testkit::friend(2).pub_hex.as_str()));
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                     o Receiving is off",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│  o Bob            2││ Alice  ! Not verified - Last message 3 d ago           │",
                "│> o Alice          !││ You *--------------------------* Alice                 │",
                "│  x Carol          !││ You haven't checked this is really Alice. Compare      │",
                "│                    ││ security words with Alice: press V.                    │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││ Alice - 3 d ago                                        │",
                "│                    ││   hello from Alice                                     │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│ A  Add a friend    ││ To Alice: write here  (Enter sends  Ctrl+J new line)   │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                          activity .....................:..",
                "? Help  Esc Friends  Enter Send  Ctrl+J New line  Tab Messages  PgUp/PgDn Scroll",
            ],
        );
    }

    #[test]
    fn a_friend_without_an_address_has_a_banner() {
        let app = pressed(
            home((80, 24), three(), &chats()),
            &[KeyCode::Down, KeyCode::Down, KeyCode::Enter],
        );
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                     o Receiving is off",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│  o Bob            2││ Carol  ! Not verified - No address to reach them       │",
                "│  o Alice          1││ You haven't checked this is really Carol. Compare      │",
                "│> x Carol          !││ security words with Carol: press V.                    │",
                "│                    ││ Raven doesn't know where to reach Carol yet. Ask them  │",
                "│                    ││ for their invite again, or press E to enter their      │",
                "│                    ││ address.                                               │",
                "│                    ││ No messages with Carol yet. Say hello!                 │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│ A  Add a friend    ││ To Carol: write here  (Enter sends  Ctrl+J new line)   │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                          activity .....................:..",
                "? Help  Esc Friends  Enter Send  Ctrl+J New line  Tab Messages  PgUp/PgDn Scroll",
            ],
        );
    }

    #[test]
    fn a_long_body_is_clipped_and_says_how_to_see_all() {
        let long = "word ".repeat(420);
        let rows = [(1, testkit::row(9, false, "", 2, long.trim_end()))];
        let app = pressed(home((80, 24), three(), &rows), &[KeyCode::Enter]);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                     o Receiving is off",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> o Bob             ││ Bob  v Verified - Last message 2 min ago               │",
                "│  o Alice          !││ You *--------------------------* Bob                   │",
                "│  x Carol          !││   word word word word word word word word word word    │",
                "│                    ││   word word word word word word word word word word    │",
                "│                    ││   word word word word word word word word word word    │",
                "│                    ││   word word word word word word word word word word    │",
                "│                    ││   word word word word word word word word word word    │",
                "│                    ││   word word word word word word word word word word    │",
                "│                    ││   word word word word word word word word word word    │",
                "│                    ││   word word word word word word word word word word    │",
                "│                    ││   word word word word word word word word word word    │",
                "│                    ││   word word word word word word word word word word    │",
                "│                    ││   word word word word word word word word word word    │",
                "│                    ││   word word word word word word word word word word    │",
                "│                    ││   word word word word word word word word word word …  │",
                "│                    ││   (+99 more characters). Press Enter on this message   │",
                "│                    ││   to show all.                                         │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│ A  Add a friend    ││ To Bob: write here  (Enter sends  Ctrl+J new line)     │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                          activity ......................:.",
                "? Help  Esc Friends  Enter Send  Ctrl+J New line  Tab Messages  PgUp/PgDn Scroll",
            ],
        );
    }

    #[test]
    fn the_highlight_is_not_the_open_friend() {
        // Bob open, then back to the list and down to Carol.
        let app = pressed(
            home((80, 24), three(), &chats()),
            &[KeyCode::Enter, KeyCode::Esc, KeyCode::Down, KeyCode::Down],
        );
        assert_eq!(app.highlight(), 2);
        assert_eq!(app.open_friend(), Some(testkit::friend(1).pub_hex.as_str()));
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                     o Receiving is off",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│  o Bob             ││ Bob  v Verified - Last message 5 min ago               │",
                "│  o Alice          1││ You *--------------------------* Bob                   │",
                "│> x Carol          !││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││ Bob - 1 h ago                                          │",
                "│                    ││   Hi! Are you coming tonight?                          │",
                "│                    ││ You - 1 h ago  vv Delivered                            │",
                "│                    ││   Yes, at eight.                                       │",
                "│                    ││ Bob - 5 min ago                                        │",
                "│                    ││   Great, see you there.                                │",
                "│                    ││   Bring the map.                                       │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│ A  Add a friend    ││ To Bob: write here  (Enter sends  Ctrl+J new line)     │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                          activity .....................:..",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
            ],
        );
        assert_eq!(cursor(&app), None, "the list has the keys");
    }

    #[test]
    fn untrusted_names_and_bodies_show_as_text_only() {
        let evil = vec![ContactView {
            label: "Bob\u{1b}]0;pwned\u{7}".into(),
            ..testkit::reachable(1)
        }];
        let rows = [(
            1,
            testkit::row(1, false, "", 1, "\u{202e}evil\u{1b}[2J text\u{7}\u{200b}!"),
        )];
        let app = pressed(home((80, 24), evil, &rows), &[KeyCode::Enter]);
        let got = testkit::render(&app, 80, 24);
        for row in &got {
            for bad in [
                "\u{1b}", "pwned", "]0;", "[2J", "\u{202e}", "\u{7}", "\u{200b}",
            ] {
                assert!(!row.contains(bad), "{bad:?} in {row:?}");
            }
        }
        testkit::assert_rows(
            &got,
            &[
                "R A V E N                                                     o Receiving is off",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> o Bob            !││ Bob  ! Not verified - Last message 1 min ago           │",
                "│                    ││ You *--------------------------* Bob                   │",
                "│                    ││ You haven't checked this is really Bob. Compare        │",
                "│                    ││ security words with Bob: press V.                      │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││ Bob - 1 min ago                                        │",
                "│                    ││   evil text!                                           │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│ A  Add a friend    ││ To Bob: write here  (Enter sends  Ctrl+J new line)     │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "1 friend - all quiet                           activity .......................:",
                "? Help  Esc Friends  Enter Send  Ctrl+J New line  Tab Messages  PgUp/PgDn Scroll",
            ],
        );
    }

    #[test]
    fn a_line_of_zwj_emoji_leaves_the_list_alone() {
        let family = "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}\u{200d}\u{1f466}";
        let with = [(1, testkit::row(1, false, "", 1, &family.repeat(40)))];
        let without = [(1, testkit::row(1, false, "", 1, "short"))];
        for look in testkit::every_look() {
            let draw = |rows: &[(u8, RowView)]| {
                let mut app = App::new(look, (80, 24), Instant::now(), 0);
                app.start(testkit::session(Receive::Off));
                for result in [
                    JobResult::Contacts {
                        contacts: Ok(three()),
                        stamp: Default::default(),
                    },
                    JobResult::History {
                        history: Ok(testkit::conversations(rows)),
                        stamp: Default::default(),
                    },
                ] {
                    testkit::send(&mut app, Msg::Job(result));
                }
                testkit::press(&mut app, KeyCode::Enter);
                testkit::render(&app, 80, 24)
            };
            let list = |rows: Vec<String>| -> Vec<String> {
                rows.iter()
                    .map(|row| row.chars().take(usize::from(LIST_WIDTH)).collect())
                    .collect()
            };
            let (wide, plain) = (draw(&with), draw(&without));
            assert_eq!(list(wide.clone()), list(plain), "{wide:#?}");
            // The emoji come apart, each one two cells, wrapped in the pane.
            assert!(wide.iter().any(|row| row.contains("\u{1f468}")));
            assert!(!wide.iter().any(|row| row.contains('\u{200d}')));
        }
    }

    #[test]
    fn a_resize_switches_between_two_panes_and_one() {
        let mut app = pressed(home((100, 30), three(), &chats()), &[KeyCode::Enter]);
        let wide = testkit::render(&app, 100, 30);
        assert!(wide[1].starts_with("┌ Friends ──"), "{:?}", wide[1]);
        testkit::resize(&mut app, 70, 20);
        let narrow = testkit::render(&app, 70, 20);
        assert!(
            !narrow[1].contains(LIST_TITLE),
            "one pane: the conversation, which has the keys"
        );
        assert!(narrow.iter().any(|row| row.contains("To Bob: ")));
        testkit::assert_rows(
            &narrow,
            &[
                "R A V E N                                           o Receiving is off",
                "┌────────────────────────────────────────────────────────────────────┐",
                "│ Bob  v Verified - Last message 5 min ago          1 new from Alice │",
                "│ You *--------------------------* Bob                               │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│ Bob - 1 h ago                                                      │",
                "│   Hi! Are you coming tonight?                                      │",
                "│ You - 1 h ago  vv Delivered                                        │",
                "│   Yes, at eight.                                                   │",
                "│ Bob - 5 min ago                                                    │",
                "│   Great, see you there.                                            │",
                "│   Bring the map.                                                   │",
                "│ ────────────────────────────────────────────────────────────────── │",
                "│ To Bob: write here  (Enter sends  Ctrl+J new line)                 │",
                "└────────────────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                activity .....................:..",
                "? Help  Esc Friends  Enter Send  Ctrl+J New line  Tab Messages        ",
            ],
        );
        testkit::resize(&mut app, 100, 30);
        assert_eq!(testkit::render(&app, 100, 30), wide);
    }

    #[test]
    fn the_composer_shows_what_is_typed_and_where() {
        let mut app = pressed(home((80, 24), three(), &chats()), &[KeyCode::Enter]);
        for c in "Hello".chars() {
            testkit::press(&mut app, KeyCode::Char(c));
        }
        let got = testkit::render(&app, 80, 24);
        testkit::assert_rows(
            &got[19..23],
            &[
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│ A  Add a friend    ││ To Bob: Hello                                          │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                          activity .....................:..",
            ],
        );
        // After 'To Bob: Hello', inside the pane's border and its space.
        assert_eq!(cursor(&app), Some((24 + 8 + 5, 20)));
        // Left twice: the cursor between the l's.
        testkit::press(&mut app, KeyCode::Left);
        testkit::press(&mut app, KeyCode::Left);
        assert_eq!(cursor(&app), Some((24 + 8 + 3, 20)));
        // A line break: the next row, under the text.
        testkit::press(&mut app, KeyCode::End);
        testkit::ctrl(&mut app, 'j');
        for c in "there".chars() {
            testkit::press(&mut app, KeyCode::Char(c));
        }
        let got = testkit::render(&app, 80, 24);
        testkit::assert_rows(
            &got[18..23],
            &[
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│                    ││ To Bob: Hello                                          │",
                "│ A  Add a friend    ││         there                                          │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                          activity .....................:..",
            ],
        );
        assert_eq!(cursor(&app), Some((24 + 8 + 5, 20)));
        // Under an overlay the cursor hides.
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(cursor(&app), None);
    }

    #[test]
    fn the_composer_keeps_the_name_on_its_first_row_and_wraps() {
        let mut app = pressed(home((80, 24), three(), &chats()), &[KeyCode::Enter]);
        testkit::paste(&mut app, &"abcdefghij".repeat(15), PasteVia::Bracketed);
        let got = testkit::render(&app, 80, 24);
        testkit::assert_rows(
            &got[17..23],
            &[
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│                    ││ To Bob: fghijabcdefghijabcdefghijabcdefghijabcdefghij  │",
                "│                    ││         abcdefghijabcdefghijabcdefghijabcdefghijabcde  │",
                "│ A  Add a friend    ││         fghijabcdefghij                                │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                          activity .....................:..",
            ],
        );
        // The cursor after the last character, on the last row: 45 cells a
        // row, so 15 on the fourth.
        assert_eq!(cursor(&app), Some((24 + 8 + 15, 20)));
    }

    #[test]
    fn the_composer_counts_bytes_near_the_limit_and_says_what_it_refuses() {
        let mut app = pressed(home((80, 24), three(), &chats()), &[KeyCode::Enter]);
        testkit::paste(&mut app, &"x".repeat(40 * 1024), PasteVia::Bracketed);
        // Over the composer's three rows.
        let separator = |app: &App| testkit::render(app, 80, 24)[17].clone();
        assert!(!separator(&app).contains("KB of"), "{:?}", separator(&app));
        testkit::paste(&mut app, &"x".repeat(6 * 1024 + 10), PasteVia::Bracketed);
        assert_eq!(
            separator(&app),
            format!("│{}││ {} 46 KB of 48 KB  │", " ".repeat(20), "─".repeat(38))
        );
        // At the limit it stops.
        testkit::paste(&mut app, &"x".repeat(4096), PasteVia::Bracketed);
        assert!(separator(&app).contains(" 48 KB of 48 KB "));
        // The reserved prefix: said over the composer, and no send.
        let mut app = pressed(home((80, 24), three(), &chats()), &[KeyCode::Enter]);
        testkit::paste(&mut app, "RVNAPP/1 hello", PasteVia::Bracketed);
        let got = testkit::render(&app, 80, 24);
        testkit::assert_rows(
            &got[17..22],
            &[
                "│                    ││   Bring the map.                                       │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│                    ││ Messages can't start with RVNAPP/ or RVNGRP/.          │",
                "│ A  Add a friend    ││ To Bob: RVNAPP/1 hello                                 │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
            ],
        );
    }

    #[test]
    fn hints_follow_the_focus() {
        let mut app = home((100, 30), three(), &chats());
        let last = |app: &App| testkit::render(app, 100, 30)[29].trim_end().to_owned();
        assert_eq!(
            last(&app),
            "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page  \
             N Network  S Settings"
        );
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(
            last(&app),
            "? Help  Esc Friends  Enter Send  Ctrl+J New line  Tab Messages  PgUp/PgDn Scroll"
        );
        testkit::press(&mut app, KeyCode::Tab);
        assert_eq!(
            last(&app),
            "? Help  Esc Back  Up/Down Choose  R Retry  C Stop trying  D Details"
        );
    }

    #[test]
    fn the_header_carries_the_users_own_name() {
        let mut app = App::new(testkit::simple_mono(), (80, 24), Instant::now(), 0);
        app.start(Session {
            settings: state(Receive::Off, "Sam"),
            ..testkit::session(Receive::Off)
        });
        assert!(testkit::render(&app, 80, 24)[0].starts_with("R A V E N - Sam "));
        let fancy = App::new(
            Look {
                glyphs: Glyphs::fancy(),
                ..testkit::simple_mono()
            },
            (60, 16),
            Instant::now(),
            0,
        );
        let mut fancy = fancy;
        fancy.start(Session {
            settings: state(Receive::Off, &"Samantha".repeat(9)),
            ..testkit::session(Receive::Off)
        });
        let header = &testkit::render(&fancy, 60, 16)[0];
        assert!(
            header.starts_with("R A V E N · SamanthaSamantha"),
            "{header:?}"
        );
        // Cut to the room the right side leaves (nothing there yet).
        assert!(header.trim_end().ends_with('…'), "{header:?}");
    }

    /// Settings receiving `receive`, with the user's own `name`.
    fn state(receive: Receive, name: &str) -> TuiState {
        TuiState {
            receive,
            display_name: name.into(),
            ..TuiState::default()
        }
    }

    #[test]
    fn history_that_cannot_be_read_says_so() {
        let mut app = pressed(home((80, 24), three(), &chats()), &[KeyCode::Enter]);
        testkit::send(
            &mut app,
            Msg::Job(JobResult::History {
                history: Err(
                    "chat history authentication failed (wrong key or tampered file)".into(),
                ),
                stamp: Default::default(),
            }),
        );
        testkit::press(&mut app, KeyCode::Tab);
        testkit::press(&mut app, KeyCode::Char('d'));
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                     o Receiving is off",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> o Bob             ││ Bob  v Verified - Last message 5 min ago               │",
                "│  o Alice          1││ You *--------------------------* Bob                   │",
                "│  x Carol          !││ Your message history can't be read.                    │",
                "│                    ││ Press D for details.                                   │",
                "│                    ││                                                        │",
                "│                    ││ chat history authentication failed (wrong key or       │",
                "│                    ││ tampered file)                                         │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│ A  Add a friend    ││ To Bob: write here  (Enter sends  Ctrl+J new line)     │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                          activity .....................:..",
                "? Help  Esc Back  Up/Down Choose  R Retry  C Stop trying  D Details             ",
            ],
        );
    }

    #[test]
    fn fancy_and_ascii_homes() {
        let fancy: &[&str] = &[
            "R A V E N                                                                       ",
            "╭ Friends ───────────╮╭────────────────────────────────────────────────────────╮",
            "│> ○ Bob             ││ Bob  ✓ Verified · Last message 5 min ago               │",
            "│  ○ Alice          1││ You ◉┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄◉ Bob                   │",
            "│  ✕ Carol          !││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││ Bob · 1 h ago                                          │",
            "│                    ││   Hi! Are you coming tonight?                          │",
            "│                    ││ You · 1 h ago  ✓✓ Delivered                            │",
            "│                    ││   Yes, at eight.                                       │",
            "│                    ││ Bob · 5 min ago                                        │",
            "│                    ││   Great, see you there.                                │",
            "│                    ││   Bring the map.                                       │",
            "│                    ││ ────────────────────────────────────────────────────── │",
            "│ A  Add a friend    ││ To Bob: write here  (Enter sends · Ctrl+J new line)    │",
            "╰────────────────────╯╰────────────────────────────────────────────────────────╯",
            "3 friends · all quiet                          activity ⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣠⣀⣀",
            "? Help · Esc Friends · Enter Send · Ctrl+J New line · Tab Messages              ",
        ];
        let ascii: &[&str] = &[
            "R A V E N                                                                       ",
            "+ Friends -----------++--------------------------------------------------------+",
            "|> o Bob             || Bob  v Verified - Last message 5 min ago               |",
            "|  o Alice          1|| You *--------------------------* Bob                   |",
            "|  x Carol          !||                                                        |",
            "|                    ||                                                        |",
            "|                    ||                                                        |",
            "|                    ||                                                        |",
            "|                    ||                                                        |",
            "|                    ||                                                        |",
            "|                    ||                                                        |",
            "|                    ||                                                        |",
            "|                    || Bob - 1 h ago                                          |",
            "|                    ||   Hi! Are you coming tonight?                          |",
            "|                    || You - 1 h ago  vv Delivered                            |",
            "|                    ||   Yes, at eight.                                       |",
            "|                    || Bob - 5 min ago                                        |",
            "|                    ||   Great, see you there.                                |",
            "|                    ||   Bring the map.                                       |",
            "|                    || ------------------------------------------------------ |",
            "| A  Add a friend    || To Bob: write here  (Enter sends  Ctrl+J new line)     |",
            "+--------------------++--------------------------------------------------------+",
            "3 friends - all quiet                          activity .....................:..",
            "? Help  Esc Friends  Enter Send  Ctrl+J New line  Tab Messages  PgUp/PgDn Scroll",
        ];
        // Groups (on in release builds since 2026-10) have their own homes
        // in ui/groups: off on this thread here.
        raven_core::group::set_lab_groups_for_this_thread(Some(false));
        for (glyphs, expected) in [(Glyphs::fancy(), fancy), (Glyphs::ascii(), ascii)] {
            let mut app = App::new(
                Look {
                    glyphs,
                    ..testkit::simple_mono()
                },
                (80, 24),
                Instant::now(),
                1_760_000_000_000,
            );
            app.start(testkit::session(Receive::Off));
            for result in [
                JobResult::Contacts {
                    contacts: Ok(three()),
                    stamp: Default::default(),
                },
                JobResult::History {
                    history: Ok(testkit::conversations(&chats())),
                    stamp: Default::default(),
                },
            ] {
                testkit::send(&mut app, Msg::Job(result));
            }
            testkit::press(&mut app, KeyCode::Enter);
            testkit::assert_rows(&testkit::render(&app, 80, 24), expected);
        }
    }

    // ── how long a message can wait ─────────────────────────────────────────

    const HOUR_MS: u64 = 3_600_000;

    /// The poller's word, then the store worker's answer: friend `n`'s
    /// horizon is `horizon` (when a message would run out, or why none can
    /// wait), and nobody else's is known.
    fn horizon_read(app: &mut App, n: u8, horizon: bridge::QueueReach) {
        testkit::send(app, Msg::Poll(PollUpdate::HorizonsDue));
        let known = Horizons::from([(testkit::friend(n).pub_hex, horizon)]);
        testkit::send(app, Msg::Job(JobResult::Horizons(known)));
    }

    /// A message to the friend could wait until `until_ms`.
    fn can_wait_until(until_ms: u64) -> bridge::QueueReach {
        bridge::QueueReach::CanWait { until_ms }
    }

    /// Home in `look` at `size` with `friends` and Bob (friend 1) open, as
    /// the store worker last read how long a message to him could wait:
    /// `state` is "can wait" (a day), "meet first" (the secure connection
    /// ended), "first message" (none yet) or "not known".
    fn horizon_home_with(
        look: Look,
        size: (u16, u16),
        friends: Vec<ContactView>,
        state: &str,
    ) -> App {
        let history = testkit::conversations(&chats());
        let mut app = testkit::home_app_in(look, size, Receive::Off, friends, history);
        testkit::press(&mut app, KeyCode::Enter);
        let until = app.now_ms() + 24 * HOUR_MS;
        match state {
            "can wait" => horizon_read(&mut app, 1, can_wait_until(until)),
            "meet first" => horizon_read(&mut app, 1, bridge::QueueReach::Ended { at_ms: 0 }),
            "first message" => horizon_read(&mut app, 1, bridge::QueueReach::NeverPaired),
            // Alice's is known, Bob's is not.
            "not known" => horizon_read(&mut app, 2, can_wait_until(until)),
            other => panic!("not a state: {other}"),
        }
        app
    }

    /// [`horizon_home_with`] Bob, Alice and Carol as the friends.
    fn horizon_home(look: Look, size: (u16, u16), state: &str) -> App {
        horizon_home_with(look, size, three(), state)
    }

    #[test]
    fn the_wait_line_in_its_three_states_at_80_by_24() {
        let draw = |state: &str| {
            let app = horizon_home(testkit::simple_mono(), (80, 24), state);
            testkit::render(&app, 80, 24)
        };
        testkit::assert_rows(
            &draw("can wait"),
            &[
                "R A V E N                                                     o Receiving is off",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> o Bob             ││ Bob  v Verified - Last message 5 min ago               │",
                "│  o Alice          1││ You *--------------------------* Bob                   │",
                "│  x Carol          !││ If Bob is away, Raven keeps trying until about 24 h    │",
                "│                    ││ from now.                                              │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││ Bob - 1 h ago                                          │",
                "│                    ││   Hi! Are you coming tonight?                          │",
                "│                    ││ You - 1 h ago  vv Delivered                            │",
                "│                    ││   Yes, at eight.                                       │",
                "│                    ││ Bob - 5 min ago                                        │",
                "│                    ││   Great, see you there.                                │",
                "│                    ││   Bring the map.                                       │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│ A  Add a friend    ││ To Bob: write here  (Enter sends  Ctrl+J new line)     │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                          activity .....................:..",
                "? Help  Esc Friends  Enter Send  Ctrl+J New line  Tab Messages  PgUp/PgDn Scroll",
            ],
        );
        // Meet first: the line, and the composer's hint says when Raven can
        // send.
        testkit::assert_rows(
            &draw("meet first"),
            &[
                "R A V E N                                                     o Receiving is off",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> o Bob             ││ Bob  v Verified - Last message 5 min ago               │",
                "│  o Alice          1││ You *--------------------------* Bob                   │",
                "│  x Carol          !││ To write to Bob, meet first: Raven can't hold new      │",
                "│                    ││ messages for them now.                                 │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││ Bob - 1 h ago                                          │",
                "│                    ││   Hi! Are you coming tonight?                          │",
                "│                    ││ You - 1 h ago  vv Delivered                            │",
                "│                    ││   Yes, at eight.                                       │",
                "│                    ││ Bob - 5 min ago                                        │",
                "│                    ││   Great, see you there.                                │",
                "│                    ││   Bring the map.                                       │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│                    ││ Raven can send this only when you're on the same       │",
                "│                    ││ network as Bob.                                        │",
                "│ A  Add a friend    ││ To Bob: write here  (Enter sends  Ctrl+J new line)     │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                          activity .....................:..",
                "? Help  Esc Friends  Enter Send  Ctrl+J New line  Tab Messages  PgUp/PgDn Scroll",
            ],
        );
        // Not known: no line, Home as before.
        testkit::assert_rows(
            &draw("not known"),
            &[
                "R A V E N                                                     o Receiving is off",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> o Bob             ││ Bob  v Verified - Last message 5 min ago               │",
                "│  o Alice          1││ You *--------------------------* Bob                   │",
                "│  x Carol          !││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││ Bob - 1 h ago                                          │",
                "│                    ││   Hi! Are you coming tonight?                          │",
                "│                    ││ You - 1 h ago  vv Delivered                            │",
                "│                    ││   Yes, at eight.                                       │",
                "│                    ││ Bob - 5 min ago                                        │",
                "│                    ││   Great, see you there.                                │",
                "│                    ││   Bring the map.                                       │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│ A  Add a friend    ││ To Bob: write here  (Enter sends  Ctrl+J new line)     │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                          activity .....................:..",
                "? Help  Esc Friends  Enter Send  Ctrl+J New line  Tab Messages  PgUp/PgDn Scroll",
            ],
        );
    }

    #[test]
    fn the_wait_line_in_its_three_states_at_70_by_20() {
        let draw = |state: &str| {
            let app = horizon_home(testkit::simple_mono(), (70, 20), state);
            testkit::render(&app, 70, 20)
        };
        testkit::assert_rows(
            &draw("can wait"),
            &[
                "R A V E N                                           o Receiving is off",
                "┌────────────────────────────────────────────────────────────────────┐",
                "│ Bob  v Verified - Last message 5 min ago          1 new from Alice │",
                "│ You *--------------------------* Bob                               │",
                "│ If Bob is away, Raven keeps trying until about 24 h from now.      │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│ Bob - 1 h ago                                                      │",
                "│   Hi! Are you coming tonight?                                      │",
                "│ You - 1 h ago  vv Delivered                                        │",
                "│   Yes, at eight.                                                   │",
                "│ Bob - 5 min ago                                                    │",
                "│   Great, see you there.                                            │",
                "│   Bring the map.                                                   │",
                "│ ────────────────────────────────────────────────────────────────── │",
                "│ To Bob: write here  (Enter sends  Ctrl+J new line)                 │",
                "└────────────────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                activity .....................:..",
                "? Help  Esc Friends  Enter Send  Ctrl+J New line  Tab Messages        ",
            ],
        );
        testkit::assert_rows(
            &draw("meet first"),
            &[
                "R A V E N                                           o Receiving is off",
                "┌────────────────────────────────────────────────────────────────────┐",
                "│ Bob  v Verified - Last message 5 min ago          1 new from Alice │",
                "│ You *--------------------------* Bob                               │",
                "│ To write to Bob, meet first: Raven can't hold new messages for     │",
                "│ them now.                                                          │",
                "│                                                                    │",
                "│ Bob - 1 h ago                                                      │",
                "│   Hi! Are you coming tonight?                                      │",
                "│ You - 1 h ago  vv Delivered                                        │",
                "│   Yes, at eight.                                                   │",
                "│ Bob - 5 min ago                                                    │",
                "│   Great, see you there.                                            │",
                "│   Bring the map.                                                   │",
                "│ ────────────────────────────────────────────────────────────────── │",
                "│ Raven can send this only when you're on the same network as Bob.   │",
                "│ To Bob: write here  (Enter sends  Ctrl+J new line)                 │",
                "└────────────────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                activity .....................:..",
                "? Help  Esc Friends  Enter Send  Ctrl+J New line  Tab Messages        ",
            ],
        );
        testkit::assert_rows(
            &draw("not known"),
            &[
                "R A V E N                                           o Receiving is off",
                "┌────────────────────────────────────────────────────────────────────┐",
                "│ Bob  v Verified - Last message 5 min ago          1 new from Alice │",
                "│ You *--------------------------* Bob                               │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│                                                                    │",
                "│ Bob - 1 h ago                                                      │",
                "│   Hi! Are you coming tonight?                                      │",
                "│ You - 1 h ago  vv Delivered                                        │",
                "│   Yes, at eight.                                                   │",
                "│ Bob - 5 min ago                                                    │",
                "│   Great, see you there.                                            │",
                "│   Bring the map.                                                   │",
                "│ ────────────────────────────────────────────────────────────────── │",
                "│ To Bob: write here  (Enter sends  Ctrl+J new line)                 │",
                "└────────────────────────────────────────────────────────────────────┘",
                "3 friends - all quiet                activity .....................:..",
                "? Help  Esc Friends  Enter Send  Ctrl+J New line  Tab Messages        ",
            ],
        );
    }

    #[test]
    fn the_wait_line_in_every_glyph_set_at_60_by_16() {
        let simple: &[&str] = &[
            "R A V E N                                 o Receiving is off",
            "┌──────────────────────────────────────────────────────────┐",
            "│ Bob  v Verified - Last message 5 min ago                 │",
            "│ You *--------------------------* Bob                     │",
            "│ To write to Bob, meet first: Raven can't hold new        │",
            "│ messages for them now.                                   │",
            "│   Yes, at eight.                                         │",
            "│ Bob - 5 min ago                                          │",
            "│   Great, see you there.                                  │",
            "│   Bring the map.                                         │",
            "│ ──────────────────────────────────────────────────────── │",
            "│ Raven can send this only when you're on the same network │",
            "│ as Bob.                                                  │",
            "│ To Bob: write here  (Enter sends  Ctrl+J new line)       │",
            "└──────────────────────────────────────────────────────────┘",
            "? Help  Esc Friends  Enter Send  Ctrl+J New line            ",
        ];
        let fancy: &[&str] = &[
            "R A V E N                                 ○ Receiving is off",
            "╭──────────────────────────────────────────────────────────╮",
            "│ Bob  ✓ Verified · Last message 5 min ago                 │",
            "│ You ◉┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄◉ Bob                     │",
            "│ To write to Bob, meet first: Raven can't hold new        │",
            "│ messages for them now.                                   │",
            "│   Yes, at eight.                                         │",
            "│ Bob · 5 min ago                                          │",
            "│   Great, see you there.                                  │",
            "│   Bring the map.                                         │",
            "│ ──────────────────────────────────────────────────────── │",
            "│ Raven can send this only when you're on the same network │",
            "│ as Bob.                                                  │",
            "│ To Bob: write here  (Enter sends · Ctrl+J new line)      │",
            "╰──────────────────────────────────────────────────────────╯",
            "? Help · Esc Friends · Enter Send · Ctrl+J New line         ",
        ];
        let ascii: &[&str] = &[
            "R A V E N                                 o Receiving is off",
            "+----------------------------------------------------------+",
            "| Bob  v Verified - Last message 5 min ago                 |",
            "| You *--------------------------* Bob                     |",
            "| To write to Bob, meet first: Raven can't hold new        |",
            "| messages for them now.                                   |",
            "|   Yes, at eight.                                         |",
            "| Bob - 5 min ago                                          |",
            "|   Great, see you there.                                  |",
            "|   Bring the map.                                         |",
            "| -------------------------------------------------------- |",
            "| Raven can send this only when you're on the same network |",
            "| as Bob.                                                  |",
            "| To Bob: write here  (Enter sends  Ctrl+J new line)       |",
            "+----------------------------------------------------------+",
            "? Help  Esc Friends  Enter Send  Ctrl+J New line            ",
        ];
        // A day: the same words in every set, between its box lines.
        let can_wait = [
            "If Bob is away, Raven keeps trying until about 24 h from",
            "now.",
        ];
        for (glyphs, meet_first, side) in [
            (Glyphs::simple(), simple, "│"),
            (Glyphs::fancy(), fancy, "│"),
            (Glyphs::ascii(), ascii, "|"),
        ] {
            let look = Look {
                glyphs,
                ..testkit::simple_mono()
            };
            let app = horizon_home(look, (60, 16), "meet first");
            testkit::assert_rows(&testkit::render(&app, 60, 16), meet_first);
            let app = horizon_home(look, (60, 16), "can wait");
            let rows = testkit::render(&app, 60, 16);
            for (row, words) in rows[4..6].iter().zip(can_wait) {
                assert_eq!(row, &format!("{side} {words:<56} {side}"));
            }
        }
    }

    #[test]
    fn the_wait_line_and_the_hint_are_dim() {
        let dim = |app: &App, x: u16, y: u16| {
            let (cols, rows) = app.size();
            let mut terminal =
                Terminal::new(TestBackend::new(cols, rows)).expect("a test terminal");
            terminal
                .draw(|f| render_frame(f, app, app.now()))
                .expect("draw");
            terminal.backend().buffer()[(x, y)]
                .modifier
                .contains(Modifier::DIM)
        };
        // The pane's words start at column 24, under the name (row 2) and
        // the route line (row 3, UXF.10).
        let app = horizon_home(testkit::simple_mono(), (80, 24), "can wait");
        assert!(!dim(&app, 24, 2), "the name");
        assert!(dim(&app, 24, 4), "the line");
        let app = horizon_home(testkit::simple_mono(), (80, 24), "meet first");
        assert!(dim(&app, 24, 4), "the line");
        assert!(dim(&app, 24, 18), "the composer's hint");
        assert!(!dim(&app, 24, 20), "the composer");
    }

    #[test]
    fn the_wait_line_says_how_long_is_left_and_nothing_once_it_is_past() {
        // Its words, on one row or two.
        let line = |app: &App| {
            let rows = testkit::render(app, 70, 20);
            rows[4..6]
                .iter()
                .map(|row| row.trim_matches(|c| c == '│' || c == ' ').to_owned())
                .collect::<Vec<_>>()
                .join(" ")
                .trim()
                .to_owned()
        };
        let mut app = horizon_home(testkit::simple_mono(), (70, 20), "not known");
        let empty = line(&app);
        for (left_ms, want) in [
            (24 * HOUR_MS, "about 24 h from now"),
            (2 * HOUR_MS - 1, "about 119 min from now"),
            (45 * 60_000, "about 45 min from now"),
            (30_000, "less than a minute from now"),
        ] {
            let until = app.now_ms() + left_ms;
            horizon_read(&mut app, 1, can_wait_until(until));
            assert_eq!(
                line(&app),
                format!("If Bob is away, Raven keeps trying until {want}."),
                "{left_ms}"
            );
        }
        // Past by the next draw: no line until a read says more.
        testkit::tick(&mut app, Duration::from_secs(31));
        assert_eq!(line(&app), empty);
        // A blocked friend: nothing is sent to them, so no line either.
        let blocked = vec![ContactView {
            blocked: true,
            ..three().remove(0)
        }];
        let bob = testkit::friend(1).pub_hex;
        for state in ["can wait", "meet first", "first message"] {
            let app = horizon_home_with(testkit::simple_mono(), (70, 20), blocked.clone(), state);
            assert_eq!(app.open_friend(), Some(bob.as_str()));
            assert!(app.horizon(&bob).is_some(), "read, but not drawn");
            let screen = testkit::screen_text(&testkit::render(&app, 70, 20));
            assert!(!screen.contains("keeps trying until"), "{screen}");
            assert!(!screen.contains("meet first"), "{screen}");
            assert!(!screen.contains("same network as"), "{screen}");
            assert!(!screen.contains("both online"), "{screen}");
        }
    }

    #[test]
    fn the_wait_line_names_the_friend_and_a_time_only() {
        // Bob with every key and address a line could give away.
        let bob = ContactView {
            label: "Bob\u{1b}]0;pwned\u{7}".into(),
            pinned: true,
            fingerprint: "If4x-36FU-omFi".into(),
            internet_dial: "203.0.113.7:7420".into(),
            p2p: "12D3KooWRavenTestPeer".into(),
            ..testkit::reachable(1)
        };
        let leaks = [
            bob.pub_hex.clone(),
            bob.pub_hex[..8].to_owned(),
            bob.address.clone(),
            bob.fingerprint.clone(),
            bob.lan_dial.clone(),
            "192.168.1.11".to_owned(),
            bob.internet_dial.clone(),
            "203.0.113.7".to_owned(),
            bob.p2p.clone(),
            "7420".to_owned(),
            "\u{1b}".to_owned(),
            "pwned".to_owned(),
        ];
        for state in ["can wait", "meet first", "first message"] {
            for size in [(80, 24), (70, 20)] {
                let look = testkit::simple_mono();
                let app = horizon_home_with(look, size, vec![bob.clone()], state);
                let friend = app.friend(&bob.pub_hex).expect("Bob");
                let width = chat_parts(&app, chat_area(&app)).messages.width;
                let words: Vec<String> = horizon_lines(&app, friend, width)
                    .into_iter()
                    .chain(composer_hint(&app, Some(friend), width))
                    .map(|line| line.to_string())
                    .collect();
                let text = words.join(" ");
                assert!(text.contains("Bob"), "{state}: {text}");
                for leak in &leaks {
                    assert!(
                        !text.contains(leak.as_str()),
                        "{state}: {leak:?} in {text:?}"
                    );
                }
                // Nor anywhere on Home.
                let screen = testkit::render(&app, size.0, size.1).join("\n");
                for leak in &leaks {
                    assert!(
                        !screen.contains(leak.as_str()),
                        "{state}: {leak:?} on screen"
                    );
                }
            }
        }
    }

    #[test]
    fn meet_first_still_sends_through_the_normal_path() {
        let enter = |state: &str| {
            let mut app = horizon_home(testkit::simple_mono(), (70, 20), state);
            for c in "hi".chars() {
                testkit::press(&mut app, KeyCode::Char(c));
            }
            let cmds = testkit::press(&mut app, KeyCode::Enter);
            (app, cmds)
        };
        let (mut app, cmds) = enter("meet first");
        let sends: Vec<(&str, &str)> = cmds
            .iter()
            .filter_map(|cmd| match cmd {
                Cmd::Send(SendJob::Send { pub_hex, text, .. }) => {
                    Some((pub_hex.as_str(), text.as_str()))
                }
                _ => None,
            })
            .collect();
        let bob = testkit::friend(1).pub_hex;
        assert_eq!(sends, [(bob.as_str(), "hi")]);
        assert_eq!(cmds, enter("not known").1, "as with no line");
        // Its outcome says what happened (UXF.1); the line and hint stay.
        let (id, _) = testkit::send_job(&cmds).expect("a send");
        let unmet = testkit::meet_first_outcome(1);
        testkit::send(&mut app, testkit::sent(id, SendResult::Failed(unmet)));
        let screen = testkit::screen_text(&testkit::render(&app, 70, 20));
        for words in [
            "To write to Bob, meet first: Raven can't hold new messages for them now.",
            "Not sent: meet first. Press R when you're together.",
            "Raven can send this only when you're on the same network as Bob.",
        ] {
            assert!(screen.contains(words), "{words:?} in {screen}");
        }
        // What the composer refuses is said there first.
        testkit::paste(&mut app, "RVNAPP/1 hello", PasteVia::Bracketed);
        let rows = testkit::render(&app, 70, 20);
        assert_eq!(
            rows[15],
            format!(
                "│ {:<66} │",
                "Messages can't start with RVNAPP/ or RVNGRP/."
            )
        );
        assert!(!testkit::screen_text(&rows).contains("same network as"));
    }

    /// E1: a friend Raven hasn't connected with yet. Home says the rule a
    /// first message goes by in the CLI's words (`raven contact list` says
    /// the same), Enter still sends, and a send that found their computer
    /// away says when to try again: when they are online, not "meet first".
    #[test]
    fn a_first_message_says_the_cli_rule_and_still_sends() {
        let mut app = horizon_home(testkit::simple_mono(), (70, 20), "first message");
        for c in "hi".chars() {
            testkit::press(&mut app, KeyCode::Char(c));
        }
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        let (id, _) = testkit::send_job(&cmds).expect("a send");
        let away = testkit::first_message_outcome(1);
        testkit::send(&mut app, testkit::sent(id, SendResult::Failed(away)));
        let screen = testkit::screen_text(&testkit::render(&app, 70, 20));
        for words in [
            "A first message needs you and Bob both online (Raven hasn't connected with Bob \
             yet).",
            "Not sent: a first message needs you both online. Press R when Bob is online.",
            "Raven can send this only while you and Bob are both online.",
        ] {
            assert!(screen.contains(words), "{words:?} in {screen}");
        }
        for not in ["meet first", "same network", "together"] {
            assert!(!screen.contains(not), "{not:?} in {screen}");
        }
    }

    // ── delivery ticks ──────────────────────────────────────────────────────

    /// Each state a message of yours can be in, set up through the App's own
    /// messages on Home with friend 1 open: (name, how, whether its
    /// animation is let come to rest first).
    #[allow(clippy::type_complexity)]
    const STATES: &[(&str, fn(&mut App), bool)] = &[
        ("waiting to send", waiting_to_send, false),
        ("sending", sending, false),
        ("connecting", connecting, false),
        ("can wait", can_wait, false),
        ("waiting", waiting, false),
        ("next send", next_send, false),
        ("not retried", not_retried, false),
        ("on hold", on_hold, false),
        ("sent", sent_not_confirmed, false),
        ("delivered", delivered, true),
        ("never left", never_left, true),
        ("time ran out", time_ran_out, true),
        ("may have it", may_have_it, true),
        ("ran out, may have it", ran_out_may_have_it, true),
        ("not sent", not_sent, true),
        ("meet first", meet_first, true),
        ("first message", first_message, true),
    ];

    fn send_hi(app: &mut App) -> u64 {
        testkit::type_and_send(app, "hi").expect("a send").0
    }

    fn queued_row(app: &mut App) {
        testkit::reload_rows(app, &[(1, testkit::row(1, true, "queued", 0, "hi"))]);
    }

    fn waiting_to_send(app: &mut App) {
        testkit::type_and_send(app, "first").expect("a send");
        send_hi(app);
    }

    fn sending(app: &mut App) {
        send_hi(app);
    }

    fn connecting(app: &mut App) {
        send_hi(app);
        queued_row(app);
    }

    /// raven-node lists it, so its deadline is known (a day off).
    fn can_wait(app: &mut App) {
        waiting(app);
        queued_row(app);
        let item = testkit::outbox_item(1, 1, "queued");
        testkit::send(app, testkit::outbox(vec![item]));
    }

    fn waiting(app: &mut App) {
        testkit::send(app, testkit::node_up());
        not_retried(app);
    }

    fn next_send(app: &mut App) {
        testkit::send(app, testkit::node_up());
        let id = send_hi(app);
        let queued = testkit::queued_outcome(1, false);
        testkit::send(app, testkit::sent(id, SendResult::Failed(queued)));
    }

    fn not_retried(app: &mut App) {
        let id = send_hi(app);
        let queued = testkit::queued_outcome(1, true);
        testkit::send(app, testkit::sent(id, SendResult::Failed(queued)));
    }

    fn on_hold(app: &mut App) {
        testkit::send(app, testkit::node_up());
        queued_row(app);
        let mut item = testkit::outbox_item(1, 1, "held");
        item.last_error_code = "NO_PEER_CERT".into();
        testkit::send(app, testkit::outbox(vec![item]));
    }

    fn sent_not_confirmed(app: &mut App) {
        let id = send_hi(app);
        let unconfirmed = testkit::unconfirmed_outcome(1);
        testkit::send(app, testkit::sent(id, SendResult::Failed(unconfirmed)));
    }

    fn delivered(app: &mut App) {
        let id = send_hi(app);
        let to = testkit::delivered_to("192.168.1.11:7420");
        testkit::send(app, testkit::sent(id, to));
    }

    fn never_left(app: &mut App) {
        connecting(app);
        let queued = testkit::queued_outcome(1, true);
        testkit::send(app, testkit::sent(1, SendResult::Failed(queued)));
        testkit::reload_rows(app, &[(1, testkit::row(1, true, "cancelled", 0, "hi"))]);
    }

    fn time_ran_out(app: &mut App) {
        connecting(app);
        let queued = testkit::queued_outcome(1, true);
        testkit::send(app, testkit::sent(1, SendResult::Failed(queued)));
        testkit::reload_rows(app, &[(1, testkit::row(1, true, "expired", 0, "hi"))]);
    }

    fn may_have_it(app: &mut App) {
        testkit::reload_rows(app, &[(1, testkit::row(1, true, "cancelled", 0, "hi"))]);
    }

    fn ran_out_may_have_it(app: &mut App) {
        testkit::reload_rows(app, &[(1, testkit::row(1, true, "expired", 0, "hi"))]);
    }

    fn not_sent(app: &mut App) {
        let id = send_hi(app);
        let refused = testkit::not_sent_outcome(1);
        testkit::send(app, testkit::sent(id, SendResult::Failed(refused)));
    }

    fn meet_first(app: &mut App) {
        let id = send_hi(app);
        let unmet = testkit::meet_first_outcome(1);
        testkit::send(app, testkit::sent(id, SendResult::Failed(unmet)));
    }

    fn first_message(app: &mut App) {
        let id = send_hi(app);
        let away = testkit::first_message_outcome(1);
        testkit::send(app, testkit::sent(id, SendResult::Failed(away)));
    }

    /// Home in `look` at 100x30 with friend 1 open, its newest message of
    /// yours in `state`.
    fn in_state(look: Look, state: &str) -> App {
        in_state_at(look, (100, 30), state)
    }

    /// [`in_state`] in a window of `size`.
    fn in_state_at(look: Look, size: (u16, u16), state: &str) -> App {
        let (_, setup, rest) = STATES
            .iter()
            .find(|(name, _, _)| *name == state)
            .expect("a known state");
        let mut app = testkit::home_app_in(
            look,
            size,
            Receive::Off,
            vec![testkit::reachable(1)],
            Conversations::new(),
        );
        testkit::press(&mut app, KeyCode::Enter);
        setup(&mut app);
        if *rest {
            testkit::tick(&mut app, Duration::from_secs(2));
        }
        app
    }

    /// The newest message's rows in the conversation pane, from its header
    /// row to its body, as drawn at `now`.
    fn newest_message(app: &App, now: Instant) -> Vec<String> {
        let rows: Vec<String> = testkit::render_at(app, 100, 30, now)
            .iter()
            .map(|row| row.chars().skip(24).take(74).collect::<String>())
            .map(|row| row.trim_end().to_owned())
            .collect();
        let head = rows
            .iter()
            .rposition(|row| row.starts_with("You") || row.starts_with("> You"))
            .expect("a message of yours");
        rows[head..]
            .iter()
            .take_while(|row| !row.starts_with("  hi"))
            .cloned()
            .collect()
    }

    #[test]
    fn every_tick_label_in_every_glyph_set() {
        let simple: &[(&str, &[&str])] = &[
            // Behind 'first', in its run: no sender line of its own.
            (
                "waiting to send",
                &[
                    "You - just now  | Sending...",
                    "  first",
                    "  ~ Waiting to send",
                ],
            ),
            ("sending", &["You - just now  | Sending..."]),
            ("connecting", &["You - just now  | Connecting..."]),
            (
                "can wait",
                &["You - just now  ~ Waiting for Friend 1 - until about 24 h from now"],
            ),
            (
                "waiting",
                &["You - just now  ~ Waiting: Raven keeps trying"],
            ),
            (
                "next send",
                &["You - just now  ~ Waiting: goes out with your next message"],
            ),
            (
                "not retried",
                &[
                    "You - just now  ~",
                    "  Waiting: not being retried (Raven's background program isn't running)",
                ],
            ),
            (
                "on hold",
                &[
                    "You - just now  ~",
                    "  On hold: Raven is still setting up a secure connection with Friend 1",
                ],
            ),
            ("sent", &["You - just now  v Sent, not confirmed yet"]),
            // With the path its own send went by (Calm).
            ("delivered", &["You - just now  vv Delivered - LAN direct"]),
            (
                "never left",
                &[
                    "You - just now  x",
                    "  Not delivered: it never left this computer. Press R to send it again.",
                ],
            ),
            (
                "time ran out",
                &[
                    "You - just now  x",
                    "  Time ran out: it never left this computer. Press R to send it again.",
                ],
            ),
            (
                "may have it",
                &[
                    "You - just now  x",
                    "  Not confirmed: Friend 1 may have it. Press Enter for options.",
                ],
            ),
            (
                "ran out, may have it",
                &[
                    "You - just now  x",
                    "  Not confirmed: Friend 1 may have it. Press Enter for options.",
                ],
            ),
            (
                "not sent",
                &[
                    "You - just now  x",
                    "  Not sent: Friend 1's computer is there, but Raven isn't receiving right",
                    "  now (it may be locked or closed). Press R to try again.",
                ],
            ),
            (
                "meet first",
                &["You - just now  x Not sent: meet first. Press R when you're together."],
            ),
            (
                "first message",
                &[
                    "You - just now  x",
                    "  Not sent: a first message needs you both online. Press R when Friend 1",
                    "  is online.",
                ],
            ),
        ];
        assert_eq!(simple.len(), STATES.len());
        let fancy_of = |row: &str| {
            row.replace(" - ", " · ")
                .replacen("  vv ", "  ✓✓ ", 1)
                .replacen("  v ", "  ✓ ", 1)
                .replacen("  | ", "  ⠋ ", 1)
                .replace("...", "…")
                .replace("  x", "  ✗")
        };
        let looks = [
            ("simple", Glyphs::simple()),
            ("ascii", Glyphs::ascii()),
            ("fancy", Glyphs::fancy()),
        ];
        for (set, glyphs) in looks {
            let look = Look {
                glyphs,
                ..testkit::simple_mono()
            };
            for (state, rows) in simple {
                let app = in_state(look, state);
                let want: Vec<String> = rows
                    .iter()
                    .map(|row| {
                        if set == "fancy" {
                            fancy_of(row)
                        } else {
                            (*row).to_owned()
                        }
                    })
                    .collect();
                assert_eq!(newest_message(&app, app.now()), want, "{set}: {state}");
            }
        }
    }

    #[test]
    fn a_sends_spinner_turns_unless_motion_is_reduced() {
        for (motion, want) in [
            (
                Motion::Full,
                [
                    "You - just now  | Sending...",
                    "You - just now  / Sending...",
                    "You - just now  - Sending...",
                ],
            ),
            (
                Motion::Reduced,
                [
                    "You - just now  ... Sending...",
                    "You - just now  ... Sending...",
                    "You - just now  ... Sending...",
                ],
            ),
        ] {
            let look = Look {
                motion,
                ..testkit::simple_mono()
            };
            let app = in_state(look, "sending");
            let t = app.now();
            let frames: Vec<String> = [0, 83, 166]
                .into_iter()
                .map(|ms| newest_message(&app, t + Duration::from_millis(ms))[0].clone())
                .collect();
            assert_eq!(frames, want, "{motion:?}");
            // The clock's seconds, the send travelling the route line, and
            // the spinner (anim.rs stills both under reduced motion).
            let moving = moving(&app);
            assert_eq!(
                moving,
                [
                    Moving::Clock {
                        at: t,
                        at_ms: app.now_ms()
                    },
                    Moving::Steps {
                        since: t,
                        every: live::ROUTE_TIME / live::ROUTE_STEPS
                    },
                    Moving::Spinner { since: t }
                ]
            );
        }
    }

    #[test]
    fn delivered_draws_in_and_a_failure_blinks_twice() {
        let look = testkit::simple_mono();
        // Delivered types itself, a character every 45 ms (Calm), the sent
        // mark for the first two.
        let mut app = in_state(look, "sending");
        delivered_now(&mut app);
        let t = app.now();
        let frames: Vec<String> = [0, 45, 90, 135, 200, 360, 405, 1_000]
            .into_iter()
            .map(|ms| newest_message(&app, t + Duration::from_millis(ms))[0].clone())
            .collect();
        assert_eq!(
            frames,
            [
                "You - just now  v",
                "You - just now  v  D",
                "You - just now  vv De",
                "You - just now  vv Del",
                "You - just now  vv Deli",
                "You - just now  vv Delivere",
                "You - just now  vv Delivered - LAN direct",
                "You - just now  vv Delivered - LAN direct",
            ]
        );
        // The draw-in, and the receipt travelling back (UXF.10).
        let listed = moving(&app);
        assert!(listed.contains(&Moving::Transition {
            start: t,
            frames: widgets::DELIVERED_FRAMES,
            length: widgets::DELIVERED_TYPING
        }));
        assert!(listed.contains(&Moving::Transition {
            start: t,
            frames: live::ROUTE_STEPS,
            length: live::ROUTE_TIME
        }));
        // Not sent: the mark off and on, twice, in a second; then still.
        let mut app = in_state(look, "sending");
        let refused = testkit::not_sent_outcome(1);
        testkit::send(&mut app, testkit::sent(1, SendResult::Failed(refused)));
        let t = app.now();
        let marks: Vec<String> = [0, 250, 500, 750, 1_000, 5_000]
            .into_iter()
            .map(|ms| newest_message(&app, t + Duration::from_millis(ms))[0].clone())
            .collect();
        assert_eq!(
            marks,
            [
                "You - just now  x",
                "You - just now",
                "You - just now  x",
                "You - just now",
                "You - just now  x",
                "You - just now  x",
            ]
        );
        // Reduced motion: both are still from the start.
        let reduced = Look {
            motion: Motion::Reduced,
            ..look
        };
        let mut app = in_state(reduced, "sending");
        delivered_now(&mut app);
        assert_eq!(
            newest_message(&app, app.now())[0],
            "You - just now  vv Delivered - LAN direct"
        );
        // Only text changes then: the clock's seconds, the ticker's news.
        let motion: Vec<Moving> = moving(&app)
            .into_iter()
            .filter(|m| !matches!(m, Moving::Clock { .. } | Moving::Deadline(_)))
            .collect();
        assert!(anim::next_change(&motion, app.look(), app.now()).is_none());
        // Messages seen as they are at the first load never move.
        let app = home(
            (100, 30),
            vec![testkit::reachable(1)],
            &[
                (1, testkit::row(1, true, "delivered", 0, "hi")),
                (1, testkit::row(2, true, "failed", 0, "hi")),
            ],
        );
        let app = pressed(app, &[KeyCode::Enter]);
        assert_eq!(
            moving(&app),
            [Moving::Clock {
                at: app.now(),
                at_ms: app.now_ms()
            }]
        );
    }

    /// The send of `in_state(.., "sending")` answered: delivered.
    fn delivered_now(app: &mut App) {
        let to = testkit::delivered_to("192.168.1.11:7420");
        testkit::send(app, testkit::sent(1, to));
    }

    #[test]
    fn a_waiting_message_says_until_when_it_can_wait() {
        let app = in_state(testkit::simple_mono(), "can wait");
        assert_eq!(
            newest_message(&app, app.now()),
            ["You - just now  ~ Waiting for Friend 1 - until about 24 h from now"]
        );
        // It changes with the minute at most: nothing but Home's clock wakes
        // the app (UXF.10).
        assert!(moving(&app)
            .iter()
            .all(|m| matches!(m, Moving::Clock { .. })));
        // With less than 2 h left, how much is left.
        for (left_ms, want) in [
            (2 * 3_600_000, "until about 2 h from now"),
            (2 * 3_600_000 - 1, "1 h left"),
            (45 * 60_000, "45 min left"),
            (30_000, "less than a minute left"),
        ] {
            let mut app = in_state(testkit::simple_mono(), "can wait");
            let mut item = testkit::outbox_item(1, 1, "queued");
            item.expires_at_ms = app.now_ms() + left_ms;
            testkit::send(&mut app, testkit::outbox(vec![item]));
            assert_eq!(
                newest_message(&app, app.now()),
                [format!("You - just now  ~ Waiting for Friend 1 - {want}")],
                "{left_ms}"
            );
        }
        // Not listed by raven-node yet: no deadline to give.
        let app = in_state(testkit::simple_mono(), "waiting");
        assert_eq!(
            newest_message(&app, app.now()),
            ["You - just now  ~ Waiting: Raven keeps trying"]
        );
    }

    /// MSG over the newest message in `state`, at 80x24.
    fn msg(state: &str) -> Vec<String> {
        let app = in_state_at(testkit::simple_mono(), (80, 24), state);
        let app = pressed(app, &[KeyCode::Tab, KeyCode::Enter]);
        testkit::render(&app, 80, 24)
    }

    #[test]
    fn msg_for_a_waiting_message() {
        testkit::assert_rows(
            &msg("can wait"),
            &[
            "R A V E N                                                   + node ok - just now",
            "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
            "│> ~ Friend 1       !││ Friend 1  ! Not verified - 1 message waiting           │",
            "│                    ││ You *--------------------------* Friend 1              │",
            "│       ┌──────────────────────────────────────────────────────────────┐pare   │",
            "│       │ Message to Friend 1 - just now                               │       │",
            "│       │ \"hi\"                                                         │       │",
            "│       │                                                              │       │",
            "│       │ Status: Waiting. Friend 1's Raven isn't reachable from here  │       │",
            "│       │ right now. Raven sends it by itself when you're both on the  │       │",
            "│       │ same network.                                                │       │",
            "│       │ Why: Friend 1's computer is there, but Raven isn't receiving │       │",
            "│       │ right now (it may be locked or closed).                      │       │",
            "│       │ What you can do: nothing. It can wait until about 24 hours   │       │",
            "│       │ from now. After that Raven won't send it, and this message   │       │",
            "│       │ will say so. Or press C to stop trying.                      │       │",
            "│       │                                                              │       │",
            "│       │ [R] Try now  [C] Stop trying  [D] Details  [Esc] Close       │ow     │",
            "│       └──────────────────────────────────────────────────────────────┘       │",
            "│                    ││ ────────────────────────────────────────────────────── │",
            "│ A  Add a friend    ││ To Friend 1: write here  (Enter sends  Ctrl+J new line │",
            "└────────────────────┘└────────────────────────────────────────────────────────┘",
            "1 message waiting for Friend 1                 activity .......................:",
            "? Help  Esc Back  Up/Down Choose  R Retry  C Stop trying  D Details             ",
            ],
        );
    }

    #[test]
    fn msg_for_a_sent_message() {
        testkit::assert_rows(
            &msg("sent"),
            &[
            "R A V E N                                                     o Receiving is off",
            "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
            "│> o Friend 1       !││ Friend 1  ! Not verified - No messages yet             │",
            "│                    ││ You *--------------------------* Friend 1              │",
            "│                    ││ You haven't checked this is really Friend 1. Compare   │",
            "│                    ││ security words with Friend 1: press V.                 │",
            "│                    ││                                                        │",
            "│       ┌──────────────────────────────────────────────────────────────┐       │",
            "│       │ Message to Friend 1 - just now                               │       │",
            "│       │ \"hi\"                                                         │       │",
            "│       │                                                              │       │",
            "│       │ Status: Sent, not confirmed yet. It left this computer, but  │       │",
            "│       │ Friend 1's Raven hasn't confirmed it.                        │       │",
            "│       │ What you can do: wait. Don't send it again.                  │       │",
            "│       │                                                              │       │",
            "│       │ [D] Details  [Esc] Close                                     │       │",
            "│       └──────────────────────────────────────────────────────────────┘       │",
            "│                    ││ > You - just now  v Sent, not confirmed yet            │",
            "│                    ││   hi                                                   │",
            "│                    ││ ────────────────────────────────────────────────────── │",
            "│ A  Add a friend    ││ To Friend 1: write here  (Enter sends  Ctrl+J new line │",
            "└────────────────────┘└────────────────────────────────────────────────────────┘",
            "Sent to Friend 1 - not confirmed yet           activity ........................",
            "? Help  Esc Back  Up/Down Choose  R Retry  C Stop trying  D Details             ",
            ],
        );
    }

    #[test]
    fn msg_for_a_message_that_may_have_arrived() {
        testkit::assert_rows(
            &msg("may have it"),
            &[
            "R A V E N                                                     o Receiving is off",
            "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
            "│> o Friend 1       !││ Friend 1  ! Not verified - Last message just now       │",
            "│                    ││ You *--------------------------* Friend 1              │",
            "│                    ││ You haven't checked this is really Friend 1. Compare   │",
            "│                    ││ security words with Friend 1: press V.                 │",
            "│       ┌──────────────────────────────────────────────────────────────┐       │",
            "│       │ Message to Friend 1 - just now                               │       │",
            "│       │ \"hi\"                                                         │       │",
            "│       │                                                              │       │",
            "│       │ Status: Not confirmed. Raven stopped trying, but it had      │       │",
            "│       │ already sent this message once, so Friend 1 may have it.     │       │",
            "│       │ What you can do: ask Friend 1. If they didn't get it, press  │       │",
            "│       │ S to send it again (they may see it twice).                  │       │",
            "│       │                                                              │       │",
            "│       │ [S] Send again anyway  [D] Details  [Esc] Close              │       │",
            "│       └──────────────────────────────────────────────────────────────┘er for │",
            "│                    ││   options.                                             │",
            "│                    ││   hi                                                   │",
            "│                    ││ ────────────────────────────────────────────────────── │",
            "│ A  Add a friend    ││ To Friend 1: write here  (Enter sends  Ctrl+J new line │",
            "└────────────────────┘└────────────────────────────────────────────────────────┘",
            "1 friend - all quiet                           activity .......................:",
            "? Help  Esc Back  Up/Down Choose  R Retry  C Stop trying  D Details             ",
            ],
        );
    }

    /// MSG over the newest message in `state`, in `look` at `size`: its
    /// deadline moved to `left_ms` from now when one is given, and Details
    /// open on `details`.
    fn msg_with(
        look: Look,
        size: (u16, u16),
        state: &str,
        left_ms: Option<u64>,
        details: bool,
    ) -> App {
        let mut app = in_state_at(look, size, state);
        if let Some(left_ms) = left_ms {
            let mut item = testkit::outbox_item(1, 1, "queued");
            item.expires_at_ms = app.now_ms() + left_ms;
            testkit::send(&mut app, testkit::outbox(vec![item]));
        }
        let mut keys = vec![KeyCode::Tab, KeyCode::Enter];
        if details {
            keys.push(KeyCode::Char('d'));
        }
        pressed(app, &keys)
    }

    #[test]
    fn msg_for_a_waiting_message_with_little_time_left() {
        let app = msg_with(
            testkit::simple_mono(),
            (80, 24),
            "can wait",
            Some(45 * 60_000),
            false,
        );
        testkit::assert_rows(&testkit::render(&app, 80, 24), &[
            "R A V E N                                                   + node ok - just now",
            "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
            "│> ~ Friend 1       !││ Friend 1  ! Not verified - 1 message waiting           │",
            "│                    ││ You *--------------------------* Friend 1              │",
            "│       ┌──────────────────────────────────────────────────────────────┐pare   │",
            "│       │ Message to Friend 1 - just now                               │       │",
            "│       │ \"hi\"                                                         │       │",
            "│       │                                                              │       │",
            "│       │ Status: Waiting. Friend 1's Raven isn't reachable from here  │       │",
            "│       │ right now. Raven sends it by itself when you're both on the  │       │",
            "│       │ same network.                                                │       │",
            "│       │ Why: Friend 1's computer is there, but Raven isn't receiving │       │",
            "│       │ right now (it may be locked or closed).                      │       │",
            "│       │ What you can do: nothing. It can wait until about 45 minutes │       │",
            "│       │ from now. After that Raven won't send it, and this message   │       │",
            "│       │ will say so. If you won't meet Friend 1 before about 45 min  │       │",
            "│       │ from now, tell them another way. Or press C to stop trying.  │       │",
            "│       │                                                              │n left │",
            "│       │ [R] Try now  [C] Stop trying  [D] Details  [Esc] Close       │       │",
            "│       └──────────────────────────────────────────────────────────────┘────── │",
            "│ A  Add a friend    ││ To Friend 1: write here  (Enter sends  Ctrl+J new line │",
            "└────────────────────┘└────────────────────────────────────────────────────────┘",
            "1 message waiting for Friend 1                 activity .......................:",
            "? Help  Esc Back  Up/Down Choose  R Retry  C Stop trying  D Details             ",
            ]);
    }

    #[test]
    fn msg_for_a_message_whose_time_ran_out() {
        testkit::assert_rows(&msg("time ran out"), &[
            "R A V E N                                                     o Receiving is off",
            "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
            "│> o Friend 1       !││ Friend 1  ! Not verified - Last message just now       │",
            "│                    ││ You *--------------------------* Friend 1              │",
            "│                    ││ You haven't checked this is really Friend 1. Compare   │",
            "│                    ││ security words with Friend 1: press V.                 │",
            "│       ┌──────────────────────────────────────────────────────────────┐       │",
            "│       │ Message to Friend 1 - just now                               │       │",
            "│       │ \"hi\"                                                         │       │",
            "│       │                                                              │       │",
            "│       │ Status: Not delivered. You and Friend 1 weren't on the same  │       │",
            "│       │ network before its time ran out, so Raven stopped trying. It │       │",
            "│       │ never left this computer.                                    │       │",
            "│       │ What you can do: press R to send it again when you're        │       │",
            "│       │ together.                                                    │       │",
            "│       │                                                              │       │",
            "│       │ [R] Send again  [D] Details  [Esc] Close                     │ss R   │",
            "│       └──────────────────────────────────────────────────────────────┘       │",
            "│                    ││   hi                                                   │",
            "│                    ││ ────────────────────────────────────────────────────── │",
            "│ A  Add a friend    ││ To Friend 1: write here  (Enter sends  Ctrl+J new line │",
            "└────────────────────┘└────────────────────────────────────────────────────────┘",
            "1 friend - all quiet                           activity .......................:",
            "? Help  Esc Back  Up/Down Choose  R Retry  C Stop trying  D Details             ",
            ]);
    }

    #[test]
    fn msg_for_a_message_that_needs_a_meeting_first() {
        testkit::assert_rows(&msg("meet first"), &[
            "R A V E N                                                     o Receiving is off",
            "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
            "│> o Friend 1       !││ Friend 1  ! Not verified - No messages yet             │",
            "│                    ││ You *--------------------------* Friend 1              │",
            "│                    ││ You haven't checked this is really Friend 1. Compare   │",
            "│       ┌──────────────────────────────────────────────────────────────┐       │",
            "│       │ Message to Friend 1 - just now                               │       │",
            "│       │ \"hi\"                                                         │       │",
            "│       │                                                              │       │",
            "│       │ Status: Not sent. Raven has no secure connection with Friend │       │",
            "│       │ 1 right now: each one lasts a day from when it is set up,    │       │",
            "│       │ and a new one needs you both on the same network at the same │       │",
            "│       │ time. Nothing was queued.                                    │       │",
            "│       │ Why: Friend 1's computer couldn't be reached (it may be off, │       │",
            "│       │ asleep, or on another network).                              │       │",
            "│       │ What you can do: press R when you're together.               │       │",
            "│       │                                                              │       │",
            "│       │ [R] Send again  [D] Details  [Esc] Close                     │ther.  │",
            "│       └──────────────────────────────────────────────────────────────┘       │",
            "│                    ││ ────────────────────────────────────────────────────── │",
            "│ A  Add a friend    ││ To Friend 1: write here  (Enter sends  Ctrl+J new line │",
            "└────────────────────┘└────────────────────────────────────────────────────────┘",
            "1 friend - all quiet                           activity ........................",
            "? Help  Esc Back  Up/Down Choose  R Retry  C Stop trying  D Details             ",
            ]);
    }

    #[test]
    fn msg_at_60x16_when_time_is_short() {
        let app = msg_with(
            testkit::simple_mono(),
            (60, 16),
            "can wait",
            Some(90 * 60_000),
            false,
        );
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "┌──────────────────────────────────────────────────────────┐",
                "│ Message to Friend 1 - just now                           │",
                "│ \"hi\"                                                     │",
                "│                                                          │",
                "│ Status: Waiting. Friend 1's Raven isn't reachable from   │",
                "│ here right now. Raven sends it by itself when you're     │",
                "│ both on the same network.                                │",
                "│ Why: Friend 1's computer is there, but Raven isn't       │",
                "│ receiving right now (it may be locked or closed).        │",
                "│ What you can do: nothing. It can wait until about 90     │",
                "│ minutes from now. After that Raven won't send it, and    │",
                "│ this message will say so. If you won't meet Friend 1     │",
                "│ before about 90 min from now, tell them another way. Or  │",
                "│ press C to stop trying.                                  │",
                "│ [R] Try now  [C] Stop trying  [D] Details  [Esc] Close   │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
    }

    #[test]
    fn no_utc_in_any_rendered_deadline() {
        const MIN: u64 = 60_000;
        for glyphs in [Glyphs::simple(), Glyphs::fancy(), Glyphs::ascii()] {
            let look = Look {
                glyphs,
                ..testkit::simple_mono()
            };
            for left_ms in [0, 30_000, 45 * MIN, 119 * MIN, 120 * MIN, 24 * 60 * MIN] {
                // The label, then MSG with its Details.
                let app = in_state(look, "can wait");
                let mut item = testkit::outbox_item(1, 1, "queued");
                item.expires_at_ms = app.now_ms() + left_ms;
                let deadline = bridge::deadline_text(item.expires_at_ms, app.now_ms());
                let mut app = app;
                testkit::send(&mut app, testkit::outbox(vec![item]));
                // The words on screen, ASCII's box lines taken out too.
                let words = |app: &App| {
                    let rows: Vec<String> = testkit::render(app, 100, 30)
                        .iter()
                        .map(|row| row.replace('|', " "))
                        .collect();
                    testkit::screen_text(&rows)
                };
                let label = words(&app);
                assert!(label.contains("Waiting for Friend 1"), "{label}");
                let app = msg_with(look, (100, 30), "can wait", Some(left_ms), true);
                let card = words(&app);
                assert!(
                    card.contains(&format!("It can wait until {}.", deadline.long)),
                    "{card}"
                );
                assert!(
                    card.contains(&format!("Expires: {}", deadline.long)),
                    "{card}"
                );
                for text in [&label, &card] {
                    assert!(!text.contains("UTC"), "{left_ms}: {text}");
                }
            }
        }
    }

    #[test]
    fn the_path_tag_takes_its_path_colour_once_delivered_has_typed() {
        // Calm: 'Delivered' types itself, then the path its own send went
        // by, in that path's colour (LAN here); a delivery from before this
        // session says no path.
        let look = Look {
            glyphs: Glyphs::fancy(),
            theme: theme::Theme::calm(&theme::DARK, theme::Depth::True),
            ..testkit::simple_mono()
        };
        let mut app = in_state(look, "sending");
        delivered_now(&mut app);
        let t = app.now();
        let cell = |at: Instant, text: &str| {
            let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("a test terminal");
            terminal.draw(|f| render_frame(f, &app, at)).expect("draw");
            let buf = terminal.backend().buffer().clone();
            let rows = testkit::buffer_lines(&buf);
            // On your message's own row.
            rows.iter().enumerate().find_map(|(y, row)| {
                let x = row.find(text).filter(|_| row.contains("You ·"))?;
                let x = u16::try_from(row[..x].chars().count()).ok()?;
                Some(buf[(x, u16::try_from(y).ok()?)].clone())
            })
        };
        assert!(
            cell(t + MS(200), "LAN direct").is_none(),
            "not while it types"
        );
        let tag = cell(t + MS(1_000), "LAN direct").expect("the path tag");
        assert_eq!(
            tag.fg,
            look.theme.path(theme::PathKind::Lan).fg.expect("a colour")
        );
        let word = cell(t + MS(1_000), "Delivered").expect("the word");
        assert_eq!(word.fg, look.theme.ok.fg.expect("a colour"));
        // Reduced motion: all of it at once.
        let mut still = app.clone();
        still.set_look_for_tests(Look {
            motion: Motion::Reduced,
            ..look
        });
        let rows = testkit::render_at(&still, 100, 30, t);
        assert!(
            rows.iter()
                .any(|row| row.contains("✓✓ Delivered · LAN direct")),
            "{rows:#?}"
        );
    }

    #[test]
    fn a_delivery_over_tor_says_via_tor_in_the_tor_colour() {
        // A send that its own dial delivered over the onion carrier: the
        // path tag after Delivered, and the friend's last path in the wide
        // list, both 'via Tor' in its colour.
        let look = Look {
            glyphs: Glyphs::fancy(),
            theme: theme::Theme::calm(&theme::DARK, theme::Depth::True),
            ..testkit::simple_mono()
        };
        let bob = ContactView {
            label: "Bob".into(),
            pinned: true,
            ..testkit::reachable(1)
        };
        let mut app = testkit::home_app_in(
            look,
            (140, 30),
            Receive::Off,
            vec![bob],
            Conversations::new(),
        );
        testkit::press(&mut app, KeyCode::Enter);
        let (id, _) = testkit::type_and_send(&mut app, "hi").expect("a send");
        let onion = live::Route {
            carrier: live::Carrier::Onion,
            dial: None,
            path: String::new(),
        };
        testkit::send(&mut app, testkit::sent(id, SendResult::Delivered(onion)));
        testkit::tick(&mut app, MS(1_000));
        let mut terminal = Terminal::new(TestBackend::new(140, 30)).expect("a test terminal");
        terminal
            .draw(|f| render_frame(f, &app, app.now()))
            .expect("draw");
        let buf = terminal.backend().buffer().clone();
        let rows = testkit::buffer_lines(&buf);
        let tor = look.theme.path(theme::PathKind::Tor).fg.expect("a colour");
        let colour_at = |y: usize, text: &str| {
            let x = rows[y].find(text).expect("the text");
            let x = u16::try_from(rows[y][..x].chars().count()).expect("a column");
            buf[(x, u16::try_from(y).expect("a row"))].fg
        };
        let head = rows
            .iter()
            .position(|row| row.contains("You ·") && row.contains("✓✓ Delivered · via Tor"))
            .expect("the tag");
        assert_eq!(colour_at(head, "via Tor"), tor);
        assert!(
            rows[2].contains("Bob") && rows[2].contains("via Tor"),
            "{:?}",
            rows[2]
        );
        assert_eq!(colour_at(2, "via Tor"), tor);
    }

    #[test]
    fn a_run_of_messages_from_one_sender_has_one_sender_line() {
        // Bob twice within 5 min, then you twice, then Bob 5 min later: one
        // sender line a run; yours keep their delivery line each.
        let rows = [
            (1, testkit::row(1, false, "", 20, "Are we still on?")),
            (1, testkit::row(2, false, "", 18, "For Saturday, I mean.")),
            (1, testkit::row(3, true, "delivered", 17, "Yes!")),
            (
                1,
                testkit::row(4, true, "delivered", 16, "I'll bring the map."),
            ),
            (1, testkit::row(5, false, "", 11, "Great.")),
        ];
        let app = pressed(home((100, 30), three(), &rows), &[KeyCode::Enter]);
        let text = testkit::render(&app, 100, 30)
            .iter()
            .map(|row| row.chars().skip(24).take(60).collect::<String>())
            .map(|row| row.trim_end().to_owned())
            .filter(|row| !row.is_empty())
            .collect::<Vec<_>>();
        let at = text
            .iter()
            .position(|row| row.starts_with("Bob - 20 min ago"))
            .expect("the run");
        assert_eq!(
            text[at..at + 9],
            [
                "Bob - 20 min ago",
                "  Are we still on?",
                "  For Saturday, I mean.",
                "You - 17 min ago  vv Delivered",
                "  Yes!",
                "  vv Delivered",
                "  I'll bring the map.",
                "Bob - 11 min ago",
                "  Great.",
            ]
        );
        // The chosen one says all of its header, in a run too.
        let app = pressed(app, &[KeyCode::Tab, KeyCode::Up, KeyCode::Up, KeyCode::Up]);
        let screen = testkit::screen_text(&testkit::render(&app, 100, 30));
        assert!(
            screen.contains("> Bob - 18 min ago For Saturday"),
            "{screen}"
        );
    }

    #[test]
    fn the_chosen_message_has_the_marker() {
        let app = in_state(testkit::simple_mono(), "delivered");
        let mut app = pressed(app, &[KeyCode::Tab]);
        assert_eq!(app.chosen(), Some(0));
        assert_eq!(
            newest_message(&app, app.now()),
            ["> You - just now  vv Delivered - LAN direct"]
        );
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(app.chosen(), None);
        assert_eq!(
            newest_message(&app, app.now()),
            ["You - just now  vv Delivered - LAN direct"]
        );
    }

    #[test]
    fn wrapping_breaks_after_spaces_else_between_graphemes() {
        assert_eq!(wrap_text("one two three", 7), ["one two", "three"]);
        assert_eq!(wrap_text("abcdefghij", 4), ["abcd", "efgh", "ij"]);
        assert_eq!(wrap_text("ab  cd", 3), ["ab", "cd"]);
        assert_eq!(wrap_text("a bcdef", 4), ["a", "bcde", "f"]);
        assert_eq!(wrap_text("", 5), [""]);
        // Two-cell characters never straddle the edge.
        assert_eq!(wrap_text("日本語です", 5), ["日本", "語で", "す"]);
        assert_eq!(hard_wrap("日本語", 3), ["日", "本", "語"]);
        assert_eq!(hard_wrap("", 3), [""]);
    }

    // ── live feel (UXF.10) ──────────────────────────────────────────────────

    const MS: fn(u64) -> Duration = Duration::from_millis;

    /// The header row of `app` drawn at `now`, with this computer's clock
    /// taken to be UTC (the test clock starts at 08:53:20).
    fn header_at(app: &App, now: Instant) -> String {
        let (cols, rows) = app.size();
        bridge::with_local_offset(Some(0), || testkit::render_at(app, cols, rows, now))[0].clone()
    }

    /// Whether the cell at (`x`, `y`) of `app` drawn at `now` is bold (the
    /// clock as in [`header_at`]).
    fn bold_at(app: &App, x: u16, y: u16, now: Instant) -> bool {
        let (cols, rows) = app.size();
        let mut terminal = Terminal::new(TestBackend::new(cols, rows)).expect("a test terminal");
        bridge::with_local_offset(Some(0), || terminal.draw(|f| render_frame(f, app, now)))
            .expect("draw");
        terminal.backend().buffer()[(x, y)]
            .modifier
            .contains(Modifier::BOLD)
    }

    /// Home in `look` at 80x24 with Bob, Alice and Carol, the user's own
    /// name Sam, and a background program that listens and just answered
    /// its Status.
    fn live_home(look: Look) -> App {
        let session = Session {
            settings: TuiState {
                display_name: "Sam".into(),
                ..testkit::session(Receive::On).settings
            },
            ..testkit::session(Receive::On)
        };
        let history = testkit::conversations(&chats());
        let mut app = testkit::home_app_from(look, (80, 24), session, three(), history);
        // The start it asked for (friends are saved) answered: listening.
        testkit::started_here(&mut app, 4242);
        app
    }

    /// A header row of 80 cells: `left`, and `right` at the right edge.
    fn header_row(left: &str, right: &str) -> String {
        let pad = 80 - display::width(left) - display::width(right);
        format!("{left}{}{right}", " ".repeat(pad))
    }

    #[test]
    fn the_live_header_in_every_glyph_set() {
        for (glyphs, left, right) in [
            (
                Glyphs::fancy(),
                "R A V E N · Sam",
                "♥ node ok · just now · 08:53:20 UTC",
            ),
            (
                Glyphs::simple(),
                "R A V E N - Sam",
                "+ node ok - just now - 08:53:20 UTC",
            ),
            (
                Glyphs::ascii(),
                "R A V E N - Sam",
                "+ node ok - just now - 08:53:20 UTC",
            ),
        ] {
            let look = Look {
                glyphs,
                ..testkit::simple_mono()
            };
            let mut app = live_home(look);
            assert_eq!(header_at(&app, app.now()), header_row(left, right));
            // The age and the clock count up by the second.
            testkit::tick(&mut app, Duration::from_secs(12));
            let later = header_at(&app, app.now());
            assert!(
                later.ends_with(&format!(
                    "node ok{0}12 s ago{0}08:53:32 UTC",
                    glyphs.inline_separator
                )),
                "{later:?}"
            );
            // Polls that fail: the warning chip, and no heart.
            testkit::send(&mut app, Msg::Poll(PollUpdate::Status(Probe::timed_out())));
            let failing = header_at(&app, app.now());
            assert!(
                failing.ends_with(&format!(
                    "! Not responding: press N{}08:53:32 UTC",
                    glyphs.inline_separator
                )),
                "{failing:?}"
            );
            assert!(!failing.contains(glyphs.heart), "{failing:?}");
        }
        // Without this computer's time: no clock, the rest as it was.
        let app = live_home(testkit::simple_mono());
        assert_eq!(
            testkit::render(&app, 80, 24)[0],
            header_row("R A V E N - Sam", "+ node ok - just now")
        );
    }

    #[test]
    fn the_heart_pulses_once_per_answered_poll() {
        let mut app = live_home(Look {
            glyphs: Glyphs::fancy(),
            ..testkit::simple_mono()
        });
        // The heart is the header's cell before ' node ok'.
        let heart_x = |app: &App| {
            let header = header_at(app, app.now());
            let at = header.find('♥').expect("the heart");
            u16::try_from(header[..at].chars().count()).expect("a column")
        };
        let x = heart_x(&app);
        let t0 = app.now();
        // Bright from the poll to the clock's next second, then dim.
        assert!(bold_at(&app, x, 0, t0));
        assert!(bold_at(&app, x, 0, t0 + MS(999)));
        assert!(!bold_at(&app, x, 0, t0 + MS(1000)));
        // The next poll (2 s on) beats again.
        testkit::tick(&mut app, Duration::from_secs(2));
        assert!(!bold_at(&app, x, 0, app.now()));
        testkit::send(&mut app, testkit::node_up());
        assert!(bold_at(&app, x, 0, app.now()));
        // Under reduced motion it never pulses: the age says it.
        let still = live_home(Look {
            glyphs: Glyphs::fancy(),
            motion: Motion::Reduced,
            ..testkit::simple_mono()
        });
        assert!(!bold_at(&still, x, 0, still.now()));
    }

    /// The route line's row of `app` at 100x30 drawn at `now` (inside the
    /// conversation pane), and the way the last delivery went under it (""
    /// when there is none).
    fn route_at(app: &App, now: Instant) -> [String; 2] {
        let rows: Vec<String> = testkit::render_at(app, 100, 30, now)
            .iter()
            .map(|row| row.chars().skip(24).take(74).collect::<String>())
            .map(|row| row.trim_end().to_owned())
            .collect();
        let at = rows
            .iter()
            .position(|row| row.starts_with("You *") || row.starts_with("You ●"))
            .expect("the route line");
        let label = Some(&rows[at + 1])
            .filter(|row| {
                ["LAN direct", "Internet direct", "p2p"]
                    .iter()
                    .any(|w| row.starts_with(w))
            })
            .cloned()
            .unwrap_or_default();
        [rows[at].clone(), label]
    }

    /// The route line to Friend 1 with `mark` at `cell` of its 26.
    fn line_with(mark: &str, cell: usize) -> String {
        format!(
            "You *{}{mark}{}* Friend 1",
            "-".repeat(cell),
            "-".repeat(25 - cell)
        )
    }

    #[test]
    fn a_message_travels_out_and_its_receipt_back() {
        let still = format!("You *{}* Friend 1", "-".repeat(26));
        let mut app = in_state(testkit::simple_mono(), "sending");
        let t = app.now();
        // While the send runs, '>' goes out: start, middle, end, around.
        let out: Vec<String> = [0, 400, 750, 800]
            .into_iter()
            .map(|ms| route_at(&app, t + MS(ms))[0].clone())
            .collect();
        assert_eq!(
            out,
            [
                line_with(">", 0),
                line_with(">", 13),
                line_with(">", 24),
                line_with(">", 0)
            ]
        );
        // How it went is not known yet: no label.
        assert_eq!(route_at(&app, t)[1], "");
        // The receipt: 'v' comes back, then the line rests, with the way
        // it went under it.
        testkit::tick(&mut app, MS(1_400));
        delivered_now(&mut app);
        let t2 = app.now();
        let back: Vec<String> = [0, 400, 750, 800, 5_000]
            .into_iter()
            .map(|ms| route_at(&app, t2 + MS(ms))[0].clone())
            .collect();
        assert_eq!(
            back,
            [
                line_with("v", 25),
                line_with("v", 12),
                line_with("v", 1),
                still.clone(),
                still.clone()
            ]
        );
        assert_eq!(route_at(&app, t2)[1], "LAN direct - 192.168.1.11:7420");
        // Under reduced motion nothing travels.
        let reduced = Look {
            motion: Motion::Reduced,
            ..testkit::simple_mono()
        };
        let mut app = in_state(reduced, "sending");
        let t = app.now();
        assert_eq!(route_at(&app, t + MS(400))[0], still);
        delivered_now(&mut app);
        assert_eq!(route_at(&app, app.now())[0], still);
    }

    #[test]
    fn nothing_says_delivered_before_the_receipt() {
        let still = format!("You *{}* Friend 1", "-".repeat(26));
        // Written to their computer, no receipt: no mark comes back, ever,
        // and the ticker says it is not confirmed.
        for state in ["sent", "can wait", "on hold", "not sent", "meet first"] {
            let app = in_state(testkit::simple_mono(), state);
            let t = app.now();
            for ms in [0, 100, 400, 800, 2_000] {
                let [line, label] = route_at(&app, t + MS(ms));
                assert_eq!(line, still, "{state} at {ms} ms");
                assert_eq!(label, "", "{state}: no route before a receipt");
            }
        }
        let app = in_state(testkit::simple_mono(), "sent");
        let ticker = testkit::render(&app, 100, 30)[28].clone();
        assert!(
            ticker.starts_with("Sent to Friend 1 - not confirmed yet  "),
            "{ticker:?}"
        );
        // The outbox says it went over the network but no receipt came: the
        // same.
        let mut app = in_state(testkit::simple_mono(), "connecting");
        let mut item = testkit::outbox_item(1, 1, "sent");
        item.carrier = "lan_dial".into();
        testkit::send(&mut app, testkit::outbox(vec![item.clone()]));
        assert_eq!(
            route_at(&app, app.now() + MS(400))[0].matches('v').count(),
            0
        );
        // Once the history says delivered, the receipt travels back, with
        // the way raven-node recorded.
        item.state = "delivered".into();
        testkit::send(&mut app, testkit::outbox(vec![item]));
        testkit::reload_rows(
            &mut app,
            &[(1, testkit::row(1, true, "delivered", 0, "hi"))],
        );
        assert_eq!(route_at(&app, app.now())[0], line_with("v", 25));
        assert_eq!(route_at(&app, app.now())[1], "LAN direct");
    }

    #[test]
    fn a_message_from_them_travels_in_before_it_shows() {
        let mut app = in_state(testkit::simple_mono(), "delivered");
        let still = format!("You *{}* Friend 1", "-".repeat(26));
        testkit::tick(&mut app, Duration::from_secs(5));
        testkit::reload_rows(
            &mut app,
            &[
                (1, testkit::row(1, true, "delivered", 0, "hi")),
                (1, testkit::row(2, false, "", 0, "hello back")),
            ],
        );
        let t = app.now();
        let shows = |at: Instant| {
            testkit::screen_text(&testkit::render_at(&app, 100, 30, at)).contains("hello back")
        };
        assert_eq!(route_at(&app, t)[0], line_with("<", 25));
        assert_eq!(route_at(&app, t + MS(400))[0], line_with("<", 12));
        assert!(!shows(t) && !shows(t + MS(799)));
        assert_eq!(route_at(&app, t + MS(800))[0], still);
        assert!(shows(t + MS(800)));
        // Under reduced motion it shows at once.
        let mut app = in_state(
            Look {
                motion: Motion::Reduced,
                ..testkit::simple_mono()
            },
            "delivered",
        );
        testkit::reload_rows(
            &mut app,
            &[(1, testkit::row(2, false, "", 0, "hello back"))],
        );
        assert!(testkit::screen_text(&testkit::render(&app, 100, 30)).contains("hello back"));
        assert_eq!(route_at(&app, app.now())[0], still);
        // A friend with no address has no route line: theirs shows at once.
        let mut app = home((100, 30), vec![testkit::friend(1)], NO_ROWS);
        testkit::press(&mut app, KeyCode::Enter);
        testkit::reload_rows(
            &mut app,
            &[(1, testkit::row(2, false, "", 0, "hello back"))],
        );
        let screen = testkit::screen_text(&testkit::render(&app, 100, 30));
        assert!(screen.contains("hello back"), "{screen}");
        assert!(!screen.contains("You *"), "{screen}");
    }

    #[test]
    fn a_waiting_mark_rings_when_raven_tries_again() {
        let look = Look {
            glyphs: Glyphs::fancy(),
            ..testkit::simple_mono()
        };
        let mut app = in_state(look, "can wait");
        // The waiting mark in the list, two cells in.
        let mark = |app: &App, at: Instant| {
            testkit::render_at(app, 100, 30, at)[2]
                .chars()
                .nth(3)
                .expect("the mark")
        };
        assert_eq!(mark(&app, app.now()), '◐');
        // raven-node tried it again: one more attempt, nobody there.
        let mut item = testkit::outbox_item(1, 1, "queued");
        item.attempts = 1;
        item.last_error_code = "NOT_REACHABLE".into();
        testkit::send(&mut app, testkit::outbox(vec![item]));
        let t = app.now();
        // The ring (Calm): its four frames in 900 ms, then the mark again.
        let frames: Vec<char> = [0, 225, 450, 675, 900]
            .into_iter()
            .map(|ms| mark(&app, t + MS(ms)))
            .collect();
        assert_eq!(frames, ['◌', '◎', '◉', '◎', '◐']);
        // The ticker: as much as fits beside the activity line.
        let ticker = testkit::render(&app, 100, 30)[28].clone();
        assert!(
            ticker.starts_with("Tried Friend 1 again · keeps trying until about 24 h from now  "),
            "{ticker:?}"
        );
        let (event, _) = app.live().event.as_ref().expect("an event");
        assert_eq!(
            event.texts("Friend 1", " · ", app.now_ms())[0],
            "Tried Friend 1 again · not reachable yet · keeps trying until about 24 h from now"
        );
        // The same list again is no new try.
        let item = app.live().rings.clone();
        testkit::tick(&mut app, Duration::from_secs(5));
        let mut same = testkit::outbox_item(1, 1, "queued");
        same.attempts = 1;
        testkit::send(&mut app, testkit::outbox(vec![same]));
        assert_eq!(app.live().rings, item);
        // Under reduced motion the mark stays.
        let mut still = in_state(
            Look {
                motion: Motion::Reduced,
                ..look
            },
            "can wait",
        );
        let mut more = testkit::outbox_item(1, 1, "queued");
        more.attempts = 1;
        testkit::send(&mut still, testkit::outbox(vec![more]));
        assert_eq!(mark(&still, still.now() + MS(200)), '◐');
    }

    #[test]
    fn the_ticker_names_the_latest_real_event() {
        // At 120 columns every word fits beside the activity line.
        let ticker = |app: &App, at: Instant| {
            testkit::render_at(app, 120, 30, at)[28]
                .split("  activity")
                .next()
                .unwrap_or_default()
                .trim_end()
                .to_owned()
        };
        let mut app = in_state_at(testkit::simple_mono(), (120, 30), "sending");
        assert_eq!(ticker(&app, app.now()), "Sending to Friend 1...");
        testkit::tick(&mut app, MS(1_400));
        delivered_now(&mut app);
        assert_eq!(
            ticker(&app, app.now()),
            "Delivered to Friend 1 via LAN direct in 1.4 s - receipt signed by Friend 1"
        );
        // News for 30 s, then how things stand.
        assert_eq!(
            ticker(&app, app.now() + Duration::from_secs(30)),
            "1 friend - all quiet"
        );
        // A message from them.
        testkit::reload_rows(
            &mut app,
            &[
                (1, testkit::row(1, true, "delivered", 0, "hi")),
                (1, testkit::row(2, false, "", 0, "hello back")),
            ],
        );
        assert_eq!(ticker(&app, app.now()), "New message from Friend 1");
        // At 80 columns the activity line stays and the words get shorter.
        let mut app = in_state_at(testkit::simple_mono(), (80, 24), "sending");
        testkit::tick(&mut app, MS(1_400));
        delivered_now(&mut app);
        assert_eq!(
            testkit::render(&app, 80, 24)[22],
            "Delivered to Friend 1 - receipt signed by ...  activity ........................"
        );
        // Listening and a message waiting.
        let app = in_state_at(testkit::simple_mono(), (120, 30), "can wait");
        assert_eq!(
            ticker(&app, app.now() + Duration::from_secs(60)),
            "Listening on your network - 1 friend - 1 message waiting for Friend 1"
        );
    }

    #[test]
    fn rows_blink_with_news_and_in_touch_marks_breathe() {
        let mut app = in_state(testkit::simple_mono(), "sending");
        // Friend 1's name in the list starts at column 5 of row 2.
        let lit = |app: &App, ms: u64| bold_at(app, 5, 2, app.now() + MS(ms));
        assert!(!lit(&app, 0), "no news yet");
        delivered_now(&mut app);
        testkit::reload_rows(
            &mut app,
            &[(1, testkit::row(1, true, "delivered", 0, "hi"))],
        );
        // On, off, on, then still.
        assert_eq!(
            [lit(&app, 0), lit(&app, 200), lit(&app, 400), lit(&app, 600)],
            [true, false, true, false]
        );
        // In touch now: the mark breathes (Calm), bright for 1.5 s from
        // the delivery, then quiet (dim in mono) for 1.5 s.
        let dim_at = |app: &App, ms: u64| {
            let (cols, rows) = app.size();
            let mut terminal =
                Terminal::new(TestBackend::new(cols, rows)).expect("a test terminal");
            terminal
                .draw(|f| render_frame(f, app, app.now() + MS(ms)))
                .expect("draw");
            terminal.backend().buffer()[(3, 2)]
                .modifier
                .contains(Modifier::DIM)
        };
        assert_eq!(
            [0, 1_499, 1_500, 2_999, 3_000].map(|ms| dim_at(&app, ms)),
            [false, false, true, true, false]
        );
        // anim.rs wakes for each breath; none under reduced motion.
        assert!(moving(&app).contains(&Moving::Steps {
            since: app.now(),
            every: BREATHE
        }));
        let mut still = app.clone();
        still.set_look_for_tests(Look {
            motion: Motion::Reduced,
            ..*app.look()
        });
        assert!(!dim_at(&still, 1_500));
    }
}
