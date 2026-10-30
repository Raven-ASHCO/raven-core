//! Small pieces every screen draws the same way: the node chip, a friend's
//! dot, a delivery tick, the spinner and the key bar. Each takes the look
//! (glyphs, theme, motion) and the time, never the App, and returns spans
//! with only the app's own text in them.
//!
//! Colour never carries meaning alone: every state has its glyph and words.
//! Green is for this computer's chip when it listens, a friend in touch and
//! what was delivered (Calm).

use std::time::{Duration, Instant};

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear};
use ratatui::Frame;

use super::live::Route;
#[cfg(test)]
use super::testkit;
use super::theme::{self, Motion, PathKind};
use super::{anim, cells, Look};

// ── Boxes, the background and keys (Calm) ──────────────────────────────────

/// A box in the glyph set's border: faint, or dim with a bold title while
/// it has the keys (`focused`).
pub(super) fn pane(look: &Look, focused: bool) -> Block<'static> {
    let t = &look.theme;
    Block::bordered()
        .border_set(look.glyphs.border)
        .border_style(if focused { t.focus } else { t.faint })
        .title_style(if focused { t.title } else { t.secondary })
}

/// A screen's box (Calm): faint, its title bold.
pub(super) fn screen_box(look: &Look) -> Block<'static> {
    let t = &look.theme;
    Block::bordered()
        .border_set(look.glyphs.border)
        .border_style(t.faint)
        .title_style(t.title)
}

/// A title for [`pane`]: bold while the box has the keys, dim otherwise.
pub(super) fn pane_title(look: &Look, title: &str, focused: bool) -> Span<'static> {
    let t = &look.theme;
    Span::styled(
        title.to_owned(),
        if focused { t.title } else { t.secondary },
    )
}

/// Every cell of `area` to the theme's background and text colour: a
/// palette's own background under everything (nothing without one).
pub(super) fn paint(buf: &mut Buffer, area: Rect, look: &Look) {
    if look.theme.paints() {
        buf.set_style(area, look.theme.base);
    }
}

/// `area` emptied for a box drawn over the screen, in the theme's
/// background.
pub(super) fn clear(f: &mut Frame, area: Rect, look: &Look) {
    f.render_widget(Clear, area);
    paint(f.buffer_mut(), area, look);
}

/// The screen behind an overlay, quietened: in a palette every cell in the
/// faint colour on the background, so the overlay stands out. The terminal's
/// own colours and none leave it as it is.
pub(super) fn shade(buf: &mut Buffer, area: Rect, look: &Look) {
    let t = &look.theme;
    if !t.paints() {
        return;
    }
    let area = area.intersection(buf.area);
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let cell = &mut buf[(x, y)];
            cell.modifier = Modifier::empty();
            cell.set_style(t.faint);
            if let Some(bg) = t.base.bg {
                cell.bg = bg;
            }
        }
    }
}

/// A key as the hints draw it: in a palette a chip, the key between a space
/// each side on the key colour, standing in for its brackets ('[Enter]' and
/// ' Enter ' are as wide); elsewhere the key as written, in the key style.
pub(super) fn key(look: &Look, key: &str) -> Span<'static> {
    let t = &look.theme;
    if !t.chips {
        return Span::styled(key.to_owned(), t.key);
    }
    let inner = key
        .strip_prefix('[')
        .and_then(|k| k.strip_suffix(']'))
        .unwrap_or(key);
    Span::styled(format!(" {inner} "), t.key)
}

/// What a key does, after [`key`] (the words start with their gap): dim a
/// space after a chip, plain otherwise.
pub(super) fn key_words(look: &Look, words: &str) -> Span<'static> {
    if look.theme.chips {
        Span::styled(format!(" {}", words.trim_start()), look.theme.secondary)
    } else {
        Span::raw(words.to_owned())
    }
}

// ── Paths, deliveries and waiting (reusable: a group's view draws them too) ─

/// The kind of path `route` went by, for its colour (tokens:
/// `color.pathRule`): a hole punched is the internet's own colour, other
/// peer-to-peer paths the relays'.
pub(super) fn path_kind(route: &Route) -> PathKind {
    route.kind()
}

/// A path tag: how a message went, in words ('LAN direct', 'p2p
/// (relayed)'), in its path's colour.
pub(super) fn path_tag(look: &Look, route: &Route) -> Span<'static> {
    Span::styled(route.words(), look.theme.path(path_kind(route)))
}

/// How a message came or went as raven-node says it ('via Tor', 'LAN
/// direct', 'from a keeper'), in its path's colour.
pub(super) fn arrived_tag(look: &Look, via: raven_core::arrivals::ArrivedVia) -> Span<'static> {
    match Route::of_arrived(via) {
        Some(route) => path_tag(look, &route),
        None => Span::styled(via.phrase(), look.theme.path(PathKind::Friend)),
    }
}

/// Delivered typing itself once its receipt came (`since`: when this app saw
/// it; None when it was so already): the label types itself a character
/// every 45 ms ([`theme::DELIVERED_CHAR`]) for 'Delivered', with the sent
/// mark for its first two; what follows 'Delivered' (when a late delivery
/// came) shows once it is typed. Nothing moves under reduced motion.
/// Returns the mark and the part of `label` showing, both as drawn.
pub(super) fn delivered_typing(
    look: &Look,
    label: &str,
    since: Option<Instant>,
    now: Instant,
) -> (Span<'static>, String) {
    let g = &look.glyphs;
    let done = (
        Span::styled(g.tick_delivered, look.theme.ok),
        label.to_owned(),
    );
    let Some(start) = since else {
        return done;
    };
    let frame = anim::transition_frame(start, now, DELIVERED_FRAMES, DELIVERED_TYPING, look.motion);
    if frame >= DELIVERED_FRAMES {
        return done;
    }
    let mark = if frame < DELIVERED_SENT_FRAMES {
        // The sent mark, as wide as the delivered one.
        let pad = cells(g.tick_delivered).saturating_sub(cells(g.tick_sent));
        Span::styled(format!("{}{}", g.tick_sent, " ".repeat(pad)), look.theme.ok)
    } else {
        done.0
    };
    let shown = label
        .chars()
        .take(usize::try_from(frame).unwrap_or(0))
        .collect();
    (mark, shown)
}

/// Delivered types its word: one frame a character.
pub(super) const DELIVERED_FRAMES: u32 = DELIVERED_WORD.len() as u32;
/// The word that types itself.
const DELIVERED_WORD: &str = "Delivered";
/// Of those frames, the ones that still show the sent mark.
const DELIVERED_SENT_FRAMES: u32 = 2;
/// How long Delivered takes to type itself.
pub(super) const DELIVERED_TYPING: Duration =
    Duration::from_millis(theme::DELIVERED_CHAR.as_millis() as u64 * DELIVERED_WORD.len() as u64);

/// After a waiting message's label, what raven-node's outbox says of its
/// last try: friends hold a sealed copy (`in_custody` of them; the outbox
/// doesn't say which), or nobody was there to reach. None when it says
/// neither.
pub(super) fn waiting_note(
    look: &Look,
    in_custody: u8,
    unreachable: bool,
) -> Option<Span<'static>> {
    let t = &look.theme;
    match (in_custody, unreachable) {
        (0, false) => None,
        (0, true) => Some(Span::styled(NOT_REACHABLE_YET, t.secondary)),
        (1, _) => Some(Span::styled(HELD_BY_A_FRIEND, t.path(PathKind::Friend))),
        (n, _) => Some(Span::styled(
            format!("held by {n} friends"),
            t.path(PathKind::Friend),
        )),
    }
}

/// [`waiting_note`]'s words.
const NOT_REACHABLE_YET: &str = "not reachable yet";
const HELD_BY_A_FRIEND: &str = "held by a friend";

/// A conversation's day line, `label` centred on a faint rule `width`
/// cells wide: '─── Today ───'.
pub(super) fn day_line(look: &Look, label: &str, width: u16) -> Line<'static> {
    let t = &look.theme;
    let rule = look.glyphs.border.horizontal_top;
    let label = format!(" {label} ");
    let left = usize::from(width).saturating_sub(cells(&label)) / 2;
    let right = usize::from(width).saturating_sub(left + cells(&label));
    Line::from(vec![
        Span::styled(rule.repeat(left), t.faint),
        Span::styled(label, t.secondary),
        Span::styled(rule.repeat(right), t.faint),
    ])
}

/// The bar in front of each line of your own messages, where the theme
/// draws it: the accent colour, the warning's while it waits. None without
/// decoration (the indent stays).
pub(super) fn own_bar(look: &Look, waiting: bool) -> Option<Span<'static>> {
    let t = &look.theme;
    t.decor.then(|| {
        Span::styled(
            format!("{} ", look.glyphs.own),
            if waiting { t.warn } else { t.accent },
        )
    })
}

/// The in-touch mark's breath at `now_ms` for one in touch since `at_ms`
/// (both on the wall clock): bright, then quiet, each for 1.5 s
/// ([`theme::BREATHE`]). Always bright under reduced motion.
pub(super) fn breath_bright(at_ms: u64, now_ms: u64, motion: Motion) -> bool {
    let every = u64::try_from(theme::BREATHE.as_millis())
        .unwrap_or(1)
        .max(1);
    motion == Motion::Reduced || (now_ms.saturating_sub(at_ms) / every).is_multiple_of(2)
}

/// The node chip on Home's header row: what this computer's background
/// program is doing. The App picks it, anim.rs spins it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Chip {
    /// Listening on the network, on `port` (None: an older node that does
    /// not say).
    Listening {
        port: Option<u16>,
    },
    /// Listening on this computer only (a loopback address).
    LocalOnly,
    SendOnly,
    /// Running, but the address it is set to listen on isn't on this
    /// computer now.
    AddressNotHere,
    /// This computer has no address but loopback.
    NotOnAnyNetwork,
    /// Being started since `since`: the chip spins.
    Starting {
        since: Instant,
    },
    NotRunning,
    /// Receiving is on, and the program starts with the first friend.
    StartsWithFirstFriend,
    ReceiveOff,
    /// A vault profile without a passphrase file (PASSFILE).
    NeedsSetup,
    NotResponding,
    /// Blocked on a Keychain dialog (KC).
    WaitingForPermission,
    /// raven-node can't open the friends list (privacy pack PP.21): its
    /// at-rest key is unavailable, or it waits for the keychain.
    LockedOut,
}

/// The chip: a mark and a few words, e.g. '● Listening on port 7420'.
pub(super) fn chip(chip: Chip, look: &Look, now: Instant) -> Line<'static> {
    let (g, t) = (&look.glyphs, &look.theme);
    let (mark, words, style): (Span<'static>, String, Style) = match chip {
        Chip::Listening { port } => (
            Span::styled(g.dot_on, t.ok),
            port.map_or_else(
                || "Listening".to_owned(),
                |port| format!("Listening on port {port}"),
            ),
            t.ok,
        ),
        Chip::LocalOnly => (
            Span::raw(g.dot_half),
            "Receiving on this computer only".to_owned(),
            Style::default(),
        ),
        Chip::SendOnly => (
            Span::raw(g.dot_half),
            "Sending only, not receiving".to_owned(),
            Style::default(),
        ),
        Chip::AddressNotHere => (
            Span::styled(g.dot_off, t.secondary),
            "Not receiving (address not here)".to_owned(),
            t.secondary,
        ),
        Chip::NotOnAnyNetwork => (
            Span::styled(g.dot_off, t.secondary),
            "Not on any network".to_owned(),
            t.secondary,
        ),
        Chip::Starting { since } => (
            spinner(look, since, now),
            format!("Starting Raven{}", g.ellipsis),
            Style::default(),
        ),
        Chip::NotRunning => (
            Span::styled(g.dot_off, t.secondary),
            "Not running".to_owned(),
            t.secondary,
        ),
        Chip::StartsWithFirstFriend => (
            Span::styled(g.dot_off, t.secondary),
            "Starts when you add a friend".to_owned(),
            t.secondary,
        ),
        Chip::ReceiveOff => (
            Span::styled(g.dot_off, t.secondary),
            "Receiving is off".to_owned(),
            t.secondary,
        ),
        Chip::NeedsSetup => (
            Span::styled(g.dot_alert, t.warn),
            "Needs setup: press N".to_owned(),
            t.warn,
        ),
        Chip::NotResponding => (
            Span::styled(g.dot_alert, t.warn),
            "Not responding: press N".to_owned(),
            t.warn,
        ),
        Chip::WaitingForPermission => (
            Span::styled(g.dot_alert, t.warn),
            "Waiting for permission".to_owned(),
            t.warn,
        ),
        Chip::LockedOut => (
            Span::styled(g.dot_off, t.warn),
            "Locked out of your friends list".to_owned(),
            t.warn,
        ),
    };
    Line::from(vec![mark, Span::raw(" "), Span::styled(words, style)])
}

/// A friend's mark in the list, by presence.rs's rules (HELP explains each).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Dot {
    /// In touch in the last 15 minutes, since Raven was opened.
    Recent,
    /// Some of your messages haven't reached them yet.
    Waiting,
    /// No recent contact (Raven has no online indicator).
    Quiet,
    /// Raven doesn't know where to reach them.
    NoAddress,
}

/// The dot (Calm): in touch in the colour of things that worked, waiting in
/// the warning's, quiet faint. The glyph says it too.
pub(super) fn dot(dot: Dot, look: &Look) -> Span<'static> {
    let (g, t) = (&look.glyphs, &look.theme);
    match dot {
        Dot::Recent => Span::styled(g.dot_recent, t.ok),
        Dot::Waiting => Span::styled(g.dot_half, t.warn),
        Dot::Quiet => Span::styled(g.dot_off, t.faint),
        Dot::NoAddress => Span::styled(g.dot_none, t.warn),
    }
}

/// The selected row's marker: the accent bar where the theme has a
/// selection colour, else the '>' marker.
pub(super) fn marker(look: &Look) -> Span<'static> {
    let (g, t) = (&look.glyphs, &look.theme);
    if t.paints() {
        Span::styled(g.bar, t.accent)
    } else {
        Span::raw(g.selected)
    }
}

/// The mark in front of a message's delivery label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TickMark {
    /// Sending or connecting, since `since`.
    Spinner { since: Instant },
    /// Waiting, or on hold: Raven keeps trying.
    Waiting,
    /// It left this computer, not confirmed yet.
    Sent,
    /// Their Raven confirmed it.
    Delivered,
    /// Not delivered, not confirmed or not sent.
    Failed,
}

/// The tick: green when delivered, the warning's colour while it waits, red
/// when not; colour is never alone in saying so (the label follows).
pub(super) fn tick(mark: TickMark, look: &Look, now: Instant) -> Span<'static> {
    let (g, t) = (&look.glyphs, &look.theme);
    match mark {
        TickMark::Spinner { since } => spinner(look, since, now),
        TickMark::Waiting => Span::styled(g.tick_waiting, t.warn),
        TickMark::Sent => Span::styled(g.tick_sent, t.secondary),
        TickMark::Delivered => Span::styled(g.tick_delivered, t.ok),
        TickMark::Failed => Span::styled(g.tick_failed, t.bad),
    }
}

/// The style of a tick's label: as its mark, the spinner's accent while it
/// sends.
pub(super) fn tick_label_style(mark: TickMark, look: &Look) -> Style {
    let t = &look.theme;
    match mark {
        TickMark::Spinner { .. } => t.accent,
        TickMark::Waiting => t.warn,
        TickMark::Sent => t.secondary,
        TickMark::Delivered => t.ok,
        TickMark::Failed => t.bad,
    }
}

/// The spinner's frame at `now` for one turning since `since`; a still
/// ellipsis under reduced motion. The screen that draws one lists it in
/// `anim::moving`, so the UI wakes for its next frame.
pub(super) fn spinner(look: &Look, since: Instant, now: Instant) -> Span<'static> {
    let frame = anim::spinner_frame(since, now, look.spinner_interval);
    Span::styled(
        look.glyphs.spinner_frame(look.motion, frame),
        look.theme.accent,
    )
}

/// Key hints in priority order, '? Help · Q Quit · …': each key in the
/// accent style and its action dimmed, with the glyph set's separator. Hints
/// that do not fit in `width` cells are dropped from the right; the first
/// one always stays.
/// The header's security chip (P6.31): the alarm mark and how many alerts
/// and warnings are open ('⚠ 2'; ASCII '!2'). Bold in every theme, and it
/// never moves; None while none is open.
pub(super) fn alarm_chip(look: &Look, open: usize) -> Option<Span<'static>> {
    if open == 0 {
        return None;
    }
    let mark = look.glyphs.alarm;
    let gap = if mark.is_ascii() { "" } else { " " };
    Some(Span::styled(format!("{mark}{gap}{open}"), look.theme.warn))
}

pub(super) fn key_bar(
    look: &Look,
    hints: &[(&'static str, &'static str)],
    width: u16,
) -> Line<'static> {
    let (g, t) = (&look.glyphs, &look.theme);
    let width = usize::from(width);
    // In a palette each key is a chip, a space each side, and the hints
    // stand apart by the chips alone.
    let (separator, pad) = if t.chips {
        (CHIP_GAP, 2)
    } else {
        (g.separator, 0)
    };
    let mut shown = 0;
    let mut used = 0;
    for (key, action) in hints {
        let hint = cells(key) + pad + 1 + cells(action);
        let more = if shown == 0 {
            hint
        } else {
            cells(separator) + hint
        };
        if shown > 0 && used + more > width {
            break;
        }
        used += more;
        shown += 1;
    }
    let mut spans = Vec::new();
    for (i, (key, action)) in hints[..shown].iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(separator, t.secondary));
        }
        if t.chips {
            spans.push(Span::styled(format!(" {key} "), t.key));
        } else {
            spans.push(Span::styled(*key, t.accent));
        }
        spans.push(Span::styled(format!(" {action}"), t.secondary));
    }
    Line::from(spans)
}

/// Between two hints whose keys are chips.
const CHIP_GAP: &str = "  ";

#[cfg(test)]
mod tests {
    use super::*;

    use theme::{Glyphs, Theme};

    /// The text of `line`, styles dropped.
    fn text(line: &Line) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    fn fancy() -> Look {
        Look {
            glyphs: Glyphs::fancy(),
            ..testkit::simple_mono()
        }
    }

    /// Home's hints with Friends focused, in HOME's priority order.
    fn friends_hints(look: &Look) -> Vec<(&'static str, &'static str)> {
        vec![
            ("?", "Help"),
            ("Q", "Quit"),
            (look.glyphs.up_down, "Choose"),
            ("Enter", "Open"),
            ("A", "Add"),
            ("V", "Verify"),
            ("E", "Friend page"),
            ("N", "Network"),
            ("S", "Settings"),
        ]
    }

    #[test]
    fn the_key_bar_drops_hints_from_the_right_to_fit() {
        let fancy = fancy();
        let all = friends_hints(&fancy);
        let bar = |width| text(&key_bar(&fancy, &all, width));
        assert_eq!(
            bar(100),
            "? Help · Q Quit · ↑↓ Choose · Enter Open · A Add · V Verify · E Friend page · \
             N Network · S Settings"
        );
        assert_eq!(
            bar(80),
            "? Help · Q Quit · ↑↓ Choose · Enter Open · A Add · V Verify · E Friend page"
        );
        assert_eq!(
            bar(60),
            "? Help · Q Quit · ↑↓ Choose · Enter Open · A Add · V Verify"
        );
        let simple = testkit::simple_mono();
        let bar = |width| text(&key_bar(&simple, &friends_hints(&simple), width));
        assert_eq!(
            bar(100),
            "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page  \
             N Network  S Settings"
        );
        assert_eq!(
            bar(80),
            "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page"
        );
        assert_eq!(
            bar(60),
            "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify"
        );
    }

    #[test]
    fn the_key_bar_always_keeps_help_and_quit() {
        for look in testkit::every_look() {
            let hints = friends_hints(&look);
            let two = format!("? Help{}Q Quit", look.glyphs.separator);
            for width in cells(&two) as u16..=120 {
                let bar = key_bar(&look, &hints, width);
                let got = text(&bar);
                assert!(got.starts_with(&two), "{width}: {got:?}");
                assert!(bar.width() <= usize::from(width), "{width}: {got:?}");
                // A prefix of the hints: none is skipped in the middle.
                let kept = got.split(look.glyphs.separator).count();
                let full: Vec<String> = hints[..kept]
                    .iter()
                    .map(|(key, action)| format!("{key} {action}"))
                    .collect();
                assert_eq!(got, full.join(look.glyphs.separator));
            }
        }
        // Narrower than two hints: the first stays, clipped by the frame.
        let look = testkit::simple_mono();
        let hints = friends_hints(&look);
        assert_eq!(text(&key_bar(&look, &hints, 13)), "? Help");
        assert_eq!(text(&key_bar(&look, &hints, 0)), "? Help");
        assert_eq!(text(&key_bar(&look, &[], 80)), "");
    }

    #[test]
    fn chips_say_what_the_background_program_does() {
        let t0 = Instant::now();
        let fancy = fancy();
        let simple = testkit::simple_mono();
        let cases = [
            (
                Chip::Listening { port: Some(7420) },
                "● Listening on port 7420",
                "* Listening on port 7420",
            ),
            (Chip::Listening { port: None }, "● Listening", "* Listening"),
            (
                Chip::LocalOnly,
                "◐ Receiving on this computer only",
                "~ Receiving on this computer only",
            ),
            (
                Chip::SendOnly,
                "◐ Sending only, not receiving",
                "~ Sending only, not receiving",
            ),
            (
                Chip::AddressNotHere,
                "○ Not receiving (address not here)",
                "o Not receiving (address not here)",
            ),
            (
                Chip::NotOnAnyNetwork,
                "○ Not on any network",
                "o Not on any network",
            ),
            (
                Chip::Starting { since: t0 },
                "⠋ Starting Raven…",
                "| Starting Raven...",
            ),
            (Chip::NotRunning, "○ Not running", "o Not running"),
            (
                Chip::StartsWithFirstFriend,
                "○ Starts when you add a friend",
                "o Starts when you add a friend",
            ),
            (Chip::ReceiveOff, "○ Receiving is off", "o Receiving is off"),
            (
                Chip::NeedsSetup,
                "! Needs setup: press N",
                "! Needs setup: press N",
            ),
            (
                Chip::NotResponding,
                "! Not responding: press N",
                "! Not responding: press N",
            ),
            (
                Chip::WaitingForPermission,
                "! Waiting for permission",
                "! Waiting for permission",
            ),
            (
                Chip::LockedOut,
                "○ Locked out of your friends list",
                "o Locked out of your friends list",
            ),
        ];
        for (c, want_fancy, want_simple) in cases {
            assert_eq!(text(&chip(c, &fancy, t0)), want_fancy);
            assert_eq!(text(&chip(c, &simple, t0)), want_simple);
        }
    }

    #[test]
    fn green_is_for_listening_and_being_in_touch() {
        let t0 = Instant::now();
        let look = Look {
            theme: Theme::color(),
            ..testkit::simple_mono()
        };
        let green = |line: &Line| line.spans.iter().any(|s| s.style == look.theme.ok);
        assert!(green(&chip(
            Chip::Listening { port: Some(7420) },
            &look,
            t0
        )));
        for c in [
            Chip::LocalOnly,
            Chip::SendOnly,
            Chip::AddressNotHere,
            Chip::NotOnAnyNetwork,
            Chip::Starting { since: t0 },
            Chip::NotRunning,
            Chip::StartsWithFirstFriend,
            Chip::ReceiveOff,
            Chip::NeedsSetup,
            Chip::NotResponding,
            Chip::WaitingForPermission,
            Chip::LockedOut,
        ] {
            assert!(!green(&chip(c, &look, t0)), "{c:?}");
        }
        // Calm: a friend in touch is green too; the mark says it as well.
        assert_eq!(dot(Dot::Recent, &look).style, look.theme.ok);
        for d in [Dot::Waiting, Dot::Quiet, Dot::NoAddress] {
            assert_ne!(dot(d, &look).style, look.theme.ok, "{d:?}");
        }
    }

    #[test]
    fn dots_and_ticks_use_the_glyph_set() {
        let t0 = Instant::now();
        let marks = |look: &Look| {
            let mut out: Vec<String> = [Dot::Recent, Dot::Waiting, Dot::Quiet, Dot::NoAddress]
                .into_iter()
                .map(|d| dot(d, look).content.into_owned())
                .collect();
            out.extend(
                [
                    TickMark::Spinner { since: t0 },
                    TickMark::Waiting,
                    TickMark::Sent,
                    TickMark::Delivered,
                    TickMark::Failed,
                ]
                .into_iter()
                .map(|m| tick(m, look, t0).content.into_owned()),
            );
            out
        };
        assert_eq!(
            marks(&fancy()),
            ["●", "◐", "○", "✕", "⠋", "~", "✓", "✓✓", "✗"]
        );
        assert_eq!(
            marks(&testkit::simple_mono()),
            ["*", "~", "o", "x", "|", "~", "v", "vv", "x"]
        );
    }

    #[test]
    fn the_spinner_turns_with_the_clock_unless_motion_is_reduced() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let frames = |look: &Look| -> Vec<String> {
            [t0, t0 + ms(83), t0 + ms(166)]
                .into_iter()
                .map(|now| spinner(look, t0, now).content.into_owned())
                .collect()
        };
        assert_eq!(frames(&fancy()), ["⠋", "⠙", "⠹"]);
        assert_eq!(frames(&testkit::simple_mono()), ["|", "/", "-"]);
        let reduced = Look {
            motion: Motion::Reduced,
            ..fancy()
        };
        assert_eq!(frames(&reduced), ["…", "…", "…"]);
        // Over SSH a frame lasts 166 ms.
        let ssh = Look {
            spinner_interval: ms(166),
            ..testkit::simple_mono()
        };
        assert_eq!(frames(&ssh), ["|", "|", "/"]);
    }
}
