//! Pure render functions: [`render`] draws the whole screen from the
//! [`App`] and the time, and reads nothing else.
//!
//! Files under ui/ reach the rest of tui through the imports here: a
//! `super::super` path is reserved for bridge.rs (testkit's scan).

pub(super) mod add_friend;
pub(super) mod groups;
pub(super) mod home;
pub(super) mod lock;
pub(super) mod meet;
pub(super) mod network;
pub(super) mod overlays;
pub(super) mod security;
pub(super) mod settings;
pub(super) mod updates;
pub(super) mod verify;
pub(super) mod widgets;
pub(super) mod wizard;

use std::time::Instant;

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::anim;
use super::app::{self, App, Look, Overlay, Screen};
use super::controller;
use super::delivery;
use super::display;
#[cfg(test)]
use super::gate;
use super::node;
use super::state_file;
#[cfg(test)]
use super::testkit;
use super::theme;
#[cfg(test)]
use super::workers;
use super::{bridge, errors, live, logo, presence};

/// SMALL's keys, on one row: the classic menu works in any window.
const SMALL_KEYS: [(&str, &str); 2] = [("[C]", " Classic menu  "), ("[Q]", " Quit")];

/// Draws the screen, then each overlay over it, then the toast on the
/// bottom row. A window below the smallest size shows SMALL instead of the
/// screen and its overlays.
pub(super) fn render(f: &mut Frame, app: &App, now: Instant) {
    let area = f.area();
    let look = app.look();
    // A palette's own background under everything (Calm).
    widgets::paint(f.buffer_mut(), area, look);
    // By the frame's size: the App's, unless a resize is still on its way.
    if app::too_small(area.width, area.height) {
        render_small(f, area, look);
    } else {
        match app.screen() {
            Screen::Wizard(step) => wizard::render(f, area, app, step, now),
            Screen::IdentityError(failure) => {
                wizard::render_identity_error(f, area, app, failure, now)
            }
            Screen::Home => home::render(f, area, app, now),
            Screen::AddFriend(add) => add_friend::render(f, area, app, add, now),
            Screen::NameClash(clash) => add_friend::render_clash(f, area, app, clash, now),
            Screen::Verify(_) => verify::render(f, area, app, now),
            Screen::Added(added) => verify::render_added(f, area, app, added, now),
            Screen::FriendPage(page) => verify::render_page(f, area, app, page, now),
            Screen::Network(net) => network::render(f, area, app, net, now),
            Screen::Meet(guide) => meet::render(f, area, app, guide, now),
            Screen::Settings(set) => settings::render(f, area, app, set, now),
        }
        // Behind an overlay the screen goes quiet (Calm).
        if !app.overlays().is_empty() {
            widgets::shade(f.buffer_mut(), area, look);
        }
        for overlay in app.overlays() {
            match overlay {
                Overlay::Help { scroll } => {
                    let privacy = app.privacy().is_some();
                    let groups = app.groups_live();
                    overlays::render_help(f, area, look, app.screen(), (privacy, groups), *scroll)
                }
                Overlay::Quit => overlays::render_quit(f, area, app, now),
                Overlay::Receive(rx) => {
                    overlays::render_receive(f, area, look, *rx, app.receive_port());
                }
                Overlay::Unlock => overlays::render_unlock(f, area, look),
                Overlay::Keychain => {
                    if let Some(kc) = app.keychain() {
                        overlays::render_keychain(f, area, look, kc, app.over_ssh(), now);
                    }
                }
                Overlay::PassFile => {
                    overlays::render_passfile(f, area, look, app.passphrase_saved())
                }
                Overlay::Firewall => {
                    let rule = app
                        .on_windows()
                        .then(|| bridge::internet_firewall_hint(&app.firewall_port().to_string()));
                    overlays::render_firewall(f, area, look, rule.as_deref());
                }
                Overlay::NetworkNote => overlays::render_network_note(f, area, look),
                Overlay::Message(view) => overlays::render_message(f, area, app, view),
                Overlay::Confirm(confirm) => {
                    overlays::render_confirm(f, area, app, &confirm.peer, &confirm.action)
                }
                Overlay::Lock(step) => overlays::render_lock(f, area, app, step, now),
                Overlay::KeepChats { choice } => {
                    overlays::render_keep_chats(f, area, look, *choice)
                }
                Overlay::DeleteChat { peer, typed } => {
                    overlays::render_delete_chat(f, area, app, peer, typed)
                }
                Overlay::ForgetAddress { peer } => {
                    overlays::render_forget_address(f, area, app, peer)
                }
                Overlay::PrivacyNotice(notice) => {
                    overlays::render_privacy_notice(f, area, app, *notice)
                }
                Overlay::Erase(erase) => overlays::render_erase(f, area, app, erase, now),
                Overlay::Security(sec) => security::render(f, area, app, *sec),
                Overlay::Locked(view) => lock::render_locked(f, area, app, view),
                Overlay::Passphrase(pass) => lock::render_passphrase(f, area, app, pass),
                Overlay::Updates(upd) => updates::render(f, area, app, upd),
                Overlay::Group(group) => groups::render_overlay(f, area, app, group),
            }
        }
    }
    // Drawn only within its time, even before an update takes it away.
    if let Some(toast) = app
        .toast()
        .filter(|toast| toast.until().is_some_and(|until| now < until))
    {
        overlays::render_toast(f, area, look, toast);
    }
}

/// Where the header says the user is (Calm): 'R A V E N · Settings'.
fn header_context(screen: &Screen) -> Option<&'static str> {
    match screen {
        Screen::AddFriend(_) | Screen::NameClash(_) | Screen::Added(_) => Some("Add a friend"),
        Screen::Verify(_) => Some("Security words"),
        Screen::FriendPage(_) => Some("Friend page"),
        Screen::Network(_) => Some("Network"),
        Screen::Meet(_) => Some("Meet without the internet"),
        Screen::Settings(_) => Some("Settings"),
        Screen::Wizard(_) | Screen::IdentityError(_) | Screen::Home => None,
    }
}

/// The header row: the wordmark and where the user is ('R A V E N ·
/// Network') on the left, but on the welcome (its card has the wordmark);
/// on the right the security chip while an alert or a warning is open
/// (P6.31), the node chip once it is known and, with `help`, the help key.
/// Home draws its own, live one (home.rs, UXF.10).
fn render_header(f: &mut Frame, area: Rect, app: &App, now: Instant, help: bool) {
    let look = app.look();
    let header = Rect { height: 1, ..area };
    let mut right = Vec::new();
    if let Some(alarm) = widgets::alarm_chip(look, app.notices().len()) {
        right.push(alarm);
        right.push(Span::styled(look.glyphs.separator, look.theme.secondary));
    }
    if let Some(chip) = app.chip() {
        right.extend(widgets::chip(chip, look, now).spans);
        if help {
            right.push(Span::styled(look.glyphs.separator, look.theme.secondary));
        }
    }
    if help {
        right.extend(widgets::key_bar(look, &[("?", "Help")], area.width).spans);
    }
    let right = Line::from(right);
    let mut left = Vec::new();
    if !matches!(
        app.screen(),
        Screen::Wizard(app::WizardStep::Welcome { .. })
    ) {
        left.push(Span::styled(logo::WORDMARK, look.theme.title));
        // Where the user is, while it fits whole beside the right side.
        let room = usize::from(area.width).saturating_sub(right.width() + 1);
        if let Some(context) = header_context(app.screen())
            .map(|context| format!("{}{context}", look.glyphs.inline_separator))
        {
            if cells(logo::WORDMARK) + cells(&context) <= room {
                left.push(Span::styled(context, look.theme.secondary));
            }
        }
    }
    f.render_widget(Paragraph::new(Line::from(left)), header);
    f.render_widget(Paragraph::new(right).right_aligned(), header);
}

/// SMALL: what size Raven needs and the window has now, wrapped, then C and
/// Q, centred as one block. When even that does not fit, the keys stay and
/// the sentence is cut.
fn render_small(f: &mut Frame, area: Rect, look: &Look) {
    if area.is_empty() {
        return;
    }
    let text = format!(
        "Raven needs a bigger window: at least {} columns by {} rows (now {} by {}).",
        app::MIN_COLS,
        app::MIN_ROWS,
        area.width,
        area.height
    );
    let mut lines: Vec<Line> = wrap(&text, area.width, 0)
        .into_iter()
        .map(Line::raw)
        .collect();
    let room = usize::from(area.height);
    lines.truncate(room - 1);
    if lines.len() + 2 <= room {
        lines.push(Line::default());
    }
    let mut keys = Vec::new();
    for (key, action) in SMALL_KEYS {
        keys.push(widgets::key(look, key));
        keys.push(widgets::key_words(look, action));
    }
    lines.push(Line::from(keys));
    let width = lines.iter().map(Line::width).max().unwrap_or(0);
    let width = u16::try_from(width).unwrap_or(u16::MAX).min(area.width);
    let height = u16::try_from(lines.len()).unwrap_or(u16::MAX);
    let block = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    };
    f.render_widget(Paragraph::new(lines), block);
}

/// The app's own copy in rows of at most `width` cells, broken at spaces.
/// Rows after the first start with `indent` spaces. A word wider than a row
/// stays whole (drawing clips it): the copy has none.
fn wrap(text: &str, width: u16, indent: u16) -> Vec<String> {
    let (width, indent) = (usize::from(width), usize::from(indent));
    let mut rows = Vec::new();
    let mut row = String::new();
    // Cells used in `row`, and how many of them are its indent.
    let (mut used, mut start) = (0, 0);
    for word in text.split(' ').filter(|word| !word.is_empty()) {
        let word_cells = cells(word);
        if used > start && used + 1 + word_cells > width {
            rows.push(std::mem::take(&mut row));
            row = " ".repeat(indent);
            (used, start) = (indent, indent);
        }
        if used > start {
            row.push(' ');
            used += 1;
        }
        row.push_str(word);
        used += word_cells;
    }
    if used > start || rows.is_empty() {
        rows.push(row);
    }
    rows
}

/// Terminal cells `text` takes, as ratatui counts them.
fn cells(text: &str) -> usize {
    Span::raw(text).width()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyCode;

    /// The app at 80x24 with the render tests' look, with `keys` pressed.
    fn app_after(keys: &[KeyCode]) -> App {
        let mut app = testkit::app((80, 24));
        for &key in keys {
            testkit::press(&mut app, key);
        }
        app
    }

    #[test]
    fn help_simple_mono() {
        let app = app_after(&[KeyCode::Char('?')]);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                                       ",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│   ┌ Help ────────────────────────────────────────────────────────────────┐   │",
                "│   │ Keys                                                                 │   │",
                "│   │ ?       Help                                                         │   │",
                "│   │ Q       Quit                                                         │   │",
                "│   │ Ctrl+C  Quit                                                         │   │",
                "│   │ L       Lock: stop Raven and quit                                    │   │",
                "│   │ Ctrl+L  Redraw the screen                                            │   │",
                "│   │ Shortcuts also work with a Persian keyboard.                         │   │",
                "│   │                                                                      │   │",
                "│   │ What the symbols mean                                                │   │",
                "│   │ * In touch: since you opened Raven, a message from them arrived, or  │   │",
                "│   │   one of yours was delivered, in the last 15 minutes. It doesn't     │   │",
                "│   │   mean they are online now.                                          │   │",
                "│   │ ~ Messages waiting: some of your messages haven't reached them yet.  │   │",
                "│   │ o No recent contact: Raven has no online indicator.                  │   │",
                "│   │ x No address: Raven doesn't know where to reach them.                │   │",
                "│   │ ! Not verified: you haven't compared security words yet. More in     │── │",
                "│   │   docs/SECURITY_WORDS.md.                                            │   │",
                "│ A │ !! Security alert: Raven noticed something about them (press D, or W │   │",
                "└───└ Esc Close  Up/Down Scroll ───────────────────────────────────────────┘───┘",
                "No friends yet - all quiet                     activity ........................",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
            ],
        );
    }

    #[test]
    fn help_scrolled_to_the_end() {
        let mut keys = vec![KeyCode::Char('?')];
        keys.extend([KeyCode::Down; 30]);
        let app = app_after(&keys);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                                       ",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│   ┌ Help ────────────────────────────────────────────────────────────────┐   │",
                "│   │   one of yours was delivered, in the last 15 minutes. It doesn't     │   │",
                "│   │   mean they are online now.                                          │   │",
                "│   │ ~ Messages waiting: some of your messages haven't reached them yet.  │   │",
                "│   │ o No recent contact: Raven has no online indicator.                  │   │",
                "│   │ x No address: Raven doesn't know where to reach them.                │   │",
                "│   │ ! Not verified: you haven't compared security words yet. More in     │   │",
                "│   │   docs/SECURITY_WORDS.md.                                            │   │",
                "│   │ !! Security alert: Raven noticed something about them (press D, or W │   │",
                "│   │    for all).                                                         │   │",
                "│   │                                                                      │   │",
                "│   │ | Sending                                                            │   │",
                "│   │ ~ Waiting (Raven keeps trying)                                       │   │",
                "│   │ v Sent: it left this computer, not confirmed yet                     │   │",
                "│   │ vv Delivered: their Raven confirmed it                               │   │",
                "│   │ x Not delivered, not confirmed or not sent                           │   │",
                "│   │                                                                      │── │",
                "│   │ Want the old menu? Settings > Classic menu, or start Raven with      │   │",
                "│ A │ RAVEN_UI=classic.                                                    │   │",
                "└───└ Esc Close  Up/Down Scroll ───────────────────────────────────────────┘───┘",
                "No friends yet - all quiet                     activity ........................",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
            ],
        );
    }

    #[test]
    fn help_says_the_keys_work_with_a_persian_keyboard() {
        // At 60x16 HELP fills the window; the line comes under the keys.
        let simple = &[
            "┌ Help ────────────────────────────────────────────────────┐",
            "│ Keys                                                     │",
            "│ ?       Help                                             │",
            "│ Q       Quit                                             │",
            "│ Ctrl+C  Quit                                             │",
            "│ L       Lock: stop Raven and quit                        │",
            "│ Ctrl+L  Redraw the screen                                │",
            "│ Shortcuts also work with a Persian keyboard.             │",
            "│                                                          │",
            "│ What the symbols mean                                    │",
            "│ * In touch: since you opened Raven, a message from them  │",
            "│   arrived, or one of yours was delivered, in the last 15 │",
            "│   minutes. It doesn't mean they are online now.          │",
            "│ ~ Messages waiting: some of your messages haven't        │",
            "│   reached them yet.                                      │",
            "└ Esc Close  Up/Down Scroll ───────────────────────────────┘",
        ];
        let fancy = &[
            "╭ Help ────────────────────────────────────────────────────╮",
            "│ Keys                                                     │",
            "│ ?       Help                                             │",
            "│ Q       Quit                                             │",
            "│ Ctrl+C  Quit                                             │",
            "│ L       Lock: stop Raven and quit                        │",
            "│ Ctrl+L  Redraw the screen                                │",
            "│ Shortcuts also work with a Persian keyboard.             │",
            "│                                                          │",
            "│ What the symbols mean                                    │",
            "│ ● In touch: since you opened Raven, a message from them  │",
            "│   arrived, or one of yours was delivered, in the last 15 │",
            "│   minutes. It doesn't mean they are online now.          │",
            "│ ◐ Messages waiting: some of your messages haven't        │",
            "│   reached them yet.                                      │",
            "╰ Esc Close · ↑↓ Scroll ───────────────────────────────────╯",
        ];
        let ascii = &[
            "+ Help ----------------------------------------------------+",
            "| Keys                                                     |",
            "| ?       Help                                             |",
            "| Q       Quit                                             |",
            "| Ctrl+C  Quit                                             |",
            "| L       Lock: stop Raven and quit                        |",
            "| Ctrl+L  Redraw the screen                                |",
            "| Shortcuts also work with a Persian keyboard.             |",
            "|                                                          |",
            "| What the symbols mean                                    |",
            "| * In touch: since you opened Raven, a message from them  |",
            "|   arrived, or one of yours was delivered, in the last 15 |",
            "|   minutes. It doesn't mean they are online now.          |",
            "| ~ Messages waiting: some of your messages haven't        |",
            "|   reached them yet.                                      |",
            "+ Esc Close  Up/Down Scroll -------------------------------+",
        ];
        for (glyphs, expected) in [
            (theme::Glyphs::simple(), simple),
            (theme::Glyphs::fancy(), fancy),
            (theme::Glyphs::ascii(), ascii),
        ] {
            let look = Look {
                glyphs,
                ..testkit::simple_mono()
            };
            let mut app = testkit::app_in(look, (60, 16));
            testkit::press(&mut app, KeyCode::Char('?'));
            testkit::assert_rows(&testkit::render(&app, 60, 16), expected);
        }
    }

    const WATCHDOG: &str =
        "raven: still waiting for macOS Keychain access (your Raven identity) after 3s.";

    fn local_only() -> node::Probe {
        node::Probe {
            reach: node::Reach::LocalOnly,
            pid: Some(4242),
            listen: Some("127.0.0.1:55001".into()),
            capabilities: vec!["ipc".into(), "lan_direct".into()],
            p2p_held: false,
            timed_out: false,
            bind: None,
            at_rest: None,
            security: None,
            locked: None,
            nearby: None,
            tor: None,
        }
    }

    #[test]
    fn the_header_chip_follows_the_background_program() {
        let mut app = testkit::settled_app((80, 24), state_file::Receive::On, 1);
        let t0 = app.now();
        let header = |app: &App, ms: u64| {
            testkit::render_at(app, 80, 24, t0 + std::time::Duration::from_millis(ms))[0].clone()
        };
        assert_eq!(
            [header(&app, 0), header(&app, 83), header(&app, 166)],
            [
                "R A V E N                                                    | Starting Raven...",
                "R A V E N                                                    / Starting Raven...",
                "R A V E N                                                    - Starting Raven...",
            ]
        );
        testkit::send(
            &mut app,
            app::Msg::Job(app::JobResult::Ensured(node::Ensured {
                result: Ok(()),
                after: local_only(),
                started_by_app: Some(4242),
                captured: String::new(),
                ring: 0..0,
            })),
        );
        assert_eq!(
            header(&app, 0),
            "R A V E N                                      ~ Receiving on this computer only"
        );
        let fancy = App::new(
            Look {
                glyphs: theme::Glyphs::fancy(),
                ..testkit::simple_mono()
            },
            (80, 24),
            t0,
            0,
        );
        let mut fancy = fancy;
        fancy.start(testkit::session(state_file::Receive::Off));
        testkit::send(
            &mut fancy,
            app::Msg::Job(app::JobResult::Probed(node::Probe::of(&Err(
                "raven-node is not running; start it".into(),
            )))),
        );
        assert_eq!(
            testkit::render(&fancy, 80, 24)[0],
            "R A V E N                                                     ○ Receiving is off"
        );
    }

    #[test]
    fn kc_says_what_the_mac_is_asking_for() {
        let mut app = testkit::ready_app((80, 24), state_file::Receive::On);
        testkit::send(&mut app, app::Msg::Stderr(WATCHDOG.into()));
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                               ! Waiting for permission",
                "┌ Friend┌──────────────────────────────────────────────────────────────┐───────┐",
                "│       │ ! Your Mac is asking for permission                          │       │",
                "│       │                                                              │       │",
                "│       │ Raven needs to read your Raven identity from your Mac's      │       │",
                "│       │ Keychain. Look for a password window (it may be hidden       │       │",
                "│       │ behind this one). Enter your Mac login password and choose   │       │",
                "│       │ Always Allow.                                                │       │",
                "│       │                                                              │       │",
                "│       │ [Esc] Hide (Raven keeps waiting)                             │       │",
                "│       └──────────────────────────────────────────────────────────────┘       │",
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
    }

    #[test]
    fn kc_for_raven_node_over_ssh() {
        let mut app = testkit::app((80, 24));
        app.start(app::Session {
            over_ssh: true,
            ..testkit::session(state_file::Receive::On)
        });
        testkit::send(
            &mut app,
            app::Msg::Stderr(
                "note: raven-node (the background service) is waiting for macOS Keychain \
                 access to your chat history."
                    .into(),
            ),
        );
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                               ! Waiting for permission",
                "┌ Friend┌──────────────────────────────────────────────────────────────┐───────┐",
                "│       │ ! Your Mac is asking for permission                          │       │",
                "│       │                                                              │       │",
                "│       │ Raven's background program (raven-node) needs to read your   │       │",
                "│       │ chat history from your Mac's Keychain. Look for a password   │       │",
                "│       │ window (it may be hidden behind this one). Enter your Mac    │       │",
                "│       │ login password and choose Always Allow.                      │       │",
                "│       │                                                              │       │",
                "│       │ Over SSH no window can appear: open Raven on the Mac itself. │       │",
                "│       │                                                              │       │",
                "│       │ [Esc] Hide (Raven keeps waiting)                             │       │",
                "│       └──────────────────────────────────────────────────────────────┘       │",
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
    }

    #[test]
    fn passfile_shows_the_two_steps() {
        let mut app = testkit::ready_app((80, 24), state_file::Receive::On);
        testkit::send(
            &mut app,
            app::Msg::Job(app::JobResult::Vault(node::Vault {
                profile: true,
                needs_passphrase_file: true,
                ..node::Vault::default()
            })),
        );
        testkit::send(
            &mut app,
            app::Msg::Job(app::JobResult::Contacts {
                contacts: Ok(vec![testkit::friend(1)]),
                stamp: Default::default(),
            }),
        );
        assert_eq!(app.overlays(), [Overlay::PassFile]);
        testkit::assert_rows(&testkit::render(&app, 80, 24), &[
            "R A V E N                                                 ! Needs setup: press N",
            "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
            "│> x Friend 1       !││                                                        │",
            "┌──────────────────────────────────────────────────────────────────────────────┐",
            "│ Raven's background program needs one more step on this computer              │",
            "│                                                                              │",
            "│ Raven keeps your keys in a passphrase-protected vault here. The background   │",
            "│ program runs without a window, so it can't ask for your passphrase. Until    │",
            "│ this is set up, Raven can't send or receive messages on this computer.       │",
            "│                                                                              │",
            "│ 1. Save your passphrase in a file only you can read:                         │",
            "│    ( umask 077; printf '%s\\n' 'your passphrase' >                            │",
            "│    ~/.config/raven/keystore-passphrase )                                     │",
            "│ 2. Open Raven with:                                                          │",
            "│    RAVEN_KEYSTORE_PASSPHRASE_FILE=~/.config/raven/keystore-passphrase raven  │",
            "│                                                                              │",
            "│ More in docs/INSTALL_Linux.md (\"Non-interactive use\").                       │",
            "│                                                                              │",
            "│ [Esc] Close                                                                  │",
            "└──────────────────────────────────────────────────────────────────────────────┘",
            "│ A  Add a friend    ││ writing.                                               │",
            "└────────────────────┘└────────────────────────────────────────────────────────┘",
            "1 friend - all quiet                           activity ........................",
            "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
        ]);
        // At the smallest size the keys stay; the blank rows give way.
        let small = testkit::render(&app, 60, 16);
        testkit::assert_rows(
            &small,
            &[
                "┌──────────────────────────────────────────────────────────┐",
                "│ Raven's background program needs one more step on this   │",
                "│ computer                                                 │",
                "│ Raven keeps your keys in a passphrase-protected vault    │",
                "│ here. The background program runs without a window, so   │",
                "│ it can't ask for your passphrase. Until this is set up,  │",
                "│ Raven can't send or receive messages on this computer.   │",
                "│ 1. Save your passphrase in a file only you can read:     │",
                "│    ( umask 077; printf '%s\\n' 'your passphrase' >        │",
                "│    ~/.config/raven/keystore-passphrase )                 │",
                "│ 2. Open Raven with:                                      │",
                "│    RAVEN_KEYSTORE_PASSPHRASE_FILE=~/.config/raven/keysto │",
                "│    re-passphrase                                         │",
                "│    raven                                                 │",
                "│ [Esc] Close                                              │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
    }

    /// The passphrase file PASSFILE's first step makes is there already:
    /// PASSFILE says what it means for a laptop someone takes (UXF.7).
    #[test]
    fn passfile_says_what_a_saved_passphrase_file_means() {
        let mut app = testkit::ready_app((80, 24), state_file::Receive::On);
        testkit::send(
            &mut app,
            app::Msg::Job(app::JobResult::Vault(node::Vault {
                profile: true,
                needs_passphrase_file: true,
                passphrase_saved: true,
                ..node::Vault::default()
            })),
        );
        testkit::send(
            &mut app,
            app::Msg::Job(app::JobResult::Contacts {
                contacts: Ok(vec![testkit::friend(1)]),
                stamp: Default::default(),
            }),
        );
        assert_eq!(app.overlays(), [Overlay::PassFile]);
        testkit::assert_rows(&testkit::render(&app, 80, 24), &[
            "┌──────────────────────────────────────────────────────────────────────────────┐",
            "│ Raven's background program needs one more step on this computer              │",
            "│                                                                              │",
            "│ Raven keeps your keys in a passphrase-protected vault here. The background   │",
            "│ program runs without a window, so it can't ask for your passphrase. Until    │",
            "│ this is set up, Raven can't send or receive messages on this computer.       │",
            "│                                                                              │",
            "│ 1. Save your passphrase in a file only you can read:                         │",
            "│    ( umask 077; printf '%s\\n' 'your passphrase' >                            │",
            "│    ~/.config/raven/keystore-passphrase )                                     │",
            "│ 2. Open Raven with:                                                          │",
            "│    RAVEN_KEYSTORE_PASSPHRASE_FILE=~/.config/raven/keystore-passphrase raven  │",
            "│                                                                              │",
            "│ Your passphrase is saved in a file on this computer                          │",
            "│ (~/.config/raven/keystore-passphrase). Anyone who can read your files can    │",
            "│ unlock Raven with it. If that worries you, delete the file when you are not  │",
            "│ using Raven (for example before you travel), and create it again when you    │",
            "│ want to send and receive.                                                    │",
            "│                                                                              │",
            "│ More in docs/INSTALL_Linux.md (\"Non-interactive use\").                       │",
            "│                                                                              │",
            "│ [Esc] Close                                                                  │",
            "└──────────────────────────────────────────────────────────────────────────────┘",
            "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
        ]);
        // At the smallest size it gives way first: the steps stay.
        let small = testkit::render(&app, 60, 16);
        assert_eq!(
            small[13..],
            [
                "│    raven                                                 │",
                "│ [Esc] Close                                              │",
                "└──────────────────────────────────────────────────────────┘",
            ]
        );
    }

    /// The app on macOS (`mac`) or Windows, one friend, receiving on, and
    /// the start it asked for answered: process 4242, started by it, its
    /// listener at `listen`. With what the answer asked for.
    fn started_on(mac: bool, listen: &str) -> (App, Vec<app::Cmd>) {
        let mut app = testkit::app((80, 24));
        app.set_mac_for_tests(mac);
        app.set_windows_for_tests(!mac);
        app.start(testkit::session(state_file::Receive::On));
        for result in [
            app::JobResult::Vault(node::Vault::default()),
            app::JobResult::Probed(node::Probe::of(&Err("raven-node is not running; x".into()))),
            app::JobResult::Managed(None),
            app::JobResult::Contacts {
                contacts: Ok(vec![testkit::friend(1)]),
                stamp: Default::default(),
            },
        ] {
            testkit::send(&mut app, app::Msg::Job(result));
        }
        let after = node::Probe {
            reach: if listen.starts_with("127.") {
                node::Reach::LocalOnly
            } else {
                node::Reach::Listening { port: Some(7420) }
            },
            listen: Some(listen.into()),
            ..local_only()
        };
        let cmds = testkit::send(
            &mut app,
            app::Msg::Job(app::JobResult::Ensured(node::Ensured {
                result: Ok(()),
                after,
                started_by_app: Some(4242),
                captured: String::new(),
                ring: 0..0,
            })),
        );
        (app, cmds)
    }

    #[test]
    fn fw_once_after_this_app_starts_a_node_on_the_network() {
        let (mut app, cmds) = started_on(true, "0.0.0.0:7420");
        assert_eq!(app.overlays(), [Overlay::Firewall]);
        // Shown once per profile: saved at once.
        assert!(cmds.iter().any(|cmd| matches!(
            cmd,
            app::Cmd::Store(app::StoreJob::SaveSettings(state)) if state.firewall_note_shown
        )));
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                   + node ok - just now",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> x Friend 1       !││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│       ┌──────────────────────────────────────────────────────────────┐       │",
                "│       │ Your computer may ask about the firewall                     │       │",
                "│       │                                                              │       │",
                "│       │ If macOS asks whether raven-node may accept incoming network │       │",
                "│       │ connections, choose Allow.                                   │       │",
                "│       │                                                              │       │",
                "│       │ [Enter] OK                                                   │       │",
                "│       └──────────────────────────────────────────────────────────────┘       │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│                    ││ Pick a friend on the left and press Enter to start     │",
                "│ A  Add a friend    ││ writing.                                               │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "Listening on your network - all quiet          activity ........................",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
            ],
        );
        // A paste's Enter does not close it; Enter does.
        testkit::paste(&mut app, "x", app::PasteVia::Bracketed);
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(app.overlays(), [Overlay::Firewall]);
        testkit::tick(&mut app, std::time::Duration::from_millis(400));
        testkit::press(&mut app, KeyCode::Enter);
        assert!(app.overlays().is_empty());
        // Not again: the next node this app starts listens with no note.
        testkit::send(
            &mut app,
            app::Msg::Poll(workers::PollUpdate::Status(node::Probe::of(&Err(
                "raven-node is not running; x".into(),
            )))),
        );
        assert_eq!(app.node().started_by_app, None);
        testkit::send(
            &mut app,
            app::Msg::Job(app::JobResult::Ensured(node::Ensured {
                result: Ok(()),
                after: node::Probe {
                    reach: node::Reach::Listening { port: Some(7420) },
                    pid: Some(4343),
                    listen: Some("0.0.0.0:7420".into()),
                    ..local_only()
                },
                started_by_app: Some(4343),
                captured: String::new(),
                ring: 0..0,
            })),
        );
        assert_eq!(app.node().started_by_app, Some(4343));
        assert!(app.overlays().is_empty());

        // Windows: the rule, for the port it listens on.
        let (app, _) = started_on(false, "0.0.0.0:7420");
        assert_eq!(app.overlays(), [Overlay::Firewall]);
        let text = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(text.contains("Windows may ask about raven-node"), "{text}");
        let rule = bridge::internet_firewall_hint("7420");
        let rule: Vec<&str> = rule.split_whitespace().collect();
        assert!(text.contains(&rule.join(" ")), "{text}");
    }

    #[test]
    fn no_fw_for_a_listener_on_this_computer_or_a_node_started_earlier() {
        // Loopback: no system asks about it.
        let (app, _) = started_on(true, "127.0.0.1:55001");
        assert!(app.overlays().is_empty());
        // Linux asks nothing either.
        let mut app = testkit::settled_app((80, 24), state_file::Receive::On, 1);
        testkit::send(
            &mut app,
            app::Msg::Job(app::JobResult::Ensured(node::Ensured {
                result: Ok(()),
                after: node::Probe {
                    reach: node::Reach::Listening { port: Some(7420) },
                    listen: Some("0.0.0.0:7420".into()),
                    ..local_only()
                },
                started_by_app: Some(4242),
                captured: String::new(),
                ring: 0..0,
            })),
        );
        assert!(app.overlays().is_empty());
        // A node that ran already: this app made no new listener.
        let mut app = testkit::app((80, 24));
        app.set_mac_for_tests(true);
        app.start(testkit::session(state_file::Receive::On));
        testkit::send(&mut app, testkit::node_up());
        assert!(app.overlays().is_empty());
    }

    /// Home with one friend, receiving `receive`, for a profile that has
    /// seen none of the notes shown once (UXF.9). With receiving on, the
    /// start it asked for has not answered yet.
    fn before_the_notes(receive: state_file::Receive) -> App {
        testkit::home_app_from(
            testkit::simple_mono(),
            (80, 24),
            testkit::unseen_session(receive),
            vec![testkit::friend(1)],
            controller::Conversations::new(),
        )
    }

    fn not_running() -> app::Msg {
        app::Msg::Poll(workers::PollUpdate::Status(node::Probe::of(&Err(
            "raven-node is not running; x".into(),
        ))))
    }

    #[test]
    fn note_says_once_what_people_on_this_network_can_see() {
        let mut app = before_the_notes(state_file::Receive::On);
        assert!(app.overlays().is_empty(), "nothing receives yet");
        let cmds = testkit::started_here(&mut app, 4242);
        assert_eq!(app.overlays(), [Overlay::NetworkNote]);
        // Remembered at once, as a save the user did not ask for: a
        // tui_state.json that can't be read is left as it is.
        assert!(cmds.iter().any(|cmd| matches!(
            cmd,
            app::Cmd::Store(app::StoreJob::SaveReadMarks(state)) if state.network_note_shown
        )));
        assert!(app.settings().network_note_shown);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                   + node ok - just now",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> x Friend 1       !││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│       ┌──────────────────────────────────────────────────────────────┐       │",
                "│       │ What people on this network can see                          │       │",
                "│       │                                                              │       │",
                "│       │ People on this network can see that this computer talks to   │       │",
                "│       │ another one, when, and how much. They can't read your        │       │",
                "│       │ messages.                                                    │       │",
                "│       │                                                              │       │",
                "│       │ [Enter] OK                                                   │       │",
                "│       └──────────────────────────────────────────────────────────────┘       │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│                    ││ Pick a friend on the left and press Enter to start     │",
                "│ A  Add a friend    ││ writing.                                               │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "Listening on your network - all quiet          activity ........................",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
            ],
        );
        // At the smallest size, over the one-pane Home.
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N                               + node ok - just now",
                "┌ Friends ─────────────────────────────────────────────────┐",
                "│> x Friend 1                                             !│",
                "┌──────────────────────────────────────────────────────────┐",
                "│ What people on this network can see                      │",
                "│                                                          │",
                "│ People on this network can see that this computer talks  │",
                "│ to another one, when, and how much. They can't read your │",
                "│ messages.                                                │",
                "│                                                          │",
                "│ [Enter] OK                                               │",
                "└──────────────────────────────────────────────────────────┘",
                "│                                                          │",
                "│ A  Add a friend                                          │",
                "└──────────────────────────────────────────────────────────┘",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify ",
            ],
        );
        // A paste's Enter does not close it; Enter does.
        testkit::paste(&mut app, "x", app::PasteVia::Bracketed);
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(app.overlays(), [Overlay::NetworkNote]);
        testkit::tick(&mut app, std::time::Duration::from_millis(400));
        testkit::press(&mut app, KeyCode::Enter);
        assert!(app.overlays().is_empty());
        // Not again: the node stops, and listens again.
        testkit::send(&mut app, not_running());
        testkit::send(&mut app, testkit::node_up());
        assert!(matches!(
            app.node().state,
            node::NodeState::Listening { .. }
        ));
        assert!(app.overlays().is_empty());
        // Nor in the next session, which starts from the settings saved.
        let mut next = testkit::home_app_from(
            testkit::simple_mono(),
            (80, 24),
            app::Session {
                settings: app.settings().clone(),
                ..testkit::unseen_session(state_file::Receive::On)
            },
            vec![testkit::friend(1)],
            controller::Conversations::new(),
        );
        testkit::started_here(&mut next, 4343);
        assert!(next.overlays().is_empty());
        // Esc closes it too; Ctrl+C opens QUIT over it.
        let mut app = before_the_notes(state_file::Receive::On);
        testkit::started_here(&mut app, 4242);
        testkit::ctrl(&mut app, 'c');
        assert_eq!(app.overlays(), [Overlay::NetworkNote, Overlay::Quit]);
        testkit::press(&mut app, KeyCode::Esc);
        testkit::press(&mut app, KeyCode::Esc);
        assert!(app.overlays().is_empty());
    }

    #[test]
    fn note_in_every_look() {
        for look in testkit::every_look() {
            let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(60, 16))
                .expect("a terminal");
            terminal
                .draw(|f| overlays::render_network_note(f, f.area(), &look))
                .expect("a draw");
            let rows = testkit::buffer_lines(terminal.backend().buffer());
            let card: Vec<&String> = rows.iter().filter(|row| !row.trim().is_empty()).collect();
            // Its borders, the title, a blank row, the three rows of the
            // note, a blank row and the key: nothing is cut.
            assert_eq!(card.len(), 9, "{rows:#?}");
            assert!(
                card[1].contains("What people on this network can see"),
                "{rows:#?}"
            );
            assert!(
                card[3].contains("People on this network can see that"),
                "{rows:#?}"
            );
            assert!(card[5].contains("messages."), "{rows:#?}");
            assert!(card[7].contains("[Enter] OK"), "{rows:#?}");
        }
    }

    #[test]
    fn note_waits_for_a_calm_moment_and_fw_goes_over_it() {
        // Receiving off: a node that listens anyway says nothing.
        let mut app = before_the_notes(state_file::Receive::Off);
        testkit::send(&mut app, testkit::node_up());
        assert!(matches!(
            app.node().state,
            node::NodeState::Listening { .. }
        ));
        assert!(app.overlays().is_empty());
        // On this computer only, or on no network at all: nobody on a
        // network sees it.
        let mut app = before_the_notes(state_file::Receive::On);
        testkit::send(
            &mut app,
            app::Msg::Job(app::JobResult::Ensured(node::Ensured {
                result: Ok(()),
                after: testkit::status(4242, "127.0.0.1:55001"),
                started_by_app: Some(4242),
                captured: String::new(),
                ring: 0..0,
            })),
        );
        assert!(app.overlays().is_empty());
        testkit::send(
            &mut app,
            app::Msg::Poll(workers::PollUpdate::Network(Some(false))),
        );
        testkit::send(&mut app, testkit::node_up());
        assert!(matches!(
            app.node().state,
            node::NodeState::Listening { .. }
        ));
        assert!(app.overlays().is_empty());
        assert!(!app.settings().network_note_shown);

        // The composer has the keys: it waits for the list.
        let mut app = before_the_notes(state_file::Receive::On);
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(app.focus(), app::Focus::Composer);
        testkit::started_here(&mut app, 4242);
        assert!(app.overlays().is_empty());
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(app.overlays(), [Overlay::NetworkNote]);

        // Adding a friend: Enter on AF-1 is AF-2's, so it waits for Home.
        let mut app = before_the_notes(state_file::Receive::On);
        testkit::press(&mut app, KeyCode::Char('a'));
        testkit::started_here(&mut app, 4242);
        testkit::paste(&mut app, &testkit::card(0xB0, ""), app::PasteVia::Bracketed);
        testkit::tick(&mut app, std::time::Duration::from_millis(400));
        assert!(app.overlays().is_empty());
        testkit::press(&mut app, KeyCode::Enter);
        assert!(matches!(app.screen(), Screen::AddFriend(add) if add.naming));
        testkit::press(&mut app, KeyCode::Esc);
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen(), &Screen::Home);
        assert_eq!(app.overlays(), [Overlay::NetworkNote]);

        // This app started it on macOS: FW goes over it, then NOTE shows.
        let mut app = before_the_notes(state_file::Receive::On);
        app.set_mac_for_tests(true);
        testkit::started_here(&mut app, 4242);
        assert_eq!(app.overlays(), [Overlay::NetworkNote, Overlay::Firewall]);
        testkit::tick(&mut app, std::time::Duration::from_millis(400));
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(app.overlays(), [Overlay::NetworkNote]);
        testkit::press(&mut app, KeyCode::Enter);
        assert!(app.overlays().is_empty());
    }

    #[test]
    fn rx_asks_before_the_first_start() {
        let app = testkit::settled_app((80, 24), state_file::Receive::Unset, 1);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                          o Not running",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> x Friend 1       !││                                                        │",
                "│                    ││                                                        │",
                "│       ┌──────────────────────────────────────────────────────────────┐       │",
                "│       │ Receive messages on this computer?                           │       │",
                "│       │                                                              │       │",
                "│       │ To get messages, Raven keeps a small background program      │       │",
                "│       │ running that listens on your network (port 7420). Only       │       │",
                "│       │ friends you add can send you anything.                       │       │",
                "│       │                                                              │       │",
                "│       │ Your computer may ask whether to allow this. On Windows,     │       │",
                "│       │ choose Private networks and Allow.                           │       │",
                "│       │                                                              │       │",
                "│       │ You can change this later in Settings.                       │       │",
                "│       │                                                              │       │",
                "│       │ > [Y] Yes, receive messages (recommended)                    │       │",
                "│       │   [N] Not now, I only want to send                           │       │",
                "│       └──────────────────────────────────────────────────────────────┘────── │",
                "│                    ││ Pick a friend on the left and press Enter to start     │",
                "│ A  Add a friend    ││ writing.                                               │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "1 friend - all quiet                           activity ........................",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
            ],
        );
    }

    #[test]
    fn wrap_breaks_at_spaces_under_the_indent() {
        assert_eq!(
            wrap("* In touch: a message from them arrived", 16, 2),
            ["* In touch: a", "  message from", "  them arrived"]
        );
        assert_eq!(wrap("exactly ten", 11, 0), ["exactly ten"]);
        assert_eq!(wrap("a  b", 10, 0), ["a b"]);
        assert_eq!(wrap("", 10, 0), [""]);
        // A word wider than the row stays whole, on a row of its own.
        assert_eq!(
            wrap("to RAVEN_UI=classic.", 8, 0),
            ["to", "RAVEN_UI=classic."]
        );
        // Width in cells, not bytes: '·' is one cell, two bytes.
        assert_eq!(wrap("a · b · c", 5, 0), ["a · b", "· c"]);
    }

    #[test]
    fn quit_simple_mono() {
        let app = app_after(&[KeyCode::Char('q')]);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                                       ",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ Quit Raven?                                              │         │",
                "│         │                                                          │         │",
                "│         │ [Enter] Quit   [Esc] Stay                                │         │",
                "│         └──────────────────────────────────────────────────────────┘         │",
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
    }

    #[test]
    fn small_window_at_40_by_3() {
        let app = testkit::app((40, 3));
        testkit::assert_rows(
            &testkit::render(&app, 40, 3),
            &[
                "Raven needs a bigger window: at least 60",
                "columns by 16 rows (now 40 by 3).       ",
                "[C] Classic menu  [Q] Quit              ",
            ],
        );
    }

    #[test]
    fn small_window_is_centred_and_hides_the_overlays() {
        let mut app = app_after(&[KeyCode::Char('?')]);
        testkit::resize(&mut app, 59, 20);
        let blank = " ".repeat(59);
        let mut rows = vec![blank.as_str(); 8];
        rows.extend([
            "Raven needs a bigger window: at least 60 columns by 16 rows",
            "(now 59 by 20).                                            ",
            blank.as_str(),
            "[C] Classic menu  [Q] Quit                                 ",
        ]);
        rows.extend([blank.as_str(); 8]);
        testkit::assert_rows(&testkit::render(&app, 59, 20), &rows);
        // A short wide window: the sentence on one row, the keys under it,
        // centred as one block.
        testkit::assert_rows(
            &testkit::render(&app, 90, 4),
            &[
                "        Raven needs a bigger window: at least 60 columns by 16 rows (now 90 by 4).        ",
                "                                                                                          ",
                "        [C] Classic menu  [Q] Quit                                                        ",
                "                                                                                          ",
            ],
        );
        // Too short for the sentence: the keys stay.
        testkit::assert_rows(
            &testkit::render(&app, 30, 2),
            &[
                " Raven needs a bigger window: ",
                " [C] Classic menu  [Q] Quit   ",
            ],
        );
        testkit::assert_rows(
            &testkit::render(&app, 30, 1),
            &["  [C] Classic menu  [Q] Quit  "],
        );
        // 60x16 is big enough: HELP is back.
        let rows = testkit::render(&app, 60, 16);
        assert!(rows.iter().any(|row| row.contains("Help")), "{rows:#?}");
        assert!(!rows.iter().any(|row| row.contains("bigger window")));
    }

    #[test]
    fn hints_keep_help_and_quit_at_every_width() {
        for look in testkit::every_look() {
            for (cols, rows) in [(60, 16), (80, 24), (100, 30)] {
                let app = App::new(look, (cols, rows), Instant::now(), 0);
                let got = testkit::render(&app, cols, rows);
                let last = got.last().expect("a last row");
                let want = format!("? Help{}Q Quit", look.glyphs.separator);
                assert!(last.starts_with(&want), "{cols}x{rows}: {last:?}");
                // Home's header has the wordmark, the heartbeat and the clock
                // (UXF.10): the help key is in the hints alone.
                assert!(
                    got[0].starts_with("R A V E N"),
                    "{cols}x{rows}: {:?}",
                    got[0]
                );
                assert!(!got[0].contains("? Help"), "{cols}x{rows}: {:?}", got[0]);
            }
        }
    }

    #[test]
    fn a_toast_covers_the_hints_until_it_goes() {
        let mut app = app_after(&[]);
        testkit::ctrl(&mut app, 'z');
        let rows = testkit::render(&app, 80, 24);
        assert_eq!(
            rows[23],
            "Pausing is not supported here. Press Q to quit.                                 "
        );
        assert_eq!(&rows[..23], &testkit::render(&app_after(&[]), 80, 24)[..23]);
        // Cut to the window, with the glyph set's ellipsis; in SMALL too.
        let mut small = testkit::app((40, 3));
        testkit::ctrl(&mut small, 'z');
        let rows = testkit::render(&small, 40, 3);
        assert_eq!(rows[2], "Pausing is not supported here. Press ...");
        assert_eq!(rows[0], "Raven needs a bigger window: at least 60");
        // Never drawn past its time, then gone: the hints are back.
        let until = app.toast().and_then(|t| t.until()).expect("on show");
        assert_eq!(
            testkit::render_at(&app, 80, 24, until)[23],
            testkit::render(&app_after(&[]), 80, 24)[23]
        );
        testkit::tick(&mut app, std::time::Duration::from_secs(5));
        assert_eq!(app.toast(), None);
        assert_eq!(
            testkit::render(&app, 80, 24),
            testkit::render(&app_after(&[]), 80, 24)
        );
    }
}
