//! Renders of the main screens for people to look at: the welcome, Home
//! with a conversation, Settings, Network and Add a friend, each as plain
//! text and as text with the colours (ANSI escapes), in every look.
//!
//! `screens_to_files` is ignored: it writes only when asked to, into the
//! folder RAVEN_TUI_SCREENS names, e.g.
//! `RAVEN_TUI_SCREENS=/tmp/screens cargo test -p ash screens_to_files -- --ignored`.

use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use crossterm::event::KeyCode;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use ratatui::Terminal;

use super::app::{App, JobResult, Look, Msg};
use super::bridge::ContactView;
use super::controller::{GroupChat, GroupMessage, GroupsRead, MemberLine, RowView};
use super::state_file::Receive;
use super::testkit;
use super::theme::{self, Depth, Glyphs, Theme};
use super::ui;
use super::workers::FileStamp;

/// The folder the renders go to.
const OUT_ENV: &str = "RAVEN_TUI_SCREENS";

/// The window sizes: the prototype's, and the smallest two-pane one.
const SIZES: [(u16, u16); 2] = [(140, 36), (80, 24)];

/// Sample friends: Alex (verified, with an address), Sam (with an address)
/// and Riley (no address).
fn friends() -> Vec<ContactView> {
    vec![
        ContactView {
            label: "Alex".into(),
            pinned: true,
            ..testkit::reachable(1)
        },
        ContactView {
            label: "Sam".into(),
            pinned: true,
            ..testkit::reachable(2)
        },
        ContactView {
            label: "Riley".into(),
            ..testkit::friend(3)
        },
    ]
}

/// A conversation with Alex and one message from Sam.
fn rows() -> Vec<(u8, RowView)> {
    vec![
        (
            1,
            testkit::row(
                1,
                false,
                "",
                26 * 60,
                "Did the new build find you on the office Wi-Fi?",
            ),
        ),
        (
            1,
            testkit::row(
                2,
                true,
                "delivered",
                26 * 60 - 1,
                "Straight away. No setup, no account.",
            ),
        ),
        (
            1,
            testkit::row(3, false, "", 90, "Are we still on for Saturday?"),
        ),
        (
            1,
            testkit::row(4, true, "delivered", 88, "Yes! I'll bring the map."),
        ),
        (
            1,
            testkit::row(5, false, "", 30, "Sam says the cabin has no signal at all."),
        ),
        (2, testkit::row(6, false, "", 4, "See you at the station.")),
    ]
}

/// Home with Alex's conversation open, the background program this app
/// started listening, and a message sent and delivered over the local
/// network (the history then has it: Alex is in touch).
fn home(look: Look, size: (u16, u16)) -> App {
    let mut app = testkit::home_app_in(
        look,
        size,
        Receive::On,
        friends(),
        testkit::conversations(&rows()),
    );
    testkit::started_here(&mut app, 4242);
    testkit::press(&mut app, KeyCode::Enter);
    let text = "On my way, leaving in 10 min.";
    if let Some((id, _)) = testkit::type_and_send(&mut app, text) {
        testkit::tick(&mut app, Duration::from_millis(900));
        testkit::send(
            &mut app,
            testkit::sent(id, testkit::delivered_to("192.168.1.11:7420")),
        );
    }
    let mut history = rows();
    history.push((1, testkit::row(7, true, "delivered", 0, text)));
    testkit::reload_rows(&mut app, &history);
    testkit::tick(&mut app, Duration::from_secs(3));
    app
}

/// Home with Sam's conversation open: one message raven-node keeps trying
/// (the last try found nobody), one a friend holds a sealed copy of.
fn home_waiting(look: Look, size: (u16, u16)) -> App {
    let mut history = rows();
    history.extend([
        (
            2,
            testkit::row(8, true, "queued", 40, "The cabin is booked for Saturday."),
        ),
        (
            2,
            testkit::row(9, true, "queued", 12, "Saturday, 9:00 at the station."),
        ),
    ]);
    let mut app = testkit::home_app_in(
        look,
        size,
        Receive::On,
        friends(),
        testkit::conversations(&history),
    );
    testkit::started_here(&mut app, 4242);
    testkit::press(&mut app, KeyCode::Down);
    testkit::press(&mut app, KeyCode::Enter);
    let mut unreachable = testkit::outbox_item(2, 8, "queued");
    unreachable.attempts = 2;
    unreachable.last_error_code = "NOT_REACHABLE".into();
    let mut held = testkit::outbox_item(2, 9, "queued");
    held.in_custody = 1;
    testkit::send(&mut app, testkit::outbox(vec![unreachable, held]));
    testkit::tick(&mut app, Duration::from_secs(3));
    app
}

/// A group's chat (the groups' lab switches on for this thread): its
/// members' messages, one passed on by a member, and one of yours that one
/// member has and another member passes on to the third.
fn group_chat(look: Look, size: (u16, u16)) -> App {
    use raven_core::group::store::{GroupSummary, GroupView, MemberView, STATUS_ACTIVE};
    use raven_core::group::store::{LINE_DELIVERED, LINE_WAITING};
    raven_core::group::set_lab_groups_for_this_thread(Some(true));
    raven_core::horizon::set_lab_horizon_for_this_thread(Some(true));
    let mut app = testkit::home_app_in(
        look,
        size,
        Receive::On,
        friends(),
        testkit::conversations(&rows()),
    );
    testkit::started_here(&mut app, 4242);
    let me = [0x70; 32];
    let summary = GroupSummary {
        id: [1; 16],
        name: "Weekend trip".into(),
        admin: me,
        i_am_admin: true,
        status: STATUS_ACTIVE.into(),
        epoch: 1,
        members: 4,
        unread: 0,
        last_ms: 0,
        last: None,
    };
    let member = |key: [u8; 32], label: &str, friend: Option<&str>| MemberView {
        key,
        label: label.into(),
        friend_name: friend.map(str::to_owned),
        admin: key == me,
        me: key == me,
    };
    let now = app.now_ms();
    let minutes = |n: u64| now - n * 60_000;
    let message = |id: u8, author: &str, via: Option<&str>, body: &str, at: u64| GroupMessage {
        id: [id; 16],
        mine: false,
        author: author.into(),
        via: via.map(str::to_owned),
        body: body.into(),
        at_ms: at,
        sent_ms: at,
        path: None,
        lines: Vec::new(),
        delivered: 0,
        total: 0,
    };
    let line = |name: &str, state: &str, relayed: bool| MemberLine {
        name: name.into(),
        state: state.into(),
        relayed,
    };
    let chat = GroupChat {
        view: GroupView {
            summary: summary.clone(),
            members: vec![
                member(me, "", None),
                member([1; 32], "Alex", Some("Alex")),
                member([2; 32], "Sam", Some("Sam")),
                member([9; 32], "Jordan", None),
            ],
        },
        messages: vec![
            message(
                0x11,
                "Alex",
                None,
                "Who is driving on Saturday?",
                minutes(50),
            ),
            message(
                0x12,
                "Jordan",
                Some("Sam"),
                "I can take three people.",
                minutes(42),
            ),
            GroupMessage {
                id: [0x13; 16],
                mine: true,
                author: "you".into(),
                via: None,
                body: "Count me in, I'll bring the map.".into(),
                at_ms: minutes(30),
                sent_ms: minutes(30),
                path: None,
                lines: vec![
                    line("Alex", LINE_DELIVERED, false),
                    line("Sam", LINE_DELIVERED, false),
                    line("Jordan", LINE_WAITING, true),
                ],
                delivered: 2,
                total: 3,
            },
        ],
    };
    let groups = vec![summary];
    // The first reads, then the group opened from the list (under the
    // three friends) and its chat read.
    for _ in 0..4 {
        groups_read(&mut app, &groups, None);
    }
    for key in [KeyCode::Down, KeyCode::Down, KeyCode::Down, KeyCode::Enter] {
        testkit::press(&mut app, key);
    }
    groups_read(&mut app, &groups, Some(chat));
    testkit::tick(&mut app, Duration::from_secs(3));
    raven_core::group::set_lab_groups_for_this_thread(None);
    raven_core::horizon::set_lab_horizon_for_this_thread(None);
    app
}

/// A groups read answered with `groups`, and `chat` for the open group.
fn groups_read(
    app: &mut App,
    groups: &[raven_core::group::store::GroupSummary],
    chat: Option<GroupChat>,
) {
    let open = chat.map(|chat| (chat.view.summary.id, Ok(chat)));
    testkit::send(
        app,
        Msg::Job(JobResult::Groups(GroupsRead {
            groups: Ok(groups.to_vec()),
            open,
            stamp: FileStamp::default(),
        })),
    );
}

/// `app` with `keys` pressed, then three seconds on.
fn after(mut app: App, keys: &[KeyCode]) -> App {
    for &key in keys {
        testkit::press(&mut app, key);
    }
    testkit::tick(&mut app, Duration::from_secs(3));
    app
}

/// The screens, by file name.
fn screens(look: Look, size: (u16, u16)) -> Vec<(&'static str, App)> {
    let mut welcome = testkit::wizard_app(size);
    welcome.set_look_for_tests(look);
    testkit::tick(&mut welcome, Duration::from_secs(5));
    let home = home(look, size);
    let mut list = home.clone();
    testkit::press(&mut list, KeyCode::Esc);
    vec![
        ("01-welcome", welcome),
        ("02-home-chat", home.clone()),
        ("03-settings", after(list.clone(), &[KeyCode::Char('s')])),
        ("04-network", after(list.clone(), &[KeyCode::Char('n')])),
        ("05-add-friend", after(list.clone(), &[KeyCode::Char('a')])),
        ("06-home-waiting", home_waiting(look, size)),
        ("07-group-chat", group_chat(look, size)),
        ("08-help", after(list.clone(), &[KeyCode::Char('?')])),
        ("09-quit", after(list, &[KeyCode::Char('q')])),
        ("10-welcome-start", {
            let mut early = testkit::wizard_app(size);
            early.set_look_for_tests(look);
            testkit::tick(&mut early, Duration::from_millis(900));
            early
        }),
    ]
}

/// The looks, by name: the Calm palettes in 24-bit colour, the terminal's
/// own colours, and plain text.
fn looks() -> Vec<(&'static str, Look)> {
    let base = testkit::simple_mono();
    let fancy = |theme| Look {
        glyphs: Glyphs::fancy(),
        theme,
        ..base
    };
    vec![
        ("fancy-dark", fancy(Theme::calm(&theme::DARK, Depth::True))),
        (
            "fancy-light",
            fancy(Theme::calm(&theme::LIGHT, Depth::True)),
        ),
        ("fancy-terminal", fancy(Theme::color())),
        (
            "simple-mono",
            Look {
                glyphs: Glyphs::simple(),
                theme: Theme::mono(),
                ..base
            },
        ),
    ]
}

/// The frame `app` draws in its window.
fn buffer(app: &App) -> Buffer {
    let (cols, rows) = app.size();
    let mut terminal = Terminal::new(TestBackend::new(cols, rows)).expect("a test terminal");
    terminal
        .draw(|f| ui::render(f, app, app.now()))
        .expect("a draw");
    terminal.backend().buffer().clone()
}

/// An SGR colour parameter for `color`: `base` 30 (foreground) or 40.
fn sgr_color(color: Color, base: u8) -> Option<String> {
    let named = |n: u8| Some((base + n).to_string());
    let bright = |n: u8| Some((base + 60 + n).to_string());
    match color {
        Color::Reset => None,
        Color::Black => named(0),
        Color::Red => named(1),
        Color::Green => named(2),
        Color::Yellow => named(3),
        Color::Blue => named(4),
        Color::Magenta => named(5),
        Color::Cyan => named(6),
        Color::Gray => named(7),
        Color::DarkGray => bright(0),
        Color::LightRed => bright(1),
        Color::LightGreen => bright(2),
        Color::LightYellow => bright(3),
        Color::LightBlue => bright(4),
        Color::LightMagenta => bright(5),
        Color::LightCyan => bright(6),
        Color::White => bright(7),
        Color::Rgb(r, g, b) => Some(format!("{};2;{r};{g};{b}", base + 8)),
        Color::Indexed(i) => Some(format!("{};5;{i}", base + 8)),
    }
}

/// The frame as text with ANSI escapes, one row a line.
fn ansi(buf: &Buffer) -> String {
    let area = buf.area;
    let mut out = String::new();
    for y in area.top()..area.bottom() {
        let mut last = String::new();
        for x in area.left()..area.right() {
            let cell = &buf[(x, y)];
            let mut params = vec!["0".to_owned()];
            for (m, code) in [
                (Modifier::BOLD, "1"),
                (Modifier::DIM, "2"),
                (Modifier::ITALIC, "3"),
                (Modifier::UNDERLINED, "4"),
                (Modifier::REVERSED, "7"),
            ] {
                if cell.modifier.contains(m) {
                    params.push(code.to_owned());
                }
            }
            params.extend(sgr_color(cell.fg, 30));
            params.extend(sgr_color(cell.bg, 40));
            let sgr = format!("\u{1b}[{}m", params.join(";"));
            if sgr != last {
                out.push_str(&sgr);
                last = sgr;
            }
            out.push_str(cell.symbol());
        }
        out.push_str("\u{1b}[0m\n");
    }
    out
}

#[test]
#[ignore = "writes files: set RAVEN_TUI_SCREENS to a folder"]
fn screens_to_files() {
    let Some(dir) = std::env::var_os(OUT_ENV) else {
        eprintln!("{OUT_ENV} is not set: nothing written");
        return;
    };
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).expect("the folder");
    for (look_name, look) in looks() {
        for size in SIZES {
            for (screen, app) in screens(look, size) {
                let buf = buffer(&app);
                let name = format!("{screen}-{look_name}-{}x{}", size.0, size.1);
                let mut text = String::new();
                for row in testkit::buffer_lines(&buf) {
                    let _ = writeln!(text, "{}", row.trim_end());
                }
                std::fs::write(dir.join(format!("{name}.txt")), text).expect("a text file");
                std::fs::write(dir.join(format!("{name}.ans")), ansi(&buf)).expect("an ANSI file");
            }
        }
    }
}
