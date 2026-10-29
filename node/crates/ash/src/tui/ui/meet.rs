//! MEET: meeting a friend without the internet, one step at a time (G on
//! Home's friend list and on NET). The guide explains and waits: it never
//! changes Wi-Fi, firewall or system settings, and nothing in it runs a
//! command (testkit's scan).
//!
//! - Step 1: what you need, and who makes the hotspot: 1 this computer, 2
//!   the friend, 3 nobody (you are on the same Wi-Fi already).
//! - Step 2a: how to make one, in the words of the system the app runs on
//!   ([`system`]; render tests set it): Windows' settings, the Linux `nmcli`
//!   command (C shows it alone, to copy), or what a Mac may not do; the
//!   first time, what whoever runs the hotspot can see (UXF.9). Step 2b:
//!   join the friend's Wi-Fi.
//! - Step 3: this computer's addresses while Raven listens on the network:
//!   every one a friend could dial (raven-core's `netifs`, read on the node
//!   worker when the step opens), hotspot first, each with the listener's
//!   port on its own row; and a field for the friend's, saved as CI's E
//!   saves it.
//! - Step 4: connected, once a message from the friend arrived or one of
//!   yours was delivered after G, with how many of the messages waiting then
//!   went and were delivered.
//!
//! Every untrusted string (the friend's name, what was typed, the address a
//! node reports) is drawn through display.rs.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use ratatui::layout::{Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::Frame;

use super::app::{App, BubbleKey, FindState, MeetState, MeetStep};
#[cfg(test)]
use super::app::{
    Cmd, FriendChange, JobResult, Key, MeetFrom, Msg, NodeJob, Overlay, PasteVia, Screen, SendJob,
    Session, StoreJob,
};
use super::bridge;
#[cfg(test)]
use super::bridge::ContactView;
#[cfg(test)]
use super::controller::{Conversations, RowView};
use super::delivery::Tick;
use super::node::NodeState;
#[cfg(test)]
use super::node::{Probe, Vault};
#[cfg(test)]
use super::state_file::Receive;
#[cfg(test)]
use super::testkit;
#[cfg(test)]
use super::theme;
#[cfg(test)]
use super::workers::{FileStamp, PollCtl, PollUpdate};
use super::{add_friend, display, overlays, render_header, verify, wizard, wrap, Look};

const TITLE: &str = " Meet without the internet ";

/// Step 1.
const NEED: &str = "You need:";
const NEEDS: [&str; 2] = [
    "both laptops with Raven open",
    "each other in your Raven friends (if not, add each other now, in person: press A)",
];
const WHO: &str = "One of you makes a small Wi-Fi (a hotspot). The other joins it. Who makes it?";
const CHOICES: [(&str, &str); 3] = [
    ("[1]", " I'll make it"),
    ("[2]", " My friend makes it"),
    ("[3]", " We're already on the same Wi-Fi"),
];

/// Step 2a, in each system's words, then for every system.
const WINDOWS_HOTSPOT: &str = "Open Settings > Network & internet > Mobile hotspot and turn it \
                               on. If Windows says it has no connection to share, let your \
                               friend make it, or use a phone hotspot.";
const LINUX_HOTSPOT: &str = "Run this in another terminal:";
/// The command, with the name and password the user puts in.
const NMCLI: &str = "nmcli device wifi hotspot ssid <name> password <long password>";
const COPY_KEY: (&str, &str) = ("[C]", " Show it alone so you can copy it");
const MAC_HOTSPOT: &str = "A Mac may not make a hotspot without internet. If it doesn't work, \
                           let your friend make it, or use a phone hotspot.";
const PASSWORD: &str = "Pick a long password. Say it out loud. Don't send it in a message.";
/// The first time this profile makes a hotspot (UXF.9).
const WHO_SEES: &str = "Whoever runs the hotspot can see which devices joined, and when.";

/// Step 2b.
const JOIN: &str = "Join the Wi-Fi your friend made. Then come back here.";

/// Step 3. NOT_RECEIVING stands for the address while no listener is on the
/// network: a friend could reach nothing there.
const THIS_COMPUTER: &str = "This computer's network address:";
/// With more than one address a friend could dial.
const THIS_COMPUTER_MANY: &str = "This computer's network addresses:";
const NOT_RECEIVING: &str = "none: Raven isn't receiving from the network now";
const ASK: (&str, &str) = (
    "Ask ",
    " to press G and read you their address. Type it here:",
);
const ONE_OF_YOU: &str = "Only one of you needs to do this.";
const ALLOW: &str =
    "Your computer may ask whether raven-node may accept connections. Choose Allow.";
/// With no saved friend to type an address for.
const NO_FRIEND: &str = "Add your friend in Raven first: press A.";

/// Step 4.
const LEAVING: &str = "When you leave: turn off the hotspot.";

/// The name a friend who has none (or is not saved any more) goes by.
const NO_NAME: &str = "your friend";

/// C on step 2a: the command alone on the plain terminal.
const COPY_HEADING: &str = "Select the command below and copy it with your terminal. Put in a \
                            name and a long password of your own:";
const COPY_FOOTER: &str = "Press any key to go back to Raven.";

const BACK_KEYS: [(&str, &str); 1] = [("[Esc]", " Back")];
const NEXT_KEYS: [(&str, &str); 2] = [("[Enter]", " Next"), ("[Esc]", " Back")];
const ADD_KEYS: [(&str, &str); 2] = [("[A]", " Add a friend"), ("[Esc]", " Back")];
const DONE_KEYS: [(&str, &str); 2] = [("[Enter]", " Open chat"), ("[Esc]", " Back")];
/// Between a card's keys.
const GAP: &str = "   ";

/// The system whose words step 2a uses: the App's, which render tests set.
/// Any system but Windows and macOS gets the Linux words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum System {
    Windows,
    Mac,
    Linux,
}

/// The system the app runs on, as the App has it.
pub(crate) fn system(app: &App) -> System {
    if app.on_windows() {
        System::Windows
    } else if app.on_mac() {
        System::Mac
    } else {
        System::Linux
    }
}

/// C's lines for the plain terminal: how to copy, the command alone, and
/// the way back.
pub(crate) fn copy_lines() -> Vec<String> {
    vec![
        COPY_HEADING.to_owned(),
        String::new(),
        NMCLI.to_owned(),
        String::new(),
        COPY_FOOTER.to_owned(),
    ]
}

/// Draws MEET's step in a card under the header row. On step 3 the
/// terminal's cursor sits after what is typed, unless an overlay is on top.
pub(super) fn render(f: &mut Frame, area: Rect, app: &App, meet: &MeetState, now: Instant) {
    if area.is_empty() {
        return;
    }
    render_header(f, area, app, now, true);
    let body = wizard::under_header(area);
    let look = app.look();
    let width = wizard::text_width(body);
    let (lines, field) = match &meet.step {
        MeetStep::Start => (start(look, width), None),
        MeetStep::MakeHotspot => (make_hotspot(app, meet.hotspot_note, width), None),
        MeetStep::JoinHotspot => (join_hotspot(look, width), None),
        MeetStep::Find(find) => find_rows(app, meet, find, width),
        MeetStep::Connected => (connected(app, meet, width), None),
    };
    let title = Span::styled(TITLE, look.theme.title);
    let (inner, drawn) = wizard::draw_card(f, body, look, Some(title), lines, body.height);
    let Some((field, col)) = field else {
        return;
    };
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

/// Step 1: what you need, and the three answers to who makes the hotspot.
fn start(look: &Look, width: u16) -> Vec<Line<'static>> {
    let mut lines = vec![Line::raw(NEED)];
    for need in NEEDS {
        lines.extend(
            wrap(&format!("{} {need}", look.glyphs.bullet), width, 2)
                .into_iter()
                .map(Line::raw),
        );
    }
    lines.push(Line::default());
    lines.extend(wizard::rows(WHO, width));
    lines.push(Line::default());
    lines.extend(
        CHOICES
            .iter()
            .map(|choice| overlays::keys_line(look, &[*choice])),
    );
    lines.push(Line::default());
    lines.extend(verify::key_rows(look, &BACK_KEYS, GAP, width));
    lines
}

/// Step 2a: how this system makes a hotspot, and the password; with `note`
/// (the first time), what whoever runs it can see.
fn make_hotspot(app: &App, note: bool, width: u16) -> Vec<Line<'static>> {
    let look = app.look();
    let mut lines = Vec::new();
    match system(app) {
        System::Windows => lines.extend(wizard::rows(WINDOWS_HOTSPOT, width)),
        System::Mac => lines.extend(wizard::rows(MAC_HOTSPOT, width)),
        System::Linux => {
            lines.extend(wizard::rows(LINUX_HOTSPOT, width));
            // Three cells in, broken and never cut, as PASSFILE's commands.
            lines.extend(
                overlays::wrap_command(NMCLI, width.saturating_sub(3))
                    .into_iter()
                    .map(|row| {
                        Line::from(vec![Span::raw("   "), Span::styled(row, look.theme.accent)])
                    }),
            );
            lines.push(overlays::keys_line(look, &[COPY_KEY]));
        }
    }
    lines.push(Line::default());
    lines.extend(wizard::rows(PASSWORD, width));
    if note {
        lines.push(Line::default());
        lines.extend(wizard::rows(WHO_SEES, width));
    }
    lines.push(Line::default());
    lines.extend(verify::key_rows(look, &NEXT_KEYS, GAP, width));
    lines
}

/// Step 2b: join the friend's Wi-Fi, then come back.
fn join_hotspot(look: &Look, width: u16) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = wizard::rows(JOIN, width).collect();
    lines.push(Line::default());
    lines.extend(verify::key_rows(look, &NEXT_KEYS, GAP, width));
    lines
}

/// Step 3's rows: this computer's addresses, then the friend's field with
/// what the last Enter found (or how to add a friend first), and the keys.
/// Also the field's row and the cell its cursor goes to, while it has the
/// keys.
fn find_rows(
    app: &App,
    meet: &MeetState,
    find: &FindState,
    width: u16,
) -> (Vec<Line<'static>>, Option<(Line<'static>, usize)>) {
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    let addresses = address_rows(app);
    let heading = if addresses.len() > 1 {
        THIS_COMPUTER_MANY
    } else {
        THIS_COMPUTER
    };
    let mut lines = vec![Line::raw(heading)];
    lines.extend(addresses);
    lines.push(Line::default());
    let friend = meet
        .friend
        .as_deref()
        .filter(|friend| app.friend(friend).is_some());
    let Some(friend) = friend else {
        lines.extend(wizard::rows(NO_FRIEND, width));
        lines.push(Line::default());
        lines.extend(verify::key_rows(look, &ADD_KEYS, GAP, width));
        return (lines, None);
    };
    let name = name_of(app, friend);
    let (before, after) = ASK;
    lines.extend(wizard::rows(&format!("{before}{name}{after}"), width));
    let field = Line::raw(format!("> {}", display::one_line(&find.text, u16::MAX, "")));
    lines.push(field.clone());
    if find.bad {
        lines.extend(add_friend::styled_rows(verify::ADDRESS_BAD, width, t.warn));
    } else if find.saved {
        let saved = match waiting_counts(app, meet) {
            Some((sent, delivered)) => format!("Saved. {}", waiting_words(sent, delivered)),
            None => format!("Saved. Send {name} a message to check that it works."),
        };
        lines.extend(add_friend::styled_rows(&saved, width, t.secondary));
    }
    lines.extend(wizard::rows(ONE_OF_YOU, width));
    lines.push(Line::default());
    lines.extend(wizard::rows(ALLOW, width));
    lines.push(Line::default());
    if find.saving {
        lines.push(Line::raw(format!("Saving{}", g.ellipsis)));
        return (lines, None);
    }
    let mut keys = vec![("[Enter]", " Save")];
    if app.contacts().len() > 1 {
        keys.push((g.up_down, " Another friend"));
    }
    keys.push(("[Esc]", " Back"));
    lines.extend(verify::key_rows(look, &keys, GAP, width));
    let col = field.width();
    (lines, Some((field, col)))
}

/// This computer's addresses, one per row three cells in, while Raven
/// listens on the network: the IP it is bound to, or with every address
/// bound each one a friend could dial that the listener takes (hotspot
/// first; 0.0.0.0, raven-node's default, takes no IPv6 address), with the
/// listener's port. Otherwise one row: that they are being read, can't be
/// told, or that nothing listens on the network (on no network at all, too).
/// The node's own text is never drawn: only the address parsed from it.
fn address_rows(app: &App) -> Vec<Line<'static>> {
    let look = app.look();
    let node = app.node();
    let checking = || format!("checking{}", look.glyphs.ellipsis);
    let addresses = match node.state {
        NodeState::Listening { port } if !app.not_on_any_network() => {
            let bound = node
                .listen
                .as_deref()
                .and_then(|listen| listen.trim().parse::<SocketAddr>().ok());
            let port = bound.map(|at| at.port()).or(port).filter(|&p| p != 0);
            let any = bound.map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |at| at.ip());
            let ips = match bound {
                Some(at) if !at.ip().is_unspecified() => Some(Some(vec![at.ip()])),
                _ => app.lan_addresses().map(|ips| {
                    ips.map(|ips| {
                        ips.iter()
                            .copied()
                            .filter(|&ip| bridge::listener_takes(any, ip))
                            .collect::<Vec<_>>()
                    })
                }),
            };
            let dial = |ip: IpAddr| match port {
                Some(port) => SocketAddr::new(ip, port).to_string(),
                None => ip.to_string(),
            };
            match ips {
                Some(Some(ips)) if ips.is_empty() => Err(NOT_RECEIVING.to_owned()),
                Some(Some(ips)) => Ok(ips.into_iter().map(dial).collect::<Vec<_>>()),
                Some(None) => Err("unknown".to_owned()),
                None => Err(checking()),
            }
        }
        NodeState::Starting { .. } | NodeState::Unknown => Err(checking()),
        _ => Err(NOT_RECEIVING.to_owned()),
    };
    let row =
        |text: String, style: Style| Line::from(vec![Span::raw("   "), Span::styled(text, style)]);
    match addresses {
        Ok(addresses) => addresses
            .into_iter()
            .map(|address| row(address, Style::default().add_modifier(Modifier::BOLD)))
            .collect(),
        Err(why) => vec![row(why, look.theme.secondary)],
    }
}

/// Step 4: connected, how the messages that were waiting went, and the
/// hotspot to turn off when there is one.
fn connected(app: &App, meet: &MeetState, width: u16) -> Vec<Line<'static>> {
    let look = app.look();
    let name = meet
        .friend
        .as_deref()
        .map_or_else(|| NO_NAME.to_owned(), |friend| name_of(app, friend));
    let mut lines =
        add_friend::styled_rows(&format!("Connected to {name}."), width, look.theme.accent);
    if let Some((sent, delivered)) = waiting_counts(app, meet) {
        lines.extend(wizard::rows(&waiting_words(sent, delivered), width));
    }
    if meet.hotspot {
        lines.extend(wizard::rows(LEAVING, width));
    }
    lines.push(Line::default());
    lines.extend(verify::key_rows(look, &DONE_KEYS, GAP, width));
    lines
}

/// The friend's name as the screens draw it, or 'your friend' without one.
fn name_of(app: &App, friend: &str) -> String {
    Some(app.shown_name(friend))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| NO_NAME.to_owned())
}

/// Of the friend's messages that were waiting at G: how many have left this
/// computer, and how many of those were delivered. None when none waited.
fn waiting_counts(app: &App, meet: &MeetState) -> Option<(usize, usize)> {
    let friend = meet.friend.as_deref()?;
    if meet.waiting.is_empty() {
        return None;
    }
    let (mut sent, mut delivered) = (0, 0);
    for mid in &meet.waiting {
        let tick = app
            .find_bubble(friend, &BubbleKey::Mid(mid.clone()))
            .and_then(|bubble| app.tick_view(bubble))
            .map(|view| view.tick);
        match tick {
            Some(Tick::Delivered) => {
                sent += 1;
                delivered += 1;
            }
            Some(Tick::Sent) => sent += 1,
            _ => {}
        }
    }
    Some((sent, delivered))
}

fn waiting_words(sent: usize, delivered: usize) -> String {
    format!("Waiting messages: {sent} sent, {delivered} delivered.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use theme::{Glyphs, Theme};

    /// Home with `friends` saved and `history` loaded, in `look` at `size`:
    /// receiving on, and a raven-node that ran before the app, listening on
    /// every address at port 7420 (so no firewall note opens).
    fn home_in(
        look: Look,
        size: (u16, u16),
        friends: Vec<ContactView>,
        history: Conversations,
    ) -> App {
        home_from(look, size, testkit::session(Receive::On), friends, history)
    }

    /// [`home_in`] for `session`.
    fn home_from(
        look: Look,
        size: (u16, u16),
        session: Session,
        friends: Vec<ContactView>,
        history: Conversations,
    ) -> App {
        let mut app = testkit::app_in(look, size);
        app.start(session);
        for result in [
            JobResult::Vault(Vault::default()),
            JobResult::Probed(testkit::status(4242, "0.0.0.0:7420")),
            JobResult::Managed(None),
            JobResult::Contacts {
                contacts: Ok(friends),
                stamp: FileStamp::default(),
            },
            JobResult::History {
                history: Ok(history),
                stamp: FileStamp::default(),
            },
        ] {
            testkit::send(&mut app, Msg::Job(result));
        }
        app
    }

    fn home(size: (u16, u16), friends: u8) -> App {
        home_in(
            testkit::simple_mono(),
            size,
            (1..=friends).map(testkit::friend).collect(),
            Conversations::new(),
        )
    }

    /// This computer's network addresses answered: 192.168.1.20 alone.
    fn address(app: &mut App) -> Vec<Cmd> {
        addresses(app, &[IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))])
    }

    /// This computer's network addresses answered: `ips`, in that order.
    fn addresses(app: &mut App, ips: &[IpAddr]) -> Vec<Cmd> {
        testkit::send(app, Msg::Job(JobResult::LanAddresses(Some(ips.to_vec()))))
    }

    /// `keys` pressed in turn, each a character (or Enter for '\n').
    fn keys(app: &mut App, keys: &str) -> Vec<Cmd> {
        let mut cmds = Vec::new();
        for c in keys.chars() {
            let code = if c == '\n' {
                KeyCode::Enter
            } else {
                KeyCode::Char(c)
            };
            cmds.extend(testkit::press(app, code));
        }
        cmds
    }

    /// MEET at step 3 for friend 1, this computer's address answered.
    fn finding(size: (u16, u16), friends: u8) -> App {
        let mut app = home(size, friends);
        keys(&mut app, "g3");
        address(&mut app);
        app
    }

    /// My message 1 to friend 1, five minutes old, as the history has it
    /// (`delivery`).
    fn mine(delivery: &str) -> (u8, RowView) {
        (1, testkit::row(1, true, delivery, 5, "see you at noon"))
    }

    /// MEET on step 4 in `look`: friend 1's message 1 was waiting when G was
    /// pressed (raven-node listed it), this computer made the hotspot (1),
    /// and the message was delivered after.
    fn connected_in(look: Look, size: (u16, u16)) -> App {
        let mut app = home_in(
            look,
            size,
            vec![testkit::friend(1)],
            testkit::conversations(&[mine("queued")]),
        );
        testkit::send(
            &mut app,
            testkit::outbox(vec![testkit::outbox_item(1, 1, "queued")]),
        );
        keys(&mut app, "g1\n");
        address(&mut app);
        testkit::reload_rows(&mut app, &[mine("delivered")]);
        app
    }

    /// The row under 'This computer's network address:' at 80x24, its box
    /// and padding taken off.
    fn address_shown(app: &App) -> String {
        let rows = testkit::render(app, 80, 24);
        let at = rows
            .iter()
            .position(|row| row.contains(THIS_COMPUTER))
            .expect("step 3's address heading");
        rows[at + 1].trim().trim_matches('│').trim().to_owned()
    }

    /// The rows under 'This computer's network addresses:' at 80x24, up to
    /// the blank row after them, their box and padding taken off.
    fn addresses_shown(app: &App) -> Vec<String> {
        let rows = testkit::render(app, 80, 24);
        let at = rows
            .iter()
            .position(|row| row.contains(THIS_COMPUTER_MANY))
            .expect("step 3's addresses heading");
        rows[at + 1..]
            .iter()
            .map(|row| row.trim().trim_matches('│').trim().to_owned())
            .take_while(|row| !row.is_empty())
            .collect()
    }

    #[test]
    fn g_opens_meet_from_home_and_net_only() {
        let mut app = home((80, 24), 2);
        // On the friend list, for the highlighted friend; nothing is read
        // or run yet.
        let cmds = keys(&mut app, "jg");
        assert!(cmds.is_empty(), "{cmds:?}");
        let Screen::Meet(meet) = app.screen() else {
            panic!("{:?}", app.screen());
        };
        assert_eq!(meet.step, MeetStep::Start);
        assert_eq!(meet.from, MeetFrom::Home);
        assert_eq!(meet.friend, Some(testkit::friend(2).pub_hex));
        // Esc returns where G was pressed.
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen(), &Screen::Home);
        keys(&mut app, "ng");
        assert!(
            matches!(app.screen(), Screen::Meet(meet) if meet.from == MeetFrom::Network),
            "{:?}",
            app.screen()
        );
        testkit::press(&mut app, KeyCode::Esc);
        assert!(matches!(app.screen(), Screen::Network(net) if net.log.is_none()));
        // Not from NET's log view.
        keys(&mut app, "lg");
        assert!(matches!(app.screen(), Screen::Network(net) if net.log.is_some()));
        testkit::press(&mut app, KeyCode::Esc);
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen(), &Screen::Home);
        // The composer takes it as text; CI and SET have no G.
        keys(&mut app, "\ng");
        assert_eq!(app.screen(), &Screen::Home);
        assert_eq!(app.composer().map(|c| c.text()), Some("g"));
        testkit::press(&mut app, KeyCode::Esc);
        keys(&mut app, "eg");
        assert!(matches!(app.screen(), Screen::FriendPage(_)));
        testkit::press(&mut app, KeyCode::Esc);
        keys(&mut app, "sg");
        assert!(matches!(app.screen(), Screen::Settings(_)));
        testkit::press(&mut app, KeyCode::Esc);
        // A Persian keyboard's G key types LAM: G all the same.
        keys(&mut app, "\u{0644}");
        assert!(
            matches!(app.screen(), Screen::Meet(_)),
            "{:?}",
            app.screen()
        );
    }

    #[test]
    fn every_step_at_80x24() {
        let mut app = home((80, 24), 1);
        keys(&mut app, "g");
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Meet without the internet           * Listening on port 7420  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌ Meet without the internet ───────────────────────────────────┐        ",
                "        │ You need:                                                    │        ",
                "        │ - both laptops with Raven open                               │        ",
                "        │ - each other in your Raven friends (if not, add each other   │        ",
                "        │   now, in person: press A)                                   │        ",
                "        │                                                              │        ",
                "        │ One of you makes a small Wi-Fi (a hotspot). The other joins  │        ",
                "        │ it. Who makes it?                                            │        ",
                "        │                                                              │        ",
                "        │ [1] I'll make it                                             │        ",
                "        │ [2] My friend makes it                                       │        ",
                "        │ [3] We're already on the same Wi-Fi                          │        ",
                "        │                                                              │        ",
                "        │ [Esc] Back                                                   │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        keys(&mut app, "1");
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Meet without the internet           * Listening on port 7420  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌ Meet without the internet ───────────────────────────────────┐        ",
                "        │ Run this in another terminal:                                │        ",
                "        │    nmcli device wifi hotspot ssid <name> password <long      │        ",
                "        │    password>                                                 │        ",
                "        │ [C] Show it alone so you can copy it                         │        ",
                "        │                                                              │        ",
                "        │ Pick a long password. Say it out loud. Don't send it in a    │        ",
                "        │ message.                                                     │        ",
                "        │                                                              │        ",
                "        │ [Enter] Next   [Esc] Back                                    │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        let mut join = home((80, 24), 1);
        keys(&mut join, "g2");
        testkit::assert_rows(
            &testkit::render(&join, 80, 24),
            &[
                "R A V E N - Meet without the internet           * Listening on port 7420  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌ Meet without the internet ───────────────────────────────────┐        ",
                "        │ Join the Wi-Fi your friend made. Then come back here.        │        ",
                "        │                                                              │        ",
                "        │ [Enter] Next   [Esc] Back                                    │        ",
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
        let cmds = keys(&mut app, "\n");
        // Joining a hotspot changes this computer's addresses: read again.
        assert!(cmds.contains(&Cmd::Node(NodeJob::LanAddresses)), "{cmds:?}");
        address(&mut app);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Meet without the internet           * Listening on port 7420  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌ Meet without the internet ───────────────────────────────────┐        ",
                "        │ This computer's network address:                             │        ",
                "        │    192.168.1.20:7420                                         │        ",
                "        │                                                              │        ",
                "        │ Ask Friend 1 to press G and read you their address. Type it  │        ",
                "        │ here:                                                        │        ",
                "        │ >                                                            │        ",
                "        │ Only one of you needs to do this.                            │        ",
                "        │                                                              │        ",
                "        │ Your computer may ask whether raven-node may accept          │        ",
                "        │ connections. Choose Allow.                                   │        ",
                "        │                                                              │        ",
                "        │ [Enter] Save   [Esc] Back                                    │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        testkit::assert_rows(
            &testkit::render(&connected_in(testkit::simple_mono(), (80, 24)), 80, 24),
            &[
                "R A V E N - Meet without the internet           * Listening on port 7420  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌ Meet without the internet ───────────────────────────────────┐        ",
                "        │ Connected to Friend 1.                                       │        ",
                "        │ Waiting messages: 1 sent, 1 delivered.                       │        ",
                "        │ When you leave: turn off the hotspot.                        │        ",
                "        │                                                              │        ",
                "        │ [Enter] Open chat   [Esc] Back                               │        ",
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
    fn every_step_at_60x16() {
        let mut app = home((60, 16), 1);
        keys(&mut app, "g");
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N                   * Listening on port 7420  ? Help",
                "┌ Meet without the internet ───────────────────────────────┐",
                "│ You need:                                                │",
                "│ - both laptops with Raven open                           │",
                "│ - each other in your Raven friends (if not, add each     │",
                "│   other now, in person: press A)                         │",
                "│                                                          │",
                "│ One of you makes a small Wi-Fi (a hotspot). The other    │",
                "│ joins it. Who makes it?                                  │",
                "│                                                          │",
                "│ [1] I'll make it                                         │",
                "│ [2] My friend makes it                                   │",
                "│ [3] We're already on the same Wi-Fi                      │",
                "│                                                          │",
                "│ [Esc] Back                                               │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
        keys(&mut app, "1");
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N                   * Listening on port 7420  ? Help",
                "                                                            ",
                "                                                            ",
                "┌ Meet without the internet ───────────────────────────────┐",
                "│ Run this in another terminal:                            │",
                "│    nmcli device wifi hotspot ssid <name> password <long  │",
                "│    password>                                             │",
                "│ [C] Show it alone so you can copy it                     │",
                "│                                                          │",
                "│ Pick a long password. Say it out loud. Don't send it in  │",
                "│ a message.                                               │",
                "│                                                          │",
                "│ [Enter] Next   [Esc] Back                                │",
                "└──────────────────────────────────────────────────────────┘",
                "                                                            ",
                "                                                            ",
            ],
        );
        let mut join = home((60, 16), 1);
        keys(&mut join, "g2");
        testkit::assert_rows(
            &testkit::render(&join, 60, 16),
            &[
                "R A V E N                   * Listening on port 7420  ? Help",
                "                                                            ",
                "                                                            ",
                "                                                            ",
                "                                                            ",
                "                                                            ",
                "┌ Meet without the internet ───────────────────────────────┐",
                "│ Join the Wi-Fi your friend made. Then come back here.    │",
                "│                                                          │",
                "│ [Enter] Next   [Esc] Back                                │",
                "└──────────────────────────────────────────────────────────┘",
                "                                                            ",
                "                                                            ",
                "                                                            ",
                "                                                            ",
                "                                                            ",
            ],
        );
        keys(&mut app, "\n");
        address(&mut app);
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N                   * Listening on port 7420  ? Help",
                "┌ Meet without the internet ───────────────────────────────┐",
                "│ This computer's network address:                         │",
                "│    192.168.1.20:7420                                     │",
                "│                                                          │",
                "│ Ask Friend 1 to press G and read you their address. Type │",
                "│ it here:                                                 │",
                "│ >                                                        │",
                "│ Only one of you needs to do this.                        │",
                "│                                                          │",
                "│ Your computer may ask whether raven-node may accept      │",
                "│ connections. Choose Allow.                               │",
                "│                                                          │",
                "│ [Enter] Save   [Esc] Back                                │",
                "└──────────────────────────────────────────────────────────┘",
                "                                                            ",
            ],
        );
        testkit::assert_rows(
            &testkit::render(&connected_in(testkit::simple_mono(), (60, 16)), 60, 16),
            &[
                "R A V E N                   * Listening on port 7420  ? Help",
                "                                                            ",
                "                                                            ",
                "                                                            ",
                "                                                            ",
                "┌ Meet without the internet ───────────────────────────────┐",
                "│ Connected to Friend 1.                                   │",
                "│ Waiting messages: 1 sent, 1 delivered.                   │",
                "│ When you leave: turn off the hotspot.                    │",
                "│                                                          │",
                "│ [Enter] Open chat   [Esc] Back                           │",
                "└──────────────────────────────────────────────────────────┘",
                "                                                            ",
                "                                                            ",
                "                                                            ",
                "                                                            ",
            ],
        );
    }

    /// Step 2a in a terminal of `size` on Windows (`windows`) or macOS.
    fn hotspot_on(size: (u16, u16), windows: bool) -> App {
        let mut app = home(size, 1);
        app.set_windows_for_tests(windows);
        app.set_mac_for_tests(!windows);
        keys(&mut app, "g1");
        app
    }

    /// [`home`] with one friend, for a profile that has not made a hotspot
    /// with Raven yet (UXF.9); the other notes were seen.
    fn before_a_hotspot(size: (u16, u16)) -> App {
        let mut session = testkit::session(Receive::On);
        session.settings.hotspot_note_shown = false;
        home_from(
            testkit::simple_mono(),
            size,
            session,
            vec![testkit::friend(1)],
            Conversations::new(),
        )
    }

    fn saves_notes(cmds: &[Cmd]) -> bool {
        cmds.iter()
            .any(|cmd| matches!(cmd, Cmd::Store(StoreJob::SaveReadMarks(_))))
    }

    #[test]
    fn the_first_hotspot_says_what_whoever_runs_it_can_see() {
        let mut app = before_a_hotspot((80, 24));
        let cmds = keys(&mut app, "g1");
        assert!(cmds.iter().any(|cmd| matches!(
            cmd,
            Cmd::Store(StoreJob::SaveReadMarks(state)) if state.hotspot_note_shown
        )));
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Meet without the internet           * Listening on port 7420  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌ Meet without the internet ───────────────────────────────────┐        ",
                "        │ Run this in another terminal:                                │        ",
                "        │    nmcli device wifi hotspot ssid <name> password <long      │        ",
                "        │    password>                                                 │        ",
                "        │ [C] Show it alone so you can copy it                         │        ",
                "        │                                                              │        ",
                "        │ Pick a long password. Say it out loud. Don't send it in a    │        ",
                "        │ message.                                                     │        ",
                "        │                                                              │        ",
                "        │ Whoever runs the hotspot can see which devices joined, and   │        ",
                "        │ when.                                                        │        ",
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
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N                   * Listening on port 7420  ? Help",
                "┌ Meet without the internet ───────────────────────────────┐",
                "│ Run this in another terminal:                            │",
                "│    nmcli device wifi hotspot ssid <name> password <long  │",
                "│    password>                                             │",
                "│ [C] Show it alone so you can copy it                     │",
                "│                                                          │",
                "│ Pick a long password. Say it out loud. Don't send it in  │",
                "│ a message.                                               │",
                "│                                                          │",
                "│ Whoever runs the hotspot can see which devices joined,   │",
                "│ and when.                                                │",
                "│                                                          │",
                "│ [Enter] Next   [Esc] Back                                │",
                "└──────────────────────────────────────────────────────────┘",
                "                                                            ",
            ],
        );
        // Back from C's copy view, it still says so on this visit.
        keys(&mut app, "c");
        testkit::press(&mut app, KeyCode::Char('x'));
        assert!(screen_text(&app).contains(WHO_SEES));
        // The next time: neither the note nor a save.
        testkit::press(&mut app, KeyCode::Esc);
        let cmds = keys(&mut app, "g1");
        assert!(!saves_notes(&cmds), "{cmds:?}");
        assert!(matches!(app.screen(), Screen::Meet(meet) if meet.step == MeetStep::MakeHotspot));
        assert!(!screen_text(&app).contains(WHO_SEES));
        // Joining the friend's hotspot (2b) leaves it for the first one made.
        let mut app = before_a_hotspot((80, 24));
        let cmds = keys(&mut app, "g2");
        assert!(!saves_notes(&cmds), "{cmds:?}");
        assert!(!screen_text(&app).contains(WHO_SEES));
        assert!(!app.settings().hotspot_note_shown);
    }

    fn screen_text(app: &App) -> String {
        testkit::screen_text(&testkit::render(app, 80, 24))
    }

    #[test]
    fn the_hotspot_step_speaks_each_systems_words() {
        testkit::assert_rows(
            &testkit::render(&hotspot_on((80, 24), true), 80, 24),
            &[
                "R A V E N - Meet without the internet           * Listening on port 7420  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌ Meet without the internet ───────────────────────────────────┐        ",
                "        │ Open Settings > Network & internet > Mobile hotspot and turn │        ",
                "        │ it on. If Windows says it has no connection to share, let    │        ",
                "        │ your friend make it, or use a phone hotspot.                 │        ",
                "        │                                                              │        ",
                "        │ Pick a long password. Say it out loud. Don't send it in a    │        ",
                "        │ message.                                                     │        ",
                "        │                                                              │        ",
                "        │ [Enter] Next   [Esc] Back                                    │        ",
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
        testkit::assert_rows(
            &testkit::render(&hotspot_on((60, 16), true), 60, 16),
            &[
                "R A V E N                   * Listening on port 7420  ? Help",
                "                                                            ",
                "                                                            ",
                "┌ Meet without the internet ───────────────────────────────┐",
                "│ Open Settings > Network & internet > Mobile hotspot and  │",
                "│ turn it on. If Windows says it has no connection to      │",
                "│ share, let your friend make it, or use a phone hotspot.  │",
                "│                                                          │",
                "│ Pick a long password. Say it out loud. Don't send it in  │",
                "│ a message.                                               │",
                "│                                                          │",
                "│ [Enter] Next   [Esc] Back                                │",
                "└──────────────────────────────────────────────────────────┘",
                "                                                            ",
                "                                                            ",
                "                                                            ",
            ],
        );
        testkit::assert_rows(
            &testkit::render(&hotspot_on((80, 24), false), 80, 24),
            &[
                "R A V E N - Meet without the internet           * Listening on port 7420  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌ Meet without the internet ───────────────────────────────────┐        ",
                "        │ A Mac may not make a hotspot without internet. If it doesn't │        ",
                "        │ work, let your friend make it, or use a phone hotspot.       │        ",
                "        │                                                              │        ",
                "        │ Pick a long password. Say it out loud. Don't send it in a    │        ",
                "        │ message.                                                     │        ",
                "        │                                                              │        ",
                "        │ [Enter] Next   [Esc] Back                                    │        ",
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
        testkit::assert_rows(
            &testkit::render(&hotspot_on((60, 16), false), 60, 16),
            &[
                "R A V E N                   * Listening on port 7420  ? Help",
                "                                                            ",
                "                                                            ",
                "┌ Meet without the internet ───────────────────────────────┐",
                "│ A Mac may not make a hotspot without internet. If it     │",
                "│ doesn't work, let your friend make it, or use a phone    │",
                "│ hotspot.                                                 │",
                "│                                                          │",
                "│ Pick a long password. Say it out loud. Don't send it in  │",
                "│ a message.                                               │",
                "│                                                          │",
                "│ [Enter] Next   [Esc] Back                                │",
                "└──────────────────────────────────────────────────────────┘",
                "                                                            ",
                "                                                            ",
                "                                                            ",
            ],
        );
        // What the App runs on decides, and only Windows and macOS have
        // words of their own.
        let mut app = home((80, 24), 1);
        assert_eq!(system(&app), System::Linux);
        app.set_mac_for_tests(true);
        assert_eq!(system(&app), System::Mac);
        app.set_mac_for_tests(false);
        app.set_windows_for_tests(true);
        assert_eq!(system(&app), System::Windows);
    }

    #[test]
    fn fancy_and_ascii_glyphs() {
        let fancy = Look {
            glyphs: Glyphs::fancy(),
            theme: Theme::mono(),
            ..testkit::simple_mono()
        };
        let mut app = home_in(
            fancy,
            (80, 24),
            vec![testkit::friend(1)],
            Conversations::new(),
        );
        keys(&mut app, "g");
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N · Meet without the internet          ● Listening on port 7420 · ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ╭ Meet without the internet ───────────────────────────────────╮        ",
                "        │ You need:                                                    │        ",
                "        │ • both laptops with Raven open                               │        ",
                "        │ • each other in your Raven friends (if not, add each other   │        ",
                "        │   now, in person: press A)                                   │        ",
                "        │                                                              │        ",
                "        │ One of you makes a small Wi-Fi (a hotspot). The other joins  │        ",
                "        │ it. Who makes it?                                            │        ",
                "        │                                                              │        ",
                "        │ [1] I'll make it                                             │        ",
                "        │ [2] My friend makes it                                       │        ",
                "        │ [3] We're already on the same Wi-Fi                          │        ",
                "        │                                                              │        ",
                "        │ [Esc] Back                                                   │        ",
                "        ╰──────────────────────────────────────────────────────────────╯        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        let ascii = Look {
            glyphs: Glyphs::ascii(),
            ..testkit::simple_mono()
        };
        let mut app = home_in(
            ascii,
            (60, 16),
            (1..=2).map(testkit::friend).collect(),
            Conversations::new(),
        );
        keys(&mut app, "g3");
        address(&mut app);
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N                   * Listening on port 7420  ? Help",
                "+ Meet without the internet -------------------------------+",
                "| This computer's network address:                         |",
                "|    192.168.1.20:7420                                     |",
                "|                                                          |",
                "| Ask Friend 1 to press G and read you their address. Type |",
                "| it here:                                                 |",
                "| >                                                        |",
                "| Only one of you needs to do this.                        |",
                "|                                                          |",
                "| Your computer may ask whether raven-node may accept      |",
                "| connections. Choose Allow.                               |",
                "|                                                          |",
                "| [Enter] Save   Up/Down Another friend   [Esc] Back       |",
                "+----------------------------------------------------------+",
                "                                                            ",
            ],
        );
        testkit::assert_rows(
            &testkit::render(&connected_in(ascii, (60, 16)), 60, 16),
            &[
                "R A V E N                   * Listening on port 7420  ? Help",
                "                                                            ",
                "                                                            ",
                "                                                            ",
                "                                                            ",
                "+ Meet without the internet -------------------------------+",
                "| Connected to Friend 1.                                   |",
                "| Waiting messages: 1 sent, 1 delivered.                   |",
                "| When you leave: turn off the hotspot.                    |",
                "|                                                          |",
                "| [Enter] Open chat   [Esc] Back                           |",
                "+----------------------------------------------------------+",
                "                                                            ",
                "                                                            ",
                "                                                            ",
                "                                                            ",
            ],
        );
    }

    /// The friend `n`'s key.
    fn key_of(n: u8) -> String {
        testkit::friend(n).pub_hex
    }

    /// MEET's step, or a panic on any other screen.
    fn step(app: &App) -> &MeetStep {
        match app.screen() {
            Screen::Meet(meet) => &meet.step,
            other => panic!("not MEET: {other:?}"),
        }
    }

    /// Step 3's field as it stands.
    fn find(app: &App) -> &FindState {
        match step(app) {
            MeetStep::Find(find) => find,
            other => panic!("not step 3: {other:?}"),
        }
    }

    fn text(app: &App) -> String {
        testkit::screen_text(&testkit::render(app, 80, 24))
    }

    /// The store worker's answer to the save of friend `n`'s address.
    fn saved(app: &mut App, n: u8, result: Result<(), String>) -> Vec<Cmd> {
        testkit::send(
            app,
            Msg::Job(JobResult::FriendChanged {
                change: FriendChange::Address,
                pub_hex: key_of(n),
                result,
                notes: Vec::new(),
            }),
        )
    }

    /// Every command the guide may hand out: this computer's addresses read
    /// (nothing is sent), the friend's address saved and the friends loaded
    /// again, one retry of what already waits, the poller's words, and COPY
    /// (with Ctrl+L's redraw).
    fn harmless(cmd: &Cmd) -> bool {
        matches!(
            cmd,
            Cmd::Node(NodeJob::LanAddresses)
                | Cmd::Store(StoreJob::SetFriendAddress { .. } | StoreJob::LoadContacts)
                | Cmd::Send(SendJob::Retry { .. })
                | Cmd::Poll(_)
                | Cmd::Peek(_)
                | Cmd::Unpeek
                | Cmd::Redraw
        )
    }

    #[test]
    fn an_address_typed_is_saved_for_the_friend_and_their_messages_tried_once() {
        let mut app = home_in(
            testkit::simple_mono(),
            (80, 24),
            vec![testkit::friend(1)],
            testkit::conversations(&[mine("queued")]),
        );
        testkit::send(
            &mut app,
            testkit::outbox(vec![testkit::outbox_item(1, 1, "queued")]),
        );
        keys(&mut app, "g3");
        address(&mut app);
        // A Persian keyboard's number row types 0-9 here.
        let typed = testkit::digits_from("10.42.0.1:7420", testkit::PERSIAN_ZERO);
        let cmds = keys(&mut app, &typed);
        assert!(cmds.is_empty(), "{cmds:?}");
        assert_eq!(find(&app).text, "10.42.0.1:7420");
        let cmds = keys(&mut app, "\n");
        assert!(cmds.iter().all(harmless), "{cmds:?}");
        let saves: Vec<&Cmd> = cmds
            .iter()
            .filter(|cmd| matches!(cmd, Cmd::Store(_)))
            .collect();
        assert_eq!(
            saves,
            [&Cmd::Store(StoreJob::SetFriendAddress {
                pub_hex: key_of(1),
                address: "10.42.0.1:7420".into(),
            })]
        );
        // The keys wait for the save, Esc too.
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Meet without the internet           * Listening on port 7420  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌ Meet without the internet ───────────────────────────────────┐        ",
                "        │ This computer's network address:                             │        ",
                "        │    192.168.1.20:7420                                         │        ",
                "        │                                                              │        ",
                "        │ Ask Friend 1 to press G and read you their address. Type it  │        ",
                "        │ here:                                                        │        ",
                "        │ > 10.42.0.1:7420                                             │        ",
                "        │ Only one of you needs to do this.                            │        ",
                "        │                                                              │        ",
                "        │ Your computer may ask whether raven-node may accept          │        ",
                "        │ connections. Choose Allow.                                   │        ",
                "        │                                                              │        ",
                "        │ Saving...                                                    │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        keys(&mut app, "9");
        testkit::press(&mut app, KeyCode::Esc);
        assert!(find(&app).saving);
        assert_eq!(find(&app).text, "10.42.0.1:7420");
        // Saved: one retry, which has raven-node try every message waiting
        // for them; the guide says so itself, with no toast.
        let cmds = saved(&mut app, 1, Ok(()));
        assert!(cmds.iter().all(harmless), "{cmds:?}");
        let retries: Vec<&Cmd> = cmds
            .iter()
            .filter(|cmd| matches!(cmd, Cmd::Send(_)))
            .collect();
        let mid = format!("{:032x}", 1);
        assert_eq!(
            retries,
            [&Cmd::Send(SendJob::Retry {
                mid: mid.clone(),
                peer: key_of(1),
            })]
        );
        assert_eq!(
            app.friend(&key_of(1)).map(|f| f.lan_dial.as_str()),
            Some("10.42.0.1:7420")
        );
        let cmds = testkit::send(
            &mut app,
            Msg::Job(JobResult::Retried {
                mid,
                peer: key_of(1),
                result: Ok(()),
                captured: String::new(),
            }),
        );
        assert!(
            cmds.contains(&Cmd::Poll(PollCtl::Burst { peer: key_of(1) })),
            "{cmds:?}"
        );
        assert!(
            app.toasts_for_tests().is_empty(),
            "{:?}",
            app.toasts_for_tests()
        );
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Meet without the internet           * Listening on port 7420  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌ Meet without the internet ───────────────────────────────────┐        ",
                "        │ This computer's network address:                             │        ",
                "        │    192.168.1.20:7420                                         │        ",
                "        │                                                              │        ",
                "        │ Ask Friend 1 to press G and read you their address. Type it  │        ",
                "        │ here:                                                        │        ",
                "        │ > 10.42.0.1:7420                                             │        ",
                "        │ Saved. Waiting messages: 0 sent, 0 delivered.                │        ",
                "        │ Only one of you needs to do this.                            │        ",
                "        │                                                              │        ",
                "        │ Your computer may ask whether raven-node may accept          │        ",
                "        │ connections. Choose Allow.                                   │        ",
                "        │                                                              │        ",
                "        │ [Enter] Save   [Esc] Back                                    │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        // It left this computer: counted as it goes.
        testkit::send(
            &mut app,
            testkit::outbox(vec![testkit::outbox_item(1, 1, "sent")]),
        );
        assert!(
            text(&app).contains("Saved. Waiting messages: 1 sent, 0 delivered."),
            "{}",
            text(&app)
        );
        // Typing again: not saved any more.
        keys(&mut app, "1");
        assert!(!text(&app).contains("Saved."), "{}", text(&app));
    }

    #[test]
    fn with_nothing_waiting_there_is_no_retry_and_a_message_checks_it() {
        let mut app = finding((80, 24), 1);
        keys(&mut app, "10.42.0.1:7420\n");
        let cmds = saved(&mut app, 1, Ok(()));
        assert!(
            !cmds.iter().any(|cmd| matches!(cmd, Cmd::Send(_))),
            "{cmds:?}"
        );
        assert!(
            text(&app).contains("Saved. Send Friend 1 a message to check that it works."),
            "{}",
            text(&app)
        );
    }

    #[test]
    fn a_bad_address_is_refused_and_a_failed_save_keeps_it() {
        let mut app = finding((80, 24), 1);
        // No port: not an address Raven can use, and nothing is saved.
        let cmds = keys(&mut app, "10.42.0.1\n");
        assert!(
            !cmds.iter().any(|cmd| matches!(cmd, Cmd::Store(_))),
            "{cmds:?}"
        );
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Meet without the internet           * Listening on port 7420  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌ Meet without the internet ───────────────────────────────────┐        ",
                "        │ This computer's network address:                             │        ",
                "        │    192.168.1.20:7420                                         │        ",
                "        │                                                              │        ",
                "        │ Ask Friend 1 to press G and read you their address. Type it  │        ",
                "        │ here:                                                        │        ",
                "        │ > 10.42.0.1                                                  │        ",
                "        │ That isn't an address Raven can use. It looks like           │        ",
                "        │ 192.168.1.30:7420.                                           │        ",
                "        │ Only one of you needs to do this.                            │        ",
                "        │                                                              │        ",
                "        │ Your computer may ask whether raven-node may accept          │        ",
                "        │ connections. Choose Allow.                                   │        ",
                "        │                                                              │        ",
                "        │ [Enter] Save   [Esc] Back                                    │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
            ],
        );
        keys(&mut app, ":7420");
        assert!(!find(&app).bad);
        keys(&mut app, "\n");
        // The save failed: why, in a toast; the address stays for Enter.
        saved(
            &mut app,
            1,
            Err("contacts.json: Permission denied (os error 13)".into()),
        );
        assert_eq!(
            app.toasts_for_tests().len(),
            1,
            "{:?}",
            app.toasts_for_tests()
        );
        assert_eq!(
            find(&app),
            &FindState {
                text: "10.42.0.1:7420".into(),
                ..FindState::default()
            }
        );
        assert_eq!(
            app.friend(&key_of(1)).map(|f| f.lan_dial.as_str()),
            Some("")
        );
        // A paste is text in the field, and Enter waits out the paste guard.
        for _ in 0..14 {
            testkit::press(&mut app, KeyCode::Backspace);
        }
        assert_eq!(find(&app).text, "");
        testkit::paste(&mut app, "192.168.7.31:7420", PasteVia::Bracketed);
        assert_eq!(find(&app).text, "192.168.7.31:7420");
        assert!(keys(&mut app, "\n").is_empty());
        testkit::tick(&mut app, Duration::from_millis(300));
        let cmds = keys(&mut app, "\n");
        assert!(
            cmds.contains(&Cmd::Store(StoreJob::SetFriendAddress {
                pub_hex: key_of(1),
                address: "192.168.7.31:7420".into(),
            })),
            "{cmds:?}"
        );
    }

    #[test]
    fn connected_once_a_message_arrives_or_one_is_delivered_after_g() {
        let mut app = home_in(
            testkit::simple_mono(),
            (80, 24),
            vec![testkit::friend(1)],
            testkit::conversations(&[mine("queued")]),
        );
        // Delivered before G: that says nothing about now.
        testkit::reload_rows(&mut app, &[mine("delivered")]);
        testkit::tick(&mut app, Duration::from_secs(1));
        keys(&mut app, "g3");
        assert!(matches!(step(&app), MeetStep::Find(_)));
        // Their message arrives after G: connected. With nothing that was
        // waiting and no hotspot, those lines go.
        let theirs = (1, testkit::row(2, false, "", 0, "I'm here"));
        testkit::reload_rows(&mut app, &[mine("delivered"), theirs.clone()]);
        assert_eq!(step(&app), &MeetStep::Connected);
        // The bottom row: Home's toast (UXF.8) for the delivery before G.
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Meet without the internet           * Listening on port 7420  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌ Meet without the internet ───────────────────────────────────┐        ",
                "        │ Connected to Friend 1.                                       │        ",
                "        │                                                              │        ",
                "        │ [Enter] Open chat   [Esc] Back                               │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "Delivered 1 message to Friend 1.                                                ",
            ],
        );
        // Enter opens the chat.
        keys(&mut app, "\n");
        assert_eq!(app.screen(), &Screen::Home);
        assert_eq!(app.open_friend(), Some(key_of(1).as_str()));
        // Connected while step 1 or 2 is read: step 3 is step 4 at once.
        let mut app = home((80, 24), 1);
        keys(&mut app, "g2");
        testkit::reload_rows(&mut app, &[theirs]);
        assert_eq!(step(&app), &MeetStep::JoinHotspot);
        keys(&mut app, "\n");
        assert_eq!(step(&app), &MeetStep::Connected);
    }

    #[test]
    fn up_and_down_choose_another_friend_on_step_3() {
        let mut app = finding((80, 24), 2);
        keys(&mut app, "10.42");
        assert!(
            text(&app).contains("Ask Friend 1 to press G"),
            "{}",
            text(&app)
        );
        assert!(
            text(&app).contains("Up/Down Another friend"),
            "{}",
            text(&app)
        );
        testkit::press(&mut app, KeyCode::Down);
        assert!(
            text(&app).contains("Ask Friend 2 to press G"),
            "{}",
            text(&app)
        );
        assert_eq!(find(&app).text, "");
        // The list ends there.
        testkit::press(&mut app, KeyCode::Down);
        assert!(
            text(&app).contains("Ask Friend 2 to press G"),
            "{}",
            text(&app)
        );
        testkit::press(&mut app, KeyCode::Up);
        assert!(
            text(&app).contains("Ask Friend 1 to press G"),
            "{}",
            text(&app)
        );
        // With one friend, nobody else to choose.
        assert!(!text(&finding((80, 24), 1)).contains("Another friend"));
    }

    #[test]
    fn with_no_friend_saved_the_guide_offers_to_add_one() {
        let mut app = home((80, 24), 0);
        keys(&mut app, "g");
        assert!(matches!(app.screen(), Screen::Meet(meet) if meet.friend.is_none()));
        keys(&mut app, "3");
        address(&mut app);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Meet without the internet           * Listening on port 7420  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌ Meet without the internet ───────────────────────────────────┐        ",
                "        │ This computer's network address:                             │        ",
                "        │    192.168.1.20:7420                                         │        ",
                "        │                                                              │        ",
                "        │ Add your friend in Raven first: press A.                     │        ",
                "        │                                                              │        ",
                "        │ [A] Add a friend   [Esc] Back                                │        ",
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
        keys(&mut app, "a");
        assert!(
            matches!(app.screen(), Screen::AddFriend(_)),
            "{:?}",
            app.screen()
        );
        // Step 1's A too.
        let mut app = home((80, 24), 1);
        keys(&mut app, "ga");
        assert!(
            matches!(app.screen(), Screen::AddFriend(_)),
            "{:?}",
            app.screen()
        );
    }

    #[test]
    fn c_shows_the_command_alone_on_linux_only() {
        let mut app = home((80, 24), 1);
        let cmds = keys(&mut app, "g1c");
        assert!(cmds.contains(&Cmd::Peek(copy_lines())), "{cmds:?}");
        assert!(app.peeking());
        assert_eq!(copy_lines()[2], NMCLI);
        // Any key brings the screen back, and does nothing more.
        assert_eq!(keys(&mut app, "2"), [Cmd::Unpeek]);
        assert!(!app.peeking());
        assert_eq!(step(&app), &MeetStep::MakeHotspot);
        // Windows and macOS have no command; nor has step 2b.
        for windows in [true, false] {
            let mut app = hotspot_on((80, 24), windows);
            assert!(keys(&mut app, "c").is_empty());
            assert!(!app.peeking());
        }
        let mut app = home((80, 24), 1);
        assert!(keys(&mut app, "g2c").is_empty());
        assert!(!app.peeking());
    }

    #[test]
    fn no_step_runs_a_system_command() {
        // Each step, as a new app gets there.
        type Start = fn() -> App;
        let starts: [(&str, Start); 9] = [
            ("step 1", || {
                let mut app = home((80, 24), 2);
                keys(&mut app, "g");
                app
            }),
            ("step 2a on Linux", || {
                let mut app = home((80, 24), 2);
                keys(&mut app, "g1");
                app
            }),
            ("step 2a on Windows", || hotspot_on((80, 24), true)),
            ("step 2a on macOS", || hotspot_on((80, 24), false)),
            ("step 2b", || {
                let mut app = home((80, 24), 2);
                keys(&mut app, "g2");
                app
            }),
            ("step 3", || finding((80, 24), 2)),
            ("step 3 with an address", || {
                let mut app = finding((80, 24), 2);
                keys(&mut app, "10.42.0.1:7420");
                app
            }),
            ("step 3 with no friend", || {
                let mut app = home((80, 24), 0);
                keys(&mut app, "g3");
                app
            }),
            ("step 4", || connected_in(testkit::simple_mono(), (80, 24))),
        ];
        let plain = |code| KeyEvent::new(code, KeyModifiers::NONE);
        // Every printable key but A, which opens Add a friend: a screen of
        // its own, which starts Raven's background program as OD-3 says.
        let mut presses: Vec<KeyEvent> = (' '..='~')
            .filter(|c| !c.eq_ignore_ascii_case(&'a'))
            .map(|c| plain(KeyCode::Char(c)))
            .collect();
        presses.extend(
            [
                KeyCode::Enter,
                KeyCode::Esc,
                KeyCode::Tab,
                KeyCode::BackTab,
                KeyCode::Backspace,
                KeyCode::Delete,
                KeyCode::Up,
                KeyCode::Down,
                KeyCode::Left,
                KeyCode::Right,
                KeyCode::Home,
                KeyCode::End,
                KeyCode::PageUp,
                KeyCode::PageDown,
                KeyCode::Char('\u{0644}'),
                KeyCode::Char('\u{06F3}'),
            ]
            .map(plain),
        );
        for c in ['c', 'l', 'u', 'j'] {
            presses.push(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL));
        }
        for (name, start) in starts {
            for key in &presses {
                let mut app = start();
                let cmds = testkit::send(&mut app, Msg::Key(Key::Event(*key)));
                assert!(cmds.iter().all(harmless), "{name}, {key:?}: {cmds:?}");
            }
        }
    }

    #[test]
    fn step_1_takes_its_answer_from_a_persian_or_arabic_number_row() {
        for (zero, answer, then) in [
            (testkit::PERSIAN_ZERO, "1", MeetStep::MakeHotspot),
            (testkit::ARABIC_INDIC_ZERO, "2", MeetStep::JoinHotspot),
        ] {
            let mut app = home((80, 24), 1);
            keys(&mut app, "g");
            keys(&mut app, &testkit::digits_from(answer, zero));
            assert_eq!(step(&app), &then);
        }
    }

    #[test]
    fn help_lists_the_guides_keys() {
        let mut app = home((80, 24), 1);
        keys(&mut app, "g?");
        assert_eq!(app.overlays(), [Overlay::Help { scroll: 0 }]);
        let text = testkit::screen_text(&testkit::render(&app, 80, 24));
        for words in [
            "1, 2, 3 Who makes the hotspot",
            "C Show the command alone (Linux)",
            "Up, Down Another friend",
        ] {
            assert!(text.contains(words), "{words}: {text}");
        }
        // NET's HELP has G.
        let mut app = home((80, 24), 1);
        keys(&mut app, "n?");
        let text = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(text.contains("G Meet without the internet"), "{text}");
        // In step 3's field ? is text.
        let mut app = finding((80, 24), 1);
        keys(&mut app, "?");
        assert!(app.overlays().is_empty());
        assert_eq!(find(&app).text, "?");
    }

    /// This computer hosts a hotspot and is on a Wi-Fi too: both
    /// addresses, the hotspot first, each with the port on its own row.
    #[test]
    fn step_3_lists_every_address_a_friend_could_dial_at_80x24() {
        let mut app = home((80, 24), 1);
        keys(&mut app, "g3");
        addresses(
            &mut app,
            &[
                IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            ],
        );
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Meet without the internet           * Listening on port 7420  ? Help",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌ Meet without the internet ───────────────────────────────────┐        ",
                "        │ This computer's network addresses:                           │        ",
                "        │    10.42.0.1:7420                                            │        ",
                "        │    192.168.1.20:7420                                         │        ",
                "        │                                                              │        ",
                "        │ Ask Friend 1 to press G and read you their address. Type it  │        ",
                "        │ here:                                                        │        ",
                "        │ >                                                            │        ",
                "        │ Only one of you needs to do this.                            │        ",
                "        │                                                              │        ",
                "        │ Your computer may ask whether raven-node may accept          │        ",
                "        │ connections. Choose Allow.                                   │        ",
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

    #[test]
    fn step_3_shows_this_computers_address_as_far_as_it_is_known() {
        // Read again on the way in: until it answers, and when it can't be
        // told.
        let mut app = home((80, 24), 1);
        let cmds = keys(&mut app, "g3");
        assert!(cmds.contains(&Cmd::Node(NodeJob::LanAddresses)), "{cmds:?}");
        assert_eq!(address_shown(&app), "checking...");
        testkit::send(&mut app, Msg::Job(JobResult::LanAddresses(None)));
        assert_eq!(address_shown(&app), "unknown");
        // Every address a friend could dial, each with the port on its own
        // row, in the order read (the hotspot first).
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        addresses(
            &mut app,
            &[
                ip("10.42.0.1"),
                ip("192.168.1.20"),
                ip("169.254.12.3"),
                ip("fd00::7"),
            ],
        );
        // The listener is on 0.0.0.0: no IPv6 address.
        assert_eq!(
            addresses_shown(&app),
            ["10.42.0.1:7420", "192.168.1.20:7420", "169.254.12.3:7420"]
        );
        // A listener on every IPv6 address takes them too (and IPv4 ones,
        // but on Windows).
        let status = |listen| Msg::Poll(PollUpdate::Status(testkit::status(4242, listen)));
        testkit::send(&mut app, status("[::]:7420"));
        if cfg!(windows) {
            assert_eq!(address_shown(&app), "[fd00::7]:7420");
        } else {
            assert_eq!(
                addresses_shown(&app),
                [
                    "10.42.0.1:7420",
                    "192.168.1.20:7420",
                    "169.254.12.3:7420",
                    "[fd00::7]:7420"
                ]
            );
        }
        testkit::send(&mut app, status("0.0.0.0:7420"));
        // On no network at all, there is nothing to tell; nor with only
        // addresses the listener does not take.
        addresses(&mut app, &[]);
        assert_eq!(address_shown(&app), NOT_RECEIVING);
        addresses(&mut app, &[ip("fd00::7")]);
        assert_eq!(address_shown(&app), NOT_RECEIVING);
        address(&mut app);
        assert_eq!(address_shown(&app), "192.168.1.20:7420");
        // A listener bound to one address: that one, with its port.
        testkit::send(&mut app, status("10.42.0.1:7421"));
        assert_eq!(address_shown(&app), "10.42.0.1:7421");
        // A port it doesn't say is no port at all.
        testkit::send(&mut app, status("0.0.0.0:0"));
        assert_eq!(address_shown(&app), "192.168.1.20");
        // Nothing a friend could reach: on this computer only, no program,
        // or no network at all.
        testkit::send(&mut app, status("127.0.0.1:7420"));
        assert_eq!(address_shown(&app), NOT_RECEIVING);
        let not_running = Probe::of(&Err("raven-node is not running; start it".into()));
        testkit::send(&mut app, Msg::Poll(PollUpdate::Status(not_running)));
        assert_eq!(address_shown(&app), NOT_RECEIVING);
        testkit::send(&mut app, status("0.0.0.0:7420"));
        assert_eq!(address_shown(&app), "192.168.1.20:7420");
        testkit::send(&mut app, Msg::Poll(PollUpdate::Network(Some(false))));
        assert_eq!(address_shown(&app), NOT_RECEIVING);
        // While this app starts it.
        let mut app = testkit::settled_app((80, 24), Receive::On, 1);
        assert!(matches!(app.node().state, NodeState::Starting { .. }));
        keys(&mut app, "g3");
        address(&mut app);
        assert_eq!(address_shown(&app), "checking...");
    }
}
