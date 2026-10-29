//! NET: what this computer's background program is doing and which ways to
//! reach friends this build has on, in plain words, and (L) the last lines
//! of its service log.
//!
//! The panel has three groups of rows. This computer: first, as raven-node's
//! Status says the at-rest state (privacy pack PP.21), that Raven can't open
//! the friends list, that sealing waits for free disk space, or that the
//! profile is not encrypted; then where it listens, or why not (on this
//! computer only, an address that isn't here, a port in use, no network at
//! all), the background program and its file, waiting messages, and the
//! Windows and SSH notes. Ways to reach friends: each way
//! in plain words, what it does or 'Not in this version' (or 'Lab only') as
//! this process's gates have them ([`GatesView`]), never on for a held one,
//! and what the running program itself reports. Security (Phase 6b P6.31,
//! once the security read answered): the open alerts and warnings (W shows
//! them), what the background program refused, the smaller notices only
//! counted and the friends sending is paused to; or why there are none.
//! About this Raven: the network address, the folder and the build. Its
//! keys stay on the bottom row and the rows above scroll. Nothing here
//! turns a gate on.
//!
//! Every untrusted string (paths, the service log, the stop advice, a
//! failure's words, the address it is set to listen on) is drawn through
//! display.rs.
//!
//! [`GatesView`]: super::node::GatesView

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Padding, Paragraph};
use ratatui::Frame;

use super::anim::Moving;
use super::app::{self, App, LogView, NetState, Screen};
#[cfg(test)]
use super::app::{Cmd, JobResult, Msg, NodeJob, Overlay, Session};
use super::bridge::{AtRestStateView, SecKept};
#[cfg(test)]
use super::controller::PrivacyRead;
use super::node::{local_host, BindFailure, GateState, GatesView, NodeFolder, NodeState, NodeView};
#[cfg(test)]
use super::node::{Ensured, Managed, Probe, Program, StopOutcome, StopPlan, Stopped, Vault};
use super::state_file::Receive;
#[cfg(test)]
use super::state_file::TuiState;
#[cfg(test)]
use super::testkit;
use super::theme::PathKind;
#[cfg(test)]
use super::theme::{self, Glyphs, Theme};
#[cfg(test)]
use super::workers::{FileStamp, PollCtl, PollUpdate};
use super::{bridge, cells, display, overlays, render_header, verify, widgets, wizard, wrap, Look};

const TITLE: &str = " Network and status ";
const LOG_TITLE: &str = " Service log ";

/// The panel's groups.
const THIS_COMPUTER: &str = "This computer";
const WAYS: &str = "Ways to reach friends";
const SECURITY: &str = "Security";
const UPDATES: &str = "Updates";
const ABOUT: &str = "About this Raven";
/// The most addresses NET's address row names (MEET lists them all).
const NET_ADDRESSES: usize = 3;

/// This computer: where the background program listens, if it does.
/// LOCAL_ONLY follows 'Receiving on this computer only (<ip>): '.
const LOCAL_ONLY: &str = "friends on your network can't reach you. If Raven was installed to \
                          start at login, its installer listens only on this computer by \
                          default. To change that, reinstall with \
                          RAVEN_LAN_LISTEN=0.0.0.0:7420, or stop it and open Raven again.";
const RECEIVE_OFF: &str = "Receiving is off (Settings).";
const SEND_ONLY: &str = "Sending only, not receiving.";
/// ADDRESS_NOT_HERE's two parts go around the address it is set to listen
/// on, cut to ADDRESS_CELLS.
const ADDRESS_NOT_HERE: (&str, &str) = (
    "Not receiving: Raven is set to listen on ",
    ", which isn't on this computer now (did you change networks?). It starts listening by \
     itself when that address is back. To listen on every network instead, reinstall with \
     RAVEN_LAN_LISTEN=0.0.0.0:7420.",
);
const ADDRESS_CELLS: u16 = 48;
/// `raven status` says the same on no network (P3.C6).
const NOT_ON_ANY_NETWORK: &str = super::bridge::NOT_ON_ANY_NETWORK_TEXT;
const NEEDS_SETUP: &str = "Raven's background program needs one more step on this computer.";
const CHECK_AGAIN: &str = "Press R to check again.";
pub(super) const STOP_ADVICE: &str = "To stop it yourself: ";
const WINDOWS_NOTE: &str = "A Raven background program for your Windows account is running. \
                            Raven can't tell whether it belongs to this Raven folder.";
/// The same once its command line names another folder, before that folder.
const OTHER_FOLDER_NOTE: &str = "The Raven background program running for your Windows account \
                                 belongs to another Raven folder: ";
const SSH_NOTE: &str = "You're connected over SSH. On some Linux systems Raven's background \
                        program stops when you log out.";

/// Ways to reach friends, each by what people do.
const WIFI: &str = "This Wi-Fi or cable";
const HOTSPOT: &str = "A laptop's hotspot";
const IN_PERSON: &str = "Meeting in person";
const BLUETOOTH: &str = "Bluetooth";
const CARRIED: &str = "A friend carries messages";
const OVER_INTERNET: &str = "Over the internet";
/// The Tor onion carrier (lab): listed only while the background program's
/// Status has its line, with that line's state.
const TOR: &str = "Tor";
/// What a way does while its gate is on, and the words while it is off or
/// on by a lab switch only.
const WIFI_ON: &str = "On. Works without the internet.";
const HOTSPOT_ON: &str = "Works. One of you makes it, the other joins (press G).";
const IN_PERSON_ON: &str =
    "Works. Messages wait here until you meet, up to a day after you were last connected.";
const ON: &str = "On.";
const OFF: &str = "Off.";
/// Bluetooth, while the background program reports no nearby engine, or
/// none runs.
const BLUETOOTH_NOT_RUN: &str = "Off: Raven's background program doesn't run it.";
const BLUETOOTH_NO_NODE: &str = "Needs Raven's background program.";
const NOT_IN_THIS_VERSION: &str = "Not in this version.";
/// The security notices can't be read (P6.31).
const SECURITY_UNREADABLE: &str = "Raven can't read its security notices right now.";
const LAB_ONLY: &str = "Lab only";
/// What the running program reports, by its Status's capability names.
const USES: [(&str, &str); 3] = [
    ("lan_direct", "Local network"),
    ("internet_direct", "Internet direct"),
    ("p2p", "Peer-to-peer"),
];
const USES_NONE: &str = "Raven's background program isn't using any of these right now.";
const P2P_HELD: &str = "Peer-to-peer is set up for it, but this release keeps it off.";

/// About this Raven.
const RELEASE: &str = "This build: Release";
const DEVELOPER: &str = "This build: Developer build (lab features may be on)";

/// X's question, in place of the keys.
const STOP_QUESTION: &str =
    "Stop Raven's background program? Friends can't reach you until it runs again.";
const STOP_KEYS: [(&str, &str); 2] = [("[Y]", " Stop"), ("[N]", " Keep it running")];

/// The log view.
const LOG_FILE: &str = "File: ";
const LOG_EMPTY: &str = "Raven's background program hasn't written anything here yet.";
const LOG_UNREADABLE: &str = "Raven couldn't read the service log.";

/// What moves on NET: the Starting row's spinner (the header chip's too,
/// while no Keychain wait takes the chip).
pub(crate) fn moving(app: &App) -> Option<Moving> {
    match (app.screen(), &app.node().state) {
        (Screen::Network(net), NodeState::Starting { since })
            if net.log.is_none() && !app.stopping() =>
        {
            Some(Moving::Spinner { since: *since })
        }
        _ => None,
    }
}

/// Draws NET under the header row: the panel or the log view in a box, its
/// rows scrolled, its keys (or the stop question) at the bottom.
pub(super) fn render(f: &mut Frame, area: Rect, app: &App, net: &NetState, now: Instant) {
    if area.is_empty() {
        return;
    }
    render_header(f, area, app, now, true);
    let look = app.look();
    let body = wizard::under_header(area);
    let title = if net.log.is_some() { LOG_TITLE } else { TITLE };
    let block = widgets::screen_box(look)
        .padding(Padding::horizontal(1))
        .title(Span::styled(title, look.theme.title));
    let inner = block.inner(body);
    f.render_widget(block, body);
    if inner.is_empty() {
        return;
    }
    let (rows, keys) = content(app, net, inner, now);
    let (rows_rect, keys_rect) = split(inner, keys.len());
    let top = top_row(net, rows.len(), rows_rect.height);
    f.render_widget(Paragraph::new(rows).scroll((top, 0)), rows_rect);
    f.render_widget(Paragraph::new(keys), keys_rect);
}

/// The furthest NET scrolls in the App's window: the panel from its top, or
/// the log view from its newest line. 0 on any other screen.
pub(crate) fn max_scroll(app: &App) -> u16 {
    let Some((rows, height)) = measure(app) else {
        return 0;
    };
    u16::try_from(rows.saturating_sub(usize::from(height))).unwrap_or(u16::MAX)
}

/// Rows NET shows at once in the App's window (PgUp and PgDn move by it).
pub(crate) fn page_rows(app: &App) -> u16 {
    measure(app).map_or(0, |(_, height)| height)
}

/// NET's rows, and how many of them show at once, in the App's window.
fn measure(app: &App) -> Option<(usize, u16)> {
    let Screen::Network(net) = app.screen() else {
        return None;
    };
    let (cols, rows) = app.size();
    let body = wizard::under_header(Rect::new(0, 0, cols, rows));
    let inner = overlays::overlay_block(app.look()).inner(body);
    let (lines, keys) = content(app, net, inner, app.now());
    let (rows_rect, _) = split(inner, keys.len());
    Some((lines.len(), rows_rect.height))
}

/// The rows that scroll and the keys under them, in the box's `inner`
/// area. When the rows don't all fit, the keys say they scroll, except
/// while X's question is asked (it takes only its answer).
fn content(
    app: &App,
    net: &NetState,
    inner: Rect,
    now: Instant,
) -> (Vec<Line<'static>>, Vec<Line<'static>>) {
    let width = inner.width;
    let look = app.look();
    let (rows, mut keys) = match &net.log {
        Some(log) => (log_rows(app, log, width), vec![("[Esc]", " Back")]),
        None => (panel_rows(app, width, now), panel_keys(app, net)),
    };
    let asking = net.asking_stop && net.log.is_none();
    let mut lines = keys_rows(app, net, &keys, width);
    if !asking && rows.len() > usize::from(split(inner, lines.len()).0.height) {
        keys.insert(keys.len() - 1, (look.glyphs.up_down, " Scroll"));
        lines = keys_rows(app, net, &keys, width);
    }
    (rows, lines)
}

/// `inner` split into the rows that scroll and, at its bottom, `keys` rows
/// of keys with a blank row above them when there is room.
fn split(inner: Rect, keys: usize) -> (Rect, Rect) {
    let keys = u16::try_from(keys).unwrap_or(u16::MAX).min(inner.height);
    let gap = u16::from(inner.height > keys + 1);
    let rows = inner.height - keys - gap;
    (
        Rect {
            height: rows,
            ..inner
        },
        Rect {
            y: inner.y + rows + gap,
            height: keys,
            ..inner
        },
    )
}

/// The first row drawn: the panel's scroll, or for the log the rows above
/// its newest window, less how far it is scrolled back.
fn top_row(net: &NetState, rows: usize, height: u16) -> u16 {
    let max = u16::try_from(rows.saturating_sub(usize::from(height))).unwrap_or(u16::MAX);
    match &net.log {
        Some(log) => max - log.scroll.min(max),
        None => net.scroll.min(max),
    }
}

// ── The panel ───────────────────────────────────────────────────────────────

fn panel_rows(app: &App, width: u16, now: Instant) -> Vec<Line<'static>> {
    let look = app.look();
    let t = &look.theme;
    let node = app.node();
    let mut lines = vec![Line::styled(THIS_COMPUTER, t.title)];
    lines.extend(at_rest_rows(app, width));
    lines.extend(listener_rows(app, width, now));
    lines.extend(plain_rows(
        &format!("Background program: {}", program_state(app)),
        width,
    ));
    if let Some(advice) = app.stop_advice() {
        let advice = display::one_line(&advice, u16::MAX, "");
        if app.on_windows() {
            // Words (Task Manager), wrapped as words.
            lines.extend(plain_rows(&format!("{STOP_ADVICE}{advice}"), width));
        } else {
            // A command with the profile's folder in it: broken, never cut.
            lines.extend(
                overlays::wrap_command(&format!("{STOP_ADVICE}{advice}"), width)
                    .into_iter()
                    .map(Line::raw),
            );
        }
    }
    lines.extend(program_file(app, width));
    let waiting = app.waiting_count();
    if waiting > 0 {
        let how = if node.running() {
            "Raven keeps trying"
        } else {
            "not being retried: the background program isn't running"
        };
        lines.extend(plain_rows(
            &format!("Waiting messages: {waiting} ({how})"),
            width,
        ));
    }
    if app.on_windows() && node.running() && node.started_by_app.is_none() {
        // Said once its command line was read, and never for this folder's
        // own (E1).
        let note = match node.folder() {
            Some(NodeFolder::Other(dir)) => Some(format!(
                "{OTHER_FOLDER_NOTE}{}.",
                display::one_line(dir, u16::MAX, "")
            )),
            Some(NodeFolder::Unknown) => Some(WINDOWS_NOTE.to_owned()),
            Some(NodeFolder::This) | None => None,
        };
        if let Some(note) = note {
            lines.extend(styled_rows(&note, width, t.secondary));
        }
    }
    if app.over_ssh() && !app.on_windows() {
        lines.extend(styled_rows(SSH_NOTE, width, t.secondary));
    }

    lines.push(Line::default());
    lines.push(Line::styled(WAYS, t.title));
    for (way, gate, works, kind) in ways(app.gates(), bluetooth_words(node)) {
        lines.extend(way_rows(look, way, gate, works, kind, width));
    }
    // Tor (lab): its state as the background program's Status says it;
    // nothing while it says nothing.
    if let Some(words) = node.tor.as_deref().and_then(tor_words) {
        lines.extend(way_rows(
            look,
            TOR,
            GateState::On,
            &words,
            PathKind::Tor,
            width,
        ));
    }
    if node.running() {
        let uses: Vec<&str> = USES
            .iter()
            .filter(|(capability, _)| node.capabilities.iter().any(|c| c == capability))
            .map(|(_, words)| *words)
            .collect();
        let text = if uses.is_empty() {
            USES_NONE.to_owned()
        } else {
            format!("Raven's background program uses: {}.", uses.join(", "))
        };
        lines.extend(styled_rows(&text, width, t.secondary));
    }
    if node.p2p_held {
        lines.extend(styled_rows(P2P_HELD, width, t.secondary));
    }

    if app.security().is_some() {
        lines.push(Line::default());
        lines.push(Line::styled(SECURITY, t.title));
        lines.extend(security_rows(app, width));
    }
    // Raven updates (P6.47): what waits to be installed, once read.
    if let Some(row) = app.updates().and_then(|view| view.net_row.as_deref()) {
        lines.push(Line::default());
        lines.push(Line::styled(UPDATES, t.title));
        lines.extend(plain_rows(
            &format!("Raven updates: {row} (press U)"),
            width,
        ));
    }

    lines.push(Line::default());
    lines.push(Line::styled(ABOUT, t.title));
    lines.extend(plain_rows(&address_row(app), width));
    lines.push(path_line(
        look,
        "Raven folder: ",
        &app.folder().to_string_lossy(),
        width,
    ));
    lines.push(Line::raw(if app.gates().developer {
        DEVELOPER
    } else {
        RELEASE
    }));
    lines
}

/// The Security group (P6.31): how many alerts and warnings are open (W
/// shows them), what the background program refused as its Status says
/// (strangers in the last hour, network sources refused for now), the
/// smaller notices only counted and whom sending is paused to; or why
/// there are none (not in this version, not kept for this profile). No
/// address, key or id.
fn security_rows(app: &App, width: u16) -> Vec<Line<'static>> {
    let t = &app.look().theme;
    let Some(read) = app.security() else {
        return Vec::new();
    };
    match read.kept {
        SecKept::Off => return styled_rows(bridge::NOT_IN_THIS_VERSION, width, t.secondary),
        SecKept::Unsealed => return styled_rows(bridge::NOT_KEPT_UNSEALED, width, t.secondary),
        SecKept::Live => {}
    }
    let mut lines = Vec::new();
    let open = read.notices.len();
    if read.unreadable.is_some() {
        lines.extend(styled_rows(SECURITY_UNREADABLE, width, t.warn));
    } else if open == 0 {
        lines.extend(plain_rows("Open alerts: none", width));
    } else {
        lines.extend(styled_rows(
            &format!("Open alerts: {open} (press W to see them)"),
            width,
            t.warn,
        ));
    }
    if let Some(counts) = app.node().security {
        lines.extend(plain_rows(
            &bridge::strangers_line(counts.strangers_1h),
            width,
        ));
        if counts.bans > 0 {
            lines.extend(plain_rows(
                &format!("Network sources Raven refuses for a while: {}", counts.bans),
                width,
            ));
        }
    }
    if read.counted > 0 {
        lines.extend(styled_rows(
            &bridge::notices_line(read.counted),
            width,
            t.secondary,
        ));
    }
    let paused: Vec<String> = read
        .paused
        .iter()
        .map(|key| app.shown_name(key))
        .filter(|name| !name.is_empty())
        .collect();
    if !paused.is_empty() {
        lines.extend(plain_rows(
            &format!("Sending paused to: {}", paused.join(", ")),
            width,
        ));
    }
    lines
}

/// 'This computer's network address': this computer's addresses a friend
/// could dial, as raven-core reads its interfaces ([`App::lan_addresses`],
/// the hotspot it hosts first), not the route out: a hotspot with no
/// upstream or a cable with no router has none, and a VPN's would be no use
/// to a friend on the same Wi-Fi. Those the listener takes while it listens
/// on the network (bound to one address: that one), else the IPv4 ones; at
/// most [`NET_ADDRESSES`]. 'none' on no network, 'unknown' when they can't
/// be read.
fn address_row(app: &App) -> String {
    const ONE: &str = "This computer's network address";
    let ips = match app.lan_addresses() {
        None => return format!("{ONE}: checking{}", app.look().glyphs.ellipsis),
        Some(None) => return format!("{ONE}: unknown"),
        Some(Some(ips)) => ips,
    };
    let node = app.node();
    let bound = match node.state {
        NodeState::Listening { .. } => node
            .listen
            .as_deref()
            .and_then(|listen| listen.trim().parse::<SocketAddr>().ok())
            .map(|at| at.ip()),
        _ => None,
    };
    let takes = bound.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let shown: Vec<String> = ips
        .iter()
        .filter(|&&ip| bridge::listener_takes(takes, ip))
        .take(NET_ADDRESSES)
        .map(IpAddr::to_string)
        .collect();
    match shown.as_slice() {
        [] => format!("{ONE}: none"),
        [one] => format!("{ONE}: {one}"),
        many => format!("{ONE}es: {}", many.join(", ")),
    }
}

/// Where the background program listens, if it does; or why not, by its
/// state, the receive setting and this computer's networks. Each with the
/// mark the header chip has. On no network at all that comes first, and
/// the program's own row follows only when it needs a word of its own.
fn listener_rows(app: &App, width: u16, now: Instant) -> Vec<Line<'static>> {
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    let node = app.node();
    let off = app.settings().receive == Receive::Off;
    let ellipsis = g.ellipsis;
    let mut lines = Vec::new();
    if app.not_on_any_network() {
        let mark = Span::styled(g.dot_off, t.secondary);
        lines.extend(marked_rows(
            mark,
            NOT_ON_ANY_NETWORK,
            Style::default(),
            width,
        ));
        let calm = matches!(
            node.state,
            NodeState::Listening { .. }
                | NodeState::ReceivingLocalOnly
                | NodeState::SendOnly
                | NodeState::NotRunning
        );
        if off || calm {
            return lines;
        }
    }
    let (mark, text, style): (Span<'static>, String, Style) = match &node.state {
        NodeState::Listening { port } => (
            Span::styled(g.dot_on, t.ok),
            match port {
                Some(port) => format!("Listening on port {port} on your network."),
                None => "Listening on your network.".to_owned(),
            },
            Style::default(),
        ),
        _ if off => (
            Span::styled(g.dot_off, t.secondary),
            RECEIVE_OFF.to_owned(),
            Style::default(),
        ),
        NodeState::ReceivingLocalOnly => {
            let host = local_host(node.listen.as_deref());
            (
                Span::raw(g.dot_half),
                format!("Receiving on this computer only ({host}): {LOCAL_ONLY}"),
                Style::default(),
            )
        }
        NodeState::Starting { since } => (
            widgets::spinner(look, *since, now),
            format!("Starting Raven{ellipsis}"),
            Style::default(),
        ),
        NodeState::SendOnly => match node.bind_failure() {
            Some(BindFailure::AddrNotHere { wanted }) => {
                let (before, after) = ADDRESS_NOT_HERE;
                let wanted = display::one_line(wanted, ADDRESS_CELLS, ellipsis);
                (
                    Span::styled(g.dot_off, t.secondary),
                    format!("{before}{wanted}{after}"),
                    Style::default(),
                )
            }
            Some(BindFailure::InUse { port }) => (
                Span::raw(g.dot_half),
                format!("Not receiving: another program on this computer uses port {port}."),
                Style::default(),
            ),
            None => (
                Span::raw(g.dot_half),
                SEND_ONLY.to_owned(),
                Style::default(),
            ),
        },
        NodeState::NeedsPassphraseFile => (
            Span::styled(g.dot_alert, t.warn),
            NEEDS_SETUP.to_owned(),
            t.warn,
        ),
        NodeState::StartFailed(plain) => (
            Span::styled(g.dot_alert, t.warn),
            format!("{} {}", plain.headline, plain.next)
                .trim()
                .to_owned(),
            Style::default(),
        ),
        NodeState::NotAnswering => (
            Span::styled(g.dot_alert, t.warn),
            format!("{}. {CHECK_AGAIN}", app::NOT_ANSWERING),
            Style::default(),
        ),
        NodeState::NotRunning => (
            Span::styled(g.dot_off, t.secondary),
            format!("{}.", app::NOT_RUNNING),
            Style::default(),
        ),
        NodeState::Unknown => (
            Span::raw(" "),
            format!("Checking Raven's background program{ellipsis}"),
            t.secondary,
        ),
    };
    lines.extend(marked_rows(mark, &text, style, width));
    lines
}

/// The background program's own row: running (its process, and who started
/// it or that it starts at login), starting, stopping, or not.
fn program_state(app: &App) -> String {
    let node = app.node();
    let ellipsis = app.look().glyphs.ellipsis;
    if app.stopping() {
        return format!("Stopping{ellipsis}");
    }
    match node.state {
        NodeState::Starting { .. } => format!("Starting{ellipsis}"),
        NodeState::NotAnswering => "Not responding".to_owned(),
        NodeState::Unknown => format!("Checking{ellipsis}"),
        _ if node.running() => {
            let how = if node.managed.is_some() {
                "set to start when you log in"
            } else if node.started_by_app.is_some() && node.started_by_app == node.pid {
                "started by this app"
            } else {
                "started earlier"
            };
            match node.pid {
                Some(pid) => format!("Running (process {pid}), {how}"),
                None => format!("Running, {how}"),
            }
        }
        _ => "Not running".to_owned(),
    }
}

/// 'Program: <the raven-node a start runs>', or why there is none.
fn program_file(app: &App, width: u16) -> Vec<Line<'static>> {
    let program = &app.node().program;
    if !program.exe_known {
        return plain_rows(&format!("Program: {}.", app::NO_PROGRAM_PATH), width);
    }
    vec![path_line(
        app.look(),
        "Program: ",
        &program.binary.to_string_lossy(),
        width,
    )]
}

/// `label`, then the path `raw` with its middle taken out when it is too long
/// for the row.
fn path_line(look: &Look, label: &'static str, raw: &str, width: u16) -> Line<'static> {
    let room = width.saturating_sub(u16::try_from(cells(label)).unwrap_or(u16::MAX));
    Line::from(vec![
        Span::raw(label),
        Span::raw(display::one_line_middle(raw, room, look.glyphs.ellipsis)),
    ])
}

/// The ways to reach friends, each with the gate it goes by and what it does
/// while that is on. A hotspot and meeting in person are the local network
/// too; Bluetooth says what the background program does (`nearby`, as
/// [`bluetooth_words`]); over the internet is Internet direct or
/// peer-to-peer.
fn ways(
    gates: &GatesView,
    nearby: &'static str,
) -> [(&'static str, GateState, &'static str, PathKind); 6] {
    [
        (WIFI, gates.lan, WIFI_ON, PathKind::Lan),
        (HOTSPOT, gates.lan, HOTSPOT_ON, PathKind::Lan),
        (IN_PERSON, gates.lan, IN_PERSON_ON, PathKind::Lan),
        (BLUETOOTH, gates.nearby, nearby, PathKind::Nearby),
        (CARRIED, gates.custody, ON, PathKind::Friend),
        (
            OVER_INTERNET,
            further_on(gates.internet, gates.p2p),
            ON,
            PathKind::Direct,
        ),
    ]
}

/// The Tor carrier's state from its Status line ('Tor: ready' is
/// 'ready'), shaped as the app's own text; None for an empty one.
fn tor_words(line: &str) -> Option<String> {
    let words = line.trim();
    let words = words.strip_prefix("Tor:").unwrap_or(words).trim();
    let words = display::one_line(words, u16::MAX, "");
    (!words.is_empty()).then_some(words)
}

/// Bluetooth nearby as the background program's Status says it, the state
/// `raven status` shows too (E1: one state per feature).
fn bluetooth_words(node: &NodeView) -> &'static str {
    match node.nearby {
        Some(true) => ON,
        Some(false) => OFF,
        None if node.running() => BLUETOOTH_NOT_RUN,
        None => BLUETOOTH_NO_NODE,
    }
}

/// The further on of two gates: On, else Lab, else Preview.
fn further_on(a: GateState, b: GateState) -> GateState {
    match (a, b) {
        (GateState::On, _) | (_, GateState::On) => GateState::On,
        (GateState::Lab, _) | (_, GateState::Lab) => GateState::Lab,
        _ => GateState::Preview,
    }
}

/// '<way> · <words>': what it does (`works`) while its gate is on, 'Not in
/// this version.' while it is off, 'Lab only' while a lab switch alone has
/// it on (a held way never reads on). Wrapped under the way, two cells in.
/// The way in its path's colour while it is on (Calm, `kind`).
fn way_rows(
    look: &Look,
    way: &str,
    gate: GateState,
    works: &str,
    kind: PathKind,
    width: u16,
) -> Vec<Line<'static>> {
    let way_style = if gate == GateState::On {
        look.theme.path(kind)
    } else {
        look.theme.text
    };
    let (words, style) = match gate {
        GateState::On => (works.to_owned(), Style::default()),
        GateState::Preview => (NOT_IN_THIS_VERSION.to_owned(), look.theme.secondary),
        // Bluetooth's state is the background program's, so it is said
        // under a lab switch too.
        GateState::Lab if way == BLUETOOTH => (format!("{LAB_ONLY}. {works}"), look.theme.warn),
        GateState::Lab => (LAB_ONLY.to_owned(), look.theme.warn),
    };
    let head = format!("{way}{}", look.glyphs.inline_separator);
    wrap(&format!("{head}{words}"), width, 2)
        .into_iter()
        .enumerate()
        .map(|(i, row)| match row.strip_prefix(head.as_str()) {
            Some(rest) if i == 0 => Line::from(vec![
                Span::styled(way.to_owned(), way_style),
                Span::styled(look.glyphs.inline_separator, look.theme.secondary),
                Span::styled(rest.to_owned(), style),
            ]),
            _ if i == 0 => Line::raw(row),
            _ => Line::styled(row, style),
        })
        .collect()
}

/// The panel's keys, only those it offers now; Esc last.
fn panel_keys(app: &App, net: &NetState) -> Vec<(&'static str, &'static str)> {
    if net.asking_stop {
        return STOP_KEYS.to_vec();
    }
    let offers = app.net_keys();
    let mut keys = vec![("[L]", " Service log")];
    if offers.start {
        keys.push(("[S]", " Start"));
    }
    if offers.stop {
        keys.push(("[X]", " Stop"));
    }
    if offers.check_again {
        keys.push(("[R]", " Check again"));
    }
    if !app.notices().is_empty() {
        keys.push(("[W]", " Security"));
    }
    if app.updates().is_some_and(|view| view.live) {
        keys.push(("[U]", " Updates"));
    }
    keys.push(("[Esc]", " Back"));
    keys
}

/// `keys` in rows of `width` cells, under X's question while it is asked.
fn keys_rows(
    app: &App,
    net: &NetState,
    keys: &[(&'static str, &'static str)],
    width: u16,
) -> Vec<Line<'static>> {
    let mut lines = if net.asking_stop && net.log.is_none() {
        plain_rows(STOP_QUESTION, width)
    } else {
        Vec::new()
    };
    lines.extend(verify::key_rows(app.look(), keys, "  ", width));
    lines
}

// ── The log view ────────────────────────────────────────────────────────────

/// The log file's path, then its last lines, each one row shaped to the
/// width; or that there are none yet, or why they can't be read.
fn log_rows(app: &App, log: &LogView, width: u16) -> Vec<Line<'static>> {
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    let file = bridge::service_log_path(app.folder());
    let mut lines =
        vec![path_line(look, LOG_FILE, &file.to_string_lossy(), width).style(t.secondary)];
    match &log.lines {
        None => lines.push(Line::raw(format!("Reading the service log{}", g.ellipsis))),
        Some(Ok(rows)) if rows.is_empty() => lines.push(Line::raw(LOG_EMPTY)),
        Some(Ok(rows)) => lines.extend(
            rows.iter()
                .map(|row| Line::raw(display::one_line(row, width, g.ellipsis))),
        ),
        Some(Err(why)) => {
            lines.push(Line::raw(LOG_UNREADABLE));
            lines.push(Line::styled(
                display::one_line(why, width, g.ellipsis),
                t.secondary,
            ));
        }
    }
    lines
}

// ── Rows ────────────────────────────────────────────────────────────────────

/// The app's own copy in rows of `width` cells.
/// The profile's at-rest state as raven-node says it (privacy pack PP.21,
/// in the UX copy's words): while Raven can't open the friends list the
/// key-root sentence (the key-gone one when its key is gone, review
/// A-keys-format-4); one row while sealing waits for free disk space, and
/// one while the user unsealed the profile. Nothing otherwise.
fn at_rest_rows(app: &App, width: u16) -> Vec<Line<'static>> {
    let t = &app.look().theme;
    match app.node().at_rest {
        Some(AtRestStateView::KeyLost) => styled_rows(bridge::KEY_LOST_TEXT, width, t.warn),
        Some(state) if state.locked_out() => {
            styled_rows(bridge::KEY_UNAVAILABLE_TEXT, width, t.warn)
        }
        Some(AtRestStateView::NeedsDiskSpace) => {
            let needed = app.privacy().and_then(|read| read.disk_needed);
            styled_rows(&bridge::disk_space_text(needed), width, t.warn)
        }
        Some(AtRestStateView::UnsealedByUser) => plain_rows(bridge::UNSEALED_TEXT, width),
        _ => Vec::new(),
    }
}

fn plain_rows(text: &str, width: u16) -> Vec<Line<'static>> {
    wrap(text, width, 0).into_iter().map(Line::raw).collect()
}

fn styled_rows(text: &str, width: u16, style: Style) -> Vec<Line<'static>> {
    wrap(text, width, 0)
        .into_iter()
        .map(|row| Line::styled(row, style))
        .collect()
}

/// `mark`, a space and `text` in `style`, wrapped under the text's start.
fn marked_rows(mark: Span<'static>, text: &str, style: Style, width: u16) -> Vec<Line<'static>> {
    let indent = u16::try_from(mark.width() + 1).unwrap_or(0);
    let rows = wrap(text, width.saturating_sub(indent), 0);
    rows.into_iter()
        .enumerate()
        .map(|(i, row)| {
            let lead = if i == 0 {
                vec![mark.clone(), Span::raw(" ")]
            } else {
                vec![Span::raw(" ".repeat(usize::from(indent)))]
            };
            let mut spans = lead;
            spans.push(Span::styled(row, style));
            Line::from(spans)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyCode;
    use raven_core::ipc::{AtRestStatus, IpcResponse, IPC_VERSION};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use bridge::{Gate, Gates};

    /// A Status from raven-node `pid`, its listener at `listen`.
    fn up(pid: u32, listen: &str) -> Probe {
        up_at_rest(pid, listen, None)
    }

    /// [`up`] saying the profile's at-rest state is `state` (privacy pack
    /// PP.4; None: an older node that does not say).
    fn up_at_rest(pid: u32, listen: &str, state: Option<&str>) -> Probe {
        Probe::of(&Ok(IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into(), "lan_direct".into()],
            p2p: None,
            pid: Some(pid),
            lan_listen: Some(listen.into()),
            last_paths: Vec::new(),
            route_hints: None,
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: state.map(|state| AtRestStatus {
                state: state.into(),
                ..AtRestStatus::default()
            }),
            lan: None,
            security: None,
            nearby: None,
            tor: None,
            learning: None,
            locked: None,
            updates: None,
        }))
    }

    fn not_running() -> Probe {
        Probe::of(&Err("raven-node is not running; start it".into()))
    }

    fn answer(app: &mut App, result: JobResult) -> Vec<Cmd> {
        testkit::send(app, Msg::Job(result))
    }

    /// The app in `size` started with `session`, its first jobs answered:
    /// no vault problem, raven-node as `probe` says, no login service,
    /// `friends` friends and no history.
    fn settled(size: (u16, u16), session: Session, probe: Probe, friends: u8) -> App {
        settled_in(testkit::simple_mono(), size, session, probe, friends)
    }

    /// [`settled`] in `look`.
    fn settled_in(
        look: Look,
        size: (u16, u16),
        session: Session,
        probe: Probe,
        friends: u8,
    ) -> App {
        let mut app = testkit::app_in(look, size);
        app.start(session);
        for result in [
            JobResult::Vault(Vault::default()),
            JobResult::Probed(probe),
            JobResult::Managed(None),
            JobResult::Contacts {
                contacts: Ok((1..=friends).map(testkit::friend).collect()),
                stamp: FileStamp::default(),
            },
            JobResult::History {
                history: Ok(Default::default()),
                stamp: FileStamp::default(),
            },
        ] {
            answer(&mut app, result);
        }
        app
    }

    /// N on the friend list, and this computer's addresses answered.
    fn open_net(app: &mut App) -> Vec<Cmd> {
        let cmds = testkit::press(app, KeyCode::Char('n'));
        answer(
            app,
            JobResult::LanAddresses(Some(vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))])),
        );
        cmds
    }

    /// One friend, receiving on, and the node this app started listening on
    /// the network as process 4242.
    fn started_here(size: (u16, u16), session: Session) -> App {
        let mut app = settled(size, session, not_running(), 1);
        answer(
            &mut app,
            JobResult::Ensured(Ensured {
                result: Ok(()),
                after: up(4242, "0.0.0.0:7420"),
                started_by_app: Some(4242),
                captured: String::new(),
                ring: 0..0,
            }),
        );
        app
    }

    /// One friend, and a node that ran before the app listening on the
    /// network as process 4242.
    fn started_earlier() -> App {
        settled(
            (80, 24),
            testkit::session(Receive::On),
            up(4242, "0.0.0.0:7420"),
            1,
        )
    }

    fn lab_gates() -> GatesView {
        let lab = Gate {
            production: false,
            live: true,
        };
        GatesView::of(
            Gates {
                lan: Gate {
                    production: true,
                    live: true,
                },
                internet: lab,
                p2p: lab,
                custody: lab,
                nearby: lab,
            },
            true,
        )
    }

    /// NET's row `y` (its keys are on row 22 at 80x24).
    fn row(app: &App, y: usize) -> String {
        testkit::render(app, 80, 24)[y].clone()
    }

    #[test]
    fn net_in_a_release_build() {
        let mut app = started_here((80, 24), testkit::session(Receive::On));
        let cmds = open_net(&mut app);
        assert!(cmds.contains(&Cmd::Node(NodeJob::LanAddresses)), "{cmds:?}");
        assert!(matches!(app.screen(), Screen::Network(_)));
        // The ways by what people do: the local network ones work, the
        // others are never on, and nothing offers to turn one on.
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Network                             * Listening on port 7420  ? Help",
                "┌ Network and status ──────────────────────────────────────────────────────────┐",
                "│ This computer                                                                │",
                "│ * Listening on port 7420 on your network.                                    │",
                "│ Background program: Running (process 4242), started by this app              │",
                "│ Program: /opt/raven/raven-node                                               │",
                "│                                                                              │",
                "│ Ways to reach friends                                                        │",
                "│ This Wi-Fi or cable - On. Works without the internet.                        │",
                "│ A laptop's hotspot - Works. One of you makes it, the other joins (press G).  │",
                "│ Meeting in person - Works. Messages wait here until you meet, up to a day    │",
                "│   after you were last connected.                                             │",
                "│ Bluetooth - Not in this version.                                             │",
                "│ A friend carries messages - Not in this version.                             │",
                "│ Over the internet - Not in this version.                                     │",
                "│ Raven's background program uses: Local network.                              │",
                "│                                                                              │",
                "│ About this Raven                                                             │",
                "│ This computer's network address: 192.168.1.20                                │",
                "│ Raven folder: /home/sam/.raven                                               │",
                "│ This build: Release                                                          │",
                "│                                                                              │",
                "│ [L] Service log  [X] Stop  [Esc] Back                                        │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
            ],
        );
        // Before the address answers, and when it can't be told.
        let mut asking = started_here((80, 24), testkit::session(Receive::On));
        testkit::press(&mut asking, KeyCode::Char('n'));
        assert_eq!(
            row(&asking, 18),
            "│ This computer's network address: checking...                                 │"
        );
        answer(&mut asking, JobResult::LanAddresses(None));
        assert_eq!(
            row(&asking, 18),
            "│ This computer's network address: unknown                                     │"
        );
        // Esc goes back to Home.
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen(), &Screen::Home);
    }

    /// NET names this computer's own addresses, as MEET does, not the
    /// route out: a cable with no router (169.254 only) or a hotspot with no
    /// upstream has no route out, and was "unknown" (D-interfaces-texts-7).
    #[test]
    fn net_names_this_computers_addresses_not_the_route_out() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let address_row = |app: &App| {
            testkit::render(app, 80, 24)
                .into_iter()
                .find(|row| row.contains("This computer's network address"))
                .unwrap_or_else(|| panic!("no address row"))
        };
        let shown = |listen: &str, ips: &[&str]| {
            let mut app = settled((80, 24), testkit::session(Receive::On), up(4242, listen), 1);
            testkit::press(&mut app, KeyCode::Char('n'));
            answer(
                &mut app,
                JobResult::LanAddresses(Some(ips.iter().map(|s| ip(s)).collect())),
            );
            address_row(&app)
        };
        // A cable between two laptops, no router.
        assert_eq!(
            shown("0.0.0.0:7420", &["169.254.12.3"]),
            "│ This computer's network address: 169.254.12.3                                │"
        );
        // A hotspot this computer hosts, first; no IPv6 address for a
        // listener on 0.0.0.0; three at most.
        assert_eq!(
            shown(
                "0.0.0.0:7420",
                &[
                    "10.42.0.1",
                    "192.168.1.20",
                    "169.254.12.3",
                    "192.168.7.4",
                    "fd00::7"
                ]
            ),
            "│ This computer's network addresses: 10.42.0.1, 192.168.1.20, 169.254.12.3     │"
        );
        // A listener bound to one address: that one.
        assert_eq!(
            shown("192.168.1.20:7420", &["10.42.0.1", "192.168.1.20"]),
            "│ This computer's network address: 192.168.1.20                                │"
        );
        // On no network at all.
        assert_eq!(
            shown("0.0.0.0:7420", &[]),
            "│ This computer's network address: none                                        │"
        );
        // Not listening on the network: its IPv4 addresses all the same.
        let mut off = settled((80, 24), testkit::session(Receive::On), not_running(), 1);
        testkit::press(&mut off, KeyCode::Char('n'));
        answer(
            &mut off,
            JobResult::LanAddresses(Some(vec![ip("fd00::7"), ip("192.168.1.20")])),
        );
        assert_eq!(
            address_row(&off),
            "│ This computer's network address: 192.168.1.20                                │"
        );
    }

    #[test]
    fn net_in_a_lab_build() {
        let session = Session {
            gates: lab_gates(),
            ..testkit::session(Receive::On)
        };
        let mut app = settled((80, 24), session, not_running(), 0);
        open_net(&mut app);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Network                       o Starts when you add a friend  ? Help",
                "┌ Network and status ──────────────────────────────────────────────────────────┐",
                "│ This computer                                                                │",
                "│ o Raven's background program isn't running.                                  │",
                "│ Background program: Not running                                              │",
                "│ Program: /opt/raven/raven-node                                               │",
                "│                                                                              │",
                "│ Ways to reach friends                                                        │",
                "│ This Wi-Fi or cable - On. Works without the internet.                        │",
                "│ A laptop's hotspot - Works. One of you makes it, the other joins (press G).  │",
                "│ Meeting in person - Works. Messages wait here until you meet, up to a day    │",
                "│   after you were last connected.                                             │",
                "│ Bluetooth - Lab only. Needs Raven's background program.                      │",
                "│ A friend carries messages - Lab only                                         │",
                "│ Over the internet - Lab only                                                 │",
                "│                                                                              │",
                "│ About this Raven                                                             │",
                "│ This computer's network address: 192.168.1.20                                │",
                "│ Raven folder: /home/sam/.raven                                               │",
                "│ This build: Developer build (lab features may be on)                         │",
                "│                                                                              │",
                "│                                                                              │",
                "│ [L] Service log  [S] Start  [Esc] Back                                       │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
            ],
        );
        // S starts it: the row turns with the chip's spinner.
        let cmds = testkit::press(&mut app, KeyCode::Char('s'));
        assert!(cmds.contains(&Cmd::Node(NodeJob::Ensure)), "{cmds:?}");
        let NodeState::Starting { since } = app.node().state else {
            panic!("{:?}", app.node().state);
        };
        assert_eq!(moving(&app), Some(Moving::Spinner { since }));
        assert_eq!(
            row(&app, 3),
            "│ | Starting Raven...                                                          │"
        );
        assert_eq!(
            row(&app, 4),
            "│ Background program: Starting...                                              │"
        );
        let later = testkit::render_at(&app, 80, 24, since + Duration::from_millis(83));
        assert!(
            later[3].starts_with("│ / Starting Raven..."),
            "{}",
            later[3]
        );
        // Nothing more to start while it starts.
        assert_eq!(
            row(&app, 22),
            "│ [L] Service log  [Esc] Back                                                  │"
        );
    }

    #[test]
    fn net_receiving_on_this_computer_only() {
        let mut app = settled(
            (80, 24),
            testkit::session(Receive::On),
            up(4242, "127.0.0.1:55001"),
            1,
        );
        answer(&mut app, JobResult::Managed(Some(Managed::LaunchAgent)));
        open_net(&mut app);
        // A login service is never stopped from here: no [X].
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Network                    ~ Receiving on this computer only  ? Help",
                "┌ Network and status ──────────────────────────────────────────────────────────┐",
                "│ This computer                                                                │",
                "│ ~ Receiving on this computer only (127.0.0.1): friends on your network can't │",
                "│   reach you. If Raven was installed to start at login, its installer listens │",
                "│   only on this computer by default. To change that, reinstall with           │",
                "│   RAVEN_LAN_LISTEN=0.0.0.0:7420, or stop it and open Raven again.            │",
                "│ Background program: Running (process 4242), set to start when you log in     │",
                "│ Program: /opt/raven/raven-node                                               │",
                "│                                                                              │",
                "│ Ways to reach friends                                                        │",
                "│ This Wi-Fi or cable - On. Works without the internet.                        │",
                "│ A laptop's hotspot - Works. One of you makes it, the other joins (press G).  │",
                "│ Meeting in person - Works. Messages wait here until you meet, up to a day    │",
                "│   after you were last connected.                                             │",
                "│ Bluetooth - Not in this version.                                             │",
                "│ A friend carries messages - Not in this version.                             │",
                "│ Over the internet - Not in this version.                                     │",
                "│ Raven's background program uses: Local network.                              │",
                "│                                                                              │",
                "│ About this Raven                                                             │",
                "│                                                                              │",
                "│ [L] Service log  Up/Down Scroll  [Esc] Back                                  │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
            ],
        );
        assert!(testkit::press(&mut app, KeyCode::Char('x')).is_empty());
        assert!(matches!(app.screen(), Screen::Network(net) if !net.asking_stop));
        // With receiving off, a listener on this computer only is the app's
        // own doing (the loopback address it sets).
        let mut off = settled(
            (80, 24),
            testkit::session(Receive::Off),
            up(4242, "127.0.0.1:55001"),
            1,
        );
        open_net(&mut off);
        assert_eq!(
            row(&off, 3),
            "│ o Receiving is off (Settings).                                               │"
        );
    }

    #[test]
    fn net_without_its_own_program_path() {
        // ext.rs would look raven-node up on PATH: the app starts none.
        let session = Session {
            program: Program {
                binary: "raven-node".into(),
                exe_known: false,
            },
            ..testkit::session(Receive::On)
        };
        let mut app = settled((80, 24), session, not_running(), 1);
        open_net(&mut app);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24)[3..8],
            &[
                "│ o Raven's background program isn't running.                                  │",
                "│ Background program: Not running                                              │",
                "│ Program: Raven can't tell where its own program is, so it can't start its    │",
                "│ background program.                                                          │",
                "│                                                                              │",
            ],
        );
        assert!(!app.net_keys().start);
        assert!(testkit::press(&mut app, KeyCode::Char('s')).is_empty());
    }

    /// E1: Bluetooth on NET says what the background program reports, the
    /// state `raven status` shows.
    #[test]
    fn tor_is_listed_only_as_the_background_program_reports_it() {
        // No Tor line in its Status (gate closed, an older build): no row.
        let mut app = started_earlier();
        open_net(&mut app);
        let text = testkit::render_text(&app);
        assert!(!text.contains("Tor"), "{text}");
        // Its line, as it says it: the state after 'Tor:'.
        for (line, words) in [
            ("Tor: starting (45 %)", "Tor - starting (45 %)"),
            ("Tor: ready", "Tor - ready"),
            (
                "Tor: blocked on this network (bridges needed)",
                "Tor - blocked on this network (bridges needed)",
            ),
        ] {
            let mut probe = up(4242, "0.0.0.0:7420");
            probe.tor = Some(line.into());
            testkit::send(&mut app, Msg::Poll(PollUpdate::Status(probe)));
            let text = testkit::render_text(&app);
            assert!(text.contains(words), "{line}: {text}");
        }
        // Calm: the way in the Tor colour.
        let look = Look {
            glyphs: Glyphs::fancy(),
            theme: Theme::calm(&theme::DARK, theme::Depth::True),
            ..testkit::simple_mono()
        };
        let rows = way_rows(&look, TOR, GateState::On, "ready", PathKind::Tor, 80);
        assert_eq!(rows[0].spans[0].content, "Tor");
        assert_eq!(rows[0].spans[0].style, look.theme.path(PathKind::Tor));
        assert_eq!(tor_words("Tor:  "), None);
        assert_eq!(tor_words("ready"), Some("ready".into()));
    }

    #[test]
    fn bluetooth_says_what_the_background_program_does() {
        let mut node = NodeView::new(Program {
            binary: "/opt/raven/raven-node".into(),
            exe_known: true,
        });
        assert_eq!(bluetooth_words(&node), BLUETOOTH_NO_NODE);
        node.state = NodeState::Listening { port: Some(7420) };
        assert_eq!(bluetooth_words(&node), BLUETOOTH_NOT_RUN);
        node.nearby = Some(false);
        assert_eq!(bluetooth_words(&node), "Off.");
        node.nearby = Some(true);
        assert_eq!(bluetooth_words(&node), "On.");
        let look = testkit::simple_mono();
        let words = |gate| {
            way_rows(&look, BLUETOOTH, gate, "Off.", PathKind::Nearby, 200)[0]
                .spans
                .iter()
                .map(|s| s.content.as_ref())
                .collect::<String>()
        };
        assert_eq!(words(GateState::On), "Bluetooth - Off.");
        assert_eq!(words(GateState::Lab), "Bluetooth - Lab only. Off.");
        assert_eq!(
            words(GateState::Preview),
            "Bluetooth - Not in this version."
        );
    }

    #[test]
    fn net_windows_note() {
        let mut app = started_earlier();
        app.set_windows_for_tests(true);
        open_net(&mut app);
        let head = [
            "R A V E N - Network                             * Listening on port 7420  ? Help",
            "┌ Network and status ──────────────────────────────────────────────────────────┐",
            "│ This computer                                                                │",
            "│ * Listening on port 7420 on your network.                                    │",
            "│ Background program: Running (process 4242), started earlier                  │",
            "│ Program: /opt/raven/raven-node                                               │",
        ];
        let ways = [
            "│                                                                              │",
            "│ Ways to reach friends                                                        │",
            "│ This Wi-Fi or cable - On. Works without the internet.                        │",
            "│ A laptop's hotspot - Works. One of you makes it, the other joins (press G).  │",
            "│ Meeting in person - Works. Messages wait here until you meet, up to a day    │",
            "│   after you were last connected.                                             │",
            "│ Bluetooth - Not in this version.                                             │",
        ];
        // Before its command line is read: no note and no advice yet, and
        // never a force-kill command to type (E1).
        let rows = testkit::render(&app, 80, 24);
        testkit::assert_rows(&rows[..6], &head);
        testkit::assert_rows(&rows[6..13], &ways);
        assert!(!app.net_keys().stop);
        let folder = |app: &mut App, folder: NodeFolder| {
            testkit::send(app, Msg::Poll(PollUpdate::NodeFolder { pid: 4242, folder }));
            let rows = testkit::render(app, 80, 24);
            assert!(
                !testkit::screen_text(&rows).contains("taskkill"),
                "{rows:#?}"
            );
            rows
        };
        // This folder's: nothing to warn about, and [X] stops it (the app's
        // own stop).
        let rows = folder(&mut app, NodeFolder::This);
        testkit::assert_rows(&rows[..6], &head);
        testkit::assert_rows(&rows[6..13], &ways);
        assert!(app.net_keys().stop);
        assert_eq!(app.stop_plan(), StopPlan::TaskKill(4242));
        assert!(rows[22].contains("[X] Stop"), "{}", rows[22]);
        // Another folder's: said, with that folder; nothing to stop here.
        let rows = folder(&mut app, NodeFolder::Other(r"C:\Homes\sam\raven-b".into()));
        testkit::assert_rows(
            &rows[6..9],
            &[
                "│ The Raven background program running for your Windows account belongs to     │",
                "│ another Raven folder: C:\\Homes\\sam\\raven-b.                                  │",
                "│                                                                              │",
            ],
        );
        assert!(!app.net_keys().stop);
        // Its command line couldn't be read: the note, and how to stop it in
        // words.
        let rows = folder(&mut app, NodeFolder::Unknown);
        testkit::assert_rows(
            &rows[5..10],
            &[
                "│ To stop it yourself: end raven-node.exe in Task Manager (Details tab).       │",
                "│ Program: /opt/raven/raven-node                                               │",
                "│ A Raven background program for your Windows account is running. Raven can't  │",
                "│ tell whether it belongs to this Raven folder.                                │",
                "│                                                                              │",
            ],
        );
        let ssh = Session {
            over_ssh: true,
            ..testkit::session(Receive::On)
        };
        let mut over_ssh = settled((80, 24), ssh, up(4242, "0.0.0.0:7420"), 1);
        over_ssh.set_windows_for_tests(true);
        open_net(&mut over_ssh);
        assert!(!testkit::screen_text(&testkit::render(&over_ssh, 80, 24)).contains("SSH"));
    }

    #[test]
    fn the_ssh_note_and_waiting_messages() {
        let ssh = Session {
            over_ssh: true,
            ..testkit::session(Receive::On)
        };
        let mut app = settled((80, 24), ssh, up(4242, "0.0.0.0:7420"), 1);
        testkit::send(
            &mut app,
            testkit::outbox(vec![
                testkit::outbox_item(1, 1, "queued"),
                testkit::outbox_item(1, 2, "queued"),
                testkit::outbox_item(1, 3, "delivered"),
            ]),
        );
        open_net(&mut app);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24)[2..10],
            &[
                "│ This computer                                                                │",
                "│ * Listening on port 7420 on your network.                                    │",
                "│ Background program: Running (process 4242), started earlier                  │",
                "│ Program: /opt/raven/raven-node                                               │",
                "│ Waiting messages: 2 (Raven keeps trying)                                     │",
                "│ You're connected over SSH. On some Linux systems Raven's background program  │",
                "│ stops when you log out.                                                      │",
                "│                                                                              │",
            ],
        );
        // Once it stops, nothing retries them.
        testkit::send(&mut app, Msg::Poll(PollUpdate::Status(not_running())));
        assert_eq!(
            row(&app, 6),
            "│ Waiting messages: 2 (not being retried: the background program isn't         │"
        );
    }

    /// Review cross-5: a message parked until its deadline (`waiting`,
    /// Phase 5a) waits for the background program too, which alone pairs
    /// and seals it again: it counts, also when that program stops.
    #[test]
    fn a_parked_message_counts_as_waiting() {
        let mut app = settled(
            (80, 24),
            testkit::session(Receive::On),
            up(4242, "0.0.0.0:7420"),
            1,
        );
        testkit::send(
            &mut app,
            testkit::outbox(vec![
                testkit::outbox_item(1, 1, "waiting"),
                testkit::outbox_item(1, 2, "delivered"),
            ]),
        );
        open_net(&mut app);
        let shown = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(
            shown.contains("Waiting messages: 1 (Raven keeps trying)"),
            "{shown}"
        );
        testkit::send(&mut app, Msg::Poll(PollUpdate::Status(not_running())));
        let shown = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(
            shown.contains("Waiting messages: 1 (not being retried: the background program"),
            "{shown}"
        );
    }

    #[test]
    fn a_small_window_scrolls_the_panel_under_its_keys() {
        let ssh = Session {
            over_ssh: true,
            ..testkit::session(Receive::On)
        };
        let mut app = settled((60, 16), ssh, up(4242, "127.0.0.1:55001"), 1);
        open_net(&mut app);
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N          ~ Receiving on this computer only  ? Help",
                "┌ Network and status ──────────────────────────────────────┐",
                "│ This computer                                            │",
                "│ ~ Receiving on this computer only (127.0.0.1): friends   │",
                "│   on your network can't reach you. If Raven was          │",
                "│   installed to start at login, its installer listens     │",
                "│   only on this computer by default. To change that,      │",
                "│   reinstall with RAVEN_LAN_LISTEN=0.0.0.0:7420, or stop  │",
                "│   it and open Raven again.                               │",
                "│ Background program: Running (process 4242), started      │",
                "│ earlier                                                  │",
                "│ Program: /opt/raven/raven-node                           │",
                "│ You're connected over SSH. On some Linux systems Raven's │",
                "│                                                          │",
                "│ [L] Service log  [X] Stop  Up/Down Scroll  [Esc] Back    │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
        let max = max_scroll(&app);
        assert!(max > 0);
        testkit::press(&mut app, KeyCode::PageDown);
        testkit::press(&mut app, KeyCode::PageDown);
        testkit::press(&mut app, KeyCode::Down);
        assert!(matches!(app.screen(), Screen::Network(net) if net.scroll == max));
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N          ~ Receiving on this computer only  ? Help",
                "┌ Network and status ──────────────────────────────────────┐",
                "│ Meeting in person - Works. Messages wait here until you  │",
                "│   meet, up to a day after you were last connected.       │",
                "│ Bluetooth - Not in this version.                         │",
                "│ A friend carries messages - Not in this version.         │",
                "│ Over the internet - Not in this version.                 │",
                "│ Raven's background program uses: Local network.          │",
                "│                                                          │",
                "│ About this Raven                                         │",
                "│ This computer's network address: 192.168.1.20            │",
                "│ Raven folder: /home/sam/.raven                           │",
                "│ This build: Release                                      │",
                "│                                                          │",
                "│ [L] Service log  [X] Stop  Up/Down Scroll  [Esc] Back    │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
        // Grown, it fits: the scroll comes back in range.
        testkit::resize(&mut app, 100, 40);
        assert!(matches!(app.screen(), Screen::Network(net) if net.scroll == 0));
        testkit::press(&mut app, KeyCode::Up);
        assert!(matches!(app.screen(), Screen::Network(net) if net.scroll == 0));
    }

    #[test]
    fn stop_is_refused_on_windows_for_a_node_this_app_did_not_start() {
        // On Windows the pipe is per user: a pid this app did not start may
        // be another profile's node.
        let mut app = started_earlier();
        app.set_windows_for_tests(true);
        open_net(&mut app);
        assert_eq!(app.stop_plan(), StopPlan::Advise(Some(4242)));
        assert!(!app.net_keys().stop);
        assert!(testkit::press(&mut app, KeyCode::Char('x')).is_empty());
        assert!(matches!(app.screen(), Screen::Network(net) if !net.asking_stop));

        // One it started, still reported: X asks, Y stops that pid. (FW and
        // the notes shown once were shown for it already.)
        let shown = Session {
            settings: testkit::notes_seen(TuiState {
                receive: Receive::On,
                firewall_note_shown: true,
                ..TuiState::default()
            }),
            ..testkit::session(Receive::On)
        };
        let mut app = started_here((80, 24), shown);
        app.set_windows_for_tests(true);
        open_net(&mut app);
        assert_eq!(app.stop_plan(), StopPlan::TaskKill(4242));
        assert!(testkit::press(&mut app, KeyCode::Char('x')).is_empty());
        // The panel is longer than its window, but the question takes only
        // its answer: no scroll hint.
        testkit::assert_rows(
            &testkit::render(&app, 80, 24)[19..],
            &[
                "│                                                                              │",
                "│ Stop Raven's background program? Friends can't reach you until it runs       │",
                "│ again.                                                                       │",
                "│ [Y] Stop  [N] Keep it running                                                │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
            ],
        );
        let cmds = testkit::press(&mut app, KeyCode::Char('y'));
        assert_eq!(
            cmds,
            [Cmd::Node(NodeJob::Stop {
                started_by_app: Some(4242),
                managed: false,
            })]
        );
        assert_eq!(
            row(&app, 4),
            "│ Background program: Stopping...                                              │"
        );
        assert!(!app.net_keys().stop && !app.net_keys().start);

        // On Unix the profile's own Status names the one to stop, whoever
        // started it; N keeps it running.
        let mut app = started_earlier();
        open_net(&mut app);
        assert_eq!(app.stop_plan(), StopPlan::Terminate(4242));
        testkit::press(&mut app, KeyCode::Char('x'));
        assert!(matches!(app.screen(), Screen::Network(net) if net.asking_stop));
        assert!(testkit::press(&mut app, KeyCode::Char('n')).is_empty());
        assert!(matches!(app.screen(), Screen::Network(net) if !net.asking_stop));
    }

    #[test]
    fn a_stop_and_what_it_found() {
        let mut app = started_earlier();
        open_net(&mut app);
        testkit::press(&mut app, KeyCode::Char('x'));
        let cmds = testkit::press(&mut app, KeyCode::Char('y'));
        assert_eq!(
            cmds,
            [Cmd::Node(NodeJob::Stop {
                started_by_app: None,
                managed: false,
            })]
        );
        // It stopped: the panel says so, and S can start it again.
        answer(
            &mut app,
            JobResult::Stopped(Stopped {
                outcome: StopOutcome::Stopped,
                after: not_running(),
            }),
        );
        assert_eq!(
            row(&app, 4),
            "│ Background program: Not running                                              │"
        );
        assert!(app.net_keys().start);
        assert_eq!(app.toast(), None);
        // Still answering after the wait: a toast.
        let mut app = started_earlier();
        open_net(&mut app);
        answer(
            &mut app,
            JobResult::Stopped(Stopped {
                outcome: StopOutcome::StillRunning,
                after: up(4242, "0.0.0.0:7420"),
            }),
        );
        assert_eq!(
            app.toast().map(|t| t.text.as_str()),
            Some(app::STILL_RUNNING_TOAST)
        );
        // Refused by the rules when the worker looked again: the advice
        // stays on show while it runs.
        answer(
            &mut app,
            JobResult::Stopped(Stopped {
                outcome: StopOutcome::Advice("kill 4242".into()),
                after: up(4242, "0.0.0.0:7420"),
            }),
        );
        assert_eq!(
            row(&app, 5),
            "│ To stop it yourself: kill 4242                                               │"
        );
        testkit::send(&mut app, Msg::Poll(PollUpdate::Status(not_running())));
        assert!(!testkit::screen_text(&testkit::render(&app, 80, 24)).contains("kill 4242"));
    }

    #[test]
    fn check_again_after_it_stopped_answering() {
        let mut app = started_earlier();
        open_net(&mut app);
        assert!(!app.net_keys().check_again);
        testkit::send(&mut app, Msg::Poll(PollUpdate::Status(Probe::timed_out())));
        testkit::send(&mut app, Msg::Poll(PollUpdate::StatusStopped));
        assert_eq!(
            row(&app, 3),
            "│ ! Raven's background program isn't answering. Press R to check again.        │"
        );
        assert_eq!(
            row(&app, 22),
            "│ [L] Service log  [R] Check again  [Esc] Back                                 │"
        );
        let cmds = testkit::press(&mut app, KeyCode::Char('r'));
        assert!(cmds.contains(&Cmd::Poll(PollCtl::CheckAgain)), "{cmds:?}");
        assert!(cmds.contains(&Cmd::Node(NodeJob::Probe)), "{cmds:?}");
    }

    #[test]
    fn the_log_view_shows_the_last_lines() {
        let mut app = started_earlier();
        open_net(&mut app);
        let cmds = testkit::press(&mut app, KeyCode::Char('l'));
        assert!(cmds.contains(&Cmd::Node(NodeJob::ServiceLog)), "{cmds:?}");
        // The poller reads the log while it is open.
        assert!(cmds
            .iter()
            .any(|c| matches!(c, Cmd::Poll(PollCtl::Hints(h)) if h.read_log)));
        assert_eq!(
            row(&app, 3),
            "│ Reading the service log...                                                   │"
        );
        let lines: Vec<String> = (1..=40)
            .map(|n| format!("raven-node: line {n}"))
            .chain(["\x1b[31mred\x1b[0m and a very long line that goes on and on past the edge of the window".into()])
            .collect();
        answer(&mut app, JobResult::ServiceLog(Ok(lines)));
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Network                             * Listening on port 7420  ? Help",
                "┌ Service log ─────────────────────────────────────────────────────────────────┐",
                "│ raven-node: line 23                                                          │",
                "│ raven-node: line 24                                                          │",
                "│ raven-node: line 25                                                          │",
                "│ raven-node: line 26                                                          │",
                "│ raven-node: line 27                                                          │",
                "│ raven-node: line 28                                                          │",
                "│ raven-node: line 29                                                          │",
                "│ raven-node: line 30                                                          │",
                "│ raven-node: line 31                                                          │",
                "│ raven-node: line 32                                                          │",
                "│ raven-node: line 33                                                          │",
                "│ raven-node: line 34                                                          │",
                "│ raven-node: line 35                                                          │",
                "│ raven-node: line 36                                                          │",
                "│ raven-node: line 37                                                          │",
                "│ raven-node: line 38                                                          │",
                "│ raven-node: line 39                                                          │",
                "│ raven-node: line 40                                                          │",
                "│ red and a very long line that goes on and on past the edge of the window     │",
                "│                                                                              │",
                "│ Up/Down Scroll  [Esc] Back                                                   │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
            ],
        );
        testkit::press(&mut app, KeyCode::PageUp);
        testkit::press(&mut app, KeyCode::Up);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24)[1..6],
            &[
                "┌ Service log ─────────────────────────────────────────────────────────────────┐",
                "│ raven-node: line 3                                                           │",
                "│ raven-node: line 4                                                           │",
                "│ raven-node: line 5                                                           │",
                "│ raven-node: line 6                                                           │",
            ],
        );
        // The log grew: read again once, after the read before answered.
        let grew = || Msg::Poll(PollUpdate::ServiceLog("new\n".into()));
        let cmds = testkit::send(&mut app, grew());
        assert!(cmds.contains(&Cmd::Node(NodeJob::ServiceLog)), "{cmds:?}");
        let cmds = testkit::send(&mut app, grew());
        assert!(!cmds.contains(&Cmd::Node(NodeJob::ServiceLog)), "{cmds:?}");
        answer(&mut app, JobResult::ServiceLog(Ok(Vec::new())));
        assert_eq!(
            row(&app, 3),
            "│ Raven's background program hasn't written anything here yet.                 │"
        );
        answer(
            &mut app,
            JobResult::ServiceLog(Err("Permission denied (os error 13)".into())),
        );
        // The file as this system joins it (Windows: a `\` before its name).
        let file = bridge::service_log_path(std::path::Path::new(testkit::FOLDER));
        let file = format!("│ File: {:<70} │", file.display());
        testkit::assert_rows(
            &testkit::render(&app, 80, 24)[2..5],
            &[
                &file,
                "│ Raven couldn't read the service log.                                         │",
                "│ Permission denied (os error 13)                                              │",
            ],
        );
        // Esc: the panel again, and the poller stops reading the log.
        let cmds = testkit::press(&mut app, KeyCode::Esc);
        assert!(cmds
            .iter()
            .any(|c| matches!(c, Cmd::Poll(PollCtl::Hints(h)) if !h.read_log)));
        assert!(matches!(app.screen(), Screen::Network(net) if net.log.is_none()));
        // A read that answers after the view closed changes nothing.
        answer(&mut app, JobResult::ServiceLog(Ok(vec!["late".into()])));
        assert!(matches!(app.screen(), Screen::Network(net) if net.log.is_none()));
    }

    #[test]
    fn passfile_opens_from_net_and_from_add_a_friend() {
        let mut app = testkit::app((80, 24));
        app.start(testkit::session(Receive::On));
        answer(
            &mut app,
            JobResult::Vault(Vault {
                profile: true,
                needs_passphrase_file: true,
                ..Vault::default()
            }),
        );
        answer(&mut app, JobResult::Probed(not_running()));
        answer(
            &mut app,
            JobResult::Contacts {
                contacts: Ok(Vec::new()),
                stamp: FileStamp::default(),
            },
        );
        // The chip says 'press N': NET opens with PASSFILE over it.
        open_net(&mut app);
        assert_eq!(app.overlays(), [Overlay::PassFile]);
        testkit::assert_rows(&testkit::render(&app, 80, 24), &[
            "R A V E N - Network                               ! Needs setup: press N  ? Help",
            "┌ Network and status ──────────────────────────────────────────────────────────┐",
            "│ This computer                                                                │",
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
            "│                                                                              │",
            "│                                                                              │",
            "│ [L] Service log  [Esc] Back                                                  │",
            "└──────────────────────────────────────────────────────────────────────────────┘",
        ]);
        testkit::press(&mut app, KeyCode::Esc);
        assert!(app.overlays().is_empty());
        assert_eq!(
            row(&app, 3),
            "│ ! Raven's background program needs one more step on this computer.           │"
        );
        assert!(!app.net_keys().start);
        // AF-1's share box says 'Press N to see how'.
        testkit::press(&mut app, KeyCode::Esc);
        testkit::press(&mut app, KeyCode::Char('a'));
        testkit::press(&mut app, KeyCode::Tab);
        testkit::press(&mut app, KeyCode::Char('n'));
        assert_eq!(app.overlays(), [Overlay::PassFile]);
    }

    #[test]
    fn help_over_net_lists_its_keys() {
        let mut app = started_earlier();
        open_net(&mut app);
        testkit::press(&mut app, KeyCode::Char('?'));
        assert_eq!(app.overlays(), [Overlay::Help { scroll: 0 }]);
        let text = testkit::screen_text(&testkit::render(&app, 80, 24));
        for key in [
            "L Service log",
            "S Start the background program",
            "X Stop it",
            "R Check again",
        ] {
            assert!(text.contains(key), "{text}");
        }
        testkit::press(&mut app, KeyCode::Esc);
        // Q asks to quit, Ctrl+C too.
        testkit::press(&mut app, KeyCode::Char('q'));
        assert_eq!(app.overlays(), [Overlay::Quit]);
    }

    // ── Why it isn't receiving, and no network at all ───────────────────────

    /// A Status from raven-node `pid` that runs with its listener down: an
    /// older node, which doesn't say why.
    fn send_only(pid: u32) -> Probe {
        Probe::of(&Ok(IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into()],
            p2p: None,
            pid: Some(pid),
            lan_listen: None,
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

    /// What the poller read of the service log: raven-node's bind of
    /// `wanted` failed with the OS's `error`, and it tries again.
    fn bind_failed(wanted: &str, error: &str) -> Msg {
        Msg::Poll(PollUpdate::ServiceLog(format!(
            "lan_direct failed: lan_direct bind {wanted}: {error}\nlan_direct: unavailable; IPC \
             and the other transports keep running; retrying in 30s\n"
        )))
    }

    /// macOS's words for an address that isn't on this computer.
    const NOT_HERE: &str = "Can't assign requested address (os error 49)";

    /// raven-node's Status, as the poller heard it.
    fn status(app: &mut App, probe: Probe) -> Vec<Cmd> {
        testkit::send(app, Msg::Poll(PollUpdate::Status(probe)))
    }

    /// Whether this computer is on any network, as the poller read it.
    fn networks(app: &mut App, on_any: Option<bool>) {
        testkit::send(app, Msg::Poll(PollUpdate::Network(on_any)));
    }

    /// Whether `cmds` last tell the poller to read the service log.
    fn reads_log(cmds: &[Cmd]) -> Option<bool> {
        cmds.iter().rev().find_map(|c| match c {
            Cmd::Poll(PollCtl::Hints(h)) => Some(h.read_log),
            _ => None,
        })
    }

    #[test]
    fn an_older_node_gets_the_address_not_here_row_from_its_log() {
        let mut app = started_earlier();
        // It runs without receiving: the poller reads its log from now on.
        let cmds = status(&mut app, send_only(4242));
        assert_eq!(reads_log(&cmds), Some(true), "{cmds:?}");
        open_net(&mut app);
        assert_eq!(
            row(&app, 3),
            "│ ~ Sending only, not receiving.                                               │"
        );
        testkit::send(&mut app, bind_failed("192.168.1.20:7420", NOT_HERE));
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Network                   o Not receiving (address not here)  ? Help",
                "┌ Network and status ──────────────────────────────────────────────────────────┐",
                "│ This computer                                                                │",
                "│ o Not receiving: Raven is set to listen on 192.168.1.20:7420, which isn't on │",
                "│   this computer now (did you change networks?). It starts listening by       │",
                "│   itself when that address is back. To listen on every network instead,      │",
                "│   reinstall with RAVEN_LAN_LISTEN=0.0.0.0:7420.                              │",
                "│ Background program: Running (process 4242), started earlier                  │",
                "│ Program: /opt/raven/raven-node                                               │",
                "│                                                                              │",
                "│ Ways to reach friends                                                        │",
                "│ This Wi-Fi or cable - On. Works without the internet.                        │",
                "│ A laptop's hotspot - Works. One of you makes it, the other joins (press G).  │",
                "│ Meeting in person - Works. Messages wait here until you meet, up to a day    │",
                "│   after you were last connected.                                             │",
                "│ Bluetooth - Not in this version.                                             │",
                "│ A friend carries messages - Not in this version.                             │",
                "│ Over the internet - Not in this version.                                     │",
                "│ Raven's background program isn't using any of these right now.               │",
                "│                                                                              │",
                "│ About this Raven                                                             │",
                "│                                                                              │",
                "│ [L] Service log  [X] Stop  Up/Down Scroll  [Esc] Back                        │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
            ],
        );
        // The same chip on Home's header (UXF.10: the wordmark, no help key).
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(
            header(&app, 80, 24),
            "R A V E N                                     o Not receiving (address not here)"
        );
        open_net(&mut app);
        // The address is back and it listens: the poller stops reading.
        let cmds = status(&mut app, up(4242, "192.168.1.20:7420"));
        assert_eq!(reads_log(&cmds), Some(false), "{cmds:?}");
        assert_eq!(
            row(&app, 3),
            "│ * Listening on port 7420 on your network.                                    │"
        );
        // Down again: the old word is gone until the log says it again.
        status(&mut app, send_only(4242));
        assert_eq!(
            row(&app, 3),
            "│ ~ Sending only, not receiving.                                               │"
        );
    }

    #[test]
    fn the_status_says_why_after_the_cutoff_pack() {
        // Its fields (CP.5) fill the Probe's `bind`; the rows are the same.
        let mut answer = Ok(IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into()],
            p2p: None,
            pid: Some(4242),
            lan_listen: None,
            last_paths: Vec::new(),
            route_hints: None,
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: Some("192.168.1.20:7420".into()),
            lan_bind_error: Some("addr_not_here".into()),
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
        });
        let told = Probe::of(&answer);
        assert_eq!(
            told.bind,
            Some(BindFailure::AddrNotHere {
                wanted: "192.168.1.20:7420".into(),
            })
        );
        if let Ok(IpcResponse::Status { lan_bind_error, .. }) = &mut answer {
            *lan_bind_error = None;
        }
        assert_eq!(
            Probe::of(&answer),
            send_only(4242),
            "an older node's Status"
        );
        let mut app = settled((80, 24), testkit::session(Receive::On), told, 1);
        open_net(&mut app);
        let mut logged = settled((80, 24), testkit::session(Receive::On), send_only(4242), 1);
        testkit::send(&mut logged, bind_failed("192.168.1.20:7420", NOT_HERE));
        open_net(&mut logged);
        assert_eq!(
            testkit::render(&app, 80, 24),
            testkit::render(&logged, 80, 24)
        );
        assert_eq!(
            header(&app, 80, 24),
            "R A V E N - Network                   o Not receiving (address not here)  ? Help"
        );
    }

    #[test]
    fn another_program_on_its_port() {
        let mut app = settled((80, 24), testkit::session(Receive::On), send_only(4242), 1);
        testkit::send(
            &mut app,
            bind_failed("0.0.0.0:7420", "Address already in use (os error 48)"),
        );
        open_net(&mut app);
        // The header keeps its chip: only NET says why.
        testkit::assert_rows(
            &testkit::render(&app, 80, 24)[..6],
            &[
                "R A V E N - Network                        ~ Sending only, not receiving  ? Help",
                "┌ Network and status ──────────────────────────────────────────────────────────┐",
                "│ This computer                                                                │",
                "│ ~ Not receiving: another program on this computer uses port 7420.            │",
                "│ Background program: Running (process 4242), started earlier                  │",
                "│ Program: /opt/raven/raven-node                                               │",
            ],
        );
        // Linux and Windows say it in their own words.
        for error in [
            "Address already in use (os error 98)",
            "Only one usage of each socket address (protocol/network address/port) is \
             normally permitted. (os error 10048)",
        ] {
            testkit::send(&mut app, bind_failed("[::]:7424", error));
            assert_eq!(
                row(&app, 3),
                "│ ~ Not receiving: another program on this computer uses port 7424.            │"
            );
        }
    }

    #[test]
    fn the_address_it_wants_is_shaped_and_cut() {
        let mut app = settled((80, 24), testkit::session(Receive::On), send_only(4242), 1);
        let long = format!("\u{1b}]0;pwned\u{7}{}:7420", "a".repeat(100));
        testkit::send(&mut app, bind_failed(&long, NOT_HERE));
        open_net(&mut app);
        let rows = testkit::render(&app, 80, 24);
        let text = testkit::screen_text(&rows);
        assert!(
            !text.contains("pwned") && !text.contains('\u{1b}'),
            "{text}"
        );
        testkit::assert_rows(
            &rows[2..8],
            &[
                "│ This computer                                                                │",
                "│ o Not receiving: Raven is set to listen on                                   │",
                "│   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa..., which isn't on this      │",
                "│   computer now (did you change networks?). It starts listening by itself     │",
                "│   when that address is back. To listen on every network instead, reinstall   │",
                "│   with RAVEN_LAN_LISTEN=0.0.0.0:7420.                                        │",
            ],
        );
    }

    #[test]
    fn net_on_no_network_at_all() {
        let mut app = started_earlier();
        open_net(&mut app);
        networks(&mut app, Some(false));
        // It listens, but nothing reaches it: the network row in place of
        // the listener's, and the chip says the same.
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Network                                 o Not on any network  ? Help",
                "┌ Network and status ──────────────────────────────────────────────────────────┐",
                "│ This computer                                                                │",
                "│ o This computer isn't on any network. To reach a friend nearby, join the     │",
                "│   same Wi-Fi, make a hotspot, or connect a cable. Your messages wait here.   │",
                "│ Background program: Running (process 4242), started earlier                  │",
                "│ Program: /opt/raven/raven-node                                               │",
                "│                                                                              │",
                "│ Ways to reach friends                                                        │",
                "│ This Wi-Fi or cable - On. Works without the internet.                        │",
                "│ A laptop's hotspot - Works. One of you makes it, the other joins (press G).  │",
                "│ Meeting in person - Works. Messages wait here until you meet, up to a day    │",
                "│   after you were last connected.                                             │",
                "│ Bluetooth - Not in this version.                                             │",
                "│ A friend carries messages - Not in this version.                             │",
                "│ Over the internet - Not in this version.                                     │",
                "│ Raven's background program uses: Local network.                              │",
                "│                                                                              │",
                "│ About this Raven                                                             │",
                "│ This computer's network address: 192.168.1.20                                │",
                "│ Raven folder: /home/sam/.raven                                               │",
                "│                                                                              │",
                "│ [L] Service log  [X] Stop  Up/Down Scroll  [Esc] Back                        │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
            ],
        );
        // The same chip on Home's header (UXF.10: the wordmark, no help key).
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(
            header(&app, 80, 24),
            "R A V E N                                                   o Not on any network"
        );
        open_net(&mut app);
        // Known again, or not known: the rows as before.
        for on_any in [Some(true), None] {
            networks(&mut app, on_any);
            assert_eq!(
                header(&app, 80, 24),
                "R A V E N - Network                             * Listening on port 7420  ? Help"
            );
            assert_eq!(
                row(&app, 3),
                "│ * Listening on port 7420 on your network.                                    │"
            );
        }
        // Not answering: that chip stays, and NET says both.
        networks(&mut app, Some(false));
        status(&mut app, Probe::timed_out());
        testkit::assert_rows(
            &testkit::render(&app, 80, 24)[..8],
            &[
                "R A V E N - Network                            ! Not responding: press N  ? Help",
                "┌ Network and status ──────────────────────────────────────────────────────────┐",
                "│ This computer                                                                │",
                "│ o This computer isn't on any network. To reach a friend nearby, join the     │",
                "│   same Wi-Fi, make a hotspot, or connect a cable. Your messages wait here.   │",
                "│ ! Raven's background program isn't answering. Press R to check again.        │",
                "│ Background program: Not responding                                           │",
                "│ Program: /opt/raven/raven-node                                               │",
            ],
        );
        // Starting (a friend is saved, so it starts by itself): the
        // spinner stays.
        let mut starting = settled((80, 24), testkit::session(Receive::On), not_running(), 1);
        assert!(matches!(starting.node().state, NodeState::Starting { .. }));
        open_net(&mut starting);
        networks(&mut starting, Some(false));
        testkit::assert_rows(
            &testkit::render(&starting, 80, 24)[..8],
            &[
                "R A V E N - Network                                  | Starting Raven...  ? Help",
                "┌ Network and status ──────────────────────────────────────────────────────────┐",
                "│ This computer                                                                │",
                "│ o This computer isn't on any network. To reach a friend nearby, join the     │",
                "│   same Wi-Fi, make a hotspot, or connect a cable. Your messages wait here.   │",
                "│ | Starting Raven...                                                          │",
                "│ Background program: Starting...                                              │",
                "│ Program: /opt/raven/raven-node                                               │",
            ],
        );
        // Receiving off, nothing running: the network says it all.
        let mut off = settled((80, 24), testkit::session(Receive::Off), not_running(), 1);
        open_net(&mut off);
        networks(&mut off, Some(false));
        testkit::assert_rows(
            &testkit::render(&off, 80, 24)[..8],
            &[
                "R A V E N - Network                                 o Not on any network  ? Help",
                "┌ Network and status ──────────────────────────────────────────────────────────┐",
                "│ This computer                                                                │",
                "│ o This computer isn't on any network. To reach a friend nearby, join the     │",
                "│   same Wi-Fi, make a hotspot, or connect a cable. Your messages wait here.   │",
                "│ Background program: Not running                                              │",
                "│ Program: /opt/raven/raven-node                                               │",
                "│                                                                              │",
            ],
        );
        networks(&mut off, Some(true));
        assert_eq!(
            row(&off, 3),
            "│ o Receiving is off (Settings).                                               │"
        );
    }

    #[test]
    fn the_new_chips_fit_at_60_columns() {
        let mut gone = settled((60, 16), testkit::session(Receive::On), send_only(4242), 1);
        testkit::send(&mut gone, bind_failed("192.168.1.20:7420", NOT_HERE));
        let mut offline = settled(
            (60, 16),
            testkit::session(Receive::On),
            up(4242, "0.0.0.0:7420"),
            1,
        );
        networks(&mut offline, Some(false));
        for (app, home, net) in [
            (
                gone,
                "R A V E N                 o Not receiving (address not here)",
                "R A V E N         o Not receiving (address not here)  ? Help",
            ),
            (
                offline,
                "R A V E N                               o Not on any network",
                "R A V E N - Network             o Not on any network  ? Help",
            ),
        ] {
            // On Home (UXF.10: the wordmark, no help key), and on NET.
            assert_eq!(header(&app, 60, 16), home);
            let mut app = app;
            open_net(&mut app);
            assert_eq!(header(&app, 60, 16), net);
        }
    }

    #[test]
    fn every_form_on_this_computer_only_is_named() {
        let ipv6: &[&str] = &[
            "│ ~ Receiving on this computer only (::1): friends on your network can't reach │",
            "│   you. If Raven was installed to start at login, its installer listens only  │",
            "│   on this computer by default. To change that, reinstall with                │",
            "│   RAVEN_LAN_LISTEN=0.0.0.0:7420, or stop it and open Raven again.            │",
        ];
        let name: &[&str] = &[
            "│ ~ Receiving on this computer only (localhost): friends on your network can't │",
            "│   reach you. If Raven was installed to start at login, its installer listens │",
            "│   only on this computer by default. To change that, reinstall with           │",
            "│   RAVEN_LAN_LISTEN=0.0.0.0:7420, or stop it and open Raven again.            │",
        ];
        for (listen, want) in [("[::1]:55001", ipv6), ("localhost:7420", name)] {
            let mut app = settled((80, 24), testkit::session(Receive::On), up(4242, listen), 1);
            open_net(&mut app);
            let rows = testkit::render(&app, 80, 24);
            assert_eq!(
                rows[0],
                "R A V E N - Network                    ~ Receiving on this computer only  ? Help"
            );
            testkit::assert_rows(&rows[3..7], want);
        }
    }

    /// NET's header row.
    fn header(app: &App, width: u16, height: u16) -> String {
        testkit::render(app, width, height)[0].clone()
    }

    // ── Ways to reach friends ───────────────────────────────────────────────

    /// Each way's row as one line of text, and the style of its words.
    fn ways_said(gates: &GatesView) -> Vec<(String, Style)> {
        let look = testkit::simple_mono();
        ways(gates, OFF)
            .into_iter()
            .map(|(way, gate, works, kind)| {
                let rows = way_rows(&look, way, gate, works, kind, 200);
                assert_eq!(rows.len(), 1, "{way}");
                let spans = &rows[0].spans;
                // No colours: the way plain (its path's colour in a
                // palette while it is on).
                assert_eq!(spans[0].style, look.theme.text, "{way}");
                let text = spans.iter().map(|s| s.content.as_ref()).collect();
                (text, spans[spans.len() - 1].style)
            })
            .collect()
    }

    #[test]
    fn the_ways_follow_the_gates_and_a_held_one_is_never_on() {
        let look = testkit::simple_mono();
        let (plain, dim, bold) = (Style::default(), look.theme.secondary, look.theme.warn);
        let said = |text: &str, style| (text.to_owned(), style);
        // A release: the local network's ways work, the rest are not in
        // this version (dim).
        assert_eq!(
            ways_said(&testkit::release_gates()),
            [
                said(
                    "This Wi-Fi or cable - On. Works without the internet.",
                    plain
                ),
                said(
                    "A laptop's hotspot - Works. One of you makes it, the other joins \
                     (press G).",
                    plain
                ),
                said(
                    "Meeting in person - Works. Messages wait here until you meet, up to a \
                     day after you were last connected.",
                    plain
                ),
                said("Bluetooth - Not in this version.", dim),
                said("A friend carries messages - Not in this version.", dim),
                said("Over the internet - Not in this version.", dim),
            ]
        );
        // A lab set: held ways the lab switch has on read 'Lab only' (bold),
        // never on; Bluetooth with the background program's state, as `raven
        // status` says it (E1).
        let lab = ways_said(&lab_gates());
        assert_eq!(lab[3], said("Bluetooth - Lab only. Off.", bold));
        assert_eq!(lab[4], said("A friend carries messages - Lab only", bold));
        assert_eq!(lab[5], said("Over the internet - Lab only", bold));
        // Nothing on yet (before the session says): the local network's ways
        // too are not in this version; with only its lab switch, lab only.
        let gate = |production, live| bridge::Gate { production, live };
        let with_lan = |lan| {
            GatesView::of(
                bridge::Gates {
                    lan,
                    internet: gate(false, false),
                    p2p: gate(false, false),
                    custody: gate(false, false),
                    nearby: gate(false, false),
                },
                true,
            )
        };
        for (lan, words, style) in [
            (gate(false, false), "Not in this version.", dim),
            (gate(false, true), "Lab only", bold),
        ] {
            let rows = ways_said(&with_lan(lan));
            for (row, way) in rows[..3].iter().zip([WIFI, HOTSPOT, IN_PERSON]) {
                assert_eq!(row, &said(&format!("{way} - {words}"), style));
            }
        }
        // Over the internet is either carrier: on when one's constant is.
        for (internet, p2p, want) in [
            (gate(true, true), gate(false, false), ("On.", plain)),
            (gate(false, false), gate(true, false), ("On.", plain)),
            (gate(false, false), gate(false, true), ("Lab only", bold)),
            (gate(false, true), gate(false, false), ("Lab only", bold)),
        ] {
            let gates = GatesView::of(
                bridge::Gates {
                    lan: gate(true, true),
                    internet,
                    p2p,
                    custody: gate(false, false),
                    nearby: gate(false, false),
                },
                false,
            );
            assert_eq!(
                ways_said(&gates)[5],
                said(&format!("Over the internet - {}", want.0), want.1)
            );
        }
    }

    #[test]
    fn net_in_every_glyph_set_at_60_by_16() {
        let fancy: (&[&str], &[&str]) = (
            &[
                "R A V E N        ○ Not receiving (address not here) · ? Help",
                "╭ Network and status ──────────────────────────────────────╮",
                "│ This computer                                            │",
                "│ ○ Not receiving: Raven is set to listen on               │",
                "│   192.168.1.20:7420, which isn't on this computer now    │",
                "│   (did you change networks?). It starts listening by     │",
                "│   itself when that address is back. To listen on every   │",
                "│   network instead, reinstall with                        │",
                "│   RAVEN_LAN_LISTEN=0.0.0.0:7420.                         │",
                "│ Background program: Running (process 4242), started      │",
                "│ earlier                                                  │",
                "│ Program: /opt/raven/raven-node                           │",
                "│                                                          │",
                "│                                                          │",
                "│ [L] Service log  [X] Stop  ↑↓ Scroll  [Esc] Back         │",
                "╰──────────────────────────────────────────────────────────╯",
            ],
            &[
                "R A V E N        ○ Not receiving (address not here) · ? Help",
                "╭ Network and status ──────────────────────────────────────╮",
                "│ Ways to reach friends                                    │",
                "│ This Wi-Fi or cable · On. Works without the internet.    │",
                "│ A laptop's hotspot · Works. One of you makes it, the     │",
                "│   other joins (press G).                                 │",
                "│ Meeting in person · Works. Messages wait here until you  │",
                "│   meet, up to a day after you were last connected.       │",
                "│ Bluetooth · Not in this version.                         │",
                "│ A friend carries messages · Not in this version.         │",
                "│ Over the internet · Not in this version.                 │",
                "│ Raven's background program isn't using any of these      │",
                "│ right now.                                               │",
                "│                                                          │",
                "│ [L] Service log  [X] Stop  ↑↓ Scroll  [Esc] Back         │",
                "╰──────────────────────────────────────────────────────────╯",
            ],
        );
        let simple: (&[&str], &[&str]) = (
            &[
                "R A V E N         o Not receiving (address not here)  ? Help",
                "┌ Network and status ──────────────────────────────────────┐",
                "│ This computer                                            │",
                "│ o Not receiving: Raven is set to listen on               │",
                "│   192.168.1.20:7420, which isn't on this computer now    │",
                "│   (did you change networks?). It starts listening by     │",
                "│   itself when that address is back. To listen on every   │",
                "│   network instead, reinstall with                        │",
                "│   RAVEN_LAN_LISTEN=0.0.0.0:7420.                         │",
                "│ Background program: Running (process 4242), started      │",
                "│ earlier                                                  │",
                "│ Program: /opt/raven/raven-node                           │",
                "│                                                          │",
                "│                                                          │",
                "│ [L] Service log  [X] Stop  Up/Down Scroll  [Esc] Back    │",
                "└──────────────────────────────────────────────────────────┘",
            ],
            &[
                "R A V E N         o Not receiving (address not here)  ? Help",
                "┌ Network and status ──────────────────────────────────────┐",
                "│ Ways to reach friends                                    │",
                "│ This Wi-Fi or cable - On. Works without the internet.    │",
                "│ A laptop's hotspot - Works. One of you makes it, the     │",
                "│   other joins (press G).                                 │",
                "│ Meeting in person - Works. Messages wait here until you  │",
                "│   meet, up to a day after you were last connected.       │",
                "│ Bluetooth - Not in this version.                         │",
                "│ A friend carries messages - Not in this version.         │",
                "│ Over the internet - Not in this version.                 │",
                "│ Raven's background program isn't using any of these      │",
                "│ right now.                                               │",
                "│                                                          │",
                "│ [L] Service log  [X] Stop  Up/Down Scroll  [Esc] Back    │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
        let ascii: (&[&str], &[&str]) = (
            &[
                "R A V E N         o Not receiving (address not here)  ? Help",
                "+ Network and status --------------------------------------+",
                "| This computer                                            |",
                "| o Not receiving: Raven is set to listen on               |",
                "|   192.168.1.20:7420, which isn't on this computer now    |",
                "|   (did you change networks?). It starts listening by     |",
                "|   itself when that address is back. To listen on every   |",
                "|   network instead, reinstall with                        |",
                "|   RAVEN_LAN_LISTEN=0.0.0.0:7420.                         |",
                "| Background program: Running (process 4242), started      |",
                "| earlier                                                  |",
                "| Program: /opt/raven/raven-node                           |",
                "|                                                          |",
                "|                                                          |",
                "| [L] Service log  [X] Stop  Up/Down Scroll  [Esc] Back    |",
                "+----------------------------------------------------------+",
            ],
            &[
                "R A V E N         o Not receiving (address not here)  ? Help",
                "+ Network and status --------------------------------------+",
                "| Ways to reach friends                                    |",
                "| This Wi-Fi or cable - On. Works without the internet.    |",
                "| A laptop's hotspot - Works. One of you makes it, the     |",
                "|   other joins (press G).                                 |",
                "| Meeting in person - Works. Messages wait here until you  |",
                "|   meet, up to a day after you were last connected.       |",
                "| Bluetooth - Not in this version.                         |",
                "| A friend carries messages - Not in this version.         |",
                "| Over the internet - Not in this version.                 |",
                "| Raven's background program isn't using any of these      |",
                "| right now.                                               |",
                "|                                                          |",
                "| [L] Service log  [X] Stop  Up/Down Scroll  [Esc] Back    |",
                "+----------------------------------------------------------+",
            ],
        );
        for (glyphs, (top, group)) in [
            (Glyphs::fancy(), fancy),
            (Glyphs::simple(), simple),
            (Glyphs::ascii(), ascii),
        ] {
            let look = Look {
                glyphs,
                ..testkit::simple_mono()
            };
            let mut app = settled_in(
                look,
                (60, 16),
                testkit::session(Receive::On),
                send_only(4242),
                1,
            );
            testkit::send(&mut app, bind_failed("192.168.1.20:7420", NOT_HERE));
            open_net(&mut app);
            testkit::assert_rows(&testkit::render(&app, 60, 16), top);
            // A window down: the ways to reach friends.
            testkit::press(&mut app, KeyCode::PageDown);
            testkit::assert_rows(&testkit::render(&app, 60, 16), group);
        }
    }

    // ── The at-rest state (privacy pack PP.21) ──────────────────────────────

    /// One friend, receiving on, and a node that ran before the app as
    /// process 4242, its Status saying the at-rest state is `state`; the
    /// privacy read not available. The state the Status brought asked for
    /// that read again, once the first one ended.
    fn at_rest_app(size: (u16, u16), state: &str) -> App {
        let mut app = settled(
            size,
            testkit::session(Receive::On),
            up_at_rest(4242, "0.0.0.0:7420", Some(state)),
            1,
        );
        let not_available = JobResult::Privacy(Err(bridge::NotAvailable));
        let again = answer(&mut app, not_available.clone());
        assert_eq!(privacy_reads(&again), 1, "{again:?}");
        assert_eq!(privacy_reads(&answer(&mut app, not_available)), 0);
        app
    }

    fn privacy_reads(cmds: &[Cmd]) -> usize {
        cmds.iter()
            .filter(|cmd| **cmd == Cmd::Store(app::StoreJob::LoadPrivacy))
            .count()
    }

    #[test]
    fn net_says_when_raven_cant_open_the_friends_list() {
        for state in ["key_unavailable", "key_lost", "waiting_for_keychain"] {
            let app = at_rest_app((80, 24), state);
            assert_eq!(app.chip(), Some(widgets::Chip::LockedOut), "{state}");
        }
        let mut app = at_rest_app((80, 24), "key_unavailable");
        open_net(&mut app);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Network                    o Locked out of your friends list  ? Help",
                "┌ Network and status ──────────────────────────────────────────────────────────┐",
                "│ This computer                                                                │",
                "│ Raven can't open your friends list: it needs your keychain (or your Raven    │",
                "│ passphrase). Until then nobody can connect to you and nothing is sent. On a  │",
                "│ Mac, answer the keychain dialog; with a passphrase file, check that it is in │",
                "│ place. Raven tries again in a few minutes, and right away when you run       │",
                "│ `raven status`.                                                              │",
                "│ * Listening on port 7420 on your network.                                    │",
                "│ Background program: Running (process 4242), started earlier                  │",
                "│ Program: /opt/raven/raven-node                                               │",
                "│                                                                              │",
                "│ Ways to reach friends                                                        │",
                "│ This Wi-Fi or cable - On. Works without the internet.                        │",
                "│ A laptop's hotspot - Works. One of you makes it, the other joins (press G).  │",
                "│ Meeting in person - Works. Messages wait here until you meet, up to a day    │",
                "│   after you were last connected.                                             │",
                "│ Bluetooth - Not in this version.                                             │",
                "│ A friend carries messages - Not in this version.                             │",
                "│ Over the internet - Not in this version.                                     │",
                "│ Raven's background program uses: Local network.                              │",
                "│                                                                              │",
                "│ [L] Service log  [X] Stop  Up/Down Scroll  [Esc] Back                        │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
            ],
        );
        let mut small = at_rest_app((60, 16), "key_unavailable");
        open_net(&mut small);
        testkit::assert_rows(
            &testkit::render(&small, 60, 16),
            &[
                "R A V E N          o Locked out of your friends list  ? Help",
                "┌ Network and status ──────────────────────────────────────┐",
                "│ This computer                                            │",
                "│ Raven can't open your friends list: it needs your        │",
                "│ keychain (or your Raven passphrase). Until then nobody   │",
                "│ can connect to you and nothing is sent. On a Mac, answer │",
                "│ the keychain dialog; with a passphrase file, check that  │",
                "│ it is in place. Raven tries again in a few minutes, and  │",
                "│ right away when you run `raven status`.                  │",
                "│ * Listening on port 7420 on your network.                │",
                "│ Background program: Running (process 4242), started      │",
                "│ earlier                                                  │",
                "│ Program: /opt/raven/raven-node                           │",
                "│                                                          │",
                "│ [L] Service log  [X] Stop  Up/Down Scroll  [Esc] Back    │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
        // The key is back: the chip and the row go, and the privacy read
        // runs again (once) for the notices.
        let cmds = status(&mut app, up_at_rest(4242, "0.0.0.0:7420", Some("sealed")));
        assert_eq!(privacy_reads(&cmds), 1, "{cmds:?}");
        assert_eq!(
            app.chip(),
            Some(widgets::Chip::Listening { port: Some(7420) })
        );
        let text = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(!text.contains("can't open your friends list"), "{text}");
        // The same state again asks for nothing; an older node says none.
        let cmds = status(&mut app, up_at_rest(4242, "0.0.0.0:7420", Some("sealed")));
        assert_eq!(privacy_reads(&cmds), 0, "{cmds:?}");
        status(&mut app, up(4242, "0.0.0.0:7420"));
        assert_eq!(app.node().at_rest, None);
        assert_eq!(
            app.chip(),
            Some(widgets::Chip::Listening { port: Some(7420) })
        );
    }

    /// Review A-keys-format-4: a key gone from the keystore is said as gone
    /// (put it back, or erase), never "answer the keychain dialog".
    #[test]
    fn net_says_when_the_friends_lists_key_is_gone() {
        let mut app = at_rest_app((80, 24), "key_lost");
        assert_eq!(app.chip(), Some(widgets::Chip::LockedOut));
        open_net(&mut app);
        let text = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(text.contains(bridge::KEY_LOST_TEXT), "{text}");
        assert!(!text.contains("answer the keychain dialog"), "{text}");
    }

    #[test]
    fn net_rows_for_disk_space_and_an_unsealed_profile() {
        // Sealing waits for free disk space: how much, once the privacy
        // read says it.
        let mut app = at_rest_app((80, 24), "needs_disk_space");
        open_net(&mut app);
        let text = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(
            text.contains(
                "Raven needs more free disk space to finish encrypting this profile. Nothing was \
                 changed."
            ),
            "{text}"
        );
        answer(
            &mut app,
            JobResult::Privacy(Ok(PrivacyRead {
                keep: bridge::ChatKeepView::Days30,
                notices: Default::default(),
                disk_needed: Some(150 << 20),
                login_item_stays_off: false,
            })),
        );
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Network                             * Listening on port 7420  ? Help",
                "┌ Network and status ──────────────────────────────────────────────────────────┐",
                "│ This computer                                                                │",
                "│ Raven needs more free disk space to finish encrypting this profile (about    │",
                "│ 150 MB). Nothing was changed.                                                │",
                "│ * Listening on port 7420 on your network.                                    │",
                "│ Background program: Running (process 4242), started earlier                  │",
                "│ Program: /opt/raven/raven-node                                               │",
                "│                                                                              │",
                "│ Ways to reach friends                                                        │",
                "│ This Wi-Fi or cable - On. Works without the internet.                        │",
                "│ A laptop's hotspot - Works. One of you makes it, the other joins (press G).  │",
                "│ Meeting in person - Works. Messages wait here until you meet, up to a day    │",
                "│   after you were last connected.                                             │",
                "│ Bluetooth - Not in this version.                                             │",
                "│ A friend carries messages - Not in this version.                             │",
                "│ Over the internet - Not in this version.                                     │",
                "│ Raven's background program uses: Local network.                              │",
                "│                                                                              │",
                "│ About this Raven                                                             │",
                "│ This computer's network address: 192.168.1.20                                │",
                "│                                                                              │",
                "│ [L] Service log  [X] Stop  Up/Down Scroll  [Esc] Back                        │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
            ],
        );
        assert_eq!(
            app.chip(),
            Some(widgets::Chip::Listening { port: Some(7420) })
        );
        // Unsealed by the user: its one line, at the smallest size.
        let mut small = at_rest_app((60, 16), "unsealed_by_user");
        open_net(&mut small);
        testkit::assert_rows(
            &testkit::render(&small, 60, 16),
            &[
                "R A V E N - Network         * Listening on port 7420  ? Help",
                "┌ Network and status ──────────────────────────────────────┐",
                "│ This computer                                            │",
                "│ This profile is not encrypted (you ran `raven privacy    │",
                "│ unseal`). To encrypt it again: `raven privacy seal-now`. │",
                "│ * Listening on port 7420 on your network.                │",
                "│ Background program: Running (process 4242), started      │",
                "│ earlier                                                  │",
                "│ Program: /opt/raven/raven-node                           │",
                "│                                                          │",
                "│ Ways to reach friends                                    │",
                "│ This Wi-Fi or cable - On. Works without the internet.    │",
                "│ A laptop's hotspot - Works. One of you makes it, the     │",
                "│                                                          │",
                "│ [L] Service log  [X] Stop  Up/Down Scroll  [Esc] Back    │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
        // Sealed, plain or migrating: no row.
        for state in ["sealed", "plain", "migrating", "a_newer_word"] {
            let mut app = at_rest_app((80, 24), state);
            open_net(&mut app);
            let text = testkit::screen_text(&testkit::render(&app, 80, 24));
            assert!(
                !text.contains("encrypt") && !text.contains("friends list"),
                "{state}: {text}"
            );
            assert_eq!(
                app.chip(),
                Some(widgets::Chip::Listening { port: Some(7420) })
            );
        }
    }

    /// Raven updates (P6.47): NET reads what waits when it opens (only while
    /// the gate is live), then has an Updates row and U.
    #[test]
    fn net_shows_what_waits_to_be_installed_and_offers_u() {
        use raven_core::security_gate::{self, SecGate};
        if !cfg!(debug_assertions) {
            return;
        }
        security_gate::set_lab_for_this_thread(SecGate::Advisory, Some(true));
        security_gate::set_lab_for_this_thread(SecGate::ReleaseBundle, Some(true));
        let mut app = testkit::app((80, 24));
        let cmds = open_net(&mut app);
        assert!(cmds
            .iter()
            .any(|cmd| matches!(cmd, Cmd::Node(NodeJob::LoadUpdates { full: false }))));
        let view = bridge::UpdateView {
            live: true,
            net_row: Some("1.5.0 ready to install".to_owned()),
            ..bridge::UpdateView::default()
        };
        testkit::send(&mut app, Msg::Job(JobResult::Updates(view)));
        let rows: Vec<String> = panel_rows(&app, 72, app.now())
            .iter()
            .map(ToString::to_string)
            .collect();
        assert!(
            rows.iter()
                .any(|row| row == "Raven updates: 1.5.0 ready to install (press U)"),
            "{rows:?}"
        );
        let Screen::Network(net) = app.screen() else {
            panic!("NET")
        };
        assert!(panel_keys(&app, net).contains(&("[U]", " Updates")));
        testkit::press(&mut app, KeyCode::Char('u'));
        assert!(matches!(app.overlays(), [Overlay::Updates(_)]));
        security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
        security_gate::set_lab_for_this_thread(SecGate::ReleaseBundle, None);
    }
}
