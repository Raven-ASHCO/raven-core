//! What is drawn over a screen: HELP, QUIT, RX, KC, PASSFILE, FW, MSG, LOCK,
//! the confirm box, the privacy pack's KEEP, DEL, FORGET and NOTICE (PP.21)
//! and ERASE (PP.22, over the whole screen), and the toast.
//!
//! QUIT says what keeps running once Raven is closed (OD-2), and offers
//! what 'When I quit' and the stop rules (OD-16) allow, and LOCK; or that
//! Raven finishes something first. While messages the background program
//! keeps trying haven't gone yet, it says so before that (UXF.8). LOCK
//! (UXF.7) says what stopping Raven protects: a passphrase-vault profile is
//! locked, a keychain one only stopped.

use std::time::Instant;

use ratatui::layout::{Position, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Padding, Paragraph};
use ratatui::Frame;

use super::anim::Moving;
use super::app::{
    self, App, Bubble, ConfirmAction, EraseStage, EraseState, KeychainView, LockStep, MessageView,
    Overlay, QuitChoice, QuitView, RunningQuit, RxState, Screen, TickView, Toast, WaitingQuit,
};
#[cfg(test)]
use super::app::{
    Cmd, ExitPlan, Focus, FriendChange, JobKind, JobName, JobResult, Key, Msg, NodeJob, PasteVia,
    Session, StoreJob, QUIT_SETTLE,
};
#[cfg(test)]
use super::bridge::EraseEnd;
use super::bridge::{ChatKeepView, ErasePlanView, Notice};
#[cfg(test)]
use super::controller::{PrivacyRead, RowView, SendResult};
use super::delivery::{self, Outcome, Tick, Waiting, WriteEvidence};
use super::node::StopOutcome;
#[cfg(test)]
use super::node::{Managed, Probe, Stopped, Vault};
#[cfg(test)]
use super::render as render_frame;
#[cfg(test)]
use super::state_file::{OnQuit, Receive, TuiState};
#[cfg(test)]
use super::testkit;
#[cfg(test)]
use super::theme::{Glyphs, Theme};
#[cfg(test)]
use super::workers::FileStamp;
#[cfg(test)]
use super::workers::{PollUpdate, Watched};
use super::{anim, bridge, cells, display, errors, network, verify, widgets, wrap, Look};

/// HELP's largest size, in cells; smaller in a smaller terminal.
const HELP_WIDTH: u16 = 72;
const HELP_HEIGHT: u16 = 20;
/// QUIT's width, in cells; narrower in a narrower terminal.
const QUIT_WIDTH: u16 = 60;
/// QUIT while the identity is being made, or a change to the friends is
/// saved: there is no quitting now.
const QUIT_SETTING_UP: &str = "Raven is finishing setting up your identity. Please wait";
const QUIT_SAVING: &str = "Raven is finishing saving your friends. Please wait";
/// QUIT's question, and what keeps running after it.
const QUIT_TITLE: &str = "Quit Raven?";
const QUIT_KEEPS: &str = "Raven's background program keeps running while this computer is on \
                          and you stay logged in, so friends can still reach you and waiting \
                          messages keep trying.";
const QUIT_MANAGED: &str = "It is set to start when you log in.";
const QUIT_STOPS: &str = "Raven's background program stops when you quit, because this app \
                          started it. Friends can't reach you until you open Raven again.";
const QUIT_NOT_RUNNING: &str = "Quit Raven? The background program isn't running, so friends \
                                can't reach you until you open Raven again.";
/// QUIT after the quit was chosen: a send goes out first, or the stop runs.
const QUIT_SENDING: &str =
    "One message is still being sent. Raven will finish it first (up to a minute).";
const QUIT_STOPPING: &str = "Stopping Raven's background program";
const QUIT_ENTER: (&str, &str) = ("[Enter]", " Quit");
const QUIT_STOP: (&str, &str) = ("[S]", " Quit and stop the background program");
const QUIT_KEEP: (&str, &str) = ("[K]", " Quit and keep it running");
const QUIT_LOCK: (&str, &str) = ("[L]", " Lock: stop Raven and quit");
const QUIT_ANYWAY: (&str, &str) = ("[Q]", " Quit anyway (it may need sending again)");
const QUIT_STAY: (&str, &str) = ("[Esc]", " Stay");
/// QUIT's warning while messages wait (UXF.8): Enter stays, Q quits anyway.
const QUIT_WAITING_KEYS: [(&str, &str); 2] =
    [("[Enter]", " Stay and wait"), ("[Q]", " Quit anyway")];
/// Between QUIT's keys.
const QUIT_GAP: &str = "   ";

/// LOCK's question (UXF.7): a passphrase-vault profile is locked; a
/// keychain or DPAPI one only stopped, since the system keeps its keys open
/// while the user is logged in.
const LOCK_VAULT_TITLE: &str = "Lock Raven now?";
const LOCK_VAULT_BODY: [&str; 2] = [
    "Raven stops. Your chats can't be opened again without your passphrase.",
    "Friends can't reach you until you open Raven again.",
];
const LOCK_VAULT_KEYS: [(&str, &str); 2] = [("[Enter]", " Lock"), LOCK_CANCEL];
const LOCK_KEYCHAIN_TITLE: &str = "Stop Raven now?";
const LOCK_KEYCHAIN_BODY: [&str; 2] = [
    "Raven stops, and friends can't reach you until you open it again.",
    "Your Raven keys stay in this computer's keychain: anyone who can log in as you can still \
     open your chats. Lock your screen or log out too.",
];
const LOCK_KEYCHAIN_KEYS: [(&str, &str); 2] = [("[Enter]", " Stop"), LOCK_CANCEL];
const LOCK_CANCEL: (&str, &str) = ("[Esc]", " Cancel");
/// LOCK's question where the node serves Lock v2 (P6.40): it keeps
/// running, locked.
const LOCK_V2_BODY: &str = "Raven keeps running but forgets its keys: friends can't reach you, \
                            and your messages wait here.";
const LOCK_V2_PASSPHRASE: &str = "Your Raven passphrase opens it again.";
/// LOCK's last paragraph when Raven's own login item runs this profile
/// (PP.23, OD-PP-12 option (a)): the app unloads it for this login session
/// only, and never turns it off (OD-11).
const LOCK_LOGIN_ITEM: &str =
    "Raven starts again when you log in. To keep it stopped, run `raven lock` in a terminal.";
/// The same when a `raven lock` turned that item off (review D-lock-tui-7):
/// it starts nothing at the next login, and the app never turns it on.
const LOCK_LOGIN_ITEM_OFF: &str = "Raven's login item stays off until you run `raven unlock`.";
/// Home's word once Raven runs again after opening the app cleared a lock
/// that turned Raven's login item off (PP.23).
const LOGIN_ITEM_OFF_NOTICE: &str =
    "Raven is running again. Raven's login item stays off until you run `raven unlock`.";
/// LOCK when the stop left the background program running: why, by how
/// the stop went, then the stop advice NET shows (if the stop rules give
/// one), then what still protects the chats.
const LOCK_MANAGED: &str = "Raven's login service keeps it running, so Lock can't stop it.";
const LOCK_NOT_HERE: &str = "Raven can't stop its background program from here.";
const LOCK_SCREEN: &str = "Lock your screen or log out.";
/// Cells of HELP's key column.
const KEY_COLUMN: usize = 8;

/// HELP's keys for the screen underneath: Home's, WZ-1's, AF-1's, VF's,
/// AF-3's, CI's, NET's, MEET's and SET's (the screens with a help key).
const HOME_KEYS: &[(&str, &str)] = &[
    ("?", "Help"),
    ("Q", "Quit"),
    ("Ctrl+C", "Quit"),
    ("L", "Lock: stop Raven and quit"),
    ("Ctrl+L", "Redraw the screen"),
];
/// Home's group keys, while groups are live (lab): a section of their own.
const GROUP_KEYS: &[(&str, &str)] = &[
    ("C", "New group (on the list)"),
    ("M", "Members of the open group"),
    (
        "Enter, D",
        "Who has it: a message of yours, member by member",
    ),
    ("Space", "Pick a friend for the group"),
    ("A", "Add members (the admin, in Members)"),
    ("X", "Remove a member (the admin, in Members)"),
    ("L", "Leave the group (in Members)"),
];
const WELCOME_KEYS: &[(&str, &str)] = &[
    ("Enter", "Get started"),
    ("C", "Classic menu"),
    ("Q, Esc", "Quit"),
    ("Ctrl+L", "Redraw the screen"),
];

/// AF-1's keys, for HELP from its share box.
const ADD_FRIEND_KEYS: &[(&str, &str)] = &[
    ("Tab", "Switch box"),
    ("L", "Address on/off"),
    ("C", "Copy view"),
    ("Ctrl+C", "Copy view"),
    ("S", "Show my invite anyway"),
    ("Enter", "Continue"),
    ("Ctrl+U", "Empty the paste box"),
    ("Esc", "Back"),
];

/// VF's keys: typing goes into its field, so none is a letter.
const VERIFY_KEYS: &[(&str, &str)] = &[
    ("Enter", "Check the words, then save"),
    ("Enter", "Check again (a friend verified already)"),
    ("Tab", "Pick the word suggested"),
    ("Tab", "Later: save as not verified (no word typed)"),
    ("Ctrl+O", "The old code instead, or back to words"),
    ("Left", "Spell the code group before"),
    ("Right", "Spell the next code group"),
    ("Esc", "Cancel: nothing is saved"),
];
/// AF-3's keys.
const ADDED_KEYS: &[(&str, &str)] = &[
    ("Enter", "Open the chat"),
    ("1", "Show my invite"),
    ("A", "Add another friend"),
    ("Esc", "Home"),
];
/// NET's keys (S, X and R only where it offers them).
const NETWORK_KEYS: &[(&str, &str)] = &[
    ("L", "Service log"),
    ("W", "Security notices"),
    ("S", "Start the background program"),
    ("X", "Stop it"),
    ("R", "Check again"),
    ("G", "Meet without the internet"),
    ("Up, Down", "Scroll"),
    ("Esc", "Back"),
];
/// MEET's keys, each on the steps that have it.
const MEET_KEYS: &[(&str, &str)] = &[
    ("1, 2, 3", "Who makes the hotspot"),
    ("A", "Add a friend"),
    ("C", "Show the command alone (Linux)"),
    ("Enter", "Next, save, or open the chat"),
    ("Up, Down", "Another friend"),
    ("Esc", "Back"),
];
/// SET's keys.
const SETTINGS_KEYS: &[(&str, &str)] = &[
    ("Up, Down", "Choose"),
    ("Enter", "Change, or open"),
    ("Right", "Next value"),
    ("Left", "Value before"),
    ("Esc", "Back"),
];
/// CI's keys.
const FRIEND_PAGE_KEYS: &[(&str, &str)] = &[
    ("R", "Rename"),
    ("E", "Edit their address"),
    ("V", "Verify"),
    ("X", "Remove"),
    ("U", "Unblock"),
    ("P", "Pause or resume sending to them"),
    ("W", "Security notices"),
    ("D", "Details of a failure"),
    ("Esc", "Back"),
];
/// CI's keys once the privacy read answered (PP.21).
const FRIEND_PAGE_PRIVACY_KEYS: &[(&str, &str)] = &[
    ("R", "Rename"),
    ("E", "Edit their address"),
    ("V", "Verify"),
    ("X", "Remove"),
    ("U", "Unblock"),
    ("C", "Delete your chat on this computer"),
    ("F", "Forget their address"),
    ("P", "Pause or resume sending to them"),
    ("W", "Security notices"),
    ("D", "Details of a failure"),
    ("Esc", "Back"),
];

const HELP_FOOTER: &str =
    "Want the old menu? Settings > Classic menu, or start Raven with RAVEN_UI=classic.";
/// Under HELP's keys: a Persian keyboard layout's letter and number keys are
/// the same shortcuts (UXF.4, `keys_fa.rs`).
const HELP_PERSIAN_KEYBOARD: &str = "Shortcuts also work with a Persian keyboard.";

/// RX's and KC's width, in cells; narrower in a narrower terminal.
const NOTE_WIDTH: u16 = 64;
/// PASSFILE's width: its commands are long.
const PASSFILE_WIDTH: u16 = 80;

/// RX: WZ-3's copy (the same question for a profile made before it).
const RX_TITLE: &str = "Receive messages on this computer?";
/// RX's first paragraph, around the port the background program listens on
/// (this profile's own, E1).
const RX_LISTENS: (&str, &str) = (
    "To get messages, Raven keeps a small background program running that listens on your \
     network (port ",
    "). Only friends you add can send you anything.",
);
const RX_BODY: [&str; 2] = [
    "Your computer may ask whether to allow this. On Windows, choose Private networks and \
     Allow.",
    "You can change this later in Settings.",
];
const RX_YES: (&str, &str) = ("[Y]", " Yes, receive messages (recommended)");
const RX_NO: (&str, &str) = ("[N]", " Not now, I only want to send");

/// KC's copy.
const KC_TITLE: &str = "Your Mac is asking for permission";
const KC_HOW: &str = "Look for a password window (it may be hidden behind this one). Enter \
                      your Mac login password and choose Always Allow.";
const KC_SSH: &str = "Over SSH no window can appear: open Raven on the Mac itself.";
const KC_KEYS: (&str, &str) = ("[Esc]", " Hide (Raven keeps waiting)");

/// PASSFILE's copy: each step is its words, then the command to type.
const PASSFILE_TITLE: &str = "Raven's background program needs one more step on this computer";
const PASSFILE_BODY: &str = "Raven keeps your keys in a passphrase-protected vault here. The \
                             background program runs without a window, so it can't ask for \
                             your passphrase. Until this is set up, Raven can't send or \
                             receive messages on this computer.";
const PASSFILE_STEPS: [(&str, &str); 2] = [
    (
        "Save your passphrase in a file only you can read:",
        "( umask 077; printf '%s\\n' 'your passphrase' > ~/.config/raven/keystore-passphrase )",
    ),
    (
        "Open Raven with:",
        "RAVEN_KEYSTORE_PASSPHRASE_FILE=~/.config/raven/keystore-passphrase raven",
    ),
];
/// PASSFILE, when the file its first step makes is there already (UXF.7).
const PASSFILE_SAVED: &str = "Your passphrase is saved in a file on this computer \
                              (~/.config/raven/keystore-passphrase). Anyone who can read your \
                              files can unlock Raven with it. If that worries you, delete the \
                              file when you are not using Raven (for example before you \
                              travel), and create it again when you want to send and receive.";
const PASSFILE_FOOTER: &str = "More in docs/INSTALL_Linux.md (\"Non-interactive use\").";
const CLOSE_KEYS: (&str, &str) = ("[Esc]", " Close");

/// FW's copy, on Windows (with the rule to add) and on macOS.
const FW_WINDOWS_TITLE: &str = "Windows may ask about raven-node";
const FW_WINDOWS_BODY: &str = "If a \"Windows Security Alert\" window appears, choose Private \
                               networks and Allow access. That needs an administrator. If you \
                               close it instead, Windows blocks friends from reaching this \
                               computer (sending still works).";
const FW_WINDOWS_RULE: &str = "The rule to add later, in an administrator PowerShell:";
const FW_MAC_TITLE: &str = "Your computer may ask about the firewall";
const FW_MAC_BODY: &str =
    "If macOS asks whether raven-node may accept incoming network connections, choose Allow.";
const FW_KEYS: (&str, &str) = ("[Enter]", " OK");

/// UNLOCK's copy (review E-harness-docs-ci-3): the app opened on a profile
/// `raven lock` locked, and asks before it starts Raven again.
const UNLOCK_TITLE: &str = "Raven is locked";
const UNLOCK_BODY: [&str; 2] = [
    "`raven lock` stopped Raven: friends can't reach you, and sending doesn't start it.",
    "Start Raven again now?",
];
const UNLOCK_KEYS: [(&str, &str); 2] = [("[Enter]", " Start Raven"), ("[Esc]", " Keep it stopped")];

/// NOTE's copy (UXF.9), with FW's key.
const NOTE_TITLE: &str = "What people on this network can see";
const NOTE_BODY: &str = "People on this network can see that this computer talks to another \
                         one, when, and how much. They can't read your messages.";

/// KEEP's copy (the privacy pack's UX copy, PP.21): SET's 'Keep chats for'
/// chooser, its values, and the help line under them.
const KEEP_TITLE: &str = "Keep chats for";
const KEEP_HELP: &str = "Older chats are deleted from this computer. Your friends' copies aren't.";
const KEEP_ALWAYS_HELP: &str = "Raven keeps your chats on this computer until you delete them.";
const KEEP_KEYS: [(&str, &str); 2] = [("[Enter]", " Save"), ("[Esc]", " Cancel")];
/// DEL's and FORGET's keys.
const DELETE_KEYS: [(&str, &str); 2] = [("[Enter]", " Delete"), ("[Esc]", " Cancel")];
const FORGET_KEYS: [(&str, &str); 2] = [("[Enter]", " Forget"), ("[Esc]", " Cancel")];
/// NOTICE's key.
const NOTICE_KEYS: (&str, &str) = ("[Enter]", " OK");

/// ERASE (PP.22): the question's field and its keys, and what it lists
/// before it (the UX copy's title and paragraph come from `raven erase`).
const ERASE_LIST: &str = "On this computer now:";
const ERASE_PROMPT: &str = "Type erase to confirm:";
const ERASE_KEYS: [(&str, &str); 2] = [("[Enter]", " Erase"), ("[Esc]", " Cancel")];
const ERASE_CANCEL: (&str, &str) = ("[Esc]", " Cancel");
/// ERASE's progress line, after a spinner.
const ERASE_READING: &str = "Reading what Raven keeps on this computer";
const ERASE_WAITING: &str = "Raven is finishing what it was doing first";
const ERASE_RUNNING: &str = "Erasing Raven from this computer";

/// MSG's width; narrower in a narrower terminal.
const MSG_WIDTH: u16 = 64;
/// Cells of MSG's quoted preview of the text.
const MSG_PREVIEW_CELLS: u16 = 40;
/// The name a screen gives a friend who is not saved any more.
const NO_NAME: &str = "your friend";

/// HELP: the keys for `screen` (the one underneath), and what every mark and
/// tick means, scrolled down by `scroll` rows (at most [`help_max_scroll`]).
pub(super) fn render_help(
    f: &mut Frame,
    area: Rect,
    look: &Look,
    screen: &Screen,
    (privacy, groups): (bool, bool),
    scroll: u16,
) {
    let rect = help_rect(area);
    // On the bottom border, between a corner and the line on each side.
    let mut keys = widgets::key_bar(
        look,
        &[("Esc", "Close"), (look.glyphs.up_down, "Scroll")],
        rect.width.saturating_sub(4),
    );
    keys.spans.insert(0, Span::raw(" "));
    keys.spans.push(Span::raw(" "));
    let block = overlay_block(look)
        .title(Span::styled(" Help ", look.theme.title))
        .title_bottom(keys);
    let inner = block.inner(rect);
    let lines = help_lines(
        look,
        help_keys(screen, privacy),
        group_keys(screen, groups),
        inner.width,
    );
    let scroll = scroll.min(max_scroll(lines.len(), inner.height));
    widgets::clear(f, rect, look);
    f.render_widget(Paragraph::new(lines).block(block).scroll((scroll, 0)), rect);
}

/// The furthest HELP scrolls over `screen` in a terminal of `size`
/// (columns, rows).
pub(crate) fn help_max_scroll(
    look: &Look,
    screen: &Screen,
    (privacy, groups): (bool, bool),
    size: (u16, u16),
) -> u16 {
    let block = overlay_block(look);
    let inner = block.inner(help_rect(Rect::new(0, 0, size.0, size.1)));
    max_scroll(
        help_lines(
            look,
            help_keys(screen, privacy),
            group_keys(screen, groups),
            inner.width,
        )
        .len(),
        inner.height,
    )
}

/// The group keys HELP lists over `screen`: Home's, while groups are live.
fn group_keys(screen: &Screen, groups: bool) -> &'static [(&'static str, &'static str)] {
    if groups && *screen == Screen::Home {
        GROUP_KEYS
    } else {
        &[]
    }
}

/// The keys HELP lists over `screen`.
fn help_keys(screen: &Screen, privacy: bool) -> &'static [(&'static str, &'static str)] {
    match screen {
        Screen::Home => HOME_KEYS,
        Screen::Wizard(_) | Screen::IdentityError(_) => WELCOME_KEYS,
        Screen::AddFriend(_) | Screen::NameClash(_) => ADD_FRIEND_KEYS,
        Screen::Verify(_) => VERIFY_KEYS,
        Screen::Added(_) => ADDED_KEYS,
        Screen::FriendPage(_) if privacy => FRIEND_PAGE_PRIVACY_KEYS,
        Screen::FriendPage(_) => FRIEND_PAGE_KEYS,
        Screen::Network(_) => NETWORK_KEYS,
        Screen::Meet(_) => MEET_KEYS,
        Screen::Settings(_) => SETTINGS_KEYS,
    }
}

/// QUIT, as [`App::quit_view`] has it: the question with what keeps
/// running and the keys that choose, the warning about messages that
/// haven't gone, or what Raven finishes first. A spinner turns while a
/// chosen quit waits (still under reduced motion).
pub(super) fn render_quit(f: &mut Frame, area: Rect, app: &App, now: Instant) {
    let look = app.look();
    let width = inner_width(QUIT_WIDTH.min(area.width));
    let ellipsis = look.glyphs.ellipsis;
    let text = |copy: &str| -> Vec<Line<'static>> {
        wrap(copy, width, 0).into_iter().map(Line::raw).collect()
    };
    let (mut lines, keys): (Vec<Line<'static>>, Vec<(&'static str, &'static str)>) =
        match app.quit_view() {
            QuitView::SettingUp => (
                text(&format!("{QUIT_SETTING_UP}{ellipsis}")),
                vec![QUIT_STAY],
            ),
            QuitView::Saving => (text(&format!("{QUIT_SAVING}{ellipsis}")), vec![QUIT_STAY]),
            QuitView::Sending { since } => (
                spinning(look, since, now, QUIT_SENDING, width),
                vec![QUIT_ANYWAY, QUIT_STAY],
            ),
            QuitView::Stopping { since } => (
                spinning(
                    look,
                    since,
                    now,
                    &format!("{QUIT_STOPPING}{ellipsis}"),
                    width,
                ),
                Vec::new(),
            ),
            QuitView::Plain => (vec![Line::raw(QUIT_TITLE)], vec![QUIT_ENTER, QUIT_STAY]),
            QuitView::NotRunning => (
                text(QUIT_NOT_RUNNING),
                vec![QUIT_ENTER, QUIT_LOCK, QUIT_STAY],
            ),
            QuitView::Running(running) => {
                let (copy, keys) = running_copy(running);
                let mut lines = vec![Line::raw(QUIT_TITLE), Line::default()];
                lines.extend(text(&copy));
                (lines, keys)
            }
            QuitView::Waiting(waiting) => {
                let mut lines = Vec::new();
                for sentence in waiting_copy(app, &waiting) {
                    lines.extend(text(&sentence));
                }
                (lines, QUIT_WAITING_KEYS.to_vec())
            }
        };
    if !keys.is_empty() {
        lines.push(Line::default());
        lines.extend(verify::key_rows(look, &keys, QUIT_GAP, width));
    }
    let rect = centered(area, QUIT_WIDTH, height_of(&lines));
    widgets::clear(f, rect, look);
    f.render_widget(
        Paragraph::new(fit(lines, rect.height)).block(overlay_block(look)),
        rect,
    );
}

/// QUIT's words and keys while the background program runs: it keeps
/// running (Enter), with S to stop it; it stops because this app started it
/// (Enter), with K to keep it; or under 'Ask me' K or S. A login service is
/// said, and never offered a stop. L (LOCK) is offered each time: LOCK says
/// itself what it can't stop.
fn running_copy(running: RunningQuit) -> (String, Vec<(&'static str, &'static str)>) {
    let stops = running.enter == Some(QuitChoice::Stop);
    let mut copy = (if stops { QUIT_STOPS } else { QUIT_KEEPS }).to_owned();
    if running.managed {
        copy.push(' ');
        copy.push_str(QUIT_MANAGED);
    }
    let mut keys = Vec::new();
    match running.enter {
        Some(QuitChoice::Keep) => {
            keys.push(QUIT_ENTER);
            if running.can_stop {
                keys.push(QUIT_STOP);
            }
        }
        Some(QuitChoice::Stop) => keys.extend([QUIT_ENTER, QUIT_KEEP]),
        None => keys.extend([QUIT_KEEP, QUIT_STOP]),
    }
    keys.extend([QUIT_LOCK, QUIT_STAY]);
    (copy, keys)
}

/// QUIT's warning while messages wait (UXF.8), two sentences: how many
/// haven't gone and to whom (the friend whose message runs out first, and
/// how many more to others), then until when they wait if you leave. The
/// time is UXF.1's deadline words; without one it is left out.
fn waiting_copy(app: &App, waiting: &WaitingQuit) -> [String; 2] {
    let name = app.shown_name(&waiting.peer);
    let (count, more) = (waiting.count, waiting.more);
    let messages = if count == 1 { "message" } else { "messages" };
    let gone = match more {
        0 if count == 1 => format!("1 message to {name} hasn't gone yet."),
        0 => format!("{count} messages to {name} haven't gone yet."),
        more => format!("{count} {messages} to {name} and {more} more haven't gone yet."),
    };
    let wait = if count + more == 1 {
        "it waits"
    } else {
        "they wait"
    };
    let until = waiting.until_ms.map_or_else(String::new, |ms| {
        format!(" (until {})", bridge::deadline_text(ms, app.now_ms()).short)
    });
    [
        gone,
        format!("If you leave this network now, {wait} until next time{until}."),
    ]
}

/// `text` after a spinner turning since `since`, wrapped under the text's
/// start.
fn spinning(
    look: &Look,
    since: Instant,
    now: Instant,
    text: &str,
    width: u16,
) -> Vec<Line<'static>> {
    let spinner = widgets::spinner(look, since, now);
    let indent = u16::try_from(spinner.width() + 1).unwrap_or(0);
    wrap(text, width.saturating_sub(indent), 0)
        .into_iter()
        .enumerate()
        .map(|(i, row)| {
            let lead = if i == 0 {
                vec![spinner.clone(), Span::raw(" ")]
            } else {
                vec![Span::raw(" ".repeat(usize::from(indent)))]
            };
            let mut spans = lead;
            spans.push(Span::raw(row));
            Line::from(spans)
        })
        .collect()
}

/// What moves in QUIT, LOCK and ERASE: the spinner while a chosen quit,
/// Enter on LOCK, or the erase waits.
pub(crate) fn moving(app: &App) -> Option<Moving> {
    let locking = app.overlays().iter().find_map(|overlay| match overlay {
        Overlay::Lock(LockStep::Locking { since, .. })
        | Overlay::Erase(EraseState::Erasing { since, .. }) => {
            Some(Moving::Spinner { since: *since })
        }
        _ => None,
    });
    if locking.is_some() || !app.overlays().contains(&Overlay::Quit) {
        return locking;
    }
    match app.quit_view() {
        QuitView::Sending { since } | QuitView::Stopping { since } => {
            Some(Moving::Spinner { since })
        }
        _ => None,
    }
}

/// LOCK at `step` (UXF.7): the question in the words of a passphrase-vault
/// profile or a keychain one, and when Raven's own login item runs this
/// profile, that it starts Raven again at the next login (PP.23); a spinner
/// while a send or a save goes first (Esc still cancels) and while the stop
/// runs; or why the stop left the background program running. QUIT's
/// width.
pub(super) fn render_lock(f: &mut Frame, area: Rect, app: &App, step: &LockStep, now: Instant) {
    let look = app.look();
    let width = inner_width(QUIT_WIDTH.min(area.width));
    let ellipsis = look.glyphs.ellipsis;
    let text = |copy: &str| -> Vec<Line<'static>> {
        wrap(copy, width, 0).into_iter().map(Line::raw).collect()
    };
    let (mut lines, keys): (Vec<Line<'static>>, Vec<(&'static str, &'static str)>) = match step {
        // Lock v2 (P6.40): the node keeps running and forgets its keys.
        LockStep::Asking if app.lock_v2_offered() => {
            let has = app
                .lock_settings()
                .is_some_and(|read| read.offer.has_passphrase());
            let mut lines = vec![Line::raw(LOCK_VAULT_TITLE)];
            let last = if has {
                LOCK_V2_PASSPHRASE
            } else {
                bridge::keys_open_to_login_text()
            };
            for paragraph in [LOCK_V2_BODY, last] {
                lines.push(Line::default());
                lines.extend(text(paragraph));
            }
            (lines, LOCK_VAULT_KEYS.to_vec())
        }
        LockStep::Asking => {
            let (title, body, keys) = if app.vault_profile() {
                (LOCK_VAULT_TITLE, LOCK_VAULT_BODY, LOCK_VAULT_KEYS)
            } else {
                (LOCK_KEYCHAIN_TITLE, LOCK_KEYCHAIN_BODY, LOCK_KEYCHAIN_KEYS)
            };
            let mut lines = vec![Line::raw(title)];
            // A vault profile's passphrase saved in a file unlocks it for
            // anyone who can read that file: `raven lock`'s paragraph, the
            // path cut in its middle to one row (review D-lock-tui-2).
            let saved = app.lock_passphrase_file().map(|file| {
                let shown = display::one_line_middle(
                    &file.display().to_string(),
                    width.saturating_sub(3),
                    ellipsis,
                );
                bridge::passphrase_file_paragraph(&shown)
            });
            // Raven's own login item: it starts Raven again at the next
            // login, unless a `raven lock` turned it off (D-lock-tui-7).
            let login_item = if app.own_login_item_off() {
                Some(LOCK_LOGIN_ITEM_OFF)
            } else {
                app.own_login_item().then_some(LOCK_LOGIN_ITEM)
            };
            let paragraphs = body
                .into_iter()
                .map(str::to_owned)
                .chain(saved)
                .chain(login_item.map(str::to_owned));
            for paragraph in paragraphs {
                lines.push(Line::default());
                lines.extend(text(&paragraph));
            }
            (lines, keys.to_vec())
        }
        LockStep::Locking {
            since,
            stopping: false,
        } => {
            let copy = if app.sending() {
                QUIT_SENDING.to_owned()
            } else {
                format!("{QUIT_SAVING}{ellipsis}")
            };
            (spinning(look, *since, now, &copy, width), vec![LOCK_CANCEL])
        }
        LockStep::Locking {
            since,
            stopping: true,
        } => (
            spinning(
                look,
                *since,
                now,
                &format!("{QUIT_STOPPING}{ellipsis}"),
                width,
            ),
            Vec::new(),
        ),
        LockStep::NotStopped(outcome) => (not_stopped_lines(app, outcome, width), vec![CLOSE_KEYS]),
    };
    if !keys.is_empty() {
        lines.push(Line::default());
        lines.extend(verify::key_rows(look, &keys, QUIT_GAP, width));
    }
    let rect = centered(area, QUIT_WIDTH, height_of(&lines));
    draw_card(f, rect, look, fit(lines, rect.height));
}

/// Why LOCK's stop left the background program running, in rows of `width`
/// cells: a login service runs it, the stop rules leave it to the user, it
/// still runs, or the stop failed. Then how to stop it by hand where NET
/// would say it (a command, broken and never cut), and what still protects
/// the chats.
fn not_stopped_lines(app: &App, outcome: &StopOutcome, width: u16) -> Vec<Line<'static>> {
    let why = match outcome {
        StopOutcome::Managed => LOCK_MANAGED,
        StopOutcome::Advice(_) => LOCK_NOT_HERE,
        StopOutcome::Failed(_) => app::NODE_STOP_FAILED_TOAST,
        StopOutcome::StillRunning | StopOutcome::Stopped | StopOutcome::NotRunning => {
            app::STILL_RUNNING_TOAST
        }
    };
    let advice = match outcome {
        StopOutcome::Advice(advice) => Some(advice.clone()),
        _ => app.stop_advice(),
    };
    let rows = |copy: &str| -> Vec<Line<'static>> {
        wrap(copy, width, 0).into_iter().map(Line::raw).collect()
    };
    let Some(advice) = advice else {
        return rows(&format!("{why} {LOCK_SCREEN}"));
    };
    // A command with the profile's folder in it, as NET shows it.
    let advice = display::one_line(&advice, u16::MAX, "");
    let mut lines = rows(why);
    lines.extend(
        wrap_command(&format!("{}{advice}", network::STOP_ADVICE), width)
            .into_iter()
            .map(Line::raw),
    );
    lines.extend(rows(LOCK_SCREEN));
    lines
}

/// RX: may Raven receive on this computer? The highlighted answer has the
/// '>' marker; Enter gives it.
pub(super) fn render_receive(f: &mut Frame, area: Rect, look: &Look, rx: RxState, port: u16) {
    let rect_width = NOTE_WIDTH.min(area.width);
    let lines = receive_lines(look, inner_width(rect_width), rx.yes, port);
    let rect = centered(area, rect_width, height_of(&lines));
    draw_card(f, rect, look, fit(lines, rect.height));
}

/// The receive question's rows at `width` cells, for RX and WZ-3: the
/// question, why (the background program listening on `port`), and the two
/// answers, `yes` highlighted or No.
pub(super) fn receive_lines(look: &Look, width: u16, yes: bool, port: u16) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(RX_TITLE, look.theme.title), Line::default()];
    let listens = format!("{}{port}{}", RX_LISTENS.0, RX_LISTENS.1);
    for paragraph in std::iter::once(listens.as_str()).chain(RX_BODY) {
        lines.extend(wrap(paragraph, width, 0).into_iter().map(Line::raw));
        lines.push(Line::default());
    }
    for ((key, words), chosen) in [(RX_YES, yes), (RX_NO, !yes)] {
        let (marker, style) = if chosen {
            (look.glyphs.selected, look.theme.selected)
        } else {
            (" ", Default::default())
        };
        let key = widgets::key(look, key);
        lines.push(Line::from(vec![
            Span::raw(format!("{marker} ")),
            Span::styled(key.content, key.style.patch(style)),
            Span::styled(words, style),
        ]));
    }
    lines
}

/// KC: a Keychain dialog holds Raven up, at the top of the screen. The
/// icon pulses once a second (still under reduced motion).
pub(super) fn render_keychain(
    f: &mut Frame,
    area: Rect,
    look: &Look,
    kc: &KeychainView,
    over_ssh: bool,
    now: Instant,
) {
    let rect_width = NOTE_WIDTH.min(area.width);
    let width = inner_width(rect_width);
    let icon = if anim::pulse_on(kc.since, now, look.motion) {
        look.theme.warn
    } else {
        look.theme.secondary
    };
    let mut lines = vec![
        Line::from(vec![
            Span::styled(look.glyphs.dot_alert, icon),
            Span::raw(" "),
            Span::styled(KC_TITLE, look.theme.accent),
        ]),
        Line::default(),
    ];
    let who = if kc.wait.service {
        "Raven's background program (raven-node) needs"
    } else {
        "Raven needs"
    };
    let body = format!(
        "{who} to read {} from your Mac's Keychain. {KC_HOW}",
        kc.wait.item
    );
    lines.extend(wrap(&body, width, 0).into_iter().map(Line::raw));
    if over_ssh {
        lines.push(Line::default());
        lines.extend(wrap(KC_SSH, width, 0).into_iter().map(Line::raw));
    }
    lines.push(Line::default());
    lines.push(keys_line(look, &[KC_KEYS]));
    // At the top, under the header row, so the screen stays readable.
    let height = height_of(&lines).min(area.height);
    let rect = Rect {
        y: area.y + u16::from(area.height > height),
        height,
        ..centered(area, rect_width, height)
    };
    draw_card(f, rect, look, fit(lines, rect.height));
}

/// PASSFILE: why raven-node can't start on a vault profile, and the two
/// steps that fix it (OD-19: the app never writes the file itself). When
/// the first step's file is there already (`saved`), what that file means
/// for a laptop someone takes (UXF.7), under the steps: at the smallest
/// size it gives way first.
pub(super) fn render_passfile(f: &mut Frame, area: Rect, look: &Look, saved: bool) {
    let rect_width = PASSFILE_WIDTH.min(area.width);
    let width = inner_width(rect_width);
    let mut lines: Vec<Line<'static>> = wrap(PASSFILE_TITLE, width, 0)
        .into_iter()
        .map(|row| Line::styled(row, look.theme.accent))
        .collect();
    lines.push(Line::default());
    lines.extend(wrap(PASSFILE_BODY, width, 0).into_iter().map(Line::raw));
    lines.push(Line::default());
    for (n, (words, command)) in (1..).zip(PASSFILE_STEPS) {
        lines.extend(
            wrap(&format!("{n}. {words}"), width, 3)
                .into_iter()
                .map(Line::raw),
        );
        lines.extend(
            wrap_command(command, width.saturating_sub(3))
                .into_iter()
                .map(|row| {
                    Line::from(vec![Span::raw("   "), Span::styled(row, look.theme.accent)])
                }),
        );
    }
    if saved {
        lines.push(Line::default());
        lines.extend(wrap(PASSFILE_SAVED, width, 0).into_iter().map(Line::raw));
    }
    lines.push(Line::default());
    lines.extend(
        wrap(PASSFILE_FOOTER, width, 0)
            .into_iter()
            .map(|row| Line::styled(row, look.theme.secondary)),
    );
    lines.push(Line::default());
    lines.push(keys_line(look, &[CLOSE_KEYS]));
    let rect = centered(area, rect_width, height_of(&lines));
    draw_card(f, rect, look, fit(lines, rect.height));
}

/// FW: the system may ask whether raven-node may accept connections. On
/// Windows (`rule`: cli.rs's firewall rule for the port) what to choose and
/// the rule to add later; on macOS, what to choose.
pub(super) fn render_firewall(f: &mut Frame, area: Rect, look: &Look, rule: Option<&str>) {
    let rect_width = if rule.is_some() {
        PASSFILE_WIDTH
    } else {
        NOTE_WIDTH
    }
    .min(area.width);
    let width = inner_width(rect_width);
    let (title, body) = match rule {
        Some(_) => (FW_WINDOWS_TITLE, FW_WINDOWS_BODY),
        None => (FW_MAC_TITLE, FW_MAC_BODY),
    };
    let mut lines: Vec<Line<'static>> = wrap(title, width, 0)
        .into_iter()
        .map(|row| Line::styled(row, look.theme.accent))
        .collect();
    lines.push(Line::default());
    lines.extend(wrap(body, width, 0).into_iter().map(Line::raw));
    if let Some(rule) = rule {
        lines.push(Line::default());
        lines.extend(wrap(FW_WINDOWS_RULE, width, 0).into_iter().map(Line::raw));
        lines.extend(
            wrap_command(rule, width.saturating_sub(3))
                .into_iter()
                .map(|row| {
                    Line::from(vec![Span::raw("   "), Span::styled(row, look.theme.accent)])
                }),
        );
    }
    lines.push(Line::default());
    lines.push(keys_line(look, &[FW_KEYS]));
    let rect = centered(area, rect_width, height_of(&lines));
    draw_card(f, rect, look, fit(lines, rect.height));
}

/// NOTE (UXF.9): what people on the network can see now that Raven receives
/// on it, in FW's plain style.
pub(super) fn render_network_note(f: &mut Frame, area: Rect, look: &Look) {
    let rect_width = NOTE_WIDTH.min(area.width);
    let width = inner_width(rect_width);
    let mut lines: Vec<Line<'static>> = wrap(NOTE_TITLE, width, 0)
        .into_iter()
        .map(|row| Line::styled(row, look.theme.accent))
        .collect();
    lines.push(Line::default());
    lines.extend(wrap(NOTE_BODY, width, 0).into_iter().map(Line::raw));
    lines.push(Line::default());
    lines.push(keys_line(look, &[FW_KEYS]));
    let rect = centered(area, rect_width, height_of(&lines));
    draw_card(f, rect, look, fit(lines, rect.height));
}

/// UNLOCK (review E-harness-docs-ci-3): the app opened on a profile `raven
/// lock` locked; Enter starts Raven again, Esc keeps it stopped.
pub(super) fn render_unlock(f: &mut Frame, area: Rect, look: &Look) {
    let rect_width = NOTE_WIDTH.min(area.width);
    let width = inner_width(rect_width);
    let mut lines: Vec<Line<'static>> = wrap(UNLOCK_TITLE, width, 0)
        .into_iter()
        .map(|row| Line::styled(row, look.theme.accent))
        .collect();
    for paragraph in UNLOCK_BODY {
        lines.push(Line::default());
        lines.extend(wrap(paragraph, width, 0).into_iter().map(Line::raw));
    }
    lines.push(Line::default());
    lines.push(keys_line(look, &UNLOCK_KEYS));
    let rect = centered(area, rect_width, height_of(&lines));
    draw_card(f, rect, look, fit(lines, rect.height));
}

/// MSG: one message of yours: to whom and when, its text quoted, where it
/// stands, why and what the user can do, the keys its state allows, and its
/// details on D. Nothing when the message has gone (sent again). MSG never
/// animates.
pub(super) fn render_message(f: &mut Frame, area: Rect, app: &App, view: &MessageView) {
    let Some(bubble) = app.find_bubble(&view.peer, &view.key) else {
        return;
    };
    let rect_width = MSG_WIDTH.min(area.width);
    let lines = message_lines(app, bubble, view, inner_width(rect_width));
    if lines.is_empty() {
        return;
    }
    let rect = centered(area, rect_width, height_of(&lines));
    draw_card(f, rect, app.look(), fit(lines, rect.height));
}

/// MSG's rows at `width` cells; none for a message with no state to show.
fn message_lines(app: &App, bubble: Bubble, view: &MessageView, width: u16) -> Vec<Line<'static>> {
    let Some(tick) = app.tick_view(bubble) else {
        return Vec::new();
    };
    let (g, t) = (&app.look().glyphs, &app.look().theme);
    let name = friend_name(app, &view.peer);
    let age = bridge::short_age(app.now_ms(), bubble.created_at_ms());
    let title = if age.is_empty() {
        format!("Message to {name}")
    } else {
        format!("Message to {name}{}{age}", g.inline_separator)
    };
    let mut lines: Vec<Line<'static>> = wrap(&title, width, 0)
        .into_iter()
        .map(|row| Line::styled(row, t.accent))
        .collect();
    let preview = display::one_line(bubble.body(), MSG_PREVIEW_CELLS, g.ellipsis);
    lines.push(Line::raw(format!("\"{preview}\"")));
    lines.push(Line::default());
    let copy = message_copy(app, &tick, &name);
    for (lead, text) in [
        ("Status: ", copy.status),
        ("Why: ", copy.why),
        ("What you can do: ", copy.what),
    ] {
        if !text.is_empty() {
            lines.extend(
                wrap(&format!("{lead}{text}"), width, 0)
                    .into_iter()
                    .map(Line::raw),
            );
        }
    }
    if view.details {
        lines.push(Line::default());
        lines.extend(
            message_details(app, &tick, width)
                .into_iter()
                .map(|row| Line::styled(row, t.secondary)),
        );
    }
    lines.push(Line::default());
    let a = tick.actions;
    let mut keys = Vec::new();
    if a.try_now {
        keys.push(("[R]", " Try now"));
    }
    if a.send_again {
        keys.push(("[R]", " Send again"));
    }
    if a.stop {
        keys.push(("[C]", " Stop trying"));
    }
    if a.send_again_anyway {
        keys.push(("[S]", " Send again anyway"));
    }
    keys.extend([("[D]", " Details"), ("[Esc]", " Close")]);
    let mut spans = Vec::new();
    for (i, (key, words)) in keys.into_iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(widgets::key(app.look(), key));
        spans.push(widgets::key_words(app.look(), words));
    }
    lines.push(Line::from(spans));
    lines
}

/// MSG's three lines, each without its lead ('Status: ', 'Why: ', 'What you
/// can do: '); an empty one is left out.
struct MessageCopy {
    status: String,
    why: String,
    what: String,
}

/// MSG's words for a message where `tick` says it stands, sent to `name`.
fn message_copy(app: &App, tick: &TickView, name: &str) -> MessageCopy {
    let ellipsis = app.look().glyphs.ellipsis;
    let held = tick
        .outbox
        .filter(|item| !item.last_error_code.is_empty())
        .map(|item| errors::explain_outbox_code(&item.last_error_code, name));
    let sent_why = tick
        .outcome()
        .and_then(Outcome::plain)
        .map(|plain| plain.headline.clone());
    let why = sent_why
        .clone()
        .or_else(|| held.as_ref().map(|plain| plain.headline.clone()))
        .unwrap_or_default();
    let or_stop = if tick.actions.stop {
        " Or press C to stop trying."
    } else {
        ""
    };
    let copy = |status: String, why: String, what: String| MessageCopy { status, why, what };
    match &tick.tick {
        Tick::Waiting(Waiting::Retried { expires_at_ms }) => {
            let what = if *expires_at_ms == 0 {
                format!(
                    "nothing. Raven keeps trying for a limited time (at most a day after you \
                     were last connected).{or_stop}"
                )
            } else {
                let deadline = bridge::deadline_text(*expires_at_ms, app.now_ms());
                let tell = if deadline.left_ms < delivery::SOON_MS {
                    let before = deadline.hh_mm.as_deref().unwrap_or(&deadline.short);
                    format!(" If you won't meet {name} before {before}, tell them another way.")
                } else {
                    String::new()
                };
                format!(
                    "nothing. It can wait until {}. After that Raven won't send it, and this \
                     message will say so.{tell}{or_stop}",
                    deadline.long
                )
            };
            copy(
                format!(
                    "Waiting. {name}'s Raven isn't reachable from here right now. Raven sends it \
                     by itself when you're both on the same network."
                ),
                why,
                what,
            )
        }
        Tick::Waiting(Waiting::NextSend) => copy(
            format!("Waiting. It goes out with your next message to {name}."),
            why,
            format!("send {name} another message when you like.{or_stop}"),
        ),
        Tick::Waiting(Waiting::NotRetried) => copy(
            "Waiting. Raven isn't trying it now: its background program isn't running.".to_owned(),
            why,
            format!(
                "nothing. Raven's background program starts again with your next message.\
                 {or_stop}"
            ),
        ),
        Tick::OnHold { .. } => {
            let next = held.map(|plain| plain.next).unwrap_or_default();
            copy(
                "On hold.".to_owned(),
                why,
                format!("{next}{or_stop}").trim().to_owned(),
            )
        }
        Tick::Sent => copy(
            format!(
                "Sent, not confirmed yet. It left this computer, but {name}'s Raven hasn't \
                 confirmed it."
            ),
            String::new(),
            "wait. Don't send it again.".to_owned(),
        ),
        Tick::Ended { expired: true } if tick.evidence == WriteEvidence::NeverWritten => copy(
            format!(
                "Not delivered. You and {name} weren't on the same network before its time ran \
                 out, so Raven stopped trying. It never left this computer."
            ),
            String::new(),
            "press R to send it again when you're together.".to_owned(),
        ),
        Tick::Ended { .. } if tick.evidence == WriteEvidence::NeverWritten => copy(
            "Not delivered. Raven stopped trying, and it never left this computer.".to_owned(),
            String::new(),
            "press R to send it again.".to_owned(),
        ),
        Tick::Ended { .. } => copy(
            format!(
                "Not confirmed. Raven stopped trying, but it had already sent this message \
                 once, so {name} may have it."
            ),
            String::new(),
            format!(
                "ask {name}. If they didn't get it, press S to send it again (they may see it \
                 twice)."
            ),
        ),
        Tick::NotSent => {
            let next = tick
                .outcome()
                .and_then(Outcome::plain)
                .map(|plain| plain.next.clone())
                .unwrap_or_default();
            let (status, again) = if tick.outcome().is_some_and(Outcome::meet_first) {
                (
                    format!(
                        "Not sent. Raven has no secure connection with {name} right now: each \
                         one lasts a day from when it is set up, and a new one needs you both \
                         on the same network at the same time. Nothing was queued."
                    ),
                    "press R when you're together.".to_owned(),
                )
            } else if tick.outcome().is_some_and(Outcome::first_message) {
                (
                    format!(
                        "Not sent. {} Nothing was queued.",
                        errors::first_message_rule(name)
                    ),
                    format!("press R when {name} is online."),
                )
            } else {
                (
                    "Not sent. Nothing was queued.".to_owned(),
                    "press R to try again.".to_owned(),
                )
            };
            let what = if next.is_empty() {
                again
            } else {
                format!("{next} Then {again}")
            };
            copy(status, why, what)
        }
        Tick::Delivered => copy(
            format!("Delivered. {name}'s Raven confirmed it."),
            String::new(),
            String::new(),
        ),
        Tick::Connecting => copy(
            format!("Connecting to {name}{ellipsis}"),
            String::new(),
            String::new(),
        ),
        Tick::Sending => copy(format!("Sending{ellipsis}"), String::new(), String::new()),
        Tick::WaitingToSend => copy(
            "Waiting to send, after the messages before it.".to_owned(),
            String::new(),
            String::new(),
        ),
    }
}

/// D in MSG: the message id's first 8 characters, the carrier, attempts,
/// last error and expiry raven-node lists, and what the send said, shaped.
fn message_details(app: &App, tick: &TickView, width: u16) -> Vec<String> {
    let mut rows = vec![match tick.mid {
        Some(mid) => format!("Message id: {}", display::one_line(mid, 8, "")),
        None => "Message id: not known yet".to_owned(),
    }];
    if let Some(item) = tick.outbox {
        if !item.carrier.is_empty() {
            rows.push(format!(
                "Carrier: {}",
                display::one_line(&item.carrier, 24, "")
            ));
        }
        rows.push(format!("Attempts: {}", item.attempts));
        if !item.last_error_code.is_empty() {
            rows.push(format!(
                "Last error: {}",
                display::one_line(&item.last_error_code, 40, "")
            ));
        }
        // Only while raven-node still holds it: a finished one has nothing
        // left to run out.
        if item.expires_at_ms > 0 && matches!(item.state.as_str(), "queued" | "sent" | "held") {
            rows.push(format!(
                "Expires: {}",
                bridge::deadline_text(item.expires_at_ms, app.now_ms()).long
            ));
        }
    }
    let technical = tick
        .outcome()
        .and_then(Outcome::plain)
        .map(|plain| plain.technical.as_str())
        .unwrap_or_default();
    let captured = tick.pending.map_or("", |send| send.captured.as_str());
    for text in [technical, captured] {
        for line in display::body_lines(text.trim(), false).lines {
            if !line.trim().is_empty() {
                rows.extend(wrap_command(&line, width));
            }
        }
    }
    rows
}

/// The friend's name as the screens draw it, or 'your friend'.
fn friend_name(app: &App, peer: &str) -> String {
    let name = app.shown_name(peer);
    if name.is_empty() {
        NO_NAME.to_owned()
    } else {
        name
    }
}

/// The question before a message of yours is stopped or sent again, with Y
/// and N.
pub(super) fn render_confirm(
    f: &mut Frame,
    area: Rect,
    app: &App,
    peer: &str,
    action: &ConfirmAction,
) {
    let look = app.look();
    let name = friend_name(app, peer);
    let (question, yes, no) = match action {
        ConfirmAction::SendAgain { .. } => (
            format!("Send this message to {name} again? They may see it twice."),
            " Send again",
            " Keep as is",
        ),
        ConfirmAction::StopTrying { .. } => (
            format!("Stop trying to send this message to {name}?"),
            " Stop",
            " Keep trying",
        ),
    };
    let rect_width = NOTE_WIDTH.min(area.width);
    let mut lines: Vec<Line<'static>> = wrap(&question, inner_width(rect_width), 0)
        .into_iter()
        .map(Line::raw)
        .collect();
    lines.push(Line::default());
    lines.push(keys_line(look, &[("[Y]", yes), ("[N]", no)]));
    let rect = centered(area, rect_width, height_of(&lines));
    draw_card(f, rect, look, fit(lines, rect.height));
}

/// What SET's 'Keep chats for' shows for `keep`, and KEEP lists.
pub(super) fn keep_label(keep: ChatKeepView) -> &'static str {
    match keep {
        ChatKeepView::Days7 => "7 days",
        ChatKeepView::Days30 => "30 days",
        ChatKeepView::Days90 => "90 days",
        ChatKeepView::Keep => "Keep",
    }
}

/// What 'Keep chats for' at `keep` means, under the row and in KEEP.
pub(super) fn keep_help(keep: ChatKeepView) -> &'static str {
    match keep {
        ChatKeepView::Keep => KEEP_ALWAYS_HELP,
        _ => KEEP_HELP,
    }
}

/// KEEP (PP.21): the four values, `choice` marked and highlighted, what it
/// means, and the keys.
pub(super) fn render_keep_chats(f: &mut Frame, area: Rect, look: &Look, choice: ChatKeepView) {
    let (g, t) = (&look.glyphs, &look.theme);
    let rect_width = NOTE_WIDTH.min(area.width);
    let width = inner_width(rect_width);
    let mut lines = vec![Line::styled(KEEP_TITLE, t.title), Line::default()];
    for keep in ChatKeepView::ALL {
        let picked = keep == choice;
        let marker = if picked { g.selected } else { " " };
        let line = Line::raw(format!("{marker} {}", keep_label(keep)));
        lines.push(if picked { line.style(t.selected) } else { line });
    }
    lines.push(Line::default());
    lines.extend(
        wrap(keep_help(choice), width, 0)
            .into_iter()
            .map(|row| Line::styled(row, t.secondary)),
    );
    lines.push(Line::default());
    let mut keys = vec![(g.up_down, " Choose")];
    keys.extend(KEEP_KEYS);
    lines.extend(verify::key_rows(look, &keys, "   ", width));
    let rect = centered(area, rect_width, height_of(&lines));
    draw_card(f, rect, look, fit(lines, rect.height));
}

/// DEL (PP.21): the question for the friend `peer`, the word as typed (the
/// terminal's cursor after it), and the keys.
pub(super) fn render_delete_chat(f: &mut Frame, area: Rect, app: &App, peer: &str, typed: &str) {
    let look = app.look();
    let name = friend_name(app, peer);
    let rect_width = NOTE_WIDTH.min(area.width);
    let width = inner_width(rect_width);
    let question = format!(
        "Delete your chat with {name} on this computer? {name} keeps their copy. Type delete to \
         confirm:"
    );
    let mut lines: Vec<Line<'static>> = wrap(&question, width, 0)
        .into_iter()
        .map(Line::raw)
        .collect();
    let field = Line::raw(format!("> {}", display::one_line(typed, u16::MAX, "")));
    lines.push(field.clone());
    lines.push(Line::default());
    lines.extend(verify::key_rows(look, &DELETE_KEYS, "   ", width));
    let rect = centered(area, rect_width, height_of(&lines));
    let lines = fit(lines, rect.height);
    let row = lines.iter().position(|line| *line == field);
    draw_card(f, rect, look, lines);
    // After the border and its padding, '> ' and the word.
    if let Some(row) = row.and_then(|row| u16::try_from(row).ok()) {
        let inner = overlay_block(look).inner(rect);
        if row < inner.height {
            let x = u16::try_from(field.width()).unwrap_or(u16::MAX);
            let x = inner.x.saturating_add(x.min(inner.width.saturating_sub(1)));
            f.set_cursor_position(Position::new(x, inner.y + row));
        }
    }
}

/// FORGET (PP.21): the question for the friend `peer` (the CLI's words)
/// and the keys.
pub(super) fn render_forget_address(f: &mut Frame, area: Rect, app: &App, peer: &str) {
    let look = app.look();
    let name = friend_name(app, peer);
    let rect_width = NOTE_WIDTH.min(area.width);
    let width = inner_width(rect_width);
    let question = format!(
        "Forget {name}'s saved address? Raven can then reach {name} only after {name} connects \
         to you, or after you save a new address."
    );
    let mut lines: Vec<Line<'static>> = wrap(&question, width, 0)
        .into_iter()
        .map(Line::raw)
        .collect();
    lines.push(Line::default());
    lines.extend(verify::key_rows(look, &FORGET_KEYS, "   ", width));
    let rect = centered(area, rect_width, height_of(&lines));
    draw_card(f, rect, look, fit(lines, rect.height));
}

/// NOTICE (PP.21): the sealing notice (on macOS with the keychain
/// sentence) or the retention notice, in the UX copy's words, and OK; or
/// that Raven's login item stays off (PP.23).
pub(super) fn render_privacy_notice(f: &mut Frame, area: Rect, app: &App, notice: Notice) {
    let look = app.look();
    let rect_width = NOTE_WIDTH.min(area.width);
    let width = inner_width(rect_width);
    let paragraphs = match (notice, app.privacy()) {
        (Notice::Sealing, _) => {
            let mut paragraphs = vec![bridge::SEALING_NOTICE.to_owned()];
            if app.on_mac() {
                paragraphs.push(bridge::KEYCHAIN_AT_START_TEXT.to_owned());
            }
            paragraphs
        }
        (Notice::Retention, Some(read)) => match read.notices.retention_from {
            Some(first) => vec![bridge::retention_notice_text(
                read.keep,
                first,
                app.now_ms(),
            )],
            None => return,
        },
        (Notice::Retention, None) => return,
        (Notice::LoginItemOff, _) => vec![LOGIN_ITEM_OFF_NOTICE.to_owned()],
    };
    let mut lines = Vec::new();
    for paragraph in paragraphs {
        if !lines.is_empty() {
            lines.push(Line::default());
        }
        lines.extend(wrap(&paragraph, width, 0).into_iter().map(Line::raw));
    }
    lines.push(Line::default());
    lines.push(keys_line(look, &[NOTICE_KEYS]));
    let rect = centered(area, rect_width, height_of(&lines));
    draw_card(f, rect, look, fit(lines, rect.height));
}

/// What ERASE lists for `plan`, in plain words: the identity, the friends,
/// the chats, the waiting messages and the keys in the system's keystore
/// (the keychain on a Mac, the keyring elsewhere); a count of none is left
/// out, and friends that can't be counted now are 'your friends'.
pub(super) fn erase_items(plan: &ErasePlanView, mac: bool) -> Vec<String> {
    let counted = |n: u32, one: &str, many: &str| match n {
        1 => format!("1 {one}"),
        n => format!("{n} {many}"),
    };
    let mut items = vec!["your identity".to_owned()];
    match plan.friends {
        None => items.push("your friends".to_owned()),
        Some(0) => {}
        Some(n) => items.push(counted(n, "friend", "friends")),
    }
    items.push("your chats".to_owned());
    if plan.waiting > 0 {
        items.push(counted(plan.waiting, "waiting message", "waiting messages"));
    }
    if plan.keychain_keys > 0 {
        let store = if mac { "keychain" } else { "keyring" };
        items.push(counted(
            plan.keychain_keys,
            &format!("key in this computer's {store}"),
            &format!("keys in this computer's {store}"),
        ));
    }
    items
}

/// ERASE (PP.22), over the whole screen: the UX copy's title and
/// paragraph, then by `erase`'s state what goes in plain words and the
/// typed word (the terminal's cursor after it), a spinner with how far the
/// erase is, or why nothing was erased; the keys on the bottom rows. In a
/// small window the list becomes one sentence, then blank rows go, then the
/// paragraph is cut: the title, the field and the keys always show.
pub(super) fn render_erase(f: &mut Frame, area: Rect, app: &App, erase: &EraseState, now: Instant) {
    let look = app.look();
    let (g, t) = (&look.glyphs, &look.theme);
    let block = overlay_block(look);
    let inner = block.inner(area);
    widgets::clear(f, area, look);
    f.render_widget(block, area);
    if inner.is_empty() {
        return;
    }
    let width = inner.width;
    let rows = |copy: &str| -> Vec<Line<'static>> {
        wrap(copy, width, 0).into_iter().map(Line::raw).collect()
    };
    // Why erase refused or stopped: a command or a folder in it is broken,
    // never cut.
    let raw = |copy: &str| -> Vec<Line<'static>> {
        wrap_command(&display::one_line(copy, u16::MAX, ""), width)
            .into_iter()
            .map(Line::raw)
            .collect()
    };
    let spinner = |since: Instant, copy: &str| {
        spinning(look, since, now, &format!("{copy}{}", g.ellipsis), width)
    };
    let mut top = vec![Line::styled(bridge::ERASE_TITLE, t.accent), Line::default()];
    let paragraph = rows(bridge::ERASE_PARAGRAPH);
    // Below the paragraph: the list (full and as one sentence), and the
    // rows that always show (the field, the progress, the keys).
    let (list, short, bottom, keys, field): (_, _, Vec<Line<'static>>, Vec<_>, _) = match erase {
        EraseState::Reading => (
            Vec::new(),
            Vec::new(),
            spinner(now, ERASE_READING),
            vec![ERASE_CANCEL],
            None,
        ),
        EraseState::Refused(why) | EraseState::NotErased(why) => {
            (Vec::new(), Vec::new(), raw(why), vec![CLOSE_KEYS], None)
        }
        EraseState::Asking { plan, typed } => {
            let items = erase_items(plan, app.on_mac());
            let mut list = rows(ERASE_LIST);
            for item in &items {
                list.extend(
                    wrap(item, width.saturating_sub(4), 0)
                        .into_iter()
                        .enumerate()
                        .map(|(i, row)| {
                            let lead = if i == 0 { g.bullet } else { " " };
                            Line::raw(format!("  {lead} {row}"))
                        }),
                );
            }
            let short = rows(&format!("{ERASE_LIST} {}.", and_list(&items)));
            let field = Line::raw(format!("> {}", display::one_line(typed, u16::MAX, "")));
            let mut bottom = rows(ERASE_PROMPT);
            bottom.push(field.clone());
            (list, short, bottom, ERASE_KEYS.to_vec(), Some(field))
        }
        EraseState::Erasing { since, stage } => {
            let copy = match stage {
                EraseStage::Waiting if app.sending() => QUIT_SENDING,
                EraseStage::Waiting => ERASE_WAITING,
                EraseStage::Stopping => QUIT_STOPPING,
                EraseStage::Running => ERASE_RUNNING,
            };
            let keys = if *stage == EraseStage::Waiting {
                vec![ERASE_CANCEL]
            } else {
                Vec::new()
            };
            (Vec::new(), Vec::new(), spinner(*since, copy), keys, None)
        }
    };
    // The keys on the bottom rows, as on SET and NET.
    let key_lines = verify::key_rows(look, &keys, "   ", width);
    let room = usize::from(inner.height).saturating_sub(key_lines.len());
    let tail = bottom;
    let tail_len = tail.len() + 1;
    // The list as rows when it fits beside the whole paragraph, else as a
    // sentence; then blank rows go (the first first: the one above the field
    // stays longest), then the paragraph's last rows.
    let list = if top.len() + paragraph.len() + 1 + list.len() + tail_len <= room {
        list
    } else {
        short
    };
    let mut body = paragraph;
    if !list.is_empty() {
        body.push(Line::default());
        body.extend(list);
    }
    body.push(Line::default());
    let mut lines = Vec::new();
    lines.append(&mut top);
    lines.extend(body);
    while lines.len() + tail.len() > room {
        match lines.iter().position(|line| line.width() == 0) {
            Some(blank) => {
                lines.remove(blank);
            }
            None => break,
        }
    }
    if lines.len() + tail.len() > room {
        // The title stays; the rows above the field are cut from the end.
        lines.truncate(room.saturating_sub(tail.len()).max(1));
    }
    lines.extend(tail);
    lines.truncate(room);
    lines.resize(room, Line::default());
    lines.extend(key_lines);
    let row = field
        .as_ref()
        .and_then(|field| lines.iter().position(|line| line == field));
    f.render_widget(Paragraph::new(lines), inner);
    // After '> ' and the word.
    if let (Some(row), Some(field)) = (row.and_then(|row| u16::try_from(row).ok()), &field) {
        let x = u16::try_from(field.width()).unwrap_or(u16::MAX);
        let x = inner.x.saturating_add(x.min(inner.width.saturating_sub(1)));
        f.set_cursor_position(Position::new(x, inner.y + row));
    }
}

/// `items` as one phrase: 'a, b and c'.
fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// A command (or any technical text) in rows of at most `width` cells:
/// broken at spaces, and a word longer than a row broken where the row ends,
/// so none of it is cut off.
pub(super) fn wrap_command(command: &str, width: u16) -> Vec<String> {
    let room = usize::from(width.max(1));
    let mut rows = Vec::new();
    for row in wrap(command, width, 0) {
        if cells(&row) <= room {
            rows.push(row);
            continue;
        }
        let chars: Vec<char> = row.chars().collect();
        rows.extend(
            chars
                .chunks(room)
                .map(|piece| piece.iter().collect::<String>()),
        );
    }
    rows
}

/// A card's keys: each key in the accent style, then its words.
pub(super) fn keys_line(look: &Look, keys: &[(&'static str, &'static str)]) -> Line<'static> {
    let mut spans = Vec::new();
    for (i, (key, words)) in keys.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("   "));
        }
        spans.push(widgets::key(look, key));
        spans.push(widgets::key_words(look, words));
    }
    Line::from(spans)
}

/// Cells for text inside a card `width` cells wide: its border and padding
/// take four.
pub(super) fn inner_width(width: u16) -> u16 {
    width.saturating_sub(4)
}

/// A card's height for `lines`: two border rows more.
pub(super) fn height_of(lines: &[Line]) -> u16 {
    u16::try_from(lines.len())
        .unwrap_or(u16::MAX)
        .saturating_add(2)
}

/// `lines` for a card `height` rows high: when they don't fit, the blank
/// rows go first, so the keys at the bottom stay.
pub(super) fn fit(mut lines: Vec<Line<'static>>, height: u16) -> Vec<Line<'static>> {
    let room = usize::from(height.saturating_sub(2));
    while lines.len() > room {
        match lines.iter().rposition(|line| line.width() == 0) {
            Some(blank) => {
                lines.remove(blank);
            }
            None => break,
        }
    }
    if lines.len() > room && room > 0 {
        // Still too many: the keys stay, the text above them is cut.
        let keys = lines.pop();
        lines.truncate(room - 1);
        lines.extend(keys);
    }
    lines
}

/// Clears `rect` and draws `lines` in an overlay card there.
pub(super) fn draw_card(f: &mut Frame, rect: Rect, look: &Look, lines: Vec<Line<'static>>) {
    widgets::clear(f, rect, look);
    f.render_widget(Paragraph::new(lines).block(overlay_block(look)), rect);
}

/// The toast on the bottom row, over the key hints until it goes: one line,
/// cut to the window.
pub(super) fn render_toast(f: &mut Frame, area: Rect, look: &Look, toast: &Toast) {
    if area.is_empty() {
        return;
    }
    let row = Rect {
        y: area.bottom() - 1,
        height: 1,
        ..area
    };
    let text = display::one_line(&toast.text, row.width, look.glyphs.ellipsis);
    widgets::clear(f, row, look);
    f.render_widget(Paragraph::new(Span::styled(text, look.theme.warn)), row);
}

/// HELP's rows at `width` cells: `keys` and that they work with a Persian
/// keyboard, then each mark and tick with its meaning ('Not verified' says
/// where the security words guide is), then the way back to the classic
/// menu.
fn help_lines(
    look: &Look,
    keys: &[(&str, &'static str)],
    group_keys: &[(&str, &'static str)],
    width: u16,
) -> Vec<Line<'static>> {
    let (g, t) = (&look.glyphs, &look.theme);
    let key_rows = |keys: &[(&str, &'static str)]| -> Vec<Line<'static>> {
        keys.iter()
            .flat_map(|(key, action)| {
                // A space after a key, however long ('Up, Down'); the action
                // wrapped under its start.
                let key = format!("{key:<width$} ", width = KEY_COLUMN - 1);
                let indent = u16::try_from(cells(&key)).unwrap_or(0);
                let room = width.saturating_sub(indent);
                wrap(action, room, 0)
                    .into_iter()
                    .enumerate()
                    .map(|(i, row)| {
                        let lead = if i == 0 {
                            key.clone()
                        } else {
                            " ".repeat(usize::from(indent))
                        };
                        Line::from(vec![
                            Span::styled(lead, t.accent.add_modifier(Modifier::BOLD)),
                            Span::raw(row),
                        ])
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    let mut lines = vec![Line::styled("Keys", t.title)];
    lines.extend(key_rows(keys));
    lines.extend(
        wrap(HELP_PERSIAN_KEYBOARD, width, 0)
            .into_iter()
            .map(|row| Line::styled(row, t.secondary)),
    );
    if !group_keys.is_empty() {
        lines.push(Line::default());
        lines.push(Line::styled("Groups", t.title));
        lines.extend(key_rows(group_keys));
    }
    lines.push(Line::default());
    lines.push(Line::styled("What the symbols mean", t.title));
    let legend = [
        (
            g.dot_recent,
            "In touch: since you opened Raven, a message from them arrived, or one of yours \
             was delivered, in the last 15 minutes. It doesn't mean they are online now.",
        ),
        (
            g.dot_half,
            "Messages waiting: some of your messages haven't reached them yet.",
        ),
        (
            g.dot_off,
            "No recent contact: Raven has no online indicator.",
        ),
        (
            g.dot_none,
            "No address: Raven doesn't know where to reach them.",
        ),
        (
            g.dot_alert,
            "Not verified: you haven't compared security words yet. More in \
             docs/SECURITY_WORDS.md.",
        ),
        (
            g.alarm_badge,
            "Security alert: Raven noticed something about them (press D, or W for all).",
        ),
    ];
    push_marked(&mut lines, &legend, width);
    lines.push(Line::default());
    let ticks = [
        // HELP never animates: the spinner's first frame.
        (g.spinner_frame(look.motion, 0), "Sending"),
        (g.tick_waiting, "Waiting (Raven keeps trying)"),
        (
            g.tick_sent,
            "Sent: it left this computer, not confirmed yet",
        ),
        (g.tick_delivered, "Delivered: their Raven confirmed it"),
        (g.tick_failed, "Not delivered, not confirmed or not sent"),
    ];
    push_marked(&mut lines, &ticks, width);
    lines.push(Line::default());
    lines.extend(
        wrap(HELP_FOOTER, width, 0)
            .into_iter()
            .map(|row| Line::styled(row, t.secondary)),
    );
    lines
}

/// Each mark, a space and its meaning, wrapped under the meaning's start.
fn push_marked(lines: &mut Vec<Line<'static>>, marks: &[(&str, &str)], width: u16) {
    for (mark, meaning) in marks {
        let indent = u16::try_from(cells(mark) + 1).unwrap_or(0);
        lines.extend(
            wrap(&format!("{mark} {meaning}"), width, indent)
                .into_iter()
                .map(Line::raw),
        );
    }
}

/// HELP's box in `area`: as large as allowed, centred.
fn help_rect(area: Rect) -> Rect {
    centered(area, HELP_WIDTH, HELP_HEIGHT)
}

/// The border and padding every overlay has, in the glyph set's border:
/// dim, with a bold title (Calm).
pub(super) fn overlay_block(look: &Look) -> Block<'static> {
    Block::bordered()
        .border_set(look.glyphs.border)
        .border_style(look.theme.focus)
        .title_style(look.theme.title)
        .padding(Padding::horizontal(1))
}

/// Rows a list of `rows` can scroll in a box `visible` rows high.
fn max_scroll(rows: usize, visible: u16) -> u16 {
    u16::try_from(rows.saturating_sub(usize::from(visible))).unwrap_or(u16::MAX)
}

/// A `width` by `height` box centred in `area`, shrunk to fit it.
pub(super) fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let (width, height) = (width.min(area.width), height.min(area.height));
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyCode;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use raven_core::ipc::OutboxItem;
    use std::path::PathBuf;
    use std::time::Duration;

    // ── QUIT ────────────────────────────────────────────────────────────────

    fn not_running() -> Probe {
        Probe::of(&Err("raven-node is not running; start it".into()))
    }

    /// The app at 80x24 with `settings`, one friend, its first jobs answered:
    /// no vault problem, no node running, no login service.
    fn settled(settings: TuiState) -> App {
        let mut app = testkit::app((80, 24));
        app.start(Session {
            settings,
            ..testkit::session(Receive::Off)
        });
        for result in [
            JobResult::Vault(Vault::default()),
            JobResult::Probed(not_running()),
            JobResult::Managed(None),
            JobResult::Contacts {
                contacts: Ok(vec![testkit::reachable(1)]),
                stamp: FileStamp::default(),
            },
            JobResult::History {
                history: Ok(Default::default()),
                stamp: FileStamp::default(),
            },
        ] {
            testkit::send(&mut app, Msg::Job(result));
        }
        app
    }

    /// 'When I quit' as `on_quit`; receiving off, so nothing starts by
    /// itself.
    fn quitting(on_quit: OnQuit) -> TuiState {
        TuiState {
            on_quit,
            receive: Receive::Off,
            ..TuiState::default()
        }
    }

    /// [`settled`], and a node that ran before the app answering as 4242.
    fn running_earlier(on_quit: OnQuit) -> App {
        let mut app = settled(quitting(on_quit));
        testkit::send(
            &mut app,
            Msg::Job(JobResult::Probed(testkit::status(4242, "0.0.0.0:7420"))),
        );
        app
    }

    /// [`settled`], and the node this app started as 4242.
    fn started_here(on_quit: OnQuit) -> App {
        let mut app = settled(quitting(on_quit));
        testkit::started_here(&mut app, 4242);
        assert_eq!(app.node().started_by_app, Some(4242));
        app
    }

    /// Q on the friend list: QUIT's rows (the dialog's band of the screen).
    fn quit_rows(app: &mut App) -> Vec<String> {
        testkit::press(app, KeyCode::Char('q'));
        assert_eq!(app.overlays(), [Overlay::Quit]);
        rows_now(app)
    }

    fn rows_now(app: &App) -> Vec<String> {
        testkit::render(app, 80, 24)[6..18].to_vec()
    }

    fn stopped(outcome: StopOutcome, after: Probe) -> Msg {
        Msg::Job(JobResult::Stopped(Stopped { outcome, after }))
    }

    const STOP_JOB: Cmd = Cmd::Node(NodeJob::Stop {
        started_by_app: None,
        managed: false,
    });

    #[test]
    fn quit_when_no_background_program_runs() {
        let mut app = settled(quitting(OnQuit::KeepRunning));
        testkit::assert_rows(
            &quit_rows(&mut app),
            &[
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ Quit Raven? The background program isn't running, so     │         │",
                "│         │ friends can't reach you until you open Raven again.      │         │",
                "│         │                                                          │         │",
                "│         │ [Enter] Quit   [L] Lock: stop Raven and quit             │         │",
                "│         │ [Esc] Stay                                               │         │",
                "│         └──────────────────────────────────────────────────────────┘         │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
            ],
        );
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Exit(ExitPlan::quit(None))]
        );
    }

    #[test]
    fn quit_keeps_it_running_or_stops_it() {
        let mut app = running_earlier(OnQuit::KeepRunning);
        testkit::assert_rows(
            &quit_rows(&mut app),
            &[
                "│                    ││                                                        │",
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ Quit Raven?                                              │         │",
                "│         │                                                          │         │",
                "│         │ Raven's background program keeps running while this      │         │",
                "│         │ computer is on and you stay logged in, so friends can    │         │",
                "│         │ still reach you and waiting messages keep trying.        │         │",
                "│         │                                                          │         │",
                "│         │ [Enter] Quit   [S] Quit and stop the background program  │         │",
                "│         │ [L] Lock: stop Raven and quit   [Esc] Stay               │         │",
                "│         └──────────────────────────────────────────────────────────┘         │",
                "│                    ││                                                        │",
            ],
        );
        // K is no key here; Enter keeps it running, and says so after.
        assert!(testkit::press(&mut app, KeyCode::Char('k')).is_empty());
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Exit(ExitPlan::quit(Some(4242)))]
        );
        assert_eq!(
            ExitPlan::quit(Some(4242)).line.as_deref(),
            Some(
                "Raven is still running in the background (process 4242), so friends can \
                 reach you while this computer is on. Open it again with: raven"
            )
        );

        // S stops it first; nothing but its answer ends QUIT then.
        let mut app = running_earlier(OnQuit::KeepRunning);
        testkit::press(&mut app, KeyCode::Char('q'));
        assert_eq!(testkit::press(&mut app, KeyCode::Char('s')), [STOP_JOB]);
        assert!(matches!(app.quit_view(), QuitView::Stopping { .. }));
        testkit::assert_rows(
            &rows_now(&app),
            &[
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ | Stopping Raven's background program...                 │         │",
                "│         └──────────────────────────────────────────────────────────┘         │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
            ],
        );
        for code in [
            KeyCode::Esc,
            KeyCode::Enter,
            KeyCode::Char('q'),
            KeyCode::Char('s'),
        ] {
            assert!(testkit::press(&mut app, code).is_empty());
        }
        assert_eq!(app.overlays(), [Overlay::Quit]);
        assert!(moving(&app).is_some(), "its spinner turns");
        assert_eq!(
            testkit::send(&mut app, stopped(StopOutcome::Stopped, not_running())),
            [Cmd::Exit(ExitPlan::quit_stopped())]
        );
        assert_eq!(
            ExitPlan::quit_stopped().line.as_deref(),
            Some("Raven's background program was stopped.")
        );

        // A stop that left it running says so on the way out.
        for answer in [
            stopped(
                StopOutcome::StillRunning,
                testkit::status(4242, "0.0.0.0:7420"),
            ),
            Msg::Job(JobResult::Failed {
                job: JobName::NodeStop,
                plain: errors::explain_node_unavailable("panicked"),
            }),
        ] {
            let mut app = running_earlier(OnQuit::KeepRunning);
            testkit::press(&mut app, KeyCode::Char('q'));
            testkit::press(&mut app, KeyCode::Char('s'));
            assert_eq!(
                testkit::send(&mut app, answer),
                [Cmd::Exit(ExitPlan::quit(Some(4242)))]
            );
        }
    }

    #[test]
    fn quit_never_stops_a_login_service() {
        let mut app = running_earlier(OnQuit::Ask);
        testkit::send(
            &mut app,
            Msg::Job(JobResult::Managed(Some(Managed::LaunchAgent))),
        );
        testkit::assert_rows(
            &quit_rows(&mut app),
            &[
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ Quit Raven?                                              │         │",
                "│         │                                                          │         │",
                "│         │ Raven's background program keeps running while this      │         │",
                "│         │ computer is on and you stay logged in, so friends can    │         │",
                "│         │ still reach you and waiting messages keep trying. It is  │         │",
                "│         │ set to start when you log in.                            │         │",
                "│         │                                                          │         │",
                "│         │ [Enter] Quit   [L] Lock: stop Raven and quit             │         │",
                "│         │ [Esc] Stay                                               │         │",
                "│         └──────────────────────────────────────────────────────────┘         │",
                "│                    ││                                                        │",
            ],
        );
        for c in ['s', 'k'] {
            assert!(testkit::press(&mut app, KeyCode::Char(c)).is_empty());
        }
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Exit(ExitPlan::quit(Some(4242)))]
        );
        // Windows stops only a node this app started (OD-16).
        let mut windows = running_earlier(OnQuit::Ask);
        windows.set_windows_for_tests(true);
        testkit::press(&mut windows, KeyCode::Char('q'));
        assert_eq!(
            windows.quit_view(),
            QuitView::Running(RunningQuit {
                managed: false,
                can_stop: false,
                enter: Some(QuitChoice::Keep),
            })
        );
        assert!(testkit::press(&mut windows, KeyCode::Char('s')).is_empty());
    }

    #[test]
    fn quit_stops_a_node_this_app_started_when_settings_say_so() {
        let mut app = started_here(OnQuit::StopIfStarted);
        testkit::assert_rows(
            &quit_rows(&mut app),
            &[
                "│                    ││                                                        │",
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ Quit Raven?                                              │         │",
                "│         │                                                          │         │",
                "│         │ Raven's background program stops when you quit, because  │         │",
                "│         │ this app started it. Friends can't reach you until you   │         │",
                "│         │ open Raven again.                                        │         │",
                "│         │                                                          │         │",
                "│         │ [Enter] Quit   [K] Quit and keep it running              │         │",
                "│         │ [L] Lock: stop Raven and quit   [Esc] Stay               │         │",
                "│         └──────────────────────────────────────────────────────────┘         │",
                "│                    ││                                                        │",
            ],
        );
        let stop = Cmd::Node(NodeJob::Stop {
            started_by_app: Some(4242),
            managed: false,
        });
        assert_eq!(testkit::press(&mut app, KeyCode::Enter), [stop]);
        // K keeps it instead.
        let mut app = started_here(OnQuit::StopIfStarted);
        testkit::press(&mut app, KeyCode::Char('q'));
        assert!(
            testkit::press(&mut app, KeyCode::Char('s')).is_empty(),
            "Enter stops here"
        );
        assert_eq!(
            testkit::press(&mut app, KeyCode::Char('k')),
            [Cmd::Exit(ExitPlan::quit(Some(4242)))]
        );
        // One that ran before the app keeps running, as by default.
        let mut app = running_earlier(OnQuit::StopIfStarted);
        testkit::press(&mut app, KeyCode::Char('q'));
        assert_eq!(
            app.quit_view(),
            QuitView::Running(RunningQuit {
                managed: false,
                can_stop: true,
                enter: Some(QuitChoice::Keep),
            })
        );
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Exit(ExitPlan::quit(Some(4242)))]
        );
    }

    /// An update installed from the app stops the node this app started
    /// and starts the new one from this app: that one is this app's own now
    /// (review lock-updates-local-7), so 'Stop Raven if this app started
    /// it' still stops it on quit (and Windows' stop rules may end it).
    /// One the install did not start here stays another's.
    #[test]
    fn the_node_an_update_started_here_is_this_apps() {
        let installed = |started| {
            Msg::Job(JobResult::UpdateInstalled {
                result: Ok(vec!["Raven 1.5.0 is installed and running.".to_owned()]),
                after: testkit::status(4243, "0.0.0.0:7420"),
                started,
            })
        };
        let mut app = started_here(OnQuit::StopIfStarted);
        testkit::send(&mut app, installed(Some(4243)));
        assert_eq!(app.node().started_by_app, Some(4243));
        testkit::press(&mut app, KeyCode::Char('q'));
        assert_eq!(
            app.quit_view(),
            QuitView::Running(RunningQuit {
                managed: false,
                can_stop: true,
                enter: Some(QuitChoice::Stop),
            })
        );
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Node(NodeJob::Stop {
                started_by_app: Some(4243),
                managed: false,
            })]
        );
        // Not started here (a login item, another program), or not the one
        // running now: nobody's, as before.
        for started in [None, Some(4300)] {
            let mut app = started_here(OnQuit::StopIfStarted);
            testkit::send(&mut app, installed(started));
            assert_eq!(app.node().started_by_app, None, "{started:?}");
            testkit::press(&mut app, KeyCode::Char('q'));
            assert!(matches!(
                app.quit_view(),
                QuitView::Running(RunningQuit {
                    enter: Some(QuitChoice::Keep),
                    ..
                })
            ));
        }
    }

    #[test]
    fn quit_asks_every_time_when_settings_say_so() {
        let mut app = started_here(OnQuit::Ask);
        testkit::assert_rows(
            &quit_rows(&mut app),
            &[
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ Quit Raven?                                              │         │",
                "│         │                                                          │         │",
                "│         │ Raven's background program keeps running while this      │         │",
                "│         │ computer is on and you stay logged in, so friends can    │         │",
                "│         │ still reach you and waiting messages keep trying.        │         │",
                "│         │                                                          │         │",
                "│         │ [K] Quit and keep it running                             │         │",
                "│         │ [S] Quit and stop the background program                 │         │",
                "│         │ [L] Lock: stop Raven and quit   [Esc] Stay               │         │",
                "│         └──────────────────────────────────────────────────────────┘         │",
                "│                    ││                                                        │",
            ],
        );
        assert!(
            testkit::press(&mut app, KeyCode::Enter).is_empty(),
            "no default"
        );
        assert_eq!(
            testkit::press(&mut app, KeyCode::Char('K')),
            [Cmd::Exit(ExitPlan::quit(Some(4242)))]
        );
        let mut app = started_here(OnQuit::Ask);
        testkit::press(&mut app, KeyCode::Char('q'));
        assert_eq!(
            testkit::press(&mut app, KeyCode::Char('S')),
            [Cmd::Node(NodeJob::Stop {
                started_by_app: Some(4242),
                managed: false,
            })]
        );
    }

    #[test]
    fn quit_takes_its_keys_from_a_persian_keyboard() {
        // The key of `latin` with a Persian keyboard layout on.
        fn persian(latin: char) -> KeyCode {
            let typed = testkit::on_persian_keyboard(&latin.to_string());
            KeyCode::Char(typed.chars().next().expect("one letter"))
        }
        let mut app = started_here(OnQuit::Ask);
        testkit::press(&mut app, persian('q'));
        assert_eq!(app.overlays(), [Overlay::Quit]);
        assert_eq!(
            testkit::press(&mut app, persian('k')),
            [Cmd::Exit(ExitPlan::quit(Some(4242)))]
        );
        let mut app = started_here(OnQuit::Ask);
        testkit::press(&mut app, persian('q'));
        assert_eq!(
            testkit::press(&mut app, persian('s')),
            [Cmd::Node(NodeJob::Stop {
                started_by_app: Some(4242),
                managed: false,
            })]
        );
    }

    #[test]
    fn quit_waits_for_a_send_or_quits_anyway() {
        // Enter opens the friend's chat; then a message goes out.
        let send = |app: &mut App| {
            testkit::press(app, KeyCode::Enter);
            assert!(testkit::type_and_send(app, "hi").is_some());
            testkit::press(app, KeyCode::Esc);
            testkit::press(app, KeyCode::Char('q'));
        };
        let delivered = || testkit::sent(1, testkit::delivered_to("192.168.1.11:7420"));

        let mut app = settled(quitting(OnQuit::KeepRunning));
        send(&mut app);
        assert_eq!(app.quit_view(), QuitView::NotRunning, "asked first");
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        assert!(matches!(app.quit_view(), QuitView::Sending { .. }));
        testkit::assert_rows(
            &rows_now(&app),
            &[
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ | One message is still being sent. Raven will finish it  │         │",
                "│         │   first (up to a minute).                                │         │",
                "│         │                                                          │         │",
                "│         │ [Q] Quit anyway (it may need sending again)   [Esc] Stay │         │",
                "│         └──────────────────────────────────────────────────────────┘         │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││ You - just now  | Connecting...                        │",
            ],
        );
        assert!(moving(&app).is_some(), "its spinner turns");
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        // The send's answer ends the app.
        assert_eq!(
            testkit::send(&mut app, delivered()),
            [Cmd::Exit(ExitPlan::quit(None))]
        );

        // Q quits at once.
        let mut app = settled(quitting(OnQuit::KeepRunning));
        send(&mut app);
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(
            testkit::press(&mut app, KeyCode::Char('q')),
            [Cmd::Exit(ExitPlan::quit(None))]
        );

        // Esc stays: the send's answer then ends nothing.
        let mut app = settled(quitting(OnQuit::KeepRunning));
        send(&mut app);
        testkit::press(&mut app, KeyCode::Enter);
        assert!(testkit::press(&mut app, KeyCode::Esc).is_empty());
        assert!(app.overlays().is_empty());
        assert!(!testkit::send(&mut app, delivered())
            .iter()
            .any(|cmd| matches!(cmd, Cmd::Exit(_))));

        // A stop waits for the send too.
        let mut app = running_earlier(OnQuit::KeepRunning);
        send(&mut app);
        assert!(testkit::press(&mut app, KeyCode::Char('s')).is_empty());
        assert!(matches!(app.quit_view(), QuitView::Sending { .. }));
        let cmds = testkit::send(&mut app, delivered());
        assert!(cmds.contains(&STOP_JOB), "{cmds:?}");
        assert!(matches!(app.quit_view(), QuitView::Stopping { .. }));
        assert_eq!(
            testkit::send(&mut app, stopped(StopOutcome::Stopped, not_running())),
            [Cmd::Exit(ExitPlan::quit_stopped())]
        );
    }

    #[test]
    fn quit_waits_while_a_friend_is_saved() {
        let mut app = settled(quitting(OnQuit::KeepRunning));
        testkit::press(&mut app, KeyCode::Char('e'));
        testkit::press(&mut app, KeyCode::Char('r'));
        testkit::press(&mut app, KeyCode::Char('x'));
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert!(
            cmds.iter().any(
                |cmd| matches!(cmd, Cmd::Store(job) if job.name().kind() == JobKind::Critical)
            ),
            "{cmds:?}"
        );
        testkit::ctrl(&mut app, 'c');
        assert_eq!(app.quit_view(), QuitView::Saving);
        testkit::assert_rows(
            &rows_now(&app),
            &[
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ ┌──────────────────────────────────────────────────────────┐ │        ",
                "        │ │ Raven is finishing saving your friends. Please wait...   │ │        ",
                "        │ │                                                          │ │        ",
                "        │ │ [Esc] Stay                                               │ │        ",
                "        │ └──────────────────────────────────────────────────────────┘ │        ",
                "        │                                                              │        ",
                "        │ Saving...                                                    │        ",
                "        └──────────────────────────────────────────────────────────────┘        ",
                "                                                                                ",
            ],
        );
        for code in [KeyCode::Enter, KeyCode::Char('q'), KeyCode::Char('s')] {
            assert!(testkit::press(&mut app, code).is_empty());
        }
        // Saved: QUIT asks as usual.
        testkit::send(
            &mut app,
            Msg::Job(JobResult::FriendChanged {
                change: FriendChange::Rename,
                pub_hex: testkit::friend(1).pub_hex,
                result: Ok(()),
                notes: Vec::new(),
            }),
        );
        assert_eq!(app.quit_view(), QuitView::NotRunning);
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Exit(ExitPlan::quit(None))]
        );
    }

    // ── QUIT with messages waiting (UXF.8) ──────────────────────────────────

    /// Messages `ids` of yours to friend `n`: waiting in the history, and
    /// listed as waiting by raven-node until a day after the test clock.
    fn queued(n: u8, ids: &[u32]) -> (Vec<(u8, RowView)>, Vec<OutboxItem>) {
        let rows = ids
            .iter()
            .map(|&id| (n, testkit::row(id, true, "queued", 5, "see you")))
            .collect();
        let items = ids
            .iter()
            .map(|&id| testkit::outbox_item(n, id, "queued"))
            .collect();
        (rows, items)
    }

    /// The app in `look` at `size`, 'When I quit' as `on_quit`: friends 1
    /// to `friends` saved, a background program that ran before the app
    /// (4242), `rows` in the history and `items` in the outbox.
    fn waiting_in(
        look: Look,
        size: (u16, u16),
        on_quit: OnQuit,
        friends: u8,
        rows: &[(u8, RowView)],
        items: Vec<OutboxItem>,
    ) -> App {
        let mut app = testkit::app_in(look, size);
        app.start(Session {
            settings: quitting(on_quit),
            ..testkit::session(Receive::Off)
        });
        for result in [
            JobResult::Vault(Vault::default()),
            JobResult::Probed(testkit::status(4242, "0.0.0.0:7420")),
            JobResult::Managed(None),
            JobResult::Contacts {
                contacts: Ok((1..=friends).map(testkit::reachable).collect()),
                stamp: FileStamp::default(),
            },
            JobResult::History {
                history: Ok(testkit::conversations(rows)),
                stamp: FileStamp::default(),
            },
        ] {
            testkit::send(&mut app, Msg::Job(result));
        }
        testkit::send(&mut app, testkit::outbox(items));
        app
    }

    /// [`waiting_in`] at 80x24 in the render tests' look.
    fn waiting(
        on_quit: OnQuit,
        friends: u8,
        rows: &[(u8, RowView)],
        items: Vec<OutboxItem>,
    ) -> App {
        waiting_in(
            testkit::simple_mono(),
            (80, 24),
            on_quit,
            friends,
            rows,
            items,
        )
    }

    /// Q, and QUIT up long enough for its keys that end the app.
    fn quit_settled(app: &mut App) {
        testkit::press(app, KeyCode::Char('q'));
        assert_eq!(app.overlays(), [Overlay::Quit]);
        testkit::tick(app, QUIT_SETTLE);
    }

    /// The question behind the warning when a background program that ran
    /// before the app keeps running.
    const KEEPS: RunningQuit = RunningQuit {
        managed: false,
        can_stop: true,
        enter: Some(QuitChoice::Keep),
    };

    #[test]
    fn quit_says_which_messages_have_not_gone_yet() {
        let (rows, items) = queued(1, &[1, 2]);
        let mut app = waiting(OnQuit::KeepRunning, 1, &rows, items.clone());
        testkit::assert_rows(
            &quit_rows(&mut app),
            &[
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ 2 messages to Friend 1 haven't gone yet.                 │         │",
                "│         │ If you leave this network now, they wait until next time │         │",
                "│         │ (until about 24 h from now).                             │         │",
                "│         │                                                          │         │",
                "│         │ [Enter] Stay and wait   [Q] Quit anyway                  │         │",
                "│         └──────────────────────────────────────────────────────────┘         │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
            ],
        );
        assert_eq!(
            app.quit_view(),
            QuitView::Waiting(WaitingQuit {
                peer: testkit::friend(1).pub_hex,
                count: 2,
                more: 0,
                until_ms: Some(items[0].expires_at_ms),
                question: KEEPS,
            })
        );
        assert!(moving(&app).is_none(), "nothing turns");
        // Enter stays and waits; so does Esc.
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        assert!(app.overlays().is_empty());
        testkit::press(&mut app, KeyCode::Char('q'));
        assert!(testkit::press(&mut app, KeyCode::Esc).is_empty());
        assert!(app.overlays().is_empty());
        // Q quits anyway, as Enter on the question would, once QUIT has been
        // up a moment: the Q that opened it, pressed twice or held down,
        // doesn't.
        testkit::press(&mut app, KeyCode::Char('q'));
        for code in [KeyCode::Char('q'), KeyCode::Char('Q')] {
            assert!(testkit::press(&mut app, code).is_empty());
        }
        testkit::tick(&mut app, QUIT_SETTLE - Duration::from_millis(1));
        assert!(testkit::press(&mut app, KeyCode::Char('q')).is_empty());
        testkit::tick(&mut app, Duration::from_millis(1));
        // S, K, L and Ctrl+C are not its keys.
        for c in ['s', 'k', 'l'] {
            assert!(testkit::press(&mut app, KeyCode::Char(c)).is_empty());
        }
        assert!(testkit::ctrl(&mut app, 'c').is_empty());
        assert_eq!(app.overlays(), [Overlay::Quit]);
        assert_eq!(
            testkit::press(&mut app, KeyCode::Char('q')),
            [Cmd::Exit(ExitPlan::quit(Some(4242)))]
        );

        // One message.
        let (rows, items) = queued(1, &[1]);
        let mut app = waiting(OnQuit::KeepRunning, 1, &rows, items);
        assert_eq!(
            testkit::screen_text(&quit_rows(&mut app)),
            "1 message to Friend 1 hasn't gone yet. If you leave this network now, it waits \
             until next time (until about 24 h from now). [Enter] Stay and wait [Q] Quit anyway"
        );
    }

    #[test]
    fn quit_warns_in_the_smallest_window_in_each_glyph_set() {
        let (rows, items) = queued(1, &[1, 2]);
        for (glyphs, want) in [
            (
                Glyphs::simple(),
                &[
                    "R A V E N                               + node ok - just now",
                    "┌ Friends ─────────────────────────────────────────────────┐",
                    "│> ~ Friend 1                                             !│",
                    "│                                                          │",
                    "┌──────────────────────────────────────────────────────────┐",
                    "│ 2 messages to Friend 1 haven't gone yet.                 │",
                    "│ If you leave this network now, they wait until next time │",
                    "│ (until about 24 h from now).                             │",
                    "│                                                          │",
                    "│ [Enter] Stay and wait   [Q] Quit anyway                  │",
                    "└──────────────────────────────────────────────────────────┘",
                    "│                                                          │",
                    "│                                                          │",
                    "│ A  Add a friend                                          │",
                    "└──────────────────────────────────────────────────────────┘",
                    "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify ",
                ][..],
            ),
            (
                Glyphs::fancy(),
                &[
                    "R A V E N                               ♥ node ok · just now",
                    "╭ Friends ─────────────────────────────────────────────────╮",
                    "│> ◐ Friend 1                                             !│",
                    "│                                                          │",
                    "╭──────────────────────────────────────────────────────────╮",
                    "│ 2 messages to Friend 1 haven't gone yet.                 │",
                    "│ If you leave this network now, they wait until next time │",
                    "│ (until about 24 h from now).                             │",
                    "│                                                          │",
                    "│ [Enter] Stay and wait   [Q] Quit anyway                  │",
                    "╰──────────────────────────────────────────────────────────╯",
                    "│                                                          │",
                    "│                                                          │",
                    "│ A  Add a friend                                          │",
                    "╰──────────────────────────────────────────────────────────╯",
                    "? Help · Q Quit · ↑↓ Choose · Enter Open · A Add · V Verify ",
                ][..],
            ),
            (
                Glyphs::ascii(),
                &[
                    "R A V E N                               + node ok - just now",
                    "+ Friends -------------------------------------------------+",
                    "|> ~ Friend 1                                             !|",
                    "|                                                          |",
                    "+----------------------------------------------------------+",
                    "| 2 messages to Friend 1 haven't gone yet.                 |",
                    "| If you leave this network now, they wait until next time |",
                    "| (until about 24 h from now).                             |",
                    "|                                                          |",
                    "| [Enter] Stay and wait   [Q] Quit anyway                  |",
                    "+----------------------------------------------------------+",
                    "|                                                          |",
                    "|                                                          |",
                    "| A  Add a friend                                          |",
                    "+----------------------------------------------------------+",
                    "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify ",
                ][..],
            ),
        ] {
            let look = Look {
                glyphs,
                theme: Theme::mono(),
                ..testkit::simple_mono()
            };
            let mut app = waiting_in(look, (60, 16), OnQuit::KeepRunning, 1, &rows, items.clone());
            testkit::press(&mut app, KeyCode::Char('q'));
            testkit::assert_rows(&testkit::render(&app, 60, 16), want);
        }
    }

    #[test]
    fn quit_names_the_friend_whose_message_runs_out_first() {
        let (mut rows, mut items) = queued(1, &[1, 2]);
        let (theirs, mut soon) = queued(2, &[3]);
        rows.extend(theirs);
        // Friend 2's runs out in 3 hours, friend 1's in a day.
        soon[0].expires_at_ms -= 21 * 3_600_000;
        let in_3_h = soon[0].expires_at_ms;
        items.extend(soon.clone());
        let mut app = waiting(OnQuit::KeepRunning, 2, &rows, items.clone());
        testkit::assert_rows(
            &quit_rows(&mut app),
            &[
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ 1 message to Friend 2 and 2 more haven't gone yet.       │         │",
                "│         │ If you leave this network now, they wait until next time │         │",
                "│         │ (until about 3 h from now).                              │         │",
                "│         │                                                          │         │",
                "│         │ [Enter] Stay and wait   [Q] Quit anyway                  │         │",
                "│         └──────────────────────────────────────────────────────────┘         │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
            ],
        );
        assert_eq!(
            app.quit_view(),
            QuitView::Waiting(WaitingQuit {
                peer: testkit::friend(2).pub_hex,
                count: 1,
                more: 2,
                until_ms: Some(in_3_h),
                question: KEEPS,
            })
        );

        // A time raven-node didn't give comes last.
        let unknown: Vec<_> = items
            .iter()
            .cloned()
            .map(|mut item| {
                if item.peer_pub_hex == testkit::friend(2).pub_hex {
                    item.expires_at_ms = 0;
                }
                item
            })
            .collect();
        let mut app = waiting(OnQuit::KeepRunning, 2, &rows, unknown);
        assert_eq!(
            testkit::screen_text(&quit_rows(&mut app)),
            "2 messages to Friend 1 and 1 more haven't gone yet. If you leave this network now, \
             they wait until next time (until about 24 h from now). [Enter] Stay and wait [Q] \
             Quit anyway"
        );
        // With none known, the list's order, and no time.
        let none: Vec<_> = items
            .into_iter()
            .map(|mut item| {
                item.expires_at_ms = 0;
                item
            })
            .collect();
        let mut app = waiting(OnQuit::KeepRunning, 2, &rows, none);
        assert_eq!(
            testkit::screen_text(&quit_rows(&mut app)),
            "2 messages to Friend 1 and 1 more haven't gone yet. If you leave this network now, \
             they wait until next time. [Enter] Stay and wait [Q] Quit anyway"
        );
    }

    /// Review cross-5: a message parked until its deadline (`waiting`,
    /// Phase 5a) waits for the background program, which alone pairs and
    /// seals it again: QUIT warns about it as about a queued one.
    #[test]
    fn quit_counts_a_parked_message() {
        let (rows, mut items) = queued(1, &[1]);
        items[0].state = "waiting".into();
        let until_ms = Some(items[0].expires_at_ms);
        let mut app = waiting(OnQuit::KeepRunning, 1, &rows, items);
        testkit::press(&mut app, KeyCode::Char('q'));
        assert_eq!(
            app.quit_view(),
            QuitView::Waiting(WaitingQuit {
                peer: testkit::friend(1).pub_hex,
                count: 1,
                more: 0,
                until_ms,
                question: KEEPS,
            })
        );
    }

    #[test]
    fn quit_without_waiting_messages_is_todays_quit() {
        let (rows, items) = queued(1, &[1, 2, 3, 4]);
        // Gone from this computer, held, or ended: nothing for staying to do.
        let ended: Vec<_> = items
            .iter()
            .cloned()
            .zip(["sent", "held", "delivered", "expired"])
            .map(|(mut item, state)| {
                item.state = state.into();
                item
            })
            .collect();
        let mut app = waiting(OnQuit::KeepRunning, 1, &rows, ended);
        testkit::press(&mut app, KeyCode::Char('q'));
        assert_eq!(app.quit_view(), QuitView::Running(KEEPS));
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Exit(ExitPlan::quit(Some(4242)))],
            "Enter quits at once"
        );
        // A list from before the history said they were delivered.
        let delivered: Vec<_> = rows
            .iter()
            .map(|(n, row)| {
                (
                    *n,
                    RowView {
                        delivery: "delivered".into(),
                        ..row.clone()
                    },
                )
            })
            .collect();
        let mut app = waiting(OnQuit::KeepRunning, 1, &delivered, items.clone());
        testkit::press(&mut app, KeyCode::Char('q'));
        assert_eq!(app.quit_view(), QuitView::Running(KEEPS));
        // Messages to someone who isn't a saved friend.
        let (rows_9, items_9) = queued(9, &[9]);
        let mut app = waiting(OnQuit::KeepRunning, 1, &rows_9, items_9);
        testkit::press(&mut app, KeyCode::Char('q'));
        assert_eq!(app.quit_view(), QuitView::Running(KEEPS));
        // With no background program, staying wouldn't send them.
        let mut app = waiting(OnQuit::KeepRunning, 1, &rows, items);
        testkit::send(&mut app, Msg::Job(JobResult::Probed(not_running())));
        testkit::press(&mut app, KeyCode::Char('q'));
        assert_eq!(app.quit_view(), QuitView::NotRunning);
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Exit(ExitPlan::quit(None))]
        );
    }

    #[test]
    fn quit_anyway_does_what_enter_on_the_question_does() {
        let (rows, items) = queued(1, &[1]);
        // 'Stop Raven if this app started it', and it did: Q stops it first.
        let mut app = waiting(OnQuit::StopIfStarted, 1, &rows, items.clone());
        testkit::started_here(&mut app, 4242);
        quit_settled(&mut app);
        assert!(matches!(app.quit_view(), QuitView::Waiting(_)));
        assert_eq!(
            testkit::press(&mut app, KeyCode::Char('q')),
            [Cmd::Node(NodeJob::Stop {
                started_by_app: Some(4242),
                managed: false,
            })]
        );
        assert!(matches!(app.quit_view(), QuitView::Stopping { .. }));

        // 'Ask me': Q goes on to the question, whose keys work at once.
        let mut app = waiting(OnQuit::Ask, 1, &rows, items.clone());
        quit_settled(&mut app);
        assert!(testkit::press(&mut app, KeyCode::Char('q')).is_empty());
        assert_eq!(
            app.quit_view(),
            QuitView::Running(RunningQuit {
                enter: None,
                ..KEEPS
            })
        );
        testkit::assert_rows(
            &rows_now(&app),
            &[
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ Quit Raven?                                              │         │",
                "│         │                                                          │         │",
                "│         │ Raven's background program keeps running while this      │         │",
                "│         │ computer is on and you stay logged in, so friends can    │         │",
                "│         │ still reach you and waiting messages keep trying.        │         │",
                "│         │                                                          │         │",
                "│         │ [K] Quit and keep it running                             │         │",
                "│         │ [S] Quit and stop the background program                 │         │",
                "│         │ [L] Lock: stop Raven and quit   [Esc] Stay               │         │",
                "│         └──────────────────────────────────────────────────────────┘         │",
                "│                    ││                                                        │",
            ],
        );
        assert_eq!(
            testkit::press(&mut app, KeyCode::Char('k')),
            [Cmd::Exit(ExitPlan::quit(Some(4242)))]
        );
        // Closed and opened again, it warns again.
        let mut app = waiting(OnQuit::Ask, 1, &rows, items.clone());
        quit_settled(&mut app);
        testkit::press(&mut app, KeyCode::Char('q'));
        testkit::press(&mut app, KeyCode::Esc);
        testkit::press(&mut app, KeyCode::Char('q'));
        assert!(matches!(app.quit_view(), QuitView::Waiting(_)));

        // On a Persian keyboard layout, the Q key.
        let mut app = waiting(OnQuit::KeepRunning, 1, &rows, items);
        let persian_q = testkit::on_persian_keyboard("q");
        let persian_q = KeyCode::Char(persian_q.chars().next().expect("a letter"));
        testkit::press(&mut app, persian_q);
        assert!(matches!(app.quit_view(), QuitView::Waiting(_)));
        testkit::tick(&mut app, QUIT_SETTLE);
        assert_eq!(
            testkit::press(&mut app, persian_q),
            [Cmd::Exit(ExitPlan::quit(Some(4242)))]
        );
    }

    #[test]
    fn the_warning_goes_when_the_messages_do_and_enter_waits_a_moment() {
        let (rows, items) = queued(1, &[1]);
        let mut app = waiting(OnQuit::KeepRunning, 1, &rows, items.clone());
        quit_settled(&mut app);
        // It left this computer while QUIT showed: the question is back.
        testkit::send(
            &mut app,
            testkit::outbox(vec![testkit::outbox_item(1, 1, "sent")]),
        );
        assert_eq!(app.quit_view(), QuitView::Running(KEEPS));
        testkit::assert_rows(
            &rows_now(&app),
            &[
                "│                    ││                                                        │",
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ Quit Raven?                                              │         │",
                "│         │                                                          │         │",
                "│         │ Raven's background program keeps running while this      │         │",
                "│         │ computer is on and you stay logged in, so friends can    │         │",
                "│         │ still reach you and waiting messages keep trying.        │         │",
                "│         │                                                          │         │",
                "│         │ [Enter] Quit   [S] Quit and stop the background program  │         │",
                "│         │ [L] Lock: stop Raven and quit   [Esc] Stay               │         │",
                "│         └──────────────────────────────────────────────────────────┘         │",
                "│                    ││                                                        │",
            ],
        );
        // An Enter meant to stay and wait doesn't quit.
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        assert!(testkit::press(&mut app, KeyCode::Char('s')).is_empty());
        assert_eq!(app.overlays(), [Overlay::Quit]);
        testkit::tick(&mut app, QUIT_SETTLE);
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Exit(ExitPlan::quit(Some(4242)))]
        );

        // The other way: a message starts waiting while the question shows.
        let mut app = waiting(OnQuit::KeepRunning, 1, &rows, Vec::new());
        quit_settled(&mut app);
        assert_eq!(app.quit_view(), QuitView::Running(KEEPS));
        testkit::send(&mut app, testkit::outbox(items));
        assert!(matches!(app.quit_view(), QuitView::Waiting(_)));
        assert!(testkit::press(&mut app, KeyCode::Char('q')).is_empty());
        assert_eq!(app.overlays(), [Overlay::Quit]);
        testkit::tick(&mut app, QUIT_SETTLE);
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        assert!(app.overlays().is_empty(), "Enter stays");
    }

    // ── LOCK ────────────────────────────────────────────────────────────────

    /// The vault check found a passphrase-vault profile.
    fn vault_profile(app: &mut App) {
        testkit::send(
            app,
            Msg::Job(JobResult::Vault(Vault {
                profile: true,
                ..Vault::default()
            })),
        );
        assert!(app.vault_profile());
    }

    /// LOCK's step, while it is open.
    fn lock_step(app: &App) -> Option<&LockStep> {
        app.overlays().iter().find_map(|overlay| match overlay {
            Overlay::Lock(step) => Some(step),
            _ => None,
        })
    }

    /// Q, then L: LOCK's question in QUIT's place.
    fn lock_from_quit(app: &mut App) {
        testkit::press(app, KeyCode::Char('q'));
        assert!(testkit::press(app, KeyCode::Char('l')).is_empty());
        assert_eq!(app.overlays(), [Overlay::Lock(LockStep::Asking)]);
    }

    #[test]
    fn lock_now_in_settings_asks_a_vault_profile() {
        let mut app = settled(quitting(OnQuit::KeepRunning));
        vault_profile(&mut app);
        testkit::press(&mut app, KeyCode::Char('s'));
        for _ in 0..20 {
            testkit::press(&mut app, KeyCode::Down);
        }
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        assert_eq!(app.overlays(), [Overlay::Lock(LockStep::Asking)]);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N - Settings                                  o Receiving is off  ? Help",
                "┌ Settings ────────────────────────────────────────────────────────────────────┐",
                "│   Symbols                                 Automatic                          │",
                "│                                                                              │",
                "│   Receiving                                                                  │",
                "│   When I quit                             Keep Raven running (recommended)   │",
                "│   Receive messages on this computer       Off                                │",
                "│   Share ┌──────────────────────────────────────────────────────────┐         │",
                "│   Show t│ Lock Raven now?                                          │         │",
                "│         │                                                          │         │",
                "│   Privac│ Raven stops. Your chats can't be opened again without    │         │",
                "│   Start │ your passphrase.                                         │         │",
                "│         │                                                          │         │",
                "│   Classi│ Friends can't reach you until you open Raven again.      │         │",
                "│   Switch│                                                          │         │",
                "│   Always│ [Enter] Lock   [Esc] Cancel                              │         │",
                "│         └──────────────────────────────────────────────────────────┘         │",
                "│   Lock                                                                       │",
                "│>  Lock now                                                                   │",
                "│──────────────────────────────────────────────────────────────────────────────│",
                "│                                                                              │",
                "│                                                                              │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
                "Up/Down Choose  [Enter] Lock  [Esc] Back                                        ",
            ],
        );
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N - Settings              o Receiving is off  ? Help",
                "┌ Settings ────────────────────────────────────────────────┐",
                "│   Privacy                                                │",
                "┌──────────────────────────────────────────────────────────┐",
                "│ Lock Raven now?                                          │",
                "│                                                          │",
                "│ Raven stops. Your chats can't be opened again without    │",
                "│ your passphrase.                                         │",
                "│                                                          │",
                "│ Friends can't reach you until you open Raven again.      │",
                "│                                                          │",
                "│ [Enter] Lock   [Esc] Cancel                              │",
                "└──────────────────────────────────────────────────────────┘",
                "│                                                          │",
                "└──────────────────────────────────────────────────────────┘",
                "Up/Down Choose  [Enter] Lock  [Esc] Back                    ",
            ],
        );
        // Esc cancels: nothing is asked, and SET is there again.
        assert!(testkit::press(&mut app, KeyCode::Esc).is_empty());
        assert!(app.overlays().is_empty());
        assert!(matches!(app.screen(), Screen::Settings(_)));
    }

    #[test]
    fn l_on_quit_asks_a_keychain_profile() {
        let mut app = running_earlier(OnQuit::KeepRunning);
        lock_from_quit(&mut app);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                   + node ok - just now",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> o Friend 1       !││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ Stop Raven now?                                          │         │",
                "│         │                                                          │         │",
                "│         │ Raven stops, and friends can't reach you until you open  │         │",
                "│         │ it again.                                                │         │",
                "│         │                                                          │         │",
                "│         │ Your Raven keys stay in this computer's keychain: anyone │         │",
                "│         │ who can log in as you can still open your chats. Lock    │         │",
                "│         │ your screen or log out too.                              │         │",
                "│         │                                                          │         │",
                "│         │ [Enter] Stop   [Esc] Cancel                              │         │",
                "│         └──────────────────────────────────────────────────────────┘         │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│                    ││ Pick a friend on the left and press Enter to start     │",
                "│ A  Add a friend    ││ writing.                                               │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "Listening on your network - all quiet          activity ........................",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
            ],
        );
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N                               + node ok - just now",
                "┌ Friends ─────────────────────────────────────────────────┐",
                "┌──────────────────────────────────────────────────────────┐",
                "│ Stop Raven now?                                          │",
                "│                                                          │",
                "│ Raven stops, and friends can't reach you until you open  │",
                "│ it again.                                                │",
                "│                                                          │",
                "│ Your Raven keys stay in this computer's keychain: anyone │",
                "│ who can log in as you can still open your chats. Lock    │",
                "│ your screen or log out too.                              │",
                "│                                                          │",
                "│ [Enter] Stop   [Esc] Cancel                              │",
                "└──────────────────────────────────────────────────────────┘",
                "└──────────────────────────────────────────────────────────┘",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify ",
            ],
        );
        app.set_look_for_tests(Look {
            glyphs: Glyphs::fancy(),
            ..testkit::simple_mono()
        });
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                   ♥ node ok · just now",
                "╭ Friends ───────────╮╭────────────────────────────────────────────────────────╮",
                "│> ○ Friend 1       !││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│         ╭──────────────────────────────────────────────────────────╮         │",
                "│         │ Stop Raven now?                                          │         │",
                "│         │                                                          │         │",
                "│         │ Raven stops, and friends can't reach you until you open  │         │",
                "│         │ it again.                                                │         │",
                "│         │                                                          │         │",
                "│         │ Your Raven keys stay in this computer's keychain: anyone │         │",
                "│         │ who can log in as you can still open your chats. Lock    │         │",
                "│         │ your screen or log out too.                              │         │",
                "│         │                                                          │         │",
                "│         │ [Enter] Stop   [Esc] Cancel                              │         │",
                "│         ╰──────────────────────────────────────────────────────────╯         │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│                    ││ Pick a friend on the left and press Enter to start     │",
                "│ A  Add a friend    ││ writing.                                               │",
                "╰────────────────────╯╰────────────────────────────────────────────────────────╯",
                "Listening on your network · all quiet          activity ⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀",
                "? Help · Q Quit · ↑↓ Choose · Enter Open · A Add · V Verify · E Friend page     ",
            ],
        );
        // Esc cancels, back to the screen; nothing is stopped.
        assert!(testkit::press(&mut app, KeyCode::Esc).is_empty());
        assert!(app.overlays().is_empty());
        // A Persian keyboard's L key opens it too; Enter right after a paste
        // is no yes; Ctrl+C does nothing here.
        let persian_l = testkit::on_persian_keyboard("l");
        let persian_l = persian_l.chars().next().expect("one letter");
        testkit::press(&mut app, KeyCode::Char('q'));
        assert!(testkit::press(&mut app, KeyCode::Char(persian_l)).is_empty());
        assert_eq!(app.overlays(), [Overlay::Lock(LockStep::Asking)]);
        assert!(testkit::ctrl(&mut app, 'c').is_empty());
        testkit::paste(&mut app, "\n", PasteVia::Bracketed);
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        assert_eq!(lock_step(&app), Some(&LockStep::Asking));
        testkit::tick(&mut app, Duration::from_millis(400));
        assert_eq!(testkit::press(&mut app, KeyCode::Enter), [lock_job(false)]);
        // While the identity or a change to the friends is saved, or before
        // QUIT knows the background program's state, there is no L.
        let mut plain = testkit::ready_app((80, 24), Receive::Off);
        testkit::press(&mut plain, KeyCode::Char('q'));
        assert_eq!(plain.quit_view(), QuitView::Plain);
        assert!(testkit::press(&mut plain, KeyCode::Char('l')).is_empty());
        assert_eq!(plain.overlays(), [Overlay::Quit]);
    }

    #[test]
    fn lock_stops_raven_once_and_ends_on_a_cleared_terminal() {
        let mut app = running_earlier(OnQuit::KeepRunning);
        lock_from_quit(&mut app);
        // Enter: exactly one stop, LOCK's job: where this build reads no
        // login items, X's stop on NET with the lock recorded around it
        // (review D-lock-tui-6).
        assert_eq!(testkit::press(&mut app, KeyCode::Enter), [lock_job(false)]);
        assert!(app.stopping());
        assert!(matches!(
            lock_step(&app),
            Some(LockStep::Locking { stopping: true, .. })
        ));
        testkit::assert_rows(
            &rows_now(&app),
            &[
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ | Stopping Raven's background program...                 │         │",
                "│         └──────────────────────────────────────────────────────────┘         │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
            ],
        );
        assert!(moving(&app).is_some(), "its spinner turns");
        // Nothing but the stop's answer ends it.
        for code in [
            KeyCode::Esc,
            KeyCode::Enter,
            KeyCode::Char('l'),
            KeyCode::Char('q'),
            KeyCode::Char('s'),
        ] {
            assert!(testkit::press(&mut app, code).is_empty());
        }
        assert!(testkit::ctrl(&mut app, 'c').is_empty());
        assert!(matches!(lock_step(&app), Some(LockStep::Locking { .. })));
        assert_eq!(
            testkit::send(&mut app, stopped(StopOutcome::Stopped, not_running())),
            [Cmd::Exit(ExitPlan::locked(false))]
        );
        // From then on the app asks for nothing more.
        assert!(testkit::send(&mut app, testkit::node_up()).is_empty());

        // A passphrase-vault profile is locked; with nothing running, the
        // same end.
        let mut app = running_earlier(OnQuit::KeepRunning);
        vault_profile(&mut app);
        lock_from_quit(&mut app);
        assert_eq!(testkit::press(&mut app, KeyCode::Enter), [lock_job(false)]);
        assert_eq!(
            testkit::send(&mut app, stopped(StopOutcome::Stopped, not_running())),
            [Cmd::Exit(ExitPlan::locked(true))]
        );
        let mut app = settled(quitting(OnQuit::KeepRunning));
        lock_from_quit(&mut app);
        assert_eq!(testkit::press(&mut app, KeyCode::Enter), [lock_job(false)]);
        assert_eq!(
            testkit::send(&mut app, stopped(StopOutcome::NotRunning, not_running())),
            [Cmd::Exit(ExitPlan::locked(false))]
        );

        // The terminal is cleared, then exactly one line, on stdout.
        for (vault, line) in [(true, "Raven is locked."), (false, "Raven is stopped.")] {
            let plan = ExitPlan::locked(vault);
            assert_eq!(
                (plan.code, plan.line.as_deref(), plan.quiet, plan.clear),
                (0, Some(line), false, true)
            );
        }
        for plan in [
            ExitPlan::quit(Some(4242)),
            ExitPlan::quit_stopped(),
            ExitPlan::part_failed(),
            ExitPlan::draw_failed(None),
        ] {
            assert!(!plan.clear, "{plan:?}");
        }
    }

    #[test]
    fn a_stop_that_left_raven_running_keeps_the_app_open_and_says_why() {
        // A login service runs it: LOCK can't stop it.
        let mut app = running_earlier(OnQuit::KeepRunning);
        testkit::send(
            &mut app,
            Msg::Job(JobResult::Managed(Some(Managed::LaunchAgent))),
        );
        lock_from_quit(&mut app);
        let managed_stop = Cmd::Node(NodeJob::Lock {
            started_by_app: None,
            own_item: false,
            managed: true,
        });
        assert_eq!(testkit::press(&mut app, KeyCode::Enter), [managed_stop]);
        let still = || testkit::status(4242, "0.0.0.0:7420");
        assert!(testkit::send(&mut app, stopped(StopOutcome::Managed, still())).is_empty());
        assert_eq!(
            lock_step(&app),
            Some(&LockStep::NotStopped(StopOutcome::Managed))
        );
        assert!(app.toast().is_none(), "LOCK says it, not a toast");
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                   + node ok - just now",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> o Friend 1       !││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ Raven's login service keeps it running, so Lock can't    │         │",
                "│         │ stop it. Lock your screen or log out.                    │         │",
                "│         │                                                          │         │",
                "│         │ [Esc] Close                                              │         │",
                "│         └──────────────────────────────────────────────────────────┘         │",
                "│                    ││                                                        │",
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
        app.set_look_for_tests(Look {
            glyphs: Glyphs::ascii(),
            theme: Theme::mono(),
            ..testkit::simple_mono()
        });
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N                               + node ok - just now",
                "+ Friends -------------------------------------------------+",
                "|> o Friend 1                                             !|",
                "|                                                          |",
                "|                                                          |",
                "+----------------------------------------------------------+",
                "| Raven's login service keeps it running, so Lock can't    |",
                "| stop it. Lock your screen or log out.                    |",
                "|                                                          |",
                "| [Esc] Close                                              |",
                "+----------------------------------------------------------+",
                "|                                                          |",
                "|                                                          |",
                "| A  Add a friend                                          |",
                "+----------------------------------------------------------+",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify ",
            ],
        );
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        assert!(testkit::press(&mut app, KeyCode::Esc).is_empty());
        assert!(app.overlays().is_empty());

        // The stop rules leave it to the user, it still runs, or the stop
        // failed: each said, with NET's stop advice where there is one.
        let cases = [
            (
                stopped(StopOutcome::Advice("kill 4242".into()), still()),
                "Raven can't stop its background program from here. To stop it yourself: \
                 kill 4242 Lock your screen or log out.",
            ),
            (
                stopped(StopOutcome::StillRunning, still()),
                "Raven asked its background program to stop, but it is still running. Lock \
                 your screen or log out.",
            ),
            // It said it stopped, but its Status still answers.
            (
                stopped(StopOutcome::Stopped, still()),
                "Raven asked its background program to stop, but it is still running. Lock \
                 your screen or log out.",
            ),
            (
                stopped(
                    StopOutcome::Failed("Operation not permitted".into()),
                    still(),
                ),
                "Raven couldn't stop its background program. Lock your screen or log out.",
            ),
            (
                Msg::Job(JobResult::Failed {
                    job: JobName::NodeStop,
                    plain: errors::explain_node_unavailable("panicked"),
                }),
                "Raven couldn't stop its background program. Lock your screen or log out.",
            ),
        ];
        for (answer, words) in cases {
            let mut app = running_earlier(OnQuit::KeepRunning);
            lock_from_quit(&mut app);
            assert_eq!(testkit::press(&mut app, KeyCode::Enter), [lock_job(false)]);
            let cmds = testkit::send(&mut app, answer);
            assert!(
                !cmds.iter().any(|cmd| matches!(cmd, Cmd::Exit(_))),
                "{cmds:?}"
            );
            assert!(matches!(lock_step(&app), Some(LockStep::NotStopped(_))));
            let text = testkit::screen_text(&testkit::render(&app, 80, 24));
            assert!(text.contains(&format!("{words} [Esc] Close")), "{text}");
            assert!(!app.stopping());
            assert!(testkit::press(&mut app, KeyCode::Esc).is_empty());
            assert!(app.overlays().is_empty());
        }
    }

    #[test]
    fn lock_waits_for_a_send_and_esc_still_cancels() {
        let mut app = running_earlier(OnQuit::KeepRunning);
        // Enter opens the friend's chat; then a message goes out.
        testkit::press(&mut app, KeyCode::Enter);
        assert!(testkit::type_and_send(&mut app, "hi").is_some());
        testkit::press(&mut app, KeyCode::Esc);
        lock_from_quit(&mut app);
        assert!(
            testkit::press(&mut app, KeyCode::Enter).is_empty(),
            "the send goes first"
        );
        assert!(matches!(
            lock_step(&app),
            Some(LockStep::Locking {
                stopping: false,
                ..
            })
        ));
        testkit::assert_rows(
            &rows_now(&app),
            &[
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ | One message is still being sent. Raven will finish it  │         │",
                "│         │   first (up to a minute).                                │         │",
                "│         │                                                          │         │",
                "│         │ [Esc] Cancel                                             │         │",
                "│         └──────────────────────────────────────────────────────────┘         │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││ You - just now  | Connecting...                        │",
            ],
        );
        assert!(moving(&app).is_some(), "its spinner turns");
        assert!(testkit::tick(&mut app, Duration::from_secs(1)).is_empty());
        // Esc cancels, and nothing was stopped.
        assert!(testkit::press(&mut app, KeyCode::Esc).is_empty());
        assert!(app.overlays().is_empty());
        assert!(!app.stopping());
        // Again: once the send has answered, the stop goes out, once.
        lock_from_quit(&mut app);
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        let delivered = testkit::sent(1, testkit::delivered_to("192.168.1.11:7420"));
        let cmds = testkit::send(&mut app, delivered);
        assert_eq!(
            cmds.iter().filter(|cmd| **cmd == lock_job(false)).count(),
            1,
            "{cmds:?}"
        );
        assert!(matches!(
            lock_step(&app),
            Some(LockStep::Locking { stopping: true, .. })
        ));
    }

    #[test]
    fn nothing_starts_by_itself_while_lock_stops_raven() {
        // Receiving on, the background program not running, the friends not
        // loaded yet: their load would start it (OD-3).
        let first_jobs = |app: &mut App| {
            for result in [
                JobResult::Vault(Vault::default()),
                JobResult::Probed(not_running()),
                JobResult::Managed(None),
            ] {
                testkit::send(app, Msg::Job(result));
            }
        };
        let friends = || {
            Msg::Job(JobResult::Contacts {
                contacts: Ok(vec![testkit::reachable(1)]),
                stamp: FileStamp::default(),
            })
        };
        let ensure = Cmd::Node(NodeJob::Ensure);
        let mut app = testkit::ready_app((80, 24), Receive::On);
        first_jobs(&mut app);
        assert!(testkit::send(&mut app, friends()).contains(&ensure));
        // Not while LOCK stops it.
        let mut app = testkit::ready_app((80, 24), Receive::On);
        first_jobs(&mut app);
        lock_from_quit(&mut app);
        assert_eq!(testkit::press(&mut app, KeyCode::Enter), [lock_job(false)]);
        let cmds = testkit::send(&mut app, friends());
        assert!(!cmds.contains(&ensure), "{cmds:?}");
        assert_eq!(
            testkit::send(&mut app, stopped(StopOutcome::NotRunning, not_running())),
            [Cmd::Exit(ExitPlan::locked(false))]
        );
    }

    #[test]
    fn a_stop_already_running_goes_before_lock_where_no_login_item_is_read() {
        let mut app = started_here(OnQuit::KeepRunning);
        // X on NET, and Y: the stop runs.
        testkit::press(&mut app, KeyCode::Char('n'));
        testkit::press(&mut app, KeyCode::Char('x'));
        let net_stop = Cmd::Node(NodeJob::Stop {
            started_by_app: Some(4242),
            managed: false,
        });
        assert_eq!(testkit::press(&mut app, KeyCode::Char('y')), [net_stop]);
        // LOCK waits for it, then sends its own job, which records the lock
        // around the stop (review D-lock-tui-6), and its answer ends the app.
        lock_from_quit(&mut app);
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        assert!(matches!(
            lock_step(&app),
            Some(LockStep::Locking {
                stopping: false,
                ..
            })
        ));
        assert_eq!(
            testkit::send(&mut app, stopped(StopOutcome::Stopped, not_running())),
            [lock_job(false)]
        );
        assert_eq!(
            testkit::send(&mut app, stopped(StopOutcome::NotRunning, not_running())),
            [Cmd::Exit(ExitPlan::locked(false))]
        );
    }

    /// FW drawn alone in a terminal of `width` by `height`; `rule` for the
    /// Windows card.
    fn firewall_rows(width: u16, height: u16, rule: Option<&str>) -> Vec<String> {
        let look = testkit::simple_mono();
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("a terminal");
        terminal
            .draw(|f| render_firewall(f, f.area(), &look, rule))
            .expect("a draw");
        testkit::buffer_lines(terminal.backend().buffer())
    }

    #[test]
    fn fw_windows_and_macos_cards() {
        // cli.rs's Windows rule for port 7420, as text (the app takes it from
        // the bridge on Windows).
        let rule = "New-NetFirewallRule -DisplayName \"Raven node\" -Direction Inbound -Program \
                    <path to raven-node.exe> -Protocol TCP -LocalPort 7420 -Profile Private \
                    (elevated PowerShell; never the Public profile)";
        testkit::assert_rows(&firewall_rows(80, 24, Some(rule)), &[
            "                                                                                ",
            "                                                                                ",
            "                                                                                ",
            "                                                                                ",
            "                                                                                ",
            "┌──────────────────────────────────────────────────────────────────────────────┐",
            "│ Windows may ask about raven-node                                             │",
            "│                                                                              │",
            "│ If a \"Windows Security Alert\" window appears, choose Private networks and    │",
            "│ Allow access. That needs an administrator. If you close it instead, Windows  │",
            "│ blocks friends from reaching this computer (sending still works).            │",
            "│                                                                              │",
            "│ The rule to add later, in an administrator PowerShell:                       │",
            "│    New-NetFirewallRule -DisplayName \"Raven node\" -Direction Inbound -Program │",
            "│    <path to raven-node.exe> -Protocol TCP -LocalPort 7420 -Profile Private   │",
            "│    (elevated PowerShell; never the Public profile)                           │",
            "│                                                                              │",
            "│ [Enter] OK                                                                   │",
            "└──────────────────────────────────────────────────────────────────────────────┘",
            "                                                                                ",
            "                                                                                ",
            "                                                                                ",
            "                                                                                ",
            "                                                                                ",
        ]);
        testkit::assert_rows(
            &firewall_rows(80, 24, None),
            &[
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "                                                                                ",
                "        ┌──────────────────────────────────────────────────────────────┐        ",
                "        │ Your computer may ask about the firewall                     │        ",
                "        │                                                              │        ",
                "        │ If macOS asks whether raven-node may accept incoming network │        ",
                "        │ connections, choose Allow.                                   │        ",
                "        │                                                              │        ",
                "        │ [Enter] OK                                                   │        ",
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
        // At the smallest size the rule is broken, never cut, and the key
        // stays.
        let small = firewall_rows(60, 16, Some(rule));
        testkit::assert_rows(
            &small,
            &[
                "┌──────────────────────────────────────────────────────────┐",
                "│ Windows may ask about raven-node                         │",
                "│                                                          │",
                "│ If a \"Windows Security Alert\" window appears, choose     │",
                "│ Private networks and Allow access. That needs an         │",
                "│ administrator. If you close it instead, Windows blocks   │",
                "│ friends from reaching this computer (sending still       │",
                "│ works).                                                  │",
                "│                                                          │",
                "│ The rule to add later, in an administrator PowerShell:   │",
                "│    New-NetFirewallRule -DisplayName \"Raven node\"         │",
                "│    -Direction Inbound -Program <path to raven-node.exe>  │",
                "│    -Protocol TCP -LocalPort 7420 -Profile Private        │",
                "│    (elevated PowerShell; never the Public profile)       │",
                "│ [Enter] OK                                               │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
    }

    #[test]
    fn help_rows_fit_its_box_in_every_look() {
        for look in testkit::every_look() {
            for (cols, rows) in [(60, 16), (80, 24), (100, 30)] {
                let inner = overlay_block(&look).inner(help_rect(Rect::new(0, 0, cols, rows)));
                for line in [HOME_KEYS, WELCOME_KEYS, NETWORK_KEYS, MEET_KEYS]
                    .into_iter()
                    .flat_map(|keys| help_lines(&look, keys, &[], inner.width))
                {
                    assert!(
                        line.width() <= usize::from(inner.width),
                        "{cols}x{rows}: {line:?} is wider than {}",
                        inner.width
                    );
                }
            }
        }
    }

    /// Every HELP's 'Not verified' line names the security words guide; the
    /// guide is there, and what it quotes from Raven is what Raven says (a
    /// change to one of these texts needs the guide changed too).
    #[test]
    fn help_names_the_security_words_guide_and_the_guide_quotes_raven() {
        const GUIDE: &str = "docs/SECURITY_WORDS.md";
        let look = testkit::simple_mono();
        for keys in [
            HOME_KEYS,
            WELCOME_KEYS,
            ADD_FRIEND_KEYS,
            VERIFY_KEYS,
            ADDED_KEYS,
            FRIEND_PAGE_KEYS,
            NETWORK_KEYS,
            MEET_KEYS,
            SETTINGS_KEYS,
        ] {
            let help: Vec<String> = help_lines(&look, keys, &[], 70)
                .iter()
                .map(ToString::to_string)
                .collect();
            assert!(help.join(" ").contains(GUIDE), "{help:#?}");
        }
        let ash = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let read = |path: &str| {
            std::fs::read_to_string(ash.join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
        };
        let guide = read(&format!("../../../{GUIDE}"));
        let guide = guide.split_whitespace().collect::<Vec<_>>().join(" ");
        for (file, quoted) in [
            ("src/tui/ui/wizard.rs", "Your security words"),
            ("src/tui/ui/verify.rs", "Your words: read these to"),
            ("src/tui/ui/verify.rs", "Check it's really"),
            ("src/tui/ui/home.rs", "You haven't checked this is really"),
            (
                "src/tui/ui/verify.rs",
                "Security words: hidden until you verify",
            ),
            ("src/tui/ui/verify.rs", "isn't one of Raven's words"),
            ("src/tui/ui/verify.rs", "Type at least 3 letters of word"),
            (
                "src/tui/ui/verify.rs",
                "Type the words with English letters",
            ),
            ("src/tui/ui/verify.rs", "A set has"),
            ("src/tui/ui/verify.rs", "don't fit together"),
            (
                "src/tui/ui/verify.rs",
                "These are real Raven words, but not",
            ),
            ("src/tui/ui/verify.rs", "They match"),
            ("src/tui/ui/verify.rs", "Stop here. Check with"),
            ("src/tui/ui/verify.rs", "Ctrl+O"),
            (
                "src/cli.rs",
                "security words do not match this key: refusing to pin",
            ),
            ("src/cli.rs", "[V]erify & pin"),
            ("src/cli.rs", "[C]ontinue unpinned"),
            ("src/cli.rs", "verify-words"),
            ("src/cli.rs", "raven contact verify"),
        ] {
            assert!(guide.contains(quoted), "{GUIDE} doesn't say {quoted:?}");
            assert!(read(file).contains(quoted), "{file} doesn't say {quoted:?}");
        }
    }

    #[test]
    fn help_scrolls_further_in_a_smaller_terminal() {
        let look = testkit::simple_mono();
        let small = help_max_scroll(&look, &Screen::Home, (false, false), (60, 16));
        let normal = help_max_scroll(&look, &Screen::Home, (false, false), (80, 24));
        assert!(small > normal && normal > 0, "{small} {normal}");
        // HELP grows no further than 72x20.
        assert_eq!(
            help_max_scroll(&look, &Screen::Home, (false, false), (200, 60)),
            normal
        );
    }

    #[test]
    fn long_commands_are_broken_never_cut() {
        assert_eq!(
            wrap_command("SOME_SETTING=~/a/long/path raven", 12),
            ["SOME_SETTING", "=~/a/long/pa", "th", "raven"]
        );
        assert_eq!(wrap_command("a b", 10), ["a b"]);
        for width in [10, 30, 53, 72] {
            for (_, command) in PASSFILE_STEPS {
                let rows = wrap_command(command, width);
                assert!(rows.iter().all(|row| cells(row) <= usize::from(width)));
                let joined: String = rows.concat();
                assert_eq!(
                    joined.replace(' ', ""),
                    command.replace(' ', ""),
                    "{width}: {rows:?}"
                );
            }
        }
    }

    #[test]
    fn a_card_too_tall_keeps_its_keys() {
        let lines = |texts: &[&str]| -> Vec<Line<'static>> {
            texts.iter().map(|t| Line::raw((*t).to_owned())).collect()
        };
        let text =
            |lines: Vec<Line>| -> Vec<String> { lines.iter().map(|l| l.to_string()).collect() };
        let card = lines(&["title", "", "body", "", "more", "", "[Esc] Close"]);
        assert_eq!(
            text(fit(card.clone(), 9)),
            ["title", "", "body", "", "more", "", "[Esc] Close"]
        );
        assert_eq!(
            text(fit(card.clone(), 7)),
            ["title", "", "body", "more", "[Esc] Close"]
        );
        assert_eq!(
            text(fit(card.clone(), 6)),
            ["title", "body", "more", "[Esc] Close"]
        );
        assert_eq!(text(fit(card, 4)), ["title", "[Esc] Close"]);
    }

    #[test]
    fn boxes_are_centred_and_shrink_to_fit() {
        assert_eq!(
            centered(Rect::new(0, 0, 80, 24), 72, 20),
            Rect::new(4, 2, 72, 20)
        );
        assert_eq!(
            centered(Rect::new(0, 0, 60, 16), 72, 20),
            Rect::new(0, 0, 60, 16)
        );
        assert_eq!(
            centered(Rect::new(3, 1, 81, 25), 60, 5),
            Rect::new(13, 11, 60, 5)
        );
        assert_eq!(max_scroll(30, 18), 12);
        assert_eq!(max_scroll(10, 18), 0);
    }

    // ── LOCK completed (privacy pack PP.23) ─────────────────────────────────

    /// The login item read answered (PP.23): Raven's own login item runs
    /// this profile (`own`), or none does.
    fn login_item_read(app: &mut App, own: bool) {
        let item = own.then_some(bridge::LoginItemView {
            managed: Managed::LaunchAgent,
            stays_off: false,
        });
        testkit::send(app, Msg::Job(JobResult::LoginItem(item)));
        assert_eq!(app.own_login_item(), own);
        assert_eq!(app.node().managed.is_some(), own);
    }

    /// LOCK's own job, once the read answered.
    fn lock_job(own_item: bool) -> Cmd {
        Cmd::Node(NodeJob::Lock {
            started_by_app: None,
            own_item,
            managed: false,
        })
    }

    /// L on the friend list: LOCK's question.
    fn lock_from_home(app: &mut App) {
        assert!(testkit::press(app, KeyCode::Char('l')).is_empty());
        assert_eq!(app.overlays(), [Overlay::Lock(LockStep::Asking)]);
    }

    /// [`running_earlier`] in `look` at `size`, the read answered with
    /// `own`, LOCK open from Home.
    fn locking_in(look: Look, size: (u16, u16), own: bool, vault: bool) -> App {
        let mut app = running_earlier(OnQuit::KeepRunning);
        app.set_look_for_tests(look);
        testkit::resize(&mut app, size.0, size.1);
        if vault {
            vault_profile(&mut app);
        }
        login_item_read(&mut app, own);
        lock_from_home(&mut app);
        app
    }

    #[test]
    fn lock_says_raven_s_own_login_item_starts_it_again_at_login() {
        let simple = testkit::simple_mono();
        let app = locking_in(simple, (80, 24), true, false);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                   + node ok - just now",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> o Friend 1       !││                                                        │",
                "│                    ││                                                        │",
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ Stop Raven now?                                          │         │",
                "│         │                                                          │         │",
                "│         │ Raven stops, and friends can't reach you until you open  │         │",
                "│         │ it again.                                                │         │",
                "│         │                                                          │         │",
                "│         │ Your Raven keys stay in this computer's keychain: anyone │         │",
                "│         │ who can log in as you can still open your chats. Lock    │         │",
                "│         │ your screen or log out too.                              │         │",
                "│         │                                                          │         │",
                "│         │ Raven starts again when you log in. To keep it stopped,  │         │",
                "│         │ run `raven lock` in a terminal.                          │         │",
                "│         │                                                          │         │",
                "│         │ [Enter] Stop   [Esc] Cancel                              │         │",
                "│         └──────────────────────────────────────────────────────────┘──────── │",
                "│                    ││ Pick a friend on the left and press Enter to start     │",
                "│ A  Add a friend    ││ writing.                                               │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "Listening on your network - all quiet          activity ........................",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
            ],
        );
        let app = locking_in(simple, (60, 16), true, false);
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "┌──────────────────────────────────────────────────────────┐",
                "│ Stop Raven now?                                          │",
                "│                                                          │",
                "│ Raven stops, and friends can't reach you until you open  │",
                "│ it again.                                                │",
                "│                                                          │",
                "│ Your Raven keys stay in this computer's keychain: anyone │",
                "│ who can log in as you can still open your chats. Lock    │",
                "│ your screen or log out too.                              │",
                "│                                                          │",
                "│ Raven starts again when you log in. To keep it stopped,  │",
                "│ run `raven lock` in a terminal.                          │",
                "│                                                          │",
                "│ [Enter] Stop   [Esc] Cancel                              │",
                "└──────────────────────────────────────────────────────────┘",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify ",
            ],
        );
        let ascii = Look {
            glyphs: Glyphs::ascii(),
            ..simple
        };
        let app = locking_in(ascii, (60, 16), true, true);
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "R A V E N                               + node ok - just now",
                "+----------------------------------------------------------+",
                "| Lock Raven now?                                          |",
                "|                                                          |",
                "| Raven stops. Your chats can't be opened again without    |",
                "| your passphrase.                                         |",
                "|                                                          |",
                "| Friends can't reach you until you open Raven again.      |",
                "|                                                          |",
                "| Raven starts again when you log in. To keep it stopped,  |",
                "| run `raven lock` in a terminal.                          |",
                "|                                                          |",
                "| [Enter] Lock   [Esc] Cancel                              |",
                "+----------------------------------------------------------+",
                "+----------------------------------------------------------+",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify ",
            ],
        );
        let app = locking_in(ascii, (80, 24), true, true);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                   + node ok - just now",
                "+ Friends -----------++--------------------------------------------------------+",
                "|> o Friend 1       !||                                                        |",
                "|                    ||                                                        |",
                "|                    ||                                                        |",
                "|         +----------------------------------------------------------+         |",
                "|         | Lock Raven now?                                          |         |",
                "|         |                                                          |         |",
                "|         | Raven stops. Your chats can't be opened again without    |         |",
                "|         | your passphrase.                                         |         |",
                "|         |                                                          |         |",
                "|         | Friends can't reach you until you open Raven again.      |         |",
                "|         |                                                          |         |",
                "|         | Raven starts again when you log in. To keep it stopped,  |         |",
                "|         | run `raven lock` in a terminal.                          |         |",
                "|         |                                                          |         |",
                "|         | [Enter] Lock   [Esc] Cancel                              |         |",
                "|         +----------------------------------------------------------+         |",
                "|                    || ------------------------------------------------------ |",
                "|                    || Pick a friend on the left and press Enter to start     |",
                "| A  Add a friend    || writing.                                               |",
                "+--------------------++--------------------------------------------------------+",
                "Listening on your network - all quiet          activity ........................",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
            ],
        );
        // Every look at both sizes: the line whole, after the question's
        // words, the keys last.
        for look in testkit::every_look() {
            for (w, h) in [(80, 24), (60, 16)] {
                for vault in [false, true] {
                    let app = locking_in(look, (w, h), true, vault);
                    let text = testkit::screen_text(&testkit::render(&app, w, h));
                    let find = |words: &str| {
                        text.find(words)
                            .unwrap_or_else(|| panic!("no {words:?} at {w}x{h}: {text}"))
                    };
                    let body = find(if vault {
                        "Friends can't reach you until you open Raven again."
                    } else {
                        "your screen or log out too."
                    });
                    let line = find("Raven starts again when you log in. To keep it stopped,");
                    let command = find("run `raven lock` in a terminal.");
                    let keys = find(if vault {
                        "[Enter] Lock"
                    } else {
                        "[Enter] Stop"
                    });
                    assert!(
                        body < line && line < command && command < keys,
                        "{w}x{h}: {text}"
                    );
                    // Without Raven's own login item: UXF.7's words, cell
                    // for cell, as before the read answered.
                    let none = locking_in(look, (w, h), false, vault);
                    let mut before = running_earlier(OnQuit::KeepRunning);
                    before.set_look_for_tests(look);
                    testkit::resize(&mut before, w, h);
                    if vault {
                        vault_profile(&mut before);
                    }
                    lock_from_home(&mut before);
                    let rows = testkit::render(&none, w, h);
                    assert_eq!(rows, testkit::render(&before, w, h));
                    assert!(!testkit::screen_text(&rows).contains("when you log in"));
                }
            }
        }
    }

    #[test]
    fn enter_unloads_raven_s_own_login_item_for_this_session_then_stops() {
        for vault in [false, true] {
            // Raven's own login item: one job, which unloads it for this
            // login session and stops Raven; the app's lock recorded there.
            let mut app = running_earlier(OnQuit::KeepRunning);
            if vault {
                vault_profile(&mut app);
            }
            login_item_read(&mut app, true);
            lock_from_home(&mut app);
            assert_eq!(testkit::press(&mut app, KeyCode::Enter), [lock_job(true)]);
            assert!(app.stopping());
            assert!(matches!(
                lock_step(&app),
                Some(LockStep::Locking { stopping: true, .. })
            ));
            for code in [KeyCode::Esc, KeyCode::Enter, KeyCode::Char('l')] {
                assert!(testkit::press(&mut app, code).is_empty());
            }
            // Raven is gone: the terminal cleared, and Raven starts again at
            // the next login, whatever keeps the keys.
            assert_eq!(
                testkit::send(&mut app, stopped(StopOutcome::Stopped, not_running())),
                [Cmd::Exit(ExitPlan::locked_until_login())]
            );

            // No login item of Raven's for this profile: LOCK's own job
            // without the unload, and UXF.7's last line.
            let mut app = running_earlier(OnQuit::KeepRunning);
            if vault {
                vault_profile(&mut app);
            }
            login_item_read(&mut app, false);
            lock_from_home(&mut app);
            assert_eq!(testkit::press(&mut app, KeyCode::Enter), [lock_job(false)]);
            assert_eq!(
                testkit::send(&mut app, stopped(StopOutcome::NotRunning, not_running())),
                [Cmd::Exit(ExitPlan::locked(vault))]
            );
        }
        // A node this app started: the job says so (Windows stops only it).
        let mut app = started_here(OnQuit::KeepRunning);
        login_item_read(&mut app, true);
        lock_from_home(&mut app);
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Node(NodeJob::Lock {
                started_by_app: Some(4242),
                own_item: true,
                managed: false,
            })]
        );
        // Esc on the question asks for nothing, and nothing is locked.
        let mut app = running_earlier(OnQuit::KeepRunning);
        login_item_read(&mut app, true);
        lock_from_home(&mut app);
        assert!(testkit::press(&mut app, KeyCode::Esc).is_empty());
        assert!(app.overlays().is_empty());
        assert!(!app.stopping());
        // Raven still answers after the stop (the job took its lock back):
        // LOCK says so and the app stays.
        lock_from_home(&mut app);
        testkit::press(&mut app, KeyCode::Enter);
        let still = testkit::status(4242, "0.0.0.0:7420");
        assert!(testkit::send(&mut app, stopped(StopOutcome::Stopped, still)).is_empty());
        assert_eq!(
            lock_step(&app),
            Some(&LockStep::NotStopped(StopOutcome::StillRunning))
        );
        assert!(testkit::press(&mut app, KeyCode::Esc).is_empty());
        assert!(app.overlays().is_empty());
    }

    #[test]
    fn a_stop_already_running_goes_before_lock_s_own_job() {
        let mut app = running_earlier(OnQuit::KeepRunning);
        login_item_read(&mut app, false);
        // X on NET, then Y: the stop runs.
        testkit::press(&mut app, KeyCode::Char('n'));
        testkit::press(&mut app, KeyCode::Char('x'));
        assert_eq!(testkit::press(&mut app, KeyCode::Char('y')), [STOP_JOB]);
        testkit::press(&mut app, KeyCode::Esc);
        lock_from_home(&mut app);
        assert!(
            testkit::press(&mut app, KeyCode::Enter).is_empty(),
            "the stop already running goes first"
        );
        assert!(matches!(
            lock_step(&app),
            Some(LockStep::Locking {
                stopping: false,
                ..
            })
        ));
        // It answered: LOCK's job goes out, once.
        let cmds = testkit::send(&mut app, stopped(StopOutcome::Stopped, not_running()));
        assert_eq!(cmds, [lock_job(false)]);
        assert_eq!(
            testkit::send(&mut app, stopped(StopOutcome::NotRunning, not_running())),
            [Cmd::Exit(ExitPlan::locked(false))]
        );
    }

    #[test]
    fn l_on_home_opens_lock_but_is_typed_in_the_composer() {
        // Where this build reads no login items L opens UXF.7's LOCK, and
        // Enter is X's stop with the lock recorded around it (LOCK's job).
        let mut app = running_earlier(OnQuit::KeepRunning);
        lock_from_home(&mut app);
        assert_eq!(testkit::press(&mut app, KeyCode::Enter), [lock_job(false)]);
        // A Persian keyboard's L key opens it too.
        let mut app = running_earlier(OnQuit::KeepRunning);
        let persian_l = testkit::on_persian_keyboard("l");
        let persian_l = persian_l.chars().next().expect("one letter");
        assert!(testkit::press(&mut app, KeyCode::Char(persian_l)).is_empty());
        assert_eq!(app.overlays(), [Overlay::Lock(LockStep::Asking)]);
        testkit::press(&mut app, KeyCode::Esc);
        // In the composer L is a letter, on any keyboard.
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(app.focus(), Focus::Composer);
        testkit::press(&mut app, KeyCode::Char('l'));
        testkit::press(&mut app, KeyCode::Char(persian_l));
        assert!(app.overlays().is_empty());
        assert_eq!(
            app.composer().map(|c| c.text().to_owned()),
            Some(format!("l{persian_l}"))
        );
        // The conversation takes it as a shortcut again.
        testkit::press(&mut app, KeyCode::Tab);
        assert_eq!(app.focus(), Focus::Messages);
        lock_from_home(&mut app);
    }

    /// Review D-lock-tui-6: LOCK confirmed before the read of Raven's own
    /// login item answered (just after the app opened) waits for it, then
    /// sends LOCK's job as the answer says; it never stops Raven without
    /// recording the lock or unloading the item.
    #[test]
    fn lock_waits_for_the_login_item_read() {
        // The first jobs answered, but not the login item read.
        let unread = || {
            let mut app = testkit::app((80, 24));
            let cmds = app.start(Session {
                settings: quitting(OnQuit::KeepRunning),
                ..testkit::session(Receive::Off)
            });
            assert!(
                cmds.contains(&Cmd::Node(NodeJob::DetectManaged)),
                "{cmds:?}"
            );
            for result in [
                JobResult::Vault(Vault::default()),
                JobResult::Probed(testkit::status(4242, "0.0.0.0:7420")),
                JobResult::Contacts {
                    contacts: Ok(vec![testkit::reachable(1)]),
                    stamp: FileStamp::default(),
                },
                JobResult::History {
                    history: Ok(Default::default()),
                    stamp: FileStamp::default(),
                },
            ] {
                testkit::send(&mut app, Msg::Job(result));
            }
            lock_from_home(&mut app);
            assert!(
                testkit::press(&mut app, KeyCode::Enter).is_empty(),
                "the read answers first"
            );
            assert!(matches!(
                lock_step(&app),
                Some(LockStep::Locking {
                    stopping: false,
                    ..
                })
            ));
            assert!(!app.stopping());
            assert!(testkit::tick(&mut app, Duration::from_secs(1)).is_empty());
            app
        };
        // Raven's own login item: LOCK's job unloads it and records the lock.
        let mut app = unread();
        let own = bridge::LoginItemView {
            managed: Managed::LaunchAgent,
            stays_off: false,
        };
        assert_eq!(
            testkit::send(&mut app, Msg::Job(JobResult::LoginItem(Some(own)))),
            [lock_job(true)]
        );
        assert!(matches!(
            lock_step(&app),
            Some(LockStep::Locking { stopping: true, .. })
        ));
        assert_eq!(
            testkit::send(&mut app, stopped(StopOutcome::Stopped, not_running())),
            [Cmd::Exit(ExitPlan::locked_until_login())]
        );
        // None of Raven's own.
        let mut app = unread();
        assert_eq!(
            testkit::send(&mut app, Msg::Job(JobResult::LoginItem(None))),
            [lock_job(false)]
        );
        // This build reads no login items: UXF.7's stop, the lock recorded
        // around it, a login service left alone.
        let mut app = unread();
        assert_eq!(
            testkit::send(&mut app, Msg::Job(JobResult::Managed(None))),
            [lock_job(false)]
        );
        let mut app = unread();
        assert_eq!(
            testkit::send(
                &mut app,
                Msg::Job(JobResult::Managed(Some(Managed::LaunchAgent)))
            ),
            [Cmd::Node(NodeJob::Lock {
                started_by_app: None,
                own_item: false,
                managed: true,
            })]
        );
        // The read failed: LOCK goes on as where none is read.
        let mut app = unread();
        let failed = Msg::Job(JobResult::Failed {
            job: JobName::NodeManaged,
            plain: errors::explain_node_unavailable("panicked"),
        });
        assert_eq!(testkit::send(&mut app, failed), [lock_job(false)]);
        // Esc while it waits: nothing goes out, then or after the answer.
        let mut app = unread();
        assert!(testkit::press(&mut app, KeyCode::Esc).is_empty());
        assert!(app.overlays().is_empty());
        assert!(testkit::send(&mut app, Msg::Job(JobResult::LoginItem(Some(own)))).is_empty());
    }

    /// Review D-lock-tui-7: Raven's own login item runs this profile, but a
    /// `raven lock` turned it off (only `raven unlock` turns it on): LOCK
    /// does not say Raven starts again at login, and its last line is the
    /// plain one.
    #[test]
    fn lock_says_a_login_item_raven_lock_turned_off_stays_off() {
        for vault in [false, true] {
            let mut app = running_earlier(OnQuit::KeepRunning);
            if vault {
                vault_profile(&mut app);
            }
            let off = bridge::LoginItemView {
                managed: Managed::LaunchAgent,
                stays_off: true,
            };
            testkit::send(&mut app, Msg::Job(JobResult::LoginItem(Some(off))));
            assert!(app.own_login_item() && app.own_login_item_off());
            lock_from_home(&mut app);
            let text = testkit::screen_text(&testkit::render(&app, 80, 24));
            assert!(!text.contains("when you log in"), "{text}");
            assert!(
                text.contains("Raven's login item stays off until you run `raven unlock`."),
                "{text}"
            );
            // The job still unloads it for this session (KeepAlive); the
            // last line says Raven is locked or stopped, not until login.
            assert_eq!(testkit::press(&mut app, KeyCode::Enter), [lock_job(true)]);
            assert_eq!(
                testkit::send(&mut app, stopped(StopOutcome::Stopped, not_running())),
                [Cmd::Exit(ExitPlan::locked(vault))]
            );
        }
        let mut app = running_earlier(OnQuit::KeepRunning);
        let off = bridge::LoginItemView {
            managed: Managed::SystemdUser,
            stays_off: true,
        };
        testkit::send(&mut app, Msg::Job(JobResult::LoginItem(Some(off))));
        lock_from_home(&mut app);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                   + node ok - just now",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> o Friend 1       !││                                                        │",
                "│                    ││                                                        │",
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ Stop Raven now?                                          │         │",
                "│         │                                                          │         │",
                "│         │ Raven stops, and friends can't reach you until you open  │         │",
                "│         │ it again.                                                │         │",
                "│         │                                                          │         │",
                "│         │ Your Raven keys stay in this computer's keychain: anyone │         │",
                "│         │ who can log in as you can still open your chats. Lock    │         │",
                "│         │ your screen or log out too.                              │         │",
                "│         │                                                          │         │",
                "│         │ Raven's login item stays off until you run `raven        │         │",
                "│         │ unlock`.                                                 │         │",
                "│         │                                                          │         │",
                "│         │ [Enter] Stop   [Esc] Cancel                              │         │",
                "│         └──────────────────────────────────────────────────────────┘──────── │",
                "│                    ││ Pick a friend on the left and press Enter to start     │",
                "│ A  Add a friend    ││ writing.                                               │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "Listening on your network - all quiet          activity ........................",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
            ],
        );
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "┌──────────────────────────────────────────────────────────┐",
                "│ Stop Raven now?                                          │",
                "│                                                          │",
                "│ Raven stops, and friends can't reach you until you open  │",
                "│ it again.                                                │",
                "│                                                          │",
                "│ Your Raven keys stay in this computer's keychain: anyone │",
                "│ who can log in as you can still open your chats. Lock    │",
                "│ your screen or log out too.                              │",
                "│                                                          │",
                "│ Raven's login item stays off until you run `raven        │",
                "│ unlock`.                                                 │",
                "│                                                          │",
                "│ [Enter] Stop   [Esc] Cancel                              │",
                "└──────────────────────────────────────────────────────────┘",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify ",
            ],
        );
    }

    /// Review D-lock-tui-2: a passphrase-vault profile whose passphrase is
    /// saved in a file (RAVEN_KEYSTORE_PASSPHRASE_FILE's, the one Raven's
    /// own login item names, or PASSFILE's): LOCK says that anyone who can
    /// read that file can unlock Raven, as `raven lock` does; a long path is
    /// cut in its middle to one row.
    #[test]
    fn lock_says_a_saved_passphrase_file_still_unlocks_a_vault_profile() {
        let saved = |file: Option<&str>| {
            let mut app = running_earlier(OnQuit::KeepRunning);
            testkit::send(
                &mut app,
                Msg::Job(JobResult::Vault(Vault {
                    profile: true,
                    passphrase_file: file.map(PathBuf::from),
                    ..Vault::default()
                })),
            );
            lock_from_home(&mut app);
            app
        };
        let app = saved(Some("/home/sam/.config/raven/keystore-passphrase"));
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                   + node ok - just now",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> o Friend 1       !││                                                        │",
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ Lock Raven now?                                          │         │",
                "│         │                                                          │         │",
                "│         │ Raven stops. Your chats can't be opened again without    │         │",
                "│         │ your passphrase.                                         │         │",
                "│         │                                                          │         │",
                "│         │ Friends can't reach you until you open Raven again.      │         │",
                "│         │                                                          │         │",
                "│         │ Your passphrase is saved in a file on this computer      │         │",
                "│         │ (/home/sam/.config/raven/keystore-passphrase). Anyone    │         │",
                "│         │ who can read your files can unlock Raven with it. If     │         │",
                "│         │ that worries you, delete the file when you are not using │         │",
                "│         │ Raven, and create it again when you want to send and     │         │",
                "│         │ receive.                                                 │         │",
                "│         │                                                          │         │",
                "│         │ [Enter] Lock   [Esc] Cancel                              │──────── │",
                "│         └──────────────────────────────────────────────────────────┘tart     │",
                "│ A  Add a friend    ││ writing.                                               │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "Listening on your network - all quiet          activity ........................",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
            ],
        );
        testkit::assert_rows(
            &testkit::render(&app, 60, 16),
            &[
                "┌──────────────────────────────────────────────────────────┐",
                "│ Lock Raven now?                                          │",
                "│                                                          │",
                "│ Raven stops. Your chats can't be opened again without    │",
                "│ your passphrase.                                         │",
                "│                                                          │",
                "│ Friends can't reach you until you open Raven again.      │",
                "│                                                          │",
                "│ Your passphrase is saved in a file on this computer      │",
                "│ (/home/sam/.config/raven/keystore-passphrase). Anyone    │",
                "│ who can read your files can unlock Raven with it. If     │",
                "│ that worries you, delete the file when you are not using │",
                "│ Raven, and create it again when you want to send and     │",
                "│ receive.                                                 │",
                "│ [Enter] Lock   [Esc] Cancel                              │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
        let long = format!(
            "/home/sam/{}/keystore-passphrase",
            "very-long-folder".repeat(6)
        );
        let app = saved(Some(&long));
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                   + node ok - just now",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> o Friend 1       !││                                                        │",
                "│         ┌──────────────────────────────────────────────────────────┐         │",
                "│         │ Lock Raven now?                                          │         │",
                "│         │                                                          │         │",
                "│         │ Raven stops. Your chats can't be opened again without    │         │",
                "│         │ your passphrase.                                         │         │",
                "│         │                                                          │         │",
                "│         │ Friends can't reach you until you open Raven again.      │         │",
                "│         │                                                          │         │",
                "│         │ Your passphrase is saved in a file on this computer      │         │",
                "│         │ (/home/sam/very-long-folde...older/keystore-passphrase). │         │",
                "│         │ Anyone who can read your files can unlock Raven with it. │         │",
                "│         │ If that worries you, delete the file when you are not    │         │",
                "│         │ using Raven, and create it again when you want to send   │         │",
                "│         │ and receive.                                             │         │",
                "│         │                                                          │         │",
                "│         │ [Enter] Lock   [Esc] Cancel                              │──────── │",
                "│         └──────────────────────────────────────────────────────────┘tart     │",
                "│ A  Add a friend    ││ writing.                                               │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "Listening on your network - all quiet          activity ........................",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
            ],
        );
        // No file: the words of before, cell for cell.
        let none = saved(None);
        let mut before = running_earlier(OnQuit::KeepRunning);
        vault_profile(&mut before);
        lock_from_home(&mut before);
        for (w, h) in [(80, 24), (60, 16)] {
            assert_eq!(testkit::render(&none, w, h), testkit::render(&before, w, h));
        }
        // A keychain profile has no such file to speak of.
        let mut keychain = running_earlier(OnQuit::KeepRunning);
        testkit::send(
            &mut keychain,
            Msg::Job(JobResult::Vault(Vault {
                passphrase_file: Some(PathBuf::from("/home/sam/pass")),
                ..Vault::default()
            })),
        );
        lock_from_home(&mut keychain);
        let text = testkit::screen_text(&testkit::render(&keychain, 80, 24));
        assert!(!text.contains("passphrase is saved"), "{text}");
        // A path is shown through display.rs: no escape reaches the screen.
        let app = saved(Some("/tmp/a\x1b[2Jb"));
        let text = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(!text.contains('\x1b'), "{text}");
        assert!(text.contains("passphrase is saved in a file"), "{text}");
    }

    #[test]
    fn a_lock_s_end_after_raven_s_own_login_item_says_until_login() {
        let plan = ExitPlan::locked_until_login();
        assert_eq!(
            (
                plan.code,
                plan.line.as_deref(),
                plan.quiet,
                plan.clear,
                plan.save.is_none()
            ),
            (
                0,
                Some("Raven is stopped until you log in again."),
                false,
                true,
                true
            )
        );
    }

    /// UNLOCK (review E-harness-docs-ci-3) over Home at 80x24 and 60x16, in
    /// Simple glyphs and in ASCII: the app opened on a profile `raven lock`
    /// locked asks before it starts Raven again.
    #[test]
    fn unlock_asks_before_raven_starts_again() {
        for (look, (w, h)) in [
            (testkit::simple_mono(), (80, 24)),
            (testkit::simple_mono(), (60, 16)),
            (
                Look {
                    glyphs: Glyphs::ascii(),
                    ..testkit::simple_mono()
                },
                (80, 24),
            ),
        ] {
            let session = app::Session {
                locked: true,
                ..testkit::session(Receive::On)
            };
            let app = testkit::home_app_from(
                look,
                (w, h),
                session,
                vec![testkit::friend(1)],
                Default::default(),
            );
            assert_eq!(app.overlays(), [Overlay::Unlock]);
            let rows = testkit::render(&app, w, h);
            let text = rows.join("\n");
            for words in [
                "Raven is locked",
                "`raven lock` stopped Raven: friends can't reach you, and",
                "Start Raven again now?",
                "[Enter] Start Raven   [Esc] Keep it stopped",
            ] {
                assert!(text.contains(words), "{w}x{h}: {words:?}\n{text}");
            }
            let expected: &[&str] = match (w, look.glyphs == Glyphs::ascii()) {
                (80, false) => UNLOCK_80,
                (60, _) => UNLOCK_60,
                _ => UNLOCK_80_ASCII,
            };
            testkit::assert_rows(&rows, expected);
        }
    }

    const UNLOCK_80: &[&str] = &[
        "R A V E N                                                          o Not running",
        "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
        "│> x Friend 1       !││                                                        │",
        "│                    ││                                                        │",
        "│                    ││                                                        │",
        "│                    ││                                                        │",
        "│                    ││                                                        │",
        "│       ┌──────────────────────────────────────────────────────────────┐       │",
        "│       │ Raven is locked                                              │       │",
        "│       │                                                              │       │",
        "│       │ `raven lock` stopped Raven: friends can't reach you, and     │       │",
        "│       │ sending doesn't start it.                                    │       │",
        "│       │                                                              │       │",
        "│       │ Start Raven again now?                                       │       │",
        "│       │                                                              │       │",
        "│       │ [Enter] Start Raven   [Esc] Keep it stopped                  │       │",
        "│       └──────────────────────────────────────────────────────────────┘       │",
        "│                    ││                                                        │",
        "│                    ││ ────────────────────────────────────────────────────── │",
        "│                    ││ Pick a friend on the left and press Enter to start     │",
        "│ A  Add a friend    ││ writing.                                               │",
        "└────────────────────┘└────────────────────────────────────────────────────────┘",
        "1 friend - all quiet                           activity ........................",
        "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
    ];
    const UNLOCK_60: &[&str] = &[
        "R A V E N                                      o Not running",
        "┌ Friends ─────────────────────────────────────────────────┐",
        "│> x Friend 1                                             !│",
        "┌──────────────────────────────────────────────────────────┐",
        "│ Raven is locked                                          │",
        "│                                                          │",
        "│ `raven lock` stopped Raven: friends can't reach you, and │",
        "│ sending doesn't start it.                                │",
        "│                                                          │",
        "│ Start Raven again now?                                   │",
        "│                                                          │",
        "│ [Enter] Start Raven   [Esc] Keep it stopped              │",
        "└──────────────────────────────────────────────────────────┘",
        "│ A  Add a friend                                          │",
        "└──────────────────────────────────────────────────────────┘",
        "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify ",
    ];
    const UNLOCK_80_ASCII: &[&str] = &[
        "R A V E N                                                          o Not running",
        "+ Friends -----------++--------------------------------------------------------+",
        "|> x Friend 1       !||                                                        |",
        "|                    ||                                                        |",
        "|                    ||                                                        |",
        "|                    ||                                                        |",
        "|                    ||                                                        |",
        "|       +--------------------------------------------------------------+       |",
        "|       | Raven is locked                                              |       |",
        "|       |                                                              |       |",
        "|       | `raven lock` stopped Raven: friends can't reach you, and     |       |",
        "|       | sending doesn't start it.                                    |       |",
        "|       |                                                              |       |",
        "|       | Start Raven again now?                                       |       |",
        "|       |                                                              |       |",
        "|       | [Enter] Start Raven   [Esc] Keep it stopped                  |       |",
        "|       +--------------------------------------------------------------+       |",
        "|                    ||                                                        |",
        "|                    || ------------------------------------------------------ |",
        "|                    || Pick a friend on the left and press Enter to start     |",
        "| A  Add a friend    || writing.                                               |",
        "+--------------------++--------------------------------------------------------+",
        "1 friend - all quiet                           activity ........................",
        "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
    ];

    #[test]
    fn opening_a_locked_profile_says_the_login_item_stays_off_once_raven_runs() {
        let wide: &[&str] = &[
            "R A V E N                                                   + node ok - just now",
            "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
            "│> x Friend 1       !││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│       ┌──────────────────────────────────────────────────────────────┐       │",
            "│       │ Raven is running again. Raven's login item stays off until   │       │",
            "│       │ you run `raven unlock`.                                      │       │",
            "│       │                                                              │       │",
            "│       │ [Enter] OK                                                   │       │",
            "│       └──────────────────────────────────────────────────────────────┘       │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││ ────────────────────────────────────────────────────── │",
            "│                    ││ Pick a friend on the left and press Enter to start     │",
            "│ A  Add a friend    ││ writing.                                               │",
            "└────────────────────┘└────────────────────────────────────────────────────────┘",
            "Listening on your network - all quiet          activity ........................",
            "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
        ];
        let small: &[&str] = &[
            "R A V E N                               + node ok - just now",
            "┌ Friends ─────────────────────────────────────────────────┐",
            "│> x Friend 1                                             !│",
            "│                                                          │",
            "│                                                          │",
            "┌──────────────────────────────────────────────────────────┐",
            "│ Raven is running again. Raven's login item stays off     │",
            "│ until you run `raven unlock`.                            │",
            "│                                                          │",
            "│ [Enter] OK                                               │",
            "└──────────────────────────────────────────────────────────┘",
            "│                                                          │",
            "│                                                          │",
            "│ A  Add a friend                                          │",
            "└──────────────────────────────────────────────────────────┘",
            "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify ",
        ];
        for ((w, h), expected) in [((80, 24), wide), ((60, 16), small)] {
            let mut app = testkit::settled_app((w, h), Receive::Off, 1);
            let read = PrivacyRead {
                keep: ChatKeepView::Days30,
                notices: Default::default(),
                disk_needed: None,
                login_item_stays_off: true,
            };
            testkit::send(&mut app, Msg::Job(JobResult::Privacy(Ok(read))));
            // Only once Raven runs again.
            assert!(app.overlays().is_empty());
            testkit::send(&mut app, testkit::node_up());
            assert_eq!(
                app.overlays(),
                [Overlay::PrivacyNotice(Notice::LoginItemOff)]
            );
            testkit::assert_rows(&testkit::render(&app, w, h), expected);
            // OK: closed, and nothing is recorded (it is said in this session
            // only, after the lock was cleared).
            testkit::tick(&mut app, Duration::from_millis(400));
            let cmds = testkit::press(&mut app, KeyCode::Enter);
            assert!(marks(&cmds).is_empty(), "{cmds:?}");
            assert!(app.overlays().is_empty());
            testkit::send(&mut app, Msg::Job(JobResult::Privacy(Ok(read))));
            testkit::send(&mut app, testkit::node_up());
            assert!(app.overlays().is_empty(), "said once");
        }
        // No such lock: no word.
        let mut app = testkit::settled_app((80, 24), Receive::Off, 1);
        testkit::privacy_on(&mut app, ChatKeepView::Days30, Default::default());
        testkit::send(&mut app, testkit::node_up());
        assert!(app.overlays().is_empty());
    }

    // ── NOTICE (privacy pack PP.21) ─────────────────────────────────────────

    const DAY_MS: u64 = 24 * 3_600_000;

    /// Home at `size` once the privacy read answered with both notices due
    /// (the first deletion in a week).
    fn notices_home(size: (u16, u16)) -> App {
        let mut app = testkit::settled_app(size, Receive::Off, 1);
        let notices = bridge::PrivacyNotices {
            sealing: true,
            retention_from: Some(app.now_ms() + 7 * DAY_MS),
        };
        testkit::privacy_on(&mut app, bridge::ChatKeepView::Days30, notices);
        app
    }

    fn marks(cmds: &[Cmd]) -> Vec<Notice> {
        cmds.iter()
            .filter_map(|cmd| match cmd {
                Cmd::Store(StoreJob::MarkNoticeShown(notice)) => Some(*notice),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_privacy_notices_show_once_each_on_home() {
        let mut app = notices_home((80, 24));
        assert_eq!(app.overlays(), [Overlay::PrivacyNotice(Notice::Sealing)]);
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "R A V E N                                                     o Receiving is off",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> x Friend 1       !││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│       ┌──────────────────────────────────────────────────────────────┐       │",
                "│       │ Raven now encrypts your friends list, their addresses and    │       │",
                "│       │ your message records on this computer with your keys. Older  │       │",
                "│       │ Raven versions can't open this profile. To go back to an     │       │",
                "│       │ older version, run `raven privacy unseal` first.             │       │",
                "│       │                                                              │       │",
                "│       │ [Enter] OK                                                   │       │",
                "│       └──────────────────────────────────────────────────────────────┘       │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│                    ││ Pick a friend on the left and press Enter to start     │",
                "│ A  Add a friend    ││ writing.                                               │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "1 friend - all quiet                           activity ........................",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
            ],
        );
        // Enter right after a paste is no answer.
        testkit::send(&mut app, Msg::Key(app::Key::PastedEnter));
        assert!(marks(&testkit::press(&mut app, KeyCode::Enter)).is_empty());
        testkit::tick(&mut app, Duration::from_millis(300));
        // OK: marked shown once, and the retention notice follows.
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(marks(&cmds), [Notice::Sealing]);
        assert_eq!(app.overlays(), [Overlay::PrivacyNotice(Notice::Retention)]);
        let rows = bridge::with_local_offset(Some(12_600), || testkit::render(&app, 80, 24));
        testkit::assert_rows(
            &rows,
            &[
                "R A V E N                                 o Receiving is off - 12:23:20 UTC+3:30",
                "┌ Friends ───────────┐┌────────────────────────────────────────────────────────┐",
                "│> x Friend 1       !││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│       ┌──────────────────────────────────────────────────────────────┐       │",
                "│       │ New: Raven deletes chats older than 30 days from this        │       │",
                "│       │ computer. The first deletion is on Thu 16 Oct. To keep chats │       │",
                "│       │ longer or always: `raven chats keep 90d` or `raven chats     │       │",
                "│       │ keep always`.                                                │       │",
                "│       │                                                              │       │",
                "│       │ [Enter] OK                                                   │       │",
                "│       └──────────────────────────────────────────────────────────────┘       │",
                "│                    ││                                                        │",
                "│                    ││                                                        │",
                "│                    ││ ────────────────────────────────────────────────────── │",
                "│                    ││ Pick a friend on the left and press Enter to start     │",
                "│ A  Add a friend    ││ writing.                                               │",
                "└────────────────────┘└────────────────────────────────────────────────────────┘",
                "1 friend - all quiet                           activity ........................",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify  E Friend page      ",
            ],
        );
        assert_eq!(
            marks(&testkit::press(&mut app, KeyCode::Esc)),
            [Notice::Retention]
        );
        assert!(app.overlays().is_empty());
        // A read still out when they were answered: not shown again here.
        let late = bridge::PrivacyNotices {
            sealing: true,
            retention_from: Some(app.now_ms() + DAY_MS),
        };
        let cmds = testkit::privacy_on(&mut app, bridge::ChatKeepView::Days30, late);
        assert!(app.overlays().is_empty(), "{cmds:?}");
        // At the smallest size, with the macOS keychain sentence; and the
        // retention notice without this computer's clock.
        let mut small = notices_home((60, 16));
        small.set_mac_for_tests(true);
        testkit::assert_rows(
            &testkit::render(&small, 60, 16),
            &[
                "R A V E N                                 o Receiving is off",
                "┌──────────────────────────────────────────────────────────┐",
                "│ Raven now encrypts your friends list, their addresses    │",
                "│ and your message records on this computer with your      │",
                "│ keys. Older Raven versions can't open this profile. To   │",
                "│ go back to an older version, run `raven privacy unseal`  │",
                "│ first.                                                   │",
                "│                                                          │",
                "│ Raven may ask once for access to your keychain when it   │",
                "│ starts. Choose Always Allow so Raven can receive         │",
                "│ messages while you are away.                             │",
                "│                                                          │",
                "│ [Enter] OK                                               │",
                "└──────────────────────────────────────────────────────────┘",
                "└──────────────────────────────────────────────────────────┘",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify ",
            ],
        );
        testkit::press(&mut small, KeyCode::Enter);
        testkit::assert_rows(
            &testkit::render(&small, 60, 16),
            &[
                "R A V E N                                 o Receiving is off",
                "┌ Friends ─────────────────────────────────────────────────┐",
                "│> x Friend 1                                             !│",
                "│                                                          │",
                "┌──────────────────────────────────────────────────────────┐",
                "│ New: Raven deletes chats older than 30 days from this    │",
                "│ computer. The first deletion is in about 7 days. To keep │",
                "│ chats longer or always: `raven chats keep 90d` or `raven │",
                "│ chats keep always`.                                      │",
                "│                                                          │",
                "│ [Enter] OK                                               │",
                "└──────────────────────────────────────────────────────────┘",
                "│                                                          │",
                "│ A  Add a friend                                          │",
                "└──────────────────────────────────────────────────────────┘",
                "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  V Verify ",
            ],
        );
    }

    #[test]
    fn the_privacy_notices_wait_for_home_and_the_privacy_read() {
        // Not available: nothing shows.
        let app = testkit::settled_app((80, 24), Receive::Off, 1);
        assert!(app.overlays().is_empty());
        // On SET: they wait for Home.
        let mut app = testkit::settled_app((80, 24), Receive::Off, 1);
        testkit::press(&mut app, KeyCode::Char('s'));
        let notices = bridge::PrivacyNotices {
            sealing: true,
            retention_from: None,
        };
        testkit::privacy_on(&mut app, bridge::ChatKeepView::Days30, notices);
        assert!(app.overlays().is_empty());
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(app.overlays(), [Overlay::PrivacyNotice(Notice::Sealing)]);
        // 'Keep' chosen on SET before the retention notice showed: it never
        // does.
        let mut app = testkit::settled_app((80, 24), Receive::Off, 1);
        let notices = bridge::PrivacyNotices {
            sealing: false,
            retention_from: Some(app.now_ms() + DAY_MS),
        };
        testkit::press(&mut app, KeyCode::Char('s'));
        testkit::privacy_on(&mut app, bridge::ChatKeepView::Days30, notices);
        for _ in 0..8 {
            testkit::press(&mut app, KeyCode::Down);
        }
        testkit::press(&mut app, KeyCode::Enter);
        assert!(matches!(app.overlays(), [Overlay::KeepChats { .. }]));
        for _ in 0..3 {
            testkit::press(&mut app, KeyCode::Down);
        }
        testkit::press(&mut app, KeyCode::Enter);
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen(), &Screen::Home);
        assert!(app.overlays().is_empty());
    }

    #[test]
    fn retention_notice_words_its_day_on_this_computers_clock() {
        // 2026-10-20 (a Tuesday) 10:35 UTC; a week before it.
        let first = 1_792_492_500_000;
        let text = |off| {
            bridge::with_local_offset(off, || {
                bridge::retention_notice_text(
                    bridge::ChatKeepView::Days30,
                    first,
                    first - 7 * DAY_MS,
                )
            })
        };
        assert_eq!(
            text(Some(12_600)),
            "New: Raven deletes chats older than 30 days from this computer. The first deletion \
             is on Tue 20 Oct. To keep chats longer or always: `raven chats keep 90d` or `raven \
             chats keep always`."
        );
        assert!(
            text(None).contains("The first deletion is in about 7 days."),
            "{}",
            text(None)
        );
    }

    #[test]
    fn the_privacy_pack_parts_in_every_look() {
        let bob = testkit::saved_as(0xB0, "Bob", true, "192.168.1.30:7420");
        for look in testkit::every_look() {
            for (w, h) in [(80, 24), (60, 16)] {
                // ASCII's box borders break a sentence that wraps: each phrase
                // checked is on one row.
                let shown = |app: &App| testkit::screen_text(&testkit::render(app, w, h));
                let says = |app: &App, words: &[&str]| {
                    let text = shown(app);
                    for want in words {
                        assert!(text.contains(want), "{want:?} at {w}x{h}: {text}");
                    }
                };
                let base = |notices| {
                    let mut app = testkit::home_app_in(
                        look,
                        (w, h),
                        Receive::Off,
                        vec![bob.clone()],
                        Default::default(),
                    );
                    testkit::privacy_on(&mut app, bridge::ChatKeepView::Days30, notices);
                    app
                };
                // SET's row, and KEEP over it.
                let mut app = base(Default::default());
                testkit::press(&mut app, KeyCode::Char('s'));
                for _ in 0..8 {
                    testkit::press(&mut app, KeyCode::Down);
                }
                says(&app, &["Keep chats for", "30 days", "copies aren't."]);
                testkit::press(&mut app, KeyCode::Enter);
                says(
                    &app,
                    &[
                        "7 days",
                        "30 days",
                        "90 days",
                        "Keep",
                        "[Enter] Save",
                        "[Esc] Cancel",
                    ],
                );
                // CI's actions, DEL and FORGET.
                let mut app = base(Default::default());
                testkit::press(&mut app, KeyCode::Char('e'));
                says(
                    &app,
                    &["[C] Delete chat with Bob", "[F] Forget Bob's address"],
                );
                testkit::press(&mut app, KeyCode::Char('c'));
                says(
                    &app,
                    &["Type delete to confirm:", "[Enter] Delete", "[Esc] Cancel"],
                );
                testkit::press(&mut app, KeyCode::Esc);
                testkit::press(&mut app, KeyCode::Char('f'));
                says(&app, &["Forget Bob's saved address?", "[Enter] Forget"]);
                // NOTICE on Home.
                let app = base(bridge::PrivacyNotices {
                    sealing: true,
                    retention_from: None,
                });
                says(&app, &["`raven privacy unseal`", "[Enter] OK"]);
            }
        }
    }

    // ── ERASE (privacy pack PP.22) ──────────────────────────────────────────

    /// What the tests' erase would delete.
    const PLAN: ErasePlanView = ErasePlanView {
        friends: Some(3),
        waiting: 2,
        keychain_keys: 4,
    };
    const ERASE_JOB: Cmd = Cmd::Store(StoreJob::Erase);

    /// The privacy read answered on `app`, then SET's last row, Enter, and
    /// ERASE's list answered with `plan`.
    fn erase_open(app: &mut App, plan: Result<ErasePlanView, String>) {
        testkit::privacy_on(app, ChatKeepView::Days30, Default::default());
        testkit::press(app, KeyCode::Char('s'));
        for _ in 0..20 {
            testkit::press(app, KeyCode::Down);
        }
        assert_eq!(
            testkit::press(app, KeyCode::Enter),
            [Cmd::Store(StoreJob::ErasePlan)]
        );
        assert_eq!(app.overlays(), [Overlay::Erase(EraseState::Reading)]);
        testkit::send(app, Msg::Job(JobResult::ErasePlan(plan)));
    }

    /// ERASE's state, if it is open.
    fn erase_state(app: &App) -> Option<&EraseState> {
        app.overlays().iter().find_map(|overlay| match overlay {
            Overlay::Erase(erase) => Some(erase),
            _ => None,
        })
    }

    /// `text` typed one key at a time, as a person types: what it asked.
    fn type_keys(app: &mut App, text: &str) -> Vec<Cmd> {
        let mut cmds = Vec::new();
        for c in text.chars() {
            cmds.extend(testkit::press(app, KeyCode::Char(c)));
        }
        cmds
    }

    /// ERASE asking, with no node running (nothing for the app to stop)
    /// and no job in flight.
    fn erase_asking() -> App {
        let mut app = settled(quitting(OnQuit::KeepRunning));
        erase_open(&mut app, Ok(PLAN));
        assert!(app.jobs_in_flight().idle(), "{:?}", app.jobs_in_flight());
        app
    }

    #[test]
    fn erase_over_the_whole_screen_in_both_sizes() {
        let mut app = erase_asking();
        app.set_mac_for_tests(true);
        type_keys(&mut app, "era");
        testkit::assert_rows(
            &testkit::render(&app, 80, 24),
            &[
                "┌──────────────────────────────────────────────────────────────────────────────┐",
                "│ Erase Raven from this computer?                                              │",
                "│                                                                              │",
                "│ This deletes your Raven identity, friends, chats and waiting messages on     │",
                "│ this computer. It can't be undone. Your friends will need to add you again.  │",
                "│ Erasing works best when the disk is encrypted (FileVault, BitLocker or       │",
                "│ LUKS); without that, pieces of old files may still be found.                 │",
                "│                                                                              │",
                "│ On this computer now:                                                        │",
                "│   - your identity                                                            │",
                "│   - 3 friends                                                                │",
                "│   - your chats                                                               │",
                "│   - 2 waiting messages                                                       │",
                "│   - 4 keys in this computer's keychain                                       │",
                "│                                                                              │",
                "│ Type erase to confirm:                                                       │",
                "│ > era                                                                        │",
                "│                                                                              │",
                "│                                                                              │",
                "│                                                                              │",
                "│                                                                              │",
                "│                                                                              │",
                "│ [Enter] Erase   [Esc] Cancel                                                 │",
                "└──────────────────────────────────────────────────────────────────────────────┘",
            ],
        );
        let mut small = settled(quitting(OnQuit::KeepRunning));
        testkit::resize(&mut small, 60, 16);
        erase_open(&mut small, Ok(PLAN));
        small.set_mac_for_tests(false);
        testkit::assert_rows(
            &testkit::render(&small, 60, 16),
            &[
                "┌──────────────────────────────────────────────────────────┐",
                "│ Erase Raven from this computer?                          │",
                "│ This deletes your Raven identity, friends, chats and     │",
                "│ waiting messages on this computer. It can't be undone.   │",
                "│ Your friends will need to add you again. Erasing works   │",
                "│ best when the disk is encrypted (FileVault, BitLocker or │",
                "│ LUKS); without that, pieces of old files may still be    │",
                "│ found.                                                   │",
                "│ On this computer now: your identity, 3 friends, your     │",
                "│ chats, 2 waiting messages and 4 keys in this computer's  │",
                "│ keyring.                                                 │",
                "│                                                          │",
                "│ Type erase to confirm:                                   │",
                "│ >                                                        │",
                "│ [Enter] Erase   [Esc] Cancel                             │",
                "└──────────────────────────────────────────────────────────┘",
            ],
        );
        // The terminal's cursor after the word.
        let cursor = |app: &App, w: u16, h: u16| {
            let mut terminal = Terminal::new(TestBackend::new(w, h)).expect("a test terminal");
            terminal
                .draw(|f| render_frame(f, app, app.now()))
                .expect("draw");
            terminal.get_cursor_position().expect("the cursor")
        };
        assert_eq!(cursor(&app, 80, 24), Position::new(7, 16));
        assert_eq!(cursor(&small, 60, 16), Position::new(4, 13));
        // What goes, in plain words: a count of none is left out, friends
        // that can't be counted now are 'your friends'.
        assert_eq!(
            erase_items(
                &ErasePlanView {
                    friends: Some(1),
                    waiting: 1,
                    keychain_keys: 1,
                },
                true
            ),
            [
                "your identity",
                "1 friend",
                "your chats",
                "1 waiting message",
                "1 key in this computer's keychain"
            ]
        );
        assert_eq!(
            erase_items(
                &ErasePlanView {
                    friends: Some(0),
                    ..ErasePlanView::default()
                },
                false
            ),
            ["your identity", "your chats"]
        );
        assert_eq!(
            erase_items(
                &ErasePlanView {
                    friends: None,
                    ..ErasePlanView::default()
                },
                false
            ),
            ["your identity", "your friends", "your chats"]
        );
    }

    #[test]
    fn erase_in_every_look_and_every_state() {
        for look in testkit::every_look() {
            for (w, h) in [(80, 24), (60, 16)] {
                let shown = |app: &App| testkit::screen_text(&testkit::render(app, w, h));
                let says = |app: &App, words: &[&str]| {
                    let text = shown(app);
                    for want in words {
                        assert!(text.contains(want), "{want:?} at {w}x{h}: {text}");
                    }
                };
                let base = || {
                    let mut app = testkit::app_in(look, (w, h));
                    app.start(Session {
                        settings: quitting(OnQuit::KeepRunning),
                        ..testkit::session(Receive::Off)
                    });
                    for result in [
                        JobResult::Vault(Vault::default()),
                        JobResult::Probed(not_running()),
                        JobResult::Managed(None),
                        JobResult::Contacts {
                            contacts: Ok(vec![testkit::reachable(1)]),
                            stamp: FileStamp::default(),
                        },
                        JobResult::History {
                            history: Ok(Default::default()),
                            stamp: FileStamp::default(),
                        },
                    ] {
                        testkit::send(&mut app, Msg::Job(result));
                    }
                    app
                };
                // SET's last row.
                let mut app = base();
                testkit::privacy_on(&mut app, ChatKeepView::Days30, Default::default());
                testkit::press(&mut app, KeyCode::Char('s'));
                for _ in 0..20 {
                    testkit::press(&mut app, KeyCode::Down);
                }
                says(&app, &["Erase Raven from this computer", "[Enter] Erase"]);
                // Reading, then the question.
                testkit::press(&mut app, KeyCode::Enter);
                says(
                    &app,
                    &[
                        "Erase Raven from this computer?",
                        "Reading what Raven keeps on this",
                        "[Esc] Cancel",
                    ],
                );
                testkit::send(&mut app, Msg::Job(JobResult::ErasePlan(Ok(PLAN))));
                says(
                    &app,
                    &[
                        "Erase Raven from this computer?",
                        "This deletes your Raven identity",
                        "Type erase to confirm:",
                        "[Enter] Erase",
                        "[Esc] Cancel",
                    ],
                );
                if h == 24 {
                    says(&app, &[&format!("{} 3 friends", look.glyphs.bullet)]);
                }
                // Erasing: the progress line, and no key.
                type_keys(&mut app, "erase");
                assert_eq!(testkit::press(&mut app, KeyCode::Enter), [ERASE_JOB]);
                says(&app, &["Erasing Raven from this computer"]);
                assert!(!shown(&app).contains("[Esc]"));
                // Nothing erased: why, and Close.
                testkit::send(
                    &mut app,
                    Msg::Job(JobResult::Erased(EraseEnd::NotErased(
                        "Raven is still running, so erase can't continue.".into(),
                    ))),
                );
                says(&app, &["Raven is still running", "[Esc] Close"]);
                // A refusal: why, and Close.
                let mut refused = base();
                erase_open(&mut refused, Err("this folder is not a profile".into()));
                says(&refused, &["this folder is not a profile", "[Esc] Close"]);
            }
        }
    }

    #[test]
    fn a_wrong_word_does_nothing_and_esc_cancels() {
        let mut app = erase_asking();
        for word in ["", "erasee", "delete", "eras", "erase now", "y"] {
            type_keys(&mut app, word);
            assert!(
                testkit::press(&mut app, KeyCode::Enter).is_empty(),
                "{word:?}"
            );
            assert!(
                matches!(erase_state(&app), Some(EraseState::Asking { .. })),
                "{word:?}"
            );
            for _ in 0..12 {
                testkit::press(&mut app, KeyCode::Backspace);
            }
        }
        // Keys that are shortcuts elsewhere are only letters here.
        assert!(type_keys(&mut app, "qsx?").is_empty());
        assert_eq!(
            erase_state(&app),
            Some(&EraseState::Asking {
                plan: PLAN,
                typed: "qsx?".into(),
            })
        );
        // Esc: nothing erased, SET again; asked again, the word is empty.
        assert!(testkit::press(&mut app, KeyCode::Esc).is_empty());
        assert!(app.overlays().is_empty());
        assert!(matches!(app.screen(), Screen::Settings(_)));
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Store(StoreJob::ErasePlan)]
        );
        // Esc while it reads; an answer for the closed box is dropped.
        testkit::press(&mut app, KeyCode::Esc);
        testkit::send(&mut app, Msg::Job(JobResult::ErasePlan(Ok(PLAN))));
        assert!(app.overlays().is_empty());
        // Ctrl+C opens QUIT over the question.
        testkit::press(&mut app, KeyCode::Enter);
        testkit::send(&mut app, Msg::Job(JobResult::ErasePlan(Ok(PLAN))));
        testkit::ctrl(&mut app, 'c');
        assert!(matches!(app.overlays(), [Overlay::Erase(_), Overlay::Quit]));
        // A refusal closes on Esc or Enter.
        let mut refused = settled(quitting(OnQuit::KeepRunning));
        erase_open(&mut refused, Err("refused".into()));
        assert!(testkit::press(&mut refused, KeyCode::Enter).is_empty());
        assert!(refused.overlays().is_empty());
    }

    #[test]
    fn the_word_is_typed_in_any_case_or_on_a_persian_keyboard_never_pasted() {
        for word in [
            "erase".to_owned(),
            "ERASE".to_owned(),
            testkit::on_persian_keyboard("erase"),
        ] {
            let mut app = erase_asking();
            type_keys(&mut app, &word);
            assert_eq!(
                testkit::press(&mut app, KeyCode::Enter),
                [ERASE_JOB],
                "{word}"
            );
        }
        // A paste clears the word, bracketed or as a burst of keys; so does
        // an Enter that came with one.
        for via in [PasteVia::Bracketed, PasteVia::Keystrokes] {
            let mut app = erase_asking();
            type_keys(&mut app, "er");
            assert!(testkit::paste(&mut app, "erase", via).is_empty());
            assert_eq!(
                erase_state(&app),
                Some(&EraseState::Asking {
                    plan: PLAN,
                    typed: String::new(),
                })
            );
            // Typed now, the Enter within 300 ms of the paste means nothing.
            type_keys(&mut app, "erase");
            assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
            testkit::tick(&mut app, Duration::from_millis(300));
            assert_eq!(testkit::press(&mut app, KeyCode::Enter), [ERASE_JOB]);
        }
        let mut app = erase_asking();
        type_keys(&mut app, "erase");
        assert!(testkit::send(&mut app, Msg::Key(Key::PastedEnter)).is_empty());
        assert!(matches!(
            erase_state(&app),
            Some(EraseState::Asking { typed, .. }) if typed.is_empty()
        ));
    }

    #[test]
    fn exactly_one_erase_job_once_nothing_else_runs() {
        let changed = |watched| {
            Msg::Poll(PollUpdate::File {
                watched,
                stamp: FileStamp::of(&std::env::current_exe().expect("a file")),
            })
        };
        // A send in flight goes first.
        let mut app = settled(quitting(OnQuit::KeepRunning));
        testkit::press(&mut app, KeyCode::Enter);
        let (local_id, _) = testkit::type_and_send(&mut app, "hi").expect("a send");
        testkit::press(&mut app, KeyCode::Esc);
        erase_open(&mut app, Ok(PLAN));
        type_keys(&mut app, "erase");
        assert!(!app.jobs_in_flight().idle());
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        assert!(matches!(
            erase_state(&app),
            Some(EraseState::Erasing {
                stage: EraseStage::Waiting,
                ..
            })
        ));
        let text = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(text.contains("One message is still being sent."), "{text}");
        assert!(moving(&app).is_some(), "its spinner turns");
        // Nothing starts by itself, nothing is read and no marker is saved
        // meanwhile.
        assert!(testkit::send(&mut app, changed(Watched::Contacts)).is_empty());
        assert!(testkit::send(&mut app, changed(Watched::History)).is_empty());
        assert!(testkit::tick(&mut app, Duration::from_secs(5)).is_empty());
        // The send's end: the erase, once, and nothing else.
        let cmds = testkit::send(
            &mut app,
            testkit::sent(local_id, SendResult::Failed("not sent".into())),
        );
        assert_eq!(cmds, [ERASE_JOB]);
        assert!(matches!(
            erase_state(&app),
            Some(EraseState::Erasing {
                stage: EraseStage::Running,
                ..
            })
        ));
        // No key, Ctrl+C, nor a change of a file asks for more; nor SMALL's
        // keys in a window too small.
        for code in [KeyCode::Enter, KeyCode::Esc, KeyCode::Char('q')] {
            assert!(testkit::press(&mut app, code).is_empty());
        }
        assert!(testkit::ctrl(&mut app, 'c').is_empty());
        testkit::resize(&mut app, 40, 10);
        for code in [KeyCode::Char('q'), KeyCode::Char('c')] {
            assert!(testkit::press(&mut app, code).is_empty());
        }
        testkit::resize(&mut app, 80, 24);
        assert!(testkit::send(&mut app, changed(Watched::History)).is_empty());
        assert!(testkit::send(&mut app, testkit::node_up()).is_empty());
        // A privacy read that says not available leaves it as it is.
        testkit::send(
            &mut app,
            Msg::Job(JobResult::Privacy(Err(bridge::NotAvailable))),
        );
        assert!(app.erasing());
        // Esc while it waited cancels, and nothing was asked for.
        let mut waiting = settled(quitting(OnQuit::KeepRunning));
        testkit::press(&mut waiting, KeyCode::Enter);
        testkit::type_and_send(&mut waiting, "hi").expect("a send");
        testkit::press(&mut waiting, KeyCode::Esc);
        erase_open(&mut waiting, Ok(PLAN));
        type_keys(&mut waiting, "erase");
        testkit::press(&mut waiting, KeyCode::Enter);
        assert!(testkit::press(&mut waiting, KeyCode::Esc).is_empty());
        assert!(waiting.overlays().is_empty());
        assert!(!waiting.erasing());
    }

    #[test]
    fn the_app_stops_its_own_node_first_then_erases() {
        let mut app = started_here(OnQuit::KeepRunning);
        erase_open(&mut app, Ok(PLAN));
        type_keys(&mut app, "erase");
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Node(NodeJob::Stop {
                started_by_app: Some(4242),
                managed: false,
            })]
        );
        let text = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(
            text.contains("Stopping Raven's background program"),
            "{text}"
        );
        // Whatever the stop says, the erase goes next (it stops Raven
        // itself, or says why it can't).
        assert_eq!(
            testkit::send(&mut app, stopped(StopOutcome::StillRunning, not_running())),
            [ERASE_JOB]
        );
        // Raven's own login item is set up too (Windows' scheduled task, as
        // review D-lock-tui-5 found it, after a LOCK ended the task's node
        // and the app started its own): the node is still this app's own,
        // so the stop may end it (on Windows only this app may).
        let mut app = started_here(OnQuit::KeepRunning);
        let task = bridge::LoginItemView {
            managed: Managed::ScheduledTask,
            stays_off: false,
        };
        testkit::send(&mut app, Msg::Job(JobResult::LoginItem(Some(task))));
        assert_eq!(app.node().managed, Some(Managed::ScheduledTask));
        erase_open(&mut app, Ok(PLAN));
        type_keys(&mut app, "erase");
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Node(NodeJob::Stop {
                started_by_app: Some(4242),
                managed: false,
            })]
        );
        assert_eq!(
            bridge::stop_plan(true, false, true, Some(4242), Some(4242)),
            bridge::StopPlan::TaskKill(4242)
        );
        // A node that ran before the app: the erase job stops it.
        let mut app = running_earlier(OnQuit::KeepRunning);
        erase_open(&mut app, Ok(PLAN));
        type_keys(&mut app, "erase");
        assert_eq!(testkit::press(&mut app, KeyCode::Enter), [ERASE_JOB]);
        // A stop job that failed: the erase still goes, once.
        let mut app = started_here(OnQuit::KeepRunning);
        erase_open(&mut app, Ok(PLAN));
        type_keys(&mut app, "erase");
        testkit::press(&mut app, KeyCode::Enter);
        let failed = Msg::Job(JobResult::Failed {
            job: JobName::NodeStop,
            plain: errors::explain_node_unavailable("panicked"),
        });
        assert_eq!(testkit::send(&mut app, failed), [ERASE_JOB]);
    }

    #[test]
    fn the_exit_plan_prints_only_the_result_list_and_saves_nothing() {
        let lines = vec![
            "Erased: identity, friends, chats, waiting messages and 3 keys. Not erased: your \
             shell history and terminal scrollback; files copied elsewhere."
                .to_owned(),
            "Left in this folder because Raven didn't create them: 1 file (/p).".to_owned(),
        ];
        let mut app = erase_asking();
        type_keys(&mut app, "erase");
        assert_eq!(testkit::press(&mut app, KeyCode::Enter), [ERASE_JOB]);
        let cmds = testkit::send(
            &mut app,
            Msg::Job(JobResult::Erased(EraseEnd::Ran {
                finished: true,
                lines: lines.clone(),
            })),
        );
        let plan = ExitPlan::erased(true, &lines);
        assert_eq!(cmds, [Cmd::Exit(plan.clone())]);
        assert_eq!(
            (plan.code, plan.quiet, plan.clear, plan.save),
            (0, false, true, None)
        );
        assert_eq!(plan.line.as_deref(), Some(lines.join("\n").as_str()));
        // From then on the app asks for nothing more.
        assert!(testkit::send(&mut app, testkit::node_up()).is_empty());
        assert!(testkit::tick(&mut app, Duration::from_secs(5)).is_empty());
        // Part-way: exactly what is left, on stderr (code 1); also when the
        // job itself failed.
        let left = vec![
            "Erase stopped: x. Still on this computer: y. Run `raven erase` to finish.".to_owned(),
        ];
        let plan = ExitPlan::erased(false, &left);
        assert_eq!(
            (plan.code, plan.line.as_deref(), plan.clear, plan.save),
            (1, Some(left[0].as_str()), true, None)
        );
        let mut app = erase_asking();
        type_keys(&mut app, "erase");
        testkit::press(&mut app, KeyCode::Enter);
        let cmds = testkit::send(
            &mut app,
            Msg::Job(JobResult::Failed {
                job: JobName::Erase,
                plain: errors::explain_node_unavailable("panicked"),
            }),
        );
        assert_eq!(
            cmds,
            [Cmd::Exit(ExitPlan::erased(
                false,
                &[
                    "Raven couldn't finish erasing this profile. Run `raven erase` to finish."
                        .into()
                ]
            ))]
        );
        // What the plain terminal gets goes through display.rs.
        let plan = ExitPlan::erased(true, &["a\x1b[2Jb".to_owned()]);
        assert!(!plan.line.unwrap_or_default().contains('\x1b'));
    }

    #[test]
    fn an_erase_that_changed_nothing_says_why_and_the_app_goes_on() {
        let mut app = erase_asking();
        type_keys(&mut app, "erase");
        testkit::press(&mut app, KeyCode::Enter);
        let why = "Raven is still running, so erase can't continue: stop it yourself (pkill -f \
                   'raven-node service'), then run `raven erase` again. Nothing was erased.";
        assert!(testkit::send(
            &mut app,
            Msg::Job(JobResult::Erased(EraseEnd::NotErased(why.into())))
        )
        .is_empty());
        assert_eq!(erase_state(&app), Some(&EraseState::NotErased(why.into())));
        assert!(
            testkit::screen_text(&testkit::render(&app, 80, 24)).contains("Nothing was erased.")
        );
        assert!(!app.erasing());
        testkit::press(&mut app, KeyCode::Esc);
        assert!(app.overlays().is_empty());
        // The files are read again as they change.
        let cmds = testkit::send(
            &mut app,
            Msg::Poll(PollUpdate::File {
                watched: Watched::Contacts,
                stamp: FileStamp::of(&std::env::current_exe().expect("a file")),
            }),
        );
        assert_eq!(cmds, [Cmd::Store(StoreJob::LoadContacts)]);
    }
}
